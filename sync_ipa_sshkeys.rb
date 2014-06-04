#!/usr/bin/ruby
require 'net/http'
require 'rubygems'
require 'net/ldap'
require 'timeout'
require 'json'
require 'base64'
require 'resolv'

$stash_host = 'localhost:7990'
$last_sync_file = '/data/stash/tmp/ssh_key_sync_time'
$stash_user = 'admin_user'
$stash_pass = 'admin_pass'

def iniread(filename)
  # the sssd config is a slightly non-standard ini file in that there are 2 significant changes that break gems like 'inifile'
  # 1) comments must be on a line by themself.
  # 2) Values are not quoted

  data = {}
  File.open(filename) do |fh|
    section = ''
    fh.each do |line|
      line.sub!(/^\s+/, '')
      line.chomp!
      if line.match(/^[#;]/) or line.match(/^\s*$/) then
        next
      elsif line.match(/^\[([^\]]+)\]/) then
        section = $1
        data[section] = {}
      else
        (key,value) = line.split(/\s*=\s*/, 2)
        if value.nil? then
          raise(StandardError, "Could not parse '#{line}'")
        end
        if data[section].nil? then # this should only happen for the default `''` section
          data[section] = {}
        end
        data[section][key] = value
      end
    end
  end
  data
end

class Key
  attr_reader :text
  attr_reader :type
  attr_reader :data
  attr_reader :comment
  attr_reader :id
  def initialize(key)
    if key.is_a?(String) then
      key.force_encoding('ASCII-8BIT')
      if !key.ascii_only? then
        key = "ssh-rsa " + Base64.encode64(key).chomp.gsub(/\s+/, '')
      end
      @text = key + " (IPA)"
    elsif key.is_a?(Hash) then
      @id = key['id']
      @text = key['text']
    end
    @text.match(/^(ssh-[dr]sa)\b[^ ]* (\S+)(?: (.*))/)
    @type = $1
    @data = $2
    @comment = $3
  end
  def ipa_key?
    !!@comment.match(/ \(IPA\)$/)
  end
  def hash
    "#{@type} #{@data}".hash
  end
  def to_s
    "#{@type} #{@data} #{@comment}"
  end
  def eql?(target)
    hash == target.hash
  end
  alias_method :==, :eql?
end

def request(method, path, body = nil)
  http = Net::HTTP.new(*($stash_host.split(':')))
  req = Net::HTTP.const_get(method.to_s.capitalize.to_sym).new("http://#{$stash_host}/rest/#{path}")
  req.basic_auth($stash_user, $stash_pass)
  if body then
    req.body = body.to_json
    req['Content-Type'] = 'application/json'
  end
  puts "REQUEST: #{method} http://#{$stash_host}/rest/#{path} #{body.inspect}" if ENV['DEBUG']
  resp = http.request(req)
  puts "RESPONSE: #{resp.code} #{resp.body.inspect}" if ENV['DEBUG']
  abort "Server failed to respond" if resp.code.nil?
  abort resp.body if resp.code.to_i >= 500
  return if resp.code.to_i >= 300
  return if resp.body.nil?
  JSON.parse(resp.body)
end

def set_user_keys(uid, keys)
  data = request(:get, "ssh/1.0/keys?user=#{uid}")
  return unless data

  keys_ipa = keys.map{|k| Key.new(k)}
  keys_stash = data['values'].map{|k| Key.new(k)}
  keys_stash_from_ipa = keys_stash.find_all{|k| k.ipa_key?}

  keys_delete = keys_stash_from_ipa - keys_ipa
  keys_add = keys_ipa - keys_stash

  keys_add.each do |key|
    request(:post, "ssh/1.0/keys?user=#{uid}", {'text' => key.to_s})
  end
  keys_delete.each do |key|
    next unless key.id
    request(:delete, "ssh/1.0/keys/#{key.id}")
  end
end

def update_keys(full = false)
  sssdconf = iniread('/etc/sssd/sssd.conf')
  ipaconf = iniread('/etc/ipa/default.conf')
  ldap_base = ipaconf['global']['basedn']
  domain = ipaconf['global']['domain']
  domains = sssdconf.keys.grep(/^domain\//).collect {|section_name| section_name.sub(/^domain\//, '')}
  if domains.nil? then
    raise(ArgumentError, 'No domains found in SSSD')
  end
  if domain.nil? then
    domain = domains[0]
  end
  domain_conf = sssdconf["domain/#{domain}"]

  last_entry_time = (!full and File.exists?($last_sync_file)) ? File.read($last_sync_file) : '20000101000000Z'

  entries = []
  ldapServers = Array.new
  unless domain_conf['ldap_uri'].nil? then
    domain_conf['ldap_uri'].split(/,+/).each do |ldap_uri_string|
      ldapServers << URI(ldap_uri_string).host
    end
  else
    ldapServers = getLdapServers(domain)
  end
  ldapServers.each do |host|

    begin
      Timeout::timeout(5) do
        #ldap = Net::LDAP.new(:host => host, :port => 636, :encryption => :simple_tls, :auth => { :method => :simple, :username => domain_conf['ldap_default_bind_dn'], :password => domain_conf['ldap_default_authtok'] }, :base => domain_conf['ldap_search_base'])
        ldap = Net::LDAP.new(:host => host, :port => 636, :encryption => :simple_tls, :base => domain_conf['ldap_search_base'])
        filter = Net::LDAP::Filter.ge('modifyTimestamp', last_entry_time) & Net::LDAP::Filter.eq('ipaSshPubKey', '*')
        ldap.search(:base => ldap_base, :filter => filter, :attributes => ['uid','ipaSshPubKey','modifyTimestamp']) do |entry|
          next if entry['modifyTimestamp'].first == last_entry_time # ldap doesnt have a `>`, only `>=`, so we have to manually test the `=` bit
          puts "USER KEYS: #{entry['uid'].first} :: #{entry['ipaSshPubKey'].inspect}" if ENV['DEBUG']
          entries << entry
        end
      end
    rescue Timeout::Error => e
      $stderr.puts "Timeout communicating with #{host}:636"
      next
    rescue => e
      $stderr.puts "Unknown error communicating with #{host}:636: #{e.to_s}"
      next
    end
    break
  end
  entries.each do |entry|
    last_entry_time = entry['modifyTimestamp'].first.to_s if entry['modifyTimestamp'].first.to_s > last_entry_time
    set_user_keys(entry['uid'].first, entry['ipaSshPubKey']) if entry['ipaSshPubKey'].size > 0
  end

  File.open($last_sync_file, 'w'){|fh| fh.write(last_entry_time)}
end

def getLdapServers (domain) 
  dns = Resolv::DNS.new
  ldapServers = Array.new
  dns.each_resource("_ldap._tcp.#{domain}", Resolv::DNS::Resource::IN::SRV) do |resource|
    ldapServers << resource.target.to_s
  end
  ldapServers
end

update_keys