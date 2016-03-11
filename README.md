stash-ipa-sshkeys
=================

Synchronise SSH Keys stored in IPA to Atlassian Stash <https://www.atlassian.com/software/stash>

This was found a while ago as a gist in a forum post, and has been "improved" on to do what we need it to do. Mostly making it work on the *ancient* version of Ruby that comes on CentOS6.5

Basically, we set it up to run every 5 minutes during business hours via cron and it keeps our SSH keys that
are uploaded to IPA sync'd with STASH so users only need to upload to one place. It would be wonderful if STASH
could just look directly in the LDAP directory where IPA stores them, but for now this is needed.

Order of operations...
* Parse various IPA config files (ipa.conf / sssd.conf) to get configurations
* If there is not a hardcoded LDAP URI (normal), look up the LDAP servers via DNS SRV records
* Connect to those LDAP servers either anonymous or with bind credentials (if security regulations require removing anonymous)
* Get a list of user accounts with SSH keys that have changed since the last time it ran
* Sync the SSH keys to Stash using API calls.

Note this requires a fairly powerful account (one that can modify other user's keys) in STASH, but just a normal user
account in LDAP.

Requirements (at least on CentOS6)
-----
* `yum install ruby rubygem-json`
* `gem install net-ldap -v 0.8.0`  _(sorry, this is not an RPM at least in EPEL or RHEL)_
   * NOTE: You can obtain rubygem-net-ldap as an rpm from Puppet Dependencies repo https://yum.puppetlabs.com/el/6/dependencies/x86_64/ 


Originally at: https://jira.atlassian.com/browse/CWD-2895

See Also: https://gist.github.com/TJM/d0ed12f3b20ebe2d55ab
