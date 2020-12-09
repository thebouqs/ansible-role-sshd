![.github/workflows/ci.yml](https://github.com/thebouqs/ansible-role-sshd/workflows/.github/workflows/ci.yml/badge.svg)
sshd
=========

This Ansbile Role will install, configure, and manage sshd (OpenSSH).

Requirements
------------

This role has no external dependancies.


Role Variables
--------------

**NOTE: All defaults shown before are for the role. The SSH Server has defaults that are used for any setting not set explicitly by the user*.*

### sshd_service_name
This is the name of the serivce to manage (ie sshd.service), it distribution specifc though **most** use sshd.service.

**default**: '' Set to distribution specific value by default

**type**: string

**example**:
```yaml
sshd_service_name: 'sshd.service'
```

### sshd_service_enable
This controls enabling the service to start during boot.

**default**: true

**type**: boolean

**example**:
```yaml
sshd_service_enable: false
```

### sshd_service_ensure
This controls the running state of the service, valid values are `started`, `stopped`, `restarted`, and `reloaded`.

**default**: 'started'

**type**: string

**example**:
```yaml
sshd_service_ensure: 'started'
```

### sshd_package_version
Controls the version of the package to install. Allows for ensuring the latest available package, from configured distribution software repositories, is installed.

**default**: `'latest'`

**type**: string

**example**:
```yaml
sshd_package_version: '8.*' # pin the version to 8 but any minor and patch
```

### sshd_package_name
The name of the OpenSSH server package to install.

**default**: `''` This defaults to the distribution specific name

**type**: string

**example**:
```yaml
sshd_package_name: 'openssh-server'
```


### sshd_config_file_path
The absolute path to the SSH Server configuration file.

**default**: `'/etc/ssh/sshd_config'`

**type**: string

**example**:
```yaml
sshd_config_file_path: '/etc/ssh/sshd_config'
```

### sshd_config_file_owner
Username of the owner to set the SSH Server configuration file to.

**default**: `'root'`

**type**: string

**example**:
```yaml
sshd_cnofig_file_owner: 'root'
```


### sshd_config_file_group
Group name to the set the SSH Server configuration file to.

**default**: `'root'`

**type**: string

**example**:
```yaml
sshd_config_file_group: 'root'
```

### sshd_config_file_mode
The file permissions to set the SSH Server configuration file to.

**default**: `''` Set to a distribution specific value

**type**: string

**example**:
```yaml
sshd_config_file_mode: 'ug=rw,o-rwx' # in octel 660
```

### sshd_ports
The ports that OpenSSH should listin on.

**default**: `['22']`

**type**: list

**example**:
```yaml
sshd_ports:
  - 22
  - 2022
```

### sshd_proto
The SSH server protocol ie 1 and/or 2.

***You should really only ever use 2***.

**default**: `'2'`

**type**: string

**example**:
```yaml
sshd_proto: '2'
```

### sshd_address_family
Then IP Address family to enable IPv4 (inet), IPv6 (inet6), or Both (any).

**default**: `''` Note OpenSSH defaults to both if no value is set in the configuration!

**type**: string

**example**:
```yaml
sshd_address_family: 'inet' # enable IPv4 only
```

### sshd_listen_address
The address(s) to enable SSH to listen on.

**default**: `[]` Note OpenSSH defaults to 0.0.0.0 and :: for IPv4 and IPv6 respectively which is **all** interfaces when no value is configured

**type**: list

**example**:
```yaml
sshd_listen_address: ['127.0.0.1', '192.168.1.22']
```

### sshd_host_key
The absolute path to the SSH Host Key(s).

**default**: `[]` The role will set distribution specific values

**type**: list of strings

**example**:
```yaml
sshd_host_keys:
  - '/etc/ssh_sshd_host/ecdsa_key'
  - '/etc/ssh_ssh_host_ed25519_key'
```

### sshd_key_regeneration_interval
Used to control rekey intervals for SSH-1.

***When set on SSH-2 it has no effect and results in deprecation warnings in the logs***

**default**: `''`

**type**: string

**example**:
```yaml
sshd_key_regeneration_interval: '3600'
```

### sshd_server_key_bits
Used to set the bit size to use during rekey in SSH-1

***Whe set on SSH-2 it has no effect and results in deprecation warnings in the logs***

**default**: `''`

**type**: string

**example**:
```yaml
sshd_server_key_bits: '1024'
```

### sshd_syslog_facility
Sets the [SYSLOG Facitity Keyword](https://en.wikipedia.org/wiki/Syslog#Facility)

**default**: `''` This role will set a distribution specific variable if one is not provided

**type**: string

**example**:
```yaml
sshd_syslog_facility: 'AUTHPRIV'
```

### sshd_log_level
Sets the log level for the service. It must be a keyword from the [SYSLOG Severity Level List](https://en.wikipedia.org/wiki/Syslog#Severity_level).

**default**: `'INFO'`

**type**: string

**example**:
```yaml
sshd_log_level: 'VERBOSE'
```

### sshd_login_grace_time
How long to wait for a login attempt before closing the session.

**default**: `''`

**type**: string

**example**:
```yaml
sshd_login_grace_time: '120s'
```

### sshd_permit_root_login
Whether or not to permit root logins, and if allowed with password, with key only, or forced-commands.
If set it must be one of the following:
  * yes (true)
  * prohibit-password (same as deprecated without-password)
  * forced-commands-only
  * no (false)

**default**: `''` A distribution specific value might be set if a value is not provided

**type**: string

**example**:
```yaml
sshd_permit_root_login: 'prohibit-password'
```

### sshd_strict_modes
Specifies whether sshd(8) should check file modes and ownership of the user's files and home directory before accepting login.

**default**: `''`

**type**: boolean

**example**:
```yaml
sshd_strict_modes: true
```

### sshd_max_auth_tries
Specifies the maximum number of authentication attempts permitted per connection.

**default**: `''`

**type**: integer

**example**:
```yaml
sshd_max_auth_tries: 6
```

### sshd_rsa_authentication
Whether to allow RSA Based Authentication.

**default**: `''`

**type**: boolean

**example**:
```yaml
sshd_rsa_authentication: false
```

### sshd_pubkey_accepted_key_types
Specifies the key types that will be accepted for public key authentication.

**default**: `[]`

**type**: list

**example**:
```yaml
sshd_pubkey_accepted_key_types:
  - 'ecdsa-sha2-nistp256-cert-v01@openssh.com'
  - 'ssh-ed25519-cert-v01@openssh.com'
  - 'sk-ecdsa-sha2-nistp256-cert-v01@openssh.com'
```

### sshd_pubkey_authentication
Whether public key authentication is allowed.

**default**: `''`

**type**: boolean

**example**:
```yaml
sshd_pubkey_authentication: true
```
### sshd_authorized_keys_file
The file that contains the public keys used for user authentication.

**default**: `''` The role will likely set a distribution specific default

**type**: string

**example**:
```yaml
sshd_authorized_keys_file: "%h/.ssh/authorized_keys"
```

### sshd_authorized_keys_command
A program to be used to look up the user's public keys.

**default**: `''`

**type**: string

**example**:
```yaml
sshd_authorized_keys_command: '/usr/bin/sss_ssh_authorizedkeys'
```

### sshd_authorized_keys_command_user
The user under whose account the AuthorizedKeysCommand is run.

**default**: `''`

**type**: string

**example**:
```yaml
sshd_authorized_keys_command_user: sssd
```

### sshd_host_based_authentication
Whether rhosts or /etc/hosts.equiv authentication together with successful public key client host authentication is allowed.

**default**: `''`

**type**: boolean

**example**:
```yaml
sshd_host_based_authentication: false
```

### sshd_ignore_user_known_hosts
whether sshd(8) should ignore the user's ~/.ssh/known_hosts during HostbasedAuthentication and use only the system-wide known hosts
file /etc/ssh/known_host.

**default**: `''`

**type**: boolean

**example**:
```yaml
sshd_ignore_user_known_hosts: true
```

### sshd_ignore_rhosts
Specifies that .rhosts and .shosts files will not be used in HostbasedAuthentication.

**default**: `''`

**type**: boolean

**example**:
```yaml
sshd_ignore_rhosts: true
```

### sshd_rhosts_rsa_authentication
Whether to use RSA based Rhost Authentication. This option is deprecated in OpenSSH.

**default**: `''`

**type**: boolean

**example**:
```yaml
sshd_rhosts_rsa_authentication: false
```

### sshd_authentication_methods
The authentication methods that must be successfully completed for a user to be granted access.

**default**: `[]`

**type**: list

**example**:
```yaml
sshd_authentication_methods:
  - 'gssapi-with-mic'
  - 'publickey'
```

### sshd_password_authentication
Specifies whether password authentication is allowed.

**default**: `''` the role might set distribution specific default

**type**: boolean

**example**:
```yaml
sshd_password_authentication: true
```

### sshd_challenge_response_authentication
Whether challenge-response authentication is allowed.

**default**: `''` The role will likely set a distribution specific value

**type**: boolean

**example**:
```yaml
sshd_challenge_response_authentication: true
```

### sshd_permit_empty_passwords
When password authentication is allowed, it specifies whether the server allows login to accounts with empty password strings.

**default**: `''` The role will likely set a distribution specific value

**type**: boolean

**example**:
```yaml
sshd_permit_empty_passwords: false
```

### sshd_kerberos_authentication
Specifies whether the password provided by the user for PasswordAuthentication will be validated through the Kerberos KDC

**default**: `''`

**type**: boolean

**example**:
```yaml
sshd_kerberos_authentication: true
```

### sshd_kerberos_or_local_passwd
If password authentication through Kerberos fails then the password will be validated via any additional
local mechanism such as /etc/passwd.

**default**: `''`

**type**: boolean

**example**:
```yaml
sshd_kerberos_or_local_passwd: false
```

### sshd_kerberos_ticket_cleanup
Specifies whether to automatically destroy the user's ticket cache file on logout

**default**: `''`

**type**: boolean

**example**:
```yaml
sshd_kerberos_ticket_cleanup: true
```
### sshd_kerberos_get_afs_token
If AFS is active and the user has a Kerberos 5 TGT, attempt to acquire an AFS token before accessing the user's home directory.

**default**: `''`

**type**: boolean

**example**:
```yaml
sshd_kerberos_get_afs_token: false
```

### sshd_gssapi_authentication
Specifies whether user authentication based on GSSAPI is allowed.

**default**: `''` The role will likely set a distribution specific setting

**type**: boolean

**example**:
```yaml
sshd_gssapi_authentication: false
```

### sshd_gssapi_cleanup_credentials
Specifies whether to automatically destroy the user's credentials cache on logout.

**default**: `''` Likely a distribution specific value will be set by role

**type**: boolean

**example**:
```yaml
sshd_gssapi_cleanup_credentials: true
```

### sshd_use_pam
Enables the Pluggable Authentication Module interface.

**default**: `''` The role will set a distribution specific value

**type**: boolean

**example**:
```yaml
sshd_use_pam: true
```

### sshd_accept_env
Specifies what environment variables sent by the client will be copied into the session's environment.

**default**: `[]` The role will likely set a distribution specific value

**type**: list

**example**:
```yaml
sshd_accept_env:
  - 'LANG'
  - 'LC_*'
```

### sshd_allow_tcp_forwarding
Specifies whether TCP forwarding is permitted. Valid options are, yes (true), no (false), all, local, or remote.

**default**: `''`

**type**: string

**example**:
```yaml
sshd_allow_tcp_forwarding: true
```

### sshd_x11_forwarding
Specifies whether X11 forwarding is permitted.

**default**: `''`

**type**: boolean

**example**:
```yaml
sshd_x11_forwarding: true
```

### sshd_x11_use_localhost
Specifies whether the SSH Server should bind the X11 forwarding server to the loopback address or to the wildcard address.

**default**: `''`

**type**: boolean

**example**:
```yaml
sshd_x11_use_localhost: true
```

### sshd_x11_display_offset
Specifies the first display number available for the SSH Server's X11 forwarding.

**default**: `''`

**type**: integer

**example**:
```yaml
sshd_x11_display_offset: 20
```

### sshd_print_motd
Specifies whether the SSH Server should print /etc/motd when a user logs in interactively.

**default**: `''`

**type**: boolean

**example**:
```yaml
sshd_print_motd: false
```

### sshd_print_last_log
Specifies whether the SSH Server should print the date and time of the last user login when a user logs in interactively.

**default**: `''`

**type**: boolean

**example**:
```yaml
sshd_print_last_log: true
```

### sshd_tcp_keep_alive
Specifies whether the system should send TCP keepalive messages to the other side.

**default**: `''`

**type**: boolean

**example**:
```yaml
sshd_tcp_keep_alive: true
```

### sshd_use_privilege_separation
Specifies whether the SSH Server separates privileges by creating an unprivileged child process to deal with incoming network traffic. Valid options are
yes (true), no (false), sandbox.

***Note this option is deprecated in newer releases of OpenSSH and defaults to enabled***

**default**: `''` the role will possibly set a distribution specific default (CentOS 7)

**type**: string

**example**:
```yaml
sshd_use_privilege_separation: sandbox
```

### sshd_permit_user_environment
Specifies whether ~/.ssh/environment and environment= options in ~/.ssh/authorized_keys are processed by the SSH Server. Valid options are
yes (true), no (false) or comma sperated list (LANG,LC\_\*).

**default**: `''`

**type**: boolean or string

**example**:
```yaml
sshd_permit_user_environment: true
```

### sshd_compression
Specifies whether compression is enabled after the user has authenticated successfully.
Valid options are yes (true), delayed (a legacy alias of yes), and no (false).

**default**: `''` The role is likely to set a distribution specific default

**type**: boolean or string

**example**:
```yaml
sshd_compression: true
```

### sshd_client_alive_interval
Sets a timeout interval in seconds after which if no data has been received from the client, the SSH Server will send a message through the encrypted
channel to request a response from the client.

**default**: `''`

**type**: string

**example**:
```yaml
sshd_client_alive_interval: '120m'
```

### sshd_client_alive_count_max
Sets the number of client alive messages which may be sent without the SSH Server receiving any messages back from the client.

**default**: `''`

**type**: integer

**example**:
```yaml
sshd_client_alive_count_max: 3
```

### sshd_use_dns
Specifies whether the SSH Server should look up the remote host name, and to check that the resolved host name for the remote IP address maps back to
the very same IP address.

**default**: `''`

**type**: boolean

**example**:
```yaml
sshd_use_dns: true
```

### sshd_max_startups
Specifies the maximum number of concurrent unauthenticated connections to the SSH daemon.

**default**: `''`

**type**: string

**example**:
```yaml
sshd_max_startups: '10:30:60' # after ten unauthenticated connections drop 30% increasing linearly till 60 connections then drop 100%
```

### sshd_max_sessions
Specifies the maximum number of open shell, login or subsystem (e.g. sftp) sessions permitted per network connection.

**default**: `''`

**type**: integer

**example**:
```yaml
sshd_max_sessions: 10
```

### sshd_permit_tunnel
Specifies whether tun device forwarding is allowed.  The argument must be yes (true), point-to-point (layer 3), ethernet (layer 2), or no (false).

**default**: `''`

**type**: string

**example**:
```yaml
sshd_permit_tunnel: true
```

### sshd_chroot_directory
Specifies the pathname of a directory to chroot (change root) to after authentication.

**default**: `''`

**type**: string

**example**:
```yaml
sshd_chroot_directory: '%h'
```

### sshd_force_command
Forces the execution of the command specified by ForceCommand, ignoring any command supplied by the client and ~/.ssh/rc if present.

**default**: `''`

**type**: string

**example**:
```yaml
sshd_force_command: "/usr/local/execute_task.sh"
```

### sshd_allow_agent_forwarding
Specifies whether ssh-agent forwarding is permitted.

**default**: `''`

**type**: boolean

**example**:
```yaml
sshd_allow_agent_forwarding: true
```

### sshd_banner
The contents of the specified file are sent to the remote user
before authentication is allowed.

**default**: `''`

**type**: string

**example**:
```yaml
sshd_banner: "This is a secure system, unauthorized access is prohibited"
```

### sshd_xauth_location
Specifies the full pathname of the xauth program, or none to
not use one.

**default**: `''`

**type**: string

**example**:
```yaml
sshd_xauth_location: '/usr/bin/xauth'
```

### sshd_ciphers
Specifies the ciphers allowed.

**default**: '[]'

**type**: list

**example**:
```yaml
sshd_ciphers:
  - 'chacha20-poly1305@openssh.com'
  - 'aes256-gcm@openssh.com'
  - 'aes128-gcm@openssh.com'
  - 'aes256-ctr'
  - 'aes192-ctr'
  - 'aes128-ctr'
```

### sshd_kex_algorithms
Specifies the available KEX (Key Exchange) algorithms.

**default**: `''`

**type**: list

**example**:
```yaml
sshd_kex_algorithms:
  - 'curve25519-sha256@libssh.org'
  - 'ecdh-sha2-nistp521'
  - 'ecdh-sha2-nistp384'
  - 'ecdh-sha2-nistp256'
  - 'diffie-hellman-group-exchange-sha256'
```

### sshd_macs
Specifies the available MAC (message authentication code) algorithms.

**default**: `[]`

**type**: list

**example**:
```yaml
sshd_macs:
  - 'hmac-sha2-512-etm@openssh.com'
  - 'hmac-sha2-256-etm@openssh.com'
  - 'umac-128-etm@openssh.com'
  - 'hmac-sha2-512'
  - 'hmac-sha2-256'
  - 'umac-128@openssh.com'
```
### sshd_deny_users
Specifies a list of user name patterns to explicitly deny login.

**default**: `[]`

**type**: list

**example**:
```yaml
sshd_deny_users:
  - 'bad_dude'
  - 'cron'
  - 'other_bad_dude'
```

### sshd_deny_groups
Specifies a list of groups to disallow login for users whose group membership matches.

**default**: `[]`

**type**: list

**example**:
```yaml
sshd_deny_groups:
  - 'lions'
  - 'tigers'
  - 'bears'
  - 'oh_my'
```

### sshd_allow_users 
A list of user name patterns that are explicitly and **only** allowed to login.

**default**: `[]`

**type**: list

**example**:
```yaml
sshd_allow_users:
  - 'dorthy'
  - 'cowardly_lion'
  - 'scarecrow'
  - 'tin_man'
```

### sshd_allow_groups
A list of groups that whose members are explicitly and **only** are allowed to login.

**default**: `[]`

**type**: list

**example**:
```yaml
sshd_allow_groups:
  - 'avengers'
  - 'gotg'
  - 'x-factor'
  - 'justice_league'
```

### sshd_revoked_keys
Specifies revoked public keys file, or none to not use one.

**default**: `[]`

**type**: list

**example**:
```yaml
sshd_revoked_keys:
  - '/etc/ssh/key_revocation_list'
```

### sshd_host_certificate
Specifies a file containing a public host certificate.

**default**: `[]`

**type**: list

**example**:
```yaml
sshd_host_certificate:
  - '/etc/ssh/sshd_pub.pem'
```

### sshd_trusted_user_ca_keys
Specifies a file containing public keys of certificate authorities that are trusted to sign user certificates for authentica‐
tion, or none to not use one.

**default**: `[]`

**type**: list

**example**:
```yaml
sshd_trusted_user_ca_keys:
  - '/etc/ssh/trusted_ca.pem'
```

### sshd_authorized_principals_file
Specifies a file that lists principal names that are accepted for certificate authentication.

**default**: `[]`

**type**: list

**example**:
```yaml
sshd_authorized_principals_file:
  - '/etc/ssh/authorzied_principals'
```

### sshd_subsystem
Configures an external subsystem (e.g. file transfer daemon).

**default**: `{}`

**type**: dictionary

**example**:
```yaml
sshd_subsystem:
  sftp: '/usr/lib/openssh/sftp-server'
```

### sshd_match
Introduces a conditional block.  If all of the criteria on the Match line are satisfied, the keywords on the following lines override those
set in the global section of the config file, until either another Match line or the end of the file.  If a keyword appears in multiple Match
blocks that are satisfied, only the first instance of the keyword is applied.

**default**: `{}`

**type**: dictionary

**example**:
```yaml
sshd_match:
  'User bastion':
    - 'PermitTTY no'
    - 'MaxSessions 0'
```

Dependencies
------------

This role has no dependancies on other Ansible Roles.

Example Playbook
----------------

Including an example of how to use your role (for instance, with variables
passed in as parameters) is always nice for users too:
```yaml
    - hosts: servers
      tasks:
        - include_role:
            name: sshd
```

Development
-----------
This Ansible Role uses the [Molecule test-framework](https://molecule.readthedocs.io/en/stable/). 
It is highly recommended that you use setup a python virtual environment for this tool and its dependancies.

### Setting up Devleopment Environment
```shell
python3 -m venv molecule3

source molecule3/bin/activate

pip3 install --upgrade pip setuptools
pip3 install wheel
cd ansible-role-sshd
pip3 install -r requirements-test.txt
```

### Testing Default Scenario
```shell
molecule test
```

License
-------

BSD

Author Information
------------------

[devops@thebouqs.com](mailto:devops@thebouqs.com)

