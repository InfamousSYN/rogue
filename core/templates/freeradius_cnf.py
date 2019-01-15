#!/usr/bin/python

freeradius_radiusd_conf = '''
# -*- text -*-
##
## radiusd.conf	-- FreeRADIUS server configuration file - 3.0.13
##
##

prefix = /usr
exec_prefix = /usr
sysconfdir = /etc
localstatedir = /var
sbindir = /usr/sbin
logdir = %s
raddbdir = /etc/freeradius-wpe/3.0
radacctdir = /var/log/freeradius-wperadacct

#  name of the running server.  See also the "-n" command-line option.
name = freeradius

#  Location of config and logfiles.
confdir = /etc/freeradius-wpe/3.0
modconfdir = /etc/freeradius-wpe/3.0/mods-config
certdir = %s
cadir   = %s
run_dir = /var/run/freeradius

# Should likely be /varlib/radiusd
db_dir = /etc/freeradius-wpe/3.0

libdir = /usr/lib/freeradius-wpe

#  pidfile: Where to place the PID of the RADIUS server.
pidfile = /var/run/freeradius/freeradius.pid

#
#  correct_escapes: use correct backslash escaping
correct_escapes = true

#  max_request_time: The maximum time (in seconds) to handle a request.
max_request_time = 30

#  cleanup_delay: The time to wait (in seconds) before cleaning up
#  a reply which was sent to the NAS.
cleanup_delay = 5

#  max_requests: The maximum number of requests which the server keeps
#  track of.  This should be 256 multiplied by the number of clients.
#  e.g. With 4 clients, this number should be 1024.
max_requests = 16384

#  hostname_lookups: Log the names of clients or just their IP addresses
hostname_lookups = no

#
#  Logging section.  The various "log_*" configuration items
#  will eventually be moved here.
#
log {
	#
	#  Destination for log messages.  This can be one of:
	#
	#	files - log to "file", as defined below.
	#	syslog - to syslog (see also the "syslog_facility", below.
	#	stdout - standard output
	#	stderr - standard error.
	destination = files
	colourise = yes

	#  The logging messages for the server are appended to the tail of this file if destination == "files"
	file = %s

	#  Which syslog facility to use
	syslog_facility = daemon

	#  Log the full User-Name attribute, as it was found in the request. allowed values: {no, yes}
	stripped_names = no

	#  Log authentication requests to the log file. allowed values: {no, yes}
	auth = yes

	#  Log passwords with the authentication requests. allowed values: {no, yes}
	#  auth_badpass  - logs password if it's rejected
	#  auth_goodpass - logs password if it's correct
	auth_badpass = %s
	auth_goodpass = %s

	#  Log additional text at the end of the "Login OK" messages.
	#  for these to work, the "auth" and "auth_goodpass" or "auth_badpass"
	#  configurations above have to be set to "yes".
    # msg_goodpass = ""
	# msg_badpass = ""

	#  The message when the user exceeds the Simultaneous-Use limit.
	msg_denied = "You are already logged in - access denied"
}

#  The program to execute to do concurrency checks.
checkrad = /usr/sbin/checkrad

# Wireless Pawn Edition log file
wpelogfile = %s

# SECURITY CONFIGURATION
security {
	#  chroot: directory where the server does "chroot".
	# chroot = /path/to/chroot/directory

	# user/group: The name (or #number) of the user/group to run radiusd as.
	# user = freerad
	# group = freerad

	#  Core dumps are a bad thing.  This should only be set to 'yes' if you're debugging a problem with the server.
	allow_core_dumps = no

	#
	#  max_attributes: The maximum number of attributes
	#  permitted in a RADIUS packet.  Packets which have MORE
	#  than this number of attributes in them will be dropped.
	max_attributes = 200

	#  reject_delay: When sending an Access-Reject, it can be
	#  delayed for a few seconds.  This may help slow down a DoS
	#  attack.  It also helps to slow down people trying to brute-force
	#  crack a users password.
	reject_delay = 1

	#  status_server: Whether or not the server will respond
	#  to Status-Server requests.
	status_server = yes
}

# PROXY CONFIGURATION
#
#  proxy_requests: Turns proxying of RADIUS requests on or off.
proxy_requests  = yes
$INCLUDE proxy.conf


# CLIENTS CONFIGURATION
#
#  Client configuration is defined in "clients.conf".
$INCLUDE clients.conf

# THREAD POOL CONFIGURATION
thread pool {
	#  Number of servers to start initially --- should be a reasonable
	#  ballpark figure.
	start_servers = 5

	#  Limit on the total number of servers running.
	max_servers = 32

	#  Server-pool size regulation.  Rather than making you guess
	#  how many servers you need, FreeRADIUS dynamically adapts to
	#  the load it sees, that is, it tries to maintain enough
	#  servers to handle the current load, plus a few spare
	#  servers to handle transient load spikes.
	min_spare_servers = 3
	max_spare_servers = 10

	#  When the server receives a packet, it places it onto an
	#  internal queue, where the worker threads (configured above)
	#  pick it up for processing.  The maximum size of that queue
	#  is given here.
	# max_queue_size = 65536

	#  There may be memory leaks or resource allocation problems with
	#  the server.  If so, set this value to 300 or so, so that the
	#  resources will be cleaned up periodically.
	max_requests_per_server = 0

	#  Automatically limit the number of accounting requests.
	#  This configuration item tracks how many requests per second
	#  the server can handle.  It does this by tracking the
	#  packets/s received by the server for processing, and
	#  comparing that to the packets/s handled by the child
	#  threads.
	auto_limit_acct = no
}

######################################################################
#
#  SNMP notifications.  Uncomment the following line to enable
#  snmptraps.  Note that you MUST also configure the full path
#  to the "snmptrap" command in the "trigger.conf" file.
#
#$INCLUDE trigger.conf

# MODULE CONFIGURATION
#
#  The names and configuration of each module is located in this section.
#
#  After the modules are defined here, they may be referred to by name,
#  in other sections of this configuration file.
#
modules {
	#
	#  Each module has a configuration as follows:
	#
	#	name [ instance ] {
	#		config_item = value
	#		...
	#	}
	#
	#  The 'name' is used to load the 'rlm_name' library
	#  which implements the functionality of the module.
	#
	#  The 'instance' is optional.  To have two different instances
	#  of a module, it first must be referred to by 'name'.
	#  The different copies of the module are then created by
	#  inventing two 'instance' names, e.g. 'instance1' and 'instance2'
	#
	#  The instance names can then be used in later configuration
	#  INSTEAD of the original 'name'.  See the 'radutmp' configuration
	#  for an example.
	#

	#
	#  As of 3.0, modules are in mods-enabled/.  Files matching
	#  the regex /[a-zA-Z0-9_.]+/ are loaded.  The modules are
	#  initialized ONLY if they are referenced in a processing
	#  section, such as authorize, authenticate, accounting,
	#  pre/post-proxy, etc.
	#
	$INCLUDE mods-enabled/
}

# Instantiation
#
#  This section orders the loading of the modules.  Modules
#  listed here will get loaded BEFORE the later sections like
#  authorize, authenticate, etc. get examined.
#
#  This section is not strictly needed.  When a section like
#  authorize refers to a module, it's automatically loaded and
#  initialized.  However, some modules may not be listed in any
#  of the following sections, so they can be listed here.
#
#  Also, listing modules here ensures that you have control over
#  the order in which they are initialized.  If one module needs
#  something defined by another module, you can list them in order
#  here, and ensure that the configuration will be OK.
#
#  After the modules listed here have been loaded, all of the modules
#  in the "mods-enabled" directory will be loaded.  Loading the
#  "mods-enabled" directory means that unlike Version 2, you usually
#  don't need to list modules here.
#
instantiate {
	#
	# We list the counter module here so that it registers
	# the check_name attribute before any module which sets
	# it
#	daily

	# subsections here can be thought of as "virtual" modules.
	#
	# e.g. If you have two redundant SQL servers, and you want to
	# use them in the authorize and accounting sections, you could
	# place a "redundant" block in each section, containing the
	# exact same text.  Or, you could uncomment the following
	# lines, and list "redundant_sql" in the authorize and
	# accounting sections.
	#
	#  The "virtual" module defined here can also be used with
	#  dynamic expansions, under a few conditions:
	#
	#  * The section is "redundant", or "load-balance", or
	#    "redundant-load-balance"
	#  * The section contains modules ONLY, and no sub-sections
	#  * all modules in the section are using the same rlm_
	#    driver, e.g. They are all sql, or all ldap, etc.
	#
	#  When those conditions are satisfied, the server will
	#  automatically register a dynamic expansion, using the
	#  name of the "virtual" module.  In the example below,
	#  it will be "redundant_sql".  You can then use this expansion
	#  just like any other:
	#
	#
	#  In this example, the expansion is done via module "sql1",
	#  and if that expansion fails, using module "sql2".
	#
	#  For best results, configure the "pool" subsection of the
	#  module so that "retry_delay" is non-zero.  That will allow
	#  the redundant block to quickly ignore all "down" SQL
	#  databases.  If instead we have "retry_delay = 0", then
	#  every time the redundant block is used, the server will try
	#  to open a connection to every "down" database, causing
	#  problems.
	#
	#redundant redundant_sql {
	#	sql1
	#	sql2
	#}
}

######################################################################
#
#  Policies are virtual modules, similar to those defined in the
#  "instantiate" section above.
#
#  Defining a policy in one of the policy.d files means that it can be
#  referenced in multiple places as a *name*, rather than as a series of
#  conditions to match, and actions to take.
#
#  Policies are something like subroutines in a normal language, but
#  they cannot be called recursively. They MUST be defined in order.
#  If policy A calls policy B, then B MUST be defined before A.
#
######################################################################
policy {
	$INCLUDE policy.d/
}

######################################################################
#
#	Load virtual servers.
#
#	This next $INCLUDE line loads files in the directory that
#	match the regular expression: /[a-zA-Z0-9_.]+/
#
#	It allows you to define new virtual servers simply by placing
#	a file into the raddb/sites-enabled/ directory.
#
$INCLUDE sites-enabled/

'''

freeradius_eap_conf = '''
# -*- text -*-
##
##  eap.conf -- Configuration for EAP types (PEAP, TTLS, etc.)
##
##	$Id: 427016c66da92b5aa87ac784e74550c4e723c0cd $

#######################################################################
#
#  Whatever you do, do NOT set 'Auth-Type := EAP'.  The server
#  is smart enough to figure this out on its own.  The most
#  common side effect of setting 'Auth-Type := EAP' is that the
#  users then cannot use ANY other authentication method.
#
eap {
	#  Invoke the default supported EAP type when
	#  EAP-Identity response is received.
	#
	#  The incoming EAP messages DO NOT specify which EAP
	#  type they will be using, so it MUST be set here.
	#
	#  For now, only one default EAP type may be used at a time.
	#
	#  If the EAP-Type attribute is set by another module,
	#  then that EAP type takes precedence over the
	#  default type configured here.
	#
	default_eap_type = %s

	#  A list is maintained to correlate EAP-Response
	#  packets with EAP-Request packets.  After a
	#  configurable length of time, entries in the list
	#  expire, and are deleted.
	#
	timer_expire     = 60

	#  There are many EAP types, but the server has support
	#  for only a limited subset.  If the server receives
	#  a request for an EAP type it does not support, then
	#  it normally rejects the request.  By setting this
	#  configuration to "yes", you can tell the server to
	#  instead keep processing the request.  Another module
	#  MUST then be configured to proxy the request to
	#  another RADIUS server which supports that EAP type.
	#
	#  If another module is NOT configured to handle the
	#  request, then the request will still end up being
	#  rejected.
	ignore_unknown_eap_types = no

	# Cisco AP1230B firmware 12.2(13)JA1 has a bug.  When given
	# a User-Name attribute in an Access-Accept, it copies one
	# more byte than it should.
	#
	# We can work around it by configurably adding an extra
	# zero byte.
	cisco_accounting_username_bug = no

	#
	#  Help prevent DoS attacks by limiting the number of
	#  sessions that the server is tracking.  For simplicity,
	#  this is taken from the "max_requests" directive in
	#  radiusd.conf.
	max_sessions = 16384

	# Supported EAP-types

	#
	#  We do NOT recommend using EAP-MD5 authentication
	#  for wireless connections.  It is insecure, and does
	#  not provide for dynamic WEP keys.
	#
	md5 {
	}

	#
	# EAP-pwd -- secure password-based authentication
	#
	pwd {
		group = 19

		#
		server_id = theserver@example.com

		#  This has the same meaning as for TLS.
		fragment_size = 1020

		# The virtual server which determines the
		# "known good" password for the user.
		# Note that unlike TLS, only the "authorize"
		# section is processed.  EAP-PWD requests can be
		# distinguished by having a User-Name, but
		# no User-Password, CHAP-Password, EAP-Message, etc.
		virtual_server = "inner-tunnel"
	}

	# Cisco LEAP
	#
	#  We do not recommend using LEAP in new deployments.  See:
	#  http://www.securiteam.com/tools/5TP012ACKE.html
	#
	#  Cisco LEAP uses the MS-CHAP algorithm (but not
	#  the MS-CHAP attributes) to perform it's authentication.
	#
	#  As a result, LEAP *requires* access to the plain-text
	#  User-Password, or the NT-Password attributes.
	#  'System' authentication is impossible with LEAP.
	#
	leap {
	}

	#  Generic Token Card.
	#
	#  Currently, this is only permitted inside of EAP-TTLS,
	#  or EAP-PEAP.  The module "challenges" the user with
	#  text, and the response from the user is taken to be
	#  the User-Password.
	#
	#  Proxying the tunneled EAP-GTC session is a bad idea,
	#  the users password will go over the wire in plain-text,
	#  for anyone to see.
	#
	gtc {
		#  The default challenge, which many clients
		#  ignore..
		#challenge = "Password: "

		#  The plain-text response which comes back
		#  is put into a User-Password attribute,
		#  and passed to another module for
		#  authentication.  This allows the EAP-GTC
		#  response to be checked against plain-text,
		#  or crypt'd passwords.
		#
		#  If you say "Local" instead of "PAP", then
		#  the module will look for a User-Password
		#  configured for the request, and do the
		#  authentication itself.
		#
		auth_type = PAP
	}

	## Common TLS configuration for TLS-based EAP types
	#
	#  See raddb/certs/README for additional comments
	#  on certificates.
	#
	#  If OpenSSL was not found at the time the server was
	#  built, the "tls", "ttls", and "peap" sections will
	#  be ignored.
	#
	#  If you do not currently have certificates signed by
	#  a trusted CA you may use the 'snakeoil' certificates.
	#  Included with the server in raddb/certs.
	#
	#  If these certificates have not been auto-generated:
	#    cd raddb/certs
	#    make
	#
	#  These test certificates SHOULD NOT be used in a normal
	#  deployment.  They are created only to make it easier
	#  to install the server, and to perform some simple
	#  tests with EAP-TLS, TTLS, or PEAP.
	#
	#  See also:
	#
	#  http://www.dslreports.com/forum/remark,9286052~mode=flat
	#
	#  Note that you should NOT use a globally known CA here!
	#  e.g. using a Verisign cert as a "known CA" means that
	#  ANYONE who has a certificate signed by them can
	#  authenticate via EAP-TLS!  This is likely not what you want.
	tls-config tls-common {
		private_key_password = whatever
		private_key_file = %s

		#  If Private key & Certificate are located in
		#  the same file, then private_key_file &
		#  certificate_file must contain the same file
		#  name.
		#
		#  If ca_file (below) is not used, then the
		#  certificate_file below MUST include not
		#  only the server certificate, but ALSO all
		#  of the CA certificates used to sign the
		#  server certificate.
		certificate_file = %s

		#  Trusted Root CA list
		#
		#  ALL of the CA's in this list will be trusted
		#  to issue client certificates for authentication.
		#
		#  In general, you should use self-signed
		#  certificates for 802.1x (EAP) authentication.
		#  In that case, this CA file should contain
		#  *one* CA certificate.
		#
		ca_file = %s

	 	#  OpenSSL will automatically create certificate chains,
	 	#  unless we tell it to not do that.  The problem is that
	 	#  it sometimes gets the chains right from a certificate
	 	#  signature view, but wrong from the clients view.
		#
		#  When setting "auto_chain = no", the server certificate
		#  file MUST include the full certificate chain.
	#	auto_chain = yes

		#
		#  If OpenSSL supports TLS-PSK, then we can use
		#  a PSK identity and (hex) password.  When the
		#  following two configuration items are specified,
		#  then certificate-based configuration items are
		#  not allowed.  e.g.:
		#
		#	private_key_password
		#	private_key_file
		#	certificate_file
		#	ca_file
		#	ca_path
		#
		#  For now, the identity is fixed, and must be the
		#  same on the client.  The passphrase must be a hex
		#  value, and can be up to 256 hex digits.
		#
		#  Future versions of the server may be able to
		#  look up the shared key (hexphrase) based on the
		#  identity.
		#
	#	psk_identity = "test"
	#	psk_hexphrase = "036363823"

		#
		#  For DH cipher suites to work, you have to
		#  run OpenSSL to create the DH file first:
		#
		#  	openssl dhparam -out certs/dh 2048
		#
		dh_file = %s

		#
		#  If your system doesn't have /dev/urandom,
		#  you will need to create this file, and
		#  periodically change its contents.
		#
		#  For security reasons, FreeRADIUS doesn't
		#  write to files in its configuration
		#  directory.
		#
	#	random_file = /dev/urandom

		#
		#  This can never exceed the size of a RADIUS
		#  packet (4096 bytes), and is preferably half
		#  that, to accommodate other attributes in
		#  RADIUS packet.  On most APs the MAX packet
		#  length is configured between 1500 - 1600
		#  In these cases, fragment size should be
		#  1024 or less.
		#
	#	fragment_size = 1024

		#  include_length is a flag which is
		#  by default set to yes If set to
		#  yes, Total Length of the message is
		#  included in EVERY packet we send.
		#  If set to no, Total Length of the
		#  message is included ONLY in the
		#  First packet of a fragment series.
		#
	#	include_length = yes


		#  Check the Certificate Revocation List
		#
		#  1) Copy CA certificates and CRLs to same directory.
		#  2) Execute 'c_rehash <CA certs&CRLs Directory>'.
		#    'c_rehash' is OpenSSL's command.
		#  3) uncomment the lines below.
		#  5) Restart radiusd
	#	check_crl = yes

		# Check if intermediate CAs have been revoked.
	#	check_all_crl = yes

		ca_path = %s

		#
		#  If check_cert_issuer is set, the value will
		#  be checked against the DN of the issuer in
		#  the client certificate.  If the values do not
		#  match, the certificate verification will fail,
		#  rejecting the user.
		#
		#  In 2.1.10 and later, this check can be done
		#  more generally by checking the value of the
		#  TLS-Client-Cert-Issuer attribute.  This check
		#  can be done via any mechanism you choose.
		#
	#	check_cert_issuer = "/C=GB/ST=Berkshire/L=Newbury/O=My Company Ltd"

		#
		#  If check_cert_cn is set, the value will
		#  be xlat'ed and checked against the CN
		#  in the client certificate.  If the values
		#  do not match, the certificate verification
		#  will fail rejecting the user.
		#
		#  This check is done only if the previous
		#  "check_cert_issuer" is not set, or if
		#  the check succeeds.
		#
		#  In 2.1.10 and later, this check can be done
		#  more generally by checking the value of the
		#  TLS-Client-Cert-CN attribute.  This check
		#  can be done via any mechanism you choose.
		#
	#	check_cert_cn = [[User-Name]]
		#
		# Set this option to specify the allowed
		# TLS cipher suites.  The format is listed
		# in "man 1 ciphers".
		#
		# For EAP-FAST, use "ALL:!EXPORT:!eNULL:!SSLv2"
		#
		cipher_list = "DEFAULT"

		# If enabled, OpenSSL will use server cipher list
		# (possibly defined by cipher_list option above)
		# for choosing right cipher suite rather than
		# using client-specified list which is OpenSSl default
		# behavior. Having it set to yes is a current best practice
		# for TLS
		cipher_server_preference = no

		# Work-arounds for OpenSSL nonsense
		# OpenSSL 1.0.1f and 1.0.1g do not calculate
		# the EAP keys correctly.  The fix is to upgrade
		# OpenSSL, or disable TLS 1.2 here. 
		#
		#  For EAP-FAST, this MUST be set to "yes".
		#
#		disable_tlsv1_2 = no

		#

		#
		#  Elliptical cryptography configuration
		#
		#  Only for OpenSSL >= 0.9.8.f
		#
		ecdh_curve = "prime256v1"

		#
		#  Session resumption / fast reauthentication
		#  cache.
		#
		#  The cache contains the following information:
		#
		#  session Id - unique identifier, managed by SSL
		#  User-Name  - from the Access-Accept
		#  Stripped-User-Name - from the Access-Request
		#  Cached-Session-Policy - from the Access-Accept
		#
		#  The "Cached-Session-Policy" is the name of a
		#  policy which should be applied to the cached
		#  session.  This policy can be used to assign
		#  VLANs, IP addresses, etc.  It serves as a useful
		#  way to re-apply the policy from the original
		#  Access-Accept to the subsequent Access-Accept
		#  for the cached session.
		#
		#  On session resumption, these attributes are
		#  copied from the cache, and placed into the
		#  reply list.
		#
		#  You probably also want "use_tunneled_reply = yes"
		#  when using fast session resumption.
		#
		cache {
			#
			#  Enable it.  The default is "no". Deleting the entire "cache"
			#  subsection also disables caching.
			#
			#  You can disallow resumption for a particular user by adding the
			#  following attribute to the control item list:
			#
			#    Allow-Session-Resumption = No
			#
			#  If "enable = no" below, you CANNOT enable resumption for just one
			#  user by setting the above attribute to "yes".
			#
			enable = yes

			#
			#  Lifetime of the cached entries, in hours. The sessions will be
			#  deleted/invalidated after this time.
			#
			lifetime = 24 # hours

			#
			#  The maximum number of entries in the
			#  cache.  Set to "0" for "infinite".
			#
			#  This could be set to the number of users
			#  who are logged in... which can be a LOT.
			#
			max_entries = 255

			#
			#  Internal "name" of the session cache. Used to
			#  distinguish which TLS context sessions belong to.
			#
			#  The server will generate a random value if unset.
			#  This will change across server restart so you MUST
			#  set the "name" if you want to persist sessions (see
			#  below).
			#
			#name = "EAP module"

			#
			#  Simple directory-based storage of sessions.
			#  Two files per session will be written, the SSL
			#  state and the cached VPs. This will persist session
			#  across server restarts.
			#
			#  The server will need write perms, and the directory
			#  should be secured from anyone else. You might want
			#  a script to remove old files from here periodically:
			#
			#
			#  This feature REQUIRES "name" option be set above.
			#
			#persist_dir = "/var/log/freeradius-wpe/tlscache"
		}

		#
		#  As of version 2.1.10, client certificates can be
		#  validated via an external command.  This allows
		#  dynamic CRLs or OCSP to be used.
		#
		#  This configuration is commented out in the
		#  default configuration.  Uncomment it, and configure
		#  the correct paths below to enable it.
		#
		#  If OCSP checking is enabled, and the OCSP checks fail,
		#  the verify section is not run.
		#
		#  If OCSP checking is disabled, the verify section is
		#  run on successful certificate validation.
		#
		verify {
			#  If the OCSP checks succeed, the verify section
			#  is run to allow additional checks.
			#
			#  If you want to skip verify on OCSP success,
			#  uncomment this configuration item, and set it
			#  to "yes".
	#		skip_if_ocsp_ok = no

			#  A temporary directory where the client
			#  certificates are stored.  This directory
			#  MUST be owned by the UID of the server,
			#  and MUST not be accessible by any other
			#  users.  When the server starts, it will do
			#  "chmod go-rwx" on the directory, for
			#  security reasons.  The directory MUST
			#  exist when the server starts.
			#
			#  You should also delete all of the files
			#  in the directory when the server starts.
	#		tmpdir = /tmp/radiusd

			#  The command used to verify the client cert.
			#  We recommend using the OpenSSL command-line
			#  tool.
			#
			#  The ca_path text is a reference to
			#  the ca_path variable defined above.
			#
			#  The [[TLS-Client-Cert-Filename]] is the name
			#  of the temporary file containing the cert
			#  in PEM format.  This file is automatically
			#  deleted by the server when the command
			#  returns.
	#		client = "/path/to/openssl verify -CApath /etc/freeradius-wpe/3.0/certs [[TLS-Client-Cert-Filename]]"
		}

		#
		#  OCSP Configuration
		#  Certificates can be verified against an OCSP
		#  Responder. This makes it possible to immediately
		#  revoke certificates without the distribution of
		#  new Certificate Revocation Lists (CRLs).
		#
		ocsp {
			#
			#  Enable it.  The default is "no".
			#  Deleting the entire "ocsp" subsection
			#  also disables ocsp checking
			#
			enable = no

			#
			#  The OCSP Responder URL can be automatically
			#  extracted from the certificate in question.
			#  To override the OCSP Responder URL set
			#  "override_cert_url = yes".
			#
			override_cert_url = yes

			#
			#  If the OCSP Responder address is not extracted from
			#  the certificate, the URL can be defined here.
			#
			url = "http://127.0.0.1/ocsp/"

			#
			# If the OCSP Responder can not cope with nonce
			# in the request, then it can be disabled here.
			#
			# For security reasons, disabling this option
			# is not recommended as nonce protects against
			# replay attacks.
			#
			# Note that Microsoft AD Certificate Services OCSP
			# Responder does not enable nonce by default. It is
			# more secure to enable nonce on the responder than
			# to disable it in the query here.
			#
			# use_nonce = yes

			#
			# Number of seconds before giving up waiting
			# for OCSP response. 0 uses system default.
			#
			# timeout = 0

			#
			# Normally an error in querying the OCSP
			# responder (no response from server, server did
			# not understand the request, etc) will result in
			# a validation failure.
			#
			# To treat these errors as 'soft' failures and
			# still accept the certificate, enable this
			# option.
			#
			# Warning: this may enable clients with revoked
			# certificates to connect if the OCSP responder
			# is not available. Use with caution.
			#
			# softfail = no
		}
	}

	## EAP-TLS
	#
	#  As of Version 3.0, the TLS configuration for TLS-based
	#  EAP types is above in the "tls-config" section.
	#
	tls {
		# Point to the common TLS configuration
		tls = tls-common

		#
		# As part of checking a client certificate, the EAP-TLS
		# sets some attributes such as TLS-Client-Cert-CN. This
		# virtual server has access to these attributes, and can
		# be used to accept or reject the request.
		#
	#	virtual_server = check-eap-tls
	}


	## EAP-TTLS
	#
	#  The TTLS module implements the EAP-TTLS protocol,
	#  which can be described as EAP inside of Diameter,
	#  inside of TLS, inside of EAP, inside of RADIUS...
	#
	#  Surprisingly, it works quite well.
	#
	ttls {
		#  Which tls-config section the TLS negotiation parameters
		#  are in - see EAP-TLS above for an explanation.
		#
		#  In the case that an old configuration from FreeRADIUS
		#  v2.x is being used, all the options of the tls-config
		#  section may also appear instead in the 'tls' section
		#  above. If that is done, the tls= option here (and in
		#  tls above) MUST be commented out.
		#
		tls = tls-common

		#  The tunneled EAP session needs a default EAP type
		#  which is separate from the one for the non-tunneled
		#  EAP module.  Inside of the TTLS tunnel, we recommend
		#  using EAP-MD5.  If the request does not contain an
		#  EAP conversation, then this configuration entry is
		#  ignored.
		#
		default_eap_type = md5

		#  The tunneled authentication request does not usually
		#  contain useful attributes like 'Calling-Station-Id',
		#  etc.  These attributes are outside of the tunnel,
		#  and normally unavailable to the tunneled
		#  authentication request.
		#
		#  By setting this configuration entry to 'yes',
		#  any attribute which is NOT in the tunneled
		#  authentication request, but which IS available
		#  outside of the tunnel, is copied to the tunneled
		#  request.
		#
		#  allowed values: {no, yes}
		#
		copy_request_to_tunnel = no

		#
		#  As of version 3.0.5, this configuration item
		#  is deprecated.  Instead, you should use
		#
		# 	update outer.session-state {
		#		...
		#
		#	}
		#
		#  This will cache attributes for the final Access-Accept.
		#
		#  The reply attributes sent to the NAS are usually
		#  based on the name of the user 'outside' of the
		#  tunnel (usually 'anonymous').  If you want to send
		#  the reply attributes based on the user name inside
		#  of the tunnel, then set this configuration entry to
		#  'yes', and the reply to the NAS will be taken from
		#  the reply to the tunneled request.
		#
		#  allowed values: {no, yes}
		#
		use_tunneled_reply = no

		#
		#  The inner tunneled request can be sent
		#  through a virtual server constructed
		#  specifically for this purpose.
		#
		#  If this entry is commented out, the inner
		#  tunneled request will be sent through
		#  the virtual server that processed the
		#  outer requests.
		#
		virtual_server = "inner-tunnel"

		#  This has the same meaning, and overwrites, the
		#  same field in the "tls" configuration, above.
		#  The default value here is "yes".
		#
	#	include_length = yes

		#
		# Unlike EAP-TLS, EAP-TTLS does not require a client
		# certificate. However, you can require one by setting the
		# following option. You can also override this option by
		# setting
		#
		#	EAP-TLS-Require-Client-Cert = Yes
		#
		# in the control items for a request.
		#
	#	require_client_cert = yes
	}


	## EAP-PEAP
	#

	##################################################
	#
	#  !!!!! WARNINGS for Windows compatibility  !!!!!
	#
	##################################################
	#
	#  If you see the server send an Access-Challenge,
	#  and the client never sends another Access-Request,
	#  then
	#
	#		STOP!
	#
	#  The server certificate has to have special OID's
	#  in it, or else the Microsoft clients will silently
	#  fail.  See the "scripts/xpextensions" file for
	#  details, and the following page:
	#
	#	http://support.microsoft.com/kb/814394/en-us
	#
	#  For additional Windows XP SP2 issues, see:
	#
	#	http://support.microsoft.com/kb/885453/en-us
	#
	#
	#  If is still doesn't work, and you're using Samba,
	#  you may be encountering a Samba bug.  See:
	#
	#	https://bugzilla.samba.org/show_bug.cgi?id=6563
	#
	#  Note that we do not necessarily agree with their
	#  explanation... but the fix does appear to work.
	#
	##################################################

	#
	#  The tunneled EAP session needs a default EAP type
	#  which is separate from the one for the non-tunneled
	#  EAP module.  Inside of the TLS/PEAP tunnel, we
	#  recommend using EAP-MS-CHAPv2.
	#
	peap {
		#  Which tls-config section the TLS negotiation parameters
		#  are in - see EAP-TLS above for an explanation.
		#
		#  In the case that an old configuration from FreeRADIUS
		#  v2.x is being used, all the options of the tls-config
		#  section may also appear instead in the 'tls' section
		#  above. If that is done, the tls= option here (and in
		#  tls above) MUST be commented out.
		#
		tls = tls-common

		#  The tunneled EAP session needs a default
		#  EAP type which is separate from the one for
		#  the non-tunneled EAP module.  Inside of the
		#  PEAP tunnel, we recommend using MS-CHAPv2,
		#  as that is the default type supported by
		#  Windows clients.
		#
		default_eap_type = mschapv2

		#  The PEAP module also has these configuration
		#  items, which are the same as for TTLS.
		#
		copy_request_to_tunnel = no

		#
		#  As of version 3.0.5, this configuration item
		#  is deprecated.  Instead, you should use
		#
		# 	update outer.session-state {
		#		...
		#
		#	}
		#
		#  This will cache attributes for the final Access-Accept.
		#
		use_tunneled_reply = no

		#  When the tunneled session is proxied, the
		#  home server may not understand EAP-MSCHAP-V2.
		#  Set this entry to "no" to proxy the tunneled
		#  EAP-MSCHAP-V2 as normal MSCHAPv2.
		#
	#	proxy_tunneled_request_as_eap = yes

		#
		#  The inner tunneled request can be sent
		#  through a virtual server constructed
		#  specifically for this purpose.
		#
		#  If this entry is commented out, the inner
		#  tunneled request will be sent through
		#  the virtual server that processed the
		#  outer requests.
		#
		virtual_server = "inner-tunnel"

		# This option enables support for MS-SoH
		# see doc/SoH.txt for more info.
		# It is disabled by default.
		#
	#	soh = yes

		#
		# The SoH reply will be turned into a request which
		# can be sent to a specific virtual server:
		#
	#	soh_virtual_server = "soh-server"

		#
		# Unlike EAP-TLS, PEAP does not require a client certificate.
		# However, you can require one by setting the following
		# option. You can also override this option by setting
		#
		#	EAP-TLS-Require-Client-Cert = Yes
		#
		# in the control items for a request.
		#
	#	require_client_cert = yes
	}

	#
	#  This takes no configuration.
	#
	#  Note that it is the EAP MS-CHAPv2 sub-module, not
	#  the main 'mschap' module.
	#
	#  Note also that in order for this sub-module to work,
	#  the main 'mschap' module MUST ALSO be configured.
	#
	#  This module is the *Microsoft* implementation of MS-CHAPv2
	#  in EAP.  There is another (incompatible) implementation
	#  of MS-CHAPv2 in EAP by Cisco, which FreeRADIUS does not
	#  currently support.
	#
	mschapv2 {
		#  Prior to version 2.1.11, the module never
		#  sent the MS-CHAP-Error message to the
		#  client.  This worked, but it had issues
		#  when the cached password was wrong.  The
		#  server *should* send "E=691 R=0" to the
		#  client, which tells it to prompt the user
		#  for a new password.
		#
		#  The default is to behave as in 2.1.10 and
		#  earlier, which is known to work.  If you
		#  set "send_error = yes", then the error
		#  message will be sent back to the client.
		#  This *may* help some clients work better,
		#  but *may* also cause other clients to stop
		#  working.
		#
#		send_error = no

		#  Server identifier to send back in the challenge.
		#  This should generally be the host name of the
		#  RADIUS server.  Or, some information to uniquely
		#  identify it.
#		identity = "FreeRADIUS"
	}

	## EAP-FAST
	#
	#  The FAST module implements the EAP-FAST protocol
	#
#	fast {
#		# Point to the common TLS configuration
#		#
#		# cipher_list though must include "ADH" for anonymous provisioning.
#		# This is not as straight forward as appending "ADH" alongside
#		# "DEFAULT" as "DEFAULT" contains "!aNULL" so instead it is
#		# recommended "ALL:!EXPORT:!eNULL:!SSLv2" is used
#		#
#		tls = tls-common
#
#		# PAC lifetime in seconds (default: seven days)
#		#
#		pac_lifetime = 604800
#
#		# Authority ID of the server
#		#
#		# if you are running a cluster of RADIUS servers, you should make
#		# the value chosen here (and for "pac_opaque_key") the same on all
#		# your RADIUS servers.  This value should be unique to your
#		# installation.  We suggest using a domain name.
#		#
#		authority_identity = "1234"
#
#		# PAC Opaque encryption key (must be exactly 32 bytes in size)
#		#
#		# This value MUST be secret, and MUST be generated using
#		# a secure method, such as via 'openssl rand -hex 32'
#		#
#		pac_opaque_key = "0123456789abcdef0123456789ABCDEF"
#
#		# Same as for TTLS, PEAP, etc.
#		#
#		virtual_server = inner-tunnel
#	}
}
'''

freeradius_eap_fast_conf = '''
# -*- text -*-
##
##  eap.conf -- Configuration for EAP types (PEAP, TTLS, etc.)
##
##	$Id: 427016c66da92b5aa87ac784e74550c4e723c0cd $

#######################################################################
#
#  Whatever you do, do NOT set 'Auth-Type := EAP'.  The server
#  is smart enough to figure this out on its own.  The most
#  common side effect of setting 'Auth-Type := EAP' is that the
#  users then cannot use ANY other authentication method.
#
eap {
	#  Invoke the default supported EAP type when
	#  EAP-Identity response is received.
	#
	#  The incoming EAP messages DO NOT specify which EAP
	#  type they will be using, so it MUST be set here.
	#
	#  For now, only one default EAP type may be used at a time.
	#
	#  If the EAP-Type attribute is set by another module,
	#  then that EAP type takes precedence over the
	#  default type configured here.
	#
	default_eap_type = %s

	#  A list is maintained to correlate EAP-Response
	#  packets with EAP-Request packets.  After a
	#  configurable length of time, entries in the list
	#  expire, and are deleted.
	#
	timer_expire     = 60

	#  There are many EAP types, but the server has support
	#  for only a limited subset.  If the server receives
	#  a request for an EAP type it does not support, then
	#  it normally rejects the request.  By setting this
	#  configuration to "yes", you can tell the server to
	#  instead keep processing the request.  Another module
	#  MUST then be configured to proxy the request to
	#  another RADIUS server which supports that EAP type.
	#
	#  If another module is NOT configured to handle the
	#  request, then the request will still end up being
	#  rejected.
	ignore_unknown_eap_types = no

	# Cisco AP1230B firmware 12.2(13)JA1 has a bug.  When given
	# a User-Name attribute in an Access-Accept, it copies one
	# more byte than it should.
	#
	# We can work around it by configurably adding an extra
	# zero byte.
	cisco_accounting_username_bug = no

	#
	#  Help prevent DoS attacks by limiting the number of
	#  sessions that the server is tracking.  For simplicity,
	#  this is taken from the "max_requests" directive in
	#  radiusd.conf.
	max_sessions = 16384

	# Supported EAP-types

	## EAP-FAST
	#
	#  The FAST module implements the EAP-FAST protocol
	#
	fast {
		# Point to the common TLS configuration
		#
		# cipher_list though must include "ADH" for anonymous provisioning.
		# This is not as straight forward as appending "ADH" alongside
		# "DEFAULT" as "DEFAULT" contains "!aNULL" so instead it is
		# recommended "ALL:!EXPORT:!eNULL:!SSLv2" is used
		#
		tls = tls-common

		# PAC lifetime in seconds (default: seven days)
		#
		pac_lifetime = 604800

		# Authority ID of the server
		#
		# if you are running a cluster of RADIUS servers, you should make
		# the value chosen here (and for "pac_opaque_key") the same on all
		# your RADIUS servers.  This value should be unique to your
		# installation.  We suggest using a domain name.
		#
		authority_identity = "1234"

		# PAC Opaque encryption key (must be exactly 32 bytes in size)
		#
		# This value MUST be secret, and MUST be generated using
		# a secure method, such as via 'openssl rand -hex 32'
		#
		pac_opaque_key = "0123456789abcdef0123456789ABCDEF"

		# Same as for TTLS, PEAP, etc.
		#
		virtual_server = inner-tunnel
	}
}
'''

freeradius_clients_conf = '''
# -*- text -*-
##
## clients.conf -- client configuration directives

client localhost {
	ipaddr = %s
	proto = %s
	secret = %s
	require_message_authenticator = no
	# shortname = localhost
	nas_type	 = other
	# login	   = root
	# password	= someadminpas
	# virtual_server = home1
	# coa_server = coa
	# response_window = 10
	limit {
		max_connections = 16
		lifetime = 0
		idle_timeout = 30
	}
}

# IPv6 Client
client localhost_ipv6 {
	ipv6addr	= ::1
	secret		= testing123
}

# All IPv6 Site-local clients
#client sitelocal_ipv6 {
#	ipv6addr	= fe80::/16
#	secret		= testing123
#}

#client example.org {
#	ipaddr		= radius.example.org
#	secret		= testing123
#}

#
#  You can now specify one secret for a network of clients.
#  When a client request comes in, the BEST match is chosen.
#  i.e. The entry from the smallest possible network.
#
#client private-network-1 {
#	ipaddr		= 192.0.2.0/24
#	secret		= secret
#}

#client private-network-2 {
#	ipaddr		= 198.51.100.0/24
#	secret		= testing123-2
#}

#######################################################################
#
#  Per-socket client lists.  The configuration entries are exactly
#  the same as above, but they are nested inside of a section.
#
#  You can have as many per-socket client lists as you have "listen"
#  sections, or you can re-use a list among multiple "listen" sections.
#
#  Un-comment this section, and edit a "listen" section to add:
#  "clients = per_socket_clients".  That IP address/port combination
#  will then accept ONLY the clients listed in this section.
#
#clients per_socket_clients {
#	client socket_client {
#		ipaddr = 192.0.2.4
#		secret = testing123
#	}
#}

'''

freeradius_eap_md5_conf = '''
# -*- text -*-
##
##  eap.conf -- Configuration for EAP types (PEAP, TTLS, etc.)
##
##	$Id: 427016c66da92b5aa87ac784e74550c4e723c0cd $

#######################################################################
#
#  Whatever you do, do NOT set 'Auth-Type := EAP'.  The server
#  is smart enough to figure this out on its own.  The most
#  common side effect of setting 'Auth-Type := EAP' is that the
#  users then cannot use ANY other authentication method.
#
eap {
	#  Invoke the default supported EAP type when
	#  EAP-Identity response is received.
	#
	#  The incoming EAP messages DO NOT specify which EAP
	#  type they will be using, so it MUST be set here.
	#
	#  For now, only one default EAP type may be used at a time.
	#
	#  If the EAP-Type attribute is set by another module,
	#  then that EAP type takes precedence over the
	#  default type configured here.
	#
	default_eap_type = %s

	#  A list is maintained to correlate EAP-Response
	#  packets with EAP-Request packets.  After a
	#  configurable length of time, entries in the list
	#  expire, and are deleted.
	#
	timer_expire     = 60

	#  There are many EAP types, but the server has support
	#  for only a limited subset.  If the server receives
	#  a request for an EAP type it does not support, then
	#  it normally rejects the request.  By setting this
	#  configuration to "yes", you can tell the server to
	#  instead keep processing the request.  Another module
	#  MUST then be configured to proxy the request to
	#  another RADIUS server which supports that EAP type.
	#
	#  If another module is NOT configured to handle the
	#  request, then the request will still end up being
	#  rejected.
	ignore_unknown_eap_types = no

	# Cisco AP1230B firmware 12.2(13)JA1 has a bug.  When given
	# a User-Name attribute in an Access-Accept, it copies one
	# more byte than it should.
	#
	# We can work around it by configurably adding an extra
	# zero byte.
	cisco_accounting_username_bug = no

	#
	#  Help prevent DoS attacks by limiting the number of
	#  sessions that the server is tracking.  For simplicity,
	#  this is taken from the "max_requests" directive in
	#  radiusd.conf.
	max_sessions = 16384

	# Supported EAP-types

	#
	#  We do NOT recommend using EAP-MD5 authentication
	#  for wireless connections.  It is insecure, and does
	#  not provide for dynamic WEP keys.
	#
	md5 {
	}
}
'''

freeradius_eap_pwd_conf = '''
# -*- text -*-
##
##  eap.conf -- Configuration for EAP types (PEAP, TTLS, etc.)
##
##	$Id: 427016c66da92b5aa87ac784e74550c4e723c0cd $

#######################################################################
#
#  Whatever you do, do NOT set 'Auth-Type := EAP'.  The server
#  is smart enough to figure this out on its own.  The most
#  common side effect of setting 'Auth-Type := EAP' is that the
#  users then cannot use ANY other authentication method.
#
eap {
	#  Invoke the default supported EAP type when
	#  EAP-Identity response is received.
	#
	#  The incoming EAP messages DO NOT specify which EAP
	#  type they will be using, so it MUST be set here.
	#
	#  For now, only one default EAP type may be used at a time.
	#
	#  If the EAP-Type attribute is set by another module,
	#  then that EAP type takes precedence over the
	#  default type configured here.
	#
	default_eap_type = %s

	#  A list is maintained to correlate EAP-Response
	#  packets with EAP-Request packets.  After a
	#  configurable length of time, entries in the list
	#  expire, and are deleted.
	#
	timer_expire     = 60

	#  There are many EAP types, but the server has support
	#  for only a limited subset.  If the server receives
	#  a request for an EAP type it does not support, then
	#  it normally rejects the request.  By setting this
	#  configuration to "yes", you can tell the server to
	#  instead keep processing the request.  Another module
	#  MUST then be configured to proxy the request to
	#  another RADIUS server which supports that EAP type.
	#
	#  If another module is NOT configured to handle the
	#  request, then the request will still end up being
	#  rejected.
	ignore_unknown_eap_types = no

	# Cisco AP1230B firmware 12.2(13)JA1 has a bug.  When given
	# a User-Name attribute in an Access-Accept, it copies one
	# more byte than it should.
	#
	# We can work around it by configurably adding an extra
	# zero byte.
	cisco_accounting_username_bug = no

	#
	#  Help prevent DoS attacks by limiting the number of
	#  sessions that the server is tracking.  For simplicity,
	#  this is taken from the "max_requests" directive in
	#  radiusd.conf.
	max_sessions = 16384

	# Supported EAP-types

	#
	# EAP-pwd -- secure password-based authentication
	#
	pwd {
		group = 19

		#
		server_id = theserver@example.com

		#  This has the same meaning as for TLS.
		fragment_size = 1020

		# The virtual server which determines the
		# "known good" password for the user.
		# Note that unlike TLS, only the "authorize"
		# section is processed.  EAP-PWD requests can be
		# distinguished by having a User-Name, but
		# no User-Password, CHAP-Password, EAP-Message, etc.
		virtual_server = "inner-tunnel"
	}
}
'''

freeradius_eap_leap_conf = '''
# -*- text -*-
##
##  eap.conf -- Configuration for EAP types (PEAP, TTLS, etc.)
##
##	$Id: 427016c66da92b5aa87ac784e74550c4e723c0cd $

#######################################################################
#
#  Whatever you do, do NOT set 'Auth-Type := EAP'.  The server
#  is smart enough to figure this out on its own.  The most
#  common side effect of setting 'Auth-Type := EAP' is that the
#  users then cannot use ANY other authentication method.
#
eap {
	#  Invoke the default supported EAP type when
	#  EAP-Identity response is received.
	#
	#  The incoming EAP messages DO NOT specify which EAP
	#  type they will be using, so it MUST be set here.
	#
	#  For now, only one default EAP type may be used at a time.
	#
	#  If the EAP-Type attribute is set by another module,
	#  then that EAP type takes precedence over the
	#  default type configured here.
	#
	default_eap_type = %s

	#  A list is maintained to correlate EAP-Response
	#  packets with EAP-Request packets.  After a
	#  configurable length of time, entries in the list
	#  expire, and are deleted.
	#
	timer_expire     = 60

	#  There are many EAP types, but the server has support
	#  for only a limited subset.  If the server receives
	#  a request for an EAP type it does not support, then
	#  it normally rejects the request.  By setting this
	#  configuration to "yes", you can tell the server to
	#  instead keep processing the request.  Another module
	#  MUST then be configured to proxy the request to
	#  another RADIUS server which supports that EAP type.
	#
	#  If another module is NOT configured to handle the
	#  request, then the request will still end up being
	#  rejected.
	ignore_unknown_eap_types = no

	# Cisco AP1230B firmware 12.2(13)JA1 has a bug.  When given
	# a User-Name attribute in an Access-Accept, it copies one
	# more byte than it should.
	#
	# We can work around it by configurably adding an extra
	# zero byte.
	cisco_accounting_username_bug = no

	#
	#  Help prevent DoS attacks by limiting the number of
	#  sessions that the server is tracking.  For simplicity,
	#  this is taken from the "max_requests" directive in
	#  radiusd.conf.
	max_sessions = 16384

	# Supported EAP-types

	# Cisco LEAP
	#
	#  We do not recommend using LEAP in new deployments.  See:
	#  http://www.securiteam.com/tools/5TP012ACKE.html
	#
	#  Cisco LEAP uses the MS-CHAP algorithm (but not
	#  the MS-CHAP attributes) to perform it's authentication.
	#
	#  As a result, LEAP *requires* access to the plain-text
	#  User-Password, or the NT-Password attributes.
	#  'System' authentication is impossible with LEAP.
	#
	leap {
	}
}
'''

freeradius_eap_gtc_conf = '''
# -*- text -*-
##
##  eap.conf -- Configuration for EAP types (PEAP, TTLS, etc.)
##
##	$Id: 427016c66da92b5aa87ac784e74550c4e723c0cd $

#######################################################################
#
#  Whatever you do, do NOT set 'Auth-Type := EAP'.  The server
#  is smart enough to figure this out on its own.  The most
#  common side effect of setting 'Auth-Type := EAP' is that the
#  users then cannot use ANY other authentication method.
#
eap {
	#  Invoke the default supported EAP type when
	#  EAP-Identity response is received.
	#
	#  The incoming EAP messages DO NOT specify which EAP
	#  type they will be using, so it MUST be set here.
	#
	#  For now, only one default EAP type may be used at a time.
	#
	#  If the EAP-Type attribute is set by another module,
	#  then that EAP type takes precedence over the
	#  default type configured here.
	#
	default_eap_type = %s

	#  A list is maintained to correlate EAP-Response
	#  packets with EAP-Request packets.  After a
	#  configurable length of time, entries in the list
	#  expire, and are deleted.
	#
	timer_expire     = 60

	#  There are many EAP types, but the server has support
	#  for only a limited subset.  If the server receives
	#  a request for an EAP type it does not support, then
	#  it normally rejects the request.  By setting this
	#  configuration to "yes", you can tell the server to
	#  instead keep processing the request.  Another module
	#  MUST then be configured to proxy the request to
	#  another RADIUS server which supports that EAP type.
	#
	#  If another module is NOT configured to handle the
	#  request, then the request will still end up being
	#  rejected.
	ignore_unknown_eap_types = no

	# Cisco AP1230B firmware 12.2(13)JA1 has a bug.  When given
	# a User-Name attribute in an Access-Accept, it copies one
	# more byte than it should.
	#
	# We can work around it by configurably adding an extra
	# zero byte.
	cisco_accounting_username_bug = no

	#
	#  Help prevent DoS attacks by limiting the number of
	#  sessions that the server is tracking.  For simplicity,
	#  this is taken from the "max_requests" directive in
	#  radiusd.conf.
	max_sessions = 16384

	# Supported EAP-types

	#  Generic Token Card.
	#
	#  Currently, this is only permitted inside of EAP-TTLS,
	#  or EAP-PEAP.  The module "challenges" the user with
	#  text, and the response from the user is taken to be
	#  the User-Password.
	#
	#  Proxying the tunneled EAP-GTC session is a bad idea,
	#  the users password will go over the wire in plain-text,
	#  for anyone to see.
	#
	gtc {
		#  The default challenge, which many clients
		#  ignore..
		#challenge = "Password: "

		#  The plain-text response which comes back
		#  is put into a User-Password attribute,
		#  and passed to another module for
		#  authentication.  This allows the EAP-GTC
		#  response to be checked against plain-text,
		#  or crypt'd passwords.
		#
		#  If you say "Local" instead of "PAP", then
		#  the module will look for a User-Password
		#  configured for the request, and do the
		#  authentication itself.
		#
		auth_type = PAP
	}
}
'''

freeradius_eap_peap_conf = '''
# -*- text -*-
##
##  eap.conf -- Configuration for EAP types (PEAP, TTLS, etc.)
##
##	$Id: 427016c66da92b5aa87ac784e74550c4e723c0cd $

#######################################################################
#
#  Whatever you do, do NOT set 'Auth-Type := EAP'.  The server
#  is smart enough to figure this out on its own.  The most
#  common side effect of setting 'Auth-Type := EAP' is that the
#  users then cannot use ANY other authentication method.
#
eap {
	#  Invoke the default supported EAP type when
	#  EAP-Identity response is received.
	#
	#  The incoming EAP messages DO NOT specify which EAP
	#  type they will be using, so it MUST be set here.
	#
	#  For now, only one default EAP type may be used at a time.
	#
	#  If the EAP-Type attribute is set by another module,
	#  then that EAP type takes precedence over the
	#  default type configured here.
	#
	default_eap_type = %s

	#  A list is maintained to correlate EAP-Response
	#  packets with EAP-Request packets.  After a
	#  configurable length of time, entries in the list
	#  expire, and are deleted.
	#
	timer_expire     = 60

	#  There are many EAP types, but the server has support
	#  for only a limited subset.  If the server receives
	#  a request for an EAP type it does not support, then
	#  it normally rejects the request.  By setting this
	#  configuration to "yes", you can tell the server to
	#  instead keep processing the request.  Another module
	#  MUST then be configured to proxy the request to
	#  another RADIUS server which supports that EAP type.
	#
	#  If another module is NOT configured to handle the
	#  request, then the request will still end up being
	#  rejected.
	ignore_unknown_eap_types = no

	# Cisco AP1230B firmware 12.2(13)JA1 has a bug.  When given
	# a User-Name attribute in an Access-Accept, it copies one
	# more byte than it should.
	#
	# We can work around it by configurably adding an extra
	# zero byte.
	cisco_accounting_username_bug = no

	#
	#  Help prevent DoS attacks by limiting the number of
	#  sessions that the server is tracking.  For simplicity,
	#  this is taken from the "max_requests" directive in
	#  radiusd.conf.
	max_sessions = 16384

	# Supported EAP-types

	## Common TLS configuration for TLS-based EAP types
	#
	#  See raddb/certs/README for additional comments
	#  on certificates.
	#
	#  If OpenSSL was not found at the time the server was
	#  built, the "tls", "ttls", and "peap" sections will
	#  be ignored.
	#
	#  If you do not currently have certificates signed by
	#  a trusted CA you may use the 'snakeoil' certificates.
	#  Included with the server in raddb/certs.
	#
	#  If these certificates have not been auto-generated:
	#    cd raddb/certs
	#    make
	#
	#  These test certificates SHOULD NOT be used in a normal
	#  deployment.  They are created only to make it easier
	#  to install the server, and to perform some simple
	#  tests with EAP-TLS, TTLS, or PEAP.
	#
	#  See also:
	#
	#  http://www.dslreports.com/forum/remark,9286052~mode=flat
	#
	#  Note that you should NOT use a globally known CA here!
	#  e.g. using a Verisign cert as a "known CA" means that
	#  ANYONE who has a certificate signed by them can
	#  authenticate via EAP-TLS!  This is likely not what you want.
	tls-config tls-common {
		private_key_password = whatever
		private_key_file = %s

		#  If Private key & Certificate are located in
		#  the same file, then private_key_file &
		#  certificate_file must contain the same file
		#  name.
		#
		#  If ca_file (below) is not used, then the
		#  certificate_file below MUST include not
		#  only the server certificate, but ALSO all
		#  of the CA certificates used to sign the
		#  server certificate.
		certificate_file = %s

		#  Trusted Root CA list
		#
		#  ALL of the CA's in this list will be trusted
		#  to issue client certificates for authentication.
		#
		#  In general, you should use self-signed
		#  certificates for 802.1x (EAP) authentication.
		#  In that case, this CA file should contain
		#  *one* CA certificate.
		#
		ca_file = %s

	 	#  OpenSSL will automatically create certificate chains,
	 	#  unless we tell it to not do that.  The problem is that
	 	#  it sometimes gets the chains right from a certificate
	 	#  signature view, but wrong from the clients view.
		#
		#  When setting "auto_chain = no", the server certificate
		#  file MUST include the full certificate chain.
	#	auto_chain = yes

		#
		#  If OpenSSL supports TLS-PSK, then we can use
		#  a PSK identity and (hex) password.  When the
		#  following two configuration items are specified,
		#  then certificate-based configuration items are
		#  not allowed.  e.g.:
		#
		#	private_key_password
		#	private_key_file
		#	certificate_file
		#	ca_file
		#	ca_path
		#
		#  For now, the identity is fixed, and must be the
		#  same on the client.  The passphrase must be a hex
		#  value, and can be up to 256 hex digits.
		#
		#  Future versions of the server may be able to
		#  look up the shared key (hexphrase) based on the
		#  identity.
		#
	#	psk_identity = "test"
	#	psk_hexphrase = "036363823"

		#
		#  For DH cipher suites to work, you have to
		#  run OpenSSL to create the DH file first:
		#
		#  	openssl dhparam -out certs/dh 2048
		#
		dh_file = %s

		#
		#  If your system doesn't have /dev/urandom,
		#  you will need to create this file, and
		#  periodically change its contents.
		#
		#  For security reasons, FreeRADIUS doesn't
		#  write to files in its configuration
		#  directory.
		#
	#	random_file = /dev/urandom

		#
		#  This can never exceed the size of a RADIUS
		#  packet (4096 bytes), and is preferably half
		#  that, to accommodate other attributes in
		#  RADIUS packet.  On most APs the MAX packet
		#  length is configured between 1500 - 1600
		#  In these cases, fragment size should be
		#  1024 or less.
		#
	#	fragment_size = 1024

		#  include_length is a flag which is
		#  by default set to yes If set to
		#  yes, Total Length of the message is
		#  included in EVERY packet we send.
		#  If set to no, Total Length of the
		#  message is included ONLY in the
		#  First packet of a fragment series.
		#
	#	include_length = yes


		#  Check the Certificate Revocation List
		#
		#  1) Copy CA certificates and CRLs to same directory.
		#  2) Execute 'c_rehash <CA certs&CRLs Directory>'.
		#    'c_rehash' is OpenSSL's command.
		#  3) uncomment the lines below.
		#  5) Restart radiusd
	#	check_crl = yes

		# Check if intermediate CAs have been revoked.
	#	check_all_crl = yes

		ca_path = %s

		#
		#  If check_cert_issuer is set, the value will
		#  be checked against the DN of the issuer in
		#  the client certificate.  If the values do not
		#  match, the certificate verification will fail,
		#  rejecting the user.
		#
		#  In 2.1.10 and later, this check can be done
		#  more generally by checking the value of the
		#  TLS-Client-Cert-Issuer attribute.  This check
		#  can be done via any mechanism you choose.
		#
	#	check_cert_issuer = "/C=GB/ST=Berkshire/L=Newbury/O=My Company Ltd"

		#
		#  If check_cert_cn is set, the value will
		#  be xlat'ed and checked against the CN
		#  in the client certificate.  If the values
		#  do not match, the certificate verification
		#  will fail rejecting the user.
		#
		#  This check is done only if the previous
		#  "check_cert_issuer" is not set, or if
		#  the check succeeds.
		#
		#  In 2.1.10 and later, this check can be done
		#  more generally by checking the value of the
		#  TLS-Client-Cert-CN attribute.  This check
		#  can be done via any mechanism you choose.
		#
	#	check_cert_cn = [[User-Name]]
		#
		# Set this option to specify the allowed
		# TLS cipher suites.  The format is listed
		# in "man 1 ciphers".
		#
		# For EAP-FAST, use "ALL:!EXPORT:!eNULL:!SSLv2"
		#
		cipher_list = "DEFAULT"

		# If enabled, OpenSSL will use server cipher list
		# (possibly defined by cipher_list option above)
		# for choosing right cipher suite rather than
		# using client-specified list which is OpenSSl default
		# behavior. Having it set to yes is a current best practice
		# for TLS
		cipher_server_preference = no

		# Work-arounds for OpenSSL nonsense
		# OpenSSL 1.0.1f and 1.0.1g do not calculate
		# the EAP keys correctly.  The fix is to upgrade
		# OpenSSL, or disable TLS 1.2 here. 
		#
		#  For EAP-FAST, this MUST be set to "yes".
		#
#		disable_tlsv1_2 = no

		#

		#
		#  Elliptical cryptography configuration
		#
		#  Only for OpenSSL >= 0.9.8.f
		#
		ecdh_curve = "prime256v1"

		#
		#  Session resumption / fast reauthentication
		#  cache.
		#
		#  The cache contains the following information:
		#
		#  session Id - unique identifier, managed by SSL
		#  User-Name  - from the Access-Accept
		#  Stripped-User-Name - from the Access-Request
		#  Cached-Session-Policy - from the Access-Accept
		#
		#  The "Cached-Session-Policy" is the name of a
		#  policy which should be applied to the cached
		#  session.  This policy can be used to assign
		#  VLANs, IP addresses, etc.  It serves as a useful
		#  way to re-apply the policy from the original
		#  Access-Accept to the subsequent Access-Accept
		#  for the cached session.
		#
		#  On session resumption, these attributes are
		#  copied from the cache, and placed into the
		#  reply list.
		#
		#  You probably also want "use_tunneled_reply = yes"
		#  when using fast session resumption.
		#
		cache {
			#
			#  Enable it.  The default is "no". Deleting the entire "cache"
			#  subsection also disables caching.
			#
			#  You can disallow resumption for a particular user by adding the
			#  following attribute to the control item list:
			#
			#    Allow-Session-Resumption = No
			#
			#  If "enable = no" below, you CANNOT enable resumption for just one
			#  user by setting the above attribute to "yes".
			#
			enable = yes

			#
			#  Lifetime of the cached entries, in hours. The sessions will be
			#  deleted/invalidated after this time.
			#
			lifetime = 24 # hours

			#
			#  The maximum number of entries in the
			#  cache.  Set to "0" for "infinite".
			#
			#  This could be set to the number of users
			#  who are logged in... which can be a LOT.
			#
			max_entries = 255

			#
			#  Internal "name" of the session cache. Used to
			#  distinguish which TLS context sessions belong to.
			#
			#  The server will generate a random value if unset.
			#  This will change across server restart so you MUST
			#  set the "name" if you want to persist sessions (see
			#  below).
			#
			#name = "EAP module"

			#
			#  Simple directory-based storage of sessions.
			#  Two files per session will be written, the SSL
			#  state and the cached VPs. This will persist session
			#  across server restarts.
			#
			#  The server will need write perms, and the directory
			#  should be secured from anyone else. You might want
			#  a script to remove old files from here periodically:
			#
			#
			#  This feature REQUIRES "name" option be set above.
			#
			#persist_dir = "/var/log/freeradius-wpe/tlscache"
		}

		#
		#  As of version 2.1.10, client certificates can be
		#  validated via an external command.  This allows
		#  dynamic CRLs or OCSP to be used.
		#
		#  This configuration is commented out in the
		#  default configuration.  Uncomment it, and configure
		#  the correct paths below to enable it.
		#
		#  If OCSP checking is enabled, and the OCSP checks fail,
		#  the verify section is not run.
		#
		#  If OCSP checking is disabled, the verify section is
		#  run on successful certificate validation.
		#
		verify {
			#  If the OCSP checks succeed, the verify section
			#  is run to allow additional checks.
			#
			#  If you want to skip verify on OCSP success,
			#  uncomment this configuration item, and set it
			#  to "yes".
	#		skip_if_ocsp_ok = no

			#  A temporary directory where the client
			#  certificates are stored.  This directory
			#  MUST be owned by the UID of the server,
			#  and MUST not be accessible by any other
			#  users.  When the server starts, it will do
			#  "chmod go-rwx" on the directory, for
			#  security reasons.  The directory MUST
			#  exist when the server starts.
			#
			#  You should also delete all of the files
			#  in the directory when the server starts.
	#		tmpdir = /tmp/radiusd

			#  The command used to verify the client cert.
			#  We recommend using the OpenSSL command-line
			#  tool.
			#
			#  The ca_path text is a reference to
			#  the ca_path variable defined above.
			#
			#  The [[TLS-Client-Cert-Filename]] is the name
			#  of the temporary file containing the cert
			#  in PEM format.  This file is automatically
			#  deleted by the server when the command
			#  returns.
	#		client = "/path/to/openssl verify -CApath /etc/freeradius-wpe/3.0/certs [[TLS-Client-Cert-Filename]]"
		}

		#
		#  OCSP Configuration
		#  Certificates can be verified against an OCSP
		#  Responder. This makes it possible to immediately
		#  revoke certificates without the distribution of
		#  new Certificate Revocation Lists (CRLs).
		#
		ocsp {
			#
			#  Enable it.  The default is "no".
			#  Deleting the entire "ocsp" subsection
			#  also disables ocsp checking
			#
			enable = no

			#
			#  The OCSP Responder URL can be automatically
			#  extracted from the certificate in question.
			#  To override the OCSP Responder URL set
			#  "override_cert_url = yes".
			#
			override_cert_url = yes

			#
			#  If the OCSP Responder address is not extracted from
			#  the certificate, the URL can be defined here.
			#
			url = "http://127.0.0.1/ocsp/"

			#
			# If the OCSP Responder can not cope with nonce
			# in the request, then it can be disabled here.
			#
			# For security reasons, disabling this option
			# is not recommended as nonce protects against
			# replay attacks.
			#
			# Note that Microsoft AD Certificate Services OCSP
			# Responder does not enable nonce by default. It is
			# more secure to enable nonce on the responder than
			# to disable it in the query here.
			#
			# use_nonce = yes

			#
			# Number of seconds before giving up waiting
			# for OCSP response. 0 uses system default.
			#
			# timeout = 0

			#
			# Normally an error in querying the OCSP
			# responder (no response from server, server did
			# not understand the request, etc) will result in
			# a validation failure.
			#
			# To treat these errors as 'soft' failures and
			# still accept the certificate, enable this
			# option.
			#
			# Warning: this may enable clients with revoked
			# certificates to connect if the OCSP responder
			# is not available. Use with caution.
			#
			# softfail = no
		}
	}

	## EAP-PEAP
	#

	##################################################
	#
	#  !!!!! WARNINGS for Windows compatibility  !!!!!
	#
	##################################################
	#
	#  If you see the server send an Access-Challenge,
	#  and the client never sends another Access-Request,
	#  then
	#
	#		STOP!
	#
	#  The server certificate has to have special OID's
	#  in it, or else the Microsoft clients will silently
	#  fail.  See the "scripts/xpextensions" file for
	#  details, and the following page:
	#
	#	http://support.microsoft.com/kb/814394/en-us
	#
	#  For additional Windows XP SP2 issues, see:
	#
	#	http://support.microsoft.com/kb/885453/en-us
	#
	#
	#  If is still doesn't work, and you're using Samba,
	#  you may be encountering a Samba bug.  See:
	#
	#	https://bugzilla.samba.org/show_bug.cgi?id=6563
	#
	#  Note that we do not necessarily agree with their
	#  explanation... but the fix does appear to work.
	#
	##################################################

	#
	#  The tunneled EAP session needs a default EAP type
	#  which is separate from the one for the non-tunneled
	#  EAP module.  Inside of the TLS/PEAP tunnel, we
	#  recommend using EAP-MS-CHAPv2.
	#
	peap {
		#  Which tls-config section the TLS negotiation parameters
		#  are in - see EAP-TLS above for an explanation.
		#
		#  In the case that an old configuration from FreeRADIUS
		#  v2.x is being used, all the options of the tls-config
		#  section may also appear instead in the 'tls' section
		#  above. If that is done, the tls= option here (and in
		#  tls above) MUST be commented out.
		#
		tls = tls-common

		#  The tunneled EAP session needs a default
		#  EAP type which is separate from the one for
		#  the non-tunneled EAP module.  Inside of the
		#  PEAP tunnel, we recommend using MS-CHAPv2,
		#  as that is the default type supported by
		#  Windows clients.
		#
		default_eap_type = mschapv2

		#  The PEAP module also has these configuration
		#  items, which are the same as for TTLS.
		#
		copy_request_to_tunnel = no

		#
		#  As of version 3.0.5, this configuration item
		#  is deprecated.  Instead, you should use
		#
		# 	update outer.session-state {
		#		...
		#
		#	}
		#
		#  This will cache attributes for the final Access-Accept.
		#
		use_tunneled_reply = no

		#  When the tunneled session is proxied, the
		#  home server may not understand EAP-MSCHAP-V2.
		#  Set this entry to "no" to proxy the tunneled
		#  EAP-MSCHAP-V2 as normal MSCHAPv2.
		#
	#	proxy_tunneled_request_as_eap = yes

		#
		#  The inner tunneled request can be sent
		#  through a virtual server constructed
		#  specifically for this purpose.
		#
		#  If this entry is commented out, the inner
		#  tunneled request will be sent through
		#  the virtual server that processed the
		#  outer requests.
		#
		virtual_server = "inner-tunnel"

		# This option enables support for MS-SoH
		# see doc/SoH.txt for more info.
		# It is disabled by default.
		#
	#	soh = yes

		#
		# The SoH reply will be turned into a request which
		# can be sent to a specific virtual server:
		#
	#	soh_virtual_server = "soh-server"

		#
		# Unlike EAP-TLS, PEAP does not require a client certificate.
		# However, you can require one by setting the following
		# option. You can also override this option by setting
		#
		#	EAP-TLS-Require-Client-Cert = Yes
		#
		# in the control items for a request.
		#
	#	require_client_cert = yes
	}

	#
	#  This takes no configuration.
	#
	#  Note that it is the EAP MS-CHAPv2 sub-module, not
	#  the main 'mschap' module.
	#
	#  Note also that in order for this sub-module to work,
	#  the main 'mschap' module MUST ALSO be configured.
	#
	#  This module is the *Microsoft* implementation of MS-CHAPv2
	#  in EAP.  There is another (incompatible) implementation
	#  of MS-CHAPv2 in EAP by Cisco, which FreeRADIUS does not
	#  currently support.
	#
	mschapv2 {
		#  Prior to version 2.1.11, the module never
		#  sent the MS-CHAP-Error message to the
		#  client.  This worked, but it had issues
		#  when the cached password was wrong.  The
		#  server *should* send "E=691 R=0" to the
		#  client, which tells it to prompt the user
		#  for a new password.
		#
		#  The default is to behave as in 2.1.10 and
		#  earlier, which is known to work.  If you
		#  set "send_error = yes", then the error
		#  message will be sent back to the client.
		#  This *may* help some clients work better,
		#  but *may* also cause other clients to stop
		#  working.
		#
#		send_error = no

		#  Server identifier to send back in the challenge.
		#  This should generally be the host name of the
		#  RADIUS server.  Or, some information to uniquely
		#  identify it.
#		identity = "FreeRADIUS"
	}
}
'''

freeradius_eap_ttls_conf = '''
# -*- text -*-
##
##  eap.conf -- Configuration for EAP types (PEAP, TTLS, etc.)
##
##	$Id: 427016c66da92b5aa87ac784e74550c4e723c0cd $

#######################################################################
#
#  Whatever you do, do NOT set 'Auth-Type := EAP'.  The server
#  is smart enough to figure this out on its own.  The most
#  common side effect of setting 'Auth-Type := EAP' is that the
#  users then cannot use ANY other authentication method.
#
eap {
	#  Invoke the default supported EAP type when
	#  EAP-Identity response is received.
	#
	#  The incoming EAP messages DO NOT specify which EAP
	#  type they will be using, so it MUST be set here.
	#
	#  For now, only one default EAP type may be used at a time.
	#
	#  If the EAP-Type attribute is set by another module,
	#  then that EAP type takes precedence over the
	#  default type configured here.
	#
	default_eap_type = %s

	#  A list is maintained to correlate EAP-Response
	#  packets with EAP-Request packets.  After a
	#  configurable length of time, entries in the list
	#  expire, and are deleted.
	#
	timer_expire     = 60

	#  There are many EAP types, but the server has support
	#  for only a limited subset.  If the server receives
	#  a request for an EAP type it does not support, then
	#  it normally rejects the request.  By setting this
	#  configuration to "yes", you can tell the server to
	#  instead keep processing the request.  Another module
	#  MUST then be configured to proxy the request to
	#  another RADIUS server which supports that EAP type.
	#
	#  If another module is NOT configured to handle the
	#  request, then the request will still end up being
	#  rejected.
	ignore_unknown_eap_types = no

	# Cisco AP1230B firmware 12.2(13)JA1 has a bug.  When given
	# a User-Name attribute in an Access-Accept, it copies one
	# more byte than it should.
	#
	# We can work around it by configurably adding an extra
	# zero byte.
	cisco_accounting_username_bug = no

	#
	#  Help prevent DoS attacks by limiting the number of
	#  sessions that the server is tracking.  For simplicity,
	#  this is taken from the "max_requests" directive in
	#  radiusd.conf.
	max_sessions = 16384

	# Supported EAP-types

	## Common TLS configuration for TLS-based EAP types
	#
	#  See raddb/certs/README for additional comments
	#  on certificates.
	#
	#  If OpenSSL was not found at the time the server was
	#  built, the "tls", "ttls", and "peap" sections will
	#  be ignored.
	#
	#  If you do not currently have certificates signed by
	#  a trusted CA you may use the 'snakeoil' certificates.
	#  Included with the server in raddb/certs.
	#
	#  If these certificates have not been auto-generated:
	#    cd raddb/certs
	#    make
	#
	#  These test certificates SHOULD NOT be used in a normal
	#  deployment.  They are created only to make it easier
	#  to install the server, and to perform some simple
	#  tests with EAP-TLS, TTLS, or PEAP.
	#
	#  See also:
	#
	#  http://www.dslreports.com/forum/remark,9286052~mode=flat
	#
	#  Note that you should NOT use a globally known CA here!
	#  e.g. using a Verisign cert as a "known CA" means that
	#  ANYONE who has a certificate signed by them can
	#  authenticate via EAP-TLS!  This is likely not what you want.
	tls-config tls-common {
		private_key_password = whatever
		private_key_file = %s

		#  If Private key & Certificate are located in
		#  the same file, then private_key_file &
		#  certificate_file must contain the same file
		#  name.
		#
		#  If ca_file (below) is not used, then the
		#  certificate_file below MUST include not
		#  only the server certificate, but ALSO all
		#  of the CA certificates used to sign the
		#  server certificate.
		certificate_file = %s

		#  Trusted Root CA list
		#
		#  ALL of the CA's in this list will be trusted
		#  to issue client certificates for authentication.
		#
		#  In general, you should use self-signed
		#  certificates for 802.1x (EAP) authentication.
		#  In that case, this CA file should contain
		#  *one* CA certificate.
		#
		ca_file = %s

	 	#  OpenSSL will automatically create certificate chains,
	 	#  unless we tell it to not do that.  The problem is that
	 	#  it sometimes gets the chains right from a certificate
	 	#  signature view, but wrong from the clients view.
		#
		#  When setting "auto_chain = no", the server certificate
		#  file MUST include the full certificate chain.
	#	auto_chain = yes

		#
		#  If OpenSSL supports TLS-PSK, then we can use
		#  a PSK identity and (hex) password.  When the
		#  following two configuration items are specified,
		#  then certificate-based configuration items are
		#  not allowed.  e.g.:
		#
		#	private_key_password
		#	private_key_file
		#	certificate_file
		#	ca_file
		#	ca_path
		#
		#  For now, the identity is fixed, and must be the
		#  same on the client.  The passphrase must be a hex
		#  value, and can be up to 256 hex digits.
		#
		#  Future versions of the server may be able to
		#  look up the shared key (hexphrase) based on the
		#  identity.
		#
	#	psk_identity = "test"
	#	psk_hexphrase = "036363823"

		#
		#  For DH cipher suites to work, you have to
		#  run OpenSSL to create the DH file first:
		#
		#  	openssl dhparam -out certs/dh 2048
		#
		dh_file = %s

		#
		#  If your system doesn't have /dev/urandom,
		#  you will need to create this file, and
		#  periodically change its contents.
		#
		#  For security reasons, FreeRADIUS doesn't
		#  write to files in its configuration
		#  directory.
		#
	#	random_file = /dev/urandom

		#
		#  This can never exceed the size of a RADIUS
		#  packet (4096 bytes), and is preferably half
		#  that, to accommodate other attributes in
		#  RADIUS packet.  On most APs the MAX packet
		#  length is configured between 1500 - 1600
		#  In these cases, fragment size should be
		#  1024 or less.
		#
	#	fragment_size = 1024

		#  include_length is a flag which is
		#  by default set to yes If set to
		#  yes, Total Length of the message is
		#  included in EVERY packet we send.
		#  If set to no, Total Length of the
		#  message is included ONLY in the
		#  First packet of a fragment series.
		#
	#	include_length = yes


		#  Check the Certificate Revocation List
		#
		#  1) Copy CA certificates and CRLs to same directory.
		#  2) Execute 'c_rehash <CA certs&CRLs Directory>'.
		#    'c_rehash' is OpenSSL's command.
		#  3) uncomment the lines below.
		#  5) Restart radiusd
	#	check_crl = yes

		# Check if intermediate CAs have been revoked.
	#	check_all_crl = yes

		ca_path = %s

		#
		#  If check_cert_issuer is set, the value will
		#  be checked against the DN of the issuer in
		#  the client certificate.  If the values do not
		#  match, the certificate verification will fail,
		#  rejecting the user.
		#
		#  In 2.1.10 and later, this check can be done
		#  more generally by checking the value of the
		#  TLS-Client-Cert-Issuer attribute.  This check
		#  can be done via any mechanism you choose.
		#
	#	check_cert_issuer = "/C=GB/ST=Berkshire/L=Newbury/O=My Company Ltd"

		#
		#  If check_cert_cn is set, the value will
		#  be xlat'ed and checked against the CN
		#  in the client certificate.  If the values
		#  do not match, the certificate verification
		#  will fail rejecting the user.
		#
		#  This check is done only if the previous
		#  "check_cert_issuer" is not set, or if
		#  the check succeeds.
		#
		#  In 2.1.10 and later, this check can be done
		#  more generally by checking the value of the
		#  TLS-Client-Cert-CN attribute.  This check
		#  can be done via any mechanism you choose.
		#
	#	check_cert_cn = [[User-Name]]
		#
		# Set this option to specify the allowed
		# TLS cipher suites.  The format is listed
		# in "man 1 ciphers".
		#
		# For EAP-FAST, use "ALL:!EXPORT:!eNULL:!SSLv2"
		#
		cipher_list = "DEFAULT"

		# If enabled, OpenSSL will use server cipher list
		# (possibly defined by cipher_list option above)
		# for choosing right cipher suite rather than
		# using client-specified list which is OpenSSl default
		# behavior. Having it set to yes is a current best practice
		# for TLS
		cipher_server_preference = no

		# Work-arounds for OpenSSL nonsense
		# OpenSSL 1.0.1f and 1.0.1g do not calculate
		# the EAP keys correctly.  The fix is to upgrade
		# OpenSSL, or disable TLS 1.2 here. 
		#
		#  For EAP-FAST, this MUST be set to "yes".
		#
#		disable_tlsv1_2 = no

		#

		#
		#  Elliptical cryptography configuration
		#
		#  Only for OpenSSL >= 0.9.8.f
		#
		ecdh_curve = "prime256v1"

		#
		#  Session resumption / fast reauthentication
		#  cache.
		#
		#  The cache contains the following information:
		#
		#  session Id - unique identifier, managed by SSL
		#  User-Name  - from the Access-Accept
		#  Stripped-User-Name - from the Access-Request
		#  Cached-Session-Policy - from the Access-Accept
		#
		#  The "Cached-Session-Policy" is the name of a
		#  policy which should be applied to the cached
		#  session.  This policy can be used to assign
		#  VLANs, IP addresses, etc.  It serves as a useful
		#  way to re-apply the policy from the original
		#  Access-Accept to the subsequent Access-Accept
		#  for the cached session.
		#
		#  On session resumption, these attributes are
		#  copied from the cache, and placed into the
		#  reply list.
		#
		#  You probably also want "use_tunneled_reply = yes"
		#  when using fast session resumption.
		#
		cache {
			#
			#  Enable it.  The default is "no". Deleting the entire "cache"
			#  subsection also disables caching.
			#
			#  You can disallow resumption for a particular user by adding the
			#  following attribute to the control item list:
			#
			#    Allow-Session-Resumption = No
			#
			#  If "enable = no" below, you CANNOT enable resumption for just one
			#  user by setting the above attribute to "yes".
			#
			enable = yes

			#
			#  Lifetime of the cached entries, in hours. The sessions will be
			#  deleted/invalidated after this time.
			#
			lifetime = 24 # hours

			#
			#  The maximum number of entries in the
			#  cache.  Set to "0" for "infinite".
			#
			#  This could be set to the number of users
			#  who are logged in... which can be a LOT.
			#
			max_entries = 255

			#
			#  Internal "name" of the session cache. Used to
			#  distinguish which TLS context sessions belong to.
			#
			#  The server will generate a random value if unset.
			#  This will change across server restart so you MUST
			#  set the "name" if you want to persist sessions (see
			#  below).
			#
			#name = "EAP module"

			#
			#  Simple directory-based storage of sessions.
			#  Two files per session will be written, the SSL
			#  state and the cached VPs. This will persist session
			#  across server restarts.
			#
			#  The server will need write perms, and the directory
			#  should be secured from anyone else. You might want
			#  a script to remove old files from here periodically:
			#
			#
			#  This feature REQUIRES "name" option be set above.
			#
			#persist_dir = "/var/log/freeradius-wpe/tlscache"
		}

		#
		#  As of version 2.1.10, client certificates can be
		#  validated via an external command.  This allows
		#  dynamic CRLs or OCSP to be used.
		#
		#  This configuration is commented out in the
		#  default configuration.  Uncomment it, and configure
		#  the correct paths below to enable it.
		#
		#  If OCSP checking is enabled, and the OCSP checks fail,
		#  the verify section is not run.
		#
		#  If OCSP checking is disabled, the verify section is
		#  run on successful certificate validation.
		#
		verify {
			#  If the OCSP checks succeed, the verify section
			#  is run to allow additional checks.
			#
			#  If you want to skip verify on OCSP success,
			#  uncomment this configuration item, and set it
			#  to "yes".
	#		skip_if_ocsp_ok = no

			#  A temporary directory where the client
			#  certificates are stored.  This directory
			#  MUST be owned by the UID of the server,
			#  and MUST not be accessible by any other
			#  users.  When the server starts, it will do
			#  "chmod go-rwx" on the directory, for
			#  security reasons.  The directory MUST
			#  exist when the server starts.
			#
			#  You should also delete all of the files
			#  in the directory when the server starts.
	#		tmpdir = /tmp/radiusd

			#  The command used to verify the client cert.
			#  We recommend using the OpenSSL command-line
			#  tool.
			#
			#  The ca_path text is a reference to
			#  the ca_path variable defined above.
			#
			#  The [[TLS-Client-Cert-Filename]] is the name
			#  of the temporary file containing the cert
			#  in PEM format.  This file is automatically
			#  deleted by the server when the command
			#  returns.
	#		client = "/path/to/openssl verify -CApath /etc/freeradius-wpe/3.0/certs [[TLS-Client-Cert-Filename]]"
		}

		#
		#  OCSP Configuration
		#  Certificates can be verified against an OCSP
		#  Responder. This makes it possible to immediately
		#  revoke certificates without the distribution of
		#  new Certificate Revocation Lists (CRLs).
		#
		ocsp {
			#
			#  Enable it.  The default is "no".
			#  Deleting the entire "ocsp" subsection
			#  also disables ocsp checking
			#
			enable = no

			#
			#  The OCSP Responder URL can be automatically
			#  extracted from the certificate in question.
			#  To override the OCSP Responder URL set
			#  "override_cert_url = yes".
			#
			override_cert_url = yes

			#
			#  If the OCSP Responder address is not extracted from
			#  the certificate, the URL can be defined here.
			#
			url = "http://127.0.0.1/ocsp/"

			#
			# If the OCSP Responder can not cope with nonce
			# in the request, then it can be disabled here.
			#
			# For security reasons, disabling this option
			# is not recommended as nonce protects against
			# replay attacks.
			#
			# Note that Microsoft AD Certificate Services OCSP
			# Responder does not enable nonce by default. It is
			# more secure to enable nonce on the responder than
			# to disable it in the query here.
			#
			# use_nonce = yes

			#
			# Number of seconds before giving up waiting
			# for OCSP response. 0 uses system default.
			#
			# timeout = 0

			#
			# Normally an error in querying the OCSP
			# responder (no response from server, server did
			# not understand the request, etc) will result in
			# a validation failure.
			#
			# To treat these errors as 'soft' failures and
			# still accept the certificate, enable this
			# option.
			#
			# Warning: this may enable clients with revoked
			# certificates to connect if the OCSP responder
			# is not available. Use with caution.
			#
			# softfail = no
		}
	}

	## EAP-TTLS
	#
	#  The TTLS module implements the EAP-TTLS protocol,
	#  which can be described as EAP inside of Diameter,
	#  inside of TLS, inside of EAP, inside of RADIUS...
	#
	#  Surprisingly, it works quite well.
	#
	ttls {
		#  Which tls-config section the TLS negotiation parameters
		#  are in - see EAP-TLS above for an explanation.
		#
		#  In the case that an old configuration from FreeRADIUS
		#  v2.x is being used, all the options of the tls-config
		#  section may also appear instead in the 'tls' section
		#  above. If that is done, the tls= option here (and in
		#  tls above) MUST be commented out.
		#
		tls = tls-common

		#  The tunneled EAP session needs a default EAP type
		#  which is separate from the one for the non-tunneled
		#  EAP module.  Inside of the TTLS tunnel, we recommend
		#  using EAP-MD5.  If the request does not contain an
		#  EAP conversation, then this configuration entry is
		#  ignored.
		#
		default_eap_type = md5

		#  The tunneled authentication request does not usually
		#  contain useful attributes like 'Calling-Station-Id',
		#  etc.  These attributes are outside of the tunnel,
		#  and normally unavailable to the tunneled
		#  authentication request.
		#
		#  By setting this configuration entry to 'yes',
		#  any attribute which is NOT in the tunneled
		#  authentication request, but which IS available
		#  outside of the tunnel, is copied to the tunneled
		#  request.
		#
		#  allowed values: {no, yes}
		#
		copy_request_to_tunnel = no

		#
		#  As of version 3.0.5, this configuration item
		#  is deprecated.  Instead, you should use
		#
		# 	update outer.session-state {
		#		...
		#
		#	}
		#
		#  This will cache attributes for the final Access-Accept.
		#
		#  The reply attributes sent to the NAS are usually
		#  based on the name of the user 'outside' of the
		#  tunnel (usually 'anonymous').  If you want to send
		#  the reply attributes based on the user name inside
		#  of the tunnel, then set this configuration entry to
		#  'yes', and the reply to the NAS will be taken from
		#  the reply to the tunneled request.
		#
		#  allowed values: {no, yes}
		#
		use_tunneled_reply = no

		#
		#  The inner tunneled request can be sent
		#  through a virtual server constructed
		#  specifically for this purpose.
		#
		#  If this entry is commented out, the inner
		#  tunneled request will be sent through
		#  the virtual server that processed the
		#  outer requests.
		#
		virtual_server = "inner-tunnel"

		#  This has the same meaning, and overwrites, the
		#  same field in the "tls" configuration, above.
		#  The default value here is "yes".
		#
	#	include_length = yes

		#
		# Unlike EAP-TLS, EAP-TTLS does not require a client
		# certificate. However, you can require one by setting the
		# following option. You can also override this option by
		# setting
		#
		#	EAP-TLS-Require-Client-Cert = Yes
		#
		# in the control items for a request.
		#
	#	require_client_cert = yes
	}
}
'''

freeradius_eap_tls_conf = '''
# -*- text -*-
##
##  eap.conf -- Configuration for EAP types (PEAP, TTLS, etc.)
##
##	$Id: 427016c66da92b5aa87ac784e74550c4e723c0cd $

#######################################################################
#
#  Whatever you do, do NOT set 'Auth-Type := EAP'.  The server
#  is smart enough to figure this out on its own.  The most
#  common side effect of setting 'Auth-Type := EAP' is that the
#  users then cannot use ANY other authentication method.
#
eap {
	#  Invoke the default supported EAP type when
	#  EAP-Identity response is received.
	#
	#  The incoming EAP messages DO NOT specify which EAP
	#  type they will be using, so it MUST be set here.
	#
	#  For now, only one default EAP type may be used at a time.
	#
	#  If the EAP-Type attribute is set by another module,
	#  then that EAP type takes precedence over the
	#  default type configured here.
	#
	default_eap_type = %s

	#  A list is maintained to correlate EAP-Response
	#  packets with EAP-Request packets.  After a
	#  configurable length of time, entries in the list
	#  expire, and are deleted.
	#
	timer_expire     = 60

	#  There are many EAP types, but the server has support
	#  for only a limited subset.  If the server receives
	#  a request for an EAP type it does not support, then
	#  it normally rejects the request.  By setting this
	#  configuration to "yes", you can tell the server to
	#  instead keep processing the request.  Another module
	#  MUST then be configured to proxy the request to
	#  another RADIUS server which supports that EAP type.
	#
	#  If another module is NOT configured to handle the
	#  request, then the request will still end up being
	#  rejected.
	ignore_unknown_eap_types = no

	# Cisco AP1230B firmware 12.2(13)JA1 has a bug.  When given
	# a User-Name attribute in an Access-Accept, it copies one
	# more byte than it should.
	#
	# We can work around it by configurably adding an extra
	# zero byte.
	cisco_accounting_username_bug = no

	#
	#  Help prevent DoS attacks by limiting the number of
	#  sessions that the server is tracking.  For simplicity,
	#  this is taken from the "max_requests" directive in
	#  radiusd.conf.
	max_sessions = 16384

	# Supported EAP-types

	## Common TLS configuration for TLS-based EAP types
	#
	#  See raddb/certs/README for additional comments
	#  on certificates.
	#
	#  If OpenSSL was not found at the time the server was
	#  built, the "tls", "ttls", and "peap" sections will
	#  be ignored.
	#
	#  If you do not currently have certificates signed by
	#  a trusted CA you may use the 'snakeoil' certificates.
	#  Included with the server in raddb/certs.
	#
	#  If these certificates have not been auto-generated:
	#    cd raddb/certs
	#    make
	#
	#  These test certificates SHOULD NOT be used in a normal
	#  deployment.  They are created only to make it easier
	#  to install the server, and to perform some simple
	#  tests with EAP-TLS, TTLS, or PEAP.
	#
	#  See also:
	#
	#  http://www.dslreports.com/forum/remark,9286052~mode=flat
	#
	#  Note that you should NOT use a globally known CA here!
	#  e.g. using a Verisign cert as a "known CA" means that
	#  ANYONE who has a certificate signed by them can
	#  authenticate via EAP-TLS!  This is likely not what you want.
	tls-config tls-common {
		private_key_password = whatever
		private_key_file = %s

		#  If Private key & Certificate are located in
		#  the same file, then private_key_file &
		#  certificate_file must contain the same file
		#  name.
		#
		#  If ca_file (below) is not used, then the
		#  certificate_file below MUST include not
		#  only the server certificate, but ALSO all
		#  of the CA certificates used to sign the
		#  server certificate.
		certificate_file = %s

		#  Trusted Root CA list
		#
		#  ALL of the CA's in this list will be trusted
		#  to issue client certificates for authentication.
		#
		#  In general, you should use self-signed
		#  certificates for 802.1x (EAP) authentication.
		#  In that case, this CA file should contain
		#  *one* CA certificate.
		#
		ca_file = %s

	 	#  OpenSSL will automatically create certificate chains,
	 	#  unless we tell it to not do that.  The problem is that
	 	#  it sometimes gets the chains right from a certificate
	 	#  signature view, but wrong from the clients view.
		#
		#  When setting "auto_chain = no", the server certificate
		#  file MUST include the full certificate chain.
	#	auto_chain = yes

		#
		#  If OpenSSL supports TLS-PSK, then we can use
		#  a PSK identity and (hex) password.  When the
		#  following two configuration items are specified,
		#  then certificate-based configuration items are
		#  not allowed.  e.g.:
		#
		#	private_key_password
		#	private_key_file
		#	certificate_file
		#	ca_file
		#	ca_path
		#
		#  For now, the identity is fixed, and must be the
		#  same on the client.  The passphrase must be a hex
		#  value, and can be up to 256 hex digits.
		#
		#  Future versions of the server may be able to
		#  look up the shared key (hexphrase) based on the
		#  identity.
		#
	#	psk_identity = "test"
	#	psk_hexphrase = "036363823"

		#
		#  For DH cipher suites to work, you have to
		#  run OpenSSL to create the DH file first:
		#
		#  	openssl dhparam -out certs/dh 2048
		#
		dh_file = %s

		#
		#  If your system doesn't have /dev/urandom,
		#  you will need to create this file, and
		#  periodically change its contents.
		#
		#  For security reasons, FreeRADIUS doesn't
		#  write to files in its configuration
		#  directory.
		#
	#	random_file = /dev/urandom

		#
		#  This can never exceed the size of a RADIUS
		#  packet (4096 bytes), and is preferably half
		#  that, to accommodate other attributes in
		#  RADIUS packet.  On most APs the MAX packet
		#  length is configured between 1500 - 1600
		#  In these cases, fragment size should be
		#  1024 or less.
		#
	#	fragment_size = 1024

		#  include_length is a flag which is
		#  by default set to yes If set to
		#  yes, Total Length of the message is
		#  included in EVERY packet we send.
		#  If set to no, Total Length of the
		#  message is included ONLY in the
		#  First packet of a fragment series.
		#
	#	include_length = yes


		#  Check the Certificate Revocation List
		#
		#  1) Copy CA certificates and CRLs to same directory.
		#  2) Execute 'c_rehash <CA certs&CRLs Directory>'.
		#    'c_rehash' is OpenSSL's command.
		#  3) uncomment the lines below.
		#  5) Restart radiusd
	#	check_crl = yes

		# Check if intermediate CAs have been revoked.
	#	check_all_crl = yes

		ca_path = %s

		#
		#  If check_cert_issuer is set, the value will
		#  be checked against the DN of the issuer in
		#  the client certificate.  If the values do not
		#  match, the certificate verification will fail,
		#  rejecting the user.
		#
		#  In 2.1.10 and later, this check can be done
		#  more generally by checking the value of the
		#  TLS-Client-Cert-Issuer attribute.  This check
		#  can be done via any mechanism you choose.
		#
	#	check_cert_issuer = "/C=GB/ST=Berkshire/L=Newbury/O=My Company Ltd"

		#
		#  If check_cert_cn is set, the value will
		#  be xlat'ed and checked against the CN
		#  in the client certificate.  If the values
		#  do not match, the certificate verification
		#  will fail rejecting the user.
		#
		#  This check is done only if the previous
		#  "check_cert_issuer" is not set, or if
		#  the check succeeds.
		#
		#  In 2.1.10 and later, this check can be done
		#  more generally by checking the value of the
		#  TLS-Client-Cert-CN attribute.  This check
		#  can be done via any mechanism you choose.
		#
	#	check_cert_cn = [[User-Name]]
		#
		# Set this option to specify the allowed
		# TLS cipher suites.  The format is listed
		# in "man 1 ciphers".
		#
		# For EAP-FAST, use "ALL:!EXPORT:!eNULL:!SSLv2"
		#
		cipher_list = "DEFAULT"

		# If enabled, OpenSSL will use server cipher list
		# (possibly defined by cipher_list option above)
		# for choosing right cipher suite rather than
		# using client-specified list which is OpenSSl default
		# behavior. Having it set to yes is a current best practice
		# for TLS
		cipher_server_preference = no

		# Work-arounds for OpenSSL nonsense
		# OpenSSL 1.0.1f and 1.0.1g do not calculate
		# the EAP keys correctly.  The fix is to upgrade
		# OpenSSL, or disable TLS 1.2 here. 
		#
		#  For EAP-FAST, this MUST be set to "yes".
		#
#		disable_tlsv1_2 = no

		#

		#
		#  Elliptical cryptography configuration
		#
		#  Only for OpenSSL >= 0.9.8.f
		#
		ecdh_curve = "prime256v1"

		#
		#  Session resumption / fast reauthentication
		#  cache.
		#
		#  The cache contains the following information:
		#
		#  session Id - unique identifier, managed by SSL
		#  User-Name  - from the Access-Accept
		#  Stripped-User-Name - from the Access-Request
		#  Cached-Session-Policy - from the Access-Accept
		#
		#  The "Cached-Session-Policy" is the name of a
		#  policy which should be applied to the cached
		#  session.  This policy can be used to assign
		#  VLANs, IP addresses, etc.  It serves as a useful
		#  way to re-apply the policy from the original
		#  Access-Accept to the subsequent Access-Accept
		#  for the cached session.
		#
		#  On session resumption, these attributes are
		#  copied from the cache, and placed into the
		#  reply list.
		#
		#  You probably also want "use_tunneled_reply = yes"
		#  when using fast session resumption.
		#
		cache {
			#
			#  Enable it.  The default is "no". Deleting the entire "cache"
			#  subsection also disables caching.
			#
			#  You can disallow resumption for a particular user by adding the
			#  following attribute to the control item list:
			#
			#    Allow-Session-Resumption = No
			#
			#  If "enable = no" below, you CANNOT enable resumption for just one
			#  user by setting the above attribute to "yes".
			#
			enable = yes

			#
			#  Lifetime of the cached entries, in hours. The sessions will be
			#  deleted/invalidated after this time.
			#
			lifetime = 24 # hours

			#
			#  The maximum number of entries in the
			#  cache.  Set to "0" for "infinite".
			#
			#  This could be set to the number of users
			#  who are logged in... which can be a LOT.
			#
			max_entries = 255

			#
			#  Internal "name" of the session cache. Used to
			#  distinguish which TLS context sessions belong to.
			#
			#  The server will generate a random value if unset.
			#  This will change across server restart so you MUST
			#  set the "name" if you want to persist sessions (see
			#  below).
			#
			#name = "EAP module"

			#
			#  Simple directory-based storage of sessions.
			#  Two files per session will be written, the SSL
			#  state and the cached VPs. This will persist session
			#  across server restarts.
			#
			#  The server will need write perms, and the directory
			#  should be secured from anyone else. You might want
			#  a script to remove old files from here periodically:
			#
			#
			#  This feature REQUIRES "name" option be set above.
			#
			#persist_dir = "/var/log/freeradius-wpe/tlscache"
		}

		#
		#  As of version 2.1.10, client certificates can be
		#  validated via an external command.  This allows
		#  dynamic CRLs or OCSP to be used.
		#
		#  This configuration is commented out in the
		#  default configuration.  Uncomment it, and configure
		#  the correct paths below to enable it.
		#
		#  If OCSP checking is enabled, and the OCSP checks fail,
		#  the verify section is not run.
		#
		#  If OCSP checking is disabled, the verify section is
		#  run on successful certificate validation.
		#
		verify {
			#  If the OCSP checks succeed, the verify section
			#  is run to allow additional checks.
			#
			#  If you want to skip verify on OCSP success,
			#  uncomment this configuration item, and set it
			#  to "yes".
	#		skip_if_ocsp_ok = no

			#  A temporary directory where the client
			#  certificates are stored.  This directory
			#  MUST be owned by the UID of the server,
			#  and MUST not be accessible by any other
			#  users.  When the server starts, it will do
			#  "chmod go-rwx" on the directory, for
			#  security reasons.  The directory MUST
			#  exist when the server starts.
			#
			#  You should also delete all of the files
			#  in the directory when the server starts.
	#		tmpdir = /tmp/radiusd

			#  The command used to verify the client cert.
			#  We recommend using the OpenSSL command-line
			#  tool.
			#
			#  The ca_path text is a reference to
			#  the ca_path variable defined above.
			#
			#  The [[TLS-Client-Cert-Filename]] is the name
			#  of the temporary file containing the cert
			#  in PEM format.  This file is automatically
			#  deleted by the server when the command
			#  returns.
	#		client = "/path/to/openssl verify -CApath /etc/freeradius-wpe/3.0/certs [[TLS-Client-Cert-Filename]]"
		}

		#
		#  OCSP Configuration
		#  Certificates can be verified against an OCSP
		#  Responder. This makes it possible to immediately
		#  revoke certificates without the distribution of
		#  new Certificate Revocation Lists (CRLs).
		#
		ocsp {
			#
			#  Enable it.  The default is "no".
			#  Deleting the entire "ocsp" subsection
			#  also disables ocsp checking
			#
			enable = no

			#
			#  The OCSP Responder URL can be automatically
			#  extracted from the certificate in question.
			#  To override the OCSP Responder URL set
			#  "override_cert_url = yes".
			#
			override_cert_url = yes

			#
			#  If the OCSP Responder address is not extracted from
			#  the certificate, the URL can be defined here.
			#
			url = "http://127.0.0.1/ocsp/"

			#
			# If the OCSP Responder can not cope with nonce
			# in the request, then it can be disabled here.
			#
			# For security reasons, disabling this option
			# is not recommended as nonce protects against
			# replay attacks.
			#
			# Note that Microsoft AD Certificate Services OCSP
			# Responder does not enable nonce by default. It is
			# more secure to enable nonce on the responder than
			# to disable it in the query here.
			#
			# use_nonce = yes

			#
			# Number of seconds before giving up waiting
			# for OCSP response. 0 uses system default.
			#
			# timeout = 0

			#
			# Normally an error in querying the OCSP
			# responder (no response from server, server did
			# not understand the request, etc) will result in
			# a validation failure.
			#
			# To treat these errors as 'soft' failures and
			# still accept the certificate, enable this
			# option.
			#
			# Warning: this may enable clients with revoked
			# certificates to connect if the OCSP responder
			# is not available. Use with caution.
			#
			# softfail = no
		}
	}

	## EAP-TLS
	#
	#  As of Version 3.0, the TLS configuration for TLS-based
	#  EAP types is above in the "tls-config" section.
	#
	tls {
		# Point to the common TLS configuration
		tls = tls-common

		#
		# As part of checking a client certificate, the EAP-TLS
		# sets some attributes such as TLS-Client-Cert-CN. This
		# virtual server has access to these attributes, and can
		# be used to accept or reject the request.
		#
	#	virtual_server = check-eap-tls
	}
}
'''