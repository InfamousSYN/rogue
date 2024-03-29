#!/usr/bin/python

freeradius_eap_tls_common = '''

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
		private_key_password = %s
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

'''
