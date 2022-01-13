#!/usr/bin/python

freeradius_eap_fast = '''

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

'''
