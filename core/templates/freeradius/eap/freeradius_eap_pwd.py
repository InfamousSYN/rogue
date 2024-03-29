#!/usr/bin/python

freeradius_eap_pwd = '''

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

'''
