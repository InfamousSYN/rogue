#!/usr/bin/python

freeradius_eap_peap = '''

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

'''
