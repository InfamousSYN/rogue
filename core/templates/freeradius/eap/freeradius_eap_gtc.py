#!/usr/bin/python

freeradius_eap_gtc = '''

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

'''
