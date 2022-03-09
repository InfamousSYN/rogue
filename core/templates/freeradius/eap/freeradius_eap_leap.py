#!/usr/bin/python

freeradius_eap_leap = '''

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

'''
