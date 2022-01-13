#!/usr/bin/python

freeradius_eap_tls = '''

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

'''
