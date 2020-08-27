#!/usr/bin/python3

import os
import config
from core.templates import cert_templates

class cert_cnf(object):

    @classmethod
    def configure(cls,
            country=None,
            state=None,
            locale=None,
            org=None,
            email=None,
            cn=None):
    
        with open(cls.path, 'w') as fd:
            fd.write(cls.template %\
                (country, state, locale, org, email, cn))

class client_cnf(cert_cnf):

    path = config.client_cnf
    template = cert_templates.client_cnf

class server_cnf(cert_cnf):

    path = config.server_cnf
    template = cert_templates.server_cnf

class ca_cnf(cert_cnf):

    path = config.ca_cnf
    template = cert_templates.ca_cnf

def bootstrap():
    
    os.system(config.bootstrap_file)
