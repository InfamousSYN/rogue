#!/usr/bin/python3
import sys

import config
from core.libs import cert_manager

def cert_wizard():

    while True:

        print('[*] Please enter two letter country '
                            'code for certs (i.e. US, FR)')

        country = input(': ').upper()
        if len(country) == 2:
            break
        print('[!] Invalid input.')

    print('[*] Please enter state or province for '
                        'certs (i.e. Ontario, New Jersey)')
    state = input(': ')

    print('[*] Please enter locale for certs (i.e. London, Hong Kong)')
    locale = input(': ')

    print('[*] Please enter organization for certs (i.e. rogue)')
    org = input(': ')

    print('[*] Please enter email for certs (i.e. rogue@rogue.rogue)')
    email = input(': ')

    print('[*] Please enter common name (CN) for certs. (i.e. rogue)')
    cn = input(': ')

    cert_manager.ca_cnf.configure(country, state, locale, org, email, cn)
    cert_manager.server_cnf.configure(country, state, locale, org, email, cn)
    cert_manager.client_cnf.configure(country, state, locale, org, email, cn)

    cert_manager.bootstrap()

    return