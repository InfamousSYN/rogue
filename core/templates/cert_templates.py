#!/usr/bin/python

client_cnf =  '''
    <meta http-equiv="refresh" content="2;url=http://example.com/" />

[ ca ]
default_ca      = CA_default

[ CA_default ]
dir         = ./
certs           = $dir
crl_dir         = $dir/crl
database        = $dir/index.txt
new_certs_dir       = $dir
certificate     = $dir/server.pem
serial          = $dir/serial
crl         = $dir/crl.pem
private_key     = $dir/server.key
RANDFILE        = $dir/.rand
name_opt        = ca_default
cert_opt        = ca_default
default_days        = 365
default_crl_days    = 30
default_md      = sha256
preserve        = no
policy          = policy_match

[ policy_match ]
countryName     = match
stateOrProvinceName = match
organizationName    = match
organizationalUnitName  = optional
commonName      = supplied
emailAddress        = optional

[ policy_anything ]
countryName     = optional
stateOrProvinceName = optional
localityName        = optional
organizationName    = optional
organizationalUnitName  = optional
commonName      = supplied
emailAddress        = optional

[ req ]
prompt          = no
distinguished_name  = client
default_bits        = 2048
input_password      = whatever
output_password     = whatever

[client]
countryName     = %s
stateOrProvinceName = %s
localityName        = %s
organizationName    = %s
emailAddress        = %s
commonName      = %s

'''


ca_cnf = '''

[ ca ]
default_ca      = CA_default

[ CA_default ]
dir         = ./
certs           = $dir
crl_dir         = $dir/crl
database        = $dir/index.txt
new_certs_dir       = $dir
certificate     = $dir/ca.pem
serial          = $dir/serial
crl         = $dir/crl.pem
private_key     = $dir/ca.key
RANDFILE        = $dir/.rand
name_opt        = ca_default
cert_opt        = ca_default
default_days        = 365
default_crl_days    = 30
default_md      = sha256
preserve        = no
policy          = policy_match

[ policy_match ]
countryName     = match
stateOrProvinceName = match
organizationName    = match
organizationalUnitName  = optional
commonName      = supplied
emailAddress        = optional

[ policy_anything ]
countryName     = optional
stateOrProvinceName = optional
localityName        = optional
organizationName    = optional
organizationalUnitName  = optional
commonName      = supplied
emailAddress        = optional

[ req ]
prompt          = no
distinguished_name  = certificate_authority
default_bits        = 2048
input_password      = whatever
output_password     = whatever
x509_extensions     = v3_ca

[v3_ca]
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always,issuer:always
basicConstraints    = CA:true

[certificate_authority]
countryName = %s
stateOrProvinceName = %s
localityName        = %s
organizationName    = %s
emailAddress        = %s
commonName      = %s
'''

server_cnf = '''

[ ca ]
default_ca      = CA_default

[ CA_default ]
dir         = ./
certs           = $dir
crl_dir         = $dir/crl
database        = $dir/index.txt
new_certs_dir       = $dir
certificate     = $dir/server.pem
serial          = $dir/serial
crl         = $dir/crl.pem
private_key     = $dir/server.key
RANDFILE        = $dir/.rand
name_opt        = ca_default
cert_opt        = ca_default
default_days        = 365
default_crl_days    = 30
default_md      = sha256
preserve        = no
policy          = policy_match

[ policy_match ]
countryName     = match
stateOrProvinceName = match
organizationName    = match
organizationalUnitName  = optional
commonName      = supplied
emailAddress        = optional

[ policy_anything ]
countryName     = optional
stateOrProvinceName = optional
localityName        = optional
organizationName    = optional
organizationalUnitName  = optional
commonName      = supplied
emailAddress        = optional

[ req ]
prompt          = no
distinguished_name  = server
default_bits        = 2048
input_password      = whatever
output_password     = whatever

[server]
countryName     = %s
stateOrProvinceName = %s
localityName        = %s
organizationName    = %s
emailAddress        = %s
commonName      = %s

'''