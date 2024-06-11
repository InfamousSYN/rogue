#!/usr/bin/python3
import os
import argparse

# application version
__version__ = "3.1.0"

# application site
__location__ = "https://rogue.infamoussyn.com/"

# directory mapping
root_dir, conf_file = os.path.split(os.path.abspath(__file__))
core_dir = root_dir + "/core"
logdir = root_dir + "/logs"
working_dir = root_dir + "/tmp"
conf_dir = core_dir + "/config"
lib_dir = core_dir + "/libs"
templates_dir = root_dir + "/templates"
hostapd_templates_dir = templates_dir + "/hostapd"

# installation
install_dir = root_dir + "/install"
software_dep = install_dir + "/software.req"
pip_dep = install_dir + "/pip.req"

## Certificates
certs_dir = core_dir + "/certs"
ca_cnf = certs_dir + "/ca.cnf"
server_cnf = certs_dir + "/server.cnf"
client_cnf = certs_dir + "/client.cnf"
bootstrap_file = certs_dir + "/bootstrap"

### Trusted Root Certificate Settings (PEM or DER file)
trusted_root_ca_pem = certs_dir + "/ca.pem"

### RADIUS Server Certificate Settings (PEM or DER file)
server_pem = certs_dir + "/server.pem"
private_key = certs_dir + "/server.key"
private_key_passwd = "whatever"
dh_file = certs_dir + "/dh"

# rogue options default values
rogue_bssid = "00:11:22:33:44:00"
rogue_essid = "rogue"
rogue_auth = "open"
rogue_hw_mode = "g"
rogue_channel = 0
rogue_default_frequency = 2
rogue_ht_mode = 0
rogue_auth_algs = 3
rogue_macaddr_acl = 0
rogue_default_eap_type = "md5"
rogue_default_eap_types = ['fast','peap','ttls','tls','leap','pwd','md5','gtc']
rogue_supported_eap_type = ["md5"]
rogue_supported_eap_types = ['all','fast','peap','ttls','tls','leap','pwd','md5','gtc']
rogue_country_options = ["AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BQ", "BR", "BS", "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN", "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM", "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW", "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS", "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO", "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI", "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW"]
rogue_vht_index = 1
rogue_vht_operations = 0
rogue_vht_index_options = 42
rogue_wpa_version = 2
rogue_eapol_version = 2
rogue_essid_mask = 0

# hostapd-wpe settings
hostapd_conf_file = "/hostapd-wpe.conf"
hostapd_conf_full = working_dir + hostapd_conf_file
hostapd_command = "%s "
hostapd_command_with_karma = "%s -k"
hostapd_command_with_debug = "%s -d"
hostapd_command_with_ddebug = "%s -dd"
hostapd_log = logdir + "/hostapd-wpe.log"
hostapd_dir = "/usr/sbin"
hostapd_bin = hostapd_dir + "/hostapd-wpe"
eap_user_file = "/etc/hostapd-wpe/hostapd-wpe.eap_user"
hostapd_accept_file = "/hostapd.accept"
hostapd_accept_file_full = working_dir + hostapd_accept_file
hostapd_deny_file = "/hostapd.deny"
hostapd_deny_file_full = working_dir + hostapd_deny_file

# freeradius-wpe settings
freeradius_dir = "/usr/sbin"
#freeradius_bin = freeradius_dir + "/freeradius-wpe"
freeradius_bin = freeradius_dir + "/freeradius-wpe"
freeradius_log = logdir + "/freeradius-wpe.log"
freeradius_working_dir = "/etc/freeradius-wpe/3.0"
freeradius_mods_dir = freeradius_working_dir + '/mods-available'
freeradius_mods_enabled_dir = freeradius_working_dir + '/mods-enabled'
freeradius_available_site_location = freeradius_working_dir + '/sites-available'
freeradius_mods_dir_eap_full = freeradius_mods_dir + '/eap'
freeradius_radiusd_full = freeradius_working_dir + '/radiusd.conf'
freeradius_clients_full = freeradius_working_dir + '/clients.conf'
freeradius_default_site_full = freeradius_available_site_location + '/default'
freeradius_command = "-X -l %s -d %s"
wpelogfile = logdir + "/freeradius-server-wpe.log"
wpelogfile_default_install = "/var/log/freeradius-server-wpe.log"
radiuslog = logdir + "/radius.log"
default_own_ip_addr = "127.0.0.1"
default_auth_server_addr = default_own_ip_addr
default_auth_server_shared_secret = "secret"
default_auth_server_port = 1812
default_acct_server_addr = default_own_ip_addr
default_acct_server_shared_secret = "secret"
default_acct_server_port = 1813

# isc-dhcp-server settings
dhcp_conf_dir = "/etc/dhcp"
dhcp_conf = dhcp_conf_dir + "/dhcpd.conf"
dhcp_default = "/etc/default/isc-dhcp-server"
default_dhcpv4_conf_location = dhcp_conf
default_ip_address = "10.254.239.1"
default_dhcp_netmask = "255.255.255.0"
default_route_subnet = "10.254.239"
default_dhcp_subnet = "10.254.239.0"
default_dhcp_pool_start = "10.254.239.10"
default_dhcp_pool_end = "10.254.239.70"
default_default_lease_time = 600
default_max_lease_time = 7200
default_primary_name_server = "8.8.8.8"
default_secondary_name_server = "8.8.4.4"

## Attack configs
supported_attack_modules = ['responder', 'modlishka', 'sslsplit']

# sslsplit
ca_key = certs_dir + "/ca_no_pass.key"
ca_crt = certs_dir + "/ca.crt"
sslsplit_log = logdir + "/sslsplit.log"
sslsplit_tmp = working_dir + "/sslsplit"
sslsplit_jail = sslsplit_tmp + "/jail"
sslsplit_encrypted_port = 8443
sslsplit_cmd = "-d -l %s -j %s -S %s -k %s -c %s ssl 0.0.0.0 %d"

# responder
responder_bin = '/usr/sbin/responder'
responder_cmd = '-I %s 2>&1'
responder_conf = '/etc/responder/Responder.conf'

# modlishka
modlishka_cmd = '-proxyDomain %s -proxyAddress %s -controlURL %s -controlCreds %s -listeningAddress %s -target %s'
modlishka_proxydomain = 'loopback.modlishka.io'
modlishka_listeningaddress = default_ip_address
modlishka_proxyaddress = None
modlishka_controlURL = 'rogue'
modlishka_controlCreds = 'rogue:rogue'

# service configs
use_systemd = True
network_manager = "network-manager"
network_manager_bin = None
dhcp_server = "isc-dhcp-server"
dhcp_server_bin = None
wpa_supplicant = "wpa_supplicant"
wpa_supplicant_bin = None
mysql_service = 'mysql'
mysql_bin = None
sslsplit_bin = "/usr/bin/sslsplit"
modlishka_bin = "/home/kali/go/bin/Modlishka"


# don't touch these
wlan_clean_sleep = 1
generic_sleep = 3
hostapd_sleep = 4
freeradius_sleep = 4
mysql_sleep = 3
sslsplit_sleep = 4
responder_sleep = 4
network_manager_sleep = 4
dhcp_server_sleep = 4
wpa_supplicant_sleep = 4
secondary_interface = "eth0"
proc_ipforward = "/proc/sys/net/ipv4/ip_forward"
default_browser = "firefox"
default_ipv6_address = 'fe80::aefe:ef01'
default_hostapd_driver = 'nl80211'
