#!/usr/bin/python
from argparse import *
import sys
import config

def set_options():
    parser = ArgumentParser(prog="%(prog)s",
                            description="The Rogue Toolkit is an extensible toolkit aimed at providing penetration testers an easy-to-use platform to deploy\
                            software-defined Access Points (AP) for the purpose of conducting penetration testing and red team engagements. By using Rogue, \
                            penetration testers can easily perform targeted evil twin attacks against a variety of wireless network types.",
                            usage="python rogue.py -i wlan0 -h g -c 6 -e rogue --auth open --internet",
                            add_help=False
                            )

    hostapd_config = parser.add_argument_group(
                    title='hostapd configuration')

    attacks = parser.add_argument_group(
                    title='Attack Arguments')

    ieee80211_config = parser.add_argument_group(
                    title='IEEE 802.11 related configuration')

    ieee80211n_config = parser.add_argument_group(
                    title='IEEE 802.11n related configuration')

    ieee80211ac_config = parser.add_argument_group(
                    title='IEEE 802.11ac related configuration')

    wpa_psk_config = parser.add_argument_group(
                    title='IWPA/IEEE 802.11i configuration')

    wep_config = parser.add_argument_group(
                    title='WEP authentication configuration')

    ieee8021x_config = parser.add_argument_group(
                    title='IEEE 802.1X-2004 configuration')

    radius_config = parser.add_argument_group(
                    title='RADIUS client configuration')

    dhcp = parser.add_argument_group(
                    title='External DHCP configuration')

    clone = parser.add_argument_group(
                    title='Website cloning configuration')

    sslsplit = parser.add_argument_group(
                    title='sslsplit configuration')

    httpd = parser.add_argument_group(
                    title='HTTPD configuration')

    parser.add_argument('-w', '--write',
                    dest='pcap_filename',
                    type=str,
                    default=None,
                    help='Write all collected wireless frames to a pcap file.')

    parser.add_argument('--internet',
                    dest='internet',
                    action='store_true',
                    help='Provide network access')

    parser.add_argument('--auth',
                    dest='auth',
                    type=str,
                    choices=['open','wep','wpa-personal','wpa-enterprise'],
                    default=config.rogue_auth,
                    help='Specify auth type. (Default: %s)' % config.rogue_auth)

    parser.add_argument('--cert-wizard',
                    dest='cert_wizard',
                    action='store_true',
                    help=('Use this flag to create a new RADIUS cert for your AP'))

    parser.add_argument('--clone-wizard',
                    dest='clone_wizard',
                    action='store_true',
                    help='Used to clone a target website')

    parser.add_argument('--show-options',
                    dest='show_options',
                    action='store_true',
                    help='Display configured options.')

    clone.add_argument('--clone-target',
                    dest='clone_target',
                    type=str,
                    help='Used to specify target website to clone (e.g. https://www.example.com/)')

    clone.add_argument('--clone-dest',
                    dest='clone_dest',
                    type=str,
                    default=config.httrack_dest,
                    help='Specify the location of the web root for the hostile portal, \r\n\
                    it is recommended that you clone to your web root. \r\n\
                    Note: httrack will create a directory in this location with the name of the site cloned. \r\n\
                    (Default: %s)' % config.httrack_dest)

    parser.add_argument('-i', '--interface',
                    dest='interface',
                    type=str,
                    help='The phy interface on which to create the AP')

    hostapd_config.add_argument('--driver',
                    dest='driver',
                    type=str,
                    choices=['hostap','nl80211','atheros','wired','none','bsd'],
                    help='Choose the hostapd-wpe driver')

    hostapd_config.add_argument('-d',
                    dest='debug',
                    action='store_true',
                    default=False,
                    help='show more hostapd-wpe debug messages')

    hostapd_config.add_argument('-dd',
                    dest='ddebug',
                    action='store_true',
                    default=False,
                    help='show even more hostapd-wpe debug messages')

    ieee80211_config.add_argument('-b', '--bssid',
                    dest='bssid',
                    default=config.rogue_bssid,
                    type=str,
                    help='Specify access point BSSID (Default: %s)' % (config.rogue_bssid))

    ieee80211_config.add_argument('-e', '--essid',
                    dest='essid',
                    type=str,
                    default=config.rogue_essid,
                    help='Specify access point ESSID (Default: %s)' % config.rogue_essid)

    ieee80211_config.add_argument('-h', '--hw-mode',
                    dest='hw_mode',
                    type=str,
                    choices=['a','b','g','n','ac'],
                    default=config.rogue_hw_mode,
                    help='Specify access point hardware mode (Default: %s).' % config.rogue_hw_mode)

    ieee80211_config.add_argument('--freq',
                    dest='freq',
                    type=int,
                    choices=[2,5],
                    default=config.rogue_default_frequency,
                    help='Specify the radio band to use (Default: %sGHz).' % config.rogue_default_frequency)

    ieee80211n_config.add_argument('--ht-mode',
                    dest='ht_mode',
                    type=int,
                    choices=[0,1,2],
                    default=config.rogue_ht_mode,
                    help='Configure supported channel width set\
                    0 = Feature disabled\
                    1 = [HT40-] (2.4 GHz = 5-13, 5 GHz = 40,48,56,64)\
                    2 = [HT40+] (2.4 GHz = 1-7 (1-9 in Europe/Japan), 5 GHz = 36,44,52,60)\
                    (Default = %s). ' % config.rogue_ht_mode)

    ieee80211n_config.add_argument('--disable-short20',
                    dest='short20',
                    action='store_false',
                    default=True,
                    help='Disables Short GI for 20 MHz for HT capabilities.')

    ieee80211n_config.add_argument('--disable-short40',
                    dest='short40',
                    action='store_false',
                    default=True,
                    help='Disables Short GI for 40 MHz for HT capabilities.')

    ieee80211_config.add_argument('-c', '--channel',
                    dest='channel',
                    type=int,
                    default=config.rogue_channel,
                    help='Specify access point channel. (Default: %s - with ACS to find an unused channel)' % config.rogue_channel)

    ieee80211_config.add_argument('--country',
                    dest='country_code',
                    type=str,
                    choices=config.rogue_country_options,
                    help='Configures of country of operation')

    ieee80211_config.add_argument('--macaddr-acl',
                    dest='macaddr_acl',
                    type=int,
                    choices=[0,1,2],
                    default=config.rogue_macaddr_acl,
                    help='Station MAC address -based authentication\r\n0 = accept unless in deny list\r\n  1 = deny unless in accept list\r\n  2 = use external RADIUS (accept/deny will be searched first)\r\n(Default: %s)' % config.rogue_macaddr_acl)

    ieee80211_config.add_argument('--mac-accept-file',
                    dest='macaddr_accept_file',
                    type=str,
                    default=config.hostapd_accept_file_full,
                    help='Location of hostapd-wpe macaddr_acl accept file (Default: %s)' % config.hostapd_accept_file_full)

    ieee80211_config.add_argument('--mac-deny-file',
                    dest='macaddr_deny_file',
                    type=str,
                    default=config.hostapd_deny_file_full,
                    help='Location of hostapd-wpe macaddr_acl deny file (Default: %s)' % config.hostapd_accept_file_full)

    ieee80211_config.add_argument('--auth-algs',
                    dest='auth_algs',
                    type=int,
                    choices=[1,2,3],
                    default=config.rogue_auth_algs,
                    help='IEEE 802.11 specifies two authentication algorithms. 1 allows only WPA2 authentication algorithms. 2 is WEP. 3 allows both. (Default: %s)' % config.rogue_auth_algs)

    ieee80211_config.add_argument('--wmm-enabled',
                    dest='wmm_enabled',
                    action="store_true",
                    help='Enable Wireless Multimedia Extensions')

    ieee80211n_config.add_argument('--require-ht',
                    dest='require_ht',
                    action='store_true',
                    default=False,
                    help='Require stations to support HT PHY (reject association if they do not). (Default: False)')

    ieee80211_config.add_argument('--ieee80211d',
                    dest='ieee80211d',
                    action='store_true',
                    default=False,
                    help='Enabling IEEE 802.11d advertises the country_code and the set of allowed channels and transmit power levels based on the regulatory limits. (Default: False)')

    ieee80211_config.add_argument('--ieee80211h',
                    dest='ieee80211h',
                    action='store_true',
                    default=False,
                    help='Enables radar detection and DFS support. DFS support is required for an outdoor 5 GHZ channel. (This can only be used if ieee80211d is enabled). (Default: False)')

    ieee80211_config.add_argument('--ap-isolate',
                    dest='ap_isolate',
                    action='store_true',
                    default=False,
                    help='Enable client isolation to prevent low-level bridging of frames between associated stations in the BSS. (Default: disabled)')

    ieee80211ac_config.add_argument('--vht-width',
                    dest='vht_oper_chwidth',
                    type=int,
                    choices=[0,1,2,3],
                    default=config.rogue_vht_index,
                    help='VHT channel width (Default: %s).' % config.rogue_vht_index)

    ieee80211ac_config.add_argument('--vht-operation',
                    dest='vht_oper',
                    type=int,
                    choices=[0,1],
                    default=config.rogue_vht_operations,
                    help='Enable toggling between 0 for vht_oper_centr_freq_seg0_idx and 1 for vht_oper_centr_freq_seg1_idx (Default: %s).' % config.rogue_vht_operations)

    ieee80211ac_config.add_argument('--vht-index',
                    dest='vht_index',
                    type=int,
                    default=config.rogue_vht_index_options,
                    help='Enables control of vht_oper_centr_freq_seg[0/1]_idx index value (Default: %s).' % (config.rogue_vht_index_options))

    ieee80211ac_config.add_argument('--require-vht',
                    dest='require_vht',
                    action='store_true',
                    default=False,
                    help='Require stations to support VHT PHY (reject association if they do not) (Default: disabled).')

    wep_config.add_argument('--wep-key-version',
                    dest='wep_default_key',
                    type=int,
                    choices=[0,1,2,3],
                    help='Determine the version of the WEP configuration')

    wep_config.add_argument('--wep-key',
                    dest='wep_key',
                    type=str,
                    help='Determine the version of the WEP configuration')

    wpa_psk_config.add_argument('--wpa-passphrase',
                    dest='wpa_passphrase',
                    type=str,
                    help='Specify the Pre-Shared Key for WPA network.')

    wpa_psk_config.add_argument('--wpa',
                    dest='wpa',
                    type=int,
                    choices=[1,2,3],
                    default=config.rogue_wpa_version,
                    help='Specify WPA type (Default: %s).' % config.rogue_wpa_version)

    wpa_psk_config.add_argument('--wpa-pairwise',
                    dest='wpa_pairwise',
                    type=str,
                    choices=['CCMP','TKIP','CCMP TKIP'],
                    default='CCMP TKIP',
                    help='(Default: \'CCMP TKIP\')')

    wpa_psk_config.add_argument('--rsn-pairwise',
                    dest='rsn_pairwise',
                    type=str,
                    choices=['CCMP','TKIP','CCMP TKIP'],
                    default='CCMP',
                    help='(Default: \'CCMP\')')

    ieee8021x_config.add_argument('--ieee8021x',
                    dest='ieee8021x',
                    action='store_true',
                    default=False,
                    help='Enable 802.1x')

    ieee8021x_config.add_argument('--eapol-version',
                    dest='eapol_version',
                    type=int,
                    choices=[1,2],
                    default=config.rogue_eapol_version,
                    help='IEEE 802.1X/EAPOL version (Default: %s)' % config.rogue_eapol_version)

    ieee8021x_config.add_argument('--eapol-workaround',
                    dest='eapol_workaround',
                    action='store_true',
                    default=False,
                    help='EAPOL-Key index workaround (set bit7) for WinXP Supplicant')

    radius_config.add_argument('--no-log-badpass',
                    dest='log_badpass',
                    action='store_true',
                    default=False,
                    help='When set, incorrect passwords will not be logged')

    radius_config.add_argument('--no-log-goodpass',
                    dest='log_goodpass',
                    action='store_true',
                    default=False,
                    help='When set, valid passwords will not be logged')

    radius_config.add_argument('--own-address',
                    dest='own_ip_addr',
                    type=str,
                    default=config.default_own_ip_addr,
                    help='The own IP address of the access point (Default: %s)' % (config.default_own_ip_addr))

    radius_config.add_argument('--auth-server-addr',
                    dest='auth_server_addr',
                    type=str,
                    default=config.default_auth_server_addr,
                    help='IP address of radius authentication server (Default: %s)' % (config.default_auth_server_addr))

    radius_config.add_argument('--auth-secret',
                    dest='auth_server_shared_secret',
                    type=str,
                    default=config.default_auth_server_shared_secret,
                    help='Radius authentication server shared secret (Default: %s)' % (config.default_auth_server_shared_secret))

    radius_config.add_argument('--auth-server-port',
                    dest='auth_server_port',
                    type=int,
                    default=config.default_auth_server_port,
                    help='Networking port of radius authentication server (Default: %d)' % (config.default_auth_server_port))

    radius_config.add_argument('--acct-server-addr',
                    dest='acct_server_addr',
                    type=str,
                    default=config.default_acct_server_addr,
                    help='IP address of radius accounting server (Default: %s)' % (config.default_acct_server_addr))

    radius_config.add_argument('--acct-secret',
                    dest='acct_server_shared_secret',
                    type=str,
                    default=config.default_acct_server_shared_secret,
                    help='Radius accounting server shared secret')

    radius_config.add_argument('--acct-server-port',
                    dest='acct_server_port',
                    type=int,
                    default=config.default_acct_server_port,
                    help='Networking port of radius accounting server (Default: %d)' % (config.default_acct_server_port))

    radius_config.add_argument('--radius-proto',
                    dest='radius_protocol',
                    type=str,
                    default='*',
                    choices=['udp','tcp','*'],
                    help='(Default: *)')

    radius_config.add_argument('--eap-type',
                    dest='default_eap_type',
                    type=str,
                    default=config.rogue_default_eap_type,
                    choices=['fast','peap','ttls','tls','leap','pwd','md5','gtc'],
                    help='(Default: %s)' % (config.rogue_default_eap_type))

    radius_config.add_argument('--print-creds',
                    dest='print_creds',
                    action='store_true',
                    help='Print intercepted credentials')

    attacks.add_argument('--karma',
                    dest='karma',
                    action='store_true',
                    help='Enable Karma.')

    attacks.add_argument('--sslsplit',
                    dest='sslsplit',
                    action='store_true',
                    help='Enable sslsplit.')

    attacks.add_argument('--responder',
                    dest='responder',
                    action='store_true',
                    help='Enable responder using default configuration.')

    attacks.add_argument('--essid-mask',
                    dest='essid_mask',
                    type=int,
                    choices=[0,1,2],
                    default=config.rogue_essid_mask,
                    help='Send empty SSID in beacons and ignore probe request frames that do not specify full SSID. \
                    1 = send empty (length=0) SSID in beacon and ignore probe request for broadcast SSID \
                    2 = clear SSID (ASCII 0), but keep the original length (this may be required with some clients \
                    that do not support empty SSID) and ignore probe requests for broadcast SSID \
                    (Default: %s)' % config.rogue_essid_mask)

    attacks.add_argument('--hostile-portal',
                    dest='hostile_portal',
                    action='store_true',
                    help='Enable hostile portal.')

    attacks.add_argument('--hostile-mode',
                    dest='hostile_mode',
                    choices=['beef','responder'],
                    type=str,
                    default=None,
                    help='Select attack type performed by hostile portal.')

    attacks.add_argument('--hostile-location',
                    dest='hostile_location',
                    type=str,
                    default=config.httrack_dest,
                    help='Used to specify the location of the cloned site location. \
                    Note: httrack creates a new directory within the destination location with the name of the site cloned. \
                    (Default: %s)' % (config.httrack_dest))

    attacks.add_argument('--target-file',
                    dest='target_file',
                    type=str,
                    default=config.hostile_target_file,
                    help='Used to specify the file in which the hostile portal hook will be inserted into. \
                    (Default: %s)' % (config.hostile_target_file))

    attacks.add_argument('--hostile-marker',
                    dest='hostile_marker',
                    type=str,
                    default=config.hostile_insert_marker,
                    help='Specify the line in the file target file to insert the web hook above. \
                    (Default: %s)' % (config.hostile_insert_marker))

    attacks.add_argument('--hostile-hook',
                    dest='hostile_hook',
                    type=str,
                    help='Specify custom hook code to insert into the target file')

    dhcp.add_argument('--lease',
                    dest='default_lease_time',
                    type=int,
                    default=config.default_default_lease_time,
                    help='Define DHCP lease time (Default: %d)' % (config.default_default_lease_time))

    dhcp.add_argument('--max-lease',
                    dest='max_lease_time',
                    type=int,
                    default=config.default_max_lease_time,
                    help='Define max DHCP lease time (Default: %d)' % (config.default_max_lease_time))

    dhcp.add_argument('--prim-name-server',
                    dest='primary_name_server',
                    type=str,
                    default=config.default_primary_name_server,
                    help='Define primary name server (Default: %s)' % (config.default_primary_name_server))

    dhcp.add_argument('--sec-name-server',
                    dest='secondary_name_server',
                    type=str,
                    default=config.default_secondary_name_server,
                    help='Define secondary name server (Default: %s)' % (config.default_secondary_name_server))

    dhcp.add_argument('--subnet',
                    dest='dhcp_subnet',
                    type=str,
                    default=config.default_dhcp_subnet,
                    help='(Default: %s)' % (config.default_dhcp_subnet))

    dhcp.add_argument('--route-subnet',
                    dest='route_subnet',
                    type=str,
                    default=config.default_route_subnet,
                    help='(Default: %s)' % (config.default_route_subnet))

    dhcp.add_argument('--netmask',
                    dest='dhcp_netmask',
                    type=str,
                    default=config.default_dhcp_netmask,
                    help='(Default: %s)' % (config.default_dhcp_netmask))

    dhcp.add_argument('--ip-address',
                    dest='ip_address',
                    type=str,
                    default=config.default_ip_address,
                    help='(Default: %s)' % (config.default_ip_address))

    dhcp.add_argument('--secondary-interface',
                    dest='secondary_interface',
                    type=str,
                    default=config.secondary_interface,
                    help='Used to specify the second phy interface used to bridge the hostapd-wpe interface (-i) with another network (Default: %s)' % (config.secondary_interface))

    dhcp.add_argument('--pool-start',
                    dest='dhcp_pool_start',
                    type=str,
                    default=config.default_dhcp_pool_start,
                    help='(Default: %s)' % (config.default_dhcp_pool_start))

    dhcp.add_argument('--pool-end',
                    dest='dhcp_pool_end',
                    type=str,
                    default=config.default_dhcp_pool_end,
                    help='(Default: %s)' % (config.default_dhcp_pool_end))

    sslsplit.add_argument('--cert-nopass',
                    dest='cert_nopass',
                    action='store_true',
                    help='Generate a x.509 Certificate with no password for the purpose of sslsplit.')

    sslsplit.add_argument('--encrypted-port',
                    dest='sslsplit_encrypted_port',
                    type=int,
                    default=config.sslsplit_encrypted_port,
                    help='Specify port for encrypted web communication (TCP/443) be redirected to. (Default: %d)' % config.sslsplit_encrypted_port)

    httpd.add_argument('--httpd-port',
                    dest='httpd_port',
                    type=int,
                    default=config.http_port,
                    help='defines the port for httpd service to listen on. (Default: %d)' % (config.http_port))

    httpd.add_argument('--httpd-ssl-port',
                    dest='http_ssl_port',
                    type=int,
                    default=config.http_ssl_port,
                    help='Defines port for SSL-enabled httpd service to listen on. (Default: %d)' % (config.http_ssl_port))

    httpd.add_argument('--ssl',
                    dest='httpd_ssl',
                    action='store_true',
                    help='Enable ssl version of rogue httpd. When enabled, --httpd-ssl-port overwrites --httpd-port. (Default: %d)' % (config.http_ssl_port))

    # Basic error handling of the programs initalisation
    try:
        arg_test = sys.argv[1]
    except IndexError:
        parser.print_help()
        exit(1)

    args, leftovers = parser.parse_known_args()
    options = args.__dict__

    # Set driver value
    if(options['driver'] is not None):
        options['driver'] = ("driver=" + options['driver'])
    else:
        options['driver'] = ("#driver=hostap")

    if(options['ddebug'] is True and options['debug'] is True):
        parser.error('[!] Specify only -d or -dd')

    # comments out the country_code line in hostapd-wpe config file if not specified
    if(options['country_code'] is not None):
        options['country_code'] = ("country_code=" + options['country_code'])
    else:
        options['country_code'] = "#country_code=AU"

    if(options['ieee80211d']):
        if(options['country_code'] is None):
            parser.error('[!] --ieee80211d has been provided without --country-code.')
        else:
            options['ieee80211d'] = 1
    else:
        pass

    if(options['ieee80211h']):
        options['ieee80211h'] = 1
    else:
        pass

    if(options['ieee80211h']):
        if(options['ieee80211d']):
            pass
        else:
            parser.error('[!] --ieee80211h has been provided without --ieee80211d.')
    else:
        pass

    # 802.11 Operation Modes
    if(options['hw_mode'] == 'n'):
        if(options['freq'] == 2):
            options['hw_mode'] = 'g'
            if(options['channel'] > 13):
                parser.error("[!] The provided channel %d can not be used with Radio Band 2.4GHz." % (options['channel']))
            else:
                pass
        else:
            options['hw_mode'] = 'a'
            if(options['channel'] == 0):
                pass
            elif(options['channel'] < 13):
                parser.error("[!] The provided channel %d can not be used with Radio Band 5.0GHz." % (options['channel']))
            else:
                pass
        options['ieee80211n'] = 1
        options['ieee80211ac'] = 0
        options['wmm_enabled'] = 1
    elif(options['hw_mode'] == 'a'):
        options['hw_mode'] = 'a'
        options['ieee80211n'] = 0
        options['ieee80211ac'] = 0
    elif options['hw_mode'] == 'ac':
        options['hw_mode'] = 'a'
        if(options['channel'] == 0):
            pass
        elif(options['channel'] < 13):
            parser.error("[!] The provided channel %d can not be used with Radio Band 5.0GHz." % (options['channel']))
        else:
            pass
        options['ieee80211n'] = 1
        options['ieee80211ac'] = 1
    else:
        options['ieee80211n'] = 0
        options['ieee80211ac'] = 0

    # Configures HT Capabilities
    if(options['require_ht']):
        options['require_ht'] = 1
    else:
        options['require_ht'] = 0

    if(options['ht_mode'] == 0):
        options['ht_capab'] = '#ht_capab='
    else:
        options['ht_capab'] = 'ht_capab='
        if(options['ht_mode'] == 1):
            options['ht_capab'] += '[HT40-]'
        else:
            options['ht_capab'] += '[HT40+]'
    if(options['short20']):
        options['ht_capab'] += '[SHORT-GI-20]'
    else:
        pass
    if(options['short40']):
        options['ht_capab'] += '[SHORT-GI-40]'
    else:
        pass

    # Configures VHT Capabilities
    if(options['require_vht']):
        options['require_vht'] = 1
    else:
        options['require_vht'] = 0

    if(options['vht_oper'] == 1):
        options['vht_oper'] = "vht_oper_centr_freq_seg1_idx"
    else:
        options['vht_oper'] = "vht_oper_centr_freq_seg0_idx"
    options['vht_operations'] = ("%s=%s" % (options['vht_oper'], options['vht_index']))

    # comments out the Wireless Multimedia Extensions (WMM) in hostapd-wpe config file if not specified
    if(options['wmm_enabled']):
        options['wmm_enabled'] = "wmm_enabled=1"
    else:
        options['wmm_enabled'] = "#wmm_enabled=1"

    if(options['auth'] == 'wep'):
        if (options['wep_default_key'] is None) or (options['wep_key'] is None):
            paser.error("[!] Please configure wep related configuration options: ['%s','%s']" % ("wep-key-version", "wep-key"))
        else:
            # Set wep-key object
            if (options['wep_default_key'] == 1) or (options['wep_default_key'] == 3):
                options['wep_key'] = ("wep_key" + str(options['wep_default_key']) + "=" + "\"" + options['wep_key'] + "\"")
            else:
                options['wep_key'] = ("wep_key" + str(options['wep_default_key']) + "=" + options['wep_key'])
    else:
        pass

    if(options['auth'] == 'wpa'):
        if (options['wpa_passphrase'] is None):
            parser.error("[!] Please configure provide the following wpa-personal configuration options: ['%s']" % ("wpa-passphrase"))

    # 802.11 Configuration
    if(options['ap_isolate']):
        options['ap_isolate'] = 1
    else:
        options['ap_isolate'] = 0

    # 802.1x Configuration
    if(options['ieee8021x']):
        options['ieee8021x'] = 1
    else:
        options['ieee8021x'] = 0

    if(options['eapol_workaround']):
        options['eapol_workaround'] = 1
    else:
        options['eapol_workaround'] = 0

    # Radius Configuration
    if(options['log_goodpass']):
        options['log_goodpass'] = 'no'
    else:
        options['log_goodpass'] = 'yes'

    if(options['log_badpass']):
        options['log_badpass'] = 'no'
    else:
        options['log_badpass'] = 'yes'

    if(options['clone_wizard']):
        if options['clone_target'] is None:
            parser.error("[!] Please set a target site to clone")

    if(options['hostile_portal']):
        if(options['hostile_mode'] is None):
            parser.error("[!] Please select a hostile portal operation mode using --hostile-mode")
        else:
            pass

    if(options['hostile_mode'] is not None):
        if(options['hostile_portal'] is not True):
            parser.error("[!] A --hostile-mode has been specified without enabling --hostile-portal.")

    if(options['hostile_hook'] is None):
        if(options['hostile_mode'] == 'beef'):
            options['hostile_hook'] = config.beef_hook
        elif(options['hostile_mode'] == 'responder'):
            options['hostile_hook'] = config.responder_hook
            options['responder'] = True
        else:
            pass
    else:
        pass

    if(options['hostile_location'] is not None):
        options['httpd_root'] = options['hostile_location']
    else:
        pass

    if(options['httpd_ssl']):
        options['httpd_port'] = options['http_ssl_port']

    if(options['hostile_portal']):
        options['enable_httpd'] = True
    else:
        options['enable_httpd'] = False

    return options
