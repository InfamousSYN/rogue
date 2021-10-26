#!/usr/bin/python3
from argparse import *
import sys
import config
import re

class optionsClass():

    def __init__(self, options, parser):
        self.options = options
        self.parser = parser
        for key, value in options.items():
            setattr(self, key, value)
        del self.options

    def __reassemble__(self):
        del self.parser
        return self.__dict__

    def check_debug(self):
        '''
        checks to make sure that only one of the hostapd-wpe debugging options is set
        '''
        if(self.ddebug is True and self.debug is True):
            parser.error('[!] Specify only -d or -dd')

    def check_driver(self):
        if(self.driver is not None):
            self.set_driver(1)
        else:
            self.set_driver(0)

    def set_driver(self, value):
        if(value > 0):
            self.driver = ("driver=%s" % (self.driver))
        else:
            self.driver = "#driver=hostap"

    def check_country(self):
        if(self.country_code is not None):
            self.set_country(1)
        else:
            self.set_country(0)

    def set_country(self, value):
        if(value > 0):
            self.country_code = ("country_code=%s" % (self.country_code))
        else:
            self.country_code = "#country_code=00"

    def check_80211d(self):
        if((self.ieee80211d) and (self.country_code is None)):
            self.parser.error('[!] --ieee80211d has been provided without --country-code.')
        elif((self.ieee80211d) and (self.country_code is not None)):
            self.set_80211d(1)
        else:
            self.set_80211d(0)

    def set_80211d(self, value):
        if(value > 0):
            self.ieee80211d = 1
        else:
            self.ieee80211d = 0

    def check_80211h(self):
        if((self.ieee80211d is False) and (self.ieee80211h is True)):
            self.parser.error('[!] --ieee80211h has been provided without --ieee80211d.')
        elif((self.ieee80211d is True) and (self.ieee80211h is True)):
            self.set_80211h(1)
        else:
            self.set_80211h(0)

    def set_80211h(self, value):
        if(value > 0):
            self.ieee80211h = 1
        else:
            self.ieee80211h = 0

    def check_hw_mode(self):
        if(self.hw_mode == 'n'):
            self.minimum_N_hwmode()
        elif(self.hw_mode == 'ac'):
            self.minimum_AC_hwmode()
        elif(self.hw_mode == 'a'):
            self.minimum_A_hwmode()
        else:
            self.default_hwmode()

    def check_channel(self):
        if((self.freq == 2) and (self.channel != 0)):
            if(self.channel > 13):
                self.parser.error("[!] The provided channel %d can not be used with Radio Band 2.4GHz." % (self.channel))
        if((self.hw_mode == 'a' or self.freq == 5) and (self.channel != 0)):
            if(self.channel < 13):
                self.parser.error("[!] The provided channel %d can not be used with Radio Band 5.0GHz." % (self.channel))

    def check_require_ht(self):
        if(self.require_ht):
            self.set_require_ht(1)
            # toggles ht_mode to an active state when the config file default value is unaltered
            if(self.ht_mode == 0):
                self.set_ht_mode(2)
        else:
            self.set_require_ht(0)

        if(self.ht_mode > 0):
            self.set_ht_capab(1)
        else:
            self.set_ht_capab(0)
    def set_ht_mode(self, value):
        self.ht_mode = value

    def set_require_ht(self, value):
        self.require_ht = value

    def set_ht_capab(self, value):
        if(value > 0):
            self.ht_capab = 'ht_capab='
            if(self.ht_mode == 1):
                self.ht_capab += '[HT40+]'
            elif(self.ht_mode == 2):
                self.ht_capab += '[HT40+]'
            else:
                pass
            if(self.short20):
                self.ht_capab += '[SHORT-GI-20]'
            if(self.short40):
                self.ht_capab += '[SHORT-GI-40]'
        else:
            self.ht_capab = '#ht_capab='

    def check_require_vht(self):
        if(self.require_vht):
            self.set_require_vht(1)
        else:
            self.set_require_vht(0)

    def set_require_vht(self, value):
        self.require_vht = value

    def check_vht_operations(self):
        if(self.vht_oper == 1):
            self.set_vht_operations(1)
        else:
            self.set_vht_operations(0)

    def set_vht_operations(self, value):
        self.vht_oper = ("vht_oper_centr_freq_seg%s_idx" % (value))
        setattr(self, "vht_operations", ("%s=%s" % (self.vht_oper, self.vht_index)))

    def check_wmm_enabled(self):
        if(self.wmm_enabled):
            self.set_wmm_enabled(1)
        else:
            self.set_wmm_enabled(0)

    def set_wmm_enabled(self, value):
        if(value > 0):
            self.wmm_enabled = 'wmm_enabled=1'
        else:
            self.wmm_enabled = '#wmm_enabled=1'

    def check_ap_isolate(self):
        if(self.ap_isolate):
            self.set_ap_isolate(1)
        else:
            self.set_ap_isolate(0)

    def set_ap_isolate(self, value):
        if(value > 0):
            self.ap_isolate = 1
        else:
            self.ap_isolate = 0

    def check_auth(self):
        if(self.auth == 'wep'):
            self.check_wep()
        elif(self.auth == 'wpa'):
            self.check_wpa_passphrase()
        else:
            pass

    def check_wep(self):
        if((self.wep_default_key is None) or (self.wep_key is None)):
            self.parser.error("[!] Please configure wep related configuration options: ['%s','%s']" % ("wep-key-version", "wep-key"))
        elif((self.wep_default_key == 1) or (self.wep_default_key == 3)):
            if(self.check_wep_key_size(self.wep_default_key, self.wep_key)):
                self.set_wep_key(self.wep_default_key, 0, self.wep_key)
            else:
                self.parser.error("[!] The wep key size is %s, please choose a 40-bit, 104-bit or 128-bit key instead")
        elif((self.wep_default_key == 0) or (self.wep_default_key == 2)):
            if(self.check_wep_key_size(self.wep_default_key, self.wep_key)):
                self.set_wep_key(self.wep_default_key, 1, self.wep_key)
            else:
                self.parser.error("[!] The wep key size is %s, please choose a 40-bit, 104-bit or 128-bit key instead")
        else:
            pass

    def check_wep_key_size(self, method, key):
        try:
            for k in [40, 104, 128]:
                if((method == 0) or (method == 2)):
                    if(len(re.findall('..', key))*8 == k):
                        return True
                    raise
                elif((method == 1) or (method == 3)):
                    if(len(key)*8 == k):
                        return True
            raise
        except Exception as e:
            return False

    def set_wep_key(self, value, method, key):
        if(method > 0):
            self.wep_key = ('wep_key%s=%s' % (value, key))
        else:
            self.wep_key = ('wep_key%s="%s"' % (value, key))

    def check_wpa_passphrase(self):
        if((self.auth == 'wpa') and (self.wpa_passphrase is None)):
            self.parser.error("[!] Please configure provide the following wpa-personal configuration options: ['%s']" % ("--wpa-passphrase"))

    #
    ## IEEE 802.1x Configuration
    #

    def check_8021x(self):
        if(self.ieee8021x):
            self.set_8021x(1)
        else:
            self.set_8021x(0)

    def set_8021x(self, value):
        self.ieee8021x = value

    def check_eapol_workaround(self):
        if(self.eapol_workaround):
            self.set_eapol_workaround(1)
        else:
            self.set_eapol_workaround(0)

    def set_eapol_workaround(self, value):
        self.eapol_workaround = value

    #
    ## RADIUS Configuration
    #

    def check_log_goodpass(self):
        if(self.log_goodpass):
            self.set_log_goodpass('no')
        else:
            self.set_log_goodpass('yes')

    def set_log_goodpass(self, value):
        self.log_goodpass = value

    def check_log_badpass(self):
        if(self.log_badpass):
            self.set_log_badpass('no')
        else:
            self.set_log_badpass('yes')

    def set_log_badpass(self, value):
        self.log_badpass = value

    def check_default_supported_eap_types(self, supported_eap_types):
        if((self.default_eap_type == 'fast') and (self.supported_eap_type != 'fast')):
            self.parser.error("[!] The default EAP type of fast is only allowed when the supported eap type is also fast")

        if((self.supported_eap_type == 'all')):
            if(self.default_eap_type in supported_eap_types):
                pass
            else:
                self.parser.error("[!] The specified default EAP type was not found in list of supported EAP types")
        else:
            if(self.default_eap_type == self.supported_eap_type):
                pass
            else:
                self.parser.error("[!] When in single supported EAP type mode, the default EAP type must match the supported EAP type")


    #
    ## Attack Configuration
    #

    def check_clone_wizard(self):
        if((self.clone_wizard is True) and (self.clone_target is None)):
            parser.error("[!] Please set a target site to clone")

    def check_hostile_mode(self):
        if(self.hostile_mode == 'beef'):
            self.set_hostile_hook(config.beef_hook)
        elif(self.hostile_mode == 'responder'):
            self.set_hostile_hook(config.responder_hook)
            self.responder = True
        elif(self.hostile_mode == 'http'):
            self.set_enable_httpd(True)
        else:
            self.set_enable_httpd(False)

    def set_hostile_hook(self, value):
        self.hostile_hook = value

    def check_hostile_portal(self):
        if((self.hostile_portal is True) and (self.hostile_mode is None)):
            self.parser.error("[!] Please select a hostile portal operation mode using --hostile-mode")
        elif((self.hostile_portal is not True) and (self.hostile_mode is not None)):
            parser.error("[!] A --hostile-mode has been specified without enabling --hostile-portal.")
        elif((self.hostile_portal is True) and (self.hostile_mode == 'http')):
            self.set_enable_httpd(True)
        else:
            pass

    def set_enable_httpd(self, value):
        setattr(self, 'enable_httpd', value)
        if(self.enable_httpd):
            self.check_httpd_ssl()

    def check_httpd_ssl(self):
        if(self.httpd_ssl):
            self.set_httpd_port(self.http_ssl_port)

    def set_httpd_port(self, value):
        self.httpd_port = value

    def check_hostile_location(self):
        if(self.hostile_location is not None):
            self.set_httpd_root(self.hostile_location)

    def set_httpd_root(self, value):
        self.httpd_root = value


    # minimum settings
    def minimum_N_hwmode(self):
        if(self.freq == 5):
            self.hw_mode = 'a'
        else:
            self.hw_mode = 'g'
        self.ieee80211n = 1
        self.ieee80211ac = 0
        self.wmm_enabled = 1

    def minimum_AC_hwmode(self):
        self.hw_mode = 'a'
        self.freq = 5
        self.ieee80211n = 1
        self.ieee80211ac = 1
        self.wmm_enabled = 1

    def minimum_A_hwmode(self):
        self.hw_mode = 'a'
        self.freq = 5
        self.ieee80211n = 0
        self.ieee80211ac = 0
        self.wmm_enabled = 0

    def default_hwmode(self):
        self.ieee80211n = 0
        self.ieee80211ac = 0
        self.wmm_enabled = 0


def set_options():
    parser = ArgumentParser(prog=sys.argv[0],
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

    parser.add_argument('-m', '--manual',
                    dest='hostapd_manual_conf',
                    type=str,
                    default=None,
                    help='Loads a custom hostapd config file instead of dynamically generating a file')

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

    radius_config.add_argument('--default-eap',
                    dest='default_eap_type',
                    type=str,
                    default=config.rogue_default_eap_type,
                    choices=config.rogue_default_eap_types,
                    help='Specify the default EAP method used in RADIUS authentication. (Default: %s)' % (config.rogue_default_eap_type))

    radius_config.add_argument('-E','--supported-eap',
                    dest='supported_eap_type',
                    type=str,
                    default=config.rogue_supported_eap_type,
                    choices=config.rogue_supported_eap_types,
                    help='Specify the default EAP method used in RADIUS authentication. (Default: %s)' % (config.rogue_supported_eap_type))    

    radius_config.add_argument('--print-creds',
                    dest='print_creds',
                    action='store_true',
                    help='Print intercepted credentials')

    radius_config.add_argument('--ca-certificate',
                    dest='ca_certificate',
                    type=str,
                    default=config.trusted_root_ca_pem,
                    help='specify trusted root CA certificate in PEM format. (Default: {})'.format(config.trusted_root_ca_pem))

    radius_config.add_argument('--server-certificate',
                    dest='server_certificate',
                    type=str,
                    default=config.server_pem,
                    help='specify RADIUS server certificate in PEM format. (Default: {})'.format(config.server_pem))

    radius_config.add_argument('--server-private-key',
                    dest='server_private_key',
                    type=str,
                    default=config.private_key,
                    help='specify RADIUS private key. (Default: {})'.format(config.private_key))

    radius_config.add_argument('--server-private-password',
                    dest='server_private_key_password',
                    type=str,
                    default=config.private_key_passwd,
                    help='provide the password RADIUS private key. (Default: {})'.format(config.private_key_passwd))

    radius_config.add_argument('--private-certificate',
                    dest='server_private_certificate',
                    type=str,
                    default=config.private_pem,
                    help='specify RADIUS private certificate')

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

    o = optionsClass(options, parser)


    o.check_debug()
    o.check_driver()
    o.check_country()
    o.check_80211d()
    o.check_80211h()
    o.check_hw_mode()
    o.check_channel()
    o.check_require_ht()
    o.check_require_vht()
    o.check_vht_operations()
    o.check_wmm_enabled()
    o.check_ap_isolate()
    o.check_auth()

    # 802.1x Configuration
    o.check_8021x()
    o.check_eapol_workaround()

    # RADIUS Configuration
    o.check_log_goodpass()
    o.check_log_badpass()
    o.check_default_supported_eap_types(config.rogue_supported_eap_types)

    # Attack Configurations
    o.check_clone_wizard()
    o.check_hostile_portal()
    o.check_hostile_mode()
    o.check_hostile_location()

    options = o.__reassemble__()

    return options