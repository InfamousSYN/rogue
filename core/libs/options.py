#!/usr/bin/python3
from argparse import *
import sys
import config
import re

class optionsClass():

    @classmethod
    def __init__(self, options, parser):
        self.options = options
        self.parser = parser
        for key, value in options.items():
            setattr(self, key, value)
        del self.options

    @classmethod
    def __reassemble__(self):
        del self.parser
        return self.__dict__

    @classmethod
    def check_debug(self):
        '''
        checks to make sure that only one of the hostapd-wpe debugging options is set
        '''
        if(self.ddebug is True and self.debug is True):
            parser.error('[!] Specify only -d or -dd')

    @classmethod
    def validate_beacon_interval(self):
        if((self.beacon_interval < 15) or self.beacon_interval > 65535):
            self.parser.error('[!] --beacon-interval has to be within 15 - 65535.')

    @classmethod
    def set_driver(self):
        self.driver = "driver={}".format(self.driver) if self.driver is not None else "#driver=hostap"

    @classmethod
    def set_country(self):
        self.country_code = "country_code={}".format(self.country_code) if self.country_code is not None else "#country_code=00"

    @classmethod
    def check_80211d(self):
        if((self.ieee80211d) and (self.country_code is None)):
            self.parser.error('[!] --ieee80211d has been provided without --country-code.')
        elif((self.ieee80211d) and (self.country_code is not None)):
            self.ieee80211d = 1
        else:
            self.ieee80211d = 0

    @classmethod
    def check_80211h(self):
        if((self.ieee80211d is False) and (self.ieee80211h is True)):
            self.parser.error('[!] --ieee80211h has been provided without --ieee80211d.')
        elif((self.ieee80211d is True) and (self.ieee80211h is True)):
            self.ieee80211h = 1
        else:
            self.ieee80211h = 0

    @classmethod
    def check_channel(self):
        if((self.freq == 2) and (self.channel != 0)):
            if(self.channel > 13):
                self.parser.error("[!] The provided channel {} can not be used with Radio Band 2.4GHz.".format(self.channel))
        if((self.hw_mode == 'a' or self.freq == 5) and (self.channel != 0)):
            if(self.channel < 13):
                self.parser.error("[!] The provided channel {} can not be used with Radio Band 5.0GHz.".format(self.channel))
        if(self.channel == 0 and self.channel_randomiser):
            import random
            print('[-] Randomised channel selection is superseding ACS')
            if((self.hw_mode == 'a' or self.freq == 5)):
                self.channel = random.choice([40,48,56,64,36,44,52,60])
            else:
                self.channel = random.randrange(1,11)
            print('[-]   Channel {} was selected'.format(self.channel))

    @classmethod
    def set_require_ht(self):
        self.require_ht = 1 if self.require_ht is True else 0

    @classmethod
    def set_ht_capability(self):
        if(self.require_ht == 1):
            if(self.ht_smps_dynamic and self.ht_smps_static):
                self.parser.error("[!] Select one Spatial Multiplexing capability --enable-smps-dynamic or --enable-smps-static")
            if(self.ht_rx_stbc1 and self.ht_rx_stbc12 and self.ht_rx_stbc123):
                self.parser.error("[!] Select one Rx STBC capability --enable-rx-stbc1, --enable-rx-stbc12 or --enable-rx-stbc123")
            self.ht_capab = "ht_capab="
            self.ht_capab = self.ht_capab+"{}".format("[HT40-]" if not self.ht40_neg else "")
            self.ht_capab = self.ht_capab+"{}".format("[HT40+]" if not self.ht40_pos else "")
            self.ht_capab = self.ht_capab+"{}".format("[SHORT-GI-20]" if not self.short20 else "")
            self.ht_capab = self.ht_capab+"{}".format("[SHORT-GI-40]" if not self.short40 else "")
            self.ht_capab = self.ht_capab+"{}".format("[GF]" if self.ht_greenfield else "")
            self.ht_capab = self.ht_capab+"{}".format("[LDPC]" if self.ht_ldpc else "")
            self.ht_capab = self.ht_capab+"{}".format("[SMPS-STATIC]" if self.ht_smps_static else "")
            self.ht_capab = self.ht_capab+"{}".format("[SMPS-DYNAMIC]" if self.ht_smps_dynamic else "")
            self.ht_capab = self.ht_capab+"{}".format("[TX-STBC]" if self.ht_tx_stbc else "")
            self.ht_capab = self.ht_capab+"{}".format("[RX-STBC1]" if self.ht_rx_stbc1 else "")
            self.ht_capab = self.ht_capab+"{}".format("[RX-STBC12]" if self.ht_rx_stbc12 else "")
            self.ht_capab = self.ht_capab+"{}".format("[RX-STBC123]" if self.ht_rx_stbc123 else "")
            self.ht_capab = self.ht_capab+"{}".format("[DELAYED-BA]" if self.ht_delayed_ba else "")
            self.ht_capab = self.ht_capab+"{}".format("[MAX-AMSDU-7935]" if self.ht_msdu7935 else "")
            self.ht_capab = self.ht_capab+"{}".format("[DSSS_CCK-40]" if self.ht_dsss_cck else "")
            self.ht_capab = self.ht_capab+"{}".format("[40-INTOLERANT]" if self.ht_40_intolerant else "")
            self.ht_capab = self.ht_capab+"{}".format("[LSIG-TXOP-PROT]" if self.ht_txop_protection else "")
        else:
            self.ht_capab = "#ht_capab="

    @classmethod
    def set_require_vht(self):
        self.require_vht = 1 if self.require_vht is True else 0

    @classmethod
    def set_vht_operations(self):
        if(self.require_vht):
            if(self.vht_operations == 0 and self.vht_index == 159):
                self.parser.error("[!] Invalid VHT operational mode and index combination!\r\n\t(For --vht-operation 0 use --vht-index 42)")
            if(self.vht_operations == 1 and self.vht_index == 42):
                self.parser.error("[!] Invalid VHT operational mode and index combination!\r\n\t(For --vht-operation 1 use --vht-index 159)")
            self.vht_operations = "vht_oper_centr_freq_seg{}_idx={}".format(self.vht_operations, self.vht_index)
        else:
            self.vht_operations = "#vht_oper_centr_freq_seg0_idx=42"

    @classmethod
    def set_vht_capability(self):
        if(self.require_vht):
            if(self.vht_mpdu7991 and self.vht_mpdu11454):
                self.parser.error("[!] Select one VHT MPDU length option --enable-mpdu7991 or --enable-mpdu11454")
            if(self.vht_rx_stbc1 and self.vht_rx_stbc12 and self.vht_rx_stbc123 and self.vht_rx_stbc1234):
                self.parser.error("[!] Select one Rx STBC capability --enable-vht-rx-stbc1, --enable-vht-rx-stbc12, --enable-vht-rx-stbc123 or --enable-vht-rx-stbc1234")
            self.vht_capab = "vht_capab="
            self.vht_capab = self.vht_capab+"{}".format("[SHORT-GI-80]" if not self.vht_short80 else "")
            self.vht_capab = self.vht_capab+"{}".format("[SHORT-GI-160]" if not self.vht_short160 else "")
            self.vht_capab = self.vht_capab+"{}".format("[HTC-VHT]" if not self.vht_htc_vht else "")
            self.vht_capab = self.vht_capab+"{}".format("[MAX-MPDU-7991]" if self.vht_mpdu7991 else "")
            self.vht_capab = self.vht_capab+"{}".format("[MAX-MPDU-11454]" if self.vht_mpdu11454 else "")
            self.vht_capab = self.vht_capab+"{}".format("[RXLDPC]" if self.vht_rx_lpdc else "")
            self.vht_capab = self.vht_capab+"{}".format("[TX-STBC-2BY1]" if self.vht_tx_stbc else "")
            self.vht_capab = self.vht_capab+"{}".format("[RX-STBC1]" if self.vht_rx_stbc1 else "")
            self.vht_capab = self.vht_capab+"{}".format("[RX-STBC12]" if self.vht_rx_stbc12 else "")
            self.vht_capab = self.vht_capab+"{}".format("[RX-STBC123]" if self.vht_rx_stbc123 else "")
            self.vht_capab = self.vht_capab+"{}".format("[RX-STBC1234]" if self.vht_rx_stbc1234 else "")
            self.vht_capab = self.vht_capab+"{}".format("[SU-BEAMFORMER]" if self.vht_beamformer else "")
            self.vht_capab = self.vht_capab+"{}".format("[SU-BEAMFORMEE]" if self.vht_beamformee else "")
            self.vht_capab = self.vht_capab+"{}".format("[SOUNDING-DIMENSION-2]" if self.vht_sd2 else "")
            self.vht_capab = self.vht_capab+"{}".format("[SOUNDING-DIMENSION-3]" if self.vht_sd3 else "")
            self.vht_capab = self.vht_capab+"{}".format("[SOUNDING-DIMENSION-4]" if self.vht_sd4 else "")
            self.vht_capab = self.vht_capab+"{}".format("[MU-BEAMFORMER]" if self.vht_mu_beamformer else "")
            self.vht_capab = self.vht_capab+"{}".format("[VHT-TXOP-PS]" if self.vht_txop_ps else "")
            self.vht_capab = self.vht_capab+"{}".format("[TX-ANTENNA-PATTERN]" if self.vht_tx_pattern else "")
            self.vht_capab = self.vht_capab+"{}".format("[RX-ANTENNA-PATTERN]" if self.vht_rx_pattern else "")
        else:
            self.vht_capab = "#vht_capab="

    @classmethod
    def set_wmm_enabled(self):
        self.wmm_enabled = "wmm_enabled=1" if self.wmm_enabled is True else "#wmm_enabled=1"

    @classmethod
    def set_ap_isolate(self):
        self.ap_isolate = 1 if self.ap_isolate is True else 0

    @classmethod
    def check_hardware_mode(self):
        self.ieee80211n = 1 if self.hw_mode == 'n' else 0
        self.ieee80211n = 1 if self.hw_mode == 'ac' else 0
        self.ieee80211ac = 1 if self.hw_mode == 'ac' else 0
        self.hw_mode = 'a' if self.ieee80211n and self.freq == 5 else 'g'
        self.hw_mode = 'a' if self.ieee80211ac else 'g'

    @classmethod
    def check_auth(self):
        if(self.auth == 'wep'):
            self.check_wep()
        elif(self.auth == 'wpa-personal'):
            self.check_wpa_passphrase()
        elif(self.auth == 'wpa-enterprise'):
            self.auth_algs=1
            self.eap_user_file = 'eap_user_file={}'.format(config.eap_user_file) if not self.disable_eap_user_file else '#eap_user_file=/etc/hostapd.eap_user'
        elif(self.auth == 'wpa3-sae'):
            self.ieee80211w = 2
            #self.rsn_pairwise = 'GCMP-256'
            #self.wpa_pairwise = 'GCMP-256'
        elif(self.auth == 'wpa3-eap'):
            self.auth_algs=1
            self.ieee80211w = 2
            self.eap_user_file = 'eap_user_file={}'.format(config.eap_user_file) if not self.disable_eap_user_file else '#eap_user_file=/etc/hostapd.eap_user'
            #self.rsn_pairwise = 'GCMP-256'
            #self.wpa_pairwise = 'GCMP-256'
        else:
            pass

    @classmethod
    def check_wep(self):
        if((self.wep_default_key is None) or (self.wep_key is None)):
            self.parser.error("[!] Please configure wep related configuration options: ['{}','{}']".format("wep-key-version", "wep-key"))
        elif((self.wep_default_key == 1) or (self.wep_default_key == 3)):
            if(self.check_wep_key_size(self.wep_default_key, self.wep_key)):
                self.set_wep_key(self.wep_default_key, 0, self.wep_key)
            else:
                self.parser.error("[!] The wep key size is {}, please choose a 40-bit, 104-bit or 128-bit key instead".format(len(self.wep_default_key)))
        elif((self.wep_default_key == 0) or (self.wep_default_key == 2)):
            if(self.check_wep_key_size(self.wep_default_key, self.wep_key)):
                self.set_wep_key(self.wep_default_key, 1, self.wep_key)
            else:
                self.parser.error("[!] The wep key size is {}, please choose a 40-bit, 104-bit or 128-bit key instead".format(len(self.wep_default_key)))
        else:
            pass

    @classmethod
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

    @classmethod
    def set_wep_key(self, value, method, key):
        if(method > 0):
            self.wep_key = ('wep_key{}={}'.format(value, key))
        else:
            self.wep_key = ('wep_key{}="{}"'.format(value, key))

    @classmethod
    def check_wpa_passphrase(self):
        if((self.auth == 'wpa') and (self.wpa_passphrase is None)):
            self.parser.error("[!] Please configure provide the following wpa-personal configuration options: ['{}']".format("--wpa-passphrase"))

    #
    ## IEEE 802.1x Configuration
    #

    @classmethod
    def set_8021x(self):
        self.ieee8021x = 1 if ((self.ieee8021x is True) or (self.auth == 'wpa-enterprise')) else 0

    @classmethod
    def set_eapol_workaround(self):
        self.eapol_workaround = 1 if self.eapol_workaround is True else 0

    #
    ## RADIUS Configuration
    #

    @classmethod
    def set_log_goodpass(self):
        self.log_goodpass = 'no' if self.log_goodpass is True else 'yes'

    @classmethod
    def set_log_badpass(self):
        self.log_badpass = 'no' if self.log_badpass is True else 'yes'

    @classmethod
    def check_default_supported_eap_types(self):
        if(('all' not in self.supported_eap_type) and (self.default_eap_type not in self.supported_eap_type)):
            print('[!] Default EAP method specified was not in supported EAP method list. Adding...')
            self.supported_eap_type.append(self.default_eap_type)

    #
    ## Attack Configuration
    #

class RawFormatter(HelpFormatter):
    def _fill_text(self, text, width, indent):
        import textwrap
        return "\n".join([textwrap.fill(line, width) for line in textwrap.indent(textwrap.dedent(text), indent).splitlines()])

def set_options():
    parser = ArgumentParser(prog=sys.argv[0],
                            description="""
    The Rogue Toolkit is an extensible toolkit aimed at providing penetration testers an easy-to-use platform to deploy software-defined Access Points (AP) for the purpose of conducting penetration testing and red team engagements. By using Rogue, penetration testers can easily perform targeted evil twin attacks against a variety of wireless network types. 
                            
    For more information: {}""".format(config.__location__),
                            usage="sudo python3 /opt/rogue/rogue.py -i wlan0 --auth wpa-enterprise --internet --essid rogue --preset-profile wifi4 --channel-randomiser --default-eap peap",
                            add_help=True,
                            formatter_class=RawFormatter,
                            )

    hostapd_config = parser.add_argument_group(
                    title='hostapd configuration')
    ieee80211_config = parser.add_argument_group(
                    title='IEEE 802.11 related configuration')
    ieee80211n_config = parser.add_argument_group(
                    title='IEEE 802.11n related configuration')
    ieee80211ac_config = parser.add_argument_group(
                    title='IEEE 802.11ac related configuration')
    wep_config = parser.add_argument_group(
                    title='WEP authentication configuration')
    wpa_psk_config = parser.add_argument_group(
                    title='IWPA/IEEE 802.11i configuration')
    ieee8021x_config = parser.add_argument_group(
                    title='IEEE 802.1X-2004 configuration')
    radius_config = parser.add_argument_group(
                    title='RADIUS client configuration')
    dhcp = parser.add_argument_group(
                    title='External DHCP configuration')
    attacks = parser.add_argument_group(
                    title='Attack Arguments')
    sslsplit = parser.add_argument_group(
                    title='sslsplit configuration')
    modlishka = parser.add_argument_group(
                    title='modlishka configuration')

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
                    choices=['open','wep','wpa-personal','wpa-enterprise','wpa3-sae','wpa3-eap'],
                    default=config.rogue_auth,
                    help='Specify auth type. (Default: {})'.format(config.rogue_auth))

    parser.add_argument('--cert-wizard',
                    dest='cert_wizard',
                    action='store_true',
                    help=('Use this flag to create a new RADIUS cert for your AP'))

    parser.add_argument('--show-options',
                    dest='show_options',
                    action='store_true',
                    help='Display configured options.')

    parser.add_argument('-i', '--interface',
                    dest='interface',
                    type=str,
                    help='The phy interface on which to create the AP')

    hostapd_config.add_argument('--driver',
                    dest='driver',
                    type=str,
                    default=None,
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
                    help='Specify access point BSSID (Default: {})'.format(config.rogue_bssid))

    ieee80211_config.add_argument('-e', '--essid',
                    dest='essid',
                    type=str,
                    default=config.rogue_essid,
                    help='Specify access point ESSID (Default: {})'.format(config.rogue_essid))

    ieee80211_config.add_argument('-p', '--preset-profile',
                    dest='80211_preset_profile',
                    type=str,
                    choices=['wifi1','wifi2','wifi3','wifi4','wifi5','wifi6'],
                    default=None,
                    help='Use a preset 802.11 profile')

    ieee80211_config.add_argument('-hm', '--hw-mode',
                    dest='hw_mode',
                    type=str,
                    choices=['a','b','g','n','ac','ax'],
                    default=config.rogue_hw_mode,
                    help='Specify access point hardware mode (Default: {}).'.format(config.rogue_hw_mode))

    ieee80211_config.add_argument('--freq',
                    dest='freq',
                    type=int,
                    choices=[2,5],
                    default=config.rogue_default_frequency,
                    help='Specify the radio band to use (Default: {}GHz).'.format(config.rogue_default_frequency))

    ieee80211_config.add_argument('--beacon-interval',
                    dest='beacon_interval',
                    type=int,
                    default=100,
                    help='Control the beacon interval (Default: 100)')

    ieee80211n_config.add_argument('--disable-ht40-',
                    dest='ht40_neg',
                    action='store_true',
                    default=False,
                    help='Disables [HT40-] HT capabilities.')

    ieee80211n_config.add_argument('--disable-ht40+',
                    dest='ht40_pos',
                    action='store_true',
                    default=False,
                    help='Disables [HT40+] HT capabilities.')

    ieee80211n_config.add_argument('--disable-short20',
                    dest='short20',
                    action='store_true',
                    default=False,
                    help='Disables Short GI for 20 MHz for HT capabilities.')

    ieee80211n_config.add_argument('--disable-short40',
                    dest='short40',
                    action='store_true',
                    default=False,
                    help='Disables Short GI for 40 MHz for HT capabilities.')

    ieee80211n_config.add_argument('--enable-ht-greenfield',
                    dest='ht_greenfield',
                    action='store_true',
                    default=False,
                    help='Enables HT-greenfield: [GF] for HT capabilities.')

    ieee80211n_config.add_argument('--enable-ldpc',
                    dest='ht_ldpc',
                    action='store_true',
                    default=False,
                    help='Enables LDPC coding capability: [LDPC] for HT capabilities.')

    ieee80211n_config.add_argument('--enable-smps-dynamic',
                    dest='ht_smps_dynamic',
                    action='store_true',
                    default=False,
                    help='Enables Spatial Multiplexing (SM) Power Save: [SMPS-DYNAMIC] for HT capabilities.')

    ieee80211n_config.add_argument('--enable-smps-static',
                    dest='ht_smps_static',
                    action='store_true',
                    default=False,
                    help='Enables Spatial Multiplexing (SM) Power Save: [SMPS-STATIC] for HT capabilities.')

    ieee80211n_config.add_argument('--enable-tx-stbc',
                    dest='ht_tx_stbc',
                    action='store_true',
                    default=False,
                    help='Enables Tx STBC: [TX-STBC] for HT capabilities.')

    ieee80211n_config.add_argument('--enable-rx-stbc1',
                    dest='ht_rx_stbc1',
                    action='store_true',
                    default=False,
                    help='Enables Rx STBC: [RX-STBC1] (one spatial stream) for HT capabilities.')

    ieee80211n_config.add_argument('--enable-rx-stbc12',
                    dest='ht_rx_stbc12',
                    action='store_true',
                    default=False,
                    help='Enables Rx STBC: [RX-STBC12] (one or two spatial stream) for HT capabilities.')

    ieee80211n_config.add_argument('--enable-rx-stbc123',
                    dest='ht_rx_stbc123',
                    action='store_true',
                    default=False,
                    help='Enables Rx STBC: [RX-STBC123] (one, two, or three spatial stream) for HT capabilities.')

    ieee80211n_config.add_argument('--enable-delayed-ba',
                    dest='ht_delayed_ba',
                    action='store_true',
                    default=False,
                    help='Enables HT-delayed Block Ack: [DELAYED-BA] for HT capabilities.')

    ieee80211n_config.add_argument('--enable-msdu7935',
                    dest='ht_msdu7935',
                    action='store_true',
                    default=False,
                    help='Enables Maximum A-MSDU length: [MAX-AMSDU-7935] for HT capabilities.')

    ieee80211n_config.add_argument('--enable-cck',
                    dest='ht_dsss_cck',
                    action='store_true',
                    default=False,
                    help='Enables DSSS/CCK Mode in 40 MHz: [DSSS_CCK-40] for HT capabilities.')

    ieee80211n_config.add_argument('--enable-40-intolerant',
                    dest='ht_40_intolerant',
                    action='store_true',
                    default=False,
                    help='Enables 40 MHz intolerant [40-INTOLERANT] for HT capabilities.')

    ieee80211n_config.add_argument('--enable-txop_protection',
                    dest='ht_txop_protection',
                    action='store_true',
                    default=False,
                    help='Enables L-SIG TXOP protection support: [LSIG-TXOP-PROT] for HT capabilities.')

    ieee80211_config.add_argument('-c', '--channel',
                    dest='channel',
                    type=int,
                    default=config.rogue_channel,
                    help='Specify access point channel. (Default: {} - with ACS to find an unused channel)'.format(config.rogue_channel))

    ieee80211_config.add_argument('--channel-randomiser',
                    dest='channel_randomiser',
                    action='store_true',
                    default=False,
                    help='Randomise the channel selected without invoking ACS')

    ieee80211_config.add_argument('--country',
                    dest='country_code',
                    type=str,
                    default=00,
                    choices=config.rogue_country_options,
                    help='Configures of country of operation')

    ieee80211_config.add_argument('--macaddr-acl',
                    dest='macaddr_acl',
                    type=int,
                    choices=[0,1,2],
                    default=config.rogue_macaddr_acl,
                    help='Station MAC address -based authentication\r\n0 = accept unless in deny list\r\n  1 = deny unless in accept list\r\n  2 = use external RADIUS (accept/deny will be searched first)\r\n(Default: {})'.format(config.rogue_macaddr_acl))

    ieee80211_config.add_argument('--mac-accept-file',
                    dest='macaddr_accept_file',
                    type=str,
                    default=config.hostapd_accept_file_full,
                    help='Location of hostapd-wpe macaddr_acl accept file (Default: {})'.format(config.hostapd_accept_file_full))

    ieee80211_config.add_argument('--mac-deny-file',
                    dest='macaddr_deny_file',
                    type=str,
                    default=config.hostapd_deny_file_full,
                    help='Location of hostapd-wpe macaddr_acl deny file (Default: {})'.format(config.hostapd_accept_file_full))

    ieee80211_config.add_argument('--auth-algs',
                    dest='auth_algs',
                    type=int,
                    choices=[1,2,3],
                    default=config.rogue_auth_algs,
                    help='IEEE 802.11 specifies two authentication algorithms. 1 allows only WPA2 authentication algorithms. 2 is WEP. 3 allows both. (Default: {})'.format(config.rogue_auth_algs))

    ieee80211_config.add_argument('--wmm-enabled',
                    dest='wmm_enabled',
                    action="store_true",
                    default=False,
                    help='Enable Wireless Multimedia Extensions')

    ieee80211_config.add_argument('--wmm-ac-bk-cwmin',
                    dest='wmm_ac_bk_cwmin',
                    type=int,
                    default=5,
                    help='')

    ieee80211_config.add_argument('--wmm-ac-bk-cwmax',
                    dest='wmm_ac_bk_cwmax',
                    type=int,
                    default=10,
                    help='')

    ieee80211_config.add_argument('--wmm-ac-bk-aifs',
                    dest='wmm_ac_bk_aifs',
                    type=int,
                    default=7,
                    help='')

    ieee80211_config.add_argument('--wmm-ac-bk-txop-limit',
                    dest='wmm_ac_bk_txop_limit',
                    type=int,
                    default=0,
                    help='')

    ieee80211_config.add_argument('--wmm-ac-bk-acm',
                    dest='wmm_ac_bk_acm',
                    type=int,
                    default=0,
                    help='')

    ieee80211_config.add_argument('--wmm-ac-be-cwmin',
                    dest='wmm_ac_be_cwmin',
                    type=int,
                    default=5,
                    help='')

    ieee80211_config.add_argument('--wmm-ac-be-cwmax',
                    dest='wmm_ac_be_cwmax',
                    type=int,
                    default=7,
                    help='')

    ieee80211_config.add_argument('--wmm-ac-be-txop-limit',
                    dest='wmm_ac_be_txop_limit',
                    type=int,
                    default=0,
                    help='')

    ieee80211_config.add_argument('--wmm-ac-be-aifs',
                    dest='wmm_ac_be_aifs',
                    type=int,
                    default=3,
                    help='')

    ieee80211_config.add_argument('--wmm-ac-be-acm',
                    dest='wmm_ac_be_acm',
                    type=int,
                    default=0,
                    help='')

    ieee80211_config.add_argument('--wmm-ac-vi-cwmin',
                    dest='wmm_ac_vi_cwmin',
                    type=int,
                    default=4,
                    help='')

    ieee80211_config.add_argument('--wmm-ac-vi-cwmax',
                    dest='wmm_ac_vi_cwmax',
                    type=int,
                    default=5,
                    help='')

    ieee80211_config.add_argument('--wmm-ac-vi-aifs',
                    dest='wmm_ac_vi_aifs',
                    type=int,
                    default=2,
                    help='')

    ieee80211_config.add_argument('--wmm-ac-vi-txop-limit',
                    dest='wmm_ac_vi_txop_limit',
                    type=int,
                    default=188,
                    help='')

    ieee80211_config.add_argument('--wmm-ac-vi-acm',
                    dest='wmm_ac_vi_acm',
                    type=int,
                    default=0,
                    help='')

    ieee80211_config.add_argument('--wmm-ac-vo-cwmin',
                    dest='wmm_ac_vo_cwmin',
                    type=int,
                    default=3,
                    help='')

    ieee80211_config.add_argument('--wmm-ac-vo-cwmax',
                    dest='wmm_ac_vo_cwmax',
                    type=int,
                    default=4,
                    help='')

    ieee80211_config.add_argument('--wmm-ac-vo-aifs',
                    dest='wmm_ac_vo_aifs',
                    type=int,
                    default=2,
                    help='')

    ieee80211_config.add_argument('--wmm-ac-vo-txop-limit',
                    dest='wmm_ac_vo_txop_limit',
                    type=int,
                    default=47,
                    help='')

    ieee80211_config.add_argument('--wmm-ac-vo-acm',
                    dest='wmm_ac_vo_acm',
                    type=int,
                    default=0,
                    help='')

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

    ieee80211_config.add_argument('--ieee80211w',
                    dest='ieee80211w',
                    choices=[0,1,2],
                    default=0,
                    help='Control whether Protected Management Frames (PMF) is disabled, optional or required. (Default: 0)')

    ieee80211ac_config.add_argument('--vht-width',
                    dest='vht_oper_chwidth',
                    type=int,
                    choices=[0,1,2,3],
                    default=config.rogue_vht_index,
                    help='VHT channel width (Default: {}).'.format(config.rogue_vht_index))

    ieee80211ac_config.add_argument('--vht-operation',
                    dest='vht_operations',
                    type=int,
                    choices=[0,1],
                    default=config.rogue_vht_operations,
                    help='Enable toggling between 0 for vht_oper_centr_freq_seg0_idx and 1 for vht_oper_centr_freq_seg1_idx (Default: {}).'.format(config.rogue_vht_operations))

    ieee80211ac_config.add_argument('--vht-index',
                    dest='vht_index',
                    type=int,
                    choices=[42, 159],
                    default=config.rogue_vht_index_options,
                    help='Enables control of vht_oper_centr_freq_seg[0/1]_idx index value (Default: {}).'.format(config.rogue_vht_index_options))

    ieee80211ac_config.add_argument('--require-vht',
                    dest='require_vht',
                    action='store_true',
                    default=False,
                    help='Require stations to support VHT PHY (reject association if they do not) (Default: disabled).')

    ieee80211ac_config.add_argument('--disable-short80',
                    dest='vht_short80',
                    action='store_true',
                    default=False,
                    help='Disables Short GI for 80 MHz: [SHORT-GI-80] for VHT capabilities.')

    ieee80211ac_config.add_argument('--disable-short160',
                    dest='vht_short160',
                    action='store_true',
                    default=False,
                    help='Disables Short GI for 160 MHz: [SHORT-GI-160] for VHT capabilities.')

    ieee80211ac_config.add_argument('--disable-htc-vht',
                    dest='vht_htc_vht',
                    action='store_true',
                    default=False,
                    help='Enables Indicates whether or not the STA supports receiving a VHT variant HT Control for VHT capabilities.')

    ieee80211ac_config.add_argument('--enable-mpdu7991',
                    dest='vht_mpdu7991',
                    action='store_true',
                    default=False,
                    help='Enables [MAX-MPDU-7991] for VHT capabilities.')

    ieee80211ac_config.add_argument('--enable-mpdu11454',
                    dest='vht_mpdu11454',
                    action='store_true',
                    default=False,
                    help='Enables [MAX-MPDU-11454] for VHT capabilities.')

    ieee80211ac_config.add_argument('--enable-rx-ldpc',
                    dest='vht_rx_lpdc',
                    action='store_true',
                    default=False,
                    help='Enables Rx LDPC coding capability: [RXLDPC] for VHT capabilities.')

    ieee80211ac_config.add_argument('--enable-vht-tx-stbc',
                    dest='vht_tx_stbc',
                    action='store_true',
                    default=False,
                    help='Enables Tx STBC: [TX-STBC-2BY1] for VHT capabilities.')

    ieee80211ac_config.add_argument('--enable-vht-rx-stbc1',
                    dest='vht_rx_stbc1',
                    action='store_true',
                    default=False,
                    help='Enables Rx STBC: [RX-STBC1] (one spatial stream) for VHT capabilities.')

    ieee80211ac_config.add_argument('--enable-vht-rx-stbc12',
                    dest='vht_rx_stbc12',
                    action='store_true',
                    default=False,
                    help='Enables Rx STBC: [RX-STBC12] (support of one and two spatial streams) for VHT capabilities.')

    ieee80211ac_config.add_argument('--enable-vht-rx-stbc123',
                    dest='vht_rx_stbc123',
                    action='store_true',
                    default=False,
                    help='Enables Rx STBC: [RX-STBC123] (support of one, two and three spatial streams) for VHT capabilities.')

    ieee80211ac_config.add_argument('--enable-vht-rx-stbc1234',
                    dest='vht_rx_stbc1234',
                    action='store_true',
                    default=False,
                    help='Enables Rx STBC: [RX-STBC1234] (support of one, two, three and four spatial streams) for VHT capabilities.')

    ieee80211ac_config.add_argument('--enable-beamformer',
                    dest='vht_beamformer',
                    action='store_true',
                    default=False,
                    help='Enables SU Beamformer Capable: [SU-BEAMFORMER] for VHT capabilities.')

    ieee80211ac_config.add_argument('--enable-beamformee',
                    dest='vht_beamformee',
                    action='store_true',
                    default=False,
                    help='Enables SU Beamformee Capable: [SU-BEAMFORMEE] for VHT capabilities.')

    ieee80211ac_config.add_argument('--enable-sd2',
                    dest='vht_sd2',
                    action='store_true',
                    default=False,
                    help='Enables two Sounding Dimensions [SOUNDING-DIMENSION-2] for VHT capabilities.')

    ieee80211ac_config.add_argument('--enable-sd3',
                    dest='vht_sd3',
                    action='store_true',
                    default=False,
                    help='Enables three Sounding Dimensions [SOUNDING-DIMENSION-3] for VHT capabilities.')

    ieee80211ac_config.add_argument('--enable-sd4',
                    dest='vht_sd4',
                    action='store_true',
                    default=False,
                    help='Enables four Sounding Dimensions [SOUNDING-DIMENSION-4] for VHT capabilities.')

    ieee80211ac_config.add_argument('--enable-mu-beamformer',
                    dest='vht_mu_beamformer',
                    action='store_true',
                    default=False,
                    help='Enables MU Beamformer Capable: [MU-BEAMFORMER] for VHT capabilities.')

    ieee80211ac_config.add_argument('--enable-txop-ps',
                    dest='vht_txop_ps',
                    action='store_true',
                    default=False,
                    help='Enables VHT TXOP PS: [VHT-TXOP-PS] for VHT capabilities.')

    ieee80211ac_config.add_argument('--enable-tx-pattern',
                    dest='vht_tx_pattern',
                    action='store_true',
                    default=False,
                    help='Enables Tx Antenna Pattern Consistency: [TX-ANTENNA-PATTERN] for VHT capabilities.')

    ieee80211ac_config.add_argument('--enable-rx-pattern',
                    dest='vht_rx_pattern',
                    action='store_true',
                    default=False,
                    help='Enables Rx Antenna Pattern Consistency: [RX-ANTENNA-PATTERN] for VHT capabilities.')

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
                    help='Specify WPA type (Default: {}).'.format(config.rogue_wpa_version))

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
                    help='Enable 802.1x (if \'auth\' is \'wpa-enterprise\' than automatically enabled)')

    ieee8021x_config.add_argument('--eapol-version',
                    dest='eapol_version',
                    type=int,
                    choices=[1,2],
                    default=config.rogue_eapol_version,
                    help='IEEE 802.1X/EAPOL version (Default: {})'.format(config.rogue_eapol_version))

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
                    help='The own IP address of the access point (Default: {})'.format(config.default_own_ip_addr))

    radius_config.add_argument('--auth-server-addr',
                    dest='auth_server_addr',
                    type=str,
                    default=config.default_auth_server_addr,
                    help='IP address of radius authentication server (Default: {})'.format(config.default_auth_server_addr))

    radius_config.add_argument('--auth-secret',
                    dest='auth_server_shared_secret',
                    type=str,
                    default=config.default_auth_server_shared_secret,
                    help='Radius authentication server shared secret (Default: {})'.format(config.default_auth_server_shared_secret))

    radius_config.add_argument('--auth-server-port',
                    dest='auth_server_port',
                    type=int,
                    default=config.default_auth_server_port,
                    help='Networking port of radius authentication server (Default: {})'.format(config.default_auth_server_port))

    radius_config.add_argument('--acct-server-addr',
                    dest='acct_server_addr',
                    type=str,
                    default=config.default_acct_server_addr,
                    help='IP address of radius accounting server (Default: {})'.format(config.default_acct_server_addr))

    radius_config.add_argument('--acct-secret',
                    dest='acct_server_shared_secret',
                    type=str,
                    default=config.default_acct_server_shared_secret,
                    help='Radius accounting server shared secret')

    radius_config.add_argument('--acct-server-port',
                    dest='acct_server_port',
                    type=int,
                    default=config.default_acct_server_port,
                    help='Networking port of radius accounting server (Default: {})'.format(config.default_acct_server_port))

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
                    help='Specify the default EAP method used in RADIUS authentication. (Default: {})'.format(config.rogue_default_eap_type))

    radius_config.add_argument('-E','--supported-eap',
                    dest='supported_eap_type',
                    type=str,
                    nargs='+',
                    default=config.rogue_supported_eap_type,
                    choices=config.rogue_supported_eap_types,
                    help='Specify the default EAP method used in RADIUS authentication. (Default: {})'.format(config.rogue_supported_eap_type))    

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

    radius_config.add_argument('--disable-eap-user-file',
                    dest='disable_eap_user_file',
                    action='store_true',
                    default=False,
                    help='')

    attacks.add_argument('-M', '--modules',
                    dest='attack_modules',
                    nargs='+',
                    default=[''],
                    choices=config.supported_attack_modules,
                    help='Enable attack modules in hostile network.\r\nSupported Modules: {}'.format(str(config.supported_attack_modules)))

    attacks.add_argument('--karma',
                    dest='karma',
                    action='store_true',
                    default=False,
                    help='Enable Karma. (Default: False).')

    attacks.add_argument('--essid-mask',
                    dest='essid_mask',
                    type=int,
                    choices=[0,1,2],
                    default=config.rogue_essid_mask,
                    help='Send empty SSID in beacons and ignore probe request frames that do not specify full SSID. \
                    1 = send empty (length=0) SSID in beacon and ignore probe request for broadcast SSID \
                    2 = clear SSID (ASCII 0), but keep the original length (this may be required with some clients \
                    that do not support empty SSID) and ignore probe requests for broadcast SSID \
                    (Default: {})'.format(config.rogue_essid_mask))

    dhcp.add_argument('--lease',
                    dest='default_lease_time',
                    type=int,
                    default=config.default_default_lease_time,
                    help='Define DHCP lease time (Default: {})'.format(config.default_default_lease_time))

    dhcp.add_argument('--max-lease',
                    dest='max_lease_time',
                    type=int,
                    default=config.default_max_lease_time,
                    help='Define max DHCP lease time (Default: {})'.format(config.default_max_lease_time))

    dhcp.add_argument('--prim-name-server',
                    dest='primary_name_server',
                    type=str,
                    default=config.default_primary_name_server,
                    help='Define primary name server (Default: {})'.format(config.default_primary_name_server))

    dhcp.add_argument('--sec-name-server',
                    dest='secondary_name_server',
                    type=str,
                    default=config.default_secondary_name_server,
                    help='Define secondary name server (Default: {})'.format(config.default_secondary_name_server))

    dhcp.add_argument('--subnet',
                    dest='dhcp_subnet',
                    type=str,
                    default=config.default_dhcp_subnet,
                    help='(Default: {})'.format(config.default_dhcp_subnet))

    dhcp.add_argument('--route-subnet',
                    dest='route_subnet',
                    type=str,
                    default=config.default_route_subnet,
                    help='(Default: {})'.format(config.default_route_subnet))

    dhcp.add_argument('--netmask',
                    dest='dhcp_netmask',
                    type=str,
                    default=config.default_dhcp_netmask,
                    help='(Default: {})'.format(config.default_dhcp_netmask))

    dhcp.add_argument('--ip-address',
                    dest='ip_address',
                    type=str,
                    default=config.default_ip_address,
                    help='(Default: {})'.format(config.default_ip_address))

    dhcp.add_argument('--secondary-interface',
                    dest='secondary_interface',
                    type=str,
                    default=config.secondary_interface,
                    help='Used to specify the second phy interface used to bridge the hostapd-wpe interface (-i) with another network (Default: {})'.format(config.secondary_interface))

    dhcp.add_argument('--pool-start',
                    dest='dhcp_pool_start',
                    type=str,
                    default=config.default_dhcp_pool_start,
                    help='(Default: {})'.format(config.default_dhcp_pool_start))

    dhcp.add_argument('--pool-end',
                    dest='dhcp_pool_end',
                    type=str,
                    default=config.default_dhcp_pool_end,
                    help='(Default: {})'.format(config.default_dhcp_pool_end))

    sslsplit.add_argument('--cert-nopass',
                    dest='cert_nopass',
                    action='store_true',
                    help='Generate a x.509 Certificate with no password for the purpose of sslsplit.')

    modlishka.add_argument('--proxyAddress',
        dest='modlishka_proxyaddress',
        default=config.modlishka_proxyaddress,
        help='Proxy that should be used (socks/https/http) - e.g.: http://127.0.0.1:8080 (Default: {})'.format(config.modlishka_proxyaddress))

    modlishka.add_argument('--proxyDomain',
        dest='modlishka_proxydomain',
        default=config.modlishka_proxydomain,
        help='Specify the domain that will be visible in target\'s browser. (Default: {})'.format(config.modlishka_proxydomain))

    modlishka.add_argument('--listeningAddress',
        dest='modlishka_listeningaddress',
        default=config.modlishka_listeningaddress,
        help='Specify listening address of modlishka server. (Default: {})'.format(config.modlishka_listeningaddress))

    modlishka.add_argument('--target',
        dest='modlishka_target',
        default=None,
        help='Target  domain name  - e.g.: target.tld')

    modlishka.add_argument('--controlURL',
        dest='modlishka_controlURL',
        default=config.modlishka_controlURL,
        help='URL to view captured credentials and settings. (Default {})'.format(config.modlishka_controlURL))

    modlishka.add_argument('--controlCreds',
        dest='modlishka_controlCreds',
        default=config.modlishka_controlCreds,
        help='Username and password to protect the credentials page.  user:pass format. (Default: {})'.format(config.modlishka_controlCreds))

    # Basic error handling of the programs initalisation
    try:
        arg_test = sys.argv[1]
    except IndexError:
        parser.print_help()
        exit(1)

    args, leftovers = parser.parse_known_args()
    options = args.__dict__

    if(options['80211_preset_profile'] is not None):
        if(options['80211_preset_profile'] == 'wifi1'):
            options['hw_mode'] = 'b'
            options['freq'] = 2
            options['ieee80211n'] = 0
            options['ieee80211ac'] = 0
            options['wmm_enabled'] = False if('--wmm-enabled' not in sys.argv) else options['wmm_enabled']
            options['wmm_ac_bk_cwmin'] = 5
            options['wmm_ac_bk_cwmax'] = 10
            options['wmm_ac_bk_aifs'] = 7
            options['wmm_ac_bk_txop_limit'] = 0
            options['wmm_ac_bk_acm'] = 0
            options['wmm_ac_be_aifs'] = 3
            options['wmm_ac_be_cwmin'] = 5
            options['wmm_ac_be_cwmax'] = 7
            options['wmm_ac_be_txop_limit'] = 0
            options['wmm_ac_be_acm'] = 0
            options['wmm_ac_vi_aifs'] = 2
            options['wmm_ac_vi_cwmin'] = 4
            options['wmm_ac_vi_cwmax'] = 5
            options['wmm_ac_vi_txop_limit'] = 188
            options['wmm_ac_vi_acm'] = 0
            options['wmm_ac_vo_aifs'] = 2
            options['wmm_ac_vo_cwmin'] = 3
            options['wmm_ac_vo_cwmax'] = 4
            options['wmm_ac_vo_txop_limit'] = 47
            options['wmm_ac_vo_acm'] = 0
            options['require_ht'] = False if('--require-ht' not in sys.argv) else options['require_ht']
            options['require_vht'] = False if('--require-vht' not in sys.argv) else options['require_vht']
        elif(options['80211_preset_profile'] == 'wifi2'):
            options['hw_mode'] = 'a'
            options['freq'] = 5
            options['ieee80211n'] = 0
            options['ieee80211ac'] = 0
            options['wmm_enabled'] = False if('--wmm-enabled' not in sys.argv) else options['wmm_enabled']
            options['wmm_ac_bk_cwmin'] = 5
            options['wmm_ac_bk_cwmax'] = 10
            options['wmm_ac_bk_aifs'] = 7
            options['wmm_ac_bk_txop_limit'] = 0
            options['wmm_ac_bk_acm'] = 0
            options['wmm_ac_be_aifs'] = 3
            options['wmm_ac_be_cwmin'] = 5
            options['wmm_ac_be_cwmax'] = 7
            options['wmm_ac_be_txop_limit'] = 0
            options['wmm_ac_be_acm'] = 0
            options['wmm_ac_vi_aifs'] = 2
            options['wmm_ac_vi_cwmin'] = 4
            options['wmm_ac_vi_cwmax'] = 5
            options['wmm_ac_vi_txop_limit'] = 188
            options['wmm_ac_vi_acm'] = 0
            options['wmm_ac_vo_aifs'] = 2
            options['wmm_ac_vo_cwmin'] = 3
            options['wmm_ac_vo_cwmax'] = 4
            options['wmm_ac_vo_txop_limit'] = 47
            options['wmm_ac_vo_acm'] = 0
            options['require_ht'] = False if('--require-ht' not in sys.argv) else options['require_ht']
            options['require_vht'] = False if('--require-vht' not in sys.argv) else options['require_vht']
        elif(options['80211_preset_profile'] == 'wifi3'):
            options['hw_mode'] = 'g'
            options['freq'] = 2
            options['ieee80211n'] = 0
            options['ieee80211ac'] = 0
            options['wmm_enabled'] = False if('--wmm-enabled' not in sys.argv) else options['wmm_enabled']
            options['wmm_ac_bk_cwmin'] = 5
            options['wmm_ac_bk_cwmax'] = 10
            options['wmm_ac_bk_aifs'] = 7
            options['wmm_ac_bk_txop_limit'] = 0
            options['wmm_ac_bk_acm'] = 0
            options['wmm_ac_be_aifs'] = 3
            options['wmm_ac_be_cwmin'] = 5
            options['wmm_ac_be_cwmax'] = 7
            options['wmm_ac_be_txop_limit'] = 0
            options['wmm_ac_be_acm'] = 0
            options['wmm_ac_vi_aifs'] = 2
            options['wmm_ac_vi_cwmin'] = 4
            options['wmm_ac_vi_cwmax'] = 5
            options['wmm_ac_vi_txop_limit'] = 188
            options['wmm_ac_vi_acm'] = 0
            options['wmm_ac_vo_aifs'] = 2
            options['wmm_ac_vo_cwmin'] = 3
            options['wmm_ac_vo_cwmax'] = 4
            options['wmm_ac_vo_txop_limit'] = 47
            options['wmm_ac_vo_acm'] = 0
            options['require_ht'] = False if('--require-ht' not in sys.argv) else options['require_ht']
            options['require_vht'] = False if('--require-vht' not in sys.argv) else options['require_vht']
        elif(options['80211_preset_profile'] == 'wifi4'):
            options['hw_mode'] = 'a' if options['freq'] == 5 else 'g'
            options['freq'] = 5 if options['freq'] == 5 else 2
            options['ieee80211n'] = 1
            options['ieee80211ac'] = 0
            options['wmm_enabled'] = False if('--wmm-enabled' not in sys.argv) else options['wmm_enabled']
            options['wmm_ac_bk_cwmin'] = 5
            options['wmm_ac_bk_cwmax'] = 10
            options['wmm_ac_bk_aifs'] = 7
            options['wmm_ac_bk_txop_limit'] = 0
            options['wmm_ac_bk_acm'] = 0
            options['wmm_ac_be_aifs'] = 3
            options['wmm_ac_be_cwmin'] = 5
            options['wmm_ac_be_cwmax'] = 7
            options['wmm_ac_be_txop_limit'] = 0
            options['wmm_ac_be_acm'] = 0
            options['wmm_ac_vi_aifs'] = 2
            options['wmm_ac_vi_cwmin'] = 4
            options['wmm_ac_vi_cwmax'] = 5
            options['wmm_ac_vi_txop_limit'] = 188
            options['wmm_ac_vi_acm'] = 0
            options['wmm_ac_vo_aifs'] = 2
            options['wmm_ac_vo_cwmin'] = 3
            options['wmm_ac_vo_cwmax'] = 4
            options['wmm_ac_vo_txop_limit'] = 47
            options['wmm_ac_vo_acm'] = 0
            options['require_ht'] = True
            options['require_vht'] = False if('--require-vht' not in sys.argv) else options['require_vht']
            options['ht_rx_stbc1'] = False if('--enable-rx-stbc1' not in sys.argv) else options['ht_rx_stbc1']
            options['ht_msdu7935'] = False if('--enable-msdu7935' not in sys.argv) else options['ht_msdu7935']
            options['ht_dsss_cck'] = False if('--enable-cck' not in sys.argv) else options['ht_dsss_cck']
        elif(options['80211_preset_profile'] == 'wifi5'):
            options['hw_mode'] = 'a'
            options['freq'] = 5
            options['ieee80211n'] = 1
            options['ieee80211ac'] = 1
            options['wmm_enabled'] = True
            options['wmm_ac_bk_cwmin'] = 5
            options['wmm_ac_bk_cwmax'] = 10
            options['wmm_ac_bk_aifs'] = 7
            options['wmm_ac_bk_txop_limit'] = 0
            options['wmm_ac_bk_acm'] = 0
            options['wmm_ac_be_aifs'] = 3
            options['wmm_ac_be_cwmin'] = 5
            options['wmm_ac_be_cwmax'] = 7
            options['wmm_ac_be_txop_limit'] = 0
            options['wmm_ac_be_acm'] = 0
            options['wmm_ac_vi_aifs'] = 2
            options['wmm_ac_vi_cwmin'] = 4
            options['wmm_ac_vi_cwmax'] = 5
            options['wmm_ac_vi_txop_limit'] = 188
            options['wmm_ac_vi_acm'] = 0
            options['wmm_ac_vo_aifs'] = 2
            options['wmm_ac_vo_cwmin'] = 3
            options['wmm_ac_vo_cwmax'] = 4
            options['wmm_ac_vo_txop_limit'] = 47
            options['wmm_ac_vo_acm'] = 0
            options['require_ht'] = True
            options['require_vht'] = True
            options['ht_rx_stbc1'] = False if('--enable-rx-stbc1' not in sys.argv) else options['ht_rx_stbc1']
            options['ht_msdu7935'] = False if('--enable-msdu7935' not in sys.argv) else options['ht_msdu7935']
            options['ht_dsss_cck'] = False if('--enable-cck' not in sys.argv) else options['ht_dsss_cck']
        elif(options['80211_preset_profile'] == 'wifi6'):
            parser.error("[!] Functionality not implemented yet!")
        else:
            parser.error("[!] Unknown 802.11 preset profile specified")

    # Attack Configurations
    options['responder'] = True if('responder' in options['attack_modules']) else False
    options['sslsplit'] = True if('sslsplit' in options['attack_modules']) else False
    options['modlishka'] = True if('modlishka' in options['attack_modules']) else False

    options = args.__dict__
    o = optionsClass(options, parser)


    o.check_debug()
    o.set_driver()
    o.set_country()
    o.check_80211d()
    o.check_80211h()
    o.check_channel()
    o.set_require_ht()
    o.set_ht_capability()
    o.set_require_vht()
    o.set_vht_operations()
    o.set_vht_capability()
    o.set_wmm_enabled()
    o.set_ap_isolate()
    o.check_auth()
    if(options['80211_preset_profile'] is None):
        o.check_hardware_mode()

    # 802.1x Configuration
    o.set_8021x()
    o.set_eapol_workaround()

    # RADIUS Configuration
    o.set_log_goodpass()
    o.set_log_badpass()
    o.check_default_supported_eap_types()


    options = o.__reassemble__()

    return options
