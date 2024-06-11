#!/usr/bin/python3
import os

import config
from core.templates import dhcpd_cnf
from core.templates import freeradius_cnf
from core.templates import responder_cnf

##
### Attack Template Engines
##
class responder_default_conf(object):
    path = config.responder_conf
    template = responder_cnf.responder_default_conf

    @classmethod
    def configure(cls,
        do_not_respond_to_own_ip_addr=None,):

        assert do_not_respond_to_own_ip_addr is not None

        try:
            print("[+] Creating Responder.conf file: %s" % cls.path)
            with open(cls.path, 'w') as fd:
                fd.write(cls.template %\
                    (do_not_respond_to_own_ip_addr))
        except Exception as e:
            print("[!] Error: %s" % e)
            return 1

class responder_no_http_conf(object):
    path = config.responder_conf
    template = responder_cnf.responder_no_http_conf

    @classmethod
    def configure(cls,
        do_not_respond_to_own_ip_addr=None,):

        assert do_not_respond_to_own_ip_addr is not None

        try:
            print("[+] Creating Responder.conf file: %s" % cls.path)
            with open(cls.path, 'w') as fd:
                fd.write(cls.template %\
                    (do_not_respond_to_own_ip_addr))
        except Exception as e:
            print("[!] Error: %s" % e)
            return 1

##
### ISC DHCP Template Engines
##
class default_dhcp(object):
    path = config.dhcp_default
    template = dhcpd_cnf.default_dhcp

    @classmethod
    def configure(cls,
            # Do NOT Change unless you know what you are doing
            default_dhcpv4_conf_location=None,
            interface=None
            ):

        assert default_dhcpv4_conf_location is not None
        assert interface is not None

        try:
            print("[+] Creating /etc/default/isc-dhcp-server file: %s" % cls.path)
            with open(cls.path, 'w') as fd:
                fd.write(cls.template %\
                    (default_dhcpv4_conf_location, interface))
        except Exception as e:
            print("[!] Error: %s" % e)
            return 1    

class dhcpd_conf(object):

    path = config.dhcp_conf
    template = dhcpd_cnf.dhcpd_cnf

    @classmethod
    def configure(cls,
            # Do NOT Change unless you know what you are doing
            router=None,
            route_gateway=None,
            route_cidr=None,
            route_subnet=None,
            name_servers=None,
            default_lease_time=None,
            max_lease_time=None,
            dhcp_subnet=None,
            dhcp_netmask=None,
            dhcp_pool_start=None,
            dhcp_pool_end=None
            ):

        assert router is not None
        assert route_gateway is not None
        assert route_cidr is not None
        assert route_subnet is not None
        assert name_servers is not None
        assert default_lease_time is not None
        assert max_lease_time is not None
        assert dhcp_subnet is not None
        assert dhcp_netmask is not None
        assert dhcp_pool_start is not None
        assert dhcp_pool_end is not None

        try:
            print("[+] Creating dhcpd.conf file: %s" % cls.path)
            with open(cls.path, 'w') as fd:
                fd.write(cls.template %\
                    (default_lease_time, max_lease_time, dhcp_subnet, dhcp_netmask, dhcp_pool_start, dhcp_pool_end, router, name_servers, route_gateway, route_cidr, route_subnet, route_gateway))
        except Exception as e:
            print("[!] Error: %s" % e)
            return 1

##
### Freeradius Template Engines
##
class freeradius_clients_conf(object):

    path = config.freeradius_clients_full
    template = freeradius_cnf.freeradius_clients_conf

    @classmethod
    def configure(cls,
            # Do NOT Change unless you know what you are doing
            own_ip_addr=None,
            auth_server_shared_secret=None,
            radius_protocol=None
            ):

        assert own_ip_addr is not None
        assert auth_server_shared_secret is not None
        assert radius_protocol is not None

        try:
            print("[+] Creating clients.conf file: %s" % cls.path)
            with open(cls.path, 'w') as fd:
                fd.write(cls.template %\
                    (own_ip_addr, radius_protocol, auth_server_shared_secret))
        except Exception as e:
            print("[!] Error: %s" % e)
            return 1

class freeradius_radiusd_conf(object):

    path = config.freeradius_radiusd_full
    template = freeradius_cnf.freeradius_radiusd_conf

    @classmethod
    def configure(cls,
            # Do NOT Change unless you know what you are doing
            logdir=None,
            radiuslog=None,
            wpelogfile=None,
            cert_dir=None,
            log_goodpass=None,
            log_badpass=None
            ):

        assert logdir is not None
        assert radiuslog is not None
        assert wpelogfile is not None
        assert cert_dir is not None
        assert log_goodpass is not None
        assert log_badpass is not None

        try:
            print("[+] Creating radiusd.conf file: %s" % cls.path)
            with open(cls.path, 'w') as fd:
                fd.write(cls.template %\
                    (logdir, cert_dir, cert_dir, radiuslog, log_badpass, log_goodpass, wpelogfile))
        except Exception as e:
            print("[!] Error: %s" % e)
            return 1

class freeradius_default_available_site_conf(object):

    path = config.freeradius_default_site_full
    template = freeradius_cnf.freeradius_default_site_conf

    @classmethod
    def configure(cls):
        try:
            print("[+] Rewriting the default site file: {}".format(cls.path))
            with open(cls.path, 'w') as fd:
                fd.write(cls.template)
        except Exception as e:
            print("[!] Error: {}".format(e))
            return 1

class freeradius_eap_conf(object):
    import config
    from core.templates.freeradius.eap import freeradius_eap_all
    from core.templates.freeradius.eap import freeradius_eap_md5
    from core.templates.freeradius.eap import freeradius_eap_pwd
    from core.templates.freeradius.eap import freeradius_eap_leap
    from core.templates.freeradius.eap import freeradius_eap_gtc
    from core.templates.freeradius.eap import freeradius_eap_tls_common
    from core.templates.freeradius.eap import freeradius_eap_tls
    from core.templates.freeradius.eap import freeradius_eap_ttls
    from core.templates.freeradius.eap import freeradius_eap_peap
    from core.templates.freeradius.eap import freeradius_eap_fast

    path = config.freeradius_mods_dir_eap_full
    template = freeradius_cnf.freeradius_eap_conf
    modules_all = freeradius_eap_all.freeradius_eap_all
    module_md5 = freeradius_eap_md5.freeradius_eap_md5
    module_pwd = freeradius_eap_pwd.freeradius_eap_pwd
    module_leap = freeradius_eap_leap.freeradius_eap_leap
    module_gtc = freeradius_eap_gtc.freeradius_eap_gtc
    module_tls_common = freeradius_eap_tls_common.freeradius_eap_tls_common
    module_tls = freeradius_eap_tls.freeradius_eap_tls
    module_ttls = freeradius_eap_ttls.freeradius_eap_ttls
    module_peap = freeradius_eap_peap.freeradius_eap_peap
    module_fast = freeradius_eap_fast.freeradius_eap_fast

    @classmethod
    def configure(cls,
            default_eap_type=None,
            private_key_password=None,
            private_key_file=None,
            certificate_file=None,
            ca_file=None,
            dh_file=None,
            ca_path=None,
            supported_eap_type=None
            ):

        assert default_eap_type is not None
        assert private_key_password is not None
        assert private_key_file is not None
        assert certificate_file is not None
        assert ca_file is not None
        assert dh_file is not None
        assert ca_path is not None
        assert supported_eap_type is not None

        if('all' in supported_eap_type):
            module = cls.modules_all %\
                (private_key_password, private_key_file, certificate_file, ca_file, dh_file, config.certs_dir,)
        else:
            module = list()
            if('md5' in supported_eap_type):
                module.append(cls.module_md5)
            if('pwd' in supported_eap_type):
                module.append(cls.module_pwd)
            if('leap' in supported_eap_type):
                module.append(cls.module_leap)
            if('gtc' in supported_eap_type):
                module.append(cls.module_gtc)
            if(('tls-config tls-common' not in module) and (('peap' in supported_eap_type) or ('tls' in supported_eap_type) or ('ttls' in supported_eap_type))):
                module.append(cls.module_tls_common %\
                    (private_key_password, private_key_file, certificate_file, ca_file, dh_file, config.certs_dir,))
            if('tls' in supported_eap_type):
                module.append(cls.module_tls)
            if('ttls' in supported_eap_type):
                module.append(cls.module_ttls)
            if('peap' in supported_eap_type):
                module.append(cls.module_peap)
            if('fast' in supported_eap_type):
                module.append(cls.module_fast)
        try:
            print("[+] Creating eap.conf file: %s" % cls.path)
            with open(cls.path, 'w') as fd:
                fd.write(cls.template %\
                    (default_eap_type, ''.join(module)))
        except Exception as e:
            print("[!] Error: %s" % e)
            return 1

##
### Hostapd Template Engines
##

class HostapdWifi1:

    class OpenCnf:

        import config
        from core.templates.hostapd import hostapd_wifi1_cnf

        path = config.hostapd_conf_full
        template = hostapd_wifi1_cnf.hostapd_wifi1_open_cnf

        @classmethod
        def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            beacon_interval=None,
            hw_mode=None,
            channel=None,
            country_code=None,
            ieee80211d=None,
            ieee80211h=None,
            bssid=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            ap_isolate=None,
            essid_mask=None,
        ):

            assert driver is not None
            assert interface is not None
            assert ssid is not None
            assert beacon_interval is not None
            assert hw_mode is not None
            assert channel is not None
            assert country_code is not None
            assert ieee80211d is not None
            assert ieee80211h is not None
            assert bssid is not None
            assert macaddr_acl is not None
            assert macaddr_accept_file is not None
            assert macaddr_deny_file is not None
            assert ap_isolate is not None
            assert essid_mask is not None

            try:
                print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)

                with open(cls.path, 'w') as fd:
                    fd.write(cls.template.format(
                        driver=driver,
                        interface=interface,
                        ssid=ssid,
                        beacon_interval=beacon_interval,
                        hw_mode=hw_mode,
                        channel=channel,
                        country_code=country_code,
                        ieee80211d=ieee80211d,
                        ieee80211h=ieee80211h,
                        bssid=bssid,
                        macaddr_acl=macaddr_acl,
                        macaddr_accept_file=macaddr_accept_file,
                        macaddr_deny_file=macaddr_deny_file,
                        ap_isolate=ap_isolate,
                        essid_mask=essid_mask
                    ))

            except Exception as e:
                print("[!] Error: %s" % e)
                return 1

    class WepCnf:

        import config
        from core.templates.hostapd import hostapd_wifi1_cnf

        path = config.hostapd_conf_full
        template = hostapd_wifi1_cnf.hostapd_wifi1_wep_cnf

        @classmethod
        def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            beacon_interval=None,
            hw_mode=None,
            channel=None,
            country_code=None,
            ieee80211d=None,
            ieee80211h=None,
            bssid=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            ap_isolate=None,
            essid_mask=None,
            wep_default_key=None,
            wep_key=None
        ):

            assert driver is not None
            assert interface is not None
            assert ssid is not None
            assert beacon_interval is not None
            assert hw_mode is not None
            assert channel is not None
            assert country_code is not None
            assert ieee80211d is not None
            assert ieee80211h is not None
            assert bssid is not None
            assert macaddr_acl is not None
            assert macaddr_accept_file is not None
            assert macaddr_deny_file is not None
            assert ap_isolate is not None
            assert essid_mask is not None
            assert wep_default_key is not None
            assert wep_key is not None

            try:
                print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)

                with open(cls.path, 'w') as fd:
                    fd.write(cls.template.format(
                        driver=driver,
                        interface=interface,
                        ssid=ssid,
                        beacon_interval=beacon_interval,
                        hw_mode=hw_mode,
                        channel=channel,
                        country_code=country_code,
                        ieee80211d=ieee80211d,
                        ieee80211h=ieee80211h,
                        bssid=bssid,
                        macaddr_acl=macaddr_acl,
                        macaddr_accept_file=macaddr_accept_file,
                        macaddr_deny_file=macaddr_deny_file,
                        ap_isolate=ap_isolate,
                        essid_mask=essid_mask,
                        wep_key=wep_key,
                        wep_default_key=wep_default_key
                    ))

            except Exception as e:
                print("[!] Error: %s" % e)
                return 1

    class WpaCnf:

        import config
        from core.templates.hostapd import hostapd_wifi1_cnf

        path = config.hostapd_conf_full
        template = hostapd_wifi1_cnf.hostapd_wifi1_wpa_cnf

        @classmethod
        def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            beacon_interval=None,
            hw_mode=None,
            channel=None,
            country_code=None,
            ieee80211d=None,
            ieee80211h=None,
            bssid=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            ap_isolate=None,
            essid_mask=None,
            wpa=None,
            wpa_passphrase=None,
            wpa_pairwise=None,
            rsn_pairwise=None,
        ):

            assert driver is not None
            assert interface is not None
            assert ssid is not None
            assert beacon_interval is not None
            assert hw_mode is not None
            assert channel is not None
            assert country_code is not None
            assert ieee80211d is not None
            assert ieee80211h is not None
            assert bssid is not None
            assert macaddr_acl is not None
            assert macaddr_accept_file is not None
            assert macaddr_deny_file is not None
            assert ap_isolate is not None
            assert essid_mask is not None
            assert wpa is not None
            assert wpa_passphrase is not None
            assert wpa_pairwise is not None
            assert rsn_pairwise is not None

            try:
                print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)

                with open(cls.path, 'w') as fd:
                    fd.write(cls.template.format(
                        driver=driver,
                        interface=interface,
                        ssid=ssid,
                        beacon_interval=beacon_interval,
                        hw_mode=hw_mode,
                        channel=channel,
                        country_code=country_code,
                        ieee80211d=ieee80211d,
                        ieee80211h=ieee80211h,
                        bssid=bssid,
                        macaddr_acl=macaddr_acl,
                        macaddr_accept_file=macaddr_accept_file,
                        macaddr_deny_file=macaddr_deny_file,
                        ap_isolate=ap_isolate,
                        essid_mask=essid_mask,
                        wpa=wpa,
                        wpa_passphrase=wpa_passphrase,
                        wpa_pairwise=wpa_pairwise,
                        rsn_pairwise=rsn_pairwise
                    ))

            except Exception as e:
                print("[!] Error: %s" % e)
                return 1

    class WpaEapCnf:

        import config
        from core.templates.hostapd import hostapd_wifi1_cnf

        path = config.hostapd_conf_full
        template = hostapd_wifi1_cnf.hostapd_wifi1_wpa_eap_cnf

        @classmethod
        def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            beacon_interval=None,
            hw_mode=None,
            channel=None,
            country_code=None,
            ieee80211d=None,
            ieee80211h=None,
            bssid=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            ap_isolate=None,
            essid_mask=None,
            wpa=None,
            wpa_pairwise=None,
            rsn_pairwise=None,
            ieee8021x=None,
            eapol_version=None,
            eapol_workaround=None,
            own_ip_addr=None,
            auth_server_addr=None,
            auth_server_port=None,
            auth_server_shared_secret=None,
            acct_server_addr=None,
            acct_server_port=None,
            acct_server_shared_secret=None,
            eap_user_file=None,
            ca_pem=None,
            server_pem=None,
            private_key=None,
            private_key_passwd=None,
            dh_file=None
        ):

            assert driver is not None
            assert interface is not None
            assert ssid is not None
            assert beacon_interval is not None
            assert hw_mode is not None
            assert channel is not None
            assert country_code is not None
            assert ieee80211d is not None
            assert ieee80211h is not None
            assert bssid is not None
            assert macaddr_acl is not None
            assert macaddr_accept_file is not None
            assert macaddr_deny_file is not None
            assert ap_isolate is not None
            assert essid_mask is not None
            assert wpa is not None
            assert wpa_pairwise is not None
            assert rsn_pairwise is not None
            assert ieee8021x is not None
            assert eapol_version is not None
            assert eapol_workaround is not None
            assert own_ip_addr is not None
            assert auth_server_addr is not None
            assert auth_server_port is not None
            assert auth_server_shared_secret is not None
            assert acct_server_addr is not None
            assert acct_server_port is not None
            assert acct_server_shared_secret is not None
            assert eap_user_file is not None
            assert ca_pem is not None
            assert server_pem is not None
            assert private_key is not None
            assert private_key_passwd is not None
            assert dh_file is not None

            try:
                print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)

                with open(cls.path, 'w') as fd:
                    fd.write(cls.template.format(
                        driver=driver,
                        interface=interface,
                        ssid=ssid,
                        beacon_interval=beacon_interval,
                        hw_mode=hw_mode,
                        channel=channel,
                        country_code=country_code,
                        ieee80211d=ieee80211d,
                        ieee80211h=ieee80211h,
                        bssid=bssid,
                        macaddr_acl=macaddr_acl,
                        macaddr_accept_file=macaddr_accept_file,
                        macaddr_deny_file=macaddr_deny_file,
                        ap_isolate=ap_isolate,
                        essid_mask=essid_mask,
                        wpa=wpa,
                        wpa_pairwise=wpa_pairwise,
                        rsn_pairwise=rsn_pairwise,
                        ieee8021x=ieee8021x,
                        eapol_version=eapol_version,
                        eapol_workaround=eapol_workaround,
                        own_ip_addr=own_ip_addr,
                        auth_server_addr=auth_server_addr,
                        auth_server_port=auth_server_port,
                        auth_server_shared_secret=auth_server_shared_secret,
                        acct_server_addr=acct_server_addr,
                        acct_server_port=acct_server_port,
                        acct_server_shared_secret=acct_server_shared_secret,
                        eap_user_file=eap_user_file,
                        ca_pem=ca_pem,
                        server_pem=server_pem,
                        private_key=private_key,
                        private_key_passwd=private_key_passwd, # unused
                        dh_file=dh_file,
                    ))

            except Exception as e:
                print("[!] Error: %s" % e)
                return 1

class HostapdWifi2:

    class OpenCnf:

        import config
        from core.templates.hostapd import hostapd_wifi2_cnf

        path = config.hostapd_conf_full
        template = hostapd_wifi2_cnf.hostapd_wifi2_open_cnf

        @classmethod
        def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            beacon_interval=None,
            hw_mode=None,
            channel=None,
            country_code=None,
            ieee80211d=None,
            ieee80211h=None,
            bssid=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            ap_isolate=None,
            essid_mask=None,
        ):

            assert driver is not None
            assert interface is not None
            assert ssid is not None
            assert beacon_interval is not None
            assert hw_mode is not None
            assert channel is not None
            assert country_code is not None
            assert ieee80211d is not None
            assert ieee80211h is not None
            assert bssid is not None
            assert macaddr_acl is not None
            assert macaddr_accept_file is not None
            assert macaddr_deny_file is not None
            assert ap_isolate is not None
            assert essid_mask is not None

            try:
                print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)

                with open(cls.path, 'w') as fd:
                    fd.write(cls.template.format(
                        driver=driver,
                        interface=interface,
                        ssid=ssid,
                        beacon_interval=beacon_interval,
                        hw_mode=hw_mode,
                        channel=channel,
                        country_code=country_code,
                        ieee80211d=ieee80211d,
                        ieee80211h=ieee80211h,
                        bssid=bssid,
                        macaddr_acl=macaddr_acl,
                        macaddr_accept_file=macaddr_accept_file,
                        macaddr_deny_file=macaddr_deny_file,
                        ap_isolate=ap_isolate,
                        essid_mask=essid_mask
                    ))

            except Exception as e:
                print("[!] Error: %s" % e)
                return 1

    class WepCnf:

        import config
        from core.templates.hostapd import hostapd_wifi2_cnf

        path = config.hostapd_conf_full
        template = hostapd_wifi2_cnf.hostapd_wifi2_wep_cnf

        @classmethod
        def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            beacon_interval=None,
            hw_mode=None,
            channel=None,
            country_code=None,
            ieee80211d=None,
            ieee80211h=None,
            bssid=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            ap_isolate=None,
            essid_mask=None,
            wep_default_key=None,
            wep_key=None
        ):

            assert driver is not None
            assert interface is not None
            assert ssid is not None
            assert beacon_interval is not None
            assert hw_mode is not None
            assert channel is not None
            assert country_code is not None
            assert ieee80211d is not None
            assert ieee80211h is not None
            assert bssid is not None
            assert macaddr_acl is not None
            assert macaddr_accept_file is not None
            assert macaddr_deny_file is not None
            assert ap_isolate is not None
            assert essid_mask is not None
            assert wep_default_key is not None
            assert wep_key is not None

            try:
                print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)

                with open(cls.path, 'w') as fd:
                    fd.write(cls.template.format(
                        driver=driver,
                        interface=interface,
                        ssid=ssid,
                        beacon_interval=beacon_interval,
                        hw_mode=hw_mode,
                        channel=channel,
                        country_code=country_code,
                        ieee80211d=ieee80211d,
                        ieee80211h=ieee80211h,
                        bssid=bssid,
                        macaddr_acl=macaddr_acl,
                        macaddr_accept_file=macaddr_accept_file,
                        macaddr_deny_file=macaddr_deny_file,
                        ap_isolate=ap_isolate,
                        essid_mask=essid_mask,
                        wep_key=wep_key,
                        wep_default_key=wep_default_key
                    ))

            except Exception as e:
                print("[!] Error: %s" % e)
                return 1

    class WpaCnf:

        import config
        from core.templates.hostapd import hostapd_wifi2_cnf

        path = config.hostapd_conf_full
        template = hostapd_wifi2_cnf.hostapd_wifi2_wpa_cnf

        @classmethod
        def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            beacon_interval=None,
            hw_mode=None,
            channel=None,
            country_code=None,
            ieee80211d=None,
            ieee80211h=None,
            bssid=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            ap_isolate=None,
            essid_mask=None,
            wpa=None,
            wpa_passphrase=None,
            wpa_pairwise=None,
            rsn_pairwise=None,
        ):

            assert driver is not None
            assert interface is not None
            assert ssid is not None
            assert beacon_interval is not None
            assert hw_mode is not None
            assert channel is not None
            assert country_code is not None
            assert ieee80211d is not None
            assert ieee80211h is not None
            assert bssid is not None
            assert macaddr_acl is not None
            assert macaddr_accept_file is not None
            assert macaddr_deny_file is not None
            assert ap_isolate is not None
            assert essid_mask is not None
            assert wpa is not None
            assert wpa_passphrase is not None
            assert wpa_pairwise is not None
            assert rsn_pairwise is not None

            try:
                print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)

                with open(cls.path, 'w') as fd:
                    fd.write(cls.template.format(
                        driver=driver,
                        interface=interface,
                        ssid=ssid,
                        beacon_interval=beacon_interval,
                        hw_mode=hw_mode,
                        channel=channel,
                        country_code=country_code,
                        ieee80211d=ieee80211d,
                        ieee80211h=ieee80211h,
                        bssid=bssid,
                        macaddr_acl=macaddr_acl,
                        macaddr_accept_file=macaddr_accept_file,
                        macaddr_deny_file=macaddr_deny_file,
                        ap_isolate=ap_isolate,
                        essid_mask=essid_mask,
                        wpa=wpa,
                        wpa_passphrase=wpa_passphrase,
                        wpa_pairwise=wpa_pairwise,
                        rsn_pairwise=rsn_pairwise
                    ))

            except Exception as e:
                print("[!] Error: %s" % e)
                return 1

    class WpaEapCnf:

        import config
        from core.templates.hostapd import hostapd_wifi2_cnf

        path = config.hostapd_conf_full
        template = hostapd_wifi2_cnf.hostapd_wifi2_wpa_eap_cnf

        @classmethod
        def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            beacon_interval=None,
            hw_mode=None,
            channel=None,
            country_code=None,
            ieee80211d=None,
            ieee80211h=None,
            bssid=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            ap_isolate=None,
            essid_mask=None,
            wpa=None,
            wpa_pairwise=None,
            rsn_pairwise=None,
            ieee8021x=None,
            eapol_version=None,
            eapol_workaround=None,
            own_ip_addr=None,
            auth_server_addr=None,
            auth_server_port=None,
            auth_server_shared_secret=None,
            acct_server_addr=None,
            acct_server_port=None,
            acct_server_shared_secret=None,
            eap_user_file=None,
            ca_pem=None,
            server_pem=None,
            private_key=None,
            private_key_passwd=None,
            dh_file=None
        ):

            assert driver is not None
            assert interface is not None
            assert ssid is not None
            assert beacon_interval is not None
            assert hw_mode is not None
            assert channel is not None
            assert country_code is not None
            assert ieee80211d is not None
            assert ieee80211h is not None
            assert bssid is not None
            assert macaddr_acl is not None
            assert macaddr_accept_file is not None
            assert macaddr_deny_file is not None
            assert ap_isolate is not None
            assert essid_mask is not None
            assert wpa is not None
            assert wpa_pairwise is not None
            assert rsn_pairwise is not None
            assert ieee8021x is not None
            assert eapol_version is not None
            assert eapol_workaround is not None
            assert own_ip_addr is not None
            assert auth_server_addr is not None
            assert auth_server_port is not None
            assert auth_server_shared_secret is not None
            assert acct_server_addr is not None
            assert acct_server_port is not None
            assert acct_server_shared_secret is not None
            assert eap_user_file is not None
            assert ca_pem is not None
            assert server_pem is not None
            assert private_key is not None
            assert private_key_passwd is not None
            assert dh_file is not None

            try:
                print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)

                with open(cls.path, 'w') as fd:
                    fd.write(cls.template.format(
                        driver=driver,
                        interface=interface,
                        ssid=ssid,
                        beacon_interval=beacon_interval,
                        hw_mode=hw_mode,
                        channel=channel,
                        country_code=country_code,
                        ieee80211d=ieee80211d,
                        ieee80211h=ieee80211h,
                        bssid=bssid,
                        macaddr_acl=macaddr_acl,
                        macaddr_accept_file=macaddr_accept_file,
                        macaddr_deny_file=macaddr_deny_file,
                        ap_isolate=ap_isolate,
                        essid_mask=essid_mask,
                        wpa=wpa,
                        wpa_pairwise=wpa_pairwise,
                        rsn_pairwise=rsn_pairwise,
                        ieee8021x=ieee8021x,
                        eapol_version=eapol_version,
                        eapol_workaround=eapol_workaround,
                        own_ip_addr=own_ip_addr,
                        auth_server_addr=auth_server_addr,
                        auth_server_port=auth_server_port,
                        auth_server_shared_secret=auth_server_shared_secret,
                        acct_server_addr=acct_server_addr,
                        acct_server_port=acct_server_port,
                        acct_server_shared_secret=acct_server_shared_secret,
                        eap_user_file=eap_user_file,
                        ca_pem=ca_pem,
                        server_pem=server_pem,
                        private_key=private_key,
                        private_key_passwd=private_key_passwd, # unused
                        dh_file=dh_file,
                    ))

            except Exception as e:
                print("[!] Error: %s" % e)
                return 1

class HostapdWifi3:

    class OpenCnf:

        import config
        from core.templates.hostapd import hostapd_wifi3_cnf

        path = config.hostapd_conf_full
        template = hostapd_wifi3_cnf.hostapd_wifi3_open_cnf

        @classmethod
        def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            beacon_interval=None,
            hw_mode=None,
            channel=None,
            country_code=None,
            ieee80211d=None,
            ieee80211h=None,
            bssid=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            ap_isolate=None,
            essid_mask=None,
        ):

            assert driver is not None
            assert interface is not None
            assert ssid is not None
            assert beacon_interval is not None
            assert hw_mode is not None
            assert channel is not None
            assert country_code is not None
            assert ieee80211d is not None
            assert ieee80211h is not None
            assert bssid is not None
            assert macaddr_acl is not None
            assert macaddr_accept_file is not None
            assert macaddr_deny_file is not None
            assert ap_isolate is not None
            assert essid_mask is not None

            try:
                print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)

                with open(cls.path, 'w') as fd:
                    fd.write(cls.template.format(
                        driver=driver,
                        interface=interface,
                        ssid=ssid,
                        beacon_interval=beacon_interval,
                        hw_mode=hw_mode,
                        channel=channel,
                        country_code=country_code,
                        ieee80211d=ieee80211d,
                        ieee80211h=ieee80211h,
                        bssid=bssid,
                        macaddr_acl=macaddr_acl,
                        macaddr_accept_file=macaddr_accept_file,
                        macaddr_deny_file=macaddr_deny_file,
                        ap_isolate=ap_isolate,
                        essid_mask=essid_mask
                    ))

            except Exception as e:
                print("[!] Error: %s" % e)
                return 1

    class WepCnf:

        import config
        from core.templates.hostapd import hostapd_wifi3_cnf

        path = config.hostapd_conf_full
        template = hostapd_wifi3_cnf.hostapd_wifi3_wep_cnf

        @classmethod
        def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            beacon_interval=None,
            hw_mode=None,
            channel=None,
            country_code=None,
            ieee80211d=None,
            ieee80211h=None,
            bssid=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            ap_isolate=None,
            essid_mask=None,
            wep_default_key=None,
            wep_key=None
        ):

            assert driver is not None
            assert interface is not None
            assert ssid is not None
            assert beacon_interval is not None
            assert hw_mode is not None
            assert channel is not None
            assert country_code is not None
            assert ieee80211d is not None
            assert ieee80211h is not None
            assert bssid is not None
            assert macaddr_acl is not None
            assert macaddr_accept_file is not None
            assert macaddr_deny_file is not None
            assert ap_isolate is not None
            assert essid_mask is not None
            assert wep_default_key is not None
            assert wep_key is not None

            try:
                print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)

                with open(cls.path, 'w') as fd:
                    fd.write(cls.template.format(
                        driver=driver,
                        interface=interface,
                        ssid=ssid,
                        beacon_interval=beacon_interval,
                        hw_mode=hw_mode,
                        channel=channel,
                        country_code=country_code,
                        ieee80211d=ieee80211d,
                        ieee80211h=ieee80211h,
                        bssid=bssid,
                        macaddr_acl=macaddr_acl,
                        macaddr_accept_file=macaddr_accept_file,
                        macaddr_deny_file=macaddr_deny_file,
                        ap_isolate=ap_isolate,
                        essid_mask=essid_mask,
                        wep_key=wep_key,
                        wep_default_key=wep_default_key
                    ))

            except Exception as e:
                print("[!] Error: %s" % e)
                return 1

    class WpaCnf:

        import config
        from core.templates.hostapd import hostapd_wifi3_cnf

        path = config.hostapd_conf_full
        template = hostapd_wifi3_cnf.hostapd_wifi3_wpa_cnf

        @classmethod
        def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            beacon_interval=None,
            hw_mode=None,
            channel=None,
            country_code=None,
            ieee80211d=None,
            ieee80211h=None,
            bssid=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            ap_isolate=None,
            essid_mask=None,
            wpa=None,
            wpa_passphrase=None,
            wpa_pairwise=None,
            rsn_pairwise=None,
        ):

            assert driver is not None
            assert interface is not None
            assert ssid is not None
            assert beacon_interval is not None
            assert hw_mode is not None
            assert channel is not None
            assert country_code is not None
            assert ieee80211d is not None
            assert ieee80211h is not None
            assert bssid is not None
            assert macaddr_acl is not None
            assert macaddr_accept_file is not None
            assert macaddr_deny_file is not None
            assert ap_isolate is not None
            assert essid_mask is not None
            assert wpa is not None
            assert wpa_passphrase is not None
            assert wpa_pairwise is not None
            assert rsn_pairwise is not None

            try:
                print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)

                with open(cls.path, 'w') as fd:
                    fd.write(cls.template.format(
                        driver=driver,
                        interface=interface,
                        ssid=ssid,
                        beacon_interval=beacon_interval,
                        hw_mode=hw_mode,
                        channel=channel,
                        country_code=country_code,
                        ieee80211d=ieee80211d,
                        ieee80211h=ieee80211h,
                        bssid=bssid,
                        macaddr_acl=macaddr_acl,
                        macaddr_accept_file=macaddr_accept_file,
                        macaddr_deny_file=macaddr_deny_file,
                        ap_isolate=ap_isolate,
                        essid_mask=essid_mask,
                        wpa=wpa,
                        wpa_passphrase=wpa_passphrase,
                        wpa_pairwise=wpa_pairwise,
                        rsn_pairwise=rsn_pairwise
                    ))

            except Exception as e:
                print("[!] Error: %s" % e)
                return 1

    class WpaEapCnf:

        import config
        from core.templates.hostapd import hostapd_wifi3_cnf

        path = config.hostapd_conf_full
        template = hostapd_wifi3_cnf.hostapd_wifi3_wpa_eap_cnf

        @classmethod
        def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            beacon_interval=None,
            hw_mode=None,
            channel=None,
            country_code=None,
            ieee80211d=None,
            ieee80211h=None,
            bssid=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            ap_isolate=None,
            essid_mask=None,
            wpa=None,
            wpa_pairwise=None,
            rsn_pairwise=None,
            ieee8021x=None,
            eapol_version=None,
            eapol_workaround=None,
            own_ip_addr=None,
            auth_server_addr=None,
            auth_server_port=None,
            auth_server_shared_secret=None,
            acct_server_addr=None,
            acct_server_port=None,
            acct_server_shared_secret=None,
            eap_user_file=None,
            ca_pem=None,
            server_pem=None,
            private_key=None,
            private_key_passwd=None,
            dh_file=None
        ):

            assert driver is not None
            assert interface is not None
            assert ssid is not None
            assert beacon_interval is not None
            assert hw_mode is not None
            assert channel is not None
            assert country_code is not None
            assert ieee80211d is not None
            assert ieee80211h is not None
            assert bssid is not None
            assert macaddr_acl is not None
            assert macaddr_accept_file is not None
            assert macaddr_deny_file is not None
            assert ap_isolate is not None
            assert essid_mask is not None
            assert wpa is not None
            assert wpa_pairwise is not None
            assert rsn_pairwise is not None
            assert ieee8021x is not None
            assert eapol_version is not None
            assert eapol_workaround is not None
            assert own_ip_addr is not None
            assert auth_server_addr is not None
            assert auth_server_port is not None
            assert auth_server_shared_secret is not None
            assert acct_server_addr is not None
            assert acct_server_port is not None
            assert acct_server_shared_secret is not None
            assert eap_user_file is not None
            assert ca_pem is not None
            assert server_pem is not None
            assert private_key is not None
            assert private_key_passwd is not None
            assert dh_file is not None

            try:
                print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)

                with open(cls.path, 'w') as fd:
                    fd.write(cls.template.format(
                        driver=driver,
                        interface=interface,
                        ssid=ssid,
                        beacon_interval=beacon_interval,
                        hw_mode=hw_mode,
                        channel=channel,
                        country_code=country_code,
                        ieee80211d=ieee80211d,
                        ieee80211h=ieee80211h,
                        bssid=bssid,
                        macaddr_acl=macaddr_acl,
                        macaddr_accept_file=macaddr_accept_file,
                        macaddr_deny_file=macaddr_deny_file,
                        ap_isolate=ap_isolate,
                        essid_mask=essid_mask,
                        wpa=wpa,
                        wpa_pairwise=wpa_pairwise,
                        rsn_pairwise=rsn_pairwise,
                        ieee8021x=ieee8021x,
                        eapol_version=eapol_version,
                        eapol_workaround=eapol_workaround,
                        own_ip_addr=own_ip_addr,
                        auth_server_addr=auth_server_addr,
                        auth_server_port=auth_server_port,
                        auth_server_shared_secret=auth_server_shared_secret,
                        acct_server_addr=acct_server_addr,
                        acct_server_port=acct_server_port,
                        acct_server_shared_secret=acct_server_shared_secret,
                        eap_user_file=eap_user_file,
                        ca_pem=ca_pem,
                        server_pem=server_pem,
                        private_key=private_key,
                        private_key_passwd=private_key_passwd, # unused
                        dh_file=dh_file,
                    ))

            except Exception as e:
                print("[!] Error: %s" % e)
                return 1

class HostapdWifi4:

    class OpenCnf:

        import config
        from core.templates.hostapd import hostapd_wifi4_cnf

        path = config.hostapd_conf_full
        template = hostapd_wifi4_cnf.hostapd_wifi4_open_cnf

        @classmethod
        def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            beacon_interval=None,
            hw_mode=None,
            channel=None,
            country_code=None,
            ieee80211d=None,
            ieee80211h=None,
            bssid=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            ap_isolate=None,
            essid_mask=None,
            require_ht=None,
            ieee80211n=None,
            wmm_enabled=None,
            ht_capab=None,
            wmm_ac_bk_cwmin=None,
            wmm_ac_bk_cwmax=None,
            wmm_ac_bk_aifs=None,
            wmm_ac_bk_txop_limit=None,
            wmm_ac_bk_acm=None,
            wmm_ac_be_aifs=None,
            wmm_ac_be_cwmin=None,
            wmm_ac_be_cwmax=None,
            wmm_ac_be_txop_limit=None,
            wmm_ac_be_acm=None,
            wmm_ac_vi_aifs=None,
            wmm_ac_vi_cwmin=None,
            wmm_ac_vi_cwmax=None,
            wmm_ac_vi_txop_limit=None,
            wmm_ac_vi_acm=None,
            wmm_ac_vo_aifs=None,
            wmm_ac_vo_cwmin=None,
            wmm_ac_vo_cwmax=None,
            wmm_ac_vo_txop_limit=None,
            wmm_ac_vo_acm=None,
            tx_queue_data3_aifs=None,
            tx_queue_data3_cwmin=None,
            tx_queue_data3_cwmax=None,
            tx_queue_data3_burst=None,
            tx_queue_data2_aifs=None,
            tx_queue_data2_cwmin=None,
            tx_queue_data2_cwmax=None,
            tx_queue_data2_burst=None,
            tx_queue_data1_aifs=None,
            tx_queue_data1_cwmin=None,
            tx_queue_data1_cwmax=None,
            tx_queue_data1_burst=None,
            tx_queue_data0_aifs=None,
            tx_queue_data0_cwmin=None,
            tx_queue_data0_cwmax=None,
            tx_queue_data0_burst=None,
        ):

            assert driver is not None
            assert interface is not None
            assert ssid is not None
            assert beacon_interval is not None
            assert hw_mode is not None
            assert channel is not None
            assert country_code is not None
            assert ieee80211d is not None
            assert ieee80211h is not None
            assert bssid is not None
            assert macaddr_acl is not None
            assert macaddr_accept_file is not None
            assert macaddr_deny_file is not None
            assert ap_isolate is not None
            assert essid_mask is not None
            assert require_ht is not None
            assert ieee80211n is not None
            assert wmm_enabled is not None
            assert ht_capab is not None
            assert wmm_ac_bk_cwmin is not None
            assert wmm_ac_bk_cwmax is not None
            assert wmm_ac_bk_aifs is not None
            assert wmm_ac_bk_txop_limit is not None
            assert wmm_ac_bk_acm is not None
            assert wmm_ac_be_aifs is not None
            assert wmm_ac_be_cwmin is not None
            assert wmm_ac_be_cwmax is not None
            assert wmm_ac_be_txop_limit is not None
            assert wmm_ac_be_acm is not None
            assert wmm_ac_vi_aifs is not None
            assert wmm_ac_vi_cwmin is not None
            assert wmm_ac_vi_cwmax is not None
            assert wmm_ac_vi_txop_limit is not None
            assert wmm_ac_vi_acm is not None
            assert wmm_ac_vo_aifs is not None
            assert wmm_ac_vo_cwmin is not None
            assert wmm_ac_vo_cwmax is not None
            assert wmm_ac_vo_txop_limit is not None
            assert wmm_ac_vo_acm is not None
            assert tx_queue_data3_aifs is not None
            assert tx_queue_data3_cwmin is not None
            assert tx_queue_data3_cwmax is not None
            assert tx_queue_data3_burst is not None
            assert tx_queue_data2_aifs is not None
            assert tx_queue_data2_cwmin is not None
            assert tx_queue_data2_cwmax is not None
            assert tx_queue_data2_burst is not None
            assert tx_queue_data1_aifs is not None
            assert tx_queue_data1_cwmin is not None
            assert tx_queue_data1_cwmax is not None
            assert tx_queue_data1_burst is not None
            assert tx_queue_data0_aifs is not None
            assert tx_queue_data0_cwmin is not None
            assert tx_queue_data0_cwmax is not None
            assert tx_queue_data0_burst is not None

            try:
                print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)

                with open(cls.path, 'w') as fd:
                    fd.write(cls.template.format(
                        driver=driver,
                        interface=interface,
                        ssid=ssid,
                        beacon_interval=beacon_interval,
                        hw_mode=hw_mode,
                        channel=channel,
                        country_code=country_code,
                        ieee80211d=ieee80211d,
                        ieee80211h=ieee80211h,
                        bssid=bssid,
                        macaddr_acl=macaddr_acl,
                        macaddr_accept_file=macaddr_accept_file,
                        macaddr_deny_file=macaddr_deny_file,
                        ap_isolate=ap_isolate,
                        essid_mask=essid_mask,
                        require_ht=require_ht,
                        ieee80211n=ieee80211n,
                        wmm_enabled=wmm_enabled,
                        ht_capab=ht_capab,
                        wmm_ac_bk_cwmin=wmm_ac_bk_cwmin,
                        wmm_ac_bk_cwmax=wmm_ac_bk_cwmax,
                        wmm_ac_bk_aifs=wmm_ac_bk_aifs,
                        wmm_ac_bk_txop_limit=wmm_ac_bk_txop_limit,
                        wmm_ac_bk_acm=wmm_ac_bk_acm,
                        wmm_ac_be_aifs=wmm_ac_be_aifs,
                        wmm_ac_be_cwmin=wmm_ac_be_cwmin,
                        wmm_ac_be_cwmax=wmm_ac_be_cwmax,
                        wmm_ac_be_txop_limit=wmm_ac_be_txop_limit,
                        wmm_ac_be_acm=wmm_ac_be_acm,
                        wmm_ac_vi_aifs=wmm_ac_vi_aifs,
                        wmm_ac_vi_cwmin=wmm_ac_vi_cwmin,
                        wmm_ac_vi_cwmax=wmm_ac_vi_cwmax,
                        wmm_ac_vi_txop_limit=wmm_ac_vi_txop_limit,
                        wmm_ac_vi_acm=wmm_ac_vi_acm,
                        wmm_ac_vo_aifs=wmm_ac_vo_aifs,
                        wmm_ac_vo_cwmin=wmm_ac_vo_cwmin,
                        wmm_ac_vo_cwmax=wmm_ac_vo_cwmax,
                        wmm_ac_vo_txop_limit=wmm_ac_vo_txop_limit,
                        wmm_ac_vo_acm=wmm_ac_vo_acm,
                        tx_queue_data3_aifs=tx_queue_data3_aifs,
                        tx_queue_data3_cwmin=tx_queue_data3_cwmin,
                        tx_queue_data3_cwmax=tx_queue_data3_cwmax,
                        tx_queue_data3_burst=tx_queue_data3_burst,
                        tx_queue_data2_aifs=tx_queue_data2_aifs,
                        tx_queue_data2_cwmin=tx_queue_data2_cwmin,
                        tx_queue_data2_cwmax=tx_queue_data2_cwmax,
                        tx_queue_data2_burst=tx_queue_data2_burst,
                        tx_queue_data1_aifs=tx_queue_data1_aifs,
                        tx_queue_data1_cwmin=tx_queue_data1_cwmin,
                        tx_queue_data1_cwmax=tx_queue_data1_cwmax,
                        tx_queue_data1_burst=tx_queue_data1_burst,
                        tx_queue_data0_aifs=tx_queue_data0_aifs,
                        tx_queue_data0_cwmin=tx_queue_data0_cwmin,
                        tx_queue_data0_cwmax=tx_queue_data0_cwmax,
                        tx_queue_data0_burst=tx_queue_data0_burst,
                    ))

            except Exception as e:
                print("[!] Error: %s" % e)
                return 1

    class WepCnf:

        import config
        from core.templates.hostapd import hostapd_wifi4_cnf

        path = config.hostapd_conf_full
        template = hostapd_wifi4_cnf.hostapd_wifi4_wep_cnf

        @classmethod
        def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            beacon_interval=None,
            hw_mode=None,
            channel=None,
            country_code=None,
            ieee80211d=None,
            ieee80211h=None,
            bssid=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            ap_isolate=None,
            essid_mask=None,
            require_ht=None,
            ieee80211n=None,
            wmm_enabled=None,
            ht_capab=None,
            wmm_ac_bk_cwmin=None,
            wmm_ac_bk_cwmax=None,
            wmm_ac_bk_aifs=None,
            wmm_ac_bk_txop_limit=None,
            wmm_ac_bk_acm=None,
            wmm_ac_be_aifs=None,
            wmm_ac_be_cwmin=None,
            wmm_ac_be_cwmax=None,
            wmm_ac_be_txop_limit=None,
            wmm_ac_be_acm=None,
            wmm_ac_vi_aifs=None,
            wmm_ac_vi_cwmin=None,
            wmm_ac_vi_cwmax=None,
            wmm_ac_vi_txop_limit=None,
            wmm_ac_vi_acm=None,
            wmm_ac_vo_aifs=None,
            wmm_ac_vo_cwmin=None,
            wmm_ac_vo_cwmax=None,
            wmm_ac_vo_txop_limit=None,
            wmm_ac_vo_acm=None,
            tx_queue_data3_aifs=None,
            tx_queue_data3_cwmin=None,
            tx_queue_data3_cwmax=None,
            tx_queue_data3_burst=None,
            tx_queue_data2_aifs=None,
            tx_queue_data2_cwmin=None,
            tx_queue_data2_cwmax=None,
            tx_queue_data2_burst=None,
            tx_queue_data1_aifs=None,
            tx_queue_data1_cwmin=None,
            tx_queue_data1_cwmax=None,
            tx_queue_data1_burst=None,
            tx_queue_data0_aifs=None,
            tx_queue_data0_cwmin=None,
            tx_queue_data0_cwmax=None,
            tx_queue_data0_burst=None,
            wep_default_key=None,
            wep_key=None
        ):

            assert driver is not None
            assert interface is not None
            assert ssid is not None
            assert beacon_interval is not None
            assert hw_mode is not None
            assert channel is not None
            assert country_code is not None
            assert ieee80211d is not None
            assert ieee80211h is not None
            assert bssid is not None
            assert macaddr_acl is not None
            assert macaddr_accept_file is not None
            assert macaddr_deny_file is not None
            assert ap_isolate is not None
            assert essid_mask is not None
            assert require_ht is not None
            assert ieee80211n is not None
            assert wmm_enabled is not None
            assert ht_capab is not None
            assert wmm_ac_bk_cwmin is not None
            assert wmm_ac_bk_cwmax is not None
            assert wmm_ac_bk_aifs is not None
            assert wmm_ac_bk_txop_limit is not None
            assert wmm_ac_bk_acm is not None
            assert wmm_ac_be_aifs is not None
            assert wmm_ac_be_cwmin is not None
            assert wmm_ac_be_cwmax is not None
            assert wmm_ac_be_txop_limit is not None
            assert wmm_ac_be_acm is not None
            assert wmm_ac_vi_aifs is not None
            assert wmm_ac_vi_cwmin is not None
            assert wmm_ac_vi_cwmax is not None
            assert wmm_ac_vi_txop_limit is not None
            assert wmm_ac_vi_acm is not None
            assert wmm_ac_vo_aifs is not None
            assert wmm_ac_vo_cwmin is not None
            assert wmm_ac_vo_cwmax is not None
            assert wmm_ac_vo_txop_limit is not None
            assert wmm_ac_vo_acm is not None
            assert tx_queue_data3_aifs is not None
            assert tx_queue_data3_cwmin is not None
            assert tx_queue_data3_cwmax is not None
            assert tx_queue_data3_burst is not None
            assert tx_queue_data2_aifs is not None
            assert tx_queue_data2_cwmin is not None
            assert tx_queue_data2_cwmax is not None
            assert tx_queue_data2_burst is not None
            assert tx_queue_data1_aifs is not None
            assert tx_queue_data1_cwmin is not None
            assert tx_queue_data1_cwmax is not None
            assert tx_queue_data1_burst is not None
            assert tx_queue_data0_aifs is not None
            assert tx_queue_data0_cwmin is not None
            assert tx_queue_data0_cwmax is not None
            assert tx_queue_data0_burst is not None
            assert wep_default_key is not None
            assert wep_key is not None

            try:
                print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)

                with open(cls.path, 'w') as fd:
                    fd.write(cls.template.format(
                        driver=driver,
                        interface=interface,
                        ssid=ssid,
                        beacon_interval=beacon_interval,
                        hw_mode=hw_mode,
                        channel=channel,
                        country_code=country_code,
                        ieee80211d=ieee80211d,
                        ieee80211h=ieee80211h,
                        bssid=bssid,
                        macaddr_acl=macaddr_acl,
                        macaddr_accept_file=macaddr_accept_file,
                        macaddr_deny_file=macaddr_deny_file,
                        ap_isolate=ap_isolate,
                        essid_mask=essid_mask,
                        require_ht=require_ht,
                        ieee80211n=ieee80211n,
                        wmm_enabled=wmm_enabled,
                        ht_capab=ht_capab,
                        wmm_ac_bk_cwmin=wmm_ac_bk_cwmin,
                        wmm_ac_bk_cwmax=wmm_ac_bk_cwmax,
                        wmm_ac_bk_aifs=wmm_ac_bk_aifs,
                        wmm_ac_bk_txop_limit=wmm_ac_bk_txop_limit,
                        wmm_ac_bk_acm=wmm_ac_bk_acm,
                        wmm_ac_be_aifs=wmm_ac_be_aifs,
                        wmm_ac_be_cwmin=wmm_ac_be_cwmin,
                        wmm_ac_be_cwmax=wmm_ac_be_cwmax,
                        wmm_ac_be_txop_limit=wmm_ac_be_txop_limit,
                        wmm_ac_be_acm=wmm_ac_be_acm,
                        wmm_ac_vi_aifs=wmm_ac_vi_aifs,
                        wmm_ac_vi_cwmin=wmm_ac_vi_cwmin,
                        wmm_ac_vi_cwmax=wmm_ac_vi_cwmax,
                        wmm_ac_vi_txop_limit=wmm_ac_vi_txop_limit,
                        wmm_ac_vi_acm=wmm_ac_vi_acm,
                        wmm_ac_vo_aifs=wmm_ac_vo_aifs,
                        wmm_ac_vo_cwmin=wmm_ac_vo_cwmin,
                        wmm_ac_vo_cwmax=wmm_ac_vo_cwmax,
                        wmm_ac_vo_txop_limit=wmm_ac_vo_txop_limit,
                        wmm_ac_vo_acm=wmm_ac_vo_acm,
                        tx_queue_data3_aifs=tx_queue_data3_aifs,
                        tx_queue_data3_cwmin=tx_queue_data3_cwmin,
                        tx_queue_data3_cwmax=tx_queue_data3_cwmax,
                        tx_queue_data3_burst=tx_queue_data3_burst,
                        tx_queue_data2_aifs=tx_queue_data2_aifs,
                        tx_queue_data2_cwmin=tx_queue_data2_cwmin,
                        tx_queue_data2_cwmax=tx_queue_data2_cwmax,
                        tx_queue_data2_burst=tx_queue_data2_burst,
                        tx_queue_data1_aifs=tx_queue_data1_aifs,
                        tx_queue_data1_cwmin=tx_queue_data1_cwmin,
                        tx_queue_data1_cwmax=tx_queue_data1_cwmax,
                        tx_queue_data1_burst=tx_queue_data1_burst,
                        tx_queue_data0_aifs=tx_queue_data0_aifs,
                        tx_queue_data0_cwmin=tx_queue_data0_cwmin,
                        tx_queue_data0_cwmax=tx_queue_data0_cwmax,
                        tx_queue_data0_burst=tx_queue_data0_burst,
                        wep_key=wep_key,
                        wep_default_key=wep_default_key
                    ))

            except Exception as e:
                print("[!] Error: %s" % e)
                return 1

    class WpaCnf:

        import config
        from core.templates.hostapd import hostapd_wifi4_cnf

        path = config.hostapd_conf_full
        template = hostapd_wifi4_cnf.hostapd_wifi4_wpa_cnf

        @classmethod
        def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            beacon_interval=None,
            hw_mode=None,
            channel=None,
            country_code=None,
            ieee80211d=None,
            ieee80211h=None,
            bssid=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            ap_isolate=None,
            essid_mask=None,
            require_ht=None,
            ieee80211n=None,
            wmm_enabled=None,
            ht_capab=None,
            wmm_ac_bk_cwmin=None,
            wmm_ac_bk_cwmax=None,
            wmm_ac_bk_aifs=None,
            wmm_ac_bk_txop_limit=None,
            wmm_ac_bk_acm=None,
            wmm_ac_be_aifs=None,
            wmm_ac_be_cwmin=None,
            wmm_ac_be_cwmax=None,
            wmm_ac_be_txop_limit=None,
            wmm_ac_be_acm=None,
            wmm_ac_vi_aifs=None,
            wmm_ac_vi_cwmin=None,
            wmm_ac_vi_cwmax=None,
            wmm_ac_vi_txop_limit=None,
            wmm_ac_vi_acm=None,
            wmm_ac_vo_aifs=None,
            wmm_ac_vo_cwmin=None,
            wmm_ac_vo_cwmax=None,
            wmm_ac_vo_txop_limit=None,
            wmm_ac_vo_acm=None,
            tx_queue_data3_aifs=None,
            tx_queue_data3_cwmin=None,
            tx_queue_data3_cwmax=None,
            tx_queue_data3_burst=None,
            tx_queue_data2_aifs=None,
            tx_queue_data2_cwmin=None,
            tx_queue_data2_cwmax=None,
            tx_queue_data2_burst=None,
            tx_queue_data1_aifs=None,
            tx_queue_data1_cwmin=None,
            tx_queue_data1_cwmax=None,
            tx_queue_data1_burst=None,
            tx_queue_data0_aifs=None,
            tx_queue_data0_cwmin=None,
            tx_queue_data0_cwmax=None,
            tx_queue_data0_burst=None,
            wpa=None,
            wpa_passphrase=None,
            wpa_pairwise=None,
            rsn_pairwise=None,
        ):

            assert driver is not None
            assert interface is not None
            assert ssid is not None
            assert beacon_interval is not None
            assert hw_mode is not None
            assert channel is not None
            assert country_code is not None
            assert ieee80211d is not None
            assert ieee80211h is not None
            assert bssid is not None
            assert macaddr_acl is not None
            assert macaddr_accept_file is not None
            assert macaddr_deny_file is not None
            assert ap_isolate is not None
            assert essid_mask is not None
            assert require_ht is not None
            assert ieee80211n is not None
            assert wmm_enabled is not None
            assert ht_capab is not None
            assert wmm_ac_bk_cwmin is not None
            assert wmm_ac_bk_cwmax is not None
            assert wmm_ac_bk_aifs is not None
            assert wmm_ac_bk_txop_limit is not None
            assert wmm_ac_bk_acm is not None
            assert wmm_ac_be_aifs is not None
            assert wmm_ac_be_cwmin is not None
            assert wmm_ac_be_cwmax is not None
            assert wmm_ac_be_txop_limit is not None
            assert wmm_ac_be_acm is not None
            assert wmm_ac_vi_aifs is not None
            assert wmm_ac_vi_cwmin is not None
            assert wmm_ac_vi_cwmax is not None
            assert wmm_ac_vi_txop_limit is not None
            assert wmm_ac_vi_acm is not None
            assert wmm_ac_vo_aifs is not None
            assert wmm_ac_vo_cwmin is not None
            assert wmm_ac_vo_cwmax is not None
            assert wmm_ac_vo_txop_limit is not None
            assert wmm_ac_vo_acm is not None
            assert tx_queue_data3_aifs is not None
            assert tx_queue_data3_cwmin is not None
            assert tx_queue_data3_cwmax is not None
            assert tx_queue_data3_burst is not None
            assert tx_queue_data2_aifs is not None
            assert tx_queue_data2_cwmin is not None
            assert tx_queue_data2_cwmax is not None
            assert tx_queue_data2_burst is not None
            assert tx_queue_data1_aifs is not None
            assert tx_queue_data1_cwmin is not None
            assert tx_queue_data1_cwmax is not None
            assert tx_queue_data1_burst is not None
            assert tx_queue_data0_aifs is not None
            assert tx_queue_data0_cwmin is not None
            assert tx_queue_data0_cwmax is not None
            assert tx_queue_data0_burst is not None
            assert wpa is not None
            assert wpa_passphrase is not None
            assert wpa_pairwise is not None
            assert rsn_pairwise is not None

            try:
                print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)

                with open(cls.path, 'w') as fd:
                    fd.write(cls.template.format(
                        driver=driver,
                        interface=interface,
                        ssid=ssid,
                        beacon_interval=beacon_interval,
                        hw_mode=hw_mode,
                        channel=channel,
                        country_code=country_code,
                        ieee80211d=ieee80211d,
                        ieee80211h=ieee80211h,
                        bssid=bssid,
                        macaddr_acl=macaddr_acl,
                        macaddr_accept_file=macaddr_accept_file,
                        macaddr_deny_file=macaddr_deny_file,
                        ap_isolate=ap_isolate,
                        essid_mask=essid_mask,
                        require_ht=require_ht,
                        ieee80211n=ieee80211n,
                        wmm_enabled=wmm_enabled,
                        ht_capab=ht_capab,
                        wmm_ac_bk_cwmin=wmm_ac_bk_cwmin,
                        wmm_ac_bk_cwmax=wmm_ac_bk_cwmax,
                        wmm_ac_bk_aifs=wmm_ac_bk_aifs,
                        wmm_ac_bk_txop_limit=wmm_ac_bk_txop_limit,
                        wmm_ac_bk_acm=wmm_ac_bk_acm,
                        wmm_ac_be_aifs=wmm_ac_be_aifs,
                        wmm_ac_be_cwmin=wmm_ac_be_cwmin,
                        wmm_ac_be_cwmax=wmm_ac_be_cwmax,
                        wmm_ac_be_txop_limit=wmm_ac_be_txop_limit,
                        wmm_ac_be_acm=wmm_ac_be_acm,
                        wmm_ac_vi_aifs=wmm_ac_vi_aifs,
                        wmm_ac_vi_cwmin=wmm_ac_vi_cwmin,
                        wmm_ac_vi_cwmax=wmm_ac_vi_cwmax,
                        wmm_ac_vi_txop_limit=wmm_ac_vi_txop_limit,
                        wmm_ac_vi_acm=wmm_ac_vi_acm,
                        wmm_ac_vo_aifs=wmm_ac_vo_aifs,
                        wmm_ac_vo_cwmin=wmm_ac_vo_cwmin,
                        wmm_ac_vo_cwmax=wmm_ac_vo_cwmax,
                        wmm_ac_vo_txop_limit=wmm_ac_vo_txop_limit,
                        wmm_ac_vo_acm=wmm_ac_vo_acm,
                        tx_queue_data3_aifs=tx_queue_data3_aifs,
                        tx_queue_data3_cwmin=tx_queue_data3_cwmin,
                        tx_queue_data3_cwmax=tx_queue_data3_cwmax,
                        tx_queue_data3_burst=tx_queue_data3_burst,
                        tx_queue_data2_aifs=tx_queue_data2_aifs,
                        tx_queue_data2_cwmin=tx_queue_data2_cwmin,
                        tx_queue_data2_cwmax=tx_queue_data2_cwmax,
                        tx_queue_data2_burst=tx_queue_data2_burst,
                        tx_queue_data1_aifs=tx_queue_data1_aifs,
                        tx_queue_data1_cwmin=tx_queue_data1_cwmin,
                        tx_queue_data1_cwmax=tx_queue_data1_cwmax,
                        tx_queue_data1_burst=tx_queue_data1_burst,
                        tx_queue_data0_aifs=tx_queue_data0_aifs,
                        tx_queue_data0_cwmin=tx_queue_data0_cwmin,
                        tx_queue_data0_cwmax=tx_queue_data0_cwmax,
                        tx_queue_data0_burst=tx_queue_data0_burst,
                        wpa=wpa,
                        wpa_passphrase=wpa_passphrase,
                        wpa_pairwise=wpa_pairwise,
                        rsn_pairwise=rsn_pairwise
                    ))

            except Exception as e:
                print("[!] Error: %s" % e)
                return 1

    class WpaEapCnf:

        import config
        from core.templates.hostapd import hostapd_wifi4_cnf

        path = config.hostapd_conf_full
        template = hostapd_wifi4_cnf.hostapd_wifi4_wpa_eap_cnf

        @classmethod
        def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            beacon_interval=None,
            hw_mode=None,
            channel=None,
            country_code=None,
            ieee80211d=None,
            ieee80211h=None,
            bssid=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            ap_isolate=None,
            essid_mask=None,
            require_ht=None,
            ieee80211n=None,
            wmm_enabled=None,
            ht_capab=None,
            wmm_ac_bk_cwmin=None,
            wmm_ac_bk_cwmax=None,
            wmm_ac_bk_aifs=None,
            wmm_ac_bk_txop_limit=None,
            wmm_ac_bk_acm=None,
            wmm_ac_be_aifs=None,
            wmm_ac_be_cwmin=None,
            wmm_ac_be_cwmax=None,
            wmm_ac_be_txop_limit=None,
            wmm_ac_be_acm=None,
            wmm_ac_vi_aifs=None,
            wmm_ac_vi_cwmin=None,
            wmm_ac_vi_cwmax=None,
            wmm_ac_vi_txop_limit=None,
            wmm_ac_vi_acm=None,
            wmm_ac_vo_aifs=None,
            wmm_ac_vo_cwmin=None,
            wmm_ac_vo_cwmax=None,
            wmm_ac_vo_txop_limit=None,
            wmm_ac_vo_acm=None,
            tx_queue_data3_aifs=None,
            tx_queue_data3_cwmin=None,
            tx_queue_data3_cwmax=None,
            tx_queue_data3_burst=None,
            tx_queue_data2_aifs=None,
            tx_queue_data2_cwmin=None,
            tx_queue_data2_cwmax=None,
            tx_queue_data2_burst=None,
            tx_queue_data1_aifs=None,
            tx_queue_data1_cwmin=None,
            tx_queue_data1_cwmax=None,
            tx_queue_data1_burst=None,
            tx_queue_data0_aifs=None,
            tx_queue_data0_cwmin=None,
            tx_queue_data0_cwmax=None,
            tx_queue_data0_burst=None,
            wpa=None,
            wpa_pairwise=None,
            rsn_pairwise=None,
            ieee8021x=None,
            eapol_version=None,
            eapol_workaround=None,
            own_ip_addr=None,
            auth_server_addr=None,
            auth_server_port=None,
            auth_server_shared_secret=None,
            acct_server_addr=None,
            acct_server_port=None,
            acct_server_shared_secret=None,
            eap_user_file=None,
            ca_pem=None,
            server_pem=None,
            private_key=None,
            private_key_passwd=None,
            dh_file=None
        ):

            assert driver is not None
            assert interface is not None
            assert ssid is not None
            assert beacon_interval is not None
            assert hw_mode is not None
            assert channel is not None
            assert country_code is not None
            assert ieee80211d is not None
            assert ieee80211h is not None
            assert bssid is not None
            assert macaddr_acl is not None
            assert macaddr_accept_file is not None
            assert macaddr_deny_file is not None
            assert ap_isolate is not None
            assert essid_mask is not None
            assert require_ht is not None
            assert ieee80211n is not None
            assert wmm_enabled is not None
            assert ht_capab is not None
            assert wmm_ac_bk_cwmin is not None
            assert wmm_ac_bk_cwmax is not None
            assert wmm_ac_bk_aifs is not None
            assert wmm_ac_bk_txop_limit is not None
            assert wmm_ac_bk_acm is not None
            assert wmm_ac_be_aifs is not None
            assert wmm_ac_be_cwmin is not None
            assert wmm_ac_be_cwmax is not None
            assert wmm_ac_be_txop_limit is not None
            assert wmm_ac_be_acm is not None
            assert wmm_ac_vi_aifs is not None
            assert wmm_ac_vi_cwmin is not None
            assert wmm_ac_vi_cwmax is not None
            assert wmm_ac_vi_txop_limit is not None
            assert wmm_ac_vi_acm is not None
            assert wmm_ac_vo_aifs is not None
            assert wmm_ac_vo_cwmin is not None
            assert wmm_ac_vo_cwmax is not None
            assert wmm_ac_vo_txop_limit is not None
            assert wmm_ac_vo_acm is not None
            assert tx_queue_data3_aifs is not None
            assert tx_queue_data3_cwmin is not None
            assert tx_queue_data3_cwmax is not None
            assert tx_queue_data3_burst is not None
            assert tx_queue_data2_aifs is not None
            assert tx_queue_data2_cwmin is not None
            assert tx_queue_data2_cwmax is not None
            assert tx_queue_data2_burst is not None
            assert tx_queue_data1_aifs is not None
            assert tx_queue_data1_cwmin is not None
            assert tx_queue_data1_cwmax is not None
            assert tx_queue_data1_burst is not None
            assert tx_queue_data0_aifs is not None
            assert tx_queue_data0_cwmin is not None
            assert tx_queue_data0_cwmax is not None
            assert tx_queue_data0_burst is not None
            assert wpa is not None
            assert wpa_pairwise is not None
            assert rsn_pairwise is not None
            assert ieee8021x is not None
            assert eapol_version is not None
            assert eapol_workaround is not None
            assert own_ip_addr is not None
            assert auth_server_addr is not None
            assert auth_server_port is not None
            assert auth_server_shared_secret is not None
            assert acct_server_addr is not None
            assert acct_server_port is not None
            assert acct_server_shared_secret is not None
            assert eap_user_file is not None
            assert ca_pem is not None
            assert server_pem is not None
            assert private_key is not None
            assert private_key_passwd is not None
            assert dh_file is not None

            try:
                print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)

                with open(cls.path, 'w') as fd:
                    fd.write(cls.template.format(
                        driver=driver,
                        interface=interface,
                        ssid=ssid,
                        beacon_interval=beacon_interval,
                        hw_mode=hw_mode,
                        channel=channel,
                        country_code=country_code,
                        ieee80211d=ieee80211d,
                        ieee80211h=ieee80211h,
                        bssid=bssid,
                        macaddr_acl=macaddr_acl,
                        macaddr_accept_file=macaddr_accept_file,
                        macaddr_deny_file=macaddr_deny_file,
                        ap_isolate=ap_isolate,
                        essid_mask=essid_mask,
                        require_ht=require_ht,
                        ieee80211n=ieee80211n,
                        wmm_enabled=wmm_enabled,
                        ht_capab=ht_capab,
                        wmm_ac_bk_cwmin=wmm_ac_bk_cwmin,
                        wmm_ac_bk_cwmax=wmm_ac_bk_cwmax,
                        wmm_ac_bk_aifs=wmm_ac_bk_aifs,
                        wmm_ac_bk_txop_limit=wmm_ac_bk_txop_limit,
                        wmm_ac_bk_acm=wmm_ac_bk_acm,
                        wmm_ac_be_aifs=wmm_ac_be_aifs,
                        wmm_ac_be_cwmin=wmm_ac_be_cwmin,
                        wmm_ac_be_cwmax=wmm_ac_be_cwmax,
                        wmm_ac_be_txop_limit=wmm_ac_be_txop_limit,
                        wmm_ac_be_acm=wmm_ac_be_acm,
                        wmm_ac_vi_aifs=wmm_ac_vi_aifs,
                        wmm_ac_vi_cwmin=wmm_ac_vi_cwmin,
                        wmm_ac_vi_cwmax=wmm_ac_vi_cwmax,
                        wmm_ac_vi_txop_limit=wmm_ac_vi_txop_limit,
                        wmm_ac_vi_acm=wmm_ac_vi_acm,
                        wmm_ac_vo_aifs=wmm_ac_vo_aifs,
                        wmm_ac_vo_cwmin=wmm_ac_vo_cwmin,
                        wmm_ac_vo_cwmax=wmm_ac_vo_cwmax,
                        wmm_ac_vo_txop_limit=wmm_ac_vo_txop_limit,
                        wmm_ac_vo_acm=wmm_ac_vo_acm,
                        tx_queue_data3_aifs=tx_queue_data3_aifs,
                        tx_queue_data3_cwmin=tx_queue_data3_cwmin,
                        tx_queue_data3_cwmax=tx_queue_data3_cwmax,
                        tx_queue_data3_burst=tx_queue_data3_burst,
                        tx_queue_data2_aifs=tx_queue_data2_aifs,
                        tx_queue_data2_cwmin=tx_queue_data2_cwmin,
                        tx_queue_data2_cwmax=tx_queue_data2_cwmax,
                        tx_queue_data2_burst=tx_queue_data2_burst,
                        tx_queue_data1_aifs=tx_queue_data1_aifs,
                        tx_queue_data1_cwmin=tx_queue_data1_cwmin,
                        tx_queue_data1_cwmax=tx_queue_data1_cwmax,
                        tx_queue_data1_burst=tx_queue_data1_burst,
                        tx_queue_data0_aifs=tx_queue_data0_aifs,
                        tx_queue_data0_cwmin=tx_queue_data0_cwmin,
                        tx_queue_data0_cwmax=tx_queue_data0_cwmax,
                        tx_queue_data0_burst=tx_queue_data0_burst,
                        wpa=wpa,
                        wpa_pairwise=wpa_pairwise,
                        rsn_pairwise=rsn_pairwise,
                        ieee8021x=ieee8021x,
                        eapol_version=eapol_version,
                        eapol_workaround=eapol_workaround,
                        own_ip_addr=own_ip_addr,
                        auth_server_addr=auth_server_addr,
                        auth_server_port=auth_server_port,
                        auth_server_shared_secret=auth_server_shared_secret,
                        acct_server_addr=acct_server_addr,
                        acct_server_port=acct_server_port,
                        acct_server_shared_secret=acct_server_shared_secret,
                        eap_user_file=eap_user_file,
                        ca_pem=ca_pem,
                        server_pem=server_pem,
                        private_key=private_key,
                        private_key_passwd=private_key_passwd, # unused
                        dh_file=dh_file,
                    ))

            except Exception as e:
                print("[!] Error: %s" % e)
                return 1,

class HostapdWifi5:

    class OpenCnf:

        import config
        from core.templates.hostapd import hostapd_wifi5_cnf

        path = config.hostapd_conf_full
        template = hostapd_wifi5_cnf.hostapd_wifi5_open_cnf

        @classmethod
        def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            beacon_interval=None,
            hw_mode=None,
            channel=None,
            country_code=None,
            ieee80211d=None,
            ieee80211h=None,
            bssid=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            ap_isolate=None,
            essid_mask=None,
            require_ht=None,
            ieee80211n=None,
            wmm_enabled=None,
            ht_capab=None,
            wmm_ac_bk_cwmin=None,
            wmm_ac_bk_cwmax=None,
            wmm_ac_bk_aifs=None,
            wmm_ac_bk_txop_limit=None,
            wmm_ac_bk_acm=None,
            wmm_ac_be_aifs=None,
            wmm_ac_be_cwmin=None,
            wmm_ac_be_cwmax=None,
            wmm_ac_be_txop_limit=None,
            wmm_ac_be_acm=None,
            wmm_ac_vi_aifs=None,
            wmm_ac_vi_cwmin=None,
            wmm_ac_vi_cwmax=None,
            wmm_ac_vi_txop_limit=None,
            wmm_ac_vi_acm=None,
            wmm_ac_vo_aifs=None,
            wmm_ac_vo_cwmin=None,
            wmm_ac_vo_cwmax=None,
            wmm_ac_vo_txop_limit=None,
            wmm_ac_vo_acm=None,
            tx_queue_data3_aifs=None,
            tx_queue_data3_cwmin=None,
            tx_queue_data3_cwmax=None,
            tx_queue_data3_burst=None,
            tx_queue_data2_aifs=None,
            tx_queue_data2_cwmin=None,
            tx_queue_data2_cwmax=None,
            tx_queue_data2_burst=None,
            tx_queue_data1_aifs=None,
            tx_queue_data1_cwmin=None,
            tx_queue_data1_cwmax=None,
            tx_queue_data1_burst=None,
            tx_queue_data0_aifs=None,
            tx_queue_data0_cwmin=None,
            tx_queue_data0_cwmax=None,
            tx_queue_data0_burst=None,
            ieee80211ac=None,
            require_vht=None,
            vht_oper_chwidth=None,
            vht_operations=None,
            vht_capability=None,
        ):

            assert driver is not None
            assert interface is not None
            assert ssid is not None
            assert beacon_interval is not None
            assert hw_mode is not None
            assert channel is not None
            assert country_code is not None
            assert ieee80211d is not None
            assert ieee80211h is not None
            assert bssid is not None
            assert macaddr_acl is not None
            assert macaddr_accept_file is not None
            assert macaddr_deny_file is not None
            assert ap_isolate is not None
            assert essid_mask is not None
            assert require_ht is not None
            assert ieee80211n is not None
            assert wmm_enabled is not None
            assert ht_capab is not None
            assert wmm_ac_bk_cwmin is not None
            assert wmm_ac_bk_cwmax is not None
            assert wmm_ac_bk_aifs is not None
            assert wmm_ac_bk_txop_limit is not None
            assert wmm_ac_bk_acm is not None
            assert wmm_ac_be_aifs is not None
            assert wmm_ac_be_cwmin is not None
            assert wmm_ac_be_cwmax is not None
            assert wmm_ac_be_txop_limit is not None
            assert wmm_ac_be_acm is not None
            assert wmm_ac_vi_aifs is not None
            assert wmm_ac_vi_cwmin is not None
            assert wmm_ac_vi_cwmax is not None
            assert wmm_ac_vi_txop_limit is not None
            assert wmm_ac_vi_acm is not None
            assert wmm_ac_vo_aifs is not None
            assert wmm_ac_vo_cwmin is not None
            assert wmm_ac_vo_cwmax is not None
            assert wmm_ac_vo_txop_limit is not None
            assert wmm_ac_vo_acm is not None
            assert tx_queue_data3_aifs is not None
            assert tx_queue_data3_cwmin is not None
            assert tx_queue_data3_cwmax is not None
            assert tx_queue_data3_burst is not None
            assert tx_queue_data2_aifs is not None
            assert tx_queue_data2_cwmin is not None
            assert tx_queue_data2_cwmax is not None
            assert tx_queue_data2_burst is not None
            assert tx_queue_data1_aifs is not None
            assert tx_queue_data1_cwmin is not None
            assert tx_queue_data1_cwmax is not None
            assert tx_queue_data1_burst is not None
            assert tx_queue_data0_aifs is not None
            assert tx_queue_data0_cwmin is not None
            assert tx_queue_data0_cwmax is not None
            assert tx_queue_data0_burst is not None
            assert ieee80211ac is not None
            assert require_vht is not None
            assert vht_oper_chwidth is not None
            assert vht_operations is not None
            assert vht_capability is not None

            try:
                print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)

                with open(cls.path, 'w') as fd:
                    fd.write(cls.template.format(
                        driver=driver,
                        interface=interface,
                        ssid=ssid,
                        beacon_interval=beacon_interval,
                        hw_mode=hw_mode,
                        channel=channel,
                        country_code=country_code,
                        ieee80211d=ieee80211d,
                        ieee80211h=ieee80211h,
                        bssid=bssid,
                        macaddr_acl=macaddr_acl,
                        macaddr_accept_file=macaddr_accept_file,
                        macaddr_deny_file=macaddr_deny_file,
                        ap_isolate=ap_isolate,
                        essid_mask=essid_mask,
                        require_ht=require_ht,
                        ieee80211n=ieee80211n,
                        wmm_enabled=wmm_enabled,
                        ht_capab=ht_capab,
                        wmm_ac_bk_cwmin=wmm_ac_bk_cwmin,
                        wmm_ac_bk_cwmax=wmm_ac_bk_cwmax,
                        wmm_ac_bk_aifs=wmm_ac_bk_aifs,
                        wmm_ac_bk_txop_limit=wmm_ac_bk_txop_limit,
                        wmm_ac_bk_acm=wmm_ac_bk_acm,
                        wmm_ac_be_aifs=wmm_ac_be_aifs,
                        wmm_ac_be_cwmin=wmm_ac_be_cwmin,
                        wmm_ac_be_cwmax=wmm_ac_be_cwmax,
                        wmm_ac_be_txop_limit=wmm_ac_be_txop_limit,
                        wmm_ac_be_acm=wmm_ac_be_acm,
                        wmm_ac_vi_aifs=wmm_ac_vi_aifs,
                        wmm_ac_vi_cwmin=wmm_ac_vi_cwmin,
                        wmm_ac_vi_cwmax=wmm_ac_vi_cwmax,
                        wmm_ac_vi_txop_limit=wmm_ac_vi_txop_limit,
                        wmm_ac_vi_acm=wmm_ac_vi_acm,
                        wmm_ac_vo_aifs=wmm_ac_vo_aifs,
                        wmm_ac_vo_cwmin=wmm_ac_vo_cwmin,
                        wmm_ac_vo_cwmax=wmm_ac_vo_cwmax,
                        wmm_ac_vo_txop_limit=wmm_ac_vo_txop_limit,
                        wmm_ac_vo_acm=wmm_ac_vo_acm,
                        tx_queue_data3_aifs=tx_queue_data3_aifs,
                        tx_queue_data3_cwmin=tx_queue_data3_cwmin,
                        tx_queue_data3_cwmax=tx_queue_data3_cwmax,
                        tx_queue_data3_burst=tx_queue_data3_burst,
                        tx_queue_data2_aifs=tx_queue_data2_aifs,
                        tx_queue_data2_cwmin=tx_queue_data2_cwmin,
                        tx_queue_data2_cwmax=tx_queue_data2_cwmax,
                        tx_queue_data2_burst=tx_queue_data2_burst,
                        tx_queue_data1_aifs=tx_queue_data1_aifs,
                        tx_queue_data1_cwmin=tx_queue_data1_cwmin,
                        tx_queue_data1_cwmax=tx_queue_data1_cwmax,
                        tx_queue_data1_burst=tx_queue_data1_burst,
                        tx_queue_data0_aifs=tx_queue_data0_aifs,
                        tx_queue_data0_cwmin=tx_queue_data0_cwmin,
                        tx_queue_data0_cwmax=tx_queue_data0_cwmax,
                        tx_queue_data0_burst=tx_queue_data0_burst,
                        ieee80211ac=ieee80211ac,
                        require_vht=require_vht,
                        vht_oper_chwidth=vht_oper_chwidth,
                        vht_operations=vht_operations,
                        vht_capability=vht_capability,
                    ))

            except Exception as e:
                print("[!] Error: %s" % e)
                return 1

    class WepCnf:

        import config
        from core.templates.hostapd import hostapd_wifi5_cnf

        path = config.hostapd_conf_full
        template = hostapd_wifi5_cnf.hostapd_wifi5_wep_cnf

        @classmethod
        def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            beacon_interval=None,
            hw_mode=None,
            channel=None,
            country_code=None,
            ieee80211d=None,
            ieee80211h=None,
            bssid=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            ap_isolate=None,
            essid_mask=None,
            require_ht=None,
            ieee80211n=None,
            wmm_enabled=None,
            ht_capab=None,
            wmm_ac_bk_cwmin=None,
            wmm_ac_bk_cwmax=None,
            wmm_ac_bk_aifs=None,
            wmm_ac_bk_txop_limit=None,
            wmm_ac_bk_acm=None,
            wmm_ac_be_aifs=None,
            wmm_ac_be_cwmin=None,
            wmm_ac_be_cwmax=None,
            wmm_ac_be_txop_limit=None,
            wmm_ac_be_acm=None,
            wmm_ac_vi_aifs=None,
            wmm_ac_vi_cwmin=None,
            wmm_ac_vi_cwmax=None,
            wmm_ac_vi_txop_limit=None,
            wmm_ac_vi_acm=None,
            wmm_ac_vo_aifs=None,
            wmm_ac_vo_cwmin=None,
            wmm_ac_vo_cwmax=None,
            wmm_ac_vo_txop_limit=None,
            wmm_ac_vo_acm=None,
            tx_queue_data3_aifs=None,
            tx_queue_data3_cwmin=None,
            tx_queue_data3_cwmax=None,
            tx_queue_data3_burst=None,
            tx_queue_data2_aifs=None,
            tx_queue_data2_cwmin=None,
            tx_queue_data2_cwmax=None,
            tx_queue_data2_burst=None,
            tx_queue_data1_aifs=None,
            tx_queue_data1_cwmin=None,
            tx_queue_data1_cwmax=None,
            tx_queue_data1_burst=None,
            tx_queue_data0_aifs=None,
            tx_queue_data0_cwmin=None,
            tx_queue_data0_cwmax=None,
            tx_queue_data0_burst=None,
            ieee80211ac=None,
            require_vht=None,
            vht_oper_chwidth=None,
            vht_operations=None,
            vht_capability=None,
            wep_default_key=None,
            wep_key=None
        ):

            assert driver is not None
            assert interface is not None
            assert ssid is not None
            assert beacon_interval is not None
            assert hw_mode is not None
            assert channel is not None
            assert country_code is not None
            assert ieee80211d is not None
            assert ieee80211h is not None
            assert bssid is not None
            assert macaddr_acl is not None
            assert macaddr_accept_file is not None
            assert macaddr_deny_file is not None
            assert ap_isolate is not None
            assert essid_mask is not None
            assert require_ht is not None
            assert ieee80211n is not None
            assert wmm_enabled is not None
            assert ht_capab is not None
            assert wmm_ac_bk_cwmin is not None
            assert wmm_ac_bk_cwmax is not None
            assert wmm_ac_bk_aifs is not None
            assert wmm_ac_bk_txop_limit is not None
            assert wmm_ac_bk_acm is not None
            assert wmm_ac_be_aifs is not None
            assert wmm_ac_be_cwmin is not None
            assert wmm_ac_be_cwmax is not None
            assert wmm_ac_be_txop_limit is not None
            assert wmm_ac_be_acm is not None
            assert wmm_ac_vi_aifs is not None
            assert wmm_ac_vi_cwmin is not None
            assert wmm_ac_vi_cwmax is not None
            assert wmm_ac_vi_txop_limit is not None
            assert wmm_ac_vi_acm is not None
            assert wmm_ac_vo_aifs is not None
            assert wmm_ac_vo_cwmin is not None
            assert wmm_ac_vo_cwmax is not None
            assert wmm_ac_vo_txop_limit is not None
            assert wmm_ac_vo_acm is not None
            assert tx_queue_data3_aifs is not None
            assert tx_queue_data3_cwmin is not None
            assert tx_queue_data3_cwmax is not None
            assert tx_queue_data3_burst is not None
            assert tx_queue_data2_aifs is not None
            assert tx_queue_data2_cwmin is not None
            assert tx_queue_data2_cwmax is not None
            assert tx_queue_data2_burst is not None
            assert tx_queue_data1_aifs is not None
            assert tx_queue_data1_cwmin is not None
            assert tx_queue_data1_cwmax is not None
            assert tx_queue_data1_burst is not None
            assert tx_queue_data0_aifs is not None
            assert tx_queue_data0_cwmin is not None
            assert tx_queue_data0_cwmax is not None
            assert tx_queue_data0_burst is not None
            assert ieee80211ac is not None
            assert require_vht is not None
            assert vht_oper_chwidth is not None
            assert vht_operations is not None
            assert vht_capability is not None
            assert wep_default_key is not None
            assert wep_key is not None

            try:
                print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)

                with open(cls.path, 'w') as fd:
                    fd.write(cls.template.format(
                        driver=driver,
                        interface=interface,
                        ssid=ssid,
                        beacon_interval=beacon_interval,
                        hw_mode=hw_mode,
                        channel=channel,
                        country_code=country_code,
                        ieee80211d=ieee80211d,
                        ieee80211h=ieee80211h,
                        bssid=bssid,
                        macaddr_acl=macaddr_acl,
                        macaddr_accept_file=macaddr_accept_file,
                        macaddr_deny_file=macaddr_deny_file,
                        ap_isolate=ap_isolate,
                        essid_mask=essid_mask,
                        require_ht=require_ht,
                        ieee80211n=ieee80211n,
                        wmm_enabled=wmm_enabled,
                        ht_capab=ht_capab,
                        wmm_ac_bk_cwmin=wmm_ac_bk_cwmin,
                        wmm_ac_bk_cwmax=wmm_ac_bk_cwmax,
                        wmm_ac_bk_aifs=wmm_ac_bk_aifs,
                        wmm_ac_bk_txop_limit=wmm_ac_bk_txop_limit,
                        wmm_ac_bk_acm=wmm_ac_bk_acm,
                        wmm_ac_be_aifs=wmm_ac_be_aifs,
                        wmm_ac_be_cwmin=wmm_ac_be_cwmin,
                        wmm_ac_be_cwmax=wmm_ac_be_cwmax,
                        wmm_ac_be_txop_limit=wmm_ac_be_txop_limit,
                        wmm_ac_be_acm=wmm_ac_be_acm,
                        wmm_ac_vi_aifs=wmm_ac_vi_aifs,
                        wmm_ac_vi_cwmin=wmm_ac_vi_cwmin,
                        wmm_ac_vi_cwmax=wmm_ac_vi_cwmax,
                        wmm_ac_vi_txop_limit=wmm_ac_vi_txop_limit,
                        wmm_ac_vi_acm=wmm_ac_vi_acm,
                        wmm_ac_vo_aifs=wmm_ac_vo_aifs,
                        wmm_ac_vo_cwmin=wmm_ac_vo_cwmin,
                        wmm_ac_vo_cwmax=wmm_ac_vo_cwmax,
                        wmm_ac_vo_txop_limit=wmm_ac_vo_txop_limit,
                        wmm_ac_vo_acm=wmm_ac_vo_acm,
                        tx_queue_data3_aifs=tx_queue_data3_aifs,
                        tx_queue_data3_cwmin=tx_queue_data3_cwmin,
                        tx_queue_data3_cwmax=tx_queue_data3_cwmax,
                        tx_queue_data3_burst=tx_queue_data3_burst,
                        tx_queue_data2_aifs=tx_queue_data2_aifs,
                        tx_queue_data2_cwmin=tx_queue_data2_cwmin,
                        tx_queue_data2_cwmax=tx_queue_data2_cwmax,
                        tx_queue_data2_burst=tx_queue_data2_burst,
                        tx_queue_data1_aifs=tx_queue_data1_aifs,
                        tx_queue_data1_cwmin=tx_queue_data1_cwmin,
                        tx_queue_data1_cwmax=tx_queue_data1_cwmax,
                        tx_queue_data1_burst=tx_queue_data1_burst,
                        tx_queue_data0_aifs=tx_queue_data0_aifs,
                        tx_queue_data0_cwmin=tx_queue_data0_cwmin,
                        tx_queue_data0_cwmax=tx_queue_data0_cwmax,
                        tx_queue_data0_burst=tx_queue_data0_burst,
                        ieee80211ac=ieee80211ac,
                        require_vht=require_vht,
                        vht_oper_chwidth=vht_oper_chwidth,
                        vht_operations=vht_operations,
                        vht_capability=vht_capability,
                        wep_key=wep_key,
                        wep_default_key=wep_default_key
                    ))

            except Exception as e:
                print("[!] Error: %s" % e)
                return 1

    class WpaCnf:

        import config
        from core.templates.hostapd import hostapd_wifi5_cnf

        path = config.hostapd_conf_full
        template = hostapd_wifi5_cnf.hostapd_wifi5_wpa_cnf

        @classmethod
        def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            beacon_interval=None,
            hw_mode=None,
            channel=None,
            country_code=None,
            ieee80211d=None,
            ieee80211h=None,
            bssid=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            ap_isolate=None,
            essid_mask=None,
            require_ht=None,
            ieee80211n=None,
            wmm_enabled=None,
            ht_capab=None,
            wmm_ac_bk_cwmin=None,
            wmm_ac_bk_cwmax=None,
            wmm_ac_bk_aifs=None,
            wmm_ac_bk_txop_limit=None,
            wmm_ac_bk_acm=None,
            wmm_ac_be_aifs=None,
            wmm_ac_be_cwmin=None,
            wmm_ac_be_cwmax=None,
            wmm_ac_be_txop_limit=None,
            wmm_ac_be_acm=None,
            wmm_ac_vi_aifs=None,
            wmm_ac_vi_cwmin=None,
            wmm_ac_vi_cwmax=None,
            wmm_ac_vi_txop_limit=None,
            wmm_ac_vi_acm=None,
            wmm_ac_vo_aifs=None,
            wmm_ac_vo_cwmin=None,
            wmm_ac_vo_cwmax=None,
            wmm_ac_vo_txop_limit=None,
            wmm_ac_vo_acm=None,
            tx_queue_data3_aifs=None,
            tx_queue_data3_cwmin=None,
            tx_queue_data3_cwmax=None,
            tx_queue_data3_burst=None,
            tx_queue_data2_aifs=None,
            tx_queue_data2_cwmin=None,
            tx_queue_data2_cwmax=None,
            tx_queue_data2_burst=None,
            tx_queue_data1_aifs=None,
            tx_queue_data1_cwmin=None,
            tx_queue_data1_cwmax=None,
            tx_queue_data1_burst=None,
            tx_queue_data0_aifs=None,
            tx_queue_data0_cwmin=None,
            tx_queue_data0_cwmax=None,
            tx_queue_data0_burst=None,
            ieee80211ac=None,
            require_vht=None,
            vht_oper_chwidth=None,
            vht_operations=None,
            vht_capability=None,
            wpa=None,
            wpa_passphrase=None,
            wpa_pairwise=None,
            rsn_pairwise=None,
        ):

            assert driver is not None
            assert interface is not None
            assert ssid is not None
            assert beacon_interval is not None
            assert hw_mode is not None
            assert channel is not None
            assert country_code is not None
            assert ieee80211d is not None
            assert ieee80211h is not None
            assert bssid is not None
            assert macaddr_acl is not None
            assert macaddr_accept_file is not None
            assert macaddr_deny_file is not None
            assert ap_isolate is not None
            assert essid_mask is not None
            assert require_ht is not None
            assert ieee80211n is not None
            assert wmm_enabled is not None
            assert ht_capab is not None
            assert wmm_ac_bk_cwmin is not None
            assert wmm_ac_bk_cwmax is not None
            assert wmm_ac_bk_aifs is not None
            assert wmm_ac_bk_txop_limit is not None
            assert wmm_ac_bk_acm is not None
            assert wmm_ac_be_aifs is not None
            assert wmm_ac_be_cwmin is not None
            assert wmm_ac_be_cwmax is not None
            assert wmm_ac_be_txop_limit is not None
            assert wmm_ac_be_acm is not None
            assert wmm_ac_vi_aifs is not None
            assert wmm_ac_vi_cwmin is not None
            assert wmm_ac_vi_cwmax is not None
            assert wmm_ac_vi_txop_limit is not None
            assert wmm_ac_vi_acm is not None
            assert wmm_ac_vo_aifs is not None
            assert wmm_ac_vo_cwmin is not None
            assert wmm_ac_vo_cwmax is not None
            assert wmm_ac_vo_txop_limit is not None
            assert wmm_ac_vo_acm is not None
            assert tx_queue_data3_aifs is not None
            assert tx_queue_data3_cwmin is not None
            assert tx_queue_data3_cwmax is not None
            assert tx_queue_data3_burst is not None
            assert tx_queue_data2_aifs is not None
            assert tx_queue_data2_cwmin is not None
            assert tx_queue_data2_cwmax is not None
            assert tx_queue_data2_burst is not None
            assert tx_queue_data1_aifs is not None
            assert tx_queue_data1_cwmin is not None
            assert tx_queue_data1_cwmax is not None
            assert tx_queue_data1_burst is not None
            assert tx_queue_data0_aifs is not None
            assert tx_queue_data0_cwmin is not None
            assert tx_queue_data0_cwmax is not None
            assert tx_queue_data0_burst is not None
            assert ieee80211ac is not None
            assert require_vht is not None
            assert vht_oper_chwidth is not None
            assert vht_operations is not None
            assert vht_capability is not None
            assert wpa is not None
            assert wpa_passphrase is not None
            assert wpa_pairwise is not None
            assert rsn_pairwise is not None

            try:
                print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)

                with open(cls.path, 'w') as fd:
                    fd.write(cls.template.format(
                        driver=driver,
                        interface=interface,
                        ssid=ssid,
                        beacon_interval=beacon_interval,
                        hw_mode=hw_mode,
                        channel=channel,
                        country_code=country_code,
                        ieee80211d=ieee80211d,
                        ieee80211h=ieee80211h,
                        bssid=bssid,
                        macaddr_acl=macaddr_acl,
                        macaddr_accept_file=macaddr_accept_file,
                        macaddr_deny_file=macaddr_deny_file,
                        ap_isolate=ap_isolate,
                        essid_mask=essid_mask,
                        require_ht=require_ht,
                        ieee80211n=ieee80211n,
                        wmm_enabled=wmm_enabled,
                        ht_capab=ht_capab,
                        wmm_ac_bk_cwmin=wmm_ac_bk_cwmin,
                        wmm_ac_bk_cwmax=wmm_ac_bk_cwmax,
                        wmm_ac_bk_aifs=wmm_ac_bk_aifs,
                        wmm_ac_bk_txop_limit=wmm_ac_bk_txop_limit,
                        wmm_ac_bk_acm=wmm_ac_bk_acm,
                        wmm_ac_be_aifs=wmm_ac_be_aifs,
                        wmm_ac_be_cwmin=wmm_ac_be_cwmin,
                        wmm_ac_be_cwmax=wmm_ac_be_cwmax,
                        wmm_ac_be_txop_limit=wmm_ac_be_txop_limit,
                        wmm_ac_be_acm=wmm_ac_be_acm,
                        wmm_ac_vi_aifs=wmm_ac_vi_aifs,
                        wmm_ac_vi_cwmin=wmm_ac_vi_cwmin,
                        wmm_ac_vi_cwmax=wmm_ac_vi_cwmax,
                        wmm_ac_vi_txop_limit=wmm_ac_vi_txop_limit,
                        wmm_ac_vi_acm=wmm_ac_vi_acm,
                        wmm_ac_vo_aifs=wmm_ac_vo_aifs,
                        wmm_ac_vo_cwmin=wmm_ac_vo_cwmin,
                        wmm_ac_vo_cwmax=wmm_ac_vo_cwmax,
                        wmm_ac_vo_txop_limit=wmm_ac_vo_txop_limit,
                        wmm_ac_vo_acm=wmm_ac_vo_acm,
                        tx_queue_data3_aifs=tx_queue_data3_aifs,
                        tx_queue_data3_cwmin=tx_queue_data3_cwmin,
                        tx_queue_data3_cwmax=tx_queue_data3_cwmax,
                        tx_queue_data3_burst=tx_queue_data3_burst,
                        tx_queue_data2_aifs=tx_queue_data2_aifs,
                        tx_queue_data2_cwmin=tx_queue_data2_cwmin,
                        tx_queue_data2_cwmax=tx_queue_data2_cwmax,
                        tx_queue_data2_burst=tx_queue_data2_burst,
                        tx_queue_data1_aifs=tx_queue_data1_aifs,
                        tx_queue_data1_cwmin=tx_queue_data1_cwmin,
                        tx_queue_data1_cwmax=tx_queue_data1_cwmax,
                        tx_queue_data1_burst=tx_queue_data1_burst,
                        tx_queue_data0_aifs=tx_queue_data0_aifs,
                        tx_queue_data0_cwmin=tx_queue_data0_cwmin,
                        tx_queue_data0_cwmax=tx_queue_data0_cwmax,
                        tx_queue_data0_burst=tx_queue_data0_burst,
                        ieee80211ac=ieee80211ac,
                        require_vht=require_vht,
                        vht_oper_chwidth=vht_oper_chwidth,
                        vht_operations=vht_operations,
                        vht_capability=vht_capability,
                        wpa=wpa,
                        wpa_passphrase=wpa_passphrase,
                        wpa_pairwise=wpa_pairwise,
                        rsn_pairwise=rsn_pairwise
                    ))

            except Exception as e:
                print("[!] Error: %s" % e)
                return 1

    class WpaEapCnf:

        import config
        from core.templates.hostapd import hostapd_wifi5_cnf

        path = config.hostapd_conf_full
        template = hostapd_wifi5_cnf.hostapd_wifi5_wpa_eap_cnf

        @classmethod
        def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            beacon_interval=None,
            hw_mode=None,
            channel=None,
            country_code=None,
            ieee80211d=None,
            ieee80211h=None,
            bssid=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            ap_isolate=None,
            essid_mask=None,
            require_ht=None,
            ieee80211n=None,
            wmm_enabled=None,
            ht_capab=None,
            wmm_ac_bk_cwmin=None,
            wmm_ac_bk_cwmax=None,
            wmm_ac_bk_aifs=None,
            wmm_ac_bk_txop_limit=None,
            wmm_ac_bk_acm=None,
            wmm_ac_be_aifs=None,
            wmm_ac_be_cwmin=None,
            wmm_ac_be_cwmax=None,
            wmm_ac_be_txop_limit=None,
            wmm_ac_be_acm=None,
            wmm_ac_vi_aifs=None,
            wmm_ac_vi_cwmin=None,
            wmm_ac_vi_cwmax=None,
            wmm_ac_vi_txop_limit=None,
            wmm_ac_vi_acm=None,
            wmm_ac_vo_aifs=None,
            wmm_ac_vo_cwmin=None,
            wmm_ac_vo_cwmax=None,
            wmm_ac_vo_txop_limit=None,
            wmm_ac_vo_acm=None,
            tx_queue_data3_aifs=None,
            tx_queue_data3_cwmin=None,
            tx_queue_data3_cwmax=None,
            tx_queue_data3_burst=None,
            tx_queue_data2_aifs=None,
            tx_queue_data2_cwmin=None,
            tx_queue_data2_cwmax=None,
            tx_queue_data2_burst=None,
            tx_queue_data1_aifs=None,
            tx_queue_data1_cwmin=None,
            tx_queue_data1_cwmax=None,
            tx_queue_data1_burst=None,
            tx_queue_data0_aifs=None,
            tx_queue_data0_cwmin=None,
            tx_queue_data0_cwmax=None,
            tx_queue_data0_burst=None,
            ieee80211ac=None,
            require_vht=None,
            vht_oper_chwidth=None,
            vht_operations=None,
            vht_capability=None,
            wpa=None,
            wpa_pairwise=None,
            rsn_pairwise=None,
            ieee8021x=None,
            eapol_version=None,
            eapol_workaround=None,
            own_ip_addr=None,
            auth_server_addr=None,
            auth_server_port=None,
            auth_server_shared_secret=None,
            acct_server_addr=None,
            acct_server_port=None,
            acct_server_shared_secret=None,
            eap_user_file=None,
            ca_pem=None,
            server_pem=None,
            private_key=None,
            private_key_passwd=None,
            dh_file=None
        ):

            assert driver is not None
            assert interface is not None
            assert ssid is not None
            assert beacon_interval is not None
            assert hw_mode is not None
            assert channel is not None
            assert country_code is not None
            assert ieee80211d is not None
            assert ieee80211h is not None
            assert bssid is not None
            assert macaddr_acl is not None
            assert macaddr_accept_file is not None
            assert macaddr_deny_file is not None
            assert ap_isolate is not None
            assert essid_mask is not None
            assert require_ht is not None
            assert ieee80211n is not None
            assert wmm_enabled is not None
            assert ht_capab is not None
            assert wmm_ac_bk_cwmin is not None
            assert wmm_ac_bk_cwmax is not None
            assert wmm_ac_bk_aifs is not None
            assert wmm_ac_bk_txop_limit is not None
            assert wmm_ac_bk_acm is not None
            assert wmm_ac_be_aifs is not None
            assert wmm_ac_be_cwmin is not None
            assert wmm_ac_be_cwmax is not None
            assert wmm_ac_be_txop_limit is not None
            assert wmm_ac_be_acm is not None
            assert wmm_ac_vi_aifs is not None
            assert wmm_ac_vi_cwmin is not None
            assert wmm_ac_vi_cwmax is not None
            assert wmm_ac_vi_txop_limit is not None
            assert wmm_ac_vi_acm is not None
            assert wmm_ac_vo_aifs is not None
            assert wmm_ac_vo_cwmin is not None
            assert wmm_ac_vo_cwmax is not None
            assert wmm_ac_vo_txop_limit is not None
            assert wmm_ac_vo_acm is not None
            assert tx_queue_data3_aifs is not None
            assert tx_queue_data3_cwmin is not None
            assert tx_queue_data3_cwmax is not None
            assert tx_queue_data3_burst is not None
            assert tx_queue_data2_aifs is not None
            assert tx_queue_data2_cwmin is not None
            assert tx_queue_data2_cwmax is not None
            assert tx_queue_data2_burst is not None
            assert tx_queue_data1_aifs is not None
            assert tx_queue_data1_cwmin is not None
            assert tx_queue_data1_cwmax is not None
            assert tx_queue_data1_burst is not None
            assert tx_queue_data0_aifs is not None
            assert tx_queue_data0_cwmin is not None
            assert tx_queue_data0_cwmax is not None
            assert tx_queue_data0_burst is not None
            assert ieee80211ac is not None
            assert require_vht is not None
            assert vht_oper_chwidth is not None
            assert vht_operations is not None
            assert vht_capability is not None
            assert wpa is not None
            assert wpa_pairwise is not None
            assert rsn_pairwise is not None
            assert ieee8021x is not None
            assert eapol_version is not None
            assert eapol_workaround is not None
            assert own_ip_addr is not None
            assert auth_server_addr is not None
            assert auth_server_port is not None
            assert auth_server_shared_secret is not None
            assert acct_server_addr is not None
            assert acct_server_port is not None
            assert acct_server_shared_secret is not None
            assert eap_user_file is not None
            assert ca_pem is not None
            assert server_pem is not None
            assert private_key is not None
            assert private_key_passwd is not None
            assert dh_file is not None

            try:
                print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)

                with open(cls.path, 'w') as fd:
                    fd.write(cls.template.format(
                        driver=driver,
                        interface=interface,
                        ssid=ssid,
                        beacon_interval=beacon_interval,
                        hw_mode=hw_mode,
                        channel=channel,
                        country_code=country_code,
                        ieee80211d=ieee80211d,
                        ieee80211h=ieee80211h,
                        bssid=bssid,
                        macaddr_acl=macaddr_acl,
                        macaddr_accept_file=macaddr_accept_file,
                        macaddr_deny_file=macaddr_deny_file,
                        ap_isolate=ap_isolate,
                        essid_mask=essid_mask,
                        require_ht=require_ht,
                        ieee80211n=ieee80211n,
                        wmm_enabled=wmm_enabled,
                        ht_capab=ht_capab,
                        wmm_ac_bk_cwmin=wmm_ac_bk_cwmin,
                        wmm_ac_bk_cwmax=wmm_ac_bk_cwmax,
                        wmm_ac_bk_aifs=wmm_ac_bk_aifs,
                        wmm_ac_bk_txop_limit=wmm_ac_bk_txop_limit,
                        wmm_ac_bk_acm=wmm_ac_bk_acm,
                        wmm_ac_be_aifs=wmm_ac_be_aifs,
                        wmm_ac_be_cwmin=wmm_ac_be_cwmin,
                        wmm_ac_be_cwmax=wmm_ac_be_cwmax,
                        wmm_ac_be_txop_limit=wmm_ac_be_txop_limit,
                        wmm_ac_be_acm=wmm_ac_be_acm,
                        wmm_ac_vi_aifs=wmm_ac_vi_aifs,
                        wmm_ac_vi_cwmin=wmm_ac_vi_cwmin,
                        wmm_ac_vi_cwmax=wmm_ac_vi_cwmax,
                        wmm_ac_vi_txop_limit=wmm_ac_vi_txop_limit,
                        wmm_ac_vi_acm=wmm_ac_vi_acm,
                        wmm_ac_vo_aifs=wmm_ac_vo_aifs,
                        wmm_ac_vo_cwmin=wmm_ac_vo_cwmin,
                        wmm_ac_vo_cwmax=wmm_ac_vo_cwmax,
                        wmm_ac_vo_txop_limit=wmm_ac_vo_txop_limit,
                        wmm_ac_vo_acm=wmm_ac_vo_acm,
                        tx_queue_data3_aifs=tx_queue_data3_aifs,
                        tx_queue_data3_cwmin=tx_queue_data3_cwmin,
                        tx_queue_data3_cwmax=tx_queue_data3_cwmax,
                        tx_queue_data3_burst=tx_queue_data3_burst,
                        tx_queue_data2_aifs=tx_queue_data2_aifs,
                        tx_queue_data2_cwmin=tx_queue_data2_cwmin,
                        tx_queue_data2_cwmax=tx_queue_data2_cwmax,
                        tx_queue_data2_burst=tx_queue_data2_burst,
                        tx_queue_data1_aifs=tx_queue_data1_aifs,
                        tx_queue_data1_cwmin=tx_queue_data1_cwmin,
                        tx_queue_data1_cwmax=tx_queue_data1_cwmax,
                        tx_queue_data1_burst=tx_queue_data1_burst,
                        tx_queue_data0_aifs=tx_queue_data0_aifs,
                        tx_queue_data0_cwmin=tx_queue_data0_cwmin,
                        tx_queue_data0_cwmax=tx_queue_data0_cwmax,
                        tx_queue_data0_burst=tx_queue_data0_burst,
                        ieee80211ac=ieee80211ac,
                        require_vht=require_vht,
                        vht_oper_chwidth=vht_oper_chwidth,
                        vht_operations=vht_operations,
                        vht_capability=vht_capability,
                        wpa=wpa,
                        wpa_pairwise=wpa_pairwise,
                        rsn_pairwise=rsn_pairwise,
                        ieee8021x=ieee8021x,
                        eapol_version=eapol_version,
                        eapol_workaround=eapol_workaround,
                        own_ip_addr=own_ip_addr,
                        auth_server_addr=auth_server_addr,
                        auth_server_port=auth_server_port,
                        auth_server_shared_secret=auth_server_shared_secret,
                        acct_server_addr=acct_server_addr,
                        acct_server_port=acct_server_port,
                        acct_server_shared_secret=acct_server_shared_secret,
                        eap_user_file=eap_user_file,
                        ca_pem=ca_pem,
                        server_pem=server_pem,
                        private_key=private_key,
                        private_key_passwd=private_key_passwd, # unused
                        dh_file=dh_file,
                    ))

            except Exception as e:
                print("[!] Error: %s" % e)
                return 1,

class HostapdWifi6:

    class OpenCnf:

        import config
        from core.templates.hostapd import hostapd_wifi6_cnf

        path = config.hostapd_conf_full
        template = hostapd_wifi6_cnf.hostapd_wifi6_open_cnf

        @classmethod
        def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            beacon_interval=None,
            hw_mode=None,
            channel=None,
            country_code=None,
            ieee80211d=None,
            ieee80211h=None,
            bssid=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            ap_isolate=None,
            essid_mask=None,
            require_ht=None,
            ieee80211n=None,
            wmm_enabled=None,
            ht_capab=None,
            wmm_ac_bk_cwmin=None,
            wmm_ac_bk_cwmax=None,
            wmm_ac_bk_aifs=None,
            wmm_ac_bk_txop_limit=None,
            wmm_ac_bk_acm=None,
            wmm_ac_be_aifs=None,
            wmm_ac_be_cwmin=None,
            wmm_ac_be_cwmax=None,
            wmm_ac_be_txop_limit=None,
            wmm_ac_be_acm=None,
            wmm_ac_vi_aifs=None,
            wmm_ac_vi_cwmin=None,
            wmm_ac_vi_cwmax=None,
            wmm_ac_vi_txop_limit=None,
            wmm_ac_vi_acm=None,
            wmm_ac_vo_aifs=None,
            wmm_ac_vo_cwmin=None,
            wmm_ac_vo_cwmax=None,
            wmm_ac_vo_txop_limit=None,
            wmm_ac_vo_acm=None,
            tx_queue_data3_aifs=None,
            tx_queue_data3_cwmin=None,
            tx_queue_data3_cwmax=None,
            tx_queue_data3_burst=None,
            tx_queue_data2_aifs=None,
            tx_queue_data2_cwmin=None,
            tx_queue_data2_cwmax=None,
            tx_queue_data2_burst=None,
            tx_queue_data1_aifs=None,
            tx_queue_data1_cwmin=None,
            tx_queue_data1_cwmax=None,
            tx_queue_data1_burst=None,
            tx_queue_data0_aifs=None,
            tx_queue_data0_cwmin=None,
            tx_queue_data0_cwmax=None,
            tx_queue_data0_burst=None,
            ieee80211ac=None,
            require_vht=None,
            vht_oper_chwidth=None,
            vht_operations=None,
            vht_capability=None,
            ieee80211ax=None,
            require_he=None,
            he_su_beamformer=None,
            he_su_beamformee=None,
            he_mu_beamformer=None,
            he_bss_color=None,
            he_default_pe_duration=None,
            he_basic_mcs_nss_set=None,
        ):

            assert driver is not None
            assert interface is not None
            assert ssid is not None
            assert beacon_interval is not None
            assert hw_mode is not None
            assert channel is not None
            assert country_code is not None
            assert ieee80211d is not None
            assert ieee80211h is not None
            assert bssid is not None
            assert macaddr_acl is not None
            assert macaddr_accept_file is not None
            assert macaddr_deny_file is not None
            assert ap_isolate is not None
            assert essid_mask is not None
            assert require_ht is not None
            assert ieee80211n is not None
            assert wmm_enabled is not None
            assert ht_capab is not None
            assert wmm_ac_bk_cwmin is not None
            assert wmm_ac_bk_cwmax is not None
            assert wmm_ac_bk_aifs is not None
            assert wmm_ac_bk_txop_limit is not None
            assert wmm_ac_bk_acm is not None
            assert wmm_ac_be_aifs is not None
            assert wmm_ac_be_cwmin is not None
            assert wmm_ac_be_cwmax is not None
            assert wmm_ac_be_txop_limit is not None
            assert wmm_ac_be_acm is not None
            assert wmm_ac_vi_aifs is not None
            assert wmm_ac_vi_cwmin is not None
            assert wmm_ac_vi_cwmax is not None
            assert wmm_ac_vi_txop_limit is not None
            assert wmm_ac_vi_acm is not None
            assert wmm_ac_vo_aifs is not None
            assert wmm_ac_vo_cwmin is not None
            assert wmm_ac_vo_cwmax is not None
            assert wmm_ac_vo_txop_limit is not None
            assert wmm_ac_vo_acm is not None
            assert tx_queue_data3_aifs is not None
            assert tx_queue_data3_cwmin is not None
            assert tx_queue_data3_cwmax is not None
            assert tx_queue_data3_burst is not None
            assert tx_queue_data2_aifs is not None
            assert tx_queue_data2_cwmin is not None
            assert tx_queue_data2_cwmax is not None
            assert tx_queue_data2_burst is not None
            assert tx_queue_data1_aifs is not None
            assert tx_queue_data1_cwmin is not None
            assert tx_queue_data1_cwmax is not None
            assert tx_queue_data1_burst is not None
            assert tx_queue_data0_aifs is not None
            assert tx_queue_data0_cwmin is not None
            assert tx_queue_data0_cwmax is not None
            assert tx_queue_data0_burst is not None
            assert ieee80211ac is not None
            assert require_vht is not None
            assert vht_oper_chwidth is not None
            assert vht_operations is not None
            assert vht_capability is not None
            assert ieee80211ax is not None
            assert require_he is not None
            assert he_su_beamformer is not None
            assert he_su_beamformee is not None
            assert he_mu_beamformer is not None
            assert he_bss_color is not None
            assert he_default_pe_duration is not None
            assert he_basic_mcs_nss_set is not None

            try:
                print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)

                with open(cls.path, 'w') as fd:
                    fd.write(cls.template.format(
                        driver=driver,
                        interface=interface,
                        ssid=ssid,
                        beacon_interval=beacon_interval,
                        hw_mode=hw_mode,
                        channel=channel,
                        country_code=country_code,
                        ieee80211d=ieee80211d,
                        ieee80211h=ieee80211h,
                        bssid=bssid,
                        macaddr_acl=macaddr_acl,
                        macaddr_accept_file=macaddr_accept_file,
                        macaddr_deny_file=macaddr_deny_file,
                        ap_isolate=ap_isolate,
                        essid_mask=essid_mask,
                        require_ht=require_ht,
                        ieee80211n=ieee80211n,
                        wmm_enabled=wmm_enabled,
                        ht_capab=ht_capab,
                        wmm_ac_bk_cwmin=wmm_ac_bk_cwmin,
                        wmm_ac_bk_cwmax=wmm_ac_bk_cwmax,
                        wmm_ac_bk_aifs=wmm_ac_bk_aifs,
                        wmm_ac_bk_txop_limit=wmm_ac_bk_txop_limit,
                        wmm_ac_bk_acm=wmm_ac_bk_acm,
                        wmm_ac_be_aifs=wmm_ac_be_aifs,
                        wmm_ac_be_cwmin=wmm_ac_be_cwmin,
                        wmm_ac_be_cwmax=wmm_ac_be_cwmax,
                        wmm_ac_be_txop_limit=wmm_ac_be_txop_limit,
                        wmm_ac_be_acm=wmm_ac_be_acm,
                        wmm_ac_vi_aifs=wmm_ac_vi_aifs,
                        wmm_ac_vi_cwmin=wmm_ac_vi_cwmin,
                        wmm_ac_vi_cwmax=wmm_ac_vi_cwmax,
                        wmm_ac_vi_txop_limit=wmm_ac_vi_txop_limit,
                        wmm_ac_vi_acm=wmm_ac_vi_acm,
                        wmm_ac_vo_aifs=wmm_ac_vo_aifs,
                        wmm_ac_vo_cwmin=wmm_ac_vo_cwmin,
                        wmm_ac_vo_cwmax=wmm_ac_vo_cwmax,
                        wmm_ac_vo_txop_limit=wmm_ac_vo_txop_limit,
                        wmm_ac_vo_acm=wmm_ac_vo_acm,
                        tx_queue_data3_aifs=tx_queue_data3_aifs,
                        tx_queue_data3_cwmin=tx_queue_data3_cwmin,
                        tx_queue_data3_cwmax=tx_queue_data3_cwmax,
                        tx_queue_data3_burst=tx_queue_data3_burst,
                        tx_queue_data2_aifs=tx_queue_data2_aifs,
                        tx_queue_data2_cwmin=tx_queue_data2_cwmin,
                        tx_queue_data2_cwmax=tx_queue_data2_cwmax,
                        tx_queue_data2_burst=tx_queue_data2_burst,
                        tx_queue_data1_aifs=tx_queue_data1_aifs,
                        tx_queue_data1_cwmin=tx_queue_data1_cwmin,
                        tx_queue_data1_cwmax=tx_queue_data1_cwmax,
                        tx_queue_data1_burst=tx_queue_data1_burst,
                        tx_queue_data0_aifs=tx_queue_data0_aifs,
                        tx_queue_data0_cwmin=tx_queue_data0_cwmin,
                        tx_queue_data0_cwmax=tx_queue_data0_cwmax,
                        tx_queue_data0_burst=tx_queue_data0_burst,
                        ieee80211ac=ieee80211ac,
                        require_vht=require_vht,
                        vht_oper_chwidth=vht_oper_chwidth,
                        vht_operations=vht_operations,
                        vht_capability=vht_capability,
                        ieee80211ax=ieee80211ax,
                        require_he=require_he,
                        he_su_beamformer=he_su_beamformer,
                        he_su_beamformee=he_su_beamformee,
                        he_mu_beamformer=he_mu_beamformer,
                        he_bss_color=he_bss_color,
                        he_default_pe_duration=he_default_pe_duration,
                        he_basic_mcs_nss_set=he_basic_mcs_nss_set,
                    ))

            except Exception as e:
                print("[!] Error: %s" % e)
                return 1

    class WepCnf:

        import config
        from core.templates.hostapd import hostapd_wifi6_cnf

        path = config.hostapd_conf_full
        template = hostapd_wifi6_cnf.hostapd_wifi6_wep_cnf

        @classmethod
        def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            beacon_interval=None,
            hw_mode=None,
            channel=None,
            country_code=None,
            ieee80211d=None,
            ieee80211h=None,
            bssid=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            ap_isolate=None,
            essid_mask=None,
            require_ht=None,
            ieee80211n=None,
            wmm_enabled=None,
            ht_capab=None,
            wmm_ac_bk_cwmin=None,
            wmm_ac_bk_cwmax=None,
            wmm_ac_bk_aifs=None,
            wmm_ac_bk_txop_limit=None,
            wmm_ac_bk_acm=None,
            wmm_ac_be_aifs=None,
            wmm_ac_be_cwmin=None,
            wmm_ac_be_cwmax=None,
            wmm_ac_be_txop_limit=None,
            wmm_ac_be_acm=None,
            wmm_ac_vi_aifs=None,
            wmm_ac_vi_cwmin=None,
            wmm_ac_vi_cwmax=None,
            wmm_ac_vi_txop_limit=None,
            wmm_ac_vi_acm=None,
            wmm_ac_vo_aifs=None,
            wmm_ac_vo_cwmin=None,
            wmm_ac_vo_cwmax=None,
            wmm_ac_vo_txop_limit=None,
            wmm_ac_vo_acm=None,
            tx_queue_data3_aifs=None,
            tx_queue_data3_cwmin=None,
            tx_queue_data3_cwmax=None,
            tx_queue_data3_burst=None,
            tx_queue_data2_aifs=None,
            tx_queue_data2_cwmin=None,
            tx_queue_data2_cwmax=None,
            tx_queue_data2_burst=None,
            tx_queue_data1_aifs=None,
            tx_queue_data1_cwmin=None,
            tx_queue_data1_cwmax=None,
            tx_queue_data1_burst=None,
            tx_queue_data0_aifs=None,
            tx_queue_data0_cwmin=None,
            tx_queue_data0_cwmax=None,
            tx_queue_data0_burst=None,
            ieee80211ac=None,
            require_vht=None,
            vht_oper_chwidth=None,
            vht_operations=None,
            vht_capability=None,
            ieee80211ax=None,
            require_he=None,
            he_su_beamformer=None,
            he_su_beamformee=None,
            he_mu_beamformer=None,
            he_bss_color=None,
            he_default_pe_duration=None,
            he_basic_mcs_nss_set=None,
            wep_default_key=None,
            wep_key=None
        ):

            assert driver is not None
            assert interface is not None
            assert ssid is not None
            assert beacon_interval is not None
            assert hw_mode is not None
            assert channel is not None
            assert country_code is not None
            assert ieee80211d is not None
            assert ieee80211h is not None
            assert bssid is not None
            assert macaddr_acl is not None
            assert macaddr_accept_file is not None
            assert macaddr_deny_file is not None
            assert ap_isolate is not None
            assert essid_mask is not None
            assert require_ht is not None
            assert ieee80211n is not None
            assert wmm_enabled is not None
            assert ht_capab is not None
            assert wmm_ac_bk_cwmin is not None
            assert wmm_ac_bk_cwmax is not None
            assert wmm_ac_bk_aifs is not None
            assert wmm_ac_bk_txop_limit is not None
            assert wmm_ac_bk_acm is not None
            assert wmm_ac_be_aifs is not None
            assert wmm_ac_be_cwmin is not None
            assert wmm_ac_be_cwmax is not None
            assert wmm_ac_be_txop_limit is not None
            assert wmm_ac_be_acm is not None
            assert wmm_ac_vi_aifs is not None
            assert wmm_ac_vi_cwmin is not None
            assert wmm_ac_vi_cwmax is not None
            assert wmm_ac_vi_txop_limit is not None
            assert wmm_ac_vi_acm is not None
            assert wmm_ac_vo_aifs is not None
            assert wmm_ac_vo_cwmin is not None
            assert wmm_ac_vo_cwmax is not None
            assert wmm_ac_vo_txop_limit is not None
            assert wmm_ac_vo_acm is not None
            assert tx_queue_data3_aifs is not None
            assert tx_queue_data3_cwmin is not None
            assert tx_queue_data3_cwmax is not None
            assert tx_queue_data3_burst is not None
            assert tx_queue_data2_aifs is not None
            assert tx_queue_data2_cwmin is not None
            assert tx_queue_data2_cwmax is not None
            assert tx_queue_data2_burst is not None
            assert tx_queue_data1_aifs is not None
            assert tx_queue_data1_cwmin is not None
            assert tx_queue_data1_cwmax is not None
            assert tx_queue_data1_burst is not None
            assert tx_queue_data0_aifs is not None
            assert tx_queue_data0_cwmin is not None
            assert tx_queue_data0_cwmax is not None
            assert tx_queue_data0_burst is not None
            assert ieee80211ac is not None
            assert require_vht is not None
            assert ieee80211ax is not None
            assert require_he is not None
            assert he_su_beamformer is not None
            assert he_su_beamformee is not None
            assert he_mu_beamformer is not None
            assert he_bss_color is not None
            assert he_default_pe_duration is not None
            assert he_basic_mcs_nss_set is not None
            assert vht_oper_chwidth is not None
            assert vht_operations is not None
            assert vht_capability is not None
            assert wep_default_key is not None
            assert wep_key is not None

            try:
                print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)

                with open(cls.path, 'w') as fd:
                    fd.write(cls.template.format(
                        driver=driver,
                        interface=interface,
                        ssid=ssid,
                        beacon_interval=beacon_interval,
                        hw_mode=hw_mode,
                        channel=channel,
                        country_code=country_code,
                        ieee80211d=ieee80211d,
                        ieee80211h=ieee80211h,
                        bssid=bssid,
                        macaddr_acl=macaddr_acl,
                        macaddr_accept_file=macaddr_accept_file,
                        macaddr_deny_file=macaddr_deny_file,
                        ap_isolate=ap_isolate,
                        essid_mask=essid_mask,
                        require_ht=require_ht,
                        ieee80211n=ieee80211n,
                        wmm_enabled=wmm_enabled,
                        ht_capab=ht_capab,
                        wmm_ac_bk_cwmin=wmm_ac_bk_cwmin,
                        wmm_ac_bk_cwmax=wmm_ac_bk_cwmax,
                        wmm_ac_bk_aifs=wmm_ac_bk_aifs,
                        wmm_ac_bk_txop_limit=wmm_ac_bk_txop_limit,
                        wmm_ac_bk_acm=wmm_ac_bk_acm,
                        wmm_ac_be_aifs=wmm_ac_be_aifs,
                        wmm_ac_be_cwmin=wmm_ac_be_cwmin,
                        wmm_ac_be_cwmax=wmm_ac_be_cwmax,
                        wmm_ac_be_txop_limit=wmm_ac_be_txop_limit,
                        wmm_ac_be_acm=wmm_ac_be_acm,
                        wmm_ac_vi_aifs=wmm_ac_vi_aifs,
                        wmm_ac_vi_cwmin=wmm_ac_vi_cwmin,
                        wmm_ac_vi_cwmax=wmm_ac_vi_cwmax,
                        wmm_ac_vi_txop_limit=wmm_ac_vi_txop_limit,
                        wmm_ac_vi_acm=wmm_ac_vi_acm,
                        wmm_ac_vo_aifs=wmm_ac_vo_aifs,
                        wmm_ac_vo_cwmin=wmm_ac_vo_cwmin,
                        wmm_ac_vo_cwmax=wmm_ac_vo_cwmax,
                        wmm_ac_vo_txop_limit=wmm_ac_vo_txop_limit,
                        wmm_ac_vo_acm=wmm_ac_vo_acm,
                        tx_queue_data3_aifs=tx_queue_data3_aifs,
                        tx_queue_data3_cwmin=tx_queue_data3_cwmin,
                        tx_queue_data3_cwmax=tx_queue_data3_cwmax,
                        tx_queue_data3_burst=tx_queue_data3_burst,
                        tx_queue_data2_aifs=tx_queue_data2_aifs,
                        tx_queue_data2_cwmin=tx_queue_data2_cwmin,
                        tx_queue_data2_cwmax=tx_queue_data2_cwmax,
                        tx_queue_data2_burst=tx_queue_data2_burst,
                        tx_queue_data1_aifs=tx_queue_data1_aifs,
                        tx_queue_data1_cwmin=tx_queue_data1_cwmin,
                        tx_queue_data1_cwmax=tx_queue_data1_cwmax,
                        tx_queue_data1_burst=tx_queue_data1_burst,
                        tx_queue_data0_aifs=tx_queue_data0_aifs,
                        tx_queue_data0_cwmin=tx_queue_data0_cwmin,
                        tx_queue_data0_cwmax=tx_queue_data0_cwmax,
                        tx_queue_data0_burst=tx_queue_data0_burst,
                        ieee80211ac=ieee80211ac,
                        require_vht=require_vht,
                        vht_oper_chwidth=vht_oper_chwidth,
                        vht_operations=vht_operations,
                        vht_capability=vht_capability,
                        ieee80211ax=ieee80211ax,
                        require_he=require_he,
                        he_su_beamformer=he_su_beamformer,
                        he_su_beamformee=he_su_beamformee,
                        he_mu_beamformer=he_mu_beamformer,
                        he_bss_color=he_bss_color,
                        he_default_pe_duration=he_default_pe_duration,
                        he_basic_mcs_nss_set=he_basic_mcs_nss_set,
                        wep_key=wep_key,
                        wep_default_key=wep_default_key
                    ))

            except Exception as e:
                print("[!] Error: %s" % e)
                return 1

    class WpaCnf:

        import config
        from core.templates.hostapd import hostapd_wifi6_cnf

        path = config.hostapd_conf_full
        template = hostapd_wifi6_cnf.hostapd_wifi6_wpa_cnf

        @classmethod
        def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            beacon_interval=None,
            hw_mode=None,
            channel=None,
            country_code=None,
            ieee80211d=None,
            ieee80211h=None,
            bssid=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            ap_isolate=None,
            essid_mask=None,
            require_ht=None,
            ieee80211n=None,
            wmm_enabled=None,
            ht_capab=None,
            wmm_ac_bk_cwmin=None,
            wmm_ac_bk_cwmax=None,
            wmm_ac_bk_aifs=None,
            wmm_ac_bk_txop_limit=None,
            wmm_ac_bk_acm=None,
            wmm_ac_be_aifs=None,
            wmm_ac_be_cwmin=None,
            wmm_ac_be_cwmax=None,
            wmm_ac_be_txop_limit=None,
            wmm_ac_be_acm=None,
            wmm_ac_vi_aifs=None,
            wmm_ac_vi_cwmin=None,
            wmm_ac_vi_cwmax=None,
            wmm_ac_vi_txop_limit=None,
            wmm_ac_vi_acm=None,
            wmm_ac_vo_aifs=None,
            wmm_ac_vo_cwmin=None,
            wmm_ac_vo_cwmax=None,
            wmm_ac_vo_txop_limit=None,
            wmm_ac_vo_acm=None,
            tx_queue_data3_aifs=None,
            tx_queue_data3_cwmin=None,
            tx_queue_data3_cwmax=None,
            tx_queue_data3_burst=None,
            tx_queue_data2_aifs=None,
            tx_queue_data2_cwmin=None,
            tx_queue_data2_cwmax=None,
            tx_queue_data2_burst=None,
            tx_queue_data1_aifs=None,
            tx_queue_data1_cwmin=None,
            tx_queue_data1_cwmax=None,
            tx_queue_data1_burst=None,
            tx_queue_data0_aifs=None,
            tx_queue_data0_cwmin=None,
            tx_queue_data0_cwmax=None,
            tx_queue_data0_burst=None,
            ieee80211ac=None,
            require_vht=None,
            vht_oper_chwidth=None,
            vht_operations=None,
            vht_capability=None,
            ieee80211ax=None,
            require_he=None,
            he_su_beamformer=None,
            he_su_beamformee=None,
            he_mu_beamformer=None,
            he_bss_color=None,
            he_default_pe_duration=None,
            he_basic_mcs_nss_set=None,
            wpa=None,
            wpa_passphrase=None,
            wpa_pairwise=None,
            rsn_pairwise=None,
        ):

            assert driver is not None
            assert interface is not None
            assert ssid is not None
            assert beacon_interval is not None
            assert hw_mode is not None
            assert channel is not None
            assert country_code is not None
            assert ieee80211d is not None
            assert ieee80211h is not None
            assert bssid is not None
            assert macaddr_acl is not None
            assert macaddr_accept_file is not None
            assert macaddr_deny_file is not None
            assert ap_isolate is not None
            assert essid_mask is not None
            assert require_ht is not None
            assert ieee80211n is not None
            assert wmm_enabled is not None
            assert ht_capab is not None
            assert wmm_ac_bk_cwmin is not None
            assert wmm_ac_bk_cwmax is not None
            assert wmm_ac_bk_aifs is not None
            assert wmm_ac_bk_txop_limit is not None
            assert wmm_ac_bk_acm is not None
            assert wmm_ac_be_aifs is not None
            assert wmm_ac_be_cwmin is not None
            assert wmm_ac_be_cwmax is not None
            assert wmm_ac_be_txop_limit is not None
            assert wmm_ac_be_acm is not None
            assert wmm_ac_vi_aifs is not None
            assert wmm_ac_vi_cwmin is not None
            assert wmm_ac_vi_cwmax is not None
            assert wmm_ac_vi_txop_limit is not None
            assert wmm_ac_vi_acm is not None
            assert wmm_ac_vo_aifs is not None
            assert wmm_ac_vo_cwmin is not None
            assert wmm_ac_vo_cwmax is not None
            assert wmm_ac_vo_txop_limit is not None
            assert wmm_ac_vo_acm is not None
            assert tx_queue_data3_aifs is not None
            assert tx_queue_data3_cwmin is not None
            assert tx_queue_data3_cwmax is not None
            assert tx_queue_data3_burst is not None
            assert tx_queue_data2_aifs is not None
            assert tx_queue_data2_cwmin is not None
            assert tx_queue_data2_cwmax is not None
            assert tx_queue_data2_burst is not None
            assert tx_queue_data1_aifs is not None
            assert tx_queue_data1_cwmin is not None
            assert tx_queue_data1_cwmax is not None
            assert tx_queue_data1_burst is not None
            assert tx_queue_data0_aifs is not None
            assert tx_queue_data0_cwmin is not None
            assert tx_queue_data0_cwmax is not None
            assert tx_queue_data0_burst is not None
            assert ieee80211ac is not None
            assert require_vht is not None
            assert vht_oper_chwidth is not None
            assert vht_operations is not None
            assert vht_capability is not None
            assert ieee80211ax is not None
            assert require_he is not None
            assert he_su_beamformer is not None
            assert he_su_beamformee is not None
            assert he_mu_beamformer is not None
            assert he_bss_color is not None
            assert he_default_pe_duration is not None
            assert he_basic_mcs_nss_set is not None
            assert wpa is not None
            assert wpa_passphrase is not None
            assert wpa_pairwise is not None
            assert rsn_pairwise is not None

            try:
                print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)

                with open(cls.path, 'w') as fd:
                    fd.write(cls.template.format(
                        driver=driver,
                        interface=interface,
                        ssid=ssid,
                        beacon_interval=beacon_interval,
                        hw_mode=hw_mode,
                        channel=channel,
                        country_code=country_code,
                        ieee80211d=ieee80211d,
                        ieee80211h=ieee80211h,
                        bssid=bssid,
                        macaddr_acl=macaddr_acl,
                        macaddr_accept_file=macaddr_accept_file,
                        macaddr_deny_file=macaddr_deny_file,
                        ap_isolate=ap_isolate,
                        essid_mask=essid_mask,
                        require_ht=require_ht,
                        ieee80211n=ieee80211n,
                        wmm_enabled=wmm_enabled,
                        ht_capab=ht_capab,
                        wmm_ac_bk_cwmin=wmm_ac_bk_cwmin,
                        wmm_ac_bk_cwmax=wmm_ac_bk_cwmax,
                        wmm_ac_bk_aifs=wmm_ac_bk_aifs,
                        wmm_ac_bk_txop_limit=wmm_ac_bk_txop_limit,
                        wmm_ac_bk_acm=wmm_ac_bk_acm,
                        wmm_ac_be_aifs=wmm_ac_be_aifs,
                        wmm_ac_be_cwmin=wmm_ac_be_cwmin,
                        wmm_ac_be_cwmax=wmm_ac_be_cwmax,
                        wmm_ac_be_txop_limit=wmm_ac_be_txop_limit,
                        wmm_ac_be_acm=wmm_ac_be_acm,
                        wmm_ac_vi_aifs=wmm_ac_vi_aifs,
                        wmm_ac_vi_cwmin=wmm_ac_vi_cwmin,
                        wmm_ac_vi_cwmax=wmm_ac_vi_cwmax,
                        wmm_ac_vi_txop_limit=wmm_ac_vi_txop_limit,
                        wmm_ac_vi_acm=wmm_ac_vi_acm,
                        wmm_ac_vo_aifs=wmm_ac_vo_aifs,
                        wmm_ac_vo_cwmin=wmm_ac_vo_cwmin,
                        wmm_ac_vo_cwmax=wmm_ac_vo_cwmax,
                        wmm_ac_vo_txop_limit=wmm_ac_vo_txop_limit,
                        wmm_ac_vo_acm=wmm_ac_vo_acm,
                        tx_queue_data3_aifs=tx_queue_data3_aifs,
                        tx_queue_data3_cwmin=tx_queue_data3_cwmin,
                        tx_queue_data3_cwmax=tx_queue_data3_cwmax,
                        tx_queue_data3_burst=tx_queue_data3_burst,
                        tx_queue_data2_aifs=tx_queue_data2_aifs,
                        tx_queue_data2_cwmin=tx_queue_data2_cwmin,
                        tx_queue_data2_cwmax=tx_queue_data2_cwmax,
                        tx_queue_data2_burst=tx_queue_data2_burst,
                        tx_queue_data1_aifs=tx_queue_data1_aifs,
                        tx_queue_data1_cwmin=tx_queue_data1_cwmin,
                        tx_queue_data1_cwmax=tx_queue_data1_cwmax,
                        tx_queue_data1_burst=tx_queue_data1_burst,
                        tx_queue_data0_aifs=tx_queue_data0_aifs,
                        tx_queue_data0_cwmin=tx_queue_data0_cwmin,
                        tx_queue_data0_cwmax=tx_queue_data0_cwmax,
                        tx_queue_data0_burst=tx_queue_data0_burst,
                        ieee80211ac=ieee80211ac,
                        require_vht=require_vht,
                        vht_oper_chwidth=vht_oper_chwidth,
                        vht_operations=vht_operations,
                        vht_capability=vht_capability,
                        ieee80211ax=ieee80211ax,
                        require_he=require_he,
                        he_su_beamformer=he_su_beamformer,
                        he_su_beamformee=he_su_beamformee,
                        he_mu_beamformer=he_mu_beamformer,
                        he_bss_color=he_bss_color,
                        he_default_pe_duration=he_default_pe_duration,
                        he_basic_mcs_nss_set=he_basic_mcs_nss_set,
                        wpa=wpa,
                        wpa_passphrase=wpa_passphrase,
                        wpa_pairwise=wpa_pairwise,
                        rsn_pairwise=rsn_pairwise
                    ))

            except Exception as e:
                print("[!] Error: %s" % e)
                return 1

    class WpaEapCnf:

        import config
        from core.templates.hostapd import hostapd_wifi6_cnf

        path = config.hostapd_conf_full
        template = hostapd_wifi6_cnf.hostapd_wifi6_wpa_eap_cnf

        @classmethod
        def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            beacon_interval=None,
            hw_mode=None,
            channel=None,
            country_code=None,
            ieee80211d=None,
            ieee80211h=None,
            bssid=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            ap_isolate=None,
            essid_mask=None,
            require_ht=None,
            ieee80211n=None,
            wmm_enabled=None,
            ht_capab=None,
            wmm_ac_bk_cwmin=None,
            wmm_ac_bk_cwmax=None,
            wmm_ac_bk_aifs=None,
            wmm_ac_bk_txop_limit=None,
            wmm_ac_bk_acm=None,
            wmm_ac_be_aifs=None,
            wmm_ac_be_cwmin=None,
            wmm_ac_be_cwmax=None,
            wmm_ac_be_txop_limit=None,
            wmm_ac_be_acm=None,
            wmm_ac_vi_aifs=None,
            wmm_ac_vi_cwmin=None,
            wmm_ac_vi_cwmax=None,
            wmm_ac_vi_txop_limit=None,
            wmm_ac_vi_acm=None,
            wmm_ac_vo_aifs=None,
            wmm_ac_vo_cwmin=None,
            wmm_ac_vo_cwmax=None,
            wmm_ac_vo_txop_limit=None,
            wmm_ac_vo_acm=None,
            tx_queue_data3_aifs=None,
            tx_queue_data3_cwmin=None,
            tx_queue_data3_cwmax=None,
            tx_queue_data3_burst=None,
            tx_queue_data2_aifs=None,
            tx_queue_data2_cwmin=None,
            tx_queue_data2_cwmax=None,
            tx_queue_data2_burst=None,
            tx_queue_data1_aifs=None,
            tx_queue_data1_cwmin=None,
            tx_queue_data1_cwmax=None,
            tx_queue_data1_burst=None,
            tx_queue_data0_aifs=None,
            tx_queue_data0_cwmin=None,
            tx_queue_data0_cwmax=None,
            tx_queue_data0_burst=None,
            ieee80211ac=None,
            require_vht=None,
            vht_oper_chwidth=None,
            vht_operations=None,
            vht_capability=None,
            ieee80211ax=None,
            require_he=None,
            he_su_beamformer=None,
            he_su_beamformee=None,
            he_mu_beamformer=None,
            he_bss_color=None,
            he_default_pe_duration=None,
            he_basic_mcs_nss_set=None,
            wpa=None,
            wpa_pairwise=None,
            rsn_pairwise=None,
            ieee8021x=None,
            eapol_version=None,
            eapol_workaround=None,
            own_ip_addr=None,
            auth_server_addr=None,
            auth_server_port=None,
            auth_server_shared_secret=None,
            acct_server_addr=None,
            acct_server_port=None,
            acct_server_shared_secret=None,
            eap_user_file=None,
            ca_pem=None,
            server_pem=None,
            private_key=None,
            private_key_passwd=None,
            dh_file=None
        ):

            assert driver is not None
            assert interface is not None
            assert ssid is not None
            assert beacon_interval is not None
            assert hw_mode is not None
            assert channel is not None
            assert country_code is not None
            assert ieee80211d is not None
            assert ieee80211h is not None
            assert bssid is not None
            assert macaddr_acl is not None
            assert macaddr_accept_file is not None
            assert macaddr_deny_file is not None
            assert ap_isolate is not None
            assert essid_mask is not None
            assert require_ht is not None
            assert ieee80211n is not None
            assert wmm_enabled is not None
            assert ht_capab is not None
            assert wmm_ac_bk_cwmin is not None
            assert wmm_ac_bk_cwmax is not None
            assert wmm_ac_bk_aifs is not None
            assert wmm_ac_bk_txop_limit is not None
            assert wmm_ac_bk_acm is not None
            assert wmm_ac_be_aifs is not None
            assert wmm_ac_be_cwmin is not None
            assert wmm_ac_be_cwmax is not None
            assert wmm_ac_be_txop_limit is not None
            assert wmm_ac_be_acm is not None
            assert wmm_ac_vi_aifs is not None
            assert wmm_ac_vi_cwmin is not None
            assert wmm_ac_vi_cwmax is not None
            assert wmm_ac_vi_txop_limit is not None
            assert wmm_ac_vi_acm is not None
            assert wmm_ac_vo_aifs is not None
            assert wmm_ac_vo_cwmin is not None
            assert wmm_ac_vo_cwmax is not None
            assert wmm_ac_vo_txop_limit is not None
            assert wmm_ac_vo_acm is not None
            assert tx_queue_data3_aifs is not None
            assert tx_queue_data3_cwmin is not None
            assert tx_queue_data3_cwmax is not None
            assert tx_queue_data3_burst is not None
            assert tx_queue_data2_aifs is not None
            assert tx_queue_data2_cwmin is not None
            assert tx_queue_data2_cwmax is not None
            assert tx_queue_data2_burst is not None
            assert tx_queue_data1_aifs is not None
            assert tx_queue_data1_cwmin is not None
            assert tx_queue_data1_cwmax is not None
            assert tx_queue_data1_burst is not None
            assert tx_queue_data0_aifs is not None
            assert tx_queue_data0_cwmin is not None
            assert tx_queue_data0_cwmax is not None
            assert tx_queue_data0_burst is not None
            assert ieee80211ac is not None
            assert require_vht is not None
            assert vht_oper_chwidth is not None
            assert vht_operations is not None
            assert vht_capability is not None
            assert ieee80211ax is not None
            assert require_he is not None
            assert he_su_beamformer is not None
            assert he_su_beamformee is not None
            assert he_mu_beamformer is not None
            assert he_bss_color is not None
            assert he_default_pe_duration is not None
            assert he_basic_mcs_nss_set is not None
            assert wpa is not None
            assert wpa_pairwise is not None
            assert rsn_pairwise is not None
            assert ieee8021x is not None
            assert eapol_version is not None
            assert eapol_workaround is not None
            assert own_ip_addr is not None
            assert auth_server_addr is not None
            assert auth_server_port is not None
            assert auth_server_shared_secret is not None
            assert acct_server_addr is not None
            assert acct_server_port is not None
            assert acct_server_shared_secret is not None
            assert eap_user_file is not None
            assert ca_pem is not None
            assert server_pem is not None
            assert private_key is not None
            assert private_key_passwd is not None
            assert dh_file is not None

            try:
                print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)

                with open(cls.path, 'w') as fd:
                    fd.write(cls.template.format(
                        driver=driver,
                        interface=interface,
                        ssid=ssid,
                        beacon_interval=beacon_interval,
                        hw_mode=hw_mode,
                        channel=channel,
                        country_code=country_code,
                        ieee80211d=ieee80211d,
                        ieee80211h=ieee80211h,
                        bssid=bssid,
                        macaddr_acl=macaddr_acl,
                        macaddr_accept_file=macaddr_accept_file,
                        macaddr_deny_file=macaddr_deny_file,
                        ap_isolate=ap_isolate,
                        essid_mask=essid_mask,
                        require_ht=require_ht,
                        ieee80211n=ieee80211n,
                        wmm_enabled=wmm_enabled,
                        ht_capab=ht_capab,
                        wmm_ac_bk_cwmin=wmm_ac_bk_cwmin,
                        wmm_ac_bk_cwmax=wmm_ac_bk_cwmax,
                        wmm_ac_bk_aifs=wmm_ac_bk_aifs,
                        wmm_ac_bk_txop_limit=wmm_ac_bk_txop_limit,
                        wmm_ac_bk_acm=wmm_ac_bk_acm,
                        wmm_ac_be_aifs=wmm_ac_be_aifs,
                        wmm_ac_be_cwmin=wmm_ac_be_cwmin,
                        wmm_ac_be_cwmax=wmm_ac_be_cwmax,
                        wmm_ac_be_txop_limit=wmm_ac_be_txop_limit,
                        wmm_ac_be_acm=wmm_ac_be_acm,
                        wmm_ac_vi_aifs=wmm_ac_vi_aifs,
                        wmm_ac_vi_cwmin=wmm_ac_vi_cwmin,
                        wmm_ac_vi_cwmax=wmm_ac_vi_cwmax,
                        wmm_ac_vi_txop_limit=wmm_ac_vi_txop_limit,
                        wmm_ac_vi_acm=wmm_ac_vi_acm,
                        wmm_ac_vo_aifs=wmm_ac_vo_aifs,
                        wmm_ac_vo_cwmin=wmm_ac_vo_cwmin,
                        wmm_ac_vo_cwmax=wmm_ac_vo_cwmax,
                        wmm_ac_vo_txop_limit=wmm_ac_vo_txop_limit,
                        wmm_ac_vo_acm=wmm_ac_vo_acm,
                        tx_queue_data3_aifs=tx_queue_data3_aifs,
                        tx_queue_data3_cwmin=tx_queue_data3_cwmin,
                        tx_queue_data3_cwmax=tx_queue_data3_cwmax,
                        tx_queue_data3_burst=tx_queue_data3_burst,
                        tx_queue_data2_aifs=tx_queue_data2_aifs,
                        tx_queue_data2_cwmin=tx_queue_data2_cwmin,
                        tx_queue_data2_cwmax=tx_queue_data2_cwmax,
                        tx_queue_data2_burst=tx_queue_data2_burst,
                        tx_queue_data1_aifs=tx_queue_data1_aifs,
                        tx_queue_data1_cwmin=tx_queue_data1_cwmin,
                        tx_queue_data1_cwmax=tx_queue_data1_cwmax,
                        tx_queue_data1_burst=tx_queue_data1_burst,
                        tx_queue_data0_aifs=tx_queue_data0_aifs,
                        tx_queue_data0_cwmin=tx_queue_data0_cwmin,
                        tx_queue_data0_cwmax=tx_queue_data0_cwmax,
                        tx_queue_data0_burst=tx_queue_data0_burst,
                        ieee80211ac=ieee80211ac,
                        require_vht=require_vht,
                        vht_oper_chwidth=vht_oper_chwidth,
                        vht_operations=vht_operations,
                        vht_capability=vht_capability,
                        ieee80211ax=ieee80211ax,
                        require_he=require_he,
                        he_su_beamformer=he_su_beamformer,
                        he_su_beamformee=he_su_beamformee,
                        he_mu_beamformer=he_mu_beamformer,
                        he_bss_color=he_bss_color,
                        he_default_pe_duration=he_default_pe_duration,
                        he_basic_mcs_nss_set=he_basic_mcs_nss_set,
                        wpa=wpa,
                        wpa_pairwise=wpa_pairwise,
                        rsn_pairwise=rsn_pairwise,
                        ieee8021x=ieee8021x,
                        eapol_version=eapol_version,
                        eapol_workaround=eapol_workaround,
                        own_ip_addr=own_ip_addr,
                        auth_server_addr=auth_server_addr,
                        auth_server_port=auth_server_port,
                        auth_server_shared_secret=auth_server_shared_secret,
                        acct_server_addr=acct_server_addr,
                        acct_server_port=acct_server_port,
                        acct_server_shared_secret=acct_server_shared_secret,
                        eap_user_file=eap_user_file,
                        ca_pem=ca_pem,
                        server_pem=server_pem,
                        private_key=private_key,
                        private_key_passwd=private_key_passwd, # unused
                        dh_file=dh_file,
                    ))

            except Exception as e:
                print("[!] Error: %s" % e)
                return 1

