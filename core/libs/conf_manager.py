#!/usr/bin/python
import os

import config
from core.templates import hostapd_cnf
from core.templates import dhcpd_cnf
from core.templates import freeradius_cnf
from core.templates import httpd_cnf
from core.templates import responder_cnf

class responder_default_conf(object):
    path = config.responder_conf
    template = responder_cnf.responder_default_conf

    @classmethod
    def configure(cls):

        try:
            print("[+] Creating Responder.conf file: %s" % cls.path)
            with open(cls.path, 'w') as fd:
                fd.write(cls.template)
        except Exception as e:
            print("[!] Error: %s" % e)
            return 1

class responder_no_http_conf(object):
    path = config.responder_conf
    template = responder_cnf.responder_no_http_conf

    @classmethod
    def configure(cls):

        try:
            print("[+] Creating Responder.conf file: %s" % cls.path)
            with open(cls.path, 'w') as fd:
                fd.write(cls.template)
        except Exception as e:
            print("[!] Error: %s" % e)
            return 1

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

class freeradius_eap_conf(object):

    path = config.freeradius_mods_dir_eap_full
    template = freeradius_cnf.freeradius_eap_conf

    @classmethod
    def configure(cls,
            default_eap_type=None,
            private_key_file=None,
            certificate_file=None,
            ca_file=None,
            dh_file=None,
            ca_path=None
            ):

        assert default_eap_type is not None
        assert private_key_file is not None
        assert certificate_file is not None
        assert ca_file is not None
        assert dh_file is not None
        assert ca_path is not None

        try:
            print("[+] Creating eap.conf file: %s" % cls.path)
            with open(cls.path, 'w') as fd:
                fd.write(cls.template %\
                    (default_eap_type, private_key_file, certificate_file, ca_file, dh_file, ca_path))
        except Exception as e:
            print("[!] Error: %s" % e)
            return 1


class freeradius_eap_fast_conf(object):

    path = config.freeradius_mods_dir_eap_full
    template = freeradius_cnf.freeradius_eap_fast_conf

    @classmethod
    def configure(cls,
            default_eap_type=None
            ):

        assert default_eap_type is not None

        try:
            print("[+] Creating eap.conf file: %s" % cls.path)
            with open(cls.path, 'w') as fd:
                fd.write(cls.template %\
                    (default_eap_type))
        except Exception as e:
            print("[!] Error: %s" % e)
            return 1

class freeradius_eap_md5_conf(object):

    path = config.freeradius_mods_dir_eap_full
    template = freeradius_cnf.freeradius_eap_md5_conf

    @classmethod
    def configure(cls,
            default_eap_type=None
            ):

        assert default_eap_type is not None

        try:
            print("[+] Creating eap.conf file: %s" % cls.path)
            with open(cls.path, 'w') as fd:
                fd.write(cls.template %\
                    (default_eap_type))
        except Exception as e:
            print("[!] Error: %s" % e)
            return 1

class freeradius_eap_pwd_conf(object):

    path = config.freeradius_mods_dir_eap_full
    template = freeradius_cnf.freeradius_eap_pwd_conf

    @classmethod
    def configure(cls,
            default_eap_type=None
            ):

        assert default_eap_type is not None

        try:
            print("[+] Creating eap.conf file: %s" % cls.path)
            with open(cls.path, 'w') as fd:
                fd.write(cls.template %\
                    (default_eap_type))
        except Exception as e:
            print("[!] Error: %s" % e)
            return 1

class freeradius_eap_leap_conf(object):

    path = config.freeradius_mods_dir_eap_full
    template = freeradius_cnf.freeradius_eap_leap_conf

    @classmethod
    def configure(cls,
            default_eap_type=None
            ):

        assert default_eap_type is not None

        try:
            print("[+] Creating eap.conf file: %s" % cls.path)
            with open(cls.path, 'w') as fd:
                fd.write(cls.template %\
                    (default_eap_type))
        except Exception as e:
            print("[!] Error: %s" % e)
            return 1

class freeradius_eap_gtc_conf(object):

    path = config.freeradius_mods_dir_eap_full
    template = freeradius_cnf.freeradius_eap_gtc_conf

    @classmethod
    def configure(cls,
            default_eap_type=None
            ):

        assert default_eap_type is not None

        try:
            print("[+] Creating eap.conf file: %s" % cls.path)
            with open(cls.path, 'w') as fd:
                fd.write(cls.template %\
                    (default_eap_type))
        except Exception as e:
            print("[!] Error: %s" % e)
            return 1

class freeradius_eap_peap_conf(object):

    path = config.freeradius_mods_dir_eap_full
    template = freeradius_cnf.freeradius_eap_peap_conf

    @classmethod
    def configure(cls,
            default_eap_type=None,
            private_key_file=None,
            certificate_file=None,
            ca_file=None,
            dh_file=None,
            ca_path=None
            ):

        assert default_eap_type is not None
        assert private_key_file is not None
        assert certificate_file is not None
        assert ca_file is not None
        assert dh_file is not None
        assert ca_path is not None

        try:
            print("[+] Creating eap.conf file: %s" % cls.path)
            with open(cls.path, 'w') as fd:
                fd.write(cls.template %\
                    (default_eap_type, private_key_file, certificate_file, ca_file, dh_file, ca_path))
        except Exception as e:
            print("[!] Error: %s" % e)
            return 1

class freeradius_eap_ttls_conf(object):

    path = config.freeradius_mods_dir_eap_full
    template = freeradius_cnf.freeradius_eap_ttls_conf

    @classmethod
    def configure(cls,
            default_eap_type=None,
            private_key_file=None,
            certificate_file=None,
            ca_file=None,
            dh_file=None,
            ca_path=None
            ):

        assert default_eap_type is not None
        assert private_key_file is not None
        assert certificate_file is not None
        assert ca_file is not None
        assert dh_file is not None
        assert ca_path is not None

        try:
            print("[+] Creating eap.conf file: %s" % cls.path)
            with open(cls.path, 'w') as fd:
                fd.write(cls.template %\
                    (default_eap_type, private_key_file, certificate_file, ca_file, dh_file, ca_path))
        except Exception as e:
            print("[!] Error: %s" % e)
            return 1

class freeradius_eap_tls_conf(object):

    path = config.freeradius_mods_dir_eap_full
    template = freeradius_cnf.freeradius_eap_tls_conf

    @classmethod
    def configure(cls,
            default_eap_type=None,
            private_key_file=None,
            certificate_file=None,
            ca_file=None,
            dh_file=None,
            ca_path=None
            ):

        assert default_eap_type is not None
        assert private_key_file is not None
        assert certificate_file is not None
        assert ca_file is not None
        assert dh_file is not None
        assert ca_path is not None

        try:
            print("[+] Creating eap.conf file: %s" % cls.path)
            with open(cls.path, 'w') as fd:
                fd.write(cls.template %\
                    (default_eap_type, private_key_file, certificate_file, ca_file, dh_file, ca_path))
        except Exception as e:
            print("[!] Error: %s" % e)
            return 1

class hostapd_open_cnf(object):

    path = config.hostapd_conf_full
    template = hostapd_cnf.hostapd_open_cnf

    @classmethod
    def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            hw_mode=None,
            ieee80211n=None,
            bssid=None,
            channel=None,
            country_code=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            auth_algs=None,
            essid_mask=None,
            wmm_enabled=None,
            ht_capab=None,
            require_ht=None,
            ieee80211ac=None,
            vht_oper_chwidth=None,
            vht_operations=None,
            require_vht=None,
            ieee80211d=None,
            ieee80211h=None,
            ap_isolate=None
            ):

        assert driver is not None
        assert interface is not None
        assert ssid is not None
        assert hw_mode is not None
        assert ieee80211n is not None
        assert bssid is not None
        assert channel is not None
        assert country_code is not None
        assert macaddr_acl is not None
        assert macaddr_accept_file is not None
        assert macaddr_deny_file is not None
        assert auth_algs is not None
        assert essid_mask is not None
        assert wmm_enabled is not None
        assert ht_capab is not None
        assert require_ht is not None
        assert ieee80211ac is not None
        assert vht_oper_chwidth is not None
        assert vht_operations is not None
        assert require_vht is not None
        assert ieee80211d is not None
        assert ieee80211h is not None
        assert ap_isolate is not None
    
    	try:
            print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)
            with open(cls.path, 'w') as fd:
                fd.write(cls.template %\
                    (driver, interface, bssid, ssid, hw_mode, channel, country_code, ieee80211d, ieee80211h, auth_algs, essid_mask, macaddr_acl, macaddr_accept_file, macaddr_deny_file, wmm_enabled, ap_isolate, ieee80211n, ht_capab, require_ht, ieee80211ac, require_vht, vht_oper_chwidth, vht_operations))
        except Exception as e:
            print("[!] Error: %s" % e)
            return 1

class hostapd_wep_cnf(object):

    path = config.hostapd_conf_full
    template = hostapd_cnf.hostapd_wep_cnf

    @classmethod
    def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            hw_mode=None,
            ieee80211n=None,
            bssid=None,
            channel=None,
            country_code=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            auth_algs=None,
            essid_mask=None,
            wmm_enabled=None,
            ht_capab=None,
            require_ht=None,
            ieee80211ac=None,
            vht_oper_chwidth=None,
            vht_operations=None,
            require_vht=None,
            ieee80211d=None,
            ieee80211h=None,
            ap_isolate=None,
            wep_default_key=None,
            wep_key=None,
            ):

        assert driver is not None
        assert interface is not None
        assert ssid is not None
        assert hw_mode is not None
        assert ieee80211n is not None
        assert bssid is not None
        assert channel is not None
        assert country_code is not None
        assert macaddr_acl is not None
        assert macaddr_accept_file is not None
        assert macaddr_deny_file is not None
        assert auth_algs is not None
        assert essid_mask is not None
        assert wmm_enabled is not None
        assert ht_capab is not None
        assert require_ht is not None
        assert ieee80211ac is not None
        assert vht_oper_chwidth is not None
        assert vht_operations is not None
        assert require_vht is not None
        assert ieee80211d is not None
        assert ieee80211h is not None
        assert ap_isolate is not None
        assert wep_default_key is not None
        assert wep_key is not None
    
        try:
            print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)
            with open(cls.path, 'w') as fd:
                fd.write(cls.template %\
                    (driver, interface, bssid, ssid, hw_mode, channel, country_code, ieee80211d, ieee80211h, auth_algs, essid_mask, macaddr_acl, macaddr_accept_file, macaddr_deny_file, wmm_enabled, ap_isolate, wep_default_key, wep_key, ieee80211n, ht_capab, require_ht, ieee80211ac, require_vht, vht_oper_chwidth, vht_operations))
        except Exception as e:
            print("[!] Error: %s" % e)
            return 1

class hostapd_wpa_psk_cnf(object):

    path = config.hostapd_conf_full
    template = hostapd_cnf.hostapd_wpa_psk_cnf

    @classmethod
    def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            hw_mode=None,
            ieee80211n=None,
            bssid=None,
            channel=None,
            country_code=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            auth_algs=None,
            essid_mask=None,
            wmm_enabled=None,
            ht_capab=None,
            require_ht=None,
            ieee80211ac=None,
            vht_oper_chwidth=None,
            vht_operations=None,
            require_vht=None,
            ieee80211d=None,
            ieee80211h=None,
            ap_isolate=None,
            wpa=None,
            wpa_passphrase=None,
            wpa_pairwise=None,
            rsn_pairwise=None,
            ):

        assert driver is not None
        assert interface is not None
        assert ssid is not None
        assert hw_mode is not None
        assert ieee80211n is not None
        assert bssid is not None
        assert channel is not None
        assert country_code is not None
        assert macaddr_acl is not None
        assert macaddr_accept_file is not None
        assert macaddr_deny_file is not None
        assert auth_algs is not None
        assert essid_mask is not None
        assert wmm_enabled is not None
        assert ht_capab is not None
        assert require_ht is not None
        assert ieee80211ac is not None
        assert vht_oper_chwidth is not None
        assert vht_operations is not None
        assert require_vht is not None
        assert ieee80211d is not None
        assert ieee80211h is not None
        assert ap_isolate is not None
        assert wpa is not None
        assert wpa_passphrase is not None
        assert wpa_pairwise is not None
        assert rsn_pairwise is not None
    
        try:
            print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)
            with open(cls.path, 'w') as fd:
                fd.write(cls.template %\
                    (driver, interface, bssid, ssid, hw_mode, channel, country_code, ieee80211d, ieee80211h, auth_algs, essid_mask, macaddr_acl, macaddr_accept_file, macaddr_deny_file, wmm_enabled, ap_isolate, ieee80211n, ht_capab, require_ht, ieee80211ac, require_vht, vht_oper_chwidth, vht_operations, wpa, wpa_passphrase, wpa_pairwise, rsn_pairwise))
        except Exception as e:
            print("[!] Error: %s" % e)
            return 1

class hostapd_wpa_eap_cnf(object):

    path = config.hostapd_conf_full
    template = hostapd_cnf.hostapd_wpa_eap_cnf

    @classmethod
    def configure(cls,
            driver=None,
            interface=None,
            ssid=None,
            hw_mode=None,
            ieee80211n=None,
            bssid=None,
            channel=None,
            country_code=None,
            macaddr_acl=None,
            macaddr_accept_file=None,
            macaddr_deny_file=None,
            auth_algs=None,
            essid_mask=None,
            wmm_enabled=None,
            ht_capab=None,
            require_ht=None,
            ieee80211ac=None,
            vht_oper_chwidth=None,
            vht_operations=None,
            require_vht=None,
            ieee80211d=None,
            ieee80211h=None,
            ap_isolate=None,
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
            dh_file=None
            ):

        assert driver is not None
        assert interface is not None
        assert ssid is not None
        assert hw_mode is not None
        assert ieee80211n is not None
        assert bssid is not None
        assert channel is not None
        assert country_code is not None
        assert macaddr_acl is not None
        assert macaddr_accept_file is not None
        assert macaddr_deny_file is not None
        assert auth_algs is not None
        assert essid_mask is not None
        assert wmm_enabled is not None
        assert ht_capab is not None
        assert require_ht is not None
        assert ieee80211ac is not None
        assert vht_oper_chwidth is not None
        assert vht_operations is not None
        assert require_vht is not None
        assert ieee80211d is not None
        assert ieee80211h is not None
        assert ap_isolate is not None
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
        assert dh_file is not None

        try:
            print("[+] Creating hostapd-wpe.confg file: %s" % cls.path)
            with open(cls.path, 'w') as fd:
                fd.write(cls.template %\
                    (driver, interface, bssid, eap_user_file, ca_pem, server_pem, private_key, dh_file, ssid, hw_mode, channel, country_code, ieee80211d, ieee80211h, auth_algs, essid_mask, macaddr_acl, macaddr_accept_file, macaddr_deny_file, wmm_enabled, ap_isolate, ieee80211n, ht_capab, require_ht, ieee80211ac, require_vht, vht_oper_chwidth, vht_operations, wpa, wpa_pairwise, rsn_pairwise, ieee8021x, eapol_version, eapol_workaround, own_ip_addr, auth_server_addr, auth_server_port, auth_server_shared_secret, acct_server_addr, acct_server_port, acct_server_shared_secret))
        except Exception as e:
            print("[!] Error: %s" % e)
            return 1

class hostapd_custom_cnf(object):
    path = config.hostapd_conf_full

    @classmethod
    def configure(cls,
        hostapd_location=None
        ):

        assert hostapd_location is not None

        try:
            print("[+] Copying custom hostapd-wpe.conf file to default rogue hostapd-wpe.conf file:\r\n %s -> %s" % (hostapd_location, cls.path))
            os.system('cp %s %s' % (hostapd_location, cls.path))
        except Exception as e:
            print("[!] Error: %s" % e)
            return 1


class http_cnf(object):

    path = config.http_conf_full
    template = httpd_cnf.httpd_conf

    @classmethod
    def configure(cls,
            port=None,
            webroot=None,
            error_log=None,
            custom_log=None
            ):

        assert port is not None
        assert webroot is not None
        assert error_log is not None
        assert custom_log is not None

        try:
            print("[+] Creating %s file: %s" % (config.http_name_conf, cls.path))
            with open(cls.path, 'w') as fd:
                fd.write(cls.template %\
                    (port, webroot, error_log, custom_log))
        except Exception as e:
            print("[!] Error: %s" % e)
            return 1

class http_ssl_cnf(object):

    path = config.http_conf_full
    template = httpd_cnf.httpd_ssl_conf

    @classmethod
    def configure(cls,
            port=None,
            addr=None,
            webroot=None,
            error_log=None,
            custom_log=None,
            server_pem=None,
            private_key=None,
            ):

        assert port is not None
        assert addr is not None
        assert webroot is not None
        assert error_log is not None
        assert custom_log is not None
        assert server_pem is not None
        assert private_key is not None

        try:
            print("[+] Creating %s file: %s" % (config.http_name_conf, cls.path))
            with open(cls.path, 'w') as fd:
                fd.write(cls.template %\
                    (addr, port, webroot, error_log, custom_log, server_pem, private_key))
        except Exception as e:
            print("[!] Error: %s" % e)
            return 1
