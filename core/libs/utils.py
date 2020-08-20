#!/usr/bin/python3
import os
import time
import config
from tqdm import tqdm

def sleep_bar(sleep_time, text=''):

    print()
    
    if text:

        print(text)
        print()

    interval = sleep_time % 1
    if interval == 0:
        interval = 1
        iterations = sleep_time
    else:
        iterations = sleep_time / interval

    for i in tqdm(range(iterations)):
        time.sleep(interval)

    print()
        

class Service(object):

    @classmethod
    def start(cls, verbose=True):

        if config.use_systemd:
            os.system('systemctl start %s' % cls.service_name)
        else:
            os.system('service %s start' % cls.service_name)
        
        if verbose:
            sleep_bar(cls.sleep_time, '[*] Starting %s service.' % cls.service_name)
        else:
            time.sleep(cls.sleep_time)

    @classmethod
    def status(cls, verbose=True):

        if config.use_systemd:
            os.system('echo "`systemctl status %s`"' % cls.service_name)
        else:
            os.system('service %s status' % cls.service_name)

        if verbose:
            sleep_bar(cls.sleep_time, '[*] Getting status of %s service.' % cls.service_name)
        else:
            time.sleep(cls.sleep_time)

    @classmethod
    def stop(cls, verbose=True):

        if config.use_systemd:
            os.system('systemctl stop %s' % cls.service_name)
        else:
            os.system('service %s stop' % cls.service_name)

        if verbose:
            sleep_bar(cls.sleep_time, '[*] stopping %s service.' % cls.service_name)
        else:
            time.sleep(cls.sleep_time)


    @classmethod
    def kill(cls, verbose=True):

        killname = os.path.basename(os.path.normpath(cls.bin_path))
        os.system('for i in `pgrep %s`; do kill $i; done' % killname)

        if verbose:
            sleep_bar(cls.sleep_time, '[*] Killing all processes for: %s' % killname)
        else:
            time.sleep(cls.sleep_time)

    @classmethod
    def kill_by_name(cls, verbose=True):

        killname = os.path.basename(os.path.normpath(cls.bin_Killname))
        os.system('for i in `pgrep %s`; do kill $i; done' % killname)

        if verbose:
            sleep_bar(cls.sleep_time, '[*] Killing all processes for: %s' % killname)
        else:
            time.sleep(cls.sleep_time)

    @classmethod
    def hardstart(cls, args='', background=True, verbose=True):

        if background:
            os.system('%s %s &' % (cls.bin_path, args))
        else:
            os.system('%s %s' % (cls.bin_path, args))

        if verbose:
            sleep_bar(cls.sleep_time, '[*] Starting process: %s' % cls.bin_path)
        else:
            time.sleep(cls.sleep_time)

class NetworkManager(Service):
    
    service_name =  config.network_manager
    bin_path = config.network_manager_bin
    sleep_time = config.network_manager_sleep

class IscDhcpServer(Service):
    
    service_name =  config.dhcp_server
    bin_path = config.dhcp_server_bin
    sleep_time = config.dhcp_server_sleep

class Hostapd(Service):

    service_name = None
    bin_path = config.hostapd_bin
    sleep_time = config.hostapd_sleep

class Freeradius(Service):

    service_name = None
    bin_path = config.freeradius_bin
    sleep_time = config.freeradius_sleep

class Beef(Service):

    service_name = config.beef
    bin_path = None
    sleep_time = config.beef_sleep

class Sslsplit(Service):

    service_name = None
    bin_path = config.sslsplit_bin
    sleep_time = config.sslsplit_sleep

class Responder(Service):

    service_name = None
    bin_path = config.responder_bin
    bin_Killname = 'Responder'
    sleep_time = config.responder_sleep

class WPASupplicant(Service):

    service_name = config.wpa_supplicant
    bin_path = config.wpa_supplicant_bin
    sleep_time = config.wpa_supplicant_sleep

class Tcpdump(Service):

    service_name = None
    bin_path = config.tcpdump_bin
    sleep_time = config.tcpdump_sleep

def wlan_clean(iface, verbose=True):

    os.system('nmcli radio wifi off')
    os.system('rfkill unblock wlan')
    os.system('ifconfig %s up' % iface)
    if verbose:
        sleep_bar(config.wlan_clean_sleep, '[*] Reticulating radio frequency splines...')
    else:
        time.sleep(config.wlan_clean_sleep)

class nmcli(object):

    @staticmethod
    def set_managed(iface):
        os.system('nmcli device set %s managed yes' % iface)
        sleep_bar(1, '[*] Reticulating radio frequency splines...')

    @staticmethod
    def set_unmanaged(iface):
        os.system('nmcli device set %s managed no' % iface)
        sleep_bar(1, '[*] Reticulating radio frequency splines...')

def set_ipforward(value):

    with open(config.proc_ipforward, 'w') as fd:
        fd.write('%d' % int(value))

class Httpd(Service):

    service_name = config.httpd
    bin_path = config.httpd_bin
    sleep_time = config.hostapd_sleep

    @staticmethod
    def enableModule():
        os.system("a2enmod ssl")

    @staticmethod
    def disableModule():
        os.system("a2dismod ssl")

    @staticmethod
    def enableSite(site_name):
        os.system("a2ensite %s" % site_name)

    @staticmethod
    def enableDefault():
        os.system("a2ensite 000-default")

    @staticmethod
    def disableSite(site_name, sites_available):
        os.system("a2dissite %s" % site_name)
        os.chdir(sites_available)
        os.system("rm %s" % (site_name))

    @staticmethod
    def disableDefault():
        os.system("a2dissite 000-default")


class Iptables(object):

    @staticmethod
    def accept_all():
        os.system('iptables --policy INPUT ACCEPT')
        os.system('iptables --policy FORWARD ACCEPT')
        os.system('iptables --policy OUTPUT ACCEPT')
   
    @staticmethod
    def flush(table=None):
        if table is None:
            os.system('iptables -F')
        else:
            os.system('iptables -t %s -F' % table)

    @staticmethod
    def isc_dhcp_server_rules(addr, iface, iface2):

        os.system('iptables -t nat -A POSTROUTING -o %s -j MASQUERADE' % (iface2))
        os.system('iptables -A FORWARD -i %s -o %s -m state --state RELATED,ESTABLISHED -j ACCEPT' % (iface2, iface))
        os.system('iptables -A FORWARD -i %s -o %s -j ACCEPT' % (iface, iface2))

    @staticmethod
    def sslsplit_rules(sslsplit_encrypted_port):
        os.system('iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports %d' % sslsplit_encrypted_port)

def set_reg():
    os.system('iw reg set 00')