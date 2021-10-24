---
layout: default
title: Get Started
nav_order: 3
has_children: false
has_toc: false
permalink: /get-started
---

# Getting Started

## Table of Contents
{: .no_toc .text-delta }

{:toc}

---

## Usage


```
usage: python rogue.py -i wlan0 -h g -c 6 -e rogue --auth open --internet

The Rogue Toolkit is an extensible toolkit aimed at providing penetration
testers an easy-to-use platform to deploy software-defined Access Points (AP)
for the purpose of conducting penetration testing and red team engagements. By
using Rogue, penetration testers can easily perform targeted evil twin attacks
against a variety of wireless network types.

optional arguments:
  -w PCAP_FILENAME, --write PCAP_FILENAME
                        Write all collected wireless frames to a pcap file.
  -m HOSTAPD_MANUAL_CONF, --manual HOSTAPD_MANUAL_CONF
                        Loads a custom hostapd config file instead of
                        dynamically generating a file
  --internet            Provide network access
  --auth {open,wep,wpa-personal,wpa-enterprise}
                        Specify auth type. (Default: open)
  --cert-wizard         Use this flag to create a new RADIUS cert for your AP
  --clone-wizard        Used to clone a target website
  --show-options        Display configured options.
  -i INTERFACE, --interface INTERFACE
                        The phy interface on which to create the AP

hostapd configuration:
  --driver {hostap,nl80211,atheros,wired,none,bsd}
                        Choose the hostapd-wpe driver
  -d                    show more hostapd-wpe debug messages
  -dd                   show even more hostapd-wpe debug messages

Attack Arguments:
  --karma               Enable Karma.
  --sslsplit            Enable sslsplit.
  --responder           Enable responder using default configuration.
  --essid-mask {0,1,2}  Send empty SSID in beacons and ignore probe request
                        frames that do not specify full SSID. 1 = send empty
                        (length=0) SSID in beacon and ignore probe request for
                        broadcast SSID 2 = clear SSID (ASCII 0), but keep the
                        original length (this may be required with some
                        clients that do not support empty SSID) and ignore
                        probe requests for broadcast SSID (Default: 0)
  --hostile-portal      Enable hostile portal.
  --hostile-mode {beef,responder}
                        Select attack type performed by hostile portal.
  --hostile-location HOSTILE_LOCATION
                        Used to specify the location of the cloned site
                        location. Note: httrack creates a new directory within
                        the destination location with the name of the site
                        cloned. (Default: /var/www/html)
  --target-file TARGET_FILE
                        Used to specify the file in which the hostile portal
                        hook will be inserted into. (Default: /index.html)
  --hostile-marker HOSTILE_MARKER
                        Specify the line in the file target file to insert the
                        web hook above. (Default: </body> )
  --hostile-hook HOSTILE_HOOK
                        Specify custom hook code to insert into the target
                        file

IEEE 802.11 related configuration:
  -b BSSID, --bssid BSSID
                        Specify access point BSSID (Default:
                        00:11:22:33:44:00)
  -e ESSID, --essid ESSID
                        Specify access point ESSID (Default: rogue)
  -h {a,b,g,n,ac}, --hw-mode {a,b,g,n,ac}
                        Specify access point hardware mode (Default: g).
  --freq {2,5}          Specify the radio band to use (Default: 2GHz).
  -c CHANNEL, --channel CHANNEL
                        Specify access point channel. (Default: 0 - with ACS
                        to find an unused channel)
  --country {AD,AE,AF,AG,AI,AL,AM,AO,AQ,AR,AS,AT,AU,AW,AX,AZ,BA,BB,BD,BE,BF,BG,BH,BI,BJ,BL,BM,BN,BO,BQ,BQ,BR,BS,BT,BV,BW,BY,BZ,CA,CC,CD,CF,CG,CH,CI,CK,CL,CM,CN,CO,CR,CU,CV,CW,CX,CY,CZ,DE,DJ,DK,DM,DO,DZ,EC,EE,EG,EH,ER,ES,ET,FI,FJ,FK,FM,FO,FR,GA,GB,GD,GE,GF,GG,GH,GI,GL,GM,GN,GP,GQ,GR,GS,GT,GU,GW,GY,HK,HM,HN,HR,HT,HU,ID,IE,IL,IM,IN,IO,IQ,IR,IS,IT,JE,JM,JO,JP,KE,KG,KH,KI,KM,KN,KP,KR,KW,KY,KZ,LA,LB,LC,LI,LK,LR,LS,LT,LU,LV,LY,MA,MC,MD,ME,MF,MG,MH,MK,ML,MM,MN,MO,MP,MQ,MR,MS,MT,MU,MV,MW,MX,MY,MZ,NA,NC,NE,NF,NG,NI,NL,NO,NP,NR,NU,NZ,OM,PA,PE,PF,PG,PH,PK,PL,PM,PN,PR,PS,PT,PW,PY,QA,RE,RO,RS,RU,RW,SA,SB,SC,SD,SE,SG,SH,SI,SJ,SK,SL,SM,SN,SO,SR,SS,ST,SV,SX,SY,SZ,TC,TD,TF,TG,TH,TJ,TK,TL,TM,TN,TO,TR,TT,TV,TW,TZ,UA,UG,UM,US,UY,UZ,VA,VC,VE,VG,VI,VN,VU,WF,WS,YE,YT,ZA,ZM,ZW}
                        Configures of country of operation
  --macaddr-acl {0,1,2}
                        Station MAC address -based authentication 0 = accept
                        unless in deny list 1 = deny unless in accept list 2 =
                        use external RADIUS (accept/deny will be searched
                        first) (Default: 0)
  --mac-accept-file MACADDR_ACCEPT_FILE
                        Location of hostapd-wpe macaddr_acl accept file
                        (Default: /home/rogue/tmp/hostapd.accept)
  --mac-deny-file MACADDR_DENY_FILE
                        Location of hostapd-wpe macaddr_acl deny file
                        (Default: /home/rogue/tmp/hostapd.accept)
  --auth-algs {1,2,3}   IEEE 802.11 specifies two authentication algorithms. 1
                        allows only WPA2 authentication algorithms. 2 is WEP.
                        3 allows both. (Default: 3)
  --wmm-enabled         Enable Wireless Multimedia Extensions
  --ieee80211d          Enabling IEEE 802.11d advertises the country_code and
                        the set of allowed channels and transmit power levels
                        based on the regulatory limits. (Default: False)
  --ieee80211h          Enables radar detection and DFS support. DFS support
                        is required for an outdoor 5 GHZ channel. (This can
                        only be used if ieee80211d is enabled). (Default:
                        False)
  --ap-isolate          Enable client isolation to prevent low-level bridging
                        of frames between associated stations in the BSS.
                        (Default: disabled)

IEEE 802.11n related configuration:
  --ht-mode {0,1,2}     Configure supported channel width set 0 = Feature
                        disabled 1 = [HT40-] (2.4 GHz = 5-13, 5 GHz =
                        40,48,56,64) 2 = [HT40+] (2.4 GHz = 1-7 (1-9 in
                        Europe/Japan), 5 GHz = 36,44,52,60) (Default = 0).
  --disable-short20     Disables Short GI for 20 MHz for HT capabilities.
  --disable-short40     Disables Short GI for 40 MHz for HT capabilities.
  --require-ht          Require stations to support HT PHY (reject association
                        if they do not). (Default: False)

IEEE 802.11ac related configuration:
  --vht-width {0,1,2,3}
                        VHT channel width (Default: 1).
  --vht-operation {0,1}
                        Enable toggling between 0 for
                        vht_oper_centr_freq_seg0_idx and 1 for
                        vht_oper_centr_freq_seg1_idx (Default: 0).
  --vht-index VHT_INDEX
                        Enables control of vht_oper_centr_freq_seg[0/1]_idx
                        index value (Default: 42).
  --require-vht         Require stations to support VHT PHY (reject
                        association if they do not) (Default: disabled).

IWPA/IEEE 802.11i configuration:
  --wpa-passphrase WPA_PASSPHRASE
                        Specify the Pre-Shared Key for WPA network.
  --wpa {1,2,3}         Specify WPA type (Default: 2).
  --wpa-pairwise {CCMP,TKIP,CCMP TKIP}
                        (Default: 'CCMP TKIP')
  --rsn-pairwise {CCMP,TKIP,CCMP TKIP}
                        (Default: 'CCMP')

WEP authentication configuration:
  --wep-key-version {0,1,2,3}
                        Determine the version of the WEP configuration
  --wep-key WEP_KEY     Determine the version of the WEP configuration

IEEE 802.1X-2004 configuration:
  --ieee8021x           Enable 802.1x
  --eapol-version {1,2}
                        IEEE 802.1X/EAPOL version (Default: 2)
  --eapol-workaround    EAPOL-Key index workaround (set bit7) for WinXP
                        Supplicant

RADIUS client configuration:
  --no-log-badpass      When set, incorrect passwords will not be logged
  --no-log-goodpass     When set, valid passwords will not be logged
  --own-address OWN_IP_ADDR
                        The own IP address of the access point (Default:
                        127.0.0.1)
  --auth-server-addr AUTH_SERVER_ADDR
                        IP address of radius authentication server (Default:
                        127.0.0.1)
  --auth-secret AUTH_SERVER_SHARED_SECRET
                        Radius authentication server shared secret (Default:
                        secret)
  --auth-server-port AUTH_SERVER_PORT
                        Networking port of radius authentication server
                        (Default: 1812)
  --acct-server-addr ACCT_SERVER_ADDR
                        IP address of radius accounting server (Default:
                        127.0.0.1)
  --acct-secret ACCT_SERVER_SHARED_SECRET
                        Radius accounting server shared secret
  --acct-server-port ACCT_SERVER_PORT
                        Networking port of radius accounting server (Default:
                        1813)
  --radius-proto {udp,tcp,*}
                        (Default: *)
  --default-eap {fast,peap,ttls,tls,leap,pwd,md5,gtc}
                        Specify the default EAP method used in RADIUS
                        authentication. (Default: md5)
  -E {all,fast,peap,ttls,tls,leap,pwd,md5,gtc}, --supported-eap {all,fast,peap,ttls,tls,leap,pwd,md5,gtc}
                        Specify the default EAP method used in RADIUS
                        authentication. (Default: md5)
  --print-creds         Print intercepted credentials

External DHCP configuration:
  --lease DEFAULT_LEASE_TIME
                        Define DHCP lease time (Default: 600)
  --max-lease MAX_LEASE_TIME
                        Define max DHCP lease time (Default: 7200)
  --prim-name-server PRIMARY_NAME_SERVER
                        Define primary name server (Default: 8.8.8.8)
  --sec-name-server SECONDARY_NAME_SERVER
                        Define secondary name server (Default: 8.8.4.4)
  --subnet DHCP_SUBNET  (Default: 10.254.239.0)
  --route-subnet ROUTE_SUBNET
                        (Default: 10.254.239)
  --netmask DHCP_NETMASK
                        (Default: 255.255.255.0)
  --ip-address IP_ADDRESS
                        (Default: 10.254.239.1)
  --secondary-interface SECONDARY_INTERFACE
                        Used to specify the second phy interface used to
                        bridge the hostapd-wpe interface (-i) with another
                        network (Default: eth0)
  --pool-start DHCP_POOL_START
                        (Default: 10.254.239.10)
  --pool-end DHCP_POOL_END
                        (Default: 10.254.239.70)

Website cloning configuration:
  --clone-target CLONE_TARGET
                        Used to specify target website to clone (e.g.
                        https://www.example.com/)
  --clone-dest CLONE_DEST
                        Specify the location of the web root for the hostile
                        portal, it is recommended that you clone to your web
                        root. Note: httrack will create a directory in this
                        location with the name of the site cloned. (Default:
                        /var/www/html)

sslsplit configuration:
  --cert-nopass         Generate a x.509 Certificate with no password for the
                        purpose of sslsplit.
  --encrypted-port SSLSPLIT_ENCRYPTED_PORT
                        Specify port for encrypted web communication (TCP/443)
                        be redirected to. (Default: 8443)

HTTPD configuration:
  --httpd-port HTTPD_PORT
                        defines the port for httpd service to listen on.
                        (Default: 80)
  --httpd-ssl-port HTTP_SSL_PORT
                        Defines port for SSL-enabled httpd service to listen
                        on. (Default: 443)
  --ssl                 Enable ssl version of rogue httpd. When enabled,
                        --httpd-ssl-port overwrites --httpd-port. (Default:
                        443)
```

---

## Dependencies

Rogue is a Python3 project, built to run on debian systems such as Kali Linux and Ubuntu. As a toolkit, Rogue is used to automatically configure a number of applications in consistent manner to provide the testing platform, these applications include:
* hostapd-wpe
* freeradius-wpe
* isc-dhcp-server
* Apache 2.0
* sslsplit
* responder
* beef
* tcpdump

---
