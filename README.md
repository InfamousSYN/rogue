The Rogue Toolkit
=================
![GitHub release (latest by date)](https://img.shields.io/github/v/release/infamoussyn/rogue) 
[![Install](https://github.com/InfamousSYN/rogue/actions/workflows/install.yml/badge.svg)](https://github.com/InfamousSYN/rogue/actions/workflows/install.yml)

Getting Started
-----
* [Introduction](https://rogue.infamoussyn.com/)
* [Usage](https://rogue.infamoussyn.com/usage)
* [Installation](https://rogue.infamoussyn.com/get-started/install) toolkit's installation guide
* [Test Cases](https://rogue.infamoussyn.com/test-cases) a collection of Rogue test case examples


Usage
-----

```
usage: sudo python3 /opt/rogue/rogue.py -i wlan0 --auth wpa-enterprise --internet --essid rogue --preset-profile wifi4 --channel-randomiser --default-eap peap

The Rogue Toolkit is an extensible toolkit aimed at providing penetration testers an easy-to-use platform to deploy software-defined Access Points (AP) for the purpose of conducting penetration testing and red team engagements. By
using Rogue, penetration testers can easily perform targeted evil twin attacks against a variety of wireless network types.

For more information: https://rogue.infamoussyn.com/

optional arguments:
  -h, --help            show this help message and exit
  -m HOSTAPD_MANUAL_CONF, --manual HOSTAPD_MANUAL_CONF
                        Loads a custom hostapd config file instead of dynamically generating a file
  --internet            Provide network access
  --auth {open,wep,wpa-personal,wpa-enterprise}
                        Specify auth type. (Default: open)
  --cert-wizard         Use this flag to create a new RADIUS cert for your AP
  --show-options        Display configured options.
  -i INTERFACE, --interface INTERFACE
                        The phy interface on which to create the AP

hostapd configuration:
  --driver {hostap,nl80211,atheros,wired,none,bsd}
                        Choose the hostapd-wpe driver
  -d                    show more hostapd-wpe debug messages
  -dd                   show even more hostapd-wpe debug messages

IEEE 802.11 related configuration:
  -b BSSID, --bssid BSSID
                        Specify access point BSSID (Default: 00:11:22:33:44:00)
  -e ESSID, --essid ESSID
                        Specify access point ESSID (Default: rogue)
  -p {wifi1,wifi2,wifi3,wifi4,wifi5,wifi6}, --preset-profile {wifi1,wifi2,wifi3,wifi4,wifi5,wifi6}
                        Use a preset 802.11 profile
  -hm {a,b,g,n,ac,ax}, --hw-mode {a,b,g,n,ac,ax}
                        Specify access point hardware mode (Default: g).
  --freq {2,5}          Specify the radio band to use (Default: 2GHz).
  --beacon-interval BEACON_INTERVAL
                        Control the beacon interval (Default: 100)
  -c CHANNEL, --channel CHANNEL
                        Specify access point channel. (Default: 0 - with ACS to find an unused channel)
  --channel-randomiser  Randomise the channel selected without invoking ACS
  --country {AD,AE,AF,AG,AI,AL,AM,AO,AQ,AR,AS,AT,AU,AW,AX,AZ,BA,BB,BD,BE,BF,BG,BH,BI,BJ,BL,BM,BN,BO,BQ,BQ,BR,BS,BT,BV,BW,BY,BZ,CA,CC,CD,CF,CG,CH,CI,CK,CL,CM,CN,CO,CR,CU,CV,CW,CX,CY,CZ,DE,DJ,DK,DM,DO,DZ,EC,EE,EG,EH,ER,ES,ET,FI,FJ,FK,FM,FO,FR,GA,GB,GD,GE,GF,GG,GH,GI,GL,GM,GN,GP,GQ,GR,GS,GT,GU,GW,GY,HK,HM,HN,HR,HT,HU,ID,IE,IL,IM,IN,IO,IQ,IR,IS,IT,JE,JM,JO,JP,KE,KG,KH,KI,KM,KN,KP,KR,KW,KY,KZ,LA,LB,LC,LI,LK,LR,LS,LT,LU,LV,LY,MA,MC,MD,ME,MF,MG,MH,MK,ML,MM,MN,MO,MP,MQ,MR,MS,MT,MU,MV,MW,MX,MY,MZ,NA,NC,NE,NF,NG,NI,NL,NO,NP,NR,NU,NZ,OM,PA,PE,PF,PG,PH,PK,PL,PM,PN,PR,PS,PT,PW,PY,QA,RE,RO,RS,RU,RW,SA,SB,SC,SD,SE,SG,SH,SI,SJ,SK,SL,SM,SN,SO,SR,SS,ST,SV,SX,SY,SZ,TC,TD,TF,TG,TH,TJ,TK,TL,TM,TN,TO,TR,TT,TV,TW,TZ,UA,UG,UM,US,UY,UZ,VA,VC,VE,VG,VI,VN,VU,WF,WS,YE,YT,ZA,ZM,ZW}
                        Configures of country of operation
  --macaddr-acl {0,1,2}
                        Station MAC address -based authentication 0 = accept unless in deny list 1 = deny unless in accept list 2 = use external RADIUS (accept/deny will be searched first) (Default: 0)
  --mac-accept-file MACADDR_ACCEPT_FILE
                        Location of hostapd-wpe macaddr_acl accept file (Default: /opt/rogue/tmp/hostapd.accept)
  --mac-deny-file MACADDR_DENY_FILE
                        Location of hostapd-wpe macaddr_acl deny file (Default: /opt/rogue/tmp/hostapd.accept)
  --auth-algs {1,2,3}   IEEE 802.11 specifies two authentication algorithms. 1 allows only WPA2 authentication algorithms. 2 is WEP. 3 allows both. (Default: 3)
  --wmm-enabled         Enable Wireless Multimedia Extensions
  --wmm-ac-bk-cwmin WMM_AC_BK_CWMIN
  --wmm-ac-bk-cwmax WMM_AC_BK_CWMAX
  --wmm-ac-bk-aifs WMM_AC_BK_AIFS
  --wmm-ac-bk-txop-limit WMM_AC_BK_TXOP_LIMIT
  --wmm-ac-bk-acm WMM_AC_BK_ACM
  --wmm-ac-be-cwmin WMM_AC_BE_CWMIN
  --wmm-ac-be-cwmax WMM_AC_BE_CWMAX
  --wmm-ac-be-txop-limit WMM_AC_BE_TXOP_LIMIT
  --wmm-ac-be-aifs WMM_AC_BE_AIFS
  --wmm-ac-be-acm WMM_AC_BE_ACM
  --wmm-ac-vi-cwmin WMM_AC_VI_CWMIN
  --wmm-ac-vi-cwmax WMM_AC_VI_CWMAX
  --wmm-ac-vi-aifs WMM_AC_VI_AIFS
  --wmm-ac-vi-txop-limit WMM_AC_VI_TXOP_LIMIT
  --wmm-ac-vi-acm WMM_AC_VI_ACM
  --wmm-ac-vo-cwmin WMM_AC_VO_CWMIN
  --wmm-ac-vo-cwmax WMM_AC_VO_CWMAX
  --wmm-ac-vo-aifs WMM_AC_VO_AIFS
  --wmm-ac-vo-txop-limit WMM_AC_VO_TXOP_LIMIT
  --wmm-ac-vo-acm WMM_AC_VO_ACM
  --ieee80211d          Enabling IEEE 802.11d advertises the country_code and the set of allowed channels and transmit power levels based on the regulatory limits. (Default: False)
  --ieee80211h          Enables radar detection and DFS support. DFS support is required for an outdoor 5 GHZ channel. (This can only be used if ieee80211d is enabled). (Default: False)
  --ap-isolate          Enable client isolation to prevent low-level bridging of frames between associated stations in the BSS. (Default: disabled)

IEEE 802.11n related configuration:
  --disable-ht40-       Disables [HT40-] HT capabilities.
  --disable-ht40+       Disables [HT40+] HT capabilities.
  --disable-short20     Disables Short GI for 20 MHz for HT capabilities.
  --disable-short40     Disables Short GI for 40 MHz for HT capabilities.
  --enable-ht-greenfield
                        Enables HT-greenfield: [GF] for HT capabilities.
  --enable-ldpc         Enables LDPC coding capability: [LDPC] for HT capabilities.
  --enable-smps-dynamic
                        Enables Spatial Multiplexing (SM) Power Save: [SMPS-DYNAMIC] for HT capabilities.
  --enable-smps-static  Enables Spatial Multiplexing (SM) Power Save: [SMPS-STATIC] for HT capabilities.
  --enable-tx-stbc      Enables Tx STBC: [TX-STBC] for HT capabilities.
  --enable-rx-stbc1     Enables Rx STBC: [RX-STBC1] (one spatial stream) for HT capabilities.
  --enable-rx-stbc12    Enables Rx STBC: [RX-STBC12] (one or two spatial stream) for HT capabilities.
  --enable-rx-stbc123   Enables Rx STBC: [RX-STBC123] (one, two, or three spatial stream) for HT capabilities.
  --enable-delayed-ba   Enables HT-delayed Block Ack: [DELAYED-BA] for HT capabilities.
  --enable-msdu7935     Enables Maximum A-MSDU length: [MAX-AMSDU-7935] for HT capabilities.
  --enable-cck          Enables DSSS/CCK Mode in 40 MHz: [DSSS_CCK-40] for HT capabilities.
  --enable-40-intolerant
                        Enables 40 MHz intolerant [40-INTOLERANT] for HT capabilities.
  --enable-txop_protection
                        Enables L-SIG TXOP protection support: [LSIG-TXOP-PROT] for HT capabilities.
  --require-ht          Require stations to support HT PHY (reject association if they do not). (Default: False)

IEEE 802.11ac related configuration:
  --vht-width {0,1,2,3}
                        VHT channel width (Default: 1).
  --vht-operation {0,1}
                        Enable toggling between 0 for vht_oper_centr_freq_seg0_idx and 1 for vht_oper_centr_freq_seg1_idx (Default: 0).
  --vht-index {42,159}  Enables control of vht_oper_centr_freq_seg[0/1]_idx index value (Default: 42).
  --require-vht         Require stations to support VHT PHY (reject association if they do not) (Default: disabled).
  --disable-short80     Disables Short GI for 80 MHz: [SHORT-GI-80] for VHT capabilities.
  --disable-short160    Disables Short GI for 160 MHz: [SHORT-GI-160] for VHT capabilities.
  --disable-htc-vht     Enables Indicates whether or not the STA supports receiving a VHT variant HT Control for VHT capabilities.
  --enable-mpdu7991     Enables [MAX-MPDU-7991] for VHT capabilities.
  --enable-mpdu11454    Enables [MAX-MPDU-11454] for VHT capabilities.
  --enable-rx-ldpc      Enables Rx LDPC coding capability: [RXLDPC] for VHT capabilities.
  --enable-vht-tx-stbc  Enables Tx STBC: [TX-STBC-2BY1] for VHT capabilities.
  --enable-vht-rx-stbc1
                        Enables Rx STBC: [RX-STBC1] (one spatial stream) for VHT capabilities.
  --enable-vht-rx-stbc12
                        Enables Rx STBC: [RX-STBC12] (support of one and two spatial streams) for VHT capabilities.
  --enable-vht-rx-stbc123
                        Enables Rx STBC: [RX-STBC123] (support of one, two and three spatial streams) for VHT capabilities.
  --enable-vht-rx-stbc1234
                        Enables Rx STBC: [RX-STBC1234] (support of one, two, three and four spatial streams) for VHT capabilities.
  --enable-beamformer   Enables SU Beamformer Capable: [SU-BEAMFORMER] for VHT capabilities.
  --enable-beamformee   Enables SU Beamformee Capable: [SU-BEAMFORMEE] for VHT capabilities.
  --enable-sd2          Enables two Sounding Dimensions [SOUNDING-DIMENSION-2] for VHT capabilities.
  --enable-sd3          Enables three Sounding Dimensions [SOUNDING-DIMENSION-3] for VHT capabilities.
  --enable-sd4          Enables four Sounding Dimensions [SOUNDING-DIMENSION-4] for VHT capabilities.
  --enable-mu-beamformer
                        Enables MU Beamformer Capable: [MU-BEAMFORMER] for VHT capabilities.
  --enable-txop-ps      Enables VHT TXOP PS: [VHT-TXOP-PS] for VHT capabilities.
  --enable-tx-pattern   Enables Tx Antenna Pattern Consistency: [TX-ANTENNA-PATTERN] for VHT capabilities.
  --enable-rx-pattern   Enables Rx Antenna Pattern Consistency: [RX-ANTENNA-PATTERN] for VHT capabilities.

WEP authentication configuration:
  --wep-key-version {0,1,2,3}
                        Determine the version of the WEP configuration
  --wep-key WEP_KEY     Determine the version of the WEP configuration

IWPA/IEEE 802.11i configuration:
  --wpa-passphrase WPA_PASSPHRASE
                        Specify the Pre-Shared Key for WPA network.
  --wpa {1,2,3}         Specify WPA type (Default: 2).
  --wpa-pairwise {CCMP,TKIP,CCMP TKIP}
                        (Default: 'CCMP TKIP')
  --rsn-pairwise {CCMP,TKIP,CCMP TKIP}
                        (Default: 'CCMP')

IEEE 802.1X-2004 configuration:
  --ieee8021x           Enable 802.1x (if 'auth' is 'wpa-enterprise' than automatically enabled)
  --eapol-version {1,2}
                        IEEE 802.1X/EAPOL version (Default: 2)
  --eapol-workaround    EAPOL-Key index workaround (set bit7) for WinXP Supplicant

RADIUS client configuration:
  --no-log-badpass      When set, incorrect passwords will not be logged
  --no-log-goodpass     When set, valid passwords will not be logged
  --own-address OWN_IP_ADDR
                        The own IP address of the access point (Default: 127.0.0.1)
  --auth-server-addr AUTH_SERVER_ADDR
                        IP address of radius authentication server (Default: 127.0.0.1)
  --auth-secret AUTH_SERVER_SHARED_SECRET
                        Radius authentication server shared secret (Default: secret)
  --auth-server-port AUTH_SERVER_PORT
                        Networking port of radius authentication server (Default: 1812)
  --acct-server-addr ACCT_SERVER_ADDR
                        IP address of radius accounting server (Default: 127.0.0.1)
  --acct-secret ACCT_SERVER_SHARED_SECRET
                        Radius accounting server shared secret
  --acct-server-port ACCT_SERVER_PORT
                        Networking port of radius accounting server (Default: 1813)
  --radius-proto {udp,tcp,*}
                        (Default: *)
  --default-eap {fast,peap,ttls,tls,leap,pwd,md5,gtc}
                        Specify the default EAP method used in RADIUS authentication. (Default: md5)
  -E {all,fast,peap,ttls,tls,leap,pwd,md5,gtc} [{all,fast,peap,ttls,tls,leap,pwd,md5,gtc} ...], --supported-eap {all,fast,peap,ttls,tls,leap,pwd,md5,gtc} [{all,fast,peap,ttls,tls,leap,pwd,md5,gtc} ...]
                        Specify the default EAP method used in RADIUS authentication. (Default: ['md5'])
  --ca-certificate CA_CERTIFICATE
                        specify trusted root CA certificate in PEM format. (Default: /opt/rogue/core/certs/ca.pem)
  --server-certificate SERVER_CERTIFICATE
                        specify RADIUS server certificate in PEM format. (Default: /opt/rogue/core/certs/server.pem)
  --server-private-key SERVER_PRIVATE_KEY
                        specify RADIUS private key. (Default: /opt/rogue/core/certs/server.key)
  --server-private-password SERVER_PRIVATE_KEY_PASSWORD
                        provide the password RADIUS private key. (Default: whatever)
  --disable-eap-user-file

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
                        Used to specify the second phy interface used to bridge the hostapd-wpe interface (-i) with another network (Default: eth0)
  --pool-start DHCP_POOL_START
                        (Default: 10.254.239.10)
  --pool-end DHCP_POOL_END
                        (Default: 10.254.239.70)

Attack Arguments:
  -M {responder,modlishka,sslsplit} [{responder,modlishka,sslsplit} ...], --modules {responder,modlishka,sslsplit} [{responder,modlishka,sslsplit} ...]
                        Enable attack modules in hostile network. Supported Modules: ['responder', 'modlishka', 'sslsplit']
  --karma               Enable Karma. (Default: False).
  --essid-mask {0,1,2}  Send empty SSID in beacons and ignore probe request frames that do not specify full SSID. 1 = send empty (length=0) SSID in beacon and ignore probe request for broadcast SSID 2 = clear SSID (ASCII 0), but keep
                        the original length (this may be required with some clients that do not support empty SSID) and ignore probe requests for broadcast SSID (Default: 0)

sslsplit configuration:
  --cert-nopass         Generate a x.509 Certificate with no password for the purpose of sslsplit.

modlishka configuration:
  --proxyAddress MODLISHKA_PROXYADDRESS
                        Proxy that should be used (socks/https/http) - e.g.: http://127.0.0.1:8080 (Default: None)
  --proxyDomain MODLISHKA_PROXYDOMAIN
                        Specify the domain that will be visible in target's browser. (Default: loopback.modlishka.io)
  --listeningAddress MODLISHKA_LISTENINGADDRESS
                        Specify listening address of modlishka server. (Default: 10.254.239.1)
  --target MODLISHKA_TARGET
                        Target domain name - e.g.: target.tld
  --controlURL MODLISHKA_CONTROLURL
                        URL to view captured credentials and settings. (Default rogue)
  --controlCreds MODLISHKA_CONTROLCREDS
                        Username and password to protect the credentials page. user:pass format. (Default: rogue:rogue)
                                                                                                                                                                                                                                            
```
