---
layout: default
title: Features
nav_order: 2
permalink: /features
---

# Features

* `Automatic Channel Selection` - The Rogue toolkit allows testers to leverage hostapd-wpe's in-built Automatic Channel Selection (ACS) functionality to perform a scan of the surrounding frequencies to detect a clear channel for hostapd-wpe to utilise. ACS can be invoked by providing a value of 0 as the channel. 
* packet capturing - The Rogue toolkit leverages `tcpdump` to allow penetration testers to record the network traffic of their evil twin networks for record keeping purposes.
* `karma` - The Rogue toolkit can invoke hostapd-wpe with in-built karma support enabled. When karma is enabled, the hostapd-wpe access point will respond to all 802.11 probe requests, not just for itself but for any requested ESSID. This feature allows the toolkit to draw in surrounding client devices that are probing for known networks and to begin to attack these devices. 
* `ESSID Masking` - The Rogue toolkit also supports ESSID cloaking, allowing testers to set the value of the SSID field in 802.11 frames to 0. This allows for stealthier attacks, especially when performing karma-based attacks.
* `network bridging` - When the Rogue toolkit is launched, it will also launch an instance of `isc-dhcp-server` which provides the `hostapd-wpe` wireless network with DHCP. However, by default this network is isolated from the internet or any other network the attack platform is also connected too. By using the `--internet` argument, a tester can bridge the rogue network with another network. This allows Rogue to provide seamless access to resources expected by the connected victims and enable follow up network attacks to compromise connected victim credentials. 
* Rogue currently supports the following IEEE 802.11 protocols:
  * 802.11b
  * 802.11g
  * 802.11n (2.4GHz/5GHz)
  * 802.11a
- Rogue currently supports the following wireless authentication types:
  * open
  * wep
  * wpa-psk(1/2)
  * wpa2-enterprise
* `x.509 Certificate Generation` - Certificates are required by the Rogue toolkit to use many of the supported EAP-types when deploying WPA2-Enterprise based wireless networks.
* The toolkit has been extended to support for `sslsplit`. This allows testers to automated perform SSL termination to be able intercept credentials exchanged over an encrypted channel. 
* The Rogue toolkit uses `freeradius-wpe` as an external Radius server when deploying wpa2-enterprise-based networks. An external Radius server is used instead of the integrated Radius server within `hostapd-wpe`. This allows for wider ranges of scenarios to be supported and support more EAP-types:
    - ttls
    - tls
    - peap
    - md5
    - pwd
    - gtc
    - leap
* The Rogue toolkit include a website cloning capabilities, using `httrack`, allowing testers to clone a website to be used in later attacks. The idea behind this capability is to allow the tester to clone captive portals or other sites of interest. Once cloned, the site can be served to connected victims through external DNS spoofing with seeded web hooks for the several hostile portal attacks.
* The toolkit has been extended to support hostile portal attacks. After cloning a website, the Rogue toolkit can insert a browser hook into a cloned page to be served to the victim. When the modified page is next view, the victim's browser will be hooked by the supported framework. The Rogue toolkit currently supports the following hostile portal modes:
  * BeEF Framework
  * responder
 
