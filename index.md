---
layout: default
title: Home
nav_order: 1
description: "The Rogue Toolkit Documentation"
permalink: /
---

# Rogue
{: .fs-9 }

An extensible toolkit providing penetration testers an easy-to-use platform to deploy Access Points during penetration testing and red team engagements. 
{: .fs-6 .fw-300 }

[Get started now](#getting-started){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 } [View it on GitHub](https://github.com/InfamousSYN/rogue){: .btn .fs-5 .mb-4 .mb-md-0 }

---

## About

Forked from s0lst1c3's [eaphammer](https://github.com/s0lst1c3/eaphammer) project, Rogue is an extensible toolkit aimed at providing penetration testers an easy-to-use platform to deploy software-defined Access Points (AP) for the purpose of conducting wireless penetration testing and red team engagements. By using Rogue, penetration testers can easily perform targeted evil twin attacks against a variety of wireless network types. 

## Get Started

### Dependencies

Rogue is a Python3 project, built to run on debian systems such as Kali Linux and Ubuntu. As a toolkit, Rogue is used to automatically configure a number of applications in consistent manner to provide the testing platform, these applications include:
* hostapd-wpe
* freeradius-wpe
* isc-dhcp-server
* Apache 2.0
* sslsplit
* responder
* beef
* tcpdump

### Quick start:

1. Download [rogue](https://github.com/InfamousSYN/rogue) 
```
git clone https://github.com/InfamousSYN/rogue ; cd ./rogue
```
2. Run installer
```
python3 ./install.py
```
3. Run rogue
```
python3 rogue.py -i wlan0 -h g -c 6 -e rogue --auth open --internet
```

### Check out Rogue's capabilities

- [See utilities options]({{ site.baseurl }}{% link docs/utilities/utilities.md %})

---

## About the project

### License

Just the Docs is distributed by an [GNU GENERAL PUBLIC LICENSE v3](https://github.com/InfamousSYN/rogue/blob/master/LICENSE).
