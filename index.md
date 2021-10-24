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

[Get started now](#get-started){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 } [View it on GitHub](https://github.com/InfamousSYN/rogue){: .btn .fs-5 .mb-4 .mb-md-0 }

---

## Get Started
Rogue is a Python3 project, built to run on debian systems such as Kali Linux and Ubuntu. The toolkit provides a highly configurable platform to automate the standardised configuration of services and applications to conduct evil twin attacks.

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

---

### License

Just the Docs is distributed by an [GNU GENERAL PUBLIC LICENSE v3](https://github.com/InfamousSYN/rogue/blob/master/LICENSE).
