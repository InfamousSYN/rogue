---
layout: default
title: Install Guide
nav_order: 2
parent: Get Started
permalink: /get-started/install
---

# Install

1. Download [rogue](https://github.com/InfamousSYN/rogue) 
```
git clone https://github.com/InfamousSYN/rogue ; cd ./rogue
```
2. Run installer
```
sudo python3 ./install.py
```
3. Run rogue
```
sudo python3 /opt/rogue/rogue.py -i wlan0 --auth wpa-enterprise --internet --essid rogue --preset-profile wifi4 --channel-randomiser --default-eap peap
```
