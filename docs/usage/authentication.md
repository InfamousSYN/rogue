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
python rogue.py -i wlan0 -h g -c 6 --auth open --internet
```

## WEP
```
python rogue.py -i wlan0 -h g -c 6 --auth wep --wep-key-version 0 --wep-key 4141414141 --internet
```

## WPA1-PSK
```
python rogue.py -i wlan0 -h g -c 6 --auth wpa-personal --wpa 1 --wpa-passphrase "test test" --internet
```

## WPA2-PSK
```
python rogue.py -i wlan0 -h g -c 6 --auth wpa-personal --wpa 2 --wpa-passphrase "test test" --internet
```

## WPA2-Enterprise
```
python rogue.py --cert-wizard
python rogue.py -i wlan0 -h n -c 6 --auth wpa-enterprise --wpa 2 --ieee8021x 1 --internet
```

*Note: Captured credentials will be stored in `rogue/logs/freeradius-server-wpe.log`*
