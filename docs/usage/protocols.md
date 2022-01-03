---
layout: default
title: Setting 802.11 Protocols
parent: Usage
nav_order: 1
permalink: /usage/protocols
---

# Setting 802.11 Protocols

The Rogue Toolkit allows users to set any of the 802.11 protocols supports by the hostapd-wpe software. Below is examples of the minimum requirements for selecting a 802.11 protocol (`--hw-mode` / `-hw` / `--preset-profile`). However, some additional arguments may also be supported by the toolkit to allow for fine-tuning.

## 802.11b ( wifi1 )
```
sudo python3 /opt/rogue/rogue.py -i wlan0 --auth open --internet --preset-profile wifi1 --channel-randomiser
```

## 802.11a ( wifi2 )
```
sudo python3 /opt/rogue/rogue.py -i wlan0 --auth open --internet --preset-profile wifi2 --channel-randomiser
```

```
#   freq        HT40-       HT40+
#   2.4 GHz     5-13        1-7 (1-9 in Europe/Japan)
#   5 GHz       40,48,56,64 36,44,52,60
```

## 802.11g ( wifi3 )
```
sudo python3 /opt/rogue/rogue.py -i wlan0 --auth open --internet --preset-profile wifi3 --channel-randomiser
```

## 802.11n (2.4 GHz) ( wifi4 )
```
sudo python3 /opt/rogue/rogue.py -i wlan0 --auth open --internet --preset-profile wifi4 --channel-randomiser
```

## 802.11n (5 GHz) ( wifi4 )
```
sudo python3 /opt/rogue/rogue.py -i wlan0 --auth open --internet --preset-profile wifi4 --freq 5 --channel-randomiser
```

```
#   freq        HT40-       HT40+
#   2.4 GHz     5-13        1-7 (1-9 in Europe/Japan)
#   5 GHz       40,48,56,64 36,44,52,60
```

## 802.11ac ( wifi5 )
```
sudo python3 /opt/rogue/rogue.py -i wlan0 --auth open --internet --preset-profile wifi5 --channel-randomiser
```

```
#   freq        HT40-       HT40+
#   2.4 GHz     5-13        1-7 (1-9 in Europe/Japan)
#   5 GHz       40,48,56,64 36,44,52,60
```

## 802.11ax ( wifi6 )
```
coming soon...
```

## Manual configuration
If the `--preset-profile` argument is not specified, rogue's operational mode can be manually configured. There are a wide range of hostapd-wpe configuration options supported to allow users to deployment a soft Access Point based on their requirements.

Example:
```
sudo python3 /opt/rogue/rogue.py -i wlan0 -hm ac --freq 5 -c 36 --htmode 2 --require-ht --wmm-enabled --ieee8021x --auth wpa-enterprise --wpa 2 --default-eap peap --internet --require-vht --disable-short160
```
