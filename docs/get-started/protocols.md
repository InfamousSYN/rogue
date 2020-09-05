---
layout: default
title: Setting 802.11 Protocols
parent: Usage
nav_order: 1
---

# Protocols

The Rogue Toolkit allows users to set any of the 802.11 protocols supports by the hostapd-wpe software. Below is examples of the minimum requirements for selecting a 802.11 protocol (`--hw-mode`/`-h`). However, some additional arguments may also be supported by the toolkit to allow for fine-tuning.

## 802.11b
```
python rogue.py -i wlan0 -h b -c 1 --auth open --internet
```

## 802.11g
```
python rogue.py -i wlan0 -h g -c 1 --auth open --internet
```

## 802.11a
```
python rogue.py -i wlan0 -h a -c 36 --auth open --internet
```

```
#   freq        HT40-       HT40+
#   2.4 GHz     5-13        1-7 (1-9 in Europe/Japan)
#   5 GHz       40,48,56,64 36,44,52,60
```

## 802.11n (2.4 GHz)
```
python rogue.py -i wlan0 -h n -c 1 --auth open --internet
```

## 802.11n (5 GHz)
```
python rogue.py -i wlan0 -h n --freq 5 -c 36 --auth open --internet
```

```
#   freq        HT40-       HT40+
#   2.4 GHz     5-13        1-7 (1-9 in Europe/Japan)
#   5 GHz       40,48,56,64 36,44,52,60
```

## 802.11ac
```
python rogue.py -i wlan0 -h ac -c 36 --auth open --internet --ht-mode 2 --require-ht --wmm-enabled --disable-short20 --disable-short40
```

```
#   freq        HT40-       HT40+
#   2.4 GHz     5-13        1-7 (1-9 in Europe/Japan)
#   5 GHz       40,48,56,64 36,44,52,60
```
