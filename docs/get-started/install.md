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
python3 ./install.py
```
3. Run rogue
```
python3 rogue.py -i wlan0 -h g -c 6 -e rogue --auth open --internet
```
