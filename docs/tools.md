---
layout: default
title: Tools
nav_order: 3
---

# Tools

The Rogue toolkit includes additional tools to aid in testing.

## hashcatifer
hashcatifer allows the user to convert hashes captured by rogue from the standard john the ripper format to a format accepted by hashcat.
```
python hashcatifer -f /var/log/freeradius-server-wpe.log -o /tmp/hashcatifer.output'
hashcat command: hashcat -m 5500 /tmp/hashcatifer.output -w wordlist
```
