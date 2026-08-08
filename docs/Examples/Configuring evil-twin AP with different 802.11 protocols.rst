Configuring evil-twin AP with different 802.11 protocols
=======================================

802.11b (wifi 1)
^^^^^^^^^^^^^^^^

```bash
sudo python3 /opt/rogue/rogue.py -i wlan0 --auth open --preset-profile wifi1 --channel-randomiser
```

802.11a (wifi 2)
^^^^^^^^^^^^^^^^

```bash
sudo python3 /opt/rogue/rogue.py -i wlan0 --auth open --preset-profile wifi2 --channel-randomiser
```

802.11g (wifi 3)
^^^^^^^^^^^^^^^^

```bash
sudo python3 /opt/rogue/rogue.py -i wlan0 --auth open --preset-profile wifi3 --channel-randomiser
```

802.11n (2.4GHz) (wifi 4)
^^^^^^^^^^^^^^^^

```bash
sudo python3 /opt/rogue/rogue.py -i wlan0 --auth open --preset-profile wifi4 --channel-randomiser
```

802.11n (5GHz) (wifi 4)
^^^^^^^^^^^^^^^^

```bash
sudo python3 /opt/rogue/rogue.py -i wlan0 --auth open --preset-profile wifi4 --freq 5 --channel-randomiser
```

802.11ac (wifi 5)
^^^^^^^^^^^^^^^^

```bash
sudo python3 /opt/rogue/rogue.py -i wlan0 --auth open --preset-profile wifi5 --channel-randomiser
```

802.11ax (wifi 6)
^^^^^^^^^^^^^^^^

The ``wifi6`` profile defaults to the 5GHz band. Use ``--freq 2`` to run on 2.4GHz instead.

```bash
sudo python3 /opt/rogue/rogue.py -i wlan0 --auth open --preset-profile wifi6 --channel-randomiser
```

```bash
sudo python3 /opt/rogue/rogue.py -i wlan0 --auth open --preset-profile wifi6 --freq 2 --channel-randomiser
```

Note: 6GHz (Wi-Fi 6E, ``--freq 6``) is not yet supported for this profile; it requires WPA3-SAE/OWE, PMF and op_class handling.

802.11be (wifi 7)
^^^^^^^^^^^^^^^^

```bash
coming soon...
```

Manual 802.11 configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Instead of using the [`--preset-profile`](https://the-rogue-toolkit.readthedocs.io/en/latest/Arguments/802-11.html#preset-profile) as a shortcut for pre-configured 802.11 protocols, the various 802.11n arguments can be invoked directly at runtime. This allows for great control over the 802.11 configuration being used. 

```bash
sudo python3 /opt/rogue/rogue.py -i wlan0 --auth open -hm ac --freq 5 -c 36 --htmode 2 --require-ht --wmm-enabled --require-vht --disable-short160
```

Custom hostapd-wpe configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The [`--manual`](https://the-rogue-toolkit.readthedocs.io/en/latest/Arguments/general.html#manual) argument allows an external `hostapd-wpe.conf` file to be used to configure the hostapd-wpe component. This is different to manually configuring the 802.11 settings, as rogue is still used in the alternative methods to dynamically generate the `hostapd-wpe.conf` file.

When `--manual` is used the authentication method is detected from the supplied file, so dependant services (such as freeradius for `wpa-enterprise` networks) are started correctly. `--auth` is optional here, but if supplied it must match the method detected in the file or the job is aborted.

```bash
sudo python3 /opt/rogue/rogue.py -i wlan0 --manual /opt/rogue/tmp/hostapd-wpe.conf
```
