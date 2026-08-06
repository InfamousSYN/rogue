General Arguments
=================

manual
^^^^^^

The `--manual` argument allows the user to specify a bespoke `hostapd-wpe.conf` file rather than using the dynamically generated version in `tmp/hostapd-wpe.conf`.

When `--manual` is used, the authentication method is automatically detected from the contents of the supplied `hostapd-wpe.conf` file (for example, `ieee8021x=1` / `wpa_key_mgmt=WPA-EAP` indicates `wpa-enterprise`). This ensures dependant services, such as the freeradius server required for `wpa-enterprise` networks, are started correctly. The `--auth` argument is optional in this mode; however, if it is supplied it must match the method detected in the file, otherwise the job is aborted. The job is also aborted if the file cannot be read or if no authentication method can be detected from its contents.

internet
^^^^^^^^

The `--internet` argument allows two interfaces to be bridged to allow upstream network communication to be supplied to rogue subnet. 

authentication
^^^^^^^^^^^^^^

The `--auth` argument specifies which authentication method be used by the rogue WLAN. 

certificate wizard
^^^^^^^^^^^^^^^^^^

The `--cert-wizard` argument invokes the self-signed certificate generation workflow, which is typically required to be conducted the first time rogue is used unless externally generated certificates are being used.  

show options
^^^^^^^^^^^^

The `--show-options` argument prints the list of invoked arguments and their values. 

interface
^^^^^^^^^^

The `--interface` argument is used to specify which WLAN interface will be used to service the rogue WLAN. 
