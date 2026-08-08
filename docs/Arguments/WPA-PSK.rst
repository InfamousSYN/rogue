WPA Arguments
=======================================

Rogue's WPA/WPA2/WPA3 behaviour is driven by two options working together:

* ``--auth`` selects the *credential model* — ``wpa-personal`` (a pre-shared
  passphrase) or ``wpa-enterprise`` (802.1X/EAP via freeradius-wpe).
* ``--wpa`` selects the *generation* — ``1`` (legacy WPA), ``2`` (WPA2) or
  ``3`` (WPA3).

Rogue combines the two to produce the correct ``wpa_key_mgmt`` and Management
Frame Protection (PMF / ``ieee80211w``) settings. Note that hostapd's ``wpa=``
directive is a bitfield where ``2`` means RSN and is used by **both** WPA2 and
WPA3 — WPA3 is expressed through the key-management suite and PMF, so
``--wpa 3`` is rendered as ``wpa=2`` with WPA3 key management.

Combinations
---------------------------------------

.. list-table::
   :header-rows: 1
   :widths: 20 10 30 20 20

   * - ``--auth``
     - ``--wpa``
     - Result (``wpa_key_mgmt``)
     - PMF (``ieee80211w``)
     - Notes
   * - ``wpa-personal``
     - ``2``
     - WPA2-Personal (``WPA-PSK``)
     - optional (1)
     - Passphrase required
   * - ``wpa-personal``
     - ``3``
     - WPA3-Personal (``SAE``)
     - required (2)
     - Passphrase required; ``sae_pwe=2``
   * - ``wpa-enterprise``
     - ``2``
     - WPA2-Enterprise (``WPA-EAP``)
     - optional (1)
     - EAP via freeradius-wpe
   * - ``wpa-enterprise``
     - ``3``
     - WPA3-Enterprise (``WPA-EAP-SHA256``)
     - required (2)
     - EAP via freeradius-wpe
   * - ``wpa-personal``
     - ``1``
     - Legacy WPA (``WPA-PSK``)
     - disabled (0)
     - Not recommended
   * - ``owe``
     - n/a
     - Enhanced Open (``OWE``)
     - required (2)
     - Encrypted, no credentials; ``--wpa`` ignored

The PMF column shows the **auto** default; ``--pmf`` overrides it (except WPA3
and OWE, which always require ``2``). ``open``/``wep`` networks are unaffected by
these options.

``owe`` (Opportunistic Wireless Encryption, a.k.a. "Enhanced Open") is an open
network with no passphrase, but the association is RSN-encrypted with PMF
required. It shares the WPA/RSN rendering path with ``wpa-personal`` — the
passphrase line is simply omitted.

.. note::

   On the 6 GHz band (``--freq 6``, Wi-Fi 6E) open and WPA2 are forbidden and PMF
   is mandatory, so rogue auto-maps the requested auth: ``open`` becomes OWE, and
   ``wpa-personal`` / ``wpa-enterprise`` are upgraded to WPA3 (SAE / EAP-SHA256).
   ``wep`` on 6 GHz is rejected.

Arguments
---------------------------------------

``--wpa {1,2,3}``
   WPA generation: 1 = legacy WPA, 2 = WPA2, 3 = WPA3. Default: 2.

``--wpa-passphrase <passphrase>``
   Pre-shared key for ``wpa-personal`` (used by both WPA2-PSK and WPA3-SAE).
   Required when ``--auth wpa-personal`` is selected.

``--pmf {0,1,2}``
   Management Frame Protection (``ieee80211w``): 0 = disabled, 1 = optional,
   2 = required. Default is auto (WPA3 → 2, WPA2 → 1, open → 0). WPA3
   (``--wpa 3``) always requires 2 — supplying ``--pmf 0`` or ``--pmf 1`` with
   ``--wpa 3`` is rejected.

``--wpa-pairwise {CCMP,TKIP,CCMP TKIP}``
   Pairwise cipher(s) for legacy WPA (WPA v1). Default: ``CCMP TKIP``.

``--rsn-pairwise {CCMP,TKIP,CCMP TKIP}``
   Pairwise cipher(s) for RSN (WPA2/WPA3). Default: ``CCMP``.

Examples
---------------------------------------

WPA2-Personal:

.. code-block:: bash

   sudo python3 /opt/rogue/rogue.py -i wlan0 --auth wpa-personal --wpa 2 --wpa-passphrase "SuperSecret" --preset-profile wifi5 --channel-randomiser --country AU

WPA3-Personal (SAE):

.. code-block:: bash

   sudo python3 /opt/rogue/rogue.py -i wlan0 --auth wpa-personal --wpa 3 --wpa-passphrase "SuperSecret" --preset-profile wifi6 --channel-randomiser --country AU

WPA3-Enterprise:

.. code-block:: bash

   sudo python3 /opt/rogue/rogue.py -i wlan0 --auth wpa-enterprise --wpa 3 --default-eap peap -E peap --preset-profile wifi6 --channel-randomiser --country AU --server-certificate ./fullchain.pem --ca-certificate ./chain.pem --server-private-key ./privkey.pem

OWE (Enhanced Open):

.. code-block:: bash

   sudo python3 /opt/rogue/rogue.py -i wlan0 --auth owe --preset-profile wifi6 --channel-randomiser --country AU
