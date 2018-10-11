#!/usr/bin/python

## Open Configuration
hostapd_open_cnf = '''##### hostapd configuration file ##############################################
# Empty lines and lines starting with # are ignored

# Driver interface type (hostap/wired/none/nl80211/bsd);
# default: hostap). nl80211 is used with all Linux mac80211 drivers.
# Use driver=none if building hostapd as a standalone RADIUS server that does
# not control any wireless/wired driver.
# driver=hostap
%s

interface=%s

##### Logging Settings ########################################################
logger_syslog=-1
logger_stdout_level=3
#logger_syslog_level=2
#logger_stdout=-1
#logger_stdout_level=2

##### Multiple BSSID support ##################################################
bssid=%s

##### IEEE 802.11 related configuration #######################################

ssid=%s

# Operation mode (a = IEEE 802.11a (5 GHz), b = IEEE 802.11b (2.4 GHz),
# g = IEEE 802.11g (2.4 GHz), ad = IEEE 802.11ad (60 GHz); a/g options are used
# with IEEE 802.11n (HT), too, to specify band). For IEEE 802.11ac (VHT), this
# needs to be set to hw_mode=a. When using ACS (see channel parameter), a
# special value "any" can be used to indicate that any support band can be used.
# This special case is currently supported only with drivers with which
# offloaded ACS is used.
# Default: IEEE 802.11b
hw_mode=%s

# Channel number (IEEE 802.11)
# (default: 0, i.e., not set)
# Please note that some drivers do not use this value from hostapd and the
# channel will need to be configured separately with iwconfig.
#
# If CONFIG_ACS build option is enabled, the channel can be selected
# automatically at run time by setting channel=acs_survey or channel=0, both of
# which will enable the ACS survey based algorithm.
channel=%d

# Country code (ISO/IEC 3166-1). Used to set regulatory domain.
# Set as needed to indicate country in which device is operating.
# This can limit available channels and transmit power.
%s

# Enable IEEE 802.11d. This advertises the country_code and the set of allowed
# channels and transmit power levels based on the regulatory limits. The
# country_code setting must be configured with the correct country for
# IEEE 802.11d functions.
# (default: 0 = disabled)
ieee80211d=%d

# Enable IEEE 802.11h. This enables radar detection and DFS support if
# available. DFS support is required on outdoor 5 GHz channels in most countries
# of the world. This can be used only with ieee80211d=1.
# (default: 0 = disabled)
ieee80211h=%d

# IEEE 802.11 specifies two authentication algorithms. hostapd can be
# configured to allow both of these or only one. Open system authentication
# should be used with IEEE 802.1X.
# Bit fields of allowed authentication algorithms:
# bit 0 = Open System Authentication
# bit 1 = Shared Key Authentication (requires WEP)
auth_algs=%d

# Send empty SSID in beacons and ignore probe request frames that do not
# specify full SSID, i.e., require stations to know SSID.
# default: disabled (0)
# 1 = send empty (length=0) SSID in beacon and ignore probe request for
#     broadcast SSID
# 2 = clear SSID (ASCII 0), but keep the original length (this may be required
#     with some clients that do not support empty SSID) and ignore probe
#     requests for broadcast SSID
ignore_broadcast_ssid=%d

# Station MAC address -based authentication
# Please note that this kind of access control requires a driver that uses
# hostapd to take care of management frame processing and as such, this can be
# used with driver=hostap or driver=nl80211, but not with driver=atheros.
# 0 = accept unless in deny list
# 1 = deny unless in accept list
# 2 = use external RADIUS server (accept/deny lists are searched first)
macaddr_acl=%d

# Default WMM parameters (IEEE 802.11 draft; 11-03-0504-03-000e):
# for 802.11a or 802.11g networks
# These parameters are sent to WMM clients when they associate.
# The parameters will be used by WMM clients for frames transmitted to the
# access point.
#
# note - txop_limit is in units of 32microseconds
# note - acm is admission control mandatory flag. 0 = admission control not
# required, 1 = mandatory
# note - Here cwMin and cmMax are in exponent form. The actual cw value used
# will be (2^n)-1 where n is the value given here. The allowed range for these
# wmm_ac_??_{cwmin,cwmax} is 0..15 with cwmax >= cwmin.
%s

# Client isolation can be used to prevent low-level bridging of frames between
# associated stations in the BSS. By default, this bridging is allowed.
ap_isolate=%d

##### IEEE 802.11n related configuration ######################################

# ieee80211n: Whether IEEE 802.11n (HT) is enabled
# 0 = disabled (default)
# 1 = enabled
# Note: You will also need to enable WMM for full HT functionality.
# Note: hw_mode=g (2.4 GHz) and hw_mode=a (5 GHz) is used to specify the band.
ieee80211n=%d

# ht_capab: HT capabilities (list of flags)
# LDPC coding capability: [LDPC] = supported
# Supported channel width set: [HT40-] = both 20 MHz and 40 MHz with secondary
#	channel below the primary channel; [HT40+] = both 20 MHz and 40 MHz
#	with secondary channel above the primary channel
#	(20 MHz only if neither is set)
#	Note: There are limits on which channels can be used with HT40- and
#	HT40+. Following table shows the channels that may be available for
#	HT40- and HT40+ use per IEEE 802.11n Annex J:
#	freq		HT40-		HT40+
#	2.4 GHz		5-13		1-7 (1-9 in Europe/Japan)
#	5 GHz		40,48,56,64	36,44,52,60
#	(depending on the location, not all of these channels may be available
#	for use)
#	Please note that 40 MHz channels may switch their primary and secondary
#	channels if needed or creation of 40 MHz channel maybe rejected based
#	on overlapping BSSes. These changes are done automatically when hostapd
#	is setting up the 40 MHz channel.
# Spatial Multiplexing (SM) Power Save: [SMPS-STATIC] or [SMPS-DYNAMIC]
#	(SMPS disabled if neither is set)
# HT-greenfield: [GF] (disabled if not set)
# Short GI for 20 MHz: [SHORT-GI-20] (disabled if not set)
# Short GI for 40 MHz: [SHORT-GI-40] (disabled if not set)
# Tx STBC: [TX-STBC] (disabled if not set)
# Rx STBC: [RX-STBC1] (one spatial stream), [RX-STBC12] (one or two spatial
#	streams), or [RX-STBC123] (one, two, or three spatial streams); Rx STBC
#	disabled if none of these set
# HT-delayed Block Ack: [DELAYED-BA] (disabled if not set)
# Maximum A-MSDU length: [MAX-AMSDU-7935] for 7935 octets (3839 octets if not
#	set)
# DSSS/CCK Mode in 40 MHz: [DSSS_CCK-40] = allowed (not allowed if not set)
# 40 MHz intolerant [40-INTOLERANT] (not advertised if not set)
# L-SIG TXOP protection support: [LSIG-TXOP-PROT] (disabled if not set)
#ht_capab=
%s

# Require stations to support HT PHY (reject association if they do not)
require_ht=%d

##### IEEE 802.11ac related configuration #####################################

# ieee80211ac: Whether IEEE 802.11ac (VHT) is enabled
# 0 = disabled (default)
# 1 = enabled
# Note: You will also need to enable WMM for full VHT functionality.
# Note: hw_mode=a is used to specify that 5 GHz band is used with VHT.
ieee80211ac=%d

# vht_capab: VHT capabilities (list of flags)
#
# vht_max_mpdu_len: [MAX-MPDU-7991] [MAX-MPDU-11454]
# Indicates maximum MPDU length
# 0 = 3895 octets (default)
# 1 = 7991 octets
# 2 = 11454 octets
# 3 = reserved
#
# supported_chan_width: [VHT160] [VHT160-80PLUS80]
# Indicates supported Channel widths
# 0 = 160 MHz & 80+80 channel widths are not supported (default)
# 1 = 160 MHz channel width is supported
# 2 = 160 MHz & 80+80 channel widths are supported
# 3 = reserved
#
# Rx LDPC coding capability: [RXLDPC]
# Indicates support for receiving LDPC coded pkts
# 0 = Not supported (default)
# 1 = Supported
#
# Short GI for 80 MHz: [SHORT-GI-80]
# Indicates short GI support for reception of packets transmitted with TXVECTOR
# params format equal to VHT and CBW = 80Mhz
# 0 = Not supported (default)
# 1 = Supported
#
# Short GI for 160 MHz: [SHORT-GI-160]
# Indicates short GI support for reception of packets transmitted with TXVECTOR
# params format equal to VHT and CBW = 160Mhz
# 0 = Not supported (default)
# 1 = Supported
#
# Tx STBC: [TX-STBC-2BY1]
# Indicates support for the transmission of at least 2x1 STBC
# 0 = Not supported (default)
# 1 = Supported
#
# Rx STBC: [RX-STBC-1] [RX-STBC-12] [RX-STBC-123] [RX-STBC-1234]
# Indicates support for the reception of PPDUs using STBC
# 0 = Not supported (default)
# 1 = support of one spatial stream
# 2 = support of one and two spatial streams
# 3 = support of one, two and three spatial streams
# 4 = support of one, two, three and four spatial streams
# 5,6,7 = reserved
#
# SU Beamformer Capable: [SU-BEAMFORMER]
# Indicates support for operation as a single user beamformer
# 0 = Not supported (default)
# 1 = Supported
#
# Compressed Steering Number of Beamformer Antennas Supported:
# [BF-ANTENNA-2] [BF-ANTENNA-3] [BF-ANTENNA-4]
#   Beamformee's capability indicating the maximum number of beamformer
#   antennas the beamformee can support when sending compressed beamforming
#   feedback
# If SU beamformer capable, set to maximum value minus 1
# else reserved (default)
#
# MU Beamformer Capable: [MU-BEAMFORMER]
# Indicates support for operation as an MU beamformer
# 0 = Not supported or sent by Non-AP STA (default)
# 1 = Supported
#
# VHT TXOP PS: [VHT-TXOP-PS]
# Indicates whether or not the AP supports VHT TXOP Power Save Mode
#  or whether or not the STA is in VHT TXOP Power Save mode
# 0 = VHT AP doesn't support VHT TXOP PS mode (OR) VHT STA not in VHT TXOP PS
#  mode
# 1 = VHT AP supports VHT TXOP PS mode (OR) VHT STA is in VHT TXOP power save
#  mode
#
# +HTC-VHT Capable: [HTC-VHT]
# Indicates whether or not the STA supports receiving a VHT variant HT Control
# field.
# 0 = Not supported (default)
# 1 = supported
#
# Maximum A-MPDU Length Exponent: [MAX-A-MPDU-LEN-EXP0]..[MAX-A-MPDU-LEN-EXP7]
# Indicates the maximum length of A-MPDU pre-EOF padding that the STA can recv
# This field is an integer in the range of 0 to 7.
# The length defined by this field is equal to
# 2 pow(13 + Maximum A-MPDU Length Exponent) -1 octets
#
# VHT Link Adaptation Capable: [VHT-LINK-ADAPT2] [VHT-LINK-ADAPT3]
# Indicates whether or not the STA supports link adaptation using VHT variant
# HT Control field
# If +HTC-VHTcapable is 1
#  0 = (no feedback) if the STA does not provide VHT MFB (default)
#  1 = reserved
#  2 = (Unsolicited) if the STA provides only unsolicited VHT MFB
#  3 = (Both) if the STA can provide VHT MFB in response to VHT MRQ and if the
#      STA provides unsolicited VHT MFB
# Reserved if +HTC-VHTcapable is 0
#
# Rx Antenna Pattern Consistency: [RX-ANTENNA-PATTERN]
# Indicates the possibility of Rx antenna pattern change
# 0 = Rx antenna pattern might change during the lifetime of an association
# 1 = Rx antenna pattern does not change during the lifetime of an association
#
# Tx Antenna Pattern Consistency: [TX-ANTENNA-PATTERN]
# Indicates the possibility of Tx antenna pattern change
# 0 = Tx antenna pattern might change during the lifetime of an association
# 1 = Tx antenna pattern does not change during the lifetime of an association
#vht_capab=[SHORT-GI-80][HTC-VHT]
#
# Require stations to support VHT PHY (reject association if they do not)
require_vht=%d

# 0 = 20 or 40 MHz operating Channel width
# 1 = 80 MHz channel width
# 2 = 160 MHz channel width
# 3 = 80+80 MHz channel width
vht_oper_chwidth=%d
#
# center freq = 5 GHz + (5 * index)
# So index 42 gives center freq 5.210 GHz
# which is channel 42 in 5G band
#
#vht_oper_centr_freq_seg0_idx=42
#
# center freq = 5 GHz + (5 * index)
# So index 159 gives center freq 5.795 GHz
# which is channel 159 in 5G band
#
#vht_oper_centr_freq_seg1_idx=159
%s

# Workaround to use station's nsts capability in (Re)Association Response frame
# This may be needed with some deployed devices as an interoperability
# workaround for beamforming if the AP's capability is greater than the
# station's capability. This is disabled by default and can be enabled by
# setting use_sta_nsts=1.
#use_sta_nsts=0
'''


## WPE Configuration
hostapd_wep_cnf = '''##### hostapd configuration file ##############################################
# Empty lines and lines starting with # are ignored

# Driver interface type (hostap/wired/none/nl80211/bsd);
# default: hostap). nl80211 is used with all Linux mac80211 drivers.
# Use driver=none if building hostapd as a standalone RADIUS server that does
# not control any wireless/wired driver.
# driver=hostap
%s

interface=%s

##### Logging Settings ########################################################
logger_syslog=-1
logger_stdout_level=3
#logger_syslog_level=2
#logger_stdout=-1
#logger_stdout_level=2

##### Multiple BSSID support ##################################################
bssid=%s

##### IEEE 802.11 related configuration #######################################

ssid=%s

# Operation mode (a = IEEE 802.11a (5 GHz), b = IEEE 802.11b (2.4 GHz),
# g = IEEE 802.11g (2.4 GHz), ad = IEEE 802.11ad (60 GHz); a/g options are used
# with IEEE 802.11n (HT), too, to specify band). For IEEE 802.11ac (VHT), this
# needs to be set to hw_mode=a. When using ACS (see channel parameter), a
# special value "any" can be used to indicate that any support band can be used.
# This special case is currently supported only with drivers with which
# offloaded ACS is used.
# Default: IEEE 802.11b
hw_mode=%s

# Channel number (IEEE 802.11)
# (default: 0, i.e., not set)
# Please note that some drivers do not use this value from hostapd and the
# channel will need to be configured separately with iwconfig.
#
# If CONFIG_ACS build option is enabled, the channel can be selected
# automatically at run time by setting channel=acs_survey or channel=0, both of
# which will enable the ACS survey based algorithm.
channel=%d

# Country code (ISO/IEC 3166-1). Used to set regulatory domain.
# Set as needed to indicate country in which device is operating.
# This can limit available channels and transmit power.
%s

# Enable IEEE 802.11d. This advertises the country_code and the set of allowed
# channels and transmit power levels based on the regulatory limits. The
# country_code setting must be configured with the correct country for
# IEEE 802.11d functions.
# (default: 0 = disabled)
ieee80211d=%d

# Enable IEEE 802.11h. This enables radar detection and DFS support if
# available. DFS support is required on outdoor 5 GHz channels in most countries
# of the world. This can be used only with ieee80211d=1.
# (default: 0 = disabled)
ieee80211h=%d

# IEEE 802.11 specifies two authentication algorithms. hostapd can be
# configured to allow both of these or only one. Open system authentication
# should be used with IEEE 802.1X.
# Bit fields of allowed authentication algorithms:
# bit 0 = Open System Authentication
# bit 1 = Shared Key Authentication (requires WEP)
auth_algs=%d

# Send empty SSID in beacons and ignore probe request frames that do not
# specify full SSID, i.e., require stations to know SSID.
# default: disabled (0)
# 1 = send empty (length=0) SSID in beacon and ignore probe request for
#     broadcast SSID
# 2 = clear SSID (ASCII 0), but keep the original length (this may be required
#     with some clients that do not support empty SSID) and ignore probe
#     requests for broadcast SSID
ignore_broadcast_ssid=%d

# Station MAC address -based authentication
# Please note that this kind of access control requires a driver that uses
# hostapd to take care of management frame processing and as such, this can be
# used with driver=hostap or driver=nl80211, but not with driver=atheros.
# 0 = accept unless in deny list
# 1 = deny unless in accept list
# 2 = use external RADIUS server (accept/deny lists are searched first)
macaddr_acl=%d

# Default WMM parameters (IEEE 802.11 draft; 11-03-0504-03-000e):
# for 802.11a or 802.11g networks
# These parameters are sent to WMM clients when they associate.
# The parameters will be used by WMM clients for frames transmitted to the
# access point.
#
# note - txop_limit is in units of 32microseconds
# note - acm is admission control mandatory flag. 0 = admission control not
# required, 1 = mandatory
# note - Here cwMin and cmMax are in exponent form. The actual cw value used
# will be (2^n)-1 where n is the value given here. The allowed range for these
# wmm_ac_??_{cwmin,cwmax} is 0..15 with cwmax >= cwmin.
%s

# Client isolation can be used to prevent low-level bridging of frames between
# associated stations in the BSS. By default, this bridging is allowed.
ap_isolate=%d

# Static WEP key configuration
#
# The key number to use when transmitting.
# It must be between 0 and 3, and the corresponding key must be set.
# default: not set
wep_default_key=%d
# The WEP keys to use.
# A key may be a quoted string or unquoted hexadecimal digits.
# The key length should be 5, 13, or 16 characters, or 10, 26, or 32
# digits, depending on whether 40-bit (64-bit), 104-bit (128-bit), or
# 128-bit (152-bit) WEP is used.
# Only the default key must be supplied; the others are optional.
# default: not set
#wep_key0=123456789a
#wep_key1="vwxyz"
#wep_key2=0102030405060708090a0b0c0d
#wep_key3=".2.4.6.8.0.23"
%s

##### IEEE 802.11n related configuration ######################################

# ieee80211n: Whether IEEE 802.11n (HT) is enabled
# 0 = disabled (default)
# 1 = enabled
# Note: You will also need to enable WMM for full HT functionality.
# Note: hw_mode=g (2.4 GHz) and hw_mode=a (5 GHz) is used to specify the band.
ieee80211n=%d

# ht_capab: HT capabilities (list of flags)
# LDPC coding capability: [LDPC] = supported
# Supported channel width set: [HT40-] = both 20 MHz and 40 MHz with secondary
#	channel below the primary channel; [HT40+] = both 20 MHz and 40 MHz
#	with secondary channel above the primary channel
#	(20 MHz only if neither is set)
#	Note: There are limits on which channels can be used with HT40- and
#	HT40+. Following table shows the channels that may be available for
#	HT40- and HT40+ use per IEEE 802.11n Annex J:
#	freq		HT40-		HT40+
#	2.4 GHz		5-13		1-7 (1-9 in Europe/Japan)
#	5 GHz		40,48,56,64	36,44,52,60
#	(depending on the location, not all of these channels may be available
#	for use)
#	Please note that 40 MHz channels may switch their primary and secondary
#	channels if needed or creation of 40 MHz channel maybe rejected based
#	on overlapping BSSes. These changes are done automatically when hostapd
#	is setting up the 40 MHz channel.
# Spatial Multiplexing (SM) Power Save: [SMPS-STATIC] or [SMPS-DYNAMIC]
#	(SMPS disabled if neither is set)
# HT-greenfield: [GF] (disabled if not set)
# Short GI for 20 MHz: [SHORT-GI-20] (disabled if not set)
# Short GI for 40 MHz: [SHORT-GI-40] (disabled if not set)
# Tx STBC: [TX-STBC] (disabled if not set)
# Rx STBC: [RX-STBC1] (one spatial stream), [RX-STBC12] (one or two spatial
#	streams), or [RX-STBC123] (one, two, or three spatial streams); Rx STBC
#	disabled if none of these set
# HT-delayed Block Ack: [DELAYED-BA] (disabled if not set)
# Maximum A-MSDU length: [MAX-AMSDU-7935] for 7935 octets (3839 octets if not
#	set)
# DSSS/CCK Mode in 40 MHz: [DSSS_CCK-40] = allowed (not allowed if not set)
# 40 MHz intolerant [40-INTOLERANT] (not advertised if not set)
# L-SIG TXOP protection support: [LSIG-TXOP-PROT] (disabled if not set)
# ht_capab=
%s

# Require stations to support HT PHY (reject association if they do not)
require_ht=%d

##### IEEE 802.11ac related configuration #####################################

# ieee80211ac: Whether IEEE 802.11ac (VHT) is enabled
# 0 = disabled (default)
# 1 = enabled
# Note: You will also need to enable WMM for full VHT functionality.
# Note: hw_mode=a is used to specify that 5 GHz band is used with VHT.
ieee80211ac=%d

# vht_capab: VHT capabilities (list of flags)
#
# vht_max_mpdu_len: [MAX-MPDU-7991] [MAX-MPDU-11454]
# Indicates maximum MPDU length
# 0 = 3895 octets (default)
# 1 = 7991 octets
# 2 = 11454 octets
# 3 = reserved
#
# supported_chan_width: [VHT160] [VHT160-80PLUS80]
# Indicates supported Channel widths
# 0 = 160 MHz & 80+80 channel widths are not supported (default)
# 1 = 160 MHz channel width is supported
# 2 = 160 MHz & 80+80 channel widths are supported
# 3 = reserved
#
# Rx LDPC coding capability: [RXLDPC]
# Indicates support for receiving LDPC coded pkts
# 0 = Not supported (default)
# 1 = Supported
#
# Short GI for 80 MHz: [SHORT-GI-80]
# Indicates short GI support for reception of packets transmitted with TXVECTOR
# params format equal to VHT and CBW = 80Mhz
# 0 = Not supported (default)
# 1 = Supported
#
# Short GI for 160 MHz: [SHORT-GI-160]
# Indicates short GI support for reception of packets transmitted with TXVECTOR
# params format equal to VHT and CBW = 160Mhz
# 0 = Not supported (default)
# 1 = Supported
#
# Tx STBC: [TX-STBC-2BY1]
# Indicates support for the transmission of at least 2x1 STBC
# 0 = Not supported (default)
# 1 = Supported
#
# Rx STBC: [RX-STBC-1] [RX-STBC-12] [RX-STBC-123] [RX-STBC-1234]
# Indicates support for the reception of PPDUs using STBC
# 0 = Not supported (default)
# 1 = support of one spatial stream
# 2 = support of one and two spatial streams
# 3 = support of one, two and three spatial streams
# 4 = support of one, two, three and four spatial streams
# 5,6,7 = reserved
#
# SU Beamformer Capable: [SU-BEAMFORMER]
# Indicates support for operation as a single user beamformer
# 0 = Not supported (default)
# 1 = Supported
#
# Compressed Steering Number of Beamformer Antennas Supported:
# [BF-ANTENNA-2] [BF-ANTENNA-3] [BF-ANTENNA-4]
#   Beamformee's capability indicating the maximum number of beamformer
#   antennas the beamformee can support when sending compressed beamforming
#   feedback
# If SU beamformer capable, set to maximum value minus 1
# else reserved (default)
#
# MU Beamformer Capable: [MU-BEAMFORMER]
# Indicates support for operation as an MU beamformer
# 0 = Not supported or sent by Non-AP STA (default)
# 1 = Supported
#
# VHT TXOP PS: [VHT-TXOP-PS]
# Indicates whether or not the AP supports VHT TXOP Power Save Mode
#  or whether or not the STA is in VHT TXOP Power Save mode
# 0 = VHT AP doesn't support VHT TXOP PS mode (OR) VHT STA not in VHT TXOP PS
#  mode
# 1 = VHT AP supports VHT TXOP PS mode (OR) VHT STA is in VHT TXOP power save
#  mode
#
# +HTC-VHT Capable: [HTC-VHT]
# Indicates whether or not the STA supports receiving a VHT variant HT Control
# field.
# 0 = Not supported (default)
# 1 = supported
#
# Maximum A-MPDU Length Exponent: [MAX-A-MPDU-LEN-EXP0]..[MAX-A-MPDU-LEN-EXP7]
# Indicates the maximum length of A-MPDU pre-EOF padding that the STA can recv
# This field is an integer in the range of 0 to 7.
# The length defined by this field is equal to
# 2 pow(13 + Maximum A-MPDU Length Exponent) -1 octets
#
# VHT Link Adaptation Capable: [VHT-LINK-ADAPT2] [VHT-LINK-ADAPT3]
# Indicates whether or not the STA supports link adaptation using VHT variant
# HT Control field
# If +HTC-VHTcapable is 1
#  0 = (no feedback) if the STA does not provide VHT MFB (default)
#  1 = reserved
#  2 = (Unsolicited) if the STA provides only unsolicited VHT MFB
#  3 = (Both) if the STA can provide VHT MFB in response to VHT MRQ and if the
#      STA provides unsolicited VHT MFB
# Reserved if +HTC-VHTcapable is 0
#
# Rx Antenna Pattern Consistency: [RX-ANTENNA-PATTERN]
# Indicates the possibility of Rx antenna pattern change
# 0 = Rx antenna pattern might change during the lifetime of an association
# 1 = Rx antenna pattern does not change during the lifetime of an association
#
# Tx Antenna Pattern Consistency: [TX-ANTENNA-PATTERN]
# Indicates the possibility of Tx antenna pattern change
# 0 = Tx antenna pattern might change during the lifetime of an association
# 1 = Tx antenna pattern does not change during the lifetime of an association
#vht_capab=[SHORT-GI-80][HTC-VHT]
#
# Require stations to support VHT PHY (reject association if they do not)
require_vht=%d

# 0 = 20 or 40 MHz operating Channel width
# 1 = 80 MHz channel width
# 2 = 160 MHz channel width
# 3 = 80+80 MHz channel width
vht_oper_chwidth=%d
#
# center freq = 5 GHz + (5 * index)
# So index 42 gives center freq 5.210 GHz
# which is channel 42 in 5G band
#
#vht_oper_centr_freq_seg0_idx=42
#
# center freq = 5 GHz + (5 * index)
# So index 159 gives center freq 5.795 GHz
# which is channel 159 in 5G band
#
#vht_oper_centr_freq_seg1_idx=159
%s

# Workaround to use station's nsts capability in (Re)Association Response frame
# This may be needed with some deployed devices as an interoperability
# workaround for beamforming if the AP's capability is greater than the
# station's capability. This is disabled by default and can be enabled by
# setting use_sta_nsts=1.
#use_sta_nsts=0
'''


## WPA-PSK Configuration
hostapd_wpa_psk_cnf='''##### hostapd configuration file ##############################################
# Empty lines and lines starting with # are ignored

# Driver interface type (hostap/wired/none/nl80211/bsd);
# default: hostap). nl80211 is used with all Linux mac80211 drivers.
# Use driver=none if building hostapd as a standalone RADIUS server that does
# not control any wireless/wired driver.
# driver=hostap
%s

interface=%s

##### Logging Settings ########################################################
logger_syslog=-1
logger_stdout_level=3
#logger_syslog_level=2
#logger_stdout=-1
#logger_stdout_level=2

##### Multiple BSSID support ##################################################
bssid=%s

##### IEEE 802.11 related configuration #######################################

ssid=%s

# Operation mode (a = IEEE 802.11a (5 GHz), b = IEEE 802.11b (2.4 GHz),
# g = IEEE 802.11g (2.4 GHz), ad = IEEE 802.11ad (60 GHz); a/g options are used
# with IEEE 802.11n (HT), too, to specify band). For IEEE 802.11ac (VHT), this
# needs to be set to hw_mode=a. When using ACS (see channel parameter), a
# special value "any" can be used to indicate that any support band can be used.
# This special case is currently supported only with drivers with which
# offloaded ACS is used.
# Default: IEEE 802.11b
hw_mode=%s

# Channel number (IEEE 802.11)
# (default: 0, i.e., not set)
# Please note that some drivers do not use this value from hostapd and the
# channel will need to be configured separately with iwconfig.
#
# If CONFIG_ACS build option is enabled, the channel can be selected
# automatically at run time by setting channel=acs_survey or channel=0, both of
# which will enable the ACS survey based algorithm.
channel=%d

# Country code (ISO/IEC 3166-1). Used to set regulatory domain.
# Set as needed to indicate country in which device is operating.
# This can limit available channels and transmit power.
%s

# Enable IEEE 802.11d. This advertises the country_code and the set of allowed
# channels and transmit power levels based on the regulatory limits. The
# country_code setting must be configured with the correct country for
# IEEE 802.11d functions.
# (default: 0 = disabled)
ieee80211d=%d

# Enable IEEE 802.11h. This enables radar detection and DFS support if
# available. DFS support is required on outdoor 5 GHz channels in most countries
# of the world. This can be used only with ieee80211d=1.
# (default: 0 = disabled)
ieee80211h=%d

# IEEE 802.11 specifies two authentication algorithms. hostapd can be
# configured to allow both of these or only one. Open system authentication
# should be used with IEEE 802.1X.
# Bit fields of allowed authentication algorithms:
# bit 0 = Open System Authentication
# bit 1 = Shared Key Authentication (requires WEP)
auth_algs=%d

# Send empty SSID in beacons and ignore probe request frames that do not
# specify full SSID, i.e., require stations to know SSID.
# default: disabled (0)
# 1 = send empty (length=0) SSID in beacon and ignore probe request for
#     broadcast SSID
# 2 = clear SSID (ASCII 0), but keep the original length (this may be required
#     with some clients that do not support empty SSID) and ignore probe
#     requests for broadcast SSID
ignore_broadcast_ssid=%d

# Station MAC address -based authentication
# Please note that this kind of access control requires a driver that uses
# hostapd to take care of management frame processing and as such, this can be
# used with driver=hostap or driver=nl80211, but not with driver=atheros.
# 0 = accept unless in deny list
# 1 = deny unless in accept list
# 2 = use external RADIUS server (accept/deny lists are searched first)
macaddr_acl=%d

# Default WMM parameters (IEEE 802.11 draft; 11-03-0504-03-000e):
# for 802.11a or 802.11g networks
# These parameters are sent to WMM clients when they associate.
# The parameters will be used by WMM clients for frames transmitted to the
# access point.
#
# note - txop_limit is in units of 32microseconds
# note - acm is admission control mandatory flag. 0 = admission control not
# required, 1 = mandatory
# note - Here cwMin and cmMax are in exponent form. The actual cw value used
# will be (2^n)-1 where n is the value given here. The allowed range for these
# wmm_ac_??_{cwmin,cwmax} is 0..15 with cwmax >= cwmin.
%s

# Client isolation can be used to prevent low-level bridging of frames between
# associated stations in the BSS. By default, this bridging is allowed.
ap_isolate=%d

##### IEEE 802.11n related configuration ######################################

# ieee80211n: Whether IEEE 802.11n (HT) is enabled
# 0 = disabled (default)
# 1 = enabled
# Note: You will also need to enable WMM for full HT functionality.
# Note: hw_mode=g (2.4 GHz) and hw_mode=a (5 GHz) is used to specify the band.
ieee80211n=%d

# ht_capab: HT capabilities (list of flags)
# LDPC coding capability: [LDPC] = supported
# Supported channel width set: [HT40-] = both 20 MHz and 40 MHz with secondary
#	channel below the primary channel; [HT40+] = both 20 MHz and 40 MHz
#	with secondary channel above the primary channel
#	(20 MHz only if neither is set)
#	Note: There are limits on which channels can be used with HT40- and
#	HT40+. Following table shows the channels that may be available for
#	HT40- and HT40+ use per IEEE 802.11n Annex J:
#	freq		HT40-		HT40+
#	2.4 GHz		5-13		1-7 (1-9 in Europe/Japan)
#	5 GHz		40,48,56,64	36,44,52,60
#	(depending on the location, not all of these channels may be available
#	for use)
#	Please note that 40 MHz channels may switch their primary and secondary
#	channels if needed or creation of 40 MHz channel maybe rejected based
#	on overlapping BSSes. These changes are done automatically when hostapd
#	is setting up the 40 MHz channel.
# Spatial Multiplexing (SM) Power Save: [SMPS-STATIC] or [SMPS-DYNAMIC]
#	(SMPS disabled if neither is set)
# HT-greenfield: [GF] (disabled if not set)
# Short GI for 20 MHz: [SHORT-GI-20] (disabled if not set)
# Short GI for 40 MHz: [SHORT-GI-40] (disabled if not set)
# Tx STBC: [TX-STBC] (disabled if not set)
# Rx STBC: [RX-STBC1] (one spatial stream), [RX-STBC12] (one or two spatial
#	streams), or [RX-STBC123] (one, two, or three spatial streams); Rx STBC
#	disabled if none of these set
# HT-delayed Block Ack: [DELAYED-BA] (disabled if not set)
# Maximum A-MSDU length: [MAX-AMSDU-7935] for 7935 octets (3839 octets if not
#	set)
# DSSS/CCK Mode in 40 MHz: [DSSS_CCK-40] = allowed (not allowed if not set)
# 40 MHz intolerant [40-INTOLERANT] (not advertised if not set)
# L-SIG TXOP protection support: [LSIG-TXOP-PROT] (disabled if not set)
#ht_capab=
%s

# Require stations to support HT PHY (reject association if they do not)
require_ht=%d

##### IEEE 802.11ac related configuration #####################################

# ieee80211ac: Whether IEEE 802.11ac (VHT) is enabled
# 0 = disabled (default)
# 1 = enabled
# Note: You will also need to enable WMM for full VHT functionality.
# Note: hw_mode=a is used to specify that 5 GHz band is used with VHT.
ieee80211ac=%d

# vht_capab: VHT capabilities (list of flags)
#
# vht_max_mpdu_len: [MAX-MPDU-7991] [MAX-MPDU-11454]
# Indicates maximum MPDU length
# 0 = 3895 octets (default)
# 1 = 7991 octets
# 2 = 11454 octets
# 3 = reserved
#
# supported_chan_width: [VHT160] [VHT160-80PLUS80]
# Indicates supported Channel widths
# 0 = 160 MHz & 80+80 channel widths are not supported (default)
# 1 = 160 MHz channel width is supported
# 2 = 160 MHz & 80+80 channel widths are supported
# 3 = reserved
#
# Rx LDPC coding capability: [RXLDPC]
# Indicates support for receiving LDPC coded pkts
# 0 = Not supported (default)
# 1 = Supported
#
# Short GI for 80 MHz: [SHORT-GI-80]
# Indicates short GI support for reception of packets transmitted with TXVECTOR
# params format equal to VHT and CBW = 80Mhz
# 0 = Not supported (default)
# 1 = Supported
#
# Short GI for 160 MHz: [SHORT-GI-160]
# Indicates short GI support for reception of packets transmitted with TXVECTOR
# params format equal to VHT and CBW = 160Mhz
# 0 = Not supported (default)
# 1 = Supported
#
# Tx STBC: [TX-STBC-2BY1]
# Indicates support for the transmission of at least 2x1 STBC
# 0 = Not supported (default)
# 1 = Supported
#
# Rx STBC: [RX-STBC-1] [RX-STBC-12] [RX-STBC-123] [RX-STBC-1234]
# Indicates support for the reception of PPDUs using STBC
# 0 = Not supported (default)
# 1 = support of one spatial stream
# 2 = support of one and two spatial streams
# 3 = support of one, two and three spatial streams
# 4 = support of one, two, three and four spatial streams
# 5,6,7 = reserved
#
# SU Beamformer Capable: [SU-BEAMFORMER]
# Indicates support for operation as a single user beamformer
# 0 = Not supported (default)
# 1 = Supported
#
# Compressed Steering Number of Beamformer Antennas Supported:
# [BF-ANTENNA-2] [BF-ANTENNA-3] [BF-ANTENNA-4]
#   Beamformee's capability indicating the maximum number of beamformer
#   antennas the beamformee can support when sending compressed beamforming
#   feedback
# If SU beamformer capable, set to maximum value minus 1
# else reserved (default)
#
# MU Beamformer Capable: [MU-BEAMFORMER]
# Indicates support for operation as an MU beamformer
# 0 = Not supported or sent by Non-AP STA (default)
# 1 = Supported
#
# VHT TXOP PS: [VHT-TXOP-PS]
# Indicates whether or not the AP supports VHT TXOP Power Save Mode
#  or whether or not the STA is in VHT TXOP Power Save mode
# 0 = VHT AP doesn't support VHT TXOP PS mode (OR) VHT STA not in VHT TXOP PS
#  mode
# 1 = VHT AP supports VHT TXOP PS mode (OR) VHT STA is in VHT TXOP power save
#  mode
#
# +HTC-VHT Capable: [HTC-VHT]
# Indicates whether or not the STA supports receiving a VHT variant HT Control
# field.
# 0 = Not supported (default)
# 1 = supported
#
# Maximum A-MPDU Length Exponent: [MAX-A-MPDU-LEN-EXP0]..[MAX-A-MPDU-LEN-EXP7]
# Indicates the maximum length of A-MPDU pre-EOF padding that the STA can recv
# This field is an integer in the range of 0 to 7.
# The length defined by this field is equal to
# 2 pow(13 + Maximum A-MPDU Length Exponent) -1 octets
#
# VHT Link Adaptation Capable: [VHT-LINK-ADAPT2] [VHT-LINK-ADAPT3]
# Indicates whether or not the STA supports link adaptation using VHT variant
# HT Control field
# If +HTC-VHTcapable is 1
#  0 = (no feedback) if the STA does not provide VHT MFB (default)
#  1 = reserved
#  2 = (Unsolicited) if the STA provides only unsolicited VHT MFB
#  3 = (Both) if the STA can provide VHT MFB in response to VHT MRQ and if the
#      STA provides unsolicited VHT MFB
# Reserved if +HTC-VHTcapable is 0
#
# Rx Antenna Pattern Consistency: [RX-ANTENNA-PATTERN]
# Indicates the possibility of Rx antenna pattern change
# 0 = Rx antenna pattern might change during the lifetime of an association
# 1 = Rx antenna pattern does not change during the lifetime of an association
#
# Tx Antenna Pattern Consistency: [TX-ANTENNA-PATTERN]
# Indicates the possibility of Tx antenna pattern change
# 0 = Tx antenna pattern might change during the lifetime of an association
# 1 = Tx antenna pattern does not change during the lifetime of an association
#vht_capab=[SHORT-GI-80][HTC-VHT]
#
# Require stations to support VHT PHY (reject association if they do not)
require_vht=%d

# 0 = 20 or 40 MHz operating Channel width
# 1 = 80 MHz channel width
# 2 = 160 MHz channel width
# 3 = 80+80 MHz channel width
vht_oper_chwidth=%d
#
# center freq = 5 GHz + (5 * index)
# So index 42 gives center freq 5.210 GHz
# which is channel 42 in 5G band
#
#vht_oper_centr_freq_seg0_idx=42
#
# center freq = 5 GHz + (5 * index)
# So index 159 gives center freq 5.795 GHz
# which is channel 159 in 5G band
#
#vht_oper_centr_freq_seg1_idx=159
%s

# Workaround to use station's nsts capability in (Re)Association Response frame
# This may be needed with some deployed devices as an interoperability
# workaround for beamforming if the AP's capability is greater than the
# station's capability. This is disabled by default and can be enabled by
# setting use_sta_nsts=1.
#use_sta_nsts=0

##### WPA/IEEE 802.11i configuration ##########################################

# Enable WPA. Setting this variable configures the AP to require WPA (either
# WPA-PSK or WPA-RADIUS/EAP based on other configuration). For WPA-PSK, either
# wpa_psk or wpa_passphrase must be set and wpa_key_mgmt must include WPA-PSK.
# Instead of wpa_psk / wpa_passphrase, wpa_psk_radius might suffice.
# For WPA-RADIUS/EAP, ieee8021x must be set (but without dynamic WEP keys),
# RADIUS authentication server must be configured, and WPA-EAP must be included
# in wpa_key_mgmt.
# This field is a bit field that can be used to enable WPA (IEEE 802.11i/D3.0)
# and/or WPA2 (full IEEE 802.11i/RSN):
# bit0 = WPA
# bit1 = IEEE 802.11i/RSN (WPA2) (dot11RSNAEnabled)
wpa=%d

# WPA pre-shared keys for WPA-PSK. This can be either entered as a 256-bit
# secret in hex format (64 hex digits), wpa_psk, or as an ASCII passphrase
# (8..63 characters) that will be converted to PSK. This conversion uses SSID
# so the PSK changes when ASCII passphrase is used and the SSID is changed.
# wpa_psk (dot11RSNAConfigPSKValue)
# wpa_passphrase (dot11RSNAConfigPSKPassPhrase)
#wpa_psk=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
#wpa_passphrase=secret passphrase
wpa_passphrase=%s

# Set of accepted key management algorithms (WPA-PSK, WPA-EAP, or both). The
# entries are separated with a space. WPA-PSK-SHA256 and WPA-EAP-SHA256 can be
# added to enable SHA256-based stronger algorithms.
# (dot11RSNAConfigAuthenticationSuitesTable)
#wpa_key_mgmt=WPA-PSK WPA-EAP
wpa_key_mgmt=WPA-PSK

# Set of accepted cipher suites (encryption algorithms) for pairwise keys
# (unicast packets). This is a space separated list of algorithms:
# CCMP = AES in Counter mode with CBC-MAC [RFC 3610, IEEE 802.11i/D7.0]
# TKIP = Temporal Key Integrity Protocol [IEEE 802.11i/D7.0]
# Group cipher suite (encryption algorithm for broadcast and multicast frames)
# is automatically selected based on this configuration. If only CCMP is
# allowed as the pairwise cipher, group cipher will also be CCMP. Otherwise,
# TKIP will be used as the group cipher.
# (dot11RSNAConfigPairwiseCiphersTable)
# Pairwise cipher for WPA (v1) (default: TKIP)
wpa_pairwise=%s
# Pairwise cipher for RSN/WPA2 (default: use wpa_pairwise value)
rsn_pairwise=%s
'''


## WPA-EAP Configuration
hostapd_wpa_eap_cnf='''##### hostapd configuration file ##############################################
# Empty lines and lines starting with # are ignored

# Driver interface type (hostap/wired/none/nl80211/bsd);
# default: hostap). nl80211 is used with all Linux mac80211 drivers.
# Use driver=none if building hostapd as a standalone RADIUS server that does
# not control any wireless/wired driver.
# driver=hostap
%s

interface=%s

##### Logging Settings ########################################################
logger_syslog=-1
logger_stdout_level=3
#logger_syslog_level=2
#logger_stdout=-1
#logger_stdout_level=2

##### Multiple BSSID support ##################################################
bssid=%s

##### SSL configuration #######################################################
# May have to change these depending on build location
eap_user_file=%s
ca_cert=%s 				# ca_pem
server_cert=%s 			# server_pem
private_key=%s
private_key_passwd=whatever
dh_file=%s

##### IEEE 802.11 related configuration #######################################

ssid=%s

# Operation mode (a = IEEE 802.11a (5 GHz), b = IEEE 802.11b (2.4 GHz),
# g = IEEE 802.11g (2.4 GHz), ad = IEEE 802.11ad (60 GHz); a/g options are used
# with IEEE 802.11n (HT), too, to specify band). For IEEE 802.11ac (VHT), this
# needs to be set to hw_mode=a. When using ACS (see channel parameter), a
# special value "any" can be used to indicate that any support band can be used.
# This special case is currently supported only with drivers with which
# offloaded ACS is used.
# Default: IEEE 802.11b
hw_mode=%s

# Channel number (IEEE 802.11)
# (default: 0, i.e., not set)
# Please note that some drivers do not use this value from hostapd and the
# channel will need to be configured separately with iwconfig.
#
# If CONFIG_ACS build option is enabled, the channel can be selected
# automatically at run time by setting channel=acs_survey or channel=0, both of
# which will enable the ACS survey based algorithm.
channel=%d

# Country code (ISO/IEC 3166-1). Used to set regulatory domain.
# Set as needed to indicate country in which device is operating.
# This can limit available channels and transmit power.
%s

# Enable IEEE 802.11d. This advertises the country_code and the set of allowed
# channels and transmit power levels based on the regulatory limits. The
# country_code setting must be configured with the correct country for
# IEEE 802.11d functions.
# (default: 0 = disabled)
ieee80211d=%d

# Enable IEEE 802.11h. This enables radar detection and DFS support if
# available. DFS support is required on outdoor 5 GHz channels in most countries
# of the world. This can be used only with ieee80211d=1.
# (default: 0 = disabled)
ieee80211h=%d

# IEEE 802.11 specifies two authentication algorithms. hostapd can be
# configured to allow both of these or only one. Open system authentication
# should be used with IEEE 802.1X.
# Bit fields of allowed authentication algorithms:
# bit 0 = Open System Authentication
# bit 1 = Shared Key Authentication (requires WEP)
auth_algs=%d

# Send empty SSID in beacons and ignore probe request frames that do not
# specify full SSID, i.e., require stations to know SSID.
# default: disabled (0)
# 1 = send empty (length=0) SSID in beacon and ignore probe request for
#     broadcast SSID
# 2 = clear SSID (ASCII 0), but keep the original length (this may be required
#     with some clients that do not support empty SSID) and ignore probe
#     requests for broadcast SSID
ignore_broadcast_ssid=%d

# Station MAC address -based authentication
# Please note that this kind of access control requires a driver that uses
# hostapd to take care of management frame processing and as such, this can be
# used with driver=hostap or driver=nl80211, but not with driver=atheros.
# 0 = accept unless in deny list
# 1 = deny unless in accept list
# 2 = use external RADIUS server (accept/deny lists are searched first)
macaddr_acl=%d

# Default WMM parameters (IEEE 802.11 draft; 11-03-0504-03-000e):
# for 802.11a or 802.11g networks
# These parameters are sent to WMM clients when they associate.
# The parameters will be used by WMM clients for frames transmitted to the
# access point.
#
# note - txop_limit is in units of 32microseconds
# note - acm is admission control mandatory flag. 0 = admission control not
# required, 1 = mandatory
# note - Here cwMin and cmMax are in exponent form. The actual cw value used
# will be (2^n)-1 where n is the value given here. The allowed range for these
# wmm_ac_??_{cwmin,cwmax} is 0..15 with cwmax >= cwmin.
%s

# Client isolation can be used to prevent low-level bridging of frames between
# associated stations in the BSS. By default, this bridging is allowed.
ap_isolate=%d

##### IEEE 802.11n related configuration ######################################

# ieee80211n: Whether IEEE 802.11n (HT) is enabled
# 0 = disabled (default)
# 1 = enabled
# Note: You will also need to enable WMM for full HT functionality.
# Note: hw_mode=g (2.4 GHz) and hw_mode=a (5 GHz) is used to specify the band.
ieee80211n=%d

# ht_capab: HT capabilities (list of flags)
# LDPC coding capability: [LDPC] = supported
# Supported channel width set: [HT40-] = both 20 MHz and 40 MHz with secondary
#	channel below the primary channel; [HT40+] = both 20 MHz and 40 MHz
#	with secondary channel above the primary channel
#	(20 MHz only if neither is set)
#	Note: There are limits on which channels can be used with HT40- and
#	HT40+. Following table shows the channels that may be available for
#	HT40- and HT40+ use per IEEE 802.11n Annex J:
#	freq		HT40-		HT40+
#	2.4 GHz		5-13		1-7 (1-9 in Europe/Japan)
#	5 GHz		40,48,56,64	36,44,52,60
#	(depending on the location, not all of these channels may be available
#	for use)
#	Please note that 40 MHz channels may switch their primary and secondary
#	channels if needed or creation of 40 MHz channel maybe rejected based
#	on overlapping BSSes. These changes are done automatically when hostapd
#	is setting up the 40 MHz channel.
# Spatial Multiplexing (SM) Power Save: [SMPS-STATIC] or [SMPS-DYNAMIC]
#	(SMPS disabled if neither is set)
# HT-greenfield: [GF] (disabled if not set)
# Short GI for 20 MHz: [SHORT-GI-20] (disabled if not set)
# Short GI for 40 MHz: [SHORT-GI-40] (disabled if not set)
# Tx STBC: [TX-STBC] (disabled if not set)
# Rx STBC: [RX-STBC1] (one spatial stream), [RX-STBC12] (one or two spatial
#	streams), or [RX-STBC123] (one, two, or three spatial streams); Rx STBC
#	disabled if none of these set
# HT-delayed Block Ack: [DELAYED-BA] (disabled if not set)
# Maximum A-MSDU length: [MAX-AMSDU-7935] for 7935 octets (3839 octets if not
#	set)
# DSSS/CCK Mode in 40 MHz: [DSSS_CCK-40] = allowed (not allowed if not set)
# 40 MHz intolerant [40-INTOLERANT] (not advertised if not set)
# L-SIG TXOP protection support: [LSIG-TXOP-PROT] (disabled if not set)
#ht_capab=
%s

# Require stations to support HT PHY (reject association if they do not)
require_ht=%d

##### IEEE 802.11ac related configuration #####################################

# ieee80211ac: Whether IEEE 802.11ac (VHT) is enabled
# 0 = disabled (default)
# 1 = enabled
# Note: You will also need to enable WMM for full VHT functionality.
# Note: hw_mode=a is used to specify that 5 GHz band is used with VHT.
ieee80211ac=%d

# vht_capab: VHT capabilities (list of flags)
#
# vht_max_mpdu_len: [MAX-MPDU-7991] [MAX-MPDU-11454]
# Indicates maximum MPDU length
# 0 = 3895 octets (default)
# 1 = 7991 octets
# 2 = 11454 octets
# 3 = reserved
#
# supported_chan_width: [VHT160] [VHT160-80PLUS80]
# Indicates supported Channel widths
# 0 = 160 MHz & 80+80 channel widths are not supported (default)
# 1 = 160 MHz channel width is supported
# 2 = 160 MHz & 80+80 channel widths are supported
# 3 = reserved
#
# Rx LDPC coding capability: [RXLDPC]
# Indicates support for receiving LDPC coded pkts
# 0 = Not supported (default)
# 1 = Supported
#
# Short GI for 80 MHz: [SHORT-GI-80]
# Indicates short GI support for reception of packets transmitted with TXVECTOR
# params format equal to VHT and CBW = 80Mhz
# 0 = Not supported (default)
# 1 = Supported
#
# Short GI for 160 MHz: [SHORT-GI-160]
# Indicates short GI support for reception of packets transmitted with TXVECTOR
# params format equal to VHT and CBW = 160Mhz
# 0 = Not supported (default)
# 1 = Supported
#
# Tx STBC: [TX-STBC-2BY1]
# Indicates support for the transmission of at least 2x1 STBC
# 0 = Not supported (default)
# 1 = Supported
#
# Rx STBC: [RX-STBC-1] [RX-STBC-12] [RX-STBC-123] [RX-STBC-1234]
# Indicates support for the reception of PPDUs using STBC
# 0 = Not supported (default)
# 1 = support of one spatial stream
# 2 = support of one and two spatial streams
# 3 = support of one, two and three spatial streams
# 4 = support of one, two, three and four spatial streams
# 5,6,7 = reserved
#
# SU Beamformer Capable: [SU-BEAMFORMER]
# Indicates support for operation as a single user beamformer
# 0 = Not supported (default)
# 1 = Supported
#
# Compressed Steering Number of Beamformer Antennas Supported:
# [BF-ANTENNA-2] [BF-ANTENNA-3] [BF-ANTENNA-4]
#   Beamformee's capability indicating the maximum number of beamformer
#   antennas the beamformee can support when sending compressed beamforming
#   feedback
# If SU beamformer capable, set to maximum value minus 1
# else reserved (default)
#
# MU Beamformer Capable: [MU-BEAMFORMER]
# Indicates support for operation as an MU beamformer
# 0 = Not supported or sent by Non-AP STA (default)
# 1 = Supported
#
# VHT TXOP PS: [VHT-TXOP-PS]
# Indicates whether or not the AP supports VHT TXOP Power Save Mode
#  or whether or not the STA is in VHT TXOP Power Save mode
# 0 = VHT AP doesn't support VHT TXOP PS mode (OR) VHT STA not in VHT TXOP PS
#  mode
# 1 = VHT AP supports VHT TXOP PS mode (OR) VHT STA is in VHT TXOP power save
#  mode
#
# +HTC-VHT Capable: [HTC-VHT]
# Indicates whether or not the STA supports receiving a VHT variant HT Control
# field.
# 0 = Not supported (default)
# 1 = supported
#
# Maximum A-MPDU Length Exponent: [MAX-A-MPDU-LEN-EXP0]..[MAX-A-MPDU-LEN-EXP7]
# Indicates the maximum length of A-MPDU pre-EOF padding that the STA can recv
# This field is an integer in the range of 0 to 7.
# The length defined by this field is equal to
# 2 pow(13 + Maximum A-MPDU Length Exponent) -1 octets
#
# VHT Link Adaptation Capable: [VHT-LINK-ADAPT2] [VHT-LINK-ADAPT3]
# Indicates whether or not the STA supports link adaptation using VHT variant
# HT Control field
# If +HTC-VHTcapable is 1
#  0 = (no feedback) if the STA does not provide VHT MFB (default)
#  1 = reserved
#  2 = (Unsolicited) if the STA provides only unsolicited VHT MFB
#  3 = (Both) if the STA can provide VHT MFB in response to VHT MRQ and if the
#      STA provides unsolicited VHT MFB
# Reserved if +HTC-VHTcapable is 0
#
# Rx Antenna Pattern Consistency: [RX-ANTENNA-PATTERN]
# Indicates the possibility of Rx antenna pattern change
# 0 = Rx antenna pattern might change during the lifetime of an association
# 1 = Rx antenna pattern does not change during the lifetime of an association
#
# Tx Antenna Pattern Consistency: [TX-ANTENNA-PATTERN]
# Indicates the possibility of Tx antenna pattern change
# 0 = Tx antenna pattern might change during the lifetime of an association
# 1 = Tx antenna pattern does not change during the lifetime of an association
#vht_capab=[SHORT-GI-80][HTC-VHT]
#
# Require stations to support VHT PHY (reject association if they do not)
require_vht=%d

# 0 = 20 or 40 MHz operating Channel width
# 1 = 80 MHz channel width
# 2 = 160 MHz channel width
# 3 = 80+80 MHz channel width
vht_oper_chwidth=%d
#
# center freq = 5 GHz + (5 * index)
# So index 42 gives center freq 5.210 GHz
# which is channel 42 in 5G band
#
#vht_oper_centr_freq_seg0_idx=42
#
# center freq = 5 GHz + (5 * index)
# So index 159 gives center freq 5.795 GHz
# which is channel 159 in 5G band
#
#vht_oper_centr_freq_seg1_idx=159
%s

# Workaround to use station's nsts capability in (Re)Association Response frame
# This may be needed with some deployed devices as an interoperability
# workaround for beamforming if the AP's capability is greater than the
# station's capability. This is disabled by default and can be enabled by
# setting use_sta_nsts=1.
#use_sta_nsts=0

##### WPA/IEEE 802.11i configuration ##########################################

# Enable WPA. Setting this variable configures the AP to require WPA (either
# WPA-PSK or WPA-RADIUS/EAP based on other configuration). For WPA-PSK, either
# wpa_psk or wpa_passphrase must be set and wpa_key_mgmt must include WPA-PSK.
# Instead of wpa_psk / wpa_passphrase, wpa_psk_radius might suffice.
# For WPA-RADIUS/EAP, ieee8021x must be set (but without dynamic WEP keys),
# RADIUS authentication server must be configured, and WPA-EAP must be included
# in wpa_key_mgmt.
# This field is a bit field that can be used to enable WPA (IEEE 802.11i/D3.0)
# and/or WPA2 (full IEEE 802.11i/RSN):
# bit0 = WPA
# bit1 = IEEE 802.11i/RSN (WPA2) (dot11RSNAEnabled)
wpa=%d

# WPA pre-shared keys for WPA-PSK. This can be either entered as a 256-bit
# secret in hex format (64 hex digits), wpa_psk, or as an ASCII passphrase
# (8..63 characters) that will be converted to PSK. This conversion uses SSID
# so the PSK changes when ASCII passphrase is used and the SSID is changed.
# wpa_psk (dot11RSNAConfigPSKValue)
# wpa_passphrase (dot11RSNAConfigPSKPassPhrase)
#wpa_psk=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
#wpa_passphrase=secret passphrase

# Set of accepted key management algorithms (WPA-PSK, WPA-EAP, or both). The
# entries are separated with a space. WPA-PSK-SHA256 and WPA-EAP-SHA256 can be
# added to enable SHA256-based stronger algorithms.
# (dot11RSNAConfigAuthenticationSuitesTable)
#wpa_key_mgmt=WPA-PSK WPA-EAP
wpa_key_mgmt=WPA-EAP

# Set of accepted cipher suites (encryption algorithms) for pairwise keys
# (unicast packets). This is a space separated list of algorithms:
# CCMP = AES in Counter mode with CBC-MAC [RFC 3610, IEEE 802.11i/D7.0]
# TKIP = Temporal Key Integrity Protocol [IEEE 802.11i/D7.0]
# Group cipher suite (encryption algorithm for broadcast and multicast frames)
# is automatically selected based on this configuration. If only CCMP is
# allowed as the pairwise cipher, group cipher will also be CCMP. Otherwise,
# TKIP will be used as the group cipher.
# (dot11RSNAConfigPairwiseCiphersTable)
# Pairwise cipher for WPA (v1) (default: TKIP)
wpa_pairwise=%s
# Pairwise cipher for RSN/WPA2 (default: use wpa_pairwise value)
rsn_pairwise=%s

##### IEEE 802.1X-2004 related configuration ##################################

# Require IEEE 802.1X authorization
ieee8021x=%d

# IEEE 802.1X/EAPOL version
# hostapd is implemented based on IEEE Std 802.1X-2004 which defines EAPOL
# version 2. However, there are many client implementations that do not handle
# the new version number correctly (they seem to drop the frames completely).
# In order to make hostapd interoperate with these clients, the version number
# can be set to the older version (1) with this configuration value.
eapol_version=%d

# Optional displayable message sent with EAP Request-Identity. The first \0
# in this string will be converted to ASCII-0 (nul). This can be used to
# separate network info (comma separated list of attribute=value pairs); see,
# e.g., RFC 4284.
#eap_message=hello
#eap_message=hello\0networkid=netw,nasid=foo,portid=0,NAIRealms=example.com

# WEP rekeying (disabled if key lengths are not set or are set to 0)
# Key lengths for default/broadcast and individual/unicast keys:
# 5 = 40-bit WEP (also known as 64-bit WEP with 40 secret bits)
# 13 = 104-bit WEP (also known as 128-bit WEP with 104 secret bits)
#wep_key_len_broadcast=5
#wep_key_len_unicast=5
# Rekeying period in seconds. 0 = do not rekey (i.e., set keys only once)
#wep_rekey_period=300

# EAPOL-Key index workaround (set bit7) for WinXP Supplicant (needed only if
# only broadcast keys are used)
eapol_key_index_workaround=%d

# EAP reauthentication period in seconds (default: 3600 seconds; 0 = disable
# reauthentication).
#eap_reauth_period=3600

# Use PAE group address (01:80:c2:00:00:03) instead of individual target
# address when sending EAPOL frames with driver=wired. This is the most common
# mechanism used in wired authentication, but it also requires that the port
# is only used by one station.
#use_pae_group_addr=1

# EAP Re-authentication Protocol (ERP) authenticator (RFC 6696)
#
# Whether to initiate EAP authentication with EAP-Initiate/Re-auth-Start before
# EAP-Identity/Request
#erp_send_reauth_start=1
#
# Domain name for EAP-Initiate/Re-auth-Start. Omitted from the message if not
# set (no local ER server). This is also used by the integrated EAP server if
# ERP is enabled (eap_server_erp=1).
#erp_domain=example.com

##### RADIUS client configuration #############################################
# for IEEE 802.1X with external Authentication Server, IEEE 802.11
# authentication with external ACL for MAC addresses, and accounting

# The own IP address of the access point (used as NAS-IP-Address)
own_ip_addr=%s

# NAS-Identifier string for RADIUS messages. When used, this should be unique
# to the NAS within the scope of the RADIUS server. Please note that hostapd
# uses a separate RADIUS client for each BSS and as such, a unique
# nas_identifier value should be configured separately for each BSS. This is
# particularly important for cases where RADIUS accounting is used
# (Accounting-On/Off messages are interpreted as clearing all ongoing sessions
# and that may get interpreted as applying to all BSSes if the same
# NAS-Identifier value is used.) For example, a fully qualified domain name
# prefixed with a unique identifier of the BSS (e.g., BSSID) can be used here.
#
# When using IEEE 802.11r, nas_identifier must be set and must be between 1 and
# 48 octets long.
#
# It is mandatory to configure either own_ip_addr or nas_identifier to be
# compliant with the RADIUS protocol. When using RADIUS accounting, it is
# strongly recommended that nas_identifier is set to a unique value for each
# BSS.
#nas_identifier=ap.example.com

# RADIUS client forced local IP address for the access point
# Normally the local IP address is determined automatically based on configured
# IP addresses, but this field can be used to force a specific address to be
# used, e.g., when the device has multiple IP addresses.
#radius_client_addr=127.0.0.1

# RADIUS authentication server
auth_server_addr=%s
auth_server_port=%d
auth_server_shared_secret=%s

# RADIUS accounting server
acct_server_addr=%s
acct_server_port=%d
acct_server_shared_secret=%s

# Secondary RADIUS servers; to be used if primary one does not reply to
# RADIUS packets. These are optional and there can be more than one secondary
# server listed.
#auth_server_addr=127.0.0.2
#auth_server_port=1812
#auth_server_shared_secret=secret2
#
#acct_server_addr=127.0.0.2
#acct_server_port=1813
#acct_server_shared_secret=secret2

# Retry interval for trying to return to the primary RADIUS server (in
# seconds). RADIUS client code will automatically try to use the next server
# when the current server is not replying to requests. If this interval is set,
# primary server will be retried after configured amount of time even if the
# currently used secondary server is still working.
#radius_retry_primary_interval=600


# Interim accounting update interval
# If this is set (larger than 0) and acct_server is configured, hostapd will
# send interim accounting updates every N seconds. Note: if set, this overrides
# possible Acct-Interim-Interval attribute in Access-Accept message. Thus, this
# value should not be configured in hostapd.conf, if RADIUS server is used to
# control the interim interval.
# This value should not be less 600 (10 minutes) and must not be less than
# 60 (1 minute).
#radius_acct_interim_interval=600

# Request Chargeable-User-Identity (RFC 4372)
# This parameter can be used to configure hostapd to request CUI from the
# RADIUS server by including Chargeable-User-Identity attribute into
# Access-Request packets.
#radius_request_cui=1

# Dynamic VLAN mode; allow RADIUS authentication server to decide which VLAN
# is used for the stations. This information is parsed from following RADIUS
# attributes based on RFC 3580 and RFC 2868: Tunnel-Type (value 13 = VLAN),
# Tunnel-Medium-Type (value 6 = IEEE 802), Tunnel-Private-Group-ID (value
# VLANID as a string). Optionally, the local MAC ACL list (accept_mac_file) can
# be used to set static client MAC address to VLAN ID mapping.
# 0 = disabled (default)
# 1 = option; use default interface if RADIUS server does not include VLAN ID
# 2 = required; reject authentication if RADIUS server does not include VLAN ID
#dynamic_vlan=0

# Per-Station AP_VLAN interface mode
# If enabled, each station is assigned its own AP_VLAN interface.
# This implies per-station group keying and ebtables filtering of inter-STA
# traffic (when passed through the AP).
# If the sta is not assigned to any VLAN, then its AP_VLAN interface will be
# added to the bridge given by the "bridge" configuration option (see above).
# Otherwise, it will be added to the per-VLAN bridge.
# 0 = disabled (default)
# 1 = enabled
#per_sta_vif=0

# VLAN interface list for dynamic VLAN mode is read from a separate text file.
# This list is used to map VLAN ID from the RADIUS server to a network
# interface. Each station is bound to one interface in the same way as with
# multiple BSSIDs or SSIDs. Each line in this text file is defining a new
# interface and the line must include VLAN ID and interface name separated by
# white space (space or tab).
# If no entries are provided by this file, the station is statically mapped
# to <bss-iface>.<vlan-id> interfaces.
#vlan_file=/etc/hostapd.vlan

# Interface where 802.1q tagged packets should appear when a RADIUS server is
# used to determine which VLAN a station is on.  hostapd creates a bridge for
# each VLAN.  Then hostapd adds a VLAN interface (associated with the interface
# indicated by 'vlan_tagged_interface') and the appropriate wireless interface
# to the bridge.
#vlan_tagged_interface=eth0

# Bridge (prefix) to add the wifi and the tagged interface to. This gets the
# VLAN ID appended. 
#vlan_bridge=brvlan

# When hostapd creates a VLAN interface on vlan_tagged_interfaces, it needs
# to know how to name it.
# 0 = vlan<XXX>, e.g., vlan1
# 1 = <vlan_tagged_interface>.<XXX>, e.g. eth0.1
#vlan_naming=0

# Arbitrary RADIUS attributes can be added into Access-Request and
# Accounting-Request packets by specifying the contents of the attributes with
# the following configuration parameters. There can be multiple of these to
# add multiple attributes. These parameters can also be used to override some
# of the attributes added automatically by hostapd.
# Format: <attr_id>[:<syntax:value>]
# attr_id: RADIUS attribute type (e.g., 26 = Vendor-Specific)
# syntax: s = string (UTF-8), d = integer, x = octet string
# value: attribute value in format indicated by the syntax
# If syntax and value parts are omitted, a null value (single 0x00 octet) is
# used.
#
# Additional Access-Request attributes
# radius_auth_req_attr=<attr_id>[:<syntax:value>]
# Examples:
# Operator-Name = "Operator"
#radius_auth_req_attr=126:s:Operator
# Service-Type = Framed (2)
#radius_auth_req_attr=6:d:2
# Connect-Info = "testing" (this overrides the automatically generated value)
#radius_auth_req_attr=77:s:testing
# Same Connect-Info value set as a hexdump
#radius_auth_req_attr=77:x:74657374696e67

#
# Additional Accounting-Request attributes
# radius_acct_req_attr=<attr_id>[:<syntax:value>]
# Examples:
# Operator-Name = "Operator"
#radius_acct_req_attr=126:s:Operator

# Dynamic Authorization Extensions (RFC 5176)
# This mechanism can be used to allow dynamic changes to user session based on
# commands from a RADIUS server (or some other disconnect client that has the
# needed session information). For example, Disconnect message can be used to
# request an associated station to be disconnected.
#
# This is disabled by default. Set radius_das_port to non-zero UDP port
# number to enable.
#radius_das_port=3799
#
# DAS client (the host that can send Disconnect/CoA requests) and shared secret
#radius_das_client=192.168.1.123 shared secret here
#
# DAS Event-Timestamp time window in seconds
#radius_das_time_window=300
#
# DAS require Event-Timestamp
#radius_das_require_event_timestamp=1
#
# DAS require Message-Authenticator
#radius_das_require_message_authenticator=1
'''
