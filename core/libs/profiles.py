#!/usr/bin/python3
'''
Data-driven 802.11 preset-profile builders.

Each preset ('wifi1'..'wifiN') is described declaratively in PROFILES and
applied to the parsed options dict by apply_profile(). This replaces the
previously copy-pasted if/elif chain in options.py so that shared settings
(notably the WMM/EDCA parameter block, which was identical across every
profile) live in a single place.

Field values may be:
  * a plain literal            -> written to options unconditionally
  * an Overridable(flag, dflt) -> the preset default is applied only when the
                                  user did NOT supply the corresponding CLI
                                  flag; otherwise their parsed value is kept.

The special key 'freq_dependent_hw_mode' selects the hardware mode from the
requested radio band (used by 802.11n, which is valid on both 2.4 and 5 GHz).
'''
import sys

# WMM (WME) EDCA parameters shared by every preset profile.
WMM_AC_DEFAULTS = {
    'wmm_ac_bk_cwmin': 5,
    'wmm_ac_bk_cwmax': 10,
    'wmm_ac_bk_aifs': 7,
    'wmm_ac_bk_txop_limit': 0,
    'wmm_ac_bk_acm': 0,
    'wmm_ac_be_aifs': 3,
    'wmm_ac_be_cwmin': 5,
    'wmm_ac_be_cwmax': 7,
    'wmm_ac_be_txop_limit': 0,
    'wmm_ac_be_acm': 0,
    'wmm_ac_vi_aifs': 2,
    'wmm_ac_vi_cwmin': 4,
    'wmm_ac_vi_cwmax': 5,
    'wmm_ac_vi_txop_limit': 188,
    'wmm_ac_vi_acm': 0,
    'wmm_ac_vo_aifs': 2,
    'wmm_ac_vo_cwmin': 3,
    'wmm_ac_vo_cwmax': 4,
    'wmm_ac_vo_txop_limit': 47,
    'wmm_ac_vo_acm': 0,
}


class Overridable(object):
    '''
    Marks a preset field whose default is applied only when the user did NOT
    supply the corresponding CLI flag. If the flag is present in argv the value
    already parsed into options (i.e. the user's choice) is preserved.
    '''
    def __init__(self, cli_flag, default):
        self.cli_flag = cli_flag
        self.default = default


class ProfileError(Exception):
    '''
    Raised by apply_profile() when a profile is selected with an unsupported
    option combination (e.g. wifi6 on the 6 GHz band before Wi-Fi 6E support
    lands). The caller is expected to translate this into a parser error.
    '''
    pass

'''
Preset profiles that are accepted as choices but not yet implemented.
Selecting one produces the historical "not implemented yet" error rather than
being treated as an unknown profile. (Kept for future generations, e.g. wifi8.)
'''
NOT_IMPLEMENTED = set()

PROFILES = {
    # 802.11b
    'wifi1': {
        'hw_mode': 'b',
        'freq': 2,
        'ieee80211n': 0,
        'ieee80211ac': 0,
        'wmm_enabled': Overridable('--wmm-enabled', False),
        'require_ht': Overridable('--require-ht', False),
        'require_vht': Overridable('--require-vht', False),
    },
    # 802.11a
    'wifi2': {
        'hw_mode': 'a',
        'freq': 5,
        'ieee80211n': 0,
        'ieee80211ac': 0,
        'wmm_enabled': Overridable('--wmm-enabled', False),
        'require_ht': Overridable('--require-ht', False),
        'require_vht': Overridable('--require-vht', False),
    },
    # 802.11g
    'wifi3': {
        'hw_mode': 'g',
        'freq': 2,
        'ieee80211n': 0,
        'ieee80211ac': 0,
        'wmm_enabled': Overridable('--wmm-enabled', False),
        'require_ht': Overridable('--require-ht', False),
        'require_vht': Overridable('--require-vht', False),
    },
    # 802.11n (High Throughput) - valid on both 2.4 and 5 GHz
    'wifi4': {
        'freq_dependent_hw_mode': True,
        'ieee80211n': 1,
        'ieee80211ac': 0,
        'wmm_enabled': Overridable('--wmm-enabled', False),
        'require_ht': True,
        'require_vht': Overridable('--require-vht', False),
        'ht_rx_stbc1': Overridable('--enable-rx-stbc1', False),
        'ht_msdu7935': Overridable('--enable-msdu7935', False),
        'ht_dsss_cck': Overridable('--enable-cck', False),
    },
    # 802.11ac (Very High Throughput)
    'wifi5': {
        'hw_mode': 'a',
        'freq': 5,
        'ieee80211n': 1,
        'ieee80211ac': 1,
        'wmm_enabled': True,
        'require_ht': True,
        'require_vht': True,
        'ht_rx_stbc1': Overridable('--enable-rx-stbc1', False),
        'ht_msdu7935': Overridable('--enable-msdu7935', False),
        'ht_dsss_cck': Overridable('--enable-cck', False),
    },
    # 802.11ax (High Efficiency / Wi-Fi 6)
    #
    # Defaults to 5 GHz; --freq overrides the band. hw_mode/freq/ieee80211n/
    # ieee80211ac/vht_oper_chwidth are derived per band by the
    # 'band_default_hw_mode' handler in apply_profile() (so they are absent
    # here). HE is always on (ieee80211ax=1) and WMM is required. HT/VHT are
    # advertised but not *required* by default, so non-HE clients can associate.
    'wifi6': {
        'band_default_hw_mode': True,
        'ieee80211ax': 1,
        'wmm_enabled': True,
        'require_ht': Overridable('--require-ht', False),
        'require_vht': Overridable('--require-vht', False),
        'ht_rx_stbc1': Overridable('--enable-rx-stbc1', False),
        'ht_msdu7935': Overridable('--enable-msdu7935', False),
        'ht_dsss_cck': Overridable('--enable-cck', False),
    },
    # 802.11be (Extremely High Throughput / Wi-Fi 7)
    #
    # Same band-derived PHY as wifi6 plus EHT (ieee80211be=1). EHT builds on HE,
    # so ieee80211ax is on too. EHT mandates WPA3/OWE + PMF on *every* band, which
    # optionsClass.check_wpa3_required() enforces. (320 MHz / MLO are future work;
    # this ships EHT up to the per-band HE width, e.g. 80/160 MHz.)
    'wifi7': {
        'band_default_hw_mode': True,
        'ieee80211ax': 1,
        'ieee80211be': 1,
        'wmm_enabled': True,
        'require_ht': Overridable('--require-ht', False),
        'require_vht': Overridable('--require-vht', False),
        'ht_rx_stbc1': Overridable('--enable-rx-stbc1', False),
        'ht_msdu7935': Overridable('--enable-msdu7935', False),
        'ht_dsss_cck': Overridable('--enable-cck', False),
    },
}


def _resolve(value, key, options, argv):
    if isinstance(value, Overridable):
        return options[key] if value.cli_flag in argv else value.default
    return value


def apply_profile(options, name, argv=None):
    '''
    Apply a named preset profile to the parsed options dict in place.

    Returns True if a known profile was applied, False if the name is unknown
    (so the caller can raise its own parser error).
    '''
    if argv is None:
        argv = sys.argv

    profile = PROFILES.get(name)
    if profile is None:
        return False

    '''
    Ensure the HE toggle always exists in the options dict so downstream
    rendering never hits a KeyError; profiles that enable it override below.
    '''
    options.setdefault('ieee80211ax', 0)
    options.setdefault('ieee80211be', 0)

    # Shared WMM/EDCA parameter block (identical across every profile).
    options.update(WMM_AC_DEFAULTS)

    # 802.11n allows either band; derive hw_mode from the requested frequency.
    if profile.get('freq_dependent_hw_mode'):
        options['hw_mode'] = 'a' if options['freq'] == 5 else 'g'
        options['freq'] = 5 if options['freq'] == 5 else 2

    # 802.11ax (Wi-Fi 6): default to 5 GHz, but honour --freq (2/5/6).
    #   2 GHz -> hw_mode g, HT on, VHT off, 20 MHz
    #   5 GHz -> hw_mode a, HT+VHT on, 80 MHz (the Wi-Fi 6 default)
    #   6 GHz -> hw_mode a, HE-only (no HT/VHT), 80 MHz (Wi-Fi 6E). Security is
    #           forced to WPA3/OWE + PMF by optionsClass.check_6ghz().
    # A user-supplied --vht-width always wins for the channel width.
    if profile.get('band_default_hw_mode'):
        freq = options['freq'] if '--freq' in argv else 5
        options['freq'] = freq
        user_width = '--vht-width' in argv
        if freq == 6:
            options['hw_mode'] = 'a'
            options['ieee80211n'] = 0
            options['ieee80211ac'] = 0
            if not user_width:
                options['vht_oper_chwidth'] = 1   # 80 MHz
        elif freq == 2:
            options['hw_mode'] = 'g'
            options['ieee80211n'] = 1
            options['ieee80211ac'] = 0
            if not user_width:
                options['vht_oper_chwidth'] = 0   # 20 MHz
        else:  # 5 GHz
            options['hw_mode'] = 'a'
            options['ieee80211n'] = 1
            options['ieee80211ac'] = 1
            if not user_width:
                options['vht_oper_chwidth'] = 1   # 80 MHz

    for key, value in profile.items():
        if key in ('freq_dependent_hw_mode', 'band_default_hw_mode'):
            continue
        options[key] = _resolve(value, key, options, argv)

    return True
