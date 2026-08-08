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

# WMM (WME) EDCA parameters shared by every preset profile. Previously these
# twenty values were copy-pasted verbatim into wifi1-wifi5.
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


# Preset profiles whose accepted as choices but not yet implemented. Selecting
# one produces the historical "not implemented yet" error rather than being
# treated as an unknown profile.
NOT_IMPLEMENTED = {'wifi6'}

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

    # Shared WMM/EDCA parameter block (identical across every profile).
    options.update(WMM_AC_DEFAULTS)

    # 802.11n allows either band; derive hw_mode from the requested frequency.
    if profile.get('freq_dependent_hw_mode'):
        options['hw_mode'] = 'a' if options['freq'] == 5 else 'g'
        options['freq'] = 5 if options['freq'] == 5 else 2

    for key, value in profile.items():
        if key == 'freq_dependent_hw_mode':
            continue
        options[key] = _resolve(value, key, options, argv)

    return True
