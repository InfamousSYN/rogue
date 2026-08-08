#!/usr/bin/python3
'''
Builds hostapd-wpe from source for the Rogue toolkit.

Rather than depend on the apt `hostapd-wpe` package (which is old and typically
built without 802.11ax/be), rogue builds its own hostapd from upstream `hostap`
at a pinned tag, applies the shipped rogue patch (KARMA support), enables the
required capabilities via a config overlay, compiles, and installs the binary
to a rogue-owned prefix.

Pinned versions and paths come from config.py:
  hostapd_src_repo, hostapd_src_ref, hostapd_build_dir,
  hostapd_patch, hostapd_config_overlay, hostapd_prefix, hostapd_bin
'''
import os
import re
import shutil
import config


def _sh(cmd):
    print("[*]   %s" % cmd)
    return os.system(cmd)


def _ensure_config_options(dotconfig, overlay):
    '''
    Ensure every `CONFIG_X=...` line in the overlay is set in .config,
    replacing any existing commented or differing definition of that key.
    '''
    wanted = []
    with open(overlay) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            token = line.split('#', 1)[0].strip()  # drop any inline comment
            if token:
                wanted.append(token)
    with open(dotconfig) as f:
        lines = f.read().splitlines()
    for w in wanted:
        key = w.split('=')[0]
        pat = re.compile(r'^#?\s*' + re.escape(key) + r'=')
        lines = [ln for ln in lines if not pat.match(ln)]
        lines.append(w)
    with open(dotconfig, 'w') as f:
        f.write('\n'.join(lines) + '\n')


def build(force=False):
    # Clone -> patch -> configure -> compile -> install. Returns 0 on success.
    repo = config.hostapd_src_repo
    ref = config.hostapd_src_ref
    build_dir = config.hostapd_build_dir
    prefix = config.hostapd_prefix
    binout = config.hostapd_bin

    if (not force) and os.path.isfile(binout):
        print("[*] hostapd-wpe already built at %s (skipping; rebuild with --force-hostapd)" % binout)
        return 0

    print("[*] Building hostapd-wpe from source (%s @ %s)" % (repo, ref))

    # Always start from a clean checkout so patching/config is deterministic.
    if os.path.isdir(build_dir):
        shutil.rmtree(build_dir)
    parent = os.path.dirname(build_dir)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)

    if _sh("git clone --depth 1 --branch %s %s %s" % (ref, repo, build_dir)) != 0:
        print("[!] Failed to clone hostap source")
        return 1

    if _sh("cd %s && patch -p1 < %s" % (build_dir, config.hostapd_patch)) != 0:
        print("[!] Failed to apply rogue hostapd patch")
        return 1

    hostapd_subdir = os.path.join(build_dir, 'hostapd')
    dotconfig = os.path.join(hostapd_subdir, '.config')
    shutil.copyfile(os.path.join(hostapd_subdir, 'defconfig'), dotconfig)
    _ensure_config_options(dotconfig, config.hostapd_config_overlay)

    if _sh("make -C %s -j$(nproc)" % hostapd_subdir) != 0:
        print("[!] hostapd build failed (are the build dependencies installed? "
              "build-essential, pkg-config, libssl-dev, libnl-3-dev, libnl-genl-3-dev)")
        return 1

    if not os.path.isdir(prefix):
        os.makedirs(prefix)
    built = os.path.join(hostapd_subdir, 'hostapd')
    shutil.copyfile(built, binout)
    os.chmod(binout, 0o755)
    print("[*] hostapd-wpe installed -> %s" % binout)
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(build(force=('--force-hostapd' in sys.argv)))
