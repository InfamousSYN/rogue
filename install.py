#!/usr/bin/python3
import os
import config

def read_deps_file(deps_file):
  with open(deps_file) as fd:
    return " ".join([ line.strip() for line in fd ])

if __name__ == "__main__":
  try:
    if input("Do you want update your package list ('apt-get update')? [y/N]").lower() == "y":
      print("[*] Downloading package lists from repositories")
      os.system("apt-get update -y")
  
    print("[*] Installing Rogue's software dependencies...")
    os.system("apt-get install -y %s" % read_deps_file(config.software_dep))
    print("[*] complete!")
  
    print("[*] Installing Rogue's Python dependencies...")
    os.system("python3 -m pip install -r %s" % config.pip_dep)
    print("[*] complete!")

    # Check if required directories exist
    print("[*] Checking if rogue's temporary directory exists")
    try:
      os.stat(config.working_dir)
    except:
      print("[+] Creating rogue's temporary directory")
      os.mkdir(config.working_dir)

    print("[*] Checking if rogue's log directory exists")
    try:
      os.stat(config.logdir)
    except:
      print("[+] Creating rogue's log directory")
      os.mkdir(config.logdir)

    print("[*] Checking if sslsplit's temporary directory exists")
    try:
      os.stat(config.sslsplit_tmp)
    except:
      print("[+] Creating rogue's temporary sslsplit directory")
      os.mkdir(config.sslsplit_tmp)

    print("[*] Checking if sslsplit's jail directory exists")
    try:
      os.stat(config.sslsplit_jail)
    except:
      print("[+] Creating rogue's sslsplit jail directory")
      os.mkdir(config.sslsplit_jail)

  except KeyboardInterrupt:
    exit(0)
