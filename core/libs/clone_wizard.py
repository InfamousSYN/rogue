#!/usr/bin/python
import subprocess

def cloner(program, clone_target, clone_dest):
    try:
        subprocess.call([program, clone_target, '-O', clone_dest], shell=False)
        return 0
    except Exception as e:
        print("[!] Error: %s" % e)
        return 1

def clone_wizard(program, clone_target, clone_dest):
    print("Attempting to clone target side ['%s'] to destination ['%s']" % (clone_target, clone_dest))
    if (cloner(program, clone_target, clone_dest) != 0 ):
        raise
        return 1
    return 0