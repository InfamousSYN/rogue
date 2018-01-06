#!/usr/bin/python


def insert(webroot, target_file, addr, hook, marker):
    try:
        f = open(webroot + target_file, "r")
        lines = f.readlines()
        f.close()
    
        try:
            i = lines.index(marker)
            print("[+] Attempting to insert the %s hook into %s at line %d" % (hook, target_file, i))
            lines.insert(i, (hook % addr))
        except Exception as e:
            print("[!] The target file \"%s\" did not contain the searched marker: %s" % (target_file, marker))
            print("[!] Exception: %s" % e)
            return 1
    
        with open(webroot + target_file, "w") as f:
            f.write(''.join(lines))
            f.close()
    except Exception as e:
        print("[!] Target site has not been cloned. Please use --clone-wizard to clone target site.")