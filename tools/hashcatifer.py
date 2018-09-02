#!/usr/bin/python
import argparse
import re

def set_options():
    try:
        parser = argparse.ArgumentParser(
            prog='hashcatifer.py',
            description='hashcatifer is a tool used to convert captured credentials from freeradius-server-wpe\'s standard john (jtr) output to a hashcat supported format.',
            usage='Example: python hashcatifer -f /var/log/freeradius-server-wpe.log -o /tmp/hashcatifer.output'
            )

        parser.add_argument(
            '--file',
            '-f',
            dest='filename',
            default='/var/log/freeradius-server-wpe.log',
            help='Specify the name of file containing captured credentials'
            )

        parser.add_argument(
            '--output',
            '-o',
            dest='output',
            default='hashcatifer.output',
            help='Specify the name output file'
            )

        parser.add_argument(
            '--format',
            dest='format',
            choices=['NETNTLMv1'],
            default='NETNTLMv1',
            help='Specify the format to output hashes as'
            )

        parser.add_argument(
            '--mode',
            '-m',
            dest='mode',
            choices=['all','single'],
            default='single',
            help='Specify the number of hashes to reformat'
            )

        args, leftover = parser.parse_known_args()
        options = args.__dict__
        return 0, options

    except Exception as error:
        print('%s' % (error))
        return 1, 0

def getHash(fline):
    regex = re.compile('.*(?:\$NETNTLM\$).*')
    return re.search(regex, fline)

def getUser(fline, user_list):
    regex = re.compile('.*(?:\:\$)')
    username = re.search(regex, fline).group()
    if username in user_list:
        return False, user_list
    else:
        user_list.append(username)
        return True, user_list

def convert2NetNTLMv1(hash_list):
    new_hash_list = []
    regex = re.compile('(.*?):(\$.*?)\$(.*?)\$(.*)')
    for hash in hash_list:
        new_hash_list.append(regex.sub(r'\1::::\4:\3', hash).rstrip('\n\n'))
    return new_hash_list

def writeFile(outfile, hash_list):
    try:
        file = open(outfile, 'w')
        for hash in hash_list:
            file.write('%s\n' % hash)
        file.close()
    except Exception as error:
       return 1

    return 0

if __name__ == '__main__':
    rtn, opts = set_options()
    if rtn != 0:
        exit(rtn)

    try:
        hash_list = []
        user_list = []
        file = open(opts['filename'], 'r')
        flist = re.split('\s+', file.read())
        file.close()
        if(opts['mode'] == 'single'):
            for fline in flist:
                if(getHash(fline)):
                    check, username = getUser(fline, user_list)
                    if check:
                        hash_list.append(fline)
        elif(opts['mode'] == 'all'):
            for fline in flist:
                if(getHash(fline)):
                    hash_list.append(fline)
        else:
            pass
        if(opts['format'] == 'NETNTLMv1'):
            print("hashcat command: hashcat -m 5500 %s -w wordlist" % opts['output'])
            hash_list = convert2NetNTLMv1(hash_list)
        else:
            pass
        hash_list.sort()
        writeFile(opts['output'], hash_list)

    except Exception as error:
        print('%s' % (error))
        exit(1)

    exit(0)
