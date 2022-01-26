#!/usr/bin/env python3

__author__ = "Mike Bond"
__copyright__ = "Copyright (c) 2021"
__license__ = "MIT"
__originalDate__ = "20210805"
__modifiedDate__ = "20210805"
__version__ = "0.1"
__maintainer__ = "Mike Bond"
__status__ = "Beta"

"""
config-dump.py executes the snmpset binary and passes Cisco SNMP OID to download a configuration file to
a TFTP server.
"""

"""Import modules"""
import argparse
import os
import sys
import random
import time
from termcolor import colored

"""Define Color Status"""
error = '\033[1m\033[31m[!]\033[0m'
warning = '\033[1m\033[33m[-]\033[0m'
info = '\033[1m\033[94m[*]\033[0m'
complete = '\033[1m\033[92m[+]\033[0m'

""" Functions """
def snmp(auth,auth_pass,protocol,proto_pass,user,target_ip,tftp_ip):
    """
    The snmp function that uses snmpset to download a config file  based on args.type selection
    :param: auth
    :param: auth_pass
    :param: protocol
    :param: proto_pass
    :param: user
    :param: target_ip
    :param: tftp_ip
    :return:
    """
    try:
        random_number = str(random.randint(100,999))
        if protocol is not None:
            command = 'snmpset -v 3 -l authpriv -a {0} -A {1} -x {2} -X {3} -u {4} {5}'\
                      .format(auth,auth_pass,protocol,proto_pass,user,target_ip)
        else:
            command = 'snmpset -v 3 -l authpriv -a {0} -A {1} -u {2} {3}'\
                      .format(auth,auth_pass,user,target_ip)
        ccCopyProtocol = '.1.3.6.1.4.1.9.9.96.1.1.1.1.2.{0} i 1'.format(random_number)
        ccCopySourceFileType = '.1.3.6.1.4.1.9.9.96.1.1.1.1.3.{0} i 4'.format(random_number)
        ccCopyDestFileType = '.1.3.6.1.4.1.9.9.96.1.1.1.1.4.{0} i 1'.format(random_number)
        ccCopyServerAddress = '.1.3.6.1.4.1.9.9.96.1.1.1.1.5.{0} a {1}'.format(random_number,tftp_ip)
        ccCopyFileName = '.1.3.6.1.4.1.9.9.96.1.1.1.1.6.{0} s {1}-config.txt'.format(random_number,target_ip)
        ccCopyEntryRowStatus = '.1.3.6.1.4.1.9.9.96.1.1.1.1.14.{0} i 4'.format(random_number)
        dev_null = '>/dev/null 2>&1'
        session = command+' '+ccCopyProtocol+' '+ccCopySourceFileType+' '+ccCopyDestFileType+' '+ccCopyServerAddress+' '+\
                  ccCopyFileName+' '+ccCopyEntryRowStatus+' '+dev_null
        results = (os.system(session))
        if results == 256:
            print (results)
            print("{0} Issue with SNMP Username and/or Password!".format(error))
            return None

        if results == 512:
            print("{0} No SNMP Read/Write access or issue with encryption".format(error))
            return None

        else:
            time.sleep(1)
            command = "netstat -anup | grep 69 >/dev/null 2>&1"
            results = os.system(command)
            if results ==  0:
                if os.path.isfile("{0}-config.txt".format(target_ip)):
                    print ("{0} Configuration file from {1} saved as {1}-config.txt in current working directory"
                          .format(complete,target_ip))
                    return None

                else:
                    print ("{0} Configuration file from {1} saved as {1}-config.txt in the root of the TFTP directory"
                          .format(complete,target_ip))
                    return None

            else:
                print ("{0} Configuration file from {1} may have been saved on TFTP server {2}"
                       .format(warning,target_ip,tftp_ip))
                return None

    except Exception as e:
        print ("{0}".format(error),e)
        return None

def main():
    """
    The main function that checks for root and then calls the snmp function
    :param:
    :return:
    """
    if not os.geteuid() == 0:
        print("{0} Execute config-dump with sudo privileges or as root".format(error))
        sys.exit(-1)

    command = "which snmpset >/dev/null 2>&1"
    results = os.system(command)
    if results != 0:
        print("{0} The snmpset binary not found on this device".format(error))
        sys.exit(-1)

    if sys.platform == 'darwin':
        print("{0} Script not tested on OSX".format(warning))
        sys.exit(-1)

    if args.protocol == 'AES':
        # Call the Function snmp; Noted issues with snmpset for AES encryption > 128
        print("{0} Authentication issues persist with AES encryption above 128".format(warning))
        snmp(args.auth,args.auth_pass,args.protocol,args.proto_pass,args.user,args.target,args.tftp)
        return None

    else:
        # Call the Function snmp
        snmp(args.auth,args.auth_pass,args.protocol,args.proto_pass,args.user,args.target,args.tftp)
        return None

def print_art():
    """
    The print_art function prints the ASCII Art
    :param:
    :return:
    """
    ascii_art1 = colored("""
        ,-. ,-. ,-. ," . ,-.
        |   | | | | |- | | |
        `-' `-' ' ' |  ' `-|
                    '     ,|
                          `' """,'yellow',attrs=['bold'])

    ascii_art2 = colored("""
                         |
                       ,-| . . ,-,-. ,-.
                       | | | | | | | | |
                       `-^ `-^ ' ' ' |-'
                                     |
                                     '
    """,'red',attrs=['bold'])
    desc = 'Download a Cisco Device Configuration with '+colored('SNMPv3','green')+' to a TFTP server'
    version = colored('\t\t   Version: ','red')+colored('{0} {1}','yellow').format(__version__,__status__)
    print ('{0} {1}'.format(ascii_art1,ascii_art2))
    print (desc,flush=True)
    print ('{0}\n'.format(version))

if __name__ == "__main__":
    # Use ArgParse with mandatory flag of -t -a -A -u -s
    try:
        # Call the 'print_art' function
        print_art()

        parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
        required = parser.add_argument_group("required arguments")
        required.add_argument("-t", "--target", type=str, help="Target SNMP Host IP Address",required=True)
        required.add_argument("-a", "--auth", type=str, help="MD5 or SHA Authentication Protocol",required=True)
        required.add_argument("-A","--auth-pass", type=str, help="MD5 or SHA Password",required=True)
        required.add_argument("-u", "--user", type=str, help="Username",required=True)
        required.add_argument("-s", "--tftp", type=str, help="TFTP Server IP Address", required=True)
        parser.add_argument("-x", "--protocol", type=str, help="DES or AES Protocol")
        parser.add_argument("-X", "--proto-pass", type=str, help="DES or AES Password")
        args = parser.parse_args()

        # Call the 'main' function
        main()

    except KeyboardInterrupt:
        print("{0} User Interrupt! Quitting....\n".format(error))
        sys.exit(-1)
    except:
        raise
    exit()
