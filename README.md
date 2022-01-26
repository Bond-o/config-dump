# config-dump
![alt text](https://img.shields.io/badge/Python-3_only-blue.svg "Python 3 only") [![MIT license](https://img.shields.io/badge/License-MIT-blue.svg)](https://lbesson.mit-license.org/)

Download a Cisco Configuration file to a TFTP server using SNMPv3.

# ABOUT
config-dump.py executes the snmpset binary and passes SNMPv3 credentials as well as Cisco SNMP OID to download a configuration file to
a TFTP server.

# USAGE
```
usage: config-dump.py [-h] -t TARGET -a AUTH -A AUTH_PASS -u USER -s TFTP [-x PROTOCOL] [-X PROTO_PASS]

optional arguments:
  -h, --help            show this help message and exit
  -x PROTOCOL, --protocol PROTOCOL
                        DES or AES Protocol
  -X PROTO_PASS, --proto-pass PROTO_PASS
                        DES or AES Password

required arguments:
  -t TARGET, --target TARGET
                        Target SNMP Host IP Address
  -a AUTH, --auth AUTH  MD5 or SHA Authentication Protocol
  -A AUTH_PASS, --auth-pass AUTH_PASS
                        MD5 or SHA Password
  -u USER, --user USER  Username
  -s TFTP, --tftp TFTP  TFTP Server IP Address
```

## Examples
```
./config-dump.py -t 192.168.1.1 -a SHA -A Passw0rd! -x AES -X Passw0rd! -u cisco -s 192.168.1.21
```

# Disclaimer
This project is intended for network administrators, security researchers, and penetration testers and should not be used for any illegal activities.
