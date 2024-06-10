#!/usr/bin/python

## Default Responder Configuration
responder_default_conf = '''[Responder Core]

; Poisoners to start
MDNS  = On
LLMNR = On
NBTNS = On

; Servers to start
SQL      = On
SMB      = On
RDP      = On
Kerberos = On
FTP      = On
POP      = On
SMTP     = On
IMAP     = On
HTTP     = On
HTTPS    = On
DNS      = On
LDAP     = On
DCERPC   = On
WINRM    = On
SNMP     = Off
MQTT     = On

; Custom challenge.
; Use "Random" for generating a random challenge for each requests (Default)
Challenge = Random

; SQLite Database file
; Delete this file to re-capture previously captured hashes
Database = Responder.db

; Default log file
SessionLog = Responder-Session.log

; Poisoners log
PoisonersLog = Poisoners-Session.log

; Analyze mode log
AnalyzeLog = Analyzer-Session.log

; Dump Responder Config log:
ResponderConfigDump = Config-Responder.log

; Specific IP Addresses to respond to (default = All)
; Example: RespondTo = 10.20.1.100-150, 10.20.3.10, fe80::e059:5c8f:a486:a4ea-a4ef, 2001:db8::8a2e:370:7334
RespondTo =

; Specific NBT-NS/LLMNR names to respond to (default = All)
; Example: RespondTo = WPAD, DEV, PROD, SQLINT
;RespondToName = WPAD, DEV, PROD, SQLINT
RespondToName = 

; Specific IP Addresses not to respond to (default = None)
; Hosts with IPv4 and IPv6 addresses must have both addresses included to prevent responding.
; Example: DontRespondTo = 10.20.1.100-150, 10.20.3.10, fe80::e059:5c8f:a486:a4ea-a4ef, 2001:db8::8a2e:370:7334
DontRespondTo = %s

; Specific NBT-NS/LLMNR names not to respond to (default = None)
; Example: DontRespondTo = NAC, IPS, IDS
DontRespondToName = ISATAP

; If set to On, we will stop answering further requests from a host
; if a hash has been previously captured for this host.
AutoIgnoreAfterSuccess = Off

; If set to On, we will send ACCOUNT_DISABLED when the client tries
; to authenticate for the first time to try to get different credentials.
; This may break file serving and is useful only for hash capture
CaptureMultipleCredentials = On

; If set to On, we will write to file all hashes captured from the same host.
; In this case, Responder will log from 172.16.0.12 all user hashes: domain\toto,
; domain\popo, domain\zozo. Recommended value: On, capture everything.
CaptureMultipleHashFromSameHost = On

[HTTP Server]

; Set to On to always serve the custom EXE
Serve-Always = Off

; Set to On to replace any requested .exe with the custom EXE
Serve-Exe = Off

; Set to On to serve the custom HTML if the URL does not contain .exe
; Set to Off to inject the 'HTMLToInject' in web pages instead
Serve-Html = Off

; Custom HTML to serve
HtmlFilename = files/AccessDenied.html

; Custom EXE File to serve
ExeFilename = ;files/filetoserve.exe

; Name of the downloaded .exe that the client will see
ExeDownloadName = ProxyClient.exe

; Custom WPAD Script
; Only set one if you really know what you're doing. Responder is taking care of that and inject the right one, with your current IP address.
WPADScript =

; HTML answer to inject in HTTP responses (before </body> tag).
; leave empty if you want to use the default one (redirect to SMB on your IP address).
HTMLToInject =

[HTTPS Server]

; Configure SSL Certificates to use
SSLCert = certs/responder.crt
SSLKey = certs/responder.key

'''

# Disable Responder's HTTP services by default
responder_no_http_conf = '''[Responder Core]

; Poisoners to start
MDNS  = On
LLMNR = On
NBTNS = On

; Servers to start
SQL      = On
SMB      = On
RDP      = On
Kerberos = On
FTP      = On
POP      = On
SMTP     = On
IMAP     = On
HTTP     = Off
HTTPS    = Off
DNS      = On
LDAP     = On
DCERPC   = On
WINRM    = On
SNMP     = Off
MQTT     = On

; Custom challenge.
; Use "Random" for generating a random challenge for each requests (Default)
Challenge = Random

; SQLite Database file
; Delete this file to re-capture previously captured hashes
Database = Responder.db

; Default log file
SessionLog = Responder-Session.log

; Poisoners log
PoisonersLog = Poisoners-Session.log

; Analyze mode log
AnalyzeLog = Analyzer-Session.log

; Dump Responder Config log:
ResponderConfigDump = Config-Responder.log

; Specific IP Addresses to respond to (default = All)
; Example: RespondTo = 10.20.1.100-150, 10.20.3.10, fe80::e059:5c8f:a486:a4ea-a4ef, 2001:db8::8a2e:370:7334
RespondTo =

; Specific NBT-NS/LLMNR names to respond to (default = All)
; Example: RespondTo = WPAD, DEV, PROD, SQLINT
;RespondToName = WPAD, DEV, PROD, SQLINT
RespondToName = 

; Specific IP Addresses not to respond to (default = None)
; Hosts with IPv4 and IPv6 addresses must have both addresses included to prevent responding.
; Example: DontRespondTo = 10.20.1.100-150, 10.20.3.10, fe80::e059:5c8f:a486:a4ea-a4ef, 2001:db8::8a2e:370:7334
DontRespondTo = %s

; Specific NBT-NS/LLMNR names not to respond to (default = None)
; Example: DontRespondTo = NAC, IPS, IDS
DontRespondToName = ISATAP

; If set to On, we will stop answering further requests from a host
; if a hash has been previously captured for this host.
AutoIgnoreAfterSuccess = Off

; If set to On, we will send ACCOUNT_DISABLED when the client tries
; to authenticate for the first time to try to get different credentials.
; This may break file serving and is useful only for hash capture
CaptureMultipleCredentials = On

; If set to On, we will write to file all hashes captured from the same host.
; In this case, Responder will log from 172.16.0.12 all user hashes: domain\toto,
; domain\popo, domain\zozo. Recommended value: On, capture everything.
CaptureMultipleHashFromSameHost = On

[HTTP Server]

; Set to On to always serve the custom EXE
Serve-Always = Off

; Set to On to replace any requested .exe with the custom EXE
Serve-Exe = Off

; Set to On to serve the custom HTML if the URL does not contain .exe
; Set to Off to inject the 'HTMLToInject' in web pages instead
Serve-Html = Off

; Custom HTML to serve
HtmlFilename = files/AccessDenied.html

; Custom EXE File to serve
ExeFilename = ;files/filetoserve.exe

; Name of the downloaded .exe that the client will see
ExeDownloadName = ProxyClient.exe

; Custom WPAD Script
; Only set one if you really know what you're doing. Responder is taking care of that and inject the right one, with your current IP address.
WPADScript =

; HTML answer to inject in HTTP responses (before </body> tag).
; leave empty if you want to use the default one (redirect to SMB on your IP address).
HTMLToInject =

[HTTPS Server]

; Configure SSL Certificates to use
SSLCert = certs/responder.crt
SSLKey = certs/responder.key

'''
