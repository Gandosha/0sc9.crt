#!/bin/bash
if [ ! -e /tmp/Target_IPs ]; then
        touch /tmp/Target_IPs
        for i in $(seq 0 254);
        do
                echo
                echo
                printf "\033[1;33mScanning 10.11."$i".0/24 for alive hosts...\033[0m\n"
                nmap -sn -T4 10.11.$i.0/24 -oG /tmp/alive_hosts_in_subnet
                cat /tmp/alive_hosts_in_subnet | grep Up | cut -d" " -f2 >> /tmp/Target_IPs
        done
fi
echo
while read target;
do
	echo
	printf "\033[1;35mStarting to enumerate $target ...\033[0m\n"
	nmap --script smb-enum-domains.nse -p445 $target
	nmap -sU -sS --script smb-enum-domains.nse -p U:137,T:139 $target
	nmap --script smb-enum-users.nse -p445 $target
	nmap -sU -sS --script smb-enum-users.nse -p U:137,T:139 $target
	nmap --script smb-enum-processes.nse -p445 $target
	nmap -sU -sS --script smb-enum-processes.nse -p U:137,T:139 $target
	nmap --script smb-enum-services.nse -p445 $target
	nmap --script smb-enum-sessions.nse -p445 $target
	nmap -sU -sS --script smb-enum-sessions.nse -p U:137,T:139 $target
	nmap --script smb-enum-shares.nse -p445 $target
	nmap -sU -sS --script smb-enum-shares.nse -p U:137,T:139 $target
	nmap --script smb-enum-users.nse -p445 $target
	nmap -sU -sS --script smb-enum-users.nse -p U:137,T:139 $target
	nmap -p 445 $target --script smb-mbenum
	nmap --script smb-os-discovery.nse -p445 $target
	nmap -sU -sS --script smb-os-discovery.nse -p U:137,T:139 $target
	nmap -p445 --script smb-protocols $target
	nmap -p139 --script smb-protocols $target
	nmap --script smb-security-mode.nse -p445 $target
	nmap -sU -sS --script smb-security-mode.nse -p U:137,T:139 $target
	nmap --script smb-server-stats.nse -p445 $target
	nmap -sU -sS --script smb-server-stats.nse -p U:137,T:139 $target
	nmap --script smb-system-info.nse -p445 $target
	nmap -sU -sS --script smb-system-info.nse -p U:137,T:139 $target
	nmap -p 110,995 --script pop3-ntlm-info $target
	nmap --script=mysql-enum -p 3306 $target
	nmap $target --script=msrpc-enum -p 445
	nmap -p 1433 --script ms-sql-ntlm-info $target
	nmap -p80 --script http-wordpress-users $target
	nmap -sV --script http-wordpress-users --script-args limit=50 $target
	nmap --script http-wordpress-enum --script-args type="themes" $target
	nmap --script http-wordpress-enum --script-args check-latest=true,search-limit=10 $target
	nmap -sV --script http-wordpress-enum $target
	nmap -sV --script=http-userdir-enum $target
	nmap --script http-svn-enum $target
	nmap -p 80 --script http-ntlm-info --script-args http-ntlm-info.root=/root/ $target
	nmap -p80 $target --script http-gitweb-projects-enum
	nmap -sV --script=http-enum $target
	nmap --script=http-drupal-enum-users --script-args http-drupal-enum-users.root="/path/" $targets
	nmap -p 80 --script http-drupal-enum $target
	nmap -p 143,993 --script imap-ntlm-info $target
	nmap -p 119,433,563 --script nntp-ntlm-info $target
	nmap -sU --script=citrix-enum-apps -p 1604 $target
	nmap --script=citrix-enum-apps-xml -p 80,443,8080 $target
	nmap -sU --script=citrix-enum-servers -p 1604 $target
	nmap --script=citrix-enum-servers-xml -p 80,443,8080 $target
	nmap -p80 --script http-avaya-ipoffice-users $target
	nmap -sV --script http-avaya-ipoffice-users $target
	nmap --script modbus-discover.nse --script-args='modbus-discover.aggressive=true' -p 502 $target
	nmap $target --script ncp-serverinfo -p 524
	nmap -sV -p 524 --script=ncp-enum-users $target
	nmap -p 119,433,563 --script nntp-ntlm-info $target
	nmap --script nrpe-enum -p 5666 $target
	nmap -p 9390 --script omp2-brute,omp2-enum-targets $target
	nmap -p 9390 --script omp2-enum-targets --script-args omp2.username=admin,omp2.password=secret $target
	nmap --script oracle-enum-users --script-args oracle-enum-users.sid=ORCL,userdb=orausers.txt -p 1521-1560 $target
	nmap --script rtsp-url-brute -p 554 $target
	nmap --script s7-info.nse -p 102 $target
	nmap --script=sip-enum-users -sU -p 5060 $target
	nmap --script=sip-enum-users -sU -p 5060 $target --script-args 'sip-enum-users.padding=4, sip-enum-users.minext=1000, sip-enum-users.maxext=9999'
	echo
done < /tmp/Target_IPs
echo
printf "\033[1;35mWhat is the REALM (krb5)?\033[0m\n"
read realm
echo
printf "\033[1;35mBefore launching http-domino-enum-passwords script, please provide a username list (path) and password list (path).\033[0m\n"
read userpath 
read passwordpath
printf "\033[1;35mIn order to invoke oracle-enum-users script, please provide an oracle users list.\033[0m\n"
read oracleuserlist
while read target2;
do
	nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='$realm' $target2
	nmap --script http-domino-enum-passwords -p 80 $target2 --script-args http-domino-enum-passwords.username=$userpath,http-domino-enum-passwords.password=$passwordpath
	nmap --script oracle-enum-users --script-args oracle-enum-users.sid=ORCL,userdb=$oracleuserlist -p 1521-1560 $target2
done < /tmp/Target_IPs
