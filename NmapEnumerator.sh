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
	nmap -sU --script=citrix-enum-apps -p 1604 $target
	nmap --script=citrix-enum-apps-xml -p 80,443,8080 $target
	nmap -sU --script=citrix-enum-servers -p 1604 $target
	nmap --script=citrix-enum-servers-xml -p 80,443,8080 $target
	nmap -p80 --script http-avaya-ipoffice-users $target
	nmap -sV --script http-avaya-ipoffice-users $target
	



	echo
done < /tmp/Target_IPs
echo
printf "What is the REALM (krb5)?"
read realm
echo
printf "Before launching http-domino-enum-passwords script, please provide a username list (path) and password list (path)."
read userpath, passwordpath
while read target;
do
	nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='$realm' $target2
	nmap --script http-domino-enum-passwords -p 80 $target2 --script-args http-domino-enum-passwords.username=$userpath,http-domino-enum-passwords.password=$passwordpath
done < /tmp/Target_IPs
