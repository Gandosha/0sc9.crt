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
        printf "\033[1;35mOpen ports in $target are:\033[0m\n"
	nmap -sS -sV -p- -T4 $target --open
	echo
	printf "\033[1;35mEnumerating for NULL sessions $target ...\033[0m\n"
	crackmapexec smb $target -u '' -p ''
	echo
	printf "\033[1;35mStarting to enumerate $target using NBTSCAN...\033[0m\n"
	nbtscan -r $target
	echo
        printf "\033[1;35mStarting to enumerate $target using enum4linux...\033[0m\n"
	enum4linux -a $target
	echo
	printf "\033[1;35mStarting to enumerate $target using Nmap's NSE...\033[0m\n"
	nmap --script smtp-enum-users.nse --script-args smtp-enum-users.methods=EXPN,VRFY,RCPT -p 25,465,587 $target
	nmap -p 23 --script telnet-ntlm-info $target
	nmap --script smb-enum-domains.nse -p445 $target
	nmap -sU -sS --script smb-enum-domains.nse -p U:137,T:139 $target
	nmap --script smb-enum-users.nse -p445 $target
	nmap -sU -sS --script smb-enum-users.nse -p U:137,T:139 $target
	nmap --script smb-enum-processes.nse -p445 $target
	nmap -sU -sS --script smb-enum-processes.nse -p U:137,T:139 $target
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
	nmap -sU --script snmp-brute $target --script-args snmp-brute.communitiesdb=/usr/share/seclists/Miscellaneous/wordlist-common-snmp-community-strings.txt
	nmap -sU -p 161 --script=snmp-interfaces $target
	nmap -sU -p 161 --script=snmp-netstat $target
	nmap -sU -p 161 --script=snmp-processes $target
	nmap -sU -p 161 --script snmp-sysdescr $target	
	nmap -sU -p 161 --script=snmp-win32-services $target
	nmap -sU -p 161 --script=snmp-win32-shares $target
	nmap -sU -p 161 --script=snmp-win32-software $target
	nmap -sU -p 161 --script=snmp-win32-users $target
	nmap -p 1080 $target --script socks-auth-info
	nmap --script snmp-info.nse -p 161 $target
	nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=admin" $target
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
	nmap --script=http-drupal-enum-users --script-args http-drupal-enum-users.root="/path/" $target
	nmap -p 80 --script http-drupal-enum $target
	nmap -sV --script http-apache-server-status $target
	nmap -p80 --script http-apache-server-status $target
	nmap -p 443 --script http-cisco-anyconnect $target
	nmap --script http-qnap-nas-info -p 443 $target
	nmap --script mysql-info.nse -p 3306 $target
	nmap -p 445 --script ms-sql-info $target
	nmap -p 1433 --script ms-sql-info --script-args mssql.instance-port=1433 $target
	nmap -p 111 --script=nfs-ls $target
	nmap -sV --script=nfs-ls $target
	nmap --script vnc-info.nse -p 5900 $target
	nmap --script vmware-version -p443 $target
	nmap -p 5019 $target --script versant-info
	nmap -p 8140 --script puppet-naivesigning $target
	nmap -p 8140 --script puppet-naivesigning --script-args puppet-naivesigning.csr=other.csr,puppet-naivesigning.node=agency $target
	nmap -p 1344 $target --script icap-info
	nmap -p 5019 $target --script versant-info
	nmap -sU --script ipmi-version -p 623 $target
	nmap -p 3205 $target --script isns-info
	nmap -sT $target -p 2010 --script=+jdwp-info
	nmap -sU -p 9100 --script=lexmark-config $target
	nmap -p 7210 --script maxdb-info $target
	nmap -p 119,433,563 --script nntp-ntlm-info $target
	nmap -sU -p 123 --script ntp-info $target
	nmap -sU -pU:123 -Pn -n --script=ntp-monlist $target
	nmap --script openwebnet-discovery $target
	nmap -p 8091 $target --script membase-http-info
	nmap -p 11211 --script memcached-info $target
	nmap --script modbus-discover.nse --script-args='modbus-discover.aggressive=true' -p 502 $target
	nmap -p 27017 --script mongodb-info $target
	nmap -p 1433 --script ms-sql-ntlm-info $target
	nmap -p 6379 $target --script redis-info
	nmap -p 8098 $target --script riak-http-info
	nmap -p 2002 $target --script rpcap-info
	nmap -p 111 --script rpcinfo.nse $target
	nmap -sU -p 500 --script ike-version $target
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
	nmap -sS -sV -p 548 --script=afp-ls $target
	nmap --script afp-serverinfo.nse -p 548 $target
	nmap --script backorifice-info $target --script-args backorifice-info.password=/usr/share/wordlists/rockyou.txt
	nmap -p 119,433,563 --script nntp-ntlm-info $target
	nmap --script nrpe-enum -p 5666 $target
	nmap -p 9390 --script omp2-brute,omp2-enum-targets $target
	nmap -p 9390 --script omp2-enum-targets --script-args omp2.username=admin,omp2.password=secret $target
	nmap --script oracle-enum-users --script-args oracle-enum-users.sid=ORCL,userdb=orausers.txt -p 1521-1560 $target
	nmap --script rtsp-url-brute -p 554 $target
	nmap --script s7-info.nse -p 102 $target
	nmap -sU -p 6481 --script=servicetags $target
	nmap --script=sip-enum-users -sU -p 5060 $target
	nmap --script=sip-enum-users -sU -p 5060 $target --script-args 'sip-enum-users.padding=4, sip-enum-users.minext=1000, sip-enum-users.maxext=9999'
	nmap -sV -PN -sU -p 3478 --script stun-info $target
	nmap -p 10000 --script ndmp-fs-info $target
	nmap -p 12345 --script netbus-info $target --script-args netbus-info.password=/usr/share/wordlists/rockyou.txt
	nmap -sU -p 69 --script tftp-enum.nse --script-args tftp-enum.filelist=/usr/share/wordlists/rockyou.txt $target
	nmap --script tn3270-info,tn3270-screen.nse $target
	nmap --script vtam-enum -p 23 $target
	nmap --script bacnet-info -sU -p 47808 $target
	nmap --script=broadcast-dropbox-listener $target
	nmap --script=broadcast-dropbox-listener --script-args=newtargets -Pn $target
	nmap --script=broadcast-eigrp-discovery $target
	nmap -sV --script=broadcast-upnp-info $target
	nmap -p 9160 $target --script=cassandra-info
	nmap --script=cics-info -p 23 $target
	nmap -p 631 $target --script cups-info
	nmap -sV --script=smtp-strangeport $target
	nmap -sU -p 8611,8612 --script bjnp-discover $target
	nmap -p 631 $target --script cups-queue-info
	nmap --script db2-das-info.nse -p 523 $target
	nmap -sU -p 67 --script=dhcp-discover $target
	nmap -p 2628 $target --script dict-info
	nmap --script drda-info.nse -p 50000 $target
	nmap -PN -p445,443 --script duplicates,nbstat,ssl-cert $target
	nmap --script flume-master-info -p 35871 $target
	nmap --script fox-info.nse -p 1911 $target
	nmap --script ganglia-info --script-args ganglia-info.timeout=60,ganglia-info.bytes=1000000 -p 8649 $target
	nmap -p 19150 $target --script gkrellm-info
	nmap -p 70 --script gopher-ls --script-args gopher-ls.maxfiles=100 $target
	nmap -p 2947 $target --script gpsd-info
	nmap --script hadoop-datanode-info.nse -p 50075 $target
	nmap --script hadoop-jobtracker-info -p 50030 $target
	nmap --script hadoop-namenode-info -p 50070 $target
	nmap --script hadoop-secondary-namenode-info -p 50090 $target
	nmap --script hadoop-tasktracker-info -p 50060 $target
	nmap --script hbase-master-info -p 60010 $target
	nmap -sU -p 17185 --script wdb-version $target
	nmap --script hnap-info -p80,8080 $target
	nmap -p80 --script http-apache-server-status $target
	nmap --script ssl-cert.nse $target
	nmap -p 443 --script ssl-cert-intaddr $target
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
printf "\033[1;33mWhat is the domain name you are about to scan?\033[0m\n"
read domain
while read target2;
do
	nmap --script smtp-commands.nse --script-args smtp-commands.domain=$domain -pT:25,465,587 $target2
	nmap -p 25,465,587 --script smtp-ntlm-info --script-args smtp-ntlm-info.domain=$domain $target2
	nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='$realm' $target2
	nmap --script http-domino-enum-passwords -p 80 $target2 --script-args http-domino-enum-passwords.username=$userpath,http-domino-enum-passwords.password=$passwordpath
	nmap --script oracle-enum-users --script-args oracle-enum-users.sid=ORCL,userdb=$oracleuserlist -p 1521-1560 $target2
done < /tmp/Target_IPs
