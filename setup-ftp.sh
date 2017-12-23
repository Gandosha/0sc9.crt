#!/bin/bash

apt-get update && apt-get install -y pure-ftpd-common pure-ftpd
ln -s /etc/pure-ftpd/conf/PureDB /etc/pure-ftpd/auth/50pure
echo no > /etc/pure-ftpd/conf/PAMAuthentication
echo no > /etc/pure-ftpd/conf/UnixAuthentication
echo "yes" > /etc/pure-ftpd/conf/CreateHomeDir
echo "no" > /etc/pure-ftpd/conf/CreateHomeDir
echo "yes" > /etc/pure-ftpd/conf/ChrootEveryone
groupadd ftpusr
useradd -g ftpusr -d /dev/null -s /etc ftpusr
mkdir ~/FTPhome
pure-pw useradd offsec -u ftpusr -g ftpusr -d ~/FTPhome
pure-pw mkdb
pure-pw show offsec


