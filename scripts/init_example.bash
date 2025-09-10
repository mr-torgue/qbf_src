#! /bin/bash

cd /usr/local/etc/bind/zones
cp /db.example .
cp /named.conf /usr/local/etc/
ldconfig

ALG=P256_FALCON512
LISTENIP=172.20.0.3


rm -rf *.key
rm -rf *.private
dnssec-keygen -a $ALG -n ZONE example
dnssec-keygen -a $ALG -n ZONE -f KSK example
rndc-confgen -a > /usr/local/etc/bind/rndc.key
cat /usr/local/etc/named.conf
dnssec-signzone -o example -N INCREMENT -t -S -K /usr/local/etc/bind/zones db.example
/move_ds.bash example. 

iptables -A INPUT -p ip -j NFQUEUE --queue-num 0 
#iptables -A OUTPUT -p ip -j NFQUEUE --queue-num 0 
ifconfig
/qbf/daemon $LISTENIP --algorithm $ALG --maxudp 1232 --debug --bypass &
named -g -d 3