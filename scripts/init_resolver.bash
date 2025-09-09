#! /bin/bash

mkdir -p /usr/local/etc/bind/root/hints/
cp /named.conf /usr/local/etc/
cp /root.hints /usr/local/etc/bind/root/hints/root.hints
ldconfig

ALG=FALCON512
LISTENIP=172.20.0.2

/install_trust_anchor.bash  
rm -rf /dsset/*  

iptables -A INPUT -p ip -j NFQUEUE --queue-num 0 
iptables -A OUTPUT -p ip -j NFQUEUE --queue-num 0
ifconfig 
/qbf/daemon $LISTENIP --algorithm $ALG --mode 2 --is_resolver --debug &
named -g -d 3