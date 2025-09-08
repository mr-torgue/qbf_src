#! /bin/bash

cp /named.conf /usr/local/etc/
cp /root.hints /usr/local/etc/bind/root/hints/root.hints
ldconfig

ALG=FALCON512

/install_trust_anchor.bash  
rm -rf /dsset/*  

iptables -A INPUT -p ip -j NFQUEUE --queue-num 0 
iptables -A OUTPUT -p ip -j NFQUEUE --queue-num 0
ifconfig 
/qbf/daemon ${LISTENIP} --maxudp 1232 --algorithm FALCON512 --mode 2 --is_resolver & 
named -d 3
/bin/bash