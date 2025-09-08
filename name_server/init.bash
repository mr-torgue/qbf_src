#! /bin/bash

cd /usr/local/etc/bind/zones

ALG=FALCON512

# TODO: check if keys exist
dnssec-keygen -a $ALG -n ZONE .
dnssec-keygen -a $ALG -n ZONE -f KSK .
/setup_files/add_ds.bash db.root example.
dnssec-signzone -o . -N INCREMENT -t -S -K /usr/local/etc/bind/zones db.root;  
/setup_files/move_ds.bash .

iptables -A INPUT -p ip -j NFQUEUE --queue-num 0
iptables -A OUTPUT -p ip -j NFQUEUE --queue-num 0 
ifconfig  
cd /  
./qbf/daemon ${LISTENIP} --algorithm $ALG --maxudp 1232 --debug & 
named -g -d 3
