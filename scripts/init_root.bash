#! /bin/bash

cd /usr/local/etc/bind/zones
cp /db.root .
cp /named.conf /usr/local/etc/
ldconfig

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <ALGORITHM> <IP>" >&2
    exit 1
fi

ALG=$1
#FALCON512, DILITHIUM2, SPHINCS+, P256_FALCON512
LISTENIP=$2

# TODO: check if keys exist
#rm -rf /dsset/*
#rm -rf *.key
#rm -rf *.private
dnssec-keygen -a $ALG -n ZONE .
dnssec-keygen -a $ALG -n ZONE -f KSK .
rndc-confgen -a > /usr/local/etc/bind/rndc.key
#rndc flush
cat /usr/local/etc/named.conf
/add_ds.bash db.root example.
dnssec-signzone -o . -N INCREMENT -t -S -K /usr/local/etc/bind/zones db.root;  
/move_ds.bash .

iptables -A INPUT -p ip -j NFQUEUE --queue-num 0
iptables -A OUTPUT -p ip -j NFQUEUE --queue-num 0 
ifconfig  
gdb --batch -ex "run" -ex "bt" -ex "quit" --args /qbf/daemon $LISTENIP --algorithm $ALG --maxudp 1232 --debug &
#gdb --args /qbf/daemon 172.20.0.3 --algorithm P256_FALCON512 --maxudp 1232 --debug &
named -g -d 3
/bin/bash