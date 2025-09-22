#! /bin/bash

cd /usr/local/etc/bind/zones
cp /db.root .
cp /named.conf /usr/local/etc/
ldconfig

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <ALGORITHM> <IP> <BYPASS>" >&2
    exit 1
fi

ALG=$1
#FALCON512, DILITHIUM2, SPHINCS+, P256_FALCON512
LISTENIP=$2
BYPASS=$3

# TODO: check if keys exist
rm -rf /dsset/*
rm -rf *.key
rm -rf *.private
dnssec-keygen -a $ALG -n ZONE .
dnssec-keygen -a $ALG -n ZONE -f KSK .
rndc-confgen -a > /usr/local/etc/bind/rndc.key
#rndc flush
cat /usr/local/etc/named.conf
/add_ds.bash db.root example.
dnssec-signzone -o . -N INCREMENT -t -S -K /usr/local/etc/bind/zones db.root;  
/move_ds.bash .

# enable rerouting through NFQUEUE
iptables -A INPUT -p ip -j NFQUEUE --queue-num 0
iptables -A OUTPUT -p ip -j NFQUEUE --queue-num 0 
ifconfig  

if [ "$BYPASS" = "true" ]; then
    echo "Using BYPASS..."
    nohup tcpdump -i any -w /tmp/$ALG-bypass.pcap &
    /qbf/daemon $LISTENIP --algorithm $ALG --maxudp 1232 --bypass --debug > /tmp/daemon-$ALG-bypass.txt &
else
    echo "Not using BYPASS..."
    nohup tcpdump -i any -w /tmp/$ALG.pcap &
    /qbf/daemon $LISTENIP --algorithm $ALG --maxudp 1232 --debug > /tmp/daemon-$ALG.txt &
fi

# /qbf/daemon 172.20.0.3 --algorithm FALCON512 --maxudp 1232 --debug
#/qbf/daemon $LISTENIP --algorithm $ALG --maxudp 1232 --debug &
#gdb --batch -ex "run" -ex "bt" -ex "quit" --args /qbf/daemon $LISTENIP --algorithm $ALG --maxudp 1232 --debug &
#gdb --args /qbf/daemon 172.20.0.3 --algorithm P256_FALCON512 --maxudp 1232 --debug &
named -g -d 3
/bin/bash