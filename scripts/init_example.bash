#! /bin/bash

cd /usr/local/etc/bind/zones
cp /db.example .
cp /named.conf /usr/local/etc/
ldconfig

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <ALGORITHM> <IP> <BYPASS>" >&2
    exit 1
fi

#apt install -y valgrind
ALG=$1
#FALCON512, DILITHIUM2, SPHINCS+, P256_FALCON512
LISTENIP=$2
BYPASS=$3

# sometimes daemon and bind9 use different names for the same sig scheme
if [ "$ALG" = "SPHINCS+" ]; then
    BIND_ALG=SPHINCS+-SHA256-128S
else
    BIND_ALG=$ALG
fi

rm -rf *.key
rm -rf *.private
dnssec-keygen -a $BIND_ALG -n ZONE example
dnssec-keygen -a $BIND_ALG -n ZONE -f KSK example
rndc-confgen -a > /usr/local/etc/bind/rndc.key
#rndc flush
cat /usr/local/etc/named.conf
dnssec-signzone -o example -N INCREMENT -t -S -K /usr/local/etc/bind/zones db.example
/move_ds.bash example. 

iptables -A INPUT -p ip -j NFQUEUE --queue-num 0 
iptables -A OUTPUT -p ip -j NFQUEUE --queue-num 0 
ifconfig

cd /tmp
if [ "$BYPASS" = "true" ]; then
    echo "Using BYPASS..."
    tcpdump -i any -w /tmp/$ALG-bypass.pcap &
    gdb --batch -ex "run" -ex "bt" -ex "quit" --args /qbf/daemon $LISTENIP --algorithm $ALG --maxudp 1232 --bypass --debug > /tmp/daemon-$ALG-bypass.txt &
else
    echo "Not using BYPASS..."
    tcpdump -i any -w /tmp/$ALG.pcap &
    gdb --batch -ex "run" -ex "bt" -ex "quit" --args /qbf/daemon $LISTENIP --algorithm $ALG --maxudp 1232 --debug > /tmp/daemon-$ALG.txt &
fi

#/qbf/daemon $LISTENIP --algorithm $ALG --maxudp 1232 --debug &
#gdb --batch -ex "run" -ex "bt" -ex "quit" --args /qbf/daemon $LISTENIP --algorithm $ALG --maxudp 1232 --debug &
#gdb --args /qbf/daemon 172.20.0.4 --algorithm P256_FALCON512 --maxudp 1232 --debug
#valgrind /qbf/daemon 172.20.0.4 --algorithm P256_FALCON512 --maxudp 1232 --debug
named -g -d 3
/bin/bash