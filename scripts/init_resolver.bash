#! /bin/bash

mkdir -p /usr/local/etc/bind/root/hints/
cp /named.conf /usr/local/etc/
cp /root.hints /usr/local/etc/bind/root/hints/root.hints
ldconfig

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <ALGORITHM> <IP>" >&2
    exit 1
fi

#apt install -y valgrind
ALG=$1
#FALCON512, DILITHIUM2, SPHINCS+, P256_FALCON512
LISTENIP=$2

/install_trust_anchor.bash  
#rndc flush
cat /usr/local/etc/named.conf
rm -rf /dsset/*  

#iptables -A INPUT -p ip -j NFQUEUE --queue-num 0 
#iptables -A OUTPUT -p ip -j NFQUEUE --queue-num 0
ifconfig 
tcpdump -i any -w /tmp/tcpdump/$ALG-nodaemon.pcap &
/qbf/daemon $LISTENIP --algorithm $ALG --maxudp 1232 --mode 2 --is_resolver --debug --bypass &
#gdb --batch -ex "run" -ex "bt" -ex "quit" --args /qbf/daemon $LISTENIP --algorithm $ALG --maxudp 1232 --mode 2 --is_resolver --debug &
#gdb --args /qbf/daemon 172.20.0.2 --algorithm P256_FALCON512 --maxudp 1232 --debug
#valgrind /qbf/daemon 172.20.0.2 --algorithm P256_FALCON512 --maxudp 1232 --debug
named -g -d 3
/bin/bash
# dig @172.20.0.2 +timeout=10 +tries=1 test.example
