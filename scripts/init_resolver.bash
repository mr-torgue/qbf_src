#! /bin/bash

mkdir -p /usr/local/etc/bind/root/hints/
cp /named.conf /usr/local/etc/
cp /root.hints /usr/local/etc/bind/root/hints/root.hints
ldconfig

if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <ALGORITHM> <IP> <BYPASS> <MODE>" >&2
    exit 1
fi

#apt install -y valgrind
ALG=$1
#FALCON512, DILITHIUM2, SPHINCS+, P256_FALCON512
LISTENIP=$2
BYPASS=$3
MODE=$4

# sometimes daemon and bind9 use different names for the same sig scheme
if [ "$ALG" = "SPHINCS+" ]; then
    BIND_ALG=SPHINCS+-SHA256-128S
else
    BIND_ALG=$ALG
fi

/install_trust_anchor.bash  
#rndc flush
cat /usr/local/etc/named.conf
rm -rf /dsset/*  

iptables -A INPUT -p ip -j NFQUEUE --queue-num 0 
iptables -A OUTPUT -p ip -j NFQUEUE --queue-num 0
ifconfig 

cd /tmp
if [ "$BYPASS" = "true" ]; then
    echo "Using BYPASS..."
    tcpdump -i any -w /tmp/tcpdump/$ALG-bypass.pcap &
    gdb --batch -ex "run" -ex "bt" -ex "quit" --args /qbf/daemon $LISTENIP --algorithm $ALG --maxudp 1232 --mode $MODE --is_resolver --bypass --debug > /tmp/daemon-$ALG-bypass.txt &
else
    echo "Not using BYPASS..."
    tcpdump -i any -w /tmp/$ALG.pcap &
    gdb --batch -ex "run" -ex "bt" -ex "quit" --args /qbf/daemon $LISTENIP --algorithm $ALG --maxudp 1232 --mode $MODE --is_resolver --debug > /tmp/daemon-$ALG.txt &
fi

#/qbf/daemon 172.20.0.2 --algorithm FALCON512 --maxudp 1232 --mode 1 --is_resolver --debug
#/qbf/daemon $LISTENIP --algorithm $ALG --maxudp 1232 --mode 2 --is_resolver --debug &
#gdb --batch -ex "run" -ex "bt" -ex "quit" --args /qbf/daemon $LISTENIP --algorithm $ALG --maxudp 1232 --mode 2 --is_resolver --debug &
#gdb --args /qbf/daemon 172.20.0.2 --algorithm P256_FALCON512 --maxudp 1232 --debug
#valgrind /qbf/daemon 172.20.0.2 --algorithm P256_FALCON512 --maxudp 1232 --debug
named -g -d 3
#tcpdump -i any -w /tmp/tcpdump/$ALG.pcap
/bin/bash
# dig @172.20.0.2 +timeout=10 +tries=1 test.example
