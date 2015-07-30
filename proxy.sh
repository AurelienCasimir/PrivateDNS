#!/bin/bash

if (( $EUID != 0 )); then
    echo "Please run as root"
    exit
fi

if [ -z "$2" ] 
    then
	echo "Usage: sudo ./proxy.sh <XPIR folder path> <server IP address>"
	echo "or     sudo ./proxy.sh <XPIR folder path> <server IP address> <server port>"
	exit
fi

if [ -z "$3" ] 
    then
	echo "Setting iptables rule"
	iptables -A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0
	./xpir_proxy $1 $2
	exit
fi

echo "Setting iptables rule"
iptables -A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0
./xpir_proxy $1 $2 $3
exit
