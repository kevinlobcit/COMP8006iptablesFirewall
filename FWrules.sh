#!/bin/bash

source FWconf.sh

iptables -F
iptables -t nat -F
iptables -t mangle -F

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# set pre and post routing
iptables -A POSTROUTING -t nat -o $NIC_EXTERNAL_NAME -j MASQUERADE
iptables -A PREROUTING -t mangle -p tcp --dport ssh -j TOS --set-tos Minimize-Delay
iptables -A PREROUTING -t mangle -p tcp --dport ftp -j TOS --set-tos Minimize-Delay
iptables -A PREROUTING -t mangle -p tcp --dport ftp-data -j TOS --set-tos Maximize-Throughput
iptables -A PREROUTING -t nat -i $NIC_EXTERNAL_NAME -d $IP_EXTERNAL -j DNAT --to-destination $IP_INTERNAL_HOST

# allow ssh into firewall from internal for demo purposes
if($DEMO_SSH_FIREWALL = true)
then
	iptables -A INPUT -p tcp --dport 22 -i $NIC_INTERNAL_NAME -m comment --comment "ssh into firewall from internal for demo" -j ACCEPT
	iptables -A OUTPUT -p tcp --sport 22 -o $NIC_INTERNAL_NAME -m comment --comment "ssh into firewall from internal for demo" -j ACCEPT
fi


#######DEFAULT DROP RULES###########################################################
#drop inbound forwarded to dport 80 from sport0-1024 
iptables -A FORWARD -m tcp -p tcp -i $NIC_EXTERNAL_NAME --dport 80 --sport 0:1023 -m comment --comment "drop forwarded dport80 from sport0-1024" -j DROP 
#drop packets with source address from external matching internal network address
iptables -A FORWARD -i $NIC_EXTERNAL_NAME -s $IP_INTERNAL_NETWORK -m comment --comment "drop spoofed internal addresses from external network" -j DROP
#drop inbound forwarded to high ports
iptables -A FORWARD -m tcp -p tcp -i $NIC_EXTERNAL_NAME --dport 1024:65535 --syn -m comment --comment "Drop inbound SYN to high ports" -j DROP
#drop forwarded synfin////////
iptables -A FORWARD -m tcp -p tcp -s 0.0.0.0/0 --tcp-flags SYN,FIN SYN,FIN -m comment --comment "drop forwarded SYNFIN" -j DROP
#drop forwarded telnet
iptables -A FORWARD -m tcp -p tcp --dport 23 -m comment --comment "drop forwared telnet" -j DROP


#######DEFAULT ACCEPT RULES#########################################################
#Inbound/outbound ssh
#external to internal
iptables -A FORWARD -m tcp -p tcp --dport 22 -d $IP_INTERNAL_NETWORK -s $IP_EXTERNAL_NETWORK -m conntrack --ctstate NEW,ESTABLISHED -m comment --comment "SSH" -j ACCEPT
iptables -A FORWARD -m tcp -p tcp --sport 22 -s $IP_INTERNAL_NETWORK -d $IP_EXTERNAL_NETWORK -m conntrack --ctstate ESTABLISHED -m comment --comment "SSH" -j ACCEPT
#internal to external
iptables -A FORWARD -m tcp -p tcp --dport 22 -s $IP_INTERNAL_NETWORK -d $IP_EXTERNAL_NETWORK -m conntrack --ctstate NEW,ESTABLISHED -m comment --comment "SSH" -j ACCEPT
iptables -A FORWARD -m tcp -p tcp --sport 22 -d $IP_INTERNAL_NETWORK -s $IP_EXTERNAL_NETWORK -m conntrack --ctstate ESTABLISHED -m comment --comment "SSH" -j ACCEPT
#Inbound/outbound http/https
#external to internal
iptables -A FORWARD -p tcp -m multiport --dport 80,443 -d $IP_INTERNAL_NETWORK -s $IP_EXTERNAL_NETWORK -m conntrack --ctstate NEW,ESTABLISHED -m comment --comment "HTTP/HTTPS" -j ACCEPT
iptables -A FORWARD -p tcp -m multiport --sport 80,443 -s $IP_INTERNAL_NETWORK -d $IP_EXTERNAL_NETWORK -m conntrack --ctstate ESTABLISHED -m comment --comment "HTTP/HTTPS" -j ACCEPT
#internal to external
iptables -A FORWARD -p tcp -m multiport --dport 80,443 -s $IP_INTERNAL_NETWORK -d $IP_EXTERNAL_NETWORK -m conntrack --ctstate NEW,ESTABLISHED -m comment --comment "HTTP/HTTPS" -j ACCEPT
iptables -A FORWARD -p tcp -m multiport --sport 80,443 -d $IP_INTERNAL_NETWORK -s $IP_EXTERNAL_NETWORK -m conntrack --ctstate ESTABLISHED -m comment --comment "HTTP/HTTPS" -j ACCEPT


#######USER DEFINED PERMITTED TCP RULES#############################################
#Inbound/outbound User defined TCP
#external to internal
iptables -A FORWARD -p tcp -m multiport --dport $ALLOWED_TCP_PORT_RANGE -d $IP_INTERNAL_NETWORK -s $IP_EXTERNAL_NETWORK -m conntrack --ctstate NEW,ESTABLISHED -m comment --comment "userDefinedTCP" -j ACCEPT
iptables -A FORWARD -p tcp -m multiport --sport $ALLOWED_TCP_PORT_RANGE -s $IP_INTERNAL_NETWORK -d $IP_EXTERNAL_NETWORK -m conntrack --ctstate ESTABLISHED -m comment --comment "userDefinedTCP" -j ACCEPT
#internal to external
iptables -A FORWARD -p tcp -m multiport --dport $ALLOWED_TCP_PORT_RANGE -s $IP_INTERNAL_NETWORK -d $IP_EXTERNAL_NETWORK -m conntrack --ctstate NEW,ESTABLISHED -m comment --comment "userDefinedTCP" -j ACCEPT
iptables -A FORWARD -p tcp -m multiport --sport $ALLOWED_TCP_PORT_RANGE -d $IP_INTERNAL_NETWORK -s $IP_EXTERNAL_NETWORK -m conntrack --ctstate ESTABLISHED -m comment --comment "userDefinedTCP" -j ACCEPT


#######USER DEFINED PERMITTED UDP RULES#############################################
#external to internal
iptables -A FORWARD -p udp -m multiport --dport $ALLOWED_UDP_PORT_RANGE -d $IP_INTERNAL_NETWORK -s $IP_EXTERNAL_NETWORK -m conntrack --ctstate NEW,ESTABLISHED -m comment --comment "userDefinedUDP" -j ACCEPT
iptables -A FORWARD -p udp -m multiport --sport $ALLOWED_UDP_PORT_RANGE -s $IP_INTERNAL_NETWORK -d $IP_EXTERNAL_NETWORK -m conntrack --ctstate ESTABLISHED -m comment --comment "userDefinedUDP" -j ACCEPT
#internal to external
iptables -A FORWARD -p udp -m multiport --dport $ALLOWED_UDP_PORT_RANGE -s $IP_INTERNAL_NETWORK -d $IP_EXTERNAL_NETWORK -m conntrack --ctstate NEW,ESTABLISHED -m comment --comment "userDefinedUDP" -j ACCEPT
iptables -A FORWARD -p udp -m multiport --sport $ALLOWED_UDP_PORT_RANGE -d $IP_INTERNAL_NETWORK -s $IP_EXTERNAL_NETWORK -m conntrack --ctstate ESTABLISHED -m comment --comment "userDefinedUDP" -j ACCEPT

#######ICMP RULES###################################################################
#need to make loop
#echo-request = 0
#echo-reply = 8
for type in "${ALLOWED_ICMP_TYPES[@]}"
do
	iptables -A FORWARD -m icmp -p icmp --icmp-type $type -d $IP_INTERNAL_NETWORK -m comment --comment "userDefinedICMP" -j ACCEPT
	iptables -A FORWARD -m icmp -p icmp --icmp-type $type -s $IP_INTERNAL_NETWORK -m comment --comment "userDefinedICMP" -j ACCEPT
done
