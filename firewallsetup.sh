#! /bin/bash

ifconfig enp0s20f0u1 192.168.2.1 up
echo "1" >/proc/sys/net/ipv4/ip_forward
route add -net 192.168.1.0 netmask 255.255.255.0 gw 192.168.1.250
route add -net 192.168.2.0/24 gw 192.168.2.1