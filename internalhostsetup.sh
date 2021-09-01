#! /bin/bash

ifconfig eth0 192.168.2.2 up
route add default gw 192.168.2.1
echo "nameserver 8.8.8.8" >/etc/resolv.conf