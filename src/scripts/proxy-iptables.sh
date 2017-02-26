#!/bin/bash

IFACE=$1

sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i $IFACE -p tcp --dport 443 -j REDIRECT --to-port 8080
