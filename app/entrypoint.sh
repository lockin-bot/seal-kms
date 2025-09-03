#!/bin/sh
set -e
busybox ip addr add 127.0.0.1/32 dev lo
busybox ip link set dev lo up

echo "127.0.0.1 localhost" > /etc/hosts
echo "nameserver 127.0.0.1" > /etc/resolv.conf
cat /etc/hosts

nautilus-server &
node /app/index.js
