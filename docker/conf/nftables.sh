#!/bin/sh
# Packet-filter logging inside the container's own network namespace.
#
# NET_ADMIN is required to install rules at all, but the rules apply only to
# this container's namespace -- nothing here can affect the host's networking.
# The log prefix matches what the `iptables` mapping keys on.
set -eu

apk add --no-cache iptables >/dev/null 2>&1 || true
mkdir -p /var/log/netfilter

# Log and drop traffic to a port nothing is listening on, so the rule actually
# fires when the generator below pokes it.
iptables -N AUFLA_LOG 2>/dev/null || true
iptables -A AUFLA_LOG -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
iptables -A AUFLA_LOG -j DROP
iptables -C OUTPUT -p tcp --dport 9999 -j AUFLA_LOG 2>/dev/null \
  || iptables -A OUTPUT -p tcp --dport 9999 -j AUFLA_LOG

# The kernel writes these to the host ring buffer, not to a file, so they are
# drained into one. This is the part that differs from a real host, where
# rsyslog would already be routing kern.* to /var/log.
while true; do
  dmesg -c 2>/dev/null | grep -F "IPTables-" >> /var/log/netfilter/kernel.log || true
  # Generate a packet so there is something to log.
  (timeout 1 nc -z 127.0.0.1 9999 >/dev/null 2>&1 || true)
  sleep 5
done
