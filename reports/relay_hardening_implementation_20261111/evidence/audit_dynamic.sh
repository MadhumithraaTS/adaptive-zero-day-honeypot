#!/bin/sh
# READ-ONLY. Locates relay/Cowrie PIDs by cmdline, then lists routes, sysctls, firewall and listeners (no writes, no network I/O).
pid_cmd() { for p in /proc/[0-9]*; do c=$(tr '\0' ' ' < $p/cmdline 2>/dev/null); case "$c" in *"$1"*) echo ${p#/proc/}; return;; esac; done; }
RELAY=$(pid_cmd "portforward"); COWRIE=$(pid_cmd "pidfile= cowrie"); VM=$(for p in /proc/[0-9]*; do [ "$(cat $p/comm 2>/dev/null)" = dockerd ] && { echo ${p#/proc/}; break; }; done)
EMNT="--mount=/proc/$VM/ns/mnt"
echo "relay_pid=$RELAY cowrie_pid=$COWRIE vm_pid=$VM relay_cmd=$(tr '\0' ' ' < /proc/$RELAY/cmdline)"
run() { echo; echo "\$ $*"; "$@" 2>&1; }
for T in "relay:$RELAY" "cowrie:$COWRIE" "vm_engine:$VM"; do
  N=${T%%:*}; P=${T##*:}; NET="--net=/proc/$P/ns/net"
  echo; echo "################ $N (pid $P, $(readlink /proc/$P/ns/net)) ################"
  run nsenter $NET ip -o addr show
  run nsenter $NET ip route show table all
  run nsenter $NET ip -6 route show table all
  run nsenter $NET ip rule show
  echo; echo "\$ sysctls"
  nsenter $NET sh -c 'for f in /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv4/conf/*/forwarding /proc/sys/net/ipv4/conf/*/rp_filter /proc/sys/net/ipv6/conf/*/forwarding /proc/sys/net/ipv6/conf/*/disable_ipv6 /proc/sys/net/bridge/bridge-nf-call-iptables; do [ -e "$f" ] && echo "$f = $(cat $f)"; done' 2>&1
  run nsenter $NET $EMNT iptables-nft-save
  run nsenter $NET $EMNT nft list ruleset
  echo; echo "\$ listeners (LISTEN tcp/tcp6; all udp)"
  awk 'NR>1 && (FILENAME ~ /udp/ || $4=="0A"){print FILENAME, "local="$2, "state="$4, "inode="$10}' /proc/$P/net/tcp /proc/$P/net/tcp6 /proc/$P/net/udp /proc/$P/net/udp6 2>&1
  echo; echo "\$ caps"; grep -E '^(Cap|NoNewPrivs|Uid)' /proc/$P/status
done
