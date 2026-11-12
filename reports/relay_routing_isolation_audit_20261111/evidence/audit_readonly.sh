#!/bin/sh
# READ-ONLY audit. Every command is a list/show/read: ip ... show, iptables-*-save, nft list, cat /proc/sys.
# No set/add/del/flush, no sysctl -w, no network I/O. Run as: wsl -d docker-desktop -u root sh -s < audit_readonly.sh
RELAY=2890; COWRIE=2837; VM=165
EMNT="--mount=/proc/$VM/ns/mnt"
run() { echo; echo "\$ $*"; "$@" 2>&1; }
for T in "relay:$RELAY" "cowrie:$COWRIE" "vm_engine:$VM"; do
  N=${T%%:*}; P=${T##*:}; NET="--net=/proc/$P/ns/net"
  echo; echo "################ $N (pid $P, $(readlink /proc/$P/ns/net)) ################"
  run nsenter $NET ip -o link show
  run nsenter $NET ip -o addr show
  run nsenter $NET ip route show table all
  run nsenter $NET ip -6 route show table all
  run nsenter $NET ip rule show
  run nsenter $NET ip neigh show
  echo; echo "\$ forwarding sysctls (read /proc/sys in netns)"
  nsenter $NET sh -c 'for f in /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv4/conf/*/forwarding /proc/sys/net/ipv4/conf/*/rp_filter /proc/sys/net/ipv4/conf/*/accept_source_route /proc/sys/net/ipv4/conf/*/proxy_arp /proc/sys/net/ipv4/conf/*/route_localnet /proc/sys/net/ipv6/conf/*/forwarding /proc/sys/net/ipv6/conf/*/disable_ipv6 /proc/sys/net/bridge/bridge-nf-call-iptables /proc/sys/net/bridge/bridge-nf-call-ip6tables; do [ -e "$f" ] && echo "$f = $(cat $f)"; done' 2>&1
  run nsenter $NET $EMNT iptables-nft-save
  run nsenter $NET $EMNT ip6tables-nft-save
  run nsenter $NET $EMNT iptables-legacy-save
  run nsenter $NET $EMNT nft list ruleset
  echo; echo "\$ listening sockets (/proc/$P/net/tcp,tcp6,udp,udp6; state 0A = LISTEN; udp all)"
  awk 'NR>1 && (FILENAME ~ /udp/ || $4=="0A"){print FILENAME, "local="$2, "state="$4, "inode="$10}' /proc/$P/net/tcp /proc/$P/net/tcp6 /proc/$P/net/udp /proc/$P/net/udp6 2>&1
done
echo; echo "################ engine binaries present ################"
for b in iptables-nft-save ip6tables-nft-save iptables-legacy-save nft; do nsenter $EMNT sh -c "command -v $b || echo '$b: not found'"; done
