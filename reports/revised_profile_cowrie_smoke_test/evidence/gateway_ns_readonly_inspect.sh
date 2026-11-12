#!/bin/sh
# Read-only: /proc reads only, no network I/O.
pid_of() { for p in /proc/[0-9]*; do [ "$(cat $p/comm 2>/dev/null)" = "$1" ] && { echo ${p#/proc/}; return; }; done; }
R=$(pid_of rpcbind); D=$(pid_of dockerd)
echo "whoami=$(id -u) rpcbind_pid=$R dockerd_pid=$D"
for n in rpcbind rpc.statd rpc.idmapd dockerd; do p=$(pid_of $n); echo "== $n pid=$p exe=$(readlink /proc/$p/exe) uid=$(awk '/^Uid/{print $2}' /proc/$p/status) ppid=$(awk '/^PPid/{print $2}' /proc/$p/status) cmd=$(tr '\0' ' ' < /proc/$p/cmdline)"; done
echo "== parent chain of rpcbind"; p=$R; for i in 1 2 3 4 5; do p=$(awk '/^PPid/{print $2}' /proc/$p/status); [ "$p" -le 1 ] 2>/dev/null && { echo "pid $p"; break; }; echo "pid $p $(tr '\0' ' ' < /proc/$p/cmdline | cut -c1-150)"; done
echo "== LISTEN tcp sockets in rpcbind netns (state 0A)"; awk 'NR>1 && $4=="0A"{print FILENAME, $2, $10}' /proc/$R/net/tcp /proc/$R/net/tcp6
echo "== UDP sockets in rpcbind netns"; awk 'NR>1{print FILENAME, $2, $10}' /proc/$R/net/udp /proc/$R/net/udp6
echo "== socket inodes per process in that netns"; for p in /proc/[0-9]*; do [ "$(readlink $p/ns/net 2>/dev/null)" = "$(readlink /proc/$R/ns/net)" ] || continue; s=$(ls -l $p/fd 2>/dev/null | grep -o 'socket:\[[0-9]*\]' | tr -d 'socket:[]' | tr '\n' ' '); [ -n "$s" ] && echo "$(cat $p/comm) pid=${p#/proc/}: $s"; done
echo "== interfaces (net/dev) and routes"; awk 'NR>2{print $1}' /proc/$R/net/dev | tr '\n' ' '; echo; awk 'NR>1{print $1,$2,$3,$8}' /proc/$R/net/route
echo "== local addresses (fib_trie LOCAL)"; awk '/\/32 host LOCAL/{print prev} {prev=$2}' /proc/$R/net/fib_trie | sort -u | tr '\n' ' '; echo
echo "== rpc config files"; for f in /etc/default/rpcbind /etc/conf.d/rpcbind /etc/netconfig /etc/exports; do [ -e /proc/$R/root$f ] && { echo "-- $f"; head -20 /proc/$R/root$f; }; done
echo "== iptables files visible?"; ls /proc/$R/root/etc/init.d 2>/dev/null | tr '\n' ' '
