#!/bin/sh
# Read-only: tool lookup and process listing. No network I/O, nothing changed.
echo "uid=$(id -u)"
for b in nsenter iptables-nft-save iptables-legacy-save iptables-save ip6tables-nft-save ip6tables-save nft ip; do printf "%s=%s\n" $b "$(command -v $b)"; done
pid_of() { for p in /proc/[0-9]*; do [ "$(cat $p/comm 2>/dev/null)" = "$1" ] && echo ${p#/proc/}; done; }
echo "dockerd=$(pid_of dockerd | head -1)"
for p in /proc/[0-9]*; do c=$(tr '\0' ' ' < $p/cmdline 2>/dev/null); case "$c" in *portforward*|*"twistd -n --umask=0022 --pidfile= cowrie"*) echo "pid=${p#/proc/} netns=$(readlink $p/ns/net) cmd=$c";; esac; done
