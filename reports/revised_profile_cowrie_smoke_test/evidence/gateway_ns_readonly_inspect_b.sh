#!/bin/sh
# Read-only: lists firewall rules and reads files; changes nothing, sends nothing.
echo "== os-release"; cat /proc/100/root/etc/os-release 2>/dev/null | head -4
echo "== packages"; awk '/^Package: (rpcbind|nfs-common|libtirpc3)$/{p=1} p&&/^(Package|Version|Status):/{print} /^$/{p=0}' /proc/100/root/var/lib/dpkg/status 2>/dev/null
echo "== nfs/rpc services in /initd config?"; grep -rl "rpcbind\|statd" /proc/59/root/etc/init* /proc/59/root/containers 2>/dev/null | head; ls /proc/59/root/containers/services 2>/dev/null | tr '\n' ' '; echo
echo "== nfs mounts in engine namespace"; grep -i nfs /proc/165/mounts | head -5; echo "(end)"
echo "== iptables binaries"; for b in iptables-save iptables-legacy-save iptables-nft-save nft; do command -v $b; ls /proc/165/root/usr/sbin/$b /proc/165/root/sbin/$b 2>/dev/null; done
