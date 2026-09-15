#!/bin/bash
# Run inside the guest as root. Every question ticket 19's initrd will have to
# answer about this provider, asked once, on the boot that carries the initrd.
set -u
echo "############ 1. the report interface, and what drives it ############"
D=/sys/kernel/config/tsm/report/factsprobe
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
rmdir "$D" 2>/dev/null
if mkdir "$D" 2>/dev/null; then
  echo "attributes:"; ls -l "$D"
  for a in provider generation privlevel privlevel_floor; do
    echo "  $a : $(cat "$D/$a" 2>/dev/null || echo '(not exposed)')"
  done
  rmdir "$D" 2>/dev/null && echo "request removed" || echo "request NOT removed"
else
  echo "no report interface at $D"
fi
echo
echo "############ 2. is this a TDX guest, and with what loaded ############"
uname -r; head -2 /etc/os-release; cat /proc/cmdline
echo "--- dmesg, tdx ---"
dmesg 2>/dev/null | grep -i tdx || echo "(no tdx lines)"
echo "--- lsmod ---"
lsmod
echo
echo "############ 3. block devices, as Google names them ############"
echo "--- /dev/disk/by-id ---"
ls -l /dev/disk/by-id/ 2>&1
echo "--- lsblk ---"
lsblk -o NAME,SERIAL,SIZE,TYPE 2>&1
echo "--- /sys/block/*/serial ---"
for b in /sys/block/*; do
  [ -e "$b/serial" ] && echo "$(basename "$b"): $(cat "$b/serial" 2>/dev/null)"
done
cat /sys/block/*/serial 2>/dev/null
echo "--- udevadm info for the boot disk ---"
BOOTDEV="$(findmnt -no SOURCE /boot 2>/dev/null)"
echo "boot filesystem is on $BOOTDEV"
udevadm info --query=all --name="$BOOTDEV" 2>&1
udevadm info --query=all --name="$(lsblk -no PKNAME "$BOOTDEV" 2>/dev/null | head -1 | sed 's#^#/dev/#')" 2>&1
echo
echo "############ 4. the network, and the metadata server ############"
echo "--- ip -d link ---"
ip -d link 2>&1
echo "--- ip addr ---"
ip addr 2>&1
echo "--- ip route ---"
ip route 2>&1
echo "--- metadata server ---"
if curl -s -m 3 -H 'Metadata-Flavor: Google' http://169.254.169.254/ > /tmp/md.out 2>/tmp/md.err; then
  echo "169.254.169.254 answered:"; head -20 /tmp/md.out
else
  echo "169.254.169.254 did not answer (curl exit $?):"; head -3 /tmp/md.err
fi
echo "--- and one value out of it ---"
curl -s -m 3 -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/instance/id; echo " (curl exit $?)"
echo
