#!/bin/sh
# Verbatim copy of the writable-must-be-noexec check from
# docs/snp/image/init.rootfs lines 30-44, with say() = echo.
# Argument $1 is the /proc/<pid>/mounts file to check (default /proc/mounts).
say() { echo "$@"; }
SRC="${1:-/proc/mounts}"
bad=0
while read -r dev mnt type opts rest; do
  case ",$opts," in
    *,rw,*) case ",$opts," in
              *,noexec,*) ;;
              *) say "WRITABLE AND EXECUTABLE: $mnt ($type,$opts)"; bad=1 ;;
            esac ;;
  esac
done < "$SRC"
if [ $bad != 0 ]; then
  say "FATAL: writable executable path present; powering off without running tunneld"
  exit 1
fi
say "no writable path is executable"
exit 0
