#!/usr/bin/env python3
"""Replay the Confidential Computing Event Log into the RTMRs and compare.

Runs INSIDE a TDX guest. Reads the CCEL data table the firmware left at
/sys/firmware/acpi/tables/data/CCEL, walks it as a TCG crypto-agile event log
(TCG PC Client Platform Firmware Profile, the format UEFI 2.10 points at),
replays every SHA-384 digest into the register it belongs to, and checks the
result against the RTMRs in a quote taken from the same boot.

This is the question that decides whether an RTMR is a statement or just a
number. If the log replays, a verifier holding it can say *which components*
produced an RTMR and check each one against something it knows. If there is no
log, an RTMR is 48 opaque bytes and the only thing anyone can do with it is
compare it to another observation of the same thing.

The PCR-to-register mapping is the TDVF's, from edk2's MapPcrToMrIndex:

    PCR 0            -> MRTD    (build time; never extended at runtime)
    PCR 1, 7         -> RTMR0
    PCR 2, 3, 4, 5   -> RTMR1
    PCR 8 .. 15      -> RTMR2
    (nothing)        -> RTMR3

and the extend is RTMR = SHA384(RTMR || digest), per TDG.MR.RTMR.EXTEND.
"""
import hashlib
import struct
import sys

CCEL_DATA = "/sys/firmware/acpi/tables/data/CCEL"
QUOTE_BODY = 48
RTMR_AT = {0: 328, 1: 376, 2: 424, 3: 472}
MRTD_AT = 136

ALG_SIZE = {0x0004: 20, 0x000B: 32, 0x000C: 48, 0x000D: 64, 0x0012: 32}
ALG_NAME = {0x0004: "sha1", 0x000B: "sha256", 0x000C: "sha384", 0x000D: "sha512", 0x0012: "sm3"}

EVENT_TYPE = {
    0x00000001: "EV_POST_CODE", 0x00000003: "EV_NO_ACTION",
    0x00000004: "EV_SEPARATOR", 0x00000005: "EV_ACTION",
    0x00000006: "EV_EVENT_TAG", 0x00000007: "EV_S_CRTM_CONTENTS",
    0x00000008: "EV_S_CRTM_VERSION", 0x00000009: "EV_CPU_MICROCODE",
    0x0000000A: "EV_PLATFORM_CONFIG_FLAGS", 0x0000000B: "EV_TABLE_OF_DEVICES",
    0x0000000C: "EV_COMPACT_HASH", 0x0000000D: "EV_IPL",
    0x0000000E: "EV_IPL_PARTITION_DATA", 0x00000010: "EV_NONHOST_CONFIG",
    0x00000012: "EV_OMIT_BOOT_DEVICE_EVENTS",
    0x80000001: "EV_EFI_VARIABLE_DRIVER_CONFIG", 0x80000002: "EV_EFI_VARIABLE_BOOT",
    0x80000003: "EV_EFI_BOOT_SERVICES_APPLICATION", 0x80000004: "EV_EFI_BOOT_SERVICES_DRIVER",
    0x80000005: "EV_EFI_RUNTIME_SERVICES_DRIVER", 0x80000006: "EV_EFI_GPT_EVENT",
    0x80000007: "EV_EFI_ACTION", 0x80000008: "EV_EFI_PLATFORM_FIRMWARE_BLOB",
    0x80000009: "EV_EFI_HANDOFF_TABLES", 0x8000000A: "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
    0x8000000B: "EV_EFI_HANDOFF_TABLES2", 0x8000000C: "EV_EFI_VARIABLE_BOOT2",
    0x80000010: "EV_EFI_HCRTM_EVENT", 0x800000E0: "EV_EFI_VARIABLE_AUTHORITY",
    0x800000E1: "EV_EFI_SPDM_FIRMWARE_BLOB", 0x800000E2: "EV_EFI_SPDM_FIRMWARE_CONFIG",
}


def mr_of(pcr):
    """The TDVF's PCR-to-measurement-register mapping. Returns 'mrtd',
    'rtmr0'..'rtmr2', or None for a PCR that extends nothing."""
    if pcr == 0:
        return "mrtd"
    if pcr in (1, 7):
        return "rtmr0"
    if pcr in (2, 3, 4, 5):
        return "rtmr1"
    if 8 <= pcr <= 15:
        return "rtmr2"
    return None


def parse(blob):
    """Yield (pcr, event_type, {alg: digest}, event_bytes) for every record."""
    off = 0
    # The first record is a legacy TCG_PCR_EVENT carrying the Spec ID event.
    pcr, etype, = struct.unpack_from("<II", blob, off)
    size = struct.unpack_from("<I", blob, off + 8 + 20)[0]
    first = blob[off + 8 + 20 + 4: off + 8 + 20 + 4 + size]
    yield pcr, etype, {}, first
    off += 8 + 20 + 4 + size

    while off + 8 <= len(blob):
        pcr, etype = struct.unpack_from("<II", blob, off)
        if pcr == 0xFFFFFFFF or (pcr == 0 and etype == 0 and off > 0):
            break
        p = off + 8
        if p + 4 > len(blob):
            break
        count = struct.unpack_from("<I", blob, p)[0]
        p += 4
        if count > 8:
            break
        digests = {}
        ok = True
        for _ in range(count):
            if p + 2 > len(blob):
                ok = False
                break
            alg = struct.unpack_from("<H", blob, p)[0]
            p += 2
            n = ALG_SIZE.get(alg)
            if n is None or p + n > len(blob):
                ok = False
                break
            digests[alg] = blob[p:p + n]
            p += n
        if not ok or p + 4 > len(blob):
            break
        size = struct.unpack_from("<I", blob, p)[0]
        p += 4
        if size > len(blob) - p:
            break
        yield pcr, etype, digests, blob[p:p + size]
        off = p + size


def describe(etype, event):
    name = EVENT_TYPE.get(etype, f"0x{etype:08x}")
    text = ""
    try:
        printable = bytes(c for c in event if 32 <= c < 127)
        if len(printable) >= max(4, len(event) // 4):
            text = printable.decode("ascii", "ignore")[:72]
        else:
            u = event.decode("utf-16-le", "ignore")
            u = "".join(c for c in u if c.isprintable())
            if len(u) >= 4:
                text = u[:72]
    except Exception:
        pass
    return name, text


def main():
    try:
        log = open(CCEL_DATA, "rb").read()
    except Exception as e:
        print(f"CCEL data table unreadable: {e}")
        print("NO EVENT LOG: an RTMR from this platform is 48 opaque bytes.")
        return 2
    print(f"CCEL data table     : {len(log)} bytes at {CCEL_DATA}")

    regs = {k: bytes(48) for k in ("rtmr0", "rtmr1", "rtmr2", "rtmr3")}
    counts = {}
    rows = []
    for pcr, etype, digests, event in parse(log):
        target = mr_of(pcr)
        name, text = describe(etype, event)
        rows.append((pcr, target or "-", name, text))
        counts[target or "(none)"] = counts.get(target or "(none)", 0) + 1
        d = digests.get(0x000C)
        if d and target and target.startswith("rtmr"):
            regs[target] = hashlib.sha384(regs[target] + d).digest()

    print(f"records             : {len(rows)}")
    print("records per register: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    print()
    print(f"{'PCR':<4} {'register':<8} {'event type':<38} description")
    for pcr, target, name, text in rows:
        print(f"{pcr:<4} {target:<8} {name:<38} {text}")
    print()

    if len(sys.argv) > 1:
        quote = open(sys.argv[1], "rb").read()
        body = quote[QUOTE_BODY:QUOTE_BODY + 584]
        print(f"{'register':<8} {'replayed == quote':<20} quote value")
        print(f"{'mrtd':<8} {'n/a (build time)':<20} {body[MRTD_AT:MRTD_AT + 48].hex()}")
        allok = True
        for i in range(4):
            r = f"rtmr{i}"
            want = body[RTMR_AT[i]:RTMR_AT[i] + 48]
            got = regs[r]
            ok = want == got
            allok = allok and ok
            print(f"{r:<8} {('YES' if ok else 'NO'):<20} {want.hex()}")
            if not ok:
                print(f"{'':<8} {'replayed:':<20} {got.hex()}")
        print()
        print("THE EVENT LOG REPLAYS TO THE QUOTE." if allok else
              "The replay does not reproduce every RTMR; see above for which.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
