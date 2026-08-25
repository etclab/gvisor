#!/usr/bin/env python3
"""Decode an SEV-SNP attestation report and, if present, its certificate table.

Reads the raw bytes the platform's report interface (configfs-tsm) produced:
  outblob -> the report          (1184 bytes)
  auxblob -> the certificate table, if the host provisioned one

No dependencies. This exists so evidence can be read by hand in ticket 01,
before any Go code exists. Field offsets follow the SEV-SNP ABI, table
"ATTESTATION_REPORT Structure".
"""
import argparse
import struct
import sys

REPORT_SIZE = 0x4A0

# TCB_VERSION is 8 bytes: boot_loader, tee, reserved[4], snp, microcode.
def tcb(raw):
    b = struct.unpack("<8B", raw)
    return {"bootloader": b[0], "tee": b[1], "snp": b[6], "microcode": b[7]}


def tcb_str(t):
    return "bootloader=%d tee=%d snp=%d microcode=%d" % (
        t["bootloader"], t["tee"], t["snp"], t["microcode"])


POLICY_BITS = [
    (16, "SMT_ALLOWED"),
    (17, "RESERVED_MBO"),      # must be one
    (18, "MIGRATE_MA_ALLOWED"),
    (19, "DEBUG_ALLOWED"),
    (20, "SINGLE_SOCKET_REQUIRED"),
    (21, "CXL_ALLOWED"),
    (22, "MEM_AES_256_XTS_REQUIRED"),
    (23, "RAPL_DISABLED"),
    (24, "CIPHERTEXT_HIDING_REQUIRED"),
]

PLATFORM_INFO_BITS = [
    (0, "SMT_EN"),
    (1, "TSME_EN"),
    (2, "ECC_EN"),
    (3, "RAPL_DIS"),
    (4, "CIPHERTEXT_HIDING_EN"),
]

SIGNING_KEY = {0: "VCEK", 1: "VLEK", 7: "NONE"}

# Certificate-table GUIDs, as they appear little-endian-mixed in the table.
CERT_GUIDS = {
    "63da758d-e664-4564-adc5-f4b93be8accd": "VCEK",
    "a8074bc2-a25a-483e-aae6-39c045a0b8a1": "VLEK",
    "4ab7b379-bbac-4fe4-a02f-05aef327c782": "ASK  (AMD SEV intermediate)",
    "c0b406a4-a803-4952-9743-3fb6014cd0ae": "ARK  (AMD root)",
    "92f81bc3-5811-4d3d-97ff-d19f88dc67ea": "CRL",
}


def guid_str(raw):
    d1, d2, d3 = struct.unpack("<IHH", raw[:8])
    return "%08x-%04x-%04x-%s-%s" % (
        d1, d2, d3, raw[8:10].hex(), raw[10:16].hex())


def bits(value, table):
    on = [name for bit, name in table if value & (1 << bit)]
    return ", ".join(on) if on else "(none)"


def parse_report(b):
    if len(b) < REPORT_SIZE:
        sys.exit("report is %d bytes, expected at least %d" % (len(b), REPORT_SIZE))
    f = {}
    f["version"] = struct.unpack_from("<I", b, 0x000)[0]
    f["guest_svn"] = struct.unpack_from("<I", b, 0x004)[0]
    f["policy"] = struct.unpack_from("<Q", b, 0x008)[0]
    f["family_id"] = b[0x010:0x020]
    f["image_id"] = b[0x020:0x030]
    f["vmpl"] = struct.unpack_from("<I", b, 0x030)[0]
    f["sig_algo"] = struct.unpack_from("<I", b, 0x034)[0]
    f["current_tcb"] = tcb(b[0x038:0x040])
    f["platform_info"] = struct.unpack_from("<Q", b, 0x040)[0]
    flags = struct.unpack_from("<I", b, 0x048)[0]
    f["author_key_en"] = flags & 1
    f["mask_chip_key"] = (flags >> 1) & 1
    f["signing_key"] = (flags >> 2) & 7
    f["report_data"] = b[0x050:0x090]
    f["measurement"] = b[0x090:0x0C0]
    f["host_data"] = b[0x0C0:0x0E0]
    f["id_key_digest"] = b[0x0E0:0x110]
    f["author_key_digest"] = b[0x110:0x140]
    f["report_id"] = b[0x140:0x160]
    f["report_id_ma"] = b[0x160:0x180]
    f["reported_tcb"] = tcb(b[0x180:0x188])
    f["cpuid_fam_id"] = b[0x188]
    f["cpuid_mod_id"] = b[0x189]
    f["cpuid_step"] = b[0x18A]
    f["chip_id"] = b[0x1A0:0x1E0]
    f["committed_tcb"] = tcb(b[0x1E0:0x1E8])
    f["current_build"] = b[0x1E8]
    f["current_minor"] = b[0x1E9]
    f["current_major"] = b[0x1EA]
    f["committed_build"] = b[0x1EC]
    f["committed_minor"] = b[0x1ED]
    f["committed_major"] = b[0x1EE]
    f["launch_tcb"] = tcb(b[0x1F0:0x1F8])
    f["signature"] = b[0x2A0:0x4A0]
    return f


def print_report(f):
    print("== SEV-SNP attestation report ==")
    print("version                : %d" % f["version"])
    print("guest_svn              : %d" % f["guest_svn"])
    print("policy                 : 0x%x" % f["policy"])
    print("  abi                  : %d.%d" % ((f["policy"] >> 8) & 0xFF, f["policy"] & 0xFF))
    print("  bits                 : %s" % bits(f["policy"], POLICY_BITS))
    print("  DEBUG_ALLOWED        : %s" % ("YES -- guest is NOT confidential"
                                           if f["policy"] & (1 << 19) else "no"))
    print("vmpl                   : %d" % f["vmpl"])
    print("signature algo         : %d (1 = ECDSA P-384 with SHA-384)" % f["sig_algo"])
    print("signing key            : %s (%d)" % (SIGNING_KEY.get(f["signing_key"], "?"),
                                                f["signing_key"]))
    print("author key enabled     : %d" % f["author_key_en"])
    print("mask chip key          : %d" % f["mask_chip_key"])
    print("platform_info          : 0x%x  [%s]" % (f["platform_info"],
                                                   bits(f["platform_info"], PLATFORM_INFO_BITS)))
    print()
    print("LAUNCH MEASUREMENT (M) : %s" % f["measurement"].hex())
    print("report_data (64B)      : %s" % f["report_data"].hex())
    print("host_data              : %s" % f["host_data"].hex())
    print("family_id              : %s" % f["family_id"].hex())
    print("image_id               : %s" % f["image_id"].hex())
    print("id_key_digest          : %s" % f["id_key_digest"].hex())
    print("author_key_digest      : %s" % f["author_key_digest"].hex())
    print("report_id              : %s" % f["report_id"].hex())
    print("chip_id                : %s" % f["chip_id"].hex())
    print()
    print("current_tcb            : %s" % tcb_str(f["current_tcb"]))
    print("reported_tcb           : %s" % tcb_str(f["reported_tcb"]))
    print("committed_tcb          : %s" % tcb_str(f["committed_tcb"]))
    print("launch_tcb             : %s" % tcb_str(f["launch_tcb"]))
    print("current firmware       : %d.%d build %d" % (f["current_major"], f["current_minor"],
                                                       f["current_build"]))
    print("committed firmware     : %d.%d build %d" % (f["committed_major"], f["committed_minor"],
                                                       f["committed_build"]))
    print("cpuid fam/mod/step     : 0x%02x/0x%02x/0x%02x" % (f["cpuid_fam_id"], f["cpuid_mod_id"],
                                                             f["cpuid_step"]))
    sig = f["signature"]
    print("signature r (first 16) : %s..." % sig[:16].hex())
    print("signature s (first 16) : %s..." % sig[72:88].hex())
    print("signature all-zero     : %s" % ("YES -- report is unsigned"
                                           if sig == b"\x00" * len(sig) else "no"))


def parse_certs(b):
    print()
    print("== certificate table (auxblob) ==")
    if not b:
        print("EMPTY -- the host did not provision a certificate chain.")
        print("Offline verification cannot use the platform chain; the KDS fetch")
        print("becomes the primary retrieval path rather than a fallback.")
        return []
    entries = []
    off = 0
    while off + 24 <= len(b):
        guid_raw = b[off:off + 16]
        coff, clen = struct.unpack_from("<II", b, off + 16)
        if guid_raw == b"\x00" * 16 and coff == 0 and clen == 0:
            break
        entries.append((guid_str(guid_raw), coff, clen))
        off += 24
    if not entries:
        print("table present (%d bytes) but contains no entries." % len(b))
        return []
    print("%-38s %-10s %-8s %s" % ("GUID", "OFFSET", "LENGTH", "MEANING"))
    for g, coff, clen in entries:
        print("%-38s %-10d %-8d %s" % (g, coff, clen, CERT_GUIDS.get(g, "unknown")))
    return entries


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report", help="raw outblob")
    ap.add_argument("--certs", help="raw auxblob")
    ap.add_argument("--extract-certs", metavar="DIR",
                    help="write each certificate in the table to DIR")
    a = ap.parse_args()

    with open(a.report, "rb") as fh:
        rb = fh.read()
    print_report(parse_report(rb))

    cb = b""
    if a.certs:
        with open(a.certs, "rb") as fh:
            cb = fh.read()
        entries = parse_certs(cb)
        if a.extract_certs and entries:
            import os
            os.makedirs(a.extract_certs, exist_ok=True)
            for g, coff, clen in entries:
                name = CERT_GUIDS.get(g, g).split()[0].lower()
                path = os.path.join(a.extract_certs, "%s.der" % name)
                with open(path, "wb") as fh:
                    fh.write(cb[coff:coff + clen])
                print("wrote %s (%d bytes)" % (path, clen))


if __name__ == "__main__":
    main()
