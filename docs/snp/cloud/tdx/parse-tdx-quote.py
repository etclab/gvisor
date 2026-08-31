#!/usr/bin/env python3
"""Decode an Intel TDX quote far enough to answer this study's question.

The counterpart of docs/snp/parse-snp-report.py, and it does the same job: read
the measurement registers out of raw evidence with no library, so that what the
probe compares is bytes off the platform rather than a library's opinion of them.

Layout is Intel's, from the TDX DCAP Quoting Library API specification
(A.3 Quote Format v4, A.3.2 TD Quote Body):

  Quote Header                       48 bytes
    version              u16 @  0    4 for the v4 format
    att_key_type         u16 @  2    2 = ECDSA-P256
    tee_type             u32 @  4    0x00000081 = TDX, 0x00000000 = SGX
    reserved/qe_svn      u16 @  8
    pce_svn              u16 @ 10
    qe_vendor_id      16 B   @ 12
    user_data         20 B   @ 28
  TD Quote Body                     584 bytes, at quote offset 48
    tee_tcb_svn       16 B   @   0
    mrseam            48 B   @  16   measurement of the TDX module
    mrsignerseam      48 B   @  64
    seam_attributes    8 B   @ 112
    td_attributes      8 B   @ 120
    xfam               8 B   @ 128
    mrtd              48 B   @ 136   initial contents of the TD, fixed at build
    mrconfigid        48 B   @ 184
    mrowner           48 B   @ 232
    mrownerconfig     48 B   @ 280
    rtmr0             48 B   @ 328   runtime-extendable
    rtmr1             48 B   @ 376
    rtmr2             48 B   @ 424
    rtmr3             48 B   @ 472
    reportdata        64 B   @ 520   the caller-supplied bytes, verbatim
  signature_data_len   u32   @ 632
  signature_data             @ 636
"""
import sys
import struct

HEADER = 48
BODY = 584
FIELDS = [
    ("tee_tcb_svn", 0, 16),
    ("mrseam", 16, 48),
    ("mrsignerseam", 64, 48),
    ("seam_attributes", 112, 8),
    ("td_attributes", 120, 8),
    ("xfam", 128, 8),
    ("mrtd", 136, 48),
    ("mrconfigid", 184, 48),
    ("mrowner", 232, 48),
    ("mrownerconfig", 280, 48),
    ("rtmr0", 328, 48),
    ("rtmr1", 376, 48),
    ("rtmr2", 424, 48),
    ("rtmr3", 472, 48),
    ("reportdata", 520, 64),
]


def main(path):
    blob = open(path, "rb").read()
    print(f"file                : {path}")
    print(f"size                : {len(blob)} bytes")
    if len(blob) < HEADER + BODY + 4:
        print(f"TOO SHORT: need at least {HEADER + BODY + 4} bytes for a v4 TDX quote")
        return 1

    version, att_key_type, tee_type, qe_svn, pce_svn = struct.unpack_from("<HHIHH", blob, 0)
    qe_vendor_id = blob[12:28]
    print(f"quote version       : {version}")
    print(f"att_key_type        : {att_key_type} {'(ECDSA-P256)' if att_key_type == 2 else ''}")
    print(f"tee_type            : 0x{tee_type:08x} {'(TDX)' if tee_type == 0x81 else '(SGX)' if tee_type == 0 else '(unknown)'}")
    print(f"qe_svn / pce_svn    : {qe_svn} / {pce_svn}")
    print(f"qe_vendor_id        : {qe_vendor_id.hex()}")

    body = blob[HEADER:HEADER + BODY]
    print()
    for name, off, width in FIELDS:
        print(f"{name:<20}: {body[off:off + width].hex()}")

    siglen = struct.unpack_from("<I", blob, HEADER + BODY)[0]
    print()
    print(f"signature_data_len  : {siglen}")
    print(f"bytes after body    : {len(blob) - HEADER - BODY - 4}")
    if siglen != len(blob) - HEADER - BODY - 4:
        print("  NOTE: declared signature length does not match the remaining bytes")

    # The caller-supplied bytes this probe hands the platform are 00 01 .. 3f.
    expect = bytes(range(64))
    got = body[520:584]
    print(f"reportdata echoes the 64 bytes handed in: {got == expect}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
