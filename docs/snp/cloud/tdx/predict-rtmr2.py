#!/usr/bin/env python3
"""Predict RTMR2 from a disk image, before anything has booted.

Takes the bytes of an Ubuntu 24.04 GCE disk image -- a file, never a running
machine -- and prints the ordered list of SHA-384 digests that shim and grub
would extend into RTMR2 on a Google Cloud TDX VM booted from it, plus the
RTMR2 those digests produce (RTMR = SHA384(RTMR || digest), from 48 zeros).

The point is the direction of travel. replay-ccel.py runs inside a guest and
checks that a log the guest was handed replays to a register the guest was
handed; it proves the two agree, and nothing about what either *should* be.
This runs outside, on the artefact a verifier can obtain independently, and
computes what RTMR2 has to be if the machine boots that image unmodified. A
verifier that can do this can hold an expected RTMR2 for an image it has never
booted, which is what "measured boot" is supposed to buy and what an opaque
48-byte comparison against a previous observation does not.

Two kinds of thing get extended into RTMR2, and the script derives both:

  (a) file bytes.  grub's tpm module is a grub_file verifier: every file grub
      opens is measured whole, with the file's name as the event description.
      Fourteen records are of this kind -- the ESP grub.cfg (twice), the four
      module lists, the real grub.cfg, grubenv (twice), bli.mod, the kernel,
      and shim's three MoK variables, which are built out of shimx64.efi's
      .vendor_cert section rather than read from a file.

  (b) synthesised strings.  Ubuntu's grub measures every command line it
      executes as sha384 of the bare string -- no prefix, no NUL -- and
      describes it in the log as "grub_cmd: <string>". The kernel command line
      gets one more record of its own. Seventy-two records are of this kind.
      They are not in the image as text: they are what the config *evaluates
      to*, so the script contains a small interpreter for the subset of grub
      script Ubuntu's grub.cfg uses, and executes the config to get them.

What this does not do. It does not read an RTMR, a quote, or an event log to
decide anything: --compare-ccel and --compare-quote only compare at the end,
and removing them changes no digest. It does not predict RTMR0 (firmware
configuration and UEFI variables), RTMR1 (the EFI boot chain and the GPT), or
MRTD. It models grub script only as far as Ubuntu's generated config needs --
if/elif/else, [ ], set/unset/export, functions, menuentry/submenu, insmod,
search, configfile, load_env/save_env, linux/initrd -- and raises on anything
it does not know rather than guessing. And it assumes the machine boots the
default menu entry with no human at the console; a keystroke at the menu, a
different entry, or an edited command line all change RTMR2, which is the
whole point of measuring them.

Modes:
  --raw disk.raw          parse the GPT and pull files straight out of the
                          image's partitions (debugfs for ext4, mtools for
                          vfat); no mount, no root, nothing booted.
  --tree DIR              the same layout unpacked on disk, DIR/boot/...,
                          for a filesystem captured out of a guest.
"""
import argparse
import hashlib
import importlib.util
import os
import re
import struct
import subprocess
import sys
import tempfile
import uuid as uuidmod

# ---------------------------------------------------------------------------
# Model inputs.
#
# These are the things that are true of the platform and of grubx64.efi rather
# than of the config, so the config cannot tell us them. Every one of them is
# either a build-time constant of the grub binary, a property of the firmware,
# or an empirical constant of grub's startup path; none of them is read from a
# quote or an event log.
# ---------------------------------------------------------------------------

# Variables grub defines for itself before the first line of the boot config
# runs. "prefix" and "root" are filled in per image; "?" is the exit status of
# the previous command. The feature_* flags are what grub 2.12 sets; the
# config branches on three of them (menuentry_id, all_video_module,
# timeout_style) and the branches taken are visible in the log.
GRUB_BUILTIN_ENV = {
    "grub_platform": "efi",
    "grub_cpu": "x86_64",
    "feature_menuentry_id": "y",
    "feature_menuentry_options": "y",
    "feature_all_video_module": "y",
    "feature_timeout_style": "y",
    "feature_default_font_path": "y",
    "feature_nativedisk_cmd": "y",
    "feature_chainloader_bpb": "y",
    "feature_ntldr": "y",
    "feature_platform_search_hint": "y",
    "feature_dhcp_no_gateway": "y",
    "?": "0",
}

# GRUB_TARGET_CPU "-" GRUB_PLATFORM: the subdirectory of $prefix that grub
# loads .mod files and the four .lst files from. A build constant of the
# signed grubx64.efi, not something in the config.
GRUB_MODULE_SUBDIR = "x86_64-efi"

# normal.mod hooks writes to $prefix and reads four lists from the new
# location, in this order (grub-core/normal/main.c:read_lists).
PREFIX_LISTS = ["command.lst", "fs.lst", "crypto.lst", "terminal.lst"]

# The config `normal` loads from $prefix at startup is opened -- and therefore
# measured -- twice before its first command runs; a config reached later by
# `configfile` is measured once. This is empirical: both records carry the
# same digest and both precede the first grub_cmd record from that file. It is
# a constant of grub 2.12's EFI startup path, not of the image.
BOOT_CONFIG_MEASUREMENTS = 2

# `fwsetup --is-supported` on this firmware returns success, so 30_uefi-firmware
# emits its menu entry. This is a firmware property; on firmware without setup
# support the config would take the other branch and RTMR2 would differ.
FWSETUP_IS_SUPPORTED = 0

# The disk grub booted from, as grub names it.
DEFAULT_DISK = "hd0"

# Where the firmware's boot option points. This comes from the UEFI
# BootOrder/BootXXXX variables, which live in firmware state and not in the
# image; \EFI\ubuntu\shimx64.efi is what the GCE boot entry for an Ubuntu
# image says, and it is visible in the RTMR1 records.
DEFAULT_EFI_DIR = "/EFI/ubuntu"

# shim 15.8 as Ubuntu ships it (shim-signed 1.58+15.8-0ubuntu1). Upstream
# shim mirrors the vendor dbx out of .vendor_cert into MokListX; Ubuntu's
# 15.8-0ubuntu1 patch deletes the .addend/.addend_size fields from the
# MokListX entry of mok_state_variable_data[], so the addend is empty and shim
# falls into the "we always want to create our key databases, so in this case
# we need a dummy entry" branch of mirror_one_mok_variable(). Set this True to
# model an unpatched shim.
SHIM_MIRRORS_VENDOR_DBX = False

# GUIDs, from shim and from UEFI 2.10.
EFI_CERT_X509_GUID = uuidmod.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")
EFI_CERT_SHA256_GUID = uuidmod.UUID("c1c41626-504c-4092-aca9-41f936934328")
SHIM_LOCK_GUID = uuidmod.UUID("605dab50-e046-4300-abb6-3dd810dd8b23")
ESP_TYPE_GUID = uuidmod.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")

QUOTE_BODY = 48
RTMR2_AT = 424
SECTOR = 512


def sha384(b):
    return hashlib.sha384(b).digest()


# ---------------------------------------------------------------------------
# Getting bytes out of the image without mounting anything
# ---------------------------------------------------------------------------

class ImageError(Exception):
    pass


class Image(object):
    """A set of numbered partitions we can read files out of."""

    def partitions(self):
        raise NotImplementedError

    def where(self, part):
        """Human description of where partition `part` lives."""
        raise NotImplementedError

    def read(self, part, path):
        """Bytes of `path` inside partition `part`, or None if absent."""
        raise NotImplementedError

    def stat(self, part, path):
        """(kind, size) with kind in {'file','dir'}, or None if absent."""
        raise NotImplementedError

    def fs_uuid_partition(self, u):
        """Partition number whose filesystem UUID is `u`, or None."""
        raise NotImplementedError


class RawImage(Image):
    """A GPT disk image. ext4 partitions are read with debugfs, vfat ones with
    mtools; both are ordinary user tools and neither needs a mount or root."""

    def __init__(self, path):
        self.path = path
        self.parts = {}
        self._cache = {}
        self._stats = {}
        self._parse_gpt()
        for n, p in self.parts.items():
            p["fstype"], p["uuid"] = self._probe_fs(p["start"])

    def _parse_gpt(self):
        with open(self.path, "rb") as f:
            f.seek(SECTOR)
            hdr = f.read(92)
            if hdr[:8] != b"EFI PART":
                raise ImageError("%s: no GPT header at LBA 1" % self.path)
            ptlba, nent, esz = struct.unpack_from("<QII", hdr, 72)
            f.seek(ptlba * SECTOR)
            tbl = f.read(nent * esz)
        for i in range(nent):
            e = tbl[i * esz:(i + 1) * esz]
            if len(e) < 128 or e[0:16] == b"\0" * 16:
                continue
            first, last = struct.unpack_from("<QQ", e, 32)
            self.parts[i + 1] = {
                "num": i + 1,
                "type": uuidmod.UUID(bytes_le=e[0:16]),
                "guid": uuidmod.UUID(bytes_le=e[16:32]),
                "start": first * SECTOR,
                "size": (last - first + 1) * SECTOR,
            }

    def _probe_fs(self, off):
        with open(self.path, "rb") as f:
            f.seek(off)
            head = f.read(4096)
        if len(head) >= 1024 + 0x70:
            if struct.unpack_from("<H", head, 1024 + 0x38)[0] == 0xEF53:
                return "ext", str(uuidmod.UUID(bytes=head[1024 + 0x68:1024 + 0x78]))
        if head[0x52:0x5A] == b"FAT32   ":
            v = struct.unpack_from("<I", head, 0x43)[0]
            return "vfat", "%04X-%04X" % (v >> 16, v & 0xFFFF)
        if head[0x36:0x39] == b"FAT":
            v = struct.unpack_from("<I", head, 0x27)[0]
            return "vfat", "%04X-%04X" % (v >> 16, v & 0xFFFF)
        return None, None

    def partitions(self):
        return sorted(self.parts)

    def where(self, part):
        p = self.parts[part]
        return "gpt%d at byte %d (%s)" % (part, p["start"], p["fstype"] or "unknown fs")

    def _run(self, argv):
        return subprocess.run(argv, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, check=False)

    def stat(self, part, path):
        key = (part, path)
        if key in self._stats:
            return self._stats[key]
        p = self.parts.get(part)
        if p is None:
            raise ImageError("no partition %d in %s" % (part, self.path))
        res = None
        if p["fstype"] == "ext":
            dev = "%s?offset=%d" % (self.path, p["start"])
            out = self._run(["debugfs", "-R", "stat %s" % path, dev]).stdout.decode(
                "utf-8", "replace")
            if "File not found" not in out and "Inode:" in out:
                m = re.search(r"Type:\s+(\w+)", out)
                s = re.search(r"Size:\s+(\d+)", out)
                kind = "dir" if (m and m.group(1) == "directory") else "file"
                res = (kind, int(s.group(1)) if s else 0)
        elif p["fstype"] == "vfat":
            img = "%s@@%d" % (self.path, p["start"])
            out = self._run(["mdir", "-i", img, "::" + path]).stdout.decode(
                "utf-8", "replace")
            if "not found" not in out and "No such" not in out:
                res = ("file", None)
        else:
            raise ImageError("partition %d: unrecognised filesystem" % part)
        self._stats[key] = res
        return res

    def read(self, part, path):
        key = (part, path)
        if key in self._cache:
            return self._cache[key]
        p = self.parts.get(part)
        if p is None:
            raise ImageError("no partition %d in %s" % (part, self.path))
        data = None
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "f")
            if p["fstype"] == "ext":
                dev = "%s?offset=%d" % (self.path, p["start"])
                r = self._run(["debugfs", "-R", "dump -p %s %s" % (path, out), dev])
                if os.path.exists(out) and b"File not found" not in r.stdout:
                    with open(out, "rb") as f:
                        data = f.read()
            elif p["fstype"] == "vfat":
                img = "%s@@%d" % (self.path, p["start"])
                self._run(["mcopy", "-n", "-i", img, "::" + path, out])
                if os.path.exists(out):
                    with open(out, "rb") as f:
                        data = f.read()
            else:
                raise ImageError("partition %d: unrecognised filesystem" % part)
        self._cache[key] = data
        if data is not None:
            self._stats[key] = ("file", len(data))
        return data

    def fs_uuid_partition(self, u):
        u = u.lower()
        for n in sorted(self.parts):
            if (self.parts[n]["uuid"] or "").lower() == u:
                return n
        return None


class TreeImage(Image):
    """A guest filesystem unpacked as directories: DIR is the root, and
    partition numbers are mapped onto subtrees of it. Used for a tarball
    captured out of a running guest, where there is no GPT to parse."""

    def __init__(self, root, mapping, uuidmap, fallback_part):
        self.root = os.path.abspath(root)
        self.map = dict(mapping)          # partition number -> directory
        self.uuidmap = dict(uuidmap)      # filesystem uuid -> partition number
        self.fallback = fallback_part

    def _p(self, part, path):
        d = self.map.get(part)
        if d is None:
            raise ImageError("no directory mapped for partition %d" % part)
        rel = path.lstrip("/")
        full = os.path.normpath(os.path.join(d, rel))
        if not full.startswith(os.path.normpath(d)):
            raise ImageError("path escapes the tree: %s" % path)
        return full

    def partitions(self):
        return sorted(self.map)

    def where(self, part):
        return "gpt%d -> %s" % (part, self.map.get(part, "?"))

    def stat(self, part, path):
        f = self._p(part, path)
        if os.path.isdir(f):
            return ("dir", None)
        if os.path.isfile(f):
            return ("file", os.path.getsize(f))
        return None

    def read(self, part, path):
        f = self._p(part, path)
        if not os.path.isfile(f):
            return None
        with open(f, "rb") as fh:
            return fh.read()

    def fs_uuid_partition(self, u):
        n = self.uuidmap.get(u.lower())
        if n is not None:
            return n
        return self.fallback


# ---------------------------------------------------------------------------
# PE and ELF picking, for shimx64.efi and grubx64.efi
# ---------------------------------------------------------------------------

def pe_sections(data):
    """[(name, virtual_size, raw_offset, raw_size)] with long names resolved
    through the COFF string table."""
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ImageError("not a PE image")
    nsec, psym, nsym, osz = struct.unpack_from("<H", data, pe + 6)[0], \
        struct.unpack_from("<I", data, pe + 12)[0], \
        struct.unpack_from("<I", data, pe + 16)[0], \
        struct.unpack_from("<H", data, pe + 20)[0]
    strtab = psym + nsym * 18 if psym else 0
    out = []
    so = pe + 24 + osz
    for i in range(nsec):
        e = data[so + i * 40:so + (i + 1) * 40]
        raw = e[0:8].rstrip(b"\0").decode("latin-1")
        name = raw
        if raw.startswith("/") and strtab:
            off = int(raw[1:])
            end = data.index(b"\0", strtab + off)
            name = data[strtab + off:end].decode("latin-1")
        vsz, _va, rsz, ro = struct.unpack_from("<IIII", e, 8)
        out.append((name, vsz, ro, rsz))
    return out


def pe_section(data, want):
    for name, vsz, ro, rsz in pe_sections(data):
        if name == want:
            return data[ro:ro + vsz]
    return None


def elf_section(data, want):
    """Contents of an ELF64 section by name, or None."""
    if data[:4] != b"\x7fELF":
        return None
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    shstr = struct.unpack_from("<Q", data, shoff + shstrndx * shentsize + 0x18)[0]
    for k in range(shnum):
        so = shoff + k * shentsize
        nameoff = struct.unpack_from("<I", data, so)[0]
        end = data.index(b"\0", shstr + nameoff)
        if data[shstr + nameoff:end].decode("latin-1") == want:
            off, size = struct.unpack_from("<QQ", data, so + 0x18)
            return data[off:off + size]
    return None


def grub_image_info(data):
    """(set of module names built into grubx64.efi, embedded prefix or None).

    grub-mkimage appends the modules it linked in as a blob introduced by
    struct grub_module_info64 {magic 'mimg', pad, offset, size}; each module is
    a grub_module_header {type, size} followed by an ELF object whose .modname
    section holds its name. `insmod X` for a name in this set loads nothing and
    so measures nothing; any other name is read from $prefix and measured."""
    base = None
    for name, vsz, ro, rsz in pe_sections(data):
        if name == "mods" and data[ro:ro + 4] == b"mimg":
            base = ro
            break
    if base is None:
        i = 0
        while True:
            i = data.find(b"mimg", i)
            if i < 0:
                raise ImageError("no grub module blob in the image")
            _m, _p, off, size = struct.unpack_from("<IIQQ", data, i)
            if 0 < off < 1 << 20 and 0 < size <= len(data) - i:
                base = i
                break
            i += 4
    _m, _p, off, size = struct.unpack_from("<IIQQ", data, base)
    p = base + off
    end = base + size
    mods = set()
    prefix = None
    while p + 8 <= end:
        t, sz = struct.unpack_from("<II", data, p)
        if sz < 8:
            break
        body = data[p + 8:p + sz]
        if t == 0:
            nm = elf_section(body, ".modname")
            if nm:
                mods.add(nm.split(b"\0")[0].decode("latin-1"))
        elif t == 3:
            prefix = body.split(b"\0")[0].decode("latin-1")
        p += sz
    return mods, prefix


def module_deps(mod_bytes):
    d = elf_section(mod_bytes, ".moddeps")
    if not d:
        return []
    return [x.decode("latin-1") for x in d.split(b"\0") if x]


# ---------------------------------------------------------------------------
# shim: what it mirrors into PCR14, which edk2 maps to RTMR2
# ---------------------------------------------------------------------------

def esl(sigtype, owner, payload):
    """One EFI_SIGNATURE_LIST holding one EFI_SIGNATURE_DATA."""
    sig = owner.bytes_le + payload
    return sigtype.bytes_le + struct.pack("<III", 28 + len(sig), 0, len(sig)) + sig


def shim_vendor_cert(shim_bytes):
    """(vendor_authorized, vendor_deauthorized) out of .vendor_cert.

    cert.S lays the section out as struct {UINT32 vendor_authorized_size;
    UINT32 vendor_deauthorized_size; UINT32 vendor_authorized_offset;
    UINT32 vendor_deauthorized_offset;} followed by the two blobs."""
    sec = pe_section(shim_bytes, ".vendor_cert")
    if sec is None:
        raise ImageError("shimx64.efi has no .vendor_cert section")
    a_sz, d_sz, a_off, d_off = struct.unpack_from("<IIII", sec, 0)
    return sec[a_off:a_off + a_sz], sec[d_off:d_off + d_sz]


def shim_mok_records(shim_bytes):
    """The three MoK variables shim 15.8 logs into PCR14 -> RTMR2, in order.

    Each is (event name, measured bytes, class, provenance note). shim's
    tpm_log_event() hashes the mirrored variable *contents* and writes the
    variable's ASCII name as the event description, so the digest is
    sha384(contents) exactly as for a file."""
    auth, deauth = shim_vendor_cert(shim_bytes)
    out = []

    if auth:
        data = esl(EFI_CERT_X509_GUID, SHIM_LOCK_GUID, auth)
        note = ("shimx64.efi .vendor_cert vendor_authorized, %d bytes of DER, wrapped by "
                "shim in one EFI_SIGNATURE_LIST (EFI_CERT_X509_GUID, owner SHIM_LOCK_GUID)"
                % len(auth))
        cls = "a"
    else:
        data = esl(EFI_CERT_SHA256_GUID, SHIM_LOCK_GUID, b"\0" * 32)
        note = "no vendor cert: shim's empty-key-database placeholder"
        cls = "c"
    out.append(("MokList", data, cls, note))

    if SHIM_MIRRORS_VENDOR_DBX and deauth:
        note = ("shimx64.efi .vendor_cert vendor_deauthorized, %d bytes, already a chain of "
                "EFI_SIGNATURE_LISTs, mirrored verbatim" % len(deauth))
        out.append(("MokListX", deauth, "a", note))
    else:
        data = esl(EFI_CERT_SHA256_GUID, SHIM_LOCK_GUID, b"\0" * 32)
        note = ("shim's empty-key-database placeholder: one EFI_SIGNATURE_LIST "
                "(EFI_CERT_SHA256_GUID, owner SHIM_LOCK_GUID) over 32 zero bytes. Ubuntu's "
                "shim 15.8-0ubuntu1 removes .addend/.addend_size from the MokListX entry, so "
                "the %d-byte vendor dbx in .vendor_cert is never mirrored" % len(deauth))
        out.append(("MokListX", data, "c", note))

    out.append(("MokListTrusted", b"\x01", "c",
                "MOK_VARIABLE_INVERSE: no MokListTrusted variable in NVRAM, so shim mirrors "
                "the single byte 0x01"))
    return out


# ---------------------------------------------------------------------------
# grub script: lexer
# ---------------------------------------------------------------------------

class GrubError(Exception):
    pass


class Unsupported(GrubError):
    pass


class Tok(object):
    __slots__ = ("kind", "segs", "text", "start", "end", "line")

    def __init__(self, kind, segs, text, start, end, line):
        self.kind = kind
        self.segs = segs
        self.text = text
        self.start = start
        self.end = end
        self.line = line

    def __repr__(self):
        return "Tok(%s,%r,line=%d)" % (self.kind, self.text, self.line)


VARCHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


def _read_var(src, i):
    """src[i] == '$'. Returns (name, next index)."""
    n = len(src)
    i += 1
    if i < n and src[i] == "{":
        j = src.index("}", i)
        return src[i + 1:j], j + 1
    if i < n and src[i] in "?*@#":
        return src[i], i + 1
    j = i
    while j < n and src[j] in VARCHARS:
        j += 1
    if j == i:
        return None, i          # a bare '$'
    return src[i:j], j


def _lex_word(src, i):
    """Segments of one word. ('lit', text) is literal, ('var', name) is an
    unquoted expansion (which grub splits on blanks), ('qvar', name) is one
    inside double quotes (which it does not)."""
    n = len(src)
    segs = []
    buf = []

    def flush():
        if buf:
            segs.append(("lit", "".join(buf)))
            del buf[:]

    while i < n:
        c = src[i]
        if c in " \t\n;":
            break
        if c == "'":
            i += 1
            j = src.index("'", i)
            buf.append(src[i:j])
            i = j + 1
            continue
        if c == '"':
            i += 1
            while i < n and src[i] != '"':
                if src[i] == "\\" and i + 1 < n and src[i + 1] in '"\\$`':
                    buf.append(src[i + 1])
                    i += 2
                    continue
                if src[i] == "$":
                    name, i2 = _read_var(src, i)
                    if name is None:
                        buf.append("$")
                        i = i2
                        continue
                    flush()
                    segs.append(("qvar", name))
                    i = i2
                    continue
                buf.append(src[i])
                i += 1
            if i >= n:
                raise GrubError("unterminated double quote")
            i += 1
            continue
        if c == "\\":
            if i + 1 >= n:
                raise GrubError("trailing backslash")
            if src[i + 1] == "\n":
                i += 2
                continue
            buf.append(src[i + 1])
            i += 2
            continue
        if c == "$":
            name, i2 = _read_var(src, i)
            if name is None:
                buf.append("$")
                i = i2
                continue
            flush()
            segs.append(("var", name))
            i = i2
            continue
        buf.append(c)
        i += 1
    flush()
    return segs, i


def lex(src):
    toks = []
    i = 0
    n = len(src)
    linestarts = [0] + [k + 1 for k, ch in enumerate(src) if ch == "\n"]

    def lineof(pos):
        lo, hi = 0, len(linestarts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if linestarts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    while i < n:
        c = src[i]
        if c in " \t":
            i += 1
            continue
        if c == "\\" and i + 1 < n and src[i + 1] == "\n":
            i += 2
            continue
        if c == "#":
            while i < n and src[i] != "\n":
                i += 1
            continue
        if c == "\n":
            toks.append(Tok("nl", None, "\n", i, i + 1, lineof(i)))
            i += 1
            continue
        if c == ";":
            toks.append(Tok("semi", None, ";", i, i + 1, lineof(i)))
            i += 1
            continue
        if c in "{}" and (i + 1 >= n or src[i + 1] in " \t\n;"):
            toks.append(Tok("lbrace" if c == "{" else "rbrace", None, c,
                            i, i + 1, lineof(i)))
            i += 1
            continue
        start = i
        segs, i = _lex_word(src, i)
        toks.append(Tok("word", segs, src[start:i], start, i, lineof(start)))
    toks.append(Tok("eof", None, "", n, n, lineof(max(0, n - 1))))
    return toks


# ---------------------------------------------------------------------------
# grub script: parser
# ---------------------------------------------------------------------------

class Simple(object):
    def __init__(self, words, block, cfg, line):
        self.words = words
        self.block = block          # (raw source text, body nodes) or None
        self.cfg = cfg
        self.line = line


class If(object):
    def __init__(self, clauses, els, cfg, line):
        self.clauses = clauses      # [(cond nodes, body nodes)]
        self.els = els
        self.cfg = cfg
        self.line = line


class FuncDef(object):
    def __init__(self, name, body, cfg, line):
        self.name = name
        self.body = body
        self.cfg = cfg
        self.line = line


UNSUPPORTED_KEYWORDS = {"while", "until", "for", "case", "esac", "select", "do", "done"}


class Parser(object):
    def __init__(self, src, cfg):
        self.src = src
        self.cfg = cfg
        self.toks = lex(src)
        self.i = 0

    def peek(self):
        return self.toks[self.i]

    def parse_all(self):
        nodes = self.parse_list(set())
        if self.peek().kind != "eof":
            t = self.peek()
            raise GrubError("%s:%d: unexpected %r" % (self.cfg, t.line, t.text))
        return nodes

    def parse_list(self, terminators):
        nodes = []
        while True:
            t = self.peek()
            while t.kind in ("nl", "semi"):
                self.i += 1
                t = self.peek()
            if t.kind in ("eof", "rbrace"):
                return nodes
            if t.kind == "word" and t.text in terminators:
                return nodes
            nodes.append(self.parse_command())

    def parse_command(self):
        t = self.peek()
        if t.kind == "word" and t.text in UNSUPPORTED_KEYWORDS:
            raise Unsupported("%s:%d: grub-script keyword %r is not modelled"
                              % (self.cfg, t.line, t.text))
        if t.kind == "word" and t.text == "if":
            return self.parse_if()
        if t.kind == "word" and t.text == "function":
            return self.parse_function()
        return self.parse_simple()

    def parse_if(self):
        t = self.peek()
        self.i += 1
        clauses = []
        while True:
            cond = self.parse_list({"then"})
            if self.peek().text != "then":
                raise GrubError("%s:%d: expected 'then'" % (self.cfg, self.peek().line))
            self.i += 1
            body = self.parse_list({"elif", "else", "fi"})
            clauses.append((cond, body))
            if self.peek().text == "elif":
                self.i += 1
                continue
            break
        els = None
        if self.peek().text == "else":
            self.i += 1
            els = self.parse_list({"fi"})
        if self.peek().text != "fi":
            raise GrubError("%s:%d: expected 'fi'" % (self.cfg, self.peek().line))
        self.i += 1
        return If(clauses, els, self.cfg, t.line)

    def parse_function(self):
        t = self.peek()
        self.i += 1
        name = self.peek()
        if name.kind != "word":
            raise GrubError("%s:%d: expected a function name" % (self.cfg, t.line))
        self.i += 1
        if self.peek().kind != "lbrace":
            raise GrubError("%s:%d: expected '{'" % (self.cfg, t.line))
        self.i += 1
        body = self.parse_list(set())
        if self.peek().kind != "rbrace":
            raise GrubError("%s:%d: expected '}'" % (self.cfg, t.line))
        self.i += 1
        return FuncDef(name.text, body, self.cfg, t.line)

    def parse_simple(self):
        t = self.peek()
        words = []
        while self.peek().kind == "word":
            words.append(self.peek())
            self.i += 1
        block = None
        if self.peek().kind == "lbrace":
            lb = self.peek()
            self.i += 1
            body = self.parse_list(set())
            if self.peek().kind != "rbrace":
                raise GrubError("%s:%d: expected '}'" % (self.cfg, self.peek().line))
            rb = self.peek()
            self.i += 1
            # grub passes a block to menuentry as one argument holding the raw
            # source from '{' to the matching '}' inclusive, unexpanded.
            block = (self.src[lb.start:rb.end], body)
        if not words and block is None:
            raise GrubError("%s:%d: empty command" % (self.cfg, t.line))
        return Simple(words, block, self.cfg, t.line)


# ---------------------------------------------------------------------------
# The records we predict
# ---------------------------------------------------------------------------

class Rec(object):
    def __init__(self, event, digest, cls, desc, note):
        self.event = event          # bytes, exactly as they appear in the log
        self.digest = digest
        self.cls = cls
        self.desc = desc
        self.note = note


class MenuEntry(object):
    def __init__(self, kind, title, ident, args, body, cfg, line):
        self.kind = kind            # 'menuentry' or 'submenu'
        self.title = title
        self.ident = ident
        self.args = args            # positional args, what setparams gets
        self.body = body
        self.cfg = cfg
        self.line = line


NOOP_COMMANDS = {
    "echo", "serial", "terminal_input", "terminal_output", "terminfo",
    "loadfont", "background_color", "background_image", "play", "sleep",
    "gfxpayload", "set_gfxpayload", "export_env", "normal", "clear",
    "savedefault", "true",
}

UNARY_FILE_TESTS = {"-e", "-f", "-d", "-s", "-r"}
UNARY_STR_TESTS = {"-n", "-z"}
BINARY_TESTS = {"=", "==", "!=", "<", ">", "-eq", "-ne", "-lt", "-le", "-gt", "-ge"}


class Grub(object):
    """Just enough of grub's normal mode to reproduce what it measures."""

    def __init__(self, image, disk, esp_part, efi_dir, notes):
        self.image = image
        self.disk = disk
        self.esp_part = esp_part
        self.efi_dir = efi_dir.rstrip("/")
        self.notes = notes
        self.recs = []
        self.env = dict(GRUB_BUILTIN_ENV)
        self.params = []                  # $1, $2, ... inside a function body
        self.funcs = {}
        self.status = 0
        self.builtin_mods = set()
        self.loaded_mods = set()
        self.prefix_hook = False

    # -- records ---------------------------------------------------------

    def rec(self, event, data, cls, desc, note):
        self.recs.append(Rec(event, sha384(data), cls, desc, note))

    def emit_cmd(self, argv, cfg, line):
        s = " ".join(argv)
        b = s.encode("latin-1")
        self.rec(b"grub_cmd: " + b + b"\0", b, "b", "grub_cmd: " + s,
                 "%s line %d" % (cfg, line))

    def emit_file(self, shown, part, path, why):
        data = self.image.read(part, path)
        if data is None:
            raise GrubError("%s: not present in the image (partition %d, %s)"
                            % (shown, part, path))
        note = "%s in %s, %d bytes; %s" % (path, self.image.where(part), len(data), why)
        self.rec(shown.encode("latin-1") + b"\0", data, "a", shown, note)
        return data

    # -- environment -----------------------------------------------------

    def setvar(self, k, v):
        self.env[k] = v
        if k == "prefix" and self.prefix_hook:
            self.read_lists(v)

    def read_lists(self, prefix):
        for name in PREFIX_LISTS:
            shown = "%s/%s/%s" % (prefix, GRUB_MODULE_SUBDIR, name)
            part, path = self.resolve(shown)
            if self.image.stat(part, path):
                self.emit_file(shown, part, path,
                               "read by normal.mod's $prefix hook (read_lists)")

    # -- paths -----------------------------------------------------------

    def resolve(self, spec):
        """'(hd0,gpt16)/grub/grub.cfg' or '/vmlinuz' -> (partition, path)."""
        if spec.startswith("("):
            j = spec.index(")")
            dev = spec[1:j]
            path = spec[j + 1:]
        else:
            dev = self.env.get("root", "")
            path = spec
        m = re.match(r"^[^,]+,(?:gpt|msdos|part)?(\d+)$", dev)
        if not m:
            raise Unsupported("cannot resolve grub device %r" % dev)
        return int(m.group(1)), path or "/"

    # -- expansion -------------------------------------------------------

    def getvar(self, name):
        """Positional parameters live beside the environment, as in grub."""
        if name.isdigit():
            k = int(name)
            return self.params[k - 1] if 1 <= k <= len(self.params) else ""
        if name == "#":
            return str(len(self.params))
        if name in ("@", "*"):
            return " ".join(self.params)
        return self.env.get(name, "")

    def expand(self, tok):
        args = [""]
        for kind, text in tok.segs:
            if kind == "lit":
                args[-1] += text
            elif kind == "qvar":
                args[-1] += self.getvar(text)
            else:
                v = self.getvar(text)
                if v == "":
                    continue
                pieces = re.split(r"[ \t]+", v)
                args[-1] += pieces[0]
                for p in pieces[1:]:
                    args.append(p)
        return args

    def argv_of(self, node):
        argv = []
        for w in node.words:
            argv.extend(self.expand(w))
        if node.block is not None:
            argv.append(node.block[0])
        return argv

    # -- test ------------------------------------------------------------

    def file_test(self, op, arg):
        part, path = self.resolve(arg)
        if op == "-s":
            st = self.image.stat(part, path)
            if not st or st[0] != "file":
                return False
            data = self.emit_file(arg, part, path,
                                  "opened by the grub `[ -s ]` test, which measures it")
            return len(data) > 0
        st = self.image.stat(part, path)
        if st is None:
            return False
        if op == "-d":
            return st[0] == "dir"
        if op in ("-f", "-r"):
            return st[0] == "file"
        return True                      # -e

    def test_primary(self, a, i):
        if i >= len(a):
            raise GrubError("test: ran off the end")
        if i + 2 < len(a) and a[i + 1] in BINARY_TESTS:
            l, op, r = a[i], a[i + 1], a[i + 2]
            if op in ("=", "=="):
                v = l == r
            elif op == "!=":
                v = l != r
            elif op == "<":
                v = l < r
            elif op == ">":
                v = l > r
            else:
                try:
                    li, ri = int(l), int(r)
                except ValueError:
                    raise GrubError("test: %r %s %r is not numeric" % (l, op, r))
                v = {"-eq": li == ri, "-ne": li != ri, "-lt": li < ri,
                     "-le": li <= ri, "-gt": li > ri, "-ge": li >= ri}[op]
            return v, i + 3
        if a[i] in UNARY_STR_TESTS and i + 1 < len(a):
            v = (a[i + 1] != "") if a[i] == "-n" else (a[i + 1] == "")
            return v, i + 2
        if a[i] in UNARY_FILE_TESTS and i + 1 < len(a):
            return self.file_test(a[i], a[i + 1]), i + 2
        if a[i].startswith("-") and len(a[i]) == 2 and i + 1 < len(a):
            raise Unsupported("test operator %r is not modelled" % a[i])
        return a[i] != "", i + 1

    def test_not(self, a, i):
        if i < len(a) and a[i] == "!":
            v, i = self.test_not(a, i + 1)
            return (not v), i
        return self.test_primary(a, i)

    def test_and(self, a, i):
        v, i = self.test_not(a, i)
        while i < len(a) and a[i] == "-a":
            r, i = self.test_not(a, i + 1)
            v = v and r
        return v, i

    def test_or(self, a, i):
        v, i = self.test_and(a, i)
        while i < len(a) and a[i] == "-o":
            r, i = self.test_and(a, i + 1)
            v = v or r
        return v, i

    def eval_test(self, a):
        v, i = self.test_or(a, 0)
        if i != len(a):
            raise Unsupported("test: cannot parse %r" % (a,))
        return v

    # -- execution -------------------------------------------------------

    def run(self, nodes):
        st = 0
        for node in nodes:
            st = self.run_node(node)
        return st

    def run_node(self, node):
        if isinstance(node, FuncDef):
            self.funcs[node.name] = node.body
            return 0                      # definitions are never measured
        if isinstance(node, If):
            for cond, body in node.clauses:
                if self.run(cond) == 0:
                    return self.run(body)
            if node.els is not None:
                return self.run(node.els)
            return 0
        return self.run_simple(node)

    def run_simple(self, node):
        argv = self.argv_of(node)
        if not argv:
            return self.status
        self.emit_cmd(argv, node.cfg, node.line)
        self.status = self.dispatch(argv, node)
        self.env["?"] = str(self.status)
        return self.status

    def dispatch(self, argv, node):
        name, args = argv[0], argv[1:]

        if name not in self.funcs and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", name):
            k, v = name.split("=", 1)
            self.setvar(k, v)
            return 0

        if name in self.funcs:
            saved = self.params
            self.params = args
            try:
                return self.run(self.funcs[name])
            finally:
                self.params = saved

        if name == "set":
            for a in args:
                if "=" in a:
                    k, v = a.split("=", 1)
                    self.setvar(k, v)
            return 0
        if name == "unset":
            for a in args:
                self.env.pop(a, None)
            return 0
        if name in ("export", "insmod_noop"):
            return 0
        if name == "false":
            return 1
        if name in ("[", "test"):
            a = list(args)
            if name == "[":
                if not a or a[-1] != "]":
                    raise GrubError("`[` without a closing `]`")
                a = a[:-1]
            return 0 if self.eval_test(a) else 1
        if name == "insmod":
            return self.cmd_insmod(args)
        if name in ("search", "search.fs_uuid", "search.file", "search.fs_label"):
            return self.cmd_search(name, args)
        if name in ("configfile", "source", "."):
            return self.cmd_configfile(name, args)
        if name == "load_env":
            return self.cmd_load_env(args)
        if name == "save_env":
            return 0                      # written, not read; not measured
        if name == "setparams":
            self.params = args
            return 0
        if name in ("linux", "linux16", "linuxefi"):
            return self.cmd_linux(args)
        if name in ("initrd", "initrd16", "initrdefi"):
            return self.cmd_initrd(args)
        if name == "fwsetup":
            if "--is-supported" in args:
                return FWSETUP_IS_SUPPORTED
            raise Unsupported("fwsetup without --is-supported would leave the OS boot path")
        if name in ("menuentry", "submenu"):
            return self.cmd_menuentry(name, args, node)
        if name in NOOP_COMMANDS:
            return 0
        raise Unsupported("grub command %r is not modelled (%s line %d)"
                          % (name, node.cfg, node.line))

    def cmd_insmod(self, args):
        if not args:
            return 1
        name = args[0]
        if name in self.builtin_mods or name in self.loaded_mods:
            return 0                      # already in the image: nothing is read
        prefix = self.env.get("prefix", "")
        shown = "%s/%s/%s.mod" % (prefix, GRUB_MODULE_SUBDIR, name)
        part, path = self.resolve(shown)
        if not self.image.stat(part, path):
            raise GrubError("insmod %s: %s is not in the image" % (name, shown))
        data = self.emit_file(shown, part, path, "loaded by `insmod %s`" % name)
        self.loaded_mods.add(name)
        for dep in module_deps(data):
            self.cmd_insmod([dep])
        return 0

    def cmd_search(self, name, args):
        var = "root"
        key = None
        mode = "fs_uuid" if name == "search.fs_uuid" else (
            "file" if name == "search.file" else (
                "label" if name == "search.fs_label" else None))
        if name.startswith("search."):
            rest = [a for a in args if not a.startswith("--")]
            if not rest:
                return 1
            key = rest[0]
            if len(rest) > 1:
                var = rest[1]
        else:
            i = 0
            while i < len(args):
                a = args[i]
                if a in ("--fs-uuid", "-u"):
                    mode = "fs_uuid"
                elif a in ("--label", "-l"):
                    mode = "label"
                elif a in ("--file", "-f"):
                    mode = "file"
                elif a.startswith("--set="):
                    var = a.split("=", 1)[1]
                elif a == "--set":
                    i += 1
                    var = args[i]
                elif a.startswith("--hint") or a in ("--no-floppy", "-n"):
                    pass
                elif a.startswith("-"):
                    raise Unsupported("search option %r is not modelled" % a)
                else:
                    key = a
                i += 1
        if mode != "fs_uuid":
            raise Unsupported("search by %s is not modelled" % mode)
        part = self.image.fs_uuid_partition(key)
        if part is None:
            raise GrubError("search --fs-uuid %s: no partition in the image has that "
                            "filesystem UUID" % key)
        self.setvar(var, "%s,gpt%d" % (self.disk, part))
        return 0

    def cmd_configfile(self, name, args):
        if not args:
            return 1
        shown = args[0]
        part, path = self.resolve(shown)
        data = self.emit_file(shown, part, path, "read by `%s`" % name)
        old_dir = self.env.get("config_directory")
        self.env["config_directory"] = shown.rsplit("/", 1)[0]
        if name == "configfile":
            menu = self.run_config_text(data, shown)
            self.boot_default(menu)
        else:
            self.run_config_text(data, shown, menu=self.menu)
        if old_dir is None:
            self.env.pop("config_directory", None)
        else:
            self.env["config_directory"] = old_dir
        return 0

    def cmd_load_env(self, args):
        f = None
        i = 0
        while i < len(args):
            if args[i] in ("-f", "--file"):
                i += 1
                f = args[i]
            elif args[i].startswith("--skip-sig"):
                pass
            i += 1
        shown = f or ("%s/grubenv" % self.env.get("prefix", ""))
        part, path = self.resolve(shown)
        if not self.image.stat(part, path):
            return 1
        data = self.emit_file(shown, part, path, "read by `load_env`")
        for line in data.decode("latin-1").split("\n"):
            line = line.strip("\x00")
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                self.setvar(k, v)
        return 0

    def cmd_linux(self, args):
        if not args:
            return 1
        shown = args[0]
        part, path = self.resolve(shown)
        self.emit_file(shown, part, path, "the kernel, opened by `linux`")
        cmdline = " ".join(args)
        b = cmdline.encode("latin-1")
        self.rec(b"kernel_cmdline: " + b + b"\0", b, "b",
                 "kernel_cmdline: " + cmdline,
                 "the argv of the `linux` command, measured again by grub's "
                 "kernel-command-line verifier")
        return 0

    def cmd_initrd(self, args):
        for shown in args:
            part, path = self.resolve(shown)
            self.emit_file(shown, part, path, "an initrd, opened by `initrd`")
        return 0

    def cmd_menuentry(self, name, args, node):
        if node.block is None:
            raise GrubError("%s without a block at %s line %d"
                            % (name, node.cfg, node.line))
        opts = args[:-1]                 # the block text is the last argument
        positional = []
        ident = None
        i = 0
        while i < len(opts):
            a = opts[i]
            if a in ("--class", "--users", "--hotkey"):
                i += 2
                continue
            if a == "--id":
                ident = opts[i + 1] if i + 1 < len(opts) else None
                i += 2
                continue
            if a.startswith("--"):
                i += 1
                continue
            positional.append(a)
            i += 1
        self.menu.append(MenuEntry(name, positional[0] if positional else "",
                                   ident, positional, node.block[1],
                                   node.cfg, node.line))
        return 0

    # -- configs and the menu -------------------------------------------

    def run_config_text(self, data, shown, menu=None):
        src = data.decode("latin-1")
        nodes = Parser(src, shown).parse_all()
        saved = getattr(self, "menu", None)
        self.menu = menu if menu is not None else []
        try:
            self.run(nodes)
            return self.menu
        finally:
            self.menu = saved

    def boot_default(self, menu):
        if not menu:
            return
        want = self.env.get("default", "0")
        entry = None
        if re.match(r"^\d+$", want):
            k = int(want)
            if 0 <= k < len(menu):
                entry = menu[k]
        if entry is None:
            for e in menu:
                if e.ident == want or e.title == want:
                    entry = e
                    break
        if entry is None:
            raise GrubError("default menu entry %r not found" % want)
        if entry.kind == "submenu":
            raise Unsupported("the default entry is a submenu; descending into one "
                              "is not modelled")
        # grub turns a menu entry into a function whose body is prefixed with
        # `setparams <title>`; that synthetic line is measured like any other.
        self.emit_cmd(["setparams"] + entry.args, entry.cfg, entry.line)
        self.run(entry.body)

    # -- the whole boot --------------------------------------------------

    def boot(self):
        esp = self.esp_part
        shim = self.image.read(esp, "%s/shimx64.efi" % self.efi_dir)
        if shim is None:
            raise GrubError("no shimx64.efi at %s on partition %d"
                            % (self.efi_dir, esp))
        for evname, data, cls, note in shim_mok_records(shim):
            self.rec(evname.encode("latin-1") + b"\0", data, cls, evname, note)

        grubefi = self.image.read(esp, "%s/grubx64.efi" % self.efi_dir)
        if grubefi is None:
            raise GrubError("no grubx64.efi at %s on partition %d"
                            % (self.efi_dir, esp))
        self.builtin_mods, embedded_prefix = grub_image_info(grubefi)
        if embedded_prefix is None:
            raise GrubError("grubx64.efi carries no embedded prefix module")
        self.notes.append("grubx64.efi: %d modules built in, embedded prefix %r"
                          % (len(self.builtin_mods), embedded_prefix))

        self.setvar("root", "%s,gpt%d" % (self.disk, esp))
        self.setvar("prefix", "(%s,gpt%d)%s" % (self.disk, esp, embedded_prefix))
        self.setvar("cmdpath", self.env["prefix"])
        # From here on, writes to $prefix pull in the four module lists, as
        # normal.mod's variable hook does once it is running.
        self.prefix_hook = True

        shown = "%s/grub.cfg" % self.env["prefix"]
        part, path = self.resolve(shown)
        data = None
        for _ in range(BOOT_CONFIG_MEASUREMENTS):
            data = self.emit_file(shown, part, path,
                                  "the boot config, opened by `normal`")
        self.env["config_directory"] = shown.rsplit("/", 1)[0]
        menu = self.run_config_text(data, shown)
        self.boot_default(menu)


# ---------------------------------------------------------------------------
# Comparing against a recorded boot
# ---------------------------------------------------------------------------

def load_ccel_parser():
    here = os.path.dirname(os.path.abspath(__file__))
    p = os.path.join(here, "replay-ccel.py")
    spec = importlib.util.spec_from_file_location("replay_ccel", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def ccel_rtmr2_records(path):
    mod = load_ccel_parser()
    with open(path, "rb") as f:
        blob = f.read()
    out = []
    for pcr, etype, digests, event in mod.parse(blob):
        if pcr == 3 and 0x000C in digests:
            out.append((digests[0x000C], event))
    return out


def flat(s, width=None):
    """One line, so a measured menuentry block does not break the listing."""
    s = s.replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t")
    if width and len(s) > width:
        s = s[:width - 3] + "..."
    return s


def show_event(ev):
    return flat(ev.rstrip(b"\0").decode("latin-1"))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Predict RTMR2 for a Google Cloud TDX VM from a disk image.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--raw", metavar="DISK.RAW",
                     help="a GPT disk image; partitions are read with debugfs/mtools")
    src.add_argument("--tree", metavar="DIR",
                     help="a guest filesystem unpacked as DIR/boot/... ")
    ap.add_argument("--esp-part", type=int, default=None,
                    help="partition number of the EFI system partition "
                         "(default: found in the GPT; required with --tree)")
    ap.add_argument("--boot-part", type=int, default=None,
                    help="partition number of /boot (required with --tree)")
    ap.add_argument("--root-part", type=int, default=1,
                    help="partition number of / (--tree only, default 1)")
    ap.add_argument("--fs-uuid", action="append", default=[], metavar="N=UUID",
                    help="--tree only: filesystem UUID of partition N, so that "
                         "`search --fs-uuid` resolves the way it would on the disk")
    ap.add_argument("--efi-dir", default=DEFAULT_EFI_DIR,
                    help="directory on the ESP the firmware boots from "
                         "(default %s)" % DEFAULT_EFI_DIR)
    ap.add_argument("--disk", default=DEFAULT_DISK,
                    help="what grub calls the boot disk (default %s)" % DEFAULT_DISK)
    ap.add_argument("--compare-ccel", metavar="FILE",
                    help="a CCEL event log from a real boot, to check against")
    ap.add_argument("--compare-quote", metavar="FILE",
                    help="a TDX quote from a real boot, to check RTMR2 against")
    ap.add_argument("--table", action="store_true",
                    help="print only the classification table")
    args = ap.parse_args()

    notes = []
    if args.raw:
        image = RawImage(args.raw)
        esp = args.esp_part
        if esp is None:
            for n in image.partitions():
                if image.parts[n]["type"] == ESP_TYPE_GUID:
                    esp = n
                    break
        if esp is None:
            print("no EFI system partition in the GPT; pass --esp-part")
            return 2
        source = args.raw
    else:
        if args.esp_part is None or args.boot_part is None:
            print("--tree needs --esp-part and --boot-part")
            return 2
        mapping = {
            args.root_part: args.tree,
            args.boot_part: os.path.join(args.tree, "boot"),
            args.esp_part: os.path.join(args.tree, "boot", "efi"),
        }
        uuidmap = {}
        for spec in args.fs_uuid:
            n, u = spec.split("=", 1)
            uuidmap[u.lower()] = int(n)
        if not uuidmap:
            notes.append("NOTE: no --fs-uuid given, so `search --fs-uuid` resolves to "
                         "partition %d (--boot-part) whatever UUID it is asked for"
                         % args.boot_part)
        image = TreeImage(args.tree, mapping, uuidmap, args.boot_part)
        esp = args.esp_part
        source = args.tree

    grub = Grub(image, args.disk, esp, args.efi_dir, notes)
    grub.boot()
    recs = grub.recs

    rtmr2 = bytes(48)
    for r in recs:
        rtmr2 = hashlib.sha384(rtmr2 + r.digest).digest()

    want = None
    if args.compare_ccel:
        want = ccel_rtmr2_records(args.compare_ccel)

    if args.table:
        print("%-4s %-3s %s" % ("idx", "cls", "digest / description / provenance"))
        for i, r in enumerate(recs):
            print("%-4d %-3s %s" % (i, r.cls, r.digest.hex()))
            print("%-9s %s" % ("", flat(r.desc, 240)))
            print("%-9s %s" % ("", flat(r.note)))
        return 0

    print("predict-rtmr2: RTMR2 computed from the image, nothing booted")
    print("source              : %s" % source)
    print("partitions          : " + ", ".join(
        image.where(n) for n in image.partitions()))
    print("ESP / EFI directory : partition %d, %s" % (esp, args.efi_dir))
    for n in notes:
        print("%-20s: %s" % ("note", n))
    print("model inputs        : grub_platform=%s, feature_menuentry_id=%s, "
          "feature_all_video_module=%s, feature_timeout_style=%s"
          % (GRUB_BUILTIN_ENV["grub_platform"],
             GRUB_BUILTIN_ENV["feature_menuentry_id"],
             GRUB_BUILTIN_ENV["feature_all_video_module"],
             GRUB_BUILTIN_ENV["feature_timeout_style"]))
    print("                      boot config measured %d times, fwsetup --is-supported=%d,"
          % (BOOT_CONFIG_MEASUREMENTS, FWSETUP_IS_SUPPORTED))
    print("                      shim mirrors vendor dbx into MokListX: %s"
          % SHIM_MIRRORS_VENDOR_DBX)
    print("records predicted   : %d" % len(recs))
    if want is not None:
        print("records recorded    : %d (%s)" % (len(want), args.compare_ccel))
    print()

    first_bad = None
    for i, r in enumerate(recs):
        st = ""
        if want is not None:
            if i < len(want):
                ok = (want[i][0] == r.digest and want[i][1] == r.event)
            else:
                ok = False
            st = "OK " if ok else "DIFF"
            if not ok and first_bad is None:
                first_bad = i
        print("%3d %s %s %s  %s" % (i, st, r.cls, r.digest.hex(), flat(r.desc, 150)))
        print("        %s<- %s" % ("" if not st else "     ", flat(r.note)))
        if first_bad is not None and first_bad == i:
            break

    print()
    if first_bad is not None:
        i = first_bad
        print("first divergence at record %d" % i)
        print("  predicted digest : %s" % recs[i].digest.hex())
        print("  recorded  digest : %s" % (want[i][0].hex() if i < len(want) else "(no such record)"))
        print("  predicted event  : %s" % show_event(recs[i].event))
        print("  recorded  event  : %s" % (show_event(want[i][1]) if i < len(want) else "(no such record)"))
        print()

    print("RTMR2 predicted     : %s" % rtmr2.hex())
    quote_ok = None
    if args.compare_quote:
        with open(args.compare_quote, "rb") as f:
            q = f.read()
        recorded = q[QUOTE_BODY + RTMR2_AT:QUOTE_BODY + RTMR2_AT + 48]
        quote_ok = recorded == rtmr2
        print("RTMR2 in quote      : %s (%s)" % (recorded.hex(), args.compare_quote))
        print("RTMR2 comparison    : %s" % ("MATCH" if quote_ok else "MISMATCH"))

    print()
    bad = []
    if want is not None:
        if first_bad is not None:
            bad.append("record %d" % first_bad)
        elif len(want) != len(recs):
            bad.append("record count %d predicted vs %d recorded" % (len(recs), len(want)))
    if quote_ok is False:
        bad.append("RTMR2")
    if want is None and quote_ok is None:
        print("RESULT: %d records, RTMR2 %s (nothing to compare against)"
              % (len(recs), rtmr2.hex()))
        return 0
    if bad:
        print("RESULT: MISMATCH at %s" % ", ".join(bad))
        return 1
    print("RESULT: MATCH")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (GrubError, ImageError) as e:
        print("predict-rtmr2: %s" % e)
        sys.exit(3)
