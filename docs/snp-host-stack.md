# SNP-capable host stack

Ticket 01. How to build a hypervisor and guest firmware that can launch a confidential
guest on this host, how to confirm the guest is genuinely confidential, and how to read
evidence out of it by hand through the platform's report interface.

Vocabulary is `CONTEXT.md`. Decisions this builds on are `docs/adr/0001`–`0004`.

Everything here was executed on the host it describes. Scripts are in `docs/snp/`;
captured output is in `docs/snp/evidence/`.

---

## Result, in one paragraph

The host kernel needed no change. Its gap was userspace: the distro QEMU (8.2.2) offers
only a `sev-guest` object, so no confidential guest can be described to it at all, and the
distro ships no firmware image in the form an SNP launch needs. Building AMDESE's QEMU and
edk2 into a local prefix closes that gap, and a stock Ubuntu 24.04 guest
now launches as an SEV-SNP guest, reports `SEV: Status: SEV SEV-ES SEV-SNP`, runs at VMPL0,
and yields a 1184-byte VCEK-signed attestation report through
`/sys/kernel/config/tsm/report/`. **The `auxblob` is empty, and no operator action on this
host can fill it** — see [The certificate chain is absent](#the-certificate-chain-is-absent),
which is the finding with consequences beyond this ticket.

---

## What was already there, and what was missing

Verified before building anything, so that the host kernel was ruled in or out on evidence
rather than assumption.

| | State |
|---|---|
| CPU | AMD EPYC 9354P (Genoa, family 0x19 model 0x11 step 1) |
| Host kernel | `6.11.0-rc3-snp-host-85ef1ac03941` |
| `kvm_amd` | `sev=Y sev_es=Y sev_snp=Y` |
| PSP firmware | `SEV-SNP API:1.55 build:39`, `SEV firmware update successful` |
| RMP table | reserved, `SEV-SNP: RMP table physical range [0xbf8d300000 - 0xc04d8fffff]` |
| IOMMU | `AMD-Vi: IOMMU SNP support enabled` |
| KVM | `kvm_amd: SEV-SNP enabled (ASIDs 1 - 509)` |
| Distro QEMU 8.2.2 | `-object help` lists `sev-guest` only — **no `sev-snp-guest`** |
| `/usr/share/OVMF` | split pflash pair only; **no unified `OVMF.fd`** — see below |

The decisive host-kernel check is unprivileged and takes a second — ask KVM directly which
VM types it supports, rather than inferring capability from a module parameter:

```
$ python3 - <<'EOF'
import fcntl, os
fd = os.open("/dev/kvm", os.O_RDWR)
print("VM types bitmask = 0x%x" % fcntl.ioctl(fd, 0xAE03, 235))  # KVM_CHECK_EXTENSION, KVM_CAP_VM_TYPES
EOF
VM types bitmask = 0x1f
```

Bit 4 is `KVM_X86_SNP_VM`. It is set, along with `KVM_CAP_GUEST_MEMFD`,
`KVM_CAP_MEMORY_ATTRIBUTES` and `KVM_CAP_USER_MEMORY2`. **No host kernel change is
required, and none was made.** Nothing in this procedure touches the bootloader, installs
a kernel, or reboots the machine.

### The firmware gap is packaging, not missing SNP support

Worth stating precisely, because "the distro OVMF has no SNP support" is the obvious guess
and it is wrong. Ubuntu's images do carry it — both the OVMF SEV-SNP metadata GUID
(`dc886566-984a-4798-a75e-5585a7bf67cc`) and the SEV-ES reset block GUID
(`00f771de-1a7e-4fcb-890e-68c77e2fb44e`) are present in `OVMF_CODE_4M.fd` and its secboot
variant, exactly as they are in the image built here.

What the distro does not ship is a *unified* firmware image. An SNP guest has no persistent
variable store, so it is booted with a single image via `-bios` rather than the
`OVMF_CODE` + `OVMF_VARS` pflash pair. `/usr/share/OVMF` contains only that pair, and
handing QEMU the code half directly fails:

```
$ qemu-system-x86_64 ... -bios /usr/share/OVMF/OVMF_CODE_4M.fd -object sev-snp-guest,...
qemu: could not load PC BIOS '/usr/share/OVMF/OVMF_CODE_4M.fd'
```

So the firmware still has to be built, but for packaging reasons. The blocker that actually
stops everything is the missing `sev-snp-guest` object in the distro QEMU.

---

## The coupled set, and where it came from

The ticket asks for hypervisor, firmware, host kernel and guest kernel built as one
coupled set from the vendor's own stack, because mismatches between them surface as opaque
launch failures. Three of the four were built here; the fourth was already installed from
the same vendor stack.

| Component | Source | Commit | Version |
|---|---|---|---|
| Build scripts | `github.com/AMDESE/AMDSEV` `main` | `6e0ef356e2d21513882abe4379a3fbadf8e51d62` | — |
| Hypervisor | `github.com/AMDESE/qemu` `snp-latest` | `afe54d06015d3c90b4b745e468ee3317c5513de8` | QEMU 10.0.0 |
| Guest firmware | `github.com/tianocore/edk2` tag `edk2-stable202502` | `fbe0805b2091393406952e84724188f8c1941837` | — |
| Guest kernel | `github.com/AMDESE/linux` `snp-guest-latest` | `038d61fd642278bab63ee8ef722c50d10ab01e8f` | 6.16.0-snp-guest-038d61fd6422 |
| Host kernel | `github.com/AMDESE/linux` `snp-host-latest` | `85ef1ac039412c99a2de119f977a3cab6079533d` | 6.11.0-rc3-snp-host-85ef1ac03941 |

The host kernel row is not something this procedure produced. It was already installed, and
its `LOCALVERSION` suffix is AMDSEV's own `-snp-host-<commit>` convention, which is what
identifies its provenance. The commit is dated 2024-08-19 and is the pairing the rest of
this set was tested against.

Hashes of the artifacts actually built, so a launch measurement computed later can be traced
to the firmware that produced it:

```
7e0821e2f3ab06cae67a2aadfaadba338f275fa4dada2ce506f646b8b3703de2  usr/local/bin/qemu-system-x86_64
8a417b9ec16707672407f545e6fe95520ebb2109eefe9bb2856c4639aa1bbb0c  usr/local/share/qemu/OVMF.fd
4b519144f1c5e17a22c4289fc6ec00e680869d549a2a9f7484590a1d4fe23cd6  usr/local/share/qemu/OVMF_CODE.fd
5d2ac383371b408398accee7ec27c8c09ea5b74a0de0ceea6513388b15be5d1e  usr/local/share/qemu/OVMF_VARS.fd
c3b443dbdafbaf3cb92d119482143a76876a752c7335a61faa917361d9724b75  guest-kernel/vmlinuz-snp-guest
```

`OVMF.fd` is the one that matters: it is the firmware passed as `-bios`, and it is the
first thing hashed into the launch measurement.

### Two deviations from AMDSEV's `build.sh`, and why

Both are recorded because a second operator will hit them.

**edk2 is pinned to a tag, not tracked on `master`.** AMDSEV's `stable-commits` sets
`OVMF_BRANCH="master"` while its own comment says the pairing is `edk2-stable202502`. edk2
master has since renamed the `GCC5` toolchain tag to `GCC`, which `common.sh` hardcodes, so
`./build.sh ovmf` fails with `[GCC5] not defined. No toolchain available for build!`.
`docs/snp/build-ovmf-pinned.sh` pins the tag AMDSEV names and autodetects the toolchain tag
either way. A pinned tag is also what the "record the exact commit" criterion actually
wants; a moving branch is not a pin.

**The privileged package installs in `common.sh` were removed rather than run.**
`build_install_qemu` and `build_install_ovmf` each begin with `sudo apt-get install`. Every
dependency they name (`uuid-dev`, `nasm`, `acpica-tools`, `libslirp-dev`) was already
present, so the lines were replaced with a no-op that records what was skipped. If a
dependency is missing on another host, install it deliberately rather than letting a build
script acquire root.

---

## Procedure

Prerequisites: `gcc`, `make`, `nasm`, `acpica-tools` (`iasl`), `uuid-dev`, `libslirp-dev`,
`libglib2.0-dev`, `libpixman-1-dev`, `python3-venv`, `cloud-image-utils`, `git`. Roughly
25 GB of disk and 30 minutes on 64 cores.

Set `STACK` to a working directory outside any tree you care about. Nothing below writes to
`/usr`, and nothing overwrites the distro QEMU or OVMF.

```bash
STACK=/path/to/host-stack
mkdir -p "$STACK" && cd "$STACK"
```

### 1. Get the vendor build scripts

```bash
git clone https://github.com/AMDESE/AMDSEV.git
git -C AMDSEV checkout 6e0ef356e2d21513882abe4379a3fbadf8e51d62
```

Remove the privileged package installs, having first confirmed the dependencies are present:

```bash
cd AMDSEV && cp common.sh common.sh.orig
python3 - <<'EOF'
import re
s = open('common.sh.orig').read()
s = re.sub(r'^(\s*)(sudo (?:apt-get|dnf) install .*)$',
           lambda m: '%s: "SKIPPED privileged package install: %s"' % (m.group(1), m.group(2)),
           s, flags=re.M)
open('common.sh', 'w').write(s)
EOF
cd ..
```

### 2. Build QEMU

```bash
cd AMDSEV
./build.sh --install "$STACK/usr/local" qemu
cd ..
"$STACK/usr/local/bin/qemu-system-x86_64" -object help | grep sev
```

The last command must list `sev-snp-guest`. If it lists only `sev-guest`, stop — nothing
downstream will work.

### 3. Build guest firmware

```bash
cp /path/to/docs/snp/build-ovmf-pinned.sh "$STACK/"
bash "$STACK/build-ovmf-pinned.sh"
```

Produces `usr/local/share/qemu/OVMF.fd`. If the edk2 tree was previously checked out at a
different revision, clean its submodules first — a stale `master` checkout makes the tag's
`git submodule update --init --recursive` fail:

```bash
git -C "$STACK/AMDSEV/ovmf" submodule deinit -f --all
git -C "$STACK/AMDSEV/ovmf" clean -xfd -e Build
```

### 4. Build the guest kernel

```bash
cd AMDSEV
mkdir -p linux/host          # makes common.sh skip a 6 GB copy of the guest tree
./build.sh --install "$STACK/usr/local" kernel guest
cd ..
```

The kernel itself builds; **`make bindeb-pkg` at the end will fail** with
`Unmet build dependencies: libdw-dev`. That is the Debian packaging step, not the kernel.
Packaging is not needed — install the kernel directly, which is also the shape ticket 06
wants:

```bash
K="$STACK/AMDSEV/linux/guest"
make -C "$K" -j"$(nproc)" modules_install \
     INSTALL_MOD_PATH="$STACK/guest-kernel/staging" INSTALL_MOD_STRIP=1
mkdir -p "$STACK/guest-kernel"
cp "$K/arch/x86/boot/bzImage" "$STACK/guest-kernel/vmlinuz-snp-guest"
tar czf "$STACK/guest-kernel/modules.tar.gz" -C "$STACK/guest-kernel/staging" lib/modules
cat "$K/include/config/kernel.release"     # 6.16.0-snp-guest-038d61fd6422
```

### 5. Prepare a stock guest

Deliberately stock. This ticket proves the evidence path works before a measured image
exists; the measured image is ticket 06.

```bash
mkdir -p "$STACK/images" "$STACK/guest"
curl -Lo "$STACK/images/noble.img" \
  https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
cp "$STACK/images/noble.img" "$STACK/guest/snp-stock.qcow2"
"$STACK/usr/local/bin/qemu-img" resize "$STACK/guest/snp-stock.qcow2" 20G

ssh-keygen -t ed25519 -N '' -C snp-ticket01 -f "$STACK/guest/id_snp"
cat > "$STACK/guest/user-data" <<EOF
#cloud-config
hostname: snp-stock
users:
  - name: snp
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: snp
    ssh_authorized_keys: [ "$(cat "$STACK/guest/id_snp.pub")" ]
ssh_pwauth: true
chpasswd: { expire: false }
EOF
printf 'instance-id: snp-stock-001\nlocal-hostname: snp-stock\n' > "$STACK/guest/meta-data"
cloud-localds "$STACK/guest/seed.iso" "$STACK/guest/user-data" "$STACK/guest/meta-data"
```

### 6. First boot, to install the guest kernel

Copy `docs/snp/launch-snp-guest.sh` and `docs/snp/gssh` into `$STACK`, then, **as root**:

```bash
bash "$STACK/launch-snp-guest.sh" -name snp-stock -mem 4096 -smp 4 -ssh-port 10022
```

The Ubuntu kernel boots SNP (`Memory Encryption Features active: AMD SEV SEV-ES SEV-SNP`)
but ships no `sev-guest` module, so it has no report interface. Install the vendor guest
kernel over ssh and build an initrd inside the guest:

```bash
V=6.16.0-snp-guest-038d61fd6422
bash "$STACK/gssh" --scp "$STACK/guest-kernel/modules.tar.gz" \
                        "$STACK/guest-kernel/vmlinuz-snp-guest" G:/tmp/
bash "$STACK/gssh" "sudo tar xzf /tmp/modules.tar.gz -C / && sudo depmod -a $V \
  && sudo cp /tmp/vmlinuz-snp-guest /boot/vmlinuz-$V && sudo update-initramfs -c -k $V"
bash "$STACK/gssh" --scp "G:/boot/initrd.img-$V" "$STACK/guest-kernel/"
bash "$STACK/gssh" 'sudo poweroff'
```

### 7. Launch the confidential guest

As root. Direct kernel boot, which is also what ticket 06 will measure:

```bash
V=6.16.0-snp-guest-038d61fd6422
bash "$STACK/launch-snp-guest.sh" -name snp-stock -mem 4096 -smp 4 -ssh-port 10022 \
  -kernel "$STACK/guest-kernel/vmlinuz-snp-guest" \
  -initrd "$STACK/guest-kernel/initrd.img-$V" \
  -append "root=LABEL=cloudimg-rootfs ro console=ttyS0 earlyprintk=serial"
```

The exact command line the script generated is in `docs/snp/evidence/qemu-cmdline.txt`. The
parts that make it a confidential guest:

```
-machine confidential-guest-support=sev0,vmport=off
-object memory-backend-memfd,id=ram1,size=4096M,share=true,prealloc=false
-machine memory-backend=ram1
-object sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=6
-bios .../OVMF.fd
```

`cbitpos` and `reduced-phys-bits` are read from CPUID `0x8000001F` EBX rather than
hardcoded. On this Genoa part that yields `cbitpos=51, reduced-phys-bits=6`. AMDSEV's own
`launch-qemu.sh` hardcodes `reduced-phys-bits=1`; the CPUID-derived 6 is what the hardware
reports and it boots, so it is what the script uses. `-reduced-phys-bits N` overrides it if
another part disagrees.

Policy `0x30000` is bit 16 (reserved, must be one) and bit 17 (SMT allowed). **Bit 19,
DEBUG, is deliberately not set.** A debug-enabled guest is not confidential — its memory is
readable by the host — and it would still produce a perfectly valid report. Verification
must reject it, which is user story 10.

---

## Confirming the guest is genuinely confidential

Four independent checks. The last one is the only one that does not take the platform's
word for it.

**1. The guest kernel says so.**

```
[    2.277879] SEV: Status: SEV SEV-ES SEV-SNP
[    2.260588] Memory Encryption Features active: AMD SEV SEV-ES SEV-SNP
[    2.631542] SEV: SNP running at VMPL0.
[    3.053596] SEV: SNP guest platform devices initialized.
```

**2. QEMU says so.** From the monitor socket:

```
(qemu) info sev
SEV type: sev-snp
state: running
build: 39
api version: 1.55
debug: off
SMT allowed: on
```

**3. The report is real.** A non-confidential VM cannot produce one at all. On the control
boot, `modprobe sev_guest` fails with `No such device` and `/dev/sev-guest` does not exist.
On the SNP boot the report interface returns 1184 bytes signed by the VCEK with
`DEBUG_ALLOWED: no` and `vmpl: 0`.

**4. The host cannot read guest memory — measured, with a control.**

A blocked attack is not evidence on its own, so this is run twice on the same disk, kernel,
initrd and RAM backing, differing only in whether `-object sev-snp-guest` is present. The
guest fills 1536 MiB of tmpfs with a 38-byte marker — 42,384,384 copies — and then root on
the host reads the guest's RAM backing directly out of `/proc/<qemu-pid>/fd/<memfd>`, with
no cooperation from the guest and no hypervisor API involved.

| | SEV-SNP on | Control: SNP off |
|---|---|---|
| Copies written into guest RAM | 42,384,384 | 42,384,384 |
| Copies visible to root on the host | **7** | **42,405,927** |
| Fraction visible | 0.000017% | 100.05% |
| Non-zero bytes in the host's 4 GiB view | 2.57% | 47.68% |
| `/dev/sev-guest` | present | absent |

The control is what makes this evidence: the method plainly finds the canary when the guest
is not confidential.

The SNP count is 7 rather than 0, and that is expected rather than a leak. Every byte the
guest sends out — the ssh command line carrying the marker text, console output — crosses
shared SWIOTLB bounce buffers, which are unencrypted by construction
(`software IO TLB: Memory encryption is active and system is using DMA bounce buffers`).
Seven copies is consistent with the marker text having crossed that path a handful of times
as ssh traffic; forty-two million copies would be the guest's memory itself. The seven were
not traced to specific buffers, so read them as a residue whose magnitude is accounted for,
not as an identified artefact. Reporting "occurrences > 0" as a failure, or expecting zero, would
both be wrong — which is why `host-read-guest-ram.py` takes the expected count and reports
a ratio.

Captured runs: `docs/snp/evidence/canary-snp.txt`, `docs/snp/evidence/canary-control.txt`.

---

## Reading evidence out by hand

Through the vendor-neutral report interface, not through any AMD-specific ioctl. The same
path yields a TDX quote on Intel; only the bytes returned are AMD-specific. That is the
seam `attest/tsm` will sit on.

```bash
sudo modprobe sev-guest
sudo mountpoint -q /sys/kernel/config || sudo mount -t configfs none /sys/kernel/config
D=/sys/kernel/config/tsm/report/ticket01
sudo mkdir $D
```

The attributes this kernel exposes:

```
-r--r--r--  auxblob            certificate chain, if the host provisioned one
-r--r--r--  generation         write counter, detects a racing writer
--w-------  inblob             the 64 caller-supplied bytes
-r--r--r--  outblob            the report
--w-------  privlevel          requested VMPL
-r--r--r--  privlevel_floor
-r--r--r--  provider           "sev_guest"
```

`inblob` must be a **single 64-byte write**; a partial write is a different request.

```bash
python3 -c "open('/tmp/inblob.bin','wb').write(bytes(range(64)))"
sudo dd if=/tmp/inblob.bin of=$D/inblob bs=64 count=1
sudo cat $D/outblob > /tmp/report.bin      # 1184 bytes
sudo cat $D/auxblob > /tmp/certs.bin       # 0 bytes on this host
sudo rmdir $D
python3 docs/snp/parse-snp-report.py /tmp/report.bin --certs /tmp/certs.bin
```

`docs/snp/guest-evidence.sh` does all of the above and prints the result base64-encoded, so
it also works from a serial console on a guest with no ssh.

The report obtained (full decode in `docs/snp/evidence/report-decoded.txt`, raw bytes in
`docs/snp/evidence/report.bin`):

```
version                : 3
policy                 : 0x30000   [SMT_ALLOWED, RESERVED_MBO]   DEBUG_ALLOWED: no
vmpl                   : 0
signature algo         : 1 (ECDSA P-384 with SHA-384)
signing key            : VCEK
platform_info          : 0x7  [SMT_EN, TSME_EN, ECC_EN]
LAUNCH MEASUREMENT (M) : 84aaf62f431f0a943944e10b0569c7c899bf5e9cfd0c6176af3f70033e241ac1
                         e9d807f5605fd7dd08bf1bf1f09b5da5
report_data (64B)      : 000102...3d3e3f    <- exactly the bytes written to inblob
current_tcb            : bootloader=9 tee=0 snp=23 microcode=72
reported_tcb           : bootloader=9 tee=0 snp=23 microcode=72
committed_tcb          : bootloader=9 tee=0 snp=23 microcode=72
launch_tcb             : bootloader=9 tee=0 snp=23 microcode=72
current firmware       : 1.55 build 39
cpuid fam/mod/step     : 0x19/0x11/0x01
signature all-zero     : no
```

Two things worth noting for later tickets. `report_data` came back byte-for-byte as
written, which is the mechanism ADR-0002's `H(pubkey ‖ ctx)` binding will ride on. And the
launch measurement was **identical across three separate boots** of the same firmware,
kernel, initrd and command line — the measurement is a stable function of its inputs, which
is the premise ticket 06's offline computation depends on.

`reported_tcb` is what a verifier compares against a reference value's TCB floor. Recorded
here as the value this platform currently produces: `bootloader=9 tee=0 snp=23
microcode=72`. It is a fact about the host today, not a floor — choosing a floor is a
reference value authoring decision.

---

## The certificate chain is absent

**`auxblob` is 0 bytes on this host, and no operator action can change that.**

This is the finding the ticket asks to be flagged loudly, and it is worse than "the operator
did not provision certificates."

The empty table is not a misconfiguration. It is what upstream KVM is written to return.
From `arch/x86/kvm/svm/sev.c` at the host kernel's commit `85ef1ac03941`:

```c
	/*
	 * As per GHCB spec, requests of type MSG_REPORT_REQ also allow for
	 * additional certificate data to be provided alongside the attestation
	 * report via the guest-provided data pages indicated by RAX/RBX. The
	 * certificate data is optional and requires additional KVM enablement
	 * to provide an interface for userspace to provide it, but KVM still
	 * needs to be able to handle extended guest requests either way. So
	 * provide a stub implementation that will always return an empty
	 * certificate table in the guest-provided data pages.
	 */
```

Three things were checked, because "the host did not provision it" and "the host cannot
provision it" have very different consequences:

- **The host kernel has no interface to provision a chain.** Its
  `include/uapi/linux/psp-sev.h` defines `SNP_PLATFORM_STATUS`, `SNP_COMMIT`,
  `SNP_SET_CONFIG` and `SNP_VLEK_LOAD`. The out-of-tree `SNP_SET_EXT_CONFIG` that
  `sev-tool` and `snphost import` used does not exist upstream.
- **Linux 6.16 is no better.** The guest kernel tree built here is Linux 6.16 (July 2025),
  and it carries the same stub verbatim, still with no `SNP_SET_EXT_CONFIG` and no
  `KVM_EXIT_VMGEXIT` in its KVM uapi. Upgrading the host kernel would not fix this.
- **QEMU 10.0 has no certificate path either.** Its `sev-snp-guest` object exposes
  `policy`, `guest-visible-workarounds`, `id-block`, `id-auth`, `author-key-enabled`,
  `vcek-disabled` and `host-data`. There is no property for a certificate chain and no
  handling of extended guest requests anywhere in the tree.

### What this costs

The spec's Solution section says:

> Verification is **offline**. The VCEK chain travels with the evidence in the `auxblob`
> the platform's report interface exposes alongside the report, so each side ships its own
> chain and neither needs to reach AMD. […] A KDS fetch remains as the fallback for
> platforms whose host did not provision the chain.

On this platform that is inverted. **The KDS fetch is the primary and only retrieval path,
not a fallback**, and the two properties the offline path was chosen for do not hold as
described:

- **Availability.** An outbound HTTPS call to AMD sits on the critical path of tunnel
  establishment. The spec names this as a cost it was avoiding.
- **Privacy.** AMD learns which chips are talking, and when. Also named, also not avoided.

This lands directly on tickets 05 and 14, which are written against the offline property.
It does not invalidate the design — the certificates are public and self-validating against
the AMD root, so where they come from does not affect soundness — but "no network needed"
is not true here, and code written assuming `auxblob` is populated will find it empty on
every run.

### The way out, which does not need a kernel change

Worth recording because the spec already built the mechanism. The reference value set and
the peer table reach the guest on a read-only block device the initrd mounts, delivered
from outside the launch measurement, and the spec's own argument is that the delivery
channel's untrustworthiness is a non-issue because the content is signature-checked. The
VCEK chain has exactly that shape — public, self-validating against the AMD root, worthless
to forge — so it can ride the same device: fetched from the KDS once at provisioning time,
delivered alongside the reference value set, and never fetched again at handshake time.

That restores both properties the `auxblob` was chosen for, needs no kernel change, and
adds no state inside the security boundary. It is a decision for tickets 05 and 14 rather
than this one, and it wants an ADR.

Deciding it is out of scope here. Recording that the fallback is now mandatory rather than
optional is the acceptance criterion, and that is what this section does.

### Where this is recorded outside this file

The spec and the issue tracker live under `.scratch/`, which is gitignored, so this file is
the tracked record. For a reader working from the spec, the same finding is marked there:

- `spec.md` gained an **Implementation findings** section, and the three places that assert
  the offline property — the Solution section, user story 5, and the Evidence and binding
  decision — are each marked inline rather than rewritten. The decisions are left standing
  until someone revisits them; only the contradiction is recorded.
- Tickets 04, 05, 09 and 14 carry a finding note and an inline mark on each affected
  acceptance criterion. Ticket 05's "verification completes with no network access to the
  vendor" is the one that is unreachable as written.
- `spec.md`'s Problem Statement also repeated the firmware claim corrected above; it is fixed
  there too.

No acceptance criterion was reworded and no ADR was written for the delivery route. Those are
decisions, and this ticket produces findings.

---

## Repeating this

Scripts, all under `docs/snp/`:

| | |
|---|---|
| `build-ovmf-pinned.sh` | build edk2 at the pinned tag into the local prefix |
| `launch-snp-guest.sh` | launch the guest; `-no-snp` gives the control |
| `gssh` | ssh/scp into the guest with the throwaway key |
| `guest-evidence.sh` | run **in the guest**: acquire and dump evidence |
| `parse-snp-report.py` | decode a report and a certificate table, no dependencies |
| `host-read-guest-ram.py` | run **on the host as root**: read guest RAM, count the canary |
| `canary-experiment.sh` | fill guest RAM with the canary |
| `canary-scan.py` | count a marker in a large file without OOM |
| `qmon.py` | talk to the QEMU human monitor socket |
| `root-runner.sh` | run privileged steps from a spool directory |

`root-runner.sh` exists because this work was done from a session that could not type a
sudo password. It runs as root inside a tmux session, watches a spool directory, and
executes `*.job` files placed there. An operator at a terminal does not need it — run the
privileged steps directly. It is kept because it documents exactly which steps needed root:
reading `/dev/sev` and `dmesg`, launching QEMU, reading `/proc/<pid>/fd`, and nothing else.

### Known-good landmarks

If a step fails, these are what a working run looks like at that point.

| Step | Expect |
|---|---|
| Host check | `KVM_CAP_VM_TYPES` bitmask has bit 4 set |
| After QEMU build | `-object help` lists `sev-snp-guest` |
| After OVMF build | `usr/local/share/qemu/OVMF.fd` exists, ~4 MiB |
| After guest kernel | `make bindeb-pkg` fails on `libdw-dev`; `arch/x86/boot/bzImage` exists anyway |
| Guest boot | `SEV: Status: SEV SEV-ES SEV-SNP` and `SNP running at VMPL0` |
| Report interface | `/dev/sev-guest` exists; `provider` reads `sev_guest` |
| `outblob` | exactly 1184 bytes |
| `auxblob` | 0 bytes — expected on this host, see above |

### Things that will bite

- **`-bios`, not pflash.** An SNP guest takes the unified `OVMF.fd` via `-bios`. The
  `OVMF_CODE.fd` + `OVMF_VARS.fd` pflash pair is for non-SNP guests, and there is no
  persistent variable store for an SNP guest.
- **`hostfwd` fails silently-ish** if the port is taken; QEMU exits with
  `Could not set up host forwarding rule`. Pick another port.
- **The Ubuntu cloud kernel boots SNP but has no `sev-guest` module.** Its config has
  `CONFIG_SEV_GUEST=m` and `CONFIG_TSM_REPORTS=m`, but the modules are not present under
  `/lib/modules`, so `modprobe sev-guest` fails with `Module sev-guest not found` and there
  is no report interface. This is why the procedure installs the vendor guest kernel rather
  than relying on the distro one.
- **HMP `pmemsave` mis-parses absolute paths** on QEMU 10.0 (`invalid char 'h' in
  expression`). Reading `/proc/<pid>/fd/<memfd>` is both a workaround and a more faithful
  test of what a host operator can actually see.
- **On this stack the measurement covers the firmware, and NOT the kernel, initrd or command
  line.** This is the opposite of what one would assume, so it is stated plainly. The firmware
  built here is `OvmfPkg/OvmfPkgX64.dsc`, which links `BlobVerifierLibNull` — it accepts every
  blob it is handed — and the launches recorded here do not pass `kernel-hashes=on`, so QEMU
  never writes a hashes table into the measured firmware page. The kernel, initrd and command
  line are loaded through `fw_cfg` and never hashed into **M**. A rebuilt OVMF does invalidate
  any recorded measurement; a rebuilt kernel or an edited command line does not move it at all.

  This also bounds what the "identical measurement across three boots" result above proves. It
  shows **M** is stable, which is consistent with **M** being a function of the firmware and the
  VMSAs alone — it is not evidence that **M** tracks the kernel, initrd or command line, because
  on this stack it does not.

  Ticket 06 establishes the property for the measured image by building
  `OvmfPkg/AmdSev/AmdSevX64.dsc`, which links `BlobVerifierLibSevHashes` and returns
  `EFI_ACCESS_DENIED` on a mismatch, and by launching with `kernel-hashes=on`. The memo's claim
  that the verity root hash on the command line covers the root filesystem transitively holds
  under that firmware and that flag, and under nothing else. See `docs/snp-measured-image.md`.

---

## What this does not establish

- **The report was not cryptographically verified here.** Its signature was not checked
  against the AMD root — that is ticket 05's work, and it needs the VCEK, which on this host
  means a KDS fetch.
- **The guest is stock.** It runs a full Ubuntu userspace and its measurement covers
  nothing of interest. That is deliberate: ticket 06 builds the measured image.
- **The launch measurement was read from the machine, not predicted.** Recorded once here as
  a cross-check for ticket 06's offline computation, exactly as the spec requires. A
  measurement learned by asking the machine is not a prediction, and a reference value built
  on one cannot fail.
- **The TCB values are observations, not a floor.** Choosing a floor is a reference value
  authoring decision.
