# Acquiring evidence from a live guest

Ticket 04. How code inside a confidential guest produces real evidence bound to a key it just
generated, and where the certificate chain that travels with it comes from. The decisions are
ADR-0002 and ADR-0005; vocabulary is `CONTEXT.md`. The code is `attest/tsm`, and the command that
runs it in a guest is `attest/cmd/acquire-evidence`.

This is the producer half of the vendor seam ticket 02 defined from the consumer side, and the
first place in this project where evidence comes from silicon rather than from a test signer.

## The interface is the kernel's, not this design's

Linux exposes every confidential-computing platform's report interface the same way, under
`/sys/kernel/config/tsm/report`. A request is a directory; the attributes inside it are the
request and its answer:

```
-r--r--r--  provider           which platform driver is behind this — "sev_guest" here
-r--r--r--  generation         write counter; advances on every write to the request
--w-------  inblob             the 64 caller-supplied bytes
-r--r--r--  outblob            the evidence
-r--r--r--  auxblob            the certificate chain, if the host provisioned one
--w-------  privlevel          requested VMPL
-r--r--r--  privlevel_floor
```

The same four steps — make the directory, write `inblob`, read `outblob`, remove the directory —
yield an SEV-SNP report on AMD and a TDX quote on Intel. Only the bytes that come back are the
vendor's, which is why the package is named for the interface rather than for AMD.

`privlevel` is deliberately left alone: the guest runs at VMPL0, which is the floor the kernel
already requests, and writing it would advance the generation counter for a knob nothing here
needs.

Three things in `attest/tsm` are AMD-specific, and all three stay behind `attest.Acquirer`: the
provider name `sev_guest`, the knowledge that the bytes are an SEV-SNP report, and reading the
caller-supplied field back out of one. Nothing above the package learns what a report is. A
second vendor adds a case to one `switch` and implements `attest.Verifier`.

## The sequence, and what each step is for

1. **Create a request of this acquirer's own.** The name is `<prefix>-<pid>-<n>`, and a name
   already taken is stepped over rather than reused: inheriting a directory means inheriting
   whatever was written to its `inblob`. Two acquisitions never share a request, because the
   second one's `inblob` would be the first one's evidence.

2. **Read `provider`, and refuse one this acquirer does not implement.** Guessing at the format
   of evidence whose vendor is unknown is how a parser becomes an attack surface. This happens at
   startup as well as at every acquisition: a tunneld that cannot produce evidence has nothing to
   offer a peer and refuses to start rather than failing at its first handshake.

3. **Write the caller-supplied bytes to `inblob`, once, whole.** One `write(2)` of exactly 64
   bytes. `os.File.Write` is not that — it retries a short write, which would turn one request
   into two — so the write goes through `SyscallConn` and is never retried. A partial `inblob` is
   a different request, not half of this one.

4. **Read `outblob`.** 1184 bytes on this host.

5. **Read `auxblob`, and record that it is empty.** See below.

6. **Check the generation counter advanced by exactly the one write this acquisition made.** The
   request directory is private, so a racing writer should be impossible; `generation` is the
   kernel's way of saying it was not, and an acquirer that ignored it could hand back evidence
   bound to somebody else's key.

7. **Check the platform returned the bytes it was handed.** The binding is the platform copying
   `inblob` into the evidence verbatim, so evidence over anything else binds nothing. This is not
   verification — no signature is checked and a platform lying about everything else would still
   pass — it is the local host reporting its own fault locally, rather than leaving a peer to
   report it as an unexplained binding refusal.

8. **Load the chain the config device holds for this report, and bundle it.** See below.

## What the evidence is bound to

The 64 bytes handed to the platform are `SHA-512(public key ‖ binding context)`, all-zero context
in v1 (ADR-0002). The acquirer does not compute them: it writes whatever
`attest.Binding.CallerSuppliedBytes` produced. Producer and consumer therefore agree by
construction rather than by comment — `Verification.Verify` recomputes the same bytes from the
key the peer presented and compares them against what the evidence carries, and both sides call
one function.

SHA-512 rather than SNP's native SHA-384 because its output is exactly the width of the field, so
no padding convention exists for two implementations to disagree about.

From the captured run — a key generated inside the guest a moment before, and the report that
came back:

```
public key (SPKI)   : 302a300506032b6570032100a9caa36e0d5a26953dc632d635379b278d0273f0792d32d948356dd4108b4ea5
caller-supplied     : 84af29971df7cba51c41f748a67a5446208be5f745083a7e1ac804fa5eec6c980607d4f2e014c3ebb3ffdcd887877e597ceb20d1b5b4804f123ee8598808a035
report_data (64B)   : 84af29971df7cba51c41f748a67a5446208be5f745083a7e1ac804fa5eec6c980607d4f2e014c3ebb3ffdcd887877e597ceb20d1b5b4804f123ee8598808a035
```

## The certificate chain comes from the config device

`auxblob` is **0 bytes** on this host, and no operator action fills it: upstream KVM ships a stub
that always returns an empty certificate table, and neither a newer kernel nor a newer hypervisor
changes that (`docs/snp-host-stack.md`, *The certificate chain is absent*). So the acquirer reads
it, records its size in an observation an operator can read, and carries on. **An empty table is
the expected state here and is not an error** — treating it as one would fail every acquisition
on every host this design runs on.

The chain that is actually bundled comes from the read-only config device, fetched once at
provisioning time (ADR-0005, `docs/provisioning-certificate-chain.md`), through
`provision.LoadFor` with the report just acquired. That call is the fail-closed boundary:

| What is wrong | What happens |
|---|---|
| No chain provisioned | Refused, naming ADR-0005. Not `os.ErrNotExist`, so "no chain here, carry on" cannot be written by accident. |
| Chain without its metadata, or metadata without its chain | Refused. |
| Metadata that does not describe the chain beside it | Refused: two provisioning runs got mixed. |
| Chain for another chip | Refused: a config device was carried between hosts. |
| Chain issued for a TCB this platform has moved off | Refused as stale, naming the symptom a peer would otherwise report — `malformed evidence` about a healthy platform. |

**Acquisition never reaches AMD's key distribution service.** There is no fallback and no getter
to hand this side of the design; a silent fetch would reinstate exactly the dependency ADR-0005
removes, and would do it invisibly, on the critical path of every tunnel. `attest/tsm`'s import
allowlist test is the structural guard: this package imports nothing of its own through which a
fetch could be written, and a new dependency fails the test until somebody justifies it there.

## Running it in a guest

Needs the guest of `docs/snp-host-stack.md` — or any confidential guest with a report interface —
and root, because `inblob` is root-only.

```sh
# On the host: build it and copy it in, with a config device beside it.
export PATH=/usr/local/go/bin:$PATH
cd attest && CGO_ENABLED=0 go build -o /tmp/acquire-evidence ./cmd/acquire-evidence

bash "$STACK/gssh" 'mkdir -p /tmp/ticket04/config-device'
bash "$STACK/gssh" --scp /tmp/acquire-evidence G:/tmp/ticket04/
bash "$STACK/gssh" --scp docs/snp/evidence/certificate-chain.bin \
                        docs/snp/evidence/certificate-chain.json G:/tmp/ticket04/config-device/

# In the guest, as root.
bash "$STACK/gssh" 'sudo modprobe sev-guest
  sudo mountpoint -q /sys/kernel/config || sudo mount -t configfs none /sys/kernel/config
  sudo /tmp/ticket04/acquire-evidence -chain-dir /tmp/ticket04/config-device -out /tmp/ticket04/bundle'
```

`-base64` prints the bundle base64-encoded instead, for a guest reachable only over a serial
console. The measured image is deliberately not required: this ticket establishes the evidence
path so that it can proceed in parallel with the image work, and the config device is any
directory holding the two provisioned files. Ticket 06 defines the real device.

## Status on this host

**Run.** 2026-08-25, in the stock SEV-SNP guest of `docs/snp-host-stack.md` (Linux
6.16.0-snp-guest-038d61fd6422, VMPL0). The whole run, including the fail-closed cases, is
`docs/snp/evidence/ticket04/acquire-run.txt`; the bundle and what produced it are in
`docs/snp/evidence/ticket04/manifest.txt`.

```
tsm: provider "sev_guest" (amd-sev-snp) returned 1184 bytes of evidence over 1 write(s);
its own certificate table is empty (auxblob, 0 bytes), which is the expected state on this
host and not an error; bundled the 4759-byte chain provisioned in
/tmp/ticket04/config-device for chip 9b3716…5243 at bootloader=9 tee=0 snp=23 microcode=72
(ADR-0005)
```

The chain that came back with the evidence is `docs/snp/evidence/certificate-chain.bin` byte for
byte — the point of ADR-0005 being that it came off the config device rather than off the
platform.

Both fail-closed paths were exercised on the same guest, against an empty directory and against a
chain with its metadata removed:

```
acquire-evidence: provision: certificate chain refused: reading .../certificate-chain.json:
no such file or directory; no certificate chain is provisioned here — provision one, do not
fetch (ADR-0005)
```

And the request directory is not left behind: `/sys/kernel/config/tsm/report` held no entries
before the run and none after it.

## What is checked without a guest

Everything above the kernel. `attest/tsm`'s tests stand in for the report interface — modelling
the ABI, not the hardware: attributes generated on read, a generation counter that advances on
every write, an `inblob` that takes exactly the field's width, an empty `auxblob` — and drive
`Acquire` over two platforms: the fake SEV-SNP platform of `attest/snpfake`, and the artifacts of
real runs. Among them:

- evidence produced over a real binding is accepted by a verifier against that binding, and
  refused against any other key — the producer and consumer halves of the seam meeting;
- the live guest's own evidence carries exactly the caller-supplied bytes the key captured beside
  it produces, which is ADR-0002 checked against bytes a machine made, offline, on every test run;
- an empty certificate table is recorded and not refused, and an unreadable one likewise;
- a missing chain, a stale chain and another chip's chain each fail closed;
- a platform that returns evidence over other bytes, an unimplemented platform, and a racing
  writer are each refused.

No confidential VM and no network. `go test ./...` from `attest/`.

## What this does not establish

- **The report was not verified.** Its signature was not checked against the AMD root here, and
  the chain was not validated. Producing and bundling is this ticket; proving is ticket 05.
- **The guest is stock.** Its launch measurement covers the firmware and not the kernel, initrd
  or command line on this firmware (`docs/snp-host-stack.md`), so the measurement in the captured
  evidence attests nothing of interest. That is deliberate — it is what let this ticket run in
  parallel with the measured image.
- **The config device was a directory.** The read-only block device, its layout and its mount are
  ticket 06's; the only thing this depends on is the two file names.
- **Nothing composes this yet.** Wiring `attest/tsm` into tunneld in place of the fake platform is
  a later ticket; `tunneld.Config` already takes the acquirer through the seam, so it is a
  substitution rather than a change.
