# Offline RTMR2 prediction from a disk image

Ticket 16. The experiment `docs/tdx-as-a-second-vendor.md` ("The gap that decides it") said
would flip its recommendation: take the Ubuntu image a Google Cloud TDX VM booted, and compute
RTMR2 — grub, kernel, command line — from the image's bytes alone, before anything boots. The
rule is `docs/snp-measurement-prediction.md`'s and applies unchanged: a value learned by asking
the machine is not a prediction. Scripts are in `docs/snp/cloud/tdx/`, evidence under
`docs/snp/evidence/tdx/predict/`.

**Verdict: yes.** RTMR2 on a Google Cloud TDX VM booting `ubuntu-2404-noble-amd64-v20260826` is
computable from the disk image with no boot, and `predict-rtmr2.py` computes it: 86 of 86
records and the register match the quote, on six independent boots including one after
`update-grub`, one after a simulated failed boot, and one after a kernel upgrade to 7.0.

---

## What was done, in order

1. **The image was pinned and its bytes obtained without booting them.** The family alias
   `ubuntu-2404-lts-amd64` had rolled to `v20260906`; the member current on 2026-08-31 was
   `ubuntu-2404-noble-amd64-v20260826` (created 08-26, next member 09-03). A disk was created
   from it and attached read-only to a non-TDX `e2-standard-2` helper, `dd`'d to the
   workstation and hashed at both ends (sha256 `d0b2b2c2…5474f`, 10 GiB). Its partition 16
   carries the filesystem UUID in the log's `search.fs_uuid` record and its partition 1 the
   PARTUUID on the log's kernel command line. `predict/image.txt` has the listing.

2. **Every record was classified** (`predict/classification.txt`). The 86 RTMR2 records are:
   - **(a) 12 records: SHA-384 of bytes that exist verbatim on the image.** The ESP
     `grub.cfg` (measured twice), the four `x86_64-efi/*.lst` files, `/grub/grub.cfg`,
     `grubenv` (twice), `bli.mod`, the kernel — each is the plain SHA-384 of the file's
     contents, and the table names the partition, its byte offset in the disk, the path and
     the size. `MokList` is also (a): it is the 1080-byte Canonical CA certificate read out of
     `shimx64.efi`'s `.vendor_cert` section, wrapped by shim in one `EFI_SIGNATURE_LIST`.
   - **(b) 72 records: SHA-384 of a string grub synthesises while running its config.** The
     digest is of the bare string, no `grub_cmd: ` prefix and no NUL; the table names the
     `grub.cfg` file and line that produced each one. Two are `kernel_cmdline:` records of the
     same shape.
   - **(c) 2 records, both explained.** `MokListX` is shim's empty-key-database placeholder
     (one `EFI_CERT_SHA256` list over 32 zero bytes): the image's `.vendor_cert` does carry an
     8.9 KB vendor dbx that upstream shim 15.8 would mirror, but Ubuntu's `15.8-0ubuntu1`
     patch drops it from the `MokListX` row, so the placeholder is what gets measured.
     `MokListTrusted` is the single byte `0x01`, shim's inverse default when the variable is
     absent from NVRAM. Neither is a file, but both are fixed by shim's source and its build.

3. **A predictor was written and run** — `predict-rtmr2.py`, ~1,500 lines. It parses the GPT,
   pulls files out of the ext4 and vfat partitions root-lessly (`debugfs`, `mtools`), reads the
   built-in module list and embedded prefix out of `grubx64.efi` itself, builds the three MoK
   values from `shimx64.efi`, and then *executes* the two grub configs with a small interpreter
   for the subset of grub script Ubuntu generates, emitting one digest per measured file and
   per executed command in grub's order. Nothing is hard-coded from the log; the config's
   evaluation is what produces the 72 strings, which is why the same script works after the
   config changes (below). `--compare-ccel`/`--compare-quote` only compare, at the end.

4. **The prediction was compared.** Against `eventlog/quote.bin`, byte for byte:

   ```
   RTMR2 predicted : ecc9935861eba8e47817c10761468525af6df776fa2fa2767be5d6d152a5ae3a62da7b750df33d8069c7ff9bae811df9
   RTMR2 in quote  : ecc9935861eba8e47817c10761468525af6df776fa2fa2767be5d6d152a5ae3a62da7b750df33d8069c7ff9bae811df9
   RESULT: MATCH
   ```

   All 86 records agree in digest *and* in event bytes (`predict/predict-v20260826.txt`).

---

## Stability: measured, not assumed

| boot | disk state grub saw | RTMR2 | prediction |
|---|---|---|---|
| probe 4 run 2 (the ticket's log) | pristine image | `ecc99358…11df9` | MATCH, 86/86 |
| probe 4 run 1 (`eventlog-wrongmap/`) | pristine image, separate VM | same | MATCH, 86/86 |
| mutate `control-reboot` | second boot of one disk | same | MATCH (quote) |
| ticket 16 `baseline`, twice (two fresh VMs) | pristine image | same | — |
| `update-grub`, nothing configured | `grub.cfg` gains an empty `30_os-prober` section | `0375c957…1847` | MATCH, 86/86 |
| `recordfail` (grubenv has `recordfail=1`) | grubenv differs; grub takes the `timeout=0` / `linux_gfx_mode=text` branches | `8db33f41…62b7` | MATCH, 82/82 |
| kernel upgrade to `7.0.0-1011-gcp` | new kernel, new `grub.cfg` | `bdd9486c…031d` | MATCH, 86/86 |

Five fresh boots of the pristine image, on four different VMs across eight days, gave the same
RTMR2. For the three mutated boots the prediction was made from a tarball of `/boot` and the
ESP captured *before* the reboot (`predict/upgrade*/*/bootstate.tar`, kept on the workstation;
`pre-boot-state.txt` beside each lists every file's sha256), and compared with the quote and
CCEL that boot then produced (`predict/predict-vs-{update-grub,recordfail,kernel-upgrade}.txt`).
The probe is `probe-tdx-upgrade.sh`; both instances are logged in `RESOURCES.md`.

**`save_env recordfail` and `save_env initrdfail`.** Both write `grubenv` at every boot, and
`grubenv` is measured twice per boot, so this was the record most likely to drift. It does
not, on a boot that completes: grub writes `recordfail=1` and `initrdfail=1`, Ubuntu's
`grub-common` and `grub-initrd-fallback` services unset them again during boot, and
`grub-editenv` restores the block to its original 1024 bytes (header plus `#` padding). That
is why the second, third and fourth boots of one disk measure the same `grubenv` as the first.
On a boot that does *not* complete, `recordfail=1` survives, the next boot measures a different
`grubenv` and takes a different path through the config — RTMR2 moves — and the prediction
still follows, because the predictor executes whatever config and `grubenv` it is given
(82 records, MATCH). So the answer is: a boot after a failed boot differs, and is predictable
given the disk state, which is no longer the image's.

**`update-grub` moves RTMR2 even when nothing changed**, because grub measures `grub.cfg`'s
bytes and `update-grub` on this image appends two comment lines it did not have. The command
stream is identical; only record 12 differs. The predicted value from the rewritten file
matches.

**A correction to the study.** The mutation probe of 2026-08-31 attributed its "initrd" move
(`0375c957…1847`) to the changed initrd. That boot is initrdless (`GRUB_FORCE_PARTUUID`), so
the initrd was never loaded or measured; the value is exactly today's `update-grub` value, and
the probe's initrd step ran `update-grub`. What moved RTMR2 there was the rewritten `grub.cfg`.
The study's conclusion that RTMR2 covers the kernel and command line stands; its claim that it
covers the initrd was not tested, and on this image's default boot path the initrd is outside
RTMR2 altogether.

---

## What the model assumes

Listed at the top of `predict-rtmr2.py`, and printed in every run's header:

- grub reports `grub_platform=efi`, `feature_menuentry_id=y`, `feature_all_video_module=y`,
  `feature_timeout_style=y`; modules live in `x86_64-efi/`.
- The boot config on the ESP is measured twice before its first command runs
  (`BOOT_CONFIG_MEASUREMENTS = 2`). This is what every log shows; the second `grub_file_open`
  in grub 2.12's `normal` path was not pinned to a source line and is recorded as empirical.
- `fwsetup --is-supported` returns 0 (a firmware property, not an image one).
- The boot disk is `hd0`; the firmware boots `\EFI\ubuntu\shimx64.efi` (from `Boot0002`, an
  NVRAM variable that is not in the image); no `MokList*` variables exist in NVRAM; Ubuntu's
  shim does not mirror the vendor dbx (`SHIM_MIRRORS_VENDOR_DBX = False`).
- The default menu entry boots unattended. A keystroke, another entry or an edited command line
  all change RTMR2, which is what measuring them is for.

Unmodelled grub script — `while`, `for`, `case`, unknown commands or test operators — makes the
script exit 3 rather than guess.

---

## What this does not establish

- **RTMR0 and RTMR1.** Firmware configuration, UEFI variables, the GPT and the shim/grub
  binaries' own measurements are Google's, not the image's. `gce-tcb-verifier` issue #73 asks
  for those and is still open. A verifier can hold them as observed provider constants, the
  way the study found the SEV-SNP launch measurement on a provider has to be held, or predict
  them from the firmware Google publishes; neither is done here.
- **That every future image behaves.** The interpreter covers what Ubuntu's `grub.d` templates
  emit today. A config that uses a construct it does not know fails loudly; that is the
  intended failure, and the fix is to extend the model, never to read the register.
- **That the value is right for a different boot disk layout.** `(hd0,gptN)` names, the ESP
  directory and the module directory are inputs; a second disk or a non-Ubuntu shim needs
  them supplied.
- **Anything about the initrd.** On this image's default path it is not loaded.

---

## Running it

```sh
# from the image, nothing mounted, nothing booted
python3 docs/snp/cloud/tdx/predict-rtmr2.py --raw disk.raw \
    --compare-ccel docs/snp/evidence/tdx/eventlog/ccel.bin \
    --compare-quote docs/snp/evidence/tdx/eventlog/quote.bin

# from a filesystem tree captured out of a guest before a boot
python3 docs/snp/cloud/tdx/predict-rtmr2.py --tree unpacked/ --esp-part 15 --boot-part 16 \
    --fs-uuid 16=b4f9057b-66e6-4f5a-bbba-a8086989e88f --compare-quote quote.bin

# the on-hardware probe (one c3-standard-4 TDX VM, four boots, deleted at the end)
bash docs/snp/cloud/tdx/probe-tdx-upgrade.sh
```
