reference-values.v20260826.json — a signed reference value set for an Intel TDX
peer, in format version 2 (the version that gave every value a vendor tag).

It is here to be read, not deployed. The .sig beside it is not copied: this
document was emitted with a throwaway Ed25519 key generated for the run and then
discarded, because the reference value author's real key is not in this
repository. An operator deploying this set emits it again with their own key —
the command below — and ships both files.

Emitted by docs/snp/cloud/tdx/emit-tdx-refvals, exactly:

  cd docs/snp/cloud/tdx/emit-tdx-refvals
  go run . \
    -rtmr2 ecc9935861eba8e47817c10761468525af6df776fa2fa2767be5d6d152a5ae3a62da7b750df33d8069c7ff9bae811df9 \
    -mrtd c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5 \
    -rtmr0 c0b8b19ca6f51dc37435da45a61ab417e59253cd31cc2eeb3e833e8b8979679fe5a65387e0014831fe7b3ec4be51896d \
    -rtmr1 02c7f19c862b3dae1592c737358d9bb13f8f0a34d3b3eca67c39bf7941a12c347635b8a291d68d9cace45b16ec25913b \
    -rtmr1 3a446943925fef7f1682fd54e1b6697df864692e28592ec373860d1868582ac14ca3029c48282eb964868a785bafd691 \
    -tcb-status UpToDate -tcb-evaluation 20 \
    -key AUTHOR.key.pem -out OUT

Where each value came from, and which kind it is:

predicted_rtmr2
  ecc99358…11df9
  docs/snp/evidence/tdx/predict/predict-v20260826.txt, line "RTMR2 predicted".
  PREDICTED: computed by docs/snp/cloud/tdx/predict-rtmr2.py from the disk image
  before anything booted, by replaying the 86 records grub and shim would
  measure. It is the only register here that names the image — grub, the kernel
  and the command line — and the only one a reference value author can compute.
  The same file records that a booted guest's quote then reported exactly this
  value ("RTMR2 comparison: MATCH"), which is the check, not the source.

observed_mrtd
  c1ee9c16…70a5
  The firmware Google boots. Byte-identical in every quote recorded under
  docs/snp/evidence/tdx (17 quotes, across images, reboots and package
  upgrades), e.g. docs/snp/evidence/tdx/eventlog/quote.bin at quote offset
  48+136. OBSERVED: nothing here can predict it, so it is pinned as the constant
  it is, and a verifier finds out if Google changes it.

observed_rtmr0
  c0b8b19c…896d
  The provider's VM configuration. Same 17 quotes, same value, at offset 48+328,
  except the one probe that deliberately changed the VM shape
  (probes-run1/tdx-probe-b). OBSERVED, for the same reason.

observed_rtmr1, first value
  02c7f19c…913b
  The boot chain as it is measured on a VM's FIRST boot, before the root
  partition is grown. docs/snp/evidence/tdx/eventlog/quote.bin, offset 48+376.
  OBSERVED.

observed_rtmr1, second value
  3a446943…d691
  The same register on EVERY LATER boot: the GPT it covers changes once, when
  the root partition is resized on first boot, and never again.
  docs/snp/evidence/tdx/predict/upgrade/update-grub/quote.bin, offset 48+376
  (python3: open(f,'rb').read()[48+376:48+424].hex()). Both values are listed
  because a set naming only the first would refuse its own peer after a reboot,
  and one naming only the second would refuse it before one.

minimum_tcb.status = UpToDate
  The stronger of the two floors the format admits: the platform must be at
  Intel's current TCB level, with no documented software mitigations
  outstanding. Chosen, not measured.

minimum_tcb.tcb_evaluation_data_number = 20
  docs/snp/evidence/tdx/collateral/tcbinfo-00806f050000.body, field
  tcbEvaluationDataNumber, for FMSPC 00806f050000 — the TCB info fetched for the
  platform these quotes came from. The floor stops a host provisioning older
  collateral: Intel raises this number at every TCB recovery, and TCB info from
  before one still verifies and still calls a since-vulnerable platform
  UpToDate.

td_attributes_policy.allow_debug = false
  A TD created with TD_ATTRIBUTES.DEBUG can be read by its host and has nothing
  to prove. The default, spelled out because the document is reviewed by eye.
