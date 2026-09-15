Ticket 19, step zero: does predict-rtmr2.py's initrd path survive contact with a
boot that actually loads an initrd? Produced by docs/snp/cloud/tdx/probe-tdx-initrd.sh
on 2026-09-10T20:09:51Z from eb9939ed4dd0b6d49e99d3a773bc1bb32622b740, on one
c3-standard-4 TDX instance (tdx-initrd, us-central1-a, image ubuntu-2404-noble-amd64-v20260826) that was deleted at the end.

Two boots of one disk. The prediction for each is made from bytes captured off
the guest before that boot, and compared with the quote and the CCEL that boot
produced.

  initrd.txt          the whole transcript of the run, console and log
  rewrite.log         the grub.cfg rewrite: the diff, and what was installed
  guest-facts.sh      the questions asked of the guest, as a script
  guest-facts.txt     their answers: the configfs-tsm provider, dmesg's tdx
                      lines, lsmod, /dev/disk/by-id, lsblk serials,
                      /sys/block/*/serial, udevadm for the boot disk, ip -d link,
                      ip addr, ip route, and the metadata server's answer --
                      the provider facts ticket 19's own initrd has to rely on
  acquire-evidence    the binary that was uploaded, built from this worktree
  acquire-evidence.txt attest/cmd/acquire-evidence run on the guest's real
                      configfs-tsm, twice: with no -chain-dir, and with one
                      that holds nothing and must be ignored
  acquire-evidence-bundle.tar  what it wrote: evidence.bin (the quote), the
                      public key it is bound to, the caller-supplied bytes, the
                      policy digest and the observation. There is no
                      certificate-chain.bin, and that is the result.

  baseline/           boot 1: the pinned image untouched, the control
  initrd/             boot 2: the same image with one line added to grub.cfg

  <label>/guest-evidence.txt  the transcript of guest-evidence-tdx.sh on that boot
  <label>/quote.bin           the TDX quote that boot produced (8000 bytes)
  <label>/quote.txt           parse-tdx-quote.py's reading of it
  <label>/ccel.b64, ccel.bin  that boot's CCEL event log
  <label>/state.txt           boot_id, /proc/cmdline, the kernel, and the sha256
                              of every file grub read, as of that boot
  <label>/pre-boot-state.txt  the same sha256 list taken BEFORE the boot, plus
                              the initrds on disk, the default menuentry with
                              its whitespace shown, lsblk and grubenv
  <label>/bootstate.tar       /boot and the ESP as grub would see them at that
                              boot, in the layout predict-rtmr2.py --tree takes
  <label>/grub.cfg            the grub.cfg inside that tarball, on its own
  <label>/unpacked/           the tarball unpacked, which is what was predicted from
  <label>/predict.txt         predict-rtmr2.py's full output for that boot,
                              every record, and MATCH or MISMATCH

The predictor was run as:

  predict-rtmr2.py --tree <label>/unpacked --esp-part 15 --boot-part 16 \
      --root-part 1 --fs-uuid 16=b4f9057b-66e6-4f5a-bbba-a8086989e88f \
      --compare-quote <label>/quote.bin --compare-ccel <label>/ccel.bin

Nothing in predict-rtmr2.py was changed to make either comparison come out.
