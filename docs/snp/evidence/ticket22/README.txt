Ticket 22 on the SEV-SNP hardware harness
=========================================

The sandbox contract, live: two guests from a rebuilt measured image, a policy
pushed from one to the other over the tunnel, a second push refused, and the
egress ceiling refusing everything it forbids from inside each guest.

Everything here was produced on 2026-09-15 by one invocation, which is the
first line of tunnel-run.txt:

  docs/snp/tunnel-on-two-guests.sh -image $STACK/image-ticket22 \
      -scenario live -scenario push-v1 -scenario push-v2 \
      -run-for 1000 -capture docs/snp/evidence/ticket22

at aa8669a4a9c66de4d01d321ca5c229d9c40a8291 on ticket-22-sandbox-contract. The
three scenarios ran against one image, which is why the image's own files are at
the top of this directory and not repeated inside each of the three.

The image
---------

  manifest.txt                  every measured input, the toolchain, the root
                                filesystem file by file, and the two digests.
                                launch_measurement is the prediction; nothing
                                here was read off a booted guest.
  predicted-measurement.txt      how that prediction was computed, offline.
  reference-values.inputs.txt    the inputs of the two signed documents.
  packaging.txt                  package-tunneld.sh's own record: the guard
                                 test, the static binary, the build.
  reference-values.json(+ .sig)  whom a guest booting this image admits, and
                                 under which policy digest. Signed by the author
                                 key whose public half is inside the
                                 measurement at /etc/attested-tunnel/author.pub.
  policy.json(+ .sig)            what a guest booting this image is. Since
                                 ticket 22 this document is ARCHIVED here and
                                 delivered nowhere: it is on no config device,
                                 no guest loads it, and a device carrying it
                                 stops the guest by name.

  launch measurement   b02657728efac22dbdd72b0388186aaa6a2c59e6c43ab92e48d6060b1e37ee342c083c34463ebc2c3537c5998d8529cc
  ceiling digest       197d4aae216ff9c22268fba6646edc3d976e924f4ccec4e8e5461d60f76ab973
  emitted policy       09a7c6974d34357f5401e70871fbca39d7ce802576756304fc501b9c8cd92d41
  author public key    3f27c388b8c18afb53cce0214c3a9c7650290073d23ceffe09042c8d017dec72

  The previous SEV-SNP image measured a234bfa378d30bbde9c5cc3b3c7649c35ea8a7ab
  f783fe95f22a44b0aeb0fc38cae92689256a5dd42197dfa1b87f7723 (ticket 18's mutual
  run). ceiling-digest.txt says what moved and why.

The runs
--------

  tunnel-run.txt        the whole transcript: every PASS line of all three
                        scenarios, the digests each turned on, and the latency
                        table. 85 passed, 0 failed.
  relay-selftest.txt    the two controls that make "MARKER not found" mean
                        something: two guests really reach each other across
                        the relay, and the relay really sees a marker when one
                        is on the wire. 5 passed, 0 failed.

  live/       two attested guests, 1000 s, one exchange after another.
  push-v1/    guest A pushes a version 1 policy at guest B, B's null sandbox
              applies it, and only then is A handed a stream.
  push-v2/    the same pair with a version 2 document. B refuses it at the
              boundary without waking a sandbox, and the tunnel goes with the
              refusal.

  Each of the three holds:

    boot.job        the exact privileged job handed to the root runner. It is
                    the whole of what ran as root, and it was reviewable as a
                    file before it ran.
    console-a.txt   guest A's serial console, from the kernel's first line to
    console-b.txt   guest B's. A measured guest has no other diagnostic
                    surface, so these are the primary record.
    relay.txt       what the on-path attacker carried and what it could read:
                    frame counts both ways, MARKER not found, and every address
                    resolved on the segment.
    segment.pcap    every frame between the two guests, for anyone who would
                    rather not take relay.txt's word for it.
    digests.txt     (push only) the document pushed, its sha256, the number
                    guest A said it was pushing and the number guest B said it
                    applied.
    push-policy.json (push only) the document itself, byte for byte.

What each of the ticket's live criteria is met by
-------------------------------------------------

1. Two guests from a REBUILT image, with the two ticket 21 leftovers fixed at
   this rebuild.
     manifest.txt (a new launch measurement), packaging.txt (the guard test ran
     before the binary was built and the binary before the image was measured),
     live/console-a.txt and live/console-b.txt ("PEER SEEN ... measurement=
     b0265772..." on each, which is the prediction in manifest.txt). The two
     leftovers are in the source, not here: selfcheck.go now names `attest-tool
     verify`, and readAuthorKey is one function in package attest.

2. A pushes P to B, and B's null sandbox acks.
     push-v1/console-a.txt:
       tunneld: push policy /config/push-policy.json: format=policy version=1 bytes=53 sha256=c067e20134c6ba70a95ece8b2f877b11f34943dd72d0ceff5038036431903e6c
     push-v1/console-b.txt:
       tunneld: SANDBOX applied format=policy version=1 bytes=53 sha256=c067e20134c6ba70a95ece8b2f877b11f34943dd72d0ceff5038036431903e6c
     The two numbers are equal, and push-v1/digests.txt is where they are put
     beside the file this harness wrote.

3. Exchanges run through the re-attestation age.
     live/console-b.txt and the table at the end of tunnel-run.txt: 34 passes
     over 1000 s, of which 2 cost a verification. The maximum age is 15
     minutes, so the second verification is the tunnel being judged afresh in
     the middle of the run, and the other 32 passes are the cache answering.

4. A second push with an unknown version is refused as PolicyNotApplied, and
   nothing crosses.
     push-v2/console-b.txt:
       tunneld: REFUSED verification refused: the policy pushed to the peer was not applied: a peer at 10.14.0.2:51743 pushed a policy this sandbox did not apply: sandbox: policy refused: version 2 is not 1
     push-v2/console-a.txt:
       tunneld: REFUSED verification refused: the policy pushed to the peer was not applied: "guest-b" at 10.14.0.3:4433 did not apply the policy pushed to it: the peer refused it: this tunneld does not read a policy of that format and version
     push-v2/console-b.txt carries no "SANDBOX applied" line and no "SANDBOX
     stream" line at all: no sandbox was woken and no stream was ever opened on
     that tunnel. Guest A's exercise failed rather than carrying on without its
     policy.

5. Unattested egress from inside a guest is still refused at the ceiling, and
   the table is captured.
     egress/<scenario>-guest-{a,b}.txt, six files, one per guest per scenario.
     Each carries the ceiling as the image carries it, the same rule set as the
     kernel handed it back, and the verdict on every attempt to leave. 24
     attempts across the six, and all 24 read REFUSED — the netfilter rule
     refusing, not a routing table with nothing to say.

What is not here
----------------

  * No guest's own measurement was read off a booted guest. Every measurement
    in this directory is the offline prediction; what the guests did was report
    the same number in their evidence, which is a different claim and the one
    worth making.
  * Nothing enforces a pushed policy. The null sandbox records format, version,
    length and digest and acknowledges; n, f and x are unparsed by every line
    of code in this tree. Enforcement is the ceiling in egress/ and the
    reference value set that admits a peer at all.
  * The pushed policy is not measured and does not claim to be. It is read off
    guest A's config device, which is the host's, and what makes it trustworthy
    to guest B is guest A's evidence rather than guest A's disk.
  * The policy scenarios of tickets 18 and 19 (policy-pinned, policy-mismatch,
    mutual) were not run. They turn on a policy document delivered on a config
    device, which ticket 22 removed; their recorded evidence stands as history.
