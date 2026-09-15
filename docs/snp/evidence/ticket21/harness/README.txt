Ticket 21: the verdict-replay harness, kept so a later ticket can re-run the
same diff rather than invent a new one.

  verdict-invocations.txt          the 111 recorded invocations ticket 20 built,
                                   one per line, SLUG<TAB>ARGS, unchanged.
  verdict-invocations-v2.txt       the 64 of them that carry no -binding-version
                                   flag, so they still parse after ec299ac2e.
  verdict-invocations-retired.txt  the 47 that do. Against this tool each prints
                                   "flag provided but not defined:
                                   -binding-version", the usage, and exits 1.
  replay-verdicts.sh               the replayer. Its own header documents
                                   REPLAY_LIST, REPLAY_PREFIX, REPLAY_CWD,
                                   REPLAY_REPO and REPLAY_AUTHORED, and the two
                                   normalisations (go-tdx-guest's timestamped
                                   WARN lines, and `go run` swallowing an exit
                                   status) that a before/after comparison needs.
  authored/                        what @AUTHORED@ in the lists expands to: the
                                   throwaway v4 reference value sets authored
                                   for ticket 05's recorded evidence, with the
                                   public half of the key that signed them. Four
                                   of the 64 live invocations read these. The
                                   private half is NOT here: verification needs
                                   the document, its signature and the public
                                   key, and nothing in this harness authors a
                                   new document.

How ticket 21 ran it:

  cd attest && /usr/local/go/bin/go build -o /tmp/attest-tool ./cmd/attest-tool
  REPLAY_LIST=.../verdict-invocations-v2.txt \
  REPLAY_AUTHORED=.../authored \
      ./replay-verdicts.sh /tmp/after /tmp/attest-tool verify

and compared line 2 onward against the transcripts of the same list taken at
205fd2154 with `go run ./cmd/verify-evidence`. Line 1 of each transcript is the
command, which differs by construction when the prefix does. The result is in
../after/verdict-diff.txt: 60 identical, 4 usage dumps differing only by the
removed flag's help lines.

One caveat on byte identity: verify echoes the path of every file it reads, so
a transcript carries REPLAY_AUTHORED's directory in its "reference value set :"
line. Replaying the four authored rows out of this checked-in copy instead of
ticket 21's scratchpad reproduces every verdict and every claim exactly --
including the author key hash 1f6ab6df... -- and differs on that one path. Pin
REPLAY_AUTHORED to the same directory on both sides of a diff, or compare the
verdict blocks rather than the whole transcript.

The 111 transcripts themselves are not kept. They are 111 files of output this
harness regenerates in about a minute, and the diff is the evidence.
