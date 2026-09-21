// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Ticket 25's proof on the dev host: a runsc sandbox whose sentry intercepts
// the connect, two tunnelds and an exit over loopback, and an unmodified agent
// inside the sandbox that does not know any of it is there.
//
//	runsc run --network=none --tunnel-socket=a.sock --tunnel-table=table.json
//	┌───────────────────────────────────────────┐
//	│ /agent-probe -network plain               │
//	│   resolver ──▶ 127.0.0.53:53 (the sentry) │      tunneld a ──tunnel──▶ tunneld b
//	│   connect 100.64.1.x:443 ──▶ Tunnel.Attach├──▶ a.sock                      │
//	└───────────────────────────────────────────┘    (AF_UNIX)                   ▼ b.sock
//	                                                                   this test's own exit
//	                                                 -allow api.anthropic.com:443,www.rfc-editor.org:443
//	                                                                             │
//	                                                                             ▼ the real network
//
// Two sandboxes are run, one after the other, and the only thing that differs
// between them is the table. The first names both destinations the task needs
// and must complete the task; the second leaves out api.anthropic.com, and its
// agent must fail its first model request — at the connect with ENETUNREACH,
// or at the resolver with NXDOMAIN, and the run records which. Everything else —
// the bundle, the rootfs, the binary, the tunnelds, the exit and its allow
// list — is the same object in both runs, so the refusal is attributable to
// the table and to nothing else.
//
// # The agent is not modified
//
// The workload is this package, built with CGO_ENABLED=0 and run with
// `-network plain`, which is `&http.Client{}`: net/http's default transport,
// Go's own resolver, no contract, no dialer of its own. Nothing in the rootfs
// or the environment tells it that a sentry is in the path. If it ever needs
// telling, that is the ticket's finding and not its fix.
//
// # What this harness can and cannot see
//
// The sentry's half of the arrangement is another agent's code and the
// workload's half is inside the sandbox, so the harness's own clock can only
// be read where the streams cross into this process: at the exit. Three of the
// four timings are taken there and the fourth is when runsc exited. The exit
// never decodes anything it carries — after the OK line the stream is TLS, and
// the claim being recorded is that this side sees host:port and ciphertext.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/attest/sandbox"
	"gvisor.dev/gvisor/attest/tunneld"
)

// The variables this test reads. AGENT_PROBE_LIVE and AGENT_PROBE_RUNSC decide
// whether it runs at all; the other two are switches for the two things that
// may not exist yet on the machine it is run on.
const (
	runscEnv = "AGENT_PROBE_RUNSC"

	// adapterEnv=0 drops the --tunnel-* flags, which is how this harness is
	// exercised against a runsc that does not have them. Such a run proves the
	// bundle, the resolver files, the key plumbing and the log capture, and
	// proves nothing at all about the adapter.
	adapterEnv = "AGENT_PROBE_ADAPTER"

	// receiverEnv names the program that listens on the remote seccheck sink
	// and prints one line per event. Without it the run records no
	// sentry/egress_refused event and says so; the refusal is still asserted,
	// on the errno the workload reported.
	receiverEnv = "AGENT_PROBE_SECCHECK_RECEIVER"

	// noteEnv is a sentence the README carries at the top, for whatever a run
	// needs said about itself that the harness cannot know — which build of
	// runsc this is, what an earlier directory beside it was.
	noteEnv = "AGENT_PROBE_NOTE"

	// evidenceEnv puts this run's captures somewhere other than
	// docs/snp/evidence/ticket25/loopback/<stamp>, which is what a rehearsal
	// against a stock runsc wants.
	evidenceEnv = "AGENT_PROBE_EVIDENCE"
)

// anchors is the one CA bundle file a workload needs; both rootfses copy the
// host's, and both name it in SSL_CERT_FILE.
const anchors = "/etc/ssl/certs/ca-certificates.crt"

// The two destinations the task needs, and the port they are permitted on.
// They are the same two the exit's -allow names and the same two ticket 23's
// policy names, because the task is byte-identical to every spike's.
const (
	modelHost     = "api.anthropic.com"
	docHost       = "www.rfc-editor.org"
	tunnelledPort = 443
)

// The two sentences a refused workload can print, as net's errors spell them.
//
// The ticket asks for ENETUNREACH, which is the errno a connect to an address
// the table does not name gets. The interface note also has the sentry answer
// NXDOMAIN for a name the table does not carry, and Go's resolver reports that
// as "no such host" before any connect happens — so for a name left out of the
// table the refusal can arrive at either place, and the harness has to know
// both to be able to say which it was.
const (
	unreachable = "network is unreachable"
	notFound    = "no such host"
)

// refusalIn is which of the two a run's output carries, or "" if neither.
func refusalIn(said string) string {
	for _, phrase := range []string{unreachable, notFound} {
		if strings.Contains(said, phrase) {
			return phrase
		}
	}
	return ""
}

func TestAdapterLoopback(t *testing.T) {
	// The skip is first and cheap: a tree without a runsc and without the live
	// variable pays nothing.
	if os.Getenv(liveEnv) != "1" {
		t.Skipf("this run spends money on the model and needs a runsc with the adapter: set %s=1 and %s to the binary", liveEnv, runscEnv)
	}
	runsc := os.Getenv(runscEnv)
	if info, err := os.Stat(runsc); err != nil || info.IsDir() {
		t.Skipf("%s=%q is not a runsc this test can start: %v", runscEnv, runsc, err)
	}
	if os.Getenv("ANTHROPIC_API_KEY") == "" {
		t.Fatalf("%s=1 and no ANTHROPIC_API_KEY in the environment: the agent inside the sandbox needs it", liveEnv)
	}

	out := newRecord(os.Stdout)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	l := newLoopback(t, ctx, out, runsc, proof{
		title: "The adapter over loopback",
		preamble: "Two runsc sandboxes. The workload is this package built with `CGO_ENABLED=0` and run as " +
			"`/agent-probe -network plain -task summarize -dir /tmp`, which is `&http.Client{}`: no contract, no " +
			"dialer of its own, Go's own resolver. The only difference between the two sandboxes is the table.",
		allow: modelHost + ":443," + docHost + ":443",
		under: "ticket25/loopback",
	})
	l.buildRootfs(t)

	// The table is the only variable. The control's is the same document with
	// one name taken out of it.
	probe := workload{
		args: []string{"/agent-probe", "-network", "plain", "-task", "summarize", "-dir", "/tmp"},
		env:  []string{"PATH=/", "HOME=/tmp", "SSL_CERT_FILE=" + anchors},
		cwd:  "/tmp",
		mounts: []any{
			map[string]any{"destination": "/proc", "type": "proc", "source": "proc"},
			// The one writable place in the sandbox, and where -dir puts
			// summary.txt. It is a tmpfs in the spec so that the rootfs can
			// stay read-only and nothing the workload writes reaches the host.
			map[string]any{"destination": "/tmp", "type": "tmpfs", "source": "tmpfs",
				"options": []string{"rw", "nosuid", "nodev", "mode=1777"}},
		},
	}
	work := l.sandbox(t, "workload", map[string]int{modelHost: tunnelledPort, docHost: tunnelledPort}, probe)
	control := l.sandbox(t, "control", map[string]int{docHost: tunnelledPort}, probe)

	if l.adapter {
		if work.err != nil {
			t.Errorf("the workload sandbox ended with %v; with both names in its table the task is meant to complete", work.err)
		}
		if said := l.said(work.stdout); !strings.Contains(said, "DONE") {
			t.Errorf("the workload's transcript does not end in the model's last word:\n%s", said)
		}
		if dialed := work.at.matching("EXIT dialed " + modelHost + ":443"); len(dialed) == 0 {
			t.Errorf("the exit never dialed %s:443, so the model request did not travel over the tunnel: %v", modelHost, work.at.matching("EXIT"))
		}
		if control.err == nil {
			t.Error("the control sandbox completed its task, and its table does not name the model's endpoint")
		}
		said := l.said(control.stderr) + l.said(control.stdout)
		switch refused := refusalIn(said); refused {
		case "":
			t.Errorf("the control failed, but not with either refusal the adapter can produce:\n%s", said)
		case unreachable:
			out.logf("\nFINDING the control was refused at the connect: %q, which is ENETUNREACH and is the word the ticket uses.", refused)
		default:
			out.logf("\nFINDING the control was refused at the resolver and never reached a connect: %q. The ticket says the off-policy name is refused with ENETUNREACH, and ENETUNREACH is what a connect to an address the table does not name gets; the interface note makes the sentry answer NXDOMAIN for a name the table does not carry, and Go's resolver reports that as %q before any connect happens. Both are the refusal and only one of them can be first — which is a finding about where the refusal lands, and it is why the seccheck event and not the errno is the thing that says why.", refused, notFound)
		}
		if dialed := control.at.matching("EXIT dialed " + modelHost); len(dialed) != 0 {
			t.Errorf("the exit dialed %s for the control, and the control's table does not name it: %v", modelHost, dialed)
		}
	} else {
		// The rehearsal. A stock runsc has no adapter and --network=none, so
		// both sandboxes must fail to reach the model, and the only thing the
		// run establishes is that everything around the adapter works.
		for _, r := range []*sandboxRun{work, control} {
			if r.err == nil {
				t.Errorf("%s: with %s=0 there is no tunnel, and the agent completed its task anyway", r.name, adapterEnv)
			}
			if said := l.said(r.stderr) + l.said(r.stdout); !strings.Contains(said, modelHost) {
				t.Errorf("%s: the failure does not name %s, so it is not the failure this rehearsal is looking for:\n%s", r.name, modelHost, said)
			}
		}
		out.logf("\nFINDING %s=0: no --tunnel-* flags were passed and no tunnel exists. This run says the bundle, the static binary, the resolver files, the CA bundle, the key plumbing and the capture all work, and says nothing whatever about the adapter.", adapterEnv)
	}

	l.record(t, "", work, control)
}

// ===== the world the two sandboxes run in =====

// A loopback is everything the two runs share: the two tunnelds, the exit, the
// rootfs, and the two directories this test writes into.
//
// There are two directories because there are two kinds of file. The rootfs,
// the binary, the tables, the debug logs and the transcripts hold no secret
// and live in the test's scratch directory. The bundle's config.json carries
// ANTHROPIC_API_KEY in process.env, so it lives under a 0700 directory in
// /dev/shm — tmpfs, never on a disk — and is removed when the test ends. The
// sockets are there too, for a shorter reason: an AF_UNIX path is 108 bytes
// and a temporary directory under /tmp is already most of one.
type loopback struct {
	ctx     context.Context
	out     *record
	runsc   string
	adapter bool

	scratch string // the rootfs, the binaries, the captures: no secrets
	shm     string // 0700 on tmpfs: the bundles, which carry the key, and the sockets
	root    string // the rootfs every bundle of this run executes
	socket  string // tunneld a's sandbox socket, which every sandbox attaches to
	p       proof  // what this run is, in the words its evidence is written in
	sha     string // the runsc this run used, by content, because the path moves

	// The four things a governed run needs of this world and an ungoverned one
	// does not (governed_test.go): the world the tunnelds were built in, so
	// that a third peer can be admitted by the same reference values; a itself,
	// so that peer can dial it; a's contract socket, so a pusher can wait until
	// there is a sandbox on it to push to; and a's console with a clock on it,
	// because a liveness teardown is a duration between two lines.
	w       *hopWorld
	aTd     *tunneld.Tunneld
	aHost   *sandbox.Host
	console *timeline

	// pushing is the pusher whose push is in flight, so that a's own clock on
	// Apply — which runs on a's goroutine and not the pusher's — lands on the
	// push it belongs to.
	pushing atomic.Pointer[pusher]

	// stateIn puts --root somewhere other than the run's own directory. A
	// pushed policy is delivered over the sentry's control socket, whose path
	// is --root plus runsc-<container id>.sock, and a sockaddr_un holds 108
	// bytes — so a deep root is a sandbox that cannot be narrowed at all
	// (spike E1 §7a). A run that pushes keeps its root short.
	stateIn string

	// points are the seccheck points this run's trace session names. The
	// default is the one ticket 25 recorded; a run that pushes an x adds the
	// point an exec refusal is emitted on.
	points []string

	// at is the run in progress, or nil between runs. The exit logs and
	// carries streams for whichever sandbox is running, and this is how those
	// lines find the run they belong to. now is the same run, for a caller
	// outside it that needs the container `runsc kill` names.
	at  atomic.Pointer[stamps]
	now atomic.Pointer[sandboxRun]
}

// A proof is what one of the two tests in this package is, in the terms its
// evidence needs: what the record is called, what the first paragraph of it
// says, where it goes under docs/snp/evidence, and what the exit may dial.
type proof struct {
	title    string
	preamble string
	allow    string
	under    string
}

// newLoopback builds the two directories and the two tunnelds. The rootfs is
// the caller's: the two tests in this package put different things inside the
// sandbox and share everything around it.
func newLoopback(t *testing.T, ctx context.Context, out *record, runsc string, p proof) *loopback {
	t.Helper()
	l := &loopback{ctx: ctx, out: out, runsc: runsc, p: p, adapter: os.Getenv(adapterEnv) != "0",
		points: []string{"sentry/egress_refused"}}
	// The binary by content and not by path. A pinned copy in a scratch
	// directory is still a path, and two runs of this test are only comparable
	// if the record says which build each of them ran.
	l.sha = sha256Of(t, runsc)
	l.scratch = t.TempDir()

	shm, err := os.MkdirTemp("/dev/shm", "t25-")
	if err != nil {
		t.Fatalf("a tmpfs directory for the bundles and the sockets: %v", err)
	}
	if err := os.Chmod(shm, 0o700); err != nil {
		t.Fatalf("%s: %v", shm, err)
	}
	l.shm = shm
	t.Cleanup(func() { os.RemoveAll(shm) })

	l.buildTunnelds(t)
	if !l.adapter {
		out.logf("%s=0: this run passes no --tunnel-socket and no --tunnel-table, and the sandbox has no network at all", adapterEnv)
	}
	return l
}

// buildTunnelds brings up a and b with the fake platform, the exit behind b,
// and the socket the sandboxes attach to in front of a. It is twohops_test.go's
// world with two tunnelds instead of three and a runsc where its middle agent
// was.
func (l *loopback) buildTunnelds(t *testing.T) {
	t.Helper()
	w := newWorld(t, l.ctx, l.out, "")
	l.w = w

	// b first, because a's peer table needs its address. b pushes nothing: the
	// far end of this arrangement is an exit and an exit holds no policy.
	b := w.start(t, "b", bImage, nil, "", nil)
	bSocket := filepath.Join(l.shm, "b.sock")
	bHost, err := sandbox.Listen(bSocket, b, w.logf("b"))
	if err != nil {
		t.Fatalf("b's sandbox socket: %v", err)
	}
	t.Cleanup(func() { bHost.Close() })
	b.Attach(bHost)
	l.serveExit(t, bSocket)

	// a pushes ticket 23's policy, so that the document naming the two
	// destinations crosses the tunnel and is recorded at the far end. Nothing
	// enforces it here; the exit's -allow is the enforcement point and the
	// sentry's table is the near one.
	a := w.start(t, "a", aImage, tunneld.PeerTable{"b": b.Addr().String()}, p0, l.aRefused)
	l.socket = filepath.Join(l.shm, "a.sock")
	aHost, err := sandbox.Listen(l.socket, a, l.aSays(w.logf("a")))
	if err != nil {
		t.Fatalf("a's sandbox socket: %v", err)
	}
	t.Cleanup(func() { aHost.Close() })
	l.aTd, l.aHost = a, aHost
	// The wrapper is a's own clock on a push, and nothing else: it embeds the
	// host, so the sandbox a tunneld sees is still the one that says which
	// policy it is enforcing. A run in which nobody pushes at a — every run
	// ticket 25 recorded — never reaches it.
	a.Attach(&appliedAt{Host: aHost, l: l})
	l.out.logf("a serves the contract on %s and dials b at %s", l.socket, b.Addr())
}

// serveExit is ticket 23's exit, unchanged and in this process: socketSandbox
// and ServeExit, which is exactly what `-exit -network socket` runs. The
// Network it is given is wrapped so that the harness can time the streams
// crossing it without the exit knowing.
func (l *loopback) serveExit(t *testing.T, socket string) {
	t.Helper()
	allow, err := parseAllow(l.p.allow)
	if err != nil {
		t.Fatalf("the exit's allow list: %v", err)
	}
	box, client, err := socketSandbox(socket, l.exitLog)
	if err != nil {
		t.Fatalf("attaching the exit to b: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	go func() {
		if err := ServeExit(l.ctx, &tapped{Network: box, at: l.at.Load}, allow, l.exitLog); err != nil && l.ctx.Err() == nil {
			l.out.logf("exit  stopped serving: %v", err)
		}
	}()
}

// exitLog is the exit's voice. Every line goes to the transcript and to the
// run in progress, which is where the assertions about what the exit dialed
// read them back from.
func (l *loopback) exitLog(format string, a ...any) {
	line := fmt.Sprintf(format, a...)
	l.out.logf("exit  %s", line)
	if at := l.at.Load(); at != nil {
		at.line(line)
	}
}

// ===== the bundle =====

// buildRootfs writes the read-only half of both bundles: one static binary and
// the four files a Go program needs to resolve a name and trust a certificate.
//
// CGO_ENABLED=0 is not a convenience. It gives a binary a rootfs of five files
// can run, and it gives Go's own resolver — which reads /etc/nsswitch.conf and
// /etc/resolv.conf and therefore asks 127.0.0.53, the address the sentry
// answers on. A cgo build would ask glibc's resolver, which is not in the
// rootfs at all.
func (l *loopback) buildRootfs(t *testing.T) {
	t.Helper()
	l.root = filepath.Join(l.scratch, "rootfs")
	for _, dir := range []string{"etc/ssl/certs", "tmp", "proc"} {
		if err := os.MkdirAll(filepath.Join(l.root, dir), 0o755); err != nil {
			t.Fatalf("the rootfs: %v", err)
		}
	}

	// The toolchain has to be on PATH. A tree without one skips rather than
	// failing: there is nothing to prove about the adapter if the thing that
	// goes inside the sandbox cannot be built at all.
	tool, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("no go on PATH to build the workload with (try PATH=/usr/local/go/bin:$PATH): %v", err)
	}
	cmd := exec.Command(tool, "build", "-o", filepath.Join(l.root, "agent-probe"), ".")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if built, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the workload: %v\n%s", err, built)
	}

	// The three files the resolver reads. `hosts: files dns` is spelled out
	// rather than left to the default because the default differs between
	// distributions and the point of this rootfs is that it has no opinions
	// this test did not write down.
	for name, text := range map[string]string{
		"etc/resolv.conf":   "nameserver 127.0.0.53\noptions timeout:5 attempts:2\n",
		"etc/hosts":         "127.0.0.1\tlocalhost\n::1\tlocalhost\n",
		"etc/nsswitch.conf": "hosts: files dns\n",
	} {
		if err := os.WriteFile(filepath.Join(l.root, name), []byte(text), 0o644); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}

	certs, err := os.ReadFile(anchors)
	if err != nil {
		t.Skipf("no %s on this host to give the workload: %v", anchors, err)
	}
	if err := os.WriteFile(filepath.Join(l.root, anchors), certs, 0o644); err != nil {
		t.Fatalf("the CA bundle: %v", err)
	}
	l.out.logf("the rootfs is %s: one static agent-probe, resolv.conf/hosts/nsswitch.conf and %d bytes of anchors", l.root, len(certs))
}

// A workload is the part of a bundle that differs between the two tests: what
// to run, where, with which variables beside the key, whether the rootfs may
// be written, and what is mounted over it.
type workload struct {
	args     []string
	env      []string // ANTHROPIC_API_KEY is added by bundle and is not here
	cwd      string
	writable bool // the rootfs is read-write, for a workload that needs a HOME
	mounts   []any
}

// bundle writes one OCI bundle. Only config.json is written here, under the
// tmpfs directory, because process.env carries the key; root.path is absolute
// and points back at the rootfs in the scratch directory, which holds nothing
// secret and is what the sandbox actually executes.
func (l *loopback) bundle(t *testing.T, name string, w workload) string {
	t.Helper()
	dir := filepath.Join(l.shm, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("the bundle directory: %v", err)
	}
	spec := map[string]any{
		"ociVersion": "1.0.0",
		"process": map[string]any{
			"terminal": false,
			"user":     map[string]any{"uid": 0, "gid": 0},
			"args":     w.args,
			// The key is appended here and nowhere else, so that a caller
			// cannot forget it and cannot put it anywhere but this file.
			"env":          append(append([]string{}, w.env...), "ANTHROPIC_API_KEY="+os.Getenv("ANTHROPIC_API_KEY")),
			"cwd":          w.cwd,
			"capabilities": map[string]any{"bounding": []string{}, "effective": []string{}, "inheritable": []string{}, "permitted": []string{}},
			"rlimits":      []any{map[string]any{"type": "RLIMIT_NOFILE", "hard": 4096, "soft": 4096}},
		},
		"root":     map[string]any{"path": l.root, "readonly": !w.writable},
		"hostname": "workload",
		"mounts":   w.mounts,
		"linux": map[string]any{"namespaces": []any{
			map[string]any{"type": "pid"},
			map[string]any{"type": "mount"},
			map[string]any{"type": "ipc"},
			map[string]any{"type": "uts"},
		}},
	}
	text, err := json.MarshalIndent(spec, "", "\t")
	if err != nil {
		t.Fatalf("the spec: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), text, 0o600); err != nil {
		t.Fatalf("config.json: %v", err)
	}
	return dir
}

// ===== the table =====

// A tunnelTable is the document --tunnel-table names, in the interface note's
// spelling: exact host names, one permitted port each, and the tunneld peer
// whose exit dials them.
type tunnelTable struct {
	DefaultExit string                 `json:"default_exit"`
	Names       map[string]tunnelEntry `json:"names"`
}

type tunnelEntry struct {
	Port int    `json:"port"`
	Peer string `json:"peer,omitempty"`
}

// ===== one sandbox =====

// A sandboxRun is one runsc container: what it was given, what it left behind
// and how it ended.
type sandboxRun struct {
	name    string
	names   []string // the host names its table carries, sorted, for the record
	dir     string   // everything this run wrote
	stdout  string
	stderr  string
	debug   string
	table   string
	digest  string   // the page of what the strace log says, written after the run
	comms   []string // the command names the sentry traced, which is what actually ran
	tunnel  []string // the adapter's own lines: every query it answered and every attach
	events  string   // the seccheck receiver's output, empty when there was none
	args    []string
	id      string // the container id, for a `runsc kill` from outside
	root    string // --root, which is also where the control socket is
	status  int
	err     error
	began   time.Time // when runsc was started, so that a line elsewhere can be placed against it
	elapsed time.Duration
	at      *stamps
}

// stateDir is --root for this run and the container id under it, which is the
// pair the sentry's control socket path is made of: --root plus
// runsc-<id>.sock, and that socket is where a pushed policy is delivered. A
// sockaddr_un holds 108 bytes, so a path over it is EINVAL at the connect and
// the peer that pushed is told its policy did not land — spike E1 §7a, found
// the hard way. Saying so here is cheaper than reading it out of a refusal,
// and it is why a run that pushes is given a shallower root than its own
// directory.
func (l *loopback) stateDir(t *testing.T, name, dir string) (root, id string) {
	t.Helper()
	root = filepath.Join(dir, "state")
	if l.stateIn != "" {
		root = filepath.Join(l.stateIn, name+"-state")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("%s: %v", root, err)
	}
	id = fmt.Sprintf("t25-%s-%d", name, os.Getpid())
	if sock := filepath.Join(root, "runsc-"+id+".sock"); len(sock) >= 108 {
		t.Fatalf("the control socket would be %d bytes at %s, and a sockaddr_un holds 108: no policy could be pushed into this sandbox (spike E1 §7a)", len(sock), sock)
	}
	return root, id
}

// sandbox writes one bundle, runs runsc over it and captures everything.
func (l *loopback) sandbox(t *testing.T, name string, names map[string]int, w workload) *sandboxRun {
	t.Helper()
	r := &sandboxRun{name: name, dir: filepath.Join(l.scratch, name), at: &stamps{at: map[string]time.Duration{}}}
	r.debug = filepath.Join(r.dir, "debug")
	if err := os.MkdirAll(r.debug, 0o700); err != nil {
		t.Fatalf("%s: %v", r.dir, err)
	}
	r.stdout, r.stderr = filepath.Join(r.dir, "stdout.txt"), filepath.Join(r.dir, "stderr.txt")
	r.table = filepath.Join(r.dir, "table.json")

	table := tunnelTable{DefaultExit: "b", Names: map[string]tunnelEntry{}}
	for host, port := range names {
		table.Names[host] = tunnelEntry{Port: port}
		r.names = append(r.names, fmt.Sprintf("%s:%d", host, port))
	}
	sort.Strings(r.names)
	text, err := json.MarshalIndent(table, "", "\t")
	if err != nil {
		t.Fatalf("the table: %v", err)
	}
	if err := os.WriteFile(r.table, text, 0o644); err != nil {
		t.Fatalf("%s: %v", r.table, err)
	}

	podInit, stop := l.receiver(t, r)
	defer stop()

	r.root, r.id = l.stateDir(t, name, r.dir)
	// S1's flag set, unchanged, plus the two the adapter adds. --network=none
	// is required with them and is what the sandbox has either way: the only
	// stack inside it is loopback, and every address the workload reaches is
	// either 127.0.0.53 or a synthetic one the sentry allocated.
	r.args = []string{
		"--root=" + r.root,
		"--platform=systrap",
		"--network=none",
		"--ignore-cgroups",
		"--rootless",
		"--gofer-network-namespace=new",
	}
	if l.adapter {
		r.args = append(r.args, "--tunnel-socket="+l.socket, "--tunnel-table="+r.table)
	}
	if podInit != "" {
		r.args = append(r.args, "--pod-init-config="+podInit)
	}
	r.args = append(r.args,
		"--debug", "--debug-log="+r.debug+"/", "--strace",
		"run", "--bundle", l.bundle(t, name, w), r.id)

	l.out.logf("\n===== sandbox %s =====", name)
	l.out.logf("%s  table = %s", name, text)
	l.out.logf("%s  $ %s %s", name, l.runsc, strings.Join(r.args, " "))

	capture := create(t, r.stdout, r.stderr)
	so, se := capture[0], capture[1]
	cmd := exec.CommandContext(l.ctx, l.runsc, r.args...)
	cmd.Stdout, cmd.Stderr = so, se

	// The clock is set before the pointer is published, not after: the exit
	// runs in its own goroutine and marks the moment it sees a stream, so a
	// zero written after the Store would be a write racing that goroutine's
	// read. The Store is the release that makes it visible.
	began := time.Now()
	r.at.zero, r.began = began, began
	l.at.Store(r.at)
	l.now.Store(r)
	r.err = cmd.Run()
	r.elapsed = time.Since(began)
	r.at.mark("task_end")
	l.at.Store(nil)
	l.now.Store(nil)
	so.Close()
	se.Close()
	if cmd.ProcessState != nil {
		r.status = cmd.ProcessState.ExitCode()
	}

	l.digest(t, r)
	l.out.logf("%s  runsc ended with status %d after %s (err=%v)", name, r.status, r.elapsed.Round(time.Millisecond), r.err)
	l.out.logf("\n%s  said on stdout:\n%s", name, l.said(r.stdout))
	if said := strings.TrimSpace(l.said(r.stderr)); said != "" {
		l.out.logf("\n%s  said on stderr:\n%s", name, said)
	}
	l.out.logf("%s  %s", name, r.at.timings())
	return r
}

// receiver starts the seccheck receiver and writes the trace session that
// sends sentry/egress_refused to it. Both are optional: the receiver is the
// sentry-side agent's deliverable and may not exist yet, and a run without it
// records no event and asserts the refusal on the workload's errno instead.
//
// The contract with the receiver is the one examples/seccheck's server has:
// argv[1] is the socket to listen on, and it prints one line per message.
func (l *loopback) receiver(t *testing.T, r *sandboxRun) (string, func()) {
	t.Helper()
	nothing := func() {}
	binary := os.Getenv(receiverEnv)
	if binary == "" {
		l.out.logf("%s  %s is unset: no seccheck receiver, so this run records no sentry/egress_refused event", r.name, receiverEnv)
		return "", nothing
	}
	if !l.adapter {
		l.out.logf("%s  %s=0: a stock runsc has no sentry/egress_refused point, so the trace session is left out", r.name, adapterEnv)
		return "", nothing
	}
	if _, err := os.Stat(binary); err != nil {
		l.out.logf("%s  %s=%q is not a receiver this test can start (%v): no event is recorded", r.name, receiverEnv, binary, err)
		return "", nothing
	}

	socket := filepath.Join(l.shm, r.name+".events")
	r.events = filepath.Join(r.dir, "seccheck.txt")
	sink := create(t, r.events)[0]
	cmd := exec.CommandContext(l.ctx, binary, socket)
	cmd.Stdout, cmd.Stderr = sink, sink
	if err := cmd.Start(); err != nil {
		sink.Close()
		l.out.logf("%s  the seccheck receiver would not start (%v): no event is recorded", r.name, err)
		r.events = ""
		return "", nothing
	}
	// The sink socket has to exist before runsc connects to it, and the
	// receiver binds it after it starts. Waiting for the path is the only
	// handshake there is.
	for waited := time.Duration(0); waited < 5*time.Second; waited += 50 * time.Millisecond {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	points := make([]any, 0, len(l.points))
	for _, name := range l.points {
		points = append(points, map[string]any{"name": name, "context_fields": []string{"time", "container_id", "thread_id"}})
	}
	session := map[string]any{"trace_session": map[string]any{
		"name":   "Default",
		"points": points,
		"sinks": []any{map[string]any{
			"name":               "remote",
			"config":             map[string]any{"endpoint": socket, "retries": 3},
			"ignore_setup_error": true,
		}},
	}}
	text, err := json.MarshalIndent(session, "", "\t")
	if err != nil {
		t.Fatalf("the trace session: %v", err)
	}
	path := filepath.Join(r.dir, "pod-init.json")
	if err := os.WriteFile(path, text, 0o644); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	l.out.logf("%s  the seccheck receiver is %s on %s, recording %s", r.name, binary, socket, strings.Join(l.points, " and "))
	return path, func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		cmd.Wait()
		sink.Close()
	}
}

// ===== the clock =====

// A stamps is one run's clock and one run's copy of what the exit said. The
// four times the ticket asks for are the first occurrence of each of four
// things, measured from the moment runsc started.
type stamps struct {
	// lineLog is what the exit said during this run, and it carries its own
	// lock: the assertions read it after the run and the exit writes it during
	// one, which is a different question from the clock below.
	lineLog

	mu   sync.Mutex
	zero time.Time
	at   map[string]time.Duration
}

// A lineLog is the lines one side of a harness said, kept so that a test can
// assert on them afterwards. There is one of it because both harnesses in this
// package want exactly this and neither wants anything more.
//
// It is a [timeline] whose clock nobody reads: "was this said" is that type's
// own filter taken from the zero time, so the lines, the lock and the search
// are written once next door rather than twice.
type lineLog struct {
	timeline
}

// matching is the remembered lines that carry prefix.
func (l *lineLog) matching(prefix string) []string {
	var found []string
	for _, said := range l.after(time.Time{}, prefix) {
		found = append(found, said.text)
	}
	return found
}

// mark records the first time something happened and ignores every later one.
func (s *stamps) mark(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.zero.IsZero() {
		return
	}
	if _, already := s.at[name]; !already {
		s.at[name] = time.Since(s.zero)
	}
}

// line keeps what the exit said and reads the one timing that is only visible
// in a log line: serveConnect answers OK after it has dialed, so the line is
// the first CONNECT having been read, checked and satisfied.
func (s *stamps) line(text string) {
	s.add(text)
	if strings.HasPrefix(text, "EXIT accepted") {
		s.mark("tunnel_open")
	}
	if strings.HasPrefix(text, "EXIT dialed") {
		s.mark("first_connect")
	}
}

// timings is the one line a run prints and the README repeats. A thing that
// never happened says so rather than reading as zero, because in the control's
// run three of the four are meant not to happen.
func (s *stamps) timings() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	parts := make([]string, 0, 4)
	for _, name := range []string{"tunnel_open", "first_connect", "first_byte", "task_end"} {
		if took, ok := s.at[name]; ok {
			parts = append(parts, fmt.Sprintf("%s=%s", name, took.Round(time.Millisecond)))
		} else {
			parts = append(parts, name+"=never")
		}
	}
	return "TIMING " + strings.Join(parts, " ")
}

// tapped is the exit's Network with the harness's clock on it, and the only
// place outside the sentry where this arrangement's streams can be timed.
type tapped struct {
	sandbox.Network
	at func() *stamps
}

func (n *tapped) Accept(ctx context.Context) (sandbox.Stream, sandbox.Attested, error) {
	s, who, err := n.Network.Accept(ctx)
	if err != nil {
		return s, who, err
	}
	return &tappedStream{Stream: s, at: n.at}, who, nil
}

// tappedStream stamps the first byte the exit sends back down the tunnel.
//
// It counts writes rather than reading any: serveConnect writes exactly one
// line — OK host:port — before it starts pumping, so the second write on a
// stream is the first byte the destination answered with. After that line the
// stream is TLS and the whole claim being recorded is that this side sees
// ciphertext, so a harness that looked at the bytes to find the same instant
// would be disproving the thing it is here to prove.
type tappedStream struct {
	sandbox.Stream
	at     func() *stamps
	writes atomic.Int64
}

func (s *tappedStream) Write(p []byte) (int, error) {
	if s.writes.Add(1) == 2 {
		if at := s.at(); at != nil {
			at.mark("first_byte")
		}
	}
	return s.Stream.Write(p)
}

// ===== the evidence =====

// record copies both runs' captures into the evidence directory and writes the
// README beside them.
//
// Nothing is copied before it has been searched for the key. A file that
// carries it is left behind and a redacted copy is put in its place, which is
// not a formality: runsc logs the container's spec at debug level, and the
// spec is where process.env is.
func (l *loopback) record(t *testing.T, notes string, runs ...*sandboxRun) {
	t.Helper()
	dest := os.Getenv(evidenceEnv)
	if dest == "" {
		tree, err := filepath.Abs("../../..")
		if err != nil {
			t.Fatalf("the worktree root: %v", err)
		}
		dest = filepath.Join(tree, "docs/snp/evidence", l.p.under, time.Now().Format("20060102-150405"))
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatalf("%s: %v", dest, err)
	}

	var withheld []string
	for _, r := range runs {
		copied, held := l.copyInto(t, r.dir, filepath.Join(dest, r.name))
		l.out.logf("%s  %d files copied to %s, %d withheld for carrying the key", r.name, copied, filepath.Join(dest, r.name), len(held))
		withheld = append(withheld, held...)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# %s: %s\n\n", l.p.title, time.Now().Format(time.RFC3339))
	fmt.Fprintf(&b, "runsc is `%s`\n(sha256 `%s`); the adapter flags were %s. The tunnelds `a` and `b` are in the test's own "+
		"process with the fake SNP platform, and ticket 23's exit — `socketSandbox` and `ServeExit`, unchanged — "+
		"is attached to `b` with `-allow %s`.\n\n%s\n\n", l.runsc, l.sha, present(l.adapter), l.p.allow, l.p.preamble)
	if note := os.Getenv(noteEnv); note != "" {
		fmt.Fprintf(&b, "%s\n\n", note)
	}
	fmt.Fprintf(&b, "A file here whose name ends `.redacted` is one that carried `ANTHROPIC_API_KEY`: the original "+
		"was not copied and this is it with the key replaced. One ending `.gz` was over %d MiB and is kept "+
		"compressed rather than trimmed.\n\n", bigFile>>20)

	fmt.Fprintf(&b, "| run | the names its table carries | runsc status | wall | timings |\n|---|---|---|---|---|\n")
	for _, r := range runs {
		fmt.Fprintf(&b, "| %s | `%s` | %d | %s | `%s` |\n", r.name, strings.Join(r.names, ", "), r.status,
			r.elapsed.Round(time.Millisecond), strings.TrimPrefix(r.at.timings(), "TIMING "))
	}
	fmt.Fprintf(&b, "\nThe four timings are measured from the moment `runsc` started. `tunnel_open` is the exit "+
		"accepting the first stream, `first_connect` is the exit answering `OK` for the first `CONNECT` line, "+
		"`first_byte` is the first byte the destination sent back down that stream, and `task_end` is `runsc` "+
		"exiting. Three of the four are taken at the exit because that is the only place in this arrangement "+
		"where the harness and the bytes meet.\n\n")

	for _, r := range runs {
		fmt.Fprintf(&b, "## %s\n\n```\n%s %s\n```\n\n", r.name, l.runsc, strings.Join(r.args, " "))
		if dialed := r.at.matching("EXIT"); len(dialed) != 0 {
			fmt.Fprintf(&b, "What the exit saw, which is host, port and ciphertext and nothing else:\n\n```\n%s\n```\n\n",
				strings.Join(dialed, "\n"))
		} else {
			fmt.Fprintf(&b, "The exit saw nothing: no stream reached it in this run.\n\n")
		}
		if len(r.tunnel) != 0 {
			fmt.Fprintf(&b, "What the adapter inside the sentry did — every name it answered and every stream it "+
				"asked for, in its own words:\n\n```\n%s\n```\n\n", strings.Join(r.tunnel, "\n"))
		} else {
			fmt.Fprintf(&b, "The adapter said nothing in this run's log.\n\n")
		}
		if r.events == "" {
			fmt.Fprintf(&b, "No `sentry/egress_refused` event was recorded: `%s` was not set, so no receiver was "+
				"listening on the remote sink. The refusal is asserted on the errno the workload reported.\n\n", receiverEnv)
			continue
		}
		fmt.Fprintf(&b, "What the seccheck receiver printed, which is the sentry's own account of the refusal and "+
			"the only place the reason for it is written down:\n\n```\n%s\n```\n\n", strings.TrimSpace(l.said(r.events)))
	}

	if notes != "" {
		fmt.Fprintf(&b, "%s\n", notes)
	}

	if len(withheld) != 0 {
		fmt.Fprintf(&b, "## Withheld\n\nThese files matched `ANTHROPIC_API_KEY` and were not copied. A "+
			"`.redacted` copy of each is here in its place.\n\n")
		for _, line := range withheld {
			fmt.Fprintf(&b, "- %s\n", line)
		}
		fmt.Fprintf(&b, "\nThe sentry writes the container's spec into its debug log, and `process.env` is in the "+
			"spec. A debug run of this bundle therefore always has the key in the log, which is why the bundle's "+
			"`config.json` lives on tmpfs and why nothing here is copied before it has been searched.\n")
	}

	readme := filepath.Join(dest, "README.md")
	if err := os.WriteFile(readme, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("%s: %v", readme, err)
	}
	l.out.logf("the evidence is in %s", dest)
}

// copyInto copies one run's captures, file by file, and never copies one that
// carries the key. It reports how many were copied and one sentence about each
// one that was not — the count of matches and never a byte of what matched.
func (l *loopback) copyInto(t *testing.T, from, to string) (int, []string) {
	t.Helper()
	key := []byte(os.Getenv("ANTHROPIC_API_KEY"))
	copied := 0
	var withheld []string
	err := filepath.Walk(from, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !info.Mode().IsRegular() {
			return err
		}
		rel, err := filepath.Rel(from, path)
		if err != nil {
			return err
		}
		text, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out := filepath.Join(to, rel)
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		if n := bytes.Count(text, key); n != 0 && len(key) != 0 {
			clean := bytes.ReplaceAll(text, key, []byte("<ANTHROPIC_API_KEY>"))
			if bytes.Contains(clean, key) {
				t.Errorf("%s still carries the key after redaction and is not being written anywhere", rel)
				return nil
			}
			withheld = append(withheld, fmt.Sprintf("`%s`: the key appears %s", filepath.Join(filepath.Base(to), rel), times(n)))
			return keep(out+".redacted", clean)
		}
		copied++
		return keep(out, text)
	})
	if err != nil {
		t.Errorf("copying %s: %v", from, err)
	}
	return copied, withheld
}

// bigFile is where "put it in the evidence as it is" turns into "put it there
// compressed". Four mebibytes is the size of the largest thing already
// committed under docs/.
const bigFile = 4 << 20

// keep puts one file in the evidence, gzipped once it is big enough that a
// repository would notice. A sentry debug log with --strace is tens of
// megabytes of repetitive text and compresses about thirteen to one, so the
// whole of it can be kept — and a trimmed trace is not a trace, it is a claim
// about one.
func keep(path string, text []byte) error {
	if len(text) < bigFile {
		return os.WriteFile(path, text, 0o644)
	}
	f, err := os.Create(path + ".gz")
	if err != nil {
		return err
	}
	z := gzip.NewWriter(f)
	if _, err := z.Write(text); err != nil {
		f.Close()
		return err
	}
	if err := z.Close(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// ===== what the strace log says =====

// digest is a page of what a tens-of-megabytes --strace log contains: which
// syscalls failed and with what, every exec, every bind and listen, the socket
// families, how many datagrams went to the resolver, and what the sentry said
// it does not implement. The log itself is kept beside it; this is the part a
// reader reads, and it is written into the run's directory so that it is
// copied and searched for the key like everything else.
func (l *loopback) digest(t *testing.T, r *sandboxRun) {
	t.Helper()
	boot := ""
	entries, err := os.ReadDir(r.debug)
	if err != nil {
		return
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".boot.") {
			boot = filepath.Join(r.debug, e.Name())
		}
	}
	if boot == "" {
		l.out.logf("%s  no sentry debug log to digest", r.name)
		return
	}
	f, err := os.Open(boot)
	if err != nil {
		t.Errorf("%s: %v", boot, err)
		return
	}
	defer f.Close()

	failed, families, unsupported, comms := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	// The three things the adapter says about itself, which are the only
	// account anywhere of what the sandbox asked the network for: --strace
	// cannot give it, because gVisor formats a sendto buffer as a pointer and
	// a DNS query's payload never reaches the log.
	// "tunnel narrow: " and "exec refused: " are the sentry's account of a
	// pushed policy landing and of an execve the policy in force did not name.
	// A run in which nobody pushes has neither.
	marks := []string{"tunnel dns: ", "tunnel attach: ", "tunnel: refused ", "tunnel narrow: ", "exec refused: "}
	var execs, binds []string
	resolver := 0
	sc := bufio.NewScanner(f)
	// A strace line carries up to --strace-log-size of arguments, and the
	// default scanner buffer is 64 KiB, which some of them exceed.
	sc.Buffer(make([]byte, 0, 1<<16), 1<<22)
	for sc.Scan() {
		line := sc.Text()
		for _, mark := range marks {
			if i := strings.Index(line, mark); i >= 0 {
				r.tunnel = append(r.tunnel, line[i:])
				break
			}
		}
		if i := strings.Index(line, "Unsupported syscall "); i >= 0 {
			if name, _, ok := strings.Cut(line[i+len("Unsupported syscall "):], "("); ok {
				unsupported[name]++
			}
			continue
		}
		// The command name is on every traced line and is the only thing that
		// says which binary made the call, which for the first process is the
		// only evidence that it ran at all: the sentry execs it itself, so
		// there is no execve line for it the way there is for its children.
		if before, _, ok := strings.Cut(line, " E "); ok {
			if words := strings.Fields(before); len(words) != 0 {
				comms[words[len(words)-1]]++
			}
		}
		_, call, ok := strings.Cut(line, " X ")
		if !ok {
			continue // an entry line says nothing about how it went
		}
		name, args, ok := strings.Cut(call, "(")
		if !ok {
			continue
		}
		if i := strings.Index(call, " errno="); i >= 0 {
			// errno=2 (no such file or directory), whole: the number alone
			// makes a reader look it up and the sentry already spelled it.
			tail := call[i+1:]
			if j := strings.Index(tail, ")"); j >= 0 {
				tail = tail[:j+1]
			}
			failed[name+" "+tail]++
		}
		switch name {
		case "execve":
			// The third argument is the environment, and the environment is
			// where the key is. What this digest is for is the argv — which
			// binary was run and how — so the line is cut at the end of it.
			if i := strings.Index(call, "], "); i >= 0 {
				call = call[:i+1] + " <env>)"
			}
			execs = append(execs, call)
		case "bind", "listen":
			binds = append(binds, call)
		case "socket":
			families[firstWords(args, 1)]++
		}
		if strings.Contains(call, "127.0.0.53, Port: 53") {
			resolver++
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# what %s says\n\nThe sentry's debug log with --strace, read once. Counts are of exit\n"+
		"lines, so an entry with no exit — a syscall the process was still in when it ended — is not here.\n", filepath.Base(boot))
	fmt.Fprintf(&b, "\n## what the adapter said\n\n%s\n", strings.Join(r.tunnel, "\n"))
	fmt.Fprintf(&b, "\n## what ran\n\n%s", tally(comms))
	fmt.Fprintf(&b, "\n## syscalls that failed\n\n%s", tally(failed))
	fmt.Fprintf(&b, "\n## syscalls the sentry does not implement\n\n%s", tally(unsupported))
	fmt.Fprintf(&b, "\n## socket families\n\n%s", tally(families))
	fmt.Fprintf(&b, "\n## datagrams and connects to 127.0.0.53:53\n\n%d\n", resolver)
	fmt.Fprintf(&b, "\n## every execve\n\n%s\n", strings.Join(execs, "\n"))
	fmt.Fprintf(&b, "\n## every bind and listen\n\n%s\n", strings.Join(binds, "\n"))

	for name := range comms {
		r.comms = append(r.comms, name)
	}
	sort.Strings(r.comms)
	r.digest = filepath.Join(r.dir, "strace-digest.txt")
	if err := os.WriteFile(r.digest, []byte(b.String()), 0o644); err != nil {
		t.Errorf("%s: %v", r.digest, err)
	}
	l.out.logf("%s  %s: %d kinds of failure, %d unsupported, %d execs, %d resolver datagrams, %d adapter lines",
		r.name, filepath.Base(r.digest), len(failed), len(unsupported), len(execs), resolver, len(r.tunnel))
}

// firstWords is the first n space-separated words of a string, which is how a
// syscall's errno and a socket's family are taken out of a line without a
// second parser to keep in step with the sentry's format.
func firstWords(text string, n int) string {
	words := strings.Fields(strings.TrimLeft(text, " "))
	if len(words) > n {
		words = words[:n]
	}
	return strings.TrimRight(strings.Join(words, " "), ",")
}

// tally is a count table, highest first, as lines a person reads.
func tally(counts map[string]int) string {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%8d  %s\n", counts[k], k)
	}
	if b.Len() == 0 {
		return "(none)\n"
	}
	return b.String()
}

// ===== small things =====

// said is a captured file with the key taken out of it, for the transcript.
// The file on disk is left as it is, because the check that decides what may
// be committed has to be made against what was actually written.
func (l *loopback) said(path string) string {
	text, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("(%s could not be read: %v)", path, err)
	}
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		text = bytes.ReplaceAll(text, []byte(key), []byte("<ANTHROPIC_API_KEY>"))
	}
	return string(text)
}

// create opens every file a run captures into, in one call, so that a run
// either has all of them or fails before it has started anything.
func create(t *testing.T, paths ...string) []*os.File {
	t.Helper()
	files := make([]*os.File, 0, len(paths))
	for _, path := range paths {
		f, err := os.Create(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		files = append(files, f)
	}
	return files
}

func present(on bool) string {
	if on {
		return "passed"
	}
	return "left out (" + adapterEnv + "=0)"
}

// sha256Of is a file by content. It streams, because one of the things this
// harness hashes is a hundred megabytes of runsc.
func sha256Of(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	defer f.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		t.Fatalf("hashing %s: %v", path, err)
	}
	return hex.EncodeToString(sum.Sum(nil))
}

// times is a count with its noun, so that a record written for a reader does
// not say "1 times".
func times(n int) string {
	if n == 1 {
		return "once"
	}
	return fmt.Sprintf("%d times", n)
}
