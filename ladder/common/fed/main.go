// ladder-fed - the rung-5a federation proxy and the tools around it.
//
// Everything the ladder adds for rung 5a lives here and in ladder/rung5a/. The gVisor
// tree is untouched: the two-layer stamp of the rung-5a spec's section 2a keeps the
// inner layer exactly where rung 3 put it -- in the sentry -- and adds the outer layer
// out here, in a host-side process, where a transport key can live without an agent
// being anywhere near it.
//
//	ladder-fed keygen   --host NAME --key FILE
//	ladder-fed mailbox  --url-file FILE
//	ladder-fed enroll offer  --key FILE --address ADDR [--mailbox URL]
//	ladder-fed enroll accept --code CODE --registry FILE [--mailbox URL]
//	ladder-fed serve    --host NAME --key FILE --registry FILE --listen ADDR
//	                    --gateway SOCK --ingest SOCK [--ladder-fed]
//	                    [--service NAME=ROLEFILE ...] [--peer HOST=ADDR ...]
//	ladder-fed status   --gateway SOCK
//	ladder-fed reborn   --gateway SOCK --service NAME
//	ladder-fed attack   --case CASE ...
//	ladder-fed bench    --key FILE --registry FILE --to HOST/PEER ...
//	ladder-fed mitm     --listen ADDR --forward ADDR --mode tcp|udp
//	ladder-fed stamp    --sender NAME [--taint 0|1] ...
//
// --ladder-fed is the gate, and it is off by default like every other ladder flag. With
// it off this is plain TCP with no registry, no signature, no channel binding, no replay
// window and no role check -- which is what rungs 3 and 4 amount to once the second hop
// is on another machine. See plain.go.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "keygen":
		err = cmdKeygen(args)
	case "mailbox":
		err = cmdMailbox(args)
	case "enroll":
		err = cmdEnroll(args)
	case "serve":
		err = cmdServe(args)
	case "status":
		err = cmdStatus(args)
	case "reborn":
		err = cmdReborn(args)
	case "attack":
		err = cmdAttack(args)
	case "bench":
		err = cmdBench(args)
	case "mitm":
		err = cmdMITM(args)
	case "stamp":
		err = cmdStamp(args)
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "ladder-fed: unknown command %q\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ladder-fed %s: %v\n", cmd, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `ladder-fed - the rung-5a federation substrate

  keygen   mint a host's long-term ed25519 key
  mailbox  run the self-hosted rendezvous server for the enrolment ceremony
  enroll   offer | accept -- the one human-pace step, once per host
  serve    the federation proxy
  status   ask a running proxy what it knows
  reborn   tell a proxy a service has been destroyed and restarted
  attack   the adversarial sender, for the per-message checks
  bench    the latency table and the concurrent burst
  mitm     a man in the middle, for the baseline and the ciphertext check
  stamp    print a synthetic sentry stamp (a forgery tool; see attack.go)

See ladder/rung5a/README.md.
`)
}

// signalContext cancels on SIGINT/SIGTERM so the demo's traps clean up properly.
func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-ch
		cancel()
	}()
	return ctx, cancel
}

// ---------------------------------------------------------------- keygen

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	host := fs.String("host", "", "the name this runtime enrols under")
	out := fs.String("key", "", "where to write the keyfile (0600)")
	version := fs.String("runtime-version", "", "carried through the ceremony; NOT enforced anywhere")
	epoch := fs.Int("policy-epoch", 1, "carried through the ceremony; NOT enforced anywhere")
	_ = fs.Parse(args)
	if *host == "" || *out == "" {
		return fmt.Errorf("--host and --key are required")
	}
	id, err := GenerateIdentity(*host)
	if err != nil {
		return err
	}
	if err := SaveIdentity(id, *out, *version, *epoch); err != nil {
		return err
	}
	fmt.Printf("KEY host=%s key=%s file=%s\n", id.Host, Fingerprint(id.Pub), *out)
	return nil
}

// ---------------------------------------------------------------- mailbox / enroll

func cmdMailbox(args []string) error {
	fs := flag.NewFlagSet("mailbox", flag.ExitOnError)
	urlFile := fs.String("url-file", "", "write the websocket URL here")
	_ = fs.Parse(args)
	ctx, cancel := signalContext()
	defer cancel()
	return RunMailbox(ctx, *urlFile)
}

func cmdEnroll(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("enroll needs a subcommand: offer | accept")
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("enroll "+sub, flag.ExitOnError)
	key := fs.String("key", "", "offer: this runtime's keyfile")
	addr := fs.String("address", "", "offer: where this runtime's proxy listens")
	code := fs.String("code", "", "accept: the code the operator transcribed")
	registry := fs.String("registry", "", "accept: the registry file to append to")
	mailbox := fs.String("mailbox", "", "the self-hosted rendezvous URL")
	urlFile := fs.String("url-file", "", "read the rendezvous URL from here")
	timeout := fs.Duration("timeout", 60*time.Second, "ceremony deadline")
	_ = fs.Parse(rest)

	url, err := mailboxURL(*mailbox, *urlFile)
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()

	switch sub {
	case "offer":
		if *key == "" {
			return fmt.Errorf("enroll offer needs --key")
		}
		return EnrollOffer(ctx, *key, *addr, url, *timeout)
	case "accept":
		if *code == "" || *registry == "" {
			return fmt.Errorf("enroll accept needs --code and --registry")
		}
		return EnrollAccept(ctx, *code, *registry, url, *timeout)
	default:
		return fmt.Errorf("unknown enroll subcommand %q", sub)
	}
}

// ---------------------------------------------------------------- serve

// mapFlag collects repeatable NAME=VALUE arguments.
type mapFlag map[string]string

func (m mapFlag) String() string { return fmt.Sprint(map[string]string(m)) }
func (m mapFlag) Set(v string) error {
	name, value, found := strings.Cut(v, "=")
	if !found || name == "" {
		return fmt.Errorf("want NAME=VALUE, got %q", v)
	}
	m[name] = value
	return nil
}

// listFlag collects a repeatable string argument.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	services, peers := mapFlag{}, mapFlag{}
	cfg := ProxyConfig{}
	fs.StringVar(&cfg.Host, "host", "", "this host's enrolled name")
	fs.StringVar(&cfg.KeyPath, "key", "", "this host's keyfile")
	fs.StringVar(&cfg.RegistryPath, "registry", "", "the enrolment registry")
	fs.StringVar(&cfg.Listen, "listen", "", "where to accept peers (host:port)")
	fs.StringVar(&cfg.Gateway, "gateway", "", "unix socket the local postbox sends on")
	fs.StringVar(&cfg.Ingest, "ingest", "", "the local postbox's socket for arrivals")
	fs.StringVar(&cfg.LogPath, "log", "", "append the proxy log here as well as stdout")
	fs.BoolVar(&cfg.Fed, "ladder-fed", false,
		"THE GATE. Off: plain TCP, no registry, no signature, no binding, no replay window, "+
			"no role check -- rungs 3-4 with the second hop on another machine. On: the substrate.")
	fs.Var(services, "service", "repeatable NAME=ROLEFILE; use NAME=- for a service with no role ceiling")
	fs.Var(peers, "peer", "repeatable HOST=ADDR, overriding the address the registry carries")
	fs.IntVar(&cfg.RecycleMaxExchanges, "recycle-max-exchanges", 0, "recycle a service after this many exchanges")
	fs.DurationVar(&cfg.RecycleMaxAge, "recycle-max-age", 0, "recycle a service this long after it started")
	fs.BoolVar(&cfg.RecycleOnTaint, "recycle-on-taint", false,
		"recycle as soon as the runtime stamps taint=1 on a message this service sends")
	fs.StringVar(&cfg.RecycleLog, "recycle-log", "", "append recycle requests here for the launcher to act on")
	_ = fs.Parse(args)
	cfg.Services, cfg.Peers = services, peers

	for _, req := range []struct{ name, value string }{
		{"--host", cfg.Host}, {"--key", cfg.KeyPath}, {"--registry", cfg.RegistryPath},
		{"--listen", cfg.Listen}, {"--gateway", cfg.Gateway}, {"--ingest", cfg.Ingest},
	} {
		if req.value == "" {
			return fmt.Errorf("%s is required", req.name)
		}
	}
	// AF_UNIX paths cap at 108 bytes and the failure reads like a permission problem.
	// The broker learned this, then the postbox, then chaind; this is the fourth time.
	for _, p := range []string{cfg.Gateway, cfg.Ingest} {
		if len(p) >= 108 {
			return fmt.Errorf("socket path is %d bytes, the AF_UNIX limit is 107: %s", len(p), p)
		}
	}

	p, err := NewProxy(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()

	errs := make(chan error, 2)
	go func() { errs <- p.ServeGateway(ctx) }()
	go func() { errs <- p.ServeInbound(ctx) }()

	p.log("up host=%s fed=%v listen=%s gateway=%s ingest=%s services=%v enrolled=%v",
		cfg.Host, cfg.Fed, cfg.Listen, cfg.Gateway, cfg.Ingest, p.serviceNames(), p.reg.Hosts())

	select {
	case err := <-errs:
		cancel()
		return err
	case <-ctx.Done():
		return nil
	}
}

// ---------------------------------------------------------------- status / reborn

func gatewayCall(sock string, req any) ([]byte, error) {
	conn, err := net.DialTimeout("unix", sock, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	blob, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(append(blob, '\n')); err != nil {
		return nil, err
	}
	buf := make([]byte, 1<<20)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return nil, err
	}
	return buf[:n], nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	sock := fs.String("gateway", "", "the proxy's gateway socket")
	_ = fs.Parse(args)
	raw, err := gatewayCall(*sock, map[string]string{"op": "status"})
	if err != nil {
		return err
	}
	os.Stdout.Write(raw)
	return nil
}

func cmdReborn(args []string) error {
	fs := flag.NewFlagSet("reborn", flag.ExitOnError)
	sock := fs.String("gateway", "", "the proxy's gateway socket")
	service := fs.String("service", "", "the service the launcher has just replaced")
	_ = fs.Parse(args)
	raw, err := gatewayCall(*sock, map[string]string{"op": "reborn", "from": *service})
	if err != nil {
		return err
	}
	os.Stdout.Write(raw)
	return nil
}

// ---------------------------------------------------------------- attack / bench / mitm

func cmdAttack(args []string) error {
	fs := flag.NewFlagSet("attack", flag.ExitOnError)
	cfg := AttackConfig{}
	fs.StringVar(&cfg.Case, "case", "honest", "which adversary to be; see AttackCases")
	fs.StringVar(&cfg.KeyPath, "key", "", "the sender's keyfile")
	fs.StringVar(&cfg.Registry, "registry", "", "the sender's own registry")
	fs.StringVar(&cfg.ToHost, "to-host", "", "the destination host")
	fs.StringVar(&cfg.ToPeer, "to-peer", "", "the destination service")
	fs.StringVar(&cfg.Addr, "addr", "", "the destination proxy's address")
	fs.StringVar(&cfg.FromPeer, "from-peer", "reader", "the sandbox identity to claim")
	fs.StringVar(&cfg.Body, "body", "", "the message body")
	fs.StringVar(&cfg.Stamp, "stamp", "", "base64 of the 256-byte stamp to carry")
	fs.StringVar(&cfg.ClaimRaw, "claim", "", "the capability claim to assert, as JSON")
	fs.BoolVar(&cfg.Plain, "plain", false, "talk the baseline transport instead")
	fs.Int64Var(&cfg.Seq, "seq", 0, "the sequence number to claim; 0 picks a fresh one")
	list := fs.Bool("list", false, "print the case catalogue and exit")
	_ = fs.Parse(args)

	if *list {
		for _, name := range sortedKeys(AttackCases) {
			fmt.Printf("%-16s %s\n", name, AttackCases[name])
		}
		return nil
	}
	if _, ok := AttackCases[cfg.Case]; !ok {
		return fmt.Errorf("unknown case %q (try --list)", cfg.Case)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := RunAttack(ctx, cfg)
	if err != nil {
		return err
	}
	blob, _ := json.Marshal(res)
	fmt.Printf("ATTACK %s\n", blob)
	// Exit non-zero when the receiver ACCEPTED the message, so a shell can read the
	// exit code as "the attack worked". Baseline expects 0 here; enforced expects 1.
	if res.Delivered {
		os.Exit(0)
	}
	os.Exit(3)
	return nil
}

func cmdBench(args []string) error {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	cfg := BenchConfig{}
	fs.StringVar(&cfg.KeyPath, "key", "", "the sender's keyfile")
	fs.StringVar(&cfg.Registry, "registry", "", "the sender's registry")
	fs.StringVar(&cfg.ToHost, "to-host", "", "the destination host")
	fs.StringVar(&cfg.ToPeer, "to-peer", "", "the destination service")
	fs.StringVar(&cfg.Addr, "addr", "", "the destination proxy's address")
	fs.StringVar(&cfg.FromPeer, "from-peer", "bench", "the sandbox identity to claim")
	fs.IntVar(&cfg.Warmup, "handshakes", 5, "how many cold handshakes to time")
	fs.IntVar(&cfg.Serial, "serial", 20, "how many warm exchanges to time one at a time")
	fs.IntVar(&cfg.Burst, "burst", 32, "how many exchanges to fire concurrently")
	fs.StringVar(&cfg.Body, "body", "bench", "the message body")
	fs.StringVar(&cfg.Claim, "claim", "", "the capability claim to assert, as JSON")
	jsonOut := fs.Bool("json", false, "print the raw numbers as JSON as well")
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	res, err := RunBench(ctx, cfg)
	if err != nil {
		return err
	}
	fmt.Print(res.Summary())
	if *jsonOut {
		blob, _ := json.Marshal(res)
		fmt.Printf("BENCH %s\n", blob)
	}
	if res.BurstCompleted != res.BurstConcurrent {
		return fmt.Errorf("burst incomplete: %d of %d", res.BurstCompleted, res.BurstConcurrent)
	}
	return nil
}

func cmdMITM(args []string) error {
	fs := flag.NewFlagSet("mitm", flag.ExitOnError)
	cfg := MITMConfig{}
	fs.StringVar(&cfg.Listen, "listen", "", "where the sender thinks the receiver is")
	fs.StringVar(&cfg.Forward, "forward", "", "where the receiver actually is")
	fs.StringVar(&cfg.Mode, "mode", "tcp", "tcp (baseline, can read and rewrite) or udp (quic, blind)")
	var rewrites listFlag
	fs.Var(&rewrites, "rewrite",
		"repeatable OLD=NEW, applied in tcp mode to the plaintext body and to the capability claim")
	fs.StringVar(&cfg.LogPath, "log", "", "append the MITM log here as well as stdout")
	_ = fs.Parse(args)

	for _, r := range rewrites {
		if !strings.Contains(r, "=") {
			return fmt.Errorf("--rewrite wants OLD=NEW, got %q", r)
		}
	}
	cfg.Rewrite = rewrites
	ctx, cancel := signalContext()
	defer cancel()
	return RunMITM(ctx, cfg)
}

func cmdStamp(args []string) error {
	fs := flag.NewFlagSet("stamp", flag.ExitOnError)
	sender := fs.String("sender", "reader", "")
	taint := fs.Int("taint", 0, "")
	grants := fs.String("grants", "", "")
	chain := fs.String("chain", "", "")
	origin := fs.String("origin", "", "")
	_ = fs.Parse(args)
	fmt.Println(SyntheticStampB64(*sender, *taint, *grants, *chain, *origin))
	return nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
