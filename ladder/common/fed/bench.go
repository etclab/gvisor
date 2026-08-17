// bench.go - the agent-pace requirement, as a measurement rather than as prose.
//
// Rung 5a, spec section 6.3 and 7. The workload requirement is stated in the spec as a
// design forcer: agent-to-agent exchanges are "ephemeral, throwaway, short-lived,
// bursty, and at agent-pace", and "no human ceremony may sit on the per-exchange path".
// Section 6 says the burst is "a demo assertion here, not prose", so this file produces
// numbers and CONTROL asserts on them.
//
// # What is being measured, and what is not
//
// This drives the substrate directly rather than through a sandbox: it opens the same
// QUIC connection, builds the same signed envelope, and is admitted or rejected by the
// same receiving proxy, but there is no gVisor sandbox and no agent behind the exchange.
// That is deliberate and it is stated in the README rather than buried: what the numbers
// describe is the FEDERATION's added cost, which is the thing rung 5a introduces. The
// cost of a sandbox reading a page has not changed since rung 0 and measuring it here
// would only obscure the delta.
//
// The three numbers the latency table wants:
//
//	enrollment  human-pace, once per host, ever. Reported by the ceremony, not here.
//	handshake   machine-pace, once per host PAIR, amortized. Cold connect.
//	stream-open agent-pace, per exchange, on a warm connection. This is the number the
//	            "no human ceremony on the per-exchange path" requirement is about.
//
// Loopback on an unloaded box. Treat every figure as a floor and say so in the table --
// a real deployment adds a network, and the point of the table is the RATIO between the
// three, which is what the two-plane split buys.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
)

// BenchConfig configures a burst.
type BenchConfig struct {
	KeyPath  string
	Registry string
	ToHost   string
	ToPeer   string
	Addr     string
	FromPeer string
	Warmup   int
	Serial   int
	Burst    int
	Body     string
	// Claim is the capability the bench asserts for its target. It is needed because
	// the RECEIVING HOST'S policy layer imports one per message, and an empty claim is
	// refused there -- correctly, and by the capability authority rather than by the
	// substrate. Measuring the substrate means not tripping over a policy check that
	// has nothing to do with it.
	Claim string
}

// BenchResult is the latency table, as data.
type BenchResult struct {
	Handshake  []int64 `json:"handshake_us"`
	StreamOpen []int64 `json:"stream_open_us"`
	// StreamExchange is END TO END: stream-open plus envelope verification plus the
	// receiving proxy's unix-socket hop into the postbox. StreamOpen isolates the first
	// term. Both are reported because collapsing them would let a reader attribute the
	// postbox's cost to the transport, or the reverse.
	StreamExchange  []int64 `json:"exchange_us"`
	BurstConcurrent int     `json:"burst_concurrent"`
	BurstCompleted  int     `json:"burst_completed"`
	BurstWallUS     int64   `json:"burst_wall_us"`
	Errors          []string
}

// RunBench performs the measurement.
func RunBench(ctx context.Context, cfg BenchConfig) (BenchResult, error) {
	var res BenchResult
	id, _, _, err := LoadIdentity(cfg.KeyPath)
	if err != nil {
		return res, err
	}
	reg, err := LoadRegistry(cfg.Registry)
	if err != nil {
		return res, err
	}
	dialer := NewDialer(id, reg)
	defer dialer.CloseAll()

	stamp := SyntheticStamp(cfg.FromPeer, 0, "", cfg.FromPeer, "")
	var claim json.RawMessage
	if cfg.Claim != "" {
		claim = json.RawMessage(cfg.Claim)
	}
	var seq int64
	var seqMu sync.Mutex
	nextSeq := func() int64 {
		seqMu.Lock()
		defer seqMu.Unlock()
		seq = NextSeq(seq)
		return seq
	}

	exchange := func(conn *Conn) error {
		env := &Envelope{
			V: EnvelopeVersion, FromHost: id.Host, FromPeer: cfg.FromPeer,
			ToHost: cfg.ToHost, ToPeer: cfg.ToPeer,
			Seq:        nextSeq(),
			Exp:        time.Now().Add(EnvelopeTTL).Unix(),
			Binding:    base64.StdEncoding.EncodeToString(conn.Binding),
			Stamp:      base64.StdEncoding.EncodeToString(stamp),
			Claim:      claim,
			BodySHA256: BodyDigest([]byte(cfg.Body)),
		}
		sig, err := env.Sign(id.Priv)
		if err != nil {
			return err
		}
		st, err := conn.quic.OpenStreamSync(ctx)
		if err != nil {
			return err
		}
		if err := WriteFrame(st, env, sig, []byte(cfg.Body)); err != nil {
			return err
		}
		if err := st.Close(); err != nil {
			return err
		}
		raw, err := io.ReadAll(io.LimitReader(st, MaxFrame))
		if err != nil {
			return err
		}
		var reply gatewayReply
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &reply)
		}
		if !reply.Delivered {
			return fmt.Errorf("not delivered: %s %s", reply.Code, reply.Reason)
		}
		return nil
	}

	// Cold handshakes. Each one drops the cache first, so every figure is a genuine
	// cold connect rather than the first one plus N reuses.
	for i := 0; i < max(1, cfg.Warmup); i++ {
		dialer.CloseAll()
		start := time.Now()
		if _, _, err := dialer.Get(ctx, cfg.ToHost, cfg.Addr); err != nil {
			return res, err
		}
		res.Handshake = append(res.Handshake, time.Since(start).Microseconds())
	}

	conn, _, err := dialer.Get(ctx, cfg.ToHost, cfg.Addr)
	if err != nil {
		return res, err
	}

	// Stream-open alone: one stream, one round trip, no envelope and no delivery. This
	// is the number section 2's claim is about -- "stream-open on a warm connection
	// costs no round trip" -- separated from everything that happens after it.
	for i := 0; i < cfg.Serial; i++ {
		start := time.Now()
		if err := ping(ctx, conn.quic); err != nil {
			res.Errors = append(res.Errors, err.Error())
			continue
		}
		res.StreamOpen = append(res.StreamOpen, time.Since(start).Microseconds())
	}

	// Serial exchanges on the warm connection. This is the agent-pace number.
	for i := 0; i < cfg.Serial; i++ {
		start := time.Now()
		if err := exchange(conn); err != nil {
			res.Errors = append(res.Errors, err.Error())
			continue
		}
		res.StreamExchange = append(res.StreamExchange, time.Since(start).Microseconds())
	}

	// The burst. K exchanges fired at once on ONE connection, which is what QUIC's lack
	// of cross-stream head-of-line blocking is for: a slow exchange delays itself and
	// nothing else. Unattended, by construction -- there is no place in this loop where
	// a human could be asked for anything, which is section 7's acceptance criterion.
	res.BurstConcurrent = cfg.Burst
	var wg sync.WaitGroup
	var mu sync.Mutex
	burstStart := time.Now()
	for i := 0; i < cfg.Burst; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := exchange(conn); err != nil {
				mu.Lock()
				res.Errors = append(res.Errors, err.Error())
				mu.Unlock()
				return
			}
			mu.Lock()
			res.BurstCompleted++
			mu.Unlock()
		}()
	}
	wg.Wait()
	res.BurstWallUS = time.Since(burstStart).Microseconds()
	return res, nil
}

// Summary renders the latency table the rung commits under expected/.
func (r BenchResult) Summary() string {
	line := func(name string, xs []int64) string {
		if len(xs) == 0 {
			return fmt.Sprintf("  %-26s %s\n", name, "no samples")
		}
		s := append([]int64(nil), xs...)
		sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
		return fmt.Sprintf("  %-26s n=%-4d min=%8s  median=%8s  max=%8s\n",
			name, len(s), us(s[0]), us(s[len(s)/2]), us(s[len(s)-1]))
	}
	out := "  " + fmt.Sprintf("%-26s %s\n", "MEASUREMENT", "LOOPBACK, UNLOADED BOX -- TREAT AS A FLOOR")
	out += line("cold handshake (Connect)", r.Handshake)
	out += line("stream-open (Converse)", r.StreamOpen)
	out += line("exchange, end to end", r.StreamExchange)
	out += fmt.Sprintf("  %-26s %d/%d completed in %s (%s each, amortized)\n",
		fmt.Sprintf("burst of %d, concurrent", r.BurstConcurrent),
		r.BurstCompleted, r.BurstConcurrent, us(r.BurstWallUS),
		us(divSafe(r.BurstWallUS, int64(max(1, r.BurstCompleted)))))
	if len(r.Errors) > 0 {
		out += fmt.Sprintf("  %-26s %d (%s)\n", "errors", len(r.Errors), r.Errors[0])
	}
	return out
}

func us(v int64) string {
	if v >= 1000 {
		return fmt.Sprintf("%.2fms", float64(v)/1000)
	}
	return fmt.Sprintf("%dus", v)
}

func divSafe(a, b int64) int64 {
	if b == 0 {
		return 0
	}
	return a / b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
