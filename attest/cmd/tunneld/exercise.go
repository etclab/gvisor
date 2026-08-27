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

package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"gvisor.dev/gvisor/attest/tunneld"
)

// exercise is the caller a Milestone 3 guest does not otherwise have: it asks
// for the peers the run configuration names and puts traffic through them.
// Milestone 4 replaces it with the sentry (spec, user story 46), and nothing
// in package tunneld knows it exists.
//
// It produces the three figures user story 50 asks for, and it produces them
// in the order that makes each mean something:
//
//   - a cold establishment, which is a QUIC handshake plus both sides
//     verifying the other's evidence — the whole cost of admission;
//   - warm exchanges one at a time on the tunnel that establishment left
//     behind, which is a stream opened, a request written and a response read
//     with no attestation anywhere in it;
//   - concurrent exchanges on that same tunnel, which is what one exchange per
//     stream buys (spec, user story 40) and the only one of the three whose
//     number would change if it had been bought differently.
//
// Repeating it is not padding. The defaults are 60 seconds idle and 15 minutes
// of maximum age, so a run longer than a quarter of an hour re-handshakes in
// the middle of itself, and the establishment figure appears a second time
// with a second verification behind it. That is re-attestation happening to a
// tunnel a caller is still using, which is a thing this design claims and
// otherwise nobody watches happen.
type exercise struct {
	// Dial names the peers to ask for, from the peer table.
	Dial []string `json:"dial"`

	// Wait bounds how long to keep asking for a peer that is not answering
	// yet. Two guests boot at once and neither waits for the other, so the
	// first establishment attempt usually meets nothing.
	Wait duration `json:"wait"`

	// Payload is the marker every request carries. A relay recording the
	// datagrams between two guests is searched for it: a run that never sent
	// it would make the search prove nothing, so it is sent, plainly, inside
	// the tunnel and nowhere else.
	Payload string `json:"payload"`

	// Exchanges is how many warm exchanges to time, one at a time.
	Exchanges int `json:"exchanges"`

	// Concurrency is how many exchanges to have in flight at once, and Rounds
	// how many times to do that.
	Concurrency int `json:"concurrency"`
	Rounds      int `json:"rounds"`

	// RepeatEvery and RunFor turn one pass into a run. Zero of either is one
	// pass and done.
	RepeatEvery duration `json:"repeat_every"`
	RunFor      duration `json:"run_for"`

	// Timeout bounds one exchange and one establishment attempt.
	Timeout duration `json:"timeout"`
}

func (e *exercise) validate() error {
	if len(e.Dial) == 0 {
		return errors.New("no peers to dial; leave the exercise out for a tunneld that only answers")
	}
	if e.Exchanges < 0 || e.Concurrency < 0 || e.Rounds < 0 {
		return errors.New("exchanges, concurrency and rounds cannot be negative")
	}
	return nil
}

func (e *exercise) withDefaults() exercise {
	d := *e
	if d.Wait.Duration <= 0 {
		d.Wait.Duration = 2 * time.Minute
	}
	if d.Timeout.Duration <= 0 {
		d.Timeout.Duration = 30 * time.Second
	}
	if d.Payload == "" {
		d.Payload = "attested-tunnel-plaintext-marker"
	}
	if d.Exchanges == 0 {
		d.Exchanges = 20
	}
	if d.Concurrency == 0 {
		d.Concurrency = 8
	}
	if d.Rounds == 0 {
		d.Rounds = 1
	}
	return d
}

// perform runs the exercise to its end and returns the first thing that went
// wrong, having tried every peer either way. A peer that cannot be established
// is a failed run and not a fatal one: the other peers' figures are worth
// having, and a console that stops at the first failure is a console that
// answers one question.
func (e *exercise) perform(ctx context.Context, td *tunneld.Tunneld, watched *watchedVerifier, logf func(string, ...any)) error {
	cfg := e.withDefaults()
	logf("exercise: dialing %s; %d warm exchanges, %d concurrent × %d rounds, marker %q",
		strings.Join(cfg.Dial, ", "), cfg.Exchanges, cfg.Concurrency, cfg.Rounds, cfg.Payload)

	var failures []string
	deadline := time.Now().Add(cfg.RunFor.Duration)
	for pass := 1; ; pass++ {
		for _, peer := range cfg.Dial {
			if err := cfg.pass(ctx, td, watched, logf, pass, peer); err != nil {
				logf("exercise: pass=%d peer=%s FAILED: %v", pass, peer, err)
				failures = append(failures, fmt.Sprintf("pass %d, peer %s: %v", pass, peer, err))
			}
		}
		// RunFor bounds the whole run, not the start of its last pass: a pass
		// begun a minute before the end is a pass whose peer stops answering
		// in the middle of it, and the failure that produces is this
		// harness's, not the tunnel's.
		if cfg.RepeatEvery.Duration <= 0 || time.Now().Add(cfg.RepeatEvery.Duration).After(deadline) {
			break
		}
		select {
		case <-time.After(cfg.RepeatEvery.Duration):
		case <-ctx.Done():
			logf("exercise: interrupted")
			return ctx.Err()
		}
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func (c exercise) pass(ctx context.Context, td *tunneld.Tunneld, watched *watchedVerifier, logf func(string, ...any), pass int, peer string) error {
	channel, err := c.establish(ctx, td, watched, logf, pass, peer)
	if err != nil {
		return err
	}
	defer channel.Close()

	if c.Exchanges > 0 {
		if err := c.warm(ctx, channel, logf, pass, peer); err != nil {
			return err
		}
	}
	if c.Concurrency > 0 && c.Rounds > 0 {
		if err := c.concurrent(ctx, channel, logf, pass, peer); err != nil {
			return err
		}
	}
	return nil
}

// establish asks for the peer, retrying a peer that is not up yet, and times
// the attempt that succeeded. The attempts before it are reported as a count
// and deliberately not folded into the figure: what user story 50 asks for is
// the cost of establishing a tunnel, not the cost of waiting for another
// machine to finish booting.
func (c exercise) establish(ctx context.Context, td *tunneld.Tunneld, watched *watchedVerifier, logf func(string, ...any), pass int, peer string) (*tunneld.Channel, error) {
	deadline := time.Now().Add(c.Wait.Duration)
	const retryAfter = time.Second
	for attempt := 1; ; attempt++ {
		before := watched.count()
		attemptCtx, cancel := context.WithTimeout(ctx, c.Timeout.Duration)
		start := time.Now()
		channel, err := td.Peer(attemptCtx, peer)
		took := time.Since(start)
		cancel()
		if err == nil {
			logf("LATENCY pass=%d peer=%s kind=establish ms=%s attempts=%d verifier_calls=%d",
				pass, peer, ms(took), attempt, watched.count()-before)
			return channel, nil
		}
		if errors.Is(err, tunneld.ErrUnknownPeer) || ctx.Err() != nil || !time.Now().Before(deadline) {
			return nil, fmt.Errorf("after %d attempt(s) over %s: %w", attempt, c.Wait.Duration, err)
		}
		if attempt == 1 {
			logf("exercise: pass=%d peer=%s not up yet, retrying until %s elapses (%v)", pass, peer, c.Wait.Duration, err)
		}
		select {
		case <-time.After(retryAfter):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// warm times exchanges one at a time on an established tunnel.
func (c exercise) warm(ctx context.Context, channel *tunneld.Channel, logf func(string, ...any), pass int, peer string) error {
	took := make([]time.Duration, 0, c.Exchanges)
	var answerer string
	for i := 0; i < c.Exchanges; i++ {
		start := time.Now()
		response, err := c.exchange(ctx, channel, pass, i)
		if err != nil {
			return fmt.Errorf("warm exchange %d: %w", i, err)
		}
		took = append(took, time.Since(start))
		answerer = response
	}
	logf("LATENCY pass=%d peer=%s kind=warm_exchange n=%d %s answered_by=%q",
		pass, peer, len(took), summarize(took), answerer)
	return nil
}

// concurrent puts Concurrency exchanges in flight at once on the one tunnel,
// Rounds times over. The wall time is the figure that says whether one
// exchange per stream bought anything: a transport with head-of-line blocking
// would show it as the sum of the per-exchange times rather than close to the
// slowest one.
func (c exercise) concurrent(ctx context.Context, channel *tunneld.Channel, logf func(string, ...any), pass int, peer string) error {
	var (
		mu    sync.Mutex
		took  []time.Duration
		fail  error
		total time.Duration
	)
	for round := 0; round < c.Rounds; round++ {
		var wg sync.WaitGroup
		start := time.Now()
		for i := 0; i < c.Concurrency; i++ {
			wg.Add(1)
			go func(seq int) {
				defer wg.Done()
				at := time.Now()
				_, err := c.exchange(ctx, channel, pass, seq)
				elapsed := time.Since(at)
				mu.Lock()
				defer mu.Unlock()
				if err != nil && fail == nil {
					fail = fmt.Errorf("concurrent exchange %d: %w", seq, err)
				}
				took = append(took, elapsed)
			}(round*c.Concurrency + i)
		}
		wg.Wait()
		total += time.Since(start)
		if fail != nil {
			return fail
		}
	}
	logf("LATENCY pass=%d peer=%s kind=concurrent streams=%d rounds=%d n=%d wall_ms=%s %s",
		pass, peer, c.Concurrency, c.Rounds, len(took), ms(total), summarize(took))
	return nil
}

// exchange sends one request and checks the response is the peer's echo of it:
// the answering sandbox's identifier, a colon, and the request unchanged. The
// identifier is returned so that a run records which guest answered rather
// than only that somebody did.
func (c exercise) exchange(ctx context.Context, channel *tunneld.Channel, pass, seq int) (string, error) {
	request := fmt.Sprintf("pass=%d seq=%d %s", pass, seq, c.Payload)
	exchangeCtx, cancel := context.WithTimeout(ctx, c.Timeout.Duration)
	defer cancel()
	response, err := channel.Exchange(exchangeCtx, []byte(request))
	if err != nil {
		return "", err
	}
	answerer, echoed, found := strings.Cut(string(response), ":")
	if !found || echoed != request || answerer == "" {
		return "", fmt.Errorf("peer answered %q, want <sandbox>:%q", response, request)
	}
	return answerer, nil
}

// summarize is the distribution, not the mean alone: a handshake hidden inside
// one exchange of twenty moves the maximum and leaves the mean looking fine.
func summarize(took []time.Duration) string {
	if len(took) == 0 {
		return "n=0"
	}
	sorted := append([]time.Duration(nil), took...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	var sum time.Duration
	for _, d := range sorted {
		sum += d
	}
	return fmt.Sprintf("min_ms=%s p50_ms=%s p90_ms=%s max_ms=%s mean_ms=%s",
		ms(sorted[0]), ms(percentile(sorted, 50)), ms(percentile(sorted, 90)),
		ms(sorted[len(sorted)-1]), ms(sum/time.Duration(len(sorted))))
}

func percentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := (len(sorted)*p + 99) / 100
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

func ms(d time.Duration) string {
	return fmt.Sprintf("%.3f", float64(d.Nanoseconds())/1e6)
}
