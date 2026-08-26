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

// acquire-evidence runs inside a confidential guest and produces one bundle:
// evidence from the platform, bound to a key generated a moment earlier, and
// the certificate chain provisioned on the config device that a verifier needs
// to check it (ADR-0002, ADR-0005).
//
//	acquire-evidence -chain-dir DIR [-out DIR] [-report-dir DIR] [-base64]
//
// It is what a tunneld does at startup, with the tunnel left out: generate a
// key, bind evidence to it, keep the pair. Here the private key is discarded
// as soon as the evidence exists — it is generated only so that the binding is
// over a real key rather than a constant — and the public key is written out
// so that the run can be checked afterwards.
//
// Nothing here verifies anything. Checking the evidence against AMD's root is
// the verifier's job and a different ticket; this is the producer.
//
// The procedure this is part of is docs/evidence-acquisition.md.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/tsm"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "acquire-evidence:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("acquire-evidence", flag.ExitOnError)
	chainDir := fs.String("chain-dir", "", "directory holding the provisioned certificate chain (the config device)")
	reportDir := fs.String("report-dir", tsm.DefaultReportDir, "the kernel's vendor-neutral report interface")
	out := fs.String("out", "", "directory to write the bundle to; empty writes nothing")
	b64 := fs.Bool("base64", false, "print the bundle base64-encoded, for recovery from a serial console")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *chainDir == "" {
		fs.Usage()
		return fmt.Errorf("no -chain-dir: evidence is bundled with the chain provisioned on the config device, and this never fetches one (ADR-0005)")
	}

	acquirer, err := tsm.New(tsm.Options{ChainDir: *chainDir, ReportDir: *reportDir, RequestName: "acquire-evidence"})
	if err != nil {
		return err
	}

	// The key this evidence is bound to. A tunneld generates one at startup
	// and holds it for the life of the process; this holds it for the length
	// of one acquisition and drops it.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generating the key: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("encoding the public key: %w", err)
	}
	binding := attest.Binding{PublicKey: spki, Context: attest.BindingContextV1}
	callerSupplied := binding.CallerSuppliedBytes()

	ev, err := acquirer.Acquire(context.Background(), callerSupplied)
	if err != nil {
		return err
	}
	observation, _ := acquirer.LastObservation()

	fmt.Println(observation)
	fmt.Printf("vendor              : %s\n", ev.Vendor)
	fmt.Printf("public key (SPKI)   : %d bytes, %x\n", len(spki), spki)
	fmt.Printf("binding context     : v%d, %x\n", binding.Context.Version(), binding.Context[:])
	fmt.Printf("caller-supplied     : %x\n", callerSupplied[:])
	fmt.Printf("  = SHA-512(public key ‖ binding context), the whole 64-byte field (ADR-0002)\n")
	fmt.Printf("evidence            : %d bytes\n", len(ev.Bytes))
	fmt.Printf("certificate chain   : %d bytes, from %s (ADR-0005)\n", len(ev.Chain), *chainDir)
	fmt.Printf("platform's own table: %d bytes — empty, as expected on this host\n", observation.CertificateTableBytes)

	if *out != "" {
		files := []struct {
			name string
			data []byte
		}{
			{"evidence.bin", ev.Bytes},
			{"certificate-chain.bin", ev.Chain},
			{"public-key.der", spki},
			{"caller-supplied.bin", callerSupplied[:]},
			{"observation.txt", []byte(observation.String() + "\n")},
		}
		if err := os.MkdirAll(*out, 0o755); err != nil {
			return err
		}
		for _, f := range files {
			path := filepath.Join(*out, f.name)
			if err := os.WriteFile(path, f.data, 0o644); err != nil {
				return fmt.Errorf("writing %s: %w", path, err)
			}
			fmt.Printf("wrote %s (%d bytes)\n", path, len(f.data))
		}
	}

	if *b64 {
		dump("evidence.bin", ev.Bytes)
		dump("certificate-chain.bin", ev.Chain)
		dump("public-key.der", spki)
	}
	return nil
}

func dump(name string, data []byte) {
	fmt.Printf("===BEGIN %s===\n%s\n===END %s===\n", name, base64.StdEncoding.EncodeToString(data), name)
}
