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

// report-evidence is the binary embedded as /usr/bin/tunneld in the images
// ticket 08 boots, and in nothing else. It is ticket 08's analogue of ticket
// 07's crosscheck-report.c, and it exists for the same reason: the measured
// image has no shell, no writable storage that outlives the guest and no
// network, so the only way a bundle gets out of it is the serial console.
//
// It does what cmd/acquire-evidence does, with the flags fixed to what the
// image provides — the certificate chain provisioned on the config device at
// /config (ADR-0005), the kernel's report interface at its default path — and
// then prints the bundle base64-encoded between marker lines so the harness on
// the host can recover it (docs/measurement-sensitivity.md).
//
// It VERIFIES NOTHING. It does not read the reference value set, it does not
// look at /etc/attested-tunnel/author.pub, and it has no opinion about the
// measurement it is carrying. The verdict is taken outside the guest by
// cmd/verify-evidence, which is the whole point: a guest that judged its own
// evidence would be judging a measurement it could not have influenced anyway,
// and would prove nothing.
//
// The private key is generated here and discarded when the guest powers off,
// exactly as in cmd/acquire-evidence: it exists so the binding is over a real
// key rather than a constant.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"

	"gvisor.dev/gvisor/attest"
	"gvisor.dev/gvisor/attest/tsm"
)

// chainDir is the config device's mount point. The initrd mounts it
// ro,noexec,nosuid,nodev, and it is outside the launch measurement — the same
// device is presented to every image ticket 08 boots, so nothing about it can
// account for a difference between their verdicts.
const chainDir = "/config"

func main() {
	if err := run(); err != nil {
		fmt.Printf("report-evidence: FAILED: %v\n", err)
		os.Exit(2)
	}
}

func run() error {
	acquirer, err := tsm.New(tsm.Options{ChainDir: chainDir, RequestName: "ticket08"})
	if err != nil {
		return err
	}
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
	fmt.Printf("report-evidence: %s\n", observation)
	fmt.Printf("report-evidence: caller-supplied %x\n", callerSupplied[:])

	// The launch measurement the platform reported, printed for the console
	// log alone. It is read at the fixed offset the SEV-SNP ABI gives it, the
	// same way ticket 07's crosscheck-report.c does, and it is never used as a
	// reference value: the verdict below is taken against a set that was
	// signed before this guest existed.
	if len(ev.Bytes) >= 0x90+48 {
		fmt.Printf("report-evidence: launch measurement as reported by the platform: %x\n", ev.Bytes[0x90:0x90+48])
	}

	dump("evidence.bin", ev.Bytes)
	dump("certificate-chain.bin", ev.Chain)
	dump("public-key.der", spki)
	fmt.Printf("report-evidence: bundle complete\n")
	return nil
}

// dump prints one file of the bundle in wrapped base64 between marker lines.
// The wrap is so a serial console with a line-length opinion cannot silently
// truncate it, and the harness reassembles by stripping newlines.
func dump(name string, data []byte) {
	enc := base64.StdEncoding.EncodeToString(data)
	fmt.Printf("===BEGIN %s (%d bytes)===\n", name, len(data))
	for i := 0; i < len(enc); i += 76 {
		fmt.Println(enc[i:min(i+76, len(enc))])
	}
	fmt.Printf("===END %s===\n", name)
}
