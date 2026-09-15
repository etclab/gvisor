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
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	"gvisor.dev/gvisor/attest/provision"
)

// runProvision fetches the certificate chain for the platform that produced
// an SEV-SNP attestation report, validates it, and writes it to the config
// device's directory — or checks that a provisioned chain is still the one for
// a platform's current report (ADR-0005).
//
//	attest-tool provision fetch -report REPORT.bin -out DIR
//	attest-tool provision check -report REPORT.bin -dir DIR
//
// The procedure this is part of is docs/provisioning-certificate-chain.md.
func runProvision(args []string) {
	if len(args) < 1 {
		provisionUsage()
	}
	var err error
	switch args[0] {
	case "fetch":
		err = fetch(args[1:])
	case "check":
		err = check(args[1:])
	default:
		provisionUsage()
	}
	if err != nil {
		// The error prefix is the name this program had before ticket 21
		// folded it into attest-tool, for the reason the other two keep
		// theirs: the transcripts of ticket 15 were recorded against it.
		fmt.Fprintln(os.Stderr, "provision-chain:", err)
		os.Exit(1)
	}
}

func provisionUsage() {
	fmt.Fprintln(os.Stderr, "usage:\n  attest-tool provision fetch -report REPORT.bin -out DIR\n  attest-tool provision check -report REPORT.bin -dir DIR")
	os.Exit(2)
}

func fetch(args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	reportPath := fs.String("report", "", "an attestation report from the platform to provision, in ABI form")
	out := fs.String("out", "", "directory to write the chain and its metadata into (the config device's contents)")
	timeout := fs.Duration("timeout", 5*time.Minute, "overall time allowed for the key distribution service")
	fs.Parse(args)
	if *reportPath == "" || *out == "" {
		fs.Usage()
		os.Exit(2)
	}
	report, err := os.ReadFile(*reportPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	chain, err := provision.Fetch(ctx, report, provision.Options{})
	if err != nil {
		return err
	}
	if err := provision.Write(*out, chain); err != nil {
		return err
	}
	describe(chain)
	fmt.Printf("written: %s/%s and %s/%s\n", *out, provision.ChainFileName, *out, provision.MetadataFileName)
	return nil
}

func check(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	reportPath := fs.String("report", "", "a current attestation report from the platform, in ABI form")
	dir := fs.String("dir", "", "directory holding the provisioned chain and its metadata")
	fs.Parse(args)
	if *reportPath == "" || *dir == "" {
		fs.Usage()
		os.Exit(2)
	}
	report, err := os.ReadFile(*reportPath)
	if err != nil {
		return err
	}
	chain, err := provision.LoadFor(*dir, report)
	if err != nil {
		return err
	}
	describe(chain)
	fmt.Println("the provisioned chain is the one for this platform's current report")
	return nil
}

func describe(c provision.Chain) {
	fmt.Printf("product line: %s\nchip id:      %s\ntcb:          bootloader=%d tee=%d snp=%d microcode=%d\nfetched at:   %s\nchain:        %d bytes\n",
		c.ProductLine, hex.EncodeToString(c.ChipID), c.TCB.Bootloader, c.TCB.TEE, c.TCB.SNP, c.TCB.Microcode,
		c.FetchedAt.Format(time.RFC3339), len(c.Bytes))
}
