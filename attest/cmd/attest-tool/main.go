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

// attest-tool is everything the attested tunnel needs a command for that is not
// the tunnel: acquiring one bundle of evidence, provisioning the certificate
// chain a verifier of that evidence needs, and taking a verdict on it.
//
//	attest-tool verify    -bundle DIR -refvals PATH -author PATH [...]
//	attest-tool acquire   [-chain-dir DIR] [-out DIR] [-report-dir DIR] [-base64]
//	attest-tool provision fetch -report REPORT.bin -out DIR
//	attest-tool provision check -report REPORT.bin -dir DIR
//
// The three were three programs until ticket 21 — cmd/verify-evidence,
// cmd/acquire-evidence and cmd/provision-chain — and they are one here because
// they are one procedure seen from three places: a guest acquires, an operator
// provisions what the acquisition needs, a workstation judges what came back.
// cmd/tunneld, which is the measured binary, is deliberately not among them.
//
// Each subcommand keeps its own flag set, its own exit statuses and the name it
// has reported errors under since the ticket that introduced it, so that a
// transcript recorded before ticket 21 and one recorded after it say the same
// thing about the same run. What the subcommands share is what they had copies
// of: the author key reader and the policy-digest parser.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "verify":
		os.Exit(runVerify(os.Args[2:], os.Stdout))
	case "acquire":
		if err := runAcquire(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "acquire-evidence:", err)
			os.Exit(1)
		}
	case "provision":
		runProvision(os.Args[2:])
	default:
		usage()
	}
}

// usage names the subcommands and nothing else: each one prints its own flags,
// with their defaults and their reasons, under -h.
func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  attest-tool verify    -bundle DIR -refvals PATH -author PATH [...]
  attest-tool acquire   [-chain-dir DIR] [-out DIR] [-report-dir DIR] [-base64]
  attest-tool provision fetch -report REPORT.bin -out DIR
  attest-tool provision check -report REPORT.bin -dir DIR

each subcommand's own flags: attest-tool SUBCOMMAND -h`)
	os.Exit(2)
}
