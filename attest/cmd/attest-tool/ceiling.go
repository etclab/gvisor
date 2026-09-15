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
	"flag"
	"fmt"
	"io"

	"gvisor.dev/gvisor/attest/ceiling"
)

// runCeiling prints the egress ceiling the measured image carries, and its
// digest.
//
//	attest-tool ceiling [-digest]
//
// The digest is the number an operator puts in a peer's policy_digest: since
// ticket 22 the digest a guest binds into its evidence is the name of the
// ceiling compiled into its image, not of a document on its config device
// (docs/policy-binding.md). It is here rather than only in tunneld because the
// operator authoring a reference value set works on a workstation, where
// running the measured guest's own binary to ask it a question would be the
// wrong instrument — and because a set is authored before any guest has booted.
//
// It reads nothing at all: this prints a constant, so the number it gives is a
// property of the source this tool was built from. Two builds of the same
// source print the same number, and a build of different source is a different
// image with a different measurement, which is the point.
//
// -digest prints the digits alone and nothing else, so a script can read it
// without parsing:
//
//	emit-refvals ... -policy-digest "$(attest-tool ceiling -digest)"
func runCeiling(args []string, out io.Writer) int {
	fs := flag.NewFlagSet("ceiling", flag.ContinueOnError)
	fs.SetOutput(out)
	digestOnly := fs.Bool("digest", false, "print the digest alone, with no text and no label, for a script to read")
	if err := fs.Parse(args); err != nil {
		return exitFailed
	}
	if *digestOnly {
		fmt.Fprintln(out, ceiling.DigestHex())
		return exitAccepted
	}
	fmt.Fprint(out, ceiling.Text())
	fmt.Fprintf(out, "\nceiling digest: %s\n", ceiling.DigestHex())
	fmt.Fprintf(out, "the interface and port compiled in: %s, udp/%d\n", ceiling.Interface, ceiling.Port)
	fmt.Fprintf(out, "this is the number a peer's policy_digest names to admit a guest built from this source\n")
	return exitAccepted
}
