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
	"bytes"
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// The two things that must be true of the artifact the image embeds, checked
// on the artifact rather than on anything computed beside it.
//
// A dependency graph is a statement about source. What goes into the launch
// measurement is a file, and the two are the same thing only for as long as
// nobody builds that file with a tag, a different entry point or a stale
// binary lying in the output directory. This builds it the way
// docs/snp/image/package-tunneld.sh does and then reads what came out.
//
// Both failures are expensive in the same particular way: they are discovered
// inside a guest, after the measurement is fixed, with the console saying
// something that sounds like a different problem. A dynamically linked binary
// does not run at all — the image's root filesystem carries no loader — and it
// fails at exec with the image already built, measured and signed for.
func TestPackagedBinaryIsStaticAndFreeOfTestSupport(t *testing.T) {
	binary := build(t)

	f, err := elf.Open(binary)
	if err != nil {
		t.Fatalf("opening the built binary: %v", err)
	}
	defer f.Close()

	for _, prog := range f.Progs {
		if prog.Type == elf.PT_INTERP {
			t.Errorf("the packaged tunneld asks for a dynamic loader (PT_INTERP); the measured image has none, so this fails at exec inside the guest with the measurement already fixed")
		}
	}
	if libs, err := f.ImportedLibraries(); err == nil && len(libs) > 0 {
		t.Errorf("the packaged tunneld needs shared libraries %v; the measured image ships none", libs)
	}

	// Package paths survive in a Go binary whether or not it keeps its symbol
	// table, so this is a check that holds for a stripped one too.
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatalf("reading the built binary: %v", err)
	}
	for _, forbidden := range []string{
		"gvisor.dev/gvisor/attest/snpfake",
		"github.com/google/go-sev-guest/testing",
	} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Errorf("the packaged tunneld carries %q; the fake platform must not be inside the launch measurement", forbidden)
		}
	}
	// The check is only worth anything if it read a binary that has this
	// command in it.
	if !bytes.Contains(raw, []byte("gvisor.dev/gvisor/attest/tunneld")) {
		t.Fatalf("the built binary does not carry package tunneld's path; this test is checking the wrong file")
	}

	// And the property the whole image chain rests on: the measurement is a
	// prediction from the build inputs, so the artifact must be a function of
	// the source and not of where the source happens to sit. Without -trimpath
	// a Go binary carries the absolute path of every file compiled into it, so
	// the same source in two worktrees produces two measurements and nobody
	// else can reproduce either. This looks for the checkout root in the bytes.
	root, err := repoRoot()
	if err != nil {
		t.Fatalf("finding the checkout root: %v", err)
	}
	if bytes.Contains(raw, []byte(root)) {
		t.Errorf("the packaged tunneld embeds the checkout path %q; the predicted launch measurement "+
			"would then depend on which directory it was built in, and could not be reproduced from source elsewhere", root)
	}
}

// repoRoot is the directory this module is checked out under, which is exactly
// the string a binary built without -trimpath would carry.
func repoRoot() (string, error) {
	here, err := os.Getwd()
	if err != nil {
		return "", err
	}
	// .../attest/cmd/tunneld -> .../
	return filepath.Dir(filepath.Dir(filepath.Dir(here))), nil
}

// build builds the command the way the packaging step does: no cgo, no tags,
// and the two flags that keep the artifact a function of the source alone.
// Anything else here would be testing a binary the image does not embed.
func build(t *testing.T) string {
	t.Helper()
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	out := filepath.Join(t.TempDir(), "tunneld")
	cmd := exec.Command(goBin, "build", "-trimpath", "-buildvcs=false", "-o", out, "gvisor.dev/gvisor/attest/cmd/tunneld")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("CGO_ENABLED=0 go build ./cmd/tunneld: %v\n%s", err, combined)
	}
	return out
}
