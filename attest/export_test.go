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

package attest

// The names this package's own tests need and no caller does.
//
// Everything above the seam is authored on disk and loaded through
// [LoadPolicyFile] and [LoadReferenceValueSetFile]: a guest reads its two
// documents off the config device, and the authoring tools under docs/snp/
// write them there. Nobody outside these tests hands the package a document
// and a signature already in memory, and nobody outside them asks what version
// this package writes. So the in-memory loaders and the version constant are
// unexported, and the names the tests use are declared here, in a file that is
// only compiled into the test binary.
//
// The tests stay in gvisor.dev/gvisor/attest_test and keep the names they had,
// so what they drive is still the surface a caller could reach — with the one
// difference that a caller cannot reach these.

// LoadPolicy is loadPolicy under the name the tests call it by.
var LoadPolicy = loadPolicy

// LoadReferenceValueSet is loadReferenceValueSet under the name the tests call
// it by.
var LoadReferenceValueSet = loadReferenceValueSet

// PolicyVersion is policyVersion, so that a test can assert a loaded policy
// carries the version this package writes without spelling the number twice.
const PolicyVersion = policyVersion
