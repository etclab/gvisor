// Copyright 2025 The gVisor Authors.
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

package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
)

// LadderNarrow implements subcommands.Command for the "ladder-narrow" command.
type LadderNarrow struct {
	containerLoader
}

// Name implements subcommands.Command.Name.
func (*LadderNarrow) Name() string {
	return "ladder-narrow"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*LadderNarrow) Synopsis() string {
	return "narrow a running sandbox's egress allowlist (requires --ladder-task-scope)"
}

// Usage implements subcommands.Command.Usage.
func (*LadderNarrow) Usage() string {
	return `ladder-narrow <container id> <cidr> [<cidr>...] - restrict the sandbox to
sending only to the given IPv4 destination prefixes. Loopback is always
allowed. The operation is attenuation-only: a request that is not contained in
the scope already installed is rejected and changes nothing.
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (*LadderNarrow) SetFlags(*flag.FlagSet) {
}

// FetchSpec implements util.SubCommand.FetchSpec.
func (l *LadderNarrow) FetchSpec(conf *config.Config, f *flag.FlagSet) (string, *specs.Spec, error) {
	c, err := l.loadContainer(conf, f, container.LoadOpts{})
	if err != nil {
		return "", nil, fmt.Errorf("loading container: %w", err)
	}
	return c.ID, c.Spec, nil
}

// Execute implements subcommands.Command.Execute.
func (l *LadderNarrow) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() < 2 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	conf := args[0].(*config.Config)

	cont, err := l.loadContainer(conf, f, container.LoadOpts{})
	if err != nil {
		return util.Errorf("LADDER narrow rejected: loading container: %v", err)
	}

	scope, err := cont.Sandbox.LadderNarrow(f.Args()[1:])
	if err != nil {
		return util.Errorf("LADDER narrow rejected: %v", err)
	}

	util.Infof("LADDER narrow ok scope=%s", strings.Join(scope, ","))
	return subcommands.ExitSuccess
}

// LadderStatus implements subcommands.Command for the "ladder-status" command.
type LadderStatus struct {
	containerLoader
}

// Name implements subcommands.Command.Name.
func (*LadderStatus) Name() string {
	return "ladder-status"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*LadderStatus) Synopsis() string {
	return "report a running sandbox's rung-2 taint state"
}

// Usage implements subcommands.Command.Usage.
func (*LadderStatus) Usage() string {
	return `ladder-status <container id> - print whether the sandbox has read from a
source labeled untrusted, and which labels it booted with. The taint bit is
monotonic and there is no command that clears it. This reads the sandbox over
runsc's control socket, which lives on the host filesystem and is never
reachable from inside the sandbox.
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (*LadderStatus) SetFlags(*flag.FlagSet) {
}

// FetchSpec implements util.SubCommand.FetchSpec.
func (l *LadderStatus) FetchSpec(conf *config.Config, f *flag.FlagSet) (string, *specs.Spec, error) {
	c, err := l.loadContainer(conf, f, container.LoadOpts{})
	if err != nil {
		return "", nil, fmt.Errorf("loading container: %w", err)
	}
	return c.ID, c.Spec, nil
}

// Execute implements subcommands.Command.Execute.
func (l *LadderStatus) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() < 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	conf := args[0].(*config.Config)

	cont, err := l.loadContainer(conf, f, container.LoadOpts{})
	if err != nil {
		return util.Errorf("LADDER status unavailable: loading container: %v", err)
	}

	st, err := cont.Sandbox.LadderStatus()
	if err != nil {
		return util.Errorf("LADDER status unavailable: %v", err)
	}

	taint := "clear"
	if st.Tainted {
		taint = "set"
	}
	util.Infof("LADDER status enabled=%t taint=%s source=%q untrusted=%s sinks=%s",
		st.Enabled, taint, st.Source,
		strings.Join(st.UntrustedPaths, ","), strings.Join(st.PrivilegedSinks, ","))
	return subcommands.ExitSuccess
}
