# Reproducible runs of boundclaw-agent-usecase against this tree's runsc fork.
# See usecase/README.md.
#
#   make runsc      (re)build runsc from THIS tree into ../bin and print its version
#   make register   register the boundclaw-runsc docker runtime (needs sudo; once)
#   make pass1      baseline: all three agents on the default runtime (runc)
#   make pass2      all three agents under boundclaw-runsc
#   make pass3      mixed: financial stays on runc (unadopted-peer scenario)
#   make sweep      run all three passes, then print one comparison table
#   make status     show whether boundclaw-runsc is registered + its binary version
#   make clean      remove result transcripts

SHELL := /bin/bash
REPO  := $(abspath $(CURDIR)/..)
RUNTIME_NAME := boundclaw-runsc
DEBUG_LOG    := /tmp/boundclaw-runsc/%ID%.%COMMAND%.log

.PHONY: runsc register status pass1 pass2 pass3 sweep clean

# One build, not two. The sequence the rung READMEs document
# (`make runsc && make copy TARGETS=runsc`) builds twice: `make runsc` uses
# `-c opt`, while a bare `make copy` uses the default config, so bazel rebuilds
# the whole target in a second configuration and it is the *fastbuild* binary
# that lands in bin/. Passing OPTIONS="-c opt" to copy makes the build and the
# copy agree on one configuration, so this is a single opt build.
runsc:
	mkdir -p $(REPO)/bin
	$(MAKE) -C $(REPO) copy OPTIONS="-c opt" TARGETS=runsc DESTINATION=$(REPO)/bin/
	@echo "built: $$($(REPO)/bin/runsc --version | head -1)"

# Registers boundclaw-runsc pointing straight at $(REPO)/bin/runsc, so future
# `make runsc` rebuilds are picked up by the next container start with no sudo
# and no docker reload.  --clobber (default) makes this idempotent.
# No --ladder-* flags yet: they gate unix-socket/annotation paths that this
# HTTP workload never touches, so today the fork is provenance-only here.
register: runsc
	sudo $(REPO)/bin/runsc install --config_file=/etc/docker/daemon.json \
	     --experimental=true --runtime=$(RUNTIME_NAME) -- \
	     --debug-log=$(DEBUG_LOG)
	sudo systemctl reload docker
	@echo "registered '$(RUNTIME_NAME)' -> $(REPO)/bin/runsc"
	@$(MAKE) --no-print-directory status

# Reports not just "is a runtime by that name registered" but "does it resolve to
# THIS checkout's binary".  With more than one clone of this tree around, the name
# can be registered while pointing at a different tree's runsc, and every pass 2/3
# result would then be attributed to the wrong build.
status:
	@printf 'runtime registered : '
	@docker info --format '{{range $$k,$$v := .Runtimes}}{{$$k}} {{end}}' \
	  | grep -qw $(RUNTIME_NAME) && echo yes || echo 'no  (run: make register)'
	@registered=$$(docker info --format \
	   '{{range $$k,$$v := .Runtimes}}{{if eq $$k "$(RUNTIME_NAME)"}}{{$$v.Path}}{{end}}{{end}}' 2>/dev/null); \
	 if [ -n "$$registered" ]; then \
	   printf 'runtime points at  : %s\n' "$$registered"; \
	   if [ "$$registered" != "$(REPO)/bin/runsc" ]; then \
	     printf 'WARNING            : that is not this checkout ($(REPO)/bin/runsc).\n'; \
	     printf '                     pass 2/3 would test the other tree.  Fix: make register\n'; \
	   fi; \
	 fi
	@if [ -x $(REPO)/bin/runsc ]; then \
	  printf 'bin/runsc version  : '; $(REPO)/bin/runsc --version | head -1; \
	else echo 'bin/runsc          : not built (run: make runsc)'; fi

pass1: ; ./run.sh 1
pass2: ; ./run.sh 2
pass3: ; ./run.sh 3

# Runs every pass even if one mismatches, then summarises. Non-zero if any did.
sweep:
	@fail=0; for p in 1 2 3; do ./run.sh $$p || fail=1; done; \
	 ./summarise.sh; exit $$fail

clean:
	rm -rf results
	@echo "cleaned usecase/results (containers are torn down by run.sh itself)"
