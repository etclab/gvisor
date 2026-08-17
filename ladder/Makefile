# Ladder demos. See ladder/README.md.
#
#   make demo RUNG=0      run one rung's three-check demo (RUNG=5a for the federation rung)
#   make demo-all         run every implemented rung, oldest first
#   make build            build the container images without running anything
#   make clean            remove ladder containers, networks, images and runtime state

SHELL := /bin/bash
RUNG ?= 0
IMPLEMENTED_RUNGS := 0 1 2 3 4 5a
COMMON := common
RUNTIME_DIR := /tmp/ladder-$(shell id -u)

# Extra flags forwarded to demo.sh, e.g. make demo RUNG=0 ARGS=--baseline-runtime=runc
ARGS ?=

.PHONY: demo demo-all build clean fed

demo:
	@test -x rung$(RUNG)/demo.sh || { echo "rung $(RUNG) has no demo.sh yet"; exit 2; }
	@rung$(RUNG)/demo.sh $(ARGS)

# Conventions section 6.2: a new rung must not regress an earlier rung's claim.
demo-all:
	@fail=0; for r in $(IMPLEMENTED_RUNGS); do \
		echo "############ rung $$r ############"; \
		rung$$r/demo.sh $(ARGS) || fail=1; \
	done; \
	if [ $$fail -ne 0 ]; then echo "DEMO-ALL: FAIL"; exit 1; fi; \
	echo "DEMO-ALL: PASS"

build:
	docker build -q -t ladder/agent-baseline:rung0 -f $(COMMON)/images/Dockerfile.agent-baseline $(COMMON)
	docker build -q -t ladder/agent-enforced:rung0 -f $(COMMON)/images/Dockerfile.agent-enforced $(COMMON)
	docker build -q -t ladder/world:rung0 -f $(COMMON)/images/Dockerfile.world $(COMMON)
	docker build -q -t ladder/agent-enforced:rung1 -f $(COMMON)/images/Dockerfile.agent-enforced $(COMMON)
	docker build -q -t ladder/world:rung1 -f $(COMMON)/images/Dockerfile.world $(COMMON)
	docker build -q -t ladder/agent-enforced:rung2 -f $(COMMON)/images/Dockerfile.agent-enforced $(COMMON)
	docker build -q -t ladder/world:rung2 -f $(COMMON)/images/Dockerfile.world $(COMMON)
	docker build -q -t ladder/agent-enforced:rung3 -f $(COMMON)/images/Dockerfile.agent-enforced $(COMMON)
	docker build -q -t ladder/world:rung3 -f $(COMMON)/images/Dockerfile.world $(COMMON)
	docker build -q -t ladder/agent-enforced:rung4 -f $(COMMON)/images/Dockerfile.agent-enforced $(COMMON)
	docker build -q -t ladder/world:rung4 -f $(COMMON)/images/Dockerfile.world $(COMMON)
	docker build -q -t ladder/agent-enforced:rung5a -f $(COMMON)/images/Dockerfile.agent-enforced $(COMMON)
	docker build -q -t ladder/world:rung5a -f $(COMMON)/images/Dockerfile.world $(COMMON)
	$(MAKE) fed

# Rung 5a's federation substrate is a separate Go module, deliberately: it depends on
# quic-go and wormhole-william, and putting those in the runtime's go.mod would change
# the tree the ladder is meant to leave alone. GOPROXY=off because the versions are
# pinned and cached -- nothing at demo time reaches the network.
fed:
	cd $(COMMON)/fed && GOFLAGS=-mod=mod GOPROXY=off $${LADDER_GO:-go} build -o $(RUNTIME_DIR)/f5a/ladder-fed .

clean:
	-docker rm -f $$(docker ps -aq --filter 'label=ladder=1') 2>/dev/null
	-for n in $$(docker network ls --filter 'label=ladder=1' --format '{{.Name}}'); do docker network rm $$n; done
	-docker rmi ladder/agent-baseline:rung0 ladder/agent-enforced:rung0 ladder/world:rung0 2>/dev/null
	-docker rmi ladder/agent-enforced:rung1 ladder/world:rung1 2>/dev/null
	-docker rmi ladder/agent-enforced:rung2 ladder/world:rung2 2>/dev/null
	-docker rmi ladder/agent-enforced:rung3 ladder/world:rung3 2>/dev/null
	-docker rmi ladder/agent-enforced:rung4 ladder/world:rung4 2>/dev/null
	-docker rmi ladder/agent-enforced:rung5a ladder/world:rung5a 2>/dev/null
	-rm -rf $(RUNTIME_DIR)
	@echo "cleaned"
