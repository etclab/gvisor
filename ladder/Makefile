# Ladder demos. See ladder/README.md.
#
#   make demo RUNG=0      run one rung's three-check demo
#   make demo-all         run every implemented rung, oldest first
#   make build            build the container images without running anything
#   make clean            remove ladder containers, networks, images and runtime state

SHELL := /bin/bash
RUNG ?= 0
IMPLEMENTED_RUNGS := 0
COMMON := common
RUNTIME_DIR := /tmp/ladder-$(shell id -u)

# Extra flags forwarded to demo.sh, e.g. make demo RUNG=0 ARGS=--baseline-runtime=runc
ARGS ?=

.PHONY: demo demo-all build clean

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

clean:
	-docker rm -f $$(docker ps -aq --filter 'label=ladder=1') 2>/dev/null
	-for n in $$(docker network ls --filter 'label=ladder=1' --format '{{.Name}}'); do docker network rm $$n; done
	-docker rmi ladder/agent-baseline:rung0 ladder/agent-enforced:rung0 ladder/world:rung0 2>/dev/null
	-rm -rf $(RUNTIME_DIR)
	@echo "cleaned"
