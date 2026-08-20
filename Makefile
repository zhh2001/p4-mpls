P4C ?= p4c-bm2-ss
P4CFLAGS ?=
PYTHON ?= python3
SUDO ?= sudo
GO ?= go

BUILD_DIR := build
P4_SOURCE := p4/mpls.p4
BMV2_JSON := $(BUILD_DIR)/mpls.json
P4INFO := $(BUILD_DIR)/mpls.p4info.txtpb
CONTROLLER := $(BUILD_DIR)/mpls-controller
CONTROLLER_SOURCES := $(wildcard controller/*.go)

.PHONY: build p4 controller test run topology clean

build: p4 controller

p4: $(BMV2_JSON) $(P4INFO)

controller: $(CONTROLLER)

test: build
	$(PYTHON) -B tests/test_pipeline.py $(BMV2_JSON) $(P4INFO)
	$(GO) test ./...
	$(GO) vet ./...
	$(SUDO) $(PYTHON) -B tests/test_topology.py
	$(SUDO) $(PYTHON) -B tests/test_controller.py $(CONTROLLER) $(BMV2_JSON) $(P4INFO)

topology: build
	$(SUDO) $(PYTHON) -B mininet/topology.py

run: build
	$(SUDO) $(PYTHON) -B mininet/topology.py \
		--controller $(CONTROLLER) --device-config $(BMV2_JSON) --p4info $(P4INFO)

$(BMV2_JSON) $(P4INFO) &: $(P4_SOURCE)
	mkdir -p $(BUILD_DIR)
	$(P4C) --std p4-16 --Werror $(P4CFLAGS) \
		--p4runtime-files $(P4INFO) -o $(BMV2_JSON) $(P4_SOURCE)

$(CONTROLLER): $(CONTROLLER_SOURCES) go.mod go.sum
	mkdir -p $(BUILD_DIR)
	$(GO) build -o $(CONTROLLER) ./controller

clean:
	rm -rf -- $(BUILD_DIR)
