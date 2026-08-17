P4C ?= p4c-bm2-ss
P4CFLAGS ?=
PYTHON ?= python3

BUILD_DIR := build
P4_SOURCE := p4/mpls.p4
BMV2_JSON := $(BUILD_DIR)/mpls.json
P4INFO := $(BUILD_DIR)/mpls.p4info.txtpb

.PHONY: build p4 test clean

build: p4

p4: $(BMV2_JSON) $(P4INFO)

test: build
	$(PYTHON) -B tests/test_pipeline.py $(BMV2_JSON) $(P4INFO)

$(BMV2_JSON) $(P4INFO) &: $(P4_SOURCE)
	mkdir -p $(BUILD_DIR)
	$(P4C) --std p4-16 --Werror $(P4CFLAGS) \
		--p4runtime-files $(P4INFO) -o $(BMV2_JSON) $(P4_SOURCE)

clean:
	rm -rf -- $(BUILD_DIR)
