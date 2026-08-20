package main

import "testing"

func TestStaticForwardingPlan(t *testing.T) {
	targets := map[string]struct {
		address  string
		deviceID uint64
	}{
		"s1": {"127.0.0.1:50051", 1},
		"s2": {"127.0.0.1:50052", 2},
		"s3": {"127.0.0.1:50053", 3},
		"s4": {"127.0.0.1:50054", 4},
	}
	if len(switchPlans) != len(targets) {
		t.Fatalf("got %d switch plans, want %d", len(switchPlans), len(targets))
	}

	seenAddresses := map[string]bool{}
	seenDevices := map[uint64]bool{}
	entryCount := 0
	for _, plan := range switchPlans {
		want, ok := targets[plan.name]
		if !ok {
			t.Fatalf("unexpected switch %q", plan.name)
		}
		if plan.address != want.address || plan.deviceID != want.deviceID {
			t.Errorf("%s: got target %s/%d, want %s/%d", plan.name, plan.address, plan.deviceID, want.address, want.deviceID)
		}
		if seenAddresses[plan.address] || seenDevices[plan.deviceID] {
			t.Errorf("%s: duplicate P4Runtime target", plan.name)
		}
		seenAddresses[plan.address] = true
		seenDevices[plan.deviceID] = true
		if len(plan.entries) != 2 {
			t.Errorf("%s: got %d entries, want 2", plan.name, len(plan.entries))
		}
		entryCount += len(plan.entries)
	}
	if entryCount != 8 {
		t.Fatalf("got %d forwarding entries, want 8", entryCount)
	}

	assertEntry(t, "s1", ipv4Match, "10.0.2.0", 24, 0, pushAction, 100, "02:00:00:02:01:01", "02:00:00:01:02:01", 2)
	assertEntry(t, "s2", mplsMatch, "", 0, 100, swapAction, 200, "02:00:00:03:01:01", "02:00:00:02:02:01", 2)
	assertEntry(t, "s3", mplsMatch, "", 0, 200, swapAction, 300, "02:00:00:04:01:01", "02:00:00:03:02:01", 2)
	assertEntry(t, "s4", mplsMatch, "", 0, 300, popAction, 0, "02:00:00:00:02:02", "02:00:00:04:02:01", 2)
	assertEntry(t, "s4", ipv4Match, "10.0.1.0", 24, 0, pushAction, 400, "02:00:00:03:02:01", "02:00:00:04:01:01", 1)
	assertEntry(t, "s3", mplsMatch, "", 0, 400, swapAction, 500, "02:00:00:02:02:01", "02:00:00:03:01:01", 1)
	assertEntry(t, "s2", mplsMatch, "", 0, 500, swapAction, 600, "02:00:00:01:02:01", "02:00:00:02:01:01", 1)
	assertEntry(t, "s1", mplsMatch, "", 0, 600, popAction, 0, "02:00:00:00:01:01", "02:00:00:01:01:01", 1)
}

func assertEntry(
	t *testing.T,
	switchName string,
	kind matchKind,
	destination string,
	prefixLength int32,
	inputLabel uint64,
	action string,
	outputLabel uint64,
	dstMAC string,
	srcMAC string,
	port uint64,
) {
	t.Helper()
	for _, plan := range switchPlans {
		if plan.name != switchName {
			continue
		}
		for _, entry := range plan.entries {
			if entry.kind == kind &&
				entry.destination == destination &&
				entry.prefixLength == prefixLength &&
				entry.inputLabel == inputLabel {
				if entry.action != action ||
					entry.outputLabel != outputLabel ||
					entry.dstMAC != dstMAC ||
					entry.srcMAC != srcMAC ||
					entry.port != port {
					t.Errorf("%s: incorrect forwarding action for %+v", switchName, entry)
				}
				return
			}
		}
	}
	t.Errorf("%s: forwarding entry not found", switchName)
}
