package main

import (
	"fmt"

	p4v1 "github.com/p4lang/p4runtime/go/p4/v1"
	"github.com/zhh2001/p4runtime-go-controller/codec"
	"github.com/zhh2001/p4runtime-go-controller/pipeline"
	"github.com/zhh2001/p4runtime-go-controller/tableentry"
)

const (
	ipv4Table      = "IngressImpl.ipv4_lpm"
	mplsTable      = "IngressImpl.mpls_forward"
	ipv4MatchField = "hdr.ipv4.dst_addr"
	mplsMatchField = "hdr.mpls.label"
	pushAction     = "IngressImpl.push_mpls"
	swapAction     = "IngressImpl.swap_mpls"
	popAction      = "IngressImpl.pop_mpls"
)

type matchKind uint8

const (
	ipv4Match matchKind = iota
	mplsMatch
)

type forwardingEntry struct {
	kind         matchKind
	destination  string
	prefixLength int32
	inputLabel   uint64
	action       string
	outputLabel  uint64
	dstMAC       string
	srcMAC       string
	port         uint64
}

type switchPlan struct {
	name     string
	address  string
	deviceID uint64
	entries  []forwardingEntry
}

var switchPlans = []switchPlan{
	{
		name: "s1", address: "127.0.0.1:50051", deviceID: 1,
		entries: []forwardingEntry{
			{
				kind: ipv4Match, destination: "10.0.2.0", prefixLength: 24,
				action: pushAction, outputLabel: 100,
				dstMAC: "02:00:00:02:01:01", srcMAC: "02:00:00:01:02:01", port: 2,
			},
			{
				kind: mplsMatch, inputLabel: 600, action: popAction,
				dstMAC: "02:00:00:00:01:01", srcMAC: "02:00:00:01:01:01", port: 1,
			},
		},
	},
	{
		name: "s2", address: "127.0.0.1:50052", deviceID: 2,
		entries: []forwardingEntry{
			{
				kind: mplsMatch, inputLabel: 100, action: swapAction, outputLabel: 200,
				dstMAC: "02:00:00:03:01:01", srcMAC: "02:00:00:02:02:01", port: 2,
			},
			{
				kind: mplsMatch, inputLabel: 500, action: swapAction, outputLabel: 600,
				dstMAC: "02:00:00:01:02:01", srcMAC: "02:00:00:02:01:01", port: 1,
			},
		},
	},
	{
		name: "s3", address: "127.0.0.1:50053", deviceID: 3,
		entries: []forwardingEntry{
			{
				kind: mplsMatch, inputLabel: 200, action: swapAction, outputLabel: 300,
				dstMAC: "02:00:00:04:01:01", srcMAC: "02:00:00:03:02:01", port: 2,
			},
			{
				kind: mplsMatch, inputLabel: 400, action: swapAction, outputLabel: 500,
				dstMAC: "02:00:00:02:02:01", srcMAC: "02:00:00:03:01:01", port: 1,
			},
		},
	},
	{
		name: "s4", address: "127.0.0.1:50054", deviceID: 4,
		entries: []forwardingEntry{
			{
				kind: mplsMatch, inputLabel: 300, action: popAction,
				dstMAC: "02:00:00:00:02:02", srcMAC: "02:00:00:04:02:01", port: 2,
			},
			{
				kind: ipv4Match, destination: "10.0.1.0", prefixLength: 24,
				action: pushAction, outputLabel: 400,
				dstMAC: "02:00:00:03:02:01", srcMAC: "02:00:00:04:01:01", port: 1,
			},
		},
	},
}

func buildEntries(p *pipeline.Pipeline, plan switchPlan) ([]*p4v1.TableEntry, error) {
	entries := make([]*p4v1.TableEntry, 0, len(plan.entries))
	for index, spec := range plan.entries {
		entry, err := buildEntry(p, spec)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", index+1, err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func buildEntry(p *pipeline.Pipeline, spec forwardingEntry) (*p4v1.TableEntry, error) {
	var builder *tableentry.Builder
	switch spec.kind {
	case ipv4Match:
		if spec.action != pushAction {
			return nil, fmt.Errorf("IPv4 match cannot use action %q", spec.action)
		}
		address, err := codec.IPv4(spec.destination)
		if err != nil {
			return nil, fmt.Errorf("destination %q: %w", spec.destination, err)
		}
		builder = tableentry.NewBuilder(p, ipv4Table).Match(
			ipv4MatchField,
			tableentry.LPM(address, spec.prefixLength),
		)
	case mplsMatch:
		if spec.action != swapAction && spec.action != popAction {
			return nil, fmt.Errorf("MPLS match cannot use action %q", spec.action)
		}
		label, err := codec.EncodeUint(spec.inputLabel, 20)
		if err != nil {
			return nil, fmt.Errorf("input label %d: %w", spec.inputLabel, err)
		}
		builder = tableentry.NewBuilder(p, mplsTable).Match(
			mplsMatchField,
			tableentry.Exact(label),
		)
	default:
		return nil, fmt.Errorf("unsupported match kind %d", spec.kind)
	}

	params := make([]tableentry.ActionParam, 0, 4)
	if spec.action == pushAction || spec.action == swapAction {
		label, err := codec.EncodeUint(spec.outputLabel, 20)
		if err != nil {
			return nil, fmt.Errorf("output label %d: %w", spec.outputLabel, err)
		}
		params = append(params, tableentry.Param("label", label))
	}

	dstMAC, err := codec.MAC(spec.dstMAC)
	if err != nil {
		return nil, fmt.Errorf("destination MAC %q: %w", spec.dstMAC, err)
	}
	srcMAC, err := codec.MAC(spec.srcMAC)
	if err != nil {
		return nil, fmt.Errorf("source MAC %q: %w", spec.srcMAC, err)
	}
	port, err := codec.EncodeUint(spec.port, 9)
	if err != nil {
		return nil, fmt.Errorf("port %d: %w", spec.port, err)
	}
	params = append(
		params,
		tableentry.Param("dst_mac", dstMAC),
		tableentry.Param("src_mac", srcMAC),
		tableentry.Param("port", port),
	)

	entry, err := builder.Action(spec.action, params...).Build()
	if err != nil {
		return nil, err
	}
	return entry, nil
}

func describeEntry(spec forwardingEntry) string {
	if spec.kind == ipv4Match {
		return fmt.Sprintf("%s/%d -> %s", spec.destination, spec.prefixLength, spec.action)
	}
	return fmt.Sprintf("label %d -> %s", spec.inputLabel, spec.action)
}
