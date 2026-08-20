# p4-mpls

This is a small bidirectional MPLS forwarding lab built with P4_16, BMv2, P4Runtime, and Mininet. A Go controller loads the pipeline and installs the static forwarding entries for four switches.

## Topology

```text
h1 --- s1 --- s2 --- s3 --- s4 --- h2
       PE      P     P      PE
```

The hosts use `10.0.1.1/24` and `10.0.2.2/24`. Traffic crosses a different label-switched path in each direction:

```text
forward: h1 --IPv4--> s1 --100--> s2 --200--> s3 --300--> s4 --IPv4--> h2
reverse: h2 --IPv4--> s4 --400--> s3 --500--> s2 --600--> s1 --IPv4--> h1
```

On the forward path, s1 pushes label 100, s2 swaps 100 for 200, s3 swaps 200 for 300, and s4 pops 300. In reverse, s4 pushes 400, s3 swaps 400 for 500, s2 swaps 500 for 600, and s1 pops 600. IPv4 routes are matched in `ipv4_lpm`; MPLS labels are matched in `mpls_forward`. Table misses are dropped.

## TTL handling

The pipeline uses a uniform TTL model. PUSH decrements the IPv4 TTL and copies the result into the MPLS header. Each SWAP decrements the MPLS TTL once. POP decrements it once more and writes the result back to IPv4. A packet entering with TTL `T` therefore leaves the four-switch path with IPv4 TTL `T - 4` (64 becomes `63 -> 62 -> 61` under MPLS, then 60 in the packet tests). Packets are dropped before a TTL can underflow, and the IPv4 header checksum is verified and recomputed in P4.

## Requirements

- Linux, GNU Make 4.3 or newer, and root access through `sudo`
- `p4c-bm2-ss` with P4_16/v1model support
- BMv2 `simple_switch_grpc`
- Mininet and Python 3 with Scapy's MPLS support
- iproute2 `ip`, `ethtool`, procps `sysctl`, iputils `ping`, and libpcap
- Go 1.25 or newer (`go.mod` selects the 1.25.3 toolchain)

The P4Runtime servers listen on `127.0.0.1:50051` through `50054`; BMv2's Thrift ports are `9090` through `9093`. These ports and the topology's fixed interface names must be free before a run starts.

## Build and run

Build the BMv2 JSON, P4Info, and controller:

```sh
make build
```

The three artifacts are written to `build/mpls.json`, `build/mpls.p4info.txtpb`, and `build/mpls-controller`.

Start the topology, program all four switches, and enter the Mininet CLI:

```sh
make run
```

The controller installs the pipeline and entries, verifies them by readback, and exits before the CLI opens.

Once the CLI opens, the path can be checked in both directions:

```text
mininet> h1 ping -c 3 10.0.2.2
mininet> h2 ping -c 3 10.0.1.1
mininet> exit
```

Run the complete build and integration suite with:

```sh
make test
```

The Makefile invokes `sudo` for tests that create Mininet links or capture packets. The suite checks both label paths and TTLs at every link, drop cases, and resource cleanup. Generated artifacts stay under `build/` and can be removed with `make clean`.

## Limits

- Only one MPLS header with an IPv4 payload is supported; packets with BoS clear are rejected.
- Only fixed 20-byte IPv4 headers are accepted. IPv4 options and IPv6 are not supported.
- Routes, neighbors, labels, ports, and next-hop MAC addresses are static. The controller is a one-shot programmer, not a routing or label-distribution process. ARP is avoided with static host routes and neighbor entries.

The project is licensed under Apache License 2.0.
