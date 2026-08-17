#include <core.p4>
#include <v1model.p4>

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_MPLS = 0x8847;

typedef bit<9> port_t;
typedef bit<20> mpls_label_t;
typedef bit<32> ipv4_addr_t;
typedef bit<48> mac_addr_t;

error {
    InvalidIPv4,
    InvalidIPv4Length,
    IPv4OptionsNotSupported,
    MPLSStackNotSupported
}

header ethernet_t {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header mpls_t {
    mpls_label_t label;
    bit<3> traffic_class;
    bit<1> bottom_of_stack;
    bit<8> ttl;
}

struct headers_t {
    ethernet_t ethernet;
    mpls_t mpls;
    ipv4_t ipv4;
}

struct metadata_t {
}

parser ParserImpl(
    packet_in packet,
    out headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata)
{
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_MPLS: parse_mpls;
            default: accept;
        }
    }

    state parse_mpls {
        packet.extract(hdr.mpls);
        verify(hdr.mpls.bottom_of_stack == 1, error.MPLSStackNotSupported);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        verify(hdr.ipv4.version == 4, error.InvalidIPv4);
        verify(hdr.ipv4.ihl == 5, error.IPv4OptionsNotSupported);
        verify(hdr.ipv4.total_len >= 20, error.InvalidIPv4Length);
        transition accept;
    }
}

control VerifyChecksumImpl(
    inout headers_t hdr,
    inout metadata_t meta)
{
    apply {
        verify_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16);
    }
}

control IngressImpl(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata)
{
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(mac_addr_t dst_mac, mac_addr_t src_mac, port_t port) {
        if (hdr.ipv4.ttl > 1) {
            hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
            hdr.ethernet.dst_addr = dst_mac;
            hdr.ethernet.src_addr = src_mac;
            standard_metadata.egress_spec = port;
        } else {
            mark_to_drop(standard_metadata);
        }
    }

    action push_mpls(
        mpls_label_t label,
        mac_addr_t dst_mac,
        mac_addr_t src_mac,
        port_t port)
    {
        if (hdr.ipv4.ttl > 1) {
            hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
            hdr.mpls.setValid();
            hdr.mpls.label = label;
            hdr.mpls.traffic_class = 0;
            hdr.mpls.bottom_of_stack = 1;
            hdr.mpls.ttl = hdr.ipv4.ttl;
            hdr.ethernet.ether_type = ETHERTYPE_MPLS;
            hdr.ethernet.dst_addr = dst_mac;
            hdr.ethernet.src_addr = src_mac;
            standard_metadata.egress_spec = port;
        } else {
            mark_to_drop(standard_metadata);
        }
    }

    action swap_mpls(
        mpls_label_t label,
        mac_addr_t dst_mac,
        mac_addr_t src_mac,
        port_t port)
    {
        if (hdr.mpls.ttl > 1) {
            hdr.mpls.label = label;
            hdr.mpls.ttl = hdr.mpls.ttl - 1;
            hdr.ethernet.dst_addr = dst_mac;
            hdr.ethernet.src_addr = src_mac;
            standard_metadata.egress_spec = port;
        } else {
            mark_to_drop(standard_metadata);
        }
    }

    action pop_mpls(mac_addr_t dst_mac, mac_addr_t src_mac, port_t port) {
        if (hdr.mpls.ttl > 1) {
            hdr.ipv4.ttl = hdr.mpls.ttl - 1;
            hdr.mpls.setInvalid();
            hdr.ethernet.ether_type = ETHERTYPE_IPV4;
            hdr.ethernet.dst_addr = dst_mac;
            hdr.ethernet.src_addr = src_mac;
            standard_metadata.egress_spec = port;
        } else {
            mark_to_drop(standard_metadata);
        }
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            ipv4_forward;
            push_mpls;
            drop;
        }
        size = 32;
        const default_action = drop();
    }

    table mpls_forward {
        key = {
            hdr.mpls.label: exact;
        }
        actions = {
            swap_mpls;
            pop_mpls;
            drop;
        }
        size = 32;
        const default_action = drop();
    }

    apply {
        if (standard_metadata.parser_error != error.NoError ||
            standard_metadata.checksum_error == 1)
        {
            drop();
        } else if (hdr.mpls.isValid()) {
            mpls_forward.apply();
        } else if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        } else {
            drop();
        }
    }
}

control EgressImpl(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata)
{
    apply {
    }
}

control ComputeChecksumImpl(
    inout headers_t hdr,
    inout metadata_t meta)
{
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16);
    }
}

control DeparserImpl(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.mpls);
        packet.emit(hdr.ipv4);
    }
}

V1Switch(
    ParserImpl(),
    VerifyChecksumImpl(),
    IngressImpl(),
    EgressImpl(),
    ComputeChecksumImpl(),
    DeparserImpl()) main;
