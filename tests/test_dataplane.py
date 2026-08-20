import os
import select
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from contextlib import contextmanager
from pathlib import Path

from scapy.all import AsyncSniffer, Ether, IP, Raw, UDP
from scapy.contrib.mpls import MPLS
from scapy.layers.inet import in4_chksum
from scapy.utils import checksum


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mininet"))

from topology import (
    HOST_CONFIG,
    PORT_MACS,
    SWITCH_CONFIG,
    build_network,
    configure_network,
    create_network,
    port_is_open,
    request_termination,
    run_controller,
    stop_process,
    stop_network,
    wait_for_switches,
)


CAPTURE_INTERFACES = (
    "s1-eth1",
    "s2-eth1",
    "s3-eth1",
    "s4-eth1",
    "s4-eth2",
)
CAPTURE_FILTER = "ether proto 0x0800 or ether proto 0x8847"
TERMINATION_SIGNALS = (signal.SIGHUP, signal.SIGTERM)
CHILD_START_SIGNALS = (*TERMINATION_SIGNALS, signal.SIGINT)

TOKENS = {
    name: f"p4-mpls-{name}".encode().ljust(32, b".")
    for name in (
        "forward",
        "reverse",
        "sentinel",
        "label-miss",
        "mpls-expiry",
        "ipv4-expiry",
        "invalid-checksum",
        "bos-zero",
        "invalid-version",
        "ipv4-options",
        "ipv4-length",
        "ipv4-miss",
    )
}

RECEIVE_CODE = """
import socket
import sys

local = (sys.argv[1], int(sys.argv[2]))
expected_peer = (sys.argv[3], int(sys.argv[4]))
expected_payload = bytes.fromhex(sys.argv[5])
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(local)
    sock.settimeout(5)
    print("READY", flush=True)
    payload, peer = sock.recvfrom(65535)
    if peer != expected_peer:
        raise SystemExit(f"unexpected peer: {peer!r}")
    if payload != expected_payload:
        raise SystemExit(f"unexpected payload: {payload!r}")
"""

SEND_CODE = """
import socket
import sys

source = (sys.argv[1], int(sys.argv[2]))
destination = (sys.argv[3], int(sys.argv[4]))
payload = bytes.fromhex(sys.argv[5])
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(source)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 64)
    sent = sock.sendto(payload, destination)
    if sent != len(payload):
        raise SystemExit(f"short send: {sent}")
"""

RAW_SEND_CODE = """
import socket
import sys

interface = sys.argv[1]
frame = bytes.fromhex(sys.argv[2])
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sock:
    sock.bind((interface, 0))
    sent = sock.send(frame)
    if sent != len(frame):
        raise SystemExit(f"short send: {sent}")
"""


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def host_ip(name):
    return HOST_CONFIG[name]["ip"].partition("/")[0]


@contextmanager
def defer_signals():
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, CHILD_START_SIGNALS)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def spawn_node_process(node, command, processes):
    with defer_signals():
        process = node.popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        processes.append(process)
    return process


def wait_process(process, description, timeout=5):
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        stop_process(process)
        raise AssertionError(f"{description} timed out") from error
    require(
        process.returncode == 0,
        f"{description} failed with status {process.returncode}: {output.strip()}",
    )
    return output


def wait_for_line(process, expected, description, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output, _ = process.communicate()
            details = output.strip()
            raise AssertionError(
                f"{description} exited with status {process.returncode}: {details}"
            )
        readable, _, _ = select.select(
            [process.stdout], [], [], max(0, deadline - time.monotonic())
        )
        if readable:
            line = process.stdout.readline().rstrip("\n")
            require(line == expected, f"{description} reported: {line}")
            return
    stop_process(process)
    raise AssertionError(f"{description} did not become ready")


def start_receiver(
    network, destination, source, source_port, destination_port, token, processes
):
    process = spawn_node_process(
        network.get(destination),
        [
            sys.executable,
            "-u",
            "-c",
            RECEIVE_CODE,
            host_ip(destination),
            str(destination_port),
            host_ip(source),
            str(source_port),
            token.hex(),
        ],
        processes,
    )
    wait_for_line(process, "READY", f"{destination} UDP receiver")
    return process


def deliver_udp(
    network,
    source,
    destination,
    source_port,
    destination_port,
    token,
    processes,
):
    receiver = start_receiver(
        network,
        destination,
        source,
        source_port,
        destination_port,
        token,
        processes,
    )
    sender = spawn_node_process(
        network.get(source),
        [
            sys.executable,
            "-c",
            SEND_CODE,
            host_ip(source),
            str(source_port),
            host_ip(destination),
            str(destination_port),
            token.hex(),
        ],
        processes,
    )
    wait_process(sender, f"{source} UDP sender")
    wait_process(receiver, f"{destination} UDP receiver")


def send_raw(node, interface, frame, description, processes):
    process = spawn_node_process(
        node,
        [sys.executable, "-c", RAW_SEND_CODE, interface, frame.hex()],
        processes,
    )
    wait_process(process, description)


def make_capture(sentinel_interfaces, sentinel_seen):
    ready = threading.Event()
    lock = threading.Lock()

    def observe(packet):
        if TOKENS["sentinel"] not in bytes(packet):
            return
        with lock:
            sentinel_interfaces.add(packet.sniffed_on)
            if sentinel_interfaces == set(CAPTURE_INTERFACES):
                sentinel_seen.set()

    sniffer = AsyncSniffer(
        iface=list(CAPTURE_INTERFACES),
        filter=CAPTURE_FILTER,
        store=True,
        prn=observe,
        started_callback=ready.set,
    )
    return sniffer, ready


def start_capture(sniffer, ready):
    try:
        with defer_signals():
            sniffer.start()
        if not ready.wait(timeout=3):
            raise AssertionError("packet capture did not become ready")
    except BaseException:
        with defer_signals():
            stop_capture(sniffer)
        raise


def stop_capture(sniffer, timeout=3):
    if sniffer is None:
        return []
    failure = None
    if sniffer.running:
        try:
            sniffer.stop(join=False)
        except BaseException as error:
            failure = error
    thread = getattr(sniffer, "thread", None)
    if thread is not None:
        thread.join(timeout=timeout)
        if thread.is_alive():
            raise AssertionError("packet capture did not stop") from failure
    if failure is not None:
        raise AssertionError(f"packet capture stop failed: {failure}") from failure
    return list(getattr(sniffer, "results", None) or [])


def wait_for_cleanup(processes, shells, interfaces, ports, sniffer, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        process_state = all(
            process is None or process.poll() is not None for process in processes
        )
        shell_state = all(shell.poll() is not None for shell in shells)
        interface_state = all(
            not (Path("/sys/class/net") / name).exists() for name in interfaces
        )
        port_state = all(not port_is_open(port) for port in ports)
        thread = getattr(sniffer, "thread", None) if sniffer is not None else None
        capture_state = thread is None or not thread.is_alive()
        if (
            process_state
            and shell_state
            and interface_state
            and port_state
            and capture_state
        ):
            return
        time.sleep(0.05)
    raise AssertionError("dataplane test resources were not fully cleaned up")


def make_ipv4_frame(
    token,
    identification,
    *,
    ttl=64,
    destination="10.0.2.2",
    version=4,
    options=None,
    total_length=None,
    invalid_checksum=False,
):
    ip = IP(
        src=host_ip("h1"),
        dst=destination,
        version=version,
        ttl=ttl,
        id=identification,
        options=options or [],
    )
    if total_length is not None:
        ip.len = total_length
    packet = (
        Ether(
            src=HOST_CONFIG["h1"]["mac"],
            dst=PORT_MACS["s1"][1],
            type=0x0800,
        )
        / ip
        / UDP(sport=47000 + identification, dport=48000)
        / Raw(load=token)
    )
    frame = bytes(packet)
    if invalid_checksum:
        decoded = Ether(frame)
        decoded[IP].chksum ^= 0xFFFF
        frame = bytes(decoded)
    return frame


def make_mpls_frame(
    token,
    identification,
    *,
    source_mac,
    destination_mac,
    label,
    bottom_of_stack,
    mpls_ttl,
    ipv4_ttl=63,
):
    return bytes(
        Ether(src=source_mac, dst=destination_mac, type=0x8847)
        / MPLS(label=label, cos=0, s=bottom_of_stack, ttl=mpls_ttl)
        / IP(
            src=host_ip("h1"),
            dst=host_ip("h2"),
            ttl=ipv4_ttl,
            id=identification,
        )
        / UDP(sport=49000 + identification, dport=50000)
        / Raw(load=token)
    )


FORWARD_STAGES = (
    {
        "interface": "s1-eth1",
        "source_mac": HOST_CONFIG["h1"]["mac"],
        "destination_mac": PORT_MACS["s1"][1],
        "ipv4_ttl": 64,
    },
    {
        "interface": "s2-eth1",
        "source_mac": PORT_MACS["s1"][2],
        "destination_mac": PORT_MACS["s2"][1],
        "label": 100,
        "mpls_ttl": 63,
        "ipv4_ttl": 63,
    },
    {
        "interface": "s3-eth1",
        "source_mac": PORT_MACS["s2"][2],
        "destination_mac": PORT_MACS["s3"][1],
        "label": 200,
        "mpls_ttl": 62,
        "ipv4_ttl": 63,
    },
    {
        "interface": "s4-eth1",
        "source_mac": PORT_MACS["s3"][2],
        "destination_mac": PORT_MACS["s4"][1],
        "label": 300,
        "mpls_ttl": 61,
        "ipv4_ttl": 63,
    },
    {
        "interface": "s4-eth2",
        "source_mac": PORT_MACS["s4"][2],
        "destination_mac": HOST_CONFIG["h2"]["mac"],
        "ipv4_ttl": 60,
    },
)

REVERSE_STAGES = (
    {
        "interface": "s4-eth2",
        "source_mac": HOST_CONFIG["h2"]["mac"],
        "destination_mac": PORT_MACS["s4"][2],
        "ipv4_ttl": 64,
    },
    {
        "interface": "s4-eth1",
        "source_mac": PORT_MACS["s4"][1],
        "destination_mac": PORT_MACS["s3"][2],
        "label": 400,
        "mpls_ttl": 63,
        "ipv4_ttl": 63,
    },
    {
        "interface": "s3-eth1",
        "source_mac": PORT_MACS["s3"][1],
        "destination_mac": PORT_MACS["s2"][2],
        "label": 500,
        "mpls_ttl": 62,
        "ipv4_ttl": 63,
    },
    {
        "interface": "s2-eth1",
        "source_mac": PORT_MACS["s2"][1],
        "destination_mac": PORT_MACS["s1"][2],
        "label": 600,
        "mpls_ttl": 61,
        "ipv4_ttl": 63,
    },
    {
        "interface": "s1-eth1",
        "source_mac": PORT_MACS["s1"][1],
        "destination_mac": HOST_CONFIG["h1"]["mac"],
        "ipv4_ttl": 60,
    },
)


def token_packets(packets, token):
    return [packet for packet in packets if token in bytes(packet)]


def require_path(packets, token, expected_interfaces, description):
    matches = token_packets(packets, token)
    observed = Counter(packet.sniffed_on for packet in matches)
    expected = Counter(expected_interfaces)
    require(
        observed == expected,
        f"{description}: expected captures {dict(expected)}, got {dict(observed)}",
    )
    return {packet.sniffed_on: packet for packet in matches}


def require_ipv4_checksum(packet, description, valid=True):
    require(IP in packet, f"{description}: missing IPv4 header")
    ip = packet[IP]
    value = checksum(bytes(ip)[: ip.ihl * 4])
    require(
        (value == 0) == valid,
        f"{description}: unexpected IPv4 checksum result {value:#x}",
    )


def verify_positive(
    packets, token, source, destination, source_port, destination_port, stages
):
    by_interface = require_path(
        packets,
        token,
        [stage["interface"] for stage in stages],
        f"{source} to {destination}",
    )
    expected_length = 20 + 8 + len(token)
    for stage in stages:
        interface = stage["interface"]
        packet = by_interface[interface]
        description = f"{source} to {destination} on {interface}"
        require(Ether in packet, f"{description}: missing Ethernet header")
        require(
            packet[Ether].src.lower() == stage["source_mac"],
            f"{description}: unexpected source MAC {packet[Ether].src}",
        )
        require(
            packet[Ether].dst.lower() == stage["destination_mac"],
            f"{description}: unexpected destination MAC {packet[Ether].dst}",
        )
        require_ipv4_checksum(packet, description)
        ip = packet[IP]
        require(ip.version == 4, f"{description}: unexpected IPv4 version {ip.version}")
        require(ip.ihl == 5, f"{description}: unexpected IPv4 IHL {ip.ihl}")
        require(
            ip.len == expected_length, f"{description}: unexpected IPv4 length {ip.len}"
        )
        require(
            ip.src == host_ip(source), f"{description}: unexpected source IP {ip.src}"
        )
        require(
            ip.dst == host_ip(destination),
            f"{description}: unexpected destination IP {ip.dst}",
        )
        require(
            ip.ttl == stage["ipv4_ttl"],
            f"{description}: unexpected IPv4 TTL {ip.ttl}",
        )
        require(UDP in packet, f"{description}: missing UDP header")
        udp = packet[UDP]
        require(udp.sport == source_port, f"{description}: unexpected UDP source port")
        require(
            udp.dport == destination_port,
            f"{description}: unexpected UDP destination port",
        )
        require(bytes(udp.payload) == token, f"{description}: payload changed")
        require(
            udp.chksum != 0 and in4_chksum(socket.IPPROTO_UDP, ip, bytes(udp)) == 0,
            f"{description}: invalid UDP checksum",
        )

        if "label" not in stage:
            require(packet[Ether].type == 0x0800, f"{description}: not IPv4 Ethernet")
            require(MPLS not in packet, f"{description}: unexpected MPLS header")
        else:
            require(packet[Ether].type == 0x8847, f"{description}: not MPLS Ethernet")
            require(MPLS in packet, f"{description}: missing MPLS header")
            mpls = packet[MPLS]
            require(mpls.label == stage["label"], f"{description}: label {mpls.label}")
            require(mpls.cos == 0, f"{description}: traffic class {mpls.cos}")
            require(mpls.s == 1, f"{description}: bottom-of-stack {mpls.s}")
            require(
                mpls.ttl == stage["mpls_ttl"],
                f"{description}: unexpected MPLS TTL {mpls.ttl}",
            )
            require(
                packet.getlayer(MPLS, nb=2) is None,
                f"{description}: more than one MPLS header",
            )


def verify_negative_cases(packets):
    label_miss = require_path(
        packets, TOKENS["label-miss"], ["s1-eth1"], "MPLS label miss"
    )["s1-eth1"]
    require(label_miss[MPLS].label == 777, "MPLS miss label changed")
    require(label_miss[MPLS].s == 1, "MPLS miss BoS changed")
    require_ipv4_checksum(label_miss, "MPLS label miss")

    expiry = require_path(
        packets,
        TOKENS["mpls-expiry"],
        ["s2-eth1", "s3-eth1"],
        "MPLS TTL expiry",
    )
    for interface, label, ttl, source_mac, destination_mac in (
        ("s2-eth1", 100, 2, PORT_MACS["s1"][2], PORT_MACS["s2"][1]),
        ("s3-eth1", 200, 1, PORT_MACS["s2"][2], PORT_MACS["s3"][1]),
    ):
        packet = expiry[interface]
        require(packet[MPLS].label == label, f"MPLS expiry label on {interface}")
        require(packet[MPLS].ttl == ttl, f"MPLS expiry TTL on {interface}")
        require(
            packet[Ether].src.lower() == source_mac,
            f"MPLS expiry source MAC on {interface}",
        )
        require(
            packet[Ether].dst.lower() == destination_mac,
            f"MPLS expiry destination MAC on {interface}",
        )
        require(packet[IP].ttl == 63, f"MPLS expiry inner IPv4 TTL on {interface}")
        require_ipv4_checksum(packet, f"MPLS TTL expiry on {interface}")

    bos_zero = require_path(
        packets, TOKENS["bos-zero"], ["s1-eth1"], "unsupported MPLS BoS"
    )["s1-eth1"]
    require(bos_zero[MPLS].label == 600, "unsupported BoS label changed")
    require(bos_zero[MPLS].s == 0, "unsupported BoS packet was not injected")

    for name, description, field, expected, valid_checksum in (
        ("ipv4-expiry", "IPv4 TTL expiry", "ttl", 1, True),
        ("invalid-checksum", "invalid IPv4 checksum", None, None, False),
        ("invalid-version", "invalid IPv4 version", "version", 5, True),
        ("ipv4-options", "unsupported IPv4 options", "ihl", 6, True),
        ("ipv4-length", "invalid IPv4 length", "len", 19, True),
        ("ipv4-miss", "IPv4 table miss", "dst", "192.0.2.1", True),
    ):
        packet = require_path(packets, TOKENS[name], ["s1-eth1"], description)[
            "s1-eth1"
        ]
        if field is not None:
            require(
                getattr(packet[IP], field) == expected,
                f"{description}: unexpected {field}",
            )
        require_ipv4_checksum(packet, description, valid=valid_checksum)
        if name == "ipv4-options":
            require(
                checksum(bytes(packet[IP])[:20]) == 0,
                "IPv4 options checksum is not valid for the fixed header",
            )


def inject_negative_cases(network, processes):
    h1 = network.get("h1")
    s1 = network.get("s1")
    mpls_cases = (
        (
            "label-miss",
            h1,
            "h1-eth0",
            101,
            HOST_CONFIG["h1"]["mac"],
            PORT_MACS["s1"][1],
            777,
            1,
            64,
        ),
        (
            "bos-zero",
            h1,
            "h1-eth0",
            104,
            HOST_CONFIG["h1"]["mac"],
            PORT_MACS["s1"][1],
            600,
            0,
            64,
        ),
        (
            "mpls-expiry",
            s1,
            "s1-eth2",
            109,
            PORT_MACS["s1"][2],
            PORT_MACS["s2"][1],
            100,
            1,
            2,
        ),
    )
    for name, node, interface, identification, src, dst, label, bos, ttl in mpls_cases:
        frame = make_mpls_frame(
            TOKENS[name],
            identification,
            source_mac=src,
            destination_mac=dst,
            label=label,
            bottom_of_stack=bos,
            mpls_ttl=ttl,
        )
        send_raw(node, interface, frame, f"{name} sender", processes)

    for name, identification, parameters in (
        ("ipv4-expiry", 102, {"ttl": 1}),
        ("invalid-checksum", 103, {"invalid_checksum": True}),
        ("invalid-version", 105, {"version": 5}),
        (
            "ipv4-options",
            106,
            {"options": b"\x00\x00\x00\x00"},
        ),
        ("ipv4-length", 107, {"total_length": 19}),
        ("ipv4-miss", 108, {"destination": "192.0.2.1"}),
    ):
        frame = make_ipv4_frame(TOKENS[name], identification, **parameters)
        send_raw(h1, "h1-eth0", frame, f"{name} sender", processes)


def run_test(controller, device_config, p4info):
    ports = [
        port
        for config in SWITCH_CONFIG.values()
        for port in (config["grpc_port"], config["thrift_port"])
    ]
    with tempfile.TemporaryDirectory(prefix="p4-mpls-dataplane-") as log_dir:
        runtime_path = Path(log_dir)
        network = None
        shells = []
        interfaces = []
        processes = []
        sniffer = None
        cleanup_failures = []
        try:
            with defer_signals():
                network = create_network(runtime_path, build=False)
            try:
                build_network(network)
            except BaseException:
                network = None
                raise
            shells = [node.shell for node in [*network.hosts, *network.switches]]
            interfaces = [
                intf.name for link in network.links for intf in (link.intf1, link.intf2)
            ]
            network.start()
            configure_network(network)
            wait_for_switches(network)
            run_controller(
                controller,
                device_config,
                p4info,
                election_id=4,
                controller_timeout=20,
                process_timeout=30,
            )

            sentinel_interfaces = set()
            sentinel_seen = threading.Event()
            sniffer, capture_ready = make_capture(sentinel_interfaces, sentinel_seen)
            start_capture(sniffer, capture_ready)

            deliver_udp(network, "h1", "h2", 41001, 42001, TOKENS["forward"], processes)
            deliver_udp(network, "h2", "h1", 42002, 41002, TOKENS["reverse"], processes)
            inject_negative_cases(network, processes)
            deliver_udp(
                network, "h1", "h2", 41003, 42003, TOKENS["sentinel"], processes
            )
            if not sentinel_seen.wait(timeout=3):
                missing = sorted(set(CAPTURE_INTERFACES) - sentinel_interfaces)
                raise AssertionError(f"capture drain marker missing from {missing}")

            captured = stop_capture(sniffer)
            verify_positive(
                captured,
                TOKENS["forward"],
                "h1",
                "h2",
                41001,
                42001,
                FORWARD_STAGES,
            )
            verify_positive(
                captured,
                TOKENS["reverse"],
                "h2",
                "h1",
                42002,
                41002,
                REVERSE_STAGES,
            )
            verify_negative_cases(captured)

            for switch in network.switches:
                require(
                    switch.process.poll() is None,
                    f"{switch.name}: BMv2 exited during packet tests",
                )
            require(
                all(port_is_open(port) for port in ports),
                "runtime endpoint closed during packet tests",
            )
        finally:
            with defer_signals():
                try:
                    stop_capture(sniffer)
                except BaseException as error:
                    cleanup_failures.append(f"capture stop: {error}")
                for process in processes:
                    try:
                        stop_process(process)
                    except BaseException as error:
                        cleanup_failures.append(f"child stop: {error}")
                if network is not None:
                    if not shells:
                        shells = [
                            node.shell
                            for node in [*network.hosts, *network.switches]
                            if node.shell is not None
                        ]
                    if not interfaces:
                        interfaces = [
                            intf.name
                            for link in network.links
                            for intf in (link.intf1, link.intf2)
                        ]
                    switch_processes = [switch.process for switch in network.switches]
                    cleanup_failures.extend(stop_network(network))
                    try:
                        wait_for_cleanup(
                            [*processes, *switch_processes],
                            shells,
                            interfaces,
                            ports,
                            sniffer,
                        )
                    except AssertionError as error:
                        cleanup_failures.append(str(error))
            require(not cleanup_failures, "; ".join(cleanup_failures))

        require(runtime_path.exists(), "runtime directory disappeared too early")

    require(not runtime_path.exists(), "runtime directory was not removed")
    print("packet-level dataplane integration: PASS")


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: test_dataplane.py CONTROLLER BMV2_JSON P4INFO")
    require(os.geteuid() == 0, "dataplane integration test must run as root")
    require(
        all(len(token) == 32 for token in TOKENS.values()),
        "packet tokens must be 32 bytes",
    )
    require(len(set(TOKENS.values())) == len(TOKENS), "packet tokens must be unique")

    controller = Path(sys.argv[1]).resolve()
    device_config = Path(sys.argv[2]).resolve()
    p4info = Path(sys.argv[3]).resolve()
    for path in (controller, device_config, p4info):
        require(path.is_file(), f"required artifact missing: {path}")

    previous_handlers = {
        signum: signal.signal(signum, request_termination)
        for signum in TERMINATION_SIGNALS
    }
    try:
        run_test(controller, device_config, p4info)
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    main()
