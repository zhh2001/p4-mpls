import os
import signal
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mininet"))

from topology import (
    HOST_CONFIG,
    INTERFACE_NAMES,
    PORT_MACS,
    SWITCH_CONFIG,
    configure_network,
    create_network,
    port_is_open,
    request_termination,
    run_in_node,
    stop_network,
    wait_for_switches,
)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def has_option(command, option, value):
    return any(
        command[index : index + 2] == [option, str(value)]
        for index in range(len(command) - 1)
    )


def verify_host(network, name):
    config = HOST_CONFIG[name]
    host = network.get(name)
    interface = host.defaultIntf().name

    addresses = run_in_node(host, "ip", "-4", "-o", "address", "show", "dev", interface)
    require(config["ip"] in addresses, f"{name}: IPv4 address missing")
    actual_mac = run_in_node(host, "cat", f"/sys/class/net/{interface}/address")
    require(actual_mac == config["mac"], f"{name}: MAC address mismatch")

    route = run_in_node(host, "ip", "-4", "route", "show", config["remote_subnet"])
    require(f"via {config['gateway']}" in route, f"{name}: static route missing")
    require(f"dev {interface}" in route, f"{name}: route interface is incorrect")

    neighbor = run_in_node(host, "ip", "neigh", "show", config["gateway"], "dev", interface)
    require(config["gateway_mac"] in neighbor, f"{name}: static neighbor missing")
    require("PERMANENT" in neighbor, f"{name}: neighbor is not permanent")

    default_route = run_in_node(host, "ip", "-4", "route", "show", "default")
    require(not default_route, f"{name}: unexpected default route")
    ipv6_disabled = run_in_node(
        host, "sysctl", "-n", "net.ipv6.conf.all.disable_ipv6"
    )
    require(ipv6_disabled == "1", f"{name}: IPv6 remains enabled")


def verify_offloads(node, interface):
    output = run_in_node(node, "ethtool", "--show-offload", interface)
    for feature in (
        "rx-checksumming",
        "tx-checksumming",
        "scatter-gather",
        "tcp-segmentation-offload",
        "generic-segmentation-offload",
        "generic-receive-offload",
        "large-receive-offload",
    ):
        require(f"{feature}: off" in output, f"{node.name}: {feature} remains enabled")


def wait_for_cleanup(processes, shells, interfaces, ports, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        processes_stopped = all(
            process is None or process.poll() is not None for process in processes
        )
        shells_stopped = all(shell.poll() is not None for shell in shells)
        interfaces_removed = all(
            not (Path("/sys/class/net") / name).exists() for name in interfaces
        )
        ports_closed = all(not port_is_open(port) for port in ports)
        if processes_stopped and shells_stopped and interfaces_removed and ports_closed:
            return
        time.sleep(0.05)
    raise AssertionError("Mininet/BMv2 resources were not fully cleaned up")


def run_test():
    ports = [
        port
        for config in SWITCH_CONFIG.values()
        for port in (config["grpc_port"], config["thrift_port"])
    ]
    with tempfile.TemporaryDirectory(prefix="p4-mpls-topology-") as log_dir:
        runtime_path = Path(log_dir)
        network = create_network(runtime_path)
        processes = []
        shells = [node.shell for node in [*network.hosts, *network.switches]]
        interfaces = [
            intf.name for link in network.links for intf in (link.intf1, link.intf2)
        ]

        try:
            network.start()
            processes = [switch.process for switch in network.switches]
            configure_network(network)
            wait_for_switches(network)
            require(not network.controllers, "unexpected Mininet controller")
            require(
                [host.name for host in network.hosts] == ["h1", "h2"],
                "unexpected hosts",
            )
            require(
                [switch.name for switch in network.switches]
                == ["s1", "s2", "s3", "s4"],
                "unexpected switches",
            )
            require(len(network.links) == 5, "unexpected link count")
            link_names = {
                frozenset((link.intf1.name, link.intf2.name)) for link in network.links
            }
            expected_links = {
                frozenset(("h1-eth0", "s1-eth1")),
                frozenset(("s1-eth2", "s2-eth1")),
                frozenset(("s2-eth2", "s3-eth1")),
                frozenset(("s3-eth2", "s4-eth1")),
                frozenset(("s4-eth2", "h2-eth0")),
            }
            require(link_names == expected_links, "unexpected topology links")
            require(set(interfaces) == INTERFACE_NAMES, "unexpected interface names")
            require(
                len({process.pid for process in processes}) == 4,
                "BMv2 process IDs are not unique",
            )

            for name, config in SWITCH_CONFIG.items():
                switch = network.get(name)
                require(switch.process.poll() is None, f"{name}: BMv2 is not running")
                require(
                    Path(f"/proc/{switch.process.pid}/exe").resolve()
                    == Path(switch.executable).resolve(),
                    f"{name}: unexpected switch executable",
                )
                require(
                    switch.device_id == config["device_id"],
                    f"{name}: incorrect device ID",
                )
                require(
                    switch.grpc_port == config["grpc_port"],
                    f"{name}: incorrect gRPC port",
                )
                require(
                    switch.thrift_port == config["thrift_port"],
                    f"{name}: incorrect Thrift port",
                )
                require("--no-p4" in switch.command, f"{name}: pipeline preloaded")
                require(
                    has_option(switch.command, "--device-id", config["device_id"]),
                    f"{name}: device ID missing from BMv2 command",
                )
                require(
                    has_option(
                        switch.command, "--thrift-port", config["thrift_port"]
                    ),
                    f"{name}: Thrift port missing from BMv2 command",
                )
                separator = switch.command.index("--")
                require(
                    switch.command[separator + 1 :]
                    == [
                        "--grpc-server-addr",
                        f"127.0.0.1:{config['grpc_port']}",
                    ],
                    f"{name}: incorrect P4Runtime command",
                )
                data_ports = {
                    port
                    for port, intf in switch.intfs.items()
                    if intf.link is not None
                }
                require(data_ports == {1, 2}, f"{name}: incorrect data-plane ports")

                for port, expected_mac in PORT_MACS[name].items():
                    interface = switch.intfs[port].name
                    require(
                        f"{port}@{interface}" in switch.command,
                        f"{name}: port {port} missing from BMv2 command",
                    )
                    actual_mac = run_in_node(
                        switch, "cat", f"/sys/class/net/{interface}/address"
                    )
                    require(
                        actual_mac == expected_mac,
                        f"{name}: port {port} MAC mismatch",
                    )
                    verify_offloads(switch, interface)

                require(
                    port_is_open(config["grpc_port"]),
                    f"{name}: P4Runtime unavailable",
                )
                require(
                    port_is_open(config["thrift_port"]),
                    f"{name}: Thrift unavailable",
                )

            for name in HOST_CONFIG:
                verify_host(network, name)
                host = network.get(name)
                verify_offloads(host, host.defaultIntf().name)
        finally:
            processes = [switch.process for switch in network.switches]
            cleanup_failures = stop_network(network)
            try:
                wait_for_cleanup(processes, shells, interfaces, ports)
            except AssertionError as error:
                details = "; ".join(cleanup_failures)
                if details:
                    raise AssertionError(f"{error}; {details}") from error
                raise
            require(not cleanup_failures, "; ".join(cleanup_failures))
            stop_errors = [
                f"{switch.name}: {switch.stop_error}"
                for switch in network.switches
                if switch.stop_error is not None
            ]
            require(not stop_errors, "; ".join(stop_errors))

        require(runtime_path.exists(), "runtime directory disappeared too early")

    require(not runtime_path.exists(), "runtime directory was not removed")
    print("topology smoke test: PASS")


def main():
    require(os.geteuid() == 0, "topology test must run as root")
    previous_handlers = {
        signum: signal.signal(signum, request_termination)
        for signum in (signal.SIGHUP, signal.SIGTERM)
    }
    try:
        run_test()
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    main()
