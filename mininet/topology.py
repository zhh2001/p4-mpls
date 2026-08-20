import argparse
import math
import os
import signal
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from mininet.cli import CLI
from mininet.log import info, setLogLevel, warn
from mininet.net import Mininet
from mininet.node import Switch
from mininet.topo import Topo


ROOT = Path(__file__).resolve().parents[1]
TERMINATION_SIGNALS = (signal.SIGHUP, signal.SIGTERM)
CHILD_START_SIGNALS = (*TERMINATION_SIGNALS, signal.SIGINT)

HOST_CONFIG = {
    "h1": {
        "ip": "10.0.1.1/24",
        "mac": "02:00:00:00:01:01",
        "remote_subnet": "10.0.2.0/24",
        "gateway": "10.0.1.254",
        "gateway_mac": "02:00:00:01:01:01",
    },
    "h2": {
        "ip": "10.0.2.2/24",
        "mac": "02:00:00:00:02:02",
        "remote_subnet": "10.0.1.0/24",
        "gateway": "10.0.2.254",
        "gateway_mac": "02:00:00:04:02:01",
    },
}

SWITCH_CONFIG = {
    "s1": {"device_id": 1, "grpc_port": 50051, "thrift_port": 9090},
    "s2": {"device_id": 2, "grpc_port": 50052, "thrift_port": 9091},
    "s3": {"device_id": 3, "grpc_port": 50053, "thrift_port": 9092},
    "s4": {"device_id": 4, "grpc_port": 50054, "thrift_port": 9093},
}

PORT_MACS = {
    "s1": {1: "02:00:00:01:01:01", 2: "02:00:00:01:02:01"},
    "s2": {1: "02:00:00:02:01:01", 2: "02:00:00:02:02:01"},
    "s3": {1: "02:00:00:03:01:01", 2: "02:00:00:03:02:01"},
    "s4": {1: "02:00:00:04:01:01", 2: "02:00:00:04:02:01"},
}

INTERFACE_NAMES = {
    "h1-eth0",
    "s1-eth1",
    "s1-eth2",
    "s2-eth1",
    "s2-eth2",
    "s3-eth1",
    "s3-eth2",
    "s4-eth1",
    "s4-eth2",
    "h2-eth0",
}


def run_in_node(node, *command):
    process = None
    try:
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, CHILD_START_SIGNALS)
        try:
            process = node.popen(
                list(command),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        output, _ = process.communicate(timeout=3)
    except subprocess.TimeoutExpired as error:
        stop_process(process)
        rendered = " ".join(command)
        raise RuntimeError(f"{node.name}: {rendered} timed out") from error
    except BaseException:
        stop_process(process)
        raise
    if process.returncode != 0:
        rendered = " ".join(command)
        raise RuntimeError(f"{node.name}: {rendered} failed: {output.strip()}")
    return output.strip()


class P4RuntimeSwitch(Switch):
    def __init__(
        self,
        name,
        device_id,
        grpc_port,
        thrift_port,
        port_macs,
        log_dir,
        executable="simple_switch_grpc",
        **params,
    ):
        super().__init__(name, **params)
        self.device_id = int(device_id)
        self.grpc_port = int(grpc_port)
        self.thrift_port = int(thrift_port)
        self.port_macs = {int(port): mac for port, mac in port_macs.items()}
        self.executable = shutil.which(executable)
        if self.executable is None:
            raise RuntimeError(f"executable not found: {executable}")

        self.log_dir = Path(log_dir).resolve()
        self.log_path = self.log_dir / f"{name}.log"
        self.process = None
        self.command = None
        self.stop_error = None
        self._log_file = None

    def start(self, controllers):
        del controllers
        if self.process is not None and self.process.poll() is None:
            raise RuntimeError(f"{self.name}: BMv2 is already running")
        self.log_dir.mkdir(parents=True, exist_ok=True)

        interfaces = []
        for port, intf in sorted(self.intfs.items()):
            if port <= 0 or intf.link is None:
                continue
            if port not in self.port_macs:
                raise RuntimeError(f"{self.name}: no MAC configured for port {port}")
            output = intf.setMAC(self.port_macs[port])
            if output.strip():
                raise RuntimeError(f"{self.name}: failed to set {intf.name} MAC: {output}")
            interfaces.append((port, intf.name))

        if set(self.port_macs) != {port for port, _ in interfaces}:
            raise RuntimeError(f"{self.name}: configured port set does not match topology")

        self.command = [
            self.executable,
            "--no-p4",
            "--device-id",
            str(self.device_id),
            "--thrift-port",
            str(self.thrift_port),
            "--log-console",
            "-L",
            "warn",
        ]
        for port, interface in interfaces:
            self.command.extend(["--interface", f"{port}@{interface}"])
        self.command.extend(
            ["--", "--grpc-server-addr", f"127.0.0.1:{self.grpc_port}"]
        )

        self._log_file = self.log_path.open("w", encoding="utf-8")
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, CHILD_START_SIGNALS)
        try:
            self.process = self.popen(
                self.command,
                stdin=subprocess.DEVNULL,
                stdout=self._log_file,
                stderr=subprocess.STDOUT,
            )
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

    def stop(self, deleteIntfs=True):
        failures = []
        try:
            if self.process is not None and self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3)
        except Exception as error:
            failures.append(f"process: {error}")
        try:
            if self._log_file is not None:
                self._log_file.close()
                self._log_file = None
        except Exception as error:
            failures.append(f"log: {error}")
        try:
            super().stop(deleteIntfs)
        except Exception as error:
            failures.append(f"interfaces: {error}")

        self.stop_error = "; ".join(failures) if failures else None
        if self.stop_error is not None:
            warn(f"*** {self.name} cleanup warning: {self.stop_error}\n")


class MplsTopo(Topo):
    def build(self, log_dir, executable="simple_switch_grpc"):
        h1 = self.addHost("h1", ip=HOST_CONFIG["h1"]["ip"], mac=HOST_CONFIG["h1"]["mac"])
        h2 = self.addHost("h2", ip=HOST_CONFIG["h2"]["ip"], mac=HOST_CONFIG["h2"]["mac"])

        switches = {}
        for name, config in SWITCH_CONFIG.items():
            switches[name] = self.addSwitch(
                name,
                cls=P4RuntimeSwitch,
                port_macs=PORT_MACS[name],
                log_dir=str(log_dir),
                executable=executable,
                **config,
            )

        self.addLink(h1, switches["s1"], port1=0, port2=1)
        self.addLink(switches["s1"], switches["s2"], port1=2, port2=1)
        self.addLink(switches["s2"], switches["s3"], port1=2, port2=1)
        self.addLink(switches["s3"], switches["s4"], port1=2, port2=1)
        self.addLink(switches["s4"], h2, port1=2, port2=0)


def port_is_open(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.1):
            return True
    except OSError:
        return False


def preflight(executable):
    if os.geteuid() != 0:
        raise RuntimeError("Mininet must run as root")
    if shutil.which(executable) is None:
        raise RuntimeError(f"executable not found: {executable}")

    existing = sorted(
        name for name in INTERFACE_NAMES if (Path("/sys/class/net") / name).exists()
    )
    if existing:
        raise RuntimeError(f"topology interfaces already exist: {', '.join(existing)}")

    busy_ports = sorted(
        port
        for config in SWITCH_CONFIG.values()
        for port in (config["grpc_port"], config["thrift_port"])
        if port_is_open(port)
    )
    if busy_ports:
        rendered = ", ".join(str(port) for port in busy_ports)
        raise RuntimeError(f"runtime ports already in use: {rendered}")


def stop_network(network):
    failures = []
    try:
        network.stop()
    except BaseException as error:
        failures.append(f"Mininet stop: {error}")
        for switch in network.switches:
            try:
                switch.stop()
            except BaseException as switch_error:
                failures.append(f"{switch.name} stop: {switch_error}")
        for link in network.links:
            try:
                link.stop()
            except BaseException as link_error:
                failures.append(f"{link}: {link_error}")
        for node in [*network.switches, *network.hosts]:
            try:
                node.terminate()
            except BaseException as node_error:
                failures.append(f"{node.name} terminate: {node_error}")
    for switch in network.switches:
        if switch.stop_error is not None:
            failures.append(f"{switch.name} cleanup: {switch.stop_error}")
    return failures


def direct_child_pids():
    path = Path(f"/proc/{os.getpid()}/task/{os.getpid()}/children")
    try:
        return {int(pid) for pid in path.read_text().split()}
    except FileNotFoundError:
        return set()


def stop_build_children(baseline, timeout=3):
    children = direct_child_pids() - baseline
    for pid in children:
        try:
            process_group = os.getpgid(pid)
            if process_group == pid:
                os.killpg(process_group, signal.SIGHUP)
            else:
                os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass

    deadline = time.monotonic() + timeout
    while children and time.monotonic() < deadline:
        for pid in list(children):
            try:
                waited, _ = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                children.remove(pid)
                continue
            if waited == pid:
                children.remove(pid)
        if children:
            time.sleep(0.05)

    for pid in list(children):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            children.remove(pid)
    deadline = time.monotonic() + 1
    while children and time.monotonic() < deadline:
        for pid in list(children):
            try:
                waited, _ = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                children.remove(pid)
                continue
            if waited == pid:
                children.remove(pid)
        if children:
            time.sleep(0.05)
    return [f"build child still running: {pid}" for pid in children]


def remove_build_interfaces():
    failures = []
    ip_command = shutil.which("ip")
    if ip_command is None:
        return ["ip executable not found during build cleanup"]
    for name in sorted(INTERFACE_NAMES):
        path = Path("/sys/class/net") / name
        if not path.exists():
            continue
        try:
            result = subprocess.run(
                [ip_command, "link", "delete", "dev", name],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=3,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            failures.append(f"{name} delete: {error}")
            continue
        if result.returncode != 0 and path.exists():
            failures.append(f"{name} delete: {result.stdout.strip()}")
    return failures


def build_network(network):
    baseline = direct_child_pids()
    try:
        network.build()
    except BaseException as error:
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, CHILD_START_SIGNALS)
        try:
            failures = stop_network(network)
            failures.extend(stop_build_children(baseline))
            failures.extend(remove_build_interfaces())
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        if failures:
            details = "; ".join(failures)
            raise RuntimeError(f"network build cleanup failed: {details}") from error
        raise
    return network


def create_network(
    log_dir=ROOT / "build" / "run", executable="simple_switch_grpc", build=True
):
    preflight(executable)
    topo = MplsTopo(log_dir=Path(log_dir).resolve(), executable=executable)
    network = Mininet(
        topo=topo,
        controller=None,
        autoSetMacs=False,
        autoStaticArp=False,
        build=False,
    )
    if not build:
        return network
    return build_network(network)


def configure_network(network):
    for node in [*network.hosts, *network.switches]:
        for intf in node.intfList():
            if intf.link is None:
                continue
            run_in_node(
                node,
                "ethtool",
                "--offload",
                intf.name,
                "rx",
                "off",
                "tx",
                "off",
                "sg",
                "off",
                "tso",
                "off",
                "gso",
                "off",
                "gro",
                "off",
                "lro",
                "off",
            )

    for name, config in HOST_CONFIG.items():
        host = network.get(name)
        interface = host.defaultIntf().name
        run_in_node(host, "sysctl", "-q", "-w", "net.ipv6.conf.all.disable_ipv6=1")
        run_in_node(
            host,
            "ip",
            "route",
            "replace",
            config["remote_subnet"],
            "via",
            config["gateway"],
            "dev",
            interface,
        )
        run_in_node(
            host,
            "ip",
            "neigh",
            "replace",
            config["gateway"],
            "lladdr",
            config["gateway_mac"],
            "nud",
            "permanent",
            "dev",
            interface,
        )


def wait_for_switches(network, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for switch in network.switches:
            if switch.process is not None and switch.process.poll() is not None:
                log = switch.log_path.read_text(errors="replace")
                raise RuntimeError(
                    f"{switch.name} exited with {switch.process.returncode}: {log.strip()}"
                )
        if all(
            port_is_open(port)
            for config in SWITCH_CONFIG.values()
            for port in (config["grpc_port"], config["thrift_port"])
        ):
            return
        time.sleep(0.05)
    raise TimeoutError("BMv2 runtime endpoints did not become ready")


def stop_process(process):
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def run_controller(
    controller,
    device_config,
    p4info,
    election_id=1,
    controller_timeout=20,
    process_timeout=30,
):
    controller, device_config, p4info = validate_controller_run(
        controller,
        device_config,
        p4info,
        election_id,
        controller_timeout,
        process_timeout,
    )

    command = [
        str(controller),
        "--device-config",
        str(device_config),
        "--p4info",
        str(p4info),
        "--election-id",
        str(election_id),
        "--timeout",
        f"{controller_timeout:g}s",
    ]
    process = None
    try:
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, CHILD_START_SIGNALS)
        try:
            process = subprocess.Popen(
                command,
                cwd=ROOT,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

        try:
            output, _ = process.communicate(timeout=process_timeout)
        except subprocess.TimeoutExpired as error:
            stop_process(process)
            raise RuntimeError("controller timed out") from error
    except BaseException:
        stop_process(process)
        raise

    if process.returncode != 0:
        details = output.strip()
        raise RuntimeError(f"controller failed with status {process.returncode}: {details}")
    if output:
        info(output if output.endswith("\n") else f"{output}\n")
    return output.strip()


def validate_controller_run(
    controller,
    device_config,
    p4info,
    election_id,
    controller_timeout,
    process_timeout,
):
    controller = Path(controller).resolve()
    device_config = Path(device_config).resolve()
    p4info = Path(p4info).resolve()
    for path in (controller, device_config, p4info):
        if not path.is_file():
            raise RuntimeError(f"required artifact missing: {path}")
    if not os.access(controller, os.X_OK):
        raise RuntimeError(f"controller is not executable: {controller}")
    if election_id <= 0:
        raise RuntimeError("controller election ID must be positive")
    if (
        not math.isfinite(controller_timeout)
        or not math.isfinite(process_timeout)
        or controller_timeout <= 0
        or process_timeout <= controller_timeout
    ):
        raise RuntimeError("controller deadlines are invalid")
    return controller, device_config, p4info


def require_root():
    if os.geteuid() != 0:
        raise SystemExit("Mininet must run as root")


class TerminationRequested(Exception):
    pass


def request_termination(signum, frame):
    del signum, frame
    raise TerminationRequested


def main():
    parser = argparse.ArgumentParser(description="Run the MPLS Mininet topology")
    parser.add_argument("--bmv2", default="simple_switch_grpc")
    parser.add_argument("--log-dir", type=Path)
    parser.add_argument("--controller", type=Path)
    parser.add_argument(
        "--device-config", type=Path, default=ROOT / "build" / "mpls.json"
    )
    parser.add_argument("--p4info", type=Path, default=ROOT / "build" / "mpls.p4info.txtpb")
    parser.add_argument("--controller-timeout", type=float, default=20)
    args = parser.parse_args()

    if args.controller is not None:
        try:
            args.controller, args.device_config, args.p4info = validate_controller_run(
                args.controller,
                args.device_config,
                args.p4info,
                1,
                args.controller_timeout,
                args.controller_timeout + 10,
            )
        except RuntimeError as error:
            parser.error(str(error))

    require_root()
    setLogLevel("info")
    previous_handlers = {
        signum: signal.signal(signum, request_termination)
        for signum in TERMINATION_SIGNALS
    }
    runtime_dir = None
    if args.log_dir is None:
        runtime_dir = tempfile.TemporaryDirectory(prefix="p4-mpls-")
        log_dir = Path(runtime_dir.name)
    else:
        log_dir = args.log_dir

    network = None
    cleanup_failures = []
    try:
        network = create_network(log_dir, args.bmv2)
        network.start()
        configure_network(network)
        wait_for_switches(network)
        info("*** P4Runtime endpoints: 127.0.0.1:50051-50054\n")
        if args.controller is not None:
            info("*** Programming the P4Runtime pipeline\n")
            run_controller(
                args.controller,
                args.device_config,
                args.p4info,
                controller_timeout=args.controller_timeout,
                process_timeout=args.controller_timeout + 10,
            )
        CLI(network)
    except TerminationRequested:
        info("\n*** Termination requested\n")
    finally:
        if network is not None:
            cleanup_failures = stop_network(network)
        if runtime_dir is not None:
            runtime_dir.cleanup()
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
    if cleanup_failures:
        raise RuntimeError("; ".join(cleanup_failures))


if __name__ == "__main__":
    main()
