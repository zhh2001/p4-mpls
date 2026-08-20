import os
import signal
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mininet"))

from topology import (
    SWITCH_CONFIG,
    configure_network,
    create_network,
    port_is_open,
    request_termination,
    stop_network,
    wait_for_switches,
)

TERMINATION_SIGNALS = (signal.SIGHUP, signal.SIGTERM)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


@contextmanager
def defer_termination():
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, TERMINATION_SIGNALS)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def stop_process(process):
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


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
    raise AssertionError("controller/Mininet/BMv2 resources were not fully cleaned up")


def run_controller(controller, device_config, p4info, extra_args, processes):
    with defer_termination():
        process = subprocess.Popen(
            [
                str(controller),
                "--device-config",
                str(device_config),
                "--p4info",
                str(p4info),
                "--timeout",
                "20s",
                *extra_args,
            ],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        processes.append(process)
    try:
        output, error_output = process.communicate(timeout=30)
    except subprocess.TimeoutExpired as error:
        stop_process(process)
        raise AssertionError("controller timed out") from error
    return process.returncode, output.splitlines(), error_output


def run_test(controller, device_config, p4info):
    ports = [
        port
        for config in SWITCH_CONFIG.values()
        for port in (config["grpc_port"], config["thrift_port"])
    ]
    with tempfile.TemporaryDirectory(prefix="p4-mpls-controller-") as log_dir:
        runtime_path = Path(log_dir)
        network = create_network(runtime_path)
        shells = [node.shell for node in [*network.hosts, *network.switches]]
        interfaces = [
            intf.name for link in network.links for intf in (link.intf1, link.intf2)
        ]
        controller_processes = []

        try:
            network.start()
            configure_network(network)
            wait_for_switches(network)

            returncode, output, error_output = run_controller(
                controller,
                device_config,
                p4info,
                ["--verify-only"],
                controller_processes,
            )
            require(returncode != 0, "verification unexpectedly accepted empty switches")
            require(not output, f"unexpected verification output: {output!r}")
            require(
                error_output.startswith("s1: verify pipeline:"),
                f"unclear incomplete-configuration error: {error_output!r}",
            )

            returncode, configured, error_output = run_controller(
                controller,
                device_config,
                p4info,
                ["--election-id", "2"],
                controller_processes,
            )
            require(returncode == 0, f"controller failed: {error_output.strip()}")
            require(not error_output, f"unexpected controller stderr: {error_output}")
            require(
                configured
                == [
                    "s1: pipeline and 2 entries verified",
                    "s2: pipeline and 2 entries verified",
                    "s3: pipeline and 2 entries verified",
                    "s4: pipeline and 2 entries verified",
                    "configured 4 switches",
                ],
                f"unexpected controller output: {configured!r}",
            )

            returncode, verified, error_output = run_controller(
                controller,
                device_config,
                p4info,
                ["--verify-only", "--election-id", "3"],
                controller_processes,
            )
            require(returncode == 0, f"verification failed: {error_output.strip()}")
            require(not error_output, f"unexpected verification stderr: {error_output}")
            require(
                verified
                == [
                    "s1: pipeline and 2 entries verified",
                    "s2: pipeline and 2 entries verified",
                    "s3: pipeline and 2 entries verified",
                    "s4: pipeline and 2 entries verified",
                    "verified 4 switches",
                ],
                f"unexpected verification output: {verified!r}",
            )

            for switch in network.switches:
                require(
                    switch.process.poll() is None,
                    f"{switch.name}: BMv2 exited during configuration",
                )
            require(
                all(port_is_open(port) for port in ports),
                "runtime endpoint closed during configuration",
            )
        finally:
            with defer_termination():
                cleanup_failures = []
                for process in controller_processes:
                    try:
                        stop_process(process)
                    except BaseException as error:
                        cleanup_failures.append(f"controller stop: {error}")
                processes = [*controller_processes]
                processes.extend(switch.process for switch in network.switches)
                cleanup_failures.extend(stop_network(network))
                try:
                    wait_for_cleanup(processes, shells, interfaces, ports)
                except AssertionError as error:
                    details = "; ".join(cleanup_failures)
                    if details:
                        raise AssertionError(f"{error}; {details}") from error
                    raise
                require(not cleanup_failures, "; ".join(cleanup_failures))

        require(runtime_path.exists(), "runtime directory disappeared too early")

    require(not runtime_path.exists(), "runtime directory was not removed")
    print("controller integration: PASS")


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: test_controller.py CONTROLLER BMV2_JSON P4INFO")
    require(os.geteuid() == 0, "controller integration test must run as root")

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
