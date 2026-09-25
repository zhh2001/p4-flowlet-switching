#!/usr/bin/env python3
"""Four BMv2 routers with deterministic links and P4Runtime configuration."""

import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Switch


ROOT = Path(__file__).resolve().parents[1]
LINKS = (
    ("h1", 0, "s1", 1),
    ("s1", 2, "s2", 1),
    ("s1", 3, "s3", 1),
    ("s2", 2, "s4", 2),
    ("s3", 2, "s4", 3),
    ("s4", 1, "h2", 0),
)
INTERFACES = tuple(f"{node}-eth{port}" for link in LINKS
                   for node, port in (link[:2], link[2:]))
PORTS = tuple(port for device in range(1, 5)
              for port in (50050 + device, 9090 + device))


def mac(node, port):
    if node == "h1":
        return "00:00:00:00:01:01"
    if node == "h2":
        return "00:00:00:00:04:01"
    return f"02:00:00:00:{int(node[1:]):02x}:{port:02x}"


def checked(node, *command):
    process = node.popen(list(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise
    if process.returncode:
        raise RuntimeError(f"{node}: {' '.join(command)}: {stderr.decode().strip()}")
    return stdout.decode()


class BMv2Switch(Switch):
    def __init__(self, name, runtime, **params):
        super().__init__(name, **params)
        self.runtime = Path(runtime)
        self.device = int(name[1:])
        self.process = None
        self.log = None

    def start(self, controllers):
        command = ["simple_switch_grpc", "--no-p4", "--device-id", str(self.device),
                   "--thrift-port", str(9090 + self.device), "--log-level", "warn"]
        for port, intf in sorted(self.intfs.items()):
            if port:
                command.extend(["-i", f"{port}@{intf.name}"])
        command.extend(["--", "--grpc-server-addr", f"127.0.0.1:{50050 + self.device}"])
        self.log = (self.runtime / f"{self.name}.log").open("w")
        self.process = subprocess.Popen(command, cwd=self.runtime, stdout=self.log,
                                        stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 10
        for port in (50050 + self.device, 9090 + self.device):
            while True:
                if self.process.poll() is not None:
                    raise RuntimeError(f"{self.name} exited during startup")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"{self.name}: port {port} did not become ready")
                    time.sleep(0.01)

    def stop(self, deleteIntfs=True):
        if self.process is not None and self.process.poll() is None:
            # An unreaped Popen child cannot have its PID reused by another process.
            if Path(f"/proc/{self.process.pid}/cwd").resolve() != self.runtime:
                raise RuntimeError(f"{self.name}: process ownership check failed")
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        if self.log is not None:
            self.log.close()
        super().stop(deleteIntfs)


class Diamond:
    def __init__(self, pipeline=None):
        self.pipeline = Path(pipeline) if pipeline else ROOT / "build/flowlet.json"
        self.net = None
        self.directory = None
        self.runtime = None
        self.switches = []
        self.shell_pids = []

    def start(self):
        if os.geteuid() != 0:
            raise PermissionError("Mininet requires root")
        for interface in INTERFACES:
            if Path("/sys/class/net", interface).exists():
                raise RuntimeError(f"interface already exists: {interface}")
        for port in PORTS:
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", port))
        self.directory = tempfile.TemporaryDirectory(prefix="flowlet-")
        self.runtime = Path(self.directory.name)
        try:
            # This topology needs no global sysctl changes from Mininet.fixLimits().
            Mininet.inited = True
            self.net = Mininet(controller=None, switch=BMv2Switch, build=False)
            self.net.addHost("h1", ip="10.0.1.1/24", mac=mac("h1", 0))
            self.net.addHost("h2", ip="10.0.4.1/24", mac=mac("h2", 0))
            for device in range(1, 5):
                self.switches.append(self.net.addSwitch(f"s{device}", runtime=self.runtime))
            for first, p1, second, p2 in LINKS:
                self.net.addLink(first, second, port1=p1, port2=p2,
                                 addr1=mac(first, p1), addr2=mac(second, p2))
            self.shell_pids = [node.pid for node in self.net.hosts + self.net.switches]
            self.net.build()
            for node in self.net.hosts + self.net.switches:
                for intf in node.intfList():
                    if intf.name != "lo":
                        checked(node, "ethtool", "-K", intf.name, "rx", "off", "tx", "off",
                                "tso", "off", "gso", "off", "gro", "off")
            for host, remote, gateway, switch in (
                    ("h1", "10.0.4.1", "10.0.1.254", "s1"),
                    ("h2", "10.0.1.1", "10.0.4.254", "s4")):
                node = self.net[host]
                checked(node, "ip", "route", "replace", f"{remote}/32", "via", gateway)
                checked(node, "ip", "neigh", "replace", gateway, "lladdr", mac(switch, 1),
                        "nud", "permanent", "dev", f"{host}-eth0")
            self.net.start()
            for device in range(1, 5):
                self.configure(device)
            return self
        except BaseException:
            for log in self.runtime.glob("*.log"):
                content = log.read_text().strip()
                if content:
                    print(f"{log.name}:\n{content}")
            self.close()
            raise

    def configure(self, device, verify_only=False, static_path=0):
        command = [str(ROOT / "build/controller"), "--device", str(device),
                   "--p4info", str(ROOT / "build/flowlet.p4info.txtpb"),
                   "--pipeline", str(self.pipeline), "--static-path", str(static_path)]
        if verify_only:
            command.append("--verify-only")
        result = subprocess.run(command, cwd=self.runtime, capture_output=True, text=True,
                                timeout=20)
        if result.returncode:
            raise RuntimeError(f"controller: {result.stderr.strip()}")
        return result.stdout.strip()

    def close(self):
        try:
            if self.net is not None:
                self.net.stop()
                self.net = None
        finally:
            if self.directory is not None:
                self.directory.cleanup()
                self.directory = None

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc, traceback):
        self.close()


def main():
    def interrupted(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    setLogLevel("info")
    try:
        with Diamond() as diamond:
            # Keep interactive use from writing Mininet history outside this run.
            CLI.readlineInited = True
            CLI(diamond.net)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
