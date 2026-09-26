"""BMv2 register inspection and deterministic tuple selection for packet tests."""

from dataclasses import dataclass
import re
import socket
import struct
import subprocess
import zlib


STATE_SIZE = 4096
TIMESTAMP_MASK = (1 << 48) - 1
FIELDS = ("flow_valid", "flow_fingerprint", "flow_last_seen", "flowlet_id", "flow_path")


@dataclass(frozen=True)
class Flow:
    src: str = "10.0.1.1"
    dst: str = "10.0.4.1"
    protocol: int = 17
    sport: int = 21001
    dport: int = 31001

    def key(self):
        return struct.pack("!4s4sBHH", socket.inet_aton(self.src), socket.inet_aton(self.dst),
                           self.protocol, self.sport, self.dport)

    def index(self):
        return zlib.crc32(self.key()) % STATE_SIZE

    def fingerprint(self):
        data = struct.pack("!4s4sHHBI", socket.inet_aton(self.dst), socket.inet_aton(self.src),
                           self.dport, self.sport, self.protocol, 0x9e3779b9)
        return zlib.crc32(data)

    def path(self, flowlet_id):
        key = self.key()
        return zlib.crc32(key[:8] + struct.pack("!I", flowlet_id) + key[8:]) % 2


def path_change_flow(protocol):
    for sport in range(20000, 20256):
        flow = Flow(protocol=protocol, sport=sport)
        if flow.path(0) == 0 and flow.path(1) == 1:
            return flow
    raise AssertionError("no path-change tuple in the 256-candidate search")


class Registers:
    def __init__(self, device):
        if device not in range(1, 5):
            raise ValueError("device must be 1..4")
        self.port = 9090 + device

    def _cli(self, commands):
        result = subprocess.run(["simple_switch_CLI", "--thrift-port", str(self.port)],
                                input="\n".join(commands) + "\n", text=True,
                                capture_output=True, timeout=5)
        if result.returncode or re.search(r"\b(error|invalid|unknown)\b",
                                         result.stdout + result.stderr, re.IGNORECASE):
            raise RuntimeError(f"register CLI failed: {result.stdout[-1000:]}{result.stderr[-1000:]}")
        return result.stdout

    def _read_commands(self, index):
        suffix = "" if index is None else f" {index}"
        return [f"register_read IngressPipe.{field}{suffix}" for field in FIELDS]

    def _parse(self, output, index):
        state = {}
        for field in FIELDS:
            suffix = "" if index is None else rf"\[{index}\]"
            matches = re.findall(rf"\bIngressPipe\.{field}{suffix}= *([0-9, ]+)", output)
            if len(matches) != 1:
                raise AssertionError(f"missing or ambiguous register result: {field}")
            values = [int(value.strip()) for value in matches[0].split(",")]
            expected = STATE_SIZE if index is None else 1
            if len(values) != expected:
                raise AssertionError(f"{field}: expected {expected} cells, got {len(values)}")
            state[field] = values if index is None else values[0]
        return state

    def read(self, index=None):
        if index is not None and not 0 <= index < STATE_SIZE:
            raise ValueError("register index out of range")
        return self._parse(self._cli(self._read_commands(index)), index)

    def reset(self):
        commands = [f"register_reset IngressPipe.{field}" for field in FIELDS]
        state = self._parse(self._cli(commands + self._read_commands(None)), None)
        if any(any(values) for values in state.values()):
            raise AssertionError("register reset did not clear all five arrays")
