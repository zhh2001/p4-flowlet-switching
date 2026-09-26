from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import socket
import sys
import time
import unittest

from scapy.all import Ether, ICMP, IP, Raw, TCP, UDP
from scapy.utils import checksum

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mininet"))
from diamond import Diamond, INTERFACES, PORTS, mac, checked
from mininet.log import setLogLevel
from packets import Capture, packet_socket
from state import Flow, Registers, TIMESTAMP_MASK, path_change_flow


def assert_clean(test, diamond):
    test.assertFalse(diamond.runtime.exists())
    for switch in diamond.switches:
        if switch.process is not None:
            test.assertIsNotNone(switch.process.poll())
    for pid in diamond.shell_pids:
        test.assertFalse(Path(f"/proc/{pid}").exists(), f"remaining shell {pid}")
    for interface in INTERFACES:
        test.assertFalse(Path("/sys/class/net", interface).exists(), interface)
    for port in PORTS:
        with socket.socket() as sock:
            test.assertNotEqual(sock.connect_ex(("127.0.0.1", port)), 0, port)


class CleanupTests(unittest.TestCase):
    def test_configuration_failure(self):
        setLogLevel("warning")
        diamond = Diamond(pipeline=ROOT / "build/absent.json")
        with redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, "controller:.*absent.json"):
                diamond.start()
        assert_clean(self, diamond)


class ForwardingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0:
            raise RuntimeError("run integration tests through make test")
        setLogLevel("warning")
        cls.diamond = Diamond()
        cls.addClassCleanup(cls.diamond.close)
        cls.diamond.start()

    @classmethod
    def tearDownClass(cls):
        cls.diamond.close()
        assert_clean(cls(), cls.diamond)

    def assert_packet(self, original, actual, hops, source_mac, destination_mac):
        expected = original.copy()
        expected.src, expected.dst = source_mac, destination_mac
        expected[IP].ttl -= hops
        del expected[IP].chksum
        expected = Ether(bytes(expected))
        self.assertEqual(bytes(actual)[:14 + actual[IP].len], bytes(expected))
        self.assertEqual(checksum(bytes(actual[IP])[:20]), 0)
        self.assertEqual(bytes(actual[IP].payload), bytes(original[IP].payload))
        if TCP in actual or (UDP in actual and actual[UDP].chksum != 0):
            transport = TCP if TCP in actual else UDP
            rebuilt = actual[IP].copy()
            del rebuilt[transport].chksum
            self.assertEqual(IP(bytes(rebuilt))[transport].chksum, actual[transport].chksum)

    def exchange(self, transport, reverse=False, lower=False):
        net = self.diamond.net
        source, destination = ("h2", "h1") if reverse else ("h1", "h2")
        edge, far = ("s4", "s1") if reverse else ("s1", "s4")
        source_ip, destination_ip = (("10.0.4.1", "10.0.1.1") if reverse
                                     else ("10.0.1.1", "10.0.4.1"))
        token = f"forwarding:{self.id()}:{reverse}:{lower}:{bytes(transport).hex()}".encode()
        original = Ether(src=mac(source, 0), dst=mac(edge, 1)) / IP(
            src=source_ip, dst=destination_ip, ttl=64, id=73) / transport / Raw(token)
        original = Ether(bytes(original))
        if TCP in original or UDP in original:
            lower = bool(Flow(source_ip, destination_ip, original[IP].proto,
                              transport.sport, transport.dport).path(0))
        branch_port = 1 if reverse else 2
        interfaces = {
            "upper": (f"{edge}-eth2", None),
            "lower": (f"{edge}-eth3", None),
            "upper_exit": (f"s2-eth{branch_port}", None),
            "lower_exit": (f"s3-eth{branch_port}", None),
            "destination": (f"{destination}-eth0", net[destination]),
        }
        with Capture(interfaces) as capture, packet_socket(f"{source}-eth0", net[source]) as sender:
            sender.send(bytes(original))
            captured = capture.collect()
        self.assert_path(original, token, captured, reverse, lower)

    def assert_path(self, original, token, captured, reverse=False, lower=False):
        destination = "h1" if reverse else "h2"
        edge, far = ("s4", "s1") if reverse else ("s1", "s4")
        branch_port = 1 if reverse else 2
        matching = {name: [p for p in packets if token in bytes(p)]
                    for name, packets in captured.items()}
        chosen = "lower" if lower else "upper"
        other = "upper" if lower else "lower"
        for name in (chosen, f"{chosen}_exit", "destination"):
            self.assertEqual(len(matching[name]), 1, name)
        for name in (other, f"{other}_exit"):
            self.assertEqual(len(matching[name]), 0, name)
        middle = "s3" if lower else "s2"
        edge_port = 3 if lower else 2
        middle_in = 2 if reverse else 1
        self.assert_packet(original, matching[chosen][0], 1,
                           mac(edge, edge_port), mac(middle, middle_in))
        self.assert_packet(original, matching[f"{chosen}_exit"][0], 2,
                           mac(middle, branch_port), mac(far, edge_port))
        self.assert_packet(original, matching["destination"][0], 3,
                           mac(far, 1), mac(destination, 0))

    def test_02_udp_forwarding(self):
        self.exchange(UDP(sport=21001, dport=31001))
        self.exchange(UDP(sport=21002, dport=31002, chksum=0))

    def test_01_tcp_forwarding(self):
        self.exchange(TCP(sport=22001, dport=32001, flags="RA", seq=1001, ack=2001))

    def test_00_icmp_forwarding(self):
        self.exchange(ICMP(type=8, id=41, seq=7))

    def test_reverse(self):
        self.exchange(UDP(sport=31001, dport=21001), reverse=True)

    def test_lower_path(self):
        try:
            self.diamond.configure(1, static_path=1)
            self.diamond.configure(4, static_path=1)
            self.exchange(ICMP(type=8, id=42, seq=1), lower=True)
            self.exchange(ICMP(type=8, id=43, seq=1), reverse=True, lower=True)
        finally:
            self.diamond.configure(1)
            self.diamond.configure(4)

    def test_ping(self):
        output = checked(self.diamond.net["h1"], "ping", "-n", "-c", "1", "-W", "2", "10.0.4.1")
        self.assertIn("1 received", output)

    def test_verify_only(self):
        for device in range(1, 5):
            self.assertIn("verified", self.diamond.configure(device, verify_only=True))
        self.diamond.timeout_us += 1
        try:
            with self.assertRaisesRegex(RuntimeError, "readback differs"):
                self.diamond.configure(1, verify_only=True)
        finally:
            self.diamond.timeout_us -= 1
        self.assertIn("verified", self.diamond.configure(1, verify_only=True))

    def flowlet_sequence(self, protocol):
        flow = path_change_flow(protocol)
        registers = Registers(1)
        registers.reset()
        Registers(4).reset()
        timeout = self.diamond.timeout_us / 1_000_000
        net = self.diamond.net
        interfaces = {
            "upper": ("s1-eth2", None), "lower": ("s1-eth3", None),
            "upper_exit": ("s2-eth2", None), "lower_exit": ("s3-eth2", None),
            "destination": ("h2-eth0", net["h2"]),
        }
        records = []

        def resident(flowlet_id):
            state = registers.read(flow.index())
            self.assertEqual(state["flow_valid"], 1)
            self.assertEqual(state["flow_fingerprint"], flow.fingerprint())
            self.assertEqual(state["flowlet_id"], flowlet_id)
            self.assertEqual(state["flow_path"], flow.path(flowlet_id))
            return state

        def wait_gap(last_send, gap):
            remaining = last_send + gap - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)

        with Capture(interfaces) as capture, packet_socket("h1-eth0", net["h1"]) as sender:
            def burst(count, flowlet_id, zero_checksum=False):
                for _ in range(count):
                    number = len(records)
                    token = f"flowlet:{protocol}:{number:04d}|".encode()
                    transport = (TCP(sport=flow.sport, dport=flow.dport, flags="RA",
                                     seq=1000 + number, ack=2000) if protocol == 6 else
                                 UDP(sport=flow.sport, dport=flow.dport,
                                     chksum=0 if zero_checksum else None))
                    frame = Ether(bytes(Ether(src=mac("h1", 0), dst=mac("s1", 1)) /
                                        IP(src=flow.src, dst=flow.dst, ttl=64, id=number) /
                                        transport / Raw(token)))
                    sender.send(bytes(frame))
                    last_send = time.monotonic()
                    records.append((frame, token, flow.path(flowlet_id)))
                    if _ + 1 < count:
                        time.sleep(0.002)
                capture.wait_for(token)
                return last_send

            last_send = burst(20, 0)
            first = resident(0)
            wait_gap(last_send, timeout / 2)
            self.assertLess(time.monotonic() - last_send, timeout * 0.8,
                            "short-gap scheduling budget exceeded")
            last_send = burst(5, 0, zero_checksum=True)
            continuation = resident(0)
            elapsed = (continuation["flow_last_seen"] - first["flow_last_seen"]) & TIMESTAMP_MASK
            self.assertGreater(elapsed, 0)
            self.assertLess(elapsed, self.diamond.timeout_us)

            wait_gap(last_send, timeout + 0.15)
            burst(1, 1)
            second = resident(1)
            self.assertNotEqual(second["flow_path"], first["flow_path"])
            self.assertGreater((second["flow_last_seen"] - continuation["flow_last_seen"]) &
                               TIMESTAMP_MASK, self.diamond.timeout_us)
            last_send = burst(19, 1)
            sticky = resident(1)
            self.assertEqual(sticky["flow_path"], second["flow_path"])
            self.assertGreater((sticky["flow_last_seen"] - second["flow_last_seen"]) & TIMESTAMP_MASK, 0)

            wait_gap(last_send, timeout + 0.15)
            burst(5, 2)
            third = resident(2)
            self.assertEqual(third["flow_path"], second["flow_path"])
            captured = capture.collect()

        for frame, token, path in records:
            self.assert_path(frame, token, captured, lower=bool(path))
        for location in ("upper", "lower", "destination"):
            wanted = [token for _, token, path in records if location == "destination" or
                      location == ("lower" if path else "upper")]
            observed = [token for packet in captured[location] for _, token, _ in records
                        if token in bytes(packet)]
            self.assertEqual(observed, wanted, f"packet order at {location}")

    def test_flowlet_udp(self):
        self.flowlet_sequence(17)

    def test_flowlet_tcp(self):
        self.flowlet_sequence(6)

    def test_ipv4_drops(self):
        net = self.diamond.net
        interfaces = {name: (interface, None) for name, interface in (
            ("upper", "s1-eth2"), ("lower", "s1-eth3"),
            ("upper_exit", "s2-eth2"), ("lower_exit", "s3-eth2"))}
        interfaces["destination"] = ("h2-eth0", net["h2"])
        cases = {
            "ttl-zero": {"ttl": 0},
            "ttl-one": {"ttl": 1},
            "route-miss": {"dst": "10.0.99.1"},
            "wrong-version": {"version": 6},
            "short-length": {"len": 19},
            "truncated": {"len": 1000},
            "options": {"options": b"\x01" * 4},
            "bad-checksum": {},
        }
        tokens = []
        with Capture(interfaces) as capture, packet_socket("h1-eth0", net["h1"]) as sender:
            for name, fields in cases.items():
                token = f"ipv4-drop:{name}".encode()
                tokens.append(token)
                ip = IP(src="10.0.1.1", dst="10.0.4.1", ttl=64)
                for key, value in fields.items():
                    setattr(ip, key, value)
                packet = Ether(src=mac("h1", 0), dst=mac("s1", 1)) / ip / UDP(
                    sport=24001, dport=34001) / Raw(token)
                packet = Ether(bytes(packet))
                if name == "bad-checksum":
                    packet[IP].chksum ^= 1
                sender.send(bytes(packet))
            observed = capture.collect()
        for name, packets in observed.items():
            for token in tokens:
                self.assertFalse(any(token in bytes(packet) for packet in packets), (name, token))
