from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import socket
import sys
import time
import unittest

from scapy.all import Ether, ICMP, IP, Raw, TCP, UDP, fragment
from scapy.utils import checksum

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mininet"))
from diamond import Diamond, INTERFACES, PORTS, mac, checked
from mininet.log import setLogLevel
from packets import Capture, packet_socket
from state import Flow, Registers, TIMESTAMP_MASK, collision_flows, path_change_flow


def wait_gap(last_send, gap):
    remaining = last_send + gap - time.monotonic()
    if remaining > 0:
        time.sleep(remaining)


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
        complete = actual[IP].frag == 0 and not actual[IP].flags.MF
        if complete and ICMP in actual:
            self.assertEqual(checksum(bytes(actual[IP].payload)), 0)
        if complete and (TCP in actual or (UDP in actual and actual[UDP].chksum != 0)):
            transport = TCP if TCP in actual else UDP
            rebuilt = actual[IP].copy()
            del rebuilt[transport].chksum
            self.assertEqual(IP(bytes(rebuilt))[transport].chksum, actual[transport].chksum)

    def exchange(self, transport, reverse=False, lower=False, payload=b""):
        net = self.diamond.net
        source = "h2" if reverse else "h1"
        edge = "s4" if reverse else "s1"
        source_ip, destination_ip = (("10.0.4.1", "10.0.1.1") if reverse
                                     else ("10.0.1.1", "10.0.4.1"))
        token = f"forwarding:{self.id()}:{reverse}:{lower}:{bytes(transport).hex()}".encode()
        original = Ether(src=mac(source, 0), dst=mac(edge, 1)) / IP(
            src=source_ip, dst=destination_ip, ttl=64, id=73) / transport / Raw(token + payload)
        original = Ether(bytes(original))
        if TCP in original or UDP in original:
            lower = bool(Flow(source_ip, destination_ip, original[IP].proto,
                              transport.sport, transport.dport).path(0))
        with Capture(self.interfaces(reverse)) as capture, packet_socket(f"{source}-eth0", net[source]) as sender:
            sender.send(bytes(original))
            captured = capture.collect()
        self.assert_path(original, token, captured, reverse, lower)

    def interfaces(self, reverse=False):
        edge, destination = ("s4", "h1") if reverse else ("s1", "h2")
        branch_port = 1 if reverse else 2
        return {
            "upper": (f"{edge}-eth2", None),
            "lower": (f"{edge}-eth3", None),
            "upper_exit": (f"s2-eth{branch_port}", None),
            "lower_exit": (f"s3-eth{branch_port}", None),
            "destination": (f"{destination}-eth0", self.diamond.net[destination]),
        }

    def send_flow(self, sender, capture, records, flow, flowlet_id, zero_checksum=False):
        number = len(records)
        token = f"{self.id()}:{flow.key().hex()}:{number:04d}|".encode()
        source, edge = ("h2", "s4") if flow.src == "10.0.4.1" else ("h1", "s1")
        transport = (TCP(sport=flow.sport, dport=flow.dport, flags="RA",
                         seq=1000 + number, ack=2000) if flow.protocol == 6 else
                     UDP(sport=flow.sport, dport=flow.dport,
                         chksum=0 if zero_checksum else None))
        frame = Ether(bytes(Ether(src=mac(source, 0), dst=mac(edge, 1)) /
                            IP(src=flow.src, dst=flow.dst, ttl=64, id=number) /
                            transport / Raw(token)))
        sender.send(bytes(frame))
        last_send = time.monotonic()
        records.append((frame, token, flow.path(flowlet_id)))
        capture.wait_for(token)
        return last_send

    def assert_resident(self, registers, flow, flowlet_id):
        state = registers.read(flow.index())
        self.assertEqual(state["flow_valid"], 1)
        self.assertEqual(state["flow_fingerprint"], flow.fingerprint())
        self.assertEqual(state["flowlet_id"], flowlet_id)
        self.assertEqual(state["flow_path"], flow.path(flowlet_id))
        return state

    def state_snapshot(self):
        return {device: Registers(device).read() for device in range(1, 5)}

    def seed_state(self, reverse):
        source = "h2" if reverse else "h1"
        records = []
        with Capture(self.interfaces(reverse)) as capture, packet_socket(
                f"{source}-eth0", self.diamond.net[source]) as sender:
            for protocol in (6, 17):
                flow = Flow(protocol=protocol, sport=24001, dport=34001)
                if reverse:
                    flow = flow.reverse()
                self.send_flow(sender, capture, records, flow, 0)
                self.assert_resident(Registers(4 if reverse else 1), flow, 0)
            self.assert_records(records, capture.collect(), reverse)

    def assert_records(self, records, captured, reverse=False):
        for frame, token, path in records:
            self.assert_path(frame, token, captured, reverse, lower=bool(path))
        for location in ("upper", "lower", "destination"):
            wanted = [token for _, token, path in records if location == "destination" or
                      location == ("lower" if path else "upper")]
            observed = [token for packet in captured[location] for _, token, _ in records
                        if token in bytes(packet)]
            self.assertEqual(observed, wanted, f"packet order at {location}")

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

    def flowlet_sequence(self, protocol, reverse=False):
        flow = path_change_flow(protocol, reverse)
        registers = Registers(4 if reverse else 1)
        other = Registers(1 if reverse else 4)
        registers.reset()
        other.reset()
        timeout = self.diamond.timeout_us / 1_000_000
        net = self.diamond.net
        if reverse:
            forward = flow.reverse()
            self.assertNotEqual(forward.key(), flow.key())
            records = []
            with Capture(self.interfaces()) as capture, packet_socket("h1-eth0", net["h1"]) as sender:
                last_send = self.send_flow(sender, capture, records, forward, 0)
                self.assert_resident(other, forward, 0)
                wait_gap(last_send, timeout + 0.15)
                self.send_flow(sender, capture, records, forward, 1)
                self.assert_resident(other, forward, 1)
                self.assert_records(records, capture.collect())
            self.assertFalse(any(any(values) for values in registers.read().values()))
        other_state = other.read()
        records = []
        source = "h2" if reverse else "h1"

        with Capture(self.interfaces(reverse)) as capture, packet_socket(f"{source}-eth0", net[source]) as sender:
            def burst(count, flowlet_id, zero_checksum=False):
                for _ in range(count):
                    last_send = self.send_flow(sender, capture, records, flow, flowlet_id, zero_checksum)
                    if _ + 1 < count:
                        time.sleep(0.002)
                return last_send

            last_send = burst(20, 0)
            first = self.assert_resident(registers, flow, 0)
            wait_gap(last_send, timeout / 2)
            self.assertLess(time.monotonic() - last_send, timeout * 0.8,
                            "short-gap scheduling budget exceeded")
            last_send = burst(5, 0, zero_checksum=True)
            continuation = self.assert_resident(registers, flow, 0)
            elapsed = (continuation["flow_last_seen"] - first["flow_last_seen"]) & TIMESTAMP_MASK
            self.assertGreater(elapsed, 0)
            self.assertLess(elapsed, self.diamond.timeout_us)

            wait_gap(last_send, timeout + 0.15)
            burst(1, 1)
            second = self.assert_resident(registers, flow, 1)
            self.assertNotEqual(second["flow_path"], first["flow_path"])
            self.assertGreater((second["flow_last_seen"] - continuation["flow_last_seen"]) &
                               TIMESTAMP_MASK, self.diamond.timeout_us)
            last_send = burst(19, 1)
            sticky = self.assert_resident(registers, flow, 1)
            self.assertEqual(sticky["flow_path"], second["flow_path"])
            self.assertGreater((sticky["flow_last_seen"] - second["flow_last_seen"]) & TIMESTAMP_MASK, 0)

            wait_gap(last_send, timeout + 0.15)
            burst(5, 2)
            third = self.assert_resident(registers, flow, 2)
            self.assertEqual(third["flow_path"], second["flow_path"])
            captured = capture.collect()

        self.assert_records(records, captured, reverse)
        self.assertEqual(other.read(), other_state, "traffic changed the opposite edge's state")
        for device in (2, 3):
            self.assertFalse(any(any(values) for values in Registers(device).read().values()),
                             f"transit switch s{device} recorded flowlet state")

    def test_flowlet_udp(self):
        self.flowlet_sequence(17)

    def test_flowlet_tcp(self):
        self.flowlet_sequence(6)

    def test_flowlet_reverse(self):
        self.flowlet_sequence(17, reverse=True)

    def test_flow_independence(self):
        a = path_change_flow(17)
        b = Flow(a.src, a.dst, 6, a.sport, a.dport)
        self.assertNotEqual(a.index(), b.index())
        registers = Registers(1)
        registers.reset()
        timeout = self.diamond.timeout_us / 1_000_000
        records = []
        with Capture(self.interfaces()) as capture, packet_socket("h1-eth0", self.diamond.net["h1"]) as sender:
            last_a = self.send_flow(sender, capture, records, a, 0)
            first_a = self.assert_resident(registers, a, 0)
            last_b = self.send_flow(sender, capture, records, b, 0)
            first_b = self.assert_resident(registers, b, 0)

            # Keep B active while A's inter-packet gap exceeds the timeout.
            for gap in (timeout * 0.4, timeout * 0.8, timeout + 0.15):
                wait_gap(last_a, gap)
                self.assertLess(time.monotonic() - last_b, timeout * 0.8,
                                "keepalive scheduling budget exceeded")
                last_b = self.send_flow(sender, capture, records, b, 0)
            active_b = self.assert_resident(registers, b, 0)
            self.assertGreater((active_b["flow_last_seen"] - first_b["flow_last_seen"]) &
                               TIMESTAMP_MASK, 0)

            self.send_flow(sender, capture, records, a, 1)
            second_a = self.assert_resident(registers, a, 1)
            self.assertGreater((second_a["flow_last_seen"] - first_a["flow_last_seen"]) &
                               TIMESTAMP_MASK, self.diamond.timeout_us)
            self.assertEqual(registers.read(b.index()), active_b)
            self.assertLess(time.monotonic() - last_b, timeout * 0.8,
                            "final continuation scheduling budget exceeded")
            self.send_flow(sender, capture, records, b, 0)
            final_b = self.assert_resident(registers, b, 0)
            elapsed = (final_b["flow_last_seen"] - active_b["flow_last_seen"]) & TIMESTAMP_MASK
            self.assertGreater(elapsed, 0)
            self.assertLess(elapsed, self.diamond.timeout_us)
            self.assertEqual(registers.read(a.index()), second_a)
            captured = capture.collect()
        self.assert_records(records, captured)
        valid = registers.read()["flow_valid"]
        self.assertEqual([index for index, value in enumerate(valid) if value],
                         sorted((a.index(), b.index())))

    def test_collision_eviction(self):
        a, b = collision_flows()
        self.assertEqual(a.index(), b.index())
        self.assertNotEqual(a.fingerprint(), b.fingerprint())
        registers = Registers(1)
        registers.reset()
        timeout = self.diamond.timeout_us / 1_000_000
        records = []
        with Capture(self.interfaces()) as capture, packet_socket("h1-eth0", self.diamond.net["h1"]) as sender:
            last_send = self.send_flow(sender, capture, records, a, 0)
            self.assert_resident(registers, a, 0)
            wait_gap(last_send, timeout + 0.15)
            last_send = self.send_flow(sender, capture, records, a, 1)
            resident_a = self.assert_resident(registers, a, 1)

            self.assertLess(time.monotonic() - last_send, timeout * 0.8)
            last_send = self.send_flow(sender, capture, records, b, 0)
            fresh_b = self.assert_resident(registers, b, 0)
            self.assertNotEqual(fresh_b["flow_path"], resident_a["flow_path"])
            elapsed = (fresh_b["flow_last_seen"] - resident_a["flow_last_seen"]) & TIMESTAMP_MASK
            self.assertGreater(elapsed, 0)
            self.assertLess(elapsed, self.diamond.timeout_us)

            wait_gap(last_send, timeout + 0.15)
            last_send = self.send_flow(sender, capture, records, b, 1)
            resident_b = self.assert_resident(registers, b, 1)
            self.assertLess(time.monotonic() - last_send, timeout * 0.8)
            self.send_flow(sender, capture, records, a, 0)
            fresh_a = self.assert_resident(registers, a, 0)
            self.assertNotEqual(fresh_a["flow_path"], resident_b["flow_path"])
            elapsed = (fresh_a["flow_last_seen"] - resident_b["flow_last_seen"]) & TIMESTAMP_MASK
            self.assertGreater(elapsed, 0)
            self.assertLess(elapsed, self.diamond.timeout_us)
            self.send_flow(sender, capture, records, a, 0)
            final_a = self.assert_resident(registers, a, 0)
            captured = capture.collect()
        self.assert_records(records, captured)
        for field, values in registers.read().items():
            self.assertEqual(values[a.index()], final_a[field])
            self.assertFalse(any(value for index, value in enumerate(values) if index != a.index()),
                             f"collision changed another slot in {field}")

    def test_bypass_state(self):
        for reverse in (False, True):
            flow = Flow().reverse() if reverse else Flow()
            source, edge = ("h2", "s4") if reverse else ("h1", "s1")
            for device in range(1, 5):
                Registers(device).reset()
            for populated in (False, True):
                with self.subTest(reverse=reverse, populated=populated):
                    if populated:
                        self.seed_state(reverse)
                    before = self.state_snapshot()
                    frames = []
                    with Capture(self.interfaces(reverse)) as capture, packet_socket(
                            f"{source}-eth0", self.diamond.net[source]) as sender:
                        for protocol in (1, 253):
                            token = f"bypass:{reverse}:{populated}:{protocol}|".encode()
                            ip = IP(src=flow.src, dst=flow.dst, ttl=64, proto=protocol)
                            if protocol == 1:
                                ip /= ICMP(type=8, id=91, seq=int(populated))
                            frame = Ether(bytes(Ether(src=mac(source, 0), dst=mac(edge, 1)) /
                                                ip / Raw(token)))
                            frames.append((frame, token))
                            sender.send(bytes(frame))
                            capture.wait_for(token)
                        observed = capture.collect()
                    for frame, token in frames:
                        self.assert_path(frame, token, observed, reverse)
                    self.assertEqual(self.state_snapshot(), before, "bypass changed flowlet state")

    def test_fragment_bypass(self):
        for reverse in (False, True):
            flow = Flow(sport=24001, dport=34001)
            if reverse:
                flow = flow.reverse()
            source, edge, destination, far = (("h2", "s4", "h1", "s1") if reverse else
                                               ("h1", "s1", "h2", "s4"))
            for device in range(1, 5):
                Registers(device).reset()
            for populated in (False, True):
                with self.subTest(reverse=reverse, populated=populated):
                    if populated:
                        self.seed_state(reverse)
                    before = self.state_snapshot()
                    datagrams = []
                    with Capture(self.interfaces(reverse)) as capture, packet_socket(
                            f"{source}-eth0", self.diamond.net[source]) as sender:
                        for protocol in (6, 17):
                            tokens = [f"fragment:{reverse}:{populated}:{protocol}:{part}|".encode()
                                      for part in (0, 1)]
                            transport = (TCP(sport=flow.sport, dport=flow.dport, flags="RA",
                                             seq=1001, ack=2001) if protocol == 6 else
                                         UDP(sport=flow.sport, dport=flow.dport))
                            padding = b"." * (64 - len(bytes(transport)) - len(tokens[0]))
                            datagram = Ether(bytes(Ether(src=mac(source, 0), dst=mac(edge, 1)) /
                                                   IP(src=flow.src, dst=flow.dst, ttl=64,
                                                      id=100 + protocol + 256 * populated) /
                                                   transport / Raw(tokens[0] + padding + tokens[1])))
                            fragments = [Ether(bytes(packet)) for packet in fragment(datagram, fragsize=64)]
                            self.assertEqual(len(fragments), 2)
                            self.assertTrue(fragments[0][IP].flags.MF)
                            self.assertEqual(fragments[0][IP].frag, 0)
                            self.assertEqual(fragments[1][IP].frag, 8)
                            for frame, token in zip(fragments, tokens):
                                self.assertIn(token, bytes(frame))
                                sender.send(bytes(frame))
                                capture.wait_for(token)
                            datagrams.append((datagram, fragments, tokens))
                        observed = capture.collect()
                    for datagram, fragments, tokens in datagrams:
                        received = []
                        for frame, token in zip(fragments, tokens):
                            self.assert_path(frame, token, observed, reverse)
                            received.append(next(p for p in observed["destination"] if token in bytes(p)))
                        reassembled = received[0].copy()
                        reassembled[IP].remove_payload()
                        reassembled[IP].flags = 0
                        reassembled[IP].frag = 0
                        del reassembled[IP].len
                        del reassembled[IP].chksum
                        reassembled /= Raw(b"".join(bytes(p[IP].payload) for p in received))
                        self.assert_packet(datagram, Ether(bytes(reassembled)), 3,
                                           mac(far, 1), mac(destination, 0))
                    self.assertEqual(self.state_snapshot(), before, "fragments changed flowlet state")

    def test_transport_integrity(self):
        payload = bytes(range(256)) * 4
        for reverse in (False, True):
            self.exchange(TCP(sport=25001, dport=35001, flags="RA", seq=0xfedcba98,
                              ack=0x87654321, window=4096,
                              options=[("MSS", 1400), ("Timestamp", (1000, 900))]),
                          reverse=reverse, payload=payload)
            self.exchange(UDP(sport=25002, dport=35002), reverse=reverse, payload=payload)

    def test_ipv4_drops(self):
        for reverse in (False, True):
            flow = Flow(sport=24001, dport=34001)
            if reverse:
                flow = flow.reverse()
            source, edge = ("h2", "s4") if reverse else ("h1", "s1")
            for device in range(1, 5):
                Registers(device).reset()
            for populated in (False, True):
                if populated:
                    self.seed_state(reverse)
                before = self.state_snapshot()
                udp = UDP(sport=flow.sport, dport=flow.dport)
                tcp = TCP(sport=flow.sport, dport=flow.dport, flags="RA")
                cases = [
                    ("ttl-zero", {"ttl": 0}, udp),
                    ("ttl-one", {"ttl": 1}, tcp),
                    ("route-miss-udp", {"dst": "10.0.99.1"}, udp),
                    ("route-miss-tcp", {"dst": "10.0.99.1"}, tcp),
                    ("wrong-version", {"version": 6}, udp),
                    ("short-ip-length", {"len": 19}, udp),
                    ("truncated-ip", {"len": 1000}, udp),
                    ("options", {"options": b"\x00" * 4}, udp),
                    ("short-ihl", {"ihl": 4}, udp),
                    ("bad-checksum-udp", {}, udp),
                    ("bad-checksum-tcp", {}, tcp),
                    ("short-tcp-header", {"proto": 6}, None),
                    ("short-udp-header", {"proto": 17}, None),
                    ("tcp-small-offset", {}, TCP(sport=flow.sport, dport=flow.dport,
                                                flags="RA", dataofs=4)),
                    ("tcp-large-offset", {}, TCP(sport=flow.sport, dport=flow.dport,
                                                flags="RA", dataofs=15)),
                    ("tcp-short-ip-payload", {"len": 39}, tcp),
                    ("udp-small-length", {}, UDP(sport=flow.sport, dport=flow.dport, len=7)),
                    ("udp-short-length", {}, UDP(sport=flow.sport, dport=flow.dport, len=8)),
                    ("udp-long-length", {}, UDP(sport=flow.sport, dport=flow.dport, len=400)),
                    ("udp-short-ip-payload", {"len": 27}, udp),
                ]
                tokens = []
                with Capture(self.interfaces(reverse)) as capture, packet_socket(
                        f"{source}-eth0", self.diamond.net[source]) as sender:
                    for index, (name, fields, transport) in enumerate(cases):
                        token = f"D{int(reverse)}{int(populated)}{index:02d}END".encode()
                        if name == "short-udp-header":
                            token = token[:6]
                        tokens.append((name, token))
                        ip = IP(src=flow.src, dst=flow.dst, ttl=64)
                        for key, value in fields.items():
                            setattr(ip, key, value)
                        frame = Ether(src=mac(source, 0), dst=mac(edge, 1)) / ip
                        if transport is not None:
                            frame /= transport
                        frame = Ether(bytes(frame / Raw(token)))
                        self.assertEqual(checksum(bytes(frame)[14:34]), 0, name)
                        if name.startswith("bad-checksum"):
                            frame[IP].chksum ^= 1
                            self.assertNotEqual(checksum(bytes(frame)[14:34]), 0, name)
                        sender.send(bytes(frame))
                    observed = capture.collect()
                for name, token in tokens:
                    with self.subTest(reverse=reverse, populated=populated, packet=name):
                        for location, packets in observed.items():
                            self.assertFalse(any(token in bytes(packet) for packet in packets), location)
                self.assertEqual(self.state_snapshot(), before, "dropped packets changed flowlet state")
