"""Raw sockets for captures and injection on the diamond's existing interfaces."""

from contextlib import ExitStack
import os
import select
import socket
import time

from scapy.all import Ether


def packet_socket(interface, host=None):
    original = os.open("/proc/self/ns/net", os.O_RDONLY)
    target = None
    sock = None
    try:
        if host is not None:
            target = os.open(f"/proc/{host.pid}/ns/net", os.O_RDONLY)
            os.setns(target, os.CLONE_NEWNET)
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        sock.bind((interface, 0))
        sock.setblocking(False)
        return sock
    except BaseException:
        if sock is not None:
            sock.close()
        raise
    finally:
        os.setns(original, os.CLONE_NEWNET)
        os.close(original)
        if target is not None:
            os.close(target)


class Capture:
    def __init__(self, interfaces):
        self.resources = ExitStack()
        self.sockets = {}
        try:
            for name, (interface, host) in interfaces.items():
                sock = self.resources.enter_context(packet_socket(interface, host))
                self.sockets[sock] = (name, host is None)
        except BaseException:
            self.resources.close()
            raise
        self.packets = {name: [] for name in interfaces}

    def collect(self, duration=0.15):
        # A bounded observation window also detects duplicates and unexpected output.
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            self._receive(max(0, deadline - time.monotonic()))
        return self.packets

    def _receive(self, timeout):
        ready, _, _ = select.select(list(self.sockets), [], [], timeout)
        for sock in ready:
            raw, address = sock.recvfrom(65535)
            name, outgoing = self.sockets[sock]
            if (address[2] == socket.PACKET_OUTGOING) == outgoing:
                self.packets[name].append(Ether(raw))

    def wait_for(self, token, location="destination", timeout=1):
        deadline = time.monotonic() + timeout
        while not any(token in bytes(packet) for packet in self.packets[location]):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f"packet not observed at {location}: {token!r}")
            self._receive(remaining)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.resources.close()
