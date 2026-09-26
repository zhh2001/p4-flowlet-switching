# p4-flowlet-switching

Timestamp-based two-path flowlet switching in P4_16/v1model on BMv2. The data plane detects flowlets and keeps their packets on one path. The Go controller uses `zhh2001/p4runtime-go-controller` v1.1.1 for configuration and readback.

```text
             s2
           /    \
          /      \
h1 --- s1          s4 --- h2
          \      /
           \    /
             s3
```

| Link  | Ports      |
| ----- | ---------- |
| h1–s1 | h1:0, s1:1 |
| s1–s2 | s1:2, s2:1 |
| s1–s3 | s1:3, s3:1 |
| s2–s4 | s2:2, s4:2 |
| s3–s4 | s3:2, s4:3 |
| s4–h2 | s4:1, h2:0 |

h1 uses `10.0.1.1/24`, MAC `00:00:00:00:01:01`; h2 uses `10.0.4.1/24`, MAC `00:00:00:00:04:01`. Switch port MACs are `02:00:00:00:<switch>:<port>`, with hexadecimal octets. Switches s1–s4 use device IDs 1–4, P4Runtime ports 50051–50054, and Thrift ports 9091–9094. Permanent host neighbors and static host routes avoid ARP. Interface offloads are disabled on the topology's links.

## Flowlet state

A flow is the unidirectional IPv4 5-tuple `(src, dst, protocol, sport, dport)`. TCP and UDP are supported. Reverse traffic has a different key: s1 selects the forward branch, and s4 independently selects the reverse branch. s2 and s3 use static IPv4 routes and never update flowlet state.

```text
p4-ecmp:
    one flow hashes to one path

p4-flowlet-switching:
    one flow may contain multiple flowlets
    packets within a flowlet remain on one path
    a sufficiently long gap starts a new flowlet
    a new flowlet may choose another path
```

Each switch's pipeline contains five arrays of 4096 register cells: `flow_valid` (1 bit), `flow_fingerprint` (32), `flow_last_seen` (48), `flowlet_id` (32), and `flow_path` (1). Static routes bypass these arrays. The slot is `CRC32(src, dst, protocol, sport, dport) % 4096`. The fingerprint uses a different field arrangement and salt: `CRC32(dst, src, dport, sport, protocol, 0x9e3779b9)`. Hash inputs use network byte order and the declared P4 field widths.

The state table is bounded and direct-mapped. Collisions evict previous flowlet state. A fingerprint mismatch replaces the slot with fresh state, starting at flowlet ID 0; it never inherits the previous resident's timestamp, ID, or selected path. A finite fingerprint can also alias, so this is not an exact unbounded flow table.

```text
packet
  |
  v
hash 5-tuple -> state slot
  |
  +-- invalid --------------> new flow
  |
  +-- fingerprint mismatch -> collision eviction
  |
  +-- fingerprint match
          |
          +-- gap <= timeout -> same flowlet / same path
          |
          +-- gap > timeout  -> new flowlet / reselect path
```

`standard_metadata.ingress_global_timestamp` is a 48-bit microsecond timestamp relative to BMv2 process startup. Gap subtraction uses 48-bit unsigned modular arithmetic. Timestamps are compared only within the selecting switch; a gap spanning an entire timestamp wrap cannot be distinguished from a shorter gap.

The keyless `flowlet_config` table supplies the timeout through its `set_timeout_us` default action. The default controller value is **500000 us**. For a matching resident, **gap > timeout** increments the flowlet ID and reselects the path; **gap <= timeout** retains both the ID and stored path. Every measured packet updates `flow_last_seen`. IDs wrap modulo 2^32.

On initialization or a new flowlet, selection is `CRC32(src, dst, flowlet_id, protocol, sport, dport) % 2`: 0 selects s2 (upper), and 1 selects s3 (lower). Packets within the flowlet reuse the stored selection. A new flowlet is not guaranteed to change path. The complete read/decision/write transition runs inside one P4 action. BMv2 locks all register arrays accessed by that action. The `@atomic` block documents the transition; BMv2 does not provide broader multi-action transaction guarantees.

## Forwarding

IPv4 validation and route lookup precede flowlet measurement. Each routed hop rewrites Ethernet addresses, decrements TTL once, and updates the IPv4 checksum. Host-to-host packets traverse three routed hops. IP endpoints, transport headers, transport checksums, and payloads are preserved, including zero UDP checksums.

ICMP, other non-TCP/UDP traffic, and all IPv4 fragments bypass flowlet state. This includes first fragments with MF set. They use the configured static branch (upper by default, or `--static-path 1` for lower). Transport ports are not extracted from fragments.

Non-IPv4 packets, bad IPv4 checksums, options (`IHL != 5`), invalid version, TTL 0/1, total lengths below 20 bytes, truncated packets, and route misses are dropped before state access. Unfragmented TCP requires at least a 20-byte header and a valid data offset within the IPv4 length. Unfragmented UDP requires length >= 8 and a length matching the IPv4 payload. TCP options remain opaque and are preserved. Switches do not generate ICMP errors or validate incoming transport checksums.

## Build and run

Prerequisites: Linux, P4 compiler with v1model, BMv2 `simple_switch_grpc` with P4Runtime and Thrift, `simple_switch_CLI`, Mininet 2.3, Python 3.12 or later, Scapy, Go 1.25 or later, GNU Make 4.3 or later, `ip`, `ethtool`, and `ping`. Mininet requires root. The first Go build may download module dependencies and the declared toolchain.

```sh
make build
make run
```

```text
mininet> net
mininet> h1 ping -c 1 10.0.4.1
mininet> exit
```

Ping follows the static branch without accessing flowlet registers. The controller installs the pipeline, timeout, path members, and routes entirely through P4Runtime. It then compares the complete pipeline and table contents, including default actions. Readback permits equivalent padded integer encodings and ordering but rejects missing, extra, duplicate, or different entries. Normal configuration replaces the pipeline and clears state. Verification performs no pipeline or table writes:

```sh
build/controller --device 1 --verify-only
```

`--timeout-us` sets the expected/configured timeout in microseconds. The controller does not track flows, timestamps, IDs, or packet-by-packet selections. BMv2's installed P4Runtime implementation lacks register access. Tests use Thrift `register_read` and `register_reset` solely for state inspection/reset; forwarding, timeout, and path configuration remain P4Runtime-driven.

Readiness uses listener checks followed by P4Runtime arbitration and verified configuration. Existing interfaces or occupied control ports cause startup to fail. Runtime logs live in a temporary directory removed at shutdown. Cleanup uses owned child processes and Mininet links; it does not run global `mn -c` or kill other switches. Mininet's global sysctl tuning is disabled.

## Tests and limitations

```sh
make test
make clean
```

Tests compile P4 with `--Werror`, inspect the pipeline and register layout, test controller construction/readback, and run real BMv2 switches in Mininet. AF_PACKET sockets are bound before injection. Captures check exact multiplicity and integrity at both branches, both transit exits, and the destination host. Captures stay in memory; build products live under `build/`.

TCP and UDP tests search at most 256 deterministic tuples for an initial upper-to-lower transition and validate it against packets and registers. They exercise a 20-packet burst, short-gap continuation, timeout-triggered reselection, stickiness afterward, and a subsequent flowlet that retains the same path. The 500 ms timeout leaves room for register inspection on the local target; controlled continuation and timeout gaps are 250 ms and 650 ms. Tests verify observed timestamp deltas without requiring exact microsecond equality. All five arrays are reset and fully read back between flowlet scenarios without restarting BMv2. TCP probes use RST/ACK to avoid kernel replies.

Reverse flowlets run on s4 while established forward state on s1 remains unchanged. Transit switches are checked for untouched registers. A protocol-only tuple difference tests independent TCP/UDP state: one flow times out while keepalive packets retain the other's flowlet. A bounded search of at most 4097 tuples finds a slot collision with distinct fingerprints. Alternating residents after nonzero flowlet IDs verifies fresh timestamps, ID 0, and independently selected paths on eviction; other slots remain untouched.

Bypass and drop tests run in both directions with empty and populated state, comparing all five arrays on all four switches. ICMP, other IPv4 protocols, and TCP/UDP first and non-first fragments must preserve state. Invalid IPv4 checksums, TTL expiry, unsupported IHL, route misses, truncated headers, and inconsistent IPv4/TCP/UDP lengths must drop without changing state. Captures also verify TCP options and binary payloads; fragmented transport checksums are checked after reassembly.

The suite also covers ordinary forward/reverse routing, both static branches, ping, live verification, and cleanup after successful operation, controller failure, or SIGTERM at the interactive CLI. `make clean` removes build products and local Python caches.

This is a reference implementation, not a production fabric load balancer. State is bounded, direct-mapped, and subject to eviction and fingerprint aliases. This is not congestion-aware load balancing: path selection has no queue, utilization, failure, or ordering feedback. A time gap alone does not guarantee that packets from successive flowlets cannot reorder in a congested network.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
