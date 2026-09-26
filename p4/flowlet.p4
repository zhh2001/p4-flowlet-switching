#include <core.p4>
#include <v1model.p4>

const bit<32> STATE_SIZE = 4096;

header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq;
    bit<32> ack;
    bit<4> data_offset;
    bit<4> reserved;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
}

struct metadata_t {
    bit<16> src_port;
    bit<16> dst_port;
    bool multipath;
    bit<1> selected_path;
    bit<48> timeout_us;
}

parser PacketParser(packet_in packet, out headers_t hdr,
                    inout metadata_t meta, inout standard_metadata_t sm) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            0x0800: ipv4;
            default: accept;
        }
    }
    state ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.version, hdr.ipv4.ihl,
                          hdr.ipv4.flags[0:0], hdr.ipv4.frag_offset,
                          hdr.ipv4.protocol) {
            (4, 5, 0, 0, 6): tcp;
            (4, 5, 0, 0, 17): udp;
            default: accept;
        }
    }
    state tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    state udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

control VerifyIPv4Checksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        verify_checksum(hdr.ipv4.isValid(), {
            hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
            hdr.ipv4.total_len, hdr.ipv4.identification, hdr.ipv4.flags,
            hdr.ipv4.frag_offset, hdr.ipv4.ttl, hdr.ipv4.protocol,
            hdr.ipv4.src_addr, hdr.ipv4.dst_addr
        }, hdr.ipv4.checksum, HashAlgorithm.csum16);
    }
}

control IngressPipe(inout headers_t hdr, inout metadata_t meta,
                    inout standard_metadata_t sm) {
    register<bit<1>>(STATE_SIZE) flow_valid;
    register<bit<32>>(STATE_SIZE) flow_fingerprint;
    register<bit<48>>(STATE_SIZE) flow_last_seen;
    register<bit<32>>(STATE_SIZE) flowlet_id;
    register<bit<1>>(STATE_SIZE) flow_path;

    action drop() {
        mark_to_drop(sm);
    }

    action set_nhop(bit<9> port, bit<48> src_mac, bit<48> dst_mac) {
        sm.egress_spec = port;
        hdr.ethernet.src_addr = src_mac;
        hdr.ethernet.dst_addr = dst_mac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action select_flowlet(bit<1> default_path) {
        meta.multipath = true;
        meta.selected_path = default_path;
    }

    action set_timeout_us(bit<48> value) {
        meta.timeout_us = value;
    }

    action update_flowlet() {
        bit<32> index;
        bit<32> fingerprint;
        bit<1> valid;
        bit<32> resident;
        bit<48> last_seen;
        bit<48> gap;
        bit<32> id;
        bool fresh;

        // BMv2 locks all five register arrays for this single action.
        @atomic {
            hash(index, HashAlgorithm.crc32, 32w0,
                 { hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.ipv4.protocol,
                   meta.src_port, meta.dst_port }, STATE_SIZE);
            hash(fingerprint, HashAlgorithm.crc32, 32w0,
                 { hdr.ipv4.dst_addr, hdr.ipv4.src_addr,
                   meta.dst_port, meta.src_port, hdr.ipv4.protocol,
                   32w0x9e3779b9 }, 64w0x100000000);

            flow_valid.read(valid, index);
            flow_fingerprint.read(resident, index);
            flow_last_seen.read(last_seen, index);
            flowlet_id.read(id, index);
            flow_path.read(meta.selected_path, index);
            gap = sm.ingress_global_timestamp - last_seen;
            fresh = valid == 0 || resident != fingerprint;

            if (fresh) {
                id = 0;
                flow_valid.write(index, 1);
                flow_fingerprint.write(index, fingerprint);
            } else if (gap > meta.timeout_us) {
                id = id + 1;
            }
            if (fresh || gap > meta.timeout_us) {
                hash(meta.selected_path, HashAlgorithm.crc32, 1w0,
                     { hdr.ipv4.src_addr, hdr.ipv4.dst_addr, id,
                       hdr.ipv4.protocol, meta.src_port, meta.dst_port }, 2w2);
                flowlet_id.write(index, id);
                flow_path.write(index, meta.selected_path);
            }
            flow_last_seen.write(index, sm.ingress_global_timestamp);
        }
    }

    table ipv4_route {
        key = { hdr.ipv4.dst_addr: lpm; }
        actions = { set_nhop; select_flowlet; drop; }
        size = 16;
        const default_action = drop();
    }

    table flowlet_config {
        actions = { set_timeout_us; }
        default_action = set_timeout_us(0);
    }

    table flowlet_path {
        key = { meta.selected_path: exact; }
        actions = { set_nhop; drop; }
        size = 2;
        const default_action = drop();
    }

    apply {
        meta.multipath = false;
        if (sm.parser_error != error.NoError || !hdr.ipv4.isValid()) {
            drop();
        } else if (hdr.ipv4.version != 4 || hdr.ipv4.ihl != 5 ||
                   hdr.ipv4.total_len < 20 ||
                   sm.packet_length < (bit<32>) hdr.ipv4.total_len + 14 ||
                   sm.checksum_error == 1 || hdr.ipv4.ttl <= 1) {
            drop();
        } else if (hdr.tcp.isValid() && (hdr.tcp.data_offset < 5 ||
                   (bit<32>) hdr.ipv4.total_len < 20 + (bit<32>) hdr.tcp.data_offset * 4)) {
            drop();
        } else if (hdr.udp.isValid() && (hdr.udp.length < 8 ||
                   (bit<32>) hdr.udp.length + 20 != (bit<32>) hdr.ipv4.total_len)) {
            drop();
        } else {
            ipv4_route.apply();
            if (meta.multipath) {
                if (hdr.tcp.isValid() || hdr.udp.isValid()) {
                    if (hdr.tcp.isValid()) {
                        meta.src_port = hdr.tcp.src_port;
                        meta.dst_port = hdr.tcp.dst_port;
                    } else {
                        meta.src_port = hdr.udp.src_port;
                        meta.dst_port = hdr.udp.dst_port;
                    }
                    flowlet_config.apply();
                    update_flowlet();
                }
                flowlet_path.apply();
            }
        }
    }
}

control EgressPipe(inout headers_t hdr, inout metadata_t meta,
                   inout standard_metadata_t sm) {
    apply { }
}

control UpdateIPv4Checksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        update_checksum(hdr.ipv4.isValid(), {
            hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
            hdr.ipv4.total_len, hdr.ipv4.identification, hdr.ipv4.flags,
            hdr.ipv4.frag_offset, hdr.ipv4.ttl, hdr.ipv4.protocol,
            hdr.ipv4.src_addr, hdr.ipv4.dst_addr
        }, hdr.ipv4.checksum, HashAlgorithm.csum16);
    }
}

control PacketDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

V1Switch(PacketParser(), VerifyIPv4Checksum(), IngressPipe(), EgressPipe(),
         UpdateIPv4Checksum(), PacketDeparser()) main;
