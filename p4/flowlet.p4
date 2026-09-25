#include <core.p4>
#include <v1model.p4>

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

struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
}

struct metadata_t { }

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
    action drop() {
        mark_to_drop(sm);
    }

    action set_nhop(bit<9> port, bit<48> src_mac, bit<48> dst_mac) {
        sm.egress_spec = port;
        hdr.ethernet.src_addr = src_mac;
        hdr.ethernet.dst_addr = dst_mac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_route {
        key = { hdr.ipv4.dst_addr: lpm; }
        actions = { set_nhop; drop; }
        size = 16;
        const default_action = drop();
    }

    apply {
        if (sm.parser_error != error.NoError || !hdr.ipv4.isValid()) {
            drop();
        } else if (hdr.ipv4.version != 4 || hdr.ipv4.ihl != 5 ||
                   hdr.ipv4.total_len < 20 ||
                   sm.packet_length < (bit<32>) hdr.ipv4.total_len + 14 ||
                   sm.checksum_error == 1 || hdr.ipv4.ttl <= 1) {
            drop();
        } else {
            ipv4_route.apply();
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
    }
}

V1Switch(PacketParser(), VerifyIPv4Checksum(), IngressPipe(), EgressPipe(),
         UpdateIPv4Checksum(), PacketDeparser()) main;
