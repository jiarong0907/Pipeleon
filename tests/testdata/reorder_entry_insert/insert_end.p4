#include <core.p4>
#include <v1model.p4>

extern void install_exact_entry_1_0<K1>(
    string table_name,
    string action_name,
    in K1 k1);

typedef bit<48>  EthernetAddress;
typedef bit<32>  IPv4Address;
typedef bit<128> IPv6Address;

header ethernet_t {
    EthernetAddress dst_addr;
    EthernetAddress src_addr;
    bit<16>         ether_type;
}

header ipv4_t {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      diffserv;
    bit<16>     total_len;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     frag_offset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     hdr_checksum;
    IPv4Address src_addr;
    IPv4Address dst_addr;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
}

struct metadata_t {
    bit<16> eni;
}

#define TCP_PROTO 6
#define IPV4_ETHTYPE 0x800

parser sirius_parser(packet_in packet,
                    out headers_t hd,
                    inout metadata_t meta,
                    inout standard_metadata_t standard_meta){
    state start {
        packet.extract(hd.ethernet);
        transition select(hd.ethernet.ether_type) {
            0x0800:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hd.ipv4);
        transition select(hd.ipv4.protocol) {
            TCP_PROTO: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hd.tcp);
        transition accept;
    }
}

control sirius_ingress(inout headers_t hdr,
                       inout metadata_t meta,
                       inout standard_metadata_t standard_metadata) {

    action permit_and_continue() { }
    action permit_and_insert() {
        install_exact_entry_1_0(
            "MyIngress.forward_tab",
            "MyIngress.forward",
            hdr.ipv4.dst_addr);
    }
    action deny() {
        mark_to_drop(standard_metadata);
        exit;
    }

    table acl_stage1 {
        key = {
            meta.eni : exact ;
            hdr.ipv4.dst_addr : ternary;
            hdr.ipv4.src_addr : ternary;
            hdr.ipv4.protocol : exact;
            hdr.tcp.src_port : exact;
            hdr.tcp.dst_port : exact;
        }
        actions = {
            permit_and_continue;
            deny;
        }
        default_action = deny;
    }

    table acl_stage2 {
        key = {
            meta.eni : exact ;
            hdr.ipv4.dst_addr : ternary;
            hdr.ipv4.src_addr : ternary;
            hdr.ipv4.protocol : exact;
            hdr.tcp.src_port : exact;
            hdr.tcp.dst_port : exact;
        }
        actions = {
            permit_and_continue;
            deny;
        }
        default_action = deny;
    }

    table acl_stage3 {
        key = {
            meta.eni : exact ;
            hdr.ipv4.dst_addr : ternary;
            hdr.ipv4.src_addr : ternary;
            hdr.ipv4.protocol : exact;
            hdr.tcp.src_port : exact;
            hdr.tcp.dst_port : exact;
        }
        actions = {
            permit_and_insert;
            deny;
        }
        default_action = deny;
    }

    apply {
        acl_stage1.apply();
        acl_stage2.apply();
        acl_stage3.apply();
    }
}

control sirius_egress(inout headers_t hdr,
                      inout metadata_t meta,
                      inout standard_metadata_t standard_metadata) {
    apply { }
}

control sirius_verify_checksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

control sirius_compute_checksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

control sirius_deparser(packet_out packet,
                   in headers_t hdr){
    apply {
	packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

V1Switch(sirius_parser(),
         sirius_verify_checksum(),
         sirius_ingress(),
         sirius_egress(),
         sirius_compute_checksum(),
         sirius_deparser()) main;
