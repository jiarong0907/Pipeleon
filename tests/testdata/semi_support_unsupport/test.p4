/* -*- P4_16 -*- */
// p4c-bm2-ss --p4v 16 --emit-externs "test.p4" -o "test.p4.json"
#include <core.p4>
#include <v1model.p4>
const bit<16> TYPE_IPV4 = 0x0800;


#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

const bit<8>  TCP_PROTOCOL = 6;
const bit<8>  UDP_PROTOCOL = 0x11;
const bit<8>  MIGRATION_PROTOCOL = 251;
const bit<8>  ICMP_PROTOCOL = 1;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

struct headers {
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    tcp_t           tcp;
    udp_t           udp;
}

struct metadata {
}
/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4           :parse_ipv4;
            default: accept;
        }
    }


    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TCP_PROTOCOL   : parse_tcp;
            UDP_PROTOCOL   : parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

extern void install_exact_entry_1_0<K1>(
    string table_name,
    string action_name,
    in K1 k1);


control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // unsupport

    // act: no install; key: range
    action unspt_tab1_act1() {
        hdr.ipv4.srcAddr = 0xffffffff;
    }

    table unspt_tab1 {
        key = {
            hdr.tcp.dstPort   : range;
        }
        actions = {
            unspt_tab1_act1;
        }
        default_action = unspt_tab1_act1();
    }

    // act: no install; key: range and others
    action unspt_tab2_act1() {
        hdr.ipv4.srcAddr = 0xffffffff;
    }
    action unspt_tab2_act2() {
        hdr.ipv4.dstAddr = 0xffffffff;
    }

    table unspt_tab2 {
        key = {
            hdr.ipv4.protocol : exact;
            hdr.ipv4.dstAddr  : exact;
            hdr.tcp.dstPort   : range;
        }
        actions = {
            unspt_tab2_act1;
            unspt_tab2_act2;
        }
        default_action = unspt_tab2_act1();
    }

    // act: install; key: range
    action unspt_tab3_act1() {
        install_exact_entry_1_0(
            "MyIngress.unspt_key_tab2",
            "MyIngress.unspt_key_tab2_act1",
            hdr.ipv4.protocol);
    }

    table unspt_tab3 {
        key = {
            hdr.tcp.dstPort   : range;
        }
        actions = {
            unspt_tab3_act1;
        }
        default_action = unspt_tab3_act1();
    }

    // act: install; key: range and others
    action unspt_tab4_act1() {
        install_exact_entry_1_0(
            "MyIngress.unspt_key_tab2",
            "MyIngress.unspt_key_tab2_act1",
            hdr.ipv4.protocol);
    }

    table unspt_tab4 {
        key = {
            hdr.ipv4.protocol : exact;
            hdr.ipv4.dstAddr  : exact;
            hdr.tcp.dstPort   : range;
        }
        actions = {
            unspt_tab4_act1;
        }
        default_action = unspt_tab4_act1();
    }

    // act: install and others; key: 2 range and others
    action unspt_tab5_act1() {
        install_exact_entry_1_0(
            "MyIngress.unspt_key_tab2",
            "MyIngress.unspt_key_tab2_act1",
            hdr.ipv4.protocol);
    }

    action unspt_tab5_act2() {
        hdr.ipv4.srcAddr = 0xffffffff;
    }

    table unspt_tab5 {
        key = {
            hdr.ipv4.protocol : exact;
            hdr.ipv4.dstAddr  : range;
            hdr.tcp.dstPort   : range;
        }
        actions = {
            unspt_tab5_act1;
            unspt_tab5_act2;
        }
        default_action = unspt_tab5_act1();
    }


    // semisupport

    // act: only 1 install
    action semispt_tab1_act1() {
        install_exact_entry_1_0(
            "MyIngress.unspt_key_tab2",
            "MyIngress.unspt_key_tab2_act1",
            hdr.ipv4.protocol);
    }

    table semispt_tab1 {
        key = {
            hdr.tcp.dstPort   : exact;
        }
        actions = {
            semispt_tab1_act1;
        }
        default_action = semispt_tab1_act1();
    }

    // act: install (default) and others
    action semispt_tab2_act1() {
        install_exact_entry_1_0(
            "MyIngress.unspt_key_tab2",
            "MyIngress.unspt_key_tab2_act1",
            hdr.ipv4.protocol);
    }

    action semispt_tab2_act2() {
        hdr.ipv4.dstAddr = 0xffffffff;
    }

    table semispt_tab2 {
        key = {
            hdr.tcp.dstPort   : exact;
        }
        actions = {
            semispt_tab2_act1;
            semispt_tab2_act2;
        }
        default_action = semispt_tab2_act1();
    }

    // act: install (not default) and others
    action semispt_tab3_act1() {
        hdr.ipv4.dstAddr = 0xffffffff;
    }

    action semispt_tab3_act2() {
        install_exact_entry_1_0(
            "MyIngress.unspt_key_tab2",
            "MyIngress.unspt_key_tab2_act1",
            hdr.ipv4.protocol);
    }

    table semispt_tab3 {
        key = {
            hdr.tcp.dstPort   : exact;
        }
        actions = {
            semispt_tab3_act1;
            semispt_tab3_act2;
        }
        default_action = semispt_tab3_act1();
    }


    // support
    action spt_tab_act1() {
        hdr.ipv4.srcAddr = 0xffffffff;
    }
    action spt_tab_act2() {
        hdr.ipv4.dstAddr = 0xffffffff;
    }
    action spt_tab_act3() {
        hdr.tcp.srcPort = 80;
    }

    table spt_tab {
        key = {
            hdr.ipv4.srcAddr : exact;
        }
        actions = {
            spt_tab_act1;
            spt_tab_act2;
            spt_tab_act3;
        }
       default_action = spt_tab_act1();
    }


    apply {
        unspt_tab1.apply();
        unspt_tab2.apply();
        unspt_tab3.apply();
        unspt_tab4.apply();
        unspt_tab5.apply();
        semispt_tab1.apply();
        semispt_tab2.apply();
        semispt_tab3.apply();
        spt_tab.apply();
    }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
