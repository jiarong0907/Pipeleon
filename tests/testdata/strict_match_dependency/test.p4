/* -*- P4_16 -*- */


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


header migration_t {
    bit<32> tabl1_data;
    bit<32> tabl2_data;
    bit<32> tabl3_data;
    bit<32> protocol;
}

struct headers {
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    migration_t     migration;
    tcp_t           tcp;
}

struct metadata {
    bit<16> aaa;
    bit<16> bbb;
    bit<16> ccc;
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
            MIGRATION_PROTOCOL: parse_migration;
            default: accept;
        }
    }

    state parse_migration {
        packet.extract(hdr.migration);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
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

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action tab1_act() {
        hdr.migration.tabl1_data = 1;
        meta.aaa = 1;
        hdr.tcp.srcPort = meta.ccc+1;
        meta.ccc = 1;
        meta.bbb = hdr.ipv4.totalLen;
        hdr.tcp.dstPort = hdr.tcp.srcPort;
    }
    table tab1 {
        actions = {
            tab1_act;
        }
    }

    action tab2_act1(bit<16> port) {
        hdr.migration.tabl2_data = 2;
        hdr.tcp.srcPort = 2;
        hdr.tcp.dstPort = port;
        hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;
    }
    action tab2_act2() {
        hdr.tcp.window = meta.bbb;
        meta.ccc = 16;
        meta.aaa = meta.ccc;
        hdr.ipv4.ttl = hdr.ipv4.ttl-1;
        hdr.ipv4.setValid();
    }
    table tab2 {
        key = {
            hdr.migration.tabl1_data : exact;
            meta.aaa: exact;
        }
        actions = {
            tab2_act1;
            tab2_act2;
        }
        default_action = tab2_act2();
    }
    action tab3_act1() {
        hdr.ipv4.ttl = 2;
        hdr.tcp.window = hdr.tcp.srcPort;
        hdr.migration.tabl2_data = 2;
    }
    action tab3_act2() {

    }
    table tab3 {
        key = {
            hdr.ethernet.srcAddr : exact;
            hdr.tcp.window : exact;
            standard_metadata.ingress_port : exact;
        }
        actions = {
            tab3_act1;
            tab3_act2;
        }
        default_action = tab3_act2();
    }

    apply {
        tab1.apply();
        tab2.apply();
        tab3.apply();
    }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {

    }
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
        packet.emit(hdr.migration);
        packet.emit(hdr.tcp);
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
