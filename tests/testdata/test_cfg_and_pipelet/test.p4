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
    bit<16> tabl1_data;
    bit<16> tabl2_data;
    bit<16> tabl3_data;
    bit<16> protocol;
}

struct headers {
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    migration_t     migration;
    tcp_t           tcp;
}

struct metadata {
    bit<16> aaa;
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

    /* test next_table_to_probability() */

    action tab1_act1() {
        hdr.ipv4.srcAddr = 0xffffffff;
    }
    action tab1_act2() {
        mark_to_drop(standard_metadata);
        exit;
    }
    table tab1 {
        key = {
            hdr.ipv4.srcAddr : exact;
        }
        actions = {
            tab1_act1;
            tab1_act2;
        }
       default_action = tab1_act2();
    }

    action tab2_act1() {
        hdr.ipv4.dstAddr = 0xffffffff;
    }
    action tab2_act2() {
        hdr.ipv4.srcAddr = 0xffffffff;
    }

    table tab2 {
        key = {
            hdr.tcp.srcPort : exact;
        }
        actions = {
            tab2_act1;
            tab2_act2;
        }
        default_action = tab2_act2();
    }

    action tab3_act1() {
        hdr.ipv4.dstAddr = 0xffffffff;
    }
    action tab3_act2() {
        mark_to_drop(standard_metadata);
        exit;
    }

    table tab3 {
        key = {
            hdr.tcp.srcPort : exact;
        }
        actions = {
            tab3_act1;
            tab3_act2;
        }
        default_action = tab3_act2();
    }

    action tab4_act1() {
        hdr.tcp.srcPort = 80;
    }

    table tab4 {
        key = {
            hdr.tcp.srcPort : exact;
        }
        actions = {
            tab4_act1;
        }
        default_action = tab4_act1();
    }

    action tab5_act1() {
        hdr.tcp.dstPort = 80;
    }

    table tab5 {
        key = {
            hdr.tcp.srcPort : exact;
        }
        actions = {
            tab5_act1;
        }
        default_action = tab5_act1();
    }

    action tab_switch1_act1() {
        hdr.tcp.dstPort = 80;
    }
    action tab_switch1_act2() {
        hdr.tcp.srcPort = 80;
    }
    table tab_switch1 {
        key = {
            hdr.tcp.srcPort : exact;
        }
        actions = {
            tab_switch1_act1;
            tab_switch1_act2;
        }
        default_action = tab_switch1_act1();
    }

    action tab7_act1() {
        hdr.tcp.srcPort = 80;
    }
    table tab7 {
        key = {
            hdr.tcp.srcPort : exact;
        }
        actions = {
            tab7_act1;
        }
        default_action = tab7_act1();
    }

    action tab8_act1() {
        hdr.tcp.srcPort = 80;
    }
    table tab8 {
        key = {
            hdr.tcp.srcPort : exact;
        }
        actions = {
            tab8_act1;
        }
        default_action = tab8_act1();
    }

    action tab9_act1() {
        hdr.tcp.srcPort = 80;
    }
    table tab9 {
        key = {
            hdr.tcp.srcPort : exact;
        }
        actions = {
            tab9_act1;
        }
        default_action = tab9_act1();
    }

    action tab10_act1() {
        hdr.tcp.srcPort = 80;
    }
    table tab10 {
        key = {
            hdr.tcp.srcPort : exact;
        }
        actions = {
            tab10_act1;
        }
        default_action = tab10_act1();
    }

    action tab11_act1() {
        hdr.tcp.srcPort = 80;
    }
    table tab11 {
        key = {
            hdr.tcp.srcPort : exact;
        }
        actions = {
            tab11_act1;
        }
        default_action = tab11_act1();
    }

    action tab12_act1() {
        hdr.tcp.srcPort = 80;
    }
    table tab12 {
        key = {
            hdr.tcp.srcPort : exact;
        }
        actions = {
            tab12_act1;
        }
        default_action = tab12_act1();
    }

    action tab13_act1() {
        hdr.tcp.srcPort = 80;
    }
    table tab13 {
        key = {
            hdr.tcp.srcPort : exact;
        }
        actions = {
            tab13_act1;
        }
        default_action = tab13_act1();
    }

    action tab14_act1() {
        hdr.tcp.srcPort = 80;
    }
    table tab14 {
        key = {
            hdr.tcp.srcPort : exact;
        }
        actions = {
            tab14_act1;
        }
        default_action = tab14_act1();
    }

    action tab15_act1() {
        hdr.tcp.srcPort = 80;
    }
    table tab15 {
        key = {
            hdr.tcp.srcPort : exact;
        }
        actions = {
            tab15_act1;
        }
        default_action = tab15_act1();
    }

    action tab16_act1() {
        hdr.tcp.srcPort = 80;
    }
    table tab16 {
        key = {
            hdr.tcp.srcPort : exact;
        }
        actions = {
            tab16_act1;
        }
        default_action = tab16_act1();
    }

    action tab17_act1() {
        hdr.tcp.srcPort = 80;
    }
    table tab17 {
        key = {
            hdr.tcp.srcPort : exact;
        }
        actions = {
            tab17_act1;
        }
        default_action = tab17_act1();
    }

    action tab_switch2_act1() {
        hdr.tcp.dstPort = 80;
    }
    action tab_switch2_act2() {
        hdr.tcp.srcPort = 80;
    }
    action tab_switch2_act3() {
        hdr.tcp.srcPort = 60;
    }
    table tab_switch2 {
        key = {
            hdr.tcp.dstPort : exact;
        }
        actions = {
            tab_switch2_act1;
            tab_switch2_act2;
            tab_switch2_act3;
        }
        default_action = tab_switch2_act1();
    }

    action tab19_act1() {
        hdr.tcp.srcPort = 80;
    }
    table tab19 {
        key = {
            hdr.tcp.srcPort : exact;
        }
        actions = {
            tab19_act1;
        }
        default_action = tab19_act1();
    }

    action tab20_act1() {
        hdr.tcp.srcPort = 80;
    }
    table tab20 {
        key = {
            hdr.tcp.srcPort : exact;
        }
        actions = {
            tab20_act1;
        }
        default_action = tab20_act1();
    }

    action tab21_act1() {
        hdr.tcp.srcPort = 80;
    }
    table tab21 {
        key = {
            hdr.tcp.srcPort : exact;
        }
        actions = {
            tab21_act1;
        }
        default_action = tab21_act1();
    }

    action tab22_act1() {
        hdr.tcp.srcPort = 80;
    }
    table tab22 {
        key = {
            hdr.tcp.srcPort : exact;
        }
        actions = {
            tab22_act1;
        }
        default_action = tab22_act1();
    }

    action tab23_act1() {
        hdr.tcp.srcPort = 80;
    }
    table tab23 {
        key = {
            hdr.tcp.srcPort : exact;
        }
        actions = {
            tab23_act1;
        }
        default_action = tab23_act1();
    }


    apply {
        tab1.apply();
        tab2.apply();
        tab3.apply();
        tab4.apply();
        if (hdr.tcp.isValid()){
            tab5.apply();
        }

        // if (tab4.apply().hit) {
        //     tab5.apply();
        // }

        switch(tab_switch1.apply().action_run) {
            tab_switch1_act1:{
                tab7.apply();
            }
            tab_switch1_act2:{
                if (hdr.tcp.isValid()){  //node_10
                    tab8.apply();
                    }
                else {
                    tab9.apply();
                    tab10.apply();
                    }
                tab11.apply();
            }
        }
        tab12.apply();
        if (hdr.tcp.isValid()){
            tab13.apply();
            if (hdr.tcp.srcPort == 80){
                tab15.apply();
                tab16.apply();
            }
            tab17.apply();
        }
        else {
            tab14.apply();
            switch(tab_switch2.apply().action_run){
                tab_switch2_act1:{
                    tab19.apply();
                }
                tab_switch2_act2:{
                    tab20.apply();
                }
                tab_switch2_act3:{
                    tab21.apply();
                }
            }
            tab22.apply();
        }
        tab23.apply();

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
