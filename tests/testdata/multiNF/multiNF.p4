#include <core.p4>
#include <v1model.p4>
#include "headers.p4"
#include "parser.p4"

extern void install_exact_entry_1_0<K1>(
    string table_name,
    string action_name,
    in K1 k1);

control MyIngress(inout headers_t hdr,
                       inout metadata_t meta,
                       inout standard_metadata_t standard_metadata) {

    action set_outbound() {
        meta.direction = direction_t.OUTBOUND;
    }

    table direction_lookup {
        key = {
            hdr.vxlan.vni : exact;
        }

        actions = {
            set_outbound;
        }

        size=10;
    }

    action set_appliance(EthernetAddress neighbor_mac,
                         EthernetAddress mac,
                         IPv4Address ip) {
        meta.encap_data.underlay_dmac = neighbor_mac;
        meta.encap_data.underlay_smac = mac;
        meta.encap_data.underlay_sip = ip;
    }

    table appliance {
        key = {
            meta.appliance_id : ternary;
        }

        actions = {
            set_appliance;
        }

        size=10;
    }

    action set_eni(bit<16> eni) {
        meta.eni = eni;
    }

    table eni_lookup_from_vm {
        key = {
            hdr.ethernet.src_addr : exact;
        }

        actions = {
            set_eni;
        }

        size=10;
    }

    action set_vni_f01() {
        meta.encap_data.vni = 0xf01;
    }

    table eni_to_vni {
        key = {
            meta.eni : exact;
        }

        actions = {
            set_vni_f01;
        }

        size=10;
    }

    action conn_track_hit() {
        meta.conn_track_hit = 1;
    }

    table conn_track_tab {
        key = {
            hdr.ipv4.src_addr        : exact;
            hdr.ipv4.dst_addr        : exact;
            hdr.ipv4.protocol        : exact;
            hdr.udp.src_port         : exact;
            hdr.udp.dst_port         : exact;
            meta.eni                 : exact;
        }
        actions = {
            conn_track_hit;
        }
    }


    action permit_and_continue() { }
    action permit_and_insert() {
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        // install_exact_entry_1_0(
        //     "MyIngress.forward_tab",
        //     "MyIngress.forward",
        //     hdr.ipv4.dst_addr);
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
            // permit_and_continue;
            deny;
        }
        default_action = deny;
    }

    action route_vnet(bit<24> dest_vnet_vni, bit<9> egress_port) {
        meta.encap_data.dest_vnet_vni = dest_vnet_vni;
        /* Send packet to port 1 by default if we reached the end of pipeline */
        standard_metadata.egress_spec = egress_port;
    }

    table dash_routing {
        key = {
            meta.eni : exact;
            hdr.ipv4.dst_addr : lpm;
        }

        actions = {
            route_vnet;
        }
    }

    table lb_ac1 {
        key = {
            hdr.tcp.src_port : exact;
            hdr.ipv4.src_addr : ternary;
        }
        actions = {
            permit_and_continue;
            deny;
        }
        default_action = deny;
    }

    table lb_ac2 {
        key = {
            hdr.tcp.src_port : exact;
            hdr.ipv4.src_addr : ternary;
        }
        actions = {
            permit_and_continue;
            deny;
        }
        default_action = deny;
    }

    table lb_ac3 {
        key = {
            hdr.tcp.src_port : exact;
            hdr.ipv4.src_addr : ternary;
        }
        actions = {
            permit_and_continue;
            deny;
        }
        default_action = deny;
    }

    action lb_set_dst_act(bit<32> ip, bit<48> mac) {
        hdr.ipv4.dst_addr = ip;
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = mac;
    }

    table lb_set_dst {
        key = {
            hdr.ipv4.src_addr : ternary;
            hdr.ipv4.dst_addr : exact;
        }
        actions = {
            lb_set_dst_act;
            NoAction;
        }
        default_action = NoAction;
    }

    action add_vlan(bit<48> mac) {
        // emulate adding vlan
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = mac;
    }

    table vlan_ingress_proc {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            add_vlan;
        }
    }

    action mac_learn() {
        // emulate mac_learn
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table mac_learning {
        key = {
            hdr.ethernet.src_addr : exact;
        }
        actions = {
            mac_learn;
            NoAction;
        }
        default_action = mac_learn;
    }

    action route() {meta.is_routable = 1; }

    table routable {
        key = {
            hdr.ethernet.src_addr : exact;
            hdr.ethernet.dst_addr : exact;
        }
        actions = {route; NoAction;}
    }

    action set_nhop(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table l3_routing {
        key = {
            hdr.ipv4.dst_addr : lpm;
        }
        actions = {set_nhop; deny;}
        default_action = deny;
    }

    action forward(bit<9> egress_spec) {
        standard_metadata.egress_spec = egress_spec;
    }

    action broadcast() {
        // TODO: use multicast here, but for emulation purpose it's ok
        standard_metadata.egress_spec = 2;
    }

    table switching {
        key =  {
            hdr.ethernet.dst_addr : exact;
        }
        actions = {forward; broadcast;}
    }

    table l2l3_acl {
        key = {
            hdr.ethernet.src_addr : exact;
            hdr.ethernet.dst_addr : exact;
            hdr.ipv4.src_addr : ternary;
            hdr.ipv4.dst_addr : ternary;
        }
        actions = {
            permit_and_continue;
            deny;
        }
        default_action = deny;
    }

    action strip_vlan() {
        // emulate striping vlan
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table vlan_egress_proc {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            strip_vlan;
        }
    }


    apply {
        // Go to the DASH pipeline
        if (hdr.vxlan.isValid()) { // node_2
            // These two can be merged
            direction_lookup.apply(); // small table
            appliance.apply(); // small table

            if (meta.direction == direction_t.OUTBOUND) { // node_5
                // These two can be merged
                eni_lookup_from_vm.apply(); // small table
                eni_to_vni.apply(); // small table // exact

                // DO NOT do connection tracking to avoid going to the software
                conn_track_tab.apply(); // exact
                if (meta.conn_track_hit == 0) { // node_9
                    // can be reordered
                    acl_stage1.apply();
                    acl_stage2.apply();
                    acl_stage3.apply();
                }
                dash_routing.apply();
            }
        }
        // Go to the load balancer
        else if (hdr.tcp.isValid() && hdr.tcp.dst_port == 1235) { // node_14
            lb_ac1.apply();
            lb_ac2.apply();
            lb_ac3.apply();
            if (hdr.ipv4.dst_addr != 0xffffffff) { // node_18
                lb_set_dst.apply();
            }
        }
        // Go to L2L3 forwarding
        else if (hdr.udp.isValid() && hdr.udp.dst_port == 1235) { // node_20
            vlan_ingress_proc.apply(); // exact
            mac_learning.apply(); // exact

            routable.apply(); // exact
            if (meta.is_routable == 1) { // node_24
                l3_routing.apply(); // lpm
            }
            switching.apply(); // exact
            l2l3_acl.apply(); // ternary
            vlan_egress_proc.apply(); // exact
        }
    }
}

control MyEgress(inout headers_t hdr,
                      inout metadata_t meta,
                      inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

V1Switch(MyParser(),
         MyVerifyChecksum(),
         MyIngress(),
         MyEgress(),
         MyComputeChecksum(),
         MyDeparser()) main;
