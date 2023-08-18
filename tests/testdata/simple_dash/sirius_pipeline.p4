#include <core.p4>
#include <v1model.p4>
#include "sirius_headers.p4"
#include "sirius_metadata.p4"
#include "sirius_parser.p4"

extern void install_exact_entry_1_0<K1>(
    string table_name,
    string action_name,
    in K1 k1);

control sirius_ingress(inout headers_t hdr,
                       inout metadata_t meta,
                       inout standard_metadata_t standard_metadata) {

    action set_direction(direction_t direction) {
        meta.direction = direction;
    }

    table direction_lookup {
        key = {
            hdr.vxlan.vni : exact @name("hdr.vxlan.vni:vni");
        }

        actions = {
            set_direction;
        }
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
            meta.appliance_id : ternary @name("meta.appliance_id:appliance_id");
        }

        actions = {
            set_appliance;
        }
    }

    action set_eni(bit<16> eni) {
        meta.eni = eni;
    }

    table eni_lookup_from_vm {
        key = {
            hdr.ethernet.src_addr : exact @name("hdr.ethernet.src_addr:smac");
        }

        actions = {
            set_eni;
        }
    }

    action set_vni(bit<24> vni) {
        meta.encap_data.vni = vni;
    }

    table eni_to_vni {
        key = {
            meta.eni : exact @name("meta.eni:eni");
        }

        actions = {
            set_vni;
        }
    }

    action conn_track_hit() {
        meta.conn_track_hit = 1;
    }

    table conn_track_tab {
        key = {
            hdr.ipv4.src_addr        : exact;
            hdr.ipv4.dst_addr        : exact;
            hdr.ipv4.protocol        : exact;
            hdr.tcp.src_port         : exact;
            hdr.tcp.dst_port         : exact;
            meta.eni                 : exact;
        }
        actions = {
            conn_track_hit;
        }
    }


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

    action route_vnet(bit<24> dest_vnet_vni) {
        meta.encap_data.dest_vnet_vni = dest_vnet_vni;
        /* Send packet to port 1 by default if we reached the end of pipeline */
        standard_metadata.egress_spec = 1;
    }

    table routing {
        key = {
            meta.eni : exact @name("meta.eni:eni");
            hdr.ipv4.dst_addr : lpm @name("hdr.ipv4.dst_addr:destination");
        }

        actions = {
            route_vnet;
        }
    }

    apply {
        direction_lookup.apply();
        appliance.apply();

        if (meta.direction == direction_t.OUTBOUND) {
            eni_lookup_from_vm.apply();
            eni_to_vni.apply();

            // send dpdk and back 1M pps
            // full hardware offload 10M pps
            conn_track_tab.apply();
            if (meta.conn_track_hit == 0) {
                acl_stage1.apply(); // 4M pps
                acl_stage2.apply();
                acl_stage3.apply();
            }
            routing.apply();
        }
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

V1Switch(sirius_parser(),
         sirius_verify_checksum(),
         sirius_ingress(),
         sirius_egress(),
         sirius_compute_checksum(),
         sirius_deparser()) main;
