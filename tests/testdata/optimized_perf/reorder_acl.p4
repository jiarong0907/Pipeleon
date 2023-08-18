#include <core.p4>
#include <v1model.p4>
#include "include/sirius_headers.p4"
#include "include/sirius_metadata.p4"
#include "include/sirius_parser.p4"

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

    apply {
        direction_lookup.apply();
        acl_stage1.apply();
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
