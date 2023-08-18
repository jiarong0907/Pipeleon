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
        routing.apply();
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
