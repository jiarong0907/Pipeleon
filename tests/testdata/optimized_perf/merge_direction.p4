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

    apply {
        direction_lookup.apply();
        appliance.apply();
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
