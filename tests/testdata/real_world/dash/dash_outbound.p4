#ifndef _SIRIUS_OUTBOUND_P4_
#define _SIRIUS_OUTBOUND_P4_

#include "dash_headers.p4"
#include "dash_acl.p4"
#include "dash_conntrack.p4"

control outbound(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata)
{
    action route_vnet(bit<16> dst_vnet_id) {
        meta.dst_vnet_id = dst_vnet_id;
    }

    action route_vnet_direct(bit<16> dst_vnet_id,
                             bit<1> is_overlay_ip_v4_or_v6,
                             IPv4ORv6Address overlay_ip) {
        meta.dst_vnet_id = dst_vnet_id;
        meta.lkup_dst_ip_addr = overlay_ip;
        meta.is_lkup_dst_ip_v6 = is_overlay_ip_v4_or_v6;
    }

    action route_direct() {
        /* send to underlay router without any encap */
    }

    action drop() {
        meta.dropped = true;
    }

    table routing {
        key = {
            meta.eni_id : exact;
            meta.is_overlay_ip_v6 : exact;
            meta.dst_ip_addr : lpm;
        }

        actions = {
            route_vnet; /* for expressroute - ecmp of overlay */
            route_vnet_direct;
            route_direct;
            drop;
        }
        default_action = drop;

    }

    action set_tunnel_mapping(IPv4Address underlay_dip,
                              EthernetAddress overlay_dmac,
                              bit<1> use_dst_vnet_vni) {
        if (use_dst_vnet_vni == 1)
            meta.vnet_id = meta.dst_vnet_id;
        meta.encap_data.overlay_dmac = overlay_dmac;
        meta.encap_data.underlay_dip = underlay_dip;
    }

    table ca_to_pa {
        key = {
            /* Flow for express route */
            meta.dst_vnet_id: exact;
            meta.is_lkup_dst_ip_v6 : exact;
            meta.lkup_dst_ip_addr : exact;
        }

        actions = {
            set_tunnel_mapping;
            @defaultonly drop;
        }
        default_action = drop;
    }

    action set_vnet_attrs(bit<24> vni) {
        meta.encap_data.vni = vni;
    }

    table vnet {
        key = {
            meta.vnet_id : exact;
        }

        actions = {
            set_vnet_attrs;
        }
    }

    apply {
#ifdef STATEFUL_P4
           ConntrackOut.apply(0);
#endif /* STATEFUL_P4 */

#ifdef PNA_CONNTRACK
        ConntrackOut.apply(hdr, meta);
#endif // PNA_CONNTRACK

        /* ACL */
        if (!meta.conntrack_data.allow_out) {
            acl.apply(hdr, meta, standard_metadata);
        }

#ifdef STATEFUL_P4
            ConntrackIn.apply(1);
#endif /* STATEFUL_P4 */

#ifdef PNA_CONNTRACK
        ConntrackIn.apply(hdr, meta);
#endif // PNA_CONNTRACK

        meta.lkup_dst_ip_addr = meta.dst_ip_addr;
        meta.is_lkup_dst_ip_v6 = meta.is_overlay_ip_v6;

        switch (routing.apply().action_run) {
            route_vnet_direct:
            route_vnet: {
                ca_to_pa.apply();
                vnet.apply();

                vxlan_encap(hdr,
                            meta.encap_data.underlay_dmac,
                            meta.encap_data.underlay_smac,
                            meta.encap_data.underlay_dip,
                            meta.encap_data.underlay_sip,
                            meta.encap_data.overlay_dmac,
                            meta.encap_data.vni);
             }
         }
    }
}

#endif /* _SIRIUS_OUTBOUND_P4_ */
