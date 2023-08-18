#ifndef __STAGE0_ENCAP_P4
#define __STAGE0_ENCAP_P4
#include "types.p4"
#include <core.p4>
#include <v1model.p4>

control encap(inout headers_t headers, inout local_metadata_t local_metadata,
                inout standard_metadata_t standard_metadata) {

  action set_ptype_only(bit<10> packet_type) {
    local_metadata.pipeline_meta.packet_type = packet_type;
  }

  action copy_outer_v6_set_ptype(bit<10> packet_type) {
    local_metadata.pipeline_meta.v6_src = headers.ip_outer.v6.src_ip;
    local_metadata.pipeline_meta.v6_dst = headers.ip_outer.v6.dst_ip;
    local_metadata.pipeline_meta.next_header = headers.ip_outer.v6.next_header;
    local_metadata.pipeline_meta.src_port = headers.l4_outer.ports.src_port;
    local_metadata.pipeline_meta.dst_port = headers.l4_outer.ports.dst_port;
    local_metadata.pipeline_meta.packet_type = packet_type;
  }

table encap_ptype_outer_v4 {
    key = {
      headers.ip_outer.v4.protocol : exact;
    }
    actions = {
      set_ptype_only;
    }

    const entries = {
        (L4Proto.TCP):
           set_ptype_only(PakcetType.IPv4TCP);
        (L4Proto.UDP):
           set_ptype_only(PakcetType.IPv4UDP);
        (L4Proto.SCTP):
           set_ptype_only(PakcetType.IPv4SCTP);
        (L4Proto.ICMP):
           set_ptype_only(PakcetType.IPv4ICMP);
        (_):
           set_ptype_only(PakcetType.IPv4Other);
      }
  }

  table encap_ptype_outer_v6 {
    key = {
      headers.ip_outer.v6.next_header : exact;
    }
    actions = {
      copy_outer_v6_set_ptype;
    }
    const entries = {
       L4Proto.TCP:
           copy_outer_v6_set_ptype(PakcetType.IPv6TCP);
       L4Proto.UDP:
           copy_outer_v6_set_ptype(PakcetType.IPv6UDP);
       L4Proto.SCTP:
           copy_outer_v6_set_ptype(PakcetType.IPv6SCTP);
       L4Proto.ICMP:
           copy_outer_v6_set_ptype(PakcetType.IPv6ICMP);
       _:
           copy_outer_v6_set_ptype(PakcetType.IPv6Other);
    }
  }

  table l2_ptype {
    key = {
        headers.mac.type : exact;
    }
    actions = {
        set_ptype_only;
    }
    const entries = {
        (EtherType.ARP): set_ptype_only(PakcetType.Arp);
    }
    default_action =
      set_ptype_only(PakcetType.L2Other);
  }

apply {
    if (headers.ip_outer.v6.isValid()) {
        encap_ptype_outer_v6.apply();
    } else if (headers.ip_outer.v4.isValid()) {
        encap_ptype_outer_v4.apply();
    }else {
      // ARP ptype
      l2_ptype.apply();
    }
  }
}
#endif
