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

  action set_ptype_reject(bit<10> packet_type) {
    local_metadata.pipeline_meta.packet_type = PakcetType.Rejected;
    local_metadata.pipeline_meta.egress = ToSW;
  }

  action copy_inner_v6_set_ptype(bit<10> packet_type) {
    local_metadata.pipeline_meta.v6_src = headers.ip_inner.v6.src_ip;
    local_metadata.pipeline_meta.v6_dst = headers.ip_inner.v6.dst_ip;
    local_metadata.pipeline_meta.next_header = headers.ip_inner.v6.next_header;
    local_metadata.pipeline_meta.src_port = headers.l4_inner.ports.src_port;
    local_metadata.pipeline_meta.dst_port = headers.l4_inner.ports.dst_port;
    local_metadata.pipeline_meta.packet_type = packet_type;
  }

table encap_ptype_inner_v4 {
    key = {
      headers.l4_outer.ports.dst_port : exact;
      headers.ip_inner.v4.protocol : optional;
    }
    actions = {
      set_ptype_only;
      set_ptype_reject;
    }
    default_action = set_ptype_reject();

    const entries = {
        (VXLAN_PORT, L4Proto.TCP):
           set_ptype_only(PakcetType.VxlanIPv4TCP);
        (VXLAN_PORT, L4Proto.UDP):
           set_ptype_only(PakcetType.VxlanIPv4UDP);
        (VXLAN_PORT, L4Proto.SCTP):
           set_ptype_only(PakcetType.VxlanIPv4SCTP);
        (VXLAN_PORT, L4Proto.ICMP):
           set_ptype_only(PakcetType.VxlanIPv4ICMP);
        (VXLAN_PORT, _):
           set_ptype_only(PakcetType.VxlanIPv4Other);
      }
  }

  table encap_ptype_inner_v6 {
    key = {
      headers.l4_outer.ports.dst_port : exact;
      headers.ip_inner.v6.next_header : optional;
    }
    actions = {
      copy_inner_v6_set_ptype;
      set_ptype_reject;
    }
    default_action = set_ptype_reject();
    const entries = {
       (VXLAN_PORT, L4Proto.TCP):
           copy_inner_v6_set_ptype(PakcetType.VxlanIPv6TCP);
       (VXLAN_PORT, L4Proto.UDP):
           copy_inner_v6_set_ptype(PakcetType.VxlanIPv6UDP);
       (VXLAN_PORT, L4Proto.SCTP):
           copy_inner_v6_set_ptype(PakcetType.VxlanIPv6SCTP);
       (VXLAN_PORT, L4Proto.ICMP):
           copy_inner_v6_set_ptype(PakcetType.VxlanIPv6ICMP);
       (VXLAN_PORT, _):
           copy_inner_v6_set_ptype(PakcetType.VxlanIPv6Other);
    }
  }

  apply {
      if (headers.ip_inner.v6.isValid()) {
          encap_ptype_inner_v6.apply();
      } else if (headers.ip_inner.v4.isValid()) {
          encap_ptype_inner_v4.apply();
      }
  }
}
#endif
