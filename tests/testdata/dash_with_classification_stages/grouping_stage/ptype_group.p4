#ifndef __STAGE_2_PTYPE_GROUP_P4
#define __STAGE_2_PTYPE_GROUP_P4

#include "types.p4"
control ptype_group_ctrl(inout headers_t headers, inout local_metadata_t local_metadata,
                inout standard_metadata_t standard_metadata) {

  action set_packet_type_group(bit<10> packet_type_group) {
    local_metadata.pipeline_meta.packet_type_group = packet_type_group;
  }

  table packet_type_group_tbl {
    key = {
       local_metadata.pipeline_meta.packet_type : exact;
    }
    actions = {
        set_packet_type_group;
    }

    const entries = {
       PacketType.Ipv4TCP:
         set_packet_type_group(PacketGroup.Ipv4);
       PacketType.Ipv4UDP:
          set_packet_type_group(PacketGroup.IPv4);
       PacketType.Ipv4SCTP:
          set_packet_type_group(PacketGroup.IPv4);
       PacketType.Ipv4ICMP:
          set_packet_type_group(PacketGroup.IPv4);
       PacketType.Ipv4Other:
          set_packet_type_group(PacketGroup.IPv4);
       PacketType.Ipv6TCP:
         set_packet_type_group(PacketGroup.IPv6);
       PacketType.Ipv6UDP:
         set_packet_type_group(PacketGroup.IPv6);
       PacketType.Ipv6SCTP:
         set_packet_type_group(PacketGroup.IPv6);
       PacketType.Ipv6ICMP:
         set_packet_type_group(PacketGroup.IPv6);
       PacketType.Ipv6Other:
         set_packet_type_group(PacketGroup.IPv6);
       PacketType.VxlanIpv4TCP:
         set_packet_type_group(PacketGroup.VxlanIpv4);
       PacketType.VxlanIpv4UDP:
          set_packet_type_group(PacketGroup.VxlanIPv4);
       PacketType.VxlanIpv4SCTP:
          set_packet_type_group(PacketGroup.VxlanIPv4);
       PacketType.VxlanIpv4ICMP:
          set_packet_type_group(PacketGroup.VxlanIPv4);
       PacketType.VxlanIpv4Other:
          set_packet_type_group(PacketGroup.VxlanIPv4);
       PacketType.VxlanIpv6TCP:
         set_packet_type_group(PacketGroup.VxlanIPv6);
       PacketType.VxlanIpv6UDP:
         set_packet_type_group(PacketGroup.VxlanIPv6);
       PacketType.VxlanIpv6SCTP:
         set_packet_type_group(PacketGroup.VxlanIPv6);
       PacketType.VxlanIpv6ICMP:
         set_packet_type_group(PacketGroup.VxlanIPv6);
       PacketType.VxlanIpv6Other:
         set_packet_type_group(PacketGroup.VxlanIPv6);
       PacketType.Arp:
         set_packet_type_group(PacketGroup.L2);
       PacketType.L2Other:
         set_packet_type_group(PacketGroup.L2);

    }

  }
  apply {
    packet_type_group_tbl.apply();

  }

}
#endif
