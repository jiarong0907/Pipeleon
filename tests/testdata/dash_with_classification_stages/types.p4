#ifndef __TYPES_P4
#define __TYPES_P4

enum bit<16> EtherType {
    IPV4      = 0x0800,
    IPV6      = 0x86DD,
    ARP       = 0x0806
};

enum bit<8> L4Proto {
    TCP       = 0x06,
    UDP       = 0x11,
    SCTP      = 0x84,
    ICMP      = 0x01,
    ICMPV6    = 0x3A,
};

enum bit<10> PakcetType {
  // Rejected
  Rejected = 100,
  // Ipv4
  IPv4TCP = 101,
  IPv4UDP = 102,
  IPv4SCTP = 103,
  IPv4ICMP = 104,
  IPv4Other = 105,
  // Ipv6
  IPv6TCP = 106,
  IPv6UDP = 107,
  IPv6SCTP = 108,
  IPv6ICMP = 109,
  IPv6Other = 110,
  // VxlanIpv4
  VxlanIPv4TCP = 201,
  VxlanIPv4UDP = 202,
  VxlanIPv4SCTP = 203,
  VxlanIPv4ICMP = 204,
  VxlanIPv4Other = 205,
  // VxlanIpv6
  VxlanIPv6TCP = 206,
  VxlanIPv6UDP = 207,
  VxlanIPv6SCTP = 208,
  VxlanIPv6ICMP = 209,
  VxlanIPv6Other = 210,
  // L2
  Arp = 301;
  L2Other = 302;
}

enum bit<10> PacketGroup {
  IPv4 = 101,
  IPv6 = 102,
  VxlanIpv4 = 103,
  VxlanIpv6 = 104,
  L2 = 105,
}


#endif
