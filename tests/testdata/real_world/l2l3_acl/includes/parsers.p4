
parser start {
    return parse_ethernet;
}

parser parse_ethernet {
    extract(ethernet_);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        ETHERTYPE_VLAN : parse_vlan;
        default: ingress;
    }
}

parser parse_vlan {
    extract(vlan_);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}

parser parse_ipv4 {
    extract(ipv4_);
    return select(latest.ihl, latest.protocol) {
        IP_PROTOCOLS_IPHL_TCP  : parse_tcp;
        IP_PROTOCOLS_IPHL_UDP  : parse_udp;
        default: ingress;
    }
}

parser parse_tcp {
    extract(tcp_);
    set_metadata(l4_metadata_.srcPort, tcp_.srcPort);
    set_metadata(l4_metadata_.dstPort, tcp_.dstPort);
    return ingress;
}

parser parse_udp {
    extract(udp_);
    set_metadata(l4_metadata_.srcPort, udp_.srcPort);
    set_metadata(l4_metadata_.dstPort, udp_.dstPort);
    return ingress;
}
