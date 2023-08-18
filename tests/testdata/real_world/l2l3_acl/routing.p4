
field_list ipv4_checksum_list {
        ipv4_.version;
        ipv4_.ihl;
        ipv4_.diffserv;
        ipv4_.totalLen;
        ipv4_.identification;
        ipv4_.flags;
        ipv4_.fragOffset;
        ipv4_.ttl;
        ipv4_.protocol;
        ipv4_.srcAddr;
        ipv4_.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4_.hdrChecksum  {
    verify ipv4_checksum if(ipv4_.ihl == 5);
    update ipv4_checksum if(ipv4_.ihl == 5);
}

action set_nhop(smac, dmac, vid) {
	modify_field(ethernet_.srcAddr, smac);
	modify_field(ethernet_.dstAddr, dmac);
	modify_field(vlan_.vid, vid);
    add_to_field(ipv4_.ttl, -1);
}

table routing {
    reads {
        ipv4_.dstAddr : lpm;
    }
    actions {set_nhop; _drop;}
    size: 2000;
}
