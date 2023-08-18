
field_list mac_learn_digest {
    standard_metadata.ingress_port;
    ethernet_.srcAddr;
	vlan_.vid;
}

action mac_learn() {
    generate_digest(MAC_LEARN_RECEIVER, mac_learn_digest);
}

table mac_learning {
    reads {
        ethernet_.srcAddr : exact;
    }
    actions {mac_learn; _nop;}
    size : 4000;
}
