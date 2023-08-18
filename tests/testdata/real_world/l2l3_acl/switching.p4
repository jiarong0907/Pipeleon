
action forward(port) {
    modify_field(standard_metadata.egress_spec, port);
}

action broadcast() {
    modify_field(intrinsic_metadata.egress_rid, 1);
}

table switching {
    reads {
        ethernet_.dstAddr : exact;
        vlan_.vid         : exact;
    }
    actions {forward; broadcast;}
    size : 4000;
}
