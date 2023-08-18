
action strip_vlan() {
    modify_field(ethernet_.etherType, vlan_.etherType);
    remove_header(vlan_);
}

table vlan_egress_proc {
    reads {
        standard_metadata.egress_spec : exact;
    }
    actions {strip_vlan; _nop;}
    size : 64;
}
