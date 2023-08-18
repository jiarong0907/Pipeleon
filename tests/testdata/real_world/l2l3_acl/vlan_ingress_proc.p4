
action add_vlan() {
    add_header(vlan_);
    modify_field(vlan_.etherType, ethernet_.etherType);
    modify_field(ethernet_.etherType, ETHERTYPE_VLAN);
}

table vlan_ingress_proc {
    reads {
    	standard_metadata.ingress_port : exact;
    	vlan_ 	  					   : valid;
        vlan_.vid 					   : exact;
    }
    actions {add_vlan; _nop;}
    size : 64;
}
