
action route() {
}

table routable {
    reads {
    	ethernet_.srcAddr : exact;
        ethernet_.dstAddr : exact;
        vlan_.vid         : exact;
    }
    actions {route; _nop;}
    size : 64;
}
