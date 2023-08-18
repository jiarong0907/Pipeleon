

table acl {
    reads {
    	ipv4_.srcAddr : ternary;
    	ipv4_.dstAddr : ternary;
    	ipv4_.protocol : ternary;
    	l4_metadata_.srcPort : ternary;
    	l4_metadata_.dstPort : ternary;
    }
    actions {_nop; _drop;}
    size : 1000;
}
