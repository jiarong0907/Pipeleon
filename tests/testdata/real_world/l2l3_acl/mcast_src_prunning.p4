
table mcast_src_pruning {
    reads {
        standard_metadata.instance_type : exact;
    }
    actions {_nop; _drop;}
    size : 1;
}
