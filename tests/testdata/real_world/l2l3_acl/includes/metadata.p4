
header_type intrinsic_metadata_t {
    fields {
        mcast_grp : 4;
        egress_rid : 16;
    }
}

metadata intrinsic_metadata_t intrinsic_metadata;


header_type l4_metadata_t {
    fields {
        srcPort : 16;
        dstPort : 16;
    }
}

metadata l4_metadata_t l4_metadata_;
