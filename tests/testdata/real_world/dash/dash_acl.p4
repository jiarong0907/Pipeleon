#ifndef _SIRIUS_ACL_P4_
#define _SIRIUS_ACL_P4_

#include "dash_headers.p4"


/*
 * This control results in a new set of tables every time
 * it is applied, i. e. inbound ACL tables are different
 * from outbound, and API will be generated for each of them
 */
control acl(inout headers_t hdr,
            inout metadata_t meta,
            inout standard_metadata_t standard_metadata)
{
    action permit() {}
    action permit_and_continue() {}
    action deny() {meta.dropped = true;}
    action deny_and_continue() {meta.dropped = true;}

    table acl_stage1 {
        key = {
            meta.stage1_dash_acl_group_id : exact;
            meta.dst_ip_addr : ternary;
            meta.src_ip_addr : ternary;
            meta.ip_protocol : ternary;
            hdr.tcp.src_port : range;
            hdr.tcp.dst_port : range;
        }
        actions = {
            permit;
            permit_and_continue;
            deny;
            deny_and_continue;
        }
        default_action = deny;
    }

    table acl_stage2 {
        key = {
            meta.stage2_dash_acl_group_id : exact;
            meta.dst_ip_addr : ternary;
            meta.src_ip_addr : ternary;
            meta.ip_protocol : ternary;
            hdr.tcp.src_port : range;
            hdr.tcp.dst_port : range;
        }
        actions = {
            permit;
            permit_and_continue;
            deny;
            deny_and_continue;
        }
        default_action = deny;
    }

    table acl_stage3 {
        key = {
            meta.stage3_dash_acl_group_id : exact;
            meta.dst_ip_addr : ternary;
            meta.src_ip_addr : ternary;
            meta.ip_protocol : ternary;
            hdr.tcp.src_port : range;
            hdr.tcp.dst_port : range;
        }
        actions = {
            permit;
            permit_and_continue;
            deny;
            deny_and_continue;
        }
        default_action = deny;
    }

    apply {
        acl_stage1.apply();
        acl_stage2.apply();
        acl_stage3.apply();
    }
}
#endif /* _SIRIUS_ACL_P4_ */
