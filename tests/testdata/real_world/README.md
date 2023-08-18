# P4 programs for pipelet statistics

These programs cannot be read by the IR directly because some unsupported features are used.
We modify the program to enable the IR read. The modification does not change the pipelet numbers and pipelet length.

## switch.p4
- header_stack ==> delete
- meter_array ==> delete
- No "default_entry" in the table json, randomly copy one from other tables.
    - port_vlan_mapping
    - ecmp_group
    - lag_group
    - fabric_lag

## L2L3_ACL
This is an example used in PISCES. https://github.com/P4-vSwitch/ovs/tree/p4/include/p4/examples/l2l3_acl
- Change the intrinsic_metadata_t to make it compatible with the latest P4C.

## fabric
- meter_array ==> delete
- No "default_entry" in the table json, randomly copy one from other tables.
    - FabricIngress.next.hashed
- 'action_const' and 'action_entry_const' for default entry are not supported yet ==> change to false
- `__HIT__` and `__MISS__` ==> remapping to action_to_next_table
    - FabricEgress.dscp_rewriter.rewriter

## dash
- ['options', '*'] ==> delete in P4
- 'action_const' and 'action_entry_const' for default entry are not supported yet
- `__HIT__` and `__MISS__` ==> Rewrite P4 to workaround this
    - FabricEgress.dscp_rewriter.rewriter
- some nodes in ingress are not reachable ==> force connecting the orphan node with its predecessor.
