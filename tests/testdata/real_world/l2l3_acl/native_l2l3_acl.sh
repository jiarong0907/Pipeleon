#! /bin/sh -ve

# Please make sure that you update the path to the current OVS directory.
DIR=~/p4-vswitch/ovs/utilities

# For this test we will pre-populate ARP caches at the end-hosts

$DIR/ovs-ofctl --protocols=OpenFlow15 del-flows br0

# Verify Checksum (Table 0)
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=0,priority=0 actions=resubmit(,1)"

# Vlan Ingress Porcessing (Table 1)
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=1,priority=32768,in_port=2,dl_vlan=1 \
						    actions=set_field:1->reg1,resubmit(,2)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=1,priority=32768,in_port=5,dl_vlan=1 \
						    actions=set_field:3->reg1,resubmit(,2)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=1,priority=32768,in_port=6,dl_vlan=1 \
						    actions=set_field:4->reg1,resubmit(,2)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=1,priority=32768,in_port=1 \
							actions=push_vlan:0x8100, \
									set_field:2->reg1, \
									resubmit(,2)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=1,priority=32768,in_port=3 \
							actions=push_vlan:0x8100, \
									set_field:5->reg1, \
									resubmit(,2)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=1,priority=32768,in_port=4 \
							actions=push_vlan:0x8100, \
									set_field:6->reg1, \
									resubmit(,2)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=1,priority=0 \
							actions="

# MAC Learning (Table 2)
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=2,priority=32768,dl_src=10:11:12:13:14:15 \
							actions=resubmit(,3)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=2,priority=32768,dl_src=10:11:12:13:14:14 \
							actions=resubmit(,3)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=2,priority=0 \
							actions=controller"

# Routable (Table 3)
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=3,priority=32768,dl_src=10:11:12:13:14:15,dl_dst=10:11:12:13:14:14,dl_vlan=1 \
							actions=resubmit(,4)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=3,priority=32768,dl_src=10:11:12:13:14:14,dl_dst=10:11:12:13:14:15,dl_vlan=0 \
							actions=resubmit(,4)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=3,priority=0 \
							actions=resubmit(,5)"

# Routing (Table 4)
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=4,priority=32768,ip,nw_dst=10.0.0.14/24,dl_vlan=1 \
							actions=set_field:11:11:12:13:14:15->dl_src, \
									set_field:11:11:12:13:14:14->dl_dst, \
									mod_vlan_vid:0, \
									dec_ttl, \
									resubmit(,5)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=4,priority=32768,ip,nw_dst=10.0.0.15/24,dl_vlan=0 \
							actions=set_field:11:11:12:13:14:14->dl_src, \
									set_field:11:11:12:13:14:15->dl_dst, \
									mod_vlan_vid:1, \
									dec_ttl, \
									resubmit(,5)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=4,priority=0 \
							actions="

# Switching (Table 5)
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=5,priority=32768,dl_dst=11:11:12:13:14:14,dl_vlan=0 \
							actions=move:NXM_NX_REG1[]->NXM_NX_REG0[] \
									resubmit(,6)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=5,priority=32768,dl_dst=11:11:12:13:14:15,dl_vlan=1 \
							actions=move:NXM_NX_REG1[]->NXM_NX_REG0[] \
									resubmit(,6)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=5,priority=0 \
							actions=flood"

# ACL (Table 6)
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=6,priority=32768,nw_src=10.0.0.15,nw_dst=10.0.0.14,tcp,tp_src=80,tp_dst=8080 \
							actions=resubmit(,7)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=6,priority=32768,nw_src=10.0.0.14,nw_dst=10.0.0.15,tcp,tp_src=8080,tp_dst=80 \
							actions=resubmit(,7)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=6,priority=0 \
							actions=resubmit(,7)"

# Vlan Egress Porcessing (Table 7)
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=7,priority=32768,reg0=1,dl_vlan=0,vlan_tci=0x1000/0x1fff \
							actions=strip_vlan, \
									resubmit(,8)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=7,priority=32768,reg0=3,dl_vlan=0,vlan_tci=0x1000/0x1fff \
							actions=strip_vlan, \
									resubmit(,8)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=7,priority=32768,reg0=4,dl_vlan=0,vlan_tci=0x1000/0x1fff \
							actions=strip_vlan, \
									resubmit(,8)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=7,priority=0 \
							actions=resubmit(,8)"

# MCast Src Prunning (Table 8)
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=8,priority=32768,in_port=1,reg0=1 actions="
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=8,priority=32768,in_port=2,reg0=2 actions="
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=8,priority=32768,in_port=3,reg0=3 actions="
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=8,priority=32768,in_port=4,reg0=4 actions="
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=8,priority=32768,in_port=5,reg0=5 actions="
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=8,priority=32768,in_port=6,reg0=6 actions="
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=8,priority=0 \
							actions=resubmit(,9)"

# Update Checksum, Deparse, and Send Packet (Table 9)
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=9,priority=0 \
							actions=output:NXM_NX_REG0[]"
