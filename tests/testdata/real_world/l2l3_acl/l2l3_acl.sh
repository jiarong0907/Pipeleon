#! /bin/sh -ve

# Please make sure that you update the path to the current OVS directory.
DIR=~/p4-vswitch/ovs/utilities

# For this test we will pre-populate ARP caches at the end-hosts

$DIR/ovs-ofctl --protocols=OpenFlow15 del-flows br0

# Verify Checksum (Table 0)
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=0,priority=32768,ipv4__valid=1 \
						    actions=calc_fields_verify(ipv4__hdrChecksum,csum16,fields:ipv4__version_ihl,ipv4__diffserv,ipv4__totalLen,ipv4__identification,ipv4__flags_fragOffset,ipv4__ttl,ipv4__protocol,ipv4__srcAddr,ipv4__dstAddr), \
									resubmit(,1)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=0,priority=0 actions="

# Vlan Ingress Porcessing (Table 1)
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=1,priority=32768,in_port=2,vlan__valid=1,vlan__pcp_cfi_vid=0x0001/0x0FFF, \
						    actions=set_field:1->reg1,resubmit(,2)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=1,priority=32768,in_port=5,vlan__valid=1,vlan__pcp_cfi_vid=0x0001/0x0FFF, \
						    actions=set_field:3->reg1,resubmit(,2)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=1,priority=32768,in_port=6,vlan__valid=1,vlan__pcp_cfi_vid=0x0001/0x0FFF, \
						    actions=set_field:4->reg1,resubmit(,2)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=1,priority=0,in_port=1,vlan__valid=0 \
							actions=add_header:vlan_, \
									set_field:0x0000/0x0FFF->vlan__pcp_cfi_vid, \
									move:OXM_OF_ETHERNET__ETHERTYPE[]->OXM_OF_VLAN__ETHERTYPE[], \
									set_field:0x8100->ethernet__etherType, \
									set_field:2->reg1, \
									resubmit(,2)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=1,priority=0,in_port=3,vlan__valid=0 \
							actions=add_header:vlan_, \
									set_field:0x0000/0x0FFF->vlan__pcp_cfi_vid, \
									move:OXM_OF_ETHERNET__ETHERTYPE[]->OXM_OF_VLAN__ETHERTYPE[], \
									set_field:0x8100->ethernet__etherType, \
									set_field:5->reg1, \
									resubmit(,2)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=1,priority=0,in_port=4,vlan__valid=0 \
							actions=add_header:vlan_, \
									set_field:0x0000/0x0FFF->vlan__pcp_cfi_vid, \
									move:OXM_OF_ETHERNET__ETHERTYPE[]->OXM_OF_VLAN__ETHERTYPE[], \
									set_field:0x8100->ethernet__etherType, \
									set_field:6->reg1, \
									resubmit(,2)"

# MAC Learning (Table 2)
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=2,priority=32768,ethernet__srcAddr=0x101112131415 \
							actions=resubmit(,3)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=2,priority=32768,ethernet__srcAddr=0x101112131414 \
							actions=resubmit(,3)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=2,priority=0 \
							actions=controller"

# Routable (Table 3)
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=3,priority=32768,ethernet__srcAddr=0x101112131415,ethernet__dstAddr=0x101112131414,vlan__pcp_cfi_vid=0x0001/0x0FFF \
							actions=resubmit(,4)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=3,priority=32768,ethernet__srcAddr=0x101112131414,ethernet__dstAddr=0x101112131415,vlan__pcp_cfi_vid=0x0000/0x0FFF \
							actions=resubmit(,4)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=3,priority=0 \
							actions=resubmit(,5)"

# Routing (Table 4)
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=4,priority=32768,ipv4__dstAddr=0x0A00000E/0xFFFFFF00,vlan__pcp_cfi_vid=0x0001/0x0FFF \
							actions=set_field:0x111112131415->ethernet__srcAddr, \
									set_field:0x111112131414->ethernet__dstAddr, \
									set_field:0x0000/0x0FFF->vlan__pcp_cfi_vid, \
									sub_from_field:1->ipv4__ttl, \
									resubmit(,5)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=4,priority=32768,ipv4__dstAddr=0x0A00000F/0xFFFFFF00,vlan__pcp_cfi_vid=0x0000/0x0FFF \
							actions=set_field:0x111112131414->ethernet__srcAddr, \
									set_field:0x111112131415->ethernet__dstAddr, \
									set_field:0x0001/0x0FFF->vlan__pcp_cfi_vid, \
									sub_from_field:1->ipv4__ttl, \
									resubmit(,5)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=4,priority=0 \
							actions="

# Switching (Table 5)
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=5,priority=32768,ethernet__dstAddr=0x111112131414,vlan__pcp_cfi_vid=0x0000/0x0FFF \
							actions=move:NXM_NX_REG1[]->NXM_NX_REG0[], \
									resubmit(,6)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=5,priority=32768,ethernet__dstAddr=0x111112131415,vlan__pcp_cfi_vid=0x0001/0x0FFF \
							actions=move:NXM_NX_REG1[]->NXM_NX_REG0[], \
									resubmit(,6)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=5,priority=0 \
							actions=flood"

# ACL (Table 6)
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=6,priority=32768,ipv4__srcAddr=0x0A00000F,ipv4__dstAddr=0x0A00000E,l4_metadata__srcPort=80,l4_metadata__dstPort=8080 \
							actions=resubmit(,7)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=6,priority=32768,ipv4__srcAddr=0x0A00000E,ipv4__dstAddr=0x0A00000F,l4_metadata__srcPort=8080,l4_metadata__dstPort=80 \
							actions=resubmit(,7)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=6,priority=0 \
							actions=resubmit(,7)"

# Vlan Egress Porcessing (Table 7)
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=7,priority=0,reg0=1 \
							actions=remove_header:vlan_ \
									resubmit(,8)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=7,priority=0,reg0=3 \
							actions=remove_header:vlan_ \
									resubmit(,8)"
$DIR/ovs-ofctl --protocols=OpenFlow15 add-flow br0 "table=7,priority=0,reg0=4 \
							actions=remove_header:vlan_ \
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
							actions=calc_fields_update(ipv4__hdrChecksum,csum16,fields:ipv4__version_ihl,ipv4__diffserv,ipv4__totalLen,ipv4__identification,ipv4__flags_fragOffset,ipv4__ttl,ipv4__protocol,ipv4__srcAddr,ipv4__dstAddr), \
									deparse, \
									output:NXM_NX_REG0[]"
