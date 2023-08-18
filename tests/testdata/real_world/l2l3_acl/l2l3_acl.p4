
#include "includes/defines.p4"
#include "includes/headers.p4"
#include "includes/metadata.p4"
#include "includes/parsers.p4"
#include "includes/actions.p4"

#include "vlan_ingress_proc.p4"
#include "mac_learning.p4"
#include "routable.p4"
#include "switching.p4"
#include "routing.p4"
#include "acl.p4"
#include "vlan_egress_proc.p4"
#include "mcast_src_prunning.p4"

/* Control-Flow */
control ingress {
	apply(vlan_ingress_proc);
	apply(mac_learning);
	apply(routable) {
		route {
			apply(routing);
		}
	}
	apply(switching);
	apply(acl);
	apply(vlan_egress_proc);

	if(standard_metadata.ingress_port == standard_metadata.egress_spec) {
        apply(mcast_src_pruning);
    }
}
