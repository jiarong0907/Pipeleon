#include "types.p4"
#include "grouping_stage/ptype_group.p4"
#include "grouping_stage/vport_group.p4"
#include <core.p4>
#include <v1model.p4>

control grouping_stage(inout headers_t headers, inout local_metadata_t local_metadata,
                inout standard_metadata_t standard_metadata) {

  ptype_group_ctrl() ptype_group;
  vport_group_ctrl() vport_group;
  apply {
    ptype_group.apply(headers, local_metadata, standard_metadata);
    vport_group.apply(headers, local_metadata, standard_metadata);
  }
}
