#ifndef __STAGE_1_VPORT_GROUP_P4
#define __STAGE_1_VPORT_GROUP_P4

control vport_group_ctrl(inout headers_t headers, inout local_metadata_t local_metadata,
                inout standard_metadata_t standard_metadata) {
  action set_vport_group(bit<11> vport_group) {
    local_metadata.pipeline_meta.vport_group = vport_group;
  }

  table port_attrib_tbl {
    key = {
      local_metadata.common_meta.flags_meta.direction : exact;
      local_metadata.common_meta.vport : exact;
    }
    actions = {
      set_vport_group;
    }
    size = 1024;
  }

  apply {
   port_attrib_tbl.apply();
  }
}
#endif
