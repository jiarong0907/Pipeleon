#include "encap.p4"
#include "unencap.p4"
#include "parser_fix_stage/encap.p4"
#include "parser_fix_stage/unencap.p4"
#include "dash_headers.p4"
#include <core.p4>
#include <v1model.p4>

control parser_fix_stage(inout headers_t headers, inout local_metadata_t local_metadata,
                inout standard_metadata_t standard_metadata) {

  action set_ptype_control_unencap() {
  }
  action set_ptype_control_encap() {
  }

  table packet_type {
    key = {
      headers.vxlan.isValid() : exact;
    }
    actions = {
       set_ptype_control_encap;
       set_ptype_control_unencap;
    }
    default_action = set_ptype_control_unencap();

    const entries = {
       (0) :
               set_ptype_control_unencap();
       (1) :
               set_ptype_control_unencap();
      }

   }

   unencap() unencap_process;
   encap() encap_process;

   apply {
     switch(packet_type.apply().action_run) {
       set_ptype_control_encap: {
         encap_process.apply(headers, local_metadata, standard_metadata);
        }
       set_ptype_control_unencap: {
         unencap_process.apply(headers, local_metadata, standard_metadata);
        }
     }
   }
}
