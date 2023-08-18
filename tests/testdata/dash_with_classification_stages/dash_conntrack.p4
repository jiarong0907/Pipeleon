#ifndef _SIRIUS_CONNTRACK_P4_
#define _SIRIUS_CONNTRACK_P4_

#include "dash_headers.p4"

#ifdef PNA_CONNTRACK

#include "pna.p4"

const ExpireTimeProfileId_t EXPIRE_TIME_PROFILE_NOW    = (ExpireTimeProfileId_t) 0;
const ExpireTimeProfileId_t EXPIRE_TIME_PROFILE_LONG   = (ExpireTimeProfileId_t) 2;

IPv4Address directionNeutralAddr (
    in direction_t direction,
    in IPv4Address outbound_address,
    in IPv4Address inbound_address)
{
    if (direction == direction_t.OUTBOUND) {
        return outbound_address;
    } else {
        return inbound_address;
    }
}

bit<16> directionNeutralPort (
    in direction_t direction,
    in bit<16> outbound_port,
    in bit<16> inbound_port)
{
    if (direction == direction_t.OUTBOUND) {
        return outbound_port;
    } else {
        return inbound_port;
    }
}


control ConntrackIn(inout headers_t hdr,
                inout metadata_t meta)
{
  action conntrackIn_allow () {
  /* Invalidate entry based on TCP flags */
          if (hdr.tcp.flags & 0x101 /* FIN/RST */) {
            set_entry_expire_time(EXPIRE_TIME_PROFILE_NOW); // New PNA extern
            /* set entry to be purged */
          }
          restart_expire_timer(); // reset expiration timer for entry
          meta.conntrack_data.allow_in = true;
  }

  action conntrackIn_miss() {
          if (hdr.tcp.flags == 0x2 /* SYN */) {
            if (meta.direction == direction_t.OUTBOUND) {
               add_entry("conntrackIn_allow"); // New PNA Extern
               //adding failiure to be eventually handled
               set_entry_expire_time(EXPIRE_TIME_PROFILE_LONG);
            }
          }
  }

  table conntrackIn {
      key = {
          directionNeutralAddr(meta.direction, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr):
              exact;
          directionNeutralAddr(meta.direction, hdr.ipv4.dstAddr, hdr.ipv4.srcAddr):
              exact;
          hdr.ipv4.protocol : exact;
          directionNeutralPort(meta.direction, hdr.tcp.srcPort, hdr.tcp.dstPort):
              exact;
          directionNeutralPort(meta.direction, hdr.tcp.dstPort, hdr.tcp.srcPort):
              exact;
          meta.eni : exact;
      }
      actions = {
          conntrackIn_allow;
          conntrackIn_miss;
      }

      add_on_miss = true; //New PNA property

      idle_timeout_with_auto_delete = true; // New PNA property
      const default_action = conntrackIn_miss; //New PNA property
  }

  apply{conntrackIn.apply();}
}


control ConntrackOut(inout headers_t hdr,
                inout metadata_t meta)
{
  action conntrackOut_allow () {
  /* Invalidate entry based on TCP flags */
          if (hdr.tcp.flags & 0x101 /* FIN/RST */) {
            set_entry_expire_time(EXPIRE_TIME_PROFILE_NOW); // New PNA extern
            /* set entry to be purged */
          }
          restart_expire_timer(); // reset expiration timer for entry
          meta.conntrack_data.allow_out = true;
  }

  action conntrackOut_miss() {
          if (hdr.tcp.flags == 0x2 /* SYN */) {
            if (meta.direction == direction_t.INBOUND) {
               add_entry("ConntrackOut_allow"); // New PNA Extern
               //adding failiure to be eventually handled
               set_entry_expire_time(EXPIRE_TIME_PROFILE_LONG);
            }
          }
  }

  table conntrackOut {
      key = {
          directionNeutralAddr(meta.direction, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr):
              exact;
          directionNeutralAddr(meta.direction, hdr.ipv4.dstAddr, hdr.ipv4.srcAddr):
              exact;
          hdr.ipv4.protocol : exact;
          directionNeutralPort(meta.direction, hdr.tcp.srcPort, hdr.tcp.dstPort):
              exact;
          directionNeutralPort(meta.direction, hdr.tcp.dstPort, hdr.tcp.srcPort):
              exact;
          meta.eni : exact;
      }
      actions = {
          conntrackOut_allow;
          conntrackOut_miss;
      }

      add_on_miss = true; //New PNA property

      idle_timeout_with_auto_delete = true; // New PNA property
      const default_action = conntrackOut_miss; //New PNA property
  }
  apply {conntrackOut.apply();}
}

#endif // PNA_CONNTRACK


#ifdef STATEFUL_P4

state_context ConntrackCtx {
}

state_graph ConnGraphOut(inout state_context flow_ctx,
                             in headers_t headers,
                             in standard_metadata_t standard_metadata)
{
    state START {
        /* Only for new connections */
        if (!headers.tcp.isValid() || headers.tcp.flags != 0x2 /* SYN */) {
            return;
        }

        if (meta.direction == direction_t.INBOUND) {
            transition ALLOW;
        }
    }

    state ALLOW {
        meta.conntrack_data.allow_out = true;

        /* Remove connection based on TCP flags */
        if (headers.tcp.flags & 0x101 /* FIN/RST */) {
            transition START;
        }
    }
}

state_graph ConnGraphIn(inout state_context flow_ctx,
                             in headers_t headers,
                             in standard_metadata_t standard_metadata)
{
    state START {
        /* Only for new connections */
        if (!headers.tcp.isValid() || headers.tcp.flags != 0x2 /* SYN */) {
            return;
        }

        if (meta.direction == direction_t.OUTBOUND) {
            transition ALLOW;
        }
    }

    state ALLOW {
        meta.conntrack_data.allow_in = true;

        /* Remove connection based on TCP flags */
        if (headers.tcp.flags & 0x101 /* FIN/RST */) {
            transition START;
        }
    }
}

state_table ConntrackOut
{
    flow_key[0] = {hdr.ipv4.src, hdr.ipv4.dst , hdr.ipv4.proto, hdr.l4.src_port, hdr.l4.dst_port, meta.eni};
    flow_key[1] = {hdr.ipv4.dst, hdr.ipv4.src , hdr.ipv4.proto, hdr.l4.dst_port, hdr.l4.src_port, meta.eni};
    eviction_policy = LRU;
    context = ConntrackCtx;
    graph = ConnGraphOut(ConntrackCtx, hdr, standard_metadata);
}

state_table ConntrackIn
{
    flow_key[0] = {hdr.ipv4.src, hdr.ipv4.dst , hdr.ipv4.proto, hdr.l4.src_port, hdr.l4.dst_port, meta.eni};
    flow_key[1] = {hdr.ipv4.dst, hdr.ipv4.src , hdr.ipv4.proto, hdr.l4.dst_port, hdr.l4.src_port, meta.eni};
    eviction_policy = LRU;
    context = ConntrackCtx;
    graph = ConnGraphIn(ConntrackCtx, hdr, standard_metadata);
}

#endif /* STATEFUL_P4 */

#endif /* _SIRIUS_CONNTRACK_P4_ */
