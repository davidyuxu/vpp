/*
 * Copyright (c) 2017 Intel and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <ppfu/ppfu.h>

/* Statistics (not all errors) */
#define foreach_ppf_srb_nb_rx_error    \
_(INVALID_DST, "Unknown destination")   \
_(INVALID_SRC, "Unknown source")	\
_(NO_SUCH_CALL, "No such call packets")	\
_(GOOD, "Good srb outgoing packets")


static char * ppf_srb_nb_rx_error_strings[] = {
#define _(sym,string) string,
  foreach_ppf_srb_nb_rx_error
#undef _
};

typedef enum {
#define _(sym,str) PPF_SRB_NB_RX_ERROR_##sym,
    foreach_ppf_srb_nb_rx_error
#undef _
    PPF_SRB_NB_RX_N_ERROR,
} ppf_srb_nb_rx_error_t;


typedef struct {
  u32 tunnel_index;
} ppf_srb_nb_rx_trace_t;

u8 * format_ppf_srb_nb_rx_trace  (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  return s;
}

always_inline uword
ppf_srb_nb_rx_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * from_frame,
		    u32 is_ip4)
{
  u32 n_left_from, next_index, * from, * to_next;
  ppf_sb_main_t *psm = &ppf_sb_main;
  vnet_main_t * vnm = psm->vnet_main;
  vnet_interface_main_t * im = &vnm->interface_main;
  u32 pkts_decapsulated = 0;
  u32 thread_index = vlib_get_thread_index();
  u32 stats_sw_if_index, stats_n_packets, stats_n_bytes;
  
  if (is_ip4)
    last_key4.as_u64 = ~0;
  else
    memset (&last_key6, 0xff, sizeof (last_key6));
  
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  
  next_index = node->cached_next_index;
  stats_sw_if_index = node->runtime_data[0];
  stats_n_packets = stats_n_bytes = 0;
  
  while (n_left_from > 0)
    {
      u32 n_left_to_next;
  
      vlib_get_next_frame (vm, node, next_index,
  			 to_next, n_left_to_next);
      
      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi0;
          vlib_buffer_t * b0;
          u32 next0;
          ip4_header_t * ip4_0;
          ppf_srb_header_t * srb0;
          u32 srb_hdr_len0 = 0;
          uword * p0;
          u32 tunnel_index0;
          ppf_gtpu_tunnel_t * t0;
          u32 error0;
          u32 sw_if_index0, len0;
                    
          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_to_next -= 1;
          n_left_from -= 1;
          
          b0 = vlib_get_buffer (vm, bi0);
          
          /* udp leaves current_data pointing at the srb header */
          srb0 = vlib_buffer_get_current (b0);

          vlib_buffer_advance
          (b0, -(word)(sizeof(udp_header_t)+sizeof(ip4_header_t)));
          ip4_0 = vlib_buffer_get_current (b0);
          
          /* pop (ip, udp, srb) */
          vlib_buffer_advance
          (b0, sizeof(*ip4_0)+sizeof(udp_header_t));
          
          tunnel_index0 = ~0;
          error0 = 0;
                             
          /* Validate UDP tunnel SIP against packet DIP */
          if (PREDICT_FALSE (ip4_0->dst_address.as_u32 != psm->src)) {
            error0 = PPF_SRB_NB_RX_ERROR_INVALID_DST;
            next0 = PPF_SRB_NB_RX_NEXT_DROP;
            goto trace0;
          }

          /* Manipulate packet 0 */

	  /* Find callline */
	  // srb_call = ppf_callline[srb0->call_id];

          /* Save transaction-id and request-id in callline */
	  /* Generate PDCP SN, map <PDCP SN> to <transaction-id + request-id> */
	  // TBD

	  /* Determine downlink tunnel */
	  // tunnel_index0 = srb_call->tunnel_index;
	  
          t0 = pool_elt_at_index (ppf_gtpu_main.tunnels, tunnel_index0);
                    
          /* Pop gtpu header */
          vlib_buffer_advance (b0, sizeof(ppf_srb_header_t));
          
          /* Determine next node */
	  next0 = PPF_SRB_NB_RX_NEXT_PDCP//PDCP-ENCAP;
          sw_if_index0 = t0->sw_if_index;
          len0 = vlib_buffer_length_in_chain (vm, b0);
          
          /* Set packet input sw_if_index to unicast GTPU tunnel for learning */
          vnet_buffer(b0)->sw_if_index[VLIB_RX] = tunnel_index0;
          
          pkts_decapsulated ++;
          stats_n_packets += 1;
          stats_n_bytes += len0;
                    
          trace0:
          b0->error = error0 ? node->errors[error0] : 0;
          
          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
          {
            ppf_srb_nb_rx_trace_t *tr
              = vlib_add_trace (vm, node, b0, sizeof (*tr));
	    // TBD
          }
                    
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
          			 to_next, n_left_to_next,
          			 bi0, next0);
        }
    
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  
  return from_frame->n_vectors;
}

static uword
ppf_srb_nb_rx (vlib_main_t * vm,
	      vlib_node_runtime_t * node,
	      vlib_frame_t * from_frame)
{
  return ppf_srb_nb_rx_inline (vm, node, from_frame, /* is_ip4 */ 1);
}


VLIB_NODE_FUNCTION_MULTIARCH (ppf_srb_nb_rx_node, ppf_srb_nb_rx)

VLIB_REGISTER_NODE (ppf_srb_nb_rx_node) = {
  .function = ppf_srb_nb_rx,
  .name = "ppf_srb_nb_rx",
  .vector_size = sizeof (u32),
  .format_trace = format_ppf_srb_nb_rx_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ppf_srb_nb_rx_error_strings),
  .error_strings = ppf_srb_nb_rx_error_strings,
  .n_next_nodes = PPF_SRB_NB_RX_N_NEXT,
  .next_nodes = {
#define _(s,n) [PPF_SRB_NB_RX_NEXT_##s] = n,
    foreach_ppf_srb_nb_rx_next
#undef _
  },
};


