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
#include <ppfu/ppf_gtpu.h>

/* Statistics (not all errors) */
#define foreach_ppf_srb_nb_rx_error    \
_(GOOD, "Good srb outgoing packets")   \
_(INVALID_DST, "Unknown destination")   \
_(INVALID_SRC, "Unknown source")	\
_(NO_SUCH_CALL, "No such call packets")	


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
  ppf_srb_header_t srb;
  u32 tunnel_index;
} ppf_srb_nb_rx_trace_t;

u8 * format_ppf_srb_nb_rx_trace  (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ppf_srb_nb_rx_trace_t * t
      = va_arg (*args, ppf_srb_nb_rx_trace_t *);

  s = format (s, "PPF SRB-NB RX: srb outgoing msg received for the call %d \n",
	      clib_net_to_host_u32(t->srb.call_id));
  s = format (s, "  transaction-id %d, request-id %d, sb_num %d, sb_id %d %d %d, length %d",
              clib_net_to_host_u32(t->srb.transaction_id),
              clib_net_to_host_u32(t->srb.msg.out.request_id),
              t->srb.msg.out.sb_num,
              t->srb.msg.out.sb_id[0], t->srb.msg.out.sb_id[1], t->srb.msg.out.sb_id[2],
              clib_net_to_host_u32(t->srb.msg.out.data_l));
  s = format (s, "  outgoing sb tunnel %d \n", t->tunnel_index);

  return s;
}

always_inline uword
ppf_srb_nb_rx_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * from_frame,
		    u32 is_ip4)
{
  u32 n_left_from, next_index, * from, * to_next;
  ppf_main_t *pm = &ppf_main;
  ppf_sb_main_t *psm = &ppf_sb_main;
  ppf_pdcp_main_t *ppm = &ppf_pdcp_main;
  CLIB_UNUSED(vnet_main_t * vnm) = psm->vnet_main;
  u32 stats_n_packets, stats_n_bytes;
    
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  
  next_index = psm->srb_rx_next_index;
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
          ppf_callline_t * c0;
          ppf_pdcp_session_t * pdcp0;
          uword key0;
          CLIB_UNUSED(ppf_srb_msg_id_t msg0);
          u32 tunnel_index0;
          u32 error0;
          u32 len0;
                    
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

          /* Validate UDP tunnel SIP against packet DIP */
          if (PREDICT_FALSE (ip4_0->src_address.as_u32 != psm->dst)) {
            error0 = PPF_SRB_NB_RX_ERROR_INVALID_SRC;
            next0 = PPF_SRB_NB_RX_NEXT_DROP;
            goto trace0;
          }
	  
          /* Manipulate packet 0 */

          /* Find callline */
          c0 = &(pm->ppf_calline_table[clib_net_to_host_u32(srb0->call_id)]);

          /* Save transaction-id and request-id in callline */
          /* Generate PDCP SN, map <PDCP SN> to <transaction-id + request-id> */
          pdcp0 = pool_elt_at_index(ppm->sessions, c0->pdcp.session_id);
          key0 = (uword)PPF_PDCP_COUNT (pdcp0->tx_hfn, pdcp0->tx_next_sn, pdcp0->sn_length);

          /* Set pdcp-info in buffer */
          vnet_buffer2(b0)->ppf_du_metadata.pdcp.count = (u32)key0;	  
          vnet_buffer2(b0)->ppf_du_metadata.pdcp.sn = pdcp0->tx_next_sn;

          /* Sequence advance */
		  PPF_PDCP_COUNT_INC (pdcp0->tx_hfn, pdcp0->tx_next_sn, pdcp0->sn_length);
	  
          if (psm->want_feedback) {
            msg0.transaction_id = clib_net_to_host_u32(srb0->transaction_id);
            msg0.request_id = clib_net_to_host_u32(srb0->msg.out.request_id);
            hash_set (c0->rb.srb.nb_out_msg_by_sn, key0, msg0.as_u64);
          }
          
          /* Determine downlink tunnel */
                    
          /* Pop gtpu header */
          vlib_buffer_advance (b0, sizeof(ppf_srb_header_t));
          
          /* Determine next node */
          if (PREDICT_TRUE(1 == srb0->msg.out.sb_num)) {
            tunnel_index0 = c0->rb.srb.sb_tunnel[srb0->msg.out.sb_id[0]].tunnel_id;	    
            
            /* Set tunnel-id in buffer */
            vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tunnel_index0;	    
            
            next0 = PPF_SB_PATH_LB_NEXT_PPF_PDCP_ENCRYPT;
          } else {
            /* Set call-id in buffer */
            vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = srb0->call_id;
            
            /* Set path-info in buffer */
            vnet_buffer2(b0)->ppf_du_metadata.path.sb_num = srb0->msg.out.sb_num;
            clib_memcpy (vnet_buffer2(b0)->ppf_du_metadata.path.sb_id, srb0->msg.out.sb_id, 3);
            
            next0 = PPF_SRB_NB_RX_NEXT_PPF_SB_PATH_LB;
          }
	  
          /* Counter here */
          len0 = vlib_buffer_length_in_chain (vm, b0);
          stats_n_packets += 1;
          stats_n_bytes += len0;
                    
          trace0:
          b0->error = error0 ? node->errors[error0] : 0;
          
          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
          {
            ppf_srb_nb_rx_trace_t *tr
              = vlib_add_trace (vm, node, b0, sizeof (*tr));
            tr->tunnel_index = tunnel_index0;
            clib_memcpy (&tr->srb, srb0, sizeof (*srb0));
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


