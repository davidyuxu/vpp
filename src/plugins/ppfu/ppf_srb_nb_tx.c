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

#define foreach_ppf_srb_nb_tx_error    \
_(ENCAPSULATED, "good packets encapsulated")

static char * ppf_srb_nb_tx_error_strings[] = {
#define _(sym,string) string,
  foreach_ppf_srb_nb_tx_error
#undef _
};

typedef enum {
#define _(sym,str) PPF_SRB_NB_TX_ERROR_##sym,
    foreach_ppf_srb_nb_tx_error
#undef _
    PPF_SRB_NB_TX_N_ERROR,
} ppf_srb_nb_tx_error_t;

typedef struct {
  ppf_srb_header_t srb;
  u32 tunnel_index;
} ppf_srb_nb_tx_trace_t;

u8 * format_ppf_srb_nb_tx_trace  (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ppf_srb_nb_tx_trace_t * t
      = va_arg (*args, ppf_srb_nb_tx_trace_t *);

  s = format (s, "PPF SRB-NB TX: srb incoming msg from sb tunnel %d \n",
	      t->tunnel_index);
  s = format (s, "  call-id %d, transaction-id %d, request-id %d, integrity_status %d, length %d \n",
              clib_net_to_host_u32(t->srb.call_id),
              clib_net_to_host_u32(t->srb.transaction_id),
              clib_net_to_host_u32(t->srb.msg.in.request_id),
              clib_net_to_host_u32(t->srb.msg.in.integrity_status),
              clib_net_to_host_u32(t->srb.msg.in.data_l));
  
  return s;
}

#define foreach_fixed_header_offset            \
    _(0) _(1) _(2) _(3) _(4) _(5)

/* Convery the signalings from SRB to PPF CP by encapsulated a defined UDP tunnel */
always_inline uword
ppf_srb_nb_tx_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * from_frame,
		    u32 is_ip4)
{
  ppf_sb_main_t *psm = &ppf_sb_main;
  ppf_gtpu_main_t *pgm = &ppf_gtpu_main;
  CLIB_UNUSED(u16 old_l0) = 0;
  u32 n_left_from, next_index, * from, * to_next;
  u32 stats_n_packets, stats_n_bytes;
  u32 next0 = PPF_SRB_NB_TX_NEXT_IP4_LOOKUP;
   
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  
  next_index = node->cached_next_index;

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
          u32 len0;
          ip4_header_t * ip4_0;
          udp_header_t * udp0;
          ppf_srb_header_t * srb0;
          u64 * copy_src0, * copy_dst0;
          u32 * copy_src_last0, * copy_dst_last0;
          u16 new_l0;
          CLIB_UNUSED(ip_csum_t sum0);
          u32 tunnel_index0;
          ppf_gtpu_tunnel_t * t0;
		  uword * p0;
          ppf_srb_msg_id_t msg0;
          
          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;
          
          b0 = vlib_get_buffer (vm, bi0);

          /* Apply the rewrite string. $$$$ vnet_rewrite? */
          vlib_buffer_advance (b0, -(word)_vec_len(psm->rewrite));
          
          ip4_0 = vlib_buffer_get_current(b0);
          
          /* Copy the fixed header */
          copy_dst0 = (u64 *) ip4_0;
          copy_src0 = (u64 *) psm->rewrite;
          
          /* Copy first 32 octets 8-bytes at a time */
          #define _(offs) copy_dst0[offs] = copy_src0[offs];
          foreach_fixed_header_offset;
          #undef _
          
          /* Last 4 octets. Hopefully gcc will be our friend */
          copy_dst_last0 = (u32 *)(&copy_dst0[4]);
          copy_src_last0 = (u32 *)(&copy_src0[4]);
          copy_dst_last0[0] = copy_src_last0[0];
          
          /* Fix the IP4 checksum and length */
		  #if 0 // fix odd ehecksum calculate issue
          sum0 = ip4_0->checksum;
          new_l0 = /* old_l0 always 0, see the rewrite setup */
            clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
          sum0 = ip_csum_update (sum0, old_l0, new_l0, ip4_header_t,
          		     length /* changed member */);
          ip4_0->checksum = ip_csum_fold (sum0);
          ip4_0->length = new_l0;
		  #else
          new_l0 = /* old_l0 always 0, see the rewrite setup */
            clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
          ip4_0->length = new_l0;
		  ip4_0->checksum = ip4_header_checksum (ip4_0);
		  #endif
          
          /* Fix UDP length and set source port */
          udp0 = (udp_header_t *)(ip4_0+1);
          new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain(vm, b0)
          			     - sizeof (*ip4_0));
          udp0->length = new_l0;

          /* Fix srb data length */
          srb0 = (ppf_srb_header_t *)(udp0+1);
          len0 = clib_host_to_net_u32 (vlib_buffer_length_in_chain(vm, b0)
                               - sizeof (*ip4_0) - sizeof(*udp0) - sizeof(*srb0));
          srb0->msg.in.data_l = len0;
          tunnel_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          t0 = pool_elt_at_index (pgm->tunnels, tunnel_index0);
          srb0->call_id = clib_host_to_net_u32(t0->call_id);

		  p0 = hash_get (ppf_main.ppf_calline_table[t0->call_id].rb.srb.nb_out_msg_by_sn, vnet_buffer2(b0)->ppf_du_metadata.pdcp.count);
		  if (PREDICT_TRUE (p0 != NULL)) {
		    msg0.as_u64 = p0[0];
			hash_unset (ppf_main.ppf_calline_table[t0->call_id].rb.srb.nb_out_msg_by_sn, vnet_buffer2(b0)->ppf_du_metadata.pdcp.count);
		  } else {
		    msg0.as_u64 = 0;
		  }

          srb0->transaction_id = clib_host_to_net_u32(msg0.transaction_id);
          srb0->msg.in.request_id = clib_host_to_net_u32(msg0.request_id);
          srb0->msg.in.integrity_status = clib_host_to_net_u32(vnet_buffer2(b0)->ppf_du_metadata.pdcp.integrity_status);

          /* counter here */
          len0 = vlib_buffer_length_in_chain (vm, b0);
          stats_n_packets += 1;
          stats_n_bytes += len0;
                      
          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
          {
            ppf_srb_nb_tx_trace_t *tr
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

  // counters, TBD
  
  return from_frame->n_vectors;
}

static uword
ppf_srb_nb_tx (vlib_main_t * vm,
	      vlib_node_runtime_t * node,
	      vlib_frame_t * from_frame)
{
  return ppf_srb_nb_tx_inline (vm, node, from_frame, /* is_ip4 */ 1);
}


VLIB_NODE_FUNCTION_MULTIARCH (ppf_srb_nb_tx_node, ppf_srb_nb_tx)

VLIB_REGISTER_NODE (ppf_srb_nb_tx_node) = {
  .function = ppf_srb_nb_tx,
  .name = "ppf_srb_nb_tx",
  .vector_size = sizeof (u32),
  .format_trace = format_ppf_srb_nb_tx_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ppf_srb_nb_tx_error_strings),
  .error_strings = ppf_srb_nb_tx_error_strings,
  .n_next_nodes = PPF_SRB_NB_TX_N_NEXT,
  .next_nodes = {
#define _(s,n) [PPF_SRB_NB_TX_NEXT_##s] = n,
    foreach_ppf_srb_nb_tx_next
#undef _
  },
};


