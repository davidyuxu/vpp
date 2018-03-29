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
              t->srb.call_id, t->srb.transaction_id, t->srb.msg.in.request_id, t->srb.msg.in.integrity_status,
              t->srb.msg.in.data_l);
  
  return s;
}

#define foreach_fixed_header4_offset            \
    _(0) _(1) _(2) _(3)

/* Convery the signalings from SRB to PPF CP by encapsulated a defined UDP tunnel */
always_inline uword
ppf_srb_nb_tx_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * from_frame,
		    u32 is_ip4)
{
  ppf_sb_main_t *psm = &ppf_sb_main;
  u16 old_l0 = 0, old_l1 = 0, old_l2 = 0, old_l3 = 0;
  u32 n_left_from, next_index, * from, * to_next;
  u32 stats_n_packets, stats_n_bytes;
  u32 next0 = 0, next1 = 0, next2 = 0, next3 = 0;
   
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  
  next0 = next1 = next2 = next3 = PPF_SRB_NB_TX_NEXT_IP4_LOOKUP;
  next_index = node->cached_next_index;

  stats_n_packets = stats_n_bytes = 0;
  
  while (n_left_from > 0)
    {
      u32 n_left_to_next;
  
      vlib_get_next_frame (vm, node, next_index,
  			 to_next, n_left_to_next);
      
      while (n_left_from >= 4 && n_left_to_next >= 2)
        {
          u32 bi0, bi1, bi2, bi3;
          vlib_buffer_t * b0, * b1, * b2, * b3;
	  u32 len0, len1, len2, len3;
          ip4_header_t * ip4_0, * ip4_1, * ip4_2, * ip4_3;
          udp_header_t * udp0, * udp1, * udp2, * udp3;
          ppf_srb_header_t * srb0, * srb1, * srb2, * srb3;
          u64 * copy_src0, * copy_dst0;
          u64 * copy_src1, * copy_dst1;
          u64 * copy_src2, * copy_dst2;
          u64 * copy_src3, * copy_dst3;
          u32 * copy_src_last0, * copy_dst_last0;
          u32 * copy_src_last1, * copy_dst_last1;
          u32 * copy_src_last2, * copy_dst_last2;
          u32 * copy_src_last3, * copy_dst_last3;
          u16 new_l0, new_l1, new_l2, new_l3;
          ip_csum_t sum0, sum1, sum2, sum3;
          
          /* Prefetch next iteration. */
          {
            vlib_buffer_t * p4, * p5, * p6, * p7;
                  
            p4 = vlib_get_buffer (vm, from[4]);
            p5 = vlib_get_buffer (vm, from[5]);
            p6 = vlib_get_buffer (vm, from[6]);
            p7 = vlib_get_buffer (vm, from[7]);
                  
            vlib_prefetch_buffer_header (p4, LOAD);
            vlib_prefetch_buffer_header (p5, LOAD);
            vlib_prefetch_buffer_header (p6, LOAD);
            vlib_prefetch_buffer_header (p7, LOAD);
                  
            CLIB_PREFETCH (p4->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
            CLIB_PREFETCH (p5->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
            CLIB_PREFETCH (p6->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
            CLIB_PREFETCH (p7->data, 2*CLIB_CACHE_LINE_BYTES, LOAD);
          }
          
          bi0 = from[0];
          bi1 = from[1];
          bi2 = from[2];
          bi3 = from[3];
          to_next[0] = bi0;
          to_next[1] = bi1;
          to_next[2] = bi2;
          to_next[3] = bi3;
          from += 4;
          to_next += 4;
          n_left_to_next -= 4;
          n_left_from -= 4;
          
          b0 = vlib_get_buffer (vm, bi0);
          b1 = vlib_get_buffer (vm, bi1);
          b2 = vlib_get_buffer (vm, bi2);
          b3 = vlib_get_buffer (vm, bi3);
                     
          /* Apply the rewrite string. $$$$ vnet_rewrite? */
          vlib_buffer_advance (b0, -(word)_vec_len(psm->rewrite));
          vlib_buffer_advance (b1, -(word)_vec_len(psm->rewrite));
          vlib_buffer_advance (b2, -(word)_vec_len(psm->rewrite));
          vlib_buffer_advance (b3, -(word)_vec_len(psm->rewrite));
          
          ip4_0 = vlib_buffer_get_current(b0);
          ip4_1 = vlib_buffer_get_current(b1);
          ip4_2 = vlib_buffer_get_current(b2);
          ip4_3 = vlib_buffer_get_current(b3);
          
          /* Copy the fixed header */
          copy_dst0 = (u64 *) ip4_0;
          copy_src0 = (u64 *) psm->rewrite;
          copy_dst1 = (u64 *) ip4_1;
          copy_src1 = (u64 *) psm->rewrite;
          copy_dst2 = (u64 *) ip4_2;
          copy_src2 = (u64 *) psm->rewrite;
          copy_dst3 = (u64 *) ip4_3;
          copy_src3 = (u64 *) psm->rewrite;
          
          /* Copy first 32 octets 8-bytes at a time */
          #define _(offs) copy_dst0[offs] = copy_src0[offs];
          foreach_fixed_header4_offset;
          #undef _
          #define _(offs) copy_dst1[offs] = copy_src1[offs];
          foreach_fixed_header4_offset;
          #undef _
          #define _(offs) copy_dst2[offs] = copy_src2[offs];
          foreach_fixed_header4_offset;
          #undef _
          #define _(offs) copy_dst3[offs] = copy_src3[offs];
          foreach_fixed_header4_offset;
          #undef _
	  
          /* Last 4 octets. Hopefully gcc will be our friend */
          copy_dst_last0 = (u32 *)(&copy_dst0[4]);
          copy_src_last0 = (u32 *)(&copy_src0[4]);
          copy_dst_last0[0] = copy_src_last0[0];
          copy_dst_last1 = (u32 *)(&copy_dst1[4]);
          copy_src_last1 = (u32 *)(&copy_src1[4]);
          copy_dst_last1[0] = copy_src_last1[0];
          copy_dst_last2 = (u32 *)(&copy_dst2[4]);
          copy_src_last2 = (u32 *)(&copy_src2[4]);
          copy_dst_last2[0] = copy_src_last2[0];
          copy_dst_last3 = (u32 *)(&copy_dst3[4]);
          copy_src_last3 = (u32 *)(&copy_src3[4]);
          copy_dst_last3[0] = copy_src_last3[0];
          
          /* Fix the IP4 checksum and length */
          sum0 = ip4_0->checksum;
          new_l0 = /* old_l0 always 0, see the rewrite setup */
            clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
          sum0 = ip_csum_update (sum0, old_l0, new_l0, ip4_header_t,
          		       length /* changed member */);
          ip4_0->checksum = ip_csum_fold (sum0);
          ip4_0->length = new_l0;
	  
          sum1 = ip4_1->checksum;
          new_l1 = /* old_l1 always 0, see the rewrite setup */
            clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b1));
          sum1 = ip_csum_update (sum1, old_l1, new_l1, ip4_header_t,
          		       length /* changed member */);
          ip4_1->checksum = ip_csum_fold (sum1);
          ip4_1->length = new_l1;
	  
          sum2 = ip4_2->checksum;
          new_l2 = /* old_l0 always 0, see the rewrite setup */
            clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b2));
          sum2 = ip_csum_update (sum2, old_l2, new_l2, ip4_header_t,
          		       length /* changed member */);
          ip4_2->checksum = ip_csum_fold (sum2);
          ip4_2->length = new_l2;
	  
          sum3 = ip4_3->checksum;
          new_l3 = /* old_l1 always 0, see the rewrite setup */
            clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b3));
          sum3 = ip_csum_update (sum3, old_l3, new_l3, ip4_header_t,
          		       length /* changed member */);
          ip4_3->checksum = ip_csum_fold (sum3);
          ip4_3->length = new_l3;
          
          /* Fix UDP length and set source port */
          udp0 = (udp_header_t *)(ip4_0+1);
          new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain(vm, b0)
          			       - sizeof (*ip4_0));
          udp0->length = new_l0;
          //udp0->src_port = flow_hash0;
          
          udp1 = (udp_header_t *)(ip4_1+1);
          new_l1 = clib_host_to_net_u16 (vlib_buffer_length_in_chain(vm, b1)
          			       - sizeof (*ip4_1));
          udp1->length = new_l1;
          //udp1->src_port = flow_hash1;

	  udp2 = (udp_header_t *)(ip4_2+1);
          new_l2 = clib_host_to_net_u16 (vlib_buffer_length_in_chain(vm, b2)
          			       - sizeof (*ip4_2));
          udp2->length = new_l2;
          //udp2->src_port = flow_hash2;

	  udp3 = (udp_header_t *)(ip4_3+1);
          new_l3 = clib_host_to_net_u16 (vlib_buffer_length_in_chain(vm, b3)
          			       - sizeof (*ip4_3));
          udp3->length = new_l3;
          //udp3->src_port = flow_hash3;

	  /* Fix srb data length */
	  srb0 = (ppf_srb_header_t *)(udp0+1);
	  new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain(vm, b0)
					 - sizeof (*ip4_0) - sizeof(*udp0) - sizeof(*srb0));
	  srb0->msg.in.data_l = new_l0;
	  srb0->call_id = vnet_buffer(b0)->sw_if_index[VLIB_TX]; // call-id
	  
	  srb1 = (ppf_srb_header_t *)(udp1+1);
	  new_l1 = clib_host_to_net_u16 (vlib_buffer_length_in_chain(vm, b1)
					 - sizeof (*ip4_1) - sizeof(*udp1) - sizeof(*srb1));
	  srb1->msg.in.data_l = new_l1;
	  srb1->call_id = vnet_buffer(b1)->sw_if_index[VLIB_TX]; // call-id

	  srb2 = (ppf_srb_header_t *)(udp2+1);
	  new_l2 = clib_host_to_net_u16 (vlib_buffer_length_in_chain(vm, b2)
					 - sizeof (*ip4_2) - sizeof(*udp2) - sizeof(*srb2));
	  srb2->msg.in.data_l = new_l2;
	  srb2->call_id = vnet_buffer(b2)->sw_if_index[VLIB_TX]; // call-id

	  srb3 = (ppf_srb_header_t *)(udp1+3);
	  new_l3 = clib_host_to_net_u16 (vlib_buffer_length_in_chain(vm, b3)
					 - sizeof (*ip4_3) - sizeof(*udp3) - sizeof(*srb3));
	  srb3->msg.in.data_l = new_l3;
	  srb3->call_id = vnet_buffer(b3)->sw_if_index[VLIB_TX]; // call-id

          /* counter here */
          len0 = vlib_buffer_length_in_chain (vm, b0);
          len1 = vlib_buffer_length_in_chain (vm, b1);
          len2 = vlib_buffer_length_in_chain (vm, b2);
          len3 = vlib_buffer_length_in_chain (vm, b3);
          stats_n_packets += 4;
          stats_n_bytes += len0 + len1 + len2 + len3;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
          {
            ppf_srb_nb_tx_trace_t *tr
              = vlib_add_trace (vm, node, b0, sizeof (*tr));
	    // TBD
          }
          
          if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
          {
            ppf_srb_nb_tx_trace_t *tr
              = vlib_add_trace (vm, node, b1, sizeof (*tr));
	    // TBD
          }
          
	  vlib_validate_buffer_enqueue_x4 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);
        }
  
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
          ip_csum_t sum0;
          
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
          foreach_fixed_header4_offset;
          #undef _
          
          /* Last 4 octets. Hopefully gcc will be our friend */
          copy_dst_last0 = (u32 *)(&copy_dst0[4]);
          copy_src_last0 = (u32 *)(&copy_src0[4]);
          copy_dst_last0[0] = copy_src_last0[0];
          
          /* Fix the IP4 checksum and length */
          sum0 = ip4_0->checksum;
          new_l0 = /* old_l0 always 0, see the rewrite setup */
            clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0));
          sum0 = ip_csum_update (sum0, old_l0, new_l0, ip4_header_t,
          		     length /* changed member */);
          ip4_0->checksum = ip_csum_fold (sum0);
          ip4_0->length = new_l0;
          
          /* Fix UDP length and set source port */
          udp0 = (udp_header_t *)(ip4_0+1);
          new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain(vm, b0)
          			     - sizeof (*ip4_0));
          udp0->length = new_l0;
          //udp0->src_port = flow_hash0;

	  /* Fix srb data length */
	  srb0 = (ppf_srb_header_t *)(udp0+1);
	  new_l0 = clib_host_to_net_u16 (vlib_buffer_length_in_chain(vm, b0)
					 - sizeof (*ip4_0) - sizeof(*udp0) - sizeof(*srb0));
	  srb0->msg.in.data_l = new_l0;
	  srb0->call_id = vnet_buffer(b0)->sw_if_index[VLIB_TX]; // call-id

          /* counter here */
          len0 = vlib_buffer_length_in_chain (vm, b0);
          stats_n_packets += 1;
          stats_n_bytes += len0;
                      
          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
          {
            ppf_srb_nb_tx_trace_t *tr
              = vlib_add_trace (vm, node, b0, sizeof (*tr));
            // TBD
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


