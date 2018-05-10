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

#define foreach_ppf_sb_path_lb_error    \
_(GOOD, "packets delivered")     \
_(NO_BUF, "duplicate buffer errors")

static char * ppf_sb_path_lb_error_strings[] = {
#define _(sym,string) string,
  foreach_ppf_sb_path_lb_error
#undef _
};

typedef enum {
#define _(sym,str) PPF_SB_PATH_LB_ERROR_##sym,
    foreach_ppf_sb_path_lb_error
#undef _
    PPF_sb_path_lb_N_ERROR,
} ppf_sb_path_lb_error_t;


typedef struct {
  u32 sw_if_index;
  u32 next_index;
} ppf_sb_path_lb_trace_t;

u8 * format_ppf_sb_path_lb_trace  (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  ppf_sb_path_lb_trace_t * t = va_arg (*args, ppf_sb_path_lb_trace_t *);
  
  s = format (s, "SB PATH_LOADBALANCE: sw_if_index %d, next index %d",
		  t->sw_if_index, t->next_index);
  return s;
}


always_inline uword
ppf_sb_path_lb_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * frame,
		    u32 is_ip4)
{
  u32 n_left_from, * from, * to_next;
  ppf_sb_path_lb_next_t next_index;
  u32 pkts_processed = 0;
  ppf_main_t *pm = &ppf_main;
  ppf_gtpu_main_t *gtm = &ppf_gtpu_main;
  u32 *buffers_duplicated = pm->buffers_duplicated_per_thread[vlib_get_thread_index ()];
  u8 s_sb_ids[MAX_SB_PER_CALL] = {0, 1, 2};
  
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = ppf_sb_main.sb_lb_next_index;
  if (pm->handoff_enable)
    next_index = PPF_SB_PATH_LB_NEXT_PPF_PDCP_HANDOFF;

  while (n_left_from > 0)
    {
	u32 n_left_to_next;

	vlib_get_next_frame (vm, node, next_index,
				   to_next, n_left_to_next);
				   
	while (n_left_from >= 8 && n_left_to_next >= 4)
	  {
	    ppf_sb_path_lb_next_t next0 = next_index;
	    ppf_sb_path_lb_next_t next1 = next_index;
	    ppf_sb_path_lb_next_t next2 = next_index;
	    ppf_sb_path_lb_next_t next3 = next_index;
	    u32 sw_if_index0 = 0;
	    u32 sw_if_index1 = 0;
	    u32 sw_if_index2 = 0;
	    u32 sw_if_index3 = 0;
	    u32 tunnel_sw_if_index0 = 0;
	    u32 tunnel_sw_if_index1 = 0;
	    u32 tunnel_sw_if_index2 = 0;
	    u32 tunnel_sw_if_index3 = 0;
	    u32 bi0, bi1, bi2, bi3;					    //map to pi0, pi1
	    vlib_buffer_t * b0, * b1, *b2, *b3;	  //map to p0, p1
	    ppf_gtpu_tunnel_t *t0, *t1, *t2, *t3;
	    u32 call_id0, call_id1, call_id2, call_id3;
	    ppf_callline_t *callline0, *callline1, *callline2, *callline3;
		u32 tunnel_id0 = ~0, tunnel_id1 = ~0, tunnel_id2 = ~0, tunnel_id3 = ~0;
	    ppf_gtpu_tunnel_id_type_t * sb_tunnels0 = NULL;
	    ppf_gtpu_tunnel_id_type_t * sb_tunnels1 = NULL;
	    ppf_gtpu_tunnel_id_type_t * sb_tunnels2 = NULL;
	    ppf_gtpu_tunnel_id_type_t * sb_tunnels3 = NULL;
	    u8 sb_num0 = 0, sb_num1 = 0, sb_num2 = 0, sb_num3 = 0;
	    u8 * sb_ids0 = s_sb_ids;
	    u8 * sb_ids1 = s_sb_ids;
	    u8 * sb_ids2 = s_sb_ids;
	    u8 * sb_ids3 = s_sb_ids;
	    
	    /* Prefetch next iteration. */
	    {
			vlib_buffer_t * p4, * p5, *p6, *p7;

			p4 = vlib_get_buffer (vm, from[4]);
			p5 = vlib_get_buffer (vm, from[5]);
			p6 = vlib_get_buffer (vm, from[6]);
			p7 = vlib_get_buffer (vm, from[7]);

			vlib_prefetch_buffer_header (p4, LOAD);
			vlib_prefetch_buffer_header (p5, LOAD);
			vlib_prefetch_buffer_header (p6, LOAD);
			vlib_prefetch_buffer_header (p7, LOAD);

	    }

	    /* speculatively enqueue b0 and b1 to the current next frame */
	    to_next[0] = bi0 = from[0];
	    to_next[1] = bi1 = from[1];
	    to_next[2] = bi2 = from[2];
	    to_next[3] = bi3 = from[3];
	    from += 4;
	    to_next += 4;
	    n_left_from -= 4;
	    n_left_to_next -= 4;

	    b0 = vlib_get_buffer (vm, bi0);
	    b1 = vlib_get_buffer (vm, bi1);
	    b2 = vlib_get_buffer (vm, bi2);
	    b3 = vlib_get_buffer (vm, bi3);

	    tunnel_sw_if_index0 = vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_RX_TUNNEL];
	    if (PREDICT_FALSE(tunnel_sw_if_index0 == ~0)) {
		   call_id0 = vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL]; // srb case
		   if (~0 == call_id0) {
			   sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_TX];
			   call_id0 = gtm->calline_index_by_sw_if_index[sw_if_index0];
			   vnet_buffer(b0)->sw_if_index[VLIB_RX] = sw_if_index0;
		   }
	    } else { 	   
		   t0 = &(gtm->tunnels[tunnel_sw_if_index0]);
		   call_id0 = t0->call_id; 
	    }
	   
	    callline0 = &(pm->ppf_calline_table[call_id0]);
	   
	    if (PREDICT_TRUE(callline0->call_type == PPF_DRB_CALL)) {
		   sb_num0 = PPF_SB_COUNT (callline0->sb_multi_path);
		   if (PREDICT_TRUE (sb_num0 == 1)) {
			   tunnel_id0 = callline0->rb.drb.sb_tunnel[PPF_SB_VALID_PATH(callline0->sb_multi_path)].tunnel_id;
			   vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tunnel_id0;	   
		   } else
			   sb_tunnels0 = callline0->rb.drb.sb_tunnel; 
	    }
	   
	    if (PREDICT_FALSE(callline0->call_type == PPF_SRB_CALL)) {
		   sb_num0 = vnet_buffer2(b0)->ppf_du_metadata.path.sb_num;
		   sb_ids0 = vnet_buffer2(b0)->ppf_du_metadata.path.sb_id; 
		   if (1 == sb_num0) {
			   tunnel_id0 = callline0->rb.srb.sb_tunnel[sb_ids0[0]].tunnel_id; 				   
			   vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tunnel_id0;	   
		   } else if ((sb_num0 > 1) && (sb_num0 <= MAX_SB_PER_CALL)) {
			   sb_tunnels0 = callline0->rb.srb.sb_tunnel;
		   } else {
			   sb_num0 = PPF_SB_COUNT (callline0->sb_multi_path);
			   if (sb_num0 == 1) {
				   tunnel_id0 = callline0->rb.srb.sb_tunnel[PPF_SB_VALID_PATH(callline0->sb_multi_path)].tunnel_id;
				   vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tunnel_id0;	   
			   } else {
				   sb_ids0 = s_sb_ids; 
				   sb_tunnels0 = callline0->rb.srb.sb_tunnel;
			   }
		   }
	    } 
	   
	    if (PREDICT_FALSE(sb_num0 > 1)) {
		   u8 id;
		   u32 duplicate = 0;
		   
		   for (id = 0; id < MAX_SB_PER_CALL; id++) {
			   tunnel_id0 = sb_tunnels0[sb_ids0[id]].tunnel_id;
			   if ((INVALID_TUNNEL_ID == tunnel_id0)
                || (PPF_SB_PATH_GET_VALID(callline0->sb_multi_path, sb_ids0[id]) == 0))
				   continue;
			   
			   duplicate++;
			   if (1 == duplicate)
				   vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tunnel_id0;
			   else if (duplicate > 1) {
				   vlib_buffer_t *c0 = vlib_buffer_copy (vm, b0);
				   if (c0) {
					   clib_memcpy (c0->opaque2, b0->opaque2, sizeof (b0->opaque2));
					   vnet_buffer2(c0)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tunnel_id0;
		   
					   vec_add1 (buffers_duplicated, vlib_get_buffer_index (vm, c0));
				   } else
					   vlib_node_increment_counter (vm, node->node_index,
													PPF_SB_PATH_LB_ERROR_NO_BUF,
													1);
		   
			   }
		   }
	    }

	    if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
		    if (b0->flags & VLIB_BUFFER_IS_TRACED) 
		    {
		      ppf_sb_path_lb_trace_t *t = 
		        vlib_add_trace (vm, node, b0, sizeof (*t));
		      t->sw_if_index = tunnel_sw_if_index0;
		      t->next_index = next0;			  
		    }
	    }

	    tunnel_sw_if_index1 = vnet_buffer2(b1)->ppf_du_metadata.tunnel_id[VLIB_RX_TUNNEL];
	    if (PREDICT_FALSE(tunnel_sw_if_index1 == ~0)) {
            call_id1 = vnet_buffer2(b1)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL]; // srb case
            if (~0 == call_id1) {
				sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_TX];
				call_id1 = gtm->calline_index_by_sw_if_index[sw_if_index1];
				vnet_buffer(b1)->sw_if_index[VLIB_RX] = sw_if_index1;
            }
	    } else {	    
			t1 = &(gtm->tunnels[tunnel_sw_if_index1]);
			call_id1 = t1->call_id;	
	    }
	    
	    callline1 = &(pm->ppf_calline_table[call_id1]);

	    if (PREDICT_TRUE(callline1->call_type == PPF_DRB_CALL)) {
		   sb_num1 = PPF_SB_COUNT (callline1->sb_multi_path);
		   if (PREDICT_TRUE (sb_num1 == 1)) {
			   tunnel_id1 = callline1->rb.drb.sb_tunnel[PPF_SB_VALID_PATH(callline1->sb_multi_path)].tunnel_id;
			   vnet_buffer2(b1)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tunnel_id1;	   
		   } else
			   sb_tunnels1 = callline0->rb.drb.sb_tunnel; 
	    }
	   
	    if (PREDICT_FALSE(callline1->call_type == PPF_SRB_CALL)) {
		   sb_num1 = vnet_buffer2(b1)->ppf_du_metadata.path.sb_num;
		   sb_ids1 = vnet_buffer2(b1)->ppf_du_metadata.path.sb_id; 
		   if (1 == sb_num1) {
			   tunnel_id1 = callline1->rb.srb.sb_tunnel[sb_ids1[0]].tunnel_id; 				   
			   vnet_buffer2(b1)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tunnel_id1;	   
		   } else if ((sb_num1 > 1) && (sb_num1 <= MAX_SB_PER_CALL)) {
			   sb_tunnels1 = callline1->rb.srb.sb_tunnel;
		   } else {
			   sb_num1 = PPF_SB_COUNT (callline1->sb_multi_path);
			   if (sb_num1 == 1) {
				   tunnel_id1 = callline1->rb.srb.sb_tunnel[PPF_SB_VALID_PATH(callline1->sb_multi_path)].tunnel_id;
				   vnet_buffer2(b1)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tunnel_id1;	   
			   } else {
				   sb_ids1 = s_sb_ids; 
				   sb_tunnels1 = callline1->rb.srb.sb_tunnel;
			   }
		   }
	    } 
	   
	    if (PREDICT_FALSE(sb_num1 > 1)) {
		   u8 id;
		   u32 duplicate = 0;
		   
		   for (id = 0; id < MAX_SB_PER_CALL; id++) {
			   tunnel_id1 = sb_tunnels1[sb_ids1[id]].tunnel_id;
			   if ((INVALID_TUNNEL_ID == tunnel_id1)
                || (PPF_SB_PATH_GET_VALID(callline1->sb_multi_path, sb_ids1[id]) == 0))
				   continue;
			   
			   duplicate++;
			   if (1 == duplicate)
				   vnet_buffer2(b1)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tunnel_id1;
			   else if (duplicate > 1) {
				   vlib_buffer_t *c1 = vlib_buffer_copy (vm, b1);
				   if (c1) {
					   clib_memcpy (c1->opaque2, b1->opaque2, sizeof (b1->opaque2));
					   vnet_buffer2(c1)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tunnel_id1;
		   
					   vec_add1 (buffers_duplicated, vlib_get_buffer_index (vm, c1));
				   } else
					   vlib_node_increment_counter (vm, node->node_index,
													PPF_SB_PATH_LB_ERROR_NO_BUF,
													1);
		   
			   }
		   }
	    }

	    if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
		  if (b1->flags & VLIB_BUFFER_IS_TRACED) 
		  {
			  ppf_sb_path_lb_trace_t *t = 
			    vlib_add_trace (vm, node, b1, sizeof (*t));
			  t->sw_if_index = tunnel_sw_if_index1;
			  t->next_index = next1;			  
		   }
	    }

	    tunnel_sw_if_index2 = vnet_buffer2(b2)->ppf_du_metadata.tunnel_id[VLIB_RX_TUNNEL];
	    if (PREDICT_FALSE(tunnel_sw_if_index2 == ~0)) {
            call_id2 = vnet_buffer2(b2)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL]; // srb case
            if (~0 == call_id2) {
				sw_if_index2 = vnet_buffer(b2)->sw_if_index[VLIB_TX];
				call_id2 = gtm->calline_index_by_sw_if_index[sw_if_index2];
				vnet_buffer(b2)->sw_if_index[VLIB_RX] = sw_if_index2;
            }
	    } else {	    
			t2 = &(gtm->tunnels[tunnel_sw_if_index2]);
			call_id2 = t2->call_id;	
	    }
	    
	    callline2 = &(pm->ppf_calline_table[call_id2]);

	    if (PREDICT_TRUE(callline2->call_type == PPF_DRB_CALL)) {
		   sb_num2 = PPF_SB_COUNT (callline2->sb_multi_path);
		   if (PREDICT_TRUE (sb_num2 == 1)) {
			   tunnel_id2 = callline2->rb.drb.sb_tunnel[PPF_SB_VALID_PATH(callline2->sb_multi_path)].tunnel_id;
			   vnet_buffer2(b2)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tunnel_id2;	   
		   } else
			   sb_tunnels2 = callline2->rb.drb.sb_tunnel; 
	    }
	   
	    if (PREDICT_FALSE(callline2->call_type == PPF_SRB_CALL)) {
		   sb_num2 = vnet_buffer2(b2)->ppf_du_metadata.path.sb_num;
		   sb_ids2 = vnet_buffer2(b2)->ppf_du_metadata.path.sb_id; 
		   if (1 == sb_num2) {
			   tunnel_id2 = callline2->rb.srb.sb_tunnel[sb_ids2[0]].tunnel_id; 				   
			   vnet_buffer2(b2)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tunnel_id2;	   
		   } else if ((sb_num2 > 1) && (sb_num2 <= MAX_SB_PER_CALL)) {
			   sb_tunnels2 = callline2->rb.srb.sb_tunnel;
		   } else {
			   sb_num2 = PPF_SB_COUNT (callline2->sb_multi_path);
			   if (sb_num2 == 1) {
				   tunnel_id2 = callline2->rb.srb.sb_tunnel[PPF_SB_VALID_PATH(callline2->sb_multi_path)].tunnel_id;
				   vnet_buffer2(b2)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tunnel_id2;	   
			   } else {
				   sb_ids2 = s_sb_ids; 
				   sb_tunnels2 = callline2->rb.srb.sb_tunnel;
			   }
		   }
	    } 
	   
	    if (PREDICT_FALSE(sb_num2 > 1)) {
		   u8 id;
		   u32 duplicate = 0;
		   
		   for (id = 0; id < MAX_SB_PER_CALL; id++) {
			   tunnel_id0 = sb_tunnels2[sb_ids2[id]].tunnel_id;
			   if ((INVALID_TUNNEL_ID == tunnel_id2)
                || (PPF_SB_PATH_GET_VALID(callline2->sb_multi_path, sb_ids2[id]) == 0))
				   continue;
			   
			   duplicate++;
			   if (1 == duplicate)
				   vnet_buffer2(b2)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tunnel_id2;
			   else if (duplicate > 1) {
				   vlib_buffer_t *c2 = vlib_buffer_copy (vm, b2);
				   if (c2) {
					   clib_memcpy (c2->opaque2, b2->opaque2, sizeof (b2->opaque2));
					   vnet_buffer2(c2)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tunnel_id2;
		   
					   vec_add1 (buffers_duplicated, vlib_get_buffer_index (vm, c2));
				   } else
					   vlib_node_increment_counter (vm, node->node_index,
													PPF_SB_PATH_LB_ERROR_NO_BUF,
													1);
		   
			   }
		   }
	    }

	    if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
		  if (b2->flags & VLIB_BUFFER_IS_TRACED) 
		  {
			  ppf_sb_path_lb_trace_t *t = 
			    vlib_add_trace (vm, node, b2, sizeof (*t));
			  t->sw_if_index = tunnel_sw_if_index2;
			  t->next_index = next2;			  
		   }
	    }

	    tunnel_sw_if_index3 = vnet_buffer2(b3)->ppf_du_metadata.tunnel_id[VLIB_RX_TUNNEL];
	    if (PREDICT_FALSE(tunnel_sw_if_index3 == ~0)) {
		   call_id3 = vnet_buffer2(b3)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL]; // srb case
		   if (~0 == call_id3) {
			   sw_if_index3 = vnet_buffer(b3)->sw_if_index[VLIB_TX];
			   call_id3 = gtm->calline_index_by_sw_if_index[sw_if_index3];
			   vnet_buffer(b3)->sw_if_index[VLIB_RX] = sw_if_index3;
		   }
	    } else { 	   
		   t3 = &(gtm->tunnels[tunnel_sw_if_index3]);
		   call_id3 = t3->call_id; 
	    }
	   
	    callline3 = &(pm->ppf_calline_table[call_id3]);
	   
	    if (PREDICT_TRUE(callline3->call_type == PPF_DRB_CALL)) {
		  sb_num3 = PPF_SB_COUNT (callline3->sb_multi_path);
		  if (PREDICT_TRUE (sb_num3 == 1)) {
			  tunnel_id3 = callline3->rb.drb.sb_tunnel[PPF_SB_VALID_PATH(callline3->sb_multi_path)].tunnel_id;
			  vnet_buffer2(b3)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tunnel_id3; 	  
		  } else
			  sb_tunnels3 = callline3->rb.drb.sb_tunnel; 
	    }
	   
	    if (PREDICT_FALSE(callline3->call_type == PPF_SRB_CALL)) {
		  sb_num3 = vnet_buffer2(b3)->ppf_du_metadata.path.sb_num;
		  sb_ids3 = vnet_buffer2(b3)->ppf_du_metadata.path.sb_id; 
		  if (1 == sb_num3) {
			  tunnel_id3 = callline3->rb.srb.sb_tunnel[sb_ids3[0]].tunnel_id;				  
			  vnet_buffer2(b3)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tunnel_id3; 	  
		  } else if ((sb_num3 > 1) && (sb_num3 <= MAX_SB_PER_CALL)) {
			  sb_tunnels3 = callline3->rb.srb.sb_tunnel;
		  } else {
			  sb_num3 = PPF_SB_COUNT (callline3->sb_multi_path);
			  if (sb_num3 == 1) {
				  tunnel_id3 = callline3->rb.srb.sb_tunnel[PPF_SB_VALID_PATH(callline3->sb_multi_path)].tunnel_id;
				  vnet_buffer2(b3)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tunnel_id3; 	  
			  } else {
				  sb_ids3 = s_sb_ids; 
				  sb_tunnels3 = callline3->rb.srb.sb_tunnel;
			  }
		  }
	    } 
	   
	    if (PREDICT_FALSE(sb_num3 > 1)) {
		  u8 id;
		  u32 duplicate = 0;
		  
		  for (id = 0; id < MAX_SB_PER_CALL; id++) {
			  tunnel_id3 = sb_tunnels3[sb_ids3[id]].tunnel_id;
			  if ((INVALID_TUNNEL_ID == tunnel_id3)
			   || (PPF_SB_PATH_GET_VALID(callline3->sb_multi_path, sb_ids3[id]) == 0))
				  continue;
			  
			  duplicate++;
			  if (1 == duplicate)
				  vnet_buffer2(b3)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tunnel_id3;
			  else if (duplicate > 1) {
				  vlib_buffer_t *c3 = vlib_buffer_copy (vm, b3);
				  if (c3) {
					  clib_memcpy (c3->opaque2, b3->opaque2, sizeof (b3->opaque2));
					  vnet_buffer2(c3)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tunnel_id3;
		  
					  vec_add1 (buffers_duplicated, vlib_get_buffer_index (vm, c3));
				  } else
					  vlib_node_increment_counter (vm, node->node_index,
												   PPF_SB_PATH_LB_ERROR_NO_BUF,
												   1);
		  
			  }
		  }
	    }
	   
	    if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
		  if (b3->flags & VLIB_BUFFER_IS_TRACED) 
		  {
			 ppf_sb_path_lb_trace_t *t = 
			   vlib_add_trace (vm, node, b3, sizeof (*t));
			 t->sw_if_index = tunnel_sw_if_index3;
			 t->next_index = next3; 			 
		  }
	    }
	 
	    pkts_processed += 4;
		 
		/* verify speculative enqueues, maybe switch current next frame */
		vlib_validate_buffer_enqueue_x4 (vm, node, next_index,
							   to_next, n_left_to_next,
							   bi0, bi1, bi2, bi3, next0, next1, next2, next3);
	  }

	while (n_left_from > 0 && n_left_to_next > 0)
	  {
	    ppf_sb_path_lb_next_t next0 = next_index;
	    u32 sw_if_index0 = 0;
	    u32 tunnel_sw_if_index0 = 0;
	    u32 bi0;					//map to pi0, pi1
	    vlib_buffer_t * b0;     //map to p0, p1
	    ppf_gtpu_tunnel_t *t0;
	    u32 call_id0;
	    ppf_callline_t *callline0;
		u32 tunnel_id0 = ~0;
	    ppf_gtpu_tunnel_id_type_t * sb_tunnels0 = NULL;
	    u8 sb_num0 = 0;
	    u8 * sb_ids0 = s_sb_ids;

	    /* speculatively enqueue b0 to the current next frame */
	    bi0 = from[0];
	    to_next[0] = bi0;
	    from += 1;
	    to_next += 1;
	    n_left_from -= 1;
	    n_left_to_next -= 1;

	    b0 = vlib_get_buffer (vm, bi0);

	    tunnel_sw_if_index0 = vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_RX_TUNNEL];
	    if (PREDICT_FALSE(tunnel_sw_if_index0 == ~0)) {
            call_id0 = vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL]; // srb case
            if (~0 == call_id0) {
				sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_TX];
				call_id0 = gtm->calline_index_by_sw_if_index[sw_if_index0];
				vnet_buffer(b0)->sw_if_index[VLIB_RX] = sw_if_index0;
            }
	    } else {	    
			t0 = &(gtm->tunnels[tunnel_sw_if_index0]);
			call_id0 = t0->call_id;	
	    }
	    
	    callline0 = &(pm->ppf_calline_table[call_id0]);

	    if (PREDICT_TRUE(callline0->call_type == PPF_DRB_CALL)) {
		   sb_num0 = PPF_SB_COUNT (callline0->sb_multi_path);
		   if (PREDICT_TRUE (sb_num0 == 1)) {
			   tunnel_id0 = callline0->rb.drb.sb_tunnel[PPF_SB_VALID_PATH(callline0->sb_multi_path)].tunnel_id;
			   vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tunnel_id0;	   
		   } else
			   sb_tunnels0 = callline0->rb.drb.sb_tunnel; 
	    }
	   
	    if (PREDICT_FALSE(callline0->call_type == PPF_SRB_CALL)) {
		   sb_num0 = vnet_buffer2(b0)->ppf_du_metadata.path.sb_num;
		   sb_ids0 = vnet_buffer2(b0)->ppf_du_metadata.path.sb_id; 
		   if (1 == sb_num0) {
			   tunnel_id0 = callline0->rb.srb.sb_tunnel[sb_ids0[0]].tunnel_id; 				   
			   vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tunnel_id0;	   
			   sb_num0 = 0;
		   } else if ((sb_num0 > 1) && (sb_num0 <= MAX_SB_PER_CALL)) {
			   sb_tunnels0 = callline0->rb.srb.sb_tunnel;
		   } else {
			   sb_num0 = PPF_SB_COUNT (callline0->sb_multi_path);
			   if (sb_num0 == 1) {
				   tunnel_id0 = callline0->rb.srb.sb_tunnel[PPF_SB_VALID_PATH(callline0->sb_multi_path)].tunnel_id;
				   vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tunnel_id0;	   
			   } else {
				   sb_ids0 = s_sb_ids; 
				   sb_tunnels0 = callline0->rb.srb.sb_tunnel;
			   }
		   }
	    } 
	   
	    if (PREDICT_FALSE(sb_num0 > 1)) {
		   u8 id;
		   u32 duplicate = 0;
		   
		   for (id = 0; id < MAX_SB_PER_CALL; id++) {
			   tunnel_id0 = sb_tunnels0[sb_ids0[id]].tunnel_id;
			   if ((INVALID_TUNNEL_ID == tunnel_id0)
                || (PPF_SB_PATH_GET_VALID(callline0->sb_multi_path, sb_ids0[id]) == 0))
				   continue;
			   
			   duplicate++;
			   if (1 == duplicate)
				   vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tunnel_id0;
			   else if (duplicate > 1) {
				   vlib_buffer_t *c0 = vlib_buffer_copy (vm, b0);
				   if (c0) {
					   clib_memcpy (c0->opaque2, b0->opaque2, sizeof (b0->opaque2));
					   vnet_buffer2(c0)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tunnel_id0;
		   
					   vec_add1 (buffers_duplicated, vlib_get_buffer_index (vm, c0));
				   } else
					   vlib_node_increment_counter (vm, node->node_index,
													PPF_SB_PATH_LB_ERROR_NO_BUF,
													1);
		   
			   }
		   }
	    }
	    
		if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
		  if (b0->flags & VLIB_BUFFER_IS_TRACED) 
		  {
			  ppf_sb_path_lb_trace_t *t = 
			    vlib_add_trace (vm, node, b0, sizeof (*t));
			  t->sw_if_index = (tunnel_sw_if_index0 == ~0) ? sw_if_index0 : tunnel_sw_if_index0;
			  t->next_index = next0;			  
		   }
	    }
 
		pkts_processed += 1;

	    /* verify speculative enqueue, maybe switch current next frame */
	    vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
							 to_next, n_left_to_next,
							 bi0, next0);
	  }

	/* Duplicate send */
	while (vec_len (buffers_duplicated) > 0) {
		while (vec_len (buffers_duplicated) > 0 && n_left_to_next > 0) {
			u32 bi = vec_pop (buffers_duplicated);
			vlib_buffer_t *b = vlib_get_buffer (vm, bi);

			to_next[0] = bi;
			to_next += 1;
			n_left_to_next -= 1;

			if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
			{
			  if (b->flags & VLIB_BUFFER_IS_TRACED) 
			  {
				  ppf_sb_path_lb_trace_t *t = 
					vlib_add_trace (vm, node, b, sizeof (*t));
				  t->sw_if_index = vnet_buffer(b)->sw_if_index[VLIB_TX];
				  t->next_index = next_index;			  
			   }
			}
			
			pkts_processed += 1;

			/* verify speculative enqueue, maybe switch current next frame */
			vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
								 to_next, n_left_to_next,
								 bi, next_index);
		}
		vlib_put_next_frame (vm, node, next_index, n_left_to_next); 		 
		vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
	}

	vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
                               PPF_SB_PATH_LB_ERROR_GOOD,
                               pkts_processed);


  return frame->n_vectors;
}


static uword
ppf_sb_path_lb (vlib_main_t * vm,
	      vlib_node_runtime_t * node,
	      vlib_frame_t * frame)
{
  return ppf_sb_path_lb_inline (vm, node, frame, /* is_ip4 */ 1);
}


VLIB_NODE_FUNCTION_MULTIARCH (ppf_sb_path_lb_node, ppf_sb_path_lb)

VLIB_REGISTER_NODE (ppf_sb_path_lb_node) = {
  .function = ppf_sb_path_lb,
  .name = "ppf_sb_path_lb",
  .vector_size = sizeof (u32),
  .format_trace = format_ppf_sb_path_lb_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ppf_sb_path_lb_error_strings),
  .error_strings = ppf_sb_path_lb_error_strings,
  .n_next_nodes = PPF_SB_PATH_LB_N_NEXT,
  .next_nodes = {
#define _(s,n) [PPF_SB_PATH_LB_NEXT_##s] = n,
    foreach_ppf_sb_path_lb_next
#undef _
  },
};


/* Statistics (not all errors) */

#define foreach_ppf_lbo_input_error    \
_(GOOD, "packets delivered")     \
_(BAD,  "packets dropped")

static char * ppf_lbo_input_error_strings[] = {
#define _(sym,string) string,
  foreach_ppf_lbo_input_error
#undef _
};

typedef enum {
#define _(sym,str) PPF_LBO_INPUT_ERROR_##sym,
    foreach_ppf_lbo_input_error
#undef _
    PPF_LBO_INPUT_N_ERROR,
} ppf_lbo_input_error_t;


typedef struct {
  u32 sw_if_index;
  u32 next_index;
} ppf_lbo_input_trace_t;

u8 * format_ppf_lbo_input_trace  (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  ppf_lbo_input_trace_t * t = va_arg (*args, ppf_lbo_input_trace_t *);
  
  s = format (s, "LBO Input: sw_if_index %d, next index %d",
		  t->sw_if_index, t->next_index);
  return s;
}


always_inline uword
ppf_lbo_input (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  ppf_lbo_input_next_t next_index;
  u32 pkts_processed = 0;
  
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = PPF_LBO_INPUT_NEXT_SB_PATH_LB;

  while (n_left_from > 0)
    {
	u32 n_left_to_next;

	vlib_get_next_frame (vm, node, next_index,
				   to_next, n_left_to_next);
				   
	while (n_left_from >= 8 && n_left_to_next >= 4)
	  {
	    ppf_lbo_input_next_t next0 = next_index;
	    ppf_lbo_input_next_t next1 = next_index;
	    ppf_lbo_input_next_t next2 = next_index;
	    ppf_lbo_input_next_t next3 = next_index;
	    u32 bi0, bi1, bi2, bi3;				  //map to pi0, pi1
	    vlib_buffer_t * b0, * b1, *b2, *b3;	  //map to p0, p1
	    
	    /* Prefetch next iteration. */
	    {
			vlib_buffer_t * p4, * p5, *p6, *p7;

			p4 = vlib_get_buffer (vm, from[4]);
			p5 = vlib_get_buffer (vm, from[5]);
			p6 = vlib_get_buffer (vm, from[6]);
			p7 = vlib_get_buffer (vm, from[7]);

			vlib_prefetch_buffer_header (p4, LOAD);
			vlib_prefetch_buffer_header (p5, LOAD);
			vlib_prefetch_buffer_header (p6, LOAD);
			vlib_prefetch_buffer_header (p7, LOAD);

	    }

	    /* speculatively enqueue b0 and b1 to the current next frame */
	    to_next[0] = bi0 = from[0];
	    to_next[1] = bi1 = from[1];
	    to_next[2] = bi2 = from[2];
	    to_next[3] = bi3 = from[3];
	    from += 4;
	    to_next += 4;
	    n_left_from -= 4;
	    n_left_to_next -= 4;

	    b0 = vlib_get_buffer (vm, bi0);
	    b1 = vlib_get_buffer (vm, bi1);
	    b2 = vlib_get_buffer (vm, bi2);
	    b3 = vlib_get_buffer (vm, bi3);

	    vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_RX_TUNNEL] = INVALID_TUNNEL_ID;
	    vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = INVALID_TUNNEL_ID;
	    
	    vnet_buffer2(b1)->ppf_du_metadata.tunnel_id[VLIB_RX_TUNNEL] = INVALID_TUNNEL_ID;
	    vnet_buffer2(b1)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = INVALID_TUNNEL_ID;
	    
	    vnet_buffer2(b2)->ppf_du_metadata.tunnel_id[VLIB_RX_TUNNEL] = INVALID_TUNNEL_ID;
	    vnet_buffer2(b2)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = INVALID_TUNNEL_ID;
	    
	    vnet_buffer2(b3)->ppf_du_metadata.tunnel_id[VLIB_RX_TUNNEL] = INVALID_TUNNEL_ID;
	    vnet_buffer2(b3)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = INVALID_TUNNEL_ID;

	    if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
		    if (b0->flags & VLIB_BUFFER_IS_TRACED) 
		    {
			    ppf_lbo_input_trace_t *t = 
				    vlib_add_trace (vm, node, b0, sizeof (*t));
			    t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
			    t->next_index = next0;			  
		    }
	    }
	    
	    if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
		    if (b1->flags & VLIB_BUFFER_IS_TRACED) 
		    {
			    ppf_lbo_input_trace_t *t = 
				    vlib_add_trace (vm, node, b1, sizeof (*t));
			    t->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_RX];
			    t->next_index = next1;			  
		    }
	    }
	    
	    if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
		    if (b2->flags & VLIB_BUFFER_IS_TRACED) 
		    {
			    ppf_lbo_input_trace_t *t = 
				    vlib_add_trace (vm, node, b2, sizeof (*t));
			    t->sw_if_index = vnet_buffer (b2)->sw_if_index[VLIB_RX];
			    t->next_index = next2;			  
		    }
	    }
	    
	    if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
		    if (b3->flags & VLIB_BUFFER_IS_TRACED) 
		    {
			    ppf_lbo_input_trace_t *t = 
				    vlib_add_trace (vm, node, b3, sizeof (*t));
			    t->sw_if_index = vnet_buffer (b3)->sw_if_index[VLIB_RX];
			    t->next_index = next3; 			 
		    }
	    }
	    
	    pkts_processed += 4;
	     
	    /* verify speculative enqueues, maybe switch current next frame */
	    vlib_validate_buffer_enqueue_x4 (vm, node, next_index,
	    								to_next, n_left_to_next,
	    								bi0, bi1, bi2, bi3, next0, next1, next2, next3);
	  }

	while (n_left_from > 0 && n_left_to_next > 0)
	  {
	    ppf_lbo_input_next_t next0 = next_index;
	    u32 bi0;					//map to pi0, pi1
	    vlib_buffer_t * b0;     //map to p0, p1

	    /* speculatively enqueue b0 to the current next frame */
	    bi0 = from[0];
	    to_next[0] = bi0;
	    from += 1;
	    to_next += 1;
	    n_left_from -= 1;
	    n_left_to_next -= 1;

	    b0 = vlib_get_buffer (vm, bi0);

	    vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_RX_TUNNEL] = INVALID_TUNNEL_ID;
	    vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = INVALID_TUNNEL_ID;
	    
	    if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
		    if (b0->flags & VLIB_BUFFER_IS_TRACED) 
		    {
			    ppf_lbo_input_trace_t *t = 
				    vlib_add_trace (vm, node, b0, sizeof (*t));
			    t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
			    t->next_index = next0;			  
		    }
	    }
 
	    pkts_processed += 1;
	    
	    /* verify speculative enqueue, maybe switch current next frame */
	    vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
	    							    to_next, n_left_to_next,
	    							    bi0, next0);
	  }

	vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index,
                               PPF_LBO_INPUT_ERROR_GOOD,
                               pkts_processed);


  return frame->n_vectors;
}


VLIB_NODE_FUNCTION_MULTIARCH (ppf_lbo_input_node, ppf_lbo_input)

VLIB_REGISTER_NODE (ppf_lbo_input_node) = {
  .function = ppf_lbo_input,
  .name = "ppf_lbo_input",
  .vector_size = sizeof (u32),
  .format_trace = format_ppf_lbo_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ppf_lbo_input_error_strings),
  .error_strings = ppf_lbo_input_error_strings,
  .n_next_nodes = PPF_LBO_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [PPF_LBO_INPUT_NEXT_##s] = n,
    foreach_ppf_lbo_input_next
#undef _
  },
};




