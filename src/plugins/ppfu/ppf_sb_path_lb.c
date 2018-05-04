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
				   
#if 0
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

	   //ASSERT (b0->current_data == 0);
	   // ASSERT (b1->current_data == 0);
	   // ASSERT (b2->current_data == 0);
	   // ASSERT (b3->current_data == 0);

	   tunnel_sw_if_index0 = vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_RX_TUNNEL];
	   
	   if (tunnel_sw_if_index0 == ~0) {
	     sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_TX];
	   
	     call_id0 = gtm->calline_index_by_sw_if_index[sw_if_index0];
	   
	     vnet_buffer(b0)->sw_if_index[VLIB_RX] = sw_if_index0;
	   
	   } else {
	   
	     t0 = &(gtm->tunnels[tunnel_sw_if_index0]);
	     call_id0 = t0->call_id; 
	   }
	   
	   callline0 = &(pm->ppf_calline_table[call_id0]); 


	    if (callline0->call_type == PPF_SRB_CALL)
	    	vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = 
	    		callline0->rb.srb.sb_tunnel[DEFAULT_SB_INDEX].tunnel_id;
	    else if (callline0->call_type == PPF_DRB_CALL)
	    	vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] =
	    		callline0->rb.drb.sb_tunnel[DEFAULT_SB_INDEX].tunnel_id;

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
	    
	    if (tunnel_sw_if_index1 == ~0) {
		sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_TX];
	    
		call_id1 = gtm->calline_index_by_sw_if_index[sw_if_index1];
	    
		vnet_buffer(b1)->sw_if_index[VLIB_RX] = sw_if_index1;
	    
	    } else {
	    
		t1 = &(gtm->tunnels[tunnel_sw_if_index1]);
		call_id1 = t1->call_id; 
	    }
	    
	    callline1 = &(pm->ppf_calline_table[call_id1]); 

	    if (callline1->call_type == PPF_SRB_CALL)
	    	vnet_buffer2(b1)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = 
	    		callline1->rb.srb.sb_tunnel[DEFAULT_SB_INDEX].tunnel_id;
	    else if (callline1->call_type == PPF_DRB_CALL)
	    	vnet_buffer2(b1)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] =
	    		callline1->rb.drb.sb_tunnel[DEFAULT_SB_INDEX].tunnel_id;

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
	    
	    if (tunnel_sw_if_index2 == ~0) {
		sw_if_index2 = vnet_buffer(b2)->sw_if_index[VLIB_TX];
	    
		call_id2 = gtm->calline_index_by_sw_if_index[sw_if_index2];
	    
		vnet_buffer(b2)->sw_if_index[VLIB_RX] = sw_if_index2;
	    
	    } else {
	    
		t2 = &(gtm->tunnels[tunnel_sw_if_index2]);
		call_id2 = t2->call_id; 
	    }
	    
	    callline2 = &(pm->ppf_calline_table[call_id2]); 

	    if (callline2->call_type == PPF_SRB_CALL)
	    	vnet_buffer2(b2)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = 
	    		callline2->rb.srb.sb_tunnel[DEFAULT_SB_INDEX].tunnel_id;
	    else if (callline2->call_type == PPF_DRB_CALL)
	    	vnet_buffer2(b2)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] =
	    		callline2->rb.drb.sb_tunnel[DEFAULT_SB_INDEX].tunnel_id;

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
	   
	   if (tunnel_sw_if_index3 == ~0) {
	     sw_if_index3 = vnet_buffer(b3)->sw_if_index[VLIB_TX];
	   
	     call_id3 = gtm->calline_index_by_sw_if_index[sw_if_index3];
	   
	     vnet_buffer(b3)->sw_if_index[VLIB_RX] = sw_if_index3;
	   
	   } else {
	   
	     t3 = &(gtm->tunnels[tunnel_sw_if_index3]);
	     call_id3 = t3->call_id; 
	   }
	   
	   callline3 = &(pm->ppf_calline_table[call_id3]);

	   
	   if (callline3->call_type == PPF_SRB_CALL)
	     vnet_buffer2(b3)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = 
		     callline3->rb.srb.sb_tunnel[DEFAULT_SB_INDEX].tunnel_id;
	   else if (callline3->call_type == PPF_DRB_CALL)
	     vnet_buffer2(b3)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] =
		     callline3->rb.drb.sb_tunnel[DEFAULT_SB_INDEX].tunnel_id;
	   
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
#endif

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

	    /* speculatively enqueue b0 to the current next frame */
	    bi0 = from[0];
	    to_next[0] = bi0;
	    from += 1;
	    to_next += 1;
	    n_left_from -= 1;
	    n_left_to_next -= 1;

	    b0 = vlib_get_buffer (vm, bi0);

	    //ASSERT (b0->current_data == 0);

	    tunnel_sw_if_index0 = vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_RX_TUNNEL];
	    if (tunnel_sw_if_index0 == ~0) {
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
            u32 sb_id;
			u32 tx_tunnel_id;
			u32 duplicate = 0;

            for (sb_id = 0; sb_id < MAX_SB_PER_CALL; sb_id++) {
				tx_tunnel_id = callline0->rb.drb.sb_tunnel[sb_id].tunnel_id;
				if (INVALID_TUNNEL_ID == tx_tunnel_id)
					continue;
				
				duplicate++;
				if (1 == duplicate)
					vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tx_tunnel_id;
				else if (duplicate > 1) {
					vlib_buffer_t *c0 = vlib_buffer_copy (vm, b0);
					if (c0) {
						clib_memcpy (c0->opaque2, b0->opaque2, sizeof (b0->opaque2));
						vnet_buffer2(c0)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tx_tunnel_id;

						vec_add1 (buffers_duplicated, vlib_get_buffer_index (vm, c0));
					} else
						vlib_node_increment_counter (vm, node->node_index,
													 PPF_SB_PATH_LB_ERROR_NO_BUF,
													 1);

				}
			}
		}


	    if (PREDICT_FALSE(callline0->call_type == PPF_SRB_CALL)) {
			u8 sb_num = vnet_buffer2(b0)->ppf_du_metadata.path.sb_num;
			u8 * sb_ids = vnet_buffer2(b0)->ppf_du_metadata.path.sb_id; 
			if (1 == sb_num) {
				u32 tx_tunnel_id = callline0->rb.srb.sb_tunnel[sb_ids[0]].tunnel_id; 					
				vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tx_tunnel_id;		
			} else if ((sb_num > 1) && (sb_num <= MAX_SB_PER_CALL)) {
	            u8  id;
				u32 tx_tunnel_id;
				u32 duplicate = 0;

	            for (id = 0; id < sb_num; id++) {
					tx_tunnel_id = callline0->rb.srb.sb_tunnel[sb_ids[id]].tunnel_id;
					if (INVALID_TUNNEL_ID == tx_tunnel_id)
						continue;
					
					duplicate++;
					if (1 == duplicate)
						vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tx_tunnel_id;
					else if (duplicate > 1) {
						vlib_buffer_t *c0 = vlib_buffer_copy (vm, b0);
						if (c0) {
							clib_memcpy (c0->opaque2, b0->opaque2, sizeof (b0->opaque2));
							vnet_buffer2(c0)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tx_tunnel_id;

							vec_add1 (buffers_duplicated, vlib_get_buffer_index (vm, c0));
						} else
							vlib_node_increment_counter (vm, node->node_index,
														 PPF_SB_PATH_LB_ERROR_NO_BUF,
														 1);
					}
				}
			} else {
	            u8  sb_id;
				u32 tx_tunnel_id;
				u32 duplicate = 0;

	            for (sb_id = 0; sb_id < MAX_SB_PER_CALL; sb_id++) {
					tx_tunnel_id = callline0->rb.srb.sb_tunnel[sb_id].tunnel_id;
					if (INVALID_TUNNEL_ID == tx_tunnel_id)
						continue;
					
					duplicate++;
					if (1 == duplicate)
						vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tx_tunnel_id;
					else if (duplicate > 1) {
						vlib_buffer_t *c0 = vlib_buffer_copy (vm, b0);
						if (c0) {
							clib_memcpy (c0->opaque2, b0->opaque2, sizeof (b0->opaque2));
							vnet_buffer2(c0)->ppf_du_metadata.tunnel_id[VLIB_TX_TUNNEL] = tx_tunnel_id;

							vec_add1 (buffers_duplicated, vlib_get_buffer_index (vm, c0));
						} else
							vlib_node_increment_counter (vm, node->node_index,
														 PPF_SB_PATH_LB_ERROR_NO_BUF,
														 1);
					}
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


