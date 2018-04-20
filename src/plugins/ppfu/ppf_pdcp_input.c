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
#define foreach_ppf_pdcp_input_error    \
_(ENCAPSULATED, "good packets encapsulated")


static char * ppf_pdcp_input_error_strings[] = {
#define _(sym,string) string,
  foreach_ppf_pdcp_input_error
#undef _
};

typedef enum {
#define _(sym,str) PPF_PDCP_INPUT_ERROR_##sym,
    foreach_ppf_pdcp_input_error
#undef _
    PPF_PDCP_INPUT_N_ERROR,
} ppf_pdcp_input_error_t;


typedef struct {
  u32 sw_if_index ;
  u32 next_index ; 
} ppf_pdcp_input_trace_t;

u8 * format_ppf_pdcp_input_trace  (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  ppf_pdcp_input_trace_t * t = va_arg (*args, ppf_pdcp_input_trace_t *);
  
  s = format (s, "PDCP_INPUT: sw_if_index %d, next index %d",
              t->sw_if_index, t->next_index);
  return s;
}

always_inline uword
ppf_pdcp_input_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * frame,
		    u32 is_ip4)
{
  u32 n_left_from, * from, * to_next;
  ppf_pdcp_input_next_t next_index;
  u32 pkts_processed = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = ppf_pdcp_main.pdcp_input_next_index;

  while (n_left_from > 0)
    {
	u32 n_left_to_next;

	vlib_get_next_frame (vm, node, next_index,
				   to_next, n_left_to_next);
				   

	while (n_left_from >= 8 && n_left_to_next >= 4)
	  {
	    ppf_pdcp_input_next_t next0 = next_index;
	    ppf_pdcp_input_next_t next1 = next_index;
	    ppf_pdcp_input_next_t next2 = next_index;
	    ppf_pdcp_input_next_t next3 = next_index;
	    u32 sw_if_index0 = 0;
	    u32 sw_if_index1 = 0;
	    u32 sw_if_index2 = 0;
	    u32 sw_if_index3 = 0;
	    u32 bi0, bi1, bi2, bi3;					    //map to pi0, pi1
	    vlib_buffer_t * b0, * b1, *b2, *b3; 	  //map to p0, p1
	    
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

		#if 0 
		//dont know what to prefetch
		// what is the difference between STORE & LOAD
		CLIB_PREFETCH (p4->data, sizeof (en0[0]), STORE);
		CLIB_PREFETCH (p5->data, sizeof (en0[0]), STORE);
		CLIB_PREFETCH (p6->data, sizeof (en0[0]), STORE);
		CLIB_PREFETCH (p7->data, sizeof (en0[0]), STORE);
		#endif
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

	    // ASSERT (b0->current_data == 0);
	    // ASSERT (b1->current_data == 0);
	    // ASSERT (b2->current_data == 0);
	    // ASSERT (b3->current_data == 0);

	    sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
	    sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];
	    sw_if_index2 = vnet_buffer(b2)->sw_if_index[VLIB_RX];
	    sw_if_index3 = vnet_buffer(b3)->sw_if_index[VLIB_RX];

    	    if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
		  if (b0->flags & VLIB_BUFFER_IS_TRACED) 
		  {
			  ppf_pdcp_input_trace_t *t = 
			    vlib_add_trace (vm, node, b0, sizeof (*t));
			  t->sw_if_index = sw_if_index0;
			  t->next_index = next0;			  
	         }
	     }
	  
	  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
	  {
		if (b1->flags & VLIB_BUFFER_IS_TRACED) 
		{
			ppf_pdcp_input_trace_t *t = 
			  vlib_add_trace (vm, node, b1, sizeof (*t));
			t->sw_if_index = sw_if_index1;
			t->next_index = next1;			
		 }
	   }

	   if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
	   {
		if (b2->flags & VLIB_BUFFER_IS_TRACED) 
		{
			ppf_pdcp_input_trace_t *t = 
			  vlib_add_trace (vm, node, b2, sizeof (*t));
			t->sw_if_index = sw_if_index2;
			t->next_index = next2;	    
			
		 }
	   }

         if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
	   {
		if (b3->flags & VLIB_BUFFER_IS_TRACED) 
		{
			ppf_pdcp_input_trace_t *t = 
			  vlib_add_trace (vm, node, b3, sizeof (*t));
			t->sw_if_index = sw_if_index3;
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
	    ppf_pdcp_input_next_t next0 = next_index;
	    u32 sw_if_index0 = 0;
	    u32 bi0;					//map to pi0, pi1
	    vlib_buffer_t * b0;	    //map to p0, p1

	    /* speculatively enqueue b0 to the current next frame */
	    bi0 = from[0];
	    to_next[0] = bi0;
	    from += 1;
	    to_next += 1;
	    n_left_from -= 1;
	    n_left_to_next -= 1;

	    b0 = vlib_get_buffer (vm, bi0);

	    //ASSERT (b0->current_data == 0);
		
	    sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

	    if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
	    {
		  if (b0->flags & VLIB_BUFFER_IS_TRACED) 
		  {
			  ppf_pdcp_input_trace_t *t = 
			    vlib_add_trace (vm, node, b0, sizeof (*t));
			  t->sw_if_index = sw_if_index0;
			  t->next_index = next0;			  
	         }
	     }
 
		
	    /* verify speculative enqueue, maybe switch current next frame */
	    vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
							 to_next, n_left_to_next,
							 bi0, next0);
	  }


	vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}


static uword
ppf_pdcp_input (vlib_main_t * vm,
	      vlib_node_runtime_t * node,
	      vlib_frame_t * frame)
{
  return ppf_pdcp_input_inline (vm, node, frame, /* is_ip4 */ 1);
}


VLIB_NODE_FUNCTION_MULTIARCH (ppf_pdcp_input_node, ppf_pdcp_input)

VLIB_REGISTER_NODE (ppf_pdcp_input_node) = {
  .function = ppf_pdcp_input,
  .name = "ppf_pdcp_input",
  .vector_size = sizeof (u32),
  .format_trace = format_ppf_pdcp_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ppf_pdcp_input_error_strings),
  .error_strings = ppf_pdcp_input_error_strings,
  .n_next_nodes = PPF_PDCP_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [PPF_PDCP_INPUT_NEXT_##s] = n,
    foreach_ppf_pdcp_input_next
#undef _
  },
};


