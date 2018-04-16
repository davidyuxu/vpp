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

#define foreach_ppf_pdcp_encrypt_error    \
_(ENCRYPTED, "good packets encrypted")    \
_(NO_SUCH_CALL, "no such call packets")   \
_(BYPASSED, "bypassed packets")

static char * ppf_pdcp_encrypt_error_strings[] = {
#define _(sym,string) string,
  foreach_ppf_pdcp_encrypt_error
#undef _
};

typedef enum {
#define _(sym,str) PPF_PDCP_ENCRYPT_ERROR_##sym,
    foreach_ppf_pdcp_encrypt_error
#undef _
    PPF_PDCP_ENCRYPT_N_ERROR,
} ppf_pdcp_encrypt_error_t;

typedef struct {
  u32 tunnel_index;
  u32 call_id;
  u32 call_type;
  u32 ue_bearer_id;
  u32 sn;
  u32 count;
  u32 error;
  u32 next_index;
} ppf_pdcp_encrypt_trace_t;

u8 * format_ppf_pdcp_encrypt_trace  (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  ppf_pdcp_encrypt_trace_t * t = va_arg (*args, ppf_pdcp_encrypt_trace_t *);
  
  s = format (s, "PDCP_ENCRYPT: tunnel_index %d, call_id %d (type %U, ue_bearer %x)\nsn %u, count %u, error %s, next_index %d",
		  t->tunnel_index, t->call_id,
		  format_ppf_call_type, t->call_type, t->ue_bearer_id,
		  t->sn, t->count, ppf_pdcp_encrypt_error_strings[t->error], t->next_index);

  return s;
}


always_inline uword
ppf_pdcp_encrypt_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * frame,
		    u32 is_ip4)
{
  ppf_main_t * pm = &ppf_main;
  ppf_gtpu_main_t * gtm = &ppf_gtpu_main;
  ppf_pdcp_main_t * ppm = &ppf_pdcp_main;
  u32 n_left_from, * from, * to_next;
  ppf_pdcp_encrypt_next_t next_index;
  u32 pkts_processed = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = ppm->pdcp_encrypt_next_index;

  while (n_left_from > 0)
    {
	u32 n_left_to_next;

	vlib_get_next_frame (vm, node, next_index,
				   to_next, n_left_to_next);
				   
	while (n_left_from >= 12 && n_left_to_next >= 4)
	  {
	    ppf_pdcp_encrypt_next_t next0 = next_index;
	    ppf_pdcp_encrypt_next_t next1 = next_index;
	    ppf_pdcp_encrypt_next_t next2 = next_index;
	    ppf_pdcp_encrypt_next_t next3 = next_index;
	    u32 bi0, bi1, bi2, bi3;
	    vlib_buffer_t * b0, * b1, *b2, *b3;
	    u32 error0 = 0, error1 = 0, error2 = 0, error3 = 0;
	    u32 tunnel_index0, tunnel_index1, tunnel_index2, tunnel_index3;
	    ppf_gtpu_tunnel_t * t0, * t1, * t2, * t3;
	    ppf_callline_t * c0, * c1, * c2, * c3;
	    ppf_pdcp_session_t * pdcp0, * pdcp1, * pdcp2, *pdcp3;
	    u8 * buf0, * buf1, * buf2, * buf3;
	    u32 count0, count1, count2, count3;
	    u32 sn0, sn1, sn2, sn3;
	    u32 len0, len1, len2, len3;
	    ppf_pdcp_security_param_t sp0, sp1, sp2, sp3;
	    
	    
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

        /* Find context */	    
	    tunnel_index0 = vnet_buffer(b0)->sw_if_index[VLIB_TX];
	    tunnel_index1 = vnet_buffer(b1)->sw_if_index[VLIB_TX];
	    tunnel_index2 = vnet_buffer(b2)->sw_if_index[VLIB_TX];
	    tunnel_index3 = vnet_buffer(b3)->sw_if_index[VLIB_TX];

	    t0 = pool_elt_at_index (gtm->tunnels, tunnel_index0);
	    t1 = pool_elt_at_index (gtm->tunnels, tunnel_index1);
	    t2 = pool_elt_at_index (gtm->tunnels, tunnel_index2);
	    t3 = pool_elt_at_index (gtm->tunnels, tunnel_index3);

	    c0 = &(pm->ppf_calline_table[t0->call_id]);
	    c1 = &(pm->ppf_calline_table[t1->call_id]);
	    c2 = &(pm->ppf_calline_table[t2->call_id]);
	    c3 = &(pm->ppf_calline_table[t3->call_id]);

	    pdcp0 = pool_elt_at_index(ppm->sessions, c0->pdcp.session_id);
	    pdcp1 = pool_elt_at_index(ppm->sessions, c1->pdcp.session_id);
	    pdcp2 = pool_elt_at_index(ppm->sessions, c2->pdcp.session_id);
	    pdcp3 = pool_elt_at_index(ppm->sessions, c3->pdcp.session_id);

        if (PREDICT_TRUE(PPF_DRB_CALL == c0->call_type)) {
			sn0 = pdcp0->tx_next_sn;
			count0 = PPF_PDCP_COUNT (pdcp0->tx_hfn, pdcp0->tx_next_sn, pdcp0->sn_length);
			PPF_PDCP_COUNT_INC (pdcp0->tx_hfn, pdcp0->tx_next_sn, pdcp0->sn_length);
        } else {
			sn0 = vnet_buffer2(b0)->ppf_du_metadata.pdcp.sn;
			count0 = vnet_buffer2(b0)->ppf_du_metadata.pdcp.count;
        }

        if (PREDICT_TRUE(PPF_DRB_CALL == c1->call_type)) {
			sn1 = pdcp1->tx_next_sn;
			count1 = PPF_PDCP_COUNT (pdcp1->tx_hfn, pdcp1->tx_next_sn, pdcp1->sn_length);
			PPF_PDCP_COUNT_INC (pdcp1->tx_hfn, pdcp1->tx_next_sn, pdcp1->sn_length);
        } else {
			sn1 = vnet_buffer2(b1)->ppf_du_metadata.pdcp.sn;
			count1 = vnet_buffer2(b1)->ppf_du_metadata.pdcp.count;
        }

        if (PREDICT_TRUE(PPF_DRB_CALL == c2->call_type)) {
			sn2 = pdcp2->tx_next_sn;
			count2 = PPF_PDCP_COUNT (pdcp2->tx_hfn, pdcp2->tx_next_sn, pdcp2->sn_length);
			PPF_PDCP_COUNT_INC (pdcp2->tx_hfn, pdcp2->tx_next_sn, pdcp2->sn_length);
        } else {
			sn2 = vnet_buffer2(b2)->ppf_du_metadata.pdcp.sn;
			count2 = vnet_buffer2(b2)->ppf_du_metadata.pdcp.count;
        }
		
        if (PREDICT_TRUE(PPF_DRB_CALL == c3->call_type)) {
			sn3 = pdcp3->tx_next_sn;
			count3 = PPF_PDCP_COUNT (pdcp3->tx_hfn, pdcp3->tx_next_sn, pdcp3->sn_length);
			PPF_PDCP_COUNT_INC (pdcp3->tx_hfn, pdcp3->tx_next_sn, pdcp3->sn_length);
        } else {
			sn3 = vnet_buffer2(b3)->ppf_du_metadata.pdcp.sn;
			count3 = vnet_buffer2(b3)->ppf_du_metadata.pdcp.count;
        }
		
        /* Handle packet 0 */
	    
	    if (PREDICT_FALSE(0 == pdcp0->header_length)) {
	      error0 = PPF_PDCP_ENCRYPT_ERROR_BYPASSED;
	      goto next0;
	    }

	    /* Prepend and encap pdcp header */
	    vlib_buffer_advance (b0, -(word)(pdcp0->header_length));
	    buf0 = vlib_buffer_get_current (b0);
	    pdcp0->encap_header (buf0, 1, sn0);

		sp0.pdcp_sess = pdcp0;
		sp0.count = count0;
		sp0.bearer = PPF_BEARER(c0->ue_bearer_id);
		sp0.dir = PPF_PDCP_DIR_ENC;

        /* Integrity */
	    len0 = vlib_buffer_length_in_chain(vm, b0);
	    vlib_buffer_put_uninit (b0, pdcp0->mac_length);
	    pdcp0->protect (buf0, buf0 + len0, len0, &sp0);

        /* Encrypt */
	    len0 = vlib_buffer_length_in_chain(vm, b0);
	    pdcp0->encrypt (buf0 + pdcp0->header_length,
	    	            buf0 + pdcp0->header_length,
	    	            len0 - pdcp0->header_length,
	    	            &sp0);

        next0:
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
          {
            if (b0->flags & VLIB_BUFFER_IS_TRACED) 
            {
              ppf_pdcp_encrypt_trace_t *t = 
                vlib_add_trace (vm, node, b0, sizeof (*t));
              t->tunnel_index = tunnel_index0;
              t->call_id = t0->call_id;
              t->call_type = c0->call_type;
              t->ue_bearer_id = c0->ue_bearer_id;
              t->sn = sn0;
              t->count = count0;
              t->error = error0;
              t->next_index = next0;			  
            }
          }

        /* Handle packet 1 */

	    if (PREDICT_FALSE(0 == pdcp1->header_length)) {
	      error1 = PPF_PDCP_ENCRYPT_ERROR_BYPASSED;
	      goto next1;
	    }

	    /* Prepend and encap pdcp header */
	    vlib_buffer_advance (b1, -(word)(pdcp1->header_length));
	    buf1 = vlib_buffer_get_current (b1);
	    pdcp1->encap_header (buf1, 1, sn1);

		sp1.pdcp_sess = pdcp1;
		sp1.count = count1;
		sp1.bearer = PPF_BEARER(c1->ue_bearer_id);
		sp1.dir = PPF_PDCP_DIR_ENC;

        /* Integrity */
	    len1 = vlib_buffer_length_in_chain(vm, b1);
	    vlib_buffer_put_uninit (b1, pdcp1->mac_length);
	    pdcp1->protect (buf1, buf1 + len1, len1, &sp1);

        /* Encrypt */
	    len1 = vlib_buffer_length_in_chain(vm, b1);
	    pdcp1->encrypt (buf1 + pdcp1->header_length,
	    	            buf1 + pdcp1->header_length,
	    	            len1 - pdcp1->header_length,
	    	            &sp1);
	  
        next1:
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
          {
            if (b1->flags & VLIB_BUFFER_IS_TRACED) 
            {
              ppf_pdcp_encrypt_trace_t *t = 
                vlib_add_trace (vm, node, b1, sizeof (*t));
              t->tunnel_index = tunnel_index1;
              t->call_id = t1->call_id;
              t->call_type = c1->call_type;
              t->ue_bearer_id = c1->ue_bearer_id;
              t->sn = sn1;
              t->count = count1;
              t->error = error1;
              t->next_index = next1;			  
            }
          }

        /* Handle packet 2 */

	    if (PREDICT_FALSE(0 == pdcp2->header_length)) {
	      error2 = PPF_PDCP_ENCRYPT_ERROR_BYPASSED;
	      goto next2;
	    }

	    /* Prepend and encap pdcp header */
	    vlib_buffer_advance (b2, -(word)(pdcp2->header_length));
	    buf2 = vlib_buffer_get_current (b2);
	    pdcp2->encap_header (buf2, 1, sn2);

		sp2.pdcp_sess = pdcp2;
		sp2.count = count2;
		sp2.bearer = PPF_BEARER(c2->ue_bearer_id);
		sp2.dir = PPF_PDCP_DIR_ENC;

        /* Integrity */
	    len2 = vlib_buffer_length_in_chain(vm, b2);
	    vlib_buffer_put_uninit (b2, pdcp2->mac_length);
	    pdcp2->protect (buf2, buf2 + len2, len2, &sp2);

        /* Encrypt */
	    len2 = vlib_buffer_length_in_chain(vm, b2);
	    pdcp2->encrypt (buf2 + pdcp2->header_length,
	    	            buf2 + pdcp2->header_length,
	    	            len2 - pdcp2->header_length,
	    	            &sp2);

        next2:
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
          {
            if (b2->flags & VLIB_BUFFER_IS_TRACED) 
            {
              ppf_pdcp_encrypt_trace_t *t = 
                vlib_add_trace (vm, node, b2, sizeof (*t));
              t->tunnel_index = tunnel_index2;
              t->call_id = t2->call_id;
              t->call_type = c2->call_type;
              t->ue_bearer_id = c2->ue_bearer_id;
              t->sn = sn2;
              t->count = count2;
              t->error = error2;
              t->next_index = next2;			  
            }
          }

        /* Handle packet 3 */

	    if (PREDICT_FALSE(0 == pdcp3->header_length)) {
	      error3 = PPF_PDCP_ENCRYPT_ERROR_BYPASSED;
	      goto next3;
	    }

	    /* Prepend and encap pdcp header */
	    vlib_buffer_advance (b3, -(word)(pdcp3->header_length));
	    buf3 = vlib_buffer_get_current (b3);
	    pdcp3->encap_header (buf3, 1, sn3);

		sp3.pdcp_sess = pdcp3;
		sp3.count = count3;
		sp3.bearer = PPF_BEARER(c3->ue_bearer_id);
		sp3.dir = PPF_PDCP_DIR_ENC;

        /* Integrity */
	    len3 = vlib_buffer_length_in_chain(vm, b3);
	    vlib_buffer_put_uninit (b3, pdcp3->mac_length);
	    pdcp3->protect (buf3, buf3 + len3, len3, &sp3);

        /* Encrypt */
	    len3 = vlib_buffer_length_in_chain(vm, b3);
	    pdcp3->encrypt (buf3 + pdcp3->header_length,
	    	            buf3 + pdcp3->header_length,
	    	            len3 - pdcp3->header_length,
	    	            &sp3);

        next3:
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
          {
            if (b3->flags & VLIB_BUFFER_IS_TRACED) 
            {
              ppf_pdcp_encrypt_trace_t *t = 
                vlib_add_trace (vm, node, b3, sizeof (*t));
              t->tunnel_index = tunnel_index3;
              t->call_id = t3->call_id;
              t->call_type = c3->call_type;
              t->ue_bearer_id = c3->ue_bearer_id;
              t->sn = sn3;
              t->count = count3;
              t->error = error3;
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
	    ppf_pdcp_encrypt_next_t next0 = next_index;
	    u32 bi0;
	    vlib_buffer_t * b0; 
	    u32 error0 = 0;
	    u32 tunnel_index0;
	    ppf_gtpu_tunnel_t * t0;
	    ppf_callline_t * c0;
	    ppf_pdcp_session_t * pdcp0;
	    u8 * buf0;
	    u32 count0;
	    u32 sn0;
	    u32 len0;
	    ppf_pdcp_security_param_t sp0;

	    /* speculatively enqueue b0 to the current next frame */
	    bi0 = from[0];
	    to_next[0] = bi0;
	    from += 1;
	    to_next += 1;
	    n_left_from -= 1;
	    n_left_to_next -= 1;

	    b0 = vlib_get_buffer (vm, bi0);

        /* Find context */
	    tunnel_index0 = vnet_buffer(b0)->sw_if_index[VLIB_TX];
	    t0 = pool_elt_at_index (gtm->tunnels, tunnel_index0);
	    c0 = &(pm->ppf_calline_table[t0->call_id]);
	    pdcp0 = pool_elt_at_index(ppm->sessions, c0->pdcp.session_id);

        if (PREDICT_TRUE(PPF_DRB_CALL == c0->call_type)) {
			sn0 = pdcp0->tx_next_sn;
			count0 = PPF_PDCP_COUNT (pdcp0->tx_hfn, pdcp0->tx_next_sn, pdcp0->sn_length);
			PPF_PDCP_COUNT_INC (pdcp0->tx_hfn, pdcp0->tx_next_sn, pdcp0->sn_length);
        } else {
			sn0 = vnet_buffer2(b0)->ppf_du_metadata.pdcp.sn;
			count0 = vnet_buffer2(b0)->ppf_du_metadata.pdcp.count;
        }

	    if (PREDICT_FALSE(0 == pdcp0->header_length)) {
	      error0 = PPF_PDCP_ENCRYPT_ERROR_BYPASSED;
	      goto next00;
	    }

        /* Prepend and encap pdcp header */
	    vlib_buffer_advance (b0, -(word)(pdcp0->header_length));
	    buf0 = vlib_buffer_get_current (b0);
	    pdcp0->encap_header (buf0, 1, sn0);

		sp0.pdcp_sess = pdcp0;
		sp0.count = count0;
		sp0.bearer = PPF_BEARER(c0->ue_bearer_id);
		sp0.dir = PPF_PDCP_DIR_ENC;

        /* Integrity */
	    len0 = vlib_buffer_length_in_chain(vm, b0);
	    vlib_buffer_put_uninit (b0, pdcp0->mac_length);
	    pdcp0->protect (buf0, buf0 + len0, len0, &sp0);

        /* Encrypt */
	    len0 = vlib_buffer_length_in_chain(vm, b0);
	    pdcp0->encrypt (buf0 + pdcp0->header_length,
	    	            buf0 + pdcp0->header_length,
	    	            len0 - pdcp0->header_length,
	    	            &sp0);

        next00:
			
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
          {
            if (b0->flags & VLIB_BUFFER_IS_TRACED) 
            {
              ppf_pdcp_encrypt_trace_t *t = 
                vlib_add_trace (vm, node, b0, sizeof (*t));
              t->tunnel_index = tunnel_index0;
              t->call_id = t0->call_id;
              t->call_type = c0->call_type;
              t->ue_bearer_id = c0->ue_bearer_id;
              t->sn = sn0;
              t->count = count0;
              t->error = error0;
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

  return frame->n_vectors;
}


static uword
ppf_pdcp_encrypt (vlib_main_t * vm,
	      vlib_node_runtime_t * node,
	      vlib_frame_t * frame)
{
  return ppf_pdcp_encrypt_inline (vm, node, frame, /* is_ip4 */ 1);
}


VLIB_NODE_FUNCTION_MULTIARCH (ppf_pdcp_encrypt_node, ppf_pdcp_encrypt)

VLIB_REGISTER_NODE (ppf_pdcp_encrypt_node) = {
  .function = ppf_pdcp_encrypt,
  .name = "ppf_pdcp_encrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_ppf_pdcp_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ppf_pdcp_encrypt_error_strings),
  .error_strings = ppf_pdcp_encrypt_error_strings,
  .n_next_nodes = PPF_PDCP_ENCRYPT_N_NEXT,
  .next_nodes = {
#define _(s,n) [PPF_PDCP_ENCRYPT_NEXT_##s] = n,
    foreach_ppf_pdcp_encrypt_next
#undef _
  },
};


