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
#define foreach_ppf_pdcp_decrypt_error    \
_(DECRYPTED, "good packets decrypted") \
_(NO_SUCH_CALL, "no such call packets") \
_(INVALID_DC, "d/c error packets") \
_(INVALID_SN, "invalid sn packets") \
_(VALIDATE_FAIL, "validation failed packets") \
_(REORDER_WINDOW_FULL, "reorder window full packets") \
_(REORDER_DUPLICATE, "reorder duplicate packets") \
_(BYPASSED, "bypassed packets")



static char * ppf_pdcp_decrypt_error_strings[] = {
#define _(sym,string) string,
  foreach_ppf_pdcp_decrypt_error
#undef _
};

typedef enum {
#define _(sym,str) PPF_PDCP_DECRYPT_ERROR_##sym,
    foreach_ppf_pdcp_decrypt_error
#undef _
    PPF_PDCP_DECRYPT_N_ERROR,
} ppf_pdcp_decrypt_error_t;


typedef struct {
  u32 tunnel_index;
  u32 call_id;
  u32 call_type;
  u32 ue_bearer_id;
  u32 sn;
  u32 hfn;
  u32 integrity_status;
  u32 error;
} ppf_pdcp_decrypt_trace_t;

u8 * format_ppf_pdcp_decrypt_trace  (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  ppf_pdcp_decrypt_trace_t * t = va_arg (*args, ppf_pdcp_decrypt_trace_t *);
  
  s = format (s, "PDCP_DECRYPT: tunnel_index %d, call_id %d (type %U, ue_bearer %x)\nsn %u, hfn %u, integrity_status %d, error %s",
		  t->tunnel_index, t->call_id, 
		  format_ppf_call_type, t->call_type, t->ue_bearer_id,
		  t->sn, t->hfn, t->integrity_status, ppf_pdcp_decrypt_error_strings[t->error]);

  return s;
}

#define BYTES_EQUAL(src, dst, len)    (0 == memcmp((char *)(src), (char *)(dst), (len)))

always_inline uword
ppf_pdcp_decrypt_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t *frame,
		    u32 is_ip4)
{
  ppf_main_t *pm = &ppf_main;
  ppf_gtpu_main_t *gtm = &ppf_gtpu_main; 
  ppf_pdcp_main_t * ppm = &ppf_pdcp_main;
  u32 n_left_from, * from, * to_next;
  ppf_pdcp_decrypt_next_t next_index;
  u32 pkts_processed = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = ppm->pdcp_decrypt_next_index;

  while (n_left_from > 0)
    {
	u32 n_left_to_next;

	vlib_get_next_frame (vm, node, next_index,
				   to_next, n_left_to_next);
				   
#if 0
	while (n_left_from >= 12 && n_left_to_next >= 4)
	  {
	    ppf_pdcp_decrypt_next_t next0 = next_index;
	    ppf_pdcp_decrypt_next_t next1 = next_index;
	    ppf_pdcp_decrypt_next_t next2 = next_index;
	    ppf_pdcp_decrypt_next_t next3 = next_index;
	    u32 bi0, bi1, bi2, bi3;  
	    vlib_buffer_t * b0, * b1, *b2, *b3;	
	    u32 error0 = 0, error1 = 0, error2 = 0, error3 = 0;
	    u32 tunnel_index0, tunnel_index1, tunnel_index2, tunnel_index3;
  	    ppf_gtpu_tunnel_t * t0, * t1, * t2, * t3;
	    u32 call_id0, call_id1, call_id2, call_id3;
  	    ppf_callline_t * c0, * c1, * c2, * c3;
	    ppf_pdcp_session_t * pdcp0, * pdcp1, * pdcp2, *pdcp3;
	    u8 * buf0, * buf1, * buf2, * buf3;
	    u8 dc0, dc1, dc2, dc3;
	    u32 sn0, sn1, sn2, sn3;
	    u32 w0, w1, w2, w3;
	    u32 hfn0, hfn1, hfn2, hfn3;
	    u32 count0, count1, count2, count3;
	    u32 count_last_fwd0, count_last_fwd1, count_last_fwd2, count_last_fwd3;
	    u32 len0, len1, len2, len3;
        ppf_pdcp_security_param_t sp0, sp1, sp2, sp3;
	    u8 xmaci[16];
	    
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

	    buf0 = vlib_buffer_get_current (b0);
	    buf1 = vlib_buffer_get_current (b1);
	    buf2 = vlib_buffer_get_current (b2);
	    buf3 = vlib_buffer_get_current (b3);

	    len0 = vlib_buffer_length_in_chain(vm, b0);
	    len1 = vlib_buffer_length_in_chain(vm, b1);
	    len2 = vlib_buffer_length_in_chain(vm, b2);
	    len3 = vlib_buffer_length_in_chain(vm, b3);

       /* Get tunnel index from buffer */
	    tunnel_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
	    tunnel_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];
	    tunnel_index2 = vnet_buffer(b2)->sw_if_index[VLIB_RX];
	    tunnel_index3 = vnet_buffer(b3)->sw_if_index[VLIB_RX];

        /* Find rx tunnel */
	    t0 = pool_elt_at_index (gtm->tunnels, tunnel_index0);
	    t1 = pool_elt_at_index (gtm->tunnels, tunnel_index1);
	    t2 = pool_elt_at_index (gtm->tunnels, tunnel_index2);
	    t3 = pool_elt_at_index (gtm->tunnels, tunnel_index3);

        /* Handle buffer 0 */
        
        /* Find callline */
	    call_id0 = t0->call_id;
	    if (PREDICT_FALSE(~0 == call_id0)) {
              error0 = PPF_PDCP_DECRYPT_ERROR_NO_SUCH_CALL;
              next0 = PPF_PDCP_DECRYPT_NEXT_DROP;
              goto trace0;
	    }
	    
	    c0 = &(pm->ppf_calline_table[call_id0]);

        /* Find pdcp session */
	    pdcp0 = pool_elt_at_index(ppm->sessions, c0->pdcp.session_id);
	    if (PREDICT_FALSE(0 == pdcp0->header_length)) {
	      error0 = PPF_PDCP_DECRYPT_ERROR_BYPASSED;
	      goto next0;
	    }

        /* Get rx 'dc' and 'sn' from buffer */
	    pdcp0->decap_header (buf0, &dc0, &sn0);
	    if (PREDICT_FALSE(0 == dc0)) {
              error0 = PPF_PDCP_DECRYPT_ERROR_INVALID_DC;
              next0 = PPF_PDCP_DECRYPT_NEXT_DROP;
              goto trace0;
	    }
	    
        w0 = (1 << (pdcp0->sn_length - 1));
        if (sn0 + w0 < pdcp0->rx_last_forwarded_sn)
          hfn0 = pdcp0->rx_hfn + 1;
        else if (sn0 >= pdcp0->rx_last_forwarded_sn + w0)
          hfn0 = pdcp0->rx_hfn - 1;
        
        count0 = PPF_PDCP_COUNT (hfn0, sn0, pdcp0->sn_length);
        count_last_fwd0  = PPF_PDCP_COUNT (pdcp0->rx_hfn, pdcp0->rx_last_forwarded_sn, pdcp0->sn_length);
        if (PREDICT_FALSE(count0 <= count_last_fwd0)) {
          error0 = PPF_PDCP_DECRYPT_ERROR_INVALID_SN;
          next0 = PPF_PDCP_DECRYPT_NEXT_DROP;
          goto trace0;
        }

		sp0.pdcp_sess = pdcp0;
		sp0.count = count0;
		sp0.bearer = PPF_BEARER(c0->ue_bearer_id);
		sp0.dir = PPF_PDCP_DIR_DEC;

        /* Decrypt */
	    len0 = vlib_buffer_length_in_chain(vm, b0);
	    pdcp0->decrypt (buf0 + pdcp0->header_length,
	    	            buf0 + pdcp0->header_length,
	    	            len0 - pdcp0->header_length,
	    	            &sp0);
	    
        /* Validate */
	    pdcp0->validate (buf0, xmaci, len0 - pdcp0->mac_length, &sp0);
	    if (pdcp0->mac_length) {
          b0->current_length -= pdcp0->mac_length;

          if ((*(u32 *)xmaci) == (*(u32 *)(buf0 + len0 - pdcp0->mac_length)))
            vnet_buffer2(b0)->ppf_du_metadata.pdcp.integrity_status = 1;
          else {
            vnet_buffer2(b0)->ppf_du_metadata.pdcp.integrity_status = 2;
            error0 = PPF_PDCP_DECRYPT_ERROR_VALIDATE_FAIL;
            goto next0;
          }
	    }

        /* FIX later!!! reorder here */

	    /* Send to next */
	    if (sn0 < pdcp0->rx_last_forwarded_sn)
              pdcp0->rx_hfn++;
	    
	    pdcp0->rx_last_forwarded_sn = sn0;
	    pdcp0->rx_next_expected_sn  = PPF_PDCP_SN_INC (sn0, pdcp0->sn_length);

        next0:
    	
          vnet_buffer2(b0)->ppf_du_metadata.pdcp.sn = sn0;
          vnet_buffer2(b0)->ppf_du_metadata.pdcp.count = count0;
          vlib_buffer_advance (b0, (word)(pdcp0->header_length));

          if (c0->call_type == PPF_SRB_CALL)
            next0 = PPF_PDCP_DECRYPT_NEXT_PPF_SRB_NB_TX;
          else if (c0->call_type == PPF_DRB_CALL)
            next0 = PPF_PDCP_DECRYPT_NEXT_PPF_GTPU4_ENCAP;

	    trace0:
	    	
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
          {
            if (b0->flags & VLIB_BUFFER_IS_TRACED) 
            {
              ppf_pdcp_decrypt_trace_t *t = 
                vlib_add_trace (vm, node, b0, sizeof (*t));
              t->tunnel_index = tunnel_index0;
              t->call_id = call_id0;
              t->call_type = c0->call_type;
              t->ue_bearer_id = c0->ue_bearer_id;
              t->sn = sn0;
              t->hfn = hfn0;
              t->integrity_status = vnet_buffer2(b0)->ppf_du_metadata.pdcp.integrity_status;
              t->error = error0;
            }
          }

        /* Handle buffer 1 */
        
        /* Find callline */
	    call_id1 = t1->call_id;
	    if (PREDICT_FALSE(~0 == call_id1)) {
              error1 = PPF_PDCP_DECRYPT_ERROR_NO_SUCH_CALL;
              next1 = PPF_PDCP_DECRYPT_NEXT_DROP;
              goto trace1;
	    }
	    
	    c1 = &(pm->ppf_calline_table[call_id1]);

        /* Find pdcp session */
	    pdcp1 = pool_elt_at_index(ppm->sessions, c1->pdcp.session_id);
	    if (PREDICT_FALSE(0 == pdcp1->header_length)) {
	      error1 = PPF_PDCP_DECRYPT_ERROR_BYPASSED;
	      goto next1;
	    }

        /* Get rx 'dc' and 'sn' from buffer */
	    pdcp1->decap_header (buf1, &dc1, &sn1);
        if (PREDICT_FALSE(0 == dc1)) {
          error1 = PPF_PDCP_DECRYPT_ERROR_INVALID_DC;
          next1 = PPF_PDCP_DECRYPT_NEXT_DROP;
          goto trace1;
        }
        
        w1 = (1 << (pdcp1->sn_length - 1));
        if (sn1 + w1 < pdcp1->rx_last_forwarded_sn)
          hfn1 = pdcp1->rx_hfn + 1;
        else if (sn1 >= pdcp1->rx_last_forwarded_sn + w1)
          hfn1 = pdcp1->rx_hfn - 1;
        
        count1 = PPF_PDCP_COUNT (hfn1, sn1, pdcp1->sn_length);
        count_last_fwd1  = PPF_PDCP_COUNT (pdcp1->rx_hfn, pdcp1->rx_last_forwarded_sn, pdcp1->sn_length);
        if (PREDICT_FALSE(count1 <= count_last_fwd1)) {
          error1 = PPF_PDCP_DECRYPT_ERROR_INVALID_SN;
          next1 = PPF_PDCP_DECRYPT_NEXT_DROP;
          goto trace1;
        }

		sp1.pdcp_sess = pdcp1;
		sp1.count = count1;
		sp1.bearer = PPF_BEARER(c1->ue_bearer_id);
		sp1.dir = PPF_PDCP_DIR_DEC;
        
        /* Decrypt */
	    pdcp1->decrypt (buf1 + pdcp1->header_length,
	    	            buf1 + pdcp1->header_length,
	    	            len1 - pdcp1->header_length,
	    	            &sp1);
	    
        /* Validate */
	    pdcp1->validate (buf1, xmaci, len1 - pdcp1->mac_length, &sp1);
	    if (pdcp1->mac_length) {
  	      b1->current_length -= pdcp1->mac_length;

	      if ((*(u32 *)xmaci) == (*(u32 *)(buf1 + len1 - pdcp1->mac_length)))
            vnet_buffer2(b1)->ppf_du_metadata.pdcp.integrity_status = 1;
          else {
            vnet_buffer2(b1)->ppf_du_metadata.pdcp.integrity_status = 2;
            error1 = PPF_PDCP_DECRYPT_ERROR_VALIDATE_FAIL;
            goto next1;
          }
	    }

        /* FIX later!!! reorder here */
        
        /* Send to next */
        if (sn1 < pdcp1->rx_last_forwarded_sn)
          pdcp1->rx_hfn++;
        
        pdcp1->rx_last_forwarded_sn = sn1;
        pdcp1->rx_next_expected_sn  = PPF_PDCP_SN_INC (sn1, pdcp1->sn_length);

	    next1:

          vnet_buffer2(b1)->ppf_du_metadata.pdcp.sn = sn1;
          vnet_buffer2(b1)->ppf_du_metadata.pdcp.count = count1;
          vlib_buffer_advance (b1, (word)(pdcp1->header_length));
          
          if (c1->call_type == PPF_SRB_CALL)
            next1 = PPF_PDCP_DECRYPT_NEXT_PPF_SRB_NB_TX;
          else if (c1->call_type == PPF_DRB_CALL)
            next1 = PPF_PDCP_DECRYPT_NEXT_PPF_GTPU4_ENCAP;
        
        trace1:
   	 
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
          {
            if (b1->flags & VLIB_BUFFER_IS_TRACED) 
            {
              ppf_pdcp_decrypt_trace_t *t = 
                vlib_add_trace (vm, node, b1, sizeof (*t));
              t->tunnel_index = tunnel_index1;
              t->call_id = call_id1;
              t->call_type = c1->call_type;
              t->ue_bearer_id = c1->ue_bearer_id;
              t->sn = sn1;
              t->hfn = hfn1;
              t->integrity_status = vnet_buffer2(b1)->ppf_du_metadata.pdcp.integrity_status;
              t->error = error1;
            }
          }

        /* Handle buffer 2 */

        /* Find callline */
	    call_id2 = t2->call_id;
	    if (PREDICT_FALSE(~0 == call_id2)) {
              error0 = PPF_PDCP_DECRYPT_ERROR_NO_SUCH_CALL;
              next0 = PPF_PDCP_DECRYPT_NEXT_DROP;
              goto trace0;
	    }
	    
	    c2 = &(pm->ppf_calline_table[call_id2]);

        /* Find pdcp session */
	    pdcp2 = pool_elt_at_index(ppm->sessions, c2->pdcp.session_id);
	    if (PREDICT_FALSE(0 == pdcp2->header_length)) {
	      error2 = PPF_PDCP_DECRYPT_ERROR_BYPASSED;
	      goto next2;
	    }

        /* Get rx 'dc' and 'sn' from buffer */
	    pdcp2->decap_header (buf2, &dc2, &sn2);            
        if (PREDICT_FALSE(0 == dc2)) {
          error2 = PPF_PDCP_DECRYPT_ERROR_INVALID_DC;
          next2 = PPF_PDCP_DECRYPT_NEXT_DROP;
          goto trace2;
        }

        w2 = (1 << (pdcp2->sn_length - 1));
        if (sn2 + w2 < pdcp2->rx_last_forwarded_sn)
          hfn2 = pdcp2->rx_hfn + 1;
        else if (sn2 >= pdcp2->rx_last_forwarded_sn + w2)
          hfn2 = pdcp2->rx_hfn - 1;
        
        count2 = PPF_PDCP_COUNT (hfn2, sn2, pdcp2->sn_length);
        count_last_fwd2  = PPF_PDCP_COUNT (pdcp2->rx_hfn, pdcp2->rx_last_forwarded_sn, pdcp2->sn_length);
        if (PREDICT_FALSE(count2 <= count_last_fwd2)) {
          error2 = PPF_PDCP_DECRYPT_ERROR_INVALID_SN;
          next2 = PPF_PDCP_DECRYPT_NEXT_DROP;
          goto trace2;
        }

		sp2.pdcp_sess = pdcp2;
		sp2.count = count2;
		sp2.bearer = PPF_BEARER(c2->ue_bearer_id);
		sp2.dir = PPF_PDCP_DIR_DEC;
        
        /* Decrypt */
	    pdcp2->decrypt (buf2 + pdcp2->header_length,
	    	            buf2 + pdcp2->header_length,
	    	            len2 - pdcp2->header_length,
	    	            &sp2);
	    
        /* Validate */
	    pdcp2->validate (buf2, xmaci, len2 - pdcp2->mac_length, &sp2);
	    if (pdcp2->mac_length) {
	      b2->current_length -= pdcp2->mac_length;

	      if ((*(u32 *)xmaci) == (*(u32 *)(buf2 + len2 - pdcp2->mac_length)))
            vnet_buffer2(b2)->ppf_du_metadata.pdcp.integrity_status = 1;
          else {
            vnet_buffer2(b2)->ppf_du_metadata.pdcp.integrity_status = 2;
            error2 = PPF_PDCP_DECRYPT_ERROR_VALIDATE_FAIL;
            goto next2;
          }
	    }

        /* FIX later!!! reorder here */
        
        /* Send to next */
        if (sn2 < pdcp2->rx_last_forwarded_sn)
          pdcp2->rx_hfn++;
        
        pdcp2->rx_last_forwarded_sn = sn2;
        pdcp2->rx_next_expected_sn  = PPF_PDCP_SN_INC (sn2, pdcp2->sn_length);

        next2:

          vnet_buffer2(b2)->ppf_du_metadata.pdcp.sn = sn2;
          vnet_buffer2(b2)->ppf_du_metadata.pdcp.count = count2;
          vlib_buffer_advance (b2, (word)(pdcp2->header_length));
          
          if (c2->call_type == PPF_SRB_CALL)
            next2 = PPF_PDCP_DECRYPT_NEXT_PPF_SRB_NB_TX;
          else if (c2->call_type == PPF_DRB_CALL)
            next2 = PPF_PDCP_DECRYPT_NEXT_PPF_GTPU4_ENCAP;
        
        trace2:
        
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
          {
            if (b2->flags & VLIB_BUFFER_IS_TRACED) 
            {
              ppf_pdcp_decrypt_trace_t *t = 
                vlib_add_trace (vm, node, b2, sizeof (*t));
              t->tunnel_index = tunnel_index2;
              t->call_id = call_id2;
              t->call_type = c2->call_type;
              t->ue_bearer_id = c2->ue_bearer_id;
              t->sn = sn2;
              t->hfn = hfn2;
              t->integrity_status = vnet_buffer2(b2)->ppf_du_metadata.pdcp.integrity_status;
              t->error = error2;
            }
          }
        
        
        /* Handle buffer 3 */

        /* Find callline */
	    call_id3 = t3->call_id;
	    if (PREDICT_FALSE(~0 == call_id3)) {
              error3 = PPF_PDCP_DECRYPT_ERROR_NO_SUCH_CALL;
              next3 = PPF_PDCP_DECRYPT_NEXT_DROP;
              goto trace3;
	    }
	    
	    c3 = &(pm->ppf_calline_table[call_id3]);

        /* Find pdcp session */
	    pdcp3 = pool_elt_at_index(ppm->sessions, c3->pdcp.session_id);
	    if (PREDICT_FALSE(0 == pdcp3->header_length)) {
	      error3 = PPF_PDCP_DECRYPT_ERROR_BYPASSED;
	      goto next3;
	    }

        /* Get rx 'dc' and 'sn' from buffer */
	    pdcp3->decap_header (buf3, &dc3, &sn3);
        if (PREDICT_FALSE(0 == dc3)) {
          error3 = PPF_PDCP_DECRYPT_ERROR_INVALID_DC;
          next3 = PPF_PDCP_DECRYPT_NEXT_DROP;
          goto trace3;
        }

        w3 = (1 << (pdcp3->sn_length - 1));
        if (sn3 + w3 < pdcp3->rx_last_forwarded_sn)
          hfn3 = pdcp3->rx_hfn + 1;
        else if (sn3 >= pdcp3->rx_last_forwarded_sn + w3)
          hfn3 = pdcp3->rx_hfn - 1;
        
        count3 = PPF_PDCP_COUNT (hfn3, sn3, pdcp3->sn_length);
        count_last_fwd3  = PPF_PDCP_COUNT (pdcp3->rx_hfn, pdcp3->rx_last_forwarded_sn, pdcp3->sn_length);
        if (PREDICT_FALSE(count3 <= count_last_fwd3)) {            
          error3 = PPF_PDCP_DECRYPT_ERROR_INVALID_SN;
          next3 = PPF_PDCP_DECRYPT_NEXT_DROP;
          goto trace3;
        }

		sp3.pdcp_sess = pdcp3;
		sp3.count = count3;
		sp3.bearer = PPF_BEARER(c3->ue_bearer_id);
		sp3.dir = PPF_PDCP_DIR_DEC;
        
        /* Decrypt */
	    pdcp3->decrypt (buf3 + pdcp3->header_length,
	    	            buf3 + pdcp3->header_length,
	    	            len3 - pdcp3->header_length,
	    	            &sp3);
	    
        /* Validate */
	    pdcp3->validate (buf3, xmaci, len3 - pdcp3->mac_length, &sp3);
	    if (pdcp3->mac_length) {
	      b3->current_length -= pdcp3->mac_length;

	      if ((*(u32 *)xmaci) == (*(u32 *)(buf3 + len3 - pdcp3->mac_length)))
            vnet_buffer2(b3)->ppf_du_metadata.pdcp.integrity_status = 1;
          else {
            vnet_buffer2(b3)->ppf_du_metadata.pdcp.integrity_status = 2;
            error3 = PPF_PDCP_DECRYPT_ERROR_VALIDATE_FAIL;
            goto next3;
          }
	    }

        /* FIX later!!! reorder here */
        
        /* Send to next */
        if (sn3 < pdcp3->rx_last_forwarded_sn)
          pdcp3->rx_hfn++;
        
        pdcp3->rx_last_forwarded_sn = sn3;
        pdcp3->rx_next_expected_sn  = PPF_PDCP_SN_INC (sn3, pdcp3->sn_length);

        next3:

          vnet_buffer2(b3)->ppf_du_metadata.pdcp.sn = sn3;
          vnet_buffer2(b3)->ppf_du_metadata.pdcp.count = count3;
          vlib_buffer_advance (b3, (word)(pdcp3->header_length));
          
          if (c3->call_type == PPF_SRB_CALL)
            next3 = PPF_PDCP_DECRYPT_NEXT_PPF_SRB_NB_TX;
          else if (c3->call_type == PPF_DRB_CALL)
            next3 = PPF_PDCP_DECRYPT_NEXT_PPF_GTPU4_ENCAP;
        
        trace3:
        
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
          {
            if (b3->flags & VLIB_BUFFER_IS_TRACED) 
            {
              ppf_pdcp_decrypt_trace_t *t = 
                vlib_add_trace (vm, node, b3, sizeof (*t));
              t->tunnel_index = tunnel_index3;
              t->call_id = call_id3;
              t->call_type = c3->call_type;
              t->ue_bearer_id = c3->ue_bearer_id;
              t->sn = sn3;
              t->hfn = hfn3;
              t->integrity_status = vnet_buffer2(b3)->ppf_du_metadata.pdcp.integrity_status;
              t->error = error3;
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
	    ppf_pdcp_decrypt_next_t next0 = next_index;
	    u32 bi0;
	    vlib_buffer_t * b0;
	    u32 error0 = 0;
	    u32 tunnel_index0;
  	    ppf_gtpu_tunnel_t * t0;
	    u32 call_id0;
  	    ppf_callline_t * c0 = NULL;
	    ppf_pdcp_session_t * pdcp0 = NULL;
	    u8 * buf0;
	    u8 dc0 = 0;
	    u32 sn0 = 0;
	    u32 w0 = 0;
	    u32 hfn0 = 0;
	    u32 count0 = 0;
	    u32 count_last_fwd0 = 0;
	    u32 len0 = 0;
	    ppf_pdcp_security_param_t sp0;
	    u8 xmaci[16];

	    /* speculatively enqueue b0 to the current next frame */
	    bi0 = from[0];
	    to_next[0] = bi0;
	    from += 1;
	    to_next += 1;
	    n_left_from -= 1;
	    n_left_to_next -= 1;

	    b0 = vlib_get_buffer (vm, bi0);
	    buf0 = vlib_buffer_get_current (b0);
	    len0 = vlib_buffer_length_in_chain(vm, b0);

        /* Get tunnel index from buffer */
	    tunnel_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

        /* Find rx tunnel */
	    t0 = pool_elt_at_index (gtm->tunnels, tunnel_index0);

        /* Handle buffer 0 */
        
        /* Find callline */
	    call_id0 = t0->call_id;
	    if (PREDICT_FALSE(~0 == call_id0)) {
              error0 = PPF_PDCP_DECRYPT_ERROR_NO_SUCH_CALL;
              next0 = PPF_PDCP_DECRYPT_NEXT_DROP;
              goto trace00;
	    }
	    
	    c0 = &(pm->ppf_calline_table[call_id0]);

        /* Find pdcp session */
	    pdcp0 = pool_elt_at_index(ppm->sessions, c0->pdcp.session_id);
	    if (PREDICT_FALSE(0 == pdcp0->header_length)) {
	      error0 = PPF_PDCP_DECRYPT_ERROR_BYPASSED;
	      goto next00;
	    }

        /* Get rx 'dc' and 'sn' from buffer */
	    pdcp0->decap_header (buf0, &dc0, &sn0);	    
	    if (PREDICT_FALSE(0 == dc0)) {
              error0 = PPF_PDCP_DECRYPT_ERROR_INVALID_DC;
              next0 = PPF_PDCP_DECRYPT_NEXT_DROP;
              goto trace00;
	    }

        hfn0 = pdcp0->rx_hfn;
		pdcp0->rx_next_expected_sn = sn0; // Fix later!!! bypass reorder for now
        if (PREDICT_FALSE(sn0 != pdcp0->rx_next_expected_sn)) {
          w0 = pdcp0->replay_window;
          if (sn0 + w0 < pdcp0->rx_last_forwarded_sn)
            hfn0 = pdcp0->rx_hfn + 1;
          else if (sn0 >= pdcp0->rx_last_forwarded_sn + w0)
            hfn0 = pdcp0->rx_hfn - 1;

		  count0 = PPF_PDCP_COUNT (hfn0, sn0, pdcp0->sn_length);
		  count_last_fwd0  = PPF_PDCP_COUNT (pdcp0->rx_hfn, pdcp0->rx_last_forwarded_sn, pdcp0->sn_length);
		  if (PREDICT_FALSE((count0 <= count_last_fwd0) || (BITMAP_ON (pdcp0->rx_replay_bitmap, count0)))) {
			error0 = PPF_PDCP_DECRYPT_ERROR_INVALID_SN;
			next0 = PPF_PDCP_DECRYPT_NEXT_DROP;
			goto trace00;
			// Fix later!!! should continue to decrypt/validate and report to the CP, only apply for SRB?
		  }

		  next0 = PPF_PDCP_DECRYPT_NEXT_REORDER;
        } else {
          if (sn0 < pdcp0->rx_last_forwarded_sn)
            hfn0 = pdcp0->rx_hfn + 1;

		  count0 = PPF_PDCP_COUNT (hfn0, sn0, pdcp0->sn_length);
        }
        

		sp0.pdcp_sess = pdcp0;
		sp0.count = count0;
		sp0.bearer = PPF_BEARER(c0->ue_bearer_id);
		sp0.dir = PPF_PDCP_DIR_DEC;

        /* Decrypt */
	    pdcp0->decrypt (buf0 + pdcp0->header_length,
	    	            buf0 + pdcp0->header_length,
	    	            len0 - pdcp0->header_length,
	    	            &sp0);
	    
        /* Validate */
	    if (pdcp0->mac_length) {
          pdcp0->validate (buf0, xmaci, len0 - pdcp0->mac_length, &sp0);
	      b0->current_length -= pdcp0->mac_length;

	      if (BYTES_EQUAL (xmaci, (buf0 + len0 - pdcp0->mac_length), pdcp0->mac_length))
            vnet_buffer2(b0)->ppf_du_metadata.pdcp.integrity_status = 1;
          else {
            vnet_buffer2(b0)->ppf_du_metadata.pdcp.integrity_status = 2;
            error0 = PPF_PDCP_DECRYPT_ERROR_VALIDATE_FAIL;
            next0 = PPF_PDCP_DECRYPT_NEXT_DROP;
            goto trace00;
          }
	    }

        /* FIX later!!! reorder here */
		if (next0 == PPF_PDCP_DECRYPT_NEXT_REORDER) {
          BITMAP_SET (pdcp0->rx_replay_bitmap, count0);
		  if (PREDICT_FALSE(count0 - count_last_fwd0 > vec_len (pdcp0->rx_reorder_buffers))) {
            error0 = PPF_PDCP_DECRYPT_ERROR_REORDER_WINDOW_FULL;
            next0 = PPF_PDCP_DECRYPT_NEXT_DROP;
            goto trace00;
          }

		  if (VEC_ELT_NE (pdcp0->rx_reorder_buffers, count0, INVALID_BUFFER_INDEX)) {
            error0 = PPF_PDCP_DECRYPT_ERROR_REORDER_DUPLICATE;
            next0 = PPF_PDCP_DECRYPT_NEXT_DROP;
            goto trace00;
		  }

		  VEC_SET (pdcp0->rx_reorder_buffers, count0, bi0);
		  goto trace00;
        }

	    /* Send to next */
        if (sn0 < pdcp0->rx_last_forwarded_sn)
          pdcp0->rx_hfn++;

        pdcp0->rx_last_forwarded_sn = sn0;
        pdcp0->rx_next_expected_sn  = PPF_PDCP_SN_INC (sn0, pdcp0->sn_length);

        next00:
    	
          vnet_buffer2(b0)->ppf_du_metadata.pdcp.sn = sn0;
          vnet_buffer2(b0)->ppf_du_metadata.pdcp.count = count0;
          
          vlib_buffer_advance (b0, (word)(pdcp0->header_length));
          
          if (c0->call_type == PPF_SRB_CALL)
            next0 = PPF_PDCP_DECRYPT_NEXT_PPF_SRB_NB_TX;
          else if (c0->call_type == PPF_DRB_CALL)
            next0 = PPF_PDCP_DECRYPT_NEXT_PPF_GTPU4_ENCAP;

	    trace00:
	    	
          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
          {
            if (b0->flags & VLIB_BUFFER_IS_TRACED) 
            {
              ppf_pdcp_decrypt_trace_t *t = 
                vlib_add_trace (vm, node, b0, sizeof (*t));
              t->tunnel_index = tunnel_index0;
              t->call_id = call_id0;
              t->call_type = c0->call_type;
              t->ue_bearer_id = c0->ue_bearer_id;
              t->sn = sn0;
              t->hfn = hfn0;
              t->integrity_status = vnet_buffer2(b0)->ppf_du_metadata.pdcp.integrity_status;
              t->error = error0;
            }
          }

        pkts_processed += 1;

        if (next0 == PPF_PDCP_DECRYPT_NEXT_REORDER) {
		  to_next -= 1;
          continue;
        }
		
        /* verify speculative enqueue, maybe switch current next frame */
        vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
        				 to_next, n_left_to_next,
        				 bi0, next0);

        /* Start to send the buffer reordered */
		if (VEC_ELT_NE (pdcp0->rx_reorder_buffers, count0 + 1, INVALID_BUFFER_INDEX) && (n_left_to_next > 0)) {
          count0 = count0 + 1;
          sn0  = PPF_PDCP_SN (count0, pdcp0->sn_length);
          hfn0 = PPF_PDCP_HFN (count0, pdcp0->sn_length);

		  if (sn0 < pdcp0->rx_last_forwarded_sn)
		  	pdcp0->rx_hfn++;
          pdcp0->rx_last_forwarded_sn = sn0;
          pdcp0->rx_next_expected_sn  = PPF_PDCP_SN_INC (sn0, pdcp0->sn_length);

		  bi0 = VEC_AT (pdcp0->rx_reorder_buffers, count0);
		  to_next[0] = bi0;
		  to_next += 1;
		  n_left_to_next -= 1;

		  next0 = next_index;

          VEC_SET (pdcp0->rx_reorder_buffers, count0, INVALID_BUFFER_INDEX);
		  goto next00;
		}
	  }

	vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}


static uword
ppf_pdcp_decrypt (vlib_main_t * vm,
	      vlib_node_runtime_t * node,
	      vlib_frame_t * frame)
{
  return ppf_pdcp_decrypt_inline (vm, node, frame, /* is_ip4 */ 1);
}

VLIB_NODE_FUNCTION_MULTIARCH (ppf_pdcp_decrypt_node, ppf_pdcp_decrypt)

VLIB_REGISTER_NODE (ppf_pdcp_decrypt_node) = {
  .function = ppf_pdcp_decrypt,
  .name = "ppf_pdcp_decrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_ppf_pdcp_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ppf_pdcp_decrypt_error_strings),
  .error_strings = ppf_pdcp_decrypt_error_strings,
  .n_next_nodes = PPF_PDCP_DECRYPT_N_NEXT,
  .next_nodes = {
#define _(s,n) [PPF_PDCP_DECRYPT_NEXT_##s] = n,
    foreach_ppf_pdcp_decrypt_next
#undef _
  },
};


