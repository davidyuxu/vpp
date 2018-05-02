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
_(REORDERED, "reordered packets") \
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
  u32 next_index;
} ppf_pdcp_decrypt_trace_t;

u8 * format_ppf_pdcp_decrypt_trace  (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  ppf_pdcp_decrypt_trace_t * t = va_arg (*args, ppf_pdcp_decrypt_trace_t *);
  
  s = format (s, "PDCP_DECRYPT: tunnel_index %d, call_id %d (type %U, ue_bearer %x)\nsn %u, hfn %u, integrity_status %d, error %s, next_index %d",
		  t->tunnel_index, t->call_id, 
		  format_ppf_call_type, t->call_type, t->ue_bearer_id,
		  t->sn, t->hfn, t->integrity_status, ppf_pdcp_decrypt_error_strings[t->error], t->next_index);

  return s;
}

#define BYTES_EQUAL(s, d, l)          (0 == memcmp((char *)(s), (char *)(d), (l)))
#define WORD_EQUAL(s, d)              (((s)[0] == (d)[0]) && ((s)[1] == (d)[1]) && ((s)[2] == (d)[2]) && ((s)[3] == (d)[3]))
#define PDCP_MAC_VALIDATE(s, d, l)    ((4 == (l)) ? WORD_EQUAL(s,d) : BYTES_EQUAL(s,d,l))

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
	while (n_left_from >= 4 && n_left_to_next >= 2)
	  {
	    ppf_pdcp_decrypt_next_t next0 = next_index;
	    ppf_pdcp_decrypt_next_t next1 = next_index;
        u32 reorder0 = 0, reorder1 = 0;
	    u32 bi0, bi1;  
	    vlib_buffer_t * b0, * b1;	
	    u32 error0 = 0, error1 = 0;
	    u32 tunnel_index0, tunnel_index1;
  	    ppf_gtpu_tunnel_t * t0, * t1;
	    u32 call_id0, call_id1;
  	    ppf_callline_t * c0, * c1;
	    ppf_pdcp_session_t * pdcp0, * pdcp1;
	    u8 * buf0, * buf1;
	    u8 dc0, dc1;
	    u32 sn0, sn1;
	    u32 w0, w1;
	    u32 hfn0, hfn1;
	    u32 count0, count1;
	    u32 count_last_fwd0, count_last_fwd1;
	    u32 len0, len1;
        ppf_pdcp_security_param_t sp0, sp1;
	    u8 xmaci[16];
	    
	    /* Prefetch next iteration. */
	    {
          vlib_buffer_t * p2, * p3;
          
          p2 = vlib_get_buffer (vm, from[2]);
          p3 = vlib_get_buffer (vm, from[3]);
          
          vlib_prefetch_buffer_header (p2, LOAD);
          vlib_prefetch_buffer_header (p3, LOAD);
          
          vlib_prefetch_buffer_header (p2, LOAD);
          vlib_prefetch_buffer_header (p3, LOAD);
	    }

	    /* speculatively enqueue b0 and b1 to the current next frame */
	    to_next[0] = bi0 = from[0];
	    to_next[1] = bi1 = from[1];
	    from += 2;
	    to_next += 2;
	    n_left_from -= 2;
	    n_left_to_next -= 2;

	    b0 = vlib_get_buffer (vm, bi0);
	    b1 = vlib_get_buffer (vm, bi1);

	    buf0 = vlib_buffer_get_current (b0);
	    buf1 = vlib_buffer_get_current (b1);

	    len0 = vlib_buffer_length_in_chain(vm, b0);
	    len1 = vlib_buffer_length_in_chain(vm, b1);

        /* Initialize reorder flag */
        reorder0 = 0;
        reorder1 = 0;

        /* Get tunnel index from buffer */
	    tunnel_index0 = vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_RX_TUNNEL];
	    tunnel_index1 = vnet_buffer2(b1)->ppf_du_metadata.tunnel_id[VLIB_RX_TUNNEL];

        /* Find rx tunnel */
	    t0 = pool_elt_at_index (gtm->tunnels, tunnel_index0);
	    t1 = pool_elt_at_index (gtm->tunnels, tunnel_index1);

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
#if 0 /* skip dc check for now */
	    if (PREDICT_FALSE(0 == dc0)) {
          error0 = PPF_PDCP_DECRYPT_ERROR_INVALID_DC;
          next0 = PPF_PDCP_DECRYPT_NEXT_DROP;
          goto trace0;
	    }
#endif

        hfn0 = pdcp0->rx_hfn;

		if (!ppm->rx_reorder)
          pdcp0->rx_next_expected_sn = sn0;

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
			goto trace0;
			// Fix later!!! should continue to decrypt/validate and report to the CP, only apply for SRB?
		  }

		  reorder0 = 1;
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
          if(pdcp0->validate (vm, b0, &sp0))
            vnet_buffer2(b0)->ppf_du_metadata.pdcp.integrity_status = 1;
          else {
            vnet_buffer2(b0)->ppf_du_metadata.pdcp.integrity_status = 2;
            error0 = PPF_PDCP_DECRYPT_ERROR_VALIDATE_FAIL;
            next0 = PPF_PDCP_DECRYPT_NEXT_DROP;
            goto trace0;
          }
	    }

        if (reorder0) {
          BITMAP_SET (pdcp0->rx_replay_bitmap, count0);
          if (PREDICT_FALSE(count0 - count_last_fwd0 > vec_len (pdcp0->rx_reorder_buffers))) {
            error0 = PPF_PDCP_DECRYPT_ERROR_REORDER_WINDOW_FULL;
            next0 = PPF_PDCP_DECRYPT_NEXT_DROP;
            goto trace0;
          }
          
          if (VEC_ELT_NE (pdcp0->rx_reorder_buffers, count0, INVALID_BUFFER_INDEX)) {
            error0 = PPF_PDCP_DECRYPT_ERROR_REORDER_DUPLICATE;
            next0 = PPF_PDCP_DECRYPT_NEXT_DROP;
            goto trace0;
          }
          
          vnet_buffer2(b0)->ppf_du_metadata.pdcp.sn = sn0;
          vnet_buffer2(b0)->ppf_du_metadata.pdcp.count = count0;
          
          vlib_buffer_advance (b0, (word)(pdcp0->header_length));

          VEC_SET (pdcp0->rx_reorder_buffers, count0, bi0);
          error0 = PPF_PDCP_DECRYPT_ERROR_REORDERED;
          goto trace0;
        }

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
              t->next_index = next0;
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
#if 0 /* skip dc check for now */
	    if (PREDICT_FALSE(0 == dc1)) {
          error1 = PPF_PDCP_DECRYPT_ERROR_INVALID_DC;
          next1 = PPF_PDCP_DECRYPT_NEXT_DROP;
          goto trace1;
	    }
#endif

        hfn1 = pdcp1->rx_hfn;

		if (!ppm->rx_reorder)
          pdcp1->rx_next_expected_sn = sn1;

        if (PREDICT_FALSE(sn1 != pdcp1->rx_next_expected_sn)) {
          w1 = pdcp1->replay_window;
          if (sn1 + w1 < pdcp1->rx_last_forwarded_sn)
            hfn1 = pdcp1->rx_hfn + 1;
          else if (sn1 >= pdcp1->rx_last_forwarded_sn + w1)
            hfn1 = pdcp1->rx_hfn - 1;

		  count1 = PPF_PDCP_COUNT (hfn1, sn1, pdcp1->sn_length);
		  count_last_fwd1  = PPF_PDCP_COUNT (pdcp1->rx_hfn, pdcp1->rx_last_forwarded_sn, pdcp1->sn_length);
		  if (PREDICT_FALSE((count1 <= count_last_fwd1) || (BITMAP_ON (pdcp1->rx_replay_bitmap, count1)))) {
			error1 = PPF_PDCP_DECRYPT_ERROR_INVALID_SN;
			next1 = PPF_PDCP_DECRYPT_NEXT_DROP;
			goto trace1;
			// Fix later!!! should continue to decrypt/validate and report to the CP, only apply for SRB?
		  }

		  reorder1 = 1;
        } else {
          if (sn1 < pdcp1->rx_last_forwarded_sn)
            hfn1 = pdcp1->rx_hfn + 1;

		  count1 = PPF_PDCP_COUNT (hfn1, sn1, pdcp1->sn_length);
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
        if (pdcp1->mac_length) {
          if(pdcp1->validate (vm, b1, &sp1))
            vnet_buffer2(b1)->ppf_du_metadata.pdcp.integrity_status = 1;
          else {
            vnet_buffer2(b1)->ppf_du_metadata.pdcp.integrity_status = 2;
            error1 = PPF_PDCP_DECRYPT_ERROR_VALIDATE_FAIL;
            next1 = PPF_PDCP_DECRYPT_NEXT_DROP;
            goto trace1;
          }
	}

        if (reorder1) {
          BITMAP_SET (pdcp1->rx_replay_bitmap, count1);
          if (PREDICT_FALSE(count1 - count_last_fwd1 > vec_len (pdcp1->rx_reorder_buffers))) {
            error1 = PPF_PDCP_DECRYPT_ERROR_REORDER_WINDOW_FULL;
            next1 = PPF_PDCP_DECRYPT_NEXT_DROP;
            goto trace1;
          }
          
          if (VEC_ELT_NE (pdcp1->rx_reorder_buffers, count1, INVALID_BUFFER_INDEX)) {
            error1 = PPF_PDCP_DECRYPT_ERROR_REORDER_DUPLICATE;
            next1 = PPF_PDCP_DECRYPT_NEXT_DROP;
            goto trace1;
          }
          
          vnet_buffer2(b1)->ppf_du_metadata.pdcp.sn = sn1;
          vnet_buffer2(b1)->ppf_du_metadata.pdcp.count = count1;
          
          vlib_buffer_advance (b1, (word)(pdcp1->header_length));

          VEC_SET (pdcp1->rx_reorder_buffers, count1, bi1);
          error1 = PPF_PDCP_DECRYPT_ERROR_REORDERED;
          goto trace1;
        }
        
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
              t->next_index = next1;
            }
          }

        pkts_processed += 2;

        if (reorder0 && reorder1) {
          to_next -= 2;
          n_left_to_next += 2;
          continue;
        }
	 
        /* verify speculative enqueues, maybe switch current next frame */
        if ((0 == reorder0) && (0 == reorder1))
          vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, bi1, next0, next1);
        else if (0 == reorder0)
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, next0);
        else
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi1, next1);

        /* Start to send the buffer reordered - pdcp0 */
        while (VEC_ELT_NE (pdcp0->rx_reorder_buffers, count0 + 1, INVALID_BUFFER_INDEX)) {		
          next0 = next_index;
          while (VEC_ELT_NE (pdcp0->rx_reorder_buffers, count0 + 1, INVALID_BUFFER_INDEX) && (n_left_to_next > 0)) {
            bi0 = VEC_AT (pdcp0->rx_reorder_buffers, count0 + 1);
            VEC_SET (pdcp0->rx_reorder_buffers, count0 + 1, INVALID_BUFFER_INDEX);
          
            b0  = vlib_get_buffer (vm, bi0);		  
            ASSERT((count0 + 1) == vnet_buffer2(b0)->ppf_du_metadata.pdcp.count);
            sn0  = vnet_buffer2(b0)->ppf_du_metadata.pdcp.sn;
            count0 = vnet_buffer2(b0)->ppf_du_metadata.pdcp.count;
          
            if (sn0 < pdcp0->rx_last_forwarded_sn)
              pdcp0->rx_hfn++;
            pdcp0->rx_last_forwarded_sn = sn0;
            pdcp0->rx_next_expected_sn  = PPF_PDCP_SN_INC (sn0, pdcp0->sn_length);
          
            to_next[0] = bi0;
            to_next += 1;
            n_left_to_next -= 1;
          				  
            if (c0->call_type == PPF_SRB_CALL)
              next0 = PPF_PDCP_DECRYPT_NEXT_PPF_SRB_NB_TX;
            else if (c0->call_type == PPF_DRB_CALL)
              next0 = PPF_PDCP_DECRYPT_NEXT_PPF_GTPU4_ENCAP;
          			  
            /* verify speculative enqueue, maybe switch current next frame */
            vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                             to_next, n_left_to_next,
                                             bi0, next0);
          }
          
          vlib_put_next_frame (vm, node, next_index, n_left_to_next); 		 
          vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
        }

        /* Start to send the buffer reordered - pdcp1 */
        while (VEC_ELT_NE (pdcp1->rx_reorder_buffers, count1 + 1, INVALID_BUFFER_INDEX)) {	  
          next1 = next_index;
          while (VEC_ELT_NE (pdcp1->rx_reorder_buffers, count1 + 1, INVALID_BUFFER_INDEX) && (n_left_to_next > 0)) {
            bi1 = VEC_AT (pdcp1->rx_reorder_buffers, count1 + 1);
            VEC_SET (pdcp1->rx_reorder_buffers, count1 + 1, INVALID_BUFFER_INDEX);
          
            b1  = vlib_get_buffer (vm, bi1);			
            ASSERT((count1 + 1) == vnet_buffer2(b1)->ppf_du_metadata.pdcp.count);
            sn1  = vnet_buffer2(b1)->ppf_du_metadata.pdcp.sn;
            count1 = vnet_buffer2(b1)->ppf_du_metadata.pdcp.count;
          
            if (sn1 < pdcp1->rx_last_forwarded_sn)
              pdcp1->rx_hfn++;
            pdcp1->rx_last_forwarded_sn = sn1;
            pdcp1->rx_next_expected_sn  = PPF_PDCP_SN_INC (sn1, pdcp1->sn_length);
          
            to_next[0] = bi1;
            to_next += 1;
            n_left_to_next -= 1;
          				
            if (c1->call_type == PPF_SRB_CALL)
              next1 = PPF_PDCP_DECRYPT_NEXT_PPF_SRB_NB_TX;
            else if (c1->call_type == PPF_DRB_CALL)
              next1 = PPF_PDCP_DECRYPT_NEXT_PPF_GTPU4_ENCAP;
          			
            /* verify speculative enqueue, maybe switch current next frame */
            vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                             to_next, n_left_to_next,
                                             bi1, next1);
          }
          
          vlib_put_next_frame (vm, node, next_index, n_left_to_next); 	   
          vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
        }
	  }
#endif

	while (n_left_from > 0 && n_left_to_next > 0)
	  {
        ppf_pdcp_decrypt_next_t next0 = next_index;
        u32 reorder0 = 0;
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

        /* Initialize reorder flag */
        reorder0 = 0;
        
        /* Get tunnel index from buffer */
        tunnel_index0 = vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_RX_TUNNEL];
        
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
		#if 0 /* skip dc check for now */
	    if (PREDICT_FALSE(0 == dc0)) {
          error0 = PPF_PDCP_DECRYPT_ERROR_INVALID_DC;
          next0 = PPF_PDCP_DECRYPT_NEXT_DROP;
          goto trace00;
	    }
		#endif

        hfn0 = pdcp0->rx_hfn;

		if (!ppm->rx_reorder)
          pdcp0->rx_next_expected_sn = sn0;

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

		  reorder0 = 1;
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
          if(pdcp0->validate (vm, b0, &sp0))
            vnet_buffer2(b0)->ppf_du_metadata.pdcp.integrity_status = 1;
          else {
            vnet_buffer2(b0)->ppf_du_metadata.pdcp.integrity_status = 2;
            error0 = PPF_PDCP_DECRYPT_ERROR_VALIDATE_FAIL;
            next0 = PPF_PDCP_DECRYPT_NEXT_DROP;
            goto trace00;
          }
	    }

        if (reorder0) {
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
          
          vnet_buffer2(b0)->ppf_du_metadata.pdcp.sn = sn0;
          vnet_buffer2(b0)->ppf_du_metadata.pdcp.count = count0;
          
          vlib_buffer_advance (b0, (word)(pdcp0->header_length));

          VEC_SET (pdcp0->rx_reorder_buffers, count0, bi0);
          error0 = PPF_PDCP_DECRYPT_ERROR_REORDERED;
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

          if (c0->lbo_mode == PPF_LBO_MODE)
          	vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_RX_TUNNEL] = ~0;
          
          if (c0->call_type == PPF_SRB_CALL) {
            next0 = PPF_PDCP_DECRYPT_NEXT_PPF_SRB_NB_TX;
          } else if (c0->call_type == PPF_DRB_CALL) {
            if (c0->lbo_mode == PPF_LBO_MODE)
			  next0 = PPF_PDCP_DECRYPT_NEXT_IP4_LOOKUP;
          	else         	
        	  next0 = PPF_PDCP_DECRYPT_NEXT_PPF_GTPU4_ENCAP;
       	  }

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
			  t->next_index = next0;
            }
          }

        pkts_processed += 1;

        if (reorder0) {
		  to_next -= 1;
          n_left_to_next += 1;
          continue;
        }
		
        /* verify speculative enqueue, maybe switch current next frame */
        vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
        				 to_next, n_left_to_next,
        				 bi0, next0);

        /* Start to send the buffer reordered */
        while (VEC_ELT_NE (pdcp0->rx_reorder_buffers, count0 + 1, INVALID_BUFFER_INDEX)) {		  
          next0 = next_index;
          while (VEC_ELT_NE (pdcp0->rx_reorder_buffers, count0 + 1, INVALID_BUFFER_INDEX) && (n_left_to_next > 0)) {
            bi0 = VEC_AT (pdcp0->rx_reorder_buffers, count0 + 1);
        	VEC_SET (pdcp0->rx_reorder_buffers, count0 + 1, INVALID_BUFFER_INDEX);
        
        	b0  = vlib_get_buffer (vm, bi0);		
            ASSERT((count0 + 1) == vnet_buffer2(b0)->ppf_du_metadata.pdcp.count);
        	sn0  = vnet_buffer2(b0)->ppf_du_metadata.pdcp.sn;
        	count0 = vnet_buffer2(b0)->ppf_du_metadata.pdcp.count;
          
            if (sn0 < pdcp0->rx_last_forwarded_sn)
              pdcp0->rx_hfn++;
        	pdcp0->rx_last_forwarded_sn = sn0;
        	pdcp0->rx_next_expected_sn	= PPF_PDCP_SN_INC (sn0, pdcp0->sn_length);
          
        	to_next[0] = bi0;
        	to_next += 1;
        	n_left_to_next -= 1;
          		  			
			if (c0->lbo_mode == PPF_LBO_MODE)
			  vnet_buffer2(b0)->ppf_du_metadata.tunnel_id[VLIB_RX_TUNNEL] = ~0;
			
			if (c0->call_type == PPF_SRB_CALL) {
			  next0 = PPF_PDCP_DECRYPT_NEXT_PPF_SRB_NB_TX;
			} else if (c0->call_type == PPF_DRB_CALL) {
			  if (c0->lbo_mode == PPF_LBO_MODE)
				next0 = PPF_PDCP_DECRYPT_NEXT_IP4_LOOKUP;
			  else			  
				next0 = PPF_PDCP_DECRYPT_NEXT_PPF_GTPU4_ENCAP;
			}
                        
            /* verify speculative enqueue, maybe switch current next frame */
            vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                             to_next, n_left_to_next,
                                             bi0, next0);
          }
        
          vlib_put_next_frame (vm, node, next_index, n_left_to_next);          
          vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
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


