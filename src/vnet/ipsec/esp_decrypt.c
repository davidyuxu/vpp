/*
 * esp_decrypt.c : IPSec ESP decrypt node
 *
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/esp.h>

#define foreach_esp_decrypt_next                \
_(DROP, "error-drop")                           \
_(IP4_INPUT, "ip4-input")                       \
_(IP6_INPUT, "ip6-input")                       \
_(IPSEC_GRE_INPUT, "ipsec-gre-input")

#define _(v, s) ESP_DECRYPT_NEXT_##v,
typedef enum
{
  foreach_esp_decrypt_next
#undef _
    ESP_DECRYPT_N_NEXT,
} esp_decrypt_next_t;


#define foreach_esp_decrypt_error                   \
 _(RX_PKTS, "ESP pkts received")                    \
 _(DECRYPTION_FAILED, "ESP decryption failed")      \
 _(LENGTH_ERROR, "ESP Invalid Length") 		 					\
 _(TRAILER_ERROR, "ESP Invalid Tailer") 						\
 _(INTEG_ERROR, "Integrity check failed")           \
 _(REPLAY, "SA replayed packet")                    \
 _(NOT_IP, "Not IP packet (dropped)")


typedef enum
{
#define _(sym,str) ESP_DECRYPT_ERROR_##sym,
  foreach_esp_decrypt_error
#undef _
    ESP_DECRYPT_N_ERROR,
} esp_decrypt_error_t;

static char *esp_decrypt_error_strings[] = {
#define _(sym,string) string,
  foreach_esp_decrypt_error
#undef _
};

typedef struct
{
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;
} esp_decrypt_trace_t;

/* packet trace format function */
static u8 *
format_esp_decrypt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  esp_decrypt_trace_t *t = va_arg (*args, esp_decrypt_trace_t *);

  s = format (s, "esp: crypto %U integrity %U",
	      format_ipsec_crypto_alg, t->crypto_alg,
	      format_ipsec_integ_alg, t->integ_alg);
  return s;
}

always_inline void
esp_decrypt_cbc (ipsec_sa_t * sa, int thread_index, u8 * in, size_t in_len,
		 u8 * iv)
{
  EVP_CIPHER_CTX *ctx = sa->context[thread_index].cipher_ctx;

  int out_len;

#ifdef IPSEC_DEBUG_OUTPUT
  ipsec_main_t *im = &ipsec_main;
  if (PREDICT_FALSE (im->debug_fformat))
    fformat (stdout, "Before DE: %U\n", format_hexdump, in, in_len);
#endif

  ASSERT (sa->crypto_alg < IPSEC_CRYPTO_N_ALG
	  && sa->crypto_alg > IPSEC_CRYPTO_ALG_NONE);

  EVP_CipherInit_ex (ctx, NULL, NULL, NULL, iv, -1);

  EVP_CipherUpdate (ctx, in, &out_len, in, in_len);

#ifdef IPSEC_DEBUG_OUTPUT
  if (PREDICT_FALSE (im->debug_fformat))
    fformat (stdout, "After DE: %U\n", format_hexdump, in, in_len);
#endif

  //EVP_CipherFinal_ex (ctx, out + out_len, &out_len);

  //fformat (stdout, "After DE: rv=%d outlen=%d\n", rv, out_len);
}

always_inline int
esp_decrypt_gcm (ipsec_sa_t * sa, int thread_index, u8 * in, size_t in_len,
		 u8 * iv, u8 * aad, size_t aad_len, u8 * tag)
{
  EVP_CIPHER_CTX *ctx = sa->context[thread_index].cipher_ctx;

  int out_len;

  //fformat (stdout, "Before DE: %U\n", format_hexdump, in, in_len);

  ASSERT (sa->crypto_alg < IPSEC_CRYPTO_N_ALG
	  && sa->crypto_alg > IPSEC_CRYPTO_ALG_NONE);

  /* Specify IV */
  EVP_CipherInit_ex (ctx, NULL, NULL, NULL, iv, -1);

  /* Zero or more calls to specify any AAD */
  EVP_CipherUpdate (ctx, NULL, &out_len, aad, aad_len);

  /* Decrypt plaintext */
  EVP_CipherUpdate (ctx, in, &out_len, in, in_len);

  //fformat (stdout, "After DE: %U\n", format_hexdump, out, in_len);

  /* Set expected tag value. */
  EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *) tag);

  /* Finalise: note get no output for GCM */
  int rv = EVP_CipherFinal_ex (ctx, in + out_len, &out_len);

  //fformat (stdout, "GCM TAG: %U\n rv=%d outen=%d\n", format_hexdump, tag, 16, rv, out_len);

  return rv;
}


static uword
esp_decrypt_node_fn (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, next_index, *to_next;
  ipsec_main_t *im = &ipsec_main;
  ipsec_proto_main_t *em = &ipsec_proto_main;
  int thread_id = vlib_get_thread_index ();

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  //u32 thread_index = vlib_get_thread_index ();

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 i_bi0, next0;
	  vlib_buffer_t *i_b0;

	  esp_header_t *esp0;
	  ipsec_sa_t *sa0;
	  u32 sa_index0 = ~0;
	  u32 seq;
	  ip4_header_t *ih4 = 0;
	  ip6_header_t *ih6 = 0;

	  esp_footer_t *f0;

	  i_bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  next0 = ESP_DECRYPT_NEXT_DROP;

	  i_b0 = vlib_get_buffer (vm, i_bi0);

	  /* we start with esp headers */
	  esp0 = vlib_buffer_get_current (i_b0);

	  sa_index0 = vnet_buffer (i_b0)->ipsec.sad_index;
	  sa0 = pool_elt_at_index (im->sad, sa_index0);

	  /* make sure we have sa context initialized */
	  ipsec_make_sa_contexts (thread_id, sa0, 0);

	  const int BLOCK_SIZE =
	    em->ipsec_proto_main_crypto_algs[sa0->crypto_alg].block_size;;
	  const int IV_SIZE =
	    em->ipsec_proto_main_crypto_algs[sa0->crypto_alg].iv_size;

	  seq = clib_host_to_net_u32 (esp0->seq);

	  /* anti-replay check */
	  if (sa0->use_anti_replay)
	    {
	      int rv = 0;

	      if (PREDICT_TRUE (sa0->use_esn))
		rv = esp_replay_check_esn (sa0, seq);
	      else
		rv = esp_replay_check (sa0, seq);

	      if (PREDICT_FALSE (rv))
		{
		  //clib_warning ("anti-replay SPI %u seq %u", sa0->spi, seq);
		  vlib_node_increment_counter (vm, esp_decrypt_node.index,
					       ESP_DECRYPT_ERROR_REPLAY, 1);
		  to_next[0] = i_bi0;
		  to_next += 1;
		  goto trace;
		}
	    }

	  sa0->total_data_size += i_b0->current_length;

	  /* MAC here */
	  MAC_FUNC mac = 0;

	  switch (sa0->integ_alg)
	    {
	    case IPSEC_INTEG_ALG_NONE:
	    default:
	      break;
	    case IPSEC_INTEG_ALG_MD5_96:
	    case IPSEC_INTEG_ALG_SHA1_96:
	    case IPSEC_INTEG_ALG_SHA_256_96:
	    case IPSEC_INTEG_ALG_SHA_256_128:
	    case IPSEC_INTEG_ALG_SHA_384_192:
	      mac = hmac_calc;
	      break;
	    case IPSEC_INTEG_ALG_AES_CMAC:
	      mac = cmac_calc;
	      break;
	    }

	  if (PREDICT_TRUE (mac != 0))
	    {
	      u8 sig[64];

	      int icv_size =
		em->ipsec_proto_main_integ_algs[sa0->integ_alg].trunc_size;

	      u8 *icv = vlib_buffer_get_tail (i_b0) - icv_size;
	      i_b0->current_length -= icv_size;

	      mac (sa0, thread_id, (u8 *) esp0, i_b0->current_length, sig);

	      if (PREDICT_FALSE (memcmp (icv, sig, icv_size)))
		{
		  vlib_node_increment_counter (vm, esp_decrypt_node.index,
					       ESP_DECRYPT_ERROR_INTEG_ERROR,
					       1);
		  to_next[0] = i_bi0;
		  to_next += 1;
		  goto trace;
		}
	    }

	  /* Anti replay */
	  if (PREDICT_TRUE (sa0->use_anti_replay))
	    {
	      if (PREDICT_TRUE (sa0->use_esn))
		esp_replay_advance_esn (sa0, seq);
	      else
		esp_replay_advance (sa0, seq);
	    }

	  to_next[0] = i_bi0;
	  to_next += 1;

	  /* skip ESP header & IV */
	  vlib_buffer_advance (i_b0, sizeof (esp_header_t) + IV_SIZE);

	  /* invalid ESP length, has to be muiltple blocks size */
	  if (PREDICT_FALSE (i_b0->current_length % BLOCK_SIZE))
	    {
	      vlib_node_increment_counter (vm,
					   esp_decrypt_node.index,
					   ESP_DECRYPT_ERROR_LENGTH_ERROR, 1);
	      goto trace;
	    }

	  switch (sa0->crypto_alg)
	    {
	    case IPSEC_CRYPTO_ALG_NONE:
	    default:
	      break;
	    case IPSEC_CRYPTO_ALG_AES_CBC_128:
	    case IPSEC_CRYPTO_ALG_AES_CBC_192:
	    case IPSEC_CRYPTO_ALG_AES_CBC_256:
	    case IPSEC_CRYPTO_ALG_DES_CBC:
	    case IPSEC_CRYPTO_ALG_3DES_CBC:
	      esp_decrypt_cbc (sa0, thread_id,
			       (u8 *) vlib_buffer_get_current (i_b0),
			       i_b0->current_length, esp0->data);
	      break;
	    case IPSEC_CRYPTO_ALG_AES_CTR_128:
	    case IPSEC_CRYPTO_ALG_AES_CTR_192:
	    case IPSEC_CRYPTO_ALG_AES_CTR_256:
	      {
		u32 ctr_iv[IV_SIZE + 2];
		ctr_iv[0] = sa0->salt;
		clib_memcpy (&ctr_iv[1], esp0->data, IV_SIZE);
		ctr_iv[3] = clib_host_to_net_u32 (1);

		esp_decrypt_cbc (sa0, thread_id,
				 (u8 *) vlib_buffer_get_current (i_b0),
				 i_b0->current_length, (u8 *) ctr_iv);
	      }
	      break;
	    case IPSEC_CRYPTO_ALG_AES_GCM_128:
	    case IPSEC_CRYPTO_ALG_AES_GCM_192:
	    case IPSEC_CRYPTO_ALG_AES_GCM_256:
	      {
		u32 gcm_iv[IV_SIZE + 1];
		gcm_iv[0] = sa0->salt;
		clib_memcpy (&gcm_iv[1], esp0->data, IV_SIZE);

		u32 aad[3];
		size_t aad_len = 8;
		aad[0] = esp0->spi;
		aad[1] = esp0->seq;

		/* esn enabled? */
		if (PREDICT_TRUE (sa0->use_esn))
		  {
		    aad[2] = clib_host_to_net_u32 (sa0->seq_hi);
		    aad_len = 12;
		  }

		int rv = esp_decrypt_gcm (sa0, thread_id,
					  (u8 *)
					  vlib_buffer_get_current (i_b0),
					  i_b0->current_length - 16,
					  (u8 *) gcm_iv, (u8 *) aad, aad_len,
					  (u8 *) vlib_buffer_get_tail (i_b0) -
					  16);

		if (PREDICT_FALSE (!rv))
		  {
		    vlib_node_increment_counter (vm, esp_decrypt_node.index,
						 ESP_DECRYPT_ERROR_INTEG_ERROR,
						 1);
		    goto trace;
		  }

		/* gcm tag */
		i_b0->current_length -= 16;
	      }

	      break;
	    }

	  if (1)
	    {
#ifdef IPSEC_DEBUG_OUTPUT
	      if (PREDICT_FALSE (im->debug_fformat))
		fformat (stdout, "DE: %U\n", format_hexdump,
			 vlib_buffer_get_current (i_b0),
			 i_b0->current_length);
#endif

	      i_b0->current_length -= sizeof (esp_footer_t);
	      f0 = (esp_footer_t *) vlib_buffer_get_tail (i_b0);

	      /* for some reason, footer is wrong */
	      if (PREDICT_FALSE (f0->pad_length >= BLOCK_SIZE))
		{
		  vlib_node_increment_counter (vm, esp_decrypt_node.index,
					       ESP_DECRYPT_ERROR_TRAILER_ERROR,
					       1);
		  goto trace;
		}

	      i_b0->current_length -= f0->pad_length;

	      /* tunnel mode */
	      if (PREDICT_TRUE (sa0->is_tunnel || sa0->is_tunnel_ip6))
		{
		  if (PREDICT_TRUE (f0->next_header == IP_PROTOCOL_IP_IN_IP))
		    {
		      next0 = ESP_DECRYPT_NEXT_IP4_INPUT;
		      ih4 = vlib_buffer_get_current (i_b0);
		    }
		  else if (f0->next_header == IP_PROTOCOL_IPV6)
		    {
		      ih6 = vlib_buffer_get_current (i_b0);
		      next0 = ESP_DECRYPT_NEXT_IP6_INPUT;
		    }
		  else
		    {
		      //clib_warning ("next header: 0x%x", f0->next_header);
		      vlib_node_increment_counter (vm, esp_decrypt_node.index,
						   ESP_DECRYPT_ERROR_DECRYPTION_FAILED,
						   1);
		      goto trace;
		    }
		}
	      /* transport mode */
	      else
		{
		  int is_ip4 = (i_b0->flags & VNET_BUFFER_F_IS_IP4) != 0;
		  int is_ip6 = (i_b0->flags & VNET_BUFFER_F_IS_IP6) != 0;
		  size_t ip_header_size = 0;

		  ASSERT (!(is_ip4 && is_ip6));

		  ip4_header_t *oih4 =
		    (ip4_header_t *) (i_b0->data +
				      vnet_buffer (i_b0)->l3_hdr_offset);
		  //oih6 = (ip6_header_t *) (i_b0->data + vnet_buffer (i_b0)->l3_hdr_offset);

		  /* restore IP header */
		  if (is_ip4)
		    ip_header_size = ip4_header_bytes (oih4);
		  else
		    ip_header_size = sizeof (ip6_header_t);

		  /* - ip header */
		  vlib_buffer_advance (i_b0, 0 - ip_header_size);

		  /* locate the new ip header */
		  ih4 = vlib_buffer_get_current (i_b0);

		  memmove (ih4, oih4, ip_header_size);

		  /* to figure out ipv4 or ipv6 */
		  if (is_ip4)
		    {
		      next0 = ESP_DECRYPT_NEXT_IP4_INPUT;

		      ih4->fragment_id = 0;
		      ih4->flags_and_fragment_offset = 0;
		      ih4->protocol = f0->next_header;
		      ih4->length =
			clib_host_to_net_u16 (vlib_buffer_length_in_chain
					      (vm, i_b0));
		      ih4->checksum = ip4_header_checksum (ih4);
		    }
		  else if (is_ip6)
		    {
		      ih6 = (ip6_header_t *) ih4;

		      next0 = ESP_DECRYPT_NEXT_IP6_INPUT;
		      ih6->ip_version_traffic_class_and_flow_label =
			ih6->ip_version_traffic_class_and_flow_label;
		      ih6->protocol = f0->next_header;
		      ih6->payload_length =
			clib_host_to_net_u16 (vlib_buffer_length_in_chain
					      (vm,
					       i_b0) - sizeof (ip6_header_t));
		    }
		  else
		    {
		      vlib_node_increment_counter (vm, esp_decrypt_node.index,
						   ESP_DECRYPT_ERROR_NOT_IP,
						   1);
		      goto trace;
		    }
		}

	      /* for IPSec-GRE tunnel next node is ipsec-gre-input */
	      if (PREDICT_FALSE
		  ((vnet_buffer (i_b0)->
		    ipsec.flags) & IPSEC_FLAG_IPSEC_GRE_TUNNEL))
		next0 = ESP_DECRYPT_NEXT_IPSEC_GRE_INPUT;

	      vnet_buffer (i_b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
	      //vnet_buffer (i_b0)->sw_if_index[VLIB_RX] = vnet_buffer (i_b0)->sw_if_index[VLIB_RX];
	    }

	trace:
	  if (PREDICT_FALSE (i_b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      esp_decrypt_trace_t *tr =
		vlib_add_trace (vm, node, i_b0, sizeof (*tr));
	      tr->crypto_alg = sa0->crypto_alg;
	      tr->integ_alg = sa0->integ_alg;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, i_bi0, next0);

	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, esp_decrypt_node.index,
			       ESP_DECRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

  return from_frame->n_vectors;
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp_decrypt_node) = {
  .function = esp_decrypt_node_fn,
  .name = "esp-decrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_decrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(esp_decrypt_error_strings),
  .error_strings = esp_decrypt_error_strings,

  .n_next_nodes = ESP_DECRYPT_N_NEXT,
  .next_nodes = {
#define _(s,n) [ESP_DECRYPT_NEXT_##s] = n,
    foreach_esp_decrypt_next
#undef _
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (esp_decrypt_node, esp_decrypt_node_fn)
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
