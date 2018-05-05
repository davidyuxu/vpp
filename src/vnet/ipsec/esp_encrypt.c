/*
 * esp_encrypt.c : IPSec ESP encrypt node
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
#include <vnet/udp/udp.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/esp.h>

ipsec_proto_main_t ipsec_proto_main;

#define foreach_esp_encrypt_next                   \
_(DROP, "error-drop")                              \
_(IP4_LOOKUP, "ip4-lookup")                        \
_(IP6_LOOKUP, "ip6-lookup")                        \
_(INTERFACE_OUTPUT, "interface-output")

#define _(v, s) ESP_ENCRYPT_NEXT_##v,
typedef enum
{
  foreach_esp_encrypt_next
#undef _
    ESP_ENCRYPT_N_NEXT,
} esp_encrypt_next_t;

#define foreach_esp_encrypt_error                   \
 _(RX_PKTS, "ESP pkts sent")                    \
 _(ENCRYPTION_FAILED, "ESP encryption failed")      \
 _(SEQ_CYCLED, "sequence number cycled")


typedef enum
{
#define _(sym,str) ESP_ENCRYPT_ERROR_##sym,
  foreach_esp_encrypt_error
#undef _
    ESP_ENCRYPT_N_ERROR,
} esp_encrypt_error_t;

static char *esp_encrypt_error_strings[] = {
#define _(sym,string) string,
  foreach_esp_encrypt_error
#undef _
};

vlib_node_registration_t esp_encrypt_node;

typedef struct
{
  u32 spi;
  u32 seq;
  u8 udp_encap;
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;
} esp_encrypt_trace_t;

/* packet trace format function */
static u8 *
format_esp_encrypt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  esp_encrypt_trace_t *t = va_arg (*args, esp_encrypt_trace_t *);

  s = format (s, "esp: spi %u seq %u crypto %U integrity %U%s",
	      t->spi, t->seq,
	      format_ipsec_crypto_alg, t->crypto_alg,
	      format_ipsec_integ_alg, t->integ_alg,
	      t->udp_encap ? " udp-encap-enabled" : "");
  return s;
}

always_inline void
esp_encrypt_cbc (ipsec_crypto_alg_t alg,
		 u8 * in, u8 * out, size_t in_len, u8 * key, u8 * iv)
{
  ipsec_proto_main_t *em = &ipsec_proto_main;
  u32 thread_index = vlib_get_thread_index ();
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX *ctx = em->per_thread_data[thread_index].encrypt_ctx;
#else
  EVP_CIPHER_CTX *ctx = &(em->per_thread_data[thread_index].encrypt_ctx);
#endif
  const EVP_CIPHER *cipher = NULL;
  int out_len;

  ASSERT (alg < IPSEC_CRYPTO_N_ALG);

  if (PREDICT_FALSE
      (em->ipsec_proto_main_crypto_algs[alg].type == IPSEC_CRYPTO_ALG_NONE))
    return;

  if (PREDICT_FALSE
      (alg != em->per_thread_data[thread_index].last_encrypt_alg))
    {
      cipher = em->ipsec_proto_main_crypto_algs[alg].type;
      em->per_thread_data[thread_index].last_encrypt_alg = alg;
    }

  EVP_EncryptInit_ex (ctx, cipher, NULL, key, iv);

  EVP_EncryptUpdate (ctx, out, &out_len, in, in_len);

	fformat (stdout, "CIPHER: %U \n", format_hexdump, out, out_len);
	
  EVP_EncryptFinal_ex (ctx, out + out_len, &out_len);
}

always_inline void
esp_encrypt_cbc2 (ipsec_sa_t *sa, u8 * in, u8 * out, size_t in_len, u8 * key, u8 * iv)
{
  u32 thread_index = vlib_get_thread_index ();
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX *ctx = sa->context[thread_index].cipher_ctx;
#else
  EVP_CIPHER_CTX *ctx = &(sa->context[thread_index].cipher_ctx);
#endif

#if 0
		ipsec_proto_main_t *em = &ipsec_proto_main;

		const EVP_CIPHER *cipher = cipher = em->ipsec_proto_main_crypto_algs[sa->crypto_alg].type;
			EVP_CipherInit_ex (ctx, cipher, NULL, sa->crypto_key, iv, 1);
#endif


  int out_len;

	ASSERT (sa->crypto_alg < IPSEC_CRYPTO_N_ALG && sa->crypto_alg > IPSEC_CRYPTO_ALG_NONE);

	EVP_CipherInit_ex (ctx, NULL, NULL, NULL, iv, -1);

  EVP_CipherUpdate (ctx, out, &out_len, in, in_len);

	//fformat (stdout, "CIPHER: %U \n", format_hexdump, out, out_len);

  EVP_CipherFinal_ex (ctx, out + out_len, &out_len);
	//EVP_EncryptInit_ex (ctx, NULL, NULL, NULL, iv);

  //EVP_EncryptUpdate (ctx, out, &out_len, in, in_len);

	//fformat (stdout, "CIPHER: %U \n", format_hexdump, out, out_len);

  //EVP_EncryptFinal_ex (ctx, out + out_len, &out_len);
}

always_inline int
esp_encrypt_gcm (ipsec_sa_t *sa, u8 * in, u8 * out, size_t in_len, u8 * key, u8 * iv, u8 * tag)
{
  u32 thread_index = vlib_get_thread_index ();
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX *ctx = sa->context[thread_index].cipher_ctx;
#else
  EVP_CIPHER_CTX *ctx = &(sa->context[thread_index].cipher_ctx);
#endif

	//fformat (stdout, "CLEAR: %U \n", format_hexdump, in, in_len);


#if 0
		ipsec_proto_main_t *em = &ipsec_proto_main;

		const EVP_CIPHER *cipher = cipher = em->ipsec_proto_main_crypto_algs[sa->crypto_alg].type;
			EVP_CipherInit_ex (ctx, cipher, NULL, sa->crypto_key, NULL, 1);
			EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_SET_IVLEN, 8, NULL);
#endif

  int out_len = 0;

	EVP_CipherInit_ex (ctx, NULL, NULL, NULL, iv, -1);

	/* Zero or more calls to specify any AAD */
	EVP_CipherUpdate (ctx, NULL, &out_len, (u8 *)&sa->seq, 4);

	/* Encrypt plaintext */
	EVP_CipherUpdate(ctx, out, &out_len, in, in_len);

#if 0 // kingwel, i guess we can save this
	int ret;

	/* Finalise: note get no output for GCM */
	EVP_EncryptFinal_ex(ctx, out, &ret);
#endif

	/* Get tag */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
#else
  EVP_CIPHER_CTX_ctrl (ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
#endif

	/* Output encrypted block */
	//fformat (stdout, "CIPHER: %U \n", format_hexdump, out, out_len);
	//fformat (stdout, "TAG: %U \n", format_hexdump, tag, 16);

	return out_len;
}


static uword
esp_encrypt_node_fn (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, *to_next = 0, next_index;
  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  ipsec_main_t *im = &ipsec_main;
  ipsec_proto_main_t *em = &ipsec_proto_main;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 i_bi0, next0;
	  vlib_buffer_t *i_b0;
	  u32 sa_index0;
	  ipsec_sa_t *sa0;
	  ip4_header_t *ih0;
	  ip6_header_t *ih6_0;

	  ip4_and_esp_header_t *n_ih0;
	  ip6_and_esp_header_t *n_ih6_0;

	  esp_footer_t *f0;
		
		u8 pad_bytes = 0;
		int blocks = 0;
		u8 * iv;
		
	  u8 is_ipv6;
	  u8 ip_udp_hdr_size;
	  u8 next_hdr_type;
	  u32 ip_proto = 0;
	  u8 transport_mode = 0;

	  i_bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  next0 = ESP_ENCRYPT_NEXT_DROP;

	  i_b0 = vlib_get_buffer (vm, i_bi0);
	  sa_index0 = vnet_buffer (i_b0)->ipsec.sad_index;
	  sa0 = pool_elt_at_index (im->sad, sa_index0);

		const int BLOCK_SIZE = em->ipsec_proto_main_crypto_algs[sa0->crypto_alg].block_size;
		const int IV_SIZE = em->ipsec_proto_main_crypto_algs[sa0->crypto_alg].iv_size;

		fformat (stdout, "IN: %U\n", format_hexdump, vlib_buffer_get_current (i_b0), i_b0->current_length);

	  if (PREDICT_FALSE (esp_seq_advance (sa0)))
	    {
	      clib_warning ("sequence number counter has cycled SPI %u",
			    sa0->spi);
	      vlib_node_increment_counter (vm, esp_encrypt_node.index,
					   ESP_ENCRYPT_ERROR_SEQ_CYCLED, 1);
	      //TODO: rekey SA
	      to_next[0] = i_bi0;
	      to_next += 1;
	      goto trace;
	    }

	  sa0->total_data_size += i_b0->current_length;


	  ih0 = vlib_buffer_get_current (i_b0);

	  to_next[0] = i_bi0;
	  to_next += 1;

	  /* is ipv6 */
	  if (PREDICT_FALSE ((ih0->ip_version_and_header_length & 0xF0) == 0x60))
    {
      is_ipv6 = 1;

			ih6_0 = vlib_buffer_get_current (i_b0);
      ip_hdr_size = sizeof (ip6_header_t);
      next_hdr_type = IP_PROTOCOL_IPV6;

			n_ih6_0 = vlib_buffer_get_current (i_b0) - sizeof (ip6_and_esp_header_t) - IV_SIZE;

      n_ih6_0->ip6.ip_version_traffic_class_and_flow_label = ih6_0->ip_version_traffic_class_and_flow_label;
      n_ih6_0->ip6.protocol = IP_PROTOCOL_IPSEC_ESP;
      n_ih6_0->ip6.hop_limit = 254;
      n_ih6_0->ip6.src_address.as_u64[0] = ih6_0->src_address.as_u64[0];
      n_ih6_0->ip6.src_address.as_u64[1] = ih6_0->src_address.as_u64[1];
      n_ih6_0->ip6.dst_address.as_u64[0] = ih6_0->dst_address.as_u64[0];
      n_ih6_0->ip6.dst_address.as_u64[1] = ih6_0->dst_address.as_u64[1];
      n_ih6_0->esp.spi = clib_net_to_host_u32 (sa0->spi);
      n_ih6_0->esp.seq = clib_net_to_host_u32 (sa0->seq);

      ip_proto = ih6_0->protocol;

      next0 = ESP_ENCRYPT_NEXT_IP6_LOOKUP;
    }
	  else
    {
      is_ipv6 = 0;
			
      ip_hdr_size = sizeof (ip4_header_t);
      next_hdr_type = IP_PROTOCOL_IP_IN_IP;

			n_ih0 = vlib_buffer_get_current (i_b0) - sizeof (ip4_and_esp_header_t) - IV_SIZE;

      n_ih0->ip4.ip_version_and_header_length = 0x45;
      n_ih0->ip4.tos = ih0->tos;
      n_ih0->ip4.fragment_id = 0;
      n_ih0->ip4.flags_and_fragment_offset = 0;
      n_ih0->ip4.ttl = 2;
      n_ih0->ip4.protocol = IP_PROTOCOL_IPSEC_ESP;
      n_ih0->ip4.src_address.as_u32 = ih0->src_address.as_u32;
      n_ih0->ip4.dst_address.as_u32 = ih0->dst_address.as_u32;
      n_ih0->esp.spi = clib_net_to_host_u32 (sa0->spi);
      n_ih0->esp.seq = clib_net_to_host_u32 (sa0->seq);

      ip_proto = ih0->protocol;

      next0 = ESP_ENCRYPT_NEXT_IP4_LOOKUP;
    }

	  if (PREDICT_TRUE (!is_ipv6 && sa0->is_tunnel && !sa0->is_tunnel_ip6))
    {
      n_ih0->ip4.src_address.as_u32 = sa0->tunnel_src_addr.ip4.as_u32;
      n_ih0->ip4.dst_address.as_u32 = sa0->tunnel_dst_addr.ip4.as_u32;

      vnet_buffer (i_b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
    }
	  else if (is_ipv6 && sa0->is_tunnel && sa0->is_tunnel_ip6)
    {
      n_ih6_0->ip6.src_address.as_u64[0] = sa0->tunnel_src_addr.ip6.as_u64[0];
      n_ih6_0->ip6.src_address.as_u64[1] = sa0->tunnel_src_addr.ip6.as_u64[1];
      n_ih6_0->ip6.dst_address.as_u64[0] = sa0->tunnel_dst_addr.ip6.as_u64[0];
      n_ih6_0->ip6.dst_address.as_u64[1] = sa0->tunnel_dst_addr.ip6.as_u64[1];

      vnet_buffer (i_b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
    }
	  else
    {
      next_hdr_type = ip_proto;
      if (vnet_buffer (i_b0)->sw_if_index[VLIB_TX] != ~0)
			{
			  transport_mode = 1;

				//ethernet_header_t *ieh0, *oeh0;
			  //ieh0 = (ethernet_header_t *) ((u8 *) vlib_buffer_get_current (i_b0) - sizeof (ethernet_header_t));
			  //oeh0 = (ethernet_header_t *) o_b0->data;

			  //clib_memcpy (oeh0, ieh0, sizeof (ethernet_header_t));
			  next0 = ESP_ENCRYPT_NEXT_INTERFACE_OUTPUT;

				// Dont have to modify sw_if_index
			  //vnet_buffer (i_b0)->sw_if_index[VLIB_TX] = vnet_buffer (i_b0)->sw_if_index[VLIB_TX];
			}
      vlib_buffer_advance (i_b0, ip_hdr_size);
    }

	  ASSERT (sa0->crypto_alg < IPSEC_CRYPTO_N_ALG);

		/* padding for CBC mode */
	  if (PREDICT_TRUE (sa0->crypto_alg != IPSEC_CRYPTO_ALG_NONE))
    {
      blocks = 1 + (i_b0->current_length + 1) / BLOCK_SIZE;

      /* pad packet in input buffer */
      pad_bytes = BLOCK_SIZE * blocks - sizeof (esp_footer_t) - i_b0->current_length;
      u8 *padding = vlib_buffer_get_tail (i_b0);
      i_b0->current_length = BLOCK_SIZE * blocks;

      for (int i = 0; i < pad_bytes; ++i)
			{
			  padding[i] = i + 1;
			}
	  }
		else
		{
			/* Append ESP footer */
			i_b0->current_length += sizeof (esp_footer_t);
		}

		/* esp footer */
    f0 = (esp_footer_t *)(vlib_buffer_get_tail (i_b0) - sizeof (esp_footer_t));
    f0->pad_length = pad_bytes;
    f0->next_header = next_hdr_type;
		
		iv = (u8 *) vlib_buffer_get_current (i_b0) - IV_SIZE;
    //RAND_bytes (iv, sizeof (iv));
    memset (iv, 0xfe, IV_SIZE);
 			
		switch (sa0->crypto_alg)
		{
			case IPSEC_CRYPTO_ALG_NONE:
			default:
				break;
			case IPSEC_CRYPTO_ALG_AES_CBC_128:
			case IPSEC_CRYPTO_ALG_AES_CBC_192:
			case IPSEC_CRYPTO_ALG_AES_CBC_256:
			case IPSEC_CRYPTO_ALG_AES_CTR_128:
			case IPSEC_CRYPTO_ALG_AES_CTR_192:
			case IPSEC_CRYPTO_ALG_AES_CTR_256:
			case IPSEC_CRYPTO_ALG_DES_CBC:
			case IPSEC_CRYPTO_ALG_3DES_CBC:
				esp_encrypt_cbc2 (sa0, (u8 *) vlib_buffer_get_current (i_b0), (u8 *) vlib_buffer_get_current (i_b0), BLOCK_SIZE * blocks, sa0->crypto_key, iv);
				break;
			case IPSEC_CRYPTO_ALG_AES_GCM_128:
			case IPSEC_CRYPTO_ALG_AES_GCM_192:
			case IPSEC_CRYPTO_ALG_AES_GCM_256:
				//u8 tag[16];
				esp_encrypt_gcm (sa0,
						 (u8 *) vlib_buffer_get_current (i_b0),
						 (u8 *) vlib_buffer_get_current (o_b0) +
						 ip_hdr_size + sizeof (esp_header_t) +
						 IV_SIZE, BLOCK_SIZE * blocks,
						 sa0->crypto_key, iv, (u8 *) vlib_buffer_get_current (o_b0) + o_b0->current_length);
				

				break;
		}

		/* Prepend the IP header + ESP header, + IV if there is */
		vlib_buffer_advance (i_b0, 0 - (ip_hdr_size + sizeof (esp_header_t) + IV_SIZE));

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
				i_b0->current_length += hmac_calc2 (sa0, (u8 *) vlib_buffer_get_current (i_b0) + ip_hdr_size, 
																	i_b0->current_length - ip_hdr_size, vlib_buffer_get_tail (i_b0), sa0->use_esn, sa0->seq_hi);
				break;
			case IPSEC_INTEG_ALG_CMAC:			
				break;
		}
			
			// dont have to change 
			//vnet_buffer (i_b0)->sw_if_index[VLIB_RX] = vnet_buffer (i_b0)->sw_if_index[VLIB_RX];

	  if (PREDICT_FALSE (is_ipv6))
    {
      n_ih6_0->ip6.payload_length = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, i_b0) - sizeof (ip6_header_t));
    }
  	else
    {
      n_ih0->ip4.length = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, i_b0));
			n_ih0->ip4.checksum = ip4_header_checksum (&n_ih0->ip4);
    }

		fformat (stdout, "IN2: %U\n", format_hexdump, vlib_buffer_get_current (i_b0), i_b0->current_length);

	  if (transport_mode)
	    vlib_buffer_reset (i_b0);


	trace:
	  if (PREDICT_FALSE (i_b0->flags & VLIB_BUFFER_IS_TRACED))
    {
		  i_b0->flags |= VLIB_BUFFER_IS_TRACED;
		  i_b0->trace_index = i_b0->trace_index;
		  esp_encrypt_trace_t *tr =
		    vlib_add_trace (vm, node, i_b0, sizeof (*tr));
		  tr->spi = sa0->spi;
		  tr->seq = sa0->seq - 1;
		  tr->udp_encap = sa0->udp_encap;
		  tr->crypto_alg = sa0->crypto_alg;
		  tr->integ_alg = sa0->integ_alg;
    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, n_left_to_next, i_bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vlib_node_increment_counter (vm, esp_encrypt_node.index,
			       ESP_ENCRYPT_ERROR_RX_PKTS,
			       from_frame->n_vectors);

  return from_frame->n_vectors;
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (esp_encrypt_node) = {
  .function = esp_encrypt_node_fn,
  .name = "esp-encrypt",
  .vector_size = sizeof (u32),
  .format_trace = format_esp_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(esp_encrypt_error_strings),
  .error_strings = esp_encrypt_error_strings,

  .n_next_nodes = ESP_ENCRYPT_N_NEXT,
  .next_nodes = {
#define _(s,n) [ESP_ENCRYPT_NEXT_##s] = n,
    foreach_esp_encrypt_next
#undef _
  },
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (esp_encrypt_node, esp_encrypt_node_fn)
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
