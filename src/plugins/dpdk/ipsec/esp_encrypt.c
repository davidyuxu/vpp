/*
 * esp_encrypt.c : IPSec ESP encrypt node using DPDK Cryptodev
 *
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

#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>

#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/esp.h>
#include <dpdk/ipsec/ipsec.h>
#include <dpdk/device/dpdk.h>
#include <dpdk/device/dpdk_priv.h>

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
 _(RX_PKTS, "ESP pkts received")                    \
 _(SEQ_CYCLED, "Sequence number cycled")            \
 _(ENQ_FAIL, "Enqueue failed to crypto device")     \
 _(DISCARD, "Not enough crypto operations, discarding frame")  \
 _(SESSION, "Failed to get crypto session")         \
 _(NOSUP, "Cipher/Auth not supported")


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

vlib_node_registration_t dpdk_esp_encrypt_node;

typedef struct
{
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;
  u8 packet_data[64];
} esp_encrypt_trace_t;

/* packet trace format function */
static u8 *
format_esp_encrypt_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  esp_encrypt_trace_t *t = va_arg (*args, esp_encrypt_trace_t *);
  ip4_header_t *ih4 = (ip4_header_t *) t->packet_data;
  u32 indent = format_get_indent (s), offset;

  s = format (s, "cipher %U auth %U\n",
	      format_ipsec_crypto_alg, t->crypto_alg,
	      format_ipsec_integ_alg, t->integ_alg);

  if ((ih4->ip_version_and_header_length & 0xF0) == 0x60)
    {
      s = format (s, "%U%U", format_white_space, indent,
		  format_ip6_header, ih4);
      offset = sizeof (ip6_header_t);
    }
  else
    {
      s = format (s, "%U%U", format_white_space, indent,
		  format_ip4_header, ih4);
      offset = ip4_header_bytes (ih4);
    }

  s = format (s, "\n%U%U", format_white_space, indent,
	      format_esp_header, t->packet_data + offset);

  return s;
}

static uword
dpdk_esp_encrypt_node_fn (vlib_main_t * vm,
			  vlib_node_runtime_t * node,
			  vlib_frame_t * from_frame)
{
  u32 n_left_from, *from, *to_next, next_index;
  ipsec_main_t *im = &ipsec_main;
  u32 thread_idx = vlib_get_thread_index ();
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  ipsec_sa_t *sa0 = 0;
  crypto_session_t *cs0 = 0;

	u16 res_idx;
	crypto_resource_t *res;

  u8 numa = rte_socket_id ();

  crypto_worker_main_t *cwm = vec_elt_at_index (dcm->workers_main, thread_idx);
	
  struct rte_crypto_op **ops = cwm->ops;

	/* ops must be allocated for both Numa zone when initializing - refer to vdev crypto_aesni_mb0,socket_id=0 */
	ASSERT (ops);

	from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;
  next_index = ESP_ENCRYPT_NEXT_DROP;

  int ret = crypto_alloc_ops (numa, ops, n_left_from);
  if (ret)
  {
    vlib_node_increment_counter (vm, dpdk_esp_encrypt_node.index, ESP_ENCRYPT_ERROR_DISCARD, 1);

    /* Discard whole frame */
		//vlib_put_next_frame (vm, node, next_index, n_left_from);
    return n_left_from;
  }

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0 = 0;
	  u32 sa_index0;
	  ip4_and_esp_header_t *ih0, *oh0 = 0;
	  ip6_and_esp_header_t *ih6_0, *oh6_0 = 0;
	  esp_header_t *esp0;
	  esp_footer_t *f0;
	  u8 is_ipv6, next_hdr_type;
	  u16 orig_sz;
	  u16 rewrite_len;
	  struct rte_mbuf *mb0 = 0;
	  struct rte_crypto_op *op;

	  bi0 = from[0];
	  from += 1;
	  n_left_from -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ih0 = vlib_buffer_get_current (b0);
	  mb0 = rte_mbuf_from_vlib_buffer (b0);

#ifdef IPSEC_DEBUG_OUTPUT
		if (PREDICT_FALSE (im->debug_fformat))
			fformat (stdout, "ENIN  : %U\n", format_hexdump, vlib_buffer_get_current (b0), b0->current_length);
#endif

	  /* ih0/ih6_0 */
	  CLIB_PREFETCH (ih0, sizeof (ih6_0[0]), LOAD);

	  /* f0 */
	  CLIB_PREFETCH (vlib_buffer_get_tail (b0), 20, STORE);
	  /* mb0 */
	  //CLIB_PREFETCH (mb0, CLIB_CACHE_LINE_BYTES, STORE);

	  op = ops[0];
	  ASSERT (op->status == RTE_CRYPTO_OP_STATUS_NOT_PROCESSED);

	  dpdk_op_priv_t *priv = crypto_op_get_priv (op);

	  CLIB_PREFETCH (op, crypto_op_len(), STORE);

	  sa_index0 = vnet_buffer (b0)->ipsec.sad_index;

    sa0 = pool_elt_at_index (im->sad, sa_index0);
		cs0 = crypto_session_from_sa_index (dcm, sa_index0);				

		/* figure out res_idx to use */
		res_idx = crypto_get_resource (cwm, sa0, cs0);
    if (PREDICT_FALSE (res_idx == (u16) ~ 0))
		{
		  //clib_warning ("No resource for thread %u", thread_idx);
		  vlib_node_increment_counter (vm,
					       dpdk_esp_encrypt_node.index,
					       ESP_ENCRYPT_ERROR_NOSUP, 1);
		  to_next[0] = bi0;
		  to_next += 1;
		  n_left_to_next -= 1;
		  goto trace;
		}

		res = vec_elt_at_index (dcm->resource, res_idx);

		/* check if session is already there, otherwise make it. this happens when the first time, or SA is updated */
		if (PREDICT_FALSE (cs0->sessions[thread_idx] == NULL))
		{
      ret = crypto_make_session (thread_idx, cs0, sa0, res, cwm, 1);
      if (PREDICT_FALSE (!ret))
			{
			  //clib_warning ("failed to create crypto session");
			  vlib_node_increment_counter (vm,
						       dpdk_esp_encrypt_node.index,
						       ESP_ENCRYPT_ERROR_SESSION, 1);
			  to_next[0] = bi0;
			  to_next += 1;
			  n_left_to_next -= 1;
			  goto trace;
			}
		}

	  if (PREDICT_FALSE (esp_seq_advance (sa0)))
    {
      //clib_warning ("sequence number counter has cycled SPI %u", sa0->spi);
      vlib_node_increment_counter (vm, dpdk_esp_encrypt_node.index,
				   ESP_ENCRYPT_ERROR_SEQ_CYCLED, 1);
      //TODO: rekey SA
      to_next[0] = bi0;
      to_next += 1;
      n_left_to_next -= 1;
      goto trace;
    }

	  orig_sz = b0->current_length;

	  /* TODO multi-seg support - total_length_not_including_first_buffer */
	  sa0->total_data_size += b0->current_length;

	  is_ipv6 = (ih0->ip4.ip_version_and_header_length & 0xF0) == 0x60;

	  const int IV_SIZE = cs0->cipher_alg->iv_len;
	  const int TRUNC_SIZE = cs0->auth_alg->trunc_size;

	  if (sa0->is_tunnel)
    {
      rewrite_len = 0;
      if (!is_ipv6 && !sa0->is_tunnel_ip6)	/* ip4inip4 */
			{
			  /* in tunnel mode send it back to FIB */
			  priv->next = DPDK_CRYPTO_INPUT_NEXT_IP4_LOOKUP;
			  u8 adv =
			    sizeof (ip4_header_t) + sizeof (esp_header_t) + IV_SIZE;
			  vlib_buffer_advance (b0, -adv);
			  oh0 = vlib_buffer_get_current (b0);
			  next_hdr_type = IP_PROTOCOL_IP_IN_IP;
			  /*
			   * oh0->ip4.ip_version_and_header_length = 0x45;
			   * oh0->ip4.tos = ih0->ip4.tos;
			   * oh0->ip4.fragment_id = 0;
			   * oh0->ip4.flags_and_fragment_offset = 0;
			   */
			  oh0->ip4.checksum_data_64[0] =
			    clib_host_to_net_u64 (0x45ULL << 56);
			  /*
			   * oh0->ip4.ttl = 254;
			   * oh0->ip4.protocol = IP_PROTOCOL_IPSEC_ESP;
			   */
			  oh0->ip4.checksum_data_32[2] =
			    clib_host_to_net_u32 (0xfe320000);

			  oh0->ip4.src_address.as_u32 =
			    sa0->tunnel_src_addr.ip4.as_u32;
			  oh0->ip4.dst_address.as_u32 =
			    sa0->tunnel_dst_addr.ip4.as_u32;
			  esp0 = &oh0->esp;
			  oh0->esp.spi = clib_host_to_net_u32 (sa0->spi);
			  oh0->esp.seq = clib_host_to_net_u32 (sa0->seq);
			}
      else if (is_ipv6 && sa0->is_tunnel_ip6)	/* ip6inip6 */
			{
			  /* in tunnel mode send it back to FIB */
			  priv->next = DPDK_CRYPTO_INPUT_NEXT_IP6_LOOKUP;

			  u8 adv =
			    sizeof (ip6_header_t) + sizeof (esp_header_t) + IV_SIZE;
			  vlib_buffer_advance (b0, -adv);
			  ih6_0 = (ip6_and_esp_header_t *) ih0;
			  oh6_0 = vlib_buffer_get_current (b0);

			  next_hdr_type = IP_PROTOCOL_IPV6;

			  oh6_0->ip6.ip_version_traffic_class_and_flow_label =
			    ih6_0->ip6.ip_version_traffic_class_and_flow_label;

			  oh6_0->ip6.protocol = IP_PROTOCOL_IPSEC_ESP;
			  oh6_0->ip6.hop_limit = 254;
			  oh6_0->ip6.src_address.as_u64[0] =
			    sa0->tunnel_src_addr.ip6.as_u64[0];
			  oh6_0->ip6.src_address.as_u64[1] =
			    sa0->tunnel_src_addr.ip6.as_u64[1];
			  oh6_0->ip6.dst_address.as_u64[0] =
			    sa0->tunnel_dst_addr.ip6.as_u64[0];
			  oh6_0->ip6.dst_address.as_u64[1] =
			    sa0->tunnel_dst_addr.ip6.as_u64[1];
			  esp0 = &oh6_0->esp;
			  oh6_0->esp.spi = clib_host_to_net_u32 (sa0->spi);
			  oh6_0->esp.seq = clib_host_to_net_u32 (sa0->seq);
			}
	    else		/* unsupported ip4inip6, ip6inip4 */
			{
			  vlib_node_increment_counter (vm,
						       dpdk_esp_encrypt_node.index,
						       ESP_ENCRYPT_ERROR_NOSUP, 1);
			  to_next[0] = bi0;
			  to_next += 1;
			  n_left_to_next -= 1;
			  goto trace;
			}
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
    }
	  else			/* transport mode */
    {
      priv->next = DPDK_CRYPTO_INPUT_NEXT_INTERFACE_OUTPUT;
      rewrite_len = vnet_buffer (b0)->ip.save_rewrite_length;
      u16 adv = sizeof (esp_header_t) + IV_SIZE;
      vlib_buffer_advance (b0, -adv - rewrite_len);
      u8 *src = ((u8 *) ih0) - rewrite_len;
      u8 *dst = vlib_buffer_get_current (b0);
      oh0 = vlib_buffer_get_current (b0) + rewrite_len;

      if (is_ipv6)
			{
			  orig_sz -= sizeof (ip6_header_t);
			  ih6_0 = (ip6_and_esp_header_t *) ih0;
			  next_hdr_type = ih6_0->ip6.protocol;
			  memmove (dst, src, rewrite_len + sizeof (ip6_header_t));
			  oh6_0 = (ip6_and_esp_header_t *) oh0;
			  oh6_0->ip6.protocol = IP_PROTOCOL_IPSEC_ESP;
			  esp0 = &oh6_0->esp;
			}
      else		/* ipv4 */
			{
			  u16 ip_size = ip4_header_bytes (&ih0->ip4);
			  orig_sz -= ip_size;
			  next_hdr_type = ih0->ip4.protocol;
			  memmove (dst, src, rewrite_len + ip_size);
			  oh0->ip4.protocol = IP_PROTOCOL_IPSEC_ESP;
			  esp0 = (esp_header_t *) (((u8 *) oh0) + ip_size);
			}
      esp0->spi = clib_host_to_net_u32 (sa0->spi);
      esp0->seq = clib_host_to_net_u32 (sa0->seq);
    }

	  ASSERT (is_pow2 (cs0->cipher_alg->boundary));
		
	  u16 mask = cs0->cipher_alg->boundary - 1;
	  u16 pad_payload_len = ((orig_sz + 2) + mask) & ~mask;
	  u8 pad_bytes = pad_payload_len - 2 - orig_sz;

	  u8 *padding =
	    vlib_buffer_put_uninit (b0, pad_bytes + 2 + TRUNC_SIZE);

	  /* The extra pad bytes would be overwritten by the digest */
	  if (pad_bytes)
	    clib_memcpy (padding, pad_data, 16);

	  f0 = (esp_footer_t *) (padding + pad_bytes);
	  f0->pad_length = pad_bytes;
	  f0->next_header = next_hdr_type;

	  if (is_ipv6)
    {
      u16 len = b0->current_length - sizeof (ip6_header_t);
      oh6_0->ip6.payload_length =	clib_host_to_net_u16 (len - rewrite_len);
    }
	  else
    {
      oh0->ip4.length =	clib_host_to_net_u16 (b0->current_length - rewrite_len);
      oh0->ip4.checksum = ip4_header_checksum (&oh0->ip4);
    }

	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  b0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;

	  /* mbuf packet starts at ESP header */
	  mb0->data_len = vlib_buffer_get_tail (b0) - ((u8 *) esp0);
	  mb0->pkt_len = vlib_buffer_get_tail (b0) - ((u8 *) esp0);
	  mb0->data_off = ((void *) esp0) - mb0->buf_addr;

	  u32 cipher_off, cipher_len, auth_len = 0;
	  u32 *aad = NULL;

	  u8 *digest = vlib_buffer_get_tail (b0) - TRUNC_SIZE;
	  u64 digest_paddr =
	    mb0->buf_physaddr + digest - ((u8 *) mb0->buf_addr);

	  if (!cs0->is_aead && (cs0->cipher_alg->alg == RTE_CRYPTO_CIPHER_AES_CBC 
				|| cs0->cipher_alg->alg == RTE_CRYPTO_CIPHER_DES_CBC 
				|| cs0->cipher_alg->alg == RTE_CRYPTO_CIPHER_3DES_CBC))
    {
			RAND_bytes ((void *) &priv->cb, IV_SIZE);

    	u8 *esp_iv = (u8 *) (esp0 + 1);
			clib_memcpy (esp_iv, &priv->cb, IV_SIZE);
			
      cipher_off = sizeof (esp_header_t) + IV_SIZE;
      cipher_len = pad_payload_len;
    }
	  else			/* CTR/GCM */
    {			
			crypto_set_icb (&priv->cb, sa0->salt, sa0->seq, sa0->seq_hi);

      u32 *esp_iv = (u32 *) (esp0 + 1);

			clib_memcpy (esp_iv, &priv->cb.iv, IV_SIZE);

      cipher_off = sizeof (esp_header_t) + IV_SIZE;
      cipher_len = pad_payload_len;
    }

	  if (cs0->is_aead)
    {
      aad = (u32 *) priv->aad;
      aad[0] = clib_host_to_net_u32 (sa0->spi);
      aad[1] = clib_host_to_net_u32 (sa0->seq);

      /* aad[3] should always be 0 */
      if (PREDICT_FALSE (sa0->use_esn))
				aad[2] = clib_host_to_net_u32 (sa0->seq_hi);
      else
				aad[2] = 0;
    }
	  else
    {
      auth_len = vlib_buffer_get_tail (b0) - ((u8 *) esp0) - TRUNC_SIZE;
      if (sa0->use_esn)
			{
			  u32 *_digest = (u32 *) digest;
			  _digest[0] = clib_host_to_net_u32 (sa0->seq_hi);
			  auth_len += 4;
			}
    }

	  crypto_op_setup (cs0->is_aead, mb0, op, cs0->sessions[thread_idx], cipher_off, cipher_len,
			   0, auth_len, (u8 *) aad, digest, digest_paddr);

		/* op done, put it into resource queue */
		res->ops[res->n_ops] = op;
		res->bi[res->n_ops] = bi0;
		res->n_ops += 1;
		ops += 1;

#ifdef IPSEC_DEBUG_OUTPUT
		if (PREDICT_FALSE (im->debug_fformat))
			fformat (stdout, "ENCAP : %U\n", format_hexdump, vlib_buffer_get_current (b0), b0->current_length);
#endif		

	trace:
	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      esp_encrypt_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->crypto_alg = sa0->crypto_alg;
	      tr->integ_alg = sa0->integ_alg;
	      u8 *p = vlib_buffer_get_current (b0);
	      if (!sa0->is_tunnel)
		p += vnet_buffer (b0)->ip.save_rewrite_length;
	      clib_memcpy (tr->packet_data, p, sizeof (tr->packet_data));
	    }
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, dpdk_esp_encrypt_node.index, ESP_ENCRYPT_ERROR_RX_PKTS, from_frame->n_vectors);

  crypto_enqueue_ops (vm, cwm, 1, dpdk_esp_encrypt_node.index, ESP_ENCRYPT_ERROR_ENQ_FAIL, numa);

	/* free all unused ops */
  crypto_free_ops (numa, ops, cwm->ops + from_frame->n_vectors - ops);

  return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpdk_esp_encrypt_node) = {
  .function = dpdk_esp_encrypt_node_fn,
  .name = "dpdk-esp-encrypt",
  .flags = VLIB_NODE_FLAG_IS_OUTPUT,
  .vector_size = sizeof (u32),
  .format_trace = format_esp_encrypt_trace,
  .n_errors = ARRAY_LEN (esp_encrypt_error_strings),
  .error_strings = esp_encrypt_error_strings,
  .n_next_nodes = 1,
  .next_nodes =
    {
      [ESP_ENCRYPT_NEXT_DROP] = "error-drop",
    }
};
/* *INDENT-ON* */

VLIB_NODE_FUNCTION_MULTIARCH (dpdk_esp_encrypt_node, dpdk_esp_encrypt_node_fn)
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
