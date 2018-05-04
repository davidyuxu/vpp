/*
 * ipsec_if.c : IPSec interface support
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

void vl_api_rpc_call_main_thread (void *fp, u8 * data, u32 data_length);

static u8 *
format_ipsec_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  ipsec_main_t *im = &ipsec_main;
  ipsec_tunnel_if_t *t = im->tunnel_interfaces + dev_instance;

  return format (s, "ipsec%d", t->show_instance);
}

#if 0
static uword
dummy_interface_tx (vlib_main_t * vm,
		    vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  clib_warning ("you shouldn't be here, leaking buffers...");
  return frame->n_vectors;
}
#endif

static clib_error_t *
ipsec_admin_up_down_function (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  ipsec_main_t *im = &ipsec_main;
  clib_error_t *err = 0;
  ipsec_tunnel_if_t *t;
  vnet_hw_interface_t *hi;
  ipsec_sa_t *sa;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  t = pool_elt_at_index (im->tunnel_interfaces, hi->hw_instance);

  if (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
    {
      ASSERT (im->cb.check_support_cb);

      sa = pool_elt_at_index (im->sad, t->input_sa_index);

      err = im->cb.check_support_cb (sa);
      if (err)
	return err;

      if (im->cb.add_del_sa_sess_cb)
	{
	  err = im->cb.add_del_sa_sess_cb (t->input_sa_index, 1);
	  if (err)
	    return err;
	}

      sa = pool_elt_at_index (im->sad, t->output_sa_index);

      err = im->cb.check_support_cb (sa);
      if (err)
	return err;

      if (im->cb.add_del_sa_sess_cb)
	{
	  err = im->cb.add_del_sa_sess_cb (t->output_sa_index, 1);
	  if (err)
	    return err;
	}

      vnet_hw_interface_set_flags (vnm, hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
    }
  else
    {
      vnet_hw_interface_set_flags (vnm, hw_if_index, 0 /* down */ );

      sa = pool_elt_at_index (im->sad, t->input_sa_index);

      if (im->cb.add_del_sa_sess_cb)
	{
	  err = im->cb.add_del_sa_sess_cb (t->input_sa_index, 0);
	  if (err)
	    return err;
	}

      sa = pool_elt_at_index (im->sad, t->output_sa_index);

      if (im->cb.add_del_sa_sess_cb)
	{
	  err = im->cb.add_del_sa_sess_cb (t->output_sa_index, 0);
	  if (err)
	    return err;
	}
    }

  return /* no error */ 0;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (ipsec_device_class, static) =
{
  .name = "IPSec",
  .format_device_name = format_ipsec_name,
  .format_tx_trace = format_ipsec_if_output_trace,
//  .tx_function = dummy_interface_tx,
  .admin_up_down_function = ipsec_admin_up_down_function,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS (ipsec_hw_class) =
{
  .name = "IPSec",
  .build_rewrite = default_build_rewrite,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};
/* *INDENT-ON* */

static int
ipsec_add_del_tunnel_if_rpc_callback (ipsec_add_del_tunnel_args_t * a)
{
  vnet_main_t *vnm = vnet_get_main ();
  ASSERT (vlib_get_thread_index () == 0);

  return ipsec_add_del_tunnel_if_internal (vnm, a, NULL);
}

int
ipsec_add_del_tunnel_if (ipsec_add_del_tunnel_args_t * args)
{
  vl_api_rpc_call_main_thread (ipsec_add_del_tunnel_if_rpc_callback,
			       (u8 *) args, sizeof (*args));
  return 0;
}

void
ipsec_create_sa_contexts (ipsec_sa_t *sa, u8 is_encrypt)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();

	vec_validate_aligned (sa->context, tm->n_vlib_mains - 1, CLIB_CACHE_LINE_BYTES);

	for (int thread_id = 0; thread_id < tm->n_vlib_mains; thread_id++)
		{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
			sa->context[thread_id].hmac_ctx = HMAC_CTX_new ();
			sa->context[thread_id].cipher_ctx = EVP_CIPHER_CTX_new ();
#else
			HMAC_CTX_init (&(sa->context[thread_id].hmac_ctx));
			EVP_CIPHER_CTX_init (&(sa->context[thread_id].cipher_ctx));
#endif
			sa->context[thread_id].cmac_ctx = CMAC_CTX_new ();
		}

	ipsec_set_sa_contexts_integ_key (sa);
	ipsec_set_sa_contexts_crypto_key (sa, is_encrypt);
}

void
ipsec_delete_sa_contexts (ipsec_sa_t *sa)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();

	for (int thread_id = 0; thread_id < tm->n_vlib_mains; thread_id++)
		{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
			HMAC_CTX_free (sa->context[thread_id].hmac_ctx);
			EVP_CIPHER_CTX_free (sa->context[thread_id].cipher_ctx);
#else
#endif
		}
	vec_free (sa->context);
}

void
ipsec_set_sa_contexts_integ_key (ipsec_sa_t *sa)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();

	ipsec_proto_main_t *em = &ipsec_proto_main;
	
	const EVP_MD *md = em->ipsec_proto_main_integ_algs[sa->integ_alg].md;
	
	for (int thread_id = 0; thread_id < tm->n_vlib_mains; thread_id++)
		{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
			HMAC_Init_ex (sa->context[thread_id].hmac_ctx, sa->integ_key, sa->integ_key_len, md, NULL);
#else
			HMAC_Init_ex (&sa->context[thread_id].hmac_ctx, sa->integ_key, sa->integ_key_len, md, NULL);
#endif
			CMAC_Init (sa->context[thread_id].cmac_ctx, sa->integ_key, 16, EVP_aes_128_cbc(), NULL);
		}
}

void
ipsec_set_sa_contexts_crypto_key (ipsec_sa_t *sa, u8 is_encrypt)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();

	ipsec_proto_main_t *em = &ipsec_proto_main;
	
	const EVP_CIPHER *cipher = em->ipsec_proto_main_crypto_algs[sa->crypto_alg].type;
	
	for (int thread_id = 0; thread_id < tm->n_vlib_mains; thread_id++)
		{
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
			if (is_encrypt)
				EVP_EncryptInit_ex (sa->context[thread_id].cipher_ctx, cipher, NULL, sa->crypto_key, NULL);
			else
				EVP_DecryptInit_ex (sa->context[thread_id].cipher_ctx, cipher, NULL, sa->crypto_key, NULL);
#else
			if (is_encrypt)
				EVP_EncryptInit_ex (&sa->context[thread_id].cipher_ctx, cipher, NULL, sa->crypto_key, NULL);
			else
				EVP_DecryptInit_ex (&sa->context[thread_id].cipher_ctx, cipher, NULL, sa->crypto_key, NULL);
#endif
		}
}


int
ipsec_add_del_tunnel_if_internal (vnet_main_t * vnm,
				  ipsec_add_del_tunnel_args_t * args,
				  u32 * sw_if_index)
{
  ipsec_tunnel_if_t *t;
  ipsec_main_t *im = &ipsec_main;
  vnet_hw_interface_t *hi = NULL;
  u32 hw_if_index = ~0;
  uword *p;
  ipsec_sa_t *sa;
  u32 dev_instance;

  u64 key = (u64) args->remote_ip.as_u32 << 32 | (u64) args->remote_spi;
  p = hash_get (im->ipsec_if_pool_index_by_key, key);

  if (args->is_add)
    {
      /* check if same src/dst pair exists */
      if (p)
	return VNET_API_ERROR_INVALID_VALUE;

      pool_get_aligned (im->tunnel_interfaces, t, CLIB_CACHE_LINE_BYTES);
      memset (t, 0, sizeof (*t));

      dev_instance = t - im->tunnel_interfaces;
      if (args->renumber)
	t->show_instance = args->show_instance;
      else
	t->show_instance = dev_instance;

      if (hash_get (im->ipsec_if_real_dev_by_show_dev, t->show_instance))
	{
	  pool_put (im->tunnel_interfaces, t);
	  return VNET_API_ERROR_INSTANCE_IN_USE;
	}

      hash_set (im->ipsec_if_real_dev_by_show_dev, t->show_instance,
		dev_instance);

      pool_get (im->sad, sa);
      memset (sa, 0, sizeof (*sa));
      t->input_sa_index = sa - im->sad;
      sa->spi = args->remote_spi;
      sa->tunnel_src_addr.ip4.as_u32 = args->remote_ip.as_u32;
      sa->tunnel_dst_addr.ip4.as_u32 = args->local_ip.as_u32;
      sa->is_tunnel = 1;
      sa->use_esn = args->esn;
      sa->use_anti_replay = args->anti_replay;
      sa->integ_alg = args->integ_alg;
      if (args->remote_integ_key_len <= sizeof (args->remote_integ_key))
	{
	  sa->integ_key_len = args->remote_integ_key_len;
	  clib_memcpy (sa->integ_key, args->remote_integ_key,
		       args->remote_integ_key_len);
	}
      sa->crypto_alg = args->crypto_alg;
      if (args->remote_crypto_key_len <= sizeof (args->remote_crypto_key))
	{
	  sa->crypto_key_len = args->remote_crypto_key_len;
	  clib_memcpy (sa->crypto_key, args->remote_crypto_key,
		       args->remote_crypto_key_len);
	}
			/* kingwel, initialize encrypt & hmac context */
			ipsec_create_sa_contexts (sa, 0);

      pool_get (im->sad, sa);
      memset (sa, 0, sizeof (*sa));
      t->output_sa_index = sa - im->sad;
      sa->spi = args->local_spi;
      sa->tunnel_src_addr.ip4.as_u32 = args->local_ip.as_u32;
      sa->tunnel_dst_addr.ip4.as_u32 = args->remote_ip.as_u32;
      sa->is_tunnel = 1;
      sa->use_esn = args->esn;
      sa->use_anti_replay = args->anti_replay;
      sa->integ_alg = args->integ_alg;
      if (args->local_integ_key_len <= sizeof (args->local_integ_key))
	{
	  sa->integ_key_len = args->local_integ_key_len;
	  clib_memcpy (sa->integ_key, args->local_integ_key,
		       args->local_integ_key_len);
	}
      sa->crypto_alg = args->crypto_alg;
      if (args->local_crypto_key_len <= sizeof (args->local_crypto_key))
	{
	  sa->crypto_key_len = args->local_crypto_key_len;
	  clib_memcpy (sa->crypto_key, args->local_crypto_key,
		       args->local_crypto_key_len);
	}
			/* kingwel, initialize encrypt & hmac context */
			ipsec_create_sa_contexts (sa, 1);

      hash_set (im->ipsec_if_pool_index_by_key, key,
		t - im->tunnel_interfaces);

      hw_if_index = vnet_register_interface (vnm, ipsec_device_class.index,
					     t - im->tunnel_interfaces,
					     ipsec_hw_class.index,
					     t - im->tunnel_interfaces);

      hi = vnet_get_hw_interface (vnm, hw_if_index);
      hi->output_node_index = ipsec_if_output_node.index;
      t->hw_if_index = hw_if_index;

      vnet_feature_enable_disable ("interface-output", "ipsec-if-output",
				   hi->sw_if_index, 1, 0, 0);

      /*1st interface, register protocol */
      if (pool_elts (im->tunnel_interfaces) == 1)
	ip4_register_protocol (IP_PROTOCOL_IPSEC_ESP,
			       ipsec_if_input_node.index);

    }
  else
    {
      /* check if exists */
      if (!p)
	return VNET_API_ERROR_INVALID_VALUE;

      t = pool_elt_at_index (im->tunnel_interfaces, p[0]);
      hi = vnet_get_hw_interface (vnm, t->hw_if_index);
      vnet_sw_interface_set_flags (vnm, hi->sw_if_index, 0);	/* admin down */

      vnet_feature_enable_disable ("interface-output", "ipsec-if-output",
				   hi->sw_if_index, 0, 0, 0);

      vnet_delete_hw_interface (vnm, t->hw_if_index);

      /* delete input and output SA */
      sa = pool_elt_at_index (im->sad, t->input_sa_index);
			ipsec_delete_sa_contexts (sa);

      pool_put (im->sad, sa);

      sa = pool_elt_at_index (im->sad, t->output_sa_index);
			ipsec_delete_sa_contexts (sa);

      pool_put (im->sad, sa);

      hash_unset (im->ipsec_if_pool_index_by_key, key);
      hash_unset (im->ipsec_if_real_dev_by_show_dev, t->show_instance);

      pool_put (im->tunnel_interfaces, t);
    }

  if (sw_if_index)
    *sw_if_index = hi->sw_if_index;

  return 0;
}

int
ipsec_add_del_ipsec_gre_tunnel (vnet_main_t * vnm,
				ipsec_add_del_ipsec_gre_tunnel_args_t * args)
{
  ipsec_tunnel_if_t *t = 0;
  ipsec_main_t *im = &ipsec_main;
  uword *p;
  ipsec_sa_t *sa;
  u64 key;
  u32 isa, osa;

  p = hash_get (im->sa_index_by_sa_id, args->local_sa_id);
  if (!p)
    return VNET_API_ERROR_INVALID_VALUE;
  isa = p[0];

  p = hash_get (im->sa_index_by_sa_id, args->remote_sa_id);
  if (!p)
    return VNET_API_ERROR_INVALID_VALUE;
  osa = p[0];
  sa = pool_elt_at_index (im->sad, p[0]);

  if (sa->is_tunnel)
    key = (u64) sa->tunnel_dst_addr.ip4.as_u32 << 32 | (u64) sa->spi;
  else
    key = (u64) args->remote_ip.as_u32 << 32 | (u64) sa->spi;

  p = hash_get (im->ipsec_if_pool_index_by_key, key);

  if (args->is_add)
    {
      /* check if same src/dst pair exists */
      if (p)
	return VNET_API_ERROR_INVALID_VALUE;

      pool_get_aligned (im->tunnel_interfaces, t, CLIB_CACHE_LINE_BYTES);
      memset (t, 0, sizeof (*t));

      t->input_sa_index = isa;
      t->output_sa_index = osa;
      t->hw_if_index = ~0;
      hash_set (im->ipsec_if_pool_index_by_key, key,
		t - im->tunnel_interfaces);

      /*1st interface, register protocol */
      if (pool_elts (im->tunnel_interfaces) == 1)
	ip4_register_protocol (IP_PROTOCOL_IPSEC_ESP,
			       ipsec_if_input_node.index);
    }
  else
    {
      /* check if exists */
      if (!p)
	return VNET_API_ERROR_INVALID_VALUE;

      t = pool_elt_at_index (im->tunnel_interfaces, p[0]);
      hash_unset (im->ipsec_if_pool_index_by_key, key);
      pool_put (im->tunnel_interfaces, t);
    }
  return 0;
}

int
ipsec_set_interface_key (vnet_main_t * vnm, u32 hw_if_index,
			 ipsec_if_set_key_type_t type, u8 alg, u8 * key)
{
  ipsec_main_t *im = &ipsec_main;
  vnet_hw_interface_t *hi;
  ipsec_tunnel_if_t *t;
  ipsec_sa_t *sa;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  t = pool_elt_at_index (im->tunnel_interfaces, hi->dev_instance);

#if 0 //kingwel
  if (hi->flags & VNET_HW_INTERFACE_FLAG_LINK_UP)
    return VNET_API_ERROR_SYSCALL_ERROR_1;
#endif

  if (type == IPSEC_IF_SET_KEY_TYPE_LOCAL_CRYPTO)
    {
      sa = pool_elt_at_index (im->sad, t->output_sa_index);
      sa->crypto_alg = alg;
      sa->crypto_key_len = vec_len (key);
      clib_memcpy (sa->crypto_key, key, vec_len (key));
			ipsec_set_sa_contexts_crypto_key (sa, 1);
    }
  else if (type == IPSEC_IF_SET_KEY_TYPE_LOCAL_INTEG)
    {
      sa = pool_elt_at_index (im->sad, t->output_sa_index);
      sa->integ_alg = alg;
      sa->integ_key_len = vec_len (key);
      clib_memcpy (sa->integ_key, key, vec_len (key));
			ipsec_set_sa_contexts_integ_key (sa);
    }
  else if (type == IPSEC_IF_SET_KEY_TYPE_REMOTE_CRYPTO)
    {
      sa = pool_elt_at_index (im->sad, t->input_sa_index);
      sa->crypto_alg = alg;
      sa->crypto_key_len = vec_len (key);
      clib_memcpy (sa->crypto_key, key, vec_len (key));
			ipsec_set_sa_contexts_crypto_key (sa, 0);
    }
  else if (type == IPSEC_IF_SET_KEY_TYPE_REMOTE_INTEG)
    {
      sa = pool_elt_at_index (im->sad, t->input_sa_index);
      sa->integ_alg = alg;
      sa->integ_key_len = vec_len (key);
      clib_memcpy (sa->integ_key, key, vec_len (key));
			ipsec_set_sa_contexts_integ_key (sa);
    }
  else
    return VNET_API_ERROR_INVALID_VALUE;

  return 0;
}


int
ipsec_set_interface_sa (vnet_main_t * vnm, u32 hw_if_index, u32 sa_id,
			u8 is_outbound)
{
  ipsec_main_t *im = &ipsec_main;
  vnet_hw_interface_t *hi;
  ipsec_tunnel_if_t *t;
  ipsec_sa_t *sa, *old_sa;
  u32 sa_index, old_sa_index;
  uword *p;

  hi = vnet_get_hw_interface (vnm, hw_if_index);
  t = pool_elt_at_index (im->tunnel_interfaces, hi->dev_instance);

  sa_index = ipsec_get_sa_index_by_sa_id (sa_id);
  if (sa_index == ~0)
    {
      clib_warning ("SA with ID %u not found", sa_id);
      return VNET_API_ERROR_INVALID_VALUE;
    }

  if (ipsec_is_sa_used (sa_index))
    {
      clib_warning ("SA with ID %u is already in use", sa_id);
      return VNET_API_ERROR_INVALID_VALUE;
    }

  sa = pool_elt_at_index (im->sad, sa_index);
  if (sa->is_tunnel_ip6)
    {
      clib_warning ("IPsec interface not supported with IPv6 endpoints");
      return VNET_API_ERROR_UNIMPLEMENTED;
    }

  if (!is_outbound)
    {
      u64 key;

      old_sa_index = t->input_sa_index;
      old_sa = pool_elt_at_index (im->sad, old_sa_index);

      /* unset old inbound hash entry. packets should stop arriving */
      key =
	(u64) old_sa->tunnel_src_addr.ip4.as_u32 << 32 | (u64) old_sa->spi;
      p = hash_get (im->ipsec_if_pool_index_by_key, key);
      if (p)
	hash_unset (im->ipsec_if_pool_index_by_key, key);

      /* set new inbound SA, then set new hash entry */
      t->input_sa_index = sa_index;
      key = (u64) sa->tunnel_src_addr.ip4.as_u32 << 32 | (u64) sa->spi;
      hash_set (im->ipsec_if_pool_index_by_key, key, hi->dev_instance);
    }
  else
    {
      old_sa_index = t->output_sa_index;
      old_sa = pool_elt_at_index (im->sad, old_sa_index);
      t->output_sa_index = sa_index;
    }

  /* remove sa_id to sa_index mapping on old SA */
  if (ipsec_get_sa_index_by_sa_id (old_sa->id) == old_sa_index)
    hash_unset (im->sa_index_by_sa_id, old_sa->id);

  if (im->cb.add_del_sa_sess_cb)
    {
      clib_error_t *err;

      err = im->cb.add_del_sa_sess_cb (old_sa_index, 0);
      if (err)
	return VNET_API_ERROR_SYSCALL_ERROR_1;
    }

  pool_put (im->sad, old_sa);

  return 0;
}


clib_error_t *
ipsec_tunnel_if_init (vlib_main_t * vm)
{
  //ipsec_main_t *im = &ipsec_main;
  return 0;
}

VLIB_INIT_FUNCTION (ipsec_tunnel_if_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
