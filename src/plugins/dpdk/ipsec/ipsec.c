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
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/api_errno.h>
#include <vnet/ipsec/ipsec.h>
#include <vlib/node_funcs.h>

#include <dpdk/device/dpdk.h>
#include <dpdk/ipsec/ipsec.h>

dpdk_crypto_main_t dpdk_crypto_main;

#define EMPTY_STRUCT {0}

static void
algos_init (u32 n_mains)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_alg_t *a;

  vec_validate_aligned (dcm->cipher_algs, IPSEC_CRYPTO_N_ALG - 1, 8);

  {
#define _(v,f,str) \
  dcm->cipher_algs[IPSEC_CRYPTO_ALG_##f].name = str; \
  dcm->cipher_algs[IPSEC_CRYPTO_ALG_##f].disabled = n_mains;
    foreach_ipsec_crypto_alg
#undef _
  }

  /* Minimum boundary for ciphers is 4B, required by ESP */
  a = &dcm->cipher_algs[IPSEC_CRYPTO_ALG_NONE];
  a->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
  a->alg = RTE_CRYPTO_CIPHER_NULL;
  a->boundary = 4;		/* 1 */
  a->key_len = 0;
  a->iv_len = 0;

  a = &dcm->cipher_algs[IPSEC_CRYPTO_ALG_AES_CBC_128];
  a->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
  a->alg = RTE_CRYPTO_CIPHER_AES_CBC;
  a->boundary = 16;
  a->key_len = 16;
  a->iv_len = 16;

  a = &dcm->cipher_algs[IPSEC_CRYPTO_ALG_AES_CBC_192];
  a->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
  a->alg = RTE_CRYPTO_CIPHER_AES_CBC;
  a->boundary = 16;
  a->key_len = 24;
  a->iv_len = 16;

  a = &dcm->cipher_algs[IPSEC_CRYPTO_ALG_AES_CBC_256];
  a->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
  a->alg = RTE_CRYPTO_CIPHER_AES_CBC;
  a->boundary = 16;
  a->key_len = 32;
  a->iv_len = 16;

  a = &dcm->cipher_algs[IPSEC_CRYPTO_ALG_AES_CTR_128];
  a->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
  a->alg = RTE_CRYPTO_CIPHER_AES_CTR;
  a->boundary = 4;		/* 1 */
  a->key_len = 16;
  a->iv_len = 8;

  a = &dcm->cipher_algs[IPSEC_CRYPTO_ALG_AES_CTR_192];
  a->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
  a->alg = RTE_CRYPTO_CIPHER_AES_CTR;
  a->boundary = 4;		/* 1 */
  a->key_len = 24;
  a->iv_len = 8;

  a = &dcm->cipher_algs[IPSEC_CRYPTO_ALG_AES_CTR_256];
  a->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
  a->alg = RTE_CRYPTO_CIPHER_AES_CTR;
  a->boundary = 4;		/* 1 */
  a->key_len = 32;
  a->iv_len = 8;

#define AES_GCM_TYPE RTE_CRYPTO_SYM_XFORM_AEAD
#define AES_GCM_ALG RTE_CRYPTO_AEAD_AES_GCM

  a = &dcm->cipher_algs[IPSEC_CRYPTO_ALG_AES_GCM_128];
  a->type = AES_GCM_TYPE;
  a->alg = AES_GCM_ALG;
  a->boundary = 4;		/* 1 */
  a->key_len = 16;
  a->iv_len = 8;
  a->trunc_size = 16;

  a = &dcm->cipher_algs[IPSEC_CRYPTO_ALG_AES_GCM_192];
  a->type = AES_GCM_TYPE;
  a->alg = AES_GCM_ALG;
  a->boundary = 4;		/* 1 */
  a->key_len = 24;
  a->iv_len = 8;
  a->trunc_size = 16;

  a = &dcm->cipher_algs[IPSEC_CRYPTO_ALG_AES_GCM_256];
  a->type = AES_GCM_TYPE;
  a->alg = AES_GCM_ALG;
  a->boundary = 4;		/* 1 */
  a->key_len = 32;
  a->iv_len = 8;
  a->trunc_size = 16;

  a = &dcm->cipher_algs[IPSEC_CRYPTO_ALG_DES_CBC];
  a->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
  a->alg = RTE_CRYPTO_CIPHER_DES_CBC;
  a->boundary = 8;
  a->key_len = 8;
  a->iv_len = 8;

  a = &dcm->cipher_algs[IPSEC_CRYPTO_ALG_3DES_CBC];
  a->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
  a->alg = RTE_CRYPTO_CIPHER_3DES_CBC;
  a->boundary = 8;
  a->key_len = 24;
  a->iv_len = 8;


  vec_validate (dcm->auth_algs, IPSEC_INTEG_N_ALG - 1);

  {
#define _(v,f,str) \
  dcm->auth_algs[IPSEC_INTEG_ALG_##f].name = str; \
  dcm->auth_algs[IPSEC_INTEG_ALG_##f].disabled = n_mains;
    foreach_ipsec_integ_alg
#undef _
  }

  a = &dcm->auth_algs[IPSEC_INTEG_ALG_NONE];
  a->type = RTE_CRYPTO_SYM_XFORM_AUTH;
  a->alg = RTE_CRYPTO_AUTH_NULL;
  a->key_len = 0;
  a->trunc_size = 0;

  a = &dcm->auth_algs[IPSEC_INTEG_ALG_MD5_96];
  a->type = RTE_CRYPTO_SYM_XFORM_AUTH;
  a->alg = RTE_CRYPTO_AUTH_MD5_HMAC;
  a->key_len = 16;
  a->trunc_size = 12;

  a = &dcm->auth_algs[IPSEC_INTEG_ALG_SHA1_96];
  a->type = RTE_CRYPTO_SYM_XFORM_AUTH;
  a->alg = RTE_CRYPTO_AUTH_SHA1_HMAC;
  a->key_len = 20;
  a->trunc_size = 12;

  a = &dcm->auth_algs[IPSEC_INTEG_ALG_SHA_256_96];
  a->type = RTE_CRYPTO_SYM_XFORM_AUTH;
  a->alg = RTE_CRYPTO_AUTH_SHA256_HMAC;
  a->key_len = 32;
  a->trunc_size = 12;

  a = &dcm->auth_algs[IPSEC_INTEG_ALG_SHA_224_112];
  a->type = RTE_CRYPTO_SYM_XFORM_AUTH;
  a->alg = RTE_CRYPTO_AUTH_SHA224_HMAC;
  a->key_len = 28;
  a->trunc_size = 14;

  a = &dcm->auth_algs[IPSEC_INTEG_ALG_SHA_256_128];
  a->type = RTE_CRYPTO_SYM_XFORM_AUTH;
  a->alg = RTE_CRYPTO_AUTH_SHA256_HMAC;
  a->key_len = 32;
  a->trunc_size = 16;

  a = &dcm->auth_algs[IPSEC_INTEG_ALG_SHA_384_192];
  a->type = RTE_CRYPTO_SYM_XFORM_AUTH;
  a->alg = RTE_CRYPTO_AUTH_SHA384_HMAC;
  a->key_len = 48;
  a->trunc_size = 24;

  a = &dcm->auth_algs[IPSEC_INTEG_ALG_SHA_512_256];
  a->type = RTE_CRYPTO_SYM_XFORM_AUTH;
  a->alg = RTE_CRYPTO_AUTH_SHA512_HMAC;
  a->key_len = 64;
  a->trunc_size = 32;

  a = &dcm->auth_algs[IPSEC_INTEG_ALG_AES_XCBC];
  a->type = RTE_CRYPTO_SYM_XFORM_AUTH;
  a->alg = RTE_CRYPTO_AUTH_AES_XCBC_MAC;
  a->key_len = 16;
  a->trunc_size = 12;

  a = &dcm->auth_algs[IPSEC_INTEG_ALG_AES_CMAC];
  a->type = RTE_CRYPTO_SYM_XFORM_AUTH;
  a->alg = RTE_CRYPTO_AUTH_AES_CMAC;
  a->key_len = 16;
  a->trunc_size = 4;
}

static u8
cipher_alg_index (const crypto_alg_t * alg)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;

  return (alg - dcm->cipher_algs);
}

static u8
auth_alg_index (const crypto_alg_t * alg)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;

  return (alg - dcm->auth_algs);
}

static crypto_alg_t *
cipher_cap_to_alg (const struct rte_cryptodev_capabilities *cap, u8 key_len)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_alg_t *alg;

  if (cap->op != RTE_CRYPTO_OP_TYPE_SYMMETRIC)
    return NULL;

  /* *INDENT-OFF* */
  vec_foreach (alg, dcm->cipher_algs)
    {
      if ((cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_CIPHER) &&
	  (alg->type == RTE_CRYPTO_SYM_XFORM_CIPHER) &&
	  (cap->sym.cipher.algo == alg->alg) &&
	  (alg->key_len == key_len))
	return alg;
      if ((cap->sym.xform_type == RTE_CRYPTO_SYM_XFORM_AEAD) &&
	  (alg->type == RTE_CRYPTO_SYM_XFORM_AEAD) &&
	  (cap->sym.aead.algo == alg->alg) &&
	  (alg->key_len == key_len))
	return alg;
    }
  /* *INDENT-ON* */

  return NULL;
}

static crypto_alg_t *
auth_cap_to_alg (const struct rte_cryptodev_capabilities *cap, u8 trunc_size)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_alg_t *alg;

  if ((cap->op != RTE_CRYPTO_OP_TYPE_SYMMETRIC) ||
      (cap->sym.xform_type != RTE_CRYPTO_SYM_XFORM_AUTH))
    return NULL;

  /* *INDENT-OFF* */
  vec_foreach (alg, dcm->auth_algs)
    {
      if ((cap->sym.auth.algo == alg->alg) &&
	  (alg->trunc_size == trunc_size))
	return alg;
    }
  /* *INDENT-ON* */

  return NULL;
}

static void
crypto_set_aead_xform (struct rte_crypto_sym_xform *xform, crypto_alg_t * c,
		       ipsec_sa_t * sa, u8 is_outbound)
{
  ASSERT (c->type == RTE_CRYPTO_SYM_XFORM_AEAD);

  xform->type = RTE_CRYPTO_SYM_XFORM_AEAD;
  xform->aead.algo = c->alg;
  xform->aead.key.data = sa->crypto_key;
  xform->aead.key.length = c->key_len;
  xform->aead.iv.offset =
    crypto_op_get_priv_offset () + offsetof (dpdk_op_priv_t, cb);
  xform->aead.iv.length = 12;
  xform->aead.digest_length = c->trunc_size;
  xform->aead.aad_length = sa->use_esn ? 12 : 8;
  xform->next = NULL;

  if (is_outbound)
    xform->aead.op = RTE_CRYPTO_AEAD_OP_ENCRYPT;
  else
    xform->aead.op = RTE_CRYPTO_AEAD_OP_DECRYPT;
}

static void
crypto_set_cipher_xform (struct rte_crypto_sym_xform *xform, crypto_alg_t * c,
			 ipsec_sa_t * sa, u8 is_outbound)
{
  ASSERT (c->type == RTE_CRYPTO_SYM_XFORM_CIPHER);

  xform->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
  xform->cipher.algo = c->alg;
  xform->cipher.key.data = sa->crypto_key;
  xform->cipher.key.length = c->key_len;
  xform->cipher.iv.offset =
    crypto_op_get_priv_offset () + offsetof (dpdk_op_priv_t, cb);
  xform->cipher.iv.length = c->iv_len;

  /* kingwel, for CTR, add 8 to make AESNI MB happy */
  if (xform->cipher.algo == RTE_CRYPTO_CIPHER_AES_CTR)
    xform->cipher.iv.length += 4;

  xform->next = NULL;

  if (is_outbound)
    xform->cipher.op = RTE_CRYPTO_CIPHER_OP_ENCRYPT;
  else
    xform->cipher.op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
}

static void
crypto_set_auth_xform (struct rte_crypto_sym_xform *xform, crypto_alg_t * a,
		       ipsec_sa_t * sa, u8 is_outbound)
{
  ASSERT (a->type == RTE_CRYPTO_SYM_XFORM_AUTH);

  xform->type = RTE_CRYPTO_SYM_XFORM_AUTH;
  xform->auth.algo = a->alg;
  xform->auth.key.data = sa->integ_key;
  xform->auth.key.length = a->key_len;
  xform->auth.digest_length = a->trunc_size;
  xform->next = NULL;

  if (is_outbound)
    xform->auth.op = RTE_CRYPTO_AUTH_OP_GENERATE;
  else
    xform->auth.op = RTE_CRYPTO_AUTH_OP_VERIFY;
}

i32
crypto_make_session (u8 thread_idx, crypto_session_t * cs, ipsec_sa_t * sa,
		     crypto_resource_t * res, crypto_worker_main_t * cwm,
		     u8 is_outbound)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_data_t *data;
  struct rte_crypto_sym_xform cipher_xform = { 0 };
  struct rte_crypto_sym_xform auth_xform = { 0 };
  struct rte_crypto_sym_xform *xfs;

  data = vec_elt_at_index (dcm->per_numa_data, res->numa);

  /* make xform */
  if (cs->cipher_alg->type == RTE_CRYPTO_SYM_XFORM_AEAD)
    {
      crypto_set_aead_xform (&cipher_xform, cs->cipher_alg, sa, is_outbound);
      xfs = &cipher_xform;
    }
  else
    {
      crypto_set_cipher_xform (&cipher_xform, cs->cipher_alg, sa,
			       is_outbound);
      crypto_set_auth_xform (&auth_xform, cs->auth_alg, sa, is_outbound);

      if (is_outbound)
	{
	  cipher_xform.next = &auth_xform;
	  xfs = &cipher_xform;
	}
      else
	{
	  auth_xform.next = &cipher_xform;
	  xfs = &auth_xform;
	}
    }

  struct rte_cryptodev_sym_session *s =
    rte_cryptodev_sym_session_create (data->session_h);
  if (!s)
    {
      data->session_h_failed += 1;
      return 0;
    }

  i32 ret =
    rte_cryptodev_sym_session_init (res->dev_id, s, xfs, data->session_drv);
  if (ret)
    {
      rte_cryptodev_sym_session_free (s);
      data->session_drv_failed += 1;
      return 0;
    }

  cs->sessions[thread_idx] = s;

  return 1;
}

static clib_error_t *
dpdk_crypto_session_disposal (u64 ts)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_session_disposal_t *s = 0;
  i32 ret;

  /* *INDENT-OFF* */
  vec_foreach (s, dcm->session_disposal)
  {
    /* ordered vector by timestamp */
    if (!(s->ts + dcm->session_timeout < ts))
			break;

		int index;
    vec_foreach_index (index, dcm->dev)
		{
			/* first clear driver based session private data */
			ret = rte_cryptodev_sym_session_clear (index, s->session);
		}

    ret = rte_cryptodev_sym_session_free (s->session);

		clib_warning ("free session %p rv=%d", s->session, ret);

    ASSERT (!ret);
  }
  /* *INDENT-ON* */

  if (s && s <= vec_end (dcm->session_disposal))
    vec_delete (dcm->session_disposal, s - dcm->session_disposal, 0);

  return 0;
}

static void
dpdk_crypto_defer_clear_session (struct rte_cryptodev_sym_session **sessions)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;

  /* defer to remove all */
  u64 ts = unix_time_now_nsec ();
  dpdk_crypto_session_disposal (ts);

  struct rte_cryptodev_sym_session **s;
  vec_foreach (s, sessions)
  {
    if (!s[0])
      continue;

    /* add to disposal queue */
    crypto_session_disposal_t sd;
    sd.ts = ts;
    sd.session = s[0];

    vec_add1 (dcm->session_disposal, sd);

    clib_warning ("add session %p to disposal list", s[0]);
  }
}

static clib_error_t *
add_del_sa_session (u32 sa_index, u8 is_add)
{
  ipsec_main_t *im = &ipsec_main;
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_session_t *session;
  u32 cs_index;

  if (is_add)
    {
      ipsec_sa_t *sa = pool_elt_at_index (im->sad, sa_index);

      /* make sure we have enough mapping entries */
      vec_validate_init_empty_aligned (dcm->sa_session_index, sa_index,
				       (u32) ~ 0, CLIB_CACHE_LINE_BYTES);

      cs_index = vec_elt (dcm->sa_session_index, sa_index);

      ASSERT (cs_index == (u32) (~0));

      pool_get_aligned (dcm->sa_session, session, CLIB_CACHE_LINE_BYTES);
      memset (session, 0, sizeof (*session));

      session->sa_index = sa_index;

      session->cipher_alg =
	vec_elt_at_index (dcm->cipher_algs, sa->crypto_alg);
      session->auth_alg = vec_elt_at_index (dcm->auth_algs, sa->integ_alg);

      session->is_aead =
	(session->cipher_alg->type == RTE_CRYPTO_SYM_XFORM_AEAD);
      if (session->is_aead)
	session->auth_alg = session->cipher_alg;

      /* make the mapping */
      vec_elt (dcm->sa_session_index, sa_index) = session - dcm->sa_session;

      /* make per thread cryptodev sesion */
      vlib_thread_main_t *tm = vlib_get_thread_main ();
      u32 n_mains = tm->n_vlib_mains;

      vec_validate_init_empty (session->sessions, n_mains - 1, 0);

      return 0;
    }

  cs_index = vec_elt (dcm->sa_session_index, sa_index);
  ASSERT (cs_index != (u32) (~0));

  session = pool_elt_at_index (dcm->sa_session, cs_index);

  dpdk_crypto_defer_clear_session (session->sessions);

  vec_free (session->sessions);

  /* return it back to pool */
  pool_put (dcm->sa_session, session);
  /* clear sa session */
  vec_elt (dcm->sa_session_index, sa_index) = (u32) ~ 0;

  return 0;
}

static clib_error_t *
update_sa_session (u32 sa_index)
{
  ipsec_main_t *im = &ipsec_main;
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  u32 cs_index;
  crypto_session_t *session;

  ipsec_sa_t *sa = pool_elt_at_index (im->sad, sa_index);

  cs_index = vec_elt (dcm->sa_session_index, sa_index);
  ASSERT (cs_index != (u32) (~0));

  session = pool_elt_at_index (dcm->sa_session, cs_index);

  session->cipher_alg = vec_elt_at_index (dcm->cipher_algs, sa->crypto_alg);
  session->auth_alg = vec_elt_at_index (dcm->auth_algs, sa->integ_alg);

  session->is_aead = (session->cipher_alg->type == RTE_CRYPTO_SYM_XFORM_AEAD);
  if (session->is_aead)
    session->auth_alg = session->cipher_alg;

  dpdk_crypto_defer_clear_session (session->sessions);

  /* zero cryptodev sesions */
  vec_zero (session->sessions);

  return 0;
}

#if 0
static clib_error_t *
dpdk_ipsec_check_support (ipsec_sa_t * sa)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;

  if (sa->integ_alg == IPSEC_INTEG_ALG_NONE)
    switch (sa->crypto_alg)
      {
      case IPSEC_CRYPTO_ALG_NONE:
      case IPSEC_CRYPTO_ALG_AES_GCM_128:
      case IPSEC_CRYPTO_ALG_AES_GCM_192:
      case IPSEC_CRYPTO_ALG_AES_GCM_256:
	break;
      default:
	return clib_error_return (0, "unsupported integ-alg %U crypto-alg %U",
				  format_ipsec_integ_alg, sa->integ_alg,
				  format_ipsec_crypto_alg, sa->crypto_alg);
      }

  /* XXX do we need the NONE check? */
  if (sa->crypto_alg != IPSEC_CRYPTO_ALG_NONE &&
      dcm->cipher_algs[sa->crypto_alg].disabled)
    return clib_error_return (0, "disabled crypto-alg %U",
			      format_ipsec_crypto_alg, sa->crypto_alg);

  /* XXX do we need the NONE check? */
  if (sa->integ_alg != IPSEC_INTEG_ALG_NONE &&
      dcm->auth_algs[sa->integ_alg].disabled)
    return clib_error_return (0, "disabled integ-alg %U",
			      format_ipsec_integ_alg, sa->integ_alg);
  return NULL;
}
#endif

static void
crypto_parse_capabilities (crypto_dev_t * dev,
			   const struct rte_cryptodev_capabilities *cap,
			   u32 n_mains)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_alg_t *alg;
  u8 len, inc;

  for (; cap->op != RTE_CRYPTO_OP_TYPE_UNDEFINED; cap++)
    {
      /* A single capability maps to multiple cipher/auth algorithms */
      switch (cap->sym.xform_type)
	{
	case RTE_CRYPTO_SYM_XFORM_AEAD:
	case RTE_CRYPTO_SYM_XFORM_CIPHER:
	  inc = cap->sym.cipher.key_size.increment;
	  inc = inc ? inc : 1;
	  for (len = cap->sym.cipher.key_size.min;
	       len <= cap->sym.cipher.key_size.max; len += inc)
	    {
	      alg = cipher_cap_to_alg (cap, len);
	      if (!alg)
		continue;
	      dev->cipher_support[cipher_alg_index (alg)] = 1;
	      alg->resources += vec_len (dev->free_resources);
	      /* At least enough resources to support one algo */
	      dcm->enabled |= (alg->resources >= n_mains);
	    }
	  break;
	case RTE_CRYPTO_SYM_XFORM_AUTH:
	  inc = cap->sym.auth.digest_size.increment;
	  inc = inc ? inc : 1;
	  for (len = 0;		//cap->sym.auth.digest_size.min;
	       len <= cap->sym.auth.digest_size.max; len += inc)
	    {
	      alg = auth_cap_to_alg (cap, len);
	      if (!alg)
		continue;
	      dev->auth_support[auth_alg_index (alg)] = 1;
	      alg->resources += vec_len (dev->free_resources);
	      /* At least enough resources to support one algo */
	      dcm->enabled |= (alg->resources >= n_mains);
	    }
	  break;
	default:
	  ;
	}
    }
}

#define DPDK_CRYPTO_N_QUEUE_DESC  2048

static clib_error_t *
crypto_dev_conf (u8 dev, u16 n_qp, u8 numa)
{
  struct rte_cryptodev_config dev_conf;
  struct rte_cryptodev_qp_conf qp_conf;
  i32 ret;
  u16 qp;
  char *error_str;

  dev_conf.socket_id = numa;
  dev_conf.nb_queue_pairs = n_qp;

  error_str = "failed to configure crypto device %u";
  ret = rte_cryptodev_configure (dev, &dev_conf);
  if (ret < 0)
    return clib_error_return (0, error_str, dev);

  error_str = "failed to setup crypto device %u queue pair %u";
  qp_conf.nb_descriptors = DPDK_CRYPTO_N_QUEUE_DESC;
  for (qp = 0; qp < n_qp; qp++)
    {
      /* note here, don't offer session pool, we are using OP as RTE_CRYPTO_OP_WITH_SESSION */
      ret = rte_cryptodev_queue_pair_setup (dev, qp, &qp_conf, numa, NULL);
      if (ret < 0)
	return clib_error_return (0, error_str, dev, qp);
    }

  return 0;
}

static void
crypto_scan_devs (u32 n_mains)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  struct rte_cryptodev *cryptodev;
  struct rte_cryptodev_info info;
  crypto_dev_t *dev;
  crypto_resource_t *res;
  clib_error_t *error;
  u32 i;
  u16 max_res_idx, res_idx, j;
  u8 drv_id;

  vec_validate_init_empty (dcm->dev, rte_cryptodev_count () - 1,
			   (crypto_dev_t) EMPTY_STRUCT);

  for (i = 0; i < rte_cryptodev_count (); i++)
    {
      dev = vec_elt_at_index (dcm->dev, i);

      cryptodev = &rte_cryptodevs[i];
      rte_cryptodev_info_get (i, &info);

      dev->id = i;
      dev->name = cryptodev->data->name;
      dev->numa = rte_cryptodev_socket_id (i);
      dev->features = info.feature_flags;
      dev->max_qp = info.max_nb_queue_pairs;
      dev->max_nb_sessions = info.sym.max_nb_sessions;
      dev->max_nb_sessions_per_qp = info.sym.max_nb_sessions_per_qp;
      drv_id = info.driver_id;
      if (drv_id >= vec_len (dcm->drv))
	vec_validate_init_empty (dcm->drv, drv_id,
				 (crypto_drv_t) EMPTY_STRUCT);
      vec_elt_at_index (dcm->drv, drv_id)->name = info.driver_name;
      dev->drv_id = drv_id;
      vec_add1 (vec_elt_at_index (dcm->drv, drv_id)->devs, i);

      if (!(info.feature_flags & RTE_CRYPTODEV_FF_SYM_OPERATION_CHAINING))
	continue;

      if ((error = crypto_dev_conf (i, dev->max_qp, dev->numa)))
	{
	  clib_error_report (error);
	  continue;
	}

      max_res_idx = (dev->max_qp / 2) - 1;

      vec_validate (dev->free_resources, max_res_idx);

      res_idx = vec_len (dcm->resource);
      vec_validate_init_empty_aligned (dcm->resource, res_idx + max_res_idx,
				       (crypto_resource_t) EMPTY_STRUCT,
				       CLIB_CACHE_LINE_BYTES);

      for (j = 0; j <= max_res_idx; j++, res_idx++)
	{
	  vec_elt (dev->free_resources, max_res_idx - j) = res_idx;
	  res = &dcm->resource[res_idx];
	  res->dev_id = i;
	  res->drv_id = drv_id;
	  res->qp_id = j * 2;
	  res->numa = dev->numa;
	  res->thread_idx = (u16) ~ 0;
	}

      crypto_parse_capabilities (dev, info.capabilities, n_mains);


      if (rte_cryptodev_start (i))
	clib_error ("Failed to start cryptodev id %u %s\n",
		    cryptodev->data->name);
    }
}

void
crypto_auto_placement (void)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_resource_t *res;
  crypto_worker_main_t *cwm;
  crypto_dev_t *dev;
  u32 thread_idx, skip_master;
  u16 res_idx, *idx;
  u8 used;
  u16 i;

  skip_master = vlib_num_workers () > 0;

  /* *INDENT-OFF* */
  vec_foreach (dev, dcm->dev)
    {
      vec_foreach_index (thread_idx, dcm->workers_main)
	{
	  if (vec_len (dev->free_resources) == 0)
	    break;

	  if (thread_idx < skip_master)
	    continue;

	  /* Check thread is not already using the device */
	  vec_foreach (idx, dev->used_resources)
	    if (dcm->resource[idx[0]].thread_idx == thread_idx)
	      continue;

	  cwm = vec_elt_at_index (dcm->workers_main, thread_idx);

	  used = 0;
	  res_idx = vec_pop (dev->free_resources);

	  /* Set device only for supported algos */
	  for (i = 0; i < IPSEC_CRYPTO_N_ALG; i++)
	    if (dev->cipher_support[i] &&
		cwm->cipher_resource_idx[i] == (u16) ~0)
	      {
		dcm->cipher_algs[i].disabled--;
		cwm->cipher_resource_idx[i] = res_idx;
		used = 1;
	      }

	  for (i = 0; i < IPSEC_INTEG_N_ALG; i++)
	    if (dev->auth_support[i] &&
		cwm->auth_resource_idx[i] == (u16) ~0)
	      {
		dcm->auth_algs[i].disabled--;
		cwm->auth_resource_idx[i] = res_idx;
		used = 1;
	      }

	  if (!used)
	    {
	      vec_add1 (dev->free_resources, res_idx);
	      continue;
	    }

	  vec_add1 (dev->used_resources, res_idx);

	  res = vec_elt_at_index (dcm->resource, res_idx);

	  ASSERT (res->thread_idx == (u16) ~0);
	  res->thread_idx = thread_idx;

	  /* Add device to vector of polling resources */
	  vec_add1 (cwm->resource_idx, res_idx);
	}
    }
  /* *INDENT-ON* */
}

static void
crypto_op_init (struct rte_mempool *mempool,
		void *_arg __attribute__ ((unused)),
		void *_obj, unsigned i __attribute__ ((unused)))
{
  struct rte_crypto_op *op = _obj;

  op->sess_type = RTE_CRYPTO_OP_WITH_SESSION;
  op->type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
  op->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;
  op->phys_addr = rte_mempool_virt2iova (_obj);
  op->mempool = mempool;
}

static clib_error_t *
crypto_create_crypto_op_pool (vlib_main_t * vm, u8 numa)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  dpdk_config_main_t *conf = &dpdk_config_main;
  crypto_data_t *data;
  u8 *pool_name;
  u32 pool_priv_size = sizeof (struct rte_crypto_op_pool_private);
  struct rte_crypto_op_pool_private *priv;
  struct rte_mempool *mp;
  clib_error_t *error = NULL;
  vlib_physmem_region_index_t pri;

  data = vec_elt_at_index (dcm->per_numa_data, numa);

  /* Already allocated */
  if (data->crypto_op)
    return NULL;

  pool_name = format (0, "crypto_pool_numa%u%c", numa, 0);

  error =
    dpdk_pool_create (vm, pool_name, crypto_op_len (), conf->num_mbufs,
		      pool_priv_size, 512, numa, &mp, &pri);

  vec_free (pool_name);

  if (error)
    return error;

  /* Initialize mempool private data */
  priv = rte_mempool_get_priv (mp);
  priv->priv_size = pool_priv_size;
  priv->type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;

  /* call the object initializers */
  rte_mempool_obj_iter (mp, crypto_op_init, 0);

  data->crypto_op = mp;

  return NULL;
}

static clib_error_t *
crypto_create_session_h_pool (vlib_main_t * vm, u8 numa, u32 elts)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_data_t *data;
  u8 *pool_name;
  struct rte_mempool *mp;
  clib_error_t *error = NULL;
  vlib_physmem_region_index_t pri;
  u32 elt_size;

  data = vec_elt_at_index (dcm->per_numa_data, numa);

  pool_name = format (0, "session_h_pool_numa%u%c", numa, 0);

  elt_size = rte_cryptodev_get_header_session_size ();

  error =
    dpdk_pool_create (vm, pool_name, elt_size, elts, 0, 512, numa, &mp, &pri);

  vec_free (pool_name);

  if (error)
    return error;

  data->session_h = mp;

  return NULL;
}

static clib_error_t *
crypto_create_session_drv_pool (vlib_main_t * vm, u8 numa, u32 elt_size,
				u32 elts)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_data_t *data;
  u8 *pool_name;
  struct rte_mempool *mp;
  clib_error_t *error = NULL;
  vlib_physmem_region_index_t pri;

  data = vec_elt_at_index (dcm->per_numa_data, numa);

  pool_name = format (0, "session_drv_pool_numa%u%c", numa, 0);

  error =
    dpdk_pool_create (vm, pool_name, elt_size, elts, 0, 512, numa, &mp, &pri);

  vec_free (pool_name);

  if (error)
    return error;

  data->session_drv = mp;

  return NULL;
}

static clib_error_t *
crypto_create_pools (vlib_main_t * vm, u32 * max_sessions)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  clib_error_t *error = NULL;
  crypto_dev_t *dev;

  u32 max_sess_size = 0, sess_sz;
  u32 max_num_sessions = 0, num_sessions;

  /* figure out the best fit private session size */
	/* *INDENT-OFF* */
	vec_foreach (dev, dcm->dev)
	{
		sess_sz = rte_cryptodev_get_private_session_size(dev->id);
		if (sess_sz > max_sess_size)
			max_sess_size = sess_sz;

		num_sessions = dev->max_nb_sessions;
		if (num_sessions > max_num_sessions)
			max_num_sessions = num_sessions;
	}
	/* *INDENT-ON* */

  *max_sessions = max_num_sessions;

  /* *INDENT-OFF* */
  vec_foreach (dev, dcm->dev)
  {
    vec_validate_aligned (dcm->per_numa_data, dev->numa, CLIB_CACHE_LINE_BYTES);
	}
  /* *INDENT-ON* */

  /* *INDENT-OFF* */
  for (int i = 0; i < vec_len (dcm->per_numa_data); i++)
  {
    error = crypto_create_crypto_op_pool (vm, i);
    if (error)
			return error;

    error = crypto_create_session_h_pool (vm, i, max_num_sessions);
    if (error)
			return error;

    error = crypto_create_session_drv_pool (vm, i, max_sess_size, max_num_sessions);
    if (error)
			return error;
  }
  /* *INDENT-ON* */

  return NULL;
}

static void
crypto_disable (void)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_data_t *data;

  dcm->enabled = 0;

  /* *INDENT-OFF* */
  vec_foreach (data, dcm->per_numa_data)
    {
      rte_mempool_free (data->crypto_op);
      rte_mempool_free (data->session_h);
			rte_mempool_free (data->session_drv);
    }
  /* *INDENT-ON* */

  vec_free (dcm->per_numa_data);
  vec_free (dcm->workers_main);
  vec_free (dcm->sa_session_index);
  pool_free (dcm->sa_session);
  vec_free (dcm->dev);
  vec_free (dcm->resource);
  vec_free (dcm->cipher_algs);
  vec_free (dcm->auth_algs);
}

static uword
dpdk_ipsec_process (vlib_main_t * vm, vlib_node_runtime_t * rt,
		    vlib_frame_t * f)
{
  ipsec_main_t *im = &ipsec_main;
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  crypto_worker_main_t *cwm;
  clib_error_t *error = NULL;
  u32 i, skip_master, n_mains;

  n_mains = tm->n_vlib_mains;
  skip_master = vlib_num_workers () > 0;

  algos_init (n_mains - skip_master);

  crypto_scan_devs (n_mains - skip_master);

  if (!(dcm->enabled))
    {
      clib_warning ("not enough DPDK crypto resources, default to OpenSSL");
      crypto_disable ();
      return 0;
    }

  dcm->session_timeout = 10e9;

  vec_validate_init_empty_aligned (dcm->workers_main, n_mains - 1,
				   (crypto_worker_main_t) EMPTY_STRUCT,
				   CLIB_CACHE_LINE_BYTES);

  /* *INDENT-OFF* */
  vec_foreach (cwm, dcm->workers_main)
    {
      vec_validate_init_empty_aligned (cwm->ops, VLIB_FRAME_SIZE - 1, 0,
				       CLIB_CACHE_LINE_BYTES);
      memset (cwm->cipher_resource_idx, ~0,
	      IPSEC_CRYPTO_N_ALG * sizeof(*cwm->cipher_resource_idx));
      memset (cwm->auth_resource_idx, ~0,
	      IPSEC_INTEG_N_ALG * sizeof(*cwm->auth_resource_idx));
    }
  /* *INDENT-ON* */

  crypto_auto_placement ();

  u32 max_sessions = 256;
  error = crypto_create_pools (vm, &max_sessions);
  if (error)
    {
      clib_error_report (error);
      crypto_disable ();
      return 0;
    }

  /* kingwel, initialize the sa sessions */
  vec_validate_init_empty_aligned (dcm->sa_session_index, max_sessions - 1,
				   (u32) (~0), CLIB_CACHE_LINE_BYTES);
  pool_alloc_aligned (dcm->sa_session, max_sessions, CLIB_CACHE_LINE_BYTES);

  /* Add new next node and set it as default */
  vlib_node_t *node, *next_node;

  next_node = vlib_get_node_by_name (vm, (u8 *) "dpdk-esp-encrypt");
  ASSERT (next_node);
  node = vlib_get_node_by_name (vm, (u8 *) "ipsec-output-ip4");
  ASSERT (node);
  im->esp_encrypt_node_index = next_node->index;
  im->esp_encrypt_next_index =
    vlib_node_add_next (vm, node->index, next_node->index);

  next_node = vlib_get_node_by_name (vm, (u8 *) "dpdk-esp-decrypt");
  ASSERT (next_node);
  node = vlib_get_node_by_name (vm, (u8 *) "ipsec-input-ip4");
  ASSERT (node);
  im->esp_decrypt_node_index = next_node->index;
  im->esp_decrypt_next_index =
    vlib_node_add_next (vm, node->index, next_node->index);

  im->cb.add_del_sa_sess_cb = add_del_sa_session;
  im->cb.update_sa_sess_cb = update_sa_session;

  node = vlib_get_node_by_name (vm, (u8 *) "dpdk-crypto-input");
  ASSERT (node);
  for (i = skip_master; i < n_mains; i++)
    vlib_node_set_state (vlib_mains[i], node->index, VLIB_NODE_STATE_POLLING);
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dpdk_ipsec_process_node,static) = {
    .function = dpdk_ipsec_process,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "dpdk-ipsec-process",
    .process_log2_n_stack_bytes = 17,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
