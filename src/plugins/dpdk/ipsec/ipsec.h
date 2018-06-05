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
#ifndef __DPDK_IPSEC_H__
#define __DPDK_IPSEC_H__

#include <vnet/vnet.h>
#include <vppinfra/cache.h>
#include <vnet/ipsec/ipsec.h>

#undef always_inline
#include <rte_config.h>
#include <rte_crypto.h>
#include <rte_cryptodev.h>

#if CLIB_DEBUG > 0
#define always_inline static inline
#else
#define always_inline static inline __attribute__ ((__always_inline__))
#endif

#if CLIB_DEBUG > 0
#define IPSEC_DEBUG_OUTPUT
#endif

#define foreach_dpdk_crypto_input_next		\
  _(DROP, "error-drop")				\
  _(IP4_LOOKUP, "ip4-lookup")                   \
  _(IP6_LOOKUP, "ip6-lookup")                   \
  _(INTERFACE_OUTPUT, "interface-output")	\
  _(DECRYPT_POST, "dpdk-esp-decrypt-post")

typedef enum
{
#define _(f,s) DPDK_CRYPTO_INPUT_NEXT_##f,
  foreach_dpdk_crypto_input_next
#undef _
    DPDK_CRYPTO_INPUT_N_NEXT,
} dpdk_crypto_input_next_t;

#define MAX_QP_PER_LCORE 16

typedef struct
{
  u32 salt;
  u32 iv[2];
  u32 cnt;
} dpdk_gcm_cnt_blk;

typedef struct
{
  dpdk_gcm_cnt_blk cb;
  u32 next;
  u8 aad[16];
  u8 icv[32];
} dpdk_op_priv_t;

typedef struct
{
  u16 *resource_idx;
  struct rte_crypto_op **ops;
  u16 cipher_resource_idx[IPSEC_CRYPTO_N_ALG];
  u16 auth_resource_idx[IPSEC_INTEG_N_ALG];
} crypto_worker_main_t;

typedef struct
{
  char *name;
  enum rte_crypto_sym_xform_type type;
  u32 alg;
  u8 key_len;
  u8 iv_len;
  u8 trunc_size;
  u8 boundary;
  u8 disabled;
  u8 resources;
} crypto_alg_t;

typedef struct
{
  u16 *free_resources;
  u16 *used_resources;
  u8 cipher_support[IPSEC_CRYPTO_N_ALG];
  u8 auth_support[IPSEC_INTEG_N_ALG];
  u8 drv_id;
  u8 numa;
  u16 id;
  const char *name;
  u32 max_qp;
  u32 max_nb_sessions;
  /* Maximum number of sessions supported by device. */
  u32 max_nb_sessions_per_qp;
  /* Maximum number of sessions per queue pair. Default 0 for infinite sessions */
  u64 features;
} crypto_dev_t;

typedef struct
{
  const char *name;
  u16 *devs;
} crypto_drv_t;

typedef struct
{
  u16 thread_idx;
  u8 remove;
  u8 drv_id;
  u8 dev_id;
  u8 numa;
  u16 qp_id;
  u16 inflights[2];
  u16 n_ops;
  u16 __unused;
  struct rte_crypto_op *ops[VLIB_FRAME_SIZE];
  u32 bi[VLIB_FRAME_SIZE];
} crypto_resource_t;

typedef struct
{
  u64 ts;
  struct rte_cryptodev_sym_session *session;
} crypto_session_disposal_t;

typedef struct
{
  struct rte_cryptodev_sym_session *session;
  u64 dev_mask;
} crypto_session_by_drv_t;

typedef struct
{
  /* Required for vec_validate_aligned */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  struct rte_mempool *crypto_op;
  struct rte_mempool *session_h;
  struct rte_mempool *session_drv;
  u64 session_h_failed;
  u64 session_drv_failed;
} crypto_data_t;

typedef struct
{
  crypto_alg_t *cipher_alg;
  crypto_alg_t *auth_alg;
  struct rte_cryptodev_sym_session **sessions;
  u32 sa_index;
  u8 is_aead;
} crypto_session_t;

typedef struct
{
  crypto_worker_main_t *workers_main;
  crypto_session_t *sa_session;
  u32 *sa_session_index;
  crypto_dev_t *dev;
  crypto_resource_t *resource;
  crypto_alg_t *cipher_algs;
  crypto_alg_t *auth_algs;
  crypto_data_t *per_numa_data;
  crypto_drv_t *drv;

  u64 session_timeout;		/* nsec */
  u8 enabled;

  crypto_session_disposal_t *session_disposal;
} dpdk_crypto_main_t;

extern dpdk_crypto_main_t dpdk_crypto_main;

static const u8 pad_data[] =
  { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0 };

void crypto_auto_placement (void);

i32 crypto_make_session (u8 thread_idx, crypto_session_t * cs,
			 ipsec_sa_t * sa, crypto_resource_t * res,
			 crypto_worker_main_t * cwm, u8 is_outbound);


static_always_inline u32
crypto_op_len (void)
{
  const u32 align = 16;
  u32 op_size =
    sizeof (struct rte_crypto_op) + sizeof (struct rte_crypto_sym_op);

  return ((op_size + align - 1) & ~(align - 1)) + sizeof (dpdk_op_priv_t);
}

static_always_inline u32
crypto_op_get_priv_offset (void)
{
  const u32 align = 16;
  u32 offset;

  offset = sizeof (struct rte_crypto_op) + sizeof (struct rte_crypto_sym_op);
  offset = (offset + align - 1) & ~(align - 1);

  return offset;
}

static_always_inline dpdk_op_priv_t *
crypto_op_get_priv (struct rte_crypto_op * op)
{
  return (dpdk_op_priv_t *) (((u8 *) op) + crypto_op_get_priv_offset ());
}

static_always_inline u16
crypto_get_resource (crypto_worker_main_t * cwm, ipsec_sa_t * sa,
		     crypto_session_t * cs)
{
  u16 cipher_res = cwm->cipher_resource_idx[sa->crypto_alg];
  u16 auth_res = cwm->auth_resource_idx[sa->integ_alg];

  if (cipher_res == auth_res)
    return cipher_res;

  if (cs->is_aead)
    return cipher_res;

  return (u16) ~ 0;
}

static_always_inline i32
crypto_alloc_ops (u8 numa, struct rte_crypto_op ** ops, u32 n)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_data_t *data = vec_elt_at_index (dcm->per_numa_data, numa);
  i32 ret;

  ret = rte_mempool_get_bulk (data->crypto_op, (void **) ops, n);
  return ret;
}

static_always_inline void
crypto_free_ops (u8 numa, struct rte_crypto_op **ops, u32 n)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_data_t *data = vec_elt_at_index (dcm->per_numa_data, numa);

  if (!n)
    return;

  rte_mempool_put_bulk (data->crypto_op, (void **) ops, n);
}

static_always_inline void
crypto_enqueue_ops (vlib_main_t * vm, crypto_worker_main_t * cwm, u8 outbound,
		    u32 node_index, u32 error, u8 numa)
{
  dpdk_crypto_main_t *dcm = &dpdk_crypto_main;
  crypto_resource_t *res;
  u16 *res_idx;

  /* *INDENT-OFF* */
  vec_foreach (res_idx, cwm->resource_idx)
    {
      u16 enq;
      res = vec_elt_at_index (dcm->resource, res_idx[0]);

      if (!res->n_ops)
				continue;

      enq = rte_cryptodev_enqueue_burst (res->dev_id, res->qp_id + outbound,
					 res->ops, res->n_ops);
      res->inflights[outbound] += enq;

      if (PREDICT_FALSE (enq < res->n_ops))
			{
			  crypto_free_ops (numa, &res->ops[enq], res->n_ops - enq);
			  vlib_buffer_free (vm, &res->bi[enq], res->n_ops - enq);
        vlib_node_increment_counter (vm, node_index, error, res->n_ops - enq);
      }
      res->n_ops = 0;
    }
  /* *INDENT-ON* */
}

static_always_inline void
crypto_set_icb (dpdk_gcm_cnt_blk * icb, u32 salt, u32 seq, u32 seq_hi)
{
  icb->salt = salt;
  icb->iv[0] = seq;
  icb->iv[1] = seq_hi;
  icb->cnt = clib_host_to_net_u32 (1);
}

static_always_inline void
crypto_op_setup (u8 is_aead, struct rte_mbuf *mb0,
		 struct rte_crypto_op *op, void *session,
		 u32 cipher_off, u32 cipher_len,
		 u32 auth_off, u32 auth_len,
		 u8 * aad, u8 * digest, u64 digest_paddr)
{
  struct rte_crypto_sym_op *sym_op;

  sym_op = (struct rte_crypto_sym_op *) (op + 1);

  sym_op->m_src = mb0;
  sym_op->session = session;

  if (is_aead)
    {
      sym_op->aead.data.offset = cipher_off;
      sym_op->aead.data.length = cipher_len;

      sym_op->aead.aad.data = aad;
      sym_op->aead.aad.phys_addr =
	op->phys_addr + (uintptr_t) aad - (uintptr_t) op;

      sym_op->aead.digest.data = digest;
      sym_op->aead.digest.phys_addr = digest_paddr;
    }
  else
    {
      sym_op->cipher.data.offset = cipher_off;
      sym_op->cipher.data.length = cipher_len;

      sym_op->auth.data.offset = auth_off;
      sym_op->auth.data.length = auth_len;

      sym_op->auth.digest.data = digest;
      sym_op->auth.digest.phys_addr = digest_paddr;
    }
}

static_always_inline crypto_session_t *
crypto_session_from_sa_index (dpdk_crypto_main_t * dcm, u32 sa_index)
{
  u32 index = vec_elt (dcm->sa_session_index, sa_index);

  if (PREDICT_FALSE (index == (u32) ~ 0))
    return NULL;

  return pool_elt_at_index (dcm->sa_session, index);
}


#endif /* __DPDK_IPSEC_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
