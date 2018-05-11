/*
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
#ifndef __ESP_H__
#define __ESP_H__

#include <vnet/ip/ip.h>
#include <vnet/ipsec/ipsec.h>

#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

typedef struct
{
  u32 spi;
  u32 seq;
  u8 data[0];
} esp_header_t;

typedef struct
{
  u8 pad_length;
  u8 next_header;
} esp_footer_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip4_header_t ip4;
  esp_header_t esp;
}) ip4_and_esp_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip4_header_t ip4;
  udp_header_t udp;
  esp_header_t esp;
}) ip4_and_udp_and_esp_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip6_header_t ip6;
  esp_header_t esp;
}) ip6_and_esp_header_t;
/* *INDENT-ON* */

typedef struct
{
  const EVP_CIPHER *type;
  u8 iv_size;
  u8 block_size;
} ipsec_proto_main_crypto_alg_t;

typedef struct
{
  const EVP_MD *md;
  u32 mac_size;
	u32 trunc_size;
} ipsec_proto_main_integ_alg_t;

typedef struct
{
  ipsec_proto_main_crypto_alg_t *ipsec_proto_main_crypto_algs;
  ipsec_proto_main_integ_alg_t *ipsec_proto_main_integ_algs;

	xoshiro256starstar_t *rand_state;

	struct {
		CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
		struct random_data data;		
		i8 buf[32];
	} * rand_data;
	
} ipsec_proto_main_t;


extern ipsec_proto_main_t ipsec_proto_main;

#define ESP_WINDOW_SIZE		(64)
#define ESP_SEQ_MAX 		(4294967295UL)

u8 *format_esp_header (u8 * s, va_list * args);

always_inline int
esp_replay_check (ipsec_sa_t * sa, u32 seq)
{
  u32 diff;

  if (PREDICT_TRUE (seq > sa->last_seq))
    return 0;

  diff = sa->last_seq - seq;

  if (ESP_WINDOW_SIZE > diff)
    return (sa->replay_window & (1ULL << diff)) ? 1 : 0;
  else
    return 1;

  return 0;
}

always_inline int
esp_replay_check_esn (ipsec_sa_t * sa, u32 seq)
{
  u32 tl = sa->last_seq;
  u32 th = sa->last_seq_hi;
  u32 diff = tl - seq;

  if (PREDICT_TRUE (tl >= (ESP_WINDOW_SIZE - 1)))
    {
      if (seq >= (tl - ESP_WINDOW_SIZE + 1))
	{
	  sa->seq_hi = th;
	  if (seq <= tl)
	    return (sa->replay_window & (1ULL << diff)) ? 1 : 0;
	  else
	    return 0;
	}
      else
	{
	  sa->seq_hi = th + 1;
	  return 0;
	}
    }
  else
    {
      if (seq >= (tl - ESP_WINDOW_SIZE + 1))
	{
	  sa->seq_hi = th - 1;
	  return (sa->replay_window & (1ULL << diff)) ? 1 : 0;
	}
      else
	{
	  sa->seq_hi = th;
	  if (seq <= tl)
	    return (sa->replay_window & (1ULL << diff)) ? 1 : 0;
	  else
	    return 0;
	}
    }

  return 0;
}

/* TODO seq increment should be atomic to be accessed by multiple workers */
always_inline void
esp_replay_advance (ipsec_sa_t * sa, u32 seq)
{
  u32 pos;

  if (seq > sa->last_seq)
    {
      pos = seq - sa->last_seq;
      if (pos < ESP_WINDOW_SIZE)
	sa->replay_window = ((sa->replay_window) << pos) | 1;
      else
	sa->replay_window = 1;
      sa->last_seq = seq;
    }
  else
    {
      pos = sa->last_seq - seq;
      sa->replay_window |= (1ULL << pos);
    }
}

always_inline void
esp_replay_advance_esn (ipsec_sa_t * sa, u32 seq)
{
  int wrap = sa->seq_hi - sa->last_seq_hi;
  u32 pos;

  if (wrap == 0 && seq > sa->last_seq)
    {
      pos = seq - sa->last_seq;
      if (pos < ESP_WINDOW_SIZE)
	sa->replay_window = ((sa->replay_window) << pos) | 1;
      else
	sa->replay_window = 1;
      sa->last_seq = seq;
    }
  else if (wrap > 0)
    {
      pos = ~seq + sa->last_seq + 1;
      if (pos < ESP_WINDOW_SIZE)
	sa->replay_window = ((sa->replay_window) << pos) | 1;
      else
	sa->replay_window = 1;
      sa->last_seq = seq;
      sa->last_seq_hi = sa->seq_hi;
    }
  else if (wrap < 0)
    {
      pos = ~seq + sa->last_seq + 1;
      sa->replay_window |= (1ULL << pos);
    }
  else
    {
      pos = sa->last_seq - seq;
      sa->replay_window |= (1ULL << pos);
    }
}

always_inline int
esp_seq_advance (ipsec_sa_t * sa)
{
  if (PREDICT_TRUE (sa->use_esn))
    {
      if (PREDICT_FALSE (sa->seq == ESP_SEQ_MAX))
	{
	  if (PREDICT_FALSE
	      (sa->use_anti_replay && sa->seq_hi == ESP_SEQ_MAX))
	    return 1;
	  sa->seq_hi++;
	}
      sa->seq++;
    }
  else
    {
      if (PREDICT_FALSE (sa->use_anti_replay && sa->seq == ESP_SEQ_MAX))
	return 1;
      sa->seq++;
    }

  return 0;
}

always_inline void
ipsec_proto_init ()
{
  ipsec_proto_main_t *em = &ipsec_proto_main;
  memset (em, 0, sizeof (em[0]));

	vlib_thread_main_t *tm = vlib_get_thread_main ();

  vec_validate (em->rand_state, tm->n_vlib_mains - 1);
  vec_validate (em->rand_data, tm->n_vlib_mains - 1);

	for (int i = 0; i < vec_len (em->rand_state); i++)
	{
		xoshiro256starstar_seed (&em->rand_state[i]);
		initstate_r (0, em->rand_data[i].buf, 32, &em->rand_data[i].data);
	}

  vec_validate (em->ipsec_proto_main_crypto_algs, IPSEC_CRYPTO_N_ALG - 1);

	ipsec_proto_main_crypto_alg_t *c;
	c = &em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_NONE];
  c->type = NULL;
  c->iv_size = 0;
  c->block_size = 4;

	/* CBC */
	c = &em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_128];
  c->type = EVP_aes_128_cbc ();
  c->iv_size = 16;
  c->block_size = 16;

	c = &em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_192];
  c->type = EVP_aes_192_cbc ();
  c->iv_size = 16;
  c->block_size = 16;
    
	c = &em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CBC_256];
	c->type = EVP_aes_256_cbc ();
	c->iv_size = 16;
	c->block_size = 16;

	/* CTR */
	c = &em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CTR_128];
  c->type = EVP_aes_128_ctr ();
  c->iv_size = 8;
  c->block_size = 4;

	c = &em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CTR_192];
  c->type = EVP_aes_192_ctr ();
  c->iv_size = 8;
  c->block_size = 4;
    
	c = &em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_CTR_256];
	c->type = EVP_aes_256_ctr ();
	c->iv_size = 8;
	c->block_size = 4;

	/* GCM */
	c = &em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_GCM_128];
  c->type = EVP_aes_128_gcm ();
  c->iv_size = 8;
  c->block_size = 4;

	c = &em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_GCM_192];
  c->type = EVP_aes_192_gcm ();
  c->iv_size = 8;
  c->block_size = 4;
    
	c = &em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_AES_GCM_256];
	c->type = EVP_aes_256_gcm ();
	c->iv_size = 8;
	c->block_size = 4;

	/* DES 3DES */
	c = &em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_DES_CBC];
	c->type = EVP_des_cbc ();
	c->iv_size = 8;
	c->block_size = 8;

	c = &em->ipsec_proto_main_crypto_algs[IPSEC_CRYPTO_ALG_3DES_CBC];
	c->type = EVP_des_ede3_cbc ();
	c->iv_size = 8;
	c->block_size = 8;

  vec_validate (em->ipsec_proto_main_integ_algs, IPSEC_INTEG_N_ALG - 1);
  ipsec_proto_main_integ_alg_t *i;

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_NONE];
  i->md = NULL;
  i->mac_size = 0;
  i->trunc_size = 0;

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_MD5_96];
  i->md = EVP_md5 ();
  i->mac_size = 12;
  i->trunc_size = 12;

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA1_96];
  i->md = EVP_sha1 ();
  i->mac_size = 12;
  i->trunc_size = 12;

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_256_96];
  i->md = EVP_sha256 ();
  i->mac_size = 32;
  i->trunc_size = 12;

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_256_128];
  i->md = EVP_sha256 ();
  i->mac_size = 32;
  i->trunc_size = 16;

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_384_192];
  i->md = EVP_sha384 ();
  i->mac_size = 48;
  i->trunc_size = 24;

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_SHA_512_256];
  i->md = EVP_sha512 ();
  i->mac_size = 64;
  i->trunc_size = 32;

  i = &em->ipsec_proto_main_integ_algs[IPSEC_INTEG_ALG_CMAC];
  i->md = NULL;
  i->mac_size = 16;
  i->trunc_size = 16;
}

typedef unsigned int (* MAC_FUNC) (ipsec_sa_t *sa, int thread_index, u8 * data, int data_len, u8 * signature);


always_inline unsigned int
hmac_calc (ipsec_sa_t *sa, int thread_index, u8 * data, int data_len, u8 * signature)
{
  ipsec_proto_main_t *em = &ipsec_proto_main;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  HMAC_CTX *ctx = sa->context[thread_index].hmac_ctx;
#else
  HMAC_CTX *ctx = &(sa->context[thread_index].hmac_ctx);
#endif

  unsigned int len;

  ASSERT (sa->integ_alg < IPSEC_INTEG_N_ALG && sa->integ_alg > IPSEC_INTEG_ALG_NONE && sa->integ_alg != IPSEC_INTEG_ALG_CMAC );

	HMAC_Init_ex (ctx, NULL, 0, NULL, NULL);

  HMAC_Update (ctx, data, data_len);

  if (PREDICT_TRUE (sa->use_esn))
    HMAC_Update (ctx, (u8 *) & sa->seq_hi, sizeof (sa->seq_hi));
	
  HMAC_Final (ctx, signature, &len);

	//fformat (stdout, "HASH: %U \n", format_hexdump, signature, len);

  return em->ipsec_proto_main_integ_algs[sa->integ_alg].trunc_size;
}

always_inline unsigned int
cmac_calc (ipsec_sa_t *sa, int thread_index, u8 * data, int data_len, u8 * signature)
{
  ipsec_proto_main_t *em = &ipsec_proto_main;

  CMAC_CTX *ctx = sa->context[thread_index].cmac_ctx;

  size_t len;

  ASSERT (sa->integ_alg == IPSEC_INTEG_ALG_CMAC);

	CMAC_Init (ctx, NULL, 0, NULL, NULL);
	//CMAC_Init(ctx, "1234567890", 16, EVP_aes_128_cbc(), NULL);

  CMAC_Update (ctx, data, data_len);

  if (PREDICT_TRUE (sa->use_esn))
    CMAC_Update (ctx, (u8 *) & sa->seq_hi, sizeof (sa->seq_hi));
	
  CMAC_Final (ctx, signature, &len);

	//fformat (stdout, "HASH: %U \n", format_hexdump, signature, len);

  return em->ipsec_proto_main_integ_algs[sa->integ_alg].trunc_size;
}

#endif /* __ESP_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
