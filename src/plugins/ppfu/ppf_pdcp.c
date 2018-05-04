/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */
#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/adj/adj_mcast.h>
#include <vnet/dpo/dpo.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <ppfu/ppfu.h>
#include <ppfu/snow3g.h>


ppf_pdcp_main_t ppf_pdcp_main; 

void 
ppf_pdcp_encap_header_5bsn (u8 * buf, u8 dc, u32 sn)
{
  *buf = (u8)(sn & 0x1f);
}

void 
ppf_pdcp_decap_header_5bsn (u8 * buf, u8 * dc, u32 * sn)
{
  *sn = (u32)(0x1f & (*buf));
  *dc = 1;
}

void 
ppf_pdcp_encap_header_7bsn (u8 * buf, u8 dc, u32 sn)
{
  *buf = (u8)((sn & 0x7f) | (dc << 7));
}

void 
ppf_pdcp_decap_header_7bsn (u8 * buf, u8 * dc, u32 * sn)
{
  *sn = (u32)(0x7f & (*buf));
  *dc = (*buf) >> 7;
}

void 
ppf_pdcp_encap_header_12bsn (u8 * buf, u8 dc, u32 sn)
{
  *buf = (dc << 7) | ((sn >> 8) & 0x0f);
  *(buf + 1) = (u8)(sn & 0xff);
}

void 
ppf_pdcp_decap_header_12bsn (u8 * buf, u8 * dc, u32 * sn)
{
  *dc = (*buf) >> 7;
  *sn = (((*buf) << 8) | ((*(buf + 1)) & 0xff)) & 0x0fff;
}

void 
ppf_pdcp_encap_header_15bsn (u8 * buf, u8 dc, u32 sn)
{
  *buf = (dc << 7) | ((sn >> 8) & 0x7f);
  *(buf + 1) = (u8)(sn & 0xff);
}

void 
ppf_pdcp_decap_header_15bsn (u8 * buf, u8 * dc, u32 * sn)
{
  *dc = (*buf) >> 7;
  *sn = (((*buf) << 8) | ((*(buf + 1)) & 0xff)) & 0x7fff;
}

void 
ppf_pdcp_encap_header_18bsn (u8 * buf, u8 dc, u32 sn)
{
  *buf = (dc << 7) | ((sn >> 16) & 0x03);
  *(buf + 1) = (u8)((sn >> 8) & 0xff);
  *(buf + 2) = (u8)(sn & 0xff);
}

void 
ppf_pdcp_decap_header_18bsn (u8 * buf, u8 * dc, u32 * sn)
{
  *dc = (*buf) >> 7;
  *sn = (((*buf) << 16) | ((*(buf + 1)) << 8) | (*(buf + 2))) & 0x3ffff;
}

always_inline void
ppf_pdcp_gen_iv (u8 alg, u32 count, u8 bearer, u8 dir, u8 * iv)
{
	memset (iv, 0, MAX_PDCP_KEY_LEN);
	
	switch (alg) {
		case PDCP_SNOW3G_CIPHERING:
			{
				iv[0]  = ((count >> 24) & 0xFF);
				iv[1]  = ((count >> 16) & 0xFF);
				iv[2]  = ((count >> 8)  & 0xFF);
				iv[3]  = ((count)       & 0xFF);
				iv[8]  = ((count >> 24) & 0xFF);
				iv[9]  = ((count >> 16) & 0xFF);
				iv[10] = ((count >> 8)  & 0xFF);
				iv[11] = ((count)       & 0xFF);
				iv[4]  = ((((bearer & 0x1F) << 1) | (dir & 0x1)) << 2);
				iv[12] = ((((bearer & 0x1F) << 1) | (dir & 0x1)) << 2);
			}
			break;

		case PDCP_AES_CIPHERING:
			{
				iv[0] = ((count >> 24) & 0xFF);
				iv[1] = ((count >> 16) & 0xFF);
				iv[2] = ((count >> 8)  & 0xFF);
				iv[3] = ((count)       & 0xFF);
				iv[4] = ((((bearer & 0x1F) << 1) | (dir & 0x1)) << 2);
			}
			break;

		case PDCP_SNOW3G_INTEGRITY:
			{
				iv[0]  = ((count>>24) & 0xFF);
				iv[1]  = ((count>>16) & 0xFF);
				iv[2]  = ((count>>8)  & 0xFF);
				iv[3]  = ((count)     & 0xFF);
				iv[4]  = (bearer & 0x1F) << 3;

				iv[8]  = ((count >> 24) & 0xFF) ^ (dir << 7);
				iv[9]  = ((count >> 16) & 0xFF);
				iv[10] = ((count >> 8)  & 0xFF);
				iv[11] = ((count >> 0)  & 0xFF);
				iv[12] = (bearer & 0x1F) << 3;
				iv[14] = (iv[14] ^ (dir << 7));
			}
			break;

		case PDCP_AES_INTEGRITY:
			{
				iv[0] = ((count >> 24) & 0xFF);
				iv[1] = ((count >> 16) & 0xFF);
				iv[2] = ((count >> 8)  & 0xFF);
				iv[3] = ((count >> 0)  & 0xFF);
				iv[4] = ((((bearer & 0x1F) << 1) | (dir & 0x1)) << 2);
				iv[5] = 0;
				iv[6] = 0;
				iv[7] = 0;
			}
			break;

		default:
			break;
	}
}

u32
ppf_pdcp_nop (u8 * in, u8 * out, u32 size, void * security_parameters)
{
	return 0;
}

bool
ppf_pdcp_eia0 (vlib_main_t * vm,vlib_buffer_t * b0, void * security_parameters)
{

	memset (vlib_buffer_put_uninit(b0, EIA_MAC_LEN), 0x00, EIA_MAC_LEN);
	return true;
}

bool
ppf_pdcp_eia1 (vlib_main_t * vm,vlib_buffer_t * b0, void * security_parameters)
{

	u8 mact[MAX_PDCP_KEY_LEN] = {0};
	u32 len;
	u8 * buf0;
	bool ret = true;

	ppf_pdcp_security_param_t * sec_para = (ppf_pdcp_security_param_t *)security_parameters;
	CLIB_UNUSED(u8 iv[16]) = {0};
	ppf_pdcp_session_t * pdcp_sess = sec_para->pdcp_sess;
	snow3g_ctx_t *ctx = &(pdcp_sess->snow3g_ctx);
	
	buf0 = vlib_buffer_get_current (b0);
	len = vlib_buffer_length_in_chain(vm, b0);


	if (PPF_PDCP_DIR_ENC == sec_para->dir) {
	    //TODO : use crypto key for intergity, align with wrong salt implemnt, need correct after salt FIX the bug
	    //append 4 octs at end of data for caculating MAC 
        snow3g_protect(ctx,sec_para->pdcp_sess->crypto_key,sec_para->count,sec_para->bearer,buf0,len,vlib_buffer_put_uninit(b0, EIA_MAC_LEN));
	    //snow3g_protect(ctx,sec_para->pdcp_sess->integrity_key,sec_para->count,sec_para->bearer,buf0,len,vlib_buffer_put_uninit(b0, EIA_MAC_LEN));
	} else {
		len -= EIA_MAC_LEN;	
	    //TODO : use crypto key for intergity, align with wrong salt implemnt, need correct after salt FIX the bug		
        snow3g_validate(ctx,sec_para->pdcp_sess->crypto_key,sec_para->count,sec_para->bearer,buf0,len,mact);
		//snow3g_validate(ctx,sec_para->pdcp_sess->integrity_key,sec_para->count,sec_para->bearer,buf0,len,mact);
		ret = (buf0[len+0]== mact[0] && buf0[len+1]== mact[1] && buf0[len+2]== mact[2] && buf0[len+3]== mact[3]);
		//trim 4 octs of MAC 
		b0->current_length -= EIA_MAC_LEN;
	}

	return ret;
}


u32
ppf_pdcp_eea1 (u8 * in, u8 * out, u32 size, void * security_parameters)
{
	ppf_pdcp_security_param_t * sec_para = (ppf_pdcp_security_param_t *)security_parameters;
	CLIB_UNUSED(u8 iv[16]) = {0};
	ppf_pdcp_session_t * pdcp_sess = sec_para->pdcp_sess;
	
	snow3g_ctx_t *ctx = &(pdcp_sess->snow3g_ctx);

	if (PPF_PDCP_DIR_ENC == sec_para->dir) {
		snow3g_encrypt(ctx,sec_para->pdcp_sess->crypto_key,sec_para->count,sec_para->bearer,in,out,size);
	} else {
		snow3g_decrypt(ctx,sec_para->pdcp_sess->crypto_key,sec_para->count,sec_para->bearer,in,out,size);
	}

	return 0;
}

bool
ppf_pdcp_eia2 (vlib_main_t * vm,vlib_buffer_t * b0, void * security_parameters)
{
	u8 mact[MAX_PDCP_KEY_LEN] = {0};
	u32 len;
        size_t mactlen;
	u8 * buf0;
	bool ret = true;

	ppf_pdcp_security_param_t * sec_para = (ppf_pdcp_security_param_t *)security_parameters;
	ppf_pdcp_session_t * pdcp_sess = sec_para->pdcp_sess;

        CMAC_CTX *ctx = (PPF_PDCP_DIR_ENC == sec_para->dir) ? pdcp_sess->down_sa.integrity_ctx : pdcp_sess->up_sa.integrity_ctx;
	//prepare IV
	vlib_buffer_advance (b0, -(word)EIA2_IV_LEN);
	// length include IV
    
	buf0 = vlib_buffer_get_current (b0);
	len = vlib_buffer_length_in_chain(vm, b0);

	//set IV
        buf0[0] = ((sec_para->count >> 24) & 0xFF);
	buf0[1] = ((sec_para->count >> 16) & 0xFF);
	buf0[2] = ((sec_para->count >> 8)  & 0xFF);
	buf0[3] = ((sec_para->count >> 0)  & 0xFF);
	buf0[4] = ((((sec_para->bearer & 0x1F) << 1) | (sec_para->dir & 0x1)) << 2);
	buf0[5] = 0;
	buf0[6] = 0;
	buf0[7] = 0;
	//just restart context
	CMAC_Init(ctx, NULL, NULL, NULL, NULL);

	// 0 for uplink(DEC) and 1 for downlink(ENC)
	if (PPF_PDCP_DIR_ENC == sec_para->dir) {

		CMAC_Update(ctx, buf0, len);
		CMAC_Final(ctx, mact, &mactlen);
		//put mac to end of data
		clib_memcpy (vlib_buffer_put_uninit(b0, EIA_MAC_LEN),mact,EIA_MAC_LEN);
	} else {
		//calculate mac exlucde 4 octs MAC-I
		len -= EIA_MAC_LEN;
		CMAC_Update(ctx, buf0, len);
		CMAC_Final(ctx, mact, &mactlen);
		//verify mac
		ret = (buf0[len+0]== mact[0] && buf0[len+1]== mact[1] && buf0[len+2]== mact[2] && buf0[len+3]== mact[3]);
		//trim 4 octs of MAC 
		b0->current_length -= EIA_MAC_LEN;
	}

	//remove IV prepend
	vlib_buffer_advance (b0, (word)EIA2_IV_LEN);


	return ret;
}

u32
ppf_pdcp_eea2 (u8 * in, u8 * out, u32 size, void * security_parameters)
{
	u8 iv[MAX_PDCP_KEY_LEN] = {0};
	int out_len;

	ppf_pdcp_security_param_t * sec_para = (ppf_pdcp_security_param_t *)security_parameters;
	ppf_pdcp_session_t * pdcp_sess = sec_para->pdcp_sess;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        EVP_CIPHER_CTX *ctx = (PPF_PDCP_DIR_ENC == sec_para->dir) ? pdcp_sess->down_sa.cypher_ctx: pdcp_sess->up_sa.cypher_ctx;
#else
        EVP_CIPHER_CTX *ctx = (PPF_PDCP_DIR_ENC == sec_para->dir) ? &(pdcp_sess->down_sa.cypher_ctx): &(pdcp_sess->up_sa.cypher_ctx);
#endif

	ppf_pdcp_gen_iv (PDCP_AES_CIPHERING,
				sec_para->count, sec_para->bearer, sec_para->dir, iv);
	//update iv
	EVP_CipherInit_ex (ctx, NULL, NULL, NULL, iv, -1);
	EVP_CipherUpdate (ctx, out, &out_len, in, size);
	EVP_CipherFinal_ex (ctx, out + out_len, &out_len);
	
	return 0;
}

bool
ppf_pdcp_eia3 (vlib_main_t * vm,vlib_buffer_t * b0, void * security_parameters)
{
	ppf_pdcp_security_param_t * sec_para = (ppf_pdcp_security_param_t *)security_parameters;
	CLIB_UNUSED(u8 iv[16]) = {0};

	ppf_pdcp_gen_iv (PDCP_ZUC_INTEGRITY,
				sec_para->count, sec_para->bearer, sec_para->dir, iv);

	// TODO:
	
	return 0;
}

u32
ppf_pdcp_eea3 (u8 * in, u8 * out, u32 size, void * security_parameters)
{
	ppf_pdcp_security_param_t * sec_para = (ppf_pdcp_security_param_t *)security_parameters;
	CLIB_UNUSED(u8 iv[16]) = {0};

	ppf_pdcp_gen_iv (PDCP_ZUC_CIPHERING,
				sec_para->count, sec_para->bearer, sec_para->dir, iv);

	// TODO:

	return 0;
}

u32
ppf_pdcp_create_session (u8 sn_length, u32 rx_count, u32 tx_count, u32 in_flight_limit)
{
  ppf_pdcp_main_t *ppm = &ppf_pdcp_main;
  ppf_pdcp_session_t *pdcp_sess = NULL;
  u32 session_id = ~0;
  u32 max_sn = ~0;

  pool_get (ppm->sessions, pdcp_sess);
  memset (pdcp_sess, 0, sizeof (*pdcp_sess));

  pdcp_sess->sn_length = sn_length;
  pdcp_sess->tx_next_sn = PPF_PDCP_SN (tx_count, sn_length);
  pdcp_sess->tx_hfn = PPF_PDCP_HFN (tx_count, sn_length);
  pdcp_sess->rx_next_expected_sn = PPF_PDCP_SN (rx_count, sn_length);
  pdcp_sess->rx_last_forwarded_sn = PPF_PDCP_SN_DEC (pdcp_sess->rx_next_expected_sn, sn_length - 1) & max_sn;
  pdcp_sess->rx_hfn = PPF_PDCP_HFN (rx_count, sn_length);
  pdcp_sess->rx_hfn = PPF_PDCP_COUNT_HFN_DEC (rx_count, sn_length);

  if (in_flight_limit == max_sn) // no value configured by upper layers
    pdcp_sess->in_flight_limit = 0x1 << (sn_length - 1); //use default value: SN-range/2 - 1
  else if (in_flight_limit != 0)
    pdcp_sess->in_flight_limit = in_flight_limit;
  else //in_flight_limit == 0
    pdcp_sess->in_flight_limit = 0x1FFFFFFFF; //0 means no in-flight limit, set limit to 2^32 + 1

  pdcp_sess->protect = &ppf_pdcp_eia0;
  pdcp_sess->validate = &ppf_pdcp_eia0;
  pdcp_sess->encrypt = &ppf_pdcp_nop;
  pdcp_sess->decrypt = &ppf_pdcp_nop;
  pdcp_sess->mac_length = 0;

  switch (pdcp_sess->sn_length) {
    case 5:
      pdcp_sess->header_length = 1;
      pdcp_sess->encap_header = &ppf_pdcp_encap_header_5bsn;
      pdcp_sess->decap_header = &ppf_pdcp_decap_header_5bsn;
      break;
    case 7:
      pdcp_sess->header_length = 1;
      pdcp_sess->encap_header = &ppf_pdcp_encap_header_7bsn;
      pdcp_sess->decap_header = &ppf_pdcp_decap_header_7bsn;
      break;
    case 12:
      pdcp_sess->header_length = 2;
      pdcp_sess->encap_header = &ppf_pdcp_encap_header_12bsn;
      pdcp_sess->decap_header = &ppf_pdcp_decap_header_12bsn;
      break;
    case 15:
      pdcp_sess->header_length = 2;
      pdcp_sess->encap_header = &ppf_pdcp_encap_header_15bsn;
      pdcp_sess->decap_header = &ppf_pdcp_decap_header_15bsn;
      break;
    case 18:
      pdcp_sess->header_length = 3;
      pdcp_sess->encap_header = &ppf_pdcp_encap_header_18bsn;
      pdcp_sess->decap_header = &ppf_pdcp_decap_header_18bsn;
      break;

    case 255: /* Only test use, bypass pdcp */
      pdcp_sess->header_length = 0;
      break;
      
    default:
      clib_warning("ERROR: Unknown sequence number length %u.\n",pdcp_sess->sn_length);
      pool_put (ppm->sessions, pdcp_sess);
      return session_id;
  }

  /* Initialize anti-replay & reorder window */
  if (255 != sn_length) {
  	pdcp_sess->replay_window = PDCP_REPLAY_WINDOW_SIZE (sn_length);
    clib_bitmap_alloc (pdcp_sess->rx_replay_bitmap, pdcp_sess->replay_window << 1);
	clib_bitmap_zero (pdcp_sess->rx_replay_bitmap);
	
    vec_validate_init_empty (pdcp_sess->rx_reorder_buffers, clib_min (ppm->rx_max_reorder_window, pdcp_sess->replay_window) - 1, INVALID_BUFFER_INDEX);
  }
  
  session_id = (u32)(pdcp_sess - ppm->sessions);
  return session_id;
}

u32 
ppf_pdcp_session_update_as_security (ppf_pdcp_session_t * pdcp_sess, ppf_pdcp_config_t * config)
{
  if (config->flags & INTEGRITY_KEY_VALID)
    clib_memcpy (pdcp_sess->integrity_key, config->integrity_key, MAX_PDCP_KEY_LEN);
  
  if (config->flags & CRYPTO_KEY_VALID)
    clib_memcpy (pdcp_sess->crypto_key, config->crypto_key, MAX_PDCP_KEY_LEN);
  
  if (config->flags & INTEGRITY_ALG_VALID)
  {
    switch(config->integrity_algorithm)
    {
      case PDCP_EIA_NONE:
      	pdcp_sess->protect = &ppf_pdcp_eia0;
        pdcp_sess->validate = &ppf_pdcp_eia0;
        pdcp_sess->mac_length = 0;
        break;
	
      case PDCP_EIA0:
        pdcp_sess->security_algorithms |= PDCP_NULL_INTEGRITY;
      	pdcp_sess->protect = &ppf_pdcp_eia0;
        pdcp_sess->validate = &ppf_pdcp_eia0;
        pdcp_sess->mac_length = 4;
        break;
	
      case PDCP_EIA1:
        pdcp_sess->security_algorithms |= PDCP_SNOW3G_INTEGRITY;
      	pdcp_sess->protect = &ppf_pdcp_eia1;
        pdcp_sess->validate = &ppf_pdcp_eia1;
        pdcp_sess->mac_length = 4;
        break;

      case PDCP_EIA2:
        pdcp_sess->security_algorithms |= PDCP_AES_INTEGRITY;
      	pdcp_sess->protect = &ppf_pdcp_eia2;
        pdcp_sess->validate = &ppf_pdcp_eia2;
        pdcp_sess->mac_length = 4;
        pdcp_sess->up_sa.integrity_ctx = CMAC_CTX_new ();
        pdcp_sess->down_sa.integrity_ctx = CMAC_CTX_new ();
        CMAC_Init(pdcp_sess->up_sa.integrity_ctx, pdcp_sess->crypto_key, 16, EVP_aes_128_cbc(), NULL);
        CMAC_Init(pdcp_sess->down_sa.integrity_ctx, pdcp_sess->crypto_key, 16, EVP_aes_128_cbc(), NULL);
        break;

      case PDCP_EIA3:
        pdcp_sess->security_algorithms |= PDCP_ZUC_INTEGRITY;
      	pdcp_sess->protect = &ppf_pdcp_eia3;
        pdcp_sess->validate = &ppf_pdcp_eia3;
        pdcp_sess->mac_length = 4;
        break;

      default:
        clib_warning ("ERROR: Unknown integrity algorithm %u.\n", config->integrity_algorithm);
        return -1;
    }
  }
  
  if (config->flags & CRYPTO_ALG_VALID)
  {
    switch (config->crypto_algorithm)
    {
      case PDCP_EEA0:
        pdcp_sess->encrypt = &ppf_pdcp_nop;
        pdcp_sess->decrypt = &ppf_pdcp_nop;
      	pdcp_sess->security_algorithms |= PDCP_NULL_CIPHERING;
        break;
	
      case PDCP_EEA1:
        pdcp_sess->encrypt = &ppf_pdcp_eea1;
        pdcp_sess->decrypt = &ppf_pdcp_eea1;
        pdcp_sess->security_algorithms |= PDCP_SNOW3G_CIPHERING;
        break;

      case PDCP_EEA2:
        pdcp_sess->encrypt = &ppf_pdcp_eea2;
        pdcp_sess->decrypt = &ppf_pdcp_eea2;
        pdcp_sess->security_algorithms |= PDCP_AES_CIPHERING;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        pdcp_sess->up_sa.cypher_ctx= EVP_CIPHER_CTX_new ();	
        pdcp_sess->down_sa.cypher_ctx= EVP_CIPHER_CTX_new ();
        EVP_CipherInit_ex (pdcp_sess->up_sa.cypher_ctx, EVP_aes_128_ctr(), NULL, pdcp_sess->crypto_key, NULL, 0);
        EVP_CipherInit_ex (pdcp_sess->down_sa.cypher_ctx, EVP_aes_128_ctr(), NULL, pdcp_sess->crypto_key, NULL, 1);

#else
        EVP_CIPHER_CTX_init (&(pdcp_sess->up_sa.cypher_ctx));
        EVP_CIPHER_CTX_init (&(pdcp_sess->down_sa.cypher_ctx));
        EVP_CipherInit_ex (&(pdcp_sess->up_sa.cypher_ctx), EVP_aes_128_ctr(), NULL, pdcp_sess->crypto_key, NULL, 0);
        EVP_CipherInit_ex (&(pdcp_sess->down_sa.cypher_ctx), EVP_aes_128_ctr(), NULL, pdcp_sess->crypto_key, NULL, 1);
#endif

        break;

      case PDCP_EEA3:
        pdcp_sess->encrypt = &ppf_pdcp_eea3;
        pdcp_sess->decrypt = &ppf_pdcp_eea3;
      	pdcp_sess->security_algorithms |= PDCP_ZUC_CIPHERING;
        break;

      default:
        clib_warning ("ERROR: Unknown crypto algorithm %u.\n", config->crypto_algorithm);
        return -1;
    }
  }
  
  return 0;
}

u32
ppf_pdcp_clear_session (ppf_pdcp_session_t * pdcp_sess)
{
  if (pdcp_sess) {
    uword i;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        EVP_CIPHER_CTX_free (pdcp_sess->up_sa.cypher_ctx);
        EVP_CIPHER_CTX_free (pdcp_sess->down_sa.cypher_ctx);
#else
	EVP_CIPHER_CTX_cleanup (&(pdcp_sess->up_sa.cypher_ctx));
	EVP_CIPHER_CTX_cleanup (&(pdcp_sess->down_sa.cypher_ctx));

#endif
	CMAC_CTX_free(pdcp_sess->up_sa.integrity_ctx);
	CMAC_CTX_free(pdcp_sess->down_sa.integrity_ctx);
  	clib_bitmap_free (pdcp_sess->rx_replay_bitmap);

    vec_foreach_index(i, pdcp_sess->rx_reorder_buffers) {
      if (VEC_ELT_NE (pdcp_sess->rx_reorder_buffers, i, INVALID_BUFFER_INDEX)) {
        vlib_buffer_free_one (&vlib_global_main, vec_elt (pdcp_sess->rx_reorder_buffers, i));
      }
    }
  	vec_free (pdcp_sess->rx_reorder_buffers);
    pool_put (ppf_pdcp_main.sessions, pdcp_sess);
  }

  return 0;
}

#define foreach_pdcp_crypto_alg   \
  _(0, EEA0, "none")              \
  _(1, EEA1, "snow-3g")           \
  _(2, EEA2, "aes-ctr-128")       \
  _(3, EEA3, "zuc")

#define foreach_pdcp_integ_alg    \
  _(0, EIA_NONE, "none") 	      \
  _(1, EIA0, "null")              \
  _(2, EIA1, "snow-3g")           \
  _(3, EIA2, "aes-cmac-128")      \
  _(4, EIA3, "zuc")

#define foreach_pdcp_security_alg        \
  _(0, NONE_SECURITY, "non-configured")  \
  _(0x01, NULL_CIPHERING, "null")        \
  _(0x02, SNOW3G_CIPHERING, "snow-3g")   \
  _(0x04, AES_CIPHERING, "aes-ctr-128")  \
  _(0x08, ZUC_CIPHERING, "zuc")          \
  _(0x10, NULL_INTEGRITY, "null")		 \
  _(0x20, SNOW3G_INTEGRITY, "snow-3g") 	 \
  _(0x40, AES_INTEGRITY, "aes-cmac-128") \
  _(0x80, ZUC_INTEGRITY, "zuc")


u8 *
format_pdcp_crypto_alg (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  u8 *t = 0;

  switch (i)
    {
#define _(v,f,str) case PDCP_##f: t = (u8 *) str; break;
      foreach_pdcp_crypto_alg
#undef _
    default:
      s = format (s, "unknown");
    }
  s = format (s, "%s", t);
  return s;
}

uword
unformat_pdcp_crypto_alg (unformat_input_t * input, va_list * args)
{
  u32 *r = va_arg (*args, u32 *);

  if (0);
#define _(v,f,s) else if (unformat (input, s)) *r = PDCP_##f;
  foreach_pdcp_crypto_alg
#undef _
    else
    return 0;
  return 1;
}

u8 *
format_pdcp_integ_alg (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  u8 *t = 0;

  switch (i)
    {
#define _(v,f,str) case PDCP_##f: t = (u8 *) str; break;
      foreach_pdcp_integ_alg
#undef _
    default:
      s = format (s, "unknown");
    }
  s = format (s, "%s", t);
  return s;
}

uword
unformat_pdcp_integ_alg (unformat_input_t * input, va_list * args)
{
  u32 *r = va_arg (*args, u32 *);

  if (0);
#define _(v,f,s) else if (unformat (input, s)) *r = PDCP_##f;
  foreach_pdcp_integ_alg
#undef _
    else
    return 0;
  return 1;
}

u8 *
format_pdcp_security_alg (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  u8 *t = 0;

  switch (i)
    {
#define _(v,f,str) case PDCP_##f: t = (u8 *) str; break;
      foreach_pdcp_security_alg
#undef _
    default:
      s = format (s, "unknown");
    }
  s = format (s, "%s", t);
  return s;
}

u8 *
format_vec32_adv (u8 * s, va_list * va)
{
  u32 *v = va_arg (*va, u32 *);
  char *fmt = va_arg (*va, char *);
  u32 num_per_row = va_arg (*va, u32);
  uword i;
  for (i = 0; i < vec_len (v); i++)
    {
      if (i > 0) {
	    s = format (s, ", ");
		if ((i % num_per_row) == 0)
		  s = format (s, "\n");
      }

      s = format (s, fmt, v[i]);

    }
  return s;
}

u8 *
format_ppf_pdcp_session (u8 * s, va_list * va)
{
  ppf_pdcp_session_t * pdcp_session = va_arg (*va, ppf_pdcp_session_t *);
  int verbose = va_arg (*va, int);

  s = format (s, "sn-length %d, header-length %d, mac-length %d, in-flight-limit %lx\n", 
              pdcp_session->sn_length, 
              pdcp_session->header_length,
              pdcp_session->mac_length,
              pdcp_session->in_flight_limit);

  s = format (s, "tx-hfn %u, tx-next %u\n", 
              pdcp_session->tx_hfn, 
              pdcp_session->tx_next_sn);

  s = format (s, "rx-hfn %u, rx-next-expected %u, rx-last-forwarded %u\n", 
              pdcp_session->rx_hfn, 
              pdcp_session->rx_next_expected_sn, 
              pdcp_session->rx_last_forwarded_sn);

  if (verbose > 1) {
    s = format (s, "replay-window %u, rx-replay-bitmap (%u bits)\n %U\n", 
                pdcp_session->replay_window, 
                clib_bitmap_bytes(pdcp_session->rx_replay_bitmap) * BITS(u8),
                format_bitmap_hex, pdcp_session->rx_replay_bitmap);
    s = format (s, "reorder-window %u, details\n%U\n", vec_len (pdcp_session->rx_reorder_buffers), 
                format_vec32_adv, pdcp_session->rx_reorder_buffers, "%d", 8);
  }

  s = format (s, "integrity-alg %U, intergity-key %U\n", 
              format_pdcp_security_alg, pdcp_session->security_algorithms & 0xf0, 
              format_hex_bytes, pdcp_session->integrity_key, MAX_PDCP_KEY_LEN);

  s = format (s, "crypto-alg %U, crypto-key %U\n", 
              format_pdcp_security_alg, pdcp_session->security_algorithms & 0x0f, 
              format_hex_bytes, pdcp_session->crypto_key, MAX_PDCP_KEY_LEN);

  return s;
}

static clib_error_t *
ppf_pdcp_add_del_session_command_fn (vlib_main_t * vm,
										unformat_input_t * input,
										vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_add = 1;
  u32 call_id = ~0;
  u32 sn_length = ~0, init_ul_count = 1, init_dl_count = 1, in_flight_limit = 0;
  u32 alg;
  u8 *key = 0;
  ppf_pdcp_config_t pdcp_cfg;
  clib_error_t *error = NULL;
  ppf_callline_t * callline;
  u32 sess_id = ~0;

  memset (&pdcp_cfg, 0, sizeof (pdcp_cfg));
  
  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
      {
        is_add = 0;
      }
      else if (unformat (line_input, "call-id %d", &call_id))
      ;
      else if (unformat (line_input, "sn-length %d", &sn_length))
      ;
      else if (unformat (line_input, "init-ul-count %d", &init_ul_count))
      ;
      else if (unformat (line_input, "init-dl-count %d", &init_dl_count))
      ;
      else if (unformat (line_input, "in-flight-limit %d", &in_flight_limit))
      ;
      else if (unformat (line_input, "crypto-alg %U", unformat_pdcp_crypto_alg, &alg)) {
        pdcp_cfg.flags |= CRYPTO_ALG_VALID;
		pdcp_cfg.crypto_algorithm = alg;
      }
      else if (unformat (line_input, "integ-alg %U", unformat_pdcp_integ_alg, &alg)) {
	    pdcp_cfg.flags |= INTEGRITY_ALG_VALID;
		pdcp_cfg.integrity_algorithm = alg;
      }
      else if (unformat (line_input, "CK %U", unformat_hex_string, &key)) {
	  	if (vec_len (key) >= MAX_PDCP_KEY_LEN) {
          pdcp_cfg.flags |= CRYPTO_KEY_VALID;
          clib_memcpy (pdcp_cfg.crypto_key, key, MAX_PDCP_KEY_LEN);
	  	}
      }
      else if (unformat (line_input, "IK %U", unformat_hex_string, &key)) {
	  	if (vec_len (key) >= MAX_PDCP_KEY_LEN) {
          pdcp_cfg.flags |= INTEGRITY_KEY_VALID;
          clib_memcpy (pdcp_cfg.integrity_key, key, MAX_PDCP_KEY_LEN);
	  	}
      }
      else
      {
        error = clib_error_return (0, "parse error: '%U'",
        format_unformat_error, line_input);
        goto done;
      }
    }
    
  if (call_id == ~0) 
   {
      error = clib_error_return (0, "call-id not specified");
      goto done;
   }

  if (is_add == 1 && sn_length == ~0) 
   {
      error = clib_error_return (0, "sn-length not specified");
      goto done;
   }

  if (call_id >= ppf_main.max_capacity)
  {
	error = clib_error_return (0, "error call-id %u, should be in range[0, %u)", call_id, ppf_main.max_capacity);
	goto done;
  }
  
  callline = &(ppf_main.ppf_calline_table[call_id]);
    
  if (is_add == 1) {
  	sess_id = ppf_pdcp_create_session (sn_length, init_ul_count, init_dl_count, in_flight_limit);
	if (~0 != sess_id) {
		ppf_pdcp_session_update_as_security (pool_elt_at_index(ppf_pdcp_main.sessions, sess_id), &pdcp_cfg);
	} else {
		error = clib_error_return (0, "create session fail, error sn-length %u", sn_length);
		goto done;
	}

	callline->pdcp.session_id = sess_id;
    vlib_cli_output (vm, "[PDCP session created], details: %U",
		format_ppf_pdcp_session, pool_elt_at_index(ppf_pdcp_main.sessions, sess_id), 2);
  }
  else { /* del */
  	if (~0 != callline->pdcp.session_id) {
      ppf_pdcp_clear_session (pool_elt_at_index (ppf_pdcp_main.sessions, callline->pdcp.session_id));
      callline->pdcp.session_id = ~0;
  	} else {
	  error = clib_error_return (0, "delete session fail, error call-id %u", call_id);
	  goto done;
  	}
  }

done:
  unformat_free (line_input);

  return error;
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (create_ppf_pdcp_session_command, static) = {
  .path = "create ppf_pdcp session",
  .short_help =	  
  "create ppf_pdcp session call-id <nn> sn-length <nn> "
  " [init-ul-count <nn>] [init-dl-count <nn>] [in-flight-limit <nn>] "  
  " [crypto-alg <alg>|integ-alg <alg>] [CK <key>|IK <key>] [del]",
  .function = ppf_pdcp_add_del_session_command_fn,
};
/* *INDENT-ON* */


static clib_error_t *
ppf_pdcp_set_reorder_command_fn (vlib_main_t * vm,
					unformat_input_t * input,
					vlib_cli_command_t * cmd)
{
  clib_error_t *error = NULL;
  u32 enable = 0;
  u32 window = 0;
  
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable"))
	    enable = 1;
      else if (unformat (input, "disable"))
	    enable = 0;
      else if (unformat (input, "window %d", &window))
	    ;
      else
      {
        error = clib_error_return (0, "parse error: '%U'", format_unformat_error, input);
        return error;
      }
    }

  ppf_pdcp_main.rx_reorder = enable;
  if (window) {
    if (window > PDCP_MAX_REORDER_WINDOW_SIZE)
      window = PDCP_MAX_REORDER_WINDOW_SIZE;
    ppf_pdcp_main.rx_max_reorder_window = (1 << max_log2 (window));
  }
  vlib_cli_output (vm, "PPF PDCP reorder is set to %s, window %d\n", (ppf_pdcp_main.rx_reorder ? "enable" : "disable"), ppf_pdcp_main.rx_max_reorder_window);

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_ppf_pdcp_reorder_command, static) = {
  .path = "set ppf_pdcp reorder",
  .short_help =	"set ppf_pdcp reorder [enable/disable] [window <nnn>]",
  .function = ppf_pdcp_set_reorder_command_fn,
};
/* *INDENT-ON* */



uword * test_bitmap = 0;
u32     test_window_bits = 8;
u32     test_window = 0;

static clib_error_t *
test_bitmap_fn (vlib_main_t * vm,
					unformat_input_t * input,
					vlib_cli_command_t * cmd)
{
  clib_error_t *error = NULL;
  u32 bit, from, to;
  u32 op = 0;
  u32 loop = 0;
  
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "set %d", &bit))
	    op = 1;
      else if (unformat (input, "clear %d", &bit))
	    op = 2;
      else if (unformat (input, "shift %d %d", &from, &to))
	    op = 3;
      else if (unformat (input, "check %d", &bit))
	    op = 4;
      else if (unformat (input, "reset window %d", &test_window_bits))
	    op = 5;
      else if (unformat (input, "auto %d", &loop))
	    op = 6;
      else
      {
        error = clib_error_return (0, "parse error: '%U'", format_unformat_error, input);
        goto done;
      }
    }

  
  test_window = 1 << test_window_bits;
  if (!test_bitmap) {
    clib_bitmap_alloc (test_bitmap, test_window << 1);
  	clib_bitmap_zero (test_bitmap);
  }

  //bit &= BITMAP_WORD_INDEX_MASK(test_bitmap);
  //from &= BITMAP_WORD_INDEX_MASK(test_bitmap);
  //to &= BITMAP_WORD_INDEX_MASK(test_bitmap);
  switch (op) {
  	case 1:
	  BITMAP_SET (test_bitmap, bit);
	  break;
		
	case 2:
	  BITMAP_CLR (test_bitmap, bit);
	  break;

    case 3:
      BITMAP_SHL (test_bitmap, from, to, test_window);
      break;

    case 4:
      if (BITMAP_ON (test_bitmap, bit))
	  	vlib_cli_output (vm, "check success!");
	  else
	    vlib_cli_output (vm, "check fail!");
      break;

    case 5:
	  if (test_bitmap) {
	  	clib_bitmap_free (test_bitmap);
		clib_bitmap_alloc (test_bitmap, test_window << 1);
		clib_bitmap_zero (test_bitmap);
	  }
	  break;

	case 6:
	  bit = 0;
	  while (loop) {
	  	BITMAP_SET (test_bitmap, bit);
		if (bit > 0)
		  BITMAP_SHL (test_bitmap, bit - 1, bit, test_window);

		vlib_cli_output (vm, "loop %u - window [%u, %u], Bitmap: %u bits\n %U",
					loop, bit + 1, bit + test_window,
					BITMAP_LEN (test_bitmap) * BITMAP_WORD_BITS (test_bitmap), format_bitmap_hex, test_bitmap);

		loop--;
		bit++;
	  }
	  break;

	default:
	  break;
  }
  
  if (test_bitmap) {
  	vlib_cli_output (vm, "Bitmap: %u bits\n %U", BITMAP_LEN (test_bitmap) * BITMAP_WORD_BITS (test_bitmap), format_bitmap_hex, test_bitmap);
  }

done:

  return error;
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_bitmap_command, static) = {
  .path = "test_bitmap",
  .short_help =	"test_bitmap <...>",
  .function = test_bitmap_fn,
};
/* *INDENT-ON* */


/**************************Start of pg***************************/

typedef struct
{
  u16 dc_sn;
} ppf_pdcp_header_t;


typedef struct
{
  pg_edit_t dc;
  pg_edit_t rev;
  pg_edit_t sn;
} pg_ppf_pdcp_header_t;

static inline void
pg_ppf_pdcp_header_init (pg_ppf_pdcp_header_t * p)
{
  pg_edit_init_bitfield (&p->sn, ppf_pdcp_header_t, dc_sn, 0, 12);
  pg_edit_init_bitfield (&p->rev, ppf_pdcp_header_t, dc_sn, 12, 3);
  pg_edit_init_bitfield (&p->dc, ppf_pdcp_header_t, dc_sn, 15, 1);
}

uword
unformat_pg_ppf_pdcp_header (unformat_input_t * input, va_list * args)
{
  pg_stream_t *s = va_arg (*args, pg_stream_t *);
  unformat_input_t sub_input = { 0 };
  pg_ppf_pdcp_header_t *p;
  u32 group_index;

  p = pg_create_edit_group (s, sizeof (p[0]), sizeof (ppf_pdcp_header_t),
			    &group_index);
  pg_ppf_pdcp_header_init (p);

  /* Defaults. */
  pg_edit_set_fixed (&p->dc, 0);  
  pg_edit_set_fixed (&p->rev, 0); 
  p->sn.type   = PG_EDIT_UNSPECIFIED;

  if (!unformat (input, "PDCP %U", unformat_input, &sub_input))
    goto error;

  /* Parse options. */
  while (1)
    {
      if (unformat (&sub_input, "sn %U",
		    unformat_pg_edit, unformat_pg_number, &p->sn))
	    ;

      else if (unformat (&sub_input, "dc") || unformat (&sub_input, "DC"))
        pg_edit_set_fixed (&p->dc, 1);

      /* Can't parse input: try next protocol level. */
      else
	    break;
    }

  {
    if (!unformat_user (&sub_input, unformat_pg_payload, s))
      goto error;

	unformat_free (&sub_input);
    return 1;
  }

error:
  /* Free up any edits we may have added. */
  pg_free_edit_group (s);
  unformat_free (&sub_input);

  return 0;
}

/***************************End of pg****************************/


static clib_error_t *
ppf_pdcp_config (vlib_main_t * vm, unformat_input_t * input)
{
  //ppf_pdcp_main_t *ppm = &ppf_pdcp_main;
  clib_error_t *error = 0;
  

  return error;
}

VLIB_CONFIG_FUNCTION (ppf_pdcp_config, "ppf_pdcp");

clib_error_t *
ppf_pdcp_init (vlib_main_t * vm)
{
  ppf_pdcp_main_t *ppm = &ppf_pdcp_main;
  pg_node_t *pn = pg_get_node (ppf_pdcp_input_node.index);

  pn->unformat_edit = unformat_pg_ppf_pdcp_header;

  ppm->vnet_main = vnet_get_main ();
  ppm->vlib_main = vm;
	
  ppm->pdcp_input_next_index = PPF_PDCP_INPUT_NEXT_PPF_PDCP_DECRYPT;
  ppm->pdcp_decrypt_next_index = PPF_PDCP_DECRYPT_NEXT_PPF_GTPU4_ENCAP;
  ppm->pdcp_encrypt_next_index = PPF_PDCP_ENCRYPT_NEXT_PPF_GTPU4_ENCAP;

  ppm->rx_reorder = 0;
  ppm->rx_max_reorder_window = (1 << max_log2(PDCP_DEF_REORDER_WINDOW_SIZE));

  if (ppf_main.max_capacity) {
    pool_init_fixed (ppm->sessions, ppf_main.max_capacity);
  }

  return 0;
}

VLIB_INIT_FUNCTION (ppf_pdcp_init);


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
