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

ppf_pdcp_main_t ppf_pdcp_main; 

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

  ppm->vnet_main = vnet_get_main ();
  ppm->vlib_main = vm;
	
  ppm->pdcp_input_next_index = PPF_PDCP_INPUT_NEXT_PPF_PDCP_DECRYPT;
  ppm->pdcp_decrypt_next_index = PPF_PDCP_DECRYPT_NEXT_PPF_GTPU4_ENCAP;
  ppm->pdcp_encrypt_next_index = PPF_PDCP_ENCRYPT_NEXT_PPF_GTPU4_ENCAP;

  if (ppf_main.max_capacity) {
    pool_init_fixed (ppm->sessions, ppf_main.max_capacity);
  }

  return 0;
}

VLIB_INIT_FUNCTION (ppf_pdcp_init);


u8 *
format_ppf_pdcp_session (u8 * s, va_list * va)
{
  ppf_pdcp_session_t * pdcp_session = va_arg (*va, ppf_pdcp_session_t *);

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

  s = format (s, "security-alg %x, intergity-key %U, crypto-key %U\n", 
  	pdcp_session->security_algorithms, 
  	format_hex_bytes, pdcp_session->integrity_key, MAX_PDCP_KEY_LEN,
  	format_hex_bytes, pdcp_session->crypto_key, MAX_PDCP_KEY_LEN);

  return s;
}

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

u32
ppf_pdcp_eia0_protect (u8 * in, u8 * out, u32 size, void * security_parameters)
{
	memset (out, 0x00, 4);
	return 0;
}

u32
ppf_pdcp_eia0_validate (u8 * in, u8 * out, u32 size, void * security_parameters)
{
	memset (out, 0x00, 4);
	return 0;
}

u32
ppf_pdcp_eia1 (u8 * in, u8 * out, u32 size, void * security_parameters)
{
	ppf_pdcp_security_param_t * sec_para = (ppf_pdcp_security_param_t *)security_parameters;
	CLIB_UNUSED(u8 iv[16]) = {0};

	ppf_pdcp_gen_iv (PDCP_SNOW3G_INTEGRITY,
				sec_para->count, sec_para->bearer, sec_para->dir, iv);

	// TODO:
	out[0] = 'S';
	out[1] = '3';
	out[2] = 'G';
	out[3] = '^';

	return 0;
}

u32
ppf_pdcp_eea1 (u8 * in, u8 * out, u32 size, void * security_parameters)
{
	ppf_pdcp_security_param_t * sec_para = (ppf_pdcp_security_param_t *)security_parameters;
	CLIB_UNUSED(u8 iv[16]) = {0};

	ppf_pdcp_gen_iv (PDCP_SNOW3G_CIPHERING,
				sec_para->count, sec_para->bearer, sec_para->dir, iv);

	// TODO:
	
	return 0;
}

u32
ppf_pdcp_eia2 (u8 * in, u8 * out, u32 size, void * security_parameters)
{
	ppf_pdcp_security_param_t * sec_para = (ppf_pdcp_security_param_t *)security_parameters;
	CLIB_UNUSED(u8 iv[16]) = {0};

	ppf_pdcp_gen_iv (PDCP_AES_INTEGRITY,
				sec_para->count, sec_para->bearer, sec_para->dir, iv);

	// TODO:
	out[0] = 'A';
	out[1] = 'E';
	out[2] = 'S';
	out[3] = '^';
	
	return 0;
}

u32
ppf_pdcp_eea2 (u8 * in, u8 * out, u32 size, void * security_parameters)
{
	ppf_pdcp_security_param_t * sec_para = (ppf_pdcp_security_param_t *)security_parameters;
	CLIB_UNUSED(u8 iv[16]) = {0};

	ppf_pdcp_gen_iv (PDCP_AES_CIPHERING,
				sec_para->count, sec_para->bearer, sec_para->dir, iv);

	// TODO:
	
	return 0;
}

u32
ppf_pdcp_eia3 (u8 * in, u8 * out, u32 size, void * security_parameters)
{
	ppf_pdcp_security_param_t * sec_para = (ppf_pdcp_security_param_t *)security_parameters;
	CLIB_UNUSED(u8 iv[16]) = {0};

	ppf_pdcp_gen_iv (PDCP_ZUC_INTEGRITY,
				sec_para->count, sec_para->bearer, sec_para->dir, iv);

	// TODO:
	out[0] = 'Z';
	out[1] = 'U';
	out[2] = 'C';
	out[3] = '^';
	
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
  pdcp_sess->tx_next_sn = tx_count; //(~(0xFFFFFFFF<<sn_length))&tx_count;
  pdcp_sess->tx_hfn = tx_count >> sn_length;
  pdcp_sess->rx_next_expected_sn = rx_count; //(~(0xFFFFFFFF<<sn_length))&rx_count;
  pdcp_sess->rx_last_forwarded_sn = (((pdcp_sess->rx_next_expected_sn - 1) & ((1 << sn_length) - 1)) & max_sn);
  pdcp_sess->rx_hfn = ((rx_count >> sn_length) - 1) & (max_sn >> sn_length);

  if (in_flight_limit == max_sn) // no value configured by upper layers
    pdcp_sess->in_flight_limit = 0x1 << (sn_length - 1); //use default value: SN-range/2 - 1
  else if (in_flight_limit != 0)
    pdcp_sess->in_flight_limit = in_flight_limit;
  else //in_flight_limit == 0
    pdcp_sess->in_flight_limit = 0x1FFFFFFFF; //0 means no in-flight limit, set limit to 2^32 + 1

  clib_warning("ppf_pdcp_create_session: configuring in-flight-limit to 0x%lx, received configuration value 0x%x \n",
		  pdcp_sess->in_flight_limit, in_flight_limit);

  pdcp_sess->protect = &ppf_pdcp_nop;
  pdcp_sess->validate = &ppf_pdcp_nop;
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
      	pdcp_sess->protect = &ppf_pdcp_nop;
        pdcp_sess->validate = &ppf_pdcp_nop;
        pdcp_sess->mac_length = 0;
        break;
	
      case PDCP_EIA0:
        pdcp_sess->security_algorithms |= PDCP_NULL_INTEGRITY;
      	pdcp_sess->protect = &ppf_pdcp_eia0_protect;
        pdcp_sess->validate = &ppf_pdcp_eia0_validate;
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
    pool_put (ppf_pdcp_main.sessions, pdcp_sess);
  }

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
