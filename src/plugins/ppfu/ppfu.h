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

#ifndef included_vnet_ppfu_h
#define included_vnet_ppfu_h

#include <vppinfra/lock.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp.h>
#include <vnet/dpo/dpo.h>
#include <vnet/adj/adj_types.h>
#include <vnet/fib/fib_table.h>
#include <openssl/evp.h>
#include <openssl/cmac.h>




#define foreach_ppf_pdcp_input_next        \
_(DROP, "error-drop")                      \
_(PPF_PDCP_DECRYPT, "ppf_pdcp_decrypt")    \
_(PPF_PDCP_HANDOFF, "ppf_pdcp_handoff")


typedef enum {
    PPF_PDCP_INPUT_NEXT_DROP,
    PPF_PDCP_INPUT_NEXT_PPF_PDCP_DECRYPT,
    PPF_PDCP_INPUT_NEXT_PPF_PDCP_HANDOFF,
    PPF_PDCP_INPUT_N_NEXT,
} ppf_pdcp_input_next_t;

#define foreach_ppf_pdcp_decrypt_next        \
_(DROP, "error-drop")                        \
_(REORDER, "ppf_pdcp_reorder")

typedef enum {
    PPF_PDCP_DECRYPT_NEXT_DROP,
    PPF_PDCP_DECRYPT_NEXT_REORDER,
    PPF_PDCP_DECRYPT_N_NEXT,
} ppf_pdcp_decrypt_next_t;

#define foreach_ppf_pdcp_reorder_next        \
_(DROP, "error-drop")                        \
_(IP4_LOOKUP, "ip4-lookup")                  \
_(IP6_LOOKUP, "ip6-lookup")	                 \
_(PPF_GTPU4_ENCAP, "ppf_gtpu4-encap")        \
_(PPF_GTPU6_ENCAP, "ppf_gtpu6-encap") 	     \
_(PPF_SRB_NB_TX, "ppf_srb_nb_tx")            \
_(PPF_TX_HANDOFF, "ppf_tx_handoff")

typedef enum {
    PPF_PDCP_REORDER_NEXT_DROP,
    PPF_PDCP_REORDER_NEXT_IP4_LOOKUP,
    PPF_PDCP_REORDER_NEXT_IP6_LOOKUP,
    PPF_PDCP_REORDER_NEXT_PPF_GTPU4_ENCAP,
    PPF_PDCP_REORDER_NEXT_PPF_GTPU6_ENCAP,
    PPF_PDCP_REORDER_NEXT_PPF_SRB_NB_TX,
    PPF_PDCP_REORDER_NEXT_PPF_TX_HANDOFF,
    PPF_PDCP_REORDER_N_NEXT,
} ppf_pdcp_reorder_next_t;


#define foreach_ppf_pdcp_encrypt_next        \
_(DROP, "error-drop")                        \
_(PPF_GTPU4_ENCAP, "ppf_gtpu4-encap")        \
_(PPF_GTPU6_ENCAP, "ppf_gtpu6-encap")        \
_(PPF_TX_HANDOFF, "ppf_tx_handoff")


typedef enum {
    PPF_PDCP_ENCRYPT_NEXT_DROP,
    PPF_PDCP_ENCRYPT_NEXT_PPF_GTPU4_ENCAP,
    PPF_PDCP_ENCRYPT_NEXT_PPF_GTPU6_ENCAP,
    PPF_PDCP_ENCRYPT_NEXT_PPF_TX_HANDOFF,
    PPF_PDCP_ENCRYPT_N_NEXT,
} ppf_pdcp_encrypt_next_t;

#define foreach_ppf_sb_path_lb_next        \
_(DROP, "error-drop")                      \
_(PPF_PDCP_ENCRYPT, "ppf_pdcp_encrypt")    \
_(PPF_PDCP_HANDOFF, "ppf_pdcp_handoff")

typedef enum {
    PPF_SB_PATH_LB_NEXT_DROP,
    PPF_SB_PATH_LB_NEXT_PPF_PDCP_ENCRYPT,
    PPF_SB_PATH_LB_NEXT_PPF_PDCP_HANDOFF,
    PPF_SB_PATH_LB_N_NEXT,
} ppf_sb_path_lb_next_t;


#define foreach_ppf_lbo_input_next        \
_(DROP, "error-drop")                      \
_(SB_PATH_LB, "ppf_sb_path_lb")

typedef enum {
    PPF_LBO_INPUT_NEXT_DROP,
    PPF_LBO_INPUT_NEXT_SB_PATH_LB,
    PPF_LBO_INPUT_N_NEXT,
} ppf_lbo_input_next_t;


#define foreach_ppf_srb_nb_rx_next        \
_(DROP, "error-drop")   		  \
_(PPF_PDCP_ENCRYPT, "ppf_pdcp_encrypt")   \
_(PPF_SB_PATH_LB, "ppf_sb_path_lb")  
  
typedef enum {
    PPF_SRB_NB_RX_NEXT_DROP,
    PPF_SRB_NB_RX_NEXT_PPF_PDCP_ENCRYPT,
    PPF_SRB_NB_RX_NEXT_PPF_SB_PATH_LB,
    PPF_SRB_NB_RX_N_NEXT,
} ppf_srb_nb_rx_next_t;

#define foreach_ppf_srb_nb_tx_next        \
 _(DROP, "error-drop")	 		\
_(IP4_LOOKUP, "ip4-lookup")

 typedef enum {
    PPF_SRB_NB_TX_NEXT_DROP,
    PPF_SRB_NB_TX_NEXT_IP4_LOOKUP,
    PPF_SRB_NB_TX_N_NEXT,
} ppf_srb_nb_tx_next_t;

#define EIA2_IV_LEN              8    /* 64 bits */
#define EIA_MAC_LEN              4    /* 32 bits */


#define MAX_PDCP_KEY_LEN              16    /* 128 bits */
#define PDCP_REPLAY_WINDOW_SIZE(l)    (1 << ((l) - 1))
#define PDCP_DEF_REORDER_WINDOW_SIZE  64
#define PDCP_MAX_REORDER_WINDOW_SIZE  1024
#define INVALID_BUFFER_INDEX          ~0

#define PPF_PDCP_COUNT(hfn, sn, len)       ((255 == (len)) ? (sn) : ((hfn) << (len) | (sn)))
#define PPF_PDCP_HFN(count, len)           ((255 == (len)) ? 0 : ((count) >> (len)))
#define PPF_PDCP_SN(count, len)            ((255 == (len)) ? (count) : (count & pow2_mask((len))))
#define PPF_PDCP_SN_INC(sn, len)           (((sn) + 1) & pow2_mask((len)))
#define PPF_PDCP_SN_DEC(sn, len)           (((sn) - 1) & pow2_mask((len)))
#define PPF_PDCP_HFN_INC(hfn, len)         (((hfn) + 1) & pow2_mask(32 - (len)))
#define PPF_PDCP_HFN_DEC(hfn, len)         (((hfn) - 1) & pow2_mask(32 - (len)))
#define PPF_PDCP_COUNT_HFN_DEC(count, len) ((255 == (len)) ? (((count) >> (len)) - 1) : ((((count) >> (len)) - 1) & pow2_mask(32 - (len))))
#define PPF_PDCP_COUNT_INC(hfn, sn, len)                \
do {                                                    \
	(sn)++;                                             \
	if ((sn) == (1 << (len))) {                        \
		(hfn) = ((hfn) + 1) & pow2_mask(32 - (len));    \
		(sn) = 0;                                       \
	}                                                   \
} while (0)

/* PDCP replay bitmap operations */
#define BITMAP_LEN(bm)               (vec_len((bm)))
#define BITMAP_WORD_INDEX_MASK(bm)   (BITMAP_LEN((bm)) - 1)
#define BITMAP_WORD_SHIFTS(bm) 	     (max_log2(BITS((bm)[0])))
#define BITMAP_WORD_BITS(bm)         (BITS((bm)[0]))
#define BITMAP_BIT_MASK(bm)          (BITMAP_WORD_BITS(bm) - 1)

#define BITMAP_WORD_INDEX(bm, bit)        ((bit) >> BITMAP_WORD_SHIFTS(bm))
#define BITMAP_WORD_INDEX_ROUND(bm, bit)  (BITMAP_WORD_INDEX((bm), (bit)) & BITMAP_WORD_INDEX_MASK((bm)))
#define	BITMAP_WORD(bm, bit)              ((bm)[BITMAP_WORD_INDEX_ROUND(bm, bit)])
#define	BITMAP_BIT(bm, bit)               (1UL << ((bit) & BITMAP_BIT_MASK(bm)))


always_inline void
__bitmap_advance__(uword * bitmap, u32 old, u32 new, u32 window)
{
	u32 index, index2, index_cur, id;
	u32 diff;
	u32 max_bit = ~0;
	u32 old_max = old + window;
	u32 new_max = new + window;
	
	/**
	 * now update the bit
	 */
	index = BITMAP_WORD_INDEX (bitmap, new_max);
	
	/**
	 * first check if the sequence number is in the range
	 */
		
	if (new_max > old_max) {
		index_cur = BITMAP_WORD_INDEX (bitmap, old_max);
		diff = index - index_cur;
		if (diff > BITMAP_LEN(bitmap)) {  /* something unusual in this case */
			diff = BITMAP_LEN(bitmap);
		}

		for (id = 0; id < diff; ++id) {
			bitmap[(id + index_cur + 1) & BITMAP_WORD_INDEX_MASK(bitmap)] = 0;
		}	
	} else {
		index2 = BITMAP_WORD_INDEX (bitmap, max_bit);
		index_cur = BITMAP_WORD_INDEX (bitmap, old_max);

		/* lastseq -> max_seq */
		diff = index2 - index_cur;
		if (diff > BITMAP_LEN(bitmap)) {  /* something unusual in this case */
			diff = BITMAP_LEN(bitmap);
		}
		
		for (id = 0; id < diff; ++id) {
			bitmap[(id + index_cur + 1) & BITMAP_WORD_INDEX_MASK(bitmap)] = 0;
		}

		/* 0 -> sequence */
		diff = index;
		for (id = 0; id <= diff; ++id) {
			bitmap[(id) & BITMAP_WORD_INDEX_MASK(bitmap)] = 0;
		}
	}
}

#define	BITMAP_ON(bm, bit)             (BITMAP_WORD(bm, bit) & BITMAP_BIT(bm, bit))
#define	BITMAP_SET(bm, bit)		       (BITMAP_WORD(bm, bit) |= BITMAP_BIT(bm, bit))
#define	BITMAP_CLR(bm, bit)		       (BITMAP_WORD(bm, bit) &= ~BITMAP_BIT(bm, bit))
#define BITMAP_SHL(bm, o, n, w)        __bitmap_advance__(bm, o, n, w)

#define VEC_INDEX_MASK(v)    (vec_len((v)) - 1)
#define VEC_AT(v, i)         (vec_elt((v), (i) & VEC_INDEX_MASK ((v))))
#define VEC_SET(v, i, e)     (VEC_AT (v, i) = (e))
#define VEC_ELT_NE(v, i, e)  ((e) != VEC_AT(v, i))
#define VEC_ELT_EQ(v, i, e)  ((e) == VEC_AT(v, i))


enum pdcp_security_alg_t 
{ 
  PDCP_NONE_SECURITY    = 0x00,
  PDCP_NULL_CIPHERING   = 0x01,
  PDCP_SNOW3G_CIPHERING = 0x02,
  PDCP_AES_CIPHERING    = 0x04,
  PDCP_ZUC_CIPHERING    = 0x08,
  PDCP_NULL_INTEGRITY   = 0x10,
  PDCP_SNOW3G_INTEGRITY = 0x20,
  PDCP_AES_INTEGRITY    = 0x40,
  PDCP_ZUC_INTEGRITY    = 0x80
};

enum pdcp_integrity_alg_t 
{ 
  PDCP_EIA_NONE,
  PDCP_EIA0,
  PDCP_EIA1,
  PDCP_EIA2,
  PDCP_EIA3
};

enum pdcp_crypt_alg_t 
{
  PDCP_EEA_NONE =0, 
  PDCP_EEA0,
  PDCP_EEA1,
  PDCP_EEA2,
  PDCP_EEA3
};

enum _config_flags_{
  INTEGRITY_KEY_VALID = 0x1,
  CRYPTO_KEY_VALID = 0x2,
  INTEGRITY_ALG_VALID = 0x4,
  CRYPTO_ALG_VALID = 0x8
};

typedef struct _ppf_pdcp_config_t_
{
  u16 flags;
  u8  integrity_key[MAX_PDCP_KEY_LEN];
  u8  crypto_key[MAX_PDCP_KEY_LEN];
  u8  integrity_algorithm;
  u8  crypto_algorithm;
  //u8 valid_paths;
  //u8 removed_paths;
  //PathContext paths[MAX_PATHS];
} ppf_pdcp_config_t;


enum {
//33.401	 DIRECTION bit shall be 0 for uplink(DEC) and 1 for downlink(ENC)

  PPF_PDCP_DIR_DEC = 0,
  PPF_PDCP_DIR_ENC = 1
};

typedef u32 (*pdcp_security_handler)(u8 * /* in */, u8 * /* out */, u32 /* len */, void * /* security parameters */);

typedef bool (*pdcp_intergity_handler)(vlib_main_t * /* in */, vlib_buffer_t * /* in */, void * /* security parameters */);




typedef struct
{
	/* LFSR */
	u32 LFSR_S0;
	u32 LFSR_S1;
	u32 LFSR_S2;
	u32 LFSR_S3;
	u32 LFSR_S4;
	u32 LFSR_S5;
	u32 LFSR_S6;
	u32 LFSR_S7;
	u32 LFSR_S8;
	u32 LFSR_S9;
	u32 LFSR_S10;
	u32 LFSR_S11;
	u32 LFSR_S12;
	u32 LFSR_S13;
	u32 LFSR_S14;
	u32 LFSR_S15;
	/* FSM */
	
	u32 FSM_R1;
	u32 FSM_R2;
	u32 FSM_R3;

}snow3g_ctx_t;

typedef struct
{
    /* the state registers of LFSR */
     u32 LFSR_S0;
     u32 LFSR_S1;
     u32 LFSR_S2;
     u32 LFSR_S3;
     u32 LFSR_S4;
     u32 LFSR_S5;
     u32 LFSR_S6;
     u32 LFSR_S7;
     u32 LFSR_S8;
     u32 LFSR_S9;
     u32 LFSR_S10;
     u32 LFSR_S11;
     u32 LFSR_S12;
     u32 LFSR_S13;
     u32 LFSR_S14;
     u32 LFSR_S15;

     /* the registers of F */
     u32 F_R1;
     u32 F_R2;

     /* the outputs of BitReorganization */
     u32 BRC_X0;
     u32 BRC_X1;
     u32 BRC_X2;
     u32 BRC_X3;

}zuc_ctx_t;

typedef struct _ppf_pdcp_sa_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX *cypher_ctx;
#else
  EVP_CIPHER_CTX cypher_ctx;
#endif
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  CMAC_CTX *integrity_ctx;
} ppf_pdcp_aes_sa_t;



typedef struct
{
  ppf_pdcp_aes_sa_t down_sa;
  ppf_pdcp_aes_sa_t up_sa;

  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  u8  security_algorithms;
  u8  sn_length;
  u8  header_length;
  u8  mac_length;
  u32 tx_hfn;
  u32 tx_next_sn;
  void (*encap_header)(u8 *, u8, u32);
  pdcp_intergity_handler protect;
  pdcp_security_handler encrypt;

  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);

  u32 rx_hfn;
  u32 rx_next_expected_sn;
  u32 rx_last_forwarded_sn;
  u32 replay_window;
  u64 in_flight_limit;
  uword * rx_replay_bitmap;  /* bitmap of rx sn */
  u32 * rx_reorder_buffers;  /* rx reordering vector*/
  void (*decap_header)(u8 *, u8 *, u32 *);
  pdcp_intergity_handler validate;
  pdcp_security_handler decrypt;

  CLIB_CACHE_LINE_ALIGN_MARK (cacheline2);

  //snow 3g ctx
  snow3g_ctx_t  snow3g_ctx;
  //zuc ctx
  zuc_ctx_t  zuc_ctx;  

  u8  integrity_key[MAX_PDCP_KEY_LEN];
  u8  crypto_key[MAX_PDCP_KEY_LEN];
} ppf_pdcp_session_t;

typedef struct
{
  ppf_pdcp_session_t * pdcp_sess;
  u32 count;
  u8  bearer;
  u8  dir;
} ppf_pdcp_security_param_t;

typedef struct
{
  ppf_pdcp_session_t * sessions;
  
  u32 pdcp_input_next_index;
  u32 pdcp_decrypt_next_index;
  u32 pdcp_encrypt_next_index;
  u32 pdcp_reorder_next_index;

  u32 rx_reorder;
  u32 rx_max_reorder_window;

   /**
   * Node type for registering to fib changes.
   */
  fib_node_type_t fib_node_type;

  /* API message ID base */
  u16 msg_id_base;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} ppf_pdcp_main_t;

extern ppf_pdcp_main_t ppf_pdcp_main;

typedef struct
{
  u8 *rewrite;
  
  /* tunnel src (vpp) and dst (cp) addresses, ipv4 is enough */
  u32 src;
  u32 dst;

  u32 want_feedback;

  u32 srb_rx_next_index;
  u32 sb_lb_next_index;  

  /* API message ID base */
  u16 msg_id_base;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} ppf_sb_main_t;

#define PPFU_HANDOFF		0
#define DEF_MAX_PPF_SESSION 100000
#define MAX_SB_PER_CALL  3

#define INVALID_TUNNEL_ID ~0

#define INVALID_CALL_TYPE ~0

#define DEFAULT_SB_INDEX 0

typedef enum
{
  PPF_GTPU_SB = 0, 			//The DRB SB GTP tunnel
  PPF_GTPU_NB,			//The DRB NB GTP tunnel
  PPF_GTPU_LBO,			//The GTP tunnel for PPF LBO
  PPF_GTPU_SRB,			//The GTP SRB SB GTP tunnel
  PPF_GTPU_NORMAL
} ppf_gtpu_tunnel_type_t;

typedef enum
{
   PPF_SRB_CALL = 0,
   PPF_DRB_CALL
} ppf_calline_type_t;

 typedef enum
{
   PPF_TUNNEL_MODE = 0,
   PPF_LBO_MODE
} ppf_calline_mode_t;

typedef struct
{
  ppf_gtpu_tunnel_type_t tunnel_type;
  u32 tunnel_id;
} ppf_gtpu_tunnel_id_type_t;

typedef union {
  struct {
    u32 transaction_id;
    u32 request_id;
  };
  u64 as_u64;
} ppf_srb_msg_id_t;

typedef struct
{
  u64 *nb_out_msg_by_sn;   /* hash <PDCP SN> -> <transaction-id + request-id> */
  ppf_gtpu_tunnel_id_type_t sb_tunnel[MAX_SB_PER_CALL];
} ppf_srb_callline_t;

typedef struct
{	
  ppf_gtpu_tunnel_id_type_t nb_tunnel;
  ppf_gtpu_tunnel_id_type_t sb_tunnel[MAX_SB_PER_CALL];
} ppf_drb_callline_t;

typedef struct
{
  u32 session_id;
} ppf_pdcp_callline_t;

#define PPF_SB_COUNT_MASK             (0x03) // pow2_mask(max_log2(MAX_SB_PER_CALL))
#define PPF_SB_PATH_MASK              (0x07) // pow2_mask(MAX_SB_PER_CALL)
#define PPF_SB_PATH_GET_VALID(mp, i)  ((mp) & (i))
#define PPF_SB_PATH_SET_VALID(mp, i)  ((mp) |= (1 << ((i) + 2)))
#define PPF_SB_COUNT(mp)              ((mp) & PPF_SB_COUNT_MASK)
#define PPF_SB_VALID_PATH(mp)         min_log2(((mp) >> 2) & PPF_SB_PATH_MASK)

typedef struct 
{	
  u32 call_index;
  ppf_calline_type_t call_type; 
  union {
    ppf_drb_callline_t drb;
    ppf_srb_callline_t srb;
  } rb;
  ppf_pdcp_callline_t pdcp;
  u8  sb_multi_path;
  u8  sb_policy;
  u8  lbo_mode;
  u8  ue_mode;
  u32 ue_bearer_id;
  u32 sw_if_index;
  u32 inner_vrf_id;
  u32 hw_if_index;
} ppf_callline_t;

#define PPF_BEARER(ub)  (((ub) >> 25) & 0x1f)

typedef struct
{
  u32 call_id;
  ppf_calline_type_t call_type;
  u32 sb_policy;
  u32 ue_bearer_id;
  u32 lbo_mode;
  u32 ue_mode;
} vnet_ppf_add_callline_args_t;

enum {
  PPF_IO_MODE_SHARED = 0,
  PPF_IO_MODE_DEDICATED
};

typedef struct
{
  ppf_callline_t * ppf_calline_table;
  
  u32 handoff_enable;
  u32 io_mode;
  u32 max_capacity;
  u32 **buffers_duplicated_per_thread;
  
  u16 msg_id_base;
} ppf_main_t;

extern ppf_main_t ppf_main;

extern ppf_sb_main_t ppf_sb_main;

extern vlib_node_registration_t ppf_pdcp_reorder_node;
extern vlib_node_registration_t ppf_pdcp_decrypt_node;
extern vlib_node_registration_t ppf_pdcp_encrypt_node;
extern vlib_node_registration_t ppf_pdcp_input_node;
extern vlib_node_registration_t ppf_sb_path_lb_node;
extern vlib_node_registration_t ppf_lbo_input_node;
extern vlib_node_registration_t ppf_srb_nb_rx_node;
extern vlib_node_registration_t ppf_srb_nb_tx_node;

typedef struct
{
  u8 is_add;
  u8 is_ip6;
  ip46_address_t src, dst;
  u32 mcast_sw_if_index;
  u32 encap_fib_index;
  u32 decap_next_index;
  u32 in_teid;
  u32 out_teid;
  u32 call_id;
  u32 tunnel_type;
} vnet_ppf_pdcp_add_del_tunnel_args_t;


typedef struct _ppf_srb_out_msg_
{
  u32 request_id;
  u8  sb_id[3];
  u8  sb_num;
  u32 data_l;
  u8  data[0];
} ppf_srb_out_msg_t;

typedef struct _ppf_srb_in_msg_
{
  u32 request_id;
  u32 integrity_status;
  u32 data_l;
  u8  data[0];
} ppf_srb_in_msg_t;

typedef struct _ppf_srb_header_t_
{
  u32 call_id;  // instead of ue_bearer_id
  u32 transaction_id;
  union {
    ppf_srb_in_msg_t  in;
    ppf_srb_out_msg_t out;
  } msg;
} ppf_srb_header_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct
{
  ip4_header_t       ip4;            /* 20 bytes */
  udp_header_t       udp;            /* 8 bytes */
  ppf_srb_header_t   srb;            /* 24 bytes */
}) ip4_srb_header_t;
/* *INDENT-ON* */

int vnet_ppf_del_callline (u32 call_id) ;

int vnet_ppf_add_callline (vnet_ppf_add_callline_args_t *c);


u8 *format_ppf_call_type (u8 * s, va_list * va);
u8 *format_ppf_pdcp_session (u8 * s, va_list * va);
u8 *format_ppf_callline (u8 * s, va_list * va);

u32 ppf_pdcp_create_session (u8 sn_length, u32 rx_count, u32 tx_count, u32 in_flight_limit);
u32 ppf_pdcp_session_update_as_security (ppf_pdcp_session_t * pdcp_sess, ppf_pdcp_config_t * config);
u32 ppf_pdcp_clear_session (ppf_pdcp_session_t * pdcp_sess);

void ppf_reset_calline (u32 call_id) ;
void ppf_init_calline (u32 call_id, ppf_calline_type_t call_type) ;

void ppf_init_callline_intf (u32 call_id);
void ppf_reset_callline_intf (u32 call_id);



#endif /* included_vnet_ppfu_h */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
