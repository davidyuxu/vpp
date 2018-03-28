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


#define foreach_ppf_pdcp_input_next        \
_(DROP, "error-drop")                  \
_(PPF_PDCP_DECRYPT, "ppf_pdcp_decrypt")          


typedef enum {
    PPF_PDCP_INPUT_NEXT_DROP,
    PPF_PDCP_INPUT_NEXT_PPF_PDCP_DECRYPT,
    PPF_PDCP_INPUT_N_NEXT,
} ppf_pdcp_input_next_t;

#define foreach_ppf_pdcp_decrypt_next        \
_(DROP, "error-drop")                  \
_(IP4_LOOKUP, "ip4-lookup")		    \
_(IP6_LOOKUP, "ip6-lookup")		    \
_(PPF_GTPU4_ENCAP, "ppf_gtpu4-encap")    \
_(PPF_GTPU6_ENCAP, "ppf_gtpu6-encap") 	\
_(PPF_SRB_NB_TX, "ppf_srb_nb_tx")

typedef enum {
    PPF_PDCP_DECRYPT_NEXT_DROP,
    PPF_PDCP_DECRYPT_NEXT_IP4_LOOKUP,
    PPF_PDCP_DECRYPT_NEXT_IP6_LOOKUP,
    PPF_PDCP_DECRYPT_NEXT_PPF_GTPU4_ENCAP,
    PPF_PDCP_DECRYPT_NEXT_PPF_GTPU6_ENCAP,
    PPF_PDCP_DECRYPT_NEXT_PPF_SRB_NB_TX,
    PPF_PDCP_DECRYPT_N_NEXT,
} ppf_pdcp_decrypt_next_t;

#define foreach_ppf_pdcp_encrypt_next        \
_(DROP, "error-drop")                  \
_(PPF_GTPU4_ENCAP, "ppf_gtpu4-encap")    \
_(PPF_GTPU6_ENCAP, "ppf_gtpu6-encap")    

typedef enum {
    PPF_PDCP_ENCRYPT_NEXT_DROP,
    PPF_PDCP_ENCRYPT_NEXT_PPF_GTPU4_ENCAP,
    PPF_PDCP_ENCRYPT_NEXT_PPF_GTPU6_ENCAP,
    PPF_PDCP_ENCRYPT_N_NEXT,
} ppf_pdcp_encrypt_next_t;

#define foreach_ppf_sb_path_lb_next        \
_(DROP, "error-drop")                  \
_(PPF_PDCP_ENCRYPT, "ppf_pdcp_encrypt")          

typedef enum {
    PPF_SB_PATH_LB_NEXT_DROP,
    PPF_SB_PATH_LB_NEXT_PPF_PDCP_ENCRYPT,
    PPF_SB_PATH_LB_N_NEXT,
} ppf_sb_path_lb_next_t;

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

typedef struct
{
  u32 out_sn;   /* outgoing sequence number */
  u32 in_sn;    /* incoming sequence number */
} ppf_pdcp_session_t;

typedef struct
{
  ppf_pdcp_session_t * sessions;
  
  u32 pdcp_input_next_index;
  u32 pdcp_decrypt_next_index;
  u32 pdcp_encrypt_next_index;

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

  u32 srb_rx_next_index;
  u32 sb_lb_next_index;  

  /* API message ID base */
  u16 msg_id_base;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} ppf_sb_main_t;

#define DEF_MAX_PPF_SESSION 100000
#define MAX_SB_PER_DRB  3

#define INVALID_TUNNEL_ID ~0

typedef enum
{
  PPF_GTPU_SB = 0, 			//The DRB SB GTP tunnel
  PPF_GTPU_NB,			//The DRB NB GTP tunnel
  PPF_GTPU_LBO,			//The GTP tunnel for PPF LBO
  PPF_GTPU_SRB,			//The GTP SRB SB GTP tunnel
  PPF_GTPU_NORMAL
} ppf_gtpu_tunnel_type_t;

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
  uword *nb_out_msg_by_sn;   /* hash <PDCP SN> -> <transaction-id + request-id> */
  ppf_gtpu_tunnel_id_type_t sb_tunnel[MAX_SB_PER_DRB];
} ppf_srb_callline_t;

typedef struct
{	
  ppf_gtpu_tunnel_id_type_t nb_tunnel;
  ppf_gtpu_tunnel_id_type_t sb_tunnel[MAX_SB_PER_DRB];
} ppf_drb_callline_t;

typedef struct
{
  u32 session_id;
} ppf_pdcp_callline_t;

typedef struct 
{	
  u32 call_index;
  union {
    ppf_drb_callline_t drb;
    ppf_srb_callline_t srb;
  } rb;
  ppf_pdcp_callline_t pdcp;
} ppf_callline_t;

typedef struct
{
  u32 max_capacity;
  ppf_callline_t * ppf_calline_table;
} ppf_main_t;

extern ppf_main_t ppf_main;

extern ppf_sb_main_t ppf_sb_main;

extern vlib_node_registration_t ppf_pdcp_decrypt_node;
extern vlib_node_registration_t ppf_pdcp_encrypt_node;
extern vlib_node_registration_t ppf_pdcp_input_node;
extern vlib_node_registration_t ppf_sb_path_lb_node;
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


#endif /* included_vnet_ppfu_h */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
