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

#ifndef included_vnet_ppf_gtpu_h
#define included_vnet_ppf_gtpu_h

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

/**
 *		Bits
 * Octets	8	7	6	5	4	3	2	1
 * 1		          Version	PT	(*)	E	S	PN
 * 2		Message Type
 * 3		Length (1st Octet)
 * 4		Length (2nd Octet)
 * 5		Tunnel Endpoint Identifier (1st Octet)
 * 6		Tunnel Endpoint Identifier (2nd Octet)
 * 7		Tunnel Endpoint Identifier (3rd Octet)
 * 8		Tunnel Endpoint Identifier (4th Octet)
 * 9		Sequence Number (1st Octet)1) 4)
 * 10		Sequence Number (2nd Octet)1) 4)
 * 11		N-PDU Number2) 4)
 * 12		Next Extension Header Type3) 4)
**/

typedef struct
{
  u8 ver_flags;
  u8 type;
  u16 length;			/* length in octets of the payload */
  u32 teid;
  u16 sequence;
  u8 pdu_number;
  u8 next_ext_type;
} ppf_gtpu_header_t;

#define PPF_GTPU_VER_MASK (7<<5)
#define PPF_GTPU_PT_BIT   (1<<4)
#define PPF_GTPU_E_BIT    (1<<2)
#define PPF_GTPU_S_BIT    (1<<1)
#define PPF_GTPU_PN_BIT   (1<<0)
#define PPF_GTPU_E_S_PN_BIT  (7<<0)

#define PPF_GTPU_V1_VER   (1<<5)

#define PPF_GTPU_PT_GTP    (1<<4)
#define PPF_GTPU_TYPE_PPF_GTPU  255

#define PPF_GTPU_HEADER_MIN   (8)

#define NEXT_EXT_HEADER_TYPE_PDU_SESSION (133) // 1000 0101

#define PPF_GTPU_PDU_SESSION_TYPE(type) (((type) >> 4) & 0xf)
#define PPF_GTPU_PDU_SESSION_RQI(rqi_qfi) ((rqi_qfi) & 0x40)
#define PPF_GTPU_PDU_SESSION_QFI(rqi_qfi) ((rqi_qfi) & 0x3f)
#define PPF_GTPU_PDU_SESSION_RQI_QFI(rqi, qfi) ((rqi << 6) | qfi)

typedef struct
{
  u8 ext_header_len;

  struct
    {
      u8 pdu_type; /* bit 0~3 : spare, bit 4~7 : PDU type */
      u8 rqi_qfi;  /* bit 0~5 : QFI, bit 6 : RQI, bit 7 : spare */
    }pdu_session_container;
  u8 next_ext_header_type;
}ppf_gtpu_ext_pdu_header_t;


/* *INDENT-OFF* */
typedef CLIB_PACKED(struct
{
  ip4_header_t ip4;            /* 20 bytes */
  udp_header_t udp;            /* 8 bytes */
  ppf_gtpu_header_t ppf_gtpu;	       /* 8 bytes */
  ppf_gtpu_ext_pdu_header_t ext_pdu_header;  /* 4 bytes */
}) ip4_ppf_gtpu_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct
{
  ip6_header_t ip6;            /* 40 bytes */
  udp_header_t udp;            /* 8 bytes */
  ppf_gtpu_header_t ppf_gtpu;     /* 8 bytes */
  ppf_gtpu_ext_pdu_header_t ext_pdu_header;  /* 4 bytes */
}) ip6_ppf_gtpu_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED
(struct {
  /*
   * Key fields: ip src and ppf_gtpu teid on incoming ppf_gtpu packet
   * all fields in NET byte order
   */
  union {
    struct {
      u32 teid;
    };
    u32 as_u32;
  };
}) ppf_gtpu4_tunnel_key_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED
(struct {
  /*
   * Key fields: ip src and ppf_gtpu teid on incoming ppf_gtpu packet
   * all fields in NET byte order
   */
  u32 teid;
}) ppf_gtpu6_tunnel_key_t;
/* *INDENT-ON* */

typedef struct
{
  /* Rewrite string */
  u8 *rewrite;

  /* FIB DPO for IP forwarding of ppf_gtpu encap packet */
  dpo_id_t next_dpo;

  /* ppf_gtpu teid in HOST byte order */
  u32 in_teid;
  u32 out_teid;

  /* tunnel src and dst addresses */
  ip46_address_t src;
  ip46_address_t dst;

  /* mcast packet output intf index (used only if dst is mcast) */
  u32 mcast_sw_if_index;

  /* decap next index */
  u32 decap_next_index;
  u32 encap_next_index;

  /* The FIB index for src/dst addresses */
  u32 encap_fib_index;

  /* vnet intfc index */
  u32 sw_if_index;
  u32 hw_if_index;

  /**
   * Linkage into the FIB object graph
   */
  fib_node_t node;

  /*
   * The FIB entry for (depending on ppf_gtpu tunnel is unicast or mcast)
   * sending unicast ppf_gtpu encap packets or receiving mcast ppf_gtpu packets
   */
  fib_node_index_t fib_entry_index;
  adj_index_t mcast_adj_index;

  /**
   * The tunnel is a child of the FIB entry for its destination. This is
   * so it receives updates when the forwarding information for that entry
   * changes.
   * The tunnels sibling index on the FIB entry's dependency list.
   */
  u32 sibling_index;

  u32 rb_index;
  
  u32 call_id;
  u32 is_ip6;
  ppf_gtpu_tunnel_type_t tunnel_type;
  u32 sb_id;
  u32 dst_port;
  u32 dscp;
  u32 protocol_config;
  u32 type;
  u32 ep_weight;
  u32 traffic_state;

} ppf_gtpu_tunnel_t;



#define foreach_ppf_gtpu_input_next        \
_(DROP, "error-drop")                  \
_(L2_INPUT, "l2-input")                \
_(IP4_INPUT,  "ip4-input")             \
_(IP6_INPUT, "ip6-input" )             \
_(GTPLO, "gtplo" )			   \
_(PPF_GTP4_ENCAP, "ppf_gtpu4-encap" )		   \
_(PPF_PDCP_INPUT, "ppf_pdcp_input" )		   \
_(PPF_SB_PATH_LB, "ppf_sb_path_lb" )


typedef enum
{
#define _(s,n) PPF_GTPU_INPUT_NEXT_##s,
  foreach_ppf_gtpu_input_next
#undef _
    PPF_GTPU_INPUT_N_NEXT,
} ppf_gtpu_input_next_t;

typedef enum
{
#define ppf_gtpu_error(n,s) PPF_GTPU_ERROR_##n,
#include <ppfu/ppf_gtpu_error.def>
#undef ppf_gtpu_error
  PPF_GTPU_N_ERROR,
} ppf_gtpu_input_error_t;

#define foreach_ppf_gtpu_encap_next        \
_(DROP, "error-drop")                  \
_(IP4_LOOKUP, "ip4-lookup")             \
_(IP6_LOOKUP, "ip6-lookup")

typedef enum
{
  PPF_GTPU_ENCAP_NEXT_DROP,
  PPF_GTPU_ENCAP_NEXT_IP4_LOOKUP,
  PPF_GTPU_ENCAP_NEXT_IP6_LOOKUP,
  PPF_GTPU_ENCAP_N_NEXT,
} ppf_gtpu_encap_next_t;

typedef struct
{
  /* vector of encap tunnel instances */
  ppf_gtpu_tunnel_t *tunnels;

  /* lookup tunnel by key */
  uword *ppf_gtpu4_tunnel_by_key;	/* keyed on teid */
  uword *ppf_gtpu6_tunnel_by_key;	/* keyed on ipv6.dst + teid */

  uword *ppf_gtpu4_tunnel_by_callid_dir;	/*key on callid + dir */

  /* local VTEP IPs ref count used by ppf_gtpu-bypass node to check if
     received ppf_gtpu packet DIP matches any local VTEP address */
  uword *vtep4;			/* local ip4 VTEPs keyed on their ip4 addr */
  uword *vtep6;			/* local ip6 VTEPs keyed on their ip6 addr */

  /* mcast shared info */
  uword *mcast_shared;		/* keyed on mcast ip46 addr */

  /* Free vlib hw_if_indices */
  u32 *free_ppf_gtpu_tunnel_hw_if_indices;

  /* Mapping from sw_if_index to tunnel index */
  u32 *calline_index_by_sw_if_index;

  /**
   * Node type for registering to fib changes.
   */
  fib_node_type_t fib_node_type;

  /* API message ID base */
  u16 msg_id_base;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* for pre-allocate, by Jordy */
  ip46_address_t src;
  ip46_address_t dst;
  u32 prealloc_tunnels;
  u32 start_teid;
} ppf_gtpu_main_t;

extern ppf_gtpu_main_t ppf_gtpu_main;

extern vlib_node_registration_t ppf_gtpu4_input_node;
extern vlib_node_registration_t ppf_gtpu6_input_node;
extern vlib_node_registration_t ppf_gtpu4_encap_node;
extern vlib_node_registration_t ppf_gtpu6_encap_node;
extern vlib_node_registration_t worker_ppfu_handoff_node;

u8 *format_ppf_gtpu_encap_trace (u8 * s, va_list * args);

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
  u32 sb_id;
  u32 dst_port;
  u32 dscp;
  u32 protocol_config;
  u32 ep_weight;
  u32 traffic_state;
  u32 type;
} vnet_ppf_gtpu_add_del_tunnel_args_t;

#if 0
int vnet_ppf_gtpu_add_del_tunnel
  (vnet_ppf_gtpu_add_del_tunnel_args_t * a, u32 * sw_if_indexp);
#endif

int vnet_ppf_gtpu_add_tunnel
  (vnet_ppf_gtpu_add_del_tunnel_args_t * a, u32 * sw_if_indexp,
   u32 * tunnel_id_ret);

int vnet_ppf_gtpu_update_tunnel
  (u32 tunnel_id, vnet_ppf_gtpu_add_del_tunnel_args_t * a);

int vnet_ppf_gtpu_del_tunnel (u32 tunnel_id);

int vnet_ppf_gtpu_add_tunnel_in_call
  (vnet_ppf_gtpu_add_del_tunnel_args_t * a, u32 * sw_if_indexp,
   u32 * tunnel_id_ret);

int vnet_ppf_gtpu_del_tunnel_in_call
  (vnet_ppf_gtpu_add_del_tunnel_args_t * a);

void vnet_int_ppf_gtpu_bypass_mode (u32 sw_if_index, u8 is_ip6, u8 is_enable);

u8 *format_ppf_gtpu_tunnel (u8 * s, va_list * args);


#endif /* included_vnet_ppf_gtpu_h */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
