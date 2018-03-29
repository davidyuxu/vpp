/*
 *------------------------------------------------------------------
 * ppfu_api.c - ppfu api
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
 *------------------------------------------------------------------
 */

#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>

#include <vppinfra/byte_order.h>
#include <vlibmemory/api.h>
#include <ppfu/ppfu.h>
#include <ppfu/ppf_gtpu.h>


#define vl_msg_id(n,h) n,
typedef enum
{
#include <ppfu/ppfu.api.h>
  /* We'll want to know how many messages IDs we need... */
  VL_MSG_FIRST_AVAILABLE,
} vl_msg_id_t;
#undef vl_msg_id

/* define message structures */
#define vl_typedefs
#include <ppfu/ppfu.api.h>
#include <vnet/ip/ip.api.h>
#undef vl_typedefs

/* define generated endian-swappers */
#define vl_endianfun
#include <ppfu/ppfu.api.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)
#define vl_printfun
#include <ppfu/ppfu.api.h>
#undef vl_printfun

/* Get the API version number */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <ppfu/ppfu.api.h>
#undef vl_api_version

#define vl_msg_name_crc_list
#include <ppfu/ppfu.api.h>
#undef vl_msg_name_crc_list

#define REPLY_MSG_ID_BASE ppfm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
setup_message_id_table (ppf_main_t * gtm, api_main_t * am)
{
#define _(id,n,crc) \
  vl_msg_api_add_msg_name_crc (am, #n "_" #crc, id + gtm->msg_id_base);
  foreach_vl_msg_name_crc_ppfu;
#undef _
}

#define foreach_ppfu_plugin_api_msg                             			\
_(PPFU_PLUGIN_GET_VERSION, ppfu_plugin_get_version)   				\
_(PPFU_PLUGIN_BEARER_INSTALL, ppfu_plugin_bearer_install) 	\
_(PPFU_PLUGIN_BEARER_UPDATE, ppfu_plugin_bearer_update) 	\
_(PPFU_PLUGIN_BEARER_RELEASE, ppfu_plugin_bearer_release)		\
_(PPFU_PLUGIN_SYSTEM_RESET, ppfu_plugin_system_reset)			


static void
vl_api_ppfu_plugin_get_version_t_handler 
(vl_api_ppfu_plugin_get_version_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;
}


static void
vl_api_ppfu_plugin_bearer_install_t_handler 
(vl_api_ppfu_plugin_bearer_install_t * mp)
{
  vl_api_ppfu_plugin_bearer_install_reply_t *rmp;
  int rv = 0;
  ppf_main_t *ppfm = &ppf_main;
  ip4_main_t *im = &ip4_main;
  ppf_callline_t *callline = NULL;
  vl_api_nb_path_context_t *nb;
  vl_api_sb_path_context_t *sb;
  ppf_gtpu_tunnel_type_t tunnel_type;
  u32 nb_in_teid, sb_in_teid[MAX_SB_PER_DRB];
  u32 result;
  int i = 0;
  
  if (mp->call_id >= ppfm->max_capacity)
  {
	rv = VNET_API_ERROR_WRONG_MAX_SESSION_NUM;
      result = 1; 
	goto out;
  }
  
  callline = &(ppfm->ppf_calline_table[mp->call_id]);

  if (callline->valid == 0) 
  {
	rv = VNET_API_ERROR_CALLINE_IN_USE;
	result = 1; 
	goto out;
  }

  nb = &(mp->nb);

  if (nb->src_ip_address != 0)
  	callline->call_type = PPF_DRB_CALL;
  else 
  	callline->call_type = PPF_SRB_CALL;

  if (callline->call_type == PPF_DRB_CALL)
  {
	  uword *p = hash_get (im->fib_index_by_table_id, ntohl (nb->encap_vrf_id));
	  if (!p)
	  {
		rv = VNET_API_ERROR_NO_SUCH_FIB;
		result = 1; 
		goto out;
	  }

	  tunnel_type = PPF_GTPU_NB;
	  nb_in_teid = ntohl(mp->ue_bearer_id);

	  vnet_ppf_gtpu_add_del_tunnel_args_t a = {
	    .is_add = 1,
	    .is_ip6 = 0,
	    .mcast_sw_if_index = 0,
	    .encap_fib_index = nb->encap_vrf_id,
	    .decap_next_index = 0,
	    .in_teid = nb_in_teid,
	    .out_teid = ntohl (nb->out_teid),
	    .dst = to_ip46 (0, nb->dst_ip_address),
	    .src = to_ip46 (0, nb->src_ip_address),
	    .call_id = mp->call_id,
	    .tunnel_type = tunnel_type,
	    .sb_id = 0,
	    .dst_port = nb->port,
	    .dscp = nb->dscp,
	    .protocol_config = nb->protocol_configuration,
	  };

	  /* Check src & dst are different */
	  if (ip46_address_cmp (&a.dst, &a.src) == 0)
	    {
		rv = VNET_API_ERROR_SAME_SRC_DST;
		result = 1; 
		goto out;
	    }

	  u32 sw_if_index = ~0;
	  rv = vnet_ppf_gtpu_add_del_tunnel (&a, &sw_if_index);

  }

  for (i = 0; i<= MAX_SB_PER_DRB; i++)
  {
  	  sb = &(mp->sb[i]);

  	  if (sb->src_ip_address != 0) {
  	  	sb_in_teid[i] = 0;
		break;
	  }
	    
	  uword *p = hash_get (im->fib_index_by_table_id, ntohl (sb->encap_vrf_id));
	  if (!p)
	  {
		rv = VNET_API_ERROR_NO_SUCH_FIB;
		result = 1; 
		goto out;
	  }

        if (callline->call_type == PPF_DRB_CALL)
	  	tunnel_type = PPF_GTPU_SB;
	  else 
	  	tunnel_type = PPF_GTPU_SRB;
	  	
	  sb_in_teid[i] = ntohl( (i << 30) |mp->ue_bearer_id);

	  vnet_ppf_gtpu_add_del_tunnel_args_t a = {
	    .is_add = 1,
	    .is_ip6 = 0,
	    .mcast_sw_if_index = 0,
	    .encap_fib_index = sb->encap_vrf_id,
	    .decap_next_index = 0,
	    .in_teid = sb_in_teid[i],
	    .out_teid = ntohl (sb->pri_out_teid),
	    .dst = to_ip46 (0, sb->pri_ip_address),
	    .src = to_ip46 (0, sb->src_ip_address),
	    .call_id = mp->call_id,
	    .tunnel_type = tunnel_type,
	    .sb_id = i,
	    .dst_port = sb->pri_port,
	    .dscp = sb->pri_dscp,
	    .protocol_config = sb->protocol_configuration,
	    .ep_weight = sb->ep_weight,
	    .traffic_state = sb->traffic_state,
	  };

	  /* Check src & dst are different */
	  if (ip46_address_cmp (&a.dst, &a.src) == 0)
	    {
		rv = VNET_API_ERROR_SAME_SRC_DST;
		goto out;
	    }

	  u32 sw_if_index = ~0;
	  rv = vnet_ppf_gtpu_add_del_tunnel (&a, &sw_if_index);
  }

  callline->valid = 1;
  callline->call_index = mp->call_id;

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_PPFU_PLUGIN_BEARER_INSTALL_REPLY,
  ({  

     for (i = 0; i<=MAX_SB_PER_DRB; i++) {
     	rmp->sb_in_teid[i] = sb_in_teid[i];
     }
      rmp->nb_in_teid = nb_in_teid;
      rmp->msg_result = result;
  }));

  /* *INDENT-ON* */
}


static void
vl_api_ppfu_plugin_bearer_update_t_handler 
(vl_api_ppfu_plugin_bearer_update_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;
}

static void
vl_api_ppfu_plugin_bearer_release_t_handler 
(vl_api_ppfu_plugin_bearer_release_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;
}

static void
vl_api_ppfu_plugin_system_reset_t_handler 
(vl_api_ppfu_plugin_system_reset_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;
}


#if 0
static void
  vl_api_ppfu_plugin_get_version_t_handler
  (vl_api_sw_interface_set_ppf_gtpu_bypass_t * mp)
{
  vl_api_sw_interface_set_ppf_gtpu_bypass_reply_t *rmp;
  int rv = 0;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  ppf_gtpu_main_t *gtm = &ppf_gtpu_main;

  VALIDATE_SW_IF_INDEX (mp);

  vnet_int_ppf_gtpu_bypass_mode (sw_if_index, mp->is_ipv6, mp->enable);
  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_SW_INTERFACE_SET_PPF_GTPU_BYPASS_REPLY);
}

static void vl_api_ppf_gtpu_add_del_tunnel_t_handler
  (vl_api_ppf_gtpu_add_del_tunnel_t * mp)
{
  vl_api_ppf_gtpu_add_del_tunnel_reply_t *rmp;
  int rv = 0;
  ip4_main_t *im = &ip4_main;
  ppf_gtpu_main_t *gtm = &ppf_gtpu_main;

  uword *p = hash_get (im->fib_index_by_table_id, ntohl (mp->encap_vrf_id));
  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto out;
    }

  vnet_ppf_gtpu_add_del_tunnel_args_t a = {
    .is_add = mp->is_add,
    .is_ip6 = mp->is_ipv6,
    .mcast_sw_if_index = ntohl (mp->mcast_sw_if_index),
    .encap_fib_index = p[0],
    .decap_next_index = ntohl (mp->decap_next_index),
    .in_teid = ntohl (mp->in_teid),
    .out_teid = ntohl (mp->out_teid),
    .dst = to_ip46 (mp->is_ipv6, mp->dst_address),
    .src = to_ip46 (mp->is_ipv6, mp->src_address),
    .call_id = 0,
    .tunnel_type = 0,
    .sb_id = 0,
  };

  /* Check src & dst are different */
  if (ip46_address_cmp (&a.dst, &a.src) == 0)
    {
      rv = VNET_API_ERROR_SAME_SRC_DST;
      goto out;
    }
  if (ip46_address_is_multicast (&a.dst) &&
      !vnet_sw_if_index_is_api_valid (a.mcast_sw_if_index))
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto out;
    }

  u32 sw_if_index = ~0;
  rv = vnet_ppf_gtpu_add_del_tunnel (&a, &sw_if_index);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_PPF_GTPU_ADD_DEL_TUNNEL_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
  /* *INDENT-ON* */
}

extern int ip4_add_del_route_t_handler (vl_api_ip_add_del_route_t * mp);
extern int ip6_add_del_route_t_handler (vl_api_ip_add_del_route_t * mp);

static int
vl_api_ppf_gtpu_add_del_route (vl_api_ip_add_del_route_t * mp)
{
//  vl_api_ip_add_del_route_reply_t *rmp;
  int rv;
  vnet_main_t *vnm = vnet_get_main ();

  vnm->api_errno = 0;

  if (mp->is_ipv6)
    rv = ip6_add_del_route_t_handler (mp);
  else
    rv = ip4_add_del_route_t_handler (mp);

  rv = (rv == 0) ? vnm->api_errno : rv;

  return rv;
}


/*Added by brant */
static void vl_api_ppf_gtpu_add_del_tunnel_v2_t_handler
  (vl_api_ppf_gtpu_add_del_tunnel_v2_t * mp)
{
  vl_api_ppf_gtpu_add_del_tunnel_v2_reply_t *rmp;
  int rv = 0;
  ip4_main_t *im = &ip4_main;
  ppf_gtpu_main_t *gtm = &ppf_gtpu_main;

  uword *p = hash_get (im->fib_index_by_table_id, ntohl (mp->encap_vrf_id));
  if (!p)
    {
      rv = VNET_API_ERROR_NO_SUCH_FIB;
      goto out;
    }

  vnet_ppf_gtpu_add_del_tunnel_args_t a = {
    .is_add = mp->is_add,
    .is_ip6 = mp->is_ipv6,
    .mcast_sw_if_index = ntohl (mp->mcast_sw_if_index),
    .encap_fib_index = p[0],
    .decap_next_index = ntohl (mp->decap_next_index),
    .in_teid = ntohl (mp->in_teid),
    .out_teid = ntohl (mp->out_teid),   
    .dst = to_ip46 (mp->is_ipv6, mp->dst_address),
    .src = to_ip46 (mp->is_ipv6, mp->src_address),
    .call_id = 0,
    .tunnel_type = 0,
    .sb_id = 0,
  };

  /* Check src & dst are different */
  if (ip46_address_cmp (&a.dst, &a.src) == 0)
    {
      rv = VNET_API_ERROR_SAME_SRC_DST;
      goto out;
    }
  if (ip46_address_is_multicast (&a.dst) &&
      !vnet_sw_if_index_is_api_valid (a.mcast_sw_if_index))
    {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
      goto out;
    }

  u32 sw_if_index = ~0;

	rv = vnet_ppf_gtpu_add_del_tunnel (&a, &sw_if_index);
	if (rv != 0) {
		goto out;
	}

	
	vl_api_ip_add_del_route_t r;
    memset (&r, 0, sizeof(r));
    r.client_index = mp->client_index;
    r.context = mp->context;
	r.is_add = mp->is_add;
	r.table_id = mp->table_id;
	r.classify_table_index = mp->classify_table_index;
	r.next_hop_table_id = mp->next_hop_table_id;
	r.next_hop_id = mp->next_hop_id;
	r.is_drop = mp->is_drop;
	r.is_unreach = mp->is_unreach;
	r.is_prohibit = mp->is_prohibit;
	r.is_ipv6 = mp->is_ipv6;
	r.is_local = mp->is_local;
	r.is_classify = mp->is_classify;
	r.is_multipath = mp->is_multipath;
	r.is_resolve_host = mp->is_resolve_host;
	r.is_resolve_attached = mp->is_resolve_attached;

	r.is_source_lookup = mp->is_source_lookup;
	r.is_udp_encap = mp->is_udp_encap;
	r.next_hop_weight = mp->next_hop_weight;
	r.next_hop_preference = mp->next_hop_preference;
	r.next_hop_proto = mp->next_hop_proto;
	r.dst_address_length = mp->dst_address_length;
	memcpy (r.dst_address, mp->dst_address_r, sizeof(r.dst_address));
	memcpy (r.next_hop_address, mp->next_hop_address, sizeof(r.next_hop_address));
	r.next_hop_n_out_labels = mp->next_hop_n_out_labels;
	r.next_hop_via_label  = mp->next_hop_via_label;
	memcpy (r.next_hop_out_label_stack, mp->next_hop_out_label_stack, sizeof(r.next_hop_out_label_stack));
	r.next_hop_sw_if_index = htonl(sw_if_index);
	
	rv = vl_api_ppf_gtpu_add_del_route(&r);

out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_PPF_GTPU_ADD_DEL_TUNNEL_V2_REPLY,
  ({
    rmp->sw_if_index = ntohl (sw_if_index);
  }));
  /* *INDENT-ON* */
}


static void send_ppf_gtpu_tunnel_details
  (ppf_gtpu_tunnel_t * t, vl_api_registration_t * reg, u32 context)
{
  vl_api_ppf_gtpu_tunnel_details_t *rmp;
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  u8 is_ipv6 = !ip46_address_is_ip4 (&t->dst);

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = ntohs (VL_API_PPF_GTPU_TUNNEL_DETAILS);
  if (is_ipv6)
    {
      memcpy (rmp->src_address, t->src.ip6.as_u8, 16);
      memcpy (rmp->dst_address, t->dst.ip6.as_u8, 16);
      rmp->encap_vrf_id = htonl (im6->fibs[t->encap_fib_index].ft_table_id);
    }
  else
    {
      memcpy (rmp->src_address, t->src.ip4.as_u8, 4);
      memcpy (rmp->dst_address, t->dst.ip4.as_u8, 4);
      rmp->encap_vrf_id = htonl (im4->fibs[t->encap_fib_index].ft_table_id);
    }
  rmp->mcast_sw_if_index = htonl (t->mcast_sw_if_index);
  rmp->in_teid = htonl (t->in_teid);
  rmp->out_teid = htonl (t->out_teid);
  rmp->decap_next_index = htonl (t->decap_next_index);
  rmp->sw_if_index = htonl (t->sw_if_index);
  rmp->is_ipv6 = is_ipv6;
  rmp->context = context;

  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_ppf_gtpu_tunnel_dump_t_handler (vl_api_ppf_gtpu_tunnel_dump_t * mp)
{
  vl_api_registration_t *reg;
  ppf_gtpu_main_t *gtm = &ppf_gtpu_main;
  ppf_gtpu_tunnel_t *t;
  u32 sw_if_index;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  sw_if_index = ntohl (mp->sw_if_index);

  if (~0 == sw_if_index)
    {
      /* *INDENT-OFF* */
      pool_foreach (t, gtm->tunnels,
      ({
        send_ppf_gtpu_tunnel_details(t, reg, mp->context);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      if ((sw_if_index >= vec_len (gtm->tunnel_index_by_sw_if_index)) ||
	  (~0 == gtm->tunnel_index_by_sw_if_index[sw_if_index]))
	{
	  return;
	}
      t = &gtm->tunnels[gtm->tunnel_index_by_sw_if_index[sw_if_index]];
      send_ppf_gtpu_tunnel_details (t, reg, mp->context);
    }
}

#endif 

static clib_error_t *
ppfu_api_hookup (vlib_main_t * vm)
{
  ppf_main_t *pm = &ppf_main;

  u8 *name = format (0, "ppfu_%08x%c", api_version, 0);
  pm->msg_id_base = vl_msg_api_get_msg_ids
    ((char *) name, VL_MSG_FIRST_AVAILABLE);

#define _(N,n)                                                  \
    vl_msg_api_set_handlers((VL_API_##N + pm->msg_id_base),     \
                           #n,                  \
                           vl_api_##n##_t_handler,              \
                           vl_noop_handler,                     \
                           vl_api_##n##_t_endian,               \
                           vl_api_##n##_t_print,                \
                           sizeof(vl_api_##n##_t), 1);
  foreach_ppfu_plugin_api_msg;
#undef _

  /* Add our API messages to the global name_crc hash table */
  setup_message_id_table (pm, &api_main);

  return 0;
}

VLIB_API_INIT_FUNCTION (ppfu_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
