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

  vl_api_nb_path_context_t *nb;
  vl_api_sb_path_context_t *sb;

  ppf_callline_t *callline = NULL;
  ppf_gtpu_tunnel_type_t tunnel_type;
  u32 nb_tunnel_added = 0, sb_tunnel_added[MAX_SB_PER_CALL] = {0};         //mark which tunnel has been added
  u32 nb_in_teid = 0, sb_in_teid[MAX_SB_PER_CALL] = {0};	     //mark return teid
  u32 nb_tunnel_id, sb_tunnel_id[MAX_SB_PER_CALL] = {0};
  u32 sw_if_index = ~0;
  u32 tunnel_id = ~0;

  int i = 0;

  if (mp->call_id >= ppfm->max_capacity)
  {
	rv = VNET_API_ERROR_WRONG_MAX_SESSION_NUM;
	goto out;
  }
  
  callline = &(ppfm->ppf_calline_table[mp->call_id]);

  if (callline->call_index != ~0) 
  {
	rv = VNET_API_ERROR_CALLLNE_IN_USE;
	goto out;
  }

  nb = &(mp->nb);

  // the source ip of nb is 0, means the nb is invalid, the call is SRB
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
		goto out;
	  }

	  tunnel_type = PPF_GTPU_NB;
	  nb_in_teid = ntohl(mp->ue_bearer_id);
  
	  vnet_ppf_gtpu_add_del_tunnel_args_t nb_tunnel = {
	    .is_ip6 = 0,
	    .mcast_sw_if_index = 0,		//to be delete	    
	    .decap_next_index = 0,		//to be delete
	    .encap_fib_index = nb->encap_vrf_id,
	    .in_teid = nb_in_teid,
	    .out_teid = ntohl (nb->out_teid),
	    .dst = to_ip46 (0, nb->dst_ip_address),
	    .src = to_ip46 (0, nb->src_ip_address),
	    .call_id = mp->call_id,
	    .tunnel_type = tunnel_type,
	    .sb_id = 0,				//only valid for sb
	    .dst_port = nb->port,
	    .dscp = nb->dscp,
	    .protocol_config = nb->protocol_configuration,
	    .type = nb->type,
	  };

	  /* Check src & dst are different */
	  if (ip46_address_cmp (&nb_tunnel.dst, &nb_tunnel.src) == 0)
	    {
		rv = VNET_API_ERROR_SAME_SRC_DST;
		goto out;
	    }

	  sw_if_index = ~0;
	  tunnel_id = ~0;
	  rv = vnet_ppf_gtpu_add_tunnel (&nb_tunnel, &sw_if_index, &tunnel_id);

	  if (rv == 0) {
	  	nb_tunnel_added = 1;
	  	nb_tunnel_id = tunnel_id;
	  } else {
	  	goto out;
	  }

  }

  for (i = 0; i<= MAX_SB_PER_CALL; i++)
  {
  	  sb = &(mp->sb[i]);

  	  if (sb->src_ip_address == 0) 
		continue;

	  uword *p = hash_get (im->fib_index_by_table_id, ntohl (sb->encap_vrf_id));
	  if (!p)
	  {
		rv = VNET_API_ERROR_NO_SUCH_FIB;
		goto out;
	  }

        if (callline->call_type == PPF_DRB_CALL)
	  	tunnel_type = PPF_GTPU_SB;
	  else 
	  	tunnel_type = PPF_GTPU_SRB;
	  	
	  sb_in_teid [i] = ((i + 1) << 30) |ntohl(mp->ue_bearer_id);

	  vnet_ppf_gtpu_add_del_tunnel_args_t sb_tunnel = {
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
	  if (ip46_address_cmp (&(sb_tunnel.dst), &(sb_tunnel.src)) == 0)
	    {
		rv = VNET_API_ERROR_SAME_SRC_DST;
		goto out;
	    }

	  sw_if_index = ~0;
	  tunnel_id = ~0;
	  rv = vnet_ppf_gtpu_add_tunnel (&(sb_tunnel), &sw_if_index, &tunnel_id);
	
	  if (rv == 0) {
	  	sb_tunnel_added[i] = 1;
	  	sb_tunnel_id[i] = tunnel_id;
	  	
	  } else {
	  	goto out;
	  }
	  
  }

  /* Create pdcp session */
  callline->pdcp.session_id = ppf_pdcp_create_session (12, 0, 0, 0);

  callline->sb_policy = mp->sb_policy;
  callline->ue_bearer_id = mp->ue_bearer_id;
  callline->call_index = mp->call_id;

  
out:
  /* *INDENT-OFF* */
  if (rv != 0) {
  	if (nb_tunnel_added == 1) {
	    vnet_ppf_gtpu_del_tunnel (nb_tunnel_id);
	    nb_tunnel_added = 0;
	}

	nb_in_teid = 0;

 	for (i = 0; i<= MAX_SB_PER_CALL; i++) {
 	    if (sb_tunnel_added[i] == 1) {
 	    	vnet_ppf_gtpu_del_tunnel (sb_tunnel_id[i]);
 	      sb_tunnel_added[i] = 0;
 	    }
 	    
 	    sb_in_teid[i] = 0;
 	} 		
  }
  
  REPLY_MACRO2(VL_API_PPFU_PLUGIN_BEARER_INSTALL_REPLY,
  ({  

     for (i = 0; i<=MAX_SB_PER_CALL; i++) {
     	rmp->sb_in_teid[i] = sb_in_teid[i];
     }
      rmp->nb_in_teid = nb_in_teid;
      rmp->call_id = mp->call_id;
      rmp->ue_bearer_id = mp->ue_bearer_id;
      rmp->transaction_id = mp->transaction_id;
  
  }));

  /* *INDENT-ON* */
}


static void
vl_api_ppfu_plugin_bearer_update_t_handler 
 (vl_api_ppfu_plugin_bearer_update_t * mp)
{
  vl_api_ppfu_plugin_bearer_update_reply_t *rmp;
  int rv = 0;
  ppf_main_t *ppfm = &ppf_main;
  ppf_gtpu_main_t *gtm = &ppf_gtpu_main;
  ip4_main_t *im = &ip4_main;

  vl_api_sb_path_context_t *sb;
    
  ppf_callline_t *callline = NULL;
  ppf_gtpu_tunnel_type_t tunnel_type;
  ppf_gtpu_tunnel_id_type_t *sb_key;
  u32 sw_if_index = ~0;
  u32 tunnel_id = ~0;
  u32 sb_in_teid[MAX_SB_PER_CALL];
  u32 sb_tunnel_added[MAX_SB_PER_CALL]={0};
  u32 sb_tunnel_id[MAX_SB_PER_CALL] = {0};
  ppf_gtpu_tunnel_t *t = NULL;

  int i = 0;

  if (mp->call_id >= ppfm->max_capacity)
  {
	rv = VNET_API_ERROR_WRONG_MAX_SESSION_NUM;
	goto out;
  }
  
  callline = &(ppfm->ppf_calline_table[mp->call_id]);

  if (callline->call_index == ~0) 
  {
	rv = VNET_API_ERROR_EMPTY_CALLINE;
	goto out;
  }

  //first, remove sbs 
  for (i = 0; i<= MAX_SB_PER_CALL; i++) 
  {
	if (callline->call_type == PPF_DRB_CALL)
	    sb_key = &(callline->rb.drb.sb_tunnel[i]);
	else 
	    sb_key = &(callline->rb.srb.sb_tunnel[i]);

	if (sb_key->tunnel_id != INVALID_TUNNEL_ID)  {

		if (mp->removal_sb_id[i] != 0) {

		  rv = vnet_ppf_gtpu_del_tunnel (sb_key->tunnel_id);
		  
		} else {
		  t = &(gtm->tunnels[sb_key->tunnel_id]);
		  
		  sb_in_teid[i] = t->in_teid;
		}
	}	  
  }

  //second, update or add sbs
  //To be done: how to rollback if updated failded in progress??
  for (i = 0; i<= MAX_SB_PER_CALL; i++)
  {
	  sb = &(mp->sb[i]);

	  if (sb->src_ip_address == 0) 
		continue;

	  uword *p = hash_get (im->fib_index_by_table_id, ntohl (sb->encap_vrf_id));
	  if (!p)
	  {
		rv = VNET_API_ERROR_NO_SUCH_FIB;
		goto out;
	  }

	  if (callline->call_type == PPF_DRB_CALL)
	    sb_key = &(callline->rb.drb.sb_tunnel[i]);
	  else 
	    sb_key = &(callline->rb.srb.sb_tunnel[i]);
	    
	  if (sb_key->tunnel_id != INVALID_TUNNEL_ID) {
	  
	  	//update sb_tunnel
		vnet_ppf_gtpu_add_del_tunnel_args_t sb_tunnel = {
		    .out_teid = ntohl (sb->pri_out_teid),
		    .dst = to_ip46 (0, sb->pri_ip_address),
		    .dst_port = sb->pri_port,
		    .dscp = sb->pri_dscp,
		    .protocol_config = sb->protocol_configuration,
		    .ep_weight = sb->ep_weight,
		    .traffic_state = sb->traffic_state,
		    .type = ~0,
		  };

	    rv = vnet_ppf_gtpu_update_tunnel (sb_key->tunnel_id, &(sb_tunnel));

	    if (rv != 0)
	    	goto out;

	 } else {

		//add sb_tunnel
		  if (callline->call_type == PPF_DRB_CALL)
			tunnel_type = PPF_GTPU_SB;
		  else 
			tunnel_type = PPF_GTPU_SRB;
			
		  sb_in_teid [i] = ((i + 1) << 30) |ntohl(mp->ue_bearer_id);

		  vnet_ppf_gtpu_add_del_tunnel_args_t sb_tunnel = {
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
		  if (ip46_address_cmp (&(sb_tunnel.dst), &(sb_tunnel.src)) == 0)
		    {
			rv = VNET_API_ERROR_SAME_SRC_DST;
			goto out;
		    }

		  sw_if_index = ~0;
		  tunnel_id = ~0;
		  rv = vnet_ppf_gtpu_add_tunnel (&(sb_tunnel), &sw_if_index, &tunnel_id);
		  
		  if (rv == 0) {
			sb_tunnel_added[i] = 1;
			sb_tunnel_id[i] = tunnel_id;
		  } else 
		  	goto out;

	  }
	  
  }

out:
  /* *INDENT-OFF* */
  if (rv != 0) {
	for (i = 0; i<= MAX_SB_PER_CALL; i++) {
	    if (sb_tunnel_added[i] != 0) {
	    	vnet_ppf_gtpu_del_tunnel (sb_tunnel_id[i]);
	    	sb_tunnel_added[i] = 0;
	    }
	    sb_in_teid[i] = 0;
	}
  }
  
  REPLY_MACRO2(VL_API_PPFU_PLUGIN_BEARER_INSTALL_REPLY,
  ({	

     for (i = 0; i<=MAX_SB_PER_CALL; i++) {
	rmp->sb_in_teid[i] = sb_in_teid[i];
     }
	rmp->call_id = mp->call_id;
	rmp->ue_bearer_id = mp->ue_bearer_id;
	rmp->transaction_id = mp->transaction_id;
  
  }));

  /* *INDENT-ON* */
}


static void
vl_api_ppfu_plugin_bearer_release_t_handler 
(vl_api_ppfu_plugin_bearer_release_t * mp)
{
  vl_api_ppfu_plugin_bearer_release_reply_t *rmp;
  int rv = 0;
  ppf_main_t *ppfm = &ppf_main;
  ppf_callline_t *callline = NULL;
  ppf_pdcp_session_t *pdcp_sess = NULL;
  int i = 0;
  ppf_gtpu_tunnel_id_type_t *nb_tunnel, *sb_tunnel[MAX_SB_PER_CALL];

  if (mp->call_id >= ppfm->max_capacity)
  {
	rv = VNET_API_ERROR_WRONG_MAX_SESSION_NUM;
	goto out;
  }
  
  callline = &(ppfm->ppf_calline_table[mp->call_id]);

  if (callline->call_index == ~0) 
  {
	rv = VNET_API_ERROR_EMPTY_CALLINE;
	goto out;
  }

  if (callline->call_type == PPF_DRB_CALL)
  {
	  nb_tunnel = &(callline->rb.drb.nb_tunnel);

	  rv = vnet_ppf_gtpu_del_tunnel (nb_tunnel->tunnel_id);

	  if (rv != 0)
	  	goto out;

  }

  for (i = 0; i<= MAX_SB_PER_CALL; i++)
  {

	  if (callline->call_type == PPF_DRB_CALL)
		sb_tunnel[i] = &(callline->rb.drb.sb_tunnel[i]);
	  else 
		sb_tunnel[i] = &(callline->rb.srb.sb_tunnel[i]);

        if (sb_tunnel[i]->tunnel_id != ~0) {	  
	  	rv = vnet_ppf_gtpu_del_tunnel (sb_tunnel[i]->tunnel_id);
	  	
	  	if (rv != 0)
	  		goto out;
	  }
	  
  }

  callline->pdcp.session_id = ~0;

  /* Clear pdcp session */
  ppf_pdcp_clear_session (pdcp_sess);

  if (callline->call_type == PPF_SRB_CALL)
  	hash_free(callline->rb.srb.nb_out_msg_by_sn);

  callline->ue_bearer_id = ~0;
  callline->call_index = ~0;
  
out:
  /* *INDENT-OFF* */
  REPLY_MACRO2(VL_API_PPFU_PLUGIN_BEARER_RELEASE_REPLY,
  ({	

	rmp->call_id = mp->call_id;
	rmp->ue_bearer_id = mp->ue_bearer_id;
	rmp->transaction_id = mp->transaction_id;
  
  }));

  /* *INDENT-ON* */
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
