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

#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <ppfu/ppfu.h>
#include <ppfu/ppf_gtpu.h>


#define __plugin_msg_base ppfu_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>


uword unformat_ip46_address (unformat_input_t * input, va_list * args)
{
  ip46_address_t *ip46 = va_arg (*args, ip46_address_t *);
  ip46_type_t type = va_arg (*args, ip46_type_t);
  if ((type != IP46_TYPE_IP6) &&
      unformat(input, "%U", unformat_ip4_address, &ip46->ip4)) {
    ip46_address_mask_ip4(ip46);
    return 1;
  } else if ((type != IP46_TYPE_IP4) &&
      unformat(input, "%U", unformat_ip6_address, &ip46->ip6)) {
    return 1;
  }
  return 0;
}
uword unformat_ip46_prefix (unformat_input_t * input, va_list * args)
{
  ip46_address_t *ip46 = va_arg (*args, ip46_address_t *);
  u8 *len = va_arg (*args, u8 *);
  ip46_type_t type = va_arg (*args, ip46_type_t);

  u32 l;
  if ((type != IP46_TYPE_IP6) && unformat(input, "%U/%u", unformat_ip4_address, &ip46->ip4, &l)) {
    if (l > 32)
      return 0;
    *len = l + 96;
    ip46->pad[0] = ip46->pad[1] = ip46->pad[2] = 0;
  } else if ((type != IP46_TYPE_IP4) && unformat(input, "%U/%u", unformat_ip6_address, &ip46->ip6, &l)) {
    if (l > 128)
      return 0;
    *len = l;
  } else {
    return 0;
  }
  return 1;
}
/////////////////////////

#define vl_msg_id(n,h) n,
typedef enum {
#include <ppfu/ppfu.api.h>
    /* We'll want to know how many messages IDs we need... */
    VL_MSG_FIRST_AVAILABLE,
} vl_msg_id_t;
#undef vl_msg_id

/* define message structures */
#define vl_typedefs
#include <ppfu/ppfu.api.h>
#undef vl_typedefs

/* declare message handlers for each api */

#define vl_endianfun             /* define message structures */
#include <ppfu/ppfu.api.h>
#undef vl_endianfun

/* instantiate all the print functions we know about */
#define vl_print(handle, ...)
#define vl_printfun
#include <ppfu/ppfu.api.h>
#undef vl_printfun

/* Get the API version number. */
#define vl_api_version(n,v) static u32 api_version=(v);
#include <ppfu/ppfu.api.h>
#undef vl_api_version

typedef struct {
    /* API message ID base */
    u16 msg_id_base;
    vat_main_t *vat_main;
} ppfu_test_main_t;

ppfu_test_main_t ppfu_test_main;

static void vl_api_ppfu_plugin_bearer_install_reply_t_handler
  (vl_api_ppfu_plugin_bearer_install_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);
  if (vam->async_mode)
    {
      vam->async_errors += (retval < 0);
    }
  else
    {
      vam->retval = retval;
      vam->result_ready = 1;
    }
}

 static void vl_api_ppfu_plugin_bearer_update_reply_t_handler
  (vl_api_ppfu_plugin_bearer_update_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);
  if (vam->async_mode)
    {
      vam->async_errors += (retval < 0);
    }
  else
    {
      vam->retval = retval;
      vam->result_ready = 1;
    }
}

 static void vl_api_ppfu_plugin_bearer_release_reply_t_handler
  (vl_api_ppfu_plugin_bearer_release_reply_t * mp)
{
  vat_main_t *vam = &vat_main;
  i32 retval = ntohl (mp->retval);
  if (vam->async_mode)
    {
      vam->async_errors += (retval < 0);
    }
  else
    {
      vam->retval = retval;
      vam->result_ready = 1;
    }
}

#define _(n)                                            \
    static void vl_api_##n##_t_handler                  \
    (vl_api_##n##_t * mp)                               \
    {                                                   \
        vat_main_t * vam = ppfu_test_main.vat_main;   \
        i32 retval = ntohl(mp->retval);                 \
        if (vam->async_mode) {                          \
            vam->async_errors += (retval < 0);          \
        } else {                                        \
            vam->retval = retval;                       \
            vam->result_ready = 1;                      \
        }                                               \
    }
#undef _

/*
 * Table of message reply handlers, must include boilerplate handlers
 * we just generated
 */

#define foreach_vpe_api_reply_msg                               \
  _(PPFU_PLUGIN_BEARER_INSTALL_REPLY, ppfu_plugin_bearer_install_reply)               \
  _(PPFU_PLUGIN_BEARER_UPDATE_REPLY, ppfu_plugin_bearer_update_reply)               \
  _(PPFU_PLUGIN_BEARER_RELEASE_REPLY, ppfu_plugin_bearer_release_reply)

static int
api_ppfu_plugin_bearer_install (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_ppfu_plugin_bearer_install_t *mp;
  
  u32 call_id, ue_bearer_id, sb_policy = 0, transaction_id;

  ip46_address_t nb_src, nb_dst;
  u32 nb_encap_vrf_id = 0, nb_out_teid = 0, nb_port = 0, nb_dscp = 0, nb_type = 0, nb_protocol_configuration = 0; 

  ip46_address_t sb0_src, sb0_pri_dst, sb0_sec_dst;
  u32 sb0_pri_out_teid = 0, sb0_pri_port = 0, sb0_pri_dscp = 0;
  u32 sb0_sec_out_teid = 0, sb0_sec_port = 0, sb0_sec_dscp = 0;
  u32 sb0_encap_vrf_id = 0,  sb0_protocol_configuration = 0, sb0_ep_weight = 0, sb0_traffic_state = 0;
  
  ip46_address_t sb1_src, sb1_pri_dst, sb1_sec_dst;
  u32 sb1_pri_out_teid = 0, sb1_pri_port = 0, sb1_pri_dscp = 0;
  u32 sb1_sec_out_teid = 0, sb1_sec_port = 0, sb1_sec_dscp = 0;
  u32 sb1_encap_vrf_id = 0, sb1_protocol_configuration = 0, sb1_ep_weight = 0, sb1_traffic_state = 0;

  ip46_address_t sb2_src, sb2_pri_dst, sb2_sec_dst;
  u32 sb2_pri_out_teid = 0, sb2_pri_port = 0, sb2_pri_dscp = 0;
  u32 sb2_sec_out_teid = 0, sb2_sec_port = 0, sb2_sec_dscp = 0;
  u32 sb2_encap_vrf_id =0, sb2_protocol_configuration =0, sb2_ep_weight = 0, sb2_traffic_state =0;


  u32 nb_set = 0, sb0_set = 0, sb1_set = 0, sb2_set = 0;

  vl_api_nb_path_context_t *nb;
  vl_api_sb_path_context_t *sb;
  
  int ret = 0;

  /* Can't "universally zero init" (={0}) due to GCC bug 53119 */
  memset (&nb_src, 0, sizeof nb_dst);
  memset (&nb_dst, 0, sizeof nb_dst);
  memset (&sb0_src, 0, sizeof sb0_src);
  memset (&sb0_pri_dst, 0, sizeof sb0_pri_dst);
  memset (&sb0_sec_dst, 0, sizeof sb0_sec_dst);
  memset (&sb1_src, 0, sizeof sb1_src);
  memset (&sb1_pri_dst, 0, sizeof sb1_pri_dst);
  memset (&sb1_sec_dst, 0, sizeof sb1_sec_dst);
  memset (&sb2_src, 0, sizeof sb2_src);
  memset (&sb2_pri_dst, 0, sizeof sb2_pri_dst);
  memset (&sb2_sec_dst, 0, sizeof sb2_sec_dst);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {

	if (unformat (line_input, "call_id %d", &call_id))
	;
	else if (unformat (line_input, "ue_bearer_id %d", &ue_bearer_id))
	;
	else if (unformat (line_input, "sb_policy %d", &sb_policy))
	;
	else if (unformat (line_input, "transaction_id %d", &transaction_id))
	;
      else if (unformat (line_input, "nb_src_ip_address %U", unformat_ip4_address, &nb_src.ip4))
      {
		nb_set =1;
      }
	else if (unformat (line_input, "nb_dst_ip_address %U", unformat_ip4_address, &nb_dst.ip4))
	;
	else if (unformat (line_input, "nb_encap_vrf_id %d", &nb_encap_vrf_id))
	;
	else if (unformat (line_input, "nb_out_teid %d", &nb_out_teid))
	;
	else if (unformat (line_input, "nb_port %d", &nb_port))
	;
	else if (unformat (line_input, "nb_dscp %d", &nb_dscp))
	;
	else if (unformat (line_input, "nb_type %d", &nb_type))
	;
	else if (unformat (line_input, "nb_protocol_configuration %d", &nb_protocol_configuration))
	;	
	else if (unformat (line_input, "sb0_src_ip_address %U", unformat_ip4_address, &sb0_src.ip4))
      {
		sb0_set =1;
      }
	else if (unformat (line_input, "sb0_encap_vrf_id %d", &sb0_encap_vrf_id))
	;
	else if (unformat (line_input, "sb0_pri_dst_ip_address %U", unformat_ip4_address, &sb0_pri_dst.ip4))
	;
	else if (unformat (line_input, "sb0_pri_out_teid %d", &sb0_pri_out_teid))
	;
	else if (unformat (line_input, "sb0_pri_port %d", &sb0_pri_port))
	;
	else if (unformat (line_input, "sb0_pri_dscp %d", &sb0_pri_dscp))
	;
	else if (unformat (line_input, "sb0_sec_dst_ip_address %U", unformat_ip4_address, &sb0_sec_dst.ip4))
	;
	else if (unformat (line_input, "sb0_sec_out_teid %d", &sb0_sec_out_teid))
	;
	else if (unformat (line_input, "sb0_sec_port %d", &sb0_sec_port))
	;
	else if (unformat (line_input, "sb0_sec_dscp %d", &sb0_sec_dscp))
	;
	else if (unformat (line_input, "sb0_protocol_configuration %d", &sb0_protocol_configuration))
	;
	else if (unformat (line_input, "sb0_ep_weight %d", &sb0_ep_weight))
	;
	else if (unformat (line_input, "sb0_traffic_state %d", &sb0_traffic_state))
	;	
	else if (unformat (line_input, "sb1_src_ip_address %U", unformat_ip4_address, &sb1_src.ip4))
      {
		sb1_set =1;
      }
	else if (unformat (line_input, "sb1_encap_vrf_id %d", &sb1_encap_vrf_id))
	;
	else if (unformat (line_input, "sb1_pri_dst_ip_address %U", unformat_ip4_address, &sb1_pri_dst.ip4))
	;
	else if (unformat (line_input, "sb1_pri_out_teid %d", &sb1_pri_out_teid))
	;
	else if (unformat (line_input, "sb1_pri_port %d", &sb1_pri_port))
	;
	else if (unformat (line_input, "sb1_pri_dscp %d", &sb1_pri_dscp))
	;
	else if (unformat (line_input, "sb1_sec_dst_ip_address %U", unformat_ip4_address, &sb1_sec_dst.ip4))
	;
	else if (unformat (line_input, "sb1_sec_out_teid %d", &sb1_sec_out_teid))
	;
	else if (unformat (line_input, "sb1_sec_port %d", &sb1_sec_port))
	;
	else if (unformat (line_input, "sb1_sec_dscp %d", &sb1_sec_dscp))
	;
	else if (unformat (line_input, "sb1_protocol_configuration %d", &sb1_protocol_configuration))
	;
	else if (unformat (line_input, "sb1_ep_weight %d", &sb1_ep_weight))
	;
	else if (unformat (line_input, "sb1_traffic_state %d", &sb1_traffic_state))
	;
	else if (unformat (line_input, "sb2_src_ip_address %U", unformat_ip4_address, &sb2_src.ip4))
      {
		sb2_set =1;
      }
	else if (unformat (line_input, "sb2_encap_vrf_id %d", &sb2_encap_vrf_id))
	;
	else if (unformat (line_input, "sb2_pri_dst_ip_address %U", unformat_ip4_address, &sb2_pri_dst.ip4))
	;
	else if (unformat (line_input, "sb2_pri_out_teid %d", &sb2_pri_out_teid))
	;
	else if (unformat (line_input, "sb2_pri_port %d", &sb2_pri_port))
	;
	else if (unformat (line_input, "sb2_pri_dscp %d", &sb2_pri_dscp))
	;
	else if (unformat (line_input, "sb2_sec_dst_ip_address %U", unformat_ip4_address, &sb2_sec_dst.ip4))
	;
	else if (unformat (line_input, "sb2_sec_out_teid %d", &sb2_sec_out_teid))
	;
	else if (unformat (line_input, "sb2_sec_port %d", &sb2_sec_port))
	;
	else if (unformat (line_input, "sb2_sec_dscp %d", &sb2_sec_dscp))
	;
	else if (unformat (line_input, "sb2_protocol_configuration %d", &sb2_protocol_configuration))
	;
	else if (unformat (line_input, "sb2_ep_weight %d", &sb2_ep_weight))
	;
	else if (unformat (line_input, "sb2_traffic_state %d", &sb2_traffic_state))
	;
	else
	{
		errmsg ("parse error '%U'", format_unformat_error, line_input);
		return -99;
	}
    }


  M (PPFU_PLUGIN_BEARER_INSTALL, mp);

  mp->call_id = call_id;
  mp->ue_bearer_id = ue_bearer_id;
  mp->sb_policy = sb_policy;
  mp->transaction_id = transaction_id;

  if (nb_set != 0)
  {
    	nb = &(mp->nb);

    	clib_memcpy (nb->src_ip_address, &nb_src.ip4, sizeof (nb_src.ip4));
    	clib_memcpy (nb->dst_ip_address, &nb_dst.ip4, sizeof (nb_dst.ip4));
   	nb->encap_vrf_id = (nb_encap_vrf_id);
    	nb->out_teid = (nb_out_teid);
    	nb->port = (nb_port);
    	nb->dscp = (nb_dscp);
    	nb->type = (nb_type);
    	nb->protocol_configuration = (nb_protocol_configuration);

    } else {
    
  	memset (&(mp->nb), 0, sizeof (vl_api_nb_path_context_t));
   }
    
  if (sb0_set != 0) 
   {
      sb = &(mp->sb[0]);

      clib_memcpy (sb->src_ip_address, &sb0_src.ip4, sizeof (sb0_src.ip4));
    	clib_memcpy (sb->pri_ip_address, &sb0_pri_dst.ip4, sizeof (sb0_pri_dst.ip4));
    	clib_memcpy (sb->sec_ip_address, &sb0_sec_dst.ip4, sizeof (sb0_sec_dst.ip4));
    	sb->encap_vrf_id = (sb0_encap_vrf_id);
    	sb->pri_out_teid = (sb0_pri_out_teid);
    	sb->pri_port = (sb0_pri_port);
    	sb->pri_dscp = (sb0_pri_dscp);
    	sb->sec_out_teid = (sb0_sec_out_teid);
    	sb->sec_port = (sb0_sec_port);
    	sb->sec_dscp = (sb0_sec_dscp);
    	sb->protocol_configuration = (sb0_protocol_configuration);
    	sb->ep_weight = (sb0_ep_weight);
    	sb->traffic_state = (sb0_traffic_state); 	
	
    } else {
    
  	memset (&(mp->sb[0]), 0, sizeof (vl_api_sb_path_context_t));
   }

  if (sb1_set != 0) 
  {
      sb = &(mp->sb[1]);

      clib_memcpy (sb->src_ip_address, &sb1_src.ip4, sizeof (sb1_src.ip4));
    	clib_memcpy (sb->pri_ip_address, &sb1_pri_dst.ip4, sizeof (sb1_pri_dst.ip4));
    	clib_memcpy (sb->sec_ip_address, &sb1_sec_dst.ip4, sizeof (sb1_sec_dst.ip4));
    	sb->encap_vrf_id = (sb1_encap_vrf_id);
    	sb->pri_out_teid = (sb1_pri_out_teid);
    	sb->pri_port = (sb1_pri_port);
    	sb->pri_dscp = (sb1_pri_dscp);
    	sb->sec_out_teid = (sb1_sec_out_teid);
    	sb->sec_port = (sb1_sec_port);
    	sb->sec_dscp = (sb1_sec_dscp);
    	sb->protocol_configuration = (sb1_protocol_configuration);
    	sb->ep_weight = (sb1_ep_weight);
    	sb->traffic_state = (sb1_traffic_state); 	
	
    } else {
    
  	memset (&(mp->sb[1]), 0, sizeof (vl_api_sb_path_context_t));
   }

  if (sb2_set != 0) 
  {
      sb = &(mp->sb[2]);

      clib_memcpy (sb->src_ip_address, &sb2_src.ip4, sizeof (sb2_src.ip4));
    	clib_memcpy (sb->pri_ip_address, &sb2_pri_dst.ip4, sizeof (sb2_pri_dst.ip4));
    	clib_memcpy (sb->sec_ip_address, &sb2_sec_dst.ip4, sizeof (sb2_sec_dst.ip4));
    	sb->encap_vrf_id = (sb2_encap_vrf_id);
    	sb->pri_out_teid = (sb2_pri_out_teid);
    	sb->pri_port = (sb2_pri_port);
    	sb->pri_dscp = (sb2_pri_dscp);
    	sb->sec_out_teid = (sb2_sec_out_teid);
    	sb->sec_port = (sb2_sec_port);
    	sb->sec_dscp = (sb2_sec_dscp);
    	sb->protocol_configuration = (sb2_protocol_configuration);
    	sb->ep_weight = (sb2_ep_weight);
    	sb->traffic_state = (sb2_traffic_state); 	
	
    } else {
    
  	memset (&(mp->sb[2]), 0, sizeof (vl_api_sb_path_context_t));
   }

   memset (&(mp->entity), 0, sizeof (vl_api_pdcp_entity_t));
   memset (&(mp->secparam), 0, sizeof (vl_api_pdcpsecurity_parameters_t));

  S (mp);
  W (ret);
  return ret;
}


static int
api_ppfu_plugin_bearer_update (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_ppfu_plugin_bearer_update_t *mp;
  
  u32 call_id, ue_bearer_id, transaction_id;

  u32 sb_del[3] = {0};

  ip46_address_t sb0_src, sb0_pri_dst, sb0_sec_dst;
  u32 sb0_pri_out_teid = 0, sb0_pri_port = 0, sb0_pri_dscp = 0;
  u32 sb0_sec_out_teid = 0, sb0_sec_port = 0, sb0_sec_dscp = 0;
  u32 sb0_encap_vrf_id = 0,  sb0_protocol_configuration = 0, sb0_ep_weight = 0, sb0_traffic_state = 0;
  
  ip46_address_t sb1_src, sb1_pri_dst, sb1_sec_dst;
  u32 sb1_pri_out_teid = 0, sb1_pri_port = 0, sb1_pri_dscp = 0;
  u32 sb1_sec_out_teid = 0, sb1_sec_port = 0, sb1_sec_dscp = 0;
  u32 sb1_encap_vrf_id = 0, sb1_protocol_configuration = 0, sb1_ep_weight = 0, sb1_traffic_state = 0;

  ip46_address_t sb2_src, sb2_pri_dst, sb2_sec_dst;
  u32 sb2_pri_out_teid = 0, sb2_pri_port = 0, sb2_pri_dscp = 0;
  u32 sb2_sec_out_teid = 0, sb2_sec_port = 0, sb2_sec_dscp = 0;
  u32 sb2_encap_vrf_id =0, sb2_protocol_configuration =0, sb2_ep_weight = 0, sb2_traffic_state =0;

  int i;

  u32 sb0_set = 0, sb1_set = 0, sb2_set = 0;

  vl_api_sb_path_context_t *sb;
  
  int ret = 0;

  /* Can't "universally zero init" (={0}) due to GCC bug 53119 */
  memset (&sb0_src, 0, sizeof sb0_src);
  memset (&sb0_pri_dst, 0, sizeof sb0_pri_dst);
  memset (&sb0_sec_dst, 0, sizeof sb0_sec_dst);
  memset (&sb1_src, 0, sizeof sb1_src);
  memset (&sb1_pri_dst, 0, sizeof sb1_pri_dst);
  memset (&sb1_sec_dst, 0, sizeof sb1_sec_dst);
  memset (&sb2_src, 0, sizeof sb2_src);
  memset (&sb2_pri_dst, 0, sizeof sb2_pri_dst);
  memset (&sb2_sec_dst, 0, sizeof sb2_sec_dst);

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {

	if (unformat (line_input, "call_id %d", &call_id))
	;
	else if (unformat (line_input, "ue_bearer_id %d", &ue_bearer_id))
	;
	else if (unformat (line_input, "transaction_id %d", &transaction_id))
	;
	else if (unformat (line_input, "sb0_del %d", &sb_del[0]))
	;
	else if (unformat (line_input, "sb1_del %d", &sb_del[1]))
	;
	else if (unformat (line_input, "sb2_del %d", &sb_del[2]))
	;
	else if (unformat (line_input, "sb0_src_ip_address %U", unformat_ip4_address, &sb0_src.ip4))
	{
		sb0_set =1;
	}
	else if (unformat (line_input, "sb0_encap_vrf_id %d", &sb0_encap_vrf_id))
	;
	else if (unformat (line_input, "sb0_pri_dst_ip_address %U", unformat_ip4_address, &sb0_pri_dst.ip4))
	;
	else if (unformat (line_input, "sb0_pri_out_teid %d", &sb0_pri_out_teid))
	;
	else if (unformat (line_input, "sb0_pri_port %d", &sb0_pri_port))
	;
	else if (unformat (line_input, "sb0_pri_dscp %d", &sb0_pri_dscp))
	;
	else if (unformat (line_input, "sb0_sec_dst_ip_address %U", unformat_ip4_address, &sb0_sec_dst.ip4))
	;
	else if (unformat (line_input, "sb0_sec_out_teid %d", &sb0_sec_out_teid))
	;
	else if (unformat (line_input, "sb0_sec_port %d", &sb0_sec_port))
	;
	else if (unformat (line_input, "sb0_sec_dscp %d", &sb0_sec_dscp))
	;
	else if (unformat (line_input, "sb0_protocol_configuration %d", &sb0_protocol_configuration))
	;
	else if (unformat (line_input, "sb0_ep_weight %d", &sb0_ep_weight))
	;
	else if (unformat (line_input, "sb0_traffic_state %d", &sb0_traffic_state))
	;	
	else if (unformat (line_input, "sb1_src_ip_address %U", unformat_ip4_address, &sb1_src.ip4))
	{
		sb1_set =1;
	}
	else if (unformat (line_input, "sb1_encap_vrf_id %d", &sb1_encap_vrf_id))
	;
	else if (unformat (line_input, "sb1_pri_dst_ip_address %U", unformat_ip4_address, &sb1_pri_dst.ip4))
	;
	else if (unformat (line_input, "sb1_pri_out_teid %d", &sb1_pri_out_teid))
	;
	else if (unformat (line_input, "sb1_pri_port %d", &sb1_pri_port))
	;
	else if (unformat (line_input, "sb1_pri_dscp %d", &sb1_pri_dscp))
	;
	else if (unformat (line_input, "sb1_sec_dst_ip_address %U", unformat_ip4_address, &sb1_sec_dst.ip4))
	;
	else if (unformat (line_input, "sb1_sec_out_teid %d", &sb1_sec_out_teid))
	;
	else if (unformat (line_input, "sb1_sec_port %d", &sb1_sec_port))
	;
	else if (unformat (line_input, "sb1_sec_dscp %d", &sb1_sec_dscp))
	;
	else if (unformat (line_input, "sb1_protocol_configuration %d", &sb1_protocol_configuration))
	;
	else if (unformat (line_input, "sb1_ep_weight %d", &sb1_ep_weight))
	;
	else if (unformat (line_input, "sb1_traffic_state %d", &sb1_traffic_state))
	;
	else if (unformat (line_input, "sb2_src_ip_address %U", unformat_ip4_address, &sb2_src.ip4))
	{
		sb2_set =1;
	}
	else if (unformat (line_input, "sb2_encap_vrf_id %d", &sb2_encap_vrf_id))
	;
	else if (unformat (line_input, "sb2_pri_dst_ip_address %U", unformat_ip4_address, &sb2_pri_dst.ip4))
	;
	else if (unformat (line_input, "sb2_pri_out_teid %d", &sb2_pri_out_teid))
	;
	else if (unformat (line_input, "sb2_pri_port %d", &sb2_pri_port))
	;
	else if (unformat (line_input, "sb2_pri_dscp %d", &sb2_pri_dscp))
	;
	else if (unformat (line_input, "sb2_sec_dst_ip_address %U", unformat_ip4_address, &sb2_sec_dst.ip4))
	;
	else if (unformat (line_input, "sb2_sec_out_teid %d", &sb2_sec_out_teid))
	;
	else if (unformat (line_input, "sb2_sec_port %d", &sb2_sec_port))
	;
	else if (unformat (line_input, "sb2_sec_dscp %d", &sb2_sec_dscp))
	;
	else if (unformat (line_input, "sb2_protocol_configuration %d", &sb2_protocol_configuration))
	;
	else if (unformat (line_input, "sb2_ep_weight %d", &sb2_ep_weight))
	;
	else if (unformat (line_input, "sb2_traffic_state %d", &sb2_traffic_state))
	;
	else
	{
		errmsg ("parse error '%U'", format_unformat_error, line_input);
		return -99;
	}
    }

  M (PPFU_PLUGIN_BEARER_UPDATE, mp);

  mp->call_id = call_id;
  mp->ue_bearer_id = ue_bearer_id;
  mp->transaction_id = transaction_id;

  for (i = 0; i < MAX_SB_PER_CALL; i ++) {

	memset (&(mp->sb[i]), 0, sizeof (vl_api_sb_path_context_t));
	if (sb_del[i] == 1) 
		mp->removal_sb_id[i] = 1;
	else 	
		mp->removal_sb_id[i] = 0;
  }

  if (sb0_set != 0) 
  {

	sb = &(mp->sb[0]);

	clib_memcpy (sb->src_ip_address, &sb0_src.ip4, sizeof (sb0_src.ip4));
	clib_memcpy (sb->pri_ip_address, &sb0_pri_dst.ip4, sizeof (sb0_pri_dst.ip4));
	clib_memcpy (sb->sec_ip_address, &sb0_sec_dst.ip4, sizeof (sb0_sec_dst.ip4));
	sb->encap_vrf_id = (sb0_encap_vrf_id);
	sb->pri_out_teid = (sb0_pri_out_teid);
	sb->pri_port = (sb0_pri_port);
	sb->pri_dscp = (sb0_pri_dscp);
	sb->sec_out_teid = (sb0_sec_out_teid);
	sb->sec_port = (sb0_sec_port);
	sb->sec_dscp = (sb0_sec_dscp);
	sb->protocol_configuration = (sb0_protocol_configuration);
	sb->ep_weight = (sb0_ep_weight);
	sb->traffic_state = (sb0_traffic_state);	
	
    }

  if (sb1_set != 0) 
  {
	sb = &(mp->sb[1]);

	clib_memcpy (sb->src_ip_address, &sb1_src.ip4, sizeof (sb1_src.ip4));
	clib_memcpy (sb->pri_ip_address, &sb1_pri_dst.ip4, sizeof (sb1_pri_dst.ip4));
	clib_memcpy (sb->sec_ip_address, &sb1_sec_dst.ip4, sizeof (sb1_sec_dst.ip4));
	sb->encap_vrf_id = (sb1_encap_vrf_id);
	sb->pri_out_teid = (sb1_pri_out_teid);
	sb->pri_port = (sb1_pri_port);
	sb->pri_dscp = (sb1_pri_dscp);
	sb->sec_out_teid = (sb1_sec_out_teid);
	sb->sec_port = (sb1_sec_port);
	sb->sec_dscp = (sb1_sec_dscp);
	sb->protocol_configuration = (sb1_protocol_configuration);
	sb->ep_weight = (sb1_ep_weight);
	sb->traffic_state = (sb1_traffic_state);	
	
    } 

  if (sb2_set != 0) 
  {
	sb = &(mp->sb[2]);

	clib_memcpy (sb->src_ip_address, &sb2_src.ip4, sizeof (sb2_src.ip4));
	clib_memcpy (sb->pri_ip_address, &sb2_pri_dst.ip4, sizeof (sb2_pri_dst.ip4));
	clib_memcpy (sb->sec_ip_address, &sb2_sec_dst.ip4, sizeof (sb2_sec_dst.ip4));
	sb->encap_vrf_id = (sb2_encap_vrf_id);
	sb->pri_out_teid = (sb2_pri_out_teid);
	sb->pri_port = (sb2_pri_port);
	sb->pri_dscp = (sb2_pri_dscp);
	sb->sec_out_teid = (sb2_sec_out_teid);
	sb->sec_port = (sb2_sec_port);
	sb->sec_dscp = (sb2_sec_dscp);
	sb->protocol_configuration = (sb2_protocol_configuration);
	sb->ep_weight = (sb2_ep_weight);
	sb->traffic_state = (sb2_traffic_state);	
	
    } 
    
  S (mp);
  W (ret);
  return ret;
}


static int
api_ppfu_plugin_bearer_release (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_ppfu_plugin_bearer_release_t *mp;
  
  u32 call_id, ue_bearer_id, transaction_id;

  int ret = 0;

  /* Can't "universally zero init" (={0}) due to GCC bug 53119 */
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {

	if (unformat (line_input, "call_id %d", &call_id))
	;
	else if (unformat (line_input, "ue_bearer_id %d", &ue_bearer_id))
	;
	else if (unformat (line_input, "transaction_id %d", &transaction_id))
	;
	else
	{
		errmsg ("parse error '%U'", format_unformat_error, line_input);
		return -99;
	}
    }

  M (PPFU_PLUGIN_BEARER_RELEASE, mp);

  mp->call_id = call_id;
  mp->ue_bearer_id = ue_bearer_id;
  mp->transaction_id = transaction_id;

  S (mp);
  W (ret);
  return ret;
}


/*
 * List of messages that the api test plugin sends,
 * and that the data plane plugin processes
 */
 
#define foreach_vpe_api_msg                                            	\
_(ppfu_plugin_bearer_install,                                          	\
        "call_id <nn> |ue_bearer_id <nn> |transaction_id <nn> \n"      	\
        "[nb_src_ip_address <ip-addr>] [nb_dst_ip_address <ip-addr>] [nb_encap_vrf_id <nn> ] [nb_out_teid <nn>] \n"         \
	  "[nb_port <nn>] [nb_dscp <nn>] [nb_type <nn>] [nb_protocol_configuration <nn>] \n"        \
	  "[sb0_src_ip_address <ip-addr>] [sb0_encap_vrf_id <nn> \n"						  \
        "[sb0_pri_dst_ip_address <ip-addr>] [sb0_pri_out_teid <nn>] [sb0_pri_port <nn>] [sb0_pri_dscp <nn>] \n"     \
        "[sb0_sec_dst_ip_address <ip-addr>] [sb0_sec_out_teid <nn>] [sb0_sec_port <nn>] [sb0_sec_dscp <nn>] \n"    \
        "[sb0_traffic_state <nn>] [sb0_ep_weight <nn>] [sb0_protocol_configuration <nn>] \n"   \
        "[sb1_src_ip_address <ip-addr>] [sb1_encap_vrf_id <nn>] \n"						  \
        "[sb1_pri_dst_ip_address <ip-addr>] [sb1_pri_out_teid <nn>] [sb1_pri_port <nn>] [sb1_pri_dscp <nn>] \n"     \
        "[sb1_sec_dst_ip_address <ip-addr>] [sb1_sec_out_teid <nn>] [sb1_sec_port <nn>] [sb1_sec_dscp <nn>] \n"    \
        "[sb1_traffic_state <nn>] [sb1_ep_weight <nn>] [sb1_protocol_configuration <nn>] \n"   \
        "[sb2_src_ip_address <ip-addr>] [sb2_encap_vrf_id <nn>] \n"						  \
        "[sb2_pri_dst_ip_address <ip-addr>] [sb2_pri_out_teid <nn>] [sb2_pri_port <nn>] [sb2_pri_dscp <nn>] \n"     \
        "[sb2_sec_dst_ip_address <ip-addr>] [sb2_sec_out_teid <nn>] [sb2_sec_port <nn>] [sb2_sec_dscp <nn>] \n"    \
        "[sb2_traffic_state <nn>] [sb2_ep_weight <nn>] [sb2_protocol_configuration <nn>] ")    \
_(ppfu_plugin_bearer_update,                                           	\
	"call_id <nn> |ue_bearer_id <nn> |transaction_id <nn> \n"	    \
	"[sb0_src_ip_address <ip-addr>] [sb0_encap_vrf_id <nn> \n"							\
	"[sb0_pri_dst_ip_address <ip-addr>] [sb0_pri_out_teid <nn>] [sb0_pri_port <nn>] [sb0_pri_dscp <nn>] \n"	\
	"[sb0_sec_dst_ip_address <ip-addr>] [sb0_sec_out_teid <nn>] [sb0_sec_port <nn>] [sb0_sec_dscp <nn>] \n"    \
	"[sb0_traffic_state <nn>] [sb0_ep_weight <nn>] [sb0_protocol_configuration <nn>] \n"   \
	"[sb1_src_ip_address <ip-addr>] [sb1_encap_vrf_id <nn>] \n" 						\
	"[sb1_pri_dst_ip_address <ip-addr>] [sb1_pri_out_teid <nn>] [sb1_pri_port <nn>] [sb1_pri_dscp <nn>] \n"	\
	"[sb1_sec_dst_ip_address <ip-addr>] [sb1_sec_out_teid <nn>] [sb1_sec_port <nn>] [sb1_sec_dscp <nn>] \n"    \
	"[sb1_traffic_state <nn>] [sb1_ep_weight <nn>] [sb1_protocol_configuration <nn>] \n"   \
	"[sb2_src_ip_address <ip-addr>] [sb2_encap_vrf_id <nn>] \n" 						\
	"[sb2_pri_dst_ip_address <ip-addr>] [sb2_pri_out_teid <nn>] [sb2_pri_port <nn>] [sb2_pri_dscp <nn>] \n"	\
	"[sb2_sec_dst_ip_address <ip-addr>] [sb2_sec_out_teid <nn>] [sb2_sec_port <nn>] [sb2_sec_dscp <nn>] \n"    \
	"[sb2_traffic_state <nn>] [sb2_ep_weight <nn>] [sb2_protocol_configuration <nn>] ")    \
_(ppfu_plugin_bearer_release,								  	\
	"call_id <nn> |ue_bearer_id <nn> |transaction_id <nn> \n")	   



static void
ppfu_vat_api_hookup (vat_main_t *vam)
{
  ppfu_test_main_t * gtm = &ppfu_test_main;
  /* Hook up handlers for replies from the data plane plug-in */
#define _(N,n)                                                  \
  vl_msg_api_set_handlers((VL_API_##N + gtm->msg_id_base),       \
                          #n,                                   \
                          vl_api_##n##_t_handler,               \
                          vl_noop_handler,                      \
                          vl_api_##n##_t_endian,                \
                          vl_api_##n##_t_print,                 \
                          sizeof(vl_api_##n##_t), 1);
  foreach_vpe_api_reply_msg;
#undef _

  /* API messages we can send */
#define _(n,h) hash_set_mem (vam->function_by_name, #n, api_##n);
  foreach_vpe_api_msg;
#undef _

  /* Help strings */
#define _(n,h) hash_set_mem (vam->help_by_name, #n, h);
  foreach_vpe_api_msg;
#undef _
}

clib_error_t * vat_plugin_register (vat_main_t *vam)
{
  ppfu_test_main_t * gtm = &ppfu_test_main;

  u8 * name;

  gtm->vat_main = vam;

  /* Ask the vpp engine for the first assigned message-id */
  name = format (0, "ppfu_%08x%c", api_version, 0);
  gtm->msg_id_base = vl_client_get_first_plugin_msg_id ((char *) name);

  if (gtm->msg_id_base != (u16) ~0)
    ppfu_vat_api_hookup (vam);

  vec_free(name);

  return 0;
}
