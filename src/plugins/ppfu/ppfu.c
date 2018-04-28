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
#include <ppfu/ppf_gtpu.h>

ppf_main_t ppf_main;

static u8 *
format_ppf_gtpu_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "ppf_gtpu_calline%d", dev_instance);
}

static clib_error_t *
ppf_gtpu_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  u32 hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
    VNET_HW_INTERFACE_FLAG_LINK_UP : 0;
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

  return /* no error */ 0;
}

static u8 *
format_ppf_gtpu_header_with_length (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  s = format (s, "unimplemented dev %u", dev_instance);
  return s;
}

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS (ppf_gtpu_hw_class) =
{
  .name = "PPF_GTPU",
  .format_header = format_ppf_gtpu_header_with_length,
  .build_rewrite = default_build_rewrite,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};
/* *INDENT-ON* */


/* *INDENT-OFF* */
VNET_DEVICE_CLASS (ppf_gtpu_device_class,static) = {
  .name = "PPF_GTPU",
  .format_device_name = format_ppf_gtpu_name,
  .format_tx_trace = format_ppf_gtpu_encap_trace,
  .admin_up_down_function = ppf_gtpu_interface_admin_up_down,
};
/* *INDENT-ON* */


static uword
unformat_ppf_call_type (unformat_input_t * input, va_list * args)
{
  u32 *result = va_arg (*args, u32 *);
  
  if (unformat (input, "srb"))
    *result = PPF_SRB_CALL;
  else if (unformat (input, "drb"))
    *result = PPF_DRB_CALL;
  else
  	return 0;

  return 1;
}

static uword
unformat_ppf_call_mode (unformat_input_t * input, va_list * args)
{
  u32 *result = va_arg (*args, u32 *);
  
  if (unformat (input, "tunnel-switch"))
    *result = PPF_TUNNEL_MODE;
  else if (unformat (input, "lbo"))
    *result = PPF_LBO_MODE;
  else
     return 0;

  return 1;
}

void ppf_reset_callline_intf (u32 call_id)
{
	ppf_main_t *pm = &ppf_main;	
	ppf_gtpu_main_t *gtm = &ppf_gtpu_main;
  	vnet_main_t *vnm = gtm->vnet_main;

	ppf_callline_t *call_line = 0;

	call_line = &(pm->ppf_calline_table [call_id]);

	if ((call_line->lbo_mode == PPF_LBO_MODE) && (call_line->sw_if_index != ~0))  
	{
	      vnet_sw_interface_set_flags (vnm, call_line->sw_if_index, 0 /* down */ );
	      vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, call_line->sw_if_index);
	      si->flags |= VNET_SW_INTERFACE_FLAG_HIDDEN;

	      /* make sure tunnel is removed from l2 bd or xconnect */
	      set_int_l2_mode (gtm->vlib_main, vnm, MODE_L3, call_line->sw_if_index, 0, 0, 0,
			       0);
	      vec_add1 (gtm->free_ppf_gtpu_tunnel_hw_if_indices, call_line->hw_if_index);

	      gtm->calline_index_by_sw_if_index[call_line->sw_if_index] = ~0;

	      call_line->hw_if_index = ~0;
	      call_line->sw_if_index = ~0;
      }
}


void ppf_init_callline_intf (u32 call_id)
{
	ppf_main_t *pm = &ppf_main;	
	ppf_gtpu_main_t *gtm = &ppf_gtpu_main;
	u32 hw_if_index = ~0;
  	u32 sw_if_index = ~0;	
  	vnet_main_t *vnm = gtm->vnet_main;

	ppf_callline_t *call_line = 0;

	call_line = &(pm->ppf_calline_table [call_id]);

	 if (call_line->lbo_mode == PPF_LBO_MODE) 
	  {
			  vnet_hw_interface_t *hi;
			  if (vec_len (gtm->free_ppf_gtpu_tunnel_hw_if_indices) > 0)
			  {
			    vnet_interface_main_t *im = &vnm->interface_main;
			    hw_if_index = gtm->free_ppf_gtpu_tunnel_hw_if_indices
				[vec_len (gtm->free_ppf_gtpu_tunnel_hw_if_indices) - 1];
			    _vec_len (gtm->free_ppf_gtpu_tunnel_hw_if_indices) -= 1;
	
			    hi = vnet_get_hw_interface (vnm, hw_if_index);
			    hi->dev_instance =call_line->call_index ;
			    hi->hw_instance = hi->dev_instance;
	
			    /* clear old stats of freed tunnel before reuse */
			    sw_if_index = hi->sw_if_index;
			    vnet_interface_counter_lock (im);
			    vlib_zero_combined_counter
				(&im->combined_sw_if_counters[VNET_INTERFACE_COUNTER_TX],
				 sw_if_index);
			    vlib_zero_combined_counter (&im->combined_sw_if_counters
							  [VNET_INTERFACE_COUNTER_RX],
							  sw_if_index);
			    vlib_zero_simple_counter (&im->sw_if_counters
							[VNET_INTERFACE_COUNTER_DROP],
							sw_if_index);
			    vnet_interface_counter_unlock (im);
			  }
			  else
			  {
			    hw_if_index = vnet_register_interface
				(vnm, ppf_gtpu_device_class.index, call_line->call_index,
				 ppf_gtpu_hw_class.index, call_line->call_index);
			    hi = vnet_get_hw_interface (vnm, hw_if_index);
			  }
	
			  u32 encap_index = ppf_sb_path_lb_node.index;
			  vnet_set_interface_output_node (vnm, hw_if_index, encap_index);
	
			  call_line->hw_if_index = hw_if_index;
			  call_line->sw_if_index = sw_if_index = hi->sw_if_index;
	
			  vec_validate_init_empty (gtm->calline_index_by_sw_if_index, sw_if_index,
						   ~0);
			  gtm->calline_index_by_sw_if_index[sw_if_index] = call_line->call_index;
	
			  vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
			  si->flags &= ~VNET_SW_INTERFACE_FLAG_HIDDEN;
			  vnet_sw_interface_set_flags (vnm, sw_if_index,
						     VNET_SW_INTERFACE_FLAG_ADMIN_UP);	

			  call_line->sw_if_index = sw_if_index;
		  	  call_line->hw_if_index = hw_if_index;

	  } else {
		  call_line->sw_if_index = ~0;
		  call_line->hw_if_index = ~0;
	  }

}


int vnet_ppf_del_callline (u32 call_id)
{

	ppf_main_t *pm = &ppf_main;
	ppf_callline_t *call_line = 0;
	ppf_gtpu_tunnel_id_type_t *tunnel = 0;

	int i, rv;

	if (call_id >= pm->max_capacity) {
		return VNET_API_ERROR_WRONG_MAX_SESSION_NUM;
  	}

	call_line = &(pm->ppf_calline_table [call_id]);

	if (call_line->call_index == ~0) 
	{
		return 0;
	}

	if (call_line->call_type == PPF_DRB_CALL)
	{
	  tunnel = &(call_line->rb.drb.nb_tunnel);

	  if ((tunnel->tunnel_id) != INVALID_TUNNEL_ID) {
	  	rv = vnet_ppf_gtpu_del_tunnel (tunnel->tunnel_id); 
  	  	if (rv != 0)
  	  	{
  	  		// should print some error log, but the del will continue
  	  	}
	  }

	}

	for (i = 0; i<= MAX_SB_PER_CALL; i++)
	{

	  if (call_line->call_type == PPF_DRB_CALL)
		tunnel = &(call_line->rb.drb.sb_tunnel[i]);
	  else 
		tunnel = &(call_line->rb.srb.sb_tunnel[i]);

	  if (tunnel->tunnel_id != INVALID_TUNNEL_ID) {	  
	  	rv = vnet_ppf_gtpu_del_tunnel (tunnel->tunnel_id);	  	
	  	if (rv != 0)
	  	{
			// should print some error log, but the del will continue
	  	}
	  } else 
	  	continue;	  
	}	

	ppf_reset_calline (call_line->call_index);
	
	return 0;	
}

void ppf_reset_calline (u32 call_id) 
{

	ppf_main_t *pm = &ppf_main;
	ppf_pdcp_main_t *ppm = &ppf_pdcp_main;

	ppf_callline_t *call_line = 0;
	ppf_pdcp_session_t *pdcp_sess = 0;

	call_line = &(pm->ppf_calline_table [call_id]);
	
	if (call_line->call_type == PPF_DRB_CALL) {

		call_line->rb.drb.nb_tunnel.tunnel_id = ~0; 

		for (int j = 0; j < MAX_SB_PER_CALL; j++) {
		  	call_line->rb.drb.sb_tunnel[j].tunnel_id = ~0;
		}
	} else if (call_line->call_type == PPF_SRB_CALL) {

		call_line->rb.srb.nb_out_msg_by_sn = 0;
		for (int j = 0; j < MAX_SB_PER_CALL; j++) {
			call_line->rb.srb.sb_tunnel[j].tunnel_id = ~0;
		}

  		hash_free(call_line->rb.srb.nb_out_msg_by_sn);
	}

	if (call_line->pdcp.session_id != ~0) {
		pdcp_sess = &(ppm->sessions[call_line->pdcp.session_id]);
		/* Clear pdcp session */
	  	ppf_pdcp_clear_session (pdcp_sess);
	  	call_line->pdcp.session_id = ~0;
  	}
  	
	ppf_reset_callline_intf (call_line->call_index);

	call_line->ue_bearer_id = ~0;
	call_line->call_type = INVALID_CALL_TYPE;
	call_line->call_index = ~0;
}

void ppf_init_calline (u32 call_id, ppf_calline_type_t call_type) 
{
	ppf_main_t *pm = &ppf_main;

	ppf_callline_t *call_line = 0;

	call_line = &(pm->ppf_calline_table [call_id]);
	
	call_line->call_index = call_id;

	call_line->call_type = call_type;
	
	if (call_line->call_type == PPF_DRB_CALL) {

		call_line->rb.drb.nb_tunnel.tunnel_id = ~0; 

		for (int j = 0; j < MAX_SB_PER_CALL; j++) {
		  call_line->rb.drb.sb_tunnel[j].tunnel_id = ~0;
		}
	} else if (call_line->call_type == PPF_SRB_CALL) {

		call_line->rb.srb.nb_out_msg_by_sn = 0;
		for (int j = 0; j < MAX_SB_PER_CALL; j++) {
		call_line->rb.srb.sb_tunnel[j].tunnel_id = ~0;
		}
	}
	
	call_line->pdcp.session_id = ~0;
 	call_line->sb_policy = ~0;
	call_line->ue_bearer_id = ~0;	
}

int vnet_ppf_add_callline (vnet_ppf_add_callline_args_t *c)
{

	ppf_main_t *pm = &ppf_main;
	ppf_callline_t *call_line = 0;

	if (c->call_id >= pm->max_capacity) {
		return VNET_API_ERROR_WRONG_MAX_SESSION_NUM;
  	}

	call_line = &(pm->ppf_calline_table [c->call_id]);

	if (call_line->call_index != ~0) 
	{
		return VNET_API_ERROR_CALLLNE_IN_USE;
	}

	ppf_init_calline (c->call_id, c->call_type);
	
	call_line->sb_policy = c->sb_policy;
	call_line->ue_bearer_id = c->ue_bearer_id;
	call_line->lbo_mode = c->lbo_mode;

	ppf_init_callline_intf (call_line->call_index);
	
      return 0;
}


static clib_error_t *
ppf_add_del_calline_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_add = 1;
  u32 call_id = ~0, sb_policy = ~0, ue_bearer_id = ~0, lbo_mode = 0;
  ppf_calline_type_t call_type = INVALID_CALL_TYPE;
  int rv;
  clib_error_t *error = NULL;
  
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
	else if (unformat (line_input, "call-type %U", unformat_ppf_call_type, &call_type))
	;
	else if (unformat (line_input, "ue-bear-id %d", &ue_bearer_id))
	;
	else if (unformat (line_input, "sb_policy %d", &sb_policy))
	;
	else if (unformat (line_input, "mode %U", unformat_ppf_call_mode, &lbo_mode))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }
    
  if (call_id == ~0) 
   {
      error = clib_error_return (0, "call id not specified");
      goto done;
    }

  if (is_add == 1) {

  	if (ue_bearer_id == ~0) 
	{
		error = clib_error_return (0, "ue_bearer_id not specified");
		goto done;
	}
    
	if (is_add == 1 && call_type == ~0) 
	{
		error = clib_error_return (0, "call type not specified");
		goto done;
	}
  }

  vnet_ppf_add_callline_args_t c = {
  	.call_id = call_id,
  	.call_type = call_type,
  	.sb_policy = sb_policy,
  	.ue_bearer_id = ue_bearer_id,
  	.lbo_mode = lbo_mode,
  };

  if (is_add == 1) {

  	rv = vnet_ppf_add_callline (&c);
  }
  else 
  	rv = vnet_ppf_del_callline (call_id);

  switch (rv)
    {
    case 0:
      if (is_add)
	vlib_cli_output (vm, "[Call line added] call-id: %d ue-bear-id: %d, call_type: %d, sb_policy: %d", 
			 c.call_id, c.ue_bearer_id, c.call_type, c.ue_bearer_id);
      break;

    case VNET_API_ERROR_CALLLNE_IN_USE:
      error = clib_error_return (0, "call already exists...");
      goto done;

    case VNET_API_ERROR_WRONG_MAX_SESSION_NUM:
      error = clib_error_return (0, "wrong call id number");
      goto done;
 
     default:
      error = clib_error_return
	(0, "vnet_ppf_del_callline returned %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}


VLIB_CLI_COMMAND (create_ppf_calline_command, static) = {
  .path = "create ppf calline",
  .short_help =	  
  "create ppf callline call-id <nn> [ call-type <type-name>] [ue-bear-id <nn>] [sb_policy <nn>]"
  "[mode <tunnel-switch|lbo>] [lbo_vrf_id <nn>] [del]",
  .function = ppf_add_del_calline_command_fn,
};


clib_error_t *
ppf_init (vlib_main_t * vm)
{
  ppf_main_t *pm = &ppf_main;
  ppf_callline_t * callline;

  u32 i;
  
  if (pm->max_capacity == 0)
    pm->max_capacity = DEF_MAX_PPF_SESSION;

  pm->ppf_calline_table = clib_mem_alloc (pm->max_capacity * sizeof (ppf_callline_t));
  ASSERT(pm->ppf_calline_table != NULL);

  for (i = 0; i < pm->max_capacity; i++) {
    callline = &(pm->ppf_calline_table[i]);
    callline->call_index = ~0;

  }

  return 0;
}

VLIB_INIT_FUNCTION (ppf_init);

static clib_error_t *
ppf_config (vlib_main_t * vm, unformat_input_t * input)
{
  uword capacity = 0;

  ppf_sb_main.src = clib_host_to_net_u32(0x01010102);
  ppf_sb_main.dst = clib_host_to_net_u32(0x01010101);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "capacity %d", &capacity))
	;
      else if (unformat (input, "srb-src %U",
    		     unformat_ip4_address, &ppf_sb_main.src))
        {
        }
      else if (unformat (input, "srb-dst %U",
    		     unformat_ip4_address, &ppf_sb_main.dst))
        {
        }
      else
	return clib_error_return (0,
				  "invalid capacity parameter `%U'",
				  format_unformat_error, input);
    }

  ppf_main.max_capacity = capacity;

  return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (ppf_config, "ppf_config");

#define foreach_ppf_callline_type    \
_(PPF_SRB_CALL, "SRB")    \
_(PPF_DRB_CALL, "DRB")

static char * ppf_callline_type_strings[] = {
#define _(sym,string) string,
  foreach_ppf_callline_type
#undef _
};

#define foreach_ppf_gtpu_tunnel_type    \
_(PPF_GTPU_SB, "DRB-SB")      \
_(PPF_GTPU_NB, "DRB-NB")      \
_(PPF_GTPU_LBO, "DRB-LBO")    \
_(PPF_GTPU_SRB, "SRB-SB")     \
_(PPF_GTPU_NORMAL, "Normal")

static char * ppf_gtpu_tunnel_type_strings[] = {
#define _(sym,string) string,
  foreach_ppf_gtpu_tunnel_type
#undef _
};

u8 *
format_ppf_gtpu_tunnel_type (u8 * s, va_list * va)
{
  int type = va_arg (*va, int);
  if ((type < 0) || (type > PPF_GTPU_NORMAL))
    s = format (s, "invalid");
  else
    s = format (s, "%s", ppf_gtpu_tunnel_type_strings[type]);
  return s;
}

u8 *
format_ppf_gtpu_tunnel_simple (u8 * s, va_list * va)
{
  ppf_gtpu_tunnel_id_type_t *it = va_arg (*va, ppf_gtpu_tunnel_id_type_t *);
  int verbose = va_arg (*va, int);
  ppf_gtpu_tunnel_t * t = 0;
  ppf_gtpu_main_t * gtm = &ppf_gtpu_main;

  s = format (s, "id %d, type %U", it->tunnel_id, format_ppf_gtpu_tunnel_type, it->tunnel_type);
  if ((verbose > 0) && (~0 != it->tunnel_id)) {
    t = pool_elt_at_index (gtm->tunnels, it->tunnel_id);
    if (t) {
      s = format (s, "\ndetails %U\n", format_ppf_gtpu_tunnel, t);
    }
  }

  return s;
}

u8 *
format_ppf_pdcp_simple (u8 * s, va_list * va)
{
  ppf_pdcp_callline_t * pdcp = va_arg (*va, ppf_pdcp_callline_t *);
  int verbose = va_arg (*va, int);
  ppf_pdcp_session_t * pdcp_session = 0;
  ppf_pdcp_main_t * ppm = &ppf_pdcp_main;

  s = format (s, "sess-id %u", pdcp->session_id);
  if ((verbose > 0) && (~0 != pdcp->session_id)) {
    pdcp_session = pool_elt_at_index (ppm->sessions, pdcp->session_id);
    if (pdcp_session) {
      s = format (s, "\ndetails %U\n", format_ppf_pdcp_session, pdcp_session, verbose);
    }
  }

  return s;
}

u8 *
format_ppf_call_type (u8 * s, va_list * va)
{
  int type = va_arg (*va, int);
  if ((type < 0) || (type > PPF_DRB_CALL))
    s = format (s, "invalid");
  else
    s = format (s, "%s", ppf_callline_type_strings[type]);
  return s;
}

u8 *
format_ppf_callline (u8 * s, va_list * va)
{
  ppf_callline_t * callline = va_arg (*va, ppf_callline_t *);
  int verbose = va_arg (*va, int);
  u8 sb = 0;

  if (~0 == callline->call_index) {
    return s;
  }

  s = format (s, "[%d]type %U ub 0x%x sb-policy 0x%x ",
  	callline->call_index,
  	format_ppf_call_type, callline->call_type,
  	callline->ue_bearer_id, callline->sb_policy);

  if (PPF_SRB_CALL == callline->call_type) {    
    if (verbose > 0) {
      s = format (s, "\nnb msg hash: %U\n", format_hash, callline->rb.srb.nb_out_msg_by_sn, ((verbose > 2) ? 1 : 0));
      
      for (sb = 0; sb < MAX_SB_PER_CALL; sb++) {
        s = format (s, "\nsb tunnel %U\n", format_ppf_gtpu_tunnel_simple, &(callline->rb.srb.sb_tunnel[sb]), verbose);
      }
    } else {
      for (sb = 0; sb < MAX_SB_PER_CALL; sb++) {
  	s = format (s, "sb tunnel {%U} ", format_ppf_gtpu_tunnel_simple, &(callline->rb.srb.sb_tunnel[sb]), verbose);
      }      
    }
  } else {
    if (verbose > 0) {
      s = format (s, "\nnb tunnel %U\n", format_ppf_gtpu_tunnel_simple, &(callline->rb.drb.nb_tunnel), verbose);
      
      for (sb = 0; sb < MAX_SB_PER_CALL; sb++) {
        s = format (s, "\nsb tunnel %U\n", format_ppf_gtpu_tunnel_simple, &(callline->rb.drb.sb_tunnel[sb]), verbose);
      }    
    } else {
      s = format (s, "nb tunnel {%U}\n", format_ppf_gtpu_tunnel_simple, &(callline->rb.drb.nb_tunnel), verbose);

      for (sb = 0; sb < MAX_SB_PER_CALL; sb++) {
        s = format (s, "sb tunnel {%U} ", format_ppf_gtpu_tunnel_simple, &(callline->rb.drb.sb_tunnel[sb]), verbose);
      }      
    }
  }

  if (verbose > 0)
    s = format (s, "\npdcp %U\n", format_ppf_pdcp_simple, &(callline->pdcp), verbose);
  else
    s = format (s, "pdcp {%U}\n", format_ppf_pdcp_simple, &(callline->pdcp), verbose);
  
  return s;
}


static clib_error_t *
ppf_show_callline (vlib_main_t * vm,
             unformat_input_t * input, vlib_cli_command_t * cmd)
{
  ppf_main_t *pm = &ppf_main;
  ppf_callline_t * callline;
  u32 call_id = ~0;
  int verbose = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (input, "%d", &call_id))
      ;
    else if (unformat (input, "verbose"))
      verbose++;
    else
      break;
  }

  if (~0 == call_id) { /* show all */
    for (call_id = 0; call_id < pm->max_capacity; call_id++) {
      callline = &(pm->ppf_calline_table[call_id]);
      if (~0 != callline->call_index)
        vlib_cli_output (vm, "%U", format_ppf_callline, callline, verbose);
    }

    return 0;
  }

  if (call_id < pm->max_capacity) {
    callline = &(pm->ppf_calline_table[call_id]);
    vlib_cli_output (vm, "%U", format_ppf_callline, callline, verbose);
  } else
    vlib_cli_output (vm, "Please input a correct call-id, range[0, %d]\n", pm->max_capacity - 1);
  
  return 0;
}

VLIB_CLI_COMMAND (ppf_show_callline_command, static) = {
    .path = "show ppf-callline",
    .short_help = "show ppf-callline [index] [verbose]",
    .function = ppf_show_callline,
};



/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
