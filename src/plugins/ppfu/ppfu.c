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

clib_error_t *
ppf_init (vlib_main_t * vm)
{
  ppf_main_t *pm = &ppf_main;
  ppf_callline_t * callline;

  u32 i, j;
  
  if (pm->max_capacity == 0)
    pm->max_capacity = DEF_MAX_PPF_SESSION;

  pm->ppf_calline_table = clib_mem_alloc (pm->max_capacity * sizeof (ppf_callline_t));
  ASSERT(pm->ppf_calline_table != NULL);

  for (i = 0; i < pm->max_capacity; i++) {
    callline = &(pm->ppf_calline_table[i]);
    callline->call_index = ~0;
    
    callline->rb.drb.nb_tunnel.tunnel_id = ~0;    
    for (j = 0; j < MAX_SB_PER_CALL; j++) {
      callline->rb.drb.sb_tunnel[j].tunnel_id = ~0;
    }
    
    callline->rb.srb.nb_out_msg_by_sn = 0;
    for (j = 0; j < MAX_SB_PER_CALL; j++) {
      callline->rb.srb.sb_tunnel[j].tunnel_id = ~0;
    }

    callline->pdcp.session_id = ~0;
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

  s = format (s, "sess-id %d", pdcp->session_id);
  if (verbose > 0) {
    pdcp_session= pool_elt_at_index (ppm->sessions, pdcp->session_id);
    if (pdcp_session) {
      s = format (s, "\ndetails %U\n", format_ppf_pdcp_session, pdcp_session);
    }
  }

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

  s = format (s, "[%d]type %s ", callline->call_index, ppf_callline_type_strings[callline->call_type]);

  if (PPF_SRB_CALL == callline->call_type) {    
    if (verbose > 0) {
      s = format (s, "\nnb msg hash: %U\n", format_hash, callline->rb.srb.nb_out_msg_by_sn, verbose);
      
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
