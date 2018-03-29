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


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
