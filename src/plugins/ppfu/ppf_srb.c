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

ppf_sb_main_t ppf_sb_main; 

static clib_error_t *
ppf_srb_config (vlib_main_t * vm, unformat_input_t * input)
{
 // ppf_srb_main_t *psm = &ppf_srb_main;
  clib_error_t *error = 0;

  return error;
}

VLIB_CONFIG_FUNCTION (ppf_srb_config, "ppf_srb");

clib_error_t *
ppf_srb_init (vlib_main_t * vm)
{
  ppf_sb_main_t *psm = &ppf_sb_main;

  psm->vnet_main = vnet_get_main ();
  psm->vlib_main = vm;
	
  psm->srb_rx_next_index = PPF_SRB_NB_RX_NEXT_PPF_SB_PATH_LB;
  psm->sb_lb_next_index = PPF_SB_PATH_LB_NEXT_PPF_PDCP_ENCRYPT;
  
  return 0;
}

VLIB_INIT_FUNCTION (ppf_srb_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
