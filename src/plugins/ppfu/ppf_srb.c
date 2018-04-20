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

#define SRB_NB_PORT  12345

static void
ppf_srb_ip_udp_rewrite ()
{
  union
  {
    ip4_srb_header_t *h4;
    u8 *rw;
  } r =
  {
  .rw = 0};
  int len = sizeof *r.h4;

  vec_validate_aligned (r.rw, len - 1, CLIB_CACHE_LINE_BYTES);

  ip4_header_t *ip = &r.h4->ip4;
  udp_header_t *udp = &r.h4->udp;
  ppf_srb_header_t *srb = &r.h4->srb;

  /* Fixed portion of the (outer) ip header */
  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 254;
  ip->protocol = IP_PROTOCOL_UDP;
  
  ip->src_address.as_u32 = ppf_sb_main.src;
  ip->dst_address.as_u32 = ppf_sb_main.dst;
  
  /* we fix up the ip4 header length and checksum after-the-fact */
  ip->checksum = ip4_header_checksum (ip);

  /* UDP header, randomize src port on something, maybe? */
  udp->src_port = clib_host_to_net_u16 (SRB_NB_PORT);
  udp->dst_port = clib_host_to_net_u16 (SRB_NB_PORT);

  /* SRB indata header */
  srb->call_id = clib_host_to_net_u32(0);
  srb->transaction_id = clib_host_to_net_u32(0);
  srb->msg.in.request_id = clib_host_to_net_u32(0);
  srb->msg.in.integrity_status = clib_host_to_net_u32(1);
  srb->msg.in.data_l = clib_host_to_net_u32(0);
  
  ppf_sb_main.rewrite = r.rw;
  
  return;
}

clib_error_t *
ppf_srb_init (vlib_main_t * vm)
{
  ppf_sb_main_t *psm = &ppf_sb_main;

  psm->vnet_main = vnet_get_main ();
  psm->vlib_main = vm;
	
  psm->srb_rx_next_index = PPF_SB_PATH_LB_NEXT_PPF_PDCP_ENCRYPT;
  psm->sb_lb_next_index = PPF_SB_PATH_LB_NEXT_PPF_PDCP_ENCRYPT;

  psm->want_feedback = 0;

  ppf_srb_ip_udp_rewrite ();

  udp_register_dst_port (vm, SRB_NB_PORT,
			 ppf_srb_nb_rx_node.index, /* is_ip4 */ 1);
  
  return 0;
}

VLIB_INIT_FUNCTION (ppf_srb_init);


static clib_error_t *
ppf_srb_set_command_fn (vlib_main_t * vm,
					unformat_input_t * input,
					vlib_cli_command_t * cmd)
{
  clib_error_t *error = NULL;
  u32 want_feedback = 0;
  
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "feedback")) {
	    if (unformat (input, "enable"))
          want_feedback = 1;
        else if (unformat (input, "disable"))
	      want_feedback = 0;
      }
      else
      {
        error = clib_error_return (0, "parse error: '%U'", format_unformat_error, input);
        return error;
      }
    }

  ppf_sb_main.want_feedback = want_feedback;
  vlib_cli_output (vm, "PPF SRB want_feedback is set to %s\n", (ppf_sb_main.want_feedback ? "enable" : "disable"));

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_ppf_srb_command, static) = {
  .path = "set ppf_srb",
  .short_help =	"set ppf_srb [feedback <enable|disable>]",
  .function = ppf_srb_set_command_fn,
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
