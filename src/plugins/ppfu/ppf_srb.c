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
#include <vnet/pg/pg.h>
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
  srb->call_id = clib_host_to_net_u32 (0);
  srb->transaction_id = clib_host_to_net_u32 (0);
  srb->msg.in.request_id = clib_host_to_net_u32 (0);
  srb->msg.in.integrity_status = clib_host_to_net_u32 (1);
  srb->msg.in.data_l = clib_host_to_net_u32 (0);

  ppf_sb_main.rewrite = r.rw;

  return;
}

static clib_error_t *
ppf_srb_set_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  clib_error_t *error = NULL;
  u32 want_feedback = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "feedback"))
	{
	  if (unformat (input, "enable"))
	    want_feedback = 1;
	  else if (unformat (input, "disable"))
	    want_feedback = 0;
	}
      else
	{
	  error =
	    clib_error_return (0, "parse error: '%U'", format_unformat_error,
			       input);
	  return error;
	}
    }

  ppf_sb_main.want_feedback = want_feedback;
  vlib_cli_output (vm, "PPF SRB want_feedback is set to %s\n",
		   (ppf_sb_main.want_feedback ? "enable" : "disable"));

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_ppf_srb_command, static) = {
  .path = "set ppf_srb",
  .short_help =	"set ppf_srb [feedback <enable|disable>]",
  .function = ppf_srb_set_command_fn,
};
/* *INDENT-ON* */



/**************************Start of pg***************************/

#define PPF_SRB_PG_EDIT_LENGTH (1 << 0)

/* Only used for pg */
typedef struct
{
  u32 call_id;
  u32 transaction_id;
  u32 request_id;
  u8 sb_id[3];
  u8 sb_num;
  u32 data_l;
} ppf_srb_in_header_t;

typedef struct
{
  pg_edit_t call_id;
  pg_edit_t transaction_id;
  pg_edit_t request_id;
  pg_edit_t sb_id[3];
  pg_edit_t sb_num;
  pg_edit_t data_l;
} pg_ppf_srb_in_header_t;

always_inline void
ppf_srb_pg_edit_function_inline (pg_main_t * pg,
				 pg_stream_t * s,
				 pg_edit_group_t * g,
				 u32 * packets, u32 n_packets, u32 flags)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 srb_offset;

  srb_offset = g->start_byte_offset;

  while (n_packets >= 1)
    {
      vlib_buffer_t *p0;
      ppf_srb_in_header_t *srb0;
      u32 srb_len0;

      p0 = vlib_get_buffer (vm, packets[0]);
      n_packets -= 1;
      packets += 1;

      srb0 = (void *) (p0->data + srb_offset);
      srb_len0 =
	vlib_buffer_length_in_chain (vm, p0) - srb_offset - sizeof (srb0[0]);

      if (flags & PPF_SRB_PG_EDIT_LENGTH)
	srb0->data_l = clib_host_to_net_u32 (srb_len0);
    }
}

static void
ppf_srb_pg_edit_function (pg_main_t * pg,
			  pg_stream_t * s,
			  pg_edit_group_t * g, u32 * packets, u32 n_packets)
{
  switch (g->edit_function_opaque)
    {
    case PPF_SRB_PG_EDIT_LENGTH:
      ppf_srb_pg_edit_function_inline (pg, s, g, packets, n_packets,
				       PPF_SRB_PG_EDIT_LENGTH);
      break;

    default:
      ASSERT (0);
      break;
    }
}

static inline void
pg_ppf_srb_header_init (pg_ppf_srb_in_header_t * p)
{
  /* Initialize fields that are not bit fields in the IP header. */
#define _(f) pg_edit_init (&p->f, ppf_srb_in_header_t, f);
  _(call_id);
  _(transaction_id);
  _(request_id);
  _(sb_id[0]);
  _(sb_id[1]);
  _(sb_id[2]);
  _(sb_num);
  _(data_l);
#undef _
}

uword
unformat_pg_ppf_srb_header (unformat_input_t * input, va_list * args)
{
  pg_stream_t *s = va_arg (*args, pg_stream_t *);
  unformat_input_t sub_input = { 0 };
  pg_ppf_srb_in_header_t *p;
  u32 group_index;

  p = pg_create_edit_group (s, sizeof (p[0]), sizeof (ppf_srb_in_header_t),
			    &group_index);
  pg_ppf_srb_header_init (p);

  /* Defaults. */
  p->call_id.type = PG_EDIT_UNSPECIFIED;
  p->transaction_id.type = PG_EDIT_UNSPECIFIED;
  p->request_id.type = PG_EDIT_UNSPECIFIED;
  p->sb_id[0].type = PG_EDIT_UNSPECIFIED;
  p->sb_id[1].type = PG_EDIT_UNSPECIFIED;
  p->sb_id[2].type = PG_EDIT_UNSPECIFIED;
  p->sb_num.type = PG_EDIT_UNSPECIFIED;
  p->data_l.type = PG_EDIT_UNSPECIFIED;

  if (!unformat (input, "SRB %U", unformat_input, &sub_input))
    goto error;

  /* Parse options. */
  while (1)
    {
      if (unformat (&sub_input, "call-id %U",
		    unformat_pg_edit, unformat_pg_number, &p->call_id))
	;

      else if (unformat (&sub_input, "transaction-id %U",
			 unformat_pg_edit, unformat_pg_number,
			 &p->transaction_id))
	;

      else if (unformat (&sub_input, "request-id %U",
			 unformat_pg_edit, unformat_pg_number,
			 &p->request_id))
	;

      else if (unformat (&sub_input, "sb-num %U",
			 unformat_pg_edit, unformat_pg_number, &p->sb_num))
	;

      else if (unformat (&sub_input, "sb-id0 %U",
			 unformat_pg_edit, unformat_pg_number, &p->sb_id[0]))
	;

      else if (unformat (&sub_input, "sb-id1 %U",
			 unformat_pg_edit, unformat_pg_number, &p->sb_id[1]))
	;

      else if (unformat (&sub_input, "sb-id2 %U",
			 unformat_pg_edit, unformat_pg_number, &p->sb_id[2]))
	;

      else if (unformat (&sub_input, "length %U",
			 unformat_pg_edit, unformat_pg_number, &p->data_l))
	;

      /* Can't parse input: try next protocol level. */
      else
	break;
    }

  {
    if (!unformat_user (&sub_input, unformat_pg_payload, s))
      goto error;

    p = pg_get_edit_group (s, group_index);
    if (p->data_l.type == PG_EDIT_UNSPECIFIED)
      {
	pg_edit_group_t *g = pg_stream_get_group (s, group_index);
	g->edit_function = ppf_srb_pg_edit_function;
	g->edit_function_opaque = 0;
	if (p->data_l.type == PG_EDIT_UNSPECIFIED)
	  g->edit_function_opaque |= PPF_SRB_PG_EDIT_LENGTH;
      }

    unformat_free (&sub_input);
    return 1;
  }

error:
  /* Free up any edits we may have added. */
  pg_free_edit_group (s);
  unformat_free (&sub_input);

  return 0;
}

/***************************End of pg****************************/

clib_error_t *
ppf_srb_init (vlib_main_t * vm)
{
  ppf_sb_main_t *psm = &ppf_sb_main;
  udp_dst_port_info_t *pi;
  pg_node_t *pn = pg_get_node (ppf_srb_nb_rx_node.index);

  pn->unformat_edit = unformat_pg_ppf_srb_header;

  psm->vnet_main = vnet_get_main ();
  psm->vlib_main = vm;

  psm->srb_rx_next_index = PPF_SRB_NB_RX_NEXT_PPF_SB_PATH_LB;
  psm->sb_lb_next_index = PPF_SB_PATH_LB_NEXT_PPF_PDCP_ENCRYPT;

  psm->want_feedback = 0;

  ppf_srb_ip_udp_rewrite ();

  udp_register_dst_port (vm, SRB_NB_PORT,
			 ppf_srb_nb_rx_node.index, /* is_ip4 */ 1);

  pi = udp_get_dst_port_info (&udp_main, SRB_NB_PORT, 1);
  if (pi)
    pi->unformat_pg_edit = unformat_pg_ppf_srb_header;

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
