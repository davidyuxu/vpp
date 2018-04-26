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

ppf_gtpu_main_t ppf_gtpu_main;

/* *INDENT-OFF* */
VNET_FEATURE_INIT (ip4_ppf_gtpu_bypass, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "ip4-ppf_gtpu-bypass",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};

VNET_FEATURE_INIT (ip6_ppf_gtpu_bypass, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "ip6-ppf_gtpu-bypass",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
};
/* *INDENT-on* */

static u8 *
format_decap_next (u8 * s, va_list * args)
{
  u32 next_index = va_arg (*args, u32);

  switch (next_index)
    {
    case PPF_GTPU_INPUT_NEXT_DROP:
      return format (s, "drop");
    case PPF_GTPU_INPUT_NEXT_L2_INPUT:
      return format (s, "l2");
    case PPF_GTPU_INPUT_NEXT_IP4_INPUT:
      return format (s, "ip4");
    case PPF_GTPU_INPUT_NEXT_IP6_INPUT:
      return format (s, "ip6");
    case PPF_GTPU_INPUT_NEXT_GTPLO:
      return format (s, "gtplo");
    case PPF_GTPU_INPUT_NEXT_PPF_GTP4_ENCAP:
      return format (s, "ppf_gtpu4-encap");
    case PPF_GTPU_INPUT_NEXT_PPF_PDCP_INPUT:
      return format (s, "ppf_pdcp_input");
    case PPF_GTPU_INPUT_NEXT_PPF_SB_PATH_LB:
      return format (s, "ppf_sb_path_lb");
    default:
      return format (s, "index %d", next_index);
    }
  return s;
}

u8 *
format_ppf_gtpu_tunnel (u8 * s, va_list * args)
{
  ppf_gtpu_tunnel_t *t = va_arg (*args, ppf_gtpu_tunnel_t *);
  ppf_gtpu_main_t *ngm = &ppf_gtpu_main;

  s = format (s, "[%d] src %U dst %U in_teid %x out_teid %x fib-idx %d sw-if-idx %u ",
	      t - ngm->tunnels,
	      format_ip46_address, &t->src, IP46_TYPE_ANY,
	      format_ip46_address, &t->dst, IP46_TYPE_ANY,
	      t->in_teid, t->out_teid, t->encap_fib_index, t->sw_if_index);

  s = format (s, "encap-dpo-idx %u ", t->next_dpo.dpoi_index);
  s = format (s, "decap-next-%U ", format_decap_next, t->decap_next_index);

  if (PREDICT_FALSE (ip46_address_is_multicast (&t->dst)))
    s = format (s, "mcast-sw-if-idx %u ", t->mcast_sw_if_index);

  return s;
}

static u8 *
format_ppf_gtpu_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "ppf_gtpu_tunnel%d", dev_instance);
}

static clib_error_t *
ppf_gtpu_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  u32 hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
    VNET_HW_INTERFACE_FLAG_LINK_UP : 0;
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

  return /* no error */ 0;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (ppf_gtpu_device_class,static) = {
  .name = "PPF_GTPU",
  .format_device_name = format_ppf_gtpu_name,
  .format_tx_trace = format_ppf_gtpu_encap_trace,
  .admin_up_down_function = ppf_gtpu_interface_admin_up_down,
};
/* *INDENT-ON* */

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

static void
ppf_gtpu_tunnel_restack_dpo (ppf_gtpu_tunnel_t * t)
{
  dpo_id_t dpo = DPO_INVALID;
  u32 encap_index = ip46_address_is_ip4 (&t->dst) ?
    ppf_gtpu4_encap_node.index : ppf_gtpu6_encap_node.index;
  fib_forward_chain_type_t forw_type = ip46_address_is_ip4 (&t->dst) ?
    FIB_FORW_CHAIN_TYPE_UNICAST_IP4 : FIB_FORW_CHAIN_TYPE_UNICAST_IP6;

  fib_entry_contribute_forwarding (t->fib_entry_index, forw_type, &dpo);
  dpo_stack_from_node (encap_index, &t->next_dpo, &dpo);
  dpo_reset (&dpo);
}

static ppf_gtpu_tunnel_t *
ppf_gtpu_tunnel_from_fib_node (fib_node_t * node)
{
  return ((ppf_gtpu_tunnel_t *) (((char *) node) -
			     STRUCT_OFFSET_OF (ppf_gtpu_tunnel_t, node)));
}

/**
 * Function definition to backwalk a FIB node -
 * Here we will restack the new dpo of PPF_GTPU DIP to encap node.
 */
static fib_node_back_walk_rc_t
ppf_gtpu_tunnel_back_walk (fib_node_t * node, fib_node_back_walk_ctx_t * ctx)
{
  ppf_gtpu_tunnel_restack_dpo (ppf_gtpu_tunnel_from_fib_node (node));
  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/**
 * Function definition to get a FIB node from its index
 */
static fib_node_t *
ppf_gtpu_tunnel_fib_node_get (fib_node_index_t index)
{
  ppf_gtpu_tunnel_t *t;
  ppf_gtpu_main_t *gtm = &ppf_gtpu_main;

  t = pool_elt_at_index (gtm->tunnels, index);

  return (&t->node);
}

/**
 * Function definition to inform the FIB node that its last lock has gone.
 */
static void
ppf_gtpu_tunnel_last_lock_gone (fib_node_t * node)
{
  /*
   * The PPF_GTPU tunnel is a root of the graph. As such
   * it never has children and thus is never locked.
   */
  ASSERT (0);
}

/*
 * Virtual function table registered by PPF_GTPU tunnels
 * for participation in the FIB object graph.
 */
const static fib_node_vft_t ppf_gtpu_vft = {
  .fnv_get = ppf_gtpu_tunnel_fib_node_get,
  .fnv_last_lock = ppf_gtpu_tunnel_last_lock_gone,
  .fnv_back_walk = ppf_gtpu_tunnel_back_walk,
};


#define foreach_copy_field                      \
_(in_teid)                                   \
_(out_teid)						\
_(mcast_sw_if_index)                            \
_(encap_fib_index)                              \
_(decap_next_index)                             \
_(src)                                          \
_(dst)							\
_(call_id)							\
_(tunnel_type)						\
_(sb_id)	

#define install_tunnel_copy                     \
_(is_ip6)                                   	\
_(mcast_sw_if_index)					\
_(decap_next_index)                            	\
_(encap_fib_index)                             	\
_(in_teid)                             		\
_(out_teid)                                    	\
_(dst)							\
_(src)							\
_(call_id)							\
_(tunnel_type)						\
_(sb_id)							\
_(dst_port)							\
_(dscp)							\
_(protocol_config)					\
_(type)							\
_(ep_weight)						\
_(traffic_state)						

#define update_tunnel_copy                      \
_(call_id)							\
_(tunnel_type)						\
_(sb_id)							\
_(is_ip6)							\
_(out_teid)                                   	\
_(dst)							\
_(dst_port)                            		\
_(dscp)                              		\
_(protocol_config)                             	\
_(ep_weight)                                    \
_(traffic_state)						\
_(type)

#define delete_tunnel_copy                      \
_(call_id)                                   	\
_(tunnel_type)						\
_(sb_id)							

static void
ip_udp_ppf_gtpu_rewrite (ppf_gtpu_tunnel_t * t, bool is_ip6)
{
  union
  {
    ip4_ppf_gtpu_header_t *h4;
    ip6_ppf_gtpu_header_t *h6;
    u8 *rw;
  } r =
  {
  .rw = 0};
  int len = is_ip6 ? sizeof *r.h6 : sizeof *r.h4;

  vec_validate_aligned (r.rw, len - 1, CLIB_CACHE_LINE_BYTES);

  udp_header_t *udp;
  ppf_gtpu_header_t *ppf_gtpu;
  /* Fixed portion of the (outer) ip header */
  if (!is_ip6)
    {
      ip4_header_t *ip = &r.h4->ip4;
      udp = &r.h4->udp;
      ppf_gtpu = &r.h4->ppf_gtpu;
      ip->ip_version_and_header_length = 0x45;
      ip->ttl = 254;
      ip->protocol = IP_PROTOCOL_UDP;

      ip->src_address = t->src.ip4;
      ip->dst_address = t->dst.ip4;

      ip->tos = t->dscp;

      /* we fix up the ip4 header length and checksum after-the-fact */
      ip->checksum = ip4_header_checksum (ip);
    }
  else
    {
      ip6_header_t *ip = &r.h6->ip6;
      udp = &r.h6->udp;
      ppf_gtpu = &r.h6->ppf_gtpu;
      ip->ip_version_traffic_class_and_flow_label =
	clib_host_to_net_u32 (6 << 28);
      ip->hop_limit = 255;
      ip->protocol = IP_PROTOCOL_UDP;

      ip->src_address = t->src.ip6;
      ip->dst_address = t->dst.ip6;
    }

  /* UDP header, randomize src port on something, maybe? */
  udp->src_port = clib_host_to_net_u16 (2152);
  udp->dst_port = clib_host_to_net_u16 (t->dst_port);

  /* PPF_GTPU header */
  ppf_gtpu->ver_flags = PPF_GTPU_V1_VER | PPF_GTPU_PT_GTP;
  ppf_gtpu->type = PPF_GTPU_TYPE_PPF_GTPU;
  ppf_gtpu->teid = clib_host_to_net_u32 (t->out_teid);

  t->rewrite = r.rw;
  /* Now only support 8-byte ppf_gtpu header. TBD */
  _vec_len (t->rewrite) = sizeof (ip4_ppf_gtpu_header_t) - 4;

  return;
}

static bool
ppf_gtpu_decap_next_is_valid (ppf_gtpu_main_t * gtm, u32 is_ip6, u32 decap_next_index)
{
  vlib_main_t *vm = gtm->vlib_main;
  u32 input_idx = (!is_ip6) ? ppf_gtpu4_input_node.index : ppf_gtpu6_input_node.index;
  vlib_node_runtime_t *r = vlib_node_get_runtime (vm, input_idx);

  return decap_next_index < r->n_next_nodes;
}

static uword
vtep_addr_ref (ip46_address_t * ip)
{
  uword *vtep = ip46_address_is_ip4 (ip) ?
    hash_get (ppf_gtpu_main.vtep4, ip->ip4.as_u32) :
    hash_get_mem (ppf_gtpu_main.vtep6, &ip->ip6);
  if (vtep)
    return ++(*vtep);
  ip46_address_is_ip4 (ip) ?
    hash_set (ppf_gtpu_main.vtep4, ip->ip4.as_u32, 1) :
    hash_set_mem_alloc (&ppf_gtpu_main.vtep6, &ip->ip6, 1);
  return 1;
}

static uword
vtep_addr_unref (ip46_address_t * ip)
{
  uword *vtep = ip46_address_is_ip4 (ip) ?
    hash_get (ppf_gtpu_main.vtep4, ip->ip4.as_u32) :
    hash_get_mem (ppf_gtpu_main.vtep6, &ip->ip6);
  ASSERT (vtep);
  if (--(*vtep) != 0)
    return *vtep;
  ip46_address_is_ip4 (ip) ?
    hash_unset (ppf_gtpu_main.vtep4, ip->ip4.as_u32) :
    hash_unset_mem_free (&ppf_gtpu_main.vtep6, &ip->ip6);
  return 0;
}

typedef CLIB_PACKED (union
		     {
		     struct
		     {
		     fib_node_index_t mfib_entry_index;
		     adj_index_t mcast_adj_index;
		     }; u64 as_u64;
		     }) mcast_shared_t;

static inline mcast_shared_t
mcast_shared_get (ip46_address_t * ip)
{
  ASSERT (ip46_address_is_multicast (ip));
  uword *p = hash_get_mem (ppf_gtpu_main.mcast_shared, ip);
  ASSERT (p);
  return (mcast_shared_t)
  {
  .as_u64 = *p};
}

static inline void
mcast_shared_add (ip46_address_t * dst, fib_node_index_t mfei, adj_index_t ai)
{
  mcast_shared_t new_ep = {
    .mcast_adj_index = ai,
    .mfib_entry_index = mfei,
  };

  hash_set_mem_alloc (&ppf_gtpu_main.mcast_shared, dst, new_ep.as_u64);
}

static inline void
mcast_shared_remove (ip46_address_t * dst)
{
  mcast_shared_t ep = mcast_shared_get (dst);

  adj_unlock (ep.mcast_adj_index);
  mfib_table_entry_delete_index (ep.mfib_entry_index, MFIB_SOURCE_GTPU);

  hash_unset_mem_free (&ppf_gtpu_main.mcast_shared, dst);
}
int vnet_ppf_gtpu_add_del_tunnel
  (vnet_ppf_gtpu_add_del_tunnel_args_t * a, u32 * sw_if_indexp)
{
  ppf_gtpu_main_t *gtm = &ppf_gtpu_main;
  ppf_main_t *pm = &ppf_main;
  ppf_gtpu_tunnel_t *t = 0;

  vnet_main_t *vnm = gtm->vnet_main;
  uword *p;
  u32 hw_if_index = ~0;
  u32 sw_if_index = ~0;
  ppf_gtpu4_tunnel_key_t key4;
  ppf_gtpu6_tunnel_key_t key6;
  u32 is_ip6 = a->is_ip6;
  ppf_callline_t *callline;
  ppf_gtpu_tunnel_id_type_t *it;
  u32 tunnel_id;

  key4.teid = ~0;
	
  if (!is_ip6)
    {
      key4.teid = clib_host_to_net_u32 (a->in_teid);
      p = hash_get (gtm->ppf_gtpu4_tunnel_by_key, key4.as_u32);
    }
  else
    {
      key6.teid = clib_host_to_net_u32 (a->in_teid);
      p = hash_get_mem (gtm->ppf_gtpu6_tunnel_by_key, &key6);
    }
    
  if (a->call_id >= pm->max_capacity) {
	return VNET_API_ERROR_WRONG_MAX_SESSION_NUM;
  }

  if (a->is_add)
    {
      l2input_main_t *l2im = &l2input_main;

      /* adding a tunnel: tunnel must not already exist */
      if (p)
	return VNET_API_ERROR_TUNNEL_EXIST;

      /*if not set explicitly, default to l2 */
      if (a->decap_next_index == ~0)
	a->decap_next_index = PPF_GTPU_INPUT_NEXT_L2_INPUT;
      if (!ppf_gtpu_decap_next_is_valid (gtm, is_ip6, a->decap_next_index))
	return VNET_API_ERROR_INVALID_DECAP_NEXT;

      pool_get_aligned (gtm->tunnels, t, CLIB_CACHE_LINE_BYTES);
      memset (t, 0, sizeof (*t));

      /* copy from arg structure */
#define _(x) t->x = a->x;
      foreach_copy_field;
#undef _

      tunnel_id = t - gtm->tunnels;
      
      //add by lollita for ppf gtpu tunnel swap
      callline = &(pm->ppf_calline_table[t->call_id]); 

      switch (t->tunnel_type) {
        case PPF_GTPU_NB:
          callline->rb.drb.nb_tunnel.tunnel_id = tunnel_id;
          callline->rb.drb.nb_tunnel.tunnel_type = t->tunnel_type;
          break;

        case PPF_GTPU_SB:
          {
            it = &(callline->rb.drb.sb_tunnel[t->sb_id]);
            
            if (it->tunnel_id != INVALID_TUNNEL_ID && it->tunnel_id != tunnel_id) {
              pool_put (gtm->tunnels, t);
              return VNET_API_ERROR_TUNNEL_EXIST;
            }
            
            it->tunnel_id = tunnel_id;
            it->tunnel_type = t->tunnel_type;
          }
          break;

        case PPF_GTPU_SRB:
          {
            it = &(callline->rb.srb.sb_tunnel[t->sb_id]);
            
            if (it->tunnel_id != INVALID_TUNNEL_ID && it->tunnel_id != tunnel_id) {
              pool_put (gtm->tunnels, t);
              return VNET_API_ERROR_TUNNEL_EXIST;
            }
            
            it->tunnel_id = tunnel_id;
            it->tunnel_type = t->tunnel_type;


          }
          break;

        default:
          break;
      }
      
      ip_udp_ppf_gtpu_rewrite (t, is_ip6);

      /* copy the key */
      if (is_ip6)
	hash_set_mem_alloc (&gtm->ppf_gtpu6_tunnel_by_key, &key6,
			    t - gtm->tunnels);
      else
	hash_set (gtm->ppf_gtpu4_tunnel_by_key, key4.as_u32, t - gtm->tunnels);

	if (t->tunnel_type == PPF_GTPU_SB ) {
		t->decap_next_index = PPF_GTPU_INPUT_NEXT_PPF_PDCP_INPUT;
	} else if (t->tunnel_type == PPF_GTPU_NB) {
		t->decap_next_index = PPF_GTPU_INPUT_NEXT_PPF_SB_PATH_LB;
	} else if (t->tunnel_type == PPF_GTPU_SRB) {
		t->decap_next_index = PPF_GTPU_INPUT_NEXT_PPF_PDCP_INPUT;
	}

	if (is_ip6) 
	 t->encap_next_index = PPF_GTPU_ENCAP_NEXT_IP6_LOOKUP;
	else
	 t->encap_next_index = PPF_GTPU_ENCAP_NEXT_IP4_LOOKUP;


	if (t->decap_next_index == ~0) {
		return VNET_API_ERROR_NEXT_HOP_NOT_FOUND_MP;
	}
		
      vnet_hw_interface_t *hi;
      if (vec_len (gtm->free_ppf_gtpu_tunnel_hw_if_indices) > 0)
	{
	  vnet_interface_main_t *im = &vnm->interface_main;
	  hw_if_index = gtm->free_ppf_gtpu_tunnel_hw_if_indices
	    [vec_len (gtm->free_ppf_gtpu_tunnel_hw_if_indices) - 1];
	  _vec_len (gtm->free_ppf_gtpu_tunnel_hw_if_indices) -= 1;

	  hi = vnet_get_hw_interface (vnm, hw_if_index);
	  hi->dev_instance = t - gtm->tunnels;
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
	    (vnm, ppf_gtpu_device_class.index, t - gtm->tunnels,
	     ppf_gtpu_hw_class.index, t - gtm->tunnels);
	  hi = vnet_get_hw_interface (vnm, hw_if_index);
	}

      /* Set ppf_gtpu tunnel output node */
      u32 encap_index = !is_ip6 ?
	ppf_gtpu4_encap_node.index : ppf_gtpu6_encap_node.index;
      vnet_set_interface_output_node (vnm, hw_if_index, encap_index);

      t->hw_if_index = hw_if_index;
      t->sw_if_index = sw_if_index = hi->sw_if_index;

      vec_validate_init_empty (gtm->tunnel_index_by_sw_if_index, sw_if_index,
			       ~0);
      gtm->tunnel_index_by_sw_if_index[sw_if_index] = t - gtm->tunnels;

      /* setup l2 input config with l2 feature and bd 0 to drop packet */
      vec_validate (l2im->configs, sw_if_index);
      l2im->configs[sw_if_index].feature_bitmap = L2INPUT_FEAT_DROP;
      l2im->configs[sw_if_index].bd_index = 0;

      vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
      si->flags &= ~VNET_SW_INTERFACE_FLAG_HIDDEN;
      vnet_sw_interface_set_flags (vnm, sw_if_index,
				   VNET_SW_INTERFACE_FLAG_ADMIN_UP);

      fib_node_init (&t->node, gtm->fib_node_type);
      fib_prefix_t tun_dst_pfx;
      vnet_flood_class_t flood_class = VNET_FLOOD_CLASS_TUNNEL_NORMAL;

      fib_prefix_from_ip46_addr (&t->dst, &tun_dst_pfx);
      if (!ip46_address_is_multicast (&t->dst))
	{
	  /* Unicast tunnel -
	   * source the FIB entry for the tunnel's destination
	   * and become a child thereof. The tunnel will then get poked
	   * when the forwarding for the entry updates, and the tunnel can
	   * re-stack accordingly
	   */
	  vtep_addr_ref (&t->src);
	  t->fib_entry_index = fib_table_entry_special_add
	    (t->encap_fib_index, &tun_dst_pfx, FIB_SOURCE_RR,
	     FIB_ENTRY_FLAG_NONE);
	  #if 0
	  t->sibling_index = fib_entry_child_add
	    (t->fib_entry_index, gtm->fib_node_type, t - gtm->tunnels);
	  #endif
	  ppf_gtpu_tunnel_restack_dpo (t);
	}
      else
	{
	  /* Multicast tunnel -
	   * as the same mcast group can be used for mutiple mcast tunnels
	   * with different VNIs, create the output fib adjecency only if
	   * it does not already exist
	   */
	  fib_protocol_t fp = fib_ip_proto (is_ip6);

	  if (vtep_addr_ref (&t->dst) == 1)
	    {
	      fib_node_index_t mfei;
	      adj_index_t ai;
	      fib_route_path_t path = {
		.frp_proto = fib_proto_to_dpo (fp),
		.frp_addr = zero_addr,
		.frp_sw_if_index = 0xffffffff,
		.frp_fib_index = ~0,
		.frp_weight = 0,
		.frp_flags = FIB_ROUTE_PATH_LOCAL,
	      };
	      const mfib_prefix_t mpfx = {
		.fp_proto = fp,
		.fp_len = (is_ip6 ? 128 : 32),
		.fp_grp_addr = tun_dst_pfx.fp_addr,
	      };

	      /*
	       * Setup the (*,G) to receive traffic on the mcast group
	       *  - the forwarding interface is for-us
	       *  - the accepting interface is that from the API
	       */
	      mfib_table_entry_path_update (t->encap_fib_index,
					    &mpfx,
					    MFIB_SOURCE_GTPU,
					    &path, MFIB_ITF_FLAG_FORWARD);

	      path.frp_sw_if_index = a->mcast_sw_if_index;
	      path.frp_flags = FIB_ROUTE_PATH_FLAG_NONE;
	      mfei = mfib_table_entry_path_update (t->encap_fib_index,
						   &mpfx,
						   MFIB_SOURCE_GTPU,
						   &path,
						   MFIB_ITF_FLAG_ACCEPT);

	      /*
	       * Create the mcast adjacency to send traffic to the group
	       */
	      ai = adj_mcast_add_or_lock (fp,
					  fib_proto_to_link (fp),
					  a->mcast_sw_if_index);

	      /*
	       * create a new end-point
	       */
	      mcast_shared_add (&t->dst, mfei, ai);
	    }

	  dpo_id_t dpo = DPO_INVALID;
	  mcast_shared_t ep = mcast_shared_get (&t->dst);

	  /* Stack shared mcast dst mac addr rewrite on encap */
	  dpo_set (&dpo, DPO_ADJACENCY_MCAST,
		   fib_proto_to_dpo (fp), ep.mcast_adj_index);

	  dpo_stack_from_node (encap_index, &t->next_dpo, &dpo);

	  dpo_reset (&dpo);
	  flood_class = VNET_FLOOD_CLASS_TUNNEL_MASTER;
	}

      vnet_get_sw_interface (vnet_get_main (), sw_if_index)->flood_class =
	flood_class;
    }
  else
    {
      /* deleting a tunnel: tunnel must exist */
      if (!p)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      t = pool_elt_at_index (gtm->tunnels, p[0]);
      sw_if_index = t->sw_if_index;

      tunnel_id = t - gtm->tunnels;

      //add by lollita for ppf gtpu tunnel swap
      callline = &(pm->ppf_calline_table[t->call_id]); 
      
      if (t->tunnel_type == PPF_GTPU_NB) {
        callline->rb.drb.nb_tunnel.tunnel_id = INVALID_TUNNEL_ID;;
      } else if ((t->tunnel_type == PPF_GTPU_SB) || (t->tunnel_type == PPF_GTPU_SRB)) {
        it = &(callline->rb.srb.sb_tunnel[t->sb_id]);
        
        if (it->tunnel_id != INVALID_TUNNEL_ID && it->tunnel_id != tunnel_id) {
          return VNET_API_ERROR_TUNNEL_EXIST;
        }
        
        it->tunnel_id = INVALID_TUNNEL_ID;

      }

      vnet_sw_interface_set_flags (vnm, t->sw_if_index, 0 /* down */ );
      vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, t->sw_if_index);
      si->flags |= VNET_SW_INTERFACE_FLAG_HIDDEN;

      /* make sure tunnel is removed from l2 bd or xconnect */
      set_int_l2_mode (gtm->vlib_main, vnm, MODE_L3, t->sw_if_index, 0, 0, 0,
		       0);
      vec_add1 (gtm->free_ppf_gtpu_tunnel_hw_if_indices, t->hw_if_index);

      gtm->tunnel_index_by_sw_if_index[t->sw_if_index] = ~0;

      if (!is_ip6)
	hash_unset (gtm->ppf_gtpu4_tunnel_by_key, key4.as_u32);
      else
	hash_unset_mem_free (&gtm->ppf_gtpu6_tunnel_by_key, &key6);

      if (!ip46_address_is_multicast (&t->dst))
	{
	  vtep_addr_unref (&t->src);
	  #if 0
	  fib_entry_child_remove (t->fib_entry_index, t->sibling_index);
	  #endif
	  fib_table_entry_delete_index (t->fib_entry_index, FIB_SOURCE_RR);
	}
      else if (vtep_addr_unref (&t->dst) == 0)
	{
	  mcast_shared_remove (&t->dst);
	}

      fib_node_deinit (&t->node);
      vec_free (t->rewrite);
      pool_put (gtm->tunnels, t);
    }

  if (sw_if_indexp)
    *sw_if_indexp = sw_if_index;

  return 0;
}


int vnet_ppf_gtpu_add_tunnel
  (vnet_ppf_gtpu_add_del_tunnel_args_t * a, u32 * sw_if_indexp, u32 *tunnel_id_ret)

{
  ppf_gtpu_main_t *gtm = &ppf_gtpu_main;
  ppf_main_t *pm = &ppf_main;
  ppf_gtpu_tunnel_t *t = 0;

  vnet_main_t *vnm = gtm->vnet_main;
  uword *p;
  u32 hw_if_index = ~0;
  u32 sw_if_index = ~0;
  ppf_gtpu4_tunnel_key_t key4;
  ppf_gtpu6_tunnel_key_t key6;
  u32 is_ip6 = a->is_ip6;
  ppf_callline_t *callline;
  ppf_gtpu_tunnel_id_type_t *it;
  u32 tunnel_id;

  key4.teid = ~0;

  if (!is_ip6)
    {
      key4.teid = clib_host_to_net_u32(a->in_teid);
      p = hash_get (gtm->ppf_gtpu4_tunnel_by_key, key4.as_u32);
    }
  else
    {
      key6.teid = clib_host_to_net_u32(a->in_teid);
      p = hash_get_mem (gtm->ppf_gtpu6_tunnel_by_key, &key6);
    }
    
  if (a->call_id >= pm->max_capacity) {
	return VNET_API_ERROR_WRONG_MAX_SESSION_NUM;
  }

    {
      l2input_main_t *l2im = &l2input_main;

      /* adding a tunnel: tunnel must not already exist */
      if (p)
	return VNET_API_ERROR_TUNNEL_EXIST;

      /*if not set explicitly, default to l2 */
      if (a->decap_next_index == ~0)
	a->decap_next_index = PPF_GTPU_INPUT_NEXT_L2_INPUT;
      if (!ppf_gtpu_decap_next_is_valid (gtm, is_ip6, a->decap_next_index))
	return VNET_API_ERROR_INVALID_DECAP_NEXT;

      pool_get_aligned (gtm->tunnels, t, CLIB_CACHE_LINE_BYTES);
      memset (t, 0, sizeof (*t));

      /* copy from arg structure */
#define _(x) t->x = a->x;
      install_tunnel_copy;
#undef _

      tunnel_id = t - gtm->tunnels;

      //add by lollita for ppf gtpu tunnel swap
      callline = &(pm->ppf_calline_table[t->call_id]); 

      switch (t->tunnel_type) {
        case PPF_GTPU_NB:
          callline->rb.drb.nb_tunnel.tunnel_id = tunnel_id;
          callline->rb.drb.nb_tunnel.tunnel_type = t->tunnel_type;
          break;

        case PPF_GTPU_SB:
          {
            it = &(callline->rb.drb.sb_tunnel[t->sb_id]);
            
            if (it->tunnel_id != INVALID_TUNNEL_ID && it->tunnel_id != tunnel_id) {
              pool_put (gtm->tunnels, t);
              return VNET_API_ERROR_TUNNEL_EXIST;
            }
            
            it->tunnel_id = tunnel_id;
            it->tunnel_type = t->tunnel_type;
          }
          break;

        case PPF_GTPU_SRB:
          {
            it = &(callline->rb.srb.sb_tunnel[t->sb_id]);
            
            if (it->tunnel_id != INVALID_TUNNEL_ID && it->tunnel_id != tunnel_id) {
              pool_put (gtm->tunnels, t);
              return VNET_API_ERROR_TUNNEL_EXIST;
            }
            
            it->tunnel_id = tunnel_id;
            it->tunnel_type = t->tunnel_type;


          }
          break;

        default:
          break;
      }
      
      ip_udp_ppf_gtpu_rewrite (t, is_ip6);
	
      /* copy the key */
      if (is_ip6)
	hash_set_mem_alloc (&gtm->ppf_gtpu6_tunnel_by_key, &key6,
			    t - gtm->tunnels);
      else
	hash_set (gtm->ppf_gtpu4_tunnel_by_key, key4.as_u32, t - gtm->tunnels);

	if (t->tunnel_type == PPF_GTPU_SB ) {
		t->decap_next_index = PPF_GTPU_INPUT_NEXT_PPF_PDCP_INPUT;
	} else if (t->tunnel_type == PPF_GTPU_NB) {
		t->decap_next_index = PPF_GTPU_INPUT_NEXT_PPF_SB_PATH_LB;
	} else if (t->tunnel_type == PPF_GTPU_SRB) {
		t->decap_next_index = PPF_GTPU_INPUT_NEXT_PPF_PDCP_INPUT;
	}

	if (is_ip6) 
	 t->encap_next_index = PPF_GTPU_ENCAP_NEXT_IP6_LOOKUP;
	else
	 t->encap_next_index = PPF_GTPU_ENCAP_NEXT_IP4_LOOKUP;


	if (t->decap_next_index == ~0) {
		return VNET_API_ERROR_NEXT_HOP_NOT_FOUND_MP;
	}

	if (pm->ue_mode == 1) 
	{
		if (!ip_is_zero(&t->dst, is_ip6))
		{
		      vnet_hw_interface_t *hi;
		      if (vec_len (gtm->free_ppf_gtpu_tunnel_hw_if_indices) > 0)
			{
			  vnet_interface_main_t *im = &vnm->interface_main;
			  hw_if_index = gtm->free_ppf_gtpu_tunnel_hw_if_indices
			    [vec_len (gtm->free_ppf_gtpu_tunnel_hw_if_indices) - 1];
			  _vec_len (gtm->free_ppf_gtpu_tunnel_hw_if_indices) -= 1;

			  hi = vnet_get_hw_interface (vnm, hw_if_index);
			  hi->dev_instance = t - gtm->tunnels;
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
			    (vnm, ppf_gtpu_device_class.index, t - gtm->tunnels,
			     ppf_gtpu_hw_class.index, t - gtm->tunnels);
			  hi = vnet_get_hw_interface (vnm, hw_if_index);
			}

		      /* Set ppf_gtpu tunnel output node */
		      u32 encap_index = !is_ip6 ?
			ppf_gtpu4_encap_node.index : ppf_gtpu6_encap_node.index;
		      vnet_set_interface_output_node (vnm, hw_if_index, encap_index);

		      t->hw_if_index = hw_if_index;
		      t->sw_if_index = sw_if_index = hi->sw_if_index;

		      vec_validate_init_empty (gtm->tunnel_index_by_sw_if_index, sw_if_index,
					       ~0);
		      gtm->tunnel_index_by_sw_if_index[sw_if_index] = t - gtm->tunnels;

		      /* setup l2 input config with l2 feature and bd 0 to drop packet */
		      vec_validate (l2im->configs, sw_if_index);
		      l2im->configs[sw_if_index].feature_bitmap = L2INPUT_FEAT_DROP;
		      l2im->configs[sw_if_index].bd_index = 0;

		      vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
		      si->flags &= ~VNET_SW_INTERFACE_FLAG_HIDDEN;
		      vnet_sw_interface_set_flags (vnm, sw_if_index,
						   VNET_SW_INTERFACE_FLAG_ADMIN_UP);

		      fib_node_init (&t->node, gtm->fib_node_type);
		      fib_prefix_t tun_dst_pfx;
		      vnet_flood_class_t flood_class = VNET_FLOOD_CLASS_TUNNEL_NORMAL;

		      fib_prefix_from_ip46_addr (&t->dst, &tun_dst_pfx);
		      if (!ip46_address_is_multicast (&t->dst))
			{
			  /* Unicast tunnel -
			   * source the FIB entry for the tunnel's destination
			   * and become a child thereof. The tunnel will then get poked
			   * when the forwarding for the entry updates, and the tunnel can
			   * re-stack accordingly
			   */
			  vtep_addr_ref (&t->src);
			  t->fib_entry_index = fib_table_entry_special_add
			    (t->encap_fib_index, &tun_dst_pfx, FIB_SOURCE_RR,
			     FIB_ENTRY_FLAG_NONE);
			  #if 0
			  t->sibling_index = fib_entry_child_add
			    (t->fib_entry_index, gtm->fib_node_type, t - gtm->tunnels);
			  #endif
			  ppf_gtpu_tunnel_restack_dpo (t);
			}
			
		      vnet_get_sw_interface (vnet_get_main (), sw_if_index)->flood_class =
			flood_class;

		}
	}

    }

 
  if (sw_if_indexp)
    *sw_if_indexp = sw_if_index;

  * tunnel_id_ret = tunnel_id;

  return 0;
}

int vnet_ppf_gtpu_update_tunnel
  (u32 tunnel_id, vnet_ppf_gtpu_add_del_tunnel_args_t * a)

{
  ppf_gtpu_main_t *gtm = &ppf_gtpu_main;
  ppf_gtpu_tunnel_t *t = 0;

  t = &(gtm->tunnels[tunnel_id]);
   
  {

      if (a->dscp != ~0) 
      	t->dscp = a->dscp;

      if (a->out_teid != ~0) 
      	t->out_teid = a->out_teid;

      if (a->protocol_config != ~0) 
      	t->protocol_config = a->protocol_config;

      if (a->dst_port != ~0) 
      	t->dst_port = a->dst_port;

      if (a->ep_weight != ~0)
      	t->ep_weight = a->ep_weight;

      if (a->traffic_state != ~0) 
		t->traffic_state = a->traffic_state;

      if (a->type != ~0) 
		t->type = a->type;

	if (!ip_is_zero(&a->dst, t->is_ip6))
		ip_copy (&(t->dst), &(a->dst), t->is_ip6);
		
	ip_udp_ppf_gtpu_rewrite (t, t->is_ip6);	

  }
    
  return 0;
}


int vnet_ppf_gtpu_del_tunnel
  (u32 tunnel_id)
{
  ppf_gtpu_main_t *gtm = &ppf_gtpu_main;
  ppf_main_t *pm = &ppf_main;
  ppf_gtpu_tunnel_t *t = NULL;

  vnet_main_t *vnm = gtm->vnet_main;

  ppf_gtpu4_tunnel_key_t key4;
  ppf_gtpu6_tunnel_key_t key6;
  ppf_callline_t *callline;
  ppf_gtpu_tunnel_id_type_t *it;
 
      t = &(gtm->tunnels[tunnel_id]);
  
      //add by lollita for ppf gtpu tunnel swap
      callline = &(pm->ppf_calline_table[t->call_id]); 
      
      if (t->tunnel_type == PPF_GTPU_NB) {
      
        callline->rb.drb.nb_tunnel.tunnel_id = INVALID_TUNNEL_ID;
        
      } else if ((t->tunnel_type == PPF_GTPU_SB) || (t->tunnel_type == PPF_GTPU_SRB)) {
        it = &(callline->rb.srb.sb_tunnel[t->sb_id]);
        
        if (it->tunnel_id != INVALID_TUNNEL_ID && it->tunnel_id != tunnel_id) {
          return VNET_API_ERROR_TUNNEL_EXIST;
        }
        
        it->tunnel_id = INVALID_TUNNEL_ID;

      }


	if (pm->ue_mode == 1)  
	{
		if (!ip_is_zero(&t->dst, t->is_ip6)){
		      vnet_sw_interface_set_flags (vnm, t->sw_if_index, 0 /* down */ );
		      vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, t->sw_if_index);
		      si->flags |= VNET_SW_INTERFACE_FLAG_HIDDEN;

		      /* make sure tunnel is removed from l2 bd or xconnect */
		      set_int_l2_mode (gtm->vlib_main, vnm, MODE_L3, t->sw_if_index, 0, 0, 0,
				       0);
		      vec_add1 (gtm->free_ppf_gtpu_tunnel_hw_if_indices, t->hw_if_index);

		      gtm->tunnel_index_by_sw_if_index[t->sw_if_index] = ~0;
      	}
      }

      if (!t->is_ip6)
      {
          key4.teid = clib_host_to_net_u32 (t->in_teid);
          hash_unset (gtm->ppf_gtpu4_tunnel_by_key, key4.as_u32);
      }
      else
      {
          key6.teid = clib_host_to_net_u32 (t->in_teid);
          hash_unset_mem_free (&gtm->ppf_gtpu6_tunnel_by_key, &key6);
      }
      
	if (pm->ue_mode == 1)  
	{

		if (!ip_is_zero(&t->dst, t->is_ip6))
		{
		      if (!ip46_address_is_multicast (&t->dst))
			{
			  vtep_addr_unref (&t->src);
			  #if 0
			  fib_entry_child_remove (t->fib_entry_index, t->sibling_index);
			  #endif
			  fib_table_entry_delete_index (t->fib_entry_index, FIB_SOURCE_RR);
			}


	     		fib_node_deinit (&t->node);
	      }
	}
	vec_free (t->rewrite);
     
      pool_put (gtm->tunnels, t);

  return 0;
}

int vnet_ppf_gtpu_add_tunnel_in_call
  (vnet_ppf_gtpu_add_del_tunnel_args_t * a, u32 * sw_if_indexp, u32 *tunnel_id_ret)

 {
	ppf_main_t *pm = &ppf_main;

	ppf_callline_t *call_line = 0;
	ppf_gtpu_tunnel_id_type_t *tunnel;

	if (a->call_id >= pm->max_capacity) {
		return VNET_API_ERROR_WRONG_MAX_SESSION_NUM;
  	}

	call_line = &(pm->ppf_calline_table [a->call_id]);

	if (call_line->call_index == ~0) 
	{
		return VNET_API_ERROR_EMPTY_CALLINE;
	}

	if (a->tunnel_type == PPF_GTPU_NB) {
	
		if (call_line->call_type != PPF_DRB_CALL) 		
			return VNET_API_ERROR_WRONG_TUNNEL_TYPE;
			
		tunnel = &(call_line->rb.drb.nb_tunnel);
		
		if (tunnel->tunnel_id != INVALID_TUNNEL_ID)
			return VNET_API_ERROR_TUNNEL_IN_USE;
			
	} else if (a->tunnel_type == PPF_GTPU_SB) {
	
		if (call_line->call_type != PPF_DRB_CALL) 		
			return VNET_API_ERROR_WRONG_TUNNEL_TYPE;
			
		tunnel = &(call_line->rb.drb.sb_tunnel[a->sb_id]);
		
		if (tunnel->tunnel_id != INVALID_TUNNEL_ID)
			return VNET_API_ERROR_TUNNEL_IN_USE;
			
	else if (a->tunnel_type == PPF_GTPU_SRB) {
				
			if (call_line->call_type != PPF_SRB_CALL) 		
				return VNET_API_ERROR_WRONG_TUNNEL_TYPE;
				
			tunnel = &(call_line->rb.srb.sb_tunnel[a->sb_id]);
			
			if (tunnel->tunnel_id != INVALID_TUNNEL_ID)
				return VNET_API_ERROR_TUNNEL_IN_USE;
				
		}	
	} 

	return vnet_ppf_gtpu_add_tunnel (a, sw_if_indexp, tunnel_id_ret);
 }

int vnet_ppf_gtpu_del_tunnel_in_call
  (vnet_ppf_gtpu_add_del_tunnel_args_t * a) 
 {

	ppf_main_t *pm = &ppf_main;

	ppf_callline_t *call_line = 0;
	ppf_gtpu_tunnel_id_type_t *tunnel;
	u32 tunnel_id = INVALID_TUNNEL_ID;

	if (a->call_id >= pm->max_capacity) {
		return VNET_API_ERROR_WRONG_MAX_SESSION_NUM;
  	}

	call_line = &(pm->ppf_calline_table [a->call_id]);

	if (call_line->call_index == ~0) 
	{
		return VNET_API_ERROR_EMPTY_CALLINE;
	}

	if (a->tunnel_type == PPF_GTPU_NB) {
	
		if (call_line->call_type != PPF_DRB_CALL) 		
			return VNET_API_ERROR_WRONG_TUNNEL_TYPE;
			
		tunnel = &(call_line->rb.drb.nb_tunnel);
		
		if (tunnel->tunnel_id == INVALID_TUNNEL_ID)
			return VNET_API_ERROR_TUNNEL_IS_EMPTY;

		tunnel_id = tunnel->tunnel_id;
	} else if (a->tunnel_type == PPF_GTPU_SB) {
	
		if (call_line->call_type != PPF_DRB_CALL) 		
			return VNET_API_ERROR_WRONG_TUNNEL_TYPE;
			
		tunnel = &(call_line->rb.drb.sb_tunnel[a->sb_id]);
		
		if (tunnel->tunnel_id == INVALID_TUNNEL_ID)
			return VNET_API_ERROR_TUNNEL_IS_EMPTY;

		tunnel_id = tunnel->tunnel_id;
	} else if (a->tunnel_type == PPF_GTPU_SRB) {
	
		if (call_line->call_type != PPF_SRB_CALL) 		
			return VNET_API_ERROR_WRONG_TUNNEL_TYPE;
			
		tunnel = &(call_line->rb.srb.sb_tunnel[a->sb_id]);
		
		if (tunnel->tunnel_id == INVALID_TUNNEL_ID)
			return VNET_API_ERROR_TUNNEL_IS_EMPTY;

		tunnel_id = tunnel->tunnel_id;
	}

 	return vnet_ppf_gtpu_del_tunnel (tunnel_id);
 }

 
 int vnet_ppf_gtpu_update_tunnel_in_call
   (vnet_ppf_gtpu_add_del_tunnel_args_t * a)
 
 {
	 ppf_main_t *pm = &ppf_main;
	 ppf_gtpu_main_t *gtm = &ppf_gtpu_main;
 
	 ppf_callline_t *call_line = 0;
	 ppf_gtpu_tunnel_id_type_t *tunnel = 0;
	 u32 tunnel_id = INVALID_TUNNEL_ID;
	 ppf_gtpu_tunnel_t *t = 0;
 
	 if (a->call_id >= pm->max_capacity) {
		 return VNET_API_ERROR_WRONG_MAX_SESSION_NUM;
	 }
 
	 call_line = &(pm->ppf_calline_table [a->call_id]);
 
	 if (call_line->call_index == ~0) 
	 {
		 return VNET_API_ERROR_EMPTY_CALLINE;
	 }
 
	 if (a->tunnel_type == PPF_GTPU_NB) {
	 
		 if (call_line->call_type != PPF_DRB_CALL)		 
			 return VNET_API_ERROR_WRONG_TUNNEL_TYPE;
			 
		 tunnel = &(call_line->rb.drb.nb_tunnel);
		 
		 if (tunnel->tunnel_id == INVALID_TUNNEL_ID)
			 return VNET_API_ERROR_TUNNEL_IS_EMPTY;

	 	 tunnel_id = tunnel->tunnel_id;
			 
	 } else if (a->tunnel_type == PPF_GTPU_SB) {
	 
		 if (call_line->call_type != PPF_DRB_CALL)		 
			 return VNET_API_ERROR_WRONG_TUNNEL_TYPE;
			 
		 tunnel = &(call_line->rb.drb.sb_tunnel[a->sb_id]);
		 
		 if (tunnel->tunnel_id == INVALID_TUNNEL_ID)
			 return VNET_API_ERROR_TUNNEL_IS_EMPTY;

             tunnel_id = tunnel->tunnel_id;			
			 
	 } else if (a->tunnel_type == PPF_GTPU_SRB) {
				 
			 if (call_line->call_type != PPF_SRB_CALL)		 
				 return VNET_API_ERROR_WRONG_TUNNEL_TYPE;
				 
			 tunnel = &(call_line->rb.srb.sb_tunnel[a->sb_id]);
			 
			 if (tunnel->tunnel_id == INVALID_TUNNEL_ID)
				 return VNET_API_ERROR_TUNNEL_IN_USE;

			 tunnel_id = tunnel->tunnel_id;			 
 
	 } 

	 t = &(gtm->tunnels[tunnel_id]);

	 if (a->is_ip6 != t->is_ip6) {
		return VNET_API_ERROR_UPDATE_TUNNEL_WRONG_IP;
	 }

	 if (ip46_address_cmp (&(t->src), &(a->dst)) == 0)
	 {
	 	return VNET_API_ERROR_SAME_SRC_DST;
	 }

	 return vnet_ppf_gtpu_update_tunnel (tunnel_id, a);
 }


static uword
get_decap_next_for_node (u32 node_index, u32 ipv4_set)
{
  ppf_gtpu_main_t *gtm = &ppf_gtpu_main;
  vlib_main_t *vm = gtm->vlib_main;
  uword input_node = (ipv4_set) ? ppf_gtpu4_input_node.index :
    ppf_gtpu6_input_node.index;

  return vlib_node_add_next (vm, input_node, node_index);
}

static uword
unformat_decap_next (unformat_input_t * input, va_list * args)
{
  u32 *result = va_arg (*args, u32 *);
  u32 ipv4_set = va_arg (*args, int);
  ppf_gtpu_main_t *gtm = &ppf_gtpu_main;
  vlib_main_t *vm = gtm->vlib_main;
  u32 node_index;
  u32 tmp;

  if (unformat (input, "l2"))
    *result = PPF_GTPU_INPUT_NEXT_L2_INPUT;
  else if (unformat (input, "ip4"))
    *result = PPF_GTPU_INPUT_NEXT_IP4_INPUT;
  else if (unformat (input, "ip6"))
    *result = PPF_GTPU_INPUT_NEXT_IP6_INPUT;
  else if (unformat (input, "node %U", unformat_vlib_node, vm, &node_index))
    *result = get_decap_next_for_node (node_index, ipv4_set);
  else if (unformat (input, "%d", &tmp))
    *result = tmp;
  else
    return 0;

  return 1;
}

static uword
unformat_ppf_gtpu_tunnel_type (unformat_input_t * input, va_list * args)
{
  u32 *result = va_arg (*args, u32 *);
  
  if (unformat (input, "sb"))
    *result = PPF_GTPU_SB;
  else if (unformat (input, "nb"))
    *result = PPF_GTPU_NB;
  else if (unformat (input, "srb"))
    *result = PPF_GTPU_SRB;
  else if (unformat (input, "lbo"))
    *result = PPF_GTPU_LBO;
  else
  	return 0;

  return 1;
}



static clib_error_t *
ppf_gtpu_add_del_tunnel_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip46_address_t src, dst;
  u8 is_add = 1;
  u8 src_set = 0;
  u8 dst_set = 0;
  u8 grp_set = 0;
  u8 ipv4_set = 0;
  u8 is_ip6 = 0;
  u32 mcast_sw_if_index = ~0;
  u32 call_id = ~0, sb_id = ~0, in_teid = ~0,  tunnel_type = ~0;
  u32 encap_fib_index = 0;
  u32 out_teid = 0;
  u32 decap_next_index = ~0;
  u32 dst_port = UDP_DST_PORT_GTPU, dscp = 0, protocol_config = 0, ep_weight = 0, traffic_state = 0, type = 0;
  u32 tmp;
  int rv;
  vnet_ppf_gtpu_add_del_tunnel_args_t _a, *a = &_a;
  u32 tunnel_sw_if_index;
  clib_error_t *error = NULL;
  u32 tunnel_id = INVALID_TUNNEL_ID;

  /* Cant "universally zero init" (={0}) due to GCC bug 53119 */
  memset (&src, 0, sizeof src);
  memset (&dst, 0, sizeof dst);

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (line_input, "src %U",
			 unformat_ip4_address, &src.ip4))
	{
	  src_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "dst %U",
			 unformat_ip4_address, &dst.ip4))
	{
	  dst_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "src %U",
			 unformat_ip6_address, &src.ip6))
	{
	  src_set = 1;
	  is_ip6 = 1;
	}
      else if (unformat (line_input, "dst %U",
			 unformat_ip6_address, &dst.ip6))
	{
	  dst_set = 1;
	  is_ip6 = 1;
	}
      else if (unformat (line_input, "group %U %U",
			 unformat_ip4_address, &dst.ip4,
			 unformat_vnet_sw_interface,
			 vnet_get_main (), &mcast_sw_if_index))
	{
	  grp_set = dst_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "group %U %U",
			 unformat_ip6_address, &dst.ip6,
			 unformat_vnet_sw_interface,
			 vnet_get_main (), &mcast_sw_if_index))
	{
	  grp_set = dst_set = 1;
	  is_ip6 = 1;
	}
      else if (unformat (line_input, "encap-vrf-id %d", &tmp))
	{
	  encap_fib_index = fib_table_find (fib_ip_proto (is_ip6), tmp);
	  if (encap_fib_index == ~0)
	    {
	      error =
		clib_error_return (0, "nonexistent encap-vrf-id %d", tmp);
	      goto done;
	    }
	}
	else if (unformat (line_input, "call-id %d", &call_id))
	;
	else if (unformat (line_input, "tunnel-type %U", unformat_ppf_gtpu_tunnel_type, &tunnel_type))
	;
	else if (unformat (line_input, "inteid %d", &in_teid))
	;
	else if (unformat (line_input, "sb_id %d", &sb_id))
	;
      else if (unformat (line_input, "decap-next %U", unformat_decap_next,
			 &decap_next_index, ipv4_set))
	;
	else if (unformat (line_input, "outteid %d", &out_teid))
	;
	else if (unformat (line_input, "dst_port %d", &dst_port))
	;
	else if (unformat (line_input, "dscp %d", &dscp))
	;
	else if (unformat (line_input, "protocol_config %d", &protocol_config))
	;
	else if (unformat (line_input, "ep_weight %d", &ep_weight))
	;
	else if (unformat (line_input, "traffic_state %d", &traffic_state))
	;
	else if (unformat (line_input, "type %d", &type))
	;
      else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (src_set == 0)
    {
      error = clib_error_return (0, "tunnel src address not specified");
      goto done;
    }

  if (dst_set == 0)
    {
      error = clib_error_return (0, "tunnel dst address not specified");
      goto done;
    }

  if (grp_set && !ip46_address_is_multicast (&dst))
    {
      error = clib_error_return (0, "tunnel group address not multicast");
      goto done;
    }

  if (grp_set == 0 && ip46_address_is_multicast (&dst))
    {
      error = clib_error_return (0, "dst address must be unicast");
      goto done;
    }

  if (grp_set && mcast_sw_if_index == ~0)
    {
      error = clib_error_return (0, "tunnel nonexistent multicast device");
      goto done;
    }

  if (ipv4_set && is_ip6)
    {
      error = clib_error_return (0, "both IPv4 and IPv6 addresses specified");
      goto done;
    }

  if (ip46_address_cmp (&src, &dst) == 0)
    {
      error = clib_error_return (0, "src and dst addresses are identical");
      goto done;
    }
  if (call_id == ~0) 
   {
      error = clib_error_return (0, "tunnel call id not specified");
      goto done;
    }
  if (tunnel_type == ~0) 
   {
      error = clib_error_return (0, "tunnel type not specified");
      goto done;
    }
   if ((tunnel_type == PPF_GTPU_SRB|| tunnel_type == PPF_GTPU_SB ) && (sb_id == ~0))
    {
	error = clib_error_return (0, "sb_id is not specified for sb tunnel");
      goto done;	
    }

  if (is_add == 1 && in_teid == ~0) 
   {
      error = clib_error_return (0, "tunnel in-teid not specified for added tunnel");
      goto done;
   }
	  
  memset (a, 0, sizeof (*a));

//  a->is_add = is_add;
//  a->is_ip6 = ipv6_set;

  if (is_add) {
 #define _(x) a->x = x;
  	install_tunnel_copy;
#undef _
  	rv = vnet_ppf_gtpu_add_tunnel_in_call (a, &tunnel_sw_if_index, &tunnel_id);

  } else {
#define _(x) a->x = x;
  	delete_tunnel_copy;
#undef _
  	rv = vnet_ppf_gtpu_del_tunnel_in_call (a);
  }
  
  switch (rv)
    {
    case 0:
      if (is_add)
	vlib_cli_output (vm, "%U decap-next: %d, call_id: %d, tunnel_type: %d", format_vnet_sw_if_index_name,
			 vnet_get_main (), tunnel_sw_if_index,
			 a->decap_next_index, a->call_id, a->tunnel_type);
      break;

    case VNET_API_ERROR_TUNNEL_EXIST:
      error = clib_error_return (0, "tunnel already exists...");
      goto done;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "tunnel does not exist...");
      goto done;

    case VNET_API_ERROR_NEXT_HOP_NOT_FOUND_MP:
      error = clib_error_return (0, "can not find decap next index for the tunnel");
      goto done;

    case VNET_API_ERROR_WRONG_MAX_SESSION_NUM:
      error = clib_error_return (0, "wrong call id number");
      goto done;
 
    case VNET_API_ERROR_EMPTY_CALLINE:
	error = clib_error_return (0, "call line is not existed");
	goto done;
    
    case VNET_API_ERROR_WRONG_TUNNEL_TYPE:
    	error = clib_error_return (0, "wrong tunnel type");
	goto done;
		    
    case VNET_API_ERROR_TUNNEL_IN_USE:
      error = clib_error_return (0, "the added tunnel is not empty");
	goto done;

    case VNET_API_ERROR_TUNNEL_IS_EMPTY:
    	error = clib_error_return (0, "the deleted tunnel is empty");
	goto done;
	
    default:
      error = clib_error_return
	(0, "vnet_ppf_gtpu_add_del_tunnel returned %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

/*?
 * Add or delete a PPF_GTPU Tunnel.
 *
 * PPF_GTPU provides the features needed to allow L2 bridge domains (BDs)
 * to span multiple servers. This is done by building an L2 overlay on
 * top of an L3 network underlay using PPF_GTPU tunnels.
 *
 * This makes it possible for servers to be co-located in the same data
 * center or be separated geographically as long as they are reachable
 * through the underlay L3 network.
 *
 * You can refer to this kind of L2 overlay bridge domain as a PPF_GTPU
 * (Virtual eXtensible VLAN) segment.
 *
 * @cliexpar
 * Example of how to create a PPF_GTPU Tunnel:
 * @cliexcmd{create ppf_gtpu tunnel src 10.0.3.1 dst 10.0.3.3 teid 13 encap-vrf-id 7}
 * Example of how to delete a PPF_GTPU Tunnel:
 * @cliexcmd{create ppf_gtpu tunnel src 10.0.3.1 dst 10.0.3.3 teid 13 del}
 ?*/
/* *INDENT-OFF* */

VLIB_CLI_COMMAND (create_ppf_gtpu_tunnel_command, static) = {
  .path = "create ppf_gtpu tunnel",
  .short_help =	  
  "create ppf_gtpu tunnel src <local-vtep-addr>"
  " {dst <remote-vtep-addr>|group <mcast-vtep-addr> <intf-name>} "  
  " call-id <nn> tunnel-type <nn> sb_id <nn> "
  " [inteid <nn>] [outteid <nn>] [encap-vrf-id <nn>] [decap-next [l2|ip4|ip6|node <name>]] ",
  " [dst_port <nn>] [dscp <nn>] [protocol_config <nn>] [ep_weight <ep_weight>] [traffic_state <nn>] [type <nn>] [del]",
  .function = ppf_gtpu_add_del_tunnel_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
ppf_gtpu_modify_tunnel_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip46_address_t dst;
  u8 is_ip6 = 0;
  u32 call_id = ~0, sb_id = ~0,  tunnel_type = ~0;
  u32 out_teid = ~0, dst_port = ~0, dscp = ~0, protocol_config = ~0, ep_weight = ~0, traffic_state = ~0, type = ~0;
  int rv;
  vnet_ppf_gtpu_add_del_tunnel_args_t _a, *a = &_a;
  clib_error_t *error = NULL;

  /* Cant "universally zero init" (={0}) due to GCC bug 53119 */
  memset (&dst, 0, sizeof dst);

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
    	if (unformat (line_input, "call-id %d", &call_id))
	;
	else if (unformat (line_input, "tunnel-type %U", unformat_ppf_gtpu_tunnel_type, &tunnel_type))
	;
	else if (unformat (line_input, "sb_id %d", &sb_id))
	;
      else if (unformat (line_input, "dst %U",
			 unformat_ip4_address, &dst.ip4))
	;
      else if (unformat (line_input, "dst %U",
			 unformat_ip6_address, &dst.ip6))
	{
	  is_ip6 = 1;
	}
	else if (unformat (line_input, "outteid %d", &out_teid))
	;
	else if (unformat (line_input, "dst_port %d", &dst_port))
	;
	else if (unformat (line_input, "dscp %d", &dscp))
	;
	else if (unformat (line_input, "protocol_config %d", &protocol_config))
	;
	else if (unformat (line_input, "ep_weight %d", &ep_weight))
	;
	else if (unformat (line_input, "traffic_state %d", &traffic_state))
	;
	else if (unformat (line_input, "type %d", &type))
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
      error = clib_error_return (0, "tunnel call id not specified");
      goto done;
    }
  if (tunnel_type == ~0) 
   {
      error = clib_error_return (0, "tunnel type not specified");
      goto done;
    }
   if ((tunnel_type == PPF_GTPU_SRB|| tunnel_type == PPF_GTPU_SB ) && (sb_id == ~0))
    {
	error = clib_error_return (0, "sb_id is not specified for sb tunnel");
      goto done;	
    }
    
  memset (a, 0, sizeof (*a));

#define _(x) a->x = x;
  update_tunnel_copy;
#undef _
  rv = vnet_ppf_gtpu_update_tunnel_in_call (a);

  switch (rv)
    {
    case 0:
	vlib_cli_output (vm, "%U call_id: %d, tunnel_type: %d", format_vnet_sw_if_index_name,
			 vnet_get_main (), 
			 a->decap_next_index, a->call_id, a->tunnel_type);
      break;

    case VNET_API_ERROR_TUNNEL_EXIST:
      error = clib_error_return (0, "tunnel already exists...");
      goto done;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "tunnel does not exist...");
      goto done;

    case VNET_API_ERROR_NEXT_HOP_NOT_FOUND_MP:
      error = clib_error_return (0, "can not find decap next index for the tunnel");
      goto done;

    case VNET_API_ERROR_WRONG_MAX_SESSION_NUM:
      error = clib_error_return (0, "wrong call id number");
      goto done;
 
    case VNET_API_ERROR_EMPTY_CALLINE:
	error = clib_error_return (0, "call line is not existed");
	goto done;
    
    case VNET_API_ERROR_WRONG_TUNNEL_TYPE:
    	error = clib_error_return (0, "wrong tunnel type");
	goto done;
		    
    case VNET_API_ERROR_TUNNEL_IN_USE:
      error = clib_error_return (0, "the added tunnel is not empty");
	goto done;

    case VNET_API_ERROR_TUNNEL_IS_EMPTY:
    	error = clib_error_return (0, "the deleted tunnel is empty");
	goto done;
	
    default:
      error = clib_error_return
	(0, "vnet_ppf_gtpu_add_del_tunnel returned %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}


VLIB_CLI_COMMAND (modify_ppf_gtpu_tunnel_command, static) = {
  .path = "modify ppf_gtpu tunnel",
  .short_help =	  
  "modify ppf_gtpu tunnel "
  " call-id <nn> tunnel-type <nn> sb_id <nn>  "  
  " [dst <remote-vtep-addr>] [outteid <nn>] ",
  " [dst_port <nn>] [dscp <nn>] [protocol_config <nn>] [ep_weight <ep_weight>] [traffic_state <nn>] [type <nn>] [del]",
  .function = ppf_gtpu_modify_tunnel_command_fn,
};


static clib_error_t *
show_ppf_gtpu_tunnel_command_fn (vlib_main_t * vm,
			     unformat_input_t * input,
			     vlib_cli_command_t * cmd)
{
  ppf_gtpu_main_t *gtm = &ppf_gtpu_main;
  ppf_gtpu_tunnel_t *t;

  if (pool_elts (gtm->tunnels) == 0)
    vlib_cli_output (vm, "No ppf_gtpu tunnels configured...");

  pool_foreach (t, gtm->tunnels, (
				   {
				   vlib_cli_output (vm, "%U",
						    format_ppf_gtpu_tunnel, t);
				   }
		));

  return 0;
}

/*?
 * Display all the PPF_GTPU Tunnel entries.
 *
 * @cliexpar
 * Example of how to display the PPF_GTPU Tunnel entries:
 * @cliexstart{show ppf_gtpu tunnel}
 * [0] src 10.0.3.1 dst 10.0.3.3 teid 13 encap_fib_index 0 sw_if_index 5 decap_next l2
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_ppf_gtpu_tunnel_command, static) = {
    .path = "show ppf_gtpu tunnel",
    .short_help = "show ppf_gtpu tunnel",
    .function = show_ppf_gtpu_tunnel_command_fn,
};
/* *INDENT-ON* */

void
vnet_int_ppf_gtpu_bypass_mode (u32 sw_if_index, u8 is_ip6, u8 is_enable)
{
  if (is_ip6)
    vnet_feature_enable_disable ("ip6-unicast", "ip6-ppf_gtpu-bypass",
				 sw_if_index, is_enable, 0, 0);
  else
    vnet_feature_enable_disable ("ip4-unicast", "ip4-ppf_gtpu-bypass",
				 sw_if_index, is_enable, 0, 0);
}

static clib_error_t *
set_ip_ppf_gtpu_bypass (u32 is_ip6,
		    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  clib_error_t *error = 0;
  u32 sw_if_index, is_enable;

  sw_if_index = ~0;
  is_enable = 1;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat_user
	  (line_input, unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (line_input, "del"))
	is_enable = 0;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (~0 == sw_if_index)
    {
      error = clib_error_return (0, "unknown interface `%U'",
				 format_unformat_error, line_input);
      goto done;
    }

  vnet_int_ppf_gtpu_bypass_mode (sw_if_index, is_ip6, is_enable);

done:
  unformat_free (line_input);

  return error;
}

static clib_error_t *
set_ip4_ppf_gtpu_bypass (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  return set_ip_ppf_gtpu_bypass (0, input, cmd);
}

/*?
 * This command adds the 'ip4-ppf_gtpu-bypass' graph node for a given interface.
 * By adding the IPv4 ppf_gtpu-bypass graph node to an interface, the node checks
 *  for and validate input ppf_gtpu packet and bypass ip4-lookup, ip4-local,
 * ip4-udp-lookup nodes to speedup ppf_gtpu packet forwarding. This node will
 * cause extra overhead to for non-ppf_gtpu packets which is kept at a minimum.
 *
 * @cliexpar
 * @parblock
 * Example of graph node before ip4-ppf_gtpu-bypass is enabled:
 * @cliexstart{show vlib graph ip4-ppf_gtpu-bypass}
 *            Name                      Next                    Previous
 * ip4-ppf_gtpu-bypass                error-drop [0]
 *                                ppf_gtpu4-input [1]
 *                                 ip4-lookup [2]
 * @cliexend
 *
 * Example of how to enable ip4-ppf_gtpu-bypass on an interface:
 * @cliexcmd{set interface ip ppf_gtpu-bypass GigabitEthernet2/0/0}
 *
 * Example of graph node after ip4-ppf_gtpu-bypass is enabled:
 * @cliexstart{show vlib graph ip4-ppf_gtpu-bypass}
 *            Name                      Next                    Previous
 * ip4-ppf_gtpu-bypass                error-drop [0]               ip4-input
 *                                ppf_gtpu4-input [1]        ip4-input-no-checksum
 *                                 ip4-lookup [2]
 * @cliexend
 *
 * Example of how to display the feature enabed on an interface:
 * @cliexstart{show ip interface features GigabitEthernet2/0/0}
 * IP feature paths configured on GigabitEthernet2/0/0...
 * ...
 * ipv4 unicast:
 *   ip4-ppf_gtpu-bypass
 *   ip4-lookup
 * ...
 * @cliexend
 *
 * Example of how to disable ip4-ppf_gtpu-bypass on an interface:
 * @cliexcmd{set interface ip ppf_gtpu-bypass GigabitEthernet2/0/0 del}
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_interface_ip_ppf_gtpu_bypass_command, static) = {
  .path = "set interface ip ppf_gtpu-bypass",
  .function = set_ip4_ppf_gtpu_bypass,
  .short_help = "set interface ip ppf_gtpu-bypass <interface> [del]",
};
/* *INDENT-ON* */

static clib_error_t *
set_ip6_ppf_gtpu_bypass (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  return set_ip_ppf_gtpu_bypass (1, input, cmd);
}

/*?
 * This command adds the 'ip6-ppf_gtpu-bypass' graph node for a given interface.
 * By adding the IPv6 ppf_gtpu-bypass graph node to an interface, the node checks
 *  for and validate input ppf_gtpu packet and bypass ip6-lookup, ip6-local,
 * ip6-udp-lookup nodes to speedup ppf_gtpu packet forwarding. This node will
 * cause extra overhead to for non-ppf_gtpu packets which is kept at a minimum.
 *
 * @cliexpar
 * @parblock
 * Example of graph node before ip6-ppf_gtpu-bypass is enabled:
 * @cliexstart{show vlib graph ip6-ppf_gtpu-bypass}
 *            Name                      Next                    Previous
 * ip6-ppf_gtpu-bypass                error-drop [0]
 *                                ppf_gtpu6-input [1]
 *                                 ip6-lookup [2]
 * @cliexend
 *
 * Example of how to enable ip6-ppf_gtpu-bypass on an interface:
 * @cliexcmd{set interface ip6 ppf_gtpu-bypass GigabitEthernet2/0/0}
 *
 * Example of graph node after ip6-ppf_gtpu-bypass is enabled:
 * @cliexstart{show vlib graph ip6-ppf_gtpu-bypass}
 *            Name                      Next                    Previous
 * ip6-ppf_gtpu-bypass                error-drop [0]               ip6-input
 *                                ppf_gtpu6-input [1]        ip4-input-no-checksum
 *                                 ip6-lookup [2]
 * @cliexend
 *
 * Example of how to display the feature enabed on an interface:
 * @cliexstart{show ip interface features GigabitEthernet2/0/0}
 * IP feature paths configured on GigabitEthernet2/0/0...
 * ...
 * ipv6 unicast:
 *   ip6-ppf_gtpu-bypass
 *   ip6-lookup
 * ...
 * @cliexend
 *
 * Example of how to disable ip6-ppf_gtpu-bypass on an interface:
 * @cliexcmd{set interface ip6 ppf_gtpu-bypass GigabitEthernet2/0/0 del}
 * @endparblock
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (set_interface_ip6_ppf_gtpu_bypass_command, static) = {
  .path = "set interface ip6 ppf_gtpu-bypass",
  .function = set_ip6_ppf_gtpu_bypass,
  .short_help = "set interface ip ppf_gtpu-bypass <interface> [del]",
};
/* *INDENT-ON* */


int
ppf_gtpu_tunnels_init()
{
  ppf_gtpu_main_t *gtm = &ppf_gtpu_main;
  ip46_address_t src, dst;
  u32 encap_fib_index = 0;
  u32 mcast_sw_if_index = ~0;
  u32 decap_next_index = PPF_GTPU_INPUT_NEXT_IP4_INPUT;
  u32 in_teid = gtm->start_teid;
  u32 out_teid = gtm->start_teid;
  int rv;
  vnet_ppf_gtpu_add_del_tunnel_args_t _a, *a = &_a;
  u32 tunnel_sw_if_index;
  u32 i;
  u32 call_id = 0;
  u32 tunnel_type = 0;
  u32 sb_id = 0;

  /* Cant "universally zero init" (={0}) due to GCC bug 53119 */
  memset (&src, 0, sizeof src);
  memset (&dst, 0, sizeof dst);
  src = gtm->src;
  dst = gtm->dst;

  memset (a, 0, sizeof (*a));

  a->is_add = 1;
  a->is_ip6 = 0;
#define _(x) a->x = x;
    foreach_copy_field;
#undef _

  /* add */
  for (i = 0; i < gtm->prealloc_tunnels; i++,a->in_teid++,a->out_teid++) {
    rv = vnet_ppf_gtpu_add_del_tunnel (a, &tunnel_sw_if_index);
    switch (rv)
      {
      case 0:
	break;
    
      case VNET_API_ERROR_TUNNEL_EXIST:
	clib_warning("tunnel already exists...");
	break;
	
      case VNET_API_ERROR_NO_SUCH_ENTRY:
	clib_warning ("tunnel does not exist...");
	break;
    
      default:
	clib_warning("vnet_ppf_gtpu_add_del_tunnel returned %d", rv);
	break;
      }
  }

  /* del */
  a->is_add = 0;
  a->in_teid = gtm->start_teid;
  a->out_teid = gtm->start_teid;
  for (i = 0; i < gtm->prealloc_tunnels; i++,a->in_teid++,a->out_teid++ ) {
    rv = vnet_ppf_gtpu_add_del_tunnel (a, &tunnel_sw_if_index);
    switch (rv)
      {
      case 0:
        break;
    
      case VNET_API_ERROR_TUNNEL_EXIST:
        clib_warning("tunnel already exists...");
        break;
        
      case VNET_API_ERROR_NO_SUCH_ENTRY:
        clib_warning ("tunnel does not exist...");
        break;
    
      default:
        clib_warning("vnet_ppf_gtpu_add_del_tunnel returned %d", rv);
        break;
      }
  }

  return 0;
}



/**************************Start of pg***************************/

#define PPF_GTPU_PG_EDIT_LENGTH (1 << 0)

typedef struct
{
  pg_edit_t ver_flags;
  pg_edit_t type;
  pg_edit_t length;
  pg_edit_t teid;
  pg_edit_t sequence;
  pg_edit_t pdu_number;
  pg_edit_t next_ext_type;
} pg_ppf_gtpu_header_t;

always_inline void
ppf_gtpu_pg_edit_function_inline (pg_main_t * pg,
                                       pg_stream_t * s,
                                       pg_edit_group_t * g,
                                       u32 * packets, u32 n_packets, u32 flags)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 gtpu_offset;

  gtpu_offset = g->start_byte_offset;

  while (n_packets >= 1)
    {
      vlib_buffer_t *p0;
      ppf_gtpu_header_t *gtpu0;
      u32 gtpu_len0;

      p0 = vlib_get_buffer (vm, packets[0]);
      n_packets -= 1;
      packets += 1;

      gtpu0 = (void *) (p0->data + gtpu_offset);
      gtpu_len0 = vlib_buffer_length_in_chain (vm, p0) - gtpu_offset - PPF_GTPU_HEADER_MIN;

      if (flags & PPF_GTPU_PG_EDIT_LENGTH)
        gtpu0->length = clib_host_to_net_u16 (gtpu_len0);
    }
}

static void
ppf_gtpu_pg_edit_function (pg_main_t * pg,
                               pg_stream_t * s,
                               pg_edit_group_t * g, u32 * packets, u32 n_packets)
{
  switch (g->edit_function_opaque)
  {
    case PPF_GTPU_PG_EDIT_LENGTH:
      ppf_gtpu_pg_edit_function_inline (pg, s, g, packets, n_packets,
                                       PPF_GTPU_PG_EDIT_LENGTH);
      break;

    default:
      ASSERT (0);
      break;
  }
}

static inline void
pg_ppf_gtpu_header_init (pg_ppf_gtpu_header_t * p)
{
  /* Initialize fields that are not bit fields in the IP header. */
#define _(f) pg_edit_init (&p->f, ppf_gtpu_header_t, f);
  _(ver_flags);
  _(type);
  _(length);
  _(teid);
  _(sequence);
  _(pdu_number);
  _(next_ext_type);
#undef _
}

uword
unformat_pg_ppf_gtpu_header (unformat_input_t * input, va_list * args)
{
  pg_stream_t *s = va_arg (*args, pg_stream_t *);
  unformat_input_t sub_input = { 0 };
  pg_ppf_gtpu_header_t *p;
  u32 group_index;

  p = pg_create_edit_group (s, sizeof (p[0]), sizeof (ppf_gtpu_header_t),
			    &group_index);
  pg_ppf_gtpu_header_init (p);

  /* Defaults. */
  pg_edit_set_fixed (&p->ver_flags, PPF_GTPU_V1_VER | PPF_GTPU_PT_GTP | PPF_GTPU_S_BIT);
  pg_edit_set_fixed (&p->type, PPF_GTPU_TYPE_PPF_GTPU);
  pg_edit_set_fixed (&p->sequence, 0);
  pg_edit_set_fixed (&p->pdu_number, 0);
  pg_edit_set_fixed (&p->next_ext_type, 0);
  
  p->teid.type   = PG_EDIT_UNSPECIFIED;
  p->length.type = PG_EDIT_UNSPECIFIED;

  if (!unformat (input, "GTPU %U", unformat_input, &sub_input))
    goto error;

  /* Parse options. */
  while (1)
    {
      if (unformat (&sub_input, "teid %U",
		    unformat_pg_edit, unformat_pg_number, &p->teid))
	    ;

      else if (unformat (&sub_input, "length %U",
			 unformat_pg_edit, unformat_pg_number, &p->length))
	    ;

      /* Can't parse input: try next protocol level. */
      else
	    break;
    }

  {
    if (!unformat_user (&sub_input, unformat_pg_payload, s))
      goto error;

    p = pg_get_edit_group (s, group_index);
    if (p->length.type == PG_EDIT_UNSPECIFIED)
    {
      pg_edit_group_t *g = pg_stream_get_group (s, group_index);
      g->edit_function = ppf_gtpu_pg_edit_function;
      g->edit_function_opaque = 0;
      if (p->length.type == PG_EDIT_UNSPECIFIED)
        g->edit_function_opaque |= PPF_GTPU_PG_EDIT_LENGTH;
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

static clib_error_t *
ppf_gtpu_config (vlib_main_t * vm, unformat_input_t * input)
{
  ppf_gtpu_main_t *gtm = &ppf_gtpu_main;
  clib_error_t *error = 0;

  gtm->prealloc_tunnels = 0;
  gtm->start_teid = 1;
  gtm->src.ip4.as_u32 = clib_host_to_net_u32(0x01010101);
  gtm->dst.ip4.as_u32 = clib_host_to_net_u32(0x02020202);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "src %U",
    		     unformat_ip4_address, &gtm->src.ip4))
        {
        }
      else if (unformat (input, "dst %U",
    		     unformat_ip4_address, &gtm->dst.ip4))
        {
        }
      else if (unformat (input, "teid %d", &gtm->start_teid))
        ;
      else if (unformat (input, "capacity %d", &gtm->prealloc_tunnels))
        ;
      else
        {
          return clib_error_return (0, "unknown input `%U'",
    				format_unformat_error, input);
        }
    }

  if (gtm->prealloc_tunnels > 0)
    ppf_gtpu_tunnels_init ();
  
  return error;
}

VLIB_CONFIG_FUNCTION (ppf_gtpu_config, "ppf_gtpu");


#define PPF_JTS_GTPU_PORT     54321

clib_error_t *
ppf_gtpu_init (vlib_main_t * vm)
{
  ppf_gtpu_main_t *gtm = &ppf_gtpu_main;
  udp_dst_port_info_t *pi;

  gtm->vnet_main = vnet_get_main ();
  gtm->vlib_main = vm;

  /* initialize the ip6 hash */
  gtm->ppf_gtpu6_tunnel_by_key = hash_create_mem (0,
					      sizeof (ppf_gtpu6_tunnel_key_t),
					      sizeof (uword));
  gtm->vtep6 = hash_create_mem (0, sizeof (ip6_address_t), sizeof (uword));
  gtm->mcast_shared = hash_create_mem (0,
				       sizeof (ip46_address_t),
				       sizeof (mcast_shared_t));


  if (PPFU_HANDOFF == 1) {
	udp_register_dst_port (vm, UDP_DST_PORT_GTPU,
			 worker_ppfu_handoff_node.index, /* is_ip4 */ 1);
	udp_register_dst_port (vm, UDP_DST_PORT_GTPU6,
			 worker_ppfu_handoff_node.index, /* is_ip4 */ 0);
  } else {
  	  udp_register_dst_port (vm, UDP_DST_PORT_GTPU,
				 ppf_gtpu4_input_node.index, /* is_ip4 */ 1);
	  udp_register_dst_port (vm, UDP_DST_PORT_GTPU6,
				 ppf_gtpu6_input_node.index, /* is_ip4 */ 0);
  }

  pi = udp_get_dst_port_info (&udp_main, UDP_DST_PORT_GTPU, 1);
  if (pi)
    pi->unformat_pg_edit = unformat_pg_ppf_gtpu_header;

  pi = udp_get_dst_port_info (&udp_main, UDP_DST_PORT_GTPU6, 0);
  if (pi)
    pi->unformat_pg_edit = unformat_pg_ppf_gtpu_header;

  /* Register RX node from JTS, by Jordy */
  udp_register_dst_port (vm, PPF_JTS_GTPU_PORT,
			 ppf_gtpu4_input_node.index, /* is_ip4 */ 1);

  pi = udp_get_dst_port_info (&udp_main, PPF_JTS_GTPU_PORT, 1);
  if (pi)
    pi->unformat_pg_edit = unformat_pg_ppf_gtpu_header;

  gtm->fib_node_type = fib_node_register_new_type (&ppf_gtpu_vft);

  return 0;
}

VLIB_INIT_FUNCTION (ppf_gtpu_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "PPF-GTPv1-U",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
