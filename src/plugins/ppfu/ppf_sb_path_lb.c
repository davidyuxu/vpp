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
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <ppfu/ppfu.h>


/* Statistics (not all errors) */

#define foreach_ppf_sb_path_lb_error    \
_(ENCAPSULATED, "good packets encapsulated")

static char * ppf_sb_path_lb_error_strings[] = {
#define _(sym,string) string,
  foreach_ppf_sb_path_lb_error
#undef _
};

typedef enum {
#define _(sym,str) PPF_SB_PATH_LB_ERROR_##sym,
    foreach_ppf_sb_path_lb_error
#undef _
    PPF_sb_path_lb_N_ERROR,
} ppf_sb_path_lb_error_t;


typedef struct {
  u32 tunnel_index;
} ppf_sb_path_lb_trace_t;

u8 * format_ppf_sb_path_lb_trace  (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  return s;
}

always_inline uword
ppf_sb_path_lb_inline (vlib_main_t * vm,
		    vlib_node_runtime_t * node,
		    vlib_frame_t * from_frame,
		    u32 is_ip4)
{

  return 0;
 }

static uword
ppf_sb_path_lb (vlib_main_t * vm,
	      vlib_node_runtime_t * node,
	      vlib_frame_t * from_frame)
{
  return ppf_sb_path_lb_inline (vm, node, from_frame, /* is_ip4 */ 1);
}


VLIB_NODE_FUNCTION_MULTIARCH (ppf_sb_path_lb_node, ppf_sb_path_lb)

VLIB_REGISTER_NODE (ppf_sb_path_lb_node) = {
  .function = ppf_sb_path_lb,
  .name = "ppf_sb_path_lb",
  .vector_size = sizeof (u32),
  .format_trace = format_ppf_sb_path_lb_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(ppf_sb_path_lb_error_strings),
  .error_strings = ppf_sb_path_lb_error_strings,
  .n_next_nodes = PPF_SB_PATH_LB_N_NEXT,
  .next_nodes = {
#define _(s,n) [PPF_SB_PATH_LB_NEXT_##s] = n,
    foreach_ppf_sb_path_lb_next
#undef _
  },
};


