/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#ifndef included_ppfu_handoff_h
#define included_ppfu_handoff_h

#include <vlib/vlib.h>
#include <ppfu/ppf_gtpu.h>

#define PPFU_HANDOFF_QUEUE_HI_THRESHOLD 30

typedef enum
{
  PPFU_HANDOFF_DISPATCH_NEXT_DROP,
  PPFU_HANDOFF_DISPATCH_NEXT_GTPU_IP4_INPUT,
  PPFU_HANDOFF_DISPATCH_NEXT_GTPU_IP6_INPUT,
  PPFU_HANDOFF_DISPATCH_N_NEXT,
} ppfu_handoff_dispatch_next_t;

#define foreach_ppfu_handoff_next        \
_(DROP, "error-drop")                  \
_(GTPU_IP4_INPUT, "ppf_gtpu4-input")             \
_(GTPU_IP6_INPUT, "ppf_gtpu6-input")

static inline u32
ppfu_gtpu_get_key (ppf_gtpu_header_t * gtph)
{
  u32 hash_key;

  u32 teid = clib_host_to_net_u32(gtph->teid);

  hash_key = 0x3fffffff & teid;

  return hash_key;
}

#endif /* included_ppfu_handoff_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
