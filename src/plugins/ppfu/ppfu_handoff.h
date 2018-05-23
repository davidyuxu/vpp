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

#define PPFU_HANDOFF_QUEUE_HI_THRESHOLD 254

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

/*******************************3 layer handoff for PDCP Start****************************/

typedef enum
{
  PPF_PDCP_HANDOFF_DISPATCH_NEXT_DROP,
  PPF_PDCP_HANDOFF_DISPATCH_NEXT_PDCP_DECRYPT,
  PPF_PDCP_HANDOFF_DISPATCH_NEXT_PDCP_ENCRYPT,
  PPF_PDCP_HANDOFF_DISPATCH_N_NEXT,
} ppf_pdcp_handoff_dispatch_next_t;

#define foreach_ppf_pdcp_handoff_next    \
_(DROP, "error-drop")                    \
_(PDCP_DECRYPT, "ppf_pdcp_decrypt")      \
_(PDCP_ENCRYPT, "ppf_pdcp_encrypt")


typedef enum
{
  PPF_TX_HANDOFF_DISPATCH_NEXT_DROP,
  PPF_TX_HANDOFF_DISPATCH_NEXT_GTPU4_ENCAP,
  PPF_TX_HANDOFF_DISPATCH_NEXT_GTPU6_ENCAP,
  PPF_TX_HANDOFF_DISPATCH_NEXT_SRB_NB_TX,
  PPF_TX_HANDOFF_DISPATCH_NEXT_IP4_LOOKUP,
  PPF_TX_HANDOFF_DISPATCH_NEXT_IP6_LOOKUP,
  PPF_TX_HANDOFF_DISPATCH_N_NEXT,
} ppf_tx_handoff_dispatch_next_t;

#define foreach_ppf_tx_handoff_next      \
_(DROP, "error-drop")                    \
_(GTPU4_ENCAP, "ppf_gtpu4-encap")        \
_(GTPU6_ENCAP, "ppf_gtpu6-encap")        \
_(SRB_NB_TX, "ppf_srb_nb_tx")            \
_(IP4_LOOKUP, "ip4-lookup")              \
_(IP6_LOOKUP, "ip6-lookup")


/*******************************3 layer handoff for PDCP End****************************/


#endif /* included_ppfu_handoff_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
