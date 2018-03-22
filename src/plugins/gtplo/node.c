/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ip/ip4_packet.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>

#include <gtplo/gtplo.h>

typedef enum {
  GTPLO_NEXT_IP4_INPUT,
  DECTTL_INPUT_NEXT_DROP,
  GTPLO_N_NEXT,
} gtplo_next_t;


typedef struct {
  gtplo_next_t next_index;
  u32 sw_if_index;
  ip4_address_t orig_src_ip;
  ip4_address_t orig_dst_ip;
  ip4_address_t new_src_ip;
  ip4_address_t new_dst_ip;
} gtplo_trace_t;

/* packet trace format function */
static u8 * format_gtplo_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  gtplo_trace_t * t = va_arg (*args, gtplo_trace_t *);
  
  s = format (s, "GTP Loopback: sw_if_index %d, next index %d\n",
              t->sw_if_index, t->next_index);
  s = format (s, "  original src %U -> original dst %U \n",
              format_ip4_address, &t->orig_src_ip, 
              format_ip4_address, &t->orig_dst_ip);
  s = format (s, "  new src %U -> new dst %U",
              format_ip4_address, &t->new_src_ip, 
              format_ip4_address, &t->new_dst_ip);

  return s;
}

vlib_node_registration_t gtplo_node;

#define foreach_gtplo_error \
_(GTPLO, "GTP Loopback packets processed")

typedef enum {
#define _(sym,str) GTPLO_ERROR_##sym,
  foreach_gtplo_error
#undef _
  GTPLO_N_ERROR,
} GTPLO_error_t;

static char * gtplo_error_strings[] = {
#define _(sym,string) string,
  foreach_gtplo_error
#undef _
};


static uword
gtplo_node_fn (vlib_main_t * vm,
                  vlib_node_runtime_t * node,
                  vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  gtplo_next_t next_index;
  u32 pkts_processed = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = GTPLO_NEXT_IP4_INPUT;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      ip4_address_t  src_addr;
      ip4_address_t  dst_addr;

      vlib_get_next_frame (vm, node, next_index,
                           to_next, n_left_to_next);
                           

      while (n_left_from >= 12 && n_left_to_next >= 4)
        {
          gtplo_next_t next0 = next_index;
          gtplo_next_t next1 = next_index;
          gtplo_next_t next2 = next_index;
          gtplo_next_t next3 = next_index;
          u32 sw_if_index0 = 0;
          u32 sw_if_index1 = 0;
          u32 sw_if_index2 = 0;
          u32 sw_if_index3 = 0;
          ip4_header_t *en0, *en1, *en2, *en3;          //map to ip0, ip1
          u32 bi0, bi1, bi2, bi3;                               //map to pi0, pi1
            vlib_buffer_t * b0, * b1, *b2, *b3;         //map to p0, p1
          
          /* Prefetch next iteration. */
          {
            vlib_buffer_t * p4, * p5, *p6, *p7;
            
            p4 = vlib_get_buffer (vm, from[4]);
            p5 = vlib_get_buffer (vm, from[5]);
            p6 = vlib_get_buffer (vm, from[6]);
            p7 = vlib_get_buffer (vm, from[7]);
            
            vlib_prefetch_buffer_header (p4, LOAD);
            vlib_prefetch_buffer_header (p5, LOAD);
            vlib_prefetch_buffer_header (p6, LOAD);
            vlib_prefetch_buffer_header (p7, LOAD);

            // what is the difference between STORE & LOAD
            CLIB_PREFETCH (p4->data, sizeof (en0[0]), STORE);
            CLIB_PREFETCH (p5->data, sizeof (en0[0]), STORE);
            CLIB_PREFETCH (p6->data, sizeof (en0[0]), STORE);
            CLIB_PREFETCH (p7->data, sizeof (en0[0]), STORE);
          }

          /* speculatively enqueue b0 and b1 to the current next frame */
          to_next[0] = bi0 = from[0];
          to_next[1] = bi1 = from[1];
          to_next[2] = bi2 = from[2];
          to_next[3] = bi3 = from[3];
          from += 4;
          to_next += 4;
          n_left_from -= 4;
          n_left_to_next -= 4;

          b0 = vlib_get_buffer (vm, bi0);
          b1 = vlib_get_buffer (vm, bi1);
          b2 = vlib_get_buffer (vm, bi2);
          b3 = vlib_get_buffer (vm, bi3);

         // ASSERT (b0->current_data == 0);
         // ASSERT (b1->current_data == 0);
         // ASSERT (b2->current_data == 0);
         // ASSERT (b3->current_data == 0);

          en0 = vlib_buffer_get_current (b0);
          en1 = vlib_buffer_get_current (b1); 
          en2 = vlib_buffer_get_current (b2); 
          en3 = vlib_buffer_get_current (b3); 

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];
          sw_if_index2 = vnet_buffer(b2)->sw_if_index[VLIB_RX];
        sw_if_index3 = vnet_buffer(b3)->sw_if_index[VLIB_RX];


        {

            clib_memcpy (src_addr.data, en0->src_address.data,
                                 sizeof (ip4_address_t));

            clib_memcpy (dst_addr.data, en0->dst_address.data,
                                 sizeof (ip4_address_t));

            clib_memcpy (en0->src_address.data, dst_addr.data,
                         sizeof (ip4_address_t));

                clib_memcpy (en0->dst_address.data, src_addr.data,
                         sizeof (ip4_address_t));
      
        /* Verify checksum. */
        en0->checksum = ip4_header_checksum (en0);
      
                  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
             {
              if (b0->flags & VLIB_BUFFER_IS_TRACED) 
                {
                    gtplo_trace_t *t = 
                      vlib_add_trace (vm, node, b0, sizeof (*t));
                    t->sw_if_index = sw_if_index0;
                    t->next_index = next0;
                    clib_memcpy (t->orig_src_ip.data, src_addr.data,
                                 sizeof (ip4_address_t));
                    clib_memcpy (t->orig_dst_ip.data, dst_addr.data,
                                 sizeof (ip4_address_t));
                    clib_memcpy (t->new_src_ip.data, en0->src_address.data,
                                 sizeof (ip4_address_t));
                    clib_memcpy (t->new_dst_ip.data, en0->dst_address.data,
                                 sizeof (ip4_address_t));                     
                    
                  }
               }
        }

        {

            clib_memcpy (src_addr.data, en1->src_address.data,
                                 sizeof (ip4_address_t));

            clib_memcpy (dst_addr.data, en1->dst_address.data,
                                 sizeof (ip4_address_t));

            clib_memcpy (en1->src_address.data, dst_addr.data,
                         sizeof (ip4_address_t));

                clib_memcpy (en1->dst_address.data, src_addr.data,
                         sizeof (ip4_address_t));
      
        /* Verify checksum. */
        en1->checksum = ip4_header_checksum (en1) ;

                  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
             {
              if (b0->flags & VLIB_BUFFER_IS_TRACED) 
                {
                    gtplo_trace_t *t = 
                      vlib_add_trace (vm, node, b1, sizeof (*t));
                    t->sw_if_index = sw_if_index1;
                    t->next_index = next1;
                    clib_memcpy (t->orig_src_ip.data, src_addr.data,
                                 sizeof (ip4_address_t));
                    clib_memcpy (t->orig_dst_ip.data, dst_addr.data,
                                 sizeof (ip4_address_t));
                    clib_memcpy (t->new_src_ip.data, en1->src_address.data,
                                 sizeof (ip4_address_t));
                    clib_memcpy (t->new_dst_ip.data, en1->dst_address.data,
                                 sizeof (ip4_address_t));                     
                    
                  }
               }
        }

        {

            clib_memcpy (src_addr.data, en2->src_address.data,
                                 sizeof (ip4_address_t));

            clib_memcpy (dst_addr.data, en2->dst_address.data,
                                 sizeof (ip4_address_t));

            clib_memcpy (en2->src_address.data, dst_addr.data,
                         sizeof (ip4_address_t));

                clib_memcpy (en2->dst_address.data, src_addr.data,
                         sizeof (ip4_address_t));
      
        /* Verify checksum. */
        en2->checksum = ip4_header_checksum (en2);

                  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
             {
              if (b0->flags & VLIB_BUFFER_IS_TRACED) 
                {
                    gtplo_trace_t *t = 
                      vlib_add_trace (vm, node, b2, sizeof (*t));
                    t->sw_if_index = sw_if_index2;
                    t->next_index = next2;
                    clib_memcpy (t->orig_src_ip.data, src_addr.data,
                                 sizeof (ip4_address_t));
                    clib_memcpy (t->orig_dst_ip.data, dst_addr.data,
                                 sizeof (ip4_address_t));
                    clib_memcpy (t->new_src_ip.data, en2->src_address.data,
                                 sizeof (ip4_address_t));
                    clib_memcpy (t->new_dst_ip.data, en2->dst_address.data,
                                 sizeof (ip4_address_t));                     
                    
                  }
               }
        }

        {

            clib_memcpy (src_addr.data, en3->src_address.data,
                                 sizeof (ip4_address_t));

            clib_memcpy (dst_addr.data, en3->dst_address.data,
                                 sizeof (ip4_address_t));

            clib_memcpy (en3->src_address.data, dst_addr.data,
                         sizeof (ip4_address_t));

                clib_memcpy (en3->dst_address.data, src_addr.data,
                         sizeof (ip4_address_t));
      
        /* Verify checksum. */
        en3->checksum = ip4_header_checksum (en3);

                  if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
             {
              if (b0->flags & VLIB_BUFFER_IS_TRACED) 
                {
                    gtplo_trace_t *t = 
                      vlib_add_trace (vm, node, b3, sizeof (*t));
                    t->sw_if_index = sw_if_index3;
                    t->next_index = next3;
                    clib_memcpy (t->orig_src_ip.data, src_addr.data,
                                 sizeof (ip4_address_t));
                    clib_memcpy (t->orig_dst_ip.data, dst_addr.data,
                                 sizeof (ip4_address_t));
                    clib_memcpy (t->new_src_ip.data, en3->src_address.data,
                                 sizeof (ip4_address_t));
                    clib_memcpy (t->new_dst_ip.data, en3->dst_address.data,
                                 sizeof (ip4_address_t));                     
                    
                  }
               }
        }

           pkts_processed += 4;
             
            /* verify speculative enqueues, maybe switch current next frame */
            vlib_validate_buffer_enqueue_x4 (vm, node, next_index,
                                             to_next, n_left_to_next,
                                             bi0, bi1, bi2, bi3, next0, next1, next2, next3);
        }

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          gtplo_next_t next0 = next_index;
          u32 sw_if_index0 = 0;
          ip4_header_t *en0;            //map to ip0, ip1
          u32 bi0;                              //map to pi0, pi1
            vlib_buffer_t * b0;         //map to p0, p1

          /* speculatively enqueue b0 to the current next frame */
          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);


  
         // ASSERT (b0->current_data == 0);

          en0 = vlib_buffer_get_current (b0);
            
          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

          {
            
                    clib_memcpy (src_addr.data, en0->src_address.data,
                                                 sizeof (ip4_address_t));
            
                    clib_memcpy (dst_addr.data, en0->dst_address.data,
                                                 sizeof (ip4_address_t));
            
                    clib_memcpy (en0->src_address.data, dst_addr.data,
                             sizeof (ip4_address_t));
            
                    clib_memcpy (en0->dst_address.data, src_addr.data,
                             sizeof (ip4_address_t));
            
                    /* Verify checksum. */
                    en0->checksum = ip4_header_checksum (en0);
            
                        if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)))
                     {
                        if (b0->flags & VLIB_BUFFER_IS_TRACED) 
                          {
                                gtplo_trace_t *t = 
                                  vlib_add_trace (vm, node, b0, sizeof (*t));
                                t->sw_if_index = sw_if_index0;
                                t->next_index = next0;
                                clib_memcpy (t->orig_src_ip.data, src_addr.data,
                                                 sizeof (ip4_address_t));
                                clib_memcpy (t->orig_dst_ip.data, dst_addr.data,
                                                 sizeof (ip4_address_t));
                                clib_memcpy (t->new_src_ip.data, en0->src_address.data,
                                                 sizeof (ip4_address_t));
                                clib_memcpy (t->new_dst_ip.data, en0->dst_address.data,
                                                 sizeof (ip4_address_t));                            

                            }
                         }
            }

          
            
          /* verify speculative enqueue, maybe switch current next frame */
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                           to_next, n_left_to_next,
                                           bi0, next0);
        }


      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (gtplo_node) = {
  .function = gtplo_node_fn,
  .name = "gtplo",
  .vector_size = sizeof (u32),
  .format_trace = format_gtplo_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(gtplo_error_strings),
  .error_strings = gtplo_error_strings,

  .n_next_nodes = GTPLO_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
      [GTPLO_NEXT_IP4_INPUT] = "ip4-input",
        [DECTTL_INPUT_NEXT_DROP] = "error-drop",
  },
};
