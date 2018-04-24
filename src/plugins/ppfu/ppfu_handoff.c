
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

#include <vnet/vnet.h>
#include <vppinfra/xxhash.h>
#include <vlib/threads.h>
#include <ppfu/ppfu.h>
#include <ppfu/ppfu_handoff.h>
#include <ppfu/ppf_gtpu.h>
#include <vnet/feature/feature.h>

typedef struct
{
  u32 cached_next_index;
  u32 num_workers;
  u32 first_worker_index;

  u32 *workers;

  /* Worker ppfu_handoff index */
  u32 frame_queue_index;

  /* convenience variables */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  u32 error_node_index;

  u32 (*hash_fn) (ppf_gtpu_header_t*);
} ppfu_handoff_main_t;

ppfu_handoff_main_t ppfu_handoff_main;
vlib_node_registration_t ppfu_handoff_dispatch_node;

typedef struct
{
  u32 hash;
  u32 teid;
  u32 next_worker_index;
  u32 buffer_index;
} worker_ppfu_handoff_trace_t;

/* packet trace format function */
static u8 *
format_worker_ppfu_handoff_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  worker_ppfu_handoff_trace_t *t = va_arg (*args, worker_ppfu_handoff_trace_t *);

  s =
    format (s, "worker-ppfu_handoff: teid 0x%x, hash 0x%x next_worker %d, buffer 0x%x",
	     t->teid, t->hash, t->next_worker_index, t->buffer_index);
  return s;
}

vlib_node_registration_t worker_ppfu_handoff_node;

static uword
worker_ppfu_handoff_node_fn (vlib_main_t * vm,
			vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  ppfu_handoff_main_t *hm = &ppfu_handoff_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 n_left_from, *from;
  static __thread vlib_frame_queue_elt_t **ppfu_handoff_queue_elt_by_worker_index;
  static __thread vlib_frame_queue_t **congested_ppfu_handoff_queue_by_worker_index
    = 0;
  vlib_frame_queue_elt_t *hf = 0;
  int i;
  u32 n_left_to_next_worker = 0, *to_next_worker = 0, *to_next_drop = 0;
  u32 next_worker_index = 0;
  u32 current_worker_index = ~0;
  vlib_frame_queue_t *fq;
  vlib_frame_t *d = 0;

  if (PREDICT_FALSE (ppfu_handoff_queue_elt_by_worker_index == 0))
    {
      vec_validate (ppfu_handoff_queue_elt_by_worker_index, tm->n_vlib_mains - 1);

      vec_validate_init_empty (congested_ppfu_handoff_queue_by_worker_index,
			       hm->first_worker_index + hm->num_workers - 1,
			       (vlib_frame_queue_t *) (~0));
    }

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      u32 hash;
      u64 hash_key;
      u32 index0;
      ppf_gtpu_header_t *gtpu0 = 0;

      bi0 = from[0];
      from += 1;
      n_left_from -= 1;

      b0 = vlib_get_buffer (vm, bi0);

      next_worker_index = hm->first_worker_index;

      /*
       * Force unknown traffic onto worker 0,
       * and into ethernet-input. $$$$ add more hashes.
       */

      /* Compute ingress LB hash */
      gtpu0 = vlib_buffer_get_current (b0);
      hash_key = hm->hash_fn (gtpu0);
      hash = (u32) clib_xxhash (hash_key);

	//Fix me, need set next id according to IP header type
      /* if input node did not specify next index, then packet
         should go to eternet-input */
  	vnet_buffer (b0)->handoff.next_index =
	  PPFU_HANDOFF_DISPATCH_NEXT_GTPU_IP4_INPUT;

      if (PREDICT_TRUE (is_pow2 (hm->num_workers)))
	index0 = hash & (hm->num_workers - 1);
      else
	index0 = hash %  (hm->num_workers);

      next_worker_index += hm->workers[index0];

      if (next_worker_index != current_worker_index)
	{
	
		fq =
		is_vlib_frame_queue_congested (hm->frame_queue_index, next_worker_index,
						 PPFU_HANDOFF_QUEUE_HI_THRESHOLD,
						 congested_ppfu_handoff_queue_by_worker_index);
		
		if (fq)
		{
		  /* if this is 1st frame */
		  if (!d)
		    {
			d = vlib_get_frame_to_node (vm, hm->error_node_index);
			to_next_drop = vlib_frame_vector_args (d);
		    }
		
		  to_next_drop[0] = bi0;
		  to_next_drop += 1;
		  d->n_vectors++;
		  goto trace0;
		}
	
	  if (hf)
	    hf->n_vectors = VLIB_FRAME_SIZE - n_left_to_next_worker;

	  hf = vlib_get_worker_handoff_queue_elt (hm->frame_queue_index,
						  next_worker_index,
						  ppfu_handoff_queue_elt_by_worker_index);

	  n_left_to_next_worker = VLIB_FRAME_SIZE - hf->n_vectors;
	  to_next_worker = &hf->buffer_index[hf->n_vectors];
	  current_worker_index = next_worker_index;
	}

      /* enqueue to correct worker thread */
      to_next_worker[0] = bi0;
      to_next_worker++;
      n_left_to_next_worker--;

      if (n_left_to_next_worker == 0)
	{
	  hf->n_vectors = VLIB_FRAME_SIZE;
	  vlib_put_frame_queue_elt (hf);
	  current_worker_index = ~0;
	  ppfu_handoff_queue_elt_by_worker_index[next_worker_index] = 0;
	  hf = 0;
	}

	trace0:
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  worker_ppfu_handoff_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->hash = hash;
	  t->teid = clib_host_to_net_u32(gtpu0->teid);
	  t->next_worker_index = next_worker_index - hm->first_worker_index;
	  t->buffer_index = bi0;
	}

    }

  if (d)
    vlib_put_frame_to_node (vm, hm->error_node_index, d);
 
  if (hf)
    hf->n_vectors = VLIB_FRAME_SIZE - n_left_to_next_worker;
 
  /* Ship frames to the worker nodes */
  for (i = 0; i < vec_len (ppfu_handoff_queue_elt_by_worker_index); i++)
    {
      if (ppfu_handoff_queue_elt_by_worker_index[i])
	{
	  hf = ppfu_handoff_queue_elt_by_worker_index[i];
	  /*
	   * It works better to let the ppfu_handoff node
	   * rate-adapt, always ship the ppfu_handoff queue element.
	   */
	  if (1 || hf->n_vectors == hf->last_n_vectors)
	    {
	      vlib_put_frame_queue_elt (hf);
	      ppfu_handoff_queue_elt_by_worker_index[i] = 0;
	    }
	  else
	    hf->last_n_vectors = hf->n_vectors;
	}
      congested_ppfu_handoff_queue_by_worker_index[i] =
	(vlib_frame_queue_t *) (~0);
    }
  hf = 0;
  current_worker_index = ~0;
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (worker_ppfu_handoff_node) = {
  .function = worker_ppfu_handoff_node_fn,
  .name = "worker-ppfu_handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_worker_ppfu_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (worker_ppfu_handoff_node, worker_ppfu_handoff_node_fn)
/* *INDENT-ON* */

typedef struct
{
  u32 buffer_index;
  u32 next_index;
} ppfu_handoff_dispatch_trace_t;

/* packet trace format function */
static u8 *
format_ppfu_handoff_dispatch_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ppfu_handoff_dispatch_trace_t *t = va_arg (*args, ppfu_handoff_dispatch_trace_t *);

  s = format (s, "ppfu_handoff-dispatch: next_index %d buffer 0x%x",
	       t->next_index, t->buffer_index);
  return s;
}

#define foreach_ppfu_handoff_dispatch_error \
_(EXAMPLE, "example packets")

typedef enum
{
#define _(sym,str) PPFU_HANDOFF_DISPATCH_ERROR_##sym,
  foreach_ppfu_handoff_dispatch_error
#undef _
    PPFU_HANDOFF_DISPATCH_N_ERROR,
} ppfu_handoff_dispatch_error_t;

static char *ppfu_handoff_dispatch_error_strings[] = {
#define _(sym,string) string,
  foreach_ppfu_handoff_dispatch_error
#undef _
};

static uword
ppfu_handoff_dispatch_node_fn (vlib_main_t * vm,
			  vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  ppfu_handoff_dispatch_next_t next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u32 next0, next1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;

	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);

	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);
	  }

	  /* speculatively enqueue b0 and b1 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  next0 = vnet_buffer (b0)->handoff.next_index;
	  next1 = vnet_buffer (b1)->handoff.next_index;

	  if (PREDICT_FALSE (vm->trace_main.trace_active_hint))
	    {
	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  vlib_trace_buffer (vm, node, next0, b0,	/* follow_chain */
				     0);
		  ppfu_handoff_dispatch_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->next_index = next0;
		  t->buffer_index = bi0;
		}
	      if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
		{
		  vlib_trace_buffer (vm, node, next1, b1,	/* follow_chain */
				     0);
		  ppfu_handoff_dispatch_trace_t *t =
		    vlib_add_trace (vm, node, b1, sizeof (*t));
		  t->next_index = next1;
		  t->buffer_index = bi1;
		}
	    }

	  /* verify speculative enqueues, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  next0 = vnet_buffer (b0)->handoff.next_index;

	  if (PREDICT_FALSE (vm->trace_main.trace_active_hint))
	    {
	      if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
		{
		  vlib_trace_buffer (vm, node, next0, b0,	/* follow_chain */
				     0);
		  ppfu_handoff_dispatch_trace_t *t =
		    vlib_add_trace (vm, node, b0, sizeof (*t));
		  t->next_index = next0;
		  t->buffer_index = bi0;
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

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ppfu_handoff_dispatch_node) = {
  .function = ppfu_handoff_dispatch_node_fn,
  .name = "ppfu_handoff-dispatch",
  .vector_size = sizeof (u32),
  .format_trace = format_ppfu_handoff_dispatch_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .flags = VLIB_NODE_FLAG_IS_HANDOFF,

  .n_errors = ARRAY_LEN(ppfu_handoff_dispatch_error_strings),
  .error_strings = ppfu_handoff_dispatch_error_strings,

  .n_next_nodes = PPFU_HANDOFF_DISPATCH_N_NEXT,

  .next_nodes = {
    	#define _(s,n) [PPFU_HANDOFF_DISPATCH_NEXT_##s] = n,
   		foreach_ppfu_handoff_next
	#undef _
  },
};

VLIB_NODE_FUNCTION_MULTIARCH (ppfu_handoff_dispatch_node, ppfu_handoff_dispatch_node_fn)
/* *INDENT-ON* */

clib_error_t *
ppfu_handoff_init (vlib_main_t * vm)
{
  ppfu_handoff_main_t *hm = &ppfu_handoff_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  clib_error_t *error;
  uword *p;
  int i = 0;

  if ((error = vlib_call_init_function (vm, threads_init)))
    return error;

  vlib_thread_registration_t *tr;
  /* Only the standard vnet worker threads are supported */
  p = hash_get_mem (tm->thread_registrations_by_name, "workers");
  if (p)
    {
      tr = (vlib_thread_registration_t *) p[0];
      if (tr)
	{
	  hm->num_workers = tr->count;
	  hm->first_worker_index = tr->first_index;
	}
    }

  vec_free (hm->workers);

  //Fixed me, has not consider stats thread yet
  for (i = 0; i < hm->num_workers; i ++) {
	vec_add1(hm->workers, i);
  }

  hm->hash_fn = ppfu_gtpu_get_key;

  hm->vlib_main = vm;
  hm->vnet_main = &vnet_main;

  vlib_node_t *error_drop_node =
	  vlib_get_node_by_name (vm, (u8 *) "error-drop");

  hm->frame_queue_index =
	vlib_frame_queue_main_init (ppfu_handoff_dispatch_node.index, 0);

  hm->error_node_index = error_drop_node->index;

	/* *INDENT-ON* */
   return 0;
}

VLIB_INIT_FUNCTION (ppfu_handoff_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
