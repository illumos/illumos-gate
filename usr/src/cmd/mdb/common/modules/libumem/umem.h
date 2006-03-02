/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MDBMOD_UMEM_H
#define	_MDBMOD_UMEM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_modapi.h>
#include <umem_impl.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int umem_ready;
extern uint32_t umem_stack_depth;

extern int umem_cache_walk_init(mdb_walk_state_t *);
extern int umem_cache_walk_step(mdb_walk_state_t *);
extern void umem_cache_walk_fini(mdb_walk_state_t *);

extern int umem_cpu_walk_init(mdb_walk_state_t *);
extern int umem_cpu_walk_step(mdb_walk_state_t *);
extern void umem_cpu_walk_fini(mdb_walk_state_t *);

extern int umem_cpu_cache_walk_init(mdb_walk_state_t *);
extern int umem_cpu_cache_walk_step(mdb_walk_state_t *);

extern int umem_slab_walk_init(mdb_walk_state_t *);
extern int umem_slab_walk_partial_init(mdb_walk_state_t *);
extern int umem_slab_walk_step(mdb_walk_state_t *);

extern int umem_hash_walk_init(mdb_walk_state_t *wsp);
extern int umem_hash_walk_step(mdb_walk_state_t *wsp);
extern void umem_hash_walk_fini(mdb_walk_state_t *wsp);

extern int umem_walk_init(mdb_walk_state_t *);
extern int bufctl_walk_init(mdb_walk_state_t *);
extern int freemem_walk_init(mdb_walk_state_t *);
extern int freectl_walk_init(mdb_walk_state_t *);

extern int umem_walk_step(mdb_walk_state_t *);
extern void umem_walk_fini(mdb_walk_state_t *);

extern int bufctl_history_walk_init(mdb_walk_state_t *);
extern int bufctl_history_walk_step(mdb_walk_state_t *);
extern void bufctl_history_walk_fini(mdb_walk_state_t *);

extern int allocdby_walk_init(mdb_walk_state_t *);
extern int allocdby_walk_step(mdb_walk_state_t *);
extern void allocdby_walk_fini(mdb_walk_state_t *);

extern int freedby_walk_init(mdb_walk_state_t *);
extern int freedby_walk_step(mdb_walk_state_t *);
extern void freedby_walk_fini(mdb_walk_state_t *);

extern int umem_log_walk_init(mdb_walk_state_t *);
extern int umem_log_walk_step(mdb_walk_state_t *);
extern void umem_log_walk_fini(mdb_walk_state_t *);

extern int allocdby_walk_init(mdb_walk_state_t *);
extern int allocdby_walk_step(mdb_walk_state_t *);
extern void allocdby_walk_fini(mdb_walk_state_t *);

extern int freedby_walk_init(mdb_walk_state_t *);
extern int freedby_walk_step(mdb_walk_state_t *);
extern void freedby_walk_fini(mdb_walk_state_t *);

extern int vmem_walk_init(mdb_walk_state_t *);
extern int vmem_walk_step(mdb_walk_state_t *);
extern void vmem_walk_fini(mdb_walk_state_t *);

extern int vmem_postfix_walk_step(mdb_walk_state_t *);

extern int vmem_seg_walk_init(mdb_walk_state_t *);
extern int vmem_seg_walk_step(mdb_walk_state_t *);
extern void vmem_seg_walk_fini(mdb_walk_state_t *);

extern int vmem_span_walk_init(mdb_walk_state_t *);
extern int vmem_alloc_walk_init(mdb_walk_state_t *);
extern int vmem_free_walk_init(mdb_walk_state_t *);

extern int allocdby(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int bufctl(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int bufctl_audit(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int freedby(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int umalog(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int umausers(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int umem_cache(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int umem_log(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int umem_malloc_dist(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int umem_malloc_info(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int umem_status(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int umem_verify(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int umem_verify_alloc(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int umem_verify_free(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int vmem(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int vmem_seg(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int whatis(uintptr_t, uint_t, int, const mdb_arg_t *);

extern void bufctl_help(void);
extern void umem_malloc_dist_help(void);
extern void umem_malloc_info_help(void);
extern void vmem_seg_help(void);

/*
 * utility functions for the rest of libumem
 */
extern int umem_init(void);
extern int umem_get_magsize(const umem_cache_t *);
extern size_t umem_estimate_allocated(uintptr_t, const umem_cache_t *);

#ifdef __cplusplus
}
#endif

#endif	/* _MDBMOD_UMEM_H */
