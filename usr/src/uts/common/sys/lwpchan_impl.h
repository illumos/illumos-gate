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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_LCHAN_IMPL_H
#define	_SYS_LCHAN_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	LWPCHAN_CVPOOL	0
#define	LWPCHAN_MPPOOL	1

#define	LWPCHAN_INITIAL_BITS	2	/* initially: 4 hash buckets */
#define	LWPCHAN_MAX_BITS	16	/* finally: up to 64K hash buckets */

/*
 * An lwpchan entry translates a process-shared lwp sync object's
 * virtual address into its logical address, an lwpchan, previously
 * computed via as_getmemid().
 */
typedef struct lwpchan_entry {
	caddr_t lwpchan_addr;		/* virtual address */
	caddr_t lwpchan_uaddr;		/* address of lock registration */
	uint16_t lwpchan_type;		/* sync object type field */
	uint16_t lwpchan_pool;		/* LWPCHAN_CVPOOL/LWPCHAN_MPPOOL */
	lwpchan_t lwpchan_lwpchan;	/* unique logical address */
	struct lwpchan_entry *lwpchan_next;	/* hash chain */
} lwpchan_entry_t;

/*
 * Hash bucket head.  The mutex protects the consistency of the hash chain.
 * Also, p->p_lcp cannot be changed while any one hash bucket lock is held.
 * (The resizing thread must acquire all of the hash bucket locks.)
 */
typedef struct lwpchan_hashbucket {
	kmutex_t lwpchan_lock;
	lwpchan_entry_t *lwpchan_chain;
} lwpchan_hashbucket_t;

/*
 * Each process maintains a cache of lwpchan translations for sync objects
 * (lwp_mutex_t, lwp_cond_t, lwp_sema_t) that are shared between processes.
 * The lwpchan cache is a hash table used to look up previously-computed
 * lwpchan_t's by process virtual address.  We keep this cache because we
 * believe that as_getmemid() is slow and we only need to call it once,
 * then remember the results.  The hashing function is very simple, and
 * assumes an even distribution of sync objects within the process's
 * address space.  When hash chains become too long, the cache is resized
 * on the fly.  The cache is freed when the process exits or execs.
 */
typedef struct lwpchan_data {
	uint_t	lwpchan_bits;		/* number of bits */
	uint_t	lwpchan_size;		/* 1 << lwpchan_bits */
	uint_t	lwpchan_mask;		/* lwpchan_size - 1 */
	uint_t	lwpchan_entries;	/* number of entries in the cache */
	lwpchan_hashbucket_t *lwpchan_cache;
	struct lwpchan_data *lwpchan_next_data;
} lwpchan_data_t;

/*
 * exported functions
 */
void lwpchan_delete_mapping(proc_t *, caddr_t start, caddr_t end);
void lwpchan_destroy_cache(int);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LCHAN_IMPL_H */
