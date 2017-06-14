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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_CALLO_H
#define	_SYS_CALLO_H

#include <sys/t_lock.h>
#include <sys/taskq.h>
#include <sys/lgrp.h>
#include <sys/processor.h>
#include <sys/cyclic.h>
#include <sys/kstat.h>
#include <sys/systm.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

typedef struct callout_list	callout_list_t;

/*
 * The callout mechanism provides general-purpose event scheduling:
 * an arbitrary function is called in a specified amount of time.
 * The expiration time for a callout is kept in its callout list
 * structure.
 */
typedef struct callout {
	struct callout	*c_idnext;	/* next in ID hash, or on freelist */
	struct callout	*c_idprev;	/* prev in ID hash */
	struct callout	*c_clnext;	/* next in callout list */
	struct callout	*c_clprev;	/* prev in callout list */
	callout_id_t	c_xid;		/* extended callout ID; see below */
	callout_list_t	*c_list;	/* callout list */
	void		(*c_func)(void *); /* function to call */
	void		*c_arg;		/* argument to function */
	kthread_t	*c_executor;	/* executing thread */
	kcondvar_t	c_done;		/* signal callout completion */
	ushort_t	c_waiting;	/* untimeout waiting flag */
} callout_t;

/*
 * The callout ID (callout_id_t) uniquely identifies a callout. The callout
 * ID is always 64 bits internally. The lower 32 bits contain an ID value.
 * The upper 32 bits contain a generation number and flags. When the ID value
 * wraps the generation number is incremented during ID generation. This
 * protects callers from ID collisions that can happen as a result of the wrap.
 *
 * The kernel internal interface, timeout_generic(), always returns a
 * callout_id_t. But the legacy interfaces, timeout() and realtime_timeout()
 * return a timeout_id_t. On a 64-bit system, timeout_id_t is also 64 bits.
 * So, the full 64-bit ID (sans the flags) can be returned. However, on 32-bit
 * systems, timeout_id_t is 32 bits. So, only the lower 32 bits can be
 * returned. In such cases, a default generation number of 0 is assigned to
 * the legacy IDs.
 *
 * The lower 32-bit ID space is partitioned into two spaces - one for
 * short-term callouts and one for long-term.
 *
 * Here is the bit layout for the callout ID:
 *
 *      63    62    61 ...  32    31      30     29 .. X+1  X ... 1   0
 *  -----------------------------------------------------------------------
 *  | Free | Exec | Generation | Long | Counter | ID bits | Table  | Type |
 *  |      |      | number     | term | High    |         | number |      |
 *  -----------------------------------------------------------------------
 *
 * Free:
 *    This bit indicates that this callout has been freed. This is for
 *    debugging purposes.
 *
 * Exec(uting):
 *    This is the executing bit which is only set in the extended callout
 *    ID. This bit indicates that the callout handler is currently being
 *    executed.
 *
 * Generation number:
 *    This is the generation part of the ID.
 *
 * Long term:
 *    This bit indicates whether this is a short-term or a long-term callout.
 *    The long-term bit exists to address the problem of callout ID collision
 *    on 32-bit systems. This is an issue because the system typically
 *    generates a large number of timeout() requests, which means that callout
 *    IDs eventually get recycled. Most timeouts are very short-lived, so that
 *    ID recycling isn't a problem; but there are a handful of timeouts which
 *    are sufficiently long-lived to see their own IDs reused. We use the
 *    long-term bit to partition the ID namespace into pieces; the short-term
 *    space gets all the heavy traffic and can wrap frequently (i.e., on the
 *    order of a day) with no ill effects; the long-term space gets very little
 *    traffic and thus never wraps. That said, we need to future proof callouts
 *    in case 32-bit systems grow in size and are able to consume callout IDs
 *    at faster rates. So, we should make all the kernel clients that use
 *    callouts to use the internal interface so that they can use IDs outside
 *    of the legacy space with a proper generation number.
 *
 * Counter High + ID counter bits:
 *    These bits represent the actual ID bits in the callout ID.
 *    The highest bit of the running counter is always set; this ensures that
 *    the callout ID is always non-zero, thus eliminating the need for an
 *    explicit wrap-around test during ID generation.
 *
 * Table number:
 *    These bits carry the table number for the callout table where the callout
 *    is queued. Each CPU has its own callout table. So, the callout tables are
 *    numbered from 0 - (max_ncpus - 1). Because max_ncpus is different on
 *    different systems, the actual number of table number bits will vary
 *    accordingly. And so will the ID counter bits.
 *
 * Type:
 *    This bit represents the callout (table) type. Each CPU has one realtime
 *    and one normal callout table.
 */
#define	CALLOUT_ID_FREE		0x8000000000000000ULL
#define	CALLOUT_EXECUTING	0x4000000000000000ULL
#define	CALLOUT_ID_FLAGS	(CALLOUT_ID_FREE | CALLOUT_EXECUTING)
#define	CALLOUT_ID_MASK		~CALLOUT_ID_FLAGS
#define	CALLOUT_GENERATION_LOW	0x100000000ULL
#define	CALLOUT_LONGTERM	0x80000000
#define	CALLOUT_COUNTER_HIGH	0x40000000
#define	CALLOUT_TYPE_BITS	1
#define	CALLOUT_NTYPES		(1 << CALLOUT_TYPE_BITS)
#define	CALLOUT_TYPE_MASK	(CALLOUT_NTYPES - 1)
#define	CALLOUT_COUNTER_SHIFT	callout_table_bits
#define	CALLOUT_TABLE(t, f)	(((f) << CALLOUT_TYPE_BITS) | (t))
#define	CALLOUT_TABLE_NUM(ct)	((ct) - callout_table)
#define	CALLOUT_TABLE_SEQID(ct)	(CALLOUT_TABLE_NUM(ct) >> CALLOUT_TYPE_BITS)

/*
 * We assume that during any period of CALLOUT_LONGTERM_TICKS ticks, at most
 * (CALLOUT_COUNTER_HIGH / callout_counter_low) callouts will be generated.
 */
#define	CALLOUT_LONGTERM_TICKS	0x4000UL
#define	CALLOUT_BUCKET_SHIFT	9
#define	CALLOUT_BUCKETS		(1 << CALLOUT_BUCKET_SHIFT)
#define	CALLOUT_BUCKET_MASK	(CALLOUT_BUCKETS - 1)
#define	CALLOUT_HASH(x)		((x) & CALLOUT_BUCKET_MASK)
#define	CALLOUT_IDHASH(x)	CALLOUT_HASH((x) >> CALLOUT_COUNTER_SHIFT)
/*
 * The multiply by 0 and 1 below are cosmetic. Just to align things better
 * and make it more readable. The multiplications will be done at compile
 * time.
 */
#define	CALLOUT_CLHASH(x)			\
	CALLOUT_HASH(				\
	    ((x)>>(CALLOUT_BUCKET_SHIFT*0)) ^	\
	    ((x)>>(CALLOUT_BUCKET_SHIFT*1)) ^	\
	    ((x)>>(CALLOUT_BUCKET_SHIFT*2)) ^	\
	    ((x)>>(CALLOUT_BUCKET_SHIFT*3)))

#define	CALLOUT_ID_TO_TABLE(id)		((id) & callout_table_mask)

#define	CALLOUT_SHORT_ID(table)		\
		((callout_id_t)(table) | CALLOUT_COUNTER_HIGH)
#define	CALLOUT_LONG_ID(table)		\
		(CALLOUT_SHORT_ID(table) | CALLOUT_LONGTERM)

#define	CALLOUT_THREADS		2

#define	CALLOUT_REALTIME	0		/* realtime callout type */
#define	CALLOUT_NORMAL		1		/* normal callout type */

/*
 * callout_t's are cache-aligned structures allocated from kmem caches. One kmem
 * cache is created per lgrp and is shared by all CPUs in that lgrp. Benefits:
 *	- cache pages are mapped only in the TLBs of the CPUs of the lgrp
 *	- data in cache pages is present only in those CPU caches
 *	- memory access performance improves with locality-awareness in kmem
 *
 * The following structure is used to manage per-lgroup kmem caches.
 *
 * NOTE: Free callout_t's go to a callout table's freelist. CPUs map to callout
 * tables via their sequence IDs, not CPU IDs. DR operations can cause a
 * free list to have callouts from multiple lgrp caches. This takes away some
 * performance, but is no worse than if we did not use lgrp caches at all.
 */
typedef struct callout_cache {
	struct callout_cache	*cc_next;	/* link in the global list */
	lgrp_handle_t		cc_hand;	/* lgroup handle */
	kmem_cache_t		*cc_cache;	/* kmem cache pointer */
	kmem_cache_t		*cc_lcache;	/* kmem cache pointer */
} callout_cache_t;

/*
 * The callout hash structure is used for queueing both callouts and
 * callout lists. That is why the fields are declared as void *.
 */
typedef struct callout_hash {
	void	*ch_head;
	void	*ch_tail;
} callout_hash_t;

/*
 * CALLOUT_LIST_FLAG_FREE
 *	Callout list is free.
 * CALLOUT_LIST_FLAG_ABSOLUTE
 *	Callout list contains absolute timers.
 * CALLOUT_LIST_FLAG_HRESTIME
 *	Callout list contains hrestime timers.
 * CALLOUT_LIST_FLAG_NANO
 *	Callout list contains 1-nanosecond resolution callouts.
 * CALLOUT_LIST_FLAG_HEAPED
 *	Callout list is present in the callout heap.
 * CALLOUT_LIST_FLAG_QUEUED
 *	Callout list is present in the callout queue.
 */
#define	CALLOUT_LIST_FLAG_FREE			0x1
#define	CALLOUT_LIST_FLAG_ABSOLUTE		0x2
#define	CALLOUT_LIST_FLAG_HRESTIME		0x4
#define	CALLOUT_LIST_FLAG_NANO			0x8
#define	CALLOUT_LIST_FLAG_HEAPED		0x10
#define	CALLOUT_LIST_FLAG_QUEUED		0x20

struct callout_list {
	callout_list_t	*cl_next;	/* next in clhash */
	callout_list_t	*cl_prev;	/* prev in clhash */
	hrtime_t	cl_expiration;	/* expiration for callouts in list */
	callout_hash_t	cl_callouts;	/* list of callouts */
	int		cl_flags;	/* callout flags */
};

/*
 * Callout heap element. Each element in the heap stores the expiration
 * as well as the corresponding callout list. This is to avoid a lookup
 * of the callout list when the heap is processed. Because we store the
 * callout list pointer in the heap element, we have to always remove
 * a heap element and its callout list together. We cannot remove one
 * without the other.
 *
 * This structure's size must be a power of two because we want an
 * integral number of these to fit into a page.
 */
typedef struct callout_heap {
	hrtime_t	ch_expiration;
	callout_list_t	*ch_list;
#ifndef _LP64
	char		ch_pad[4];	/* pad to power of 2 */
#endif
} callout_heap_t;

/*
 * When the heap contains too many empty callout lists, it needs to be
 * cleaned up. The decision to clean up the heap is a function of the
 * number of empty entries and the heap size. Also, we don't want to
 * clean up small heaps.
 */
#define	CALLOUT_MIN_REAP	(CALLOUT_BUCKETS >> 3)
#define	CALLOUT_CLEANUP(ct)	((ct->ct_nreap >= callout_min_reap) &&	\
				    (ct->ct_nreap >= (ct->ct_heap_num >> 1)))

/*
 * Per-callout table kstats.
 *
 * CALLOUT_TIMEOUTS
 *	Callouts created since boot.
 * CALLOUT_TIMEOUTS_PENDING
 *	Number of outstanding callouts.
 * CALLOUT_UNTIMEOUTS_UNEXPIRED
 *	Number of cancelled callouts that have not expired.
 * CALLOUT_UNTIMEOUTS_EXECUTING
 *	Number of cancelled callouts that were executing at the time of
 *	cancellation.
 * CALLOUT_UNTIMEOUTS_EXPIRED
 *	Number of cancelled callouts that had already expired at the time
 *	of cancellations.
 * CALLOUT_EXPIRATIONS
 *	Number of callouts that expired.
 * CALLOUT_ALLOCATIONS
 *	Number of callout structures allocated.
 * CALLOUT_CLEANUPS
 *	Number of times a callout table is cleaned up.
 */
typedef enum callout_stat_type {
	CALLOUT_TIMEOUTS,
	CALLOUT_TIMEOUTS_PENDING,
	CALLOUT_UNTIMEOUTS_UNEXPIRED,
	CALLOUT_UNTIMEOUTS_EXECUTING,
	CALLOUT_UNTIMEOUTS_EXPIRED,
	CALLOUT_EXPIRATIONS,
	CALLOUT_ALLOCATIONS,
	CALLOUT_CLEANUPS,
	CALLOUT_NUM_STATS
} callout_stat_type_t;

/*
 * Callout flags:
 *
 * CALLOUT_FLAG_ROUNDUP
 *	Roundup the expiration time to the next resolution boundary.
 *	If this flag is not specified, the expiration time is rounded down.
 * CALLOUT_FLAG_ABSOLUTE
 *	Normally, the expiration passed to the timeout API functions is an
 *	expiration interval. If this flag is specified, then it is
 *	interpreted as the expiration time itself.
 * CALLOUT_FLAG_HRESTIME
 *	Normally, callouts are not affected by changes to system time
 *	(hrestime). This flag is used to create a callout that is affected
 *	by system time. If system time changes, these timers must be
 *	handled in a special way (see callout.c). These are used by condition
 *	variables and LWP timers that need this behavior.
 * CALLOUT_FLAG_32BIT
 *	Legacy interfaces timeout() and realtime_timeout() pass this flag
 *	to timeout_generic() to indicate that a 32-bit ID should be allocated.
 */
#define	CALLOUT_FLAG_ROUNDUP		0x1
#define	CALLOUT_FLAG_ABSOLUTE		0x2
#define	CALLOUT_FLAG_HRESTIME		0x4
#define	CALLOUT_FLAG_32BIT		0x8

/*
 * On 32-bit systems, the legacy interfaces, timeout() and realtime_timeout(),
 * must pass CALLOUT_FLAG_32BIT to timeout_generic() so that a 32-bit ID
 * can be generated.
 */
#ifdef _LP64
#define	CALLOUT_LEGACY		0
#else
#define	CALLOUT_LEGACY		CALLOUT_FLAG_32BIT
#endif

/*
 * All of the state information associated with a callout table.
 * The fields are ordered with cache performance in mind.
 */
typedef struct callout_table {
	kmutex_t	ct_mutex;	/* protects all callout state */
	callout_t	*ct_free;	/* free callout structures */
	callout_list_t	*ct_lfree;	/* free callout list structures */
	callout_id_t	ct_short_id;	/* most recently issued short-term ID */
	callout_id_t	ct_long_id;	/* most recently issued long-term ID */
	callout_hash_t 	*ct_idhash;	/* ID hash chains */
	callout_hash_t 	*ct_clhash;	/* callout list hash */
	kstat_named_t	*ct_kstat_data;	/* callout kstat data */

	uint_t		ct_type;	/* callout table type */
	uint_t		ct_suspend;	/* suspend count */
	cyclic_id_t	ct_cyclic;	/* cyclic for this table */
	callout_heap_t	*ct_heap;	/* callout expiration heap */
	ulong_t		ct_heap_num;	/* occupied slots in the heap */
	ulong_t		ct_heap_max;	/* end of the heap */
	kmem_cache_t	*ct_cache;	/* callout kmem cache */
	kmem_cache_t	*ct_lcache;	/* callout list kmem cache */
	callout_id_t	ct_gen_id;	/* generation based ID */

	callout_hash_t	ct_expired;	/* list of expired callout lists */
	taskq_t		*ct_taskq;	/* taskq to execute normal callouts */
	kstat_t		*ct_kstats;	/* callout kstats */
	int		ct_nreap;	/* # heap entries that need reaping */
	cyclic_id_t	ct_qcyclic;	/* cyclic for the callout queue */
	callout_hash_t	ct_queue;	/* overflow queue of callouts */
#ifndef _LP64
	char		ct_pad[12];	/* cache alignment */
#endif
	/*
	 * This structure should be aligned to a 64-byte (cache-line)
	 * boundary. Make sure the padding is right for 32-bit as well
	 * as 64-bit kernels.
	 */
} callout_table_t;

/*
 * Short hand definitions for the callout kstats.
 */
#define	ct_timeouts							\
		ct_kstat_data[CALLOUT_TIMEOUTS].value.ui64
#define	ct_timeouts_pending						\
		ct_kstat_data[CALLOUT_TIMEOUTS_PENDING].value.ui64
#define	ct_untimeouts_unexpired						\
		ct_kstat_data[CALLOUT_UNTIMEOUTS_UNEXPIRED].value.ui64
#define	ct_untimeouts_executing						\
		ct_kstat_data[CALLOUT_UNTIMEOUTS_EXECUTING].value.ui64
#define	ct_untimeouts_expired						\
		ct_kstat_data[CALLOUT_UNTIMEOUTS_EXPIRED].value.ui64
#define	ct_expirations							\
		ct_kstat_data[CALLOUT_EXPIRATIONS].value.ui64
#define	ct_allocations							\
		ct_kstat_data[CALLOUT_ALLOCATIONS].value.ui64
#define	ct_cleanups							\
		ct_kstat_data[CALLOUT_CLEANUPS].value.ui64

/*
 * CALLOUT_CHUNK is the minimum initial size of each heap, and the amount
 * by which a full heap is expanded to make room for new entries.
 */
#define	CALLOUT_CHUNK		(PAGESIZE / sizeof (callout_heap_t))

/*
 * CALLOUT_MIN_HEAP_SIZE defines the minimum size for the callout heap for
 * the whole system.
 */
#define	CALLOUT_MIN_HEAP_SIZE	(64 * 1024 * sizeof (callout_heap_t))

/*
 * CALLOUT_MEM_FRACTION defines the fraction of available physical memory that
 * can be allocated towards the callout heap for the whole system.
 */
#define	CALLOUT_MEM_FRACTION	4096

#define	CALLOUT_HEAP_PARENT(index)	(((index) - 1) >> 1)
#define	CALLOUT_HEAP_RIGHT(index)	(((index) + 1) << 1)
#define	CALLOUT_HEAP_LEFT(index)	((((index) + 1) << 1) - 1)

#define	CALLOUT_TCP_RESOLUTION		10000000ULL

#define	CALLOUT_ALIGN	64	/* cache line size */

#ifdef _LP64
#define	CALLOUT_MAX_TICKS	NSEC_TO_TICK(CY_INFINITY);
#else
#define	CALLOUT_MAX_TICKS	LONG_MAX
#endif

#define	CALLOUT_TOLERANCE	200000		/* nanoseconds */

extern void		callout_init(void);
extern void		membar_sync(void);
extern void		callout_cpu_online(cpu_t *);
extern void		callout_cpu_offline(cpu_t *);
extern void		callout_hrestime(void);

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CALLO_H */
