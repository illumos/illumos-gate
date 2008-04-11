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
/*	  All Rights Reserved  	*/


/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_CALLO_H
#define	_SYS_CALLO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/t_lock.h>
#include <sys/taskq.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef long	callout_id_t;		/* internal form of timeout_id_t */

/*
 * The callout mechanism provides general-purpose event scheduling:
 * an arbitrary function is called in a specified amount of time.
 */
typedef struct callout {
	struct callout	*c_idnext;	/* next in ID hash, or on freelist */
	struct callout	*c_idprev;	/* prev in ID hash */
	struct callout	*c_lbnext;	/* next in lbolt hash */
	struct callout	*c_lbprev;	/* prev in lbolt hash */
	callout_id_t	c_xid;		/* extended callout ID; see below */
	clock_t		c_runtime;	/* absolute run time */
	int64_t		c_runhrtime;	/* run time ticks since epoch */
	void		(*c_func)(void *); /* function to call */
	void		*c_arg;		/* argument to function */
	kthread_id_t	c_executor;	/* thread executing callout */
	kcondvar_t	c_done;		/* signal callout completion */
} callout_t;

/*
 * The extended callout ID consists of the callout ID (as returned by
 * timeout()) plus a bit indicating whether the callout is executing.
 *
 * The callout ID uniquely identifies a callout.  It contains a table ID,
 * indicating which callout table the callout belongs to, a bit indicating
 * whether this is a short-term or long-term callout, and a running counter.
 * The highest bit of the running counter is always set; this ensures that
 * the callout ID is always non-zero, thus eliminating the need for an
 * explicit wrap-around test during ID generation.
 *
 * The long-term bit exists to address the problem of callout ID collision.
 * This is an issue because the system typically generates a large number of
 * timeout() requests, which means that callout IDs eventually get recycled.
 * Most timeouts are very short-lived, so that ID recycling isn't a problem;
 * but there are a handful of timeouts which are sufficiently long-lived to
 * see their own IDs reused.  We use the long-term bit to partition the
 * ID namespace into pieces; the short-term space gets all the heavy traffic
 * and can wrap frequently (i.e., on the order of a day) with no ill effects;
 * the long-term space gets very little traffic and thus never wraps.
 */
#define	CALLOUT_EXECUTING	(1UL << (8 * sizeof (long) - 1))
#define	CALLOUT_LONGTERM	(1UL << (8 * sizeof (long) - 2))
#define	CALLOUT_COUNTER_HIGH	(1UL << (8 * sizeof (long) - 3))
#define	CALLOUT_FANOUT_BITS	3
#define	CALLOUT_TYPE_BITS	1
#define	CALLOUT_NTYPES		(1 << CALLOUT_TYPE_BITS)
#define	CALLOUT_FANOUT		(1 << CALLOUT_FANOUT_BITS)
#define	CALLOUT_FANOUT_MASK	(CALLOUT_FANOUT - 1)
#define	CALLOUT_COUNTER_SHIFT	(CALLOUT_TYPE_BITS + CALLOUT_FANOUT_BITS)
#define	CALLOUT_COUNTER_LOW	(1 << CALLOUT_COUNTER_SHIFT)
#define	CALLOUT_TABLES		CALLOUT_COUNTER_LOW
#define	CALLOUT_TABLE_MASK	(CALLOUT_TABLES - 1)
#define	CALLOUT_TABLE(t, f)	\
	(((t) << CALLOUT_FANOUT_BITS) + ((f) & CALLOUT_FANOUT_MASK))

/*
 * We assume that during any period of CALLOUT_LONGTERM_TICKS ticks, at most
 * (CALLOUT_COUNTER_HIGH / CALLOUT_COUNTER_LOW) callouts will be generated.
 */
#define	CALLOUT_LONGTERM_TICKS	0x4000
#define	CALLOUT_BUCKETS		512		/* MUST be a power of 2 */
#define	CALLOUT_BUCKET_MASK	(CALLOUT_BUCKETS - 1)
#define	CALLOUT_HASH(x)		((x) & CALLOUT_BUCKET_MASK)
#define	CALLOUT_IDHASH(x)	CALLOUT_HASH((x) >> CALLOUT_COUNTER_SHIFT)
#define	CALLOUT_LBHASH(x)	CALLOUT_HASH(x)

#define	CALLOUT_THREADS		2		/* keep it simple for now */

#define	CALLOUT_REALTIME	0		/* realtime callout type */
#define	CALLOUT_NORMAL		1		/* normal callout type */

/*
 * All of the state information associated with a callout table.
 * The fields are ordered with cache performance in mind.
 */
typedef struct callout_table {
	kmutex_t	ct_lock;	/* protects all callout state */
	callout_t	*ct_freelist;	/* free callout structures */
	clock_t		ct_curtime;	/* current time; tracks lbolt */
	clock_t		ct_runtime;	/* the callouts we're running now */
	int64_t		ct_curhrtime;	/* current time ticks since epoch */
	taskq_t		*ct_taskq;	/* taskq to execute normal callouts */
	callout_id_t	ct_short_id;	/* most recently issued short-term ID */
	callout_id_t	ct_long_id;	/* most recently issued long-term ID */
	callout_t 	*ct_idhash[CALLOUT_BUCKETS];	/* ID hash chains */
	callout_t 	*ct_lbhash[CALLOUT_BUCKETS];	/* lbolt hash chains */
} callout_table_t;

#ifdef	_KERNEL
extern	void		callout_init(void);
extern	void		callout_schedule(void);
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CALLO_H */
