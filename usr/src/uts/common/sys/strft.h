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

#ifndef _SYS_STRFT_H
#define	_SYS_STRFT_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The flow trace subsystem is used to trace the flow of STREAMS messages
 * through a stream.
 *
 * WARNING: this is a private subsystem and subject to change at any time!
 */

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stream.h>

/*
 * Some evnt defines, values 0..N are reserved for internal use,
 * (N+1)..0x1FFF are available for arbitrary module/drvier use,
 * 0x8000 (RD/WR q marker) and 0x4000 (thread cs marker) are or'ed
 * flag bits reserved for internal use.
 */
#define	FTEV_MASK	0x1FFF
#define	FTEV_ISWR	0x8000
#define	FTEV_CS		0x4000
#define	FTEV_PS		0x2000

#define	FTEV_QMASK	0x1F00

#define	FTEV_ALLOCMASK	0x1FF8
#define	FTEV_ALLOCB	0x0000
#define	FTEV_ESBALLOC	0x0001
#define	FTEV_DESBALLOC	0x0002
#define	FTEV_ESBALLOCA	0x0003
#define	FTEV_DESBALLOCA	0x0004
#define	FTEV_ALLOCBIG	0x0005
#define	FTEV_ALLOCBW	0x0006
#define	FTEV_BCALLOCB	0x0007
#define	FTEV_FREEB	0x0008
#define	FTEV_DUPB	0x0009
#define	FTEV_COPYB	0x000A

#define	FTEV_CALLER	0x000F

#define	FTEV_PUT	0x0100
#define	FTEV_PUTQ	0x0105
#define	FTEV_GETQ	0x0106
#define	FTEV_RMVQ	0x0107
#define	FTEV_INSQ	0x0108
#define	FTEV_PUTBQ	0x0109
#define	FTEV_FLUSHQ	0x010A
#define	FTEV_PUTNEXT	0x010D
#define	FTEV_RWNEXT	0x010E

#define	FTBLK_EVNTS	9
#define	FTSTK_DEPTH	15

/*
 * Stack information for each flow trace event; recorded when str_ftstack
 * is non-zero.
 */
typedef struct ftstk {
	uint_t		fs_depth;
	pc_t		fs_stk[FTSTK_DEPTH];
} ftstk_t;

/*
 * Data structure that contains the timestamp, module/driver name, next
 * module/driver name, optional callstack, event and event data (not certain
 * as to its use yet: RSF).  There is one per event.  Every time str_ftevent()
 * is called, one of the indices is filled in with this data.
 */
typedef struct ftevnt {
	hrtime_t	ts;		/* event timestamp, per gethrtime() */
	char 		*mid;		/* module/driver name */
	char		*midnext; 	/* next module/driver name */
	ushort_t 	evnt;		/* FTEV_* value above */
	ushort_t 	data;		/* event data */
	ftstk_t		*stk;		/* optional event callstack */
} ftevnt_t;

/*
 * A linked list of ftevnt arrays.
 */
typedef struct ftblk {
	struct ftblk *nxt;	/* next ftblk (or NULL if none) */
	int ix;			/* index of next free ev[] */
	struct ftevnt ev[FTBLK_EVNTS];
} ftblk_t;

/*
 * The flow trace header (start of event list).  It consists of the
 *      current writable block (tail)
 *      a hash value (for recovering trace information)
 *      The last thread to process an event
 *      The last cpu to process an event
 *      The start of the list
 * This structure is attached to a dblk, and traces a message through
 * a flow.
 */
typedef struct fthdr {
	struct ftblk *tail;
	uint_t hash;		/* accumulated hash value (sum of mid's) */
	void *thread;
	int cpu_seqid;
	struct ftblk first;
} fthdr_t;

#ifdef _KERNEL

struct datab;

extern void str_ftevent(fthdr_t *, void *, ushort_t, ushort_t);
extern void str_ftfree(struct datab *);
extern int str_ftnever, str_ftstack;

/*
 * Allocate flow-trace information and record an allocation event.
 */
#define	STR_FTALLOC(hpp, e, d) {					\
	if (str_ftnever == 0) {						\
		fthdr_t *_hp = *(hpp);					\
									\
		ASSERT(_hp == NULL);					\
		_hp = kmem_cache_alloc(fthdr_cache, KM_NOSLEEP);	\
		if ((*hpp = _hp) != NULL) {				\
			_hp->tail = &_hp->first;			\
			_hp->hash = 0;					\
			_hp->thread = curthread;			\
			_hp->cpu_seqid = CPU->cpu_seqid;		\
			_hp->first.nxt = NULL;				\
			_hp->first.ix = 0;				\
			str_ftevent(_hp, caller(), (e), (d));		\
		}							\
	}								\
}

/*
 * Add a flow-trace event to the passed-in mblk_t and any other mblk_t's
 * chained off of b_cont.
 */
#define	STR_FTEVENT_MSG(mp, p, e, d) {					\
	if (str_ftnever == 0) {						\
		mblk_t *_mp;						\
		fthdr_t *_hp;						\
									\
		for (_mp = (mp); _mp != NULL; _mp = _mp->b_cont) {	\
			if ((_hp = DB_FTHDR(_mp)) != NULL)		\
				str_ftevent(_hp, (p), (e), (d));	\
		}							\
	}								\
}

/*
 * Add a flow-trace event to *just* the passed-in mblk_t.
 */
#define	STR_FTEVENT_MBLK(mp, p, e, d) {					\
	if (str_ftnever == 0) {						\
		fthdr_t *_hp;						\
									\
		if ((mp) != NULL && ((_hp = DB_FTHDR(mp)) != NULL)) 	\
			str_ftevent(_hp, (p), (e), (d));		\
	}								\
}

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_STRFT_H */
