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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2015, Joyent, Inc.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef	_VM_SEG_H
#define	_VM_SEG_H

#include <sys/vnode.h>
#include <sys/avl.h>
#include <vm/seg_enum.h>
#include <vm/faultcode.h>
#include <vm/hat.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * VM - Segments.
 */

struct anon_map;

/*
 * kstat statistics for segment advise
 */
typedef struct {
	kstat_named_t MADV_FREE_hit;
	kstat_named_t MADV_FREE_miss;
} segadvstat_t;

/*
 * memory object ids
 */
typedef struct memid { u_longlong_t val[2]; } memid_t;

/*
 * An address space contains a set of segments, managed by drivers.
 * Drivers support mapped devices, sharing, copy-on-write, etc.
 *
 * The seg structure contains a lock to prevent races, the base virtual
 * address and size of the segment, a back pointer to the containing
 * address space, pointers to maintain an AVL tree of segments in the
 * same address space, and procedure and data hooks for the driver.
 * The AVL tree of segments for the address space is sorted by
 * ascending base addresses and overlapping segments are not allowed.
 *
 * After a segment is created, faults may occur on pages of the segment.
 * When a fault occurs, the fault handling code must get the desired
 * object and set up the hardware translation to the object.  For some
 * objects, the fault handling code also implements copy-on-write.
 *
 * When the hat wants to unload a translation, it can call the unload
 * routine which is responsible for processing reference and modify bits.
 *
 * Each segment is protected by it's containing address space lock.  To
 * access any field in the segment structure, the "as" must be locked.
 * If a segment field is to be modified, the address space lock must be
 * write locked.
 */

typedef struct pcache_link {
	struct pcache_link	*p_lnext;
	struct pcache_link	*p_lprev;
} pcache_link_t;

typedef struct seg {
	caddr_t	s_base;			/* base virtual address */
	size_t	s_size;			/* size in bytes */
	uint_t	s_szc;			/* max page size code */
	uint_t	s_flags;		/* flags for segment, see below */
	struct	as *s_as;		/* containing address space */
	avl_node_t s_tree;		/* AVL tree links to segs in this as */
	struct	seg_ops *s_ops;		/* ops vector: see below */
	void *s_data;			/* private data for instance */
	kmutex_t s_pmtx;		/* protects seg's pcache list */
	pcache_link_t s_phead;		/* head of seg's pcache list */
} seg_t;

#define	S_PURGE		(0x01)		/* seg should be purged in as_gap() */

struct	seg_ops {
	int	(*dup)(struct seg *, struct seg *);
	int	(*unmap)(struct seg *, caddr_t, size_t);
	void	(*free)(struct seg *);
	faultcode_t (*fault)(struct hat *, struct seg *, caddr_t, size_t,
	    enum fault_type, enum seg_rw);
	faultcode_t (*faulta)(struct seg *, caddr_t);
	int	(*setprot)(struct seg *, caddr_t, size_t, uint_t);
	int	(*checkprot)(struct seg *, caddr_t, size_t, uint_t);
	int	(*kluster)(struct seg *, caddr_t, ssize_t);
	size_t	(*swapout)(struct seg *);
	int	(*sync)(struct seg *, caddr_t, size_t, int, uint_t);
	size_t	(*incore)(struct seg *, caddr_t, size_t, char *);
	int	(*lockop)(struct seg *, caddr_t, size_t, int, int, ulong_t *,
			size_t);
	int	(*getprot)(struct seg *, caddr_t, size_t, uint_t *);
	u_offset_t	(*getoffset)(struct seg *, caddr_t);
	int	(*gettype)(struct seg *, caddr_t);
	int	(*getvp)(struct seg *, caddr_t, struct vnode **);
	int	(*advise)(struct seg *, caddr_t, size_t, uint_t);
	void	(*dump)(struct seg *);
	int	(*pagelock)(struct seg *, caddr_t, size_t, struct page ***,
			enum lock_type, enum seg_rw);
	int	(*setpagesize)(struct seg *, caddr_t, size_t, uint_t);
	int	(*getmemid)(struct seg *, caddr_t, memid_t *);
	struct lgrp_mem_policy_info	*(*getpolicy)(struct seg *, caddr_t);
	int	(*capable)(struct seg *, segcapability_t);
	int	(*inherit)(struct seg *, caddr_t, size_t, uint_t);
};

#ifdef _KERNEL

/*
 * Generic segment operations
 */
extern	void	seg_init(void);
extern	struct	seg *seg_alloc(struct as *as, caddr_t base, size_t size);
extern	int	seg_attach(struct as *as, caddr_t base, size_t size,
			struct seg *seg);
extern	void	seg_unmap(struct seg *seg);
extern	void	seg_free(struct seg *seg);

/*
 * functions for pagelock cache support
 */
typedef	int (*seg_preclaim_cbfunc_t)(void *, caddr_t, size_t,
    struct page **, enum seg_rw, int);

extern	struct	page **seg_plookup(struct seg *seg, struct anon_map *amp,
    caddr_t addr, size_t len, enum seg_rw rw, uint_t flags);
extern	void	seg_pinactive(struct seg *seg, struct anon_map *amp,
    caddr_t addr, size_t len, struct page **pp, enum seg_rw rw,
    uint_t flags, seg_preclaim_cbfunc_t callback);

extern	void	seg_ppurge(struct seg *seg, struct anon_map *amp,
    uint_t flags);
extern	void	seg_ppurge_wiredpp(struct page **pp);

extern	int	seg_pinsert_check(struct seg *seg, struct anon_map *amp,
    caddr_t addr, size_t len, uint_t flags);
extern	int	seg_pinsert(struct seg *seg, struct anon_map *amp,
    caddr_t addr, size_t len, size_t wlen, struct page **pp, enum seg_rw rw,
    uint_t flags, seg_preclaim_cbfunc_t callback);

extern	void	seg_pasync_thread(void);
extern	void	seg_preap(void);
extern	int	seg_p_disable(void);
extern	void	seg_p_enable(void);

extern	segadvstat_t	segadvstat;

/*
 * Flags for pagelock cache support.
 * Flags argument is passed as uint_t to pcache routines.  upper 16 bits of
 * the flags argument are reserved for alignment page shift when SEGP_PSHIFT
 * is set.
 */
#define	SEGP_FORCE_WIRED	0x1	/* skip check against seg_pwindow */
#define	SEGP_AMP		0x2	/* anon map's pcache entry */
#define	SEGP_PSHIFT		0x4	/* addr pgsz shift for hash function */

/*
 * Return values for seg_pinsert and seg_pinsert_check functions.
 */
#define	SEGP_SUCCESS		0	/* seg_pinsert() succeeded */
#define	SEGP_FAIL		1	/* seg_pinsert() failed */

/* Page status bits for segop_incore */
#define	SEG_PAGE_INCORE		0x01	/* VA has a page backing it */
#define	SEG_PAGE_LOCKED		0x02	/* VA has a page that is locked */
#define	SEG_PAGE_HASCOW		0x04	/* VA has a page with a copy-on-write */
#define	SEG_PAGE_SOFTLOCK	0x08	/* VA has a page with softlock held */
#define	SEG_PAGE_VNODEBACKED	0x10	/* Segment is backed by a vnode */
#define	SEG_PAGE_ANON		0x20	/* VA has an anonymous page */
#define	SEG_PAGE_VNODE		0x40	/* VA has a vnode page backing it */

#define	SEGOP_DUP(s, n)		    (*(s)->s_ops->dup)((s), (n))
#define	SEGOP_UNMAP(s, a, l)	    (*(s)->s_ops->unmap)((s), (a), (l))
#define	SEGOP_FREE(s)		    (*(s)->s_ops->free)((s))
#define	SEGOP_FAULT(h, s, a, l, t, rw) \
		(*(s)->s_ops->fault)((h), (s), (a), (l), (t), (rw))
#define	SEGOP_FAULTA(s, a)	    (*(s)->s_ops->faulta)((s), (a))
#define	SEGOP_SETPROT(s, a, l, p)   (*(s)->s_ops->setprot)((s), (a), (l), (p))
#define	SEGOP_CHECKPROT(s, a, l, p) (*(s)->s_ops->checkprot)((s), (a), (l), (p))
#define	SEGOP_KLUSTER(s, a, d)	    (*(s)->s_ops->kluster)((s), (a), (d))
#define	SEGOP_SWAPOUT(s)	    (*(s)->s_ops->swapout)((s))
#define	SEGOP_SYNC(s, a, l, atr, f) \
		(*(s)->s_ops->sync)((s), (a), (l), (atr), (f))
#define	SEGOP_INCORE(s, a, l, v)    (*(s)->s_ops->incore)((s), (a), (l), (v))
#define	SEGOP_LOCKOP(s, a, l, atr, op, b, p) \
		(*(s)->s_ops->lockop)((s), (a), (l), (atr), (op), (b), (p))
#define	SEGOP_GETPROT(s, a, l, p)   (*(s)->s_ops->getprot)((s), (a), (l), (p))
#define	SEGOP_GETOFFSET(s, a)	    (*(s)->s_ops->getoffset)((s), (a))
#define	SEGOP_GETTYPE(s, a)	    (*(s)->s_ops->gettype)((s), (a))
#define	SEGOP_GETVP(s, a, vpp)	    (*(s)->s_ops->getvp)((s), (a), (vpp))
#define	SEGOP_ADVISE(s, a, l, b)    (*(s)->s_ops->advise)((s), (a), (l), (b))
#define	SEGOP_DUMP(s)		    (*(s)->s_ops->dump)((s))
#define	SEGOP_PAGELOCK(s, a, l, p, t, rw) \
		(*(s)->s_ops->pagelock)((s), (a), (l), (p), (t), (rw))
#define	SEGOP_SETPAGESIZE(s, a, l, szc) \
		(*(s)->s_ops->setpagesize)((s), (a), (l), (szc))
#define	SEGOP_GETMEMID(s, a, mp)    (*(s)->s_ops->getmemid)((s), (a), (mp))
#define	SEGOP_GETPOLICY(s, a)	    (*(s)->s_ops->getpolicy)((s), (a))
#define	SEGOP_CAPABLE(s, c)	    (*(s)->s_ops->capable)((s), (c))
#define	SEGOP_INHERIT(s, a, l, b)   (*(s)->s_ops->inherit)((s), (a), (l), (b))

#define	seg_page(seg, addr) \
	(((uintptr_t)((addr) - (seg)->s_base)) >> PAGESHIFT)

#define	seg_pages(seg) \
	(((uintptr_t)((seg)->s_size + PAGEOFFSET)) >> PAGESHIFT)

#define	IE_NOMEM	-1	/* internal to seg layer */
#define	IE_RETRY	-2	/* internal to seg layer */
#define	IE_REATTACH	-3	/* internal to seg layer */

/* Values for SEGOP_INHERIT */
#define	SEGP_INH_ZERO	0x01

int seg_inherit_notsup(struct seg *, caddr_t, size_t, uint_t);

/* Delay/retry factors for seg_p_mem_config_pre_del */
#define	SEGP_PREDEL_DELAY_FACTOR	4
/*
 * As a workaround to being unable to purge the pagelock
 * cache during a DR delete memory operation, we use
 * a stall threshold that is twice the maximum seen
 * during testing.  This workaround will be removed
 * when a suitable fix is found.
 */
#define	SEGP_STALL_SECONDS	25
#define	SEGP_STALL_THRESHOLD \
	(SEGP_STALL_SECONDS * SEGP_PREDEL_DELAY_FACTOR)

#ifdef VMDEBUG

uint_t	seg_page(struct seg *, caddr_t);
uint_t	seg_pages(struct seg *);

#endif	/* VMDEBUG */

boolean_t	seg_can_change_zones(struct seg *);
size_t		seg_swresv(struct seg *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _VM_SEG_H */
