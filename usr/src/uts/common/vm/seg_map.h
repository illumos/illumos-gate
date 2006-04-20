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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef	_VM_SEG_MAP_H
#define	_VM_SEG_MAP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * When segmap is created it is possible to program its behavior,
 *	using the create args [needed for performance reasons].
 * Segmap creates n lists of pages.
 *	For VAC machines, there will be at least one free list
 *	per color. If more than one free list per color is needed,
 *	set nfreelist as needed.
 *
 *	For PAC machines, it will be treated as VAC with only one
 *	color- every page is of the same color. Again, set nfreelist
 *	to get more than one free list.
 */
struct segmap_crargs {
	uint_t	prot;
	uint_t	shmsize;	/* shm_alignment for VAC, 0 for PAC. */
	uint_t	nfreelist;	/* number of freelist per color, >= 1 */
};

#include <vm/kpm.h>
#include <vm/vpm.h>

/*
 * Each smap struct represents a MAXBSIZE sized mapping to the
 * <sm_vp, sm_off> given in the structure.  The location of the
 * the structure in the array gives the virtual address of the
 * mapping. Structure rearranged for 64bit sm_off.
 */
struct	smap {
	kmutex_t	sm_mtx;		/* protect non-list fields */
	struct	vnode	*sm_vp;		/* vnode pointer (if mapped) */
	struct	smap	*sm_hash;	/* hash pointer */
	struct	smap	*sm_next;	/* next pointer */
	struct	smap	*sm_prev;	/* previous pointer */
	u_offset_t	sm_off;		/* file offset for mapping */
	ushort_t	sm_bitmap;	/* bit map for locked translations */
	ushort_t	sm_refcnt;	/* reference count for uses */
	ushort_t	sm_flags;	/* smap flags */
	ushort_t	sm_free_ndx;	/* freelist */
#ifdef	SEGKPM_SUPPORT
	struct kpme	sm_kpme;	/* segkpm */
#endif
};

#ifdef	SEGKPM_SUPPORT
#define	GET_KPME(smp)	(&(smp)->sm_kpme)
#define	sm_kpme_next	sm_kpme.kpe_next
#define	sm_kpme_prev	sm_kpme.kpe_prev
#define	sm_kpme_page	sm_kpme.kpe_page
#else
#define	GET_KPME(smp)	((struct kpme *)NULL)
#endif

/* sm_flags */
#define	SM_KPM_NEWPAGE	   0x00000001	/* page created in segmap_getmapft */
#define	SM_NOTKPM_RELEASED 0x00000002	/* released smap not in segkpm mode */
#define	SM_QNDX_ZERO	   0x00000004	/* on the index 0 freelist */
#define	SM_READ_DATA	   0x00000010	/* page created for read */
#define	SM_WRITE_DATA	   0x00000020	/* page created for write */

/*
 * Multiple smap free lists are maintained so that allocations
 * will scale with cpu count. Each free list is made up of 2 queues
 * so that allocations and deallocations can proceed concurrently.
 * Each queue structure is padded to 64 bytes to avoid false sharing.
 */
#define	SM_FREEQ_PAD (64 - sizeof (struct smap *) - sizeof (kmutex_t))
struct 	sm_freeq {
	struct smap	*smq_free;	/* points into freelist */
	kmutex_t	smq_mtx;	/* protects smq_free */
	char		smq_pad[SM_FREEQ_PAD];
};

struct	smfree {
	struct sm_freeq	sm_freeq[2];	/* alloc and release queues */
	struct sm_freeq	*sm_allocq;	/* current allocq */
	struct sm_freeq	*sm_releq;	/* current releq */
	kcondvar_t	sm_free_cv;
	ushort_t	sm_want;	/* someone wants a slot of this color */
};

/*
 * Cached smaps are kept on hash chains to enable fast reclaim lookups.
 */
struct  smaphash {
	kmutex_t	sh_mtx;		/* protects this hash chain */
	struct  smap	*sh_hash_list;  /* start of hash chain */
};

/*
 * (Semi) private data maintained by the segmap driver per SEGMENT mapping
 * All fields in segmap_data are read-only after the segment is created.
 *
 */

struct	segmap_data {
	struct	smap	*smd_sm;	/* array of smap structures */
	long		smd_npages;	/* size of smap array */
	struct smfree	*smd_free;	/* ptr to freelist header array */
	struct smaphash *smd_hash;	/* ptr to hash header array */
	int		smd_nfree;	/* number of free lists */
	uchar_t		smd_prot;	/* protections for all smap's */
};

/*
 * Statistics for segmap operations.
 *
 * No explicit locking to protect these stats.
 */
struct segmapcnt {
	kstat_named_t	smp_fault;	/* number of segmap_faults */
	kstat_named_t	smp_faulta;	/* number of segmap_faultas */
	kstat_named_t	smp_getmap;	/* number of segmap_getmaps */
	kstat_named_t	smp_get_use;	/* getmaps that reuse existing map */
	kstat_named_t	smp_get_reclaim; /* getmaps that do a reclaim */
	kstat_named_t	smp_get_reuse;	/* getmaps that reuse a slot */
	kstat_named_t	smp_get_unused;	/* getmaps that reuse existing map */
	kstat_named_t	smp_get_nofree;	/* getmaps with no free slots */
	kstat_named_t	smp_rel_async;	/* releases that are async */
	kstat_named_t	smp_rel_write;	/* releases that write */
	kstat_named_t	smp_rel_free;	/* releases that free */
	kstat_named_t	smp_rel_abort;	/* releases that abort */
	kstat_named_t	smp_rel_dontneed; /* releases with dontneed set */
	kstat_named_t	smp_release;	/* releases with no other action */
	kstat_named_t	smp_pagecreate;	/* pagecreates */
	kstat_named_t   smp_free_notfree; /* pages not freed in */
					/* segmap_pagefree */
	kstat_named_t   smp_free_dirty; /* dirty pages freeed */
					/* in segmap_pagefree */
	kstat_named_t   smp_free;	/* clean pages freeed in */
					/* segmap_pagefree */
	kstat_named_t	smp_stolen;	/* segmap_getmapflt() stole */
					/* from get_free_smp() */
	kstat_named_t	smp_get_nomtx;	/* free smaps but no mutex */
};

/*
 * These are flags used on release.  Some of these might get handled
 * by segment operations needed for msync (when we figure them out).
 * SM_ASYNC modifies SM_WRITE.  SM_DONTNEED modifies SM_FREE.  SM_FREE
 * and SM_INVAL as well as SM_FREE and SM_DESTROY are mutually exclusive.
 * SM_DESTROY behaves like SM_INVAL but also forces the pages to be
 * destroyed -- this prevents them from being written to the backing
 * store.
 */
#define	SM_WRITE	0x01		/* write back the pages upon release */
#define	SM_ASYNC	0x02		/* do the write asynchronously */
#define	SM_FREE		0x04		/* put pages back on free list */
#define	SM_INVAL	0x08		/* invalidate page (no caching) */
#define	SM_DONTNEED	0x10		/* less likely to be needed soon */
#define	SM_DESTROY	0x20		/* invalidate page, don't write back */

/*
 * These are the forcefault flags used on getmapflt.
 *
 * The orginal semantic was extended to allow using the segkpm mapping
 * scheme w/o a major segmap interface change for MAXBSIZE == PAGESIZE
 * (which is required to enable segkpm for MAXBSIZE > PAGESIZE).
 * Most segmap consumers needn't to be changed at all or only need to
 * be changed slightly to take advantage of segkpm. Because the segkpm
 * virtual address is based on the physical address of a page, a page is
 * required to determine the virtual address (return value). Pages mapped
 * with segkpm are always at least read locked and are hence protected
 * from pageout or fsflush from segmap_getmap until segmap_release. This
 * implies, that the segkpm mappings are locked within this period too.
 * No trap driven segmap_fault's are possible in segkpm mode.
 *
 * The following combinations of "forcefault" and "rw" allow segkpm mode.
 * (1) SM_FAULT, S_READ
 * (2) SM_FAULT, S_WRITE
 * (3) SM_PAGECREATE, S_WRITE
 * (4) SM_LOCKPROTO, {S_READ, S_WRITE, S_OTHER}
 *
 * The regular additional operations (come in pairs in most of the cases):
 * . segmap_pagecreate/segmap_pageunlock
 * . segmap_fault(F_SOFTLOCK)/segmap_fault(F_SOFTUNLOCK)
 *
 * are mostly a no-op in segkpm mode with the following exceptions:
 * . The "newpage" return value of segmap_pagecreate is still supported
 *   for zeroout operations needed on newly created pages.
 *
 * . segmap_fault() must follow when a error could be expected in
 *   the VOP_GETPAGE. In segkpm mode this error is recognized in
 *   segmap_getmapflt and returned from the following segmap_fault()
 *   call. The "hole" optimization (read only after first VOP_GETPAGE
 *   mapping in segmap_getmapflt followed by a trap driven protection
 *   fault and a second VOP_GETPAGE via segmap_fault) cannot be used.
 *
 * . segmap_fault(F_SOFTUNLOCK) must follow when segmap_getmapflt was
 *   called w/ (SM_LOCKPROTO, S_OTHER). S_WRITE has to be applied, when
 *   the page should be marked "dirty". Otherwise the page is not
 *   written to the backing store later (as mentioned above, no page
 *   or protection faults are possible in segkpm mode). Caller cannot
 *   use only S_OTHER and rely on a protection fault to force the page
 *   to become dirty.
 *
 * . The segmap_pagecreate parameter softlock is ignored, pages and
 *   mappings are locked anyway.
 *
 * SM_LOCKPROTO is used in the fbio layer and some special segmap consumers.
 */
#define	SM_PAGECREATE	0x00		/* create page in segkpm mode, no I/O */
#define	SM_FAULT	0x01		/* fault in page if necessary */
#define	SM_LOCKPROTO	0x02		/* lock/unlock protocol used */

#define	MAXBSHIFT	13		/* log2(MAXBSIZE) */

#define	MAXBOFFSET	(MAXBSIZE - 1)
#define	MAXBMASK	(~MAXBOFFSET)

/*
 * SMAP_HASHAVELEN is the average length desired for this chain, from
 * which the size of the smd_hash table is derived at segment create time.
 * SMAP_HASHVPSHIFT is defined so that 1 << SMAP_HASHVPSHIFT is the
 * approximate size of a vnode struct.
 */
#define	SMAP_HASHAVELEN		4
#define	SMAP_HASHVPSHIFT	6


#ifdef _KERNEL
/*
 * The kernel generic mapping segment.
 */
extern struct seg *segkmap;

/*
 * Public seg_map segment operations.
 */
extern int	segmap_create(struct seg *, void *);
extern int	segmap_pagecreate(struct seg *, caddr_t, size_t, int);
extern void	segmap_pageunlock(struct seg *, caddr_t, size_t, enum seg_rw);
extern faultcode_t segmap_fault(struct hat *, struct seg *, caddr_t, size_t,
		enum fault_type, enum seg_rw);
extern caddr_t	segmap_getmap(struct seg *, struct vnode *, u_offset_t);
extern caddr_t	segmap_getmapflt(struct seg *, struct vnode *, u_offset_t,
		size_t, int, enum seg_rw);
extern int	segmap_release(struct seg *, caddr_t, uint_t);
extern void	segmap_flush(struct seg *, struct vnode *);
extern void	segmap_inval(struct seg *, struct vnode *, u_offset_t);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _VM_SEG_MAP_H */
