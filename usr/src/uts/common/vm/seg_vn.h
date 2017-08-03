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
 * Copyright 2018 Joyent, Inc.
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

#ifndef	_VM_SEG_VN_H
#define	_VM_SEG_VN_H

#include <sys/lgrp.h>
#include <vm/anon.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * A pointer to this structure is passed to segvn_create().
 */
typedef struct segvn_crargs {
	struct	vnode *vp;	/* vnode mapped from */
	struct	cred *cred;	/* credentials */
	u_offset_t	offset; /* starting offset of vnode for mapping */
	uchar_t	type;		/* type of sharing done */
	uchar_t	prot;		/* protections */
	uchar_t	maxprot;	/* maximum protections */
	uint_t	flags;		/* flags */
	struct	anon_map *amp;	/* anon mapping to map to */
	uint_t	szc;		/* max preferred page size code */
	uint_t	lgrp_mem_policy_flags;
} segvn_crargs_t;

/*
 * (Semi) private data maintained by the seg_vn driver per segment mapping.
 *
 * The read/write segment lock protects all of segvn_data including the
 * vpage array.  All fields in segvn_data are treated as read-only when
 * the "read" version of the address space and the segment locks are held.
 * The "write" version of the segment lock, however, is required in order to
 * update the following fields:
 *
 *	pageprot
 *	prot
 *	amp
 *	vpage
 *
 * 	softlockcnt
 * is written by acquiring either the readers lock on the segment and
 * freemem lock, or any lock combination which guarantees exclusive use
 * of this segment (e.g., adress space writers lock,
 * address space readers lock + segment writers lock).
 */
typedef struct	segvn_data {
	krwlock_t lock;		/* protect segvn_data and vpage array */
	kmutex_t segfree_syncmtx; /* barrier lock for segvn_free() */
	uchar_t	pageprot;	/* true if per page protections present */
	uchar_t	prot;		/* current segment prot if pageprot == 0 */
	uchar_t	maxprot;	/* maximum segment protections */
	uchar_t	type;		/* type of sharing done */
	u_offset_t offset;	/* starting offset of vnode for mapping */
	struct	vnode *vp;	/* vnode that segment mapping is to */
	ulong_t	anon_index;	/* starting index into anon_map anon array */
	struct	anon_map *amp;	/* pointer to anon share structure, if needed */
	struct	vpage *vpage;	/* per-page information, if needed */
	struct	cred *cred;	/* mapping credentials */
	size_t	swresv;		/* swap space reserved for this segment */
	uchar_t	advice;		/* madvise flags for segment */
	uchar_t	pageadvice;	/* true if per page advice set */
	uchar_t svn_inz;	/* true if pages marked as inherit zero */
	ushort_t flags;		/* flags - from sys/mman.h */
	spgcnt_t softlockcnt;	/* # of pages SOFTLOCKED in seg */
	lgrp_mem_policy_info_t policy_info; /* memory allocation policy */
	hat_region_cookie_t rcookie;	/* region for hat calls */
	lgrp_mem_policy_info_t tr_policy_info; /* memory allocation for TR */
	struct	seg *seg;	/* pointer back to seg */
	struct	segvn_data *svn_trnext; /* textrepl list next link */
	struct	segvn_data *svn_trprev; /* textrepl list prev link */
	int	tr_state;	/* TR (text replication) state */
	uchar_t	pageswap;	/* true if per page swap accounting is set */
	spgcnt_t softlockcnt_sbase; /* # of softlocks for seg start addr */
	spgcnt_t softlockcnt_send; /* # of softlocks for seg end addr */
} segvn_data_t;

#ifdef _KERNEL

/*
 * segment text replication states.
 */
#define	SEGVN_TR_INIT	(0)	/* Check if text replication can be enabled */
#define	SEGVN_TR_ON	(1)	/* Text replication is enabled */
#define	SEGVN_TR_OFF	(2)	/* Text replication is disabled */

/*
 * Inherit zero states
 */
#define	SEGVN_INZ_NONE	(0)	/* Nothing in the segment is inherit zero */
#define	SEGVN_INZ_ALL	(1)	/* Everything in the segment is inherit zero */
#define	SEGVN_INZ_VPP	(2)	/* Check struct vpages for inherit zero */

/*
 * Macros for segvn segment driver locking.
 */
#define	SEGVN_LOCK_ENTER(as, lock, type)	rw_enter((lock), (type))
#define	SEGVN_LOCK_EXIT(as, lock)		rw_exit((lock))
#define	SEGVN_LOCK_DOWNGRADE(as, lock)		rw_downgrade((lock))
#define	SEGVN_LOCK_TRYENTER(as, lock, type)	rw_tryenter((lock), (type))

/*
 * Macros to test lock states.
 */
#define	SEGVN_LOCK_HELD(as, lock)		RW_LOCK_HELD((lock))
#define	SEGVN_READ_HELD(as, lock)		RW_READ_HELD((lock))
#define	SEGVN_WRITE_HELD(as, lock)		RW_WRITE_HELD((lock))

/*
 * Macro used to detect the need to Break the sharing of COW pages
 *
 * The rw == S_WRITE is for the COW case
 * rw == S_READ and type == SOFTLOCK is for the physio case
 * We don't want to share a softlocked page because it can cause problems
 * with multithreaded apps but if rw == S_READ_NOCOW it's ok to not break
 * sharing of COW pages even in SOFTLOCK case.
 */
#define	BREAK_COW_SHARE(rw, type, seg_type) ((rw == S_WRITE || \
	(type == F_SOFTLOCK && rw != S_READ_NOCOW)) && \
	seg_type == MAP_PRIVATE)

#define	SEGVN_ZFOD_ARGS(prot, max)	\
	{ NULL, NULL, 0, MAP_PRIVATE, prot, max, 0, NULL, 0, 0 }

#define	AS_MAP_CHECK_VNODE_LPOOB(crfp, argsp)				\
	((crfp) == (segcreate_func_t)segvn_create &&			\
	(((struct segvn_crargs *)(argsp))->flags &			\
	    (MAP_TEXT | MAP_INITDATA)) &&				\
	((struct segvn_crargs *)(argsp))->szc == 0 &&			\
	((struct segvn_crargs *)(argsp))->vp != NULL)

#define	AS_MAP_CHECK_ANON_LPOOB(crfp, argsp)				\
	((crfp) == (segcreate_func_t)segvn_create &&			\
	(((struct segvn_crargs *)(argsp))->szc == 0 ||			\
	((struct segvn_crargs *)(argsp))->szc == AS_MAP_HEAP ||		\
	((struct segvn_crargs *)(argsp))->szc == AS_MAP_STACK) &&	\
	((struct segvn_crargs *)(argsp))->vp == NULL)

#define	SVNTR_HASH_FUNC(vp)	(((((uintptr_t)(vp)) >> 4) ^		\
				    (((uintptr_t)(vp)) >> 11)) & 	\
					(svntr_hashtab_sz - 1))

#define	SEGVN_TR_ADDSTAT(stat)						\
	segvn_textrepl_stats[CPU->cpu_id].tr_stat_##stat++

#define	SEGVN_DATA(seg)	((struct segvn_data *)(seg)->s_data)
#define	SEG_IS_PARTIAL_RESV(seg)	\
	((seg)->s_ops == &segvn_ops && SEGVN_DATA(seg) != NULL && \
	(SEGVN_DATA(seg)->vp == NULL || \
	SEGVN_DATA(seg)->vp->v_type != VREG) &&	\
	(SEGVN_DATA(seg)->flags & MAP_NORESERVE))

/*
 * A hash table entry looked up by vnode, off/eoff and szc to find anon map to
 * use for text replication based on main thread's (t_tid = 1) lgrp.
 */
typedef struct svntr {
	struct vnode	*tr_vp;		/* text file vnode */
	u_offset_t	tr_off;		/* tr_vp mapping start offset */
	size_t		tr_eoff;	/* tr_vp mapping end offset */
	uint_t		tr_szc;		/* tr_vp mapping pagesize */
	int		tr_valid;	/* entry validity state */
	struct svntr	*tr_next;	/* next svntr in this hash bucket */
	timestruc_t	tr_mtime;	/* tr_vp modification time */
	timestruc_t	tr_ctime;	/* time of last change to attributes */
	ulong_t		tr_refcnt;	/* number of segs sharing this entry */
	segvn_data_t	*tr_svnhead;	/* list of segs sharing this entry */
	struct anon_map	*tr_amp[NLGRPS_MAX]; /* per lgrp anon maps */
} svntr_t;

typedef struct svntr_bucket {
	svntr_t		*tr_head;	/* first svntr in this hash bucket */
	kmutex_t	tr_lock;	/* per bucket lock */
} svntr_bucket_t;

typedef struct svntr_stats {
	ulong_t		tr_stat_gaerr;   /* VOP_GETATTR() failures */
	ulong_t		tr_stat_overmap; /* no TR due to beyond EOF mappings */
	ulong_t		tr_stat_wrcnt;	 /* no TR due to writtable mappings */
	ulong_t		tr_stat_stale;	 /* TR entry is stale */
	ulong_t		tr_stat_overlap; /* overlap with other mappings */
	ulong_t		tr_stat_nokmem;	 /* no TR due to kmem alloc failures */
	ulong_t		tr_stat_noanon;	 /* no TR due to no swap space */
	ulong_t		tr_stat_normem;  /* no TR due to no repl memory */
	ulong_t		tr_stat_nolock;	 /* async TR failure due to locks */
	ulong_t		tr_stat_asyncrepl; /* number of async TRs */
	ulong_t		tr_stat_repl;	  /* number of sync TRs */
	ulong_t		tr_stat_newamp;	  /* number of new amp allocs for TR */
} svntr_stats_t;

extern void	segvn_init(void);
extern int	segvn_create(struct seg **, void *);

extern	struct seg_ops segvn_ops;

/*
 * Provided as shorthand for creating user zfod segments.
 */
extern	caddr_t zfod_argsp;
extern	caddr_t kzfod_argsp;
extern	caddr_t stack_exec_argsp;
extern	caddr_t stack_noexec_argsp;

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _VM_SEG_VN_H */
