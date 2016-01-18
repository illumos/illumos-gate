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

/*
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*	 All Rights Reserved   */

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef	_VM_AS_H
#define	_VM_AS_H

#include <sys/watchpoint.h>
#include <vm/seg.h>
#include <vm/faultcode.h>
#include <vm/hat.h>
#include <sys/avl.h>
#include <sys/proc.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * VM - Address spaces.
 */

/*
 * Each address space consists of a sorted list of segments
 * and machine dependent address translation information.
 *
 * All the hard work is in the segment drivers and the
 * hardware address translation code.
 *
 * The segment list is represented as an AVL tree.
 *
 * The address space lock (a_lock) is a long term lock which serializes
 * access to certain operations (as_map, as_unmap) and protects the
 * underlying generic segment data (seg.h) along with some fields in the
 * address space structure as shown below:
 *
 *	address space structure 	segment structure
 *
 *	a_segtree			s_base
 *	a_size				s_size
 *	a_lastgap			s_link
 *	a_seglast			s_ops
 *					s_as
 *					s_data
 *
 * The address space contents lock (a_contents) is a short term
 * lock that protects most of the data in the address space structure.
 * This lock is always acquired after the "a_lock" in all situations
 * except while dealing with AS_CLAIMGAP to avoid deadlocks.
 *
 * The following fields are protected by this lock:
 *
 *	a_flags (AS_PAGLCK, AS_CLAIMGAP, etc.)
 *	a_unmapwait
 *	a_seglast
 *
 * The address space lock (a_lock) is always held prior to any segment
 * operation.  Some segment drivers use the address space lock to protect
 * some or all of their segment private data, provided the version of
 * "a_lock" (read vs. write) is consistent with the use of the data.
 *
 * The following fields are protected by the hat layer lock:
 *
 *	a_vbits
 *	a_hat
 *	a_hrm
 */

struct as {
	kmutex_t a_contents;	/* protect certain fields in the structure */
	uchar_t  a_flags;	/* as attributes */
	uchar_t	a_vbits;	/* used for collecting statistics */
	kcondvar_t a_cv;	/* used by as_rangelock */
	struct	hat *a_hat;	/* hat structure */
	struct	hrmstat *a_hrm; /* ref and mod bits */
	caddr_t	a_userlimit;	/* highest allowable address in this as */
	struct seg *a_seglast;	/* last segment hit on the addr space */
	krwlock_t a_lock;	/* protects segment related fields */
	size_t	a_size;		/* total size of address space */
	struct seg *a_lastgap;	/* last seg found by as_gap() w/ AS_HI (mmap) */
	struct seg *a_lastgaphl; /* last seg saved in as_gap() either for */
				/* AS_HI or AS_LO used in as_addseg() */
	avl_tree_t a_segtree;	/* segments in this address space. (AVL tree) */
	avl_tree_t a_wpage;	/* watched pages (procfs) */
	uchar_t	a_updatedir;	/* mappings changed, rebuild a_objectdir */
	timespec_t a_updatetime;	/* time when mappings last changed */
	vnode_t	**a_objectdir;	/* object directory (procfs) */
	size_t	a_sizedir;	/* size of object directory */
	struct as_callback *a_callbacks; /* callback list */
	proc_t	*a_proc;	/* back pointer to proc */
	size_t	a_resvsize;	/* size of reserved part of address space */
};

#define	AS_PAGLCK		0x80
#define	AS_CLAIMGAP		0x40
#define	AS_UNMAPWAIT		0x20
#define	AS_NEEDSPURGE		0x10	/* mostly for seg_nf, see as_purge() */
#define	AS_NOUNMAPWAIT		0x02

#define	AS_ISPGLCK(as)		((as)->a_flags & AS_PAGLCK)
#define	AS_ISCLAIMGAP(as)	((as)->a_flags & AS_CLAIMGAP)
#define	AS_ISUNMAPWAIT(as)	((as)->a_flags & AS_UNMAPWAIT)
#define	AS_ISNOUNMAPWAIT(as)	((as)->a_flags & AS_NOUNMAPWAIT)

#define	AS_SETPGLCK(as)		((as)->a_flags |= AS_PAGLCK)
#define	AS_SETCLAIMGAP(as)	((as)->a_flags |= AS_CLAIMGAP)
#define	AS_SETUNMAPWAIT(as)	((as)->a_flags |= AS_UNMAPWAIT)
#define	AS_SETNOUNMAPWAIT(as)	((as)->a_flags |= AS_NOUNMAPWAIT)

#define	AS_CLRPGLCK(as)		((as)->a_flags &= ~AS_PAGLCK)
#define	AS_CLRCLAIMGAP(as)	((as)->a_flags &= ~AS_CLAIMGAP)
#define	AS_CLRUNMAPWAIT(as)	((as)->a_flags &= ~AS_UNMAPWAIT)
#define	AS_CLRNOUNMAPWAIT(as)	((as)->a_flags &= ~AS_NOUNMAPWAIT)

#define	AS_TYPE_64BIT(as)	\
	    (((as)->a_userlimit > (caddr_t)UINT32_MAX) ? 1 : 0)

/*
 * Flags for as_map/as_map_ansegs
 */
#define	AS_MAP_NO_LPOOB		((uint_t)-1)
#define	AS_MAP_HEAP		((uint_t)-2)
#define	AS_MAP_STACK		((uint_t)-3)

/*
 * The as_callback is the basic structure which supports the ability to
 * inform clients of specific events pertaining to address space management.
 * A user calls as_add_callback to register an address space callback
 * for a range of pages, specifying the events that need to occur.
 * When as_do_callbacks is called and finds a 'matching' entry, the
 * callback is called once, and the callback function MUST call
 * as_delete_callback when all callback activities are complete.
 * The thread calling as_do_callbacks blocks until the as_delete_callback
 * is called.  This allows for asynchorous events to subside before the
 * as_do_callbacks thread continues.
 *
 * An example of the need for this is a driver which has done long-term
 * locking of memory.  Address space management operations (events) such
 * as as_free, as_umap, and as_setprot will block indefinitely until the
 * pertinent memory is unlocked.  The callback mechanism provides the
 * way to inform the driver of the event so that the driver may do the
 * necessary unlocking.
 *
 * The contents of this structure is protected by a_contents lock
 */
typedef void (*callback_func_t)(struct as *, void *, uint_t);
struct as_callback {
	struct as_callback	*ascb_next;		/* list link */
	uint_t			ascb_events;		/* event types */
	callback_func_t		ascb_func;   		/* callback function */
	void			*ascb_arg;		/* callback argument */
	caddr_t			ascb_saddr;		/* start address */
	size_t			ascb_len;		/* address range */
};
/*
 * Callback events
 */
#define	AS_FREE_EVENT		0x1
#define	AS_SETPROT_EVENT	0x2
#define	AS_UNMAP_EVENT		0x4
#define	AS_CALLBACK_CALLED	((uint_t)(1U << (8 * sizeof (uint_t) - 1U)))
#define	AS_UNMAPWAIT_EVENT				\
		(AS_FREE_EVENT | AS_SETPROT_EVENT | AS_UNMAP_EVENT)
#define	AS_ALL_EVENT					\
		(AS_FREE_EVENT | AS_SETPROT_EVENT | AS_UNMAP_EVENT)


/* Return code values for as_callback_delete */
enum as_cbdelete_rc {
	AS_CALLBACK_DELETED,
	AS_CALLBACK_NOTFOUND,
	AS_CALLBACK_DELETE_DEFERRED
};

#ifdef _KERNEL

/*
 * Flags for as_gap.
 */
#define	AH_DIR		0x1	/* direction flag mask */
#define	AH_LO		0x0	/* find lowest hole */
#define	AH_HI		0x1	/* find highest hole */
#define	AH_CONTAIN	0x2	/* hole must contain `addr' */

extern struct as kas;		/* kernel's address space */

/*
 * Macros for address space locking.  Note that we use RW_READER_STARVEWRITER
 * whenever we acquire the address space lock as reader to assure that it can
 * be used without regard to lock order in conjunction with filesystem locks.
 * This allows filesystems to safely induce user-level page faults with
 * filesystem locks held while concurrently allowing filesystem entry points
 * acquiring those same locks to be called with the address space lock held as
 * reader.  RW_READER_STARVEWRITER thus prevents reader/reader+RW_WRITE_WANTED
 * deadlocks in the style of fop_write()+as_fault()/as_*()+fop_putpage() and
 * fop_read()+as_fault()/as_*()+fop_getpage().  (See the Big Theory Statement
 * in rwlock.c for more information on the semantics of and motivation behind
 * RW_READER_STARVEWRITER.)
 */
#define	AS_LOCK_ENTER(as, type)		rw_enter(&(as)->a_lock, \
	(type) == RW_READER ? RW_READER_STARVEWRITER : (type))
#define	AS_LOCK_EXIT(as)		rw_exit(&(as)->a_lock)
#define	AS_LOCK_DESTROY(as)		rw_destroy(&(as)->a_lock)
#define	AS_LOCK_TRYENTER(as, type)	rw_tryenter(&(as)->a_lock, \
	(type) == RW_READER ? RW_READER_STARVEWRITER : (type))

/*
 * Macros to test lock states.
 */
#define	AS_LOCK_HELD(as)		RW_LOCK_HELD(&(as)->a_lock)
#define	AS_READ_HELD(as)		RW_READ_HELD(&(as)->a_lock)
#define	AS_WRITE_HELD(as)		RW_WRITE_HELD(&(as)->a_lock)

/*
 * macros to walk thru segment lists
 */
#define	AS_SEGFIRST(as)		avl_first(&(as)->a_segtree)
#define	AS_SEGNEXT(as, seg)	AVL_NEXT(&(as)->a_segtree, (seg))
#define	AS_SEGPREV(as, seg)	AVL_PREV(&(as)->a_segtree, (seg))

void	as_init(void);
void	as_avlinit(struct as *);
struct	seg *as_segat(struct as *as, caddr_t addr);
void	as_rangelock(struct as *as);
void	as_rangeunlock(struct as *as);
struct	as *as_alloc();
void	as_free(struct as *as);
int	as_dup(struct as *as, struct proc *forkedproc);
struct	seg *as_findseg(struct as *as, caddr_t addr, int tail);
int	as_addseg(struct as *as, struct seg *newseg);
struct	seg *as_removeseg(struct as *as, struct seg *seg);
faultcode_t as_fault(struct hat *hat, struct as *as, caddr_t addr, size_t size,
		enum fault_type type, enum seg_rw rw);
faultcode_t as_faulta(struct as *as, caddr_t addr, size_t size);
int	as_setprot(struct as *as, caddr_t addr, size_t size, uint_t prot);
int	as_checkprot(struct as *as, caddr_t addr, size_t size, uint_t prot);
int	as_unmap(struct as *as, caddr_t addr, size_t size);
int	as_map(struct as *as, caddr_t addr, size_t size, int ((*crfp)()),
		void *argsp);
void	as_purge(struct as *as);
int	as_gap(struct as *as, size_t minlen, caddr_t *basep, size_t *lenp,
		uint_t flags, caddr_t addr);
int	as_gap_aligned(struct as *as, size_t minlen, caddr_t *basep,
	    size_t *lenp, uint_t flags, caddr_t addr, size_t align,
	    size_t redzone, size_t off);

int	as_memory(struct as *as, caddr_t *basep, size_t *lenp);
size_t	as_swapout(struct as *as);
int	as_incore(struct as *as, caddr_t addr, size_t size, char *vec,
		size_t *sizep);
int	as_ctl(struct as *as, caddr_t addr, size_t size, int func, int attr,
		uintptr_t arg, ulong_t *lock_map, size_t pos);
int	as_pagelock(struct as *as, struct page ***ppp, caddr_t addr,
		size_t size, enum seg_rw rw);
void	as_pageunlock(struct as *as, struct page **pp, caddr_t addr,
		size_t size, enum seg_rw rw);
int	as_setpagesize(struct as *as, caddr_t addr, size_t size, uint_t szc,
		boolean_t wait);
int	as_set_default_lpsize(struct as *as, caddr_t addr, size_t size);
void	as_setwatch(struct as *as);
void	as_clearwatch(struct as *as);
int	as_getmemid(struct as *, caddr_t, memid_t *);

int	as_add_callback(struct as *, void (*)(), void *, uint_t,
			caddr_t, size_t, int);
uint_t	as_delete_callback(struct as *, void *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _VM_AS_H */
