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
 * Copyright (c) 1986, 2010, Oracle and/or its affiliates. All rights reserved.
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

#ifndef	_VM_PAGE_H
#define	_VM_PAGE_H

#include <vm/seg.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_KERNEL) || defined(_KMEMUSER)

/*
 * Shared/Exclusive lock.
 */

/*
 * Types of page locking supported by page_lock & friends.
 */
typedef enum {
	SE_SHARED,
	SE_EXCL			/* exclusive lock (value == -1) */
} se_t;

/*
 * For requesting that page_lock reclaim the page from the free list.
 */
typedef enum {
	P_RECLAIM,		/* reclaim page from free list */
	P_NO_RECLAIM		/* DON`T reclaim the page	*/
} reclaim_t;

/*
 * Callers of page_try_reclaim_lock and page_lock_es can use this flag
 * to get SE_EXCL access before reader/writers are given access.
 */
#define	SE_EXCL_WANTED	0x02

/*
 * All page_*lock() requests will be denied unless this flag is set in
 * the 'es' parameter.
 */
#define	SE_RETIRED	0x04

#endif	/* _KERNEL | _KMEMUSER */

typedef int	selock_t;

/*
 * Define VM_STATS to turn on all sorts of statistic gathering about
 * the VM layer.  By default, it is only turned on when DEBUG is
 * also defined.
 */
#ifdef DEBUG
#define	VM_STATS
#endif	/* DEBUG */

#ifdef VM_STATS
#define	VM_STAT_ADD(stat)			(stat)++
#define	VM_STAT_COND_ADD(cond, stat)		((void) (!(cond) || (stat)++))
#else
#define	VM_STAT_ADD(stat)
#define	VM_STAT_COND_ADD(cond, stat)
#endif	/* VM_STATS */

#ifdef _KERNEL

/*
 * PAGE_LLOCK_SIZE is 2 * NCPU, but no smaller than 128.
 * PAGE_LLOCK_SHIFT is log2(PAGE_LLOCK_SIZE).
 *
 * We use ? : instead of #if because <vm/page.h> is included everywhere;
 * NCPU_P2 is only a constant in the "unix" module.
 *
 */
#define	PAGE_LLOCK_SHIFT \
	    ((unsigned)(((2*NCPU_P2) > 128) ? NCPU_LOG2 + 1 : 7))

#define	PAGE_LLOCK_SIZE (1ul << PAGE_LLOCK_SHIFT)

/*
 * The number of low order 0 (or less variable) bits in the page_t address.
 */
#if defined(__sparc)
#define	PP_SHIFT		7
#else
#define	PP_SHIFT		6
#endif

/*
 * pp may be the root of a large page, and many low order bits will be 0.
 * Shift and XOR multiple times to capture the good bits across the range of
 * possible page sizes.
 */
#define	PAGE_LLOCK_HASH(pp)	\
	(((((uintptr_t)(pp) >> PP_SHIFT) ^ \
	((uintptr_t)(pp) >> (PAGE_LLOCK_SHIFT + PP_SHIFT))) ^ \
	((uintptr_t)(pp) >> ((PAGE_LLOCK_SHIFT * 2) + PP_SHIFT)) ^ \
	((uintptr_t)(pp) >> ((PAGE_LLOCK_SHIFT * 3) + PP_SHIFT))) & \
	(PAGE_LLOCK_SIZE - 1))

#define	page_struct_lock(pp)	\
	mutex_enter(&page_llocks[PAGE_LLOCK_HASH(PP_PAGEROOT(pp))].pad_mutex)
#define	page_struct_unlock(pp)	\
	mutex_exit(&page_llocks[PAGE_LLOCK_HASH(PP_PAGEROOT(pp))].pad_mutex)

#endif	/* _KERNEL */

#include <sys/t_lock.h>

struct as;

/*
 * Each physical page has a page structure, which is used to maintain
 * these pages as a cache.  A page can be found via a hashed lookup
 * based on the [vp, offset].  If a page has an [vp, offset] identity,
 * then it is entered on a doubly linked circular list off the
 * vnode using the vpnext/vpprev pointers.   If the p_free bit
 * is on, then the page is also on a doubly linked circular free
 * list using next/prev pointers.  If the "p_selock" and "p_iolock"
 * are held, then the page is currently being read in (exclusive p_selock)
 * or written back (shared p_selock).  In this case, the next/prev pointers
 * are used to link the pages together for a consecutive i/o request.  If
 * the page is being brought in from its backing store, then other processes
 * will wait for the i/o to complete before attaching to the page since it
 * will have an "exclusive" lock.
 *
 * Each page structure has the locks described below along with
 * the fields they protect:
 *
 *	p_selock	This is a per-page shared/exclusive lock that is
 *			used to implement the logical shared/exclusive
 *			lock for each page.  The "shared" lock is normally
 *			used in most cases while the "exclusive" lock is
 *			required to destroy or retain exclusive access to
 *			a page (e.g., while reading in pages).  The appropriate
 *			lock is always held whenever there is any reference
 *			to a page structure (e.g., during i/o).
 *			(Note that with the addition of the "writer-lock-wanted"
 *			semantics (via SE_EWANTED), threads must not acquire
 *			multiple reader locks or else a deadly embrace will
 *			occur in the following situation: thread 1 obtains a
 *			reader lock; next thread 2 fails to get a writer lock
 *			but specified SE_EWANTED so it will wait by either
 *			blocking (when using page_lock_es) or spinning while
 *			retrying (when using page_try_reclaim_lock) until the
 *			reader lock is released; then thread 1 attempts to
 *			get another reader lock but is denied due to
 *			SE_EWANTED being set, and now both threads are in a
 *			deadly embrace.)
 *
 *				p_hash
 *				p_vnode
 *				p_offset
 *
 *				p_free
 *				p_age
 *
 *	p_iolock	This is a binary semaphore lock that provides
 *			exclusive access to the i/o list links in each
 *			page structure.  It is always held while the page
 *			is on an i/o list (i.e., involved in i/o).  That is,
 *			even though a page may be only `shared' locked
 *			while it is doing a write, the following fields may
 *			change anyway.  Normally, the page must be
 *			`exclusively' locked to change anything in it.
 *
 *				p_next
 *				p_prev
 *
 * The following fields are protected by the global page_llocks[]:
 *
 *				p_lckcnt
 *				p_cowcnt
 *
 * The following lists are protected by the global page_freelock:
 *
 *				page_cachelist
 *				page_freelist
 *
 * The following, for our purposes, are protected by
 * the global freemem_lock:
 *
 *				freemem
 *				freemem_wait
 *				freemem_cv
 *
 * The following fields are protected by hat layer lock(s).  When a page
 * structure is not mapped and is not associated with a vnode (after a call
 * to page_hashout() for example) the p_nrm field may be modified with out
 * holding the hat layer lock:
 *
 *				p_nrm
 *				p_mapping
 *				p_share
 *
 * The following field is file system dependent.  How it is used and
 * the locking strategies applied are up to the individual file system
 * implementation.
 *
 *				p_fsdata
 *
 * The page structure is used to represent and control the system's
 * physical pages.  There is one instance of the structure for each
 * page that is not permenately allocated.  For example, the pages that
 * hold the page structures are permanently held by the kernel
 * and hence do not need page structures to track them.  The array
 * of page structures is allocated early on in the kernel's life and
 * is based on the amount of available physical memory.
 *
 * Each page structure may simultaneously appear on several linked lists.
 * The lists are:  hash list, free or in i/o list, and a vnode's page list.
 * Each type of list is protected by a different group of mutexes as described
 * below:
 *
 * The hash list is used to quickly find a page when the page's vnode and
 * offset within the vnode are known.  Each page that is hashed is
 * connected via the `p_hash' field.  The anchor for each hash is in the
 * array `page_hash'.  An array of mutexes, `ph_mutex', protects the
 * lists anchored by page_hash[].  To either search or modify a given hash
 * list, the appropriate mutex in the ph_mutex array must be held.
 *
 * The free list contains pages that are `free to be given away'.  For
 * efficiency reasons, pages on this list are placed in two catagories:
 * pages that are still associated with a vnode, and pages that are not
 * associated with a vnode.  Free pages always have their `p_free' bit set,
 * free pages that are still associated with a vnode also have their
 * `p_age' bit set.  Pages on the free list are connected via their
 * `p_next' and `p_prev' fields.  When a page is involved in some sort
 * of i/o, it is not free and these fields may be used to link associated
 * pages together.  At the moment, the free list is protected by a
 * single mutex `page_freelock'.  The list of free pages still associated
 * with a vnode is anchored by `page_cachelist' while other free pages
 * are anchored in architecture dependent ways (to handle page coloring etc.).
 *
 * Pages associated with a given vnode appear on a list anchored in the
 * vnode by the `v_pages' field.  They are linked together with
 * `p_vpnext' and `p_vpprev'.  The field `p_offset' contains a page's
 * offset within the vnode.  The pages on this list are not kept in
 * offset order.  These lists, in a manner similar to the hash lists,
 * are protected by an array of mutexes called `vph_hash'.  Before
 * searching or modifying this chain the appropriate mutex in the
 * vph_hash[] array must be held.
 *
 * Again, each of the lists that a page can appear on is protected by a
 * mutex.  Before reading or writing any of the fields comprising the
 * list, the appropriate lock must be held.  These list locks should only
 * be held for very short intervals.
 *
 * In addition to the list locks, each page structure contains a
 * shared/exclusive lock that protects various fields within it.
 * To modify one of these fields, the `p_selock' must be exclusively held.
 * To read a field with a degree of certainty, the lock must be at least
 * held shared.
 *
 * Removing a page structure from one of the lists requires holding
 * the appropriate list lock and the page's p_selock.  A page may be
 * prevented from changing identity, being freed, or otherwise modified
 * by acquiring p_selock shared.
 *
 * To avoid deadlocks, a strict locking protocol must be followed.  Basically
 * there are two cases:  In the first case, the page structure in question
 * is known ahead of time (e.g., when the page is to be added or removed
 * from a list).  In the second case, the page structure is not known and
 * must be found by searching one of the lists.
 *
 * When adding or removing a known page to one of the lists, first the
 * page must be exclusively locked (since at least one of its fields
 * will be modified), second the lock protecting the list must be acquired,
 * third the page inserted or deleted, and finally the list lock dropped.
 *
 * The more interesting case occures when the particular page structure
 * is not known ahead of time.  For example, when a call is made to
 * page_lookup(), it is not known if a page with the desired (vnode and
 * offset pair) identity exists.  So the appropriate mutex in ph_mutex is
 * acquired, the hash list searched, and if the desired page is found
 * an attempt is made to lock it.  The attempt to acquire p_selock must
 * not block while the hash list lock is held.  A deadlock could occure
 * if some other process was trying to remove the page from the list.
 * The removing process (following the above protocol) would have exclusively
 * locked the page, and be spinning waiting to acquire the lock protecting
 * the hash list.  Since the searching process holds the hash list lock
 * and is waiting to acquire the page lock, a deadlock occurs.
 *
 * The proper scheme to follow is: first, lock the appropriate list,
 * search the list, and if the desired page is found either use
 * page_trylock() (which will not block) or pass the address of the
 * list lock to page_lock().  If page_lock() can not acquire the page's
 * lock, it will drop the list lock before going to sleep.  page_lock()
 * returns a value to indicate if the list lock was dropped allowing the
 * calling program to react appropriately (i.e., retry the operation).
 *
 * If the list lock was dropped before the attempt at locking the page
 * was made, checks would have to be made to ensure that the page had
 * not changed identity before its lock was obtained.  This is because
 * the interval between dropping the list lock and acquiring the page
 * lock is indeterminate.
 *
 * In addition, when both a hash list lock (ph_mutex[]) and a vnode list
 * lock (vph_mutex[]) are needed, the hash list lock must be acquired first.
 * The routine page_hashin() is a good example of this sequence.
 * This sequence is ASSERTed by checking that the vph_mutex[] is not held
 * just before each acquisition of one of the mutexs in ph_mutex[].
 *
 * So, as a quick summary:
 *
 * 	pse_mutex[]'s protect the p_selock and p_cv fields.
 *
 * 	p_selock protects the p_free, p_age, p_vnode, p_offset and p_hash,
 *
 * 	ph_mutex[]'s protect the page_hash[] array and its chains.
 *
 * 	vph_mutex[]'s protect the v_pages field and the vp page chains.
 *
 *	First lock the page, then the hash chain, then the vnode chain.  When
 *	this is not possible `trylocks' must be used.  Sleeping while holding
 *	any of these mutexes (p_selock is not a mutex) is not allowed.
 *
 *
 *	field		reading		writing		    ordering
 *	======================================================================
 *	p_vnode		p_selock(E,S)	p_selock(E)
 *	p_offset
 *	p_free
 *	p_age
 *	=====================================================================
 *	p_hash		p_selock(E,S)	p_selock(E) &&	    p_selock, ph_mutex
 *					ph_mutex[]
 *	=====================================================================
 *	p_vpnext	p_selock(E,S)	p_selock(E) &&	    p_selock, vph_mutex
 *	p_vpprev			vph_mutex[]
 *	=====================================================================
 *	When the p_free bit is set:
 *
 *	p_next		p_selock(E,S)	p_selock(E) &&	    p_selock,
 *	p_prev				page_freelock	    page_freelock
 *
 *	When the p_free bit is not set:
 *
 *	p_next		p_selock(E,S)	p_selock(E) &&	    p_selock, p_iolock
 *	p_prev				p_iolock
 *	=====================================================================
 *	p_selock	pse_mutex[]	pse_mutex[]	    can`t acquire any
 *	p_cv						    other mutexes or
 *							    sleep while holding
 *							    this lock.
 *	=====================================================================
 *	p_lckcnt	p_selock(E,S)	p_selock(E)
 *					    OR
 *					p_selock(S) &&
 *					page_llocks[]
 *	p_cowcnt
 *	=====================================================================
 *	p_nrm		hat layer lock	hat layer lock
 *	p_mapping
 *	p_pagenum
 *	=====================================================================
 *
 *	where:
 *		E----> exclusive version of p_selock.
 *		S----> shared version of p_selock.
 *
 *
 *	Global data structures and variable:
 *
 *	field		reading		writing		    ordering
 *	=====================================================================
 *	page_hash[]	ph_mutex[]	ph_mutex[]	    can hold this lock
 *							    before acquiring
 *							    a vph_mutex or
 *							    pse_mutex.
 *	=====================================================================
 *	vp->v_pages	vph_mutex[]	vph_mutex[]	    can only acquire
 *							    a pse_mutex while
 *							    holding this lock.
 *	=====================================================================
 *	page_cachelist	page_freelock	page_freelock	    can't acquire any
 *	page_freelist	page_freelock	page_freelock
 *	=====================================================================
 *	freemem		freemem_lock	freemem_lock	    can't acquire any
 *	freemem_wait					    other mutexes while
 *	freemem_cv					    holding this mutex.
 *	=====================================================================
 *
 * Page relocation, PG_NORELOC and P_NORELOC.
 *
 * Pages may be relocated using the page_relocate() interface. Relocation
 * involves moving the contents and identity of a page to another, free page.
 * To relocate a page, the SE_EXCL lock must be obtained. The way to prevent
 * a page from being relocated is to hold the SE_SHARED lock (the SE_EXCL
 * lock must not be held indefinitely). If the page is going to be held
 * SE_SHARED indefinitely, then the PG_NORELOC hint should be passed
 * to page_create_va so that pages that are prevented from being relocated
 * can be managed differently by the platform specific layer.
 *
 * Pages locked in memory using page_pp_lock (p_lckcnt/p_cowcnt != 0)
 * are guaranteed to be held in memory, but can still be relocated
 * providing the SE_EXCL lock can be obtained.
 *
 * The P_NORELOC bit in the page_t.p_state field is provided for use by
 * the platform specific code in managing pages when the PG_NORELOC
 * hint is used.
 *
 * Memory delete and page locking.
 *
 * The set of all usable pages is managed using the global page list as
 * implemented by the memseg structure defined below. When memory is added
 * or deleted this list changes. Additions to this list guarantee that the
 * list is never corrupt.  In order to avoid the necessity of an additional
 * lock to protect against failed accesses to the memseg being deleted and,
 * more importantly, the page_ts, the memseg structure is never freed and the
 * page_t virtual address space is remapped to a page (or pages) of
 * zeros.  If a page_t is manipulated while it is p_selock'd, or if it is
 * locked indirectly via a hash or freelist lock, it is not possible for
 * memory delete to collect the page and so that part of the page list is
 * prevented from being deleted. If the page is referenced outside of one
 * of these locks, it is possible for the page_t being referenced to be
 * deleted.  Examples of this are page_t pointers returned by
 * page_numtopp_nolock, page_first and page_next.  Providing the page_t
 * is re-checked after taking the p_selock (for p_vnode != NULL), the
 * remapping to the zero pages will be detected.
 *
 *
 * Page size (p_szc field) and page locking.
 *
 * p_szc field of free pages is changed by free list manager under freelist
 * locks and is of no concern to the rest of VM subsystem.
 *
 * p_szc changes of allocated anonymous (swapfs) can only be done only after
 * exclusively locking all constituent pages and calling hat_pageunload() on
 * each of them. To prevent p_szc changes of non free anonymous (swapfs) large
 * pages it's enough to either lock SHARED any of constituent pages or prevent
 * hat_pageunload() by holding hat level lock that protects mapping lists (this
 * method is for hat code only)
 *
 * To increase (promote) p_szc of allocated non anonymous file system pages
 * one has to first lock exclusively all involved constituent pages and call
 * hat_pageunload() on each of them. To prevent p_szc promote it's enough to
 * either lock SHARED any of constituent pages that will be needed to make a
 * large page or prevent hat_pageunload() by holding hat level lock that
 * protects mapping lists (this method is for hat code only).
 *
 * To decrease (demote) p_szc of an allocated non anonymous file system large
 * page one can either use the same method as used for changeing p_szc of
 * anonymous large pages or if it's not possible to lock all constituent pages
 * exclusively a different method can be used. In the second method one only
 * has to exclusively lock one of constituent pages but then one has to
 * acquire further locks by calling page_szc_lock() and
 * hat_page_demote(). hat_page_demote() acquires hat level locks and then
 * demotes the page. This mechanism relies on the fact that any code that
 * needs to prevent p_szc of a file system large page from changeing either
 * locks all constituent large pages at least SHARED or locks some pages at
 * least SHARED and calls page_szc_lock() or uses hat level page locks.
 * Demotion using this method is implemented by page_demote_vp_pages().
 * Please see comments in front of page_demote_vp_pages(), hat_page_demote()
 * and page_szc_lock() for more details.
 *
 * Lock order: p_selock, page_szc_lock, ph_mutex/vph_mutex/freelist,
 * hat level locks.
 */

typedef struct page {
	u_offset_t	p_offset;	/* offset into vnode for this page */
	struct vnode	*p_vnode;	/* vnode that this page is named by */
	selock_t	p_selock;	/* shared/exclusive lock on the page */
#if defined(_LP64)
	uint_t		p_vpmref;	/* vpm ref - index of the vpmap_t */
#endif
	struct page	*p_hash;	/* hash by [vnode, offset] */
	struct page	*p_vpnext;	/* next page in vnode list */
	struct page	*p_vpprev;	/* prev page in vnode list */
	struct page	*p_next;	/* next page in free/intrans lists */
	struct page	*p_prev;	/* prev page in free/intrans lists */
	ushort_t	p_lckcnt;	/* number of locks on page data */
	ushort_t	p_cowcnt;	/* number of copy on write lock */
	kcondvar_t	p_cv;		/* page struct's condition var */
	kcondvar_t	p_io_cv;	/* for iolock */
	uchar_t		p_iolock_state;	/* replaces p_iolock */
	volatile uchar_t p_szc;		/* page size code */
	uchar_t		p_fsdata;	/* file system dependent byte */
	uchar_t		p_state;	/* p_free, p_noreloc */
	uchar_t		p_nrm;		/* non-cache, ref, mod readonly bits */
#if defined(__sparc)
	uchar_t		p_vcolor;	/* virtual color */
#else
	uchar_t		p_embed;	/* x86 - changes p_mapping & p_index */
#endif
	uchar_t		p_index;	/* MPSS mapping info. Not used on x86 */
	uchar_t		p_toxic;	/* page has an unrecoverable error */
	void		*p_mapping;	/* hat specific translation info */
	pfn_t		p_pagenum;	/* physical page number */

	uint_t		p_share;	/* number of translations */
#if defined(_LP64)
	uint_t		p_sharepad;	/* pad for growing p_share */
#endif
	uint_t		p_slckcnt;	/* number of softlocks */
#if defined(__sparc)
	uint_t		p_kpmref;	/* number of kpm mapping sharers */
	struct kpme	*p_kpmelist;	/* kpm specific mapping info */
#else
	/* index of entry in p_map when p_embed is set */
	uint_t		p_mlentry;
#endif
#if defined(_LP64)
	kmutex_t	p_ilock;	/* protects p_vpmref */
#else
	uint64_t	p_msresv_2;	/* page allocation debugging */
#endif
} page_t;


typedef	page_t	devpage_t;
#define	devpage	page

#define	PAGE_LOCK_MAXIMUM \
	((1 << (sizeof (((page_t *)0)->p_lckcnt) * NBBY)) - 1)

#define	PAGE_SLOCK_MAXIMUM UINT_MAX

/*
 * Page hash table is a power-of-two in size, externally chained
 * through the hash field.  PAGE_HASHAVELEN is the average length
 * desired for this chain, from which the size of the page_hash
 * table is derived at boot time and stored in the kernel variable
 * page_hashsz.  In the hash function it is given by PAGE_HASHSZ.
 *
 * PAGE_HASH_FUNC returns an index into the page_hash[] array.  This
 * index is also used to derive the mutex that protects the chain.
 *
 * In constructing the hash function, first we dispose of unimportant bits
 * (page offset from "off" and the low 3 bits of "vp" which are zero for
 * struct alignment). Then shift and sum the remaining bits a couple times
 * in order to get as many source bits from the two source values into the
 * resulting hashed value.  Note that this will perform quickly, since the
 * shifting/summing are fast register to register operations with no additional
 * memory references).
 *
 * PH_SHIFT_SIZE is the amount to use for the successive shifts in the hash
 * function below.  The actual value is LOG2(PH_TABLE_SIZE), so that as many
 * bits as possible will filter thru PAGE_HASH_FUNC() and PAGE_HASH_MUTEX().
 *
 * We use ? : instead of #if because <vm/page.h> is included everywhere;
 * NCPU maps to a global variable outside of the "unix" module.
 */
#if defined(_LP64)
#define	PH_SHIFT_SIZE	((NCPU < 4) ? 7		: (NCPU_LOG2 + 1))
#else	/* 32 bits */
#define	PH_SHIFT_SIZE	((NCPU < 4) ? 4		: 7)
#endif	/* _LP64 */

#define	PH_TABLE_SIZE	(1ul << PH_SHIFT_SIZE)

/*
 *
 * We take care to get as much randomness as possible from both the vp and
 * the offset.  Workloads can have few vnodes with many offsets, many vnodes
 * with few offsets or a moderate mix of both.  This hash should perform
 * equally well for each of these possibilities and for all types of memory
 * allocations.
 *
 * vnodes representing files are created over a long period of time and
 * have good variation in the upper vp bits, and the right shifts below
 * capture these bits.  However, swap vnodes are created quickly in a
 * narrow vp* range.  Refer to comments at swap_alloc: vnum has exactly
 * AN_VPSHIFT bits, so the kmem_alloc'd vnode addresses have approximately
 * AN_VPSHIFT bits of variation above their VNODE_ALIGN low order 0 bits.
 * Spread swap vnodes widely in the hash table by XOR'ing a term with the
 * vp bits of variation left shifted to the top of the range.
 */

#define	PAGE_HASHSZ	page_hashsz
#define	PAGE_HASHAVELEN		4
#define	PAGE_HASH_FUNC(vp, off) \
	(((((uintptr_t)(off) >> PAGESHIFT) ^ \
	    ((uintptr_t)(off) >> (PAGESHIFT + PH_SHIFT_SIZE))) ^ \
	    (((uintptr_t)(vp) >> 3) ^ \
	    ((uintptr_t)(vp) >> (3 + PH_SHIFT_SIZE)) ^ \
	    ((uintptr_t)(vp) >> (3 + 2 * PH_SHIFT_SIZE)) ^ \
	    ((uintptr_t)(vp) << \
	    (page_hashsz_shift - AN_VPSHIFT - VNODE_ALIGN_LOG2)))) & \
	    (PAGE_HASHSZ - 1))

#ifdef _KERNEL

/*
 * The page hash value is re-hashed to an index for the ph_mutex array.
 *
 * For 64 bit kernels, the mutex array is padded out to prevent false
 * sharing of cache sub-blocks (64 bytes) of adjacent mutexes.
 *
 * For 32 bit kernels, we don't want to waste kernel address space with
 * padding, so instead we rely on the hash function to introduce skew of
 * adjacent vnode/offset indexes (the left shift part of the hash function).
 * Since sizeof (kmutex_t) is 8, we shift an additional 3 to skew to a different
 * 64 byte sub-block.
 */
extern pad_mutex_t ph_mutex[];

#define	PAGE_HASH_MUTEX(x) \
	&(ph_mutex[((x) ^ ((x) >> PH_SHIFT_SIZE) + ((x) << 3)) & \
		(PH_TABLE_SIZE - 1)].pad_mutex)

/*
 * Flags used while creating pages.
 */
#define	PG_EXCL		0x0001
#define	PG_WAIT		0x0002		/* Blocking memory allocations */
#define	PG_PHYSCONTIG	0x0004		/* NOT SUPPORTED */
#define	PG_MATCH_COLOR	0x0008		/* SUPPORTED by free list routines */
#define	PG_NORELOC	0x0010		/* Non-relocatable alloc hint. */
					/* Page must be PP_ISNORELOC */
#define	PG_PANIC	0x0020		/* system will panic if alloc fails */
#define	PG_PUSHPAGE	0x0040		/* alloc may use reserve */
#define	PG_LOCAL	0x0080		/* alloc from given lgrp only */
#define	PG_NORMALPRI	0x0100		/* PG_WAIT like priority, but */
					/* non-blocking */
/*
 * When p_selock has the SE_EWANTED bit set, threads waiting for SE_EXCL
 * access are given priority over all other waiting threads.
 */
#define	SE_EWANTED	0x40000000
#define	PAGE_LOCKED(pp)		(((pp)->p_selock & ~SE_EWANTED) != 0)
#define	PAGE_SHARED(pp)		(((pp)->p_selock & ~SE_EWANTED) > 0)
#define	PAGE_EXCL(pp)		((pp)->p_selock < 0)
#define	PAGE_LOCKED_SE(pp, se)	\
	((se) == SE_EXCL ? PAGE_EXCL(pp) : PAGE_SHARED(pp))

extern	long page_hashsz;
extern	unsigned int page_hashsz_shift;
extern	page_t **page_hash;

extern	pad_mutex_t page_llocks[];	/* page logical lock mutex */
extern	kmutex_t freemem_lock;		/* freemem lock */

extern	pgcnt_t	total_pages;		/* total pages in the system */

/*
 * Variables controlling locking of physical memory.
 */
extern	pgcnt_t	pages_pp_maximum;	/* tuning: lock + claim <= max */
extern	void init_pages_pp_maximum(void);

struct lgrp;

/* page_list_{add,sub} flags */

/* which list */
#define	PG_FREE_LIST	0x0001
#define	PG_CACHE_LIST	0x0002

/* where on list */
#define	PG_LIST_TAIL	0x0010
#define	PG_LIST_HEAD	0x0020

/* called from */
#define	PG_LIST_ISINIT	0x1000

/*
 * Page frame operations.
 */
page_t	*page_lookup(struct vnode *, u_offset_t, se_t);
page_t	*page_lookup_create(struct vnode *, u_offset_t, se_t, page_t *,
	spgcnt_t *, int);
page_t	*page_lookup_nowait(struct vnode *, u_offset_t, se_t);
page_t	*page_find(struct vnode *, u_offset_t);
page_t	*page_exists(struct vnode *, u_offset_t);
int	page_exists_physcontig(vnode_t *, u_offset_t, uint_t, page_t *[]);
int	page_exists_forreal(struct vnode *, u_offset_t, uint_t *);
void	page_needfree(spgcnt_t);
page_t	*page_create(struct vnode *, u_offset_t, size_t, uint_t);
int	page_alloc_pages(struct vnode *, struct seg *, caddr_t, page_t **,
	page_t **, uint_t, int, int);
page_t  *page_create_va_large(vnode_t *vp, u_offset_t off, size_t bytes,
	uint_t flags, struct seg *seg, caddr_t vaddr, void *arg);
page_t	*page_create_va(struct vnode *, u_offset_t, size_t, uint_t,
	struct seg *, caddr_t);
int	page_create_wait(pgcnt_t npages, uint_t flags);
void    page_create_putback(spgcnt_t npages);
void	page_free(page_t *, int);
void	page_free_at_startup(page_t *);
void	page_free_pages(page_t *);
void	free_vp_pages(struct vnode *, u_offset_t, size_t);
int	page_reclaim(page_t *, kmutex_t *);
int	page_reclaim_pages(page_t *, kmutex_t *, uint_t);
void	page_destroy(page_t *, int);
void	page_destroy_pages(page_t *);
void	page_destroy_free(page_t *);
void	page_rename(page_t *, struct vnode *, u_offset_t);
int	page_hashin(page_t *, struct vnode *, u_offset_t, kmutex_t *);
void	page_hashout(page_t *, kmutex_t *);
int	page_num_hashin(pfn_t, struct vnode *, u_offset_t);
void	page_add(page_t **, page_t *);
void	page_add_common(page_t **, page_t *);
void	page_sub(page_t **, page_t *);
void	page_sub_common(page_t **, page_t *);
page_t	*page_get_freelist(struct vnode *, u_offset_t, struct seg *,
		caddr_t, size_t, uint_t, struct lgrp *);

page_t	*page_get_cachelist(struct vnode *, u_offset_t, struct seg *,
		caddr_t, uint_t, struct lgrp *);
#if defined(__i386) || defined(__amd64)
int	page_chk_freelist(uint_t);
#endif
void	page_list_add(page_t *, int);
void	page_boot_demote(page_t *);
void	page_promote_size(page_t *, uint_t);
void	page_list_add_pages(page_t *, int);
void	page_list_sub(page_t *, int);
void	page_list_sub_pages(page_t *, uint_t);
void	page_list_xfer(page_t *, int, int);
void	page_list_break(page_t **, page_t **, size_t);
void	page_list_concat(page_t **, page_t **);
void	page_vpadd(page_t **, page_t *);
void	page_vpsub(page_t **, page_t *);
int	page_lock(page_t *, se_t, kmutex_t *, reclaim_t);
int	page_lock_es(page_t *, se_t, kmutex_t *, reclaim_t, int);
void page_lock_clr_exclwanted(page_t *);
int	page_trylock(page_t *, se_t);
int	page_try_reclaim_lock(page_t *, se_t, int);
int	page_tryupgrade(page_t *);
void	page_downgrade(page_t *);
void	page_unlock(page_t *);
void	page_unlock_nocapture(page_t *);
void	page_lock_delete(page_t *);
int	page_deleted(page_t *);
int	page_pp_lock(page_t *, int, int);
void	page_pp_unlock(page_t *, int, int);
int	page_resv(pgcnt_t, uint_t);
void	page_unresv(pgcnt_t);
void	page_pp_useclaim(page_t *, page_t *, uint_t);
int	page_addclaim(page_t *);
int	page_subclaim(page_t *);
int	page_addclaim_pages(page_t **);
int	page_subclaim_pages(page_t **);
pfn_t	page_pptonum(page_t *);
page_t	*page_numtopp(pfn_t, se_t);
page_t	*page_numtopp_noreclaim(pfn_t, se_t);
page_t	*page_numtopp_nolock(pfn_t);
page_t	*page_numtopp_nowait(pfn_t, se_t);
page_t  *page_first();
page_t  *page_next(page_t *);
page_t  *page_list_next(page_t *);
page_t	*page_nextn(page_t *, ulong_t);
page_t	*page_next_scan_init(void **);
page_t	*page_next_scan_large(page_t *, ulong_t *, void **);
void    prefetch_page_r(void *);
int	ppcopy(page_t *, page_t *);
void	page_relocate_hash(page_t *, page_t *);
void	pagezero(page_t *, uint_t, uint_t);
void	pagescrub(page_t *, uint_t, uint_t);
void	page_io_lock(page_t *);
void	page_io_unlock(page_t *);
int	page_io_trylock(page_t *);
int	page_iolock_assert(page_t *);
void	page_iolock_init(page_t *);
void	page_io_wait(page_t *);
int	page_io_locked(page_t *);
pgcnt_t	page_busy(int);
void	page_lock_init(void);
ulong_t	page_share_cnt(page_t *);
int	page_isshared(page_t *);
int	page_isfree(page_t *);
int	page_isref(page_t *);
int	page_ismod(page_t *);
int	page_release(page_t *, int);
void	page_retire_init(void);
int	page_retire(uint64_t, uchar_t);
int	page_retire_check(uint64_t, uint64_t *);
int	page_unretire(uint64_t);
int	page_unretire_pp(page_t *, int);
void	page_tryretire(page_t *);
void	page_retire_mdboot();
uint64_t	page_retire_pend_count(void);
uint64_t	page_retire_pend_kas_count(void);
void	page_retire_incr_pend_count(void *);
void	page_retire_decr_pend_count(void *);
void	page_clrtoxic(page_t *, uchar_t);
void	page_settoxic(page_t *, uchar_t);

int	page_reclaim_mem(pgcnt_t, pgcnt_t, int);

void page_set_props(page_t *, uint_t);
void page_clr_all_props(page_t *);
int page_clear_lck_cow(page_t *, int);

kmutex_t	*page_vnode_mutex(struct vnode *);
kmutex_t	*page_se_mutex(struct page *);
kmutex_t	*page_szc_lock(struct page *);
int		page_szc_lock_assert(struct page *pp);

/*
 * Page relocation interfaces. page_relocate() is generic.
 * page_get_replacement_page() is provided by the PSM.
 * page_free_replacement_page() is generic.
 */
int group_page_trylock(page_t *, se_t);
void group_page_unlock(page_t *);
int page_relocate(page_t **, page_t **, int, int, spgcnt_t *, struct lgrp *);
int do_page_relocate(page_t **, page_t **, int, spgcnt_t *, struct lgrp *);
page_t *page_get_replacement_page(page_t *, struct lgrp *, uint_t);
void page_free_replacement_page(page_t *);
int page_relocate_cage(page_t **, page_t **);

int page_try_demote_pages(page_t *);
int page_try_demote_free_pages(page_t *);
void page_demote_free_pages(page_t *);

struct anon_map;

void page_mark_migrate(struct seg *, caddr_t, size_t, struct anon_map *,
    ulong_t, vnode_t *, u_offset_t, int);
void page_migrate(struct seg *, caddr_t, page_t **, pgcnt_t);

/*
 * Tell the PIM we are adding physical memory
 */
void add_physmem(page_t *, size_t, pfn_t);
void add_physmem_cb(page_t *, pfn_t);	/* callback for page_t part */

/*
 * hw_page_array[] is configured with hardware supported page sizes by
 * platform specific code.
 */
typedef struct {
	size_t	hp_size;
	uint_t	hp_shift;
	uint_t  hp_colors;
	pgcnt_t	hp_pgcnt;	/* base pagesize cnt */
} hw_pagesize_t;

extern hw_pagesize_t	hw_page_array[];
extern uint_t		page_coloring_shift;
extern uint_t		page_colors_mask;
extern int		cpu_page_colors;
extern uint_t		colorequiv;
extern uchar_t		colorequivszc[];

uint_t	page_num_pagesizes(void);
uint_t	page_num_user_pagesizes(int);
size_t	page_get_pagesize(uint_t);
size_t	page_get_user_pagesize(uint_t n);
pgcnt_t	page_get_pagecnt(uint_t);
uint_t	page_get_shift(uint_t);
int	page_szc(size_t);
int	page_szc_user_filtered(size_t);

/* page_get_replacement page flags */
#define	PGR_SAMESZC	0x1	/* only look for page size same as orig */
#define	PGR_NORELOC	0x2	/* allocate a P_NORELOC page */

/*
 * macros for "masked arithmetic"
 * The purpose is to step through all combinations of a set of bits while
 * keeping some other bits fixed. Fixed bits need not be contiguous. The
 * variable bits need not be contiguous either, or even right aligned. The
 * trick is to set all fixed bits to 1, then increment, then restore the
 * fixed bits. If incrementing causes a carry from a low bit position, the
 * carry propagates thru the fixed bits, because they are temporarily set to 1.
 *	v is the value
 *	i is the increment
 *	eq_mask defines the fixed bits
 *	mask limits the size of the result
 */
#define	ADD_MASKED(v, i, eq_mask, mask) \
	(((((v) | (eq_mask)) + (i)) & (mask) & ~(eq_mask)) | ((v) & (eq_mask)))

/*
 * convenience macro which increments by 1
 */
#define	INC_MASKED(v, eq_mask, mask) ADD_MASKED(v, 1, eq_mask, mask)

#endif	/* _KERNEL */

/*
 * Constants used for the p_iolock_state
 */
#define	PAGE_IO_INUSE	0x1
#define	PAGE_IO_WANTED	0x2

/*
 * Constants used for page_release status
 */
#define	PGREL_NOTREL    0x1
#define	PGREL_CLEAN	0x2
#define	PGREL_MOD	0x3

/*
 * The p_state field holds what used to be the p_age and p_free
 * bits.  These fields are protected by p_selock (see above).
 */
#define	P_FREE		0x80		/* Page on free list */
#define	P_NORELOC	0x40		/* Page is non-relocatable */
#define	P_MIGRATE	0x20		/* Migrate page on next touch */
#define	P_SWAP		0x10		/* belongs to vnode that is V_ISSWAP */
#define	P_BOOTPAGES	0x08		/* member of bootpages list */
#define	P_RAF		0x04		/* page retired at free */

#define	PP_ISFREE(pp)		((pp)->p_state & P_FREE)
#define	PP_ISAGED(pp)		(((pp)->p_state & P_FREE) && \
					((pp)->p_vnode == NULL))
#define	PP_ISNORELOC(pp)	((pp)->p_state & P_NORELOC)
#define	PP_ISKAS(pp)		(VN_ISKAS((pp)->p_vnode))
#define	PP_ISNORELOCKERNEL(pp)	(PP_ISNORELOC(pp) && PP_ISKAS(pp))
#define	PP_ISMIGRATE(pp)	((pp)->p_state & P_MIGRATE)
#define	PP_ISSWAP(pp)		((pp)->p_state & P_SWAP)
#define	PP_ISBOOTPAGES(pp)	((pp)->p_state & P_BOOTPAGES)
#define	PP_ISRAF(pp)		((pp)->p_state & P_RAF)

#define	PP_SETFREE(pp)		((pp)->p_state = ((pp)->p_state & ~P_MIGRATE) \
				| P_FREE)
#define	PP_SETAGED(pp)		ASSERT(PP_ISAGED(pp))
#define	PP_SETNORELOC(pp)	((pp)->p_state |= P_NORELOC)
#define	PP_SETMIGRATE(pp)	((pp)->p_state |= P_MIGRATE)
#define	PP_SETSWAP(pp)		((pp)->p_state |= P_SWAP)
#define	PP_SETBOOTPAGES(pp)	((pp)->p_state |= P_BOOTPAGES)
#define	PP_SETRAF(pp)		((pp)->p_state |= P_RAF)

#define	PP_CLRFREE(pp)		((pp)->p_state &= ~P_FREE)
#define	PP_CLRAGED(pp)		ASSERT(!PP_ISAGED(pp))
#define	PP_CLRNORELOC(pp)	((pp)->p_state &= ~P_NORELOC)
#define	PP_CLRMIGRATE(pp)	((pp)->p_state &= ~P_MIGRATE)
#define	PP_CLRSWAP(pp)		((pp)->p_state &= ~P_SWAP)
#define	PP_CLRBOOTPAGES(pp)	((pp)->p_state &= ~P_BOOTPAGES)
#define	PP_CLRRAF(pp)		((pp)->p_state &= ~P_RAF)

/*
 * Flags for page_t p_toxic, for tracking memory hardware errors.
 *
 * These flags are OR'ed into p_toxic with page_settoxic() to track which
 * error(s) have occurred on a given page. The flags are cleared with
 * page_clrtoxic(). Both page_settoxic() and page_cleartoxic use atomic
 * primitives to manipulate the p_toxic field so no other locking is needed.
 *
 * When an error occurs on a page, p_toxic is set to record the error. The
 * error could be a memory error or something else (i.e. a datapath). The Page
 * Retire mechanism does not try to determine the exact cause of the error;
 * Page Retire rightly leaves that sort of determination to FMA's Diagnostic
 * Engine (DE).
 *
 * Note that, while p_toxic bits can be set without holding any locks, they
 * should only be cleared while holding the page exclusively locked.
 * There is one exception to this, the PR_CAPTURE bit is protected by a mutex
 * within the page capture logic and thus to set or clear the bit, that mutex
 * needs to be held.  The page does not need to be locked but the page_clrtoxic
 * function must be used as we need an atomic operation.
 * Also note that there is what amounts to a hack to prevent recursion with
 * large pages such that if we are unlocking a page and the PR_CAPTURE bit is
 * set, we will only try to capture the page if the current threads T_CAPTURING
 * flag is not set.  If the flag is set, the unlock will not try to capture
 * the page even though the PR_CAPTURE bit is set.
 *
 * Pages with PR_UE or PR_FMA flags are retired unconditionally, while pages
 * with PR_MCE are retired if the system has not retired too many of them.
 *
 * A page must be exclusively locked to be retired. Pages can be retired if
 * they are mapped, modified, or both, as long as they are not marked PR_UE,
 * since pages with uncorrectable errors cannot be relocated in memory.
 * Once a page has been successfully retired it is zeroed, attached to the
 * retired_pages vnode and, finally, PR_RETIRED is set in p_toxic. The other
 * p_toxic bits are NOT cleared. Pages are not left locked after retiring them
 * to avoid special case code throughout the kernel; rather, page_*lock() will
 * fail to lock the page, unless SE_RETIRED is passed as an argument.
 *
 * While we have your attention, go take a look at the comments at the
 * beginning of page_retire.c too.
 */
#define	PR_OK		0x00	/* no problem */
#define	PR_MCE		0x01	/* page has seen two or more CEs */
#define	PR_UE		0x02	/* page has an unhandled UE */
#define	PR_UE_SCRUBBED	0x04	/* page has seen a UE but was cleaned */
#define	PR_FMA		0x08	/* A DE wants this page retired */
#define	PR_CAPTURE	0x10	/* page is hashed on page_capture_hash[] */
#define	PR_RESV		0x20	/* Reserved for future use */
#define	PR_MSG		0x40	/* message(s) already printed for this page */
#define	PR_RETIRED	0x80	/* This page has been retired */

#define	PR_REASONS	(PR_UE | PR_MCE | PR_FMA)
#define	PR_TOXIC	(PR_UE)
#define	PR_ERRMASK	(PR_UE | PR_UE_SCRUBBED | PR_MCE | PR_FMA)
#define	PR_TOXICFLAGS	(0xCF)

#define	PP_RETIRED(pp)	((pp)->p_toxic & PR_RETIRED)
#define	PP_TOXIC(pp)	((pp)->p_toxic & PR_TOXIC)
#define	PP_PR_REQ(pp)	(((pp)->p_toxic & PR_REASONS) && !PP_RETIRED(pp))
#define	PP_PR_NOSHARE(pp)						\
	((((pp)->p_toxic & (PR_RETIRED | PR_FMA | PR_UE)) == PR_FMA) &&	\
	!PP_ISKAS(pp))

/*
 * Flags for page_unretire_pp
 */
#define	PR_UNR_FREE	0x1
#define	PR_UNR_CLEAN	0x2
#define	PR_UNR_TEMP	0x4

/*
 * kpm large page description.
 * The virtual address range of segkpm is divided into chunks of
 * kpm_pgsz. Each chunk is controlled by a kpm_page_t. The ushort
 * is sufficient for 2^^15 * PAGESIZE, so e.g. the maximum kpm_pgsz
 * for 8K is 256M and 2G for 64K pages. It it kept as small as
 * possible to save physical memory space.
 *
 * There are 2 segkpm mapping windows within in the virtual address
 * space when we have to prevent VAC alias conflicts. The so called
 * Alias window (mappings are always by PAGESIZE) is controlled by
 * kp_refcnta. The regular window is controlled by kp_refcnt for the
 * normal operation, which is to use the largest available pagesize.
 * When VAC alias conflicts are present within a chunk in the regular
 * window the large page mapping is broken up into smaller PAGESIZE
 * mappings. kp_refcntc is used to control the pages that are invoked
 * in the conflict and kp_refcnts holds the active mappings done
 * with the small page size. In non vac conflict mode kp_refcntc is
 * also used as "go" indication (-1) for the trap level tsbmiss
 * handler.
 */
typedef struct kpm_page {
	short kp_refcnt;	/* pages mapped large */
	short kp_refcnta;	/* pages mapped in Alias window */
	short kp_refcntc;	/* TL-tsbmiss flag; #vac alias conflict pages */
	short kp_refcnts;	/* vac alias: pages mapped small */
} kpm_page_t;

/*
 * Note: khl_lock offset changes must be reflected in sfmmu_asm.s
 */
typedef struct kpm_hlk {
	kmutex_t khl_mutex;	/* kpm_page mutex */
	uint_t   khl_lock;	/* trap level tsbmiss handling */
} kpm_hlk_t;

/*
 * kpm small page description.
 * When kpm_pgsz is equal to PAGESIZE a smaller representation is used
 * to save memory space. Alias range mappings and regular segkpm
 * mappings are done in units of PAGESIZE and can share the mapping
 * information and the mappings are always distinguishable by their
 * virtual address. Other information needed for VAC conflict prevention
 * is already available on a per page basis.
 *
 * The state about how a kpm page is mapped and whether it is ready to go
 * is indicated by the following 1 byte kpm_spage structure. This byte is
 * split into two 4-bit parts - kp_mapped and kp_mapped_go.
 * 	- kp_mapped == 1	the page is mapped cacheable
 *	- kp_mapped == 2	the page is mapped non-cacheable
 *	- kp_mapped_go == 1	the mapping is ready to be dropped in
 *	- kp_mapped_go == 0	the mapping is not ready to be dropped in.
 * When kp_mapped_go == 0, we will have C handler resolve the VAC conflict.
 * Otherwise, the assembly tsb miss handler can simply drop in the mapping
 * when a tsb miss occurs.
 */
typedef union kpm_spage {
	struct {
#ifdef  _BIG_ENDIAN
		uchar_t mapped_go: 4;	/* go or nogo flag */
		uchar_t mapped: 4;	/* page mapped small */
#else
		uchar_t mapped: 4;	/* page mapped small */
		uchar_t mapped_go: 4;	/* go or nogo flag */
#endif
	} kpm_spage_un;
	uchar_t kp_mapped_flag;
} kpm_spage_t;

#define	kp_mapped	kpm_spage_un.mapped
#define	kp_mapped_go	kpm_spage_un.mapped_go

/*
 * Note: kshl_lock offset changes must be reflected in sfmmu_asm.s
 */
typedef struct kpm_shlk {
	uint_t   kshl_lock;	/* trap level tsbmiss handling */
} kpm_shlk_t;

/*
 * Each segment of physical memory is described by a memseg struct.
 * Within a segment, memory is considered contiguous. The members
 * can be categorized as follows:
 * . Platform independent:
 *         pages, epages, pages_base, pages_end, next, lnext.
 * . 64bit only but platform independent:
 *         kpm_pbase, kpm_nkpmpgs, kpm_pages, kpm_spages.
 * . Really platform or mmu specific:
 *         pagespa, epagespa, nextpa, kpm_pagespa.
 * . Mixed:
 *         msegflags.
 */
struct memseg {
	page_t *pages, *epages;		/* [from, to] in page array */
	pfn_t pages_base, pages_end;	/* [from, to] in page numbers */
	struct memseg *next;		/* next segment in list */
	struct memseg *lnext;		/* next segment in deleted list */
#if defined(__sparc)
	uint64_t pagespa, epagespa;	/* [from, to] page array physical */
	uint64_t nextpa;		/* physical next pointer */
	pfn_t	kpm_pbase;		/* start of kpm range */
	pgcnt_t kpm_nkpmpgs;		/* # of kpm_pgsz pages */
	union _mseg_un {
		kpm_page_t  *kpm_lpgs;	/* ptr to kpm_page array */
		kpm_spage_t *kpm_spgs;	/* ptr to kpm_spage array */
	} mseg_un;
	uint64_t kpm_pagespa;		/* physical ptr to kpm (s)pages array */
#endif /* __sparc */
	uint_t msegflags;		/* memseg flags */
};

/* memseg union aliases */
#define	kpm_pages	mseg_un.kpm_lpgs
#define	kpm_spages	mseg_un.kpm_spgs

/* msegflags */
#define	MEMSEG_DYNAMIC		0x1	/* DR: memory was added dynamically */
#define	MEMSEG_META_INCL	0x2	/* DR: memseg includes it's metadata */
#define	MEMSEG_META_ALLOC	0x4	/* DR: memseg allocated it's metadata */

/* memseg support macros */
#define	MSEG_NPAGES(SEG)	((SEG)->pages_end - (SEG)->pages_base)

/* memseg hash */
#define	MEM_HASH_SHIFT		0x9
#define	N_MEM_SLOTS		0x200		/* must be a power of 2 */
#define	MEMSEG_PFN_HASH(pfn)	(((pfn)/mhash_per_slot) & (N_MEM_SLOTS - 1))

/* memseg  externals */
extern struct memseg *memsegs;		/* list of memory segments */
extern ulong_t mhash_per_slot;
extern uint64_t memsegspa;		/* memsegs as physical address */

void build_pfn_hash();
extern struct memseg *page_numtomemseg_nolock(pfn_t pfnum);

/*
 * page capture related info:
 * The page capture routines allow us to asynchronously capture given pages
 * for the explicit use of the requestor.  New requestors can be added by
 * explicitly adding themselves to the PC_* flags below and incrementing
 * PC_NUM_CALLBACKS as necessary.
 *
 * Subsystems using page capture must register a callback before attempting
 * to capture a page.  A duration of -1 will indicate that we will never give
 * up while trying to capture a page and will only stop trying to capture the
 * given page once we have successfully captured it.  Thus the user needs to be
 * aware of the behavior of all callers who have a duration of -1.
 *
 * For now, only /dev/physmem and page retire use the page capture interface
 * and only a single request can be outstanding for a given page.  Thus, if
 * /dev/phsymem wants a page and page retire also wants the same page, only
 * the page retire request will be honored until the point in time that the
 * page is actually retired, at which point in time, subsequent requests by
 * /dev/physmem will succeed if the CAPTURE_GET_RETIRED flag was set.
 */

#define	PC_RETIRE		(0)
#define	PC_PHYSMEM		(1)
#define	PC_NUM_CALLBACKS	(2)
#define	PC_MASK			((1 << PC_NUM_CALLBACKS) - 1)

#define	CAPTURE_RETIRE		(1 << PC_RETIRE)
#define	CAPTURE_PHYSMEM		(1 << PC_PHYSMEM)

#define	CAPTURE_ASYNC		(0x0200)

#define	CAPTURE_GET_RETIRED	(0x1000)
#define	CAPTURE_GET_CAGE	(0x2000)

struct page_capture_callback {
	int cb_active;		/* 1 means active, 0 means inactive */
	clock_t duration;	/* the length in time that we'll attempt to */
				/* capture this page asynchronously. (in HZ) */
	krwlock_t cb_rwlock;
	int (*cb_func)(page_t *, void *, uint_t); /* callback function */
};

extern kcondvar_t pc_cv;

void page_capture_register_callback(uint_t index, clock_t duration,
    int (*cb_func)(page_t *, void *, uint_t));
void page_capture_unregister_callback(uint_t index);
int page_trycapture(page_t *pp, uint_t szc, uint_t flags, void *datap);
void page_unlock_capture(page_t *pp);
int page_capture_unretire_pp(page_t *);

extern int memsegs_trylock(int);
extern void memsegs_lock(int);
extern void memsegs_unlock(int);
extern int memsegs_lock_held(void);
extern void memlist_read_lock(void);
extern void memlist_read_unlock(void);
extern void memlist_write_lock(void);
extern void memlist_write_unlock(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _VM_PAGE_H */
