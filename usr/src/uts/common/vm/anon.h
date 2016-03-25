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
 * Copyright (c) 2015, Joyent, Inc. All rights reserved.
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

#ifndef	_VM_ANON_H
#define	_VM_ANON_H

#include <sys/cred.h>
#include <sys/zone.h>
#include <vm/seg.h>
#include <vm/vpage.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * VM - Anonymous pages.
 */

typedef	unsigned long anoff_t;		/* anon offsets */

/*
 *	Each anonymous page, either in memory or in swap, has an anon structure.
 * The structure (slot) provides a level of indirection between anonymous pages
 * and their backing store.
 *
 *	(an_vp, an_off) names the vnode of the anonymous page for this slot.
 *
 * 	(an_pvp, an_poff) names the location of the physical backing store
 * 	for the page this slot represents. If the name is null there is no
 * 	associated physical store. The physical backing store location can
 *	change while the slot is in use.
 *
 *	an_hash is a hash list of anon slots. The list is hashed by
 * 	(an_vp, an_off) of the associated anonymous page and provides a
 *	method of going from the name of an anonymous page to its
 * 	associated anon slot.
 *
 *	an_refcnt holds a reference count which is the number of separate
 * 	copies that will need to be created in case of copy-on-write.
 *	A refcnt > 0 protects the existence of the slot. The refcnt is
 * 	initialized to 1 when the anon slot is created in anon_alloc().
 *	If a client obtains an anon slot and allows multiple threads to
 * 	share it, then it is the client's responsibility to insure that
 *	it does not allow one thread to try to reference the slot at the
 *	same time as another is trying to decrement the last count and
 *	destroy the anon slot. E.g., the seg_vn segment type protects
 *	against this with higher level locks.
 */

struct anon {
	struct vnode *an_vp;	/* vnode of anon page */
	struct vnode *an_pvp;	/* vnode of physical backing store */
	anoff_t an_off;		/* offset of anon page */
	anoff_t an_poff;	/* offset in vnode */
	struct anon *an_hash;	/* hash table of anon slots */
	int an_refcnt;		/* # of people sharing slot */
};

#define	AN_CACHE_ALIGN_LOG2	4	/* log2(AN_CACHE_ALIGN) */
#define	AN_CACHE_ALIGN	(1U << AN_CACHE_ALIGN_LOG2) /* anon address aligned */
						/* 16 bytes */


#ifdef _KERNEL
/*
 * The swapinfo_lock protects:
 *		swapinfo list
 *		individual swapinfo structures
 *
 * The anoninfo_lock protects:
 *		anoninfo counters
 *
 * The anonhash_lock protects:
 *		anon hash lists
 *		anon slot fields
 *
 * Fields in the anon slot which are read-only for the life of the slot
 * (an_vp, an_off) do not require the anonhash_lock be held to access them.
 * If you access a field without the anonhash_lock held you must be holding
 * the slot with an_refcnt to make sure it isn't destroyed.
 * To write (an_pvp, an_poff) in a given slot you must also hold the
 * p_iolock of the anonymous page for slot.
 */
extern kmutex_t anoninfo_lock;
extern kmutex_t swapinfo_lock;
extern pad_mutex_t *anonhash_lock;
extern pad_mutex_t anon_array_lock[];
extern kcondvar_t anon_array_cv[];

/*
 * Global hash table to provide a function from (vp, off) -> ap
 */
extern size_t anon_hash_size;
extern unsigned int anon_hash_shift;
extern struct anon **anon_hash;
#define	ANON_HASH_SIZE	anon_hash_size
#define	ANON_HASHAVELEN	4
/*
 * Try to use as many bits of randomness from both vp and off as we can.
 * This should help spreading evenly for a variety of workloads.  See comments
 * for PAGE_HASH_FUNC for more explanation.
 */
#define	ANON_HASH(vp, off)	\
	(((((uintptr_t)(off) >> PAGESHIFT) ^ \
		((uintptr_t)(off) >> (PAGESHIFT + anon_hash_shift))) ^ \
		(((uintptr_t)(vp) >> 3) ^ \
		((uintptr_t)(vp) >> (3 + anon_hash_shift)) ^ \
		((uintptr_t)(vp) >> (3 + 2 * anon_hash_shift)) ^ \
		((uintptr_t)(vp) << \
		    (anon_hash_shift - AN_VPSHIFT - VNODE_ALIGN_LOG2)))) & \
		(anon_hash_size - 1))

#define	AH_LOCK_SIZE	(2 << NCPU_LOG2)

#define	AH_MUTEX(vp, off)				\
	(&anonhash_lock[(ANON_HASH((vp), (off)) &	\
	    (AH_LOCK_SIZE - 1))].pad_mutex)

#endif	/* _KERNEL */

/*
 * Declaration for the Global counters to accurately
 * track the kernel foot print in memory.
 */
extern  pgcnt_t pages_locked;
extern  pgcnt_t pages_claimed;
extern  pgcnt_t pages_useclaim;
extern  pgcnt_t obp_pages;

/*
 * Anonymous backing store accounting structure for swapctl.
 *
 * ani_max = maximum amount of swap space
 *	(including potentially available physical memory)
 * ani_free = amount of unallocated anonymous memory
 *	(some of which might be reserved and including
 *	potentially available physical memory)
 * ani_resv = amount of claimed (reserved) anonymous memory
 *
 * The swap data can be aquired more efficiently through the
 * kstats interface.
 * Total slots currently available for reservation =
 *	MAX(ani_max - ani_resv, 0) + (availrmem - swapfs_minfree)
 */
struct anoninfo {
	pgcnt_t	ani_max;
	pgcnt_t	ani_free;
	pgcnt_t	ani_resv;
};

#ifdef _SYSCALL32
struct anoninfo32 {
	size32_t ani_max;
	size32_t ani_free;
	size32_t ani_resv;
};
#endif /* _SYSCALL32 */

/*
 * Define the NCPU pool of the ani_free counters. Update the counter
 * of the cpu on which the thread is running and in every clock intr
 * sync anoninfo.ani_free with the current total off all the NCPU entries.
 */

typedef	struct	ani_free {
	pgcnt_t		ani_count;
	uchar_t		pad[64 - sizeof (pgcnt_t)];
			/* XXX 64 = cacheline size */
} ani_free_t;

#define	ANI_MAX_POOL	(NCPU_P2)
extern	ani_free_t	*ani_free_pool;

/*
 * Since each CPU has its own bucket in ani_free_pool, there should be no
 * contention here.
 */
#define	ANI_ADD(inc)	{ \
	pgcnt_t	*ani_countp; \
	int	index; \
	index = (CPU->cpu_seqid & (ANI_MAX_POOL - 1)); \
	ani_countp = &ani_free_pool[index].ani_count; \
	atomic_add_long(ani_countp, inc); \
}

extern void	set_anoninfo(void);

/*
 * Anon array pointers are allocated in chunks. Each chunk
 * has PAGESIZE/sizeof(u_long *) of anon pointers.
 * There are two levels of arrays for anon array pointers larger
 * than a chunk. The first level points to anon array chunks.
 * The second level consists of chunks of anon pointers.
 *
 * If anon array is smaller than a chunk then the whole anon array
 * is created (memory is allocated for whole anon array).
 * If anon array is larger than a chunk only first level array is
 * allocated. Then other arrays (chunks) are allocated only when
 * they are initialized with anon pointers.
 */
struct anon_hdr {
	kmutex_t serial_lock;	/* serialize array chunk allocation */
	pgcnt_t	size;		/* number of pointers to (anon) pages */
	void	**array_chunk;	/* pointers to anon pointers or chunks of */
				/* anon pointers */
	int	flags;		/* ANON_ALLOC_FORCE force preallocation of */
				/* whole anon array	*/
};

#ifdef	_LP64
#define	ANON_PTRSHIFT	3
#define	ANON_PTRMASK	~7
#else
#define	ANON_PTRSHIFT	2
#define	ANON_PTRMASK	~3
#endif

#define	ANON_CHUNK_SIZE		(PAGESIZE >> ANON_PTRSHIFT)
#define	ANON_CHUNK_SHIFT	(PAGESHIFT - ANON_PTRSHIFT)
#define	ANON_CHUNK_OFF		(ANON_CHUNK_SIZE - 1)

/*
 * Anon flags.
 */
#define	ANON_SLEEP		0x0	/* ok to block */
#define	ANON_NOSLEEP		0x1	/* non-blocking call */
#define	ANON_ALLOC_FORCE	0x2	/* force single level anon array */
#define	ANON_GROWDOWN		0x4	/* anon array should grow downward */

struct kshmid;

/*
 * The anon_map structure is used by various clients of the anon layer to
 * manage anonymous memory.   When anonymous memory is shared,
 * then the different clients sharing it will point to the
 * same anon_map structure.  Also, if a segment is unmapped
 * in the middle where an anon_map structure exists, the
 * newly created segment will also share the anon_map structure,
 * although the two segments will use different ranges of the
 * anon array.  When mappings are private (or shared with
 * a reference count of 1), an unmap operation will free up
 * a range of anon slots in the array given by the anon_map
 * structure.  Because of fragmentation due to this unmapping,
 * we have to store the size of the anon array in the anon_map
 * structure so that we can free everything when the referernce
 * count goes to zero.
 *
 * A new rangelock scheme is introduced to make the anon layer scale.
 * A reader/writer lock per anon_amp and an array of system-wide hash
 * locks, anon_array_lock[] are introduced to replace serial_lock and
 * anonmap lock.  The writer lock is held when we want to singlethreaD
 * the reference to the anon array pointers or when references to
 * anon_map's members, whereas reader lock and anon_array_lock are
 * held to allows multiple threads to reference different part of
 * anon array.  A global set of condition variables, anon_array_cv,
 * are used with anon_array_lock[] to make the hold time of the locks
 * short.
 *
 * szc is used to calculate the index of hash locks and cv's.  We
 * could've just used seg->s_szc if not for the possible sharing of
 * anon_amp between SYSV shared memory and ISM, so now we introduce
 * szc in the anon_map structure.  For MAP_SHARED, the amp->szc is either
 * 0 (base page size) or page_num_pagesizes() - 1, while MAP_PRIVATE
 * the amp->szc could be anything in [0, page_num_pagesizes() - 1].
 */
typedef struct anon_map {
	krwlock_t a_rwlock;	/* protect anon_map and anon array */
	size_t	size;		/* size in bytes mapped by the anon array */
	struct	anon_hdr *ahp; 	/* anon array header pointer, containing */
				/* anon pointer array(s) */
	size_t	swresv;		/* swap space reserved for this anon_map */
	ulong_t	refcnt;		/* reference count on this structure */
	ushort_t a_szc;		/* max szc among shared processes */
	void	*locality;	/* lgroup locality info */
	struct kshmid *a_sp;	/* kshmid if amp backs sysV, or NULL */
	int	a_purgewait;	/* somebody waits for slocks to go away */
	kcondvar_t a_purgecv;	/* cv for waiting for slocks to go away */
	kmutex_t a_purgemtx;	/* mutex for anonmap_purge() */
	spgcnt_t a_softlockcnt; /* number of pages locked in pcache */
	kmutex_t a_pmtx;	/* protects amp's pcache list */
	pcache_link_t a_phead;	/* head of amp's pcache list */
} amp_t;

#ifdef _KERNEL

#define	ANON_BUSY		0x1
#define	ANON_ISBUSY(slot)	(*(slot) & ANON_BUSY)
#define	ANON_SETBUSY(slot)	(*(slot) |= ANON_BUSY)
#define	ANON_CLRBUSY(slot)	(*(slot) &= ~ANON_BUSY)

#define	ANON_MAP_SHIFT		6	/* log2(sizeof (struct anon_map)) */
#define	ANON_ARRAY_SHIFT	7	/* log2(ANON_LOCKSIZE) */
#define	ANON_LOCKSIZE		128

#define	ANON_LOCK_ENTER(lock, type)	rw_enter((lock), (type))
#define	ANON_LOCK_EXIT(lock)		rw_exit((lock))
#define	ANON_LOCK_HELD(lock)		RW_LOCK_HELD((lock))
#define	ANON_READ_HELD(lock)		RW_READ_HELD((lock))
#define	ANON_WRITE_HELD(lock)		RW_WRITE_HELD((lock))

#define	ANON_ARRAY_HASH(amp, idx)\
	((((idx) + ((idx) >> ANON_ARRAY_SHIFT) +\
	((idx) >> (ANON_ARRAY_SHIFT << 1)) +\
	((idx) >> (ANON_ARRAY_SHIFT + (ANON_ARRAY_SHIFT << 1)))) ^\
	((uintptr_t)(amp) >> ANON_MAP_SHIFT)) & (ANON_LOCKSIZE - 1))

typedef struct anon_sync_obj {
	kmutex_t	*sync_mutex;
	kcondvar_t	*sync_cv;
	ulong_t		*sync_data;
} anon_sync_obj_t;

/*
 * Anonymous backing store accounting structure for kernel.
 * ani_max = total reservable slots on physical (disk-backed) swap
 * ani_phys_resv = total phys slots reserved for use by clients
 * ani_mem_resv = total mem slots reserved for use by clients
 * ani_free = # unallocated physical slots + # of reserved unallocated
 * memory slots
 */

/*
 * Initial total swap slots available for reservation
 */
#define	TOTAL_AVAILABLE_SWAP \
	(k_anoninfo.ani_max + MAX((spgcnt_t)(availrmem - swapfs_minfree), 0))

/*
 * Swap slots currently available for reservation
 */
#define	CURRENT_TOTAL_AVAILABLE_SWAP				\
	((k_anoninfo.ani_max - k_anoninfo.ani_phys_resv) +	\
	    MAX((spgcnt_t)(availrmem - swapfs_minfree), 0))

struct k_anoninfo {
	pgcnt_t	ani_max;	/* total reservable slots on phys */
					/* (disk) swap */
	pgcnt_t	ani_free;	/* # of unallocated phys and mem slots */
	pgcnt_t	ani_phys_resv;	/* # of reserved phys (disk) slots */
	pgcnt_t	ani_mem_resv;	/* # of reserved mem slots */
	pgcnt_t	ani_locked_swap; /* # of swap slots locked in reserved */
				/* mem swap */
};

extern	struct k_anoninfo k_anoninfo;

extern void	anon_init(void);
extern struct	anon *anon_alloc(struct vnode *, anoff_t);
extern void	anon_dup(struct anon_hdr *, ulong_t,
		    struct anon_hdr *, ulong_t, size_t);
extern void	anon_dup_fill_holes(struct anon_hdr *, ulong_t,
		    struct anon_hdr *, ulong_t, size_t, uint_t, int);
extern int	anon_fill_cow_holes(struct seg *, caddr_t, struct anon_hdr *,
		    ulong_t, struct vnode *, u_offset_t, size_t, uint_t,
		    uint_t, struct vpage [], struct cred *);
extern void	anon_free(struct anon_hdr *, ulong_t, size_t);
extern void	anon_free_pages(struct anon_hdr *, ulong_t, size_t, uint_t);
extern int	anon_disclaim(struct anon_map *,
		    ulong_t, size_t, uint_t, pgcnt_t *);
extern int	anon_getpage(struct anon **, uint_t *, struct page **,
		    size_t, struct seg *, caddr_t, enum seg_rw, struct cred *);
extern int	swap_getconpage(struct vnode *, u_offset_t, size_t,
		    uint_t *, page_t *[], size_t, page_t *, uint_t *,
		    spgcnt_t *, struct seg *, caddr_t,
		    enum seg_rw, struct cred *);
extern int	anon_map_getpages(struct anon_map *, ulong_t,
		    uint_t, struct seg *, caddr_t, uint_t,
		    uint_t *, page_t *[], uint_t *,
		    struct vpage [], enum seg_rw, int, int, int, struct cred *);
extern int	anon_map_privatepages(struct anon_map *, ulong_t,
		    uint_t, struct seg *, caddr_t, uint_t,
		    page_t *[], struct vpage [], int, int, struct cred *);
extern struct	page *anon_private(struct anon **, struct seg *,
		    caddr_t, uint_t, struct page *,
		    int, struct cred *);
extern struct	page *anon_zero(struct seg *, caddr_t,
		    struct anon **, struct cred *);
extern int	anon_map_createpages(struct anon_map *, ulong_t,
		    size_t, struct page **,
		    struct seg *, caddr_t,
		    enum seg_rw, struct cred *);
extern int	anon_map_demotepages(struct anon_map *, ulong_t,
		    struct seg *, caddr_t, uint_t,
		    struct vpage [], struct cred *);
extern void	anon_shmap_free_pages(struct anon_map *, ulong_t, size_t);
extern int	anon_resvmem(size_t, boolean_t, zone_t *, int);
extern void	anon_unresvmem(size_t, zone_t *);
extern struct	anon_map *anonmap_alloc(size_t, size_t, int);
extern void	anonmap_free(struct anon_map *);
extern void	anonmap_purge(struct anon_map *);
extern void	anon_swap_free(struct anon *, struct page *);
extern void	anon_decref(struct anon *);
extern int	non_anon(struct anon_hdr *, ulong_t, u_offset_t *, size_t *);
extern pgcnt_t	anon_pages(struct anon_hdr *, ulong_t, pgcnt_t);
extern int	anon_swap_adjust(pgcnt_t);
extern void	anon_swap_restore(pgcnt_t);
extern struct	anon_hdr *anon_create(pgcnt_t, int);
extern void	anon_release(struct anon_hdr *, pgcnt_t);
extern struct	anon *anon_get_ptr(struct anon_hdr *, ulong_t);
extern ulong_t	*anon_get_slot(struct anon_hdr *, ulong_t);
extern struct	anon *anon_get_next_ptr(struct anon_hdr *, ulong_t *);
extern int	anon_set_ptr(struct anon_hdr *, ulong_t, struct anon *, int);
extern int 	anon_copy_ptr(struct anon_hdr *, ulong_t,
		    struct anon_hdr *, ulong_t, pgcnt_t, int);
extern pgcnt_t	anon_grow(struct anon_hdr *, ulong_t *, pgcnt_t, pgcnt_t, int);
extern void	anon_array_enter(struct anon_map *, ulong_t,
			anon_sync_obj_t *);
extern int	anon_array_try_enter(struct anon_map *, ulong_t,
			anon_sync_obj_t *);
extern void	anon_array_exit(anon_sync_obj_t *);

/*
 * anon_resv checks to see if there is enough swap space to fulfill a
 * request and if so, reserves the appropriate anonymous memory resources.
 * anon_checkspace just checks to see if there is space to fulfill the request,
 * without taking any resources.  Both return 1 if successful and 0 if not.
 *
 * Macros are provided as anon reservation is usually charged to the zone of
 * the current process.  In some cases (such as anon reserved by tmpfs), a
 * zone pointer is needed to charge the appropriate zone.
 */
#define	anon_unresv(size)		anon_unresvmem(size, curproc->p_zone)
#define	anon_unresv_zone(size, zone)	anon_unresvmem(size, zone)
#define	anon_resv(size)			\
	anon_resvmem((size), 1, curproc->p_zone, 1)
#define	anon_resv_zone(size, zone)	anon_resvmem((size), 1, zone, 1)
#define	anon_checkspace(size, zone)	anon_resvmem((size), 0, zone, 0)
#define	anon_try_resv_zone(size, zone)	anon_resvmem((size), 1, zone, 0)

/*
 * Flags to anon_private
 */
#define	STEAL_PAGE	0x1	/* page can be stolen */
#define	LOCK_PAGE	0x2	/* page must be ``logically'' locked */

/*
 * SEGKP ANON pages that are locked are assumed to be LWP stack pages
 * and thus count towards the user pages locked count.
 * This value is protected by the same lock as availrmem.
 */
extern pgcnt_t anon_segkp_pages_locked;

extern int anon_debug;

#ifdef ANON_DEBUG

#define	A_ANON	0x01
#define	A_RESV	0x02
#define	A_MRESV	0x04

/* vararg-like debugging macro. */
#define	ANON_PRINT(f, printf_args) \
		if (anon_debug & f) \
			printf printf_args

#else	/* ANON_DEBUG */

#define	ANON_PRINT(f, printf_args)

#endif	/* ANON_DEBUG */

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _VM_ANON_H */
