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
 * Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * VM - Hardware Address Translation management for Spitfire MMU.
 *
 * This file implements the machine specific hardware translation
 * needed by the VM system.  The machine independent interface is
 * described in <vm/hat.h> while the machine dependent interface
 * and data structures are described in <vm/hat_sfmmu.h>.
 *
 * The hat layer manages the address translation hardware as a cache
 * driven by calls from the higher levels in the VM system.
 */

#include <sys/types.h>
#include <sys/kstat.h>
#include <vm/hat.h>
#include <vm/hat_sfmmu.h>
#include <vm/page.h>
#include <sys/pte.h>
#include <sys/systm.h>
#include <sys/mman.h>
#include <sys/sysmacros.h>
#include <sys/machparam.h>
#include <sys/vtrace.h>
#include <sys/kmem.h>
#include <sys/mmu.h>
#include <sys/cmn_err.h>
#include <sys/cpu.h>
#include <sys/cpuvar.h>
#include <sys/debug.h>
#include <sys/lgrp.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/vmsystm.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_kp.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kpm.h>
#include <vm/rm.h>
#include <sys/t_lock.h>
#include <sys/obpdefs.h>
#include <sys/vm_machparam.h>
#include <sys/var.h>
#include <sys/trap.h>
#include <sys/machtrap.h>
#include <sys/scb.h>
#include <sys/bitmap.h>
#include <sys/machlock.h>
#include <sys/membar.h>
#include <sys/atomic.h>
#include <sys/cpu_module.h>
#include <sys/prom_debug.h>
#include <sys/ksynch.h>
#include <sys/mem_config.h>
#include <sys/mem_cage.h>
#include <vm/vm_dep.h>
#include <sys/fpu/fpusystm.h>
#include <vm/mach_kpm.h>
#include <sys/callb.h>

#ifdef	DEBUG
#define	SFMMU_VALIDATE_HMERID(hat, rid, saddr, len)			\
	if (SFMMU_IS_SHMERID_VALID(rid)) {				\
		caddr_t _eaddr = (saddr) + (len);			\
		sf_srd_t *_srdp;					\
		sf_region_t *_rgnp;					\
		ASSERT((rid) < SFMMU_MAX_HME_REGIONS);			\
		ASSERT(SF_RGNMAP_TEST(hat->sfmmu_hmeregion_map, rid));	\
		ASSERT((hat) != ksfmmup);				\
		_srdp = (hat)->sfmmu_srdp;				\
		ASSERT(_srdp != NULL);					\
		ASSERT(_srdp->srd_refcnt != 0);				\
		_rgnp = _srdp->srd_hmergnp[(rid)];			\
		ASSERT(_rgnp != NULL && _rgnp->rgn_id == rid);		\
		ASSERT(_rgnp->rgn_refcnt != 0);				\
		ASSERT(!(_rgnp->rgn_flags & SFMMU_REGION_FREE));	\
		ASSERT((_rgnp->rgn_flags & SFMMU_REGION_TYPE_MASK) ==	\
		    SFMMU_REGION_HME);					\
		ASSERT((saddr) >= _rgnp->rgn_saddr);			\
		ASSERT((saddr) < _rgnp->rgn_saddr + _rgnp->rgn_size);	\
		ASSERT(_eaddr > _rgnp->rgn_saddr);			\
		ASSERT(_eaddr <= _rgnp->rgn_saddr + _rgnp->rgn_size);	\
	}

#define	SFMMU_VALIDATE_SHAREDHBLK(hmeblkp, srdp, rgnp, rid) 	 	 \
{						 			 \
		caddr_t _hsva;						 \
		caddr_t _heva;						 \
		caddr_t _rsva;					 	 \
		caddr_t _reva;					 	 \
		int	_ttesz = get_hblk_ttesz(hmeblkp);		 \
		int	_flagtte;					 \
		ASSERT((srdp)->srd_refcnt != 0);			 \
		ASSERT((rid) < SFMMU_MAX_HME_REGIONS);			 \
		ASSERT((rgnp)->rgn_id == rid);				 \
		ASSERT(!((rgnp)->rgn_flags & SFMMU_REGION_FREE));	 \
		ASSERT(((rgnp)->rgn_flags & SFMMU_REGION_TYPE_MASK) ==	 \
		    SFMMU_REGION_HME);					 \
		ASSERT(_ttesz <= (rgnp)->rgn_pgszc);			 \
		_hsva = (caddr_t)get_hblk_base(hmeblkp);		 \
		_heva = get_hblk_endaddr(hmeblkp);			 \
		_rsva = (caddr_t)P2ALIGN(				 \
		    (uintptr_t)(rgnp)->rgn_saddr, HBLK_MIN_BYTES);	 \
		_reva = (caddr_t)P2ROUNDUP(				 \
		    (uintptr_t)((rgnp)->rgn_saddr + (rgnp)->rgn_size),	 \
		    HBLK_MIN_BYTES);					 \
		ASSERT(_hsva >= _rsva);				 	 \
		ASSERT(_hsva < _reva);				 	 \
		ASSERT(_heva > _rsva);				 	 \
		ASSERT(_heva <= _reva);				 	 \
		_flagtte = (_ttesz < HBLK_MIN_TTESZ) ? HBLK_MIN_TTESZ :  \
			_ttesz;						 \
		ASSERT(rgnp->rgn_hmeflags & (0x1 << _flagtte));		 \
}

#else /* DEBUG */
#define	SFMMU_VALIDATE_HMERID(hat, rid, addr, len)
#define	SFMMU_VALIDATE_SHAREDHBLK(hmeblkp, srdp, rgnp, rid)
#endif /* DEBUG */

#if defined(SF_ERRATA_57)
extern caddr_t errata57_limit;
#endif

#define	HME8BLK_SZ_RND		((roundup(HME8BLK_SZ, sizeof (int64_t))) /  \
				(sizeof (int64_t)))
#define	HBLK_RESERVE		((struct hme_blk *)hblk_reserve)

#define	HBLK_RESERVE_CNT	128
#define	HBLK_RESERVE_MIN	20

static struct hme_blk		*freehblkp;
static kmutex_t			freehblkp_lock;
static int			freehblkcnt;

static int64_t			hblk_reserve[HME8BLK_SZ_RND];
static kmutex_t			hblk_reserve_lock;
static kthread_t		*hblk_reserve_thread;

static nucleus_hblk8_info_t	nucleus_hblk8;
static nucleus_hblk1_info_t	nucleus_hblk1;

/*
 * Data to manage per-cpu hmeblk pending queues, hmeblks are queued here
 * after the initial phase of removing an hmeblk from the hash chain, see
 * the detailed comment in sfmmu_hblk_hash_rm() for further details.
 */
static cpu_hme_pend_t		*cpu_hme_pend;
static uint_t			cpu_hme_pend_thresh;
/*
 * SFMMU specific hat functions
 */
void	hat_pagecachectl(struct page *, int);

/* flags for hat_pagecachectl */
#define	HAT_CACHE	0x1
#define	HAT_UNCACHE	0x2
#define	HAT_TMPNC	0x4

/*
 * Flag to allow the creation of non-cacheable translations
 * to system memory. It is off by default. At the moment this
 * flag is used by the ecache error injector. The error injector
 * will turn it on when creating such a translation then shut it
 * off when it's finished.
 */

int	sfmmu_allow_nc_trans = 0;

/*
 * Flag to disable large page support.
 * 	value of 1 => disable all large pages.
 *	bits 1, 2, and 3 are to disable 64K, 512K and 4M pages respectively.
 *
 * For example, use the value 0x4 to disable 512K pages.
 *
 */
#define	LARGE_PAGES_OFF		0x1

/*
 * The disable_large_pages and disable_ism_large_pages variables control
 * hat_memload_array and the page sizes to be used by ISM and the kernel.
 *
 * The disable_auto_data_large_pages and disable_auto_text_large_pages variables
 * are only used to control which OOB pages to use at upper VM segment creation
 * time, and are set in hat_init_pagesizes and used in the map_pgsz* routines.
 * Their values may come from platform or CPU specific code to disable page
 * sizes that should not be used.
 *
 * WARNING: 512K pages are currently not supported for ISM/DISM.
 */
uint_t	disable_large_pages = 0;
uint_t	disable_ism_large_pages = (1 << TTE512K);
uint_t	disable_auto_data_large_pages = 0;
uint_t	disable_auto_text_large_pages = 0;

/*
 * Private sfmmu data structures for hat management
 */
static struct kmem_cache *sfmmuid_cache;
static struct kmem_cache *mmuctxdom_cache;

/*
 * Private sfmmu data structures for tsb management
 */
static struct kmem_cache *sfmmu_tsbinfo_cache;
static struct kmem_cache *sfmmu_tsb8k_cache;
static struct kmem_cache *sfmmu_tsb_cache[NLGRPS_MAX];
static vmem_t *kmem_bigtsb_arena;
static vmem_t *kmem_tsb_arena;

/*
 * sfmmu static variables for hmeblk resource management.
 */
static vmem_t *hat_memload1_arena; /* HAT translation arena for sfmmu1_cache */
static struct kmem_cache *sfmmu8_cache;
static struct kmem_cache *sfmmu1_cache;
static struct kmem_cache *pa_hment_cache;

static kmutex_t 	ism_mlist_lock;	/* mutex for ism mapping list */
/*
 * private data for ism
 */
static struct kmem_cache *ism_blk_cache;
static struct kmem_cache *ism_ment_cache;
#define	ISMID_STARTADDR	NULL

/*
 * Region management data structures and function declarations.
 */

static void	sfmmu_leave_srd(sfmmu_t *);
static int	sfmmu_srdcache_constructor(void *, void *, int);
static void	sfmmu_srdcache_destructor(void *, void *);
static int	sfmmu_rgncache_constructor(void *, void *, int);
static void	sfmmu_rgncache_destructor(void *, void *);
static int	sfrgnmap_isnull(sf_region_map_t *);
static int	sfhmergnmap_isnull(sf_hmeregion_map_t *);
static int	sfmmu_scdcache_constructor(void *, void *, int);
static void	sfmmu_scdcache_destructor(void *, void *);
static void	sfmmu_rgn_cb_noop(caddr_t, caddr_t, caddr_t,
    size_t, void *, u_offset_t);

static uint_t srd_hashmask = SFMMU_MAX_SRD_BUCKETS - 1;
static sf_srd_bucket_t *srd_buckets;
static struct kmem_cache *srd_cache;
static uint_t srd_rgn_hashmask = SFMMU_MAX_REGION_BUCKETS - 1;
static struct kmem_cache *region_cache;
static struct kmem_cache *scd_cache;

#ifdef sun4v
int use_bigtsb_arena = 1;
#else
int use_bigtsb_arena = 0;
#endif

/* External /etc/system tunable, for turning on&off the shctx support */
int disable_shctx = 0;
/* Internal variable, set by MD if the HW supports shctx feature */
int shctx_on = 0;

#ifdef DEBUG
static void check_scd_sfmmu_list(sfmmu_t **, sfmmu_t *, int);
#endif
static void sfmmu_to_scd_list(sfmmu_t **, sfmmu_t *);
static void sfmmu_from_scd_list(sfmmu_t **, sfmmu_t *);

static sf_scd_t *sfmmu_alloc_scd(sf_srd_t *, sf_region_map_t *);
static void sfmmu_find_scd(sfmmu_t *);
static void sfmmu_join_scd(sf_scd_t *, sfmmu_t *);
static void sfmmu_finish_join_scd(sfmmu_t *);
static void sfmmu_leave_scd(sfmmu_t *, uchar_t);
static void sfmmu_destroy_scd(sf_srd_t *, sf_scd_t *, sf_region_map_t *);
static int sfmmu_alloc_scd_tsbs(sf_srd_t *, sf_scd_t *);
static void sfmmu_free_scd_tsbs(sfmmu_t *);
static void sfmmu_tsb_inv_ctx(sfmmu_t *);
static int find_ism_rid(sfmmu_t *, sfmmu_t *, caddr_t, uint_t *);
static void sfmmu_ism_hatflags(sfmmu_t *, int);
static int sfmmu_srd_lock_held(sf_srd_t *);
static void sfmmu_remove_scd(sf_scd_t **, sf_scd_t *);
static void sfmmu_add_scd(sf_scd_t **headp, sf_scd_t *);
static void sfmmu_link_scd_to_regions(sf_srd_t *, sf_scd_t *);
static void sfmmu_unlink_scd_from_regions(sf_srd_t *, sf_scd_t *);
static void sfmmu_link_to_hmeregion(sfmmu_t *, sf_region_t *);
static void sfmmu_unlink_from_hmeregion(sfmmu_t *, sf_region_t *);

/*
 * ``hat_lock'' is a hashed mutex lock for protecting sfmmu TSB lists,
 * HAT flags, synchronizing TLB/TSB coherency, and context management.
 * The lock is hashed on the sfmmup since the case where we need to lock
 * all processes is rare but does occur (e.g. we need to unload a shared
 * mapping from all processes using the mapping).  We have a lot of buckets,
 * and each slab of sfmmu_t's can use about a quarter of them, giving us
 * a fairly good distribution without wasting too much space and overhead
 * when we have to grab them all.
 */
#define	SFMMU_NUM_LOCK	128		/* must be power of two */
hatlock_t	hat_lock[SFMMU_NUM_LOCK];

/*
 * Hash algorithm optimized for a small number of slabs.
 *  7 is (highbit((sizeof sfmmu_t)) - 1)
 * This hash algorithm is based upon the knowledge that sfmmu_t's come from a
 * kmem_cache, and thus they will be sequential within that cache.  In
 * addition, each new slab will have a different "color" up to cache_maxcolor
 * which will skew the hashing for each successive slab which is allocated.
 * If the size of sfmmu_t changed to a larger size, this algorithm may need
 * to be revisited.
 */
#define	TSB_HASH_SHIFT_BITS (7)
#define	PTR_HASH(x) ((uintptr_t)x >> TSB_HASH_SHIFT_BITS)

#ifdef DEBUG
int tsb_hash_debug = 0;
#define	TSB_HASH(sfmmup)	\
	(tsb_hash_debug ? &hat_lock[0] : \
	&hat_lock[PTR_HASH(sfmmup) & (SFMMU_NUM_LOCK-1)])
#else	/* DEBUG */
#define	TSB_HASH(sfmmup)	&hat_lock[PTR_HASH(sfmmup) & (SFMMU_NUM_LOCK-1)]
#endif	/* DEBUG */


/* sfmmu_replace_tsb() return codes. */
typedef enum tsb_replace_rc {
	TSB_SUCCESS,
	TSB_ALLOCFAIL,
	TSB_LOSTRACE,
	TSB_ALREADY_SWAPPED,
	TSB_CANTGROW
} tsb_replace_rc_t;

/*
 * Flags for TSB allocation routines.
 */
#define	TSB_ALLOC	0x01
#define	TSB_FORCEALLOC	0x02
#define	TSB_GROW	0x04
#define	TSB_SHRINK	0x08
#define	TSB_SWAPIN	0x10

/*
 * Support for HAT callbacks.
 */
#define	SFMMU_MAX_RELOC_CALLBACKS	10
int sfmmu_max_cb_id = SFMMU_MAX_RELOC_CALLBACKS;
static id_t sfmmu_cb_nextid = 0;
static id_t sfmmu_tsb_cb_id;
struct sfmmu_callback *sfmmu_cb_table;

kmutex_t	kpr_mutex;
kmutex_t	kpr_suspendlock;
kthread_t	*kreloc_thread;

/*
 * Enable VA->PA translation sanity checking on DEBUG kernels.
 * Disabled by default.  This is incompatible with some
 * drivers (error injector, RSM) so if it breaks you get
 * to keep both pieces.
 */
int hat_check_vtop = 0;

/*
 * Private sfmmu routines (prototypes)
 */
static struct hme_blk *sfmmu_shadow_hcreate(sfmmu_t *, caddr_t, int, uint_t);
static struct 	hme_blk *sfmmu_hblk_alloc(sfmmu_t *, caddr_t,
			struct hmehash_bucket *, uint_t, hmeblk_tag, uint_t,
			uint_t);
static caddr_t	sfmmu_hblk_unload(struct hat *, struct hme_blk *, caddr_t,
			caddr_t, demap_range_t *, uint_t);
static caddr_t	sfmmu_hblk_sync(struct hat *, struct hme_blk *, caddr_t,
			caddr_t, int);
static void	sfmmu_hblk_free(struct hme_blk **);
static void	sfmmu_hblks_list_purge(struct hme_blk **, int);
static uint_t	sfmmu_get_free_hblk(struct hme_blk **, uint_t);
static uint_t	sfmmu_put_free_hblk(struct hme_blk *, uint_t);
static struct hme_blk *sfmmu_hblk_steal(int);
static int	sfmmu_steal_this_hblk(struct hmehash_bucket *,
			struct hme_blk *, uint64_t, struct hme_blk *);
static caddr_t	sfmmu_hblk_unlock(struct hme_blk *, caddr_t, caddr_t);

static void	hat_do_memload_array(struct hat *, caddr_t, size_t,
		    struct page **, uint_t, uint_t, uint_t);
static void	hat_do_memload(struct hat *, caddr_t, struct page *,
		    uint_t, uint_t, uint_t);
static void	sfmmu_memload_batchsmall(struct hat *, caddr_t, page_t **,
		    uint_t, uint_t, pgcnt_t, uint_t);
void		sfmmu_tteload(struct hat *, tte_t *, caddr_t, page_t *,
			uint_t);
static int	sfmmu_tteload_array(sfmmu_t *, tte_t *, caddr_t, page_t **,
			uint_t, uint_t);
static struct hmehash_bucket *sfmmu_tteload_acquire_hashbucket(sfmmu_t *,
					caddr_t, int, uint_t);
static struct hme_blk *sfmmu_tteload_find_hmeblk(sfmmu_t *,
			struct hmehash_bucket *, caddr_t, uint_t, uint_t,
			uint_t);
static int	sfmmu_tteload_addentry(sfmmu_t *, struct hme_blk *, tte_t *,
			caddr_t, page_t **, uint_t, uint_t);
static void	sfmmu_tteload_release_hashbucket(struct hmehash_bucket *);

static int	sfmmu_pagearray_setup(caddr_t, page_t **, tte_t *, int);
static pfn_t	sfmmu_uvatopfn(caddr_t, sfmmu_t *, tte_t *);
void		sfmmu_memtte(tte_t *, pfn_t, uint_t, int);
#ifdef VAC
static void	sfmmu_vac_conflict(struct hat *, caddr_t, page_t *);
static int	sfmmu_vacconflict_array(caddr_t, page_t *, int *);
int	tst_tnc(page_t *pp, pgcnt_t);
void	conv_tnc(page_t *pp, int);
#endif

static void	sfmmu_get_ctx(sfmmu_t *);
static void	sfmmu_free_sfmmu(sfmmu_t *);

static void	sfmmu_ttesync(struct hat *, caddr_t, tte_t *, page_t *);
static void	sfmmu_chgattr(struct hat *, caddr_t, size_t, uint_t, int);

cpuset_t	sfmmu_pageunload(page_t *, struct sf_hment *, int);
static void	hat_pagereload(struct page *, struct page *);
static cpuset_t	sfmmu_pagesync(page_t *, struct sf_hment *, uint_t);
#ifdef VAC
void	sfmmu_page_cache_array(page_t *, int, int, pgcnt_t);
static void	sfmmu_page_cache(page_t *, int, int, int);
#endif

cpuset_t	sfmmu_rgntlb_demap(caddr_t, sf_region_t *,
    struct hme_blk *, int);
static void	sfmmu_tlbcache_demap(caddr_t, sfmmu_t *, struct hme_blk *,
			pfn_t, int, int, int, int);
static void	sfmmu_ismtlbcache_demap(caddr_t, sfmmu_t *, struct hme_blk *,
			pfn_t, int);
static void	sfmmu_tlb_demap(caddr_t, sfmmu_t *, struct hme_blk *, int, int);
static void	sfmmu_tlb_range_demap(demap_range_t *);
static void	sfmmu_invalidate_ctx(sfmmu_t *);
static void	sfmmu_sync_mmustate(sfmmu_t *);

static void 	sfmmu_tsbinfo_setup_phys(struct tsb_info *, pfn_t);
static int	sfmmu_tsbinfo_alloc(struct tsb_info **, int, int, uint_t,
			sfmmu_t *);
static void	sfmmu_tsb_free(struct tsb_info *);
static void	sfmmu_tsbinfo_free(struct tsb_info *);
static int	sfmmu_init_tsbinfo(struct tsb_info *, int, int, uint_t,
			sfmmu_t *);
static void	sfmmu_tsb_chk_reloc(sfmmu_t *, hatlock_t *);
static void	sfmmu_tsb_swapin(sfmmu_t *, hatlock_t *);
static int	sfmmu_select_tsb_szc(pgcnt_t);
static void	sfmmu_mod_tsb(sfmmu_t *, caddr_t, tte_t *, int);
#define		sfmmu_load_tsb(sfmmup, vaddr, tte, szc) \
	sfmmu_mod_tsb(sfmmup, vaddr, tte, szc)
#define		sfmmu_unload_tsb(sfmmup, vaddr, szc)    \
	sfmmu_mod_tsb(sfmmup, vaddr, NULL, szc)
static void	sfmmu_copy_tsb(struct tsb_info *, struct tsb_info *);
static tsb_replace_rc_t sfmmu_replace_tsb(sfmmu_t *, struct tsb_info *, uint_t,
    hatlock_t *, uint_t);
static void	sfmmu_size_tsb(sfmmu_t *, int, uint64_t, uint64_t, int);

#ifdef VAC
void	sfmmu_cache_flush(pfn_t, int);
void	sfmmu_cache_flushcolor(int, pfn_t);
#endif
static caddr_t	sfmmu_hblk_chgattr(sfmmu_t *, struct hme_blk *, caddr_t,
			caddr_t, demap_range_t *, uint_t, int);

static uint64_t	sfmmu_vtop_attr(uint_t, int mode, tte_t *);
static uint_t	sfmmu_ptov_attr(tte_t *);
static caddr_t	sfmmu_hblk_chgprot(sfmmu_t *, struct hme_blk *, caddr_t,
			caddr_t, demap_range_t *, uint_t);
static uint_t	sfmmu_vtop_prot(uint_t, uint_t *);
static int	sfmmu_idcache_constructor(void *, void *, int);
static void	sfmmu_idcache_destructor(void *, void *);
static int	sfmmu_hblkcache_constructor(void *, void *, int);
static void	sfmmu_hblkcache_destructor(void *, void *);
static void	sfmmu_hblkcache_reclaim(void *);
static void	sfmmu_shadow_hcleanup(sfmmu_t *, struct hme_blk *,
			struct hmehash_bucket *);
static void	sfmmu_hblk_hash_rm(struct hmehash_bucket *, struct hme_blk *,
			struct hme_blk *, struct hme_blk **, int);
static void	sfmmu_hblk_hash_add(struct hmehash_bucket *, struct hme_blk *,
			uint64_t);
static struct hme_blk *sfmmu_check_pending_hblks(int);
static void	sfmmu_free_hblks(sfmmu_t *, caddr_t, caddr_t, int);
static void	sfmmu_cleanup_rhblk(sf_srd_t *, caddr_t, uint_t, int);
static void	sfmmu_unload_hmeregion_va(sf_srd_t *, uint_t, caddr_t, caddr_t,
			int, caddr_t *);
static void	sfmmu_unload_hmeregion(sf_srd_t *, sf_region_t *);

static void	sfmmu_rm_large_mappings(page_t *, int);

static void	hat_lock_init(void);
static void	hat_kstat_init(void);
static int	sfmmu_kstat_percpu_update(kstat_t *ksp, int rw);
static void	sfmmu_set_scd_rttecnt(sf_srd_t *, sf_scd_t *);
static	int	sfmmu_is_rgnva(sf_srd_t *, caddr_t, ulong_t, ulong_t);
static void	sfmmu_check_page_sizes(sfmmu_t *, int);
int	fnd_mapping_sz(page_t *);
static void	iment_add(struct ism_ment *,  struct hat *);
static void	iment_sub(struct ism_ment *, struct hat *);
static pgcnt_t	ism_tsb_entries(sfmmu_t *, int szc);
extern void	sfmmu_setup_tsbinfo(sfmmu_t *);
extern void	sfmmu_clear_utsbinfo(void);

static void		sfmmu_ctx_wrap_around(mmu_ctx_t *, boolean_t);

extern int vpm_enable;

/* kpm globals */
#ifdef	DEBUG
/*
 * Enable trap level tsbmiss handling
 */
int	kpm_tsbmtl = 1;

/*
 * Flush the TLB on kpm mapout. Note: Xcalls are used (again) for the
 * required TLB shootdowns in this case, so handle w/ care. Off by default.
 */
int	kpm_tlb_flush;
#endif	/* DEBUG */

static void	*sfmmu_vmem_xalloc_aligned_wrapper(vmem_t *, size_t, int);

#ifdef DEBUG
static void	sfmmu_check_hblk_flist();
#endif

/*
 * Semi-private sfmmu data structures.  Some of them are initialize in
 * startup or in hat_init. Some of them are private but accessed by
 * assembly code or mach_sfmmu.c
 */
struct hmehash_bucket *uhme_hash;	/* user hmeblk hash table */
struct hmehash_bucket *khme_hash;	/* kernel hmeblk hash table */
uint64_t	uhme_hash_pa;		/* PA of uhme_hash */
uint64_t	khme_hash_pa;		/* PA of khme_hash */
int 		uhmehash_num;		/* # of buckets in user hash table */
int 		khmehash_num;		/* # of buckets in kernel hash table */

uint_t		max_mmu_ctxdoms = 0;	/* max context domains in the system */
mmu_ctx_t	**mmu_ctxs_tbl;		/* global array of context domains */
uint64_t	mmu_saved_gnum = 0;	/* to init incoming MMUs' gnums */

#define	DEFAULT_NUM_CTXS_PER_MMU 8192
static uint_t	nctxs = DEFAULT_NUM_CTXS_PER_MMU;

int		cache;			/* describes system cache */

caddr_t		ktsb_base;		/* kernel 8k-indexed tsb base address */
uint64_t	ktsb_pbase;		/* kernel 8k-indexed tsb phys address */
int		ktsb_szcode;		/* kernel 8k-indexed tsb size code */
int		ktsb_sz;		/* kernel 8k-indexed tsb size */

caddr_t		ktsb4m_base;		/* kernel 4m-indexed tsb base address */
uint64_t	ktsb4m_pbase;		/* kernel 4m-indexed tsb phys address */
int		ktsb4m_szcode;		/* kernel 4m-indexed tsb size code */
int		ktsb4m_sz;		/* kernel 4m-indexed tsb size */

uint64_t	kpm_tsbbase;		/* kernel seg_kpm 4M TSB base address */
int		kpm_tsbsz;		/* kernel seg_kpm 4M TSB size code */
uint64_t	kpmsm_tsbbase;		/* kernel seg_kpm 8K TSB base address */
int		kpmsm_tsbsz;		/* kernel seg_kpm 8K TSB size code */

#ifndef sun4v
int		utsb_dtlb_ttenum = -1;	/* index in TLB for utsb locked TTE */
int		utsb4m_dtlb_ttenum = -1; /* index in TLB for 4M TSB TTE */
int		dtlb_resv_ttenum;	/* index in TLB of first reserved TTE */
caddr_t		utsb_vabase;		/* reserved kernel virtual memory */
caddr_t		utsb4m_vabase;		/* for trap handler TSB accesses */
#endif /* sun4v */
uint64_t	tsb_alloc_bytes = 0;	/* bytes allocated to TSBs */
vmem_t		*kmem_tsb_default_arena[NLGRPS_MAX];	/* For dynamic TSBs */
vmem_t		*kmem_bigtsb_default_arena[NLGRPS_MAX]; /* dynamic 256M TSBs */

/*
 * Size to use for TSB slabs.  Future platforms that support page sizes
 * larger than 4M may wish to change these values, and provide their own
 * assembly macros for building and decoding the TSB base register contents.
 * Note disable_large_pages will override the value set here.
 */
static	uint_t tsb_slab_ttesz = TTE4M;
size_t	tsb_slab_size = MMU_PAGESIZE4M;
uint_t	tsb_slab_shift = MMU_PAGESHIFT4M;
/* PFN mask for TTE */
size_t	tsb_slab_mask = MMU_PAGEOFFSET4M >> MMU_PAGESHIFT;

/*
 * Size to use for TSB slabs.  These are used only when 256M tsb arenas
 * exist.
 */
static uint_t	bigtsb_slab_ttesz = TTE256M;
static size_t	bigtsb_slab_size = MMU_PAGESIZE256M;
static uint_t	bigtsb_slab_shift = MMU_PAGESHIFT256M;
/* 256M page alignment for 8K pfn */
static size_t	bigtsb_slab_mask = MMU_PAGEOFFSET256M >> MMU_PAGESHIFT;

/* largest TSB size to grow to, will be smaller on smaller memory systems */
static int	tsb_max_growsize = 0;

/*
 * Tunable parameters dealing with TSB policies.
 */

/*
 * This undocumented tunable forces all 8K TSBs to be allocated from
 * the kernel heap rather than from the kmem_tsb_default_arena arenas.
 */
#ifdef	DEBUG
int	tsb_forceheap = 0;
#endif	/* DEBUG */

/*
 * Decide whether to use per-lgroup arenas, or one global set of
 * TSB arenas.  The default is not to break up per-lgroup, since
 * most platforms don't recognize any tangible benefit from it.
 */
int	tsb_lgrp_affinity = 0;

/*
 * Used for growing the TSB based on the process RSS.
 * tsb_rss_factor is based on the smallest TSB, and is
 * shifted by the TSB size to determine if we need to grow.
 * The default will grow the TSB if the number of TTEs for
 * this page size exceeds 75% of the number of TSB entries,
 * which should _almost_ eliminate all conflict misses
 * (at the expense of using up lots and lots of memory).
 */
#define	TSB_RSS_FACTOR		(TSB_ENTRIES(TSB_MIN_SZCODE) * 0.75)
#define	SFMMU_RSS_TSBSIZE(tsbszc)	(tsb_rss_factor << tsbszc)
#define	SELECT_TSB_SIZECODE(pgcnt) ( \
	(enable_tsb_rss_sizing)? sfmmu_select_tsb_szc(pgcnt) : \
	default_tsb_size)
#define	TSB_OK_SHRINK()	\
	(tsb_alloc_bytes > tsb_alloc_hiwater || freemem < desfree)
#define	TSB_OK_GROW()	\
	(tsb_alloc_bytes < tsb_alloc_hiwater && freemem > desfree)

int	enable_tsb_rss_sizing = 1;
int	tsb_rss_factor	= (int)TSB_RSS_FACTOR;

/* which TSB size code to use for new address spaces or if rss sizing off */
int default_tsb_size = TSB_8K_SZCODE;

static uint64_t tsb_alloc_hiwater; /* limit TSB reserved memory */
uint64_t tsb_alloc_hiwater_factor; /* tsb_alloc_hiwater = physmem / this */
#define	TSB_ALLOC_HIWATER_FACTOR_DEFAULT	32

#ifdef DEBUG
static int tsb_random_size = 0;	/* set to 1 to test random tsb sizes on alloc */
static int tsb_grow_stress = 0;	/* if set to 1, keep replacing TSB w/ random */
static int tsb_alloc_mtbf = 0;	/* fail allocation every n attempts */
static int tsb_alloc_fail_mtbf = 0;
static int tsb_alloc_count = 0;
#endif /* DEBUG */

/* if set to 1, will remap valid TTEs when growing TSB. */
int tsb_remap_ttes = 1;

/*
 * If we have more than this many mappings, allocate a second TSB.
 * This default is chosen because the I/D fully associative TLBs are
 * assumed to have at least 8 available entries. Platforms with a
 * larger fully-associative TLB could probably override the default.
 */

#ifdef sun4v
int tsb_sectsb_threshold = 0;
#else
int tsb_sectsb_threshold = 8;
#endif

/*
 * kstat data
 */
struct sfmmu_global_stat sfmmu_global_stat;
struct sfmmu_tsbsize_stat sfmmu_tsbsize_stat;

/*
 * Global data
 */
sfmmu_t 	*ksfmmup;		/* kernel's hat id */

#ifdef DEBUG
static void	chk_tte(tte_t *, tte_t *, tte_t *, struct hme_blk *);
#endif

/* sfmmu locking operations */
static kmutex_t *sfmmu_mlspl_enter(struct page *, int);
static int	sfmmu_mlspl_held(struct page *, int);

kmutex_t *sfmmu_page_enter(page_t *);
void	sfmmu_page_exit(kmutex_t *);
int	sfmmu_page_spl_held(struct page *);

/* sfmmu internal locking operations - accessed directly */
static void	sfmmu_mlist_reloc_enter(page_t *, page_t *,
				kmutex_t **, kmutex_t **);
static void	sfmmu_mlist_reloc_exit(kmutex_t *, kmutex_t *);
static hatlock_t *
		sfmmu_hat_enter(sfmmu_t *);
static hatlock_t *
		sfmmu_hat_tryenter(sfmmu_t *);
static void	sfmmu_hat_exit(hatlock_t *);
static void	sfmmu_hat_lock_all(void);
static void	sfmmu_hat_unlock_all(void);
static void	sfmmu_ismhat_enter(sfmmu_t *, int);
static void	sfmmu_ismhat_exit(sfmmu_t *, int);

kpm_hlk_t	*kpmp_table;
uint_t		kpmp_table_sz;	/* must be a power of 2 */
uchar_t		kpmp_shift;

kpm_shlk_t	*kpmp_stable;
uint_t		kpmp_stable_sz;	/* must be a power of 2 */

/*
 * SPL_TABLE_SIZE is 2 * NCPU, but no smaller than 128.
 * SPL_SHIFT is log2(SPL_TABLE_SIZE).
 */
#if ((2*NCPU_P2) > 128)
#define	SPL_SHIFT	((unsigned)(NCPU_LOG2 + 1))
#else
#define	SPL_SHIFT	7U
#endif
#define	SPL_TABLE_SIZE	(1U << SPL_SHIFT)
#define	SPL_MASK	(SPL_TABLE_SIZE - 1)

/*
 * We shift by PP_SHIFT to take care of the low-order 0 bits of a page_t
 * and by multiples of SPL_SHIFT to get as many varied bits as we can.
 */
#define	SPL_INDEX(pp) \
	((((uintptr_t)(pp) >> PP_SHIFT) ^ \
	((uintptr_t)(pp) >> (PP_SHIFT + SPL_SHIFT)) ^ \
	((uintptr_t)(pp) >> (PP_SHIFT + SPL_SHIFT * 2)) ^ \
	((uintptr_t)(pp) >> (PP_SHIFT + SPL_SHIFT * 3))) & \
	SPL_MASK)

#define	SPL_HASH(pp)    \
	(&sfmmu_page_lock[SPL_INDEX(pp)].pad_mutex)

static	pad_mutex_t	sfmmu_page_lock[SPL_TABLE_SIZE];

/* Array of mutexes protecting a page's mapping list and p_nrm field. */

#define	MML_TABLE_SIZE	SPL_TABLE_SIZE
#define	MLIST_HASH(pp)	(&mml_table[SPL_INDEX(pp)].pad_mutex)

static pad_mutex_t	mml_table[MML_TABLE_SIZE];

/*
 * hat_unload_callback() will group together callbacks in order
 * to avoid xt_sync() calls.  This is the maximum size of the group.
 */
#define	MAX_CB_ADDR	32

tte_t	hw_tte;
static ulong_t sfmmu_dmr_maxbit = DMR_MAXBIT;

static char	*mmu_ctx_kstat_names[] = {
	"mmu_ctx_tsb_exceptions",
	"mmu_ctx_tsb_raise_exception",
	"mmu_ctx_wrap_around",
};

/*
 * Wrapper for vmem_xalloc since vmem_create only allows limited
 * parameters for vm_source_alloc functions.  This function allows us
 * to specify alignment consistent with the size of the object being
 * allocated.
 */
static void *
sfmmu_vmem_xalloc_aligned_wrapper(vmem_t *vmp, size_t size, int vmflag)
{
	return (vmem_xalloc(vmp, size, size, 0, 0, NULL, NULL, vmflag));
}

/* Common code for setting tsb_alloc_hiwater. */
#define	SFMMU_SET_TSB_ALLOC_HIWATER(pages)	tsb_alloc_hiwater = \
		ptob(pages) / tsb_alloc_hiwater_factor

/*
 * Set tsb_max_growsize to allow at most all of physical memory to be mapped by
 * a single TSB.  physmem is the number of physical pages so we need physmem 8K
 * TTEs to represent all those physical pages.  We round this up by using
 * 1<<highbit().  To figure out which size code to use, remember that the size
 * code is just an amount to shift the smallest TSB size to get the size of
 * this TSB.  So we subtract that size, TSB_START_SIZE, from highbit() (or
 * highbit() - 1) to get the size code for the smallest TSB that can represent
 * all of physical memory, while erring on the side of too much.
 *
 * Restrict tsb_max_growsize to make sure that:
 *	1) TSBs can't grow larger than the TSB slab size
 *	2) TSBs can't grow larger than UTSB_MAX_SZCODE.
 */
#define	SFMMU_SET_TSB_MAX_GROWSIZE(pages) {				\
	int	_i, _szc, _slabszc, _tsbszc;				\
									\
	_i = highbit(pages);						\
	if ((1 << (_i - 1)) == (pages))					\
		_i--;		/* 2^n case, round down */              \
	_szc = _i - TSB_START_SIZE;					\
	_slabszc = bigtsb_slab_shift - (TSB_START_SIZE + TSB_ENTRY_SHIFT); \
	_tsbszc = MIN(_szc, _slabszc);                                  \
	tsb_max_growsize = MIN(_tsbszc, UTSB_MAX_SZCODE);               \
}

/*
 * Given a pointer to an sfmmu and a TTE size code, return a pointer to the
 * tsb_info which handles that TTE size.
 */
#define	SFMMU_GET_TSBINFO(tsbinfop, sfmmup, tte_szc) {			\
	(tsbinfop) = (sfmmup)->sfmmu_tsb;				\
	ASSERT(((tsbinfop)->tsb_flags & TSB_SHAREDCTX) ||		\
	    sfmmu_hat_lock_held(sfmmup));				\
	if ((tte_szc) >= TTE4M)	{					\
		ASSERT((tsbinfop) != NULL);				\
		(tsbinfop) = (tsbinfop)->tsb_next;			\
	}								\
}

/*
 * Macro to use to unload entries from the TSB.
 * It has knowledge of which page sizes get replicated in the TSB
 * and will call the appropriate unload routine for the appropriate size.
 */
#define	SFMMU_UNLOAD_TSB(addr, sfmmup, hmeblkp, ismhat)		\
{									\
	int ttesz = get_hblk_ttesz(hmeblkp);				\
	if (ttesz == TTE8K || ttesz == TTE4M) {				\
		sfmmu_unload_tsb(sfmmup, addr, ttesz);			\
	} else {							\
		caddr_t sva = ismhat ? addr : 				\
		    (caddr_t)get_hblk_base(hmeblkp);			\
		caddr_t eva = sva + get_hblk_span(hmeblkp);		\
		ASSERT(addr >= sva && addr < eva);			\
		sfmmu_unload_tsb_range(sfmmup, sva, eva, ttesz);	\
	}								\
}


/* Update tsb_alloc_hiwater after memory is configured. */
/*ARGSUSED*/
static void
sfmmu_update_post_add(void *arg, pgcnt_t delta_pages)
{
	/* Assumes physmem has already been updated. */
	SFMMU_SET_TSB_ALLOC_HIWATER(physmem);
	SFMMU_SET_TSB_MAX_GROWSIZE(physmem);
}

/*
 * Update tsb_alloc_hiwater before memory is deleted.  We'll do nothing here
 * and update tsb_alloc_hiwater and tsb_max_growsize after the memory is
 * deleted.
 */
/*ARGSUSED*/
static int
sfmmu_update_pre_del(void *arg, pgcnt_t delta_pages)
{
	return (0);
}

/* Update tsb_alloc_hiwater after memory fails to be unconfigured. */
/*ARGSUSED*/
static void
sfmmu_update_post_del(void *arg, pgcnt_t delta_pages, int cancelled)
{
	/*
	 * Whether the delete was cancelled or not, just go ahead and update
	 * tsb_alloc_hiwater and tsb_max_growsize.
	 */
	SFMMU_SET_TSB_ALLOC_HIWATER(physmem);
	SFMMU_SET_TSB_MAX_GROWSIZE(physmem);
}

static kphysm_setup_vector_t sfmmu_update_vec = {
	KPHYSM_SETUP_VECTOR_VERSION,	/* version */
	sfmmu_update_post_add,		/* post_add */
	sfmmu_update_pre_del,		/* pre_del */
	sfmmu_update_post_del		/* post_del */
};


/*
 * HME_BLK HASH PRIMITIVES
 */

/*
 * Enter a hme on the mapping list for page pp.
 * When large pages are more prevalent in the system we might want to
 * keep the mapping list in ascending order by the hment size. For now,
 * small pages are more frequent, so don't slow it down.
 */
#define	HME_ADD(hme, pp)					\
{								\
	ASSERT(sfmmu_mlist_held(pp));				\
								\
	hme->hme_prev = NULL;					\
	hme->hme_next = pp->p_mapping;				\
	hme->hme_page = pp;					\
	if (pp->p_mapping) {					\
		((struct sf_hment *)(pp->p_mapping))->hme_prev = hme;\
		ASSERT(pp->p_share > 0);			\
	} else  {						\
		/* EMPTY */					\
		ASSERT(pp->p_share == 0);			\
	}							\
	pp->p_mapping = hme;					\
	pp->p_share++;						\
}

/*
 * Enter a hme on the mapping list for page pp.
 * If we are unmapping a large translation, we need to make sure that the
 * change is reflect in the corresponding bit of the p_index field.
 */
#define	HME_SUB(hme, pp)					\
{								\
	ASSERT(sfmmu_mlist_held(pp));				\
	ASSERT(hme->hme_page == pp || IS_PAHME(hme));		\
								\
	if (pp->p_mapping == NULL) {				\
		panic("hme_remove - no mappings");		\
	}							\
								\
	membar_stst();	/* ensure previous stores finish */	\
								\
	ASSERT(pp->p_share > 0);				\
	pp->p_share--;						\
								\
	if (hme->hme_prev) {					\
		ASSERT(pp->p_mapping != hme);			\
		ASSERT(hme->hme_prev->hme_page == pp ||		\
			IS_PAHME(hme->hme_prev));		\
		hme->hme_prev->hme_next = hme->hme_next;	\
	} else {						\
		ASSERT(pp->p_mapping == hme);			\
		pp->p_mapping = hme->hme_next;			\
		ASSERT((pp->p_mapping == NULL) ?		\
			(pp->p_share == 0) : 1);		\
	}							\
								\
	if (hme->hme_next) {					\
		ASSERT(hme->hme_next->hme_page == pp ||		\
			IS_PAHME(hme->hme_next));		\
		hme->hme_next->hme_prev = hme->hme_prev;	\
	}							\
								\
	/* zero out the entry */				\
	hme->hme_next = NULL;					\
	hme->hme_prev = NULL;					\
	hme->hme_page = NULL;					\
								\
	if (hme_size(hme) > TTE8K) {				\
		/* remove mappings for remainder of large pg */	\
		sfmmu_rm_large_mappings(pp, hme_size(hme));	\
	}							\
}

/*
 * This function returns the hment given the hme_blk and a vaddr.
 * It assumes addr has already been checked to belong to hme_blk's
 * range.
 */
#define	HBLKTOHME(hment, hmeblkp, addr)					\
{									\
	int index;							\
	HBLKTOHME_IDX(hment, hmeblkp, addr, index)			\
}

/*
 * Version of HBLKTOHME that also returns the index in hmeblkp
 * of the hment.
 */
#define	HBLKTOHME_IDX(hment, hmeblkp, addr, idx)			\
{									\
	ASSERT(in_hblk_range((hmeblkp), (addr)));			\
									\
	if (get_hblk_ttesz(hmeblkp) == TTE8K) {				\
		idx = (((uintptr_t)(addr) >> MMU_PAGESHIFT) & (NHMENTS-1)); \
	} else								\
		idx = 0;						\
									\
	(hment) = &(hmeblkp)->hblk_hme[idx];				\
}

/*
 * Disable any page sizes not supported by the CPU
 */
void
hat_init_pagesizes()
{
	int 		i;

	mmu_exported_page_sizes = 0;
	for (i = TTE8K; i < max_mmu_page_sizes; i++) {

		szc_2_userszc[i] = (uint_t)-1;
		userszc_2_szc[i] = (uint_t)-1;

		if ((mmu_exported_pagesize_mask & (1 << i)) == 0) {
			disable_large_pages |= (1 << i);
		} else {
			szc_2_userszc[i] = mmu_exported_page_sizes;
			userszc_2_szc[mmu_exported_page_sizes] = i;
			mmu_exported_page_sizes++;
		}
	}

	disable_ism_large_pages |= disable_large_pages;
	disable_auto_data_large_pages = disable_large_pages;
	disable_auto_text_large_pages = disable_large_pages;

	/*
	 * Initialize mmu-specific large page sizes.
	 */
	if (&mmu_large_pages_disabled) {
		disable_large_pages |= mmu_large_pages_disabled(HAT_LOAD);
		disable_ism_large_pages |=
		    mmu_large_pages_disabled(HAT_LOAD_SHARE);
		disable_auto_data_large_pages |=
		    mmu_large_pages_disabled(HAT_AUTO_DATA);
		disable_auto_text_large_pages |=
		    mmu_large_pages_disabled(HAT_AUTO_TEXT);
	}
}

/*
 * Initialize the hardware address translation structures.
 */
void
hat_init(void)
{
	int 		i;
	uint_t		sz;
	size_t		size;

	hat_lock_init();
	hat_kstat_init();

	/*
	 * Hardware-only bits in a TTE
	 */
	MAKE_TTE_MASK(&hw_tte);

	hat_init_pagesizes();

	/* Initialize the hash locks */
	for (i = 0; i < khmehash_num; i++) {
		mutex_init(&khme_hash[i].hmehash_mutex, NULL,
		    MUTEX_DEFAULT, NULL);
		khme_hash[i].hmeh_nextpa = HMEBLK_ENDPA;
	}
	for (i = 0; i < uhmehash_num; i++) {
		mutex_init(&uhme_hash[i].hmehash_mutex, NULL,
		    MUTEX_DEFAULT, NULL);
		uhme_hash[i].hmeh_nextpa = HMEBLK_ENDPA;
	}
	khmehash_num--;		/* make sure counter starts from 0 */
	uhmehash_num--;		/* make sure counter starts from 0 */

	/*
	 * Allocate context domain structures.
	 *
	 * A platform may choose to modify max_mmu_ctxdoms in
	 * set_platform_defaults(). If a platform does not define
	 * a set_platform_defaults() or does not choose to modify
	 * max_mmu_ctxdoms, it gets one MMU context domain for every CPU.
	 *
	 * For all platforms that have CPUs sharing MMUs, this
	 * value must be defined.
	 */
	if (max_mmu_ctxdoms == 0)
		max_mmu_ctxdoms = max_ncpus;

	size = max_mmu_ctxdoms * sizeof (mmu_ctx_t *);
	mmu_ctxs_tbl = kmem_zalloc(size, KM_SLEEP);

	/* mmu_ctx_t is 64 bytes aligned */
	mmuctxdom_cache = kmem_cache_create("mmuctxdom_cache",
	    sizeof (mmu_ctx_t), 64, NULL, NULL, NULL, NULL, NULL, 0);
	/*
	 * MMU context domain initialization for the Boot CPU.
	 * This needs the context domains array allocated above.
	 */
	mutex_enter(&cpu_lock);
	sfmmu_cpu_init(CPU);
	mutex_exit(&cpu_lock);

	/*
	 * Intialize ism mapping list lock.
	 */

	mutex_init(&ism_mlist_lock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * Each sfmmu structure carries an array of MMU context info
	 * structures, one per context domain. The size of this array depends
	 * on the maximum number of context domains. So, the size of the
	 * sfmmu structure varies per platform.
	 *
	 * sfmmu is allocated from static arena, because trap
	 * handler at TL > 0 is not allowed to touch kernel relocatable
	 * memory. sfmmu's alignment is changed to 64 bytes from
	 * default 8 bytes, as the lower 6 bits will be used to pass
	 * pgcnt to vtag_flush_pgcnt_tl1.
	 */
	size = sizeof (sfmmu_t) + sizeof (sfmmu_ctx_t) * (max_mmu_ctxdoms - 1);

	sfmmuid_cache = kmem_cache_create("sfmmuid_cache", size,
	    64, sfmmu_idcache_constructor, sfmmu_idcache_destructor,
	    NULL, NULL, static_arena, 0);

	sfmmu_tsbinfo_cache = kmem_cache_create("sfmmu_tsbinfo_cache",
	    sizeof (struct tsb_info), 0, NULL, NULL, NULL, NULL, NULL, 0);

	/*
	 * Since we only use the tsb8k cache to "borrow" pages for TSBs
	 * from the heap when low on memory or when TSB_FORCEALLOC is
	 * specified, don't use magazines to cache them--we want to return
	 * them to the system as quickly as possible.
	 */
	sfmmu_tsb8k_cache = kmem_cache_create("sfmmu_tsb8k_cache",
	    MMU_PAGESIZE, MMU_PAGESIZE, NULL, NULL, NULL, NULL,
	    static_arena, KMC_NOMAGAZINE);

	/*
	 * Set tsb_alloc_hiwater to 1/tsb_alloc_hiwater_factor of physical
	 * memory, which corresponds to the old static reserve for TSBs.
	 * tsb_alloc_hiwater_factor defaults to 32.  This caps the amount of
	 * memory we'll allocate for TSB slabs; beyond this point TSB
	 * allocations will be taken from the kernel heap (via
	 * sfmmu_tsb8k_cache) and will be throttled as would any other kmem
	 * consumer.
	 */
	if (tsb_alloc_hiwater_factor == 0) {
		tsb_alloc_hiwater_factor = TSB_ALLOC_HIWATER_FACTOR_DEFAULT;
	}
	SFMMU_SET_TSB_ALLOC_HIWATER(physmem);

	for (sz = tsb_slab_ttesz; sz > 0; sz--) {
		if (!(disable_large_pages & (1 << sz)))
			break;
	}

	if (sz < tsb_slab_ttesz) {
		tsb_slab_ttesz = sz;
		tsb_slab_shift = MMU_PAGESHIFT + (sz << 1) + sz;
		tsb_slab_size = 1 << tsb_slab_shift;
		tsb_slab_mask = (1 << (tsb_slab_shift - MMU_PAGESHIFT)) - 1;
		use_bigtsb_arena = 0;
	} else if (use_bigtsb_arena &&
	    (disable_large_pages & (1 << bigtsb_slab_ttesz))) {
		use_bigtsb_arena = 0;
	}

	if (!use_bigtsb_arena) {
		bigtsb_slab_shift = tsb_slab_shift;
	}
	SFMMU_SET_TSB_MAX_GROWSIZE(physmem);

	/*
	 * On smaller memory systems, allocate TSB memory in smaller chunks
	 * than the default 4M slab size. We also honor disable_large_pages
	 * here.
	 *
	 * The trap handlers need to be patched with the final slab shift,
	 * since they need to be able to construct the TSB pointer at runtime.
	 */
	if ((tsb_max_growsize <= TSB_512K_SZCODE) &&
	    !(disable_large_pages & (1 << TTE512K))) {
		tsb_slab_ttesz = TTE512K;
		tsb_slab_shift = MMU_PAGESHIFT512K;
		tsb_slab_size = MMU_PAGESIZE512K;
		tsb_slab_mask = MMU_PAGEOFFSET512K >> MMU_PAGESHIFT;
		use_bigtsb_arena = 0;
	}

	if (!use_bigtsb_arena) {
		bigtsb_slab_ttesz = tsb_slab_ttesz;
		bigtsb_slab_shift = tsb_slab_shift;
		bigtsb_slab_size = tsb_slab_size;
		bigtsb_slab_mask = tsb_slab_mask;
	}


	/*
	 * Set up memory callback to update tsb_alloc_hiwater and
	 * tsb_max_growsize.
	 */
	i = kphysm_setup_func_register(&sfmmu_update_vec, (void *) 0);
	ASSERT(i == 0);

	/*
	 * kmem_tsb_arena is the source from which large TSB slabs are
	 * drawn.  The quantum of this arena corresponds to the largest
	 * TSB size we can dynamically allocate for user processes.
	 * Currently it must also be a supported page size since we
	 * use exactly one translation entry to map each slab page.
	 *
	 * The per-lgroup kmem_tsb_default_arena arenas are the arenas from
	 * which most TSBs are allocated.  Since most TSB allocations are
	 * typically 8K we have a kmem cache we stack on top of each
	 * kmem_tsb_default_arena to speed up those allocations.
	 *
	 * Note the two-level scheme of arenas is required only
	 * because vmem_create doesn't allow us to specify alignment
	 * requirements.  If this ever changes the code could be
	 * simplified to use only one level of arenas.
	 *
	 * If 256M page support exists on sun4v, 256MB kmem_bigtsb_arena
	 * will be provided in addition to the 4M kmem_tsb_arena.
	 */
	if (use_bigtsb_arena) {
		kmem_bigtsb_arena = vmem_create("kmem_bigtsb", NULL, 0,
		    bigtsb_slab_size, sfmmu_vmem_xalloc_aligned_wrapper,
		    vmem_xfree, heap_arena, 0, VM_SLEEP);
	}

	kmem_tsb_arena = vmem_create("kmem_tsb", NULL, 0, tsb_slab_size,
	    sfmmu_vmem_xalloc_aligned_wrapper,
	    vmem_xfree, heap_arena, 0, VM_SLEEP);

	if (tsb_lgrp_affinity) {
		char s[50];
		for (i = 0; i < NLGRPS_MAX; i++) {
			if (use_bigtsb_arena) {
				(void) sprintf(s, "kmem_bigtsb_lgrp%d", i);
				kmem_bigtsb_default_arena[i] = vmem_create(s,
				    NULL, 0, 2 * tsb_slab_size,
				    sfmmu_tsb_segkmem_alloc,
				    sfmmu_tsb_segkmem_free, kmem_bigtsb_arena,
				    0, VM_SLEEP | VM_BESTFIT);
			}

			(void) sprintf(s, "kmem_tsb_lgrp%d", i);
			kmem_tsb_default_arena[i] = vmem_create(s,
			    NULL, 0, PAGESIZE, sfmmu_tsb_segkmem_alloc,
			    sfmmu_tsb_segkmem_free, kmem_tsb_arena, 0,
			    VM_SLEEP | VM_BESTFIT);

			(void) sprintf(s, "sfmmu_tsb_lgrp%d_cache", i);
			sfmmu_tsb_cache[i] = kmem_cache_create(s,
			    PAGESIZE, PAGESIZE, NULL, NULL, NULL, NULL,
			    kmem_tsb_default_arena[i], 0);
		}
	} else {
		if (use_bigtsb_arena) {
			kmem_bigtsb_default_arena[0] =
			    vmem_create("kmem_bigtsb_default", NULL, 0,
			    2 * tsb_slab_size, sfmmu_tsb_segkmem_alloc,
			    sfmmu_tsb_segkmem_free, kmem_bigtsb_arena, 0,
			    VM_SLEEP | VM_BESTFIT);
		}

		kmem_tsb_default_arena[0] = vmem_create("kmem_tsb_default",
		    NULL, 0, PAGESIZE, sfmmu_tsb_segkmem_alloc,
		    sfmmu_tsb_segkmem_free, kmem_tsb_arena, 0,
		    VM_SLEEP | VM_BESTFIT);
		sfmmu_tsb_cache[0] = kmem_cache_create("sfmmu_tsb_cache",
		    PAGESIZE, PAGESIZE, NULL, NULL, NULL, NULL,
		    kmem_tsb_default_arena[0], 0);
	}

	sfmmu8_cache = kmem_cache_create("sfmmu8_cache", HME8BLK_SZ,
	    HMEBLK_ALIGN, sfmmu_hblkcache_constructor,
	    sfmmu_hblkcache_destructor,
	    sfmmu_hblkcache_reclaim, (void *)HME8BLK_SZ,
	    hat_memload_arena, KMC_NOHASH);

	hat_memload1_arena = vmem_create("hat_memload1", NULL, 0, PAGESIZE,
	    segkmem_alloc_permanent, segkmem_free, heap_arena, 0,
	    VMC_DUMPSAFE | VM_SLEEP);

	sfmmu1_cache = kmem_cache_create("sfmmu1_cache", HME1BLK_SZ,
	    HMEBLK_ALIGN, sfmmu_hblkcache_constructor,
	    sfmmu_hblkcache_destructor,
	    NULL, (void *)HME1BLK_SZ,
	    hat_memload1_arena, KMC_NOHASH);

	pa_hment_cache = kmem_cache_create("pa_hment_cache", PAHME_SZ,
	    0, NULL, NULL, NULL, NULL, static_arena, KMC_NOHASH);

	ism_blk_cache = kmem_cache_create("ism_blk_cache",
	    sizeof (ism_blk_t), ecache_alignsize, NULL, NULL,
	    NULL, NULL, static_arena, KMC_NOHASH);

	ism_ment_cache = kmem_cache_create("ism_ment_cache",
	    sizeof (ism_ment_t), 0, NULL, NULL,
	    NULL, NULL, NULL, 0);

	/*
	 * We grab the first hat for the kernel,
	 */
	AS_LOCK_ENTER(&kas, RW_WRITER);
	kas.a_hat = hat_alloc(&kas);
	AS_LOCK_EXIT(&kas);

	/*
	 * Initialize hblk_reserve.
	 */
	((struct hme_blk *)hblk_reserve)->hblk_nextpa =
	    va_to_pa((caddr_t)hblk_reserve);

#ifndef UTSB_PHYS
	/*
	 * Reserve some kernel virtual address space for the locked TTEs
	 * that allow us to probe the TSB from TL>0.
	 */
	utsb_vabase = vmem_xalloc(heap_arena, tsb_slab_size, tsb_slab_size,
	    0, 0, NULL, NULL, VM_SLEEP);
	utsb4m_vabase = vmem_xalloc(heap_arena, tsb_slab_size, tsb_slab_size,
	    0, 0, NULL, NULL, VM_SLEEP);
#endif

#ifdef VAC
	/*
	 * The big page VAC handling code assumes VAC
	 * will not be bigger than the smallest big
	 * page- which is 64K.
	 */
	if (TTEPAGES(TTE64K) < CACHE_NUM_COLOR) {
		cmn_err(CE_PANIC, "VAC too big!");
	}
#endif

	uhme_hash_pa = va_to_pa(uhme_hash);
	khme_hash_pa = va_to_pa(khme_hash);

	/*
	 * Initialize relocation locks. kpr_suspendlock is held
	 * at PIL_MAX to prevent interrupts from pinning the holder
	 * of a suspended TTE which may access it leading to a
	 * deadlock condition.
	 */
	mutex_init(&kpr_mutex, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&kpr_suspendlock, NULL, MUTEX_SPIN, (void *)PIL_MAX);

	/*
	 * If Shared context support is disabled via /etc/system
	 * set shctx_on to 0 here if it was set to 1 earlier in boot
	 * sequence by cpu module initialization code.
	 */
	if (shctx_on && disable_shctx) {
		shctx_on = 0;
	}

	if (shctx_on) {
		srd_buckets = kmem_zalloc(SFMMU_MAX_SRD_BUCKETS *
		    sizeof (srd_buckets[0]), KM_SLEEP);
		for (i = 0; i < SFMMU_MAX_SRD_BUCKETS; i++) {
			mutex_init(&srd_buckets[i].srdb_lock, NULL,
			    MUTEX_DEFAULT, NULL);
		}

		srd_cache = kmem_cache_create("srd_cache", sizeof (sf_srd_t),
		    0, sfmmu_srdcache_constructor, sfmmu_srdcache_destructor,
		    NULL, NULL, NULL, 0);
		region_cache = kmem_cache_create("region_cache",
		    sizeof (sf_region_t), 0, sfmmu_rgncache_constructor,
		    sfmmu_rgncache_destructor, NULL, NULL, NULL, 0);
		scd_cache = kmem_cache_create("scd_cache", sizeof (sf_scd_t),
		    0, sfmmu_scdcache_constructor,  sfmmu_scdcache_destructor,
		    NULL, NULL, NULL, 0);
	}

	/*
	 * Pre-allocate hrm_hashtab before enabling the collection of
	 * refmod statistics.  Allocating on the fly would mean us
	 * running the risk of suffering recursive mutex enters or
	 * deadlocks.
	 */
	hrm_hashtab = kmem_zalloc(HRM_HASHSIZE * sizeof (struct hrmstat *),
	    KM_SLEEP);

	/* Allocate per-cpu pending freelist of hmeblks */
	cpu_hme_pend = kmem_zalloc((NCPU * sizeof (cpu_hme_pend_t)) + 64,
	    KM_SLEEP);
	cpu_hme_pend = (cpu_hme_pend_t *)P2ROUNDUP(
	    (uintptr_t)cpu_hme_pend, 64);

	for (i = 0; i < NCPU; i++) {
		mutex_init(&cpu_hme_pend[i].chp_mutex, NULL, MUTEX_DEFAULT,
		    NULL);
	}

	if (cpu_hme_pend_thresh == 0) {
		cpu_hme_pend_thresh = CPU_HME_PEND_THRESH;
	}
}

/*
 * Initialize locking for the hat layer, called early during boot.
 */
static void
hat_lock_init()
{
	int i;

	/*
	 * initialize the array of mutexes protecting a page's mapping
	 * list and p_nrm field.
	 */
	for (i = 0; i < MML_TABLE_SIZE; i++)
		mutex_init(&mml_table[i].pad_mutex, NULL, MUTEX_DEFAULT, NULL);

	if (kpm_enable) {
		for (i = 0; i < kpmp_table_sz; i++) {
			mutex_init(&kpmp_table[i].khl_mutex, NULL,
			    MUTEX_DEFAULT, NULL);
		}
	}

	/*
	 * Initialize array of mutex locks that protects sfmmu fields and
	 * TSB lists.
	 */
	for (i = 0; i < SFMMU_NUM_LOCK; i++)
		mutex_init(HATLOCK_MUTEXP(&hat_lock[i]), NULL, MUTEX_DEFAULT,
		    NULL);
}

#define	SFMMU_KERNEL_MAXVA \
	(kmem64_base ? (uintptr_t)kmem64_end : (SYSLIMIT))

/*
 * Allocate a hat structure.
 * Called when an address space first uses a hat.
 */
struct hat *
hat_alloc(struct as *as)
{
	sfmmu_t *sfmmup;
	int i;
	uint64_t cnum;
	extern uint_t get_color_start(struct as *);

	ASSERT(AS_WRITE_HELD(as));
	sfmmup = kmem_cache_alloc(sfmmuid_cache, KM_SLEEP);
	sfmmup->sfmmu_as = as;
	sfmmup->sfmmu_flags = 0;
	sfmmup->sfmmu_tteflags = 0;
	sfmmup->sfmmu_rtteflags = 0;
	LOCK_INIT_CLEAR(&sfmmup->sfmmu_ctx_lock);

	if (as == &kas) {
		ksfmmup = sfmmup;
		sfmmup->sfmmu_cext = 0;
		cnum = KCONTEXT;

		sfmmup->sfmmu_clrstart = 0;
		sfmmup->sfmmu_tsb = NULL;
		/*
		 * hat_kern_setup() will call sfmmu_init_ktsbinfo()
		 * to setup tsb_info for ksfmmup.
		 */
	} else {

		/*
		 * Just set to invalid ctx. When it faults, it will
		 * get a valid ctx. This would avoid the situation
		 * where we get a ctx, but it gets stolen and then
		 * we fault when we try to run and so have to get
		 * another ctx.
		 */
		sfmmup->sfmmu_cext = 0;
		cnum = INVALID_CONTEXT;

		/* initialize original physical page coloring bin */
		sfmmup->sfmmu_clrstart = get_color_start(as);
#ifdef DEBUG
		if (tsb_random_size) {
			uint32_t randval = (uint32_t)gettick() >> 4;
			int size = randval % (tsb_max_growsize + 1);

			/* chose a random tsb size for stress testing */
			(void) sfmmu_tsbinfo_alloc(&sfmmup->sfmmu_tsb, size,
			    TSB8K|TSB64K|TSB512K, 0, sfmmup);
		} else
#endif /* DEBUG */
			(void) sfmmu_tsbinfo_alloc(&sfmmup->sfmmu_tsb,
			    default_tsb_size,
			    TSB8K|TSB64K|TSB512K, 0, sfmmup);
		sfmmup->sfmmu_flags = HAT_SWAPPED | HAT_ALLCTX_INVALID;
		ASSERT(sfmmup->sfmmu_tsb != NULL);
	}

	ASSERT(max_mmu_ctxdoms > 0);
	for (i = 0; i < max_mmu_ctxdoms; i++) {
		sfmmup->sfmmu_ctxs[i].cnum = cnum;
		sfmmup->sfmmu_ctxs[i].gnum = 0;
	}

	for (i = 0; i < max_mmu_page_sizes; i++) {
		sfmmup->sfmmu_ttecnt[i] = 0;
		sfmmup->sfmmu_scdrttecnt[i] = 0;
		sfmmup->sfmmu_ismttecnt[i] = 0;
		sfmmup->sfmmu_scdismttecnt[i] = 0;
		sfmmup->sfmmu_pgsz[i] = TTE8K;
	}
	sfmmup->sfmmu_tsb0_4minflcnt = 0;
	sfmmup->sfmmu_iblk = NULL;
	sfmmup->sfmmu_ismhat = 0;
	sfmmup->sfmmu_scdhat = 0;
	sfmmup->sfmmu_ismblkpa = (uint64_t)-1;
	if (sfmmup == ksfmmup) {
		CPUSET_ALL(sfmmup->sfmmu_cpusran);
	} else {
		CPUSET_ZERO(sfmmup->sfmmu_cpusran);
	}
	sfmmup->sfmmu_free = 0;
	sfmmup->sfmmu_rmstat = 0;
	sfmmup->sfmmu_clrbin = sfmmup->sfmmu_clrstart;
	cv_init(&sfmmup->sfmmu_tsb_cv, NULL, CV_DEFAULT, NULL);
	sfmmup->sfmmu_srdp = NULL;
	SF_RGNMAP_ZERO(sfmmup->sfmmu_region_map);
	bzero(sfmmup->sfmmu_hmeregion_links, SFMMU_L1_HMERLINKS_SIZE);
	sfmmup->sfmmu_scdp = NULL;
	sfmmup->sfmmu_scd_link.next = NULL;
	sfmmup->sfmmu_scd_link.prev = NULL;
	return (sfmmup);
}

/*
 * Create per-MMU context domain kstats for a given MMU ctx.
 */
static void
sfmmu_mmu_kstat_create(mmu_ctx_t *mmu_ctxp)
{
	mmu_ctx_stat_t	stat;
	kstat_t		*mmu_kstat;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(mmu_ctxp->mmu_kstat == NULL);

	mmu_kstat = kstat_create("unix", mmu_ctxp->mmu_idx, "mmu_ctx",
	    "hat", KSTAT_TYPE_NAMED, MMU_CTX_NUM_STATS, KSTAT_FLAG_VIRTUAL);

	if (mmu_kstat == NULL) {
		cmn_err(CE_WARN, "kstat_create for MMU %d failed",
		    mmu_ctxp->mmu_idx);
	} else {
		mmu_kstat->ks_data = mmu_ctxp->mmu_kstat_data;
		for (stat = 0; stat < MMU_CTX_NUM_STATS; stat++)
			kstat_named_init(&mmu_ctxp->mmu_kstat_data[stat],
			    mmu_ctx_kstat_names[stat], KSTAT_DATA_INT64);
		mmu_ctxp->mmu_kstat = mmu_kstat;
		kstat_install(mmu_kstat);
	}
}

/*
 * plat_cpuid_to_mmu_ctx_info() is a platform interface that returns MMU
 * context domain information for a given CPU. If a platform does not
 * specify that interface, then the function below is used instead to return
 * default information. The defaults are as follows:
 *
 *	- The number of MMU context IDs supported on any CPU in the
 *	  system is 8K.
 *	- There is one MMU context domain per CPU.
 */
/*ARGSUSED*/
static void
sfmmu_cpuid_to_mmu_ctx_info(processorid_t cpuid, mmu_ctx_info_t *infop)
{
	infop->mmu_nctxs = nctxs;
	infop->mmu_idx = cpu[cpuid]->cpu_seqid;
}

/*
 * Called during CPU initialization to set the MMU context-related information
 * for a CPU.
 *
 * cpu_lock serializes accesses to mmu_ctxs and mmu_saved_gnum.
 */
void
sfmmu_cpu_init(cpu_t *cp)
{
	mmu_ctx_info_t	info;
	mmu_ctx_t	*mmu_ctxp;

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (&plat_cpuid_to_mmu_ctx_info == NULL)
		sfmmu_cpuid_to_mmu_ctx_info(cp->cpu_id, &info);
	else
		plat_cpuid_to_mmu_ctx_info(cp->cpu_id, &info);

	ASSERT(info.mmu_idx < max_mmu_ctxdoms);

	if ((mmu_ctxp = mmu_ctxs_tbl[info.mmu_idx]) == NULL) {
		/* Each mmu_ctx is cacheline aligned. */
		mmu_ctxp = kmem_cache_alloc(mmuctxdom_cache, KM_SLEEP);
		bzero(mmu_ctxp, sizeof (mmu_ctx_t));

		mutex_init(&mmu_ctxp->mmu_lock, NULL, MUTEX_SPIN,
		    (void *)ipltospl(DISP_LEVEL));
		mmu_ctxp->mmu_idx = info.mmu_idx;
		mmu_ctxp->mmu_nctxs = info.mmu_nctxs;
		/*
		 * Globally for lifetime of a system,
		 * gnum must always increase.
		 * mmu_saved_gnum is protected by the cpu_lock.
		 */
		mmu_ctxp->mmu_gnum = mmu_saved_gnum + 1;
		mmu_ctxp->mmu_cnum = NUM_LOCKED_CTXS;

		sfmmu_mmu_kstat_create(mmu_ctxp);

		mmu_ctxs_tbl[info.mmu_idx] = mmu_ctxp;
	} else {
		ASSERT(mmu_ctxp->mmu_idx == info.mmu_idx);
		ASSERT(mmu_ctxp->mmu_nctxs <= info.mmu_nctxs);
	}

	/*
	 * The mmu_lock is acquired here to prevent races with
	 * the wrap-around code.
	 */
	mutex_enter(&mmu_ctxp->mmu_lock);


	mmu_ctxp->mmu_ncpus++;
	CPUSET_ADD(mmu_ctxp->mmu_cpuset, cp->cpu_id);
	CPU_MMU_IDX(cp) = info.mmu_idx;
	CPU_MMU_CTXP(cp) = mmu_ctxp;

	mutex_exit(&mmu_ctxp->mmu_lock);
}

static void
sfmmu_ctxdom_free(mmu_ctx_t *mmu_ctxp)
{
	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(!MUTEX_HELD(&mmu_ctxp->mmu_lock));

	mutex_destroy(&mmu_ctxp->mmu_lock);

	if (mmu_ctxp->mmu_kstat)
		kstat_delete(mmu_ctxp->mmu_kstat);

	/* mmu_saved_gnum is protected by the cpu_lock. */
	if (mmu_saved_gnum < mmu_ctxp->mmu_gnum)
		mmu_saved_gnum = mmu_ctxp->mmu_gnum;

	kmem_cache_free(mmuctxdom_cache, mmu_ctxp);
}

/*
 * Called to perform MMU context-related cleanup for a CPU.
 */
void
sfmmu_cpu_cleanup(cpu_t *cp)
{
	mmu_ctx_t	*mmu_ctxp;

	ASSERT(MUTEX_HELD(&cpu_lock));

	mmu_ctxp = CPU_MMU_CTXP(cp);
	ASSERT(mmu_ctxp != NULL);

	/*
	 * The mmu_lock is acquired here to prevent races with
	 * the wrap-around code.
	 */
	mutex_enter(&mmu_ctxp->mmu_lock);

	CPU_MMU_CTXP(cp) = NULL;

	CPUSET_DEL(mmu_ctxp->mmu_cpuset, cp->cpu_id);
	if (--mmu_ctxp->mmu_ncpus == 0) {
		mmu_ctxs_tbl[mmu_ctxp->mmu_idx] = NULL;
		mutex_exit(&mmu_ctxp->mmu_lock);
		sfmmu_ctxdom_free(mmu_ctxp);
		return;
	}

	mutex_exit(&mmu_ctxp->mmu_lock);
}

uint_t
sfmmu_ctxdom_nctxs(int idx)
{
	return (mmu_ctxs_tbl[idx]->mmu_nctxs);
}

#ifdef sun4v
/*
 * sfmmu_ctxdoms_* is an interface provided to help keep context domains
 * consistant after suspend/resume on system that can resume on a different
 * hardware than it was suspended.
 *
 * sfmmu_ctxdom_lock(void) locks all context domains and prevents new contexts
 * from being allocated.  It acquires all hat_locks, which blocks most access to
 * context data, except for a few cases that are handled separately or are
 * harmless.  It wraps each domain to increment gnum and invalidate on-CPU
 * contexts, and forces cnum to its max.  As a result of this call all user
 * threads that are running on CPUs trap and try to perform wrap around but
 * can't because hat_locks are taken.  Threads that were not on CPUs but started
 * by scheduler go to sfmmu_alloc_ctx() to aquire context without checking
 * hat_lock, but fail, because cnum == nctxs, and therefore also trap and block
 * on hat_lock trying to wrap.  sfmmu_ctxdom_lock() must be called before CPUs
 * are paused, else it could deadlock acquiring locks held by paused CPUs.
 *
 * sfmmu_ctxdoms_remove() removes context domains from every CPUs and records
 * the CPUs that had them.  It must be called after CPUs have been paused. This
 * ensures that no threads are in sfmmu_alloc_ctx() accessing domain data,
 * because pause_cpus sends a mondo interrupt to every CPU, and sfmmu_alloc_ctx
 * runs with interrupts disabled.  When CPUs are later resumed, they may enter
 * sfmmu_alloc_ctx, but it will check for CPU_MMU_CTXP = NULL and immediately
 * return failure.  Or, they will be blocked trying to acquire hat_lock. Thus
 * after sfmmu_ctxdoms_remove returns, we are guaranteed that no one is
 * accessing the old context domains.
 *
 * sfmmu_ctxdoms_update(void) frees space used by old context domains and
 * allocates new context domains based on hardware layout.  It initializes
 * every CPU that had context domain before migration to have one again.
 * sfmmu_ctxdoms_update must be called after CPUs are resumed, else it
 * could deadlock acquiring locks held by paused CPUs.
 *
 * sfmmu_ctxdoms_unlock(void) releases all hat_locks after which user threads
 * acquire new context ids and continue execution.
 *
 * Therefore functions should be called in the following order:
 *       suspend_routine()
 *		sfmmu_ctxdom_lock()
 *		pause_cpus()
 *		suspend()
 *			if (suspend failed)
 *				sfmmu_ctxdom_unlock()
 *		...
 *		sfmmu_ctxdom_remove()
 *		resume_cpus()
 *		sfmmu_ctxdom_update()
 *		sfmmu_ctxdom_unlock()
 */
static cpuset_t sfmmu_ctxdoms_pset;

void
sfmmu_ctxdoms_remove()
{
	processorid_t	id;
	cpu_t		*cp;

	/*
	 * Record the CPUs that have domains in sfmmu_ctxdoms_pset, so they can
	 * be restored post-migration. A CPU may be powered off and not have a
	 * domain, for example.
	 */
	CPUSET_ZERO(sfmmu_ctxdoms_pset);

	for (id = 0; id < NCPU; id++) {
		if ((cp = cpu[id]) != NULL && CPU_MMU_CTXP(cp) != NULL) {
			CPUSET_ADD(sfmmu_ctxdoms_pset, id);
			CPU_MMU_CTXP(cp) = NULL;
		}
	}
}

void
sfmmu_ctxdoms_lock(void)
{
	int		idx;
	mmu_ctx_t	*mmu_ctxp;

	sfmmu_hat_lock_all();

	/*
	 * At this point, no thread can be in sfmmu_ctx_wrap_around, because
	 * hat_lock is always taken before calling it.
	 *
	 * For each domain, set mmu_cnum to max so no more contexts can be
	 * allocated, and wrap to flush on-CPU contexts and force threads to
	 * acquire a new context when we later drop hat_lock after migration.
	 * Setting mmu_cnum may race with sfmmu_alloc_ctx which also sets cnum,
	 * but the latter uses CAS and will miscompare and not overwrite it.
	 */
	kpreempt_disable(); /* required by sfmmu_ctx_wrap_around */
	for (idx = 0; idx < max_mmu_ctxdoms; idx++) {
		if ((mmu_ctxp = mmu_ctxs_tbl[idx]) != NULL) {
			mutex_enter(&mmu_ctxp->mmu_lock);
			mmu_ctxp->mmu_cnum = mmu_ctxp->mmu_nctxs;
			/* make sure updated cnum visible */
			membar_enter();
			mutex_exit(&mmu_ctxp->mmu_lock);
			sfmmu_ctx_wrap_around(mmu_ctxp, B_FALSE);
		}
	}
	kpreempt_enable();
}

void
sfmmu_ctxdoms_unlock(void)
{
	sfmmu_hat_unlock_all();
}

void
sfmmu_ctxdoms_update(void)
{
	processorid_t	id;
	cpu_t		*cp;
	uint_t		idx;
	mmu_ctx_t	*mmu_ctxp;

	/*
	 * Free all context domains.  As side effect, this increases
	 * mmu_saved_gnum to the maximum gnum over all domains, which is used to
	 * init gnum in the new domains, which therefore will be larger than the
	 * sfmmu gnum for any process, guaranteeing that every process will see
	 * a new generation and allocate a new context regardless of what new
	 * domain it runs in.
	 */
	mutex_enter(&cpu_lock);

	for (idx = 0; idx < max_mmu_ctxdoms; idx++) {
		if (mmu_ctxs_tbl[idx] != NULL) {
			mmu_ctxp = mmu_ctxs_tbl[idx];
			mmu_ctxs_tbl[idx] = NULL;
			sfmmu_ctxdom_free(mmu_ctxp);
		}
	}

	for (id = 0; id < NCPU; id++) {
		if (CPU_IN_SET(sfmmu_ctxdoms_pset, id) &&
		    (cp = cpu[id]) != NULL)
			sfmmu_cpu_init(cp);
	}
	mutex_exit(&cpu_lock);
}
#endif

/*
 * Hat_setup, makes an address space context the current active one.
 * In sfmmu this translates to setting the secondary context with the
 * corresponding context.
 */
void
hat_setup(struct hat *sfmmup, int allocflag)
{
	hatlock_t *hatlockp;

	/* Init needs some special treatment. */
	if (allocflag == HAT_INIT) {
		/*
		 * Make sure that we have
		 * 1. a TSB
		 * 2. a valid ctx that doesn't get stolen after this point.
		 */
		hatlockp = sfmmu_hat_enter(sfmmup);

		/*
		 * Swap in the TSB.  hat_init() allocates tsbinfos without
		 * TSBs, but we need one for init, since the kernel does some
		 * special things to set up its stack and needs the TSB to
		 * resolve page faults.
		 */
		sfmmu_tsb_swapin(sfmmup, hatlockp);

		sfmmu_get_ctx(sfmmup);

		sfmmu_hat_exit(hatlockp);
	} else {
		ASSERT(allocflag == HAT_ALLOC);

		hatlockp = sfmmu_hat_enter(sfmmup);
		kpreempt_disable();

		CPUSET_ADD(sfmmup->sfmmu_cpusran, CPU->cpu_id);
		/*
		 * sfmmu_setctx_sec takes <pgsz|cnum> as a parameter,
		 * pagesize bits don't matter in this case since we are passing
		 * INVALID_CONTEXT to it.
		 * Compatibility Note: hw takes care of MMU_SCONTEXT1
		 */
		sfmmu_setctx_sec(INVALID_CONTEXT);
		sfmmu_clear_utsbinfo();

		kpreempt_enable();
		sfmmu_hat_exit(hatlockp);
	}
}

/*
 * Free all the translation resources for the specified address space.
 * Called from as_free when an address space is being destroyed.
 */
void
hat_free_start(struct hat *sfmmup)
{
	ASSERT(AS_WRITE_HELD(sfmmup->sfmmu_as));
	ASSERT(sfmmup != ksfmmup);

	sfmmup->sfmmu_free = 1;
	if (sfmmup->sfmmu_scdp != NULL) {
		sfmmu_leave_scd(sfmmup, 0);
	}

	ASSERT(sfmmup->sfmmu_scdp == NULL);
}

void
hat_free_end(struct hat *sfmmup)
{
	int i;

	ASSERT(sfmmup->sfmmu_free == 1);
	ASSERT(sfmmup->sfmmu_ttecnt[TTE8K] == 0);
	ASSERT(sfmmup->sfmmu_ttecnt[TTE64K] == 0);
	ASSERT(sfmmup->sfmmu_ttecnt[TTE512K] == 0);
	ASSERT(sfmmup->sfmmu_ttecnt[TTE4M] == 0);
	ASSERT(sfmmup->sfmmu_ttecnt[TTE32M] == 0);
	ASSERT(sfmmup->sfmmu_ttecnt[TTE256M] == 0);

	if (sfmmup->sfmmu_rmstat) {
		hat_freestat(sfmmup->sfmmu_as, NULL);
	}

	while (sfmmup->sfmmu_tsb != NULL) {
		struct tsb_info *next = sfmmup->sfmmu_tsb->tsb_next;
		sfmmu_tsbinfo_free(sfmmup->sfmmu_tsb);
		sfmmup->sfmmu_tsb = next;
	}

	if (sfmmup->sfmmu_srdp != NULL) {
		sfmmu_leave_srd(sfmmup);
		ASSERT(sfmmup->sfmmu_srdp == NULL);
		for (i = 0; i < SFMMU_L1_HMERLINKS; i++) {
			if (sfmmup->sfmmu_hmeregion_links[i] != NULL) {
				kmem_free(sfmmup->sfmmu_hmeregion_links[i],
				    SFMMU_L2_HMERLINKS_SIZE);
				sfmmup->sfmmu_hmeregion_links[i] = NULL;
			}
		}
	}
	sfmmu_free_sfmmu(sfmmup);

#ifdef DEBUG
	for (i = 0; i < SFMMU_L1_HMERLINKS; i++) {
		ASSERT(sfmmup->sfmmu_hmeregion_links[i] == NULL);
	}
#endif

	kmem_cache_free(sfmmuid_cache, sfmmup);
}

/*
 * Set up any translation structures, for the specified address space,
 * that are needed or preferred when the process is being swapped in.
 */
/* ARGSUSED */
void
hat_swapin(struct hat *hat)
{
}

/*
 * Free all of the translation resources, for the specified address space,
 * that can be freed while the process is swapped out. Called from as_swapout.
 * Also, free up the ctx that this process was using.
 */
void
hat_swapout(struct hat *sfmmup)
{
	struct hmehash_bucket *hmebp;
	struct hme_blk *hmeblkp;
	struct hme_blk *pr_hblk = NULL;
	struct hme_blk *nx_hblk;
	int i;
	struct hme_blk *list = NULL;
	hatlock_t *hatlockp;
	struct tsb_info *tsbinfop;
	struct free_tsb {
		struct free_tsb *next;
		struct tsb_info *tsbinfop;
	};			/* free list of TSBs */
	struct free_tsb *freelist, *last, *next;

	SFMMU_STAT(sf_swapout);

	/*
	 * There is no way to go from an as to all its translations in sfmmu.
	 * Here is one of the times when we take the big hit and traverse
	 * the hash looking for hme_blks to free up.  Not only do we free up
	 * this as hme_blks but all those that are free.  We are obviously
	 * swapping because we need memory so let's free up as much
	 * as we can.
	 *
	 * Note that we don't flush TLB/TSB here -- it's not necessary
	 * because:
	 *  1) we free the ctx we're using and throw away the TSB(s);
	 *  2) processes aren't runnable while being swapped out.
	 */
	ASSERT(sfmmup != KHATID);
	for (i = 0; i <= UHMEHASH_SZ; i++) {
		hmebp = &uhme_hash[i];
		SFMMU_HASH_LOCK(hmebp);
		hmeblkp = hmebp->hmeblkp;
		pr_hblk = NULL;
		while (hmeblkp) {

			if ((hmeblkp->hblk_tag.htag_id == sfmmup) &&
			    !hmeblkp->hblk_shw_bit && !hmeblkp->hblk_lckcnt) {
				ASSERT(!hmeblkp->hblk_shared);
				(void) sfmmu_hblk_unload(sfmmup, hmeblkp,
				    (caddr_t)get_hblk_base(hmeblkp),
				    get_hblk_endaddr(hmeblkp),
				    NULL, HAT_UNLOAD);
			}
			nx_hblk = hmeblkp->hblk_next;
			if (!hmeblkp->hblk_vcnt && !hmeblkp->hblk_hmecnt) {
				ASSERT(!hmeblkp->hblk_lckcnt);
				sfmmu_hblk_hash_rm(hmebp, hmeblkp, pr_hblk,
				    &list, 0);
			} else {
				pr_hblk = hmeblkp;
			}
			hmeblkp = nx_hblk;
		}
		SFMMU_HASH_UNLOCK(hmebp);
	}

	sfmmu_hblks_list_purge(&list, 0);

	/*
	 * Now free up the ctx so that others can reuse it.
	 */
	hatlockp = sfmmu_hat_enter(sfmmup);

	sfmmu_invalidate_ctx(sfmmup);

	/*
	 * Free TSBs, but not tsbinfos, and set SWAPPED flag.
	 * If TSBs were never swapped in, just return.
	 * This implies that we don't support partial swapping
	 * of TSBs -- either all are swapped out, or none are.
	 *
	 * We must hold the HAT lock here to prevent racing with another
	 * thread trying to unmap TTEs from the TSB or running the post-
	 * relocator after relocating the TSB's memory.  Unfortunately, we
	 * can't free memory while holding the HAT lock or we could
	 * deadlock, so we build a list of TSBs to be freed after marking
	 * the tsbinfos as swapped out and free them after dropping the
	 * lock.
	 */
	if (SFMMU_FLAGS_ISSET(sfmmup, HAT_SWAPPED)) {
		sfmmu_hat_exit(hatlockp);
		return;
	}

	SFMMU_FLAGS_SET(sfmmup, HAT_SWAPPED);
	last = freelist = NULL;
	for (tsbinfop = sfmmup->sfmmu_tsb; tsbinfop != NULL;
	    tsbinfop = tsbinfop->tsb_next) {
		ASSERT((tsbinfop->tsb_flags & TSB_SWAPPED) == 0);

		/*
		 * Cast the TSB into a struct free_tsb and put it on the free
		 * list.
		 */
		if (freelist == NULL) {
			last = freelist = (struct free_tsb *)tsbinfop->tsb_va;
		} else {
			last->next = (struct free_tsb *)tsbinfop->tsb_va;
			last = last->next;
		}
		last->next = NULL;
		last->tsbinfop = tsbinfop;
		tsbinfop->tsb_flags |= TSB_SWAPPED;
		/*
		 * Zero out the TTE to clear the valid bit.
		 * Note we can't use a value like 0xbad because we want to
		 * ensure diagnostic bits are NEVER set on TTEs that might
		 * be loaded.  The intent is to catch any invalid access
		 * to the swapped TSB, such as a thread running with a valid
		 * context without first calling sfmmu_tsb_swapin() to
		 * allocate TSB memory.
		 */
		tsbinfop->tsb_tte.ll = 0;
	}

	/* Now we can drop the lock and free the TSB memory. */
	sfmmu_hat_exit(hatlockp);
	for (; freelist != NULL; freelist = next) {
		next = freelist->next;
		sfmmu_tsb_free(freelist->tsbinfop);
	}
}

/*
 * Duplicate the translations of an as into another newas
 */
/* ARGSUSED */
int
hat_dup(struct hat *hat, struct hat *newhat, caddr_t addr, size_t len,
	uint_t flag)
{
	sf_srd_t *srdp;
	sf_scd_t *scdp;
	int i;
	extern uint_t get_color_start(struct as *);

	ASSERT((flag == 0) || (flag == HAT_DUP_ALL) || (flag == HAT_DUP_COW) ||
	    (flag == HAT_DUP_SRD));
	ASSERT(hat != ksfmmup);
	ASSERT(newhat != ksfmmup);
	ASSERT(flag != HAT_DUP_ALL || hat->sfmmu_srdp == newhat->sfmmu_srdp);

	if (flag == HAT_DUP_COW) {
		panic("hat_dup: HAT_DUP_COW not supported");
	}

	if (flag == HAT_DUP_SRD && ((srdp = hat->sfmmu_srdp) != NULL)) {
		ASSERT(srdp->srd_evp != NULL);
		VN_HOLD(srdp->srd_evp);
		ASSERT(srdp->srd_refcnt > 0);
		newhat->sfmmu_srdp = srdp;
		atomic_inc_32((volatile uint_t *)&srdp->srd_refcnt);
	}

	/*
	 * HAT_DUP_ALL flag is used after as duplication is done.
	 */
	if (flag == HAT_DUP_ALL && ((srdp = newhat->sfmmu_srdp) != NULL)) {
		ASSERT(newhat->sfmmu_srdp->srd_refcnt >= 2);
		newhat->sfmmu_rtteflags = hat->sfmmu_rtteflags;
		if (hat->sfmmu_flags & HAT_4MTEXT_FLAG) {
			newhat->sfmmu_flags |= HAT_4MTEXT_FLAG;
		}

		/* check if need to join scd */
		if ((scdp = hat->sfmmu_scdp) != NULL &&
		    newhat->sfmmu_scdp != scdp) {
			int ret;
			SF_RGNMAP_IS_SUBSET(&newhat->sfmmu_region_map,
			    &scdp->scd_region_map, ret);
			ASSERT(ret);
			sfmmu_join_scd(scdp, newhat);
			ASSERT(newhat->sfmmu_scdp == scdp &&
			    scdp->scd_refcnt >= 2);
			for (i = 0; i < max_mmu_page_sizes; i++) {
				newhat->sfmmu_ismttecnt[i] =
				    hat->sfmmu_ismttecnt[i];
				newhat->sfmmu_scdismttecnt[i] =
				    hat->sfmmu_scdismttecnt[i];
			}
		}

		sfmmu_check_page_sizes(newhat, 1);
	}

	if (flag == HAT_DUP_ALL && consistent_coloring == 0 &&
	    update_proc_pgcolorbase_after_fork != 0) {
		hat->sfmmu_clrbin = get_color_start(hat->sfmmu_as);
	}
	return (0);
}

void
hat_memload(struct hat *hat, caddr_t addr, struct page *pp,
	uint_t attr, uint_t flags)
{
	hat_do_memload(hat, addr, pp, attr, flags,
	    SFMMU_INVALID_SHMERID);
}

void
hat_memload_region(struct hat *hat, caddr_t addr, struct page *pp,
	uint_t attr, uint_t flags, hat_region_cookie_t rcookie)
{
	uint_t rid;
	if (rcookie == HAT_INVALID_REGION_COOKIE) {
		hat_do_memload(hat, addr, pp, attr, flags,
		    SFMMU_INVALID_SHMERID);
		return;
	}
	rid = (uint_t)((uint64_t)rcookie);
	ASSERT(rid < SFMMU_MAX_HME_REGIONS);
	hat_do_memload(hat, addr, pp, attr, flags, rid);
}

/*
 * Set up addr to map to page pp with protection prot.
 * As an optimization we also load the TSB with the
 * corresponding tte but it is no big deal if  the tte gets kicked out.
 */
static void
hat_do_memload(struct hat *hat, caddr_t addr, struct page *pp,
	uint_t attr, uint_t flags, uint_t rid)
{
	tte_t tte;


	ASSERT(hat != NULL);
	ASSERT(PAGE_LOCKED(pp));
	ASSERT(!((uintptr_t)addr & MMU_PAGEOFFSET));
	ASSERT(!(flags & ~SFMMU_LOAD_ALLFLAG));
	ASSERT(!(attr & ~SFMMU_LOAD_ALLATTR));
	SFMMU_VALIDATE_HMERID(hat, rid, addr, MMU_PAGESIZE);

	if (PP_ISFREE(pp)) {
		panic("hat_memload: loading a mapping to free page %p",
		    (void *)pp);
	}

	ASSERT((hat == ksfmmup) || AS_LOCK_HELD(hat->sfmmu_as));

	if (flags & ~SFMMU_LOAD_ALLFLAG)
		cmn_err(CE_NOTE, "hat_memload: unsupported flags %d",
		    flags & ~SFMMU_LOAD_ALLFLAG);

	if (hat->sfmmu_rmstat)
		hat_resvstat(MMU_PAGESIZE, hat->sfmmu_as, addr);

#if defined(SF_ERRATA_57)
	if ((hat != ksfmmup) && AS_TYPE_64BIT(hat->sfmmu_as) &&
	    (addr < errata57_limit) && (attr & PROT_EXEC) &&
	    !(flags & HAT_LOAD_SHARE)) {
		cmn_err(CE_WARN, "hat_memload: illegal attempt to make user "
		    " page executable");
		attr &= ~PROT_EXEC;
	}
#endif

	sfmmu_memtte(&tte, pp->p_pagenum, attr, TTE8K);
	(void) sfmmu_tteload_array(hat, &tte, addr, &pp, flags, rid);

	/*
	 * Check TSB and TLB page sizes.
	 */
	if ((flags & HAT_LOAD_SHARE) == 0) {
		sfmmu_check_page_sizes(hat, 1);
	}
}

/*
 * hat_devload can be called to map real memory (e.g.
 * /dev/kmem) and even though hat_devload will determine pf is
 * for memory, it will be unable to get a shared lock on the
 * page (because someone else has it exclusively) and will
 * pass dp = NULL.  If tteload doesn't get a non-NULL
 * page pointer it can't cache memory.
 */
void
hat_devload(struct hat *hat, caddr_t addr, size_t len, pfn_t pfn,
	uint_t attr, int flags)
{
	tte_t tte;
	struct page *pp = NULL;
	int use_lgpg = 0;

	ASSERT(hat != NULL);

	ASSERT(!(flags & ~SFMMU_LOAD_ALLFLAG));
	ASSERT(!(attr & ~SFMMU_LOAD_ALLATTR));
	ASSERT((hat == ksfmmup) || AS_LOCK_HELD(hat->sfmmu_as));
	if (len == 0)
		panic("hat_devload: zero len");
	if (flags & ~SFMMU_LOAD_ALLFLAG)
		cmn_err(CE_NOTE, "hat_devload: unsupported flags %d",
		    flags & ~SFMMU_LOAD_ALLFLAG);

#if defined(SF_ERRATA_57)
	if ((hat != ksfmmup) && AS_TYPE_64BIT(hat->sfmmu_as) &&
	    (addr < errata57_limit) && (attr & PROT_EXEC) &&
	    !(flags & HAT_LOAD_SHARE)) {
		cmn_err(CE_WARN, "hat_devload: illegal attempt to make user "
		    " page executable");
		attr &= ~PROT_EXEC;
	}
#endif

	/*
	 * If it's a memory page find its pp
	 */
	if (!(flags & HAT_LOAD_NOCONSIST) && pf_is_memory(pfn)) {
		pp = page_numtopp_nolock(pfn);
		if (pp == NULL) {
			flags |= HAT_LOAD_NOCONSIST;
		} else {
			if (PP_ISFREE(pp)) {
				panic("hat_memload: loading "
				    "a mapping to free page %p",
				    (void *)pp);
			}
			if (!PAGE_LOCKED(pp) && !PP_ISNORELOC(pp)) {
				panic("hat_memload: loading a mapping "
				    "to unlocked relocatable page %p",
				    (void *)pp);
			}
			ASSERT(len == MMU_PAGESIZE);
		}
	}

	if (hat->sfmmu_rmstat)
		hat_resvstat(len, hat->sfmmu_as, addr);

	if (flags & HAT_LOAD_NOCONSIST) {
		attr |= SFMMU_UNCACHEVTTE;
		use_lgpg = 1;
	}
	if (!pf_is_memory(pfn)) {
		attr |= SFMMU_UNCACHEPTTE | HAT_NOSYNC;
		use_lgpg = 1;
		switch (attr & HAT_ORDER_MASK) {
			case HAT_STRICTORDER:
			case HAT_UNORDERED_OK:
				/*
				 * we set the side effect bit for all non
				 * memory mappings unless merging is ok
				 */
				attr |= SFMMU_SIDEFFECT;
				break;
			case HAT_MERGING_OK:
			case HAT_LOADCACHING_OK:
			case HAT_STORECACHING_OK:
				break;
			default:
				panic("hat_devload: bad attr");
				break;
		}
	}
	while (len) {
		if (!use_lgpg) {
			sfmmu_memtte(&tte, pfn, attr, TTE8K);
			(void) sfmmu_tteload_array(hat, &tte, addr, &pp,
			    flags, SFMMU_INVALID_SHMERID);
			len -= MMU_PAGESIZE;
			addr += MMU_PAGESIZE;
			pfn++;
			continue;
		}
		/*
		 *  try to use large pages, check va/pa alignments
		 *  Note that 32M/256M page sizes are not (yet) supported.
		 */
		if ((len >= MMU_PAGESIZE4M) &&
		    !((uintptr_t)addr & MMU_PAGEOFFSET4M) &&
		    !(disable_large_pages & (1 << TTE4M)) &&
		    !(mmu_ptob(pfn) & MMU_PAGEOFFSET4M)) {
			sfmmu_memtte(&tte, pfn, attr, TTE4M);
			(void) sfmmu_tteload_array(hat, &tte, addr, &pp,
			    flags, SFMMU_INVALID_SHMERID);
			len -= MMU_PAGESIZE4M;
			addr += MMU_PAGESIZE4M;
			pfn += MMU_PAGESIZE4M / MMU_PAGESIZE;
		} else if ((len >= MMU_PAGESIZE512K) &&
		    !((uintptr_t)addr & MMU_PAGEOFFSET512K) &&
		    !(disable_large_pages & (1 << TTE512K)) &&
		    !(mmu_ptob(pfn) & MMU_PAGEOFFSET512K)) {
			sfmmu_memtte(&tte, pfn, attr, TTE512K);
			(void) sfmmu_tteload_array(hat, &tte, addr, &pp,
			    flags, SFMMU_INVALID_SHMERID);
			len -= MMU_PAGESIZE512K;
			addr += MMU_PAGESIZE512K;
			pfn += MMU_PAGESIZE512K / MMU_PAGESIZE;
		} else if ((len >= MMU_PAGESIZE64K) &&
		    !((uintptr_t)addr & MMU_PAGEOFFSET64K) &&
		    !(disable_large_pages & (1 << TTE64K)) &&
		    !(mmu_ptob(pfn) & MMU_PAGEOFFSET64K)) {
			sfmmu_memtte(&tte, pfn, attr, TTE64K);
			(void) sfmmu_tteload_array(hat, &tte, addr, &pp,
			    flags, SFMMU_INVALID_SHMERID);
			len -= MMU_PAGESIZE64K;
			addr += MMU_PAGESIZE64K;
			pfn += MMU_PAGESIZE64K / MMU_PAGESIZE;
		} else {
			sfmmu_memtte(&tte, pfn, attr, TTE8K);
			(void) sfmmu_tteload_array(hat, &tte, addr, &pp,
			    flags, SFMMU_INVALID_SHMERID);
			len -= MMU_PAGESIZE;
			addr += MMU_PAGESIZE;
			pfn++;
		}
	}

	/*
	 * Check TSB and TLB page sizes.
	 */
	if ((flags & HAT_LOAD_SHARE) == 0) {
		sfmmu_check_page_sizes(hat, 1);
	}
}

void
hat_memload_array(struct hat *hat, caddr_t addr, size_t len,
	struct page **pps, uint_t attr, uint_t flags)
{
	hat_do_memload_array(hat, addr, len, pps, attr, flags,
	    SFMMU_INVALID_SHMERID);
}

void
hat_memload_array_region(struct hat *hat, caddr_t addr, size_t len,
	struct page **pps, uint_t attr, uint_t flags,
	hat_region_cookie_t rcookie)
{
	uint_t rid;
	if (rcookie == HAT_INVALID_REGION_COOKIE) {
		hat_do_memload_array(hat, addr, len, pps, attr, flags,
		    SFMMU_INVALID_SHMERID);
		return;
	}
	rid = (uint_t)((uint64_t)rcookie);
	ASSERT(rid < SFMMU_MAX_HME_REGIONS);
	hat_do_memload_array(hat, addr, len, pps, attr, flags, rid);
}

/*
 * Map the largest extend possible out of the page array. The array may NOT
 * be in order.  The largest possible mapping a page can have
 * is specified in the p_szc field.  The p_szc field
 * cannot change as long as there any mappings (large or small)
 * to any of the pages that make up the large page. (ie. any
 * promotion/demotion of page size is not up to the hat but up to
 * the page free list manager).  The array
 * should consist of properly aligned contigous pages that are
 * part of a big page for a large mapping to be created.
 */
static void
hat_do_memload_array(struct hat *hat, caddr_t addr, size_t len,
	struct page **pps, uint_t attr, uint_t flags, uint_t rid)
{
	int  ttesz;
	size_t mapsz;
	pgcnt_t	numpg, npgs;
	tte_t tte;
	page_t *pp;
	uint_t large_pages_disable;

	ASSERT(!((uintptr_t)addr & MMU_PAGEOFFSET));
	SFMMU_VALIDATE_HMERID(hat, rid, addr, len);

	if (hat->sfmmu_rmstat)
		hat_resvstat(len, hat->sfmmu_as, addr);

#if defined(SF_ERRATA_57)
	if ((hat != ksfmmup) && AS_TYPE_64BIT(hat->sfmmu_as) &&
	    (addr < errata57_limit) && (attr & PROT_EXEC) &&
	    !(flags & HAT_LOAD_SHARE)) {
		cmn_err(CE_WARN, "hat_memload_array: illegal attempt to make "
		    "user page executable");
		attr &= ~PROT_EXEC;
	}
#endif

	/* Get number of pages */
	npgs = len >> MMU_PAGESHIFT;

	if (flags & HAT_LOAD_SHARE) {
		large_pages_disable = disable_ism_large_pages;
	} else {
		large_pages_disable = disable_large_pages;
	}

	if (npgs < NHMENTS || large_pages_disable == LARGE_PAGES_OFF) {
		sfmmu_memload_batchsmall(hat, addr, pps, attr, flags, npgs,
		    rid);
		return;
	}

	while (npgs >= NHMENTS) {
		pp = *pps;
		for (ttesz = pp->p_szc; ttesz != TTE8K; ttesz--) {
			/*
			 * Check if this page size is disabled.
			 */
			if (large_pages_disable & (1 << ttesz))
				continue;

			numpg = TTEPAGES(ttesz);
			mapsz = numpg << MMU_PAGESHIFT;
			if ((npgs >= numpg) &&
			    IS_P2ALIGNED(addr, mapsz) &&
			    IS_P2ALIGNED(pp->p_pagenum, numpg)) {
				/*
				 * At this point we have enough pages and
				 * we know the virtual address and the pfn
				 * are properly aligned.  We still need
				 * to check for physical contiguity but since
				 * it is very likely that this is the case
				 * we will assume they are so and undo
				 * the request if necessary.  It would
				 * be great if we could get a hint flag
				 * like HAT_CONTIG which would tell us
				 * the pages are contigous for sure.
				 */
				sfmmu_memtte(&tte, (*pps)->p_pagenum,
				    attr, ttesz);
				if (!sfmmu_tteload_array(hat, &tte, addr,
				    pps, flags, rid)) {
					break;
				}
			}
		}
		if (ttesz == TTE8K) {
			/*
			 * We were not able to map array using a large page
			 * batch a hmeblk or fraction at a time.
			 */
			numpg = ((uintptr_t)addr >> MMU_PAGESHIFT)
			    & (NHMENTS-1);
			numpg = NHMENTS - numpg;
			ASSERT(numpg <= npgs);
			mapsz = numpg * MMU_PAGESIZE;
			sfmmu_memload_batchsmall(hat, addr, pps, attr, flags,
			    numpg, rid);
		}
		addr += mapsz;
		npgs -= numpg;
		pps += numpg;
	}

	if (npgs) {
		sfmmu_memload_batchsmall(hat, addr, pps, attr, flags, npgs,
		    rid);
	}

	/*
	 * Check TSB and TLB page sizes.
	 */
	if ((flags & HAT_LOAD_SHARE) == 0) {
		sfmmu_check_page_sizes(hat, 1);
	}
}

/*
 * Function tries to batch 8K pages into the same hme blk.
 */
static void
sfmmu_memload_batchsmall(struct hat *hat, caddr_t vaddr, page_t **pps,
		    uint_t attr, uint_t flags, pgcnt_t npgs, uint_t rid)
{
	tte_t	tte;
	page_t *pp;
	struct hmehash_bucket *hmebp;
	struct hme_blk *hmeblkp;
	int	index;

	while (npgs) {
		/*
		 * Acquire the hash bucket.
		 */
		hmebp = sfmmu_tteload_acquire_hashbucket(hat, vaddr, TTE8K,
		    rid);
		ASSERT(hmebp);

		/*
		 * Find the hment block.
		 */
		hmeblkp = sfmmu_tteload_find_hmeblk(hat, hmebp, vaddr,
		    TTE8K, flags, rid);
		ASSERT(hmeblkp);

		do {
			/*
			 * Make the tte.
			 */
			pp = *pps;
			sfmmu_memtte(&tte, pp->p_pagenum, attr, TTE8K);

			/*
			 * Add the translation.
			 */
			(void) sfmmu_tteload_addentry(hat, hmeblkp, &tte,
			    vaddr, pps, flags, rid);

			/*
			 * Goto next page.
			 */
			pps++;
			npgs--;

			/*
			 * Goto next address.
			 */
			vaddr += MMU_PAGESIZE;

			/*
			 * Don't crossover into a different hmentblk.
			 */
			index = (int)(((uintptr_t)vaddr >> MMU_PAGESHIFT) &
			    (NHMENTS-1));

		} while (index != 0 && npgs != 0);

		/*
		 * Release the hash bucket.
		 */

		sfmmu_tteload_release_hashbucket(hmebp);
	}
}

/*
 * Construct a tte for a page:
 *
 * tte_valid = 1
 * tte_size2 = size & TTE_SZ2_BITS (Panther and Olympus-C only)
 * tte_size = size
 * tte_nfo = attr & HAT_NOFAULT
 * tte_ie = attr & HAT_STRUCTURE_LE
 * tte_hmenum = hmenum
 * tte_pahi = pp->p_pagenum >> TTE_PASHIFT;
 * tte_palo = pp->p_pagenum & TTE_PALOMASK;
 * tte_ref = 1 (optimization)
 * tte_wr_perm = attr & PROT_WRITE;
 * tte_no_sync = attr & HAT_NOSYNC
 * tte_lock = attr & SFMMU_LOCKTTE
 * tte_cp = !(attr & SFMMU_UNCACHEPTTE)
 * tte_cv = !(attr & SFMMU_UNCACHEVTTE)
 * tte_e = attr & SFMMU_SIDEFFECT
 * tte_priv = !(attr & PROT_USER)
 * tte_hwwr = if nosync is set and it is writable we set the mod bit (opt)
 * tte_glb = 0
 */
void
sfmmu_memtte(tte_t *ttep, pfn_t pfn, uint_t attr, int tte_sz)
{
	ASSERT(!(attr & ~SFMMU_LOAD_ALLATTR));

	ttep->tte_inthi = MAKE_TTE_INTHI(pfn, attr, tte_sz, 0 /* hmenum */);
	ttep->tte_intlo = MAKE_TTE_INTLO(pfn, attr, tte_sz, 0 /* hmenum */);

	if (TTE_IS_NOSYNC(ttep)) {
		TTE_SET_REF(ttep);
		if (TTE_IS_WRITABLE(ttep)) {
			TTE_SET_MOD(ttep);
		}
	}
	if (TTE_IS_NFO(ttep) && TTE_IS_EXECUTABLE(ttep)) {
		panic("sfmmu_memtte: can't set both NFO and EXEC bits");
	}
}

/*
 * This function will add a translation to the hme_blk and allocate the
 * hme_blk if one does not exist.
 * If a page structure is specified then it will add the
 * corresponding hment to the mapping list.
 * It will also update the hmenum field for the tte.
 *
 * Currently this function is only used for kernel mappings.
 * So pass invalid region to sfmmu_tteload_array().
 */
void
sfmmu_tteload(struct hat *sfmmup, tte_t *ttep, caddr_t vaddr, page_t *pp,
	uint_t flags)
{
	ASSERT(sfmmup == ksfmmup);
	(void) sfmmu_tteload_array(sfmmup, ttep, vaddr, &pp, flags,
	    SFMMU_INVALID_SHMERID);
}

/*
 * Load (ttep != NULL) or unload (ttep == NULL) one entry in the TSB.
 * Assumes that a particular page size may only be resident in one TSB.
 */
static void
sfmmu_mod_tsb(sfmmu_t *sfmmup, caddr_t vaddr, tte_t *ttep, int ttesz)
{
	struct tsb_info *tsbinfop = NULL;
	uint64_t tag;
	struct tsbe *tsbe_addr;
	uint64_t tsb_base;
	uint_t tsb_size;
	int vpshift = MMU_PAGESHIFT;
	int phys = 0;

	if (sfmmup == ksfmmup) { /* No support for 32/256M ksfmmu pages */
		phys = ktsb_phys;
		if (ttesz >= TTE4M) {
#ifndef sun4v
			ASSERT((ttesz != TTE32M) && (ttesz != TTE256M));
#endif
			tsb_base = (phys)? ktsb4m_pbase : (uint64_t)ktsb4m_base;
			tsb_size = ktsb4m_szcode;
		} else {
			tsb_base = (phys)? ktsb_pbase : (uint64_t)ktsb_base;
			tsb_size = ktsb_szcode;
		}
	} else {
		SFMMU_GET_TSBINFO(tsbinfop, sfmmup, ttesz);

		/*
		 * If there isn't a TSB for this page size, or the TSB is
		 * swapped out, there is nothing to do.  Note that the latter
		 * case seems impossible but can occur if hat_pageunload()
		 * is called on an ISM mapping while the process is swapped
		 * out.
		 */
		if (tsbinfop == NULL || (tsbinfop->tsb_flags & TSB_SWAPPED))
			return;

		/*
		 * If another thread is in the middle of relocating a TSB
		 * we can't unload the entry so set a flag so that the
		 * TSB will be flushed before it can be accessed by the
		 * process.
		 */
		if ((tsbinfop->tsb_flags & TSB_RELOC_FLAG) != 0) {
			if (ttep == NULL)
				tsbinfop->tsb_flags |= TSB_FLUSH_NEEDED;
			return;
		}
#if defined(UTSB_PHYS)
		phys = 1;
		tsb_base = (uint64_t)tsbinfop->tsb_pa;
#else
		tsb_base = (uint64_t)tsbinfop->tsb_va;
#endif
		tsb_size = tsbinfop->tsb_szc;
	}
	if (ttesz >= TTE4M)
		vpshift = MMU_PAGESHIFT4M;

	tsbe_addr = sfmmu_get_tsbe(tsb_base, vaddr, vpshift, tsb_size);
	tag = sfmmu_make_tsbtag(vaddr);

	if (ttep == NULL) {
		sfmmu_unload_tsbe(tsbe_addr, tag, phys);
	} else {
		if (ttesz >= TTE4M) {
			SFMMU_STAT(sf_tsb_load4m);
		} else {
			SFMMU_STAT(sf_tsb_load8k);
		}

		sfmmu_load_tsbe(tsbe_addr, tag, ttep, phys);
	}
}

/*
 * Unmap all entries from [start, end) matching the given page size.
 *
 * This function is used primarily to unmap replicated 64K or 512K entries
 * from the TSB that are inserted using the base page size TSB pointer, but
 * it may also be called to unmap a range of addresses from the TSB.
 */
void
sfmmu_unload_tsb_range(sfmmu_t *sfmmup, caddr_t start, caddr_t end, int ttesz)
{
	struct tsb_info *tsbinfop;
	uint64_t tag;
	struct tsbe *tsbe_addr;
	caddr_t vaddr;
	uint64_t tsb_base;
	int vpshift, vpgsz;
	uint_t tsb_size;
	int phys = 0;

	/*
	 * Assumptions:
	 *  If ttesz == 8K, 64K or 512K, we walk through the range 8K
	 *  at a time shooting down any valid entries we encounter.
	 *
	 *  If ttesz >= 4M we walk the range 4M at a time shooting
	 *  down any valid mappings we find.
	 */
	if (sfmmup == ksfmmup) {
		phys = ktsb_phys;
		if (ttesz >= TTE4M) {
#ifndef sun4v
			ASSERT((ttesz != TTE32M) && (ttesz != TTE256M));
#endif
			tsb_base = (phys)? ktsb4m_pbase : (uint64_t)ktsb4m_base;
			tsb_size = ktsb4m_szcode;
		} else {
			tsb_base = (phys)? ktsb_pbase : (uint64_t)ktsb_base;
			tsb_size = ktsb_szcode;
		}
	} else {
		SFMMU_GET_TSBINFO(tsbinfop, sfmmup, ttesz);

		/*
		 * If there isn't a TSB for this page size, or the TSB is
		 * swapped out, there is nothing to do.  Note that the latter
		 * case seems impossible but can occur if hat_pageunload()
		 * is called on an ISM mapping while the process is swapped
		 * out.
		 */
		if (tsbinfop == NULL || (tsbinfop->tsb_flags & TSB_SWAPPED))
			return;

		/*
		 * If another thread is in the middle of relocating a TSB
		 * we can't unload the entry so set a flag so that the
		 * TSB will be flushed before it can be accessed by the
		 * process.
		 */
		if ((tsbinfop->tsb_flags & TSB_RELOC_FLAG) != 0) {
			tsbinfop->tsb_flags |= TSB_FLUSH_NEEDED;
			return;
		}
#if defined(UTSB_PHYS)
		phys = 1;
		tsb_base = (uint64_t)tsbinfop->tsb_pa;
#else
		tsb_base = (uint64_t)tsbinfop->tsb_va;
#endif
		tsb_size = tsbinfop->tsb_szc;
	}
	if (ttesz >= TTE4M) {
		vpshift = MMU_PAGESHIFT4M;
		vpgsz = MMU_PAGESIZE4M;
	} else {
		vpshift = MMU_PAGESHIFT;
		vpgsz = MMU_PAGESIZE;
	}

	for (vaddr = start; vaddr < end; vaddr += vpgsz) {
		tag = sfmmu_make_tsbtag(vaddr);
		tsbe_addr = sfmmu_get_tsbe(tsb_base, vaddr, vpshift, tsb_size);
		sfmmu_unload_tsbe(tsbe_addr, tag, phys);
	}
}

/*
 * Select the optimum TSB size given the number of mappings
 * that need to be cached.
 */
static int
sfmmu_select_tsb_szc(pgcnt_t pgcnt)
{
	int szc = 0;

#ifdef DEBUG
	if (tsb_grow_stress) {
		uint32_t randval = (uint32_t)gettick() >> 4;
		return (randval % (tsb_max_growsize + 1));
	}
#endif	/* DEBUG */

	while ((szc < tsb_max_growsize) && (pgcnt > SFMMU_RSS_TSBSIZE(szc)))
		szc++;
	return (szc);
}

/*
 * This function will add a translation to the hme_blk and allocate the
 * hme_blk if one does not exist.
 * If a page structure is specified then it will add the
 * corresponding hment to the mapping list.
 * It will also update the hmenum field for the tte.
 * Furthermore, it attempts to create a large page translation
 * for <addr,hat> at page array pps.  It assumes addr and first
 * pp is correctly aligned.  It returns 0 if successful and 1 otherwise.
 */
static int
sfmmu_tteload_array(sfmmu_t *sfmmup, tte_t *ttep, caddr_t vaddr,
	page_t **pps, uint_t flags, uint_t rid)
{
	struct hmehash_bucket *hmebp;
	struct hme_blk *hmeblkp;
	int 	ret;
	uint_t	size;

	/*
	 * Get mapping size.
	 */
	size = TTE_CSZ(ttep);
	ASSERT(!((uintptr_t)vaddr & TTE_PAGE_OFFSET(size)));

	/*
	 * Acquire the hash bucket.
	 */
	hmebp = sfmmu_tteload_acquire_hashbucket(sfmmup, vaddr, size, rid);
	ASSERT(hmebp);

	/*
	 * Find the hment block.
	 */
	hmeblkp = sfmmu_tteload_find_hmeblk(sfmmup, hmebp, vaddr, size, flags,
	    rid);
	ASSERT(hmeblkp);

	/*
	 * Add the translation.
	 */
	ret = sfmmu_tteload_addentry(sfmmup, hmeblkp, ttep, vaddr, pps, flags,
	    rid);

	/*
	 * Release the hash bucket.
	 */
	sfmmu_tteload_release_hashbucket(hmebp);

	return (ret);
}

/*
 * Function locks and returns a pointer to the hash bucket for vaddr and size.
 */
static struct hmehash_bucket *
sfmmu_tteload_acquire_hashbucket(sfmmu_t *sfmmup, caddr_t vaddr, int size,
    uint_t rid)
{
	struct hmehash_bucket *hmebp;
	int hmeshift;
	void *htagid = sfmmutohtagid(sfmmup, rid);

	ASSERT(htagid != NULL);

	hmeshift = HME_HASH_SHIFT(size);

	hmebp = HME_HASH_FUNCTION(htagid, vaddr, hmeshift);

	SFMMU_HASH_LOCK(hmebp);

	return (hmebp);
}

/*
 * Function returns a pointer to an hmeblk in the hash bucket, hmebp. If the
 * hmeblk doesn't exists for the [sfmmup, vaddr & size] signature, a hmeblk is
 * allocated.
 */
static struct hme_blk *
sfmmu_tteload_find_hmeblk(sfmmu_t *sfmmup, struct hmehash_bucket *hmebp,
	caddr_t vaddr, uint_t size, uint_t flags, uint_t rid)
{
	hmeblk_tag hblktag;
	int hmeshift;
	struct hme_blk *hmeblkp, *pr_hblk, *list = NULL;

	SFMMU_VALIDATE_HMERID(sfmmup, rid, vaddr, TTEBYTES(size));

	hblktag.htag_id = sfmmutohtagid(sfmmup, rid);
	ASSERT(hblktag.htag_id != NULL);
	hmeshift = HME_HASH_SHIFT(size);
	hblktag.htag_bspage = HME_HASH_BSPAGE(vaddr, hmeshift);
	hblktag.htag_rehash = HME_HASH_REHASH(size);
	hblktag.htag_rid = rid;

ttearray_realloc:

	HME_HASH_SEARCH_PREV(hmebp, hblktag, hmeblkp, pr_hblk, &list);

	/*
	 * We block until hblk_reserve_lock is released; it's held by
	 * the thread, temporarily using hblk_reserve, until hblk_reserve is
	 * replaced by a hblk from sfmmu8_cache.
	 */
	if (hmeblkp == (struct hme_blk *)hblk_reserve &&
	    hblk_reserve_thread != curthread) {
		SFMMU_HASH_UNLOCK(hmebp);
		mutex_enter(&hblk_reserve_lock);
		mutex_exit(&hblk_reserve_lock);
		SFMMU_STAT(sf_hblk_reserve_hit);
		SFMMU_HASH_LOCK(hmebp);
		goto ttearray_realloc;
	}

	if (hmeblkp == NULL) {
		hmeblkp = sfmmu_hblk_alloc(sfmmup, vaddr, hmebp, size,
		    hblktag, flags, rid);
		ASSERT(!SFMMU_IS_SHMERID_VALID(rid) || hmeblkp->hblk_shared);
		ASSERT(SFMMU_IS_SHMERID_VALID(rid) || !hmeblkp->hblk_shared);
	} else {
		/*
		 * It is possible for 8k and 64k hblks to collide since they
		 * have the same rehash value. This is because we
		 * lazily free hblks and 8K/64K blks could be lingering.
		 * If we find size mismatch we free the block and & try again.
		 */
		if (get_hblk_ttesz(hmeblkp) != size) {
			ASSERT(!hmeblkp->hblk_vcnt);
			ASSERT(!hmeblkp->hblk_hmecnt);
			sfmmu_hblk_hash_rm(hmebp, hmeblkp, pr_hblk,
			    &list, 0);
			goto ttearray_realloc;
		}
		if (hmeblkp->hblk_shw_bit) {
			/*
			 * if the hblk was previously used as a shadow hblk then
			 * we will change it to a normal hblk
			 */
			ASSERT(!hmeblkp->hblk_shared);
			if (hmeblkp->hblk_shw_mask) {
				sfmmu_shadow_hcleanup(sfmmup, hmeblkp, hmebp);
				ASSERT(SFMMU_HASH_LOCK_ISHELD(hmebp));
				goto ttearray_realloc;
			} else {
				hmeblkp->hblk_shw_bit = 0;
			}
		}
		SFMMU_STAT(sf_hblk_hit);
	}

	/*
	 * hat_memload() should never call kmem_cache_free() for kernel hmeblks;
	 * see block comment showing the stacktrace in sfmmu_hblk_alloc();
	 * set the flag parameter to 1 so that sfmmu_hblks_list_purge() will
	 * just add these hmeblks to the per-cpu pending queue.
	 */
	sfmmu_hblks_list_purge(&list, 1);

	ASSERT(get_hblk_ttesz(hmeblkp) == size);
	ASSERT(!hmeblkp->hblk_shw_bit);
	ASSERT(!SFMMU_IS_SHMERID_VALID(rid) || hmeblkp->hblk_shared);
	ASSERT(SFMMU_IS_SHMERID_VALID(rid) || !hmeblkp->hblk_shared);
	ASSERT(hmeblkp->hblk_tag.htag_rid == rid);

	return (hmeblkp);
}

/*
 * Function adds a tte entry into the hmeblk. It returns 0 if successful and 1
 * otherwise.
 */
static int
sfmmu_tteload_addentry(sfmmu_t *sfmmup, struct hme_blk *hmeblkp, tte_t *ttep,
	caddr_t vaddr, page_t **pps, uint_t flags, uint_t rid)
{
	page_t *pp = *pps;
	int hmenum, size, remap;
	tte_t tteold, flush_tte;
#ifdef DEBUG
	tte_t orig_old;
#endif /* DEBUG */
	struct sf_hment *sfhme;
	kmutex_t *pml, *pmtx;
	hatlock_t *hatlockp;
	int myflt;

	/*
	 * remove this panic when we decide to let user virtual address
	 * space be >= USERLIMIT.
	 */
	if (!TTE_IS_PRIVILEGED(ttep) && vaddr >= (caddr_t)USERLIMIT)
		panic("user addr %p in kernel space", (void *)vaddr);
#if defined(TTE_IS_GLOBAL)
	if (TTE_IS_GLOBAL(ttep))
		panic("sfmmu_tteload: creating global tte");
#endif

#ifdef DEBUG
	if (pf_is_memory(sfmmu_ttetopfn(ttep, vaddr)) &&
	    !TTE_IS_PCACHEABLE(ttep) && !sfmmu_allow_nc_trans)
		panic("sfmmu_tteload: non cacheable memory tte");
#endif /* DEBUG */

	/* don't simulate dirty bit for writeable ISM/DISM mappings */
	if ((flags & HAT_LOAD_SHARE) && TTE_IS_WRITABLE(ttep)) {
		TTE_SET_REF(ttep);
		TTE_SET_MOD(ttep);
	}

	if ((flags & HAT_LOAD_SHARE) || !TTE_IS_REF(ttep) ||
	    !TTE_IS_MOD(ttep)) {
		/*
		 * Don't load TSB for dummy as in ISM.  Also don't preload
		 * the TSB if the TTE isn't writable since we're likely to
		 * fault on it again -- preloading can be fairly expensive.
		 */
		flags |= SFMMU_NO_TSBLOAD;
	}

	size = TTE_CSZ(ttep);
	switch (size) {
	case TTE8K:
		SFMMU_STAT(sf_tteload8k);
		break;
	case TTE64K:
		SFMMU_STAT(sf_tteload64k);
		break;
	case TTE512K:
		SFMMU_STAT(sf_tteload512k);
		break;
	case TTE4M:
		SFMMU_STAT(sf_tteload4m);
		break;
	case (TTE32M):
		SFMMU_STAT(sf_tteload32m);
		ASSERT(mmu_page_sizes == max_mmu_page_sizes);
		break;
	case (TTE256M):
		SFMMU_STAT(sf_tteload256m);
		ASSERT(mmu_page_sizes == max_mmu_page_sizes);
		break;
	}

	ASSERT(!((uintptr_t)vaddr & TTE_PAGE_OFFSET(size)));
	SFMMU_VALIDATE_HMERID(sfmmup, rid, vaddr, TTEBYTES(size));
	ASSERT(!SFMMU_IS_SHMERID_VALID(rid) || hmeblkp->hblk_shared);
	ASSERT(SFMMU_IS_SHMERID_VALID(rid) || !hmeblkp->hblk_shared);

	HBLKTOHME_IDX(sfhme, hmeblkp, vaddr, hmenum);

	/*
	 * Need to grab mlist lock here so that pageunload
	 * will not change tte behind us.
	 */
	if (pp) {
		pml = sfmmu_mlist_enter(pp);
	}

	sfmmu_copytte(&sfhme->hme_tte, &tteold);
	/*
	 * Look for corresponding hment and if valid verify
	 * pfns are equal.
	 */
	remap = TTE_IS_VALID(&tteold);
	if (remap) {
		pfn_t	new_pfn, old_pfn;

		old_pfn = TTE_TO_PFN(vaddr, &tteold);
		new_pfn = TTE_TO_PFN(vaddr, ttep);

		if (flags & HAT_LOAD_REMAP) {
			/* make sure we are remapping same type of pages */
			if (pf_is_memory(old_pfn) != pf_is_memory(new_pfn)) {
				panic("sfmmu_tteload - tte remap io<->memory");
			}
			if (old_pfn != new_pfn &&
			    (pp != NULL || sfhme->hme_page != NULL)) {
				panic("sfmmu_tteload - tte remap pp != NULL");
			}
		} else if (old_pfn != new_pfn) {
			panic("sfmmu_tteload - tte remap, hmeblkp 0x%p",
			    (void *)hmeblkp);
		}
		ASSERT(TTE_CSZ(&tteold) == TTE_CSZ(ttep));
	}

	if (pp) {
		if (size == TTE8K) {
#ifdef VAC
			/*
			 * Handle VAC consistency
			 */
			if (!remap && (cache & CACHE_VAC) && !PP_ISNC(pp)) {
				sfmmu_vac_conflict(sfmmup, vaddr, pp);
			}
#endif

			if (TTE_IS_WRITABLE(ttep) && PP_ISRO(pp)) {
				pmtx = sfmmu_page_enter(pp);
				PP_CLRRO(pp);
				sfmmu_page_exit(pmtx);
			} else if (!PP_ISMAPPED(pp) &&
			    (!TTE_IS_WRITABLE(ttep)) && !(PP_ISMOD(pp))) {
				pmtx = sfmmu_page_enter(pp);
				if (!(PP_ISMOD(pp))) {
					PP_SETRO(pp);
				}
				sfmmu_page_exit(pmtx);
			}

		} else if (sfmmu_pagearray_setup(vaddr, pps, ttep, remap)) {
			/*
			 * sfmmu_pagearray_setup failed so return
			 */
			sfmmu_mlist_exit(pml);
			return (1);
		}
	}

	/*
	 * Make sure hment is not on a mapping list.
	 */
	ASSERT(remap || (sfhme->hme_page == NULL));

	/* if it is not a remap then hme->next better be NULL */
	ASSERT((!remap) ? sfhme->hme_next == NULL : 1);

	if (flags & HAT_LOAD_LOCK) {
		if ((hmeblkp->hblk_lckcnt + 1) >= MAX_HBLK_LCKCNT) {
			panic("too high lckcnt-hmeblk %p",
			    (void *)hmeblkp);
		}
		atomic_inc_32(&hmeblkp->hblk_lckcnt);

		HBLK_STACK_TRACE(hmeblkp, HBLK_LOCK);
	}

#ifdef VAC
	if (pp && PP_ISNC(pp)) {
		/*
		 * If the physical page is marked to be uncacheable, like
		 * by a vac conflict, make sure the new mapping is also
		 * uncacheable.
		 */
		TTE_CLR_VCACHEABLE(ttep);
		ASSERT(PP_GET_VCOLOR(pp) == NO_VCOLOR);
	}
#endif
	ttep->tte_hmenum = hmenum;

#ifdef DEBUG
	orig_old = tteold;
#endif /* DEBUG */

	while (sfmmu_modifytte_try(&tteold, ttep, &sfhme->hme_tte) < 0) {
		if ((sfmmup == KHATID) &&
		    (flags & (HAT_LOAD_LOCK | HAT_LOAD_REMAP))) {
			sfmmu_copytte(&sfhme->hme_tte, &tteold);
		}
#ifdef DEBUG
		chk_tte(&orig_old, &tteold, ttep, hmeblkp);
#endif /* DEBUG */
	}
	ASSERT(TTE_IS_VALID(&sfhme->hme_tte));

	if (!TTE_IS_VALID(&tteold)) {

		atomic_inc_16(&hmeblkp->hblk_vcnt);
		if (rid == SFMMU_INVALID_SHMERID) {
			atomic_inc_ulong(&sfmmup->sfmmu_ttecnt[size]);
		} else {
			sf_srd_t *srdp = sfmmup->sfmmu_srdp;
			sf_region_t *rgnp = srdp->srd_hmergnp[rid];
			/*
			 * We already accounted for region ttecnt's in sfmmu
			 * during hat_join_region() processing. Here we
			 * only update ttecnt's in region struture.
			 */
			atomic_inc_ulong(&rgnp->rgn_ttecnt[size]);
		}
	}

	myflt = (astosfmmu(curthread->t_procp->p_as) == sfmmup);
	if (size > TTE8K && (flags & HAT_LOAD_SHARE) == 0 &&
	    sfmmup != ksfmmup) {
		uchar_t tteflag = 1 << size;
		if (rid == SFMMU_INVALID_SHMERID) {
			if (!(sfmmup->sfmmu_tteflags & tteflag)) {
				hatlockp = sfmmu_hat_enter(sfmmup);
				sfmmup->sfmmu_tteflags |= tteflag;
				sfmmu_hat_exit(hatlockp);
			}
		} else if (!(sfmmup->sfmmu_rtteflags & tteflag)) {
			hatlockp = sfmmu_hat_enter(sfmmup);
			sfmmup->sfmmu_rtteflags |= tteflag;
			sfmmu_hat_exit(hatlockp);
		}
		/*
		 * Update the current CPU tsbmiss area, so the current thread
		 * won't need to take the tsbmiss for the new pagesize.
		 * The other threads in the process will update their tsb
		 * miss area lazily in sfmmu_tsbmiss_exception() when they
		 * fail to find the translation for a newly added pagesize.
		 */
		if (size > TTE64K && myflt) {
			struct tsbmiss *tsbmp;
			kpreempt_disable();
			tsbmp = &tsbmiss_area[CPU->cpu_id];
			if (rid == SFMMU_INVALID_SHMERID) {
				if (!(tsbmp->uhat_tteflags & tteflag)) {
					tsbmp->uhat_tteflags |= tteflag;
				}
			} else {
				if (!(tsbmp->uhat_rtteflags & tteflag)) {
					tsbmp->uhat_rtteflags |= tteflag;
				}
			}
			kpreempt_enable();
		}
	}

	if (size >= TTE4M && (flags & HAT_LOAD_TEXT) &&
	    !SFMMU_FLAGS_ISSET(sfmmup, HAT_4MTEXT_FLAG)) {
		hatlockp = sfmmu_hat_enter(sfmmup);
		SFMMU_FLAGS_SET(sfmmup, HAT_4MTEXT_FLAG);
		sfmmu_hat_exit(hatlockp);
	}

	flush_tte.tte_intlo = (tteold.tte_intlo ^ ttep->tte_intlo) &
	    hw_tte.tte_intlo;
	flush_tte.tte_inthi = (tteold.tte_inthi ^ ttep->tte_inthi) &
	    hw_tte.tte_inthi;

	if (remap && (flush_tte.tte_inthi || flush_tte.tte_intlo)) {
		/*
		 * If remap and new tte differs from old tte we need
		 * to sync the mod bit and flush TLB/TSB.  We don't
		 * need to sync ref bit because we currently always set
		 * ref bit in tteload.
		 */
		ASSERT(TTE_IS_REF(ttep));
		if (TTE_IS_MOD(&tteold)) {
			sfmmu_ttesync(sfmmup, vaddr, &tteold, pp);
		}
		/*
		 * hwtte bits shouldn't change for SRD hmeblks as long as SRD
		 * hmes are only used for read only text. Adding this code for
		 * completeness and future use of shared hmeblks with writable
		 * mappings of VMODSORT vnodes.
		 */
		if (hmeblkp->hblk_shared) {
			cpuset_t cpuset = sfmmu_rgntlb_demap(vaddr,
			    sfmmup->sfmmu_srdp->srd_hmergnp[rid], hmeblkp, 1);
			xt_sync(cpuset);
			SFMMU_STAT_ADD(sf_region_remap_demap, 1);
		} else {
			sfmmu_tlb_demap(vaddr, sfmmup, hmeblkp, 0, 0);
			xt_sync(sfmmup->sfmmu_cpusran);
		}
	}

	if ((flags & SFMMU_NO_TSBLOAD) == 0) {
		/*
		 * We only preload 8K and 4M mappings into the TSB, since
		 * 64K and 512K mappings are replicated and hence don't
		 * have a single, unique TSB entry. Ditto for 32M/256M.
		 */
		if (size == TTE8K || size == TTE4M) {
			sf_scd_t *scdp;
			hatlockp = sfmmu_hat_enter(sfmmup);
			/*
			 * Don't preload private TSB if the mapping is used
			 * by the shctx in the SCD.
			 */
			scdp = sfmmup->sfmmu_scdp;
			if (rid == SFMMU_INVALID_SHMERID || scdp == NULL ||
			    !SF_RGNMAP_TEST(scdp->scd_hmeregion_map, rid)) {
				sfmmu_load_tsb(sfmmup, vaddr, &sfhme->hme_tte,
				    size);
			}
			sfmmu_hat_exit(hatlockp);
		}
	}
	if (pp) {
		if (!remap) {
			HME_ADD(sfhme, pp);
			atomic_inc_16(&hmeblkp->hblk_hmecnt);
			ASSERT(hmeblkp->hblk_hmecnt > 0);

			/*
			 * Cannot ASSERT(hmeblkp->hblk_hmecnt <= NHMENTS)
			 * see pageunload() for comment.
			 */
		}
		sfmmu_mlist_exit(pml);
	}

	return (0);
}
/*
 * Function unlocks hash bucket.
 */
static void
sfmmu_tteload_release_hashbucket(struct hmehash_bucket *hmebp)
{
	ASSERT(SFMMU_HASH_LOCK_ISHELD(hmebp));
	SFMMU_HASH_UNLOCK(hmebp);
}

/*
 * function which checks and sets up page array for a large
 * translation.  Will set p_vcolor, p_index, p_ro fields.
 * Assumes addr and pfnum of first page are properly aligned.
 * Will check for physical contiguity. If check fails it return
 * non null.
 */
static int
sfmmu_pagearray_setup(caddr_t addr, page_t **pps, tte_t *ttep, int remap)
{
	int 	i, index, ttesz;
	pfn_t	pfnum;
	pgcnt_t	npgs;
	page_t *pp, *pp1;
	kmutex_t *pmtx;
#ifdef VAC
	int osz;
	int cflags = 0;
	int vac_err = 0;
#endif
	int newidx = 0;

	ttesz = TTE_CSZ(ttep);

	ASSERT(ttesz > TTE8K);

	npgs = TTEPAGES(ttesz);
	index = PAGESZ_TO_INDEX(ttesz);

	pfnum = (*pps)->p_pagenum;
	ASSERT(IS_P2ALIGNED(pfnum, npgs));

	/*
	 * Save the first pp so we can do HAT_TMPNC at the end.
	 */
	pp1 = *pps;
#ifdef VAC
	osz = fnd_mapping_sz(pp1);
#endif

	for (i = 0; i < npgs; i++, pps++) {
		pp = *pps;
		ASSERT(PAGE_LOCKED(pp));
		ASSERT(pp->p_szc >= ttesz);
		ASSERT(pp->p_szc == pp1->p_szc);
		ASSERT(sfmmu_mlist_held(pp));

		/*
		 * XXX is it possible to maintain P_RO on the root only?
		 */
		if (TTE_IS_WRITABLE(ttep) && PP_ISRO(pp)) {
			pmtx = sfmmu_page_enter(pp);
			PP_CLRRO(pp);
			sfmmu_page_exit(pmtx);
		} else if (!PP_ISMAPPED(pp) && !TTE_IS_WRITABLE(ttep) &&
		    !PP_ISMOD(pp)) {
			pmtx = sfmmu_page_enter(pp);
			if (!(PP_ISMOD(pp))) {
				PP_SETRO(pp);
			}
			sfmmu_page_exit(pmtx);
		}

		/*
		 * If this is a remap we skip vac & contiguity checks.
		 */
		if (remap)
			continue;

		/*
		 * set p_vcolor and detect any vac conflicts.
		 */
#ifdef VAC
		if (vac_err == 0) {
			vac_err = sfmmu_vacconflict_array(addr, pp, &cflags);

		}
#endif

		/*
		 * Save current index in case we need to undo it.
		 * Note: "PAGESZ_TO_INDEX(sz)	(1 << (sz))"
		 *	"SFMMU_INDEX_SHIFT	6"
		 *	 "SFMMU_INDEX_MASK	((1 << SFMMU_INDEX_SHIFT) - 1)"
		 *	 "PP_MAPINDEX(p_index)	(p_index & SFMMU_INDEX_MASK)"
		 *
		 * So:	index = PAGESZ_TO_INDEX(ttesz);
		 *	if ttesz == 1 then index = 0x2
		 *		    2 then index = 0x4
		 *		    3 then index = 0x8
		 *		    4 then index = 0x10
		 *		    5 then index = 0x20
		 * The code below checks if it's a new pagesize (ie, newidx)
		 * in case we need to take it back out of p_index,
		 * and then or's the new index into the existing index.
		 */
		if ((PP_MAPINDEX(pp) & index) == 0)
			newidx = 1;
		pp->p_index = (PP_MAPINDEX(pp) | index);

		/*
		 * contiguity check
		 */
		if (pp->p_pagenum != pfnum) {
			/*
			 * If we fail the contiguity test then
			 * the only thing we need to fix is the p_index field.
			 * We might get a few extra flushes but since this
			 * path is rare that is ok.  The p_ro field will
			 * get automatically fixed on the next tteload to
			 * the page.  NO TNC bit is set yet.
			 */
			while (i >= 0) {
				pp = *pps;
				if (newidx)
					pp->p_index = (PP_MAPINDEX(pp) &
					    ~index);
				pps--;
				i--;
			}
			return (1);
		}
		pfnum++;
		addr += MMU_PAGESIZE;
	}

#ifdef VAC
	if (vac_err) {
		if (ttesz > osz) {
			/*
			 * There are some smaller mappings that causes vac
			 * conflicts. Convert all existing small mappings to
			 * TNC.
			 */
			SFMMU_STAT_ADD(sf_uncache_conflict, npgs);
			sfmmu_page_cache_array(pp1, HAT_TMPNC, CACHE_FLUSH,
			    npgs);
		} else {
			/* EMPTY */
			/*
			 * If there exists an big page mapping,
			 * that means the whole existing big page
			 * has TNC setting already. No need to covert to
			 * TNC again.
			 */
			ASSERT(PP_ISTNC(pp1));
		}
	}
#endif	/* VAC */

	return (0);
}

#ifdef VAC
/*
 * Routine that detects vac consistency for a large page. It also
 * sets virtual color for all pp's for this big mapping.
 */
static int
sfmmu_vacconflict_array(caddr_t addr, page_t *pp, int *cflags)
{
	int vcolor, ocolor;

	ASSERT(sfmmu_mlist_held(pp));

	if (PP_ISNC(pp)) {
		return (HAT_TMPNC);
	}

	vcolor = addr_to_vcolor(addr);
	if (PP_NEWPAGE(pp)) {
		PP_SET_VCOLOR(pp, vcolor);
		return (0);
	}

	ocolor = PP_GET_VCOLOR(pp);
	if (ocolor == vcolor) {
		return (0);
	}

	if (!PP_ISMAPPED(pp) && !PP_ISMAPPED_KPM(pp)) {
		/*
		 * Previous user of page had a differnet color
		 * but since there are no current users
		 * we just flush the cache and change the color.
		 * As an optimization for large pages we flush the
		 * entire cache of that color and set a flag.
		 */
		SFMMU_STAT(sf_pgcolor_conflict);
		if (!CacheColor_IsFlushed(*cflags, ocolor)) {
			CacheColor_SetFlushed(*cflags, ocolor);
			sfmmu_cache_flushcolor(ocolor, pp->p_pagenum);
		}
		PP_SET_VCOLOR(pp, vcolor);
		return (0);
	}

	/*
	 * We got a real conflict with a current mapping.
	 * set flags to start unencaching all mappings
	 * and return failure so we restart looping
	 * the pp array from the beginning.
	 */
	return (HAT_TMPNC);
}
#endif	/* VAC */

/*
 * creates a large page shadow hmeblk for a tte.
 * The purpose of this routine is to allow us to do quick unloads because
 * the vm layer can easily pass a very large but sparsely populated range.
 */
static struct hme_blk *
sfmmu_shadow_hcreate(sfmmu_t *sfmmup, caddr_t vaddr, int ttesz, uint_t flags)
{
	struct hmehash_bucket *hmebp;
	hmeblk_tag hblktag;
	int hmeshift, size, vshift;
	uint_t shw_mask, newshw_mask;
	struct hme_blk *hmeblkp;

	ASSERT(sfmmup != KHATID);
	if (mmu_page_sizes == max_mmu_page_sizes) {
		ASSERT(ttesz < TTE256M);
	} else {
		ASSERT(ttesz < TTE4M);
		ASSERT(sfmmup->sfmmu_ttecnt[TTE32M] == 0);
		ASSERT(sfmmup->sfmmu_ttecnt[TTE256M] == 0);
	}

	if (ttesz == TTE8K) {
		size = TTE512K;
	} else {
		size = ++ttesz;
	}

	hblktag.htag_id = sfmmup;
	hmeshift = HME_HASH_SHIFT(size);
	hblktag.htag_bspage = HME_HASH_BSPAGE(vaddr, hmeshift);
	hblktag.htag_rehash = HME_HASH_REHASH(size);
	hblktag.htag_rid = SFMMU_INVALID_SHMERID;
	hmebp = HME_HASH_FUNCTION(sfmmup, vaddr, hmeshift);

	SFMMU_HASH_LOCK(hmebp);

	HME_HASH_FAST_SEARCH(hmebp, hblktag, hmeblkp);
	ASSERT(hmeblkp != (struct hme_blk *)hblk_reserve);
	if (hmeblkp == NULL) {
		hmeblkp = sfmmu_hblk_alloc(sfmmup, vaddr, hmebp, size,
		    hblktag, flags, SFMMU_INVALID_SHMERID);
	}
	ASSERT(hmeblkp);
	if (!hmeblkp->hblk_shw_mask) {
		/*
		 * if this is a unused hblk it was just allocated or could
		 * potentially be a previous large page hblk so we need to
		 * set the shadow bit.
		 */
		ASSERT(!hmeblkp->hblk_vcnt && !hmeblkp->hblk_hmecnt);
		hmeblkp->hblk_shw_bit = 1;
	} else if (hmeblkp->hblk_shw_bit == 0) {
		panic("sfmmu_shadow_hcreate: shw bit not set in hmeblkp 0x%p",
		    (void *)hmeblkp);
	}
	ASSERT(hmeblkp->hblk_shw_bit == 1);
	ASSERT(!hmeblkp->hblk_shared);
	vshift = vaddr_to_vshift(hblktag, vaddr, size);
	ASSERT(vshift < 8);
	/*
	 * Atomically set shw mask bit
	 */
	do {
		shw_mask = hmeblkp->hblk_shw_mask;
		newshw_mask = shw_mask | (1 << vshift);
		newshw_mask = atomic_cas_32(&hmeblkp->hblk_shw_mask, shw_mask,
		    newshw_mask);
	} while (newshw_mask != shw_mask);

	SFMMU_HASH_UNLOCK(hmebp);

	return (hmeblkp);
}

/*
 * This routine cleanup a previous shadow hmeblk and changes it to
 * a regular hblk.  This happens rarely but it is possible
 * when a process wants to use large pages and there are hblks still
 * lying around from the previous as that used these hmeblks.
 * The alternative was to cleanup the shadow hblks at unload time
 * but since so few user processes actually use large pages, it is
 * better to be lazy and cleanup at this time.
 */
static void
sfmmu_shadow_hcleanup(sfmmu_t *sfmmup, struct hme_blk *hmeblkp,
	struct hmehash_bucket *hmebp)
{
	caddr_t addr, endaddr;
	int hashno, size;

	ASSERT(hmeblkp->hblk_shw_bit);
	ASSERT(!hmeblkp->hblk_shared);

	ASSERT(SFMMU_HASH_LOCK_ISHELD(hmebp));

	if (!hmeblkp->hblk_shw_mask) {
		hmeblkp->hblk_shw_bit = 0;
		return;
	}
	addr = (caddr_t)get_hblk_base(hmeblkp);
	endaddr = get_hblk_endaddr(hmeblkp);
	size = get_hblk_ttesz(hmeblkp);
	hashno = size - 1;
	ASSERT(hashno > 0);
	SFMMU_HASH_UNLOCK(hmebp);

	sfmmu_free_hblks(sfmmup, addr, endaddr, hashno);

	SFMMU_HASH_LOCK(hmebp);
}

static void
sfmmu_free_hblks(sfmmu_t *sfmmup, caddr_t addr, caddr_t endaddr,
	int hashno)
{
	int hmeshift, shadow = 0;
	hmeblk_tag hblktag;
	struct hmehash_bucket *hmebp;
	struct hme_blk *hmeblkp;
	struct hme_blk *nx_hblk, *pr_hblk, *list = NULL;

	ASSERT(hashno > 0);
	hblktag.htag_id = sfmmup;
	hblktag.htag_rehash = hashno;
	hblktag.htag_rid = SFMMU_INVALID_SHMERID;

	hmeshift = HME_HASH_SHIFT(hashno);

	while (addr < endaddr) {
		hblktag.htag_bspage = HME_HASH_BSPAGE(addr, hmeshift);
		hmebp = HME_HASH_FUNCTION(sfmmup, addr, hmeshift);
		SFMMU_HASH_LOCK(hmebp);
		/* inline HME_HASH_SEARCH */
		hmeblkp = hmebp->hmeblkp;
		pr_hblk = NULL;
		while (hmeblkp) {
			if (HTAGS_EQ(hmeblkp->hblk_tag, hblktag)) {
				/* found hme_blk */
				ASSERT(!hmeblkp->hblk_shared);
				if (hmeblkp->hblk_shw_bit) {
					if (hmeblkp->hblk_shw_mask) {
						shadow = 1;
						sfmmu_shadow_hcleanup(sfmmup,
						    hmeblkp, hmebp);
						break;
					} else {
						hmeblkp->hblk_shw_bit = 0;
					}
				}

				/*
				 * Hblk_hmecnt and hblk_vcnt could be non zero
				 * since hblk_unload() does not gurantee that.
				 *
				 * XXX - this could cause tteload() to spin
				 * where sfmmu_shadow_hcleanup() is called.
				 */
			}

			nx_hblk = hmeblkp->hblk_next;
			if (!hmeblkp->hblk_vcnt && !hmeblkp->hblk_hmecnt) {
				sfmmu_hblk_hash_rm(hmebp, hmeblkp, pr_hblk,
				    &list, 0);
			} else {
				pr_hblk = hmeblkp;
			}
			hmeblkp = nx_hblk;
		}

		SFMMU_HASH_UNLOCK(hmebp);

		if (shadow) {
			/*
			 * We found another shadow hblk so cleaned its
			 * children.  We need to go back and cleanup
			 * the original hblk so we don't change the
			 * addr.
			 */
			shadow = 0;
		} else {
			addr = (caddr_t)roundup((uintptr_t)addr + 1,
			    (1 << hmeshift));
		}
	}
	sfmmu_hblks_list_purge(&list, 0);
}

/*
 * This routine's job is to delete stale invalid shared hmeregions hmeblks that
 * may still linger on after pageunload.
 */
static void
sfmmu_cleanup_rhblk(sf_srd_t *srdp, caddr_t addr, uint_t rid, int ttesz)
{
	int hmeshift;
	hmeblk_tag hblktag;
	struct hmehash_bucket *hmebp;
	struct hme_blk *hmeblkp;
	struct hme_blk *pr_hblk;
	struct hme_blk *list = NULL;

	ASSERT(SFMMU_IS_SHMERID_VALID(rid));
	ASSERT(rid < SFMMU_MAX_HME_REGIONS);

	hmeshift = HME_HASH_SHIFT(ttesz);
	hblktag.htag_bspage = HME_HASH_BSPAGE(addr, hmeshift);
	hblktag.htag_rehash = ttesz;
	hblktag.htag_rid = rid;
	hblktag.htag_id = srdp;
	hmebp = HME_HASH_FUNCTION(srdp, addr, hmeshift);

	SFMMU_HASH_LOCK(hmebp);
	HME_HASH_SEARCH_PREV(hmebp, hblktag, hmeblkp, pr_hblk, &list);
	if (hmeblkp != NULL) {
		ASSERT(hmeblkp->hblk_shared);
		ASSERT(!hmeblkp->hblk_shw_bit);
		if (hmeblkp->hblk_vcnt || hmeblkp->hblk_hmecnt) {
			panic("sfmmu_cleanup_rhblk: valid hmeblk");
		}
		ASSERT(!hmeblkp->hblk_lckcnt);
		sfmmu_hblk_hash_rm(hmebp, hmeblkp, pr_hblk,
		    &list, 0);
	}
	SFMMU_HASH_UNLOCK(hmebp);
	sfmmu_hblks_list_purge(&list, 0);
}

/* ARGSUSED */
static void
sfmmu_rgn_cb_noop(caddr_t saddr, caddr_t eaddr, caddr_t r_saddr,
    size_t r_size, void *r_obj, u_offset_t r_objoff)
{
}

/*
 * Searches for an hmeblk which maps addr, then unloads this mapping
 * and updates *eaddrp, if the hmeblk is found.
 */
static void
sfmmu_unload_hmeregion_va(sf_srd_t *srdp, uint_t rid, caddr_t addr,
    caddr_t eaddr, int ttesz, caddr_t *eaddrp)
{
	int hmeshift;
	hmeblk_tag hblktag;
	struct hmehash_bucket *hmebp;
	struct hme_blk *hmeblkp;
	struct hme_blk *pr_hblk;
	struct hme_blk *list = NULL;

	ASSERT(SFMMU_IS_SHMERID_VALID(rid));
	ASSERT(rid < SFMMU_MAX_HME_REGIONS);
	ASSERT(ttesz >= HBLK_MIN_TTESZ);

	hmeshift = HME_HASH_SHIFT(ttesz);
	hblktag.htag_bspage = HME_HASH_BSPAGE(addr, hmeshift);
	hblktag.htag_rehash = ttesz;
	hblktag.htag_rid = rid;
	hblktag.htag_id = srdp;
	hmebp = HME_HASH_FUNCTION(srdp, addr, hmeshift);

	SFMMU_HASH_LOCK(hmebp);
	HME_HASH_SEARCH_PREV(hmebp, hblktag, hmeblkp, pr_hblk, &list);
	if (hmeblkp != NULL) {
		ASSERT(hmeblkp->hblk_shared);
		ASSERT(!hmeblkp->hblk_lckcnt);
		if (hmeblkp->hblk_vcnt || hmeblkp->hblk_hmecnt) {
			*eaddrp = sfmmu_hblk_unload(NULL, hmeblkp, addr,
			    eaddr, NULL, HAT_UNLOAD);
			ASSERT(*eaddrp > addr);
		}
		ASSERT(!hmeblkp->hblk_vcnt && !hmeblkp->hblk_hmecnt);
		sfmmu_hblk_hash_rm(hmebp, hmeblkp, pr_hblk,
		    &list, 0);
	}
	SFMMU_HASH_UNLOCK(hmebp);
	sfmmu_hblks_list_purge(&list, 0);
}

static void
sfmmu_unload_hmeregion(sf_srd_t *srdp, sf_region_t *rgnp)
{
	int ttesz = rgnp->rgn_pgszc;
	size_t rsz = rgnp->rgn_size;
	caddr_t rsaddr = rgnp->rgn_saddr;
	caddr_t readdr = rsaddr + rsz;
	caddr_t rhsaddr;
	caddr_t va;
	uint_t rid = rgnp->rgn_id;
	caddr_t cbsaddr;
	caddr_t cbeaddr;
	hat_rgn_cb_func_t rcbfunc;
	ulong_t cnt;

	ASSERT(SFMMU_IS_SHMERID_VALID(rid));
	ASSERT(rid < SFMMU_MAX_HME_REGIONS);

	ASSERT(IS_P2ALIGNED(rsaddr, TTEBYTES(ttesz)));
	ASSERT(IS_P2ALIGNED(rsz, TTEBYTES(ttesz)));
	if (ttesz < HBLK_MIN_TTESZ) {
		ttesz = HBLK_MIN_TTESZ;
		rhsaddr = (caddr_t)P2ALIGN((uintptr_t)rsaddr, HBLK_MIN_BYTES);
	} else {
		rhsaddr = rsaddr;
	}

	if ((rcbfunc = rgnp->rgn_cb_function) == NULL) {
		rcbfunc = sfmmu_rgn_cb_noop;
	}

	while (ttesz >= HBLK_MIN_TTESZ) {
		cbsaddr = rsaddr;
		cbeaddr = rsaddr;
		if (!(rgnp->rgn_hmeflags & (1 << ttesz))) {
			ttesz--;
			continue;
		}
		cnt = 0;
		va = rsaddr;
		while (va < readdr) {
			ASSERT(va >= rhsaddr);
			if (va != cbeaddr) {
				if (cbeaddr != cbsaddr) {
					ASSERT(cbeaddr > cbsaddr);
					(*rcbfunc)(cbsaddr, cbeaddr,
					    rsaddr, rsz, rgnp->rgn_obj,
					    rgnp->rgn_objoff);
				}
				cbsaddr = va;
				cbeaddr = va;
			}
			sfmmu_unload_hmeregion_va(srdp, rid, va, readdr,
			    ttesz, &cbeaddr);
			cnt++;
			va = rhsaddr + (cnt << TTE_PAGE_SHIFT(ttesz));
		}
		if (cbeaddr != cbsaddr) {
			ASSERT(cbeaddr > cbsaddr);
			(*rcbfunc)(cbsaddr, cbeaddr, rsaddr,
			    rsz, rgnp->rgn_obj,
			    rgnp->rgn_objoff);
		}
		ttesz--;
	}
}

/*
 * Release one hardware address translation lock on the given address range.
 */
void
hat_unlock(struct hat *sfmmup, caddr_t addr, size_t len)
{
	struct hmehash_bucket *hmebp;
	hmeblk_tag hblktag;
	int hmeshift, hashno = 1;
	struct hme_blk *hmeblkp, *list = NULL;
	caddr_t endaddr;

	ASSERT(sfmmup != NULL);

	ASSERT((sfmmup == ksfmmup) || AS_LOCK_HELD(sfmmup->sfmmu_as));
	ASSERT((len & MMU_PAGEOFFSET) == 0);
	endaddr = addr + len;
	hblktag.htag_id = sfmmup;
	hblktag.htag_rid = SFMMU_INVALID_SHMERID;

	/*
	 * Spitfire supports 4 page sizes.
	 * Most pages are expected to be of the smallest page size (8K) and
	 * these will not need to be rehashed. 64K pages also don't need to be
	 * rehashed because an hmeblk spans 64K of address space. 512K pages
	 * might need 1 rehash and and 4M pages might need 2 rehashes.
	 */
	while (addr < endaddr) {
		hmeshift = HME_HASH_SHIFT(hashno);
		hblktag.htag_bspage = HME_HASH_BSPAGE(addr, hmeshift);
		hblktag.htag_rehash = hashno;
		hmebp = HME_HASH_FUNCTION(sfmmup, addr, hmeshift);

		SFMMU_HASH_LOCK(hmebp);

		HME_HASH_SEARCH(hmebp, hblktag, hmeblkp, &list);
		if (hmeblkp != NULL) {
			ASSERT(!hmeblkp->hblk_shared);
			/*
			 * If we encounter a shadow hmeblk then
			 * we know there are no valid hmeblks mapping
			 * this address at this size or larger.
			 * Just increment address by the smallest
			 * page size.
			 */
			if (hmeblkp->hblk_shw_bit) {
				addr += MMU_PAGESIZE;
			} else {
				addr = sfmmu_hblk_unlock(hmeblkp, addr,
				    endaddr);
			}
			SFMMU_HASH_UNLOCK(hmebp);
			hashno = 1;
			continue;
		}
		SFMMU_HASH_UNLOCK(hmebp);

		if (!HME_REHASH(sfmmup) || (hashno >= mmu_hashcnt)) {
			/*
			 * We have traversed the whole list and rehashed
			 * if necessary without finding the address to unlock
			 * which should never happen.
			 */
			panic("sfmmu_unlock: addr not found. "
			    "addr %p hat %p", (void *)addr, (void *)sfmmup);
		} else {
			hashno++;
		}
	}

	sfmmu_hblks_list_purge(&list, 0);
}

void
hat_unlock_region(struct hat *sfmmup, caddr_t addr, size_t len,
    hat_region_cookie_t rcookie)
{
	sf_srd_t *srdp;
	sf_region_t *rgnp;
	int ttesz;
	uint_t rid;
	caddr_t eaddr;
	caddr_t va;
	int hmeshift;
	hmeblk_tag hblktag;
	struct hmehash_bucket *hmebp;
	struct hme_blk *hmeblkp;
	struct hme_blk *pr_hblk;
	struct hme_blk *list;

	if (rcookie == HAT_INVALID_REGION_COOKIE) {
		hat_unlock(sfmmup, addr, len);
		return;
	}

	ASSERT(sfmmup != NULL);
	ASSERT(sfmmup != ksfmmup);

	srdp = sfmmup->sfmmu_srdp;
	rid = (uint_t)((uint64_t)rcookie);
	VERIFY3U(rid, <, SFMMU_MAX_HME_REGIONS);
	eaddr = addr + len;
	va = addr;
	list = NULL;
	rgnp = srdp->srd_hmergnp[rid];
	SFMMU_VALIDATE_HMERID(sfmmup, rid, addr, len);

	ASSERT(IS_P2ALIGNED(addr, TTEBYTES(rgnp->rgn_pgszc)));
	ASSERT(IS_P2ALIGNED(len, TTEBYTES(rgnp->rgn_pgszc)));
	if (rgnp->rgn_pgszc < HBLK_MIN_TTESZ) {
		ttesz = HBLK_MIN_TTESZ;
	} else {
		ttesz = rgnp->rgn_pgszc;
	}
	while (va < eaddr) {
		while (ttesz < rgnp->rgn_pgszc &&
		    IS_P2ALIGNED(va, TTEBYTES(ttesz + 1))) {
			ttesz++;
		}
		while (ttesz >= HBLK_MIN_TTESZ) {
			if (!(rgnp->rgn_hmeflags & (1 << ttesz))) {
				ttesz--;
				continue;
			}
			hmeshift = HME_HASH_SHIFT(ttesz);
			hblktag.htag_bspage = HME_HASH_BSPAGE(va, hmeshift);
			hblktag.htag_rehash = ttesz;
			hblktag.htag_rid = rid;
			hblktag.htag_id = srdp;
			hmebp = HME_HASH_FUNCTION(srdp, va, hmeshift);
			SFMMU_HASH_LOCK(hmebp);
			HME_HASH_SEARCH_PREV(hmebp, hblktag, hmeblkp, pr_hblk,
			    &list);
			if (hmeblkp == NULL) {
				SFMMU_HASH_UNLOCK(hmebp);
				ttesz--;
				continue;
			}
			ASSERT(hmeblkp->hblk_shared);
			va = sfmmu_hblk_unlock(hmeblkp, va, eaddr);
			ASSERT(va >= eaddr ||
			    IS_P2ALIGNED((uintptr_t)va, TTEBYTES(ttesz)));
			SFMMU_HASH_UNLOCK(hmebp);
			break;
		}
		if (ttesz < HBLK_MIN_TTESZ) {
			panic("hat_unlock_region: addr not found "
			    "addr %p hat %p", (void *)va, (void *)sfmmup);
		}
	}
	sfmmu_hblks_list_purge(&list, 0);
}

/*
 * Function to unlock a range of addresses in an hmeblk.  It returns the
 * next address that needs to be unlocked.
 * Should be called with the hash lock held.
 */
static caddr_t
sfmmu_hblk_unlock(struct hme_blk *hmeblkp, caddr_t addr, caddr_t endaddr)
{
	struct sf_hment *sfhme;
	tte_t tteold, ttemod;
	int ttesz, ret;

	ASSERT(in_hblk_range(hmeblkp, addr));
	ASSERT(hmeblkp->hblk_shw_bit == 0);

	endaddr = MIN(endaddr, get_hblk_endaddr(hmeblkp));
	ttesz = get_hblk_ttesz(hmeblkp);

	HBLKTOHME(sfhme, hmeblkp, addr);
	while (addr < endaddr) {
readtte:
		sfmmu_copytte(&sfhme->hme_tte, &tteold);
		if (TTE_IS_VALID(&tteold)) {

			ttemod = tteold;

			ret = sfmmu_modifytte_try(&tteold, &ttemod,
			    &sfhme->hme_tte);

			if (ret < 0)
				goto readtte;

			if (hmeblkp->hblk_lckcnt == 0)
				panic("zero hblk lckcnt");

			if (((uintptr_t)addr + TTEBYTES(ttesz)) >
			    (uintptr_t)endaddr)
				panic("can't unlock large tte");

			ASSERT(hmeblkp->hblk_lckcnt > 0);
			atomic_dec_32(&hmeblkp->hblk_lckcnt);
			HBLK_STACK_TRACE(hmeblkp, HBLK_UNLOCK);
		} else {
			panic("sfmmu_hblk_unlock: invalid tte");
		}
		addr += TTEBYTES(ttesz);
		sfhme++;
	}
	return (addr);
}

/*
 * Physical Address Mapping Framework
 *
 * General rules:
 *
 * (1) Applies only to seg_kmem memory pages. To make things easier,
 *     seg_kpm addresses are also accepted by the routines, but nothing
 *     is done with them since by definition their PA mappings are static.
 * (2) hat_add_callback() may only be called while holding the page lock
 *     SE_SHARED or SE_EXCL of the underlying page (e.g., as_pagelock()),
 *     or passing HAC_PAGELOCK flag.
 * (3) prehandler() and posthandler() may not call hat_add_callback() or
 *     hat_delete_callback(), nor should they allocate memory. Post quiesce
 *     callbacks may not sleep or acquire adaptive mutex locks.
 * (4) Either prehandler() or posthandler() (but not both) may be specified
 *     as being NULL.  Specifying an errhandler() is optional.
 *
 * Details of using the framework:
 *
 * registering a callback (hat_register_callback())
 *
 *	Pass prehandler, posthandler, errhandler addresses
 *	as described below. If capture_cpus argument is nonzero,
 *	suspend callback to the prehandler will occur with CPUs
 *	captured and executing xc_loop() and CPUs will remain
 *	captured until after the posthandler suspend callback
 *	occurs.
 *
 * adding a callback (hat_add_callback())
 *
 *      as_pagelock();
 *	hat_add_callback();
 *      save returned pfn in private data structures or program registers;
 *      as_pageunlock();
 *
 * prehandler()
 *
 *	Stop all accesses by physical address to this memory page.
 *	Called twice: the first, PRESUSPEND, is a context safe to acquire
 *	adaptive locks. The second, SUSPEND, is called at high PIL with
 *	CPUs captured so adaptive locks may NOT be acquired (and all spin
 *	locks must be XCALL_PIL or higher locks).
 *
 *	May return the following errors:
 *		EIO:	A fatal error has occurred. This will result in panic.
 *		EAGAIN:	The page cannot be suspended. This will fail the
 *			relocation.
 *		0:	Success.
 *
 * posthandler()
 *
 *      Save new pfn in private data structures or program registers;
 *	not allowed to fail (non-zero return values will result in panic).
 *
 * errhandler()
 *
 *	called when an error occurs related to the callback.  Currently
 *	the only such error is HAT_CB_ERR_LEAKED which indicates that
 *	a page is being freed, but there are still outstanding callback(s)
 *	registered on the page.
 *
 * removing a callback (hat_delete_callback(); e.g., prior to freeing memory)
 *
 *	stop using physical address
 *	hat_delete_callback();
 *
 */

/*
 * Register a callback class.  Each subsystem should do this once and
 * cache the id_t returned for use in setting up and tearing down callbacks.
 *
 * There is no facility for removing callback IDs once they are created;
 * the "key" should be unique for each module, so in case a module is unloaded
 * and subsequently re-loaded, we can recycle the module's previous entry.
 */
id_t
hat_register_callback(int key,
	int (*prehandler)(caddr_t, uint_t, uint_t, void *),
	int (*posthandler)(caddr_t, uint_t, uint_t, void *, pfn_t),
	int (*errhandler)(caddr_t, uint_t, uint_t, void *),
	int capture_cpus)
{
	id_t id;

	/*
	 * Search the table for a pre-existing callback associated with
	 * the identifier "key".  If one exists, we re-use that entry in
	 * the table for this instance, otherwise we assign the next
	 * available table slot.
	 */
	for (id = 0; id < sfmmu_max_cb_id; id++) {
		if (sfmmu_cb_table[id].key == key)
			break;
	}

	if (id == sfmmu_max_cb_id) {
		id = sfmmu_cb_nextid++;
		if (id >= sfmmu_max_cb_id)
			panic("hat_register_callback: out of callback IDs");
	}

	ASSERT(prehandler != NULL || posthandler != NULL);

	sfmmu_cb_table[id].key = key;
	sfmmu_cb_table[id].prehandler = prehandler;
	sfmmu_cb_table[id].posthandler = posthandler;
	sfmmu_cb_table[id].errhandler = errhandler;
	sfmmu_cb_table[id].capture_cpus = capture_cpus;

	return (id);
}

#define	HAC_COOKIE_NONE	(void *)-1

/*
 * Add relocation callbacks to the specified addr/len which will be called
 * when relocating the associated page. See the description of pre and
 * posthandler above for more details.
 *
 * If HAC_PAGELOCK is included in flags, the underlying memory page is
 * locked internally so the caller must be able to deal with the callback
 * running even before this function has returned.  If HAC_PAGELOCK is not
 * set, it is assumed that the underlying memory pages are locked.
 *
 * Since the caller must track the individual page boundaries anyway,
 * we only allow a callback to be added to a single page (large
 * or small).  Thus [addr, addr + len) MUST be contained within a single
 * page.
 *
 * Registering multiple callbacks on the same [addr, addr+len) is supported,
 * _provided_that_ a unique parameter is specified for each callback.
 * If multiple callbacks are registered on the same range the callback will
 * be invoked with each unique parameter. Registering the same callback with
 * the same argument more than once will result in corrupted kernel state.
 *
 * Returns the pfn of the underlying kernel page in *rpfn
 * on success, or PFN_INVALID on failure.
 *
 * cookiep (if passed) provides storage space for an opaque cookie
 * to return later to hat_delete_callback(). This cookie makes the callback
 * deletion significantly quicker by avoiding a potentially lengthy hash
 * search.
 *
 * Returns values:
 *    0:      success
 *    ENOMEM: memory allocation failure (e.g. flags was passed as HAC_NOSLEEP)
 *    EINVAL: callback ID is not valid
 *    ENXIO:  ["vaddr", "vaddr" + len) is not mapped in the kernel's address
 *            space
 *    ERANGE: ["vaddr", "vaddr" + len) crosses a page boundary
 */
int
hat_add_callback(id_t callback_id, caddr_t vaddr, uint_t len, uint_t flags,
	void *pvt, pfn_t *rpfn, void **cookiep)
{
	struct 		hmehash_bucket *hmebp;
	hmeblk_tag 	hblktag;
	struct hme_blk	*hmeblkp;
	int 		hmeshift, hashno;
	caddr_t 	saddr, eaddr, baseaddr;
	struct pa_hment *pahmep;
	struct sf_hment *sfhmep, *osfhmep;
	kmutex_t	*pml;
	tte_t   	tte;
	page_t		*pp;
	vnode_t		*vp;
	u_offset_t	off;
	pfn_t		pfn;
	int		kmflags = (flags & HAC_SLEEP)? KM_SLEEP : KM_NOSLEEP;
	int		locked = 0;

	/*
	 * For KPM mappings, just return the physical address since we
	 * don't need to register any callbacks.
	 */
	if (IS_KPM_ADDR(vaddr)) {
		uint64_t paddr;
		SFMMU_KPM_VTOP(vaddr, paddr);
		*rpfn = btop(paddr);
		if (cookiep != NULL)
			*cookiep = HAC_COOKIE_NONE;
		return (0);
	}

	if (callback_id < (id_t)0 || callback_id >= sfmmu_cb_nextid) {
		*rpfn = PFN_INVALID;
		return (EINVAL);
	}

	if ((pahmep = kmem_cache_alloc(pa_hment_cache, kmflags)) == NULL) {
		*rpfn = PFN_INVALID;
		return (ENOMEM);
	}

	sfhmep = &pahmep->sfment;

	saddr = (caddr_t)((uintptr_t)vaddr & MMU_PAGEMASK);
	eaddr = saddr + len;

rehash:
	/* Find the mapping(s) for this page */
	for (hashno = TTE64K, hmeblkp = NULL;
	    hmeblkp == NULL && hashno <= mmu_hashcnt;
	    hashno++) {
		hmeshift = HME_HASH_SHIFT(hashno);
		hblktag.htag_id = ksfmmup;
		hblktag.htag_rid = SFMMU_INVALID_SHMERID;
		hblktag.htag_bspage = HME_HASH_BSPAGE(saddr, hmeshift);
		hblktag.htag_rehash = hashno;
		hmebp = HME_HASH_FUNCTION(ksfmmup, saddr, hmeshift);

		SFMMU_HASH_LOCK(hmebp);

		HME_HASH_FAST_SEARCH(hmebp, hblktag, hmeblkp);

		if (hmeblkp == NULL)
			SFMMU_HASH_UNLOCK(hmebp);
	}

	if (hmeblkp == NULL) {
		kmem_cache_free(pa_hment_cache, pahmep);
		*rpfn = PFN_INVALID;
		return (ENXIO);
	}

	ASSERT(!hmeblkp->hblk_shared);

	HBLKTOHME(osfhmep, hmeblkp, saddr);
	sfmmu_copytte(&osfhmep->hme_tte, &tte);

	if (!TTE_IS_VALID(&tte)) {
		SFMMU_HASH_UNLOCK(hmebp);
		kmem_cache_free(pa_hment_cache, pahmep);
		*rpfn = PFN_INVALID;
		return (ENXIO);
	}

	/*
	 * Make sure the boundaries for the callback fall within this
	 * single mapping.
	 */
	baseaddr = (caddr_t)get_hblk_base(hmeblkp);
	ASSERT(saddr >= baseaddr);
	if (eaddr > saddr + TTEBYTES(TTE_CSZ(&tte))) {
		SFMMU_HASH_UNLOCK(hmebp);
		kmem_cache_free(pa_hment_cache, pahmep);
		*rpfn = PFN_INVALID;
		return (ERANGE);
	}

	pfn = sfmmu_ttetopfn(&tte, vaddr);

	/*
	 * The pfn may not have a page_t underneath in which case we
	 * just return it. This can happen if we are doing I/O to a
	 * static portion of the kernel's address space, for instance.
	 */
	pp = osfhmep->hme_page;
	if (pp == NULL) {
		SFMMU_HASH_UNLOCK(hmebp);
		kmem_cache_free(pa_hment_cache, pahmep);
		*rpfn = pfn;
		if (cookiep)
			*cookiep = HAC_COOKIE_NONE;
		return (0);
	}
	ASSERT(pp == PP_PAGEROOT(pp));

	vp = pp->p_vnode;
	off = pp->p_offset;

	pml = sfmmu_mlist_enter(pp);

	if (flags & HAC_PAGELOCK) {
		if (!page_trylock(pp, SE_SHARED)) {
			/*
			 * Somebody is holding SE_EXCL lock. Might
			 * even be hat_page_relocate(). Drop all
			 * our locks, lookup the page in &kvp, and
			 * retry. If it doesn't exist in &kvp and &zvp,
			 * then we must be dealing with a kernel mapped
			 * page which doesn't actually belong to
			 * segkmem so we punt.
			 */
			sfmmu_mlist_exit(pml);
			SFMMU_HASH_UNLOCK(hmebp);
			pp = page_lookup(&kvp, (u_offset_t)saddr, SE_SHARED);

			/* check zvp before giving up */
			if (pp == NULL)
				pp = page_lookup(&zvp, (u_offset_t)saddr,
				    SE_SHARED);

			/* Okay, we didn't find it, give up */
			if (pp == NULL) {
				kmem_cache_free(pa_hment_cache, pahmep);
				*rpfn = pfn;
				if (cookiep)
					*cookiep = HAC_COOKIE_NONE;
				return (0);
			}
			page_unlock(pp);
			goto rehash;
		}
		locked = 1;
	}

	if (!PAGE_LOCKED(pp) && !panicstr)
		panic("hat_add_callback: page 0x%p not locked", (void *)pp);

	if (osfhmep->hme_page != pp || pp->p_vnode != vp ||
	    pp->p_offset != off) {
		/*
		 * The page moved before we got our hands on it.  Drop
		 * all the locks and try again.
		 */
		ASSERT((flags & HAC_PAGELOCK) != 0);
		sfmmu_mlist_exit(pml);
		SFMMU_HASH_UNLOCK(hmebp);
		page_unlock(pp);
		locked = 0;
		goto rehash;
	}

	if (!VN_ISKAS(vp)) {
		/*
		 * This is not a segkmem page but another page which
		 * has been kernel mapped. It had better have at least
		 * a share lock on it. Return the pfn.
		 */
		sfmmu_mlist_exit(pml);
		SFMMU_HASH_UNLOCK(hmebp);
		if (locked)
			page_unlock(pp);
		kmem_cache_free(pa_hment_cache, pahmep);
		ASSERT(PAGE_LOCKED(pp));
		*rpfn = pfn;
		if (cookiep)
			*cookiep = HAC_COOKIE_NONE;
		return (0);
	}

	/*
	 * Setup this pa_hment and link its embedded dummy sf_hment into
	 * the mapping list.
	 */
	pp->p_share++;
	pahmep->cb_id = callback_id;
	pahmep->addr = vaddr;
	pahmep->len = len;
	pahmep->refcnt = 1;
	pahmep->flags = 0;
	pahmep->pvt = pvt;

	sfhmep->hme_tte.ll = 0;
	sfhmep->hme_data = pahmep;
	sfhmep->hme_prev = osfhmep;
	sfhmep->hme_next = osfhmep->hme_next;

	if (osfhmep->hme_next)
		osfhmep->hme_next->hme_prev = sfhmep;

	osfhmep->hme_next = sfhmep;

	sfmmu_mlist_exit(pml);
	SFMMU_HASH_UNLOCK(hmebp);

	if (locked)
		page_unlock(pp);

	*rpfn = pfn;
	if (cookiep)
		*cookiep = (void *)pahmep;

	return (0);
}

/*
 * Remove the relocation callbacks from the specified addr/len.
 */
void
hat_delete_callback(caddr_t vaddr, uint_t len, void *pvt, uint_t flags,
	void *cookie)
{
	struct		hmehash_bucket *hmebp;
	hmeblk_tag	hblktag;
	struct hme_blk	*hmeblkp;
	int		hmeshift, hashno;
	caddr_t		saddr;
	struct pa_hment	*pahmep;
	struct sf_hment	*sfhmep, *osfhmep;
	kmutex_t	*pml;
	tte_t		tte;
	page_t		*pp;
	vnode_t		*vp;
	u_offset_t	off;
	int		locked = 0;

	/*
	 * If the cookie is HAC_COOKIE_NONE then there is no pa_hment to
	 * remove so just return.
	 */
	if (cookie == HAC_COOKIE_NONE || IS_KPM_ADDR(vaddr))
		return;

	saddr = (caddr_t)((uintptr_t)vaddr & MMU_PAGEMASK);

rehash:
	/* Find the mapping(s) for this page */
	for (hashno = TTE64K, hmeblkp = NULL;
	    hmeblkp == NULL && hashno <= mmu_hashcnt;
	    hashno++) {
		hmeshift = HME_HASH_SHIFT(hashno);
		hblktag.htag_id = ksfmmup;
		hblktag.htag_rid = SFMMU_INVALID_SHMERID;
		hblktag.htag_bspage = HME_HASH_BSPAGE(saddr, hmeshift);
		hblktag.htag_rehash = hashno;
		hmebp = HME_HASH_FUNCTION(ksfmmup, saddr, hmeshift);

		SFMMU_HASH_LOCK(hmebp);

		HME_HASH_FAST_SEARCH(hmebp, hblktag, hmeblkp);

		if (hmeblkp == NULL)
			SFMMU_HASH_UNLOCK(hmebp);
	}

	if (hmeblkp == NULL)
		return;

	ASSERT(!hmeblkp->hblk_shared);

	HBLKTOHME(osfhmep, hmeblkp, saddr);

	sfmmu_copytte(&osfhmep->hme_tte, &tte);
	if (!TTE_IS_VALID(&tte)) {
		SFMMU_HASH_UNLOCK(hmebp);
		return;
	}

	pp = osfhmep->hme_page;
	if (pp == NULL) {
		SFMMU_HASH_UNLOCK(hmebp);
		ASSERT(cookie == NULL);
		return;
	}

	vp = pp->p_vnode;
	off = pp->p_offset;

	pml = sfmmu_mlist_enter(pp);

	if (flags & HAC_PAGELOCK) {
		if (!page_trylock(pp, SE_SHARED)) {
			/*
			 * Somebody is holding SE_EXCL lock. Might
			 * even be hat_page_relocate(). Drop all
			 * our locks, lookup the page in &kvp, and
			 * retry. If it doesn't exist in &kvp and &zvp,
			 * then we must be dealing with a kernel mapped
			 * page which doesn't actually belong to
			 * segkmem so we punt.
			 */
			sfmmu_mlist_exit(pml);
			SFMMU_HASH_UNLOCK(hmebp);
			pp = page_lookup(&kvp, (u_offset_t)saddr, SE_SHARED);
			/* check zvp before giving up */
			if (pp == NULL)
				pp = page_lookup(&zvp, (u_offset_t)saddr,
				    SE_SHARED);

			if (pp == NULL) {
				ASSERT(cookie == NULL);
				return;
			}
			page_unlock(pp);
			goto rehash;
		}
		locked = 1;
	}

	ASSERT(PAGE_LOCKED(pp));

	if (osfhmep->hme_page != pp || pp->p_vnode != vp ||
	    pp->p_offset != off) {
		/*
		 * The page moved before we got our hands on it.  Drop
		 * all the locks and try again.
		 */
		ASSERT((flags & HAC_PAGELOCK) != 0);
		sfmmu_mlist_exit(pml);
		SFMMU_HASH_UNLOCK(hmebp);
		page_unlock(pp);
		locked = 0;
		goto rehash;
	}

	if (!VN_ISKAS(vp)) {
		/*
		 * This is not a segkmem page but another page which
		 * has been kernel mapped.
		 */
		sfmmu_mlist_exit(pml);
		SFMMU_HASH_UNLOCK(hmebp);
		if (locked)
			page_unlock(pp);
		ASSERT(cookie == NULL);
		return;
	}

	if (cookie != NULL) {
		pahmep = (struct pa_hment *)cookie;
		sfhmep = &pahmep->sfment;
	} else {
		for (sfhmep = pp->p_mapping; sfhmep != NULL;
		    sfhmep = sfhmep->hme_next) {

			/*
			 * skip va<->pa mappings
			 */
			if (!IS_PAHME(sfhmep))
				continue;

			pahmep = sfhmep->hme_data;
			ASSERT(pahmep != NULL);

			/*
			 * if pa_hment matches, remove it
			 */
			if ((pahmep->pvt == pvt) &&
			    (pahmep->addr == vaddr) &&
			    (pahmep->len == len)) {
				break;
			}
		}
	}

	if (sfhmep == NULL) {
		if (!panicstr) {
			panic("hat_delete_callback: pa_hment not found, pp %p",
			    (void *)pp);
		}
		return;
	}

	/*
	 * Note: at this point a valid kernel mapping must still be
	 * present on this page.
	 */
	pp->p_share--;
	if (pp->p_share <= 0)
		panic("hat_delete_callback: zero p_share");

	if (--pahmep->refcnt == 0) {
		if (pahmep->flags != 0)
			panic("hat_delete_callback: pa_hment is busy");

		/*
		 * Remove sfhmep from the mapping list for the page.
		 */
		if (sfhmep->hme_prev) {
			sfhmep->hme_prev->hme_next = sfhmep->hme_next;
		} else {
			pp->p_mapping = sfhmep->hme_next;
		}

		if (sfhmep->hme_next)
			sfhmep->hme_next->hme_prev = sfhmep->hme_prev;

		sfmmu_mlist_exit(pml);
		SFMMU_HASH_UNLOCK(hmebp);

		if (locked)
			page_unlock(pp);

		kmem_cache_free(pa_hment_cache, pahmep);
		return;
	}

	sfmmu_mlist_exit(pml);
	SFMMU_HASH_UNLOCK(hmebp);
	if (locked)
		page_unlock(pp);
}

/*
 * hat_probe returns 1 if the translation for the address 'addr' is
 * loaded, zero otherwise.
 *
 * hat_probe should be used only for advisorary purposes because it may
 * occasionally return the wrong value. The implementation must guarantee that
 * returning the wrong value is a very rare event. hat_probe is used
 * to implement optimizations in the segment drivers.
 *
 */
int
hat_probe(struct hat *sfmmup, caddr_t addr)
{
	pfn_t pfn;
	tte_t tte;

	ASSERT(sfmmup != NULL);

	ASSERT((sfmmup == ksfmmup) || AS_LOCK_HELD(sfmmup->sfmmu_as));

	if (sfmmup == ksfmmup) {
		while ((pfn = sfmmu_vatopfn(addr, sfmmup, &tte))
		    == PFN_SUSPENDED) {
			sfmmu_vatopfn_suspended(addr, sfmmup, &tte);
		}
	} else {
		pfn = sfmmu_uvatopfn(addr, sfmmup, NULL);
	}

	if (pfn != PFN_INVALID)
		return (1);
	else
		return (0);
}

ssize_t
hat_getpagesize(struct hat *sfmmup, caddr_t addr)
{
	tte_t tte;

	if (sfmmup == ksfmmup) {
		if (sfmmu_vatopfn(addr, sfmmup, &tte) == PFN_INVALID) {
			return (-1);
		}
	} else {
		if (sfmmu_uvatopfn(addr, sfmmup, &tte) == PFN_INVALID) {
			return (-1);
		}
	}

	ASSERT(TTE_IS_VALID(&tte));
	return (TTEBYTES(TTE_CSZ(&tte)));
}

uint_t
hat_getattr(struct hat *sfmmup, caddr_t addr, uint_t *attr)
{
	tte_t tte;

	if (sfmmup == ksfmmup) {
		if (sfmmu_vatopfn(addr, sfmmup, &tte) == PFN_INVALID) {
			tte.ll = 0;
		}
	} else {
		if (sfmmu_uvatopfn(addr, sfmmup, &tte) == PFN_INVALID) {
			tte.ll = 0;
		}
	}
	if (TTE_IS_VALID(&tte)) {
		*attr = sfmmu_ptov_attr(&tte);
		return (0);
	}
	*attr = 0;
	return ((uint_t)0xffffffff);
}

/*
 * Enables more attributes on specified address range (ie. logical OR)
 */
void
hat_setattr(struct hat *hat, caddr_t addr, size_t len, uint_t attr)
{
	ASSERT(hat->sfmmu_as != NULL);

	sfmmu_chgattr(hat, addr, len, attr, SFMMU_SETATTR);
}

/*
 * Assigns attributes to the specified address range.  All the attributes
 * are specified.
 */
void
hat_chgattr(struct hat *hat, caddr_t addr, size_t len, uint_t attr)
{
	ASSERT(hat->sfmmu_as != NULL);

	sfmmu_chgattr(hat, addr, len, attr, SFMMU_CHGATTR);
}

/*
 * Remove attributes on the specified address range (ie. loginal NAND)
 */
void
hat_clrattr(struct hat *hat, caddr_t addr, size_t len, uint_t attr)
{
	ASSERT(hat->sfmmu_as != NULL);

	sfmmu_chgattr(hat, addr, len, attr, SFMMU_CLRATTR);
}

/*
 * Change attributes on an address range to that specified by attr and mode.
 */
static void
sfmmu_chgattr(struct hat *sfmmup, caddr_t addr, size_t len, uint_t attr,
	int mode)
{
	struct hmehash_bucket *hmebp;
	hmeblk_tag hblktag;
	int hmeshift, hashno = 1;
	struct hme_blk *hmeblkp, *list = NULL;
	caddr_t endaddr;
	cpuset_t cpuset;
	demap_range_t dmr;

	CPUSET_ZERO(cpuset);

	ASSERT((sfmmup == ksfmmup) || AS_LOCK_HELD(sfmmup->sfmmu_as));
	ASSERT((len & MMU_PAGEOFFSET) == 0);
	ASSERT(((uintptr_t)addr & MMU_PAGEOFFSET) == 0);

	if ((attr & PROT_USER) && (mode != SFMMU_CLRATTR) &&
	    ((addr + len) > (caddr_t)USERLIMIT)) {
		panic("user addr %p in kernel space",
		    (void *)addr);
	}

	endaddr = addr + len;
	hblktag.htag_id = sfmmup;
	hblktag.htag_rid = SFMMU_INVALID_SHMERID;
	DEMAP_RANGE_INIT(sfmmup, &dmr);

	while (addr < endaddr) {
		hmeshift = HME_HASH_SHIFT(hashno);
		hblktag.htag_bspage = HME_HASH_BSPAGE(addr, hmeshift);
		hblktag.htag_rehash = hashno;
		hmebp = HME_HASH_FUNCTION(sfmmup, addr, hmeshift);

		SFMMU_HASH_LOCK(hmebp);

		HME_HASH_SEARCH(hmebp, hblktag, hmeblkp, &list);
		if (hmeblkp != NULL) {
			ASSERT(!hmeblkp->hblk_shared);
			/*
			 * We've encountered a shadow hmeblk so skip the range
			 * of the next smaller mapping size.
			 */
			if (hmeblkp->hblk_shw_bit) {
				ASSERT(sfmmup != ksfmmup);
				ASSERT(hashno > 1);
				addr = (caddr_t)P2END((uintptr_t)addr,
				    TTEBYTES(hashno - 1));
			} else {
				addr = sfmmu_hblk_chgattr(sfmmup,
				    hmeblkp, addr, endaddr, &dmr, attr, mode);
			}
			SFMMU_HASH_UNLOCK(hmebp);
			hashno = 1;
			continue;
		}
		SFMMU_HASH_UNLOCK(hmebp);

		if (!HME_REHASH(sfmmup) || (hashno >= mmu_hashcnt)) {
			/*
			 * We have traversed the whole list and rehashed
			 * if necessary without finding the address to chgattr.
			 * This is ok, so we increment the address by the
			 * smallest hmeblk range for kernel mappings or for
			 * user mappings with no large pages, and the largest
			 * hmeblk range, to account for shadow hmeblks, for
			 * user mappings with large pages and continue.
			 */
			if (sfmmup == ksfmmup)
				addr = (caddr_t)P2END((uintptr_t)addr,
				    TTEBYTES(1));
			else
				addr = (caddr_t)P2END((uintptr_t)addr,
				    TTEBYTES(hashno));
			hashno = 1;
		} else {
			hashno++;
		}
	}

	sfmmu_hblks_list_purge(&list, 0);
	DEMAP_RANGE_FLUSH(&dmr);
	cpuset = sfmmup->sfmmu_cpusran;
	xt_sync(cpuset);
}

/*
 * This function chgattr on a range of addresses in an hmeblk.  It returns the
 * next addres that needs to be chgattr.
 * It should be called with the hash lock held.
 * XXX It should be possible to optimize chgattr by not flushing every time but
 * on the other hand:
 * 1. do one flush crosscall.
 * 2. only flush if we are increasing permissions (make sure this will work)
 */
static caddr_t
sfmmu_hblk_chgattr(struct hat *sfmmup, struct hme_blk *hmeblkp, caddr_t addr,
	caddr_t endaddr, demap_range_t *dmrp, uint_t attr, int mode)
{
	tte_t tte, tteattr, tteflags, ttemod;
	struct sf_hment *sfhmep;
	int ttesz;
	struct page *pp = NULL;
	kmutex_t *pml, *pmtx;
	int ret;
	int use_demap_range;
#if defined(SF_ERRATA_57)
	int check_exec;
#endif

	ASSERT(in_hblk_range(hmeblkp, addr));
	ASSERT(hmeblkp->hblk_shw_bit == 0);
	ASSERT(!hmeblkp->hblk_shared);

	endaddr = MIN(endaddr, get_hblk_endaddr(hmeblkp));
	ttesz = get_hblk_ttesz(hmeblkp);

	/*
	 * Flush the current demap region if addresses have been
	 * skipped or the page size doesn't match.
	 */
	use_demap_range = (TTEBYTES(ttesz) == DEMAP_RANGE_PGSZ(dmrp));
	if (use_demap_range) {
		DEMAP_RANGE_CONTINUE(dmrp, addr, endaddr);
	} else if (dmrp != NULL) {
		DEMAP_RANGE_FLUSH(dmrp);
	}

	tteattr.ll = sfmmu_vtop_attr(attr, mode, &tteflags);
#if defined(SF_ERRATA_57)
	check_exec = (sfmmup != ksfmmup) &&
	    AS_TYPE_64BIT(sfmmup->sfmmu_as) &&
	    TTE_IS_EXECUTABLE(&tteattr);
#endif
	HBLKTOHME(sfhmep, hmeblkp, addr);
	while (addr < endaddr) {
		sfmmu_copytte(&sfhmep->hme_tte, &tte);
		if (TTE_IS_VALID(&tte)) {
			if ((tte.ll & tteflags.ll) == tteattr.ll) {
				/*
				 * if the new attr is the same as old
				 * continue
				 */
				goto next_addr;
			}
			if (!TTE_IS_WRITABLE(&tteattr)) {
				/*
				 * make sure we clear hw modify bit if we
				 * removing write protections
				 */
				tteflags.tte_intlo |= TTE_HWWR_INT;
			}

			pml = NULL;
			pp = sfhmep->hme_page;
			if (pp) {
				pml = sfmmu_mlist_enter(pp);
			}

			if (pp != sfhmep->hme_page) {
				/*
				 * tte must have been unloaded.
				 */
				ASSERT(pml);
				sfmmu_mlist_exit(pml);
				continue;
			}

			ASSERT(pp == NULL || sfmmu_mlist_held(pp));

			ttemod = tte;
			ttemod.ll = (ttemod.ll & ~tteflags.ll) | tteattr.ll;
			ASSERT(TTE_TO_TTEPFN(&ttemod) == TTE_TO_TTEPFN(&tte));

#if defined(SF_ERRATA_57)
			if (check_exec && addr < errata57_limit)
				ttemod.tte_exec_perm = 0;
#endif
			ret = sfmmu_modifytte_try(&tte, &ttemod,
			    &sfhmep->hme_tte);

			if (ret < 0) {
				/* tte changed underneath us */
				if (pml) {
					sfmmu_mlist_exit(pml);
				}
				continue;
			}

			if (tteflags.tte_intlo & TTE_HWWR_INT) {
				/*
				 * need to sync if we are clearing modify bit.
				 */
				sfmmu_ttesync(sfmmup, addr, &tte, pp);
			}

			if (pp && PP_ISRO(pp)) {
				if (tteattr.tte_intlo & TTE_WRPRM_INT) {
					pmtx = sfmmu_page_enter(pp);
					PP_CLRRO(pp);
					sfmmu_page_exit(pmtx);
				}
			}

			if (ret > 0 && use_demap_range) {
				DEMAP_RANGE_MARKPG(dmrp, addr);
			} else if (ret > 0) {
				sfmmu_tlb_demap(addr, sfmmup, hmeblkp, 0, 0);
			}

			if (pml) {
				sfmmu_mlist_exit(pml);
			}
		}
next_addr:
		addr += TTEBYTES(ttesz);
		sfhmep++;
		DEMAP_RANGE_NEXTPG(dmrp);
	}
	return (addr);
}

/*
 * This routine converts virtual attributes to physical ones.  It will
 * update the tteflags field with the tte mask corresponding to the attributes
 * affected and it returns the new attributes.  It will also clear the modify
 * bit if we are taking away write permission.  This is necessary since the
 * modify bit is the hardware permission bit and we need to clear it in order
 * to detect write faults.
 */
static uint64_t
sfmmu_vtop_attr(uint_t attr, int mode, tte_t *ttemaskp)
{
	tte_t ttevalue;

	ASSERT(!(attr & ~SFMMU_LOAD_ALLATTR));

	switch (mode) {
	case SFMMU_CHGATTR:
		/* all attributes specified */
		ttevalue.tte_inthi = MAKE_TTEATTR_INTHI(attr);
		ttevalue.tte_intlo = MAKE_TTEATTR_INTLO(attr);
		ttemaskp->tte_inthi = TTEINTHI_ATTR;
		ttemaskp->tte_intlo = TTEINTLO_ATTR;
		break;
	case SFMMU_SETATTR:
		ASSERT(!(attr & ~HAT_PROT_MASK));
		ttemaskp->ll = 0;
		ttevalue.ll = 0;
		/*
		 * a valid tte implies exec and read for sfmmu
		 * so no need to do anything about them.
		 * since priviledged access implies user access
		 * PROT_USER doesn't make sense either.
		 */
		if (attr & PROT_WRITE) {
			ttemaskp->tte_intlo |= TTE_WRPRM_INT;
			ttevalue.tte_intlo |= TTE_WRPRM_INT;
		}
		break;
	case SFMMU_CLRATTR:
		/* attributes will be nand with current ones */
		if (attr & ~(PROT_WRITE | PROT_USER)) {
			panic("sfmmu: attr %x not supported", attr);
		}
		ttemaskp->ll = 0;
		ttevalue.ll = 0;
		if (attr & PROT_WRITE) {
			/* clear both writable and modify bit */
			ttemaskp->tte_intlo |= TTE_WRPRM_INT | TTE_HWWR_INT;
		}
		if (attr & PROT_USER) {
			ttemaskp->tte_intlo |= TTE_PRIV_INT;
			ttevalue.tte_intlo |= TTE_PRIV_INT;
		}
		break;
	default:
		panic("sfmmu_vtop_attr: bad mode %x", mode);
	}
	ASSERT(TTE_TO_TTEPFN(&ttevalue) == 0);
	return (ttevalue.ll);
}

static uint_t
sfmmu_ptov_attr(tte_t *ttep)
{
	uint_t attr;

	ASSERT(TTE_IS_VALID(ttep));

	attr = PROT_READ;

	if (TTE_IS_WRITABLE(ttep)) {
		attr |= PROT_WRITE;
	}
	if (TTE_IS_EXECUTABLE(ttep)) {
		attr |= PROT_EXEC;
	}
	if (!TTE_IS_PRIVILEGED(ttep)) {
		attr |= PROT_USER;
	}
	if (TTE_IS_NFO(ttep)) {
		attr |= HAT_NOFAULT;
	}
	if (TTE_IS_NOSYNC(ttep)) {
		attr |= HAT_NOSYNC;
	}
	if (TTE_IS_SIDEFFECT(ttep)) {
		attr |= SFMMU_SIDEFFECT;
	}
	if (!TTE_IS_VCACHEABLE(ttep)) {
		attr |= SFMMU_UNCACHEVTTE;
	}
	if (!TTE_IS_PCACHEABLE(ttep)) {
		attr |= SFMMU_UNCACHEPTTE;
	}
	return (attr);
}

/*
 * hat_chgprot is a deprecated hat call.  New segment drivers
 * should store all attributes and use hat_*attr calls.
 *
 * Change the protections in the virtual address range
 * given to the specified virtual protection.  If vprot is ~PROT_WRITE,
 * then remove write permission, leaving the other
 * permissions unchanged.  If vprot is ~PROT_USER, remove user permissions.
 *
 */
void
hat_chgprot(struct hat *sfmmup, caddr_t addr, size_t len, uint_t vprot)
{
	struct hmehash_bucket *hmebp;
	hmeblk_tag hblktag;
	int hmeshift, hashno = 1;
	struct hme_blk *hmeblkp, *list = NULL;
	caddr_t endaddr;
	cpuset_t cpuset;
	demap_range_t dmr;

	ASSERT((len & MMU_PAGEOFFSET) == 0);
	ASSERT(((uintptr_t)addr & MMU_PAGEOFFSET) == 0);

	ASSERT(sfmmup->sfmmu_as != NULL);

	CPUSET_ZERO(cpuset);

	if ((vprot != (uint_t)~PROT_WRITE) && (vprot & PROT_USER) &&
	    ((addr + len) > (caddr_t)USERLIMIT)) {
		panic("user addr %p vprot %x in kernel space",
		    (void *)addr, vprot);
	}
	endaddr = addr + len;
	hblktag.htag_id = sfmmup;
	hblktag.htag_rid = SFMMU_INVALID_SHMERID;
	DEMAP_RANGE_INIT(sfmmup, &dmr);

	while (addr < endaddr) {
		hmeshift = HME_HASH_SHIFT(hashno);
		hblktag.htag_bspage = HME_HASH_BSPAGE(addr, hmeshift);
		hblktag.htag_rehash = hashno;
		hmebp = HME_HASH_FUNCTION(sfmmup, addr, hmeshift);

		SFMMU_HASH_LOCK(hmebp);

		HME_HASH_SEARCH(hmebp, hblktag, hmeblkp, &list);
		if (hmeblkp != NULL) {
			ASSERT(!hmeblkp->hblk_shared);
			/*
			 * We've encountered a shadow hmeblk so skip the range
			 * of the next smaller mapping size.
			 */
			if (hmeblkp->hblk_shw_bit) {
				ASSERT(sfmmup != ksfmmup);
				ASSERT(hashno > 1);
				addr = (caddr_t)P2END((uintptr_t)addr,
				    TTEBYTES(hashno - 1));
			} else {
				addr = sfmmu_hblk_chgprot(sfmmup, hmeblkp,
				    addr, endaddr, &dmr, vprot);
			}
			SFMMU_HASH_UNLOCK(hmebp);
			hashno = 1;
			continue;
		}
		SFMMU_HASH_UNLOCK(hmebp);

		if (!HME_REHASH(sfmmup) || (hashno >= mmu_hashcnt)) {
			/*
			 * We have traversed the whole list and rehashed
			 * if necessary without finding the address to chgprot.
			 * This is ok so we increment the address by the
			 * smallest hmeblk range for kernel mappings and the
			 * largest hmeblk range, to account for shadow hmeblks,
			 * for user mappings and continue.
			 */
			if (sfmmup == ksfmmup)
				addr = (caddr_t)P2END((uintptr_t)addr,
				    TTEBYTES(1));
			else
				addr = (caddr_t)P2END((uintptr_t)addr,
				    TTEBYTES(hashno));
			hashno = 1;
		} else {
			hashno++;
		}
	}

	sfmmu_hblks_list_purge(&list, 0);
	DEMAP_RANGE_FLUSH(&dmr);
	cpuset = sfmmup->sfmmu_cpusran;
	xt_sync(cpuset);
}

/*
 * This function chgprots a range of addresses in an hmeblk.  It returns the
 * next addres that needs to be chgprot.
 * It should be called with the hash lock held.
 * XXX It shold be possible to optimize chgprot by not flushing every time but
 * on the other hand:
 * 1. do one flush crosscall.
 * 2. only flush if we are increasing permissions (make sure this will work)
 */
static caddr_t
sfmmu_hblk_chgprot(sfmmu_t *sfmmup, struct hme_blk *hmeblkp, caddr_t addr,
	caddr_t endaddr, demap_range_t *dmrp, uint_t vprot)
{
	uint_t pprot;
	tte_t tte, ttemod;
	struct sf_hment *sfhmep;
	uint_t tteflags;
	int ttesz;
	struct page *pp = NULL;
	kmutex_t *pml, *pmtx;
	int ret;
	int use_demap_range;
#if defined(SF_ERRATA_57)
	int check_exec;
#endif

	ASSERT(in_hblk_range(hmeblkp, addr));
	ASSERT(hmeblkp->hblk_shw_bit == 0);
	ASSERT(!hmeblkp->hblk_shared);

#ifdef DEBUG
	if (get_hblk_ttesz(hmeblkp) != TTE8K &&
	    (endaddr < get_hblk_endaddr(hmeblkp))) {
		panic("sfmmu_hblk_chgprot: partial chgprot of large page");
	}
#endif /* DEBUG */

	endaddr = MIN(endaddr, get_hblk_endaddr(hmeblkp));
	ttesz = get_hblk_ttesz(hmeblkp);

	pprot = sfmmu_vtop_prot(vprot, &tteflags);
#if defined(SF_ERRATA_57)
	check_exec = (sfmmup != ksfmmup) &&
	    AS_TYPE_64BIT(sfmmup->sfmmu_as) &&
	    ((vprot & PROT_EXEC) == PROT_EXEC);
#endif
	HBLKTOHME(sfhmep, hmeblkp, addr);

	/*
	 * Flush the current demap region if addresses have been
	 * skipped or the page size doesn't match.
	 */
	use_demap_range = (TTEBYTES(ttesz) == MMU_PAGESIZE);
	if (use_demap_range) {
		DEMAP_RANGE_CONTINUE(dmrp, addr, endaddr);
	} else if (dmrp != NULL) {
		DEMAP_RANGE_FLUSH(dmrp);
	}

	while (addr < endaddr) {
		sfmmu_copytte(&sfhmep->hme_tte, &tte);
		if (TTE_IS_VALID(&tte)) {
			if (TTE_GET_LOFLAGS(&tte, tteflags) == pprot) {
				/*
				 * if the new protection is the same as old
				 * continue
				 */
				goto next_addr;
			}
			pml = NULL;
			pp = sfhmep->hme_page;
			if (pp) {
				pml = sfmmu_mlist_enter(pp);
			}
			if (pp != sfhmep->hme_page) {
				/*
				 * tte most have been unloaded
				 * underneath us.  Recheck
				 */
				ASSERT(pml);
				sfmmu_mlist_exit(pml);
				continue;
			}

			ASSERT(pp == NULL || sfmmu_mlist_held(pp));

			ttemod = tte;
			TTE_SET_LOFLAGS(&ttemod, tteflags, pprot);
#if defined(SF_ERRATA_57)
			if (check_exec && addr < errata57_limit)
				ttemod.tte_exec_perm = 0;
#endif
			ret = sfmmu_modifytte_try(&tte, &ttemod,
			    &sfhmep->hme_tte);

			if (ret < 0) {
				/* tte changed underneath us */
				if (pml) {
					sfmmu_mlist_exit(pml);
				}
				continue;
			}

			if (tteflags & TTE_HWWR_INT) {
				/*
				 * need to sync if we are clearing modify bit.
				 */
				sfmmu_ttesync(sfmmup, addr, &tte, pp);
			}

			if (pp && PP_ISRO(pp)) {
				if (pprot & TTE_WRPRM_INT) {
					pmtx = sfmmu_page_enter(pp);
					PP_CLRRO(pp);
					sfmmu_page_exit(pmtx);
				}
			}

			if (ret > 0 && use_demap_range) {
				DEMAP_RANGE_MARKPG(dmrp, addr);
			} else if (ret > 0) {
				sfmmu_tlb_demap(addr, sfmmup, hmeblkp, 0, 0);
			}

			if (pml) {
				sfmmu_mlist_exit(pml);
			}
		}
next_addr:
		addr += TTEBYTES(ttesz);
		sfhmep++;
		DEMAP_RANGE_NEXTPG(dmrp);
	}
	return (addr);
}

/*
 * This routine is deprecated and should only be used by hat_chgprot.
 * The correct routine is sfmmu_vtop_attr.
 * This routine converts virtual page protections to physical ones.  It will
 * update the tteflags field with the tte mask corresponding to the protections
 * affected and it returns the new protections.  It will also clear the modify
 * bit if we are taking away write permission.  This is necessary since the
 * modify bit is the hardware permission bit and we need to clear it in order
 * to detect write faults.
 * It accepts the following special protections:
 * ~PROT_WRITE = remove write permissions.
 * ~PROT_USER = remove user permissions.
 */
static uint_t
sfmmu_vtop_prot(uint_t vprot, uint_t *tteflagsp)
{
	if (vprot == (uint_t)~PROT_WRITE) {
		*tteflagsp = TTE_WRPRM_INT | TTE_HWWR_INT;
		return (0);		/* will cause wrprm to be cleared */
	}
	if (vprot == (uint_t)~PROT_USER) {
		*tteflagsp = TTE_PRIV_INT;
		return (0);		/* will cause privprm to be cleared */
	}
	if ((vprot == 0) || (vprot == PROT_USER) ||
	    ((vprot & PROT_ALL) != vprot)) {
		panic("sfmmu_vtop_prot -- bad prot %x", vprot);
	}

	switch (vprot) {
	case (PROT_READ):
	case (PROT_EXEC):
	case (PROT_EXEC | PROT_READ):
		*tteflagsp = TTE_PRIV_INT | TTE_WRPRM_INT | TTE_HWWR_INT;
		return (TTE_PRIV_INT); 		/* set prv and clr wrt */
	case (PROT_WRITE):
	case (PROT_WRITE | PROT_READ):
	case (PROT_EXEC | PROT_WRITE):
	case (PROT_EXEC | PROT_WRITE | PROT_READ):
		*tteflagsp = TTE_PRIV_INT | TTE_WRPRM_INT;
		return (TTE_PRIV_INT | TTE_WRPRM_INT); 	/* set prv and wrt */
	case (PROT_USER | PROT_READ):
	case (PROT_USER | PROT_EXEC):
	case (PROT_USER | PROT_EXEC | PROT_READ):
		*tteflagsp = TTE_PRIV_INT | TTE_WRPRM_INT | TTE_HWWR_INT;
		return (0); 			/* clr prv and wrt */
	case (PROT_USER | PROT_WRITE):
	case (PROT_USER | PROT_WRITE | PROT_READ):
	case (PROT_USER | PROT_EXEC | PROT_WRITE):
	case (PROT_USER | PROT_EXEC | PROT_WRITE | PROT_READ):
		*tteflagsp = TTE_PRIV_INT | TTE_WRPRM_INT;
		return (TTE_WRPRM_INT); 	/* clr prv and set wrt */
	default:
		panic("sfmmu_vtop_prot -- bad prot %x", vprot);
	}
	return (0);
}

/*
 * Alternate unload for very large virtual ranges. With a true 64 bit VA,
 * the normal algorithm would take too long for a very large VA range with
 * few real mappings. This routine just walks thru all HMEs in the global
 * hash table to find and remove mappings.
 */
static void
hat_unload_large_virtual(
	struct hat		*sfmmup,
	caddr_t			startaddr,
	size_t			len,
	uint_t			flags,
	hat_callback_t		*callback)
{
	struct hmehash_bucket *hmebp;
	struct hme_blk *hmeblkp;
	struct hme_blk *pr_hblk = NULL;
	struct hme_blk *nx_hblk;
	struct hme_blk *list = NULL;
	int i;
	demap_range_t dmr, *dmrp;
	cpuset_t cpuset;
	caddr_t	endaddr = startaddr + len;
	caddr_t	sa;
	caddr_t	ea;
	caddr_t	cb_sa[MAX_CB_ADDR];
	caddr_t	cb_ea[MAX_CB_ADDR];
	int	addr_cnt = 0;
	int	a = 0;

	if (sfmmup->sfmmu_free) {
		dmrp = NULL;
	} else {
		dmrp = &dmr;
		DEMAP_RANGE_INIT(sfmmup, dmrp);
	}

	/*
	 * Loop through all the hash buckets of HME blocks looking for matches.
	 */
	for (i = 0; i <= UHMEHASH_SZ; i++) {
		hmebp = &uhme_hash[i];
		SFMMU_HASH_LOCK(hmebp);
		hmeblkp = hmebp->hmeblkp;
		pr_hblk = NULL;
		while (hmeblkp) {
			nx_hblk = hmeblkp->hblk_next;

			/*
			 * skip if not this context, if a shadow block or
			 * if the mapping is not in the requested range
			 */
			if (hmeblkp->hblk_tag.htag_id != sfmmup ||
			    hmeblkp->hblk_shw_bit ||
			    (sa = (caddr_t)get_hblk_base(hmeblkp)) >= endaddr ||
			    (ea = get_hblk_endaddr(hmeblkp)) <= startaddr) {
				pr_hblk = hmeblkp;
				goto next_block;
			}

			ASSERT(!hmeblkp->hblk_shared);
			/*
			 * unload if there are any current valid mappings
			 */
			if (hmeblkp->hblk_vcnt != 0 ||
			    hmeblkp->hblk_hmecnt != 0)
				(void) sfmmu_hblk_unload(sfmmup, hmeblkp,
				    sa, ea, dmrp, flags);

			/*
			 * on unmap we also release the HME block itself, once
			 * all mappings are gone.
			 */
			if ((flags & HAT_UNLOAD_UNMAP) != 0 &&
			    !hmeblkp->hblk_vcnt &&
			    !hmeblkp->hblk_hmecnt) {
				ASSERT(!hmeblkp->hblk_lckcnt);
				sfmmu_hblk_hash_rm(hmebp, hmeblkp, pr_hblk,
				    &list, 0);
			} else {
				pr_hblk = hmeblkp;
			}

			if (callback == NULL)
				goto next_block;

			/*
			 * HME blocks may span more than one page, but we may be
			 * unmapping only one page, so check for a smaller range
			 * for the callback
			 */
			if (sa < startaddr)
				sa = startaddr;
			if (--ea > endaddr)
				ea = endaddr - 1;

			cb_sa[addr_cnt] = sa;
			cb_ea[addr_cnt] = ea;
			if (++addr_cnt == MAX_CB_ADDR) {
				if (dmrp != NULL) {
					DEMAP_RANGE_FLUSH(dmrp);
					cpuset = sfmmup->sfmmu_cpusran;
					xt_sync(cpuset);
				}

				for (a = 0; a < MAX_CB_ADDR; ++a) {
					callback->hcb_start_addr = cb_sa[a];
					callback->hcb_end_addr = cb_ea[a];
					callback->hcb_function(callback);
				}
				addr_cnt = 0;
			}

next_block:
			hmeblkp = nx_hblk;
		}
		SFMMU_HASH_UNLOCK(hmebp);
	}

	sfmmu_hblks_list_purge(&list, 0);
	if (dmrp != NULL) {
		DEMAP_RANGE_FLUSH(dmrp);
		cpuset = sfmmup->sfmmu_cpusran;
		xt_sync(cpuset);
	}

	for (a = 0; a < addr_cnt; ++a) {
		callback->hcb_start_addr = cb_sa[a];
		callback->hcb_end_addr = cb_ea[a];
		callback->hcb_function(callback);
	}

	/*
	 * Check TSB and TLB page sizes if the process isn't exiting.
	 */
	if (!sfmmup->sfmmu_free)
		sfmmu_check_page_sizes(sfmmup, 0);
}

/*
 * Unload all the mappings in the range [addr..addr+len). addr and len must
 * be MMU_PAGESIZE aligned.
 */

extern struct seg *segkmap;
#define	ISSEGKMAP(sfmmup, addr) (sfmmup == ksfmmup && \
segkmap->s_base <= (addr) && (addr) < (segkmap->s_base + segkmap->s_size))


void
hat_unload_callback(
	struct hat *sfmmup,
	caddr_t addr,
	size_t len,
	uint_t flags,
	hat_callback_t *callback)
{
	struct hmehash_bucket *hmebp;
	hmeblk_tag hblktag;
	int hmeshift, hashno, iskernel;
	struct hme_blk *hmeblkp, *pr_hblk, *list = NULL;
	caddr_t endaddr;
	cpuset_t cpuset;
	int addr_count = 0;
	int a;
	caddr_t cb_start_addr[MAX_CB_ADDR];
	caddr_t cb_end_addr[MAX_CB_ADDR];
	int issegkmap = ISSEGKMAP(sfmmup, addr);
	demap_range_t dmr, *dmrp;

	ASSERT(sfmmup->sfmmu_as != NULL);

	ASSERT((sfmmup == ksfmmup) || (flags & HAT_UNLOAD_OTHER) || \
	    AS_LOCK_HELD(sfmmup->sfmmu_as));

	ASSERT(sfmmup != NULL);
	ASSERT((len & MMU_PAGEOFFSET) == 0);
	ASSERT(!((uintptr_t)addr & MMU_PAGEOFFSET));

	/*
	 * Probing through a large VA range (say 63 bits) will be slow, even
	 * at 4 Meg steps between the probes. So, when the virtual address range
	 * is very large, search the HME entries for what to unload.
	 *
	 *	len >> TTE_PAGE_SHIFT(TTE4M) is the # of 4Meg probes we'd need
	 *
	 *	UHMEHASH_SZ is number of hash buckets to examine
	 *
	 */
	if (sfmmup != KHATID && (len >> TTE_PAGE_SHIFT(TTE4M)) > UHMEHASH_SZ) {
		hat_unload_large_virtual(sfmmup, addr, len, flags, callback);
		return;
	}

	CPUSET_ZERO(cpuset);

	/*
	 * If the process is exiting, we can save a lot of fuss since
	 * we'll flush the TLB when we free the ctx anyway.
	 */
	if (sfmmup->sfmmu_free) {
		dmrp = NULL;
	} else {
		dmrp = &dmr;
		DEMAP_RANGE_INIT(sfmmup, dmrp);
	}

	endaddr = addr + len;
	hblktag.htag_id = sfmmup;
	hblktag.htag_rid = SFMMU_INVALID_SHMERID;

	/*
	 * It is likely for the vm to call unload over a wide range of
	 * addresses that are actually very sparsely populated by
	 * translations.  In order to speed this up the sfmmu hat supports
	 * the concept of shadow hmeblks. Dummy large page hmeblks that
	 * correspond to actual small translations are allocated at tteload
	 * time and are referred to as shadow hmeblks.  Now, during unload
	 * time, we first check if we have a shadow hmeblk for that
	 * translation.  The absence of one means the corresponding address
	 * range is empty and can be skipped.
	 *
	 * The kernel is an exception to above statement and that is why
	 * we don't use shadow hmeblks and hash starting from the smallest
	 * page size.
	 */
	if (sfmmup == KHATID) {
		iskernel = 1;
		hashno = TTE64K;
	} else {
		iskernel = 0;
		if (mmu_page_sizes == max_mmu_page_sizes) {
			hashno = TTE256M;
		} else {
			hashno = TTE4M;
		}
	}
	while (addr < endaddr) {
		hmeshift = HME_HASH_SHIFT(hashno);
		hblktag.htag_bspage = HME_HASH_BSPAGE(addr, hmeshift);
		hblktag.htag_rehash = hashno;
		hmebp = HME_HASH_FUNCTION(sfmmup, addr, hmeshift);

		SFMMU_HASH_LOCK(hmebp);

		HME_HASH_SEARCH_PREV(hmebp, hblktag, hmeblkp, pr_hblk, &list);
		if (hmeblkp == NULL) {
			/*
			 * didn't find an hmeblk. skip the appropiate
			 * address range.
			 */
			SFMMU_HASH_UNLOCK(hmebp);
			if (iskernel) {
				if (hashno < mmu_hashcnt) {
					hashno++;
					continue;
				} else {
					hashno = TTE64K;
					addr = (caddr_t)roundup((uintptr_t)addr
					    + 1, MMU_PAGESIZE64K);
					continue;
				}
			}
			addr = (caddr_t)roundup((uintptr_t)addr + 1,
			    (1 << hmeshift));
			if ((uintptr_t)addr & MMU_PAGEOFFSET512K) {
				ASSERT(hashno == TTE64K);
				continue;
			}
			if ((uintptr_t)addr & MMU_PAGEOFFSET4M) {
				hashno = TTE512K;
				continue;
			}
			if (mmu_page_sizes == max_mmu_page_sizes) {
				if ((uintptr_t)addr & MMU_PAGEOFFSET32M) {
					hashno = TTE4M;
					continue;
				}
				if ((uintptr_t)addr & MMU_PAGEOFFSET256M) {
					hashno = TTE32M;
					continue;
				}
				hashno = TTE256M;
				continue;
			} else {
				hashno = TTE4M;
				continue;
			}
		}
		ASSERT(hmeblkp);
		ASSERT(!hmeblkp->hblk_shared);
		if (!hmeblkp->hblk_vcnt && !hmeblkp->hblk_hmecnt) {
			/*
			 * If the valid count is zero we can skip the range
			 * mapped by this hmeblk.
			 * We free hblks in the case of HAT_UNMAP.  HAT_UNMAP
			 * is used by segment drivers as a hint
			 * that the mapping resource won't be used any longer.
			 * The best example of this is during exit().
			 */
			addr = (caddr_t)roundup((uintptr_t)addr + 1,
			    get_hblk_span(hmeblkp));
			if ((flags & HAT_UNLOAD_UNMAP) ||
			    (iskernel && !issegkmap)) {
				sfmmu_hblk_hash_rm(hmebp, hmeblkp, pr_hblk,
				    &list, 0);
			}
			SFMMU_HASH_UNLOCK(hmebp);

			if (iskernel) {
				hashno = TTE64K;
				continue;
			}
			if ((uintptr_t)addr & MMU_PAGEOFFSET512K) {
				ASSERT(hashno == TTE64K);
				continue;
			}
			if ((uintptr_t)addr & MMU_PAGEOFFSET4M) {
				hashno = TTE512K;
				continue;
			}
			if (mmu_page_sizes == max_mmu_page_sizes) {
				if ((uintptr_t)addr & MMU_PAGEOFFSET32M) {
					hashno = TTE4M;
					continue;
				}
				if ((uintptr_t)addr & MMU_PAGEOFFSET256M) {
					hashno = TTE32M;
					continue;
				}
				hashno = TTE256M;
				continue;
			} else {
				hashno = TTE4M;
				continue;
			}
		}
		if (hmeblkp->hblk_shw_bit) {
			/*
			 * If we encounter a shadow hmeblk we know there is
			 * smaller sized hmeblks mapping the same address space.
			 * Decrement the hash size and rehash.
			 */
			ASSERT(sfmmup != KHATID);
			hashno--;
			SFMMU_HASH_UNLOCK(hmebp);
			continue;
		}

		/*
		 * track callback address ranges.
		 * only start a new range when it's not contiguous
		 */
		if (callback != NULL) {
			if (addr_count > 0 &&
			    addr == cb_end_addr[addr_count - 1])
				--addr_count;
			else
				cb_start_addr[addr_count] = addr;
		}

		addr = sfmmu_hblk_unload(sfmmup, hmeblkp, addr, endaddr,
		    dmrp, flags);

		if (callback != NULL)
			cb_end_addr[addr_count++] = addr;

		if (((flags & HAT_UNLOAD_UNMAP) || (iskernel && !issegkmap)) &&
		    !hmeblkp->hblk_vcnt && !hmeblkp->hblk_hmecnt) {
			sfmmu_hblk_hash_rm(hmebp, hmeblkp, pr_hblk, &list, 0);
		}
		SFMMU_HASH_UNLOCK(hmebp);

		/*
		 * Notify our caller as to exactly which pages
		 * have been unloaded. We do these in clumps,
		 * to minimize the number of xt_sync()s that need to occur.
		 */
		if (callback != NULL && addr_count == MAX_CB_ADDR) {
			if (dmrp != NULL) {
				DEMAP_RANGE_FLUSH(dmrp);
				cpuset = sfmmup->sfmmu_cpusran;
				xt_sync(cpuset);
			}

			for (a = 0; a < MAX_CB_ADDR; ++a) {
				callback->hcb_start_addr = cb_start_addr[a];
				callback->hcb_end_addr = cb_end_addr[a];
				callback->hcb_function(callback);
			}
			addr_count = 0;
		}
		if (iskernel) {
			hashno = TTE64K;
			continue;
		}
		if ((uintptr_t)addr & MMU_PAGEOFFSET512K) {
			ASSERT(hashno == TTE64K);
			continue;
		}
		if ((uintptr_t)addr & MMU_PAGEOFFSET4M) {
			hashno = TTE512K;
			continue;
		}
		if (mmu_page_sizes == max_mmu_page_sizes) {
			if ((uintptr_t)addr & MMU_PAGEOFFSET32M) {
				hashno = TTE4M;
				continue;
			}
			if ((uintptr_t)addr & MMU_PAGEOFFSET256M) {
				hashno = TTE32M;
				continue;
			}
			hashno = TTE256M;
		} else {
			hashno = TTE4M;
		}
	}

	sfmmu_hblks_list_purge(&list, 0);
	if (dmrp != NULL) {
		DEMAP_RANGE_FLUSH(dmrp);
		cpuset = sfmmup->sfmmu_cpusran;
		xt_sync(cpuset);
	}
	if (callback && addr_count != 0) {
		for (a = 0; a < addr_count; ++a) {
			callback->hcb_start_addr = cb_start_addr[a];
			callback->hcb_end_addr = cb_end_addr[a];
			callback->hcb_function(callback);
		}
	}

	/*
	 * Check TSB and TLB page sizes if the process isn't exiting.
	 */
	if (!sfmmup->sfmmu_free)
		sfmmu_check_page_sizes(sfmmup, 0);
}

/*
 * Unload all the mappings in the range [addr..addr+len). addr and len must
 * be MMU_PAGESIZE aligned.
 */
void
hat_unload(struct hat *sfmmup, caddr_t addr, size_t len, uint_t flags)
{
	hat_unload_callback(sfmmup, addr, len, flags, NULL);
}


/*
 * Find the largest mapping size for this page.
 */
int
fnd_mapping_sz(page_t *pp)
{
	int sz;
	int p_index;

	p_index = PP_MAPINDEX(pp);

	sz = 0;
	p_index >>= 1;	/* don't care about 8K bit */
	for (; p_index; p_index >>= 1) {
		sz++;
	}

	return (sz);
}

/*
 * This function unloads a range of addresses for an hmeblk.
 * It returns the next address to be unloaded.
 * It should be called with the hash lock held.
 */
static caddr_t
sfmmu_hblk_unload(struct hat *sfmmup, struct hme_blk *hmeblkp, caddr_t addr,
	caddr_t endaddr, demap_range_t *dmrp, uint_t flags)
{
	tte_t	tte, ttemod;
	struct	sf_hment *sfhmep;
	int	ttesz;
	long	ttecnt;
	page_t *pp;
	kmutex_t *pml;
	int ret;
	int use_demap_range;

	ASSERT(in_hblk_range(hmeblkp, addr));
	ASSERT(!hmeblkp->hblk_shw_bit);
	ASSERT(sfmmup != NULL || hmeblkp->hblk_shared);
	ASSERT(sfmmup == NULL || !hmeblkp->hblk_shared);
	ASSERT(dmrp == NULL || !hmeblkp->hblk_shared);

#ifdef DEBUG
	if (get_hblk_ttesz(hmeblkp) != TTE8K &&
	    (endaddr < get_hblk_endaddr(hmeblkp))) {
		panic("sfmmu_hblk_unload: partial unload of large page");
	}
#endif /* DEBUG */

	endaddr = MIN(endaddr, get_hblk_endaddr(hmeblkp));
	ttesz = get_hblk_ttesz(hmeblkp);

	use_demap_range = ((dmrp == NULL) ||
	    (TTEBYTES(ttesz) == DEMAP_RANGE_PGSZ(dmrp)));

	if (use_demap_range) {
		DEMAP_RANGE_CONTINUE(dmrp, addr, endaddr);
	} else if (dmrp != NULL) {
		DEMAP_RANGE_FLUSH(dmrp);
	}
	ttecnt = 0;
	HBLKTOHME(sfhmep, hmeblkp, addr);

	while (addr < endaddr) {
		pml = NULL;
		sfmmu_copytte(&sfhmep->hme_tte, &tte);
		if (TTE_IS_VALID(&tte)) {
			pp = sfhmep->hme_page;
			if (pp != NULL) {
				pml = sfmmu_mlist_enter(pp);
			}

			/*
			 * Verify if hme still points to 'pp' now that
			 * we have p_mapping lock.
			 */
			if (sfhmep->hme_page != pp) {
				if (pp != NULL && sfhmep->hme_page != NULL) {
					ASSERT(pml != NULL);
					sfmmu_mlist_exit(pml);
					/* Re-start this iteration. */
					continue;
				}
				ASSERT((pp != NULL) &&
				    (sfhmep->hme_page == NULL));
				goto tte_unloaded;
			}

			/*
			 * This point on we have both HASH and p_mapping
			 * lock.
			 */
			ASSERT(pp == sfhmep->hme_page);
			ASSERT(pp == NULL || sfmmu_mlist_held(pp));

			/*
			 * We need to loop on modify tte because it is
			 * possible for pagesync to come along and
			 * change the software bits beneath us.
			 *
			 * Page_unload can also invalidate the tte after
			 * we read tte outside of p_mapping lock.
			 */
again:
			ttemod = tte;

			TTE_SET_INVALID(&ttemod);
			ret = sfmmu_modifytte_try(&tte, &ttemod,
			    &sfhmep->hme_tte);

			if (ret <= 0) {
				if (TTE_IS_VALID(&tte)) {
					ASSERT(ret < 0);
					goto again;
				}
				if (pp != NULL) {
					panic("sfmmu_hblk_unload: pp = 0x%p "
					    "tte became invalid under mlist"
					    " lock = 0x%p", (void *)pp,
					    (void *)pml);
				}
				continue;
			}

			if (!(flags & HAT_UNLOAD_NOSYNC)) {
				sfmmu_ttesync(sfmmup, addr, &tte, pp);
			}

			/*
			 * Ok- we invalidated the tte. Do the rest of the job.
			 */
			ttecnt++;

			if (flags & HAT_UNLOAD_UNLOCK) {
				ASSERT(hmeblkp->hblk_lckcnt > 0);
				atomic_dec_32(&hmeblkp->hblk_lckcnt);
				HBLK_STACK_TRACE(hmeblkp, HBLK_UNLOCK);
			}

			/*
			 * Normally we would need to flush the page
			 * from the virtual cache at this point in
			 * order to prevent a potential cache alias
			 * inconsistency.
			 * The particular scenario we need to worry
			 * about is:
			 * Given:  va1 and va2 are two virtual address
			 * that alias and map the same physical
			 * address.
			 * 1.   mapping exists from va1 to pa and data
			 * has been read into the cache.
			 * 2.   unload va1.
			 * 3.   load va2 and modify data using va2.
			 * 4    unload va2.
			 * 5.   load va1 and reference data.  Unless we
			 * flush the data cache when we unload we will
			 * get stale data.
			 * Fortunately, page coloring eliminates the
			 * above scenario by remembering the color a
			 * physical page was last or is currently
			 * mapped to.  Now, we delay the flush until
			 * the loading of translations.  Only when the
			 * new translation is of a different color
			 * are we forced to flush.
			 */
			if (use_demap_range) {
				/*
				 * Mark this page as needing a demap.
				 */
				DEMAP_RANGE_MARKPG(dmrp, addr);
			} else {
				ASSERT(sfmmup != NULL);
				ASSERT(!hmeblkp->hblk_shared);
				sfmmu_tlb_demap(addr, sfmmup, hmeblkp,
				    sfmmup->sfmmu_free, 0);
			}

			if (pp) {
				/*
				 * Remove the hment from the mapping list
				 */
				ASSERT(hmeblkp->hblk_hmecnt > 0);

				/*
				 * Again, we cannot
				 * ASSERT(hmeblkp->hblk_hmecnt <= NHMENTS);
				 */
				HME_SUB(sfhmep, pp);
				membar_stst();
				atomic_dec_16(&hmeblkp->hblk_hmecnt);
			}

			ASSERT(hmeblkp->hblk_vcnt > 0);
			atomic_dec_16(&hmeblkp->hblk_vcnt);

			ASSERT(hmeblkp->hblk_hmecnt || hmeblkp->hblk_vcnt ||
			    !hmeblkp->hblk_lckcnt);

#ifdef VAC
			if (pp && (pp->p_nrm & (P_KPMC | P_KPMS | P_TNC))) {
				if (PP_ISTNC(pp)) {
					/*
					 * If page was temporary
					 * uncached, try to recache
					 * it. Note that HME_SUB() was
					 * called above so p_index and
					 * mlist had been updated.
					 */
					conv_tnc(pp, ttesz);
				} else if (pp->p_mapping == NULL) {
					ASSERT(kpm_enable);
					/*
					 * Page is marked to be in VAC conflict
					 * to an existing kpm mapping and/or is
					 * kpm mapped using only the regular
					 * pagesize.
					 */
					sfmmu_kpm_hme_unload(pp);
				}
			}
#endif	/* VAC */
		} else if ((pp = sfhmep->hme_page) != NULL) {
				/*
				 * TTE is invalid but the hme
				 * still exists. let pageunload
				 * complete its job.
				 */
				ASSERT(pml == NULL);
				pml = sfmmu_mlist_enter(pp);
				if (sfhmep->hme_page != NULL) {
					sfmmu_mlist_exit(pml);
					continue;
				}
				ASSERT(sfhmep->hme_page == NULL);
		} else if (hmeblkp->hblk_hmecnt != 0) {
			/*
			 * pageunload may have not finished decrementing
			 * hblk_vcnt and hblk_hmecnt. Find page_t if any and
			 * wait for pageunload to finish. Rely on pageunload
			 * to decrement hblk_hmecnt after hblk_vcnt.
			 */
			pfn_t pfn = TTE_TO_TTEPFN(&tte);
			ASSERT(pml == NULL);
			if (pf_is_memory(pfn)) {
				pp = page_numtopp_nolock(pfn);
				if (pp != NULL) {
					pml = sfmmu_mlist_enter(pp);
					sfmmu_mlist_exit(pml);
					pml = NULL;
				}
			}
		}

tte_unloaded:
		/*
		 * At this point, the tte we are looking at
		 * should be unloaded, and hme has been unlinked
		 * from page too. This is important because in
		 * pageunload, it does ttesync() then HME_SUB.
		 * We need to make sure HME_SUB has been completed
		 * so we know ttesync() has been completed. Otherwise,
		 * at exit time, after return from hat layer, VM will
		 * release as structure which hat_setstat() (called
		 * by ttesync()) needs.
		 */
#ifdef DEBUG
		{
			tte_t	dtte;

			ASSERT(sfhmep->hme_page == NULL);

			sfmmu_copytte(&sfhmep->hme_tte, &dtte);
			ASSERT(!TTE_IS_VALID(&dtte));
		}
#endif

		if (pml) {
			sfmmu_mlist_exit(pml);
		}

		addr += TTEBYTES(ttesz);
		sfhmep++;
		DEMAP_RANGE_NEXTPG(dmrp);
	}
	/*
	 * For shared hmeblks this routine is only called when region is freed
	 * and no longer referenced.  So no need to decrement ttecnt
	 * in the region structure here.
	 */
	if (ttecnt > 0 && sfmmup != NULL) {
		atomic_add_long(&sfmmup->sfmmu_ttecnt[ttesz], -ttecnt);
	}
	return (addr);
}

/*
 * Invalidate a virtual address range for the local CPU.
 * For best performance ensure that the va range is completely
 * mapped, otherwise the entire TLB will be flushed.
 */
void
hat_flush_range(struct hat *sfmmup, caddr_t va, size_t size)
{
	ssize_t sz;
	caddr_t endva = va + size;

	while (va < endva) {
		sz = hat_getpagesize(sfmmup, va);
		if (sz < 0) {
			vtag_flushall();
			break;
		}
		vtag_flushpage(va, (uint64_t)sfmmup);
		va += sz;
	}
}

/*
 * Synchronize all the mappings in the range [addr..addr+len).
 * Can be called with clearflag having two states:
 * HAT_SYNC_DONTZERO means just return the rm stats
 * HAT_SYNC_ZERORM means zero rm bits in the tte and return the stats
 */
void
hat_sync(struct hat *sfmmup, caddr_t addr, size_t len, uint_t clearflag)
{
	struct hmehash_bucket *hmebp;
	hmeblk_tag hblktag;
	int hmeshift, hashno = 1;
	struct hme_blk *hmeblkp, *list = NULL;
	caddr_t endaddr;
	cpuset_t cpuset;

	ASSERT((sfmmup == ksfmmup) || AS_LOCK_HELD(sfmmup->sfmmu_as));
	ASSERT((len & MMU_PAGEOFFSET) == 0);
	ASSERT((clearflag == HAT_SYNC_DONTZERO) ||
	    (clearflag == HAT_SYNC_ZERORM));

	CPUSET_ZERO(cpuset);

	endaddr = addr + len;
	hblktag.htag_id = sfmmup;
	hblktag.htag_rid = SFMMU_INVALID_SHMERID;

	/*
	 * Spitfire supports 4 page sizes.
	 * Most pages are expected to be of the smallest page
	 * size (8K) and these will not need to be rehashed. 64K
	 * pages also don't need to be rehashed because the an hmeblk
	 * spans 64K of address space. 512K pages might need 1 rehash and
	 * and 4M pages 2 rehashes.
	 */
	while (addr < endaddr) {
		hmeshift = HME_HASH_SHIFT(hashno);
		hblktag.htag_bspage = HME_HASH_BSPAGE(addr, hmeshift);
		hblktag.htag_rehash = hashno;
		hmebp = HME_HASH_FUNCTION(sfmmup, addr, hmeshift);

		SFMMU_HASH_LOCK(hmebp);

		HME_HASH_SEARCH(hmebp, hblktag, hmeblkp, &list);
		if (hmeblkp != NULL) {
			ASSERT(!hmeblkp->hblk_shared);
			/*
			 * We've encountered a shadow hmeblk so skip the range
			 * of the next smaller mapping size.
			 */
			if (hmeblkp->hblk_shw_bit) {
				ASSERT(sfmmup != ksfmmup);
				ASSERT(hashno > 1);
				addr = (caddr_t)P2END((uintptr_t)addr,
				    TTEBYTES(hashno - 1));
			} else {
				addr = sfmmu_hblk_sync(sfmmup, hmeblkp,
				    addr, endaddr, clearflag);
			}
			SFMMU_HASH_UNLOCK(hmebp);
			hashno = 1;
			continue;
		}
		SFMMU_HASH_UNLOCK(hmebp);

		if (!HME_REHASH(sfmmup) || (hashno >= mmu_hashcnt)) {
			/*
			 * We have traversed the whole list and rehashed
			 * if necessary without finding the address to sync.
			 * This is ok so we increment the address by the
			 * smallest hmeblk range for kernel mappings and the
			 * largest hmeblk range, to account for shadow hmeblks,
			 * for user mappings and continue.
			 */
			if (sfmmup == ksfmmup)
				addr = (caddr_t)P2END((uintptr_t)addr,
				    TTEBYTES(1));
			else
				addr = (caddr_t)P2END((uintptr_t)addr,
				    TTEBYTES(hashno));
			hashno = 1;
		} else {
			hashno++;
		}
	}
	sfmmu_hblks_list_purge(&list, 0);
	cpuset = sfmmup->sfmmu_cpusran;
	xt_sync(cpuset);
}

static caddr_t
sfmmu_hblk_sync(struct hat *sfmmup, struct hme_blk *hmeblkp, caddr_t addr,
	caddr_t endaddr, int clearflag)
{
	tte_t	tte, ttemod;
	struct sf_hment *sfhmep;
	int ttesz;
	struct page *pp;
	kmutex_t *pml;
	int ret;

	ASSERT(hmeblkp->hblk_shw_bit == 0);
	ASSERT(!hmeblkp->hblk_shared);

	endaddr = MIN(endaddr, get_hblk_endaddr(hmeblkp));

	ttesz = get_hblk_ttesz(hmeblkp);
	HBLKTOHME(sfhmep, hmeblkp, addr);

	while (addr < endaddr) {
		sfmmu_copytte(&sfhmep->hme_tte, &tte);
		if (TTE_IS_VALID(&tte)) {
			pml = NULL;
			pp = sfhmep->hme_page;
			if (pp) {
				pml = sfmmu_mlist_enter(pp);
			}
			if (pp != sfhmep->hme_page) {
				/*
				 * tte most have been unloaded
				 * underneath us.  Recheck
				 */
				ASSERT(pml);
				sfmmu_mlist_exit(pml);
				continue;
			}

			ASSERT(pp == NULL || sfmmu_mlist_held(pp));

			if (clearflag == HAT_SYNC_ZERORM) {
				ttemod = tte;
				TTE_CLR_RM(&ttemod);
				ret = sfmmu_modifytte_try(&tte, &ttemod,
				    &sfhmep->hme_tte);
				if (ret < 0) {
					if (pml) {
						sfmmu_mlist_exit(pml);
					}
					continue;
				}

				if (ret > 0) {
					sfmmu_tlb_demap(addr, sfmmup,
					    hmeblkp, 0, 0);
				}
			}
			sfmmu_ttesync(sfmmup, addr, &tte, pp);
			if (pml) {
				sfmmu_mlist_exit(pml);
			}
		}
		addr += TTEBYTES(ttesz);
		sfhmep++;
	}
	return (addr);
}

/*
 * This function will sync a tte to the page struct and it will
 * update the hat stats. Currently it allows us to pass a NULL pp
 * and we will simply update the stats.  We may want to change this
 * so we only keep stats for pages backed by pp's.
 */
static void
sfmmu_ttesync(struct hat *sfmmup, caddr_t addr, tte_t *ttep, page_t *pp)
{
	uint_t rm = 0;
	int   	sz;
	pgcnt_t	npgs;

	ASSERT(TTE_IS_VALID(ttep));

	if (TTE_IS_NOSYNC(ttep)) {
		return;
	}

	if (TTE_IS_REF(ttep))  {
		rm = P_REF;
	}
	if (TTE_IS_MOD(ttep))  {
		rm |= P_MOD;
	}

	if (rm == 0) {
		return;
	}

	sz = TTE_CSZ(ttep);
	if (sfmmup != NULL && sfmmup->sfmmu_rmstat) {
		int i;
		caddr_t	vaddr = addr;

		for (i = 0; i < TTEPAGES(sz); i++, vaddr += MMU_PAGESIZE) {
			hat_setstat(sfmmup->sfmmu_as, vaddr, MMU_PAGESIZE, rm);
		}

	}

	/*
	 * XXX I want to use cas to update nrm bits but they
	 * currently belong in common/vm and not in hat where
	 * they should be.
	 * The nrm bits are protected by the same mutex as
	 * the one that protects the page's mapping list.
	 */
	if (!pp)
		return;
	ASSERT(sfmmu_mlist_held(pp));
	/*
	 * If the tte is for a large page, we need to sync all the
	 * pages covered by the tte.
	 */
	if (sz != TTE8K) {
		ASSERT(pp->p_szc != 0);
		pp = PP_GROUPLEADER(pp, sz);
		ASSERT(sfmmu_mlist_held(pp));
	}

	/* Get number of pages from tte size. */
	npgs = TTEPAGES(sz);

	do {
		ASSERT(pp);
		ASSERT(sfmmu_mlist_held(pp));
		if (((rm & P_REF) != 0 && !PP_ISREF(pp)) ||
		    ((rm & P_MOD) != 0 && !PP_ISMOD(pp)))
			hat_page_setattr(pp, rm);

		/*
		 * Are we done? If not, we must have a large mapping.
		 * For large mappings we need to sync the rest of the pages
		 * covered by this tte; goto the next page.
		 */
	} while (--npgs > 0 && (pp = PP_PAGENEXT(pp)));
}

/*
 * Execute pre-callback handler of each pa_hment linked to pp
 *
 * Inputs:
 *   flag: either HAT_PRESUSPEND or HAT_SUSPEND.
 *   capture_cpus: pointer to return value (below)
 *
 * Returns:
 *   Propagates the subsystem callback return values back to the caller;
 *   returns 0 on success.  If capture_cpus is non-NULL, the value returned
 *   is zero if all of the pa_hments are of a type that do not require
 *   capturing CPUs prior to suspending the mapping, else it is 1.
 */
static int
hat_pageprocess_precallbacks(struct page *pp, uint_t flag, int *capture_cpus)
{
	struct sf_hment	*sfhmep;
	struct pa_hment *pahmep;
	int (*f)(caddr_t, uint_t, uint_t, void *);
	int		ret;
	id_t		id;
	int		locked = 0;
	kmutex_t	*pml;

	ASSERT(PAGE_EXCL(pp));
	if (!sfmmu_mlist_held(pp)) {
		pml = sfmmu_mlist_enter(pp);
		locked = 1;
	}

	if (capture_cpus)
		*capture_cpus = 0;

top:
	for (sfhmep = pp->p_mapping; sfhmep; sfhmep = sfhmep->hme_next) {
		/*
		 * skip sf_hments corresponding to VA<->PA mappings;
		 * for pa_hment's, hme_tte.ll is zero
		 */
		if (!IS_PAHME(sfhmep))
			continue;

		pahmep = sfhmep->hme_data;
		ASSERT(pahmep != NULL);

		/*
		 * skip if pre-handler has been called earlier in this loop
		 */
		if (pahmep->flags & flag)
			continue;

		id = pahmep->cb_id;
		ASSERT(id >= (id_t)0 && id < sfmmu_cb_nextid);
		if (capture_cpus && sfmmu_cb_table[id].capture_cpus != 0)
			*capture_cpus = 1;
		if ((f = sfmmu_cb_table[id].prehandler) == NULL) {
			pahmep->flags |= flag;
			continue;
		}

		/*
		 * Drop the mapping list lock to avoid locking order issues.
		 */
		if (locked)
			sfmmu_mlist_exit(pml);

		ret = f(pahmep->addr, pahmep->len, flag, pahmep->pvt);
		if (ret != 0)
			return (ret);	/* caller must do the cleanup */

		if (locked) {
			pml = sfmmu_mlist_enter(pp);
			pahmep->flags |= flag;
			goto top;
		}

		pahmep->flags |= flag;
	}

	if (locked)
		sfmmu_mlist_exit(pml);

	return (0);
}

/*
 * Execute post-callback handler of each pa_hment linked to pp
 *
 * Same overall assumptions and restrictions apply as for
 * hat_pageprocess_precallbacks().
 */
static void
hat_pageprocess_postcallbacks(struct page *pp, uint_t flag)
{
	pfn_t pgpfn = pp->p_pagenum;
	pfn_t pgmask = btop(page_get_pagesize(pp->p_szc)) - 1;
	pfn_t newpfn;
	struct sf_hment *sfhmep;
	struct pa_hment *pahmep;
	int (*f)(caddr_t, uint_t, uint_t, void *, pfn_t);
	id_t	id;
	int	locked = 0;
	kmutex_t *pml;

	ASSERT(PAGE_EXCL(pp));
	if (!sfmmu_mlist_held(pp)) {
		pml = sfmmu_mlist_enter(pp);
		locked = 1;
	}

top:
	for (sfhmep = pp->p_mapping; sfhmep; sfhmep = sfhmep->hme_next) {
		/*
		 * skip sf_hments corresponding to VA<->PA mappings;
		 * for pa_hment's, hme_tte.ll is zero
		 */
		if (!IS_PAHME(sfhmep))
			continue;

		pahmep = sfhmep->hme_data;
		ASSERT(pahmep != NULL);

		if ((pahmep->flags & flag) == 0)
			continue;

		pahmep->flags &= ~flag;

		id = pahmep->cb_id;
		ASSERT(id >= (id_t)0 && id < sfmmu_cb_nextid);
		if ((f = sfmmu_cb_table[id].posthandler) == NULL)
			continue;

		/*
		 * Convert the base page PFN into the constituent PFN
		 * which is needed by the callback handler.
		 */
		newpfn = pgpfn | (btop((uintptr_t)pahmep->addr) & pgmask);

		/*
		 * Drop the mapping list lock to avoid locking order issues.
		 */
		if (locked)
			sfmmu_mlist_exit(pml);

		if (f(pahmep->addr, pahmep->len, flag, pahmep->pvt, newpfn)
		    != 0)
			panic("sfmmu: posthandler failed");

		if (locked) {
			pml = sfmmu_mlist_enter(pp);
			goto top;
		}
	}

	if (locked)
		sfmmu_mlist_exit(pml);
}

/*
 * Suspend locked kernel mapping
 */
void
hat_pagesuspend(struct page *pp)
{
	struct sf_hment *sfhmep;
	sfmmu_t *sfmmup;
	tte_t tte, ttemod;
	struct hme_blk *hmeblkp;
	caddr_t addr;
	int index, cons;
	cpuset_t cpuset;

	ASSERT(PAGE_EXCL(pp));
	ASSERT(sfmmu_mlist_held(pp));

	mutex_enter(&kpr_suspendlock);

	/*
	 * We're about to suspend a kernel mapping so mark this thread as
	 * non-traceable by DTrace. This prevents us from running into issues
	 * with probe context trying to touch a suspended page
	 * in the relocation codepath itself.
	 */
	curthread->t_flag |= T_DONTDTRACE;

	index = PP_MAPINDEX(pp);
	cons = TTE8K;

retry:
	for (sfhmep = pp->p_mapping; sfhmep; sfhmep = sfhmep->hme_next) {

		if (IS_PAHME(sfhmep))
			continue;

		if (get_hblk_ttesz(sfmmu_hmetohblk(sfhmep)) != cons)
			continue;

		/*
		 * Loop until we successfully set the suspend bit in
		 * the TTE.
		 */
again:
		sfmmu_copytte(&sfhmep->hme_tte, &tte);
		ASSERT(TTE_IS_VALID(&tte));

		ttemod = tte;
		TTE_SET_SUSPEND(&ttemod);
		if (sfmmu_modifytte_try(&tte, &ttemod,
		    &sfhmep->hme_tte) < 0)
			goto again;

		/*
		 * Invalidate TSB entry
		 */
		hmeblkp = sfmmu_hmetohblk(sfhmep);

		sfmmup = hblktosfmmu(hmeblkp);
		ASSERT(sfmmup == ksfmmup);
		ASSERT(!hmeblkp->hblk_shared);

		addr = tte_to_vaddr(hmeblkp, tte);

		/*
		 * No need to make sure that the TSB for this sfmmu is
		 * not being relocated since it is ksfmmup and thus it
		 * will never be relocated.
		 */
		SFMMU_UNLOAD_TSB(addr, sfmmup, hmeblkp, 0);

		/*
		 * Update xcall stats
		 */
		cpuset = cpu_ready_set;
		CPUSET_DEL(cpuset, CPU->cpu_id);

		/* LINTED: constant in conditional context */
		SFMMU_XCALL_STATS(ksfmmup);

		/*
		 * Flush TLB entry on remote CPU's
		 */
		xt_some(cpuset, vtag_flushpage_tl1, (uint64_t)addr,
		    (uint64_t)ksfmmup);
		xt_sync(cpuset);

		/*
		 * Flush TLB entry on local CPU
		 */
		vtag_flushpage(addr, (uint64_t)ksfmmup);
	}

	while (index != 0) {
		index = index >> 1;
		if (index != 0)
			cons++;
		if (index & 0x1) {
			pp = PP_GROUPLEADER(pp, cons);
			goto retry;
		}
	}
}

#ifdef	DEBUG

#define	N_PRLE	1024
struct prle {
	page_t *targ;
	page_t *repl;
	int status;
	int pausecpus;
	hrtime_t whence;
};

static struct prle page_relocate_log[N_PRLE];
static int prl_entry;
static kmutex_t prl_mutex;

#define	PAGE_RELOCATE_LOG(t, r, s, p)					\
	mutex_enter(&prl_mutex);					\
	page_relocate_log[prl_entry].targ = *(t);			\
	page_relocate_log[prl_entry].repl = *(r);			\
	page_relocate_log[prl_entry].status = (s);			\
	page_relocate_log[prl_entry].pausecpus = (p);			\
	page_relocate_log[prl_entry].whence = gethrtime();		\
	prl_entry = (prl_entry == (N_PRLE - 1))? 0 : prl_entry + 1;	\
	mutex_exit(&prl_mutex);

#else	/* !DEBUG */
#define	PAGE_RELOCATE_LOG(t, r, s, p)
#endif

/*
 * Core Kernel Page Relocation Algorithm
 *
 * Input:
 *
 * target : 	constituent pages are SE_EXCL locked.
 * replacement:	constituent pages are SE_EXCL locked.
 *
 * Output:
 *
 * nrelocp:	number of pages relocated
 */
int
hat_page_relocate(page_t **target, page_t **replacement, spgcnt_t *nrelocp)
{
	page_t		*targ, *repl;
	page_t		*tpp, *rpp;
	kmutex_t	*low, *high;
	spgcnt_t	npages, i;
	page_t		*pl = NULL;
	int		old_pil;
	cpuset_t	cpuset;
	int		cap_cpus;
	int		ret;
#ifdef VAC
	int		cflags = 0;
#endif

	if (!kcage_on || PP_ISNORELOC(*target)) {
		PAGE_RELOCATE_LOG(target, replacement, EAGAIN, -1);
		return (EAGAIN);
	}

	mutex_enter(&kpr_mutex);
	kreloc_thread = curthread;

	targ = *target;
	repl = *replacement;
	ASSERT(repl != NULL);
	ASSERT(targ->p_szc == repl->p_szc);

	npages = page_get_pagecnt(targ->p_szc);

	/*
	 * unload VA<->PA mappings that are not locked
	 */
	tpp = targ;
	for (i = 0; i < npages; i++) {
		(void) hat_pageunload(tpp, SFMMU_KERNEL_RELOC);
		tpp++;
	}

	/*
	 * Do "presuspend" callbacks, in a context from which we can still
	 * block as needed. Note that we don't hold the mapping list lock
	 * of "targ" at this point due to potential locking order issues;
	 * we assume that between the hat_pageunload() above and holding
	 * the SE_EXCL lock that the mapping list *cannot* change at this
	 * point.
	 */
	ret = hat_pageprocess_precallbacks(targ, HAT_PRESUSPEND, &cap_cpus);
	if (ret != 0) {
		/*
		 * EIO translates to fatal error, for all others cleanup
		 * and return EAGAIN.
		 */
		ASSERT(ret != EIO);
		hat_pageprocess_postcallbacks(targ, HAT_POSTUNSUSPEND);
		PAGE_RELOCATE_LOG(target, replacement, ret, -1);
		kreloc_thread = NULL;
		mutex_exit(&kpr_mutex);
		return (EAGAIN);
	}

	/*
	 * acquire p_mapping list lock for both the target and replacement
	 * root pages.
	 *
	 * low and high refer to the need to grab the mlist locks in a
	 * specific order in order to prevent race conditions.  Thus the
	 * lower lock must be grabbed before the higher lock.
	 *
	 * This will block hat_unload's accessing p_mapping list.  Since
	 * we have SE_EXCL lock, hat_memload and hat_pageunload will be
	 * blocked.  Thus, no one else will be accessing the p_mapping list
	 * while we suspend and reload the locked mapping below.
	 */
	tpp = targ;
	rpp = repl;
	sfmmu_mlist_reloc_enter(tpp, rpp, &low, &high);

	kpreempt_disable();

	/*
	 * We raise our PIL to 13 so that we don't get captured by
	 * another CPU or pinned by an interrupt thread.  We can't go to
	 * PIL 14 since the nexus driver(s) may need to interrupt at
	 * that level in the case of IOMMU pseudo mappings.
	 */
	cpuset = cpu_ready_set;
	CPUSET_DEL(cpuset, CPU->cpu_id);
	if (!cap_cpus || CPUSET_ISNULL(cpuset)) {
		old_pil = splr(XCALL_PIL);
	} else {
		old_pil = -1;
		xc_attention(cpuset);
	}
	ASSERT(getpil() == XCALL_PIL);

	/*
	 * Now do suspend callbacks. In the case of an IOMMU mapping
	 * this will suspend all DMA activity to the page while it is
	 * being relocated. Since we are well above LOCK_LEVEL and CPUs
	 * may be captured at this point we should have acquired any needed
	 * locks in the presuspend callback.
	 */
	ret = hat_pageprocess_precallbacks(targ, HAT_SUSPEND, NULL);
	if (ret != 0) {
		repl = targ;
		goto suspend_fail;
	}

	/*
	 * Raise the PIL yet again, this time to block all high-level
	 * interrupts on this CPU. This is necessary to prevent an
	 * interrupt routine from pinning the thread which holds the
	 * mapping suspended and then touching the suspended page.
	 *
	 * Once the page is suspended we also need to be careful to
	 * avoid calling any functions which touch any seg_kmem memory
	 * since that memory may be backed by the very page we are
	 * relocating in here!
	 */
	hat_pagesuspend(targ);

	/*
	 * Now that we are confident everybody has stopped using this page,
	 * copy the page contents.  Note we use a physical copy to prevent
	 * locking issues and to avoid fpRAS because we can't handle it in
	 * this context.
	 */
	for (i = 0; i < npages; i++, tpp++, rpp++) {
#ifdef VAC
		/*
		 * If the replacement has a different vcolor than
		 * the one being replacd, we need to handle VAC
		 * consistency for it just as we were setting up
		 * a new mapping to it.
		 */
		if ((PP_GET_VCOLOR(rpp) != NO_VCOLOR) &&
		    (tpp->p_vcolor != rpp->p_vcolor) &&
		    !CacheColor_IsFlushed(cflags, PP_GET_VCOLOR(rpp))) {
			CacheColor_SetFlushed(cflags, PP_GET_VCOLOR(rpp));
			sfmmu_cache_flushcolor(PP_GET_VCOLOR(rpp),
			    rpp->p_pagenum);
		}
#endif
		/*
		 * Copy the contents of the page.
		 */
		ppcopy_kernel(tpp, rpp);
	}

	tpp = targ;
	rpp = repl;
	for (i = 0; i < npages; i++, tpp++, rpp++) {
		/*
		 * Copy attributes.  VAC consistency was handled above,
		 * if required.
		 */
		rpp->p_nrm = tpp->p_nrm;
		tpp->p_nrm = 0;
		rpp->p_index = tpp->p_index;
		tpp->p_index = 0;
#ifdef VAC
		rpp->p_vcolor = tpp->p_vcolor;
#endif
	}

	/*
	 * First, unsuspend the page, if we set the suspend bit, and transfer
	 * the mapping list from the target page to the replacement page.
	 * Next process postcallbacks; since pa_hment's are linked only to the
	 * p_mapping list of root page, we don't iterate over the constituent
	 * pages.
	 */
	hat_pagereload(targ, repl);

suspend_fail:
	hat_pageprocess_postcallbacks(repl, HAT_UNSUSPEND);

	/*
	 * Now lower our PIL and release any captured CPUs since we
	 * are out of the "danger zone".  After this it will again be
	 * safe to acquire adaptive mutex locks, or to drop them...
	 */
	if (old_pil != -1) {
		splx(old_pil);
	} else {
		xc_dismissed(cpuset);
	}

	kpreempt_enable();

	sfmmu_mlist_reloc_exit(low, high);

	/*
	 * Postsuspend callbacks should drop any locks held across
	 * the suspend callbacks.  As before, we don't hold the mapping
	 * list lock at this point.. our assumption is that the mapping
	 * list still can't change due to our holding SE_EXCL lock and
	 * there being no unlocked mappings left. Hence the restriction
	 * on calling context to hat_delete_callback()
	 */
	hat_pageprocess_postcallbacks(repl, HAT_POSTUNSUSPEND);
	if (ret != 0) {
		/*
		 * The second presuspend call failed: we got here through
		 * the suspend_fail label above.
		 */
		ASSERT(ret != EIO);
		PAGE_RELOCATE_LOG(target, replacement, ret, cap_cpus);
		kreloc_thread = NULL;
		mutex_exit(&kpr_mutex);
		return (EAGAIN);
	}

	/*
	 * Now that we're out of the performance critical section we can
	 * take care of updating the hash table, since we still
	 * hold all the pages locked SE_EXCL at this point we
	 * needn't worry about things changing out from under us.
	 */
	tpp = targ;
	rpp = repl;
	for (i = 0; i < npages; i++, tpp++, rpp++) {

		/*
		 * replace targ with replacement in page_hash table
		 */
		targ = tpp;
		page_relocate_hash(rpp, targ);

		/*
		 * concatenate target; caller of platform_page_relocate()
		 * expects target to be concatenated after returning.
		 */
		ASSERT(targ->p_next == targ);
		ASSERT(targ->p_prev == targ);
		page_list_concat(&pl, &targ);
	}

	ASSERT(*target == pl);
	*nrelocp = npages;
	PAGE_RELOCATE_LOG(target, replacement, 0, cap_cpus);
	kreloc_thread = NULL;
	mutex_exit(&kpr_mutex);
	return (0);
}

/*
 * Called when stray pa_hments are found attached to a page which is
 * being freed.  Notify the subsystem which attached the pa_hment of
 * the error if it registered a suitable handler, else panic.
 */
static void
sfmmu_pahment_leaked(struct pa_hment *pahmep)
{
	id_t cb_id = pahmep->cb_id;

	ASSERT(cb_id >= (id_t)0 && cb_id < sfmmu_cb_nextid);
	if (sfmmu_cb_table[cb_id].errhandler != NULL) {
		if (sfmmu_cb_table[cb_id].errhandler(pahmep->addr, pahmep->len,
		    HAT_CB_ERR_LEAKED, pahmep->pvt) == 0)
			return;		/* non-fatal */
	}
	panic("pa_hment leaked: 0x%p", (void *)pahmep);
}

/*
 * Remove all mappings to page 'pp'.
 */
int
hat_pageunload(struct page *pp, uint_t forceflag)
{
	struct page *origpp = pp;
	struct sf_hment *sfhme, *tmphme;
	struct hme_blk *hmeblkp;
	kmutex_t *pml;
#ifdef VAC
	kmutex_t *pmtx;
#endif
	cpuset_t cpuset, tset;
	int index, cons;
	int pa_hments;

	ASSERT(PAGE_EXCL(pp));

	tmphme = NULL;
	pa_hments = 0;
	CPUSET_ZERO(cpuset);

	pml = sfmmu_mlist_enter(pp);

#ifdef VAC
	if (pp->p_kpmref)
		sfmmu_kpm_pageunload(pp);
	ASSERT(!PP_ISMAPPED_KPM(pp));
#endif
	/*
	 * Clear vpm reference. Since the page is exclusively locked
	 * vpm cannot be referencing it.
	 */
	if (vpm_enable) {
		pp->p_vpmref = 0;
	}

	index = PP_MAPINDEX(pp);
	cons = TTE8K;
retry:
	for (sfhme = pp->p_mapping; sfhme; sfhme = tmphme) {
		tmphme = sfhme->hme_next;

		if (IS_PAHME(sfhme)) {
			ASSERT(sfhme->hme_data != NULL);
			pa_hments++;
			continue;
		}

		hmeblkp = sfmmu_hmetohblk(sfhme);

		/*
		 * If there are kernel mappings don't unload them, they will
		 * be suspended.
		 */
		if (forceflag == SFMMU_KERNEL_RELOC && hmeblkp->hblk_lckcnt &&
		    hmeblkp->hblk_tag.htag_id == ksfmmup)
			continue;

		tset = sfmmu_pageunload(pp, sfhme, cons);
		CPUSET_OR(cpuset, tset);
	}

	while (index != 0) {
		index = index >> 1;
		if (index != 0)
			cons++;
		if (index & 0x1) {
			/* Go to leading page */
			pp = PP_GROUPLEADER(pp, cons);
			ASSERT(sfmmu_mlist_held(pp));
			goto retry;
		}
	}

	/*
	 * cpuset may be empty if the page was only mapped by segkpm,
	 * in which case we won't actually cross-trap.
	 */
	xt_sync(cpuset);

	/*
	 * The page should have no mappings at this point, unless
	 * we were called from hat_page_relocate() in which case we
	 * leave the locked mappings which will be suspended later.
	 */
	ASSERT(!PP_ISMAPPED(origpp) || pa_hments ||
	    (forceflag == SFMMU_KERNEL_RELOC));

#ifdef VAC
	if (PP_ISTNC(pp)) {
		if (cons == TTE8K) {
			pmtx = sfmmu_page_enter(pp);
			PP_CLRTNC(pp);
			sfmmu_page_exit(pmtx);
		} else {
			conv_tnc(pp, cons);
		}
	}
#endif	/* VAC */

	if (pa_hments && forceflag != SFMMU_KERNEL_RELOC) {
		/*
		 * Unlink any pa_hments and free them, calling back
		 * the responsible subsystem to notify it of the error.
		 * This can occur in situations such as drivers leaking
		 * DMA handles: naughty, but common enough that we'd like
		 * to keep the system running rather than bringing it
		 * down with an obscure error like "pa_hment leaked"
		 * which doesn't aid the user in debugging their driver.
		 */
		for (sfhme = pp->p_mapping; sfhme; sfhme = tmphme) {
			tmphme = sfhme->hme_next;
			if (IS_PAHME(sfhme)) {
				struct pa_hment *pahmep = sfhme->hme_data;
				sfmmu_pahment_leaked(pahmep);
				HME_SUB(sfhme, pp);
				kmem_cache_free(pa_hment_cache, pahmep);
			}
		}

		ASSERT(!PP_ISMAPPED(origpp));
	}

	sfmmu_mlist_exit(pml);

	return (0);
}

cpuset_t
sfmmu_pageunload(page_t *pp, struct sf_hment *sfhme, int cons)
{
	struct hme_blk *hmeblkp;
	sfmmu_t *sfmmup;
	tte_t tte, ttemod;
#ifdef DEBUG
	tte_t orig_old;
#endif /* DEBUG */
	caddr_t addr;
	int ttesz;
	int ret;
	cpuset_t cpuset;

	ASSERT(pp != NULL);
	ASSERT(sfmmu_mlist_held(pp));
	ASSERT(!PP_ISKAS(pp));

	CPUSET_ZERO(cpuset);

	hmeblkp = sfmmu_hmetohblk(sfhme);

readtte:
	sfmmu_copytte(&sfhme->hme_tte, &tte);
	if (TTE_IS_VALID(&tte)) {
		sfmmup = hblktosfmmu(hmeblkp);
		ttesz = get_hblk_ttesz(hmeblkp);
		/*
		 * Only unload mappings of 'cons' size.
		 */
		if (ttesz != cons)
			return (cpuset);

		/*
		 * Note that we have p_mapping lock, but no hash lock here.
		 * hblk_unload() has to have both hash lock AND p_mapping
		 * lock before it tries to modify tte. So, the tte could
		 * not become invalid in the sfmmu_modifytte_try() below.
		 */
		ttemod = tte;
#ifdef DEBUG
		orig_old = tte;
#endif /* DEBUG */

		TTE_SET_INVALID(&ttemod);
		ret = sfmmu_modifytte_try(&tte, &ttemod, &sfhme->hme_tte);
		if (ret < 0) {
#ifdef DEBUG
			/* only R/M bits can change. */
			chk_tte(&orig_old, &tte, &ttemod, hmeblkp);
#endif /* DEBUG */
			goto readtte;
		}

		if (ret == 0) {
			panic("pageunload: cas failed?");
		}

		addr = tte_to_vaddr(hmeblkp, tte);

		if (hmeblkp->hblk_shared) {
			sf_srd_t *srdp = (sf_srd_t *)sfmmup;
			uint_t rid = hmeblkp->hblk_tag.htag_rid;
			sf_region_t *rgnp;
			ASSERT(SFMMU_IS_SHMERID_VALID(rid));
			ASSERT(rid < SFMMU_MAX_HME_REGIONS);
			ASSERT(srdp != NULL);
			rgnp = srdp->srd_hmergnp[rid];
			SFMMU_VALIDATE_SHAREDHBLK(hmeblkp, srdp, rgnp, rid);
			cpuset = sfmmu_rgntlb_demap(addr, rgnp, hmeblkp, 1);
			sfmmu_ttesync(NULL, addr, &tte, pp);
			ASSERT(rgnp->rgn_ttecnt[ttesz] > 0);
			atomic_dec_ulong(&rgnp->rgn_ttecnt[ttesz]);
		} else {
			sfmmu_ttesync(sfmmup, addr, &tte, pp);
			atomic_dec_ulong(&sfmmup->sfmmu_ttecnt[ttesz]);

			/*
			 * We need to flush the page from the virtual cache
			 * in order to prevent a virtual cache alias
			 * inconsistency. The particular scenario we need
			 * to worry about is:
			 * Given:  va1 and va2 are two virtual address that
			 * alias and will map the same physical address.
			 * 1.   mapping exists from va1 to pa and data has
			 *	been read into the cache.
			 * 2.   unload va1.
			 * 3.   load va2 and modify data using va2.
			 * 4    unload va2.
			 * 5.   load va1 and reference data.  Unless we flush
			 *	the data cache when we unload we will get
			 *	stale data.
			 * This scenario is taken care of by using virtual
			 * page coloring.
			 */
			if (sfmmup->sfmmu_ismhat) {
				/*
				 * Flush TSBs, TLBs and caches
				 * of every process
				 * sharing this ism segment.
				 */
				sfmmu_hat_lock_all();
				mutex_enter(&ism_mlist_lock);
				kpreempt_disable();
				sfmmu_ismtlbcache_demap(addr, sfmmup, hmeblkp,
				    pp->p_pagenum, CACHE_NO_FLUSH);
				kpreempt_enable();
				mutex_exit(&ism_mlist_lock);
				sfmmu_hat_unlock_all();
				cpuset = cpu_ready_set;
			} else {
				sfmmu_tlb_demap(addr, sfmmup, hmeblkp, 0, 0);
				cpuset = sfmmup->sfmmu_cpusran;
			}
		}

		/*
		 * Hme_sub has to run after ttesync() and a_rss update.
		 * See hblk_unload().
		 */
		HME_SUB(sfhme, pp);
		membar_stst();

		/*
		 * We can not make ASSERT(hmeblkp->hblk_hmecnt <= NHMENTS)
		 * since pteload may have done a HME_ADD() right after
		 * we did the HME_SUB() above. Hmecnt is now maintained
		 * by cas only. no lock guranteed its value. The only
		 * gurantee we have is the hmecnt should not be less than
		 * what it should be so the hblk will not be taken away.
		 * It's also important that we decremented the hmecnt after
		 * we are done with hmeblkp so that this hmeblk won't be
		 * stolen.
		 */
		ASSERT(hmeblkp->hblk_hmecnt > 0);
		ASSERT(hmeblkp->hblk_vcnt > 0);
		atomic_dec_16(&hmeblkp->hblk_vcnt);
		atomic_dec_16(&hmeblkp->hblk_hmecnt);
		/*
		 * This is bug 4063182.
		 * XXX: fixme
		 * ASSERT(hmeblkp->hblk_hmecnt || hmeblkp->hblk_vcnt ||
		 *	!hmeblkp->hblk_lckcnt);
		 */
	} else {
		panic("invalid tte? pp %p &tte %p",
		    (void *)pp, (void *)&tte);
	}

	return (cpuset);
}

/*
 * While relocating a kernel page, this function will move the mappings
 * from tpp to dpp and modify any associated data with these mappings.
 * It also unsuspends the suspended kernel mapping.
 */
static void
hat_pagereload(struct page *tpp, struct page *dpp)
{
	struct sf_hment *sfhme;
	tte_t tte, ttemod;
	int index, cons;

	ASSERT(getpil() == PIL_MAX);
	ASSERT(sfmmu_mlist_held(tpp));
	ASSERT(sfmmu_mlist_held(dpp));

	index = PP_MAPINDEX(tpp);
	cons = TTE8K;

	/* Update real mappings to the page */
retry:
	for (sfhme = tpp->p_mapping; sfhme != NULL; sfhme = sfhme->hme_next) {
		if (IS_PAHME(sfhme))
			continue;
		sfmmu_copytte(&sfhme->hme_tte, &tte);
		ttemod = tte;

		/*
		 * replace old pfn with new pfn in TTE
		 */
		PFN_TO_TTE(ttemod, dpp->p_pagenum);

		/*
		 * clear suspend bit
		 */
		ASSERT(TTE_IS_SUSPEND(&ttemod));
		TTE_CLR_SUSPEND(&ttemod);

		if (sfmmu_modifytte_try(&tte, &ttemod, &sfhme->hme_tte) < 0)
			panic("hat_pagereload(): sfmmu_modifytte_try() failed");

		/*
		 * set hme_page point to new page
		 */
		sfhme->hme_page = dpp;
	}

	/*
	 * move p_mapping list from old page to new page
	 */
	dpp->p_mapping = tpp->p_mapping;
	tpp->p_mapping = NULL;
	dpp->p_share = tpp->p_share;
	tpp->p_share = 0;

	while (index != 0) {
		index = index >> 1;
		if (index != 0)
			cons++;
		if (index & 0x1) {
			tpp = PP_GROUPLEADER(tpp, cons);
			dpp = PP_GROUPLEADER(dpp, cons);
			goto retry;
		}
	}

	curthread->t_flag &= ~T_DONTDTRACE;
	mutex_exit(&kpr_suspendlock);
}

uint_t
hat_pagesync(struct page *pp, uint_t clearflag)
{
	struct sf_hment *sfhme, *tmphme = NULL;
	struct hme_blk *hmeblkp;
	kmutex_t *pml;
	cpuset_t cpuset, tset;
	int	index, cons;
	extern	ulong_t po_share;
	page_t	*save_pp = pp;
	int	stop_on_sh = 0;
	uint_t	shcnt;

	CPUSET_ZERO(cpuset);

	if (PP_ISRO(pp) && (clearflag & HAT_SYNC_STOPON_MOD)) {
		return (PP_GENERIC_ATTR(pp));
	}

	if ((clearflag & HAT_SYNC_ZERORM) == 0) {
		if ((clearflag & HAT_SYNC_STOPON_REF) && PP_ISREF(pp)) {
			return (PP_GENERIC_ATTR(pp));
		}
		if ((clearflag & HAT_SYNC_STOPON_MOD) && PP_ISMOD(pp)) {
			return (PP_GENERIC_ATTR(pp));
		}
		if (clearflag & HAT_SYNC_STOPON_SHARED) {
			if (pp->p_share > po_share) {
				hat_page_setattr(pp, P_REF);
				return (PP_GENERIC_ATTR(pp));
			}
			stop_on_sh = 1;
			shcnt = 0;
		}
	}

	clearflag &= ~HAT_SYNC_STOPON_SHARED;
	pml = sfmmu_mlist_enter(pp);
	index = PP_MAPINDEX(pp);
	cons = TTE8K;
retry:
	for (sfhme = pp->p_mapping; sfhme; sfhme = tmphme) {
		/*
		 * We need to save the next hment on the list since
		 * it is possible for pagesync to remove an invalid hment
		 * from the list.
		 */
		tmphme = sfhme->hme_next;
		if (IS_PAHME(sfhme))
			continue;
		/*
		 * If we are looking for large mappings and this hme doesn't
		 * reach the range we are seeking, just ignore it.
		 */
		hmeblkp = sfmmu_hmetohblk(sfhme);

		if (hme_size(sfhme) < cons)
			continue;

		if (stop_on_sh) {
			if (hmeblkp->hblk_shared) {
				sf_srd_t *srdp = hblktosrd(hmeblkp);
				uint_t rid = hmeblkp->hblk_tag.htag_rid;
				sf_region_t *rgnp;
				ASSERT(SFMMU_IS_SHMERID_VALID(rid));
				ASSERT(rid < SFMMU_MAX_HME_REGIONS);
				ASSERT(srdp != NULL);
				rgnp = srdp->srd_hmergnp[rid];
				SFMMU_VALIDATE_SHAREDHBLK(hmeblkp, srdp,
				    rgnp, rid);
				shcnt += rgnp->rgn_refcnt;
			} else {
				shcnt++;
			}
			if (shcnt > po_share) {
				/*
				 * tell the pager to spare the page this time
				 * around.
				 */
				hat_page_setattr(save_pp, P_REF);
				index = 0;
				break;
			}
		}
		tset = sfmmu_pagesync(pp, sfhme,
		    clearflag & ~HAT_SYNC_STOPON_RM);
		CPUSET_OR(cpuset, tset);

		/*
		 * If clearflag is HAT_SYNC_DONTZERO, break out as soon
		 * as the "ref" or "mod" is set or share cnt exceeds po_share.
		 */
		if ((clearflag & ~HAT_SYNC_STOPON_RM) == HAT_SYNC_DONTZERO &&
		    (((clearflag & HAT_SYNC_STOPON_MOD) && PP_ISMOD(save_pp)) ||
		    ((clearflag & HAT_SYNC_STOPON_REF) && PP_ISREF(save_pp)))) {
			index = 0;
			break;
		}
	}

	while (index) {
		index = index >> 1;
		cons++;
		if (index & 0x1) {
			/* Go to leading page */
			pp = PP_GROUPLEADER(pp, cons);
			goto retry;
		}
	}

	xt_sync(cpuset);
	sfmmu_mlist_exit(pml);
	return (PP_GENERIC_ATTR(save_pp));
}

/*
 * Get all the hardware dependent attributes for a page struct
 */
static cpuset_t
sfmmu_pagesync(struct page *pp, struct sf_hment *sfhme,
	uint_t clearflag)
{
	caddr_t addr;
	tte_t tte, ttemod;
	struct hme_blk *hmeblkp;
	int ret;
	sfmmu_t *sfmmup;
	cpuset_t cpuset;

	ASSERT(pp != NULL);
	ASSERT(sfmmu_mlist_held(pp));
	ASSERT((clearflag == HAT_SYNC_DONTZERO) ||
	    (clearflag == HAT_SYNC_ZERORM));

	SFMMU_STAT(sf_pagesync);

	CPUSET_ZERO(cpuset);

sfmmu_pagesync_retry:

	sfmmu_copytte(&sfhme->hme_tte, &tte);
	if (TTE_IS_VALID(&tte)) {
		hmeblkp = sfmmu_hmetohblk(sfhme);
		sfmmup = hblktosfmmu(hmeblkp);
		addr = tte_to_vaddr(hmeblkp, tte);
		if (clearflag == HAT_SYNC_ZERORM) {
			ttemod = tte;
			TTE_CLR_RM(&ttemod);
			ret = sfmmu_modifytte_try(&tte, &ttemod,
			    &sfhme->hme_tte);
			if (ret < 0) {
				/*
				 * cas failed and the new value is not what
				 * we want.
				 */
				goto sfmmu_pagesync_retry;
			}

			if (ret > 0) {
				/* we win the cas */
				if (hmeblkp->hblk_shared) {
					sf_srd_t *srdp = (sf_srd_t *)sfmmup;
					uint_t rid =
					    hmeblkp->hblk_tag.htag_rid;
					sf_region_t *rgnp;
					ASSERT(SFMMU_IS_SHMERID_VALID(rid));
					ASSERT(rid < SFMMU_MAX_HME_REGIONS);
					ASSERT(srdp != NULL);
					rgnp = srdp->srd_hmergnp[rid];
					SFMMU_VALIDATE_SHAREDHBLK(hmeblkp,
					    srdp, rgnp, rid);
					cpuset = sfmmu_rgntlb_demap(addr,
					    rgnp, hmeblkp, 1);
				} else {
					sfmmu_tlb_demap(addr, sfmmup, hmeblkp,
					    0, 0);
					cpuset = sfmmup->sfmmu_cpusran;
				}
			}
		}
		sfmmu_ttesync(hmeblkp->hblk_shared ? NULL : sfmmup, addr,
		    &tte, pp);
	}
	return (cpuset);
}

/*
 * Remove write permission from a mappings to a page, so that
 * we can detect the next modification of it. This requires modifying
 * the TTE then invalidating (demap) any TLB entry using that TTE.
 * This code is similar to sfmmu_pagesync().
 */
static cpuset_t
sfmmu_pageclrwrt(struct page *pp, struct sf_hment *sfhme)
{
	caddr_t addr;
	tte_t tte;
	tte_t ttemod;
	struct hme_blk *hmeblkp;
	int ret;
	sfmmu_t *sfmmup;
	cpuset_t cpuset;

	ASSERT(pp != NULL);
	ASSERT(sfmmu_mlist_held(pp));

	CPUSET_ZERO(cpuset);
	SFMMU_STAT(sf_clrwrt);

retry:

	sfmmu_copytte(&sfhme->hme_tte, &tte);
	if (TTE_IS_VALID(&tte) && TTE_IS_WRITABLE(&tte)) {
		hmeblkp = sfmmu_hmetohblk(sfhme);
		sfmmup = hblktosfmmu(hmeblkp);
		addr = tte_to_vaddr(hmeblkp, tte);

		ttemod = tte;
		TTE_CLR_WRT(&ttemod);
		TTE_CLR_MOD(&ttemod);
		ret = sfmmu_modifytte_try(&tte, &ttemod, &sfhme->hme_tte);

		/*
		 * if cas failed and the new value is not what
		 * we want retry
		 */
		if (ret < 0)
			goto retry;

		/* we win the cas */
		if (ret > 0) {
			if (hmeblkp->hblk_shared) {
				sf_srd_t *srdp = (sf_srd_t *)sfmmup;
				uint_t rid = hmeblkp->hblk_tag.htag_rid;
				sf_region_t *rgnp;
				ASSERT(SFMMU_IS_SHMERID_VALID(rid));
				ASSERT(rid < SFMMU_MAX_HME_REGIONS);
				ASSERT(srdp != NULL);
				rgnp = srdp->srd_hmergnp[rid];
				SFMMU_VALIDATE_SHAREDHBLK(hmeblkp,
				    srdp, rgnp, rid);
				cpuset = sfmmu_rgntlb_demap(addr,
				    rgnp, hmeblkp, 1);
			} else {
				sfmmu_tlb_demap(addr, sfmmup, hmeblkp, 0, 0);
				cpuset = sfmmup->sfmmu_cpusran;
			}
		}
	}

	return (cpuset);
}

/*
 * Walk all mappings of a page, removing write permission and clearing the
 * ref/mod bits. This code is similar to hat_pagesync()
 */
static void
hat_page_clrwrt(page_t *pp)
{
	struct sf_hment *sfhme;
	struct sf_hment *tmphme = NULL;
	kmutex_t *pml;
	cpuset_t cpuset;
	cpuset_t tset;
	int	index;
	int	 cons;

	CPUSET_ZERO(cpuset);

	pml = sfmmu_mlist_enter(pp);
	index = PP_MAPINDEX(pp);
	cons = TTE8K;
retry:
	for (sfhme = pp->p_mapping; sfhme; sfhme = tmphme) {
		tmphme = sfhme->hme_next;

		/*
		 * If we are looking for large mappings and this hme doesn't
		 * reach the range we are seeking, just ignore its.
		 */

		if (hme_size(sfhme) < cons)
			continue;

		tset = sfmmu_pageclrwrt(pp, sfhme);
		CPUSET_OR(cpuset, tset);
	}

	while (index) {
		index = index >> 1;
		cons++;
		if (index & 0x1) {
			/* Go to leading page */
			pp = PP_GROUPLEADER(pp, cons);
			goto retry;
		}
	}

	xt_sync(cpuset);
	sfmmu_mlist_exit(pml);
}

/*
 * Set the given REF/MOD/RO bits for the given page.
 * For a vnode with a sorted v_pages list, we need to change
 * the attributes and the v_pages list together under page_vnode_mutex.
 */
void
hat_page_setattr(page_t *pp, uint_t flag)
{
	vnode_t		*vp = pp->p_vnode;
	page_t		**listp;
	kmutex_t	*pmtx;
	kmutex_t	*vphm = NULL;
	int		noshuffle;

	noshuffle = flag & P_NSH;
	flag &= ~P_NSH;

	ASSERT(!(flag & ~(P_MOD | P_REF | P_RO)));

	/*
	 * nothing to do if attribute already set
	 */
	if ((pp->p_nrm & flag) == flag)
		return;

	if ((flag & P_MOD) != 0 && vp != NULL && IS_VMODSORT(vp) &&
	    !noshuffle) {
		vphm = page_vnode_mutex(vp);
		mutex_enter(vphm);
	}

	pmtx = sfmmu_page_enter(pp);
	pp->p_nrm |= flag;
	sfmmu_page_exit(pmtx);

	if (vphm != NULL) {
		/*
		 * Some File Systems examine v_pages for NULL w/o
		 * grabbing the vphm mutex. Must not let it become NULL when
		 * pp is the only page on the list.
		 */
		if (pp->p_vpnext != pp) {
			page_vpsub(&vp->v_pages, pp);
			if (vp->v_pages != NULL)
				listp = &vp->v_pages->p_vpprev->p_vpnext;
			else
				listp = &vp->v_pages;
			page_vpadd(listp, pp);
		}
		mutex_exit(vphm);
	}
}

void
hat_page_clrattr(page_t *pp, uint_t flag)
{
	vnode_t		*vp = pp->p_vnode;
	kmutex_t	*pmtx;

	ASSERT(!(flag & ~(P_MOD | P_REF | P_RO)));

	pmtx = sfmmu_page_enter(pp);

	/*
	 * Caller is expected to hold page's io lock for VMODSORT to work
	 * correctly with pvn_vplist_dirty() and pvn_getdirty() when mod
	 * bit is cleared.
	 * We don't have assert to avoid tripping some existing third party
	 * code. The dirty page is moved back to top of the v_page list
	 * after IO is done in pvn_write_done().
	 */
	pp->p_nrm &= ~flag;
	sfmmu_page_exit(pmtx);

	if ((flag & P_MOD) != 0 && vp != NULL && IS_VMODSORT(vp)) {

		/*
		 * VMODSORT works by removing write permissions and getting
		 * a fault when a page is made dirty. At this point
		 * we need to remove write permission from all mappings
		 * to this page.
		 */
		hat_page_clrwrt(pp);
	}
}

uint_t
hat_page_getattr(page_t *pp, uint_t flag)
{
	ASSERT(!(flag & ~(P_MOD | P_REF | P_RO)));
	return ((uint_t)(pp->p_nrm & flag));
}

/*
 * DEBUG kernels: verify that a kernel va<->pa translation
 * is safe by checking the underlying page_t is in a page
 * relocation-safe state.
 */
#ifdef	DEBUG
void
sfmmu_check_kpfn(pfn_t pfn)
{
	page_t *pp;
	int index, cons;

	if (hat_check_vtop == 0)
		return;

	if (kvseg.s_base == NULL || panicstr)
		return;

	pp = page_numtopp_nolock(pfn);
	if (!pp)
		return;

	if (PAGE_LOCKED(pp) || PP_ISNORELOC(pp))
		return;

	/*
	 * Handed a large kernel page, we dig up the root page since we
	 * know the root page might have the lock also.
	 */
	if (pp->p_szc != 0) {
		index = PP_MAPINDEX(pp);
		cons = TTE8K;
again:
		while (index != 0) {
			index >>= 1;
			if (index != 0)
				cons++;
			if (index & 0x1) {
				pp = PP_GROUPLEADER(pp, cons);
				goto again;
			}
		}
	}

	if (PAGE_LOCKED(pp) || PP_ISNORELOC(pp))
		return;

	/*
	 * Pages need to be locked or allocated "permanent" (either from
	 * static_arena arena or explicitly setting PG_NORELOC when calling
	 * page_create_va()) for VA->PA translations to be valid.
	 */
	if (!PP_ISNORELOC(pp))
		panic("Illegal VA->PA translation, pp 0x%p not permanent",
		    (void *)pp);
	else
		panic("Illegal VA->PA translation, pp 0x%p not locked",
		    (void *)pp);
}
#endif	/* DEBUG */

/*
 * Returns a page frame number for a given virtual address.
 * Returns PFN_INVALID to indicate an invalid mapping
 */
pfn_t
hat_getpfnum(struct hat *hat, caddr_t addr)
{
	pfn_t pfn;
	tte_t tte;

	/*
	 * We would like to
	 * ASSERT(AS_LOCK_HELD(as));
	 * but we can't because the iommu driver will call this
	 * routine at interrupt time and it can't grab the as lock
	 * or it will deadlock: A thread could have the as lock
	 * and be waiting for io.  The io can't complete
	 * because the interrupt thread is blocked trying to grab
	 * the as lock.
	 */

	if (hat == ksfmmup) {
		if (IS_KMEM_VA_LARGEPAGE(addr)) {
			ASSERT(segkmem_lpszc > 0);
			pfn = sfmmu_kvaszc2pfn(addr, segkmem_lpszc);
			if (pfn != PFN_INVALID) {
				sfmmu_check_kpfn(pfn);
				return (pfn);
			}
		} else if (segkpm && IS_KPM_ADDR(addr)) {
			return (sfmmu_kpm_vatopfn(addr));
		}
		while ((pfn = sfmmu_vatopfn(addr, ksfmmup, &tte))
		    == PFN_SUSPENDED) {
			sfmmu_vatopfn_suspended(addr, ksfmmup, &tte);
		}
		sfmmu_check_kpfn(pfn);
		return (pfn);
	} else {
		return (sfmmu_uvatopfn(addr, hat, NULL));
	}
}

/*
 * This routine will return both pfn and tte for the vaddr.
 */
static pfn_t
sfmmu_uvatopfn(caddr_t vaddr, struct hat *sfmmup, tte_t *ttep)
{
	struct hmehash_bucket *hmebp;
	hmeblk_tag hblktag;
	int hmeshift, hashno = 1;
	struct hme_blk *hmeblkp = NULL;
	tte_t tte;

	struct sf_hment *sfhmep;
	pfn_t pfn;

	/* support for ISM */
	ism_map_t	*ism_map;
	ism_blk_t	*ism_blkp;
	int		i;
	sfmmu_t *ism_hatid = NULL;
	sfmmu_t *locked_hatid = NULL;
	sfmmu_t	*sv_sfmmup = sfmmup;
	caddr_t	sv_vaddr = vaddr;
	sf_srd_t *srdp;

	if (ttep == NULL) {
		ttep = &tte;
	} else {
		ttep->ll = 0;
	}

	ASSERT(sfmmup != ksfmmup);
	SFMMU_STAT(sf_user_vtop);
	/*
	 * Set ism_hatid if vaddr falls in a ISM segment.
	 */
	ism_blkp = sfmmup->sfmmu_iblk;
	if (ism_blkp != NULL) {
		sfmmu_ismhat_enter(sfmmup, 0);
		locked_hatid = sfmmup;
	}
	while (ism_blkp != NULL && ism_hatid == NULL) {
		ism_map = ism_blkp->iblk_maps;
		for (i = 0; ism_map[i].imap_ismhat && i < ISM_MAP_SLOTS; i++) {
			if (vaddr >= ism_start(ism_map[i]) &&
			    vaddr < ism_end(ism_map[i])) {
				sfmmup = ism_hatid = ism_map[i].imap_ismhat;
				vaddr = (caddr_t)(vaddr -
				    ism_start(ism_map[i]));
				break;
			}
		}
		ism_blkp = ism_blkp->iblk_next;
	}
	if (locked_hatid) {
		sfmmu_ismhat_exit(locked_hatid, 0);
	}

	hblktag.htag_id = sfmmup;
	hblktag.htag_rid = SFMMU_INVALID_SHMERID;
	do {
		hmeshift = HME_HASH_SHIFT(hashno);
		hblktag.htag_bspage = HME_HASH_BSPAGE(vaddr, hmeshift);
		hblktag.htag_rehash = hashno;
		hmebp = HME_HASH_FUNCTION(sfmmup, vaddr, hmeshift);

		SFMMU_HASH_LOCK(hmebp);

		HME_HASH_FAST_SEARCH(hmebp, hblktag, hmeblkp);
		if (hmeblkp != NULL) {
			ASSERT(!hmeblkp->hblk_shared);
			HBLKTOHME(sfhmep, hmeblkp, vaddr);
			sfmmu_copytte(&sfhmep->hme_tte, ttep);
			SFMMU_HASH_UNLOCK(hmebp);
			if (TTE_IS_VALID(ttep)) {
				pfn = TTE_TO_PFN(vaddr, ttep);
				return (pfn);
			}
			break;
		}
		SFMMU_HASH_UNLOCK(hmebp);
		hashno++;
	} while (HME_REHASH(sfmmup) && (hashno <= mmu_hashcnt));

	if (SF_HMERGNMAP_ISNULL(sv_sfmmup)) {
		return (PFN_INVALID);
	}
	srdp = sv_sfmmup->sfmmu_srdp;
	ASSERT(srdp != NULL);
	ASSERT(srdp->srd_refcnt != 0);
	hblktag.htag_id = srdp;
	hashno = 1;
	do {
		hmeshift = HME_HASH_SHIFT(hashno);
		hblktag.htag_bspage = HME_HASH_BSPAGE(sv_vaddr, hmeshift);
		hblktag.htag_rehash = hashno;
		hmebp = HME_HASH_FUNCTION(srdp, sv_vaddr, hmeshift);

		SFMMU_HASH_LOCK(hmebp);
		for (hmeblkp = hmebp->hmeblkp; hmeblkp != NULL;
		    hmeblkp = hmeblkp->hblk_next) {
			uint_t rid;
			sf_region_t *rgnp;
			caddr_t rsaddr;
			caddr_t readdr;

			if (!HTAGS_EQ_SHME(hmeblkp->hblk_tag, hblktag,
			    sv_sfmmup->sfmmu_hmeregion_map)) {
				continue;
			}
			ASSERT(hmeblkp->hblk_shared);
			rid = hmeblkp->hblk_tag.htag_rid;
			ASSERT(SFMMU_IS_SHMERID_VALID(rid));
			ASSERT(rid < SFMMU_MAX_HME_REGIONS);
			rgnp = srdp->srd_hmergnp[rid];
			SFMMU_VALIDATE_SHAREDHBLK(hmeblkp, srdp, rgnp, rid);
			HBLKTOHME(sfhmep, hmeblkp, sv_vaddr);
			sfmmu_copytte(&sfhmep->hme_tte, ttep);
			rsaddr = rgnp->rgn_saddr;
			readdr = rsaddr + rgnp->rgn_size;
#ifdef DEBUG
			if (TTE_IS_VALID(ttep) ||
			    get_hblk_ttesz(hmeblkp) > TTE8K) {
				caddr_t eva = tte_to_evaddr(hmeblkp, ttep);
				ASSERT(eva > sv_vaddr);
				ASSERT(sv_vaddr >= rsaddr);
				ASSERT(sv_vaddr < readdr);
				ASSERT(eva <= readdr);
			}
#endif /* DEBUG */
			/*
			 * Continue the search if we
			 * found an invalid 8K tte outside of the area
			 * covered by this hmeblk's region.
			 */
			if (TTE_IS_VALID(ttep)) {
				SFMMU_HASH_UNLOCK(hmebp);
				pfn = TTE_TO_PFN(sv_vaddr, ttep);
				return (pfn);
			} else if (get_hblk_ttesz(hmeblkp) > TTE8K ||
			    (sv_vaddr >= rsaddr && sv_vaddr < readdr)) {
				SFMMU_HASH_UNLOCK(hmebp);
				pfn = PFN_INVALID;
				return (pfn);
			}
		}
		SFMMU_HASH_UNLOCK(hmebp);
		hashno++;
	} while (hashno <= mmu_hashcnt);
	return (PFN_INVALID);
}


/*
 * For compatability with AT&T and later optimizations
 */
/* ARGSUSED */
void
hat_map(struct hat *hat, caddr_t addr, size_t len, uint_t flags)
{
	ASSERT(hat != NULL);
}

/*
 * Return the number of mappings to a particular page.  This number is an
 * approximation of the number of people sharing the page.
 *
 * shared hmeblks or ism hmeblks are counted as 1 mapping here.
 * hat_page_checkshare() can be used to compare threshold to share
 * count that reflects the number of region sharers albeit at higher cost.
 */
ulong_t
hat_page_getshare(page_t *pp)
{
	page_t *spp = pp;	/* start page */
	kmutex_t *pml;
	ulong_t	cnt;
	int index, sz = TTE64K;

	/*
	 * We need to grab the mlist lock to make sure any outstanding
	 * load/unloads complete.  Otherwise we could return zero
	 * even though the unload(s) hasn't finished yet.
	 */
	pml = sfmmu_mlist_enter(spp);
	cnt = spp->p_share;

#ifdef VAC
	if (kpm_enable)
		cnt += spp->p_kpmref;
#endif
	if (vpm_enable && pp->p_vpmref) {
		cnt += 1;
	}

	/*
	 * If we have any large mappings, we count the number of
	 * mappings that this large page is part of.
	 */
	index = PP_MAPINDEX(spp);
	index >>= 1;
	while (index) {
		pp = PP_GROUPLEADER(spp, sz);
		if ((index & 0x1) && pp != spp) {
			cnt += pp->p_share;
			spp = pp;
		}
		index >>= 1;
		sz++;
	}
	sfmmu_mlist_exit(pml);
	return (cnt);
}

/*
 * Return 1 if the number of mappings exceeds sh_thresh. Return 0
 * otherwise. Count shared hmeblks by region's refcnt.
 */
int
hat_page_checkshare(page_t *pp, ulong_t sh_thresh)
{
	kmutex_t *pml;
	ulong_t	cnt = 0;
	int index, sz = TTE8K;
	struct sf_hment *sfhme, *tmphme = NULL;
	struct hme_blk *hmeblkp;

	pml = sfmmu_mlist_enter(pp);

#ifdef VAC
	if (kpm_enable)
		cnt = pp->p_kpmref;
#endif

	if (vpm_enable && pp->p_vpmref) {
		cnt += 1;
	}

	if (pp->p_share + cnt > sh_thresh) {
		sfmmu_mlist_exit(pml);
		return (1);
	}

	index = PP_MAPINDEX(pp);

again:
	for (sfhme = pp->p_mapping; sfhme; sfhme = tmphme) {
		tmphme = sfhme->hme_next;
		if (IS_PAHME(sfhme)) {
			continue;
		}

		hmeblkp = sfmmu_hmetohblk(sfhme);
		if (hme_size(sfhme) != sz) {
			continue;
		}

		if (hmeblkp->hblk_shared) {
			sf_srd_t *srdp = hblktosrd(hmeblkp);
			uint_t rid = hmeblkp->hblk_tag.htag_rid;
			sf_region_t *rgnp;
			ASSERT(SFMMU_IS_SHMERID_VALID(rid));
			ASSERT(rid < SFMMU_MAX_HME_REGIONS);
			ASSERT(srdp != NULL);
			rgnp = srdp->srd_hmergnp[rid];
			SFMMU_VALIDATE_SHAREDHBLK(hmeblkp, srdp,
			    rgnp, rid);
			cnt += rgnp->rgn_refcnt;
		} else {
			cnt++;
		}
		if (cnt > sh_thresh) {
			sfmmu_mlist_exit(pml);
			return (1);
		}
	}

	index >>= 1;
	sz++;
	while (index) {
		pp = PP_GROUPLEADER(pp, sz);
		ASSERT(sfmmu_mlist_held(pp));
		if (index & 0x1) {
			goto again;
		}
		index >>= 1;
		sz++;
	}
	sfmmu_mlist_exit(pml);
	return (0);
}

/*
 * Unload all large mappings to the pp and reset the p_szc field of every
 * constituent page according to the remaining mappings.
 *
 * pp must be locked SE_EXCL. Even though no other constituent pages are
 * locked it's legal to unload the large mappings to the pp because all
 * constituent pages of large locked mappings have to be locked SE_SHARED.
 * This means if we have SE_EXCL lock on one of constituent pages none of the
 * large mappings to pp are locked.
 *
 * Decrease p_szc field starting from the last constituent page and ending
 * with the root page. This method is used because other threads rely on the
 * root's p_szc to find the lock to syncronize on. After a root page_t's p_szc
 * is demoted then other threads will succeed in sfmmu_mlspl_enter(). This
 * ensures that p_szc changes of the constituent pages appears atomic for all
 * threads that use sfmmu_mlspl_enter() to examine p_szc field.
 *
 * This mechanism is only used for file system pages where it's not always
 * possible to get SE_EXCL locks on all constituent pages to demote the size
 * code (as is done for anonymous or kernel large pages).
 *
 * See more comments in front of sfmmu_mlspl_enter().
 */
void
hat_page_demote(page_t *pp)
{
	int index;
	int sz;
	cpuset_t cpuset;
	int sync = 0;
	page_t *rootpp;
	struct sf_hment *sfhme;
	struct sf_hment *tmphme = NULL;
	struct hme_blk *hmeblkp;
	uint_t pszc;
	page_t *lastpp;
	cpuset_t tset;
	pgcnt_t npgs;
	kmutex_t *pml;
	kmutex_t *pmtx = NULL;

	ASSERT(PAGE_EXCL(pp));
	ASSERT(!PP_ISFREE(pp));
	ASSERT(!PP_ISKAS(pp));
	ASSERT(page_szc_lock_assert(pp));
	pml = sfmmu_mlist_enter(pp);

	pszc = pp->p_szc;
	if (pszc == 0) {
		goto out;
	}

	index = PP_MAPINDEX(pp) >> 1;

	if (index) {
		CPUSET_ZERO(cpuset);
		sz = TTE64K;
		sync = 1;
	}

	while (index) {
		if (!(index & 0x1)) {
			index >>= 1;
			sz++;
			continue;
		}
		ASSERT(sz <= pszc);
		rootpp = PP_GROUPLEADER(pp, sz);
		for (sfhme = rootpp->p_mapping; sfhme; sfhme = tmphme) {
			tmphme = sfhme->hme_next;
			ASSERT(!IS_PAHME(sfhme));
			hmeblkp = sfmmu_hmetohblk(sfhme);
			if (hme_size(sfhme) != sz) {
				continue;
			}
			tset = sfmmu_pageunload(rootpp, sfhme, sz);
			CPUSET_OR(cpuset, tset);
		}
		if (index >>= 1) {
			sz++;
		}
	}

	ASSERT(!PP_ISMAPPED_LARGE(pp));

	if (sync) {
		xt_sync(cpuset);
#ifdef VAC
		if (PP_ISTNC(pp)) {
			conv_tnc(rootpp, sz);
		}
#endif	/* VAC */
	}

	pmtx = sfmmu_page_enter(pp);

	ASSERT(pp->p_szc == pszc);
	rootpp = PP_PAGEROOT(pp);
	ASSERT(rootpp->p_szc == pszc);
	lastpp = PP_PAGENEXT_N(rootpp, TTEPAGES(pszc) - 1);

	while (lastpp != rootpp) {
		sz = PP_MAPINDEX(lastpp) ? fnd_mapping_sz(lastpp) : 0;
		ASSERT(sz < pszc);
		npgs = (sz == 0) ? 1 : TTEPAGES(sz);
		ASSERT(P2PHASE(lastpp->p_pagenum, npgs) == npgs - 1);
		while (--npgs > 0) {
			lastpp->p_szc = (uchar_t)sz;
			lastpp = PP_PAGEPREV(lastpp);
		}
		if (sz) {
			/*
			 * make sure before current root's pszc
			 * is updated all updates to constituent pages pszc
			 * fields are globally visible.
			 */
			membar_producer();
		}
		lastpp->p_szc = sz;
		ASSERT(IS_P2ALIGNED(lastpp->p_pagenum, TTEPAGES(sz)));
		if (lastpp != rootpp) {
			lastpp = PP_PAGEPREV(lastpp);
		}
	}
	if (sz == 0) {
		/* the loop above doesn't cover this case */
		rootpp->p_szc = 0;
	}
out:
	ASSERT(pp->p_szc == 0);
	if (pmtx != NULL) {
		sfmmu_page_exit(pmtx);
	}
	sfmmu_mlist_exit(pml);
}

/*
 * Refresh the HAT ismttecnt[] element for size szc.
 * Caller must have set ISM busy flag to prevent mapping
 * lists from changing while we're traversing them.
 */
pgcnt_t
ism_tsb_entries(sfmmu_t *sfmmup, int szc)
{
	ism_blk_t	*ism_blkp = sfmmup->sfmmu_iblk;
	ism_map_t	*ism_map;
	pgcnt_t		npgs = 0;
	pgcnt_t		npgs_scd = 0;
	int		j;
	sf_scd_t	*scdp;
	uchar_t		rid;

	ASSERT(SFMMU_FLAGS_ISSET(sfmmup, HAT_ISMBUSY));
	scdp = sfmmup->sfmmu_scdp;

	for (; ism_blkp != NULL; ism_blkp = ism_blkp->iblk_next) {
		ism_map = ism_blkp->iblk_maps;
		for (j = 0; ism_map[j].imap_ismhat && j < ISM_MAP_SLOTS; j++) {
			rid = ism_map[j].imap_rid;
			ASSERT(rid == SFMMU_INVALID_ISMRID ||
			    rid < sfmmup->sfmmu_srdp->srd_next_ismrid);

			if (scdp != NULL && rid != SFMMU_INVALID_ISMRID &&
			    SF_RGNMAP_TEST(scdp->scd_ismregion_map, rid)) {
				/* ISM is in sfmmup's SCD */
				npgs_scd +=
				    ism_map[j].imap_ismhat->sfmmu_ttecnt[szc];
			} else {
				/* ISMs is not in SCD */
				npgs +=
				    ism_map[j].imap_ismhat->sfmmu_ttecnt[szc];
			}
		}
	}
	sfmmup->sfmmu_ismttecnt[szc] = npgs;
	sfmmup->sfmmu_scdismttecnt[szc] = npgs_scd;
	return (npgs);
}

/*
 * Yield the memory claim requirement for an address space.
 *
 * This is currently implemented as the number of bytes that have active
 * hardware translations that have page structures.  Therefore, it can
 * underestimate the traditional resident set size, eg, if the
 * physical page is present and the hardware translation is missing;
 * and it can overestimate the rss, eg, if there are active
 * translations to a frame buffer with page structs.
 * Also, it does not take sharing into account.
 *
 * Note that we don't acquire locks here since this function is most often
 * called from the clock thread.
 */
size_t
hat_get_mapped_size(struct hat *hat)
{
	size_t		assize = 0;
	int 		i;

	if (hat == NULL)
		return (0);

	for (i = 0; i < mmu_page_sizes; i++)
		assize += ((pgcnt_t)hat->sfmmu_ttecnt[i] +
		    (pgcnt_t)hat->sfmmu_scdrttecnt[i]) * TTEBYTES(i);

	if (hat->sfmmu_iblk == NULL)
		return (assize);

	for (i = 0; i < mmu_page_sizes; i++)
		assize += ((pgcnt_t)hat->sfmmu_ismttecnt[i] +
		    (pgcnt_t)hat->sfmmu_scdismttecnt[i]) * TTEBYTES(i);

	return (assize);
}

int
hat_stats_enable(struct hat *hat)
{
	hatlock_t	*hatlockp;

	hatlockp = sfmmu_hat_enter(hat);
	hat->sfmmu_rmstat++;
	sfmmu_hat_exit(hatlockp);
	return (1);
}

void
hat_stats_disable(struct hat *hat)
{
	hatlock_t	*hatlockp;

	hatlockp = sfmmu_hat_enter(hat);
	hat->sfmmu_rmstat--;
	sfmmu_hat_exit(hatlockp);
}

/*
 * Routines for entering or removing  ourselves from the
 * ism_hat's mapping list. This is used for both private and
 * SCD hats.
 */
static void
iment_add(struct ism_ment *iment,  struct hat *ism_hat)
{
	ASSERT(MUTEX_HELD(&ism_mlist_lock));

	iment->iment_prev = NULL;
	iment->iment_next = ism_hat->sfmmu_iment;
	if (ism_hat->sfmmu_iment) {
		ism_hat->sfmmu_iment->iment_prev = iment;
	}
	ism_hat->sfmmu_iment = iment;
}

static void
iment_sub(struct ism_ment *iment, struct hat *ism_hat)
{
	ASSERT(MUTEX_HELD(&ism_mlist_lock));

	if (ism_hat->sfmmu_iment == NULL) {
		panic("ism map entry remove - no entries");
	}

	if (iment->iment_prev) {
		ASSERT(ism_hat->sfmmu_iment != iment);
		iment->iment_prev->iment_next = iment->iment_next;
	} else {
		ASSERT(ism_hat->sfmmu_iment == iment);
		ism_hat->sfmmu_iment = iment->iment_next;
	}

	if (iment->iment_next) {
		iment->iment_next->iment_prev = iment->iment_prev;
	}

	/*
	 * zero out the entry
	 */
	iment->iment_next = NULL;
	iment->iment_prev = NULL;
	iment->iment_hat =  NULL;
	iment->iment_base_va = 0;
}

/*
 * Hat_share()/unshare() return an (non-zero) error
 * when saddr and daddr are not properly aligned.
 *
 * The top level mapping element determines the alignment
 * requirement for saddr and daddr, depending on different
 * architectures.
 *
 * When hat_share()/unshare() are not supported,
 * HATOP_SHARE()/UNSHARE() return 0
 */
int
hat_share(struct hat *sfmmup, caddr_t addr,
	struct hat *ism_hatid, caddr_t sptaddr, size_t len, uint_t ismszc)
{
	ism_blk_t	*ism_blkp;
	ism_blk_t	*new_iblk;
	ism_map_t 	*ism_map;
	ism_ment_t	*ism_ment;
	int		i, added;
	hatlock_t	*hatlockp;
	int		reload_mmu = 0;
	uint_t		ismshift = page_get_shift(ismszc);
	size_t		ismpgsz = page_get_pagesize(ismszc);
	uint_t		ismmask = (uint_t)ismpgsz - 1;
	size_t		sh_size = ISM_SHIFT(ismshift, len);
	ushort_t	ismhatflag;
	hat_region_cookie_t rcookie;
	sf_scd_t	*old_scdp;

#ifdef DEBUG
	caddr_t		eaddr = addr + len;
#endif /* DEBUG */

	ASSERT(ism_hatid != NULL && sfmmup != NULL);
	ASSERT(sptaddr == ISMID_STARTADDR);
	/*
	 * Check the alignment.
	 */
	if (!ISM_ALIGNED(ismshift, addr) || !ISM_ALIGNED(ismshift, sptaddr))
		return (EINVAL);

	/*
	 * Check size alignment.
	 */
	if (!ISM_ALIGNED(ismshift, len))
		return (EINVAL);

	/*
	 * Allocate ism_ment for the ism_hat's mapping list, and an
	 * ism map blk in case we need one.  We must do our
	 * allocations before acquiring locks to prevent a deadlock
	 * in the kmem allocator on the mapping list lock.
	 */
	new_iblk = kmem_cache_alloc(ism_blk_cache, KM_SLEEP);
	ism_ment = kmem_cache_alloc(ism_ment_cache, KM_SLEEP);

	/*
	 * Serialize ISM mappings with the ISM busy flag, and also the
	 * trap handlers.
	 */
	sfmmu_ismhat_enter(sfmmup, 0);

	/*
	 * Allocate an ism map blk if necessary.
	 */
	if (sfmmup->sfmmu_iblk == NULL) {
		sfmmup->sfmmu_iblk = new_iblk;
		bzero(new_iblk, sizeof (*new_iblk));
		new_iblk->iblk_nextpa = (uint64_t)-1;
		membar_stst();	/* make sure next ptr visible to all CPUs */
		sfmmup->sfmmu_ismblkpa = va_to_pa((caddr_t)new_iblk);
		reload_mmu = 1;
		new_iblk = NULL;
	}

#ifdef DEBUG
	/*
	 * Make sure mapping does not already exist.
	 */
	ism_blkp = sfmmup->sfmmu_iblk;
	while (ism_blkp != NULL) {
		ism_map = ism_blkp->iblk_maps;
		for (i = 0; i < ISM_MAP_SLOTS && ism_map[i].imap_ismhat; i++) {
			if ((addr >= ism_start(ism_map[i]) &&
			    addr < ism_end(ism_map[i])) ||
			    eaddr > ism_start(ism_map[i]) &&
			    eaddr <= ism_end(ism_map[i])) {
				panic("sfmmu_share: Already mapped!");
			}
		}
		ism_blkp = ism_blkp->iblk_next;
	}
#endif /* DEBUG */

	ASSERT(ismszc >= TTE4M);
	if (ismszc == TTE4M) {
		ismhatflag = HAT_4M_FLAG;
	} else if (ismszc == TTE32M) {
		ismhatflag = HAT_32M_FLAG;
	} else if (ismszc == TTE256M) {
		ismhatflag = HAT_256M_FLAG;
	}
	/*
	 * Add mapping to first available mapping slot.
	 */
	ism_blkp = sfmmup->sfmmu_iblk;
	added = 0;
	while (!added) {
		ism_map = ism_blkp->iblk_maps;
		for (i = 0; i < ISM_MAP_SLOTS; i++)  {
			if (ism_map[i].imap_ismhat == NULL) {

				ism_map[i].imap_ismhat = ism_hatid;
				ism_map[i].imap_vb_shift = (uchar_t)ismshift;
				ism_map[i].imap_rid = SFMMU_INVALID_ISMRID;
				ism_map[i].imap_hatflags = ismhatflag;
				ism_map[i].imap_sz_mask = ismmask;
				/*
				 * imap_seg is checked in ISM_CHECK to see if
				 * non-NULL, then other info assumed valid.
				 */
				membar_stst();
				ism_map[i].imap_seg = (uintptr_t)addr | sh_size;
				ism_map[i].imap_ment = ism_ment;

				/*
				 * Now add ourselves to the ism_hat's
				 * mapping list.
				 */
				ism_ment->iment_hat = sfmmup;
				ism_ment->iment_base_va = addr;
				ism_hatid->sfmmu_ismhat = 1;
				mutex_enter(&ism_mlist_lock);
				iment_add(ism_ment, ism_hatid);
				mutex_exit(&ism_mlist_lock);
				added = 1;
				break;
			}
		}
		if (!added && ism_blkp->iblk_next == NULL) {
			ism_blkp->iblk_next = new_iblk;
			new_iblk = NULL;
			bzero(ism_blkp->iblk_next,
			    sizeof (*ism_blkp->iblk_next));
			ism_blkp->iblk_next->iblk_nextpa = (uint64_t)-1;
			membar_stst();
			ism_blkp->iblk_nextpa =
			    va_to_pa((caddr_t)ism_blkp->iblk_next);
		}
		ism_blkp = ism_blkp->iblk_next;
	}

	/*
	 * After calling hat_join_region, sfmmup may join a new SCD or
	 * move from the old scd to a new scd, in which case, we want to
	 * shrink the sfmmup's private tsb size, i.e., pass shrink to
	 * sfmmu_check_page_sizes at the end of this routine.
	 */
	old_scdp = sfmmup->sfmmu_scdp;

	rcookie = hat_join_region(sfmmup, addr, len, (void *)ism_hatid, 0,
	    PROT_ALL, ismszc, NULL, HAT_REGION_ISM);
	if (rcookie != HAT_INVALID_REGION_COOKIE) {
		ism_map[i].imap_rid = (uchar_t)((uint64_t)rcookie);
	}
	/*
	 * Update our counters for this sfmmup's ism mappings.
	 */
	for (i = 0; i <= ismszc; i++) {
		if (!(disable_ism_large_pages & (1 << i)))
			(void) ism_tsb_entries(sfmmup, i);
	}

	/*
	 * For ISM and DISM we do not support 512K pages, so we only only
	 * search the 4M and 8K/64K hashes for 4 pagesize cpus, and search the
	 * 256M or 32M, and 4M and 8K/64K hashes for 6 pagesize cpus.
	 *
	 * Need to set 32M/256M ISM flags to make sure
	 * sfmmu_check_page_sizes() enables them on Panther.
	 */
	ASSERT((disable_ism_large_pages & (1 << TTE512K)) != 0);

	switch (ismszc) {
	case TTE256M:
		if (!SFMMU_FLAGS_ISSET(sfmmup, HAT_256M_ISM)) {
			hatlockp = sfmmu_hat_enter(sfmmup);
			SFMMU_FLAGS_SET(sfmmup, HAT_256M_ISM);
			sfmmu_hat_exit(hatlockp);
		}
		break;
	case TTE32M:
		if (!SFMMU_FLAGS_ISSET(sfmmup, HAT_32M_ISM)) {
			hatlockp = sfmmu_hat_enter(sfmmup);
			SFMMU_FLAGS_SET(sfmmup, HAT_32M_ISM);
			sfmmu_hat_exit(hatlockp);
		}
		break;
	default:
		break;
	}

	/*
	 * If we updated the ismblkpa for this HAT we must make
	 * sure all CPUs running this process reload their tsbmiss area.
	 * Otherwise they will fail to load the mappings in the tsbmiss
	 * handler and will loop calling pagefault().
	 */
	if (reload_mmu) {
		hatlockp = sfmmu_hat_enter(sfmmup);
		sfmmu_sync_mmustate(sfmmup);
		sfmmu_hat_exit(hatlockp);
	}

	sfmmu_ismhat_exit(sfmmup, 0);

	/*
	 * Free up ismblk if we didn't use it.
	 */
	if (new_iblk != NULL)
		kmem_cache_free(ism_blk_cache, new_iblk);

	/*
	 * Check TSB and TLB page sizes.
	 */
	if (sfmmup->sfmmu_scdp != NULL && old_scdp != sfmmup->sfmmu_scdp) {
		sfmmu_check_page_sizes(sfmmup, 0);
	} else {
		sfmmu_check_page_sizes(sfmmup, 1);
	}
	return (0);
}

/*
 * hat_unshare removes exactly one ism_map from
 * this process's as.  It expects multiple calls
 * to hat_unshare for multiple shm segments.
 */
void
hat_unshare(struct hat *sfmmup, caddr_t addr, size_t len, uint_t ismszc)
{
	ism_map_t 	*ism_map;
	ism_ment_t	*free_ment = NULL;
	ism_blk_t	*ism_blkp;
	struct hat	*ism_hatid;
	int 		found, i;
	hatlock_t	*hatlockp;
	struct tsb_info	*tsbinfo;
	uint_t		ismshift = page_get_shift(ismszc);
	size_t		sh_size = ISM_SHIFT(ismshift, len);
	uchar_t		ism_rid;
	sf_scd_t	*old_scdp;

	ASSERT(ISM_ALIGNED(ismshift, addr));
	ASSERT(ISM_ALIGNED(ismshift, len));
	ASSERT(sfmmup != NULL);
	ASSERT(sfmmup != ksfmmup);

	ASSERT(sfmmup->sfmmu_as != NULL);

	/*
	 * Make sure that during the entire time ISM mappings are removed,
	 * the trap handlers serialize behind us, and that no one else
	 * can be mucking with ISM mappings.  This also lets us get away
	 * with not doing expensive cross calls to flush the TLB -- we
	 * just discard the context, flush the entire TSB, and call it
	 * a day.
	 */
	sfmmu_ismhat_enter(sfmmup, 0);

	/*
	 * Remove the mapping.
	 *
	 * We can't have any holes in the ism map.
	 * The tsb miss code while searching the ism map will
	 * stop on an empty map slot.  So we must move
	 * everyone past the hole up 1 if any.
	 *
	 * Also empty ism map blks are not freed until the
	 * process exits. This is to prevent a MT race condition
	 * between sfmmu_unshare() and sfmmu_tsbmiss_exception().
	 */
	found = 0;
	ism_blkp = sfmmup->sfmmu_iblk;
	while (!found && ism_blkp != NULL) {
		ism_map = ism_blkp->iblk_maps;
		for (i = 0; i < ISM_MAP_SLOTS; i++) {
			if (addr == ism_start(ism_map[i]) &&
			    sh_size == (size_t)(ism_size(ism_map[i]))) {
				found = 1;
				break;
			}
		}
		if (!found)
			ism_blkp = ism_blkp->iblk_next;
	}

	if (found) {
		ism_hatid = ism_map[i].imap_ismhat;
		ism_rid = ism_map[i].imap_rid;
		ASSERT(ism_hatid != NULL);
		ASSERT(ism_hatid->sfmmu_ismhat == 1);

		/*
		 * After hat_leave_region, the sfmmup may leave SCD,
		 * in which case, we want to grow the private tsb size when
		 * calling sfmmu_check_page_sizes at the end of the routine.
		 */
		old_scdp = sfmmup->sfmmu_scdp;
		/*
		 * Then remove ourselves from the region.
		 */
		if (ism_rid != SFMMU_INVALID_ISMRID) {
			hat_leave_region(sfmmup, (void *)((uint64_t)ism_rid),
			    HAT_REGION_ISM);
		}

		/*
		 * And now guarantee that any other cpu
		 * that tries to process an ISM miss
		 * will go to tl=0.
		 */
		hatlockp = sfmmu_hat_enter(sfmmup);
		sfmmu_invalidate_ctx(sfmmup);
		sfmmu_hat_exit(hatlockp);

		/*
		 * Remove ourselves from the ism mapping list.
		 */
		mutex_enter(&ism_mlist_lock);
		iment_sub(ism_map[i].imap_ment, ism_hatid);
		mutex_exit(&ism_mlist_lock);
		free_ment = ism_map[i].imap_ment;

		/*
		 * We delete the ism map by copying
		 * the next map over the current one.
		 * We will take the next one in the maps
		 * array or from the next ism_blk.
		 */
		while (ism_blkp != NULL) {
			ism_map = ism_blkp->iblk_maps;
			while (i < (ISM_MAP_SLOTS - 1)) {
				ism_map[i] = ism_map[i + 1];
				i++;
			}
			/* i == (ISM_MAP_SLOTS - 1) */
			ism_blkp = ism_blkp->iblk_next;
			if (ism_blkp != NULL) {
				ism_map[i] = ism_blkp->iblk_maps[0];
				i = 0;
			} else {
				ism_map[i].imap_seg = 0;
				ism_map[i].imap_vb_shift = 0;
				ism_map[i].imap_rid = SFMMU_INVALID_ISMRID;
				ism_map[i].imap_hatflags = 0;
				ism_map[i].imap_sz_mask = 0;
				ism_map[i].imap_ismhat = NULL;
				ism_map[i].imap_ment = NULL;
			}
		}

		/*
		 * Now flush entire TSB for the process, since
		 * demapping page by page can be too expensive.
		 * We don't have to flush the TLB here anymore
		 * since we switch to a new TLB ctx instead.
		 * Also, there is no need to flush if the process
		 * is exiting since the TSB will be freed later.
		 */
		if (!sfmmup->sfmmu_free) {
			hatlockp = sfmmu_hat_enter(sfmmup);
			for (tsbinfo = sfmmup->sfmmu_tsb; tsbinfo != NULL;
			    tsbinfo = tsbinfo->tsb_next) {
				if (tsbinfo->tsb_flags & TSB_SWAPPED)
					continue;
				if (tsbinfo->tsb_flags & TSB_RELOC_FLAG) {
					tsbinfo->tsb_flags |=
					    TSB_FLUSH_NEEDED;
					continue;
				}

				sfmmu_inv_tsb(tsbinfo->tsb_va,
				    TSB_BYTES(tsbinfo->tsb_szc));
			}
			sfmmu_hat_exit(hatlockp);
		}
	}

	/*
	 * Update our counters for this sfmmup's ism mappings.
	 */
	for (i = 0; i <= ismszc; i++) {
		if (!(disable_ism_large_pages & (1 << i)))
			(void) ism_tsb_entries(sfmmup, i);
	}

	sfmmu_ismhat_exit(sfmmup, 0);

	/*
	 * We must do our freeing here after dropping locks
	 * to prevent a deadlock in the kmem allocator on the
	 * mapping list lock.
	 */
	if (free_ment != NULL)
		kmem_cache_free(ism_ment_cache, free_ment);

	/*
	 * Check TSB and TLB page sizes if the process isn't exiting.
	 */
	if (!sfmmup->sfmmu_free) {
		if (found && old_scdp != NULL && sfmmup->sfmmu_scdp == NULL) {
			sfmmu_check_page_sizes(sfmmup, 1);
		} else {
			sfmmu_check_page_sizes(sfmmup, 0);
		}
	}
}

/* ARGSUSED */
static int
sfmmu_idcache_constructor(void *buf, void *cdrarg, int kmflags)
{
	/* void *buf is sfmmu_t pointer */
	bzero(buf, sizeof (sfmmu_t));

	return (0);
}

/* ARGSUSED */
static void
sfmmu_idcache_destructor(void *buf, void *cdrarg)
{
	/* void *buf is sfmmu_t pointer */
}

/*
 * setup kmem hmeblks by bzeroing all members and initializing the nextpa
 * field to be the pa of this hmeblk
 */
/* ARGSUSED */
static int
sfmmu_hblkcache_constructor(void *buf, void *cdrarg, int kmflags)
{
	struct hme_blk *hmeblkp;

	bzero(buf, (size_t)cdrarg);
	hmeblkp = (struct hme_blk *)buf;
	hmeblkp->hblk_nextpa = va_to_pa((caddr_t)hmeblkp);

#ifdef	HBLK_TRACE
	mutex_init(&hmeblkp->hblk_audit_lock, NULL, MUTEX_DEFAULT, NULL);
#endif	/* HBLK_TRACE */

	return (0);
}

/* ARGSUSED */
static void
sfmmu_hblkcache_destructor(void *buf, void *cdrarg)
{

#ifdef	HBLK_TRACE

	struct hme_blk *hmeblkp;

	hmeblkp = (struct hme_blk *)buf;
	mutex_destroy(&hmeblkp->hblk_audit_lock);

#endif	/* HBLK_TRACE */
}

#define	SFMMU_CACHE_RECLAIM_SCAN_RATIO 8
static int sfmmu_cache_reclaim_scan_ratio = SFMMU_CACHE_RECLAIM_SCAN_RATIO;
/*
 * The kmem allocator will callback into our reclaim routine when the system
 * is running low in memory.  We traverse the hash and free up all unused but
 * still cached hme_blks.  We also traverse the free list and free them up
 * as well.
 */
/*ARGSUSED*/
static void
sfmmu_hblkcache_reclaim(void *cdrarg)
{
	int i;
	struct hmehash_bucket *hmebp;
	struct hme_blk *hmeblkp, *nx_hblk, *pr_hblk = NULL;
	static struct hmehash_bucket *uhmehash_reclaim_hand;
	static struct hmehash_bucket *khmehash_reclaim_hand;
	struct hme_blk *list = NULL, *last_hmeblkp;
	cpuset_t cpuset = cpu_ready_set;
	cpu_hme_pend_t *cpuhp;

	/* Free up hmeblks on the cpu pending lists */
	for (i = 0; i < NCPU; i++) {
		cpuhp = &cpu_hme_pend[i];
		if (cpuhp->chp_listp != NULL)  {
			mutex_enter(&cpuhp->chp_mutex);
			if (cpuhp->chp_listp == NULL) {
				mutex_exit(&cpuhp->chp_mutex);
				continue;
			}
			for (last_hmeblkp = cpuhp->chp_listp;
			    last_hmeblkp->hblk_next != NULL;
			    last_hmeblkp = last_hmeblkp->hblk_next)
				;
			last_hmeblkp->hblk_next = list;
			list = cpuhp->chp_listp;
			cpuhp->chp_listp = NULL;
			cpuhp->chp_count = 0;
			mutex_exit(&cpuhp->chp_mutex);
		}

	}

	if (list != NULL) {
		kpreempt_disable();
		CPUSET_DEL(cpuset, CPU->cpu_id);
		xt_sync(cpuset);
		xt_sync(cpuset);
		kpreempt_enable();
		sfmmu_hblk_free(&list);
		list = NULL;
	}

	hmebp = uhmehash_reclaim_hand;
	if (hmebp == NULL || hmebp > &uhme_hash[UHMEHASH_SZ])
		uhmehash_reclaim_hand = hmebp = uhme_hash;
	uhmehash_reclaim_hand += UHMEHASH_SZ / sfmmu_cache_reclaim_scan_ratio;

	for (i = UHMEHASH_SZ / sfmmu_cache_reclaim_scan_ratio; i; i--) {
		if (SFMMU_HASH_LOCK_TRYENTER(hmebp) != 0) {
			hmeblkp = hmebp->hmeblkp;
			pr_hblk = NULL;
			while (hmeblkp) {
				nx_hblk = hmeblkp->hblk_next;
				if (!hmeblkp->hblk_vcnt &&
				    !hmeblkp->hblk_hmecnt) {
					sfmmu_hblk_hash_rm(hmebp, hmeblkp,
					    pr_hblk, &list, 0);
				} else {
					pr_hblk = hmeblkp;
				}
				hmeblkp = nx_hblk;
			}
			SFMMU_HASH_UNLOCK(hmebp);
		}
		if (hmebp++ == &uhme_hash[UHMEHASH_SZ])
			hmebp = uhme_hash;
	}

	hmebp = khmehash_reclaim_hand;
	if (hmebp == NULL || hmebp > &khme_hash[KHMEHASH_SZ])
		khmehash_reclaim_hand = hmebp = khme_hash;
	khmehash_reclaim_hand += KHMEHASH_SZ / sfmmu_cache_reclaim_scan_ratio;

	for (i = KHMEHASH_SZ / sfmmu_cache_reclaim_scan_ratio; i; i--) {
		if (SFMMU_HASH_LOCK_TRYENTER(hmebp) != 0) {
			hmeblkp = hmebp->hmeblkp;
			pr_hblk = NULL;
			while (hmeblkp) {
				nx_hblk = hmeblkp->hblk_next;
				if (!hmeblkp->hblk_vcnt &&
				    !hmeblkp->hblk_hmecnt) {
					sfmmu_hblk_hash_rm(hmebp, hmeblkp,
					    pr_hblk, &list, 0);
				} else {
					pr_hblk = hmeblkp;
				}
				hmeblkp = nx_hblk;
			}
			SFMMU_HASH_UNLOCK(hmebp);
		}
		if (hmebp++ == &khme_hash[KHMEHASH_SZ])
			hmebp = khme_hash;
	}
	sfmmu_hblks_list_purge(&list, 0);
}

/*
 * sfmmu_get_ppvcolor should become a vm_machdep or hatop interface.
 * same goes for sfmmu_get_addrvcolor().
 *
 * This function will return the virtual color for the specified page. The
 * virtual color corresponds to this page current mapping or its last mapping.
 * It is used by memory allocators to choose addresses with the correct
 * alignment so vac consistency is automatically maintained.  If the page
 * has no color it returns -1.
 */
/*ARGSUSED*/
int
sfmmu_get_ppvcolor(struct page *pp)
{
#ifdef VAC
	int color;

	if (!(cache & CACHE_VAC) || PP_NEWPAGE(pp)) {
		return (-1);
	}
	color = PP_GET_VCOLOR(pp);
	ASSERT(color < mmu_btop(shm_alignment));
	return (color);
#else
	return (-1);
#endif	/* VAC */
}

/*
 * This function will return the desired alignment for vac consistency
 * (vac color) given a virtual address.  If no vac is present it returns -1.
 */
/*ARGSUSED*/
int
sfmmu_get_addrvcolor(caddr_t vaddr)
{
#ifdef VAC
	if (cache & CACHE_VAC) {
		return (addr_to_vcolor(vaddr));
	} else {
		return (-1);
	}
#else
	return (-1);
#endif	/* VAC */
}

#ifdef VAC
/*
 * Check for conflicts.
 * A conflict exists if the new and existent mappings do not match in
 * their "shm_alignment fields. If conflicts exist, the existant mappings
 * are flushed unless one of them is locked. If one of them is locked, then
 * the mappings are flushed and converted to non-cacheable mappings.
 */
static void
sfmmu_vac_conflict(struct hat *hat, caddr_t addr, page_t *pp)
{
	struct hat *tmphat;
	struct sf_hment *sfhmep, *tmphme = NULL;
	struct hme_blk *hmeblkp;
	int vcolor;
	tte_t tte;

	ASSERT(sfmmu_mlist_held(pp));
	ASSERT(!PP_ISNC(pp));		/* page better be cacheable */

	vcolor = addr_to_vcolor(addr);
	if (PP_NEWPAGE(pp)) {
		PP_SET_VCOLOR(pp, vcolor);
		return;
	}

	if (PP_GET_VCOLOR(pp) == vcolor) {
		return;
	}

	if (!PP_ISMAPPED(pp) && !PP_ISMAPPED_KPM(pp)) {
		/*
		 * Previous user of page had a different color
		 * but since there are no current users
		 * we just flush the cache and change the color.
		 */
		SFMMU_STAT(sf_pgcolor_conflict);
		sfmmu_cache_flush(pp->p_pagenum, PP_GET_VCOLOR(pp));
		PP_SET_VCOLOR(pp, vcolor);
		return;
	}

	/*
	 * If we get here we have a vac conflict with a current
	 * mapping.  VAC conflict policy is as follows.
	 * - The default is to unload the other mappings unless:
	 * - If we have a large mapping we uncache the page.
	 * We need to uncache the rest of the large page too.
	 * - If any of the mappings are locked we uncache the page.
	 * - If the requested mapping is inconsistent
	 * with another mapping and that mapping
	 * is in the same address space we have to
	 * make it non-cached.  The default thing
	 * to do is unload the inconsistent mapping
	 * but if they are in the same address space
	 * we run the risk of unmapping the pc or the
	 * stack which we will use as we return to the user,
	 * in which case we can then fault on the thing
	 * we just unloaded and get into an infinite loop.
	 */
	if (PP_ISMAPPED_LARGE(pp)) {
		int sz;

		/*
		 * Existing mapping is for big pages. We don't unload
		 * existing big mappings to satisfy new mappings.
		 * Always convert all mappings to TNC.
		 */
		sz = fnd_mapping_sz(pp);
		pp = PP_GROUPLEADER(pp, sz);
		SFMMU_STAT_ADD(sf_uncache_conflict, TTEPAGES(sz));
		sfmmu_page_cache_array(pp, HAT_TMPNC, CACHE_FLUSH,
		    TTEPAGES(sz));

		return;
	}

	/*
	 * check if any mapping is in same as or if it is locked
	 * since in that case we need to uncache.
	 */
	for (sfhmep = pp->p_mapping; sfhmep; sfhmep = tmphme) {
		tmphme = sfhmep->hme_next;
		if (IS_PAHME(sfhmep))
			continue;
		hmeblkp = sfmmu_hmetohblk(sfhmep);
		tmphat = hblktosfmmu(hmeblkp);
		sfmmu_copytte(&sfhmep->hme_tte, &tte);
		ASSERT(TTE_IS_VALID(&tte));
		if (hmeblkp->hblk_shared || tmphat == hat ||
		    hmeblkp->hblk_lckcnt) {
			/*
			 * We have an uncache conflict
			 */
			SFMMU_STAT(sf_uncache_conflict);
			sfmmu_page_cache_array(pp, HAT_TMPNC, CACHE_FLUSH, 1);
			return;
		}
	}

	/*
	 * We have an unload conflict
	 * We have already checked for LARGE mappings, therefore
	 * the remaining mapping(s) must be TTE8K.
	 */
	SFMMU_STAT(sf_unload_conflict);

	for (sfhmep = pp->p_mapping; sfhmep; sfhmep = tmphme) {
		tmphme = sfhmep->hme_next;
		if (IS_PAHME(sfhmep))
			continue;
		hmeblkp = sfmmu_hmetohblk(sfhmep);
		ASSERT(!hmeblkp->hblk_shared);
		(void) sfmmu_pageunload(pp, sfhmep, TTE8K);
	}

	if (PP_ISMAPPED_KPM(pp))
		sfmmu_kpm_vac_unload(pp, addr);

	/*
	 * Unloads only do TLB flushes so we need to flush the
	 * cache here.
	 */
	sfmmu_cache_flush(pp->p_pagenum, PP_GET_VCOLOR(pp));
	PP_SET_VCOLOR(pp, vcolor);
}

/*
 * Whenever a mapping is unloaded and the page is in TNC state,
 * we see if the page can be made cacheable again. 'pp' is
 * the page that we just unloaded a mapping from, the size
 * of mapping that was unloaded is 'ottesz'.
 * Remark:
 * The recache policy for mpss pages can leave a performance problem
 * under the following circumstances:
 * . A large page in uncached mode has just been unmapped.
 * . All constituent pages are TNC due to a conflicting small mapping.
 * . There are many other, non conflicting, small mappings around for
 *   a lot of the constituent pages.
 * . We're called w/ the "old" groupleader page and the old ottesz,
 *   but this is irrelevant, since we're no more "PP_ISMAPPED_LARGE", so
 *   we end up w/ TTE8K or npages == 1.
 * . We call tst_tnc w/ the old groupleader only, and if there is no
 *   conflict, we re-cache only this page.
 * . All other small mappings are not checked and will be left in TNC mode.
 * The problem is not very serious because:
 * . mpss is actually only defined for heap and stack, so the probability
 *   is not very high that a large page mapping exists in parallel to a small
 *   one (this is possible, but seems to be bad programming style in the
 *   appl).
 * . The problem gets a little bit more serious, when those TNC pages
 *   have to be mapped into kernel space, e.g. for networking.
 * . When VAC alias conflicts occur in applications, this is regarded
 *   as an application bug. So if kstat's show them, the appl should
 *   be changed anyway.
 */
void
conv_tnc(page_t *pp, int ottesz)
{
	int cursz, dosz;
	pgcnt_t curnpgs, dopgs;
	pgcnt_t pg64k;
	page_t *pp2;

	/*
	 * Determine how big a range we check for TNC and find
	 * leader page. cursz is the size of the biggest
	 * mapping that still exist on 'pp'.
	 */
	if (PP_ISMAPPED_LARGE(pp)) {
		cursz = fnd_mapping_sz(pp);
	} else {
		cursz = TTE8K;
	}

	if (ottesz >= cursz) {
		dosz = ottesz;
		pp2 = pp;
	} else {
		dosz = cursz;
		pp2 = PP_GROUPLEADER(pp, dosz);
	}

	pg64k = TTEPAGES(TTE64K);
	dopgs = TTEPAGES(dosz);

	ASSERT(dopgs == 1 || ((dopgs & (pg64k - 1)) == 0));

	while (dopgs != 0) {
		curnpgs = TTEPAGES(cursz);
		if (tst_tnc(pp2, curnpgs)) {
			SFMMU_STAT_ADD(sf_recache, curnpgs);
			sfmmu_page_cache_array(pp2, HAT_CACHE, CACHE_NO_FLUSH,
			    curnpgs);
		}

		ASSERT(dopgs >= curnpgs);
		dopgs -= curnpgs;

		if (dopgs == 0) {
			break;
		}

		pp2 = PP_PAGENEXT_N(pp2, curnpgs);
		if (((dopgs & (pg64k - 1)) == 0) && PP_ISMAPPED_LARGE(pp2)) {
			cursz = fnd_mapping_sz(pp2);
		} else {
			cursz = TTE8K;
		}
	}
}

/*
 * Returns 1 if page(s) can be converted from TNC to cacheable setting,
 * returns 0 otherwise. Note that oaddr argument is valid for only
 * 8k pages.
 */
int
tst_tnc(page_t *pp, pgcnt_t npages)
{
	struct	sf_hment *sfhme;
	struct	hme_blk *hmeblkp;
	tte_t	tte;
	caddr_t	vaddr;
	int	clr_valid = 0;
	int 	color, color1, bcolor;
	int	i, ncolors;

	ASSERT(pp != NULL);
	ASSERT(!(cache & CACHE_WRITEBACK));

	if (npages > 1) {
		ncolors = CACHE_NUM_COLOR;
	}

	for (i = 0; i < npages; i++) {
		ASSERT(sfmmu_mlist_held(pp));
		ASSERT(PP_ISTNC(pp));
		ASSERT(PP_GET_VCOLOR(pp) == NO_VCOLOR);

		if (PP_ISPNC(pp)) {
			return (0);
		}

		clr_valid = 0;
		if (PP_ISMAPPED_KPM(pp)) {
			caddr_t kpmvaddr;

			ASSERT(kpm_enable);
			kpmvaddr = hat_kpm_page2va(pp, 1);
			ASSERT(!(npages > 1 && IS_KPM_ALIAS_RANGE(kpmvaddr)));
			color1 = addr_to_vcolor(kpmvaddr);
			clr_valid = 1;
		}

		for (sfhme = pp->p_mapping; sfhme; sfhme = sfhme->hme_next) {
			if (IS_PAHME(sfhme))
				continue;
			hmeblkp = sfmmu_hmetohblk(sfhme);

			sfmmu_copytte(&sfhme->hme_tte, &tte);
			ASSERT(TTE_IS_VALID(&tte));

			vaddr = tte_to_vaddr(hmeblkp, tte);
			color = addr_to_vcolor(vaddr);

			if (npages > 1) {
				/*
				 * If there is a big mapping, make sure
				 * 8K mapping is consistent with the big
				 * mapping.
				 */
				bcolor = i % ncolors;
				if (color != bcolor) {
					return (0);
				}
			}
			if (!clr_valid) {
				clr_valid = 1;
				color1 = color;
			}

			if (color1 != color) {
				return (0);
			}
		}

		pp = PP_PAGENEXT(pp);
	}

	return (1);
}

void
sfmmu_page_cache_array(page_t *pp, int flags, int cache_flush_flag,
	pgcnt_t npages)
{
	kmutex_t *pmtx;
	int i, ncolors, bcolor;
	kpm_hlk_t *kpmp;
	cpuset_t cpuset;

	ASSERT(pp != NULL);
	ASSERT(!(cache & CACHE_WRITEBACK));

	kpmp = sfmmu_kpm_kpmp_enter(pp, npages);
	pmtx = sfmmu_page_enter(pp);

	/*
	 * Fast path caching single unmapped page
	 */
	if (npages == 1 && !PP_ISMAPPED(pp) && !PP_ISMAPPED_KPM(pp) &&
	    flags == HAT_CACHE) {
		PP_CLRTNC(pp);
		PP_CLRPNC(pp);
		sfmmu_page_exit(pmtx);
		sfmmu_kpm_kpmp_exit(kpmp);
		return;
	}

	/*
	 * We need to capture all cpus in order to change cacheability
	 * because we can't allow one cpu to access the same physical
	 * page using a cacheable and a non-cachebale mapping at the same
	 * time. Since we may end up walking the ism mapping list
	 * have to grab it's lock now since we can't after all the
	 * cpus have been captured.
	 */
	sfmmu_hat_lock_all();
	mutex_enter(&ism_mlist_lock);
	kpreempt_disable();
	cpuset = cpu_ready_set;
	xc_attention(cpuset);

	if (npages > 1) {
		/*
		 * Make sure all colors are flushed since the
		 * sfmmu_page_cache() only flushes one color-
		 * it does not know big pages.
		 */
		ncolors = CACHE_NUM_COLOR;
		if (flags & HAT_TMPNC) {
			for (i = 0; i < ncolors; i++) {
				sfmmu_cache_flushcolor(i, pp->p_pagenum);
			}
			cache_flush_flag = CACHE_NO_FLUSH;
		}
	}

	for (i = 0; i < npages; i++) {

		ASSERT(sfmmu_mlist_held(pp));

		if (!(flags == HAT_TMPNC && PP_ISTNC(pp))) {

			if (npages > 1) {
				bcolor = i % ncolors;
			} else {
				bcolor = NO_VCOLOR;
			}

			sfmmu_page_cache(pp, flags, cache_flush_flag,
			    bcolor);
		}

		pp = PP_PAGENEXT(pp);
	}

	xt_sync(cpuset);
	xc_dismissed(cpuset);
	mutex_exit(&ism_mlist_lock);
	sfmmu_hat_unlock_all();
	sfmmu_page_exit(pmtx);
	sfmmu_kpm_kpmp_exit(kpmp);
	kpreempt_enable();
}

/*
 * This function changes the virtual cacheability of all mappings to a
 * particular page.  When changing from uncache to cacheable the mappings will
 * only be changed if all of them have the same virtual color.
 * We need to flush the cache in all cpus.  It is possible that
 * a process referenced a page as cacheable but has sinced exited
 * and cleared the mapping list.  We still to flush it but have no
 * state so all cpus is the only alternative.
 */
static void
sfmmu_page_cache(page_t *pp, int flags, int cache_flush_flag, int bcolor)
{
	struct	sf_hment *sfhme;
	struct	hme_blk *hmeblkp;
	sfmmu_t *sfmmup;
	tte_t	tte, ttemod;
	caddr_t	vaddr;
	int	ret, color;
	pfn_t	pfn;

	color = bcolor;
	pfn = pp->p_pagenum;

	for (sfhme = pp->p_mapping; sfhme; sfhme = sfhme->hme_next) {

		if (IS_PAHME(sfhme))
			continue;
		hmeblkp = sfmmu_hmetohblk(sfhme);

		sfmmu_copytte(&sfhme->hme_tte, &tte);
		ASSERT(TTE_IS_VALID(&tte));
		vaddr = tte_to_vaddr(hmeblkp, tte);
		color = addr_to_vcolor(vaddr);

#ifdef DEBUG
		if ((flags & HAT_CACHE) && bcolor != NO_VCOLOR) {
			ASSERT(color == bcolor);
		}
#endif

		ASSERT(flags != HAT_TMPNC || color == PP_GET_VCOLOR(pp));

		ttemod = tte;
		if (flags & (HAT_UNCACHE | HAT_TMPNC)) {
			TTE_CLR_VCACHEABLE(&ttemod);
		} else {	/* flags & HAT_CACHE */
			TTE_SET_VCACHEABLE(&ttemod);
		}
		ret = sfmmu_modifytte_try(&tte, &ttemod, &sfhme->hme_tte);
		if (ret < 0) {
			/*
			 * Since all cpus are captured modifytte should not
			 * fail.
			 */
			panic("sfmmu_page_cache: write to tte failed");
		}

		sfmmup = hblktosfmmu(hmeblkp);
		if (cache_flush_flag == CACHE_FLUSH) {
			/*
			 * Flush TSBs, TLBs and caches
			 */
			if (hmeblkp->hblk_shared) {
				sf_srd_t *srdp = (sf_srd_t *)sfmmup;
				uint_t rid = hmeblkp->hblk_tag.htag_rid;
				sf_region_t *rgnp;
				ASSERT(SFMMU_IS_SHMERID_VALID(rid));
				ASSERT(rid < SFMMU_MAX_HME_REGIONS);
				ASSERT(srdp != NULL);
				rgnp = srdp->srd_hmergnp[rid];
				SFMMU_VALIDATE_SHAREDHBLK(hmeblkp,
				    srdp, rgnp, rid);
				(void) sfmmu_rgntlb_demap(vaddr, rgnp,
				    hmeblkp, 0);
				sfmmu_cache_flush(pfn, addr_to_vcolor(vaddr));
			} else if (sfmmup->sfmmu_ismhat) {
				if (flags & HAT_CACHE) {
					SFMMU_STAT(sf_ism_recache);
				} else {
					SFMMU_STAT(sf_ism_uncache);
				}
				sfmmu_ismtlbcache_demap(vaddr, sfmmup, hmeblkp,
				    pfn, CACHE_FLUSH);
			} else {
				sfmmu_tlbcache_demap(vaddr, sfmmup, hmeblkp,
				    pfn, 0, FLUSH_ALL_CPUS, CACHE_FLUSH, 1);
			}

			/*
			 * all cache entries belonging to this pfn are
			 * now flushed.
			 */
			cache_flush_flag = CACHE_NO_FLUSH;
		} else {
			/*
			 * Flush only TSBs and TLBs.
			 */
			if (hmeblkp->hblk_shared) {
				sf_srd_t *srdp = (sf_srd_t *)sfmmup;
				uint_t rid = hmeblkp->hblk_tag.htag_rid;
				sf_region_t *rgnp;
				ASSERT(SFMMU_IS_SHMERID_VALID(rid));
				ASSERT(rid < SFMMU_MAX_HME_REGIONS);
				ASSERT(srdp != NULL);
				rgnp = srdp->srd_hmergnp[rid];
				SFMMU_VALIDATE_SHAREDHBLK(hmeblkp,
				    srdp, rgnp, rid);
				(void) sfmmu_rgntlb_demap(vaddr, rgnp,
				    hmeblkp, 0);
			} else if (sfmmup->sfmmu_ismhat) {
				if (flags & HAT_CACHE) {
					SFMMU_STAT(sf_ism_recache);
				} else {
					SFMMU_STAT(sf_ism_uncache);
				}
				sfmmu_ismtlbcache_demap(vaddr, sfmmup, hmeblkp,
				    pfn, CACHE_NO_FLUSH);
			} else {
				sfmmu_tlb_demap(vaddr, sfmmup, hmeblkp, 0, 1);
			}
		}
	}

	if (PP_ISMAPPED_KPM(pp))
		sfmmu_kpm_page_cache(pp, flags, cache_flush_flag);

	switch (flags) {

		default:
			panic("sfmmu_pagecache: unknown flags");
			break;

		case HAT_CACHE:
			PP_CLRTNC(pp);
			PP_CLRPNC(pp);
			PP_SET_VCOLOR(pp, color);
			break;

		case HAT_TMPNC:
			PP_SETTNC(pp);
			PP_SET_VCOLOR(pp, NO_VCOLOR);
			break;

		case HAT_UNCACHE:
			PP_SETPNC(pp);
			PP_CLRTNC(pp);
			PP_SET_VCOLOR(pp, NO_VCOLOR);
			break;
	}
}
#endif	/* VAC */


/*
 * Wrapper routine used to return a context.
 *
 * It's the responsibility of the caller to guarantee that the
 * process serializes on calls here by taking the HAT lock for
 * the hat.
 *
 */
static void
sfmmu_get_ctx(sfmmu_t *sfmmup)
{
	mmu_ctx_t *mmu_ctxp;
	uint_t pstate_save;
	int ret;

	ASSERT(sfmmu_hat_lock_held(sfmmup));
	ASSERT(sfmmup != ksfmmup);

	if (SFMMU_FLAGS_ISSET(sfmmup, HAT_ALLCTX_INVALID)) {
		sfmmu_setup_tsbinfo(sfmmup);
		SFMMU_FLAGS_CLEAR(sfmmup, HAT_ALLCTX_INVALID);
	}

	kpreempt_disable();

	mmu_ctxp = CPU_MMU_CTXP(CPU);
	ASSERT(mmu_ctxp);
	ASSERT(mmu_ctxp->mmu_idx < max_mmu_ctxdoms);
	ASSERT(mmu_ctxp == mmu_ctxs_tbl[mmu_ctxp->mmu_idx]);

	/*
	 * Do a wrap-around if cnum reaches the max # cnum supported by a MMU.
	 */
	if (mmu_ctxp->mmu_cnum == mmu_ctxp->mmu_nctxs)
		sfmmu_ctx_wrap_around(mmu_ctxp, B_TRUE);

	/*
	 * Let the MMU set up the page sizes to use for
	 * this context in the TLB. Don't program 2nd dtlb for ism hat.
	 */
	if ((&mmu_set_ctx_page_sizes) && (sfmmup->sfmmu_ismhat == 0)) {
		mmu_set_ctx_page_sizes(sfmmup);
	}

	/*
	 * sfmmu_alloc_ctx and sfmmu_load_mmustate will be performed with
	 * interrupts disabled to prevent race condition with wrap-around
	 * ctx invalidatation. In sun4v, ctx invalidation also involves
	 * a HV call to set the number of TSBs to 0. If interrupts are not
	 * disabled until after sfmmu_load_mmustate is complete TSBs may
	 * become assigned to INVALID_CONTEXT. This is not allowed.
	 */
	pstate_save = sfmmu_disable_intrs();

	if (sfmmu_alloc_ctx(sfmmup, 1, CPU, SFMMU_PRIVATE) &&
	    sfmmup->sfmmu_scdp != NULL) {
		sf_scd_t *scdp = sfmmup->sfmmu_scdp;
		sfmmu_t *scsfmmup = scdp->scd_sfmmup;
		ret = sfmmu_alloc_ctx(scsfmmup, 1, CPU, SFMMU_SHARED);
		/* debug purpose only */
		ASSERT(!ret || scsfmmup->sfmmu_ctxs[CPU_MMU_IDX(CPU)].cnum
		    != INVALID_CONTEXT);
	}
	sfmmu_load_mmustate(sfmmup);

	sfmmu_enable_intrs(pstate_save);

	kpreempt_enable();
}

/*
 * When all cnums are used up in a MMU, cnum will wrap around to the
 * next generation and start from 2.
 */
static void
sfmmu_ctx_wrap_around(mmu_ctx_t *mmu_ctxp, boolean_t reset_cnum)
{

	/* caller must have disabled the preemption */
	ASSERT(curthread->t_preempt >= 1);
	ASSERT(mmu_ctxp != NULL);

	/* acquire Per-MMU (PM) spin lock */
	mutex_enter(&mmu_ctxp->mmu_lock);

	/* re-check to see if wrap-around is needed */
	if (mmu_ctxp->mmu_cnum < mmu_ctxp->mmu_nctxs)
		goto done;

	SFMMU_MMU_STAT(mmu_wrap_around);

	/* update gnum */
	ASSERT(mmu_ctxp->mmu_gnum != 0);
	mmu_ctxp->mmu_gnum++;
	if (mmu_ctxp->mmu_gnum == 0 ||
	    mmu_ctxp->mmu_gnum > MAX_SFMMU_GNUM_VAL) {
		cmn_err(CE_PANIC, "mmu_gnum of mmu_ctx 0x%p is out of bound.",
		    (void *)mmu_ctxp);
	}

	if (mmu_ctxp->mmu_ncpus > 1) {
		cpuset_t cpuset;

		membar_enter(); /* make sure updated gnum visible */

		SFMMU_XCALL_STATS(NULL);

		/* xcall to others on the same MMU to invalidate ctx */
		cpuset = mmu_ctxp->mmu_cpuset;
		ASSERT(CPU_IN_SET(cpuset, CPU->cpu_id) || !reset_cnum);
		CPUSET_DEL(cpuset, CPU->cpu_id);
		CPUSET_AND(cpuset, cpu_ready_set);

		/*
		 * Pass in INVALID_CONTEXT as the first parameter to
		 * sfmmu_raise_tsb_exception, which invalidates the context
		 * of any process running on the CPUs in the MMU.
		 */
		xt_some(cpuset, sfmmu_raise_tsb_exception,
		    INVALID_CONTEXT, INVALID_CONTEXT);
		xt_sync(cpuset);

		SFMMU_MMU_STAT(mmu_tsb_raise_exception);
	}

	if (sfmmu_getctx_sec() != INVALID_CONTEXT) {
		sfmmu_setctx_sec(INVALID_CONTEXT);
		sfmmu_clear_utsbinfo();
	}

	/*
	 * No xcall is needed here. For sun4u systems all CPUs in context
	 * domain share a single physical MMU therefore it's enough to flush
	 * TLB on local CPU. On sun4v systems we use 1 global context
	 * domain and flush all remote TLBs in sfmmu_raise_tsb_exception
	 * handler. Note that vtag_flushall_uctxs() is called
	 * for Ultra II machine, where the equivalent flushall functionality
	 * is implemented in SW, and only user ctx TLB entries are flushed.
	 */
	if (&vtag_flushall_uctxs != NULL) {
		vtag_flushall_uctxs();
	} else {
		vtag_flushall();
	}

	/* reset mmu cnum, skips cnum 0 and 1 */
	if (reset_cnum == B_TRUE)
		mmu_ctxp->mmu_cnum = NUM_LOCKED_CTXS;

done:
	mutex_exit(&mmu_ctxp->mmu_lock);
}


/*
 * For multi-threaded process, set the process context to INVALID_CONTEXT
 * so that it faults and reloads the MMU state from TL=0. For single-threaded
 * process, we can just load the MMU state directly without having to
 * set context invalid. Caller must hold the hat lock since we don't
 * acquire it here.
 */
static void
sfmmu_sync_mmustate(sfmmu_t *sfmmup)
{
	uint_t cnum;
	uint_t pstate_save;

	ASSERT(sfmmup != ksfmmup);
	ASSERT(sfmmu_hat_lock_held(sfmmup));

	kpreempt_disable();

	/*
	 * We check whether the pass'ed-in sfmmup is the same as the
	 * current running proc. This is to makes sure the current proc
	 * stays single-threaded if it already is.
	 */
	if ((sfmmup == curthread->t_procp->p_as->a_hat) &&
	    (curthread->t_procp->p_lwpcnt == 1)) {
		/* single-thread */
		cnum = sfmmup->sfmmu_ctxs[CPU_MMU_IDX(CPU)].cnum;
		if (cnum != INVALID_CONTEXT) {
			uint_t curcnum;
			/*
			 * Disable interrupts to prevent race condition
			 * with sfmmu_ctx_wrap_around ctx invalidation.
			 * In sun4v, ctx invalidation involves setting
			 * TSB to NULL, hence, interrupts should be disabled
			 * untill after sfmmu_load_mmustate is completed.
			 */
			pstate_save = sfmmu_disable_intrs();
			curcnum = sfmmu_getctx_sec();
			if (curcnum == cnum)
				sfmmu_load_mmustate(sfmmup);
			sfmmu_enable_intrs(pstate_save);
			ASSERT(curcnum == cnum || curcnum == INVALID_CONTEXT);
		}
	} else {
		/*
		 * multi-thread
		 * or when sfmmup is not the same as the curproc.
		 */
		sfmmu_invalidate_ctx(sfmmup);
	}

	kpreempt_enable();
}


/*
 * Replace the specified TSB with a new TSB.  This function gets called when
 * we grow, shrink or swapin a TSB.  When swapping in a TSB (TSB_SWAPIN), the
 * TSB_FORCEALLOC flag may be used to force allocation of a minimum-sized TSB
 * (8K).
 *
 * Caller must hold the HAT lock, but should assume any tsb_info
 * pointers it has are no longer valid after calling this function.
 *
 * Return values:
 *	TSB_ALLOCFAIL	Failed to allocate a TSB, due to memory constraints
 *	TSB_LOSTRACE	HAT is busy, i.e. another thread is already doing
 *			something to this tsbinfo/TSB
 *	TSB_SUCCESS	Operation succeeded
 */
static tsb_replace_rc_t
sfmmu_replace_tsb(sfmmu_t *sfmmup, struct tsb_info *old_tsbinfo, uint_t szc,
    hatlock_t *hatlockp, uint_t flags)
{
	struct tsb_info *new_tsbinfo = NULL;
	struct tsb_info *curtsb, *prevtsb;
	uint_t tte_sz_mask;
	int i;

	ASSERT(sfmmup != ksfmmup);
	ASSERT(sfmmup->sfmmu_ismhat == 0);
	ASSERT(sfmmu_hat_lock_held(sfmmup));
	ASSERT(szc <= tsb_max_growsize);

	if (SFMMU_FLAGS_ISSET(sfmmup, HAT_BUSY))
		return (TSB_LOSTRACE);

	/*
	 * Find the tsb_info ahead of this one in the list, and
	 * also make sure that the tsb_info passed in really
	 * exists!
	 */
	for (prevtsb = NULL, curtsb = sfmmup->sfmmu_tsb;
	    curtsb != old_tsbinfo && curtsb != NULL;
	    prevtsb = curtsb, curtsb = curtsb->tsb_next)
		;
	ASSERT(curtsb != NULL);

	if (!(flags & TSB_SWAPIN) && SFMMU_FLAGS_ISSET(sfmmup, HAT_SWAPPED)) {
		/*
		 * The process is swapped out, so just set the new size
		 * code.  When it swaps back in, we'll allocate a new one
		 * of the new chosen size.
		 */
		curtsb->tsb_szc = szc;
		return (TSB_SUCCESS);
	}
	SFMMU_FLAGS_SET(sfmmup, HAT_BUSY);

	tte_sz_mask = old_tsbinfo->tsb_ttesz_mask;

	/*
	 * All initialization is done inside of sfmmu_tsbinfo_alloc().
	 * If we fail to allocate a TSB, exit.
	 *
	 * If tsb grows with new tsb size > 4M and old tsb size < 4M,
	 * then try 4M slab after the initial alloc fails.
	 *
	 * If tsb swapin with tsb size > 4M, then try 4M after the
	 * initial alloc fails.
	 */
	sfmmu_hat_exit(hatlockp);
	if (sfmmu_tsbinfo_alloc(&new_tsbinfo, szc,
	    tte_sz_mask, flags, sfmmup) &&
	    (!(flags & (TSB_GROW | TSB_SWAPIN)) || (szc <= TSB_4M_SZCODE) ||
	    (!(flags & TSB_SWAPIN) &&
	    (old_tsbinfo->tsb_szc >= TSB_4M_SZCODE)) ||
	    sfmmu_tsbinfo_alloc(&new_tsbinfo, TSB_4M_SZCODE,
	    tte_sz_mask, flags, sfmmup))) {
		(void) sfmmu_hat_enter(sfmmup);
		if (!(flags & TSB_SWAPIN))
			SFMMU_STAT(sf_tsb_resize_failures);
		SFMMU_FLAGS_CLEAR(sfmmup, HAT_BUSY);
		return (TSB_ALLOCFAIL);
	}
	(void) sfmmu_hat_enter(sfmmup);

	/*
	 * Re-check to make sure somebody else didn't muck with us while we
	 * didn't hold the HAT lock.  If the process swapped out, fine, just
	 * exit; this can happen if we try to shrink the TSB from the context
	 * of another process (such as on an ISM unmap), though it is rare.
	 */
	if (!(flags & TSB_SWAPIN) && SFMMU_FLAGS_ISSET(sfmmup, HAT_SWAPPED)) {
		SFMMU_STAT(sf_tsb_resize_failures);
		SFMMU_FLAGS_CLEAR(sfmmup, HAT_BUSY);
		sfmmu_hat_exit(hatlockp);
		sfmmu_tsbinfo_free(new_tsbinfo);
		(void) sfmmu_hat_enter(sfmmup);
		return (TSB_LOSTRACE);
	}

#ifdef	DEBUG
	/* Reverify that the tsb_info still exists.. for debugging only */
	for (prevtsb = NULL, curtsb = sfmmup->sfmmu_tsb;
	    curtsb != old_tsbinfo && curtsb != NULL;
	    prevtsb = curtsb, curtsb = curtsb->tsb_next)
		;
	ASSERT(curtsb != NULL);
#endif	/* DEBUG */

	/*
	 * Quiesce any CPUs running this process on their next TLB miss
	 * so they atomically see the new tsb_info.  We temporarily set the
	 * context to invalid context so new threads that come on processor
	 * after we do the xcall to cpusran will also serialize behind the
	 * HAT lock on TLB miss and will see the new TSB.  Since this short
	 * race with a new thread coming on processor is relatively rare,
	 * this synchronization mechanism should be cheaper than always
	 * pausing all CPUs for the duration of the setup, which is what
	 * the old implementation did.  This is particuarly true if we are
	 * copying a huge chunk of memory around during that window.
	 *
	 * The memory barriers are to make sure things stay consistent
	 * with resume() since it does not hold the HAT lock while
	 * walking the list of tsb_info structures.
	 */
	if ((flags & TSB_SWAPIN) != TSB_SWAPIN) {
		/* The TSB is either growing or shrinking. */
		sfmmu_invalidate_ctx(sfmmup);
	} else {
		/*
		 * It is illegal to swap in TSBs from a process other
		 * than a process being swapped in.  This in turn
		 * implies we do not have a valid MMU context here
		 * since a process needs one to resolve translation
		 * misses.
		 */
		ASSERT(curthread->t_procp->p_as->a_hat == sfmmup);
	}

#ifdef DEBUG
	ASSERT(max_mmu_ctxdoms > 0);

	/*
	 * Process should have INVALID_CONTEXT on all MMUs
	 */
	for (i = 0; i < max_mmu_ctxdoms; i++) {

		ASSERT(sfmmup->sfmmu_ctxs[i].cnum == INVALID_CONTEXT);
	}
#endif

	new_tsbinfo->tsb_next = old_tsbinfo->tsb_next;
	membar_stst();	/* strict ordering required */
	if (prevtsb)
		prevtsb->tsb_next = new_tsbinfo;
	else
		sfmmup->sfmmu_tsb = new_tsbinfo;
	membar_enter();	/* make sure new TSB globally visible */

	/*
	 * We need to migrate TSB entries from the old TSB to the new TSB
	 * if tsb_remap_ttes is set and the TSB is growing.
	 */
	if (tsb_remap_ttes && ((flags & TSB_GROW) == TSB_GROW))
		sfmmu_copy_tsb(old_tsbinfo, new_tsbinfo);

	SFMMU_FLAGS_CLEAR(sfmmup, HAT_BUSY);

	/*
	 * Drop the HAT lock to free our old tsb_info.
	 */
	sfmmu_hat_exit(hatlockp);

	if ((flags & TSB_GROW) == TSB_GROW) {
		SFMMU_STAT(sf_tsb_grow);
	} else if ((flags & TSB_SHRINK) == TSB_SHRINK) {
		SFMMU_STAT(sf_tsb_shrink);
	}

	sfmmu_tsbinfo_free(old_tsbinfo);

	(void) sfmmu_hat_enter(sfmmup);
	return (TSB_SUCCESS);
}

/*
 * This function will re-program hat pgsz array, and invalidate the
 * process' context, forcing the process to switch to another
 * context on the next TLB miss, and therefore start using the
 * TLB that is reprogrammed for the new page sizes.
 */
void
sfmmu_reprog_pgsz_arr(sfmmu_t *sfmmup, uint8_t *tmp_pgsz)
{
	int i;
	hatlock_t *hatlockp = NULL;

	hatlockp = sfmmu_hat_enter(sfmmup);
	/* USIII+-IV+ optimization, requires hat lock */
	if (tmp_pgsz) {
		for (i = 0; i < mmu_page_sizes; i++)
			sfmmup->sfmmu_pgsz[i] = tmp_pgsz[i];
	}
	SFMMU_STAT(sf_tlb_reprog_pgsz);

	sfmmu_invalidate_ctx(sfmmup);

	sfmmu_hat_exit(hatlockp);
}

/*
 * The scd_rttecnt field in the SCD must be updated to take account of the
 * regions which it contains.
 */
static void
sfmmu_set_scd_rttecnt(sf_srd_t *srdp, sf_scd_t *scdp)
{
	uint_t rid;
	uint_t i, j;
	ulong_t w;
	sf_region_t *rgnp;

	ASSERT(srdp != NULL);

	for (i = 0; i < SFMMU_HMERGNMAP_WORDS; i++) {
		if ((w = scdp->scd_region_map.bitmap[i]) == 0) {
			continue;
		}

		j = 0;
		while (w) {
			if (!(w & 0x1)) {
				j++;
				w >>= 1;
				continue;
			}
			rid = (i << BT_ULSHIFT) | j;
			j++;
			w >>= 1;

			ASSERT(SFMMU_IS_SHMERID_VALID(rid));
			ASSERT(rid < SFMMU_MAX_HME_REGIONS);
			rgnp = srdp->srd_hmergnp[rid];
			ASSERT(rgnp->rgn_refcnt > 0);
			ASSERT(rgnp->rgn_id == rid);

			scdp->scd_rttecnt[rgnp->rgn_pgszc] +=
			    rgnp->rgn_size >> TTE_PAGE_SHIFT(rgnp->rgn_pgszc);

			/*
			 * Maintain the tsb0 inflation cnt for the regions
			 * in the SCD.
			 */
			if (rgnp->rgn_pgszc >= TTE4M) {
				scdp->scd_sfmmup->sfmmu_tsb0_4minflcnt +=
				    rgnp->rgn_size >>
				    (TTE_PAGE_SHIFT(TTE8K) + 2);
			}
		}
	}
}

/*
 * This function assumes that there are either four or six supported page
 * sizes and at most two programmable TLBs, so we need to decide which
 * page sizes are most important and then tell the MMU layer so it
 * can adjust the TLB page sizes accordingly (if supported).
 *
 * If these assumptions change, this function will need to be
 * updated to support whatever the new limits are.
 *
 * The growing flag is nonzero if we are growing the address space,
 * and zero if it is shrinking.  This allows us to decide whether
 * to grow or shrink our TSB, depending upon available memory
 * conditions.
 */
static void
sfmmu_check_page_sizes(sfmmu_t *sfmmup, int growing)
{
	uint64_t ttecnt[MMU_PAGE_SIZES];
	uint64_t tte8k_cnt, tte4m_cnt;
	uint8_t i;
	int sectsb_thresh;

	/*
	 * Kernel threads, processes with small address spaces not using
	 * large pages, and dummy ISM HATs need not apply.
	 */
	if (sfmmup == ksfmmup || sfmmup->sfmmu_ismhat != NULL)
		return;

	if (!SFMMU_LGPGS_INUSE(sfmmup) &&
	    sfmmup->sfmmu_ttecnt[TTE8K] <= tsb_rss_factor)
		return;

	for (i = 0; i < mmu_page_sizes; i++) {
		ttecnt[i] = sfmmup->sfmmu_ttecnt[i] +
		    sfmmup->sfmmu_ismttecnt[i];
	}

	/* Check pagesizes in use, and possibly reprogram DTLB. */
	if (&mmu_check_page_sizes)
		mmu_check_page_sizes(sfmmup, ttecnt);

	/*
	 * Calculate the number of 8k ttes to represent the span of these
	 * pages.
	 */
	tte8k_cnt = ttecnt[TTE8K] +
	    (ttecnt[TTE64K] << (MMU_PAGESHIFT64K - MMU_PAGESHIFT)) +
	    (ttecnt[TTE512K] << (MMU_PAGESHIFT512K - MMU_PAGESHIFT));
	if (mmu_page_sizes == max_mmu_page_sizes) {
		tte4m_cnt = ttecnt[TTE4M] +
		    (ttecnt[TTE32M] << (MMU_PAGESHIFT32M - MMU_PAGESHIFT4M)) +
		    (ttecnt[TTE256M] << (MMU_PAGESHIFT256M - MMU_PAGESHIFT4M));
	} else {
		tte4m_cnt = ttecnt[TTE4M];
	}

	/*
	 * Inflate tte8k_cnt to allow for region large page allocation failure.
	 */
	tte8k_cnt += sfmmup->sfmmu_tsb0_4minflcnt;

	/*
	 * Inflate TSB sizes by a factor of 2 if this process
	 * uses 4M text pages to minimize extra conflict misses
	 * in the first TSB since without counting text pages
	 * 8K TSB may become too small.
	 *
	 * Also double the size of the second TSB to minimize
	 * extra conflict misses due to competition between 4M text pages
	 * and data pages.
	 *
	 * We need to adjust the second TSB allocation threshold by the
	 * inflation factor, since there is no point in creating a second
	 * TSB when we know all the mappings can fit in the I/D TLBs.
	 */
	sectsb_thresh = tsb_sectsb_threshold;
	if (sfmmup->sfmmu_flags & HAT_4MTEXT_FLAG) {
		tte8k_cnt <<= 1;
		tte4m_cnt <<= 1;
		sectsb_thresh <<= 1;
	}

	/*
	 * Check to see if our TSB is the right size; we may need to
	 * grow or shrink it.  If the process is small, our work is
	 * finished at this point.
	 */
	if (tte8k_cnt <= tsb_rss_factor && tte4m_cnt <= sectsb_thresh) {
		return;
	}
	sfmmu_size_tsb(sfmmup, growing, tte8k_cnt, tte4m_cnt, sectsb_thresh);
}

static void
sfmmu_size_tsb(sfmmu_t *sfmmup, int growing, uint64_t tte8k_cnt,
	uint64_t tte4m_cnt, int sectsb_thresh)
{
	int tsb_bits;
	uint_t tsb_szc;
	struct tsb_info *tsbinfop;
	hatlock_t *hatlockp = NULL;

	hatlockp = sfmmu_hat_enter(sfmmup);
	ASSERT(hatlockp != NULL);
	tsbinfop = sfmmup->sfmmu_tsb;
	ASSERT(tsbinfop != NULL);

	/*
	 * If we're growing, select the size based on RSS.  If we're
	 * shrinking, leave some room so we don't have to turn around and
	 * grow again immediately.
	 */
	if (growing)
		tsb_szc = SELECT_TSB_SIZECODE(tte8k_cnt);
	else
		tsb_szc = SELECT_TSB_SIZECODE(tte8k_cnt << 1);

	if (!growing && (tsb_szc < tsbinfop->tsb_szc) &&
	    (tsb_szc >= default_tsb_size) && TSB_OK_SHRINK()) {
		(void) sfmmu_replace_tsb(sfmmup, tsbinfop, tsb_szc,
		    hatlockp, TSB_SHRINK);
	} else if (growing && tsb_szc > tsbinfop->tsb_szc && TSB_OK_GROW()) {
		(void) sfmmu_replace_tsb(sfmmup, tsbinfop, tsb_szc,
		    hatlockp, TSB_GROW);
	}
	tsbinfop = sfmmup->sfmmu_tsb;

	/*
	 * With the TLB and first TSB out of the way, we need to see if
	 * we need a second TSB for 4M pages.  If we managed to reprogram
	 * the TLB page sizes above, the process will start using this new
	 * TSB right away; otherwise, it will start using it on the next
	 * context switch.  Either way, it's no big deal so there's no
	 * synchronization with the trap handlers here unless we grow the
	 * TSB (in which case it's required to prevent using the old one
	 * after it's freed). Note: second tsb is required for 32M/256M
	 * page sizes.
	 */
	if (tte4m_cnt > sectsb_thresh) {
		/*
		 * If we're growing, select the size based on RSS.  If we're
		 * shrinking, leave some room so we don't have to turn
		 * around and grow again immediately.
		 */
		if (growing)
			tsb_szc = SELECT_TSB_SIZECODE(tte4m_cnt);
		else
			tsb_szc = SELECT_TSB_SIZECODE(tte4m_cnt << 1);
		if (tsbinfop->tsb_next == NULL) {
			struct tsb_info *newtsb;
			int allocflags = SFMMU_FLAGS_ISSET(sfmmup, HAT_SWAPPED)?
			    0 : TSB_ALLOC;

			sfmmu_hat_exit(hatlockp);

			/*
			 * Try to allocate a TSB for 4[32|256]M pages.  If we
			 * can't get the size we want, retry w/a minimum sized
			 * TSB.  If that still didn't work, give up; we can
			 * still run without one.
			 */
			tsb_bits = (mmu_page_sizes == max_mmu_page_sizes)?
			    TSB4M|TSB32M|TSB256M:TSB4M;
			if ((sfmmu_tsbinfo_alloc(&newtsb, tsb_szc, tsb_bits,
			    allocflags, sfmmup)) &&
			    (tsb_szc <= TSB_4M_SZCODE ||
			    sfmmu_tsbinfo_alloc(&newtsb, TSB_4M_SZCODE,
			    tsb_bits, allocflags, sfmmup)) &&
			    sfmmu_tsbinfo_alloc(&newtsb, TSB_MIN_SZCODE,
			    tsb_bits, allocflags, sfmmup)) {
				return;
			}

			hatlockp = sfmmu_hat_enter(sfmmup);

			sfmmu_invalidate_ctx(sfmmup);

			if (sfmmup->sfmmu_tsb->tsb_next == NULL) {
				sfmmup->sfmmu_tsb->tsb_next = newtsb;
				SFMMU_STAT(sf_tsb_sectsb_create);
				sfmmu_hat_exit(hatlockp);
				return;
			} else {
				/*
				 * It's annoying, but possible for us
				 * to get here.. we dropped the HAT lock
				 * because of locking order in the kmem
				 * allocator, and while we were off getting
				 * our memory, some other thread decided to
				 * do us a favor and won the race to get a
				 * second TSB for this process.  Sigh.
				 */
				sfmmu_hat_exit(hatlockp);
				sfmmu_tsbinfo_free(newtsb);
				return;
			}
		}

		/*
		 * We have a second TSB, see if it's big enough.
		 */
		tsbinfop = tsbinfop->tsb_next;

		/*
		 * Check to see if our second TSB is the right size;
		 * we may need to grow or shrink it.
		 * To prevent thrashing (e.g. growing the TSB on a
		 * subsequent map operation), only try to shrink if
		 * the TSB reach exceeds twice the virtual address
		 * space size.
		 */
		if (!growing && (tsb_szc < tsbinfop->tsb_szc) &&
		    (tsb_szc >= default_tsb_size) && TSB_OK_SHRINK()) {
			(void) sfmmu_replace_tsb(sfmmup, tsbinfop,
			    tsb_szc, hatlockp, TSB_SHRINK);
		} else if (growing && tsb_szc > tsbinfop->tsb_szc &&
		    TSB_OK_GROW()) {
			(void) sfmmu_replace_tsb(sfmmup, tsbinfop,
			    tsb_szc, hatlockp, TSB_GROW);
		}
	}

	sfmmu_hat_exit(hatlockp);
}

/*
 * Free up a sfmmu
 * Since the sfmmu is currently embedded in the hat struct we simply zero
 * out our fields and free up the ism map blk list if any.
 */
static void
sfmmu_free_sfmmu(sfmmu_t *sfmmup)
{
	ism_blk_t	*blkp, *nx_blkp;
#ifdef	DEBUG
	ism_map_t	*map;
	int 		i;
#endif

	ASSERT(sfmmup->sfmmu_ttecnt[TTE8K] == 0);
	ASSERT(sfmmup->sfmmu_ttecnt[TTE64K] == 0);
	ASSERT(sfmmup->sfmmu_ttecnt[TTE512K] == 0);
	ASSERT(sfmmup->sfmmu_ttecnt[TTE4M] == 0);
	ASSERT(sfmmup->sfmmu_ttecnt[TTE32M] == 0);
	ASSERT(sfmmup->sfmmu_ttecnt[TTE256M] == 0);
	ASSERT(SF_RGNMAP_ISNULL(sfmmup));

	sfmmup->sfmmu_free = 0;
	sfmmup->sfmmu_ismhat = 0;

	blkp = sfmmup->sfmmu_iblk;
	sfmmup->sfmmu_iblk = NULL;

	while (blkp) {
#ifdef	DEBUG
		map = blkp->iblk_maps;
		for (i = 0; i < ISM_MAP_SLOTS; i++) {
			ASSERT(map[i].imap_seg == 0);
			ASSERT(map[i].imap_ismhat == NULL);
			ASSERT(map[i].imap_ment == NULL);
		}
#endif
		nx_blkp = blkp->iblk_next;
		blkp->iblk_next = NULL;
		blkp->iblk_nextpa = (uint64_t)-1;
		kmem_cache_free(ism_blk_cache, blkp);
		blkp = nx_blkp;
	}
}

/*
 * Locking primitves accessed by HATLOCK macros
 */

#define	SFMMU_SPL_MTX	(0x0)
#define	SFMMU_ML_MTX	(0x1)

#define	SFMMU_MLSPL_MTX(type, pg)	(((type) == SFMMU_SPL_MTX) ? \
					    SPL_HASH(pg) : MLIST_HASH(pg))

kmutex_t *
sfmmu_page_enter(struct page *pp)
{
	return (sfmmu_mlspl_enter(pp, SFMMU_SPL_MTX));
}

void
sfmmu_page_exit(kmutex_t *spl)
{
	mutex_exit(spl);
}

int
sfmmu_page_spl_held(struct page *pp)
{
	return (sfmmu_mlspl_held(pp, SFMMU_SPL_MTX));
}

kmutex_t *
sfmmu_mlist_enter(struct page *pp)
{
	return (sfmmu_mlspl_enter(pp, SFMMU_ML_MTX));
}

void
sfmmu_mlist_exit(kmutex_t *mml)
{
	mutex_exit(mml);
}

int
sfmmu_mlist_held(struct page *pp)
{

	return (sfmmu_mlspl_held(pp, SFMMU_ML_MTX));
}

/*
 * Common code for sfmmu_mlist_enter() and sfmmu_page_enter().  For
 * sfmmu_mlist_enter() case mml_table lock array is used and for
 * sfmmu_page_enter() sfmmu_page_lock lock array is used.
 *
 * The lock is taken on a root page so that it protects an operation on all
 * constituent pages of a large page pp belongs to.
 *
 * The routine takes a lock from the appropriate array. The lock is determined
 * by hashing the root page. After taking the lock this routine checks if the
 * root page has the same size code that was used to determine the root (i.e
 * that root hasn't changed).  If root page has the expected p_szc field we
 * have the right lock and it's returned to the caller. If root's p_szc
 * decreased we release the lock and retry from the beginning.  This case can
 * happen due to hat_page_demote() decreasing p_szc between our load of p_szc
 * value and taking the lock. The number of retries due to p_szc decrease is
 * limited by the maximum p_szc value. If p_szc is 0 we return the lock
 * determined by hashing pp itself.
 *
 * If our caller doesn't hold a SE_SHARED or SE_EXCL lock on pp it's also
 * possible that p_szc can increase. To increase p_szc a thread has to lock
 * all constituent pages EXCL and do hat_pageunload() on all of them. All the
 * callers that don't hold a page locked recheck if hmeblk through which pp
 * was found still maps this pp.  If it doesn't map it anymore returned lock
 * is immediately dropped. Therefore if sfmmu_mlspl_enter() hits the case of
 * p_szc increase after taking the lock it returns this lock without further
 * retries because in this case the caller doesn't care about which lock was
 * taken. The caller will drop it right away.
 *
 * After the routine returns it's guaranteed that hat_page_demote() can't
 * change p_szc field of any of constituent pages of a large page pp belongs
 * to as long as pp was either locked at least SHARED prior to this call or
 * the caller finds that hment that pointed to this pp still references this
 * pp (this also assumes that the caller holds hme hash bucket lock so that
 * the same pp can't be remapped into the same hmeblk after it was unmapped by
 * hat_pageunload()).
 */
static kmutex_t *
sfmmu_mlspl_enter(struct page *pp, int type)
{
	kmutex_t	*mtx;
	uint_t		prev_rszc = UINT_MAX;
	page_t		*rootpp;
	uint_t		szc;
	uint_t		rszc;
	uint_t		pszc = pp->p_szc;

	ASSERT(pp != NULL);

again:
	if (pszc == 0) {
		mtx = SFMMU_MLSPL_MTX(type, pp);
		mutex_enter(mtx);
		return (mtx);
	}

	/* The lock lives in the root page */
	rootpp = PP_GROUPLEADER(pp, pszc);
	mtx = SFMMU_MLSPL_MTX(type, rootpp);
	mutex_enter(mtx);

	/*
	 * Return mml in the following 3 cases:
	 *
	 * 1) If pp itself is root since if its p_szc decreased before we took
	 * the lock pp is still the root of smaller szc page. And if its p_szc
	 * increased it doesn't matter what lock we return (see comment in
	 * front of this routine).
	 *
	 * 2) If pp's not root but rootpp is the root of a rootpp->p_szc size
	 * large page we have the right lock since any previous potential
	 * hat_page_demote() is done demoting from greater than current root's
	 * p_szc because hat_page_demote() changes root's p_szc last. No
	 * further hat_page_demote() can start or be in progress since it
	 * would need the same lock we currently hold.
	 *
	 * 3) If rootpp's p_szc increased since previous iteration it doesn't
	 * matter what lock we return (see comment in front of this routine).
	 */
	if (pp == rootpp || (rszc = rootpp->p_szc) == pszc ||
	    rszc >= prev_rszc) {
		return (mtx);
	}

	/*
	 * hat_page_demote() could have decreased root's p_szc.
	 * In this case pp's p_szc must also be smaller than pszc.
	 * Retry.
	 */
	if (rszc < pszc) {
		szc = pp->p_szc;
		if (szc < pszc) {
			mutex_exit(mtx);
			pszc = szc;
			goto again;
		}
		/*
		 * pp's p_szc increased after it was decreased.
		 * page cannot be mapped. Return current lock. The caller
		 * will drop it right away.
		 */
		return (mtx);
	}

	/*
	 * root's p_szc is greater than pp's p_szc.
	 * hat_page_demote() is not done with all pages
	 * yet. Wait for it to complete.
	 */
	mutex_exit(mtx);
	rootpp = PP_GROUPLEADER(rootpp, rszc);
	mtx = SFMMU_MLSPL_MTX(type, rootpp);
	mutex_enter(mtx);
	mutex_exit(mtx);
	prev_rszc = rszc;
	goto again;
}

static int
sfmmu_mlspl_held(struct page *pp, int type)
{
	kmutex_t	*mtx;

	ASSERT(pp != NULL);
	/* The lock lives in the root page */
	pp = PP_PAGEROOT(pp);
	ASSERT(pp != NULL);

	mtx = SFMMU_MLSPL_MTX(type, pp);
	return (MUTEX_HELD(mtx));
}

static uint_t
sfmmu_get_free_hblk(struct hme_blk **hmeblkpp, uint_t critical)
{
	struct  hme_blk *hblkp;


	if (freehblkp != NULL) {
		mutex_enter(&freehblkp_lock);
		if (freehblkp != NULL) {
			/*
			 * If the current thread is owning hblk_reserve OR
			 * critical request from sfmmu_hblk_steal()
			 * let it succeed even if freehblkcnt is really low.
			 */
			if (freehblkcnt <= HBLK_RESERVE_MIN && !critical) {
				SFMMU_STAT(sf_get_free_throttle);
				mutex_exit(&freehblkp_lock);
				return (0);
			}
			freehblkcnt--;
			*hmeblkpp = freehblkp;
			hblkp = *hmeblkpp;
			freehblkp = hblkp->hblk_next;
			mutex_exit(&freehblkp_lock);
			hblkp->hblk_next = NULL;
			SFMMU_STAT(sf_get_free_success);

			ASSERT(hblkp->hblk_hmecnt == 0);
			ASSERT(hblkp->hblk_vcnt == 0);
			ASSERT(hblkp->hblk_nextpa == va_to_pa((caddr_t)hblkp));

			return (1);
		}
		mutex_exit(&freehblkp_lock);
	}

	/* Check cpu hblk pending queues */
	if ((*hmeblkpp = sfmmu_check_pending_hblks(TTE8K)) != NULL) {
		hblkp = *hmeblkpp;
		hblkp->hblk_next = NULL;
		hblkp->hblk_nextpa = va_to_pa((caddr_t)hblkp);

		ASSERT(hblkp->hblk_hmecnt == 0);
		ASSERT(hblkp->hblk_vcnt == 0);

		return (1);
	}

	SFMMU_STAT(sf_get_free_fail);
	return (0);
}

static uint_t
sfmmu_put_free_hblk(struct hme_blk *hmeblkp, uint_t critical)
{
	struct  hme_blk *hblkp;

	ASSERT(hmeblkp->hblk_hmecnt == 0);
	ASSERT(hmeblkp->hblk_vcnt == 0);
	ASSERT(hmeblkp->hblk_nextpa == va_to_pa((caddr_t)hmeblkp));

	/*
	 * If the current thread is mapping into kernel space,
	 * let it succede even if freehblkcnt is max
	 * so that it will avoid freeing it to kmem.
	 * This will prevent stack overflow due to
	 * possible recursion since kmem_cache_free()
	 * might require creation of a slab which
	 * in turn needs an hmeblk to map that slab;
	 * let's break this vicious chain at the first
	 * opportunity.
	 */
	if (freehblkcnt < HBLK_RESERVE_CNT || critical) {
		mutex_enter(&freehblkp_lock);
		if (freehblkcnt < HBLK_RESERVE_CNT || critical) {
			SFMMU_STAT(sf_put_free_success);
			freehblkcnt++;
			hmeblkp->hblk_next = freehblkp;
			freehblkp = hmeblkp;
			mutex_exit(&freehblkp_lock);
			return (1);
		}
		mutex_exit(&freehblkp_lock);
	}

	/*
	 * Bring down freehblkcnt to HBLK_RESERVE_CNT. We are here
	 * only if freehblkcnt is at least HBLK_RESERVE_CNT *and*
	 * we are not in the process of mapping into kernel space.
	 */
	ASSERT(!critical);
	while (freehblkcnt > HBLK_RESERVE_CNT) {
		mutex_enter(&freehblkp_lock);
		if (freehblkcnt > HBLK_RESERVE_CNT) {
			freehblkcnt--;
			hblkp = freehblkp;
			freehblkp = hblkp->hblk_next;
			mutex_exit(&freehblkp_lock);
			ASSERT(get_hblk_cache(hblkp) == sfmmu8_cache);
			kmem_cache_free(sfmmu8_cache, hblkp);
			continue;
		}
		mutex_exit(&freehblkp_lock);
	}
	SFMMU_STAT(sf_put_free_fail);
	return (0);
}

static void
sfmmu_hblk_swap(struct hme_blk *new)
{
	struct hme_blk *old, *hblkp, *prev;
	uint64_t newpa;
	caddr_t	base, vaddr, endaddr;
	struct hmehash_bucket *hmebp;
	struct sf_hment *osfhme, *nsfhme;
	page_t *pp;
	kmutex_t *pml;
	tte_t tte;
	struct hme_blk *list = NULL;

#ifdef	DEBUG
	hmeblk_tag		hblktag;
	struct hme_blk		*found;
#endif
	old = HBLK_RESERVE;
	ASSERT(!old->hblk_shared);

	/*
	 * save pa before bcopy clobbers it
	 */
	newpa = new->hblk_nextpa;

	base = (caddr_t)get_hblk_base(old);
	endaddr = base + get_hblk_span(old);

	/*
	 * acquire hash bucket lock.
	 */
	hmebp = sfmmu_tteload_acquire_hashbucket(ksfmmup, base, TTE8K,
	    SFMMU_INVALID_SHMERID);

	/*
	 * copy contents from old to new
	 */
	bcopy((void *)old, (void *)new, HME8BLK_SZ);

	/*
	 * add new to hash chain
	 */
	sfmmu_hblk_hash_add(hmebp, new, newpa);

	/*
	 * search hash chain for hblk_reserve; this needs to be performed
	 * after adding new, otherwise prev won't correspond to the hblk which
	 * is prior to old in hash chain when we call sfmmu_hblk_hash_rm to
	 * remove old later.
	 */
	for (prev = NULL,
	    hblkp = hmebp->hmeblkp; hblkp != NULL && hblkp != old;
	    prev = hblkp, hblkp = hblkp->hblk_next)
		;

	if (hblkp != old)
		panic("sfmmu_hblk_swap: hblk_reserve not found");

	/*
	 * p_mapping list is still pointing to hments in hblk_reserve;
	 * fix up p_mapping list so that they point to hments in new.
	 *
	 * Since all these mappings are created by hblk_reserve_thread
	 * on the way and it's using at least one of the buffers from each of
	 * the newly minted slabs, there is no danger of any of these
	 * mappings getting unloaded by another thread.
	 *
	 * tsbmiss could only modify ref/mod bits of hments in old/new.
	 * Since all of these hments hold mappings established by segkmem
	 * and mappings in segkmem are setup with HAT_NOSYNC, ref/mod bits
	 * have no meaning for the mappings in hblk_reserve.  hments in
	 * old and new are identical except for ref/mod bits.
	 */
	for (vaddr = base; vaddr < endaddr; vaddr += TTEBYTES(TTE8K)) {

		HBLKTOHME(osfhme, old, vaddr);
		sfmmu_copytte(&osfhme->hme_tte, &tte);

		if (TTE_IS_VALID(&tte)) {
			if ((pp = osfhme->hme_page) == NULL)
				panic("sfmmu_hblk_swap: page not mapped");

			pml = sfmmu_mlist_enter(pp);

			if (pp != osfhme->hme_page)
				panic("sfmmu_hblk_swap: mapping changed");

			HBLKTOHME(nsfhme, new, vaddr);

			HME_ADD(nsfhme, pp);
			HME_SUB(osfhme, pp);

			sfmmu_mlist_exit(pml);
		}
	}

	/*
	 * remove old from hash chain
	 */
	sfmmu_hblk_hash_rm(hmebp, old, prev, &list, 1);

#ifdef	DEBUG

	hblktag.htag_id = ksfmmup;
	hblktag.htag_rid = SFMMU_INVALID_SHMERID;
	hblktag.htag_bspage = HME_HASH_BSPAGE(base, HME_HASH_SHIFT(TTE8K));
	hblktag.htag_rehash = HME_HASH_REHASH(TTE8K);
	HME_HASH_FAST_SEARCH(hmebp, hblktag, found);

	if (found != new)
		panic("sfmmu_hblk_swap: new hblk not found");
#endif

	SFMMU_HASH_UNLOCK(hmebp);

	/*
	 * Reset hblk_reserve
	 */
	bzero((void *)old, HME8BLK_SZ);
	old->hblk_nextpa = va_to_pa((caddr_t)old);
}

/*
 * Grab the mlist mutex for both pages passed in.
 *
 * low and high will be returned as pointers to the mutexes for these pages.
 * low refers to the mutex residing in the lower bin of the mlist hash, while
 * high refers to the mutex residing in the higher bin of the mlist hash.  This
 * is due to the locking order restrictions on the same thread grabbing
 * multiple mlist mutexes.  The low lock must be acquired before the high lock.
 *
 * If both pages hash to the same mutex, only grab that single mutex, and
 * high will be returned as NULL
 * If the pages hash to different bins in the hash, grab the lower addressed
 * lock first and then the higher addressed lock in order to follow the locking
 * rules involved with the same thread grabbing multiple mlist mutexes.
 * low and high will both have non-NULL values.
 */
static void
sfmmu_mlist_reloc_enter(struct page *targ, struct page *repl,
    kmutex_t **low, kmutex_t **high)
{
	kmutex_t	*mml_targ, *mml_repl;

	/*
	 * no need to do the dance around szc as in sfmmu_mlist_enter()
	 * because this routine is only called by hat_page_relocate() and all
	 * targ and repl pages are already locked EXCL so szc can't change.
	 */

	mml_targ = MLIST_HASH(PP_PAGEROOT(targ));
	mml_repl = MLIST_HASH(PP_PAGEROOT(repl));

	if (mml_targ == mml_repl) {
		*low = mml_targ;
		*high = NULL;
	} else {
		if (mml_targ < mml_repl) {
			*low = mml_targ;
			*high = mml_repl;
		} else {
			*low = mml_repl;
			*high = mml_targ;
		}
	}

	mutex_enter(*low);
	if (*high)
		mutex_enter(*high);
}

static void
sfmmu_mlist_reloc_exit(kmutex_t *low, kmutex_t *high)
{
	if (high)
		mutex_exit(high);
	mutex_exit(low);
}

static hatlock_t *
sfmmu_hat_enter(sfmmu_t *sfmmup)
{
	hatlock_t	*hatlockp;

	if (sfmmup != ksfmmup) {
		hatlockp = TSB_HASH(sfmmup);
		mutex_enter(HATLOCK_MUTEXP(hatlockp));
		return (hatlockp);
	}
	return (NULL);
}

static hatlock_t *
sfmmu_hat_tryenter(sfmmu_t *sfmmup)
{
	hatlock_t	*hatlockp;

	if (sfmmup != ksfmmup) {
		hatlockp = TSB_HASH(sfmmup);
		if (mutex_tryenter(HATLOCK_MUTEXP(hatlockp)) == 0)
			return (NULL);
		return (hatlockp);
	}
	return (NULL);
}

static void
sfmmu_hat_exit(hatlock_t *hatlockp)
{
	if (hatlockp != NULL)
		mutex_exit(HATLOCK_MUTEXP(hatlockp));
}

static void
sfmmu_hat_lock_all(void)
{
	int i;
	for (i = 0; i < SFMMU_NUM_LOCK; i++)
		mutex_enter(HATLOCK_MUTEXP(&hat_lock[i]));
}

static void
sfmmu_hat_unlock_all(void)
{
	int i;
	for (i = SFMMU_NUM_LOCK - 1; i >= 0; i--)
		mutex_exit(HATLOCK_MUTEXP(&hat_lock[i]));
}

int
sfmmu_hat_lock_held(sfmmu_t *sfmmup)
{
	ASSERT(sfmmup != ksfmmup);
	return (MUTEX_HELD(HATLOCK_MUTEXP(TSB_HASH(sfmmup))));
}

/*
 * Locking primitives to provide consistency between ISM unmap
 * and other operations.  Since ISM unmap can take a long time, we
 * use HAT_ISMBUSY flag (protected by the hatlock) to avoid creating
 * contention on the hatlock buckets while ISM segments are being
 * unmapped.  The tradeoff is that the flags don't prevent priority
 * inversion from occurring, so we must request kernel priority in
 * case we have to sleep to keep from getting buried while holding
 * the HAT_ISMBUSY flag set, which in turn could block other kernel
 * threads from running (for example, in sfmmu_uvatopfn()).
 */
static void
sfmmu_ismhat_enter(sfmmu_t *sfmmup, int hatlock_held)
{
	hatlock_t *hatlockp;

	THREAD_KPRI_REQUEST();
	if (!hatlock_held)
		hatlockp = sfmmu_hat_enter(sfmmup);
	while (SFMMU_FLAGS_ISSET(sfmmup, HAT_ISMBUSY))
		cv_wait(&sfmmup->sfmmu_tsb_cv, HATLOCK_MUTEXP(hatlockp));
	SFMMU_FLAGS_SET(sfmmup, HAT_ISMBUSY);
	if (!hatlock_held)
		sfmmu_hat_exit(hatlockp);
}

static void
sfmmu_ismhat_exit(sfmmu_t *sfmmup, int hatlock_held)
{
	hatlock_t *hatlockp;

	if (!hatlock_held)
		hatlockp = sfmmu_hat_enter(sfmmup);
	ASSERT(SFMMU_FLAGS_ISSET(sfmmup, HAT_ISMBUSY));
	SFMMU_FLAGS_CLEAR(sfmmup, HAT_ISMBUSY);
	cv_broadcast(&sfmmup->sfmmu_tsb_cv);
	if (!hatlock_held)
		sfmmu_hat_exit(hatlockp);
	THREAD_KPRI_RELEASE();
}

/*
 *
 * Algorithm:
 *
 * (1) if segkmem is not ready, allocate hblk from an array of pre-alloc'ed
 *	hblks.
 *
 * (2) if we are allocating an hblk for mapping a slab in sfmmu_cache,
 *
 * 		(a) try to return an hblk from reserve pool of free hblks;
 *		(b) if the reserve pool is empty, acquire hblk_reserve_lock
 *		    and return hblk_reserve.
 *
 * (3) call kmem_cache_alloc() to allocate hblk;
 *
 *		(a) if hblk_reserve_lock is held by the current thread,
 *		    atomically replace hblk_reserve by the hblk that is
 *		    returned by kmem_cache_alloc; release hblk_reserve_lock
 *		    and call kmem_cache_alloc() again.
 *		(b) if reserve pool is not full, add the hblk that is
 *		    returned by kmem_cache_alloc to reserve pool and
 *		    call kmem_cache_alloc again.
 *
 */
static struct hme_blk *
sfmmu_hblk_alloc(sfmmu_t *sfmmup, caddr_t vaddr,
	struct hmehash_bucket *hmebp, uint_t size, hmeblk_tag hblktag,
	uint_t flags, uint_t rid)
{
	struct hme_blk *hmeblkp = NULL;
	struct hme_blk *newhblkp;
	struct hme_blk *shw_hblkp = NULL;
	struct kmem_cache *sfmmu_cache = NULL;
	uint64_t hblkpa;
	ulong_t index;
	uint_t owner;		/* set to 1 if using hblk_reserve */
	uint_t forcefree;
	int sleep;
	sf_srd_t *srdp;
	sf_region_t *rgnp;

	ASSERT(SFMMU_HASH_LOCK_ISHELD(hmebp));
	ASSERT(hblktag.htag_rid == rid);
	SFMMU_VALIDATE_HMERID(sfmmup, rid, vaddr, TTEBYTES(size));
	ASSERT(!SFMMU_IS_SHMERID_VALID(rid) ||
	    IS_P2ALIGNED(vaddr, TTEBYTES(size)));

	/*
	 * If segkmem is not created yet, allocate from static hmeblks
	 * created at the end of startup_modules().  See the block comment
	 * in startup_modules() describing how we estimate the number of
	 * static hmeblks that will be needed during re-map.
	 */
	if (!hblk_alloc_dynamic) {

		ASSERT(!SFMMU_IS_SHMERID_VALID(rid));

		if (size == TTE8K) {
			index = nucleus_hblk8.index;
			if (index >= nucleus_hblk8.len) {
				/*
				 * If we panic here, see startup_modules() to
				 * make sure that we are calculating the
				 * number of hblk8's that we need correctly.
				 */
				prom_panic("no nucleus hblk8 to allocate");
			}
			hmeblkp =
			    (struct hme_blk *)&nucleus_hblk8.list[index];
			nucleus_hblk8.index++;
			SFMMU_STAT(sf_hblk8_nalloc);
		} else {
			index = nucleus_hblk1.index;
			if (nucleus_hblk1.index >= nucleus_hblk1.len) {
				/*
				 * If we panic here, see startup_modules().
				 * Most likely you need to update the
				 * calculation of the number of hblk1 elements
				 * that the kernel needs to boot.
				 */
				prom_panic("no nucleus hblk1 to allocate");
			}
			hmeblkp =
			    (struct hme_blk *)&nucleus_hblk1.list[index];
			nucleus_hblk1.index++;
			SFMMU_STAT(sf_hblk1_nalloc);
		}

		goto hblk_init;
	}

	SFMMU_HASH_UNLOCK(hmebp);

	if (sfmmup != KHATID && !SFMMU_IS_SHMERID_VALID(rid)) {
		if (mmu_page_sizes == max_mmu_page_sizes) {
			if (size < TTE256M)
				shw_hblkp = sfmmu_shadow_hcreate(sfmmup, vaddr,
				    size, flags);
		} else {
			if (size < TTE4M)
				shw_hblkp = sfmmu_shadow_hcreate(sfmmup, vaddr,
				    size, flags);
		}
	} else if (SFMMU_IS_SHMERID_VALID(rid)) {
		/*
		 * Shared hmes use per region bitmaps in rgn_hmeflag
		 * rather than shadow hmeblks to keep track of the
		 * mapping sizes which have been allocated for the region.
		 * Here we cleanup old invalid hmeblks with this rid,
		 * which may be left around by pageunload().
		 */
		int ttesz;
		caddr_t va;
		caddr_t	eva = vaddr + TTEBYTES(size);

		ASSERT(sfmmup != KHATID);

		srdp = sfmmup->sfmmu_srdp;
		ASSERT(srdp != NULL && srdp->srd_refcnt != 0);
		rgnp = srdp->srd_hmergnp[rid];
		ASSERT(rgnp != NULL && rgnp->rgn_id == rid);
		ASSERT(rgnp->rgn_refcnt != 0);
		ASSERT(size <= rgnp->rgn_pgszc);

		ttesz = HBLK_MIN_TTESZ;
		do {
			if (!(rgnp->rgn_hmeflags & (0x1 << ttesz))) {
				continue;
			}

			if (ttesz > size && ttesz != HBLK_MIN_TTESZ) {
				sfmmu_cleanup_rhblk(srdp, vaddr, rid, ttesz);
			} else if (ttesz < size) {
				for (va = vaddr; va < eva;
				    va += TTEBYTES(ttesz)) {
					sfmmu_cleanup_rhblk(srdp, va, rid,
					    ttesz);
				}
			}
		} while (++ttesz <= rgnp->rgn_pgszc);
	}

fill_hblk:
	owner = (hblk_reserve_thread == curthread) ? 1 : 0;

	if (owner && size == TTE8K) {

		ASSERT(!SFMMU_IS_SHMERID_VALID(rid));
		/*
		 * We are really in a tight spot. We already own
		 * hblk_reserve and we need another hblk.  In anticipation
		 * of this kind of scenario, we specifically set aside
		 * HBLK_RESERVE_MIN number of hblks to be used exclusively
		 * by owner of hblk_reserve.
		 */
		SFMMU_STAT(sf_hblk_recurse_cnt);

		if (!sfmmu_get_free_hblk(&hmeblkp, 1))
			panic("sfmmu_hblk_alloc: reserve list is empty");

		goto hblk_verify;
	}

	ASSERT(!owner);

	if ((flags & HAT_NO_KALLOC) == 0) {

		sfmmu_cache = ((size == TTE8K) ? sfmmu8_cache : sfmmu1_cache);
		sleep = ((sfmmup == KHATID) ? KM_NOSLEEP : KM_SLEEP);

		if ((hmeblkp = kmem_cache_alloc(sfmmu_cache, sleep)) == NULL) {
			hmeblkp = sfmmu_hblk_steal(size);
		} else {
			/*
			 * if we are the owner of hblk_reserve,
			 * swap hblk_reserve with hmeblkp and
			 * start a fresh life.  Hope things go
			 * better this time.
			 */
			if (hblk_reserve_thread == curthread) {
				ASSERT(sfmmu_cache == sfmmu8_cache);
				sfmmu_hblk_swap(hmeblkp);
				hblk_reserve_thread = NULL;
				mutex_exit(&hblk_reserve_lock);
				goto fill_hblk;
			}
			/*
			 * let's donate this hblk to our reserve list if
			 * we are not mapping kernel range
			 */
			if (size == TTE8K && sfmmup != KHATID) {
				if (sfmmu_put_free_hblk(hmeblkp, 0))
					goto fill_hblk;
			}
		}
	} else {
		/*
		 * We are here to map the slab in sfmmu8_cache; let's
		 * check if we could tap our reserve list; if successful,
		 * this will avoid the pain of going thru sfmmu_hblk_swap
		 */
		SFMMU_STAT(sf_hblk_slab_cnt);
		if (!sfmmu_get_free_hblk(&hmeblkp, 0)) {
			/*
			 * let's start hblk_reserve dance
			 */
			SFMMU_STAT(sf_hblk_reserve_cnt);
			owner = 1;
			mutex_enter(&hblk_reserve_lock);
			hmeblkp = HBLK_RESERVE;
			hblk_reserve_thread = curthread;
		}
	}

hblk_verify:
	ASSERT(hmeblkp != NULL);
	set_hblk_sz(hmeblkp, size);
	ASSERT(hmeblkp->hblk_nextpa == va_to_pa((caddr_t)hmeblkp));
	SFMMU_HASH_LOCK(hmebp);
	HME_HASH_FAST_SEARCH(hmebp, hblktag, newhblkp);
	if (newhblkp != NULL) {
		SFMMU_HASH_UNLOCK(hmebp);
		if (hmeblkp != HBLK_RESERVE) {
			/*
			 * This is really tricky!
			 *
			 * vmem_alloc(vmem_seg_arena)
			 *  vmem_alloc(vmem_internal_arena)
			 *   segkmem_alloc(heap_arena)
			 *    vmem_alloc(heap_arena)
			 *    page_create()
			 *    hat_memload()
			 *	kmem_cache_free()
			 *	 kmem_cache_alloc()
			 *	  kmem_slab_create()
			 *	   vmem_alloc(kmem_internal_arena)
			 *	    segkmem_alloc(heap_arena)
			 *		vmem_alloc(heap_arena)
			 *		page_create()
			 *		hat_memload()
			 *		  kmem_cache_free()
			 *		...
			 *
			 * Thus, hat_memload() could call kmem_cache_free
			 * for enough number of times that we could easily
			 * hit the bottom of the stack or run out of reserve
			 * list of vmem_seg structs.  So, we must donate
			 * this hblk to reserve list if it's allocated
			 * from sfmmu8_cache *and* mapping kernel range.
			 * We don't need to worry about freeing hmeblk1's
			 * to kmem since they don't map any kmem slabs.
			 *
			 * Note: When segkmem supports largepages, we must
			 * free hmeblk1's to reserve list as well.
			 */
			forcefree = (sfmmup == KHATID) ? 1 : 0;
			if (size == TTE8K &&
			    sfmmu_put_free_hblk(hmeblkp, forcefree)) {
				goto re_verify;
			}
			ASSERT(sfmmup != KHATID);
			kmem_cache_free(get_hblk_cache(hmeblkp), hmeblkp);
		} else {
			/*
			 * Hey! we don't need hblk_reserve any more.
			 */
			ASSERT(owner);
			hblk_reserve_thread = NULL;
			mutex_exit(&hblk_reserve_lock);
			owner = 0;
		}
re_verify:
		/*
		 * let's check if the goodies are still present
		 */
		SFMMU_HASH_LOCK(hmebp);
		HME_HASH_FAST_SEARCH(hmebp, hblktag, newhblkp);
		if (newhblkp != NULL) {
			/*
			 * return newhblkp if it's not hblk_reserve;
			 * if newhblkp is hblk_reserve, return it
			 * _only if_ we are the owner of hblk_reserve.
			 */
			if (newhblkp != HBLK_RESERVE || owner) {
				ASSERT(!SFMMU_IS_SHMERID_VALID(rid) ||
				    newhblkp->hblk_shared);
				ASSERT(SFMMU_IS_SHMERID_VALID(rid) ||
				    !newhblkp->hblk_shared);
				return (newhblkp);
			} else {
				/*
				 * we just hit hblk_reserve in the hash and
				 * we are not the owner of that;
				 *
				 * block until hblk_reserve_thread completes
				 * swapping hblk_reserve and try the dance
				 * once again.
				 */
				SFMMU_HASH_UNLOCK(hmebp);
				mutex_enter(&hblk_reserve_lock);
				mutex_exit(&hblk_reserve_lock);
				SFMMU_STAT(sf_hblk_reserve_hit);
				goto fill_hblk;
			}
		} else {
			/*
			 * it's no more! try the dance once again.
			 */
			SFMMU_HASH_UNLOCK(hmebp);
			goto fill_hblk;
		}
	}

hblk_init:
	if (SFMMU_IS_SHMERID_VALID(rid)) {
		uint16_t tteflag = 0x1 <<
		    ((size < HBLK_MIN_TTESZ) ? HBLK_MIN_TTESZ : size);

		if (!(rgnp->rgn_hmeflags & tteflag)) {
			atomic_or_16(&rgnp->rgn_hmeflags, tteflag);
		}
		hmeblkp->hblk_shared = 1;
	} else {
		hmeblkp->hblk_shared = 0;
	}
	set_hblk_sz(hmeblkp, size);
	ASSERT(SFMMU_HASH_LOCK_ISHELD(hmebp));
	hmeblkp->hblk_next = (struct hme_blk *)NULL;
	hmeblkp->hblk_tag = hblktag;
	hmeblkp->hblk_shadow = shw_hblkp;
	hblkpa = hmeblkp->hblk_nextpa;
	hmeblkp->hblk_nextpa = HMEBLK_ENDPA;

	ASSERT(get_hblk_ttesz(hmeblkp) == size);
	ASSERT(get_hblk_span(hmeblkp) == HMEBLK_SPAN(size));
	ASSERT(hmeblkp->hblk_hmecnt == 0);
	ASSERT(hmeblkp->hblk_vcnt == 0);
	ASSERT(hmeblkp->hblk_lckcnt == 0);
	ASSERT(hblkpa == va_to_pa((caddr_t)hmeblkp));
	sfmmu_hblk_hash_add(hmebp, hmeblkp, hblkpa);
	return (hmeblkp);
}

/*
 * This function cleans up the hme_blk and returns it to the free list.
 */
/* ARGSUSED */
static void
sfmmu_hblk_free(struct hme_blk **listp)
{
	struct hme_blk *hmeblkp, *next_hmeblkp;
	int		size;
	uint_t		critical;
	uint64_t	hblkpa;

	ASSERT(*listp != NULL);

	hmeblkp = *listp;
	while (hmeblkp != NULL) {
		next_hmeblkp = hmeblkp->hblk_next;
		ASSERT(!hmeblkp->hblk_hmecnt);
		ASSERT(!hmeblkp->hblk_vcnt);
		ASSERT(!hmeblkp->hblk_lckcnt);
		ASSERT(hmeblkp != (struct hme_blk *)hblk_reserve);
		ASSERT(hmeblkp->hblk_shared == 0);
		ASSERT(hmeblkp->hblk_shw_bit == 0);
		ASSERT(hmeblkp->hblk_shadow == NULL);

		hblkpa = va_to_pa((caddr_t)hmeblkp);
		ASSERT(hblkpa != (uint64_t)-1);
		critical = (hblktosfmmu(hmeblkp) == KHATID) ? 1 : 0;

		size = get_hblk_ttesz(hmeblkp);
		hmeblkp->hblk_next = NULL;
		hmeblkp->hblk_nextpa = hblkpa;

		if (hmeblkp->hblk_nuc_bit == 0) {

			if (size != TTE8K ||
			    !sfmmu_put_free_hblk(hmeblkp, critical))
				kmem_cache_free(get_hblk_cache(hmeblkp),
				    hmeblkp);
		}
		hmeblkp = next_hmeblkp;
	}
}

#define	BUCKETS_TO_SEARCH_BEFORE_UNLOAD	30
#define	SFMMU_HBLK_STEAL_THRESHOLD 5

static uint_t sfmmu_hblk_steal_twice;
static uint_t sfmmu_hblk_steal_count, sfmmu_hblk_steal_unload_count;

/*
 * Steal a hmeblk from user or kernel hme hash lists.
 * For 8K tte grab one from reserve pool (freehblkp) before proceeding to
 * steal and if we fail to steal after SFMMU_HBLK_STEAL_THRESHOLD attempts
 * tap into critical reserve of freehblkp.
 * Note: We remain looping in this routine until we find one.
 */
static struct hme_blk *
sfmmu_hblk_steal(int size)
{
	static struct hmehash_bucket *uhmehash_steal_hand = NULL;
	struct hmehash_bucket *hmebp;
	struct hme_blk *hmeblkp = NULL, *pr_hblk;
	uint64_t hblkpa;
	int i;
	uint_t loop_cnt = 0, critical;

	for (;;) {
		/* Check cpu hblk pending queues */
		if ((hmeblkp = sfmmu_check_pending_hblks(size)) != NULL) {
			hmeblkp->hblk_nextpa = va_to_pa((caddr_t)hmeblkp);
			ASSERT(hmeblkp->hblk_hmecnt == 0);
			ASSERT(hmeblkp->hblk_vcnt == 0);
			return (hmeblkp);
		}

		if (size == TTE8K) {
			critical =
			    (++loop_cnt > SFMMU_HBLK_STEAL_THRESHOLD) ? 1 : 0;
			if (sfmmu_get_free_hblk(&hmeblkp, critical))
				return (hmeblkp);
		}

		hmebp = (uhmehash_steal_hand == NULL) ? uhme_hash :
		    uhmehash_steal_hand;
		ASSERT(hmebp >= uhme_hash && hmebp <= &uhme_hash[UHMEHASH_SZ]);

		for (i = 0; hmeblkp == NULL && i <= UHMEHASH_SZ +
		    BUCKETS_TO_SEARCH_BEFORE_UNLOAD; i++) {
			SFMMU_HASH_LOCK(hmebp);
			hmeblkp = hmebp->hmeblkp;
			hblkpa = hmebp->hmeh_nextpa;
			pr_hblk = NULL;
			while (hmeblkp) {
				/*
				 * check if it is a hmeblk that is not locked
				 * and not shared. skip shadow hmeblks with
				 * shadow_mask set i.e valid count non zero.
				 */
				if ((get_hblk_ttesz(hmeblkp) == size) &&
				    (hmeblkp->hblk_shw_bit == 0 ||
				    hmeblkp->hblk_vcnt == 0) &&
				    (hmeblkp->hblk_lckcnt == 0)) {
					/*
					 * there is a high probability that we
					 * will find a free one. search some
					 * buckets for a free hmeblk initially
					 * before unloading a valid hmeblk.
					 */
					if ((hmeblkp->hblk_vcnt == 0 &&
					    hmeblkp->hblk_hmecnt == 0) || (i >=
					    BUCKETS_TO_SEARCH_BEFORE_UNLOAD)) {
						if (sfmmu_steal_this_hblk(hmebp,
						    hmeblkp, hblkpa, pr_hblk)) {
							/*
							 * Hblk is unloaded
							 * successfully
							 */
							break;
						}
					}
				}
				pr_hblk = hmeblkp;
				hblkpa = hmeblkp->hblk_nextpa;
				hmeblkp = hmeblkp->hblk_next;
			}

			SFMMU_HASH_UNLOCK(hmebp);
			if (hmebp++ == &uhme_hash[UHMEHASH_SZ])
				hmebp = uhme_hash;
		}
		uhmehash_steal_hand = hmebp;

		if (hmeblkp != NULL)
			break;

		/*
		 * in the worst case, look for a free one in the kernel
		 * hash table.
		 */
		for (i = 0, hmebp = khme_hash; i <= KHMEHASH_SZ; i++) {
			SFMMU_HASH_LOCK(hmebp);
			hmeblkp = hmebp->hmeblkp;
			hblkpa = hmebp->hmeh_nextpa;
			pr_hblk = NULL;
			while (hmeblkp) {
				/*
				 * check if it is free hmeblk
				 */
				if ((get_hblk_ttesz(hmeblkp) == size) &&
				    (hmeblkp->hblk_lckcnt == 0) &&
				    (hmeblkp->hblk_vcnt == 0) &&
				    (hmeblkp->hblk_hmecnt == 0)) {
					if (sfmmu_steal_this_hblk(hmebp,
					    hmeblkp, hblkpa, pr_hblk)) {
						break;
					} else {
						/*
						 * Cannot fail since we have
						 * hash lock.
						 */
						panic("fail to steal?");
					}
				}

				pr_hblk = hmeblkp;
				hblkpa = hmeblkp->hblk_nextpa;
				hmeblkp = hmeblkp->hblk_next;
			}

			SFMMU_HASH_UNLOCK(hmebp);
			if (hmebp++ == &khme_hash[KHMEHASH_SZ])
				hmebp = khme_hash;
		}

		if (hmeblkp != NULL)
			break;
		sfmmu_hblk_steal_twice++;
	}
	return (hmeblkp);
}

/*
 * This routine does real work to prepare a hblk to be "stolen" by
 * unloading the mappings, updating shadow counts ....
 * It returns 1 if the block is ready to be reused (stolen), or 0
 * means the block cannot be stolen yet- pageunload is still working
 * on this hblk.
 */
static int
sfmmu_steal_this_hblk(struct hmehash_bucket *hmebp, struct hme_blk *hmeblkp,
	uint64_t hblkpa, struct hme_blk *pr_hblk)
{
	int shw_size, vshift;
	struct hme_blk *shw_hblkp;
	caddr_t vaddr;
	uint_t shw_mask, newshw_mask;
	struct hme_blk *list = NULL;

	ASSERT(SFMMU_HASH_LOCK_ISHELD(hmebp));

	/*
	 * check if the hmeblk is free, unload if necessary
	 */
	if (hmeblkp->hblk_vcnt || hmeblkp->hblk_hmecnt) {
		sfmmu_t *sfmmup;
		demap_range_t dmr;

		sfmmup = hblktosfmmu(hmeblkp);
		if (hmeblkp->hblk_shared || sfmmup->sfmmu_ismhat) {
			return (0);
		}
		DEMAP_RANGE_INIT(sfmmup, &dmr);
		(void) sfmmu_hblk_unload(sfmmup, hmeblkp,
		    (caddr_t)get_hblk_base(hmeblkp),
		    get_hblk_endaddr(hmeblkp), &dmr, HAT_UNLOAD);
		DEMAP_RANGE_FLUSH(&dmr);
		if (hmeblkp->hblk_vcnt || hmeblkp->hblk_hmecnt) {
			/*
			 * Pageunload is working on the same hblk.
			 */
			return (0);
		}

		sfmmu_hblk_steal_unload_count++;
	}

	ASSERT(hmeblkp->hblk_lckcnt == 0);
	ASSERT(hmeblkp->hblk_vcnt == 0 && hmeblkp->hblk_hmecnt == 0);

	sfmmu_hblk_hash_rm(hmebp, hmeblkp, pr_hblk, &list, 1);
	hmeblkp->hblk_nextpa = hblkpa;

	shw_hblkp = hmeblkp->hblk_shadow;
	if (shw_hblkp) {
		ASSERT(!hmeblkp->hblk_shared);
		shw_size = get_hblk_ttesz(shw_hblkp);
		vaddr = (caddr_t)get_hblk_base(hmeblkp);
		vshift = vaddr_to_vshift(shw_hblkp->hblk_tag, vaddr, shw_size);
		ASSERT(vshift < 8);
		/*
		 * Atomically clear shadow mask bit
		 */
		do {
			shw_mask = shw_hblkp->hblk_shw_mask;
			ASSERT(shw_mask & (1 << vshift));
			newshw_mask = shw_mask & ~(1 << vshift);
			newshw_mask = atomic_cas_32(&shw_hblkp->hblk_shw_mask,
			    shw_mask, newshw_mask);
		} while (newshw_mask != shw_mask);
		hmeblkp->hblk_shadow = NULL;
	}

	/*
	 * remove shadow bit if we are stealing an unused shadow hmeblk.
	 * sfmmu_hblk_alloc needs it that way, will set shadow bit later if
	 * we are indeed allocating a shadow hmeblk.
	 */
	hmeblkp->hblk_shw_bit = 0;

	if (hmeblkp->hblk_shared) {
		sf_srd_t	*srdp;
		sf_region_t	*rgnp;
		uint_t		rid;

		srdp = hblktosrd(hmeblkp);
		ASSERT(srdp != NULL && srdp->srd_refcnt != 0);
		rid = hmeblkp->hblk_tag.htag_rid;
		ASSERT(SFMMU_IS_SHMERID_VALID(rid));
		ASSERT(rid < SFMMU_MAX_HME_REGIONS);
		rgnp = srdp->srd_hmergnp[rid];
		ASSERT(rgnp != NULL);
		SFMMU_VALIDATE_SHAREDHBLK(hmeblkp, srdp, rgnp, rid);
		hmeblkp->hblk_shared = 0;
	}

	sfmmu_hblk_steal_count++;
	SFMMU_STAT(sf_steal_count);

	return (1);
}

struct hme_blk *
sfmmu_hmetohblk(struct sf_hment *sfhme)
{
	struct hme_blk *hmeblkp;
	struct sf_hment *sfhme0;
	struct hme_blk *hblk_dummy = 0;

	/*
	 * No dummy sf_hments, please.
	 */
	ASSERT(sfhme->hme_tte.ll != 0);

	sfhme0 = sfhme - sfhme->hme_tte.tte_hmenum;
	hmeblkp = (struct hme_blk *)((uintptr_t)sfhme0 -
	    (uintptr_t)&hblk_dummy->hblk_hme[0]);

	return (hmeblkp);
}

/*
 * On swapin, get appropriately sized TSB(s) and clear the HAT_SWAPPED flag.
 * If we can't get appropriately sized TSB(s), try for 8K TSB(s) using
 * KM_SLEEP allocation.
 *
 * Return 0 on success, -1 otherwise.
 */
static void
sfmmu_tsb_swapin(sfmmu_t *sfmmup, hatlock_t *hatlockp)
{
	struct tsb_info *tsbinfop, *next;
	tsb_replace_rc_t rc;
	boolean_t gotfirst = B_FALSE;

	ASSERT(sfmmup != ksfmmup);
	ASSERT(sfmmu_hat_lock_held(sfmmup));

	while (SFMMU_FLAGS_ISSET(sfmmup, HAT_SWAPIN)) {
		cv_wait(&sfmmup->sfmmu_tsb_cv, HATLOCK_MUTEXP(hatlockp));
	}

	if (SFMMU_FLAGS_ISSET(sfmmup, HAT_SWAPPED)) {
		SFMMU_FLAGS_SET(sfmmup, HAT_SWAPIN);
	} else {
		return;
	}

	ASSERT(sfmmup->sfmmu_tsb != NULL);

	/*
	 * Loop over all tsbinfo's replacing them with ones that actually have
	 * a TSB.  If any of the replacements ever fail, bail out of the loop.
	 */
	for (tsbinfop = sfmmup->sfmmu_tsb; tsbinfop != NULL; tsbinfop = next) {
		ASSERT(tsbinfop->tsb_flags & TSB_SWAPPED);
		next = tsbinfop->tsb_next;
		rc = sfmmu_replace_tsb(sfmmup, tsbinfop, tsbinfop->tsb_szc,
		    hatlockp, TSB_SWAPIN);
		if (rc != TSB_SUCCESS) {
			break;
		}
		gotfirst = B_TRUE;
	}

	switch (rc) {
	case TSB_SUCCESS:
		SFMMU_FLAGS_CLEAR(sfmmup, HAT_SWAPPED|HAT_SWAPIN);
		cv_broadcast(&sfmmup->sfmmu_tsb_cv);
		return;
	case TSB_LOSTRACE:
		break;
	case TSB_ALLOCFAIL:
		break;
	default:
		panic("sfmmu_replace_tsb returned unrecognized failure code "
		    "%d", rc);
	}

	/*
	 * In this case, we failed to get one of our TSBs.  If we failed to
	 * get the first TSB, get one of minimum size (8KB).  Walk the list
	 * and throw away the tsbinfos, starting where the allocation failed;
	 * we can get by with just one TSB as long as we don't leave the
	 * SWAPPED tsbinfo structures lying around.
	 */
	tsbinfop = sfmmup->sfmmu_tsb;
	next = tsbinfop->tsb_next;
	tsbinfop->tsb_next = NULL;

	sfmmu_hat_exit(hatlockp);
	for (tsbinfop = next; tsbinfop != NULL; tsbinfop = next) {
		next = tsbinfop->tsb_next;
		sfmmu_tsbinfo_free(tsbinfop);
	}
	hatlockp = sfmmu_hat_enter(sfmmup);

	/*
	 * If we don't have any TSBs, get a single 8K TSB for 8K, 64K and 512K
	 * pages.
	 */
	if (!gotfirst) {
		tsbinfop = sfmmup->sfmmu_tsb;
		rc = sfmmu_replace_tsb(sfmmup, tsbinfop, TSB_MIN_SZCODE,
		    hatlockp, TSB_SWAPIN | TSB_FORCEALLOC);
		ASSERT(rc == TSB_SUCCESS);
	}

	SFMMU_FLAGS_CLEAR(sfmmup, HAT_SWAPPED|HAT_SWAPIN);
	cv_broadcast(&sfmmup->sfmmu_tsb_cv);
}

static int
sfmmu_is_rgnva(sf_srd_t *srdp, caddr_t addr, ulong_t w, ulong_t bmw)
{
	ulong_t bix = 0;
	uint_t rid;
	sf_region_t *rgnp;

	ASSERT(srdp != NULL);
	ASSERT(srdp->srd_refcnt != 0);

	w <<= BT_ULSHIFT;
	while (bmw) {
		if (!(bmw & 0x1)) {
			bix++;
			bmw >>= 1;
			continue;
		}
		rid = w | bix;
		rgnp = srdp->srd_hmergnp[rid];
		ASSERT(rgnp->rgn_refcnt > 0);
		ASSERT(rgnp->rgn_id == rid);
		if (addr < rgnp->rgn_saddr ||
		    addr >= (rgnp->rgn_saddr + rgnp->rgn_size)) {
			bix++;
			bmw >>= 1;
		} else {
			return (1);
		}
	}
	return (0);
}

/*
 * Handle exceptions for low level tsb_handler.
 *
 * There are many scenarios that could land us here:
 *
 * If the context is invalid we land here. The context can be invalid
 * for 3 reasons: 1) we couldn't allocate a new context and now need to
 * perform a wrap around operation in order to allocate a new context.
 * 2) Context was invalidated to change pagesize programming 3) ISMs or
 * TSBs configuration is changeing for this process and we are forced into
 * here to do a syncronization operation. If the context is valid we can
 * be here from window trap hanlder. In this case just call trap to handle
 * the fault.
 *
 * Note that the process will run in INVALID_CONTEXT before
 * faulting into here and subsequently loading the MMU registers
 * (including the TSB base register) associated with this process.
 * For this reason, the trap handlers must all test for
 * INVALID_CONTEXT before attempting to access any registers other
 * than the context registers.
 */
void
sfmmu_tsbmiss_exception(struct regs *rp, uintptr_t tagaccess, uint_t traptype)
{
	sfmmu_t *sfmmup, *shsfmmup;
	uint_t ctxtype;
	klwp_id_t lwp;
	char lwp_save_state;
	hatlock_t *hatlockp, *shatlockp;
	struct tsb_info *tsbinfop;
	struct tsbmiss *tsbmp;
	sf_scd_t *scdp;

	SFMMU_STAT(sf_tsb_exceptions);
	SFMMU_MMU_STAT(mmu_tsb_exceptions);
	sfmmup = astosfmmu(curthread->t_procp->p_as);
	/*
	 * note that in sun4u, tagacces register contains ctxnum
	 * while sun4v passes ctxtype in the tagaccess register.
	 */
	ctxtype = tagaccess & TAGACC_CTX_MASK;

	ASSERT(sfmmup != ksfmmup && ctxtype != KCONTEXT);
	ASSERT(sfmmup->sfmmu_ismhat == 0);
	ASSERT(!SFMMU_FLAGS_ISSET(sfmmup, HAT_SWAPPED) ||
	    ctxtype == INVALID_CONTEXT);

	if (ctxtype != INVALID_CONTEXT && traptype != T_DATA_PROT) {
		/*
		 * We may land here because shme bitmap and pagesize
		 * flags are updated lazily in tsbmiss area on other cpus.
		 * If we detect here that tsbmiss area is out of sync with
		 * sfmmu update it and retry the trapped instruction.
		 * Otherwise call trap().
		 */
		int ret = 0;
		uchar_t tteflag_mask = (1 << TTE64K) | (1 << TTE8K);
		caddr_t addr = (caddr_t)(tagaccess & TAGACC_VADDR_MASK);

		/*
		 * Must set lwp state to LWP_SYS before
		 * trying to acquire any adaptive lock
		 */
		lwp = ttolwp(curthread);
		ASSERT(lwp);
		lwp_save_state = lwp->lwp_state;
		lwp->lwp_state = LWP_SYS;

		hatlockp = sfmmu_hat_enter(sfmmup);
		kpreempt_disable();
		tsbmp = &tsbmiss_area[CPU->cpu_id];
		ASSERT(sfmmup == tsbmp->usfmmup);
		if (((tsbmp->uhat_tteflags ^ sfmmup->sfmmu_tteflags) &
		    ~tteflag_mask) ||
		    ((tsbmp->uhat_rtteflags ^  sfmmup->sfmmu_rtteflags) &
		    ~tteflag_mask)) {
			tsbmp->uhat_tteflags = sfmmup->sfmmu_tteflags;
			tsbmp->uhat_rtteflags = sfmmup->sfmmu_rtteflags;
			ret = 1;
		}
		if (sfmmup->sfmmu_srdp != NULL) {
			ulong_t *sm = sfmmup->sfmmu_hmeregion_map.bitmap;
			ulong_t *tm = tsbmp->shmermap;
			ulong_t i;
			for (i = 0; i < SFMMU_HMERGNMAP_WORDS; i++) {
				ulong_t d = tm[i] ^ sm[i];
				if (d) {
					if (d & sm[i]) {
						if (!ret && sfmmu_is_rgnva(
						    sfmmup->sfmmu_srdp,
						    addr, i, d & sm[i])) {
							ret = 1;
						}
					}
					tm[i] = sm[i];
				}
			}
		}
		kpreempt_enable();
		sfmmu_hat_exit(hatlockp);
		lwp->lwp_state = lwp_save_state;
		if (ret) {
			return;
		}
	} else if (ctxtype == INVALID_CONTEXT) {
		/*
		 * First, make sure we come out of here with a valid ctx,
		 * since if we don't get one we'll simply loop on the
		 * faulting instruction.
		 *
		 * If the ISM mappings are changing, the TSB is relocated,
		 * the process is swapped, the process is joining SCD or
		 * leaving SCD or shared regions we serialize behind the
		 * controlling thread with hat lock, sfmmu_flags and
		 * sfmmu_tsb_cv condition variable.
		 */

		/*
		 * Must set lwp state to LWP_SYS before
		 * trying to acquire any adaptive lock
		 */
		lwp = ttolwp(curthread);
		ASSERT(lwp);
		lwp_save_state = lwp->lwp_state;
		lwp->lwp_state = LWP_SYS;

		hatlockp = sfmmu_hat_enter(sfmmup);
retry:
		if ((scdp = sfmmup->sfmmu_scdp) != NULL) {
			shsfmmup = scdp->scd_sfmmup;
			ASSERT(shsfmmup != NULL);

			for (tsbinfop = shsfmmup->sfmmu_tsb; tsbinfop != NULL;
			    tsbinfop = tsbinfop->tsb_next) {
				if (tsbinfop->tsb_flags & TSB_RELOC_FLAG) {
					/* drop the private hat lock */
					sfmmu_hat_exit(hatlockp);
					/* acquire the shared hat lock */
					shatlockp = sfmmu_hat_enter(shsfmmup);
					/*
					 * recheck to see if anything changed
					 * after we drop the private hat lock.
					 */
					if (sfmmup->sfmmu_scdp == scdp &&
					    shsfmmup == scdp->scd_sfmmup) {
						sfmmu_tsb_chk_reloc(shsfmmup,
						    shatlockp);
					}
					sfmmu_hat_exit(shatlockp);
					hatlockp = sfmmu_hat_enter(sfmmup);
					goto retry;
				}
			}
		}

		for (tsbinfop = sfmmup->sfmmu_tsb; tsbinfop != NULL;
		    tsbinfop = tsbinfop->tsb_next) {
			if (tsbinfop->tsb_flags & TSB_RELOC_FLAG) {
				cv_wait(&sfmmup->sfmmu_tsb_cv,
				    HATLOCK_MUTEXP(hatlockp));
				goto retry;
			}
		}

		/*
		 * Wait for ISM maps to be updated.
		 */
		if (SFMMU_FLAGS_ISSET(sfmmup, HAT_ISMBUSY)) {
			cv_wait(&sfmmup->sfmmu_tsb_cv,
			    HATLOCK_MUTEXP(hatlockp));
			goto retry;
		}

		/* Is this process joining an SCD? */
		if (SFMMU_FLAGS_ISSET(sfmmup, HAT_JOIN_SCD)) {
			/*
			 * Flush private TSB and setup shared TSB.
			 * sfmmu_finish_join_scd() does not drop the
			 * hat lock.
			 */
			sfmmu_finish_join_scd(sfmmup);
			SFMMU_FLAGS_CLEAR(sfmmup, HAT_JOIN_SCD);
		}

		/*
		 * If we're swapping in, get TSB(s).  Note that we must do
		 * this before we get a ctx or load the MMU state.  Once
		 * we swap in we have to recheck to make sure the TSB(s) and
		 * ISM mappings didn't change while we slept.
		 */
		if (SFMMU_FLAGS_ISSET(sfmmup, HAT_SWAPPED)) {
			sfmmu_tsb_swapin(sfmmup, hatlockp);
			goto retry;
		}

		sfmmu_get_ctx(sfmmup);

		sfmmu_hat_exit(hatlockp);
		/*
		 * Must restore lwp_state if not calling
		 * trap() for further processing. Restore
		 * it anyway.
		 */
		lwp->lwp_state = lwp_save_state;
		return;
	}
	trap(rp, (caddr_t)tagaccess, traptype, 0);
}

static void
sfmmu_tsb_chk_reloc(sfmmu_t *sfmmup, hatlock_t *hatlockp)
{
	struct tsb_info *tp;

	ASSERT(sfmmu_hat_lock_held(sfmmup));

	for (tp = sfmmup->sfmmu_tsb; tp != NULL; tp = tp->tsb_next) {
		if (tp->tsb_flags & TSB_RELOC_FLAG) {
			cv_wait(&sfmmup->sfmmu_tsb_cv,
			    HATLOCK_MUTEXP(hatlockp));
			break;
		}
	}
}

/*
 * sfmmu_vatopfn_suspended is called from GET_TTE when TL=0 and
 * TTE_SUSPENDED bit set in tte we block on aquiring a page lock
 * rather than spinning to avoid send mondo timeouts with
 * interrupts enabled. When the lock is acquired it is immediately
 * released and we return back to sfmmu_vatopfn just after
 * the GET_TTE call.
 */
void
sfmmu_vatopfn_suspended(caddr_t vaddr, sfmmu_t *sfmmu, tte_t *ttep)
{
	struct page	**pp;

	(void) as_pagelock(sfmmu->sfmmu_as, &pp, vaddr, TTE_CSZ(ttep), S_WRITE);
	as_pageunlock(sfmmu->sfmmu_as, pp, vaddr, TTE_CSZ(ttep), S_WRITE);
}

/*
 * sfmmu_tsbmiss_suspended is called from GET_TTE when TL>0 and
 * TTE_SUSPENDED bit set in tte. We do this so that we can handle
 * cross traps which cannot be handled while spinning in the
 * trap handlers. Simply enter and exit the kpr_suspendlock spin
 * mutex, which is held by the holder of the suspend bit, and then
 * retry the trapped instruction after unwinding.
 */
/*ARGSUSED*/
void
sfmmu_tsbmiss_suspended(struct regs *rp, uintptr_t tagacc, uint_t traptype)
{
	ASSERT(curthread != kreloc_thread);
	mutex_enter(&kpr_suspendlock);
	mutex_exit(&kpr_suspendlock);
}

/*
 * This routine could be optimized to reduce the number of xcalls by flushing
 * the entire TLBs if region reference count is above some threshold but the
 * tradeoff will depend on the size of the TLB. So for now flush the specific
 * page a context at a time.
 *
 * If uselocks is 0 then it's called after all cpus were captured and all the
 * hat locks were taken. In this case don't take the region lock by relying on
 * the order of list region update operations in hat_join_region(),
 * hat_leave_region() and hat_dup_region(). The ordering in those routines
 * guarantees that list is always forward walkable and reaches active sfmmus
 * regardless of where xc_attention() captures a cpu.
 */
cpuset_t
sfmmu_rgntlb_demap(caddr_t addr, sf_region_t *rgnp,
    struct hme_blk *hmeblkp, int uselocks)
{
	sfmmu_t	*sfmmup;
	cpuset_t cpuset;
	cpuset_t rcpuset;
	hatlock_t *hatlockp;
	uint_t rid = rgnp->rgn_id;
	sf_rgn_link_t *rlink;
	sf_scd_t *scdp;

	ASSERT(hmeblkp->hblk_shared);
	ASSERT(SFMMU_IS_SHMERID_VALID(rid));
	ASSERT(rid < SFMMU_MAX_HME_REGIONS);

	CPUSET_ZERO(rcpuset);
	if (uselocks) {
		mutex_enter(&rgnp->rgn_mutex);
	}
	sfmmup = rgnp->rgn_sfmmu_head;
	while (sfmmup != NULL) {
		if (uselocks) {
			hatlockp = sfmmu_hat_enter(sfmmup);
		}

		/*
		 * When an SCD is created the SCD hat is linked on the sfmmu
		 * region lists for each hme region which is part of the
		 * SCD. If we find an SCD hat, when walking these lists,
		 * then we flush the shared TSBs, if we find a private hat,
		 * which is part of an SCD, but where the region
		 * is not part of the SCD then we flush the private TSBs.
		 */
		if (!sfmmup->sfmmu_scdhat && sfmmup->sfmmu_scdp != NULL &&
		    !SFMMU_FLAGS_ISSET(sfmmup, HAT_JOIN_SCD)) {
			scdp = sfmmup->sfmmu_scdp;
			if (SF_RGNMAP_TEST(scdp->scd_hmeregion_map, rid)) {
				if (uselocks) {
					sfmmu_hat_exit(hatlockp);
				}
				goto next;
			}
		}

		SFMMU_UNLOAD_TSB(addr, sfmmup, hmeblkp, 0);

		kpreempt_disable();
		cpuset = sfmmup->sfmmu_cpusran;
		CPUSET_AND(cpuset, cpu_ready_set);
		CPUSET_DEL(cpuset, CPU->cpu_id);
		SFMMU_XCALL_STATS(sfmmup);
		xt_some(cpuset, vtag_flushpage_tl1,
		    (uint64_t)addr, (uint64_t)sfmmup);
		vtag_flushpage(addr, (uint64_t)sfmmup);
		if (uselocks) {
			sfmmu_hat_exit(hatlockp);
		}
		kpreempt_enable();
		CPUSET_OR(rcpuset, cpuset);

next:
		/* LINTED: constant in conditional context */
		SFMMU_HMERID2RLINKP(sfmmup, rid, rlink, 0, 0);
		ASSERT(rlink != NULL);
		sfmmup = rlink->next;
	}
	if (uselocks) {
		mutex_exit(&rgnp->rgn_mutex);
	}
	return (rcpuset);
}

/*
 * This routine takes an sfmmu pointer and the va for an adddress in an
 * ISM region as input and returns the corresponding region id in ism_rid.
 * The return value of 1 indicates that a region has been found and ism_rid
 * is valid, otherwise 0 is returned.
 */
static int
find_ism_rid(sfmmu_t *sfmmup, sfmmu_t *ism_sfmmup, caddr_t va, uint_t *ism_rid)
{
	ism_blk_t	*ism_blkp;
	int		i;
	ism_map_t	*ism_map;
#ifdef DEBUG
	struct hat	*ism_hatid;
#endif
	ASSERT(sfmmu_hat_lock_held(sfmmup));

	ism_blkp = sfmmup->sfmmu_iblk;
	while (ism_blkp != NULL) {
		ism_map = ism_blkp->iblk_maps;
		for (i = 0; i < ISM_MAP_SLOTS && ism_map[i].imap_ismhat; i++) {
			if ((va >= ism_start(ism_map[i])) &&
			    (va < ism_end(ism_map[i]))) {

				*ism_rid = ism_map[i].imap_rid;
#ifdef DEBUG
				ism_hatid = ism_map[i].imap_ismhat;
				ASSERT(ism_hatid == ism_sfmmup);
				ASSERT(ism_hatid->sfmmu_ismhat);
#endif
				return (1);
			}
		}
		ism_blkp = ism_blkp->iblk_next;
	}
	return (0);
}

/*
 * Special routine to flush out ism mappings- TSBs, TLBs and D-caches.
 * This routine may be called with all cpu's captured. Therefore, the
 * caller is responsible for holding all locks and disabling kernel
 * preemption.
 */
/* ARGSUSED */
static void
sfmmu_ismtlbcache_demap(caddr_t addr, sfmmu_t *ism_sfmmup,
	struct hme_blk *hmeblkp, pfn_t pfnum, int cache_flush_flag)
{
	cpuset_t 	cpuset;
	caddr_t 	va;
	ism_ment_t	*ment;
	sfmmu_t		*sfmmup;
#ifdef VAC
	int 		vcolor;
#endif

	sf_scd_t	*scdp;
	uint_t		ism_rid;

	ASSERT(!hmeblkp->hblk_shared);
	/*
	 * Walk the ism_hat's mapping list and flush the page
	 * from every hat sharing this ism_hat. This routine
	 * may be called while all cpu's have been captured.
	 * Therefore we can't attempt to grab any locks. For now
	 * this means we will protect the ism mapping list under
	 * a single lock which will be grabbed by the caller.
	 * If hat_share/unshare scalibility becomes a performance
	 * problem then we may need to re-think ism mapping list locking.
	 */
	ASSERT(ism_sfmmup->sfmmu_ismhat);
	ASSERT(MUTEX_HELD(&ism_mlist_lock));
	addr = addr - ISMID_STARTADDR;

	for (ment = ism_sfmmup->sfmmu_iment; ment; ment = ment->iment_next) {

		sfmmup = ment->iment_hat;

		va = ment->iment_base_va;
		va = (caddr_t)((uintptr_t)va  + (uintptr_t)addr);

		/*
		 * When an SCD is created the SCD hat is linked on the ism
		 * mapping lists for each ISM segment which is part of the
		 * SCD. If we find an SCD hat, when walking these lists,
		 * then we flush the shared TSBs, if we find a private hat,
		 * which is part of an SCD, but where the region
		 * corresponding to this va is not part of the SCD then we
		 * flush the private TSBs.
		 */
		if (!sfmmup->sfmmu_scdhat && sfmmup->sfmmu_scdp != NULL &&
		    !SFMMU_FLAGS_ISSET(sfmmup, HAT_JOIN_SCD) &&
		    !SFMMU_FLAGS_ISSET(sfmmup, HAT_ISMBUSY)) {
			if (!find_ism_rid(sfmmup, ism_sfmmup, va,
			    &ism_rid)) {
				cmn_err(CE_PANIC,
				    "can't find matching ISM rid!");
			}

			scdp = sfmmup->sfmmu_scdp;
			if (SFMMU_IS_ISMRID_VALID(ism_rid) &&
			    SF_RGNMAP_TEST(scdp->scd_ismregion_map,
			    ism_rid)) {
				continue;
			}
		}
		SFMMU_UNLOAD_TSB(va, sfmmup, hmeblkp, 1);

		cpuset = sfmmup->sfmmu_cpusran;
		CPUSET_AND(cpuset, cpu_ready_set);
		CPUSET_DEL(cpuset, CPU->cpu_id);
		SFMMU_XCALL_STATS(sfmmup);
		xt_some(cpuset, vtag_flushpage_tl1, (uint64_t)va,
		    (uint64_t)sfmmup);
		vtag_flushpage(va, (uint64_t)sfmmup);

#ifdef VAC
		/*
		 * Flush D$
		 * When flushing D$ we must flush all
		 * cpu's. See sfmmu_cache_flush().
		 */
		if (cache_flush_flag == CACHE_FLUSH) {
			cpuset = cpu_ready_set;
			CPUSET_DEL(cpuset, CPU->cpu_id);

			SFMMU_XCALL_STATS(sfmmup);
			vcolor = addr_to_vcolor(va);
			xt_some(cpuset, vac_flushpage_tl1, pfnum, vcolor);
			vac_flushpage(pfnum, vcolor);
		}
#endif	/* VAC */
	}
}

/*
 * Demaps the TSB, CPU caches, and flushes all TLBs on all CPUs of
 * a particular virtual address and ctx.  If noflush is set we do not
 * flush the TLB/TSB.  This function may or may not be called with the
 * HAT lock held.
 */
static void
sfmmu_tlbcache_demap(caddr_t addr, sfmmu_t *sfmmup, struct hme_blk *hmeblkp,
	pfn_t pfnum, int tlb_noflush, int cpu_flag, int cache_flush_flag,
	int hat_lock_held)
{
#ifdef VAC
	int vcolor;
#endif
	cpuset_t cpuset;
	hatlock_t *hatlockp;

	ASSERT(!hmeblkp->hblk_shared);

#if defined(lint) && !defined(VAC)
	pfnum = pfnum;
	cpu_flag = cpu_flag;
	cache_flush_flag = cache_flush_flag;
#endif

	/*
	 * There is no longer a need to protect against ctx being
	 * stolen here since we don't store the ctx in the TSB anymore.
	 */
#ifdef VAC
	vcolor = addr_to_vcolor(addr);
#endif

	/*
	 * We must hold the hat lock during the flush of TLB,
	 * to avoid a race with sfmmu_invalidate_ctx(), where
	 * sfmmu_cnum on a MMU could be set to INVALID_CONTEXT,
	 * causing TLB demap routine to skip flush on that MMU.
	 * If the context on a MMU has already been set to
	 * INVALID_CONTEXT, we just get an extra flush on
	 * that MMU.
	 */
	if (!hat_lock_held && !tlb_noflush)
		hatlockp = sfmmu_hat_enter(sfmmup);

	kpreempt_disable();
	if (!tlb_noflush) {
		/*
		 * Flush the TSB and TLB.
		 */
		SFMMU_UNLOAD_TSB(addr, sfmmup, hmeblkp, 0);

		cpuset = sfmmup->sfmmu_cpusran;
		CPUSET_AND(cpuset, cpu_ready_set);
		CPUSET_DEL(cpuset, CPU->cpu_id);

		SFMMU_XCALL_STATS(sfmmup);

		xt_some(cpuset, vtag_flushpage_tl1, (uint64_t)addr,
		    (uint64_t)sfmmup);

		vtag_flushpage(addr, (uint64_t)sfmmup);
	}

	if (!hat_lock_held && !tlb_noflush)
		sfmmu_hat_exit(hatlockp);

#ifdef VAC
	/*
	 * Flush the D$
	 *
	 * Even if the ctx is stolen, we need to flush the
	 * cache. Our ctx stealer only flushes the TLBs.
	 */
	if (cache_flush_flag == CACHE_FLUSH) {
		if (cpu_flag & FLUSH_ALL_CPUS) {
			cpuset = cpu_ready_set;
		} else {
			cpuset = sfmmup->sfmmu_cpusran;
			CPUSET_AND(cpuset, cpu_ready_set);
		}
		CPUSET_DEL(cpuset, CPU->cpu_id);
		SFMMU_XCALL_STATS(sfmmup);
		xt_some(cpuset, vac_flushpage_tl1, pfnum, vcolor);
		vac_flushpage(pfnum, vcolor);
	}
#endif	/* VAC */
	kpreempt_enable();
}

/*
 * Demaps the TSB and flushes all TLBs on all cpus for a particular virtual
 * address and ctx.  If noflush is set we do not currently do anything.
 * This function may or may not be called with the HAT lock held.
 */
static void
sfmmu_tlb_demap(caddr_t addr, sfmmu_t *sfmmup, struct hme_blk *hmeblkp,
	int tlb_noflush, int hat_lock_held)
{
	cpuset_t cpuset;
	hatlock_t *hatlockp;

	ASSERT(!hmeblkp->hblk_shared);

	/*
	 * If the process is exiting we have nothing to do.
	 */
	if (tlb_noflush)
		return;

	/*
	 * Flush TSB.
	 */
	if (!hat_lock_held)
		hatlockp = sfmmu_hat_enter(sfmmup);
	SFMMU_UNLOAD_TSB(addr, sfmmup, hmeblkp, 0);

	kpreempt_disable();

	cpuset = sfmmup->sfmmu_cpusran;
	CPUSET_AND(cpuset, cpu_ready_set);
	CPUSET_DEL(cpuset, CPU->cpu_id);

	SFMMU_XCALL_STATS(sfmmup);
	xt_some(cpuset, vtag_flushpage_tl1, (uint64_t)addr, (uint64_t)sfmmup);

	vtag_flushpage(addr, (uint64_t)sfmmup);

	if (!hat_lock_held)
		sfmmu_hat_exit(hatlockp);

	kpreempt_enable();

}

/*
 * Special case of sfmmu_tlb_demap for MMU_PAGESIZE hblks. Use the xcall
 * call handler that can flush a range of pages to save on xcalls.
 */
static int sfmmu_xcall_save;

/*
 * this routine is never used for demaping addresses backed by SRD hmeblks.
 */
static void
sfmmu_tlb_range_demap(demap_range_t *dmrp)
{
	sfmmu_t *sfmmup = dmrp->dmr_sfmmup;
	hatlock_t *hatlockp;
	cpuset_t cpuset;
	uint64_t sfmmu_pgcnt;
	pgcnt_t pgcnt = 0;
	int pgunload = 0;
	int dirtypg = 0;
	caddr_t addr = dmrp->dmr_addr;
	caddr_t eaddr;
	uint64_t bitvec = dmrp->dmr_bitvec;

	ASSERT(bitvec & 1);

	/*
	 * Flush TSB and calculate number of pages to flush.
	 */
	while (bitvec != 0) {
		dirtypg = 0;
		/*
		 * Find the first page to flush and then count how many
		 * pages there are after it that also need to be flushed.
		 * This way the number of TSB flushes is minimized.
		 */
		while ((bitvec & 1) == 0) {
			pgcnt++;
			addr += MMU_PAGESIZE;
			bitvec >>= 1;
		}
		while (bitvec & 1) {
			dirtypg++;
			bitvec >>= 1;
		}
		eaddr = addr + ptob(dirtypg);
		hatlockp = sfmmu_hat_enter(sfmmup);
		sfmmu_unload_tsb_range(sfmmup, addr, eaddr, TTE8K);
		sfmmu_hat_exit(hatlockp);
		pgunload += dirtypg;
		addr = eaddr;
		pgcnt += dirtypg;
	}

	ASSERT((pgcnt<<MMU_PAGESHIFT) <= dmrp->dmr_endaddr - dmrp->dmr_addr);
	if (sfmmup->sfmmu_free == 0) {
		addr = dmrp->dmr_addr;
		bitvec = dmrp->dmr_bitvec;

		/*
		 * make sure it has SFMMU_PGCNT_SHIFT bits only,
		 * as it will be used to pack argument for xt_some
		 */
		ASSERT((pgcnt > 0) &&
		    (pgcnt <= (1 << SFMMU_PGCNT_SHIFT)));

		/*
		 * Encode pgcnt as (pgcnt -1 ), and pass (pgcnt - 1) in
		 * the low 6 bits of sfmmup. This is doable since pgcnt
		 * always >= 1.
		 */
		ASSERT(!((uint64_t)sfmmup & SFMMU_PGCNT_MASK));
		sfmmu_pgcnt = (uint64_t)sfmmup |
		    ((pgcnt - 1) & SFMMU_PGCNT_MASK);

		/*
		 * We must hold the hat lock during the flush of TLB,
		 * to avoid a race with sfmmu_invalidate_ctx(), where
		 * sfmmu_cnum on a MMU could be set to INVALID_CONTEXT,
		 * causing TLB demap routine to skip flush on that MMU.
		 * If the context on a MMU has already been set to
		 * INVALID_CONTEXT, we just get an extra flush on
		 * that MMU.
		 */
		hatlockp = sfmmu_hat_enter(sfmmup);
		kpreempt_disable();

		cpuset = sfmmup->sfmmu_cpusran;
		CPUSET_AND(cpuset, cpu_ready_set);
		CPUSET_DEL(cpuset, CPU->cpu_id);

		SFMMU_XCALL_STATS(sfmmup);
		xt_some(cpuset, vtag_flush_pgcnt_tl1, (uint64_t)addr,
		    sfmmu_pgcnt);

		for (; bitvec != 0; bitvec >>= 1) {
			if (bitvec & 1)
				vtag_flushpage(addr, (uint64_t)sfmmup);
			addr += MMU_PAGESIZE;
		}
		kpreempt_enable();
		sfmmu_hat_exit(hatlockp);

		sfmmu_xcall_save += (pgunload-1);
	}
	dmrp->dmr_bitvec = 0;
}

/*
 * In cases where we need to synchronize with TLB/TSB miss trap
 * handlers, _and_ need to flush the TLB, it's a lot easier to
 * throw away the context from the process than to do a
 * special song and dance to keep things consistent for the
 * handlers.
 *
 * Since the process suddenly ends up without a context and our caller
 * holds the hat lock, threads that fault after this function is called
 * will pile up on the lock.  We can then do whatever we need to
 * atomically from the context of the caller.  The first blocked thread
 * to resume executing will get the process a new context, and the
 * process will resume executing.
 *
 * One added advantage of this approach is that on MMUs that
 * support a "flush all" operation, we will delay the flush until
 * cnum wrap-around, and then flush the TLB one time.  This
 * is rather rare, so it's a lot less expensive than making 8000
 * x-calls to flush the TLB 8000 times.
 *
 * A per-process (PP) lock is used to synchronize ctx allocations in
 * resume() and ctx invalidations here.
 */
static void
sfmmu_invalidate_ctx(sfmmu_t *sfmmup)
{
	cpuset_t cpuset;
	int cnum, currcnum;
	mmu_ctx_t *mmu_ctxp;
	int i;
	uint_t pstate_save;

	SFMMU_STAT(sf_ctx_inv);

	ASSERT(sfmmu_hat_lock_held(sfmmup));
	ASSERT(sfmmup != ksfmmup);

	kpreempt_disable();

	mmu_ctxp = CPU_MMU_CTXP(CPU);
	ASSERT(mmu_ctxp);
	ASSERT(mmu_ctxp->mmu_idx < max_mmu_ctxdoms);
	ASSERT(mmu_ctxp == mmu_ctxs_tbl[mmu_ctxp->mmu_idx]);

	currcnum = sfmmup->sfmmu_ctxs[mmu_ctxp->mmu_idx].cnum;

	pstate_save = sfmmu_disable_intrs();

	lock_set(&sfmmup->sfmmu_ctx_lock);	/* acquire PP lock */
	/* set HAT cnum invalid across all context domains. */
	for (i = 0; i < max_mmu_ctxdoms; i++) {

		cnum = 	sfmmup->sfmmu_ctxs[i].cnum;
		if (cnum == INVALID_CONTEXT) {
			continue;
		}

		sfmmup->sfmmu_ctxs[i].cnum = INVALID_CONTEXT;
	}
	membar_enter();	/* make sure globally visible to all CPUs */
	lock_clear(&sfmmup->sfmmu_ctx_lock);	/* release PP lock */

	sfmmu_enable_intrs(pstate_save);

	cpuset = sfmmup->sfmmu_cpusran;
	CPUSET_DEL(cpuset, CPU->cpu_id);
	CPUSET_AND(cpuset, cpu_ready_set);
	if (!CPUSET_ISNULL(cpuset)) {
		SFMMU_XCALL_STATS(sfmmup);
		xt_some(cpuset, sfmmu_raise_tsb_exception,
		    (uint64_t)sfmmup, INVALID_CONTEXT);
		xt_sync(cpuset);
		SFMMU_STAT(sf_tsb_raise_exception);
		SFMMU_MMU_STAT(mmu_tsb_raise_exception);
	}

	/*
	 * If the hat to-be-invalidated is the same as the current
	 * process on local CPU we need to invalidate
	 * this CPU context as well.
	 */
	if ((sfmmu_getctx_sec() == currcnum) &&
	    (currcnum != INVALID_CONTEXT)) {
		/* sets shared context to INVALID too */
		sfmmu_setctx_sec(INVALID_CONTEXT);
		sfmmu_clear_utsbinfo();
	}

	SFMMU_FLAGS_SET(sfmmup, HAT_ALLCTX_INVALID);

	kpreempt_enable();

	/*
	 * we hold the hat lock, so nobody should allocate a context
	 * for us yet
	 */
	ASSERT(sfmmup->sfmmu_ctxs[mmu_ctxp->mmu_idx].cnum == INVALID_CONTEXT);
}

#ifdef VAC
/*
 * We need to flush the cache in all cpus.  It is possible that
 * a process referenced a page as cacheable but has sinced exited
 * and cleared the mapping list.  We still to flush it but have no
 * state so all cpus is the only alternative.
 */
void
sfmmu_cache_flush(pfn_t pfnum, int vcolor)
{
	cpuset_t cpuset;

	kpreempt_disable();
	cpuset = cpu_ready_set;
	CPUSET_DEL(cpuset, CPU->cpu_id);
	SFMMU_XCALL_STATS(NULL);	/* account to any ctx */
	xt_some(cpuset, vac_flushpage_tl1, pfnum, vcolor);
	xt_sync(cpuset);
	vac_flushpage(pfnum, vcolor);
	kpreempt_enable();
}

void
sfmmu_cache_flushcolor(int vcolor, pfn_t pfnum)
{
	cpuset_t cpuset;

	ASSERT(vcolor >= 0);

	kpreempt_disable();
	cpuset = cpu_ready_set;
	CPUSET_DEL(cpuset, CPU->cpu_id);
	SFMMU_XCALL_STATS(NULL);	/* account to any ctx */
	xt_some(cpuset, vac_flushcolor_tl1, vcolor, pfnum);
	xt_sync(cpuset);
	vac_flushcolor(vcolor, pfnum);
	kpreempt_enable();
}
#endif	/* VAC */

/*
 * We need to prevent processes from accessing the TSB using a cached physical
 * address.  It's alright if they try to access the TSB via virtual address
 * since they will just fault on that virtual address once the mapping has
 * been suspended.
 */
#pragma weak sendmondo_in_recover

/* ARGSUSED */
static int
sfmmu_tsb_pre_relocator(caddr_t va, uint_t tsbsz, uint_t flags, void *tsbinfo)
{
	struct tsb_info *tsbinfop = (struct tsb_info *)tsbinfo;
	sfmmu_t *sfmmup = tsbinfop->tsb_sfmmu;
	hatlock_t *hatlockp;
	sf_scd_t *scdp;

	if (flags != HAT_PRESUSPEND)
		return (0);

	/*
	 * If tsb is a shared TSB with TSB_SHAREDCTX set, sfmmup must
	 * be a shared hat, then set SCD's tsbinfo's flag.
	 * If tsb is not shared, sfmmup is a private hat, then set
	 * its private tsbinfo's flag.
	 */
	hatlockp = sfmmu_hat_enter(sfmmup);
	tsbinfop->tsb_flags |= TSB_RELOC_FLAG;

	if (!(tsbinfop->tsb_flags & TSB_SHAREDCTX)) {
		sfmmu_tsb_inv_ctx(sfmmup);
		sfmmu_hat_exit(hatlockp);
	} else {
		/* release lock on the shared hat */
		sfmmu_hat_exit(hatlockp);
		/* sfmmup is a shared hat */
		ASSERT(sfmmup->sfmmu_scdhat);
		scdp = sfmmup->sfmmu_scdp;
		ASSERT(scdp != NULL);
		/* get private hat from the scd list */
		mutex_enter(&scdp->scd_mutex);
		sfmmup = scdp->scd_sf_list;
		while (sfmmup != NULL) {
			hatlockp = sfmmu_hat_enter(sfmmup);
			/*
			 * We do not call sfmmu_tsb_inv_ctx here because
			 * sendmondo_in_recover check is only needed for
			 * sun4u.
			 */
			sfmmu_invalidate_ctx(sfmmup);
			sfmmu_hat_exit(hatlockp);
			sfmmup = sfmmup->sfmmu_scd_link.next;

		}
		mutex_exit(&scdp->scd_mutex);
	}
	return (0);
}

static void
sfmmu_tsb_inv_ctx(sfmmu_t *sfmmup)
{
	extern uint32_t sendmondo_in_recover;

	ASSERT(sfmmu_hat_lock_held(sfmmup));

	/*
	 * For Cheetah+ Erratum 25:
	 * Wait for any active recovery to finish.  We can't risk
	 * relocating the TSB of the thread running mondo_recover_proc()
	 * since, if we did that, we would deadlock.  The scenario we are
	 * trying to avoid is as follows:
	 *
	 * THIS CPU			RECOVER CPU
	 * --------			-----------
	 *				Begins recovery, walking through TSB
	 * hat_pagesuspend() TSB TTE
	 *				TLB miss on TSB TTE, spins at TL1
	 * xt_sync()
	 *	send_mondo_timeout()
	 *	mondo_recover_proc()
	 *	((deadlocked))
	 *
	 * The second half of the workaround is that mondo_recover_proc()
	 * checks to see if the tsb_info has the RELOC flag set, and if it
	 * does, it skips over that TSB without ever touching tsbinfop->tsb_va
	 * and hence avoiding the TLB miss that could result in a deadlock.
	 */
	if (&sendmondo_in_recover) {
		membar_enter();	/* make sure RELOC flag visible */
		while (sendmondo_in_recover) {
			drv_usecwait(1);
			membar_consumer();
		}
	}

	sfmmu_invalidate_ctx(sfmmup);
}

/* ARGSUSED */
static int
sfmmu_tsb_post_relocator(caddr_t va, uint_t tsbsz, uint_t flags,
	void *tsbinfo, pfn_t newpfn)
{
	hatlock_t *hatlockp;
	struct tsb_info *tsbinfop = (struct tsb_info *)tsbinfo;
	sfmmu_t	*sfmmup = tsbinfop->tsb_sfmmu;

	if (flags != HAT_POSTUNSUSPEND)
		return (0);

	hatlockp = sfmmu_hat_enter(sfmmup);

	SFMMU_STAT(sf_tsb_reloc);

	/*
	 * The process may have swapped out while we were relocating one
	 * of its TSBs.  If so, don't bother doing the setup since the
	 * process can't be using the memory anymore.
	 */
	if ((tsbinfop->tsb_flags & TSB_SWAPPED) == 0) {
		ASSERT(va == tsbinfop->tsb_va);
		sfmmu_tsbinfo_setup_phys(tsbinfop, newpfn);

		if (tsbinfop->tsb_flags & TSB_FLUSH_NEEDED) {
			sfmmu_inv_tsb(tsbinfop->tsb_va,
			    TSB_BYTES(tsbinfop->tsb_szc));
			tsbinfop->tsb_flags &= ~TSB_FLUSH_NEEDED;
		}
	}

	membar_exit();
	tsbinfop->tsb_flags &= ~TSB_RELOC_FLAG;
	cv_broadcast(&sfmmup->sfmmu_tsb_cv);

	sfmmu_hat_exit(hatlockp);

	return (0);
}

/*
 * Allocate and initialize a tsb_info structure.  Note that we may or may not
 * allocate a TSB here, depending on the flags passed in.
 */
static int
sfmmu_tsbinfo_alloc(struct tsb_info **tsbinfopp, int tsb_szc, int tte_sz_mask,
	uint_t flags, sfmmu_t *sfmmup)
{
	int err;

	*tsbinfopp = (struct tsb_info *)kmem_cache_alloc(
	    sfmmu_tsbinfo_cache, KM_SLEEP);

	if ((err = sfmmu_init_tsbinfo(*tsbinfopp, tte_sz_mask,
	    tsb_szc, flags, sfmmup)) != 0) {
		kmem_cache_free(sfmmu_tsbinfo_cache, *tsbinfopp);
		SFMMU_STAT(sf_tsb_allocfail);
		*tsbinfopp = NULL;
		return (err);
	}
	SFMMU_STAT(sf_tsb_alloc);

	/*
	 * Bump the TSB size counters for this TSB size.
	 */
	(*(((int *)&sfmmu_tsbsize_stat) + tsb_szc))++;
	return (0);
}

static void
sfmmu_tsb_free(struct tsb_info *tsbinfo)
{
	caddr_t tsbva = tsbinfo->tsb_va;
	uint_t tsb_size = TSB_BYTES(tsbinfo->tsb_szc);
	struct kmem_cache *kmem_cachep = tsbinfo->tsb_cache;
	vmem_t	*vmp = tsbinfo->tsb_vmp;

	/*
	 * If we allocated this TSB from relocatable kernel memory, then we
	 * need to uninstall the callback handler.
	 */
	if (tsbinfo->tsb_cache != sfmmu_tsb8k_cache) {
		uintptr_t slab_mask;
		caddr_t slab_vaddr;
		page_t **ppl;
		int ret;

		ASSERT(tsb_size <= MMU_PAGESIZE4M || use_bigtsb_arena);
		if (tsb_size > MMU_PAGESIZE4M)
			slab_mask = ~((uintptr_t)bigtsb_slab_mask) << PAGESHIFT;
		else
			slab_mask = ~((uintptr_t)tsb_slab_mask) << PAGESHIFT;
		slab_vaddr = (caddr_t)((uintptr_t)tsbva & slab_mask);

		ret = as_pagelock(&kas, &ppl, slab_vaddr, PAGESIZE, S_WRITE);
		ASSERT(ret == 0);
		hat_delete_callback(tsbva, (uint_t)tsb_size, (void *)tsbinfo,
		    0, NULL);
		as_pageunlock(&kas, ppl, slab_vaddr, PAGESIZE, S_WRITE);
	}

	if (kmem_cachep != NULL) {
		kmem_cache_free(kmem_cachep, tsbva);
	} else {
		vmem_xfree(vmp, (void *)tsbva, tsb_size);
	}
	tsbinfo->tsb_va = (caddr_t)0xbad00bad;
	atomic_add_64(&tsb_alloc_bytes, -(int64_t)tsb_size);
}

static void
sfmmu_tsbinfo_free(struct tsb_info *tsbinfo)
{
	if ((tsbinfo->tsb_flags & TSB_SWAPPED) == 0) {
		sfmmu_tsb_free(tsbinfo);
	}
	kmem_cache_free(sfmmu_tsbinfo_cache, tsbinfo);

}

/*
 * Setup all the references to physical memory for this tsbinfo.
 * The underlying page(s) must be locked.
 */
static void
sfmmu_tsbinfo_setup_phys(struct tsb_info *tsbinfo, pfn_t pfn)
{
	ASSERT(pfn != PFN_INVALID);
	ASSERT(pfn == va_to_pfn(tsbinfo->tsb_va));

#ifndef sun4v
	if (tsbinfo->tsb_szc == 0) {
		sfmmu_memtte(&tsbinfo->tsb_tte, pfn,
		    PROT_WRITE|PROT_READ, TTE8K);
	} else {
		/*
		 * Round down PA and use a large mapping; the handlers will
		 * compute the TSB pointer at the correct offset into the
		 * big virtual page.  NOTE: this assumes all TSBs larger
		 * than 8K must come from physically contiguous slabs of
		 * size tsb_slab_size.
		 */
		sfmmu_memtte(&tsbinfo->tsb_tte, pfn & ~tsb_slab_mask,
		    PROT_WRITE|PROT_READ, tsb_slab_ttesz);
	}
	tsbinfo->tsb_pa = ptob(pfn);

	TTE_SET_LOCKED(&tsbinfo->tsb_tte); /* lock the tte into dtlb */
	TTE_SET_MOD(&tsbinfo->tsb_tte);    /* enable writes */

	ASSERT(TTE_IS_PRIVILEGED(&tsbinfo->tsb_tte));
	ASSERT(TTE_IS_LOCKED(&tsbinfo->tsb_tte));
#else /* sun4v */
	tsbinfo->tsb_pa = ptob(pfn);
#endif /* sun4v */
}


/*
 * Returns zero on success, ENOMEM if over the high water mark,
 * or EAGAIN if the caller needs to retry with a smaller TSB
 * size (or specify TSB_FORCEALLOC if the allocation can't fail).
 *
 * This call cannot fail to allocate a TSB if TSB_FORCEALLOC
 * is specified and the TSB requested is PAGESIZE, though it
 * may sleep waiting for memory if sufficient memory is not
 * available.
 */
static int
sfmmu_init_tsbinfo(struct tsb_info *tsbinfo, int tteszmask,
    int tsbcode, uint_t flags, sfmmu_t *sfmmup)
{
	caddr_t vaddr = NULL;
	caddr_t slab_vaddr;
	uintptr_t slab_mask;
	int tsbbytes = TSB_BYTES(tsbcode);
	int lowmem = 0;
	struct kmem_cache *kmem_cachep = NULL;
	vmem_t *vmp = NULL;
	lgrp_id_t lgrpid = LGRP_NONE;
	pfn_t pfn;
	uint_t cbflags = HAC_SLEEP;
	page_t **pplist;
	int ret;

	ASSERT(tsbbytes <= MMU_PAGESIZE4M || use_bigtsb_arena);
	if (tsbbytes > MMU_PAGESIZE4M)
		slab_mask = ~((uintptr_t)bigtsb_slab_mask) << PAGESHIFT;
	else
		slab_mask = ~((uintptr_t)tsb_slab_mask) << PAGESHIFT;

	if (flags & (TSB_FORCEALLOC | TSB_SWAPIN | TSB_GROW | TSB_SHRINK))
		flags |= TSB_ALLOC;

	ASSERT((flags & TSB_FORCEALLOC) == 0 || tsbcode == TSB_MIN_SZCODE);

	tsbinfo->tsb_sfmmu = sfmmup;

	/*
	 * If not allocating a TSB, set up the tsbinfo, set TSB_SWAPPED, and
	 * return.
	 */
	if ((flags & TSB_ALLOC) == 0) {
		tsbinfo->tsb_szc = tsbcode;
		tsbinfo->tsb_ttesz_mask = tteszmask;
		tsbinfo->tsb_va = (caddr_t)0xbadbadbeef;
		tsbinfo->tsb_pa = -1;
		tsbinfo->tsb_tte.ll = 0;
		tsbinfo->tsb_next = NULL;
		tsbinfo->tsb_flags = TSB_SWAPPED;
		tsbinfo->tsb_cache = NULL;
		tsbinfo->tsb_vmp = NULL;
		return (0);
	}

#ifdef DEBUG
	/*
	 * For debugging:
	 * Randomly force allocation failures every tsb_alloc_mtbf
	 * tries if TSB_FORCEALLOC is not specified.  This will
	 * return ENOMEM if tsb_alloc_mtbf is odd, or EAGAIN if
	 * it is even, to allow testing of both failure paths...
	 */
	if (tsb_alloc_mtbf && ((flags & TSB_FORCEALLOC) == 0) &&
	    (tsb_alloc_count++ == tsb_alloc_mtbf)) {
		tsb_alloc_count = 0;
		tsb_alloc_fail_mtbf++;
		return ((tsb_alloc_mtbf & 1)? ENOMEM : EAGAIN);
	}
#endif	/* DEBUG */

	/*
	 * Enforce high water mark if we are not doing a forced allocation
	 * and are not shrinking a process' TSB.
	 */
	if ((flags & TSB_SHRINK) == 0 &&
	    (tsbbytes + tsb_alloc_bytes) > tsb_alloc_hiwater) {
		if ((flags & TSB_FORCEALLOC) == 0)
			return (ENOMEM);
		lowmem = 1;
	}

	/*
	 * Allocate from the correct location based upon the size of the TSB
	 * compared to the base page size, and what memory conditions dictate.
	 * Note we always do nonblocking allocations from the TSB arena since
	 * we don't want memory fragmentation to cause processes to block
	 * indefinitely waiting for memory; until the kernel algorithms that
	 * coalesce large pages are improved this is our best option.
	 *
	 * Algorithm:
	 *	If allocating a "large" TSB (>8K), allocate from the
	 *		appropriate kmem_tsb_default_arena vmem arena
	 *	else if low on memory or the TSB_FORCEALLOC flag is set or
	 *	tsb_forceheap is set
	 *		Allocate from kernel heap via sfmmu_tsb8k_cache with
	 *		KM_SLEEP (never fails)
	 *	else
	 *		Allocate from appropriate sfmmu_tsb_cache with
	 *		KM_NOSLEEP
	 *	endif
	 */
	if (tsb_lgrp_affinity)
		lgrpid = lgrp_home_id(curthread);
	if (lgrpid == LGRP_NONE)
		lgrpid = 0;	/* use lgrp of boot CPU */

	if (tsbbytes > MMU_PAGESIZE) {
		if (tsbbytes > MMU_PAGESIZE4M) {
			vmp = kmem_bigtsb_default_arena[lgrpid];
			vaddr = (caddr_t)vmem_xalloc(vmp, tsbbytes, tsbbytes,
			    0, 0, NULL, NULL, VM_NOSLEEP);
		} else {
			vmp = kmem_tsb_default_arena[lgrpid];
			vaddr = (caddr_t)vmem_xalloc(vmp, tsbbytes, tsbbytes,
			    0, 0, NULL, NULL, VM_NOSLEEP);
		}
#ifdef	DEBUG
	} else if (lowmem || (flags & TSB_FORCEALLOC) || tsb_forceheap) {
#else	/* !DEBUG */
	} else if (lowmem || (flags & TSB_FORCEALLOC)) {
#endif	/* DEBUG */
		kmem_cachep = sfmmu_tsb8k_cache;
		vaddr = (caddr_t)kmem_cache_alloc(kmem_cachep, KM_SLEEP);
		ASSERT(vaddr != NULL);
	} else {
		kmem_cachep = sfmmu_tsb_cache[lgrpid];
		vaddr = (caddr_t)kmem_cache_alloc(kmem_cachep, KM_NOSLEEP);
	}

	tsbinfo->tsb_cache = kmem_cachep;
	tsbinfo->tsb_vmp = vmp;

	if (vaddr == NULL) {
		return (EAGAIN);
	}

	atomic_add_64(&tsb_alloc_bytes, (int64_t)tsbbytes);
	kmem_cachep = tsbinfo->tsb_cache;

	/*
	 * If we are allocating from outside the cage, then we need to
	 * register a relocation callback handler.  Note that for now
	 * since pseudo mappings always hang off of the slab's root page,
	 * we need only lock the first 8K of the TSB slab.  This is a bit
	 * hacky but it is good for performance.
	 */
	if (kmem_cachep != sfmmu_tsb8k_cache) {
		slab_vaddr = (caddr_t)((uintptr_t)vaddr & slab_mask);
		ret = as_pagelock(&kas, &pplist, slab_vaddr, PAGESIZE, S_WRITE);
		ASSERT(ret == 0);
		ret = hat_add_callback(sfmmu_tsb_cb_id, vaddr, (uint_t)tsbbytes,
		    cbflags, (void *)tsbinfo, &pfn, NULL);

		/*
		 * Need to free up resources if we could not successfully
		 * add the callback function and return an error condition.
		 */
		if (ret != 0) {
			if (kmem_cachep) {
				kmem_cache_free(kmem_cachep, vaddr);
			} else {
				vmem_xfree(vmp, (void *)vaddr, tsbbytes);
			}
			as_pageunlock(&kas, pplist, slab_vaddr, PAGESIZE,
			    S_WRITE);
			return (EAGAIN);
		}
	} else {
		/*
		 * Since allocation of 8K TSBs from heap is rare and occurs
		 * during memory pressure we allocate them from permanent
		 * memory rather than using callbacks to get the PFN.
		 */
		pfn = hat_getpfnum(kas.a_hat, vaddr);
	}

	tsbinfo->tsb_va = vaddr;
	tsbinfo->tsb_szc = tsbcode;
	tsbinfo->tsb_ttesz_mask = tteszmask;
	tsbinfo->tsb_next = NULL;
	tsbinfo->tsb_flags = 0;

	sfmmu_tsbinfo_setup_phys(tsbinfo, pfn);

	sfmmu_inv_tsb(vaddr, tsbbytes);

	if (kmem_cachep != sfmmu_tsb8k_cache) {
		as_pageunlock(&kas, pplist, slab_vaddr, PAGESIZE, S_WRITE);
	}

	return (0);
}

/*
 * Initialize per cpu tsb and per cpu tsbmiss_area
 */
void
sfmmu_init_tsbs(void)
{
	int i;
	struct tsbmiss	*tsbmissp;
	struct kpmtsbm	*kpmtsbmp;
#ifndef sun4v
	extern int	dcache_line_mask;
#endif /* sun4v */
	extern uint_t	vac_colors;

	/*
	 * Init. tsb miss area.
	 */
	tsbmissp = tsbmiss_area;

	for (i = 0; i < NCPU; tsbmissp++, i++) {
		/*
		 * initialize the tsbmiss area.
		 * Do this for all possible CPUs as some may be added
		 * while the system is running. There is no cost to this.
		 */
		tsbmissp->ksfmmup = ksfmmup;
#ifndef sun4v
		tsbmissp->dcache_line_mask = (uint16_t)dcache_line_mask;
#endif /* sun4v */
		tsbmissp->khashstart =
		    (struct hmehash_bucket *)va_to_pa((caddr_t)khme_hash);
		tsbmissp->uhashstart =
		    (struct hmehash_bucket *)va_to_pa((caddr_t)uhme_hash);
		tsbmissp->khashsz = khmehash_num;
		tsbmissp->uhashsz = uhmehash_num;
	}

	sfmmu_tsb_cb_id = hat_register_callback('T'<<16 | 'S' << 8 | 'B',
	    sfmmu_tsb_pre_relocator, sfmmu_tsb_post_relocator, NULL, 0);

	if (kpm_enable == 0)
		return;

	/* -- Begin KPM specific init -- */

	if (kpm_smallpages) {
		/*
		 * If we're using base pagesize pages for seg_kpm
		 * mappings, we use the kernel TSB since we can't afford
		 * to allocate a second huge TSB for these mappings.
		 */
		kpm_tsbbase = ktsb_phys? ktsb_pbase : (uint64_t)ktsb_base;
		kpm_tsbsz = ktsb_szcode;
		kpmsm_tsbbase = kpm_tsbbase;
		kpmsm_tsbsz = kpm_tsbsz;
	} else {
		/*
		 * In VAC conflict case, just put the entries in the
		 * kernel 8K indexed TSB for now so we can find them.
		 * This could really be changed in the future if we feel
		 * the need...
		 */
		kpmsm_tsbbase = ktsb_phys? ktsb_pbase : (uint64_t)ktsb_base;
		kpmsm_tsbsz = ktsb_szcode;
		kpm_tsbbase = ktsb_phys? ktsb4m_pbase : (uint64_t)ktsb4m_base;
		kpm_tsbsz = ktsb4m_szcode;
	}

	kpmtsbmp = kpmtsbm_area;
	for (i = 0; i < NCPU; kpmtsbmp++, i++) {
		/*
		 * Initialize the kpmtsbm area.
		 * Do this for all possible CPUs as some may be added
		 * while the system is running. There is no cost to this.
		 */
		kpmtsbmp->vbase = kpm_vbase;
		kpmtsbmp->vend = kpm_vbase + kpm_size * vac_colors;
		kpmtsbmp->sz_shift = kpm_size_shift;
		kpmtsbmp->kpmp_shift = kpmp_shift;
		kpmtsbmp->kpmp2pshft = (uchar_t)kpmp2pshft;
		if (kpm_smallpages == 0) {
			kpmtsbmp->kpmp_table_sz = kpmp_table_sz;
			kpmtsbmp->kpmp_tablepa = va_to_pa(kpmp_table);
		} else {
			kpmtsbmp->kpmp_table_sz = kpmp_stable_sz;
			kpmtsbmp->kpmp_tablepa = va_to_pa(kpmp_stable);
		}
		kpmtsbmp->msegphashpa = va_to_pa(memseg_phash);
		kpmtsbmp->flags = KPMTSBM_ENABLE_FLAG;
#ifdef	DEBUG
		kpmtsbmp->flags |= (kpm_tsbmtl) ?  KPMTSBM_TLTSBM_FLAG : 0;
#endif	/* DEBUG */
		if (ktsb_phys)
			kpmtsbmp->flags |= KPMTSBM_TSBPHYS_FLAG;
	}

	/* -- End KPM specific init -- */
}

/* Avoid using sfmmu_tsbinfo_alloc() to avoid kmem_alloc - no real reason */
struct tsb_info ktsb_info[2];

/*
 * Called from hat_kern_setup() to setup the tsb_info for ksfmmup.
 */
void
sfmmu_init_ktsbinfo()
{
	ASSERT(ksfmmup != NULL);
	ASSERT(ksfmmup->sfmmu_tsb == NULL);
	/*
	 * Allocate tsbinfos for kernel and copy in data
	 * to make debug easier and sun4v setup easier.
	 */
	ktsb_info[0].tsb_sfmmu = ksfmmup;
	ktsb_info[0].tsb_szc = ktsb_szcode;
	ktsb_info[0].tsb_ttesz_mask = TSB8K|TSB64K|TSB512K;
	ktsb_info[0].tsb_va = ktsb_base;
	ktsb_info[0].tsb_pa = ktsb_pbase;
	ktsb_info[0].tsb_flags = 0;
	ktsb_info[0].tsb_tte.ll = 0;
	ktsb_info[0].tsb_cache = NULL;

	ktsb_info[1].tsb_sfmmu = ksfmmup;
	ktsb_info[1].tsb_szc = ktsb4m_szcode;
	ktsb_info[1].tsb_ttesz_mask = TSB4M;
	ktsb_info[1].tsb_va = ktsb4m_base;
	ktsb_info[1].tsb_pa = ktsb4m_pbase;
	ktsb_info[1].tsb_flags = 0;
	ktsb_info[1].tsb_tte.ll = 0;
	ktsb_info[1].tsb_cache = NULL;

	/* Link them into ksfmmup. */
	ktsb_info[0].tsb_next = &ktsb_info[1];
	ktsb_info[1].tsb_next = NULL;
	ksfmmup->sfmmu_tsb = &ktsb_info[0];

	sfmmu_setup_tsbinfo(ksfmmup);
}

/*
 * Cache the last value returned from va_to_pa().  If the VA specified
 * in the current call to cached_va_to_pa() maps to the same Page (as the
 * previous call to cached_va_to_pa()), then compute the PA using
 * cached info, else call va_to_pa().
 *
 * Note: this function is neither MT-safe nor consistent in the presence
 * of multiple, interleaved threads.  This function was created to enable
 * an optimization used during boot (at a point when there's only one thread
 * executing on the "boot CPU", and before startup_vm() has been called).
 */
static uint64_t
cached_va_to_pa(void *vaddr)
{
	static uint64_t prev_vaddr_base = 0;
	static uint64_t prev_pfn = 0;

	if ((((uint64_t)vaddr) & MMU_PAGEMASK) == prev_vaddr_base) {
		return (prev_pfn | ((uint64_t)vaddr & MMU_PAGEOFFSET));
	} else {
		uint64_t pa = va_to_pa(vaddr);

		if (pa != ((uint64_t)-1)) {
			/*
			 * Computed physical address is valid.  Cache its
			 * related info for the next cached_va_to_pa() call.
			 */
			prev_pfn = pa & MMU_PAGEMASK;
			prev_vaddr_base = ((uint64_t)vaddr) & MMU_PAGEMASK;
		}

		return (pa);
	}
}

/*
 * Carve up our nucleus hblk region.  We may allocate more hblks than
 * asked due to rounding errors but we are guaranteed to have at least
 * enough space to allocate the requested number of hblk8's and hblk1's.
 */
void
sfmmu_init_nucleus_hblks(caddr_t addr, size_t size, int nhblk8, int nhblk1)
{
	struct hme_blk *hmeblkp;
	size_t hme8blk_sz, hme1blk_sz;
	size_t i;
	size_t hblk8_bound;
	ulong_t j = 0, k = 0;

	ASSERT(addr != NULL && size != 0);

	/* Need to use proper structure alignment */
	hme8blk_sz = roundup(HME8BLK_SZ, sizeof (int64_t));
	hme1blk_sz = roundup(HME1BLK_SZ, sizeof (int64_t));

	nucleus_hblk8.list = (void *)addr;
	nucleus_hblk8.index = 0;

	/*
	 * Use as much memory as possible for hblk8's since we
	 * expect all bop_alloc'ed memory to be allocated in 8k chunks.
	 * We need to hold back enough space for the hblk1's which
	 * we'll allocate next.
	 */
	hblk8_bound = size - (nhblk1 * hme1blk_sz) - hme8blk_sz;
	for (i = 0; i <= hblk8_bound; i += hme8blk_sz, j++) {
		hmeblkp = (struct hme_blk *)addr;
		addr += hme8blk_sz;
		hmeblkp->hblk_nuc_bit = 1;
		hmeblkp->hblk_nextpa = cached_va_to_pa((caddr_t)hmeblkp);
	}
	nucleus_hblk8.len = j;
	ASSERT(j >= nhblk8);
	SFMMU_STAT_ADD(sf_hblk8_ncreate, j);

	nucleus_hblk1.list = (void *)addr;
	nucleus_hblk1.index = 0;
	for (; i <= (size - hme1blk_sz); i += hme1blk_sz, k++) {
		hmeblkp = (struct hme_blk *)addr;
		addr += hme1blk_sz;
		hmeblkp->hblk_nuc_bit = 1;
		hmeblkp->hblk_nextpa = cached_va_to_pa((caddr_t)hmeblkp);
	}
	ASSERT(k >= nhblk1);
	nucleus_hblk1.len = k;
	SFMMU_STAT_ADD(sf_hblk1_ncreate, k);
}

/*
 * This function is currently not supported on this platform. For what
 * it's supposed to do, see hat.c and hat_srmmu.c
 */
/* ARGSUSED */
faultcode_t
hat_softlock(struct hat *hat, caddr_t addr, size_t *lenp, page_t **ppp,
    uint_t flags)
{
	return (FC_NOSUPPORT);
}

/*
 * Searchs the mapping list of the page for a mapping of the same size. If not
 * found the corresponding bit is cleared in the p_index field. When large
 * pages are more prevalent in the system, we can maintain the mapping list
 * in order and we don't have to traverse the list each time. Just check the
 * next and prev entries, and if both are of different size, we clear the bit.
 */
static void
sfmmu_rm_large_mappings(page_t *pp, int ttesz)
{
	struct sf_hment *sfhmep;
	struct hme_blk *hmeblkp;
	int	index;
	pgcnt_t	npgs;

	ASSERT(ttesz > TTE8K);

	ASSERT(sfmmu_mlist_held(pp));

	ASSERT(PP_ISMAPPED_LARGE(pp));

	/*
	 * Traverse mapping list looking for another mapping of same size.
	 * since we only want to clear index field if all mappings of
	 * that size are gone.
	 */

	for (sfhmep = pp->p_mapping; sfhmep; sfhmep = sfhmep->hme_next) {
		if (IS_PAHME(sfhmep))
			continue;
		hmeblkp = sfmmu_hmetohblk(sfhmep);
		if (hme_size(sfhmep) == ttesz) {
			/*
			 * another mapping of the same size. don't clear index.
			 */
			return;
		}
	}

	/*
	 * Clear the p_index bit for large page.
	 */
	index = PAGESZ_TO_INDEX(ttesz);
	npgs = TTEPAGES(ttesz);
	while (npgs-- > 0) {
		ASSERT(pp->p_index & index);
		pp->p_index &= ~index;
		pp = PP_PAGENEXT(pp);
	}
}

/*
 * return supported features
 */
/* ARGSUSED */
int
hat_supported(enum hat_features feature, void *arg)
{
	switch (feature) {
	case    HAT_SHARED_PT:
	case	HAT_DYNAMIC_ISM_UNMAP:
	case	HAT_VMODSORT:
		return (1);
	case	HAT_SHARED_REGIONS:
		if (shctx_on)
			return (1);
		else
			return (0);
	default:
		return (0);
	}
}

void
hat_enter(struct hat *hat)
{
	hatlock_t	*hatlockp;

	if (hat != ksfmmup) {
		hatlockp = TSB_HASH(hat);
		mutex_enter(HATLOCK_MUTEXP(hatlockp));
	}
}

void
hat_exit(struct hat *hat)
{
	hatlock_t	*hatlockp;

	if (hat != ksfmmup) {
		hatlockp = TSB_HASH(hat);
		mutex_exit(HATLOCK_MUTEXP(hatlockp));
	}
}

/*ARGSUSED*/
void
hat_reserve(struct as *as, caddr_t addr, size_t len)
{
}

static void
hat_kstat_init(void)
{
	kstat_t *ksp;

	ksp = kstat_create("unix", 0, "sfmmu_global_stat", "hat",
	    KSTAT_TYPE_RAW, sizeof (struct sfmmu_global_stat),
	    KSTAT_FLAG_VIRTUAL);
	if (ksp) {
		ksp->ks_data = (void *) &sfmmu_global_stat;
		kstat_install(ksp);
	}
	ksp = kstat_create("unix", 0, "sfmmu_tsbsize_stat", "hat",
	    KSTAT_TYPE_RAW, sizeof (struct sfmmu_tsbsize_stat),
	    KSTAT_FLAG_VIRTUAL);
	if (ksp) {
		ksp->ks_data = (void *) &sfmmu_tsbsize_stat;
		kstat_install(ksp);
	}
	ksp = kstat_create("unix", 0, "sfmmu_percpu_stat", "hat",
	    KSTAT_TYPE_RAW, sizeof (struct sfmmu_percpu_stat) * NCPU,
	    KSTAT_FLAG_WRITABLE);
	if (ksp) {
		ksp->ks_update = sfmmu_kstat_percpu_update;
		kstat_install(ksp);
	}
}

/* ARGSUSED */
static int
sfmmu_kstat_percpu_update(kstat_t *ksp, int rw)
{
	struct sfmmu_percpu_stat *cpu_kstat = ksp->ks_data;
	struct tsbmiss *tsbm = tsbmiss_area;
	struct kpmtsbm *kpmtsbm = kpmtsbm_area;
	int i;

	ASSERT(cpu_kstat);
	if (rw == KSTAT_READ) {
		for (i = 0; i < NCPU; cpu_kstat++, tsbm++, kpmtsbm++, i++) {
			cpu_kstat->sf_itlb_misses = 0;
			cpu_kstat->sf_dtlb_misses = 0;
			cpu_kstat->sf_utsb_misses = tsbm->utsb_misses -
			    tsbm->uprot_traps;
			cpu_kstat->sf_ktsb_misses = tsbm->ktsb_misses +
			    kpmtsbm->kpm_tsb_misses - tsbm->kprot_traps;
			cpu_kstat->sf_tsb_hits = 0;
			cpu_kstat->sf_umod_faults = tsbm->uprot_traps;
			cpu_kstat->sf_kmod_faults = tsbm->kprot_traps;
		}
	} else {
		/* KSTAT_WRITE is used to clear stats */
		for (i = 0; i < NCPU; tsbm++, kpmtsbm++, i++) {
			tsbm->utsb_misses = 0;
			tsbm->ktsb_misses = 0;
			tsbm->uprot_traps = 0;
			tsbm->kprot_traps = 0;
			kpmtsbm->kpm_dtlb_misses = 0;
			kpmtsbm->kpm_tsb_misses = 0;
		}
	}
	return (0);
}

#ifdef	DEBUG

tte_t  *gorig[NCPU], *gcur[NCPU], *gnew[NCPU];

/*
 * A tte checker. *orig_old is the value we read before cas.
 *	*cur is the value returned by cas.
 *	*new is the desired value when we do the cas.
 *
 *	*hmeblkp is currently unused.
 */

/* ARGSUSED */
void
chk_tte(tte_t *orig_old, tte_t *cur, tte_t *new, struct hme_blk *hmeblkp)
{
	pfn_t i, j, k;
	int cpuid = CPU->cpu_id;

	gorig[cpuid] = orig_old;
	gcur[cpuid] = cur;
	gnew[cpuid] = new;

#ifdef lint
	hmeblkp = hmeblkp;
#endif

	if (TTE_IS_VALID(orig_old)) {
		if (TTE_IS_VALID(cur)) {
			i = TTE_TO_TTEPFN(orig_old);
			j = TTE_TO_TTEPFN(cur);
			k = TTE_TO_TTEPFN(new);
			if (i != j) {
				/* remap error? */
				panic("chk_tte: bad pfn, 0x%lx, 0x%lx", i, j);
			}

			if (i != k) {
				/* remap error? */
				panic("chk_tte: bad pfn2, 0x%lx, 0x%lx", i, k);
			}
		} else {
			if (TTE_IS_VALID(new)) {
				panic("chk_tte: invalid cur? ");
			}

			i = TTE_TO_TTEPFN(orig_old);
			k = TTE_TO_TTEPFN(new);
			if (i != k) {
				panic("chk_tte: bad pfn3, 0x%lx, 0x%lx", i, k);
			}
		}
	} else {
		if (TTE_IS_VALID(cur)) {
			j = TTE_TO_TTEPFN(cur);
			if (TTE_IS_VALID(new)) {
				k = TTE_TO_TTEPFN(new);
				if (j != k) {
					panic("chk_tte: bad pfn4, 0x%lx, 0x%lx",
					    j, k);
				}
			} else {
				panic("chk_tte: why here?");
			}
		} else {
			if (!TTE_IS_VALID(new)) {
				panic("chk_tte: why here2 ?");
			}
		}
	}
}

#endif /* DEBUG */

extern void prefetch_tsbe_read(struct tsbe *);
extern void prefetch_tsbe_write(struct tsbe *);


/*
 * We want to prefetch 7 cache lines ahead for our read prefetch.  This gives
 * us optimal performance on Cheetah+.  You can only have 8 outstanding
 * prefetches at any one time, so we opted for 7 read prefetches and 1 write
 * prefetch to make the most utilization of the prefetch capability.
 */
#define	TSBE_PREFETCH_STRIDE (7)

void
sfmmu_copy_tsb(struct tsb_info *old_tsbinfo, struct tsb_info *new_tsbinfo)
{
	int old_bytes = TSB_BYTES(old_tsbinfo->tsb_szc);
	int new_bytes = TSB_BYTES(new_tsbinfo->tsb_szc);
	int old_entries = TSB_ENTRIES(old_tsbinfo->tsb_szc);
	int new_entries = TSB_ENTRIES(new_tsbinfo->tsb_szc);
	struct tsbe *old;
	struct tsbe *new;
	struct tsbe *new_base = (struct tsbe *)new_tsbinfo->tsb_va;
	uint64_t va;
	int new_offset;
	int i;
	int vpshift;
	int last_prefetch;

	if (old_bytes == new_bytes) {
		bcopy(old_tsbinfo->tsb_va, new_tsbinfo->tsb_va, new_bytes);
	} else {

		/*
		 * A TSBE is 16 bytes which means there are four TSBE's per
		 * P$ line (64 bytes), thus every 4 TSBE's we prefetch.
		 */
		old = (struct tsbe *)old_tsbinfo->tsb_va;
		last_prefetch = old_entries - (4*(TSBE_PREFETCH_STRIDE+1));
		for (i = 0; i < old_entries; i++, old++) {
			if (((i & (4-1)) == 0) && (i < last_prefetch))
				prefetch_tsbe_read(old);
			if (!old->tte_tag.tag_invalid) {
				/*
				 * We have a valid TTE to remap.  Check the
				 * size.  We won't remap 64K or 512K TTEs
				 * because they span more than one TSB entry
				 * and are indexed using an 8K virt. page.
				 * Ditto for 32M and 256M TTEs.
				 */
				if (TTE_CSZ(&old->tte_data) == TTE64K ||
				    TTE_CSZ(&old->tte_data) == TTE512K)
					continue;
				if (mmu_page_sizes == max_mmu_page_sizes) {
					if (TTE_CSZ(&old->tte_data) == TTE32M ||
					    TTE_CSZ(&old->tte_data) == TTE256M)
						continue;
				}

				/* clear the lower 22 bits of the va */
				va = *(uint64_t *)old << 22;
				/* turn va into a virtual pfn */
				va >>= 22 - TSB_START_SIZE;
				/*
				 * or in bits from the offset in the tsb
				 * to get the real virtual pfn. These
				 * correspond to bits [21:13] in the va
				 */
				vpshift =
				    TTE_BSZS_SHIFT(TTE_CSZ(&old->tte_data)) &
				    0x1ff;
				va |= (i << vpshift);
				va >>= vpshift;
				new_offset = va & (new_entries - 1);
				new = new_base + new_offset;
				prefetch_tsbe_write(new);
				*new = *old;
			}
		}
	}
}

/*
 * unused in sfmmu
 */
void
hat_dump(void)
{
}

/*
 * Called when a thread is exiting and we have switched to the kernel address
 * space.  Perform the same VM initialization resume() uses when switching
 * processes.
 *
 * Note that sfmmu_load_mmustate() is currently a no-op for kernel threads, but
 * we call it anyway in case the semantics change in the future.
 */
/*ARGSUSED*/
void
hat_thread_exit(kthread_t *thd)
{
	uint_t pgsz_cnum;
	uint_t pstate_save;

	ASSERT(thd->t_procp->p_as == &kas);

	pgsz_cnum = KCONTEXT;
#ifdef sun4u
	pgsz_cnum |= (ksfmmup->sfmmu_cext << CTXREG_EXT_SHIFT);
#endif

	/*
	 * Note that sfmmu_load_mmustate() is currently a no-op for
	 * kernel threads. We need to disable interrupts here,
	 * simply because otherwise sfmmu_load_mmustate() would panic
	 * if the caller does not disable interrupts.
	 */
	pstate_save = sfmmu_disable_intrs();

	/* Compatibility Note: hw takes care of MMU_SCONTEXT1 */
	sfmmu_setctx_sec(pgsz_cnum);
	sfmmu_load_mmustate(ksfmmup);
	sfmmu_enable_intrs(pstate_save);
}


/*
 * SRD support
 */
#define	SRD_HASH_FUNCTION(vp)	(((((uintptr_t)(vp)) >> 4) ^ \
				    (((uintptr_t)(vp)) >> 11)) & \
				    srd_hashmask)

/*
 * Attach the process to the srd struct associated with the exec vnode
 * from which the process is started.
 */
void
hat_join_srd(struct hat *sfmmup, vnode_t *evp)
{
	uint_t hash = SRD_HASH_FUNCTION(evp);
	sf_srd_t *srdp;
	sf_srd_t *newsrdp;

	ASSERT(sfmmup != ksfmmup);
	ASSERT(sfmmup->sfmmu_srdp == NULL);

	if (!shctx_on) {
		return;
	}

	VN_HOLD(evp);

	if (srd_buckets[hash].srdb_srdp != NULL) {
		mutex_enter(&srd_buckets[hash].srdb_lock);
		for (srdp = srd_buckets[hash].srdb_srdp; srdp != NULL;
		    srdp = srdp->srd_hash) {
			if (srdp->srd_evp == evp) {
				ASSERT(srdp->srd_refcnt >= 0);
				sfmmup->sfmmu_srdp = srdp;
				atomic_inc_32(
				    (volatile uint_t *)&srdp->srd_refcnt);
				mutex_exit(&srd_buckets[hash].srdb_lock);
				return;
			}
		}
		mutex_exit(&srd_buckets[hash].srdb_lock);
	}
	newsrdp = kmem_cache_alloc(srd_cache, KM_SLEEP);
	ASSERT(newsrdp->srd_next_ismrid == 0 && newsrdp->srd_next_hmerid == 0);

	newsrdp->srd_evp = evp;
	newsrdp->srd_refcnt = 1;
	newsrdp->srd_hmergnfree = NULL;
	newsrdp->srd_ismrgnfree = NULL;

	mutex_enter(&srd_buckets[hash].srdb_lock);
	for (srdp = srd_buckets[hash].srdb_srdp; srdp != NULL;
	    srdp = srdp->srd_hash) {
		if (srdp->srd_evp == evp) {
			ASSERT(srdp->srd_refcnt >= 0);
			sfmmup->sfmmu_srdp = srdp;
			atomic_inc_32((volatile uint_t *)&srdp->srd_refcnt);
			mutex_exit(&srd_buckets[hash].srdb_lock);
			kmem_cache_free(srd_cache, newsrdp);
			return;
		}
	}
	newsrdp->srd_hash = srd_buckets[hash].srdb_srdp;
	srd_buckets[hash].srdb_srdp = newsrdp;
	sfmmup->sfmmu_srdp = newsrdp;

	mutex_exit(&srd_buckets[hash].srdb_lock);

}

static void
sfmmu_leave_srd(sfmmu_t *sfmmup)
{
	vnode_t *evp;
	sf_srd_t *srdp = sfmmup->sfmmu_srdp;
	uint_t hash;
	sf_srd_t **prev_srdpp;
	sf_region_t *rgnp;
	sf_region_t *nrgnp;
#ifdef DEBUG
	int rgns = 0;
#endif
	int i;

	ASSERT(sfmmup != ksfmmup);
	ASSERT(srdp != NULL);
	ASSERT(srdp->srd_refcnt > 0);
	ASSERT(sfmmup->sfmmu_scdp == NULL);
	ASSERT(sfmmup->sfmmu_free == 1);

	sfmmup->sfmmu_srdp = NULL;
	evp = srdp->srd_evp;
	ASSERT(evp != NULL);
	if (atomic_dec_32_nv((volatile uint_t *)&srdp->srd_refcnt)) {
		VN_RELE(evp);
		return;
	}

	hash = SRD_HASH_FUNCTION(evp);
	mutex_enter(&srd_buckets[hash].srdb_lock);
	for (prev_srdpp = &srd_buckets[hash].srdb_srdp;
	    (srdp = *prev_srdpp) != NULL; prev_srdpp = &srdp->srd_hash) {
		if (srdp->srd_evp == evp) {
			break;
		}
	}
	if (srdp == NULL || srdp->srd_refcnt) {
		mutex_exit(&srd_buckets[hash].srdb_lock);
		VN_RELE(evp);
		return;
	}
	*prev_srdpp = srdp->srd_hash;
	mutex_exit(&srd_buckets[hash].srdb_lock);

	ASSERT(srdp->srd_refcnt == 0);
	VN_RELE(evp);

#ifdef DEBUG
	for (i = 0; i < SFMMU_MAX_REGION_BUCKETS; i++) {
		ASSERT(srdp->srd_rgnhash[i] == NULL);
	}
#endif /* DEBUG */

	/* free each hme regions in the srd */
	for (rgnp = srdp->srd_hmergnfree; rgnp != NULL; rgnp = nrgnp) {
		nrgnp = rgnp->rgn_next;
		ASSERT(rgnp->rgn_id < srdp->srd_next_hmerid);
		ASSERT(rgnp->rgn_refcnt == 0);
		ASSERT(rgnp->rgn_sfmmu_head == NULL);
		ASSERT(rgnp->rgn_flags & SFMMU_REGION_FREE);
		ASSERT(rgnp->rgn_hmeflags == 0);
		ASSERT(srdp->srd_hmergnp[rgnp->rgn_id] == rgnp);
#ifdef DEBUG
		for (i = 0; i < MMU_PAGE_SIZES; i++) {
			ASSERT(rgnp->rgn_ttecnt[i] == 0);
		}
		rgns++;
#endif /* DEBUG */
		kmem_cache_free(region_cache, rgnp);
	}
	ASSERT(rgns == srdp->srd_next_hmerid);

#ifdef DEBUG
	rgns = 0;
#endif
	/* free each ism rgns in the srd */
	for (rgnp = srdp->srd_ismrgnfree; rgnp != NULL; rgnp = nrgnp) {
		nrgnp = rgnp->rgn_next;
		ASSERT(rgnp->rgn_id < srdp->srd_next_ismrid);
		ASSERT(rgnp->rgn_refcnt == 0);
		ASSERT(rgnp->rgn_sfmmu_head == NULL);
		ASSERT(rgnp->rgn_flags & SFMMU_REGION_FREE);
		ASSERT(srdp->srd_ismrgnp[rgnp->rgn_id] == rgnp);
#ifdef DEBUG
		for (i = 0; i < MMU_PAGE_SIZES; i++) {
			ASSERT(rgnp->rgn_ttecnt[i] == 0);
		}
		rgns++;
#endif /* DEBUG */
		kmem_cache_free(region_cache, rgnp);
	}
	ASSERT(rgns == srdp->srd_next_ismrid);
	ASSERT(srdp->srd_ismbusyrgns == 0);
	ASSERT(srdp->srd_hmebusyrgns == 0);

	srdp->srd_next_ismrid = 0;
	srdp->srd_next_hmerid = 0;

	bzero((void *)srdp->srd_ismrgnp,
	    sizeof (sf_region_t *) * SFMMU_MAX_ISM_REGIONS);
	bzero((void *)srdp->srd_hmergnp,
	    sizeof (sf_region_t *) * SFMMU_MAX_HME_REGIONS);

	ASSERT(srdp->srd_scdp == NULL);
	kmem_cache_free(srd_cache, srdp);
}

/* ARGSUSED */
static int
sfmmu_srdcache_constructor(void *buf, void *cdrarg, int kmflags)
{
	sf_srd_t *srdp = (sf_srd_t *)buf;
	bzero(buf, sizeof (*srdp));

	mutex_init(&srdp->srd_mutex, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&srdp->srd_scd_mutex, NULL, MUTEX_DEFAULT, NULL);
	return (0);
}

/* ARGSUSED */
static void
sfmmu_srdcache_destructor(void *buf, void *cdrarg)
{
	sf_srd_t *srdp = (sf_srd_t *)buf;

	mutex_destroy(&srdp->srd_mutex);
	mutex_destroy(&srdp->srd_scd_mutex);
}

/*
 * The caller makes sure hat_join_region()/hat_leave_region() can't be called
 * at the same time for the same process and address range. This is ensured by
 * the fact that address space is locked as writer when a process joins the
 * regions. Therefore there's no need to hold an srd lock during the entire
 * execution of hat_join_region()/hat_leave_region().
 */

#define	RGN_HASH_FUNCTION(obj)	(((((uintptr_t)(obj)) >> 4) ^ \
				    (((uintptr_t)(obj)) >> 11)) & \
					srd_rgn_hashmask)
/*
 * This routine implements the shared context functionality required when
 * attaching a segment to an address space. It must be called from
 * hat_share() for D(ISM) segments and from segvn_create() for segments
 * with the MAP_PRIVATE and MAP_TEXT flags set. It returns a region_cookie
 * which is saved in the private segment data for hme segments and
 * the ism_map structure for ism segments.
 */
hat_region_cookie_t
hat_join_region(struct hat *sfmmup,
	caddr_t r_saddr,
	size_t r_size,
	void *r_obj,
	u_offset_t r_objoff,
	uchar_t r_perm,
	uchar_t r_pgszc,
	hat_rgn_cb_func_t r_cb_function,
	uint_t flags)
{
	sf_srd_t *srdp = sfmmup->sfmmu_srdp;
	uint_t rhash;
	uint_t rid;
	hatlock_t *hatlockp;
	sf_region_t *rgnp;
	sf_region_t *new_rgnp = NULL;
	int i;
	uint16_t *nextidp;
	sf_region_t **freelistp;
	int maxids;
	sf_region_t **rarrp;
	uint16_t *busyrgnsp;
	ulong_t rttecnt;
	uchar_t tteflag;
	uchar_t r_type = flags & HAT_REGION_TYPE_MASK;
	int text = (r_type == HAT_REGION_TEXT);

	if (srdp == NULL || r_size == 0) {
		return (HAT_INVALID_REGION_COOKIE);
	}

	ASSERT(sfmmup != ksfmmup);
	ASSERT(AS_WRITE_HELD(sfmmup->sfmmu_as));
	ASSERT(srdp->srd_refcnt > 0);
	ASSERT(!(flags & ~HAT_REGION_TYPE_MASK));
	ASSERT(flags == HAT_REGION_TEXT || flags == HAT_REGION_ISM);
	ASSERT(r_pgszc < mmu_page_sizes);
	if (!IS_P2ALIGNED(r_saddr, TTEBYTES(r_pgszc)) ||
	    !IS_P2ALIGNED(r_size, TTEBYTES(r_pgszc))) {
		panic("hat_join_region: region addr or size is not aligned\n");
	}


	r_type = (r_type == HAT_REGION_ISM) ? SFMMU_REGION_ISM :
	    SFMMU_REGION_HME;
	/*
	 * Currently only support shared hmes for the read only main text
	 * region.
	 */
	if (r_type == SFMMU_REGION_HME && ((r_obj != srdp->srd_evp) ||
	    (r_perm & PROT_WRITE))) {
		return (HAT_INVALID_REGION_COOKIE);
	}

	rhash = RGN_HASH_FUNCTION(r_obj);

	if (r_type == SFMMU_REGION_ISM) {
		nextidp = &srdp->srd_next_ismrid;
		freelistp = &srdp->srd_ismrgnfree;
		maxids = SFMMU_MAX_ISM_REGIONS;
		rarrp = srdp->srd_ismrgnp;
		busyrgnsp = &srdp->srd_ismbusyrgns;
	} else {
		nextidp = &srdp->srd_next_hmerid;
		freelistp = &srdp->srd_hmergnfree;
		maxids = SFMMU_MAX_HME_REGIONS;
		rarrp = srdp->srd_hmergnp;
		busyrgnsp = &srdp->srd_hmebusyrgns;
	}

	mutex_enter(&srdp->srd_mutex);

	for (rgnp = srdp->srd_rgnhash[rhash]; rgnp != NULL;
	    rgnp = rgnp->rgn_hash) {
		if (rgnp->rgn_saddr == r_saddr && rgnp->rgn_size == r_size &&
		    rgnp->rgn_obj == r_obj && rgnp->rgn_objoff == r_objoff &&
		    rgnp->rgn_perm == r_perm && rgnp->rgn_pgszc == r_pgszc) {
			break;
		}
	}

rfound:
	if (rgnp != NULL) {
		ASSERT((rgnp->rgn_flags & SFMMU_REGION_TYPE_MASK) == r_type);
		ASSERT(rgnp->rgn_cb_function == r_cb_function);
		ASSERT(rgnp->rgn_refcnt >= 0);
		rid = rgnp->rgn_id;
		ASSERT(rid < maxids);
		ASSERT(rarrp[rid] == rgnp);
		ASSERT(rid < *nextidp);
		atomic_inc_32((volatile uint_t *)&rgnp->rgn_refcnt);
		mutex_exit(&srdp->srd_mutex);
		if (new_rgnp != NULL) {
			kmem_cache_free(region_cache, new_rgnp);
		}
		if (r_type == SFMMU_REGION_HME) {
			int myjoin =
			    (sfmmup == astosfmmu(curthread->t_procp->p_as));

			sfmmu_link_to_hmeregion(sfmmup, rgnp);
			/*
			 * bitmap should be updated after linking sfmmu on
			 * region list so that pageunload() doesn't skip
			 * TSB/TLB flush. As soon as bitmap is updated another
			 * thread in this process can already start accessing
			 * this region.
			 */
			/*
			 * Normally ttecnt accounting is done as part of
			 * pagefault handling. But a process may not take any
			 * pagefaults on shared hmeblks created by some other
			 * process. To compensate for this assume that the
			 * entire region will end up faulted in using
			 * the region's pagesize.
			 *
			 */
			if (r_pgszc > TTE8K) {
				tteflag = 1 << r_pgszc;
				if (disable_large_pages & tteflag) {
					tteflag = 0;
				}
			} else {
				tteflag = 0;
			}
			if (tteflag && !(sfmmup->sfmmu_rtteflags & tteflag)) {
				hatlockp = sfmmu_hat_enter(sfmmup);
				sfmmup->sfmmu_rtteflags |= tteflag;
				sfmmu_hat_exit(hatlockp);
			}
			hatlockp = sfmmu_hat_enter(sfmmup);

			/*
			 * Preallocate 1/4 of ttecnt's in 8K TSB for >= 4M
			 * region to allow for large page allocation failure.
			 */
			if (r_pgszc >= TTE4M) {
				sfmmup->sfmmu_tsb0_4minflcnt +=
				    r_size >> (TTE_PAGE_SHIFT(TTE8K) + 2);
			}

			/* update sfmmu_ttecnt with the shme rgn ttecnt */
			rttecnt = r_size >> TTE_PAGE_SHIFT(r_pgszc);
			atomic_add_long(&sfmmup->sfmmu_ttecnt[r_pgszc],
			    rttecnt);

			if (text && r_pgszc >= TTE4M &&
			    (tteflag || ((disable_large_pages >> TTE4M) &
			    ((1 << (r_pgszc - TTE4M + 1)) - 1))) &&
			    !SFMMU_FLAGS_ISSET(sfmmup, HAT_4MTEXT_FLAG)) {
				SFMMU_FLAGS_SET(sfmmup, HAT_4MTEXT_FLAG);
			}

			sfmmu_hat_exit(hatlockp);
			/*
			 * On Panther we need to make sure TLB is programmed
			 * to accept 32M/256M pages.  Call
			 * sfmmu_check_page_sizes() now to make sure TLB is
			 * setup before making hmeregions visible to other
			 * threads.
			 */
			sfmmu_check_page_sizes(sfmmup, 1);
			hatlockp = sfmmu_hat_enter(sfmmup);
			SF_RGNMAP_ADD(sfmmup->sfmmu_hmeregion_map, rid);

			/*
			 * if context is invalid tsb miss exception code will
			 * call sfmmu_check_page_sizes() and update tsbmiss
			 * area later.
			 */
			kpreempt_disable();
			if (myjoin &&
			    (sfmmup->sfmmu_ctxs[CPU_MMU_IDX(CPU)].cnum
			    != INVALID_CONTEXT)) {
				struct tsbmiss *tsbmp;

				tsbmp = &tsbmiss_area[CPU->cpu_id];
				ASSERT(sfmmup == tsbmp->usfmmup);
				BT_SET(tsbmp->shmermap, rid);
				if (r_pgszc > TTE64K) {
					tsbmp->uhat_rtteflags |= tteflag;
				}

			}
			kpreempt_enable();

			sfmmu_hat_exit(hatlockp);
			ASSERT((hat_region_cookie_t)((uint64_t)rid) !=
			    HAT_INVALID_REGION_COOKIE);
		} else {
			hatlockp = sfmmu_hat_enter(sfmmup);
			SF_RGNMAP_ADD(sfmmup->sfmmu_ismregion_map, rid);
			sfmmu_hat_exit(hatlockp);
		}
		ASSERT(rid < maxids);

		if (r_type == SFMMU_REGION_ISM) {
			sfmmu_find_scd(sfmmup);
		}
		return ((hat_region_cookie_t)((uint64_t)rid));
	}

	ASSERT(new_rgnp == NULL);

	if (*busyrgnsp >= maxids) {
		mutex_exit(&srdp->srd_mutex);
		return (HAT_INVALID_REGION_COOKIE);
	}

	ASSERT(MUTEX_HELD(&srdp->srd_mutex));
	if (*freelistp != NULL) {
		rgnp = *freelistp;
		*freelistp = rgnp->rgn_next;
		ASSERT(rgnp->rgn_id < *nextidp);
		ASSERT(rgnp->rgn_id < maxids);
		ASSERT(rgnp->rgn_flags & SFMMU_REGION_FREE);
		ASSERT((rgnp->rgn_flags & SFMMU_REGION_TYPE_MASK)
		    == r_type);
		ASSERT(rarrp[rgnp->rgn_id] == rgnp);
		ASSERT(rgnp->rgn_hmeflags == 0);
	} else {
		/*
		 * release local locks before memory allocation.
		 */
		mutex_exit(&srdp->srd_mutex);

		new_rgnp = kmem_cache_alloc(region_cache, KM_SLEEP);

		mutex_enter(&srdp->srd_mutex);
		for (rgnp = srdp->srd_rgnhash[rhash]; rgnp != NULL;
		    rgnp = rgnp->rgn_hash) {
			if (rgnp->rgn_saddr == r_saddr &&
			    rgnp->rgn_size == r_size &&
			    rgnp->rgn_obj == r_obj &&
			    rgnp->rgn_objoff == r_objoff &&
			    rgnp->rgn_perm == r_perm &&
			    rgnp->rgn_pgszc == r_pgszc) {
				break;
			}
		}
		if (rgnp != NULL) {
			goto rfound;
		}

		if (*nextidp >= maxids) {
			mutex_exit(&srdp->srd_mutex);
			goto fail;
		}
		rgnp = new_rgnp;
		new_rgnp = NULL;
		rgnp->rgn_id = (*nextidp)++;
		ASSERT(rgnp->rgn_id < maxids);
		ASSERT(rarrp[rgnp->rgn_id] == NULL);
		rarrp[rgnp->rgn_id] = rgnp;
	}

	ASSERT(rgnp->rgn_sfmmu_head == NULL);
	ASSERT(rgnp->rgn_hmeflags == 0);
#ifdef DEBUG
	for (i = 0; i < MMU_PAGE_SIZES; i++) {
		ASSERT(rgnp->rgn_ttecnt[i] == 0);
	}
#endif
	rgnp->rgn_saddr = r_saddr;
	rgnp->rgn_size = r_size;
	rgnp->rgn_obj = r_obj;
	rgnp->rgn_objoff = r_objoff;
	rgnp->rgn_perm = r_perm;
	rgnp->rgn_pgszc = r_pgszc;
	rgnp->rgn_flags = r_type;
	rgnp->rgn_refcnt = 0;
	rgnp->rgn_cb_function = r_cb_function;
	rgnp->rgn_hash = srdp->srd_rgnhash[rhash];
	srdp->srd_rgnhash[rhash] = rgnp;
	(*busyrgnsp)++;
	ASSERT(*busyrgnsp <= maxids);
	goto rfound;

fail:
	ASSERT(new_rgnp != NULL);
	kmem_cache_free(region_cache, new_rgnp);
	return (HAT_INVALID_REGION_COOKIE);
}

/*
 * This function implements the shared context functionality required
 * when detaching a segment from an address space. It must be called
 * from hat_unshare() for all D(ISM) segments and from segvn_unmap(),
 * for segments with a valid region_cookie.
 * It will also be called from all seg_vn routines which change a
 * segment's attributes such as segvn_setprot(), segvn_setpagesize(),
 * segvn_clrszc() & segvn_advise(), as well as in the case of COW fault
 * from segvn_fault().
 */
void
hat_leave_region(struct hat *sfmmup, hat_region_cookie_t rcookie, uint_t flags)
{
	sf_srd_t *srdp = sfmmup->sfmmu_srdp;
	sf_scd_t *scdp;
	uint_t rhash;
	uint_t rid = (uint_t)((uint64_t)rcookie);
	hatlock_t *hatlockp = NULL;
	sf_region_t *rgnp;
	sf_region_t **prev_rgnpp;
	sf_region_t *cur_rgnp;
	void *r_obj;
	int i;
	caddr_t	r_saddr;
	caddr_t r_eaddr;
	size_t	r_size;
	uchar_t	r_pgszc;
	uchar_t r_type = flags & HAT_REGION_TYPE_MASK;

	ASSERT(sfmmup != ksfmmup);
	ASSERT(srdp != NULL);
	ASSERT(srdp->srd_refcnt > 0);
	ASSERT(!(flags & ~HAT_REGION_TYPE_MASK));
	ASSERT(flags == HAT_REGION_TEXT || flags == HAT_REGION_ISM);
	ASSERT(!sfmmup->sfmmu_free || sfmmup->sfmmu_scdp == NULL);

	r_type = (r_type == HAT_REGION_ISM) ? SFMMU_REGION_ISM :
	    SFMMU_REGION_HME;

	if (r_type == SFMMU_REGION_ISM) {
		ASSERT(SFMMU_IS_ISMRID_VALID(rid));
		ASSERT(rid < SFMMU_MAX_ISM_REGIONS);
		rgnp = srdp->srd_ismrgnp[rid];
	} else {
		ASSERT(SFMMU_IS_SHMERID_VALID(rid));
		ASSERT(rid < SFMMU_MAX_HME_REGIONS);
		rgnp = srdp->srd_hmergnp[rid];
	}
	ASSERT(rgnp != NULL);
	ASSERT(rgnp->rgn_id == rid);
	ASSERT((rgnp->rgn_flags & SFMMU_REGION_TYPE_MASK) == r_type);
	ASSERT(!(rgnp->rgn_flags & SFMMU_REGION_FREE));
	ASSERT(AS_LOCK_HELD(sfmmup->sfmmu_as));

	if (sfmmup->sfmmu_free) {
		ulong_t rttecnt;
		r_pgszc = rgnp->rgn_pgszc;
		r_size = rgnp->rgn_size;

		ASSERT(sfmmup->sfmmu_scdp == NULL);
		if (r_type == SFMMU_REGION_ISM) {
			SF_RGNMAP_DEL(sfmmup->sfmmu_ismregion_map, rid);
		} else {
			/* update shme rgns ttecnt in sfmmu_ttecnt */
			rttecnt = r_size >> TTE_PAGE_SHIFT(r_pgszc);
			ASSERT(sfmmup->sfmmu_ttecnt[r_pgszc] >= rttecnt);

			atomic_add_long(&sfmmup->sfmmu_ttecnt[r_pgszc],
			    -rttecnt);

			SF_RGNMAP_DEL(sfmmup->sfmmu_hmeregion_map, rid);
		}
	} else if (r_type == SFMMU_REGION_ISM) {
		hatlockp = sfmmu_hat_enter(sfmmup);
		ASSERT(rid < srdp->srd_next_ismrid);
		SF_RGNMAP_DEL(sfmmup->sfmmu_ismregion_map, rid);
		scdp = sfmmup->sfmmu_scdp;
		if (scdp != NULL &&
		    SF_RGNMAP_TEST(scdp->scd_ismregion_map, rid)) {
			sfmmu_leave_scd(sfmmup, r_type);
			ASSERT(sfmmu_hat_lock_held(sfmmup));
		}
		sfmmu_hat_exit(hatlockp);
	} else {
		ulong_t rttecnt;
		r_pgszc = rgnp->rgn_pgszc;
		r_saddr = rgnp->rgn_saddr;
		r_size = rgnp->rgn_size;
		r_eaddr = r_saddr + r_size;

		ASSERT(r_type == SFMMU_REGION_HME);
		hatlockp = sfmmu_hat_enter(sfmmup);
		ASSERT(rid < srdp->srd_next_hmerid);
		SF_RGNMAP_DEL(sfmmup->sfmmu_hmeregion_map, rid);

		/*
		 * If region is part of an SCD call sfmmu_leave_scd().
		 * Otherwise if process is not exiting and has valid context
		 * just drop the context on the floor to lose stale TLB
		 * entries and force the update of tsb miss area to reflect
		 * the new region map. After that clean our TSB entries.
		 */
		scdp = sfmmup->sfmmu_scdp;
		if (scdp != NULL &&
		    SF_RGNMAP_TEST(scdp->scd_hmeregion_map, rid)) {
			sfmmu_leave_scd(sfmmup, r_type);
			ASSERT(sfmmu_hat_lock_held(sfmmup));
		}
		sfmmu_invalidate_ctx(sfmmup);

		i = TTE8K;
		while (i < mmu_page_sizes) {
			if (rgnp->rgn_ttecnt[i] != 0) {
				sfmmu_unload_tsb_range(sfmmup, r_saddr,
				    r_eaddr, i);
				if (i < TTE4M) {
					i = TTE4M;
					continue;
				} else {
					break;
				}
			}
			i++;
		}
		/* Remove the preallocated 1/4 8k ttecnt for 4M regions. */
		if (r_pgszc >= TTE4M) {
			rttecnt = r_size >> (TTE_PAGE_SHIFT(TTE8K) + 2);
			ASSERT(sfmmup->sfmmu_tsb0_4minflcnt >=
			    rttecnt);
			sfmmup->sfmmu_tsb0_4minflcnt -= rttecnt;
		}

		/* update shme rgns ttecnt in sfmmu_ttecnt */
		rttecnt = r_size >> TTE_PAGE_SHIFT(r_pgszc);
		ASSERT(sfmmup->sfmmu_ttecnt[r_pgszc] >= rttecnt);
		atomic_add_long(&sfmmup->sfmmu_ttecnt[r_pgszc], -rttecnt);

		sfmmu_hat_exit(hatlockp);
		if (scdp != NULL && sfmmup->sfmmu_scdp == NULL) {
			/* sfmmup left the scd, grow private tsb */
			sfmmu_check_page_sizes(sfmmup, 1);
		} else {
			sfmmu_check_page_sizes(sfmmup, 0);
		}
	}

	if (r_type == SFMMU_REGION_HME) {
		sfmmu_unlink_from_hmeregion(sfmmup, rgnp);
	}

	r_obj = rgnp->rgn_obj;
	if (atomic_dec_32_nv((volatile uint_t *)&rgnp->rgn_refcnt)) {
		return;
	}

	/*
	 * looks like nobody uses this region anymore. Free it.
	 */
	rhash = RGN_HASH_FUNCTION(r_obj);
	mutex_enter(&srdp->srd_mutex);
	for (prev_rgnpp = &srdp->srd_rgnhash[rhash];
	    (cur_rgnp = *prev_rgnpp) != NULL;
	    prev_rgnpp = &cur_rgnp->rgn_hash) {
		if (cur_rgnp == rgnp && cur_rgnp->rgn_refcnt == 0) {
			break;
		}
	}

	if (cur_rgnp == NULL) {
		mutex_exit(&srdp->srd_mutex);
		return;
	}

	ASSERT((rgnp->rgn_flags & SFMMU_REGION_TYPE_MASK) == r_type);
	*prev_rgnpp = rgnp->rgn_hash;
	if (r_type == SFMMU_REGION_ISM) {
		rgnp->rgn_flags |= SFMMU_REGION_FREE;
		ASSERT(rid < srdp->srd_next_ismrid);
		rgnp->rgn_next = srdp->srd_ismrgnfree;
		srdp->srd_ismrgnfree = rgnp;
		ASSERT(srdp->srd_ismbusyrgns > 0);
		srdp->srd_ismbusyrgns--;
		mutex_exit(&srdp->srd_mutex);
		return;
	}
	mutex_exit(&srdp->srd_mutex);

	/*
	 * Destroy region's hmeblks.
	 */
	sfmmu_unload_hmeregion(srdp, rgnp);

	rgnp->rgn_hmeflags = 0;

	ASSERT(rgnp->rgn_sfmmu_head == NULL);
	ASSERT(rgnp->rgn_id == rid);
	for (i = 0; i < MMU_PAGE_SIZES; i++) {
		rgnp->rgn_ttecnt[i] = 0;
	}
	rgnp->rgn_flags |= SFMMU_REGION_FREE;
	mutex_enter(&srdp->srd_mutex);
	ASSERT(rid < srdp->srd_next_hmerid);
	rgnp->rgn_next = srdp->srd_hmergnfree;
	srdp->srd_hmergnfree = rgnp;
	ASSERT(srdp->srd_hmebusyrgns > 0);
	srdp->srd_hmebusyrgns--;
	mutex_exit(&srdp->srd_mutex);
}

/*
 * For now only called for hmeblk regions and not for ISM regions.
 */
void
hat_dup_region(struct hat *sfmmup, hat_region_cookie_t rcookie)
{
	sf_srd_t *srdp = sfmmup->sfmmu_srdp;
	uint_t rid = (uint_t)((uint64_t)rcookie);
	sf_region_t *rgnp;
	sf_rgn_link_t *rlink;
	sf_rgn_link_t *hrlink;
	ulong_t	rttecnt;

	ASSERT(sfmmup != ksfmmup);
	ASSERT(srdp != NULL);
	ASSERT(srdp->srd_refcnt > 0);

	ASSERT(rid < srdp->srd_next_hmerid);
	ASSERT(SFMMU_IS_SHMERID_VALID(rid));
	ASSERT(rid < SFMMU_MAX_HME_REGIONS);

	rgnp = srdp->srd_hmergnp[rid];
	ASSERT(rgnp->rgn_refcnt > 0);
	ASSERT(rgnp->rgn_id == rid);
	ASSERT((rgnp->rgn_flags & SFMMU_REGION_TYPE_MASK) == SFMMU_REGION_HME);
	ASSERT(!(rgnp->rgn_flags & SFMMU_REGION_FREE));

	atomic_inc_32((volatile uint_t *)&rgnp->rgn_refcnt);

	/* LINTED: constant in conditional context */
	SFMMU_HMERID2RLINKP(sfmmup, rid, rlink, 1, 0);
	ASSERT(rlink != NULL);
	mutex_enter(&rgnp->rgn_mutex);
	ASSERT(rgnp->rgn_sfmmu_head != NULL);
	/* LINTED: constant in conditional context */
	SFMMU_HMERID2RLINKP(rgnp->rgn_sfmmu_head, rid, hrlink, 0, 0);
	ASSERT(hrlink != NULL);
	ASSERT(hrlink->prev == NULL);
	rlink->next = rgnp->rgn_sfmmu_head;
	rlink->prev = NULL;
	hrlink->prev = sfmmup;
	/*
	 * make sure rlink's next field is correct
	 * before making this link visible.
	 */
	membar_stst();
	rgnp->rgn_sfmmu_head = sfmmup;
	mutex_exit(&rgnp->rgn_mutex);

	/* update sfmmu_ttecnt with the shme rgn ttecnt */
	rttecnt = rgnp->rgn_size >> TTE_PAGE_SHIFT(rgnp->rgn_pgszc);
	atomic_add_long(&sfmmup->sfmmu_ttecnt[rgnp->rgn_pgszc], rttecnt);
	/* update tsb0 inflation count */
	if (rgnp->rgn_pgszc >= TTE4M) {
		sfmmup->sfmmu_tsb0_4minflcnt +=
		    rgnp->rgn_size >> (TTE_PAGE_SHIFT(TTE8K) + 2);
	}
	/*
	 * Update regionid bitmask without hat lock since no other thread
	 * can update this region bitmask right now.
	 */
	SF_RGNMAP_ADD(sfmmup->sfmmu_hmeregion_map, rid);
}

/* ARGSUSED */
static int
sfmmu_rgncache_constructor(void *buf, void *cdrarg, int kmflags)
{
	sf_region_t *rgnp = (sf_region_t *)buf;
	bzero(buf, sizeof (*rgnp));

	mutex_init(&rgnp->rgn_mutex, NULL, MUTEX_DEFAULT, NULL);

	return (0);
}

/* ARGSUSED */
static void
sfmmu_rgncache_destructor(void *buf, void *cdrarg)
{
	sf_region_t *rgnp = (sf_region_t *)buf;
	mutex_destroy(&rgnp->rgn_mutex);
}

static int
sfrgnmap_isnull(sf_region_map_t *map)
{
	int i;

	for (i = 0; i < SFMMU_RGNMAP_WORDS; i++) {
		if (map->bitmap[i] != 0) {
			return (0);
		}
	}
	return (1);
}

static int
sfhmergnmap_isnull(sf_hmeregion_map_t *map)
{
	int i;

	for (i = 0; i < SFMMU_HMERGNMAP_WORDS; i++) {
		if (map->bitmap[i] != 0) {
			return (0);
		}
	}
	return (1);
}

#ifdef DEBUG
static void
check_scd_sfmmu_list(sfmmu_t **headp, sfmmu_t *sfmmup, int onlist)
{
	sfmmu_t *sp;
	sf_srd_t *srdp = sfmmup->sfmmu_srdp;

	for (sp = *headp; sp != NULL; sp = sp->sfmmu_scd_link.next) {
		ASSERT(srdp == sp->sfmmu_srdp);
		if (sp == sfmmup) {
			if (onlist) {
				return;
			} else {
				panic("shctx: sfmmu 0x%p found on scd"
				    "list 0x%p", (void *)sfmmup,
				    (void *)*headp);
			}
		}
	}
	if (onlist) {
		panic("shctx: sfmmu 0x%p not found on scd list 0x%p",
		    (void *)sfmmup, (void *)*headp);
	} else {
		return;
	}
}
#else /* DEBUG */
#define	check_scd_sfmmu_list(headp, sfmmup, onlist)
#endif /* DEBUG */

/*
 * Removes an sfmmu from the SCD sfmmu list.
 */
static void
sfmmu_from_scd_list(sfmmu_t **headp, sfmmu_t *sfmmup)
{
	ASSERT(sfmmup->sfmmu_srdp != NULL);
	check_scd_sfmmu_list(headp, sfmmup, 1);
	if (sfmmup->sfmmu_scd_link.prev != NULL) {
		ASSERT(*headp != sfmmup);
		sfmmup->sfmmu_scd_link.prev->sfmmu_scd_link.next =
		    sfmmup->sfmmu_scd_link.next;
	} else {
		ASSERT(*headp == sfmmup);
		*headp = sfmmup->sfmmu_scd_link.next;
	}
	if (sfmmup->sfmmu_scd_link.next != NULL) {
		sfmmup->sfmmu_scd_link.next->sfmmu_scd_link.prev =
		    sfmmup->sfmmu_scd_link.prev;
	}
}


/*
 * Adds an sfmmu to the start of the queue.
 */
static void
sfmmu_to_scd_list(sfmmu_t **headp, sfmmu_t *sfmmup)
{
	check_scd_sfmmu_list(headp, sfmmup, 0);
	sfmmup->sfmmu_scd_link.prev = NULL;
	sfmmup->sfmmu_scd_link.next = *headp;
	if (*headp != NULL)
		(*headp)->sfmmu_scd_link.prev = sfmmup;
	*headp = sfmmup;
}

/*
 * Remove an scd from the start of the queue.
 */
static void
sfmmu_remove_scd(sf_scd_t **headp, sf_scd_t *scdp)
{
	if (scdp->scd_prev != NULL) {
		ASSERT(*headp != scdp);
		scdp->scd_prev->scd_next = scdp->scd_next;
	} else {
		ASSERT(*headp == scdp);
		*headp = scdp->scd_next;
	}

	if (scdp->scd_next != NULL) {
		scdp->scd_next->scd_prev = scdp->scd_prev;
	}
}

/*
 * Add an scd to the start of the queue.
 */
static void
sfmmu_add_scd(sf_scd_t **headp, sf_scd_t *scdp)
{
	scdp->scd_prev = NULL;
	scdp->scd_next = *headp;
	if (*headp != NULL) {
		(*headp)->scd_prev = scdp;
	}
	*headp = scdp;
}

static int
sfmmu_alloc_scd_tsbs(sf_srd_t *srdp, sf_scd_t *scdp)
{
	uint_t rid;
	uint_t i;
	uint_t j;
	ulong_t w;
	sf_region_t *rgnp;
	ulong_t tte8k_cnt = 0;
	ulong_t tte4m_cnt = 0;
	uint_t tsb_szc;
	sfmmu_t *scsfmmup = scdp->scd_sfmmup;
	sfmmu_t	*ism_hatid;
	struct tsb_info *newtsb;
	int szc;

	ASSERT(srdp != NULL);

	for (i = 0; i < SFMMU_RGNMAP_WORDS; i++) {
		if ((w = scdp->scd_region_map.bitmap[i]) == 0) {
			continue;
		}
		j = 0;
		while (w) {
			if (!(w & 0x1)) {
				j++;
				w >>= 1;
				continue;
			}
			rid = (i << BT_ULSHIFT) | j;
			j++;
			w >>= 1;

			if (rid < SFMMU_MAX_HME_REGIONS) {
				rgnp = srdp->srd_hmergnp[rid];
				ASSERT(rgnp->rgn_id == rid);
				ASSERT(rgnp->rgn_refcnt > 0);

				if (rgnp->rgn_pgszc < TTE4M) {
					tte8k_cnt += rgnp->rgn_size >>
					    TTE_PAGE_SHIFT(TTE8K);
				} else {
					ASSERT(rgnp->rgn_pgszc >= TTE4M);
					tte4m_cnt += rgnp->rgn_size >>
					    TTE_PAGE_SHIFT(TTE4M);
					/*
					 * Inflate SCD tsb0 by preallocating
					 * 1/4 8k ttecnt for 4M regions to
					 * allow for lgpg alloc failure.
					 */
					tte8k_cnt += rgnp->rgn_size >>
					    (TTE_PAGE_SHIFT(TTE8K) + 2);
				}
			} else {
				rid -= SFMMU_MAX_HME_REGIONS;
				rgnp = srdp->srd_ismrgnp[rid];
				ASSERT(rgnp->rgn_id == rid);
				ASSERT(rgnp->rgn_refcnt > 0);

				ism_hatid = (sfmmu_t *)rgnp->rgn_obj;
				ASSERT(ism_hatid->sfmmu_ismhat);

				for (szc = 0; szc < TTE4M; szc++) {
					tte8k_cnt +=
					    ism_hatid->sfmmu_ttecnt[szc] <<
					    TTE_BSZS_SHIFT(szc);
				}

				ASSERT(rgnp->rgn_pgszc >= TTE4M);
				if (rgnp->rgn_pgszc >= TTE4M) {
					tte4m_cnt += rgnp->rgn_size >>
					    TTE_PAGE_SHIFT(TTE4M);
				}
			}
		}
	}

	tsb_szc = SELECT_TSB_SIZECODE(tte8k_cnt);

	/* Allocate both the SCD TSBs here. */
	if (sfmmu_tsbinfo_alloc(&scsfmmup->sfmmu_tsb,
	    tsb_szc, TSB8K|TSB64K|TSB512K, TSB_ALLOC, scsfmmup) &&
	    (tsb_szc <= TSB_4M_SZCODE ||
	    sfmmu_tsbinfo_alloc(&scsfmmup->sfmmu_tsb,
	    TSB_4M_SZCODE, TSB8K|TSB64K|TSB512K,
	    TSB_ALLOC, scsfmmup))) {

		SFMMU_STAT(sf_scd_1sttsb_allocfail);
		return (TSB_ALLOCFAIL);
	} else {
		scsfmmup->sfmmu_tsb->tsb_flags |= TSB_SHAREDCTX;

		if (tte4m_cnt) {
			tsb_szc = SELECT_TSB_SIZECODE(tte4m_cnt);
			if (sfmmu_tsbinfo_alloc(&newtsb, tsb_szc,
			    TSB4M|TSB32M|TSB256M, TSB_ALLOC, scsfmmup) &&
			    (tsb_szc <= TSB_4M_SZCODE ||
			    sfmmu_tsbinfo_alloc(&newtsb, TSB_4M_SZCODE,
			    TSB4M|TSB32M|TSB256M,
			    TSB_ALLOC, scsfmmup))) {
				/*
				 * If we fail to allocate the 2nd shared tsb,
				 * just free the 1st tsb, return failure.
				 */
				sfmmu_tsbinfo_free(scsfmmup->sfmmu_tsb);
				SFMMU_STAT(sf_scd_2ndtsb_allocfail);
				return (TSB_ALLOCFAIL);
			} else {
				ASSERT(scsfmmup->sfmmu_tsb->tsb_next == NULL);
				newtsb->tsb_flags |= TSB_SHAREDCTX;
				scsfmmup->sfmmu_tsb->tsb_next = newtsb;
				SFMMU_STAT(sf_scd_2ndtsb_alloc);
			}
		}
		SFMMU_STAT(sf_scd_1sttsb_alloc);
	}
	return (TSB_SUCCESS);
}

static void
sfmmu_free_scd_tsbs(sfmmu_t *scd_sfmmu)
{
	while (scd_sfmmu->sfmmu_tsb != NULL) {
		struct tsb_info *next = scd_sfmmu->sfmmu_tsb->tsb_next;
		sfmmu_tsbinfo_free(scd_sfmmu->sfmmu_tsb);
		scd_sfmmu->sfmmu_tsb = next;
	}
}

/*
 * Link the sfmmu onto the hme region list.
 */
void
sfmmu_link_to_hmeregion(sfmmu_t *sfmmup, sf_region_t *rgnp)
{
	uint_t rid;
	sf_rgn_link_t *rlink;
	sfmmu_t *head;
	sf_rgn_link_t *hrlink;

	rid = rgnp->rgn_id;
	ASSERT(SFMMU_IS_SHMERID_VALID(rid));

	/* LINTED: constant in conditional context */
	SFMMU_HMERID2RLINKP(sfmmup, rid, rlink, 1, 1);
	ASSERT(rlink != NULL);
	mutex_enter(&rgnp->rgn_mutex);
	if ((head = rgnp->rgn_sfmmu_head) == NULL) {
		rlink->next = NULL;
		rlink->prev = NULL;
		/*
		 * make sure rlink's next field is NULL
		 * before making this link visible.
		 */
		membar_stst();
		rgnp->rgn_sfmmu_head = sfmmup;
	} else {
		/* LINTED: constant in conditional context */
		SFMMU_HMERID2RLINKP(head, rid, hrlink, 0, 0);
		ASSERT(hrlink != NULL);
		ASSERT(hrlink->prev == NULL);
		rlink->next = head;
		rlink->prev = NULL;
		hrlink->prev = sfmmup;
		/*
		 * make sure rlink's next field is correct
		 * before making this link visible.
		 */
		membar_stst();
		rgnp->rgn_sfmmu_head = sfmmup;
	}
	mutex_exit(&rgnp->rgn_mutex);
}

/*
 * Unlink the sfmmu from the hme region list.
 */
void
sfmmu_unlink_from_hmeregion(sfmmu_t *sfmmup, sf_region_t *rgnp)
{
	uint_t rid;
	sf_rgn_link_t *rlink;

	rid = rgnp->rgn_id;
	ASSERT(SFMMU_IS_SHMERID_VALID(rid));

	/* LINTED: constant in conditional context */
	SFMMU_HMERID2RLINKP(sfmmup, rid, rlink, 0, 0);
	ASSERT(rlink != NULL);
	mutex_enter(&rgnp->rgn_mutex);
	if (rgnp->rgn_sfmmu_head == sfmmup) {
		sfmmu_t *next = rlink->next;
		rgnp->rgn_sfmmu_head = next;
		/*
		 * if we are stopped by xc_attention() after this
		 * point the forward link walking in
		 * sfmmu_rgntlb_demap() will work correctly since the
		 * head correctly points to the next element.
		 */
		membar_stst();
		rlink->next = NULL;
		ASSERT(rlink->prev == NULL);
		if (next != NULL) {
			sf_rgn_link_t *nrlink;
			/* LINTED: constant in conditional context */
			SFMMU_HMERID2RLINKP(next, rid, nrlink, 0, 0);
			ASSERT(nrlink != NULL);
			ASSERT(nrlink->prev == sfmmup);
			nrlink->prev = NULL;
		}
	} else {
		sfmmu_t *next = rlink->next;
		sfmmu_t *prev = rlink->prev;
		sf_rgn_link_t *prlink;

		ASSERT(prev != NULL);
		/* LINTED: constant in conditional context */
		SFMMU_HMERID2RLINKP(prev, rid, prlink, 0, 0);
		ASSERT(prlink != NULL);
		ASSERT(prlink->next == sfmmup);
		prlink->next = next;
		/*
		 * if we are stopped by xc_attention()
		 * after this point the forward link walking
		 * will work correctly since the prev element
		 * correctly points to the next element.
		 */
		membar_stst();
		rlink->next = NULL;
		rlink->prev = NULL;
		if (next != NULL) {
			sf_rgn_link_t *nrlink;
			/* LINTED: constant in conditional context */
			SFMMU_HMERID2RLINKP(next, rid, nrlink, 0, 0);
			ASSERT(nrlink != NULL);
			ASSERT(nrlink->prev == sfmmup);
			nrlink->prev = prev;
		}
	}
	mutex_exit(&rgnp->rgn_mutex);
}

/*
 * Link scd sfmmu onto ism or hme region list for each region in the
 * scd region map.
 */
void
sfmmu_link_scd_to_regions(sf_srd_t *srdp, sf_scd_t *scdp)
{
	uint_t rid;
	uint_t i;
	uint_t j;
	ulong_t w;
	sf_region_t *rgnp;
	sfmmu_t *scsfmmup;

	scsfmmup = scdp->scd_sfmmup;
	ASSERT(scsfmmup->sfmmu_scdhat);
	for (i = 0; i < SFMMU_RGNMAP_WORDS; i++) {
		if ((w = scdp->scd_region_map.bitmap[i]) == 0) {
			continue;
		}
		j = 0;
		while (w) {
			if (!(w & 0x1)) {
				j++;
				w >>= 1;
				continue;
			}
			rid = (i << BT_ULSHIFT) | j;
			j++;
			w >>= 1;

			if (rid < SFMMU_MAX_HME_REGIONS) {
				rgnp = srdp->srd_hmergnp[rid];
				ASSERT(rgnp->rgn_id == rid);
				ASSERT(rgnp->rgn_refcnt > 0);
				sfmmu_link_to_hmeregion(scsfmmup, rgnp);
			} else {
				sfmmu_t *ism_hatid = NULL;
				ism_ment_t *ism_ment;
				rid -= SFMMU_MAX_HME_REGIONS;
				rgnp = srdp->srd_ismrgnp[rid];
				ASSERT(rgnp->rgn_id == rid);
				ASSERT(rgnp->rgn_refcnt > 0);

				ism_hatid = (sfmmu_t *)rgnp->rgn_obj;
				ASSERT(ism_hatid->sfmmu_ismhat);
				ism_ment = &scdp->scd_ism_links[rid];
				ism_ment->iment_hat = scsfmmup;
				ism_ment->iment_base_va = rgnp->rgn_saddr;
				mutex_enter(&ism_mlist_lock);
				iment_add(ism_ment, ism_hatid);
				mutex_exit(&ism_mlist_lock);

			}
		}
	}
}
/*
 * Unlink scd sfmmu from ism or hme region list for each region in the
 * scd region map.
 */
void
sfmmu_unlink_scd_from_regions(sf_srd_t *srdp, sf_scd_t *scdp)
{
	uint_t rid;
	uint_t i;
	uint_t j;
	ulong_t w;
	sf_region_t *rgnp;
	sfmmu_t *scsfmmup;

	scsfmmup = scdp->scd_sfmmup;
	for (i = 0; i < SFMMU_RGNMAP_WORDS; i++) {
		if ((w = scdp->scd_region_map.bitmap[i]) == 0) {
			continue;
		}
		j = 0;
		while (w) {
			if (!(w & 0x1)) {
				j++;
				w >>= 1;
				continue;
			}
			rid = (i << BT_ULSHIFT) | j;
			j++;
			w >>= 1;

			if (rid < SFMMU_MAX_HME_REGIONS) {
				rgnp = srdp->srd_hmergnp[rid];
				ASSERT(rgnp->rgn_id == rid);
				ASSERT(rgnp->rgn_refcnt > 0);
				sfmmu_unlink_from_hmeregion(scsfmmup,
				    rgnp);

			} else {
				sfmmu_t *ism_hatid = NULL;
				ism_ment_t *ism_ment;
				rid -= SFMMU_MAX_HME_REGIONS;
				rgnp = srdp->srd_ismrgnp[rid];
				ASSERT(rgnp->rgn_id == rid);
				ASSERT(rgnp->rgn_refcnt > 0);

				ism_hatid = (sfmmu_t *)rgnp->rgn_obj;
				ASSERT(ism_hatid->sfmmu_ismhat);
				ism_ment = &scdp->scd_ism_links[rid];
				ASSERT(ism_ment->iment_hat == scdp->scd_sfmmup);
				ASSERT(ism_ment->iment_base_va ==
				    rgnp->rgn_saddr);
				mutex_enter(&ism_mlist_lock);
				iment_sub(ism_ment, ism_hatid);
				mutex_exit(&ism_mlist_lock);

			}
		}
	}
}
/*
 * Allocates and initialises a new SCD structure, this is called with
 * the srd_scd_mutex held and returns with the reference count
 * initialised to 1.
 */
static sf_scd_t *
sfmmu_alloc_scd(sf_srd_t *srdp, sf_region_map_t *new_map)
{
	sf_scd_t *new_scdp;
	sfmmu_t *scsfmmup;
	int i;

	ASSERT(MUTEX_HELD(&srdp->srd_scd_mutex));
	new_scdp = kmem_cache_alloc(scd_cache, KM_SLEEP);

	scsfmmup = kmem_cache_alloc(sfmmuid_cache, KM_SLEEP);
	new_scdp->scd_sfmmup = scsfmmup;
	scsfmmup->sfmmu_srdp = srdp;
	scsfmmup->sfmmu_scdp = new_scdp;
	scsfmmup->sfmmu_tsb0_4minflcnt = 0;
	scsfmmup->sfmmu_scdhat = 1;
	CPUSET_ALL(scsfmmup->sfmmu_cpusran);
	bzero(scsfmmup->sfmmu_hmeregion_links, SFMMU_L1_HMERLINKS_SIZE);

	ASSERT(max_mmu_ctxdoms > 0);
	for (i = 0; i < max_mmu_ctxdoms; i++) {
		scsfmmup->sfmmu_ctxs[i].cnum = INVALID_CONTEXT;
		scsfmmup->sfmmu_ctxs[i].gnum = 0;
	}

	for (i = 0; i < MMU_PAGE_SIZES; i++) {
		new_scdp->scd_rttecnt[i] = 0;
	}

	new_scdp->scd_region_map = *new_map;
	new_scdp->scd_refcnt = 1;
	if (sfmmu_alloc_scd_tsbs(srdp, new_scdp) != TSB_SUCCESS) {
		kmem_cache_free(scd_cache, new_scdp);
		kmem_cache_free(sfmmuid_cache, scsfmmup);
		return (NULL);
	}
	if (&mmu_init_scd) {
		mmu_init_scd(new_scdp);
	}
	return (new_scdp);
}

/*
 * The first phase of a process joining an SCD. The hat structure is
 * linked to the SCD queue and then the HAT_JOIN_SCD sfmmu flag is set
 * and a cross-call with context invalidation is used to cause the
 * remaining work to be carried out in the sfmmu_tsbmiss_exception()
 * routine.
 */
static void
sfmmu_join_scd(sf_scd_t *scdp, sfmmu_t *sfmmup)
{
	hatlock_t *hatlockp;
	sf_srd_t *srdp = sfmmup->sfmmu_srdp;
	int i;
	sf_scd_t *old_scdp;

	ASSERT(srdp != NULL);
	ASSERT(scdp != NULL);
	ASSERT(scdp->scd_refcnt > 0);
	ASSERT(AS_WRITE_HELD(sfmmup->sfmmu_as));

	if ((old_scdp = sfmmup->sfmmu_scdp) != NULL) {
		ASSERT(old_scdp != scdp);

		mutex_enter(&old_scdp->scd_mutex);
		sfmmu_from_scd_list(&old_scdp->scd_sf_list, sfmmup);
		mutex_exit(&old_scdp->scd_mutex);
		/*
		 * sfmmup leaves the old scd. Update sfmmu_ttecnt to
		 * include the shme rgn ttecnt for rgns that
		 * were in the old SCD
		 */
		for (i = 0; i < mmu_page_sizes; i++) {
			ASSERT(sfmmup->sfmmu_scdrttecnt[i] ==
			    old_scdp->scd_rttecnt[i]);
			atomic_add_long(&sfmmup->sfmmu_ttecnt[i],
			    sfmmup->sfmmu_scdrttecnt[i]);
		}
	}

	/*
	 * Move sfmmu to the scd lists.
	 */
	mutex_enter(&scdp->scd_mutex);
	sfmmu_to_scd_list(&scdp->scd_sf_list, sfmmup);
	mutex_exit(&scdp->scd_mutex);
	SF_SCD_INCR_REF(scdp);

	hatlockp = sfmmu_hat_enter(sfmmup);
	/*
	 * For a multi-thread process, we must stop
	 * all the other threads before joining the scd.
	 */

	SFMMU_FLAGS_SET(sfmmup, HAT_JOIN_SCD);

	sfmmu_invalidate_ctx(sfmmup);
	sfmmup->sfmmu_scdp = scdp;

	/*
	 * Copy scd_rttecnt into sfmmup's sfmmu_scdrttecnt, and update
	 * sfmmu_ttecnt to not include the rgn ttecnt just joined in SCD.
	 */
	for (i = 0; i < mmu_page_sizes; i++) {
		sfmmup->sfmmu_scdrttecnt[i] = scdp->scd_rttecnt[i];
		ASSERT(sfmmup->sfmmu_ttecnt[i] >= scdp->scd_rttecnt[i]);
		atomic_add_long(&sfmmup->sfmmu_ttecnt[i],
		    -sfmmup->sfmmu_scdrttecnt[i]);
	}
	/* update tsb0 inflation count */
	if (old_scdp != NULL) {
		sfmmup->sfmmu_tsb0_4minflcnt +=
		    old_scdp->scd_sfmmup->sfmmu_tsb0_4minflcnt;
	}
	ASSERT(sfmmup->sfmmu_tsb0_4minflcnt >=
	    scdp->scd_sfmmup->sfmmu_tsb0_4minflcnt);
	sfmmup->sfmmu_tsb0_4minflcnt -= scdp->scd_sfmmup->sfmmu_tsb0_4minflcnt;

	sfmmu_hat_exit(hatlockp);

	if (old_scdp != NULL) {
		SF_SCD_DECR_REF(srdp, old_scdp);
	}

}

/*
 * This routine is called by a process to become part of an SCD. It is called
 * from sfmmu_tsbmiss_exception() once most of the initial work has been
 * done by sfmmu_join_scd(). This routine must not drop the hat lock.
 */
static void
sfmmu_finish_join_scd(sfmmu_t *sfmmup)
{
	struct tsb_info	*tsbinfop;

	ASSERT(sfmmu_hat_lock_held(sfmmup));
	ASSERT(sfmmup->sfmmu_scdp != NULL);
	ASSERT(SFMMU_FLAGS_ISSET(sfmmup, HAT_JOIN_SCD));
	ASSERT(!SFMMU_FLAGS_ISSET(sfmmup, HAT_ISMBUSY));
	ASSERT(SFMMU_FLAGS_ISSET(sfmmup, HAT_ALLCTX_INVALID));

	for (tsbinfop = sfmmup->sfmmu_tsb; tsbinfop != NULL;
	    tsbinfop = tsbinfop->tsb_next) {
		if (tsbinfop->tsb_flags & TSB_SWAPPED) {
			continue;
		}
		ASSERT(!(tsbinfop->tsb_flags & TSB_RELOC_FLAG));

		sfmmu_inv_tsb(tsbinfop->tsb_va,
		    TSB_BYTES(tsbinfop->tsb_szc));
	}

	/* Set HAT_CTX1_FLAG for all SCD ISMs */
	sfmmu_ism_hatflags(sfmmup, 1);

	SFMMU_STAT(sf_join_scd);
}

/*
 * This routine is called in order to check if there is an SCD which matches
 * the process's region map if not then a new SCD may be created.
 */
static void
sfmmu_find_scd(sfmmu_t *sfmmup)
{
	sf_srd_t *srdp = sfmmup->sfmmu_srdp;
	sf_scd_t *scdp, *new_scdp;
	int ret;

	ASSERT(srdp != NULL);
	ASSERT(AS_WRITE_HELD(sfmmup->sfmmu_as));

	mutex_enter(&srdp->srd_scd_mutex);
	for (scdp = srdp->srd_scdp; scdp != NULL;
	    scdp = scdp->scd_next) {
		SF_RGNMAP_EQUAL(&scdp->scd_region_map,
		    &sfmmup->sfmmu_region_map, ret);
		if (ret == 1) {
			SF_SCD_INCR_REF(scdp);
			mutex_exit(&srdp->srd_scd_mutex);
			sfmmu_join_scd(scdp, sfmmup);
			ASSERT(scdp->scd_refcnt >= 2);
			atomic_dec_32((volatile uint32_t *)&scdp->scd_refcnt);
			return;
		} else {
			/*
			 * If the sfmmu region map is a subset of the scd
			 * region map, then the assumption is that this process
			 * will continue attaching to ISM segments until the
			 * region maps are equal.
			 */
			SF_RGNMAP_IS_SUBSET(&scdp->scd_region_map,
			    &sfmmup->sfmmu_region_map, ret);
			if (ret == 1) {
				mutex_exit(&srdp->srd_scd_mutex);
				return;
			}
		}
	}

	ASSERT(scdp == NULL);
	/*
	 * No matching SCD has been found, create a new one.
	 */
	if ((new_scdp = sfmmu_alloc_scd(srdp, &sfmmup->sfmmu_region_map)) ==
	    NULL) {
		mutex_exit(&srdp->srd_scd_mutex);
		return;
	}

	/*
	 * sfmmu_alloc_scd() returns with a ref count of 1 on the scd.
	 */

	/* Set scd_rttecnt for shme rgns in SCD */
	sfmmu_set_scd_rttecnt(srdp, new_scdp);

	/*
	 * Link scd onto srd_scdp list and scd sfmmu onto region/iment lists.
	 */
	sfmmu_link_scd_to_regions(srdp, new_scdp);
	sfmmu_add_scd(&srdp->srd_scdp, new_scdp);
	SFMMU_STAT_ADD(sf_create_scd, 1);

	mutex_exit(&srdp->srd_scd_mutex);
	sfmmu_join_scd(new_scdp, sfmmup);
	ASSERT(new_scdp->scd_refcnt >= 2);
	atomic_dec_32((volatile uint32_t *)&new_scdp->scd_refcnt);
}

/*
 * This routine is called by a process to remove itself from an SCD. It is
 * either called when the processes has detached from a segment or from
 * hat_free_start() as a result of calling exit.
 */
static void
sfmmu_leave_scd(sfmmu_t *sfmmup, uchar_t r_type)
{
	sf_scd_t *scdp = sfmmup->sfmmu_scdp;
	sf_srd_t *srdp =  sfmmup->sfmmu_srdp;
	hatlock_t *hatlockp = TSB_HASH(sfmmup);
	int i;

	ASSERT(scdp != NULL);
	ASSERT(srdp != NULL);

	if (sfmmup->sfmmu_free) {
		/*
		 * If the process is part of an SCD the sfmmu is unlinked
		 * from scd_sf_list.
		 */
		mutex_enter(&scdp->scd_mutex);
		sfmmu_from_scd_list(&scdp->scd_sf_list, sfmmup);
		mutex_exit(&scdp->scd_mutex);
		/*
		 * Update sfmmu_ttecnt to include the rgn ttecnt for rgns that
		 * are about to leave the SCD
		 */
		for (i = 0; i < mmu_page_sizes; i++) {
			ASSERT(sfmmup->sfmmu_scdrttecnt[i] ==
			    scdp->scd_rttecnt[i]);
			atomic_add_long(&sfmmup->sfmmu_ttecnt[i],
			    sfmmup->sfmmu_scdrttecnt[i]);
			sfmmup->sfmmu_scdrttecnt[i] = 0;
		}
		sfmmup->sfmmu_scdp = NULL;

		SF_SCD_DECR_REF(srdp, scdp);
		return;
	}

	ASSERT(r_type != SFMMU_REGION_ISM ||
	    SFMMU_FLAGS_ISSET(sfmmup, HAT_ISMBUSY));
	ASSERT(scdp->scd_refcnt);
	ASSERT(!sfmmup->sfmmu_free);
	ASSERT(sfmmu_hat_lock_held(sfmmup));
	ASSERT(AS_LOCK_HELD(sfmmup->sfmmu_as));

	/*
	 * Wait for ISM maps to be updated.
	 */
	if (r_type != SFMMU_REGION_ISM) {
		while (SFMMU_FLAGS_ISSET(sfmmup, HAT_ISMBUSY) &&
		    sfmmup->sfmmu_scdp != NULL) {
			cv_wait(&sfmmup->sfmmu_tsb_cv,
			    HATLOCK_MUTEXP(hatlockp));
		}

		if (sfmmup->sfmmu_scdp == NULL) {
			sfmmu_hat_exit(hatlockp);
			return;
		}
		SFMMU_FLAGS_SET(sfmmup, HAT_ISMBUSY);
	}

	if (SFMMU_FLAGS_ISSET(sfmmup, HAT_JOIN_SCD)) {
		SFMMU_FLAGS_CLEAR(sfmmup, HAT_JOIN_SCD);
		/*
		 * Since HAT_JOIN_SCD was set our context
		 * is still invalid.
		 */
	} else {
		/*
		 * For a multi-thread process, we must stop
		 * all the other threads before leaving the scd.
		 */

		sfmmu_invalidate_ctx(sfmmup);
	}

	/* Clear all the rid's for ISM, delete flags, etc */
	ASSERT(SFMMU_FLAGS_ISSET(sfmmup, HAT_ISMBUSY));
	sfmmu_ism_hatflags(sfmmup, 0);

	/*
	 * Update sfmmu_ttecnt to include the rgn ttecnt for rgns that
	 * are in SCD before this sfmmup leaves the SCD.
	 */
	for (i = 0; i < mmu_page_sizes; i++) {
		ASSERT(sfmmup->sfmmu_scdrttecnt[i] ==
		    scdp->scd_rttecnt[i]);
		atomic_add_long(&sfmmup->sfmmu_ttecnt[i],
		    sfmmup->sfmmu_scdrttecnt[i]);
		sfmmup->sfmmu_scdrttecnt[i] = 0;
		/* update ismttecnt to include SCD ism before hat leaves SCD */
		sfmmup->sfmmu_ismttecnt[i] += sfmmup->sfmmu_scdismttecnt[i];
		sfmmup->sfmmu_scdismttecnt[i] = 0;
	}
	/* update tsb0 inflation count */
	sfmmup->sfmmu_tsb0_4minflcnt += scdp->scd_sfmmup->sfmmu_tsb0_4minflcnt;

	if (r_type != SFMMU_REGION_ISM) {
		SFMMU_FLAGS_CLEAR(sfmmup, HAT_ISMBUSY);
	}
	sfmmup->sfmmu_scdp = NULL;

	sfmmu_hat_exit(hatlockp);

	/*
	 * Unlink sfmmu from scd_sf_list this can be done without holding
	 * the hat lock as we hold the sfmmu_as lock which prevents
	 * hat_join_region from adding this thread to the scd again. Other
	 * threads check if sfmmu_scdp is NULL under hat lock and if it's NULL
	 * they won't get here, since sfmmu_leave_scd() clears sfmmu_scdp
	 * while holding the hat lock.
	 */
	mutex_enter(&scdp->scd_mutex);
	sfmmu_from_scd_list(&scdp->scd_sf_list, sfmmup);
	mutex_exit(&scdp->scd_mutex);
	SFMMU_STAT(sf_leave_scd);

	SF_SCD_DECR_REF(srdp, scdp);
	hatlockp = sfmmu_hat_enter(sfmmup);

}

/*
 * Unlink and free up an SCD structure with a reference count of 0.
 */
static void
sfmmu_destroy_scd(sf_srd_t *srdp, sf_scd_t *scdp, sf_region_map_t *scd_rmap)
{
	sfmmu_t *scsfmmup;
	sf_scd_t *sp;
	hatlock_t *shatlockp;
	int i, ret;

	mutex_enter(&srdp->srd_scd_mutex);
	for (sp = srdp->srd_scdp; sp != NULL; sp = sp->scd_next) {
		if (sp == scdp)
			break;
	}
	if (sp == NULL || sp->scd_refcnt) {
		mutex_exit(&srdp->srd_scd_mutex);
		return;
	}

	/*
	 * It is possible that the scd has been freed and reallocated with a
	 * different region map while we've been waiting for the srd_scd_mutex.
	 */
	SF_RGNMAP_EQUAL(scd_rmap, &sp->scd_region_map, ret);
	if (ret != 1) {
		mutex_exit(&srdp->srd_scd_mutex);
		return;
	}

	ASSERT(scdp->scd_sf_list == NULL);
	/*
	 * Unlink scd from srd_scdp list.
	 */
	sfmmu_remove_scd(&srdp->srd_scdp, scdp);
	mutex_exit(&srdp->srd_scd_mutex);

	sfmmu_unlink_scd_from_regions(srdp, scdp);

	/* Clear shared context tsb and release ctx */
	scsfmmup = scdp->scd_sfmmup;

	/*
	 * create a barrier so that scd will not be destroyed
	 * if other thread still holds the same shared hat lock.
	 * E.g., sfmmu_tsbmiss_exception() needs to acquire the
	 * shared hat lock before checking the shared tsb reloc flag.
	 */
	shatlockp = sfmmu_hat_enter(scsfmmup);
	sfmmu_hat_exit(shatlockp);

	sfmmu_free_scd_tsbs(scsfmmup);

	for (i = 0; i < SFMMU_L1_HMERLINKS; i++) {
		if (scsfmmup->sfmmu_hmeregion_links[i] != NULL) {
			kmem_free(scsfmmup->sfmmu_hmeregion_links[i],
			    SFMMU_L2_HMERLINKS_SIZE);
			scsfmmup->sfmmu_hmeregion_links[i] = NULL;
		}
	}
	kmem_cache_free(sfmmuid_cache, scsfmmup);
	kmem_cache_free(scd_cache, scdp);
	SFMMU_STAT(sf_destroy_scd);
}

/*
 * Modifies the HAT_CTX1_FLAG for each of the ISM segments which correspond to
 * bits which are set in the ism_region_map parameter. This flag indicates to
 * the tsbmiss handler that mapping for these segments should be loaded using
 * the shared context.
 */
static void
sfmmu_ism_hatflags(sfmmu_t *sfmmup, int addflag)
{
	sf_scd_t *scdp = sfmmup->sfmmu_scdp;
	ism_blk_t *ism_blkp;
	ism_map_t *ism_map;
	int i, rid;

	ASSERT(sfmmup->sfmmu_iblk != NULL);
	ASSERT(scdp != NULL);
	/*
	 * Note that the caller either set HAT_ISMBUSY flag or checked
	 * under hat lock that HAT_ISMBUSY was not set by another thread.
	 */
	ASSERT(sfmmu_hat_lock_held(sfmmup));

	ism_blkp = sfmmup->sfmmu_iblk;
	while (ism_blkp != NULL) {
		ism_map = ism_blkp->iblk_maps;
		for (i = 0; ism_map[i].imap_ismhat && i < ISM_MAP_SLOTS; i++) {
			rid = ism_map[i].imap_rid;
			if (rid == SFMMU_INVALID_ISMRID) {
				continue;
			}
			ASSERT(rid >= 0 && rid < SFMMU_MAX_ISM_REGIONS);
			if (SF_RGNMAP_TEST(scdp->scd_ismregion_map, rid) &&
			    addflag) {
				ism_map[i].imap_hatflags |=
				    HAT_CTX1_FLAG;
			} else {
				ism_map[i].imap_hatflags &=
				    ~HAT_CTX1_FLAG;
			}
		}
		ism_blkp = ism_blkp->iblk_next;
	}
}

static int
sfmmu_srd_lock_held(sf_srd_t *srdp)
{
	return (MUTEX_HELD(&srdp->srd_mutex));
}

/* ARGSUSED */
static int
sfmmu_scdcache_constructor(void *buf, void *cdrarg, int kmflags)
{
	sf_scd_t *scdp = (sf_scd_t *)buf;

	bzero(buf, sizeof (sf_scd_t));
	mutex_init(&scdp->scd_mutex, NULL, MUTEX_DEFAULT, NULL);
	return (0);
}

/* ARGSUSED */
static void
sfmmu_scdcache_destructor(void *buf, void *cdrarg)
{
	sf_scd_t *scdp = (sf_scd_t *)buf;

	mutex_destroy(&scdp->scd_mutex);
}

/*
 * The listp parameter is a pointer to a list of hmeblks which are partially
 * freed as result of calling sfmmu_hblk_hash_rm(), the last phase of the
 * freeing process is to cross-call all cpus to ensure that there are no
 * remaining cached references.
 *
 * If the local generation number is less than the global then we can free
 * hmeblks which are already on the pending queue as another cpu has completed
 * the cross-call.
 *
 * We cross-call to make sure that there are no threads on other cpus accessing
 * these hmblks and then complete the process of freeing them under the
 * following conditions:
 * 	The total number of pending hmeblks is greater than the threshold
 *	The reserve list has fewer than HBLK_RESERVE_CNT hmeblks
 *	It is at least 1 second since the last time we cross-called
 *
 * Otherwise, we add the hmeblks to the per-cpu pending queue.
 */
static void
sfmmu_hblks_list_purge(struct hme_blk **listp, int dontfree)
{
	struct hme_blk *hblkp, *pr_hblkp = NULL;
	int		count = 0;
	cpuset_t	cpuset = cpu_ready_set;
	cpu_hme_pend_t	*cpuhp;
	timestruc_t	now;
	int		one_second_expired = 0;

	gethrestime_lasttick(&now);

	for (hblkp = *listp; hblkp != NULL; hblkp = hblkp->hblk_next) {
		ASSERT(hblkp->hblk_shw_bit == 0);
		ASSERT(hblkp->hblk_shared == 0);
		count++;
		pr_hblkp = hblkp;
	}

	cpuhp = &cpu_hme_pend[CPU->cpu_seqid];
	mutex_enter(&cpuhp->chp_mutex);

	if ((cpuhp->chp_count + count) == 0) {
		mutex_exit(&cpuhp->chp_mutex);
		return;
	}

	if ((now.tv_sec - cpuhp->chp_timestamp) > 1) {
		one_second_expired  = 1;
	}

	if (!dontfree && (freehblkcnt < HBLK_RESERVE_CNT ||
	    (cpuhp->chp_count + count) > cpu_hme_pend_thresh ||
	    one_second_expired)) {
		/* Append global list to local */
		if (pr_hblkp == NULL) {
			*listp = cpuhp->chp_listp;
		} else {
			pr_hblkp->hblk_next = cpuhp->chp_listp;
		}
		cpuhp->chp_listp = NULL;
		cpuhp->chp_count = 0;
		cpuhp->chp_timestamp = now.tv_sec;
		mutex_exit(&cpuhp->chp_mutex);

		kpreempt_disable();
		CPUSET_DEL(cpuset, CPU->cpu_id);
		xt_sync(cpuset);
		xt_sync(cpuset);
		kpreempt_enable();

		/*
		 * At this stage we know that no trap handlers on other
		 * cpus can have references to hmeblks on the list.
		 */
		sfmmu_hblk_free(listp);
	} else if (*listp != NULL) {
		pr_hblkp->hblk_next = cpuhp->chp_listp;
		cpuhp->chp_listp = *listp;
		cpuhp->chp_count += count;
		*listp = NULL;
		mutex_exit(&cpuhp->chp_mutex);
	} else {
		mutex_exit(&cpuhp->chp_mutex);
	}
}

/*
 * Add an hmeblk to the the hash list.
 */
void
sfmmu_hblk_hash_add(struct hmehash_bucket *hmebp, struct hme_blk *hmeblkp,
	uint64_t hblkpa)
{
	ASSERT(SFMMU_HASH_LOCK_ISHELD(hmebp));
#ifdef	DEBUG
	if (hmebp->hmeblkp == NULL) {
		ASSERT(hmebp->hmeh_nextpa == HMEBLK_ENDPA);
	}
#endif /* DEBUG */

	hmeblkp->hblk_nextpa = hmebp->hmeh_nextpa;
	/*
	 * Since the TSB miss handler now does not lock the hash chain before
	 * walking it, make sure that the hmeblks nextpa is globally visible
	 * before we make the hmeblk globally visible by updating the chain root
	 * pointer in the hash bucket.
	 */
	membar_producer();
	hmebp->hmeh_nextpa = hblkpa;
	hmeblkp->hblk_next = hmebp->hmeblkp;
	hmebp->hmeblkp = hmeblkp;

}

/*
 * This function is the first part of a 2 part process to remove an hmeblk
 * from the hash chain. In this phase we unlink the hmeblk from the hash chain
 * but leave the next physical pointer unchanged. The hmeblk is then linked onto
 * a per-cpu pending list using the virtual address pointer.
 *
 * TSB miss trap handlers that start after this phase will no longer see
 * this hmeblk. TSB miss handlers that still cache this hmeblk in a register
 * can still use it for further chain traversal because we haven't yet modifed
 * the next physical pointer or freed it.
 *
 * In the second phase of hmeblk removal we'll issue a barrier xcall before
 * we reuse or free this hmeblk. This will make sure all lingering references to
 * the hmeblk after first phase disappear before we finally reclaim it.
 * This scheme eliminates the need for TSB miss handlers to lock hmeblk chains
 * during their traversal.
 *
 * The hmehash_mutex must be held when calling this function.
 *
 * Input:
 *	 hmebp - hme hash bucket pointer
 *	 hmeblkp - address of hmeblk to be removed
 *	 pr_hblk - virtual address of previous hmeblkp
 *	 listp - pointer to list of hmeblks linked by virtual address
 *	 free_now flag - indicates that a complete removal from the hash chains
 *			 is necessary.
 *
 * It is inefficient to use the free_now flag as a cross-call is required to
 * remove a single hmeblk from the hash chain but is necessary when hmeblks are
 * in short supply.
 */
void
sfmmu_hblk_hash_rm(struct hmehash_bucket *hmebp, struct hme_blk *hmeblkp,
    struct hme_blk *pr_hblk, struct hme_blk **listp,
    int free_now)
{
	int shw_size, vshift;
	struct hme_blk *shw_hblkp;
	uint_t		shw_mask, newshw_mask;
	caddr_t		vaddr;
	int		size;
	cpuset_t cpuset = cpu_ready_set;

	ASSERT(SFMMU_HASH_LOCK_ISHELD(hmebp));

	if (hmebp->hmeblkp == hmeblkp) {
		hmebp->hmeh_nextpa = hmeblkp->hblk_nextpa;
		hmebp->hmeblkp = hmeblkp->hblk_next;
	} else {
		pr_hblk->hblk_nextpa = hmeblkp->hblk_nextpa;
		pr_hblk->hblk_next = hmeblkp->hblk_next;
	}

	size = get_hblk_ttesz(hmeblkp);
	shw_hblkp = hmeblkp->hblk_shadow;
	if (shw_hblkp) {
		ASSERT(hblktosfmmu(hmeblkp) != KHATID);
		ASSERT(!hmeblkp->hblk_shared);
#ifdef	DEBUG
		if (mmu_page_sizes == max_mmu_page_sizes) {
			ASSERT(size < TTE256M);
		} else {
			ASSERT(size < TTE4M);
		}
#endif /* DEBUG */

		shw_size = get_hblk_ttesz(shw_hblkp);
		vaddr = (caddr_t)get_hblk_base(hmeblkp);
		vshift = vaddr_to_vshift(shw_hblkp->hblk_tag, vaddr, shw_size);
		ASSERT(vshift < 8);
		/*
		 * Atomically clear shadow mask bit
		 */
		do {
			shw_mask = shw_hblkp->hblk_shw_mask;
			ASSERT(shw_mask & (1 << vshift));
			newshw_mask = shw_mask & ~(1 << vshift);
			newshw_mask = atomic_cas_32(&shw_hblkp->hblk_shw_mask,
			    shw_mask, newshw_mask);
		} while (newshw_mask != shw_mask);
		hmeblkp->hblk_shadow = NULL;
	}
	hmeblkp->hblk_shw_bit = 0;

	if (hmeblkp->hblk_shared) {
#ifdef	DEBUG
		sf_srd_t	*srdp;
		sf_region_t	*rgnp;
		uint_t		rid;

		srdp = hblktosrd(hmeblkp);
		ASSERT(srdp != NULL && srdp->srd_refcnt != 0);
		rid = hmeblkp->hblk_tag.htag_rid;
		ASSERT(SFMMU_IS_SHMERID_VALID(rid));
		ASSERT(rid < SFMMU_MAX_HME_REGIONS);
		rgnp = srdp->srd_hmergnp[rid];
		ASSERT(rgnp != NULL);
		SFMMU_VALIDATE_SHAREDHBLK(hmeblkp, srdp, rgnp, rid);
#endif /* DEBUG */
		hmeblkp->hblk_shared = 0;
	}
	if (free_now) {
		kpreempt_disable();
		CPUSET_DEL(cpuset, CPU->cpu_id);
		xt_sync(cpuset);
		xt_sync(cpuset);
		kpreempt_enable();

		hmeblkp->hblk_nextpa = HMEBLK_ENDPA;
		hmeblkp->hblk_next = NULL;
	} else {
		/* Append hmeblkp to listp for processing later. */
		hmeblkp->hblk_next = *listp;
		*listp = hmeblkp;
	}
}

/*
 * This routine is called when memory is in short supply and returns a free
 * hmeblk of the requested size from the cpu pending lists.
 */
static struct hme_blk *
sfmmu_check_pending_hblks(int size)
{
	int i;
	struct hme_blk *hmeblkp = NULL, *last_hmeblkp;
	int found_hmeblk;
	cpuset_t cpuset = cpu_ready_set;
	cpu_hme_pend_t *cpuhp;

	/* Flush cpu hblk pending queues */
	for (i = 0; i < NCPU; i++) {
		cpuhp = &cpu_hme_pend[i];
		if (cpuhp->chp_listp != NULL)  {
			mutex_enter(&cpuhp->chp_mutex);
			if (cpuhp->chp_listp == NULL)  {
				mutex_exit(&cpuhp->chp_mutex);
				continue;
			}
			found_hmeblk = 0;
			last_hmeblkp = NULL;
			for (hmeblkp = cpuhp->chp_listp; hmeblkp != NULL;
			    hmeblkp = hmeblkp->hblk_next) {
				if (get_hblk_ttesz(hmeblkp) == size) {
					if (last_hmeblkp == NULL) {
						cpuhp->chp_listp =
						    hmeblkp->hblk_next;
					} else {
						last_hmeblkp->hblk_next =
						    hmeblkp->hblk_next;
					}
					ASSERT(cpuhp->chp_count > 0);
					cpuhp->chp_count--;
					found_hmeblk = 1;
					break;
				} else {
					last_hmeblkp = hmeblkp;
				}
			}
			mutex_exit(&cpuhp->chp_mutex);

			if (found_hmeblk) {
				kpreempt_disable();
				CPUSET_DEL(cpuset, CPU->cpu_id);
				xt_sync(cpuset);
				xt_sync(cpuset);
				kpreempt_enable();
				return (hmeblkp);
			}
		}
	}
	return (NULL);
}
