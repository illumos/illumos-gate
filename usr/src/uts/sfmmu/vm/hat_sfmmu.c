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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <sys/dtrace.h>
#include <vm/vm_dep.h>
#include <vm/xhat_sfmmu.h>
#include <sys/fpu/fpusystm.h>

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
 * WARNING: 512K pages MUST be disabled for ISM/DISM. If not
 * a process would page fault indefinitely if it tried to
 * access a 512K page.
 */
int	disable_ism_large_pages = (1 << TTE512K);
int	disable_large_pages = 0;
int	disable_auto_large_pages = 0;

/*
 * Private sfmmu data structures for hat management
 */
static struct kmem_cache *sfmmuid_cache;

/*
 * Private sfmmu data structures for ctx management
 */
static struct ctx	*ctxhand;	/* hand used while stealing ctxs */
static struct ctx	*ctxfree;	/* head of free ctx list */
static struct ctx	*ctxdirty;	/* head of dirty ctx list */

/*
 * Private sfmmu data structures for tsb management
 */
static struct kmem_cache *sfmmu_tsbinfo_cache;
static struct kmem_cache *sfmmu_tsb8k_cache;
static struct kmem_cache *sfmmu_tsb_cache[NLGRPS_MAX];
static vmem_t *kmem_tsb_arena;

/*
 * sfmmu static variables for hmeblk resource management.
 */
static vmem_t *hat_memload1_arena; /* HAT translation arena for sfmmu1_cache */
static struct kmem_cache *sfmmu8_cache;
static struct kmem_cache *sfmmu1_cache;
static struct kmem_cache *pa_hment_cache;

static kmutex_t 	ctx_list_lock;	/* mutex for ctx free/dirty lists */
static kmutex_t 	ism_mlist_lock;	/* mutex for ism mapping list */
/*
 * private data for ism
 */
static struct kmem_cache *ism_blk_cache;
static struct kmem_cache *ism_ment_cache;
#define	ISMID_STARTADDR	NULL

/*
 * Whether to delay TLB flushes and use Cheetah's flush-all support
 * when removing contexts from the dirty list.
 */
int delay_tlb_flush;
int disable_delay_tlb_flush;

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

/*
 * Kernel page relocation is enabled by default for non-caged
 * kernel pages.  This has little effect unless segkmem_reloc is
 * set, since by default kernel memory comes from inside the
 * kernel cage.
 */
int hat_kpr_enabled = 1;

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
			struct hmehash_bucket *, uint_t, hmeblk_tag, uint_t);
static caddr_t	sfmmu_hblk_unload(struct hat *, struct hme_blk *, caddr_t,
			caddr_t, demap_range_t *, uint_t);
static caddr_t	sfmmu_hblk_sync(struct hat *, struct hme_blk *, caddr_t,
			caddr_t, int);
static void	sfmmu_hblk_free(struct hmehash_bucket *, struct hme_blk *,
			uint64_t, struct hme_blk **);
static void	sfmmu_hblks_list_purge(struct hme_blk **);
static uint_t	sfmmu_get_free_hblk(struct hme_blk **, uint_t);
static uint_t	sfmmu_put_free_hblk(struct hme_blk *, uint_t);
static struct hme_blk *sfmmu_hblk_steal(int);
static int	sfmmu_steal_this_hblk(struct hmehash_bucket *,
			struct hme_blk *, uint64_t, uint64_t,
			struct hme_blk *);
static caddr_t	sfmmu_hblk_unlock(struct hme_blk *, caddr_t, caddr_t);

static void	sfmmu_memload_batchsmall(struct hat *, caddr_t, page_t **,
		    uint_t, uint_t, pgcnt_t);
void		sfmmu_tteload(struct hat *, tte_t *, caddr_t, page_t *,
			uint_t);
static int	sfmmu_tteload_array(sfmmu_t *, tte_t *, caddr_t, page_t **,
			uint_t);
static struct hmehash_bucket *sfmmu_tteload_acquire_hashbucket(sfmmu_t *,
					caddr_t, int);
static struct hme_blk *sfmmu_tteload_find_hmeblk(sfmmu_t *,
			struct hmehash_bucket *, caddr_t, uint_t, uint_t);
static int	sfmmu_tteload_addentry(sfmmu_t *, struct hme_blk *, tte_t *,
			caddr_t, page_t **, uint_t);
static void	sfmmu_tteload_release_hashbucket(struct hmehash_bucket *);

static int	sfmmu_pagearray_setup(caddr_t, page_t **, tte_t *, int);
pfn_t		sfmmu_uvatopfn(caddr_t, sfmmu_t *);
void		sfmmu_memtte(tte_t *, pfn_t, uint_t, int);
static void	sfmmu_vac_conflict(struct hat *, caddr_t, page_t *);
static int	sfmmu_vacconflict_array(caddr_t, page_t *, int *);
static int	tst_tnc(page_t *pp, pgcnt_t);
static void	conv_tnc(page_t *pp, int);

static struct ctx *sfmmu_get_ctx(sfmmu_t *);
static void	sfmmu_free_ctx(sfmmu_t *, struct ctx *);
static void	sfmmu_free_sfmmu(sfmmu_t *);

static void	sfmmu_gettte(struct hat *, caddr_t, tte_t *);
static void	sfmmu_ttesync(struct hat *, caddr_t, tte_t *, page_t *);
static void	sfmmu_chgattr(struct hat *, caddr_t, size_t, uint_t, int);

static cpuset_t	sfmmu_pageunload(page_t *, struct sf_hment *, int);
static void	hat_pagereload(struct page *, struct page *);
static cpuset_t	sfmmu_pagesync(page_t *, struct sf_hment *, uint_t);
static void	sfmmu_page_cache_array(page_t *, int, int, pgcnt_t);
static void	sfmmu_page_cache(page_t *, int, int, int);

static void	sfmmu_tlbcache_demap(caddr_t, sfmmu_t *, struct hme_blk *,
			pfn_t, int, int, int, int);
static void	sfmmu_ismtlbcache_demap(caddr_t, sfmmu_t *, struct hme_blk *,
			pfn_t, int);
static void	sfmmu_tlb_demap(caddr_t, sfmmu_t *, struct hme_blk *, int, int);
static void	sfmmu_tlb_range_demap(demap_range_t *);
static void	sfmmu_tlb_ctx_demap(sfmmu_t *);
static void	sfmmu_tlb_all_demap(void);
static void	sfmmu_tlb_swap_ctx(sfmmu_t *, struct ctx *);
static void	sfmmu_sync_mmustate(sfmmu_t *);

static void 	sfmmu_tsbinfo_setup_phys(struct tsb_info *, pfn_t);
static int	sfmmu_tsbinfo_alloc(struct tsb_info **, int, int, uint_t,
			sfmmu_t *);
static void	sfmmu_tsb_free(struct tsb_info *);
static void	sfmmu_tsbinfo_free(struct tsb_info *);
static int	sfmmu_init_tsbinfo(struct tsb_info *, int, int, uint_t,
			sfmmu_t *);

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

static void	sfmmu_cache_flush(pfn_t, int);
void		sfmmu_cache_flushcolor(int, pfn_t);
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
static void	sfmmu_free_hblks(sfmmu_t *, caddr_t, caddr_t, int);

static void	sfmmu_reuse_ctx(struct ctx *, sfmmu_t *);
static void	sfmmu_disallow_ctx_steal(sfmmu_t *);
static void	sfmmu_allow_ctx_steal(sfmmu_t *);

static void	sfmmu_rm_large_mappings(page_t *, int);

static void	hat_lock_init(void);
static void	hat_kstat_init(void);
static int	sfmmu_kstat_percpu_update(kstat_t *ksp, int rw);
static void	sfmmu_check_page_sizes(sfmmu_t *, int);
static int	fnd_mapping_sz(page_t *);
static void	iment_add(struct ism_ment *,  struct hat *);
static void	iment_sub(struct ism_ment *, struct hat *);
static pgcnt_t	ism_tsb_entries(sfmmu_t *, int szc);
extern void	sfmmu_setup_tsbinfo(sfmmu_t *);
extern void	sfmmu_clear_utsbinfo(void);

/* kpm prototypes */
static caddr_t	sfmmu_kpm_mapin(page_t *);
static void	sfmmu_kpm_mapout(page_t *, caddr_t);
static int	sfmmu_kpme_lookup(struct kpme *, page_t *);
static void	sfmmu_kpme_add(struct kpme *, page_t *);
static void	sfmmu_kpme_sub(struct kpme *, page_t *);
static caddr_t	sfmmu_kpm_getvaddr(page_t *, int *);
static int	sfmmu_kpm_fault(caddr_t, struct memseg *, page_t *);
static int	sfmmu_kpm_fault_small(caddr_t, struct memseg *, page_t *);
static void	sfmmu_kpm_vac_conflict(page_t *, caddr_t);
static void	sfmmu_kpm_pageunload(page_t *);
static void	sfmmu_kpm_vac_unload(page_t *, caddr_t);
static void	sfmmu_kpm_demap_large(caddr_t);
static void	sfmmu_kpm_demap_small(caddr_t);
static void	sfmmu_kpm_demap_tlbs(caddr_t, int);
static void	sfmmu_kpm_hme_unload(page_t *);
static kpm_hlk_t *sfmmu_kpm_kpmp_enter(page_t *, pgcnt_t);
static void	sfmmu_kpm_kpmp_exit(kpm_hlk_t *kpmp);
static void	sfmmu_kpm_page_cache(page_t *, int, int);

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
struct ctx	*ctxs;			/* used by <machine/mmu.c> */
uint_t		nctxs;			/* total number of contexts */

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

/*
 * Size to use for TSB slabs.  Future platforms that support page sizes
 * larger than 4M may wish to change these values, and provide their own
 * assembly macros for building and decoding the TSB base register contents.
 */
uint_t	tsb_slab_size = MMU_PAGESIZE4M;
uint_t	tsb_slab_shift = MMU_PAGESHIFT4M;
uint_t	tsb_slab_ttesz = TTE4M;
uint_t	tsb_slab_mask = 0x1ff;	/* 4M page alignment for 8K pfn */

/* largest TSB size to grow to, will be smaller on smaller memory systems */
int	tsb_max_growsize = UTSB_MAX_SZCODE;

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
int tsb_sectsb_threshold = 8;

/*
 * kstat data
 */
struct sfmmu_global_stat sfmmu_global_stat;
struct sfmmu_tsbsize_stat sfmmu_tsbsize_stat;

/*
 * Global data
 */
sfmmu_t 	*ksfmmup;		/* kernel's hat id */
struct ctx 	*kctx;			/* kernel's context */

#ifdef DEBUG
static void	chk_tte(tte_t *, tte_t *, tte_t *, struct hme_blk *);
#endif

/* sfmmu locking operations */
static kmutex_t *sfmmu_mlspl_enter(struct page *, int);
static int	sfmmu_mlspl_held(struct page *, int);

static kmutex_t *sfmmu_page_enter(page_t *);
static void	sfmmu_page_exit(kmutex_t *);
static int	sfmmu_page_spl_held(struct page *);

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

/*
 * Array of mutexes protecting a page's mapping list and p_nrm field.
 *
 * The hash function looks complicated, but is made up so that:
 *
 * "pp" not shifted, so adjacent pp values will hash to different cache lines
 *  (8 byte alignment * 8 bytes/mutes == 64 byte coherency subblock)
 *
 * "pp" >> mml_shift, incorporates more source bits into the hash result
 *
 *  "& (mml_table_size - 1), should be faster than using remainder "%"
 *
 * Hopefully, mml_table, mml_table_size and mml_shift are all in the same
 * cacheline, since they get declared next to each other below. We'll trust
 * ld not to do something random.
 */
#ifdef	DEBUG
int mlist_hash_debug = 0;
#define	MLIST_HASH(pp)	(mlist_hash_debug ? &mml_table[0] : \
	&mml_table[((uintptr_t)(pp) + \
	((uintptr_t)(pp) >> mml_shift)) & (mml_table_sz - 1)])
#else	/* !DEBUG */
#define	MLIST_HASH(pp)   &mml_table[ \
	((uintptr_t)(pp) + ((uintptr_t)(pp) >> mml_shift)) & (mml_table_sz - 1)]
#endif	/* !DEBUG */

kmutex_t		*mml_table;
uint_t			mml_table_sz;	/* must be a power of 2 */
uint_t			mml_shift;	/* log2(mml_table_sz) + 3 for align */

/*
 * kpm_page lock hash.
 * All slots should be used equally and 2 adjacent kpm_page_t's
 * shouldn't have their mutexes in the same cache line.
 */
#ifdef	DEBUG
int kpmp_hash_debug = 0;
#define	KPMP_HASH(kpp)	(kpmp_hash_debug ? &kpmp_table[0] : &kpmp_table[ \
	((uintptr_t)(kpp) + ((uintptr_t)(kpp) >> kpmp_shift)) \
	& (kpmp_table_sz - 1)])
#else	/* !DEBUG */
#define	KPMP_HASH(kpp)	&kpmp_table[ \
	((uintptr_t)(kpp) + ((uintptr_t)(kpp) >> kpmp_shift)) \
	& (kpmp_table_sz - 1)]
#endif	/* DEBUG */

kpm_hlk_t	*kpmp_table;
uint_t		kpmp_table_sz;	/* must be a power of 2 */
uchar_t		kpmp_shift;

#ifdef	DEBUG
#define	KPMP_SHASH(kpp)	(kpmp_hash_debug ? &kpmp_stable[0] : &kpmp_stable[ \
	(((uintptr_t)(kpp) << kpmp_shift) + (uintptr_t)(kpp)) \
	& (kpmp_stable_sz - 1)])
#else	/* !DEBUG */
#define	KPMP_SHASH(kpp)	&kpmp_stable[ \
	(((uintptr_t)(kpp) << kpmp_shift) + (uintptr_t)(kpp)) \
	& (kpmp_stable_sz - 1)]
#endif	/* DEBUG */

kpm_shlk_t	*kpmp_stable;
uint_t		kpmp_stable_sz;	/* must be a power of 2 */

/*
 * SPL_HASH was improved to avoid false cache line sharing
 */
#define	SPL_TABLE_SIZE	128
#define	SPL_MASK	(SPL_TABLE_SIZE - 1)
#define	SPL_SHIFT	7		/* log2(SPL_TABLE_SIZE) */

#define	SPL_INDEX(pp) \
	((((uintptr_t)(pp) >> SPL_SHIFT) ^ \
	((uintptr_t)(pp) >> (SPL_SHIFT << 1))) & \
	(SPL_TABLE_SIZE - 1))

#define	SPL_HASH(pp)    \
	(&sfmmu_page_lock[SPL_INDEX(pp) & SPL_MASK].pad_mutex)

static	pad_mutex_t	sfmmu_page_lock[SPL_TABLE_SIZE];


/*
 * hat_unload_callback() will group together callbacks in order
 * to avoid xt_sync() calls.  This is the maximum size of the group.
 */
#define	MAX_CB_ADDR	32

#ifdef DEBUG

/*
 * Debugging trace ring buffer for stolen and freed ctxs.  The
 * stolen_ctxs[] array is protected by the ctx_trace_mutex.
 */
struct ctx_trace stolen_ctxs[TRSIZE];
struct ctx_trace *ctx_trace_first = &stolen_ctxs[0];
struct ctx_trace *ctx_trace_last = &stolen_ctxs[TRSIZE-1];
struct ctx_trace *ctx_trace_ptr = &stolen_ctxs[0];
kmutex_t ctx_trace_mutex;
uint_t	num_ctx_stolen = 0;

int	ism_debug = 0;

#endif /* DEBUG */

tte_t	hw_tte;
static ulong_t sfmmu_dmr_maxbit = DMR_MAXBIT;

/*
 * kpm virtual address to physical address
 */
#define	SFMMU_KPM_VTOP(vaddr, paddr) {					\
	uintptr_t r, v;							\
									\
	r = ((vaddr) - kpm_vbase) >> (uintptr_t)kpm_size_shift;		\
	(paddr) = (vaddr) - kpm_vbase;					\
	if (r != 0) {							\
		v = ((uintptr_t)(vaddr) >> MMU_PAGESHIFT) &		\
		    vac_colors_mask;					\
		(paddr) -= r << kpm_size_shift;				\
		if (r > v)						\
			(paddr) += (r - v) << MMU_PAGESHIFT;		\
		else							\
			(paddr) -= r << MMU_PAGESHIFT;			\
	}								\
}

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
 * If the computed size code is less than the current tsb_max_growsize, we set
 * tsb_max_growsize to the computed size code.  In the case where the computed
 * size code is greater than tsb_max_growsize, we have these restrictions that
 * apply to increasing tsb_max_growsize:
 *	1) TSBs can't grow larger than the TSB slab size
 *	2) TSBs can't grow larger than UTSB_MAX_SZCODE.
 */
#define	SFMMU_SET_TSB_MAX_GROWSIZE(pages) {				\
	int	i, szc;							\
									\
	i = highbit(pages);						\
	if ((1 << (i - 1)) == (pages))					\
		i--;		/* 2^n case, round down */		\
	szc = i - TSB_START_SIZE;					\
	if (szc < tsb_max_growsize)					\
		tsb_max_growsize = szc;					\
	else if ((szc > tsb_max_growsize) &&				\
	    (szc <= tsb_slab_shift - (TSB_START_SIZE + TSB_ENTRY_SHIFT))) \
		tsb_max_growsize = MIN(szc, UTSB_MAX_SZCODE);		\
}

/*
 * Given a pointer to an sfmmu and a TTE size code, return a pointer to the
 * tsb_info which handles that TTE size.
 */
#define	SFMMU_GET_TSBINFO(tsbinfop, sfmmup, tte_szc)			\
	(tsbinfop) = (sfmmup)->sfmmu_tsb;				\
	ASSERT(sfmmu_hat_lock_held(sfmmup));				\
	if ((tte_szc) >= TTE4M)						\
		(tsbinfop) = (tsbinfop)->tsb_next;

/*
 * Return the number of mappings present in the HAT
 * for a particular process and page size.
 */
#define	SFMMU_TTE_CNT(sfmmup, szc)					\
	(sfmmup)->sfmmu_iblk?						\
	    (sfmmup)->sfmmu_ismttecnt[(szc)] +				\
	    (sfmmup)->sfmmu_ttecnt[(szc)] :				\
	    (sfmmup)->sfmmu_ttecnt[(szc)];

/*
 * Macro to use to unload entries from the TSB.
 * It has knowledge of which page sizes get replicated in the TSB
 * and will call the appropriate unload routine for the appropriate size.
 */
#define	SFMMU_UNLOAD_TSB(addr, sfmmup, hmeblkp)				\
{									\
	int ttesz = get_hblk_ttesz(hmeblkp);				\
	if (ttesz == TTE8K || ttesz == TTE4M) {				\
		sfmmu_unload_tsb(sfmmup, addr, ttesz);			\
	} else {							\
		caddr_t sva = (caddr_t)get_hblk_base(hmeblkp);		\
		caddr_t eva = sva + get_hblk_span(hmeblkp);		\
		ASSERT(addr >= sva && addr < eva);			\
		sfmmu_unload_tsb_range(sfmmup, sva, eva, ttesz);	\
	}								\
}


/* Update tsb_alloc_hiwater after memory is configured. */
/*ARGSUSED*/
static void
sfmmu_update_tsb_post_add(void *arg, pgcnt_t delta_pages)
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
sfmmu_update_tsb_pre_del(void *arg, pgcnt_t delta_pages)
{
	return (0);
}

/* Update tsb_alloc_hiwater after memory fails to be unconfigured. */
/*ARGSUSED*/
static void
sfmmu_update_tsb_post_del(void *arg, pgcnt_t delta_pages, int cancelled)
{
	/*
	 * Whether the delete was cancelled or not, just go ahead and update
	 * tsb_alloc_hiwater and tsb_max_growsize.
	 */
	SFMMU_SET_TSB_ALLOC_HIWATER(physmem);
	SFMMU_SET_TSB_MAX_GROWSIZE(physmem);
}

static kphysm_setup_vector_t sfmmu_update_tsb_vec = {
	KPHYSM_SETUP_VECTOR_VERSION,	/* version */
	sfmmu_update_tsb_post_add,	/* post_add */
	sfmmu_update_tsb_pre_del,	/* pre_del */
	sfmmu_update_tsb_post_del	/* post_del */
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
		extern int	disable_text_largepages;
		extern int	disable_initdata_largepages;

		szc_2_userszc[i] = (uint_t)-1;
		userszc_2_szc[i] = (uint_t)-1;

		if ((mmu_exported_pagesize_mask & (1 << i)) == 0) {
			disable_large_pages |= (1 << i);
			disable_ism_large_pages |= (1 << i);
			disable_text_largepages |= (1 << i);
			disable_initdata_largepages |= (1 << i);
		} else {
			szc_2_userszc[i] = mmu_exported_page_sizes;
			userszc_2_szc[mmu_exported_page_sizes] = i;
			mmu_exported_page_sizes++;
		}
	}

	disable_auto_large_pages = disable_large_pages;

	/*
	 * Initialize mmu-specific large page sizes.
	 */
	if ((mmu_page_sizes == max_mmu_page_sizes) &&
	    (&mmu_large_pages_disabled)) {
		disable_large_pages |= mmu_large_pages_disabled(HAT_LOAD);
		disable_ism_large_pages |=
		    mmu_large_pages_disabled(HAT_LOAD_SHARE);
		disable_auto_large_pages |=
		    mmu_large_pages_disabled(HAT_LOAD_AUTOLPG);
	}

}

/*
 * Initialize the hardware address translation structures.
 */
void
hat_init(void)
{
	struct ctx	*ctx;
	struct ctx	*cur_ctx = NULL;
	int 		i;

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
	}
	for (i = 0; i < uhmehash_num; i++) {
		mutex_init(&uhme_hash[i].hmehash_mutex, NULL,
		    MUTEX_DEFAULT, NULL);
	}
	khmehash_num--;		/* make sure counter starts from 0 */
	uhmehash_num--;		/* make sure counter starts from 0 */

	/*
	 * Initialize ctx structures and list lock.
	 * We keep two lists of ctxs. The "free" list contains contexts
	 * ready to use.  The "dirty" list contains contexts that are OK
	 * to use after flushing the TLBs of any stale mappings.
	 */
	mutex_init(&ctx_list_lock, NULL, MUTEX_DEFAULT, NULL);
	kctx = &ctxs[KCONTEXT];
	ctx = &ctxs[NUM_LOCKED_CTXS];
	ctxhand = ctxfree = ctx;		/* head of free list */
	ctxdirty = NULL;
	for (i = NUM_LOCKED_CTXS; i < nctxs; i++) {
		cur_ctx = &ctxs[i];
		cur_ctx->ctx_flags = CTX_FREE_FLAG;
		cur_ctx->ctx_free = &ctxs[i + 1];
	}
	cur_ctx->ctx_free = NULL;		/* tail of free list */

	/*
	 * Intialize ism mapping list lock.
	 */
	mutex_init(&ism_mlist_lock, NULL, MUTEX_DEFAULT, NULL);

	sfmmuid_cache = kmem_cache_create("sfmmuid_cache", sizeof (sfmmu_t),
	    0, sfmmu_idcache_constructor, sfmmu_idcache_destructor,
	    NULL, NULL, NULL, 0);

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

	/* Set tsb_max_growsize. */
	SFMMU_SET_TSB_MAX_GROWSIZE(physmem);

	/*
	 * On smaller memory systems, allocate TSB memory in 512K chunks
	 * instead of the default 4M slab size.  The trap handlers need to
	 * be patched with the final slab shift since they need to be able
	 * to construct the TSB pointer at runtime.
	 */
	if ((tsb_max_growsize <= TSB_512K_SZCODE) &&
	    !(disable_large_pages & (1 << TTE512K))) {
		tsb_slab_size = MMU_PAGESIZE512K;
		tsb_slab_shift = MMU_PAGESHIFT512K;
		tsb_slab_ttesz = TTE512K;
		tsb_slab_mask = 0x3f;	/* 512K page alignment for 8K pfn */
	}

	/*
	 * Set up memory callback to update tsb_alloc_hiwater and
	 * tsb_max_growsize.
	 */
	i = kphysm_setup_func_register(&sfmmu_update_tsb_vec, (void *) 0);
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
	 */
	kmem_tsb_arena = vmem_create("kmem_tsb", NULL, 0, tsb_slab_size,
	    sfmmu_vmem_xalloc_aligned_wrapper, vmem_xfree, heap_arena,
	    0, VM_SLEEP);

	if (tsb_lgrp_affinity) {
		char s[50];
		for (i = 0; i < NLGRPS_MAX; i++) {
			(void) sprintf(s, "kmem_tsb_lgrp%d", i);
			kmem_tsb_default_arena[i] =
			    vmem_create(s, NULL, 0, PAGESIZE,
			    sfmmu_tsb_segkmem_alloc, sfmmu_tsb_segkmem_free,
			    kmem_tsb_arena, 0, VM_SLEEP | VM_BESTFIT);
			(void) sprintf(s, "sfmmu_tsb_lgrp%d_cache", i);
			sfmmu_tsb_cache[i] = kmem_cache_create(s, PAGESIZE,
			    PAGESIZE, NULL, NULL, NULL, NULL,
			    kmem_tsb_default_arena[i], 0);
		}
	} else {
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
	    segkmem_alloc_permanent, segkmem_free, heap_arena, 0, VM_SLEEP);

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
	AS_LOCK_ENTER(&kas, &kas.a_lock, RW_WRITER);
	kas.a_hat = hat_alloc(&kas);
	AS_LOCK_EXIT(&kas, &kas.a_lock);

	/*
	 * Initialize hblk_reserve.
	 */
	((struct hme_blk *)hblk_reserve)->hblk_nextpa =
				va_to_pa((caddr_t)hblk_reserve);

#ifndef sun4v
	/*
	 * Reserve some kernel virtual address space for the locked TTEs
	 * that allow us to probe the TSB from TL>0.
	 */
	utsb_vabase = vmem_xalloc(heap_arena, tsb_slab_size, tsb_slab_size,
		0, 0, NULL, NULL, VM_SLEEP);
	utsb4m_vabase = vmem_xalloc(heap_arena, tsb_slab_size, tsb_slab_size,
		0, 0, NULL, NULL, VM_SLEEP);
#endif

	/*
	 * The big page VAC handling code assumes VAC
	 * will not be bigger than the smallest big
	 * page- which is 64K.
	 */
	if (TTEPAGES(TTE64K) < CACHE_NUM_COLOR) {
		cmn_err(CE_PANIC, "VAC too big!");
	}

	(void) xhat_init();

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
}

/*
 * Initialize locking for the hat layer, called early during boot.
 */
static void
hat_lock_init()
{
	int i;
	struct ctx *ctx;

	/*
	 * initialize the array of mutexes protecting a page's mapping
	 * list and p_nrm field.
	 */
	for (i = 0; i < mml_table_sz; i++)
		mutex_init(&mml_table[i], NULL, MUTEX_DEFAULT, NULL);

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

#ifdef	DEBUG
	mutex_init(&ctx_trace_mutex, NULL, MUTEX_DEFAULT, NULL);
#endif	/* DEBUG */

	for (ctx = ctxs, i = 0; i < nctxs; i++, ctx++) {
		rw_init(&ctx->ctx_rwlock, NULL, RW_DEFAULT, NULL);
	}
}

extern caddr_t kmem64_base, kmem64_end;

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
	struct ctx *ctx;
	int i;
	extern uint_t get_color_start(struct as *);

	ASSERT(AS_WRITE_HELD(as, &as->a_lock));
	sfmmup = kmem_cache_alloc(sfmmuid_cache, KM_SLEEP);
	sfmmup->sfmmu_as = as;
	sfmmup->sfmmu_flags = 0;

	if (as == &kas) {
		ctx = kctx;
		ksfmmup = sfmmup;
		sfmmup->sfmmu_cnum = ctxtoctxnum(ctx);
		ASSERT(sfmmup->sfmmu_cnum == KCONTEXT);
		sfmmup->sfmmu_cext = 0;
		ctx->ctx_sfmmu = sfmmup;
		ctx->ctx_flags = 0;
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
		sfmmup->sfmmu_cnum = INVALID_CONTEXT;
		sfmmup->sfmmu_cext = 0;
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
		sfmmup->sfmmu_flags = HAT_SWAPPED;
		ASSERT(sfmmup->sfmmu_tsb != NULL);
	}
	sfmmu_setup_tsbinfo(sfmmup);
	for (i = 0; i < max_mmu_page_sizes; i++) {
		sfmmup->sfmmu_ttecnt[i] = 0;
		sfmmup->sfmmu_ismttecnt[i] = 0;
		sfmmup->sfmmu_pgsz[i] = TTE8K;
	}

	sfmmup->sfmmu_iblk = NULL;
	sfmmup->sfmmu_ismhat = 0;
	sfmmup->sfmmu_ismblkpa = (uint64_t)-1;
	if (sfmmup == ksfmmup) {
		CPUSET_ALL(sfmmup->sfmmu_cpusran);
	} else {
		CPUSET_ZERO(sfmmup->sfmmu_cpusran);
	}
	sfmmup->sfmmu_free = 0;
	sfmmup->sfmmu_rmstat = 0;
	sfmmup->sfmmu_clrbin = sfmmup->sfmmu_clrstart;
	sfmmup->sfmmu_xhat_provider = NULL;
	cv_init(&sfmmup->sfmmu_tsb_cv, NULL, CV_DEFAULT, NULL);
	return (sfmmup);
}

/*
 * Hat_setup, makes an address space context the current active one.
 * In sfmmu this translates to setting the secondary context with the
 * corresponding context.
 */
void
hat_setup(struct hat *sfmmup, int allocflag)
{
	struct ctx *ctx;
	uint_t ctx_num;
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

		sfmmu_disallow_ctx_steal(sfmmup);

		kpreempt_disable();

		ctx = sfmmutoctx(sfmmup);
		CPUSET_ADD(sfmmup->sfmmu_cpusran, CPU->cpu_id);
		ctx_num = ctxtoctxnum(ctx);
		ASSERT(sfmmup == ctx->ctx_sfmmu);
		ASSERT(ctx_num >= NUM_LOCKED_CTXS);
		sfmmu_setctx_sec(ctx_num);
		sfmmu_load_mmustate(sfmmup);

		kpreempt_enable();

		/*
		 * Allow ctx to be stolen.
		 */
		sfmmu_allow_ctx_steal(sfmmup);
		sfmmu_hat_exit(hatlockp);
	} else {
		ASSERT(allocflag == HAT_ALLOC);

		hatlockp = sfmmu_hat_enter(sfmmup);
		kpreempt_disable();

		CPUSET_ADD(sfmmup->sfmmu_cpusran, CPU->cpu_id);
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
	ASSERT(AS_WRITE_HELD(sfmmup->sfmmu_as, &sfmmup->sfmmu_as->a_lock));
	ASSERT(sfmmup != ksfmmup);
	ASSERT(sfmmup->sfmmu_xhat_provider == NULL);

	sfmmup->sfmmu_free = 1;
}

void
hat_free_end(struct hat *sfmmup)
{
	int i;

	ASSERT(sfmmup->sfmmu_xhat_provider == NULL);
	if (sfmmup->sfmmu_ismhat) {
		for (i = 0; i < mmu_page_sizes; i++) {
			sfmmup->sfmmu_ttecnt[i] = 0;
			sfmmup->sfmmu_ismttecnt[i] = 0;
		}
	} else {
		/* EMPTY */
		ASSERT(sfmmup->sfmmu_ttecnt[TTE8K] == 0);
		ASSERT(sfmmup->sfmmu_ttecnt[TTE64K] == 0);
		ASSERT(sfmmup->sfmmu_ttecnt[TTE512K] == 0);
		ASSERT(sfmmup->sfmmu_ttecnt[TTE4M] == 0);
		ASSERT(sfmmup->sfmmu_ttecnt[TTE32M] == 0);
		ASSERT(sfmmup->sfmmu_ttecnt[TTE256M] == 0);
	}

	if (sfmmup->sfmmu_rmstat) {
		hat_freestat(sfmmup->sfmmu_as, NULL);
	}
	if (!delay_tlb_flush) {
		sfmmu_tlb_ctx_demap(sfmmup);
		xt_sync(sfmmup->sfmmu_cpusran);
	} else {
		SFMMU_STAT(sf_tlbflush_deferred);
	}
	sfmmu_free_ctx(sfmmup, sfmmutoctx(sfmmup));
	while (sfmmup->sfmmu_tsb != NULL) {
		struct tsb_info *next = sfmmup->sfmmu_tsb->tsb_next;
		sfmmu_tsbinfo_free(sfmmup->sfmmu_tsb);
		sfmmup->sfmmu_tsb = next;
	}
	sfmmu_free_sfmmu(sfmmup);

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
	ASSERT(hat->sfmmu_xhat_provider == NULL);
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
	struct ctx *ctx;
	int cnum;
	int i;
	uint64_t hblkpa, prevpa, nx_pa;
	struct hme_blk *list = NULL;
	hatlock_t *hatlockp;
	struct tsb_info *tsbinfop;
	struct free_tsb {
		struct free_tsb *next;
		struct tsb_info *tsbinfop;
	};			/* free list of TSBs */
	struct free_tsb *freelist, *last, *next;

	ASSERT(sfmmup->sfmmu_xhat_provider == NULL);
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
		hblkpa = hmebp->hmeh_nextpa;
		prevpa = 0;
		pr_hblk = NULL;
		while (hmeblkp) {

			ASSERT(!hmeblkp->hblk_xhat_bit);

			if ((hmeblkp->hblk_tag.htag_id == sfmmup) &&
			    !hmeblkp->hblk_shw_bit && !hmeblkp->hblk_lckcnt) {
				(void) sfmmu_hblk_unload(sfmmup, hmeblkp,
					(caddr_t)get_hblk_base(hmeblkp),
					get_hblk_endaddr(hmeblkp),
					NULL, HAT_UNLOAD);
			}
			nx_hblk = hmeblkp->hblk_next;
			nx_pa = hmeblkp->hblk_nextpa;
			if (!hmeblkp->hblk_vcnt && !hmeblkp->hblk_hmecnt) {
				ASSERT(!hmeblkp->hblk_lckcnt);
				sfmmu_hblk_hash_rm(hmebp, hmeblkp,
					prevpa, pr_hblk);
				sfmmu_hblk_free(hmebp, hmeblkp, hblkpa, &list);
			} else {
				pr_hblk = hmeblkp;
				prevpa = hblkpa;
			}
			hmeblkp = nx_hblk;
			hblkpa = nx_pa;
		}
		SFMMU_HASH_UNLOCK(hmebp);
	}

	sfmmu_hblks_list_purge(&list);

	/*
	 * Now free up the ctx so that others can reuse it.
	 */
	hatlockp = sfmmu_hat_enter(sfmmup);
	ctx = sfmmutoctx(sfmmup);
	cnum = ctxtoctxnum(ctx);

	if (cnum != INVALID_CONTEXT) {
		rw_enter(&ctx->ctx_rwlock, RW_WRITER);
		if (sfmmup->sfmmu_cnum == cnum) {
			sfmmu_reuse_ctx(ctx, sfmmup);
			/*
			 * Put ctx back to the free list.
			 */
			mutex_enter(&ctx_list_lock);
			CTX_SET_FLAGS(ctx, CTX_FREE_FLAG);
			ctx->ctx_free = ctxfree;
			ctxfree = ctx;
			mutex_exit(&ctx_list_lock);
		}
		rw_exit(&ctx->ctx_rwlock);
	}

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
	ASSERT(hat->sfmmu_xhat_provider == NULL);
	ASSERT((flag == 0) || (flag == HAT_DUP_ALL) || (flag == HAT_DUP_COW));

	if (flag == HAT_DUP_COW) {
		panic("hat_dup: HAT_DUP_COW not supported");
	}
	return (0);
}

/*
 * Set up addr to map to page pp with protection prot.
 * As an optimization we also load the TSB with the
 * corresponding tte but it is no big deal if  the tte gets kicked out.
 */
void
hat_memload(struct hat *hat, caddr_t addr, struct page *pp,
	uint_t attr, uint_t flags)
{
	tte_t tte;


	ASSERT(hat != NULL);
	ASSERT(PAGE_LOCKED(pp));
	ASSERT(!((uintptr_t)addr & MMU_PAGEOFFSET));
	ASSERT(!(flags & ~SFMMU_LOAD_ALLFLAG));
	ASSERT(!(attr & ~SFMMU_LOAD_ALLATTR));

	if (PP_ISFREE(pp)) {
		panic("hat_memload: loading a mapping to free page %p",
		    (void *)pp);
	}

	if (hat->sfmmu_xhat_provider) {
		XHAT_MEMLOAD(hat, addr, pp, attr, flags);
		return;
	}

	ASSERT((hat == ksfmmup) ||
		AS_LOCK_HELD(hat->sfmmu_as, &hat->sfmmu_as->a_lock));

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
	(void) sfmmu_tteload_array(hat, &tte, addr, &pp, flags);

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

	if (hat->sfmmu_xhat_provider) {
		XHAT_DEVLOAD(hat, addr, len, pfn, attr, flags);
		return;
	}

	ASSERT(!(flags & ~SFMMU_LOAD_ALLFLAG));
	ASSERT(!(attr & ~SFMMU_LOAD_ALLATTR));
	ASSERT((hat == ksfmmup) ||
		AS_LOCK_HELD(hat->sfmmu_as, &hat->sfmmu_as->a_lock));
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
			    flags);
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
			    flags);
			len -= MMU_PAGESIZE4M;
			addr += MMU_PAGESIZE4M;
			pfn += MMU_PAGESIZE4M / MMU_PAGESIZE;
		} else if ((len >= MMU_PAGESIZE512K) &&
		    !((uintptr_t)addr & MMU_PAGEOFFSET512K) &&
		    !(disable_large_pages & (1 << TTE512K)) &&
		    !(mmu_ptob(pfn) & MMU_PAGEOFFSET512K)) {
			sfmmu_memtte(&tte, pfn, attr, TTE512K);
			(void) sfmmu_tteload_array(hat, &tte, addr, &pp,
			    flags);
			len -= MMU_PAGESIZE512K;
			addr += MMU_PAGESIZE512K;
			pfn += MMU_PAGESIZE512K / MMU_PAGESIZE;
		} else if ((len >= MMU_PAGESIZE64K) &&
		    !((uintptr_t)addr & MMU_PAGEOFFSET64K) &&
		    !(disable_large_pages & (1 << TTE64K)) &&
		    !(mmu_ptob(pfn) & MMU_PAGEOFFSET64K)) {
			sfmmu_memtte(&tte, pfn, attr, TTE64K);
			(void) sfmmu_tteload_array(hat, &tte, addr, &pp,
			    flags);
			len -= MMU_PAGESIZE64K;
			addr += MMU_PAGESIZE64K;
			pfn += MMU_PAGESIZE64K / MMU_PAGESIZE;
		} else {
			sfmmu_memtte(&tte, pfn, attr, TTE8K);
			(void) sfmmu_tteload_array(hat, &tte, addr, &pp,
			    flags);
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
void
hat_memload_array(struct hat *hat, caddr_t addr, size_t len,
	struct page **pps, uint_t attr, uint_t flags)
{
	int  ttesz;
	size_t mapsz;
	pgcnt_t	numpg, npgs;
	tte_t tte;
	page_t *pp;
	int large_pages_disable;

	ASSERT(!((uintptr_t)addr & MMU_PAGEOFFSET));

	if (hat->sfmmu_xhat_provider) {
		XHAT_MEMLOAD_ARRAY(hat, addr, len, pps, attr, flags);
		return;
	}

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
		sfmmu_memload_batchsmall(hat, addr, pps, attr, flags, npgs);
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
				    pps, flags)) {
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
							numpg);
		}
		addr += mapsz;
		npgs -= numpg;
		pps += numpg;
	}

	if (npgs) {
		sfmmu_memload_batchsmall(hat, addr, pps, attr, flags, npgs);
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
		    uint_t attr, uint_t flags, pgcnt_t npgs)
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
		hmebp = sfmmu_tteload_acquire_hashbucket(hat, vaddr, TTE8K);
		ASSERT(hmebp);

		/*
		 * Find the hment block.
		 */
		hmeblkp = sfmmu_tteload_find_hmeblk(hat, hmebp, vaddr,
				TTE8K, flags);
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
					vaddr, pps, flags);

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
 * tte_size2 = size & TTE_SZ2_BITS (Panther-only)
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
 */
void
sfmmu_tteload(struct hat *sfmmup, tte_t *ttep, caddr_t vaddr, page_t *pp,
	uint_t flags)
{
	(void) sfmmu_tteload_array(sfmmup, ttep, vaddr, &pp, flags);
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
	page_t **pps, uint_t flags)
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
	hmebp = sfmmu_tteload_acquire_hashbucket(sfmmup, vaddr, size);
	ASSERT(hmebp);

	/*
	 * Find the hment block.
	 */
	hmeblkp = sfmmu_tteload_find_hmeblk(sfmmup, hmebp, vaddr, size, flags);
	ASSERT(hmeblkp);

	/*
	 * Add the translation.
	 */
	ret = sfmmu_tteload_addentry(sfmmup, hmeblkp, ttep, vaddr, pps, flags);

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
sfmmu_tteload_acquire_hashbucket(sfmmu_t *sfmmup, caddr_t vaddr, int size)
{
	struct hmehash_bucket *hmebp;
	int hmeshift;

	hmeshift = HME_HASH_SHIFT(size);

	hmebp = HME_HASH_FUNCTION(sfmmup, vaddr, hmeshift);

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
	caddr_t vaddr, uint_t size, uint_t flags)
{
	hmeblk_tag hblktag;
	int hmeshift;
	struct hme_blk *hmeblkp, *pr_hblk, *list = NULL;
	uint64_t hblkpa, prevpa;
	struct kmem_cache *sfmmu_cache;
	uint_t forcefree;

	hblktag.htag_id = sfmmup;
	hmeshift = HME_HASH_SHIFT(size);
	hblktag.htag_bspage = HME_HASH_BSPAGE(vaddr, hmeshift);
	hblktag.htag_rehash = HME_HASH_REHASH(size);

ttearray_realloc:

	HME_HASH_SEARCH_PREV(hmebp, hblktag, hmeblkp, hblkpa,
	    pr_hblk, prevpa, &list);

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
		    hblktag, flags);
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
			sfmmu_hblk_hash_rm(hmebp, hmeblkp, prevpa, pr_hblk);
			sfmmu_hblk_free(hmebp, hmeblkp, hblkpa, &list);
			goto ttearray_realloc;
		}
		if (hmeblkp->hblk_shw_bit) {
			/*
			 * if the hblk was previously used as a shadow hblk then
			 * we will change it to a normal hblk
			 */
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
	 * hat_memload() should never call kmem_cache_free(); see block
	 * comment showing the stacktrace in sfmmu_hblk_alloc();
	 * enqueue each hblk in the list to reserve list if it's created
	 * from sfmmu8_cache *and* sfmmup == KHATID.
	 */
	forcefree = (sfmmup == KHATID) ? 1 : 0;
	while ((pr_hblk = list) != NULL) {
		list = pr_hblk->hblk_next;
		sfmmu_cache = get_hblk_cache(pr_hblk);
		if ((sfmmu_cache == sfmmu8_cache) &&
		    sfmmu_put_free_hblk(pr_hblk, forcefree))
			continue;

		ASSERT(sfmmup != KHATID);
		kmem_cache_free(sfmmu_cache, pr_hblk);
	}

	ASSERT(get_hblk_ttesz(hmeblkp) == size);
	ASSERT(!hmeblkp->hblk_shw_bit);

	return (hmeblkp);
}

/*
 * Function adds a tte entry into the hmeblk. It returns 0 if successful and 1
 * otherwise.
 */
static int
sfmmu_tteload_addentry(sfmmu_t *sfmmup, struct hme_blk *hmeblkp, tte_t *ttep,
	caddr_t vaddr, page_t **pps, uint_t flags)
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

	/*
	 * remove this panic when we decide to let user virtual address
	 * space be >= USERLIMIT.
	 */
	if (!TTE_IS_PRIVILEGED(ttep) && vaddr >= (caddr_t)USERLIMIT)
		panic("user addr %p in kernel space", vaddr);
#if defined(TTE_IS_GLOBAL)
	if (TTE_IS_GLOBAL(ttep))
		panic("sfmmu_tteload: creating global tte");
#endif

#ifdef DEBUG
	if (pf_is_memory(sfmmu_ttetopfn(ttep, vaddr)) &&
	    !TTE_IS_PCACHEABLE(ttep) && !sfmmu_allow_nc_trans)
		panic("sfmmu_tteload: non cacheable memory tte");
#endif /* DEBUG */

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
			/*
			 * Handle VAC consistency
			 */
			if (!remap && (cache & CACHE_VAC) && !PP_ISNC(pp)) {
				sfmmu_vac_conflict(sfmmup, vaddr, pp);
			}

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
		if (((int)hmeblkp->hblk_lckcnt + 1) >= MAX_HBLK_LCKCNT) {
			panic("too high lckcnt-hmeblk %p",
			    (void *)hmeblkp);
		}
		atomic_add_16(&hmeblkp->hblk_lckcnt, 1);

		HBLK_STACK_TRACE(hmeblkp, HBLK_LOCK);
	}

	if (pp && PP_ISNC(pp)) {
		/*
		 * If the physical page is marked to be uncacheable, like
		 * by a vac conflict, make sure the new mapping is also
		 * uncacheable.
		 */
		TTE_CLR_VCACHEABLE(ttep);
		ASSERT(PP_GET_VCOLOR(pp) == NO_VCOLOR);
	}
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

	if (!TTE_IS_VALID(&tteold)) {

		atomic_add_16(&hmeblkp->hblk_vcnt, 1);
		atomic_add_long(&sfmmup->sfmmu_ttecnt[size], 1);

		/*
		 * HAT_RELOAD_SHARE has been deprecated with lpg DISM.
		 */

		if (size > TTE8K && (flags & HAT_LOAD_SHARE) == 0 &&
		    sfmmup != ksfmmup) {
			/*
			 * If this is the first large mapping for the process
			 * we must force any CPUs running this process to TL=0
			 * where they will reload the HAT flags from the
			 * tsbmiss area.  This is necessary to make the large
			 * mappings we are about to load visible to those CPUs;
			 * otherwise they'll loop forever calling pagefault()
			 * since we don't search large hash chains by default.
			 */
			hatlockp = sfmmu_hat_enter(sfmmup);
			if (size == TTE512K &&
			    !SFMMU_FLAGS_ISSET(sfmmup, HAT_512K_FLAG)) {
				SFMMU_FLAGS_SET(sfmmup, HAT_512K_FLAG);
				sfmmu_sync_mmustate(sfmmup);
			} else if (size == TTE4M &&
			    !SFMMU_FLAGS_ISSET(sfmmup, HAT_4M_FLAG)) {
				SFMMU_FLAGS_SET(sfmmup, HAT_4M_FLAG);
				sfmmu_sync_mmustate(sfmmup);
			} else if (size == TTE64K &&
			    !SFMMU_FLAGS_ISSET(sfmmup, HAT_64K_FLAG)) {
				SFMMU_FLAGS_SET(sfmmup, HAT_64K_FLAG);
				/* no sync mmustate; 64K shares 8K hashes */
			} else if (mmu_page_sizes == max_mmu_page_sizes) {
			    if (size == TTE32M &&
				!SFMMU_FLAGS_ISSET(sfmmup, HAT_32M_FLAG)) {
				SFMMU_FLAGS_SET(sfmmup, HAT_32M_FLAG);
				sfmmu_sync_mmustate(sfmmup);
			    } else if (size == TTE256M &&
				!SFMMU_FLAGS_ISSET(sfmmup, HAT_256M_FLAG)) {
				SFMMU_FLAGS_SET(sfmmup, HAT_256M_FLAG);
				sfmmu_sync_mmustate(sfmmup);
			    }
			}
			if (size >= TTE4M && (flags & HAT_LOAD_TEXT) &&
			    !SFMMU_FLAGS_ISSET(sfmmup, HAT_4MTEXT_FLAG)) {
				SFMMU_FLAGS_SET(sfmmup, HAT_4MTEXT_FLAG);
			}
			sfmmu_hat_exit(hatlockp);
		}
	}
	ASSERT(TTE_IS_VALID(&sfhme->hme_tte));

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
		sfmmu_tlb_demap(vaddr, sfmmup, hmeblkp, 0, 0);
		xt_sync(sfmmup->sfmmu_cpusran);
	}

	if ((flags & SFMMU_NO_TSBLOAD) == 0) {
		/*
		 * We only preload 8K and 4M mappings into the TSB, since
		 * 64K and 512K mappings are replicated and hence don't
		 * have a single, unique TSB entry. Ditto for 32M/256M.
		 */
		if (size == TTE8K || size == TTE4M) {
			hatlockp = sfmmu_hat_enter(sfmmup);
			sfmmu_load_tsb(sfmmup, vaddr, &sfhme->hme_tte, size);
			sfmmu_hat_exit(hatlockp);
		}
	}
	if (pp) {
		if (!remap) {
			HME_ADD(sfhme, pp);
			atomic_add_16(&hmeblkp->hblk_hmecnt, 1);
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
	int 	i, index, ttesz, osz;
	pfn_t	pfnum;
	pgcnt_t	npgs;
	int cflags = 0;
	page_t *pp, *pp1;
	kmutex_t *pmtx;
	int vac_err = 0;
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
	osz = fnd_mapping_sz(pp1);

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
		if (vac_err == 0) {
			vac_err = sfmmu_vacconflict_array(addr, pp, &cflags);

		}

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

	return (0);
}

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

	if (!PP_ISMAPPED(pp)) {
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
	hmebp = HME_HASH_FUNCTION(sfmmup, vaddr, hmeshift);

	SFMMU_HASH_LOCK(hmebp);

	HME_HASH_FAST_SEARCH(hmebp, hblktag, hmeblkp);
	ASSERT(hmeblkp != (struct hme_blk *)hblk_reserve);
	if (hmeblkp == NULL) {
		hmeblkp = sfmmu_hblk_alloc(sfmmup, vaddr, hmebp, size,
			hblktag, flags);
	}
	ASSERT(hmeblkp);
	if (!hmeblkp->hblk_shw_mask) {
		/*
		 * if this is a unused hblk it was just allocated or could
		 * potentially be a previous large page hblk so we need to
		 * set the shadow bit.
		 */
		hmeblkp->hblk_shw_bit = 1;
	}
	ASSERT(hmeblkp->hblk_shw_bit == 1);
	vshift = vaddr_to_vshift(hblktag, vaddr, size);
	ASSERT(vshift < 8);
	/*
	 * Atomically set shw mask bit
	 */
	do {
		shw_mask = hmeblkp->hblk_shw_mask;
		newshw_mask = shw_mask | (1 << vshift);
		newshw_mask = cas32(&hmeblkp->hblk_shw_mask, shw_mask,
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
	uint64_t hblkpa, prevpa, nx_pa;

	ASSERT(hashno > 0);
	hblktag.htag_id = sfmmup;
	hblktag.htag_rehash = hashno;

	hmeshift = HME_HASH_SHIFT(hashno);

	while (addr < endaddr) {
		hblktag.htag_bspage = HME_HASH_BSPAGE(addr, hmeshift);
		hmebp = HME_HASH_FUNCTION(sfmmup, addr, hmeshift);
		SFMMU_HASH_LOCK(hmebp);
		/* inline HME_HASH_SEARCH */
		hmeblkp = hmebp->hmeblkp;
		hblkpa = hmebp->hmeh_nextpa;
		prevpa = 0;
		pr_hblk = NULL;
		while (hmeblkp) {
			ASSERT(hblkpa == va_to_pa((caddr_t)hmeblkp));
			if (HTAGS_EQ(hmeblkp->hblk_tag, hblktag)) {
				/* found hme_blk */
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
			nx_pa = hmeblkp->hblk_nextpa;
			if (!hmeblkp->hblk_vcnt && !hmeblkp->hblk_hmecnt) {
				sfmmu_hblk_hash_rm(hmebp, hmeblkp, prevpa,
					pr_hblk);
				sfmmu_hblk_free(hmebp, hmeblkp, hblkpa, &list);
			} else {
				pr_hblk = hmeblkp;
				prevpa = hblkpa;
			}
			hmeblkp = nx_hblk;
			hblkpa = nx_pa;
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
	sfmmu_hblks_list_purge(&list);
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
	ASSERT(sfmmup->sfmmu_xhat_provider == NULL);

	ASSERT((sfmmup == ksfmmup) ||
		AS_LOCK_HELD(sfmmup->sfmmu_as, &sfmmup->sfmmu_as->a_lock));
	ASSERT((len & MMU_PAGEOFFSET) == 0);
	endaddr = addr + len;
	hblktag.htag_id = sfmmup;

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

	sfmmu_hblks_list_purge(&list);
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
			atomic_add_16(&hmeblkp->hblk_lckcnt, -1);
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
 *     SE_SHARED or SE_EXCL of the underlying page (e.g., as_pagelock()).
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

/*
 * Add relocation callbacks to the specified addr/len which will be called
 * when relocating the associated page.  See the description of pre and
 * posthandler above for more details.  IMPT: this operation is only valid
 * on seg_kmem pages!!
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
 * in which case the corresponding callback will be called once with each
 * unique parameter specified. The number of subsequent deletes must match
 * since reference counts are held.  If a callback is desired for each
 * virtual object with the same parameter specified for multiple callbacks,
 * a different virtual address should be specified at the time of
 * callback registration.
 *
 * Returns the pfn of the underlying kernel page in *rpfn
 * on success, or PFN_INVALID on failure.
 *
 * Returns values:
 *    0:      success
 *    ENOMEM: memory allocation failure (e.g. flags was passed as HAC_NOSLEEP)
 *    EINVAL: callback ID is not valid
 *    ENXIO:  ["vaddr", "vaddr" + len) is not mapped in the kernel's address
 *            space, or crosses a page boundary
 */
int
hat_add_callback(id_t callback_id, caddr_t vaddr, uint_t len, uint_t flags,
	void *pvt, pfn_t *rpfn)
{
	struct 		hmehash_bucket *hmebp;
	hmeblk_tag 	hblktag;
	struct hme_blk	*hmeblkp;
	int 		hmeshift, hashno;
	caddr_t 	saddr, eaddr, baseaddr;
	struct pa_hment *pahmep, *tpahmep;
	struct sf_hment *sfhmep, *osfhmep, *tsfhmep;
	kmutex_t	*pml;
	tte_t   	tte;
	page_t		*pp, *rpp;
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

	/*
	 * Make sure the boundaries for the callback fall within this
	 * single mapping.
	 */
	baseaddr = (caddr_t)get_hblk_base(hmeblkp);
	ASSERT(saddr >= baseaddr);
	if (eaddr > (caddr_t)get_hblk_endaddr(hmeblkp)) {
		SFMMU_HASH_UNLOCK(hmebp);
		kmem_cache_free(pa_hment_cache, pahmep);
		*rpfn = PFN_INVALID;
		return (ENXIO);
	}

	HBLKTOHME(osfhmep, hmeblkp, saddr);
	sfmmu_copytte(&osfhmep->hme_tte, &tte);

	ASSERT(TTE_IS_VALID(&tte));
	pfn = sfmmu_ttetopfn(&tte, vaddr);

	/*
	 * The pfn may not have a page_t underneath in which case we
	 * just return it. This can happen if we are doing I/O to a
	 * static portion of the kernel's address space, for instance.
	 */
	pp = osfhmep->hme_page;
	if (pp == NULL || pp->p_vnode != &kvp) {
		SFMMU_HASH_UNLOCK(hmebp);
		kmem_cache_free(pa_hment_cache, pahmep);
		*rpfn = pfn;
		return (0);
	}

	pml = sfmmu_mlist_enter(pp);

	if ((flags & HAC_PAGELOCK) && !locked) {
		if (!page_trylock(pp, SE_SHARED)) {
			page_t *tpp;

			/*
			 * Somebody is holding SE_EXCL lock.  Drop all
			 * our locks, lookup the page in &kvp, and
			 * retry. If it doesn't exist in &kvp, then we
			 * die here; we should have caught it above,
			 * meaning the page must have changed identity
			 * (e.g. the caller didn't hold onto the page
			 * lock after establishing the kernel mapping)
			 */
			sfmmu_mlist_exit(pml);
			SFMMU_HASH_UNLOCK(hmebp);
			tpp = page_lookup(&kvp, (u_offset_t)saddr, SE_SHARED);
			if (tpp == NULL) {
				panic("hat_add_callback: page not found: 0x%p",
				    pp);
			}
			pp = tpp;
			rpp = PP_PAGEROOT(pp);
			if (rpp != pp) {
				page_unlock(pp);
				(void) page_lock(rpp, SE_SHARED, NULL,
				    P_NO_RECLAIM);
			}
			locked = 1;
			goto rehash;
		}
		locked = 1;
	}

	if (!PAGE_LOCKED(pp) && !panicstr)
		panic("hat_add_callback: page 0x%p not locked", pp);

	if (osfhmep->hme_page != pp || pp->p_vnode != &kvp ||
	    pp->p_offset < (u_offset_t)baseaddr ||
	    pp->p_offset > (u_offset_t)eaddr) {
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

	ASSERT(osfhmep->hme_page == pp);

	for (tsfhmep = pp->p_mapping; tsfhmep != NULL;
	    tsfhmep = tsfhmep->hme_next) {

		/*
		 * skip va to pa mappings
		 */
		if (!IS_PAHME(tsfhmep))
			continue;

		tpahmep = tsfhmep->hme_data;
		ASSERT(tpahmep != NULL);

		/*
		 * See if the pahment already exists.
		 */
		if ((tpahmep->pvt == pvt) &&
		    (tpahmep->addr == vaddr) &&
		    (tpahmep->len == len)) {
			ASSERT(tpahmep->cb_id == callback_id);
			tpahmep->refcnt++;
			pp->p_share++;

			sfmmu_mlist_exit(pml);
			SFMMU_HASH_UNLOCK(hmebp);

			if (locked)
				page_unlock(pp);

			kmem_cache_free(pa_hment_cache, pahmep);

			*rpfn = pfn;
			return (0);
		}
	}

	/*
	 * setup this shiny new pa_hment ..
	 */
	pp->p_share++;
	pahmep->cb_id = callback_id;
	pahmep->addr = vaddr;
	pahmep->len = len;
	pahmep->refcnt = 1;
	pahmep->flags = 0;
	pahmep->pvt = pvt;

	/*
	 * .. and also set up the sf_hment and link to p_mapping list.
	 */
	sfhmep->hme_tte.ll = 0;
	sfhmep->hme_data = pahmep;
	sfhmep->hme_prev = osfhmep;
	sfhmep->hme_next = osfhmep->hme_next;

	if (osfhmep->hme_next)
		osfhmep->hme_next->hme_prev = sfhmep;

	osfhmep->hme_next = sfhmep;

	sfmmu_mlist_exit(pml);
	SFMMU_HASH_UNLOCK(hmebp);

	*rpfn = pfn;
	if (locked)
		page_unlock(pp);

	return (0);
}

/*
 * Remove the relocation callbacks from the specified addr/len.
 */
void
hat_delete_callback(caddr_t vaddr, uint_t len, void *pvt, uint_t flags)
{
	struct		hmehash_bucket *hmebp;
	hmeblk_tag	hblktag;
	struct hme_blk	*hmeblkp;
	int		hmeshift, hashno;
	caddr_t		saddr, eaddr, baseaddr;
	struct pa_hment	*pahmep;
	struct sf_hment	*sfhmep, *osfhmep;
	kmutex_t	*pml;
	tte_t		tte;
	page_t		*pp, *rpp;
	int		locked = 0;

	if (IS_KPM_ADDR(vaddr))
		return;

	saddr = (caddr_t)((uintptr_t)vaddr & MMU_PAGEMASK);
	eaddr = saddr + len;

rehash:
	/* Find the mapping(s) for this page */
	for (hashno = TTE64K, hmeblkp = NULL;
	    hmeblkp == NULL && hashno <= mmu_hashcnt;
	    hashno++) {
		hmeshift = HME_HASH_SHIFT(hashno);
		hblktag.htag_id = ksfmmup;
		hblktag.htag_bspage = HME_HASH_BSPAGE(saddr, hmeshift);
		hblktag.htag_rehash = hashno;
		hmebp = HME_HASH_FUNCTION(ksfmmup, saddr, hmeshift);

		SFMMU_HASH_LOCK(hmebp);

		HME_HASH_FAST_SEARCH(hmebp, hblktag, hmeblkp);

		if (hmeblkp == NULL)
			SFMMU_HASH_UNLOCK(hmebp);
	}

	if (hmeblkp == NULL) {
		if (!panicstr) {
			panic("hat_delete_callback: addr 0x%p not found",
			    saddr);
		}
		return;
	}

	baseaddr = (caddr_t)get_hblk_base(hmeblkp);
	HBLKTOHME(osfhmep, hmeblkp, saddr);

	sfmmu_copytte(&osfhmep->hme_tte, &tte);
	ASSERT(TTE_IS_VALID(&tte));

	pp = osfhmep->hme_page;
	if (pp == NULL || pp->p_vnode != &kvp) {
		SFMMU_HASH_UNLOCK(hmebp);
		return;
	}

	pml = sfmmu_mlist_enter(pp);

	if ((flags & HAC_PAGELOCK) && !locked) {
		if (!page_trylock(pp, SE_SHARED)) {
			/*
			 * Somebody is holding SE_EXCL lock.  Drop all
			 * our locks, lookup the page in &kvp, and
			 * retry.
			 */
			sfmmu_mlist_exit(pml);
			SFMMU_HASH_UNLOCK(hmebp);
			pp = page_lookup(&kvp, (u_offset_t)saddr, SE_SHARED);
			ASSERT(pp != NULL);
			rpp = PP_PAGEROOT(pp);
			if (rpp != pp) {
				page_unlock(pp);
				(void) page_lock(rpp, SE_SHARED, NULL,
				    P_NO_RECLAIM);
			}
			locked = 1;
			goto rehash;
		}
		locked = 1;
	}

	ASSERT(PAGE_LOCKED(pp));

	if (osfhmep->hme_page != pp || pp->p_vnode != &kvp ||
	    pp->p_offset < (u_offset_t)baseaddr ||
	    pp->p_offset > (u_offset_t)eaddr) {
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

	ASSERT(osfhmep->hme_page == pp);

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
	ASSERT(sfmmup->sfmmu_xhat_provider == NULL);

	ASSERT((sfmmup == ksfmmup) ||
		AS_LOCK_HELD(sfmmup->sfmmu_as, &sfmmup->sfmmu_as->a_lock));

	if (sfmmup == ksfmmup) {
		while ((pfn = sfmmu_vatopfn(addr, sfmmup, &tte))
		    == PFN_SUSPENDED) {
			sfmmu_vatopfn_suspended(addr, sfmmup, &tte);
		}
	} else {
		pfn = sfmmu_uvatopfn(addr, sfmmup);
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

	ASSERT(sfmmup->sfmmu_xhat_provider == NULL);

	sfmmu_gettte(sfmmup, addr, &tte);
	if (TTE_IS_VALID(&tte)) {
		return (TTEBYTES(TTE_CSZ(&tte)));
	}
	return (-1);
}

static void
sfmmu_gettte(struct hat *sfmmup, caddr_t addr, tte_t *ttep)
{
	struct hmehash_bucket *hmebp;
	hmeblk_tag hblktag;
	int hmeshift, hashno = 1;
	struct hme_blk *hmeblkp, *list = NULL;
	struct sf_hment *sfhmep;

	/* support for ISM */
	ism_map_t	*ism_map;
	ism_blk_t	*ism_blkp;
	int		i;
	sfmmu_t		*ism_hatid = NULL;
	sfmmu_t		*locked_hatid = NULL;

	ASSERT(!((uintptr_t)addr & MMU_PAGEOFFSET));

	ism_blkp = sfmmup->sfmmu_iblk;
	if (ism_blkp) {
		sfmmu_ismhat_enter(sfmmup, 0);
		locked_hatid = sfmmup;
	}
	while (ism_blkp && ism_hatid == NULL) {
		ism_map = ism_blkp->iblk_maps;
		for (i = 0; ism_map[i].imap_ismhat && i < ISM_MAP_SLOTS; i++) {
			if (addr >= ism_start(ism_map[i]) &&
			    addr < ism_end(ism_map[i])) {
				sfmmup = ism_hatid = ism_map[i].imap_ismhat;
				addr = (caddr_t)(addr -
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
	ttep->ll = 0;

	do {
		hmeshift = HME_HASH_SHIFT(hashno);
		hblktag.htag_bspage = HME_HASH_BSPAGE(addr, hmeshift);
		hblktag.htag_rehash = hashno;
		hmebp = HME_HASH_FUNCTION(sfmmup, addr, hmeshift);

		SFMMU_HASH_LOCK(hmebp);

		HME_HASH_SEARCH(hmebp, hblktag, hmeblkp, &list);
		if (hmeblkp != NULL) {
			HBLKTOHME(sfhmep, hmeblkp, addr);
			sfmmu_copytte(&sfhmep->hme_tte, ttep);
			SFMMU_HASH_UNLOCK(hmebp);
			break;
		}
		SFMMU_HASH_UNLOCK(hmebp);
		hashno++;
	} while (HME_REHASH(sfmmup) && (hashno <= mmu_hashcnt));

	sfmmu_hblks_list_purge(&list);
}

uint_t
hat_getattr(struct hat *sfmmup, caddr_t addr, uint_t *attr)
{
	tte_t tte;

	ASSERT(sfmmup->sfmmu_xhat_provider == NULL);

	sfmmu_gettte(sfmmup, addr, &tte);
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
	if (hat->sfmmu_xhat_provider) {
		XHAT_SETATTR(hat, addr, len, attr);
		return;
	} else {
		/*
		 * This must be a CPU HAT. If the address space has
		 * XHATs attached, change attributes for all of them,
		 * just in case
		 */
		ASSERT(hat->sfmmu_as != NULL);
		if (hat->sfmmu_as->a_xhat != NULL)
			xhat_setattr_all(hat->sfmmu_as, addr, len, attr);
	}

	sfmmu_chgattr(hat, addr, len, attr, SFMMU_SETATTR);
}

/*
 * Assigns attributes to the specified address range.  All the attributes
 * are specified.
 */
void
hat_chgattr(struct hat *hat, caddr_t addr, size_t len, uint_t attr)
{
	if (hat->sfmmu_xhat_provider) {
		XHAT_CHGATTR(hat, addr, len, attr);
		return;
	} else {
		/*
		 * This must be a CPU HAT. If the address space has
		 * XHATs attached, change attributes for all of them,
		 * just in case
		 */
		ASSERT(hat->sfmmu_as != NULL);
		if (hat->sfmmu_as->a_xhat != NULL)
			xhat_chgattr_all(hat->sfmmu_as, addr, len, attr);
	}

	sfmmu_chgattr(hat, addr, len, attr, SFMMU_CHGATTR);
}

/*
 * Remove attributes on the specified address range (ie. loginal NAND)
 */
void
hat_clrattr(struct hat *hat, caddr_t addr, size_t len, uint_t attr)
{
	if (hat->sfmmu_xhat_provider) {
		XHAT_CLRATTR(hat, addr, len, attr);
		return;
	} else {
		/*
		 * This must be a CPU HAT. If the address space has
		 * XHATs attached, change attributes for all of them,
		 * just in case
		 */
		ASSERT(hat->sfmmu_as != NULL);
		if (hat->sfmmu_as->a_xhat != NULL)
			xhat_clrattr_all(hat->sfmmu_as, addr, len, attr);
	}

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

	ASSERT((sfmmup == ksfmmup) ||
		AS_LOCK_HELD(sfmmup->sfmmu_as, &sfmmup->sfmmu_as->a_lock));
	ASSERT((len & MMU_PAGEOFFSET) == 0);
	ASSERT(((uintptr_t)addr & MMU_PAGEOFFSET) == 0);

	if ((attr & PROT_USER) && (mode != SFMMU_CLRATTR) &&
	    ((addr + len) > (caddr_t)USERLIMIT)) {
		panic("user addr %p in kernel space",
		    (void *)addr);
	}

	endaddr = addr + len;
	hblktag.htag_id = sfmmup;
	DEMAP_RANGE_INIT(sfmmup, &dmr);

	while (addr < endaddr) {
		hmeshift = HME_HASH_SHIFT(hashno);
		hblktag.htag_bspage = HME_HASH_BSPAGE(addr, hmeshift);
		hblktag.htag_rehash = hashno;
		hmebp = HME_HASH_FUNCTION(sfmmup, addr, hmeshift);

		SFMMU_HASH_LOCK(hmebp);

		HME_HASH_SEARCH(hmebp, hblktag, hmeblkp, &list);
		if (hmeblkp != NULL) {
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

	sfmmu_hblks_list_purge(&list);
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

	endaddr = MIN(endaddr, get_hblk_endaddr(hmeblkp));
	ttesz = get_hblk_ttesz(hmeblkp);

	/*
	 * Flush the current demap region if addresses have been
	 * skipped or the page size doesn't match.
	 */
	use_demap_range = (TTEBYTES(ttesz) == DEMAP_RANGE_PGSZ(dmrp));
	if (use_demap_range) {
		DEMAP_RANGE_CONTINUE(dmrp, addr, endaddr);
	} else {
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

	if (sfmmup->sfmmu_xhat_provider) {
		XHAT_CHGPROT(sfmmup, addr, len, vprot);
		return;
	} else {
		/*
		 * This must be a CPU HAT. If the address space has
		 * XHATs attached, change attributes for all of them,
		 * just in case
		 */
		ASSERT(sfmmup->sfmmu_as != NULL);
		if (sfmmup->sfmmu_as->a_xhat != NULL)
			xhat_chgprot_all(sfmmup->sfmmu_as, addr, len, vprot);
	}

	CPUSET_ZERO(cpuset);

	if ((vprot != (uint_t)~PROT_WRITE) && (vprot & PROT_USER) &&
	    ((addr + len) > (caddr_t)USERLIMIT)) {
		panic("user addr %p vprot %x in kernel space",
		    (void *)addr, vprot);
	}
	endaddr = addr + len;
	hblktag.htag_id = sfmmup;
	DEMAP_RANGE_INIT(sfmmup, &dmr);

	while (addr < endaddr) {
		hmeshift = HME_HASH_SHIFT(hashno);
		hblktag.htag_bspage = HME_HASH_BSPAGE(addr, hmeshift);
		hblktag.htag_rehash = hashno;
		hmebp = HME_HASH_FUNCTION(sfmmup, addr, hmeshift);

		SFMMU_HASH_LOCK(hmebp);

		HME_HASH_SEARCH(hmebp, hblktag, hmeblkp, &list);
		if (hmeblkp != NULL) {
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

	sfmmu_hblks_list_purge(&list);
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
	} else {
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
	uint64_t hblkpa, prevpa, nx_pa;
	hatlock_t	*hatlockp;
	struct tsb_info	*tsbinfop;
	struct ctx	*ctx;
	caddr_t	endaddr = startaddr + len;
	caddr_t	sa;
	caddr_t	ea;
	caddr_t	cb_sa[MAX_CB_ADDR];
	caddr_t	cb_ea[MAX_CB_ADDR];
	int	addr_cnt = 0;
	int	a = 0;
	int	cnum;

	hatlockp = sfmmu_hat_enter(sfmmup);

	/*
	 * Since we know we're unmapping a huge range of addresses,
	 * just throw away the context and switch to another.  It's
	 * cheaper than trying to unmap all of the TTEs we may find
	 * from the TLB individually, which is too expensive in terms
	 * of xcalls.  Better yet, if we're exiting, no need to flush
	 * anything at all!
	 */
	if (!sfmmup->sfmmu_free) {
		ctx = sfmmutoctx(sfmmup);
		rw_enter(&ctx->ctx_rwlock, RW_WRITER);
		cnum = sfmmutoctxnum(sfmmup);
		if (cnum != INVALID_CONTEXT) {
			sfmmu_tlb_swap_ctx(sfmmup, ctx);
		}
		rw_exit(&ctx->ctx_rwlock);

		for (tsbinfop = sfmmup->sfmmu_tsb; tsbinfop != NULL;
		    tsbinfop = tsbinfop->tsb_next) {
			if (tsbinfop->tsb_flags & TSB_SWAPPED)
				continue;
			sfmmu_inv_tsb(tsbinfop->tsb_va,
			    TSB_BYTES(tsbinfop->tsb_szc));
		}
	}

	/*
	 * Loop through all the hash buckets of HME blocks looking for matches.
	 */
	for (i = 0; i <= UHMEHASH_SZ; i++) {
		hmebp = &uhme_hash[i];
		SFMMU_HASH_LOCK(hmebp);
		hmeblkp = hmebp->hmeblkp;
		hblkpa = hmebp->hmeh_nextpa;
		prevpa = 0;
		pr_hblk = NULL;
		while (hmeblkp) {
			nx_hblk = hmeblkp->hblk_next;
			nx_pa = hmeblkp->hblk_nextpa;

			/*
			 * skip if not this context, if a shadow block or
			 * if the mapping is not in the requested range
			 */
			if (hmeblkp->hblk_tag.htag_id != sfmmup ||
			    hmeblkp->hblk_shw_bit ||
			    (sa = (caddr_t)get_hblk_base(hmeblkp)) >= endaddr ||
			    (ea = get_hblk_endaddr(hmeblkp)) <= startaddr) {
				pr_hblk = hmeblkp;
				prevpa = hblkpa;
				goto next_block;
			}

			/*
			 * unload if there are any current valid mappings
			 */
			if (hmeblkp->hblk_vcnt != 0 ||
			    hmeblkp->hblk_hmecnt != 0)
				(void) sfmmu_hblk_unload(sfmmup, hmeblkp,
				    sa, ea, NULL, flags);

			/*
			 * on unmap we also release the HME block itself, once
			 * all mappings are gone.
			 */
			if ((flags & HAT_UNLOAD_UNMAP) != 0 &&
			    !hmeblkp->hblk_vcnt &&
			    !hmeblkp->hblk_hmecnt) {
				ASSERT(!hmeblkp->hblk_lckcnt);
				sfmmu_hblk_hash_rm(hmebp, hmeblkp,
					prevpa, pr_hblk);
				sfmmu_hblk_free(hmebp, hmeblkp, hblkpa, &list);
			} else {
				pr_hblk = hmeblkp;
				prevpa = hblkpa;
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
				for (a = 0; a < MAX_CB_ADDR; ++a) {
					callback->hcb_start_addr = cb_sa[a];
					callback->hcb_end_addr = cb_ea[a];
					callback->hcb_function(callback);
				}
				addr_cnt = 0;
			}

next_block:
			hmeblkp = nx_hblk;
			hblkpa = nx_pa;
		}
		SFMMU_HASH_UNLOCK(hmebp);
	}

	sfmmu_hblks_list_purge(&list);

	for (a = 0; a < addr_cnt; ++a) {
		callback->hcb_start_addr = cb_sa[a];
		callback->hcb_end_addr = cb_ea[a];
		callback->hcb_function(callback);
	}

	sfmmu_hat_exit(hatlockp);

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
	uint64_t hblkpa, prevpa;
	int addr_count = 0;
	int a;
	caddr_t cb_start_addr[MAX_CB_ADDR];
	caddr_t cb_end_addr[MAX_CB_ADDR];
	int issegkmap = ISSEGKMAP(sfmmup, addr);
	demap_range_t dmr, *dmrp;

	if (sfmmup->sfmmu_xhat_provider) {
		XHAT_UNLOAD_CALLBACK(sfmmup, addr, len, flags, callback);
		return;
	} else {
		/*
		 * This must be a CPU HAT. If the address space has
		 * XHATs attached, unload the mappings for all of them,
		 * just in case
		 */
		ASSERT(sfmmup->sfmmu_as != NULL);
		if (sfmmup->sfmmu_as->a_xhat != NULL)
			xhat_unload_callback_all(sfmmup->sfmmu_as, addr,
			    len, flags, callback);
	}

	ASSERT((sfmmup == ksfmmup) || (flags & HAT_UNLOAD_OTHER) || \
	    AS_LOCK_HELD(sfmmup->sfmmu_as, &sfmmup->sfmmu_as->a_lock));

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
	if (sfmmup->sfmmu_free)
		dmrp = NULL;
	else
		dmrp = &dmr;

	DEMAP_RANGE_INIT(sfmmup, dmrp);
	endaddr = addr + len;
	hblktag.htag_id = sfmmup;

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

		HME_HASH_SEARCH_PREV(hmebp, hblktag, hmeblkp, hblkpa, pr_hblk,
			prevpa, &list);
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
				sfmmu_hblk_hash_rm(hmebp, hmeblkp, prevpa,
				    pr_hblk);
				sfmmu_hblk_free(hmebp, hmeblkp, hblkpa, &list);
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
			sfmmu_hblk_hash_rm(hmebp, hmeblkp, prevpa,
			    pr_hblk);
			sfmmu_hblk_free(hmebp, hmeblkp, hblkpa, &list);
		}
		SFMMU_HASH_UNLOCK(hmebp);

		/*
		 * Notify our caller as to exactly which pages
		 * have been unloaded. We do these in clumps,
		 * to minimize the number of xt_sync()s that need to occur.
		 */
		if (callback != NULL && addr_count == MAX_CB_ADDR) {
			DEMAP_RANGE_FLUSH(dmrp);
			if (dmrp != NULL) {
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

	sfmmu_hblks_list_purge(&list);
	DEMAP_RANGE_FLUSH(dmrp);
	if (dmrp != NULL) {
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
	if (sfmmup->sfmmu_xhat_provider) {
		XHAT_UNLOAD(sfmmup, addr, len, flags);
		return;
	}
	hat_unload_callback(sfmmup, addr, len, flags, NULL);
}


/*
 * Find the largest mapping size for this page.
 */
static int
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
#ifdef DEBUG
	if (get_hblk_ttesz(hmeblkp) != TTE8K &&
	    (endaddr < get_hblk_endaddr(hmeblkp))) {
		panic("sfmmu_hblk_unload: partial unload of large page");
	}
#endif /* DEBUG */

	endaddr = MIN(endaddr, get_hblk_endaddr(hmeblkp));
	ttesz = get_hblk_ttesz(hmeblkp);

	use_demap_range = (do_virtual_coloring &&
				TTEBYTES(ttesz) == DEMAP_RANGE_PGSZ(dmrp));
	if (use_demap_range) {
		DEMAP_RANGE_CONTINUE(dmrp, addr, endaddr);
	} else {
		DEMAP_RANGE_FLUSH(dmrp);
	}
	ttecnt = 0;
	HBLKTOHME(sfhmep, hmeblkp, addr);

	while (addr < endaddr) {
		pml = NULL;
again:
		sfmmu_copytte(&sfhmep->hme_tte, &tte);
		if (TTE_IS_VALID(&tte)) {
			pp = sfhmep->hme_page;
			if (pp && pml == NULL) {
				pml = sfmmu_mlist_enter(pp);
			}

			/*
			 * Verify if hme still points to 'pp' now that
			 * we have p_mapping lock.
			 */
			if (sfhmep->hme_page != pp) {
				if (pp != NULL && sfhmep->hme_page != NULL) {
					if (pml) {
						sfmmu_mlist_exit(pml);
					}
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
			ttemod = tte;

			TTE_SET_INVALID(&ttemod);
			ret = sfmmu_modifytte_try(&tte, &ttemod,
			    &sfhmep->hme_tte);

			if (ret <= 0) {
				if (TTE_IS_VALID(&tte)) {
					goto again;
				} else {
					/*
					 * We read in a valid pte, but it
					 * is unloaded by page_unload.
					 * hme_page has become NULL and
					 * we hold no p_mapping lock.
					 */
					ASSERT(pp == NULL && pml == NULL);
					goto tte_unloaded;
				}
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
				atomic_add_16(&hmeblkp->hblk_lckcnt, -1);
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
			 * 1.	mapping exists from va1 to pa and data
			 * has been read into the cache.
			 * 2.	unload va1.
			 * 3.	load va2 and modify data using va2.
			 * 4	unload va2.
			 * 5.	load va1 and reference data.  Unless we
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
				if (do_virtual_coloring) {
					sfmmu_tlb_demap(addr, sfmmup, hmeblkp,
					    sfmmup->sfmmu_free, 0);
				} else {
					pfn_t pfnum;

					pfnum = TTE_TO_PFN(addr, &tte);
					sfmmu_tlbcache_demap(addr, sfmmup,
					    hmeblkp, pfnum, sfmmup->sfmmu_free,
					    FLUSH_NECESSARY_CPUS,
					    CACHE_FLUSH, 0);
				}
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
				atomic_add_16(&hmeblkp->hblk_hmecnt, -1);
			}

			ASSERT(hmeblkp->hblk_vcnt > 0);
			atomic_add_16(&hmeblkp->hblk_vcnt, -1);

			ASSERT(hmeblkp->hblk_hmecnt || hmeblkp->hblk_vcnt ||
			    !hmeblkp->hblk_lckcnt);

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
					pml = NULL;
					goto again;
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
	if (ttecnt > 0)
		atomic_add_long(&sfmmup->sfmmu_ttecnt[ttesz], -ttecnt);
	return (addr);
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

	ASSERT(sfmmup->sfmmu_xhat_provider == NULL);
	ASSERT((sfmmup == ksfmmup) ||
		AS_LOCK_HELD(sfmmup->sfmmu_as, &sfmmup->sfmmu_as->a_lock));
	ASSERT((len & MMU_PAGEOFFSET) == 0);
	ASSERT((clearflag == HAT_SYNC_DONTZERO) ||
		(clearflag == HAT_SYNC_ZERORM));

	CPUSET_ZERO(cpuset);

	endaddr = addr + len;
	hblktag.htag_id = sfmmup;
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
	sfmmu_hblks_list_purge(&list);
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
	if (sfmmup->sfmmu_rmstat) {
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
	 * Call into dtrace to tell it we're about to suspend a
	 * kernel mapping. This prevents us from running into issues
	 * with probe context trying to touch a suspended page
	 * in the relocation codepath itself.
	 */
	if (dtrace_kreloc_init)
		(*dtrace_kreloc_init)();

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

		addr = tte_to_vaddr(hmeblkp, tte);

		/*
		 * No need to make sure that the TSB for this sfmmu is
		 * not being relocated since it is ksfmmup and thus it
		 * will never be relocated.
		 */
		SFMMU_UNLOAD_TSB(addr, sfmmup, hmeblkp);

		/*
		 * Update xcall stats
		 */
		cpuset = cpu_ready_set;
		CPUSET_DEL(cpuset, CPU->cpu_id);

		/* LINTED: constant in conditional context */
		SFMMU_XCALL_STATS(KCONTEXT);

		/*
		 * Flush TLB entry on remote CPU's
		 */
		xt_some(cpuset, vtag_flushpage_tl1, (uint64_t)addr, KCONTEXT);
		xt_sync(cpuset);

		/*
		 * Flush TLB entry on local CPU
		 */
		vtag_flushpage(addr, KCONTEXT);
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

	if (hat_kpr_enabled == 0 || !kcage_on || PP_ISNORELOC(*target)) {
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
	 * If the replacement page is of a different virtual color
	 * than the page it is replacing, we need to handle the VAC
	 * consistency for it just as we would if we were setting up
	 * a new mapping to a page.
	 */
	if ((tpp->p_szc == 0) && (PP_GET_VCOLOR(rpp) != NO_VCOLOR)) {
		if (tpp->p_vcolor != rpp->p_vcolor) {
			sfmmu_cache_flushcolor(PP_GET_VCOLOR(rpp),
			    rpp->p_pagenum);
		}
	}

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
		rpp->p_vcolor = tpp->p_vcolor;
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
	panic("pa_hment leaked: 0x%p", pahmep);
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
	kmutex_t *pml, *pmtx;
	cpuset_t cpuset, tset;
	int index, cons;
	int xhme_blks;
	int pa_hments;

	ASSERT(PAGE_EXCL(pp));

retry_xhat:
	tmphme = NULL;
	xhme_blks = 0;
	pa_hments = 0;
	CPUSET_ZERO(cpuset);

	pml = sfmmu_mlist_enter(pp);

	if (pp->p_kpmref)
		sfmmu_kpm_pageunload(pp);
	ASSERT(!PP_ISMAPPED_KPM(pp));

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
		if (hmeblkp->hblk_xhat_bit) {
			struct xhat_hme_blk *xblk =
			    (struct xhat_hme_blk *)hmeblkp;

			(void) XHAT_PAGEUNLOAD(xblk->xhat_hme_blk_hat,
			    pp, forceflag, XBLK2PROVBLK(xblk));

			xhme_blks = 1;
			continue;
		}

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
	ASSERT(!PP_ISMAPPED(origpp) || xhme_blks || pa_hments ||
	    (forceflag == SFMMU_KERNEL_RELOC));

	if (PP_ISTNC(pp)) {
		if (cons == TTE8K) {
			pmtx = sfmmu_page_enter(pp);
			PP_CLRTNC(pp);
			sfmmu_page_exit(pmtx);
		} else {
			conv_tnc(pp, cons);
		}
	}

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

		ASSERT(!PP_ISMAPPED(origpp) || xhme_blks);
	}

	sfmmu_mlist_exit(pml);

	/*
	 * XHAT may not have finished unloading pages
	 * because some other thread was waiting for
	 * mlist lock and XHAT_PAGEUNLOAD let it do
	 * the job.
	 */
	if (xhme_blks) {
		pp = origpp;
		goto retry_xhat;
	}

	return (0);
}

static cpuset_t
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
	ASSERT(pp->p_vnode != &kvp);

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

		sfmmu_ttesync(sfmmup, addr, &tte, pp);

		atomic_add_long(&sfmmup->sfmmu_ttecnt[ttesz], -1);

		/*
		 * We need to flush the page from the virtual cache
		 * in order to prevent a virtual cache alias
		 * inconsistency. The particular scenario we need
		 * to worry about is:
		 * Given:  va1 and va2 are two virtual address that
		 * alias and will map the same physical address.
		 * 1.	mapping exists from va1 to pa and data has
		 *	been read into the cache.
		 * 2.	unload va1.
		 * 3.	load va2 and modify data using va2.
		 * 4	unload va2.
		 * 5.	load va1 and reference data.  Unless we flush
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
			if (do_virtual_coloring)
				sfmmu_ismtlbcache_demap(addr, sfmmup, hmeblkp,
					pp->p_pagenum, CACHE_NO_FLUSH);
			else
				sfmmu_ismtlbcache_demap(addr, sfmmup, hmeblkp,
					pp->p_pagenum, CACHE_FLUSH);
			kpreempt_enable();
			mutex_exit(&ism_mlist_lock);
			sfmmu_hat_unlock_all();
			cpuset = cpu_ready_set;
		} else if (do_virtual_coloring) {
			sfmmu_tlb_demap(addr, sfmmup, hmeblkp, 0, 0);
			cpuset = sfmmup->sfmmu_cpusran;
		} else {
			sfmmu_tlbcache_demap(addr, sfmmup, hmeblkp,
				pp->p_pagenum, 0, FLUSH_NECESSARY_CPUS,
				CACHE_FLUSH, 0);
			cpuset = sfmmup->sfmmu_cpusran;
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
		atomic_add_16(&hmeblkp->hblk_vcnt, -1);
		atomic_add_16(&hmeblkp->hblk_hmecnt, -1);
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

	if (dtrace_kreloc_fini)
		(*dtrace_kreloc_fini)();
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

	CPUSET_ZERO(cpuset);

	if (PP_ISRO(pp) && (clearflag & HAT_SYNC_STOPON_MOD)) {
		return (PP_GENERIC_ATTR(pp));
	}

	if ((clearflag == (HAT_SYNC_STOPON_REF | HAT_SYNC_DONTZERO)) &&
	    PP_ISREF(pp)) {
		return (PP_GENERIC_ATTR(pp));
	}

	if ((clearflag == (HAT_SYNC_STOPON_MOD | HAT_SYNC_DONTZERO)) &&
	    PP_ISMOD(pp)) {
		return (PP_GENERIC_ATTR(pp));
	}

	if ((clearflag & HAT_SYNC_STOPON_SHARED) != 0 &&
	    (pp->p_share > po_share) &&
	    !(clearflag & HAT_SYNC_ZERORM)) {
		if (PP_ISRO(pp))
			hat_page_setattr(pp, P_REF);
		return (PP_GENERIC_ATTR(pp));
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
		/*
		 * If we are looking for large mappings and this hme doesn't
		 * reach the range we are seeking, just ignore its.
		 */
		hmeblkp = sfmmu_hmetohblk(sfhme);
		if (hmeblkp->hblk_xhat_bit)
			continue;

		if (hme_size(sfhme) < cons)
			continue;
		tset = sfmmu_pagesync(pp, sfhme,
			clearflag & ~HAT_SYNC_STOPON_RM);
		CPUSET_OR(cpuset, tset);
		/*
		 * If clearflag is HAT_SYNC_DONTZERO, break out as soon
		 * as the "ref" or "mod" is set.
		 */
		if ((clearflag & ~HAT_SYNC_STOPON_RM) == HAT_SYNC_DONTZERO &&
		    ((clearflag & HAT_SYNC_STOPON_MOD) && PP_ISMOD(save_pp)) ||
		    ((clearflag & HAT_SYNC_STOPON_REF) && PP_ISREF(save_pp))) {
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
				sfmmu_tlb_demap(addr, sfmmup, hmeblkp, 0, 0);
				cpuset = sfmmup->sfmmu_cpusran;
			}
		}

		sfmmu_ttesync(sfmmup, addr, &tte, pp);
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

		/*
		 * xhat mappings should never be to a VMODSORT page.
		 */
		ASSERT(hmeblkp->hblk_xhat_bit == 0);

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
			sfmmu_tlb_demap(addr, sfmmup, hmeblkp, 0, 0);
			cpuset = sfmmup->sfmmu_cpusran;
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

	ASSERT(!(flag & ~(P_MOD | P_REF | P_RO)));

	/*
	 * nothing to do if attribute already set
	 */
	if ((pp->p_nrm & flag) == flag)
		return;

	if ((flag & P_MOD) != 0 && vp != NULL && IS_VMODSORT(vp)) {
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
	kmutex_t	*vphm = NULL;
	kmutex_t	*pmtx;

	ASSERT(!(flag & ~(P_MOD | P_REF | P_RO)));

	/*
	 * For vnode with a sorted v_pages list, we need to change
	 * the attributes and the v_pages list together under page_vnode_mutex.
	 */
	if ((flag & P_MOD) != 0 && vp != NULL && IS_VMODSORT(vp)) {
		vphm = page_vnode_mutex(vp);
		mutex_enter(vphm);
	}

	pmtx = sfmmu_page_enter(pp);
	pp->p_nrm &= ~flag;
	sfmmu_page_exit(pmtx);

	if (vphm != NULL) {
		/*
		 * Some File Systems examine v_pages for NULL w/o
		 * grabbing the vphm mutex. Must not let it become NULL when
		 * pp is the only page on the list.
		 */
		if (pp->p_vpnext != pp) {
			page_vpsub(&vp->v_pages, pp);
			page_vpadd(&vp->v_pages, pp);
		}
		mutex_exit(vphm);

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

	if (hat_kpr_enabled == 0 || kvseg.s_base == NULL || panicstr)
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
		panic("Illegal VA->PA translation, pp 0x%p not permanent", pp);
	else
		panic("Illegal VA->PA translation, pp 0x%p not locked", pp);
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
	 * ASSERT(AS_LOCK_HELD(as, &as->a_lock));
	 * but we can't because the iommu driver will call this
	 * routine at interrupt time and it can't grab the as lock
	 * or it will deadlock: A thread could have the as lock
	 * and be waiting for io.  The io can't complete
	 * because the interrupt thread is blocked trying to grab
	 * the as lock.
	 */

	ASSERT(hat->sfmmu_xhat_provider == NULL);

	if (hat == ksfmmup) {
		if (segkpm && IS_KPM_ADDR(addr))
			return (sfmmu_kpm_vatopfn(addr));
		while ((pfn = sfmmu_vatopfn(addr, ksfmmup, &tte))
		    == PFN_SUSPENDED) {
			sfmmu_vatopfn_suspended(addr, ksfmmup, &tte);
		}
		sfmmu_check_kpfn(pfn);
		return (pfn);
	} else {
		return (sfmmu_uvatopfn(addr, hat));
	}
}

/*
 * hat_getkpfnum() is an obsolete DDI routine, and its use is discouraged.
 * Use hat_getpfnum(kas.a_hat, ...) instead.
 *
 * We'd like to return PFN_INVALID if the mappings have underlying page_t's
 * but can't right now due to the fact that some software has grown to use
 * this interface incorrectly. So for now when the interface is misused,
 * return a warning to the user that in the future it won't work in the
 * way they're abusing it, and carry on (after disabling page relocation).
 */
pfn_t
hat_getkpfnum(caddr_t addr)
{
	pfn_t pfn;
	tte_t tte;
	int badcaller = 0;
	extern int segkmem_reloc;

	if (segkpm && IS_KPM_ADDR(addr)) {
		badcaller = 1;
		pfn = sfmmu_kpm_vatopfn(addr);
	} else {
		while ((pfn = sfmmu_vatopfn(addr, ksfmmup, &tte))
		    == PFN_SUSPENDED) {
			sfmmu_vatopfn_suspended(addr, ksfmmup, &tte);
		}
		badcaller = pf_is_memory(pfn);
	}

	if (badcaller) {
		/*
		 * We can't return PFN_INVALID or the caller may panic
		 * or corrupt the system.  The only alternative is to
		 * disable page relocation at this point for all kernel
		 * memory.  This will impact any callers of page_relocate()
		 * such as FMA or DR.
		 *
		 * RFE: Add junk here to spit out an ereport so the sysadmin
		 * can be advised that he should upgrade his device driver
		 * so that this doesn't happen.
		 */
		hat_getkpfnum_badcall(caller());
		if (hat_kpr_enabled && segkmem_reloc) {
			hat_kpr_enabled = 0;
			segkmem_reloc = 0;
			cmn_err(CE_WARN, "Kernel Page Relocation is DISABLED");
		}
	}
	return (pfn);
}

pfn_t
sfmmu_uvatopfn(caddr_t vaddr, struct hat *sfmmup)
{
	struct hmehash_bucket *hmebp;
	hmeblk_tag hblktag;
	int hmeshift, hashno = 1;
	struct hme_blk *hmeblkp = NULL;

	struct sf_hment *sfhmep;
	tte_t tte;
	pfn_t pfn;

	/* support for ISM */
	ism_map_t	*ism_map;
	ism_blk_t	*ism_blkp;
	int		i;
	sfmmu_t *ism_hatid = NULL;
	sfmmu_t *locked_hatid = NULL;


	ASSERT(sfmmup != ksfmmup);
	SFMMU_STAT(sf_user_vtop);
	/*
	 * Set ism_hatid if vaddr falls in a ISM segment.
	 */
	ism_blkp = sfmmup->sfmmu_iblk;
	if (ism_blkp) {
		sfmmu_ismhat_enter(sfmmup, 0);
		locked_hatid = sfmmup;
	}
	while (ism_blkp && ism_hatid == NULL) {
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
	do {
		hmeshift = HME_HASH_SHIFT(hashno);
		hblktag.htag_bspage = HME_HASH_BSPAGE(vaddr, hmeshift);
		hblktag.htag_rehash = hashno;
		hmebp = HME_HASH_FUNCTION(sfmmup, vaddr, hmeshift);

		SFMMU_HASH_LOCK(hmebp);

		HME_HASH_FAST_SEARCH(hmebp, hblktag, hmeblkp);
		if (hmeblkp != NULL) {
			HBLKTOHME(sfhmep, hmeblkp, vaddr);
			sfmmu_copytte(&sfhmep->hme_tte, &tte);
			if (TTE_IS_VALID(&tte)) {
				pfn = TTE_TO_PFN(vaddr, &tte);
			} else {
				pfn = PFN_INVALID;
			}
			SFMMU_HASH_UNLOCK(hmebp);
			return (pfn);
		}
		SFMMU_HASH_UNLOCK(hmebp);
		hashno++;
	} while (HME_REHASH(sfmmup) && (hashno <= mmu_hashcnt));
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
	ASSERT(hat->sfmmu_xhat_provider == NULL);
}

/*
 * Return the number of mappings to a particular page.
 * This number is an approximation of the number of
 * number of people sharing the page.
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

	if (kpm_enable)
		cnt += spp->p_kpmref;

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
			hmeblkp = sfmmu_hmetohblk(sfhme);
			if (hme_size(sfhme) != sz) {
				continue;
			}
			if (hmeblkp->hblk_xhat_bit) {
				cmn_err(CE_PANIC,
				    "hat_page_demote: xhat hmeblk");
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
		if (PP_ISTNC(pp)) {
			conv_tnc(rootpp, sz);
		}
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
	int		j;

	ASSERT(SFMMU_FLAGS_ISSET(sfmmup, HAT_ISMBUSY));
	for (; ism_blkp != NULL; ism_blkp = ism_blkp->iblk_next) {
		ism_map = ism_blkp->iblk_maps;
		for (j = 0; ism_map[j].imap_ismhat && j < ISM_MAP_SLOTS; j++)
			npgs += ism_map[j].imap_ismhat->sfmmu_ttecnt[szc];
	}
	sfmmup->sfmmu_ismttecnt[szc] = npgs;
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

	ASSERT(hat->sfmmu_xhat_provider == NULL);

	for (i = 0; i < mmu_page_sizes; i++)
		assize += (pgcnt_t)hat->sfmmu_ttecnt[i] * TTEBYTES(i);

	if (hat->sfmmu_iblk == NULL)
		return (assize);

	for (i = 0; i < mmu_page_sizes; i++)
		assize += (pgcnt_t)hat->sfmmu_ismttecnt[i] * TTEBYTES(i);

	return (assize);
}

int
hat_stats_enable(struct hat *hat)
{
	hatlock_t	*hatlockp;

	ASSERT(hat->sfmmu_xhat_provider == NULL);

	hatlockp = sfmmu_hat_enter(hat);
	hat->sfmmu_rmstat++;
	sfmmu_hat_exit(hatlockp);
	return (1);
}

void
hat_stats_disable(struct hat *hat)
{
	hatlock_t	*hatlockp;

	ASSERT(hat->sfmmu_xhat_provider == NULL);

	hatlockp = sfmmu_hat_enter(hat);
	hat->sfmmu_rmstat--;
	sfmmu_hat_exit(hatlockp);
}

/*
 * Routines for entering or removing  ourselves from the
 * ism_hat's mapping list.
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

	ASSERT(sfmmup->sfmmu_xhat_provider == NULL);

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
	while (ism_blkp) {
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
				ism_map[i].imap_vb_shift = (ushort_t)ismshift;
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
				ism_hatid->sfmmu_flags = 0;
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
	 * Update our counters for this sfmmup's ism mappings.
	 */
	for (i = 0; i <= ismszc; i++) {
		if (!(disable_ism_large_pages & (1 << i)))
			(void) ism_tsb_entries(sfmmup, i);
	}

	hatlockp = sfmmu_hat_enter(sfmmup);

	/*
	 * For ISM and DISM we do not support 512K pages, so we only
	 * only search the 4M and 8K/64K hashes for 4 pagesize cpus, and search
	 * the 256M or 32M, and 4M and 8K/64K hashes for 6 pagesize cpus.
	 */
	ASSERT((disable_ism_large_pages & (1 << TTE512K)) != 0);

	if (ismszc > TTE4M && !SFMMU_FLAGS_ISSET(sfmmup, HAT_4M_FLAG))
		SFMMU_FLAGS_SET(sfmmup, HAT_4M_FLAG);

	if (!SFMMU_FLAGS_ISSET(sfmmup, HAT_64K_FLAG))
		SFMMU_FLAGS_SET(sfmmup, HAT_64K_FLAG);

	/*
	 * If we updated the ismblkpa for this HAT or we need
	 * to start searching the 256M or 32M or 4M hash, we must
	 * make sure all CPUs running this process reload their
	 * tsbmiss area.  Otherwise they will fail to load the mappings
	 * in the tsbmiss handler and will loop calling pagefault().
	 */
	switch (ismszc) {
	case TTE256M:
		if (reload_mmu || !SFMMU_FLAGS_ISSET(sfmmup, HAT_256M_FLAG)) {
			SFMMU_FLAGS_SET(sfmmup, HAT_256M_FLAG);
			sfmmu_sync_mmustate(sfmmup);
		}
		break;
	case TTE32M:
		if (reload_mmu || !SFMMU_FLAGS_ISSET(sfmmup, HAT_32M_FLAG)) {
			SFMMU_FLAGS_SET(sfmmup, HAT_32M_FLAG);
			sfmmu_sync_mmustate(sfmmup);
		}
		break;
	case TTE4M:
		if (reload_mmu || !SFMMU_FLAGS_ISSET(sfmmup, HAT_4M_FLAG)) {
			SFMMU_FLAGS_SET(sfmmup, HAT_4M_FLAG);
			sfmmu_sync_mmustate(sfmmup);
		}
		break;
	default:
		break;
	}

	/*
	 * Now we can drop the locks.
	 */
	sfmmu_ismhat_exit(sfmmup, 1);
	sfmmu_hat_exit(hatlockp);

	/*
	 * Free up ismblk if we didn't use it.
	 */
	if (new_iblk != NULL)
		kmem_cache_free(ism_blk_cache, new_iblk);

	/*
	 * Check TSB and TLB page sizes.
	 */
	sfmmu_check_page_sizes(sfmmup, 1);

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
	struct ctx	*ctx;
	int 		cnum, found, i;
	hatlock_t	*hatlockp;
	struct tsb_info	*tsbinfo;
	uint_t		ismshift = page_get_shift(ismszc);
	size_t		sh_size = ISM_SHIFT(ismshift, len);

	ASSERT(ISM_ALIGNED(ismshift, addr));
	ASSERT(ISM_ALIGNED(ismshift, len));
	ASSERT(sfmmup != NULL);
	ASSERT(sfmmup != ksfmmup);

	if (sfmmup->sfmmu_xhat_provider) {
		XHAT_UNSHARE(sfmmup, addr, len);
		return;
	} else {
		/*
		 * This must be a CPU HAT. If the address space has
		 * XHATs attached, inform all XHATs that ISM segment
		 * is going away
		 */
		ASSERT(sfmmup->sfmmu_as != NULL);
		if (sfmmup->sfmmu_as->a_xhat != NULL)
			xhat_unshare_all(sfmmup->sfmmu_as, addr, len);
	}

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
	while (!found && ism_blkp) {
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
		ASSERT(ism_hatid != NULL);
		ASSERT(ism_hatid->sfmmu_ismhat == 1);
		ASSERT(ism_hatid->sfmmu_cnum == INVALID_CONTEXT);

		/*
		 * First remove ourselves from the ism mapping list.
		 */
		mutex_enter(&ism_mlist_lock);
		iment_sub(ism_map[i].imap_ment, ism_hatid);
		mutex_exit(&ism_mlist_lock);
		free_ment = ism_map[i].imap_ment;

		/*
		 * Now gurantee that any other cpu
		 * that tries to process an ISM miss
		 * will go to tl=0.
		 */
		hatlockp = sfmmu_hat_enter(sfmmup);
		ctx = sfmmutoctx(sfmmup);
		rw_enter(&ctx->ctx_rwlock, RW_WRITER);
		cnum = sfmmutoctxnum(sfmmup);

		if (cnum != INVALID_CONTEXT) {
			sfmmu_tlb_swap_ctx(sfmmup, ctx);
		}
		rw_exit(&ctx->ctx_rwlock);
		sfmmu_hat_exit(hatlockp);

		/*
		 * We delete the ism map by copying
		 * the next map over the current one.
		 * We will take the next one in the maps
		 * array or from the next ism_blk.
		 */
		while (ism_blkp) {
			ism_map = ism_blkp->iblk_maps;
			while (i < (ISM_MAP_SLOTS - 1)) {
				ism_map[i] = ism_map[i + 1];
				i++;
			}
			/* i == (ISM_MAP_SLOTS - 1) */
			ism_blkp = ism_blkp->iblk_next;
			if (ism_blkp) {
				ism_map[i] = ism_blkp->iblk_maps[0];
				i = 0;
			} else {
				ism_map[i].imap_seg = 0;
				ism_map[i].imap_vb_shift = 0;
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
	if (!sfmmup->sfmmu_free)
		sfmmu_check_page_sizes(sfmmup, 0);
}

/* ARGSUSED */
static int
sfmmu_idcache_constructor(void *buf, void *cdrarg, int kmflags)
{
	/* void *buf is sfmmu_t pointer */
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
	uint64_t hblkpa, prevpa, nx_pa;
	struct hmehash_bucket *hmebp;
	struct hme_blk *hmeblkp, *nx_hblk, *pr_hblk = NULL;
	static struct hmehash_bucket *uhmehash_reclaim_hand;
	static struct hmehash_bucket *khmehash_reclaim_hand;
	struct hme_blk *list = NULL;

	hmebp = uhmehash_reclaim_hand;
	if (hmebp == NULL || hmebp > &uhme_hash[UHMEHASH_SZ])
		uhmehash_reclaim_hand = hmebp = uhme_hash;
	uhmehash_reclaim_hand += UHMEHASH_SZ / sfmmu_cache_reclaim_scan_ratio;

	for (i = UHMEHASH_SZ / sfmmu_cache_reclaim_scan_ratio; i; i--) {
		if (SFMMU_HASH_LOCK_TRYENTER(hmebp) != 0) {
			hmeblkp = hmebp->hmeblkp;
			hblkpa = hmebp->hmeh_nextpa;
			prevpa = 0;
			pr_hblk = NULL;
			while (hmeblkp) {
				nx_hblk = hmeblkp->hblk_next;
				nx_pa = hmeblkp->hblk_nextpa;
				if (!hmeblkp->hblk_vcnt &&
				    !hmeblkp->hblk_hmecnt) {
					sfmmu_hblk_hash_rm(hmebp, hmeblkp,
						prevpa, pr_hblk);
					sfmmu_hblk_free(hmebp, hmeblkp,
					    hblkpa, &list);
				} else {
					pr_hblk = hmeblkp;
					prevpa = hblkpa;
				}
				hmeblkp = nx_hblk;
				hblkpa = nx_pa;
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
			hblkpa = hmebp->hmeh_nextpa;
			prevpa = 0;
			pr_hblk = NULL;
			while (hmeblkp) {
				nx_hblk = hmeblkp->hblk_next;
				nx_pa = hmeblkp->hblk_nextpa;
				if (!hmeblkp->hblk_vcnt &&
				    !hmeblkp->hblk_hmecnt) {
					sfmmu_hblk_hash_rm(hmebp, hmeblkp,
						prevpa, pr_hblk);
					sfmmu_hblk_free(hmebp, hmeblkp,
					    hblkpa, &list);
				} else {
					pr_hblk = hmeblkp;
					prevpa = hblkpa;
				}
				hmeblkp = nx_hblk;
				hblkpa = nx_pa;
			}
			SFMMU_HASH_UNLOCK(hmebp);
		}
		if (hmebp++ == &khme_hash[KHMEHASH_SZ])
			hmebp = khme_hash;
	}
	sfmmu_hblks_list_purge(&list);
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
int
sfmmu_get_ppvcolor(struct page *pp)
{
	int color;

	if (!(cache & CACHE_VAC) || PP_NEWPAGE(pp)) {
		return (-1);
	}
	color = PP_GET_VCOLOR(pp);
	ASSERT(color < mmu_btop(shm_alignment));
	return (color);
}

/*
 * This function will return the desired alignment for vac consistency
 * (vac color) given a virtual address.  If no vac is present it returns -1.
 */
int
sfmmu_get_addrvcolor(caddr_t vaddr)
{
	if (cache & CACHE_VAC) {
		return (addr_to_vcolor(vaddr));
	} else {
		return (-1);
	}

}

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
		hmeblkp = sfmmu_hmetohblk(sfhmep);
		if (hmeblkp->hblk_xhat_bit)
			continue;
		tmphat = hblktosfmmu(hmeblkp);
		sfmmu_copytte(&sfhmep->hme_tte, &tte);
		ASSERT(TTE_IS_VALID(&tte));
		if ((tmphat == hat) || hmeblkp->hblk_lckcnt) {
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
		hmeblkp = sfmmu_hmetohblk(sfhmep);
		if (hmeblkp->hblk_xhat_bit)
			continue;
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
static void
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
static int
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
			hmeblkp = sfmmu_hmetohblk(sfhme);
			if (hmeblkp->hblk_xhat_bit)
				continue;

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

static void
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

		hmeblkp = sfmmu_hmetohblk(sfhme);

		if (hmeblkp->hblk_xhat_bit)
			continue;

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
			if (sfmmup->sfmmu_ismhat) {
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
			if (sfmmup->sfmmu_ismhat) {
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

/*
 * This routine gets called when the system has run out of free contexts.
 * This will simply choose context passed to it to be stolen and reused.
 */
/* ARGSUSED */
static void
sfmmu_reuse_ctx(struct ctx *ctx, sfmmu_t *sfmmup)
{
	sfmmu_t *stolen_sfmmup;
	cpuset_t cpuset;
	ushort_t	cnum = ctxtoctxnum(ctx);

	ASSERT(cnum != KCONTEXT);
	ASSERT(rw_read_locked(&ctx->ctx_rwlock) == 0);	/* write locked */

	/*
	 * simply steal and reuse the ctx passed to us.
	 */
	stolen_sfmmup = ctx->ctx_sfmmu;
	ASSERT(sfmmu_hat_lock_held(sfmmup));
	ASSERT(stolen_sfmmup->sfmmu_cnum == cnum);
	ASSERT(stolen_sfmmup != ksfmmup);

	TRACE_CTXS(&ctx_trace_mutex, ctx_trace_ptr, cnum, stolen_sfmmup,
	    sfmmup, CTX_TRC_STEAL);
	SFMMU_STAT(sf_ctxsteal);

	/*
	 * Update sfmmu and ctx structs. After this point all threads
	 * belonging to this hat/proc will fault and not use the ctx
	 * being stolen.
	 */
	kpreempt_disable();
	/*
	 * Enforce reverse order of assignments from sfmmu_get_ctx().  This
	 * is done to prevent a race where a thread faults with the context
	 * but the TSB has changed.
	 */
	stolen_sfmmup->sfmmu_cnum = INVALID_CONTEXT;
	membar_enter();
	ctx->ctx_sfmmu = NULL;

	/*
	 * 1. flush TLB in all CPUs that ran the process whose ctx
	 * we are stealing.
	 * 2. change context for all other CPUs to INVALID_CONTEXT,
	 * if they are running in the context that we are going to steal.
	 */
	cpuset = stolen_sfmmup->sfmmu_cpusran;
	CPUSET_DEL(cpuset, CPU->cpu_id);
	CPUSET_AND(cpuset, cpu_ready_set);
	SFMMU_XCALL_STATS(cnum);
	xt_some(cpuset, sfmmu_ctx_steal_tl1, cnum, INVALID_CONTEXT);
	xt_sync(cpuset);

	/*
	 * flush TLB of local processor
	 */
	vtag_flushctx(cnum);

	/*
	 * If we just stole the ctx from the current process
	 * on local cpu then we also invalidate his context
	 * here.
	 */
	if (sfmmu_getctx_sec() == cnum) {
		sfmmu_setctx_sec(INVALID_CONTEXT);
		sfmmu_clear_utsbinfo();
	}

	kpreempt_enable();
	SFMMU_STAT(sf_tlbflush_ctx);
}

/*
 * Returns a context with the reader lock held.
 *
 * We maintain 2 different list of contexts.  The first list
 * is the free list and it is headed by ctxfree.  These contexts
 * are ready to use.  The second list is the dirty list and is
 * headed by ctxdirty. These contexts have been freed but haven't
 * been flushed from the TLB.
 *
 * It's the responsibility of the caller to guarantee that the
 * process serializes on calls here by taking the HAT lock for
 * the hat.
 *
 * Changing the page size is a rather complicated process, so
 * rather than jump through lots of hoops to special case it,
 * the easiest way to go about it is to tell the MMU we want
 * to change page sizes and then switch to using a different
 * context.  When we program the context registers for the
 * process, we can take care of setting up the (new) page size
 * for that context at that point.
 */

static struct ctx *
sfmmu_get_ctx(sfmmu_t *sfmmup)
{
	struct ctx *ctx;
	ushort_t cnum;
	struct ctx *lastctx = &ctxs[nctxs-1];
	struct ctx *firstctx = &ctxs[NUM_LOCKED_CTXS];
	uint_t	found_stealable_ctx;
	uint_t	retry_count = 0;

#define	NEXT_CTX(ctx)   (((ctx) >= lastctx) ? firstctx : ((ctx) + 1))

retry:

	ASSERT(sfmmup->sfmmu_cnum != KCONTEXT);
	/*
	 * Check to see if this process has already got a ctx.
	 * In that case just set the sec-ctx, grab a readers lock, and
	 * return.
	 *
	 * We have to double check after we get the readers lock on the
	 * context, since it could be stolen in this short window.
	 */
	if (sfmmup->sfmmu_cnum >= NUM_LOCKED_CTXS) {
		ctx = sfmmutoctx(sfmmup);
		rw_enter(&ctx->ctx_rwlock, RW_READER);
		if (ctx->ctx_sfmmu == sfmmup) {
			return (ctx);
		} else {
			rw_exit(&ctx->ctx_rwlock);
		}
	}

	found_stealable_ctx = 0;
	mutex_enter(&ctx_list_lock);
	if ((ctx = ctxfree) != NULL) {
		/*
		 * Found a ctx in free list. Delete it from the list and
		 * use it.  There's a short window where the stealer can
		 * look at the context before we grab the lock on the
		 * context, so we have to handle that with the free flag.
		 */
		SFMMU_STAT(sf_ctxfree);
		ctxfree = ctx->ctx_free;
		ctx->ctx_sfmmu = NULL;
		mutex_exit(&ctx_list_lock);
		rw_enter(&ctx->ctx_rwlock, RW_WRITER);
		ASSERT(ctx->ctx_sfmmu == NULL);
		ASSERT((ctx->ctx_flags & CTX_FREE_FLAG) != 0);
	} else if ((ctx = ctxdirty) != NULL) {
		/*
		 * No free contexts.  If we have at least one dirty ctx
		 * then flush the TLBs on all cpus if necessary and move
		 * the dirty list to the free list.
		 */
		SFMMU_STAT(sf_ctxdirty);
		ctxdirty = NULL;
		if (delay_tlb_flush)
			sfmmu_tlb_all_demap();
		ctxfree = ctx->ctx_free;
		ctx->ctx_sfmmu = NULL;
		mutex_exit(&ctx_list_lock);
		rw_enter(&ctx->ctx_rwlock, RW_WRITER);
		ASSERT(ctx->ctx_sfmmu == NULL);
		ASSERT((ctx->ctx_flags & CTX_FREE_FLAG) != 0);
	} else {
		/*
		 * No free context available, so steal one.
		 *
		 * The policy to choose the appropriate context is simple;
		 * just sweep all the ctxs using ctxhand. This will steal
		 * the LRU ctx.
		 *
		 * We however only steal a non-free context that can be
		 * write locked.  Keep searching till we find a stealable
		 * ctx.
		 */
		mutex_exit(&ctx_list_lock);
		ctx = ctxhand;
		do {
			/*
			 * If you get the writers lock, and the ctx isn't
			 * a free ctx, THEN you can steal this ctx.
			 */
			if ((ctx->ctx_flags & CTX_FREE_FLAG) == 0 &&
			    rw_tryenter(&ctx->ctx_rwlock, RW_WRITER) != 0) {
				if (ctx->ctx_flags & CTX_FREE_FLAG) {
					/* let the first guy have it */
					rw_exit(&ctx->ctx_rwlock);
				} else {
					found_stealable_ctx = 1;
					break;
				}
			}
			ctx = NEXT_CTX(ctx);
		} while (ctx != ctxhand);

		if (found_stealable_ctx) {
			/*
			 * Try and reuse the ctx.
			 */
			sfmmu_reuse_ctx(ctx, sfmmup);

		} else if (retry_count++ < GET_CTX_RETRY_CNT) {
			goto retry;

		} else {
			panic("Can't find any stealable context");
		}
	}

	ASSERT(rw_read_locked(&ctx->ctx_rwlock) == 0);	/* write locked */
	ctx->ctx_sfmmu = sfmmup;

	/*
	 * Clear the ctx_flags field.
	 */
	ctx->ctx_flags = 0;

	cnum = ctxtoctxnum(ctx);
	membar_exit();
	sfmmup->sfmmu_cnum = cnum;

	/*
	 * Let the MMU set up the page sizes to use for
	 * this context in the TLB. Don't program 2nd dtlb for ism hat.
	 */
	if ((&mmu_set_ctx_page_sizes) && (sfmmup->sfmmu_ismhat == 0))
		mmu_set_ctx_page_sizes(sfmmup);

	/*
	 * Downgrade to reader's lock.
	 */
	rw_downgrade(&ctx->ctx_rwlock);

	/*
	 * If this value doesn't get set to what we want
	 * it won't matter, so don't worry about locking.
	 */
	ctxhand = NEXT_CTX(ctx);

	/*
	 * Better not have been stolen while we held the ctx'
	 * lock or we're hosed.
	 */
	ASSERT(sfmmup == sfmmutoctx(sfmmup)->ctx_sfmmu);

	return (ctx);

#undef NEXT_CTX
}


/*
 * Set the process context to INVALID_CONTEXT (but
 * without stealing the ctx) so that it faults and
 * reloads the MMU state from TL=0.  Caller must
 * hold the hat lock since we don't acquire it here.
 */
static void
sfmmu_sync_mmustate(sfmmu_t *sfmmup)
{
	int cnum;
	cpuset_t cpuset;

	ASSERT(sfmmup != ksfmmup);
	ASSERT(sfmmu_hat_lock_held(sfmmup));

	kpreempt_disable();

	cnum = sfmmutoctxnum(sfmmup);
	if (cnum != INVALID_CONTEXT) {
		cpuset = sfmmup->sfmmu_cpusran;
		CPUSET_DEL(cpuset, CPU->cpu_id);
		CPUSET_AND(cpuset, cpu_ready_set);
		SFMMU_XCALL_STATS(cnum);

		xt_some(cpuset, sfmmu_raise_tsb_exception,
		    cnum, INVALID_CONTEXT);
		xt_sync(cpuset);

		/*
		 * If the process is running on the local CPU
		 * we need to update the MMU state here as well.
		 */
		if (sfmmu_getctx_sec() == cnum)
			sfmmu_load_mmustate(sfmmup);

		SFMMU_STAT(sf_tsb_raise_exception);
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
	cpuset_t cpuset;
	struct ctx *ctx = NULL;
	int ctxnum;

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
	    prevtsb = curtsb, curtsb = curtsb->tsb_next);
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
	 */
	sfmmu_hat_exit(hatlockp);
	if (sfmmu_tsbinfo_alloc(&new_tsbinfo, szc, tte_sz_mask,
	    flags, sfmmup)) {
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
	    prevtsb = curtsb, curtsb = curtsb->tsb_next);
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
		ctx = sfmmutoctx(sfmmup);
		rw_enter(&ctx->ctx_rwlock, RW_WRITER);

		ctxnum = sfmmutoctxnum(sfmmup);
		sfmmup->sfmmu_cnum = INVALID_CONTEXT;
		membar_enter();	/* make sure visible on all CPUs */

		kpreempt_disable();
		if (ctxnum != INVALID_CONTEXT) {
			cpuset = sfmmup->sfmmu_cpusran;
			CPUSET_DEL(cpuset, CPU->cpu_id);
			CPUSET_AND(cpuset, cpu_ready_set);
			SFMMU_XCALL_STATS(ctxnum);

			xt_some(cpuset, sfmmu_raise_tsb_exception,
			    ctxnum, INVALID_CONTEXT);
			xt_sync(cpuset);

			SFMMU_STAT(sf_tsb_raise_exception);
		}
		kpreempt_enable();
	} else {
		/*
		 * It is illegal to swap in TSBs from a process other
		 * than a process being swapped in.  This in turn
		 * implies we do not have a valid MMU context here
		 * since a process needs one to resolve translation
		 * misses.
		 */
		ASSERT(curthread->t_procp->p_as->a_hat == sfmmup);
		ASSERT(sfmmutoctxnum(sfmmup) == INVALID_CONTEXT);
	}

	new_tsbinfo->tsb_next = old_tsbinfo->tsb_next;
	membar_stst();	/* strict ordering required */
	if (prevtsb)
		prevtsb->tsb_next = new_tsbinfo;
	else
		sfmmup->sfmmu_tsb = new_tsbinfo;
	membar_enter();	/* make sure new TSB globally visible */
	sfmmu_setup_tsbinfo(sfmmup);

	/*
	 * We need to migrate TSB entries from the old TSB to the new TSB
	 * if tsb_remap_ttes is set and the TSB is growing.
	 */
	if (tsb_remap_ttes && ((flags & TSB_GROW) == TSB_GROW))
		sfmmu_copy_tsb(old_tsbinfo, new_tsbinfo);

	if ((flags & TSB_SWAPIN) != TSB_SWAPIN) {
		kpreempt_disable();
		membar_exit();
		sfmmup->sfmmu_cnum = ctxnum;
		if (ctxnum != INVALID_CONTEXT &&
		    sfmmu_getctx_sec() == ctxnum) {
			sfmmu_load_mmustate(sfmmup);
		}
		kpreempt_enable();
		rw_exit(&ctx->ctx_rwlock);
	}

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
 * Steal context from process, forcing the process to switch to another
 * context on the next TLB miss, and therefore start using the TLB that
 * is reprogrammed for the new page sizes.
 */
void
sfmmu_steal_context(sfmmu_t *sfmmup, uint8_t *tmp_pgsz)
{
	struct ctx *ctx;
	int i, cnum;
	hatlock_t *hatlockp = NULL;

	hatlockp = sfmmu_hat_enter(sfmmup);
	/* USIII+-IV+ optimization, requires hat lock */
	if (tmp_pgsz) {
		for (i = 0; i < mmu_page_sizes; i++)
			sfmmup->sfmmu_pgsz[i] = tmp_pgsz[i];
	}
	SFMMU_STAT(sf_tlb_reprog_pgsz);
	ctx = sfmmutoctx(sfmmup);
	rw_enter(&ctx->ctx_rwlock, RW_WRITER);
	cnum = sfmmutoctxnum(sfmmup);

	if (cnum != INVALID_CONTEXT) {
		sfmmu_tlb_swap_ctx(sfmmup, ctx);
	}
	rw_exit(&ctx->ctx_rwlock);
	sfmmu_hat_exit(hatlockp);
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

	if ((sfmmup->sfmmu_flags & HAT_LGPG_FLAGS) == 0 &&
	    sfmmup->sfmmu_ttecnt[TTE8K] <= tsb_rss_factor)
		return;

	for (i = 0; i < mmu_page_sizes; i++) {
		ttecnt[i] = SFMMU_TTE_CNT(sfmmup, i);
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
			    allocflags, sfmmup) != 0) &&
			    (sfmmu_tsbinfo_alloc(&newtsb, TSB_MIN_SZCODE,
			    tsb_bits, allocflags, sfmmup) != 0)) {
				return;
			}

			hatlockp = sfmmu_hat_enter(sfmmup);

			if (sfmmup->sfmmu_tsb->tsb_next == NULL) {
				sfmmup->sfmmu_tsb->tsb_next = newtsb;
				SFMMU_STAT(sf_tsb_sectsb_create);
				sfmmu_setup_tsbinfo(sfmmup);
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
 * Get the preferred page size code for a hat.
 * This is only advice, so locking is not done;
 * this transitory information could change
 * following the call anyway.  This interface is
 * sun4 private.
 */
/*ARGSUSED*/
uint_t
hat_preferred_pgsz(struct hat *hat, caddr_t vaddr, size_t maplen, int maptype)
{
	sfmmu_t *sfmmup = (sfmmu_t *)hat;
	uint_t szc, maxszc = mmu_page_sizes - 1;
	size_t pgsz;

	if (maptype == MAPPGSZ_ISM) {
		for (szc = maxszc; szc >= TTE4M; szc--) {
			if (disable_ism_large_pages & (1 << szc))
				continue;

			pgsz = hw_page_array[szc].hp_size;
			if ((maplen >= pgsz) && IS_P2ALIGNED(vaddr, pgsz))
				return (szc);
		}
		return (TTE4M);
	} else if (&mmu_preferred_pgsz) { /* USIII+-USIV+ */
		return (mmu_preferred_pgsz(sfmmup, vaddr, maplen));
	} else {	/* USIII, USII, Niagara */
		for (szc = maxszc; szc > TTE8K; szc--) {
			if (disable_large_pages & (1 << szc))
				continue;

			pgsz = hw_page_array[szc].hp_size;
			if ((maplen >= pgsz) && IS_P2ALIGNED(vaddr, pgsz))
				return (szc);
		}
		return (TTE8K);
	}
}

/*
 * Free up a ctx
 */
static void
sfmmu_free_ctx(sfmmu_t *sfmmup, struct ctx *ctx)
{
	int ctxnum;

	rw_enter(&ctx->ctx_rwlock, RW_WRITER);

	TRACE_CTXS(&ctx_trace_mutex, ctx_trace_ptr, sfmmup->sfmmu_cnum,
	    sfmmup, 0, CTX_TRC_FREE);

	if (sfmmup->sfmmu_cnum == INVALID_CONTEXT) {
		CPUSET_ZERO(sfmmup->sfmmu_cpusran);
		rw_exit(&ctx->ctx_rwlock);
		return;
	}

	ASSERT(sfmmup == ctx->ctx_sfmmu);

	ctx->ctx_sfmmu = NULL;
	ctx->ctx_flags = 0;
	sfmmup->sfmmu_cnum = INVALID_CONTEXT;
	membar_enter();
	CPUSET_ZERO(sfmmup->sfmmu_cpusran);
	ctxnum = sfmmu_getctx_sec();
	if (ctxnum == ctxtoctxnum(ctx)) {
		sfmmu_setctx_sec(INVALID_CONTEXT);
		sfmmu_clear_utsbinfo();
	}

	/*
	 * Put the freed ctx on the dirty list
	 */
	mutex_enter(&ctx_list_lock);
	CTX_SET_FLAGS(ctx, CTX_FREE_FLAG);
	ctx->ctx_free = ctxdirty;
	ctxdirty = ctx;
	mutex_exit(&ctx_list_lock);

	rw_exit(&ctx->ctx_rwlock);
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
	ASSERT(sfmmup->sfmmu_cnum == INVALID_CONTEXT);
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

static void
sfmmu_page_exit(kmutex_t *spl)
{
	mutex_exit(spl);
}

static int
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
			 * If the current thread is owning hblk_reserve,
			 * let it succede even if freehblkcnt is really low.
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
			return (1);
		}
		mutex_exit(&freehblkp_lock);
	}
	SFMMU_STAT(sf_get_free_fail);
	return (0);
}

static uint_t
sfmmu_put_free_hblk(struct hme_blk *hmeblkp, uint_t critical)
{
	struct  hme_blk *hblkp;

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
	uint64_t hblkpa, prevpa, newpa;
	caddr_t	base, vaddr, endaddr;
	struct hmehash_bucket *hmebp;
	struct sf_hment *osfhme, *nsfhme;
	page_t *pp;
	kmutex_t *pml;
	tte_t tte;

#ifdef	DEBUG
	hmeblk_tag		hblktag;
	struct hme_blk		*found;
#endif
	old = HBLK_RESERVE;

	/*
	 * save pa before bcopy clobbers it
	 */
	newpa = new->hblk_nextpa;

	base = (caddr_t)get_hblk_base(old);
	endaddr = base + get_hblk_span(old);

	/*
	 * acquire hash bucket lock.
	 */
	hmebp = sfmmu_tteload_acquire_hashbucket(ksfmmup, base, TTE8K);

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
	 * after adding new, otherwise prevpa and prev won't correspond
	 * to the hblk which is prior to old in hash chain when we call
	 * sfmmu_hblk_hash_rm to remove old later.
	 */
	for (prevpa = 0, prev = NULL,
	    hblkpa = hmebp->hmeh_nextpa, hblkp = hmebp->hmeblkp;
	    hblkp != NULL && hblkp != old;
	    prevpa = hblkpa, prev = hblkp,
	    hblkpa = hblkp->hblk_nextpa, hblkp = hblkp->hblk_next);

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
	sfmmu_hblk_hash_rm(hmebp, old, prevpa, prev);

#ifdef	DEBUG

	hblktag.htag_id = ksfmmup;
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
	uint_t flags)
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

	ASSERT(SFMMU_HASH_LOCK_ISHELD(hmebp));

	/*
	 * If segkmem is not created yet, allocate from static hmeblks
	 * created at the end of startup_modules().  See the block comment
	 * in startup_modules() describing how we estimate the number of
	 * static hmeblks that will be needed during re-map.
	 */
	if (!hblk_alloc_dynamic) {

		if (size == TTE8K) {
			index = nucleus_hblk8.index;
			if (index >= nucleus_hblk8.len) {
				/*
				 * If we panic here, see startup_modules() to
				 * make sure that we are calculating the
				 * number of hblk8's that we need correctly.
				 */
				panic("no nucleus hblk8 to allocate");
			}
			hmeblkp =
			    (struct hme_blk *)&nucleus_hblk8.list[index];
			nucleus_hblk8.index++;
			SFMMU_STAT(sf_hblk8_nalloc);
		} else {
			index = nucleus_hblk1.index;
			if (nucleus_hblk1.index >= nucleus_hblk1.len) {
				/*
				 * If we panic here, see startup_modules()
				 * and H8TOH1; most likely you need to
				 * update the calculation of the number
				 * of hblk1's the kernel needs to boot.
				 */
				panic("no nucleus hblk1 to allocate");
			}
			hmeblkp =
			    (struct hme_blk *)&nucleus_hblk1.list[index];
			nucleus_hblk1.index++;
			SFMMU_STAT(sf_hblk1_nalloc);
		}

		goto hblk_init;
	}

	SFMMU_HASH_UNLOCK(hmebp);

	if (sfmmup != KHATID) {
		if (mmu_page_sizes == max_mmu_page_sizes) {
			if (size < TTE256M)
				shw_hblkp = sfmmu_shadow_hcreate(sfmmup, vaddr,
				    size, flags);
		} else {
			if (size < TTE4M)
				shw_hblkp = sfmmu_shadow_hcreate(sfmmup, vaddr,
				    size, flags);
		}
	}

fill_hblk:
	owner = (hblk_reserve_thread == curthread) ? 1 : 0;

	if (owner && size == TTE8K) {

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
			if (size == TTE8K && sfmmup != KHATID)
				if (sfmmu_put_free_hblk(hmeblkp, 0))
					goto fill_hblk;
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
	set_hblk_sz(hmeblkp, size);
	ASSERT(SFMMU_HASH_LOCK_ISHELD(hmebp));
	hmeblkp->hblk_next = (struct hme_blk *)NULL;
	hmeblkp->hblk_tag = hblktag;
	hmeblkp->hblk_shadow = shw_hblkp;
	hblkpa = hmeblkp->hblk_nextpa;
	hmeblkp->hblk_nextpa = 0;

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
 * This function performs any cleanup required on the hme_blk
 * and returns it to the free list.
 */
/* ARGSUSED */
static void
sfmmu_hblk_free(struct hmehash_bucket *hmebp, struct hme_blk *hmeblkp,
	uint64_t hblkpa, struct hme_blk **listp)
{
	int shw_size, vshift;
	struct hme_blk *shw_hblkp;
	uint_t		shw_mask, newshw_mask;
	uintptr_t	vaddr;
	int		size;
	uint_t		critical;

	ASSERT(hmeblkp);
	ASSERT(!hmeblkp->hblk_hmecnt);
	ASSERT(!hmeblkp->hblk_vcnt);
	ASSERT(!hmeblkp->hblk_lckcnt);
	ASSERT(hblkpa == va_to_pa((caddr_t)hmeblkp));
	ASSERT(hmeblkp != (struct hme_blk *)hblk_reserve);

	critical = (hblktosfmmu(hmeblkp) == KHATID) ? 1 : 0;

	size = get_hblk_ttesz(hmeblkp);
	shw_hblkp = hmeblkp->hblk_shadow;
	if (shw_hblkp) {
		ASSERT(hblktosfmmu(hmeblkp) != KHATID);
		if (mmu_page_sizes == max_mmu_page_sizes) {
			ASSERT(size < TTE256M);
		} else {
			ASSERT(size < TTE4M);
		}

		shw_size = get_hblk_ttesz(shw_hblkp);
		vaddr = get_hblk_base(hmeblkp);
		vshift = vaddr_to_vshift(shw_hblkp->hblk_tag, vaddr, shw_size);
		ASSERT(vshift < 8);
		/*
		 * Atomically clear shadow mask bit
		 */
		do {
			shw_mask = shw_hblkp->hblk_shw_mask;
			ASSERT(shw_mask & (1 << vshift));
			newshw_mask = shw_mask & ~(1 << vshift);
			newshw_mask = cas32(&shw_hblkp->hblk_shw_mask,
				shw_mask, newshw_mask);
		} while (newshw_mask != shw_mask);
		hmeblkp->hblk_shadow = NULL;
	}
	hmeblkp->hblk_next = NULL;
	hmeblkp->hblk_nextpa = hblkpa;
	hmeblkp->hblk_shw_bit = 0;

	if (hmeblkp->hblk_nuc_bit == 0) {

		if (size == TTE8K && sfmmu_put_free_hblk(hmeblkp, critical))
			return;

		hmeblkp->hblk_next = *listp;
		*listp = hmeblkp;
	}
}

static void
sfmmu_hblks_list_purge(struct hme_blk **listp)
{
	struct hme_blk	*hmeblkp;

	while ((hmeblkp = *listp) != NULL) {
		*listp = hmeblkp->hblk_next;
		kmem_cache_free(get_hblk_cache(hmeblkp), hmeblkp);
	}
}

#define	BUCKETS_TO_SEARCH_BEFORE_UNLOAD	30

static uint_t sfmmu_hblk_steal_twice;
static uint_t sfmmu_hblk_steal_count, sfmmu_hblk_steal_unload_count;

/*
 * Steal a hmeblk
 * Enough hmeblks were allocated at startup (nucleus hmeblks) and also
 * hmeblks were added dynamically. We should never ever not be able to
 * find one. Look for an unused/unlocked hmeblk in user hash table.
 */
static struct hme_blk *
sfmmu_hblk_steal(int size)
{
	static struct hmehash_bucket *uhmehash_steal_hand = NULL;
	struct hmehash_bucket *hmebp;
	struct hme_blk *hmeblkp = NULL, *pr_hblk;
	uint64_t hblkpa, prevpa;
	int i;

	for (;;) {
		hmebp = (uhmehash_steal_hand == NULL) ? uhme_hash :
			uhmehash_steal_hand;
		ASSERT(hmebp >= uhme_hash && hmebp <= &uhme_hash[UHMEHASH_SZ]);

		for (i = 0; hmeblkp == NULL && i <= UHMEHASH_SZ +
		    BUCKETS_TO_SEARCH_BEFORE_UNLOAD; i++) {
			SFMMU_HASH_LOCK(hmebp);
			hmeblkp = hmebp->hmeblkp;
			hblkpa = hmebp->hmeh_nextpa;
			prevpa = 0;
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
						    hmeblkp, hblkpa, prevpa,
						    pr_hblk)) {
							/*
							 * Hblk is unloaded
							 * successfully
							 */
							break;
						}
					}
				}
				pr_hblk = hmeblkp;
				prevpa = hblkpa;
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
			prevpa = 0;
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
					    hmeblkp, hblkpa, prevpa, pr_hblk)) {
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
				prevpa = hblkpa;
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
	uint64_t hblkpa, uint64_t prevpa, struct hme_blk *pr_hblk)
{
	int shw_size, vshift;
	struct hme_blk *shw_hblkp;
	uintptr_t vaddr;
	uint_t shw_mask, newshw_mask;

	ASSERT(SFMMU_HASH_LOCK_ISHELD(hmebp));

	/*
	 * check if the hmeblk is free, unload if necessary
	 */
	if (hmeblkp->hblk_vcnt || hmeblkp->hblk_hmecnt) {
		sfmmu_t *sfmmup;
		demap_range_t dmr;

		sfmmup = hblktosfmmu(hmeblkp);
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

	sfmmu_hblk_hash_rm(hmebp, hmeblkp, prevpa, pr_hblk);
	hmeblkp->hblk_nextpa = hblkpa;

	shw_hblkp = hmeblkp->hblk_shadow;
	if (shw_hblkp) {
		shw_size = get_hblk_ttesz(shw_hblkp);
		vaddr = get_hblk_base(hmeblkp);
		vshift = vaddr_to_vshift(shw_hblkp->hblk_tag, vaddr, shw_size);
		ASSERT(vshift < 8);
		/*
		 * Atomically clear shadow mask bit
		 */
		do {
			shw_mask = shw_hblkp->hblk_shw_mask;
			ASSERT(shw_mask & (1 << vshift));
			newshw_mask = shw_mask & ~(1 << vshift);
			newshw_mask = cas32(&shw_hblkp->hblk_shw_mask,
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
 * Make sure that there is a valid ctx, if not get a ctx.
 * Also, get a readers lock on the ctx, so that the ctx cannot
 * be stolen underneath us.
 */
static void
sfmmu_disallow_ctx_steal(sfmmu_t *sfmmup)
{
	struct	ctx *ctx;

	ASSERT(sfmmup != ksfmmup);
	ASSERT(sfmmup->sfmmu_ismhat == 0);

	/*
	 * If ctx has been stolen, get a ctx.
	 */
	if (sfmmup->sfmmu_cnum == INVALID_CONTEXT) {
		/*
		 * Our ctx was stolen. Get a ctx with rlock.
		 */
		ctx = sfmmu_get_ctx(sfmmup);
		return;
	} else {
		ctx = sfmmutoctx(sfmmup);
	}

	/*
	 * Get the reader lock.
	 */
	rw_enter(&ctx->ctx_rwlock, RW_READER);
	if (ctx->ctx_sfmmu != sfmmup) {
		/*
		 * The ctx got stolen, so spin again.
		 */
		rw_exit(&ctx->ctx_rwlock);
		ctx = sfmmu_get_ctx(sfmmup);
	}

	ASSERT(sfmmup->sfmmu_cnum >= NUM_LOCKED_CTXS);
}

/*
 * Decrement reference count for our ctx. If the reference count
 * becomes 0, our ctx can be stolen by someone.
 */
static void
sfmmu_allow_ctx_steal(sfmmu_t *sfmmup)
{
	struct	ctx *ctx;

	ASSERT(sfmmup != ksfmmup);
	ASSERT(sfmmup->sfmmu_ismhat == 0);
	ctx = sfmmutoctx(sfmmup);

	ASSERT(sfmmup == ctx->ctx_sfmmu);
	ASSERT(sfmmup->sfmmu_cnum != INVALID_CONTEXT);
	rw_exit(&ctx->ctx_rwlock);
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

/*
 * Handle exceptions for low level tsb_handler.
 *
 * There are many scenarios that could land us here:
 *
 *	1) Process has no context.  In this case, ctx is
 *         INVALID_CONTEXT and sfmmup->sfmmu_cnum == 1 so
 *         we will acquire a context before returning.
 *      2) Need to re-load our MMU state.  In this case,
 *         ctx is INVALID_CONTEXT and sfmmup->sfmmu_cnum != 1.
 *      3) ISM mappings are being updated.  This is handled
 *         just like case #2.
 *      4) We wish to program a new page size into the TLB.
 *         This is handled just like case #1, since changing
 *         TLB page size requires us to flush the TLB.
 *	5) Window fault and no valid translation found.
 *
 * Cases 1-4, ctx is INVALID_CONTEXT so we handle it and then
 * exit which will retry the trapped instruction.  Case #5 we
 * punt to trap() which will raise us a trap level and handle
 * the fault before unwinding.
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
	sfmmu_t *sfmmup;
	uint_t ctxnum;
	klwp_id_t lwp;
	char lwp_save_state;
	hatlock_t *hatlockp;
	struct tsb_info *tsbinfop;

	SFMMU_STAT(sf_tsb_exceptions);
	sfmmup = astosfmmu(curthread->t_procp->p_as);
	ctxnum = tagaccess & TAGACC_CTX_MASK;

	ASSERT(sfmmup != ksfmmup && ctxnum != KCONTEXT);
	ASSERT(sfmmup->sfmmu_ismhat == 0);
	/*
	 * First, make sure we come out of here with a valid ctx,
	 * since if we don't get one we'll simply loop on the
	 * faulting instruction.
	 *
	 * If the ISM mappings are changing, the TSB is being relocated, or
	 * the process is swapped out we serialize behind the controlling
	 * thread with the sfmmu_flags and sfmmu_tsb_cv condition variable.
	 * Otherwise we synchronize with the context stealer or the thread
	 * that required us to change out our MMU registers (such
	 * as a thread changing out our TSB while we were running) by
	 * locking the HAT and grabbing the rwlock on the context as a
	 * reader temporarily.
	 */
	if (ctxnum == INVALID_CONTEXT ||
	    SFMMU_FLAGS_ISSET(sfmmup, HAT_SWAPPED)) {
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

		sfmmu_disallow_ctx_steal(sfmmup);
		ctxnum = sfmmup->sfmmu_cnum;
		kpreempt_disable();
		sfmmu_setctx_sec(ctxnum);
		sfmmu_load_mmustate(sfmmup);
		kpreempt_enable();
		sfmmu_allow_ctx_steal(sfmmup);
		sfmmu_hat_exit(hatlockp);
		/*
		 * Must restore lwp_state if not calling
		 * trap() for further processing. Restore
		 * it anyway.
		 */
		lwp->lwp_state = lwp_save_state;
		if (sfmmup->sfmmu_ttecnt[TTE8K] != 0 ||
		    sfmmup->sfmmu_ttecnt[TTE64K] != 0 ||
		    sfmmup->sfmmu_ttecnt[TTE512K] != 0 ||
		    sfmmup->sfmmu_ttecnt[TTE4M] != 0 ||
		    sfmmup->sfmmu_ttecnt[TTE32M] != 0 ||
		    sfmmup->sfmmu_ttecnt[TTE256M] != 0) {
			return;
		}
		if (traptype == T_DATA_PROT) {
			traptype = T_DATA_MMU_MISS;
		}
	}
	trap(rp, (caddr_t)tagaccess, traptype, 0);
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
	int 		ctxnum;
	int 		vcolor;
	int		ttesz;

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
		ctxnum = sfmmup->sfmmu_cnum;
		va = ment->iment_base_va;
		va = (caddr_t)((uintptr_t)va  + (uintptr_t)addr);

		/*
		 * Flush TSB of ISM mappings.
		 */
		ttesz = get_hblk_ttesz(hmeblkp);
		if (ttesz == TTE8K || ttesz == TTE4M) {
			sfmmu_unload_tsb(sfmmup, va, ttesz);
		} else {
			caddr_t sva = va;
			caddr_t eva;
			ASSERT(addr == (caddr_t)get_hblk_base(hmeblkp));
			eva = sva + get_hblk_span(hmeblkp);
			sfmmu_unload_tsb_range(sfmmup, sva, eva, ttesz);
		}

		if (ctxnum != INVALID_CONTEXT) {
			/*
			 * Flush TLBs.  We don't need to do this for
			 * invalid context since the flushing is already
			 * done as part of context stealing.
			 */
			cpuset = sfmmup->sfmmu_cpusran;
			CPUSET_AND(cpuset, cpu_ready_set);
			CPUSET_DEL(cpuset, CPU->cpu_id);
			SFMMU_XCALL_STATS(ctxnum);
			xt_some(cpuset, vtag_flushpage_tl1, (uint64_t)va,
			    ctxnum);
			vtag_flushpage(va, ctxnum);
		}

		/*
		 * Flush D$
		 * When flushing D$ we must flush all
		 * cpu's. See sfmmu_cache_flush().
		 */
		if (cache_flush_flag == CACHE_FLUSH) {
			cpuset = cpu_ready_set;
			CPUSET_DEL(cpuset, CPU->cpu_id);
			SFMMU_XCALL_STATS(ctxnum);
			vcolor = addr_to_vcolor(va);
			xt_some(cpuset, vac_flushpage_tl1, pfnum, vcolor);
			vac_flushpage(pfnum, vcolor);
		}
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
	int ctxnum, vcolor;
	cpuset_t cpuset;
	hatlock_t *hatlockp;

	/*
	 * There is no longer a need to protect against ctx being
	 * stolen here since we don't store the ctx in the TSB anymore.
	 */
	vcolor = addr_to_vcolor(addr);

	kpreempt_disable();
	if (!tlb_noflush) {
		/*
		 * Flush the TSB.
		 */
		if (!hat_lock_held)
			hatlockp = sfmmu_hat_enter(sfmmup);
		SFMMU_UNLOAD_TSB(addr, sfmmup, hmeblkp);
		ctxnum = (int)sfmmutoctxnum(sfmmup);
		if (!hat_lock_held)
			sfmmu_hat_exit(hatlockp);

		if (ctxnum != INVALID_CONTEXT) {
			/*
			 * Flush TLBs.  We don't need to do this if our
			 * context is invalid context.  Since we hold the
			 * HAT lock the context must have been stolen and
			 * hence will be flushed before re-use.
			 */
			cpuset = sfmmup->sfmmu_cpusran;
			CPUSET_AND(cpuset, cpu_ready_set);
			CPUSET_DEL(cpuset, CPU->cpu_id);
			SFMMU_XCALL_STATS(ctxnum);
			xt_some(cpuset, vtag_flushpage_tl1, (uint64_t)addr,
				ctxnum);
			vtag_flushpage(addr, ctxnum);
		}
	}

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
		SFMMU_XCALL_STATS(sfmmutoctxnum(sfmmup));
		xt_some(cpuset, vac_flushpage_tl1, pfnum, vcolor);
		vac_flushpage(pfnum, vcolor);
	}
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
	int ctxnum;
	cpuset_t cpuset;
	hatlock_t *hatlockp;

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
	SFMMU_UNLOAD_TSB(addr, sfmmup, hmeblkp);
	ctxnum = sfmmutoctxnum(sfmmup);
	if (!hat_lock_held)
		sfmmu_hat_exit(hatlockp);

	/*
	 * Flush TLBs.  We don't need to do this if our context is invalid
	 * context.  Since we hold the HAT lock the context must have been
	 * stolen and hence will be flushed before re-use.
	 */
	if (ctxnum != INVALID_CONTEXT) {
		/*
		 * There is no need to protect against ctx being stolen.
		 * If the ctx is stolen we will simply get an extra flush.
		 */
		kpreempt_disable();
		cpuset = sfmmup->sfmmu_cpusran;
		CPUSET_AND(cpuset, cpu_ready_set);
		CPUSET_DEL(cpuset, CPU->cpu_id);
		SFMMU_XCALL_STATS(ctxnum);
		xt_some(cpuset, vtag_flushpage_tl1, (uint64_t)addr, ctxnum);
		vtag_flushpage(addr, ctxnum);
		kpreempt_enable();
	}
}

/*
 * Special case of sfmmu_tlb_demap for MMU_PAGESIZE hblks. Use the xcall
 * call handler that can flush a range of pages to save on xcalls.
 */
static int sfmmu_xcall_save;

static void
sfmmu_tlb_range_demap(demap_range_t *dmrp)
{
	sfmmu_t *sfmmup = dmrp->dmr_sfmmup;
	int ctxnum;
	hatlock_t *hatlockp;
	cpuset_t cpuset;
	uint64_t ctx_pgcnt;
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

	/*
	 * In the case where context is invalid context, bail.
	 * We hold the hat lock while checking the ctx to prevent
	 * a race with sfmmu_replace_tsb() which temporarily sets
	 * the ctx to INVALID_CONTEXT to force processes to enter
	 * sfmmu_tsbmiss_exception().
	 */
	hatlockp = sfmmu_hat_enter(sfmmup);
	ctxnum = sfmmutoctxnum(sfmmup);
	sfmmu_hat_exit(hatlockp);
	if (ctxnum == INVALID_CONTEXT) {
		dmrp->dmr_bitvec = 0;
		return;
	}

	ASSERT((pgcnt<<MMU_PAGESHIFT) <= dmrp->dmr_endaddr - dmrp->dmr_addr);
	if (sfmmup->sfmmu_free == 0) {
		addr = dmrp->dmr_addr;
		bitvec = dmrp->dmr_bitvec;
		ctx_pgcnt = (uint64_t)((ctxnum << 16) | pgcnt);
		kpreempt_disable();
		cpuset = sfmmup->sfmmu_cpusran;
		CPUSET_AND(cpuset, cpu_ready_set);
		CPUSET_DEL(cpuset, CPU->cpu_id);
		SFMMU_XCALL_STATS(ctxnum);
		xt_some(cpuset, vtag_flush_pgcnt_tl1, (uint64_t)addr,
			ctx_pgcnt);
		for (; bitvec != 0; bitvec >>= 1) {
			if (bitvec & 1)
				vtag_flushpage(addr, ctxnum);
			addr += MMU_PAGESIZE;
		}
		kpreempt_enable();
		sfmmu_xcall_save += (pgunload-1);
	}
	dmrp->dmr_bitvec = 0;
}

/*
 * Flushes only TLB.
 */
static void
sfmmu_tlb_ctx_demap(sfmmu_t *sfmmup)
{
	int ctxnum;
	cpuset_t cpuset;

	ctxnum = (int)sfmmutoctxnum(sfmmup);
	if (ctxnum == INVALID_CONTEXT) {
		/*
		 * if ctx was stolen then simply return
		 * whoever stole ctx is responsible for flush.
		 */
		return;
	}
	ASSERT(ctxnum != KCONTEXT);
	/*
	 * There is no need to protect against ctx being stolen.  If the
	 * ctx is stolen we will simply get an extra flush.
	 */
	kpreempt_disable();

	cpuset = sfmmup->sfmmu_cpusran;
	CPUSET_DEL(cpuset, CPU->cpu_id);
	CPUSET_AND(cpuset, cpu_ready_set);
	SFMMU_XCALL_STATS(ctxnum);

	/*
	 * Flush TLB.
	 * RFE: it might be worth delaying the TLB flush as well. In that
	 * case each cpu would have to traverse the dirty list and flush
	 * each one of those ctx from the TLB.
	 */
	vtag_flushctx(ctxnum);
	xt_some(cpuset, vtag_flushctx_tl1, ctxnum, 0);

	kpreempt_enable();
	SFMMU_STAT(sf_tlbflush_ctx);
}

/*
 * Flushes all TLBs.
 */
static void
sfmmu_tlb_all_demap(void)
{
	cpuset_t cpuset;

	/*
	 * There is no need to protect against ctx being stolen.  If the
	 * ctx is stolen we will simply get an extra flush.
	 */
	kpreempt_disable();

	cpuset = cpu_ready_set;
	CPUSET_DEL(cpuset, CPU->cpu_id);
	/* LINTED: constant in conditional context */
	SFMMU_XCALL_STATS(INVALID_CONTEXT);

	vtag_flushall();
	xt_some(cpuset, vtag_flushall_tl1, 0, 0);
	xt_sync(cpuset);

	kpreempt_enable();
	SFMMU_STAT(sf_tlbflush_all);
}

/*
 * In cases where we need to synchronize with TLB/TSB miss trap
 * handlers, _and_ need to flush the TLB, it's a lot easier to
 * steal the context from the process and free it than to do a
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
 * we run out of contexts, and then flush the TLB one time.  This
 * is rather rare, so it's a lot less expensive than making 8000
 * x-calls to flush the TLB 8000 times.  Another is that we can do
 * all of this without pausing CPUs, due to some knowledge of how
 * resume() loads processes onto the processor; it sets the thread
 * into cpusran, and _then_ looks at cnum.  Because we do things in
 * the reverse order here, we guarantee exactly one of the following
 * statements is always true:
 *
 *   1) Nobody is in resume() so we have nothing to worry about anyway.
 *   2) The thread in resume() isn't in cpusran when we do the xcall,
 *      so we know when it does set itself it'll see cnum is
 *      INVALID_CONTEXT.
 *   3) The thread in resume() is in cpusran, and already might have
 *      looked at the old cnum.  That's OK, because we'll xcall it
 *      and, if necessary, flush the TLB along with the rest of the
 *      crowd.
 */
static void
sfmmu_tlb_swap_ctx(sfmmu_t *sfmmup, struct ctx *ctx)
{
	cpuset_t cpuset;
	int cnum;

	if (sfmmup->sfmmu_cnum == INVALID_CONTEXT)
		return;

	SFMMU_STAT(sf_ctx_swap);

	kpreempt_disable();

	ASSERT(rw_read_locked(&ctx->ctx_rwlock) == 0);
	ASSERT(ctx->ctx_sfmmu == sfmmup);

	cnum = ctxtoctxnum(ctx);
	ASSERT(sfmmup->sfmmu_cnum == cnum);
	ASSERT(cnum >= NUM_LOCKED_CTXS);

	sfmmup->sfmmu_cnum = INVALID_CONTEXT;
	membar_enter();	/* make sure visible on all CPUs */
	ctx->ctx_sfmmu = NULL;

	cpuset = sfmmup->sfmmu_cpusran;
	CPUSET_DEL(cpuset, CPU->cpu_id);
	CPUSET_AND(cpuset, cpu_ready_set);
	SFMMU_XCALL_STATS(cnum);

	/*
	 * Force anybody running this process on CPU
	 * to enter sfmmu_tsbmiss_exception() on the
	 * next TLB miss, synchronize behind us on
	 * the HAT lock, and grab a new context.  At
	 * that point the new page size will become
	 * active in the TLB for the new context.
	 * See sfmmu_get_ctx() for details.
	 */
	if (delay_tlb_flush) {
		xt_some(cpuset, sfmmu_raise_tsb_exception,
		    cnum, INVALID_CONTEXT);
		SFMMU_STAT(sf_tlbflush_deferred);
	} else {
		xt_some(cpuset, sfmmu_ctx_steal_tl1, cnum, INVALID_CONTEXT);
		vtag_flushctx(cnum);
		SFMMU_STAT(sf_tlbflush_ctx);
	}
	xt_sync(cpuset);

	/*
	 * If we just stole the ctx from the current
	 * process on local CPU we need to invalidate
	 * this CPU context as well.
	 */
	if (sfmmu_getctx_sec() == cnum) {
		sfmmu_setctx_sec(INVALID_CONTEXT);
		sfmmu_clear_utsbinfo();
	}

	kpreempt_enable();

	/*
	 * Now put old ctx on the dirty list since we may not
	 * have flushed the context out of the TLB.  We'll let
	 * the next guy who uses this ctx flush it instead.
	 */
	mutex_enter(&ctx_list_lock);
	CTX_SET_FLAGS(ctx, CTX_FREE_FLAG);
	ctx->ctx_free = ctxdirty;
	ctxdirty = ctx;
	mutex_exit(&ctx_list_lock);
}

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
	int	ctxnum = INVALID_CONTEXT;

	kpreempt_disable();
	cpuset = cpu_ready_set;
	CPUSET_DEL(cpuset, CPU->cpu_id);
	SFMMU_XCALL_STATS(ctxnum);	/* account to any ctx */
	xt_some(cpuset, vac_flushpage_tl1, pfnum, vcolor);
	xt_sync(cpuset);
	vac_flushpage(pfnum, vcolor);
	kpreempt_enable();
}

void
sfmmu_cache_flushcolor(int vcolor, pfn_t pfnum)
{
	cpuset_t cpuset;
	int	ctxnum = INVALID_CONTEXT;

	ASSERT(vcolor >= 0);

	kpreempt_disable();
	cpuset = cpu_ready_set;
	CPUSET_DEL(cpuset, CPU->cpu_id);
	SFMMU_XCALL_STATS(ctxnum);	/* account to any ctx */
	xt_some(cpuset, vac_flushcolor_tl1, vcolor, pfnum);
	xt_sync(cpuset);
	vac_flushcolor(vcolor, pfnum);
	kpreempt_enable();
}

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
	hatlock_t *hatlockp;
	struct tsb_info *tsbinfop = (struct tsb_info *)tsbinfo;
	sfmmu_t *sfmmup = tsbinfop->tsb_sfmmu;
	struct ctx *ctx;
	int cnum;
	extern uint32_t sendmondo_in_recover;

	if (flags != HAT_PRESUSPEND)
		return (0);

	hatlockp = sfmmu_hat_enter(sfmmup);

	tsbinfop->tsb_flags |= TSB_RELOC_FLAG;

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

	ctx = sfmmutoctx(sfmmup);
	rw_enter(&ctx->ctx_rwlock, RW_WRITER);
	cnum = sfmmutoctxnum(sfmmup);

	if (cnum != INVALID_CONTEXT) {
		/*
		 * Force all threads for this sfmmu to sfmmu_tsbmiss_exception
		 * on their next TLB miss.
		 */
		sfmmu_tlb_swap_ctx(sfmmup, ctx);
	}

	rw_exit(&ctx->ctx_rwlock);

	sfmmu_hat_exit(hatlockp);

	return (0);
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
		sfmmu_setup_tsbinfo(sfmmup);

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
		uintptr_t slab_mask = ~((uintptr_t)tsb_slab_mask) << PAGESHIFT;
		caddr_t slab_vaddr = (caddr_t)((uintptr_t)tsbva & slab_mask);
		page_t **ppl;
		int ret;

		ret = as_pagelock(&kas, &ppl, slab_vaddr, PAGESIZE, S_WRITE);
		ASSERT(ret == 0);
		hat_delete_callback(tsbva, (uint_t)tsb_size, (void *)tsbinfo,
		    0);
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
	uintptr_t slab_mask = ~((uintptr_t)tsb_slab_mask) << PAGESHIFT;
	int tsbbytes = TSB_BYTES(tsbcode);
	int lowmem = 0;
	struct kmem_cache *kmem_cachep = NULL;
	vmem_t *vmp = NULL;
	lgrp_id_t lgrpid = LGRP_NONE;
	pfn_t pfn;
	uint_t cbflags = HAC_SLEEP;
	page_t **pplist;
	int ret;

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
		vmp = kmem_tsb_default_arena[lgrpid];
		vaddr = (caddr_t)vmem_xalloc(vmp, tsbbytes, tsbbytes, 0, 0,
		    NULL, NULL, VM_NOSLEEP);
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
		    cbflags, (void *)tsbinfo, &pfn);

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

	if (kmem_cachep != sfmmu_tsb8k_cache) {
		as_pageunlock(&kas, pplist, slab_vaddr, PAGESIZE, S_WRITE);
	}

	sfmmu_inv_tsb(vaddr, tsbbytes);
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
	ASSERT(hat->sfmmu_xhat_provider == NULL);
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
		hmeblkp = sfmmu_hmetohblk(sfhmep);
		if (hmeblkp->hblk_xhat_bit)
			continue;
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
			cpu_kstat->sf_itlb_misses = tsbm->itlb_misses;
			cpu_kstat->sf_dtlb_misses = tsbm->dtlb_misses;
			cpu_kstat->sf_utsb_misses = tsbm->utsb_misses -
				tsbm->uprot_traps;
			cpu_kstat->sf_ktsb_misses = tsbm->ktsb_misses +
				kpmtsbm->kpm_tsb_misses - tsbm->kprot_traps;

			if (tsbm->itlb_misses > 0 && tsbm->dtlb_misses > 0) {
				cpu_kstat->sf_tsb_hits =
				(tsbm->itlb_misses + tsbm->dtlb_misses) -
				(tsbm->utsb_misses + tsbm->ktsb_misses +
				kpmtsbm->kpm_tsb_misses);
			} else {
				cpu_kstat->sf_tsb_hits = 0;
			}
			cpu_kstat->sf_umod_faults = tsbm->uprot_traps;
			cpu_kstat->sf_kmod_faults = tsbm->kprot_traps;
		}
	} else {
		/* KSTAT_WRITE is used to clear stats */
		for (i = 0; i < NCPU; tsbm++, kpmtsbm++, i++) {
			tsbm->itlb_misses = 0;
			tsbm->dtlb_misses = 0;
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
	uint_t i, j, k;
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
				panic("chk_tte: bad pfn, 0x%x, 0x%x",
					i, j);
			}

			if (i != k) {
				/* remap error? */
				panic("chk_tte: bad pfn2, 0x%x, 0x%x",
					i, k);
			}
		} else {
			if (TTE_IS_VALID(new)) {
				panic("chk_tte: invalid cur? ");
			}

			i = TTE_TO_TTEPFN(orig_old);
			k = TTE_TO_TTEPFN(new);
			if (i != k) {
				panic("chk_tte: bad pfn3, 0x%x, 0x%x",
					i, k);
			}
		}
	} else {
		if (TTE_IS_VALID(cur)) {
			j = TTE_TO_TTEPFN(cur);
			if (TTE_IS_VALID(new)) {
				k = TTE_TO_TTEPFN(new);
				if (j != k) {
					panic("chk_tte: bad pfn4, 0x%x, 0x%x",
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
 * Kernel Physical Mapping (kpm) facility
 */

/* -- hat_kpm interface section -- */

/*
 * Mapin a locked page and return the vaddr.
 * When a kpme is provided by the caller it is added to
 * the page p_kpmelist. The page to be mapped in must
 * be at least read locked (p_selock).
 */
caddr_t
hat_kpm_mapin(struct page *pp, struct kpme *kpme)
{
	kmutex_t	*pml;
	caddr_t		vaddr;

	if (kpm_enable == 0) {
		cmn_err(CE_WARN, "hat_kpm_mapin: kpm_enable not set");
		return ((caddr_t)NULL);
	}

	if (pp == NULL || PAGE_LOCKED(pp) == 0) {
		cmn_err(CE_WARN, "hat_kpm_mapin: pp zero or not locked");
		return ((caddr_t)NULL);
	}

	pml = sfmmu_mlist_enter(pp);
	ASSERT(pp->p_kpmref >= 0);

	vaddr = (pp->p_kpmref == 0) ?
		sfmmu_kpm_mapin(pp) : hat_kpm_page2va(pp, 1);

	if (kpme != NULL) {
		/*
		 * Tolerate multiple mapins for the same kpme to avoid
		 * the need for an extra serialization.
		 */
		if ((sfmmu_kpme_lookup(kpme, pp)) == 0)
			sfmmu_kpme_add(kpme, pp);

		ASSERT(pp->p_kpmref > 0);

	} else {
		pp->p_kpmref++;
	}

	sfmmu_mlist_exit(pml);
	return (vaddr);
}

/*
 * Mapout a locked page.
 * When a kpme is provided by the caller it is removed from
 * the page p_kpmelist. The page to be mapped out must be at
 * least read locked (p_selock).
 * Note: The seg_kpm layer provides a mapout interface for the
 * case that a kpme is used and the underlying page is unlocked.
 * This can be used instead of calling this function directly.
 */
void
hat_kpm_mapout(struct page *pp, struct kpme *kpme, caddr_t vaddr)
{
	kmutex_t	*pml;

	if (kpm_enable == 0) {
		cmn_err(CE_WARN, "hat_kpm_mapout: kpm_enable not set");
		return;
	}

	if (IS_KPM_ADDR(vaddr) == 0) {
		cmn_err(CE_WARN, "hat_kpm_mapout: no kpm address");
		return;
	}

	if (pp == NULL || PAGE_LOCKED(pp) == 0) {
		cmn_err(CE_WARN, "hat_kpm_mapout: page zero or not locked");
		return;
	}

	if (kpme != NULL) {
		ASSERT(pp == kpme->kpe_page);
		pp = kpme->kpe_page;
		pml = sfmmu_mlist_enter(pp);

		if (sfmmu_kpme_lookup(kpme, pp) == 0)
			panic("hat_kpm_mapout: kpme not found pp=%p",
				(void *)pp);

		ASSERT(pp->p_kpmref > 0);
		sfmmu_kpme_sub(kpme, pp);

	} else {
		pml = sfmmu_mlist_enter(pp);
		pp->p_kpmref--;
	}

	ASSERT(pp->p_kpmref >= 0);
	if (pp->p_kpmref == 0)
		sfmmu_kpm_mapout(pp, vaddr);

	sfmmu_mlist_exit(pml);
}

/*
 * Return the kpm virtual address for the page at pp.
 * If checkswap is non zero and the page is backed by a
 * swap vnode the physical address is used rather than
 * p_offset to determine the kpm region.
 * Note: The function has to be used w/ extreme care. The
 * stability of the page identity is in the responsibility
 * of the caller.
 */
caddr_t
hat_kpm_page2va(struct page *pp, int checkswap)
{
	int		vcolor, vcolor_pa;
	uintptr_t	paddr, vaddr;

	ASSERT(kpm_enable);

	paddr = ptob(pp->p_pagenum);
	vcolor_pa = addr_to_vcolor(paddr);

	if (checkswap && pp->p_vnode && IS_SWAPFSVP(pp->p_vnode))
		vcolor = (PP_ISNC(pp)) ? vcolor_pa : PP_GET_VCOLOR(pp);
	else
		vcolor = addr_to_vcolor(pp->p_offset);

	vaddr = (uintptr_t)kpm_vbase + paddr;

	if (vcolor_pa != vcolor) {
		vaddr += ((uintptr_t)(vcolor - vcolor_pa) << MMU_PAGESHIFT);
		vaddr += (vcolor_pa > vcolor) ?
			((uintptr_t)vcolor_pa << kpm_size_shift) :
			((uintptr_t)(vcolor - vcolor_pa) << kpm_size_shift);
	}

	return ((caddr_t)vaddr);
}

/*
 * Return the page for the kpm virtual address vaddr.
 * Caller is responsible for the kpm mapping and lock
 * state of the page.
 */
page_t *
hat_kpm_vaddr2page(caddr_t vaddr)
{
	uintptr_t	paddr;
	pfn_t		pfn;

	ASSERT(IS_KPM_ADDR(vaddr));

	SFMMU_KPM_VTOP(vaddr, paddr);
	pfn = (pfn_t)btop(paddr);

	return (page_numtopp_nolock(pfn));
}

/* page to kpm_page */
#define	PP2KPMPG(pp, kp) {						\
	struct memseg	*mseg;						\
	pgcnt_t		inx;						\
	pfn_t		pfn;						\
									\
	pfn = pp->p_pagenum;						\
	mseg = page_numtomemseg_nolock(pfn);				\
	ASSERT(mseg);							\
	inx = ptokpmp(kpmptop(ptokpmp(pfn)) - mseg->kpm_pbase);		\
	ASSERT(inx < mseg->kpm_nkpmpgs);				\
	kp = &mseg->kpm_pages[inx];					\
}

/* page to kpm_spage */
#define	PP2KPMSPG(pp, ksp) {						\
	struct memseg	*mseg;						\
	pgcnt_t		inx;						\
	pfn_t		pfn;						\
									\
	pfn = pp->p_pagenum;						\
	mseg = page_numtomemseg_nolock(pfn);				\
	ASSERT(mseg);							\
	inx = pfn - mseg->kpm_pbase;					\
	ksp = &mseg->kpm_spages[inx];					\
}

/*
 * hat_kpm_fault is called from segkpm_fault when a kpm tsbmiss occurred
 * which could not be resolved by the trap level tsbmiss handler for the
 * following reasons:
 * . The vaddr is in VAC alias range (always PAGESIZE mapping size).
 * . The kpm (s)page range of vaddr is in a VAC alias prevention state.
 * . tsbmiss handling at trap level is not desired (DEBUG kernel only,
 *   kpm_tsbmtl == 0).
 */
int
hat_kpm_fault(struct hat *hat, caddr_t vaddr)
{
	int		error;
	uintptr_t	paddr;
	pfn_t		pfn;
	struct memseg	*mseg;
	page_t	*pp;

	if (kpm_enable == 0) {
		cmn_err(CE_WARN, "hat_kpm_fault: kpm_enable not set");
		return (ENOTSUP);
	}

	ASSERT(hat == ksfmmup);
	ASSERT(IS_KPM_ADDR(vaddr));

	SFMMU_KPM_VTOP(vaddr, paddr);
	pfn = (pfn_t)btop(paddr);
	mseg = page_numtomemseg_nolock(pfn);
	if (mseg == NULL)
		return (EFAULT);

	pp = &mseg->pages[(pgcnt_t)(pfn - mseg->pages_base)];
	ASSERT((pfn_t)pp->p_pagenum == pfn);

	if (!PAGE_LOCKED(pp))
		return (EFAULT);

	if (kpm_smallpages == 0)
		error = sfmmu_kpm_fault(vaddr, mseg, pp);
	else
		error = sfmmu_kpm_fault_small(vaddr, mseg, pp);

	return (error);
}

extern  krwlock_t memsegslock;

/*
 * memseg_hash[] was cleared, need to clear memseg_phash[] too.
 */
void
hat_kpm_mseghash_clear(int nentries)
{
	pgcnt_t i;

	if (kpm_enable == 0)
		return;

	for (i = 0; i < nentries; i++)
		memseg_phash[i] = MSEG_NULLPTR_PA;
}

/*
 * Update memseg_phash[inx] when memseg_hash[inx] was changed.
 */
void
hat_kpm_mseghash_update(pgcnt_t inx, struct memseg *msp)
{
	if (kpm_enable == 0)
		return;

	memseg_phash[inx] = (msp) ? va_to_pa(msp) : MSEG_NULLPTR_PA;
}

/*
 * Update kpm memseg members from basic memseg info.
 */
void
hat_kpm_addmem_mseg_update(struct memseg *msp, pgcnt_t nkpmpgs,
	offset_t kpm_pages_off)
{
	if (kpm_enable == 0)
		return;

	msp->kpm_pages = (kpm_page_t *)((caddr_t)msp->pages + kpm_pages_off);
	msp->kpm_nkpmpgs = nkpmpgs;
	msp->kpm_pbase = kpmptop(ptokpmp(msp->pages_base));
	msp->pagespa = va_to_pa(msp->pages);
	msp->epagespa = va_to_pa(msp->epages);
	msp->kpm_pagespa = va_to_pa(msp->kpm_pages);
}

/*
 * Setup nextpa when a memseg is inserted.
 * Assumes that the memsegslock is already held.
 */
void
hat_kpm_addmem_mseg_insert(struct memseg *msp)
{
	if (kpm_enable == 0)
		return;

	ASSERT(RW_LOCK_HELD(&memsegslock));
	msp->nextpa = (memsegs) ? va_to_pa(memsegs) : MSEG_NULLPTR_PA;
}

/*
 * Setup memsegspa when a memseg is (head) inserted.
 * Called before memsegs is updated to complete a
 * memseg insert operation.
 * Assumes that the memsegslock is already held.
 */
void
hat_kpm_addmem_memsegs_update(struct memseg *msp)
{
	if (kpm_enable == 0)
		return;

	ASSERT(RW_LOCK_HELD(&memsegslock));
	ASSERT(memsegs);
	memsegspa = va_to_pa(msp);
}

/*
 * Return end of metadata for an already setup memseg.
 *
 * Note: kpm_pages and kpm_spages are aliases and the underlying
 * member of struct memseg is a union, therefore they always have
 * the same address within a memseg. They must be differentiated
 * when pointer arithmetic is used with them.
 */
caddr_t
hat_kpm_mseg_reuse(struct memseg *msp)
{
	caddr_t end;

	if (kpm_smallpages == 0)
		end = (caddr_t)(msp->kpm_pages + msp->kpm_nkpmpgs);
	else
		end = (caddr_t)(msp->kpm_spages + msp->kpm_nkpmpgs);

	return (end);
}

/*
 * Update memsegspa (when first memseg in list
 * is deleted) or nextpa  when a memseg deleted.
 * Assumes that the memsegslock is already held.
 */
void
hat_kpm_delmem_mseg_update(struct memseg *msp, struct memseg **mspp)
{
	struct memseg *lmsp;

	if (kpm_enable == 0)
		return;

	ASSERT(RW_LOCK_HELD(&memsegslock));

	if (mspp == &memsegs) {
		memsegspa = (msp->next) ?
				va_to_pa(msp->next) : MSEG_NULLPTR_PA;
	} else {
		lmsp = (struct memseg *)
			((uint64_t)mspp - offsetof(struct memseg, next));
		lmsp->nextpa = (msp->next) ?
				va_to_pa(msp->next) : MSEG_NULLPTR_PA;
	}
}

/*
 * Update kpm members for all memseg's involved in a split operation
 * and do the atomic update of the physical memseg chain.
 *
 * Note: kpm_pages and kpm_spages are aliases and the underlying member
 * of struct memseg is a union, therefore they always have the same
 * address within a memseg. With that the direct assignments and
 * va_to_pa conversions below don't have to be distinguished wrt. to
 * kpm_smallpages. They must be differentiated when pointer arithmetic
 * is used with them.
 *
 * Assumes that the memsegslock is already held.
 */
void
hat_kpm_split_mseg_update(struct memseg *msp, struct memseg **mspp,
	struct memseg *lo, struct memseg *mid, struct memseg *hi)
{
	pgcnt_t start, end, kbase, kstart, num;
	struct memseg *lmsp;

	if (kpm_enable == 0)
		return;

	ASSERT(RW_LOCK_HELD(&memsegslock));
	ASSERT(msp && mid && msp->kpm_pages);

	kbase = ptokpmp(msp->kpm_pbase);

	if (lo) {
		num = lo->pages_end - lo->pages_base;
		start = kpmptop(ptokpmp(lo->pages_base));
		/* align end to kpm page size granularity */
		end = kpmptop(ptokpmp(start + num - 1)) + kpmpnpgs;
		lo->kpm_pbase = start;
		lo->kpm_nkpmpgs = ptokpmp(end - start);
		lo->kpm_pages = msp->kpm_pages;
		lo->kpm_pagespa = va_to_pa(lo->kpm_pages);
		lo->pagespa = va_to_pa(lo->pages);
		lo->epagespa = va_to_pa(lo->epages);
		lo->nextpa = va_to_pa(lo->next);
	}

	/* mid */
	num = mid->pages_end - mid->pages_base;
	kstart = ptokpmp(mid->pages_base);
	start = kpmptop(kstart);
	/* align end to kpm page size granularity */
	end = kpmptop(ptokpmp(start + num - 1)) + kpmpnpgs;
	mid->kpm_pbase = start;
	mid->kpm_nkpmpgs = ptokpmp(end - start);
	if (kpm_smallpages == 0) {
		mid->kpm_pages = msp->kpm_pages + (kstart - kbase);
	} else {
		mid->kpm_spages = msp->kpm_spages + (kstart - kbase);
	}
	mid->kpm_pagespa = va_to_pa(mid->kpm_pages);
	mid->pagespa = va_to_pa(mid->pages);
	mid->epagespa = va_to_pa(mid->epages);
	mid->nextpa = (mid->next) ?  va_to_pa(mid->next) : MSEG_NULLPTR_PA;

	if (hi) {
		num = hi->pages_end - hi->pages_base;
		kstart = ptokpmp(hi->pages_base);
		start = kpmptop(kstart);
		/* align end to kpm page size granularity */
		end = kpmptop(ptokpmp(start + num - 1)) + kpmpnpgs;
		hi->kpm_pbase = start;
		hi->kpm_nkpmpgs = ptokpmp(end - start);
		if (kpm_smallpages == 0) {
			hi->kpm_pages = msp->kpm_pages + (kstart - kbase);
		} else {
			hi->kpm_spages = msp->kpm_spages + (kstart - kbase);
		}
		hi->kpm_pagespa = va_to_pa(hi->kpm_pages);
		hi->pagespa = va_to_pa(hi->pages);
		hi->epagespa = va_to_pa(hi->epages);
		hi->nextpa = (hi->next) ? va_to_pa(hi->next) : MSEG_NULLPTR_PA;
	}

	/*
	 * Atomic update of the physical memseg chain
	 */
	if (mspp == &memsegs) {
		memsegspa = (lo) ? va_to_pa(lo) : va_to_pa(mid);
	} else {
		lmsp = (struct memseg *)
			((uint64_t)mspp - offsetof(struct memseg, next));
		lmsp->nextpa = (lo) ? va_to_pa(lo) : va_to_pa(mid);
	}
}

/*
 * Walk the memsegs chain, applying func to each memseg span and vcolor.
 */
void
hat_kpm_walk(void (*func)(void *, void *, size_t), void *arg)
{
	pfn_t	pbase, pend;
	int	vcolor;
	void	*base;
	size_t	size;
	struct memseg *msp;
	extern uint_t vac_colors;

	for (msp = memsegs; msp; msp = msp->next) {
		pbase = msp->pages_base;
		pend = msp->pages_end;
		for (vcolor = 0; vcolor < vac_colors; vcolor++) {
			base = ptob(pbase) + kpm_vbase + kpm_size * vcolor;
			size = ptob(pend - pbase);
			func(arg, base, size);
		}
	}
}


/* -- sfmmu_kpm internal section -- */

/*
 * Return the page frame number if a valid segkpm mapping exists
 * for vaddr, otherwise return PFN_INVALID. No locks are grabbed.
 * Should only be used by other sfmmu routines.
 */
pfn_t
sfmmu_kpm_vatopfn(caddr_t vaddr)
{
	uintptr_t	paddr;
	pfn_t		pfn;
	page_t	*pp;

	ASSERT(kpm_enable && IS_KPM_ADDR(vaddr));

	SFMMU_KPM_VTOP(vaddr, paddr);
	pfn = (pfn_t)btop(paddr);
	pp = page_numtopp_nolock(pfn);
	if (pp && pp->p_kpmref)
		return (pfn);
	else
		return ((pfn_t)PFN_INVALID);
}

/*
 * Lookup a kpme in the p_kpmelist.
 */
static int
sfmmu_kpme_lookup(struct kpme *kpme, page_t *pp)
{
	struct kpme	*p;

	for (p = pp->p_kpmelist; p; p = p->kpe_next) {
		if (p == kpme)
			return (1);
	}
	return (0);
}

/*
 * Insert a kpme into the p_kpmelist and increment
 * the per page kpm reference count.
 */
static void
sfmmu_kpme_add(struct kpme *kpme, page_t *pp)
{
	ASSERT(pp->p_kpmref >= 0);

	/* head insert */
	kpme->kpe_prev = NULL;
	kpme->kpe_next = pp->p_kpmelist;

	if (pp->p_kpmelist)
		pp->p_kpmelist->kpe_prev = kpme;

	pp->p_kpmelist = kpme;
	kpme->kpe_page = pp;
	pp->p_kpmref++;
}

/*
 * Remove a kpme from the p_kpmelist and decrement
 * the per page kpm reference count.
 */
static void
sfmmu_kpme_sub(struct kpme *kpme, page_t *pp)
{
	ASSERT(pp->p_kpmref > 0);

	if (kpme->kpe_prev) {
		ASSERT(pp->p_kpmelist != kpme);
		ASSERT(kpme->kpe_prev->kpe_page == pp);
		kpme->kpe_prev->kpe_next = kpme->kpe_next;
	} else {
		ASSERT(pp->p_kpmelist == kpme);
		pp->p_kpmelist = kpme->kpe_next;
	}

	if (kpme->kpe_next) {
		ASSERT(kpme->kpe_next->kpe_page == pp);
		kpme->kpe_next->kpe_prev = kpme->kpe_prev;
	}

	kpme->kpe_next = kpme->kpe_prev = NULL;
	kpme->kpe_page = NULL;
	pp->p_kpmref--;
}

/*
 * Mapin a single page, it is called every time a page changes it's state
 * from kpm-unmapped to kpm-mapped. It may not be called, when only a new
 * kpm instance does a mapin and wants to share the mapping.
 * Assumes that the mlist mutex is already grabbed.
 */
static caddr_t
sfmmu_kpm_mapin(page_t *pp)
{
	kpm_page_t	*kp;
	kpm_hlk_t	*kpmp;
	caddr_t		vaddr;
	int		kpm_vac_range;
	pfn_t		pfn;
	tte_t		tte;
	kmutex_t	*pmtx;
	int		uncached;
	kpm_spage_t	*ksp;
	kpm_shlk_t	*kpmsp;
	int		oldval;

	ASSERT(sfmmu_mlist_held(pp));
	ASSERT(pp->p_kpmref == 0);

	vaddr = sfmmu_kpm_getvaddr(pp, &kpm_vac_range);

	ASSERT(IS_KPM_ADDR(vaddr));
	uncached = PP_ISNC(pp);
	pfn = pp->p_pagenum;

	if (kpm_smallpages)
		goto smallpages_mapin;

	PP2KPMPG(pp, kp);

	kpmp = KPMP_HASH(kp);
	mutex_enter(&kpmp->khl_mutex);

	ASSERT(PP_ISKPMC(pp) == 0);
	ASSERT(PP_ISKPMS(pp) == 0);

	if (uncached) {
		/* ASSERT(pp->p_share); XXX use hat_page_getshare */
		if (kpm_vac_range == 0) {
			if (kp->kp_refcnts == 0) {
				/*
				 * Must remove large page mapping if it exists.
				 * Pages in uncached state can only be mapped
				 * small (PAGESIZE) within the regular kpm
				 * range.
				 */
				if (kp->kp_refcntc == -1) {
					/* remove go indication */
					sfmmu_kpm_tsbmtl(&kp->kp_refcntc,
						&kpmp->khl_lock, KPMTSBM_STOP);
				}
				if (kp->kp_refcnt > 0 && kp->kp_refcntc == 0)
					sfmmu_kpm_demap_large(vaddr);
			}
			ASSERT(kp->kp_refcntc >= 0);
			kp->kp_refcntc++;
		}
		pmtx = sfmmu_page_enter(pp);
		PP_SETKPMC(pp);
		sfmmu_page_exit(pmtx);
	}

	if ((kp->kp_refcntc > 0 || kp->kp_refcnts > 0) && kpm_vac_range == 0) {
		/*
		 * Have to do a small (PAGESIZE) mapin within this kpm_page
		 * range since it is marked to be in VAC conflict mode or
		 * when there are still other small mappings around.
		 */

		/* tte assembly */
		if (uncached == 0)
			KPM_TTE_VCACHED(tte.ll, pfn, TTE8K);
		else
			KPM_TTE_VUNCACHED(tte.ll, pfn, TTE8K);

		/* tsb dropin */
		sfmmu_kpm_load_tsb(vaddr, &tte, MMU_PAGESHIFT);

		pmtx = sfmmu_page_enter(pp);
		PP_SETKPMS(pp);
		sfmmu_page_exit(pmtx);

		kp->kp_refcnts++;
		ASSERT(kp->kp_refcnts > 0);
		goto exit;
	}

	if (kpm_vac_range == 0) {
		/*
		 * Fast path / regular case, no VAC conflict handling
		 * in progress within this kpm_page range.
		 */
		if (kp->kp_refcnt == 0) {

			/* tte assembly */
			KPM_TTE_VCACHED(tte.ll, pfn, TTE4M);

			/* tsb dropin */
			sfmmu_kpm_load_tsb(vaddr, &tte, MMU_PAGESHIFT4M);

			/* Set go flag for TL tsbmiss handler */
			if (kp->kp_refcntc == 0)
				sfmmu_kpm_tsbmtl(&kp->kp_refcntc,
						&kpmp->khl_lock, KPMTSBM_START);

			ASSERT(kp->kp_refcntc == -1);
		}
		kp->kp_refcnt++;
		ASSERT(kp->kp_refcnt);

	} else {
		/*
		 * The page is not setup according to the common VAC
		 * prevention rules for the regular and kpm mapping layer
		 * E.g. the page layer was not able to deliver a right
		 * vcolor'ed page for a given vaddr corresponding to
		 * the wanted p_offset. It has to be mapped in small in
		 * within the corresponding kpm vac range in order to
		 * prevent VAC alias conflicts.
		 */

		/* tte assembly */
		if (uncached == 0) {
			KPM_TTE_VCACHED(tte.ll, pfn, TTE8K);
		} else {
			KPM_TTE_VUNCACHED(tte.ll, pfn, TTE8K);
		}

		/* tsb dropin */
		sfmmu_kpm_load_tsb(vaddr, &tte, MMU_PAGESHIFT);

		kp->kp_refcnta++;
		if (kp->kp_refcntc == -1) {
			ASSERT(kp->kp_refcnt > 0);

			/* remove go indication */
			sfmmu_kpm_tsbmtl(&kp->kp_refcntc, &kpmp->khl_lock,
					KPMTSBM_STOP);
		}
		ASSERT(kp->kp_refcntc >= 0);
	}
exit:
	mutex_exit(&kpmp->khl_mutex);
	return (vaddr);

smallpages_mapin:
	if (uncached == 0) {
		/* tte assembly */
		KPM_TTE_VCACHED(tte.ll, pfn, TTE8K);
	} else {
		/* ASSERT(pp->p_share); XXX use hat_page_getshare */
		pmtx = sfmmu_page_enter(pp);
		PP_SETKPMC(pp);
		sfmmu_page_exit(pmtx);
		/* tte assembly */
		KPM_TTE_VUNCACHED(tte.ll, pfn, TTE8K);
	}

	/* tsb dropin */
	sfmmu_kpm_load_tsb(vaddr, &tte, MMU_PAGESHIFT);

	PP2KPMSPG(pp, ksp);
	kpmsp = KPMP_SHASH(ksp);

	oldval = sfmmu_kpm_stsbmtl(&ksp->kp_mapped, &kpmsp->kshl_lock,
				(uncached) ? KPM_MAPPEDSC : KPM_MAPPEDS);

	if (oldval != 0)
		panic("sfmmu_kpm_mapin: stale smallpages mapping");

	return (vaddr);
}

/*
 * Mapout a single page, it is called every time a page changes it's state
 * from kpm-mapped to kpm-unmapped. It may not be called, when only a kpm
 * instance calls mapout and there are still other instances mapping the
 * page. Assumes that the mlist mutex is already grabbed.
 *
 * Note: In normal mode (no VAC conflict prevention pending) TLB's are
 * not flushed. This is the core segkpm behavior to avoid xcalls. It is
 * no problem because a translation from a segkpm virtual address to a
 * physical address is always the same. The only downside is a slighty
 * increased window of vulnerability for misbehaving _kernel_ modules.
 */
static void
sfmmu_kpm_mapout(page_t *pp, caddr_t vaddr)
{
	kpm_page_t	*kp;
	kpm_hlk_t	*kpmp;
	int		alias_range;
	kmutex_t	*pmtx;
	kpm_spage_t	*ksp;
	kpm_shlk_t	*kpmsp;
	int		oldval;

	ASSERT(sfmmu_mlist_held(pp));
	ASSERT(pp->p_kpmref == 0);

	alias_range = IS_KPM_ALIAS_RANGE(vaddr);

	if (kpm_smallpages)
		goto smallpages_mapout;

	PP2KPMPG(pp, kp);
	kpmp = KPMP_HASH(kp);
	mutex_enter(&kpmp->khl_mutex);

	if (alias_range) {
		ASSERT(PP_ISKPMS(pp) == 0);
		if (kp->kp_refcnta <= 0) {
			panic("sfmmu_kpm_mapout: bad refcnta kp=%p",
				(void *)kp);
		}

		if (PP_ISTNC(pp))  {
			if (PP_ISKPMC(pp) == 0) {
				/*
				 * Uncached kpm mappings must always have
				 * forced "small page" mode.
				 */
				panic("sfmmu_kpm_mapout: uncached page not "
					"kpm marked");
			}
			sfmmu_kpm_demap_small(vaddr);

			pmtx = sfmmu_page_enter(pp);
			PP_CLRKPMC(pp);
			sfmmu_page_exit(pmtx);

			/*
			 * Check if we can resume cached mode. This might
			 * be the case if the kpm mapping was the only
			 * mapping in conflict with other non rule
			 * compliant mappings. The page is no more marked
			 * as kpm mapped, so the conv_tnc path will not
			 * change kpm state.
			 */
			conv_tnc(pp, TTE8K);

		} else if (PP_ISKPMC(pp) == 0) {
			/* remove TSB entry only */
			sfmmu_kpm_unload_tsb(vaddr, MMU_PAGESHIFT);

		} else {
			/* already demapped */
			pmtx = sfmmu_page_enter(pp);
			PP_CLRKPMC(pp);
			sfmmu_page_exit(pmtx);
		}
		kp->kp_refcnta--;
		goto exit;
	}

	if (kp->kp_refcntc <= 0 && kp->kp_refcnts == 0) {
		/*
		 * Fast path / regular case.
		 */
		ASSERT(kp->kp_refcntc >= -1);
		ASSERT(!(pp->p_nrm & (P_KPMC | P_KPMS | P_TNC | P_PNC)));

		if (kp->kp_refcnt <= 0)
			panic("sfmmu_kpm_mapout: bad refcnt kp=%p", (void *)kp);

		if (--kp->kp_refcnt == 0) {
			/* remove go indication */
			if (kp->kp_refcntc == -1) {
				sfmmu_kpm_tsbmtl(&kp->kp_refcntc,
					&kpmp->khl_lock, KPMTSBM_STOP);
			}
			ASSERT(kp->kp_refcntc == 0);

			/* remove TSB entry */
			sfmmu_kpm_unload_tsb(vaddr, MMU_PAGESHIFT4M);
#ifdef	DEBUG
			if (kpm_tlb_flush)
				sfmmu_kpm_demap_tlbs(vaddr, KCONTEXT);
#endif
		}

	} else {
		/*
		 * The VAC alias path.
		 * We come here if the kpm vaddr is not in any alias_range
		 * and we are unmapping a page within the regular kpm_page
		 * range. The kpm_page either holds conflict pages and/or
		 * is in "small page" mode. If the page is not marked
		 * P_KPMS it couldn't have a valid PAGESIZE sized TSB
		 * entry. Dcache flushing is done lazy and follows the
		 * rules of the regular virtual page coloring scheme.
		 *
		 * Per page states and required actions:
		 *   P_KPMC: remove a kpm mapping that is conflicting.
		 *   P_KPMS: remove a small kpm mapping within a kpm_page.
		 *   P_TNC:  check if we can re-cache the page.
		 *   P_PNC:  we cannot re-cache, sorry.
		 * Per kpm_page:
		 *   kp_refcntc > 0: page is part of a kpm_page with conflicts.
		 *   kp_refcnts > 0: rm a small mapped page within a kpm_page.
		 */

		if (PP_ISKPMS(pp)) {
			if (kp->kp_refcnts < 1) {
				panic("sfmmu_kpm_mapout: bad refcnts kp=%p",
					(void *)kp);
			}
			sfmmu_kpm_demap_small(vaddr);

			/*
			 * Check if we can resume cached mode. This might
			 * be the case if the kpm mapping was the only
			 * mapping in conflict with other non rule
			 * compliant mappings. The page is no more marked
			 * as kpm mapped, so the conv_tnc path will not
			 * change kpm state.
			 */
			if (PP_ISTNC(pp))  {
				if (!PP_ISKPMC(pp)) {
					/*
					 * Uncached kpm mappings must always
					 * have forced "small page" mode.
					 */
					panic("sfmmu_kpm_mapout: uncached "
						"page not kpm marked");
				}
				conv_tnc(pp, TTE8K);
			}
			kp->kp_refcnts--;
			kp->kp_refcnt++;
			pmtx = sfmmu_page_enter(pp);
			PP_CLRKPMS(pp);
			sfmmu_page_exit(pmtx);
		}

		if (PP_ISKPMC(pp)) {
			if (kp->kp_refcntc < 1) {
				panic("sfmmu_kpm_mapout: bad refcntc kp=%p",
					(void *)kp);
			}
			pmtx = sfmmu_page_enter(pp);
			PP_CLRKPMC(pp);
			sfmmu_page_exit(pmtx);
			kp->kp_refcntc--;
		}

		if (kp->kp_refcnt-- < 1)
			panic("sfmmu_kpm_mapout: bad refcnt kp=%p", (void *)kp);
	}
exit:
	mutex_exit(&kpmp->khl_mutex);
	return;

smallpages_mapout:
	PP2KPMSPG(pp, ksp);
	kpmsp = KPMP_SHASH(ksp);

	if (PP_ISKPMC(pp) == 0) {
		oldval = sfmmu_kpm_stsbmtl(&ksp->kp_mapped,
					&kpmsp->kshl_lock, 0);

		if (oldval != KPM_MAPPEDS) {
			/*
			 * When we're called after sfmmu_kpm_hme_unload,
			 * KPM_MAPPEDSC is valid too.
			 */
			if (oldval != KPM_MAPPEDSC)
				panic("sfmmu_kpm_mapout: incorrect mapping");
		}

		/* remove TSB entry */
		sfmmu_kpm_unload_tsb(vaddr, MMU_PAGESHIFT);
#ifdef	DEBUG
		if (kpm_tlb_flush)
			sfmmu_kpm_demap_tlbs(vaddr, KCONTEXT);
#endif

	} else if (PP_ISTNC(pp)) {
		oldval = sfmmu_kpm_stsbmtl(&ksp->kp_mapped,
					&kpmsp->kshl_lock, 0);

		if (oldval != KPM_MAPPEDSC || PP_ISKPMC(pp) == 0)
			panic("sfmmu_kpm_mapout: inconsistent TNC mapping");

		sfmmu_kpm_demap_small(vaddr);

		pmtx = sfmmu_page_enter(pp);
		PP_CLRKPMC(pp);
		sfmmu_page_exit(pmtx);

		/*
		 * Check if we can resume cached mode. This might be
		 * the case if the kpm mapping was the only mapping
		 * in conflict with other non rule compliant mappings.
		 * The page is no more marked as kpm mapped, so the
		 * conv_tnc path will not change the kpm state.
		 */
		conv_tnc(pp, TTE8K);

	} else {
		oldval = sfmmu_kpm_stsbmtl(&ksp->kp_mapped,
					&kpmsp->kshl_lock, 0);

		if (oldval != KPM_MAPPEDSC)
			panic("sfmmu_kpm_mapout: inconsistent mapping");

		pmtx = sfmmu_page_enter(pp);
		PP_CLRKPMC(pp);
		sfmmu_page_exit(pmtx);
	}
}

#define	abs(x)  ((x) < 0 ? -(x) : (x))

/*
 * Determine appropriate kpm mapping address and handle any kpm/hme
 * conflicts. Page mapping list and its vcolor parts must be protected.
 */
static caddr_t
sfmmu_kpm_getvaddr(page_t *pp, int *kpm_vac_rangep)
{
	int		vcolor, vcolor_pa;
	caddr_t		vaddr;
	uintptr_t	paddr;


	ASSERT(sfmmu_mlist_held(pp));

	paddr = ptob(pp->p_pagenum);
	vcolor_pa = addr_to_vcolor(paddr);

	if (pp->p_vnode && IS_SWAPFSVP(pp->p_vnode)) {
		vcolor = (PP_NEWPAGE(pp) || PP_ISNC(pp)) ?
		    vcolor_pa : PP_GET_VCOLOR(pp);
	} else {
		vcolor = addr_to_vcolor(pp->p_offset);
	}

	vaddr = kpm_vbase + paddr;
	*kpm_vac_rangep = 0;

	if (vcolor_pa != vcolor) {
		*kpm_vac_rangep = abs(vcolor - vcolor_pa);
		vaddr += ((uintptr_t)(vcolor - vcolor_pa) << MMU_PAGESHIFT);
		vaddr += (vcolor_pa > vcolor) ?
			((uintptr_t)vcolor_pa << kpm_size_shift) :
			((uintptr_t)(vcolor - vcolor_pa) << kpm_size_shift);

		ASSERT(!PP_ISMAPPED_LARGE(pp));
	}

	if (PP_ISNC(pp))
		return (vaddr);

	if (PP_NEWPAGE(pp)) {
		PP_SET_VCOLOR(pp, vcolor);
		return (vaddr);
	}

	if (PP_GET_VCOLOR(pp) == vcolor)
		return (vaddr);

	ASSERT(!PP_ISMAPPED_KPM(pp));
	sfmmu_kpm_vac_conflict(pp, vaddr);

	return (vaddr);
}

/*
 * VAC conflict state bit values.
 * The following defines are used to make the handling of the
 * various input states more concise. For that the kpm states
 * per kpm_page and per page are combined in a summary state.
 * Each single state has a corresponding bit value in the
 * summary state. These defines only apply for kpm large page
 * mappings. Within comments the abbreviations "kc, c, ks, s"
 * are used as short form of the actual state, e.g. "kc" for
 * "kp_refcntc > 0", etc.
 */
#define	KPM_KC	0x00000008	/* kpm_page: kp_refcntc > 0 */
#define	KPM_C	0x00000004	/* page: P_KPMC set */
#define	KPM_KS	0x00000002	/* kpm_page: kp_refcnts > 0 */
#define	KPM_S	0x00000001	/* page: P_KPMS set */

/*
 * Summary states used in sfmmu_kpm_fault (KPM_TSBM_*).
 * See also more detailed comments within in the sfmmu_kpm_fault switch.
 * Abbreviations used:
 * CONFL: VAC conflict(s) within a kpm_page.
 * MAPS:  Mapped small: Page mapped in using a regular page size kpm mapping.
 * RASM:  Re-assembling of a large page mapping possible.
 * RPLS:  Replace: TSB miss due to TSB replacement only.
 * BRKO:  Breakup Other: A large kpm mapping has to be broken because another
 *        page within the kpm_page is already involved in a VAC conflict.
 * BRKT:  Breakup This: A large kpm mapping has to be broken, this page is
 *        is involved in a VAC conflict.
 */
#define	KPM_TSBM_CONFL_GONE	(0)
#define	KPM_TSBM_MAPS_RASM	(KPM_KS)
#define	KPM_TSBM_RPLS_RASM	(KPM_KS | KPM_S)
#define	KPM_TSBM_MAPS_BRKO	(KPM_KC)
#define	KPM_TSBM_MAPS		(KPM_KC | KPM_KS)
#define	KPM_TSBM_RPLS		(KPM_KC | KPM_KS | KPM_S)
#define	KPM_TSBM_MAPS_BRKT	(KPM_KC | KPM_C)
#define	KPM_TSBM_MAPS_CONFL	(KPM_KC | KPM_C | KPM_KS)
#define	KPM_TSBM_RPLS_CONFL	(KPM_KC | KPM_C | KPM_KS | KPM_S)

/*
 * kpm fault handler for mappings with large page size.
 */
int
sfmmu_kpm_fault(caddr_t vaddr, struct memseg *mseg, page_t *pp)
{
	int		error;
	pgcnt_t		inx;
	kpm_page_t	*kp;
	tte_t		tte;
	pfn_t		pfn = pp->p_pagenum;
	kpm_hlk_t	*kpmp;
	kmutex_t	*pml;
	int		alias_range;
	int		uncached = 0;
	kmutex_t	*pmtx;
	int		badstate;
	uint_t		tsbmcase;

	alias_range = IS_KPM_ALIAS_RANGE(vaddr);

	inx = ptokpmp(kpmptop(ptokpmp(pfn)) - mseg->kpm_pbase);
	if (inx >= mseg->kpm_nkpmpgs) {
		cmn_err(CE_PANIC, "sfmmu_kpm_fault: kpm overflow in memseg "
			"0x%p  pp 0x%p", (void *)mseg, (void *)pp);
	}

	kp = &mseg->kpm_pages[inx];
	kpmp = KPMP_HASH(kp);

	pml = sfmmu_mlist_enter(pp);

	if (!PP_ISMAPPED_KPM(pp)) {
		sfmmu_mlist_exit(pml);
		return (EFAULT);
	}

	mutex_enter(&kpmp->khl_mutex);

	if (alias_range) {
		ASSERT(!PP_ISMAPPED_LARGE(pp));
		if (kp->kp_refcnta > 0) {
			if (PP_ISKPMC(pp)) {
				pmtx = sfmmu_page_enter(pp);
				PP_CLRKPMC(pp);
				sfmmu_page_exit(pmtx);
			}
			/*
			 * Check for vcolor conflicts. Return here
			 * w/ either no conflict (fast path), removed hme
			 * mapping chains (unload conflict) or uncached
			 * (uncache conflict). VACaches are cleaned and
			 * p_vcolor and PP_TNC are set accordingly for the
			 * conflict cases.  Drop kpmp for uncache conflict
			 * cases since it will be grabbed within
			 * sfmmu_kpm_page_cache in case of an uncache
			 * conflict.
			 */
			mutex_exit(&kpmp->khl_mutex);
			sfmmu_kpm_vac_conflict(pp, vaddr);
			mutex_enter(&kpmp->khl_mutex);

			if (PP_ISNC(pp)) {
				uncached = 1;
				pmtx = sfmmu_page_enter(pp);
				PP_SETKPMC(pp);
				sfmmu_page_exit(pmtx);
			}
			goto smallexit;

		} else {
			/*
			 * We got a tsbmiss on a not active kpm_page range.
			 * Let segkpm_fault decide how to panic.
			 */
			error = EFAULT;
		}
		goto exit;
	}

	badstate = (kp->kp_refcnt < 0 || kp->kp_refcnts < 0);
	if (kp->kp_refcntc == -1) {
		/*
		 * We should come here only if trap level tsb miss
		 * handler is disabled.
		 */
		badstate |= (kp->kp_refcnt == 0 || kp->kp_refcnts > 0 ||
			PP_ISKPMC(pp) || PP_ISKPMS(pp) || PP_ISNC(pp));

		if (badstate == 0)
			goto largeexit;
	}

	if (badstate || kp->kp_refcntc < 0)
		goto badstate_exit;

	/*
	 * Combine the per kpm_page and per page kpm VAC states to
	 * a summary state in order to make the kpm fault handling
	 * more concise.
	 */
	tsbmcase = (((kp->kp_refcntc > 0) ? KPM_KC : 0) |
			((kp->kp_refcnts > 0) ? KPM_KS : 0) |
			(PP_ISKPMC(pp) ? KPM_C : 0) |
			(PP_ISKPMS(pp) ? KPM_S : 0));

	switch (tsbmcase) {
	case KPM_TSBM_CONFL_GONE:		/* - - - - */
		/*
		 * That's fine, we either have no more vac conflict in
		 * this kpm page or someone raced in and has solved the
		 * vac conflict for us -- call sfmmu_kpm_vac_conflict
		 * to take care for correcting the vcolor and flushing
		 * the dcache if required.
		 */
		mutex_exit(&kpmp->khl_mutex);
		sfmmu_kpm_vac_conflict(pp, vaddr);
		mutex_enter(&kpmp->khl_mutex);

		if (PP_ISNC(pp) || kp->kp_refcnt <= 0 ||
		    addr_to_vcolor(vaddr) != PP_GET_VCOLOR(pp)) {
			panic("sfmmu_kpm_fault: inconsistent CONFL_GONE "
				"state, pp=%p", (void *)pp);
		}
		goto largeexit;

	case KPM_TSBM_MAPS_RASM:		/* - - ks - */
		/*
		 * All conflicts in this kpm page are gone but there are
		 * already small mappings around, so we also map this
		 * page small. This could be the trigger case for a
		 * small mapping reaper, if this is really needed.
		 * For now fall thru to the KPM_TSBM_MAPS handling.
		 */

	case KPM_TSBM_MAPS:			/* kc - ks - */
		/*
		 * Large page mapping is already broken, this page is not
		 * conflicting, so map it small. Call sfmmu_kpm_vac_conflict
		 * to take care for correcting the vcolor and flushing
		 * the dcache if required.
		 */
		mutex_exit(&kpmp->khl_mutex);
		sfmmu_kpm_vac_conflict(pp, vaddr);
		mutex_enter(&kpmp->khl_mutex);

		if (PP_ISNC(pp) || kp->kp_refcnt <= 0 ||
		    addr_to_vcolor(vaddr) != PP_GET_VCOLOR(pp)) {
			panic("sfmmu_kpm_fault:  inconsistent MAPS state, "
				"pp=%p", (void *)pp);
		}
		kp->kp_refcnt--;
		kp->kp_refcnts++;
		pmtx = sfmmu_page_enter(pp);
		PP_SETKPMS(pp);
		sfmmu_page_exit(pmtx);
		goto smallexit;

	case KPM_TSBM_RPLS_RASM:		/* - - ks s */
		/*
		 * All conflicts in this kpm page are gone but this page
		 * is mapped small. This could be the trigger case for a
		 * small mapping reaper, if this is really needed.
		 * For now we drop it in small again. Fall thru to the
		 * KPM_TSBM_RPLS handling.
		 */

	case KPM_TSBM_RPLS:			/* kc - ks s */
		/*
		 * Large page mapping is already broken, this page is not
		 * conflicting but already mapped small, so drop it in
		 * small again.
		 */
		if (PP_ISNC(pp) ||
		    addr_to_vcolor(vaddr) != PP_GET_VCOLOR(pp)) {
			panic("sfmmu_kpm_fault:  inconsistent RPLS state, "
				"pp=%p", (void *)pp);
		}
		goto smallexit;

	case KPM_TSBM_MAPS_BRKO:		/* kc - - - */
		/*
		 * The kpm page where we live in is marked conflicting
		 * but this page is not conflicting. So we have to map it
		 * in small. Call sfmmu_kpm_vac_conflict to take care for
		 * correcting the vcolor and flushing the dcache if required.
		 */
		mutex_exit(&kpmp->khl_mutex);
		sfmmu_kpm_vac_conflict(pp, vaddr);
		mutex_enter(&kpmp->khl_mutex);

		if (PP_ISNC(pp) || kp->kp_refcnt <= 0 ||
		    addr_to_vcolor(vaddr) != PP_GET_VCOLOR(pp)) {
			panic("sfmmu_kpm_fault:  inconsistent MAPS_BRKO state, "
				"pp=%p", (void *)pp);
		}
		kp->kp_refcnt--;
		kp->kp_refcnts++;
		pmtx = sfmmu_page_enter(pp);
		PP_SETKPMS(pp);
		sfmmu_page_exit(pmtx);
		goto smallexit;

	case KPM_TSBM_MAPS_BRKT:		/* kc c - - */
	case KPM_TSBM_MAPS_CONFL:		/* kc c ks - */
		if (!PP_ISMAPPED(pp)) {
			/*
			 * We got a tsbmiss on kpm large page range that is
			 * marked to contain vac conflicting pages introduced
			 * by hme mappings. The hme mappings are all gone and
			 * must have bypassed the kpm alias prevention logic.
			 */
			panic("sfmmu_kpm_fault: stale VAC conflict, pp=%p",
				(void *)pp);
		}

		/*
		 * Check for vcolor conflicts. Return here w/ either no
		 * conflict (fast path), removed hme mapping chains
		 * (unload conflict) or uncached (uncache conflict).
		 * Dcache is cleaned and p_vcolor and P_TNC are set
		 * accordingly. Drop kpmp for uncache conflict cases
		 * since it will be grabbed within sfmmu_kpm_page_cache
		 * in case of an uncache conflict.
		 */
		mutex_exit(&kpmp->khl_mutex);
		sfmmu_kpm_vac_conflict(pp, vaddr);
		mutex_enter(&kpmp->khl_mutex);

		if (kp->kp_refcnt <= 0)
			panic("sfmmu_kpm_fault: bad refcnt kp=%p", (void *)kp);

		if (PP_ISNC(pp)) {
			uncached = 1;
		} else {
			/*
			 * When an unload conflict is solved and there are
			 * no other small mappings around, we can resume
			 * largepage mode. Otherwise we have to map or drop
			 * in small. This could be a trigger for a small
			 * mapping reaper when this was the last conflict
			 * within the kpm page and when there are only
			 * other small mappings around.
			 */
			ASSERT(addr_to_vcolor(vaddr) == PP_GET_VCOLOR(pp));
			ASSERT(kp->kp_refcntc > 0);
			kp->kp_refcntc--;
			pmtx = sfmmu_page_enter(pp);
			PP_CLRKPMC(pp);
			sfmmu_page_exit(pmtx);
			ASSERT(PP_ISKPMS(pp) == 0);
			if (kp->kp_refcntc == 0 && kp->kp_refcnts == 0)
				goto largeexit;
		}

		kp->kp_refcnt--;
		kp->kp_refcnts++;
		pmtx = sfmmu_page_enter(pp);
		PP_SETKPMS(pp);
		sfmmu_page_exit(pmtx);
		goto smallexit;

	case KPM_TSBM_RPLS_CONFL:		/* kc c ks s */
		if (!PP_ISMAPPED(pp)) {
			/*
			 * We got a tsbmiss on kpm large page range that is
			 * marked to contain vac conflicting pages introduced
			 * by hme mappings. They are all gone and must have
			 * somehow bypassed the kpm alias prevention logic.
			 */
			panic("sfmmu_kpm_fault: stale VAC conflict, pp=%p",
				(void *)pp);
		}

		/*
		 * This state is only possible for an uncached mapping.
		 */
		if (!PP_ISNC(pp)) {
			panic("sfmmu_kpm_fault: page not uncached, pp=%p",
				(void *)pp);
		}
		uncached = 1;
		goto smallexit;

	default:
badstate_exit:
		panic("sfmmu_kpm_fault: inconsistent VAC state, vaddr=%p kp=%p "
			"pp=%p", (void *)vaddr, (void *)kp, (void *)pp);
	}

smallexit:
	/* tte assembly */
	if (uncached == 0)
		KPM_TTE_VCACHED(tte.ll, pfn, TTE8K);
	else
		KPM_TTE_VUNCACHED(tte.ll, pfn, TTE8K);

	/* tsb dropin */
	sfmmu_kpm_load_tsb(vaddr, &tte, MMU_PAGESHIFT);

	error = 0;
	goto exit;

largeexit:
	if (kp->kp_refcnt > 0) {

		/* tte assembly */
		KPM_TTE_VCACHED(tte.ll, pfn, TTE4M);

		/* tsb dropin */
		sfmmu_kpm_load_tsb(vaddr, &tte, MMU_PAGESHIFT4M);

		if (kp->kp_refcntc == 0) {
			/* Set "go" flag for TL tsbmiss handler */
			sfmmu_kpm_tsbmtl(&kp->kp_refcntc, &kpmp->khl_lock,
					KPMTSBM_START);
		}
		ASSERT(kp->kp_refcntc == -1);
		error = 0;

	} else
		error = EFAULT;
exit:
	mutex_exit(&kpmp->khl_mutex);
	sfmmu_mlist_exit(pml);
	return (error);
}

/*
 * kpm fault handler for mappings with small page size.
 */
int
sfmmu_kpm_fault_small(caddr_t vaddr, struct memseg *mseg, page_t *pp)
{
	int		error = 0;
	pgcnt_t		inx;
	kpm_spage_t	*ksp;
	kpm_shlk_t	*kpmsp;
	kmutex_t	*pml;
	pfn_t		pfn = pp->p_pagenum;
	tte_t		tte;
	kmutex_t	*pmtx;
	int		oldval;

	inx = pfn - mseg->kpm_pbase;
	ksp = &mseg->kpm_spages[inx];
	kpmsp = KPMP_SHASH(ksp);

	pml = sfmmu_mlist_enter(pp);

	if (!PP_ISMAPPED_KPM(pp)) {
		sfmmu_mlist_exit(pml);
		return (EFAULT);
	}

	/*
	 * kp_mapped lookup protected by mlist mutex
	 */
	if (ksp->kp_mapped == KPM_MAPPEDS) {
		/*
		 * Fast path tsbmiss
		 */
		ASSERT(!PP_ISKPMC(pp));
		ASSERT(!PP_ISNC(pp));

		/* tte assembly */
		KPM_TTE_VCACHED(tte.ll, pfn, TTE8K);

		/* tsb dropin */
		sfmmu_kpm_load_tsb(vaddr, &tte, MMU_PAGESHIFT);

	} else if (ksp->kp_mapped == KPM_MAPPEDSC) {
		/*
		 * Got here due to existing or gone kpm/hme VAC conflict.
		 * Recheck for vcolor conflicts. Return here w/ either
		 * no conflict, removed hme mapping chain (unload
		 * conflict) or uncached (uncache conflict). VACaches
		 * are cleaned and p_vcolor and PP_TNC are set accordingly
		 * for the conflict cases.
		 */
		sfmmu_kpm_vac_conflict(pp, vaddr);

		if (PP_ISNC(pp)) {
			/* ASSERT(pp->p_share); XXX use hat_page_getshare */

			/* tte assembly */
			KPM_TTE_VUNCACHED(tte.ll, pfn, TTE8K);

			/* tsb dropin */
			sfmmu_kpm_load_tsb(vaddr, &tte, MMU_PAGESHIFT);

		} else {
			if (PP_ISKPMC(pp)) {
				pmtx = sfmmu_page_enter(pp);
				PP_CLRKPMC(pp);
				sfmmu_page_exit(pmtx);
			}

			/* tte assembly */
			KPM_TTE_VCACHED(tte.ll, pfn, TTE8K);

			/* tsb dropin */
			sfmmu_kpm_load_tsb(vaddr, &tte, MMU_PAGESHIFT);

			oldval = sfmmu_kpm_stsbmtl(&ksp->kp_mapped,
					&kpmsp->kshl_lock, KPM_MAPPEDS);

			if (oldval != KPM_MAPPEDSC)
				panic("sfmmu_kpm_fault_small: "
					"stale smallpages mapping");
		}

	} else {
		/*
		 * We got a tsbmiss on a not active kpm_page range.
		 * Let decide segkpm_fault how to panic.
		 */
		error = EFAULT;
	}

	sfmmu_mlist_exit(pml);
	return (error);
}

/*
 * Check/handle potential hme/kpm mapping conflicts
 */
static void
sfmmu_kpm_vac_conflict(page_t *pp, caddr_t vaddr)
{
	int		vcolor;
	struct sf_hment	*sfhmep;
	struct hat	*tmphat;
	struct sf_hment	*tmphme = NULL;
	struct hme_blk	*hmeblkp;
	tte_t		tte;

	ASSERT(sfmmu_mlist_held(pp));

	if (PP_ISNC(pp))
		return;

	vcolor = addr_to_vcolor(vaddr);
	if (PP_GET_VCOLOR(pp) == vcolor)
		return;

	/*
	 * There could be no vcolor conflict between a large cached
	 * hme page and a non alias range kpm page (neither large nor
	 * small mapped). So if a hme conflict already exists between
	 * a constituent page of a large hme mapping and a shared small
	 * conflicting hme mapping, both mappings must be already
	 * uncached at this point.
	 */
	ASSERT(!PP_ISMAPPED_LARGE(pp));

	if (!PP_ISMAPPED(pp)) {
		/*
		 * Previous hme user of page had a different color
		 * but since there are no current users
		 * we just flush the cache and change the color.
		 */
		SFMMU_STAT(sf_pgcolor_conflict);
		sfmmu_cache_flush(pp->p_pagenum, PP_GET_VCOLOR(pp));
		PP_SET_VCOLOR(pp, vcolor);
		return;
	}

	/*
	 * If we get here we have a vac conflict with a current hme
	 * mapping. This must have been established by forcing a wrong
	 * colored mapping, e.g. by using mmap(2) with MAP_FIXED.
	 */

	/*
	 * Check if any mapping is in same as or if it is locked
	 * since in that case we need to uncache.
	 */
	for (sfhmep = pp->p_mapping; sfhmep; sfhmep = tmphme) {
		tmphme = sfhmep->hme_next;
		hmeblkp = sfmmu_hmetohblk(sfhmep);
		if (hmeblkp->hblk_xhat_bit)
			continue;
		tmphat = hblktosfmmu(hmeblkp);
		sfmmu_copytte(&sfhmep->hme_tte, &tte);
		ASSERT(TTE_IS_VALID(&tte));
		if ((tmphat == ksfmmup) || hmeblkp->hblk_lckcnt) {
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
	 */
	SFMMU_STAT(sf_unload_conflict);

	for (sfhmep = pp->p_mapping; sfhmep; sfhmep = tmphme) {
		tmphme = sfhmep->hme_next;
		hmeblkp = sfmmu_hmetohblk(sfhmep);
		if (hmeblkp->hblk_xhat_bit)
			continue;
		(void) sfmmu_pageunload(pp, sfhmep, TTE8K);
	}

	/*
	 * Unloads only does tlb flushes so we need to flush the
	 * dcache vcolor here.
	 */
	sfmmu_cache_flush(pp->p_pagenum, PP_GET_VCOLOR(pp));
	PP_SET_VCOLOR(pp, vcolor);
}

/*
 * Remove all kpm mappings using kpme's for pp and check that
 * all kpm mappings (w/ and w/o kpme's) are gone.
 */
static void
sfmmu_kpm_pageunload(page_t *pp)
{
	caddr_t		vaddr;
	struct kpme	*kpme, *nkpme;

	ASSERT(pp != NULL);
	ASSERT(pp->p_kpmref);
	ASSERT(sfmmu_mlist_held(pp));

	vaddr = hat_kpm_page2va(pp, 1);

	for (kpme = pp->p_kpmelist; kpme; kpme = nkpme) {
		ASSERT(kpme->kpe_page == pp);

		if (pp->p_kpmref == 0)
			panic("sfmmu_kpm_pageunload: stale p_kpmref pp=%p "
				"kpme=%p", (void *)pp, (void *)kpme);

		nkpme = kpme->kpe_next;

		/* Add instance callback here here if needed later */
		sfmmu_kpme_sub(kpme, pp);
	}

	/*
	 * Also correct after mixed kpme/nonkpme mappings. If nonkpme
	 * segkpm clients have unlocked the page and forgot to mapout
	 * we panic here.
	 */
	if (pp->p_kpmref != 0)
		panic("sfmmu_kpm_pageunload: bad refcnt pp=%p", (void *)pp);

	sfmmu_kpm_mapout(pp, vaddr);
}

/*
 * Remove a large kpm mapping from kernel TSB and all TLB's.
 */
static void
sfmmu_kpm_demap_large(caddr_t vaddr)
{
	sfmmu_kpm_unload_tsb(vaddr, MMU_PAGESHIFT4M);
	sfmmu_kpm_demap_tlbs(vaddr, KCONTEXT);
}

/*
 * Remove a small kpm mapping from kernel TSB and all TLB's.
 */
static void
sfmmu_kpm_demap_small(caddr_t vaddr)
{
	sfmmu_kpm_unload_tsb(vaddr, MMU_PAGESHIFT);
	sfmmu_kpm_demap_tlbs(vaddr, KCONTEXT);
}

/*
 * Demap a kpm mapping in all TLB's.
 */
static void
sfmmu_kpm_demap_tlbs(caddr_t vaddr, int ctxnum)
{
	cpuset_t cpuset;

	kpreempt_disable();
	cpuset = ksfmmup->sfmmu_cpusran;
	CPUSET_AND(cpuset, cpu_ready_set);
	CPUSET_DEL(cpuset, CPU->cpu_id);
	SFMMU_XCALL_STATS(ctxnum);
	xt_some(cpuset, vtag_flushpage_tl1, (uint64_t)vaddr, ctxnum);
	vtag_flushpage(vaddr, ctxnum);
	kpreempt_enable();
}

/*
 * Summary states used in sfmmu_kpm_vac_unload (KPM_VUL__*).
 * See also more detailed comments within in the sfmmu_kpm_vac_unload switch.
 * Abbreviations used:
 * BIG:   Large page kpm mapping in use.
 * CONFL: VAC conflict(s) within a kpm_page.
 * INCR:  Count of conflicts within a kpm_page is going to be incremented.
 * DECR:  Count of conflicts within a kpm_page is going to be decremented.
 * UNMAP_SMALL: A small (regular page size) mapping is going to be unmapped.
 * TNC:   Temporary non cached: a kpm mapped page is mapped in TNC state.
 */
#define	KPM_VUL_BIG		(0)
#define	KPM_VUL_CONFL_INCR1	(KPM_KS)
#define	KPM_VUL_UNMAP_SMALL1	(KPM_KS | KPM_S)
#define	KPM_VUL_CONFL_INCR2	(KPM_KC)
#define	KPM_VUL_CONFL_INCR3	(KPM_KC | KPM_KS)
#define	KPM_VUL_UNMAP_SMALL2	(KPM_KC | KPM_KS | KPM_S)
#define	KPM_VUL_CONFL_DECR1	(KPM_KC | KPM_C)
#define	KPM_VUL_CONFL_DECR2	(KPM_KC | KPM_C | KPM_KS)
#define	KPM_VUL_TNC		(KPM_KC | KPM_C | KPM_KS | KPM_S)

/*
 * Handle VAC unload conflicts introduced by hme mappings or vice
 * versa when a hme conflict mapping is replaced by a non conflict
 * one. Perform actions and state transitions according to the
 * various page and kpm_page entry states. VACache flushes are in
 * the responsibiliy of the caller. We still hold the mlist lock.
 */
static void
sfmmu_kpm_vac_unload(page_t *pp, caddr_t vaddr)
{
	kpm_page_t	*kp;
	kpm_hlk_t	*kpmp;
	caddr_t		kpmvaddr = hat_kpm_page2va(pp, 1);
	int		newcolor;
	kmutex_t	*pmtx;
	uint_t		vacunlcase;
	int		badstate = 0;
	kpm_spage_t	*ksp;
	kpm_shlk_t	*kpmsp;

	ASSERT(PAGE_LOCKED(pp));
	ASSERT(sfmmu_mlist_held(pp));
	ASSERT(!PP_ISNC(pp));

	newcolor = addr_to_vcolor(kpmvaddr) != addr_to_vcolor(vaddr);
	if (kpm_smallpages)
		goto smallpages_vac_unload;

	PP2KPMPG(pp, kp);
	kpmp = KPMP_HASH(kp);
	mutex_enter(&kpmp->khl_mutex);

	if (IS_KPM_ALIAS_RANGE(kpmvaddr)) {
		if (kp->kp_refcnta < 1) {
			panic("sfmmu_kpm_vac_unload: bad refcnta kpm_page=%p\n",
				(void *)kp);
		}

		if (PP_ISKPMC(pp) == 0) {
			if (newcolor == 0)
				goto exit;
			sfmmu_kpm_demap_small(kpmvaddr);
			pmtx = sfmmu_page_enter(pp);
			PP_SETKPMC(pp);
			sfmmu_page_exit(pmtx);

		} else if (newcolor == 0) {
			pmtx = sfmmu_page_enter(pp);
			PP_CLRKPMC(pp);
			sfmmu_page_exit(pmtx);

		} else {
			badstate++;
		}

		goto exit;
	}

	badstate = (kp->kp_refcnt < 0 || kp->kp_refcnts < 0);
	if (kp->kp_refcntc == -1) {
		/*
		 * We should come here only if trap level tsb miss
		 * handler is disabled.
		 */
		badstate |= (kp->kp_refcnt == 0 || kp->kp_refcnts > 0 ||
			PP_ISKPMC(pp) || PP_ISKPMS(pp) || PP_ISNC(pp));
	} else {
		badstate |= (kp->kp_refcntc < 0);
	}

	if (badstate)
		goto exit;

	if (PP_ISKPMC(pp) == 0 && newcolor == 0) {
		ASSERT(PP_ISKPMS(pp) == 0);
		goto exit;
	}

	/*
	 * Combine the per kpm_page and per page kpm VAC states
	 * to a summary state in order to make the vac unload
	 * handling more concise.
	 */
	vacunlcase = (((kp->kp_refcntc > 0) ? KPM_KC : 0) |
			((kp->kp_refcnts > 0) ? KPM_KS : 0) |
			(PP_ISKPMC(pp) ? KPM_C : 0) |
			(PP_ISKPMS(pp) ? KPM_S : 0));

	switch (vacunlcase) {
	case KPM_VUL_BIG:				/* - - - - */
		/*
		 * Have to breakup the large page mapping to be
		 * able to handle the conflicting hme vaddr.
		 */
		if (kp->kp_refcntc == -1) {
			/* remove go indication */
			sfmmu_kpm_tsbmtl(&kp->kp_refcntc,
					&kpmp->khl_lock, KPMTSBM_STOP);
		}
		sfmmu_kpm_demap_large(kpmvaddr);

		ASSERT(kp->kp_refcntc == 0);
		kp->kp_refcntc++;
		pmtx = sfmmu_page_enter(pp);
		PP_SETKPMC(pp);
		sfmmu_page_exit(pmtx);
		break;

	case KPM_VUL_UNMAP_SMALL1:			/* -  - ks s */
	case KPM_VUL_UNMAP_SMALL2:			/* kc - ks s */
		/*
		 * New conflict w/ an active kpm page, actually mapped
		 * in by small TSB/TLB entries. Remove the mapping and
		 * update states.
		 */
		ASSERT(newcolor);
		sfmmu_kpm_demap_small(kpmvaddr);
		kp->kp_refcnts--;
		kp->kp_refcnt++;
		kp->kp_refcntc++;
		pmtx = sfmmu_page_enter(pp);
		PP_CLRKPMS(pp);
		PP_SETKPMC(pp);
		sfmmu_page_exit(pmtx);
		break;

	case KPM_VUL_CONFL_INCR1:			/* -  - ks - */
	case KPM_VUL_CONFL_INCR2:			/* kc - -  - */
	case KPM_VUL_CONFL_INCR3:			/* kc - ks - */
		/*
		 * New conflict on a active kpm mapped page not yet in
		 * TSB/TLB. Mark page and increment the kpm_page conflict
		 * count.
		 */
		ASSERT(newcolor);
		kp->kp_refcntc++;
		pmtx = sfmmu_page_enter(pp);
		PP_SETKPMC(pp);
		sfmmu_page_exit(pmtx);
		break;

	case KPM_VUL_CONFL_DECR1:			/* kc c -  - */
	case KPM_VUL_CONFL_DECR2:			/* kc c ks - */
		/*
		 * A conflicting hme mapping is removed for an active
		 * kpm page not yet in TSB/TLB. Unmark page and decrement
		 * the kpm_page conflict count.
		 */
		ASSERT(newcolor == 0);
		kp->kp_refcntc--;
		pmtx = sfmmu_page_enter(pp);
		PP_CLRKPMC(pp);
		sfmmu_page_exit(pmtx);
		break;

	case KPM_VUL_TNC:				/* kc c ks s */
		cmn_err(CE_NOTE, "sfmmu_kpm_vac_unload: "
			"page not in NC state");
		/* FALLTHRU */

	default:
		badstate++;
	}
exit:
	if (badstate) {
		panic("sfmmu_kpm_vac_unload: inconsistent VAC state, "
			"kpmvaddr=%p kp=%p pp=%p",
			(void *)kpmvaddr, (void *)kp, (void *)pp);
	}
	mutex_exit(&kpmp->khl_mutex);

	return;

smallpages_vac_unload:
	if (newcolor == 0)
		return;

	PP2KPMSPG(pp, ksp);
	kpmsp = KPMP_SHASH(ksp);

	if (PP_ISKPMC(pp) == 0) {
		if (ksp->kp_mapped == KPM_MAPPEDS) {
			/*
			 * Stop TL tsbmiss handling
			 */
			(void) sfmmu_kpm_stsbmtl(&ksp->kp_mapped,
					&kpmsp->kshl_lock, KPM_MAPPEDSC);

			sfmmu_kpm_demap_small(kpmvaddr);

		} else if (ksp->kp_mapped != KPM_MAPPEDSC) {
			panic("sfmmu_kpm_vac_unload: inconsistent mapping");
		}

		pmtx = sfmmu_page_enter(pp);
		PP_SETKPMC(pp);
		sfmmu_page_exit(pmtx);

	} else {
		if (ksp->kp_mapped != KPM_MAPPEDSC)
			panic("sfmmu_kpm_vac_unload: inconsistent mapping");
	}
}

/*
 * Page is marked to be in VAC conflict to an existing kpm mapping
 * or is kpm mapped using only the regular pagesize. Called from
 * sfmmu_hblk_unload when a mlist is completely removed.
 */
static void
sfmmu_kpm_hme_unload(page_t *pp)
{
	/* tte assembly */
	kpm_page_t	*kp;
	kpm_hlk_t	*kpmp;
	caddr_t		vaddr;
	kmutex_t	*pmtx;
	uint_t		flags;
	kpm_spage_t	*ksp;

	ASSERT(sfmmu_mlist_held(pp));
	ASSERT(PP_ISMAPPED_KPM(pp));

	flags = pp->p_nrm & (P_KPMC | P_KPMS);
	if (kpm_smallpages)
		goto smallpages_hme_unload;

	if (flags == (P_KPMC | P_KPMS)) {
		panic("sfmmu_kpm_hme_unload: page should be uncached");

	} else if (flags == P_KPMS) {
		/*
		 * Page mapped small but not involved in VAC conflict
		 */
		return;
	}

	vaddr = hat_kpm_page2va(pp, 1);

	PP2KPMPG(pp, kp);
	kpmp = KPMP_HASH(kp);
	mutex_enter(&kpmp->khl_mutex);

	if (IS_KPM_ALIAS_RANGE(vaddr)) {
		if (kp->kp_refcnta < 1) {
			panic("sfmmu_kpm_hme_unload: bad refcnta kpm_page=%p\n",
				(void *)kp);
		}

	} else {
		if (kp->kp_refcntc < 1) {
			panic("sfmmu_kpm_hme_unload: bad refcntc kpm_page=%p\n",
				(void *)kp);
		}
		kp->kp_refcntc--;
	}

	pmtx = sfmmu_page_enter(pp);
	PP_CLRKPMC(pp);
	sfmmu_page_exit(pmtx);

	mutex_exit(&kpmp->khl_mutex);
	return;

smallpages_hme_unload:
	if (flags != P_KPMC)
		panic("sfmmu_kpm_hme_unload: page should be uncached");

	vaddr = hat_kpm_page2va(pp, 1);
	PP2KPMSPG(pp, ksp);

	if (ksp->kp_mapped != KPM_MAPPEDSC)
		panic("sfmmu_kpm_hme_unload: inconsistent mapping");

	/*
	 * Keep KPM_MAPPEDSC until the next kpm tsbmiss where it
	 * prevents TL tsbmiss handling and force a hat_kpm_fault.
	 * There we can start over again.
	 */

	pmtx = sfmmu_page_enter(pp);
	PP_CLRKPMC(pp);
	sfmmu_page_exit(pmtx);
}

/*
 * Special hooks for sfmmu_page_cache_array() when changing the
 * cacheability of a page. It is used to obey the hat_kpm lock
 * ordering (mlist -> kpmp -> spl, and back).
 */
static kpm_hlk_t *
sfmmu_kpm_kpmp_enter(page_t *pp, pgcnt_t npages)
{
	kpm_page_t	*kp;
	kpm_hlk_t	*kpmp;

	ASSERT(sfmmu_mlist_held(pp));

	if (kpm_smallpages || PP_ISMAPPED_KPM(pp) == 0)
		return (NULL);

	ASSERT(npages <= kpmpnpgs);

	PP2KPMPG(pp, kp);
	kpmp = KPMP_HASH(kp);
	mutex_enter(&kpmp->khl_mutex);

	return (kpmp);
}

static void
sfmmu_kpm_kpmp_exit(kpm_hlk_t *kpmp)
{
	if (kpm_smallpages || kpmp == NULL)
		return;

	mutex_exit(&kpmp->khl_mutex);
}

/*
 * Summary states used in sfmmu_kpm_page_cache (KPM_*).
 * See also more detailed comments within in the sfmmu_kpm_page_cache switch.
 * Abbreviations used:
 * UNC:     Input state for an uncache request.
 *   BIG:     Large page kpm mapping in use.
 *   SMALL:   Page has a small kpm mapping within a kpm_page range.
 *   NODEMAP: No demap needed.
 *   NOP:     No operation needed on this input state.
 * CACHE:   Input state for a re-cache request.
 *   MAPS:    Page is in TNC and kpm VAC conflict state and kpm mapped small.
 *   NOMAP:   Page is in TNC and kpm VAC conflict state, but not small kpm
 *            mapped.
 *   NOMAPO:  Page is in TNC and kpm VAC conflict state, but not small kpm
 *            mapped. There are also other small kpm mappings within this
 *            kpm_page.
 */
#define	KPM_UNC_BIG		(0)
#define	KPM_UNC_NODEMAP1	(KPM_KS)
#define	KPM_UNC_SMALL1		(KPM_KS | KPM_S)
#define	KPM_UNC_NODEMAP2	(KPM_KC)
#define	KPM_UNC_NODEMAP3	(KPM_KC | KPM_KS)
#define	KPM_UNC_SMALL2		(KPM_KC | KPM_KS | KPM_S)
#define	KPM_UNC_NOP1		(KPM_KC | KPM_C)
#define	KPM_UNC_NOP2		(KPM_KC | KPM_C | KPM_KS)
#define	KPM_CACHE_NOMAP		(KPM_KC | KPM_C)
#define	KPM_CACHE_NOMAPO	(KPM_KC | KPM_C | KPM_KS)
#define	KPM_CACHE_MAPS		(KPM_KC | KPM_C | KPM_KS | KPM_S)

/*
 * This function is called when the virtual cacheability of a page
 * is changed and the page has an actice kpm mapping. The mlist mutex,
 * the spl hash lock and the kpmp mutex (if needed) are already grabbed.
 */
static void
sfmmu_kpm_page_cache(page_t *pp, int flags, int cache_flush_tag)
{
	kpm_page_t	*kp;
	kpm_hlk_t	*kpmp;
	caddr_t		kpmvaddr;
	int		badstate = 0;
	uint_t		pgcacase;
	kpm_spage_t	*ksp;
	kpm_shlk_t	*kpmsp;
	int		oldval;

	ASSERT(PP_ISMAPPED_KPM(pp));
	ASSERT(sfmmu_mlist_held(pp));
	ASSERT(sfmmu_page_spl_held(pp));

	if (flags != HAT_TMPNC && flags != HAT_CACHE)
		panic("sfmmu_kpm_page_cache: bad flags");

	kpmvaddr = hat_kpm_page2va(pp, 1);

	if (flags == HAT_TMPNC && cache_flush_tag == CACHE_FLUSH) {
		pfn_t pfn = pp->p_pagenum;
		int vcolor = addr_to_vcolor(kpmvaddr);
		cpuset_t cpuset = cpu_ready_set;

		/* Flush vcolor in DCache */
		CPUSET_DEL(cpuset, CPU->cpu_id);
		SFMMU_XCALL_STATS(ksfmmup->sfmmu_cnum);
		xt_some(cpuset, vac_flushpage_tl1, pfn, vcolor);
		vac_flushpage(pfn, vcolor);
	}

	if (kpm_smallpages)
		goto smallpages_page_cache;

	PP2KPMPG(pp, kp);
	kpmp = KPMP_HASH(kp);
	ASSERT(MUTEX_HELD(&kpmp->khl_mutex));

	if (IS_KPM_ALIAS_RANGE(kpmvaddr)) {
		if (kp->kp_refcnta < 1) {
			panic("sfmmu_kpm_page_cache: bad refcnta "
				"kpm_page=%p\n", (void *)kp);
		}
		sfmmu_kpm_demap_small(kpmvaddr);
		if (flags == HAT_TMPNC) {
			PP_SETKPMC(pp);
			ASSERT(!PP_ISKPMS(pp));
		} else {
			ASSERT(PP_ISKPMC(pp));
			PP_CLRKPMC(pp);
		}
		goto exit;
	}

	badstate = (kp->kp_refcnt < 0 || kp->kp_refcnts < 0);
	if (kp->kp_refcntc == -1) {
		/*
		 * We should come here only if trap level tsb miss
		 * handler is disabled.
		 */
		badstate |= (kp->kp_refcnt == 0 || kp->kp_refcnts > 0 ||
			PP_ISKPMC(pp) || PP_ISKPMS(pp) || PP_ISNC(pp));
	} else {
		badstate |= (kp->kp_refcntc < 0);
	}

	if (badstate)
		goto exit;

	/*
	 * Combine the per kpm_page and per page kpm VAC states to
	 * a summary state in order to make the VAC cache/uncache
	 * handling more concise.
	 */
	pgcacase = (((kp->kp_refcntc > 0) ? KPM_KC : 0) |
			((kp->kp_refcnts > 0) ? KPM_KS : 0) |
			(PP_ISKPMC(pp) ? KPM_C : 0) |
			(PP_ISKPMS(pp) ? KPM_S : 0));

	if (flags == HAT_CACHE) {
		switch (pgcacase) {
		case KPM_CACHE_MAPS:			/* kc c ks s */
			sfmmu_kpm_demap_small(kpmvaddr);
			if (kp->kp_refcnts < 1) {
				panic("sfmmu_kpm_page_cache: bad refcnts "
				"kpm_page=%p\n", (void *)kp);
			}
			kp->kp_refcnts--;
			kp->kp_refcnt++;
			PP_CLRKPMS(pp);
			/* FALLTHRU */

		case KPM_CACHE_NOMAP:			/* kc c -  - */
		case KPM_CACHE_NOMAPO:			/* kc c ks - */
			kp->kp_refcntc--;
			PP_CLRKPMC(pp);
			break;

		default:
			badstate++;
		}
		goto exit;
	}

	switch (pgcacase) {
	case KPM_UNC_BIG:				/* - - - - */
		if (kp->kp_refcnt < 1) {
			panic("sfmmu_kpm_page_cache: bad refcnt "
				"kpm_page=%p\n", (void *)kp);
		}

		/*
		 * Have to breakup the large page mapping in preparation
		 * to the upcoming TNC mode handled by small mappings.
		 * The demap can already be done due to another conflict
		 * within the kpm_page.
		 */
		if (kp->kp_refcntc == -1) {
			/* remove go indication */
			sfmmu_kpm_tsbmtl(&kp->kp_refcntc,
				&kpmp->khl_lock, KPMTSBM_STOP);
		}
		ASSERT(kp->kp_refcntc == 0);
		sfmmu_kpm_demap_large(kpmvaddr);
		kp->kp_refcntc++;
		PP_SETKPMC(pp);
		break;

	case KPM_UNC_SMALL1:				/* -  - ks s */
	case KPM_UNC_SMALL2:				/* kc - ks s */
		/*
		 * Have to demap an already small kpm mapping in preparation
		 * to the upcoming TNC mode. The demap can already be done
		 * due to another conflict within the kpm_page.
		 */
		sfmmu_kpm_demap_small(kpmvaddr);
		kp->kp_refcntc++;
		kp->kp_refcnts--;
		kp->kp_refcnt++;
		PP_CLRKPMS(pp);
		PP_SETKPMC(pp);
		break;

	case KPM_UNC_NODEMAP1:				/* -  - ks - */
		/* fallthru */

	case KPM_UNC_NODEMAP2:				/* kc - -  - */
	case KPM_UNC_NODEMAP3:				/* kc - ks - */
		kp->kp_refcntc++;
		PP_SETKPMC(pp);
		break;

	case KPM_UNC_NOP1:				/* kc c -  - */
	case KPM_UNC_NOP2:				/* kc c ks - */
		break;

	default:
		badstate++;
	}
exit:
	if (badstate) {
		panic("sfmmu_kpm_page_cache: inconsistent VAC state "
			"kpmvaddr=%p kp=%p pp=%p", (void *)kpmvaddr,
			(void *)kp, (void *)pp);
	}
	return;

smallpages_page_cache:
	PP2KPMSPG(pp, ksp);
	kpmsp = KPMP_SHASH(ksp);

	oldval = sfmmu_kpm_stsbmtl(&ksp->kp_mapped,
				&kpmsp->kshl_lock, KPM_MAPPEDSC);

	if (!(oldval == KPM_MAPPEDS || oldval == KPM_MAPPEDSC))
		panic("smallpages_page_cache: inconsistent mapping");

	sfmmu_kpm_demap_small(kpmvaddr);

	if (flags == HAT_TMPNC) {
		PP_SETKPMC(pp);
		ASSERT(!PP_ISKPMS(pp));

	} else {
		ASSERT(PP_ISKPMC(pp));
		PP_CLRKPMC(pp);
	}

	/*
	 * Keep KPM_MAPPEDSC until the next kpm tsbmiss where it
	 * prevents TL tsbmiss handling and force a hat_kpm_fault.
	 * There we can start over again.
	 */
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
	ASSERT(thd->t_procp->p_as == &kas);

	sfmmu_setctx_sec(KCONTEXT);
	sfmmu_load_mmustate(ksfmmup);
}
