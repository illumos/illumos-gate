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
 * Copyright (c) 1987, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * VM - Hardware Address Translation management.
 *
 * This file describes the contents of the sun-reference-mmu(sfmmu)-
 * specific hat data structures and the sfmmu-specific hat procedures.
 * The machine-independent interface is described in <vm/hat.h>.
 */

#ifndef	_VM_HAT_SFMMU_H
#define	_VM_HAT_SFMMU_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _ASM

#include <sys/types.h>

#endif /* _ASM */

#ifdef	_KERNEL

#include <sys/pte.h>
#include <vm/mach_sfmmu.h>
#include <sys/mmu.h>

/*
 * Don't alter these without considering changes to ism_map_t.
 */
#define	DEFAULT_ISM_PAGESIZE		MMU_PAGESIZE4M
#define	DEFAULT_ISM_PAGESZC		TTE4M
#define	ISM_PG_SIZE(ism_vbshift)	(1 << ism_vbshift)
#define	ISM_SZ_MASK(ism_vbshift)	(ISM_PG_SIZE(ism_vbshift) - 1)
#define	ISM_MAP_SLOTS	8	/* Change this carefully. */

#ifndef _ASM

#include <sys/t_lock.h>
#include <vm/hat.h>
#include <vm/seg.h>
#include <sys/machparam.h>
#include <sys/systm.h>
#include <sys/x_call.h>
#include <vm/page.h>
#include <sys/ksynch.h>

typedef struct hat sfmmu_t;
typedef struct sf_scd sf_scd_t;

/*
 * SFMMU attributes for hat_memload/hat_devload
 */
#define	SFMMU_UNCACHEPTTE	0x01000000	/* unencache in physical $ */
#define	SFMMU_UNCACHEVTTE	0x02000000	/* unencache in virtual $ */
#define	SFMMU_SIDEFFECT		0x04000000	/* set side effect bit */
#define	SFMMU_LOAD_ALLATTR	(HAT_PROT_MASK | HAT_ORDER_MASK |	\
		HAT_ENDIAN_MASK | HAT_NOFAULT | HAT_NOSYNC |		\
		SFMMU_UNCACHEPTTE | SFMMU_UNCACHEVTTE | SFMMU_SIDEFFECT)


/*
 * sfmmu flags for hat_memload/hat_devload
 */
#define	SFMMU_NO_TSBLOAD	0x08000000	/* do not preload tsb */
#define	SFMMU_LOAD_ALLFLAG	(HAT_LOAD | HAT_LOAD_LOCK |		\
		HAT_LOAD_ADV | HAT_LOAD_CONTIG | HAT_LOAD_NOCONSIST |	\
		HAT_LOAD_SHARE | HAT_LOAD_REMAP | SFMMU_NO_TSBLOAD |	\
		HAT_RELOAD_SHARE | HAT_NO_KALLOC | HAT_LOAD_TEXT)

/*
 * sfmmu internal flag to hat_pageunload that spares locked mappings
 */
#define	SFMMU_KERNEL_RELOC	0x8000

/*
 * mode for sfmmu_chgattr
 */
#define	SFMMU_SETATTR	0x0
#define	SFMMU_CLRATTR	0x1
#define	SFMMU_CHGATTR	0x2

/*
 * sfmmu specific flags for page_t
 */
#define	P_PNC	0x8		/* non-caching is permanent bit */
#define	P_TNC	0x10		/* non-caching is temporary bit */
#define	P_KPMS	0x20		/* kpm mapped small (vac alias prevention) */
#define	P_KPMC	0x40		/* kpm conflict page (vac alias prevention) */

#define	PP_GENERIC_ATTR(pp)	((pp)->p_nrm & (P_MOD | P_REF | P_RO))
#define	PP_ISMOD(pp)		((pp)->p_nrm & P_MOD)
#define	PP_ISREF(pp)		((pp)->p_nrm & P_REF)
#define	PP_ISRO(pp)		((pp)->p_nrm & P_RO)
#define	PP_ISNC(pp)		((pp)->p_nrm & (P_PNC|P_TNC))
#define	PP_ISPNC(pp)		((pp)->p_nrm & P_PNC)
#ifdef VAC
#define	PP_ISTNC(pp)		((pp)->p_nrm & P_TNC)
#endif
#define	PP_ISKPMS(pp)		((pp)->p_nrm & P_KPMS)
#define	PP_ISKPMC(pp)		((pp)->p_nrm & P_KPMC)

#define	PP_SETMOD(pp)		((pp)->p_nrm |= P_MOD)
#define	PP_SETREF(pp)		((pp)->p_nrm |= P_REF)
#define	PP_SETREFMOD(pp)	((pp)->p_nrm |= (P_REF|P_MOD))
#define	PP_SETRO(pp)		((pp)->p_nrm |= P_RO)
#define	PP_SETREFRO(pp)		((pp)->p_nrm |= (P_REF|P_RO))
#define	PP_SETPNC(pp)		((pp)->p_nrm |= P_PNC)
#ifdef VAC
#define	PP_SETTNC(pp)		((pp)->p_nrm |= P_TNC)
#endif
#define	PP_SETKPMS(pp)		((pp)->p_nrm |= P_KPMS)
#define	PP_SETKPMC(pp)		((pp)->p_nrm |= P_KPMC)

#define	PP_CLRMOD(pp)		((pp)->p_nrm &= ~P_MOD)
#define	PP_CLRREF(pp)		((pp)->p_nrm &= ~P_REF)
#define	PP_CLRREFMOD(pp)	((pp)->p_nrm &= ~(P_REF|P_MOD))
#define	PP_CLRRO(pp)		((pp)->p_nrm &= ~P_RO)
#define	PP_CLRPNC(pp)		((pp)->p_nrm &= ~P_PNC)
#ifdef VAC
#define	PP_CLRTNC(pp)		((pp)->p_nrm &= ~P_TNC)
#endif
#define	PP_CLRKPMS(pp)		((pp)->p_nrm &= ~P_KPMS)
#define	PP_CLRKPMC(pp)		((pp)->p_nrm &= ~P_KPMC)

/*
 * All shared memory segments attached with the SHM_SHARE_MMU flag (ISM)
 * will be constrained to a 4M, 32M or 256M alignment. Also since every newly-
 * created ISM segment is created out of a new address space at base va
 * of 0 we don't need to store it.
 */
#define	ISM_ALIGN(shift)	(1 << shift)	/* base va aligned to <n>M  */
#define	ISM_ALIGNED(shift, va)	(((uintptr_t)va & (ISM_ALIGN(shift) - 1)) == 0)
#define	ISM_SHIFT(shift, x)	((uintptr_t)x >> (shift))

/*
 * Pad locks out to cache sub-block boundaries to prevent
 * false sharing, so several processes don't contend for
 * the same line if they aren't using the same lock.  Since
 * this is a typedef we also have a bit of freedom in
 * changing lock implementations later if we decide it
 * is necessary.
 */
typedef struct hat_lock {
	kmutex_t hl_mutex;
	uchar_t hl_pad[64 - sizeof (kmutex_t)];
} hatlock_t;

#define	HATLOCK_MUTEXP(hatlockp)	(&((hatlockp)->hl_mutex))

/*
 * All segments mapped with ISM are guaranteed to be 4M, 32M or 256M aligned.
 * Also size is guaranteed to be in 4M, 32M or 256M chunks.
 * ism_seg consists of the following members:
 * [XX..22] base address of ism segment. XX is 63 or 31 depending whether
 *	caddr_t is 64 bits or 32 bits.
 * [21..0] size of segment.
 *
 * NOTE: Don't alter this structure without changing defines above and
 * the tsb_miss and protection handlers.
 */
typedef struct ism_map {
	uintptr_t	imap_seg;  	/* base va + sz of ISM segment */
	uchar_t		imap_vb_shift;	/* mmu_pageshift for ism page size */
	uchar_t		imap_rid;	/* region id for ism */
	ushort_t	imap_hatflags;	/* primary ism page size */
	uint_t		imap_sz_mask;	/* mmu_pagemask for ism page size */
	sfmmu_t		*imap_ismhat; 	/* hat id of dummy ISM as */
	struct ism_ment	*imap_ment;	/* pointer to mapping list entry */
} ism_map_t;

#define	ism_start(map)	((caddr_t)((map).imap_seg & \
				~ISM_SZ_MASK((map).imap_vb_shift)))
#define	ism_size(map)	((map).imap_seg & ISM_SZ_MASK((map).imap_vb_shift))
#define	ism_end(map)	((caddr_t)(ism_start(map) + (ism_size(map) * \
				ISM_PG_SIZE((map).imap_vb_shift))))
/*
 * ISM mapping entry. Used to link all hat's sharing a ism_hat.
 * Same function as the p_mapping list for a page.
 */
typedef struct ism_ment {
	sfmmu_t		*iment_hat;	/* back pointer to hat_share() hat */
	caddr_t		iment_base_va;	/* hat's va base for this ism seg */
	struct ism_ment	*iment_next;	/* next ism map entry */
	struct ism_ment	*iment_prev;	/* prev ism map entry */
} ism_ment_t;

/*
 * ISM segment block. One will be hung off the sfmmu structure if a
 * a process uses ISM.  More will be linked using ismblk_next if more
 * than ISM_MAP_SLOTS segments are attached to this proc.
 *
 * All modifications to fields in this structure will be protected
 * by the hat mutex.  In order to avoid grabbing this lock in low level
 * routines (tsb miss/protection handlers and vatopfn) while not
 * introducing any race conditions with hat_unshare, we will set
 * CTX_ISM_BUSY bit in the ctx struct. Any mmu traps that occur
 * for this ctx while this bit is set will be handled in sfmmu_tsb_excption
 * where it will synchronize behind the hat mutex.
 */
typedef struct ism_blk {
	ism_map_t		iblk_maps[ISM_MAP_SLOTS];
	struct ism_blk		*iblk_next;
	uint64_t		iblk_nextpa;
} ism_blk_t;

/*
 * TSB access information.  All fields are protected by the process's
 * hat lock.
 */

struct tsb_info {
	caddr_t		tsb_va;		/* tsb base virtual address */
	uint64_t	tsb_pa;		/* tsb base physical address */
	struct tsb_info	*tsb_next;	/* next tsb used by this process */
	uint16_t	tsb_szc;	/* tsb size code */
	uint16_t	tsb_flags;	/* flags for this tsb; see below */
	uint_t		tsb_ttesz_mask;	/* page size masks; see below */

	tte_t		tsb_tte;	/* tte to lock into DTLB */
	sfmmu_t		*tsb_sfmmu;	/* sfmmu */
	kmem_cache_t	*tsb_cache;	/* cache from which mem allocated */
	vmem_t		*tsb_vmp;	/* vmem arena from which mem alloc'd */
};

/*
 * Values for "tsb_ttesz_mask" bitmask.
 */
#define	TSB8K	(1 << TTE8K)
#define	TSB64K  (1 << TTE64K)
#define	TSB512K (1 << TTE512K)
#define	TSB4M   (1 << TTE4M)
#define	TSB32M  (1 << TTE32M)
#define	TSB256M (1 << TTE256M)

/*
 * Values for "tsb_flags" field.
 */
#define	TSB_RELOC_FLAG		0x1
#define	TSB_FLUSH_NEEDED	0x2
#define	TSB_SWAPPED	0x4
#define	TSB_SHAREDCTX		0x8

#endif	/* !_ASM */

/*
 * Data structures for shared hmeblk support.
 */

/*
 * Do not increase the maximum number of ism/hme regions without checking first
 * the impact on ism_map_t, TSB miss area, hblk tag and region id type in
 * sf_region structure.
 * Initially, shared hmes will only be used for the main text segment
 * therefore this value will be set to 64, it will be increased when shared
 * libraries are included.
 */

#define	SFMMU_MAX_HME_REGIONS		(64)
#define	SFMMU_HMERGNMAP_WORDS		BT_BITOUL(SFMMU_MAX_HME_REGIONS)

#define	SFMMU_PRIVATE	0
#define	SFMMU_SHARED	1

#define	HMEBLK_ENDPA	1

#ifndef _ASM

#define	SFMMU_MAX_ISM_REGIONS		(64)
#define	SFMMU_ISMRGNMAP_WORDS		BT_BITOUL(SFMMU_MAX_ISM_REGIONS)

#define	SFMMU_RGNMAP_WORDS	(SFMMU_HMERGNMAP_WORDS + SFMMU_ISMRGNMAP_WORDS)

#define	SFMMU_MAX_REGION_BUCKETS	(128)
#define	SFMMU_MAX_SRD_BUCKETS		(2048)

typedef struct sf_hmeregion_map {
	ulong_t	bitmap[SFMMU_HMERGNMAP_WORDS];
} sf_hmeregion_map_t;

typedef struct sf_ismregion_map {
	ulong_t	bitmap[SFMMU_ISMRGNMAP_WORDS];
} sf_ismregion_map_t;

typedef union sf_region_map_u {
	struct _h_rmap_s {
		sf_hmeregion_map_t hmeregion_map;
		sf_ismregion_map_t ismregion_map;
	} h_rmap_s;
	ulong_t	bitmap[SFMMU_RGNMAP_WORDS];
} sf_region_map_t;

#define	SF_RGNMAP_ZERO(map) {				\
	int _i;						\
	for (_i = 0; _i < SFMMU_RGNMAP_WORDS; _i++) {	\
		(map).bitmap[_i] = 0;			\
	}						\
}

/*
 * Returns 1 if map1 and map2 are equal.
 */
#define	SF_RGNMAP_EQUAL(map1, map2, rval)	{		\
	int _i;							\
	for (_i = 0; _i < SFMMU_RGNMAP_WORDS; _i++) {		\
		if ((map1)->bitmap[_i] != (map2)->bitmap[_i])	\
			break;					\
	}							\
	if (_i < SFMMU_RGNMAP_WORDS)				\
		rval = 0;					\
	else							\
		rval = 1;					\
}

#define	SF_RGNMAP_ADD(map, r)		BT_SET((map).bitmap, r)
#define	SF_RGNMAP_DEL(map, r)		BT_CLEAR((map).bitmap, r)
#define	SF_RGNMAP_TEST(map, r)		BT_TEST((map).bitmap, r)

/*
 * Tests whether map2 is a subset of map1, returns 1 if
 * this assertion is true.
 */
#define	SF_RGNMAP_IS_SUBSET(map1, map2, rval)	{		\
	int _i;							\
	for (_i = 0; _i < SFMMU_RGNMAP_WORDS; _i++) {		\
		if (((map1)->bitmap[_i]	& (map2)->bitmap[_i])	\
		    != (map2)->bitmap[_i])  {	 		\
			break;					\
		}						\
	}							\
	if (_i < SFMMU_RGNMAP_WORDS)		 		\
		rval = 0;					\
	else							\
		rval = 1;					\
}

#define	SF_SCD_INCR_REF(scdp) {						\
	atomic_inc_32((volatile uint32_t *)&(scdp)->scd_refcnt);	\
}

#define	SF_SCD_DECR_REF(srdp, scdp) {				\
	sf_region_map_t _scd_rmap = (scdp)->scd_region_map;	\
	if (!atomic_dec_32_nv((volatile uint32_t *)&(scdp)->scd_refcnt)) {\
		sfmmu_destroy_scd((srdp), (scdp), &_scd_rmap);	\
	}							\
}

/*
 * A sfmmup link in the link list of sfmmups that share the same region.
 */
typedef struct sf_rgn_link {
	sfmmu_t	*next;
	sfmmu_t *prev;
} sf_rgn_link_t;

/*
 * rgn_flags values.
 */
#define	SFMMU_REGION_HME	0x1
#define	SFMMU_REGION_ISM	0x2
#define	SFMMU_REGION_FREE	0x8

#define	SFMMU_REGION_TYPE_MASK	(0x3)

/*
 * sf_region defines a text or (D)ISM segment which map
 * the same underlying physical object.
 */
typedef struct sf_region {
	caddr_t			rgn_saddr;   /* base addr of attached seg */
	size_t			rgn_size;    /* size of attached seg */
	void			*rgn_obj;    /* the underlying object id */
	u_offset_t		rgn_objoff;  /* offset in the object mapped */
	uchar_t			rgn_perm;    /* PROT_READ/WRITE/EXEC */
	uchar_t			rgn_pgszc;   /* page size of the region */
	uchar_t			rgn_flags;   /* region type, free flag */
	uchar_t			rgn_id;
	int			rgn_refcnt;  /* # of hats sharing the region */
	/* callback function for hat_unload_callback */
	hat_rgn_cb_func_t	rgn_cb_function;
	struct sf_region	*rgn_hash;   /* hash chain linking the rgns */
	kmutex_t		rgn_mutex;   /* protect region sfmmu list */
	/* A link list of processes attached to this region */
	sfmmu_t			*rgn_sfmmu_head;
	ulong_t			rgn_ttecnt[MMU_PAGE_SIZES];
	uint16_t		rgn_hmeflags; /* rgn tte size flags */
} sf_region_t;

#define	rgn_next	rgn_hash

/* srd */
typedef struct sf_shared_region_domain {
	vnode_t			*srd_evp;	/* executable vnode */
	/* hme region table */
	sf_region_t		*srd_hmergnp[SFMMU_MAX_HME_REGIONS];
	/* ism region table */
	sf_region_t		*srd_ismrgnp[SFMMU_MAX_ISM_REGIONS];
	/* hash chain linking srds */
	struct sf_shared_region_domain *srd_hash;
	/* pointer to the next free hme region */
	sf_region_t		*srd_hmergnfree;
	/* pointer to the next free ism region */
	sf_region_t		*srd_ismrgnfree;
	/* id of next ism region created */
	uint16_t		srd_next_ismrid;
	/* id of next hme region created */
	uint16_t		srd_next_hmerid;
	uint16_t		srd_ismbusyrgns; /* # of ism rgns in use */
	uint16_t		srd_hmebusyrgns; /* # of hme rgns in use */
	int			srd_refcnt;	 /* # of procs in the srd */
	kmutex_t		srd_mutex;	 /* sync add/remove rgns */
	kmutex_t		srd_scd_mutex;
	sf_scd_t		*srd_scdp;	 /* list of scds in srd */
	/* hash of regions associated with the same executable */
	sf_region_t		*srd_rgnhash[SFMMU_MAX_REGION_BUCKETS];
} sf_srd_t;

typedef struct sf_srd_bucket {
	kmutex_t	srdb_lock;
	sf_srd_t	*srdb_srdp;
} sf_srd_bucket_t;

/*
 * The value of SFMMU_L1_HMERLINKS and SFMMU_L2_HMERLINKS will be increased
 * to 16 when the use of shared hmes for shared libraries is enabled.
 */

#define	SFMMU_L1_HMERLINKS		(8)
#define	SFMMU_L2_HMERLINKS		(8)
#define	SFMMU_L1_HMERLINKS_SHIFT	(3)
#define	SFMMU_L1_HMERLINKS_MASK		(SFMMU_L1_HMERLINKS - 1)
#define	SFMMU_L2_HMERLINKS_MASK		(SFMMU_L2_HMERLINKS - 1)
#define	SFMMU_L1_HMERLINKS_SIZE		\
	(SFMMU_L1_HMERLINKS * sizeof (sf_rgn_link_t *))
#define	SFMMU_L2_HMERLINKS_SIZE		\
	(SFMMU_L2_HMERLINKS * sizeof (sf_rgn_link_t))

#if (SFMMU_L1_HMERLINKS * SFMMU_L2_HMERLINKS < SFMMU_MAX_HME_REGIONS)
#error Not Enough HMERLINKS
#endif

/*
 * This macro grabs hat lock and allocates level 2 hat chain
 * associated with a shme rgn. In the majority of cases, the macro
 * is called with alloc = 0, and lock = 0.
 * A pointer to the level 2 sf_rgn_link_t structure is returned in the lnkp
 * parameter.
 */
#define	SFMMU_HMERID2RLINKP(sfmmup, rid, lnkp, alloc, lock)		\
{									\
	int _l1ix = ((rid) >> SFMMU_L1_HMERLINKS_SHIFT) &		\
	    SFMMU_L1_HMERLINKS_MASK;					\
	int _l2ix = ((rid) & SFMMU_L2_HMERLINKS_MASK);			\
	hatlock_t *_hatlockp;						\
	lnkp = (sfmmup)->sfmmu_hmeregion_links[_l1ix];			\
	if (lnkp != NULL) {						\
		lnkp = &lnkp[_l2ix];					\
	} else if (alloc && lock) {					\
		lnkp = kmem_zalloc(SFMMU_L2_HMERLINKS_SIZE, KM_SLEEP);	\
		_hatlockp = sfmmu_hat_enter(sfmmup);			\
		if ((sfmmup)->sfmmu_hmeregion_links[_l1ix] != NULL) {	\
			sfmmu_hat_exit(_hatlockp);			\
			kmem_free(lnkp, SFMMU_L2_HMERLINKS_SIZE);	\
			lnkp = (sfmmup)->sfmmu_hmeregion_links[_l1ix];	\
			ASSERT(lnkp != NULL);				\
		} else {						\
			(sfmmup)->sfmmu_hmeregion_links[_l1ix] = lnkp;	\
			sfmmu_hat_exit(_hatlockp);			\
		}							\
		lnkp = &lnkp[_l2ix];					\
	} else if (alloc) {						\
		lnkp = kmem_zalloc(SFMMU_L2_HMERLINKS_SIZE, KM_SLEEP);	\
		ASSERT((sfmmup)->sfmmu_hmeregion_links[_l1ix] == NULL);	\
		(sfmmup)->sfmmu_hmeregion_links[_l1ix] = lnkp;		\
		lnkp = &lnkp[_l2ix];					\
	}								\
}

/*
 *  Per cpu pending freelist of hmeblks.
 */
typedef struct cpu_hme_pend {
	struct   hme_blk *chp_listp;
	kmutex_t chp_mutex;
	time_t	 chp_timestamp;
	uint_t   chp_count;
	uint8_t	 chp_pad[36];		/* pad to 64 bytes */
} cpu_hme_pend_t;

/*
 * The default value of the threshold for the per cpu pending queues of hmeblks.
 * The queues are flushed if either the number of hmeblks on the queue is above
 * the threshold, or one second has elapsed since the last flush.
 */
#define	CPU_HME_PEND_THRESH 1000

/*
 * Per-MMU context domain kstats.
 *
 * TSB Miss Exceptions
 *	Number of times a TSB miss exception is handled in an MMU. See
 *	sfmmu_tsbmiss_exception() for more details.
 * TSB Raise Exception
 *	Number of times the CPUs within an MMU are cross-called
 *	to invalidate either a specific process context (when the process
 *	switches MMU contexts) or the context of any process that is
 *	running on those CPUs (as part of the MMU context wrap-around).
 * Wrap Around
 *	The number of times a wrap-around of MMU context happens.
 */
typedef enum mmu_ctx_stat_types {
	MMU_CTX_TSB_EXCEPTIONS,		/* TSB miss exceptions handled */
	MMU_CTX_TSB_RAISE_EXCEPTION,	/* ctx invalidation cross calls */
	MMU_CTX_WRAP_AROUND,		/* wraparounds */
	MMU_CTX_NUM_STATS
} mmu_ctx_stat_t;

/*
 * Per-MMU context domain structure. This is instantiated the first time a CPU
 * belonging to the MMU context domain is configured into the system, at boot
 * time or at DR time.
 *
 * mmu_gnum
 *	The current generation number for the context IDs on this MMU context
 *	domain. It is protected by mmu_lock.
 * mmu_cnum
 *	The current cnum to be allocated on this MMU context domain. It
 *	is protected via CAS.
 * mmu_nctxs
 *	The max number of context IDs supported on every CPU in this
 *	MMU context domain. This is needed here in case the system supports
 *      mixed type of processors/MMUs. It also helps to make ctx switch code
 *      access fewer cache lines i.e. no need to retrieve it from some global
 *      nctxs.
 * mmu_lock
 *	The mutex spin lock used to serialize context ID wrap around
 * mmu_idx
 *	The index for this MMU context domain structure in the global array
 *	mmu_ctxdoms.
 * mmu_ncpus
 *	The actual number of CPUs that have been configured in this
 *	MMU context domain. This also acts as a reference count for the
 *	structure. When the last CPU in an MMU context domain is unconfigured,
 *	the structure is freed. It is protected by mmu_lock.
 * mmu_cpuset
 *	The CPU set of configured CPUs for this MMU context domain. Used
 *	to cross-call all the CPUs in the MMU context domain to invalidate
 *	context IDs during a wraparound operation. It is protected by mmu_lock.
 */

typedef struct mmu_ctx {
	uint64_t	mmu_gnum;
	uint_t		mmu_cnum;
	uint_t		mmu_nctxs;
	kmutex_t	mmu_lock;
	uint_t		mmu_idx;
	uint_t		mmu_ncpus;
	cpuset_t	mmu_cpuset;
	kstat_t		*mmu_kstat;
	kstat_named_t	mmu_kstat_data[MMU_CTX_NUM_STATS];
} mmu_ctx_t;

#define	mmu_tsb_exceptions	\
		mmu_kstat_data[MMU_CTX_TSB_EXCEPTIONS].value.ui64
#define	mmu_tsb_raise_exception	\
		mmu_kstat_data[MMU_CTX_TSB_RAISE_EXCEPTION].value.ui64
#define	mmu_wrap_around		\
		mmu_kstat_data[MMU_CTX_WRAP_AROUND].value.ui64

extern uint_t		max_mmu_ctxdoms;
extern mmu_ctx_t	**mmu_ctxs_tbl;

extern void	sfmmu_cpu_init(cpu_t *);
extern void	sfmmu_cpu_cleanup(cpu_t *);

extern uint_t	sfmmu_ctxdom_nctxs(int);

#ifdef sun4v
extern void	sfmmu_ctxdoms_remove(void);
extern void	sfmmu_ctxdoms_lock(void);
extern void	sfmmu_ctxdoms_unlock(void);
extern void	sfmmu_ctxdoms_update(void);
#endif

/*
 * The following structure is used to get MMU context domain information for
 * a CPU from the platform.
 *
 * mmu_idx
 *	The MMU context domain index within the global array mmu_ctxs
 * mmu_nctxs
 *	The number of context IDs supported in the MMU context domain
 */
typedef struct mmu_ctx_info {
	uint_t		mmu_idx;
	uint_t		mmu_nctxs;
} mmu_ctx_info_t;

#pragma weak plat_cpuid_to_mmu_ctx_info

extern void	plat_cpuid_to_mmu_ctx_info(processorid_t, mmu_ctx_info_t *);

/*
 * Each address space has an array of sfmmu_ctx_t structures, one structure
 * per MMU context domain.
 *
 * cnum
 *	The context ID allocated for an address space on an MMU context domain
 * gnum
 *	The generation number for the context ID in the MMU context domain.
 *
 * This structure needs to be a power-of-two in size.
 */
typedef struct sfmmu_ctx {
	uint64_t	gnum:48;
	uint64_t	cnum:16;
} sfmmu_ctx_t;


/*
 * The platform dependent hat structure.
 * tte counts should be protected by cas.
 * cpuset is protected by cas.
 *
 * ttecnt accounting for mappings which do not use shared hme is carried out
 * during pagefault handling. In the shared hme case, only the first process
 * to access a mapping generates a pagefault, subsequent processes simply
 * find the shared hme entry during trap handling and therefore there is no
 * corresponding event to initiate ttecnt accounting. Currently, as shared
 * hmes are only used for text segments, when joining a region we assume the
 * worst case and add the the number of ttes required to map the entire region
 * to the ttecnt corresponding to the region pagesize. However, if the region
 * has a 4M pagesize, and memory is low, the allocation of 4M pages may fail
 * then 8K pages will be allocated instead and the first TSB which stores 8K
 * mappings will potentially be undersized. To compensate for the potential
 * underaccounting in this case we always add 1/4 of the region size to the 8K
 * ttecnt.
 *
 * Note that sfmmu_xhat_provider MUST be the first element.
 */

struct hat {
	void		*sfmmu_xhat_provider;	/* NULL for CPU hat */
	cpuset_t	sfmmu_cpusran;	/* cpu bit mask for efficient xcalls */
	struct	as	*sfmmu_as;	/* as this hat provides mapping for */
	/* per pgsz private ttecnt + shme rgns ttecnt for rgns not in SCD */
	ulong_t		sfmmu_ttecnt[MMU_PAGE_SIZES];
	/* shme rgns ttecnt for rgns in SCD */
	ulong_t		sfmmu_scdrttecnt[MMU_PAGE_SIZES];
	/* est. ism ttes that are NOT in a SCD */
	ulong_t		sfmmu_ismttecnt[MMU_PAGE_SIZES];
	/* ttecnt for isms that are in a SCD */
	ulong_t		sfmmu_scdismttecnt[MMU_PAGE_SIZES];
	/* inflate tsb0 to allow for large page alloc failure in region */
	ulong_t		sfmmu_tsb0_4minflcnt;
	union _h_un {
		ism_blk_t	*sfmmu_iblkp;  /* maps to ismhat(s) */
		ism_ment_t	*sfmmu_imentp; /* ism hat's mapping list */
	} h_un;
	uint_t		sfmmu_free:1;	/* hat to be freed - set on as_free */
	uint_t		sfmmu_ismhat:1;	/* hat is dummy ism hatid */
	uint_t		sfmmu_scdhat:1;	/* hat is dummy scd hatid */
	uchar_t		sfmmu_rmstat;	/* refmod stats refcnt */
	ushort_t	sfmmu_clrstart;	/* start color bin for page coloring */
	ushort_t	sfmmu_clrbin;	/* per as phys page coloring bin */
	ushort_t	sfmmu_flags;	/* flags */
	uchar_t		sfmmu_tteflags;	/* pgsz flags */
	uchar_t		sfmmu_rtteflags; /* pgsz flags for SRD hmes */
	struct tsb_info	*sfmmu_tsb;	/* list of per as tsbs */
	uint64_t	sfmmu_ismblkpa; /* pa of sfmmu_iblkp, or -1 */
	lock_t		sfmmu_ctx_lock;	/* sync ctx alloc and invalidation */
	kcondvar_t	sfmmu_tsb_cv;	/* signals TSB swapin or relocation */
	uchar_t		sfmmu_cext;	/* context page size encoding */
	uint8_t		sfmmu_pgsz[MMU_PAGE_SIZES];  /* ranking for MMU */
	sf_srd_t	*sfmmu_srdp;
	sf_scd_t	*sfmmu_scdp;	/* scd this address space belongs to */
	sf_region_map_t	sfmmu_region_map;
	sf_rgn_link_t	*sfmmu_hmeregion_links[SFMMU_L1_HMERLINKS];
	sf_rgn_link_t	sfmmu_scd_link;	/* link to scd or pending queue */
#ifdef sun4v
	struct hv_tsb_block sfmmu_hvblock;
#endif
	/*
	 * sfmmu_ctxs is a variable length array of max_mmu_ctxdoms # of
	 * elements. max_mmu_ctxdoms is determined at run-time.
	 * sfmmu_ctxs[1] is just the fist element of an array, it always
	 * has to be the last field to ensure that the memory allocated
	 * for sfmmu_ctxs is consecutive with the memory of the rest of
	 * the hat data structure.
	 */
	sfmmu_ctx_t	sfmmu_ctxs[1];

};

#define	sfmmu_iblk	h_un.sfmmu_iblkp
#define	sfmmu_iment	h_un.sfmmu_imentp

#define	sfmmu_hmeregion_map	sfmmu_region_map.h_rmap_s.hmeregion_map
#define	sfmmu_ismregion_map	sfmmu_region_map.h_rmap_s.ismregion_map

#define	SF_RGNMAP_ISNULL(sfmmup)	\
	(sfrgnmap_isnull(&(sfmmup)->sfmmu_region_map))
#define	SF_HMERGNMAP_ISNULL(sfmmup)	\
	(sfhmergnmap_isnull(&(sfmmup)->sfmmu_hmeregion_map))

struct sf_scd {
	sfmmu_t		*scd_sfmmup;	/* shared context hat */
	/* per pgsz ttecnt for shme rgns in SCD */
	ulong_t		scd_rttecnt[MMU_PAGE_SIZES];
	uint_t		scd_refcnt;	/* address spaces attached to scd */
	sf_region_map_t scd_region_map; /* bit mask of attached segments */
	sf_scd_t	*scd_next;	/* link pointers for srd_scd list */
	sf_scd_t	*scd_prev;
	sfmmu_t 	*scd_sf_list;	/* list of doubly linked hat structs */
	kmutex_t 	scd_mutex;
	/*
	 * Link used to add an scd to the sfmmu_iment list.
	 */
	ism_ment_t	scd_ism_links[SFMMU_MAX_ISM_REGIONS];
};

#define	scd_hmeregion_map	scd_region_map.h_rmap_s.hmeregion_map
#define	scd_ismregion_map	scd_region_map.h_rmap_s.ismregion_map

extern int disable_shctx;
extern int shctx_on;

/*
 * bit mask for managing vac conflicts on large pages.
 * bit 1 is for uncache flag.
 * bits 2 through min(num of cache colors + 1,31) are
 * for cache colors that have already been flushed.
 */
#ifdef VAC
#define	CACHE_NUM_COLOR		(shm_alignment >> MMU_PAGESHIFT)
#else
#define	CACHE_NUM_COLOR		1
#endif

#define	CACHE_VCOLOR_MASK(vcolor)	(2 << (vcolor & (CACHE_NUM_COLOR - 1)))

#define	CacheColor_IsFlushed(flag, vcolor) \
					((flag) & CACHE_VCOLOR_MASK(vcolor))

#define	CacheColor_SetFlushed(flag, vcolor) \
					((flag) |= CACHE_VCOLOR_MASK(vcolor))
/*
 * Flags passed to sfmmu_page_cache to flush page from vac or not.
 */
#define	CACHE_FLUSH	0
#define	CACHE_NO_FLUSH	1

/*
 * Flags passed to sfmmu_tlbcache_demap
 */
#define	FLUSH_NECESSARY_CPUS	0
#define	FLUSH_ALL_CPUS		1

#ifdef	DEBUG
/*
 * For debugging purpose only. Maybe removed later.
 */
struct ctx_trace {
	sfmmu_t		*sc_sfmmu_stolen;
	sfmmu_t		*sc_sfmmu_stealing;
	clock_t		sc_time;
	ushort_t	sc_type;
	ushort_t	sc_cnum;
};
#define	CTX_TRC_STEAL	0x1
#define	CTX_TRC_FREE	0x0
#define	TRSIZE	0x400
#define	NEXT_CTXTR(ptr)	(((ptr) >= ctx_trace_last) ? \
		ctx_trace_first : ((ptr) + 1))
#define	TRACE_CTXS(mutex, ptr, cnum, stolen_sfmmu, stealing_sfmmu, type) \
	mutex_enter(mutex);						\
	(ptr)->sc_sfmmu_stolen = (stolen_sfmmu);			\
	(ptr)->sc_sfmmu_stealing = (stealing_sfmmu);			\
	(ptr)->sc_cnum = (cnum);					\
	(ptr)->sc_type = (type);					\
	(ptr)->sc_time = ddi_get_lbolt();				\
	(ptr) = NEXT_CTXTR(ptr);					\
	num_ctx_stolen += (type);					\
	mutex_exit(mutex);
#else

#define	TRACE_CTXS(mutex, ptr, cnum, stolen_sfmmu, stealing_sfmmu, type)

#endif	/* DEBUG */

#endif	/* !_ASM */

/*
 * Macros for sfmmup->sfmmu_flags access.  The macros that change the flags
 * ASSERT() that we're holding the HAT lock before changing the flags;
 * however callers that read the flags may do so without acquiring the lock
 * in a fast path, and then recheck the flag after acquiring the lock in
 * a slow path.
 */
#define	SFMMU_FLAGS_ISSET(sfmmup, flags) \
	(((sfmmup)->sfmmu_flags & (flags)) == (flags))

#define	SFMMU_FLAGS_CLEAR(sfmmup, flags) \
	(ASSERT(sfmmu_hat_lock_held((sfmmup))), \
	(sfmmup)->sfmmu_flags &= ~(flags))

#define	SFMMU_FLAGS_SET(sfmmup, flags) \
	(ASSERT(sfmmu_hat_lock_held((sfmmup))), \
	(sfmmup)->sfmmu_flags |= (flags))

#define	SFMMU_TTEFLAGS_ISSET(sfmmup, flags) \
	((((sfmmup)->sfmmu_tteflags | (sfmmup)->sfmmu_rtteflags) & (flags)) == \
	    (flags))


/*
 * sfmmu tte HAT flags, must fit in 8 bits
 */
#define	HAT_CHKCTX1_FLAG 0x1
#define	HAT_64K_FLAG	(0x1 << TTE64K)
#define	HAT_512K_FLAG	(0x1 << TTE512K)
#define	HAT_4M_FLAG	(0x1 << TTE4M)
#define	HAT_32M_FLAG	(0x1 << TTE32M)
#define	HAT_256M_FLAG	(0x1 << TTE256M)

/*
 * sfmmu HAT flags, 16 bits at the moment.
 */
#define	HAT_4MTEXT_FLAG		0x01
#define	HAT_32M_ISM		0x02
#define	HAT_256M_ISM		0x04
#define	HAT_SWAPPED		0x08 /* swapped out */
#define	HAT_SWAPIN		0x10 /* swapping in */
#define	HAT_BUSY		0x20 /* replacing TSB(s) */
#define	HAT_ISMBUSY		0x40 /* adding/removing/traversing ISM maps */

#define	HAT_CTX1_FLAG   	0x100 /* ISM imap hatflag for ctx1 */
#define	HAT_JOIN_SCD		0x200 /* region is joining scd */
#define	HAT_ALLCTX_INVALID	0x400 /* all per-MMU ctxs are invalidated */

#define	SFMMU_LGPGS_INUSE(sfmmup)					\
	(((sfmmup)->sfmmu_tteflags | (sfmmup)->sfmmu_rtteflags) ||	\
	    ((sfmmup)->sfmmu_iblk != NULL))

/*
 * Starting with context 0, the first NUM_LOCKED_CTXS contexts
 * are locked so that sfmmu_getctx can't steal any of these
 * contexts.  At the time this software was being developed, the
 * only context that needs to be locked is context 0 (the kernel
 * context), and context 1 (reserved for stolen context). So this constant
 * was originally defined to be 2.
 *
 * For sun4v only, USER_CONTEXT_TYPE represents any user context.  Many
 * routines only care whether the context is kernel, invalid or user.
 */

#define	NUM_LOCKED_CTXS 2
#define	INVALID_CONTEXT	1

#ifdef sun4v
#define	USER_CONTEXT_TYPE	NUM_LOCKED_CTXS
#endif
#if defined(sun4v) || defined(UTSB_PHYS)
/*
 * Get the location in the 4MB base TSB of the tsbe for this fault.
 * Assumes that the second TSB only contains 4M mappings.
 *
 * In:
 *   tagacc = tag access register (not clobbered)
 *   tsbe = 2nd TSB base register
 *   tmp1, tmp2 = scratch registers
 * Out:
 *   tsbe = pointer to the tsbe in the 2nd TSB
 */

#define	GET_4MBASE_TSBE_PTR(tagacc, tsbe, tmp1, tmp2)			\
	and	tsbe, TSB_SOFTSZ_MASK, tmp2;	/* tmp2=szc */		\
	andn	tsbe, TSB_SOFTSZ_MASK, tsbe;	/* tsbbase */		\
	mov	TSB_ENTRIES(0), tmp1;	/* nentries in TSB size 0 */	\
	sllx	tmp1, tmp2, tmp1;	/* tmp1 = nentries in TSB */	\
	sub	tmp1, 1, tmp1;		/* mask = nentries - 1 */	\
	srlx	tagacc, MMU_PAGESHIFT4M, tmp2; 				\
	and	tmp2, tmp1, tmp1;	/* tsbent = virtpage & mask */	\
	sllx	tmp1, TSB_ENTRY_SHIFT, tmp1;	/* entry num --> ptr */	\
	add	tsbe, tmp1, tsbe	/* add entry offset to TSB base */

#define	GET_2ND_TSBE_PTR(tagacc, tsbe, tmp1, tmp2)			\
	GET_4MBASE_TSBE_PTR(tagacc, tsbe, tmp1, tmp2)

/*
 * Get the location in the 3rd TSB of the tsbe for this fault.
 * The 3rd TSB corresponds to the shared context, and is used
 * for 8K - 512k pages.
 *
 * In:
 *   tagacc = tag access register (not clobbered)
 *   tsbe, tmp1, tmp2 = scratch registers
 * Out:
 *   tsbe = pointer to the tsbe in the 3rd TSB
 */

#define	GET_3RD_TSBE_PTR(tagacc, tsbe, tmp1, tmp2)			\
	and	tsbe, TSB_SOFTSZ_MASK, tmp2;    /* tmp2=szc */		\
	andn	tsbe, TSB_SOFTSZ_MASK, tsbe;    /* tsbbase */		\
	mov	TSB_ENTRIES(0), tmp1;	/* nentries in TSB size 0 */	\
	sllx	tmp1, tmp2, tmp1;	/* tmp1 = nentries in TSB */	\
	sub	tmp1, 1, tmp1;		/* mask = nentries - 1 */	\
	srlx	tagacc, MMU_PAGESHIFT, tmp2;				\
	and	tmp2, tmp1, tmp1;	/* tsbent = virtpage & mask */	\
	sllx	tmp1, TSB_ENTRY_SHIFT, tmp1;    /* entry num --> ptr */	\
	add	tsbe, tmp1, tsbe	/* add entry offset to TSB base */

#define	GET_4TH_TSBE_PTR(tagacc, tsbe, tmp1, tmp2)                      \
	GET_4MBASE_TSBE_PTR(tagacc, tsbe, tmp1, tmp2)
/*
 * Copy the sfmmu_region_map or scd_region_map to the tsbmiss
 * shmermap or scd_shmermap, from sfmmu_load_mmustate.
 */
#define	SET_REGION_MAP(rgn_map, tsbmiss_map, cnt, tmp, label)		\
	/* BEGIN CSTYLED */						\
label:									;\
        ldx     [rgn_map], tmp						;\
        dec     cnt							;\
        add     rgn_map, CLONGSIZE, rgn_map                             ;\
        stx     tmp, [tsbmiss_map]                                      ;\
        brnz,pt cnt, label                                              ;\
	    add   tsbmiss_map, CLONGSIZE, tsbmiss_map                    \
	/* END CSTYLED */

/*
 * If there is no scd, then zero the tsbmiss scd_shmermap,
 * from sfmmu_load_mmustate.
 */
#define	ZERO_REGION_MAP(tsbmiss_map, cnt, label)                        \
	/* BEGIN CSTYLED */                                             \
label:                                                                  ;\
        dec     cnt                                                     ;\
        stx     %g0, [tsbmiss_map]                                      ;\
        brnz,pt cnt, label                                              ;\
	    add   tsbmiss_map, CLONGSIZE, tsbmiss_map                    
	/* END CSTYLED */

/*
 * Set hmemisc to 1 if the shared hme is also part of an scd.
 * In:
 *   tsbarea = tsbmiss area (not clobbered)
 *   hmeblkpa  = hmeblkpa +  hmentoff + SFHME_TTE (not clobbered)
 *   hmentoff = hmentoff + SFHME_TTE = tte offset(clobbered)
 * Out:
 *   use_shctx = 1 if shme is in scd and 0 otherwise
 */
#define	GET_SCDSHMERMAP(tsbarea, hmeblkpa, hmentoff, use_shctx)               \
	/* BEGIN CSTYLED */   	                                              \
        sub     hmeblkpa, hmentoff, hmentoff    /* hmentofff = hmeblkpa */   ;\
        add     hmentoff, HMEBLK_TAG, hmentoff                               ;\
        ldxa    [hmentoff]ASI_MEM, hmentoff     /* read 1st part of tag */   ;\
        and     hmentoff, HTAG_RID_MASK, hmentoff       /* mask off rid */   ;\
        and     hmentoff, BT_ULMASK, use_shctx  /* mask bit index */         ;\
        srlx    hmentoff, BT_ULSHIFT, hmentoff  /* extract word */           ;\
        sllx    hmentoff, CLONGSHIFT, hmentoff  /* index */                  ;\
        add     tsbarea, hmentoff, hmentoff             /* add to tsbarea */ ;\
        ldx     [hmentoff + TSBMISS_SCDSHMERMAP], hmentoff      /* scdrgn */ ;\
        srlx    hmentoff, use_shctx, use_shctx                               ;\
        and     use_shctx, 0x1, use_shctx                                     \
	/* END CSTYLED */

/*
 * Synthesize a TSB base register contents for a process.
 *
 * In:
 *   tsbinfo = TSB info pointer (ro)
 *   tsbreg, tmp1 = scratch registers
 * Out:
 *   tsbreg = value to program into TSB base register
 */

#define	MAKE_UTSBREG(tsbinfo, tsbreg, tmp1)			\
	ldx	[tsbinfo + TSBINFO_PADDR], tsbreg;		\
	lduh	[tsbinfo + TSBINFO_SZCODE], tmp1;		\
	and	tmp1, TSB_SOFTSZ_MASK, tmp1;			\
	or	tsbreg, tmp1, tsbreg;


/*
 * Load TSB base register to TSBMISS area for privte contexts.
 * This register contains utsb_pabase in bits 63:13, and TSB size
 * code in bits 2:0.
 *
 * For private context
 * In:
 *   tsbreg = value to load (ro)
 *   regnum = constant or register
 *   tmp1 = scratch register
 * Out:
 *   Specified scratchpad register updated
 *
 */
#define	SET_UTSBREG(regnum, tsbreg, tmp1)				\
	mov	regnum, tmp1;						\
	stxa	tsbreg, [tmp1]ASI_SCRATCHPAD	/* save tsbreg */
/*
 * Get TSB base register from the scratchpad for private contexts
 *
 * In:
 *   regnum = constant or register
 *   tsbreg = scratch
 * Out:
 *   tsbreg = tsbreg from the specified scratchpad register
 */
#define	GET_UTSBREG(regnum, tsbreg)					\
	mov	regnum, tsbreg;						\
	ldxa	[tsbreg]ASI_SCRATCHPAD, tsbreg

/*
 * Load TSB base register to TSBMISS area for shared contexts.
 * This register contains utsb_pabase in bits 63:13, and TSB size
 * code in bits 2:0.
 *
 * In:
 *   tsbmiss = pointer to tsbmiss area
 *   tsbmissoffset = offset to right tsb pointer
 *   tsbreg = value to load (ro)
 * Out:
 *   Specified tsbmiss area updated
 *
 */
#define	SET_UTSBREG_SHCTX(tsbmiss, tsbmissoffset, tsbreg)		\
	stx	tsbreg, [tsbmiss + tsbmissoffset]	/* save tsbreg */

/*
 * Get TSB base register from the scratchpad for
 * shared contexts
 *
 * In:
 *   tsbmiss = pointer to tsbmiss area
 *   tsbmissoffset = offset to right tsb pointer
 *   tsbreg = scratch
 * Out:
 *   tsbreg = tsbreg from the specified scratchpad register
 */
#define	GET_UTSBREG_SHCTX(tsbmiss, tsbmissoffset, tsbreg)		\
	ldx	[tsbmiss + tsbmissoffset], tsbreg

#endif /* defined(sun4v) || defined(UTSB_PHYS) */

#ifndef	_ASM

/*
 * Kernel page relocation stuff.
 */
struct sfmmu_callback {
	int key;
	int (*prehandler)(caddr_t, uint_t, uint_t, void *);
	int (*posthandler)(caddr_t, uint_t, uint_t, void *, pfn_t);
	int (*errhandler)(caddr_t, uint_t, uint_t, void *);
	int capture_cpus;
};

extern int sfmmu_max_cb_id;
extern struct sfmmu_callback *sfmmu_cb_table;

struct pa_hment;

/*
 * RFE: With multihat gone we gain back an int.  We could use this to
 * keep ref bits on a per cpu basis to eliminate xcalls.
 */
struct sf_hment {
	tte_t hme_tte;			/* tte for this hment */

	union {
		struct page *page;	/* what page this maps */
		struct pa_hment *data;	/* pa_hment */
	} sf_hment_un;

	struct	sf_hment *hme_next;	/* next hment */
	struct	sf_hment *hme_prev;	/* prev hment */
};

struct pa_hment {
	caddr_t		addr;		/* va */
	uint_t		len;		/* bytes */
	ushort_t	flags;		/* internal flags */
	ushort_t	refcnt;		/* reference count */
	id_t		cb_id;		/* callback id, table index */
	void		*pvt;		/* handler's private data */
	struct sf_hment	sfment;		/* corresponding dummy sf_hment */
};

#define	hme_page		sf_hment_un.page
#define	hme_data		sf_hment_un.data
#define	hme_size(sfhmep)	((int)(TTE_CSZ(&(sfhmep)->hme_tte)))
#define	PAHME_SZ		(sizeof (struct pa_hment))
#define	SFHME_SZ		(sizeof (struct sf_hment))

#define	IS_PAHME(hme)	((hme)->hme_tte.ll == 0)

/*
 * hmeblk_tag structure
 * structure used to obtain a match on a hme_blk.  Currently consists of
 * the address of the sfmmu struct (or hatid), the base page address of the
 * hme_blk, and the rehash count.  The rehash count is actually only 2 bits
 * and has the following meaning:
 * 1 = 8k or 64k hash sequence.
 * 2 = 512k hash sequence.
 * 3 = 4M hash sequence.
 * We require this count because we don't want to get a false hit on a 512K or
 * 4M rehash with a base address corresponding to a 8k or 64k hmeblk.
 * Note:  The ordering and size of the hmeblk_tag members are implictly known
 * by the tsb miss handlers written in assembly.  Do not change this structure
 * without checking those routines.  See HTAG_SFMMUPSZ define.
 */

/*
 * In private hmeblks hblk_rid field must be SFMMU_INVALID_RID.
 */
typedef union {
	struct {
		uint64_t	hblk_basepg: 51,	/* hme_blk base pg # */
				hblk_rehash: 3,		/* rehash number */
				hblk_rid: 10;		/* hme_blk region id */
		void		*hblk_id;
	} hblk_tag_un;
	uint64_t		htag_tag[2];
} hmeblk_tag;

#define	htag_id		hblk_tag_un.hblk_id
#define	htag_bspage	hblk_tag_un.hblk_basepg
#define	htag_rehash	hblk_tag_un.hblk_rehash
#define	htag_rid	hblk_tag_un.hblk_rid

#endif /* !_ASM */

#define	HTAG_REHASH_SHIFT	10
#define	HTAG_MAX_RID	(((0x1 << HTAG_REHASH_SHIFT) - 1))
#define	HTAG_RID_MASK	HTAG_MAX_RID

/* used for tagging all per sfmmu (i.e. non SRD) private hmeblks */
#define	SFMMU_INVALID_SHMERID	HTAG_MAX_RID

#if SFMMU_INVALID_SHMERID < SFMMU_MAX_HME_REGIONS
#error SFMMU_INVALID_SHMERID < SFMMU_MAX_HME_REGIONS
#endif

#define	SFMMU_IS_SHMERID_VALID(rid)	((rid) != SFMMU_INVALID_SHMERID)

/* ISM regions */
#define	SFMMU_INVALID_ISMRID	0xff

#if SFMMU_INVALID_ISMRID < SFMMU_MAX_ISM_REGIONS
#error SFMMU_INVALID_ISMRID < SFMMU_MAX_ISM_REGIONS
#endif

#define	SFMMU_IS_ISMRID_VALID(rid)	((rid) != SFMMU_INVALID_ISMRID)


#define	HTAGS_EQ(tag1, tag2)	(((tag1.htag_tag[0] ^ tag2.htag_tag[0]) | \
				(tag1.htag_tag[1] ^ tag2.htag_tag[1])) == 0)

/*
 * this macro must only be used for comparing tags in shared hmeblks.
 */
#define	HTAGS_EQ_SHME(hmetag, tag, hrmap)				\
	(((hmetag).htag_rid != SFMMU_INVALID_SHMERID) &&	        \
	(((((hmetag).htag_tag[0] ^ (tag).htag_tag[0]) &			\
		~HTAG_RID_MASK) |	        			\
	    ((hmetag).htag_tag[1] ^ (tag).htag_tag[1])) == 0) &&	\
	SF_RGNMAP_TEST(hrmap, hmetag.htag_rid))

#define	HME_REHASH(sfmmup)						\
	((sfmmup)->sfmmu_ttecnt[TTE512K] != 0 ||			\
	(sfmmup)->sfmmu_ttecnt[TTE4M] != 0 ||				\
	(sfmmup)->sfmmu_ttecnt[TTE32M] != 0 ||				\
	(sfmmup)->sfmmu_ttecnt[TTE256M] != 0)

#define	NHMENTS		8		/* # of hments in an 8k hme_blk */
					/* needs to be multiple of 2 */

#ifndef	_ASM

#ifdef	HBLK_TRACE

#define	HBLK_LOCK		1
#define	HBLK_UNLOCK		0
#define	HBLK_STACK_DEPTH	6
#define	HBLK_AUDIT_CACHE_SIZE	16
#define	HBLK_LOCK_PATTERN	0xaaaaaaaa
#define	HBLK_UNLOCK_PATTERN	0xbbbbbbbb

struct hblk_lockcnt_audit {
	int		flag;		/* lock or unlock */
	kthread_id_t	thread;
	int		depth;
	pc_t		stack[HBLK_STACK_DEPTH];
};

#endif	/* HBLK_TRACE */


/*
 * Hment block structure.
 * The hme_blk is the node data structure which the hash structure
 * mantains. An hme_blk can have 2 different sizes depending on the
 * number of hments it implicitly contains.  When dealing with 64K, 512K,
 * or 4M hments there is one hment per hme_blk.  When dealing with
 * 8k hments we allocate an hme_blk plus an additional 7 hments to
 * give us a total of 8 (NHMENTS) hments that can be referenced through a
 * hme_blk.
 *
 * The hmeblk structure contains 2 tte reference counters used to determine if
 * it is ok to free up the hmeblk.  Both counters have to be zero in order
 * to be able to free up hmeblk.  They are protected by cas.
 * hblk_hmecnt is the number of hments present on pp mapping lists.
 * hblk_vcnt reflects number of valid ttes in hmeblk.
 *
 * The hmeblk now also has per tte lock cnts.  This is required because
 * the counts can be high and there are not enough bits in the tte. When
 * physio is fixed to not lock the translations we should be able to move
 * the lock cnt back to the tte.  See bug id 1198554.
 *
 * Note that xhat_hme_blk's layout follows this structure: hme_blk_misc
 * and sf_hment are at the same offsets in both structures. Whenever
 * hme_blk is changed, xhat_hme_blk may need to be updated as well.
 */

struct hme_blk_misc {
	uint_t	notused:25;
	uint_t	shared_bit:1;	/* set for SRD shared hmeblk */
	uint_t	xhat_bit:1;	/* set for an xhat hme_blk */
	uint_t	shadow_bit:1;	/* set for a shadow hme_blk */
	uint_t	nucleus_bit:1;	/* set for a nucleus hme_blk */
	uint_t	ttesize:3;	/* contains ttesz of hmeblk */
};

struct hme_blk {
	volatile uint64_t hblk_nextpa;	/* physical address for hash list */

	hmeblk_tag	hblk_tag;	/* tag used to obtain an hmeblk match */

	struct hme_blk	*hblk_next;	/* on free list or on hash list */
					/* protected by hash lock */

	struct hme_blk	*hblk_shadow;	/* pts to shadow hblk */
					/* protected by hash lock */
	uint_t		hblk_span;	/* span of memory hmeblk maps */

	struct hme_blk_misc	hblk_misc;

	union {
		struct {
			ushort_t hblk_hmecount;	/* hment on mlists counter */
			ushort_t hblk_validcnt;	/* valid tte reference count */
		} hblk_counts;
		uint_t		hblk_shadow_mask;
	} hblk_un;

	uint_t		hblk_lckcnt;

#ifdef	HBLK_TRACE
	kmutex_t	hblk_audit_lock;	/* lock to protect index */
	uint_t		hblk_audit_index;	/* index into audit_cache */
	struct	hblk_lockcnt_audit hblk_audit_cache[HBLK_AUDIT_CACHE_SIZE];
#endif	/* HBLK_AUDIT */

	struct sf_hment hblk_hme[1];	/* hment array */
};

#define	hblk_shared	hblk_misc.shared_bit
#define	hblk_xhat_bit   hblk_misc.xhat_bit
#define	hblk_shw_bit	hblk_misc.shadow_bit
#define	hblk_nuc_bit	hblk_misc.nucleus_bit
#define	hblk_ttesz	hblk_misc.ttesize
#define	hblk_hmecnt	hblk_un.hblk_counts.hblk_hmecount
#define	hblk_vcnt	hblk_un.hblk_counts.hblk_validcnt
#define	hblk_shw_mask	hblk_un.hblk_shadow_mask

#define	MAX_HBLK_LCKCNT	0xFFFFFFFF
#define	HMEBLK_ALIGN	0x8		/* hmeblk has to be double aligned */

#ifdef	HBLK_TRACE

#define	HBLK_STACK_TRACE(hmeblkp, lock)					\
{									\
	int flag = lock;	/* to pacify lint */			\
	int audit_index;						\
									\
	mutex_enter(&hmeblkp->hblk_audit_lock);				\
	audit_index = hmeblkp->hblk_audit_index;			\
	hmeblkp->hblk_audit_index = ((hmeblkp->hblk_audit_index + 1) &	\
	    (HBLK_AUDIT_CACHE_SIZE - 1));				\
	mutex_exit(&hmeblkp->hblk_audit_lock);				\
									\
	if (flag)							\
		hmeblkp->hblk_audit_cache[audit_index].flag =		\
		    HBLK_LOCK_PATTERN;					\
	else								\
		hmeblkp->hblk_audit_cache[audit_index].flag =		\
		    HBLK_UNLOCK_PATTERN;				\
									\
	hmeblkp->hblk_audit_cache[audit_index].thread = curthread;	\
	hmeblkp->hblk_audit_cache[audit_index].depth =			\
	    getpcstack(hmeblkp->hblk_audit_cache[audit_index].stack,	\
	    HBLK_STACK_DEPTH);						\
}

#else

#define	HBLK_STACK_TRACE(hmeblkp, lock)

#endif	/* HBLK_TRACE */

#define	HMEHASH_FACTOR	16	/* used to calc # of buckets in hme hash */

/*
 * A maximum number of user hmeblks is defined in order to place an upper
 * limit on how much nucleus memory is required and to avoid overflowing the
 * tsbmiss uhashsz and khashsz data areas. The number below corresponds to
 * the number of buckets required, for an average hash chain length of 4 on
 * a 16TB machine.
 */

#define	MAX_UHME_BUCKETS	(0x1 << 30)
#define	MAX_KHME_BUCKETS	(0x1 << 30)

/*
 * The minimum number of kernel hash buckets.
 */
#define	MIN_KHME_BUCKETS	0x800

/*
 * The number of hash buckets must be a power of 2. If the initial calculated
 * value is less than USER_BUCKETS_THRESHOLD we round up to the next greater
 * power of 2, otherwise we round down to avoid huge over allocations.
 */
#define	USER_BUCKETS_THRESHOLD	(1<<22)

#define	MAX_NUCUHME_BUCKETS	0x4000
#define	MAX_NUCKHME_BUCKETS	0x2000

/*
 * There are 2 locks in the hmehash bucket.  The hmehash_mutex is
 * a regular mutex used to make sure operations on a hash link are only
 * done by one thread.  Any operation which comes into the hat with
 * a <vaddr, as> will grab the hmehash_mutex.  Normally one would expect
 * the tsb miss handlers to grab the hash lock to make sure the hash list
 * is consistent while we traverse it.  Unfortunately this can lead to
 * deadlocks or recursive mutex enters since it is possible for
 * someone holding the lock to take a tlb/tsb miss.
 * To solve this problem we have added the hmehash_listlock.  This lock
 * is only grabbed by the tsb miss handlers, vatopfn, and while
 * adding/removing a hmeblk from the hash list. The code is written to
 * guarantee we won't take a tlb miss while holding this lock.
 */
struct hmehash_bucket {
	kmutex_t	hmehash_mutex;
	volatile uint64_t hmeh_nextpa;	/* physical address for hash list */
	struct hme_blk *hmeblkp;
	uint_t		hmeh_listlock;
};

#endif /* !_ASM */

#define	SFMMU_PGCNT_MASK	0x3f
#define	SFMMU_PGCNT_SHIFT	6
#define	INVALID_MMU_ID		-1
#define	SFMMU_MMU_GNUM_RSHIFT	16
#define	SFMMU_MMU_CNUM_LSHIFT	(64 - SFMMU_MMU_GNUM_RSHIFT)
#define	MAX_SFMMU_CTX_VAL	((1 << 16) - 1) /* for sanity check */
#define	MAX_SFMMU_GNUM_VAL	((0x1UL << 48) - 1)

/*
 * The tsb miss handlers written in assembly know that sfmmup
 * is a 64 bit ptr.
 *
 * The bspage and re-hash part is 64 bits, with the sfmmup being another 64
 * bits.
 */
#define	HTAG_SFMMUPSZ		0	/* Not really used for LP64 */
#define	HTAG_BSPAGE_SHIFT	13

/*
 * Assembly routines need to be able to get to ttesz
 */
#define	HBLK_SZMASK		0x7

#ifndef _ASM

/*
 * Returns the number of bytes that an hmeblk spans given its tte size
 */
#define	get_hblk_span(hmeblkp) ((hmeblkp)->hblk_span)
#define	get_hblk_ttesz(hmeblkp)	((hmeblkp)->hblk_ttesz)
#define	get_hblk_cache(hmeblkp)	(((hmeblkp)->hblk_ttesz == TTE8K) ? \
	sfmmu8_cache : sfmmu1_cache)
#define	HMEBLK_SPAN(ttesz)						\
	((ttesz == TTE8K)? (TTEBYTES(ttesz) * NHMENTS) : TTEBYTES(ttesz))

#define	set_hblk_sz(hmeblkp, ttesz)				\
	(hmeblkp)->hblk_ttesz = (ttesz);			\
	(hmeblkp)->hblk_span = HMEBLK_SPAN(ttesz)

#define	get_hblk_base(hmeblkp)					\
	((uintptr_t)(hmeblkp)->hblk_tag.htag_bspage << MMU_PAGESHIFT)

#define	get_hblk_endaddr(hmeblkp)				\
	((caddr_t)(get_hblk_base(hmeblkp) + get_hblk_span(hmeblkp)))

#define	in_hblk_range(hmeblkp, vaddr)					\
	(((uintptr_t)(vaddr) >= get_hblk_base(hmeblkp)) &&		\
	((uintptr_t)(vaddr) < (get_hblk_base(hmeblkp) +			\
	get_hblk_span(hmeblkp))))

#define	tte_to_vaddr(hmeblkp, tte)	((caddr_t)(get_hblk_base(hmeblkp) \
	+ (TTEBYTES(TTE_CSZ(&tte)) * (tte).tte_hmenum)))

#define	tte_to_evaddr(hmeblkp, ttep)	((caddr_t)(get_hblk_base(hmeblkp) \
	+ (TTEBYTES(TTE_CSZ(ttep)) * ((ttep)->tte_hmenum + 1))))

#define	vaddr_to_vshift(hblktag, vaddr, shwsz)				\
	((((uintptr_t)(vaddr) >> MMU_PAGESHIFT) - (hblktag.htag_bspage)) >>\
	TTE_BSZS_SHIFT((shwsz) - 1))

#define	HME8BLK_SZ	(sizeof (struct hme_blk) + \
			(NHMENTS - 1) * sizeof (struct sf_hment))
#define	HME1BLK_SZ	(sizeof (struct hme_blk))
#define	H1MIN		(2 + MAX_BIGKTSB_TTES)	/* nucleus text+data, ktsb */

/*
 * Hme_blk hash structure
 * Active mappings are kept in a hash structure of hme_blks.  The hash
 * function is based on (ctx, vaddr) The size of the hash table size is a
 * power of 2 such that the average hash chain lenth is HMENT_HASHAVELEN.
 * The hash actually consists of 2 separate hashes.  One hash is for the user
 * address space and the other hash is for the kernel address space.
 * The number of buckets are calculated at boot time and stored in the global
 * variables "uhmehash_num" and "khmehash_num".  By making the hash table size
 * a power of 2 we can use a simply & function to derive an index instead of
 * a divide.
 *
 * HME_HASH_FUNCTION(hatid, vaddr, shift) returns a pointer to a hme_hash
 * bucket.
 * An hme hash bucket contains a pointer to an hme_blk and the mutex that
 * protects the link list.
 * Spitfire supports 4 page sizes.  8k and 64K pages only need one hash.
 * 512K pages need 2 hashes and 4M pages need 3 hashes.
 * The 'shift' parameter controls how many bits the vaddr will be shifted in
 * the hash function. It is calculated in the HME_HASH_SHIFT(ttesz) function
 * and it varies depending on the page size as follows:
 *	8k pages:  	HBLK_RANGE_SHIFT
 *	64k pages:	MMU_PAGESHIFT64K
 *	512K pages:	MMU_PAGESHIFT512K
 *	4M pages:	MMU_PAGESHIFT4M
 * An assembly version of the hash function exists in sfmmu_ktsb_miss(). All
 * changes should be reflected in both versions.  This function and the TSB
 * miss handlers are the only places which know about the two hashes.
 *
 * HBLK_RANGE_SHIFT controls range of virtual addresses that will fall
 * into the same bucket for a particular process.  It is currently set to
 * be equivalent to 64K range or one hme_blk.
 *
 * The hme_blks in the hash are protected by a per hash bucket mutex
 * known as SFMMU_HASH_LOCK.
 * You need to acquire this lock before traversing the hash bucket link
 * list, while adding/removing a hme_blk to the list, and while
 * modifying an hme_blk.  A possible optimization is to replace these
 * mutexes by readers/writer lock but right now it is not clear whether
 * this is a win or not.
 *
 * The HME_HASH_TABLE_SEARCH will search the hash table for the
 * hme_blk that contains the hment that corresponds to the passed
 * ctx and vaddr.  It assumed the SFMMU_HASH_LOCK is held.
 */

#endif /* ! _ASM */

#define	KHATID			ksfmmup
#define	UHMEHASH_SZ		uhmehash_num
#define	KHMEHASH_SZ		khmehash_num
#define	HMENT_HASHAVELEN	4
#define	HBLK_RANGE_SHIFT	MMU_PAGESHIFT64K /* shift for HBLK_BS_MASK */
#define	HBLK_MIN_TTESZ		1
#define	HBLK_MIN_BYTES		MMU_PAGESIZE64K
#define	HBLK_MIN_SHIFT		MMU_PAGESHIFT64K
#define	MAX_HASHCNT		5
#define	DEFAULT_MAX_HASHCNT	3

#ifndef _ASM

#define	HASHADDR_MASK(hashno)	TTE_PAGEMASK(hashno)

#define	HME_HASH_SHIFT(ttesz)						\
	((ttesz == TTE8K)? HBLK_RANGE_SHIFT : TTE_PAGE_SHIFT(ttesz))

#define	HME_HASH_ADDR(vaddr, hmeshift)					\
	((caddr_t)(((uintptr_t)(vaddr) >> (hmeshift)) << (hmeshift)))

#define	HME_HASH_BSPAGE(vaddr, hmeshift)				\
	(((uintptr_t)(vaddr) >> (hmeshift)) << ((hmeshift) - MMU_PAGESHIFT))

#define	HME_HASH_REHASH(ttesz)						\
	(((ttesz) < TTE512K)? 1 : (ttesz))

#define	HME_HASH_FUNCTION(hatid, vaddr, shift)				     \
	((((void *)hatid) != ((void *)KHATID)) ?			     \
	(&uhme_hash[ (((uintptr_t)(hatid) ^ ((uintptr_t)vaddr >> (shift))) & \
	    UHMEHASH_SZ) ]):						     \
	(&khme_hash[ (((uintptr_t)(hatid) ^ ((uintptr_t)vaddr >> (shift))) & \
	    KHMEHASH_SZ) ]))

/*
 * This macro will traverse a hmeblk hash link list looking for an hme_blk
 * that owns the specified vaddr and hatid.  If if doesn't find one , hmeblkp
 * will be set to NULL, otherwise it will point to the correct hme_blk.
 * This macro also cleans empty hblks.
 */
#define	HME_HASH_SEARCH_PREV(hmebp, hblktag, hblkp, pr_hblk, listp)	\
{									\
	struct hme_blk *nx_hblk;					\
									\
	ASSERT(SFMMU_HASH_LOCK_ISHELD(hmebp));				\
	hblkp = hmebp->hmeblkp;						\
	pr_hblk = NULL;							\
	while (hblkp) {							\
		if (HTAGS_EQ(hblkp->hblk_tag, hblktag)) {		\
			/* found hme_blk */				\
			break;						\
		}							\
		nx_hblk = hblkp->hblk_next;				\
		if (!hblkp->hblk_vcnt && !hblkp->hblk_hmecnt) {		\
			sfmmu_hblk_hash_rm(hmebp, hblkp, pr_hblk,	\
			    listp, 0);					\
		} else {						\
			pr_hblk = hblkp;				\
		}							\
		hblkp = nx_hblk;					\
	}								\
}

#define	HME_HASH_SEARCH(hmebp, hblktag, hblkp, listp)			\
{									\
	struct hme_blk *pr_hblk;					\
									\
	HME_HASH_SEARCH_PREV(hmebp, hblktag, hblkp,  pr_hblk, listp);	\
}

/*
 * This macro will traverse a hmeblk hash link list looking for an hme_blk
 * that owns the specified vaddr and hatid.  If if doesn't find one , hmeblkp
 * will be set to NULL, otherwise it will point to the correct hme_blk.
 * It doesn't remove empty hblks.
 */
#define	HME_HASH_FAST_SEARCH(hmebp, hblktag, hblkp)			\
	ASSERT(SFMMU_HASH_LOCK_ISHELD(hmebp));				\
	for (hblkp = hmebp->hmeblkp; hblkp;				\
	    hblkp = hblkp->hblk_next) {					\
		if (HTAGS_EQ(hblkp->hblk_tag, hblktag)) {		\
			/* found hme_blk */				\
			break;						\
		}							\
	}

#define	SFMMU_HASH_LOCK(hmebp)						\
		(mutex_enter(&hmebp->hmehash_mutex))

#define	SFMMU_HASH_UNLOCK(hmebp)					\
		(mutex_exit(&hmebp->hmehash_mutex))

#define	SFMMU_HASH_LOCK_TRYENTER(hmebp)					\
		(mutex_tryenter(&hmebp->hmehash_mutex))

#define	SFMMU_HASH_LOCK_ISHELD(hmebp)					\
		(mutex_owned(&hmebp->hmehash_mutex))

#define	SFMMU_XCALL_STATS(sfmmup)					\
{									\
	if (sfmmup == ksfmmup) {					\
		SFMMU_STAT(sf_kernel_xcalls);				\
	} else {							\
		SFMMU_STAT(sf_user_xcalls);				\
	}								\
}

#define	astosfmmu(as)		((as)->a_hat)
#define	hblktosfmmu(hmeblkp)	((sfmmu_t *)(hmeblkp)->hblk_tag.htag_id)
#define	hblktosrd(hmeblkp)	((sf_srd_t *)(hmeblkp)->hblk_tag.htag_id)
#define	sfmmutoas(sfmmup)	((sfmmup)->sfmmu_as)

#define	sfmmutohtagid(sfmmup, rid)			   \
	(((rid) == SFMMU_INVALID_SHMERID) ? (void *)(sfmmup) : \
	(void *)((sfmmup)->sfmmu_srdp))

/*
 * We use the sfmmu data structure to keep the per as page coloring info.
 */
#define	as_color_bin(as)	(astosfmmu(as)->sfmmu_clrbin)
#define	as_color_start(as)	(astosfmmu(as)->sfmmu_clrstart)

typedef struct {
	char	h8[HME8BLK_SZ];
} hblk8_t;

typedef struct {
	char	h1[HME1BLK_SZ];
} hblk1_t;

typedef struct {
	ulong_t  	index;
	ulong_t  	len;
	hblk8_t		*list;
} nucleus_hblk8_info_t;

typedef struct {
	ulong_t		index;
	ulong_t		len;
	hblk1_t		*list;
} nucleus_hblk1_info_t;

/*
 * This struct is used for accumlating information about a range
 * of pages that are unloading so that a single xcall can flush
 * the entire range from remote tlbs. A function that must demap
 * a range of virtual addresses declares one of these structures
 * and initializes using DEMP_RANGE_INIT(). It then passes a pointer to this
 * struct to the appropriate sfmmu_hblk_* level function which does
 * all the bookkeeping using the other macros. When the function has
 * finished the virtual address range, it needs to call DEMAP_RANGE_FLUSH()
 * macro to take care of any remaining unflushed mappings.
 *
 * The maximum range this struct can represent is the number of bits
 * in the dmr_bitvec field times the pagesize in dmr_pgsz. Currently, only
 * MMU_PAGESIZE pages are supported.
 *
 * Since there are now cases where it's no longer necessary to do
 * flushes (e.g. when the process isn't runnable because it's swapping
 * out or exiting) we allow these macros to take a NULL dmr input and do
 * nothing in that case.
 */
typedef struct {
	sfmmu_t		*dmr_sfmmup;	/* relevant hat */
	caddr_t		dmr_addr;	/* beginning address */
	caddr_t		dmr_endaddr;	/* ending  address */
	ulong_t		dmr_bitvec;	/* valid pages found */
	ulong_t		dmr_bit;	/* next page to examine */
	ulong_t		dmr_maxbit;	/* highest page in range */
	ulong_t		dmr_pgsz;	/* page size in range */
} demap_range_t;

#define	DMR_MAXBIT ((ulong_t)1<<63) /* dmr_bit high bit */

#define	DEMAP_RANGE_INIT(sfmmup, dmrp) \
	(dmrp)->dmr_sfmmup = (sfmmup); \
	(dmrp)->dmr_bitvec = 0; \
	(dmrp)->dmr_maxbit = sfmmu_dmr_maxbit; \
	(dmrp)->dmr_pgsz = MMU_PAGESIZE;

#define	DEMAP_RANGE_PGSZ(dmrp) ((dmrp)? (dmrp)->dmr_pgsz : MMU_PAGESIZE)

#define	DEMAP_RANGE_CONTINUE(dmrp, addr, endaddr) \
	if ((dmrp) != NULL) { \
	if ((dmrp)->dmr_bitvec != 0 && (dmrp)->dmr_endaddr != (addr)) \
		sfmmu_tlb_range_demap(dmrp); \
	(dmrp)->dmr_endaddr = (endaddr); \
	}

#define	DEMAP_RANGE_FLUSH(dmrp) \
	if ((dmrp)->dmr_bitvec != 0)			\
		sfmmu_tlb_range_demap(dmrp);


#define	DEMAP_RANGE_MARKPG(dmrp, addr) \
	if ((dmrp) != NULL) { \
		if ((dmrp)->dmr_bitvec == 0) { \
			(dmrp)->dmr_addr = (addr); \
			(dmrp)->dmr_bit = 1; \
		} \
		(dmrp)->dmr_bitvec |= (dmrp)->dmr_bit; \
	}

#define	DEMAP_RANGE_NEXTPG(dmrp) \
	if ((dmrp) != NULL && (dmrp)->dmr_bitvec != 0) { \
		if ((dmrp)->dmr_bit & (dmrp)->dmr_maxbit) { \
			sfmmu_tlb_range_demap(dmrp); \
		} else { \
			(dmrp)->dmr_bit <<= 1; \
		} \
	}

/*
 * TSB related structures
 *
 * The TSB is made up of tte entries.  Both the tag and data are present
 * in the TSB.  The TSB locking is managed as follows:
 * A software bit in the tsb tag is used to indicate that entry is locked.
 * If a cpu servicing a tsb miss reads a locked entry the tag compare will
 * fail forcing the cpu to go to the hat hash for the translation.
 * The cpu who holds the lock can then modify the data side, and the tag side.
 * The last write should be to the word containing the lock bit which will
 * clear the lock and allow the tsb entry to be read.  It is assumed that all
 * cpus reading the tsb will do so with atomic 128-bit loads.  An atomic 128
 * bit load is required to prevent the following from happening:
 *
 * cpu 0			cpu 1			comments
 *
 * ldx tag						tag unlocked
 *				ldstub lock		set lock
 *				stx data
 *				stx tag			unlock
 * ldx tag						incorrect tte!!!
 *
 * The software also maintains a bit in the tag to indicate an invalid
 * tsb entry.  The purpose of this bit is to allow the tsb invalidate code
 * to invalidate a tsb entry with a single cas.  See code for details.
 */

union tsb_tag {
	struct {
		uint32_t	tag_res0:16;	/* reserved - context area */
		uint32_t	tag_inv:1;	/* sw - invalid tsb entry */
		uint32_t	tag_lock:1;	/* sw - locked tsb entry */
		uint32_t	tag_res1:4;	/* reserved */
		uint32_t	tag_va_hi:10;	/* va[63:54] */
		uint32_t	tag_va_lo;	/* va[53:22] */
	} tagbits;
	struct tsb_tagints {
		uint32_t	inthi;
		uint32_t	intlo;
	} tagints;
};
#define	tag_invalid		tagbits.tag_inv
#define	tag_locked		tagbits.tag_lock
#define	tag_vahi		tagbits.tag_va_hi
#define	tag_valo		tagbits.tag_va_lo
#define	tag_inthi		tagints.inthi
#define	tag_intlo		tagints.intlo

struct tsbe {
	union tsb_tag	tte_tag;
	tte_t		tte_data;
};

/*
 * A per cpu struct is kept that duplicates some info
 * used by the tl>0 tsb miss handlers plus it provides
 * a scratch area.  Its purpose is to minimize cache misses
 * in the tsb miss handler and is 128 bytes (2 e$ lines).
 *
 * There should be one allocated per cpu in nucleus memory
 * and should be aligned on an ecache line boundary.
 */
struct tsbmiss {
	sfmmu_t			*ksfmmup;	/* kernel hat id */
	sfmmu_t			*usfmmup;	/* user hat id */
	sf_srd_t		*usrdp;		/* user's SRD hat id */
	struct tsbe		*tsbptr;	/* hardware computed ptr */
	struct tsbe		*tsbptr4m;	/* hardware computed ptr */
	struct tsbe		*tsbscdptr;	/* hardware computed ptr */
	struct tsbe		*tsbscdptr4m;	/* hardware computed ptr */
	uint64_t		ismblkpa;
	struct hmehash_bucket	*khashstart;
	struct hmehash_bucket	*uhashstart;
	uint_t			khashsz;
	uint_t			uhashsz;
	uint16_t 		dcache_line_mask; /* used to flush dcache */
	uchar_t			uhat_tteflags;	/* private page sizes */
	uchar_t			uhat_rtteflags;	/* SHME pagesizes */
	uint32_t		utsb_misses;
	uint32_t		ktsb_misses;
	uint16_t		uprot_traps;
	uint16_t		kprot_traps;
	/*
	 * scratch[0] -> TSB_TAGACC
	 * scratch[1] -> TSBMISS_HMEBP
	 * scratch[2] -> TSBMISS_HATID
	 */
	uintptr_t		scratch[3];
	ulong_t		shmermap[SFMMU_HMERGNMAP_WORDS];	/* 8 bytes */
	ulong_t		scd_shmermap[SFMMU_HMERGNMAP_WORDS];	/* 8 bytes */
	uint8_t		pad[48];			/* pad to 64 bytes */
};

/*
 * A per cpu struct is kept for the use within the tl>0 kpm tsb
 * miss handler. Some members are duplicates of common data or
 * the physical addresses of common data. A few members are also
 * written by the tl>0 kpm tsb miss handler. Its purpose is to
 * minimize cache misses in the kpm tsb miss handler and occupies
 * one ecache line. There should be one allocated per cpu in
 * nucleus memory and it should be aligned on an ecache line
 * boundary. It is not merged w/ struct tsbmiss since there is
 * not much to share and the tsbmiss pathes are different, so
 * a kpm tlbmiss/tsbmiss only touches one cacheline, except for
 * (DEBUG || SFMMU_STAT_GATHER) where the dtlb_misses counter
 * of struct tsbmiss is used on every dtlb miss.
 */
struct kpmtsbm {
	caddr_t		vbase;		/* start of address kpm range */
	caddr_t		vend;		/* end of address kpm range */
	uchar_t		flags;		/* flags needed in TL tsbmiss handler */
	uchar_t		sz_shift;	/* for single kpm window */
	uchar_t		kpmp_shift;	/* hash lock shift */
	uchar_t		kpmp2pshft;	/* kpm page to page shift */
	uint_t		kpmp_table_sz;	/* size of kpmp_table or kpmp_stable */
	uint64_t	kpmp_tablepa;	/* paddr of kpmp_table or kpmp_stable */
	uint64_t	msegphashpa;	/* paddr of memseg_phash */
	struct tsbe	*tsbptr;	/* saved ktsb pointer */
	uint_t		kpm_dtlb_misses; /* kpm tlbmiss counter */
	uint_t		kpm_tsb_misses;	/* kpm tsbmiss counter */
	uintptr_t	pad[1];
};

extern size_t	tsb_slab_size;
extern uint_t	tsb_slab_shift;
extern size_t	tsb_slab_mask;

#endif /* !_ASM */

/*
 * Flags for TL kpm tsbmiss handler
 */
#define	KPMTSBM_ENABLE_FLAG	0x01	/* bit copy of kpm_enable */
#define	KPMTSBM_TLTSBM_FLAG	0x02	/* use TL tsbmiss handler */
#define	KPMTSBM_TSBPHYS_FLAG	0x04	/* use ASI_MEM for TSB update */

/*
 * The TSB
 * All TSB sizes supported by the hardware are now supported (8K - 1M).
 * For kernel TSBs we may go beyond the hardware supported sizes and support
 * larger TSBs via software.
 * All TTE sizes are supported in the TSB; the manner in which this is
 * done is cpu dependent.
 */
#define	TSB_MIN_SZCODE		TSB_8K_SZCODE	/* min. supported TSB size */
#define	TSB_MIN_OFFSET_MASK	(TSB_OFFSET_MASK(TSB_MIN_SZCODE))

#ifdef sun4v
#define	UTSB_MAX_SZCODE		TSB_256M_SZCODE /* max. supported TSB size */
#else /* sun4u */
#define	UTSB_MAX_SZCODE		TSB_1M_SZCODE	/* max. supported TSB size */
#endif /* sun4v */

#define	UTSB_MAX_OFFSET_MASK	(TSB_OFFSET_MASK(UTSB_MAX_SZCODE))

#define	TSB_FREEMEM_MIN		0x1000		/* 32 mb */
#define	TSB_FREEMEM_LARGE	0x10000		/* 512 mb */
#define	TSB_8K_SZCODE		0		/* 512 entries */
#define	TSB_16K_SZCODE		1		/* 1k entries */
#define	TSB_32K_SZCODE		2		/* 2k entries */
#define	TSB_64K_SZCODE		3		/* 4k entries */
#define	TSB_128K_SZCODE		4		/* 8k entries */
#define	TSB_256K_SZCODE		5		/* 16k entries */
#define	TSB_512K_SZCODE		6		/* 32k entries */
#define	TSB_1M_SZCODE		7		/* 64k entries */
#define	TSB_2M_SZCODE		8		/* 128k entries */
#define	TSB_4M_SZCODE		9		/* 256k entries */
#define	TSB_8M_SZCODE		10		/* 512k entries */
#define	TSB_16M_SZCODE		11		/* 1M entries */
#define	TSB_32M_SZCODE		12		/* 2M entries */
#define	TSB_64M_SZCODE		13		/* 4M entries */
#define	TSB_128M_SZCODE		14		/* 8M entries */
#define	TSB_256M_SZCODE		15		/* 16M entries */
#define	TSB_ENTRY_SHIFT		4	/* each entry = 128 bits = 16 bytes */
#define	TSB_ENTRY_SIZE		(1 << 4)
#define	TSB_START_SIZE		9
#define	TSB_ENTRIES(tsbsz)	(1 << (TSB_START_SIZE + tsbsz))
#define	TSB_BYTES(tsbsz)	(TSB_ENTRIES(tsbsz) << TSB_ENTRY_SHIFT)
#define	TSB_OFFSET_MASK(tsbsz)	(TSB_ENTRIES(tsbsz) - 1)
#define	TSB_BASEADDR_MASK	((1 << 12) - 1)

/*
 * sun4u platforms
 * ---------------
 * We now support two user TSBs with one TSB base register.
 * Hence the TSB base register is split up as follows:
 *
 * When only one TSB present:
 *   [63  62..42  41..13  12..4  3..0]
 *     ^   ^       ^       ^     ^
 *     |   |       |       |     |
 *     |   |       |       |     |_ TSB size code
 *     |   |       |       |
 *     |   |       |       |_ Reserved 0
 *     |   |       |
 *     |   |       |_ TSB VA[41..13]
 *     |   |
 *     |   |_ VA hole (Spitfire), zeros (Cheetah and beyond)
 *     |
 *     |_ 0
 *
 * When second TSB present:
 *   [63  62..42  41..33  32..29  28..22  21..13  12..4  3..0]
 *     ^   ^       ^       ^       ^       ^       ^     ^
 *     |   |       |       |       |       |       |     |
 *     |   |       |       |       |       |       |     |_ First TSB size code
 *     |   |       |       |       |       |       |
 *     |   |       |       |       |       |       |_ Reserved 0
 *     |   |       |       |       |       |
 *     |   |       |       |       |       |_ First TSB's VA[21..13]
 *     |   |       |       |       |
 *     |   |       |       |       |_ Reserved for future use
 *     |   |       |       |
 *     |   |       |       |_ Second TSB's size code
 *     |   |       |
 *     |   |       |_ Second TSB's VA[21..13]
 *     |   |
 *     |   |_ VA hole (Spitfire) / ones (Cheetah and beyond)
 *     |
 *     |_ 1
 *
 * Note that since we store 21..13 of each TSB's VA, TSBs and their slabs
 * may be up to 4M in size.  For now, only hardware supported TSB sizes
 * are supported, though the slabs are usually 4M in size.
 *
 * sun4u platforms that define UTSB_PHYS use physical addressing to access
 * the user TSBs at TL>0.  The first user TSB base is in the MMU I/D TSB Base
 * registers.  The second TSB base uses a dedicated scratchpad register which
 * requires a definition of SCRATCHPAD_UTSBREG2 in mach_sfmmu.h.  The layout for
 * both registers is equivalent to sun4v below, except the TSB PA range is
 * [46..13] for sun4u.
 *
 * sun4v platforms
 * ---------------
 * On sun4v platforms, we use two dedicated scratchpad registers as pseudo
 * hardware TSB base registers to hold up to two different user TSBs.
 *
 * Each register contains TSB's physical base and size code information
 * as follows:
 *
 *   [63..56  55..13  12..4  3..0]
 *      ^       ^       ^     ^
 *      |       |       |     |
 *      |       |       |     |_ TSB size code
 *      |       |       |
 *      |       |       |_ Reserved 0
 *      |       |
 *      |       |_ TSB PA[55..13]
 *      |
 *      |
 *      |
 *      |_ 0 for valid TSB
 *
 * Absence of a user TSB (primarily the second user TSB) is indicated by
 * storing a negative value in the TSB base register. This allows us to
 * check for presence of a user TSB by simply checking bit# 63.
 */
#define	TSBREG_MSB_SHIFT	32		/* set upper bits */
#define	TSBREG_MSB_CONST	0xfffff800	/* set bits 63..43 */
#define	TSBREG_FIRTSB_SHIFT	42		/* to clear bits 63:22 */
#define	TSBREG_SECTSB_MKSHIFT	20		/* 21:13 --> 41:33 */
#define	TSBREG_SECTSB_LSHIFT	22		/* to clear bits 63:42 */
#define	TSBREG_SECTSB_RSHIFT	(TSBREG_SECTSB_MKSHIFT + TSBREG_SECTSB_LSHIFT)
						/* sectsb va -> bits 21:13 */
						/* after clearing upper bits */
#define	TSBREG_SECSZ_SHIFT	29		/* to get sectsb szc to 3:0 */
#define	TSBREG_VAMASK_SHIFT	13		/* set up VA mask */

#define	BIGKTSB_SZ_MASK		0xf
#define	TSB_SOFTSZ_MASK		BIGKTSB_SZ_MASK
#define	MIN_BIGKTSB_SZCODE	9	/* 256k entries */
#define	MAX_BIGKTSB_SZCODE	11	/* 1024k entries */
#define	MAX_BIGKTSB_TTES	(TSB_BYTES(MAX_BIGKTSB_SZCODE) / MMU_PAGESIZE4M)

#define	TAG_VALO_SHIFT		22		/* tag's va are bits 63-22 */
/*
 * sw bits used on tsb_tag - bit masks used only in assembly
 * use only a sethi for these fields.
 */
#define	TSBTAG_INVALID	0x00008000		/* tsb_tag.tag_invalid */
#define	TSBTAG_LOCKED	0x00004000		/* tsb_tag.tag_locked */

#ifdef	_ASM

/*
 * Marker to indicate that this instruction will be hot patched at runtime
 * to some other value.
 * This value must be zero since it fills in the imm bits of the target
 * instructions to be patched
 */
#define	RUNTIME_PATCH	(0)

/*
 * V9 defines nop instruction as the following, which we use
 * at runtime to nullify some instructions we don't want to
 * execute in the trap handlers on certain platforms.
 */
#define	MAKE_NOP_INSTR(reg)	\
	sethi	%hi(0x1000000), reg

/*
 * This macro constructs a SPARC V9 "jmpl <source reg>, %g0"
 * instruction, with the source register specified by the jump_reg_number.
 * The jmp opcode [24:19] = 11 1000 and source register is bits [18:14].
 * The instruction is returned in reg. The macro is used to patch in a jmpl
 * instruction at runtime.
 */
#define	MAKE_JMP_INSTR(jump_reg_number, reg, tmp)	\
	sethi	%hi(0x81c00000), reg;			\
	mov	jump_reg_number, tmp;			\
	sll	tmp, 14, tmp;				\
	or	reg, tmp, reg

/*
 * Macro to get hat per-MMU cnum on this CPU.
 * sfmmu - In, pass in "sfmmup" from the caller.
 * cnum	- Out, return 'cnum' to the caller
 * scr	- scratch
 */
#define	SFMMU_CPU_CNUM(sfmmu, cnum, scr)				      \
	CPU_ADDR(scr, cnum);	/* scr = load CPU struct addr */	      \
	ld	[scr + CPU_MMU_IDX], cnum;	/* cnum = mmuid */	      \
	add	sfmmu, SFMMU_CTXS, scr;	/* scr = sfmmup->sfmmu_ctxs[] */      \
	sllx    cnum, SFMMU_MMU_CTX_SHIFT, cnum;			      \
	add	scr, cnum, scr;		/* scr = sfmmup->sfmmu_ctxs[id] */    \
	ldx	[scr + SFMMU_MMU_GC_NUM], scr;	/* sfmmu_ctxs[id].gcnum */    \
	sllx    scr, SFMMU_MMU_CNUM_LSHIFT, scr;			      \
	srlx    scr, SFMMU_MMU_CNUM_LSHIFT, cnum;	/* cnum = sfmmu cnum */

/*
 * Macro to get hat gnum & cnum assocaited with sfmmu_ctx[mmuid] entry
 * entry - In,  pass in (&sfmmu_ctxs[mmuid] - SFMMU_CTXS) from the caller.
 * gnum - Out, return sfmmu gnum
 * cnum - Out, return sfmmu cnum
 * reg	- scratch
 */
#define	SFMMU_MMUID_GNUM_CNUM(entry, gnum, cnum, reg)			     \
	ldx	[entry + SFMMU_CTXS], reg;  /* reg = sfmmu (gnum | cnum) */  \
	srlx	reg, SFMMU_MMU_GNUM_RSHIFT, gnum;    /* gnum = sfmmu gnum */ \
	sllx	reg, SFMMU_MMU_CNUM_LSHIFT, cnum;			     \
	srlx	cnum, SFMMU_MMU_CNUM_LSHIFT, cnum;   /* cnum = sfmmu cnum */

/*
 * Macro to get this CPU's tsbmiss area.
 */
#define	CPU_TSBMISS_AREA(tsbmiss, tmp1)					\
	CPU_INDEX(tmp1, tsbmiss);		/* tmp1 = cpu idx */	\
	sethi	%hi(tsbmiss_area), tsbmiss;	/* tsbmiss base ptr */	\
	mulx    tmp1, TSBMISS_SIZE, tmp1;	/* byte offset */	\
	or	tsbmiss, %lo(tsbmiss_area), tsbmiss;			\
	add	tsbmiss, tmp1, tsbmiss		/* tsbmiss area of CPU */


/*
 * Macro to set kernel context + page size codes in DMMU primary context
 * register. It is only necessary for sun4u because sun4v does not need
 * page size codes
 */
#ifdef sun4v

#define	SET_KCONTEXTREG(reg0, reg1, reg2, reg3, reg4, label1, label2, label3)

#else

#define	SET_KCONTEXTREG(reg0, reg1, reg2, reg3, reg4, label1, label2, label3) \
	sethi	%hi(kcontextreg), reg0;					\
	ldx	[reg0 + %lo(kcontextreg)], reg0;			\
	mov	MMU_PCONTEXT, reg1;					\
	ldxa	[reg1]ASI_MMU_CTX, reg2;				\
	xor	reg0, reg2, reg2;					\
	brz	reg2, label3;						\
	srlx	reg2, CTXREG_NEXT_SHIFT, reg2;				\
	rdpr	%pstate, reg3;		/* disable interrupts */	\
	btst	PSTATE_IE, reg3;					\
/*CSTYLED*/								\
	bnz,a,pt %icc, label1;						\
	wrpr	reg3, PSTATE_IE, %pstate;				\
/*CSTYLED*/								\
label1:;								\
	brz	reg2, label2;	   /* need demap if N_pgsz0/1 change */	\
	sethi	%hi(FLUSH_ADDR), reg4;					\
	mov	DEMAP_ALL_TYPE, reg2;					\
	stxa	%g0, [reg2]ASI_DTLB_DEMAP;				\
	stxa	%g0, [reg2]ASI_ITLB_DEMAP;				\
/*CSTYLED*/								\
label2:;								\
	stxa	reg0, [reg1]ASI_MMU_CTX;				\
	flush	reg4;							\
	btst	PSTATE_IE, reg3;					\
/*CSTYLED*/								\
	bnz,a,pt %icc, label3;						\
	wrpr	%g0, reg3, %pstate;	/* restore interrupt state */	\
label3:;

#endif

/*
 * Macro to setup arguments with kernel sfmmup context + page size before
 * calling sfmmu_setctx_sec()
 */
#ifdef sun4v
#define	SET_KAS_CTXSEC_ARGS(sfmmup, arg0, arg1)			\
	set	KCONTEXT, arg0;					\
	set	0, arg1;
#else
#define	SET_KAS_CTXSEC_ARGS(sfmmup, arg0, arg1)			\
	ldub	[sfmmup + SFMMU_CEXT], arg1;			\
	set	KCONTEXT, arg0;					\
	sll	arg1, CTXREG_EXT_SHIFT, arg1;
#endif

#define	PANIC_IF_INTR_DISABLED_PSTR(pstatereg, label, scr)	       	\
	andcc	pstatereg, PSTATE_IE, %g0;	/* panic if intrs */	\
/*CSTYLED*/								\
	bnz,pt	%icc, label;			/* already disabled */	\
	nop;								\
									\
	sethi	%hi(panicstr), scr;					\
	ldx	[scr + %lo(panicstr)], scr;				\
	tst	scr;							\
/*CSTYLED*/								\
	bnz,pt	%xcc, label;						\
	nop;								\
									\
	save	%sp, -SA(MINFRAME), %sp;				\
	sethi	%hi(sfmmu_panic1), %o0;					\
	call	panic;							\
	or	%o0, %lo(sfmmu_panic1), %o0;				\
/*CSTYLED*/								\
label:

#define	PANIC_IF_INTR_ENABLED_PSTR(label, scr)				\
	/*								\
	 * The caller must have disabled interrupts.			\
	 * If interrupts are not disabled, panic			\
	 */								\
	rdpr	%pstate, scr;						\
	andcc	scr, PSTATE_IE, %g0;					\
/*CSTYLED*/								\
	bz,pt	%icc, label;						\
	nop;								\
									\
	sethi	%hi(panicstr), scr;					\
	ldx	[scr + %lo(panicstr)], scr;				\
	tst	scr;							\
/*CSTYLED*/								\
	bnz,pt	%xcc, label;						\
	nop;								\
									\
	sethi	%hi(sfmmu_panic6), %o0;					\
	call	panic;							\
	or	%o0, %lo(sfmmu_panic6), %o0;				\
/*CSTYLED*/								\
label:

#endif	/* _ASM */

#ifndef _ASM

#ifdef VAC
/*
 * Page coloring
 * The p_vcolor field of the page struct (1 byte) is used to store the
 * virtual page color.  This provides for 255 colors.  The value zero is
 * used to mean the page has no color - never been mapped or somehow
 * purified.
 */

#define	PP_GET_VCOLOR(pp)	(((pp)->p_vcolor) - 1)
#define	PP_NEWPAGE(pp)		(!(pp)->p_vcolor)
#define	PP_SET_VCOLOR(pp, color)                                          \
	((pp)->p_vcolor = ((color) + 1))

/*
 * As mentioned p_vcolor == 0 means there is no color for this page.
 * But PP_SET_VCOLOR(pp, color) expects 'color' to be real color minus
 * one so we define this constant.
 */
#define	NO_VCOLOR	(-1)

#define	addr_to_vcolor(addr) \
	(((uint_t)(uintptr_t)(addr) >> MMU_PAGESHIFT) & vac_colors_mask)
#else	/* VAC */
#define	addr_to_vcolor(addr)	(0)
#endif	/* VAC */

/*
 * The field p_index in the psm page structure is for large pages support.
 * P_index is a bit-vector of the different mapping sizes that a given page
 * is part of. An hme structure for a large mapping is only added in the
 * group leader page (first page). All pages covered by a given large mapping
 * have the corrosponding mapping bit set in their p_index field. This allows
 * us to only store an explicit hme structure in the leading page which
 * simplifies the mapping link list management. Furthermore, it provides us
 * a fast mechanism for determining the largest mapping a page is part of. For
 * exmaple, a page with a 64K and a 4M mappings has a p_index value of 0x0A.
 *
 * Implementation note: even though the first bit in p_index is reserved
 * for 8K mappings, it is NOT USED by the code and SHOULD NOT be set.
 * In addition, the upper four bits of the p_index field are used by the
 * code as temporaries
 */

/*
 * Defines for psm page struct fields and large page support
 */
#define	SFMMU_INDEX_SHIFT		6
#define	SFMMU_INDEX_MASK		((1 << SFMMU_INDEX_SHIFT) - 1)

/* Return the mapping index */
#define	PP_MAPINDEX(pp)	((pp)->p_index & SFMMU_INDEX_MASK)

/*
 * These macros rely on the following property:
 * All pages constituting a large page are covered by a virtually
 * contiguous set of page_t's.
 */

/* Return the leader for this mapping size */
#define	PP_GROUPLEADER(pp, sz) \
	(&(pp)[-(int)(pp->p_pagenum & (TTEPAGES(sz)-1))])

/* Return the root page for this page based on p_szc */
#define	PP_PAGEROOT(pp)	((pp)->p_szc == 0 ? (pp) : \
	PP_GROUPLEADER((pp), (pp)->p_szc))

#define	PP_PAGENEXT_N(pp, n)	((pp) + (n))
#define	PP_PAGENEXT(pp)		PP_PAGENEXT_N((pp), 1)

#define	PP_PAGEPREV_N(pp, n)	((pp) - (n))
#define	PP_PAGEPREV(pp)		PP_PAGEPREV_N((pp), 1)

#define	PP_ISMAPPED_LARGE(pp)	(PP_MAPINDEX(pp) != 0)

/* Need function to test the page mappping which takes p_index into account */
#define	PP_ISMAPPED(pp)	((pp)->p_mapping || PP_ISMAPPED_LARGE(pp))

/*
 * Don't call this macro with sz equal to zero. 8K mappings SHOULD NOT
 * set p_index field.
 */
#define	PAGESZ_TO_INDEX(sz)	(1 << (sz))


/*
 * prototypes for hat assembly routines.  Some of these are
 * known to machine dependent VM code.
 */
extern uint64_t sfmmu_make_tsbtag(caddr_t);
extern struct tsbe *
		sfmmu_get_tsbe(uint64_t, caddr_t, int, int);
extern void	sfmmu_load_tsbe(struct tsbe *, uint64_t, tte_t *, int);
extern void	sfmmu_unload_tsbe(struct tsbe *, uint64_t, int);
extern void	sfmmu_load_mmustate(sfmmu_t *);
extern void	sfmmu_raise_tsb_exception(uint64_t, uint64_t);
#ifndef sun4v
extern void	sfmmu_itlb_ld_kva(caddr_t, tte_t *);
extern void	sfmmu_dtlb_ld_kva(caddr_t, tte_t *);
#endif /* sun4v */
extern void	sfmmu_copytte(tte_t *, tte_t *);
extern int	sfmmu_modifytte(tte_t *, tte_t *, tte_t *);
extern int	sfmmu_modifytte_try(tte_t *, tte_t *, tte_t *);
extern pfn_t	sfmmu_ttetopfn(tte_t *, caddr_t);
extern uint_t	sfmmu_disable_intrs(void);
extern void	sfmmu_enable_intrs(uint_t);
/*
 * functions exported to machine dependent VM code
 */
extern void	sfmmu_patch_ktsb(void);
#ifndef UTSB_PHYS
extern void	sfmmu_patch_utsb(void);
#endif /* UTSB_PHYS */
extern pfn_t	sfmmu_vatopfn(caddr_t, sfmmu_t *, tte_t *);
extern void	sfmmu_vatopfn_suspended(caddr_t, sfmmu_t *, tte_t *);
extern pfn_t	sfmmu_kvaszc2pfn(caddr_t, int);
#ifdef	DEBUG
extern void	sfmmu_check_kpfn(pfn_t);
#else
#define		sfmmu_check_kpfn(pfn)	/* disabled */
#endif	/* DEBUG */
extern void	sfmmu_memtte(tte_t *, pfn_t, uint_t, int);
extern void	sfmmu_tteload(struct hat *, tte_t *, caddr_t, page_t *,	uint_t);
extern void	sfmmu_tsbmiss_exception(struct regs *, uintptr_t, uint_t);
extern void	sfmmu_init_tsbs(void);
extern caddr_t  sfmmu_ktsb_alloc(caddr_t);
extern int	sfmmu_getctx_pri(void);
extern int	sfmmu_getctx_sec(void);
extern void	sfmmu_setctx_sec(uint_t);
extern void	sfmmu_inv_tsb(caddr_t, uint_t);
extern void	sfmmu_init_ktsbinfo(void);
extern int	sfmmu_setup_4lp(void);
extern void	sfmmu_patch_mmu_asi(int);
extern void	sfmmu_init_nucleus_hblks(caddr_t, size_t, int, int);
extern void	sfmmu_cache_flushall(void);
extern pgcnt_t  sfmmu_tte_cnt(sfmmu_t *, uint_t);
extern void	*sfmmu_tsb_segkmem_alloc(vmem_t *, size_t, int);
extern void	sfmmu_tsb_segkmem_free(vmem_t *, void *, size_t);
extern void	sfmmu_reprog_pgsz_arr(sfmmu_t *, uint8_t *);

extern void	hat_kern_setup(void);
extern int	hat_page_relocate(page_t **, page_t **, spgcnt_t *);
extern int	sfmmu_get_ppvcolor(struct page *);
extern int	sfmmu_get_addrvcolor(caddr_t);
extern int	sfmmu_hat_lock_held(sfmmu_t *);
extern int	sfmmu_alloc_ctx(sfmmu_t *, int, struct cpu *, int);

/*
 * Functions exported to xhat_sfmmu.c
 */
extern kmutex_t *sfmmu_mlist_enter(page_t *);
extern void	sfmmu_mlist_exit(kmutex_t *);
extern int	sfmmu_mlist_held(struct page *);
extern struct hme_blk *sfmmu_hmetohblk(struct sf_hment *);

/*
 * MMU-specific functions optionally imported from the CPU module
 */
#pragma weak mmu_init_scd
#pragma weak mmu_large_pages_disabled
#pragma weak mmu_set_ctx_page_sizes
#pragma weak mmu_check_page_sizes

extern void mmu_init_scd(sf_scd_t *);
extern uint_t mmu_large_pages_disabled(uint_t);
extern void mmu_set_ctx_page_sizes(sfmmu_t *);
extern void mmu_check_page_sizes(sfmmu_t *, uint64_t *);

extern sfmmu_t 		*ksfmmup;
extern caddr_t		ktsb_base;
extern uint64_t		ktsb_pbase;
extern int		ktsb_sz;
extern int		ktsb_szcode;
extern caddr_t		ktsb4m_base;
extern uint64_t		ktsb4m_pbase;
extern int		ktsb4m_sz;
extern int		ktsb4m_szcode;
extern uint64_t		kpm_tsbbase;
extern int		kpm_tsbsz;
extern int		ktsb_phys;
extern int		enable_bigktsb;
#ifndef sun4v
extern int		utsb_dtlb_ttenum;
extern int		utsb4m_dtlb_ttenum;
#endif /* sun4v */
extern int		uhmehash_num;
extern int		khmehash_num;
extern struct hmehash_bucket *uhme_hash;
extern struct hmehash_bucket *khme_hash;
extern uint_t		hblk_alloc_dynamic;
extern struct tsbmiss	tsbmiss_area[NCPU];
extern struct kpmtsbm	kpmtsbm_area[NCPU];

#ifndef sun4v
extern int		dtlb_resv_ttenum;
extern caddr_t		utsb_vabase;
extern caddr_t		utsb4m_vabase;
#endif /* sun4v */
extern vmem_t		*kmem_tsb_default_arena[];
extern int		tsb_lgrp_affinity;

extern uint_t		disable_large_pages;
extern uint_t		disable_ism_large_pages;
extern uint_t		disable_auto_data_large_pages;
extern uint_t		disable_auto_text_large_pages;

/* kpm externals */
extern pfn_t		sfmmu_kpm_vatopfn(caddr_t);
extern void		sfmmu_kpm_patch_tlbm(void);
extern void		sfmmu_kpm_patch_tsbm(void);
extern void		sfmmu_patch_shctx(void);
extern void		sfmmu_kpm_load_tsb(caddr_t, tte_t *, int);
extern void		sfmmu_kpm_unload_tsb(caddr_t, int);
extern void		sfmmu_kpm_tsbmtl(short *, uint_t *, int);
extern int		sfmmu_kpm_stsbmtl(uchar_t *, uint_t *, int);
extern caddr_t		kpm_vbase;
extern size_t		kpm_size;
extern struct memseg	*memseg_hash[];
extern uint64_t		memseg_phash[];
extern kpm_hlk_t	*kpmp_table;
extern kpm_shlk_t	*kpmp_stable;
extern uint_t		kpmp_table_sz;
extern uint_t		kpmp_stable_sz;
extern uchar_t		kpmp_shift;

#define	PP_ISMAPPED_KPM(pp)	((pp)->p_kpmref > 0)

#define	IS_KPM_ALIAS_RANGE(vaddr)					\
	(((vaddr) - kpm_vbase) >> (uintptr_t)kpm_size_shift > 0)

#endif /* !_ASM */

/* sfmmu_kpm_tsbmtl flags */
#define	KPMTSBM_STOP		0
#define	KPMTSBM_START		1

/*
 * For kpm_smallpages, the state about how a kpm page is mapped and whether
 * it is ready to go is indicated by the two 4-bit fields defined in the
 * kpm_spage structure as follows:
 * kp_mapped_flag bit[0:3] - the page is mapped cacheable or not
 * kp_mapped_flag bit[4:7] - the mapping is ready to go or not
 * If the bit KPM_MAPPED_GO is on, it indicates that the assembly tsb miss
 * handler can drop the mapping in regardless of the caching state of the
 * mapping. Otherwise, we will have C handler resolve the VAC conflict no
 * matter the page is currently mapped cacheable or non-cacheable.
 */
#define	KPM_MAPPEDS		0x1	/* small mapping valid, no conflict */
#define	KPM_MAPPEDSC		0x2	/* small mapping valid, conflict */
#define	KPM_MAPPED_GO		0x10	/* the mapping is ready to go */
#define	KPM_MAPPED_MASK		0xf

/* Physical memseg address NULL marker */
#define	MSEG_NULLPTR_PA		-1

/*
 * Memseg hash defines for kpm trap level tsbmiss handler.
 * Must be in sync w/ page.h .
 */
#define	SFMMU_MEM_HASH_SHIFT		0x9
#define	SFMMU_N_MEM_SLOTS		0x200
#define	SFMMU_MEM_HASH_ENTRY_SHIFT	3

#ifndef	_ASM
#if (SFMMU_MEM_HASH_SHIFT != MEM_HASH_SHIFT)
#error SFMMU_MEM_HASH_SHIFT != MEM_HASH_SHIFT
#endif
#if (SFMMU_N_MEM_SLOTS != N_MEM_SLOTS)
#error SFMMU_N_MEM_SLOTS != N_MEM_SLOTS
#endif

/* Physical memseg address NULL marker */
#define	SFMMU_MEMSEG_NULLPTR_PA		-1

/*
 * Check KCONTEXT to be zero, asm parts depend on that assumption.
 */
#if (KCONTEXT != 0)
#error KCONTEXT != 0
#endif
#endif	/* !_ASM */


#endif /* _KERNEL */

#ifndef _ASM
/*
 * ctx, hmeblk, mlistlock and other stats for sfmmu
 */
struct sfmmu_global_stat {
	int		sf_tsb_exceptions;	/* # of tsb exceptions */
	int		sf_tsb_raise_exception;	/* # tsb exc. w/o TLB flush */

	int		sf_pagefaults;		/* # of pagefaults */

	int		sf_uhash_searches;	/* # of user hash searches */
	int		sf_uhash_links;		/* # of user hash links */
	int		sf_khash_searches;	/* # of kernel hash searches */
	int		sf_khash_links;		/* # of kernel hash links */

	int		sf_swapout;		/* # times hat swapped out */

	int		sf_tsb_alloc;		/* # TSB allocations */
	int		sf_tsb_allocfail;	/* # times TSB alloc fail */
	int		sf_tsb_sectsb_create;	/* # times second TSB added */

	int		sf_scd_1sttsb_alloc;	/* # SCD 1st TSB allocations */
	int		sf_scd_2ndtsb_alloc;	/* # SCD 2nd TSB allocations */
	int		sf_scd_1sttsb_allocfail; /* # SCD 1st TSB alloc fail */
	int		sf_scd_2ndtsb_allocfail; /* # SCD 2nd TSB alloc fail */


	int		sf_tteload8k;		/* calls to sfmmu_tteload */
	int		sf_tteload64k;		/* calls to sfmmu_tteload */
	int		sf_tteload512k;		/* calls to sfmmu_tteload */
	int		sf_tteload4m;		/* calls to sfmmu_tteload */
	int		sf_tteload32m;		/* calls to sfmmu_tteload */
	int		sf_tteload256m;		/* calls to sfmmu_tteload */

	int		sf_tsb_load8k;		/* # times loaded 8K tsbent */
	int		sf_tsb_load4m;		/* # times loaded 4M tsbent */

	int		sf_hblk_hit;		/* found hblk during tteload */
	int		sf_hblk8_ncreate;	/* static hblk8's created */
	int		sf_hblk8_nalloc;	/* static hblk8's allocated */
	int		sf_hblk1_ncreate;	/* static hblk1's created */
	int		sf_hblk1_nalloc;	/* static hblk1's allocated */
	int		sf_hblk_slab_cnt;	/* sfmmu8_cache slab creates */
	int		sf_hblk_reserve_cnt;	/* hblk_reserve usage */
	int		sf_hblk_recurse_cnt;	/* hblk_reserve	owner reqs */
	int		sf_hblk_reserve_hit;	/* hblk_reserve hash hits */
	int		sf_get_free_success;	/* reserve list allocs */
	int		sf_get_free_throttle;	/* fails due to throttling */
	int		sf_get_free_fail;	/* fails due to empty list */
	int		sf_put_free_success;	/* reserve list frees */
	int		sf_put_free_fail;	/* fails due to full list */

	int		sf_pgcolor_conflict;	/* VAC conflict resolution */
	int		sf_uncache_conflict;	/* VAC conflict resolution */
	int		sf_unload_conflict;	/* VAC unload resolution */
	int		sf_ism_uncache;		/* VAC conflict resolution */
	int		sf_ism_recache;		/* VAC conflict resolution */
	int		sf_recache;		/* VAC conflict resolution */

	int		sf_steal_count;		/* # of hblks stolen */

	int		sf_pagesync;		/* # of pagesyncs */
	int		sf_clrwrt;		/* # of clear write perms */
	int		sf_pagesync_invalid;	/* pagesync with inv tte */

	int		sf_kernel_xcalls;	/* # of kernel cross calls */
	int		sf_user_xcalls;		/* # of user cross calls */

	int		sf_tsb_grow;		/* # of user tsb grows */
	int		sf_tsb_shrink;		/* # of user tsb shrinks */
	int		sf_tsb_resize_failures;	/* # of user tsb resize */
	int		sf_tsb_reloc;		/* # of user tsb relocations */

	int		sf_user_vtop;		/* # of user vatopfn calls */

	int		sf_ctx_inv;		/* #times invalidate MMU ctx */

	int		sf_tlb_reprog_pgsz;	/* # times switch TLB pgsz */

	int		sf_region_remap_demap;	/* # times shme remap demap */

	int		sf_create_scd;		/* # times SCD is created */
	int		sf_join_scd;		/* # process joined scd */
	int		sf_leave_scd;		/* # process left scd */
	int		sf_destroy_scd;		/* # times SCD is destroyed */
};

struct sfmmu_tsbsize_stat {
	int		sf_tsbsz_8k;
	int		sf_tsbsz_16k;
	int		sf_tsbsz_32k;
	int		sf_tsbsz_64k;
	int		sf_tsbsz_128k;
	int		sf_tsbsz_256k;
	int		sf_tsbsz_512k;
	int		sf_tsbsz_1m;
	int		sf_tsbsz_2m;
	int		sf_tsbsz_4m;
	int		sf_tsbsz_8m;
	int		sf_tsbsz_16m;
	int		sf_tsbsz_32m;
	int		sf_tsbsz_64m;
	int		sf_tsbsz_128m;
	int		sf_tsbsz_256m;
};

struct sfmmu_percpu_stat {
	int	sf_itlb_misses;		/* # of itlb misses */
	int	sf_dtlb_misses;		/* # of dtlb misses */
	int	sf_utsb_misses;		/* # of user tsb misses */
	int	sf_ktsb_misses;		/* # of kernel tsb misses */
	int	sf_tsb_hits;		/* # of tsb hits */
	int	sf_umod_faults;		/* # of mod (prot viol) flts */
	int	sf_kmod_faults;		/* # of mod (prot viol) flts */
};

#define	SFMMU_STAT(stat)		sfmmu_global_stat.stat++
#define	SFMMU_STAT_ADD(stat, amount)	sfmmu_global_stat.stat += (amount)
#define	SFMMU_STAT_SET(stat, count)	sfmmu_global_stat.stat = (count)

#define	SFMMU_MMU_STAT(stat)		{		\
	mmu_ctx_t *ctx = CPU->cpu_m.cpu_mmu_ctxp;	\
	if (ctx)					\
		ctx->stat++;				\
}

#endif /* !_ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _VM_HAT_SFMMU_H */
