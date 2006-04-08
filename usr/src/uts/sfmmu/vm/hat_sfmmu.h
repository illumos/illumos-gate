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

/*
 * VM - Hardware Address Translation management.
 *
 * This file describes the contents of the sun-reference-mmu(sfmmu)-
 * specific hat data structures and the sfmmu-specific hat procedures.
 * The machine-independent interface is described in <vm/hat.h>.
 */

#ifndef	_VM_HAT_SFMMU_H
#define	_VM_HAT_SFMMU_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#define	PP_ISTNC(pp)		((pp)->p_nrm & P_TNC)
#define	PP_ISKPMS(pp)		((pp)->p_nrm & P_KPMS)
#define	PP_ISKPMC(pp)		((pp)->p_nrm & P_KPMC)

#define	PP_SETMOD(pp)		((pp)->p_nrm |= P_MOD)
#define	PP_SETREF(pp)		((pp)->p_nrm |= P_REF)
#define	PP_SETREFMOD(pp)	((pp)->p_nrm |= (P_REF|P_MOD))
#define	PP_SETRO(pp)		((pp)->p_nrm |= P_RO)
#define	PP_SETREFRO(pp)		((pp)->p_nrm |= (P_REF|P_RO))
#define	PP_SETPNC(pp)		((pp)->p_nrm |= P_PNC)
#define	PP_SETTNC(pp)		((pp)->p_nrm |= P_TNC)
#define	PP_SETKPMS(pp)		((pp)->p_nrm |= P_KPMS)
#define	PP_SETKPMC(pp)		((pp)->p_nrm |= P_KPMC)

#define	PP_CLRMOD(pp)		((pp)->p_nrm &= ~P_MOD)
#define	PP_CLRREF(pp)		((pp)->p_nrm &= ~P_REF)
#define	PP_CLRREFMOD(pp)	((pp)->p_nrm &= ~(P_REF|P_MOD))
#define	PP_CLRRO(pp)		((pp)->p_nrm &= ~P_RO)
#define	PP_CLRPNC(pp)		((pp)->p_nrm &= ~P_PNC)
#define	PP_CLRTNC(pp)		((pp)->p_nrm &= ~P_TNC)
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
	ushort_t	imap_vb_shift;	/* mmu_pageshift for ism page size */
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

/*
 * The platform dependent hat structure.
 * tte counts should be protected by cas.
 * cpuset is protected by cas.
 *
 * Note that sfmmu_xhat_provider MUST be the first element.
 */
struct hat {
	void		*sfmmu_xhat_provider;	/* NULL for CPU hat */
	cpuset_t	sfmmu_cpusran;	/* cpu bit mask for efficient xcalls */
	struct	as	*sfmmu_as;	/* as this hat provides mapping for */
	ulong_t		sfmmu_ttecnt[MMU_PAGE_SIZES]; /* per sz tte counts */
	ulong_t		sfmmu_ismttecnt[MMU_PAGE_SIZES]; /* est. ism ttes */
	union _h_un {
		ism_blk_t	*sfmmu_iblkp;  /* maps to ismhat(s) */
		ism_ment_t	*sfmmu_imentp; /* ism hat's mapping list */
	} h_un;
	uint_t		sfmmu_free:1;	/* hat to be freed - set on as_free */
	uint_t		sfmmu_ismhat:1;	/* hat is dummy ism hatid */
	uint_t		sfmmu_ctxflushed:1;	/* ctx has been flushed */
	uchar_t		sfmmu_rmstat;	/* refmod stats refcnt */
	uchar_t		sfmmu_clrstart;	/* start color bin for page coloring */
	ushort_t	sfmmu_clrbin;	/* per as phys page coloring bin */
	short		sfmmu_cnum;	/* context number */
	ushort_t	sfmmu_flags;	/* flags */
	struct tsb_info	*sfmmu_tsb;	/* list of per as tsbs */
	uint64_t	sfmmu_ismblkpa; /* pa of sfmmu_iblkp, or -1 */
	kcondvar_t	sfmmu_tsb_cv;	/* signals TSB swapin or relocation */
	uchar_t		sfmmu_cext;	/* context page size encoding */
	uint8_t		sfmmu_pgsz[MMU_PAGE_SIZES];  /* ranking for MMU */
#ifdef sun4v
	struct hv_tsb_block sfmmu_hvblock;
#endif
};

#define	sfmmu_iblk	h_un.sfmmu_iblkp
#define	sfmmu_iment	h_un.sfmmu_imentp

/*
 * bit mask for managing vac conflicts on large pages.
 * bit 1 is for uncache flag.
 * bits 2 through min(num of cache colors + 1,31) are
 * for cache colors that have already been flushed.
 */
#define	CACHE_UNCACHE		1
#define	CACHE_NUM_COLOR		(shm_alignment >> MMU_PAGESHIFT)

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

/*
 * Software context structure.  The size of this structure is currently
 * hardwired into the tsb miss handlers in assembly code through the
 * CTX_SZ_SHIFT define.  Since this define is used in a shift we should keep
 * this structure a power of two.
 *
 * ctx_flags:
 * Bit 0 : Free flag.
 */
struct ctx {
	union _ctx_un {
		sfmmu_t *ctx_sfmmup;	/* back pointer to hat id */
		struct ctx *ctx_freep;	/* next ctx in freelist */
	} ctx_un;
	krwlock_t	ctx_rwlock;	/* protect context from stealer */
	uint32_t	ctx_flags;	/* flags */
	uint8_t		pad[12];
};

#define	ctx_sfmmu	ctx_un.ctx_sfmmup
#define	ctx_free	ctx_un.ctx_freep

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
	(ptr)->sc_time = lbolt;						\
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

/*
 * sfmmu HAT flags
 */
#define	HAT_64K_FLAG	0x01
#define	HAT_512K_FLAG	0x02
#define	HAT_4M_FLAG	0x04
#define	HAT_32M_FLAG	0x08
#define	HAT_256M_FLAG	0x10
#define	HAT_4MTEXT_FLAG	0x80
#define	HAT_SWAPPED	0x100	/* swapped out */
#define	HAT_SWAPIN	0x200	/* swapping in */
#define	HAT_BUSY	0x400	/* replacing TSB(s) */
#define	HAT_ISMBUSY	0x800	/* adding/removing/traversing ISM maps */

#define	HAT_LGPG_FLAGS						\
	(HAT_64K_FLAG | HAT_512K_FLAG | HAT_4M_FLAG |		\
	    HAT_32M_FLAG | HAT_256M_FLAG)

#define	HAT_FLAGS_MASK						\
	(HAT_LGPG_FLAGS | HAT_4MTEXT_FLAG | HAT_SWAPPED |	\
	    HAT_SWAPIN | HAT_BUSY | HAT_ISMBUSY)

/*
 * Context flags
 */
#define	CTX_FREE_FLAG		0x1
#define	CTX_FLAGS_MASK		0x1

#define	CTX_SET_FLAGS(ctx, flag)					\
{									\
	uint32_t old, new;						\
									\
	do {								\
		new = old = (ctx)->ctx_flags;				\
		new &= CTX_FLAGS_MASK;					\
		new |= flag;						\
		new = cas32(&(ctx)->ctx_flags, old, new);		\
	} while (new != old);						\
}

#define	CTX_CLEAR_FLAGS(ctx, flag)					\
{									\
	uint32_t old, new;						\
									\
	do {								\
		new = old = (ctx)->ctx_flags;				\
		new &= CTX_FLAGS_MASK & ~(flag);			\
		new = cas32(&(ctx)->ctx_flags, old, new);		\
	} while (new != old);						\
}

#define	ctxtoctxnum(ctx)	((ushort_t)((ctx) - ctxs))

/*
 * Defines needed for ctx stealing.
 */
#define	GET_CTX_RETRY_CNT	100

/*
 * Starting with context 0, the first NUM_LOCKED_CTXS contexts
 * are locked so that sfmmu_getctx can't steal any of these
 * contexts.  At the time this software was being developed, the
 * only context that needs to be locked is context 0 (the kernel
 * context), and context 1 (reserved for stolen context). So this constant
 * was originally defined to be 2.
 */
#define	NUM_LOCKED_CTXS 2
#define	INVALID_CONTEXT	1

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

extern int hat_kpr_enabled;

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

typedef union {
	struct {
		uint64_t	hblk_basepg: 51, /* hme_blk base pg # */
				hblk_rehash: 13; /* rehash number */
		sfmmu_t		*sfmmup;
	} hblk_tag_un;
	uint64_t		htag_tag[2];
} hmeblk_tag;

#define	htag_id		hblk_tag_un.sfmmup
#define	htag_bspage	hblk_tag_un.hblk_basepg
#define	htag_rehash	hblk_tag_un.hblk_rehash

#define	HTAGS_EQ(tag1, tag2)	(((tag1.htag_tag[0] ^ tag2.htag_tag[0]) | \
				(tag1.htag_tag[1] ^ tag2.htag_tag[1])) == 0)
#define	HME_REHASH(sfmmup)						\
	((sfmmup)->sfmmu_ttecnt[TTE512K] != 0 ||			\
	(sfmmup)->sfmmu_ttecnt[TTE4M] != 0 ||				\
	(sfmmup)->sfmmu_ttecnt[TTE32M] != 0 ||				\
	(sfmmup)->sfmmu_ttecnt[TTE256M] != 0)

#endif /* !_ASM */

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
	ushort_t locked_cnt;	/* HAT_LOAD_LOCK ref cnt */
	uint_t	notused:10;
	uint_t	xhat_bit:1;	/* set for an xhat hme_blk */
	uint_t	shadow_bit:1;	/* set for a shadow hme_blk */
	uint_t	nucleus_bit:1;	/* set for a nucleus hme_blk */
	uint_t	ttesize:3;	/* contains ttesz of hmeblk */
};

struct hme_blk {
	uint64_t	hblk_nextpa;	/* physical address for hash list */

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

#ifdef	HBLK_TRACE
	kmutex_t	hblk_audit_lock;	/* lock to protect index */
	uint_t		hblk_audit_index;	/* index into audit_cache */
	struct	hblk_lockcnt_audit hblk_audit_cache[HBLK_AUDIT_CACHE_SIZE];
#endif	/* HBLK_AUDIT */

	struct sf_hment hblk_hme[1];	/* hment array */
};

#define	hblk_lckcnt	hblk_misc.locked_cnt
#define	hblk_xhat_bit   hblk_misc.xhat_bit
#define	hblk_shw_bit	hblk_misc.shadow_bit
#define	hblk_nuc_bit	hblk_misc.nucleus_bit
#define	hblk_ttesz	hblk_misc.ttesize
#define	hblk_hmecnt	hblk_un.hblk_counts.hblk_hmecount
#define	hblk_vcnt	hblk_un.hblk_counts.hblk_validcnt
#define	hblk_shw_mask	hblk_un.hblk_shadow_mask

#define	MAX_HBLK_LCKCNT	0xFFFF
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
	uint64_t	hmeh_nextpa;	/* physical address for hash list */
	struct hme_blk *hmeblkp;
	uint_t		hmeh_listlock;
};

#endif /* !_ASM */


/*
 * The tsb miss handlers written in assembly know that sfmmup
 * is a 64 bit ptr.
 *
 * The bspage and re-hash part is 64 bits, with the sfmmup being another 64
 * bits.
 */
#define	HTAG_SFMMUPSZ		0	/* Not really used for LP64 */
#define	HTAG_REHASHSZ		13

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

#define	vaddr_to_vshift(hblktag, vaddr, shwsz)				\
	((((uintptr_t)(vaddr) >> MMU_PAGESHIFT) - (hblktag.htag_bspage)) >>\
	TTE_BSZS_SHIFT((shwsz) - 1))

#define	HME8BLK_SZ	(sizeof (struct hme_blk) + \
			(NHMENTS - 1) * sizeof (struct sf_hment))
#define	HME1BLK_SZ	(sizeof (struct hme_blk))
#define	H8TOH1		(MMU_PAGESIZE4M / MMU_PAGESIZE)
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
#define	MAX_HASHCNT		5
#define	DEFAULT_MAX_HASHCNT	3

#ifndef _ASM

#define	HASHADDR_MASK(hashno)	TTE_PAGEMASK(hashno)

#define	HME_HASH_SHIFT(ttesz)						\
	((ttesz == TTE8K)? HBLK_RANGE_SHIFT : TTE_PAGE_SHIFT(ttesz))	\

#define	HME_HASH_ADDR(vaddr, hmeshift)					\
	((caddr_t)(((uintptr_t)(vaddr) >> (hmeshift)) << (hmeshift)))

#define	HME_HASH_BSPAGE(vaddr, hmeshift)				\
	(((uintptr_t)(vaddr) >> (hmeshift)) << ((hmeshift) - MMU_PAGESHIFT))

#define	HME_HASH_REHASH(ttesz)						\
	(((ttesz) < TTE512K)? 1 : (ttesz))

#define	HME_HASH_FUNCTION(hatid, vaddr, shift)				\
	((hatid != KHATID)?						\
	(&uhme_hash[ (((uintptr_t)(hatid) ^ ((uintptr_t)vaddr >> (shift))) & \
	    UHMEHASH_SZ) ]):					\
	(&khme_hash[ (((uintptr_t)(hatid) ^ ((uintptr_t)vaddr >> (shift))) & \
	    KHMEHASH_SZ) ]))

/*
 * This macro will traverse a hmeblk hash link list looking for an hme_blk
 * that owns the specified vaddr and hatid.  If if doesn't find one , hmeblkp
 * will be set to NULL, otherwise it will point to the correct hme_blk.
 * This macro also cleans empty hblks.
 */
#define	HME_HASH_SEARCH_PREV(hmebp, hblktag, hblkp, hblkpa,		\
	pr_hblk, prevpa, listp)						\
{									\
	struct hme_blk *nx_hblk;					\
	uint64_t 	nx_pa;						\
									\
	ASSERT(SFMMU_HASH_LOCK_ISHELD(hmebp));				\
	hblkp = hmebp->hmeblkp;						\
	hblkpa = hmebp->hmeh_nextpa;					\
	prevpa = 0;							\
	pr_hblk = NULL;							\
	while (hblkp) {							\
		if (HTAGS_EQ(hblkp->hblk_tag, hblktag)) {		\
			/* found hme_blk */				\
			break;						\
		}							\
		nx_hblk = hblkp->hblk_next;				\
		nx_pa = hblkp->hblk_nextpa;				\
		if (!hblkp->hblk_vcnt && !hblkp->hblk_hmecnt) {		\
			sfmmu_hblk_hash_rm(hmebp, hblkp, prevpa, pr_hblk); \
			sfmmu_hblk_free(hmebp, hblkp, hblkpa, listp);   \
		} else {						\
			pr_hblk = hblkp;				\
			prevpa = hblkpa;				\
		}							\
		hblkp = nx_hblk;					\
		hblkpa = nx_pa;						\
	}								\
}

#define	HME_HASH_SEARCH(hmebp, hblktag, hblkp, listp)			\
{									\
	struct hme_blk *pr_hblk;					\
	uint64_t hblkpa, prevpa;					\
									\
	HME_HASH_SEARCH_PREV(hmebp, hblktag, hblkp, hblkpa, pr_hblk,	\
		prevpa, listp);						\
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
	}								\


#define	SFMMU_HASH_LOCK(hmebp)						\
		(mutex_enter(&hmebp->hmehash_mutex))

#define	SFMMU_HASH_UNLOCK(hmebp)					\
		(mutex_exit(&hmebp->hmehash_mutex))

#define	SFMMU_HASH_LOCK_TRYENTER(hmebp)					\
		(mutex_tryenter(&hmebp->hmehash_mutex))

#define	SFMMU_HASH_LOCK_ISHELD(hmebp)					\
		(mutex_owned(&hmebp->hmehash_mutex))

#define	SFMMU_XCALL_STATS(ctxnum)					\
{									\
	if (ctxnum == KCONTEXT) {					\
		SFMMU_STAT(sf_kernel_xcalls);				\
	} else {							\
		SFMMU_STAT(sf_user_xcalls);				\
	}								\
}

#define	astosfmmu(as)		((as)->a_hat)
#define	sfmmutoctxnum(sfmmup)	((sfmmup)->sfmmu_cnum)
#define	sfmmutoctx(sfmmup)	(&ctxs[sfmmutoctxnum(sfmmup)])
#define	hblktosfmmu(hmeblkp)	((sfmmu_t *)(hmeblkp)->hblk_tag.htag_id)
#define	sfmmutoas(sfmmup)	((sfmmup)->sfmmu_as)
#define	ctxnumtoctx(ctxnum)	(&ctxs[ctxnum])
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
	sfmmu_t		*dmr_sfmmup;	/* relevent hat */
	caddr_t		dmr_addr;	/* beginning address */
	caddr_t		dmr_endaddr;	/* ending  address */
	ulong_t		dmr_bitvec;	/* valid pages found */
	ulong_t		dmr_bit;	/* next page to examine */
	ulong_t		dmr_maxbit;	/* highest page in range */
	ulong_t		dmr_pgsz;	/* page size in range */
} demap_range_t;

#define	DMR_MAXBIT ((ulong_t)1<<63) /* dmr_bit high bit */

#define	DEMAP_RANGE_INIT(sfmmup, dmrp) \
	if ((dmrp) != NULL) { \
	(dmrp)->dmr_sfmmup = (sfmmup); \
	(dmrp)->dmr_bitvec = 0; \
	(dmrp)->dmr_maxbit = sfmmu_dmr_maxbit; \
	(dmrp)->dmr_pgsz = MMU_PAGESIZE; \
	}

#define	DEMAP_RANGE_PGSZ(dmrp) ((dmrp)? (dmrp)->dmr_pgsz : MMU_PAGESIZE)

#define	DEMAP_RANGE_CONTINUE(dmrp, addr, endaddr) \
	if ((dmrp) != NULL) { \
	if ((dmrp)->dmr_bitvec != 0 && (dmrp)->dmr_endaddr != (addr)) \
		sfmmu_tlb_range_demap(dmrp); \
	(dmrp)->dmr_endaddr = (endaddr); \
	}

#define	DEMAP_RANGE_FLUSH(dmrp) \
	if ((dmrp) != NULL) { \
		if ((dmrp)->dmr_bitvec != 0) \
			sfmmu_tlb_range_demap(dmrp); \
	}

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
	struct tsbe		*tsbptr;	/* hardware computed ptr */
	struct tsbe		*tsbptr4m;	/* hardware computed ptr */
	uint64_t		ismblkpa;
	struct hmehash_bucket	*khashstart;
	struct hmehash_bucket	*uhashstart;
	uint_t			khashsz;
	uint_t			uhashsz;
	uint16_t 		dcache_line_mask; /* used to flush dcache */
	uint16_t		hat_flags;
	uint32_t		itlb_misses;
	uint32_t		dtlb_misses;
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
	uint8_t			pad[0x10];
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

extern uint_t  tsb_slab_size;
extern uint_t  tsb_slab_shift;
extern uint_t  tsb_slab_ttesz;
extern uint_t  tsb_slab_pamask;

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

#define	UTSB_MAX_SZCODE		TSB_1M_SZCODE /* max. supported TSB size */
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
 * requires a definition of SCRATCHPAD_UTSBREG in mach_sfmmu.h.  The layout for
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
 * Macro to get this CPU's tsbmiss area.
 */
#define	CPU_TSBMISS_AREA(tsbmiss, tmp1)					\
	CPU_INDEX(tmp1, tsbmiss);		/* tmp1 = cpu idx */	\
	sethi	%hi(tsbmiss_area), tsbmiss;	/* tsbmiss base ptr */	\
	sllx    tmp1, TSBMISS_SHIFT, tmp1;	/* byte offset */	\
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

#endif	/* _ASM */

#ifndef _ASM

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
extern void	sfmmu_ctx_steal_tl1(uint64_t, uint64_t);
extern void	sfmmu_raise_tsb_exception(uint64_t, uint64_t);
#ifndef sun4v
extern void	sfmmu_itlb_ld(caddr_t, int, tte_t *);
extern void	sfmmu_dtlb_ld(caddr_t, int, tte_t *);
#endif /* sun4v */
extern void	sfmmu_copytte(tte_t *, tte_t *);
extern int	sfmmu_modifytte(tte_t *, tte_t *, tte_t *);
extern int	sfmmu_modifytte_try(tte_t *, tte_t *, tte_t *);
extern pfn_t	sfmmu_ttetopfn(tte_t *, caddr_t);
extern void	sfmmu_hblk_hash_rm(struct hmehash_bucket *,
			struct hme_blk *, uint64_t, struct hme_blk *);
extern void	sfmmu_hblk_hash_add(struct hmehash_bucket *, struct hme_blk *,
			uint64_t);

/*
 * functions exported to machine dependent VM code
 */
extern void	sfmmu_patch_ktsb(void);
#ifndef UTSB_PHYS
extern void	sfmmu_patch_utsb(void);
#endif /* UTSB_PHYS */
extern pfn_t	sfmmu_vatopfn(caddr_t, sfmmu_t *, tte_t *);
extern void	sfmmu_vatopfn_suspended(caddr_t, sfmmu_t *, tte_t *);
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
extern void	sfmmu_setctx_sec(int);
extern void	sfmmu_inv_tsb(caddr_t, uint_t);
extern void	sfmmu_init_ktsbinfo(void);
extern int	sfmmu_setup_4lp(void);
extern void	sfmmu_patch_mmu_asi(int);
extern void	sfmmu_init_nucleus_hblks(caddr_t, size_t, int, int);
extern void	sfmmu_cache_flushall(void);
extern pgcnt_t  sfmmu_tte_cnt(sfmmu_t *, uint_t);
extern void	*sfmmu_tsb_segkmem_alloc(vmem_t *, size_t, int);
extern void	sfmmu_tsb_segkmem_free(vmem_t *, void *, size_t);
extern void	sfmmu_steal_context(sfmmu_t *, uint8_t *);

extern void	hat_kern_setup(void);
extern int	hat_page_relocate(page_t **, page_t **, spgcnt_t *);
extern uint_t	hat_preferred_pgsz(struct hat *, caddr_t, size_t, int);
extern int	sfmmu_get_ppvcolor(struct page *);
extern int	sfmmu_get_addrvcolor(caddr_t);
extern int	sfmmu_hat_lock_held(sfmmu_t *);

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
#pragma weak mmu_large_pages_disabled
#pragma weak mmu_set_ctx_page_sizes
#pragma weak mmu_preferred_pgsz
#pragma weak mmu_check_page_sizes

extern int mmu_large_pages_disabled(uint_t);
extern void mmu_set_ctx_page_sizes(sfmmu_t *);
extern uint_t mmu_preferred_pgsz(sfmmu_t *, caddr_t, size_t);
extern void mmu_check_page_sizes(sfmmu_t *, uint64_t *);

extern sfmmu_t 		*ksfmmup;
extern struct ctx	*ctxs;
extern uint_t		nctxs;
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
extern kmutex_t		*mml_table;
extern uint_t		mml_table_sz;
extern uint_t		mml_shift;
extern uint_t		hblk_alloc_dynamic;
extern struct tsbmiss	tsbmiss_area[NCPU];
extern struct kpmtsbm	kpmtsbm_area[NCPU];
extern int		tsb_max_growsize;
#ifndef sun4v
extern int		dtlb_resv_ttenum;
extern caddr_t		utsb_vabase;
extern caddr_t		utsb4m_vabase;
#endif /* sun4v */
extern vmem_t		*kmem_tsb_default_arena[];
extern int		tsb_lgrp_affinity;

/* kpm externals */
extern pfn_t		sfmmu_kpm_vatopfn(caddr_t);
extern void		sfmmu_kpm_patch_tlbm(void);
extern void		sfmmu_kpm_patch_tsbm(void);
extern void		sfmmu_kpm_load_tsb(caddr_t, tte_t *, int);
extern void		sfmmu_kpm_unload_tsb(caddr_t, int);
extern void		sfmmu_kpm_tsbmtl(short *, uint_t *, int);
extern int		sfmmu_kpm_stsbmtl(char *, uint_t *, int);
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

/* kpm_smallpages kp_mapped values */
#define	KPM_MAPPEDS		-1	/* small mapping valid, no conflict */
#define	KPM_MAPPEDSC		1	/* small mapping valid, conflict */

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

	int		sf_ctxfree;		/* ctx alloc from free list */
	int		sf_ctxdirty;		/* ctx alloc from dirty list */
	int		sf_ctxsteal;		/* ctx allocated by steal */

	int		sf_tsb_alloc;		/* # TSB allocations */
	int		sf_tsb_allocfail;	/* # times TSB alloc fail */
	int		sf_tsb_sectsb_create;	/* # times second TSB added */

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

	int		sf_ctx_swap;		/* # times switched MMU ctxs */
	int		sf_tlbflush_all;	/* # times flush all TLBs */
	int		sf_tlbflush_ctx;	/* # times flush TLB ctx */
	int		sf_tlbflush_deferred;	/* # times !flush ctx imm. */

	int		sf_tlb_reprog_pgsz;	/* # times switch TLB pgsz */
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

#define	SFMMU_STAT(stat)		sfmmu_global_stat.stat++;
#define	SFMMU_STAT_ADD(stat, amount)	sfmmu_global_stat.stat += amount;
#define	SFMMU_STAT_SET(stat, count)	sfmmu_global_stat.stat = count;

#endif /* !_ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _VM_HAT_SFMMU_H */
