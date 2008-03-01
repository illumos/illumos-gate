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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/archsystm.h>
#include <sys/vmsystm.h>
#include <sys/machparam.h>
#include <sys/machsystm.h>
#include <vm/vm_dep.h>
#include <vm/hat_sfmmu.h>
#include <vm/seg_kmem.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/cpu_module.h>
#include <sys/sysmacros.h>
#include <sys/panic.h>

/*
 * pan_disable_ism_large_pages and pan_disable_large_pages are the Panther-
 * specific versions of disable_ism_large_pages and disable_large_pages,
 * and feed back into those two hat variables at hat initialization time,
 * for Panther-only systems.
 *
 * chpjag_disable_large_pages is the Ch/Jaguar-specific version of
 * disable_large_pages. Ditto for pan_disable_large_pages.
 * Note that the Panther and Ch/Jaguar ITLB do not support 32M/256M pages.
 */
static int panther_only = 0;

static uint_t pan_disable_large_pages = (1 << TTE256M);
static uint_t chjag_disable_large_pages = ((1 << TTE32M) | (1 << TTE256M));

static uint_t mmu_disable_ism_large_pages = ((1 << TTE64K) |
	(1 << TTE512K) | (1 << TTE32M) | (1 << TTE256M));
static uint_t mmu_disable_auto_data_large_pages =  ((1 << TTE64K) |
	(1 << TTE512K) | (1 << TTE32M) | (1 << TTE256M));
static uint_t mmu_disable_auto_text_large_pages =  ((1 << TTE64K) |
	(1 << TTE512K) | (1 << TTE32M) | (1 << TTE256M));

/*
 * The function returns the USIII+(i)-IV+ mmu-specific values for the
 * hat's disable_large_pages and disable_ism_large_pages variables.
 * Currently the hat's disable_large_pages and disable_ism_large_pages
 * already contain the generic sparc 4 page size info, and the return
 * values are or'd with those values.
 */
uint_t
mmu_large_pages_disabled(uint_t flag)
{
	uint_t pages_disable = 0;
	extern int use_text_pgsz64K;
	extern int use_text_pgsz512K;

	if (flag == HAT_LOAD) {
		if (panther_only) {
			pages_disable = pan_disable_large_pages;
		} else {
			pages_disable = chjag_disable_large_pages;
		}
	} else if (flag == HAT_LOAD_SHARE) {
		pages_disable = mmu_disable_ism_large_pages;
	} else if (flag == HAT_AUTO_DATA) {
		pages_disable = mmu_disable_auto_data_large_pages;
	} else if (flag == HAT_AUTO_TEXT) {
		pages_disable = mmu_disable_auto_text_large_pages;
		if (use_text_pgsz512K) {
			pages_disable &= ~(1 << TTE512K);
		}
		if (use_text_pgsz64K) {
			pages_disable &= ~(1 << TTE64K);
		}
	}
	return (pages_disable);
}

#if defined(CPU_IMP_DUAL_PAGESIZE)
/*
 * If a platform is running with only Ch+ or Jaguar, and then someone DR's
 * in a Panther board, the Panther mmu will not like it if one of the already
 * running threads is context switched to the Panther and tries to program
 * a 512K or 4M page into the T512_1. So make these platforms pay the price
 * and follow the Panther DTLB restrictions by default. :)
 * The mmu_init_mmu_page_sizes code below takes care of heterogeneous
 * platforms that don't support DR, like daktari.
 *
 * The effect of these restrictions is to limit the allowable values in
 * sfmmu_pgsz[0] and sfmmu_pgsz[1], since these hat variables are used in
 * mmu_set_ctx_page_sizes to set up the values in the sfmmu_cext that
 * are used at context switch time. The value in sfmmu_pgsz[0] is used in
 * P_pgsz0 and sfmmu_pgsz[1] is used in P_pgsz1, as per Figure F-1-1
 * IMMU and DMMU Primary Context Register in the Panther Implementation
 * Supplement and Table 15-21 DMMU Primary Context Register in the
 * Cheetah+ Delta PRM.
 */
#ifdef MIXEDCPU_DR_SUPPORTED
int panther_dtlb_restrictions = 1;
#else
int panther_dtlb_restrictions = 0;
#endif /* MIXEDCPU_DR_SUPPORTED */

/*
 * init_mmu_page_sizes is set to one after the bootup time initialization
 * via mmu_init_mmu_page_sizes, to indicate that mmu_page_sizes has a
 * valid value.
 */
int init_mmu_page_sizes = 0;

/*
 * mmu_init_large_pages is called with the desired ism_pagesize parameter,
 * for Panther-only systems. It may be called from set_platform_defaults,
 * if some value other than 4M is desired, for Panther-only systems.
 * mmu_ism_pagesize is the tunable.  If it has a bad value, then only warn,
 * since it would be bad form to panic due
 * to a user typo.
 *
 * The function re-initializes the disable_ism_large_pages and
 * pan_disable_large_pages variables, which are closely related.
 * Aka, if 32M is the desired [D]ISM page sizes, then 256M cannot be allowed
 * for non-ISM large page usage, or DTLB conflict will occur. Please see the
 * Panther PRM for additional DTLB technical info.
 */
void
mmu_init_large_pages(size_t ism_pagesize)
{
	if (cpu_impl_dual_pgsz == 0) {	/* disable_dual_pgsz flag */
		pan_disable_large_pages = ((1 << TTE32M) | (1 << TTE256M));
		mmu_disable_ism_large_pages = ((1 << TTE64K) |
		    (1 << TTE512K) | (1 << TTE32M) | (1 << TTE256M));
		mmu_disable_auto_data_large_pages = ((1 << TTE64K) |
		    (1 << TTE512K) | (1 << TTE32M) | (1 << TTE256M));
		return;
	}

	switch (ism_pagesize) {
	case MMU_PAGESIZE4M:
		pan_disable_large_pages = (1 << TTE256M);
		mmu_disable_ism_large_pages = ((1 << TTE64K) |
		    (1 << TTE512K) | (1 << TTE32M) | (1 << TTE256M));
		mmu_disable_auto_data_large_pages = ((1 << TTE64K) |
		    (1 << TTE512K) | (1 << TTE32M) | (1 << TTE256M));
		break;
	case MMU_PAGESIZE32M:
		pan_disable_large_pages = (1 << TTE256M);
		mmu_disable_ism_large_pages = ((1 << TTE64K) |
		    (1 << TTE512K) | (1 << TTE256M));
		mmu_disable_auto_data_large_pages = ((1 << TTE64K) |
		    (1 << TTE512K) | (1 << TTE4M) | (1 << TTE256M));
		adjust_data_maxlpsize(ism_pagesize);
		break;
	case MMU_PAGESIZE256M:
		pan_disable_large_pages = (1 << TTE32M);
		mmu_disable_ism_large_pages = ((1 << TTE64K) |
		    (1 << TTE512K) | (1 << TTE32M));
		mmu_disable_auto_data_large_pages = ((1 << TTE64K) |
		    (1 << TTE512K) | (1 << TTE4M) | (1 << TTE32M));
		adjust_data_maxlpsize(ism_pagesize);
		break;
	default:
		cmn_err(CE_WARN, "Unrecognized mmu_ism_pagesize value 0x%lx",
		    ism_pagesize);
		break;
	}
}

/*
 * Re-initialize mmu_page_sizes and friends, for Panther mmu support.
 * Called during very early bootup from check_cpus_set().
 * Can be called to verify that mmu_page_sizes are set up correctly.
 * Note that ncpus is not initialized at this point in the bootup sequence.
 */
int
mmu_init_mmu_page_sizes(int cinfo)
{
	int npanther = cinfo;

	if (!init_mmu_page_sizes) {
		if (npanther == ncpunode) {
			mmu_page_sizes = MMU_PAGE_SIZES;
			mmu_hashcnt = MAX_HASHCNT;
			mmu_ism_pagesize = DEFAULT_ISM_PAGESIZE;
			mmu_exported_pagesize_mask = (1 << TTE8K) |
			    (1 << TTE64K) | (1 << TTE512K) | (1 << TTE4M) |
			    (1 << TTE32M) | (1 << TTE256M);
			panther_dtlb_restrictions = 1;
			panther_only = 1;
		} else if (npanther > 0) {
			panther_dtlb_restrictions = 1;
		}
		init_mmu_page_sizes = 1;
		return (0);
	}
	return (1);
}


/* Cheetah+ and later worst case DTLB parameters */
#ifndef	LOCKED_DTLB_ENTRIES
#define	LOCKED_DTLB_ENTRIES	5	/* 2 user TSBs, 2 nucleus, + OBP */
#endif
#define	TOTAL_DTLB_ENTRIES	16
#define	AVAIL_32M_ENTRIES	0
#define	AVAIL_256M_ENTRIES	0
#define	AVAIL_DTLB_ENTRIES	(TOTAL_DTLB_ENTRIES - LOCKED_DTLB_ENTRIES)
static uint64_t ttecnt_threshold[MMU_PAGE_SIZES] = {
	AVAIL_DTLB_ENTRIES, AVAIL_DTLB_ENTRIES,
	AVAIL_DTLB_ENTRIES, AVAIL_DTLB_ENTRIES,
	AVAIL_32M_ENTRIES, AVAIL_256M_ENTRIES };

/*
 * The purpose of this code is to indirectly reorganize the sfmmu_pgsz array
 * in order to handle the Panther mmu DTLB requirements. Panther only supports
 * the 32M/256M pages in the T512_1 and not in the T16, so the Panther cpu
 * can only support one of the two largest page sizes at a time (efficiently).
 * Panther only supports 512K and 4M pages in the T512_0, and 32M/256M pages
 * in the T512_1.  So check the sfmmu flags and ttecnt before enabling
 * the T512_1 for 32M or 256M page sizes, and make sure that 512K and 4M
 * requests go to the T512_0.
 *
 * The tmp_pgsz array comes into this routine in sorted order, as it is
 * sorted from largest to smallest #pages per pagesize in use by the hat code,
 * and leaves with the Panther mmu DTLB requirements satisfied. Note that
 * when the array leaves this function it may not contain all of the page
 * size codes that it had coming into the function.
 *
 * Note that for DISM the flag can be set but the ttecnt can be 0, if we
 * didn't fault any pages in. This allows the t512_1 to be reprogrammed,
 * because the T16 does not support the two giant page sizes. ouch.
 */
static void
mmu_fixup_large_pages(struct hat *hat, uint64_t *ttecnt, uint8_t *tmp_pgsz)
{
	uint_t pgsz0 = tmp_pgsz[0];
	uint_t pgsz1 = tmp_pgsz[1];
	uint_t spgsz;

	/*
	 * Don't program 2nd dtlb for kernel and ism hat
	 */
	ASSERT(hat->sfmmu_ismhat == 0);
	ASSERT(hat != ksfmmup);
	ASSERT(cpu_impl_dual_pgsz == 1);

	ASSERT(!SFMMU_TTEFLAGS_ISSET(hat, HAT_32M_FLAG) ||
	    !SFMMU_TTEFLAGS_ISSET(hat, HAT_256M_FLAG));
	ASSERT(!SFMMU_TTEFLAGS_ISSET(hat, HAT_256M_FLAG) ||
	    !SFMMU_TTEFLAGS_ISSET(hat, HAT_32M_FLAG));
	ASSERT(!SFMMU_FLAGS_ISSET(hat, HAT_32M_ISM) ||
	    !SFMMU_FLAGS_ISSET(hat, HAT_256M_ISM));
	ASSERT(!SFMMU_FLAGS_ISSET(hat, HAT_256M_ISM) ||
	    !SFMMU_FLAGS_ISSET(hat, HAT_32M_ISM));

	if (SFMMU_TTEFLAGS_ISSET(hat, HAT_32M_FLAG) ||
	    (ttecnt[TTE32M] != 0) ||
	    SFMMU_FLAGS_ISSET(hat, HAT_32M_ISM)) {

		spgsz = pgsz1;
		pgsz1 = TTE32M;
		if (pgsz0 == TTE32M)
			pgsz0 = spgsz;

	} else if (SFMMU_TTEFLAGS_ISSET(hat, HAT_256M_FLAG) ||
	    (ttecnt[TTE256M] != 0) ||
	    SFMMU_FLAGS_ISSET(hat, HAT_256M_ISM)) {

		spgsz = pgsz1;
		pgsz1 = TTE256M;
		if (pgsz0 == TTE256M)
			pgsz0 = spgsz;

	} else if ((pgsz1 == TTE512K) || (pgsz1 == TTE4M)) {
		if ((pgsz0 != TTE512K) && (pgsz0 != TTE4M)) {
			spgsz = pgsz0;
			pgsz0 = pgsz1;
			pgsz1 = spgsz;
		} else {
			pgsz1 = page_szc(MMU_PAGESIZE);
		}
	}
	/*
	 * This implements PAGESIZE programming of the T8s
	 * if large TTE counts don't exceed the thresholds.
	 */
	if (ttecnt[pgsz0] < ttecnt_threshold[pgsz0])
		pgsz0 = page_szc(MMU_PAGESIZE);
	if (ttecnt[pgsz1] < ttecnt_threshold[pgsz1])
		pgsz1 = page_szc(MMU_PAGESIZE);
	tmp_pgsz[0] = pgsz0;
	tmp_pgsz[1] = pgsz1;
}

/*
 * Function to set up the page size values used to reprogram the DTLBs,
 * when page sizes used by a process change significantly.
 */
static void
mmu_setup_page_sizes(struct hat *hat, uint64_t *ttecnt, uint8_t *tmp_pgsz)
{
	uint_t pgsz0, pgsz1;

	/*
	 * Don't program 2nd dtlb for kernel and ism hat
	 */
	ASSERT(hat->sfmmu_ismhat == NULL);
	ASSERT(hat != ksfmmup);

	if (cpu_impl_dual_pgsz == 0)	/* disable_dual_pgsz flag */
		return;

	/*
	 * hat->sfmmu_pgsz[] is an array whose elements
	 * contain a sorted order of page sizes.  Element
	 * 0 is the most commonly used page size, followed
	 * by element 1, and so on.
	 *
	 * ttecnt[] is an array of per-page-size page counts
	 * mapped into the process.
	 *
	 * If the HAT's choice for page sizes is unsuitable,
	 * we can override it here.  The new values written
	 * to the array will be handed back to us later to
	 * do the actual programming of the TLB hardware.
	 *
	 * The policy we use for programming the dual T8s on
	 * Cheetah+ and beyond is as follows:
	 *
	 *   We have two programmable TLBs, so we look at
	 *   the two most common page sizes in the array, which
	 *   have already been computed for us by the HAT.
	 *   If the TTE count of either of a preferred page size
	 *   exceeds the number of unlocked T16 entries,
	 *   we reprogram one of the T8s to that page size
	 *   to avoid thrashing in the T16.  Else we program
	 *   that T8 to the base page size.  Note that we do
	 *   not force either T8 to be the base page size if a
	 *   process is using more than two page sizes.  Policy
	 *   decisions about which page sizes are best to use are
	 *   left to the upper layers.
	 *
	 *   Note that for Panther, 4M and 512K pages need to be
	 *   programmed into T512_0, and 32M and 256M into T512_1,
	 *   so we don't want to go through the MIN/MAX code.
	 *   For partial-Panther systems, we still want to make sure
	 *   that 4M and 512K page sizes NEVER get into the T512_1.
	 *   Since the DTLB flags are not set up on a per-cpu basis,
	 *   Panther rules must be applied for mixed Panther/Cheetah+/
	 *   Jaguar configurations.
	 */
	if (panther_dtlb_restrictions) {
		if ((tmp_pgsz[1] == TTE512K) || (tmp_pgsz[1] == TTE4M)) {
			if ((tmp_pgsz[0] != TTE512K) &&
			    (tmp_pgsz[0] != TTE4M)) {
				pgsz1 = tmp_pgsz[0];
				pgsz0 = tmp_pgsz[1];
			} else {
				pgsz0 = tmp_pgsz[0];
				pgsz1 = page_szc(MMU_PAGESIZE);
			}
		} else {
			pgsz0 = tmp_pgsz[0];
			pgsz1 = tmp_pgsz[1];
		}
	} else {
		pgsz0 = MIN(tmp_pgsz[0], tmp_pgsz[1]);
		pgsz1 = MAX(tmp_pgsz[0], tmp_pgsz[1]);
	}

	/*
	 * This implements PAGESIZE programming of the T8s
	 * if large TTE counts don't exceed the thresholds.
	 */
	if (ttecnt[pgsz0] < ttecnt_threshold[pgsz0])
		pgsz0 = page_szc(MMU_PAGESIZE);
	if (ttecnt[pgsz1] < ttecnt_threshold[pgsz1])
		pgsz1 = page_szc(MMU_PAGESIZE);
	tmp_pgsz[0] = pgsz0;
	tmp_pgsz[1] = pgsz1;
}

/*
 * The HAT calls this function when an MMU context is allocated so that we
 * can reprogram the large TLBs appropriately for the new process using
 * the context.
 *
 * The caller must hold the HAT lock.
 */
void
mmu_set_ctx_page_sizes(struct hat *hat)
{
	uint_t pgsz0, pgsz1;
	uint_t new_cext;

	ASSERT(sfmmu_hat_lock_held(hat));
	ASSERT(hat != ksfmmup);

	if (cpu_impl_dual_pgsz == 0)	/* disable_dual_pgsz flag */
		return;

	/*
	 * If supported, reprogram the TLBs to a larger pagesize.
	 */
	pgsz0 = hat->sfmmu_pgsz[0];
	pgsz1 = hat->sfmmu_pgsz[1];
	ASSERT(pgsz0 < mmu_page_sizes);
	ASSERT(pgsz1 < mmu_page_sizes);
#ifdef DEBUG
	if (panther_dtlb_restrictions) {
		ASSERT(pgsz1 != TTE512K);
		ASSERT(pgsz1 != TTE4M);
	}
	if (panther_only) {
		ASSERT(pgsz0 != TTE32M);
		ASSERT(pgsz0 != TTE256M);
	}
#endif /* DEBUG */
	new_cext = TAGACCEXT_MKSZPAIR(pgsz1, pgsz0);
	if (hat->sfmmu_cext != new_cext) {
#ifdef DEBUG
		int i;
		/*
		 * assert cnum should be invalid, this is because pagesize
		 * can only be changed after a proc's ctxs are invalidated.
		 */
		for (i = 0; i < max_mmu_ctxdoms; i++) {
			ASSERT(hat->sfmmu_ctxs[i].cnum == INVALID_CONTEXT);
		}
#endif /* DEBUG */
		hat->sfmmu_cext = new_cext;
	}

	/*
	 * sfmmu_setctx_sec() will take care of the
	 * rest of the chores reprogramming the hat->sfmmu_cext
	 * page size values into the DTLBs.
	 */
}

/*
 * This function assumes that there are either four or six supported page
 * sizes and at most two programmable TLBs, so we need to decide which
 * page sizes are most important and then adjust the TLB page sizes
 * accordingly (if supported).
 *
 * If these assumptions change, this function will need to be
 * updated to support whatever the new limits are.
 */
void
mmu_check_page_sizes(sfmmu_t *sfmmup, uint64_t *ttecnt)
{
	uint64_t sortcnt[MMU_PAGE_SIZES];
	uint8_t tmp_pgsz[MMU_PAGE_SIZES];
	uint8_t i, j, max;
	uint16_t oldval, newval;

	/*
	 * We only consider reprogramming the TLBs if one or more of
	 * the two most used page sizes changes and we're using
	 * large pages in this process, except for Panther 32M/256M pages,
	 * which the Panther T16 does not support.
	 */
	if (SFMMU_LGPGS_INUSE(sfmmup)) {
		/* Sort page sizes. */
		for (i = 0; i < mmu_page_sizes; i++) {
			sortcnt[i] = ttecnt[i];
		}
		for (j = 0; j < mmu_page_sizes; j++) {
			for (i = mmu_page_sizes - 1, max = 0; i > 0; i--) {
				if (sortcnt[i] > sortcnt[max])
					max = i;
			}
			tmp_pgsz[j] = max;
			sortcnt[max] = 0;
		}

		/*
		 * Handle Panther page dtlb calcs separately. The check
		 * for actual or potential 32M/256M pages must occur
		 * every time due to lack of T16 support for them.
		 * The sort works fine for Ch+/Jag, but Panther has
		 * pagesize restrictions for both DTLBs.
		 */
		oldval = sfmmup->sfmmu_pgsz[0] << 8 | sfmmup->sfmmu_pgsz[1];

		if (panther_only) {
			mmu_fixup_large_pages(sfmmup, ttecnt, tmp_pgsz);
		} else {
			/* Check 2 largest values after the sort. */
			mmu_setup_page_sizes(sfmmup, ttecnt, tmp_pgsz);
		}
		newval = tmp_pgsz[0] << 8 | tmp_pgsz[1];
		if (newval != oldval) {
			sfmmu_reprog_pgsz_arr(sfmmup, tmp_pgsz);
		}
	}
}

#endif	/* CPU_IMP_DUAL_PAGESIZE */

struct heap_lp_page_size {
	int    impl;
	uint_t tte;
	int    use_dt512;
};

struct heap_lp_page_size heap_lp_pgsz[] = {

	{CHEETAH_IMPL, TTE8K, 0},		/* default */
	{CHEETAH_IMPL, TTE64K, 0},
	{CHEETAH_IMPL, TTE4M, 0},

	{ CHEETAH_PLUS_IMPL, TTE4M,  1 },	/* default */
	{ CHEETAH_PLUS_IMPL, TTE4M,  0 },
	{ CHEETAH_PLUS_IMPL, TTE64K, 1 },
	{ CHEETAH_PLUS_IMPL, TTE64K, 0 },
	{ CHEETAH_PLUS_IMPL, TTE8K,  0 },

	{ JALAPENO_IMPL, TTE4M,  1 },		/* default */
	{ JALAPENO_IMPL, TTE4M,  0 },
	{ JALAPENO_IMPL, TTE64K, 1 },
	{ JALAPENO_IMPL, TTE64K, 0 },
	{ JALAPENO_IMPL, TTE8K,  0 },

	{ JAGUAR_IMPL, TTE4M, 1 },		/* default */
	{ JAGUAR_IMPL, TTE4M, 0 },
	{ JAGUAR_IMPL, TTE64K, 1 },
	{ JAGUAR_IMPL, TTE64K, 0 },
	{ JAGUAR_IMPL, TTE8K, 0 },

	{ SERRANO_IMPL, TTE4M,  1 },		/* default */
	{ SERRANO_IMPL, TTE4M,  0 },
	{ SERRANO_IMPL, TTE64K, 1 },
	{ SERRANO_IMPL, TTE64K, 0 },
	{ SERRANO_IMPL, TTE8K,  0 },

	{ PANTHER_IMPL, TTE4M, 1 },		/* default */
	{ PANTHER_IMPL, TTE4M, 0 },
	{ PANTHER_IMPL, TTE64K, 1 },
	{ PANTHER_IMPL, TTE64K, 0 },
	{ PANTHER_IMPL, TTE8K, 0 }
};

int	heaplp_use_dt512 = -1;

void
mmu_init_kernel_pgsz(struct hat *hat)
{
	uint_t tte = page_szc(segkmem_lpsize);
	uchar_t new_cext_primary, new_cext_nucleus;

	if (heaplp_use_dt512 == 0 || tte > TTE4M) {
		/* do not reprogram dt512 tlb */
		tte = TTE8K;
	}

	new_cext_nucleus = TAGACCEXT_MKSZPAIR(tte, TTE8K);
	new_cext_primary = TAGACCEXT_MKSZPAIR(TTE8K, tte);

	hat->sfmmu_cext = new_cext_primary;
	kcontextreg = ((uint64_t)new_cext_nucleus << CTXREG_NEXT_SHIFT) |
	    ((uint64_t)new_cext_primary << CTXREG_EXT_SHIFT);
}

size_t
mmu_get_kernel_lpsize(size_t lpsize)
{
	struct heap_lp_page_size *p_lpgsz, *pend_lpgsz;
	int impl = cpunodes[getprocessorid()].implementation;
	uint_t tte = TTE8K;

	if (cpu_impl_dual_pgsz == 0) {
		heaplp_use_dt512 = 0;
		return (MMU_PAGESIZE);
	}

	pend_lpgsz = (struct heap_lp_page_size *)
	    ((char *)heap_lp_pgsz + sizeof (heap_lp_pgsz));

	/* search for a valid segkmem_lpsize */
	for (p_lpgsz = heap_lp_pgsz; p_lpgsz < pend_lpgsz; p_lpgsz++) {
		if (impl != p_lpgsz->impl)
			continue;

		if (lpsize == 0) {
			/*
			 * no setting for segkmem_lpsize in /etc/system
			 * use default from the table
			 */
			tte = p_lpgsz->tte;
			heaplp_use_dt512 = p_lpgsz->use_dt512;
			break;
		}

		if (lpsize == TTEBYTES(p_lpgsz->tte) &&
		    (heaplp_use_dt512 == -1 ||
		    heaplp_use_dt512 == p_lpgsz->use_dt512)) {

			tte = p_lpgsz->tte;
			heaplp_use_dt512 = p_lpgsz->use_dt512;

			/* found a match */
			break;
		}
	}

	if (p_lpgsz == pend_lpgsz) {
		/* nothing found: disable large page kernel heap */
		tte = TTE8K;
		heaplp_use_dt512 = 0;
	}

	lpsize = TTEBYTES(tte);

	return (lpsize);
}
