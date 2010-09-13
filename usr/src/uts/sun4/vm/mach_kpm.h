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

#ifndef	_MACH_KPM_H
#define	_MACH_KPM_H

#ifdef	__cplusplus
extern "C" {
#endif

/* kpm prototypes : routines defined in uts/sfmmu/vm/hat_sfmmu.c file */
extern kmutex_t *sfmmu_page_enter(page_t *);
extern void	sfmmu_page_exit(kmutex_t *);
extern void	sfmmu_cache_flush(pfn_t, int);
extern void	sfmmu_page_cache_array(page_t *, int, int, pgcnt_t);
extern cpuset_t	sfmmu_pageunload(page_t *, struct sf_hment *, int);
extern int	tst_tnc(page_t *pp, pgcnt_t);
extern void	conv_tnc(page_t *pp, int);
extern int	fnd_mapping_sz(page_t *);
extern int	sfmmu_page_spl_held(struct page *);

/* kpm prototypes : routines defined in uts/sun4[uv]/vm/mach_kpm.c file */
extern void	sfmmu_kpm_pageunload(page_t *);
extern void	sfmmu_kpm_vac_unload(page_t *, caddr_t);
extern void	sfmmu_kpm_hme_unload(page_t *);
extern kpm_hlk_t *sfmmu_kpm_kpmp_enter(page_t *, pgcnt_t);
extern void	sfmmu_kpm_kpmp_exit(kpm_hlk_t *kpmp);
extern void	sfmmu_kpm_page_cache(page_t *, int, int);

/* flags for hat_pagecachectl */
#define	HAT_CACHE	0x1
#define	HAT_UNCACHE	0x2
#define	HAT_TMPNC	0x4

/*
 * kstat data
 */
struct sfmmu_global_stat sfmmu_global_stat;

/* kpm globals */
#ifdef	DEBUG
/*
 * Flush the TLB on kpm mapout. Note: Xcalls are used (again) for the
 * required TLB shootdowns in this case, so handle w/ care. Off by default.
 */
int	kpm_tlb_flush;
#endif	/* DEBUG */

/*
 * kpm_page lock hash.
 * All slots should be used equally and 2 adjacent kpm_page_t's
 * shouldn't have their mutexes in the same cache line.
 */
#ifdef	DEBUG
int kpmp_hash_debug;
#define	KPMP_HASH(kpp)	(kpmp_hash_debug ? &kpmp_table[0] : &kpmp_table[ \
	((uintptr_t)(kpp) + ((uintptr_t)(kpp) >> kpmp_shift)) \
	& (kpmp_table_sz - 1)])
#else	/* !DEBUG */
#define	KPMP_HASH(kpp)	&kpmp_table[ \
	((uintptr_t)(kpp) + ((uintptr_t)(kpp) >> kpmp_shift)) \
	& (kpmp_table_sz - 1)]
#endif	/* DEBUG */

#ifdef	DEBUG
#define	KPMP_SHASH(kpp)	(kpmp_hash_debug ? &kpmp_stable[0] : &kpmp_stable[ \
	(((uintptr_t)(kpp) << kpmp_shift) + (uintptr_t)(kpp)) \
	& (kpmp_stable_sz - 1)])
#else	/* !DEBUG */
#define	KPMP_SHASH(kpp)	&kpmp_stable[ \
	(((uintptr_t)(kpp) << kpmp_shift) + (uintptr_t)(kpp)) \
	& (kpmp_stable_sz - 1)]
#endif	/* DEBUG */

/*
 * kpm virtual address to physical address. Any changes in this macro must
 * also be ported to the assembly implementation in sfmmu_asm.s
 */
#ifdef VAC
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
#else	/* VAC */
#define	SFMMU_KPM_VTOP(vaddr, paddr) {					\
	(paddr) = (vaddr) - kpm_vbase;					\
}
#endif	/* VAC */

#ifdef	__cplusplus
}
#endif

#endif	/* _MACH_KPM_H */
