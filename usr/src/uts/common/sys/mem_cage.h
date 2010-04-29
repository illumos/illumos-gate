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
 * Copyright (c) 1997, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_MEM_CAGE_H
#define	_SYS_MEM_CAGE_H

#include <sys/types.h>
#include <sys/memlist.h>

/*
 * Memory caging interfaces.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#define	KCT_FAILURE	0
#define	KCT_CRIT	1
#define	KCT_NONCRIT	2

extern int kernel_cage_enable;
extern int kcage_on;
extern kthread_id_t kcage_cageout_thread;
extern pgcnt_t kcage_freemem;
extern pgcnt_t kcage_needfree;
extern pgcnt_t kcage_lotsfree;
extern pgcnt_t kcage_desfree;
extern pgcnt_t kcage_minfree;
extern pgcnt_t kcage_throttlefree;

extern void kcage_freemem_add(pgcnt_t);
extern void kcage_freemem_sub(pgcnt_t);
extern int kcage_create_throttle(pgcnt_t, int);

/*
 * Control direction of growth: 0: increasing pfns, 1: decreasing.
 */
typedef enum {KCAGE_UP, KCAGE_DOWN} kcage_dir_t;
extern void kcage_range_init(struct memlist *, kcage_dir_t, pgcnt_t);
extern int kcage_range_add(pfn_t, pgcnt_t, kcage_dir_t);

extern int kcage_current_pfn(pfn_t *);
extern int kcage_range_delete(pfn_t, pgcnt_t);
extern int kcage_range_delete_post_mem_del(pfn_t, pgcnt_t);

extern void kcage_recalc_thresholds(void);

/* Called from vm_pageout.c */
extern void kcage_cageout_init(void);
extern void kcage_cageout_wakeup(void);

/* Called from clock thread in clock.c */
extern void kcage_tick(void);

/* Called from vm_pagelist.c */
extern int kcage_next_range(int incage,
    pfn_t lo, pfn_t hi, pfn_t *nlo, pfn_t *nhi);

extern kcage_dir_t kcage_startup_dir;

#if defined(__sparc)
/* Macros to throttle memory allocations from the kernel cage. */

#define	KERNEL_THROTTLE_NONCRIT(npages, flags)			\
	(kcage_create_throttle(1, flags) == KCT_NONCRIT)

#define	KERNEL_THROTTLE(npages, flags)				\
	if (((flags) & PG_NORELOC) &&				\
	    (kcage_freemem < (kcage_throttlefree + (npages)))) {  \
		(void) kcage_create_throttle(npages, flags);	\
	}


#define	KERNEL_THROTTLE_PGCREATE(npages, flags, cond)			\
	((((flags) & (PG_NORELOC|(cond)) ==  (PG_NORELOC|(cond))) &&	\
	    (kcage_freemem < (kcage_throttlefree + (npages)))	   &&	\
	    (kcage_create_throttle(npages, flags) == KCT_FAILURE)) ? \
	    1 : 0)

#define	KERNEL_NOT_THROTTLED(flags) (!kcage_on || !((flags) & PG_NORELOC))
#endif /* __sparc */

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MEM_CAGE_H */
