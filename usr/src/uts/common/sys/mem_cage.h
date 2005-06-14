/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_MEM_CAGE_H
#define	_SYS_MEM_CAGE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

/* Third arg controls direction of growth: 0: increasing pfns, 1: decreasing. */
extern int kcage_range_trylock(void);
extern void kcage_range_lock(void);
extern void kcage_range_unlock(void);
extern int kcage_current_pfn(pfn_t *);
extern int kcage_range_islocked(void);
extern int kcage_range_init(struct memlist *, int);
extern int kcage_range_add(pfn_t, pgcnt_t, int);
extern int kcage_range_delete(pfn_t, pgcnt_t);
extern int kcage_range_delete_post_mem_del(pfn_t, pgcnt_t);

extern void kcage_init(pgcnt_t);
extern void kcage_recalc_thresholds(void);

/* Called from vm_pageout.c */
extern void kcage_cageout_init(void);
extern void kcage_cageout_wakeup(void);

/* Called from clock thread in clock.c */
extern void kcage_tick(void);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MEM_CAGE_H */
