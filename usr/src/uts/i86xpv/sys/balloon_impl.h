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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_BALLOON_IMPL_H
#define	_SYS_BALLOON_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/balloon.h>
#include <sys/types.h>
#include <vm/page.h>
#include <sys/xen_mmu.h>	/* to get typedef of mfn_t */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This file contains interfaces for both the balloon kernel thread
 * and the balloon driver.  The balloon device is installed under /dev/xen,
 * and can be used with the ioctl values in balloon.h to get the balloon
 * memory status.
 */

/* balloon thread declarations */
void balloon_init(pgcnt_t);
size_t balloon_values(int);
void balloon_drv_added(int64_t);
void balloon_drv_subtracted(int64_t);
long balloon_alloc_pages(uint_t, mfn_t *);
long balloon_free_pages(uint_t, mfn_t *, caddr_t, pfn_t *);
long balloon_replace_pages(uint_t, page_t **, uint_t, uint_t, mfn_t *);

/* balloon driver information */
#define	BALLOON_MINOR		0

/*
 * Critical stats for the balloon thread.  All values are in pages.
 */
typedef struct {
	pgcnt_t bln_current_pages;	/* current reservation */
	pgcnt_t bln_new_target;		/* target value for reservation */
	pgcnt_t bln_max_pages;	/* first pfn for which we don't have a page_t */
	pgcnt_t bln_low;	/* lowest value of reservation since boot */
	pgcnt_t bln_high;	/* highest value of reservation since boot */
	spgcnt_t bln_hv_pages;	/* number of total pages given to hypervisor */
	spgcnt_t bln_hard_limit;	/* domain's max-mem limit */
} bln_stats_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_BALLOON_IMPL_H */
