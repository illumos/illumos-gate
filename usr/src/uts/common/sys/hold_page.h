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

#ifndef _SYS_HOLD_PAGE_H
#define	_SYS_HOLD_PAGE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <vm/page.h>

/*
 * swrand generates entropy by mapping different pages in the system.  This
 * can create problems for some hypervisors, as certain pages may be removed
 * from the system at any time.  The following interfaces allow swrand to
 * check the validity and make sure a page is not given away while it is mapped.
 *
 * int plat_hold_page(pfn_t pfn, int lock, page_t **pp_ret)
 *
 *	If lock is PLAT_HOLD_NO_LOCK, simply check if the page pfn is valid
 *	in the system.  If the page is valid, PLAT_HOLD_OK will be returned.
 *	pp_ret is ignored if lock is PLAT_HOLD_NO_LOCK.
 *
 *	If lock is PLAT_HOLD_LOCK, in addition to the above, attempt to lock
 *	the page exclusively.  Again, if the lock is successful, the page
 *	pointer will be put in pp_ret, and PLAT_HOLD_OK will be returned.
 *	pp_ret must be passed to a later call to plat_release_page.  If the
 *	page wasn't found, or the lock couldn't be grabbed, the return value
 *	will be PLAT_HOLD_FAIL.
 *
 * void plat_release_page(page_t *pp)
 *
 *	Unlock the page pp.  Should only be called after a previous,
 *	successful call to plat_hold_page(pfn, PLAT_HOLD_LOCK, &pp);
 */

#define	PLAT_HOLD_NO_LOCK	0
#define	PLAT_HOLD_LOCK		1

#define	PLAT_HOLD_OK		0
#define	PLAT_HOLD_FAIL		1

extern int plat_hold_page(pfn_t, int, page_t **);
extern void plat_release_page(page_t *);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_HOLD_PAGE_H */
