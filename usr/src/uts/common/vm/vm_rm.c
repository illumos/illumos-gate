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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mman.h>
#include <sys/sysmacros.h>
#include <sys/errno.h>
#include <sys/signal.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>

#include <vm/hat.h>
#include <vm/as.h>
#include <vm/seg_vn.h>
#include <vm/rm.h>
#include <vm/seg.h>
#include <vm/page.h>

/*
 * Yield the memory claim requirement for an address space.
 *
 * This is currently implemented as the number of active hardware
 * translations that have page structures.  Therefore, it can
 * underestimate the traditional resident set size, eg, if the
 * physical page is present and the hardware translation is missing;
 * and it can overestimate the rss, eg, if there are active
 * translations to a frame buffer with page structs.
 * Also, it does not take sharing into account.
 */
size_t
rm_asrss(as)
	register struct as *as;
{
	if (as != (struct as *)NULL && as != &kas)
		return ((size_t)btop(hat_get_mapped_size(as->a_hat)));
	else
		return (0);
}

/*
 * Return a 16-bit binary fraction representing the percent of total memory
 * used by this address space.  Binary point is to right of high-order bit.
 * Defined as the ratio of a_rss for the process to total physical memory.
 * This assumes 2s-complement arithmetic and that shorts and longs are
 * 16 bits and 32 bits, respectively.
 */
ushort_t
rm_pctmemory(struct as *as)
{
	/* This can't overflow */
	ulong_t num = (ulong_t)rm_asrss(as) << (PAGESHIFT-1);
	int shift = 16 - PAGESHIFT;
	ulong_t total = total_pages;

	if (shift < 0) {
		num >>= (-shift);
		shift = 0;
	}
	while (shift > 0 && (num & 0x80000000) == 0) {
		shift--;
		num <<= 1;
	}
	if (shift > 0)
		total >>= shift;

	return (num / total);
}
