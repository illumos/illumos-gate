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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
 * Yield the size of an address space.
 *
 * The size can only be used as a hint since we cannot guarantee it
 * will stay the same size unless the as->a_lock is held by the caller.
 */
size_t
rm_assize(struct as *as)
{
	size_t size = 0;
	struct seg *seg;
	struct segvn_data *svd;
	extern struct seg_ops segdev_ops;	/* needs a header file */

	ASSERT(as != NULL && AS_READ_HELD(as, &as->a_lock));

	if (as == &kas)
		return (0);

	for (seg = AS_SEGFIRST(as); seg != NULL; seg = AS_SEGNEXT(as, seg)) {
		if (seg->s_ops == &segdev_ops &&
		    ((SEGOP_GETTYPE(seg, seg->s_base) &
		    (MAP_SHARED | MAP_PRIVATE)) == 0)) {
			/*
			 * Don't include mappings of /dev/null.  These just
			 * reserve address space ranges and have no memory.
			 * We cheat by knowing that these segments come
			 * from segdev and have no mapping type.
			 */
			/* EMPTY */;
		} else if (seg->s_ops == &segvn_ops &&
		    (svd = (struct segvn_data *)seg->s_data) != NULL &&
		    (svd->vp == NULL || svd->vp->v_type != VREG) &&
		    (svd->flags & MAP_NORESERVE)) {
			/*
			 * Don't include MAP_NORESERVE pages in the
			 * address range unless their mappings have
			 * actually materialized.  We cheat by knowing
			 * that segvn is the only segment driver that
			 * supports MAP_NORESERVE and that the actual
			 * number of bytes reserved is in the segment's
			 * private data structure.
			 */
			size += svd->swresv;
		} else {
			caddr_t addr = seg->s_base;
			size_t segsize = seg->s_size;
			vnode_t *vp;
			vattr_t vattr;

			/*
			 * If the segment is mapped beyond the end of the
			 * underlying mapped file, if any, then limit the
			 * segment's size contribution to the file size.
			 */
			vattr.va_mask = AT_SIZE;
			if (seg->s_ops == &segvn_ops &&
			    SEGOP_GETVP(seg, addr, &vp) == 0 &&
			    vp != NULL && vp->v_type == VREG &&
			    VOP_GETATTR(vp, &vattr, ATTR_HINT,
			    CRED(), NULL) == 0) {
				u_offset_t filesize = vattr.va_size;
				u_offset_t offset = SEGOP_GETOFFSET(seg, addr);

				if (filesize < offset)
					filesize = 0;
				else
					filesize -= offset;
				filesize = P2ROUNDUP_TYPED(filesize, PAGESIZE,
				    u_offset_t);
				if ((u_offset_t)segsize > filesize)
					segsize = filesize;
			}
			size += segsize;
		}
	}

	return (size);
}

/*
 * Yield the memory claim requirement for an address space.
 *
 * This is currently implemented as the number of active hardware
 * translations that have page structures.  Therefore, it can
 * underestimate the traditional resident set size, eg, if the
 * physical page is present and the hardware translation is missing;
 * and it can overestimate the rss, eg, if there are active
 * translations to a frame buffer with page structs.
 * Also, it does not take sharing and XHATs into account.
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
