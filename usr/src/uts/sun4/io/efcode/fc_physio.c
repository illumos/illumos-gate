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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/buf.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/vmsystm.h>
#include <sys/mman.h>
#include <sys/vm.h>
#include <sys/ddi.h>

#include <vm/as.h>
#include <vm/page.h>

/*
 * Prepare for raw I/O request - derived from default_physio()
 * This is the 'setup' portion of physio, limited to dealing
 * with unstructured access to a single range of user space addresses.
 *
 * This is quite limited in functionality compared to physio().
 *
 * 1. allocate and return buf header
 * 2. lock down user pages and verify access protections
 *
 * Use B_READ (S_WRITE) for unstructured access. (We don't know the
 * direction of the transfer, so use the safest.)
 */

int
fc_physio_setup(struct buf **bpp, void *io_base, size_t io_len)
{
	struct proc *procp;
	struct as *asp;
	int error = 0;
	page_t **pplist;
	struct buf *bp = *bpp;

	bp = getrbuf(KM_SLEEP);
	bp->b_iodone = NULL;
	bp->b_resid = 0;
	*bpp = bp;

	/* segflg *is always* UIO_USERSPACE for us */
	procp = ttoproc(curthread);
	asp = procp->p_as;

	ASSERT(SEMA_HELD(&bp->b_sem));

	bp->b_error = 0;
	bp->b_proc = procp;

	bp->b_flags = B_BUSY | B_PHYS | B_READ;
	bp->b_edev = 0;
	bp->b_lblkno = 0;

	/*
	 * Don't count on b_addr remaining untouched by the
	 * code below (it may be reset because someone does
	 * a bp_mapin on the buffer).
	 */
	bp->b_un.b_addr = io_base;
	bp->b_bcount = io_len;

	error = as_pagelock(asp, &pplist, io_base, io_len, S_WRITE);

	if (error != 0) {
		bp->b_flags |= B_ERROR;
		bp->b_error = error;
		bp->b_flags &= ~(B_BUSY|B_WANTED|B_PHYS);
		freerbuf(bp);
		*bpp = NULL;
		return (error);
	}

	bp->b_shadow = pplist;
	if (pplist != NULL) {
		bp->b_flags |= B_SHADOW;
	}
	return (0);
}

/*
 * unlock the pages and free the buf header, if we allocated it.
 */
void
fc_physio_free(struct buf **bpp, void *io_base, size_t io_len)
{
	struct buf *bp = *bpp;
	page_t **pplist = NULL;

	/*
	 * unlock the pages
	 */

	if (bp->b_flags & B_SHADOW)
		pplist = bp->b_shadow;

	as_pageunlock(bp->b_proc->p_as, pplist, io_base, io_len, S_WRITE);

	bp->b_flags &= ~(B_BUSY|B_WANTED|B_PHYS|B_SHADOW);

	freerbuf(bp);
	*bpp = NULL;
}
