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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/buf.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/fbuf.h>
#include <sys/kmem.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <sys/cred.h>
#include <sys/vnode.h>
#include <vm/hat.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_kmem.h>
#include <vm/seg_map.h>
#include <vm/seg_kpm.h>


/*
 * Pseudo-bio routines which use a segmap mapping to address file data.
 */

/*
 * Return a pointer to locked kernel virtual address for
 * the given <vp, off> for len bytes.  It is not allowed to
 * have the offset cross a MAXBSIZE boundary over len bytes.
 */
int
fbread(vnode_t *vp, offset_t off, uint_t len, enum seg_rw rw,
	struct fbuf **fbpp)
{
	caddr_t addr;
	ulong_t o;
	struct fbuf *fbp;
	faultcode_t err;
	caddr_t	raddr;
	uint_t	rsize;
	uintptr_t pgoff = PAGEOFFSET;

	o = (ulong_t)(off & (offset_t)MAXBOFFSET);
	if (o + len > MAXBSIZE)
		cmn_err(CE_PANIC, "fbread");

	if (segmap_kpm) {
		addr = segmap_getmapflt(segkmap, vp, off & (offset_t)MAXBMASK,
					MAXBSIZE, SM_LOCKPROTO, rw);
	} else {
		addr = segmap_getmapflt(segkmap, vp,
				off & (offset_t)MAXBMASK, MAXBSIZE, 0, rw);
	}

	raddr = (caddr_t)((uintptr_t)(addr + o) & ~pgoff);
	rsize = (((uintptr_t)(addr + o) + len + pgoff) & ~pgoff) -
	    (uintptr_t)raddr;

	err = segmap_fault(kas.a_hat, segkmap, raddr, rsize, F_SOFTLOCK, rw);
	if (err) {
		(void) segmap_release(segkmap, addr, 0);
		if (FC_CODE(err) == FC_OBJERR)
			return (FC_ERRNO(err));
		else
			return (EIO);
	}

	*fbpp = fbp = kmem_alloc(sizeof (struct fbuf), KM_SLEEP);
	fbp->fb_addr = addr + o;
	fbp->fb_count = len;
	return (0);
}

/*
 * Similar to fbread() but we call segmap_pagecreate instead of using
 * segmap_fault for SOFTLOCK to create the pages without using VOP_GETPAGE
 * and then we zero up to the length rounded to a page boundary.
 * XXX - this won't work right when bsize < PAGESIZE!!!
 */
void
fbzero(vnode_t *vp, offset_t off, uint_t len, struct fbuf **fbpp)
{
	caddr_t addr;
	ulong_t o, zlen;
	struct fbuf *fbp;

	o = (ulong_t)(off & MAXBOFFSET);
	if (o + len > MAXBSIZE)
		cmn_err(CE_PANIC, "fbzero: Bad offset/length");

	if (segmap_kpm) {
		addr = segmap_getmapflt(segkmap, vp, off & (offset_t)MAXBMASK,
				MAXBSIZE, SM_PAGECREATE, S_WRITE) + o;
	} else {
		addr = segmap_getmap(segkmap, vp, off & (offset_t)MAXBMASK) + o;
	}

	*fbpp = fbp = kmem_alloc(sizeof (struct fbuf), KM_SLEEP);
	fbp->fb_addr = addr;
	fbp->fb_count = len;

	(void) segmap_pagecreate(segkmap, addr, len, 1);

	/*
	 * Now we zero all the memory in the mapping we are interested in.
	 */
	zlen = (caddr_t)ptob(btopr((uintptr_t)(len + addr))) - addr;
	if (zlen < len || (o + zlen > MAXBSIZE))
		cmn_err(CE_PANIC, "fbzero: Bad zlen");
	bzero(addr, zlen);
}

/*
 * FBCOMMON() is the common code for fbrelse, fbwrite and variants thereof:
 *
 * fbrelse()	release fbp
 * fbwrite()	direct write
 * fbdwrite()	delayed write
 */
#define	FBCOMMON(fbp, rw, flags, howtoreturn) \
{ \
	caddr_t addr; \
	size_t size; \
	uintptr_t pgoff = PAGEOFFSET; \
	addr = (caddr_t)((uintptr_t)fbp->fb_addr & ~pgoff); \
	size = ((fbp->fb_addr - addr) + fbp->fb_count + pgoff) & ~pgoff; \
	(void) segmap_fault(kas.a_hat, segkmap, addr, size, F_SOFTUNLOCK, rw); \
	addr = (caddr_t)((uintptr_t)fbp->fb_addr & MAXBMASK); \
	kmem_free(fbp, sizeof (struct fbuf)); \
	howtoreturn(segmap_release(segkmap, addr, flags)); \
}

void
fbrelse(struct fbuf *fbp, enum seg_rw rw)
{
	FBCOMMON(fbp, rw, 0, (void))
}

int
fbwrite(struct fbuf *fbp)
{
	FBCOMMON(fbp, S_WRITE, SM_WRITE, return)
}

int
fbdwrite(struct fbuf *fbp)
{
	FBCOMMON(fbp, S_WRITE, 0, return)
}

/*
 * Perform a synchronous indirect write of the given block number
 * on the given device, using the given fbuf.  Upon return the fbp
 * is invalid.
 */
int
fbiwrite(struct fbuf *fbp, vnode_t *devvp, daddr_t bn, int bsize)
{
	struct buf *bp;
	int error, fberror;

	/*
	 * Allocate a temp bp using pageio_setup, but then use it
	 * for physio to the area mapped by fbuf which is currently
	 * all locked down in place.
	 *
	 * XXX - need to have a generalized bp header facility
	 * which we build up pageio_setup on top of.  Other places
	 * (like here and in device drivers for the raw I/O case)
	 * could then use these new facilities in a more straight
	 * forward fashion instead of playing all these games.
	 */
	bp = pageio_setup((struct page *)NULL, fbp->fb_count, devvp, B_WRITE);
	bp->b_flags &= ~B_PAGEIO;		/* XXX */
	bp->b_un.b_addr = fbp->fb_addr;

	bp->b_blkno = bn * btod(bsize);
	bp->b_dev = cmpdev(devvp->v_rdev);	/* store in old dev format */
	bp->b_edev = devvp->v_rdev;
	bp->b_proc = NULL;			/* i.e. the kernel */

	(void) bdev_strategy(bp);
	error = biowait(bp);
	pageio_done(bp);

	/*CSTYLED*/
	FBCOMMON(fbp, S_OTHER, 0, fberror = )

	return (error ? error : fberror);
}
