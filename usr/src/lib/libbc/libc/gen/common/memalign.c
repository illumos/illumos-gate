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
 * Copyright 1987 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI" 

#include "mallint.h"
#include <errno.h>

extern	int errno;

/*
 * memalign(align,nbytes)
 *
 * Description:
 *	Returns a block of specified size on a specified alignment boundary.
 *
 * Algorithm:
 *	Malloc enough to ensure that a block can be aligned correctly.
 *	Find the alignment point and return the fragments
 *	before and after the block.
 *
 * Errors:
 *	Returns NULL and sets errno as follows:
 *	[EINVAL]
 *		if nbytes = 0,
 *		or if alignment is misaligned,
 *	 	or if the heap has been detectably corrupted.
 *	[ENOMEM]
 *		if the requested memory could not be allocated.
 */

char *
memalign(align, nbytes)
	uint	align;
	uint	nbytes;
{
	uint	reqsize;		/* Num of bytes to get from malloc() */
	register char	*p;		/* Ptr returned from malloc() */
	register Dblk	blk;		/* For addressing fragment blocks */
	register uint	blksize;	/* Current (shrinking) block size */
	register char	*alignedp;	/* Ptr to properly aligned boundary */
	register Dblk	aligned_blk;	/* The block to be returned */
	register uint	frag_size;	/* size of fragments fore and aft */
	uint	x;			/* ccom can't do (char*)(uint/uint) */

	/*
	 * check for valid size and alignment parameters
	 */
	if (nbytes == 0 || misaligned(align)) {
		errno = EINVAL;
		return NULL;
	}

	/*
	 * Malloc enough memory to guarantee that the result can be
	 * aligned correctly. The worst case is when malloc returns
	 * a block so close to the next alignment boundary that a
	 * fragment of minimum size cannot be created.
	 */
	nbytes = roundup(nbytes, ALIGNSIZ);
	reqsize = nbytes + align + SMALLEST_BLK;
	p = malloc(reqsize);
	if (p == NULL) {
		return NULL;
	}

	/*
	 * get size of the entire block (overhead and all)
	 */
	blk = (Dblk)(p - ALIGNSIZ);	/* back up to get length word */
	blksize = blk->size;

	/*
	 * locate the proper alignment boundary within the block.
	 */
	x = roundup((uint)p, align);		/* ccom work-around */
	alignedp = (char *)x;
	aligned_blk = (Dblk)(alignedp - ALIGNSIZ);

	/*
	 * Check out the space to the left of the alignment
	 * boundary, and split off a fragment if necessary.
	 */
	frag_size = (uint)aligned_blk - (uint)blk;
	if (frag_size != 0) {
		/*
		 * Create a fragment to the left of the aligned block.
		 */
		if ( frag_size < SMALLEST_BLK ) {
			/*
			 * Not enough space. So make the split
			 * at the other end of the alignment unit.
			 */
			frag_size += align;
			aligned_blk = nextblk(aligned_blk,align);
		}
		blk->size = frag_size;
		blksize -= frag_size;
		aligned_blk->size = blksize;
		free(blk->data);
	}

	/*
	 * Is there a (sufficiently large) fragment to the
	 * right of the aligned block?
	 */
	nbytes += ALIGNSIZ;
	frag_size = blksize - nbytes;
	if (frag_size > SMALLEST_BLK) {
		/*
		 * split and free a fragment on the right
		 */
		blk = nextblk(aligned_blk, nbytes);
		blk->size = frag_size;
		aligned_blk->size -= frag_size;
		free(blk->data);
	}
	return(aligned_blk->data);
}
