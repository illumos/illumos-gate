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
 * Copyright 2016 Joyent, Inc.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#include "lint.h"
#include "mallint.h"
#include "mtlib.h"

#define	_misaligned(p)		((unsigned)(p) & 3)
		/* 4-byte "word" alignment is considered ok in LP64 */
#define	_nextblk(p, size)	((TREE *)((uintptr_t)(p) + (size)))

/*
 * memalign(align, nbytes)
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
 *		or if the heap has been detectably corrupted.
 *	[ENOMEM]
 *		if the requested memory could not be allocated.
 */

void *
memalign(size_t align, size_t nbytes)
{
	size_t	 reqsize;	/* Num of bytes to get from malloc() */
	TREE	*p;		/* Ptr returned from malloc() */
	TREE	*blk;		/* For addressing fragment blocks */
	size_t	blksize;	/* Current (shrinking) block size */
	TREE	*alignedp;	/* Ptr to properly aligned boundary */
	TREE	*aligned_blk;	/* The block to be returned */
	size_t	frag_size;	/* size of fragments fore and aft */
	size_t	 x;

	if (!primary_link_map) {
		errno = ENOTSUP;
		return (NULL);
	}

	/*
	 * check for valid size and alignment parameters
	 * MAX_ALIGN check prevents overflow in later calculation.
	 */
	if (nbytes == 0 || _misaligned(align) || align == 0 ||
	    align > MAX_ALIGN) {
		errno = EINVAL;
		return (NULL);
	}

	/*
	 * Malloc enough memory to guarantee that the result can be
	 * aligned correctly. The worst case is when malloc returns
	 * a block so close to the next alignment boundary that a
	 * fragment of minimum size cannot be created.  In order to
	 * make sure we can handle this, we need to force the
	 * alignment to be at least as large as the minimum frag size
	 * (MINSIZE + WORDSIZE).
	 */

	/* check for size that could overflow calculations */
	if (nbytes > MAX_MALLOC) {
		errno = ENOMEM;
		return (NULL);
	}
	ROUND(nbytes);
	if (nbytes < MINSIZE)
		nbytes = MINSIZE;
	ROUND(align);
	while (align < MINSIZE + WORDSIZE)
		align <<= 1;
	reqsize = nbytes + align + (MINSIZE + WORDSIZE);

	/* check for overflow */
	if (reqsize < nbytes) {
		errno = ENOMEM;
		return (NULL);
	}

	p = (TREE *)malloc(reqsize);
	if (p == (TREE *)NULL) {
		/* malloc sets errno */
		return (NULL);
	}
	(void) mutex_lock(&libc_malloc_lock);

	/*
	 * get size of the entire block (overhead and all)
	 */
	blk = BLOCK(p);			/* back up to get length word */
	blksize = SIZE(blk);
	CLRBITS01(blksize);

	/*
	 * locate the proper alignment boundary within the block.
	 */
	x = (size_t)p;
	if (x % align != 0)
		x += align - (x % align);
	alignedp = (TREE *)x;
	aligned_blk = BLOCK(alignedp);

	/*
	 * Check out the space to the left of the alignment
	 * boundary, and split off a fragment if necessary.
	 */
	frag_size = (size_t)aligned_blk - (size_t)blk;
	if (frag_size != 0) {
		/*
		 * Create a fragment to the left of the aligned block.
		 */
		if (frag_size < MINSIZE + WORDSIZE) {
			/*
			 * Not enough space. So make the split
			 * at the other end of the alignment unit.
			 * We know this yields enough space, because
			 * we forced align >= MINSIZE + WORDSIZE above.
			 */
			frag_size += align;
			aligned_blk = _nextblk(aligned_blk, align);
		}
		blksize -= frag_size;
		SIZE(aligned_blk) = blksize | BIT0;
		frag_size -= WORDSIZE;
		SIZE(blk) = frag_size | BIT0 | ISBIT1(SIZE(blk));
		_free_unlocked(DATA(blk));
	}

	/*
	 * Is there a (sufficiently large) fragment to the
	 * right of the aligned block?
	 */
	frag_size = blksize - nbytes;
	if (frag_size >= MINSIZE + WORDSIZE) {
		/*
		 * split and free a fragment on the right
		 */
		blksize = SIZE(aligned_blk);
		SIZE(aligned_blk) = nbytes;
		blk = NEXT(aligned_blk);
		SETOLD01(SIZE(aligned_blk), blksize);
		frag_size -= WORDSIZE;
		SIZE(blk) = frag_size | BIT0;
		_free_unlocked(DATA(blk));
	}
	(void) mutex_unlock(&libc_malloc_lock);
	return (DATA(aligned_blk));
}

/*
 * This is the ISO/IEC C11 version of memalign. We have kept it as a separate
 * function, but it is basically the same thing. Note that this is implemented
 * this way to make life easier to libraries which already interpose on
 * memalign.
 */
void *
aligned_alloc(size_t align, size_t size)
{
	return (memalign(align, size));
}
