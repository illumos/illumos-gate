/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * wizard:/space/4.3reno/usr/src/lib/libc/stdlib/malloc.c
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that: (1) source distributions retain this entire copyright
 * notice and comment, and (2) distributions including binaries display
 * the following acknowledgement:  ``This product includes software
 * developed by the University of California, Berkeley and its contributors''
 * in the documentation or other materials provided with the distribution
 * and in all advertising materials mentioning features or use of this
 * software. Neither the name of the University nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * malloc.c (Caltech) 2/21/82
 * Chris Kingsley, kingsley@cit-20.
 *
 * This is a very fast storage allocator.  It allocates blocks of a small
 * number of different sizes, and keeps free lists of each size.  Blocks that
 * don't exactly fit are passed up to the next larger size.  In this
 * implementation, the available sizes are 2^n-4 bytes long (ILP32)
 * or 2^n-8 bytes long (LP64).
 */

/*LINTLIBRARY*/
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>

/*
 * The overhead on a block is at least 4 bytes.  When free, this space
 * contains a pointer to the next free block, and the bottom two bits must
 * be zero.  When in use, the first byte is set to MAGIC, and the second
 * byte is the size index.  The remaining bytes are for alignment.
 * The order of elements is critical: ov_magic must overlay the low order
 * bits of ov_next, and ov_magic can not be a valid ov_next bit pattern.
 * Overhead is 4 bytes for ILP32, 8 bytes for LP64
 */
union	overhead {
	union	overhead *ov_next;	/* when free */
	struct {
#if defined(_LITTLE_ENDIAN)
		uchar_t	ovu_magic;	/* magic number */
		uchar_t	ovu_index;	/* bucket # */
		uchar_t	ovu_pad[sizeof (union overhead *) - 2];
#elif defined(_BIG_ENDIAN)
		uchar_t	ovu_pad[sizeof (union overhead *) - 2];
		uchar_t	ovu_index;	/* bucket # */
		uchar_t	ovu_magic;	/* magic number */
#else
#error "Endianness is not defined"
#endif
	} ovu;
};

#define	ov_magic	ovu.ovu_magic
#define	ov_index	ovu.ovu_index

#define	MAGIC		0xef		/* magic # on accounting info */

/*
 * nextf[i] is the pointer to the next free block of size 2^(i+EXP).
 * The smallest allocatable block is 8 bytes (ILP32) or 16 bytes (LP64).
 * The overhead information precedes the data area returned to the user.
 */
#ifdef _LP64
#define	EXP	4
#define	NBUCKETS 60
#else
#define	EXP	3
#define	NBUCKETS 29
#endif
static	union overhead *nextf[NBUCKETS];

static	int	pagesz;			/* page size */
static	long	sbrk_adjust;		/* in case sbrk() does alignment */
static	int	pagebucket;		/* page size bucket */
static	void	morecore(int);
static	int	findbucket(union overhead *, int);

void *
malloc(size_t nbytes)
{
	union overhead *op;
	int bucket;
	ssize_t	n;
	size_t amt;

	/*
	 * First time malloc is called, setup page size and
	 * align break pointer so all data will be page aligned.
	 */
	if (pagesz == 0) {
		pagesz = getpagesize();
		op = sbrk(0);
		n = pagesz - sizeof (*op) - ((uintptr_t)op & (pagesz - 1));
		if (n < 0)
			n += pagesz;
		if (n) {
			if (sbrk(n) == (void *)-1)
				return (NULL);
			/*
			 * We were careful to arrange that
			 * sbrk(0) + sizeof (union overhead)
			 * should end up on a page boundary.
			 * If the underlying sbrk() performs alignment
			 * then this is false.  We compute the adjustment.
			 */
			op = sbrk(0);
			sbrk_adjust = (uintptr_t)(op + 1) & (pagesz - 1);
		} else {
			sbrk_adjust = 0;
		}
		bucket = 0;
		amt = (1UL << EXP);
		while (pagesz > amt) {
			amt <<= 1;
			bucket++;
		}
		pagebucket = bucket;
	}
	/*
	 * Convert amount of memory requested into closest block size
	 * stored in hash buckets which satisfies request.
	 * Account for space used per block for accounting.
	 */
	if (nbytes <= (n = pagesz - sizeof (*op))) {
		amt = (1UL << EXP);	/* size of first bucket */
		bucket = 0;
		n = -(ssize_t)(sizeof (*op));
	} else {
		amt = pagesz;
		bucket = pagebucket;
	}
	while (nbytes > amt + n) {
		amt <<= 1;
		if (amt == 0)
			return (NULL);
		bucket++;
	}
	/*
	 * If nothing in hash bucket right now,
	 * request more memory from the system.
	 */
	if ((op = nextf[bucket]) == NULL) {
		morecore(bucket);
		if ((op = nextf[bucket]) == NULL)
			return (NULL);
	}
	/* remove from linked list */
	nextf[bucket] = op->ov_next;
	op->ov_magic = MAGIC;
	op->ov_index = (uchar_t)bucket;
	return (op + 1);
}

/*
 * Allocate more memory to the indicated bucket.
 */
static void
morecore(int bucket)
{
	union overhead *op;
	size_t sz;			/* size of desired block */
	ssize_t amt;			/* amount to allocate */
	long nblks;			/* how many blocks we get */

	sz = 1UL << (bucket + EXP);
	if (sz == 0)
		return;
	if (sz < pagesz) {
		amt = pagesz;
		nblks = amt / sz;
	} else {
		amt = sz + pagesz;
		nblks = 1;
	}
	if (amt <= 0)
		return;
	if (amt > LONG_MAX) {
		intptr_t	delta;
		/*
		 * the value required is too big for sbrk() to deal with
		 * in one go, so use sbrk() at most 2 times instead.
		 */
		op = sbrk(0);
		delta = LONG_MAX;
		while (delta > 0) {
			if (sbrk(delta) == (void *)-1) {
				if (op != sbrk(0))
					(void) sbrk(-LONG_MAX);
				return;
			}
			amt -= LONG_MAX;
			delta = amt;
		}
	}
	else
		op = sbrk(amt);
	/* no more room! */
	if (op == (union overhead *)-1)
		return;
	/* LINTED improper alignment */
	op = (union overhead *)((caddr_t)op - sbrk_adjust);
	/*
	 * Add new memory allocated to that on
	 * free list for this hash bucket.
	 */
	nextf[bucket] = op;
	while (--nblks > 0) {
		/* LINTED improper alignment */
		op->ov_next = (union overhead *)((caddr_t)op + sz);
		/* LINTED improper alignment */
		op = (union overhead *)((caddr_t)op + sz);
	}
}

void
free(void *cp)
{
	int size;
	union overhead *op;

	if (cp == NULL)
		return;
	/* LINTED improper alignment */
	op = (union overhead *)((caddr_t)cp - sizeof (union overhead));
	if (op->ov_magic != MAGIC)
		return;			/* previously freed? */
	size = op->ov_index;
	op->ov_next = nextf[size];	/* also clobbers ov_magic */
	nextf[size] = op;
}

/*
 * When a program attempts "storage compaction" as mentioned in the
 * old malloc man page, it realloc's an already freed block.  Usually
 * this is the last block it freed; occasionally it might be farther
 * back.  We have to search all the free lists for the block in order
 * to determine its bucket: 1st we make one pass thru the lists
 * checking only the first block in each; if that fails we search
 * ``realloc_srchlen'' blocks in each list for a match (the variable
 * is extern so the caller can modify it).  If that fails we just copy
 * however many bytes was given to realloc() and hope it's not huge.
 */
int realloc_srchlen = 4;	/* 4 should be plenty, -1 =>'s whole list */

void *
realloc(void *cp, size_t nbytes)
{
	size_t onb;
	int i;
	union overhead *op;
	char *res;
	int was_alloced = 0;

	if (cp == NULL)
		return (malloc(nbytes));
	/* LINTED improper alignment */
	op = (union overhead *)((caddr_t)cp - sizeof (union overhead));
	if (op->ov_magic == MAGIC) {
		was_alloced++;
		i = op->ov_index;
	} else {
		/*
		 * Already free, doing "compaction".
		 *
		 * Search for the old block of memory on the
		 * free list.  First, check the most common
		 * case (last element free'd), then (this failing)
		 * the last ``realloc_srchlen'' items free'd.
		 * If all lookups fail, then just malloc() the
		 * space and copy the size of the new space.
		 */
		if ((i = findbucket(op, 1)) < 0 &&
		    (i = findbucket(op, realloc_srchlen)) < 0) {
			if ((res = malloc(nbytes)) != NULL)
				(void) memmove(res, cp, nbytes);
			return (res);
		}
	}
	onb = 1UL << (i + EXP);
	if (onb < pagesz)
		onb -= sizeof (*op);
	else
		onb += pagesz - sizeof (*op);
	/* avoid the copy if same size block */
	if (was_alloced) {
		size_t sz = 0;
		if (i) {
			sz = 1UL << (i + EXP - 1);
			if (sz < pagesz)
				sz -= sizeof (*op);
			else
				sz += pagesz - sizeof (*op);
		}
		if (nbytes <= onb && nbytes > sz) {
			return (cp);
		} else
			free(cp);
	}
	if ((res = malloc(nbytes)) == NULL)
		return (NULL);
	if (cp != res)		/* common optimization if "compacting" */
		(void) memmove(res, cp, (nbytes < onb) ? nbytes : onb);
	return (res);
}

/*
 * Search ``srchlen'' elements of each free list for a block whose
 * header starts at ``freep''.  If srchlen is -1 search the whole list.
 * Return bucket number, or -1 if not found.
 */
static int
findbucket(union overhead *freep, int srchlen)
{
	union overhead *p;
	int i, j;

	for (i = 0; i < NBUCKETS; i++) {
		j = 0;
		for (p = nextf[i]; p && j != srchlen; p = p->ov_next) {
			if (p == freep)
				return (i);
			j++;
		}
	}
	return (-1);
}
