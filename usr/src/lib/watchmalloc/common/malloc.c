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
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 *	Memory management: malloc(), realloc(), free(), memalign().
 *
 *	The following #-parameters may be redefined:
 *	GETCORE: a function to get more core memory.
 *		GETCORE(0) is assumed to return the next available
 *		address. Default is 'sbrk'.
 *	ERRCORE: the error code as returned by GETCORE.
 *		Default is ((char *)(-1)).
 *	CORESIZE: a desired unit (measured in bytes) to be used
 *		with GETCORE. Default is (1024*ALIGN).
 *
 *	This algorithm is based on a best fit strategy with lists of
 *	free elts maintained in a self-adjusting binary tree. Each list
 *	contains all elts of the same size. The tree is ordered by size.
 *	For results on self-adjusting trees, see the paper:
 *		Self-Adjusting Binary Trees,
 *		DD Sleator & RE Tarjan, JACM 1985.
 *
 *	The header of a block contains the size of the data part in bytes.
 *	Since the size of a block is 0%4, the low two bits of the header
 *	are free and used as follows:
 *
 *		BIT0:	1 for busy (block is in use), 0 for free.
 *		BIT1:	if the block is busy, this bit is 1 if the
 *			preceding block in contiguous memory is free.
 *			Otherwise, it is always 0.
 */

#include "mallint.h"

static	mutex_t	__watch_malloc_lock = DEFAULTMUTEX;

static	TREE	*Root;		/* root of the free tree */
static	TREE	*Bottom;	/* the last free chunk in the arena */
static	char	*Baddr;		/* current high address of the arena */

static	void	t_delete(TREE *);
static	void	t_splay(TREE *);
static	void	realfree(void *);
static	void	*malloc_unlocked(size_t);
static	void	free_unlocked(void *);
static	TREE	*morecore(size_t);

static	void	protect(TREE *);
static	void	unprotect(TREE *);

#define	FREEPAT	0
#define	LIVEPAT	1

/*
 * Patterns to be copied into freed blocks and allocated blocks.
 * 0xfeedbeef and 0xfeedface are invalid pointer values in all programs.
 */
static	uint64_t	patterns[2] = {
	0xdeadbeefdeadbeefULL,	/* pattern in a freed block */
	0xbaddcafebaddcafeULL	/* pattern in an allocated block */
};

static void
copy_pattern(int pat, TREE *tp)
{
	uint64_t pattern = patterns[pat];
	size_t sz = SIZE(tp) / sizeof (uint64_t);
	/* LINTED improper alignment */
	uint64_t *datap = (uint64_t *)DATA(tp);

	while (sz--)
		*datap++ = pattern;
}

/*
 * Keep lists of small blocks, LIFO order.
 */
static	TREE	*List[MINSIZE/WORDSIZE-1];
static	TREE	*Last[MINSIZE/WORDSIZE-1];

/* number of blocks to get at one time */
#define	NPS	(WORDSIZE*8)

static void *
smalloc(size_t size)
{
	TREE	*tp;
	size_t	i;

	ASSERT(size % WORDSIZE == 0);
	/* want to return a unique pointer on malloc(0) */
	if (size == 0)
		size = WORDSIZE;

	/* list to use */
	i = size / WORDSIZE - 1;

	if (List[i] == NULL) {
		TREE	*np;
		int	n;
		ASSERT((size + WORDSIZE) * NPS >= MINSIZE);

		/* get NPS of these block types */
		if ((np = malloc_unlocked((size + WORDSIZE)*NPS)) == NULL)
			return (NULL);

		/* make them into a link list */
		for (n = 0, List[i] = np; n < NPS; ++n) {
			tp = np;
			SIZE(tp) = size;
			copy_pattern(FREEPAT, tp);
			if (n == NPS - 1) {
				Last[i] = tp;
				np = NULL;
			} else {
				/* LINTED improper alignment */
				np = NEXT(tp);
			}
			AFTER(tp) = np;
			protect(tp);
		}
	}

	/* allocate from the head of the queue */
	tp = List[i];
	unprotect(tp);
	if ((List[i] = AFTER(tp)) == NULL)
		Last[i] = NULL;
	copy_pattern(LIVEPAT, tp);
	SETBIT0(SIZE(tp));
	protect(tp);
	return (DATA(tp));
}

void *
malloc(size_t size)
{
	void	*ret;
	(void) mutex_lock(&__watch_malloc_lock);
	ret = malloc_unlocked(size);
	(void) mutex_unlock(&__watch_malloc_lock);
	return (ret);
}

static void *
malloc_unlocked(size_t size)
{
	size_t	n;
	TREE	*tp, *sp, *tmp;

	COUNT(nmalloc);
	ASSERT(WORDSIZE == ALIGN);

	/* check for size that could overflow calculations */
	if (size > MAX_MALLOC) {
		errno = ENOMEM;
		return (NULL);
	}
	/* make sure that size is 0 mod ALIGN */
	ROUND(size);

	/* small blocks */
	if (size < MINSIZE)
		return (smalloc(size));

	/* search for an elt of the right size */
	sp = NULL;
	n = 0;
	if (Root) {
		tp = Root;
		for (;;) {
			unprotect(tp);
			if (SIZE(tp) >= size) {	/* branch left */
				if (n == 0 || n >= SIZE(tp)) {
					sp = tp;
					n = SIZE(tp);
				}
				if ((tmp = LEFT(tp)) != NULL) {
					protect(tp);
					tp = tmp;
				} else {
					protect(tp);
					break;
				}
			} else {		/* branch right */
				if ((tmp = RIGHT(tp)) != NULL) {
					protect(tp);
					tp = tmp;
				} else {
					protect(tp);
					break;
				}
			}
		}

		if (sp) {
			unprotect(sp);
			t_delete(sp);
		} else if (tp != Root) {
			/* make the searched-to element the root */
			unprotect(tp);
			t_splay(tp);
			protect(tp);
			Root = tp;
		}
	}

	/* if found none fitted in the tree */
	if (sp == NULL) {
		if (Bottom) {
			unprotect(Bottom);
			if (size <= SIZE(Bottom)) {
				sp = Bottom;
				CLRBITS01(SIZE(sp));
			} else {
				protect(Bottom);
				if ((sp = morecore(size)) == NULL)
					return (NULL);
			}
		} else {
			if ((sp = morecore(size)) == NULL)
				return (NULL);
		}
	}

	/* tell the forward neighbor that we're busy */
	/* LINTED improper alignment */
	tmp = NEXT(sp);
	unprotect(tmp);
	CLRBIT1(SIZE(tmp));
	ASSERT(ISBIT0(SIZE(tmp)));
	protect(tmp);

	/* if the leftover is enough for a new free piece */
	if ((n = (SIZE(sp) - size)) >= MINSIZE + WORDSIZE) {
		n -= WORDSIZE;
		SIZE(sp) = size;
		/* LINTED improper alignment */
		tp = NEXT(sp);
		SIZE(tp) = n | BIT0;
		realfree(DATA(tp));
	} else if (BOTTOM(sp))
		Bottom = NULL;

	/* return the allocated space */
	copy_pattern(LIVEPAT, sp);
	SIZE(sp) |= BIT0;
	protect(sp);
	return (DATA(sp));
}

/*
 *	realloc().
 *	If the block size is increasing, we try forward merging first.
 *	This is not best-fit but it avoids some data recopying.
 */
void *
realloc(void *old, size_t size)
{
	TREE	*tp, *np;
	size_t	ts;
	char	*new;

	COUNT(nrealloc);

	/* check for size that could overflow calculations */
	if (size > MAX_MALLOC) {
		errno = ENOMEM;
		return (NULL);
	}

	/* pointer to the block */
	(void) mutex_lock(&__watch_malloc_lock);
	if (old == NULL) {
		new = malloc_unlocked(size);
		(void) mutex_unlock(&__watch_malloc_lock);
		return (new);
	}

	/* make sure that size is 0 mod ALIGN */
	ROUND(size);

	/* LINTED improper alignment */
	tp = BLOCK(old);
	unprotect(tp);
	ts = SIZE(tp);

	/* if the block was freed, data has been destroyed. */
	if (!ISBIT0(ts)) {
		/* XXX; complain here! */
		protect(tp);
		(void) mutex_unlock(&__watch_malloc_lock);
		errno = EINVAL;
		return (NULL);
	}

	CLRBITS01(SIZE(tp));
	if (size == SIZE(tp)) {	/* nothing to do */
		SIZE(tp) = ts;
		protect(tp);
		(void) mutex_unlock(&__watch_malloc_lock);
		return (old);
	}

	/* special cases involving small blocks */
	if (size < MINSIZE || SIZE(tp) < MINSIZE) {
		if (size == 0) {
			SETOLD01(SIZE(tp), ts);
			free_unlocked(old);
			(void) mutex_unlock(&__watch_malloc_lock);
			return (NULL);
		}
		goto call_malloc;
	}

	/* block is increasing in size, try merging the next block */
	if (size > SIZE(tp)) {
		/* LINTED improper alignment */
		np = NEXT(tp);
		unprotect(np);
		if (ISBIT0(SIZE(np)))
			protect(np);
		else {
			TREE *tmp;
			ASSERT(SIZE(np) >= MINSIZE);
			ASSERT(!ISBIT1(SIZE(np)));
			SIZE(tp) += SIZE(np) + WORDSIZE;
			if (np != Bottom)
				t_delete(np);
			else
				Bottom = NULL;
			/* LINTED improper alignment */
			tmp = NEXT(np);
			unprotect(tmp);
			CLRBIT1(SIZE(tmp));
			protect(tmp);
		}

		/* not enough & at TRUE end of memory, try extending core */
		if (size > SIZE(tp) && BOTTOM(tp) && GETCORE(0) == Baddr) {
			Bottom = tp;
			protect(Bottom);
			if ((tp = morecore(size)) == NULL) {
				tp = Bottom;
				Bottom = NULL;
				unprotect(tp);
			}
		}
	}

	/* got enough space to use */
	if (size <= SIZE(tp)) {
		size_t n;
chop_big:
		if ((n = (SIZE(tp) - size)) >= MINSIZE + WORDSIZE) {
			n -= WORDSIZE;
			SIZE(tp) = size;
			/* LINTED improper alignment */
			np = NEXT(tp);
			SIZE(np) = n | BIT0;
			realfree(DATA(np));
		} else if (BOTTOM(tp))
			Bottom = NULL;

		/* the previous block may be free */
		SETOLD01(SIZE(tp), ts);
		protect(tp);
		(void) mutex_unlock(&__watch_malloc_lock);
		return (old);
	}

call_malloc:	/* call malloc to get a new block */
	SETOLD01(SIZE(tp), ts);
	if ((new = malloc_unlocked(size)) != NULL) {
		CLRBITS01(ts);
		if (ts > size)
			ts = size;
		(void) memcpy(new, old, ts);
		free_unlocked(old);
		(void) mutex_unlock(&__watch_malloc_lock);
		return (new);
	}

	/*
	 * Attempt special case recovery allocations since malloc() failed:
	 *
	 * 1. size <= SIZE(tp) < MINSIZE
	 *	Simply return the existing block
	 * 2. SIZE(tp) < size < MINSIZE
	 *	malloc() may have failed to allocate the chunk of
	 *	small blocks. Try asking for MINSIZE bytes.
	 * 3. size < MINSIZE <= SIZE(tp)
	 *	malloc() may have failed as with 2.  Change to
	 *	MINSIZE allocation which is taken from the beginning
	 *	of the current block.
	 * 4. MINSIZE <= SIZE(tp) < size
	 *	If the previous block is free and the combination of
	 *	these two blocks has at least size bytes, then merge
	 *	the two blocks copying the existing contents backwards.
	 */
	CLRBITS01(SIZE(tp));
	if (SIZE(tp) < MINSIZE) {
		if (size < SIZE(tp))		/* case 1. */ {
			SETOLD01(SIZE(tp), ts);
			protect(tp);
			(void) mutex_unlock(&__watch_malloc_lock);
			return (old);
		} else if (size < MINSIZE)	/* case 2. */ {
			size = MINSIZE;
			goto call_malloc;
		}
	} else if (size < MINSIZE)		/* case 3. */ {
		size = MINSIZE;
		goto chop_big;
	} else if (ISBIT1(ts)) {
		np = LAST(tp);
		unprotect(np);
		if ((SIZE(np) + SIZE(tp) + WORDSIZE) >= size) {
			ASSERT(!ISBIT0(SIZE(np)));
			t_delete(np);
			SIZE(np) += SIZE(tp) + WORDSIZE;
			/*
			 * Since the copy may overlap, use memmove().
			 */
			(void) memmove(DATA(np), old, SIZE(tp));
			old = DATA(np);
			tp = np;
			CLRBIT1(ts);
			goto chop_big;
		}
		protect(np);
	}
	SETOLD01(SIZE(tp), ts);
	protect(tp);
	(void) mutex_unlock(&__watch_malloc_lock);
	/* malloc() sets errno */
	return (NULL);
}

/*
 *	realfree().
 *	Coalescing of adjacent free blocks is done first.
 *	Then, the new free block is leaf-inserted into the free tree
 *	without splaying. This strategy does not guarantee the amortized
 *	O(nlogn) behaviour for the insert/delete/find set of operations
 *	on the tree. In practice, however, free is much more infrequent
 *	than malloc/realloc and the tree searches performed by these
 *	functions adequately keep the tree in balance.
 */
static void
realfree(void *old)
{
	TREE	*tp, *sp, *np, *tmp;
	size_t	ts, size;

	COUNT(nfree);

	/* pointer to the block */
	/* LINTED improper alignment */
	tp = BLOCK(old);
	unprotect(tp);
	ts = SIZE(tp);
	if (!ISBIT0(ts)) {	/* block is not busy; previously freed? */
		protect(tp);	/* force a watchpoint trap */
		CLRBIT0(SIZE(tp));
		return;
	}
	CLRBITS01(SIZE(tp));
	copy_pattern(FREEPAT, tp);

	/* small block, return it to the tail of its queue */
	if (SIZE(tp) < MINSIZE) {
		ASSERT(SIZE(tp) / WORDSIZE >= 1);
		ts = SIZE(tp) / WORDSIZE - 1;
		AFTER(tp) = NULL;
		protect(tp);
		if (List[ts] == NULL) {
			List[ts] = tp;
			Last[ts] = tp;
		} else {
			sp = Last[ts];
			unprotect(sp);
			AFTER(sp) = tp;
			protect(sp);
			Last[ts] = tp;
		}
		return;
	}

	/* see if coalescing with next block is warranted */
	/* LINTED improper alignment */
	np = NEXT(tp);
	unprotect(np);
	if (ISBIT0(SIZE(np)))
		protect(np);
	else {
		if (np != Bottom)
			t_delete(np);
		SIZE(tp) += SIZE(np) + WORDSIZE;
	}

	/* the same with the preceding block */
	if (ISBIT1(ts)) {
		np = LAST(tp);
		unprotect(np);
		ASSERT(!ISBIT0(SIZE(np)));
		ASSERT(np != Bottom);
		t_delete(np);
		SIZE(np) += SIZE(tp) + WORDSIZE;
		tp = np;
	}

	/* initialize tree info */
	PARENT(tp) = LEFT(tp) = RIGHT(tp) = LINKFOR(tp) = NULL;

	/* set bottom block, or insert in the free tree */
	if (BOTTOM(tp))
		Bottom = tp;
	else {
		/* search for the place to insert */
		if (Root) {
			size = SIZE(tp);
			np = Root;
			for (;;) {
				unprotect(np);
				if (SIZE(np) > size) {
					if ((tmp = LEFT(np)) != NULL) {
						protect(np);
						np = tmp;
					} else {
						LEFT(np) = tp;
						PARENT(tp) = np;
						protect(np);
						break;
					}
				} else if (SIZE(np) < size) {
					if ((tmp = RIGHT(np)) != NULL) {
						protect(np);
						np = tmp;
					} else {
						RIGHT(np) = tp;
						PARENT(tp) = np;
						protect(np);
						break;
					}
				} else {
					if ((sp = PARENT(np)) != NULL) {
						unprotect(sp);
						if (np == LEFT(sp))
							LEFT(sp) = tp;
						else
							RIGHT(sp) = tp;
						PARENT(tp) = sp;
						protect(sp);
					} else
						Root = tp;

					/* insert to head of list */
					if ((sp = LEFT(np)) != NULL) {
						unprotect(sp);
						PARENT(sp) = tp;
						protect(sp);
					}
					LEFT(tp) = sp;

					if ((sp = RIGHT(np)) != NULL) {
						unprotect(sp);
						PARENT(sp) = tp;
						protect(sp);
					}
					RIGHT(tp) = sp;

					/* doubly link list */
					LINKFOR(tp) = np;
					LINKBAK(np) = tp;
					SETNOTREE(np);
					protect(np);

					break;
				}
			}
		} else {
			Root = tp;
		}
	}

	/*
	 * Tell next block that this one is free.
	 * The first WORD of the next block contains self's address.
	 */
	/* LINTED improper alignment */
	tmp = NEXT(tp);
	unprotect(tmp);
	/* LINTED improper alignment */
	*(SELFP(tp)) = tp;
	SETBIT1(SIZE(tmp));
	ASSERT(ISBIT0(SIZE(tmp)));
	protect(tmp);
	protect(tp);
}

/*
 * Get more core. Gaps in memory are noted as busy blocks.
 */
static TREE *
morecore(size_t size)
{
	TREE	*tp;
	size_t	n, offset, requestsize;
	char	*addr;

	/* compute new amount of memory to get */
	tp = Bottom;
	n = size + 2 * WORDSIZE;
	addr = GETCORE(0);

	if (addr == ERRCORE)
		/* errno set by GETCORE sbrk */
		return (NULL);

	/* need to pad size out so that addr is aligned */
	if ((((size_t)addr) % ALIGN) != 0)
		offset = ALIGN - (size_t)addr % ALIGN;
	else
		offset = 0;

	if (tp)
		unprotect(tp);

	/* if not segmented memory, what we need may be smaller */
	if (addr == Baddr) {
		n -= WORDSIZE;
		if (tp != NULL)
			n -= SIZE(tp);
	}

	/* get a multiple of CORESIZE */
	n = ((n - 1) / CORESIZE + 1) * CORESIZE;
	requestsize = n + offset;

	/* check if nsize request could overflow in GETCORE */
	if (requestsize > MAX_MALLOC - (size_t)addr) {
		if (tp)
			protect(tp);
		errno = ENOMEM;
		return (NULL);
	}

	if (requestsize > MAX_GETCORE) {
		intptr_t	delta;
		/*
		 * the value required is too big for GETCORE() to deal with
		 * in one go, so use GETCORE() at most 2 times instead.
		 * Argument to GETCORE() must be multiple of ALIGN.
		 * If not, GETCORE(-MAX_GETCORE) will not return brk point
		 * to previous value, but will be ALIGN more.
		 * This would leave a small hole.
		 */
		delta = MAX_GETCORE;
		while (delta > 0) {
			if (GETCORE(delta) == ERRCORE) {
				if (tp)
					protect(tp);
				if (addr != GETCORE(0))
					(void) GETCORE(-MAX_GETCORE);
				return (NULL);
			}
			requestsize -= MAX_GETCORE;
			delta = requestsize;
		}
	} else if (GETCORE(requestsize) == ERRCORE) {
		if (tp)
			protect(tp);
		return (NULL);
	}

	/* contiguous memory */
	if (addr == Baddr) {
		ASSERT(offset == 0);
		if (tp) {
			addr = ((char *)tp);
			n += SIZE(tp) + 2 * WORDSIZE;
		} else {
			addr = Baddr - WORDSIZE;
			n += WORDSIZE;
		}
	} else {
		addr += offset;
	}

	/* new bottom address */
	Baddr = addr + n;

	/* new bottom block */
	/* LINTED improper alignment */
	tp = ((TREE *)addr);
	SIZE(tp) = n - 2 * WORDSIZE;
	ASSERT((SIZE(tp) % ALIGN) == 0);

	/* reserved the last word to head any noncontiguous memory */
	/* LINTED improper alignment */
	SETBIT0(SIZE(NEXT(tp)));

	/* non-contiguous memory, free old bottom block */
	if (Bottom && Bottom != tp) {
		SETBIT0(SIZE(Bottom));
		realfree(DATA(Bottom));
	}

	return (tp);
}

/*
 * Utility function to avoid protecting a tree node twice.
 * Return true if tp is in the NULL-terminated array of tree nodes.
 */
static int
in_list(TREE *tp, TREE **npp)
{
	TREE *sp;

	while ((sp = *npp++) != NULL)
		if (tp == sp)
			return (1);
	return (0);
}

/*
 * Tree rotation functions (BU: bottom-up, TD: top-down).
 * All functions are entered with the arguments unprotected.
 * They must return in the same condition, with all other elements
 * that have been unprotected during the operation re-protected.
 */
static void
LEFT1(TREE *x, TREE *y)
{
	TREE *node[3];
	TREE **npp = node;
	TREE *tp;

	if ((RIGHT(x) = LEFT(y)) != NULL) {
		unprotect(*npp++ = RIGHT(x));
		PARENT(RIGHT(x)) = x;
	}
	if ((PARENT(y) = PARENT(x)) != NULL) {
		unprotect(*npp++ = PARENT(x));
		if (LEFT(PARENT(x)) == x)
			LEFT(PARENT(y)) = y;
		else
			RIGHT(PARENT(y)) = y;
	}
	LEFT(y) = x;
	PARENT(x) = y;

	*npp = NULL;
	npp = node;
	while ((tp = *npp++) != NULL)
		if (tp != x && tp != y && !in_list(tp, npp))
			protect(tp);
}

static void
RIGHT1(TREE *x, TREE *y)
{
	TREE *node[3];
	TREE **npp = node;
	TREE *tp;

	if ((LEFT(x) = RIGHT(y)) != NULL) {
		unprotect(*npp++ = LEFT(x));
		PARENT(LEFT(x)) = x;
	}
	if ((PARENT(y) = PARENT(x)) != NULL) {
		unprotect(*npp++ = PARENT(x));
		if (LEFT(PARENT(x)) == x)
			LEFT(PARENT(y)) = y;
		else
			RIGHT(PARENT(y)) = y;
	}
	RIGHT(y) = x;
	PARENT(x) = y;

	*npp = NULL;
	npp = node;
	while ((tp = *npp++) != NULL)
		if (tp != x && tp != y && !in_list(tp, npp))
			protect(tp);
}

static void
BULEFT2(TREE *x, TREE *y, TREE *z)
{
	TREE *node[4];
	TREE **npp = node;
	TREE *tp;

	if ((RIGHT(x) = LEFT(y)) != NULL) {
		unprotect(*npp++ = RIGHT(x));
		PARENT(RIGHT(x)) = x;
	}
	if ((RIGHT(y) = LEFT(z)) != NULL) {
		unprotect(*npp++ = RIGHT(y));
		PARENT(RIGHT(y)) = y;
	}
	if ((PARENT(z) = PARENT(x)) != NULL) {
		unprotect(*npp++ = PARENT(x));
		if (LEFT(PARENT(x)) == x)
			LEFT(PARENT(z)) = z;
		else
			RIGHT(PARENT(z)) = z;
	}
	LEFT(z) = y;
	PARENT(y) = z;
	LEFT(y) = x;
	PARENT(x) = y;

	*npp = NULL;
	npp = node;
	while ((tp = *npp++) != NULL)
		if (tp != x && tp != y && tp != z && !in_list(tp, npp))
			protect(tp);
}

static void
BURIGHT2(TREE *x, TREE *y, TREE *z)
{
	TREE *node[4];
	TREE **npp = node;
	TREE *tp;

	if ((LEFT(x) = RIGHT(y)) != NULL) {
		unprotect(*npp++ = LEFT(x));
		PARENT(LEFT(x)) = x;
	}
	if ((LEFT(y) = RIGHT(z)) != NULL) {
		unprotect(*npp++ = LEFT(y));
		PARENT(LEFT(y)) = y;
	}
	if ((PARENT(z) = PARENT(x)) != NULL) {
		unprotect(*npp++ = PARENT(x));
		if (LEFT(PARENT(x)) == x)
			LEFT(PARENT(z)) = z;
		else
			RIGHT(PARENT(z)) = z;
	}
	RIGHT(z) = y;
	PARENT(y) = z;
	RIGHT(y) = x;
	PARENT(x) = y;

	*npp = NULL;
	npp = node;
	while ((tp = *npp++) != NULL)
		if (tp != x && tp != y && tp != z && !in_list(tp, npp))
			protect(tp);
}

static void
TDLEFT2(TREE *x, TREE *y, TREE *z)
{
	TREE *node[3];
	TREE **npp = node;
	TREE *tp;

	if ((RIGHT(y) = LEFT(z)) != NULL) {
		unprotect(*npp++ = RIGHT(y));
		PARENT(RIGHT(y)) = y;
	}
	if ((PARENT(z) = PARENT(x)) != NULL) {
		unprotect(*npp++ = PARENT(x));
		if (LEFT(PARENT(x)) == x)
			LEFT(PARENT(z)) = z;
		else
			RIGHT(PARENT(z)) = z;
	}
	PARENT(x) = z;
	LEFT(z) = x;

	*npp = NULL;
	npp = node;
	while ((tp = *npp++) != NULL)
		if (tp != x && tp != y && tp != z && !in_list(tp, npp))
			protect(tp);
}

#if 0	/* Not used, for now */
static void
TDRIGHT2(TREE *x, TREE *y, TREE *z)
{
	TREE *node[3];
	TREE **npp = node;
	TREE *tp;

	if ((LEFT(y) = RIGHT(z)) != NULL) {
		unprotect(*npp++ = LEFT(y));
		PARENT(LEFT(y)) = y;
	}
	if ((PARENT(z) = PARENT(x)) != NULL) {
		unprotect(*npp++ = PARENT(x));
		if (LEFT(PARENT(x)) == x)
			LEFT(PARENT(z)) = z;
		else
			RIGHT(PARENT(z)) = z;
	}
	PARENT(x) = z;
	RIGHT(z) = x;

	*npp = NULL;
	npp = node;
	while ((tp = *npp++) != NULL)
		if (tp != x && tp != y && tp != z && !in_list(tp, npp))
			protect(tp);
}
#endif

/*
 *	Delete a tree element
 */
static void
t_delete(TREE *op)
{
	TREE *tp, *sp, *gp;

	/* if this is a non-tree node */
	if (ISNOTREE(op)) {
		tp = LINKBAK(op);
		unprotect(tp);
		if ((sp = LINKFOR(op)) != NULL) {
			unprotect(sp);
			LINKBAK(sp) = tp;
			protect(sp);
		}
		LINKFOR(tp) = sp;
		protect(tp);
		return;
	}

	/* make op the root of the tree */
	if (PARENT(op))
		t_splay(op);

	/* if this is the start of a list */
	if ((tp = LINKFOR(op)) != NULL) {
		unprotect(tp);
		PARENT(tp) = NULL;
		if ((sp = LEFT(op)) != NULL) {
			unprotect(sp);
			PARENT(sp) = tp;
			protect(sp);
		}
		LEFT(tp) = sp;

		if ((sp = RIGHT(op)) != NULL) {
			unprotect(sp);
			PARENT(sp) = tp;
			protect(sp);
		}
		RIGHT(tp) = sp;

		Root = tp;
		protect(tp);
		return;
	}

	/* if op has a non-null left subtree */
	if ((tp = LEFT(op)) != NULL) {
		unprotect(tp);
		PARENT(tp) = NULL;
		if (RIGHT(op)) {
			/* make the right-end of the left subtree its root */
			while ((sp = RIGHT(tp)) != NULL) {
				unprotect(sp);
				if ((gp = RIGHT(sp)) != NULL) {
					unprotect(gp);
					TDLEFT2(tp, sp, gp);
					protect(sp);
					protect(tp);
					tp = gp;
				} else {
					LEFT1(tp, sp);
					protect(tp);
					tp = sp;
				}
			}

			/* hook the right subtree of op to the above elt */
			RIGHT(tp) = sp = RIGHT(op);
			unprotect(sp);
			PARENT(sp) = tp;
			protect(sp);
		}
		protect(tp);
	} else if ((tp = RIGHT(op)) != NULL) {	/* no left subtree */
		unprotect(tp);
		PARENT(tp) = NULL;
		protect(tp);
	}

	Root = tp;
}

/*
 *	Bottom up splaying (simple version).
 *	The basic idea is to roughly cut in half the
 *	path from Root to tp and make tp the new root.
 */
static void
t_splay(TREE *tp)
{
	TREE *pp, *gp;

	/* iterate until tp is the root */
	while ((pp = PARENT(tp)) != NULL) {
		unprotect(pp);
		/* grandparent of tp */
		gp = PARENT(pp);
		if (gp)
			unprotect(gp);

		/* x is a left child */
		if (LEFT(pp) == tp) {
			if (gp && LEFT(gp) == pp) {
				BURIGHT2(gp, pp, tp);
				protect(gp);
			} else {
				if (gp)
					protect(gp);
				RIGHT1(pp, tp);
			}
		} else {
			ASSERT(RIGHT(pp) == tp);
			if (gp && RIGHT(gp) == pp) {
				BULEFT2(gp, pp, tp);
				protect(gp);
			} else {
				if (gp)
					protect(gp);
				LEFT1(pp, tp);
			}
		}
		protect(pp);
		unprotect(tp);	/* just in case */
	}
}

void
free(void *old)
{
	(void) mutex_lock(&__watch_malloc_lock);
	free_unlocked(old);
	(void) mutex_unlock(&__watch_malloc_lock);
}


static void
free_unlocked(void *old)
{
	if (old != NULL)
		realfree(old);
}


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
 *		or if the heap has been detectably corrupted.
 *	[ENOMEM]
 *		if the requested memory could not be allocated.
 */

#define	misaligned(p)		((unsigned)(p) & 3)
		/* 4-byte "word" alignment is considered ok in LP64 */
#define	nextblk(p, size)	((TREE *)((char *)(p) + (size)))

void *
memalign(size_t align, size_t nbytes)
{
	size_t	reqsize;	/* Num of bytes to get from malloc() */
	TREE	*p;		/* Ptr returned from malloc() */
	TREE	*blk;		/* For addressing fragment blocks */
	size_t	blksize;	/* Current (shrinking) block size */
	TREE	*alignedp;	/* Ptr to properly aligned boundary */
	TREE	*aligned_blk;	/* The block to be returned */
	size_t	frag_size;	/* size of fragments fore and aft */
	size_t	x;

	/*
	 * check for valid size and alignment parameters
	 * MAX_ALIGN check prevents overflow in later calculation.
	 */
	if (nbytes == 0 || misaligned(align) || align == 0 ||
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

	/* check for size that could overflow ROUND calculation */
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
	p = (TREE *) malloc(reqsize);
	if (p == (TREE *) NULL) {
		/* malloc sets errno */
		return (NULL);
	}
	(void) mutex_lock(&__watch_malloc_lock);

	/*
	 * get size of the entire block (overhead and all)
	 */
	/* LINTED improper alignment */
	blk = BLOCK(p);			/* back up to get length word */
	unprotect(blk);
	blksize = SIZE(blk);
	CLRBITS01(blksize);

	/*
	 * locate the proper alignment boundary within the block.
	 */
	x = (size_t)p;
	if (x % align != 0)
		x += align - (x % align);
	alignedp = (TREE *)x;
	/* LINTED improper alignment */
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
			/* LINTED improper alignment */
			aligned_blk = nextblk(aligned_blk, align);
		}
		blksize -= frag_size;
		SIZE(aligned_blk) = blksize | BIT0;
		frag_size -= WORDSIZE;
		SIZE(blk) = frag_size | BIT0 | ISBIT1(SIZE(blk));
		free_unlocked(DATA(blk));
		/*
		 * free_unlocked(DATA(blk)) has the side-effect of calling
		 * protect() on the block following blk, that is, aligned_blk.
		 * We recover from this by unprotect()ing it here.
		 */
		unprotect(aligned_blk);
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
		/* LINTED improper alignment */
		blk = NEXT(aligned_blk);
		SETOLD01(SIZE(aligned_blk), blksize);
		frag_size -= WORDSIZE;
		SIZE(blk) = frag_size | BIT0;
		free_unlocked(DATA(blk));
	}
	copy_pattern(LIVEPAT, aligned_blk);
	protect(aligned_blk);
	(void) mutex_unlock(&__watch_malloc_lock);
	return (DATA(aligned_blk));
}

void *
valloc(size_t size)
{
	static unsigned pagesize;
	if (!pagesize)
		pagesize = _sysconf(_SC_PAGESIZE);
	return (memalign(pagesize, size));
}

void *
calloc(size_t num, size_t size)
{
	void *mp;
	size_t total;

	total = num * size;

	/* check for overflow */
	if (num != 0 && total / num != size) {
		errno = ENOMEM;
		return (NULL);
	}
	if ((mp = malloc(total)) != NULL)
		(void) memset(mp, 0, total);
	return (mp);
}

/* ARGSUSED1 */
void
cfree(void *p, size_t num, size_t size)
{
	free(p);
}

typedef struct {
	long cmd;
	prwatch_t prwatch;
} ctl_t;

static pid_t my_pid = 0;	/* to check for whether we fork()d */
static int dont_watch = 0;
static int do_stop = 0;
static int ctlfd = -1;
struct stat ctlstatb;
static int wflags = WA_WRITE;

static void
init_watch()
{
	char str[80];
	char *s;

	my_pid = getpid();

	dont_watch = 1;

	if ((s = getenv("MALLOC_DEBUG")) == NULL)
		return;

	s = strncpy(str, s, sizeof (str));
	while (s != NULL) {
		char *e = strchr(s, ',');
		if (e)
			*e++ = '\0';
		if (strcmp(s, "STOP") == 0)
			do_stop = 1;
		else if (strcmp(s, "WATCH") == 0)
			dont_watch = 0;
		else if (strcmp(s, "RW") == 0) {
			dont_watch = 0;
			wflags = WA_READ|WA_WRITE;
		}
		s = e;
	}

	if (dont_watch)
		return;

	if ((ctlfd = open("/proc/self/ctl", O_WRONLY)) < 0 ||
	    fstat(ctlfd, &ctlstatb) != 0) {
		if (ctlfd >= 0)
			(void) close(ctlfd);
		ctlfd = -1;
		dont_watch = 1;
		return;
	}
	/* close-on-exec */
	(void) fcntl(ctlfd, F_SETFD, 1);

	if (do_stop) {
		int pfd;
		pstatus_t pstatus;
		struct {
			long cmd;
			fltset_t fltset;
		} ctl;

		/*
		 * Play together with some /proc controller
		 * that has set other stop-on-fault flags.
		 */
		premptyset(&ctl.fltset);
		if ((pfd = open("/proc/self/status", O_RDONLY)) >= 0) {
			if (read(pfd, &pstatus, sizeof (pstatus))
			    == sizeof (pstatus))
				ctl.fltset = pstatus.pr_flttrace;
			(void) close(pfd);
		}
		praddset(&ctl.fltset, FLTWATCH);
		ctl.cmd = PCSFAULT;
		(void) write(ctlfd, &ctl, sizeof (ctl));
	}
}

static int
nowatch()
{
	struct stat statb;

	if (dont_watch)
		return (1);
	if (ctlfd < 0)	/* first time */
		init_watch();
	else if (fstat(ctlfd, &statb) != 0 ||
	    statb.st_dev != ctlstatb.st_dev ||
	    statb.st_ino != ctlstatb.st_ino) {
		/*
		 * Someone closed our file descriptor.
		 * Just open another one.
		 */
		if ((ctlfd = open("/proc/self/ctl", O_WRONLY)) < 0 ||
		    fstat(ctlfd, &ctlstatb) != 0) {
			if (ctlfd >= 0)
				(void) close(ctlfd);
			ctlfd = -1;
			dont_watch = 1;
			return (1);
		}
		/* close-on-exec */
		(void) fcntl(ctlfd, F_SETFD, 1);
	}
	if (my_pid != getpid()) {
		/*
		 * We fork()d since the last call to the allocator.
		 * watchpoints are not inherited across fork().
		 * XXX: how to recover from this ???
		 */
		dont_watch = 1;
		(void) close(ctlfd);
		ctlfd = -1;
	}
	return (dont_watch);
}

static void
protect(TREE *tp)
{
	ctl_t ctl;
	size_t size, sz;

	if (nowatch())
		return;
	if (tp == NULL || DATA(tp) == Baddr)
		return;

	sz = size = SIZE(tp);
	CLRBITS01(size);
	if (size == 0)
		return;
	if (ISBIT0(sz))		/* block is busy, protect only the head */
		size = 0;
	ctl.cmd = PCWATCH;
	ctl.prwatch.pr_vaddr = (uintptr_t)tp;
	ctl.prwatch.pr_size = size + WORDSIZE;
	ctl.prwatch.pr_wflags = wflags;
	(void) write(ctlfd, &ctl, sizeof (ctl));
}

static void
unprotect(TREE *tp)
{
	ctl_t ctl;

	if (nowatch())
		return;
	if (tp == NULL || DATA(tp) == Baddr)
		return;

	ctl.cmd = PCWATCH;
	ctl.prwatch.pr_vaddr = (uintptr_t)tp;
	ctl.prwatch.pr_size = WORDSIZE;		/* size is arbitrary */
	ctl.prwatch.pr_wflags = 0;		/* clear the watched area */
	(void) write(ctlfd, &ctl, sizeof (ctl));
}

static void
malloc_prepare()
{
	(void) mutex_lock(&__watch_malloc_lock);
}

static void
malloc_release()
{
	(void) mutex_unlock(&__watch_malloc_lock);
}

#pragma init(malloc_init)
static void
malloc_init(void)
{
	(void) pthread_atfork(malloc_prepare, malloc_release, malloc_release);
}
