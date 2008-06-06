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
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	Memory management: malloc(), realloc(), free().
 *
 *	The following #-parameters may be redefined:
 *	SEGMENTED: if defined, memory requests are assumed to be
 *		non-contiguous across calls of GETCORE's.
 *	GETCORE: a function to get more core memory. If not SEGMENTED,
 *		GETCORE(0) is assumed to return the next available
 *		address. Default is 'sbrk'.
 *	ERRCORE: the error code as returned by GETCORE.
 *		Default is (char *)(-1).
 *	CORESIZE: a desired unit (measured in bytes) to be used
 *		with GETCORE. Default is (1024*ALIGN).
 *
 *	This algorithm is based on a  best fit strategy with lists of
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

#include "lint.h"
#include "mallint.h"
#include "mtlib.h"

/*
 * Some abusers of the system (notably java1.2) acquire __malloc_lock
 * in order to prevent threads from holding it while they are being
 * suspended via thr_suspend() or thr_suspend_allmutators().
 * This never worked when alternate malloc() libraries were used
 * because they don't use __malloc_lock for their locking strategy.
 * We leave __malloc_lock as an external variable to satisfy these
 * old programs, but we define a new lock, private to libc, to do the
 * real locking: libc_malloc_lock.  This puts libc's malloc() package
 * on the same footing as all other malloc packages.
 */
mutex_t __malloc_lock = DEFAULTMUTEX;
mutex_t libc_malloc_lock = DEFAULTMUTEX;

static TREE	*Root,		/* root of the free tree */
		*Bottom,	/* the last free chunk in the arena */
		*_morecore(size_t);	/* function to get more core */

static char	*Baddr;		/* current high address of the arena */
static char	*Lfree;		/* last freed block with data intact */

static void	t_delete(TREE *);
static void	t_splay(TREE *);
static void	realfree(void *);
static void	cleanfree(void *);
static void	*_malloc_unlocked(size_t);

#define	FREESIZE (1<<5) /* size for preserving free blocks until next malloc */
#define	FREEMASK FREESIZE-1

static void *flist[FREESIZE];	/* list of blocks to be freed on next malloc */
static int freeidx;		/* index of free blocks in flist % FREESIZE */

/*
 * Interfaces used only by atfork_init() functions.
 */
void
malloc_locks(void)
{
	(void) mutex_lock(&libc_malloc_lock);
}

void
malloc_unlocks(void)
{
	(void) mutex_unlock(&libc_malloc_lock);
}

/*
 *	Allocation of small blocks
 */
static TREE	*List[MINSIZE/WORDSIZE-1]; /* lists of small blocks */

static void *
_smalloc(size_t size)
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
		TREE *np;
		int n;
		/* number of blocks to get at one time */
#define	NPS (WORDSIZE*8)
		ASSERT((size + WORDSIZE) * NPS >= MINSIZE);

		/* get NPS of these block types */
		if ((List[i] = _malloc_unlocked((size + WORDSIZE) * NPS)) == 0)
			return (0);

		/* make them into a link list */
		for (n = 0, np = List[i]; n < NPS; ++n) {
			tp = np;
			SIZE(tp) = size;
			np = NEXT(tp);
			AFTER(tp) = np;
		}
		AFTER(tp) = NULL;
	}

	/* allocate from the head of the queue */
	tp = List[i];
	List[i] = AFTER(tp);
	SETBIT0(SIZE(tp));
	return (DATA(tp));
}

void *
malloc(size_t size)
{
	void *ret;

	if (!primary_link_map) {
		errno = ENOTSUP;
		return (NULL);
	}
	assert_no_libc_locks_held();
	(void) mutex_lock(&libc_malloc_lock);
	ret = _malloc_unlocked(size);
	(void) mutex_unlock(&libc_malloc_lock);
	return (ret);
}

static void *
_malloc_unlocked(size_t size)
{
	size_t	n;
	TREE	*tp, *sp;
	size_t	o_bit1;

	COUNT(nmalloc);
	ASSERT(WORDSIZE == ALIGN);

	/* check for size that could overflow calculations */
	if (size > MAX_MALLOC) {
		errno = ENOMEM;
		return (NULL);
	}

	/* make sure that size is 0 mod ALIGN */
	ROUND(size);

	/* see if the last free block can be used */
	if (Lfree) {
		sp = BLOCK(Lfree);
		n = SIZE(sp);
		CLRBITS01(n);
		if (n == size) {
			/*
			 * exact match, use it as is
			 */
			freeidx = (freeidx + FREESIZE - 1) &
			    FREEMASK; /* 1 back */
			flist[freeidx] = Lfree = NULL;
			return (DATA(sp));
		} else if (size >= MINSIZE && n > size) {
			/*
			 * got a big enough piece
			 */
			freeidx = (freeidx + FREESIZE - 1) &
			    FREEMASK; /* 1 back */
			flist[freeidx] = Lfree = NULL;
			o_bit1 = SIZE(sp) & BIT1;
			SIZE(sp) = n;
			goto leftover;
		}
	}
	o_bit1 = 0;

	/* perform free's of space since last malloc */
	cleanfree(NULL);

	/* small blocks */
	if (size < MINSIZE)
		return (_smalloc(size));

	/* search for an elt of the right size */
	sp = NULL;
	n  = 0;
	if (Root) {
		tp = Root;
		for (;;) {
			/* branch left */
			if (SIZE(tp) >= size) {
				if (n == 0 || n >= SIZE(tp)) {
					sp = tp;
					n = SIZE(tp);
				}
				if (LEFT(tp))
					tp = LEFT(tp);
				else
					break;
			} else { /* branch right */
				if (RIGHT(tp))
					tp = RIGHT(tp);
				else
					break;
			}
		}

		if (sp) {
			t_delete(sp);
		} else if (tp != Root) {
			/* make the searched-to element the root */
			t_splay(tp);
			Root = tp;
		}
	}

	/* if found none fitted in the tree */
	if (!sp) {
		if (Bottom && size <= SIZE(Bottom)) {
			sp = Bottom;
			CLRBITS01(SIZE(sp));
		} else if ((sp = _morecore(size)) == NULL) /* no more memory */
			return (NULL);
	}

	/* tell the forward neighbor that we're busy */
	CLRBIT1(SIZE(NEXT(sp)));

	ASSERT(ISBIT0(SIZE(NEXT(sp))));

leftover:
	/* if the leftover is enough for a new free piece */
	if ((n = (SIZE(sp) - size)) >= MINSIZE + WORDSIZE) {
		n -= WORDSIZE;
		SIZE(sp) = size;
		tp = NEXT(sp);
		SIZE(tp) = n|BIT0;
		realfree(DATA(tp));
	} else if (BOTTOM(sp))
		Bottom = NULL;

	/* return the allocated space */
	SIZE(sp) |= BIT0 | o_bit1;
	return (DATA(sp));
}


/*
 * realloc().
 *
 * If the block size is increasing, we try forward merging first.
 * This is not best-fit but it avoids some data recopying.
 */
void *
realloc(void *old, size_t size)
{
	TREE	*tp, *np;
	size_t	ts;
	char	*new;

	if (!primary_link_map) {
		errno = ENOTSUP;
		return (NULL);
	}

	assert_no_libc_locks_held();
	COUNT(nrealloc);

	/* check for size that could overflow calculations */
	if (size > MAX_MALLOC) {
		errno = ENOMEM;
		return (NULL);
	}

	/* pointer to the block */
	(void) mutex_lock(&libc_malloc_lock);
	if (old == NULL) {
		new = _malloc_unlocked(size);
		(void) mutex_unlock(&libc_malloc_lock);
		return (new);
	}

	/* perform free's of space since last malloc */
	cleanfree(old);

	/* make sure that size is 0 mod ALIGN */
	ROUND(size);

	tp = BLOCK(old);
	ts = SIZE(tp);

	/* if the block was freed, data has been destroyed. */
	if (!ISBIT0(ts)) {
		(void) mutex_unlock(&libc_malloc_lock);
		return (NULL);
	}

	/* nothing to do */
	CLRBITS01(SIZE(tp));
	if (size == SIZE(tp)) {
		SIZE(tp) = ts;
		(void) mutex_unlock(&libc_malloc_lock);
		return (old);
	}

	/* special cases involving small blocks */
	if (size < MINSIZE || SIZE(tp) < MINSIZE) {
		/* free is size is zero */
		if (size == 0) {
			SETOLD01(SIZE(tp), ts);
			_free_unlocked(old);
			(void) mutex_unlock(&libc_malloc_lock);
			return (NULL);
		} else {
			goto call_malloc;
		}
	}

	/* block is increasing in size, try merging the next block */
	if (size > SIZE(tp)) {
		np = NEXT(tp);
		if (!ISBIT0(SIZE(np))) {
			ASSERT(SIZE(np) >= MINSIZE);
			ASSERT(!ISBIT1(SIZE(np)));
			SIZE(tp) += SIZE(np) + WORDSIZE;
			if (np != Bottom)
				t_delete(np);
			else
				Bottom = NULL;
			CLRBIT1(SIZE(NEXT(np)));
		}

#ifndef SEGMENTED
		/* not enough & at TRUE end of memory, try extending core */
		if (size > SIZE(tp) && BOTTOM(tp) && GETCORE(0) == Baddr) {
			Bottom = tp;
			if ((tp = _morecore(size)) == NULL) {
				tp = Bottom;
				Bottom = NULL;
				}
		}
#endif
	}

	/* got enough space to use */
	if (size <= SIZE(tp)) {
		size_t n;

chop_big:
		if ((n = (SIZE(tp) - size)) >= MINSIZE + WORDSIZE) {
			n -= WORDSIZE;
			SIZE(tp) = size;
			np = NEXT(tp);
			SIZE(np) = n|BIT0;
			realfree(DATA(np));
		} else if (BOTTOM(tp))
			Bottom = NULL;

		/* the previous block may be free */
		SETOLD01(SIZE(tp), ts);
		(void) mutex_unlock(&libc_malloc_lock);
		return (old);
	}

	/* call malloc to get a new block */
call_malloc:
	SETOLD01(SIZE(tp), ts);
	if ((new = _malloc_unlocked(size)) != NULL) {
		CLRBITS01(ts);
		if (ts > size)
			ts = size;
		MEMCOPY(new, old, ts);
		_free_unlocked(old);
		(void) mutex_unlock(&libc_malloc_lock);
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
		if (size < SIZE(tp)) {			/* case 1. */
			SETOLD01(SIZE(tp), ts);
			(void) mutex_unlock(&libc_malloc_lock);
			return (old);
		} else if (size < MINSIZE) {		/* case 2. */
			size = MINSIZE;
			goto call_malloc;
		}
	} else if (size < MINSIZE) {			/* case 3. */
		size = MINSIZE;
		goto chop_big;
	} else if (ISBIT1(ts) &&
	    (SIZE(np = LAST(tp)) + SIZE(tp) + WORDSIZE) >= size) {
		ASSERT(!ISBIT0(SIZE(np)));
		t_delete(np);
		SIZE(np) += SIZE(tp) + WORDSIZE;
		/*
		 * Since the copy may overlap, use memmove() if available.
		 * Otherwise, copy by hand.
		 */
		(void) memmove(DATA(np), old, SIZE(tp));
		old = DATA(np);
		tp = np;
		CLRBIT1(ts);
		goto chop_big;
	}
	SETOLD01(SIZE(tp), ts);
	(void) mutex_unlock(&libc_malloc_lock);
	return (NULL);
}


/*
 * realfree().
 *
 * Coalescing of adjacent free blocks is done first.
 * Then, the new free block is leaf-inserted into the free tree
 * without splaying. This strategy does not guarantee the amortized
 * O(nlogn) behaviour for the insert/delete/find set of operations
 * on the tree. In practice, however, free is much more infrequent
 * than malloc/realloc and the tree searches performed by these
 * functions adequately keep the tree in balance.
 */
static void
realfree(void *old)
{
	TREE	*tp, *sp, *np;
	size_t	ts, size;

	COUNT(nfree);

	/* pointer to the block */
	tp = BLOCK(old);
	ts = SIZE(tp);
	if (!ISBIT0(ts))
		return;
	CLRBITS01(SIZE(tp));

	/* small block, put it in the right linked list */
	if (SIZE(tp) < MINSIZE) {
		ASSERT(SIZE(tp) / WORDSIZE >= 1);
		ts = SIZE(tp) / WORDSIZE - 1;
		AFTER(tp) = List[ts];
		List[ts] = tp;
		return;
	}

	/* see if coalescing with next block is warranted */
	np = NEXT(tp);
	if (!ISBIT0(SIZE(np))) {
		if (np != Bottom)
			t_delete(np);
		SIZE(tp) += SIZE(np) + WORDSIZE;
	}

	/* the same with the preceding block */
	if (ISBIT1(ts)) {
		np = LAST(tp);
		ASSERT(!ISBIT0(SIZE(np)));
		ASSERT(np != Bottom);
		t_delete(np);
		SIZE(np) += SIZE(tp) + WORDSIZE;
		tp = np;
	}

	/* initialize tree info */
	PARENT(tp) = LEFT(tp) = RIGHT(tp) = LINKFOR(tp) = NULL;

	/* the last word of the block contains self's address */
	*(SELFP(tp)) = tp;

	/* set bottom block, or insert in the free tree */
	if (BOTTOM(tp))
		Bottom = tp;
	else {
		/* search for the place to insert */
		if (Root) {
			size = SIZE(tp);
			np = Root;
			for (;;) {
				if (SIZE(np) > size) {
					if (LEFT(np))
						np = LEFT(np);
					else {
						LEFT(np) = tp;
						PARENT(tp) = np;
						break;
					}
				} else if (SIZE(np) < size) {
					if (RIGHT(np))
						np = RIGHT(np);
					else {
						RIGHT(np) = tp;
						PARENT(tp) = np;
						break;
					}
				} else {
					if ((sp = PARENT(np)) != NULL) {
						if (np == LEFT(sp))
							LEFT(sp) = tp;
						else
							RIGHT(sp) = tp;
						PARENT(tp) = sp;
					} else
						Root = tp;

					/* insert to head of list */
					if ((sp = LEFT(np)) != NULL)
						PARENT(sp) = tp;
					LEFT(tp) = sp;

					if ((sp = RIGHT(np)) != NULL)
						PARENT(sp) = tp;
					RIGHT(tp) = sp;

					/* doubly link list */
					LINKFOR(tp) = np;
					LINKBAK(np) = tp;
					SETNOTREE(np);

					break;
				}
			}
		} else
			Root = tp;
	}

	/* tell next block that this one is free */
	SETBIT1(SIZE(NEXT(tp)));

	ASSERT(ISBIT0(SIZE(NEXT(tp))));
}

/*
 * Get more core. Gaps in memory are noted as busy blocks.
 */
static TREE *
_morecore(size_t size)
{
	TREE	*tp;
	ssize_t	n, offset;
	char	*addr;
	ssize_t	nsize;

	/* compute new amount of memory to get */
	tp = Bottom;
	n = (ssize_t)size + 2 * WORDSIZE;
	addr = GETCORE(0);

	if (addr == ERRCORE)
		return (NULL);

	/* need to pad size out so that addr is aligned */
	if ((((uintptr_t)addr) % ALIGN) != 0)
		offset = ALIGN - (uintptr_t)addr % ALIGN;
	else
		offset = 0;

#ifndef SEGMENTED
	/* if not segmented memory, what we need may be smaller */
	if (addr == Baddr) {
		n -= WORDSIZE;
		if (tp != NULL)
			n -= SIZE(tp);
	}
#endif

	/* get a multiple of CORESIZE */
	n = ((n - 1) / CORESIZE + 1) * CORESIZE;
	nsize = n + offset;

	/* check if nsize request could overflow in GETCORE */
	if ((size_t)nsize > MAX_MALLOC - (uintptr_t)addr) {
		errno = ENOMEM;
		return (NULL);
	}

	if ((size_t)nsize <= MAX_GETCORE) {
		if (GETCORE(nsize) == ERRCORE)
			return (NULL);
	} else {
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
				if (addr != GETCORE(0))
					(void) GETCORE(-MAX_GETCORE);
				return (NULL);
			}
			nsize -= MAX_GETCORE;
			delta = nsize;
		}
	}

	/* contiguous memory */
	if (addr == Baddr) {
		ASSERT(offset == 0);
		if (tp) {
			addr = (char *)tp;
			n += SIZE(tp) + 2 * WORDSIZE;
		} else {
			addr = Baddr - WORDSIZE;
			n += WORDSIZE;
		}
	} else
		addr += offset;

	/* new bottom address */
	Baddr = addr + n;

	/* new bottom block */
	tp = (TREE *)(uintptr_t)addr;
	SIZE(tp) = n - 2 * WORDSIZE;
	ASSERT((SIZE(tp) % ALIGN) == 0);

	/* reserved the last word to head any noncontiguous memory */
	SETBIT0(SIZE(NEXT(tp)));

	/* non-contiguous memory, free old bottom block */
	if (Bottom && Bottom != tp) {
		SETBIT0(SIZE(Bottom));
		realfree(DATA(Bottom));
	}

	return (tp);
}


/*
 * Tree rotation functions (BU: bottom-up, TD: top-down)
 */

#define	LEFT1(x, y)		\
			if ((RIGHT(x) = LEFT(y)) != NULL) PARENT(RIGHT(x)) = x;\
			if ((PARENT(y) = PARENT(x)) != NULL)\
				if (LEFT(PARENT(x)) == x) LEFT(PARENT(y)) = y;\
				else RIGHT(PARENT(y)) = y;\
			LEFT(y) = x; PARENT(x) = y

#define	RIGHT1(x, y)		\
			if ((LEFT(x) = RIGHT(y)) != NULL) PARENT(LEFT(x)) = x;\
			if ((PARENT(y) = PARENT(x)) != NULL)\
				if (LEFT(PARENT(x)) == x) LEFT(PARENT(y)) = y;\
				else RIGHT(PARENT(y)) = y;\
			RIGHT(y) = x; PARENT(x) = y

#define	BULEFT2(x, y, z)	\
			if ((RIGHT(x) = LEFT(y)) != NULL) PARENT(RIGHT(x)) = x;\
			if ((RIGHT(y) = LEFT(z)) != NULL) PARENT(RIGHT(y)) = y;\
			if ((PARENT(z) = PARENT(x)) != NULL)\
				if (LEFT(PARENT(x)) == x) LEFT(PARENT(z)) = z;\
				else RIGHT(PARENT(z)) = z;\
			LEFT(z) = y; PARENT(y) = z; LEFT(y) = x; PARENT(x) = y

#define	BURIGHT2(x, y, z)	\
			if ((LEFT(x) = RIGHT(y)) != NULL) PARENT(LEFT(x)) = x;\
			if ((LEFT(y) = RIGHT(z)) != NULL) PARENT(LEFT(y)) = y;\
			if ((PARENT(z) = PARENT(x)) != NULL)\
				if (LEFT(PARENT(x)) == x) LEFT(PARENT(z)) = z;\
				else RIGHT(PARENT(z)) = z;\
			RIGHT(z) = y; PARENT(y) = z; RIGHT(y) = x; PARENT(x) = y

#define	TDLEFT2(x, y, z)	\
			if ((RIGHT(y) = LEFT(z)) != NULL) PARENT(RIGHT(y)) = y;\
			if ((PARENT(z) = PARENT(x)) != NULL)\
				if (LEFT(PARENT(x)) == x) LEFT(PARENT(z)) = z;\
				else RIGHT(PARENT(z)) = z;\
			PARENT(x) = z; LEFT(z) = x;

#define	TDRIGHT2(x, y, z)	\
			if ((LEFT(y) = RIGHT(z)) != NULL) PARENT(LEFT(y)) = y;\
			if ((PARENT(z) = PARENT(x)) != NULL)\
				if (LEFT(PARENT(x)) == x) LEFT(PARENT(z)) = z;\
				else RIGHT(PARENT(z)) = z;\
			PARENT(x) = z; RIGHT(z) = x;

/*
 * Delete a tree element
 */
static void
t_delete(TREE *op)
{
	TREE	*tp, *sp, *gp;

	/* if this is a non-tree node */
	if (ISNOTREE(op)) {
		tp = LINKBAK(op);
		if ((sp = LINKFOR(op)) != NULL)
			LINKBAK(sp) = tp;
		LINKFOR(tp) = sp;
		return;
	}

	/* make op the root of the tree */
	if (PARENT(op))
		t_splay(op);

	/* if this is the start of a list */
	if ((tp = LINKFOR(op)) != NULL) {
		PARENT(tp) = NULL;
		if ((sp = LEFT(op)) != NULL)
			PARENT(sp) = tp;
		LEFT(tp) = sp;

		if ((sp = RIGHT(op)) != NULL)
			PARENT(sp) = tp;
		RIGHT(tp) = sp;

		Root = tp;
		return;
	}

	/* if op has a non-null left subtree */
	if ((tp = LEFT(op)) != NULL) {
		PARENT(tp) = NULL;

		if (RIGHT(op)) {
			/* make the right-end of the left subtree its root */
			while ((sp = RIGHT(tp)) != NULL) {
				if ((gp = RIGHT(sp)) != NULL) {
					TDLEFT2(tp, sp, gp);
					tp = gp;
				} else {
					LEFT1(tp, sp);
					tp = sp;
				}
			}

			/* hook the right subtree of op to the above elt */
			RIGHT(tp) = RIGHT(op);
			PARENT(RIGHT(tp)) = tp;
		}
	} else if ((tp = RIGHT(op)) != NULL)	/* no left subtree */
		PARENT(tp) = NULL;

	Root = tp;
}

/*
 * Bottom up splaying (simple version).
 * The basic idea is to roughly cut in half the
 * path from Root to tp and make tp the new root.
 */
static void
t_splay(TREE *tp)
{
	TREE	*pp, *gp;

	/* iterate until tp is the root */
	while ((pp = PARENT(tp)) != NULL) {
		/* grandparent of tp */
		gp = PARENT(pp);

		/* x is a left child */
		if (LEFT(pp) == tp) {
			if (gp && LEFT(gp) == pp) {
				BURIGHT2(gp, pp, tp);
			} else {
				RIGHT1(pp, tp);
			}
		} else {
			ASSERT(RIGHT(pp) == tp);
			if (gp && RIGHT(gp) == pp) {
				BULEFT2(gp, pp, tp);
			} else {
				LEFT1(pp, tp);
			}
		}
	}
}


/*
 *	free().
 *	Performs a delayed free of the block pointed to
 *	by old. The pointer to old is saved on a list, flist,
 *	until the next malloc or realloc. At that time, all the
 *	blocks pointed to in flist are actually freed via
 *	realfree(). This allows the contents of free blocks to
 *	remain undisturbed until the next malloc or realloc.
 */
void
free(void *old)
{
	if (!primary_link_map) {
		errno = ENOTSUP;
		return;
	}
	assert_no_libc_locks_held();
	(void) mutex_lock(&libc_malloc_lock);
	_free_unlocked(old);
	(void) mutex_unlock(&libc_malloc_lock);
}


void
_free_unlocked(void *old)
{
	int	i;

	if (old == NULL)
		return;

	/*
	 * Make sure the same data block is not freed twice.
	 * 3 cases are checked.  It returns immediately if either
	 * one of the conditions is true.
	 *	1. Last freed.
	 *	2. Not in use or freed already.
	 *	3. In the free list.
	 */
	if (old == Lfree)
		return;
	if (!ISBIT0(SIZE(BLOCK(old))))
		return;
	for (i = 0; i < freeidx; i++)
		if (old == flist[i])
			return;

	if (flist[freeidx] != NULL)
		realfree(flist[freeidx]);
	flist[freeidx] = Lfree = old;
	freeidx = (freeidx + 1) & FREEMASK; /* one forward */
}

/*
 * cleanfree() frees all the blocks pointed to be flist.
 *
 * realloc() should work if it is called with a pointer
 * to a block that was freed since the last call to malloc() or
 * realloc(). If cleanfree() is called from realloc(), ptr
 * is set to the old block and that block should not be
 * freed since it is actually being reallocated.
 */
static void
cleanfree(void *ptr)
{
	char	**flp;

	flp = (char **)&(flist[freeidx]);
	for (;;) {
		if (flp == (char **)&(flist[0]))
			flp = (char **)&(flist[FREESIZE]);
		if (*--flp == NULL)
			break;
		if (*flp != ptr)
			realfree(*flp);
		*flp = NULL;
	}
	freeidx = 0;
	Lfree = NULL;
}
