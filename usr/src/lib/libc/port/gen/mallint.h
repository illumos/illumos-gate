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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


#include <sys/isa_defs.h>
#include <stdlib.h>
#include <memory.h>
#include <thread.h>
#include <synch.h>
#include <mtlib.h>
#include <errno.h>
#include <sys/types.h>
#include <string.h>
#include <limits.h>

/* debugging macros */
#ifdef	DEBUG
#define	ASSERT(p)	((void) ((p) || (abort(), 0)))
#define	COUNT(n)	((void) n++)
static int		nmalloc, nrealloc, nfree;
#else
#define	ASSERT(p)	((void)0)
#define	COUNT(n)	((void)0)
#endif /* DEBUG */

/* function to copy data from one area to another */
#define	MEMCOPY(to, fr, n)	((void) memcpy(to, fr, n))

/* for conveniences */
#ifndef NULL
#define	NULL		(0)
#endif

#define	WORDSIZE	(sizeof (WORD))
#define	MINSIZE		(sizeof (TREE) - sizeof (WORD))
#define	ROUND(s)	if (s % WORDSIZE) s += (WORDSIZE - (s % WORDSIZE))

#ifdef	DEBUG32
/*
 * The following definitions ease debugging
 * on a machine in which sizeof(pointer) == sizeof(int) == 4.
 * These definitions are not portable.
 *
 * Alignment (ALIGN) changed to 8 for SPARC ldd/std.
 */
#define	ALIGN	8
typedef int	WORD;
typedef struct _t_ {
	size_t		t_s;
	struct _t_	*t_p;
	struct _t_	*t_l;
	struct _t_	*t_r;
	struct _t_	*t_n;
	struct _t_	*t_d;
} TREE;
#define	SIZE(b)		((b)->t_s)
#define	AFTER(b)	((b)->t_p)
#define	PARENT(b)	((b)->t_p)
#define	LEFT(b)		((b)->t_l)
#define	RIGHT(b)	((b)->t_r)
#define	LINKFOR(b)	((b)->t_n)
#define	LINKBAK(b)	((b)->t_p)

#else	/* !DEBUG32 */
/*
 * All of our allocations will be aligned on the least multiple of 4,
 * at least, so the two low order bits are guaranteed to be available.
 */
#ifdef _LP64
#define	ALIGN		16
#else
#define	ALIGN		8
#endif

/* the proto-word; size must be ALIGN bytes */
typedef union _w_ {
	size_t		w_i;		/* an unsigned int */
	struct _t_	*w_p;		/* a pointer */
	char		w_a[ALIGN];	/* to force size */
} WORD;

/* structure of a node in the free tree */
typedef struct _t_ {
	WORD	t_s;	/* size of this element */
	WORD	t_p;	/* parent node */
	WORD	t_l;	/* left child */
	WORD	t_r;	/* right child */
	WORD	t_n;	/* next in link list */
	WORD	t_d;	/* dummy to reserve space for self-pointer */
} TREE;

/* usable # of bytes in the block */
#define	SIZE(b)		(((b)->t_s).w_i)

/* free tree pointers */
#define	PARENT(b)	(((b)->t_p).w_p)
#define	LEFT(b)		(((b)->t_l).w_p)
#define	RIGHT(b)	(((b)->t_r).w_p)

/* forward link in lists of small blocks */
#define	AFTER(b)	(((b)->t_p).w_p)

/* forward and backward links for lists in the tree */
#define	LINKFOR(b)	(((b)->t_n).w_p)
#define	LINKBAK(b)	(((b)->t_p).w_p)

#endif	/* DEBUG32 */

/* set/test indicator if a block is in the tree or in a list */
#define	SETNOTREE(b)	(LEFT(b) = (TREE *)(-1))
#define	ISNOTREE(b)	(LEFT(b) == (TREE *)(-1))

/* functions to get information on a block */
#define	DATA(b)		((char *)(((uintptr_t)(b)) + WORDSIZE))
#define	BLOCK(d)	((TREE *)(((uintptr_t)(d)) - WORDSIZE))
#define	SELFP(b)	((TREE **)(((uintptr_t)(b)) + SIZE(b)))
#define	LAST(b)		(*((TREE **)(((uintptr_t)(b)) - WORDSIZE)))
#define	NEXT(b)		((TREE *)(((uintptr_t)(b)) + SIZE(b) + WORDSIZE))
#define	BOTTOM(b)	((DATA(b) + SIZE(b) + WORDSIZE) == Baddr)

/* functions to set and test the lowest two bits of a word */
#define	BIT0		(01)		/* ...001 */
#define	BIT1		(02)		/* ...010 */
#define	BITS01		(03)		/* ...011 */
#define	ISBIT0(w)	((w) & BIT0)	/* Is busy? */
#define	ISBIT1(w)	((w) & BIT1)	/* Is the preceding free? */
#define	SETBIT0(w)	((w) |= BIT0)	/* Block is busy */
#define	SETBIT1(w)	((w) |= BIT1)	/* The preceding is free */
#define	CLRBIT0(w)	((w) &= ~BIT0)	/* Clean bit0 */
#define	CLRBIT1(w)	((w) &= ~BIT1)	/* Clean bit1 */
#define	SETBITS01(w)	((w) |= BITS01)	/* Set bits 0 & 1 */
#define	CLRBITS01(w)	((w) &= ~BITS01) /* Clean bits 0 & 1 */
#define	SETOLD01(n, o)	((n) |= (BITS01 & (o)))

/* system call to get more core */
#define	GETCORE		sbrk
#define	ERRCORE		((void *)(-1))
#define	CORESIZE	(1024*ALIGN)
#define	MAX_GETCORE (size_t)(SSIZE_MAX & ~(ALIGN - 1))	/* round down ALIGN */
#define	MAX_MALLOC (size_t)(SIZE_MAX - CORESIZE - 3 * ALIGN) /* overflow chk */
#define	MAX_ALIGN	(1 + (size_t)SSIZE_MAX)

extern void	*GETCORE(ssize_t);
extern void	_free_unlocked(void *);

extern mutex_t libc_malloc_lock;
