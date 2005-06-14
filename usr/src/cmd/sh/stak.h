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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 *	UNIX shell
 */

/* To use stack as temporary workspace across
 * possible storage allocation (eg name lookup)
 * a) get ptr from `relstak'
 * b) can now use `pushstak'
 * c) then reset with `setstak'
 * d) `absstak' gives real address if needed
 */
#define		relstak()	(staktop-stakbot)
#define		absstak(x)	(stakbot+Rcheat(x))
#define		setstak(x)	(staktop=absstak(x))
#define		pushstak(c)	(*staktop++=(c))
#define		zerostak()	(*staktop=0)

/* Used to address an item left on the top of
 * the stack (very temporary)
 */
#define		curstak()	(staktop)

/* `usestak' before `pushstak' then `fixstak'
 * These routines are safe against heap
 * being allocated.
 */
#define		usestak()	{locstak();}

/* for local use only since it hands
 * out a real address for the stack top
 */
extern unsigned char		*locstak();

/* Will allocate the item being used and return its
 * address (safe now).
 */
#define		fixstak()	endstak(staktop)

/* For use after `locstak' to hand back
 * new stack top and then allocate item
 */
extern unsigned char		*endstak();

/* Copy a string onto the stack and
 * allocate the space.
 */
extern unsigned char		*cpystak();

/* Copy a string onto the stack, checking for stack overflow
 * as the copy is done.  Same calling sequence as "movstr".
 */
extern unsigned char		*movstrstak();

/* Move bytes onto the stack, checking for stack overflow
 * as the copy is done.  Same calling sequence as the C
 * library routine "memcpy".
 */
extern unsigned char		*memcpystak();

/* Allocate given ammount of stack space */
extern unsigned char		*getstak();

/* Grow the data segment to include a given location */
extern void		growstak();

/* A chain of ptrs of stack blocks that
 * have become covered by heap allocation.
 * `tdystak' will return them to the heap.
 */
extern struct blk	*stakbsy;

/* Base of the entire stack */
extern unsigned char		*stakbas;

/* Top of entire stack */
extern unsigned char		*brkend;

/* Base of current item */
extern unsigned char		*stakbot;

/* Top of current item */
extern unsigned char		*staktop;

/* Used with tdystak */
extern unsigned char		*savstak();
