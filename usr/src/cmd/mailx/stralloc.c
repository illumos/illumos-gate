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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
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

/*
 * mailx -- a modified version of a University of California at Berkeley
 *	mail program
 *
 * Memory allocation routines.
 * Memory handed out here are reclaimed at the top of the command
 * loop each time, so they need not be freed.
 */

#include "rcv.h"
#include <locale.h>

static void		*lastptr;	/* addr of last buffer allocated */
static struct strings	*lastsp;	/* last string space allocated from */

/*
 * Allocate size more bytes of space and return the address of the
 * first byte to the caller.  An even number of bytes are always
 * allocated so that the space will always be on a word boundary.
 * The string spaces are of exponentially increasing size, to satisfy
 * the occasional user with enormous string size requests.
 */

void *
salloc(unsigned size)
{
	register char *t;
	register unsigned s;
	register struct strings *sp;
	int index;

	s = size;
#if defined(u3b) || defined(sparc)
	s += 3;		/* needs alignment on quad boundary */
	s &= ~03;
#elif defined(i386)
	s++;
	s &= ~01;
#else
#error Unknown architecture!
#endif
	index = 0;
	for (sp = &stringdope[0]; sp < &stringdope[NSPACE]; sp++) {
		if (sp->s_topFree == NOSTR && (STRINGSIZE << index) >= s)
			break;
		if (sp->s_nleft >= s)
			break;
		index++;
	}
	if (sp >= &stringdope[NSPACE])
		panic("String too large");
	if (sp->s_topFree == NOSTR) {
		index = sp - &stringdope[0];
		sp->s_topFree = (char *) calloc(STRINGSIZE << index,
		    (unsigned) 1);
		if (sp->s_topFree == NOSTR) {
			fprintf(stderr, gettext("No room for space %d\n"),
			    index);
			panic("Internal error");
		}
		sp->s_nextFree = sp->s_topFree;
		sp->s_nleft = STRINGSIZE << index;
	}
	sp->s_nleft -= s;
	t = sp->s_nextFree;
	sp->s_nextFree += s;
	lastptr = t;
	lastsp = sp;
	return(t);
}

/*
 * Reallocate size bytes of space and return the address of the
 * first byte to the caller.  The old data is copied into the new area.
 */

void *
srealloc(void *optr, unsigned size)
{
	void *nptr;

	/* if we just want to expand the last allocation, that's easy */
	if (optr == lastptr) {
		register unsigned s, delta;
		register struct strings *sp = lastsp;

		s = size;
#if defined(u3b) || defined(sparc)
		s += 3;		/* needs alignment on quad boundary */
		s &= ~03;
#elif defined(i386)
		s++;
		s &= ~01;
#else
#error Unknown architecture!
#endif /* defined(u3b) || defined(sparc) */
		delta = s - (sp->s_nextFree - (char *)optr);
		if (delta <= sp->s_nleft) {
			sp->s_nextFree += delta;
			sp->s_nleft -= delta;
			return (optr);
		}
	}
	nptr = salloc(size);
	if (nptr)
		memcpy(nptr, optr, size);	/* XXX - copying too much */
	return nptr;
}

/*
 * Reset the string area to be empty.
 * Called to free all strings allocated
 * since last reset.
 */
void 
sreset(void)
{
	register struct strings *sp;
	register int index;

	if (noreset)
		return;
	minit();
	index = 0;
	for (sp = &stringdope[0]; sp < &stringdope[NSPACE]; sp++) {
		if (sp->s_topFree == NOSTR)
			continue;
		sp->s_nextFree = sp->s_topFree;
		sp->s_nleft = STRINGSIZE << index;
		index++;
	}
	lastptr = NULL;
	lastsp = NULL;
}
