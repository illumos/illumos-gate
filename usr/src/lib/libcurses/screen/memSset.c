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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

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

/*LINTLIBRARY*/

#include <sys/types.h>
#include "curses.h"

/*
 * additional memory routine to deal with memory areas in units of chtypes.
 */

void
memSset(chtype *s, chtype c, int n)

#if u3b
{
	int count;			/* %r8 */
	char *from;			/* %r7 */
	char *to; 			/* %r6 */

	count = (n - 1) * sizeof (chtype);
	if (count > 0) {
		chtype *sfrom = s;	/* %r5 */

		to = (char *)(sfrom + 1);
		from = (char *)sfrom;
		*sfrom = c;
		asm("	movblkb	%r8, %r7, %r6");
		/* bcopy (count, to, from) */
	} else if (count == 0)
		*s = c;
}
#else
#if u3b2 || u3b15
{
	char *to;			/* 0(%fp) */
	char *from;			/* 4(%fp) */
	int count;		/* %r8 */

	count = (n - 1) * sizeof (chtype);
	if (count > 0) {
		chtype *sfrom = s;	/* %r7 */

		to = (char *)(sfrom + 1);
		from = (char *)sfrom;
		*sfrom = c;

/* Evidently one can not specify the regs for movblb. So I move */
/* them in myself below to the regs where they belong. */
		asm("	movw	%r8,%r2");	/* count */
		asm("	movw	0(%fp),%r1");	/* to */
		asm("	movw	4(%fp),%r0");	/* from */
		asm("	movblb");
	} else if (count == 0)
		*s = c;
}
#else
{
    while (n-- > 0)
	*s++ = c;
}
#endif /* u3b2 || u3b15 */
#endif /* u3b */

/* The vax block copy command doesn't work the way I want. */
/* If anyone finds a version that does, I'd like to know. */
#if __bad__vax__

/* this is the code within memcpy which shows how to do a block copy */

memcpy(char *to, char *from, int count)
{
	if (count > 0) {
		asm("	movc3	12(ap),*4(ap),*8(ap)");
	}
}
#endif /* __bad__vax__ */
