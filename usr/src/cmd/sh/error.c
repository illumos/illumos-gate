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
 * Copyright 1990 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * UNIX shell
 */

#include	"defs.h"


/* ========	error handling	======== */

void
failed(unsigned char *s1, const char *s2)
{
	prp();
	prs_cntl(s1);
	if (s2) {
		prs(colon);
		prs((unsigned char *)s2);
	}
	newline();
	exitsh(ERROR);
}

void
error(unsigned char *s)
{
	failed(s, (const char *)NIL);
}

void
exitsh(int xno)
{
	/*
	 * Arrive here from `FATAL' errors
	 *  a) exit command,
	 *  b) default trap,
	 *  c) fault with no trap set.
	 *
	 * Action is to return to command level or exit.
	 */
	exitval = xno;
	flags |= eflag;
	if ((flags & (forcexit | forked | errflg | ttyflg)) != ttyflg)
		done(0);
	else
	{
		clearup();
		restore(0);
		(void) setb(1);
		execbrk = breakcnt = funcnt = 0;
		longjmp(errshell, 1);
	}
}

void
rmtemp(struct ionod *base)
{
	while (iotemp > base) {
		unlink(iotemp->ioname);
		free(iotemp->iolink);
		iotemp = iotemp->iolst;
	}
}

void
rmfunctmp(void)
{
	while (fiotemp) {
		unlink(fiotemp->ioname);
		fiotemp = fiotemp->iolst;
	}
}

void
failure(unsigned char *s1, unsigned char *s2)
{
	prp();
	prs_cntl(s1);
	if (s2) {
		prs(colon);
		prs(s2);
	}
	newline();

	if (flags & errflg)
		exitsh(ERROR);

	flags |= eflag;
	exitval = ERROR;
	exitset();
}
