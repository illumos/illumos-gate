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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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
error(const char *s)
{
	prp();
	prs(_gettext(s));
	newline();
	exitsh(ERROR);
}

static void
failed_body(unsigned char *s1, const char *s2, unsigned char *s3, int gflag)
{
	prp();
	if (gflag)
		prs(_gettext((const char *)s1));
	else
		prs_cntl(s1);
	prs(colon);
	prs(_gettext(s2));
	if (s3)
		prs(s3);
	newline();
}

void
failed_real(unsigned char *s1, const char *s2, unsigned char *s3)
{
	failed_body(s1, s2, s3, 0);
	exitsh(ERROR);
}

void
failure_real(unsigned char *s1, const char *s2, int gflag)
{
	failed_body(s1, s2, NULL, gflag);

	if (flags & errflg)
		exitsh(ERROR);

	flags |= eflag;
	exitval = ERROR;
	exitset();
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
