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
 * Copyright 1987 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"  /* from S5R2 1.2 */

/*LINTLIBRARY*/
/*
 *	ssignal, gsignal: software signals
 */
#include <signal.h>

/* Highest allowable user signal number */
#define	MAXSIG NSIG

/* Lowest allowable signal number (lowest user number is always 1) */
#define	MINSIG (-4)

/* Table of signal values */
typedef int (*sigfunc)();
sigfunc *ssigp;


sigfunc *
_ssig()
{
	if (ssigp == 0)
		ssigp = (sigfunc *)calloc(MAXSIG-MINSIG+1, sizeof (sigfunc));
	return (ssigp);
}

int
(*ssignal(sig, fn))()
register int sig, (*fn)();
{
	register int (*savefn)();
	register sigfunc *sp = _ssig();

	if (sp == 0)
		return ((int (*)())SIG_DFL);
	if (sig >= MINSIG && sig <= MAXSIG) {
		savefn = sp[sig-MINSIG];
		sp[sig-MINSIG] = fn;
	} else
		savefn = (int (*)())SIG_DFL;

	return (savefn);
}

int
gsignal(sig)
register int sig;
{
	register int (*sigfn)();
	register sigfunc *sp = _ssig();

	if (sp == 0)
		return (0);
	if (sig < MINSIG || sig > MAXSIG ||
				(sigfn = sp[sig-MINSIG]) == (int (*)())SIG_DFL)
		return (0);
	else if (sigfn == (int (*)())SIG_IGN)
		return (1);
	else {
		sp[sig-MINSIG] = (int (*)())SIG_DFL;
		return ((*sigfn)(sig));
	}
}
