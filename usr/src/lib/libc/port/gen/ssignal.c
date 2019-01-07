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
/*	All Rights Reserved	*/

/*
 *	ssignal, gsignal: software signals
 */

#include "lint.h"
#include <sys/types.h>
#include <signal.h>

/* Highest allowable user signal number */
#define	MAXSIGNUM	17

/* Lowest allowable signal number (lowest user number is always 1) */
#define	MINSIG	(-4)

/* Table of signal values */
static int (*sigs[MAXSIGNUM-MINSIG+1])(int);

int (*
ssignal(int sig, int (*action)(int)))(int)
{
	int (*savefn)(int);

	if (sig >= MINSIG && sig <= MAXSIGNUM) {
		savefn = sigs[sig-MINSIG];
		sigs[sig-MINSIG] = action;
	} else {
		savefn = (int(*)(int))(uintptr_t)SIG_DFL;
	}

	return (savefn);
}

int
gsignal(int sig)
{
	int (*sigfn)(int);

	if (sig < MINSIG || sig > MAXSIGNUM ||
	    (sigfn = sigs[sig-MINSIG]) == (int(*)(int))(uintptr_t)SIG_DFL) {
		return (0);
	} else {
		if (sigfn == (int(*)(int))(uintptr_t)SIG_IGN) {
			return (1);
		} else {
			sigs[sig-MINSIG] = (int(*)(int))(uintptr_t)SIG_DFL;
			return ((*sigfn)(sig));
		}
	}
}
