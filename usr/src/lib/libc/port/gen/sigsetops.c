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
 * POSIX signal manipulation functions.
 */
#pragma weak _sigfillset = sigfillset
#pragma weak _sigemptyset = sigemptyset
#pragma weak _sigaddset = sigaddset
#pragma weak _sigdelset = sigdelset
#pragma weak _sigismember = sigismember

#include "lint.h"
#include <sys/types.h>
#include <stdio.h>
#include <sys/param.h>
#include <sys/signal.h>
#include <errno.h>
#include "libc.h"

#define	SIGSETSIZE	4
#define	MAXBITNO (NBPW*8)

static sigset_t sigs;
static int sigsinit;

#define	sigword(n) ((n-1)/MAXBITNO)
#define	bitmask(n) (1L<<((n-1)%MAXBITNO))

static int
sigvalid(int sig)
{
	if (sig <= 0 || sig > (MAXBITNO * SIGSETSIZE))
		return (0);

	if (!sigsinit) {
		(void) __sigfillset(&sigs);
		sigsinit++;
	}

	return ((sigs.__sigbits[sigword(sig)] & bitmask(sig)) != 0);
}

int
sigfillset(sigset_t *set)
{
	if (!sigsinit) {
		(void) __sigfillset(&sigs);
		sigsinit++;
	}

	*set = sigs;
	return (0);
}

int
sigemptyset(sigset_t *set)
{
	set->__sigbits[0] = 0;
	set->__sigbits[1] = 0;
	set->__sigbits[2] = 0;
	set->__sigbits[3] = 0;
	return (0);
}

int
sigaddset(sigset_t *set, int sig)
{
	if (!sigvalid(sig)) {
		errno = EINVAL;
		return (-1);
	}
	set->__sigbits[sigword(sig)] |= bitmask(sig);
	return (0);
}

int
sigdelset(sigset_t *set, int sig)
{
	if (!sigvalid(sig)) {
		errno = EINVAL;
		return (-1);
	}
	set->__sigbits[sigword(sig)] &= ~bitmask(sig);
	return (0);
}

int
sigismember(const sigset_t *set, int sig)
{
	if (!sigvalid(sig)) {
		errno = EINVAL;
		return (-1);
	}
	return ((set->__sigbits[sigword(sig)] & bitmask(sig)) != 0);
}
