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
 * Copyright 1994 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * posix signal package
 */
#include <stdio.h>
#include <signal.h>
#include <errno.h>

#define cantmask        (sigmask(SIGKILL)|sigmask(SIGSTOP))


/*
 * sigemptyset - all known signals
 */
int
sigemptyset(sigset_t *sigp)
{
	if (!sigp) {
		errno = EINVAL;
		return (-1);
	}
	*sigp = 0;
	return (0);
}
    
/*
 * sigfillset - all known signals
 */
int
sigfillset(sigset_t *sigp)
{
	if (!sigp) {
		errno = EINVAL;
		return (-1);
	}
	*sigp = sigmask(NSIG - 1) | (sigmask(NSIG - 1) - 1);
	return (0);
}

/*
 * add the signal to the set
 */
int
sigaddset(sigset_t *sigp, int signo)	
{
	if (!sigp  ||  signo <= 0  ||  signo >= NSIG) {
		errno = EINVAL;
		return (-1);
	}
	*sigp |= sigmask(signo);
	return (0);
}

/*
 * remove the signal from the set
 */
int
sigdelset(sigset_t *sigp, int signo)
{
	if (!sigp  ||  signo <= 0  ||  signo >= NSIG) {
		errno = EINVAL;
		return (-1);
	}
	*sigp &= ~sigmask(signo);
	return (0);
}

/*
 * return true if the signal is in the set (return is 0 or 1)
 */
int
sigismember(sigset_t *sigp, int signo)
{
	if (!sigp  ||  signo <= 0  ||  signo >= NSIG) {
		errno = EINVAL;
		return (-1);
	}
	return ((*sigp & sigmask(signo)) != 0);
}
