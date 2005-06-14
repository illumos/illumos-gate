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
#pragma ident	"%Z%%M%	%I%	%E% SMI" 

/*
 * Copyright (c) 1987 Sun Microsystems, Inc. 
 */

#include <errno.h>
#include <sys/signal.h>

int
sighold(sig)
	int sig;
{

	if (sig == SIGKILL) {
		errno = EINVAL;
		return (-1);	/* sigblock quietly disallows SIGKILL */
	}
	(void) sigblock(sigmask(sig));
	return (0);		/* SVID specifies 0 return on success */
}

int
sigrelse(sig)
	int sig;
{

	if (sig == SIGKILL) {
		errno = EINVAL;
		return (-1);	/* sigsetmask quietly disallows SIGKILL */
	}
	(void) sigsetmask(sigblock(0) & ~sigmask(sig));
	return (0);		/* SVID specifies 0 return on success */
}

int
sigignore(sig)
	int sig;
{
	struct sigvec vec;

	if (sig == SIGKILL) {
		errno = EINVAL;
		return (-1);	/* sigsetmask quietly disallows SIGKILL */
	}
	if (sigvec(sig, (struct sigvec *)0, &vec) < 0)
		return (-1);
	vec.sv_handler = SIG_IGN;
	if (sigvec(sig, &vec, (struct sigvec *)0) < 0)
		return (-1);
	(void) sigsetmask(sigblock(0) & ~sigmask(sig));
	return (0);		/* SVID specifies 0 return on success */
}

void (*
sigset(sig, func))()
	int sig;
	void (*func)();
{
	struct sigvec newvec;
	int newmask;
	struct sigvec oldvec;
	int oldmask;

	if (sigvec(sig, (struct sigvec *)0, &oldvec) < 0)
		return (SIG_ERR);
	oldmask = sigblock(0);
	newvec = oldvec;
	newvec.sv_flags |= SV_INTERRUPT;
	newvec.sv_flags &= ~SV_RESETHAND;
	newvec.sv_mask = 0;
	newmask = oldmask;
	if (func == SIG_HOLD) {
		/*
		 * Signal will be held.  Set the bit for that
		 * signal in the signal mask.  Leave the action
		 * alone.
		 */
		newmask |= sigmask(sig);
	} else {
		/*
		 * Signal will not be held.  Clear the bit
		 * for it in the signal mask.  Set the action
		 * for it.
		 */
		newmask &= ~sigmask(sig);
		newvec.sv_handler = func;
	}
	if (sigvec(sig, &newvec, (struct sigvec *)0) < 0)
		return (SIG_ERR);
	if (sigsetmask(newmask) < 0)
		return (SIG_ERR);
	if (oldmask & sigmask(sig))
		return (SIG_HOLD);      /* signal was held */
	else
		return (oldvec.sv_handler);
}
