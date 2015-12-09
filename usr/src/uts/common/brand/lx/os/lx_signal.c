/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/signal.h>
#include <sys/sunddi.h>
#include <lx_signum.h>

void
lx_ltos_sigset(lx_sigset_t *lsigp, k_sigset_t *ssigp)
{
	int lx_sig, sig;

	sigemptyset(ssigp);
	for (lx_sig = 1; lx_sig <= LX_NSIG; lx_sig++) {
		if (lx_sigismember(lsigp, lx_sig) &&
		    ((sig = ltos_signo[lx_sig]) > 0))
			sigaddset(ssigp, sig);
	}

	/* Emulate sigutok() restrictions */
	ssigp->__sigbits[0] &= (FILLSET0 & ~CANTMASK0);
	ssigp->__sigbits[1] &= (FILLSET1 & ~CANTMASK1);
	ssigp->__sigbits[2] &= (FILLSET2 & ~CANTMASK2);
}

void
lx_stol_sigset(k_sigset_t *ssigp, lx_sigset_t *lsigp)
{
	int sig, lx_sig;

	bzero(lsigp, sizeof (lx_sigset_t));
	for (sig = 1; sig < NSIG; sig++) {
		if (sigismember(ssigp, sig) &&
		    ((lx_sig = stol_signo[sig]) > 0))
			lx_sigaddset(lsigp, lx_sig);
	}
}
