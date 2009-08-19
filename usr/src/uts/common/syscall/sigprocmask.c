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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/fault.h>
#include <sys/signal.h>
#include <sys/schedctl.h>
#include <sys/debug.h>

int64_t
lwp_sigmask(int how, uint_t bits0, uint_t bits1)
{
	kthread_t *t = curthread;
	proc_t *p = ttoproc(t);
	rval_t rv;

	/*
	 * We don't need to acquire p->p_lock here;
	 * we are manipulating thread-private data.
	 */

	schedctl_finish_sigblock(t);

	bits0 &= (FILLSET0 & ~CANTMASK0);
	bits1 &= (FILLSET1 & ~CANTMASK1);

	rv.r_val1 = t->t_hold.__sigbits[0];
	rv.r_val2 = t->t_hold.__sigbits[1];

	switch (how) {
	case SIG_BLOCK:
		t->t_hold.__sigbits[0] |= bits0;
		t->t_hold.__sigbits[1] |= bits1;
		break;
	case SIG_UNBLOCK:
		t->t_hold.__sigbits[0] &= ~bits0;
		t->t_hold.__sigbits[1] &= ~bits1;
		if (sigcheck(p, t))
			t->t_sig_check = 1;
		break;
	case SIG_SETMASK:
		t->t_hold.__sigbits[0] = bits0;
		t->t_hold.__sigbits[1] = bits1;
		if (sigcheck(p, t))
			t->t_sig_check = 1;
		break;
	}

	return (rv.r_vals);
}

/*
 * This system call is no longer called from libc.
 * It exists solely for the benefit of statically-linked
 * binaries from the past.  It should be eliminated.
 */
int
sigprocmask(int how, sigset_t *setp, sigset_t *osetp)
{
	sigset_t set;
	k_sigset_t kset;
	rval_t rv;

	/*
	 * User's oset and set might be the same address, so copyin first and
	 * save before copying out.
	 */
	if (setp) {
		switch (how) {
		case SIG_BLOCK:
		case SIG_UNBLOCK:
		case SIG_SETMASK:
			break;
		default:
			return (set_errno(EINVAL));
		}
		if (copyin((caddr_t)setp, (caddr_t)&set, sizeof (sigset_t)))
			return (set_errno(EFAULT));
		sigutok(&set, &kset);
	} else {
		/* none of SIG_BLOCK, SIG_UNBLOCK, SIG_SETMASK equals 0 */
		how = 0;
		sigemptyset(&kset);
	}

	rv.r_vals = lwp_sigmask(how, kset.__sigbits[0], kset.__sigbits[1]);

	if (osetp) {
		kset.__sigbits[0] = rv.r_val1;
		kset.__sigbits[1] = rv.r_val2;
		sigktou(&kset, &set);
		if (copyout((caddr_t)&set, (caddr_t)osetp, sizeof (sigset_t)))
			return (set_errno(EFAULT));
	}

	return (0);
}
