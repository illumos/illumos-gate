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
/*	  All Rights Reserved	*/

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/fault.h>
#include <sys/procset.h>
#include <sys/signal.h>
#include <sys/schedctl.h>
#include <sys/debug.h>


/*
 * ssig() is the old common entry for signal, sigset, sighold,
 * sigrelse, sigignore and sigpause.
 *
 * All of these interfaces have been reimplemented in libc using
 * calls to sigaction, sigsuspend and sigprocmask.
 *
 * This kernel interface is no longer called by any application
 * that is dynamically linked with libc.  It exists solely for
 * the benefit of really old statically-linked applications.
 * It should be removed from the system.
 */

int
ssig(int signo, void (*func)())
{
	int sig;
	struct proc *p;
	int flags;
	int retval = 0;
	int sigcld_look = 0;

	sig = signo & SIGNO_MASK;

	if (sig <= 0 || sig >= NSIG || sigismember(&cantmask, sig))
		return (set_errno(EINVAL));

	p = ttoproc(curthread);
	mutex_enter(&p->p_lock);
	schedctl_finish_sigblock(curthread);
	switch (signo & ~SIGNO_MASK) {

	case SIGHOLD:	/* sighold */
		sigaddset(&curthread->t_hold, sig);
		mutex_exit(&p->p_lock);
		return (0);

	case SIGRELSE:	/* sigrelse */
		sigdelset(&curthread->t_hold, sig);
		curthread->t_sig_check = 1;	/* so ISSIG will see release */
		mutex_exit(&p->p_lock);
		return (0);

	case SIGPAUSE:	/* sigpause */
		sigdelset(&curthread->t_hold, sig);
		curthread->t_sig_check = 1;	/* so ISSIG will see release */
		/* pause() */
		while (cv_wait_sig_swap(&curthread->t_delay_cv, &p->p_lock))
			;
		mutex_exit(&p->p_lock);
		return (set_errno(EINTR));

	case SIGIGNORE:	/* signore */
		sigdelset(&curthread->t_hold, sig);
		curthread->t_sig_check = 1;	/* so ISSIG will see release */
		func = SIG_IGN;
		flags = 0;
		break;

	case SIGDEFER:		/* sigset */
		if (sigismember(&curthread->t_hold, sig))
			retval = (int)SIG_HOLD;
		else
			retval = (int)(uintptr_t)PTOU(curproc)->u_signal[sig-1];
		if (func == SIG_HOLD) {
			sigaddset(&curthread->t_hold, sig);
			mutex_exit(&p->p_lock);
			return (retval);
		}

#if defined(__sparc)
		/*
		 * Check alignment of handler
		 */
		if (func != SIG_IGN && func != SIG_DFL &&
		    ((uintptr_t)func & 0x3) != 0) {
			mutex_exit(&p->p_lock);
			return (set_errno(EINVAL));
		}
#endif
		sigdelset(&curthread->t_hold, sig);
		curthread->t_sig_check = 1;	/* so post_syscall sees it */
		flags = 0;
		break;

	case 0:	/* signal */
#if defined(__sparc)
		/*
		 * Check alignment of handler
		 */
		if (func != SIG_IGN && func != SIG_DFL &&
		    ((uintptr_t)func & 0x3) != 0) {
			mutex_exit(&p->p_lock);
			return (set_errno(EINVAL));
		}
#endif
		retval = (int)(uintptr_t)PTOU(curproc)->u_signal[sig-1];
		flags = SA_RESETHAND|SA_NODEFER;
		break;

	default:		/* error */
		mutex_exit(&p->p_lock);
		return (set_errno(EINVAL));
	}

	if (sigismember(&stopdefault, sig))
		flags |= SA_RESTART;
	else if (sig == SIGCLD) {
		flags |= SA_NOCLDSTOP;
		if (func == SIG_IGN)
			flags |= SA_NOCLDWAIT;
		sigcld_look = 1;
	}

	setsigact(sig, func, nullsmask, flags);
	mutex_exit(&p->p_lock);

	if (sigcld_look)
		sigcld_repost();

	return (retval);
}
