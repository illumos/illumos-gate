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
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "signalmap.h"
#include <sys/signal.h>
#include <sys/errno.h>

extern int errno;
void (*handlers[32])();		/* XXX - 32???  NSIG, maybe? */

void
maphandler(int sig, int code, struct sigcontext *scp, char *addr)
{
	switch (sig) {
		case SIGBUS:
		case SIGSEGV:
			switch (FC_CODE(code)) {
			case 3:		/* 5.x value for FC_OBJERR */
				code = FC_MAKE_ERR(FC_ERRNO(code));
				break;
			case 5:		/* 5.x value for FC_NOMAP */
				code = FC_NOMAP;
				break;
			}
			break;
	}
	__sendsig(maptooldsig(sig), code, scp, addr, handlers[sig]);
}
	
void (*
signal(int sig, void (*a)(int)))(int)
{
	int newsig;

	struct sigvec osv, sv;

	sv.sv_handler = a;
	sv.sv_mask = 0;
#ifdef S5EMUL
	sv.sv_flags = SV_INTERRUPT|SV_RESETHAND;
#else
	sv.sv_flags = 0;
#endif
	if (sigvec(sig, &sv, &osv) < 0)
		return (BADSIG);
	return (osv.sv_handler);
}


int
sigvec(int sig, struct sigvec *nvec, struct sigvec *ovec)
{
	int newsig;
	struct sigvec tvec, *tvecp;
	void (*oldhand)(int);

	if ((int)nvec == -1 || (int)ovec == -1) {
		errno = EFAULT;
		return (-1);
	}

	newsig = maptonewsig(sig);
	oldhand = handlers[newsig];

	if ((tvecp = nvec) != 0) {
		tvec = *nvec;
		tvecp = &tvec;
		/*
		 * To be compatible with the behavior of SunOS 4.x:
		 * If the new signal handler is SIG_IGN or SIG_DFL,
		 * do not change the signal's entry in the handler array.
		 * This allows a child of vfork(2) to set signal handlers
		 * to SIG_IGN or SIG_DFL without affecting the parent.
		 */
		if (tvecp->sv_handler != SIG_DFL &&
		    tvecp->sv_handler != SIG_IGN) {
			handlers[newsig] = tvecp->sv_handler;
			tvecp->sv_handler = maphandler;
		}
	}

	if (ucbsigvec(newsig, tvecp, ovec) == -1) {
		handlers[newsig] = oldhand;
		return (-1);
	}

	if (ovec && ovec->sv_handler != SIG_DFL && ovec->sv_handler != SIG_IGN)
		ovec->sv_handler = oldhand;

	return (0);
}

int
sigsetmask(int mask)
{
	int ret;
	ret = ucbsigsetmask(maptonewmask(mask));
	return (maptooldmask(ret));
}

int
sigblock(int mask)
{
	int ret;
	ret = ucbsigblock(maptonewmask(mask));
	return (maptooldmask(ret));
}


int
sigpause(int mask)
{
	int ret;
	return (ucbsigpause(maptonewmask(mask)));
}

int
siginterrupt(int sig, int flag)
{
	return (ucbsiginterrupt(maptonewsig(sig), flag));
}


int
maptonewsig(int sig)
{
	switch (sig) {
	case SIGURG:               /* urgent condition on IO channel */
		return (XSIGURG);
	case SIGSTOP:              /* sendable stop signal not from tty */
		return (XSIGSTOP);
	case SIGTSTP:            /* stop signal from tty */
		return (XSIGTSTP);
	case SIGCONT:            /* continue a stopped process */
		return (XSIGCONT);
	case SIGCLD:          /* System V name for SIGCHLD */
		return (XSIGCLD);
	case SIGTTIN:          /* to readers pgrp upon background tty read */
		return (XSIGTTIN);
	case SIGTTOU:         /* like TTIN for output */
		return (XSIGTTOU);
	case SIGIO:        /* input/output possible signal */
		return (XSIGIO);
	case SIGXCPU:       /* exceeded CPU time limit */
		return (XSIGXCPU);
	case SIGXFSZ:       /* exceeded file size limit */
		return (XSIGXFSZ);
	case SIGVTALRM:      /* virtual time alarm */
		return (XSIGVTALRM);
	case SIGPROF:        /* profiling time alarm */
		return (XSIGPROF);
	case SIGWINCH:       /* window changed */
		return (XSIGWINCH);
	case SIGLOST:	     /* resource lost, not supported */
		return (-1);
	case SIGUSR1:
		return (XSIGUSR1);
	case SIGUSR2:      /* user defined signal 2 */
		return (XSIGUSR2);
	default:
		return (sig);
	}
}

int
maptooldsig(int sig)
{
	switch (sig) {
	case XSIGURG:               /* urgent condition on IO channel */
		return (SIGURG);
	case XSIGSTOP:              /* sendable stop signal not from tty */
		return (SIGSTOP);
	case XSIGTSTP:            /* stop signal from tty */
		return (SIGTSTP);
	case XSIGCONT:            /* continue a stopped process */
		return (SIGCONT);
	case XSIGCLD:          /* System V name for SIGCHLD */
		return (SIGCLD);
	case XSIGTTIN:          /* to readers pgrp upon background tty read */
		return (SIGTTIN);
	case XSIGTTOU:         /* like TTIN for output */
		return (SIGTTOU);
	case XSIGIO:        /* input/output possible signal */
		return (SIGIO);
	case XSIGXCPU:       /* exceeded CPU time limit */
		return (SIGXCPU);
	case XSIGXFSZ:       /* exceeded file size limit */
		return (SIGXFSZ);
	case XSIGVTALRM:      /* virtual time alarm */
		return (SIGVTALRM);
	case XSIGPROF:        /* profiling time alarm */
		return (SIGPROF);
	case XSIGWINCH:       /* window changed */
		return (SIGWINCH);
	case XSIGUSR1:
		return (SIGUSR1);
	case XSIGUSR2:      /* user defined signal 2 */
		return (SIGUSR2);
	case XSIGPWR:      /* user defined signal 2 */
		return (-1);
	default:
		return (sig);
	}
}

int
maptooldmask(int mask)
{
	int omask;

	omask = mask & 0x7FFF;		/* these signo are same */

	if (mask & sigmask(XSIGURG))
		omask |= sigmask(SIGURG);
	if (mask & sigmask(XSIGSTOP))
		omask |= sigmask(SIGSTOP);
	if (mask & sigmask(XSIGTSTP))
		omask |= sigmask(SIGTSTP);
	if (mask & sigmask(XSIGCONT))
		omask |= sigmask(SIGCONT);
	if (mask & sigmask(XSIGCLD))
		omask |= sigmask(SIGCLD);
	if (mask & sigmask(XSIGTTIN))
		omask |= sigmask(SIGTTIN);
	if (mask & sigmask(XSIGTTOU))
		omask |= sigmask(SIGTTOU);
	if (mask & sigmask(XSIGIO))
		omask |= sigmask(SIGIO);
	if (mask & sigmask(XSIGXCPU))
		omask |= sigmask(SIGXCPU);
	if (mask & sigmask(XSIGXFSZ))
		omask |= sigmask(SIGXFSZ);
	if (mask & sigmask(XSIGVTALRM))
		omask |= sigmask(SIGVTALRM);
	if (mask & sigmask(XSIGPROF))
		omask |= sigmask(SIGPROF);
	if (mask & sigmask(XSIGWINCH))
		omask |= sigmask(SIGWINCH);
	if (mask & sigmask(XSIGUSR1))
		omask |= sigmask(SIGUSR1);
	if (mask & sigmask(XSIGUSR2))
		omask |= sigmask(SIGUSR2);
	return (omask);
}	


int
maptonewmask(int omask)
{
	int mask;

	if (omask == -1) {
		return (-1);
	}

	mask = omask & 0x7FFF;		/* these signo are the same */

	if (omask & sigmask(SIGURG))
		mask |= sigmask(XSIGURG);
	if (omask & sigmask(SIGSTOP))
		mask |= sigmask(XSIGSTOP);
	if (omask & sigmask(SIGTSTP))
		mask |= sigmask(XSIGTSTP);
	if (omask & sigmask(SIGCONT))
		mask |= sigmask(XSIGCONT);
	if (omask & sigmask(SIGCLD))
		mask |= sigmask(XSIGCLD);
	if (omask & sigmask(SIGTTIN))
		mask |= sigmask(XSIGTTIN);
	if (omask & sigmask(SIGTTOU))
		mask |= sigmask(XSIGTTOU);
	if (omask & sigmask(SIGIO))
		mask |= sigmask(XSIGIO);
	if (omask & sigmask(SIGXCPU))
		mask |= sigmask(XSIGXCPU);
	if (omask & sigmask(SIGXFSZ))
		mask |= sigmask(XSIGXFSZ);
	if (omask & sigmask(SIGVTALRM))
		mask |= sigmask(XSIGVTALRM);
	if (omask & sigmask(SIGPROF))
		mask |= sigmask(XSIGPROF);
	if (omask & sigmask(SIGWINCH))
		mask |= sigmask(XSIGWINCH);
	if (omask & sigmask(SIGUSR1))
		mask |= sigmask(XSIGUSR1);
	if (omask & sigmask(SIGUSR2))
		mask |= sigmask(XSIGUSR2);
	return (mask);
}	
