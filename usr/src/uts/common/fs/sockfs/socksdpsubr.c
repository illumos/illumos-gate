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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/strsubr.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>

#include <sys/vfs.h>
#include <sys/vfs_opreg.h>

#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/strsun.h>
#include <sys/signal.h>

#include <inet/sdp_itf.h>
#include "socksdp.h"


/*
 * Wait until the socket is connected or there is an error.
 * fmode should contain any nonblocking flags.
 */
int
sosdp_waitconnected(struct sonode *so, int fmode)
{
	int error;

	ASSERT(MUTEX_HELD(&so->so_lock));
	ASSERT((so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING)) ||
	    so->so_error != 0);

	while ((so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING)) ==
	    SS_ISCONNECTING && so->so_error == 0) {

		dprint(3, ("waiting for SS_ISCONNECTED on %p\n", (void *)so));
		if (fmode & (FNDELAY|FNONBLOCK))
			return (EINPROGRESS);

		if (!cv_wait_sig_swap(&so->so_state_cv, &so->so_lock)) {
			/*
			 * Return EINTR and let the application use
			 * nonblocking techniques for detecting when
			 * the connection has been established.
			 */
			error = EINTR;
			break;
		}
		dprint(3, ("awoken on %p\n", (void *)so));
	}

	if (so->so_error != 0) {
		error = sogeterr(so);
		ASSERT(error != 0);
		dprint(3, ("sosdp_waitconnected: error %d\n", error));
	} else if (so->so_state & SS_ISCONNECTED) {
		error = 0;
	}
	return (error);
}


/*
 * Change the process/process group to which SIGIO is sent.
 */
int
sosdp_chgpgrp(struct sdp_sonode *ss, pid_t pid)
{
	int error;

	ASSERT(MUTEX_HELD(&ss->ss_so.so_lock));
	if (pid != 0) {
		/*
		 * Permissions check by sending signal 0.
		 * Note that when kill fails it does a
		 * set_errno causing the system call to fail.
		 */
		error = kill(pid, 0);
		if (error != 0) {
			return (error);
		}
	}
	ss->ss_so.so_pgrp = pid;
	return (0);
}


/*
 * Generate a SIGIO, for 'writable' events include siginfo structure,
 * for read events just send the signal.
 */
/*ARGSUSED*/
static void
sosdp_sigproc(proc_t *proc, int event)
{
	k_siginfo_t info;

	if (event & SDPSIG_WRITE) {
		info.si_signo = SIGPOLL;
		info.si_code = POLL_OUT;
		info.si_errno = 0;
		info.si_fd = 0;
		info.si_band = 0;
		sigaddq(proc, NULL, &info, KM_NOSLEEP);
	}
	if (event & SDPSIG_READ) {
		sigtoproc(proc, NULL, SIGPOLL);
	}
	if (event & SDPSIG_URG) {
		sigtoproc(proc, NULL, SIGURG);
	}
}

void
sosdp_sendsig(struct sdp_sonode *ss, int event)
{
	proc_t *proc;
	struct sonode *so = &ss->ss_so;

	ASSERT(MUTEX_HELD(&ss->ss_so.so_lock));

	if (so->so_pgrp == 0 || (!(so->so_state & SS_ASYNC) &&
	    event != SDPSIG_URG)) {
		return;
	}

	dprint(3, ("sending sig %d to %d\n", event, so->so_pgrp));

	if (so->so_pgrp > 0) {
		/*
		 * XXX This unfortunately still generates
		 * a signal when a fd is closed but
		 * the proc is active.
		 */
		mutex_enter(&pidlock);
		proc = prfind(so->so_pgrp);
		if (proc == NULL) {
			mutex_exit(&pidlock);
			return;
		}
		mutex_enter(&proc->p_lock);
		mutex_exit(&pidlock);
		sosdp_sigproc(proc, event);
		mutex_exit(&proc->p_lock);
	} else {
		/*
		 * Send to process group. Hold pidlock across
		 * calls to sosdp_sigproc().
		 */
		pid_t pgrp = -so->so_pgrp;

		mutex_enter(&pidlock);
		proc = pgfind(pgrp);
		while (proc != NULL) {
			mutex_enter(&proc->p_lock);
			sosdp_sigproc(proc, event);
			mutex_exit(&proc->p_lock);
			proc = proc->p_pglink;
		}
		mutex_exit(&pidlock);
	}
}


/*
 * Inherit socket properties
 */
void
sosdp_so_inherit(struct sdp_sonode *lss, struct sdp_sonode *nss)
{
	struct sonode *nso = &nss->ss_so;
	struct sonode *lso = &lss->ss_so;

	nso->so_options = lso->so_options & (SO_DEBUG|SO_REUSEADDR|
	    SO_KEEPALIVE|SO_DONTROUTE|SO_BROADCAST|SO_USELOOPBACK|
	    SO_OOBINLINE|SO_DGRAM_ERRIND|SO_LINGER);
	nso->so_sndbuf = lso->so_sndbuf;
	nso->so_rcvbuf = lso->so_rcvbuf;
	nso->so_pgrp = lso->so_pgrp;

	nso->so_rcvlowat = lso->so_rcvlowat;
	nso->so_sndlowat = lso->so_sndlowat;
}
