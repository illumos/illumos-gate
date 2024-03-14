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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <signal.h>
#include <thread.h>
#include <unistd.h>
#include <errno.h>

#include "sysevent_signal.h"

static se_signal_f *sig_handlers[NSIG];
static void *sig_data[NSIG];

static void
sig_stub(int sig, siginfo_t *sip, void *ucp)
{
	sig_handlers[sig](sig, sip, (ucontext_t *)ucp, sig_data[sig]);
}

int
se_signal_sethandler(int sig, se_signal_f *handler, void *data)
{
	struct sigaction act;
	int status;

	sig_handlers[sig] = handler;
	sig_data[sig] = data;

	if (handler == SE_SIG_DFL) {
		act.sa_handler = SIG_DFL;
		act.sa_flags = SA_RESTART;
	} else if (handler == SE_SIG_IGN) {
		act.sa_handler = SIG_IGN;
		act.sa_flags = SA_RESTART;
	} else {
		act.sa_sigaction = sig_stub;
		act.sa_flags = SA_SIGINFO | SA_RESTART;
	}

	(void) sigfillset(&act.sa_mask);

	if ((status = sigaction(sig, &act, NULL)) == 0)
		(void) se_signal_unblock(sig);

	return (status);
}

int
se_signal_unblock(int sig)
{
	sigset_t set;

	(void) sigemptyset(&set);
	(void) sigaddset(&set, sig);

	return (thr_sigsetmask(SIG_UNBLOCK, &set, NULL));
}

int
se_signal_blockall(void)
{
	sigset_t set;

	(void) sigfillset(&set);
	return (thr_sigsetmask(SIG_BLOCK, &set, NULL));
}

int
se_signal_unblockall(void)
{
	sigset_t set;

	(void) sigfillset(&set);
	return (thr_sigsetmask(SIG_UNBLOCK, &set, NULL));
}
