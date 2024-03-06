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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <signal.h>
#include <unistd.h>
#include <errno.h>

#include <mdb/mdb_signal.h>
#include <mdb/mdb_debug.h>

static mdb_signal_f *sig_handlers[NSIG];
static void *sig_data[NSIG];

static void
sig_stub(int sig, siginfo_t *sip, void *ucp)
{
	sig_handlers[sig](sig, sip, (ucontext_t *)ucp, sig_data[sig]);
}

int
mdb_signal_sethandler(int sig, mdb_signal_f *handler, void *data)
{
	struct sigaction act;
	int status;

	ASSERT(sig > 0 && sig < NSIG && sig != SIGKILL && sig != SIGSTOP);

	sig_handlers[sig] = handler;
	sig_data[sig] = data;

	if (handler == MDB_SIG_DFL) {
		act.sa_handler = SIG_DFL;
		act.sa_flags = SA_RESTART;
	} else if (handler == MDB_SIG_IGN) {
		act.sa_handler = SIG_IGN;
		act.sa_flags = SA_RESTART;
	} else {
		act.sa_sigaction = sig_stub;
		act.sa_flags = SA_SIGINFO | SA_RESTART | SA_ONSTACK;
	}

	(void) sigemptyset(&act.sa_mask);

	if (sig == SIGWINCH || sig == SIGTSTP) {
		(void) sigaddset(&act.sa_mask, SIGWINCH);
		(void) sigaddset(&act.sa_mask, SIGTSTP);
		(void) sigaddset(&act.sa_mask, SIGHUP);
		(void) sigaddset(&act.sa_mask, SIGTERM);
	}

	if ((status = sigaction(sig, &act, NULL)) == 0)
		(void) mdb_signal_unblock(sig);

	return (status);
}

mdb_signal_f *
mdb_signal_gethandler(int sig, void **datap)
{
	if (datap != NULL)
		*datap = sig_data[sig];

	return (sig_handlers[sig]);
}

int
mdb_signal_raise(int sig)
{
	return (kill(getpid(), sig));
}

int
mdb_signal_pgrp(int sig)
{
	return (kill(0, sig));
}

int
mdb_signal_block(int sig)
{
	sigset_t set;

	(void) sigemptyset(&set);
	(void) sigaddset(&set, sig);

	return (sigprocmask(SIG_BLOCK, &set, NULL));
}

int
mdb_signal_unblock(int sig)
{
	sigset_t set;

	(void) sigemptyset(&set);
	(void) sigaddset(&set, sig);

	return (sigprocmask(SIG_UNBLOCK, &set, NULL));
}

int
mdb_signal_blockall(void)
{
	sigset_t set;

	(void) sigfillset(&set);
	return (sigprocmask(SIG_BLOCK, &set, NULL));
}

int
mdb_signal_unblockall(void)
{
	sigset_t set;

	(void) sigfillset(&set);
	return (sigprocmask(SIG_UNBLOCK, &set, NULL));
}
