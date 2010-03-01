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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * ldom_utils.c
 *
 * Common functions within the library
 *
 */

#include <stdio.h>
#include <signal.h>
#include <pthread.h>

/*
 * ldom_find_thr_sig()
 * Description:
 *     Find an unmasked signal which is used for terminating the thread
 *
 *     If the libldom.so thread is started before all fmd modules are loaded,
 *     all signals are unmasked. Either SIGTERM or SIGUSR1 can be used to
 *     stop the thread.
 *     If the thread is started by a fmd module, fmd has masked all signals
 *     except the client.thrsig and a list of reserver/non-catchable signals.
 *     The fmd client.thrsig signal must be used to stop the thread. The default
 *     value of the client.thrsig is SIGUSR1.
 *
 *     This fucntion first tries to check if the SIGTERM, SIGUSR1 or SIGUSR2
 *     signal is umasked. If so, select this signal.
 *     Otherwise, go through all the signals and find an umasked one.
 */
int
ldom_find_thr_sig(void)
{
	int i;
	sigset_t oset, rset;
	int sig[] = {SIGTERM, SIGUSR1, SIGUSR2};
	int sig_sz = sizeof (sig) / sizeof (int);
	int rc = SIGTERM;

	/* prefered set of signals that are likely used to terminate threads */
	(void) sigemptyset(&oset);
	(void) pthread_sigmask(SIG_SETMASK, NULL, &oset);
	for (i = 0; i < sig_sz; i++) {
		if (sigismember(&oset, sig[i]) == 0) {
			return (sig[i]);
		}
	}

	/* reserved set of signals that are not allowed to terminate thread */
	(void) sigemptyset(&rset);
	(void) sigaddset(&rset, SIGABRT);
	(void) sigaddset(&rset, SIGKILL);
	(void) sigaddset(&rset, SIGSTOP);
	(void) sigaddset(&rset, SIGCANCEL);

	/* Find signal that is not masked and not in the reserved list. */
	for (i = 1; i < MAXSIG; i++) {
		if (sigismember(&rset, i) == 1) {
			continue;
		}
		if (sigismember(&oset, i) == 0) {
			return (i);
		}
	}

	return (rc);
}
