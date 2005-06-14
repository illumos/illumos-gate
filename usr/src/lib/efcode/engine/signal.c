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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/termio.h>

#include <fcode/private.h>
#include <fcode/log.h>

static fcode_env_t *saved_envp;
static struct termio saved_termio;

static void
process_signal(int sig, siginfo_t *sip, void *addr)
{
	/*
	 * Format appropriate error message, want fault addr if Bus Error
	 * or Segmentation Violation.
	 */
	switch (sig) {
	case SIGSEGV:
	case SIGBUS:
	case SIGILL:
	case SIGFPE:
		forth_abort(saved_envp, "%s: Fault Addr: 0x%08x",
		    strsignal(sig), sip->si_addr);

	case SIGQUIT:
		ioctl(fileno(stdin), TCSETA, &saved_termio);
		log_message(MSG_FATAL, "SIGQUIT\n");
		abort();

	case SIGINT:
		ioctl(fileno(stdin), TCSETA, &saved_termio);
		break;
	}
	forth_abort(saved_envp, strsignal(sig));
}

void
install_handlers(fcode_env_t *env)
{
	struct sigaction sa;

	saved_envp = env;

	ioctl(fileno(stdin), TCGETA, &saved_termio);

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO|SA_NODEFER;
	sa.sa_handler = 0;
	sa.sa_sigaction = process_signal;

	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGFPE, &sa, NULL);
}
