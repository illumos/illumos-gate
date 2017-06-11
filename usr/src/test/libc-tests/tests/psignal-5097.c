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
 * Copyright 2016 Joyent, Inc.
 */

/*
 * psignal and psiginfo test cases.
 */

#include <signal.h>
#include <strings.h>
#include <siginfo.h>

int
main(void)
{
	struct siginfo sinfo;

	psignal(SIGSEGV, "hello world");
	psignal(SIGINFO, NULL);

	bzero(&sinfo, sizeof (struct siginfo));
	sinfo.si_signo = SIGSEGV;
	psiginfo(&sinfo, "hello world");
	sinfo.si_signo = SIGINFO;
	psiginfo(&sinfo, NULL);
	return (0);
}
