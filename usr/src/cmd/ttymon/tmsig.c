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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#include	<stdio.h>
#include	<signal.h>
#include	"tmextern.h"

/*
 * catch_signals:
 *	ttymon catch some signals and ignore the rest.
 *
 *	SIGTERM	- killed by somebody
 *	SIGPOLL - got message on pmpipe, probably from sac
 *			   or on PCpipe
 *	SIGCLD	- tmchild died
 */
void
catch_signals(void)
{
	sigset_t cset;
	struct sigaction sigact;

#ifdef	DEBUG
	debug("in catch_signals");
#endif

	cset = Origmask;
	(void) sigdelset(&cset, SIGTERM);
	(void) sigdelset(&cset, SIGCLD);
	(void) sigdelset(&cset, SIGPOLL);
#ifdef	DEBUG
	(void) sigdelset(&cset, SIGUSR1);
	(void) sigdelset(&cset, SIGUSR2);
#endif
	(void) sigprocmask(SIG_SETMASK, &cset, NULL);
	sigact.sa_flags = 0;
	sigact.sa_handler = sigterm;
	(void) sigemptyset(&sigact.sa_mask);
	(void) sigaddset(&sigact.sa_mask, SIGTERM);
	(void) sigaction(SIGTERM, &sigact, NULL);
	sigact.sa_flags = 0;
	sigact.sa_handler = sigchild;
	(void) sigemptyset(&sigact.sa_mask);
	(void) sigaction(SIGCLD, &sigact, NULL);
	sigact.sa_flags = 0;
	sigact.sa_handler = sigpoll_catch;
	(void) sigemptyset(&sigact.sa_mask);
	(void) sigaddset(&sigact.sa_mask, SIGPOLL);
	(void) sigaction(SIGPOLL, &sigact, NULL);
#ifdef	DEBUG
	sigact.sa_flags = 0;
	sigact.sa_handler = dump_pmtab;
	(void) sigemptyset(&sigact.sa_mask);
	(void) sigaddset(&sigact.sa_mask, SIGUSR1);
	(void) sigaction(SIGUSR1, &sigact, NULL);
	sigact.sa_flags = 0;
	sigact.sa_handler = dump_ttydefs;
	(void) sigemptyset(&sigact.sa_mask);
	(void) sigaddset(&sigact.sa_mask, SIGUSR2);
	(void) sigaction(SIGUSR2, &sigact, NULL);
#endif
}

/*
 * child_sigcatch() - tmchild inherits some signal_catch from parent
 *		      and need to reset them
 */
void
child_sigcatch(void)
{
	struct	sigaction	sigact;
	sigset_t cset;

	cset = Origmask;
	(void) sigdelset(&cset, SIGINT);
	(void) sigdelset(&cset, SIGPOLL);
	(void) sigprocmask(SIG_SETMASK, &cset, NULL);
	sigact.sa_flags = 0;
	sigact.sa_handler = sigpoll;
	(void) sigemptyset(&sigact.sa_mask);
	(void) sigaddset(&sigact.sa_mask, SIGPOLL);
	(void) sigaction(SIGPOLL, &sigact, NULL);
	sigact.sa_flags = 0;
	sigact.sa_handler = sigint;
	(void) sigemptyset(&sigact.sa_mask);
	(void) sigaddset(&sigact.sa_mask, SIGINT);
	(void) sigaction(SIGINT, &sigact, NULL);
}
