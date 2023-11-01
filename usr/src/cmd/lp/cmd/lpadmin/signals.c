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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#include "signal.h"

#include "lpadmin.h"

static int		trapping	= -1;	/* -1 means first time */

static
#ifdef	SIGPOLL
	void
#else
	int
#endif
			(*old_sighup)(),
			(*old_sigint)(),
			(*old_sigquit)(),
			(*old_sigterm)();

/**
 ** catch() - CLEAN UP AFTER SIGNAL
 **/

static void
catch (int sig __unused)
{
	(void)signal (SIGHUP, SIG_IGN);
	(void)signal (SIGINT, SIG_IGN);
	(void)signal (SIGQUIT, SIG_IGN);
	(void)signal (SIGTERM, SIG_IGN);
	done (1);
}

/**
 ** trap_signals() - SET SIGNALS TO BE CAUGHT FOR CLEAN EXIT
 **/

void			trap_signals ()
{
	switch (trapping) {

	case -1:	/* first time */

#define	SETSIG(SIG) \
		if (signal(SIG, SIG_IGN) != SIG_IGN) \
			signal (SIG, catch);

		SETSIG (SIGHUP);
		SETSIG (SIGINT);
		SETSIG (SIGQUIT);
		SETSIG (SIGTERM);
		break;

	case 0:		/* currently ignoring */
		signal (SIGHUP, old_sighup);
		signal (SIGINT, old_sigint);
		signal (SIGQUIT, old_sigquit);
		signal (SIGTERM, old_sigterm);
		trapping = 1;
		break;

	case 1:		/* already trapping */
		break;

	}
	return;
}

/**
 ** ignore_signals() - SET SIGNALS TO BE IGNORED FOR CRITICAL SECTIONS
 **/

void			ignore_signals ()
{
	switch (trapping) {

	case -1:	/* first time */
		trap_signals ();
		/*fall through*/

	case 1:		/* currently trapping */
		old_sighup = signal(SIGHUP, SIG_IGN);
		old_sigint = signal(SIGINT, SIG_IGN);
		old_sigquit = signal(SIGQUIT, SIG_IGN);
		old_sigterm = signal(SIGTERM, SIG_IGN);
		trapping = 0;
		break;

	case 0:		/* already ignoring */
		break;

	}
	return;
}
