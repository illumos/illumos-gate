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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "stdio.h"
#include "errno.h"
#include "sys/types.h"
#include "signal.h"
#include "stdlib.h"

#include "lp.h"
#include "msgs.h"
#include "printers.h"

#define	WHO_AM_I	I_AM_LPSTAT
#include "oam.h"

#include "lpstat.h"
#include <locale.h>


#ifdef SIGPOLL
static void
#else
static int
#endif
#if	defined(__STDC__)
			catch ( int );
#else
			catch();
#endif

#if	defined(__STDC__)
static void		mallocfail ( void );
#else
static void		mallocfail ();
#endif

int			exit_rc			= 0,
			inquire_type		= INQ_UNKNOWN,
			scheduler_active	= 0,
			r;		/* Says -r was specified */

char			*alllist[]	= {
	NAME_ALL,
	0
};

/**
 ** main()
 **/

int
#if	defined(__STDC__)
main (
	int			argc,
	char *			argv[]
)
#else
main (argc, argv)
	int			argc;
	char			*argv[];
#endif
{
	(void) setlocale (LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	lp_alloc_fail_handler = mallocfail;
	parse (argc, argv);
	done (0);
	/*NOTREACHED*/
	return (0);
}

/**
 ** def()
 **/

void
#if	defined(__STDC__)
def (
	void
)
#else
def ()
#endif
{
	char			*name;

	if ((name = getdefault()))
		(void) printf(gettext("system default destination: %s\n"), name);
	else
		(void) printf(gettext("no system default destination\n"));

	return;
}

/**
 ** running()
 **/

void
#if	defined(__STDC__)
running (
	void
)
#else
running ()
#endif
{
	(void) printf((scheduler_active ? gettext("scheduler is running\n") :
		gettext("scheduler is not running\n")));
	return;
}

/**
 ** printer_configured()
 **/
int
printer_configured(void)
{
	long	lastdir = -1;
	char	*name;
	int	nameisprinter;

	while ((name = next_dir(Lp_A_Printers, &lastdir)) != NULL) {
		nameisprinter = isprinter(name);
		Free(name);
		if (nameisprinter)
			return (1);
	}
	return (0);
}

/**
 ** startup()
 **/

void
#if	defined(__STDC__)
startup (
	void
)
#else
startup ()
#endif
{
	int			try;


	if (signal(SIGHUP, SIG_IGN) != SIG_IGN)
		(void)signal (SIGHUP, catch);

	if (signal(SIGINT, SIG_IGN) != SIG_IGN)
		(void)signal (SIGINT, catch);

	if (signal(SIGQUIT, SIG_IGN) != SIG_IGN)
		(void)signal (SIGQUIT, catch);

	if (signal(SIGTERM, SIG_IGN) != SIG_IGN)
		(void)signal (SIGTERM, catch);

	for (try = 1; try <= 5; try++) {
		scheduler_active = (mopen() == 0);
		if (scheduler_active || errno != ENOSPC)
			break;
		sleep (3);
	}

	return;
}

/**
 ** catch()
 **/

#ifdef SIGPOLL
static void
#else
static int
#endif
#if	defined(__STDC__)
catch (
	int			ignore
)
#else
catch (ignore)
	int			ignore;
#endif
{
	(void)signal (SIGHUP, SIG_IGN);
	(void)signal (SIGINT, SIG_IGN);
	(void)signal (SIGQUIT, SIG_IGN);
	(void)signal (SIGTERM, SIG_IGN);
	done (2);
}

/**
 ** mallocfail()
 **/

static void
#if	defined(__STDC__)
mallocfail (
	void
)
#else
mallocfail ()
#endif
{
	LP_ERRMSG (ERROR, E_LP_MALLOC);
	done (1);
}
