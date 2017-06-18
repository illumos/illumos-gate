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
 * Copyright (c) 2017 Peter Tribble.
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */

/*
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 */

#include <locale.h>
#include <libintl.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pkgtrans.h>
#include <pkglib.h>
#include <pkglocs.h>
#include <libadm.h>
#include <libinst.h>
#include <messages.h>

static int	options;

static void	usage(void);
static void	trap(int signo);

int
main(int argc, char *argv[])
{
	int	c;
	void	(*func)();
	extern int	optind;
	int		ret;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	(void) set_prog_name(argv[0]);

	while ((c = getopt(argc, argv, "snio?")) != EOF) {
		switch (c) {
		case 'n':
			options |= PT_RENAME;
			break;

		case 'i':
			options |= PT_INFO_ONLY;
			break;

		case 'o':
			options |= PT_OVERWRITE;
			break;

		case 's':
			options |= PT_ODTSTREAM;
			break;

		default:
			usage();
			return (1);
		}
	}
	func = signal(SIGINT, trap);
	if (func != SIG_DFL)
		(void) signal(SIGINT, func);
	(void) signal(SIGHUP, trap);
	(void) signal(SIGQUIT, trap);
	(void) signal(SIGTERM, trap);
	(void) signal(SIGPIPE, trap);
	(void) signal(SIGPWR, trap);

	if ((argc-optind) < 2) {
		usage();
		return (1);
	}

	ret = pkgtrans(flex_device(argv[optind], 1),
	    flex_device(argv[optind+1], 1), &argv[optind+2], options);

	quit(ret);
	/*NOTREACHED*/
}

void
quit(int retcode)
{
	(void) signal(SIGINT, SIG_IGN);
	(void) signal(SIGHUP, SIG_IGN);
	(void) ds_close(1);
	(void) pkghead(NULL);
	exit(retcode);
}

static void
trap(int signo)
{
	(void) signal(SIGINT, SIG_IGN);
	(void) signal(SIGHUP, SIG_IGN);

	if (signo == SIGINT) {
		progerr(gettext("aborted at user request.\n"));
		quit(3);
	}
	progerr(gettext("aborted by signal %d\n"), signo);
	quit(1);
}

static void
usage(void)
{
	(void) fprintf(stderr,
	    gettext("usage: %s [-ions] srcdev dstdev [pkg [pkg...]]\n"),
	    get_prog_name());
}
