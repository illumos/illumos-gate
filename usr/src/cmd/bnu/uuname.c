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

#include "uucp.h"

/*
 * returns a list of remote systems accessible to uucico
 * option:
 *	-l	-> returns only the local system name.
 *	-c	-> print remote systems accessible to cu
 */
int
main(argc,argv)
int argc;
char **argv;
{
	int c, lflg = 0, cflg = 0;
	char s[BUFSIZ], prev[BUFSIZ], name[BUFSIZ];
	extern void setservice();
	extern int sysaccess(), getsysline();

	/* Set locale environment variables local definitions */
	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it wasn't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ( (c = getopt(argc, argv, "lc")) != EOF )
		switch(c) {
		case 'c':
			cflg++;
			break;
		case 'l':
			lflg++;
			break;
		default:
			(void) fprintf(stderr, gettext("usage: uuname [-l|-c]\n"));
			exit(1);
		}

	if (lflg) {
		if ( cflg )
			(void) fprintf(stderr,
			gettext("uuname: -l overrides -c ... -c option ignored\n"));
		uucpname(name);

		puts(name);
		exit(0);
	}

	if ( cflg )
		setservice("cu");
	else
		setservice("uucico");

	if ( sysaccess(EACCESS_SYSTEMS) != 0 ) {
		(void)fprintf(stderr, gettext(
		    "%s: cannot access Systems files\n"), argv[0]);
		exit(1);
	}

	while ( getsysline(s, sizeof(s)) ) {
		if((s[0] == '#') || (s[0] == ' ') || (s[0] == '\t') ||
		    (s[0] == '\n'))
			continue;
		(void) sscanf(s, "%s", name);
		if (EQUALS(name, prev))
		    continue;
		puts(name);
		(void) strcpy(prev, name);
	}
	return (0);
}

/* small, private copies of assert(), logent(), */
/* cleanup() so we can use routines in sysfiles.c */

/*ARGSUSED*/
void
assert(s1, s2, i1, file, line)
char *s1, *s2, *file; int i1, line;
{
	(void)fprintf(stderr, "uuname: %s %s\n", s2, s1);
	return;
}

/*ARGSUSED*/
void logent(s1, s2)
char *s1, *s2;
{
}

void cleanup(int code)
{
	exit(code);
}
