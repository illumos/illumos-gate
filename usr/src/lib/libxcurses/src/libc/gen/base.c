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
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * MKS Library -- basename -- produce base name of a file name
 * NOTE: not standard SVID routine.
 *
 * Copyright 1985, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 * james Partanen, June '95
 *
 */
#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/gen/rcs/base.c 1.26 1995/08/02 17:32:36 rodney Exp $";
#endif
#endif

#include <string.h>

#define DIRNAME		0
#define BASENAME	1

#define M_FSDELIM(c)	((c)=='/')
#define M_DRDELIM(c)	(0)

static char curdir[] = ".";

/*f
 * Since the goal is essentially common: find the last occurring
 * M_FSDELIM, and since most of the degenerate cases end up with the
 * same result, let's do most of the work in one function.
 *	- check degenerate arg forms
 *	- deal with a possible drive specifier
 *	- deal with degenerate paths
 *	- find last non-trailing M_FSDELIM
 *	- deal with degenerate dirname
 *	- deal with general case, returning prefix or suffix based on type
 */
static char *
basedir(char *arg, int type)
{
	register char *cp, *path;

	if (arg==(char *)0 || *arg=='\0' ||
		(*arg=='.' && (arg[1]=='\0' ||
		(type==DIRNAME && arg[1]=='.' && arg[2]=='\0'))))

		return curdir;	/* arg NULL, empty, ".", or ".." in DIRNAME */

	if (M_DRDELIM(arg[1]))	/* drive-specified pathnames */
		path = arg+2;
	else
		path = arg;

	if (path[1]=='\0'&&M_FSDELIM(*path))	/* "/", or drive analog */
		return arg;

	cp = strchr(path, '\0');
	cp--;

	while (cp != path && M_FSDELIM(*cp))
		*(cp--) = '\0';

	for (;cp>path && !M_FSDELIM(*cp); cp--)
		;

	if (!M_FSDELIM(*cp))
		if (type==DIRNAME && path!=arg) {
			*path = '\0';
			return arg;	/* curdir on the specified drive */
		} else
			return (type==DIRNAME)?curdir:path;
	else if (cp == path && type == DIRNAME) {
		cp[1] = '\0';
		return arg;		/* root directory involved */
	} else if (cp == path && cp[1] == '\0')
		return(arg);
	else if (type == BASENAME)
		return ++cp;
	*cp = '\0';
	return arg;
}

/*f
 * Finds the dirname of the given file.  Spec1170 conformant.
 */
char *
dirname(char *arg)
{
	return(basedir(arg, DIRNAME));
}

/*f
 * Finds the basename of the given file.  Spec1170 conformant.
 */
char *
basename(char *arg)
{
	return(basedir(arg, BASENAME));
}

#ifdef TEST_MAIN_BASE_C
#include <stdio.h>

int main(int argc, char **argv)
{
	int cnt;
	char arg[128];
	char *tmp;

	if (argc>1) {
		for (cnt=argc--;argc;argc--) {
			tmp = strdup(argv[cnt-argc]);
			printf("%s\t%s\n",
				dirname(argv[cnt-argc]),
				basename(tmp));
			free(tmp);
		}
		return 0;
	}

	printf("enter pathnames less than 128 chars.  enter 'q' to quit.\n");

	while(gets(arg))
		if (!strcmp(arg, "q"))
			break;
		else {
			tmp = strdup(arg);
			printf("%s\t%s\n", dirname(arg), basename(tmp));
			free(tmp);
		}

	return 0;
}
#endif /* TEST_MAIN_BASE_C */
