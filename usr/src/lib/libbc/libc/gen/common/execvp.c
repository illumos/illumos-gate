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

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/
/*
 *	execlp(name, arg,...,0)	(like execl, but does path search)
 *	execvp(name, argv)	(like execv, but does path search)
 */
#include <errno.h>
#include <sys/param.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static char *execat(char *, char *, char *);
static char *shell = "/bin/sh";

int
execlp(char *name, ...)
{
	va_list	args;
	int	r;

	va_start(args, name);
	r = execvp(name, (char **)args);
	va_end(args);

	return (r);
}

int
execvp(char *name, char **argv)
{
	char	*pathstr;
	char	fname[MAXPATHLEN];
	char	*newargs[256];
	int	i;
	char	*cp;
	unsigned etxtbsy = 1;
	int	eacces = 0;

	if ((pathstr = getenv("PATH")) == NULL)
		pathstr = ":/usr/ucb:/bin:/usr/bin";
	cp = strchr(name, '/') ? "": pathstr;

	do {
		cp = execat(cp, name, fname);
	retry:
		(void) execv(fname, argv);
		switch (errno) {
		case ENOEXEC:
			newargs[0] = "sh";
			newargs[1] = fname;
			for (i = 1; (newargs[i+1] = argv[i]) != NULL; ++i) {
				if (i >= 254) {
					errno = E2BIG;
					return(-1);
				}
			}
			(void) execv(shell, newargs);
			return (-1);
		case ETXTBSY:
			if (++etxtbsy > 5)
				return (-1);
			(void) sleep(etxtbsy);
			goto retry;
		case EACCES:
			++eacces;
			break;
		case ENOMEM:
		case E2BIG:
		case EFAULT:
			return (-1);
		}
	} while (cp);
	if (eacces)
		errno = EACCES;
	return (-1);
}

static char *
execat(char *s1, char *s2, char *si)
{
	char	*s;
	char	*end;

	s = si;
	end = s + MAXPATHLEN;
	while (*s1 && *s1 != ':' && s < end)
		*s++ = *s1++;
	if (si != s && s < end)
		*s++ = '/';
	while (*s2 && s < end)
		*s++ = *s2++;
	*s = '\0';
	return (*s1 ? ++s1: 0);
}
