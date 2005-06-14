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
 * Copyright 1992 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"  /* from S5R2 1.2 */

/*LINTLIBRARY*/
/*
 *	execlp(name, arg,...,0)	(like execl, but does path search)
 *	execvp(name, argv)	(like execv, but does path search)
 */
#include <sys/errno.h>
#include <sys/param.h>
#include <varargs.h>
#define	NULL	0

static char *execat();
static char *shell = "/bin/sh";
extern char *getenv(), *strchr();
extern unsigned sleep();
extern int errno, execv();

/*VARARGS1*/
int
execlp(name, va_alist)
	char	*name;
	va_dcl
{
	va_list args;

	va_start(args);
	return(execvp(name, (char **)args));
}

int
execvp(name, argv)
char	*name, **argv;
{
	char	*pathstr;
	char	fname[MAXPATHLEN];
	char	*newargs[256];
	int	i;
	register char	*cp;
	register unsigned etxtbsy=1;
	register int eacces=0;

	if((pathstr = getenv("PATH")) == NULL)
		pathstr = ":/usr/ucb:/bin:/usr/bin";
	cp = strchr(name, '/')? "": pathstr;

	do {
		cp = execat(cp, name, fname);
	retry:
		(void) execv(fname, argv);
		switch(errno) {
		case ENOEXEC:
			newargs[0] = "sh";
			newargs[1] = fname;
			for(i=1; newargs[i+1]=argv[i]; ++i) {
				if(i >= 254) {
					errno = E2BIG;
					return(-1);
				}
			}
			(void) execv(shell, newargs);
			return(-1);
		case ETXTBSY:
			if(++etxtbsy > 5)
				return(-1);
			(void) sleep(etxtbsy);
			goto retry;
		case EACCES:
			++eacces;
			break;
		case ENOMEM:
		case E2BIG:
		case EFAULT:
			return(-1);
		}
	} while(cp);
	if(eacces)
		errno = EACCES;
	return(-1);
}

static char *
execat(s1, s2, si)
register char *s1, *s2;
char	*si;
{
	register char	*s;
	char	*end;

	s = si;
	end = s + MAXPATHLEN;
	while(*s1 && *s1 != ':' && s < end)
		*s++ = *s1++;
	if(si != s && s < end)
		*s++ = '/';
	while(*s2 && s < end)
		*s++ = *s2++;
	*s = '\0';
	return(*s1? ++s1: 0);
}
