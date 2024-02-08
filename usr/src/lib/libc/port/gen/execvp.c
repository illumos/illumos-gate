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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2024 Oxide Computer Company
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 *	execlp(name, arg,...,0)	(like execl, but does path search)
 *	execvp(name, argv)	(like execv, but does path search)
 *	execvpe(name, argv, envp) (like execve, but does path search)
 */

#pragma weak _execlp = execlp
#pragma weak _execvp = execvp

#include "lint.h"
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <alloca.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <paths.h>

static const char *execat(const char *, const char *, char *);

extern  int __xpg4;	/* defined in xpg4.c; 0 if not xpg4-compiled program */

/*VARARGS1*/
int
execlp(const char *name, const char *arg0, ...)
{
	char **argp;
	va_list args;
	char **argvec;
	int err;
	int nargs = 0;
	char *nextarg;

	/*
	 * count the number of arguments in the variable argument list
	 * and allocate an argument vector for them on the stack,
	 * adding space for a terminating null pointer at the end
	 * and one additional space for argv[0] which is no longer
	 * counted by the varargs loop.
	 */

	va_start(args, arg0);

	while (va_arg(args, char *) != (char *)0)
		nargs++;

	va_end(args);

	/*
	 * load the arguments in the variable argument list
	 * into the argument vector and add the terminating null pointer
	 */

	va_start(args, arg0);
	/* workaround for bugid 1242839 */
	argvec = alloca((size_t)((nargs + 2) * sizeof (char *)));
	nextarg = va_arg(args, char *);
	argp = argvec;
	*argp++ = (char *)arg0;
	while (nargs-- && nextarg != (char *)0) {
		*argp = nextarg;
		argp++;
		nextarg = va_arg(args, char *);
	}
	va_end(args);
	*argp = (char *)0;

	/*
	 * call execvp()
	 */

	err = execvp(name, argvec);
	return (err);
}

static int
execvpe_int(const char *name, char *const *argv, char *const *envp,
    boolean_t use_env)
{
	const char	*pathstr;
	char	fname[PATH_MAX+2];
	char	*newargs[256];
	int	i;
	const char *cp;
	unsigned etxtbsy = 1;
	int eacces = 0;

	if (*name == '\0') {
		errno = ENOENT;
		return (-1);
	}
	if ((pathstr = getenv("PATH")) == NULL) {
		/*
		 * XPG4:  pathstr is equivalent to CSPATH, except that
		 * :/usr/sbin is appended when root, and pathstr must end
		 * with a colon when not root.  Keep these paths in sync
		 * with CSPATH in confstr.c.  Note that pathstr must end
		 * with a colon when not root so that when name doesn't
		 * contain '/', the last call to execat() will result in an
		 * attempt to execv name from the current directory.
		 */
		if (geteuid() == 0 || getuid() == 0) {
			if (__xpg4 == 0) {	/* not XPG4 */
				pathstr = "/usr/sbin:/usr/ccs/bin:/usr/bin";
			} else {		/* XPG4 (CSPATH + /usr/sbin) */
				pathstr = "/usr/xpg4/bin:/usr/ccs/bin:/usr/bin:"
				    "/opt/SUNWspro/bin:/usr/sbin";
			}
		} else {
			if (__xpg4 == 0) {	/* not XPG4 */
				pathstr = "/usr/ccs/bin:/usr/bin:";
			} else {		/* XPG4 (CSPATH) */
				pathstr = "/usr/xpg4/bin:/usr/ccs/bin:"
				    "/usr/bin:/opt/SUNWspro/bin:";
			}
		}
	}
	cp = strchr(name, '/')? (const char *)"": pathstr;

	do {
		cp = execat(cp, name, fname);
	retry:
		/*
		 * 4025035 and 4038378
		 * if a filename begins with a "-" prepend "./" so that
		 * the shell can't interpret it as an option
		 */
		if (*fname == '-') {
			size_t size = strlen(fname) + 1;
			if ((size + 2) > sizeof (fname)) {
				errno = E2BIG;
				return (-1);
			}
			(void) memmove(fname + 2, fname, size);
			fname[0] = '.';
			fname[1] = '/';
		}
		if (use_env) {
			(void) execve(fname, argv, envp);
		} else {
			(void) execv(fname, argv);
		}
		switch (errno) {
		case ENOEXEC:
			newargs[0] = "sh";
			newargs[1] = fname;
			for (i = 1; (newargs[i + 1] = argv[i]) != NULL; ++i) {
				if (i >= 254) {
					errno = E2BIG;
					return (-1);
				}
			}
			if (use_env) {
				(void) execve(_PATH_BSHELL, newargs, envp);
			} else {
				(void) execv(_PATH_BSHELL, newargs);
			}
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

int
execvp(const char *file, char *const *argv)
{
	return (execvpe_int(file, argv, NULL, B_FALSE));
}

int
execvpe(const char *file, char *const *argv, char *const *envp)
{
	return (execvpe_int(file, argv, envp, B_TRUE));
}

static const char *
execat(const char *s1, const char *s2, char *si)
{
	char	*s;
	int cnt = PATH_MAX + 1; /* number of characters in s2 */

	s = si;
	while (*s1 && *s1 != ':') {
		if (cnt > 0) {
			*s++ = *s1++;
			cnt--;
		} else
			s1++;
	}
	if (si != s && cnt > 0) {
		*s++ = '/';
		cnt--;
	}
	while (*s2 && cnt > 0) {
		*s++ = *s2++;
		cnt--;
	}
	*s = '\0';
	return (*s1 ? ++s1: 0);
}
