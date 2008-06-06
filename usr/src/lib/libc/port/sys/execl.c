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
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	execl(name, arg0, arg1, ..., argn, 0)
 *	environment automatically passed.
 */

#pragma weak _execl = execl

#include "lint.h"
#include <alloca.h>
#include <malloc.h>
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>

/*VARARGS1*/
int
execl(const char *name, const char *arg0, ...)
{
	char **argp;
	va_list args;
	char **argvec;
	extern char **environ;
	int err;
	int nargs = 0;
	char *nextarg;

	/*
	 * count the number of arguments in the variable argument list
	 * and allocate an argument vector for them on the stack,
	 * adding an extra element for a terminating null pointer
	 */

	va_start(args, arg0);
	while (va_arg(args, char *) != (char *)0) {
		nargs++;
	}
	va_end(args);

	/*
	 * load the arguments in the variable argument list
	 * into the argument vector and add the terminating null pointer
	 */

	va_start(args, arg0);

	/* workaround for bugid 1242839 */
	argvec = (char **)alloca((size_t)((nargs + 2) * sizeof (char *)));
	argp = argvec;
	*argp++ = (char *)arg0;
	while ((nextarg = va_arg(args, char *)) != (char *)0) {
		*argp++ = nextarg;
	}
	va_end(args);
	*argp = (char *)0;

	/*
	 * call execve()
	 */

	err = execve(name, argvec, environ);
	return (err);
}
