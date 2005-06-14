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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 1989-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>

#define	NO_PERROR	0
#define	PERROR		1

char *progname;

void
setprogname(char *name)
{
	register char *p = name, c;

	if (p)
		while (c = *p++)
			if (c == '/')
				name = p;

	progname = name;
}

/* _error([no_perror, ] fmt [, arg ...]) */
/*VARARGS*/
int
_error(int do_perror, char *fmt, ...)
{
	int saved_errno;
	va_list ap;

	saved_errno = errno;

	/*
	 * flush all buffers
	 */
	(void) fflush(NULL);
	if (progname)
		(void) fprintf(stderr, "%s: ", progname);

	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);

	if (do_perror == NO_PERROR)
		(void) fprintf(stderr, "\n");
	else {
		(void) fprintf(stderr, ": ");
		errno = saved_errno;
		perror("");
	}

	return (1);
}
