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
 * MKS library
 * Copyright 1985, 1992 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */
#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/gen/rcs/eprintf.c 1.17 1994/06/17 19:42:34 hilary Exp $";
#endif
#endif

#include <mks.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>

char *_cmdname;

/*f
 * print error message followed by errno value.
 * The value of errno is guaranteed to be restored on exit.
 */
/* VARARGS0 */
LDEFN int
eprintf VARARG1(const char *, fmt)
{
	va_list args;
	register int saveerrno = errno;
	register int nprf = 0;
	char *str;

	if (_cmdname != NULL)
		nprf += fprintf(stderr, "%s: ", _cmdname);
	va_start(args, fmt);
	nprf += vfprintf(stderr, fmt, args);
	va_end(args);
	str = strerror(saveerrno);
	if (*str == '\0')
		nprf += fprintf(stderr, ": error %d\n", saveerrno);
	else
		nprf += fprintf(stderr,": %s\n", str);
	errno = saveerrno;
	return (nprf);
}
