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

#include "lint.h"
#include <mtlib.h>
#include <stdarg.h>
#include <values.h>
#include <errno.h>
#include <thread.h>
#include <synch.h>
#include <sys/types.h>
#include "print.h"
#include "libc.h"

/*VARARGS2*/
int
sprintf(char *string, const char *format, ...)
{
	ssize_t count;
	FILE siop;
	va_list ap;

	siop._cnt = MAXINT;
	siop._base = siop._ptr = (unsigned char *)string;
	siop._flag = _IOREAD; /* distinguish dummy file descriptor */
	va_start(ap, format);

	count = _ndoprnt(format, ap, &siop, 0);
	va_end(ap);
	*siop._ptr = '\0'; /* plant terminating null character */
	if (count == EOF) {
		return (EOF);
	}

	/* check for overflow */
	if ((size_t)count > MAXINT) {
		errno = EOVERFLOW;
		return (EOF);
	} else {
		return ((int)count);
	}
}

#ifndef _LP64

/*
 * 32-bit shadow function of sprintf().
 * When using the c89 compiler to build 32-bit applications, the size
 * of intmax_t is 32-bits, otherwise the size of intmax_t is 64-bits.
 * The shadow function uses 32-bit size of intmax_t for %j conversion.
 * The #pragma redefine_extname in <stdio.h> selects the proper routine
 * at compile time for the user application.
 * NOTE: this function is only available in the 32-bit library.
 */

int
_sprintf_c89(char *string, const char *format, ...)
{
	ssize_t count;
	va_list ap;

	va_start(ap, format);
	count = _vsprintf_c89(string, format, ap);
	va_end(ap);
	return ((int)count);
}

#endif	/* _LP64 */
