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
 * Copyright 2025 Hans Rosenfeld
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

#include "lint.h"
#include <mtlib.h>
#include <stdarg.h>
#include <values.h>
#include <errno.h>
#include <synch.h>
#include <thread.h>
#include <sys/types.h>
#include "print.h"
#include "libc.h"
#include <stdio_ext.h>
#include <upanic.h>

#ifdef _C89_INTMAX32
/*
 * 32-bit shadow function of vsprintf() and sprintf() are built here.
 * When using the c89 compiler to build 32-bit applications, the size
 * of intmax_t is 32-bits, otherwise the size of intmax_t is 64-bits.
 * The shadow function uses 32-bit size of intmax_t for %j conversion.
 * The #pragma redefine_extname in <stdio.h> selects the proper routine
 * at compile time for the user application.
 * NOTE: these functions are only available in the 32-bit library.
 */
#pragma redefine_extname vsprintf _vsprintf_c89
#pragma redefine_extname sprintf _sprintf_c89
#endif

int
vsprintf(char *string, const char *format, va_list ap)
{
	ssize_t count;
	FILE siop;

	/*
	 * The dummy FILE * created for vsprintf has the _IOREAD
	 * flag set to distinguish it from printf and fprintf
	 * invocations. It also has the _IOWRT flag set to indicate
	 * it is writable, which is checked later by vfprintf().
	 */
	siop._flag = _IOWRT | _IOREAD;
	siop._cnt = MAXINT;
	siop._base = siop._ptr = (unsigned char *)string;

	/*
	 * Mark the dummy FILE so that no locking is ever done.
	 */
	if (__fsetlocking(&siop, FSETLOCKING_BYCALLER) == -1)
		upanic(NULL, 0);	/* this should never happen */

	count = vfprintf(&siop, format, ap);

	*siop._ptr = '\0'; /* plant terminating null character */

	return ((int)count);
}

int
sprintf(char *string, const char *format, ...)
{
	int count;
	va_list ap;

	va_start(ap, format);
	count = vsprintf(string, format, ap);
	va_end(ap);

	return (count);
}
