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
#include <errno.h>
#include <thread.h>
#include <synch.h>
#include <values.h>
#include "print.h"
#include <sys/types.h>
#include "libc.h"
#include "mse.h"

/*VARARGS1*/
int
printf(const char *format, ...)
{
	ssize_t count;
	rmutex_t *lk;
	va_list ap;

	va_start(ap, format);

	/* Use F*LOCKFILE() macros because printf() is not async-safe. */
	FLOCKFILE(lk, stdout);

	_SET_ORIENTATION_BYTE(stdout);

	if (!(stdout->_flag & _IOWRT)) {
		/* if no write flag */
		if (stdout->_flag & _IORW) {
			/* if ok, cause read-write */
			stdout->_flag |= _IOWRT;
		} else {
			/* else error */
			FUNLOCKFILE(lk);
			errno = EBADF;
			return (EOF);
		}
	}
	count = _ndoprnt(format, ap, stdout, 0);
	va_end(ap);

	/* check for errors or EOF */
	if (FERROR(stdout) || count ==  EOF) {
		FUNLOCKFILE(lk);
		return (EOF);
	}

	FUNLOCKFILE(lk);

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
 * 32-bit shadow function of printf().
 * When using the c89 compiler to build 32-bit applications, the size
 * of intmax_t is 32-bits, otherwise the size of intmax_t is 64-bits.
 * The shadow function uses 32-bit size of intmax_t for %j conversion.
 * The #pragma redefine_extname in <stdio.h> selects the proper routine
 * at compile time for the user application.
 * NOTE: this function only exists in the 32-bit library.
 */

int
_printf_c89(const char *format, ...)
{
	ssize_t count;
	va_list ap;

	va_start(ap, format);
	count = _vprintf_c89(format, ap);
	va_end(ap);
	return ((int)count);
}

#endif
