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
/*
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2025 Hans Rosenfeld
 */

#include "lint.h"
#include "file64.h"
#include <mtlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <thread.h>
#include <synch.h>
#include <values.h>
#include <wchar.h>
#include "print.h"
#include "stdiom.h"
#include <sys/types.h>
#include "libc.h"
#include "mse.h"
#include <stdio_ext.h>
#include <upanic.h>

#ifdef _C89_INTMAX32
#pragma redefine_extname vfwprintf _vfwprintf_c89
#pragma redefine_extname vswprintf _vswprintf_c89
#pragma redefine_extname vwprintf _vwprintf_c89
#pragma redefine_extname fwprintf _fwprintf_c89
#pragma redefine_extname swprintf _swprintf_c89
#pragma redefine_extname wprintf _wprintf_c89
#endif

/*
 * 32-bit shadow functions _vwprintf_c89(), _vfwprintf_c89(), _vswprintf_c89(),
 * _wprintf_c89(), _fwprintf_c89(), and _swprintf_c89() are included here.
 * When using the c89 compiler to build 32-bit applications, the size
 * of intmax_t is 32-bits, otherwise the size of intmax_t is 64-bits.
 * The shadow function uses 32-bit size of intmax_t for j conversion.
 * The #pragma redefine_extname in <wchar.h> selects the proper routine
 * at compile time for the user application.
 * NOTE: shadow functions only exist in the 32-bit library.
 */

int
vfwprintf(FILE *iop, const wchar_t *format, va_list ap)
{
	ssize_t	count;
	rmutex_t	*lk;

	FLOCKFILE(lk, iop);

	if (GET_NO_MODE(iop))
		_setorientation(iop, _WC_MODE);

	if (!(iop->_flag & _IOWRT)) {
		/* if no write flag */
		if (iop->_flag & _IORW) {
			/* if ok, cause read-write */
			iop->_flag |= _IOWRT;
		} else {
			/* else error */
			errno = EBADF;
			FUNLOCKFILE(lk);
			return (EOF);
		}
	}
#ifdef _C89_INTMAX32
	count = _ndoprnt(format, ap, iop, _F_INTMAX32);
#else
	count = _ndoprnt(format, ap, iop, 0);
#endif
	if (FERROR(iop) || count == EOF) {
		FUNLOCKFILE(lk);
		return (EOF);
	}
	FUNLOCKFILE(lk);
	/* check for overflow */
	if ((size_t)count > MAXINT) {
		errno = EOVERFLOW;
		return (EOF);
	}

	return ((int)count);
}

int
fwprintf(FILE *iop, const wchar_t *format, ...)
{
	int count;
	va_list	ap;

	va_start(ap, format);
	count = vfwprintf(iop, format, ap);
	va_end(ap);

	return (count);
}

int
vwprintf(const wchar_t *format, va_list ap)
{
	int count;

	count = vfwprintf(stdout, format, ap);

	return (count);
}

int
wprintf(const wchar_t *format, ...)
{
	int count;
	va_list	ap;

	va_start(ap, format);
	count = vfwprintf(stdout, format, ap);
	va_end(ap);

	return (count);
}

int
vswprintf(wchar_t *string, size_t n, const wchar_t *format, va_list ap)
{
	int	count;
	FILE	siop;
	wchar_t	*wp;

	if (n == 0)
		return (EOF);

	/*
	 * The dummy FILE * created for vswprintf has the _IOREAD
	 * flag set to distinguish it from wprintf and wfprintf
	 * invocations. It also has the _IOWRT flag set to indicate
	 * it is writable, which is checked later by vfwprintf().
	 */
	siop._flag = _IOWRT | _IOREAD;
	siop._cnt = (ssize_t)n - 1;
	siop._base = siop._ptr = (unsigned char *)string;

	/*
	 * Mark the dummy FILE so that no locking is ever done.
	 */
	if (__fsetlocking(&siop, FSETLOCKING_BYCALLER) == -1)
		upanic(NULL, 0);	/* this should never happen */

	count = vfwprintf(&siop, format, ap);

	wp = (wchar_t *)(uintptr_t)siop._ptr;
	*wp = L'\0';

	return (count);
}

int
swprintf(wchar_t *string, size_t n, const wchar_t *format, ...)
{
	int count;
	va_list	ap;

	va_start(ap, format);
	count = vswprintf(string, n, format, ap);
	va_end(ap);

	return (count);
}
