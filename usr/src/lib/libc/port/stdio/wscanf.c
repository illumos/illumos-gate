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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include "file64.h"
#include <mtlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <thread.h>
#include <synch.h>
#include <wchar.h>
#include <errno.h>
#include <stdlib.h>
#include <alloca.h>
#include "mse.h"
#include "stdiom.h"
#include "libc.h"

int
wscanf(const wchar_t *fmt, ...)
{
	int ret;
	va_list	ap;

	va_start(ap, fmt);
	ret = vwscanf(fmt, ap);
	va_end(ap);

	return (ret);
}

int
fwscanf(FILE *iop, const wchar_t *fmt, ...)
{
	int ret;
	va_list	ap;

	va_start(ap, fmt);
	ret = vfwscanf(iop, fmt, ap);
	va_end(ap);

	return (ret);
}

int
swscanf(const wchar_t *wstr, const wchar_t *fmt, ...)
{
	int ret;
	va_list	ap;

	va_start(ap, fmt);
	ret = vswscanf(wstr, fmt, ap);
	va_end(ap);

	return (ret);
}


#ifndef _LP64

/*
 * 32-bit shadow function _wscanf_c89(), _fwscanf_c89(), _swscanf_c89()
 * are included here.
 * When using the c89 compiler to build 32-bit applications, the size
 * of intmax_t is 32-bits, otherwise the size of intmax_t is 64-bits.
 * The shadow function uses 32-bit size of intmax_t for %j conversion.
 * The #pragma redefine_extname in <stdio.h> selects the proper routine
 * at compile time for the user application.
 * NOTE: the shadow function only exists in the 32-bit library.
 */

int
_wscanf_c89(const wchar_t *fmt, ...)
{
	int ret;
	va_list	ap;

	va_start(ap, fmt);
	ret = _vwscanf_c89(fmt, ap);
	va_end(ap);

	return (ret);
}

int
_fwscanf_c89(FILE *iop, const wchar_t *fmt, ...)
{
	int ret;
	va_list	ap;

	va_start(ap, fmt);
	ret = _vfwscanf_c89(iop, fmt, ap);
	va_end(ap);

	return (ret);
}

int
_swscanf_c89(const wchar_t *wstr, const wchar_t *fmt, ...)
{
	int ret;
	va_list	ap;

	va_start(ap, fmt);
	ret = _vswscanf_c89(wstr, fmt, ap);
	va_end(ap);

	return (ret);
}
#endif	/* _LP64 */
