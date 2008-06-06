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
#include "file64.h"
#include "mtlib.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <thread.h>
#include <synch.h>
#include "libc.h"
#include "stdiom.h"
#include "mse.h"
#include <stdio_ext.h>

/*VARARGS1*/
int
scanf(const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vscanf(fmt, ap);
	va_end(ap);

	return (ret);
}

/*VARARGS2*/
int
fscanf(FILE *iop, const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vfscanf(iop, fmt, ap);
	va_end(ap);

	return (ret);
}

/*VARARGS2*/
int
sscanf(const char *str, const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vsscanf(str, fmt, ap);
	va_end(ap);

	return (ret);
}

#ifndef _LP64

/*
 * 32-bit shadow functions _scanf_c89(), _fscanf_c89(), _sscanf_c89()
 * included here.
 * When using the c89 compiler to build 32-bit applications, the size
 * of intmax_t is 32-bits, otherwise the size of intmax_t is 64-bits.
 * The shadow function uses 32-bit size of intmax_t for %j conversion.
 * The #pragma redefine_extname in <stdio.h> selects the proper routine
 * at compile time for the user application.
 * NOTE: the shadow function only exists in the 32-bit library.
 */

int
_scanf_c89(const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = _vscanf_c89(fmt, ap);
	va_end(ap);

	return (ret);
}

int
_fscanf_c89(FILE *iop, const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = _vfscanf_c89(iop, fmt, ap);
	va_end(ap);

	return (ret);
}

int
_sscanf_c89(const char *str, const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = _vsscanf_c89(str, fmt, ap);
	va_end(ap);

	return (ret);
}

#endif	/* _LP64 */
