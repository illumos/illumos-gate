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

#ifndef _C89_INTMAX32
#pragma weak _vscanf = vscanf
#pragma weak _vfscanf = vfscanf
#pragma weak _vsscanf = vsscanf
#endif

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


/*
 * 32-bit shadow functions _vscanf_c89(), _vfscanf_c89(), _vsscanf_c89()
 * are included here.
 * When using the c89 compiler to build 32-bit applications, the size
 * of intmax_t is 32-bits, otherwise the size of intmax_t is 64-bits.
 * The shadow function uses 32-bit size of intmax_t for %j conversion.
 * The #pragma redefine_extname in <stdio.h> selects the proper routine
 * at compile time for the user application.
 * NOTE: the shadow function only exists in the 32-bit library.
 */

int
#ifdef _C89_INTMAX32	/* _C89_INTMAX32 version in 32-bit libc only */
_vscanf_c89(const char *fmt, va_list ap)
#else
vscanf(const char *fmt, va_list ap)
#endif
{
	rmutex_t	*lk;
	int	ret;

	FLOCKFILE(lk, stdin);

	_SET_ORIENTATION_BYTE(stdin);

#ifdef _C89_INTMAX32
	ret = __doscan_u(stdin, fmt, ap, _F_INTMAX32);
#else
	ret = __doscan_u(stdin, fmt, ap, 0);
#endif

	FUNLOCKFILE(lk);
	return (ret);
}

int
#ifdef _C89_INTMAX32	/* _C89_INTMAX32 version in 32-bit libc only */
_vfscanf_c89(FILE *iop, const char *fmt, va_list ap)
#else
vfscanf(FILE *iop, const char *fmt, va_list ap)
#endif
{
	rmutex_t	*lk;
	int	ret;

	FLOCKFILE(lk, iop);

	_SET_ORIENTATION_BYTE(iop);

#ifdef _C89_INTMAX32
	ret = __doscan_u(iop, fmt, ap, _F_INTMAX32);
#else
	ret = __doscan_u(iop, fmt, ap, 0);
#endif
	FUNLOCKFILE(lk);
	return (ret);
}

int
#ifdef _C89_INTMAX32	/* _C89_INTMAX32 version in 32-bit libc only */
_vsscanf_c89(const char *str, const char *fmt, va_list ap)
#else
vsscanf(const char *str, const char *fmt, va_list ap)
#endif
{
	FILE strbuf;

	/*
	 * The dummy FILE * created for sscanf has the _IOWRT
	 * flag set to distinguish it from scanf and fscanf
	 * invocations.
	 */
	strbuf._flag = _IOREAD | _IOWRT;
	strbuf._ptr = strbuf._base = (unsigned char *)str;
	strbuf._cnt = strlen(str);
	SET_FILE(&strbuf, _NFILE);

	/*
	 * Mark the stream so that routines called by __doscan_u()
	 * do not do any locking. In particular this avoids a NULL
	 * lock pointer being used by getc() causing a core dump.
	 * See bugid -  1210179 program SEGV's in sscanf if linked with
	 * the libthread.
	 * This also makes sscanf() quicker since it does not need
	 * to do any locking.
	 */
	if (__fsetlocking(&strbuf, FSETLOCKING_BYCALLER) == -1) {
		return (-1);	/* this should never happen */
	}

	/* as this stream is local to this function, no locking is be done */
#ifdef _C89_INTMAX32
	return (__doscan_u(&strbuf, fmt, ap, _F_INTMAX32));
#else
	return (__doscan_u(&strbuf, fmt, ap, 0));
#endif
}
