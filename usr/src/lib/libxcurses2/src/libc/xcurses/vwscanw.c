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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

/*
 * vwscanw.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] =
"$Header: /team/ps/sun_xcurses/archive/local_changes/xcurses/src/lib/"
"libxcurses/src/libc/xcurses/rcs/vwscanw.c 1.2 1998/05/27 16:57:09 "
"cbates Exp $";
#endif
#endif

#include <private.h>
#include <limits.h>

#undef va_start
#undef va_end
#undef va_arg

#include <stdarg.h>
#include <stdio.h>

extern int _vsscanf(char *, char *, va_list);

int
vwscanw(WINDOW *w, char *fmt, va_list ap)
{
	int	code;
	char	buffer[LINE_MAX];

	if (wgetnstr(w, buffer, (int)sizeof (buffer)) != OK)
		return (ERR);
	code = _vsscanf(buffer, fmt, ap);

	va_end(ap);
#ifdef EXACT_SPEC
	return ((code == EOF) ? ERR : OK);
#else
	return (code);
#endif
}
