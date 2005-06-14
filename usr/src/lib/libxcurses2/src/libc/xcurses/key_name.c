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
 * Copyright (c) 1995-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

/*
 * key_name.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] =
"$Header: /team/ps/sun_xcurses/archive/local_changes/xcurses/src/lib/"
"libxcurses/src/libc/xcurses/rcs/key_name.c 1.2 1998/05/28 15:18:35 "
"cbates Exp $";
#endif
#endif

#include <private.h>

char *
key_name(wchar_t wc)
{
	size_t	len;
	cchar_t	cc;
	wchar_t	*ws;
	static char	mbs[MB_LEN_MAX + 1];
	static const char	*unknown_key = "UNKNOWN KEY";

	(void) __m_wc_cc(wc, &cc);

	ws = (wchar_t *) wunctrl(&cc);

	if ((len = wcstombs(mbs, ws, MB_LEN_MAX)) == (size_t) -1)
		return ((char *)unknown_key);

	mbs[len] = '\0';

	return (mbs);
}
