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
 * setcchar.c
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
"libxcurses/src/libc/xcurses/rcs/setcchar.c 1.5 1998/05/26 19:12:33 "
"cbates Exp $";
#endif
#endif

#include <private.h>

/* ARGUSED */
int
setcchar(cchar_t *cc, const wchar_t *wcs, attr_t at,
	short co, const void *opts)
{
	int	i;

	if ((wcs == NULL) || wcs[0] == (wchar_t)0) {
		i = __m_wc_cc((wint_t)0, cc);
		cc->_at = at;
		cc->_co = co;
		if (i != -1)
			i = 0;
	} else if (wcs[1] == (wchar_t)0) {
		i = __m_wc_cc((wint_t)wcs[0], cc);
		cc->_at = at;
		cc->_co = co;
		if (i != -1)
			i = 1;
	} else {
		i = __m_wcs_cc(wcs, at, co, cc);
	}

	return ((i < 0 || (wcs && wcs[i] != '\0')) ? ERR : OK);
}
