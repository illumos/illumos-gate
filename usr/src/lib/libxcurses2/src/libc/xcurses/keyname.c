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
 * keyname.c
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
"libxcurses/src/libc/xcurses/rcs/keyname.c 1.3 1998/05/29 15:58:43 "
"cbates Exp $";
#endif
#endif

#include <private.h>

char *
keyname(int ch)
{
	const short	(*p)[2];
	char	*str;
	static const char	*unknown_key = "UNKNOWN KEY";


	/* Lookup KEY_ code. */
	for (p = __m_keyindex; **p != -1; ++p) {
		if ((*p)[1] == ch) {
			str = (char *)strfnames[**p];
			goto done;
		}
	}

	/* unctrl() handles printable, control, and meta keys. */
	if ((str = unctrl(ch)) == NULL)	{
	    str = (char *)unknown_key;
	}
done:
	return (str);
}
