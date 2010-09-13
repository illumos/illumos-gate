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
 * tgetstr.c
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
"libxcurses/src/libc/xcurses/rcs/tgetstr.c 1.4 1998/05/28 17:10:23 "
"cbates Exp $";
#endif
#endif

#include <private.h>
#include <string.h>

/*
 * Termcap Emulation
 *
 * Similar to tigetstr() except cap is a termcap code and area is
 * the buffer area used to receive a copy of the string.
 */
char *
tgetstr(char *cap, char **area)
{
	int	i;
	const char	**p;
	char	*value = (char *) -1;

	for (p = strcodes, i = 0; *p != NULL; p++, i++) {
		if (memcmp(*p, cap, 2) == 0) {
			value = cur_term->_str[i];
			if (area && *area != NULL)
				*area += strlen(strcpy(*area, value));
			break;
		}
	}

	return (value);
}
