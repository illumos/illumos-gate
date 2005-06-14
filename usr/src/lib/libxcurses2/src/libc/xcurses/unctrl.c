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
 * unctrl.c
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
"libxcurses/src/libc/xcurses/rcs/unctrl.c 1.3 1998/05/29 15:58:55 "
"cbates Exp $";
#endif
#endif

#include <private.h>
#include <limits.h>
#include <ctype.h>

static const char *carat[] = {
	"^?",
	"^@",
	"^A",
	"^B",
	"^C",
	"^D",
	"^E",
	"^F",
	"^G",
	"^H",
	"^I",
	"^J",
	"^K",
	"^L",
	"^M",
	"^N",
	"^O",
	"^P",
	"^Q",
	"^R",
	"^S",
	"^T",
	"^U",
	"^V",
	"^W",
	"^X",
	"^Y",
	"^Z",
	"^[",
	"^\\",
	"^]",
	"^^",
	"^_"
};

char *
unctrl(chtype ch)
{
	char	*str;
	int	c, msb;
	static char	chr[5];


	/* Map wide character to a wide string. */
	c = (int)(ch & A_CHARTEXT);
	msb = 1 << (CHAR_BIT-1);

	if (c & ~((1 << CHAR_BIT) - 1)) {
		/* Only know about single-byte characters I guess ... */
		return (NULL);
	}
	if (iscntrl(c)) {
		/* ASCII DEL */
		if (c == 127)
			return ((char *)carat[0]);

		/* ASCII control codes. */
		if (0 <= c && c < 32)
			return ((char *)carat[c+1]);

		/* Something we don't know what to do with. */
		return (NULL);
	} else if (c & msb) {
		/* Meta key notation if high bit is set on character. */
		c &= ~msb;

		chr[0] = 'M';
		chr[1] = '-';

		if (iscntrl(c)) {
			str = (char *) unctrl(c);
			chr[2] = *str++;
			chr[3] = *str;
			chr[4] = '\0';
		} else {
			chr[2] = (char)c;
			chr[3] = '\0';
		}
	} else {
		/* Return byte as is. */
		chr[0] = (char)c;
		chr[1] = '\0';
	}

	return (chr);
}
