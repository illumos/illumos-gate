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
 * tputs.c
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
"libxcurses/src/libc/xcurses/rcs/tputs.c 1.4 1998/06/03 12:57:02 "
"cbates Exp $";
#endif
#endif

#include <private.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

int
__m_putchar(int byte)
{
	return (putchar(byte));
}

#undef putp

int
putp(const char *s)
{
	int	code;

	code = tputs(s, 1, __m_putchar);

	return (code);
}

int
tputs(const char *string, int affcnt, int (*putout)(int))
{
	(void) __m_tputs(string, affcnt, putout);

	return (OK);
}

/*
 * Apply padding information to a string and write it out.
 * Note the '/' option is not supported.
 */
int
__m_tputs(const char *string, int affcnt, int (*putout)(int))
{
	char	*mark;
	int	i, baud, len, null, number;

	baud = baudrate();
	null = pad_char == NULL ? '\0' : pad_char[0];

	for (len = 0; *string; ++string) {
		/* Look for "$<num.????>" */
		if (*string == '$' && string[1] == '<' &&
			(isdigit(string[2]) || string[2] == '.') &&
			(mark = strchr(string, '>'))) {
			number = atoi(string + 2) * 10;
			if ((string = strchr(string, '.')) != NULL)
				number += *++string - '0';
			string = mark;
			if (*--mark == '*')
				number *= affcnt;
#ifdef	BREAKS_ftputs_ftputs1_2
			if (padding_baud_rate && baud >= padding_baud_rate &&
				!xon_xoff) {
#else	/* BREAKS_ftputs_ftputs1_2 */
			if (baud >= padding_baud_rate) {
#endif	/* BREAKS_ftputs_ftputs1_2 */
				number = (baud / 8 * number) / 10000;
				len += number;
				if (putout != (int (*)(int)) NULL) {
					for (i = 0; i < number; i++)
						(void) (*putout)(null);
				}
			}
		} else {
			++len;
			if (putout != (int (*)(int)) NULL)
				(void) (*putout)(*string);
		}
	}

	return (len);
}
