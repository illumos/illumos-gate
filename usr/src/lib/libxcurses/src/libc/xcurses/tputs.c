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
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/tputs.c 1.4 1995/07/19 12:44:45 ant Exp $";
#endif
#endif

#include <private.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

int
__m_putchar(byte)
int byte;
{
	return putchar(byte);
}

int
(putp)(const char *s)
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("putp(%p = \"%s\")", s, s);
#endif

	code = tputs(s, 1, __m_putchar);

	return __m_return_code("putp", code);
}

/*f
 * Apply padding information to a string and write it out.
 * Note the '/' option is not supported.
 */
int
tputs(string, affcnt, putout)
const char *string;
int affcnt;
int (*putout)(int);
{
	char *mark;
	int i, baud, len, null, number;

#ifdef M_CURSES_TRACE
	__m_trace("tputs(%p = \"%s\", %d, %p)", string, string, affcnt, putout);
#endif

	baud = baudrate();
	null = pad_char == (char *) 0 ? '\0' : pad_char[0];

	for (len = 0; *string; ++string){
		/* Look for "$<num.????>" */
		if (*string == '$' 
		&& string[1] == '<' 
		&& (isdigit(string[2]) || string[2] == '.')
		&& (mark = strchr(string, '>'))){
			number = atoi(string+2) * 10;
			if ((string = strchr(string, '.')) != (char *) 0)
				number += *++string-'0';	
			string = mark;
			if (*--mark == '*')
				number *= affcnt;
			if (padding_baud_rate &&  baud >= padding_baud_rate 
			&& !xon_xoff) {
				number = (baud/10 * number)/1000;
				len += number;
				if (putout != (int (*)(int)) 0) {
					for (i=0; i < number; i++)
						(void) (*putout)(null);
				}
			}
		} else {
			++len;
			if (putout != (int (*)(int)) 0)
				(void) (*putout)(*string);
		}
	}

	return __m_return_int("tputs", len);
}


