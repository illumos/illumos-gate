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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright  (c) 1985 AT&T
 *	All Rights Reserved
 */
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.9 */

#include <curses.h>
#include "wish.h"
#include "token.h"
#include "winp.h"
#include "fmacs.h"
#include "vtdefs.h"
#include "vt.h"
#include "string.h"

#define STR_SIZE	256

int
freadline(row, buff, terminate)
int row;
char *buff;
int terminate;
{
	register int len, size = 0;
	chtype ch_string[STR_SIZE];

	fgo (row, 0);
	len = winchnstr((&VT_array[VT_curid])->win, ch_string, LASTCOL + 1) - 1;

	/* extract characters from the ch_string and copy them into buff */

	while (len >= 0 && ((ch_string[len] & A_CHARTEXT) == ' '))
		len--;

	if (len >= 0) {		/* if there is text on this line */
		size = ++len;
		len = 0;
		while (len < size)
			*buff++ = ch_string[len++] & A_CHARTEXT;
	}
	if (terminate)
		*buff = '\0';
	return(size);
}
