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
/*  Copyright (c) 1988 AT&T */
/*    All Rights Reserved   */


/*
 *      Copyright (c) 1997, by Sun Microsystems, Inc.
 *      All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include	"curses_inc.h"
#include	<sys/types.h>
#include	<ctype.h>

#define	CSWIDTH	514

short		cswidth[4] = {-1, 1, 1, 1};	/* character length */
short		_curs_scrwidth[4] = {1, 1, 1, 1};	/* screen width */

/*
 * This function is called only once in a program.
 * Before cgetwidth() is called, setlocale() must be called.
 */

void
mbgetwidth(void)
{
	unsigned char *cp = &__ctype[CSWIDTH];

	cswidth[0] = cp[0];
	cswidth[1] = cp[1];
	cswidth[2] = cp[2];
	_curs_scrwidth[0] = cp[3];
	_curs_scrwidth[1] = cp[4];
	_curs_scrwidth[2] = cp[5];

}

int
mbeucw(int c)
{
	c &= 0xFF;

	if (c & 0x80) {
		if (c == SS2) {
			return (cswidth[1]);
		} else if (c == SS3) {
			return (cswidth[2]);
		}
		return (cswidth[0]);
	}
	return (1);
}

int
mbscrw(int c)
{
	c &= 0xFF;

	if (c & 0x80) {
		if (c == SS2) {
			return (_curs_scrwidth[1]);
		} else if (c == SS3) {
			return (_curs_scrwidth[2]);
		}
		return (_curs_scrwidth[0]);
	}
	return (1);
}

int
wcscrw(wchar_t wc)
{
	int	rv;

	switch (wc & EUCMASK) {
	case	P11:	/* Code set 1 */
		rv = _curs_scrwidth[0];
		break;
	case	P01:	/* Code set 2 */
		rv = _curs_scrwidth[1];
		break;
	case	P10:	/* Code set 3 */
		rv = _curs_scrwidth[2];
		break;
	default	:	/* Code set 0 */
		rv = 1;
		break;
	}

	return (rv);
}
