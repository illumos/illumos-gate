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
 * wacs.c
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
"libxcurses/src/libc/xcurses/rcs/wacs.c 1.6 1998/05/04 21:16:22 "
"cbates Exp $";
#endif
#endif

#include <private.h>
#include <limits.h>

/*
 * Mapping defined in Xcurses Section 6.2.12 (p260).
 */
const cchar_t __WACS_VLINE =
	{ 1, 1, 0, WA_ALTCHARSET, L"x" };
const cchar_t __WACS_HLINE =
	{ 1, 1, 0, WA_ALTCHARSET, L"q" };
const cchar_t __WACS_ULCORNER =
	{ 1, 1, 0, WA_ALTCHARSET, L"l" };
const cchar_t __WACS_URCORNER =
	{ 1, 1, 0, WA_ALTCHARSET, L"k" };
const cchar_t __WACS_LLCORNER =
	{ 1, 1, 0, WA_ALTCHARSET, L"m" };
const cchar_t __WACS_LRCORNER =
	{ 1, 1, 0, WA_ALTCHARSET, L"j" };
const cchar_t __WACS_RTEE =
	{ 1, 1, 0, WA_ALTCHARSET, L"u" };
const cchar_t __WACS_LTEE =
	{ 1, 1, 0, WA_ALTCHARSET, L"t" };
const cchar_t __WACS_BTEE =
	{ 1, 1, 0, WA_ALTCHARSET, L"v" };
const cchar_t __WACS_TTEE =
	{ 1, 1, 0, WA_ALTCHARSET, L"w" };
const cchar_t __WACS_PLUS =
	{ 1, 1, 0, WA_ALTCHARSET, L"n" };
const cchar_t __WACS_S1 =
	{ 1, 1, 0, WA_ALTCHARSET, L"o" };
const cchar_t __WACS_S9 =
	{ 1, 1, 0, WA_ALTCHARSET, L"s" };
const cchar_t __WACS_DIAMOND =
	{ 1, 1, 0, WA_ALTCHARSET, L"`" };
const cchar_t __WACS_CKBOARD =
	{ 1, 1, 0, WA_ALTCHARSET, L"a" };
const cchar_t __WACS_DEGREE =
	{ 1, 1, 0, WA_ALTCHARSET, L"f" };
const cchar_t __WACS_PLMINUS =
	{ 1, 1, 0, WA_ALTCHARSET, L"g" };
const cchar_t __WACS_BULLET =
	{ 1, 1, 0, WA_ALTCHARSET, L"~" };
const cchar_t __WACS_LARROW =
	{ 1, 1, 0, WA_ALTCHARSET, L"," };
const cchar_t __WACS_RARROW =
	{ 1, 1, 0, WA_ALTCHARSET, L"+" };
const cchar_t __WACS_DARROW =
	{ 1, 1, 0, WA_ALTCHARSET, L"." };
const cchar_t __WACS_UARROW =
	{ 1, 1, 0, WA_ALTCHARSET, L"-" };
const cchar_t __WACS_BOARD =
	{ 1, 1, 0, WA_ALTCHARSET, L"h" };
const cchar_t __WACS_LANTERN =
	{ 1, 1, 0, WA_ALTCHARSET, L"i" };
const cchar_t __WACS_BLOCK =
	{ 1, 1, 0, WA_ALTCHARSET, L"0" };

/* The default characters are from the _primary_ character set. */
static const unsigned char acs_defaults[] =
	"x|q-l+k+m+j+u+t+v+w+n+o-s_`+a:f\'g#~o,<+>.v-^h#i#0#";

int
__m_acs_cc(chtype acs, cchar_t *cc)
{
	int	i;
	unsigned char	*acsc;
	chtype	vacs;

	vacs = acs & A_CHARTEXT;

	/* Is it a single-byte character? */
	if (UCHAR_MAX < vacs ||
		__m_chtype_cc(acs, cc) == ERR)
		return (-1);

	if (!(acs & A_ALTCHARSET))
		return (0);

	/* Pick the acs mapping string to use. */
	if (acs_chars == NULL) {
		/* Use primary character set. */
		acsc = (unsigned char *) acs_defaults;
		acs &= ~A_ALTCHARSET;
	} else {
		acsc = (unsigned char *) acs_chars;
	}

	/* Assume that acsc is even in length. */
	for (i = 0; acsc[i] != '\0'; i += 2) {
		if (acsc[i] == vacs) {
			(void) __m_chtype_cc((chtype)
				((acs & A_ATTRIBUTES) | acsc[i+1]), cc);
			break;
		}
	}

	return (0);
}

/* Returns 1 if ALTCHARSET is to be cleared (override). 0 Otherwise. */
int
__m_wacs_cc(const cchar_t *acs, cchar_t *cc)
{
	int	i;
	unsigned char	*acsc, mb[MB_LEN_MAX];
	int	clearit = 0;

	*cc = *acs;
	cc->_f = 1;

	/* Is it a single-byte character? */
	if (!(acs->_at & WA_ALTCHARSET) ||
		acs->_n != 1 || wctomb((char *) mb, acs->_wc[0]) != 1)
		/* No, just return the original character. */
		return (0);

	/* Pick the acs mapping string to use. */
	if (acs_chars == NULL) {
		/* Use primary character set. */
		acsc = (unsigned char *) acs_defaults;
		clearit = 1;
	} else {
		acsc = (unsigned char *) acs_chars;
	}

	/* Assume that acsc is even in length. */
	for (i = 0; acsc[i] != '\0'; i += 2) {
		if (acsc[i] == *mb) {
			(void) mbtowc(cc->_wc, (char *) &acsc[i+1], 1);
			break;
		}
	}

	return (clearit);
}
