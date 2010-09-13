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
 * wacs.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/wacs.c 1.8 1995/10/02 19:48:06 ant Exp $";
#endif
#endif

#include <private.h>
#include <limits.h>

/*
 * Mapping defined in Xcurses Section 6.2.12 (p260).
 */
const cchar_t __WACS_VLINE = 
	{ 1, 1, WA_ALTCHARSET, 0, M_MB_L("x") };
const cchar_t __WACS_HLINE = 
	{ 1, 1, WA_ALTCHARSET, 0, M_MB_L("q") };
const cchar_t __WACS_ULCORNER = 
	{ 1, 1, WA_ALTCHARSET, 0, M_MB_L("l") };
const cchar_t __WACS_URCORNER = 
	{ 1, 1, WA_ALTCHARSET, 0, M_MB_L("k") };
const cchar_t __WACS_LLCORNER = 
	{ 1, 1, WA_ALTCHARSET, 0, M_MB_L("m") };
const cchar_t __WACS_LRCORNER = 
	{ 1, 1, WA_ALTCHARSET, 0, M_MB_L("j") };
const cchar_t __WACS_RTEE = 
	{ 1, 1, WA_ALTCHARSET, 0, M_MB_L("u") };
const cchar_t __WACS_LTEE = 
	{ 1, 1, WA_ALTCHARSET, 0, M_MB_L("t") };
const cchar_t __WACS_BTEE = 
	{ 1, 1, WA_ALTCHARSET, 0, M_MB_L("v") };
const cchar_t __WACS_TTEE = 
	{ 1, 1, WA_ALTCHARSET, 0, M_MB_L("w") };
const cchar_t __WACS_PLUS = 
	{ 1, 1, WA_ALTCHARSET, 0, M_MB_L("n") };
const cchar_t __WACS_S1 = 
	{ 1, 1, WA_ALTCHARSET, 0, M_MB_L("o") };
const cchar_t __WACS_S9 = 
	{ 1, 1, WA_ALTCHARSET, 0, M_MB_L("s") };
const cchar_t __WACS_DIAMOND = 
	{ 1, 1, WA_ALTCHARSET, 0, M_MB_L("`") };
const cchar_t __WACS_CKBOARD = 
	{ 1, 1, WA_ALTCHARSET, 0, M_MB_L("a") };
const cchar_t __WACS_DEGREE = 
	{ 1, 1, WA_ALTCHARSET, 0, M_MB_L("f") };
const cchar_t __WACS_PLMINUS = 
	{ 1, 1, WA_ALTCHARSET, 0, M_MB_L("g") };
const cchar_t __WACS_BULLET = 
	{ 1, 1, WA_ALTCHARSET, 0, M_MB_L("~") };
const cchar_t __WACS_LARROW = 
	{ 1, 1, WA_ALTCHARSET, 0, M_MB_L(",") };
const cchar_t __WACS_RARROW = 
	{ 1, 1, WA_ALTCHARSET, 0, M_MB_L("+") };
const cchar_t __WACS_DARROW = 
	{ 1, 1, WA_ALTCHARSET, 0, M_MB_L(".") };
const cchar_t __WACS_UARROW = 
	{ 1, 1, WA_ALTCHARSET, 0, M_MB_L("-") };
const cchar_t __WACS_BOARD = 
	{ 1, 1, WA_ALTCHARSET, 0, M_MB_L("h") };
const cchar_t __WACS_LANTERN = 
	{ 1, 1, WA_ALTCHARSET, 0, M_MB_L("i") };
const cchar_t __WACS_BLOCK = 
	{ 1, 1, WA_ALTCHARSET, 0, M_MB_L("0") };

#ifdef NOT_NOW
const cchar_t *WACS_VLINE = (const cchar_t *) &__WACS_VLINE;
const cchar_t *WACS_HLINE = (const cchar_t *) &__WACS_HLINE;
const cchar_t *WACS_ULCORNER = (const cchar_t *) &__WACS_ULCORNER;
const cchar_t *WACS_URCORNER = (const cchar_t *) &__WACS_URCORNER;
const cchar_t *WACS_LLCORNER = (const cchar_t *) &__WACS_LLCORNER;
const cchar_t *WACS_LRCORNER = (const cchar_t *) &__WACS_LRCORNER;
const cchar_t *WACS_RTEE = (const cchar_t *) &__WACS_RTEE;
const cchar_t *WACS_LTEE = (const cchar_t *) &__WACS_LTEE;
const cchar_t *WACS_BTEE = (const cchar_t *) &__WACS_BTEE;
const cchar_t *WACS_TTEE = (const cchar_t *) &__WACS_TTEE;
const cchar_t *WACS_PLUS = (const cchar_t *) &__WACS_PLUS;
const cchar_t *WACS_S1 = (const cchar_t *) &__WACS_S1;
const cchar_t *WACS_S9 = (const cchar_t *) &__WACS_S9;
const cchar_t *WACS_DIAMOND = (const cchar_t *) &__WACS_DIAMOND;
const cchar_t *WACS_CKBOARD = (const cchar_t *) &__WACS_CKBOARD;
const cchar_t *WACS_DEGREE = (const cchar_t *) &__WACS_DEGREE;
const cchar_t *WACS_PLMINUS = (const cchar_t *) &__WACS_PLMINUS;
const cchar_t *WACS_BULLET = (const cchar_t *) &__WACS_BULLET;
const cchar_t *WACS_LARROW = (const cchar_t *) &__WACS_LARROW;
const cchar_t *WACS_RARROW = (const cchar_t *) &__WACS_RARROW;
const cchar_t *WACS_DARROW = (const cchar_t *) &__WACS_DARROW;
const cchar_t *WACS_UARROW = (const cchar_t *) &__WACS_UARROW;
const cchar_t *WACS_BOARD = (const cchar_t *) &__WACS_BOARD;
const cchar_t *WACS_LANTERN = (const cchar_t *) &__WACS_LANTERN;
const cchar_t *WACS_BLOCK = (const cchar_t *) &__WACS_BLOCK;
#endif

/* The default characters are from the _primary_ character set. */
static unsigned char acs_defaults[] = 
	"x|q-l+k+m+j+u+t+v+w+n+o-s_`+a:f\'g#~o,<+>.v-^h#i#0#";

int
__m_acs_cc(chtype acs, cchar_t *cc)
{
	int i, ch;
	unsigned char *acsc;

	/* Is it a single-byte character? */
	if (UCHAR_MAX < (A_CHARTEXT & acs) || __m_chtype_cc(acs, cc) == ERR)
		return -1;

	if (!(acs & A_ALTCHARSET))
		return 0;
		
	/* Pick the acs mapping string to use. */
	if (acs_chars == (char *) 0) {
		/* Use primary character set. */
		acsc = acs_defaults;
		acs &= ~A_ALTCHARSET;
	} else {
		acsc = (unsigned char *) acs_chars;
	}

	/* Assume that acsc is even in length. */
	for (i = 0; acsc[i] != '\0'; i += 2) {
		if (acsc[i] == (acs & A_CHARTEXT)) {
			(void) __m_chtype_cc(
				(chtype) ((acs & A_ATTRIBUTES) | acsc[i+1]), cc
			);
			break;
		}
	}

	return 0;
}

int
__m_wacs_cc(const cchar_t *acs, cchar_t *cc)
{
	int i;
	unsigned char *acsc, mb[MB_LEN_MAX];

	*cc = *acs;
	cc->_f = 1;

	/* Is it a single-byte character? */
	if (!(acs->_at & WA_ALTCHARSET)
	|| acs->_n != 1 || wctomb((char *) mb, acs->_wc[0]) != 1)
		/* No, just return the original character. */
		return 0;

	/* Pick the acs mapping string to use. */
	if (acs_chars == (char *) 0) {
		/* Use primary character set. */
		acsc = acs_defaults;
		cc->_at &= ~A_ALTCHARSET;
	} else {
		acsc = (unsigned char *) acs_chars;
	}

	/* Assume that acsc is even in length. */
	for (i = 0; acsc[i] != '\0'; i += 2) {
		if (acsc[i] == *mb) {
			(void) mbtowc(cc->_wc, (char *) &acsc[i+1], 1);
			cc->_at |= A_ALTCHARSET;
			break;
		}
	}

	return 0;
}
