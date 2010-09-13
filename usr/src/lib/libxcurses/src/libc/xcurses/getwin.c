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
 * getwin.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/getwin.c 1.2 1995/06/12 17:48:38 ant Exp $";
#endif
#endif

#include <private.h>
#include <limits.h>

static int
get_cc(w, mbs, fp)
WINDOW *w;
char *mbs;
FILE *fp;
{
	short co;
	attr_t at;
	int i, n, y, x;

	if (fscanf(fp, "%d,%d,%hx,%hd,", &y, &x, &at, &co) < 4)
		return 0;

	if (fscanf(fp, "%[^\n]%n ", mbs, &n) < 1)
		return 0;

	if (wattr_set(w, at, co, (void *) 0) == ERR)
		return 0;

	if (mvwaddstr(w, y, x, mbs) == ERR)
		return 0;

	(void) wstandend(w);

	return n;
}

WINDOW *
getwin(fp)
FILE *fp;
{
	char *mbs;
	WINDOW *w;
	short flags;
	int by, bx, my, mx;

#ifdef M_CURSES_TRACE
	__m_trace("getwin(%p)", fp);
#endif

	/* Get window dimensions and location to create a new window. */
	if (fscanf(fp, "MAX=%d,%d BEG=%d,%d ", &my, &mx, &by, &bx) < 4)
		goto error1;

	if ((mbs = (char *) malloc((size_t) (LINE_MAX+1))) == (char *) 0)
		goto error1;
	
	if ((w = newwin(my, mx, by, bx)) == (WINDOW *) 0)
		goto error2;

	/* Read other window attributes. */
	by = fscanf(
		fp, "SCROLL=%hd,%hd VMIN=%hd VTIME=%hd FLAGS=%hx FG=%hx,%hd ", 
		&w->_top, &w->_bottom, &w->_vmin, &w->_vtime, &flags,
		&w->_fg._at, &w->_fg._co
	); 
	if (by < 7)
		goto error3;

	w->_flags &= ~W_CONFIG_MASK;
	w->_flags |= flags;

	by = fscanf( fp, "BG=%hx,%hd,%[^\n] ", &w->_bg._at, &w->_bg._co, mbs);
	if (by < 3)
		goto error3;

	while (get_cc(w, mbs, fp))
		;
	
	if (fscanf(fp, "CUR=%hd,%hd", &w->_cury, &w->_curx) < 2)
		goto error3;
		
	free(mbs);
	
	return __m_return_pointer("getwin", w);
error3:
	(void) delwin(w);
error2:
	free(mbs);
error1:
	rewind(fp);

	return __m_return_pointer("getwin", (WINDOW *) 0);
}

static int
put_cc(w, y, x, mbs, len, fp)
WINDOW *w;
int y, x;
char *mbs;
int len;
FILE *fp;
{
	int i;
	short co;
	attr_t at;

	at = w->_line[y][x]._at;
	co = w->_line[y][x]._co;

	/* Write first character as a multibyte string. */
	(void) __m_cc_mbs(&w->_line[y][x], mbs, len);

	/* Write additional characters with same colour and attributes. */
	for (i = x;;) {
		i = __m_cc_next(w, y, i);
		if (w->_maxx <= i)
			break;
		if (w->_line[y][i]._at != at || w->_line[y][i]._co != co)
			break;
		(void) __m_cc_mbs(&w->_line[y][i], mbs, 0);
	}

	/* Terminate string. */
	(void) __m_cc_mbs((const cchar_t *) 0, (char *) 0, 0);

	(void) fprintf(fp, "%d,%d,%#x,%d,%s\n", y, x, at, co, mbs);

	/* Return index of next unprocessed column. */
	return i;
}

int
putwin(w, fp)
WINDOW *w;
FILE *fp;
{
	char *mbs;
	int y, x, mbs_len;

#ifdef M_CURSES_TRACE
	__m_trace("putwin(%p, %p)", w, fp);
#endif

	mbs_len = columns * M_CCHAR_MAX * MB_LEN_MAX * sizeof *mbs + 1;
	if ((mbs = (char *) malloc((size_t) mbs_len)) == (char *) 0)
		return __m_return_code("putwin", ERR);
	
	(void) fprintf(
		fp, "MAX=%d,%d\nBEG=%d,%d\nSCROLL=%d,%d\n",
		w->_maxy, w->_maxx, w->_begy, w->_begx, w->_top, w->_bottom
	);
	(void) fprintf(
		fp, "VMIN=%d\nVTIME=%d\nFLAGS=%#x\nFG=%#x,%d\n", 
		w->_vmin, w->_vtime, w->_flags & W_CONFIG_MASK,
		w->_fg._at, w->_fg._co
	);

	(void) __m_cc_mbs(&w->_bg, mbs, mbs_len);
	(void) __m_cc_mbs((const cchar_t *) 0, (char *) 0, 0);
	(void) fprintf(fp, "BG=%#x,%d,%s\n", w->_bg._at, w->_bg._co, mbs);

	for (y = 0; y < w->_maxy; ++y) {
		for (x = 0; x < w->_maxx; )
			x = put_cc(w, y, x, mbs, mbs_len, fp);
	}

	(void) fprintf(fp, "CUR=%d,%d\n", w->_curx, w->_cury);

	free(mbs);

	return __m_return_code("putwin", OK);
}

