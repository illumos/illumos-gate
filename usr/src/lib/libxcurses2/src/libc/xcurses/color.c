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
 * color.c
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
"libxcurses/src/libc/xcurses/rcs/color.c 1.6 1998/05/28 17:10:14 "
"cbates Exp $";
#endif
#endif

#include <private.h>
#include <stdlib.h>

int
start_color(void)
{
	COLORS = max_colors;
	COLOR_PAIRS = max_pairs;

	if (orig_colors != (char *) 0)
		(void) TPUTS(orig_colors, 1, __m_outc);

	if (orig_pair != (char *) 0)
		(void) TPUTS(orig_pair, 1, __m_outc);

	if (0 < max_colors) {
		cur_term->_color = calloc(max_colors,
			sizeof (*cur_term->_color));
		if (cur_term->_color == (short (*)[3]) 0)
			goto error1;
	}

	if (0 < max_pairs) {
		cur_term->_pair = calloc(max_pairs, sizeof (*cur_term->_pair));
		if (cur_term->_pair == (short (*)[2]) 0)
			goto error2;
	}

	(void) init_color(COLOR_BLACK,		0,	0,	0);
	(void) init_color(COLOR_RED,		1000,	0,	0);
	(void) init_color(COLOR_GREEN,		0,	1000,	0);
	(void) init_color(COLOR_BLUE,		0,	0,	1000);
	(void) init_color(COLOR_YELLOW,	1000,	1000,	0);
	(void) init_color(COLOR_MAGENTA,	1000,	0,	1000);
	(void) init_color(COLOR_CYAN,		0,	1000,	1000);
	(void) init_color(COLOR_WHITE,		1000,	1000,	1000);

	return (OK);
error2:
	if (cur_term->_color != (short (*)[3]) 0)
		free(cur_term->_color);
error1:
	return (ERR);
}

int
init_color(short color, short r, short g, short b)
{
	int code = ERR;

	if (!can_change || color < 0 || max_colors <= color ||
		r < 0 || 1000 < r ||
		g < 0 || 1000 < g ||
		b < 0 || 1000 < b)
		goto error;

	/* Remember color settings for future queries. */
	cur_term->_color[color][0] = r;
	cur_term->_color[color][1] = g;
	cur_term->_color[color][2] = b;

	code = OK;

	/* Set the color. */
	if (initialize_color != (char *) 0) {
		code = tputs(tparm(initialize_color, (long) color,
			(long) r, (long) g, (long) b, 0L, 0L, 0L, 0L, 0L),
			1, __m_outc);
	}
error:
	return (code);
}

int
init_pair(short pair, short f, short b)
{
	int code = ERR;

	if (pair < 0 || max_pairs <= pair ||
		f < 0 || max_colors <= f ||
		b < 0 || max_colors <= b)
		goto error;

	/* Remember color-pair settings for future queries. */
	cur_term->_pair[pair][0] = f;
	cur_term->_pair[pair][1] = b;

	code = OK;

	/* Set color-pair (foreground-background). */
	if (initialize_pair != (char *) 0) {
		code = tputs(tparm(initialize_pair,
			(long) cur_term->_color[f][0],
			(long) cur_term->_color[f][1],
			(long) cur_term->_color[f][2],
			(long) cur_term->_color[b][0],
			(long) cur_term->_color[b][1],
			(long) cur_term->_color[b][2],
			0L, 0L, 0L), 1, __m_outc);
	}
error:
	return (code);
}

int
color_content(short color, short *r, short *g, short *b)
{
	if (color < 0 || max_colors <= color)
		return (ERR);

	/*
	 * There does not appear to be a terminfo entry to query the
	 * color settings, so we retain them in an array for quick
	 * access.
	 */
	*r = cur_term->_color[color][0];
	*g = cur_term->_color[color][1];
	*b = cur_term->_color[color][2];

	return (OK);
}

int
pair_content(short pair, short *f, short *b)
{
	if (pair < 0 || max_pairs <= pair)
		return (ERR);

	/*
	 * There does not appear to be a terminfo entry to query the
	 * color-pair settings, so we retain them in an array for quick
	 * access.
	 */
	*f = cur_term->_pair[pair][0];
	*b = cur_term->_pair[pair][1];

	return (OK);
}
