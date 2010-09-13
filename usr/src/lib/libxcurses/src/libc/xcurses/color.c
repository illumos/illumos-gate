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
 * color.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/color.c 1.2 1995/10/02 15:15:02 ant Exp $";
#endif
#endif

#include <private.h>
#include <stdlib.h>

int
start_color()
{
	int code = ERR;

#ifdef M_CURSES_TRACE
	__m_trace("start_color(void)");
#endif

	COLORS = max_colors;
	COLOR_PAIRS = max_pairs; 

	if (orig_colors != (char *) 0)
		(void) tputs(orig_colors, 1, __m_outc);

	if (orig_pair != (char *) 0)
		(void) tputs(orig_pair, 1, __m_outc);

	if (0 < max_colors) {
		cur_term->_color = calloc(max_colors, sizeof *cur_term->_color);
		if (cur_term->_color == (short (*)[3]) 0)
			goto error1;
	}
		
	if (0 < max_pairs) {
		cur_term->_pair = calloc(max_pairs, sizeof *cur_term->_pair);
		if (cur_term->_pair == (short (*)[2]) 0) 
			goto error2;
	}

	return __m_return_code("start_color", OK);
error2:
	if (cur_term->_color != (short (*)[3]) 0)
		free(cur_term->_color);
error1:
	return __m_return_code("start_color", ERR);
}

int
init_color(short color, short r, short g, short b)
{
	int code = ERR;

#ifdef M_CURSES_TRACE
	__m_trace("init_color(%d, %d, %d, %d)", color, r, g, b);
#endif

	if (!can_change || color < 0 || max_colors <= color
	|| r < 0 || 1000 < r
	|| g < 0 || 1000 < g
	|| b < 0 || 1000 < b)
		goto error;
		
	/* Remember color settings for future queries. */
	cur_term->_color[color][0] = r;
	cur_term->_color[color][1] = g;
	cur_term->_color[color][2] = b;

	code = OK;

	/* Set the color. */
	if (initialize_color != (char *) 0) {
		code = tputs(
			tparm(
				initialize_color, (long) color,
				(long) r, (long) g, (long) b, 
				0L, 0L, 0L, 0L, 0L
			), 1, __m_outc
		);
	}
error:
	return __m_return_code("init_color", code);
}

int
init_pair(short pair, short f, short b)
{
	int code = ERR;

#ifdef M_CURSES_TRACE
	__m_trace("init_pair(%d, %d, %d)", pair, f, b);
#endif

	if (pair < 0 || max_pairs <= pair 
	|| f < 0 || max_colors <= f
	|| b < 0 || max_colors <= b)
		goto error;

	/* Remember color-pair settings for future queries. */
	cur_term->_pair[pair][0] = f;
	cur_term->_pair[pair][1] = b;

	code = OK;

	/* Set color-pair (foreground-background). */
	if (initialize_pair == (char *) 0) {
		code = tputs(
			tparm(
				initialize_pair, 
				(long) cur_term->_pair[f][0], 
				(long) cur_term->_pair[f][1], 
				(long) cur_term->_pair[f][2], 
				(long) cur_term->_pair[b][0],
				(long) cur_term->_pair[b][1],
				(long) cur_term->_pair[b][2],
				0L, 0L, 0L
			), 1, __m_outc
		);
	}
error:
	return __m_return_code("init_pair", code);
}

int
color_content(short color, short *r, short *g, short *b)
{
#ifdef M_CURSES_TRACE
	__m_trace("color_content(%d, %p, %p, %p)", color, r, g, b);
#endif

	if (color < 0 || max_colors <= color)
		return __m_return_code("color_content", ERR);

	/* There does not appear to be a terminfo entry to query the
	 * color settings, so we retain them in an array for quick
	 * access.
	 */
	*r = cur_term->_color[color][0];
	*g = cur_term->_color[color][1];
	*b = cur_term->_color[color][2];

	return __m_return_code("color_content", OK);
}

int
pair_content(short pair, short *f, short *b)
{
#ifdef M_CURSES_TRACE
	__m_trace("pair_content(%d, %p, %p)", pair, f, b);
#endif
	if (pair < 0 || max_pairs <= pair)
		return __m_return_code("pair_content", ERR);

	/* There does not appear to be a terminfo entry to query the
	 * color-pair settings, so we retain them in an array for quick
	 * access.
	 */
	*f = cur_term->_pair[pair][0];
	*b = cur_term->_pair[pair][1];

	return __m_return_code("pair_content", OK);
}

