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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <sys/types.h>
#include <stdlib.h>
#include "curses_inc.h"

#ifdef PC6300PLUS
#include <fcntl.h>
#include <sys/console.h>
#endif

int
start_color(void)
{
	short  i, j;
	_Color *color_tbl;

#ifdef PC6300PLUS
	struct console  con;
#endif

	/* if not a color terminal, return error    */

	if ((COLOR_PAIRS = max_pairs) == -1)
		return (ERR);

	/* we have only 6 bits to store color-pair info	*/

	if (COLOR_PAIRS > 64)
		COLOR_PAIRS = 64;

#ifdef PC6300PLUS
	ioctl(cur_term->Filedes, CONIOGETDATA, &con);
	if (!con.color)
		return (ERR);
#endif

	/* allocate pairs_tbl	*/

	if ((cur_term->_pairs_tbl =
	    (_Color_pair *) malloc((COLOR_PAIRS+1) *
	    sizeof (_Color_pair))) == NULL)
		goto err2;

	COLORS = max_colors;

/*  the following is not required because we assume that color 0 is */
/*  always a default background.  if this will change, we may want  */
/*  to store the default colors in entry 0 of pairs_tbl.	    */
/*
 *	cur_term->_pairs_tbl[0].foreground = 0;
 *	cur_term->_pairs_tbl[0].background = COLORS;
 */

	/* if terminal can change the definition of the color	*/
	/* allocate color_tbl					*/

	if (can_change)
		if ((color_tbl = (cur_term->_color_tbl =
		    (_Color *) malloc(COLORS * sizeof (_Color)))) == NULL)
			goto err1;

	/* allocate color mark map for cookie terminals */

	if (ceol_standout_glitch || (magic_cookie_glitch >= 0)) {
		int	i, nc;
		char	**marks;

		if ((marks = (char **)calloc((unsigned)LINES,
		    sizeof (char *))) == NULL)
			goto err;
		SP->_color_mks = marks;
		nc = (COLS / BITSPERBYTE) + (COLS % BITSPERBYTE ? 1 : 0);
		if ((*marks = (char *)calloc((unsigned)nc * LINES,
		    sizeof (char))) == NULL) {
			free(marks);
err:			free(color_tbl);
			cur_term->_color_tbl = NULL;
err1:			free(cur_term->_pairs_tbl);
			cur_term->_pairs_tbl = NULL;
err2:			return (ERR);
		}

		for (i = LINES - 1; i-- > 0; ++marks)
			*(marks + 1) = *marks + nc;
	}

	if (can_change) {
	/* initialize color_tbl with the following colors: black, blue,	*/
	/* green, cyan, red, magenta, yellow, black.  if table has more	*/
	/* than 8 entries, use the same 8 colors for the following 8	*/
	/* positions, and then again, and again ....  If table has less	*/
	/* then 8 entries, use as many colors as will fit in.		*/

		for (i = 0; i < COLORS; i++) {
			j = i%8;

			if (j%2)
				color_tbl[i].b = 1000;
			else
				color_tbl[i].b = 0;

			if ((j%4) > 1)
				color_tbl[i].g = 1000;
			else
				color_tbl[i].g = 0;

			if (j > 3)
				color_tbl[i].r = 1000;
			else
				color_tbl[i].r = 0;
		}

		if (orig_colors)
			(void) tputs(orig_colors, 1, _outch);
	}

	if (orig_pair)
		(void) tputs(tparm_p0(orig_pair), 1, _outch);

	/* for Tek terminals set the background color to zero */

	if (set_background) {
		(void) tputs(tparm_p1(set_background, 0), 1, _outch);
		cur_term->_cur_pair.background = 0;
		cur_term->_cur_pair.foreground = -1;
	}
	return (OK);
}
