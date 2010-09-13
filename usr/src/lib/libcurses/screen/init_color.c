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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
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
#include "curses_inc.h"


static	void	_rgb_to_hls(float, float, float, int *, int *, int *);
static float	MAX(float, float, float), MIN(float, float, float);


int
init_color(short color, short r, short g, short b)
{
	_Color *ctp = cur_term->_color_tbl;  /* color table pointer */

	/* check if terminal can change color and validity of the	    */
	/* first argument						    */

	if (!can_change || color >= COLORS || color < 0)
		return (ERR);

	/* if any of the last 3 arguments is out of 0 - 1000 range,	*/
	/* adjust them accordingly					*/

	if (r > 1000)	r = 1000;
	if (g > 1000)	g = 1000;
	if (b > 1000)	b = 1000;
	if (r < 0)	r = 0;
	if (g < 0)	g = 0;
	if (b < 0)	b = 0;

	/* if the call came from scr_reset, the color_table already	*/
	/* contains desired values, but we should still send escape seq. */

	/* if new color is exactly the same as the old one, return */

	if (ctp[color].r == r && ctp[color].g == g && ctp[color].b == b)
		return (OK);

	/* update color table		*/

	ctp[color].r = r;   ctp[color].g = g;    ctp[color].b = b;

	/* all the occurrences of color on the screen must be changed   */
	/* to the new definition					*/

	/* for terminals that can define individual colors (Tek model)  */
	/* send an escape sequence to define that color			*/

	if (initialize_color) {
		if (hue_lightness_saturation) {
			int	h, s, l;
			_rgb_to_hls((float)r, (float)g, (float)b, &h, &l, &s);
			(void) tputs(tparm_p4(initialize_color, color, h, l, s),
			    1, _outch);
		} else
			(void) tputs(tparm_p4(initialize_color, color, r, g, b),
			    1, _outch);


	}

	/* for terminals that can only define color pairs, go through   */
	/* pairs table, and re-initialize all pairs that use given color */

	else {
		short i;
		_Color_pair *ptp = cur_term->_pairs_tbl;
		/* pairs table pointer */
		for (i = 0; i < COLOR_PAIRS; i++) {
			if (ptp[i].foreground == color ||
			    ptp[i].background == color)
				_init_HP_pair(i, ptp[i].foreground,
				    ptp[i].background);
		}
	}
	return (OK);
}




static void
_rgb_to_hls(float r, float g, float b, int *hh, int *ll, int *ss)
{
	float	rc, gc, bc, h, l, s;
	double	max, min;

	r /= 1000;  g /= 1000;  b /= 1000;

	max = MAX(r, g, b);
	min = MIN(r, g, b);

	/* calculate lightness  */

	l = (max + min) / 2;

	/* calculate saturation */

	if (max == min) {
		s = 0;
		h = 0;
	} else {
		if (l < 0.5)
			s = (max - min) / (max + min);
		else
			s = (max - min) / (2 - max - min);

		/* calculate hue   */

		rc = (max - r) / (max - min);
		gc = (max - g) / (max - min);
		bc = (max - b) / (max - min);

		if (r == max)
			h = bc - gc;
		else if (g == max)
			h = 2 + rc - bc;
		else /* if (b == max) */
			h = 4 + gc - rc;

		h = h * 60;
		if (h < 0.0)
			h = h + 360;

		/* until here we have converted into HSL.  */
		/* Now, to convert into */
		/* Tektronix HLS, add 120 to h		*/

		h = ((int)(h+120))%360;
	}
	*hh = (int) h;
	*ss = (int) (s * 100);
	*ll = (int) (l * 100);
}


static float
MAX(float a, float b, float c)
{
	if (a >= b)
		if (a >= c)
			return (a);
		else return (c);
	else if (c >= b)
		return (c);
	else return (b);
}

static float
MIN(float a, float b, float c)
{
	if (a > b)
		if (b > c)
			return (c);
		else return (b);
	else if (a < c)
		return (a);
	else return (c);
}
