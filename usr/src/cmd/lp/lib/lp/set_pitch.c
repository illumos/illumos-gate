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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.9	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "string.h"
#include "stdlib.h"

#include "lp.h"
#include "lp.set.h"

extern char		*tparm();

short			output_res_char		= -1,
			output_res_line		= -1,
			output_res_horz_inch	= -1,
			output_res_vert_inch	= -1;

/**
 ** set_pitch()
 **/

int
#if	defined(__STDC__)
set_pitch (
	char *			str,
	int			which,
	int			putout
)
#else
set_pitch (str, which, putout)
	char			*str;
	int			which,
				putout;
#endif
{
	double			xpi;

	int			ixpi;

	short			*output_res_p,
				*output_res_inch_p;

	unsigned short		xpi_changes_res;

	char			*rest,
				*change_pitch,
				*change_res,
				*p;


	if (which == 'H') {

		tidbit ((char *)0, "cpi", &change_pitch);
		tidbit ((char *)0, "chr", &change_res);

		output_res_inch_p = &output_res_horz_inch;
		if (output_res_horz_inch == -1)
			tidbit ((char *)0, "orhi", output_res_inch_p);

		output_res_p = &output_res_char;
		if (output_res_char == -1)
			tidbit ((char *)0, "orc", output_res_p);

		tidbit ((char *)0, "cpix", &xpi_changes_res);

	} else {

		tidbit ((char *)0, "lpi", &change_pitch);;
		tidbit ((char *)0, "cvr", &change_res);;

		output_res_inch_p = &output_res_vert_inch;
		if (output_res_vert_inch == -1)
			tidbit ((char *)0, "orvi", output_res_inch_p);

		output_res_p = &output_res_line;
		if (output_res_line == -1)
			tidbit ((char *)0, "orl", output_res_p);

		tidbit ((char *)0, "lpix", &xpi_changes_res);;

	}

	xpi = strtod(str, &rest);
	if (which == 'H' && STREQU(str, NAME_PICA))
		ixpi = R(xpi = 10);

	else if (which == 'H' && STREQU(str, NAME_ELITE))
		ixpi = R(xpi = 12);

	else if (
		which == 'H'
	     && (
			STREQU(str, NAME_COMPRESSED)
		     || xpi >= N_COMPRESSED
		)
	) {
		if (change_pitch) {

			for (ixpi = MAX_COMPRESSED; ixpi; ixpi--)
				if ((p = tparm(change_pitch, ixpi)) && *p)
					break;
			if (!ixpi)
				ixpi = 10;
			xpi = (double)ixpi;

		} else if (change_res && *output_res_inch_p != -1) {

			for (xpi = MAX_COMPRESSED; xpi >= 1.; xpi -= 1.)
				if (
			(p = tparm(change_res, R(*output_res_inch_p / xpi)))
				     && *p
				)
					break;
			if (xpi < 1.)
				xpi = 10.;
			ixpi = R(xpi);

		} else
			return (E_FAILURE);

	} else {

		if (xpi <= 0)
			return (E_BAD_ARGS);

		switch (*rest) {
		case ' ':
		case 0:
			break;
		case 'c':
			/*
			 * Convert to [lines|chars] per inch.
			 */
			xpi *= 2.54;
			/* fall through */
		case 'i':
			break;
		default:
			return (E_BAD_ARGS);
		}

		ixpi = R(xpi);

	}

	if (
		*output_res_inch_p != -1
	     && *output_res_p != -1
	     && R(*output_res_inch_p / (double)*output_res_p) == ixpi
	)
		return (E_SUCCESS);

	else if (
		change_pitch
	     && (p = tparm(change_pitch, ixpi))
	     && *p
	) {

		if (putout)
			putp (p);
		if (xpi_changes_res) {
			if (*output_res_inch_p != -1)
				*output_res_inch_p = R(*output_res_p * xpi);
		} else {
			if (*output_res_p != -1)
				*output_res_p = R(*output_res_inch_p / xpi);
		}
		return (E_SUCCESS);

	} else if (
		change_res
	     && *output_res_inch_p != -1
	     && (p = tparm(change_res, R(*output_res_inch_p / xpi)))
	     && *p
	) {

		if (putout)
			putp (p);
		if (*output_res_p != -1)
			*output_res_p = R(*output_res_inch_p / xpi);
		return (E_SUCCESS);

	} else

		return (E_FAILURE);
}
