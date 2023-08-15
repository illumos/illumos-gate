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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.13	*/
/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "string.h"
#include "stdlib.h"

#include "lp.h"
#include "lp.set.h"

#if	defined(__STDC__)

char *			tparm ( char * , ... );
int			putp ( char * );
int			tidbit ( char * , char * , ... );

#else

extern char		*tparm();
int			putp();
int			tidbit();

#endif

extern short		output_res_char,
			output_res_line,
			output_res_horz_inch,
			output_res_vert_inch;

/**
 ** set_size()
 **/

int
#if	defined(__STDC__)
set_size (
	char *			str,
	int			which,
	int			putout
)
#else
set_size (str, which, putout)
	char			*str;
	int			which,
				putout;
#endif
{
	static int		cleared_margins_already	= 0;

	double			size;

	int			i,
				isize,
				ret;

	short			curval,
				output_res,
				output_res_inch;

	char			*rest,
				*set_margin1,
				*set_margin2,
				*set_margin1_parm,
				*set_margin2_parm,
				*set_both_margins	= 0,
				*move1,
				*move2,
				*step2,
				*p1,
				*p2,
				*sp1,
				*sp2,
				*carriage_return,
				*parm_right_cursor,
				*column_address,
				*repeat_char,
				*cursor_right,
				*parm_down_cursor,
				*row_address,
				*cursor_down,
				*clear_margins,
				*finale,
				*slines;


	if (which == 'W') {

		tidbit ((char *)0, "cols", &curval);

		if (output_res_char == -1)
			tidbit ((char *)0, "orc", &output_res_char);
		output_res = output_res_char;

		if (output_res_horz_inch == -1)
			tidbit ((char *)0, "orhi", &output_res_horz_inch);
		output_res_inch = output_res_horz_inch;

	} else {

		tidbit ((char *)0, "lines", &curval);

		if (output_res_line == -1)
			tidbit ((char *)0, "orl", &output_res_line);
		output_res = output_res_line;

		if (output_res_vert_inch == -1)
			tidbit ((char *)0, "orvi", &output_res_vert_inch);
		output_res_inch = output_res_vert_inch;

	}

	size = strtod(str, &rest);
	if (size <= 0)
		return (E_BAD_ARGS);

	switch (*rest) {
	case ' ':
	case 0:
		break;
	case 'c':
		/*
		 * Convert to inches.
		 */
		size /= 2.54;
		/* fall through */
	case 'i':
		/*
		 * Convert to lines/columns.
		 */
		if (output_res == -1 || output_res_inch == -1)
			return (E_FAILURE);
		size *= output_res_inch / output_res;
		break;
	default:
		return (E_BAD_ARGS);
	}


	if ((isize = R(size)) == curval)
		return (E_SUCCESS);

	/*
	 * We number things 0 through N (e.g. an 80 column
	 * page is numbered 0 to 79). Thus if we are asked
	 * to set a width of 132, we set the left margin at
	 * 0 and the right at 131.
	 * Of course, if we're using the "slines" string,
	 * we give the length as N+1.
	 */
	isize--;

	/*
	 * When the width or length is set using the set-margin-at-
	 * current-position caps (e.g. smgl and smgr, smgt, smgb):
	 * If a parameterized motion capability exists, then we'll try
	 * to use it. However, if the instantiation of the capability
 	 * (through tparm()) gives nothing, assume this means the motion
	 * is not allowed--don't try the next choice. This is the only
	 * way we have of checking for a width or length beyond the
	 * limits of the printer. If a parameterized motion capability
	 * doesn't exist, we have no way to check out-of-bounds width
	 * and length, sorry.
	 *
	 * When the width or length is set using parameterized caps
	 * (e.g. smglp and smgrp, or slines for length), the above is not
	 * a problem, of course.
	 */
	if (which == 'W') {

		tidbit ((char *)0, "smgl", &set_margin1);
		tidbit ((char *)0, "smgr", &set_margin2);
		tidbit ((char *)0, "smglp", &set_margin1_parm);
		tidbit ((char *)0, "smgrp", &set_margin2_parm);
		tidbit ((char *)0, "smglr", &set_both_margins);

		tidbit ((char *)0, "cr", &carriage_return);
		tidbit ((char *)0, "cuf", &parm_right_cursor);
		tidbit ((char *)0, "hpa", &column_address);
		tidbit ((char *)0, "rep", &repeat_char);
		tidbit ((char *)0, "cuf1", &cursor_right);

		if (OKAY(carriage_return))
			move1 = carriage_return;
		else
			move1 = "\r";

		if (OKAY(parm_right_cursor)) {
			move2 = tparm(parm_right_cursor, isize);
			step2 = 0;

		} else if (OKAY(column_address)) {
			move2 = tparm(column_address, isize);
			step2 = 0;

		} else if (OKAY(repeat_char)) {
			move2 = tparm(repeat_char, ' ', isize);
			step2 = 0;

		} else if (OKAY(cursor_right)) {
			move2 = 0;
			step2 = cursor_right;

		} else {
			move2 = 0;
			step2 = " ";
		}

		finale = move1;		/* i.e. carriage return */

	} else {

		tidbit ((char *)0, "smgt", &set_margin1);
		tidbit ((char *)0, "smgb", &set_margin2);
		tidbit ((char *)0, "smgtp", &set_margin1_parm);
		tidbit ((char *)0, "smgbp", &set_margin2_parm);
		tidbit ((char *)0, "smgtb", &set_both_margins);

		/*
		 * For compatibility with SVR3.2 era Terminfo files,
		 * we check "u9" as an alias for "slines" IF a check
		 * of "slines" comes up empty.
		 */
		slines = 0; /* (in case compiled with old tidbit) */
		tidbit ((char *)0, "slines", &slines);
		if (!OKAY(slines))
			tidbit ((char *)0, "u9", &slines);

		tidbit ((char *)0, "cud", &parm_down_cursor);
		tidbit ((char *)0, "vpa", &row_address);
		tidbit ((char *)0, "cud1", &cursor_down);

		move1 = "";	/* Assume we're already at top-of-page */

		if (OKAY(parm_down_cursor)) {
			move2 = tparm(parm_down_cursor, isize);
			step2 = 0;

		} else if (OKAY(row_address)) {
			move2 = tparm(row_address, isize);
			step2 = 0;

		} else if (OKAY(cursor_down)) {
			move2 = 0;
			step2 = cursor_down;

		} else {
			move2 = 0;
			step2 = "\n";
		}

		/*
		 * This has to be smarter, but we don't have the
		 * smarts ourselves, yet; i.e. what do we do if
		 * there is no "ff"?
		 */
		tidbit ((char *)0, "ff", &finale);

	}

	/*
	 * For a short while we needed a kludge in Terminfo
	 * whereby if only one of the left/right or top/bottom
	 * parameterized margin setters was defined, it was
	 * a parm-string that could set BOTH margins. We now have
	 * separate strings for setting both margins, but we still
	 * allow the kludge.
	 */
	if (!OKAY(set_both_margins)) {
		if (OKAY(set_margin1_parm) && !OKAY(set_margin2_parm))
			set_both_margins = set_margin1_parm;
		else if (OKAY(set_margin2_parm) && !OKAY(set_margin1_parm))
			set_both_margins = set_margin2_parm;
	}

	sp1 = sp2 = 0;

	if (
		which == 'L'
	     && OKAY(slines)
	     && (p1 = tparm(slines, isize + 1))
	) {
		if (putout)
			putp (p1);
		finale = 0;
		ret = E_SUCCESS;

	} else if (
		OKAY(set_both_margins)
	     && (p1 = tparm(set_both_margins, 0, isize))
	     && *p1
	     && (sp1 = Strdup(p1))
	) {

		if (putout) {

			if (!cleared_margins_already) {
				tidbit ((char *)0, "mgc", &clear_margins);
				if (OKAY(clear_margins)) {
					cleared_margins_already = 1;
					putp (clear_margins);
				}
			}

			putp (sp1);

		}
		ret = E_SUCCESS;

	/*
	 * The "smgbp" string takes two parameters; each defines the
	 * position of the margin, the first counting lines from the top
	 * of the page, the second counting lines from the bottom of the
	 * page. This shows the flaw in using the set-margin commands
	 * for setting the page length, because BY DEFINITION the second
	 * parameter must be 0 for us. But giving 0 won't cause a change
	 * in the page length, will it!
	 *
	 * Anyway, the "smgrp" expects just one parameter (thus will
	 * ignore a second parameter) so we can safely give the second
	 * parameter without caring which of width or length we're
	 * setting.
	 */
	} else if (
		OKAY(set_margin1_parm)
	     && (p1 = tparm(set_margin1_parm, 0))
	     && *p1
	     && (sp1 = Strdup(p1))
	     && OKAY(set_margin2_parm)
	     && (p2 = tparm(set_margin2_parm, isize, 0))
	     && *p2
	     && (sp2 = Strdup(p2))
	) {

		if (putout) {

			if (!cleared_margins_already) {
				tidbit ((char *)0, "mgc", &clear_margins);
				if (OKAY(clear_margins)) {
					cleared_margins_already = 1;
					putp (clear_margins);
				}
			}

			putp (sp1);
			putp (sp2);

		}
		ret = E_SUCCESS;

	} else if (
		OKAY(set_margin1)
	     && OKAY(set_margin2)
	     && (OKAY(move2) || OKAY(step2))
	) {

		register char		*p,
					*q;

		register int		free_it = 0;

		if (putout) {

			if (!cleared_margins_already) {
				tidbit ((char *)0, "mgc", &clear_margins);
				if (OKAY(clear_margins)) {
					cleared_margins_already = 1;
					putp (clear_margins);
				}
			}

			putp (move1);
			putp (set_margin1);

			if (!move2) {
				move2 = Malloc(isize * strlen(step2) + 1);
				if (!move2)
					return (E_MALLOC);
				for (p = move2, i = 0; i < isize; i++)
					for (q = step2; *q; )
						*p++ = *q++;
				*p = 0;
				free_it = 1;
			}

			putp (move2);
			putp (set_margin2);

			if (free_it)
				Free (move2);
		}
		ret = E_SUCCESS;

	} else
		ret = E_FAILURE;

	if (putout && OKAY(finale))
		putp (finale);

	if (sp1)
		Free (sp1);
	if (sp2)
		Free (sp2);
	return (ret);
}
