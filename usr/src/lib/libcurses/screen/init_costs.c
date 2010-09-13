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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
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

#include	<stdlib.h>
#include	<sys/types.h>
#include	"curses_inc.h"

/*
 * Figure out (roughly) how much each of these capabilities costs.
 * In the parameterized cases, we just take a typical case and
 * use that value.  This is done only once at startup, since it
 * would be too expensive for intensive use.
 */

static  int 	_cost_fn(char *, int);

static	short	offsets[] = {
		    52,		/* insert_character, */
		    21,		/* delete_character, */
		    12,		/* cursor_home, */
		    18,		/* cursor_to_ll, */
		    14,		/* cursor_left, */
		    17,		/* cursor_right, */
		    11,		/* cursor_down, */
		    19,		/* cursor_up, */
		    2,		/* carriage_return, */
		    134,	/* tab, */
		    0,		/* back_tab, */
		    6,		/* clr_eol, */
		    269,	/* clr_bol, */
#define	FIRST_LOOP	13
		    108,	/* parm_ich, */
		    105,	/* parm_dch, */
		    111,	/* parm_left_cursor, */
		    114,	/* parm_up_cursor, */
		    107,	/* parm_down_cursor, */
		    112,	/* parm_right_cursor, */
#define	SECOND_LOOP	19
		};

void
_init_costs(void)
{
	short	*costptr = &(SP->term_costs.icfixed);
	char	**str_array = (char **) cur_strs;
	int	i = 0;
	char	save_xflag = xon_xoff;

	xon_xoff = 0;
/*
 * This next block of code is actually correct in that it takes into
 * account many things that wrefresh has to keep figuring in the function
 * _useidch.  Wrefresh MUST be changed (in the words of Tony Hansen) !!!
 *
 * Wrefresh has been changed (in my words -Phong Vo) !!!!
 */
	*costptr++ = ((enter_insert_mode) && (exit_insert_mode)) ?
	    _cost_fn(enter_insert_mode, 0) + _cost_fn(exit_insert_mode, 0) : 0;

	*costptr++ = ((enter_delete_mode) && (exit_delete_mode)) ?
	    _cost_fn(enter_delete_mode, 0) + _cost_fn(exit_delete_mode, 0) : 0;

	while (i < FIRST_LOOP)
		*costptr++ = _cost_fn(str_array[offsets[i++]], 1);

	while (i < SECOND_LOOP)
		*costptr++ = _cost_fn(tparm_p1(str_array[offsets[i++]], 10), 1);

	*costptr++ = _cost_fn(tparm_p2(cursor_address, 8, 10), 1);
	*costptr++ = _cost_fn(tparm_p1(row_address, 8), 1);

	xon_xoff = save_xflag;
#ifdef	DEBUG
	if (outf) {
		fprintf(outf, "icfixed %d=%d+%d\n", _COST(icfixed),
		    _cost_fn(enter_insert_mode, 0),
		    _cost_fn(exit_insert_mode, 0));
		fprintf(outf, "from ich1 %x '%s' %d\n", insert_character,
		    insert_character, _cost_fn(insert_character, 1));
		fprintf(outf, "ip %x '%s' %d\n", insert_padding,
		    insert_padding, _cost_fn(insert_padding, 1));
		fprintf(outf, "dcfixed %d\n", _COST(dcfixed));
	}
#endif	/* DEBUG */
/*FALLTHROUGH*/
}

static int counter = 0;
int
/* ARGSUSED */
_countchar(char dummy)
{
	counter++;
	return (0);
}

/*
 * Figure out the _COST in characters to print this string.
 * Due to padding, we can't just use strlen, so instead we
 * feed it through tputs and trap the results.
 * Even if the terminal uses xon/xoff handshaking, count the
 * pad chars here since they estimate the real time to do the
 * operation, useful in calculating costs.
 */

static int
_cost_fn(char *str, int affcnt)
{
	if (str == NULL)
		return (LARGECOST);
	counter = 0;
	(void) tputs(str, affcnt, _countchar);
	return (counter);
}
