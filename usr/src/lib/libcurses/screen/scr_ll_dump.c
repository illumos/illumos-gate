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

#include	"curses_inc.h"
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<unistd.h>

int
scr_ll_dump(FILE *filep)
{
	short	magic = SVR3_DUMP_MAGIC_NUMBER, rv = ERR;
	char	*thistty;
	SLK_MAP	*slk = SP->slk;
	struct	stat	statbuf;

	if (fwrite((char *) &magic, sizeof (short), 1, filep) != 1)
		goto err;

	/* write term name and modification time */
	if ((thistty = ttyname(cur_term->Filedes)) == NULL)
		statbuf.st_mtime = 0;
	else
		(void) stat(thistty, &statbuf);

	if (fwrite((char *) &(statbuf.st_mtime), sizeof (time_t),
	    1, filep) != 1)
		goto err;

	/* write curscr */
	if (_INPUTPENDING)
		(void) force_doupdate();
	if (putwin(curscr, filep) == ERR)
		goto err;

	/* next output: 0 no slk, 1 hardware slk, 2 simulated slk */

	magic = (!slk) ? 0 : (slk->_win) ? 2 : 1;
	if (fwrite((char *) &magic, sizeof (int), 1, filep) != 1)
		goto err;
	if (magic) {
		short	i, labmax = slk->_num, lablen = slk->_len + 1;

		/* output the soft labels themselves */
		if ((fwrite((char *) &labmax,
		    sizeof (short), 1, filep) != 1) ||
		    (fwrite((char *) &lablen, sizeof (short),
		    1, filep) != 1)) {
			goto err;
		}
		for (i = 0; i < labmax; i++)
			if ((fwrite(slk->_ldis[i], sizeof (char), lablen,
			    filep) != lablen) || (fwrite(slk->_lval[i],
			    sizeof (char), lablen, filep) != lablen)) {
				goto err;
			}
	}

	/* now write information about colors.  Use the following format. */
	/* Line 1 is mandatory, the remaining lines are required only if  */
	/* line one is 1.						  */
	/* line 1: 0 (no colors) or 1 (colors)				  */
	/* line 2: number of colors, number of color pairs, can_change	  */
	/* X lines: Contents of colors (r, g, b)			  */
	/* Y lines: Contents of color-pairs				  */

	magic = ((cur_term->_pairs_tbl) ? 1 : 0);
	if (fwrite((char *) &magic, sizeof (int), 1, filep) != 1)
		goto err;
	if (magic) {
		/* number of colors and color_pairs	*/
		if ((fwrite((char *) &COLORS, sizeof (int), 1, filep) != 1) ||
		    (fwrite((char *) &COLOR_PAIRS, sizeof (int), 1, filep) !=
		    1) || (fwrite((char *) &can_change, sizeof (char), 1,
		    filep) != 1))
			goto err;

		/* contents of color_table		*/

		if (can_change) {
			if (fwrite((char *) &(cur_term->_color_tbl->r),
			    sizeof (_Color), COLORS, filep) != COLORS)
				goto err;
		}

		/* contents of pairs_table		*/

		if (fwrite((char *) &(cur_term->_pairs_tbl->foreground),
		    sizeof (_Color_pair), COLOR_PAIRS, filep) != COLOR_PAIRS)
			goto err;
	}

	/* success */
	rv = OK;
err :
	return (rv);
}
