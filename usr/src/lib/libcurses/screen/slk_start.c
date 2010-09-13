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

#include	<sys/types.h>
#include	<stdlib.h>
#include	"curses_inc.h"

/*
 * Initialize usage of soft labels
 * This routine should be called before each call of newscreen
 * or initscr to initialize for the next terminal.
 *
 * ng:	number of groupings. If gp is NULL, it denotes one
 * 	of two default groupings:
 * 	0:	- - -   - -   - - -
 * 	1:      - - - -     - - - -
 * gp:	groupings.
 */

static	void	_init_slk_func(void);
static  int	_slk_setpos(int, short *);
static	int	_ngroups, _groups[LABMAX];

int
slk_start(int ng, int *gp)
{
	int	i = 0, j = 0;

	if (gp == NULL) {
		switch (ng) {
			case 2 :
				_ngroups = 2;
				_groups[0] = 4;
				_groups[1] = 4;
				break;

			case 3 :
no_format :
				_ngroups = 3;
				_groups[0] = 3;
				_groups[1] = 2;
				_groups[2] = 3;
				break;

			default :
				if (label_format) {
				    int		k;
				    char	ch1[3], *ch = label_format;

					/*CONSTCOND*/
					while (TRUE) {
						if ((*ch == ',') ||
						    (*ch == '\0')) {
							ch1[i] = '\0';
							if ((k = atoi(ch1)) <=
							    0)
								goto err;
							_groups[j++] = k;
							i = 0;
							if (*ch == '\0') {
								break;
							}
						} else
							ch1[i++] = *ch++;
					}
				} else
					goto no_format;
				break;
		}
	} else {
		for (; i < ng; i++) {
			if ((j += gp[i]) > LABMAX)
err :
				return (ERR);
			_groups[i] = gp[i];
		}
		_ngroups = ng;
	}

	/* signal newscreen() */
	_slk_init = _init_slk_func;
	return (OK);
}

static	void
_init_slk_func(void)
{
	int	i, len, num;
	SLK_MAP	*slk;
	char	*cp, *ep;
	WINDOW	*win;

	/* clear this out to ready for next time */
	_slk_init = NULL;

	/* get space for slk structure */
	if ((slk = (SLK_MAP *) malloc(sizeof (SLK_MAP))) == NULL) {
		curs_errno = CURS_BAD_MALLOC;
#ifdef	DEBUG
		strcpy(curs_parm_err, "_init_slk_func");
#endif	/* DEBUG */
		return;
	}

	/* compute actual number of labels */
	num = 0;
	for (i = 0; i < _ngroups; i++)
		num += _groups[i];

	/* max label length */
	if (plab_norm && (label_height * label_width >= LABLEN) &&
	    (num_labels >= num)) {
		win = NULL;
		goto next;
	} else {
		if ((win = newwin(1, COLS, LINES - 1, 0)) == NULL)
			goto err;
		win->_leave = TRUE;
		(void) wattrset(win, A_REVERSE | A_DIM);

		/* remove one line from the screen */
		LINES = --SP->lsize;
		if ((len = (COLS - 1) / (num + 1)) > LABLEN) {
next :
			len = LABLEN;
		}
	}

	/* positions to place labels */
	if (len <= 0 || num <= 0 || (_slk_setpos(len, slk->_labx) == ERR)) {
		if (win != NULL)
			(void) delwin(win);
err :
		free(slk);
	} else {
		/* LINTED */
		slk->_num = (short) num;
		/* LINTED */
		slk->_len = (short) len;

		for (i = 0; i < num; ++i) {
			cp = slk->_ldis[i];
			ep = cp + len;
			for (; cp < ep; ++cp)
				*cp = ' ';
			*ep = '\0';
			slk->_lval[i][0] = '\0';
			slk->_lch[i] = TRUE;
		}

		slk->_changed = TRUE;
		slk->_win = win;

		_do_slk_ref = _slk_update;
		_do_slk_tch = slk_touch;
		_do_slk_noref = slk_noutrefresh;

		SP->slk = slk;
	}
}


/*
 * Compute placements of labels. The general idea is to spread
 * the groups out evenly. This routine is designed for the day
 * when > 8 labels and other kinds of groupings may be desired.
 *
 * The main assumption behind the algorithm is that the total
 * # of labels in all the groups is <= LABMAX.
 *
 * len: length of a label
 * labx: to return the coords of the labels.
 */

static int
_slk_setpos(int len, short *labx)
{
	int	i, k, n, spread, left, begadd;
	int	grpx[LABMAX];

	/* compute starting coords for each group */
	grpx[0] = 0;
	if (_ngroups > 1) {
		/* spacing between groups */
		for (i = 0, n = 0; i < _ngroups; ++i)
			n += _groups[i] * (len + 1) - 1;
		if ((spread = (COLS - (n + 1))/(_ngroups - 1)) <= 0)
			return (ERR);
		left = (COLS-(n + 1)) % (_ngroups - 1);
		begadd = (_ngroups / 2) - (left / 2);

		/* coords of groups */
		for (i = 1; i < _ngroups; ++i) {
			grpx[i] = grpx[i - 1] + (_groups[i - 1] *
			    (len + 1) - 1) + spread;
			if (left > 0 && i > begadd) {
				grpx[i]++;
				left--;
			}
		}
	}

	/* now set coords of each label */
	n = 0;
	for (i = 0; i < _ngroups; ++i)
		for (k = 0; k < _groups[i]; ++k)
			labx[n++] = grpx[i] + k * (len + 1);
	return (OK);
}
