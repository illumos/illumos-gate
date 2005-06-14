/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#ifndef lint
static char
sccsid[] = "@(#)newwin.c 1.7 89/07/13 SMI"; /* from UCB 5.1 85/06/07 */
#endif	/* not lint */

/*
 * allocate space for and set up defaults for a new window
 *
 */

#include	"curses.ext"
#include 	<malloc.h>

#define	SMALLOC	(short *)malloc

/* forward declaration */
static WINDOW *makenew(int, int, int, int);

#undef		nl	/* don't need it here, and it interferes	*/

WINDOW *
newwin(int num_lines, int num_cols, int begy, int begx)
{
	WINDOW	*win;
	char	*sp;
	int	i, by, bx, nl, nc;
	int	j;

	by = begy;
	bx = begx;
	nl = num_lines;
	nc = num_cols;

	if (nl == 0)
		nl = LINES - by;
	if (nc == 0)
		nc = COLS - bx;
	if ((win = makenew(nl, nc, by, bx)) == NULL)
		return (ERR);
	if ((win->_firstch = SMALLOC(nl * sizeof (win->_firstch[0]))) == NULL) {
		free(win->_y);
		free(win);
		return (NULL);
	}
	if ((win->_lastch = SMALLOC(nl * sizeof (win->_lastch[0]))) == NULL) {
		free(win->_y);
		free(win->_firstch);
		free(win);
		return (NULL);
	}
	win->_nextp = win;
	for (i = 0; i < nl; i++) {
		win->_firstch[i] = _NOCHANGE;
		win->_lastch[i] = _NOCHANGE;
	}
	for (i = 0; i < nl; i++)
		if ((win->_y[i] = malloc(nc * sizeof (win->_y[0]))) == NULL) {
			for (j = 0; j < i; j++)
				free(win->_y[j]);
			free(win->_firstch);
			free(win->_lastch);
			free(win->_y);
			free(win);
			return (ERR);
		}
		else
			for (sp = win->_y[i]; sp < win->_y[i] + nc; )
				*sp++ = ' ';
	win->_ch_off = 0;
#ifdef DEBUG
	fprintf(outf, "NEWWIN: win->_ch_off = %d\n", win->_ch_off);
#endif
	return (win);
}

WINDOW *
subwin(WINDOW *orig, int num_lines, int num_cols, int begy, int begx)
{
	WINDOW	*win;
	int	by, bx, nl, nc;

	by = begy;
	bx = begx;
	nl = num_lines;
	nc = num_cols;

	/*
	 * make sure window fits inside the original one
	 */
#ifdef	DEBUG
	fprintf(outf, "SUBWIN(%0.2o, %d, %d, %d, %d)\n", orig, nl, nc, by, bx);
#endif
	if (by < orig->_begy || bx < orig->_begx ||
	    by + nl > orig->_maxy + orig->_begy ||
	    bx + nc > orig->_maxx + orig->_begx)
		return (ERR);
	if (nl == 0)
		nl = orig->_maxy + orig->_begy - by;
	if (nc == 0)
		nc = orig->_maxx + orig->_begx - bx;
	if ((win = makenew(nl, nc, by, bx)) == NULL)
		return (ERR);
	win->_nextp = orig->_nextp;
	orig->_nextp = win;
	win->_orig = orig;
	_set_subwin_(orig, win);
	return (win);
}

/*
 * this code is shared with mvwin()
 */

void
_set_subwin_(WINDOW *orig, WINDOW *win)
{
	int	i, j, k;

	j = win->_begy - orig->_begy;
	k = win->_begx - orig->_begx;
	win->_ch_off = (short)k;
#ifdef DEBUG
	fprintf(outf, "_SET_SUBWIN_: win->_ch_off = %d\n", win->_ch_off);
#endif
	win->_firstch = &orig->_firstch[j];
	win->_lastch = &orig->_lastch[j];
	for (i = 0; i < win->_maxy; i++, j++)
		win->_y[i] = &orig->_y[j][k];

}

/*
 *	This routine sets up a window buffer and returns a pointer to it.
 */

static WINDOW *
makenew(int num_lines, int num_cols, int begy, int begx)
{
	WINDOW	*win;
	int	by, bx, nl, nc;

	by = begy;
	bx = begx;
	nl = num_lines;
	nc = num_cols;

#ifdef	DEBUG
	fprintf(outf, "MAKENEW(%d, %d, %d, %d)\n", nl, nc, by, bx);
#endif
	if ((win = (WINDOW *) malloc(sizeof (*win))) == NULL)
		return (NULL);
#ifdef DEBUG
	fprintf(outf, "MAKENEW: nl = %d\n", nl);
#endif
	if ((win->_y = (char **)malloc(nl * sizeof (win->_y[0]))) == NULL) {
		free(win);
		return (NULL);
	}
#ifdef DEBUG
	fprintf(outf, "MAKENEW: nc = %d\n", nc);
#endif
	win->_cury = win->_curx = 0;
	win->_clear = FALSE;
	win->_maxy = (short)nl;
	win->_maxx = (short)nc;
	win->_begy = (short)by;
	win->_begx = (short)bx;
	win->_flags = 0;
	win->_scroll = win->_leave = FALSE;
	_swflags_(win);
	win->_orig = NULL;
#ifdef DEBUG
	fprintf(outf, "MAKENEW: win->_clear = %d\n", win->_clear);
	fprintf(outf, "MAKENEW: win->_leave = %d\n", win->_leave);
	fprintf(outf, "MAKENEW: win->_scroll = %d\n", win->_scroll);
	fprintf(outf, "MAKENEW: win->_flags = %0.2o\n", win->_flags);
	fprintf(outf, "MAKENEW: win->_maxy = %d\n", win->_maxy);
	fprintf(outf, "MAKENEW: win->_maxx = %d\n", win->_maxx);
	fprintf(outf, "MAKENEW: win->_begy = %d\n", win->_begy);
	fprintf(outf, "MAKENEW: win->_begx = %d\n", win->_begx);
#endif
	return (win);
}

void
_swflags_(WINDOW *win)
{
	win->_flags &= ~(_ENDLINE|_FULLLINE|_FULLWIN|_SCROLLWIN);
	if (win->_begx + win->_maxx == COLS) {
		win->_flags |= _ENDLINE;
		if (win->_begx == 0) {
			if (AL && DL)
				win->_flags |= _FULLLINE;
			if (win->_maxy == LINES && win->_begy == 0)
				win->_flags |= _FULLWIN;
		}
		if (win->_begy + win->_maxy == LINES)
			win->_flags |= _SCROLLWIN;
	}
}
