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
 * Copyright (c) 1995-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

/*
 * doupdate.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char const rcsID[] =
"$Header: /team/ps/sun_xcurses/archive/local_changes/xcurses/src/lib/"
"libxcurses/src/libc/xcurses/rcs/doupdate.c 1.22 1998/06/04 12:13:38 "
"cbates Exp $";
#endif
#endif

#include <sys/isa_defs.h>
#include <private.h>
#include <string.h>
#include <signal.h>

#undef SIGTSTP

/*
 * This value is the ideal length for the cursor addressing sequence
 * being four bytes long, ie. "<escape><cursor addressing code><row><col>".
 * eg. VT52 - "\EYrc" or ADM3A - "\E=rc"
 */
#define	JUMP_SIZE	4

/*
 * This value is the ideal length for the clear-to-eol sequence
 * being two bytes long, ie "<escape><clear eol code>".
 */
#define	CEOL_SIZE	2

#define	GOTO(r, c)	((void) __m_mvcur(curscr->_cury, curscr->_curx,\
	r, c, __m_outc), curscr->_cury = r, curscr->_curx = c)

typedef struct cost_op {
	short	cost;
	short	op;
} lcost;

typedef void (*t_action)(int, int);


#define	LC(i, j) 	(lc[(i) * (LINES + 1) + (j)])

static lcost *lc = NULL;
#if defined(_LP64)
static unsigned int	*nhash = NULL;
#else
static unsigned long	*nhash = NULL;
#endif
static t_action *del = NULL;
static t_action *ins_rep = NULL;

static WINDOW	*newscr;

static void erase_bottom(int, int);
static void clear_bottom(int);
static void complex(void);
static int cost(int, int);
static void lines_delete(int, int);
static void lines_insert(int, int);
static void lines_replace(int, int);
static void script(int, int);
static int scroll_up(int);
static void simple(void);
static void text_replace(int);
#if 0
static int scroll_dn(int);
#endif


/*
 * Wrapper that streams Curses output.
 *
 * All escape sequences going to the screen come through here.
 * All ordinary characters go to the screen via the putc in doupdate.c
 */
int
__m_outc(int ch)
{
	return (putc(ch, __m_screen->_of));
}

/*
 * Allocate or grow doupdate() structures.
 */
int
__m_doupdate_init(void)
{
	void	*new;
	static short	nlines = 0;

	if (lines <= 0)
		return (-1);

	if (lines <= nlines)
		return (0);

	new = malloc((lines + 1) * (lines + 1) * sizeof (*lc));
	if (new == NULL)
		return (-1);
	if (lc != NULL)
		free(lc);
	lc = (lcost *) new;

	new = malloc((lines + lines) * sizeof (*del));
	if (new == NULL)
		return (-1);
	if (del != NULL)
		free(del);
	del = (t_action *) new;
	ins_rep = del + lines;

	new = malloc(lines * sizeof (*nhash));
	if (new == NULL)
		return (-1);
	if (nhash != NULL)
		free(nhash);
#if defined(_LP64)
	nhash = (unsigned int *) new;
#else
	nhash = (unsigned long *) new;
#endif

	nlines = lines;

	return (0);
}

static void
erase_bottom(int start, int end)
{
	int i;

	for (i = start; i < end; ++i) {
		(void) __m_cc_erase(curscr, i, 0, i, curscr->_maxx - 1);
		__m_cc_hash(curscr, __m_screen->_hash, i);
	}
}

/*
 *  Clear from the start of the current row to bottom of screen.
 */
static void
clear_bottom(int y)
{
	/* Restore default color pair before doing area clears. */
	if (back_color_erase)
		(void) vid_puts(WA_NORMAL, 0, (void *) 0, __m_outc);

	if (y == 0 && clear_screen != NULL) {
		(void) TPUTS(clear_screen, 1, __m_outc);
	} else {
		(void) __m_mvcur(-1, -1, y, 0, __m_outc);
		if (clr_eos != NULL) {
			(void) TPUTS(clr_eos, 1, __m_outc);
		} else if (clr_eol != NULL) {
			for (;;) {
				(void) TPUTS(clr_eol, 1, __m_outc);
				if (LINES <= y)
					break;
				(void) __m_mvcur(y, 0, y + 1, 0, __m_outc);
				++y;
			}
		}
	}

	curscr->_cury = y;
	curscr->_curx = 0;
}



/*
 * Rewrite of text_replace() implementation by C. Bates of MKS
 *
 * This code creates a list of 'regions' for each test line which
 * is to be replaced. Each region describes a portion of the line.
 * Logic is performed on the list of regions, then the regions
 * are used to generate output.
 */
typedef	struct LineRegion {
	int	col;	/* Starting column of region */
	int	size;	/* Size of region */
	/* 0: Difference Region, 1: Common Region, 2: Delete Region */
	int	type;
} LineRegion;
#define	REGION_DIFFERENT	0
#define	REGION_COMMON		1
#define	REGION_DELETE		2

#define	DELETE_SEARCH_LIMIT	4
#define	DELETE_THRESHOLD	10

static LineRegion	regions[1024];
int	nRegions = 0;

/*
 * Return the first column of the completely blank End-of-line
 */
static int
_find_blank_tail(int row)
{
	cchar_t	*nptr;
	int	tail = COLS;

	if (!clr_eol)
		return (COLS);
	/*
	 * Find start of blank tail region.
	 */
	nptr = &newscr->_line[row][COLS];
	for (; 0 < tail; --tail) {
		if (!__m_cc_compare(--nptr, &newscr->_bg, 1))
			break;
	}
	return (tail);
}

/*
 * Send all the characters in the region to the terminal
 */
static void
_writeRegion(int row, LineRegion region)
{
	short	npair;
	attr_t	nattr;
	int	i;
	cchar_t	*optr = &curscr->_line[row][region.col];
	cchar_t	*nptr = &newscr->_line[row][region.col];

	for (i = 0; i < region.size; i++, nptr++, optr++) {
		nattr = nptr->_at;
		npair = nptr->_co;

		/*
		 * Change attribute state.
		 */
		if ((ATTR_STATE != nattr) || (optr->_at != nattr) ||
			(cur_term->_co != npair)) {
			(void) vid_puts(nattr, npair, NULL, __m_outc);
		}
		/*
		 * Don't display internal characters.
		 */
		if (nptr->_f)
			(void) __m_cc_write(nptr);

		/*
		 * Update copy of screen image.
		 */
		*optr = *nptr;
		curscr->_curx = region.col + i + 1;
	}
}

/*
 * Delete some characters from the terminal for this region
 */
static void
_deleteRegion(int row, LineRegion region)
{
	int	i;
	cchar_t	*optr = &curscr->_line[row][region.col];

	if ((region.size <= 1) || !parm_dch) {
		for (i = 0; i < region.size; i++)
			(void) TPUTS(delete_character, 1, __m_outc);
	} else {
		(void) TPUTS(tparm(parm_dch, (long)region.size,
			0, 0, 0, 0, 0, 0, 0, 0), region.size, __m_outc);
	}
	for (i = region.col; i < COLS - region.size; i++) {
		/*
		 * Delete the chars in the image of the real screen
		 */
		*optr = *(optr + region.size);
		optr++;
	}
}

/*
 * Use clr_eol control if possible
 */
static void
_clearToEOL(int row, int tail)
{
	if (tail < COLS) {
		GOTO(row, tail);
		/*
		 * Restore default color pair before area clear.
		 */
		if (back_color_erase)
			(void) vid_puts(WA_NORMAL, 0, NULL, __m_outc);

		(void) TPUTS(clr_eol, 1, __m_outc);
		(void) __m_cc_erase(curscr, row, tail, row, COLS - 1);
	}
}

/*
 * Delete leading common region
 */
static void
_normalizeRegions1(void)
{
	int	iRegion;

	/*
	 * Delete leading common region
	 */
	if (regions[0].type == REGION_COMMON) {
		nRegions--;
		for (iRegion = 0; iRegion < nRegions; iRegion++) {
			regions[iRegion] = regions[iRegion + 1];
		}
	}
}

/*
 * Give each region a size, then delete all trailing common regions
 */
static void
_normalizeRegions2(void)
{
	int	iRegion;

	for (iRegion = 0; iRegion < nRegions - 1; iRegion++) {
		regions[iRegion].size = regions[iRegion + 1].col -
			regions[iRegion].col;
	}
	regions[nRegions - 1].size = COLS - regions[nRegions - 1].col;

	/*
	 * Delete trailing common regions
	 */
	while (regions[nRegions - 1].type == REGION_COMMON)
		nRegions--;
}

/*
 * Tiny common regions are merged into adjacent difference regions
 */
static void
_mergeTinyRegions(void)
{
	int	from;
	int	to;
	for (from = 1, to = 1; from < nRegions; ) {
		if ((regions[from].type == REGION_COMMON) &&
			(regions[from].size < JUMP_SIZE)) {
			/*
			 * Merge out tiny common regions
			 */
			regions[to - 1].size += regions[from].size;
			/*
			 * Now join adjacent non-common regions
			 */
			if (++from < nRegions)
				regions[to - 1].size += regions[from++].size;
		} else {
			regions[to++] = regions[from++];
		}
	}
	nRegions = to;
}

/*
 * Create the initial list of regions for this row
 */
static int
_findRegions(int row)
{
	int	cmp;
	int	old_cmp;
	int	col;
	int	bestDeleteCount;
	cchar_t	*nptr = &newscr->_line[row][0];
	cchar_t	*optr = &curscr->_line[row][0];

	col = 0;
	nRegions = 0;
	bestDeleteCount = 0;
	if ((__m_screen->_flags & S_INS_DEL_CHAR) &&
		(parm_dch || delete_character)) {
		int	bestFit = 0;
		int	deletePoint;
		int	deleteCount;
		int	matches;

		/*
		 * Skip to first difference
		 */
		for (col = 0; col < COLS; col++) {
			if (!__m_cc_compare(&optr[col], &nptr[col], 1))
				break;
		}
		deletePoint = col;
		for (deleteCount = 1; deleteCount < DELETE_SEARCH_LIMIT;
			deleteCount++) {
			matches = 0;
			for (col = deletePoint; col < COLS - deleteCount;
				col++) {
				if (__m_cc_compare(&optr[col + deleteCount],
					&nptr[col], 1))
					matches++;
				else
					break;
			}
			if (matches > bestFit) {
				bestFit = matches;
				bestDeleteCount = deleteCount;
			}
		}
		if (bestFit > DELETE_THRESHOLD) {
			regions[nRegions].type = REGION_DELETE;
			regions[nRegions].col = deletePoint;
			regions[nRegions].size = bestDeleteCount;
			nRegions++;
			col = deletePoint + bestDeleteCount;
		} else {
			col = 0;
			nRegions = 0;
			/* Forget trying to use character delete */
			bestDeleteCount = 0;
		}
	}
	for (old_cmp = -1; col + bestDeleteCount < COLS; col++) {
		cmp = __m_cc_compare(&optr[col + bestDeleteCount],
			&nptr[col], 1);
		if (cmp != old_cmp) {
			regions[nRegions].type = cmp ? REGION_COMMON :
				REGION_DIFFERENT;
			regions[nRegions].col = col;
			regions[nRegions].size = 0;	/* Determine later */
			nRegions++;
			old_cmp = cmp;
		}
	}
	if (bestDeleteCount) {
		/*
		 * Force update of end-of-line if delete is to be used
		 */
		regions[nRegions].type = REGION_DIFFERENT;
		regions[nRegions].col = col;
		regions[nRegions].size = 0;	/* Determine later */
		nRegions++;
	}
	_normalizeRegions1();
	if (nRegions == 0)
		return (0);		/* No difference regions */

	_normalizeRegions2();
	return (1);
}

/*
 * Determine if Clr-EOL optimization can be used, and
 * adjust regions accordingly
 */
static int
_ceolAdjustRegions(int row)
{
	int	iRegion;
	int	blankEolStart = _find_blank_tail(row);

	for (iRegion = 0; iRegion < nRegions; iRegion++) {
		switch (regions[iRegion].type) {
		case REGION_DIFFERENT:
			if (regions[iRegion].col >= blankEolStart) {
				/*
				 * Delete this and all following regions
				 */
				nRegions = iRegion;
				return (blankEolStart);
			}
			if (regions[iRegion].col + regions[iRegion].size >
				blankEolStart) {
				/*
				 * Truncate this region to end
				 * where blank EOL starts
				 */
				regions[iRegion].size = blankEolStart -
					regions[iRegion].col;
				/*
				 * Delete all following regions
				 */
				nRegions = iRegion + 1;
				return (blankEolStart);
			}
			break;
		case REGION_COMMON:
			break;
		case REGION_DELETE:		/* Scrap the whole thing */
			return (COLS);
		}
	}
	return (COLS);	/* Couldn't use Clear EOL optimization */
}

/*
 * Generate output, based on region list
 */
static void
_updateRegions(int row)
{
	int	ceolStart;
	int	iRegion;

	ceolStart = _ceolAdjustRegions(row);

	/*
	 * regions are guaranteed to start with a non-common region.
	 * tiny common regions have also been merged into
	 * bracketting common-regions.
	 */
	if (nRegions) {
		for (iRegion = 0; iRegion < nRegions; iRegion++) {
			switch (regions[iRegion].type) {
			case REGION_COMMON:
				break;
			case REGION_DELETE:
				/*
				 * Start of non-common region
				 */
				GOTO(row, regions[iRegion].col);
				_deleteRegion(row, regions[iRegion]);
				break;
			case REGION_DIFFERENT:
				/*
				 * Star of non-common region
				 */
				GOTO(row, regions[iRegion].col);
				_writeRegion(row, regions[iRegion]);
				break;
			}
		}
	}
	if (ceolStart != COLS) {
		_clearToEOL(row, ceolStart);
	}
}

/*
 * The new text_replace algorithm, which uses regions
 */
static void
text_replace(int row)
{
	if (!_findRegions(row))
		return;
	_mergeTinyRegions();
	_updateRegions(row);

	/*
	 * Line wrapping checks.
	 */
	if (COLS <= curscr->_curx) {
		--curscr->_curx;
		if (auto_right_margin && (row < LINES - 1)) {
			if (eat_newline_glitch) {
				(void) __m_outc('\r');
				(void) __m_outc('\n');
			}
			++curscr->_cury;
			curscr->_curx = 0;
		}
	}
}

/*
 * Replace a block of lines.
 * Only ever used for complex().
 */
static void
lines_replace(int from, int to_1)
{
	for (; from < to_1; ++from)
		text_replace(from);
}

/*
 * Delete a block of lines.
 * Only ever used for complex().
 */
static void
lines_delete(int from, int to_1)
{
	int count = to_1 - from;

	if (LINES <= to_1) {
		erase_bottom(from, LINES);
		clear_bottom(from);
	} else {
		GOTO(from, 0);
		(void) winsdelln(curscr, -count);

		if (parm_delete_line != NULL) {
			/*
			 * Assume that the sequence to delete more than one
			 * line is faster than repeated single delete_lines.
			 */
			(void) TPUTS(tparm(parm_delete_line, (long)count,
				0, 0, 0, 0, 0, 0, 0, 0), count, __m_outc);
		} else if (delete_line != NULL) {
			while (from++ < to_1)
				(void) TPUTS(delete_line, 1, __m_outc);
		} else  {
			/* Error -- what to do. */
			return;
		}
	}
}

/*
 * Insert a block of lines.
 * Only ever used for complex().
 *
 * We must assume that insert_line and parm_insert_line reset the
 * cursor column to zero.  Therefore it is text_replace() responsiblity
 * to move the cursor to the correct column to begin the update.
 */
static void
lines_insert(int from, int to_1)
{
	int	row;
	int	count = to_1 - from;

	/*
	 * Position the cursor and insert a block of lines into the screen
	 * image now, insert lines into the physical screen, then draw the
	 * new screen lines.
	 */
	GOTO(from, 0);
	(void) winsdelln(curscr, count);

	if (parm_insert_line != NULL) {
		/*
		 * Assume that the sequence to insert more than one line is
		 * faster than repeated single insert_lines.
		 */
		(void) TPUTS(tparm(parm_insert_line, (long)count,
			0, 0, 0, 0, 0, 0, 0, 0), count, __m_outc);
	} else if (insert_line != NULL) {
		/*
		 * For the single line insert we use to iterate moving
		 * the cursor, inserting, and then drawing a line.  That
		 * would appear to be slow but visually appealing.  However,
		 * people on slow terminals want speed and those on fast
		 * terminal won't see it.
		 */
		for (row = from; row < to_1; ++row)
			(void) TPUTS(insert_line, 1, __m_outc);
	} else {
		/* Error -- what to do. */
		return;
	}

	for (row = from; row < to_1; ++row)
		text_replace(row);
}

static int
scroll_up(int n)
{
	int	count = n;
	int	start, finish, to;

	if (scroll_forward != NULL) {
		GOTO(LINES-1, 0);
		while (0 < n--)
			(void) TPUTS(scroll_forward, 1, __m_outc);
	} else if (parm_delete_line != NULL && 1 < n) {
		GOTO(0, 0);
		(void) TPUTS(tparm(parm_delete_line, (long)n,
			0, 0, 0, 0, 0, 0, 0, 0), n, __m_outc);
	} else if (delete_line != NULL) {
		GOTO(0, 0);
		while (0 < n--)
			(void) TPUTS(delete_line, 1, __m_outc);
	} else {
		return (0);
	}

	/* Scroll recorded image. */
	start = 0;
	finish = count-1;
	to = lines;

	(void) __m_cc_erase(curscr, start, 0, finish, curscr->_maxx-1);
	(void) __m_ptr_move((void **) curscr->_line,
		curscr->_maxy, start, finish, to);

	simple();

	return (1);
}

#if 0
static int
scroll_dn(int n)
{
	int	count = n;
	int	start, finish, to;

	if (LINES < n)
		return (0);

	if (scroll_reverse != NULL) {
		GOTO(0, 0);
		while (0 < n--)
			(void) TPUTS(scroll_reverse, 1, __m_outc);
	} else if (parm_insert_line != NULL && 1 < n) {
		GOTO(0, 0);
		(void) TPUTS(tparm(parm_insert_line, (long)n,
			0, 0, 0, 0, 0, 0, 0, 0), n, __m_outc);
	} else if (insert_line != NULL) {
		GOTO(0, 0);
		while (0 < n--)
			(void) TPUTS(insert_line, 1, __m_outc);
	} else {
		return (0);
	}

	/* Scroll recorded image. */
	start = lines - count;
	finish = lines - 1;
	to = 0;

	(void) __m_cc_erase(curscr, start, 0, finish, curscr->_maxx-1);
	(void) __m_ptr_move((void **) curscr->_line,
		curscr->_maxy, start, finish, to);

	simple();

	return (1);
}
#endif

/*
 * Dynamic programming algorithm for the string edit problem.
 *
 * This is a modified Gosling cost algorithm that takes into account
 * null/move operations.
 *
 * Costs for move, delete, replace, and insert are 0, 1, 2, and 3
 * repectively.
 */
#define	MOVE_COST	0
#define	REPLACE_COST	10
#define	INSERT_COST	12
#define	DELETE_COST	1

static int
cost(int fr, int lr)
{
	lcost	*lcp;
	int	or, nr, cc;
#if defined(_LP64)
	unsigned int	*ohash = __m_screen->_hash;
#else
	unsigned long	*ohash = __m_screen->_hash;
#endif

	/*
	 * Prepare initial row and column of cost matrix.
	 *
	 *	0 3 6 9 ...
	 *	1
	 *	2
	 *	3
	 *	:
	 */
	LC(fr, fr).cost = MOVE_COST;
	for (cc = 1, ++lr, nr = fr+1; nr <= lr; ++nr, ++cc) {
		/* Top row is 3, 6, 9, ... */
		LC(fr, nr).cost = cc * INSERT_COST;
		LC(fr, nr).op = 'i';

		/* Left column is 1, 2, 3, ... */
		LC(nr, fr).cost = cc * DELETE_COST;
		LC(nr, fr).op = 'd';
	}

	for (--lr, or = fr; or <= lr; ++or) {
		for (nr = fr; nr <= lr; ++nr) {
			lcp = &LC(or + 1, nr + 1);

			/* Assume move op. */
			lcp->cost = LC(or, nr).cost;
			lcp->op = 'm';

			if (ohash[or] != nhash[nr]) {
				/* Lines are different, assume replace op. */
				lcp->cost += REPLACE_COST;
				lcp->op = 'r';
			}

			/* Compare insert op. */
			if ((cc = LC(or + 1, nr).cost + INSERT_COST) <
				lcp->cost) {
				lcp->cost = cc;
				lcp->op = 'i';
			}

			/* Compare delete op. */
			if ((cc = LC(or, nr + 1).cost + DELETE_COST) <
				lcp->cost) {
				lcp->cost = cc;
				lcp->op = 'd';
			}
		}
	}

	return (LC(lr + 1, lr + 1).cost);
}

/*
 * Build edit script.
 *
 * Normally this would be a recursve routine doing the deletes, inserts,
 * and replaces on individual lines. Instead we build the script so that
 * we can later do the operations on a block basis.  For terminals with
 * parm_delete or parm_insert strings this will be better in terms of the
 * number of characters sent to delete and insert a block of lines.
 *
 * Also we can optimize the script so that tail inserts become replaces.
 * This saves unnecessary inserts operations when the tail can just be
 * overwritten.
 */
static void
script(int fr, int lr)
{
	int	i, j;
	cchar_t	*cp;

	i = j = lr + 1;

	(void) memset(del, 0, sizeof (*del) * LINES);
	(void) memset(ins_rep, 0, sizeof (*ins_rep) * LINES);

	do {
		/*
		 * We don't have to bounds check i or j becuase row fr and
		 * column fr of lc have been preset in order to guarantee the
		 * correct motion.
		 */
		switch (LC(i, j).op) {
		case 'i':
			--j;
			ins_rep[j] = lines_insert;
			break;
		case 'd':
			--i;
			del[i] = lines_delete;
			break;
		case 'm':
			--i;
			--j;
			break;
		case 'r':
			--i;
			--j;
			ins_rep[j] = lines_replace;
			break;
		}
	} while (fr < i || fr < j);

	/* Optimize Tail Inserts */
	for (i = LINES-1; 0 <= i && ins_rep[i] == lines_insert; --i) {
		/* Make each character in the screen line image invalid. */
		for (cp = curscr->_line[i], j = 0; j < COLS; ++j, ++cp)
			cp->_n = -1;
		ins_rep[i] = lines_replace;
	}
}

/*
 * Complex update algorithm using insert/delete line operations.
 *
 * References:
 * [MyM86]	E.W. Myers & W. Miller, Row Replacement Algorithms for
 *		Screen Editors, TR 86-19, Dept. Computer Science, U. of Arizona
 * [MyM87]	E.W. Myers & W. Miller, A Simple Row Replacement Method,
 *		TR 86-28, Dept. Computer Science, U. of Arizona
 * [Mil87]	W. Miller, A Software Tools Sampler, Prentice-Hall, 1987
 * [Gos81]	James Gosling, A redisplay algorithm, Proceedings of the
 *		ACM Symposium on Text Manipulation, SIGPLAN Notices,
 *		16(6) June 1981, pg 123-129
 *
 * All the above were reviewed and experimented with.  Due to the nature of
 * Curses' having to handling overlapping WINDOWs, the only suitable
 * algorithum is [Gos81].  The others are better suited to editor type
 * applications that have one window being the entire terminal screen.
 *
 */
static void
complex(void)
{
	int	fr = -1;
	int	i, j, lr;
	t_action	func;

	/* Find block of lines to change */
	for (i = 0; i < LINES; ++i) {
		if (newscr->_first[i] < newscr->_last[i]) {
			/* Compute new hash. */
			__m_cc_hash(newscr, nhash, i);
			if (fr == -1)
				fr = i;
			lr = i;
		} else {
			/* Line not dirty so hash same as before. */
			nhash[i] = __m_screen->_hash[i];
		}
	}

	if (fr != -1) {
		/* Gosling */
		(void) cost(fr, lr);
		script(fr, lr);

		/* Do deletes first in reverse order. */
		for (j = lr; fr <= j; --j) {
			if (del[j] != (t_action) 0) {
				for (i = j-1; fr <= i; --i)
					if (del[i] == (t_action) 0)
						break;

				lines_delete(i+1, j+1);
				j = i;
			}
		}

		/* Do insert/replace in forward order. */
		for (i = fr; i <= lr; ++i) {
			if ((func = ins_rep[i]) != (t_action) 0) {
				/* Find size of block */
				for (j = i; j <= lr && ins_rep[j] == func; ++j)
					;
				(*func)(i, j);
				i = j - 1;
			}
		}
		/*
		 * _line[], which contains pointers to screen lines,
		 * may be shuffled.
		 */
		for (i = fr; i <= lr; ++i) {
			/* Save new hash for next update. */
			__m_screen->_hash[i] = nhash[i];

			/* Mark line as untouched. */
			newscr->_first[i] = newscr->_maxx;
			newscr->_last[i] = -1;
		}
	}
}

/*
 * Simple screen update algorithm
 *
 * We perform a simple incremental update of the terminal screen.
 * Only the segment of a line that was touched is replaced on the
 * line.
 */
static void
simple(void)
{
	int row;

	for (row = 0; row < newscr->_maxy; ++row) {
		if (newscr->_first[row] < newscr->_last[row]) {
			text_replace(row);

			/* Mark line as untouched. */
			newscr->_first[row] = newscr->_maxx;
			newscr->_last[row] = -1;
			__m_cc_hash(curscr, __m_screen->_hash, row);
		}
	}

	newscr->_flags &= ~W_REDRAW_WINDOW;
}

void
wtouchln_hard(WINDOW *w, int y, int n)
{
	int	last;

	last = w->_maxx;

	for (; (y < w->_maxy) && (0 < n); ++y, --n) {
		/*
		 * Force compare in doupdate to fail.
		 * Touch should be unconditional
		 */
(void) memset(&__m_screen->_curscr->_line[w->_begy + y][w->_begx],
	0xff, last * sizeof (cchar_t));
	}
}
/*
 * Send all changes made to _newscr to the physical terminal.
 *
 * If idlok() is set TRUE then doupdate will try and use hardware insert
 * and delete line sequences in an effort to optimize output.  idlok()
 * should really only be used in applications that want a proper scrolling
 * effect.
 *
 * Added scroll heuristic to handle special case where a full size window
 * with full size scroll region, will scroll the window and replace dirty
 * lines instead of performing usual cost/script operations.
 */
int
doupdate(void)
{
#ifdef SIGTSTP
	int (*oldsig)(int) = signal(SIGTSTP, SIG_IGN);
#endif

	if (pollTypeahead()) {
		return (OK);
	}
	newscr = __m_screen->_newscr;

	if (__m_screen->_flags & S_ENDWIN) {
		/* Return from temporary escape done with endwin(). */
		__m_screen->_flags &= ~S_ENDWIN;

		(void) reset_prog_mode();
		if (enter_ca_mode != NULL)
			(void) TPUTS(enter_ca_mode, 1, __m_outc);
		if (keypad_xmit != NULL)
			(void) TPUTS(keypad_xmit, 1, __m_outc);
		if (ena_acs != NULL)
			(void) TPUTS(ena_acs, 1, __m_outc);

		/* Force redraw of screen. */
		newscr->_flags |= W_CLEAR_WINDOW;
	}
	/*
	 * When redrawwing a window, we not only assume that line
	 * noise may have lost characters, but line noise may have
	 * generated bogus characters on the screen outside the
	 * the window in question, in which case redraw the entire
	 * screen to be sure.
	 */
	if ((newscr->_flags & (W_CLEAR_WINDOW | W_REDRAW_WINDOW)) ||
		(curscr->_flags & W_CLEAR_WINDOW)) {
		erase_bottom(0, newscr->_maxy);
		clear_bottom(0);
		(void) wtouchln(newscr, 0, newscr->_maxy, 1);
		newscr->_flags &= ~W_CLEAR_WINDOW;
		curscr->_flags &= ~W_CLEAR_WINDOW;
	}

	/*
	 * Scrolling heuristic should only be used if lines being
	 * scrolled are clean because scrolling overrides updates
	 *
	 * Right now, the following code should always turn off
	 * scrolling, because the internal scroll touches the
	 * scrolled lines. This thing requires a lot more care
	 * than I have right now...
	 */
	if (newscr->_scroll) {
		int	y;
		for (y = 0; y < newscr->_maxy; ++y) {
			if (0 <= newscr->_last[y]) {
				newscr->_scroll = 0;
			}
		}
		newscr->_scroll = 0;	/* Just fudge it for now ... */
	}
	if (newscr->_flags & W_REDRAW_WINDOW) {
		simple();
	} else {
		if (newscr->_scroll == 0) {
			if (__m_screen->_flags & S_INS_DEL_LINE) {
				complex();
			} else {
				simple();
			}
		} else {
			if (!scroll_up(newscr->_scroll)) {
				if (__m_screen->_flags & S_INS_DEL_LINE) {
					complex();
				} else {
					simple();
				}
			}
		}
	}

	if (!(newscr->_flags & W_LEAVE_CURSOR))	{
		GOTO(newscr->_cury, newscr->_curx);
	}

	if (!(curscr->_flags & W_FLUSH)) {
		(void) fflush(__m_screen->_of);
	}

	newscr->_scroll = curscr->_scroll = 0;

	/* Send labels to terminal that supports them. */
	__m_slk_doupdate();
#ifdef SIGTSTP
	signal(SIGTSTP, oldsig);
#endif

	return (OK);
}

/*
 * If true, the implementation may use hardware insert and delete,
 * character features of the terminal.  The window parameter
 * is ignored.
 */
/* ARGSUSED */
void
idcok(WINDOW *w, bool bf)
{
	__m_screen->_flags &= ~S_INS_DEL_CHAR;
	if (bf)
		__m_screen->_flags |= S_INS_DEL_CHAR;
}

/*
 * If true, the implementation may use hardware insert, delete,
 * and scroll line features of the terminal.  The window parameter
 * is ignored.
 */
/* ARGSUSED */
int
idlok(WINDOW *w, bool bf)
{
	__m_screen->_flags &= ~S_INS_DEL_LINE;
	if (bf && has_il())
		__m_screen->_flags |= S_INS_DEL_LINE;

	return (OK);
}

/*
 * Use the POSIX 32-bit CRC function to compute a hash value
 * for the window line.
 */
void
#if defined(_LP64)
__m_cc_hash(WINDOW *w, unsigned int *array, int y)
#else
__m_cc_hash(WINDOW *w, unsigned long *array, int y)
#endif
{
	array[y] = 0;
	m_crcposix(&array[y], (unsigned char *) w->_line[y],
		(size_t)(w->_maxx * sizeof (**w->_line)));
}
