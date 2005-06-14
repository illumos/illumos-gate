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
 * Copyright (c) 1995-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

/*
 * mvcur.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc. All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] =
"$Header: /team/ps/sun_xcurses/archive/local_changes/xcurses/src/lib/"
"libxcurses/src/libc/xcurses/rcs/mvcur.c 1.4 1998/05/29 18:09:09 "
"cbates Exp $";
#endif
#endif

#include <private.h>
#include <string.h>

#define	VECTOR_SIZE		128	/* size of strategy buffer */

/*
 * #define
 * Make_seq_best(s1, s2)
 *
 * Make_seq_best() swaps the values of the pointers if s1->cost > s2->cost.
 */
#define	Make_seq_best(s1, s2)	\
	if (s1->cost > s2->cost) {	\
	    struct Sequence	*temp = s1; \
	    s1 = s2;			\
	    s2 = temp;			\
	}

#define	zero_seq(seq)	((seq)->end = (seq)->vec, (seq)->cost = 0)

struct Sequence {
	int	vec[VECTOR_SIZE];	/* vector of operations */
	int	*end;		/* end of vector */
	int	cost;		/* cost of vector */
};

static bool	relative;		/* set if we really know where we are */

/*
 * Add sequence 2 to sequence 1.
 */
static void
add_seq(struct Sequence *seq1, struct Sequence *seq2)
{
	if (seq1->cost >= __MOVE_INFINITY || seq2->cost >= __MOVE_INFINITY)
		seq1->cost = __MOVE_INFINITY;
	else {
		int	*vptr = seq2->vec;
		while (vptr != seq2->end)
			*(seq1->end++) = *(vptr++);
		seq1->cost += seq2->cost;
	}
}

/*
 * add_op() adds the operator op and the appropriate
 * number of paramaters to seq.  It also increases the
 * cost appropriately.
 *
 * If op takes no parameters then p0 is taken to be a count.
 */
static void
add_op(struct Sequence *seq, int op, int p1, int p2)
{
	*(seq->end++) = op;
	*(seq->end++) = p1;
	*(seq->end++) = p2;

	if (cur_term->_move[op]._seq == NULL) {
		seq->cost = __MOVE_INFINITY;
	} else if (op < __MOVE_MAX_RELATIVE) {
		/* No parameters, total is cost * p1. */
		seq->cost += cur_term->_move[op]._cost * p1;
	} else {
		/* Cursor motion using parameters have fixed cost. */
		seq->cost = cur_term->_move[op]._cost;
	}
}

/*
 * row() adds the best sequence for moving the cursor from orow
 * to nrow to seq.
 *
 * row() considers row_address, parm_up/down_cursor and cursor_up/down.
 */
static void
row(struct Sequence *outseq, int orow, int nrow)
{
	struct Sequence	seqA, seqB;
	struct Sequence	*best = &seqA;
	struct Sequence	*try = &seqB;
	int	parm_cursor, one_step, dist;

	if (nrow == orow)
		return;

	if (nrow < orow) {
		parm_cursor = __MOVE_N_UP;
		one_step = __MOVE_UP;
		dist = orow - nrow;
	} else {
		parm_cursor = __MOVE_N_DOWN;
		one_step = __MOVE_DOWN;
		dist = nrow - orow;
	}

	/* try out direct row addressing */
	zero_seq(best);
	add_op(best, __MOVE_ROW, nrow, 0);

	/* try out paramaterized up or down motion */
	zero_seq(try);
	add_op(try, parm_cursor, dist, 0);
	Make_seq_best(best, try);

	/* try getting there one step at a time... */
	zero_seq(try);
	add_op(try, one_step, dist, 0);
	Make_seq_best(best, try);

	add_seq(outseq, best);
}

/*
 * Motion indexes used in simp_col().
 */
typedef struct {
	int	_tab;	/* Tab index. */
	int	_one;	/* Single-step index, same direction as tab. */
	int	_opp;	/* Single-step index, opposite direction to tab. */
} t_steps;

/*
 * simp_col(outseq, oldcol, newcol)
 *
 * simp_col() adds the best simple sequence for getting from oldcol
 * to newcol to outseq. simp_col() considers (back_)tab and
 * cursor_left/right.
 */
static void
simp_col(struct Sequence *outseq, int oc, int nc)
{
	t_steps	*dir;
	int	dist, tabs, tabstop;
	struct Sequence	seqA, seqB, *best, *try;
	static t_steps	right = { __MOVE_TAB, __MOVE_RIGHT, __MOVE_LEFT };
	static t_steps	left = { __MOVE_BACK_TAB, __MOVE_LEFT, __MOVE_RIGHT };

	if (oc == nc)
		return;

	tabs = tabstop = 0;
	best = &seqA;
	try = &seqB;

	if (oc < nc) {
		dir = &right;

		if (0 < init_tabs) {
			/* Tabstop preceeding nc. */
			tabstop = nc / init_tabs;

			tabs = tabstop - oc / init_tabs;
			if (0 < tabs)
				/* Set oc to tabstop before nc : oc <= nc. */
				oc = tabstop * init_tabs;

			/* Distance from next tabstop to nc in columns. */
			tabstop = init_tabs - nc % init_tabs;
		}

		dist = nc - oc;
	} else {
		dir = &left;

		if (0 < init_tabs) {
			/* Tabstop preceeding nc. */
			tabstop = nc / init_tabs;

			tabs = (oc - 1) / init_tabs - tabstop;
			if (0 < tabs)
				/* Set oc to tabstop after nc : nc <= oc. */
				oc = (tabstop + 1) * init_tabs;

			/* Distance from tabstop preceeding nc in columns. */
			tabstop = nc % init_tabs;
		}

		dist = oc - nc;
	}

	if (0 < tabs) {
		/* Tab as close as possible to nc. */
		zero_seq(best);
		add_op(best, dir->_tab, tabs, 0);
		add_seq(outseq, best);

		/* If tabs alone get us there, then stop. */
		if (oc == nc)
			return;
	}

	/*
	 * We're not exactly positioned yet.  Compare the worth of
	 * two sequences :
	 *   1.	single-step to location;
	 *   2.	over tab by one tabstop, then single-step back to location.
	 */

	/* 1. Single-step to location. */
	zero_seq(best);
	add_op(best, dir->_one, dist, 0);

	/* 2. Over tab by one tabstop, then single-step back to location. */
	if (0 < tabstop &&
		(nc < columns-init_tabs || auto_left_margin ||
		eat_newline_glitch)) {
		zero_seq(try);
		add_op(try, dir->_tab, 1, 0);

		/*
		 * vt100 terminals only wrap the cursor when a spacing
		 * character is written.  Control characters like <tab>
		 * will not cause a line wrap.  Adjust the number of
		 * columns to backup by to reflect the cursor having been
		 * placed in the last column.  See O'Reilly Termcap &
		 * Terminfo book.
		 */
		if (eat_newline_glitch && columns <= nc + tabstop)
			tabstop = columns - nc - 1;

		add_op(try, dir->_opp, tabstop, 0);
		Make_seq_best(best, try);
	}

	add_seq(outseq, best);
}

/*
 * column() adds the best sequence for moving the cursor from oldcol
 * to newcol to outseq.
 *
 * column() considers column_address, parm_left/right_cursor,
 * simp_col() and carriage_return + simp_col().
 */
static void
column(struct Sequence *outseq, int ocol, int ncol)
{
	struct Sequence	seqA, seqB;
	struct Sequence	*best = &seqA;
	struct Sequence	*try = &seqB;
	int	parm_cursor, dist;

	if (ncol == ocol)
		return;

	/* try out direct column addressing */
	zero_seq(best);
	add_op(best, __MOVE_COLUMN, ncol, 0);

	/* try out paramaterized left or right motion */
	if (ncol < ocol) {
		parm_cursor = __MOVE_N_LEFT;
		dist = ocol - ncol;
	} else {
		parm_cursor = __MOVE_N_RIGHT;
		dist = ncol - ocol;
	}
	zero_seq(try);
	add_op(try, parm_cursor, dist, 0);
	Make_seq_best(best, try);

	if (ncol < ocol || !relative) {
		/* try carriage_return then simp_col() */
		zero_seq(try);
		add_op(try, __MOVE_RETURN, 1, 0);
		simp_col(try, 0, ncol);
		Make_seq_best(best, try);
	}

	/* try getting there by simpl_col() */
	zero_seq(try);
	simp_col(try, ocol, ncol);
	Make_seq_best(best, try);

	add_seq(outseq, best);
}

/*
 * send relevant terminal sequences to the screen
 */
static int
out_seq(struct Sequence *seq, int (*putout)(int))
{
	long	p1, p2;
	int	*ptr, op;

	if (__MOVE_INFINITY <= seq->cost)
		return (ERR);

	for (ptr = seq->vec; ptr < seq->end; ) {
		op = *ptr++;
		p1 = *ptr++;
		p2 = *ptr++;

		if (op < __MOVE_MAX_RELATIVE) {
			while (0 < p1--)
				(void) TPUTS(cur_term->_move[op]._seq, 1,
					putout);
		} else {
			(void) TPUTS(tparm(cur_term->_move[op]._seq, p1, p2,
				0, 0, 0, 0, 0, 0, 0), 1, putout);
		}
	}

	return (OK);
}

/*
 * Low-level relative cursor motion.  __m_mvcur() looks for the optimal
 * way to move the cursor from point A to point B.  If either of the
 * coordinates for point A are -1 then only absolute addressing is used.
 * If the coordinates are out-of-bounds then they are MODed into bounds.
 *
 * Since __m_mvcur() must perform output to various terminals, an API
 * similar to tputs() and vidputs() was adopted.
 */
int
__m_mvcur(int oldrow, int oldcol, int newrow, int newcol, int (*putout)(int))
{
	struct Sequence	seqA, seqB;	/* allocate work structures */
	struct Sequence	col0seq;	/* sequence to get from col0 to nc */
	struct Sequence	*best = &seqA;	/* best sequence so far */
	struct Sequence	*try = &seqB;	/* next try */

	newrow %= lines;
	newcol %= columns;

	zero_seq(best);

	/* try out direct cursor addressing */
	add_op(best, __MOVE_ROW_COLUMN, newrow, newcol);

	if (newrow == lines-1 && newcol == columns-1) {
		/* Force absolute position at bottom right because we	*/
		/* don't know where the terminal thinks it is...	*/
		return (out_seq(best, putout));
	}
	if ((relative = (0 <= oldrow && 0 <= oldcol)) != 0) {
		oldrow %= lines;
		oldcol %= columns;

		/* try out independent row/column addressing */
		zero_seq(try);
		row(try, oldrow, newrow);
		column(try, oldcol, newcol);
		Make_seq_best(best, try);
	}
	if (newcol < oldcol || !relative) {
		zero_seq(&col0seq);
		column(&col0seq, 0, newcol);
		if (col0seq.cost < __MOVE_INFINITY) {
			/* try out homing and then row/column */
			if (newrow < oldrow || !relative) {
				zero_seq(try);
				add_op(try, __MOVE_HOME, 1, 0);
				row(try, 0, newrow);
				add_seq(try, &col0seq);
				Make_seq_best(best, try);
			}

			/* try out homing to last line  and then row/column */
			if (newrow > oldrow || !relative) {
				zero_seq(try);
				add_op(try, __MOVE_LAST_LINE, 1, 0);
				row(try, lines - 1, newrow);
				add_seq(try, &col0seq);
				Make_seq_best(best, try);
			}
		}
	}

	return (out_seq(best, putout));
}

/*
 * A do nothing output function for tputs().
 */
static int
nilout(int ch)
{
	return (ch);
}

/*
 * Initialize an entry in cur_term->_move[] with parameters p1 and p2.
 * Note that some capabilities will ignore their parameters.
 */
static void
cost(char *cap, int index, int p1, int p2)
{
	cur_term->_move[index]._seq = cap;

	if (cap == (char *) 0 || cap[0] == '\0') {
		cur_term->_move[index]._cost = __MOVE_INFINITY;
	} else {
		cur_term->_move[index]._cost = __m_tputs(
			tparm(cap, (long) p1, (long) p2, 0, 0, 0, 0, 0, 0, 0),
			1, nilout);

		if (cap == cursor_down && strchr(cap, '\n') != (char *) 0)
			cur_term->_move[index]._cost = __MOVE_INFINITY;
	}
}

void
__m_mvcur_cost(void)
{
	/*
	 * Relative cursor motion that will be costed on a per
	 * character basis in __m_mvcur().
	 */
	cost(cursor_up, __MOVE_UP, 0, 0);
	cost(cursor_down, __MOVE_DOWN, 0, 0);
	cost(cursor_left, __MOVE_LEFT, 0, 0);
	cost(cursor_right, __MOVE_RIGHT, 0, 0);
	cost(dest_tabs_magic_smso ? NULL : tab, __MOVE_TAB, 0, 0);
	cost(dest_tabs_magic_smso ? NULL : back_tab,
		__MOVE_BACK_TAB, 0, 0);

	/* Absolute cursor motion with fixed cost. */
	cost(cursor_home, __MOVE_HOME, 0, 0);
	cost(cursor_to_ll, __MOVE_LAST_LINE, 0, 0);
	cost(carriage_return, __MOVE_RETURN, 0, 0);

	/* Parameter cursor motion with worst case cost. */
	cost(row_address, __MOVE_ROW, lines-1, 0);
	cost(parm_up_cursor, __MOVE_N_UP, lines-1, 0);
	cost(parm_down_cursor, __MOVE_N_DOWN, lines-1, 0);
	cost(column_address, __MOVE_COLUMN, columns-1, 0);
	cost(parm_left_cursor, __MOVE_N_LEFT, columns-1, 0);
	cost(parm_right_cursor, __MOVE_N_RIGHT, columns-1, 0);
	cost(cursor_address, __MOVE_ROW_COLUMN, lines-1, columns-1);
}

#undef mvcur

int
mvcur(int oy, int ox, int ny, int nx)
{
	return (__m_mvcur(oy, ox, ny, nx, __m_outc));
}
