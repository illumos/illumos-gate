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
 * Copyright 2015 Gary Mills
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

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
static char const rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/doupdate.c 1.9 1995/07/26 17:45:06 ant Exp $";
#endif
#endif

#include <private.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>

#undef SIGTSTP

/*
 * Disable typeahead trapping because it slow down updated dramatically
 * on MPE/iX.
 */
#ifdef MPE_STUB
#undef M_CURSES_TYPEAHEAD
#endif

/*
 * This value is the ideal length for the cursor addressing sequence 
 * being four bytes long, ie. "<escape><cursor addressing code><row><col>".
 * eg. VT52 - "\EYrc" or ADM3A - "\E=rc"
 */
#define JUMP_SIZE	4

/*
 * This value is the ideal length for the clear-to-eol sequence
 * being two bytes long, ie "<escape><clear eol code>".
 */
#define CEOL_SIZE	2

#define GOTO(r,c)	(__m_mvcur(curscr->_cury, curscr->_curx,r,c,__m_outc),\
			curscr->_cury = r, curscr->_curx = c)

typedef struct cost_op {
	short cost;
	short op;
} lcost;

typedef void (*t_action)(int, int);

static jmp_buf breakout;

#define LC(i,j) 	(lc[(i) * (LINES + 1) + (j)])

static lcost *lc = (lcost *) 0;
static unsigned long *nhash = (unsigned long *) 0;
static t_action *del = (t_action *) 0;
static t_action *ins_rep = (t_action *) 0;

static WINDOW *newscr;

STATIC void erase_bottom(int);
STATIC void clear_bottom(int);
STATIC void complex(void);
STATIC int cost(int, int);
STATIC void lines_delete(int, int);
STATIC void lines_insert(int, int);
STATIC void lines_replace(int, int);
STATIC void script(int, int);
STATIC int scroll_dn(int);
STATIC int scroll_up(int);
STATIC void simple(void);
STATIC void text_replace(int);
STATIC void block_over(int, int, int);

/*f
 * Wrapper that streams Curses output.
 * 
 * All escape sequences going to the screen come through here.
 * All ordinary characters go to the screen via the putc in doupdate.c
 */
int
__m_outc(ch)
int ch;
{
        return putc(ch, __m_screen->_of);
}

/*
 * Allocate or grow doupdate() structures.
 */
int
__m_doupdate_init() 
{
	void *new;
	static short nlines = 0;

	if (lines <= 0)
		return -1;

	if (lines <= nlines)
		return 0;

	new = m_malloc((lines+1) * (lines+1) * sizeof *lc);
	if (new == (void *) 0)
		return -1;
	if (lc != (lcost *) 0)
		free(lc);
	lc = (lcost *) new;

	new = m_malloc((lines + lines) * sizeof *del);
	if (new == (void *) 0)
		return -1;
	if (del != (t_action *) 0)
		free(del);
	del = (t_action *) new;
	ins_rep = del + lines;

	new = m_malloc(lines * sizeof *nhash);
	if (new == (void *) 0)
		return -1;
	if (nhash != (unsigned long *) 0)
		free(nhash);
	nhash = (unsigned long *) new;

	nlines = lines;

	return 0;
}

STATIC void
erase_bottom(y)
int y;
{
	int i;

	for (i = y; i < LINES; ++i) {
		(void) __m_cc_erase(curscr, i, 0, i, curscr->_maxx-1);
		__m_cc_hash(curscr, __m_screen->_hash, i);
	}
}

/*f
 *  Clear from the start of the current row to bottom of screen.
 */
STATIC void
clear_bottom(y)
int y;
{
	erase_bottom(y);

	/* Restore default color pair before doing area clears. */
	if (back_color_erase)
		(void) vid_puts(WA_NORMAL, 0, (void *) 0, __m_outc);

	if (y == 0 && clear_screen != (char *) 0) {
		(void) tputs(clear_screen, 1, __m_outc);
	} else {
		(void) __m_mvcur(-1, -1, y, 0, __m_outc);
		if (clr_eos != (char *) 0) {
			(void) tputs(clr_eos, 1, __m_outc);
		} else if (clr_eol != (char *) 0) {
			for (;;) {
				(void) tputs(clr_eol, 1, __m_outc);
				if (LINES <= y)
					break;
				(void) __m_mvcur(y, 0, y+1, 0, __m_outc);
				++y;
			}
		}
	}

	curscr->_cury = y;
	curscr->_curx = 0;
}

/*f
 * Replace a line of text.  
 *
 * The principal scheme is to overwrite the region of a line between
 * the first and last differing characters.  A clear-eol is used to
 * optimise an update region that consist largely of blanks.  This can
 * happen fairly often in the case of scrolled lines or full redraws.
 *
 * Miller's line redraw algorithm, used in the 'S' editor [Mil87], 
 * should be re-investigated to see if it is simple and fast enough for 
 * our needs, and if it can be adapted to handle the ceol_standout_glitch 
 * (HP 2392A terminals) and multibyte character sequences.
 *
 * Very early versions of this code applied a Gosling algorithm column
 * wise in addition to the row-wise used in complex().  It was removed
 * in favour of both computation and transmission speed.  The assumption
 * being that overwrites of a line region occured far more frequently
 * than the need to insert/delete several isolated characters. 
 *
 * References:
 * [Mil87]	W. Miller, A Software Tools Sampler, Prentice-Hall, 1987
 */
STATIC void
text_replace(row)
int row;
{
	short npair;
	attr_t cookie, nattr; 
	cchar_t *optr, *nptr;
	int col, last, tail, jump, count;
	
#ifdef M_CURSES_TYPEAHEAD
	/* Before replacing a line of text, check for type-ahead. */
	if (__m_screen->_flags & S_ISATTY) {
		unsigned char cc;

		if (read(__m_screen->_kfd, &cc, sizeof cc) == sizeof cc) {
			(void) ungetch(cc);
			longjmp(breakout, 1);
		}
	}
#endif /* M_CURSES_TYPEAHEAD */

	col = newscr->_first[row];
	if (col < 0)
		col = 0;

	last = newscr->_last[row];
	if (COLS < last)
		last = COLS;

	if (clr_eol != (char *) 0) {
		/* Find start of blank tail region. */
		nptr = &newscr->_line[row][COLS];
		for (tail = COLS; 0 < tail; --tail) {
			if (!__m_cc_compare(--nptr, &newscr->_bg, 1))
				break;
		}

		/* Only consider clear-to-end-of-line optimization if the
		 * blank tail falls within the end of the dirty region by
		 * more than ideal length of clear-to-end-of-line sequence.
		 * Else disable the check by forcing tail to be at the
		 * end-of-line.
		 */
		if (last < tail + CEOL_SIZE)
			tail = COLS;
	}

	optr = &curscr->_line[row][col];
	nptr = &newscr->_line[row][col];

	for (jump = -1; col < last; ) {
		/* Skip common regions. */
		for (count = 0; __m_cc_compare(optr, nptr, 1); ++count) {
			/* Advance before possible goto. */
			++optr;
			++nptr;

			if (last <= ++col)
				goto done;
		}

                /* Move the cursor by redrawing characters or using
                 * cursor motion commands.  The first time that we
                 * address this row, jump equals -1, so that the cursor
                 * will be forced to the correct screen line.  Once
                 * there, we should be able to track the cursor motion
                 * along the line and jump only when the cost of redrawing
		 * to column N is more expensive than a jump to column N.
                 */
                if (jump < count) {
			/* First time addressing this row or cost of
			 * jumping cheaper than redrawing.
			 */
                        jump = JUMP_SIZE;
                        GOTO(row, col);
			count = 0;

			/* If attributes at start of field are different
			 * force an attribute cookie to be dropped.
			 */
			if (ceol_standout_glitch 
			&& (optr->_at != nptr->_at || optr->_co != nptr->_co))
				ATTR_STATE |= WA_COOKIE;
                } else {
                        /* Redraw to move short distance. */
			optr -= count;
			nptr -= count;
			col -= count;
		}

		/* Write difference region. */
		while (col < last 
		&& (!__m_cc_compare(optr, nptr, 1) || 0 < count--)) {
write_loop:
			/* Check for clear-to-end-of-line optimization. */
			if (clr_eol != (char *) 0 && tail <= col) {
				/* For HP terminals, only clear-to-end-of-line
				 * once the attributes have been turned off.
				 * Other terminals, we can proceed normally.
				 */
				if (!ceol_standout_glitch
				|| ATTR_STATE == WA_NORMAL) {
					curscr->_curx = col;
					goto done;
				}
			}

			++col;

			/* Make sure we don't scroll the screen by writing
			 * to the bottom right corner.  
			 */
			if (COLS <= col && LINES-1 <= row
			&& auto_right_margin && !eat_newline_glitch) {
				/*** TODO
				 *** Insert character/auto_right_margin
				 *** hacks for writting into the last
				 *** column of the last line so as not
				 *** to scroll.
				 ***/ 
				curscr->_curx = col;
				goto done;
			}

			/* Remember any existing attribute cookie. */
			cookie = optr->_at & WA_COOKIE;

			nattr = nptr->_at;
			npair = nptr->_co;

			/* Change attribute state.  On HP terminals we also
			 * have to check for attribute cookies that may need
			 * to be changed.
			 */
			if (ATTR_STATE != nattr 
			|| optr->_at != nattr || optr->_co != npair) {
				(void) vid_puts(
					nattr, npair, (void *) 0, __m_outc
				);

				/* Remember new or existing cookie. */
				cookie = WA_COOKIE;
			}

			/* Don't display internal characters. */
			if (nptr->_f) 
				(void) __m_cc_write(nptr);

			/* Update copy of screen image. */
			*optr++ = *nptr++;
			optr->_at |= cookie;
		}

		curscr->_curx = col;

		/* Check the attributes at the end of the field with
		 * those of start of the next common region.  If they
		 * differ, force another iteration of the write-loop
		 * that will change the attribute state.
		 */ 
		if (ceol_standout_glitch && col < COLS 
		&& ATTR_STATE != (optr->_at & ~WA_COOKIE))
			goto write_loop;
	}
done:
	/* Before leaving this line, check if we have to turn off 
	 * attributes and record a cookie.
	 */
	if (!move_standout_mode && ATTR_STATE != WA_NORMAL) {
		/* ceol_standout_glitch, which affects HP terminals,
		 * drops hidden cookies on the screen where ever the
		 * cursor is, so disabling attributes before a cursor
		 * motion operation could disturb existing highlights.
		 */
		if (ceol_standout_glitch)
			/* Attributes on an HP terminal do not cross lines. */
			ATTR_STATE = A_NORMAL;
		else
			(void) vid_puts(WA_NORMAL, 0, (void *) 0, __m_outc);
	}

	/* Re-check for clear to end-of-line optimization. */
	if (clr_eol != (char *) 0 && tail <= col && col < last) {
		/* Is the tail of the current screen image non-blank? */
		for (tail = col; tail < COLS; ++tail, ++optr)
			if (!__m_cc_compare(optr, &newscr->_bg, 1))
				break;

		/* If tail didn't reach the right margin of
		 * the current screen image, then we will
		 * make it look like the new image with a
		 * clear to end-of-line.
		 */
		if (tail < COLS) {
			/* Restore default color pair before area clear. */
			if (back_color_erase)
				(void) vid_puts(
					WA_NORMAL, 0, (void *) 0, __m_outc
				);

			(void) tputs(clr_eol, 1, __m_outc);
			__m_cc_erase(curscr, row, tail, row, COLS-1);
		}
	} 

	/* Line wrapping checks. */
	if (COLS <= curscr->_curx) {
		--curscr->_curx;
		if (auto_right_margin && row < LINES-1) {
			if (eat_newline_glitch) {
				__m_outc('\r');
				__m_outc('\n');
			}
			++curscr->_cury;
			curscr->_curx = 0;
		}
	} 
}

/*f
 * Replace a block of lines.
 * Only ever used for complex().
 */
STATIC void 
lines_replace(from, to_1)
int from, to_1;
{
	for (; from < to_1; ++from)
		text_replace(from);
}

/*f
 * Delete a block of lines.
 * Only ever used for complex().
 */
STATIC void 
lines_delete(from, to_1)
int from, to_1;
{
	int count = to_1 - from;

	if (LINES <= to_1) {
		clear_bottom(from);
	} else {
		GOTO(from, 0);
		(void) winsdelln(curscr, -count);

		if (parm_delete_line != (char *) 0) {
			/* Assume that the sequence to delete more than one 
			 * line is faster than repeated single delete_lines. 
			 */
			(void) tputs(
				tparm(
					parm_delete_line, (long) count,
					0, 0, 0, 0, 0, 0, 0, 0
				), count, __m_outc
			);
		} else if (delete_line != (char *) 0) {
			while (from++ < to_1)
				(void) tputs(delete_line, 1, __m_outc);
		} else  {
			/* Error -- what to do. */
			return;
		}
	}
}

/*f
 * Insert a block of lines.
 * Only ever used for complex().
 *
 * We must assume that insert_line and parm_insert_line reset the 
 * cursor column to zero.  Therefore it is text_replace() responsiblity
 * to move the cursor to the correct column to begin the update.
 */
STATIC void 
lines_insert(from, to_1)
int from, to_1;
{
	int row, count = to_1 - from;

	/* Position the cursor and insert a block of lines into the screen
	 * image now, insert lines into the physical screen, then draw the
	 * new screen lines.  
	 */ 
	GOTO(from, 0);
	(void) winsdelln(curscr, count);

	if (parm_insert_line != (char *) 0) {
		/* Assume that the sequence to insert more than one line is
		 * faster than repeated single insert_lines. 
		 */
		(void) tputs(
			tparm(
				parm_insert_line, (long) count,
				0, 0, 0, 0, 0, 0, 0, 0
			), count, __m_outc
		);
	} else if (insert_line != (char *) 0) {
		/* For the single line insert we use to iterate moving
		 * the cursor, inserting, and then drawing a line.  That
		 * would appear to be slow but visually appealing.  However,
		 * people on slow terminals want speed and those on fast
		 * terminal won't see it.
		 */
		for (row = from; row < to_1; ++row)
			(void) tputs(insert_line, 1, __m_outc);
	} else {
		/* Error -- what to do. */
		return;
	}

	for (row = from; row < to_1; ++row)
		text_replace(row);
}

STATIC int
scroll_up(n)
int n;
{
	int count = n;
	int start, finish, to, row;

	if (scroll_forward != (char *) 0) {
		GOTO(LINES-1, 0);
		while (0 < n--)
			(void) tputs(scroll_forward, 1, __m_outc);
	} else if (parm_delete_line != (char *) 0 && 1 < n) {
		GOTO(0, 0);
		(void) tputs(
			tparm(
				parm_delete_line, (long) n, 
				0, 0, 0, 0, 0, 0, 0, 0
			), n, __m_outc
		);
	} else if (delete_line != (char *) 0) {
		GOTO(0, 0);
		while (0 < n--)
			(void) tputs(delete_line, 1, __m_outc);
	} else {
		return 0;
	}

	/* Scroll recorded image. */
	start = 0;
	finish = count-1;
	to = lines;

	(void) __m_cc_erase(curscr, start, 0, finish, curscr->_maxx-1);
	(void) __m_ptr_move(
		(void **) curscr->_line, curscr->_maxy, start, finish, to
	); 

	simple();

	return 1;
}

STATIC int 
scroll_dn(n)
int n;
{
	int count = n;
	int start, finish, to, row;

	if (LINES < n)
		return 0;

	if (scroll_reverse != (char *) 0) {
		GOTO(0, 0);
		while (0 < n--)
			(void) tputs(scroll_reverse, 1, __m_outc);
	} else if (parm_insert_line != (char *) 0 && 1 < n) {
		GOTO(0, 0);
		(void) tputs(
			tparm(
				parm_insert_line, (long) n, 
				0, 0, 0, 0, 0, 0, 0, 0
			), n, __m_outc
		);
	} else if (insert_line != (char *) 0) {
		GOTO(0, 0);
		while (0 < n--)
			(void) tputs(insert_line, 1, __m_outc);
	} else {
		return 0;
	}

	/* Scroll recorded image. */
	start = lines - count;
	finish = lines - 1;
	to = 0;

	(void) __m_cc_erase(curscr, start, 0, finish, curscr->_maxx-1);
	(void) __m_ptr_move(
		(void **) curscr->_line, curscr->_maxy, start, finish, to
	); 

	simple();

	return 1;
}

#ifdef NEVER
STATIC int
is_same_line(old, new, count)
cchar_t *old, *new;
int count;
{
	while (0 < count--)
		if (!__m_cc_compare(old, new, 1))
			return 0;

	return 1;
}
#endif /* NEVER */

/*f
 * Dynamic programming algorithm for the string edit problem.
 *
 * This is a modified Gosling cost algorithm that takes into account
 * null/move operations. 
 *
 * Costs for move, delete, replace, and insert are 0, 1, 2, and 3
 * repectively. 
 */
STATIC int
cost(fr, lr)
int fr, lr;
{
	register lcost *lcp;
	register int or, nr, cc;
	register unsigned long *ohash = __m_screen->_hash;
	cchar_t **oline = curscr->_line;
	cchar_t **nline = newscr->_line;
	int linesz = COLS * sizeof **oline;

	/* Prepare initial row and column of cost matrix. 
	 *
	 *	0 3 6 9 ...
	 *	1
	 *	2
	 *	3
	 *	:
	 */
	LC(fr,fr).cost = 0;
	for (cc = 1, ++lr, nr = fr+1; nr <= lr; ++nr, ++cc) {
		/* Top row is 3, 6, 9, ... */
		LC(fr,nr).cost = cc * 3;
		LC(fr,nr).op = 'i';

		/* Left column is 1, 2, 3, ... */
		LC(nr,fr).cost = cc; 
		LC(nr,fr).op = 'd'; 
	}

	for (--lr, or = fr; or <= lr; ++or) {
		for (nr = fr; nr <= lr; ++nr) {
			lcp = &LC(or+1,nr+1);

			/* Assume move op. */
			lcp->cost = LC(or,nr).cost; 
			lcp->op = 'm';

			if (ohash[or] != nhash[nr]
#ifdef NEVER
/* Should no longer require this code.  Using the POSIX 32-bit CRC to
 * generate a hash value should be sufficient now, since text_replace() 
 * will compare the contents of a line and output only the dirty regions.
 */
			|| !is_same_line(oline[or], nline[nr], linesz)
#endif
			) {
				/* Lines are different, assume replace op. */
				lcp->cost += 2;
				lcp->op = 'r';
			}

			/* Compare insert op. */
			if ((cc = LC(or+1,nr).cost + 3) < lcp->cost) {
				lcp->cost = cc;
				lcp->op = 'i';
			}

			/* Compare delete op. */
			if ((cc = LC(or,nr+1).cost + 1) < lcp->cost) {
				lcp->cost = cc;
				lcp->op = 'd';
			}
		}
	}

	return LC(lr+1,lr+1).cost;
}

/*f
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
STATIC void
script(fr, lr)
int fr, lr;
{
	int i, j;
	cchar_t *cp;

	i = j = lr + 1;	

	memset(del, 0, sizeof *del * LINES);
	memset(ins_rep, 0, sizeof *ins_rep * LINES);

	do {
		/* We don't have to bounds check i or j becuase row fr and 
		 * column fr of lc have been preset in order to guarantee the 
		 * correct motion.
		 */
		switch (LC(i,j).op) {
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
 
/*f
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
STATIC void
complex()
{
	int fr = -1;
	int i, j, lr;
	t_action func;

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
		cost(fr, lr);
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
				i = j-1;
			}
		}
record:
		/* _line[], which contains pointers to screen lines, 
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

/*f
 * Simple screen update algorithm
 *
 * We perform a simple incremental update of the terminal screen. 
 * Only the segment of a line that was touched is replaced on the 
 * line.
 */
STATIC void
simple()
{
	int row;

	for (row = 0; row < LINES; ++row) {
		if (newscr->_first[row] < newscr->_last[row]) {
			text_replace(row);

			/* Mark line as untouched. */
			newscr->_first[row] = newscr->_maxx;
			newscr->_last[row] = -1;

			if (__m_screen->_flags & S_INS_DEL_LINE)
				__m_cc_hash(newscr, nhash, row);
		}
	}

	newscr->_flags &= ~W_REDRAW_WINDOW;
}

/*f
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
doupdate()
{
#ifdef SIGTSTP
	int (*oldsig)(int) = signal(SIGTSTP, SIG_IGN);
#endif

#ifdef M_CURSES_TYPEAHEAD
	unsigned char cc;
	volatile int min, time, icanon;

	if (__m_screen->_flags & S_ISATTY) {
		/* Set up non-blocking input for typeahead trapping. */
		min = cur_term->_prog.c_cc[VMIN];
		time = cur_term->_prog.c_cc[VTIME];
		icanon = cur_term->_prog.c_lflag & ICANON;

		cur_term->_prog.c_cc[VMIN] = 0;
		cur_term->_prog.c_cc[VTIME] = 0;
		cur_term->_prog.c_lflag &= ~ICANON;

		(void) tcsetattr(__m_screen->_kfd, TCSANOW, &cur_term->_prog);
	}
#endif /* M_CURSES_TYPEAHEAD */

#ifdef M_CURSES_TRACE
	__m_trace(
		"doupdate(void) using %s algorithm.", 
		(__m_screen->_flags & S_INS_DEL_LINE) ? "complex" : "simple"
	);
#endif

	newscr = __m_screen->_newscr;

	if (__m_screen->_flags & S_ENDWIN) {
		/* Return from temporary escape done with endwin(). */
		__m_screen->_flags &= ~S_ENDWIN;

		(void) reset_prog_mode();
		if (enter_ca_mode != (char *) 0)
			(void) tputs(enter_ca_mode, 1, __m_outc);
		if (keypad_xmit != (char *) 0)
			(void) tputs(keypad_xmit, 1, __m_outc);
		if (ena_acs != (char *) 0)
			(void) tputs(ena_acs, 1, __m_outc);

		/* Force redraw of screen. */
		newscr->_flags |= W_CLEAR_WINDOW;
	}

#ifdef M_CURSES_TYPEAHEAD
	if (setjmp(breakout) == 0) {
		if ((__m_screen->_flags & S_ISATTY)
		&& read(__m_screen->_kfd, &cc, sizeof cc) == sizeof cc) {
			(void) ungetch(cc);
			longjmp(breakout, 1);
		}
#endif /* M_CURSES_TYPEAHEAD */

		/* When redrawwing a window, we not only assume that line 
		 * noise may have lost characters, but line noise may have
		 * generated bogus characters on the screen outside the
		 * the window in question, in which case redraw the entire
		 * screen to be sure.
		 */
		if (newscr->_flags & (W_CLEAR_WINDOW | W_REDRAW_WINDOW)) {
			clear_bottom(0);
			newscr->_flags &= ~W_CLEAR_WINDOW;
			(void) wtouchln(newscr, 0, newscr->_maxy, 1);
		}

		if (newscr->_flags & W_REDRAW_WINDOW)
			simple();
#if 0		/* This first expression, of undefined section, is useless
		 * since newscr->_scroll is unsigned and never LT zero.
		 */
		else if (newscr->_scroll < 0 && scroll_dn(-newscr->_scroll))
#else
		else if (scroll_dn(-newscr->_scroll))
#endif
			;
		else if (0 < newscr->_scroll && scroll_up(newscr->_scroll))
			;
		else if (__m_screen->_flags & S_INS_DEL_LINE)
			complex();
		else
			simple();

		if (!(newscr->_flags & W_LEAVE_CURSOR))
			GOTO(newscr->_cury, newscr->_curx);

		if (!(curscr->_flags & W_FLUSH))
			(void) fflush(__m_screen->_of);
#ifdef M_CURSES_TYPEAHEAD
	}

	if (__m_screen->_flags & S_ISATTY) {
		/* Restore previous input mode. */
		cur_term->_prog.c_cc[VMIN] = min;
		cur_term->_prog.c_cc[VTIME] = time;
		cur_term->_prog.c_lflag |= icanon;

		(void) tcsetattr(__m_screen->_kfd,TCSANOW,&cur_term->_prog);
	}
#endif /* M_CURSES_TYPEAHEAD */

	newscr->_scroll = curscr->_scroll = 0;
#ifdef SIGTSTP
	signal(SIGTSTP, oldsig);
#endif

	return __m_return_code("doupdate", OK);
}

/*
 * If true, the implementation may use hardware insert and delete,
 * character features of the terminal.  The window parameter
 * is ignored.
 */
void
idcok(WINDOW *w, bool bf)
{
#ifdef M_CURSES_TRACE
	__m_trace("idcok(%p, %d)", w, bf);
#endif
 
	__m_screen->_flags &= ~S_INS_DEL_CHAR;
	if (bf)
		__m_screen->_flags |= S_INS_DEL_CHAR;

	__m_return_void("idcok");
}
 
/*
 * If true, the implementation may use hardware insert, delete,
 * and scroll line features of the terminal.  The window parameter
 * is ignored.
 */
int
idlok(WINDOW *w, bool bf)
{
#ifdef M_CURSES_TRACE
	__m_trace("idlok(%p, %d)", w, bf);
#endif

	__m_screen->_flags &= ~S_INS_DEL_LINE;
	if (bf && has_il())
		__m_screen->_flags |= S_INS_DEL_LINE;

	return __m_return_code("idlok", OK);
}

/*
 * Use the POSIX 32-bit CRC function to compute a hash value 
 * for the window line.
 */
void
__m_cc_hash(w, array, y)
WINDOW *w;
unsigned long *array;
int y;
{
	array[y] = 0;
	m_crcposix(
		&array[y], (unsigned char *) w->_line[y], 
		(size_t) (w->_maxx * sizeof **w->_line)
	);
}


