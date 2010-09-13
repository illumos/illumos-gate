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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 *      Copyright (c) 1997, by Sun Microsystems, Inc.
 *      All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI" /* SVr4.0 1.5 */

/*LINTLIBRARY*/

#include <sys/types.h>
#include "utility.h"

#define	SizePrev(f, v)	((v) - Buf(f))		/* from beginning to v	*/
#define	SizeNext(f, v)	(BufSize(f) - SizePrev(f, v))
					/* from v through end	*/
#define	OffscreenRows(c)	((c)->drows - (c)->rows)
#define	OffscreenCols(c)	((c)->dcols - (c)->cols)

/* _next_char move to next char with wrap to next line at end of line */
int
_next_char(FORM *f)
{
	if (++X(f) == Xmax(f)) {
		if (++Y(f) == Ymax(f)) {
			--X(f);
			--Y(f);
			return (E_REQUEST_DENIED);	/* at last char */
		}
		X(f) = 0;
	}
	return (E_OK);
}

/*
 * _prev_char - move to previous char with
 * wrap to previous line at beginning of line
 */
int
_prev_char(FORM *f)
{
	if (--X(f) < 0) {
		if (--Y(f) < 0) {
			++X(f);
			++Y(f);
			return (E_REQUEST_DENIED);	/* at first char */
		}
		X(f) = Xmax(f) - 1;
	}
	return (E_OK);
}

/* _next_line - move to beginning of next line */
int
_next_line(FORM *f)
{
	if (++Y(f) == Ymax(f)) {
		--Y(f);
		return (E_REQUEST_DENIED);	/* at last line */
	}
	X(f) = 0;
	return (E_OK);
}

/* _prev_line - move to beginning of previous line */
int
_prev_line(FORM *f)
{
	if (--Y(f) < 0) {
		++Y(f);
		return (E_REQUEST_DENIED);	/* at first line */
	}
	X(f) = 0;
	return (E_OK);
}

/* _next_word - move to beginning of next word */
int
_next_word(FORM *f)
{
	FIELD *		c = C(f);
	char *		v = LineBuf(c, Y(f)) + X(f);	/* position in buffer */
	char *		t;

	_sync_buffer(f);

	t = _whsp_beg(v, (int) SizeNext(c, v));
	v = _data_beg(t, (int) SizeNext(c, t));

	if (v == t)
		return (E_REQUEST_DENIED);	/* at last word */

	if (OneRow(c) && c->dcols != c->cols) {
	/* one row and field has grown */
		t = v;

		while (*t != ' ' && *t != '\0')  /* find end of word + 1 */
			t++;

		if (t - (Buf(c) + B(f)) > c->cols) {
			if (t - v > c->cols) {
			/* word longer than visible field */
				B(f) = (int) (v - Buf(c));
			} else {
				B(f) = (int) (t - (Buf(c) + c->cols));
			}

			X(f) = (int) (v - Buf(c));
			return (E_OK);
		}
	}

	_adjust_cursor(f, v);
	return (E_OK);
}

/* _prev_word - move to beginning of previous word */
int
_prev_word(FORM *f)
{
	FIELD *		c = C(f);
	char *		v = LineBuf(c, Y(f)) + X(f);	/* position in buffer */
	char *		t;

	_sync_buffer(f);

	t = _data_end(Buf(c), (int) SizePrev(c, v));
	v = _whsp_end(Buf(c), (int) SizePrev(c, t));

	if (v == t)
		return (E_REQUEST_DENIED);	/* at first word */

	_adjust_cursor(f, v);
	return (E_OK);
}

/* _beg_field - move to first non-pad char in field */
int
_beg_field(FORM *f)
{
	FIELD *	c = C(f);

	_sync_buffer(f);
	_adjust_cursor(f, _data_beg(Buf(c), BufSize(c)));
	return (E_OK);
}

/* _end_field - move after last non-pad char in field */
int
_end_field(FORM *f)
{
	FIELD *	c = C(f);
	char *	end;

	_sync_buffer(f);
	end = _data_end(Buf(c), BufSize(c));

	if (end == Buf(c) + BufSize(c))
		end--;

	_adjust_cursor(f, end);
	return (E_OK);
}

/* _beg_line - move to first non-pad char on current line */
int
_beg_line(FORM *f)
{
	FIELD *c = C(f);

	_sync_buffer(f);
	_adjust_cursor(f, _data_beg(LineBuf(c, Y(f)), Xmax(f)));
	return (E_OK);
}

/* _end_line - move after last non-pad char on current line */
int
_end_line(FORM *f)
{
	FIELD	*c = C(f);
	char	*end;

	_sync_buffer(f);
	end = _data_end(LineBuf(c, Y(f)), Xmax(f));

	if (end == LineBuf(c, Y(f)) + Xmax(f))
		end--;

	_adjust_cursor(f, end);
	return (E_OK);
}

/* _left_char - move left */
int
_left_char(FORM *f)
{
	if (--X(f) < 0) {
		++X(f);
		return (E_REQUEST_DENIED);	/* at left side */
	}
	return (E_OK);
}

/* _right_char - move right */
int
_right_char(FORM *f)
{
	if (++X(f) == Xmax(f)) {
		--X(f);
		return (E_REQUEST_DENIED);	/* at right side */
	}
	return (E_OK);
}

/* _up_char - move up */
int
_up_char(FORM *f)
{
	if (--Y(f) < 0) {
		++Y(f);
		return (E_REQUEST_DENIED);	/* at top */
	}
	return (E_OK);
}

/* _down_char - move down */
int
_down_char(FORM *f)
{
	if (++Y(f) == Ymax(f)) {
		--Y(f);
		return (E_REQUEST_DENIED);	/* at bottom */
	}
	return (E_OK);
}

/* _scr_fline - scroll forward one line */
int
_scr_fline(FORM *f)
{
	FIELD	*c = C(f);

	if (++T(f) > OffscreenRows(c)) {
		--T(f);
		return (E_REQUEST_DENIED);	/* at bottom */
	}
	++Y(f);
	Set(c, TOP_CHG);
	return (E_OK);
}

/* _scr_bline - scroll backward one line */
int
_scr_bline(FORM *f)
{
	FIELD	*c = C(f);

	if (--T(f) < 0) {
		++T(f);
		return (E_REQUEST_DENIED);	/* at top */
	}
	--Y(f);
	Set(c, TOP_CHG);
	return (E_OK);
}

/* _scr_fpage - scroll forward one page(C(f) -> rows) */
int
_scr_fpage(FORM *f)
{
	FIELD *		c = C(f);
	int		m = OffscreenRows(c) - T(f);
	int		n = c -> rows < m ? c -> rows : m;

	if (n) {
		Y(f) += n;
		T(f) += n;
		Set(c, TOP_CHG);
		return (E_OK);
	}
	return (E_REQUEST_DENIED);	/* at bottom */
}

/* _scr_bpage - scroll backward one page(C(f) -> rows) */
int
_scr_bpage(FORM *f)
{
	FIELD *		c = C(f);
	int		m = T(f);
	int		n = c -> rows < m ? c -> rows : m;

	if (n) {
		Y(f) -= n;
		T(f) -= n;
		Set(c, TOP_CHG);
		return (E_OK);
	}
	return (E_REQUEST_DENIED);	/* at top */
}

/* _scr_fhpage - scroll forward one half page(C(f)->rows + 1)/2) */
int
_scr_fhpage(FORM *f)
{
	FIELD *		c = C(f);
	int		m = OffscreenRows(c) - T(f);
	int		h = (c->rows + 1)/2;
	int		n = h < m ? h : m;

	if (n) {
		Y(f) += n;
		T(f) += n;
		Set(c, TOP_CHG);
		return (E_OK);
	}
	return (E_REQUEST_DENIED);	/* at bottom */
}

/* _scr_bhpage - scroll backward one half page(C(f)->rows + 1)/2) */
int
_scr_bhpage(FORM *f)
{
	FIELD *		c = C(f);
	int		m = T(f);
	int		h = (c->rows + 1)/2;
	int		n = h < m ? h : m;

	if (n) {
		Y(f) -= n;
		T(f) -= n;
		Set(c, TOP_CHG);
		return (E_OK);
	}
	return (E_REQUEST_DENIED);	/* at top */
}

/* _scr_fchar - horizontal scroll forward one char */
int
_scr_fchar(FORM *f)
{
	FIELD	*c = C(f);

	if (++B(f) > OffscreenCols(c)) {
		--B(f);
		return (E_REQUEST_DENIED);	/* at end */
	}
	++X(f);
	return (E_OK);
}

/* _scr_bchar - horizontal scroll backward one char */
int
_scr_bchar(FORM *f)
{

	if (--B(f) < 0) {
		++B(f);
		return (E_REQUEST_DENIED);	/* at beginning */
	}
	--X(f);
	return (E_OK);
}

/* _scr_hfline - horizontal scroll forward one line(C(f)->cols) */
int
_scr_hfline(FORM *f)
{
	FIELD	*c = C(f);
	int	m = OffscreenCols(c) - B(f);
	int	n = c -> cols < m ? c -> cols : m;

	if (n) {
		X(f) += n;
		B(f) += n;
		return (E_OK);
	}
	return (E_REQUEST_DENIED);	/* at end */
}

/* _scr_hbline - horizontal scroll backward one line(C(f)->cols) */
int
_scr_hbline(FORM *f)
{
	FIELD	*c = C(f);
	int	m = B(f);
	int	n = c -> cols < m ? c -> cols : m;

	if (n) {
		X(f) -= n;
		B(f) -= n;
		return (E_OK);
	}
	return (E_REQUEST_DENIED);	/* at end */
}

/* _scr_hfhalf - horizontal scroll forward one half line(C(f)->cols/2) */
int
_scr_hfhalf(FORM *f)
{
	FIELD	*c = C(f);
	int	m = OffscreenCols(c) - B(f);
	int	h = (c->cols + 1)/2;
	int	n = h < m ? h : m;

	if (n) {
		X(f) += n;
		B(f) += n;
		return (E_OK);
	}
	return (E_REQUEST_DENIED);	/* at end */
}

/* _scr_hbhalf - horizontal scroll backward one half line(C(f)->cols/2) */
int
_scr_hbhalf(FORM *f)
{
	FIELD	*c = C(f);
	int	m = B(f);
	int	h = (c->cols + 1)/2;
	int	n = h < m ? h : m;

	if (n) {
		X(f) -= n;
		B(f) -= n;
		return (E_OK);
	}
	return (E_REQUEST_DENIED);	/* at top */
}
