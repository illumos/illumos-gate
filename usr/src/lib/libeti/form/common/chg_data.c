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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <sys/types.h>
#include <stdlib.h>
#include "utility.h"

#define	AT_BOTTOM(f)	(Y(f) == Ymax(f) - 1)		/* last line	*/
#define	AT_END(f)	(Y(f) == Ymax(f) - 1 && X(f) == Xmax(f) - 1)
							/* last char */
#define	AT_BEGINNING(f)	(Y(f) == 0 && X(f) == 0)	/* first char	*/

static int
room_for_line(FORM *f)
{
	char *v;

	_sync_buffer(f);
	v = LineBuf(C(f), Ymax(f) - 1);
	return (v == _data_end(v, Xmax(f)));	/* check for empty line */
}

static int
room_for_char(FORM *f)
{
	WINDOW * w = W(f);
	int c;

	(void) wmove(w, Y(f), Xmax(f) - 1);
	c = (int)(winch(w) & A_CHARTEXT);
	(void) wmove(w, Y(f), X(f));
	return (c == Pad(C(f)));	/* check for empty char */
}

static int
extra_padding(char *str, int nstr)		/* used for word wrapping */
{
	int c = *(str + nstr - 1);

	if (c == '"' || c == '\'')
		c = *(str + nstr - 2);

	return ((c == '.' || c == '?' || c == '!' || c == ':') ? 2 : 1);

}

BOOLEAN
_grow_field(FIELD *c, int chunks)
{
	/* This function handles the growth of dymanically growable fields */
	/* Returns TRUE if successful, FALSE otherwise	*/

	FORM		*f = c->form;
	WINDOW		*w = W(f);
	BOOLEAN		current = Status(f, POSTED) && c == C(f);
	char		*old_buf;
	char		*new_buf;
	char		*save;
	int		old_len = BufSize(c);
	int		grow;
	int		lcv;
	int		max = c->maxgrow;
	int		i;

	if (current && Status(f, WIN_CHG)) {
		_win_to_buf(w, c);
		Clr(f, WIN_CHG);
		Set(f, BUF_CHG);
	}

	if (OneRow(c)) {
		grow = chunks * c->cols;

		if (max)
			grow = MIN(max - c->dcols, grow);

		c->dcols += grow;

		if (c->dcols == max)
			Clr(c, GROWABLE);
	} else {
		grow = chunks * (c->rows + c->nrow);

		if (max)
			grow = MIN(max - c->drows, grow);

		c->drows += grow;
		grow *= c->cols;

		if (c->drows == max)
			Clr(c, GROWABLE);
	}

	save = old_buf = Buf(c);
	new_buf = Buf(c) = malloc(TotalBuf(c));

	if (!new_buf)
		return (FALSE);

	lcv = c->nbuf + 1;

	for (i = 0; i < lcv; i++) {
		(void) memcpy(new_buf, old_buf, old_len);
		(void) memset(new_buf + old_len, ' ', grow);
		old_buf += old_len + 1;
		new_buf += old_len + grow;
		*new_buf++ = '\0';
	}

	free(save);	/* delete old buffer */

	if (current) {
		(void) delwin(w);
		W(f) = w = newwin(c->drows, c->dcols, 0, 0);

		if (!w)
			return (FALSE);

		wbkgdset(w, Pad(c) | Back(c));
		(void) wattrset(w, Fore(c));
		(void) werase(w);
		_buf_to_win(c, w);
		(void) untouchwin(w);
		(void) wmove(w, Y(f), X(f));
	}

	if (c->link != c) {
		FIELD	*p = c->link;

		while (p != c) {
			Buf(p) = Buf(c);
			p->drows = c->drows;
			p->dcols = c->dcols;
			/* _sync_field(p) */
			p = p->link;
		}
	}

	return (TRUE);
}

static int
insert_str(FORM *f, int y, int off, int nstr)	/* used for word wrapping */
{
	WINDOW		*w	= W(f);
	FIELD		*c	= C(f);
	char		*vbeg	= LineBuf(c, y);
	char		*v	= _data_end(vbeg, Xmax(f));
	int		x	= (int)(v - vbeg);
	int		n	= Xmax(f) - x;
	int		pad	= extra_padding(Buf(c) + off, nstr);
	int		siz	= nstr + 1 + pad;
	int		ret 	= E_REQUEST_DENIED;

	if (n >= siz) {	/* check for fit on this line */
		(void) wmove(w, y, 0);
		(void) winsnstr(w, Buf(c) + off, nstr);
		(void) wmove(w, y, nstr);
		(void) winsnstr(w, "  ", pad);
	} else {		/* wrap */
		if (y == Ymax(f) - 1 && Status(c, GROWABLE)) {
			if (!_grow_field(c, 1))
				return (E_SYSTEM_ERROR);

			vbeg = LineBuf(c, y);	/* grow changes buffer */
			w = W(f);		/* grow changes window */
		}

		v = _data_beg(vbeg + Xmax(f) - siz, siz);
		v = _whsp_end(vbeg, (int)(v - vbeg));
		x = (int)(v - vbeg);
		n = Xmax(f) - x - n;

		if (y < Ymax(f) - 1 && (ret =
		    insert_str(f, y+1, (int)(v - Buf(c)), n)) == E_OK) {
			(void) wmove(w, y, x);
			(void) wclrtoeol(w);
			(void) wmove(w, y, 0);
			(void) winsnstr(w, Buf(c) + off, nstr);
			(void) wmove(w, y, nstr);
			(void) winsnstr(w, "  ", pad);
		} else
			return (ret);	/* no room for wrap */
	}
	return (E_OK);
}

static int
wrap_ok(FORM *f)		/* used for word wrapping */
{
/*
 * when this routine is called a char has already been added/inserted
 * on the screen at Y(f), X(f).  this routine checks to see if the current
 * line needs wrapping and if so attempts the wrap.  if unsuccessful
 * it deletes the char at Y(f), X(f) and returns FALSE.
 */
	FIELD		*c = C(f);
	BOOLEAN		at_bottom = AT_BOTTOM(f);
	int		ret = E_REQUEST_DENIED;

	if (Opt(c, O_WRAP) && !OneRow(c) && !room_for_char(f) &&
	    (!at_bottom || Status(c, GROWABLE))) {
		WINDOW *w;
		char *vbeg;
		char *v;
		int x, n;

		if (at_bottom && !_grow_field(c, 1))
			return (E_SYSTEM_ERROR);

		vbeg = LineBuf(c, Y(f));
		w = W(f);

		_win_to_buf(w, c);	/* sync buffer without changing flags */

		v = _whsp_end(vbeg, Xmax(f));
		x = (int)(v - vbeg);
		n = Xmax(f) - x;

		if (x && (ret = insert_str(f, Y(f)+1, (int)(v - Buf(c)), n)) ==
		    E_OK) {
			w = W(f);	/* window may change in insert_str */
			(void) wmove(w, Y(f), x);
			(void) wclrtoeol(w);

			if (X(f) >= x) {
				++Y(f);
				X(f) = X(f) - x;
			}
		} else {	/* error condition */
			if (ret == E_SYSTEM_ERROR)
				return (E_SYSTEM_ERROR);

			(void) wmove(w, Y(f), X(f));
			(void) wdelch(w);	/* delete the char */
			_win_to_buf(w, c);	/* restore buffer  */
			return (E_REQUEST_DENIED);
		}
	}
	return (E_OK);
}

int
_new_line(FORM *f)
{
/*
 *		overloaded operation
 *
 *	if at beginning of field
 *		move to next field
 *
 *	else if in OVERLAY mode
 *		if on last line of field
 *			clear to eol and move to next field
 *		else
 *			clear to eol and move to beginning of next line
 *
 *	else if in INSERT mode
 *		if on last line of field
 *			move to next field
 *		else
 *			move text from cursor to eol to new line
 */
	BOOLEAN		at_bottom = AT_BOTTOM(f);
	FIELD *		c = C(f);

	if (Opt(f, O_NL_OVERLOAD) && AT_BEGINNING(f))
		return (_field_navigation(_next_field, f));

	if (!Opt(c, O_EDIT))
		return (E_REQUEST_DENIED);

	if (Status(f, OVERLAY)) {		/* OVERLAY mode	*/
		if (at_bottom && (!Status(c, GROWABLE) || OneRow(c))) {
			if (Opt(f, O_NL_OVERLOAD)) {
				(void) wclrtoeol(W(f));
				Set(f, WIN_CHG);
				return (_field_navigation(_next_field, f));
			} else
				return (E_REQUEST_DENIED);
		}

		if (at_bottom && !_grow_field(c, 1))
			return (E_SYSTEM_ERROR);

		(void) wclrtoeol(W(f));
		++Y(f); X(f) = 0;
	} else {		/* INSERT mode	*/
		BOOLEAN		room;

		if (at_bottom && (!Status(c, GROWABLE) || OneRow(c))) {
			if (Opt(f, O_NL_OVERLOAD))
				return (_field_navigation(_next_field, f));
			else
				return (E_REQUEST_DENIED);
		}

		room = !at_bottom && room_for_line(f);

		if (room || Status(c, GROWABLE)) {
			WINDOW	*w;
			char *v;
			char *vend;

			if (!room && !_grow_field(c, 1))
				return (E_SYSTEM_ERROR);

			w = W(f);
			v = LineBuf(c, Y(f)) + X(f);
			vend = _data_end(v, Xmax(f) - X(f));

			(void) wclrtoeol(w);
			++Y(f); X(f) = 0;
			(void) wmove(w, Y(f), X(f));
			(void) winsertln(w);
			(void) waddnstr(w, v, (int)(vend - v));
		} else
			return (E_REQUEST_DENIED);
	}
	Set(f, WIN_CHG);
	return (E_OK);
}

/* _ins_char - insert blank char with error on overflow */
int
_ins_char(FORM *f)
{
	FIELD	*c = C(f);
	BOOLEAN	room = room_for_char(f);

	if (CheckChar(c, ' ') && (room || (OneRow(c) &&
	    Status(c, GROWABLE)))) {
		if (!room && !_grow_field(c, 1))
			return (E_SYSTEM_ERROR);

		(void) winsch(W(f), ' ');

		return (wrap_ok(f));
	}
	return (E_REQUEST_DENIED);
}

/* _ins_line -  insert blank line with error on overflow */
int
_ins_line(FORM *f)
{
	BOOLEAN		room = !AT_BOTTOM(f) && room_for_line(f);
	FIELD		*c = C(f);

	if (CheckChar(c, ' ') && !OneRow(c) && (room || Status(c, GROWABLE))) {
		if (!room && !_grow_field(c, 1))
			return (E_SYSTEM_ERROR);

		X(f) = 0;
		(void) winsertln(W(f));
		return (E_OK);
	}
	return (E_REQUEST_DENIED);
}

/* _del_char - delete char at cursor */
int
_del_char(FORM *f)
{
	(void) wdelch(W(f));
	return (E_OK);
}

int
_del_prev(FORM *f)
{
/*
 *		overloaded operation
 *
 *	if at beginning of field
 *		move to previous field
 *
 *	else if in OVERLAY mode
 *		if at beginning of line
 *			error
 *		else
 *			delete previous char
 *
 *	else if in INSERT mode
 *		if at beginning of line
 *			if current line can fit on preceding
 *				join current line with preceding line
 *			else
 *				error
 *		else
 *			delete previous char
 */
	WINDOW *	w = W(f);
	FIELD *		c = C(f);

	if (AT_BEGINNING(f)) {
		if (Opt(f, O_BS_OVERLOAD))
			return (_field_navigation(_prev_field, f));
		else
			return (E_REQUEST_DENIED);
	}
	if (!Opt(c, O_EDIT))
		return (E_REQUEST_DENIED);

	if (--X(f) < 0) {
		++X(f);

		if (Status(f, OVERLAY))	/* OVERLAY mode	*/
			return (E_REQUEST_DENIED);
		else {			/* INSERT mode	*/
			char *p = LineBuf(c, Y(f) - 1);
			char *v = LineBuf(c, Y(f));
			char *pend;
			char *vend;

			_sync_buffer(f);
			pend = _data_end(p, Xmax(f));
			vend = _data_end(v, Xmax(f));

			if ((vend - v) > (Xmax(f) - (pend - p)))
				return (E_REQUEST_DENIED);
			else {
				(void) wdeleteln(w);
				_adjust_cursor(f, pend);
				(void) wmove(w, Y(f), X(f));
				(void) waddnstr(w, v, (int)(vend - v));
			}
		}
	} else {
		(void) wmove(w, Y(f), X(f));
		(void) wdelch(w);
	}
	Set(f, WIN_CHG);
	return (E_OK);
}

/* _del_line - delete current line */
int
_del_line(FORM *f)
{
	X(f) = 0;
	(void) wdeleteln(W(f));
	return (E_OK);
}

/* _del_word - delete word under cursor plus trailing blanks */
int
_del_word(FORM *f)
{
	FIELD *c = C(f);
	WINDOW *w = W(f);
	char *y = LineBuf(c, Y(f));
	char *t = y + Xmax(f);
	char *v = y + X(f);
	char *x = v;

	_sync_buffer(f);

	if (*v == ' ')
		return (E_REQUEST_DENIED);

	_adjust_cursor(f, _whsp_end(y, X(f)));
	(void) wmove(w, Y(f), X(f));
	(void) wclrtoeol(w);

	v = _whsp_beg(v, (int)(t - v));
	v = _data_beg(v, (int)(t - v));

	if (v != x && *v != ' ')
		(void) waddnstr(w, v, (int)(_data_end(v, (int)(t - v)) - v));

	return (E_OK);
}

/* _clr_eol - clear to end of line */
int
_clr_eol(FORM *f)
{
	(void) wclrtoeol(W(f));
	return (E_OK);
}

/* _clr_eof - clear to end of field */
int
_clr_eof(FORM *f)
{
	(void) wclrtobot(W(f));
	return (E_OK);
}

/* _clr_field - clear entire field */
int
_clr_field(FORM *f)
{
	X(f) = 0; Y(f) = 0;
	(void) werase(W(f));
	return (E_OK);
}

/* _ovl_mode - go into overlay mode */
int
_ovl_mode(FORM *f)
{
	Set(f, OVERLAY);
	return (E_OK);
}

/* _ins_mode - go into insert mode */
int
_ins_mode(FORM *f)
{
	Clr(f, OVERLAY);
	return (E_OK);
}

/* _validation - apply validation function associated with field type */
int
_validation(FORM *f)
{
	return (_validate(f) ? E_OK : E_INVALID_FIELD);
}

/* _next_choice - apply next choice function associated with field type */
int
_next_choice(FORM *f)
{
	_sync_buffer(f);
	return (NextChoice(C(f)) ? E_OK : E_REQUEST_DENIED);
}

/* _prev_choice - apply previous choice function associated with field type */
int
_prev_choice(FORM *f)
{
	_sync_buffer(f);
	return (PrevChoice(C(f)) ? E_OK : E_REQUEST_DENIED);
}

/*
 * _data_entry - enter printable ascii char ch
 * in current field at cursor position
 */
int
_data_entry(FORM *f, int ch)
{
	FIELD *		c = C(f);	/* current field	*/
	WINDOW *	w = W(f);	/* field window		*/
	BOOLEAN		at_end;
	int		ret;

	if (!Opt(c, O_EDIT))
		return (E_REQUEST_DENIED);

	if (AT_BEGINNING(f) && Opt(c, O_BLANK) && ! Status(f, BUF_CHG) &&
	    !Status(f, WIN_CHG))
		(void) werase(w);

	if (Status(f, OVERLAY))	/* OVERLAY mode	*/
		(void) waddch(w, (chtype) ch);
	else {				/* INSERT mode	*/
		BOOLEAN	room = room_for_char(f);

		if (room || (OneRow(c) && Status(c, GROWABLE))) {
			if (!room && !_grow_field(c, 1))
				return (E_SYSTEM_ERROR);

			(void) winsch(w, (chtype) ch);
		} else
			return (E_REQUEST_DENIED);
	}

	if ((ret = wrap_ok(f)) != E_OK)
		return (ret);

	Set(f, WIN_CHG);

	at_end = AT_END(f);

	if (at_end && !Status(c, GROWABLE) && Opt(c, O_AUTOSKIP))
		return (_field_navigation(_next_field, f));

	if (at_end && Status(c, GROWABLE) && !_grow_field(c, 1))
		return (E_SYSTEM_ERROR);

	(void) _next_char(f);
	return (E_OK);
}
