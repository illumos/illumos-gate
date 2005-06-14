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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * m_cc.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/m_cc.c 1.8 1995/09/20 15:26:52 ant Exp $";
#endif
#endif

#include <private.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <m_wio.h>

typedef struct {
	int max;
	int used;
	char *mbs;
} t_string;

static int
write_string(byte, sp)
int byte;
t_string *sp;
{
	if (sp->max <= sp->used)
		return EOF;

	sp->mbs[sp->used++] = byte;

	return byte;
}

/*
 * Convert a wint_t string into a multibyte string.  
 *
 * The conversion stops at the end of string or the first WEOF.  
 * Return the number of bytes successfully placed into mbs.
 */
int
wistombs(mbs, wis, n)
char *mbs;
const wint_t *wis;
int n;
{
	int last;
	t_string string = { 0 };
	t_wide_io convert = { 0 };
	
	string.max = n;
	string.mbs = mbs;
	convert.object = (void *) &string;
	convert.put = (int (*)(int, void *)) write_string;

	for (;; ++wis) {
		/* In case of error, rewind string to the last character. */
		last = string.used;

		if (m_wio_put(*wis, &convert) < 0) {
			string.used = last;
			break;
		}

		/* Test for end of string AFTER trying to copy into the 
		 * buffer, because m_wio_put() has to handle state changes 
		 * back to the initial state on '\0' or WEOF.
		 */
		if (*wis == '\0' || *wis == WEOF)
			break;
	}

	/* m_wio_put() does not write '\0', because the "stream"
	 * object is considered to be in "text" mode, which in the
	 * case of file I/O produces undefined results for systems
	 * using locking-shift character sets.
	 */
	string.mbs[string.used] = '\0';

	return string.used;
}

/*
 * Convert a wint_t string (filled in by wgetn_wstr()) to a wchar_t string.
 * The conversion stops at the end of string or the first WEOF.  Return the
 * number of successfully copied characters.
 *
 * This routinue should be used when sizeof (wchar_t) < sizeof (wint_t).
 */
int
wistowcs(wcs, wis, n)
wchar_t *wcs;
const wint_t *wis;
int n;
{
	wchar_t *start;

	if (n < 0)
		n = INT_MAX;

	for (start = wcs; *wis != '\0' && 0 < n; ++wis, ++wcs, --n) {
		if (*wis == WEOF)
			break;
		*wcs = (wchar_t) *wis;
	}
	*wcs = '\0';

	return (int) (wcs - start);
}

/*
 * Convert a chtype to a cchar_t.
 */
int
__m_chtype_cc(ch, cc)
chtype ch;
cchar_t *cc;
{
	char mb;

	cc->_f = 1;
        cc->_n = 1;
	mb = (char)(ch & A_CHARTEXT);

	if (mbtowc(cc->_wc, &mb, 1) < 0)
		return ERR;

        cc->_co = (short) PAIR_NUMBER(ch);
        cc->_at = (attr_t) ((ch & (A_ATTRIBUTES & ~A_COLOR)) >> 16);

	return OK;
}

/*
 * Return a complex character as a chtype.
 */
chtype
__m_cc_chtype(cc)
const cchar_t *cc;
{
	chtype ch;
	unsigned char mb[MB_LEN_MAX];

	/* Is it a single-byte character? */
	if (cc->_n != 1 || wctomb((char *) mb, cc->_wc[0]) != 1)
		return (chtype) ERR;

	ch = ((chtype) cc->_at << 16) & ~A_COLOR;
	ch |= COLOR_PAIR(cc->_co) | mb[0];

	return ch;
}

/*
 * Convert a complex character's "character" into a multibyte string.
 * The attribute and colour are ignored.
 *
 * If 0 < n, set a new multibyte string and convert the first character, 
 * returning either -1 on error or the number of bytes used to convert the
 * character.
 *
 * If n == 0, continue appending to the current multibyte string and return
 * a value as for 0 < n case.
 *
 * If n < 0, return the accumulated byte length of the current multibyte 
 * string and do nothing else.
 *
 * When converting a character, a null cchar_t pointer will force the initial 
 * shift state and append a '\0' to the multibyte string.  The return value
 * will instead by the number of bytes used to shift to the initial state,
 * and exclude the '\0'.
 */
int
__m_cc_mbs(cc, mbs, n)
const cchar_t *cc;
char *mbs;
int n;
{
	cchar_t *cp;
	int i, bytes, count, last;
	mbstate_t initial = { 0 };
	static t_string string = { 0 };
	static t_wide_io convert = { 0 };

	if (n < 0) {
		/* Return total number of bytes written to multibyte string. */
		return string.used;
	} else if (0 < n) {
		/* Start a new conversion. */
		string.max = n;
		string.used = 0;
		string.mbs = mbs;

		convert._state = initial;
		convert._next = convert._size = 0;
		convert.object = (void *) &string;
		convert.put = (int (*)(int, void *)) write_string;
	} /* else n == 0, continue appending to previous mbs. */

	/* In case of error, rewind string to the last character. */
	last = string.used;

	if (cc == (cchar_t *) 0) {
		/* Force initial shift state. */
		if ((count = m_wio_put('\0', &convert)) < 0) {
			string.used = last;
			return -1;
		}

		if (string.used < string.max)
			string.mbs[string.used++] = '\0';
	} else {
		for (count = i = 0; i < cc->_n; ++i, count += bytes)
			if ((bytes = m_wio_put(cc->_wc[i], &convert)) < 0) {
				string.used = last;
				return -1;
			}
	}

	return count;
}

/*
 * Convert a stty character into a wchar_t.
 */
int
__m_tty_wc(index, wcp)
int index;
wchar_t *wcp;
{
	char mb;
	int code;

	/* Refer to _shell instead of _prog, since _shell will 
	 * correctly reflect the user's prefered settings, whereas 
	 * _prog may not have been initialised if both input and 
	 * output have been redirected.
	 */
	mb = cur_term->_shell.c_cc[index];
	code = mbtowc(wcp, &mb, 1) < 0 ? ERR : OK;

	return code;
}

/*
 * Build a cchar_t from the leading spacing and non-spacing characters 
 * in the multibyte character string.  Only one spacing character is copied
 * from the multibyte character string.
 *
 * Return the number of characters copied from the string, or -1 on error.
 */
int
__m_mbs_cc(const char *mbs, attr_t at, short co, cchar_t *cc)
{
	wchar_t wc;
	const char *start;
	int i, nbytes, width, have_one;

	for (start = mbs, have_one = i = 0; *mbs != '\0'; mbs += nbytes, ++i) {
		if (sizeof cc->_wc <= i)
			/* Too many characters. */
			return -1;

		if ((nbytes = mbtowc(&wc, mbs, UINT_MAX)) < 0)
			/* Invalid multibyte sequence. */
			return -1;

		if (nbytes == 0)
			/* Remainder of string evaluates to the null byte. */
			break;

		if (iscntrl(*mbs))
			/* Treat control codes like a spacing character. */
			width = 1;
		else if ((width = wcwidth(wc)) < 0)
			return -1;
		
		/* Do we have a spacing character? */
		if (0 < width) {
			if (have_one)
				break;
			have_one = 1;
		}

		cc->_wc[i] = wc;
	}

        cc->_f = 1;
	cc->_n = i;
        cc->_co = co;
        cc->_at = at;

	(void) __m_cc_sort(cc);

	return (int) (mbs - start);
}

/*
 * Build a cchar_t from the leading spacing and non-spacing characters 
 * in the wide character string.  Only one spacinig character is copied
 * from the wide character string.
 *
 * Return the number of characters copied from the string, or -1 on error.
 */
int
__m_wcs_cc(const wchar_t *wcs, attr_t at, short co, cchar_t *cc)
{
	short i;
	int width, have_one;
	const wchar_t *start;

	for (start = wcs, have_one = i = 0; *wcs != '\0'; ++wcs, ++i) {
		if (sizeof cc->_wc <= i)
			/* Too many characters. */
			return -1;

		if ((width = wcwidth(*wcs)) < 0)
			return -1;

		if (0 < width) {
			if (have_one)
				break;
			have_one = 1;
		}

		cc->_wc[i] = *wcs;
	}

        cc->_f = 1;
	cc->_n = i;
        cc->_co = co;
        cc->_at = at;

	(void) __m_cc_sort(cc);

	return (int) (wcs - start);
}

/*
 * Convert a single wide character into a complex character.
 */
int
__m_wc_cc(wint_t wc, cchar_t *cc)
{
	wchar_t wcs[2];

	if (wc == WEOF)
		return -1;

	wcs[0] = (wchar_t)wc;
	wcs[1] = '\0';
	(void) __m_wcs_cc(wcs, WA_NORMAL, 0, cc);

	return 0;
}

/*
 * Sort a complex character into a spacing character followed 
 * by any non-spacing characters in increasing order of oridinal 
 * values.  This facilitates both comparision and writting of
 * complex characters.  More than one spacing character is
 * considered an error.
 *
 * Return the spacing character's column width or -1 if more
 * than one spacing character appears in cc.
 */
int
__m_cc_sort(cc)
cchar_t *cc;
{
	wchar_t wc;
	int width, i, j, spacing;

	/* Find spacing character and place in as first element. */
	for (width = spacing = i = 0; i < cc->_n; ++i) {
		j = wcwidth(cc->_wc[i]);
		if (0 < j) {
			/* More than one spacing character is an error. */
			if (0 < width)
				return -1;

			wc = cc->_wc[0];
			cc->_wc[0] = cc->_wc[i];
			cc->_wc[i]  = wc;

			spacing = 1;
			width = j;
			break;
		}
	}

	/* Bubble sort small array. */
	for (i = spacing; i < cc->_n; ++i) {
		for (j = cc->_n - 1; i < j; --j) {
			if (cc->_wc[j-1] > cc->_wc[j]) {
				wc = cc->_wc[j];
				cc->_wc[j] = cc->_wc[j-1];
				cc->_wc[j-1]  = wc;
			}
		}
	}
		
	return width;
}

/*
 * Return width inn screen columns of the character.
 */
int
__m_cc_width(cc)
const cchar_t *cc;
{
	return wcwidth(cc->_wc[0]);
}

/*
 * Return the first column of a multi-column character, in window.
 */
int
__m_cc_first(w, y, x)
WINDOW *w;
int y, x;
{
	register cchar_t *lp;

	for (lp = w->_line[y]; 0 < x; --x) {
		if (lp[x]._f)
			break;
	}

	return x;
}

/*
 * Return the start of the next multi-column character, in window.
 */
int
__m_cc_next(w, y, x)
WINDOW *w;
int y, x;
{
	cchar_t *lp;

	for (lp = w->_line[y]; ++x < w->_maxx; ) {
		if (lp[x]._f)
			break;
	}

	return x;
}

/*
 * Return true if valid last column of a multi-column character.
 */
int
__m_cc_islast(w, y, x)
WINDOW *w;
int y, x;
{
	int first, width;

	first = __m_cc_first(w, y, x);
	width = __m_cc_width(&w->_line[y][x]);

	return first + width == x + 1;
}

/*
 * Replace the character at the current cursor location
 * according to the column width of the character.  The
 * cursor does not advance.
 *
 * Return -1 if the character won't fit on the line and the background
 * was written in its place; else return the width of the character in
 * screen columns.
 */
int
__m_cc_replace(w, y, x, cc, as_is)
WINDOW *w;
int y, x; 
const cchar_t *cc;
int as_is;
{
	int i, width; 
	cchar_t *cp, *np;

	width = __m_cc_width(cc);

        /* If we try to write a broad character that would exceed the
         * right margin, then write the background character instead.
         */     
	if (0 < width && w->_maxx < x + width) {
		(void) __m_cc_erase(w, y, x, y, w->_maxx-1);
		return -1;
	}

	/* Erase the region to be occupied by the new character.
	 * __m_cc_erase() will erase whole characters so that
	 * writing a multicolumn character that overwrites the
	 * trailing and leading portions of two already existing 
	 * multicolumn characters, erases the remaining portions.
	 */
	(void) __m_cc_erase(w, y, x, y, x + width - 1);

	/* Write the first column of the character. */
	cp = &w->_line[y][x++];
	if (cc->_wc[0] == ' ' || cc->_wc[0] == M_MB_L(' ')) {
		*cp = w->_bg;
		cp->_at |= cc->_at;
		if (cc->_co != 0)
			cp->_co = cc->_co;
	} else {
		(void) __m_wacs_cc(cc, cp);
		if (cc->_co == 0)
			cp->_co = w->_fg._co;
	}

	cp->_at |= w->_fg._at | w->_bg._at;

	/* Mark this as the first column of the character. */
	cp->_f = 1;

	/* Duplicate the character in every column the character occupies. */
	for (np = cp + 1, i = 1; i < width; ++i, ++x, ++np) {
		*np = *cp;
		np->_f = 0;
	}

	return width;
}

int
__m_do_scroll(WINDOW *w, int y, int x, int *yp, int *xp)
{
	if (w->_maxx <= x)
		x = w->_maxx-1;

	++y;

	if (y == w->_bottom) {
		--y;
		if (w->_flags & W_CAN_SCROLL) {
			if (wscrl(w, 1) == ERR)
				return ERR;
			x = 0;
		}
	} else if (w->_maxy <= y) {
		y = w->_maxy-1;
	} else {
		/* The cursor wraps for any line (in and out of the scroll
		 * region) except for the last line of the scroll region.  
		 */
		x = 0;
	}

	*yp = y;
	*xp = x;

	return OK;
}

/*
 * Add the character at the current cursor location
 * according to the column width of the character.  
 * The cursor will be advanced.
 *
 * Return ERR if adding the character causes the
 * screen to scroll, when it is disallowed.
 */
int
__m_cc_add(w, y, x, cc, as_is, yp, xp)
WINDOW *w;
int y, x; 
const cchar_t *cc;
int as_is, *yp, *xp;
{
	int nx, width, code = ERR;

#ifdef M_CURSES_TRACE
	__m_trace(
		"__m_cc_add(%p, %d, %d, %p, %d, %p, %p)", 
		w, y, x, cc, as_is, yp, xp
	);
#endif

	switch (cc->_wc[0]) {
	case '\t':
		nx = x + (8 - (x & 07));
		if (__m_cc_erase(w, y, x, y, nx-1) == -1)
			goto error;
		x = nx;

		if (w->_maxx <= x) {
			if (__m_do_scroll(w, y, x, &y, &x) == ERR)
				goto error;
		}
		break;
	case '\n':
		if (__m_cc_erase(w, y, x, y, w->_maxx-1) == -1)
			goto error;
 
		if (__m_do_scroll(w, y, x, &y, &x) == ERR)
			goto error;
		break;
	case '\r':
		x = 0;
		break;
	case '\b':
		if (0 < x)
			--x;
		break;
	default:
		width = __m_cc_replace(w, y, x, cc, as_is);

		x += width;

		if (width < 0 || w->_maxx <= x) {
			if (__m_do_scroll(w, y, x, &y, &x) == ERR)
				goto error;

			if (width < 0)
				x += __m_cc_replace(w, y, x, cc, as_is);
		}
	}

	code = OK;
error:
	*yp = y;
	*xp = x;

	return __m_return_code("__m_cc_add", code);
}

/*
 * Erase region from (y,x) to (ly, lx) inclusive.  The
 * region is extended left and right in the case where
 * the portions of a multicolumn characters are erased.
 *
 * Return -1 if the region is not an integral multiple 
 * of the background character, else zero for success.
 */
int
__m_cc_erase(w, y, x, ly, lx)
WINDOW *w;
int y, x, ly, lx;
{
	cchar_t *cp;
	int i, width;

	if (ly < y)
		return -1;

	if (w->_maxy <= ly)
		ly = w->_maxy - 1;
	if (w->_maxx <= lx)
		lx = w->_maxx - 1;

	/* Erase from first whole character (inclusive) to next 
	 * character (exclusive).
	 */
	x = __m_cc_first(w, y, x);
	lx = __m_cc_next(w, ly, lx) - 1;

	/* Is the region to blank out an integral width of the 
	 * background character?
	 */
	width = __m_cc_width(&w->_bg);

	if (y < ly && (lx + 1) % width != 0)
		return -1;
	if ((lx - x + 1) % width != 0)
		return -1;

	for (; y < ly; ++y, x = 0) {
		if (x < w->_first[y])
			w->_first[y] = (short) x;
		
		for (cp = w->_line[y], i = 0; x < w->_maxx; ++x, ++i) {
			cp[x] = w->_bg;

			/* The start of each new character will be set true
			 * while internal columns of the character will be
			 * reset to false.
			 */
			cp[x]._f = (short) (i % width == 0);
		}
			
		if (w->_last[y] < x)
			w->_last[y] = (short) x;
	}

	if (x < w->_first[y])
		w->_first[y] = (short) x;

	for (cp = w->_line[y], i = 0; x <= lx; ++x, ++i) {
		cp[x] = w->_bg;

		/* The start of each new character will be set true
		 * while internal columns of the character will be
		 * reset to false.
		 */
		cp[x]._f = (short) (i % width == 0);
	}

	if (w->_last[y] < x)
		w->_last[y] = (short) x;

	return 0;
}

/*
 * Expand the character to the left or right of the given position.
 * Return the value returned by __m_cc_replace().
 */
int
__m_cc_expand(w, y, x, side)
WINDOW *w;
int y, x, side;
{
	cchar_t cc;
	int dx, width;

	width = __m_cc_width(&w->_line[y][x]);

	if (side < 0)
		dx = __m_cc_next(w, y, x) - width;
	else if (0 < side)
		dx = __m_cc_first(w, y, x);
	else
		return -1;

	/* __m_cc_replace() will erase the region containing 
	 * the character we want to expand.
	 */
	cc = w->_line[y][x];

	return __m_cc_replace(w, y, dx, &cc, 0);
}

/*
 * Return true if characters are equal.  
 *
 * NOTE to guarantee correct results, make sure that both
 * characters have been passed through __m_cc_sort().
 */
int
__m_cc_compare(c1, c2, exact)
const cchar_t *c1, *c2;
int exact;
{
	int i;

	if (exact && c1->_f != c2->_f)
		return 0;
	if (c1->_n != c2->_n)
		return 0;
	if ((c1->_at & ~WA_COOKIE) != (c2->_at & ~WA_COOKIE))
		return 0;
	if (c1->_co != c2->_co)
		return 0;

	for (i = 0; i < c1->_n; ++i)
		if (c1->_wc[i] != c2->_wc[i])
			return 0;

	return 1;
}

/*
 * Write to the stream the character portion of a cchar_t.
 */
int
__m_cc_write(cc)
const cchar_t *cc;
{
	size_t i, j;
	char mb[MB_LEN_MAX];

	errno = 0;
	for (i = 0; i < cc->_n; ++i) {
		j = wcrtomb(mb, cc->_wc[i], &__m_screen->_state);
		if (errno != 0)
			return EOF;
		if (fwrite(mb, sizeof *mb, j, __m_screen->_of) == 0)
			return EOF;
	}

	return 0;
}
