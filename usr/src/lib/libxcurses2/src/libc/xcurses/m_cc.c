/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

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
static char rcsID[] =
"$Header: /team/ps/sun_xcurses/archive/local_changes/xcurses/src/lib/"
"libxcurses/src/libc/xcurses/rcs/m_cc.c 1.40 1998/06/12 12:45:39 "
"cbates Exp $";
#endif
#endif

#include <private.h>
#include <limits.h>
#include <m_wio.h>
#include <string.h>

typedef struct {
	int	max;
	int	used;
	char	*mbs;
} t_string;

static int
write_string(int byte, t_string *sp)
{
	if (sp->max <= sp->used)
		return (EOF);

	sp->mbs[sp->used++] = (char)byte;

	return (byte);
}

/*
 * Convert a wint_t string into a multibyte string.
 *
 * The conversion stops at the end of string or the first WEOF.
 * Return the number of bytes successfully placed into mbs.
 */
int
wistombs(char *mbs, const wint_t *wis, int n)
{
	int last;
	t_string string = { 0 };
	t_wide_io convert = { 0 };

	string.max = n;
	string.mbs = mbs;
	convert.object = (void *) &string;
	convert.put = (int (*)(int, void *)) write_string;

	for (; ; ++wis) {
		/* In case of error, rewind string to the last character. */
		last = string.used;

		if (m_wio_put(*wis, &convert) < 0) {
			string.used = last;
			break;
		}

		/*
		 * Test for end of string AFTER trying to copy into the
		 * buffer, because m_wio_put() has to handle state changes
		 * back to the initial state on '\0' or WEOF.
		 */
		if (*wis == '\0' || *wis == WEOF)
			break;
	}

	/*
	 * m_wio_put() does not write '\0', because the "stream"
	 * object is considered to be in "text" mode, which in the
	 * case of file I/O produces undefined results for systems
	 * using locking-shift character sets.
	 */
	string.mbs[string.used] = '\0';

	return (string.used);
}

/*
 * Convert a wint_t string (filled in by wgetn_wstr()) to a wchar_t string.
 * The conversion stops at the end of string or the first WEOF.  Return the
 * number of successfully copied characters.
 *
 * This routinue should be used when sizeof (wchar_t) < sizeof (wint_t).
 */
int
wistowcs(wchar_t *wcs, const wint_t *wis, int n)
{
	wchar_t	*start;

	if (n < 0)
		n = INT_MAX;

	for (start = wcs; *wis != '\0' && 0 < n; ++wis, ++wcs, --n) {
		if (*wis == WEOF)
			break;
		*wcs = (wchar_t)*wis;
	}
	*wcs = '\0';

	/* (wcs - start) should be enough small to fit in "int" */
	return ((int)(wcs - start));
}

void
__m_touch_locs(WINDOW *w, int row, int firstCol, int lastCol)
{
	if (w) {
		if (firstCol < w->_first[row])
			w->_first[row] = (short)firstCol;
		if (lastCol > w->_last[row])
			w->_last[row] = (short)lastCol;
	}
}

/*
 * Convert a chtype to a cchar_t.
 */
int
__m_chtype_cc(chtype ch, cchar_t *cc)
{
	char	mb;

	cc->_f = 1;
	cc->_n = 1;
	mb = (char)(ch & A_CHARTEXT);

	cc->_co = (short)PAIR_NUMBER((int)ch);
	cc->_at = (attr_t)((ch & (A_ATTRIBUTES & ~A_COLOR)) >> 16);

	if (mb == 0)
		cc->_wc[0] = cc->_wc[1] = 0;
	else if (mbtowc(cc->_wc, &mb, 1) < 0) {
		return (ERR);
	}
	return (OK);
}

/*
 * Return a complex character as a chtype.
 */
chtype
__m_cc_chtype(const cchar_t *cc)
{
	chtype	ch;
	unsigned char	mb[MB_LEN_MAX];

	/* Is it a single-byte character? */
	if (cc->_n != 1 || wctomb((char *)mb, cc->_wc[0]) != 1)
		return ((chtype) ERR);

	ch = ((chtype) cc->_at << 16) & ~A_COLOR;
	ch |= COLOR_PAIR(cc->_co) | mb[0];

	return (ch);
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
__m_cc_mbs(const cchar_t *cc, char *mbs, int n)
{
	int	i, bytes, count, last;
	static t_string	string = { 0 };
	static t_wide_io	convert = { 0 };

	if (n < 0) {
		/* Return total number of bytes written to multibyte string. */
		return (string.used);
	} else if (0 < n) {
		/* Start a new conversion. */
		string.max = n;
		string.used = 0;
		string.mbs = mbs;

		convert._next = convert._size = 0;
		convert.object = (void *) &string;
		convert.put = (int (*)(int, void *)) write_string;
	} /* else n == 0, continue appending to previous mbs. */

	/* In case of error, rewind string to the last character. */
	last = string.used;

	if (cc == NULL) {
		/* Force initial shift state. */
		if ((count = m_wio_put('\0', &convert)) < 0) {
			string.used = last;
			return (-1);
		}

		if (string.used < string.max)
			string.mbs[string.used++] = '\0';
	} else {
		for (count = i = 0; i < cc->_n; ++i, count += bytes)
			if ((bytes = m_wio_put(cc->_wc[i], &convert)) < 0) {
				string.used = last;
				return (-1);
			}
	}

	return (count);
}

/*
 * Convert a stty character into a wchar_t.
 */
int
__m_tty_wc(int index, wchar_t *wcp)
{
	char	mb;
	int	code;

	/*
	 * Refer to _shell instead of _prog, since _shell will
	 * correctly reflect the user's prefered settings, whereas
	 * _prog may not have been initialised if both input and
	 * output have been redirected.
	 */
	mb = (char)PTERMIOS(_shell)->c_cc[index];
	if (mb)
	    code = mbtowc(wcp, &mb, 1) < 0 ? ERR : OK;
	else
	    code = ERR;

	return (code);
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
	wchar_t	wc;
	const char	*start;
	int	i, nbytes, width, have_one;

	for (start = mbs, have_one = i = 0; *mbs != '\0'; mbs += nbytes, ++i) {
		if (sizeof (cc->_wc) <= i)
			/* Too many characters. */
			return (-1);

		if ((nbytes = mbtowc(&wc, mbs, UINT_MAX)) < 0)
			/* Invalid multibyte sequence. */
			return (-1);

		if (nbytes == 0)
			/* Remainder of string evaluates to the null byte. */
			break;

		if (iscntrl(*mbs))
			/* Treat control codes like a spacing character. */
			width = 1;
		else
			width = wcwidth(wc);

		/* Do we have a spacing character? */
		if (0 < width) {
			if (have_one)
				break;
			have_one = 1;
		}

		cc->_wc[i] = wc;
	}

	cc->_f = 1;
	cc->_n = (short)i;
	cc->_co = co;
	cc->_at = at;

	(void) __m_cc_sort(cc);

	/* (mbs - start) should be enough small to fit in "int" */
	return ((int)(mbs - start));
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
	short	i;
	const wchar_t	*start;

	for (start = wcs, i = 0; *wcs != '\0'; ++wcs, ++i) {
		if (sizeof (cc->_wc) <= i) {
			/* Too many characters. */
			return (-1);
		}

		if (wcwidth(*wcs) > 0) {
			if (i != 0)
				break;
		} else if ((*wcs == L'\n') || (*wcs == L'\t') ||
			(*wcs == L'\b') || (*wcs == L'\r'))	{
			if (i != 0)
				break;
			cc->_wc[i++] = *wcs++;
			break;
		}

		cc->_wc[i] = *wcs;
	}

	cc->_f = 1;
	cc->_n = i;
	cc->_co = co;
	cc->_at = at;

	/* (wcs - start) should be enough small to fit in "int" */
	return ((int)(wcs - start));
}

/*
 * Convert a single wide character into a complex character.
 */
int
__m_wc_cc(wint_t wc, cchar_t *cc)
{
	wchar_t	wcs[2];

	if (wc == WEOF)
		return (-1);

	if (wc == 0) {
		/*
		 * converting a null character to a complex character.
		 * __m_wcs_cc assumes that the string is empty, so
		 * just do it here.
		 */
		cc->_f = 1;
		cc->_n = 1;
		cc->_co = 0;
		cc->_at = WA_NORMAL;
		cc->_wc[0] = 0;
		cc->_wc[1] = 0;
	} else {
		/* A real character */
		wcs[0] = (wchar_t)wc;
		wcs[1] = '\0';
		(void) __m_wcs_cc(wcs, WA_NORMAL, 0, cc);
	}

	return (0);
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
__m_cc_sort(cchar_t *cc)
{
	wchar_t	wc;
	int	width, i, j, spacing;

	/* Find spacing character and place in as first element. */
	for (width = spacing = i = 0; i < cc->_n; ++i) {
		j = wcwidth(cc->_wc[i]);
		if (0 < j) {
			/* More than one spacing character is an error. */
			if (0 < width)
				return (-1);

			wc = cc->_wc[0];
			cc->_wc[0] = cc->_wc[i];
			cc->_wc[i] = wc;

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

	return (width);
}

/*
 * Return the first column of a multi-column character, in window.
 */
int
__m_cc_first(WINDOW *w, int y, int x)
{
	cchar_t	*lp;

	for (lp = w->_line[y]; 0 < x; --x) {
		if (lp[x]._f)
			break;
	}

	return (x);
}

/*
 * Return the start of the next multi-column character, in window.
 */
int
__m_cc_next(WINDOW *w, int y, int x)
{
	cchar_t	*lp;

	for (lp = w->_line[y]; ++x < w->_maxx; ) {
		if (lp[x]._f)
			break;
	}

	return (x);
}

/*
 * Return true if valid last column of a multi-column character.
 */
int
__m_cc_islast(WINDOW *w, int y, int x)
{
	int	first, width;

	first = __m_cc_first(w, y, x);
	width = __m_cc_width(&w->_line[y][x]);

	return ((first + width) == (x + 1));
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
/* ARGSUSED */
int
__m_cc_replace(WINDOW *w, int y, int x,
	const cchar_t *cc, int as_is)
{
	int	i, width;
	cchar_t	*cp, *np;

	width = __m_cc_width(cc);

	if (width <= 0)
		return (__m_cc_modify(w, y, x, cc));

	/*
	 * If we try to write a broad character that would exceed the
	 * right margin, then write the background character instead.
	 */
	if (0 < width && w->_maxx < x + width) {
		(void) __m_cc_erase(w, y, x, y, w->_maxx-1);
		return (-1);
	}

	/*
	 * Erase the region to be occupied by the new character.
	 * __m_cc_erase() will erase whole characters so that
	 * writing a multicolumn character that overwrites the
	 * trailing and leading portions of two already existing
	 * multicolumn characters, erases the remaining portions.
	 */
	(void) __m_cc_erase(w, y, x, y, x + width - 1);

	/* Write the first column of the character. */
	cp = &w->_line[y][x++];
	if (cc->_wc[0] == L' ') {
		*cp = w->_bg;
		cp->_at = cc->_at | w->_fg._at;
		/*
		 * This method fixes:
		 * /tset/CAPIxcurses/fmvwaddchs/fmvwaddchs1{3}
		 * /tset/CAPIxcurses/fwins_wch/fwins_wch1{5}
		 */
		cp->_co = (cc->_co) ? cc->_co : w->_fg._co;
	} else {
		if (__m_wacs_cc(cc, cp)) {
			/*
			 * __m_wacs_cc says ALTCHARSET should be cleared
			 * ... Takes priority
			 */
		    cp->_at = (cc->_at | w->_fg._at) & ~WA_ALTCHARSET;
		} else {
		    cp->_at = cc->_at | w->_fg._at;
		}
		cp->_co = (cc->_co) ? cc->_co : w->_fg._co;
	}

	/* Mark this as the first column of the character. */
	cp->_f = 1;

	/* Duplicate the character in every column the character occupies. */
	for (np = cp + 1, i = 1; i < width; ++i, ++x, ++np) {
		*np = *cp;
		np->_f = 0;
	}

	return (width);
}

int
__m_do_scroll(WINDOW *w, int y, int x, int *yp, int *xp)
{
	int	code = OK;
	if (w->_maxx <= x)
		x = w->_maxx - 1;

	++y;

	if (y == w->_bottom) {
		--y;
		if (w->_flags & W_CAN_SCROLL) {
			if (wscrl(w, 1) == ERR)
				return (ERR);
			x = 0;
			/* Test suite seems to want this */
			w->_flags |= W_FLUSH;
		} else {
#ifdef	BREAKS
			w->_curx = x;	/* Cheezy doing it here	*/
			w->_cury = y;
#endif	/* BREAKS */
			code = ERR;	/* No scrolling allowed */
		}
	} else if (w->_maxy <= y) {
		y = w->_maxy - 1;
	} else {
		/*
		 * The cursor wraps for any line (in and out of the scroll
		 * region) except for the last line of the scroll region.
		 */
		x = 0;
	}

	*yp = y;
	*xp = x;

	return (code);
}

/*
 * Add the character at the current cursor location
 * according to the column width of the character.
 * The cursor will be advanced.
 * Wrapping is done.
 *
 * Return ERR if adding the character causes the
 * screen to scroll, when it is disallowed.
 */
int
__m_cc_add(WINDOW *w, int y, int x,
	const cchar_t *cc, int as_is, int *yp, int *xp)
{
	int	nx, width, code = ERR;

	switch (cc->_wc[0]) {
	case L'\t':
		nx = x + (8 - (x & 07));
		if (nx >= w->_maxx)	{
			/* This fixes (scroll-disabled) */
			/* /tset/CAPIxcurses/fwaddch/fwaddch1{4} but */
			/* what does it break? */
			nx = w->_maxx;
		}
		if (__m_cc_erase(w, y, x, y, nx-1) == -1)
			goto error;
		x = nx;

		if (w->_maxx <= x) {
			if (__m_do_scroll(w, y, x, &y, &x) == ERR)
				goto error;
		}
		break;
	case L'\n':
		if (__m_cc_erase(w, y, x, y, w->_maxx-1) == -1)
			goto error;

		if (__m_do_scroll(w, y, x, &y, &x) == ERR)
			goto error;
		break;
	case L'\r':
		x = 0;
		break;
	case L'\b':
		if (0 < x)
			--x;
		else
			(void) beep();
		break;
	default:
		width = __m_cc_replace(w, y, x, cc, as_is);

		x += width;

		if (width < 0 || w->_maxx <= x) {
			if (__m_do_scroll(w, y, x, &y, &x) == ERR) {
				goto error;
			}

			if (width < 0)
				x += __m_cc_replace(w, y, x, cc, as_is);
		}
	}

	code = OK;
error:
	*yp = y;
	*xp = x;

	return (code);
}

/*
 * Stripped version of __m_cc_add which does much less special character
 * processing. Functions such as waddchnstr() are not supposed to do
 * any special character processing but what does one do when a '\n'
 * is sent? The test suite expects a new line to start...
 *
 * Return ERR if adding the character causes the
 * screen to scroll, when it is disallowed.
 */
int
__m_cc_add_k(WINDOW *w, int y, int x,
	const cchar_t *cc, int as_is, int *yp, int *xp)
{
	int	width, code = ERR;

	switch (cc->_wc[0]) {
	case L'\n':
		if (__m_cc_erase(w, y, x, y, w->_maxx-1) == -1)
			goto error;

		if (__m_do_scroll(w, y, x, &y, &x) == ERR)
			goto error;
		break;
	default:
		width = __m_cc_replace(w, y, x, cc, as_is);
		x += width;
	}

	code = OK;
error:
	*yp = y;
	*xp = x;

	return (code);
}

/*
 * Append non-spacing characters to the a spacing character at (y, x).
 * Return -1 on error, else 0.
 */
int
__m_cc_modify(WINDOW *w, int y, int x, const cchar_t *cc)
{
	cchar_t	*cp, tch;
	int	i, j, width;

	x = __m_cc_first(w, y, x);
	cp = &w->_line[y][x];

	/* Is there enough room for the non-spacing characters. */
	if (_M_CCHAR_MAX < cp->_n + cc->_n)
		return (-1);

	for (i = cp->_n, j = 0; j < cc->_n; ++i, ++j)
		cp->_wc[i] = cc->_wc[j];
	cp->_n = (short)i;

	width = __m_cc_width(cp);

	__m_touch_locs(w, y, x, x + width);

	/* Assert that the modified spacing character is sorted. */
	(void) __m_cc_sort(cp);

	/* Dulicate in every column occupied by the spacing character. */
	while (0 < --width) {
		tch = *cp;
		cp[1] = tch;
		cp++;
	}

	return (0);
}

static void
__m_cc_erase_in_line(WINDOW *w, int y, int x, int lx, int bgWidth)
{
	cchar_t	*cp;
	int	i;

	if (x < w->_first[y])
		w->_first[y] = (short)x;

	for (cp = w->_line[y], i = 0; x <= lx; ++x, ++i) {
		cp[x] = w->_bg;
		/*
		 * The start of each new character will be set true
		 * while internal columns of the character will be
		 * reset to false.
		 */
		cp[x]._f = (short)(i % bgWidth == 0);
	}
	if (w->_last[y] < x)
		w->_last[y] = (short)x;
}

/* Window has a parent. Handle width chars overlapping with parent */
static void
__m_cc_erase_in_line_sub(WINDOW *w, int y, int x,
	int lx, int bgWidth, int parentBGWidth)
{
	cchar_t	*cp;
	int	i;
	int	xi;
	int	wmin, wmax;
	int	wlx;
	WINDOW	*parent = w->_parent;
	int 	parentY = w->_begy + y - parent->_begy;
	int	dx = w->_begx - parent->_begx;

	/* Switch to parent context and calculate limits */
	xi = x = __m_cc_first(parent, parentY, dx + x);
	wlx = lx = __m_cc_next(parent, parentY, dx + lx) - 1;
	if (wlx >= dx + w->_maxx) wlx = dx + w->_maxx - 1;

	for (cp = parent->_line[parentY]; x <= lx; ) {
		if ((x < dx) || (x >= (dx + w->_maxx))) {
			/* Outside target window */
			for (i = 0; x <= lx && i <= parentBGWidth; x++, i++) {
				cp[x] = parent->_bg;
				cp[x]._f = (i == 0);
			}
		} else {
			/* Inside target window */
			for (i = 0; x <= wlx; x++, i++) {
				cp[x] = w->_bg;
				cp[x]._f = (short)(i % bgWidth == 0);
			}
		}
	}
	wmax = x - dx;		/* Defaults */
	wmin = xi - dx;
	if ((xi < dx) || (x >= dx + w->_maxx)) {
		/* Overlaps parent. Must touch parent and child */
		int	pmin, pmax;

		pmax = dx;		/* Defaults */
		pmin = dx + w->_maxx;
		if (xi < dx) {
			wmin = 0;
			pmin = xi;
		}
		if (x >= dx + w->_maxx) {
			/* Ends right of target window */
			wmax = w->_maxx;
			pmax = x;
		}
		if (pmin < parent->_first[parentY])
			parent->_first[parentY] = (short)pmin;
		if (pmax > parent->_last[parentY])
			parent->_last[parentY] = (short)pmax;
	}
	if (wmin < w->_first[y])
		w->_first[y] = (short)wmin;
	if (wmax > w->_last[y])
		w->_last[y] = (short)wmax;
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
__m_cc_erase(WINDOW *w, int y, int x, int ly, int lx)
{
	int	bgWidth;

	if (ly < y)
		return (-1);

	if (w->_maxy <= ly)
		ly = w->_maxy - 1;

	/*
	 * Is the region to blank out an integral width of the
	 * background character?
	 */
	bgWidth = __m_cc_width(&w->_bg);

	if (bgWidth <= 0)
		return (-1);

	/*
	 * Erase Pattern will look like:
	 *			EEEEEEE|
	 *	EEEEEEEEEEEEEEE|
	 *	EEEEEEEEEEE    |
	 */
	if (w->_parent) {
		/*
		 * Use slower alg. for subwindows.
		 * They might erase stuff in parent-context
		 */
		int	parentBGWidth = __m_cc_width(&w->_parent->_bg);
		for (; y < ly; ++y, x = 0) {
			__m_cc_erase_in_line_sub(w, y, x, w->_maxx-1,
				bgWidth, parentBGWidth);
		}
		__m_cc_erase_in_line_sub(w, y, x, lx, bgWidth, parentBGWidth);
	} else {
		/* Root windows - no need to work in parent context at all */
		if (w->_maxx <= lx)
			lx = w->_maxx - 1;

		/*
		 * Erase from first whole character (inclusive) to next
		 * character (exclusive).
		 */
		x = __m_cc_first(w, y, x);
		lx = __m_cc_next(w, ly, lx) - 1;

		for (; y < ly; ++y, x = 0) {
			__m_cc_erase_in_line(w, y, x, w->_maxx-1, bgWidth);
		}
		__m_cc_erase_in_line(w, y, x, lx, bgWidth);
	}
	return (0);
}

/*
 * Expand the character to the left or right of the given position.
 * Return the value returned by __m_cc_replace().
 */
int
__m_cc_expand(WINDOW *w, int y, int x, int side)
{
	cchar_t	cc;
	int	dx, width;

	width = __m_cc_width(&w->_line[y][x]);

	if (side < 0)
		dx = __m_cc_next(w, y, x) - width;
	else if (0 < side)
		dx = __m_cc_first(w, y, x);
	else
		return (-1);

	/*
	 * __m_cc_replace() will erase the region containing
	 * the character we want to expand.
	 */
	cc = w->_line[y][x];

	return (__m_cc_replace(w, y, dx, &cc, 0));
}

/* Revised version of __m_cc_compare() to compare only the char parts */

int
__m_cc_equal(const cchar_t *c1, const cchar_t *c2)
{
	int	i;

	if (c1->_f != c2->_f)
		return (0);
	if (c1->_n != c2->_n)
		return (0);
	for (i = 0; i < c1->_n; ++i)
		if (c1->_wc[i] != c2->_wc[i])
			return (0);
	return (1);
}

/*
 * Return true if characters are equal.
 *
 * NOTE to guarantee correct results, make sure that both
 * characters have been passed through __m_cc_sort().
 */
int
__m_cc_compare(const cchar_t *c1, const cchar_t *c2, int exact)
{
	int	i;

	if (exact && c1->_f != c2->_f)
		return (0);
	if (c1->_n != c2->_n)
		return (0);
	if ((c1->_at & ~WA_COOKIE) != (c2->_at & ~WA_COOKIE))
		return (0);
	if (c1->_co != c2->_co)
		return (0);

	for (i = 0; i < c1->_n; ++i)
		if (c1->_wc[i] != c2->_wc[i])
			return (0);

	return (1);
}

/*
 * Write to the stream the character portion of a cchar_t.
 */
int
__m_cc_write(const cchar_t *cc)
{
	int	j;
	size_t	i;
	char	mb[MB_LEN_MAX];
/*
 * 4131273 UNIX98: xcurses library renders complex characters incorrectly
 */
	int	backed_up = 0;

	for (i = 0; i < cc->_n; ++i) {
		j = wctomb(mb, cc->_wc[i]);
		if (j == -1)
			return (EOF);
		if (i == 1) {
			/*
			 * Move cursor back where it was
			 */
			if (fwrite(cursor_left, 1, strlen(cursor_left),
				__m_screen->_of) == 0) {
				return (EOF);
			}
			backed_up = 1;
		}
		if (fwrite(mb, sizeof (*mb), (size_t)j, __m_screen->_of) == 0) {
			return (EOF);
		}
	}
	if (backed_up) {
		/*
		 * Move cursor back where it was
		 */
		if (fwrite(cursor_right, 1, strlen(cursor_right),
			__m_screen->_of) == 0) {
			return (EOF);
		}
	}

	__m_screen->_flags |= W_FLUSH;
	return (0);
}
