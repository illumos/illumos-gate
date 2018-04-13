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
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * slk.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#include <private.h>

/*
 * Flag for initialisation soft label keys once setupterm() has been called.
 */
int
slk_init(int fmt)
{
	int code = ERR;

#ifdef M_CURSES_TRACE
	__m_trace("slk_init(%d)", fmt);
#endif

	if (0 <= fmt && fmt <= 1) {
		__m_slk_format = fmt;
		code = OK;
	}

	return __m_return_code("slk_init", code);
}

int
slk_attron(const chtype at)
{
	int code = ERR;

#ifdef M_CURSES_TRACE
	__m_trace("slk_attron(%lx)", at);
#endif

	if (__m_screen->_slk._w != NULL)
		code = wattron(__m_screen->_slk._w, at);

	return __m_return_code("slk_attron", code);
}

int
slk_attroff(const chtype at)
{
	int code = ERR;

#ifdef M_CURSES_TRACE
	__m_trace("slk_attroff(%lx)", at);
#endif

	if (__m_screen->_slk._w != NULL)
		code = wattroff(__m_screen->_slk._w, at);

	return __m_return_code("slk_attroff", code);
}

int
slk_attrset(const chtype at)
{
	int code = ERR;

#ifdef M_CURSES_TRACE
	__m_trace("slk_attrset(%lx)", at);
#endif

	if (__m_screen->_slk._w != NULL)
		code = wattrset(__m_screen->_slk._w, at);

	return __m_return_code("slk_attrset", code);
}

int
slk_attr_off(const attr_t at, void *opts)
{
	int code = ERR;

#ifdef M_CURSES_TRACE
	__m_trace("slk_attr_off(%x, %p)", at, opts);
#endif

	if (__m_screen->_slk._w != NULL)
		code = wattr_off(__m_screen->_slk._w, at, opts);

	return __m_return_code("slk_attr_off", code);
}

int
slk_attr_on(const attr_t at, void *opts)
{
	int code = ERR;

#ifdef M_CURSES_TRACE
	__m_trace("slk_attr_on(%x, %p)", at, opts);
#endif

	if (__m_screen->_slk._w != NULL)
		code = wattr_on(__m_screen->_slk._w, at, opts);

	return __m_return_code("slk_attr_on", code);
}

int
slk_attr_set(const attr_t at, short co, void *opts)
{
	int code = ERR;

#ifdef M_CURSES_TRACE
	__m_trace("slk_attr_set(%x, %d, %p)", at, co, opts);
#endif

	if (__m_screen->_slk._w != NULL)
		code = wattr_set(__m_screen->_slk._w, at, co, opts);

	return __m_return_code("slk_attr_set", code);
}

int
slk_color(short co)
{
	int code = ERR;

#ifdef M_CURSES_TRACE
	__m_trace("slk_color(%d)", co);
#endif

	if (__m_screen->_slk._w != NULL)
		code = wcolor_set(__m_screen->_slk._w, co, NULL);

	return __m_return_code("slk_color", code);
}

int 
slk_touch()
{
	int code = ERR;

#ifdef M_CURSES_TRACE
	__m_trace("slk_touch(void)");
#endif

	if (__m_screen->_slk._w != NULL)
		code = wtouchln(__m_screen->_slk._w, 0, 1, 1);

	return __m_return_code("slk_touch", code);
}

int 
slk_clear()
{
	int code = ERR;

#ifdef M_CURSES_TRACE
	__m_trace("slk_clear(void)");
#endif

	if (__m_screen->_slk._w != NULL) {
		if (werase(__m_screen->_slk._w) == OK)
			code = wrefresh(__m_screen->_slk._w);
	} else if (label_off != NULL) {
		(void) tputs(label_off, 1, __m_outc);
		(void) fflush(__m_screen->_of);
		code = OK;
	}
	
	return __m_return_code("slk_clear", code);
}

int 
slk_restore()
{
	int i, code = ERR;

#ifdef M_CURSES_TRACE
	__m_trace("slk_clear(void)");
#endif

	if (__m_screen->_slk._w != NULL) {
		for (i = 0; i < 8; ++i) {
			if (__m_screen->_slk._labels[i] != NULL) {
				(void) slk_set(
					i, __m_screen->_slk._labels[i],
					__m_screen->_slk._justify[i]
				);
			}
		}

		code = slk_refresh();
	} else if (label_on != NULL) {
		(void) tputs(label_on, 1, __m_outc);
		(void) fflush(__m_screen->_of);
		code = OK;
	}
	
	return __m_return_code("slk_clear", code);
}

int
slk_noutrefresh() 
{
	int code = ERR;

#ifdef M_CURSES_TRACE
	__m_trace("slk_noutrefresh(void)");
#endif

	if (__m_screen->_slk._w != NULL)
		code = wnoutrefresh(__m_screen->_slk._w);

	return __m_return_code("slk_noutrefresh", code);
}

int
slk_refresh()
{
	int code = ERR;

#ifdef M_CURSES_TRACE
	__m_trace("slk_refresh(void)");
#endif

	if ((code = slk_noutrefresh()) == OK)
		code = doupdate();

	return __m_return_code("slk_refresh", code);
}

char *
slk_label(int index)
{
#ifdef M_CURSES_TRACE
	__m_trace("slk_label(%d)", index);
#endif

	return __m_return_pointer("slk_label", __m_screen->_slk._labels[index]);
}

int
slk_set(int index, const char *label, int justify)
{
	int code = ERR;
	wchar_t wcs[M_CCHAR_MAX * 8 + 1];

#ifdef M_CURSES_TRACE
	__m_trace("slk_set(%d, %p, %d)", index, label, justify);
#endif

	if (0 < mbstowcs(wcs, label, sizeof wcs)) 
		code = slk_wset(index, wcs, justify);

	return __m_return_code("slk_set", code);
}

int
slk_wset(int index, const wchar_t *label, int justify)
{
	cchar_t cc;
	short (*k)[2];
	int i, width, code = ERR;
	wchar_t wcs[M_CCHAR_MAX * 8 + 1], *wp;
	char mbs[MB_LEN_MAX * ((1 + M_CCHAR_MAX) * 8) + 1];

	/* 
	 * These label start columns assume 80 columns in order to
	 * fit 8 _slk._labels of 8 columns.
	 */
	static short format[][8] = {
		{ 0, 10, 20, 31, 41, 52, 62, 72 },
		{ 0, 10, 20, 30, 42, 52, 62, 72 },
	};

#ifdef M_CURSES_TRACE
	__m_trace("slk_wset(%d, %p, %d)", index, label, justify);
#endif

	if (index < 1 || 8 < index || justify < 0 || 2 < justify)
		goto error1;

	if (label == NULL)
		label = M_MB_L("");

	/* Copy the characters that fill the first 8 columns of the label. */
	for (wp = wcs, width = 0; *label != '\0'; label += i, wp += cc._n) {
		if ((i = __m_wcs_cc(label, A_NORMAL, 0, &cc)) < 0)
			goto error1;	


		if (8 < (width += __m_cc_width(&cc)))
			break;

		(void) wcsncpy(wp, cc._wc, cc._n);
	}
	*wp = '\0';

	if (wcstombs(mbs, wcs, sizeof mbs) == (size_t) -1)
		goto error1;

	/* Remember the new label. */
	__m_screen->_slk._justify[index] = (short) justify;
	if (__m_screen->_slk._labels[index] != NULL)
		free(__m_screen->_slk._labels[index]);
	if ((__m_screen->_slk._labels[index] = m_strdup(mbs)) == NULL)
		goto error1;
	
	if (__m_screen->_slk._w != NULL) {
		/* Write the justified label into the slk window. */
		i = format[__m_slk_format][index];
		(void) __m_cc_erase(__m_screen->_slk._w, 0, i, 0, i + 7);

		switch (justify) {
		case 0:
			break;
		case 1:
			i += width / 2;
			break;
		case 2:
			i = i + 8 - width;
			break;
		}

		(void) mvwaddstr(__m_screen->_slk._w, 0, i, mbs);
	} else if (plab_norm != NULL) {
		(void) tputs(
			tparm(
				plab_norm, (long) index, (long) mbs,
				0L, 0L, 0L, 0L, 0L, 0L, 0L
			), 1, __m_outc
		);
	} else if (pkey_plab != NULL) {
		/* Lookup multibyte sequence for the function key. */
		for (i = KEY_F(index), k = __m_keyindex; (*k)[1] != i; ++k)
			;

		if (cur_term->_str[**k] != NULL) {
			(void) tputs(
				tparm(
					pkey_plab, (long) index, 
					(long) cur_term->_str[**k], 
					(long) mbs, 0L, 0L, 0L, 0L, 0L, 0L
				), 1, __m_outc
			);
		}
	}

	code = OK;
error1:
	return __m_return_code("slk_wset", code);
}
