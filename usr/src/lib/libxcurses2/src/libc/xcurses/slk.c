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
 * slk.c
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
"libxcurses/src/libc/xcurses/rcs/slk.c 1.9 1998/05/20 17:26:23 "
"cbates Exp $";
#endif
#endif

#include <private.h>
#include <string.h>

int	__m_slk_labels_on;
int	__m_slk_touched = 0;
/*
 * Flag for initialisation soft label keys once setupterm() has been called.
 */
int
slk_init(int fmt)
{
	int	code = ERR;

	if (0 <= fmt && fmt <= 1) {
		__m_slk_format = fmt;
		__m_slk_labels_on = 1;
		code = OK;
	}

	return (code);
}

int
slk_attron(const chtype at)
{
	int	code = OK;

	if (__m_screen->_slk._w != NULL)
		code = wattron(__m_screen->_slk._w, (int) at);

	return (code);
}

int
slk_attroff(const chtype at)
{
	int	code = OK;

	if (__m_screen->_slk._w != NULL)
		code = wattroff(__m_screen->_slk._w, (int) at);

	return (code);
}

int
slk_attrset(const chtype at)
{
	int	code = OK;

	if (__m_screen->_slk._w != NULL)
		code = wattrset(__m_screen->_slk._w, (int) at);

	return (code);
}

int
slk_attr_off(const attr_t at, void *opts)
{
	int	code = OK;

	if (__m_screen->_slk._w != NULL)
		code = wattr_off(__m_screen->_slk._w, at, opts);

	return (code);
}

int
slk_attr_on(const attr_t at, void *opts)
{
	int	code = OK;

	if (__m_screen->_slk._w != NULL)
		code = wattr_on(__m_screen->_slk._w, at, opts);

	return (code);
}

int
slk_attr_set(const attr_t at, short co, void *opts)
{
	int	code = OK;

	if (__m_screen->_slk._w != NULL)
		code = wattr_set(__m_screen->_slk._w, at, co, opts);

	return (code);
}

int
slk_color(short co)
{
	int	code = OK;

	if (__m_screen->_slk._w != NULL)
		code = wcolor_set(__m_screen->_slk._w, co, (void *) 0);

	return (code);
}

int
slk_touch(void)
{
	int	code = OK;
	WINDOW	*w = __m_screen->_slk._w;

	if (w != NULL) {
		code = wtouchln(w, 0, 1, 1);
		wtouchln_hard(w, 0, 1);
	} else
		__m_slk_touched = 1;

	return (code);
}

/*
 * These label start columns assume 80 columns in order to
 * fit 8 _slk._labels of 8 columns.
 */
static const int	format[][8] = {
	{ 0, 9, 18, 31, 40, 53, 62, 71 },
	{ 0, 9, 18, 27, 44, 53, 62, 71 },
};

#define	_LABEL_LENGTH_MALLOC	\
	(MB_LEN_MAX * ((1 + _M_CCHAR_MAX) * 8) + 1)

void
__m_slk_set_all(void)
{
	int	i;

	for (i = 0; i < 8; ++i) {
		if (__m_screen->_slk._labels[i] != NULL) {
			(void) slk_set(i + 1, __m_screen->_slk._labels[i],
				__m_screen->_slk._justify[i]);
		}
	}
}

int
__m_slk_clear(int kluge)
{
	int	i;
	int	index;
	int	code = ERR;

	if (__m_screen->_slk._w != NULL) {
		cchar_t	_bg = __m_screen->_slk._w->_bg;
		if (kluge) {
			/* Test suite expects spaces to have FG attributes */
			__m_screen->_slk._w->_bg = __m_screen->_slk._w->_fg;
		}
		for (index = 0; index < 8; ++index) {
			i = format[__m_slk_format][index];
			(void) __m_cc_erase(__m_screen->_slk._w,
				0, i, 0, i + 7);
		}
		__m_screen->_slk._w->_bg = _bg;		/* Restore ... */

	} else if (plab_norm != NULL) {
		for (index = 0; index < 8; ++index) {
			char	*p;
			p = __m_screen->_slk._saved[index];
			if (!p) {
				p = (char *)malloc(_LABEL_LENGTH_MALLOC);
				if (p == NULL)
					goto error;
				__m_screen->_slk._saved[index] = p;
			}
			(void) strcpy(p, (kluge) ? "" : "        ");
		}
	}
	if (__m_screen->_slk._w != NULL) {
		code = wrefresh(__m_screen->_slk._w);
	} else {
		__m_slk_labels_on = 0;
		code = slk_refresh();
	}

error:
	return (code);
}

int
slk_clear(void)
{
	return (__m_slk_clear(0));
}

int
slk_restore(void)
{
	int	code;

	__m_slk_set_all();
	__m_slk_labels_on = 1;
	code = slk_refresh();
	return (code);
}

int
slk_noutrefresh(void)
{
	int	code;

	if (__m_screen->_slk._w != NULL)
		code = wnoutrefresh(__m_screen->_slk._w);
	else {
		if (__m_slk_touched) {
			__m_slk_set_all();
			__m_slk_touched = 0;
		}
		if (__m_slk_labels_on) {
			if (label_on != NULL) {
				(void) TPUTS(label_on, 1, __m_outc);
			}
		} else {
			if (label_off != NULL) {
				(void) TPUTS(label_off, 1, __m_outc);
			}
		}
		(void) fflush(__m_screen->_of);
		code = OK;
	}

	return (code);
}

int
slk_refresh(void)
{
	int	code;

	if ((code = slk_noutrefresh()) == OK)
		code = doupdate();

	return (code);
}

void
__m_slk_doupdate(void)
{
	if ((__m_screen->_slk._w == NULL) && plab_norm) {
		int	index;
		for (index = 0; index < 8; index++) {
			char	*s = __m_screen->_slk._saved[index];
			if (s) {
				(void) TPUTS(tparm(plab_norm, (long) index+1,
					(long) s, 0L, 0L, 0L, 0L, 0L, 0L, 0L),
					1, __m_outc);
			}
		}
	}
}

char *
slk_label(int index)
{
	char	*label;

	if (index < 1 || 8 < index) {
		label = NULL;
	} else {
		label = __m_screen->_slk._labels[index-1];
	}
	return (label);
}

int
slk_set(int index, const char *label, int justify)
{
	int	code = ERR;
	wchar_t	wcs[_M_CCHAR_MAX * 8 + 1];

	if ((label == NULL) || *label == '\0')
		label = "        ";
	if (mbstowcs(wcs, label, sizeof (wcs)) != (size_t)-1)
		code = slk_wset(index, wcs, justify);

	return (code);
}

int
slk_wset(int index, const wchar_t *label, int justify)
{
	cchar_t	cc;
	int	i, width, code = ERR;
	wchar_t	wcs[_M_CCHAR_MAX * 8 + 1], *wp;
	char	mbs[_LABEL_LENGTH_MALLOC];
	char	tmbs[_LABEL_LENGTH_MALLOC];
	int	ww = 0;
	int	left1, left2;
	static const char	*spcs = "        ";

	if (index < 1 || 8 < index || justify < 0 || 2 < justify)
		goto error1;

	index--;	/* Shift from {1..8} to {0..7} */

	if (label == NULL)
		label = L"";

	/* Copy the characters that fill the first 8 columns of the label. */
	for (wp = wcs, width = 0; *label != '\0'; label += i, wp += cc._n) {
		if ((i = __m_wcs_cc(label, A_NORMAL, 0, &cc)) < 0)
			goto error1;

		ww += __m_cc_width(&cc);
		if (ww > 8)
			break;
		else
			width = ww;

		(void) wcsncpy(wp, cc._wc, cc._n);
	}
	*wp = '\0';

	if (wcstombs(tmbs, wcs, sizeof (mbs)) == (size_t) -1)
		goto error1;

	if (width == 8) {
		(void) strcpy(mbs, tmbs);
	} else {
		switch (justify) {
		case 0:
			(void) strcpy(mbs, tmbs);
			(void) strncat(mbs, spcs, (8 - width));
			*(mbs + strlen(tmbs) + (8 - width)) = '\0';
			break;
		case 1:
			left1 = (8 - width) / 2;
			(void) strncpy(mbs, spcs, left1);
			(void) strcpy(mbs + left1, tmbs);
			left2 = 8 - width - left1;
			(void) strncat(mbs, spcs, left2);
			*(mbs + left1 + strlen(tmbs) + left2) = '\0';
			break;
		case 2:
			left1 = 8 - width;
			(void) strncpy(mbs, spcs, left1);
			(void) strcpy(mbs + left1, tmbs);
			break;
		}
	}

	/* Remember the new label. */
	__m_screen->_slk._justify[index] = (short) justify;

	if (__m_screen->_slk._labels[index] != NULL)
		free(__m_screen->_slk._labels[index]);
	if ((__m_screen->_slk._labels[index] = strdup(tmbs)) == NULL)
		goto error1;

	if (plab_norm != NULL) {
		char	*p;
		p = __m_screen->_slk._saved[index];
		if (!p) {
			p = (char *)malloc(_LABEL_LENGTH_MALLOC);
			if (p == NULL)
				goto error1;
			__m_screen->_slk._saved[index] = p;
		}
		(void) strcpy(p, mbs);
	}

	__m_slk_labels_on = 1;

	if (__m_screen->_slk._w != NULL) {
		cchar_t	_bg = __m_screen->_slk._w->_bg;
		/* Write the justified label into the slk window. */
		i = format[__m_slk_format][index];
		__m_screen->_slk._w->_bg = __m_screen->_slk._w->_fg;
		(void) __m_cc_erase(__m_screen->_slk._w, 0, i, 0, i + 7);
		__m_screen->_slk._w->_bg = _bg;		/* Restore ... */

		(void) mvwaddstr(__m_screen->_slk._w, 0, i, mbs);
	}

	code = OK;
error1:
	return (code);
}
