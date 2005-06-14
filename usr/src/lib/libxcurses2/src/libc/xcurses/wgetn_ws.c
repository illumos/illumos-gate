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
 * wgetn_ws.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] =
"$Header: /team/ps/sun_xcurses/archive/local_changes/xcurses/src/lib/"
"libxcurses/src/libc/xcurses/rcs/wgetn_ws.c 1.7 1998/06/04 19:56:00 "
"cbates Exp $";
#endif
#endif

#include <private.h>
#include <limits.h>
#include <stdlib.h>
#include <m_wio.h>

static wint_t	fld_key;
static int	fld_echo;	/* Software echo flag. */
static int	fld_index;	/* Number of characters in fld_buffer. */
static int	fld_bytes;	/* fld_index expressed in bytes. */
static int	fld_mb;		/* Field is a multibyte character string. */
static wint_t	*fld_buffer;	/* Wide character buffer. */
static int	fld_maxlength;	/* Character length of buffer. */
static WINDOW	*fld_window;
static int	fld_row, fld_col;	/* Start of field in fld_window. */

static int	fld_done(void);
static int	fld_erase(void);
static int	fld_kill(void);
static int	fld_insert(void);

typedef struct t_key_entry {
	int	type;
	wint_t	code;
	int	(*func)(void);
} t_key_entry;

#define	ERASE_KEY	0
#define	KILL_KEY	1
#define	EOF_KEY		2
#define	EOL_KEY		3

static t_key_entry	key_table[] = {
	{ OK, 0, fld_erase },
	{ OK, 0, fld_kill },
#if VEOF == VMIN
	{ OK, '\x04', fld_done },
	{ OK, '\r', fld_done },
#else
	{ OK, 0, fld_done },
	{ OK, 0, fld_done },
#endif
	{ OK, '\n', fld_done },
	{ OK, WEOF, fld_done },
	{ KEY_CODE_YES, KEY_LEFT, fld_erase },
	{ KEY_CODE_YES, KEY_BACKSPACE, fld_erase },
	{ KEY_CODE_YES, KEY_ENTER, fld_done },
	{ ERR, 0, fld_insert }
};

/*
 * The effect of wgetnstr() is as though a series of calls to wgetch()
 * were made, until a <newline> or <return> are received.  The
 * resulting value is placed in the area pointed to by the character
 * pointer 's'.  wgetnstr() reads at most n characters, thus
 * preventing a possible overflow of the input buffer.  The user's
 * erase and kill characters are interpreted.
 *
 * If n < 0, wgetnstr() will read until a <newline> or <return> is
 * entered.  To accept functions keys, keypad() must be set for the
 * window.
 */
int
__m_wgetn_wstr(WINDOW *w, void *s, int n, int mb_flag)
{
	int	type;
	wchar_t	wc;
	t_key_entry	*k;
	struct termios	saved;

	if (n == 0) {
	    *(char *)s = '\0';
	    return (OK);
	}
	fld_window = w;
	fld_index = 0;
	fld_bytes = 0;
	fld_mb = mb_flag;

	/* Read at most N bytes from the field. */
	fld_maxlength = n < 0 ? LINE_MAX : n;

	/* Make sure there is enough to hold the largest characater. */
	if (fld_mb && (fld_maxlength < (int)MB_CUR_MAX))
		return (ERR);

	if (mb_flag) {
		/*
		 * Create a wint_t buffer, which makes it easier to
		 * handle erasing characters from the line.
		 */
		fld_buffer = (wint_t *) calloc(fld_maxlength + 1,
			sizeof (*fld_buffer));
		if (fld_buffer == NULL)
			return (ERR);
	} else {
		fld_buffer = (wint_t *) s;
	}

#if VEOF != VMIN
	(void) __m_tty_wc(VEOL, &wc);
	key_table[EOL_KEY].code = (wint_t) wc;
	(void) __m_tty_wc(VEOF, &wc);
	key_table[EOF_KEY].code = (wint_t) wc;
#endif
	(void) __m_tty_wc(VKILL, &wc);
	key_table[KILL_KEY].code = (wint_t) wc;
	(void) __m_tty_wc(VERASE, &wc);
	key_table[ERASE_KEY].code = (wint_t) wc;

	getyx(fld_window, fld_row, fld_col);

	/*
	 * We remember if the user specified echo on or off, then disable it
	 * so that wgetch() doesn't perform any echoing before we've had a
	 * chance to process the key.  fld_insert() will handle the necessary
	 * echoing of characters.
	 */
	fld_echo = __m_set_echo(0);
	saved = *PTERMIOS(_prog);

	if (!(cur_term->_flags & __TERM_HALF_DELAY))
		(void) cbreak();

	for (; ; ) {
		if ((type = wget_wch(fld_window, &fld_key)) == ERR)
			break;

		for (k = key_table; k->type != ERR; ++k) {
			if (k->type == type && k->code == fld_key) {
				break;
			}
		}

		if (k->func != (int (*)(void)) NULL && !(*k->func)()) {
			/* If the edit function returned false then quit. */
			fld_buffer[fld_index] = '\0';
			break;
		}
	}

	/* Restore the I/O settings. */
	(void) __m_set_echo(fld_echo);
	(void) __m_tty_set(&saved);

	if (mb_flag) {
		(void) wistombs((char *) s, fld_buffer, fld_maxlength-1);
		free(fld_buffer);
	}

	return ((type == ERR) ? ERR : OK);
}

static int
wint_len(wint_t wc)
{
	int	len;
	char	mb[MB_LEN_MAX];

	if (wc == WEOF)
		return (0);

	len = wctomb(mb, (wchar_t) wc);

	return ((len < 0) ? 0 : len);
}

static int
fld_done(void)
{
	cchar_t	cc;

	if (fld_echo) {
		(void) __m_wc_cc(fld_key, &cc);
		(void) wadd_wch(fld_window, &cc);
	}
	return (0);
}

static int
fld_erase(void)
{
	int	x, y, width;

	if (fld_index <= 0) {
		fld_buffer[fld_index-1] = 0;
		return (1);
	}

	width = wcwidth(fld_buffer[--fld_index]);
	fld_bytes -= wint_len(fld_buffer[fld_index]);
	fld_buffer[fld_index] = '\0';
	getyx(fld_window, y, x);

	if (0 < x) {
		/* Rubout previous character. */
		x -= width;
	} else if (0 < y) {
		/* Reverse line wrap. */
		--y;
		x = fld_window->_maxx - 1;

		/*
		 * Find end of previous character, skipping any background
		 * character that may have been written by auto-wrap.
		 */
		while (fld_buffer[fld_index] != fld_window->_line[y][x]._wc[0])
			--x;

		/* Find first column of character. */
		x = __m_cc_first(fld_window, y, x);
	}

	(void) __m_cc_erase(fld_window, y, x, y, x);

	fld_window->_cury = (short) y;
	fld_window->_curx = (short) x;

	return (1);
}

static int
fld_kill(void)
{
	int	y, x;

	getyx(fld_window, y, x);
	(void) __m_cc_erase(fld_window, fld_row, fld_col, y, x);

	fld_window->_cury = (short) fld_row;
	fld_window->_curx = (short) fld_col;
	fld_index = fld_bytes = 0;
	fld_buffer[0] = '\0';

	return (1);
}

static int
fld_insert(void)
{
	cchar_t	cc;
	t_wide_io	*wio;

	if (fld_maxlength <= (fld_index + 1))
		/* Completely full, terminate input. */
		return (0);

	wio = (t_wide_io *) __m_screen->_in;

	/*
	 * Don't exceed the byte length for the field.
	 *
	 * m_wio_get() called by wget_wch(), records the
	 * number of bytes converted, when _next == _size.
	 *
	 * wget_wch() makes sure that _next == _size by
	 * pushing invalid multibyte characters on to an
	 * input stack.
	 */
	if (fld_mb && fld_maxlength < fld_bytes + wio->_size) {
		/* Is there still room for single-byte characters? */
		if (fld_bytes < fld_maxlength) {
			(void) beep();
			return (1);
		}

		/* Completely full, terminate input. */
		return (0);
	}

	if (0 <= fld_key) {
		fld_buffer[fld_index++] = fld_key;
		fld_bytes += wio->_size;

		if (fld_echo) {
			(void) __m_wc_cc(fld_key, &cc);
			(void) wadd_wch(fld_window, &cc);
		}
	} else {
		(void) beep();
	}

	return (1);
}

int
wgetnstr(WINDOW *w, char *s, int n)
{
	int	code;

	code = __m_wgetn_wstr(w, (void *) s, n, 1);

	return (code);
}

int
wgetn_wstr(WINDOW *w, wint_t *s, int n)
{
	int	code;

	code = __m_wgetn_wstr(w, (void *) s, n, 0);

	return (code);
}
