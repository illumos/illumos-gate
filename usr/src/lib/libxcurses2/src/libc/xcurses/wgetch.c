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
 * Copyright (c) 1995-1998, 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

/*
 * wgetch.c
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
"libxcurses/src/libc/xcurses/rcs/wgetch.c 1.23 1998/06/05 16:38:43 "
"cbates Exp $";
#endif
#endif

#include <private.h>
#include <string.h>
#include <errno.h>

static struct termios	read_termios;

int
iqContainsFullLine(void)
{
	int	i;

	if (!(PTERMIOS(_prog)->c_lflag & ICANON)) {
		/*
		 * Non-canonical mode ...
		 * Don't care about full lines ... continue
		 */
		return (1);
	}
	if (read_termios.c_lflag & ICANON) {
		/*
		 * Terminal subsystem worries about lines etc. ...
		 * continue ...
		 */
		return (1);
	}
	/* We turned off ICANON so we have to do it ourselves */
	if ((read_termios.c_cc[VMIN] == 0) &&
		(read_termios.c_cc[VTIME] != 0)) {
		/* We set delay mode. Only error if noting in the read */
		return (!iqIsEmpty());
	}
	for (i = __m_screen->_unget._count - 1; i >= 0; i--) {
		int	ch = __m_screen->_unget._stack[i];
		if (PTERMIOS(_shell)->c_cc[VEOL] == ch)
			return (1);
		if ('\n' == ch)
			return (1);
	}
	return (0);
}

void
iqPush(unsigned int ch)
{
	if (__m_screen->_unget._count >= __m_screen->_unget._size)
		return;
	__m_screen->_unget._stack[__m_screen->_unget._count++] =
		(int) ch;
}

void
iqAdd(unsigned int ch)
{
	int	count;

	if (++(__m_screen->_unget._count) >= __m_screen->_unget._size)
		__m_screen->_unget._count = __m_screen->_unget._size - 1;
	count = __m_screen->_unget._count - 1;
	if (count) {
		(void) memmove(__m_screen->_unget._stack + 1,
			__m_screen->_unget._stack, count * sizeof (int));
	}
	__m_screen->_unget._stack[0] = (int) ch;
}

int
iqIsEmpty(void)
{
	return (__m_screen->_unget._count == 0);
}

void
iqReset(void)
{
	__m_screen->_unget._count = 0;
}

/* Assumes count > 0 */
int
iqPull(void)
{
	int	ch;

	ch = __m_screen->_unget._stack[--(__m_screen->_unget._count)];
	return (ch);
}

/* Discard n characters from front of Q */
void
iqTrash(int n)
{
	__m_screen->_unget._count -= n;
	if (__m_screen->_unget._count < 0) {
		__m_screen->_unget._count = 0;
	}
}

int
iqGetNth(int n)
{
	int	ch;

	if (__m_screen->_unget._count - n <= 0) {
		return (EOF);
	}
	ch = __m_screen->_unget._stack[__m_screen->_unget._count - n - 1];
	return (ch);
}


struct termios
__m_tty_override_mode(int vmin, int vtime)
{
	struct termios	rval;
	struct termios	newstuff;

	rval = newstuff = *PTERMIOS(_actual);

	/* If halfdelay mode. Leave canonical mode intact */
	if (!(vmin == 0 && vtime == 0) &&
		(cur_term->_flags & __TERM_HALF_DELAY))
		return (rval);

	/* If blocking mode. Leave canonical mode intact */
	if (vmin == 1)
		return (rval);

	/* VMIN and VTIME trash VEOL and VEOF so canonical cannot work */
	newstuff.c_cc[VMIN] = (cc_t) vmin;
	newstuff.c_cc[VTIME] = (cc_t) vtime;
	newstuff.c_lflag &= ~ICANON;

	(void) __m_tty_set(&newstuff);
	return (rval);
}

int
__m_read_input_char(int *pChar)
{
	if (req_for_input != NULL) {
		(void) TPUTS(req_for_input, 1, __m_outc);
	}
	clearerr(__m_screen->_if);
	*pChar = 0;
	/* save actual setting for later test */
	read_termios = *PTERMIOS(_actual);

	errno = 0;
	if ((*pChar = fgetc(__m_screen->_if)) == EOF) {
		return ((errno) ? ERR : OK);
	}

	if (((PTERMIOS(_prog)->c_cflag & CSIZE) != CS8) && (*pChar != EOF))
		*pChar &= 0x7f;
	return (OK);
}

int
__m_typeahead_read_input_char(int *pChar)
{
	unsigned char	ch;
	ssize_t	r;

	if (req_for_input != NULL) {
		(void) TPUTS(req_for_input, 1, __m_outc);
	}

	*pChar = 0;
	/* save actual setting for later test */
	read_termios = *PTERMIOS(_actual);

	errno = 0;
	if ((r = read(__m_screen->_kfd, (void *)&ch, 1)) > 0) {
		if ((PTERMIOS(_prog)->c_cflag & CSIZE) != CS8) {
			*pChar = ch & 0x7f;
		} else {
			*pChar = (int)ch;
		}
		return (OK);
	} else if (r == 0) {
		*pChar = EOF;
		return (OK);
	} else {
		return (ERR);
	}
}


static int	klugeTypeaheadInGetch = 0;

int
pollTypeahead(void)
{
	struct termios	save;
	int	ch;

	if (!(__m_screen->_flags & S_ISATTY) ||
		!(__m_screen->_flags & S_TYPEAHEAD_OK)) {
		/* Typeahead disabled */
		return (0);
	}
	save = __m_tty_override_mode(0, 0);
	while (__m_typeahead_read_input_char(&ch) == OK) {
		if (ch == EOF)
			break;
		iqAdd(ch);
	}
	(void) __m_tty_set(&save);
	/* if in wgetch, always do refresh */
	return ((klugeTypeaheadInGetch) ? 0 : !iqIsEmpty());
}

/*
 * Push single-byte character back onto the input queue.
 *
 * MKS EXTENSION permits the return value of wgetch(), which
 * can be a KEY_ value, to be pushed back.
 */
int
ungetch(int ch)
{
	iqPush(ch);
	return (OK);
}

/*
 * Return true if the SCREEN's stream has an I/O error.
 * Ignore the window parameter.
 */
/* ARGSUSED */
int
__xc_ferror(void *w)
{
	return (ferror(__m_screen->_if));
}

/* ARGSUSED */
int
__xc_ungetc(int ch, void *w)
{
	iqPush(ch);
	return (1);
}

/*
 * Return true if the SCREEN's stream has seen EOF.
 * Ignore the window parameter.
 */
/* ARGSUSED */
int
__xc_feof(void *w)
{
	return (feof(__m_screen->_if));
}

/*
 * Clear the error and eof flags of the SCREEN's stream.
 * Ignore the window parameter.
 */
/* ARGSUSED */
void
__xc_clearerr(void *w)
{
	clearerr(__m_screen->_if);
}

int
__m_echo(WINDOW *w, int ch)
{
	if (!(__m_screen->_flags & S_ECHO))
		return (ch);
	if (!(0 <= ch && ch != EOF)) {
		(void) beep();
		return (ERR);
	}
	if (ch == '\b') {
		if (w->_curx <= 0) {
			(void) beep();
			return (ch);
		}
		w->_curx--;
		(void) wdelch(w);
	} else {
		(void) waddch(w, ch);
	}
	(void) wrefresh(w);
	return (ch);
}

int
wgetch(WINDOW *w)
{
	t_decode	*node;
	int	ch, i, timeout;
	struct termios	save;

	__m_screen->_flags |= S_TYPEAHEAD_OK;

	klugeTypeaheadInGetch = 1;
	(void) wrefresh(w);
	klugeTypeaheadInGetch = 0;

	if (iqIsEmpty()) {
	    save = __m_tty_override_mode(w->_vmin, w->_vtime);
	    if (__m_read_input_char(&ch) == ERR) {
			(void) __m_tty_set(&save);
			return (ERR);
	    }
	    if (!((ch == EOF) && (PTERMIOS(_prog)->c_lflag & ICANON))) {
			/* Put EOF on Q only in non-canonical mode */
			iqAdd(ch);
	    }
		(void) __m_tty_set(&save);
	}
	ch = iqGetNth(0);
	if (!iqContainsFullLine()) {
	    return (ERR);
	}

	/*
	 * Only check for function keys if keypad is true and we
	 * did not read a KEY_ value (which are < 0), nor EOF.
	 * It is conceivable that a KEY_ was pushed back with
	 * ungetch().
	 */
	if ((w->_flags & W_USE_KEYPAD) && 0 <= ch && ch != EOF) {
		/*
		 * Treat the termios ERASE key the same as key_backspace.
		 *
		 * We used to change the key_backspace entry to be a string
		 * containing the ERASE key in setupterm(), but this would
		 * then disable the real terminfo entry for the backspace key.
		 * Apparently VT300 terminals change the key code/sequence
		 * of the backspace key in application keypad mode.
		 * See SR 6014.
		 *
		 * Refer to _shell instead of _prog, since _shell will
		 * correctly reflect the user's prefered settings, whereas
		 * _prog may not have been initialised if both input and
		 * output have been redirected.
		 */
#ifdef _POSIX_VDISABLE
		if (PTERMIOS(_shell)->c_cc[VERASE] != _POSIX_VDISABLE)
#endif
			if (ch == PTERMIOS(_shell)->c_cc[VERASE]) {
				/* Discard ch from Q */
				(void) iqPull();
				return (KEY_BACKSPACE);
			}

		/* Begin check for function key. */
		node = (t_decode *) __m_screen->_decode;

		/* Use input stack as a queue. */
		timeout = w->_flags & W_USE_TIMEOUT;
		for (i = 1; ; i++) {
			while (node->ch != ch) {
				node = node->sibling;
				if (node == NULL)
					goto uncoded;
			}

			/* Found funuction key? */
			if (node->key != 0) {
				/* Trash all input used to make the FKey */
				iqTrash(i);
				return (__m_echo(w, node->key));
			}

			/*
			 * Get next candidate character -
			 * either from Q or input
			 */
			if ((ch = iqGetNth(i)) == EOF) {
				/*
				 * Setup interbyte timer (once only).
				 * fgetc() will return EOF if no input received,
				 * which may not be a true EOF.
				 */
				if (timeout) {
					(void) __m_tty_override_mode(0,
						M_CURSES_INTERBYTE_TIME);
				}
				timeout = 0;
				if (__m_read_input_char(&ch) == ERR)
				    return (ERR);
				/* Timeout or real eof. */
				if (ch == EOF)
					break;
				iqAdd(ch);
			}

			/* Incomplete sequence, continue. */
			node = node->child;
		}
	}
uncoded:
	/* Return first byte received or EOF. */
	ch = iqPull();
	return (__m_echo(w, ch));
}
