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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/wgetch.c 1.5 1995/06/19 16:12:13 ant Exp $";
#endif
#endif

#include <private.h>

/*
 * Push single-byte character back onto the input queue.
 *
 * MKS EXTENSION permits the return value of wgetch(), which 
 * can be a KEY_ value, to be pushed back.
 */
int
ungetch(ch)
int ch;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("ungetch(%d)", ch);
#endif
	code = __xc_ungetc(ch, (WINDOW *) 0) == EOF ? ERR : OK;

	return __m_return_code("ungetch", code);
}

/*
 * Push a single-byte character or KEY_ value but onto the
 * input queue.  Ignore the window parameter.
 */
int
__xc_ungetc(int ch, void *w)
{
	if (ISFULL())
		return EOF;

	PUSH(ch);

	return 0;
}

/*
 * Return true if the SCREEN's stream has an I/O error.
 * Ignore the window parameter.
 */
int
__xc_ferror(void *w)
{
	return ferror(__m_screen->_if);
}

/*
 * Return true if the SCREEN's stream has seen EOF.
 * Ignore the window parameter.
 */
int
__xc_feof(void *w)
{
	return feof(__m_screen->_if);
}

/*
 * Clear the error and eof flags of the SCREEN's stream.
 * Ignore the window parameter.
 */
void
__xc_clearerr(void *w)
{
	clearerr(__m_screen->_if);
}

int 
wgetch(w)
WINDOW *w;
{
	t_decode *node;
	int ch, i, j, timeout;

#ifdef M_CURSES_TRACE
	__m_trace("wgetch(%p) at (%d, %d).", w, w->_cury, w->_curx);
#endif

	(void) wrefresh(w);

	if (!ISEMPTY())
		return __m_return_int("wgetch", POP());

	/* Only change the terminal's input method if the window 
	 * requires different settings from what is currently set.
	 * We do this because tcsetattr() on some systems can be
	 * _really_ slow to do for each character. 
	 *
	 * NOTE that halfdelay() overrides nodelay() and wtimeout().
	 */ 
	if (!(cur_term->_flags & __TERM_HALF_DELAY) 
	&& (cur_term->_prog.c_cc[VMIN] != w->_vmin
	|| cur_term->_prog.c_cc[VTIME] != w->_vtime)) {
		cur_term->_prog.c_cc[VMIN] = w->_vmin; 
		cur_term->_prog.c_cc[VTIME] = w->_vtime; 

		if (__m_tty_set(&cur_term->_prog) == ERR)
			return __m_return_int("wgetch", EOF);
	}

	if (req_for_input != (char *) 0)
		(void) tputs(req_for_input, 1, __m_outc);

	clearerr(__m_screen->_if);
	ch = fgetc(__m_screen->_if);

	/* Only check for function keys if keypad is true and we 
	 * did not read a KEY_ value (which are < 0), nor EOF.
	 * It is conceivable that a KEY_ was pushed back with 
	 * ungetch().
	 */
	if ((w->_flags & W_USE_KEYPAD) && 0 <= ch && ch != EOF) {
		/* Treat the termios ERASE key the same as key_backspace. 
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
		if (cur_term->_shell.c_cc[VERASE] != _POSIX_VDISABLE)
#endif
			if (ch == cur_term->_shell.c_cc[VERASE])
				return __m_return_int("wgetch", KEY_BACKSPACE);

		/* Begin check for function key. */
		node = (t_decode *) __m_screen->_decode;

		/* Use input stack as a queue. */
		timeout = w->_flags & W_USE_TIMEOUT;
		for (RESET(); !ISFULL(); ) {
			PUSH(ch);

			while (node->ch != ch) {
				node = node->sibling;
				if (node == (t_decode *) 0)
					goto invalid;
			}

			/* Found funuction key? */
			if (node->key != 0) {
				RESET();
				return __m_return_int("wgetch", node->key);
			}

			/* Setup interbyte timer (once only).  fgetc() will 
			 * return EOF if no input received, which may not be 
			 * a true EOF.
			 */
			if (timeout) {
				cur_term->_prog.c_cc[VMIN] = 0;	
				cur_term->_prog.c_cc[VTIME] = 
					M_CURSES_INTERBYTE_TIME;
				(void) __m_tty_set(&cur_term->_prog);
			}
			timeout = 0;

			if ((ch = fgetc(__m_screen->_if)) == EOF)
				/* Timeout or real eof. */
				break;

			/* Incomplete sequence, continue. */
			node = node->child;
		}
invalid:
		/* Reverse contents of the input queue to form a stack. */
		for (i = 0, j = __m_screen->_unget._count; i < --j; ++i) {
			ch = __m_screen->_unget._stack[i];
			__m_screen->_unget._stack[i] = 
				__m_screen->_unget._stack[j];
			__m_screen->_unget._stack[j] = ch;
		}
			
		/* Return first byte received or EOF. */
		ch = POP();
	}

	if ((__m_screen->_flags & S_ECHO) && 0 <= ch && ch != EOF)  {
		(void) waddch(w, ch);
		(void) wrefresh(w);
	}

	return __m_return_int("wgetch", ch);
}

