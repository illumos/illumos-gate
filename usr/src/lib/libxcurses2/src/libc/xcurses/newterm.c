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
 * newterm.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char const rcsID[] =
"$Header: /team/ps/sun_xcurses/archive/local_changes/xcurses/src/lib/"
"libxcurses/src/libc/xcurses/rcs/newterm.c 1.13 1998/06/04 19:55:52 "
"cbates Exp $";
#endif
#endif

#include <sys/isa_defs.h>
#include <private.h>
#include <m_wio.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

int	LINES, COLS;
int	COLORS, COLOR_PAIRS;

WINDOW	*curscr;
WINDOW	*stdscr;
SCREEN	*__m_screen;

static short	assume_one_line = FALSE;

/*
 * Assume terminal has only one screen line by restricting those
 * capabilities that assume more than one line.  This function must
 * be called before initscr() or newterm().
 *
 * This flag will reset after initscr() or newterm() so that subsequent
 * calls to newterm(), without a preceding call to filter(), will load
 * an unmodified terminal.  THIS IS NOT HISTORICAL PRACTICE, BUT DEEMED
 * USEFUL.
 */
void
filter(void)
{
	assume_one_line = TRUE;
}

/*
 * SIGTSTP Handler.
 */
/* ARGSUSED */
void
tstp(int signo)
{
#ifdef SIGTSTP
	/*
	 * Only permit SIGTSTP if the curent process is the process
	 * group leader.  If the process is not the current group
	 * leader, then suspending the current process will suspend
	 * other members of the process group, such as the parent
	 * process.
	 */
	if (getpid() == getpgrp()) {
		(void) endwin();

#ifdef SIG_UNBLOCK
		{
			sigset_t unblock;

			(void) sigemptyset(&unblock);
			(void) sigaddset(&unblock, SIGTSTP);
			(void) sigprocmask(SIG_UNBLOCK, &unblock,
				(sigset_t *) 0);
		}
#endif /* SIG_UNBLOCK */
		(void) signal(SIGTSTP, SIG_DFL);
		(void) kill(0, SIGTSTP);
	} else {
		(void) beep();
	}

	(void) signal(SIGTSTP, tstp);
	(void) wrefresh(curscr);
#else /* no SIGTSTP */
	(void) beep();
#endif /* SIGTSTP */
}

int	__m_slk_format = -1;

/*
 * Do real soft label key initialisation once setupterm() have been called
 * to load the current terminal.  Determine whether the terminal supplies
 * soft label keys, or whether we have to fake it by using the last line
 * of a terminal screen.
 */
/* ARGSUSED */
int
__m_slk_init(SCREEN *sp, int style)
{
	int	code;

	code = ERR;

	(void) memset(&sp->_slk, 0, sizeof (sp->_slk));

	/* Does the terminal have a method to program the soft label key? */
	if (plab_norm != NULL || pkey_plab  != NULL) {
		code = OK;
		goto done;
	}

	/* We have to fake it. */
	if (lines < 2)
		goto done;

	sp->_slk._w = subwin(sp->_newscr, 1, 0, lines-1, 0);
	if (sp->_slk._w == NULL)
		goto done;

	/* Test suite seems to expect this */
	(void) wattrset(sp->_slk._w, A_DIM|A_REVERSE);
	(void) ripoffline(-1, 0);
	code = OK;
done:
	return (code);
}

/*
 * The XCurses specification is unclear how ripoffline() would
 * affect newterm().  We assume that it can't be used with newterm()
 * and that it only affects initscr(), which is responsible for
 * creating stdscr.
 */
t_rip	rip = { 0 };

/*
 * If line is positive (1), one line is removed from the beginning of
 * stdscr; else if line is negative (-1), one line is removed from the end.
 */
int
ripoffline(int line, int (*init)(WINDOW *, int))
{
	int	i;

	i = rip.top - rip.bottom;

	if (line != 0 && i < M_CURSES_MAX_RIPOFFLINE) {
		rip.line[i].init = init;
		if (line < 0)
			rip.line[i].dy = --rip.bottom;
		else
			rip.line[i].dy = rip.top++;
	}

	return (OK);
}

/*
 * Create a new terminal screen.  Used if a program is going to be sending
 * output to more than one terminal.  It returns a SCREEN* for the terminal.
 * The parameters are a terminal name, output FILE*, and input FILE*.  If
 * the terminal name is null then $TERM is used.  The program must also
 * call endwin() for each terminal being used before exiting from curses.
 * If newterm() is called more than once for the same terminal, the first
 * terminal referred to must be the last one for which endwin() is called.
 */
SCREEN *
newterm(char *term, FILE *out_fp, FILE *in_fp)
{
	WINDOW	*w;
	t_wide_io	*wio;
	SCREEN	*sp, *osp;
	int	i, n, y, errret;

	/*
	 * Input stream should be unbuffered so that m_tfgetc() works
	 * correctly on BSD and SUN systems.
	 */
	(void) setvbuf(in_fp, (char *) 0, _IONBF, BUFSIZ);
#if 0
/*
 * Not sure whether we really want to concern ourselves with the output
 * buffer scheme.  Might be best to leave it upto the application to
 * deal with buffer schemes and when to perform flushes.
 *
 * MKS Vi uses MKS Curses and so must support the ability to switch in
 * and out of Curses mode when switching from Vi to Ex and back.
 * Problem is that in Vi mode you would prefer full buffered output to
 * give updates a smoother appearance and Ex mode you require line
 * buffered in order to see prompts and messages.
 */
	(void) setvbuf(out_fp, (char *) 0, _IOLBF, BUFSIZ);
#endif
	errno = 0;

	if (__m_setupterm(term, fileno(in_fp), fileno(out_fp), &errret)
		== ERR) {
		switch (errret) {
		case -1:
			errno = ENOMEM;
			break;
		case 2:
			errno = ENAMETOOLONG;
			break;
		case 0:
		default:
			errno = ENOENT;
			break;
		}
		goto error1;
	}

	if (__m_doupdate_init())
		goto error1;

	if ((sp = (SCREEN *) calloc(1, sizeof (*sp))) == NULL)
		goto error1;

	sp->_kfd = -1;
	sp->_if = in_fp;
	sp->_of = out_fp;
	sp->_term = cur_term;

	sp->_unget._size = __m_decode_init((t_decode **) &sp->_decode);

	/*
	 * Maximum length of a multbyte key sequence, including
	 * multibyte characters and terminal function keys.
	 */
	if (sp->_unget._size < (M_TYPEAHEAD_SIZE + MB_LEN_MAX))
		sp->_unget._size = M_TYPEAHEAD_SIZE + MB_LEN_MAX;

	sp->_unget._stack = calloc((size_t) sp->_unget._size,
		sizeof (*sp->_unget._stack));
	if (sp->_unget._stack == NULL)
		goto error2;

	if ((wio = (t_wide_io *) calloc(1, sizeof (*wio))) == NULL)
		goto error2;

	/* Setup wide input for XCurses. */
	wio->get = (int (*)(void *)) wgetch;
	wio->unget = __xc_ungetc;
	wio->reset = __xc_clearerr;
	wio->iserror = __xc_ferror;
	wio->iseof = __xc_feof;
	sp->_in = wio;

	if (assume_one_line) {
		/* Assume only one line. */
		lines = 1;

		/* Disable capabilities that assume more than one line. */
		clear_screen = clr_eos = cursor_up = cursor_down = NULL;
		cursor_home = cursor_to_ll = cursor_address = NULL;
		row_address = parm_up_cursor = parm_down_cursor = NULL;

		/* Re-evaluate the cursor motion costs. */
		__m_mvcur_cost();

		/* Reset flag for subsequent calls to newterm(). */
		assume_one_line = FALSE;
	}

	if ((sp->_curscr = newwin(lines, columns, 0, 0)) == NULL)
		goto error2;

	if ((sp->_newscr = newwin(lines, columns, 0, 0)) == NULL)
		goto error2;

#if defined(_LP64)
	sp->_hash = (unsigned int *) calloc(lines, sizeof (*sp->_hash));
#else
	sp->_hash = (unsigned long *) calloc(lines, sizeof (*sp->_hash));
#endif
	if (sp->_hash == NULL)
		goto error2;

	if (0 <= __m_slk_format && __m_slk_init(sp, __m_slk_format) == ERR) {
		goto error2;
	}

	/*
	 * doupdate() will perform the final screen preparations like
	 * enter_ca_mode, reset_prog_mode() (to assert the termios
	 * changes), etc.
	 */
	sp->_flags |= S_ENDWIN;

#ifdef SIGTSTP
	(void) signal(SIGTSTP, tstp);
#endif
	/* Assert that __m_screen is set to the new terminal. */
	osp = set_term(sp);

	/* Disable echo in tty driver, Curses does software echo. */
	PTERMIOS(_prog)->c_lflag &= ~ECHO;

	/* Enable mappnig of cr -> nl on input and nl -> crlf on output. */
	PTERMIOS(_prog)->c_iflag |= ICRNL;
	PTERMIOS(_prog)->c_oflag |= OPOST;
#ifdef ONLCR
	PTERMIOS(_prog)->c_oflag |= ONLCR;
#endif
	cur_term->_flags |= __TERM_NL_IS_CRLF;

#ifdef TAB0
	/* Use real tabs. */
	PTERMIOS(_prog)->c_oflag &= ~(TAB1|TAB2|TAB3);
#endif

	/*
	 * Default to 'cbreak' mode as per
	 * test /tset/CAPIxcurses/fcbreak/fcbreak1{4}
	 */
	cur_term->_flags &= ~__TERM_HALF_DELAY;

	/*
	 * Default to 'idcok' mode as per
	 * test /tset/CAPIxcurses/fidcok/fidcok1{3}
	 */
	__m_screen->_flags |= S_INS_DEL_CHAR;

	PTERMIOS(_prog)->c_cc[VMIN] = 1;
	PTERMIOS(_prog)->c_cc[VTIME] = 0;
	PTERMIOS(_prog)->c_lflag &= ~ICANON;

	(void) __m_tty_set_prog_mode();
	(void) __m_set_echo(1);
	(void) typeahead(fileno(in_fp));

	(void) __m_slk_clear(1);

	n = rip.top - rip.bottom;
	if (stdscr == NULL) {
		stdscr = newwin(lines - n, 0, rip.top, 0);
		if (stdscr == NULL)
			goto error3;
	}
	/*
	 * Create and initialise ripped off line windows.
	 * It is the application's responsiblity to free the
	 * windows when the application terminates.
	 */
	for (i = 0; i < n; ++i) {
		if (rip.line[i].created)
			continue;
		y = rip.line[i].dy;
		if (y < 0)
			y += lines;

		w = newwin(1, 0, y, 0);
		if (rip.line[i].init != (int (*)(WINDOW *, int)) 0)
			(void) (*rip.line[i].init)(w, columns);
		rip.line[i].created = 1;
	}
	LINES = stdscr->_maxy = sp->_curscr->_maxy - n;

	return (sp);
error3:
	(void) set_term(osp);
error2:
	delscreen(sp);
error1:
	return (NULL);
}

/*
 * Free storage associated with a screen structure.
 * NOTE endwin() does not do this.
 */
void
delscreen(SCREEN *sp)
{
	if (sp != NULL) {
		if (sp->_slk._w != NULL)
			(void) delwin(sp->_slk._w);

		(void) delwin(sp->_newscr);
		(void) delwin(sp->_curscr);
		(void) del_curterm(sp->_term);

		__m_decode_free((t_decode **) &sp->_decode);

		if (sp->_hash != NULL)
			free(sp->_hash);

		if (sp->_unget._stack != NULL)
			free(sp->_unget._stack);

		if (sp->_in != NULL)
			free(sp->_in);

		free(sp);
	}
}

/*
 * Switch current terminal for Curses layer.
 */
SCREEN *
set_term(SCREEN *screen)
{
	SCREEN	*osp = __m_screen;

	if (screen != NULL) {
		(void) set_curterm(screen->_term);
		curscr = screen->_curscr;
		__m_screen = screen;

		LINES = lines;
		COLS = columns;
		COLORS = max_colors;
		COLOR_PAIRS = max_pairs;
	}

	return (osp);
}

int
typeahead(int fd)
{
	__m_screen->_flags &= ~S_ISATTY;
	if (fd != -1) {
		if (isatty(fd)) {
			__m_screen->_kfd = fd;
			__m_screen->_flags |= S_ISATTY;
		} else {
			__m_screen->_kfd = -1;
		}
	}

	return (OK);
}

int
__m_set_echo(int bf)
{
	int	old;

	old = (__m_screen->_flags & S_ECHO) == S_ECHO;

	__m_screen->_flags &= ~S_ECHO;
	if (bf)
		__m_screen->_flags |= S_ECHO;

	return (old);
}
