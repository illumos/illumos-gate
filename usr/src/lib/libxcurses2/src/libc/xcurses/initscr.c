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
 * initscr.c
 *
 * XCurses Library
 *
 * Copyright 1986, 1994 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] =
"$Header: /team/ps/sun_xcurses/archive/local_changes/xcurses/src/lib/"
"libxcurses/src/libc/xcurses/rcs/initscr.c 1.4 1998/04/30 20:30:21 "
"cbates Exp $";
#endif
#endif

#include <private.h>
#include <errno.h>
#include <stdlib.h>

static const char nomem_msg[] = "Failed to allocate required memory.\n";
static const char noterm_msg[] = "Unknown terminal \"%s\".\n";
static const char dumb_msg[] =
	"Terminal \"%s\" has insufficent capabilities for Curses.\n";

/*
 * Initialize XCurses for use with a single terminal.  stdin and stdout
 * are used.  If a program needs an indication of error conditions,
 * so that it can continue to run in a line-oriented mode, use newterm()
 * instead.
 */
WINDOW *
initscr(void)
{
	SCREEN	*sp;
	char	*term, *err;

	errno = 0;
	sp = newterm(NULL, stdout, stdin);

	if (sp == NULL) {
		err = (errno == ENOMEM) ? (char *)nomem_msg :
			(char *)noterm_msg;
		goto error_1;
	}

	(void) set_term(sp);

	/*
	 * We require some form of cursor positioning and the ability to
	 * clear the end of a line.  These abilities should be sufficient
	 * to provide minimum full screen support.
	 */
	if ((1 < lines) && (cursor_address == NULL) &&
		(row_address == NULL) &&
		((cursor_up == NULL) || (cursor_down == NULL)) &&
		((parm_up_cursor == NULL) || (parm_down_cursor == NULL))) {
		err = (char *)dumb_msg;
		goto error_3;
	}

	if (((1 < lines) && (cursor_address == NULL)) &&
		(column_address == NULL) &&
		((cursor_left == NULL) || (cursor_right == NULL)) &&
		((parm_left_cursor == NULL) ||
		(parm_right_cursor == NULL))) {
		err = (char *)dumb_msg;
		goto error_3;
	}

	if (clr_eol == NULL) {
		err = (char *)dumb_msg;
		goto error_3;
	}

	return (stdscr);

error_3:
	(void) delwin(stdscr);
	(void) endwin();
	(void) delscreen(sp);

error_1:
	/*
	 * newterm()/setupterm() attempts to load $TERM, else if
	 * $TERM is not defined, the vendor's default terminal type.
	 */
	if ((term = getenv("TERM")) == NULL) {
		term = M_TERM_NAME;
	}

	(void) fprintf(stderr, err, term);
	exit(1);
	return (NULL);
}
