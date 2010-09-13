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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * scr_dump.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/scr_dump.c 1.1 1995/06/21 16:19:43 ant Exp $";
#endif
#endif

#include <private.h>
#include <sys/types.h>
#include <sys/stat.h>

/*
 * Save the current screen image.
 */
int
scr_dump(f)
const char *f;
{
	int code;
	FILE *fp;

#ifdef M_CURSES_TRACE
	__m_trace("scr_dump(%p=\"%s\")", f);
#endif

	code = ERR;

	if ((fp = fopen(f, "wF")) != (FILE *) 0) {
		code = putwin(curscr, fp);
		(void) fclose(fp);
	}

	return __m_return_code("scr_dump", code);
}

static int
scr_replace(w, f)
WINDOW *w;
const char *f;
{
	int i;
	FILE *fp;
	WINDOW *new;

	if ((fp = fopen(f, "rF")) == (FILE *) 0)
		return ERR;

	new = getwin(fp);
	(void) fclose(fp);

	if (new == (WINDOW *) 0)
		return ERR;

	if (new->_maxy != w->_maxy || new->_maxx != w->_maxx) {
		(void) delwin(new);
		return ERR;
	}

	/* Replace contents of curscr window structure. */
	free(w->_base);
	free(w->_line);
	free(w->_first);
	*w = *new;

	/* Rehash the current screen? */
	if (w == curscr)
		for (i = 0; i < w->_maxy; ++i)
			__m_cc_hash(w, __m_screen->_hash, i);

	/* Discard the working window. */
	new->_base = (cchar_t *) 0;
	new->_line = (cchar_t **) 0;
	new->_first = (short *) 0;
	(void) delwin(new);

	return OK;
}

/*
 * A picture of what scr_restore(), scr_init(), and scr_set() do :
 *
 *				scr_restore()		scr_init()
 *				    |			    |
 *	stdscr			    V			    V
 *	+----+			 newscr			 curscr
 *	|    | 			+-------+		+-------+
 *	+----+  refresh() ->	|	|		|	|
 *				|	| doupdate() ->	|	|
 *	  w			|	| 		|	|
 *	+----+  wrefresh(w) ->	|	|		|	|
 *	|    | 			+-------+		+-------+
 *	+----+                        ^			  ^
 *				      |	                  |
 *				      \---- scr_set() ----/
 */

/*
 * Get a screen image that will appear next doupdate(),
 * replacing the current screen.
 */
int
scr_restore(f)
const char *f;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("scr_restore(%p=\"%s\")", f);
#endif

	code = scr_replace(__m_screen->_newscr, f);

	return __m_return_code("scr_restore", code);
}

/*
 * Get the screen image that really reflects what is on the screen,
 * though the applicatiion may not want it.  A subsequent doupdate()
 * will compared and make changes against this image.
 */
int
scr_init(f)
const char *f;
{
	int code;
	struct stat tty, dump;

#ifdef M_CURSES_TRACE
	__m_trace("scr_init(%p=\"%s\")", f);
#endif

	if ((non_rev_rmcup && exit_ca_mode != (char *) 0)
	|| stat(f, &dump) != 0 || stat(ctermid((char *) 0), &tty) != 0
	|| dump.st_mtime < tty.st_mtime)
		code = ERR;
	else
		code = scr_replace(__m_screen->_curscr, f);

	return __m_return_code("scr_init", code);
}

/*
 * Get the screen image that is really on the screen and that the
 * application wants on the screen.
 */
int
scr_set(f)
const char *f;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("scr_set(%p=\"%s\")", f);
#endif

	if ((code = scr_init(f)) == OK)
		code = scr_restore(f);

	return __m_return_code("scr_set", code);
}

