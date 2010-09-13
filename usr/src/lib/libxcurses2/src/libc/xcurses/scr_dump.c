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

/* LINTLIBRARY */

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
static char rcsID[] =
"$Header: /team/ps/sun_xcurses/archive/local_changes/xcurses/src/lib/"
"libxcurses/src/libc/xcurses/rcs/scr_dump.c 1.6 1998/06/01 16:25:23 "
"cbates Exp $";
#endif
#endif

#include <private.h>
#include <sys/types.h>
#include <sys/stat.h>

/*
 * Save the current screen image.
 */
int
scr_dump(const char *f)
{
	int	code;
	FILE	*fp;

	code = ERR;

	if ((fp = fopen(f, "wF")) != NULL) {
		code = putwin(curscr, fp);
		(void) fclose(fp);
	}

	return (code);
}

static int
scr_replace(WINDOW *w, const char *f)
{
	int	i;
	FILE	*fp;
	WINDOW	*new;

	if ((fp = fopen(f, "rF")) == NULL)
		return (ERR);

	new = getwin(fp);
	(void) fclose(fp);

	if (new == NULL)
		return (ERR);

	if (new->_maxy != w->_maxy || new->_maxx != w->_maxx) {
		(void) delwin(new);
		return (ERR);
	}

	/* Replace contents of curscr window structure. */
	free(w->_base);
	free(w->_line);
	free(w->_first);
	new->_flags &= ~W_CLEAR_WINDOW;	/* Removed default clear command */
	*w = *new;

	/* Rehash the current screen? */
	if (w == curscr)
		for (i = 0; i < w->_maxy; ++i)
			__m_cc_hash(w, __m_screen->_hash, i);

	/* Discard the working window. */
	new->_base = NULL;
	new->_line = NULL;
	new->_first = NULL;
	(void) delwin(new);
	/* Make sure we know where the cursor is */
	(void) __m_mvcur(-1, -1, curscr->_cury, curscr->_curx, __m_outc);
	return (OK);
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
scr_restore(const char *f)
{
	int	code;

	code = scr_replace(__m_screen->_newscr, f);

	return (code);
}

/*
 * Get the screen image that really reflects what is on the screen,
 * though the applicatiion may not want it.  A subsequent doupdate()
 * will compared and make changes against this image.
 */
int
scr_init(const char *f)
{
	int	code;
	struct stat	tty, dump;
	char	*name;

	name = ttyname(cur_term->_ofd);
	if ((non_rev_rmcup && exit_ca_mode != NULL) ||
		stat(f, &dump) != 0 || name == NULL || stat(name, &tty) != 0)
		code = ERR;
	else {
		if (dump.st_mtime < tty.st_mtime)
			code = ERR;
		else {
			code = scr_replace(__m_screen->_curscr, f);
		}
	}

	return (code);
}

/*
 * Get the screen image that is really on the screen and that the
 * application wants on the screen.
 */
int
scr_set(const char *f)
{
	int	code;

	if ((code = scr_init(f)) == OK)
		code = scr_restore(f);

	return (code);
}
