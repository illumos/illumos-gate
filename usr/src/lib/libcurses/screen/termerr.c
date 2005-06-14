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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include	"curses_inc.h"
#include	"_curs_gettext.h"
#include <signal.h>   /* use this file to determine if this is SVR4.0 system */
#include <sys/types.h>

char    *term_err_strings[8];
static int first_term_err_message = 0;

void
termerr(void)
{
	if (first_term_err_message == 0) {
		first_term_err_message = 1;
		term_err_strings[0] =
#ifdef SIGSTOP  /* SVR4.0 and beyond */
	_curs_gettext("/usr/share/lib/terminfo is unaccessible");
#else
	_curs_gettext("/usr/lib/terminfo is unaccessible");
#endif
		term_err_strings[1] =
	_curs_gettext("I don't know anything about your \"%s\" terminal");
		term_err_strings[2] =
	_curs_gettext("corrupted terminfo entry");
		term_err_strings[3] =
	_curs_gettext("terminfo entry too long");
		term_err_strings[4] =
	_curs_gettext("TERMINFO pathname for device exceeds 512 characters");
		term_err_strings[5] =
#ifdef DEBUG
		"malloc returned NULL in function \"%s\"";
#else
	_curs_gettext("malloc returned NULL");
#endif /* DEBUG */
		term_err_strings[6] =
	_curs_gettext("terminfo file for \"%s\" terminal is not readable");
	}

	(void) fprintf(stderr, _curs_gettext("Sorry, "));
	(void) fprintf(stderr, term_err_strings[term_errno-1], term_parm_err);
	(void) fprintf(stderr, ".\r\n");
}
