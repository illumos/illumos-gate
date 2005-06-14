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

#include	<stdlib.h>
#include	<sys/types.h>
#include 	"curses_inc.h"
#include 	"_curs_gettext.h"

char	*curs_err_strings[4];
static int  first_curs_err_message = 0;

void
curserr(void)
{
	if (first_curs_err_message == 0) {
		first_curs_err_message = 1;
		curs_err_strings[0] =
	_curs_gettext("I don't know how to deal with your \"%s\" terminal");
		curs_err_strings[1] =
	_curs_gettext("I need to know a more specific terminal type "
	    "than \"%s\"");
		curs_err_strings[2] =
#ifdef DEBUG
		"malloc returned NULL in function \"%s\"";
#else
	_curs_gettext("malloc returned NULL");
#endif /* DEBUG */
	}

	(void) fprintf(stderr, _curs_gettext("Sorry, "));
	(void) fprintf(stderr, curs_err_strings[curs_errno], curs_parm_err);
	(void) fprintf(stderr, ".\r\n");
}
