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

#include	<sys/types.h>
#include	"curses_inc.h"

/*
 * This is useful after saving/restoring memory from a file (e.g. as
 * in a rogue save game).  It assumes that the modes and windows are
 * as wanted by the user, but the terminal type and baud rate may
 * have changed.
 */

extern	char	_called_before;

int
/* The next line causes a lint warning because errret is not used */
restartterm(char *term, int filenum, int *errret)
/* int	filenum - This is a UNIX file descriptor, not a stdio ptr. */
{
	int	saveecho = SP->fl_echoit;
	int	savecbreak = cur_term->_fl_rawmode;
	int	savenl;

#ifdef	SYSV
	savenl = PROGTTYS.c_iflag & ONLCR;
#else	/* SYSV */
	savenl = PROGTTY.sg_flags & CRMOD;
#endif	/* SYSV */

	_called_before = 0;
	(void) setupterm(term, filenum, (int *) 0);

	/* Restore curses settable flags, leaving other stuff alone. */
	SP->fl_echoit = saveecho;

	(void) nocbreak();
	(void) noraw();
	if (savecbreak == 1)
		(void) cbreak();
	else
		if (savecbreak == 2)
			(void) raw();

	if (savenl)
		(void) nl();
	else
		(void) nonl();

	(void) reset_prog_mode();

	LINES = SP->lsize;
	COLS = columns;
	return (OK);
}
