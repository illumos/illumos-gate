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

/* Define global variables */

#include	<sys/types.h>
#include	"curses_inc.h"

WINDOW	*stdscr, *curscr, *_virtscr;
int	LINES, COLS, TABSIZE, COLORS, COLOR_PAIRS;
short	curs_errno = -1;
int	(*_setidln)(void), (*_useidln)(void),
	(*_quick_ptr)(WINDOW *, chtype);
int	(*_do_slk_ref)(void), (*_do_slk_tch)(void), (*_do_slk_noref)(void);
void	(*_rip_init)(void);		/* to initialize rip structures */
void	(*_slk_init)(void);		/* to initialize slk structures */
SCREEN	*SP;
MOUSE_STATUS Mouse_status = {-1, -1, {BUTTON_RELEASED, BUTTON_RELEASED,
			    BUTTON_RELEASED}, 0};

#ifdef	_VR3_COMPAT_CODE
void	(*_y16update)(WINDOW *, int, int, int, int);
chtype	*acs32map;

#undef	acs_map
_ochtype	*acs_map;
#else	/* _VR3_COMPAT_CODE */
chtype		*acs_map;
#endif	/* _VR3_COMPAT_CODE */

char	*curses_version = "SVR4", curs_parm_err[32];
bool	_use_env = TRUE;

#ifdef	DEBUG
FILE	*outf = stderr;		/* debug output file */
#endif	/* DEBUG */

short	_csmax,		/* max size of a multi-byte character */
	_scrmax;	/* max size of a multi-column character */
bool	_mbtrue;	/* a true multi-byte character */
