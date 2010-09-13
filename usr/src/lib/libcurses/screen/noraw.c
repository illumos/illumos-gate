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

int
noraw(void)
{
#ifdef	SYSV
	/* Enable interrupt characters */
	PROGTTYS.c_lflag |= (ISIG|ICANON);
	PROGTTYS.c_cc[VEOF] = _CTRL('D');
	PROGTTYS.c_cc[VEOL] = 0;
	PROGTTYS.c_iflag |= IXON;
#else	/* SYSV */
	PROGTTY.sg_flags &= ~(RAW|CBREAK);
#endif	/* SYSV */

#ifdef	DEBUG
#ifdef	SYSV
	if (outf)
		fprintf(outf, "noraw(), file %x, flags %x\n",
		    cur_term->Filedes, PROGTTYS.c_lflag);
#else	/* SYSV */
	if (outf)
		fprintf(outf, "noraw(), file %x, flags %x\n",
		    cur_term->Filedes, PROGTTY.sg_flags);
#endif	/* SYSV */
#endif	/* DEBUG */

	cur_term->_fl_rawmode = FALSE;
	cur_term->_delay = -1;
	(void) reset_prog_mode();
#ifdef	FIONREAD
	cur_term->timeout = 0;
#endif	/* FIONREAD */
	return (OK);
}
