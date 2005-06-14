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

/*
 * Routines to deal with setting and resetting modes in the tty driver.
 * See also setupterm.c in the termlib part.
 */
#include <sys/types.h>
#include "curses_inc.h"

int
cbreak(void)
{
	/*
	 * This optimization is here because till SVR3.1 curses did not come up
	 * in cbreak mode and now it does.  Therefore, most programs when they
	 * call cbreak won't pay for it since we'll know we're in the right
	 * mode.
	 */

	if (cur_term->_fl_rawmode != 1) {
#ifdef SYSV
	/*
	 * You might ask why ICRNL has anything to do with cbreak.
	 * The problem is that there are function keys that send
	 * a carriage return (some hp's).  Curses cannot virtualize
	 * these function keys if CR is being mapped to a NL.  Sooo,
	 * when we start a program up we unmap those but if you are
	 * in nocbreak then we map them back.  The reason for that is that
	 * if a getch or getstr is done and you are in nocbreak the tty
	 * driver won't return until it sees a new line and since we've
	 * turned it off any program that has nl() and nocbreak() would
	 * force the user to type a NL.  The problem with the function keys
	 * only gets solved if you are in cbreak mode which is OK
	 * since program taking action on a function key is probably
	 * in cbreak because who would expect someone to press a function
	 * key and then return ?????
	 */

		PROGTTYS.c_iflag &= ~ICRNL;
		PROGTTYS.c_lflag &= ~ICANON;
		PROGTTYS.c_cc[VMIN] = 1;
		PROGTTYS.c_cc[VTIME] = 0;
#else
		PROGTTY.sg_flags |= (CBREAK | CRMOD);
#endif

#ifdef DEBUG
#ifdef SYSV
		if (outf)
			fprintf(outf, "cbreak(), file %x, flags %x\n",
			    cur_term->Filedes, PROGTTYS.c_lflag);
#else
		if (outf)
			fprintf(outf, "cbreak(), file %x, flags %x\n",
			    cur_term->Filedes, PROGTTY.sg_flags);
#endif
#endif
		cur_term->_fl_rawmode = 1;
		cur_term->_delay = -1;
		(void) reset_prog_mode();
#ifdef FIONREAD
		cur_term->timeout = 0;
#endif /* FIONREAD */
	}
	return (OK);
}
