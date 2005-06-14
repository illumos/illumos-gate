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
/*	  All Rights Reserved  	*/

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

/* TRUE => all 8 bits of input character should be passed through. */

int
_meta(int bf)
{
	/*
	 * Do the appropriate fiddling with the tty driver to make it send
	 * all 8 bits through.  On SYSV this means clearing ISTRIP, on
	 * V7 you have to resort to RAW mode.
	 */
#ifdef	SYSV
	if (bf)
		PROGTTYS.c_iflag &= ~ISTRIP;
	else
		PROGTTYS.c_iflag |= ISTRIP;
	(void) reset_prog_mode();
#else	/* SYSV */
	if (bf)
		raw();
	else
		noraw();
#endif	/* SYSV */

	/* Do whatever is needed to put the terminal into meta-mode. */

	if ((SP->fl_meta = bf) != 0)
		(void) tputs(meta_on, 1, _outch);
	else
		(void) tputs(meta_off, 1, _outch);
	(void) fflush(SP->term_file);
	return (OK);
}
