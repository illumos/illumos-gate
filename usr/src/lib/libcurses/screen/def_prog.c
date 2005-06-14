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

#include <sys/types.h>
#include <unistd.h>
#include "curses_inc.h"

int
def_prog_mode(void)
{
	/* ioctl errors are ignored so pipes work */
#ifdef SYSV
	if ((prog_istermios = ioctl(cur_term -> Filedes,
		TCGETS, &(PROGTTYS))) < 0) {
		int i;

		(void) ioctl(cur_term -> Filedes, TCGETA, &(PROGTTY));
		PROGTTYS.c_lflag = PROGTTY.c_lflag;
		PROGTTYS.c_oflag = PROGTTY.c_oflag;
		PROGTTYS.c_iflag = PROGTTY.c_iflag;
		PROGTTYS.c_cflag = PROGTTY.c_cflag;
		for (i = 0; i < NCC; i++)
			PROGTTYS.c_cc[i] = PROGTTY.c_cc[i];
	}
#else
	(void) ioctl(cur_term -> Filedes, TIOCGETP, &(PROGTTY));
#endif
	return (OK);
}
