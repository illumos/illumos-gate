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
savetty(void)
{
#ifdef SYSV
	if (prog_istermios < 0) {
		int i;

		PROGTTY.c_lflag = PROGTTYS.c_lflag;
		PROGTTY.c_oflag = PROGTTYS.c_oflag;
		PROGTTY.c_iflag = PROGTTYS.c_iflag;
		PROGTTY.c_cflag = PROGTTYS.c_cflag;
		for (i = 0; i < NCC; i++)
			PROGTTY.c_cc[i] = PROGTTYS.c_cc[i];
		SP->save_tty_buf = PROGTTY;
	} else
		SP->save_tty_bufs = PROGTTYS;
#else	/* SYSV */
	SP->save_tty_buf = PROGTTY;
#endif	/* SYSV */
#ifdef DEBUG
#ifdef SYSV
	if (outf)
		fprintf(outf, "savetty(), file %x, SP %x, flags %x,%x,%x,%x\n",
	cur_term->Filedes, SP, PROGTTYS.c_iflag, PROGTTYS.c_oflag,
	PROGTTYS.c_cflag, PROGTTYS.c_lflag);
#else
	if (outf)
		fprintf(outf, "savetty(), file %x, SP %x, flags %x\n",
	cur_term->Filedes, SP, PROGTTY.sg_flags);
#endif
#endif
	return (OK);
}
