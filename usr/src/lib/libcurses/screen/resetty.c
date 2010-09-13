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
resetty(void)
{
#ifdef	SYSV
	if ((_BRS(SP->save_tty_bufs)) != 0) {
		PROGTTYS = SP->save_tty_bufs;
		prog_istermios = 0;
#ifdef	DEBUG
		if (outf)
			fprintf(outf, "resetty(), file %x, SP %x, flags %x, "
			    "%x, %x, %x\n", cur_term->Filedes, SP,
			    PROGTTYS.c_iflag, PROGTTYS.c_oflag,
			    PROGTTYS.c_cflag, PROGTTYS.c_lflag);
#endif	/* DEBUG */
		(void) reset_prog_mode();
	} else if ((_BR(SP->save_tty_buf)) != 0) {
		int i;

		PROGTTY = SP->save_tty_buf;
		prog_istermios = -1;
#ifdef	DEBUG
		if (outf)
			fprintf(outf, "resetty(), file %x, SP %x, flags %x, "
			    "%x, %x, %x\n", cur_term->Filedes, SP,
			    PROGTTY.c_iflag, PROGTTY.c_oflag,
			    PROGTTY.c_cflag, PROGTTY.c_lflag);
#endif	/* DEBUG */
		PROGTTYS.c_lflag = PROGTTY.c_lflag;
		PROGTTYS.c_oflag = PROGTTY.c_oflag;
		PROGTTYS.c_iflag = PROGTTY.c_iflag;
		PROGTTYS.c_cflag = PROGTTY.c_cflag;
		for (i = 0; i < NCC; i++)
			PROGTTYS.c_cc[i] = PROGTTY.c_cc[i];
		(void) reset_prog_mode();
	}
#else	/* SYSV */
	if ((_BR(SP->save_tty_buf)) != 0) {
		PROGTTY = SP->save_tty_buf;
#ifdef	DEBUG
		if (outf)
		    fprintf(outf, "resetty(), file %x, SP %x, flags %x\n",
			cur_term->Filedes, SP, PROGTTY.sg_flags);
#endif	/* DEBUG */
		(void) reset_prog_mode();
	}
#endif	/* SYSV */
	return (OK);
}
