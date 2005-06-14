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
#include	<unistd.h>
#include	"curses_inc.h"

int
reset_shell_mode(void)
{
#ifdef	DIOCSETT
	/*
	 * Restore any virtual terminal setting.  This must be done
	 * before the TIOCSETN because DIOCSETT will clobber flags like xtabs.
	 */
	cur_term -> old.st_flgs |= TM_SET;
	(void) ioctl(cur_term->Filedes, DIOCSETT, &cur_term -> old);
#endif	/* DIOCSETT */
#ifdef	SYSV
	if (_BRS(SHELLTTYS)) {
		if (shell_istermios < 0) {
			int i;

			SHELLTTY.c_lflag = SHELLTTYS.c_lflag;
			SHELLTTY.c_oflag = SHELLTTYS.c_oflag;
			SHELLTTY.c_iflag = SHELLTTYS.c_iflag;
			SHELLTTY.c_cflag = SHELLTTYS.c_cflag;
			for (i = 0; i < NCC; i++)
				SHELLTTY.c_cc[i] = SHELLTTYS.c_cc[i];
			(void) ioctl(cur_term -> Filedes, TCSETAW, &SHELLTTY);
		} else
			(void) ioctl(cur_term -> Filedes, TCSETSW, &SHELLTTYS);
#ifdef	LTILDE
		if (cur_term -> newlmode != cur_term -> oldlmode)
			(void) ioctl(cur_term -> Filedes, TIOCLSET,
			    &cur_term -> oldlmode);
#endif	/* LTILDE */
	}
#else	/* SYSV */
	if (_BR(SHELLTTY)) {
		(void) ioctl(cur_term -> Filedes, TIOCSETN, &SHELLTTY);
#ifdef	LTILDE
		if (cur_term -> newlmode != cur_term -> oldlmode)
			(void) ioctl(cur_term -> Filedes, TIOCLSET,
			    &cur_term -> oldlmode);
#endif	/* LTILDE */
	}
#endif	/* SYSV */
	return (OK);
}
