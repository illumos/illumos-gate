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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright  (c) 1986 AT&T
 *	All Rights Reserved
 */
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.6 */

#include	<fcntl.h>
#include	<curses.h>
#include	"wish.h"
#include	"vt.h"
#include	"vtdefs.h"

void
showmail(force)
bool	force;
{
	register bool	status;
	static char	mail[]   = "MAIL";
	static char	blanks[] = "    ";
	static bool	last_status;
	static long	last_check;
	extern time_t	Cur_time;	/* EFT abs k16 */
	extern int	Mail_col;
	extern long	Mail_check;
	extern char	*Mail_file;

	if (force || Cur_time - last_check >= Mail_check) {
		register int	fd;
		char	buf[8];

/* Is there an easier way ??? */
		status = ((fd = open(Mail_file, O_RDONLY)) >= 0 && read(fd, buf, sizeof(buf)) == sizeof(buf) && strncmp(buf, "Forward ", sizeof(buf)));
		if (fd >= 0)
			close(fd);
/* ??? */
		if (status == last_status)
			return;
		last_status = status;
/* new */
		{
		WINDOW		*win;
	
		win = VT_array[ STATUS_WIN ].win;
		mvwaddstr( win, 0, Mail_col, status ? mail : blanks );
		if ( status )
			beep();
		}
	}
	last_check = Cur_time;
}
