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
#include	<fcntl.h>

/*
 * Set the current time-out period for getting input.
 *
 * delay:	< 0 for infinite delay (blocking read)
 * 		= 0 for no delay read
 * 		> 0 to specify a period in millisecs to wait
 *		for input, then return '\0' if none comes
 */

static void	_setblock(int), _settimeout(int);

int
ttimeout(int delay)
{
	if (cur_term->_inputfd < 0)
		return (ERR);

	if (delay < 0)
		delay = -1;

	if (cur_term->_delay == delay)
		goto good;

#ifdef	SYSV
	if (delay > 0) {
		if (cur_term->_delay < 0)
			_setblock(-delay);
		_settimeout(delay);
	} else
		if ((delay + cur_term->_delay) == -1)
			_setblock(delay);
		else {
			if (delay < 0)
				_setblock(delay);
			_settimeout(delay);
		}
#else	/* SYSV */
	cbreak();
#endif	/* SYSV */

	cur_term->_delay = delay;
good:
	return (OK);
}

#ifdef	SYSV
/* set the terminal to nodelay (==0) or block(<0) */
static	void
_setblock(int block)
{
	int	flags = fcntl(cur_term->_inputfd, F_GETFL, 0);

	if (block < 0)
		flags &= ~O_NDELAY;
	else
		flags |= O_NDELAY;

	(void) fcntl(cur_term->_inputfd, F_SETFL, flags);
}

/*
 * set the terminal to timeout in t milliseconds,
 * rounded up to the nearest 10th of a second.
 */
static	void
_settimeout(int num)
{
	PROGTTYS.c_lflag &= ~ICANON;
	if (num > 0) {
		PROGTTYS.c_cc[VMIN] = 0;
		PROGTTYS.c_cc[VTIME] = (num > 25500) ? 255 : (num + 99) / 100;
		cur_term->_fl_rawmode = 3;
	} else {
		PROGTTYS.c_cc[VMIN] = 1;
		PROGTTYS.c_cc[VTIME] = 0;
		cur_term->_fl_rawmode = 1;
	}
	(void) reset_prog_mode();
}
#endif	/* SYSV */
