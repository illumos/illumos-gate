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
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * baudrate.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/baudrate.c 1.2 1995/09/27 19:09:07 ant Exp $";
#endif
#endif

#include <private.h>

typedef struct {
	speed_t speed;
	int value;
} t_baud;

static t_baud speeds[] = {
	{ B0, 0 }, 
	{ B50, 50 }, 
	{ B75, 75 }, 
	{ B110, 110 }, 
	{ B134, 134 },
	{ B150, 150 },
	{ B200, 200 }, 
	{ B300, 300 },
	{ B600, 600 },
	{ B1200, 1200 }, 
	{ B1800, 1800 },
	{ B2400, 2400 },
	{ B4800, 4800 }, 
	{ B9600, 9600 }, 
	{ B19200, 19200 },
	{ B38400, 38400 },
	{ (speed_t) -1, -1 }
};

/*f
 * Return the output speed of the terminal.  The number returned is in
 * bits per second and is an integer.
 */
int
baudrate()
{
	int i;
	speed_t value;

#ifdef M_CURSES_TRACE
	__m_trace("baudrate(void)");
#endif

 	value = cfgetospeed(&cur_term->_prog);

	for (i = 0; speeds[i].speed != (speed_t) -1; ++i) 
		if (speeds[i].speed == value)
			break;

	return __m_return_int("baudrate", speeds[i].value);
}
