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

/*
 * baudrate.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#include <private.h>

typedef struct {
	speed_t speed;
	int value;
} t_baud;

static t_baud speeds[] = {
	{ B0,		0 },
	{ B50,		50 },
	{ B75,		75 },
	{ B110,		110 },
	{ B134,		134 },
	{ B150,		150 },
	{ B200,		200 },
	{ B300,		300 },
	{ B600,		600 },
	{ B1200,	1200 },
	{ B1800,	1800 },
	{ B2400,	2400 },
	{ B4800,	4800 },
	{ B9600,	9600 },
	{ B19200,	19200 },
	{ B38400,	38400 },
	{ B57600,	57600 },
	{ B76800,	76800 },
	{ B115200,	115200 },
	{ B153600,	153600 },
	{ B230400,	230400 },
	{ B307200,	307200 },
	{ B460800,	460800 },
	{ B921600,	921600 },
	{ B1000000,	1000000 },
	{ B1152000,	1152000 },
	{ B1500000,	1500000 },
	{ B2000000,	2000000 },
	{ B2500000,	2500000 },
	{ B3000000,	3000000 },
	{ B3500000,	3500000 },
	{ B4000000,	4000000 },
	{ (speed_t)-1,	-1 }
};

/*
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

	for (i = 0; speeds[i].speed != (speed_t) -1; ++i) {
		if (speeds[i].speed == value) {
			break;
		}
	}

	return __m_return_int("baudrate", speeds[i].value);
}
