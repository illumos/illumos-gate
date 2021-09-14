/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
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

/*LINTLIBRARY*/

#include	<sys/types.h>
#include	"curses_inc.h"

/*
 * The following array gives the number of tens of milliseconds per
 * character for each speed as returned by gtty.  Thus since 300
 * baud returns a 7, there are 33.3 milliseconds per char at 300 baud.
 */
static short tmspc10[] = {
	0,	/* 0 baud */
	2000,	/* 50 baud */
	1333,	/* 75 baud */
	909,	/* 110 baud */
	743,	/* 134 baud */
	666,	/* 150 baud */
	500,	/* 200 baud */
	333,	/* 300 baud */
	166,	/* 600 baud */
	83,	/* 1200 baud */
	55,	/* 1800 baud */
	41,	/* 2400 baud */
	20,	/* 4800 baud */
	10,	/* 9600 baud */
	5,	/* 19200 baud */
	2,	/* 38400 baud */
	2,	/* 57600 baud */
	1,	/* 76800 baud */
	1,	/* 115200 baud */
	1,	/* 153600 baud */
	1,	/* 230400 baud */
	1,	/* 307200 baud */
	1,	/* 460800 baud */
	1,	/* 921600 baud */
	1,	/* 1000000 baud */
	1,	/* 1152000 baud */
	1,	/* 1500000 baud */
	1,	/* 2000000 baud */
	1,	/* 2500000 baud */
	1,	/* 3000000 baud */
	1,	/* 3500000 baud */
	1,	/* 4000000 baud */
};

/*
 * Insert a delay into the output stream for "delay/10" milliseconds.
 * Round up by a half a character frame, and then do the delay.
 * Too bad there are no user program accessible programmed delays.
 * Transmitting pad characters slows many terminals down and also
 * loads the system.
 */

int
_delay(int delay, int (*outc)(char))
{
	int	mspc10;
	char	pc;
	int	outspeed;

	/* if there is no pad character, then just return */
	if (no_pad_char)
		goto good;

#ifdef SYSV
	outspeed = _BRS(PROGTTYS);
#else	/* SYSV */
	outspeed = _BR(PROGTTY);
#endif	/* SYSV */
	if (outspeed <= 0 || outspeed >=
	    (sizeof (tmspc10) / sizeof (tmspc10[0])))
		return (ERR);

	mspc10 = tmspc10[outspeed];
	delay += mspc10 / 2;
	if (pad_char)
		pc = *pad_char;
	else
		pc = 0;
	for (delay /= mspc10; delay-- > 0; )
		(*outc)(pc);
good:
	return (OK);
}
