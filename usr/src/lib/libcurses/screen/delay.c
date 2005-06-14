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

/*
 * The following array gives the number of tens of milliseconds per
 * character for each speed as returned by gtty.  Thus since 300
 * baud returns a 7, there are 33.3 milliseconds per char at 300 baud.
 */
static	short	tmspc10[] =
		{
		    /* 0   50    75   110 134.5 150  200  300   baud */
			0, 2000, 1333, 909, 743, 666, 500, 333,
		    /* 600 1200 1800 2400 4800 9600 19200 38400 baud */
			166, 83,  55,  41,  20,  10,   5,    2,
		    /* 57600, 76800, 115200, 153600, 230400 307200 baud */
			2,	1,	1,	1,	1,	1,
		    /* 460800 baud */
			1
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
