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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "termio.h"

/*
 * The following macro computes the number of seconds to sleep
 * AFTER waiting for the system buffers to be drained.
 *
 * Various choices:
 *
 *	- A percentage (perhaps even >100%) of the time it would
 *	  take to print the printer's buffer. Use this if it appears
 *	  the printers are affected if the port is closed before they
 *	  finish printing.
 *
 *	- 0. Use this to avoid any extra sleep after waiting for the
 *	  system buffers to be flushed.
 *
 *	- N > 0. Use this to have a fixed sleep after flushing the
 *	  system buffers.
 *
 * The sleep period can be overridden by a single command line argument.
 */
			/* 25% of the print-full-buffer time, plus 1 */
#define LONG_ENOUGH(BUFSZ,CPS)	 (1 + ((250 * BUFSZ) / CPS) / 1000)

extern int		tidbit();

/**
 ** main()
 **/

int
main(int argc, char *argv[])
{
	extern char		*getenv();

	short			bufsz	= -1,
				cps	= -1;

	char			*TERM;

	int			sleep_time	= 0;


	/*
	 * Wait for the output to drain.
	 */
	ioctl (1, TCSBRK, (struct termio *)1);

	/*
	 * Decide how long to sleep.
	 */
	if (argc != 2 || (sleep_time = atoi(argv[1])) < 0)
		if ((TERM = getenv("TERM"))) {
			tidbit (TERM, "bufsz", &bufsz);
			tidbit (TERM, "cps", &cps);
			if (cps > 0 && bufsz > 0)
				sleep_time = LONG_ENOUGH(bufsz, cps);
		} else
			sleep_time = 2;

	/*
	 * Wait ``long enough'' for the printer to finish
	 * printing what's in its buffer.
	 */
	if (sleep_time)
		sleep (sleep_time);

	return (0);
}
