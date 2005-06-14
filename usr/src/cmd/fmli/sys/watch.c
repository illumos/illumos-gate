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
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.3 */

#include	<stdio.h>
#include	<sys/types.h>
#include	<sys/times.h>
#include	"wish.h"

clock_t	times();	/* EFT abs k16 */

/*
 * call stopwatch with "0" to "reset", and with a non-zero value
 * to print elapsed times on the stderr
 */
void
stopwatch(flag)
int	flag;
{
	static clock_t	start;	/* EFT abs k16 */
	static struct tms	tbuf;

	if (flag == 0)
		start = times(&tbuf);
	else {
		clock_t	stop;	/* EFT abs k16 */
		struct tms	stoptim;

		stop = times(&stoptim);
#ifdef _DEBUG0
		_debug0(stderr, "Real %d.%02d, User %d.%02d, System %d.%02d\n",
			(stop - start) / 100, (stop - start) % 100,
			(stoptim.tms_utime - tbuf.tms_utime) / 100,
			(stoptim.tms_utime - tbuf.tms_utime) % 100,
			(stoptim.tms_stime - tbuf.tms_stime) / 100,
			(stoptim.tms_stime - tbuf.tms_stime) % 100);
#endif
	}
}
