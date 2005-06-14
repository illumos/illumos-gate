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

#include	<time.h>
#include	<curses.h>
#include	"wish.h"
#include	"vtdefs.h"
/* #include	"status.h"  empty include file abs 9/14/88 */
#include	"vt.h"
#include	"ctl.h"

void
showdate()
{
	register struct tm	*t;
	char	*ctime();
	static int	oldday;
	static char	*day[] = {
		"Sunday",
		"Monday",
		"Tuesday",
		"Wednesday",
		"Thursday",
		"Friday",
		"Saturday",
	};
	static char	*month[] = {
		"January",
		"February",
		"March",
		"April",
		"May",
		"June",
		"July",
		"August",
		"September",
		"October",
		"November",
		"December",
	};
	extern time_t	Cur_time;	/* EFT abs k16 */

	Cur_time = time( (time_t)0L );

	t = localtime(&Cur_time);
	if (oldday != t->tm_mday) {
		char	datebuf[DATE_LEN];
		register int	n, s;
		register vt_id	oldvid;
		int	r, c;
		int	datecol;

		vt_ctl(STATUS_WIN, CTGETSIZ, &r, &c);
		datecol = (c - DATE_LEN) / 2;
		oldday = t->tm_mday;
		oldvid = vt_current(STATUS_WIN);
		wgo(0, datecol);
		sprintf(datebuf, "AT&T FACE - %s %s %d, %4d", day[t->tm_wday], month[t->tm_mon], t->tm_mday, t->tm_year + 1900);
		s = strlen(datebuf);
		n = (DATE_LEN - s) / 2;
		winprintf("%*s%s%*s", n, "", datebuf, DATE_LEN - n - s, "");
		vt_current(oldvid);
	}
}
