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
 * Copyright (c) 2014 Gary Mills
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * This routine converts time as follows.  The epoch is 0000  Jan  1
 * 1970  GMT.   The  argument  time  is  in seconds since then.  The
 * localtime(t) entry returns a pointer to an array containing:
 *
 *		  seconds (0-59)
 *		  minutes (0-59)
 *		  hours (0-23)
 *		  day of month (1-31)
 *		  month (0-11)
 *		  year
 *		  weekday (0-6, Sun is 0)
 *		  day of the year
 *		  daylight savings flag
 *
 * The routine corrects for daylight saving time and  will  work  in
 * any  time  zone provided "timezone" is adjusted to the difference
 * between Greenwich and local standard time (measured in seconds).
 *
 *	 ascftime(buf, format, t)	-> where t is produced by localtime
 *				           and returns a ptr to a character
 *				           string that has the ascii time in
 *				           the format specified by the format
 *				           argument (see date(1) for format
 *				           syntax).
 *
 *	 cftime(buf, format, t) 	-> just calls ascftime.
 *
 *
 *
 */

#include	"lint.h"
#include	<mtlib.h>
#include	<stddef.h>
#include	<time.h>
#include	<limits.h>
#include	<stdlib.h>
#include	<thread.h>
#include	<synch.h>

int
cftime(char *buf, char *format, const time_t *t)
{
	struct tm res;
	struct tm *p;

	p = localtime_r(t, &res);
	if (p == NULL) {
		*buf = '\0';
		return (0);
	}
	/* LINTED do not use ascftime() */
	return (ascftime(buf, format, p));
}

int
ascftime(char *buf, const char *format, const struct tm *tm)
{
	/* Set format string, if not already set */
	if (format == NULL || *format == '\0')
		if (((format = getenv("CFTIME")) == 0) || *format == 0)
			format =  "%+";

	return ((int)strftime(buf, LONG_MAX, format, tm));
}
