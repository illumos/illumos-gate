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

#include	<sys/time.h>
#include	<string.h>
#include	<stdio.h>
#include	"_conv.h"
#include	"time_msg.h"

/*
 * Translate a struct timeval into a string appropriate for ld(1) and ld.so.1(1)
 * diagnostics.
 */
const char *
conv_time(struct timeval *oldtime, struct timeval *newtime,
    Conv_time_buf_t *time_buf)
{
	int		hour, min;
	time_t		sec;
	suseconds_t	usec;

	sec = newtime->tv_sec - oldtime->tv_sec;
	if (newtime->tv_usec >= oldtime->tv_usec)
		usec = newtime->tv_usec - oldtime->tv_usec;
	else {
		usec = (newtime->tv_usec + MICROSEC) - oldtime->tv_usec;
		sec -= 1;
	}

	/*
	 * The default display is "sec.fraction", but ld(1) has been know to
	 * ascend into minutes, and in worst case scenarios, hours.
	 */
	if ((min = sec / 60) != 0)
		sec = sec % 60;
	if ((hour = min / 60) != 0)
		min = min % 60;

	if (hour)
		(void) snprintf(time_buf->buf, sizeof (time_buf->buf),
		    MSG_ORIG(MSG_TIME_HMSF), hour, min, sec, usec);
	else if (min)
		(void) snprintf(time_buf->buf, sizeof (time_buf->buf),
		    MSG_ORIG(MSG_TIME_MSF), min, sec, usec);
	else
		(void) snprintf(time_buf->buf, sizeof (time_buf->buf),
		    MSG_ORIG(MSG_TIME_SF), sec, usec);

	return ((const char *)time_buf);
}
