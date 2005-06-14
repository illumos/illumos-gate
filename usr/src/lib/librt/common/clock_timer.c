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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma	weak clock_getres = _clock_getres
#pragma	weak clock_gettime = _clock_gettime
#pragma	weak clock_settime = _clock_settime
#pragma	weak timer_create = _timer_create
#pragma	weak timer_delete = _timer_delete
#pragma	weak timer_getoverrun = _timer_getoverrun
#pragma	weak timer_gettime = _timer_gettime
#pragma	weak timer_settime = _timer_settime

#pragma	weak clock_nanosleep = _clock_nanosleep
#pragma	weak nanosleep = _nanosleep

#include <time.h>
#include <sys/types.h>
#include "pos4.h"

int
_clock_getres(clockid_t clock_id, struct timespec *res)
{
	return (__clock_getres(clock_id, res));
}

int
_clock_gettime(clockid_t clock_id, struct timespec *tp)
{
	return (__clock_gettime(clock_id, tp));
}

int
_clock_settime(clockid_t clock_id, const struct timespec *tp)
{
	return (__clock_settime(clock_id, tp));
}

int
_timer_create(clockid_t clock_id, struct sigevent *evp, timer_t *timerid)
{
	return (__timer_create(clock_id, evp, timerid));
}

int
_timer_delete(timer_t timerid)
{
	return (__timer_delete(timerid));
}

int
_timer_getoverrun(timer_t timerid)
{
	return (__timer_getoverrun(timerid));
}

int
_timer_gettime(timer_t timerid, struct itimerspec *value)
{
	return (__timer_gettime(timerid, value));
}

int
_timer_settime(timer_t timerid, int flags, const struct itimerspec *value,
    struct itimerspec *ovalue)
{
	return (__timer_settime(timerid, flags, value, ovalue));
}

int
_clock_nanosleep(clockid_t clock_id, int flags,
	const struct timespec *rqtp, struct timespec *rmtp)
{
	return (__clock_nanosleep(clock_id, flags, rqtp, rmtp));
}

int
_nanosleep(const struct timespec *rqtp, struct timespec *rmtp)
{
	return (__nanosleep(rqtp, rmtp));
}
