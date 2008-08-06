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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"__clock_timer.s"

#include "SYS.h"

/*
 * int
 * __clock_getres(clockid_t clock_id, timespec_t *res)
 */

	ENTRY(__clock_getres)
	SYSTRAP_RVAL1(clock_getres)
	SYSCERROR
	RET
	SET_SIZE(__clock_getres)

/*
 * int
 * __clock_settime(clockid_t clock_id, timespec_t *tp)
 */

	ENTRY(__clock_settime)
	SYSTRAP_RVAL1(clock_settime)
	SYSCERROR
	RET
	SET_SIZE(__clock_settime)

/*
 * int
 * __timer_create(clockid_t clock_id, struct sigevent *evp, timer_t *timerid)
 */

	ENTRY(__timer_create)
	SYSTRAP_RVAL1(timer_create)
	SYSCERROR
	RET
	SET_SIZE(__timer_create)

/*
 * int
 * __timer_delete(timer_t timerid)
 */

	ENTRY(__timer_delete)
	SYSTRAP_RVAL1(timer_delete)
	SYSCERROR
	RET
	SET_SIZE(__timer_delete)

/*
 * int
 * __timer_getoverrun(timer_t timerid)
 */

	ENTRY(__timer_getoverrun)
	SYSTRAP_RVAL1(timer_getoverrun)
	SYSCERROR
	RET
	SET_SIZE(__timer_getoverrun)

/*
 * int
 * __timer_gettime(timer_t timerid, struct itimerspec *value)
 */

	ENTRY(__timer_gettime)
	SYSTRAP_RVAL1(timer_gettime)
	SYSCERROR
	RET
	SET_SIZE(__timer_gettime)

/*
 * int
 * __timer_settime(timer_t timerid, int flags,
 *	const struct itimerspec *value, struct itimerspec *ovalue)
 */

	ENTRY(__timer_settime)
	SYSTRAP_RVAL1(timer_settime)
	SYSCERROR
	RET
	SET_SIZE(__timer_settime)

/*
 * int
 * __nanosleep(const timespec_t *rqtp, timespec_t *rmtp)
 */

	ENTRY(__nanosleep)
	SYSTRAP_RVAL1(nanosleep)
	SYSLWPERR
	RET
	SET_SIZE(__nanosleep)
