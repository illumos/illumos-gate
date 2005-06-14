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

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/archsystm.h>

#include <sys/clock.h>
#include <sys/debug.h>
#include <sys/smp_impldefs.h>
#include <sys/rtc.h>

/*
 * This file contains all generic part of clock and timer handling.
 * Specifics are now in a seperate file and may be overridden by OEM
 * modules which get loaded. Defaults come from i8254.c and hardclk.c
 */
unsigned int microdata = 50;	/* loop count for 10 microsecond wait. */
				/* MUST be initialized for those who */
				/* insist on calling "tenmicrosec" before */
				/* the clock has been initialized. */

timestruc_t (*todgetf)(void) = pc_tod_get;
void (*todsetf)(timestruc_t) = pc_tod_set;

long gmt_lag;		/* offset in seconds of gmt to local time */

/*
 * Write the specified time into the clock chip.
 * Must be called with tod_lock held.
 */
void
tod_set(timestruc_t ts)
{
	ASSERT(MUTEX_HELD(&tod_lock));

	/*
	 * Prevent false alarm in tod_validate() due to tod value change.
	 */
	tod_fault_reset();
	(*todsetf)(ts);
}

/*
 * Read the current time from the clock chip and convert to UNIX form.
 * Assumes that the year in the clock chip is valid.
 * Must be called with tod_lock held.
 */
timestruc_t
tod_get(void)
{
	timestruc_t ts;

	ASSERT(MUTEX_HELD(&tod_lock));

	ts = (*todgetf)();
	ts.tv_sec = tod_validate(ts.tv_sec);
	return (ts);
}

void
sgmtl(long arg)
{
	gmt_lag = arg;
}

long
ggmtl(void)
{
	return (gmt_lag);
}

/* rtcsync() - set 'time', assuming RTC and GMT lag are correct */

void
rtcsync(void)
{
	timestruc_t ts;

	mutex_enter(&tod_lock);
	ts = (*todgetf)();
	set_hrestime(&ts);
	mutex_exit(&tod_lock);
}
