/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) David L. Mills 1993, 1994
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted, provided
 * that the above copyright notice appears in all copies and that both the
 * copyright notice and this permission notice appear in supporting
 * documentation, and that the name University of Delaware not be used in
 * advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission.	The University of Delaware
 * makes no representations about the suitability this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Modification history kern_ntptime.c
 *
 * 24 Sep 94	David L. Mills
 *	Tightened code at exits.
 *
 * 24 Mar 94	David L. Mills
 *	Revised syscall interface to include new variables for PPS
 *	time discipline.
 *
 * 14 Feb 94	David L. Mills
 *	Added code for external clock
 *
 * 28 Nov 93	David L. Mills
 *	Revised frequency scaling to conform with adjusted parameters
 *
 * 17 Sep 93	David L. Mills
 *	Created file
 */
/*
 * ntp_gettime(), ntp_adjtime() - precision time interface
 *
 * These routines consitute the Network Time Protocol (NTP) interfaces
 * for user and daemon application programs. The ntp_gettime() routine
 * provides the time, maximum error (synch distance) and estimated error
 * (dispersion) to client user application programs. The ntp_adjtime()
 * routine is used by the NTP daemon to adjust the system clock to an
 * externally derived time. The time offset and related variables set by
 * this routine are used by clock() to adjust the phase and
 * frequency of the phase-lock loop which controls the system clock.
 */
#include <sys/param.h>
#include <sys/user.h>
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/cpuvar.h>
#include <sys/timer.h>
#include <sys/debug.h>
#include <sys/timex.h>
#include <sys/model.h>
#include <sys/policy.h>

/*
 * ntp_gettime() - NTP user application interface
 */
int
ntp_gettime(struct ntptimeval *tp)
{
	timestruc_t tod;
	struct ntptimeval ntv;
	model_t datamodel = get_udatamodel();

	gethrestime(&tod);
	if (tod.tv_sec > TIME32_MAX)
		return (set_errno(EOVERFLOW));
	ntv.time.tv_sec = tod.tv_sec;
	ntv.time.tv_usec = tod.tv_nsec / (NANOSEC / MICROSEC);
	ntv.maxerror = time_maxerror;
	ntv.esterror = time_esterror;

	if (datamodel == DATAMODEL_NATIVE) {
		if (copyout(&ntv, tp, sizeof (ntv)))
			return (set_errno(EFAULT));
	} else {
		struct ntptimeval32 ntv32;

		if (TIMEVAL_OVERFLOW(&ntv.time))
			return (set_errno(EOVERFLOW));

		TIMEVAL_TO_TIMEVAL32(&ntv32.time, &ntv.time);

		ntv32.maxerror = ntv.maxerror;
		ntv32.esterror = ntv.esterror;

		if (copyout(&ntv32, tp, sizeof (ntv32)))
			return (set_errno(EFAULT));
	}

	/*
	 * Status word error decode. If any of these conditions
	 * occur, an error is returned, instead of the status
	 * word. Most applications will care only about the fact
	 * the system clock may not be trusted, not about the
	 * details.
	 *
	 * Hardware or software error
	 */
	if ((time_status & (STA_UNSYNC | STA_CLOCKERR)) ||
	/*
	 * PPS signal lost when either time or frequency
	 * synchronization requested
	 */
	    (time_status & (STA_PPSFREQ | STA_PPSTIME) &&
		!(time_status & STA_PPSSIGNAL)) ||

	/*
	 * PPS jitter exceeded when time synchronization
	 * requested
	 */
	    (time_status & STA_PPSTIME && time_status & STA_PPSJITTER) ||

	/*
	 * PPS wander exceeded or calibration error when
	 * frequency synchronization requested
	 */
	    (time_status & STA_PPSFREQ && time_status &
		(STA_PPSWANDER | STA_PPSERROR)))
		return (TIME_ERROR);

	return (time_state);
}

/*
 * ntp_adjtime() - NTP daemon application interface
 */
int
ntp_adjtime(struct timex *tp)
{
	struct timex ntv;
	int modes;

	if (copyin(tp, &ntv, sizeof (ntv)))
		return (set_errno(EFAULT));

	/*
	 * Update selected clock variables - only privileged users can
	 * change anything. Note that there is no error checking here on
	 * the assumption privileged users know what they're doing.
	 */
	modes = ntv.modes;

	if (modes != 0 && secpolicy_settime(CRED()) != 0)
		return (set_errno(EPERM));

	if (ntv.constant < 0 || ntv.constant > 30)
		return (set_errno(EINVAL));

	mutex_enter(&tod_lock);
	if (modes & MOD_MAXERROR)
		time_maxerror = ntv.maxerror;
	if (modes & MOD_ESTERROR)
		time_esterror = ntv.esterror;
	if (modes & MOD_STATUS) {
		time_status &= STA_RONLY;
		time_status |= ntv.status & ~STA_RONLY;
	}
	if (modes & MOD_TIMECONST)
		time_constant = ntv.constant;
	if (modes & MOD_OFFSET)
		clock_update(ntv.offset);
	if (modes & MOD_FREQUENCY)
		time_freq = ntv.freq - pps_freq;
	/*
	 * Retrieve all clock variables
	 */
	ntv.offset = time_offset / SCALE_UPDATE;
	ntv.freq = time_freq + pps_freq;
	ntv.maxerror = time_maxerror;
	ntv.esterror = time_esterror;
	ntv.status = time_status;
	ntv.constant = time_constant;
	ntv.precision = time_precision;
	ntv.tolerance = time_tolerance;
	ntv.shift = pps_shift;
	ntv.ppsfreq = pps_freq;
	ntv.jitter = pps_jitter >> PPS_AVG;
	ntv.stabil = pps_stabil;
	ntv.calcnt = pps_calcnt;
	ntv.errcnt = pps_errcnt;
	ntv.jitcnt = pps_jitcnt;
	ntv.stbcnt = pps_stbcnt;
	mutex_exit(&tod_lock);

	if (copyout(&ntv, tp, sizeof (ntv)))
		return (set_errno(EFAULT));

	/*
	 * Status word error decode.  See comments in
	 * ntp_gettime() routine.
	 */
	if ((time_status & (STA_UNSYNC | STA_CLOCKERR)) ||
	    (time_status & (STA_PPSFREQ | STA_PPSTIME) &&
	    !(time_status & STA_PPSSIGNAL)) ||
	    (time_status & STA_PPSTIME &&
	    time_status & STA_PPSJITTER) ||
	    (time_status & STA_PPSFREQ &&
	    time_status & (STA_PPSWANDER | STA_PPSERROR)))
		return (TIME_ERROR);

	return (time_state);
}
