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
/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/hrtcntl.h>
#include <sys/errno.h>
#include <sys/hrtsys.h>
#include <sys/time.h>
#include <sys/timer.h>
#include <sys/cmn_err.h>

/*
 * This file contains the code that manages the hardware clocks and
 * timers.  We must provide UNIX with a HZ resolution clock and give
 * the user an interface to the timers through system calls.
 */

static int hrt_checkres(ulong res);
static int hrt_bsd_cancel(int clock);
static int hrt_checkclock(register int clock);

/*
 * Argument vectors for the various flavors of hrtsys().
 */

#define	HRTCNTL		0
#define	HRTALARM	1
#define	HRTSLEEP	2
#define	HRTCANCEL	3

struct 	hrtsysa {
	int	opcode;
};

struct	hrtcntla {
	int		opcode;
	int		cmd;
	int		clk;
	interval_t	*intp;
	hrtimes_t	*hrtp;
};

struct	hrtalarma {
	int	opcode;
	hrtcmd_t	*cmdp;
	int		cmds;
};


/*
 * Hrtcntl (time control) system call.
 */


/*ARGSUSED1*/
int
hrtcntl(uap, rvp)
	register struct hrtcntla *uap;
	rval_t	*rvp;
{
	register int	error = 0;
	hrtimes_t	temptofd;

	switch (uap->cmd) {

	case HRT_TOFD:	/* Get the time of day */

		if (uap->clk != CLK_STD) {
			error = EINVAL;
			break;
		}

		if (copyin((caddr_t)uap->hrtp,
		    (caddr_t)&temptofd, sizeof (hrtimes_t))) {
			error = EFAULT;
			break;
		}

		if ((error = hrt_checkres(temptofd.hrt_res)))
			break;

		hrt_gettofd(&temptofd);

		if (copyout((caddr_t)&temptofd,
		    (caddr_t)uap->hrtp, sizeof (hrtimes_t)))
			error = EFAULT;

		break;

	default:
		error = EINVAL;
		break;
	}
	return (error);
}

/*
 * Hrtalarm (start one or more alarms) system call.
 */

int
hrtalarm(uap, rvp)
	register struct hrtalarma *uap;
	rval_t	*rvp;
{
	register hrtcmd_t	*cp;
	hrtcmd_t		*hrcmdp;
	uint			alarm_cnt;
	int			cnt;
	int			error = 0;
	int			cmd;
	hrtcmd_t		timecmd;
	hrtimes_t		delay_ht;


	/*
	 * Return EINVAL for negative and zero counts.
	 */

	if (uap->cmds <= 0)
		return (EINVAL);

	cp = &timecmd;
	hrcmdp = uap->cmdp;
	alarm_cnt = 0;

	/* Loop through and process each command. */

	for (cnt = 0; cnt < uap->cmds; cnt++, hrcmdp++) {

		if (copyin((caddr_t)hrcmdp, (caddr_t)cp, sizeof (hrtcmd_t)))
			return (EFAULT);

		cmd = cp->hrtc_cmd;

		/*
		 * If we try to post a Berkley Timer remove
		 * previous timers.
		 */

		if (cmd == HRT_BSD || cmd == HRT_BSD_REP)
			(void) hrt_bsd_cancel(cp->hrtc_clk);

		/*	See what kind of command we have.  */

		switch (cmd) {
		case HRT_BSD:		/* one-shot timer */
		{
			struct itimerval itv;
			u_int which;

			if (error = hrt_checkclock(cp->hrtc_clk))
				break;
			switch (cp->hrtc_clk) {
			case CLK_STD:
				which = ITIMER_REAL;
				break;
			case CLK_USERVIRT:
				which = ITIMER_VIRTUAL;
				break;
			case CLK_PROCVIRT:
				which = ITIMER_PROF;
				break;
			default:
				error = EINVAL;
				goto bad;
			}
			itv.it_value.tv_sec = cp->hrtc_int.hrt_secs;
			itv.it_value.tv_usec = cp->hrtc_int.hrt_rem;
			itv.it_interval.tv_sec = 0;
			itv.it_interval.tv_usec = 0;
			(void) xsetitimer(which, &itv, 1);

			break;
		}

		case HRT_BSD_REP:
		{
			struct itimerval itv;
			u_int which;

			switch (cp->hrtc_clk) {
			case CLK_STD:
				which = ITIMER_REAL;
				break;
			case CLK_USERVIRT:
				which = ITIMER_VIRTUAL;
				break;
			case CLK_PROCVIRT:
				which = ITIMER_PROF;
				break;
			default:
				error = EINVAL;
				goto bad;
			}
			itv.it_value.tv_sec = cp->hrtc_tod.hrt_secs;
			itv.it_value.tv_usec = cp->hrtc_tod.hrt_rem;
			itv.it_interval.tv_sec = cp->hrtc_int.hrt_secs;
			itv.it_interval.tv_usec = cp->hrtc_int.hrt_rem;
			(void) xsetitimer(which, &itv, 1);

			break;
		}

		case HRT_BSD_PEND:
			{
				struct itimerval itv;
				u_int which;

				switch (cp->hrtc_clk) {
				case CLK_STD:
					which = ITIMER_REAL;
					break;
				case CLK_USERVIRT:
					which = ITIMER_VIRTUAL;
					break;
				case CLK_PROCVIRT:
					which = ITIMER_PROF;
					break;
				default:
					error = EINVAL;
					goto bad;
				}
				(void) xgetitimer(which, &itv, 1);
				delay_ht.hrt_secs = itv.it_value.tv_sec;
				delay_ht.hrt_rem = itv.it_value.tv_usec;
			}

			if (copyout((caddr_t)&delay_ht,
			    (caddr_t)&hrcmdp->hrtc_int, sizeof (hrtimes_t)))
				error = EFAULT;

			break;

		case HRT_BSD_CANCEL:
			if (error = hrt_checkclock(cp->hrtc_clk))
				break;

			error = hrt_bsd_cancel(cp->hrtc_clk);

			break;

		default :
			error = EINVAL;
			break;
		}
bad:
		if (error) {
			cp->hrtc_flags |= HRTF_ERROR;
			cp->hrtc_error = error;
		} else {
			cp->hrtc_flags |= HRTF_DONE;
			cp->hrtc_error = 0;
			alarm_cnt++;
		}
		if (copyout((caddr_t)&cp->hrtc_flags,
		    (caddr_t)&hrcmdp->hrtc_flags,
		    sizeof (cp->hrtc_flags) + sizeof (cp->hrtc_error))) {
			error = EFAULT;
			return (error);
		}
	}
	rvp->r_val1 = alarm_cnt;
	return (0);
}


/*
 * Cancel BSD timers
 */

static int
hrt_bsd_cancel(int clock)
{
	struct itimerval itv;
	u_int which;

	switch (clock) {
	case CLK_STD:
		which = ITIMER_REAL;
		break;
	case CLK_USERVIRT:
		which = ITIMER_VIRTUAL;
		break;
	case CLK_PROCVIRT:
		which = ITIMER_PROF;
		break;
	default:
		return (EINVAL);
	}
	itv.it_value.tv_sec = 0;
	itv.it_value.tv_usec = 0;
	(void) xsetitimer(which, &itv, 1);
	return (0);
}


/*
 * Return 0 if "res" is a legal resolution. Otherwise,
 * return an error code, ERANGE.
 */

static int
hrt_checkres(ulong res)
{
	if (res == 0 || res > NANOSEC)
		return (ERANGE);
	return (0);
}

/*
 * Return 0 if "clock" is a valid clock. Otherwise,
 * return an error code, EINVAL.
 */

static int
hrt_checkclock(register int clock)
{
	switch (clock)
	case CLK_STD:
	case CLK_USERVIRT:
	case CLK_PROCVIRT:
		return (0);

	return (EINVAL);
}


/*
 * Set the current time of day in a specified resolution into
 * a hrtimes_t structure.
 */
void
hrt_gettofd(hrtimes_t *td)
{
	ulong new_res = td->hrt_res;
	timestruc_t ts;

	gethrestime(&ts);
	td->hrt_secs = ts.tv_sec;
	td->hrt_rem = ts.tv_nsec;
	td->hrt_res = NANOSEC;

	if (new_res != td->hrt_res) {
		td->hrt_rem /= NANOSEC / new_res;
		td->hrt_res = new_res;
	}
}


/*
 * System entry point for hrtcntl, hrtalarm
 * system calls.
 */

int
hrtsys(uap, rvp)
	register struct	hrtsysa *uap;
	rval_t *rvp;
{
	register int	error;

	switch (uap->opcode) {
	case	HRTCNTL:
		error = hrtcntl((struct hrtcntla *)uap, rvp);
		break;
	case	HRTALARM:
		error = hrtalarm((struct hrtalarma *)uap, rvp);
		break;
	default:
		error = EINVAL;
		break;
	}

	return (error);
}
