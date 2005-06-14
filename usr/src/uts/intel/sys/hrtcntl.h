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
 * Copyright (c) 1997-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef _SYS_HRTCNTL_H
#define	_SYS_HRTCNTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The following are the possible commands for the hrtcntl,
 * hrtalarm, and hrtsleep system calls.
 */

typedef	enum	hrtcmds {

		/*   hrtcntl	commands   */
	HRT_GETRES,		/* Get the resolution of a clock.	*/
	HRT_TOFD,		/* Get the value of time since		*/
				/* 00:00:00 GMT, January 1, 1970	*/
	HRT_STARTIT,		/* Start timing an activity		*/
	HRT_GETIT,		/* Return the interval time elapsed	*/
				/* since the corresponding HRT_STARTIT	*/
				/* command has been issued.		*/
		/*   hrtalarm   commands   */
	HRT_ALARM,		/* Start a timer and post an alarm	*/
				/* event after the time interval has	*/
				/* elapsed.				*/
	HRT_RALARM,		/* Post an alarm repeatedly after	*/
				/* every time interval.			*/
	HRT_TODALARM,		/* Similar to HRT_ALARM except that	*/
				/* the time at which the alarm is to	*/
				/* posted is specified by an absolute	*/
				/* time.				*/
	HRT_INT_RPT,		/* Start a repeating alarm some time	*/
				/* in the future.			*/
	HRT_TOD_RPT,		/* Similar to HRT_INT_RPT except that	*/
				/* the time of day when the alarm	*/
				/* should begin is specified.		*/
	HRT_PENDING,		/* Determine the time remaining until	*/
				/* a pending alarm fires.		*/
		/*   hrtsleep   commands  */
	HRT_INTSLP,		/* Put the process to sleep for an	*/
				/* interval.				*/
	HRT_TODSLP,		/* Put the process to sleep until	*/
				/* a specified time of day.		*/
		/*
		 * The following fields will be used
		 * to implement BSD timers
		 */
	HRT_BSD,
	HRT_BSD_PEND,
	HRT_RBSD,
	HRT_BSD_REP,
	HRT_BSD_CANCEL
} hrtcmds_t;

/*
 *	Definitions for specifying rounding mode.
 */

#define	HRT_TRUNC	0	/* Round results down.	*/
#define	HRT_RND		1	/* Round results (rnd up if fractional	*/
				/*   part >= .5 otherwise round down).	*/
#define	HRT_RNDUP	2	/* Always round results up.	*/

/*
 *	Definition for the type of internal buffer used with the
 *	HRT_STARTIT and HRT_GETIT commands.
 */

typedef	struct interval {
	unsigned long	i_word1;
	unsigned long	i_word2;
	int		i_clock;
} interval_t;

/*
 *	Structure used to represent a high-resolution time-of-day
 *	or interval.
 */

typedef struct hrtime {
	ulong_t	hrt_secs;	/* Seconds.				*/
	long	hrt_rem;	/* A value less than a second.		*/
	ulong_t	hrt_res;	/* The resolution of hrt_rem.		*/
} hrtimes_t;


/*
 *	The structure used for the hrtalarm and hrtsleep system calls.
 */

typedef struct hrtcmd {
	int		hrtc_cmd;	/* A timer command.		*/
	int		hrtc_clk;	/* Which clock to use.		*/
	hrtimes_t	hrtc_int;	/* A time interval.		*/
	hrtimes_t	hrtc_tod;	/* A time of day.		*/
	int		hrtc_flags;	/* Various flags. 		*/
	int		hrtc_error;	/* An error code		*/
					/* (see eys/errno.h).		*/
#ifdef notdef
	ecb_t		hrtc_ecb;	/* An event control block.	*/
#endif
} hrtcmd_t;

/*
 * Flags for the hrtc_flags field.
 */

#define	HRTF_DONE	0x0001	/* The requested alarm has been set.	*/
#define	HRTF_ERROR	0x0002	/* An error has been encountered.	*/

/*
 * Multiple clocks
 */

#define	CLK_STD		0x0001	/* The standard real-time clock.	*/
#define	CLK_USERVIRT	0x0002	/* A clock measuring user process	*/
				/* virtual time.			*/
#define	CLK_PROCVIRT	0x0004	/* A clock measuring a process' virtual */
				/* time.				*/

/*
 * Function Prototypes
 * ===================
 *
 *	The following are prototypes for the library functions which
 *	users call.
 */

#if defined(__STDC__) && !defined(_KERNEL)
int   hrtcntl(int, int, interval_t *, hrtimes_t *);
int   hrtalarm(hrtcmd_t *, int);
int   hrtsleep(hrtcmd_t *);
int   hrtcancel(const long *, int);
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HRTCNTL_H */
