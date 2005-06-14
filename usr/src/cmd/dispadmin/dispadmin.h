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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	Note that this file does not exist in the SVr4 base, but
 *	is largely derived from sys/hrtcntl.h, hence the AT&T
 *	copyright is propagated.  SVr4.0 1.9
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The following is an excerpt from <sys/hrtcntl.h>. HRT timers are not
 * supported by SunOS (which will support the POSIX definition). Dispadmin
 * uses the hrt routine _hrtnewres because it coincidentally does the
 * right thing. These defines allow this routine to be locally included
 * in dispadmin (rather than exported in libc). This should be improved in
 * the long term.
 */

/*
 *	Definitions for specifying rounding mode.
 */

#define	HRT_TRUNC	0	/* Round results down.	*/
#define	HRT_RND		1	/* Round results (rnd up if fractional	*/
				/*   part >= .5 otherwise round down).	*/
#define	HRT_RNDUP	2	/* Always round results up.	*/

/*
 *	Structure used to represent a high-resolution time-of-day
 *	or interval.
 */

typedef struct hrtimer {
	ulong_t	hrt_secs;	/* Seconds.				*/
	long	hrt_rem;	/* A value less than a second.		*/
	ulong_t	hrt_res;	/* The resolution of hrt_rem.		*/
} hrtimer_t;

/*
 * Functions in subr.c
 */
extern void fatalerr(const char *, ...);
extern long hrtconvert(hrtimer_t *);
extern int _hrtnewres(hrtimer_t *, ulong_t, long);
