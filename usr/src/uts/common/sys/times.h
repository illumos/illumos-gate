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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _SYS_TIMES_H
#define	_SYS_TIMES_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Structure returned by times()
 */
struct tms {
	clock_t	tms_utime;		/* user time */
	clock_t	tms_stime;		/* system time */
	clock_t	tms_cutime;		/* user time, children */
	clock_t	tms_cstime;		/* system time, children */
};

#if defined(_SYSCALL32)

/*
 * Kernel's view of ILP32 data structure
 */
struct tms32 {
	clock32_t tms_utime;		/* user time */
	clock32_t tms_stime;		/* system time */
	clock32_t tms_cutime;		/* user time, children */
	clock32_t tms_cstime;		/* system time, children */
};

#endif	/* _SYSCALL32 */

clock_t times(struct tms *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TIMES_H */
