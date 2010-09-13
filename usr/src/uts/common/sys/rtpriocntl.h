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
 * Copyright (c) 1997-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _SYS_RTPRIOCNTL_H
#define	_SYS_RTPRIOCNTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.4 */

#include <sys/types.h>
#include <sys/thread.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Real-time class specific structures for the priocntl system call.
 */

typedef struct rtparms {
	pri_t	rt_pri;		/* real-time priority */
	uint_t	rt_tqsecs;	/* seconds in time quantum */
	int	rt_tqnsecs;	/* additional nanosecs in time quant */
} rtparms_t;


typedef struct rtinfo {
	pri_t	rt_maxpri;	/* maximum configured real-time priority */
} rtinfo_t;


#define	RT_NOCHANGE	-1
#define	RT_TQINF	-2
#define	RT_TQDEF	-3

/*
 * Real-time class specific keys for the priocntl system call varargs interface.
 */
#define	RT_KY_PRI	1	/* real-time priority */
#define	RT_KY_TQSECS	2	/* seconds in time quantum */
#define	RT_KY_TQNSECS	3	/* nanoseconds in time quantum */
#define	RT_KY_TQSIG	4	/* real-time time quantum signal */

/*
 * The following is used by the dispadmin(1M) command for
 * scheduler administration and is not for general use.
 */

#ifdef _SYSCALL32
/* Data structure for ILP32 clients */
typedef struct rtadmin32 {
	caddr32_t	rt_dpents;
	int16_t		rt_ndpents;
	int16_t		rt_cmd;
} rtadmin32_t;
#endif /* _SYSCALL32 */

typedef struct rtadmin {
	struct rtdpent	*rt_dpents;
	short		rt_ndpents;
	short		rt_cmd;
} rtadmin_t;

#define	RT_GETDPSIZE	1
#define	RT_GETDPTBL	2
#define	RT_SETDPTBL	3

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_RTPRIOCNTL_H */
