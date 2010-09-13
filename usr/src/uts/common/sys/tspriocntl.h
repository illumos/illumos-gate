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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_TSPRIOCNTL_H
#define	_SYS_TSPRIOCNTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.5 */

#include <sys/types.h>
#include <sys/thread.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Time-sharing class specific structures for the priocntl system call.
 */

typedef struct tsparms {
	pri_t	ts_uprilim;	/* user priority limit */
	pri_t	ts_upri;	/* user priority */
} tsparms_t;


typedef struct tsinfo {
	pri_t	ts_maxupri;	/* configured limits of user priority range */
} tsinfo_t;

#define	TS_NOCHANGE	-32768

/*
 * Time-sharing class specific keys for the priocntl system call
 * varargs interface.
 */
#define	TS_KY_UPRILIM	1	/* user priority limit */
#define	TS_KY_UPRI	2	/* user priority */

/*
 * The following is used by the dispadmin(1M) command for
 * scheduler administration and is not for general use.
 */

#ifdef _SYSCALL32
/* Data structure for ILP32 clients */
typedef struct tsadmin32 {
	caddr32_t	ts_dpents;
	int16_t		ts_ndpents;
	int16_t		ts_cmd;
} tsadmin32_t;
#endif /* _SYSCALL32 */

typedef struct tsadmin {
	struct tsdpent	*ts_dpents;
	short		ts_ndpents;
	short		ts_cmd;
} tsadmin_t;

#define	TS_GETDPSIZE	1
#define	TS_GETDPTBL	2
#define	TS_SETDPTBL	3

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TSPRIOCNTL_H */
