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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_FXPRIOCNTL_H
#define	_SYS_FXPRIOCNTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/thread.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Fixed-priority class specific structures for the priocntl system call.
 */

typedef struct fxparms {
	pri_t	fx_upri;	/* fixed-priority user priority */
	pri_t	fx_uprilim;	/* fixed-priority user priority limit */
	uint_t	fx_tqsecs;	/* seconds in time quantum */
	int	fx_tqnsecs;	/* additional nanosecs in time quant */
} fxparms_t;


typedef struct fxinfo {
	pri_t	fx_maxupri;	/* configured limits of user priority range */
} fxinfo_t;


#define	FX_NOCHANGE	-32768
#define	FX_TQINF	-2
#define	FX_TQDEF	-3

/*
 * Fixed-priority class specific keys for the priocntl system call varargs
 * interface.
 */
#define	FX_KY_UPRILIM	1	/* fixed-priority user priority limit */
#define	FX_KY_UPRI	2	/* fixed-priority user priority */
#define	FX_KY_TQSECS	3	/* seconds in time quantum */
#define	FX_KY_TQNSECS	4	/* nanoseconds in time quantum */


/*
 * The following is used by the dispadmin(1M) command for
 * scheduler administration and is not for general use.
 */

#ifdef _SYSCALL32
/* Data structure for ILP32 clients */
typedef struct fxadmin32 {
	caddr32_t	fx_dpents;
	int16_t		fx_ndpents;
	int16_t		fx_cmd;
} fxadmin32_t;
#endif /* _SYSCALL32 */

typedef struct fxadmin {
	struct fxdpent	*fx_dpents;
	short		fx_ndpents;
	short		fx_cmd;
} fxadmin_t;

#define	FX_GETDPSIZE	1
#define	FX_GETDPTBL	2
#define	FX_SETDPTBL	3

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FXPRIOCNTL_H */
