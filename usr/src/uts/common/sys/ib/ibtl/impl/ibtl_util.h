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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_IB_IBTL_IMPL_IBTL_UTIL_H
#define	_SYS_IB_IBTL_IMPL_IBTL_UTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ibtl_util.h
 *
 * All data structures and function prototypes that serve as helper
 * routines for IBTF implementation.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ib/ib_types.h>
#include <sys/varargs.h>

/*
 * Time Related Functions
 *
 *   ibt_usec2ib
 *	This function converts the standard input time in microseconds to
 *	IB's 6 bits of timeout exponent, calculated based on
 *	time = 4.096us * 2 ^ exp.
 *
 *   ibt_ib2usec
 *	This function converts the input IB timeout exponent (6 bits) to
 *	standard time in microseconds, calculated based on
 *	time = 4.096us * 2 ^ exp.
 */
ib_time_t	ibt_usec2ib(clock_t microsecs);
clock_t		ibt_ib2usec(ib_time_t ib_time);


/*
 * IB logging, debug and console message handling
 */


/*
 * warnings, console & syslog buffer.
 * For Non recoverable or Major Errors
 */
#define	IBTF_LOG_L0	0

/*
 * syslog buffer or IBTF trace buffer (console if booted /w debug)
 * For additional information on Non recoverable errors and
 * warnings/informational message for sys-admin types.
 */
#define	IBTF_LOG_L1	1

/*
 * debug only
 * for more verbose trace than L1, for e.g. recoverable errors,
 * or intersting trace
 */
#define	IBTF_LOG_L2	2

/*
 * debug only
 * for more verbose trace than L2, for e.g. printing function entries....
 */
#define	IBTF_LOG_L3	3

/*
 * debug only
 * for more verbose trace than L3, for e.g. printing minor function entries...
 */
#define	IBTF_LOG_L4	4

/*
 * debug only
 * most verbose level. Used only for  excessive trace, for e.g.
 * printing structures etc.
 */
#define	IBTF_LOG_L5	5

/*
 * debug only
 * for messages from softints, taskqs, intr handlers, timeout handlers etc.
 * Only gets printed if "ibtl_allow_intr_msgs" is set
 */
#define	IBTF_LOG_LINTR	6


#ifdef DEBUG
#define	IBTF_DPRINTF_LINTR	ibtl_dprintf_intr
#define	IBTF_DPRINTF_L5		ibtl_dprintf5
#define	IBTF_DPRINTF_L4		ibtl_dprintf4
#define	IBTF_DPRINTF_L3		ibtl_dprintf3

void ibtl_dprintf_intr(
		char		*name,
		char		*fmt, ...);
void ibtl_dprintf5(
		char		*name,
		char		*fmt, ...);
void ibtl_dprintf4(
		char		*name,
		char		*fmt, ...);
void ibtl_dprintf3(
		char		*name,
		char		*fmt, ...);
#else
#define	IBTF_DPRINTF_LINTR	0 &&
#define	IBTF_DPRINTF_L5		0 &&
#define	IBTF_DPRINTF_L4		0 &&
#define	IBTF_DPRINTF_L3		0 &&
#endif

#define	IBTF_DPRINTF_L2	ibtl_dprintf2
#define	IBTF_DPRINTF_L1	ibtl_dprintf1
#define	IBTF_DPRINTF_L0	ibtl_dprintf0

void ibtl_dprintf2(
		char		*name,
		char		*fmt, ...);
void ibtl_dprintf1(
		char		*name,
		char		*fmt, ...);
void ibtl_dprintf0(
		char		*name,
		char		*fmt, ...);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_IBTL_IMPL_IBTL_UTIL_H */
