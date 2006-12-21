/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _RDSIB_DEBUG_H
#define	_RDSIB_DEBUG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#define		LABEL	"RDS"

/*
 * warnings, console & syslog buffer.
 * For Non recoverable or Major Errors
 */
#define	RDS_LOG_L0	0

/*
 * syslog buffer or RDS trace buffer (console if booted /w debug)
 * For additional information on Non recoverable errors and
 * warnings/informational message for sys-admin types.
 */
#define	RDS_LOG_L1	1

/*
 * debug only
 * for more verbose trace than L1, for e.g. recoverable errors,
 * or intersting trace
 */
#define	RDS_LOG_L2	2

/*
 * debug only
 * for more verbose trace than L2, for e.g. informational messages
 */
#define	RDS_LOG_L3	3

/*
 * debug only
 * for more verbose trace than L3, for e.g. printing function entries...
 */
#define	RDS_LOG_L4	4

/*
 * debug only
 * most verbose level. Used only for  excessive trace, for e.g.
 * printing structures etc.
 */
#define	RDS_LOG_L5	5

/*
 * debug only
 * for messages from softints, taskqs, intr handlers, timeout handlers etc.
 */
#define	RDS_LOG_LINTR	6


#ifdef DEBUG
#define	RDS_DPRINTF_INTR	rds_dprintf_intr
#define	RDS_DPRINTF5		rds_dprintf5
#define	RDS_DPRINTF4		rds_dprintf4
#define	RDS_DPRINTF3		rds_dprintf3

void rds_dprintf_intr(
		char		*name,
		char		*fmt, ...);
void rds_dprintf5(
		char		*name,
		char		*fmt, ...);
void rds_dprintf4(
		char		*name,
		char		*fmt, ...);
void rds_dprintf3(
		char		*name,
		char		*fmt, ...);
#else
#define	RDS_DPRINTF_INTR	0 &&
#define	RDS_DPRINTF5		0 &&
#define	RDS_DPRINTF4		0 &&
#define	RDS_DPRINTF3		0 &&
#endif

#define	RDS_DPRINTF2	rds_dprintf2
#define	RDS_DPRINTF1	rds_dprintf1
#define	RDS_DPRINTF0	rds_dprintf0

void rds_dprintf2(
		char		*name,
		char		*fmt, ...);
void rds_dprintf1(
		char		*name,
		char		*fmt, ...);
void rds_dprintf0(
		char		*name,
		char		*fmt, ...);

#ifdef __cplusplus
}
#endif

#endif	/* _RDSIB_DEBUG_H */
