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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _RDSV3_DEBUG_H
#define	_RDSV3_DEBUG_H

#ifdef __cplusplus
extern "C" {
#endif

#define		LABEL	"RDSV3"

/*
 * warnings, console & syslog buffer.
 * For Non recoverable or Major Errors
 */
#define	RDSV3_LOG_L0	0

/*
 * syslog buffer or RDS trace buffer (console if booted /w debug)
 * For additional information on Non recoverable errors and
 * warnings/informational message for sys-admin types.
 */
#define	RDSV3_LOG_L1	1

/*
 * debug only
 * for more verbose trace than L1, for e.g. recoverable errors,
 * or intersting trace
 */
#define	RDSV3_LOG_L2	2

/*
 * debug only
 * for more verbose trace than L2, for e.g. informational messages
 */
#define	RDSV3_LOG_L3	3

/*
 * debug only
 * for more verbose trace than L3, for e.g. printing function entries...
 */
#define	RDSV3_LOG_L4	4

/*
 * debug only
 * most verbose level. Used only for  excessive trace, for e.g.
 * printing structures etc.
 */
#define	RDSV3_LOG_L5	5

/*
 * debug only
 * for messages from softints, taskqs, intr handlers, timeout handlers etc.
 */
#define	RDSV3_LOG_LINTR	6


#ifdef DEBUG
#define	RDSV3_DPRINTF_INTR	rdsv3_dprintf_intr
#define	RDSV3_DPRINTF5		rdsv3_dprintf5
#define	RDSV3_DPRINTF4		rdsv3_dprintf4
#define	RDSV3_DPRINTF3		rdsv3_dprintf3

void rdsv3_dprintf_intr(
		char		*name,
		char		*fmt, ...);
void rdsv3_dprintf5(
		char		*name,
		char		*fmt, ...);
void rdsv3_dprintf4(
		char		*name,
		char		*fmt, ...);
void rdsv3_dprintf3(
		char		*name,
		char		*fmt, ...);
#else
#define	RDSV3_DPRINTF_INTR	0 &&
#define	RDSV3_DPRINTF5		0 &&
#define	RDSV3_DPRINTF4		0 &&
#define	RDSV3_DPRINTF3		0 &&
#endif

#define	RDSV3_DPRINTF2		rdsv3_dprintf2
#define	RDSV3_DPRINTF1		rdsv3_dprintf1
#define	RDSV3_DPRINTF0		rdsv3_dprintf0

void rdsv3_dprintf2(
		char		*name,
		char		*fmt, ...);
void rdsv3_dprintf1(
		char		*name,
		char		*fmt, ...);
void rdsv3_dprintf0(
		char		*name,
		char		*fmt, ...);

void rdsv3_trace(
		char		*name,
		uint8_t		lvl,
		char		*fmt, ...);

void rdsv3_vprintk(
		char		*name,
		uint8_t		lvl,
		const char	*fmt,
		va_list		ap);

/* defined in rds_debug.c */
void rdsv3_logging_initialization();
void rdsv3_logging_destroy();
int rdsv3_printk_ratelimit(void);

#ifdef __cplusplus
}
#endif

#endif	/* _RDSV3_DEBUG_H */
