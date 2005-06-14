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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_LOM_IO_H
#define	_SYS_LOM_IO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * I/O header file for Alarm
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ioccom.h>

/* ioctls for the alarm card */

#define	TSIOCALSTATE	_IOWR('a', 1, ts_aldata_t)
#define	TSIOCALCTL	_IOW('a',  2, ts_aldata_t)

/*
 * Defines for identifying the four alarms
 */
#define	ALARM_NUM_0	0
#define	ALARM_NUM_1	1
#define	ALARM_NUM_2	2
#define	ALARM_NUM_3	3

#define	ALARM_CRITICAL	ALARM_NUM_0
#define	ALARM_MAJOR		ALARM_NUM_1
#define	ALARM_MINOR		ALARM_NUM_2
#define	ALARM_USER		ALARM_NUM_3

/*
 * typedefs used in alarm ioctl definitions
 */

typedef
struct {
		int alarm_no;
		int alarm_state;
} ts_aldata_t;

/*
 * Values for alarm_state
 */
#define	ALARM_OFF	0
#define	ALARM_ON	1

/*
 * old commands to manipulate the control node
 */

#define	LOMIOCALCTL	TSIOCALCTL
#define	LOMIOCALSTATE	TSIOCALSTATE

/*
 * typedefs used in LOMlite ioctl definitions
 */

typedef
struct {
	int alarm_no;
	int state;
} lom_aldata_t;

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_LOM_IO_H */
