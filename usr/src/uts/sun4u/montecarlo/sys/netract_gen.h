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
 * Copyright (c) 1999, 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * MonteCarlo's Common I2C Driver Definitions
 *
 * These definitions are derived from, or the same as,
 * some of the definitions from sun4u/sys/envctrl_gen.h,
 * which are common definitions for workgroup server platforms.
 */

#ifndef	_SYS_NETRACT_GEN_H
#define	_SYS_NETRACT_GEN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


#ifndef	_SYS_ENVCTRL_GEN_H
#define	_SYS_ENVCTRL_GEN_H

#define	ENVCTRL_NORMAL_MODE	0x01
#define	ENVCTRL_DIAG_MODE	0x02
#define	ENVC_DEBUG_MODE		0x03

/*
 * Max number of a particular
 * device on one bus.
 */
#define	ENVCTRL_MAX_DEVS	0x10
#define	ENVCTRL_I2C_NODEV	0xFF
#define	ENVCTRL_INSTANCE_0	0x00

/*
 * Kstat structure definitions (PSARC 1996/159)
 */
typedef struct envctrl_fan {
	int instance;			/* instance of this type */
	int type;			/* CPU, PS or AMBIENT fan */
	boolean_t fans_ok;		/* are the fans okay */
	int fanflt_num;			/* if not okay, which fan faulted */
	uint_t fanspeed;			/* chip to set speed of fans */
} envctrl_fan_t;

#endif	/* _SYS_ENVCTRL_GEN_H */

#define	ENVC_IOC_SETMODE	(int)(_IOW('p', 77, uchar_t))
#define	ENVC_IOC_GETMODE	(int)(_IOR('p', 87, uchar_t))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NETRACT_GEN_H */
