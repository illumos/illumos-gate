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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SF880DRD_H
#define	_SF880DRD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	DEBUG
int dakdr_debug = 0;
#define	DPRINTF(ARGLIST)	if (dakdr_debug & 0x1) printf ARGLIST;
#else
#define	DPRINTF(ARGLIST)
#endif	/* DEBUG */

/*
 * CONSTANTS
 */
#define	SLOTS_PER_CONTROLLER	4
#define	NUM_CONTROLLERS		4
#define	NUM_FDS			(SLOTS_PER_CONTROLLER * NUM_CONTROLLERS)
#define	GPTWO_CONTROLLER	3

/*
 * Device paths/names
 */
#define	EBUS_DEV_NAME		"/devices/pci@9,700000/ebus@1/"
#define	SEG5_DEV_NAME		EBUS_DEV_NAME "i2c@1,30/"

#define	SSC050_LED_PORT		SEG5_DEV_NAME "ioexp@0,82:port_4"

#define	HPC3130_DEV_FMT SEG5_DEV_NAME "hotplug-controller@0,%2x:port_%1x"

/*
 * Front panel leds (Cf. Daktari spec 7.2.5.7).
 */
#define	SYS_FAULT_LED		0
#define	SYS_OK2REMOVE_LED	1
#define	DISK_FAULT_LED		2
#define	POWER_FAULT_LED		3
#define	THERM_RIGHT_LED		4
#define	LEFT_DOOR_ATTEN_LED	5
#define	RIGHT_DOOR_ATTEN_LED	6
#define	THERM_LEFT_LED		7

#define	LED_ON			0
#define	LED_OFF			1

#ifdef	__cplusplus
}
#endif

#endif	/* _SF880DRD_H */
