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
 * Copyright (c) 1994, by Sun Microsystems, Inc.
 */

#ifndef	_SYS_BATTERY_H
#define	_SYS_BATTERY_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * battery.h:	Declarations for the common battery interface.
 *	It is expected that any module supporting /dev/battery
 *	will support the following ioctls. When the BATT_STATUS
 *	ioctl is used, a module may return -1 for any fields which
 *	are not known.
 */

#define	BATT_IDSTR_LEN	40

/*
 * Generic ioctls
 */
typedef enum {
	BATT_STATUS = 0,	/* Module will return a battery_t structure */
	BATT_ESCAPE		/* Module specific */
} batt_ioctl_t;

/*
 * Response fields
 */
typedef enum {
	NOT_PRESENT = 0,
	EMPTY,			/* Battery has (effectively) no capacity */
	LOW_CAPACITY,		/* Battery has less than 25% capacity */
	MED_CAPACITY,		/* Battery has less than 50% capacity */
	HIGH_CAPACITY,		/* Battery has less than 75% capacity */
	FULL_CAPACITY,		/* Battery has more than 75% capacity */
	EOL			/* Battery is dead */
} batt_status_t;

typedef enum {
	DISCHARGE = 0,		/* Battery is discharging (i.e. in use) */
	FULL_CHARGE,		/* Battery is charging at its fastest rate */
	TRICKLE_CHARGE		/* Battery is charging at a slower rate */
} batt_charge_t;

typedef struct {
	char		id_string[BATT_IDSTR_LEN];
	int		total;		/* Total capacity (mWhrs) */
	char		capacity;	/* Current capacity (percentage) */
	int		discharge_rate;	/* Current discharge rate (mW) */
	int		discharge_time;	/* Discharge time at current rate (s) */
	batt_status_t	status;		/* General battery status */
	batt_charge_t	charge;		/* Current charging condition */
} battery_t;


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_BATTERY_H */
