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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_DAK_HPC3130_EVENTS_H
#define	_DAK_HPC3130_EVENTS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	HPC3130_DAK_IOC			('D' << 8)
#define	HPC3130_GET_EVENT		(HPC3130_DAK_IOC | 0)	/* (uint8_t) */
#define	HPC3130_CONF_DR			(HPC3130_DAK_IOC | 1)

#define	HPC3130_SLOTS			0x4
#define	HPC3130_CONTROLLERS		0x4
#define	HPC3130_DR_DISABLE		0x0
#define	HPC3130_DR_ENABLE		0x1

#ifdef _KERNEL

/*
 * Internal events bits.  These are translated to hpc3130_event_type_t's
 * by the time the user sees them (in ioctl(HPC3130_GET_SOFT_EVENT))
 */
#define	HPC3130_IEVENT_OCCUPANCY	(1<<0)
#define	HPC3130_IEVENT_POWER		(1<<1)
#define	HPC3130_IEVENT_BUTTON		(1<<2)
#define	HPC3130_IEVENT_FAULT		(1<<3)
#define	HPC3130_IEVENT_OK2REM		(1<<4)
#endif /* _KERNEL */

typedef enum {
	HPC3130_EVENT_NONE,
	HPC3130_EVENT_INSERTION,
	HPC3130_EVENT_REMOVAL,
	HPC3130_EVENT_POWERON,
	HPC3130_EVENT_POWEROFF,
	HPC3130_EVENT_BUTTON,
	HPC3130_LED_FAULT_ON,
	HPC3130_LED_FAULT_OFF,
	HPC3130_LED_REMOVABLE_ON,
	HPC3130_LED_REMOVABLE_OFF
} hpc3130_event_type_t;

#define	HPC3130_NAME_MAX MAXPATHLEN

typedef enum {
	HPC3130_SLOT_TYPE_PCI,
	HPC3130_SLOT_TYPE_SBD
} hpc3130_slot_type_t;

struct hpc3130_event {
	hpc3130_event_type_t id;
	char name[HPC3130_NAME_MAX];
};

#ifdef	__cplusplus
}
#endif

#endif	/* _DAK_HPC3130_EVENTS_H */
