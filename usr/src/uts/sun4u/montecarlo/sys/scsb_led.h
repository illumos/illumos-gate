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
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Netra ct SCB/SSB driver (scsb) support for controlling the
 * LEDs on the System Status Board that represent the cPCI Slots.
 * Each slot has a pair of LEDs, one green (OK) and one amber (NOK).
 * The OK (green) LED can also be made to blink.
 */

#ifndef	_SYS_SCSB_LED_H
#define	_SYS_SCSB_LED_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	_SCSBIOC		('s' << 8)

/* The ioctl command */
#define	ENVC_IOC_SETFSP		(_SCSBIOC | 23)

/* Netra ct 400 has 5 slots, Netra ct 800 has 8 slots.  Including CPU */
#define	NCT800_MAX_SLOTS	8
#define	NCT400_MAX_SLOTS	5

typedef	uint16_t	scsb_unum_t;

typedef enum {
	SLOT	= 0
} scsb_utype_t;

typedef enum {
	NOK =	0,
	OK  =	1,
} scsb_led_t;

typedef enum {
	OFF =	0,
	ON  =	1,
	BLINK =	2
} scsb_ustate_t;

typedef struct {
	scsb_unum_t	unit_number;
	scsb_utype_t	unit_type;
	scsb_ustate_t	unit_state;
	scsb_led_t	led_type;
} scsb_uinfo_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSB_LED_H */
