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

#ifndef	_TODBQ4802_H
#define	_TODBQ4802_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

extern  char	*v_rtc_addr_reg;

#ifdef	DEBUG
#include <sys/promif.h>
#define	DPRINTF if (bq4802_debug_flags) prom_printf
#else
#define	DPRINTF
#endif	/* DEBUG */

#define	BQ4802_DATA_REG(x)	(*(volatile uint8_t *)(v_rtc_addr_reg + x))

/*
 * Definitions for Real Time Clock driver (TI BQ4802 chip).
 */
#define	RTC_SEC		0x0	/* Seconds */
#define	RTC_ASEC	0x1	/* Seconds Alarm */
#define	RTC_MIN		0x2	/* Minutes */
#define	RTC_AMIN	0x3	/* Minutes Alarm */
#define	RTC_HRS		0x4	/* Hours */
#define	RTC_AHRS	0x5	/* Hours Alarm */
#define	RTC_DOM		0x6	/* Day-of-Month */
#define	RTC_ADOM	0x7	/* Day-of-Month Alarm */
#define	RTC_DOW		0x8	/* Day-of-Week */
#define	RTC_MON		0x9	/* Month */
#define	RTC_YEAR	0xa	/* Year */
#define	RTC_CENTURY	0xf	/* Century */

#define	RTC_RATES	0xb	/* Control Register B */
#define	RTC_ENABLES	0xc	/* Control Register C */
#define	RTC_FLAGS	0xd	/* Control Register D */
#define	RTC_CNTRL	0xe	/* Control Register E */

/*
 * Control register B definitions
 */
#define	RTC_RS		0x0f	/* Rate select for periodic interrupt */
#define	RTC_WD		0x70	/* Watchdog time-out rate */

/*
 * Control register C definitions
 */
#define	RTC_ABE		0x01	/* Alarm Int. Enable in Battery-backup Mode */
#define	RTC_PWRIE	0x02	/* Power-fail Interrupt Enable */
#define	RTC_PIE		0x04	/* Periodic Interrupt Enable */
#define	RTC_AIE		0x08	/* Alarm Interrupt Enable */

/*
 * Control Register D definitions
 */
#define	RTC_BVF		0x01	/* Battery-valid flag */
#define	RTC_PWRF	0x02	/* Power-fail Interrupt flag */
#define	RTC_PF		0x04	/* Periodic Interrupt flag */
#define	RTC_AF		0x08	/* Alarm Interrupt flag */

/*
 * Control Register E definitions
 */
#define	RTC_DSE		0x01	/* Daylight Savings Enable */
#define	RTC_HM		0x02	/* Hour mode, 1 = 24 hour, 0 = 12 hour */
#define	RTC_STOP_N	0x04	/* Oscillator Stop and Start */
#define	RTC_UTI		0x08	/* Update Transfer Inhibit */

struct	rtc_t {
	uint8_t	rtc_sec;	/* seconds */
	uint8_t	rtc_asec;	/* alarm seconds */
	uint8_t	rtc_min;	/* mins */
	uint8_t	rtc_amin;	/* alarm mins */
	uint8_t	rtc_hrs;	/* hours */
	uint8_t	rtc_ahrs;	/* alarm hours */
	uint8_t	rtc_dom;	/* day of the month */
	uint8_t	rtc_adom;	/* alarm day of the month */
	uint8_t	rtc_dow;	/* day of the week */
	uint8_t	rtc_mon;	/* month */
	uint8_t	rtc_year;	/* year */
	uint8_t	rtc_rates;	/* rates */
	uint8_t	rtc_enables;	/* enables */
	uint8_t	rtc_flags;	/* flags */
	uint8_t	rtc_control;	/* control */
	uint8_t	rtc_century;	/* century */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _TODBQ4802_H */
