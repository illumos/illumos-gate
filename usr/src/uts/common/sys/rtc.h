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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef _SYS_RTC_H
#define	_SYS_RTC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * Definitions for Real Time Clock driver (Motorola MC146818 chip).
 */

/*
 * MP NOTE:
 * cmos_lck must be locked when addressing CMOS via
 * RTC_ADDR and RTC_DATA i/o addresses
 */
#define	RTC_ADDR	0x70	/* I/O port address of for register select */
#define	RTC_DATA	0x71	/* I/O port address for data read/write */

/*
 * Register A definitions
 */
#define	RTC_A		0x0a	/* register A address */
#define	RTC_UIP		0x80	/* Update in progress bit */
#define	RTC_DIV0	0x00	/* Time base of 4.194304 MHz */
#define	RTC_DIV1	0x10	/* Time base of 1.048576 MHz */
#define	RTC_DIV2	0x20	/* Time base of 32.768 KHz */
#define	RTC_RATE6	0x06	/* interrupt rate of 976.562 */

/*
 * Register B definitions
 */
#define	RTC_B		0x0b	/* register B address */
#define	RTC_SET		0x80	/* stop updates for time set */
#define	RTC_PIE		0x40	/* Periodic interrupt enable */
#define	RTC_AIE		0x20	/* Alarm interrupt enable */
#define	RTC_UIE		0x10	/* Update ended interrupt enable */
#define	RTC_SQWE	0x08	/* Square wave enable */
#define	RTC_DM		0x04	/* Date mode, 1 = binary, 0 = BCD */
#define	RTC_HM		0x02	/* hour mode, 1 = 24 hour, 0 = 12 hour */
#define	RTC_DSE		0x01	/* Daylight savings enable */

/*
 * Register C definitions
 */
#define	RTC_C		0x0c	/* register C address */
#define	RTC_IRQF	0x80	/* IRQ flag */
#define	RTC_PF		0x40	/* PF flag bit */
#define	RTC_AF		0x20	/* AF flag bit */
#define	RTC_UF		0x10	/* UF flag bit */

/*
 * Register D definitions
 */
#define	RTC_D		0x0d	/* register D address */
#define	RTC_VRT		0x80	/* Valid RAM and time bit */

#define	RTC_NREG	0x0e	/* number of RTC registers */
#define	RTC_NREGP	0x0c	/* number of RTC registers to set time */
#define	RTC_CENTURY	0x32	/* not included in RTC_NREG(P) */

/*
 * Ioctl definitions for accessing RTC.
 */
#define	RTCIOC	('R' << 8)

#define	RTCRTIME	(RTCIOC | 0x01)		/* Read time from RTC */
#define	RTCSTIME	(RTCIOC | 0x02)		/* Set time into RTC */

struct	rtc_t {			/* registers 0x0 to 0xD, 0x32 */
	unsigned char	rtc_sec;
	unsigned char	rtc_asec;
	unsigned char	rtc_min;
	unsigned char	rtc_amin;
	unsigned char	rtc_hr;
	unsigned char	rtc_ahr;
	unsigned char	rtc_dow;
	unsigned char	rtc_dom;
	unsigned char	rtc_mon;
	unsigned char	rtc_yr;
	unsigned char	rtc_statusa;
	unsigned char	rtc_statusb;
	unsigned char	rtc_statusc;
	unsigned char	rtc_statusd;
	unsigned char	rtc_century; /* register 0x32 */
	unsigned char	rtc_adom;	/* ACPI-provided day alarm */
	unsigned char	rtc_amon;	/* ACPI-provided mon alarm */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_RTC_H */
