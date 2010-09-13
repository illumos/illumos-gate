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
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_TODM5819_H
#define	_TODM5819_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

extern  char    *v_rtc_addr_reg;
extern  volatile uint8_t *v_rtc_data_reg;

#ifdef	DEBUG
#include <sys/promif.h>
#define	DPRINTF if (m5819_debug_flags) prom_printf
#else
#define	DPRINTF
#endif	/* DEBUG */

#define	M5819_ADDR_REG		*(volatile uint8_t *)v_rtc_addr_reg
#define	M5819_DATA_REG		*(volatile uint8_t *)v_rtc_data_reg


/*
 * Definitions for Real Time Clock driver (m5819 chip).
 */

/*
 * Common registers between Banks 0, 1, and 2.
 */
#define	RTC_SEC		0x0	/* Seconds */
#define	RTC_ASEC	0x1	/* Seconds Alarm */
#define	RTC_MIN		0x2	/* Minutes */
#define	RTC_AMIN	0x3	/* Minutes Alarm */
#define	RTC_HRS		0x4	/* Hours */
#define	RTC_AHRS	0x5	/* Hours Alarm */
#define	RTC_DOW		0x6	/* Day-of-Week */
#define	RTC_DOM		0x7	/* Day-of-Month */
#define	RTC_MON		0x8	/* Month */
#define	RTC_YEAR	0x9	/* Year */
#define	RTC_A		0xa	/* Control Register A */
#define	RTC_B		0xb	/* Control Register B */
#define	RTC_C		0xc	/* Control Register C */
#define	RTC_D		0xd	/* Control Register D */
#define	RTC_CENTURY	0x32	/* Century */

/*
 * Control register A definitions
 */
#define	RTC_DIV0	0x10	/* Bank Select */
#define	RTC_DIV1	0x20	/* Oscillator enable */
#define	RTC_DIV2	0x40	/* Countdown chain */
#define	RTC_UIP		0x80	/* Update in progress bit */

/*
 * Control register B definitions
 */
#define	RTC_DSE		0x01	/* Daylight Savings Enable */
#define	RTC_HM		0x02	/* Hour mode, 1 = 24 hour, 0 = 12 hour */
#define	RTC_DM		0x04	/* Date mode, 1 = binary, 0 = BCD */
#define	RTC_UIE		0x10	/* Update-ended Interrupt Enable */
#define	RTC_AIE		0x20	/* Alarm Interrupt Enable */
#define	RTC_PIE		0x40	/* Periodic Interrupt Enable */
#define	RTC_SET		0x80	/* Stop updates for time set */

/*
 * Control Register C definitions
 */
#define	RTC_UF		0x10	/* UF flag bit */
#define	RTC_AF		0x20	/* AF flag bit */
#define	RTC_PF		0x40	/* PF flag bit */
#define	RTC_IRQF	0x80	/* IRQ flag */

/*
 * Control Register D definitions
 */
#define	RTC_VRT		0x80	/* Valid RAM and time bit */


/*
 * Bank 2 Registers
 */
#define	APC_APCR1	0x40	/* APC Control Register 1 */
#define	APC_APCR2	0x41	/* APC Control Register 2 */
#define	APC_APSR	0x42	/* APC Status Register */
#define	APC_WDWR	0x43	/* Wake up Day of Week */
#define	APC_WDMR	0x44	/* Wake up Date of Month */
#define	APC_WMR		0x45	/* Wake up Month */
#define	APC_WYR		0x46	/* Wake up Year */
#define	APC_WCR		0x48	/* Wake up Century */

#define	RTC_CADDR	0x51	/* Century address register */

/*
 * APC Control Register 1 (APCR1) definitions
 */
#define	APC_FSTRC	0x40	/* Fail-safe Timer Reset Command */

/*
 * APC Control Register 2 (APCR2) definitions
 */
#define	APC_TME		0x01	/* Timer Match Enable */

/*
 * The following two defintions are used in conjuction to wait
 * for the UIP bit to clear.
 */
#define	TODM5819_UIP_RETRY_THRESH 6
#define	TODM5819_UIP_WAIT_USEC 56


struct	rtc_t {
	uint8_t	rtc_sec;	/* seconds */
	uint8_t	rtc_asec;	/* alarm seconds */
	uint8_t	rtc_min;	/* mins */
	uint8_t	rtc_amin;	/* alarm mins */
	uint8_t	rtc_hrs;	/* hours */
	uint8_t	rtc_ahrs;	/* alarm hours */
	uint8_t	rtc_dow;	/* day of the week */
	uint8_t	rtc_dom;	/* day of the month */
	uint8_t	rtc_mon;	/* month */
	uint8_t	rtc_year;	/* year */
	uint8_t	rtc_rega;	/* REG A */
	uint8_t	rtc_regb;	/* REG B */
	uint8_t	rtc_regc;	/* REG C */
	uint8_t	rtc_regd;	/* REG D */
	uint8_t	rtc_century;	/* century */
	uint8_t	rtc_adom;	/* alarm  day */
	uint8_t	rtc_amon;	/* alarm  mon */
	uint8_t	apc_apcr1;	/* APC Control register 1 */
	uint8_t	apc_apcr2;	/* APC Control register 2 */
	uint8_t	apc_apsr;	/* APC Status register */
	uint8_t	apc_wdwr;	/* Wakeup date of the month */
	uint8_t	apc_wdmr;	/* Wakeup day of month */
	uint8_t	apc_wmr;	/* Wakeup month register */
	uint8_t	apc_wyr;	/* Wakeup year register */
	uint8_t	apc_wcr;	/* Wakeup Century reg. */
};


#define	RTC_GET8(offset) (M5819_ADDR_REG = (offset), M5819_DATA_REG)
#define	RTC_PUT8(offset, value) (	\
	M5819_ADDR_REG = (offset),	\
	M5819_DATA_REG = (value))

#ifdef	__cplusplus
}
#endif

#endif	/* _TODM5819_H */
