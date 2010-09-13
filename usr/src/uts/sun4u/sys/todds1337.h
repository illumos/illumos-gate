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

#ifndef	_TODDS1337_H
#define	_TODDS1337_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/i2c/clients/i2c_client.h>

extern char	*v_rtc_addr_reg;
extern volatile uint8_t	*v_rtc_data_reg;

#define	DS1337_ADDR_REG		*(volatile uint8_t *)v_rtc_addr_reg
#define	DS1337_DATA_REG		*(volatile uint8_t *)v_rtc_data_reg
#define	DS1337_NODE_TYPE	"ddi_i2c:tod"

struct rtc_t {
	uint8_t		rtc_sec;	/* Seconds[0-60] */
	uint8_t		rtc_min;	/* Minutes[0-60] */
	uint8_t		rtc_hrs;	/* Hours[(1-12)/(0-23)] */
	uint8_t		rtc_dow;	/* Day of week[1-7] */
	uint8_t		rtc_dom;	/* Day of month[(1-28/29/30/31)] */
	uint8_t		rtc_mon;	/* Month[1-12] */
	uint8_t		rtc_year;	/* Year[00-99] */
	uint8_t		rtc_asec;	/* Alarm #1 seconds */
	uint8_t		rtc_amin;	/* Alarm #1 minutes */
	uint8_t		rtc_ahrs;	/* Alarm #1 hours   */
	uint8_t		rtc_aday;	/* Alarm #1 day [month/week] */
	uint8_t		rtc_a2min;	/* Alarm #2 minutes */
	uint8_t		rtc_a2hrs;	/* Alarm #2 hours   */
	uint8_t		rtc_a2day;	/* Alarm #2 day [month/week] */
	uint8_t		rtc_ctl;	/* DS1337 Control register */
	uint8_t		rtc_status;	/* DS1337 Status register  */
};


/*
 * Register definitions for RTC driver (DS1337 chip)
 */

#define	RTC_SEC		0x00	/* 00h Second */
#define	RTC_MIN		0x01	/* 01h Minutes */
#define	RTC_HRS		0x02	/* 02h Hours */
#define	RTC_DOW		0x03	/* 03h Day-of-week */
#define	RTC_DOM		0x04	/* 04h Day-of-month */
#define	RTC_MON		0x05	/* 05h Month */
#define	RTC_YEAR	0x06	/* 06h Year */
#define	RTC_ALARM_SEC	0x07	/* 07h Alarm #1 Second  */
#define	RTC_ALARM_MIN	0x08	/* 08h Alarm #1 Minutes */
#define	RTC_ALARM_HRS	0x09	/* 09h Alarm #1 Hours   */
#define	RTC_ALARM_DAY	0x0a	/* 0Ah Alarm #1 Day [month/week] */
#define	RTC_CTL		0x0e	/* 0Eh Control register */
#define	RTC_STATUS	0x0f	/* 0Fh Status register  */

#define	RTC_DYDT_MASK	0x40

/*
 * Control register definitions
 */

#define	RTC_CTL_EOSC	0x80	/* Active low */
#define	RTC_CTL_RS2	0x10
#define	RTC_CTL_RS1	0x08
#define	RTC_CTL_INTCN	0x04
#define	RTC_CTL_A2IE	0x02
#define	RTC_CTL_A1IE	0x01


/*
 * Status register definitions
 */

#define	RTC_STATUS_OSF	0x80
#define	RTC_STATUS_A2F	0x02
#define	RTC_STATUS_A1F	0x01

/* per instance based */

#define	TOD_DETACHED		0x00	/* TOD detached */
#define	TOD_ATTACHED		0x01	/* TOD attached */

typedef struct ds1337_state {
	i2c_client_hdl_t	ds1337_i2c_hdl;
	char			i2ctod_name[MAXNAMELEN];  /* node name */
	kmutex_t		i2ctod_mutex;   /* protects soft state */
	int			instance;
	dev_info_t		*dip;
	uint32_t		state;
	ddi_periodic_t		cycid; /* periodical callback */
	struct rtc_t		rtc;
	i2c_transfer_t		*i2c_tp;
	ddi_softintr_t   	soft_intr_id;
	uint32_t		progress;
}ds1337_state_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _TODDS1337_H */
