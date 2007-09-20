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

#ifndef	_TODDS1307_H
#define	_TODDS1307_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/i2c/clients/i2c_client.h>

extern char	*v_rtc_addr_reg;
extern volatile uint8_t	*v_rtc_data_reg;

#define	DS1307_ADDR_REG		*(volatile uint8_t *)v_rtc_addr_reg
#define	DS1307_DATA_REG		*(volatile uint8_t *)v_rtc_data_reg
#define	DS1307_NODE_TYPE	"ddi_i2c:tod"

struct rtc_t {
	uint8_t		rtc_sec;	/* Seconds[0-60] */
	uint8_t		rtc_min;	/* Minutes[0-60] */
	uint8_t		rtc_hrs;	/* Hours[(1-12)/(0-23)] */
	uint8_t		rtc_dow;	/* Day of week[1-7] */
	uint8_t		rtc_dom;	/* Day of month[(1-28/29/30/31)] */
	uint8_t		rtc_mon;	/* Month[1-12] */
	uint8_t		rtc_year;	/* Year[00-99] */
	uint8_t		rtc_ctl;	/* DS1307 Control register */
};


/*
 * Register definitions for RTC driver (DS1307 chip)
 */

#define	RTC_SEC		0x00	/* 00h Second */
#define	RTC_MIN		0x01	/* 01h Minutes */
#define	RTC_HRS		0x02	/* 02h Hours */
#define	RTC_DOW		0x03	/* 03h Day-of-week */
#define	RTC_DOM		0x04	/* 04h Day-of-month */
#define	RTC_MON		0x05	/* 05h Month */
#define	RTC_YEAR	0x06	/* 06h Year */
#define	RTC_CTL		0x07	/* 07h Control reg. */

/* Oscillator */

#define	OSCILLATOR_REG		0x00	/* Oscillator Reg Addr */
#define	OSCILLATOR_DISABLE	0x80

/* per instance based */

#define	TOD_DETACHED		0x00	/* TOD detached */
#define	TOD_ATTACHED		0x01	/* TOD attached */

typedef struct ds1307_state {
	i2c_client_hdl_t	ds1307_i2c_hdl;
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
}ds1307_state_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _TODDS1307_H */
