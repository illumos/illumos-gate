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

#ifndef _EPIC_H
#define	_EPIC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * EPIC is slow device. Need to interlace delay between two accesses.
 */
#define	EPIC_DELAY 10000

/*
 * EPIC Registers from Indirect Address/Data
 */
#define	EPIC_FIRE_INTERRUPT		0x01
#define	EPIC_FIRE_INT_MASK		0x01

#define	EPIC_IND_FW_VERSION		0x05

#define	EPIC_IND_LED_STATE0		0x06

#define	EPIC_ALERT_LED_MASK		0x0C
#define	EPIC_ALERT_LED_OFF		0x00
#define	EPIC_ALERT_LED_ON		0x04

#define	EPIC_POWER_LED_MASK		0x30
#define	EPIC_POWER_LED_OFF		0x00
#define	EPIC_POWER_LED_ON		0x10
#define	EPIC_POWER_LED_SB_BLINK		0x20
#define	EPIC_POWER_LED_FAST_BLINK	0x30

#define	EPIC_HOST_INT_ENABLE_REG	0x1a
#define	EPIC_POWER_BUTTON_INT		0x01
#define	EPIC_HOST_INTR_CLEAR		0x00
#define	EPIC_POWER_BUTTON_INT_MASK	0x01
#define	EPIC_HOST_INT_STATUS_REG	0x1b

#define	EPIC_ATOM_DATA			0x80
#define	EPIC_ATOM_ADDR			0x81

#define	EPIC_ATOM_INTR_CLEAR		0x01
#define	EPIC_ATOM_INTR_READ		0x02
#define	EPIC_ATOM_INTR_ENABLE		0x03


/*
 * EPIC ioctl commands
 */

#define	EPIC_SET_ALERT_LED		0x11
#define	EPIC_RESET_ALERT_LED		0x12

#define	EPIC_SET_POWER_LED		0x21
#define	EPIC_RESET_POWER_LED		0x22
#define	EPIC_SB_BL_POWER_LED		0x23
#define	EPIC_FAST_BL_POWER_LED		0x24

#define	EPIC_GET_FW			0x30

/*
 *	READ/WRITE macros for the port used by epic (LED) driver
 */

#define	EPIC_READ(HANDLE, REG, LHS, ADDR)\
		drv_usecwait(EPIC_DELAY);\
		(void) ddi_put8((HANDLE),\
		(uint8_t *)(REG)+\
		    EPIC_IND_ADDR, (ADDR));\
		drv_usecwait(EPIC_DELAY);\
		(LHS) =  ddi_get8((HANDLE),\
				(uint8_t *)(REG)+\
				EPIC_IND_DATA);

#define	EPIC_WRITE(HANDLE, REG, ADDR, MASK, DATA)\
		drv_usecwait(EPIC_DELAY);\
		(void) ddi_put8((HANDLE),\
		(uint8_t *)(REG)+\
		    EPIC_IND_ADDR, (ADDR));\
		drv_usecwait(EPIC_DELAY);\
		(void) ddi_put8((HANDLE),\
		(uint8_t *)(REG)+\
		    EPIC_WRITE_MASK, (MASK));\
		drv_usecwait(EPIC_DELAY);\
		(void) ddi_put8((HANDLE),\
		(uint8_t *)(REG)+\
		    EPIC_IND_DATA, (DATA));

/*
 *	READ/WRITE macros for the port used by power button driver
 */

#define	EPIC_RD(HANDLE, REG, LHS)\
		drv_usecwait(EPIC_DELAY);\
		(LHS) =  ddi_get8((HANDLE),\
			(uint8_t *)(REG)+\
			EPIC_ATOM_DATA);

#define	EPIC_WR(HANDLE, REG, DATA)\
		drv_usecwait(EPIC_DELAY);\
		(void) ddi_put8((HANDLE),\
		(uint8_t *)(REG)+\
		EPIC_ATOM_ADDR, (DATA));


#ifdef	__cplusplus
}
#endif

#endif /* _EPIC_H */
