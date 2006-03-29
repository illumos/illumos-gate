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

#ifndef	_MONTERCARLO_SYS_SCSBIOCTL_H
#define	_MONTERCARLO_SYS_SCSBIOCTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * SCB HW information, which is needed in scsb.h for scsb.c.
 * there are 32 data registers on the system controller board
 * most are used in P1.0, all are used in P1.5
 */
#define	SCSB_DATA_REGISTERS		48


#define	_SCSBIOC		('s' << 8)

#define	SCSBIOC_GET_STATUS 	(_SCSBIOC | 1)		/* Internal	*/
#define	SCSBIOC_I2C_XFER	(_SCSBIOC | 2)		/* Internal	*/

#define	SCSBIOC_ALL_LEDS_ON 	(_SCSBIOC | 3)		/* Diagnostics	*/
#define	SCSBIOC_ALL_LEDS_OFF 	(_SCSBIOC | 4)		/* Diagnostics	*/

#define	SCSBIOC_FREEZE 		(_SCSBIOC | 5)		/* Internal	*/
#define	SCSBIOC_RESTORE 	(_SCSBIOC | 6)		/* Internal	*/

#define	SCSBIOC_LED_NOK_SET	(_SCSBIOC | 7)		/* Diagnostics	*/
#define	SCSBIOC_LED_NOK_GET	(_SCSBIOC | 8)		/* Diagnostics	*/
#define	SCSBIOC_LED_OK_SET	(_SCSBIOC | 9)		/* Diagnostics	*/
#define	SCSBIOC_LED_OK_GET	(_SCSBIOC | 10)		/* Diagnostics	*/
#define	SCSBIOC_GET_FAN_STATUS	(_SCSBIOC | 11)		/* Internal	*/
#define	SCSBIOC_RESET_UNIT	(_SCSBIOC | 12)		/* Diagnostics	*/
#define	SCSBIOC_FAKE_INTR	(_SCSBIOC | 13)		/* Internal	*/
#define	SCSBIOC_BSELECT_SET	(_SCSBIOC | 14)		/* Internal	*/
#define	SCSBIOC_BSELECT_GET	(_SCSBIOC | 15)		/* Internal	*/
#define	SCSBIOC_BHEALTHY_SET	(_SCSBIOC | 16)		/* Internal	*/
#define	SCSBIOC_BHEALTHY_GET	(_SCSBIOC | 17)		/* Internal	*/
#define	SCSBIOC_GET_INTR_ARRAY	(_SCSBIOC | 18)		/* Internal	*/

#define	ENVC_IOC_ACQUIRE_SLOT_LED_CTRL	(_SCSBIOC | 21)	/* EnvMon	*/
#define	ENVC_IOC_RELEASE_SLOT_LED_CTRL	(_SCSBIOC | 22)	/* EnvMon	*/
#define	ENVC_IOC_SETFSP		(_SCSBIOC | 23)		/* EnvMon	*/
#define	ENVC_IOC_GETDSKLED	(_SCSBIOC | 24)		/* EnvMon	*/
#define	ENVC_IOC_SETDSKLED	(_SCSBIOC | 25)		/* EnvMon	*/
#define	ENVC_IOC_REGISTER_PID	(_SCSBIOC | 26)		/* EnvMon	*/
#define	ENVC_IOC_UNREGISTER_PID	(_SCSBIOC | 27)		/* EnvMon	*/
#define	ENVC_IOC_ACCONF_RESTORED (_SCSBIOC | 28)	/* EnvMon	*/
#define	ENVC_IOC_ACCONF_STORED	(_SCSBIOC | 29)		/* EnvMon	*/

#define	SCSBIOC_REG_READ	(_SCSBIOC | 31)		/* Diagnostic	*/
#define	SCSBIOC_REG_WRITE	(_SCSBIOC | 32)		/* Diagnostic	*/
#define	SCSBIOC_GET_VERSIONS	(_SCSBIOC | 33)		/* Diagnostic	*/

/* these are for debug/testing and may be temporary */
#define	SCSBIOC_SHUTDOWN_POLL	(_SCSBIOC | 41)		/* Internal	*/
#define	SCSBIOC_SLOT_OCCUPANCY	(_SCSBIOC | 42)		/* Internal	*/
#define	SCSBIOC_INTEVENT_POLL	(_SCSBIOC | 43)		/* Internal	*/
#define	SCSBIOC_TOPOLOGY_DUMP	(_SCSBIOC | 44)		/* Internal	*/
#define	SCSBIOC_VALUE_MODE	(_SCSBIOC | 45)		/* Internal	*/
#define	SCSBIOC_GET_SLOT_INFO	(_SCSBIOC | 46)		/* Internal	*/
#define	SCSBIOC_DEBUG_MODE	(_SCSBIOC | 52)		/* Internal	*/

/*
 * SCSBIOC_GET_VERSIONS structure
 */
#define	SCSB_MODSTR_LEN	64
#define	SCSB_VERSTR_LEN	12
typedef struct scsb_ids {
	char 	modldrv_string[SCSB_MODSTR_LEN];
	char	scsb_version[SCSB_VERSTR_LEN];
	uint8_t promid;
	uint8_t pad[3];
} scsb_ids_t;


typedef enum {
	GET  =	0,
	SET  =	1
} scsb_op_t;

typedef enum {
	NOK =	0,
	OK  =	1,
	NOUSE =	2
} scsb_led_t;

#define	SCSB_LED_TYPES		2

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


/* SCSBIOC_GET_STATUS data */
typedef struct {
	uchar_t	scsb_reg[SCSB_DATA_REGISTERS];
} scsb_status_t;


/* SCSBIOC_REG_READ / SCSBIOC_REG_WRITE data */
typedef struct {
	int16_t		ioc_result;  /* O: return value			*/
	uint16_t	ioc_resio;   /* O: bytes not transfered		*/
	uint16_t	ioc_wlen;    /* I: length of write buffer	*/
	uint16_t	ioc_rlen;    /* I: length of read buffer	*/
	uchar_t		ioc_rbuf[64];
	uchar_t		ioc_wbuf[64];
	uchar_t		ioc_regindex;
} scsb_ioc_rdwr_t;


#ifdef	__cplusplus
}
#endif

#endif	/* _MONTERCARLO_SYS_SCSBIOCTL_H */
