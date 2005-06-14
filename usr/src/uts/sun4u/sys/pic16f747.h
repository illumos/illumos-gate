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

#ifndef _PIC16f747_H
#define	_PIC16f747_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * PIC Registers
 */
#define	RF_COMMAND	0x00
#define	RF_STATUS	0x01
#define	RF_IND_DATA	0x40
#define	RF_IND_ADDR	0x41
#define	RF_ENV_S0	0x80
#define	RF_ENV_S1	0x81
#define	RF_TPM_S0	0xC0
#define	RF_TPM_S1	0xC1

/*
 * PIC Registers from Indirect Address/Data
 */
#define	RF_FAN0_PERIOD	0x00
#define	RF_FAN1_PERIOD	0x01
#define	RF_FAN2_PERIOD	0x02
#define	RF_FAN3_PERIOD	0x03
#define	RF_FAN4_PERIOD	0x04
#define	RF_LOCAL_TEMP	0x06
#define	RF_REMOTE1_TEMP	0x07
#define	RF_REMOTE2_TEMP	0x08
#define	RF_REMOTE3_TEMP	0x09
#define	RF_LM95221_TEMP	0x0A
#define	RF_FIRE_TEMP	0x0B
#define	RF_LSI1064_TEMP	0x0C
#define	RF_FRONT_TEMP	0x0D
#define	RF_FAN_STATUS	0x0E
#define	RF_VCORE0	0x0F
#define	RF_VCORE1	0x10

/*
 * Bitmasks for RF_STATUS register
 */
#define	ST_FFAULT		0x01	/* fan failure has occurred */
#define	ST_ENV_BUSY		0x02	/* environmental bus is busy */
#define	ST_STALE_ADT_DATA	0x04	/* ADT7462 data currently invalid */
#define	ST_STALE_LM_DATA	0x08	/* LM95221 data currently invalid */
#define	ST_FW_VERSION		0xF0	/* firmware version number */

/*
 * Bitmasks for RF_COMMAND values
 */
#define	CMD_TO_ESTAR		0x01
#define	CMD_PIC_RESET		0x80

/* Number of fans/sensors */
#define	MAX_PIC_NODES		16
#define	N_FANS			5
#define	N_SENSORS		8
#define	N_PIC_NODES		(N_FANS+N_SENSORS+1)

/*
 * PIC devices' node name and register offset
 */
#define	PICDEV_NODE_TYPE	"pic_client:env-monitor"
typedef struct minor_node_info {
	char		*minor_name;	/* node name */
	uint8_t		reg_offset;	/* indirect register offset */
	uint8_t		ff_shift;	/* fan fault shift (only for fans) */
} minor_node_info;

/*
 * PIC device minor numbers are constructed as <inst_9-12>:<unit_0-8>
 */
#define	PIC_INST_TO_MINOR(x)	(((x) << 8) & 0x0F00)
#define	PIC_UNIT_TO_MINOR(x)	((x) & 0xFF)
#define	PIC_MINOR_TO_UNIT(x)	((x) & 0xFF)
#define	PIC_MINOR_TO_INST(x)	(((x)>> 8) & 0xF)

/*
 * PIC ioctl commands
 */
#define	PICIOC	('X'<<8)
#define	PIC_GET_TEMPERATURE	(PICIOC|1)
#define	PIC_GET_FAN_SPEED	(PICIOC|2)
#define	PIC_SET_FAN_SPEED	(PICIOC|3)
#define	PIC_GET_STATUS		(PICIOC|4)
#define	PIC_GET_FAN_STATUS	(PICIOC|5)
#define	PIC_SET_ESTAR_MODE	(PICIOC|6)

/*
 * Miscellaneous
 */
#define	MAX_PIC_INSTANCES	4
#define	MAX_RETRIES		10

#ifdef	__cplusplus
}
#endif

#endif /* _PIC16f747_H */
