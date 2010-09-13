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

#ifndef _ADM1031_IMPL_H
#define	_ADM1031_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


#define	ADM1031_PIL			4
#define	ADM1031_MAX_XFER		4

#define	ADM1031_WRITE_COMMAND_BASE	30


/* This register has the value of fan speeds */
#define	ADM1031_FAN_SPEED_INST_REG_1		0x08
#define	ADM1031_FAN_SPEED_INST_REG_2		0x09

/* This register has the value of temperatures */

#define	ADM1031_LOCAL_TEMP_INST_REG		0x0A
#define	ADM1031_REMOTE_TEMP_INST_REG_1		0x0B
#define	ADM1031_REMOTE_TEMP_INST_REG_2		0x0C


#define	ADM1031_STAT_1_REG			0x02
#define	ADM1031_STAT_2_REG			0x03
#define	ADM1031_DEVICE_ID_REG			0x3D
#define	ADM1031_CONFIG_REG_1			0x00
#define	ADM1031_CONFIG_REG_2 			0x01
#define	ADM1031_FAN_CHAR_1_REG			0x20
#define	ADM1031_FAN_CHAR_2_REG			0x21
#define	ADM1031_FAN_SPEED_CONFIG_REG		0x22
#define	ADM1031_FAN_HIGH_LIMIT_1_REG		0x10
#define	ADM1031_FAN_HIGH_LIMIT_2_REG		0x11
#define	ADM1031_LOCAL_TEMP_RANGE_REG		0x24
#define	ADM1031_REMOTE_TEMP_RANGE_1_REG		0x25
#define	ADM1031_REMOTE_TEMP_RANGE_2_REG		0x26
#define	ADM1031_EXTD_TEMP_RESL_REG		0x06
#define	ADM1031_LOCAL_TEMP_OFFSET_REG		0x0D
#define	ADM1031_REMOTE_TEMP_OFFSET_1_REG	0x0E
#define	ADM1031_REMOTE_TEMP_OFFSET_2_REG	0x0F
#define	ADM1031_LOCAL_TEMP_HIGH_LIMIT_REG	0x14
#define	ADM1031_REMOTE_TEMP_HIGH_LIMIT_1_REG    0x18
#define	ADM1031_REMOTE_TEMP_HIGH_LIMIT_2_REG    0x1C
#define	ADM1031_LOCAL_TEMP_LOW_LIMIT_REG	0x15
#define	ADM1031_REMOTE_TEMP_LOW_LIMIT_1_REG	0x19
#define	ADM1031_REMOTE_TEMP_LOW_LIMIT_2_REG	0x1D
#define	ADM1031_LOCAL_TEMP_THERM_LIMIT_REG	0x16
#define	ADM1031_REMOTE_TEMP_THERM_LIMIT_1_REG	0x1A
#define	ADM1031_REMOTE_TEMP_THERM_LIMIT_2_REG	0x1E



#define	ADM1031_TEMP_CHANS		3
#define	ADM1031_FAN_SPEED_CHANS		2

#define	ADM1031_TEMPERATURES		0
#define	ADM1031_FANS			1
#define	ADM1031_CONTROL			2


#define	ADM1031_INST_TO_MINOR(x)	((x << 8) & 0xF00)
#define	ADM1031_FCN_TO_MINOR(x)		((x << 4) & 0x0F0)
#define	ADM1031_FCNINST_TO_MINOR(x)	(x & 0x00F)
#define	ADM1031_MINOR_TO_FCNINST(x)	(0x00F & x)
#define	ADM1031_MINOR_TO_FCN(x)		((0x0F0 & x) >> 4)
#define	ADM1031_MINOR_TO_INST(x)	((x & 0xF00) >> 8)

#define	ADM1031_CHECK_FOR_WRITES(x)	 (x > 26)

/*
 * Maximum speed for a fan is 0xf(100% PWM duty cycle) and minimum is
 * 0x0(0% PWM duty cycle).
 */
#define	ADM1031_CHECK_INVALID_SPEED(x) ((x) > 0x0F)

/*
 * Check if the minor node corresponds with the correct function.
 */
#define	ADM1031_CHECK_FAN_CMD(x)	\
	(((x >= 6) && (x < 11)) || ((x >= 36) && (x < 41)))

#define	ADM1031_CHECK_TEMPERATURE_CMD(x) 	\
	(((x >= 11) && (x < 27)) || ((x >= 41) && (x < 57)))

#define	ADM1031_CHECK_CONTROL_CMD(x)	\
	(((x >= 1) && (x < 6)) || ((x >= 34) && (x < 36)))


#define	MLSN(x)		(x & 0xf0)
#define	MMSN(x)		(x & 0x0f)

#define	ADM1031_BUSYFLAG	0x1
#define	ADM1031_TBUFFLAG	0x2
#define	ADM1031_REGFLAG		0x4
#define	ADM1031_MUTEXFLAG	0x8
#define	ADM1031_INTRFLAG	0x10
#define	ADM1031_AUTOFLAG	0x80

#define	ADM1031_NODE_TYPE	"ddi_i2c:hardware_monitor"

typedef struct adm1031_cpr_state {
	uint8_t		config_reg_1;
	uint8_t		config_reg_2;
	uint8_t		fan_speed_reg;
} adm1031_cpr_state_t;

typedef struct adm1031_unit {
	dev_info_t		*adm1031_dip;
	i2c_transfer_t		*adm1031_transfer;
	ddi_iblock_cookie_t	adm1031_icookie;
	kmutex_t		adm1031_mutex;
	kcondvar_t		adm1031_cv;
	kmutex_t		adm1031_imutex;
	kcondvar_t		adm1031_icv;
	int			adm1031_cvwaiting;
	int			adm1031_flags;
	i2c_client_hdl_t	adm1031_hdl;
	char			adm1031_name[12];
	int			adm1031_oflag;
	adm1031_cpr_state_t	adm1031_cpr_state;
} adm1031_unit_t;

typedef struct minor_info {
	char			*minor_name;
	uchar_t			reg;
} minor_info;

#ifdef	__cplusplus
}
#endif

#endif /* _ADM1031_IMPL_H */
