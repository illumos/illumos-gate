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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_MAX1617_IMPL_H
#define	_MAX1617_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAX1617_BUSY	0x01

#define	MAX1617_MAX_REGS		16
#define	MAX1617_LOCAL_TEMP_REG		0
#define	MAX1617_REMOTE_TEMP_REG		1
#define	MAX1617_STATUS_REG		2
#define	MAX1617_CONFIG_REG		3
#define	MAX1617_CONV_RATE_REG		4
#define	MAX1617_LOCALTEMP_HIGH_REG	5
#define	MAX1617_LOCALTEMP_LOW_REG	6
#define	MAX1617_REMOTETEMP_HIGH_REG	7
#define	MAX1617_REMOTETEMP_LOW_REG	8

#define	MAX1617_CONFIG_WR_REG		9
#define	MAX1617_CONV_RATE_WR_REG	10
#define	MAX1617_LOCALTEMP_HIGH_WR_REG	11
#define	MAX1617_LOCALTEMP_LOW_WR_REG	12
#define	MAX1617_REMOTETEMP_HIGH_WR_REG	13
#define	MAX1617_REMOTETEMP_LOW_WR_REG	14
#define	MAX1617_ONE_SHOT_CMD_REG	15

#define	MAX1617_INST_TO_MINOR(x) (x << 4)
#define	MAX1617_MINOR_TO_INST(x) ((x & 0xFFFFFFF0) >> 4)
#define	MAX1617_FCN_TO_MINOR(x)  (x)
#define	MAX1617_MINOR_TO_FCN(x)  (0x0F & x)
#define	MAX1617_AMB_TEMP 0
#define	MAX1617_CPU_TEMP 1

#define	MAX1617_NODE_TYPE "ddi_i2c:temperature_sensor"

struct max1617_cpr_state {
	uint8_t		max1617_config;
	uint8_t		max1617_conv_rate;
	int8_t		max1617_lcl_hlimit;
	int8_t		max1617_lcl_llimit;
	int8_t		max1617_remote_hlimit;
	int8_t		max1617_remote_llimit;
};

struct max1617_unit {
	kmutex_t	max1617_mutex;
	uint8_t		max1617_flags;
	kcondvar_t	max1617_cv;
	uint16_t	max1617_oflag;
	i2c_client_hdl_t	max1617_hdl;
	char		max1617_name[24];
	struct max1617_cpr_state max1617_cpr_state;
};

#ifdef	__cplusplus
}
#endif

#endif	/* _MAX1617_IMPL_H */
