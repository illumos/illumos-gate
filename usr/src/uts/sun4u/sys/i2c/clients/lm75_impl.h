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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_LM75_IMPL_H
#define	_LM75_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	LM75_TEMPERATURE_REG		0x00
#define	LM75_CONFIGURATION_REG		0x01
#define	LM75_HYST_REG			0x02
#define	LM75_OVERTEMP_REG		0x03

#define	LM75_COMP_MASK		0x100
#define	LM75_COMP_MASK_UPPER	0xff

#include <sys/i2c/clients/i2c_client.h>

struct lm75_unit {
	kmutex_t		lm75_mutex;
	uint8_t			lm75_flags;
	int			lm75_oflag;
	i2c_client_hdl_t	lm75_hdl;
	char			lm75_name[24];
};

#ifdef DEBUG

static int lm75debug = 0;
#define	D1CMN_ERR(ARGS) if (lm75debug & 0x1) cmn_err ARGS;
#define	D2CMN_ERR(ARGS) if (lm75debug & 0x2) cmn_err ARGS;

#else

#define	D1CMN_ERR(ARGS)
#define	D2CMN_ERR(ARGS)

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _LM75_IMPL_H */
