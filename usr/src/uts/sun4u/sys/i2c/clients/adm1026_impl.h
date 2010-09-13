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

#ifndef	_ADM1026_IMPL_H
#define	_ADM1026_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


#include <sys/i2c/clients/i2c_client.h>

typedef struct adm1026_unit {
	kmutex_t		adm1026_mutex;
	int			adm1026_oflag;
	i2c_client_hdl_t	adm1026_hdl;
} adm1026_unit_t;

/*
 * ADM1026 has 4 GPIO Config registers used to set Polarity and Direction.
 * To config a particular GPIO, the low 16 bits of the reg_mask member
 * of the i2c_gpio_t struct is used as a logical mask to indicate which
 * GPIO pin(s) to access and the reg_val member is used to set/clear those
 * GPIO pins' P or D bit(s).
 *
 * GPIO#  3  2  1  0
 *      +--+--+--+--+
 *      |PD|PD|PD|PD|	<-- ADM1026_GPIO_CFG1
 *      +--+--+--+--+       Logical Mask: 0x000f
 *
 * GPIO#  7  6  5  4
 *      +--+--+--+--+
 *      |PD|PD|PD|PD|	<-- ADM1026_GPIO_CFG2
 *      +--+--+--+--+       Logical Mask: 0x00f0
 *
 * GPIO# 11 10  9  8
 *      +--+--+--+--+
 *      |PD|PD|PD|PD|	<-- ADM1026_GPIO_CFG3
 *      +--+--+--+--+       Logical Mask: 0x0f00
 *
 * GPIO# 15 14 13 12
 *      +--+--+--+--+
 *      |PD|PD|PD|PD|	<-- ADM1026_GPIO_CFG4
 *      +--+--+--+--+       Logical Mask: 0xf000
 */

#define	ADM1026_GPIO_CFG1	0x08	/* Config GPIO 03-00 in/out + hi/lo */
#define	ADM1026_GPIO_CFG2	0x09	/* Config GPIO 07-04 in/out + hi/lo */
#define	ADM1026_GPIO_CFG3	0x0a	/* Config GPIO 11-08 in/out + hi/lo */
#define	ADM1026_GPIO_CFG4	0x0b	/* Config GPIO 15-12 in/out + hi/lo */

/*
 * ADM1026 has 2 GPIO Output registers to set GPIO pins.
 * To set a particular GPIO pin, the low 16 bits of the reg_mask member
 * of the i2c_gpio_t struct is used as a 1:1 mask of the 16 GPIO pin(s)
 * to access and the reg_val member is used to set/clear the GPIO pin(s).
 *
 * GPIO# 76 54 32 10
 *
 *      +--+--+--+--+
 *      |xx|xx|xx|xx|	<-- ADM1026_STS_REG5
 *      +--+--+--+--+       Logical Mask: 0x00ff
 *
 * GPIO# 11 11 11 98
 *       54 32 10
 *      +--+--+--+--+
 *      |xx|xx|xx|xx|	<-- ADM1026_STS_REG6
 *      +--+--+--+--+       Logical Mask: 0xff00
 */

#define	ADM1026_STS_REG5	0x24	/* GPIO 07-00 */
#define	ADM1026_STS_REG6	0x25	/* GPIO 15-08 */

#define	OUTPUT_SHIFT		8
#define	BITSPERCFG		2	/* Polarity + Dir bits per GPIO cfg */

#define	DIR_BIT			1	/* Dir bit = lo bit of GPIO cfg */
#define	POLARITY_BIT		2	/* Polarity bit = hi bit GPIO cfg */

#define	BYTES_PER_OUTPUT	2

#define	BYTES_PER_CONFIG	4

#define	NUMBER_OF_GPIOS		16

#define	GPIOS_PER_CFG_BYTE	4

#define	GPIO_CFG_MASK		0xf


#ifdef DEBUG

static int adm1026_dbg = 0;
#define	D1CMN_ERR(ARGS) { if (adm1026_dbg & 0x1) cmn_err ARGS; }
#define	D2CMN_ERR(ARGS) { if (adm1026_dbg & 0x2) cmn_err ARGS; }

#else

#define	D1CMN_ERR(ARGS)
#define	D2CMN_ERR(ARGS)

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _ADM1026_IMPL_H */
