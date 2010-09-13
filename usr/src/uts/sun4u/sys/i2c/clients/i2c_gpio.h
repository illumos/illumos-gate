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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _I2C_GPIO_H
#define	_I2C_GPIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/i2c/clients/i2c_client.h>

#ifdef	__cplusplus
extern "C" {
#endif


#define	GPIO_GET_INPUT		(I2C_PVT_BASE_IOCTL + 0)
#define	GPIO_GET_OUTPUT		(I2C_PVT_BASE_IOCTL + 1)
#define	GPIO_SET_OUTPUT		(I2C_PVT_BASE_IOCTL + 2)
#define	GPIO_GET_POLARITY	(I2C_PVT_BASE_IOCTL + 3)
#define	GPIO_SET_POLARITY	(I2C_PVT_BASE_IOCTL + 4)
#define	GPIO_GET_CONFIG		(I2C_PVT_BASE_IOCTL + 5)
#define	GPIO_SET_CONFIG		(I2C_PVT_BASE_IOCTL + 6)


typedef struct i2c_gpio {
	uint32_t	reg_val;
	uint32_t	reg_mask;
} i2c_gpio_t;


#ifdef	__cplusplus
}
#endif

#endif /* _I2C_GPIO_H */
