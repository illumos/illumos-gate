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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_I2C_CLIENT_H
#define	_I2C_CLIENT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Common IOCTL definitions for client drivers.
 */

#define	I2C_BASE_IOCTL	('M' << 8)

#define	I2C_GET_PORT		(I2C_BASE_IOCTL | 0)
#define	I2C_SET_PORT		(I2C_BASE_IOCTL | 1)
#define	I2C_GET_BIT		(I2C_BASE_IOCTL | 2)
#define	I2C_SET_BIT		(I2C_BASE_IOCTL | 3)
#define	I2C_GET_REG		(I2C_BASE_IOCTL | 4)
#define	I2C_SET_REG		(I2C_BASE_IOCTL | 5)
#define	I2C_GET_TEMPERATURE	(I2C_BASE_IOCTL | 7)
#define	I2C_GET_FAN_SPEED	(I2C_BASE_IOCTL | 8)
#define	I2C_SET_FAN_SPEED	(I2C_BASE_IOCTL | 9)
#define	I2C_SET_OUTPUT		(I2C_BASE_IOCTL | 10)
#define	I2C_GET_OUTPUT		(I2C_BASE_IOCTL | 11)
#define	I2C_GET_INPUT		(I2C_BASE_IOCTL | 12)
#define	I2C_SET_MODE		(I2C_BASE_IOCTL | 13)
#define	I2C_GET_MODE		(I2C_BASE_IOCTL | 14)

/*
 * A private IOCTL definition to be used by clients. The first 128 ioctls
 * derived by OR'ing with I2C_BASE_IOCTL are common. The next 128
 * ioctls derived by OR'ing with I2C_PVT_BASE_IOCTL are client private.
 */

#define	I2C_PVT_BASE_IOCTL	(I2C_BASE_IOCTL + 128)

/*
 * ARGS for I2C_*_MODE
 */
#define	I2C_NORMAL	0
#define	I2C_DEBUG	1

/*
 * ARGS for i2c_bit_t direction
 */

#define	DIR_NO_CHANGE	0
#define	DIR_OUTPUT	1
#define	DIR_INPUT	2


#define	INST_TO_MINOR(x) (x << 4)
#define	MINOR_TO_INST(x) ((x & 0xFFFFFFF0) >> 4)
#define	PORT_TO_MINOR(x)  (x)
#define	MINOR_TO_PORT(x)  (0x0F & x)

#define	I2C_PORT(x)		(0x00 + x)

typedef struct i2c_port {
	uint8_t		value;
	uint8_t		direction;
	uint8_t		dir_mask;
} i2c_port_t;

typedef struct i2c_bit {
	uchar_t		bit_num;
	boolean_t	bit_value;
	uint8_t		direction;
} i2c_bit_t;

typedef struct i2c_reg {
	uint8_t		reg_num;
	int32_t		reg_value;
} i2c_reg_t;

#if defined(_KERNEL)

#include <sys/i2c/misc/i2c_svc.h>

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _I2C_CLIENT_H */
