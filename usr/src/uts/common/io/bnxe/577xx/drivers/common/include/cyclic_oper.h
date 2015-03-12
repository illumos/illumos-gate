/*******************************************************************************
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
 *
 * Copyright 2014 QLogic Corporation
 * The contents of this file are subject to the terms of the
 * QLogic End User License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://www.qlogic.com/Resources/Documents/DriverDownloadHelp/
 * QLogic_End_User_Software_License.txt
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 *
 * Module Description:
 *  This file should include pure ANSI C defines
 *
 * History:
 *    25/04/10 Shay Haroush        Inception.
 ******************************************************************************/
#ifndef CYCLIC_OPERATIONS
#define CYCLIC_OPERATIONS

/********	Cyclic Operators Macros	********/

#define _ABS_DIFF(x, y) ((x) > (y) ? (x) - (y) : (y) - (x))

static __inline u8_t _cyclic_lt(u32_t x, u32_t y, u32_t d)
{
	u32_t diff = _ABS_DIFF(x,y);
	return (diff < d) ? x < y : x > y;
}

static __inline u8_t _cyclic_le(u32_t x, u32_t y, u32_t d)
{
	u32_t diff = _ABS_DIFF(x,y);
	return (diff < d) ? x <= y : x >= y;
}

#define CYCLIC_LT_8(x, y)  (_cyclic_lt(x, y, 128))
#define CYCLIC_LT_16(x, y) (_cyclic_lt(x, y, 32768))
#define CYCLIC_LT_24(x, y) (_cyclic_lt(x, y, 8388608))
#define CYCLIC_LT_32(x, y) (_cyclic_lt(x, y, 2147483648))

#define CYCLIC_LE_8(x, y)  (_cyclic_le(x, y, 128))
#define CYCLIC_LE_16(x, y) (_cyclic_le(x, y, 32768))
#define CYCLIC_LE_24(x, y) (_cyclic_le(x, y, 8388608))
#define CYCLIC_LE_32(x, y) (_cyclic_le(x, y, 2147483648))

#define CYCLIC_GT_8(x, y)  (!(CYCLIC_LE_8(x, y)))
#define CYCLIC_GT_16(x, y) (!(CYCLIC_LE_16(x, y)))
#define CYCLIC_GT_24(x, y) (!(CYCLIC_LE_24(x, y)))
#define CYCLIC_GT_32(x, y) (!(CYCLIC_LE_32(x, y)))

#define CYCLIC_GE_8(x, y)  (!(CYCLIC_LT_8(x, y)))
#define CYCLIC_GE_16(x, y) (!(CYCLIC_LT_16(x, y)))
#define CYCLIC_GE_24(x, y) (!(CYCLIC_LT_24(x, y)))
#define CYCLIC_GE_32(x, y) (!(CYCLIC_LT_32(x, y)))

// bits = number of bits in x, y (i.e., sizeof_x)
#define CYCLIC_LT_BITS(x, y, bits)	_cyclic_lt(x, y, 1 << ((bits)-1))
#define CYCLIC_LE_BITS(x, y, bits)	_cyclic_le(x, y, 1 << ((bits)-1))
#define CYCLIC_GT_BITS(x, y, bits)	(!(CYCLIC_LE_BITS(x, y, bits)))
#define CYCLIC_GE_BITS(x, y, bits)	(!(CYCLIC_LT_BITS(x, y, bits)))

/********	End	Cyclic Operators Macros	********/

#endif // CYCLIC_OPERATIONS
