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
 *
 * History:
 *    25/10/09 Shay Haroush        Inception.
 ******************************************************************************/

#ifndef __bcm_utils_h__
#define __bcm_utils_h__
#include "bcmtype.h"
#include "utils.h"

#include "cyclic_oper.h"

/*
U64_LO
U64_HI
get 64 hi/lo value
*/
#define U64_LO(x)           ((u32_t)(((u64_t)(x)) & (u64_t)0xffffffff))
#define U64_HI(x)           ((u32_t)(((u64_t)(x)) >> 32))
#define HILO_U64(hi, lo)	((((u64)(hi)) << 32) + (lo))

#ifndef MAX_VARIABLE_VALUE
#define MAX_VARIABLE_VALUE(x)   ((((u64_t)1) << (sizeof(x) * BITS_PER_BYTE)) -1)
#endif //MAX_VARIABLE_VALUE

/*
 * Inlined SWAP functions to ensure arguments are never re-evaluated and remain
 * atomic.  For example, an argument passed in that is actually a de-reference
 * to volatile memory would be de-referenced multiple times if these swap
 * routines were macros.
 */

static __inline u16_t SWAP_BYTES16(u16_t val16)
{
    return (((val16 & 0x00ff) << 8) |
            ((val16 & 0xff00) >> 8));
}

static __inline u32_t SWAP_BYTES32(u32_t val32)
{
    return ((SWAP_BYTES16(val32 & 0x0000ffff) << 16) |
            (SWAP_BYTES16((val32 & 0xffff0000) >> 16)));
}


static __inline u64_t SWAP_DWORDS(u64_t val)
{
    return (((val & (u64_t)0x00000000ffffffffLL) << 32) |
            ((val & (u64_t)0xffffffff00000000LL) >> 32));
}

#endif /* __bcm_utils_h__ */
