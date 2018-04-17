/*
* CDDL HEADER START
*
* The contents of this file are subject to the terms of the
* Common Development and Distribution License, v.1,  (the "License").
* You may not use this file except in compliance with the License.
*
* You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
* or http://opensource.org/licenses/CDDL-1.0.
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
* Copyright 2014-2017 Cavium, Inc. 
* The contents of this file are subject to the terms of the Common Development 
* and Distribution License, v.1,  (the "License").

* You may not use this file except in compliance with the License.

* You can obtain a copy of the License at available 
* at http://opensource.org/licenses/CDDL-1.0

* See the License for the specific language governing permissions and 
* limitations under the License.
*/

#ifndef _QEDE_TYPES_H
#define _QEDE_TYPES_H

typedef uint8_t			u8;
typedef uint8_t			U8;
typedef uint16_t		u16;
typedef uint16_t		U16;
typedef uint32_t		u32;
typedef uint32_t		U32;
typedef uint64_t		u64;
typedef	uint64_t		U64;
typedef	boolean_t		bool;

typedef u16			__le16;
typedef	u32			__le32;
typedef	u64			__le64;

typedef int8_t			s8;
typedef int16_t			s16;
typedef int32_t			s32;
typedef int64_t			s64;

typedef	void *			int_ptr_t;

typedef int OSAL_BE32;
typedef	void *	osal_dpc_t;
typedef u64 dma_addr_t;

/*
 * NOTE: This should be changed to
 * u32 for 32-bit. Add appr. ifdef
 * or kerenl type which suits this
 * requirement
 */
typedef	u64 osal_uintptr_t;

#endif  /* !_QEDE_TYPES_H */
