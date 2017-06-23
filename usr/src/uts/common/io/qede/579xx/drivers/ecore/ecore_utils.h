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

#ifndef __ECORE_UTILS_H__
#define __ECORE_UTILS_H__

/* dma_addr_t manip */
/* Suppress "right shift count >= width of type" warning when that quantity is
 * 32-bits rquires the >> 16) >> 16)
 */
#define PTR_LO(x)		((u32)(((osal_uintptr_t)(x)) & 0xffffffff))
#define PTR_HI(x)		((u32)((((osal_uintptr_t)(x)) >> 16) >> 16))

#define DMA_LO(x)		((u32)(((dma_addr_t)(x)) & 0xffffffff))
#define DMA_HI(x)		((u32)(((dma_addr_t)(x)) >> 32))

#define DMA_LO_LE(x)		OSAL_CPU_TO_LE32(DMA_LO(x))
#define DMA_HI_LE(x)		OSAL_CPU_TO_LE32(DMA_HI(x))

/* It's assumed that whoever includes this has previously included an hsi
 * file defining the regpair.
 */
#define DMA_REGPAIR_LE(x, val)	(x).hi = DMA_HI_LE((val)); \
				(x).lo = DMA_LO_LE((val))

#define HILO_GEN(hi, lo, type)	((((type)(hi)) << 32) + (lo))
#define HILO_DMA(hi, lo)	HILO_GEN(hi, lo, dma_addr_t)
#define HILO_64(hi, lo)		HILO_GEN(hi, lo, u64)
#define HILO_DMA_REGPAIR(regpair)	(HILO_DMA(regpair.hi, regpair.lo))
#define HILO_64_REGPAIR(regpair)	(HILO_64(regpair.hi, regpair.lo))

#endif
