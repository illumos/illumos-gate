/*
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
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#ifndef _MEM_CACHE_H
#define	_MEM_CACHE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	mem_cache_device	"/devices/pseudo/mem_cache@0:mem_cache0"
#define	mem_cache_device1	"/devices/pseudo/mem_cache@1:mem_cache1"
#define	mem_cache_device2	"/devices/pseudo/mem_cache@2:mem_cache2"
#define	mem_cache_device3	"/devices/pseudo/mem_cache@3:mem_cache3"
#define	MEM_CACHE_DRIVER_NAME	"mem_cache"
#ifdef DEBUG
#define	MAX_MEM_CACHE_INSTANCES	4
#else
#define	MAX_MEM_CACHE_INSTANCES	1
#endif
#define	PN_CACHE_NWAYS	4
#define	PN_CACHE_LINESIZE	64
#define	PN_CACHE_LINE_SHIFT	6
#define	MAX_BIT_POSITION	511
#define	PN_L2_IDX_HW_ECC_EN	INT64_C(0x0000000000400000)
#define	PN_L3_IDX_HW_ECC_EN	INT64_C(0x0000000002000000)
#define	MSB_BIT_MASK		(1 << 15)
#define	TAG_BIT_MASK		0x3f


/*
 * Private ioctls for fmd(1M).  These interfaces are Sun Private.  Applications
 * and drivers should not make use of these interfaces: they can change without
 * notice and programs that consume them will fail to run on future releases.
 */

#define	MEM_CACHE_RETIRE	(('C' << 8) | 0x01)
#define	MEM_CACHE_ISRETIRED	(('C' << 8) | 0x02)
#define	MEM_CACHE_UNRETIRE	(('C' << 8) | 0x03)
#define	MEM_CACHE_STATE		(('C' << 8) | 0x04)
#define	MEM_CACHE_READ_TAGS	(('C' << 8) | 0x05)
#define	MEM_CACHE_INJECT_ERR	(('C' << 8) | 0x06)
#define	MEM_CACHE_READ_ERROR_INJECTED_TAGS	(('C' << 8) | 0x07)
#define	MEM_CACHE_PARK_UNPARK	(('C' << 8) | 0x08)
#define	MEM_CACHE_READ_RETIRE_CODE	(('C' << 8) | 0x09)
#define	MEM_CACHE_RW_RETIRE_CODE	(('C' << 8) | 0x0a)
#define	MEM_CACHE_RETIRE_AND_RW	(('C' << 8) | 0x0b)
#define	MEM_CACHE_RW_COLLISION_CODE	(('C' << 8) | 0x0c)
#define	MEM_CACHE_UNRETIRE_AND_RW	(('C' << 8) | 0x0d)
#define	MEM_CACHE_RETIRE_AND_UNRETIRE_RW	(('C' << 8) | 0x0e)

typedef enum {
	L2_CACHE_DATA,
	L2_CACHE_TAG,
	L3_CACHE_DATA,
	L3_CACHE_TAG
} cache_id_t;

typedef struct cache_info {
		int		cpu_id;
		cache_id_t	cache;
		uint32_t	index;
		uint32_t	way;
		uint16_t	bit;
		void		*datap;
} cache_info_t;

#ifdef	__cplusplus
}
#endif

#endif /* _MEM_CACHE_H */
