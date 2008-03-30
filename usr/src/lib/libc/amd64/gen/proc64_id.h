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
 * Copyright (c) 2008, Intel Corporation
 * All rights reserved.
 */

#ifndef	_PROC64_ID_H
#define	_PROC64_ID_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/x86_archext.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Defines to determine what SSE instructions can be used for memops or strops.
 */
#define	NO_SSE		0x00	/* Default -- Don't use SSE instructions */
#define	USE_SSE2	0x01	/* SSE2 */
#define	USE_SSE3	0x02	/* SSE3 */
#define	USE_SSSE3	0x04	/* Supplemental SSE3 */
#define	USE_SSE4_1	0x08	/* SSE 4.1 */
#define	USE_SSE4_2	0x10	/* SSE 4.2 */

/*
 * Cache size defaults for Core 2 Duo
 */
#define	INTEL_DFLT_L1_CACHE_SIZE	(32 * 1024)
#define	INTEL_DFLT_L2_CACHE_SIZE	(4 * 1024 * 1024)
#define	INTEL_DFLT_LARGEST_CACHE_SIZE	(4 * 1024 * 1024)

/*
 * Cache size defaults for AMD SledgeHammer
 */
#define	AMD_DFLT_L1_CACHE_SIZE		(64 * 1024)
#define	AMD_DFLT_L1_HALF_CACHE_SIZE	(32 * 1024)
#define	AMD_DFLT_L2_CACHE_SIZE		(1024 * 1024)
#define	AMD_DFLT_L2_HALF_CACHE_SIZE	(512 * 1024)

#ifdef _ASM
	.extern .memops_method
#else

void __libc_get_cpuid(int cpuid_function, void *out_reg, int cache_index);
void __intel_set_memops_method(long sse_level);
void __intel_set_cache_sizes(long l1_cache_size, long l2_cache_size,
    long largest_level_cache);

#endif /* _ASM */

#ifdef	__cplusplus
}
#endif

#endif /* _PROC64_ID_H */
