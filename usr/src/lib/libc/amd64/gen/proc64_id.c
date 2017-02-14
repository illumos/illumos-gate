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
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 */

/*
 * Portions Copyright 2009 Advanced Micro Devices, Inc.
 */

#include <sys/types.h>
#include "proc64_id.h"

/*
 * Intel cpuid eax=4 Cache Types
 */
#define	NULL_CACHE		0x0
#define	DATA_CACHE		0x1
#define	INSTRUCTION_CACHE	0x2
#define	UNIFIED_CACHE		0x3

struct cpuid_values {
	uint_t eax;
	uint_t ebx;
	uint_t ecx;
	uint_t edx;
};

/*
 * get_intel_cache_info()
 *	Get cpu cache sizes for optimized 64-bit libc functions mem* and str*.
 *	Find the sizes of the 1st, 2nd and largest level caches.
 */
static void
get_intel_cache_info(void)
{
	int cache_level;
	int largest_cache_level = 0;
	int cache_index = 0;
	int cache_type;
	int line_size, partitions, ways, sets;
	uint_t cache_size;
	uint_t l1_cache_size = 0;
	uint_t l2_cache_size = 0;
	uint_t largest_level_cache = 0;
	struct cpuid_values cpuid_info;

	while (1) {
		__libc_get_cpuid(4, (uint_t *)&cpuid_info, cache_index);

		cache_type = cpuid_info.eax & 0x1f;
		if (cache_type == NULL_CACHE) {
			/*
			 * No more caches.
			 */
			break;
		}
		cache_index += 1;

		if (cache_type == INSTRUCTION_CACHE) {
			/*
			 * Don't care for memops
			 */
			continue;
		}

		cache_level = (cpuid_info.eax >> 0x5) & 0x7;
		line_size = (cpuid_info.ebx & 0xfff) + 1;
		partitions = ((cpuid_info.ebx >> 12) & 0x3ff) + 1;
		ways = ((cpuid_info.ebx >> 22) & 0x3ff) + 1;
		sets = cpuid_info.ecx + 1;
		cache_size = ways * partitions * line_size * sets;

		if (cache_level == 1) {
			l1_cache_size = cache_size;
		}
		if (cache_level == 2) {
			l2_cache_size = cache_size;
		}
		if (cache_level > largest_cache_level) {
			largest_cache_level = cache_level;
			largest_level_cache = cache_size;
		}
	}

	__set_cache_sizes(l1_cache_size, l2_cache_size, largest_level_cache);
}

/*
 * get_amd_cache_info()
 *      Same as get_intel_cache_info() but for AMD processors
 */
static void
get_amd_cache_info(void)
{
	uint_t l1_cache_size = AMD_DFLT_L1_CACHE_SIZE;
	uint_t l2_cache_size = AMD_DFLT_L2_CACHE_SIZE;
	uint_t l3_cache_size = 0;
	uint_t largest_level_cache = 0;
	struct cpuid_values cpuid_info;
	uint_t maxeax;
	int ncores;

	cpuid_info.eax = 0;
	__libc_get_cpuid(0x80000000, (uint_t *)&cpuid_info, -1);
	maxeax = cpuid_info.eax;

	if (maxeax >= 0x80000005) {	/* We have L1D info */
		__libc_get_cpuid(0x80000005, (uint_t *)&cpuid_info, -1);
		l1_cache_size = ((cpuid_info.ecx >> 24) & 0xff) * 1024;
	}

	if (maxeax >= 0x80000006) {	/* We have L2 and L3 info */
		__libc_get_cpuid(0x80000006, (uint_t *)&cpuid_info, -1);
		l2_cache_size = ((cpuid_info.ecx >> 16) & 0xffff) * 1024;
		l3_cache_size = ((cpuid_info.edx >> 18) & 0x3fff) * 512 * 1024;
	}

	/*
	 * L3 cache is shared between cores on the processor
	 */
	if (maxeax >= 0x80000008 && l3_cache_size != 0) {
		largest_level_cache = l3_cache_size;

		/*
		 * Divide by number of cores on the processor
		 */
		__libc_get_cpuid(0x80000008, (uint_t *)&cpuid_info, -1);
		ncores = (cpuid_info.ecx & 0xff) + 1;
		if (ncores > 1)
			largest_level_cache /= ncores;

		/*
		 * L3 is a victim cache for L2
		 */
		largest_level_cache += l2_cache_size;
	} else {
		largest_level_cache = l2_cache_size;
	}

	__set_cache_sizes(l1_cache_size, l2_cache_size,
	    largest_level_cache);
}

/*
 * proc64_id()
 *	Determine cache and SSE level to use for memops and strops specific to
 *	processor type.
 */
void
__proc64id(void)
{
	int use_sse = NO_SSE;
	struct cpuid_values cpuid_info;

	__libc_get_cpuid(0, &cpuid_info, 0);

	/*
	 * Check for AuthenticAMD
	 */
	if ((cpuid_info.ebx == 0x68747541) && /* Auth */
	    (cpuid_info.edx == 0x69746e65) && /* enti */
	    (cpuid_info.ecx == 0x444d4163)) { /* cAMD */
		get_amd_cache_info();
		return;
	}

	/*
	 * Check for GenuineIntel
	 */
	if ((cpuid_info.ebx != 0x756e6547) || /* Genu */
	    (cpuid_info.edx != 0x49656e69) || /* ineI */
	    (cpuid_info.ecx != 0x6c65746e)) { /* ntel */
		/*
		 * Not Intel - use defaults.
		 */
		return;
	}

	/*
	 * Genuine Intel
	 */

	/*
	 * Look for CPUID function 4 support - Deterministic Cache Parameters.
	 * Otherwise use default cache sizes.
	 */
	if (cpuid_info.eax >= 4) {
		get_intel_cache_info();

		/*
		 * Check what SSE versions are supported.
		 */
		__libc_get_cpuid(1, &cpuid_info, 0);
		if (cpuid_info.ecx & CPUID_INTC_ECX_SSE4_2) {
			use_sse |= USE_SSE4_2;
		}
		if (cpuid_info.ecx & CPUID_INTC_ECX_SSE4_1) {
			use_sse |= USE_SSE4_1;
		}
		if (cpuid_info.ecx & CPUID_INTC_ECX_SSSE3) {
			use_sse |= USE_SSSE3;
		}
		if (cpuid_info.ecx & CPUID_INTC_ECX_SSE3) {
			use_sse |= USE_SSE3;
		}
		if (cpuid_info.edx & CPUID_INTC_EDX_SSE2) {
			use_sse |= USE_SSE2;
		}
		use_sse |= USE_BSF;
		__intel_set_memops_method(use_sse);
	} else {
		__set_cache_sizes(INTEL_DFLT_L1_CACHE_SIZE,
		    INTEL_DFLT_L2_CACHE_SIZE,
		    INTEL_DFLT_LARGEST_CACHE_SIZE);
		__intel_set_memops_method(use_sse);
	}
}
