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

/*
 * Copyright (c) 2008, Intel Corporation
 * All rights reserved.
 */

/*
 * Assembler support routines to getcpuid information used to set
 * cache size information. Cache information used by memset, strcpy, etc..
 */

	.file	"proc64_support.s"

#include <sys/asm_linkage.h>
#include "proc64_id.h"

	.global .memops_method

/*
 * Defaults for Core 2 Duo
 */
	.data
	.balign  8
.memops_method:
	.int	NO_SSE

/*
 * Get cpuid data.
 * (void)__libc_get_cpuid(int cpuid_function, void *out_reg, int cache_index )
 */
	.text

	ENTRY(__libc_get_cpuid)
	# rdi = cpuid function, rsi = out_reg addr, rdx = cache index(fn 4)
	push	%rbx
	mov	%edx,%ecx
	mov	%edi,%eax
	cpuid
	mov	%eax,(%rsi)
	mov	%ebx,0x4(%rsi)
	mov	%ecx,0x8(%rsi)
	mov	%edx,0xc(%rsi)
	pop	%rbx              
	ret
	SET_SIZE(__libc_get_cpuid)

/*
 * Set memops SSE level to use.
 * void __intel_set_memops_method(long sse_level);
 */
	ENTRY(__intel_set_memops_method)
	mov	%edi,.memops_method(%rip)
	ret
	SET_SIZE(__intel_set_memops_method)

/*
 * Set cache info global variables used by various libc primitives.
 * __intel_set_cache_sizes(long l1_cache_size, long l2_cache_size, long largest_level_cache);
 */
	ENTRY(__intel_set_cache_sizes)
	# rdi = l1_cache_size, rsi = l2_cache_size, rdx = largest_level_cache

        mov     %rdi,.amd64cache1(%rip)
        shr     $1, %rdi
        mov     %rdi,.amd64cache1half(%rip)

        mov     %rsi,.amd64cache2(%rip)
        shr     $1, %rsi
        mov     %rsi,.amd64cache2half(%rip)

	mov	%rdx,.largest_level_cache_size(%rip)
	ret
	SET_SIZE(__intel_set_cache_sizes)
