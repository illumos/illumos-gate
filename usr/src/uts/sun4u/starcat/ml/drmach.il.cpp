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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file is through cpp before being used as
 * an inline.  It contains support routines used
 * only by DR for the copy-rename sequence.
 */

#if defined(lint)
#include <sys/types.h>
#endif /* lint */

#include <sys/sun4asi.h>
#include <sys/privregs.h>
#include <sys/cheetahregs.h>
#include <sys/machparam.h>
#include <sys/machthread.h>
#include <sys/mmu.h>
#include <sys/cheetahasm.h>

#if defined(lint)

/*ARGSUSED*/
void
bcopy32_il(uint64_t paddr1, uint64_t paddr2)
{}

void
flush_dcache_il(void)
{}

void
flush_icache_il(void)
{}

void
flush_pcache_il(void)
{}

/*ARGSUSED*/
void
flush_ecache_il(uint64_t physaddr, uint_t size, uint_t linesz)
{}

#else /* lint */

	!
	! bcopy32_il
	!
	! input:
	!	%o0	source PA
	!	%o1	destination PA
	!
	! returns:
	!	nothing
	!
	! A simple copy routine that copies 32 bytes using physical
	! addresses. Used by drmach_copy_rename() to copy permanent
	! memory. Assumes domain is quiesced and addresses are
	! aligned appropriately.
	!
	! Derived from Starfire DR 2.6 version of bcopy32_il.
	!
	! NOTE: The rdpr instruction executes as a noop. It has no
	! runtime value or purpose. It exists here solely for its
	! magical property that protects bcopy32_il from the
	! actions of Sun Pro's code generator. The ldxa instructions
	! used in this inline are not supported by the inline feature
	! of the Sun Pro 5.0 product. See inline(1) for details.
	! Without the rdpr, the code generator improperly rewrites
	! the instructions and emits a misrepresentation of the logic.
	!
	.inline bcopy32_il, 0
	rdpr	%pstate, %g0		! See note.
        ldxa    [%o0]ASI_MEM, %o2
	add	%o0, 8, %o0
        ldxa    [%o0]ASI_MEM, %o3
	add	%o0, 8, %o0
        ldxa    [%o0]ASI_MEM, %o4
	add	%o0, 8, %o0
        ldxa    [%o0]ASI_MEM, %o5
	stxa    %o2, [%o1]ASI_MEM
	add	%o1, 8, %o1
	stxa    %o3, [%o1]ASI_MEM
	add	%o1, 8, %o1
	stxa    %o4, [%o1]ASI_MEM
	add	%o1, 8, %o1
	stxa    %o5, [%o1]ASI_MEM
	.end

	!
	! flush_dcache_il
	!
	! input:
	!	nothing
	!
	! output:
	!	nothing
	!
	! Flushes data cache. Used by drmach_copy_rename() after
	! the rename step to ensure the data cache tags and mtags
	! are properly synchronized. Assumes domain is quiesced.
	!
	.inline	flush_dcache_il, 0
	set	dcache_size, %o0
	ld	[%o0], %o0
	set	dcache_linesize, %o1
	ld	[%o1], %o1
	CH_DCACHE_FLUSHALL(%o0, %o1, %o2)
	.end

	!
	! flush_icache_il
	!
	! input:
	!	nothing
	!
	! output:
	!	nothing
	!
	! Flushes instruction cache. Used by drmach_copy_rename()
	! after the rename step to ensure the instruction cache tags
	! and mtags are properly synchronized. Assumes domain is
	! quiesced.
	!
	! Panther has a larger Icache compared to Cheetahplus or Jaguar.
	!
	.inline flush_icache_il, 0
	GET_CPU_IMPL(%o0)
	cmp	%o0, PANTHER_IMPL
	bne	%xcc, 1f
	  nop
	set	PN_ICACHE_SIZE, %o0
	set	PN_ICACHE_LSIZE, %o1
	ba	2f
	  nop
1:
	set	CH_ICACHE_SIZE, %o0
	set	CH_ICACHE_LSIZE, %o1
2:
	CH_ICACHE_FLUSHALL(%o0, %o1, %o2, %o3)
	.end

	!
	! flush_pcache_il
	!
	! input:
	!	nothing
	!
	! output:
	!	nothing
	!
	! Flushes prefetch cache. Used by drmach_copy_rename() after
	! the rename step to ensure the prefetch cache tags and mtags
	! are properly synchronized. Assumes domain is quiesced.
	!
	.inline	flush_pcache_il, 0
	PCACHE_FLUSHALL(%o1, %o2, %o3)
	.end

	!
	! flush_ecache_il
	!
	! input:
	!	%o0	PA of flush span
	!	%o1	size of this processor's E$
	!	%o2	line size of this processor's E$
	!
	! output:
	!	nothing
	!
	! Flushes external cache. Used by drmach_copy_rename() after
	! the rename step to ensure the external cache tags and mtags
	! are properly synchronized. Assumes domain is quiesced.
	!
	! Panther needs to flush L2 cache before L3 cache.
	!
	.inline flush_ecache_il, 0
        PN_L2_FLUSHALL(%o3, %o4, %o5)
	ECACHE_FLUSHALL(%o1, %o2, %o0, %o3)
	.end

#endif /* lint */

