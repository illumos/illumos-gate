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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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

#ifndef	INLINE

#include <sys/asm_linkage.h>

#else /* INLINE */

#define	ENTRY_NP(x)	.inline	x,0
#define	retl		/* nop */
#define	SET_SIZE(x)	.end

#endif /* INLINE */

#include <sys/privregs.h>
#include <sys/sun4asi.h>
#include <sys/machparam.h>

#include <sys/intreg.h>
#include <sys/opl_olympus_regs.h>

/*
 * Bcopy routine used by DR to copy
 * between physical addresses.
 * Borrowed from Starfire DR 2.6.
 */
#if defined(lint)

/*ARGSUSED*/
void
bcopy32_il(uint64_t paddr1, uint64_t paddr2)
{}

#else /* lint */

	ENTRY_NP(bcopy32_il)
	.register %g2, #scratch
	.register %g3, #scratch
	rdpr	%pstate, %g0
	ldxa	[%o0]ASI_MEM, %o2
	add	%o0, 8, %o0
	ldxa	[%o0]ASI_MEM, %o3
	add	%o0, 8, %o0
	ldxa	[%o0]ASI_MEM, %g1
	add	%o0, 8, %o0
	ldxa	[%o0]ASI_MEM, %g2

	stxa	%o2, [%o1]ASI_MEM
	add	%o1, 8, %o1
	stxa	%o3, [%o1]ASI_MEM
	add	%o1, 8, %o1
	stxa	%g1, [%o1]ASI_MEM
	add	%o1, 8, %o1
	stxa	%g2, [%o1]ASI_MEM

	retl
	nop
	SET_SIZE(bcopy32_il)

#endif /* lint */

#if defined(lint)

/*ARGSUSED*/
void
flush_cache_il(void)
{}

#else /* lint */

	ENTRY_NP(flush_cache_il)
	rdpr	%pstate, %o3
	andn	%o3, PSTATE_IE, %o4
	wrpr	%g0, %o4, %pstate
	mov	ASI_L2_CTRL_U2_FLUSH, %o4
	mov	ASI_L2_CTRL_RW_ADDR, %o5
	stxa	%o4, [%o5]ASI_L2_CTRL
	! retl
	wrpr	%g0, %o3, %pstate	! restore earlier pstate
	SET_SIZE(flush_cache_il)

#endif /* lint */

#if defined(lint)
/* ARGUSED */
uint64_t
drmach_get_stick_il(void)
{}

#else /* lint */
	ENTRY_NP(drmach_get_stick_il)
	retl
	rd	STICK, %o0
	SET_SIZE(drmach_get_stick_il)
#endif /* lint */

#if defined(lint)
/* ARGUSED */
void
membar_sync_il(void)
{}

#else /* lint */
	ENTRY_NP(membar_sync_il)
	retl
	membar #Sync
	SET_SIZE(membar_sync_il)
#endif /* lint */


#if defined(lint)

/* ARGSUSED */
void
flush_instr_mem_il(caddr_t vaddr)
{}

#else	/* lint */

/*
 * flush_instr_mem:
 *	Flush 1 page of the I-$ starting at vaddr
 * 	%o0 vaddr
 *
 * SPARC64-VI maintains consistency of the on-chip Instruction Cache with
 * the stores from all processors so that a FLUSH instruction is only needed
 * to ensure pipeline is consistent. This means a single flush is sufficient at
 * the end of a sequence of stores that updates the instruction stream to
 * ensure correct operation.
 */

	ENTRY_NP(flush_instr_mem_il)
	flush	%o0			! address irrelevant
	retl
	 nop
	SET_SIZE(flush_instr_mem_il)

#endif	/* lint */

#if defined(lint)

/* ARGSUSED */
void
drmach_sleep_il(void)
{}

#else	/* lint */

/*
 * drmach-sleep_il:
 *
 * busy loop wait can affect performance of the sibling strand
 * the sleep instruction can be used to avoid that.
 */

	ENTRY_NP(drmach_sleep_il)
.word	0x81b01060
	retl
	 nop
	SET_SIZE(drmach_sleep_il)

#endif	/* lint */

#if defined(lint)

/* ARGSUSED */
void
flush_windows_il(void)
{}

#else	/* lint */

/*
 * flush_windows_il:
 *
 */

	ENTRY_NP(flush_windows_il)
	retl
	 flushw
	SET_SIZE(flush_windows_il)

#endif	/* lint */
