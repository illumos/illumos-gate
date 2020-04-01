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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "assym.h"

#include <sys/asm_linkage.h>
#include <sys/machthread.h>		/* for reg definition */

#include <sys/machasi.h>		/* sun4u ASI */
#include <sys/mmu.h>
#include <sys/privregs.h>
#include <sys/machparam.h>
#include <vm/hat_sfmmu.h>
#include <sys/cpr_impl.h>
#include <sys/intreg.h>
#include <sys/clock.h>

/*
 * resume kernel entry point from cprboot
 * 	1. restore I/D TSB registers
 *	2. restore primary and secondary context registers
 *	3. initialize cpu state registers
 *	4. set up the thread and lwp registers for the cpr process
 *	5. switch to kernel trap
 *	6. restore checkpoint pc and stack pointer
 *	7. longjmp back to kernel
 *
 * registers from cprboot:exit_to_kernel()
 *	%o0	prom cookie
 *	%o1	struct sun4u_machdep *mdp
 *
 * Any change to this register assignment
 * require changes to cprboot_srt0.s
 */

	!
	! reserve 4k for cpr tmp stack; tstack should be first,
	! any new data symbols should be added after tstack.
	!
	.seg	".data"
	.global	i_cpr_data_page, i_cpr_tstack_size
	.global	i_cpr_orig_cif

	.align	MMU_PAGESIZE
i_cpr_data_page:
	.skip	4096
i_cpr_tstack:
	.word	0
i_cpr_tstack_size:
	.word	4096

	.align	8
prom_tba:
	.word	0, 0
i_cpr_orig_cif:
	.nword	0
i_cpr_tmp_cif:
	.nword	0


	!
	! set text to begin at a page boundary so we can
	! map this one page and jump to it from cprboot
	!
	.seg	".text"
	.align	MMU_PAGESIZE

	ENTRY(i_cpr_resume_setup)
	!
	! save %o args to locals
	!
	mov	%o0, %l4
	mov	%o1, %l5

	!
	! Restore PCONTEXT
	!
	sethi	%hi(FLUSH_ADDR), %g3
	ld	[%l5 + CPR_MD_PRI], %g1		! mdp->mmu_ctx_pri
	set	MMU_PCONTEXT, %g2
	stxa	%g1, [%g2]ASI_DMMU
	flush	%g3

	!
	! Restore SCONTEXT.  We do not need to set up the TSB
	! registers.  Since we are restoring INVALID_CONTEXT into
	! the secondary context the HAT will do that for us.
	!
	ld	[%l5 + CPR_MD_SEC], %g1		! mdp->mmu_ctx_sec
	set	MMU_SCONTEXT, %g2
	stxa	%g1, [%g2]ASI_DMMU
	flush	%g3

	!
	! Allow user rdtick, and rdstick if applicable
	!
	CLEARTICKNPT

	!
	! copy saved thread pointer to %g7
	!
	ldx	[%l5 + CPR_MD_THRP], THREAD_REG		! mdp->thrp

	!
	! since csu_md_t lives in a cprboot data page,
	! copy select data to registers for later use
	! before freeing cprboot text/data pages
	!
	ldx	[%l5 + CPR_MD_QSAV_PC], %l7	! l7 = mdp->qsav_pc
	ldx	[%l5 + CPR_MD_QSAV_SP], %l6	! l6 = mdp->qsav_sp

	!
	! save cookie from the new/tmp prom
	!
	set	i_cpr_tmp_cif, %g1
	stn	%l4, [%g1]

	!
	! save prom tba
	!
	set	prom_tba, %g1
	rdpr	%tba, %g2
	stx	%g2, [%g1]

	!
	! start slave cpus, pause them within kernel text,
	! and restore the original prom pages
	!
	call	i_cpr_mp_setup
	nop

	!
	! since this routine is entered only by a jmp from cprboot,
	! we can set cpr_suspend_succeeded here
	!
	set	cpr_suspend_succeeded, %l0
	mov	1, %l1
	st	%l1, [%l0]

	!
	! special shortened version of longjmp
	! Don't need to flushw
	!
	mov	%l7, %i7		! i7 = saved pc
	mov	%l6, %fp		! i6 = saved sp
	ret				! return 1
	restore	%g0, 1, %o0		! takes underflow, switches stack
	SET_SIZE(i_cpr_resume_setup)


	!
	! while running on the new/tmp prom, the prom's trap table
	! must be used to handle translations within prom space
	! since the kernel's mappings may not match this prom.
	!
	! always set %tba to the prom's trap table before calling
	! any prom service; after returning, read %tba again;
	! if the %tba wasn't changed by the prom service,
	! restore the original %tba.
	!
	! a call stack looks like this:
	!
	! current prom cookie
	! [i_cpr_cif_wrapper]
	! client_handler
	! p1275_sparc_cif_handler
	! prom_xxx
	!
	ENTRY(i_cpr_cif_wrapper)
	save	%sp, -SA64(MINFRAME64 + 8), %sp
	rdpr	%tba, %o5		! read original %tba
	stx	%o5, [%fp + V9BIAS64 - 8]
	set	prom_tba, %l4
	ldx	[%l4], %o4		! read prom_tba
	wrpr	%o4, %tba		! switch to prom trap table

	set	i_cpr_tmp_cif, %g3	! cookie for new/tmp prom
	ldn	[%g3], %g4
	jmpl	%g4, %o7		! call prom service
	mov	%i0, %o0

	ldx	[%l4], %o4		! read prom_tba
	rdpr	%tba, %o3		! read current %tba
	cmp	%o3, %o4		! did prom change %tba ?
	bne,pn	%xcc, 1f		! yes, dont reset %tba
	nop
	ldx	[%fp + V9BIAS64 - 8], %o5
	wrpr	%o5, %tba		! no change, restore orignal
1:
	ret
	restore	%g0, %o0, %o0
	SET_SIZE(i_cpr_cif_wrapper)


	!
	! write dtlb entry at index
	!
	ENTRY(dtlb_wr_entry)
	sllx    %o0, 3, %o0			! index << 3
	ldx	[%o1], %o5			! o5 = tte.ll
	ldx	[%o2], %o4			! o4 = va_tag
	srlx	%o4, MMU_PAGESHIFT, %o4		! clear any page offset
	sllx	%o4, MMU_PAGESHIFT, %o4		! o4 = va_tag & PAGEMASK
	set	MMU_TAG_ACCESS, %o3
	stxa	%o4, [%o3]ASI_DMMU
	stxa	%o5, [%o0]ASI_DTLB_ACCESS
	membar	#Sync
	retl
	nop
	SET_SIZE(dtlb_wr_entry)


	!
	! write itlb entry at index
	!
	ENTRY(itlb_wr_entry)
	sllx    %o0, 3, %o0			! index << 3
	ldx	[%o1], %o5			! o5 = tte.ll
	ldx	[%o2], %o4			! o4 = va_tag
	srlx	%o4, MMU_PAGESHIFT, %o4		! clear any page offset
	sllx	%o4, MMU_PAGESHIFT, %o4		! o4 = va_tag & PAGEMASK
	set	MMU_TAG_ACCESS, %o3
	stxa	%o4, [%o3]ASI_IMMU
	stxa	%o5, [%o0]ASI_ITLB_ACCESS
	membar	#Sync
	retl
	nop
	SET_SIZE(itlb_wr_entry)

