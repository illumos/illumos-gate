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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Assembly code support for the Olympus-C module
 */

#include "assym.h"

#include <sys/asm_linkage.h>
#include <sys/mmu.h>
#include <vm/hat_sfmmu.h>
#include <sys/machparam.h>
#include <sys/machcpuvar.h>
#include <sys/machthread.h>
#include <sys/machtrap.h>
#include <sys/privregs.h>
#include <sys/asm_linkage.h>
#include <sys/trap.h>
#include <sys/opl_olympus_regs.h>
#include <sys/opl_module.h>
#include <sys/xc_impl.h>
#include <sys/intreg.h>
#include <sys/async.h>
#include <sys/clock.h>
#include <sys/cmpregs.h>

#ifdef TRAPTRACE
#include <sys/traptrace.h>
#endif /* TRAPTRACE */

/*
 * Macro that flushes the entire Ecache.
 *
 * arg1 = ecache size
 * arg2 = ecache linesize
 * arg3 = ecache flush address - Not used for olympus-C
 */
#define	ECACHE_FLUSHALL(arg1, arg2, arg3, tmp1)				\
	mov	ASI_L2_CTRL_U2_FLUSH, arg1;				\
	mov	ASI_L2_CTRL_RW_ADDR, arg2;				\
	stxa	arg1, [arg2]ASI_L2_CTRL

/*
 * SPARC64-VI MMU and Cache operations.
 */

	ENTRY_NP(vtag_flushpage)
	/*
	 * flush page from the tlb
	 *
	 * %o0 = vaddr
	 * %o1 = sfmmup
	 */
	rdpr	%pstate, %o5
#ifdef DEBUG
	PANIC_IF_INTR_DISABLED_PSTR(%o5, opl_di_l3, %g1)
#endif /* DEBUG */
	/*
	 * disable ints
	 */
	andn	%o5, PSTATE_IE, %o4
	wrpr	%o4, 0, %pstate

	/*
	 * Then, blow out the tlb
	 * Interrupts are disabled to prevent the primary ctx register
	 * from changing underneath us.
	 */
	sethi   %hi(ksfmmup), %o3
        ldx     [%o3 + %lo(ksfmmup)], %o3
        cmp     %o3, %o1
        bne,pt   %xcc, 1f			! if not kernel as, go to 1
	  sethi	%hi(FLUSH_ADDR), %o3
	/*
	 * For Kernel demaps use primary. type = page implicitly
	 */
	stxa	%g0, [%o0]ASI_DTLB_DEMAP	/* dmmu flush for KCONTEXT */
	stxa	%g0, [%o0]ASI_ITLB_DEMAP	/* immu flush for KCONTEXT */
	flush	%o3
	retl
	  wrpr	%g0, %o5, %pstate		/* enable interrupts */
1:
	/*
	 * User demap.  We need to set the primary context properly.
	 * Secondary context cannot be used for SPARC64-VI IMMU.
	 * %o0 = vaddr
	 * %o1 = sfmmup
	 * %o3 = FLUSH_ADDR
	 */
	SFMMU_CPU_CNUM(%o1, %g1, %g2)		! %g1 = sfmmu cnum on this CPU
	
	ldub	[%o1 + SFMMU_CEXT], %o4		! %o4 = sfmmup->sfmmu_cext
	sll	%o4, CTXREG_EXT_SHIFT, %o4
	or	%g1, %o4, %g1			! %g1 = primary pgsz | cnum

	wrpr	%g0, 1, %tl
	set	MMU_PCONTEXT, %o4
	or	DEMAP_PRIMARY | DEMAP_PAGE_TYPE, %o0, %o0
	ldxa	[%o4]ASI_DMMU, %o2		! %o2 = save old ctxnum
	srlx	%o2, CTXREG_NEXT_SHIFT, %o1	! need to preserve nucleus pgsz
	sllx	%o1, CTXREG_NEXT_SHIFT, %o1	! %o1 = nucleus pgsz
	or	%g1, %o1, %g1			! %g1 = nucleus pgsz | primary pgsz | cnum
	stxa	%g1, [%o4]ASI_DMMU		! wr new ctxum 

	stxa	%g0, [%o0]ASI_DTLB_DEMAP
	stxa	%g0, [%o0]ASI_ITLB_DEMAP
	stxa	%o2, [%o4]ASI_DMMU		/* restore old ctxnum */
	flush	%o3
	wrpr	%g0, 0, %tl

	retl
	wrpr	%g0, %o5, %pstate		/* enable interrupts */
	SET_SIZE(vtag_flushpage)


	ENTRY_NP2(vtag_flushall, demap_all)
	/*
	 * flush the tlb
	 */
	sethi	%hi(FLUSH_ADDR), %o3
	set	DEMAP_ALL_TYPE, %g1
	stxa	%g0, [%g1]ASI_DTLB_DEMAP
	stxa	%g0, [%g1]ASI_ITLB_DEMAP
	flush	%o3
	retl
	nop
	SET_SIZE(demap_all)
	SET_SIZE(vtag_flushall)


	ENTRY_NP(vtag_flushpage_tl1)
	/*
	 * x-trap to flush page from tlb and tsb
	 *
	 * %g1 = vaddr, zero-extended on 32-bit kernel
	 * %g2 = sfmmup
	 *
	 * assumes TSBE_TAG = 0
	 */
	srln	%g1, MMU_PAGESHIFT, %g1
		
	sethi   %hi(ksfmmup), %g3
        ldx     [%g3 + %lo(ksfmmup)], %g3
        cmp     %g3, %g2
        bne,pt	%xcc, 1f                        ! if not kernel as, go to 1
	  slln	%g1, MMU_PAGESHIFT, %g1		/* g1 = vaddr */

	/* We need to demap in the kernel context */
	or	DEMAP_NUCLEUS | DEMAP_PAGE_TYPE, %g1, %g1
	stxa	%g0, [%g1]ASI_DTLB_DEMAP
	stxa	%g0, [%g1]ASI_ITLB_DEMAP
	retry
1:
	/* We need to demap in a user context */
	or	DEMAP_PRIMARY | DEMAP_PAGE_TYPE, %g1, %g1

	SFMMU_CPU_CNUM(%g2, %g6, %g3)	! %g6 = sfmmu cnum on this CPU
	
	ldub	[%g2 + SFMMU_CEXT], %g4		! %g4 = sfmmup->cext
	sll	%g4, CTXREG_EXT_SHIFT, %g4
	or	%g6, %g4, %g6			! %g6 = primary pgsz | cnum

	set	MMU_PCONTEXT, %g4
	ldxa	[%g4]ASI_DMMU, %g5		! %g5 = save old ctxnum
	srlx	%g5, CTXREG_NEXT_SHIFT, %g2	! %g2 = nucleus pgsz 
	sllx	%g2, CTXREG_NEXT_SHIFT, %g2	! preserve nucleus pgsz 
	or	%g6, %g2, %g6			! %g6 = nucleus pgsz | primary pgsz | cnum	
	stxa	%g6, [%g4]ASI_DMMU		! wr new ctxum
	stxa	%g0, [%g1]ASI_DTLB_DEMAP
	stxa	%g0, [%g1]ASI_ITLB_DEMAP
	stxa	%g5, [%g4]ASI_DMMU		! restore old ctxnum
	retry
	SET_SIZE(vtag_flushpage_tl1)


	ENTRY_NP(vtag_flush_pgcnt_tl1)
	/*
	 * x-trap to flush pgcnt MMU_PAGESIZE pages from tlb
	 *
	 * %g1 = vaddr, zero-extended on 32-bit kernel
	 * %g2 = <sfmmup58|pgcnt6>
	 *
	 * NOTE: this handler relies on the fact that no
	 *	interrupts or traps can occur during the loop
	 *	issuing the TLB_DEMAP operations. It is assumed
	 *	that interrupts are disabled and this code is
	 *	fetching from the kernel locked text address.
	 *
	 * assumes TSBE_TAG = 0
	 */
	set	SFMMU_PGCNT_MASK, %g4
	and	%g4, %g2, %g3			/* g3 = pgcnt - 1 */
	add	%g3, 1, %g3			/* g3 = pgcnt */

	andn	%g2, SFMMU_PGCNT_MASK, %g2	/* g2 = sfmmup */
	srln	%g1, MMU_PAGESHIFT, %g1

	sethi   %hi(ksfmmup), %g4
        ldx     [%g4 + %lo(ksfmmup)], %g4
        cmp     %g4, %g2
        bne,pn   %xcc, 1f			/* if not kernel as, go to 1 */
	  slln	%g1, MMU_PAGESHIFT, %g1		/* g1 = vaddr */

	/* We need to demap in the kernel context */
	or	DEMAP_NUCLEUS | DEMAP_PAGE_TYPE, %g1, %g1
	set	MMU_PAGESIZE, %g2		/* g2 = pgsize */
	sethi   %hi(FLUSH_ADDR), %g5
4:
	stxa	%g0, [%g1]ASI_DTLB_DEMAP
	stxa	%g0, [%g1]ASI_ITLB_DEMAP
	flush	%g5				! flush required by immu

	deccc	%g3				/* decr pgcnt */
	bnz,pt	%icc,4b
	  add	%g1, %g2, %g1			/* next page */
	retry
1:
	/*
	 * We need to demap in a user context
	 *
	 * g2 = sfmmup
	 * g3 = pgcnt
	 */
	SFMMU_CPU_CNUM(%g2, %g5, %g6)		! %g5 = sfmmu cnum on this CPU
		
	or	DEMAP_PRIMARY | DEMAP_PAGE_TYPE, %g1, %g1

	ldub	[%g2 + SFMMU_CEXT], %g4		! %g4 = sfmmup->cext
	sll	%g4, CTXREG_EXT_SHIFT, %g4
	or	%g5, %g4, %g5

	set	MMU_PCONTEXT, %g4
	ldxa	[%g4]ASI_DMMU, %g6		/* rd old ctxnum */
	srlx	%g6, CTXREG_NEXT_SHIFT, %g2	/* %g2 = nucleus pgsz */
	sllx	%g2, CTXREG_NEXT_SHIFT, %g2	/* preserve nucleus pgsz */
	or	%g5, %g2, %g5			/* %g5 = nucleus pgsz | primary pgsz | cnum */
	stxa	%g5, [%g4]ASI_DMMU		/* wr new ctxum */

	set	MMU_PAGESIZE, %g2		/* g2 = pgsize */
	sethi   %hi(FLUSH_ADDR), %g5
3:
	stxa	%g0, [%g1]ASI_DTLB_DEMAP
	stxa	%g0, [%g1]ASI_ITLB_DEMAP
	flush	%g5				! flush required by immu

	deccc	%g3				/* decr pgcnt */
	bnz,pt	%icc,3b
	  add	%g1, %g2, %g1			/* next page */

	stxa	%g6, [%g4]ASI_DMMU		/* restore old ctxnum */
	retry
	SET_SIZE(vtag_flush_pgcnt_tl1)


	ENTRY_NP(vtag_flushall_tl1)
	/*
	 * x-trap to flush tlb
	 */
	set	DEMAP_ALL_TYPE, %g4
	stxa	%g0, [%g4]ASI_DTLB_DEMAP
	stxa	%g0, [%g4]ASI_ITLB_DEMAP
	retry
	SET_SIZE(vtag_flushall_tl1)


/*
 * VAC (virtual address conflict) does not apply to OPL.
 * VAC resolution is managed by the Olympus processor hardware.
 * As a result, all OPL VAC flushing routines are no-ops.
 */

	ENTRY(vac_flushpage)
	retl
	  nop
	SET_SIZE(vac_flushpage)

	ENTRY_NP(vac_flushpage_tl1)
	retry
	SET_SIZE(vac_flushpage_tl1)


	ENTRY(vac_flushcolor)
	retl
	 nop
	SET_SIZE(vac_flushcolor)



	ENTRY(vac_flushcolor_tl1)
	retry
	SET_SIZE(vac_flushcolor_tl1)

/*
 * Determine whether or not the IDSR is busy.
 * Entry: no arguments
 * Returns: 1 if busy, 0 otherwise
 */
	ENTRY(idsr_busy)
	ldxa	[%g0]ASI_INTR_DISPATCH_STATUS, %g1
	clr	%o0
	btst	IDSR_BUSY, %g1
	bz,a,pt	%xcc, 1f
	mov	1, %o0
1:
	retl
	nop
	SET_SIZE(idsr_busy)

	.global _dispatch_status_busy
_dispatch_status_busy:
	.asciz	"ASI_INTR_DISPATCH_STATUS error: busy"
	.align	4

/*
 * Setup interrupt dispatch data registers
 * Entry:
 *	%o0 - function or inumber to call
 *	%o1, %o2 - arguments (2 uint64_t's)
 */
	.seg "text"

	ENTRY(init_mondo)
#ifdef DEBUG
	!
	! IDSR should not be busy at the moment
	!
	ldxa	[%g0]ASI_INTR_DISPATCH_STATUS, %g1
	btst	IDSR_BUSY, %g1
	bz,pt	%xcc, 1f
	nop
	sethi	%hi(_dispatch_status_busy), %o0
	call	panic
	or	%o0, %lo(_dispatch_status_busy), %o0
#endif /* DEBUG */

	ALTENTRY(init_mondo_nocheck)
	!
	! interrupt vector dispatch data reg 0
	!
1:
	mov	IDDR_0, %g1
	mov	IDDR_1, %g2
	mov	IDDR_2, %g3
	stxa	%o0, [%g1]ASI_INTR_DISPATCH

	!
	! interrupt vector dispatch data reg 1
	!
	stxa	%o1, [%g2]ASI_INTR_DISPATCH

	!
	! interrupt vector dispatch data reg 2
	!
	stxa	%o2, [%g3]ASI_INTR_DISPATCH

	membar	#Sync
	retl
	nop
	SET_SIZE(init_mondo_nocheck)
	SET_SIZE(init_mondo)


/*
 * Ship mondo to aid using busy/nack pair bn
 */
	ENTRY_NP(shipit)
	sll	%o0, IDCR_PID_SHIFT, %g1	! IDCR<23:14> = agent id
	sll	%o1, IDCR_BN_SHIFT, %g2		! IDCR<28:24> = b/n pair
	or	%g1, IDCR_OFFSET, %g1		! IDCR<13:0> = 0x70
	or	%g1, %g2, %g1
	stxa	%g0, [%g1]ASI_INTR_DISPATCH	! interrupt vector dispatch
	membar	#Sync
	retl
	nop
	SET_SIZE(shipit)


/*
 * flush_instr_mem:
 *	Flush 1 page of the I-$ starting at vaddr
 * 	%o0 vaddr
 *	%o1 bytes to be flushed
 *
 * SPARC64-VI maintains consistency of the on-chip Instruction Cache with
 * the stores from all processors so that a FLUSH instruction is only needed
 * to ensure pipeline is consistent. This means a single flush is sufficient at
 * the end of a sequence of stores that updates the instruction stream to
 * ensure correct operation.
 */

	ENTRY(flush_instr_mem)
	flush	%o0			! address irrelevant
	retl
	nop
	SET_SIZE(flush_instr_mem)


/*
 * flush_ecache:
 *	%o0 - 64 bit physical address
 *	%o1 - ecache size
 *	%o2 - ecache linesize
 */

	ENTRY(flush_ecache)

	/*
	 * Flush the entire Ecache.
	 */
	ECACHE_FLUSHALL(%o1, %o2, %o0, %o4)
	retl
	nop
	SET_SIZE(flush_ecache)

	/*
	 * I/D cache flushing is not needed for OPL processors
	 */
	ENTRY(kdi_flush_idcache)
	retl
	nop
	SET_SIZE(kdi_flush_idcache)

#ifdef	TRAPTRACE
/*
 * Simplified trap trace macro for OPL. Adapted from us3.
 */
#define	OPL_TRAPTRACE(ptr, scr1, scr2, label)			\
	CPU_INDEX(scr1, ptr);					\
	sll	scr1, TRAPTR_SIZE_SHIFT, scr1;			\
	set	trap_trace_ctl, ptr;				\
	add	ptr, scr1, scr1;				\
	ld	[scr1 + TRAPTR_LIMIT], ptr;			\
	tst	ptr;						\
	be,pn	%icc, label/**/1;				\
	 ldx	[scr1 + TRAPTR_PBASE], ptr;			\
	ld	[scr1 + TRAPTR_OFFSET], scr1;			\
	add	ptr, scr1, ptr;					\
	rd	%asi, scr2;					\
	wr	%g0, TRAPTR_ASI, %asi;				\
	rd	STICK, scr1;					\
	stxa    scr1, [ptr + TRAP_ENT_TICK]%asi;		\
	rdpr	%tl, scr1;					\
	stha    scr1, [ptr + TRAP_ENT_TL]%asi;			\
	rdpr	%tt, scr1;					\
	stha	scr1, [ptr + TRAP_ENT_TT]%asi;			\
	rdpr	%tpc, scr1;					\
	stna    scr1, [ptr + TRAP_ENT_TPC]%asi;			\
	rdpr	%tstate, scr1;					\
	stxa	scr1, [ptr + TRAP_ENT_TSTATE]%asi;		\
	stna    %sp, [ptr + TRAP_ENT_SP]%asi;			\
	stna    %g0, [ptr + TRAP_ENT_TR]%asi;			\
	stna    %g0, [ptr + TRAP_ENT_F1]%asi;			\
	stna    %g0, [ptr + TRAP_ENT_F2]%asi;			\
	stna    %g0, [ptr + TRAP_ENT_F3]%asi;			\
	stna    %g0, [ptr + TRAP_ENT_F4]%asi;			\
	wr	%g0, scr2, %asi;				\
	CPU_INDEX(ptr, scr1);					\
	sll	ptr, TRAPTR_SIZE_SHIFT, ptr;			\
	set	trap_trace_ctl, scr1;				\
	add	scr1, ptr, ptr;					\
	ld	[ptr + TRAPTR_OFFSET], scr1;			\
	ld	[ptr + TRAPTR_LIMIT], scr2;			\
	st	scr1, [ptr + TRAPTR_LAST_OFFSET];		\
	add	scr1, TRAP_ENT_SIZE, scr1;			\
	sub	scr2, TRAP_ENT_SIZE, scr2;			\
	cmp	scr1, scr2;					\
	movge	%icc, 0, scr1;					\
	st	scr1, [ptr + TRAPTR_OFFSET];			\
label/**/1:
#endif	/* TRAPTRACE */



/*
 * Macros facilitating error handling.
 */

/*
 * Save alternative global registers reg1, reg2, reg3
 * to scratchpad registers 1, 2, 3 respectively.
 */
#define	OPL_SAVE_GLOBAL(reg1, reg2, reg3)	\
	stxa	reg1, [%g0]ASI_SCRATCHPAD		;\
	mov	OPL_SCRATCHPAD_SAVE_AG2, reg1	;\
	stxa	reg2, [reg1]ASI_SCRATCHPAD		;\
	mov	OPL_SCRATCHPAD_SAVE_AG3, reg1	;\
	stxa	reg3, [reg1]ASI_SCRATCHPAD

/*
 * Restore alternative global registers reg1, reg2, reg3
 * from scratchpad registers 1, 2, 3 respectively.
 */
#define	OPL_RESTORE_GLOBAL(reg1, reg2, reg3)			\
	mov	OPL_SCRATCHPAD_SAVE_AG3, reg1			;\
	ldxa	[reg1]ASI_SCRATCHPAD, reg3				;\
	mov	OPL_SCRATCHPAD_SAVE_AG2, reg1			;\
	ldxa	[reg1]ASI_SCRATCHPAD, reg2				;\
	ldxa	[%g0]ASI_SCRATCHPAD, reg1

/*
 * Logs value `val' into the member `offset' of a structure
 * at physical address `pa'
 */
#define	LOG_REG(pa, offset, val)				\
	add	pa, offset, pa					;\
	stxa	val, [pa]ASI_MEM

#define	FLUSH_ALL_TLB(tmp1)					\
	set	DEMAP_ALL_TYPE, tmp1				;\
	stxa	%g0, [tmp1]ASI_ITLB_DEMAP			;\
	stxa	%g0, [tmp1]ASI_DTLB_DEMAP			;\
	sethi	%hi(FLUSH_ADDR), tmp1				;\
	flush	tmp1

/*
 * Extracts the Physaddr to Logging Buffer field of the OPL_SCRATCHPAD_ERRLOG
 * scratch register by zeroing all other fields. Result is in pa.
 */
#define	LOG_ADDR(pa)							\
	mov	OPL_SCRATCHPAD_ERRLOG, pa				;\
	ldxa	[pa]ASI_SCRATCHPAD, pa					;\
	sllx	pa, 64-ERRLOG_REG_EIDR_SHIFT, pa			;\
	srlx	pa, 64-ERRLOG_REG_EIDR_SHIFT+ERRLOG_REG_ERR_SHIFT, pa	;\
	sllx	pa, ERRLOG_REG_ERR_SHIFT, pa

/*
 * Advance the per-cpu error log buffer pointer to the next
 * ERRLOG_SZ entry, making sure that it will modulo (wraparound)
 * ERRLOG_BUFSIZ boundary. The args logpa, bufmask, tmp are
 * unused input registers for this macro.
 *
 * Algorithm:
 * 1. logpa = contents of errorlog scratchpad register
 * 2. bufmask = ERRLOG_BUFSIZ - 1
 * 3. tmp = logpa & ~(bufmask)     (tmp is now logbase)
 * 4. logpa += ERRLOG_SZ
 * 5. logpa = logpa & bufmask      (get new offset to logbase)
 * 4. logpa = tmp | logpa
 * 7. write logpa back into errorlog scratchpad register
 *
 * new logpa = (logpa & ~bufmask) | ((logpa + ERRLOG_SZ) & bufmask)
 *
 */
#define	UPDATE_LOGADD(logpa, bufmask, tmp)			\
	set	OPL_SCRATCHPAD_ERRLOG, tmp			;\
	ldxa	[tmp]ASI_SCRATCHPAD, logpa				;\
	set	(ERRLOG_BUFSZ-1), bufmask			;\
	andn	logpa, bufmask, tmp				;\
	add	logpa, ERRLOG_SZ, logpa				;\
	and	logpa, bufmask, logpa				;\
	or	tmp, logpa, logpa				;\
	set	OPL_SCRATCHPAD_ERRLOG, tmp			;\
	stxa	logpa, [tmp]ASI_SCRATCHPAD

/* Log error status registers into the log buffer */
#define	LOG_SYNC_REG(sfsr, sfar, tmp)				\
	LOG_ADDR(tmp)						;\
	LOG_REG(tmp, LOG_SFSR_OFF, sfsr)			;\
	LOG_ADDR(tmp)						;\
	mov	tmp, sfsr					;\
	LOG_REG(tmp, LOG_SFAR_OFF, sfar)			;\
	rd	STICK, sfar					;\
	mov	sfsr, tmp					;\
	LOG_REG(tmp, LOG_STICK_OFF, sfar)			;\
	rdpr	%tl, tmp					;\
	sllx	tmp, 32, sfar					;\
	rdpr	%tt, tmp					;\
	or	sfar, tmp, sfar					;\
	mov	sfsr, tmp					;\
	LOG_REG(tmp, LOG_TL_OFF, sfar)				;\
	set	OPL_SCRATCHPAD_ERRLOG, tmp			;\
	ldxa	[tmp]ASI_SCRATCHPAD, sfar				;\
	mov	sfsr, tmp					;\
	LOG_REG(tmp, LOG_ASI3_OFF, sfar)			;\
	rdpr	%tpc, sfar					;\
	mov	sfsr, tmp					;\
	LOG_REG(tmp, LOG_TPC_OFF, sfar)				;\
	UPDATE_LOGADD(sfsr, sfar, tmp)

#define	LOG_UGER_REG(uger, tmp, tmp2)				\
	LOG_ADDR(tmp)						;\
	mov	tmp, tmp2					;\
	LOG_REG(tmp2, LOG_UGER_OFF, uger)			;\
	mov	tmp, uger					;\
	rd	STICK, tmp2					;\
	LOG_REG(tmp, LOG_STICK_OFF, tmp2)			;\
	rdpr	%tl, tmp					;\
	sllx	tmp, 32, tmp2					;\
	rdpr	%tt, tmp					;\
	or	tmp2, tmp, tmp2					;\
	mov	uger, tmp					;\
	LOG_REG(tmp, LOG_TL_OFF, tmp2)				;\
	set	OPL_SCRATCHPAD_ERRLOG, tmp2			;\
	ldxa	[tmp2]ASI_SCRATCHPAD, tmp2				;\
	mov	uger, tmp					;\
	LOG_REG(tmp, LOG_ASI3_OFF, tmp2)			;\
	rdpr	%tstate, tmp2					;\
	mov	uger, tmp					;\
	LOG_REG(tmp, LOG_TSTATE_OFF, tmp2)			;\
	rdpr	%tpc, tmp2					;\
	mov	uger, tmp					;\
	LOG_REG(tmp, LOG_TPC_OFF, tmp2)				;\
	UPDATE_LOGADD(uger, tmp, tmp2)

/*
 * Scrub the STICK_COMPARE register to clear error by updating
 * it to a reasonable value for interrupt generation.
 * Ensure that we observe the CPU_ENABLE flag so that we
 * don't accidentally enable TICK interrupt in STICK_COMPARE
 * i.e. no clock interrupt will be generated if CPU_ENABLE flag
 * is off.
 */
#define	UPDATE_STICK_COMPARE(tmp1, tmp2)			\
	CPU_ADDR(tmp1, tmp2)					;\
	lduh	[tmp1 + CPU_FLAGS], tmp2			;\
	andcc	tmp2, CPU_ENABLE, %g0 				;\
	set	OPL_UGER_STICK_DIFF, tmp2			;\
	rd	STICK, tmp1					;\
	add	tmp1, tmp2, tmp1				;\
	mov	1, tmp2						;\
	sllx	tmp2, TICKINT_DIS_SHFT, tmp2			;\
	or	tmp1, tmp2, tmp2				;\
	movnz	%xcc, tmp1, tmp2				;\
	wr	tmp2, %g0, STICK_COMPARE

/*
 * Reset registers that may be corrupted by IAUG_CRE error.
 * To update interrupt handling related registers force the
 * clock interrupt.
 */
#define	IAG_CRE(tmp1, tmp2)					\
	set	OPL_SCRATCHPAD_ERRLOG, tmp1			;\
	ldxa	[tmp1]ASI_SCRATCHPAD, tmp1				;\
	srlx	tmp1, ERRLOG_REG_EIDR_SHIFT, tmp1		;\
	set	ERRLOG_REG_EIDR_MASK, tmp2			;\
	and	tmp1, tmp2, tmp1				;\
	stxa	tmp1, [%g0]ASI_EIDR				;\
	wr	%g0, 0, SOFTINT					;\
	sethi	%hi(hres_last_tick), tmp1			;\
	ldx	[tmp1 + %lo(hres_last_tick)], tmp1		;\
	set	OPL_UGER_STICK_DIFF, tmp2			;\
	add	tmp1, tmp2, tmp1				;\
	wr	tmp1, %g0, STICK				;\
	UPDATE_STICK_COMPARE(tmp1, tmp2)


#define	CLEAR_FPREGS(tmp)					\
	wr	%g0, FPRS_FEF, %fprs				;\
	wr	%g0, %g0, %gsr					;\
	sethi	%hi(opl_clr_freg), tmp				;\
	or	tmp, %lo(opl_clr_freg), tmp			;\
	ldx	[tmp], %fsr					;\
	fzero	 %d0						;\
	fzero	 %d2						;\
	fzero	 %d4						;\
	fzero	 %d6						;\
	fzero	 %d8						;\
	fzero	 %d10						;\
	fzero	 %d12						;\
	fzero	 %d14						;\
	fzero	 %d16						;\
	fzero	 %d18						;\
	fzero	 %d20						;\
	fzero	 %d22						;\
	fzero	 %d24						;\
	fzero	 %d26						;\
	fzero	 %d28						;\
	fzero	 %d30						;\
	fzero	 %d32						;\
	fzero	 %d34						;\
	fzero	 %d36						;\
	fzero	 %d38						;\
	fzero	 %d40						;\
	fzero	 %d42						;\
	fzero	 %d44						;\
	fzero	 %d46						;\
	fzero	 %d48						;\
	fzero	 %d50						;\
	fzero	 %d52						;\
	fzero	 %d54						;\
	fzero	 %d56						;\
	fzero	 %d58						;\
	fzero	 %d60						;\
	fzero	 %d62						;\
	wr	%g0, %g0, %fprs

#define	CLEAR_GLOBALS()						\
	mov	%g0, %g1					;\
	mov	%g0, %g2					;\
	mov	%g0, %g3					;\
	mov	%g0, %g4					;\
	mov	%g0, %g5					;\
	mov	%g0, %g6					;\
	mov	%g0, %g7

/*
 * We do not clear the alternative globals here because they
 * are scratch registers, i.e. there is no code that reads from
 * them without write to them firstly. In other words every
 * read always follows write that makes extra write to the
 * alternative globals unnecessary.
 */
#define	CLEAR_GEN_REGS(tmp1, label)				\
	set	TSTATE_KERN, tmp1				;\
	wrpr	%g0, tmp1, %tstate				;\
	mov	%g0, %y						;\
	mov	%g0, %asi					;\
	mov	%g0, %ccr					;\
	mov	%g0, %l0					;\
	mov	%g0, %l1					;\
	mov	%g0, %l2					;\
	mov	%g0, %l3					;\
	mov	%g0, %l4					;\
	mov	%g0, %l5					;\
	mov	%g0, %l6					;\
	mov	%g0, %l7					;\
	mov	%g0, %i0					;\
	mov	%g0, %i1					;\
	mov	%g0, %i2					;\
	mov	%g0, %i3					;\
	mov	%g0, %i4					;\
	mov	%g0, %i5					;\
	mov	%g0, %i6					;\
	mov	%g0, %i7					;\
	mov	%g0, %o1					;\
	mov	%g0, %o2					;\
	mov	%g0, %o3					;\
	mov	%g0, %o4					;\
	mov	%g0, %o5					;\
	mov	%g0, %o6					;\
	mov	%g0, %o7					;\
	mov	%g0, %o0					;\
	mov	%g0, %g4					;\
	mov	%g0, %g5					;\
	mov	%g0, %g6					;\
	mov	%g0, %g7					;\
	rdpr	%tl, tmp1					;\
	cmp	tmp1, 1						;\
	be,pt	%xcc, label/**/1				;\
	 rdpr	%pstate, tmp1					;\
	wrpr	tmp1, PSTATE_AG|PSTATE_IG, %pstate		;\
	CLEAR_GLOBALS()						;\
	rdpr	%pstate, tmp1					;\
	wrpr	tmp1, PSTATE_IG|PSTATE_MG, %pstate		;\
	CLEAR_GLOBALS()						;\
	rdpr	%pstate, tmp1					;\
	wrpr	tmp1, PSTATE_MG|PSTATE_AG, %pstate		;\
	ba,pt	%xcc, label/**/2				;\
	 nop							;\
label/**/1:							;\
	wrpr	tmp1, PSTATE_AG, %pstate			;\
	CLEAR_GLOBALS()						;\
	rdpr	%pstate, tmp1					;\
	wrpr	tmp1, PSTATE_AG, %pstate			;\
label/**/2:


/*
 * Reset all window related registers
 */
#define	RESET_WINREG(tmp)					\
	sethi	%hi(nwin_minus_one), tmp			;\
	ld	[tmp + %lo(nwin_minus_one)], tmp		;\
	wrpr	%g0, tmp, %cwp					;\
	wrpr	%g0, tmp, %cleanwin				;\
	sub	tmp, 1, tmp					;\
	wrpr	%g0, tmp, %cansave				;\
	wrpr	%g0, %g0, %canrestore				;\
	wrpr	%g0, %g0, %otherwin				;\
	wrpr	%g0, PIL_MAX, %pil				;\
	wrpr	%g0, WSTATE_KERN, %wstate


#define	RESET_PREV_TSTATE(tmp1, tmp2, label)			\
	rdpr	%tl, tmp1					;\
	subcc	tmp1, 1, tmp1					;\
	bz,pt	%xcc, label/**/1				;\
	 nop							;\
	wrpr	tmp1, %g0, %tl					;\
	set	TSTATE_KERN, tmp2				;\
	wrpr	tmp2, %g0, %tstate				;\
	wrpr	%g0, %g0, %tpc					;\
	wrpr	%g0, %g0, %tnpc					;\
	add	tmp1, 1, tmp1					;\
	wrpr	tmp1, %g0, %tl					;\
label/**/1:


/*
 * %pstate, %pc, %npc are propagated to %tstate, %tpc, %tnpc,
 * and we reset these regiseter here.
 */
#define	RESET_CUR_TSTATE(tmp)					\
	set	TSTATE_KERN, tmp				;\
	wrpr	%g0, tmp, %tstate				;\
	wrpr	%g0, 0, %tpc					;\
	wrpr	%g0, 0, %tnpc					;\
	RESET_WINREG(tmp)

/*
 * In case of urgent errors some MMU registers may be
 * corrupted, so we set here some reasonable values for
 * them. Note that resetting MMU registers also reset the context
 * info, we will need to reset the window registers to prevent
 * spill/fill that depends on context info for correct behaviour.
 * Note that the TLBs must be flushed before programming the context
 * registers.
 */

#define	RESET_MMU_REGS(tmp1, tmp2, tmp3)			\
	FLUSH_ALL_TLB(tmp1)					;\
	set	MMU_PCONTEXT, tmp1				;\
	sethi	%hi(kcontextreg), tmp2				;\
	ldx	[tmp2 + %lo(kcontextreg)], tmp2			;\
	stxa	tmp2, [tmp1]ASI_DMMU				;\
	set	MMU_SCONTEXT, tmp1				;\
	stxa	tmp2, [tmp1]ASI_DMMU				;\
	sethi	%hi(ktsb_base), tmp1				;\
	ldx	[tmp1 + %lo(ktsb_base)], tmp2			;\
	mov	MMU_TSB, tmp3					;\
	stxa	tmp2, [tmp3]ASI_IMMU				;\
	stxa	tmp2, [tmp3]ASI_DMMU				;\
	membar	#Sync						;\
	RESET_WINREG(tmp1)

#define	RESET_TSB_TAGPTR(tmp)					\
	set	MMU_TAG_ACCESS, tmp				;\
	stxa	%g0, [tmp]ASI_IMMU				;\
	stxa	%g0, [tmp]ASI_DMMU				;\
	membar	#Sync

/*
 * In case of errors in the MMU_TSB_PREFETCH registers we have to
 * reset them. We can use "0" as the reset value, this way we set
 * the "V" bit of the registers to 0, which will disable the prefetch
 * so the values of the other fields are irrelevant.
 */
#define	RESET_TSB_PREFETCH(tmp)			\
	set	VA_UTSBPREF_8K, tmp 		;\
	stxa	%g0, [tmp]ASI_ITSB_PREFETCH	;\
	set	VA_UTSBPREF_4M, tmp 		;\
	stxa	%g0, [tmp]ASI_ITSB_PREFETCH	;\
	set	VA_KTSBPREF_8K, tmp 		;\
	stxa	%g0, [tmp]ASI_ITSB_PREFETCH	;\
	set	VA_KTSBPREF_4M, tmp 		;\
	stxa	%g0, [tmp]ASI_ITSB_PREFETCH	;\
	set	VA_UTSBPREF_8K, tmp 		;\
	stxa	%g0, [tmp]ASI_DTSB_PREFETCH	;\
	set	VA_UTSBPREF_4M, tmp 		;\
	stxa	%g0, [tmp]ASI_DTSB_PREFETCH	;\
	set	VA_KTSBPREF_8K, tmp 		;\
	stxa	%g0, [tmp]ASI_DTSB_PREFETCH	;\
	set	VA_KTSBPREF_4M, tmp 		;\
	stxa	%g0, [tmp]ASI_DTSB_PREFETCH

/*
 * In case of errors in the MMU_SHARED_CONTEXT register we have to
 * reset its value. We can use "0" as the reset value, it will put
 * 0 in the IV field disabling the shared context support, and
 * making values of all the other fields of the register irrelevant.
 */
#define	RESET_SHARED_CTXT(tmp)			\
	set	MMU_SHARED_CONTEXT, tmp		;\
	stxa	%g0, [tmp]ASI_DMMU

/*
 * RESET_TO_PRIV()
 *
 * In many cases, we need to force the thread into privilege mode because
 * privilege mode is only thing in which the system continue to work
 * due to undeterminable user mode information that come from register
 * corruption.
 *
 *  - opl_uger_ctxt
 *    If the error is secondary TSB related register parity, we have no idea
 *    what value is supposed to be for it.
 *
 *  The below three cases %tstate is not accessible until it is overwritten
 *  with some value, so we have no clue if the thread was running on user mode
 *  or not
 *   - opl_uger_pstate
 *     If the error is %pstate parity, it propagates to %tstate.
 *   - opl_uger_tstate
 *     No need to say the reason
 *   - opl_uger_r
 *     If the error is %ccr or %asi parity, it propagates to %tstate
 *
 * For the above four cases, user mode info may not be available for
 * sys_trap() and user_trap() to work consistently. So we have to force
 * the thread into privilege mode.
 *
 * Forcing the thread to privilege mode requires forcing
 * regular %g7 to be CPU_THREAD. Because if it was running on user mode,
 * %g7 will be set in user_trap(). Also since the %sp may be in
 * an inconsistent state, we need to do a stack reset and switch to
 * something we know i.e. current thread's kernel stack.
 * We also reset the window registers and MMU registers just to
 * make sure.
 *
 * To set regular %g7, we need to clear PSTATE_AG bit and need to
 * use one local register. Note that we are panicking and will never
 * unwind back so it is ok to clobber a local.
 *
 * If the thread was running in user mode, the %tpc value itself might be
 * within the range of OBP addresses. %tpc must be forced to be zero to prevent
 * sys_trap() from going to prom_trap()
 *
 */
#define	RESET_TO_PRIV(tmp, tmp1, tmp2, local)			\
	RESET_MMU_REGS(tmp, tmp1, tmp2)				;\
	CPU_ADDR(tmp, tmp1)					;\
	ldx	[tmp + CPU_THREAD], local			;\
	ldx	[local + T_STACK], tmp				;\
	sub	tmp, STACK_BIAS, %sp				;\
	rdpr	%pstate, tmp					;\
	wrpr	tmp, PSTATE_AG, %pstate				;\
	mov	local, %g7					;\
	rdpr	%pstate, local					;\
	wrpr	local, PSTATE_AG, %pstate			;\
	wrpr	%g0, 1, %tl					;\
	set	TSTATE_KERN, tmp				;\
	rdpr	%cwp, tmp1					;\
	or	tmp, tmp1, tmp					;\
	wrpr	tmp, %g0, %tstate				;\
	wrpr	%g0, %tpc


/*
 * We normally don't expect CE traps since we disable the
 * 0x63 trap reporting at the start of day. There is a
 * small window before we disable them, so let check for
 * it. Otherwise, panic.
 */

	.align	128
	ENTRY_NP(ce_err)
	mov	AFSR_ECR, %g1
	ldxa	[%g1]ASI_ECR, %g1
	andcc	%g1, ASI_ECR_RTE_UE | ASI_ECR_RTE_CEDG, %g0
	bz,pn	%xcc, 1f
	 nop
	retry
1:
	/*
	 * We did disabled the 0x63 trap reporting.
	 * This shouldn't happen - panic.
	 */
	set	trap, %g1
	rdpr	%tt, %g3
	sethi	%hi(sys_trap), %g5
	jmp	%g5 + %lo(sys_trap)
	sub	%g0, 1, %g4
	SET_SIZE(ce_err)


/*
 * We don't use trap for CE detection.
 */
	ENTRY_NP(ce_err_tl1)
	set	trap, %g1
	rdpr	%tt, %g3
	sethi	%hi(sys_trap), %g5
	jmp	%g5 + %lo(sys_trap)
	sub	%g0, 1, %g4
	SET_SIZE(ce_err_tl1)


/*
 * async_err is the default handler for IAE/DAE traps.
 * For OPL, we patch in the right handler at start of day.
 * But if a IAE/DAE trap get generated before the handler
 * is patched, panic.
 */
	ENTRY_NP(async_err)
	set	trap, %g1
	rdpr	%tt, %g3
	sethi	%hi(sys_trap), %g5
	jmp	%g5 + %lo(sys_trap)
	sub	%g0, 1, %g4
	SET_SIZE(async_err)

	.seg	".data"
	.global	opl_clr_freg
	.global opl_cpu0_err_log

	.align	16
opl_clr_freg:
	.word	0
	.align	16

	.align	MMU_PAGESIZE
opl_cpu0_err_log:
	.skip	MMU_PAGESIZE

/*
 * Common synchronous error trap handler (tt=0xA, 0x32)
 * All TL=0 and TL>0 0xA and 0x32 traps vector to this handler.
 * The error handling can be best summarized as follows:
 * 0. Do TRAPTRACE if enabled.
 * 1. Save globals %g1, %g2 & %g3 onto the scratchpad regs.
 * 2. The SFSR register is read and verified as valid by checking
 *    SFSR.FV bit being set. If the SFSR.FV is not set, the
 *    error cases cannot be decoded/determined and the SFPAR
 *    register that contain the physical faultaddr is also
 *    not valid. Also the SPFAR is only valid for UE/TO/BERR error
 *    cases. Assuming the SFSR.FV is valid:
 *    - BERR(bus error)/TO(timeout)/UE case
 *      If any of these error cases are detected, read the SFPAR
 *      to get the faultaddress. Generate ereport.
 *    - TLB Parity case (only recoverable case)
 *      For DAE, read SFAR for the faultaddress. For IAE,
 *	use %tpc for faultaddress (SFAR is not valid in IAE)
 *	Flush all the tlbs.
 *	Subtract one from the recoverable error count stored in
 *	the error log scratch register. If the threshold limit
 *	is reached (zero) - generate ereport. Else
 *	restore globals and retry (no ereport is generated).
 *    - TLB Multiple hits
 *	For DAE, read SFAR for the faultaddress. For IAE,
 *	use %tpc for faultaddress (SFAR is not valid in IAE).
 *	Flush all tlbs and generate ereport.
 * 3. TL=0 and TL>0 considerations
 *    - Since both TL=0 & TL>1 traps are made to vector into
 *      the same handler, the underlying assumption/design here is
 *      that any nested error condition (if happens) occurs only
 *	in the handler and the system is assumed to eventually
 *      Red-mode. With this philosophy in mind, the recoverable
 *      TLB Parity error case never check the TL level before it
 *      retry. Note that this is ok for the TL>1 case (assuming we
 *	don't have a nested error) since we always save the globals
 *      %g1, %g2 & %g3 whenever we enter this trap handler.
 *    - Additional TL=0 vs TL>1 handling includes:
 *      - For UE error occuring under TL>1, special handling
 *        is added to prevent the unlikely chance of a cpu-lockup
 *        when a UE was originally detected in user stack and
 *        the spill trap handler taken from sys_trap() so happened
 *        to reference the same UE location. Under the above
 *        condition (TL>1 and UE error), paranoid code is added
 *        to reset window regs so that spill traps can't happen
 *        during the unwind back to TL=0 handling.
 *        Note that we can do that because we are not returning
 *	  back.
 * 4. Ereport generation.
 *    - Ereport generation is performed when we unwind to the TL=0
 *      handling code via sys_trap(). on_trap()/lofault protection
 *      will apply there.
 *
 */
	ENTRY_NP(opl_sync_trap)
#ifdef	TRAPTRACE
	OPL_TRAPTRACE(%g1, %g2, %g3, opl_sync_trap_lb)
	rdpr	%tt, %g1
#endif	/* TRAPTRACE */
	cmp	%g1, T_INSTR_ERROR
	bne,pt	%xcc, 0f
	 mov	MMU_SFSR, %g3
	ldxa	[%g3]ASI_IMMU, %g1	! IAE trap case tt = 0xa
	andcc	%g1, SFSR_FV, %g0
	bz,a,pn %xcc, 2f		! Branch if SFSR is invalid and
	 rdpr	%tpc, %g2		! use %tpc for faultaddr instead

	sethi	%hi(SFSR_UE|SFSR_BERR|SFSR_TO), %g3
	andcc	%g1, %g3, %g0		! Check for UE/BERR/TO errors
	bz,a,pt %xcc, 1f		! Branch if not UE/BERR/TO and
	 rdpr	%tpc, %g2		! use %tpc as faultaddr
	set	OPL_MMU_SFPAR, %g3	! In the UE/BERR/TO cases, use
	ba,pt	%xcc, 2f		! SFPAR as faultaddr
	 ldxa	[%g3]ASI_IMMU, %g2
0:
	ldxa	[%g3]ASI_DMMU, %g1	! DAE trap case tt = 0x32
	andcc	%g1, SFSR_FV, %g0
	bnz,pt  %xcc, 7f		! branch if SFSR.FV is valid
	 mov	MMU_SFAR, %g2		! set %g2 to use SFAR
	ba,pt	%xcc, 2f		! SFSR.FV is not valid, read SFAR
	 ldxa	[%g2]ASI_DMMU, %g2	! for faultaddr
7:
	sethi  %hi(SFSR_UE|SFSR_BERR|SFSR_TO), %g3
	andcc	%g1, %g3, %g0		! Check UE/BERR/TO for valid SFPAR
	movnz	%xcc, OPL_MMU_SFPAR, %g2 ! Use SFPAR instead of SFAR for
	ldxa	[%g2]ASI_DMMU, %g2	! faultaddr
1:
	sethi	%hi(SFSR_TLB_PRT), %g3
	andcc	%g1, %g3, %g0
	bz,pt	%xcc, 8f		! branch for TLB multi-hit check
	 nop
	/*
	 * This is the TLB parity error case and it is the
	 * only retryable error case.
	 * Only %g1, %g2 and %g3 are allowed
	 */
	FLUSH_ALL_TLB(%g3)
	set	OPL_SCRATCHPAD_ERRLOG, %g3
	ldxa	[%g3]ASI_SCRATCHPAD, %g3		! Read errlog scratchreg
	and	%g3, ERRLOG_REG_NUMERR_MASK, %g3! Extract the error count
	subcc	%g3, 1, %g0			! Subtract one from the count
	bz,pn	%xcc, 2f		! too many TLB parity errs in a certain
	 nop				! period, branch to generate ereport
	LOG_SYNC_REG(%g1, %g2, %g3)	! Record into the error log
	set	OPL_SCRATCHPAD_ERRLOG, %g3
	ldxa	[%g3]ASI_SCRATCHPAD, %g2
	sub	%g2, 1, %g2		! decrement error counter by 1
	stxa	%g2, [%g3]ASI_SCRATCHPAD	! update the errlog scratchreg
	OPL_RESTORE_GLOBAL(%g1, %g2, %g3)
	retry
8:
	sethi	%hi(SFSR_TLB_MUL), %g3
	andcc	%g1, %g3, %g0
	bz,pt	%xcc, 2f		! check for the TLB multi-hit errors
	 nop
	FLUSH_ALL_TLB(%g3)
2:
	/*
	 * non-retryable error handling
	 * now we can use other registers since
	 * we will not be returning back
	 */
	mov	%g1, %g5		! %g5 = SFSR
	mov	%g2, %g6		! %g6 = SFPAR or SFAR/tpc
	LOG_SYNC_REG(%g1, %g2, %g3)	! Record into the error log

	/*
	 * Special case for UE on user stack.
	 * There is a possibility that the same error may come back here
	 * by touching the same UE in spill trap handler taken from
	 * sys_trap(). It ends up with an infinite loop causing a cpu lockup.
	 * Conditions for this handling this case are:
	 * - SFSR_FV is valid and SFSR_UE is set
	 * - we are at TL > 1
	 * If the above conditions are true,  we force %cansave to be a
	 * big number to prevent spill trap in sys_trap(). Note that
	 * we will not be returning back.
	 */
	rdpr	%tt, %g4		! %g4 == ttype
	rdpr	%tl, %g1		! %g1 == tl
	cmp	%g1, 1			! Check if TL == 1
	be,pt	%xcc, 3f		! branch if we came from TL=0
	 nop
	andcc	%g5, SFSR_FV, %g0	! see if SFSR.FV is valid
	bz,pn	%xcc, 4f		! branch, checking UE is meaningless
	sethi	%hi(SFSR_UE), %g2
	andcc	%g5, %g2, %g0		! check for UE
	bz,pt	%xcc, 4f		! branch if not UE
	 nop
	RESET_WINREG(%g1)		! reset windows to prevent spills
4:
	RESET_USER_RTT_REGS(%g2, %g3, opl_sync_trap_resetskip)
opl_sync_trap_resetskip:
	mov	%g5, %g3		! pass SFSR to the 3rd arg
	mov	%g6, %g2		! pass SFAR to the 2nd arg
	set	opl_cpu_isync_tl1_error, %g1
	set	opl_cpu_dsync_tl1_error, %g6
	cmp	%g4, T_INSTR_ERROR
	movne	%icc, %g6, %g1
	ba,pt	%icc, 6f
	nop
3:
	mov	%g5, %g3		! pass SFSR to the 3rd arg
	mov	%g6, %g2		! pass SFAR to the 2nd arg
	set	opl_cpu_isync_tl0_error, %g1
	set	opl_cpu_dsync_tl0_error, %g6
	cmp	%g4, T_INSTR_ERROR
	movne	%icc, %g6, %g1
6:
	sethi	%hi(sys_trap), %g5
	jmp	%g5 + %lo(sys_trap)
	 mov	PIL_15, %g4
	SET_SIZE(opl_sync_trap)

/*
 * Common Urgent error trap handler (tt=0x40)
 * All TL=0 and TL>0 0x40 traps vector to this handler.
 * The error handling can be best summarized as follows:
 * 1. Read the Urgent error status register (UGERSR)
 *    Faultaddress is N/A here and it is not collected.
 * 2. Check to see if we have a multiple errors case
 *    If so, we enable WEAK_ED (weak error detection) bit
 *    to prevent any potential error storms and branch directly
 *    to generate ereport. (we don't decode/handle individual
 *    error cases when we get a multiple error situation)
 * 3. Now look for the recoverable error cases which include
 *    IUG_DTLB, IUG_ITLB or COREERR errors. If any of the
 *    recoverable errors are detected, do the following:
 *    - Flush all tlbs.
 *    - Verify that we came from TL=0, if not, generate
 *      ereport. Note that the reason we don't recover
 *      at TL>0 is because the AGs might be corrupted or
 *      inconsistent. We can't save/restore them into
 *      the scratchpad regs like we did for opl_sync_trap().
 *    - Check the INSTEND[5:4] bits in the UGERSR. If the
 *      value is 0x3 (11b), this error is not recoverable.
 *      Generate ereport.
 *    - Subtract one from the recoverable error count stored in
 *      the error log scratch register. If the threshold limit
 *      is reached (zero) - generate ereport.
 *    - If the count is within the limit, update the count
 *      in the error log register (subtract one). Log the error
 *      info in the log buffer. Capture traptrace if enabled.
 *      Retry (no ereport generated)
 * 4. The rest of the error cases are unrecoverable and will
 *    be handled according (flushing regs, etc as required).
 *    For details on these error cases (UGER_CRE, UGER_CTXT, etc..)
 *    consult the OPL cpu/mem philosophy doc.
 *    Ereport will be generated for these errors.
 * 5. Ereport generation.
 *    - Ereport generation for urgent error trap always
 *      result in a panic when we unwind to the TL=0 handling
 *      code via sys_trap(). on_trap()/lofault protection do
 *      not apply there.
 */
	ENTRY_NP(opl_uger_trap)
	set	ASI_UGERSR, %g2
	ldxa	[%g2]ASI_AFSR, %g1		! Read the UGERSR reg

	set	UGESR_MULTI, %g2
	andcc	%g1, %g2, %g0			! Check for Multi-errs
	bz,pt	%xcc, opl_uger_is_recover	! branch if not Multi-errs
	 nop
	set	AFSR_ECR, %g2
	ldxa	[%g2]ASI_AFSR, %g3		! Enable Weak error
	or	%g3, ASI_ECR_WEAK_ED, %g3	! detect mode to prevent
	stxa	%g3, [%g2]ASI_AFSR		! potential error storms
	ba	%xcc, opl_uger_panic1
	 nop

opl_uger_is_recover:
	set	UGESR_CAN_RECOVER, %g2		! Check for recoverable
	andcc	%g1, %g2, %g0			! errors i.e.IUG_DTLB,
	bz,pt	%xcc, opl_uger_cre		! IUG_ITLB or COREERR
	 nop

	/*
	 * Fall thru to handle recoverable case
	 * Need to do the following additional checks to determine
	 * if this is indeed recoverable.
	 * 1. Error trap came from TL=0 and
	 * 2. INSTEND[5:4] bits in UGERSR is not 0x3
	 * 3. Recoverable error count limit not reached
	 *
	 */
	FLUSH_ALL_TLB(%g3)
	rdpr	%tl, %g3		! Read TL
	cmp	%g3, 1			! Check if we came from TL=0
	bne,pt	%xcc, opl_uger_panic	! branch if came from TL>0
	 nop
	srlx	%g1, 4, %g2		! shift INSTEND[5:4] -> [1:0]
	and	%g2, 3, %g2		! extract the shifted [1:0] bits
	cmp	%g2, 3			! check if INSTEND is recoverable
	be,pt   %xcc, opl_uger_panic	! panic if ([1:0] = 11b)
	 nop
	set	OPL_SCRATCHPAD_ERRLOG, %g3
	ldxa	[%g3]ASI_SCRATCHPAD, %g2		! Read errlog scratch reg
	and	%g2, ERRLOG_REG_NUMERR_MASK, %g3! Extract error count and
	subcc	%g3, 1, %g3			! subtract one from it
	bz,pt   %xcc, opl_uger_panic	! If count reached zero, too many
	 nop				! errors, branch to generate ereport
	sub	%g2, 1, %g2			! Subtract one from the count
	set	OPL_SCRATCHPAD_ERRLOG, %g3	! and write back the updated
	stxa	%g2, [%g3]ASI_SCRATCHPAD		! count into the errlog reg
	LOG_UGER_REG(%g1, %g2, %g3)		! Log the error info
#ifdef	TRAPTRACE
	OPL_TRAPTRACE(%g1, %g2, %g3, opl_uger_trap_lb)
#endif	/* TRAPTRACE */
	retry					! retry - no ereport

	/*
	 * Process the rest of the unrecoverable error cases
	 * All error cases below ultimately branch to either
	 * opl_uger_panic or opl_uger_panic1.
	 * opl_uger_panic1 is the same as opl_uger_panic except
	 * for the additional execution of the RESET_TO_PRIV()
	 * macro that does a heavy handed reset. Read the
	 * comments for RESET_TO_PRIV() macro for more info.
	 */
opl_uger_cre:
	set	UGESR_IAUG_CRE, %g2
	andcc	%g1, %g2, %g0
	bz,pt	%xcc, opl_uger_ctxt
	 nop
	IAG_CRE(%g2, %g3)
	set	AFSR_ECR, %g2
	ldxa	[%g2]ASI_AFSR, %g3
	or	%g3, ASI_ECR_WEAK_ED, %g3
	stxa	%g3, [%g2]ASI_AFSR
	ba	%xcc, opl_uger_panic
	 nop

opl_uger_ctxt:
	set	UGESR_IAUG_TSBCTXT, %g2
	andcc	%g1, %g2, %g0
	bz,pt	%xcc, opl_uger_tsbp
	 nop
	GET_CPU_IMPL(%g2)
	cmp	%g2, JUPITER_IMPL
	bne	%xcc, 1f
	  nop
	RESET_SHARED_CTXT(%g2)
1:
	RESET_MMU_REGS(%g2, %g3, %g4)
	ba	%xcc, opl_uger_panic
	 nop

opl_uger_tsbp:
	set	UGESR_IUG_TSBP, %g2
	andcc	%g1, %g2, %g0
	bz,pt	%xcc, opl_uger_pstate
	 nop
	GET_CPU_IMPL(%g2)
	cmp	%g2, JUPITER_IMPL
	bne	%xcc, 1f
	  nop
	RESET_TSB_PREFETCH(%g2)
1:
	RESET_TSB_TAGPTR(%g2)

	/*
	 * IUG_TSBP error may corrupt MMU registers
	 * Reset them here.
	 */
	RESET_MMU_REGS(%g2, %g3, %g4)
	ba	%xcc, opl_uger_panic
	 nop

opl_uger_pstate:
	set	UGESR_IUG_PSTATE, %g2
	andcc	%g1, %g2, %g0
	bz,pt	%xcc, opl_uger_tstate
	 nop
	RESET_CUR_TSTATE(%g2)
	ba	%xcc, opl_uger_panic1
	 nop

opl_uger_tstate:
	set	UGESR_IUG_TSTATE, %g2
	andcc	%g1, %g2, %g0
	bz,pt	%xcc, opl_uger_f
	 nop
	RESET_PREV_TSTATE(%g2, %g3, opl_uger_tstate_1)
	ba	%xcc, opl_uger_panic1
	 nop

opl_uger_f:
	set	UGESR_IUG_F, %g2
	andcc	%g1, %g2, %g0
	bz,pt	%xcc, opl_uger_r
	 nop
	CLEAR_FPREGS(%g2)
	ba	%xcc, opl_uger_panic
	 nop

opl_uger_r:
	set	UGESR_IUG_R, %g2
	andcc	%g1, %g2, %g0
	bz,pt	%xcc, opl_uger_panic1
	 nop
	CLEAR_GEN_REGS(%g2, opl_uger_r_1)
	ba	%xcc, opl_uger_panic1
	 nop

opl_uger_panic:
	mov	%g1, %g2			! %g2 = arg #1
	LOG_UGER_REG(%g1, %g3, %g4)
	ba	%xcc, opl_uger_panic_cmn
	 nop

opl_uger_panic1:
	mov	%g1, %g2			! %g2 = arg #1
	LOG_UGER_REG(%g1, %g3, %g4)
	RESET_TO_PRIV(%g1, %g3, %g4, %l0)

	/*
	 * Set up the argument for sys_trap.
	 * %g2 = arg #1 already set above
	 */
opl_uger_panic_cmn:
	RESET_USER_RTT_REGS(%g4, %g5, opl_uger_panic_resetskip)
opl_uger_panic_resetskip:
	rdpr	%tl, %g3			! arg #2
	set	opl_cpu_urgent_error, %g1	! pc
	sethi	%hi(sys_trap), %g5
	jmp	%g5 + %lo(sys_trap)
	 mov	PIL_15, %g4
	SET_SIZE(opl_uger_trap)

/*
 * OPL ta3 support (note please, that win_reg
 * area size for each cpu is 2^7 bytes)
 */

#define	RESTORE_WREGS(tmp1, tmp2)		\
	CPU_INDEX(tmp1, tmp2)			;\
	sethi	%hi(opl_ta3_save), tmp2		;\
	ldx	[tmp2 +%lo(opl_ta3_save)], tmp2	;\
	sllx	tmp1, 7, tmp1			;\
	add	tmp2, tmp1, tmp2		;\
	ldx	[tmp2 + 0], %l0			;\
	ldx	[tmp2 + 8], %l1			;\
	ldx	[tmp2 + 16], %l2		;\
	ldx	[tmp2 + 24], %l3		;\
	ldx	[tmp2 + 32], %l4		;\
	ldx	[tmp2 + 40], %l5		;\
	ldx	[tmp2 + 48], %l6		;\
	ldx	[tmp2 + 56], %l7		;\
	ldx	[tmp2 + 64], %i0		;\
	ldx	[tmp2 + 72], %i1		;\
	ldx	[tmp2 + 80], %i2		;\
	ldx	[tmp2 + 88], %i3		;\
	ldx	[tmp2 + 96], %i4		;\
	ldx	[tmp2 + 104], %i5		;\
	ldx	[tmp2 + 112], %i6		;\
	ldx	[tmp2 + 120], %i7

#define	SAVE_WREGS(tmp1, tmp2)			\
	CPU_INDEX(tmp1, tmp2)			;\
	sethi	%hi(opl_ta3_save), tmp2		;\
	ldx	[tmp2 +%lo(opl_ta3_save)], tmp2	;\
	sllx	tmp1, 7, tmp1			;\
	add	tmp2, tmp1, tmp2		;\
	stx	%l0, [tmp2 + 0] 		;\
	stx	%l1, [tmp2 + 8] 		;\
	stx	%l2, [tmp2 + 16] 		;\
	stx	%l3, [tmp2 + 24]		;\
	stx	%l4, [tmp2 + 32]		;\
	stx	%l5, [tmp2 + 40]		;\
	stx	%l6, [tmp2 + 48] 		;\
	stx	%l7, [tmp2 + 56]		;\
	stx	%i0, [tmp2 + 64]		;\
	stx	%i1, [tmp2 + 72]		;\
	stx	%i2, [tmp2 + 80]		;\
	stx	%i3, [tmp2 + 88]		;\
	stx	%i4, [tmp2 + 96]		;\
	stx	%i5, [tmp2 + 104]		;\
	stx	%i6, [tmp2 + 112]		;\
	stx	%i7, [tmp2 + 120] 


/*
 * The purpose of this function is to make sure that the restore 
 * instruction after the flushw does not cause a fill trap. The sun4u 
 * fill trap handler can not handle a tlb fault of an unmapped stack 
 * except at the restore instruction at user_rtt. On OPL systems the 
 * stack can get unmapped between the flushw and restore instructions 
 * since multiple strands share the tlb.
 */
	ENTRY_NP(opl_ta3_trap)
	set	trap, %g1
	mov	T_FLUSHW, %g3
	sub	%g0, 1, %g4
	rdpr	%cwp, %g5
	SAVE_WREGS(%g2, %g6)
	save
	flushw
	rdpr	%cwp, %g6
	wrpr	%g5, %cwp
	RESTORE_WREGS(%g2, %g5)
	wrpr	%g6, %cwp
	restored
	restore

	ba,a    fast_trap_done
	SET_SIZE(opl_ta3_trap)

	ENTRY_NP(opl_cleanw_subr)
	set	trap, %g1
	mov	T_FLUSHW, %g3
	sub	%g0, 1, %g4
	rdpr	%cwp, %g5
	SAVE_WREGS(%g2, %g6)
	save
	flushw
	rdpr	%cwp, %g6
	wrpr	%g5, %cwp
	RESTORE_WREGS(%g2, %g5)
	wrpr	%g6, %cwp
	restored
	restore
	jmp	%g7
	  nop
	SET_SIZE(opl_cleanw_subr)

/*
 * The actual trap handler for tt=0x0a, and tt=0x32
 */
	ENTRY_NP(opl_serr_instr)
	OPL_SAVE_GLOBAL(%g1,%g2,%g3)
	sethi   %hi(opl_sync_trap), %g3
	jmp	%g3 + %lo(opl_sync_trap)
	 rdpr    %tt, %g1
	.align  32
	SET_SIZE(opl_serr_instr)

/*
 * The actual trap handler for tt=0x40
 */
	ENTRY_NP(opl_ugerr_instr)
	sethi   %hi(opl_uger_trap), %g3
	jmp	%g3 + %lo(opl_uger_trap)
	 nop
	.align  32
	SET_SIZE(opl_ugerr_instr)

/*
 * The actual trap handler for tt=0x103 (flushw)
 */
	ENTRY_NP(opl_ta3_instr)
	sethi   %hi(opl_ta3_trap), %g3
	jmp	%g3 + %lo(opl_ta3_trap)
	 nop
	.align  32
	SET_SIZE(opl_ta3_instr)

/*
 * The patch for the .clean_windows code
 */
	ENTRY_NP(opl_ta4_instr)
	sethi   %hi(opl_cleanw_subr), %g3
	add	%g3, %lo(opl_cleanw_subr), %g3
	jmpl	%g3, %g7
	  add	%g7, 8, %g7
	nop
	nop
	nop
	SET_SIZE(opl_ta4_instr)

	ENTRY_NP(stick_timestamp)
	rd	STICK, %g1	! read stick reg
	sllx	%g1, 1, %g1
	srlx	%g1, 1, %g1	! clear npt bit

	retl
	stx	%g1, [%o0]	! store the timestamp
	SET_SIZE(stick_timestamp)


	ENTRY_NP(stick_adj)
	rdpr	%pstate, %g1		! save processor state
	andn	%g1, PSTATE_IE, %g3
	ba	1f			! cache align stick adj
	wrpr	%g0, %g3, %pstate	! turn off interrupts

	.align	16
1:	nop

	rd	STICK, %g4		! read stick reg
	add	%g4, %o0, %o1		! adjust stick with skew
	wr	%o1, %g0, STICK		! write stick reg

	retl
	wrpr	%g1, %pstate		! restore processor state
	SET_SIZE(stick_adj)

	ENTRY_NP(kdi_get_stick)
	rd	STICK, %g1
	stx	%g1, [%o0]
	retl
	mov	%g0, %o0
	SET_SIZE(kdi_get_stick)

	ENTRY(dtrace_blksuword32)
	save	%sp, -SA(MINFRAME + 4), %sp

	rdpr	%pstate, %l1
	andn	%l1, PSTATE_IE, %l2		! disable interrupts to
	wrpr	%g0, %l2, %pstate		! protect our FPU diddling

	rd	%fprs, %l0
	andcc	%l0, FPRS_FEF, %g0
	bz,a,pt	%xcc, 1f			! if the fpu is disabled
	wr	%g0, FPRS_FEF, %fprs		! ... enable the fpu

	st	%f0, [%fp + STACK_BIAS - 4]	! save %f0 to the stack
1:
	set	0f, %l5
	/*
	 * We're about to write a block full or either total garbage
	 * (not kernel data, don't worry) or user floating-point data
	 * (so it only _looks_ like garbage).
	 */
	ld	[%i1], %f0			! modify the block
	membar	#Sync
	stn	%l5, [THREAD_REG + T_LOFAULT]	! set up the lofault handler
	stda	%d0, [%i0]ASI_BLK_COMMIT_S	! store the modified block
	membar	#Sync
	flush	%i0				! flush instruction pipeline
	stn	%g0, [THREAD_REG + T_LOFAULT]	! remove the lofault handler

	bz,a,pt	%xcc, 1f
	wr	%g0, %l0, %fprs			! restore %fprs

	ld	[%fp + STACK_BIAS - 4], %f0	! restore %f0
1:

	wrpr	%g0, %l1, %pstate		! restore interrupts

	ret
	restore	%g0, %g0, %o0

0:
	membar	#Sync
	stn	%g0, [THREAD_REG + T_LOFAULT]	! remove the lofault handler

	bz,a,pt	%xcc, 1f
	wr	%g0, %l0, %fprs			! restore %fprs

	ld	[%fp + STACK_BIAS - 4], %f0	! restore %f0
1:

	wrpr	%g0, %l1, %pstate		! restore interrupts

	/*
	 * If tryagain is set (%i2) we tail-call dtrace_blksuword32_err()
	 * which deals with watchpoints. Otherwise, just return -1.
	 */
	brnz,pt	%i2, 1f
	nop
	ret
	restore	%g0, -1, %o0
1:
	call	dtrace_blksuword32_err
	restore

	SET_SIZE(dtrace_blksuword32)

	ENTRY_NP(ras_cntr_reset)
	set	OPL_SCRATCHPAD_ERRLOG, %o1
	ldxa	[%o1]ASI_SCRATCHPAD, %o0
	or	%o0, ERRLOG_REG_NUMERR_MASK, %o0
	retl
	 stxa	%o0, [%o1]ASI_SCRATCHPAD
	SET_SIZE(ras_cntr_reset)

	ENTRY_NP(opl_error_setup)
	/*
	 * Initialize the error log scratchpad register
	 */
	ldxa	[%g0]ASI_EIDR, %o2
	sethi	%hi(ERRLOG_REG_EIDR_MASK), %o1
	or	%o1, %lo(ERRLOG_REG_EIDR_MASK), %o1
	and	%o2, %o1, %o3
	sllx	%o3, ERRLOG_REG_EIDR_SHIFT, %o2
	or	%o2, %o0, %o3
	or	%o3, ERRLOG_REG_NUMERR_MASK, %o0
	set	OPL_SCRATCHPAD_ERRLOG, %o1
	stxa	%o0, [%o1]ASI_SCRATCHPAD
	/*
	 * Disable all restrainable error traps
	 */
	mov	AFSR_ECR, %o1
	ldxa	[%o1]ASI_AFSR, %o0
	andn	%o0, ASI_ECR_RTE_UE|ASI_ECR_RTE_CEDG, %o0
	retl
	  stxa	%o0, [%o1]ASI_AFSR
	SET_SIZE(opl_error_setup)

	ENTRY_NP(cpu_early_feature_init)
	/*
	 * Enable MMU translating multiple page sizes for
	 * sITLB and sDTLB.
	 */
        mov	LSU_MCNTL, %o0
        ldxa	[%o0] ASI_MCNTL, %o1
        or	%o1, MCNTL_MPG_SITLB | MCNTL_MPG_SDTLB, %o1
          stxa	%o1, [%o0] ASI_MCNTL
	/*
	 * Demap all previous entries.
	 */
	sethi	%hi(FLUSH_ADDR), %o1
	set	DEMAP_ALL_TYPE, %o0
	stxa	%g0, [%o0]ASI_DTLB_DEMAP
	stxa	%g0, [%o0]ASI_ITLB_DEMAP
	retl
	  flush	%o1
	SET_SIZE(cpu_early_feature_init)

/*
 * This function is called for each (enabled) CPU. We use it to
 * initialize error handling related registers.
 */
	ENTRY(cpu_feature_init)
	!
	! get the device_id and store the device_id
	! in the appropriate cpunodes structure
	! given the cpus index
	!
	CPU_INDEX(%o0, %o1)
	mulx %o0, CPU_NODE_SIZE, %o0
	set  cpunodes + DEVICE_ID, %o1
	ldxa [%g0] ASI_DEVICE_SERIAL_ID, %o2
	stx  %o2, [%o0 + %o1]
	!
	! initialize CPU registers
	!
	ba	opl_cpu_reg_init
	nop
	SET_SIZE(cpu_feature_init)

	/*
	 * Clear the NPT (non-privileged trap) bit in the %tick/%stick
	 * registers. In an effort to make the change in the
	 * tick/stick counter as consistent as possible, we disable
	 * all interrupts while we're changing the registers. We also
	 * ensure that the read and write instructions are in the same
	 * line in the instruction cache.
	 */
	ENTRY_NP(cpu_clearticknpt)
	rdpr	%pstate, %g1		/* save processor state */
	andn	%g1, PSTATE_IE, %g3	/* turn off */
	wrpr	%g0, %g3, %pstate	/*   interrupts */
	rdpr	%tick, %g2		/* get tick register */
	brgez,pn %g2, 1f		/* if NPT bit off, we're done */
	mov	1, %g3			/* create mask */
	sllx	%g3, 63, %g3		/*   for NPT bit */
	ba,a,pt	%xcc, 2f
	.align	8			/* Ensure rd/wr in same i$ line */
2:
	rdpr	%tick, %g2		/* get tick register */
	wrpr	%g3, %g2, %tick		/* write tick register, */
					/*   clearing NPT bit   */
1:
	rd	STICK, %g2		/* get stick register */
	brgez,pn %g2, 3f		/* if NPT bit off, we're done */
	mov	1, %g3			/* create mask */
	sllx	%g3, 63, %g3		/*   for NPT bit */
	ba,a,pt	%xcc, 4f
	.align	8			/* Ensure rd/wr in same i$ line */
4:
	rd	STICK, %g2		/* get stick register */
	wr	%g3, %g2, STICK		/* write stick register, */
					/*   clearing NPT bit   */
3:
	jmp	%g4 + 4
	wrpr	%g0, %g1, %pstate	/* restore processor state */

	SET_SIZE(cpu_clearticknpt)

	/*
	 * Halt the current strand with the suspend instruction.
	 * The compiler/asm currently does not support this suspend
	 * instruction mnemonic, use byte code for now.
	 */
	ENTRY_NP(cpu_halt_cpu)
	.word   0x81b01040
	retl
	nop
	SET_SIZE(cpu_halt_cpu)

	/*
	 * Pause the current strand with the sleep instruction.
	 * The compiler/asm currently does not support this sleep
	 * instruction mnemonic, use byte code for now.
	 */
	ENTRY_NP(cpu_smt_pause)
	.word   0x81b01060
	retl
	nop
	SET_SIZE(cpu_smt_pause)

