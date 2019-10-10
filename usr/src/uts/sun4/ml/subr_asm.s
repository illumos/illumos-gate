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

/*
 * General machine architecture & implementation specific
 * assembly language routines.
 */
#include "assym.h"

#include <sys/asm_linkage.h>
#include <sys/async.h>
#include <sys/machthread.h>
#include <sys/vis.h>
#include <sys/machsig.h>

	ENTRY(set_trap_table)
	set	trap_table, %o1
	rdpr	%tba, %o0
	wrpr	%o1, %tba
	retl
	wrpr	%g0, WSTATE_KERN, %wstate
	SET_SIZE(set_trap_table)

	! Store long word value at physical address
	!
	! void  stdphys(uint64_t physaddr, uint64_t value)
	!
	ENTRY(stdphys)
	/*
	 * disable interrupts, clear Address Mask to access 64 bit physaddr
	 */
	rdpr	%pstate, %o4
	andn	%o4, PSTATE_IE | PSTATE_AM, %o5
	wrpr	%o5, 0, %pstate
	stxa	%o1, [%o0]ASI_MEM
	retl
	wrpr	%g0, %o4, %pstate	! restore earlier pstate register value
	SET_SIZE(stdphys)


	! Store long word value at physical i/o address
	!
	! void  stdphysio(u_longlong_t physaddr, u_longlong_t value)
	!
	ENTRY(stdphysio)
	/*
	 * disable interrupts, clear Address Mask to access 64 bit physaddr
	 */
	rdpr	%pstate, %o4
	andn	%o4, PSTATE_IE | PSTATE_AM, %o5
	wrpr	%o5, 0, %pstate		! clear IE, AM bits
	stxa	%o1, [%o0]ASI_IO
	retl
	wrpr	%g0, %o4, %pstate	! restore earlier pstate register value
	SET_SIZE(stdphysio)


	!
	! Load long word value at physical address
	!
	! uint64_t lddphys(uint64_t physaddr)
	!
	ENTRY(lddphys)
	rdpr	%pstate, %o4
	andn	%o4, PSTATE_IE | PSTATE_AM, %o5
	wrpr	%o5, 0, %pstate
	ldxa	[%o0]ASI_MEM, %o0
	retl
	wrpr	%g0, %o4, %pstate	! restore earlier pstate register value
	SET_SIZE(lddphys)

	!
	! Load long word value at physical i/o address
	!
	! unsigned long long lddphysio(u_longlong_t physaddr)
	!
	ENTRY(lddphysio)
	rdpr	%pstate, %o4
	andn	%o4, PSTATE_IE | PSTATE_AM, %o5
	wrpr	%o5, 0, %pstate	! clear IE, AM bits
	ldxa	[%o0]ASI_IO, %o0
	retl
	wrpr	%g0, %o4, %pstate	! restore earlier pstate register value
	SET_SIZE(lddphysio)

	!
	! Store value at physical address
	!
	! void  stphys(uint64_t physaddr, int value)
	!
	ENTRY(stphys)
	rdpr	%pstate, %o4
	andn	%o4, PSTATE_IE | PSTATE_AM, %o5
	wrpr	%o5, 0, %pstate
	sta	%o1, [%o0]ASI_MEM
	retl
	wrpr	%g0, %o4, %pstate	! restore earlier pstate register value
	SET_SIZE(stphys)


	!
	! load value at physical address
	!
	! int   ldphys(uint64_t physaddr)
	!
	ENTRY(ldphys)
	rdpr	%pstate, %o4
	andn	%o4, PSTATE_IE | PSTATE_AM, %o5
	wrpr	%o5, 0, %pstate
	lda	[%o0]ASI_MEM, %o0
	srl	%o0, 0, %o0	! clear upper 32 bits
	retl
	wrpr	%g0, %o4, %pstate	! restore earlier pstate register value
	SET_SIZE(ldphys)

	!
	! Store value into physical address in I/O space
	!
	! void stphysio(u_longlong_t physaddr, uint_t value)
	!
	ENTRY_NP(stphysio)
	rdpr	%pstate, %o4		/* read PSTATE reg */
	andn	%o4, PSTATE_IE | PSTATE_AM, %o5
	wrpr	%o5, 0, %pstate
	stwa	%o1, [%o0]ASI_IO	/* store value via bypass ASI */
	retl
	wrpr	%g0, %o4, %pstate	/* restore the PSTATE */
	SET_SIZE(stphysio)

	!
	! Store value into physical address in I/O space
	!
	! void sthphysio(u_longlong_t physaddr, ushort_t value)
	!
	ENTRY_NP(sthphysio)
	rdpr	%pstate, %o4		/* read PSTATE reg */
	andn	%o4, PSTATE_IE | PSTATE_AM, %o5
	wrpr	%o5, 0, %pstate
	stha	%o1, [%o0]ASI_IO	/* store value via bypass ASI */
	retl
	wrpr	%g0, %o4, %pstate		/* restore the PSTATE */
	SET_SIZE(sthphysio)

	!
	! Store value into one byte physical address in I/O space
	!
	! void stbphysio(u_longlong_t physaddr, uchar_t value)
	!
	ENTRY_NP(stbphysio)
	rdpr	%pstate, %o4		/* read PSTATE reg */
	andn	%o4, PSTATE_IE | PSTATE_AM, %o5
	wrpr	%o5, 0, %pstate
	stba	%o1, [%o0]ASI_IO	/* store byte via bypass ASI */
	retl
	wrpr	%g0, %o4, %pstate	/* restore the PSTATE */
	SET_SIZE(stbphysio)

	!
	! load value at physical address in I/O space
	!
	! uint_t   ldphysio(u_longlong_t physaddr)
	!
	ENTRY_NP(ldphysio)
	rdpr	%pstate, %o4		/* read PSTATE reg */
	andn	%o4, PSTATE_IE | PSTATE_AM, %o5
	wrpr	%o5, 0, %pstate
	lduwa	[%o0]ASI_IO, %o0	/* load value via bypass ASI */
	retl
	wrpr	%g0, %o4, %pstate	/* restore pstate */
	SET_SIZE(ldphysio)

	!
	! load value at physical address in I/O space
	!
	! ushort_t   ldhphysio(u_longlong_t physaddr)
	!
	ENTRY_NP(ldhphysio)
	rdpr	%pstate, %o4		/* read PSTATE reg */
	andn	%o4, PSTATE_IE | PSTATE_AM, %o5
	wrpr	%o5, 0, %pstate
	lduha	[%o0]ASI_IO, %o0	/* load value via bypass ASI */
	retl
	wrpr	%g0, %o4, %pstate	/* restore pstate */
	SET_SIZE(ldhphysio)

	!
	! load byte value at physical address in I/O space
	!
	! uchar_t   ldbphysio(u_longlong_t physaddr)
	!
	ENTRY_NP(ldbphysio)
	rdpr	%pstate, %o4		/* read PSTATE reg */
	andn	%o4, PSTATE_IE | PSTATE_AM, %o5
	wrpr	%o5, 0, %pstate
	lduba	[%o0]ASI_IO, %o0	/* load value via bypass ASI */
	retl
	wrpr	%g0, %o4, %pstate	/* restore pstate */
	SET_SIZE(ldbphysio)

/*
 * save_gsr(kfpu_t *fp)
 * Store the graphics status register
 */

	ENTRY_NP(save_gsr)
	rd	%gsr, %g2			! save gsr
	retl
	stx	%g2, [%o0 + FPU_GSR]
	SET_SIZE(save_gsr)

	ENTRY_NP(restore_gsr)
	ldx	[%o0 + FPU_GSR], %g2
	wr	%g2, %g0, %gsr
	retl
	nop
	SET_SIZE(restore_gsr)

/*
 * uint64_t
 * _fp_read_pgsr()
 * Get the graphics status register info from fp and return it
 */

	ENTRY_NP(_fp_read_pgsr)
	retl
	rd	%gsr, %o0
	SET_SIZE(_fp_read_pgsr)


/*
 * uint64_t
 * get_gsr(kfpu_t *fp)
 * Get the graphics status register info from fp and return it
 */

	ENTRY_NP(get_gsr)
	retl
	ldx	[%o0 + FPU_GSR], %o0
	SET_SIZE(get_gsr)

/*
 * _fp_write_pgsr(uint64_t *buf, kfpu_t *fp)
 * Set the graphics status register info to fp from buf
 */

	ENTRY_NP(_fp_write_pgsr)
	retl
	mov	%o0, %gsr
	SET_SIZE(_fp_write_pgsr)

/*	
 * set_gsr(uint64_t buf, kfpu_t *fp)
 * Set the graphics status register info to fp from buf
 */

	ENTRY_NP(set_gsr)
	retl
	stx	%o0, [%o1 + FPU_GSR]
	SET_SIZE(set_gsr)

	ENTRY_NP(kdi_cpu_index)
	CPU_INDEX(%g1, %g2)
	jmp	%g7
	nop
	SET_SIZE(kdi_cpu_index)

	ENTRY_NP(kmdb_enter)
	t	ST_KMDB_TRAP
	retl
	nop
	SET_SIZE(kmdb_enter)

/*
 * The Spitfire floating point code has been changed not to use install/
 * save/restore/fork/freectx() because of the special memcpy library
 * routines, which will lose too much performance if they have to go
 * through the fp_disabled trap (which used to call installctx()). So
 * now fp_save/fp_restore are called from resume, and they don't care
 * whether floating point was enabled from the user program via the
 * fp_enabled trap or from the memcpy library, which just turns on floating
 * point in the fprs register itself. The new routine lwp_freeregs is
 * called everywhere freectx is called, and code was added to the sun4u-
 * specific version of lwp_forkregs (which is called everywhere forkctx
 * is called) to handle forking the floating point registers.
 *
 * Note that for the fprs dirty upper/lower bits are not used for now,
 * because the #instructions to determine if we need to use them is probably
 * greater than the #insructions just using them. This is a possible future
 * optimization, only do it with very careful benchmarking!
 *
 * The fp_fksave and and fp_load were split into two routines for the
 * sake of efficiency between the getfpregs/xregs_getfpregs and
 * setfpregs/xregs_setfpregs. But note that for saving and restoring
 * context, both *must* happen. For prmachdep, aka access from [k]adb,
 * it's OK if only one part happens.
 */ 

/*
 * fp_save(kfpu_t *fp)
 * fp_fksave(kfpu_t *fp)
 * Store the floating point registers.
 */

	ENTRY_NP(fp_save)
	ALTENTRY(fp_fksave)
	BSTORE_FPREGS(%o0, %o1)			! store V9 regs
	retl
	stx	%fsr, [%o0 + FPU_FSR]		! store fsr
	SET_SIZE(fp_fksave)
	SET_SIZE(fp_save)

/*
 * fp_v8_fksave(kfpu_t *fp)
 *
 * This is like the above routine but only saves the lower half.
 */

	ENTRY_NP(fp_v8_fksave)
	BSTORE_V8_FPREGS(%o0, %o1)		! store V8 regs
	retl
	stx	%fsr, [%o0 + FPU_FSR]		! store fsr
	SET_SIZE(fp_v8_fksave)

/*
 * fp_v8p_fksave(kfpu_t *fp)
 *
 * This is like the above routine but only saves the upper half.
 */

	ENTRY_NP(fp_v8p_fksave)
	BSTORE_V8P_FPREGS(%o0, %o1)		! store V9 extra regs
	retl
	stx	%fsr, [%o0 + FPU_FSR]		! store fsr
	SET_SIZE(fp_v8p_fksave)

/*
 * fp_restore(kfpu_t *fp)
 */

	ENTRY_NP(fp_restore)
	BLOAD_FPREGS(%o0, %o1)			! load V9 regs
	retl
	ldx	[%o0 + FPU_FSR], %fsr		! restore fsr
	SET_SIZE(fp_restore)

/*
 * fp_v8_load(kfpu_t *fp)
 */

	ENTRY_NP(fp_v8_load)
	BLOAD_V8_FPREGS(%o0, %o1)		! load V8 regs
	retl
	ldx	[%o0 + FPU_FSR], %fsr		! restore fsr
	SET_SIZE(fp_v8_load)

/*
 * fp_v8p_load(kfpu_t *fp)
 */

	ENTRY_NP(fp_v8p_load)
	BLOAD_V8P_FPREGS(%o0, %o1)		! load V9 extra regs
	retl
	ldx	[%o0 + FPU_FSR], %fsr		! restore fsr
	SET_SIZE(fp_v8p_load)

