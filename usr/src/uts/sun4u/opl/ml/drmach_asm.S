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
 */

/*
 * This file is through cpp before being used as
 * an inline.  It contains support routines used
 * only by DR for the copy-rename sequence.
 */

#include "assym.h"
#include "drmach_offsets.h"

#include <sys/asm_linkage.h>
#include <sys/param.h>
#include <sys/privregs.h>
#include <sys/spitregs.h>
#include <sys/mmu.h>
#include <sys/machthread.h>
#include <sys/pte.h>
#include <sys/stack.h>
#include <sys/vis.h>
#include <sys/intreg.h>
#include <sys/cheetahregs.h>
#include <sys/drmach.h>
#include <sys/sbd_ioctl.h>

/*
 * turn off speculative mode to prevent unwanted memory access
 * when we are in the FMEM loops
 */

#define	FJSV_SPECULATIVE_OFF(reg, tmp1, tmp2)				\
	rdpr	%pstate, reg						;\
	andn	reg, PSTATE_IE, tmp1					;\
	wrpr	%g0, tmp1, %pstate					;\
	ldxa	[%g0]ASI_MCNTL, tmp1					;\
	set	1, tmp2							;\
	sllx	tmp2, MCNTL_SPECULATIVE_SHIFT, tmp2						;\
	or	tmp1, tmp2, tmp1					;\
	stxa	tmp1, [%g0]ASI_MCNTL					;\
	membar #Sync


	.align  8
	ENTRY_NP(drmach_fmem_loop_script)
	/* turn off speculative mode */
	FJSV_SPECULATIVE_OFF(%o5, %o3, %o4);

	/* read the critical region to get everything in the cache */
	mov	%o0, %o3
0:
	ldx	[%o3], %o4
	sub	%o1, 8, %o1
	brnz	%o1, 0b
	 add	%o3, 8, %o3

	/* clear L2_CTRL_UGE_TRAP error bit */
	mov	ASI_L2_CTRL_RW_ADDR, %o1
	ldxa	[%o1]ASI_L2_CTRL, %o3
	sethi	%hi(ASI_L2_CTRL_UGE_TRAP), %o4
	btst	%o3, %o4
	bz,pn	%xcc, 1f
	 nop
	stxa	%o4, [%o1]ASI_L2_CTRL

	/* now tell the master CPU that we are ready */
1:
	set	FMEM_LOOP_FMEM_READY, %o3
	stb	%o3, [%o2]
	membar #Sync
	ba	 5f
	 nop

	/*
	 * note that we branch to 5f, which branches right back to 2 here.
	 * The trick is that when that branch instruction has already been
	 * patched to a branch to itself - an infinite loop.
	 * The master thread will patch it back to "ba 2b" when it
	 * completes.
	 */

	/* Once we are back, we first check if there has been any
	 * L2_CTRL_UGE_TRAP errors, if so we have to fail the
	 * operation.  This will cause a panic because the system
	 * is already in inconsistent state.
	 */
2:
	mov	ASI_L2_CTRL_RW_ADDR, %o3
	ldxa	[%o3]ASI_L2_CTRL, %o3
	sethi	%hi(ASI_L2_CTRL_UGE_TRAP), %o4
	btst	%o3, %o4
	bz,pn	%xcc, 3f
	 mov	%g0, %o4
	set	EOPL_FMEM_HW_ERROR, %o4

	/* set error code and stat code */
3:
	set	FMEM_LOOP_DONE, %o3
	stb	%o3, [%o2]

	/* turn on speculative mode again */
	ldxa	[%g0]ASI_MCNTL, %o0
	set	1, %o1
	sllx	%o1, MCNTL_SPECULATIVE_SHIFT, %o1
	andn	%o0, %o1, %o0
	ba	4f
	 nop
.align 32
4:
	stxa	%o0, [%g0]ASI_MCNTL
	membar	#Sync
	wrpr	%g0, %o5, %pstate
	retl
	 mov	%o4, %o0
.align 8
5:
	ALTENTRY(drmach_fmem_loop_script_rtn)
	/*
	 * busy wait will affect sibling strands so
	 * we put sleep instruction in the delay slot
	 */
	ba	2b
.word	 0x81b01060
	SET_SIZE(drmach_fmem_loop_script)

	.align  8
	ENTRY_NP(drmach_flush_icache)
	stxa	%g0, [%g0]ASI_ALL_FLUSH_L1I
	membar	#Sync
	retl
	 nop
	SET_SIZE(drmach_flush_icache)

.align 32
	ENTRY_NP(drmach_fmem_exec_script)
	/* turn off speculative mode */
	FJSV_SPECULATIVE_OFF(%o5, %o3, %o4);
	/* save locals to save area */
	add	%o0, SAVE_LOCAL, %o2
	stx	%l0, [%o2+8*0]
	stx	%l1, [%o2+8*1]
	stx	%l2, [%o2+8*2]
	stx	%l3, [%o2+8*3]
	stx	%l4, [%o2+8*4]
	stx	%l5, [%o2+8*5]
	stx	%l6, [%o2+8*6]
	stx	%l7, [%o2+8*7]
	mov	%o5, %l6
	/* l7 is set only when FMEM cmd is issued to SCF */
	mov	%g0, %l7

	/* read the critical region to put everything in the cache */
	mov	%o0, %o2
0:
	ldx	[%o2], %o4
	sub	%o1, 8, %o1
	brnz	%o1, 0b
	 add	%o2, 8, %o2
	ba	4f
	 nop

	/* we branch to 4f but eventually we branch back here to finish up */
1:
	mov	%l6, %o5
	/*
	 * save some registers for debugging
	 * l0 - SCF_REG_BASE
	 * l1 - SCF_TD
	 * l2 - SCF_TD + 8
	 * l5 - DELAY
	 */
	add	%o0, SAVE_LOG, %o1
	stx	%l0, [%o1+8*0]
	stx	%l1, [%o1+8*1]
	stx	%l2, [%o1+8*2]
	stx	%l5, [%o1+8*3]

	add	%o0, FMEM_ISSUED, %o1
	st	%l7, [%o1]

	/* Check for L2_CTRL_UGE_TRAP error */
	mov	ASI_L2_CTRL_RW_ADDR, %l0
	ldxa	[%l0]ASI_L2_CTRL, %l1
	sethi	%hi(ASI_L2_CTRL_UGE_TRAP), %l2
	btst	%l1, %l2
	bz,pn	%xcc, 2f
	 nop
	set	EOPL_FMEM_HW_ERROR, %o4
2:
	/* restore all locals */
	add	%o0, SAVE_LOCAL, %o1
	ldx	[%o1+8*0], %l0
	ldx	[%o1+8*1], %l1
	ldx	[%o1+8*2], %l2
	ldx	[%o1+8*3], %l3
	ldx	[%o1+8*4], %l4
	ldx	[%o1+8*5], %l5
	ldx	[%o1+8*6], %l6
	ldx	[%o1+8*7], %l7

	/* turn on speculative mode */
	ldxa	[%g0]ASI_MCNTL, %o1
	set	1, %o2
	sllx	%o2, MCNTL_SPECULATIVE_SHIFT, %o2
	andn	%o1, %o2, %o1
	ba	3f
	 nop
.align 32
3:
	stxa	%o1, [%g0]ASI_MCNTL
	membar	#Sync
	/* return error code here */
	mov	%o4, %o0
	retl
	 wrpr	%g0, %o5, %pstate

	/* clear L2_CTRL_UGE_TRAP error bit */
4:
	mov	ASI_L2_CTRL_RW_ADDR, %l0
	ldxa	[%l0]ASI_L2_CTRL, %l1
	sethi	%hi(ASI_L2_CTRL_UGE_TRAP), %l2
	btst	%l1, %l2
	bz,pn	%xcc, 5f
	 nop
	stxa	%l2, [%l0]ASI_L2_CTRL
5:
	/* set up the register locations and parameters */
	ldx	[%o0 + SCF_REG_BASE], %l0
	ldx	[%o0 + SCF_TD], %l1
	ldx	[%o0 + SCF_TD+8], %l2
	ldx	[%o0 + DELAY], %l5

	/* check if SCF is ONLINE */
	add	%l0, SCF_STATUS_EX, %o1
	lduwa	[%o1]ASI_IO, %o2
	sethi	%hi(SCF_STATUS_EX_ONLINE), %o3
	btst	%o2, %o3
	bne	%xcc, 6f
	 nop
	set	EOPL_FMEM_SCF_OFFLINE, %o4
	ba	1b
	 nop

	/* check if SCF is busy */
	add	%l0, SCF_COMMAND, %o1
	lduha	[%o1]ASI_IO, %o2
	sethi	%hi(SCF_CMD_BUSY), %o3
	btst	%o2, %o3
	be	%xcc, 6f
	 nop
	set	EOPL_FMEM_SCF_BUSY, %o4
	ba	1b
	 nop

	/* clear STATUS bit */
6:
	add	%l0, SCF_STATUS, %o1
	lduha	[%o1]ASI_IO, %o2
	sethi	%hi(SCF_STATUS_READY), %o3
	btst	%o2, %o3
	be	%xcc, 7f
	 nop
	stha	%o3, [%o1]ASI_IO

	/* clear CMD_COMPLETE bit */
7:
	mov	SCF_STATUS_CMD_COMPLETE, %o3
	btst	%o2, %o3
	be,a	%xcc, 8f
	 nop
	stha	%o3, [%o1]ASI_IO
8:
	add	%l0, (SCF_TDATA+0xe), %o1
	mov	%l2, %o4
	mov	SCF_RETRY_CNT, %o5

	sethi	%hi(0xffff), %l2
	or	%l2, %lo(0xffff), %l2

	and	%o4, %l2, %o3

	/*
	 * o1 points to SCFBASE.SCF_TDATA[0xe]
	 * l0 points to SCFBASE
	 * crticial->SCF_TD[0] = source board #
	 * crticial->SCF_TD[1] = target board #
	 * l1 = critical->SCF_TD[0 - 7]
	 * l2 = 0xffff
	 * o4 = critical->SCF_TD[8 - 15]
	 * o3 = (*o4) & 0xffff

	/*
	 * Because there is no parity protection on the ebus
	 * we read the data back after the write to verify
	 * we write 2 bytes at a time.
	 * If the data read is not the same as data written
	 * we retry up to a limit of SCF_RETRY_CNT
	 */
9:
	stha	%o3, [%o1]ASI_IO
	lduha	[%o1]ASI_IO, %o2
	sub	%o5, 1, %o5
	brnz	%o5, 7f
	 nop
	set	EOPL_FMEM_RETRY_OUT, %o4
	ba	1b
	 nop
7:
	cmp	%o2, %o3
	bne,a	9b
	 nop

	sub	%o1, %l0, %o2
	cmp	%o2, (SCF_TDATA+0x8)
	bne	%xcc, 2f
	 srlx	%o4, 16, %o4
	mov	%l1, %o4

	/* if we have reach TDATA+8, we switch to l1 */
	/* XXX: Why we need 2 loops??? */
2:
	sub	%o1, 2, %o1
	mov	SCF_RETRY_CNT, %o5
	and	%o4, %l2, %o3

	sub	%o1, %l0, %o2
	cmp	%o2, (SCF_TDATA)
	bge,a	9b
	 nop

	/* if we reach TDATA, we are done */

	/* read from SCF back to our buffer for debugging */
	add	%l0, (SCF_TDATA), %o1
	ldxa	[%o1]ASI_IO, %o2
	stx	%o2, [%o0+SCF_TD]

	add	%l0, (SCF_TDATA+8), %o1
	ldxa	[%o1]ASI_IO, %o2
	stx	%o2, [%o0+SCF_TD+8]

	/* The following code conforms to the FMEM
	   sequence (4) as described in the Columbus2
	   logical spec section 4.6
	*/

	/* read from SCF SB INFO register */
	sethi	%hi(SCF_SB_INFO_OFFSET), %o2
	or	%o2, %lo(SCF_SB_INFO_OFFSET), %o2
	add	%l0, %o2, %o1
	lduba	[%o1]ASI_IO, %o2

	/* If BUSY bit is set, abort */
	or	%g0, (SCF_SB_INFO_BUSY), %o1
	btst	%o1, %o2
	set	EOPL_FMEM_SCF_BUSY, %o4
	bne	1b
	 nop

	rd	STICK, %l1
	add	%l5, %l1, %l5

	/* Now tell SCF to do it */
	add	%l0, SCF_COMMAND, %o1

	/* 0x10A6 is the magic command */
	sethi	%hi(0x10A6), %o2
	or	%o2, %lo(0x10A6), %o2
	stha	%o2, [%o1]ASI_IO

	mov	1, %l7			! FMEM is issued

	add	%l0, SCF_STATUS, %o1
	sethi	%hi(SCF_STATUS_READY), %o2
	mov	SCF_STATUS_CMD_COMPLETE, %o3

	/* read STATUS_READY bit and clear it only if it is set */
	/* XXX: this STATUS_READY checking seems meaningless */
3:
	lduha	[%o1]ASI_IO, %o4
	btst	%o2, %o4
	be	%xcc, 4f		! STATUS_READY is not set
	 nop
	stha	%o2, [%o1]ASI_IO	! Clear if the bit is set

	/* check CMD_COMPLETE bit and clear */
4:
	btst	%o3, %o4
	be	%xcc, 5f		! CMD_COMPLETE is not set
	 nop
	stha	%o3, [%o1]ASI_IO	! Now we are done and clear it
	ba	%xcc, 6f
	 mov	ESBD_NOERROR, %o4

	/* timeout delay checking */
5:
	rd	STICK, %l2
	cmp	%l5, %l2
	bge	%xcc, 3b
	 nop
	set	EOPL_FMEM_TIMEOUT, %o4

	/* we are done or timed out */
6:
	ba,a	1b
	 nop
	SET_SIZE(drmach_fmem_exec_script)

	ENTRY_NP(drmach_fmem_exec_script_end)
	nop
	SET_SIZE(drmach_fmem_exec_script_end)

	ENTRY_NP(patch_inst)
	ldx	[%o0], %o2
	casx	[%o0], %o2, %o1
	flush	%o0
	membar #Sync
	ldx	[%o0], %o2
	retl
	 mov	%o2, %o0
	SET_SIZE(patch_inst)

	ENTRY_NP(drmach_sys_trap)
	mov	-1, %g4
	set	sys_trap, %g5
	jmp	%g5
	 nop
	SET_SIZE(drmach_sys_trap)

	ENTRY_NP(drmach_get_stick)
	retl
	rd	STICK, %o0
	SET_SIZE(drmach_get_stick)

	ENTRY_NP(drmach_flush)
	mov	%o0, %o2
0:
	flush	%o2
	sub	%o1, 8, %o1
	brnz	%o1, 0b
	 add	%o2, 8, %o2
	retl
	 nop
	SET_SIZE(drmach_flush)
