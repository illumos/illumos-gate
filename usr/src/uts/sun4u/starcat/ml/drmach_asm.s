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
 * only by DR.
 */

#if defined(lint)
#include <sys/types.h>
#else
#include "assym.h"
#endif /* lint */

#include <sys/asm_linkage.h>
#include <sys/clock.h>
#include <sys/param.h>
#include <sys/privregs.h>
#include <sys/machasi.h>
#include <sys/mmu.h>
#include <sys/machthread.h>
#include <sys/pte.h>
#include <sys/stack.h>
#include <sys/vis.h>
#include <sys/cheetahregs.h>
#include <sys/cmpregs.h>
#include <sys/intreg.h>
#include <sys/cheetahasm.h>

#if defined(lint)

/*ARGSUSED*/
void
drmach_shutdown_asm(uint64_t estack, uint64_t flushaddr,
    int size, int lsz, uint64_t physmem)
{}

/*ARGSUSED*/
void
drmach_rename(uint64_t *script, uint_t *err, uint64_t *id)
{}

void
drmach_rename_end(void)
{}

/*ARGSUSED*/
void
drmach_rename_wait(uint64_t not_used_0, uint64_t not_used_1)
{
}

/*ARGSUSED*/
void
drmach_rename_done(uint64_t not_used_0, uint64_t not_used_1)
{
}

/*ARGSUSED*/
void
drmach_rename_abort(uint64_t not_used_0, uint64_t not_used_1)
{
}

/*ARGSUSED*/
uint64_t
lddsafconfig(void)
{
	return (0x0ull);
}

/* ARGSUSED */
uint32_t
drmach_bc_bzero(void *addr, size_t size)
{
	return (0x0);
}

#else /* lint */

#define BUS_SYNC(reg1, reg2)					\
1:								;\
	ldx	[reg1], reg2					;\
	brz,pn	reg2, 2f					;\
	add	reg1, 8, reg1					;\
	ldxa	[reg2]ASI_MEM, %g0				;\
	ba,a	1b						;\
	nop							;\
2:

#define LOAD_MB(cpuid, mb_data, reg1)				\
	set	drmach_xt_mb, reg1				;\
	ldx	[reg1], reg1					;\
	add	reg1, cpuid, reg1				;\
	ldub	[reg1], mb_data					;\
	stub	%g0, [reg1]

#define LPA_MASK 0x7ff8

#define SET_LPA(cmd, reg1, reg2)				\
	btst	0x80, cmd					;\
	bz	2f						;\
	nop							;\
	btst	0x40, cmd					;\
	bnz,a	1f						;\
	mov	%g0, cmd					;\
	and	cmd, 0x1f, cmd					;\
	sllx	cmd, 3, reg1					;\
	add	cmd, 1, cmd					;\
	sllx	cmd, 9, cmd					;\
	or	cmd, reg1, cmd					;\
1:								;\
	set	LPA_MASK, reg2					;\
	ldxa	[%g0]ASI_SAFARI_CONFIG, reg1			;\
	and	cmd, reg2, cmd					;\
	andn	reg1, reg2, reg1				;\
	or	reg1, cmd, reg1					;\
	stxa	reg1, [%g0]ASI_SAFARI_CONFIG			;\
	membar	#Sync						;\
2:								;\

#define SET_NULL_LPA(reg1, reg2)				\
	set	LPA_MASK, reg2					;\
	ldxa	[%g0]ASI_SAFARI_CONFIG, reg1			;\
	andn	reg1, reg2, reg1				;\
	stxa	reg1, [%g0]ASI_SAFARI_CONFIG			;\
	membar	#Sync						;\

	! ATOMIC_ADD_LONG
	! This code is run at TL > 0, being exec'd via a cross trap.
	! While running at trap level > 0, all memory accesses are
	! performed using NUCLEUS context, which is always 0.
	! Since the cross trap handler does not force PRIMARY context
	! to be zero, the following casxa instruction must specify
	! NUCLEUS ASI.
	! This ASI must be specified explicitly (via casxa), rather
	! than using casx. This is because of the fact that the
	! default casx specifies ASI_PRIMARY, which if non-zero, can
	! prevent the cpu from translating the address, leading to panic
	! on bad trap following repetitive dtlb misses.  This behavior
	! was encountered on MCPUs when using casx instruction.
#define ATOMIC_ADD_LONG(label, simm, reg1, reg2, reg3)		\
	set	label, reg1					;\
	ldx	[reg1], reg2					;\
1:								;\
	add	reg2, simm, reg3				;\
	casxa	[reg1]ASI_N, reg2, reg3				;\
	cmp	reg2, reg3					;\
	bne,a,pn %xcc, 1b					;\
	ldx	[reg1], reg2

#define HERE(reg1, simm, reg2)					\
	rdpr	%tick, reg2					;\
	stx	reg2, [reg1 + simm]

	!
	! Returns processor icache size and linesize in reg1 and
	! reg2, respectively.
	!
	! Panther has a larger icache compared to Cheetahplus and
	! Jaguar.
	!
#define	GET_ICACHE_PARAMS(reg1, reg2)				\
	GET_CPU_IMPL(reg1)					;\
	cmp	reg1, PANTHER_IMPL				;\
	bne	%xcc, 1f					;\
	  nop							;\
	set	PN_ICACHE_SIZE, reg1				;\
	set	PN_ICACHE_LSIZE, reg2				;\
	ba	2f						;\
	  nop							;\
1:								;\
	set	CH_ICACHE_SIZE, reg1				;\
	set	CH_ICACHE_LSIZE, reg2				;\
2:

#define	DRMACH_MCU_IDLE_READS	3

	! Macro to check if a Panther MC is idle.  The EMU Activity
	! Status register is first read to clear the MCU status bit.
	! The MCU status is then checked DRMACH_MCU_IDLE_READS times
	! to verify the MCU is indeed idle.  A single non-idle status
	! will fail the idle check.  This could be made more lenient
	! by adding a retry loop.
	!	addr:	Panther EMU Activity Status register read address.
	!		Assumed to be 0x18 for local ASI access or else
	!		FIREPLANE_ADDRESS_REG + 0x400050 for PIO access.
	!		0 is returned in this register if MCU is idle and
	!		queues are empty.  Otherwise, -1 is returned in this
	!		register.
	!	asi:	Immediate asi value.  Assumed to be ASI_SAFARI_CONFIG
	!		for local ASI or ASI_IO for PIO access.
	!	scr1:	Scratch 
	!	scr2:	Scratch 
	!
#define	CHECK_MCU_IDLE(addr, asi, scr1, scr2)			\
	ldxa	[addr]asi, %g0					;\
	ba	1f						;\
	  clr	scr2						;\
0:								;\
	btst	MCU_ACT_STATUS, scr1				;\
	bne,a	2f						;\
	  sub	%g0, 1, addr					;\
	inc	scr2						;\
1:								;\
	cmp	scr2, DRMACH_MCU_IDLE_READS			;\
	ble,a	0b						;\
	  ldxa    [addr]asi, scr1				;\
	clr	addr						;\
2:

	! drmach_shutdown_asm
	!
	! inputs:
	!	%o0 = stack pointer
	!	%o1 = ecache flush address (ignored if cheetah+ processor)
	!	%o2 = ecache size
	!	%o3 = ecache line size
	!	%o4 = phys addr of byte to clear when finished
	!
	! output:
	!	Stores a zero at [%o4]ASI_MEM when the processor
	!	is ready to be removed from domain coherency.
	!
	ENTRY_NP(drmach_shutdown_asm)
	membar	#LoadStore		! parsley.

	! Calculate pointer to data area. Determine size of
	! drmach_shutdown_asm, add to base address and align
	! to next 16 byte boundary. Leave result in %g6.
	set	drmach_shutdown_asm_end, %g6
	set	drmach_shutdown_asm, %g1
	set	drmach_cpu_sram_va, %g2
	ldx	[%g2], %g2
	sub	%g6, %g1, %g6
	add	%g6, %g2, %g6
	add	%g6, 15, %g6
	andn	%g6, 15, %g6
	
	! Save parameters
	stx	%o0, [%g6 + 0]		! save stack pointer
	stx	%o1, [%g6 + 24]		! save E$ flush PA
	st	%o2, [%g6 + 32]		! save E$ size
	st	%o3, [%g6 + 36]		! save E$ linesize
	stx	%o4, [%g6 + 40]		! save phys addr of signal byte

	set	dcache_size, %g1
	ld	[%g1], %g1
	st	%g1, [%g6 + 8]		! save dcache_size
	set	dcache_linesize, %g1
	ld	[%g1], %g1
	st	%g1, [%g6 + 12]		! save dcache_linesize

	GET_ICACHE_PARAMS(%g1, %g2)
	st	%g1, [%g6 + 16]		! save icache_size
	st	%g2, [%g6 + 20]		! save icache_linesize

	! Flushes all active windows except the current one.
	! Can cause spill traps to occur.
	flushw

	! Make sure all asynchronous processing is complete.
	! Note: has no implications on pending bus transactions.
	membar	#Sync

	! Move stack. Algorithm copied from t0stacktop setup of
	! %sp in sun4u/ml/locore.s
	! Replaces SWITCH_STACK() macro used in Starfire DR.
	ldx	[%g6 + 0], %g1
	sub	%g1, SA(KFPUSIZE+GSR_SIZE), %g2
 	and	%g2, 0x3f, %g3
 	sub	%g2, %g3, %o2
 	sub	%o2, SA(MPCBSIZE) + STACK_BIAS, %sp
	stx	%sp, [%g6 + 48]		! for debug

	HERE(%g6, 128, %g1)		! initialization complete (for debug)

	! Panther needs to flush the L2 cache before the L3
	! cache is flushed by the ecache flushall macro.
	PN_L2_FLUSHALL(%g1, %g2, %g3)
	
	! Flush E$. The purpose of this flush is to rid the E$ of
	! lines in states O or Os. Implicitly flushes W$.
	ldx	[%g6 + 24], %g1		! *ecache_flushaddr
	ld	[%g6 + 32], %g2		! ecache_size
	ld	[%g6 + 36], %g3		! ecache_linesize
	ECACHE_FLUSHALL(%g2, %g3, %g1, %g4)

	! Since the bus sync list read below does not guarantee
	! transaction completion on Panther domains, as an
	! optimization Panther skips the read and subsequent
	! E$ flush.
	GET_CPU_IMPL(%g1)
	cmp	%g1, PANTHER_IMPL
	be	%xcc, drmach_shutdown_ecache_flushed
	  nop

	!
	! Ensure all outstanding writebacks have retired.  Following this
	! sync, all writes must be strictly managed.
	! 
	set	drmach_bus_sync_list, %g1
	BUS_SYNC(%g1, %g2)

	! Flush E$ again to victimize references to drmach_bus_sync_list.
	ldx     [%g6 + 24], %g1         ! *ecache_flushaddr
	ld	[%g6 + 32], %g2		! ecache_size
	ld	[%g6 + 36], %g3		! ecache_linesize
	ECACHE_FLUSHALL(%g2, %g3, %g1, %g4)

drmach_shutdown_ecache_flushed:

	ld	[%g6 + 8], %g1		! flush dcache
	ld	[%g6 + 12], %g2
	CH_DCACHE_FLUSHALL(%g1, %g2, %g3)

	ld	[%g6 + 16], %g1		! flush icache
	ld	[%g6 + 20], %g2
	CH_ICACHE_FLUSHALL(%g1, %g2, %g3, %g4)

	PCACHE_FLUSHALL(%g1, %g2, %g3) ! flush pcache (no parameters)

	!
	! Flush all unlocked dtlb and itlb entries.
	! Replaces TLB_FLUSH_UNLOCKED macro used in Starfire DR.
	!
	sethi	%hi(FLUSH_ADDR), %g1
	set	DEMAP_ALL_TYPE, %g2
	stxa	%g0, [%g2]ASI_DTLB_DEMAP
	stxa	%g0, [%g2]ASI_ITLB_DEMAP
	flush	%g1

	!
	! Zero LPA by clearing CBASE and CBND. Following
	! this, all transactions to cachable address space
	! will be of the remote flavor.
	!
	SET_NULL_LPA(%g1, %g2)

	HERE(%g6, 136, %g1)		! preparation complete (for debug)

	!
	! Clear byte to signal finished.
	! NOTE: This store will allocate in the E$. It is
	! vitally important that this line is demoted to
	! state I before removing this processor from the
	! coherency.  The demotion is ensured by a synchronous
	! "steal back" that takes place in drmach_cpu_poweroff.
	ldx	[%g6 + 40], %g1
	stba	%g0, [%g1]ASI_MEM
5:
	HERE(%g6, 144, %g1)		! spin indicator (for debug)
	ba	5b
	  nop

	.asciz	"drmach_shutdown_asm"		! for debug
	.align	4
	.global	drmach_shutdown_asm_end
drmach_shutdown_asm_end:
	SET_SIZE(drmach_shutdown_asm)


	! lddsafconfig
	!
	! input:
	!	nothing
	!
	! output:
	!	%o0	content of this processor's SCR
	!
	!	Returns current value of this processor's Safari
	!	Configuration Register.
	!
	ENTRY(lddsafconfig)
        retl
        ldxa    [%g0]ASI_SAFARI_CONFIG, %o0
        SET_SIZE(lddsafconfig)

	! drmach_rename
	!
	! input:
	!	%o0	pointer to register address/value compound list
	!	%o1	address for setting error code if rename did not
	!		complete.  Unmodified if no error.
	!	%o2	address for returning opaque memory controller id
	!		in case of error.  Unmodified if no error.
	!	Global	drmach_xt_mb[cpuid] is expected to be the new LPA.
	!
	! output:
	!	[%o1] =	1 if failed to idle memory controller, otherwise unmodified.
	!	[%o2] = id of failed memory controller, otherwise unmodified.
	!
	! Perform HW register reprogramming. This is the "rename" step for
	! the copy-rename process.  drmach_rename is copied to a cpu's sram
	! followed by register address/value pairs -- the text and data are
	! sourced from the sram while drmach_rename is executed.
	!
	! The parameter is assumed to point to a concatenation of six
	! zero-terminated lists located in non-cachable storage. The assumed
	! format (and purpose) of each list is as follows:
	!
	!	1) a copy of drmach_bus_sync_list. A list of PA for each
	!	   active memory bank in the domain. Used to infer the
	!	   the completion of all pending coherent transactions
	!	   initiated by this processor. Assumes MC work queue
	!	   does not implement read bypass. This is true of Cheetah,
	!	   Cheetah+, and Jaguar processors.  Panther does support
	!	   read bypass, so for Panther MCs with read-bypass-write
	!	   enabled, the read is issued but it does not guarantee
	!	   completion of outstanding writes in the MC queue.  
	!	2) address/id pair for the local Panther EMU Activity Status
	!	   Register of this processor.  The register address is assumed
	!	   to be a VA which is polled via ASI_SAFARI_CONFIG until the
	!	   MC queues are empty.  The id is an opaque identifier which
	!	   must be returned along with an error code if the MCU status
	!	   does not go idle.  See the parameter description above.
	!	   This section will be empty if this processor is not a Panther.
	!	   Both the address and id are assumed to be 64 bit values.
	!	3) address/id pairs for non-local Panther EMU Activity Status
	!	   Registers on other source and target processors.  The register
	!	   address is assumed to be a PIO address which is polled via
	!	   ASI_IO to drain/idle the MCs on other Panther procs.  The
	!	   id is an opaque identifier which must be returned along with
	!	   an error code if a MC fails to go idle.  This section will
	!	   empty if there are no non-local Panther processors on the
	!	   source and target expanders.  Both the address and id are
	!	   assumed to be 64 bit values.
	!	4) address/value pairs for the Memory Address Decoder
	!	   register of this processor. The register address is
	!	   assumed to be a VA within ASM_MC_DECODE space. The
	!	   address and value elements are assumed to 64 bit values.
	!	5) address/value pairs for any 64 bit register accessible
	!	   via ASI_IO. The address and value fields are assumed to
	!	   be 64 bit values.
	!	   This list is typically used for reprogramming the Memory
	!	   Address Decoder Register of other cpus and for reprogram-
	!	   ming the Safari Configuration Register of I/O controllers.
	!	6) address/value pairs for any 32 bit register accessible
	!	   via ASI_IO. The address element is assumed to be a 64 bit
	!	   value. The value element is assumed to be a 64 bit word
	!	   containing a 32 bit value in the lower half.
	!	   This list typically contains address/value pairs for
	!	   AXQ CASM tables.
	!
	ENTRY_NP(drmach_rename)

	mov	%o1, %o4		! save error code address
	mov	%o2, %o5		! save error id address

	BUS_SYNC(%o0, %o1)		! run section 1

	SET_NULL_LPA(%o1, %o2)		! prep for cachable transactions
					! after rename completes.
					! e.g.: the load_mb that occurs below
3:
	ldx	[%o0], %o1		! run section 2
	brz,a,pn %o1, 4f
	add	%o0, 8, %o0		! skip section 2 terminator
	CHECK_MCU_IDLE(%o1, ASI_SAFARI_CONFIG, %o2, %o3)
	cmp	%o1, 0			! idled?
	be,a	3b			! ok, advance
	  add	%o0, 16, %o0
	mov	1, %o1			! not idle, bailout
	stw	%o1, [%o4]		! set MC idle error code
	ldx	[%o0 + 8], %o1
	stx	%o1, [%o5]		! set MC idle error id
	retl
	  nop
4:
	ldx	[%o0], %o1		! run section 3
	brz,a,pn %o1, 5f
	add	%o0, 8, %o0		! skip section 3 terminator
	CHECK_MCU_IDLE(%o1, ASI_IO, %o2, %o3)
	cmp	%o1, 0			! idled?
	be,a	4b			! ok, advance
	  add	%o0, 16, %o0
	mov	1, %o1			! not idle, bailout
	stw	%o1, [%o4]		! set MC idle error code
	ldx	[%o0 + 8], %o1
	stx	%o1, [%o5]		! set MC idle error id
	retl
	  nop
5:
	ldx	[%o0], %o1		! run section 4
	brz,a,pn %o1, 6f
	add	%o0, 8, %o0		! skip section 4 terminator
	ldx	[%o0 + 8], %o2
	stxa	%o2, [%o1]ASI_MC_DECODE
	membar	#Sync
	ldxa	[%o1]ASI_MC_DECODE, %g0	! read back to insure written
	b	5b
	add	%o0, 16, %o0
6:
	ldx	[%o0], %o1		! run section 5
	brz,a,pn %o1, 7f
	add	%o0, 8, %o0		! skip section 5 terminator
	ldx	[%o0 + 8], %o2
	stxa	%o2, [%o1]ASI_IO
	ldxa	[%o1]ASI_IO, %g0	! read back to insure written
	b	6b
	add	%o0, 16, %o0
7:
	ldx	[%o0], %o1		! run section 6
	brz,a,pn %o1, 8f
	nop
	ldx	[%o0 + 8], %o2
	stwa	%o2, [%o1]ASI_IO
	lduwa	[%o1]ASI_IO, %g0	! read back to insure written
	b	7b
	add	%o0, 16, %o0
8:
	CPU_INDEX(%o0, %o1)
	LOAD_MB(%o0, %o1, %o2)
	SET_LPA(%o1, %o0, %o2)

	retl
	nop

	.asciz	"drmach_rename"		! for debug
	.align	4
	SET_SIZE(drmach_rename)

	.global drmach_rename_end
drmach_rename_end:


	! drmach_rename_wait
	!
	! input:
	!	nothing
	!
	! output:
	!	nothing
	!
	! drmach_rename_wait is a cross-trap function used to move a
	! cpu's execution out of coherent space while a copy-rename
	! operation is in progress.
	!
	! In each CPU SRAM exists an area (16KB on Cheetah+ boards,
	! 32KB on Jaguar/Panther boards) reserved for DR. This area is
	! logically divided by DR into 8KB pages, one page per CPU (or
	! core) in a port pair. (Two Safari ports share HW resources on
	! a CPU/MEM board. These are referred to as a port pair.) 
	!
	! This routine begins by mapping the appropriate SRAM page,
	! transferring the machine code (between the labels
	! drmach_rename_wait_asm and drmach_rename_wait_asm_end), then
	! jumping to SRAM.  After returning from SRAM, the page is
	! demapped before the cross-call is exited (sic).
	!
	! The machine code flushes all caches, waits for a special
	! interrupt vector, then updates the processor's LPA and
	! resynchronizes caches with the new home memory.
	!
	! The special interrupt vector is assumed to be a cross-call to
	! drmach_rename_done sent by the master processor upon completing
	! the copy-rename operation. The interrupt is received and discarded;
	! The cross-call to drmach_rename_done is never executed.  Instead
	! the Interrupt Receive Status Register is employed, temporarily,
	! as a semaphore. This avoids unwanted bus traffic during the critical
	! rename operation.
	!
	ENTRY_NP(drmach_rename_wait)

	CPU_INDEX(%g5, %g1)		! put cpuid in %g5

	!
	! sfmmu_dtlb_ld(drmach_cpu_sram_va,
	!	KCONTEXT, drmach_cpu_sram_tte[cpuid]);
	! sfmmu_itlb_ld(drmach_cpu_sram_va,
	!	KCONTEXT, drmach_cpu_sram_tte[cpuid]);
	!
	set	drmach_cpu_sram_tte, %g1
	sllx	%g5, 3, %g2
	ldx	[%g1 + %g2], %g3
	set	drmach_cpu_sram_va, %g1
	ldx	[%g1], %g1
	or	%g1, KCONTEXT, %g2	! preserve %g1
	set	MMU_TAG_ACCESS, %g4
	set	cpu_impl_dual_pgsz, %g6 
	ld      [%g6], %g6 
	brz	%g6, 1f
	  nop
	
	sethi	%hi(ksfmmup), %g6
	ldx	[%g6 + %lo(ksfmmup)], %g6
	ldub    [%g6 + SFMMU_CEXT], %g6
        sll     %g6, TAGACCEXT_SHIFT, %g6

	set	MMU_TAG_ACCESS_EXT, %g7
	stxa	%g6, [%g7]ASI_DMMU
1:
	stxa	%g2, [%g4]ASI_DMMU
	stxa    %g3, [%g0]ASI_DTLB_IN
	membar	#Sync
	sethi	%hi(FLUSH_ADDR), %g6
	stxa	%g2, [%g4]ASI_IMMU
	stxa    %g3, [%g0]ASI_ITLB_IN
	flush	%g6

	!
	! copy drmach_rename_wait_asm block to SRAM. Preserve entry
	! point in %g1. After the code has been copied, align %g6
	! (the destination pointer) to the next highest 16 byte
	! boundary. This will define the start of the data area.
	!
	mov	%g1, %g6
	set	drmach_rename_wait_asm, %g2
	set	drmach_rename_wait_asm_end, %g3
0:
	lduw	[%g2], %g4		! do copy
	stw	%g4, [%g6]
	add	%g2, 4, %g2
	cmp	%g2, %g3
	bne	0b
	add	%g6, 4, %g6
	
	add	%g6, 15, %g6		! locate data area on next 16 byte
	andn	%g6, 15, %g6		! boundary following text
					! WARNING: no bounds checking

	jmpl	%g1, %g7		! jump to code in cpu sram
	nop

	set	drmach_cpu_sram_va, %g1	! vtab_flushpage_tl1(drmach_cpu_sram_va,
	ldx	[%g1], %g1		! 	KCONTEXT);
	set	KCONTEXT, %g2
	set	MMU_PCONTEXT, %g4
	or	%g1, DEMAP_PRIMARY | DEMAP_PAGE_TYPE, %g1
	ldxa	[%g4]ASI_DMMU, %g5	/* rd old ctxnum */
	stxa	%g2, [%g4]ASI_DMMU	/* wr new ctxum */
	stxa	%g0, [%g1]ASI_DTLB_DEMAP
	stxa	%g0, [%g1]ASI_ITLB_DEMAP
	stxa	%g5, [%g4]ASI_DMMU	/* restore old ctxnum */

	retry

drmach_rename_wait_asm:
	! the following code is copied to a cpu's sram and executed
	! from there.
	! Input:
	!	%g5 is cpuid
	!	%g6 is data area (follows text)
	!	%g7 is link address back to caller
	!
	st	%g5, [%g6 + 4]		! save cpuid (for debug)

	set	dcache_size, %g1
	ld	[%g1], %g1
	st	%g1, [%g6 + 8]		! save dcache_size
	set	dcache_linesize, %g1
	ld	[%g1], %g1
	st	%g1, [%g6 + 12]		! save dcache_linesize

	GET_ICACHE_PARAMS(%g1, %g2)
	st	%g1, [%g6 + 16]		! save icache_size
	st	%g2, [%g6 + 20]		! save icache_linesize

	set	drmach_iocage_paddr, %g1
	ldx	[%g1], %g1
	stx	%g1, [%g6 + 24]		! save *ecache_flushadr

	mulx	%g5, CPU_NODE_SIZE, %g1	! %g4 = &cpunodes[cpuid]
	set	cpunodes, %g4
	add	%g4, %g1, %g4
	ld	[%g4 + ECACHE_SIZE], %g1
	st	%g1, [%g6 + 32]		! save ecache_size
	ld	[%g4 + ECACHE_LINESIZE], %g1
	st	%g1, [%g6 + 36]		! save ecache_linesize

	LOAD_MB(%g5, %g1, %g2)		! save mailbox data
	stb	%g1, [%g6 + 40]

	membar	#Sync			! Complete any pending processing.

	! Flush E$. The purpose of this flush is to rid the E$ of
	! lines in states O or Os. Implicitly flushes W$.
	! NOTE: Reading the bus sync list and r/w ops on drmach_xt_ready
	! will disturb the E$. The lines of the bus sync list will be
	! in state S. The line containing drmach_xt_ready will be in
	! state O. Before proceeding with the copy-rename, the master
	! processor will "steal back" the drmach_xt_ready (sic) line.
	! This will demote the state of the line in E$ to I.
	! However, the lines containing the bus sync list must be
	! victimized before returning to the OS. This is vital because
	! following copy-rename the corresponding lines in the new home
	! memory will be in state gM. The resulting S,gM state pair is
	! invalid and does represent a loss of coherency. Flushing the
	! E$ after the bus sync list is read will be sufficient to
	! avoid the invalid condition.
	!
	! For Panther, there is redundancy as both cores flush the shared
	! L2 and L3 caches.  As an optimization, only one core could do the
	! flush of the shared caches, however care must be taken that the
	! sibling core does not install owned lines once the flush begins.
	PN_L2_FLUSHALL(%g1, %g2, %g3)
	ldx	[%g6 + 24], %g1		! *ecache_flushaddr
	ld	[%g6 + 32], %g2		! ecache_size
	ld	[%g6 + 36], %g3		! ecache_linesize
	ECACHE_FLUSHALL(%g2, %g3, %g1, %g4)

	! Make sure all outstanding transactions for this processor
	! have retired. See E$ note above.
	set	drmach_bus_sync_list, %g1
	BUS_SYNC(%g1, %g2)

	HERE(%g6, 128, %g4)		! preparation complete (for debug)

	! Signal this processor is ready for rename operation to begin.
	! See E$ note above.
	ATOMIC_ADD_LONG(drmach_xt_ready, 1, %g2, %g3, %g4)

	! Loop on IRSR waiting for interrupt. The expected interrupt
	! is a cross-trap to drmach_wait_done. It is sent by the master
	! processor when the copy-rename operation is complete. The
	! received cross-trap is used only as a signal. It is not executed.
2:
	HERE(%g6, 136, %g4)		! last poll tick (for debug)

	ldxa	[%g0]ASI_INTR_RECEIVE_STATUS, %g4	! wait for xt
	btst	IRSR_BUSY, %g4
	bz	2b
	nop
	stx	%g4, [%g6 + 64]		! save status and payload
	set	IRDR_0, %g2
	ldxa	[%g2]ASI_INTR_RECEIVE, %g2
	stx	%g2, [%g6 + 72]
	set	IRDR_1, %g2
	ldxa	[%g2]ASI_INTR_RECEIVE, %g2
	stx	%g2, [%g6 + 80]
	set	IRDR_2, %g2
	ldxa	[%g2]ASI_INTR_RECEIVE, %g2
	stx	%g2, [%g6 + 88]

					! clear rcv status
	stxa	%g0, [%g0]ASI_INTR_RECEIVE_STATUS
	membar	#Sync

	HERE(%g6, 144, %g4)		! signal rcvd tick (for debug)

	! Check for copy-rename abort signal. If this signal is received,
	! the LPA change is skipped since the rename step was not done.
	! The cache flushes are still done as paranoia.
	set	drmach_rename_abort, %g1
	ldx	[%g6 + 72], %g2
	cmp 	%g1, %g2
	be	3f
	nop

	! Resume waiting if this is not drmach_rename_done.
	set	drmach_rename_done, %g1
	cmp 	%g1, %g2
	bne	2b
	nop

	ldub	[%g6 + 40], %g1		! get saved mailbox data
	SET_LPA(%g1, %g2, %g3)		! set LPA as indicated by the mb data

3:
	! Flush all caches (E, D, I and P) to ensure each is resynchronized
	! with the corresponding states in the new home memory. (W$ is
	! implicitly flushed when the E$ is flushed.)
	!
	! Panther needs to flush the L2 cache before the L3
	! cache is flushed by the ecache flushall macro.
	PN_L2_FLUSHALL(%g1, %g2, %g3)

	ldx	[%g6 + 24], %g1		! *ecache_flushaddr
	ld	[%g6 + 32], %g2		! ecache_size
	ld	[%g6 + 36], %g3		! ecache_linesize
	ECACHE_FLUSHALL(%g2, %g3, %g1, %g4)

	ld	[%g6 + 8], %g1		! flush dcache
	ld	[%g6 + 12], %g2
	CH_DCACHE_FLUSHALL(%g1, %g2, %g3)

	ld	[%g6 + 16], %g1		! flush icache
	ld	[%g6 + 20], %g2
	CH_ICACHE_FLUSHALL(%g1, %g2, %g3, %g4)

	PCACHE_FLUSHALL(%g1, %g2, %g3)	! flush pcache (no parameters)

	HERE(%g6, 152, %g4)		! done tick (for debug)

	jmpl	%g7+8, %g0
	nop

	.asciz	"drmach_rename_wait"	! for debug
	.align	4
drmach_rename_wait_asm_end:
	SET_SIZE(drmach_rename_wait)


	! drmach_rename_done
	!
	! input:
	!	nothing
	!
	! output:
	!	nothing
	!
	! Used as signal data. See drmach_rename_wait.
	!
	ENTRY_NP(drmach_rename_done)
	retry
	SET_SIZE(drmach_rename_done)

	! drmach_rename_abort
	!
	! input:
	!	nothing
	!
	! output:
	!	nothing
	!
	! Used as signal data. See drmach_rename_wait.
	!
	ENTRY_NP(drmach_rename_abort)
	retry
	SET_SIZE(drmach_rename_abort)


	! drmach_set_lpa
	!
	! input:
	!	Globals: drmach_xt_mb[cpuid] contains new LPA data
	!
	! output:
	!	nothing
	!
	! Sets the executing processor's LPA as indicated by the command
	! stored in drmach_xt_mb, a byte array indexed by cpuid. Assumes
	! the caller is preventing illegal LPA settings and transistions.
	!
	ENTRY_NP(drmach_set_lpa)

	!
	! Set %g1 to this processor's cpuid.
	!
	CPU_INDEX(%g1, %g2)

	!
	! Get LPA message from mailbox, leave in %g5.
	!
	LOAD_MB(%g1, %g5, %g2)

	!
	! Set LPA, mailbox data in %g5.
	!
	SET_LPA(%g5, %g1, %g2)

	!
	! Signal work is done.
	!
	ATOMIC_ADD_LONG(drmach_xt_ready, 1, %g1, %g2, %g3)

	retry
	SET_SIZE(drmach_set_lpa)

!
! drmach_bc_bzero
!
! inputs:
! 	%o0 = base vaddr of area to clear (must be 64-byte aligned)
!	%o1 = size of area to clear (must be multiple of 256 bytes)
!
! outputs:
!	%o0 =
!		0 (success)
!		1 (size too small or not modulo 256)
!		2 (vaddr not 64-byte aligned)
!
! Zero a block of storage using block commit stores.
! Nonzero return if caller's address or size are not
! block aligned.
!


	ENTRY(drmach_bc_bzero)

	! verify size is >= 256 bytes
	cmp	%o1, 256
	blu,a	.bz_done
	mov	1, %o0			! error code 1 for invalid size

	! verify size is a multiple of 256
	btst	(256-1), %o1
	bnz,a	.bz_done
	mov	1, %o0			! error code 1 for invalid size

	! verify that vaddr is aligned for block stores
	btst	(64-1), %o0
	bnz,a	.bz_done
	mov	2, %o0			! error code 2 for invalid alignment

	! save fprs for restore when finished
	rd	%fprs, %g1

	! make sure FPU is enabled
	rdpr	%pstate, %g3
	btst	PSTATE_PEF, %g3
	bnz	.bz_block
	nop
	andn	%g3, PSTATE_PEF, %g4
	wrpr	%g4, PSTATE_PEF, %pstate
	
.bz_block:
	membar	#StoreStore|#StoreLoad|#LoadStore
	wr	%g0, FPRS_FEF, %fprs

	! Clear block
	fzero	%d0
	fzero	%d2
	fzero	%d4
	fzero	%d6
	fzero	%d8
	fzero	%d10
	fzero	%d12
	fzero	%d14
	wr	%g0, ASI_BLK_COMMIT_P, %asi
	mov	256, %o3
	ba	.bz_doblock
	nop

.bz_blkstart:	
      ! stda	%d0, [%o0+192]%asi  ! in dly slot of branch that got us here
	stda	%d0, [%o0+128]%asi
	stda	%d0, [%o0+64]%asi
	stda	%d0, [%o0]%asi
	add	%o0, %o3, %o0
	sub	%o1, %o3, %o1
.bz_doblock:
	cmp	%o1, 256
	bgeu,a	%ncc, .bz_blkstart
	stda	%d0, [%o0+192]%asi

.bz_finish:
	membar	#StoreLoad|#StoreStore
	clr	%o0
	wr	%g1, %fprs		! restore fprs
	btst	PSTATE_PEF, %g3		! restore pstate if necessary
	bnz	.bz_done
	nop
	wrpr	%g3, %g0, %pstate
.bz_done:
	membar	#Sync
	retl
	nop

	SET_SIZE(drmach_bc_bzero)

#endif /* lint */
