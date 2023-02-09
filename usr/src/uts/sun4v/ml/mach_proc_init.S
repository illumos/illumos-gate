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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * sun4v processor initialization
 *
 * This is the kernel entry point for CPUs that enter Solaris
 * directly from the hypervisor. i.e. without going through OBP.
 */

#include "assym.h"

#include <sys/asm_linkage.h>
#include <sys/hypervisor_api.h>
#include <sys/machasi.h>
#include <sys/machpcb.h>
#include <sys/machlock.h>
#include <sys/mmu.h>
#include <sys/lpad.h>

	/*
	 * %o0 - hcall specified arg (cpuid)
	 * %i0 - real memory base
	 * %i1 - memory size
	 */
	ENTRY_NP(mach_cpu_startup)
	/*
	 * Calculate the data pointer. The landing pad
	 * data immediately follows the landing pad text.
	 */
	rd	%pc, %l0
	add	%l0, LPAD_TEXT_SIZE, %l1	! %l1 has start of data

	/*
	 * Setup the initial state of the CPU.
	 */
	wrpr	%g0, 0, %tl
	wrpr	%g0, 0, %gl
	wrpr	%g0, MAXWIN - 2, %cansave
	wrpr	%g0, MAXWIN - 2, %cleanwin
	wrpr	%g0, 0, %canrestore
	wrpr	%g0, 0, %otherwin
	wrpr	%g0, 0, %cwp
	wrpr	%g0, 0, %wstate
	wr	%g0, %y
	wrpr	%g0, PIL_MAX, %pil

	set	trap_table, %g1
	wrpr	%g1, %tba

	! initialize cpuid into scratchpad register
	mov	SCRATCHPAD_CPUID, %g1
	stxa	%o0, [%g1]ASI_SCRATCHPAD
	
	! sanity check the data section
	setx	LPAD_MAGIC_VAL, %g2, %g1
	ldx	[%l1 + LPAD_MAGIC], %g2
	cmp	%g1, %g2
	bne	startup_error
	  nop

	/*
	 * Loop through the array of TTE's, installing the
	 * VA to RA mapping for each one.
	 */
	ldx	[%l1 + LPAD_NMAP], %l2		! %l2 = number of mappings
	add	%l1, LPAD_MAP, %l3		! %l3 = the current mapping

	/*
	 * Sanity check the number of mappings.
	 */
	mulx	%l2, LPAD_MAP_SIZE, %g1
	add	%l3, %g1, %g1			! %g1 = end of the array
	add	%l1, LPAD_DATA_SIZE, %g2	! %g2 = end of data section
	sub	%g2, %g1, %g2
	brlz	%g2, startup_error
	  nop

0:
	cmp	%l2, %g0
	be	3f
	  nop

	ldx	[%l3 + LPAD_MAP_FLAGS], %l4	! %l4 = flags

	/*
	 * Generate args for the HV call
	 */
	ldx	[%l3 + LPAD_MAP_VA], %o0	! %o0 = virtual address
	mov	KCONTEXT, %o1			! %o1 = context
	ldx	[%l3 + LPAD_MAP_TTE], %o2	! %o2 = TTE
	and	%l4, FLAG_MMUFLAGS_MASK, %o3	! %o3 = MMU flags

	! check if this is a locked TTE
	and	%l4, FLAG_LOCK_MASK, %l4
	cmp	%l4, %g0
	bne	1f
	  nop

	! install an unlocked entry
	ta	MMU_MAP_ADDR
	ba	2f
	  nop
1:
	! install a locked entry
	mov	MAP_PERM_ADDR, %o5
	ta	FAST_TRAP

2:
	! check for errors from the hcall
	cmp	%o0, %g0
	bne	startup_error
	  nop
	
	sub	%l2, 1, %l2			! decrement counter
	add	%l3, LPAD_MAP_SIZE, %l3		! increment pointer

	ba	0b
	  nop

3:
	/*
	 * Set the MMU fault status area
	 */
	ldx	[%l1 + LPAD_MMFSA_RA], %o0

	mov	MMU_SET_INFOPTR, %o5
	ta	FAST_TRAP

	! check for errors from the hcall
	cmp	%o0, %g0
	bne	startup_error
	  nop

	/*
	 * Load remaining arguments before enabling the
	 * MMU so that the loads can be done using real
	 * addresses.
	 */
	ldx	[%l1 + LPAD_PC], %l3		! %l3 = specified entry point
	ldx	[%l1 + LPAD_ARG], %l4		! %l4 = specified argument
	ldx	[%l1 + LPAD_INUSE], %l5		! %l5 = va of inuse mailbox

	/*
	 * Enable the MMU. On success, it returns to the
	 * global version of the landing pad text, rather
	 * than the text copied into the lpad buffer.
	 */
	mov	1, %o0				! %o0 = enable flag (1 = enable)
	set	startup_complete, %o1		! VA of return address
	mov	MMU_ENABLE, %o5
	ta	FAST_TRAP

	/*
	 * On errors, just enter a spin loop until the
	 * CPU that initiated the start recovers the CPU.
	 */
startup_error:
	ba	startup_error
	  nop

	/*
	 * Jump to the generic CPU initialization code.
	 */
startup_complete:
	mov	%l4, %o0
	jmpl	%l3, %g0
	  stx	%g0, [%l5]			! clear the inuse mailbox

	SET_SIZE(mach_cpu_startup)

	.global mach_cpu_startup_end
mach_cpu_startup_end:

