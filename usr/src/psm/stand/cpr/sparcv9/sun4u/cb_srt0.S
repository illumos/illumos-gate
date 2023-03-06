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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * cb_srt0.s - cprboot startup code
 */
#include <sys/asm_linkage.h>
#include <sys/machthread.h>
#include <sys/privregs.h>
#include <sys/cpr_impl.h>
#include <sys/param.h>
#include <sys/mmu.h>

#if defined(lint)
#include <sys/cpr.h>
void *estack;
caddr_t _end[1];
#endif

#include "cprboot.h"


#if defined(lint)

/* ARGSUSED */
void
_start(void *a, ...)
{}

#else	/* !lint */

	.seg	".bss"
	.align	MMU_PAGESIZE
	.skip	CB_SSS
eslave_stack:				! top of slave cpu stack
	.skip	CB_MSS
estack:					! top of cprboot stack
	.global	estack

	.seg	".data"
	.align	8
local_cif:
	.xword	0			! space for prom cookie

	.seg	".text"
	.align	8

	!
	! regs on entry:
	! %o4 = prom cookie
	!
	ENTRY(_start)
	set	estack - STACK_BIAS, %o5
	save	%o5, -SA(MINFRAME), %sp

	!
	! clear the bss
	!
	set	_edata, %o0
	set	_end, %g2
	call	bzero
	sub	%g2, %o0, %o1		! bss size = (_end - _edata)

	!
	! Set pstate to a known state:
	! enable fp, privilege, interrupt enable
	!
	wrpr	%g0, PSTATE_PEF|PSTATE_PRIV|PSTATE_IE, %pstate

	!
	! first stage
	!
	set	local_cif, %g2
	stx	%i4, [%g2]
	mov	%i4, %o0		! SPARCV9/CIF
	call	main			! Mcprboot [tag]
	mov	1, %o1			! first=true

	!
	! switch to new stack
	!
	set	CB_STACK_VIRT + CB_STACK_SIZE, %o5
	sub	%o5, STACK_BIAS + SA(MINFRAME), %sp

	!
	! second stage
	!
	set	local_cif, %g2
	ldx	[%g2], %o0		! SPARCV9/CIF
	call	main			! Mcprboot [tag]
	mov	0, %o1			! first=false

	call	prom_exit_to_mon	! can't happen... :-)
	nop
	SET_SIZE(_start)

#endif	/* lint */


#if defined(lint)

/*
 * args from cprboot main:
 * 	%o0	prom cookie
 *	%o1	struct sun4u_machdep *mdp
 *
 * Any change to this register assignment requires
 * changes to uts/sun4u/ml/cpr_resume_setup.s
 */

/* ARGSUSED */
void
exit_to_kernel(void *cookie, csu_md_t *mdp)
{}

#else	/* lint */

	ENTRY(exit_to_kernel)
	!
	! setup temporary stack and adjust
	! by the saved kernel stack bias
	!
	set	tmp_stack, %g1			! g1 = &tmp_stack
	ldx	[%g1], %l2			! l2 =  tmp_stack
	sub	%l2, SA(MINFRAME), %l2
	ld	[%o1 + CPR_MD_KSB], %l4		! mdp->ksb
	sub	%l2, %l4, %sp

	!
	! set pstate and wstate from saved values
	!
	lduh	[%o1 + CPR_MD_KPSTATE], %l4	! l4 = mdp->kpstate
	wrpr	%g0, %l4, %pstate
	lduh	[%o1 + CPR_MD_KWSTATE], %l4	! l4 = mdp->kwstate
	wrpr	%g0, %l4, %wstate

	!
	! jump to kernel with %o0 and %o1 unchanged
	!
	ldx	[%o1 + CPR_MD_FUNC], %l3	! l3 = mdp->func
	jmpl	%l3, %g0
	nop

	/* there is no return from here */
	unimp	0
	SET_SIZE(exit_to_kernel)

#endif	/* lint */


#if defined(lint)

/* ARGSUSED */
int
client_handler(void *cif_handler, void *arg_array)
{ return (0); }

#else

	!
	! 64/64 client interface for ieee1275 prom
	!
	ENTRY(client_handler)
	mov	%o7, %g1
	mov	%o0, %g5
	mov	%o1, %o0
	jmp	%g5
	mov	%g1, %o7
	SET_SIZE(client_handler)

#endif	/* lint */


#if defined(lint)

/* ARGSUSED */
void
bzero(void *base, size_t len)
{}

#else

	ENTRY(bzero)
	brz,pn	%o1, 2f
	nop
	mov	%o0, %o2
	mov	%o1, %o3
1:
	stub	%g0, [%o2]
	dec	%o3
	brgz,pt	%o3, 1b
	inc	%o2
2:
	retl
	nop
	SET_SIZE(bzero)

#endif	/* lint */


#if defined(lint)

/* ARGSUSED */
void
phys_xcopy(physaddr_t phys_src, physaddr_t phys_dst, size_t len)
{}

#else

	!
	! copy len bytes from src to dst phys addrs;
	! requires src/dst/len 8-byte alignment;
	! used only for copying phys pages
	!
	ENTRY(phys_xcopy)
	brz,pn	%o2, 2f
	mov	%o0, %o3			! %o3 = src
	mov	%o1, %o4			! %o4 = dst
1:
	ldxa	[%o3]ASI_MEM, %o5		! %o5  = *src
	stxa	%o5, [%o4]ASI_MEM		! *dst = %o5
	dec	8, %o2				! len  -= 8
	inc	8, %o3				! src  += 8
	brgz,pt	%o2, 1b				! branch when (len > 0)
	inc	8, %o4				! dst  += 8
2:
	retl
	nop
	SET_SIZE(phys_xcopy)

#endif


#if defined(lint)

/* ARGSUSED */
void
get_dtlb_entry(int index, caddr_t *vaddrp, tte_t *tte)
{}

#else	/* lint */

	ENTRY(get_dtlb_entry)
	sllx	%o0, 3, %o0
	ldxa	[%o0]ASI_DTLB_ACCESS, %o3
	stx	%o3, [%o2]
	ldxa	[%o0]ASI_DTLB_TAGREAD, %o4
	retl
	stx	%o4, [%o1]
	SET_SIZE(get_dtlb_entry)

#endif


#if defined(lint)

/* ARGSUSED */
void
set_itlb_entry(int index, caddr_t vaddr, tte_t *tte)
{}

/* ARGSUSED */
void
set_dtlb_entry(int index, caddr_t vaddr, tte_t *tte)
{}

#else	/* lint */

	ENTRY(set_dtlb_entry)
	sllx    %o0, 3, %o0
	srlx	%o1, MMU_PAGESHIFT, %o1
	sllx	%o1, MMU_PAGESHIFT, %o1
	set	MMU_TAG_ACCESS, %o4
	ldx	[%o2], %o3
	stxa	%o1, [%o4]ASI_DMMU
	stxa	%o3, [%o0]ASI_DTLB_ACCESS
	membar	#Sync
	retl
	nop
	SET_SIZE(set_dtlb_entry)

	ENTRY(set_itlb_entry)
	sllx    %o0, 3, %o0
	srlx	%o1, MMU_PAGESHIFT, %o1
	sllx	%o1, MMU_PAGESHIFT, %o1
	set	MMU_TAG_ACCESS, %o4
	ldx	[%o2], %o3
	stxa	%o1, [%o4]ASI_IMMU
	stxa	%o3, [%o0]ASI_ITLB_ACCESS
	membar	#Sync
	retl
	nop
	SET_SIZE(set_itlb_entry)

#endif


#if defined(lint)

uint_t
getmid(void)
{ return (0); }

#else	/* lint */

	ENTRY(getmid)
	CPU_INDEX(%o0, %o1)
	retl
	nop
	SET_SIZE(getmid)

#endif


#if defined(lint)

/* ARGSUSED */
void
cpu_launch(int cpuid)
{
	slave_init(cpuid);
}

#else	/* lint */

	ENTRY(cpu_launch)
	set	CB_STACK_VIRT + CB_SSS, %o5
	sub	%o5, STACK_BIAS + SA(MINFRAME), %sp
	wrpr	%g0, PSTATE_PEF|PSTATE_PRIV|PSTATE_IE, %pstate
	call	slave_init
	nop
	unimp	0
	SET_SIZE(cpu_launch)

#endif


#if defined(lint)

void
membar_stld(void)
{}

#else	/* lint */

	ENTRY(membar_stld)
	retl
	membar	#StoreLoad
	SET_SIZE(membar_stld)

#endif


#if defined(lint)

/* ARGSUSED */
void
cb_usec_wait(int usecs)
{}

#else

	.align	32			! cache alignment for next 8 instr
	ENTRY(cb_usec_wait)

	sethi	%hi(cpu_delay), %o1
	ld	[%o1 + %lo(cpu_delay)], %o1
	mov	%o1, %o2
1:	brnz,pt	%o2, 1b			! usec countdown loop
	dec	%o2			! 2 instr in loop

	dec	%o0			! for each usec:
	brgz,pt	%o0, 1b			! run the above loop
	mov	%o1, %o2

	retl
	nop
	SET_SIZE(cb_usec_wait)

#endif
