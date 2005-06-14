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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * General machine architecture & implementation specific
 * assembly language routines.
 */
#if defined(lint)
#include <sys/types.h>
#include <sys/machsystm.h>
#include <sys/t_lock.h>
#else	/* lint */
#include "assym.h"
#endif	/* lint */

#include <sys/asm_linkage.h>
#include <sys/async.h>
#include <sys/machthread.h>

#if defined(lint)
caddr_t
set_trap_table(void)
{
	return ((caddr_t)0);
}
#else /* lint */

	ENTRY(set_trap_table)
	set	trap_table, %o1
	rdpr	%tba, %o0
	wrpr	%o1, %tba
	retl
	wrpr	%g0, WSTATE_KERN, %wstate
	SET_SIZE(set_trap_table)

#endif /* lint */

#if defined(lint)

/*ARGSUSED*/
void
stphys(uint64_t physaddr, int value)
{}

/*ARGSUSED*/
int
ldphys(uint64_t physaddr)
{ return (0); }

/*ARGSUSED*/
void
stdphys(uint64_t physaddr, uint64_t value)
{}

/*ARGSUSED*/
uint64_t
lddphys(uint64_t physaddr)
{ return (0x0ull); }

/* ARGSUSED */
void
stphysio(u_longlong_t physaddr, uint_t value)
{}

/* ARGSUSED */
uint_t
ldphysio(u_longlong_t physaddr)
{ return(0); }

/* ARGSUSED */
void
sthphysio(u_longlong_t physaddr, ushort_t value)
{}

/* ARGSUSED */
ushort_t
ldhphysio(u_longlong_t physaddr)
{ return(0); }

/* ARGSUSED */
void
stbphysio(u_longlong_t physaddr, uchar_t value)
{}

/* ARGSUSED */
uchar_t
ldbphysio(u_longlong_t physaddr)
{ return(0); }

/*ARGSUSED*/
void
stdphysio(u_longlong_t physaddr, u_longlong_t value)
{}

/*ARGSUSED*/
u_longlong_t
lddphysio(u_longlong_t physaddr)
{ return (0ull); }

#else

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
#endif  /* lint */

/*
 * save_gsr(kfpu_t *fp)
 * Store the graphics status register
 */

#if defined(lint) || defined(__lint)

/* ARGSUSED */
void
save_gsr(kfpu_t *fp)
{}

#else	/* lint */

	ENTRY_NP(save_gsr)
	rd	%gsr, %g2			! save gsr
	retl
	stx	%g2, [%o0 + FPU_GSR]
	SET_SIZE(save_gsr)

#endif	/* lint */

#if defined(lint) || defined(__lint)

/* ARGSUSED */
void
restore_gsr(kfpu_t *fp)
{}

#else	/* lint */

	ENTRY_NP(restore_gsr)
	ldx	[%o0 + FPU_GSR], %g2
	wr	%g2, %g0, %gsr
	retl
	nop
	SET_SIZE(restore_gsr)

#endif	/* lint */

/*
 * uint64_t
 * get_phys_gsr()
 * Get the graphics status register info from fp and return it
 */

#if defined(lint) || defined(__lint)

/* ARGSUSED */
uint64_t
get_phys_gsr(kfpu_t *fp)
{ return 0; }

#else	/* lint */

	ENTRY_NP(get_phys_gsr)
	retl
	rd	%gsr, %o0
	SET_SIZE(get_phys_gsr)

#endif	/* lint */


/*
 * uint64_t
 * get_gsr(kfpu_t *fp)
 * Get the graphics status register info from fp and return it
 */

#if defined(lint) || defined(__lint)

/* ARGSUSED */
uint64_t
get_gsr(kfpu_t *fp)
{ return 0; }

#else	/* lint */

	ENTRY_NP(get_gsr)
	retl
	ldx	[%o0 + FPU_GSR], %o0
	SET_SIZE(get_gsr)

#endif

/*
 * set_phys_gsr(uint64_t *buf, kfpu_t *fp)
 * Set the graphics status register info to fp from buf
 */

#if defined(lint) || defined(__lint)

/* ARGSUSED */
void
set_phys_gsr(uint64_t buf, kfpu_t *fp)
{}

#else	/* lint */

	ENTRY_NP(set_phys_gsr)
	retl
	mov	%o0, %gsr
	SET_SIZE(set_phys_gsr)

#endif	/* lint */

/*	
 * set_gsr(uint64_t buf, kfpu_t *fp)
 * Set the graphics status register info to fp from buf
 */

#if defined(lint) || defined(__lint)

/* ARGSUSED */
void
set_gsr(uint64_t buf, kfpu_t *fp)
{}

#else	/* lint */

	ENTRY_NP(set_gsr)
	retl
	stx	%o0, [%o1 + FPU_GSR]
	SET_SIZE(set_gsr)

#endif	/* lint */
/*
 * Routine to get the pstate reg - used by vis emulation code
 * to test whether the AM bit for 32 bit instructions
 * has been set.
 */
#if defined(lint) || defined(__lint)

/* ARGSUSED */
uint_t
get_pstate(void)
{ return 0; }
#else	/* lint */

	ENTRY_NP(get_pstate)
	retl
	rdpr	%pstate, %o0
	SET_SIZE(get_pstate)

#endif	/* lint */
/*
 * Routine to get the ccr bits - used by vis emulation code
 * to get the ccr bits before an edge instruction is performed
 *
 */

#if defined(lint) || defined(__lint)

/* ARGSUSED */

uint_t
get_ccr()
{ return 0; }
#else	/* lint */

	ENTRY_NP(get_ccr)
	retl
	rd	%ccr, %o0
	SET_SIZE(get_ccr)

#endif

/*
 * Routine to set the ccr bits - used by vis emulation code
 * to set the ccr bits after an edge instruction is performed
 *
 */
#if defined(lint) || defined(__lint)

/* ARGSUSED */
		
void
set_ccr(uint_t buf)
{}
#else	/* lint */

	ENTRY_NP(set_ccr)
	retl
	mov	%o0, %ccr
	SET_SIZE(set_ccr)

#endif	/* lint */

#if defined(lint) || defined(__lint)
void
kdi_cpu_index(void)
{
}

#else	/* lint */

	ENTRY_NP(kdi_cpu_index)
	CPU_INDEX(%g1, %g2)
	jmp	%g7
	nop
	SET_SIZE(kdi_cpu_index)

#endif	/* lint */
