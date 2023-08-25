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

#ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains no entry points which can be called directly from
 * C and hence is of no interest to lint. However, we want to avoid the
 * dreaded "Empty translation unit"  warning.
 */

#include <sys/asm_linkage.h>
#include <sys/fdreg.h>
#include <sys/fdvar.h>
#include "fd_assym.h"

/*
 * Since this is part of a Sparc "generic" module, it may be loaded during
 * reconfigure time on systems that do not support the fast interrupt
 * handler.  On these machines the symbol "impl_setintreg_on" will be
 * undefined but we don't want to cause error messages when we load.
 */
	.weak	impl_setintreg_on
	.type	impl_setintreg_on, #function
	.weak	fd_softintr_cookie
	.type	fd_softintr_cookie, #object

#define	Tmp2	%l4	/* temp register prior to dispatch to right opmode */
#define	Reg	%l4	/* pointer to the chip's registers */
#define	Fdc	%l3	/* pointer to fdctlr structure */
#define	Adr	%l5	/* data address pointer */
#define	Len	%l6	/* data length counter */
#define	Tmp	%l7	/* general scratch */
#define	TRIGGER	0x33
	ENTRY(fd_intr)		! fd standard interrupt handler
	save	%sp, -SA(MINFRAME), %sp
	!
	! Traverse the list of controllers until we find the first
	! controller expecting an interrupt. Unfortunately, the
	! 82072 floppy controller really doesn't have a way to tell
	! you that it is interrupting.
	!
	set	fdctlrs, Fdc		! load list of controllers
	ldn	[Fdc], Fdc		! get the first in the list...
1:	tst	Fdc			! do we have any more to check
	bz	.panic			! Nothing to service. Panic
	nop

3:	ldub	[Fdc + FD_OPMODE], Tmp2	! load opmode into Tmp2
	and	Tmp2, 0x3, Tmp2		! opmode must be 1, 2, or 3
	tst	Tmp2			! non-zero?
	bnz	.mutex_enter		! yes!
	nop
	ldn	[Fdc + FD_NEXT], Tmp	! Try next ctlr...
	tst	Tmp
	bnz,a	1b
	mov	Tmp, Fdc
					! no more controllers
	mov	0x2, Tmp2		! must be spurious or "ready" int
.mutex_enter:
	!
	! grab high level mutex for this controller
	!
	sethi	%hi(asm_mutex_spin_enter), %l7
	jmpl	%l7 + %lo(asm_mutex_spin_enter), %l7
	add	Fdc, FD_HILOCK, %l6
	!
	! dispatch to correct handler
	!
	cmp	Tmp2, 3			!case 3: results ?
	be,a	.opmode3		! yes...
	ldn	[Fdc + FD_REG], Reg	! load pointer to h/w registers
	cmp	Tmp2, 2			!case 2: seek/recalibrate ?
	be	.opmode2		! yes..
	ldn	[Fdc + FD_REG], Reg	! load pointer to h/w registers
	!
	! opmode 1:
	! read/write/format data-xfer case - they have a result phase
	!
.opmode1:
	ld	[Fdc + FD_RLEN], Len
	!
	! XXX- test for null raddr
	!
	ldn	[Fdc + FD_RADDR], Adr

	!
	! while the fifo ready bit set, then data/status available
	!
1:	ldub	[Reg], Tmp		! get csr
	andcc	Tmp, RQM, %g0		!
	be	4f			! branch if bit clear
	andcc	Tmp, NDM, %g0		! NDM set means data
	be	7f			! if not set, it is status time
	andcc	Tmp, DIO, %g0		! check for input vs. output data
	be	2f			!
	sub	Len, 0x1, Len		! predecrement length...
	ldub	[Reg + 0x1], Tmp	! DIO set, *addr = *fifo
	b	3f			!
	stb	Tmp, [Adr]		!
2:	ldsb	[Adr], Tmp		! *fifo = *addr
	stb	Tmp, [Reg + 0x1]	!
3:	tst	Len			! if (len == 0) send TC
	bne	1b			! branch if not....
	add	Adr, 0x1, Adr		!
	b	6f			!
	.empty				!
	!
	! save updated len, addr
	!
4:	st	Len, [Fdc + FD_RLEN]
	b	.out			! not done yet, return
	stn	Adr, [Fdc + FD_RADDR]
	!
	! END OF TRANSFER - if read/write, toggle the TC
	! bit in AUXIO_REG then save status and set state = 3.
	!
5:
	!
	! Stash len and addr before they get lost
	!
	st	Len, [Fdc + FD_RLEN]
6:	stn	Adr, [Fdc + FD_RADDR]
	!
	! Begin TC delay...
	! Old comment:
	!	five nops provide 100ns of delay at 10MIPS to ensure
	!	TC is wide enough at slowest possible floppy clock
	!	(500ns @ 250Kbps).
	!
	! I gather this mean that we have to give 100ns delay for TC.
	!
	! At 100 Mips, that would be 1 * 10 (10) nops.
	!

	ldn	[Fdc + FD_AUXIOVA], Adr
	ldub	[Fdc + FD_AUXIODATA], Tmp2
	ldub	[Adr], Tmp
	or	Tmp, Tmp2, Tmp
	stb	Tmp, [Adr]
	nop; nop; nop; nop; nop; nop; nop; nop; nop; nop	! 10 nops
	!
	! End TC delay...now clear the TC bit
	!
	ldub	[Fdc + FD_AUXIODATA2], Tmp2
	andn	Tmp, Tmp2, Tmp
	stb	Tmp, [Adr]

	!
	! set opmode to 3 to indicate going into status mode
	!
	mov	3, Tmp
	b	.out
	stb	Tmp, [Fdc + FD_OPMODE]
	!
	! error status state: save old pointers, go direct to result snarfing
	!
7:	st	Len, [Fdc + FD_RLEN]
	stn	Adr, [Fdc + FD_RADDR]
	mov	0x3, Tmp
	b	.opmode3
	stb	Tmp, [Fdc + FD_OPMODE]
	!
	! opmode 2:
	! recalibrate/seek - no result phase, must do sense interrupt status.
	!
.opmode2:
	ldub	[Reg], Tmp			! Tmp = *csr
1:	andcc	Tmp, CB, %g0			! is CB set?
	bne	1b				! yes, keep waiting
	ldub	[Reg], Tmp			!! Tmp = *csr
	!
	! wait!!! should we check rqm first???  ABSOLUTELY YES!!!!
	!
1:	andcc	Tmp, RQM, %g0		!
	be,a	1b			! branch if bit clear
	ldub	[Reg], Tmp		! busy wait until RQM set
	mov	SNSISTAT, Tmp		! cmd for SENSE_INTERRUPT_STATUS
	stb	Tmp, [Reg + 0x1]
	!
	! NOTE: we ignore DIO here, assume it is set before RQM!
	!
	ldub	[Reg], Tmp			! busy wait until RQM set
1:	andcc	Tmp, RQM, Tmp
	be,a	1b				! branch if bit clear
	ldub	[Reg], Tmp			! busy wait until RQM set
	!
	! fdc->c_csb.csb_rslt[0] = *fifo;
	!
	ldub	[Reg + 0x1], Tmp
	stb	Tmp, [Fdc + FD_RSLT]
	ldub	[Reg], Tmp			! busy wait until RQM set
1:	andcc	Tmp, RQM, Tmp
	be,a	1b				! branch if bit clear
	ldub	[Reg], Tmp			! busy wait until RQM set
	!
	! fdc->c_csb.csb_rslt[1] = *fifo;
	!
	ldub	[Reg + 0x1], Tmp
	b	.notify
	stb	Tmp, [Fdc + FD_RSLT + 1]
	!
	! case 3: result mode
	! We are in result mode make sure all status bytes are read out
	!
	! We have to have *both* RQM and DIO set.
	!
.opmode3:
	add	Fdc, FD_RSLT, Adr		! load address of csb->csb_rslt
	add	Adr, 10, Len			! put an upper bound on it..
	ldub	[Reg], Tmp			!
1:	andcc	Tmp, CB, %g0			! is CB set?
	be	.notify				! no, jump around, must be done
	andcc	Tmp, RQM, %g0			! check for RQM in delay slot
	be,a	1b				! No RQM, go back
	ldub	[Reg], Tmp			! and load control reg in delay
	andcc	Tmp, DIO, %g0			! DIO set?
	be,a	1b				! No DIO, go back
	ldub	[Reg], Tmp			! and load control reg in delay
	!
	! CB && DIO && RQM all true.
	! Time to get a byte.
	!
	ldub	[Reg + 0x1], Tmp		! *fifo into Tmp
	cmp	Adr, Len			! already at our limit?
	bge,a	1b				! Yes, go back..
	ldub	[Reg], Tmp			! and load control reg in delay
	stb	Tmp, [Adr]			! store new byte
	add	Adr, 1, Adr			! increment address
	b	1b				! and pop back to the top
	ldub	[Reg], Tmp			! and load control reg in delay

	!
	! schedule 2nd stage interrupt
	!
.notify:
	!
	! if fast traps are enabled, use the platform dependent
	! impl_setintreg_on function.
	!
	ldub    [Fdc + FD_FASTTRAP], Tmp
	tst     Tmp
	bnz	.fast
	nop

	!
	! fast traps are not in use.  Do not schedule the soft interrupt
	! at this time.  Wait to trigger it at the end of the handler
	! when the mutexes have been released
	!
	mov   	TRIGGER, Tmp2
	b	.out
	nop

	!
	! fast traps are enabled.  Schedule the soft interrupt.
	! impl_setintreg uses %l4-%l7
	!
.fast:	sethi   %hi(fd_softintr_cookie), %l6
	sethi	%hi(impl_setintreg_on), %l7
	jmpl	%l7 + %lo(impl_setintreg_on), %l7
	ld      [%l6 + %lo(fd_softintr_cookie)], %l6
	!
	! set new opmode to 4
	!
	mov	0x4, Tmp
	stb	Tmp, [Fdc + FD_OPMODE]

	!
	! and fall through to exit
	!
.out:
	!
	! update high level interrupt counter...
	!
	ldn	[Fdc + FD_HIINTCT], Adr
	tst	Adr
	be,a	1f
	nop
	ld	[Adr], Tmp
	inc	Tmp
	st	Tmp, [Adr]
1:
	!
	! Release mutex
	!
	sethi	%hi(asm_mutex_spin_exit), %l7
	jmpl	%l7 + %lo(asm_mutex_spin_exit), %l7
	add	Fdc, FD_HILOCK, %l6

	!
	! schedule the soft interrupt if needed
	!
	cmp	Tmp2, TRIGGER
	bne	.end
	nop

   	!
	! set new opmode to 4
        !
	mov     0x4, Tmp
        stb     Tmp, [Fdc + FD_OPMODE]

	! invoke ddi_trigger_softintr.  load
	! softid parameter in the delay slot
	!
	call	ddi_trigger_softintr
	ldn	[Fdc + FD_SOFTID], %o0

.end:	mov	1, %i0
	ret
	restore
	SET_SIZE(fd_intr)

.panic:
        ! invoke a kernel panic
        sethi   %hi(panic_msg), %o1
        ldn    [%o1 + %lo(panic_msg)], %o1
        mov     3, %o0
        call    cmn_err
	nop


