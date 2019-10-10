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

#include <sys/asi.h>
#include <sys/asm_linkage.h>
#include <sys/machthread.h>
#include <sys/privregs.h>
#include <sys/ontrap.h>
#include <sys/dditypes.h>

#include "assym.h"

/*
 * This file implements the following ddi common access 
 * functions:
 *
 *	ddi_get{8,16,32,64}
 *	ddi_put{8,16,32,64}
 *
 * and the underlying "trivial" implementations
 *
 *      i_ddi_{get,put}{8,16,32,64}
 *
 * which assume that there is no need to check the access handle -
 * byte swapping will be done by the mmu and the address is always
 * accessible via ld/st instructions.
 */

/*
 * The functionality of each of the ddi_get/put routines is performed by
 * the respective indirect function defined in the access handle.  Use of
 * the access handle functions provides compatibility across platforms for
 * drivers.
 * 
 * By default, the indirect access handle functions are initialized to the
 * i_ddi_get/put routines to perform memory mapped IO.  If memory mapped IO
 * is not possible or desired, the access handle must be intialized to another
 * valid routine to perform the sepcified IO operation.
 *
 * The alignment and placement of the following functions have been optimized
 * such that the implementation specific versions, i_ddi*, fall within the 
 * same cache-line of the generic versions, ddi_*.  This insures that an
 * I-cache hit will occur thus minimizing the performance impact of using the
 * access handle.
 */

	.align 32
	ENTRY(ddi_get8)
	ALTENTRY(ddi_getb)
	ALTENTRY(ddi_io_get8)
	ALTENTRY(ddi_io_getb)
	ALTENTRY(ddi_mem_get8)
	ALTENTRY(ddi_mem_getb)
	ldn      [%o0 + AHI_GET8], %g1   /* hdl->ahi_get8 access hndl */
	jmpl    %g1, %g0                 /* jump to access handle routine */
	nop
	SET_SIZE(ddi_get8)
	SET_SIZE(ddi_getb)
	SET_SIZE(ddi_io_get8)
	SET_SIZE(ddi_io_getb)
	SET_SIZE(ddi_mem_get8)
	SET_SIZE(ddi_mem_getb)

	.align 16
	ENTRY(i_ddi_get8)
	retl
	ldub	[%o1], %o0
	SET_SIZE(i_ddi_get8)

	.align 32
	ENTRY(ddi_get16)
	ALTENTRY(ddi_getw)
	ALTENTRY(ddi_io_get16)
	ALTENTRY(ddi_io_getw)
	ALTENTRY(ddi_mem_get16)
	ALTENTRY(ddi_mem_getw)
	ldn      [%o0 + AHI_GET16], %g1   /* hdl->ahi_get16 access hndl */
	jmpl    %g1, %g0                  /* jump to access handle routine */
	nop
	SET_SIZE(ddi_get16)
	SET_SIZE(ddi_getw)
	SET_SIZE(ddi_io_get16)
	SET_SIZE(ddi_io_getw)
	SET_SIZE(ddi_mem_get16)
	SET_SIZE(ddi_mem_getw)

	.align 16
	ENTRY(i_ddi_get16)
	ALTENTRY(i_ddi_swap_get16)
	retl
	lduh	[%o1], %o0
	SET_SIZE(i_ddi_get16)
	SET_SIZE(i_ddi_swap_get16)

	.align 32
	ENTRY(ddi_get32)
	ALTENTRY(ddi_getl)
	ALTENTRY(ddi_io_get32)
	ALTENTRY(ddi_io_getl)
	ALTENTRY(ddi_mem_get32)
	ALTENTRY(ddi_mem_getl)
	ldn      [%o0 + AHI_GET32], %g1   /* hdl->ahi_get32 access handle */
	jmpl    %g1, %g0		  /* jump to access handle routine */
	nop
	SET_SIZE(ddi_get32)
	SET_SIZE(ddi_getl)
	SET_SIZE(ddi_io_get32)
	SET_SIZE(ddi_io_getl)
	SET_SIZE(ddi_mem_get32)
	SET_SIZE(ddi_mem_getl)

	.align 16
	ENTRY(i_ddi_get32)
	ALTENTRY(i_ddi_swap_get32)
	retl
	ld	[%o1], %o0
	SET_SIZE(i_ddi_get32)
	SET_SIZE(i_ddi_swap_get32)

	.align 32
	ENTRY(ddi_get64)
	ALTENTRY(ddi_getll)
	ALTENTRY(ddi_io_get64)
	ALTENTRY(ddi_io_getll)
	ALTENTRY(ddi_mem_get64)
	ALTENTRY(ddi_mem_getll)
	ldn      [%o0 + AHI_GET64], %g1   /* hdl->ahi_get64 access handle */
	jmpl    %g1, %g0                  /* jump to access handle routine */
	nop
	SET_SIZE(ddi_get64)
	SET_SIZE(ddi_getll)
	SET_SIZE(ddi_io_get64)
	SET_SIZE(ddi_io_getll)
	SET_SIZE(ddi_mem_get64)
	SET_SIZE(ddi_mem_getll)

	.align 16
	ENTRY(i_ddi_get64)
	ALTENTRY(i_ddi_swap_get64)
	retl
	ldx	[%o1], %o0
	SET_SIZE(i_ddi_get64)
	SET_SIZE(i_ddi_swap_get64)

	.align 32
	ENTRY(ddi_put8)
	ALTENTRY(ddi_putb)
	ALTENTRY(ddi_io_put8)
	ALTENTRY(ddi_io_putb)
	ALTENTRY(ddi_mem_put8)
	ALTENTRY(ddi_mem_putb)
	ldn      [%o0 + AHI_PUT8], %g1   /* hdl->ahi_put8 access handle */
	jmpl    %g1, %g0                 /* jump to access handle routine */
	nop
	SET_SIZE(ddi_put8)
	SET_SIZE(ddi_putb)
	SET_SIZE(ddi_io_put8)
	SET_SIZE(ddi_io_putb)
	SET_SIZE(ddi_mem_put8)
	SET_SIZE(ddi_mem_putb)

	.align 16
	ENTRY(i_ddi_put8)
	retl
	stub	%o2, [%o1]
	SET_SIZE(i_ddi_put8)

	.align 32
	ENTRY(ddi_put16)
	ALTENTRY(ddi_putw)
	ALTENTRY(ddi_io_put16)
	ALTENTRY(ddi_io_putw)
	ALTENTRY(ddi_mem_put16)
	ALTENTRY(ddi_mem_putw)
	ldn      [%o0 + AHI_PUT16], %g1   /* hdl->ahi_put16 access handle */
	jmpl    %g1, %g0                  /* jump to access handle routine */
	nop
	SET_SIZE(ddi_put16)
	SET_SIZE(ddi_putw)
	SET_SIZE(ddi_io_put16)
	SET_SIZE(ddi_io_putw)
	SET_SIZE(ddi_mem_put16)
	SET_SIZE(ddi_mem_putw)

	.align 16
	ENTRY(i_ddi_put16)
	ALTENTRY(i_ddi_swap_put16)
	retl
	stuh	%o2, [%o1]
	SET_SIZE(i_ddi_put16)
	SET_SIZE(i_ddi_swap_put16)

	.align 32
	ENTRY(ddi_put32)
	ALTENTRY(ddi_putl)
	ALTENTRY(ddi_io_put32)
	ALTENTRY(ddi_io_putl)
	ALTENTRY(ddi_mem_put32)
	ALTENTRY(ddi_mem_putl)
	ldn      [%o0 + AHI_PUT32], %g1   /* hdl->ahi_put16 access handle */
	jmpl    %g1, %g0                  /* jump to access handle routine */
	nop
	SET_SIZE(ddi_put32)
	SET_SIZE(ddi_putl)
	SET_SIZE(ddi_io_put32)
	SET_SIZE(ddi_io_putl)
	SET_SIZE(ddi_mem_put32)
	SET_SIZE(ddi_mem_putl)

	.align 16
	ENTRY(i_ddi_put32)
	ALTENTRY(i_ddi_swap_put32)
	retl
	st	%o2, [%o1]
	SET_SIZE(i_ddi_put32)
	SET_SIZE(i_ddi_swap_put32)

	.align 32
	ENTRY(ddi_put64)
	ALTENTRY(ddi_putll)
	ALTENTRY(ddi_io_put64)
	ALTENTRY(ddi_io_putll)
	ALTENTRY(ddi_mem_put64)
	ALTENTRY(ddi_mem_putll)
	ldn      [%o0 + AHI_PUT64], %g1   /* hdl->ahi_put64 access handle */
	jmpl    %g1, %g0                  /* jump to access handle routine */ 
	nop
	SET_SIZE(ddi_put64)
	SET_SIZE(ddi_putll)
	SET_SIZE(ddi_io_put64)
	SET_SIZE(ddi_io_putll)
	SET_SIZE(ddi_mem_put64)
	SET_SIZE(ddi_mem_putll)

	.align 16
	ENTRY(i_ddi_put64)
	ALTENTRY(i_ddi_swap_put64)
	retl
	stx	%o2, [%o1]
	SET_SIZE(i_ddi_put64)
	SET_SIZE(i_ddi_swap_put64)

/*
 * The ddi_io_rep_get/put routines don't take a flag argument like the "plain"
 * and mem versions do.  This flag is used to determine whether or not the 
 * device address or port should be automatically incremented.  For IO space,
 * the device port is never incremented and as such, the flag is always set
 * to DDI_DEV_NO_AUTOINCR.
 *
 * This define processes the repetitive get functionality.  Automatic 
 * incrementing of the device address is determined by the flag field 
 * %o4.  If this is set for AUTOINCR, %o4 is updated with 1 for the 
 * subsequent increment in 2:.
 * 
 * If this flag is not set for AUTOINCR, %o4 is update with a value of 0 thus
 * making the increment operation a non-operation.
 */

#define DDI_REP_GET(n,s)			\
	cmp	DDI_DEV_NO_AUTOINCR, %o4;	\
	mov	%g0, %o4;			\
	brz,pn	%o3, 1f;			\
	movnz	%xcc, n, %o4;			\
2:						\
	dec	%o3;				\
	ld/**/s	[%o2], %g4;			\
	add	%o2, %o4, %o2;			\
	st/**/s	%g4, [%o1];			\
	brnz,pt	%o3, 2b;			\
	add	%o1, n, %o1;			\
1:

	.align 32
	ENTRY(ddi_rep_get8)
	ALTENTRY(ddi_rep_getb)
	ALTENTRY(ddi_mem_rep_get8)
	ALTENTRY(ddi_mem_rep_getb)
	ldn      [%o0 + AHI_REP_GET8], %g1
	jmpl    %g1, %g0
	nop
	SET_SIZE(ddi_rep_get8)
	SET_SIZE(ddi_rep_getb)
	SET_SIZE(ddi_mem_rep_get8)
	SET_SIZE(ddi_mem_rep_getb)

	.align 16
	ENTRY(i_ddi_rep_get8)
	DDI_REP_GET(1,ub)
	retl
	nop
	SET_SIZE(i_ddi_rep_get8)
	
	.align 32
	ENTRY(ddi_rep_get16)
	ALTENTRY(ddi_rep_getw)
	ALTENTRY(ddi_mem_rep_get16)
	ALTENTRY(ddi_mem_rep_getw)
	ldn	[%o0 + AHI_REP_GET16], %g1
	jmpl    %g1, %g0
	nop
	SET_SIZE(ddi_rep_get16)
	SET_SIZE(ddi_rep_getw)
	SET_SIZE(ddi_mem_rep_get16)
	SET_SIZE(ddi_mem_rep_getw)

	.align 16
	ENTRY(i_ddi_rep_get16)
	ALTENTRY(i_ddi_swap_rep_get16)
	DDI_REP_GET(2,uh)
	retl
	nop
	SET_SIZE(i_ddi_rep_get16)
	SET_SIZE(i_ddi_swap_rep_get16)

	.align 32
	ENTRY(ddi_rep_get32)
	ALTENTRY(ddi_rep_getl)
	ALTENTRY(ddi_mem_rep_get32)
	ALTENTRY(ddi_mem_rep_getl)
	ldn      [%o0 + AHI_REP_GET32], %g1
	jmpl    %g1, %g0
	nop
	SET_SIZE(ddi_rep_get32)
	SET_SIZE(ddi_rep_getl)
	SET_SIZE(ddi_mem_rep_get32)
	SET_SIZE(ddi_mem_rep_getl)

	.align 16
	ENTRY(i_ddi_rep_get32)
	ALTENTRY(i_ddi_swap_rep_get32)
	DDI_REP_GET(4,/**/)
	retl
	nop
	SET_SIZE(i_ddi_rep_get32)
	SET_SIZE(i_ddi_swap_rep_get32)

	.align 32
	ENTRY(ddi_rep_get64)
	ALTENTRY(ddi_rep_getll)
	ALTENTRY(ddi_mem_rep_get64)
	ALTENTRY(ddi_mem_rep_getll)
	ldn      [%o0 + AHI_REP_GET64], %g1
	jmpl    %g1, %g0
	nop
	SET_SIZE(ddi_rep_get64)
	SET_SIZE(ddi_rep_getll)
	SET_SIZE(ddi_mem_rep_get64)
	SET_SIZE(ddi_mem_rep_getll)

	.align 16
	ENTRY(i_ddi_rep_get64)
	ALTENTRY(i_ddi_swap_rep_get64)
	DDI_REP_GET(8,x)
	retl
	nop
	SET_SIZE(i_ddi_rep_get64)
	SET_SIZE(i_ddi_swap_rep_get64)

/* 
 * This define processes the repetitive put functionality.  Automatic 
 * incrementing of the device address is determined by the flag field 
 * %o4.  If this is set for AUTOINCR, %o4 is updated with 1 for the 
 * subsequent increment in 2:.
 * 
 * If this flag is not set for AUTOINCR, %o4 is update with a value of 0 thus
 * making the increment operation a non-operation.
 */
#define DDI_REP_PUT(n,s)			\
	cmp	DDI_DEV_NO_AUTOINCR, %o4;	\
	mov	%g0, %o4;			\
	brz,pn	%o3, 1f;			\
	movnz	%xcc, n, %o4;			\
2:						\
	dec	%o3;				\
	ld/**/s	[%o1], %g4;			\
	add	%o1, n, %o1;			\
	st/**/s	%g4, [%o2];			\
	brnz,pt	%o3, 2b;			\
	add	%o2, %o4, %o2;			\
1:

	.align 32
	ENTRY(ddi_rep_put8)
	ALTENTRY(ddi_rep_putb)
	ALTENTRY(ddi_mem_rep_put8)
	ALTENTRY(ddi_mem_rep_putb)
	ldn      [%o0 + AHI_REP_PUT8], %g1
	jmpl    %g1, %g0
	nop
	SET_SIZE(ddi_rep_put8)
	SET_SIZE(ddi_rep_putb)
	SET_SIZE(ddi_mem_rep_put8)
	SET_SIZE(ddi_mem_rep_putb)

	.align 16
	ENTRY(i_ddi_rep_put8)
	DDI_REP_PUT(1,ub)
	retl
	nop
	SET_SIZE(i_ddi_rep_put8)

	.align 32
	ENTRY(ddi_rep_put16)
	ALTENTRY(ddi_rep_putw)
	ALTENTRY(ddi_mem_rep_put16)
	ALTENTRY(ddi_mem_rep_putw)
	ldn      [%o0 + AHI_REP_PUT16], %g1
	jmpl    %g1, %g0
	nop
	SET_SIZE(ddi_rep_put16)
	SET_SIZE(ddi_rep_putw)
	SET_SIZE(ddi_mem_rep_put16)
	SET_SIZE(ddi_mem_rep_putw)

	.align 16
	ENTRY(i_ddi_rep_put16)
	ALTENTRY(i_ddi_swap_rep_put16)
	DDI_REP_PUT(2,uh)
	retl
	nop
	SET_SIZE(i_ddi_rep_put16)
	SET_SIZE(i_ddi_swap_rep_put16)

	.align 32
	ENTRY(ddi_rep_put32)
	ALTENTRY(ddi_rep_putl)
	ALTENTRY(ddi_mem_rep_put32)
	ALTENTRY(ddi_mem_rep_putl)
	ldn      [%o0 + AHI_REP_PUT32], %g1
	jmpl    %g1, %g0
	nop
	SET_SIZE(ddi_rep_put32)
	SET_SIZE(ddi_rep_putl)
	SET_SIZE(ddi_mem_rep_put32)
	SET_SIZE(ddi_mem_rep_putl)

	.align 16
	ENTRY(i_ddi_rep_put32)
	ALTENTRY(i_ddi_swap_rep_put32)
	DDI_REP_PUT(4,/**/)
	retl
	nop
	SET_SIZE(i_ddi_rep_put32)
	SET_SIZE(i_ddi_swap_rep_put32)

	.align 32
	ENTRY(ddi_rep_put64)
	ALTENTRY(ddi_rep_putll)
	ALTENTRY(ddi_mem_rep_put64)
	ALTENTRY(ddi_mem_rep_putll)
	ldn      [%o0 + AHI_REP_PUT64], %g1
	jmpl    %g1, %g0
	nop
	SET_SIZE(ddi_rep_put64)
	SET_SIZE(ddi_rep_putll)
	SET_SIZE(ddi_mem_rep_put64)
	SET_SIZE(ddi_mem_rep_putll)

	.align 16
	ENTRY(i_ddi_rep_put64)
	ALTENTRY(i_ddi_swap_rep_put64)
	DDI_REP_PUT(8,x)
	retl
	nop
	SET_SIZE(i_ddi_rep_put64)
	SET_SIZE(i_ddi_swap_rep_put64)

	.align 16
	ENTRY(ddi_io_rep_get8)
	ALTENTRY(ddi_io_rep_getb)
	set	DDI_DEV_NO_AUTOINCR, %o4 /* Set flag to DDI_DEV_NO_AUTOINCR */
	ldn	[%o0 + AHI_REP_GET8], %g1
	jmpl    %g1, %g0
	nop
	SET_SIZE(ddi_io_rep_get8)
	SET_SIZE(ddi_io_rep_getb)

	.align 16
	ENTRY(ddi_io_rep_get16)
	ALTENTRY(ddi_io_rep_getw)
	set	DDI_DEV_NO_AUTOINCR, %o4 /* Set flag to DDI_DEV_NO_AUTOINCR */
	ldn	[%o0 + AHI_REP_GET16], %g1
	jmpl    %g1, %g0
	nop
	SET_SIZE(ddi_io_rep_get16)
	SET_SIZE(ddi_io_rep_getw)

	.align 16
	ENTRY(ddi_io_rep_get32)
	ALTENTRY(ddi_io_rep_getl)
	set	DDI_DEV_NO_AUTOINCR, %o4 /* Set flag to DDI_DEV_NO_AUTOINCR */
	ldn	[%o0 + AHI_REP_GET32], %g1
	jmpl    %g1, %g0
	nop
	SET_SIZE(ddi_io_rep_get32)
	SET_SIZE(ddi_io_rep_getl)

	.align 16
	ENTRY(ddi_io_rep_get64)
	ALTENTRY(ddi_io_rep_getll)
	set	DDI_DEV_NO_AUTOINCR, %o4 /* Set flag to DDI_DEV_NO_AUTOINCR */
	ldn	[%o0 + AHI_REP_GET64], %g1
	jmpl    %g1, %g0
	nop
	SET_SIZE(ddi_io_rep_get64)
	SET_SIZE(ddi_io_rep_getll)

        .align 64
	ENTRY(ddi_check_acc_handle)
	save	%sp, -SA(WINDOWSIZE), %sp	! get a new window
	ldn	[%i0 + AHI_FAULT_CHECK], %g1
	jmpl	%g1, %o7
	mov	%i0, %o0
	brnz,a,pn %o0, 0f			! if (return_value != 0)
	mov	-1, %o0				! 	return (DDI_FAILURE)
0:						! else	return (DDI_SUCCESS)
	sra	%o0, 0, %i0
	ret
	restore
	SET_SIZE(ddi_check_acc_handle)

        .align 16
        ENTRY(i_ddi_acc_fault_check)
	retl
	ld      [%o0 + AHI_FAULT], %o0
        SET_SIZE(i_ddi_acc_fault_check)

	.align 16
	ENTRY(ddi_io_rep_put8)
	ALTENTRY(ddi_io_rep_putb)
	set	DDI_DEV_NO_AUTOINCR, %o4 /* Set flag to DDI_DEV_NO_AUTOINCR */
	ldn	[%o0 + AHI_REP_PUT8], %g1
	jmpl    %g1, %g0
	nop
	SET_SIZE(ddi_io_rep_put8)
	SET_SIZE(ddi_io_rep_putb)

	.align 16
	ENTRY(ddi_io_rep_put16)
	ALTENTRY(ddi_io_rep_putw)
	set	DDI_DEV_NO_AUTOINCR, %o4 /* Set flag to DDI_DEV_NO_AUTOINCR */
	ldn	[%o0 + AHI_REP_PUT16], %g1
	jmpl    %g1, %g0
	nop
	SET_SIZE(ddi_io_rep_put16)
	SET_SIZE(ddi_io_rep_putw)

	.align 16
	ENTRY(ddi_io_rep_put32)
	ALTENTRY(ddi_io_rep_putl)
	set	DDI_DEV_NO_AUTOINCR, %o4 /* Set flag to DDI_DEV_NO_AUTOINCR */
	ldn	[%o0 + AHI_REP_PUT32], %g1
	jmpl    %g1, %g0
	nop
	SET_SIZE(ddi_io_rep_put32)
	SET_SIZE(ddi_io_rep_putl)

	.align 16
	ENTRY(ddi_io_rep_put64)
	ALTENTRY(ddi_io_rep_putll)
	set	DDI_DEV_NO_AUTOINCR, %o4 /* Set flag to DDI_DEV_NO_AUTOINCR */
	ldn	[%o0 + AHI_REP_PUT64], %g1
	jmpl    %g1, %g0
	nop
	SET_SIZE(ddi_io_rep_put64)
	SET_SIZE(ddi_io_rep_putll)

	ENTRY(do_peek)
	rdpr	%pstate, %o3	! check ints
	andcc	%o3, PSTATE_IE, %g0
	bz,a	done
	or	%g0, 1, %o0	! Return failure if ints are disabled
	wrpr	%o3, PSTATE_IE, %pstate
	cmp	%o0, 8		! 64-bit?
	bne,a	.peek_int
	cmp	%o0, 4		! 32-bit?
	ldx	[%o1], %g1
	ba	.peekdone
	stx	%g1, [%o2]
.peek_int:
	bne,a	.peek_half
	cmp	%o0, 2		! 16-bit?
	lduw	[%o1], %g1
	ba	.peekdone
	stuw	%g1, [%o2]
.peek_half:
	bne,a	.peek_byte
	ldub	[%o1], %g1	! 8-bit!
	lduh	[%o1], %g1
	ba	.peekdone
	stuh	%g1, [%o2]
.peek_byte:
	stub	%g1, [%o2]
.peekdone:
	membar	#Sync		! Make sure the loads take
	rdpr	%pstate, %o3	! check&enable ints
	andcc	%o3, PSTATE_IE, %g0
	bnz	1f
	nop
	wrpr	%o3, PSTATE_IE, %pstate
1:	
	mov	%g0, %o0
done:
	retl
	nop
	SET_SIZE(do_peek)

	ENTRY(do_poke)
	cmp	%o0, 8		! 64 bit?
	bne,a	.poke_int
	cmp	%o0, 4		! 32-bit?
	ldx	[%o2], %g1
	ba	.pokedone
	stx	%g1, [%o1]
.poke_int:
	bne,a	.poke_half
	cmp	%o0, 2		! 16-bit?
	lduw	[%o2], %g1
	ba	.pokedone
	stuw	%g1, [%o1]
.poke_half:
	bne,a	.poke_byte
	ldub	[%o2], %g1	! 8-bit!
	lduh	[%o2], %g1
	ba	.pokedone
	stuh	%g1, [%o1]
.poke_byte:
	stub	%g1, [%o1]
.pokedone:
	membar	#Sync
	retl
	mov	%g0, %o0
	SET_SIZE(do_poke)


/*
 * The peek_fault() and poke_fault() routines below are used as on_trap()
 * trampoline routines.  i_ddi_peek and i_ddi_poke execute do_peek and do_poke
 * under on_trap protection (see <sys/ontrap.h>), but modify ot_trampoline to
 * refer to the corresponding routine below.  If a trap occurs, the trap code
 * will bounce back to the trampoline code, which will effectively cause
 * do_peek or do_poke to return DDI_FAILURE, instead of longjmp'ing back to
 * on_trap.  In the case of a peek, we may also need to re-enable interrupts.
 */
	.seg	".data"
.peek_panic:
	.asciz	"peek_fault: missing or invalid on_trap_data"
.poke_panic:
	.asciz	"poke_fault: missing or invalid on_trap_data"

	ENTRY(peek_fault)
	ldn	[THREAD_REG + T_ONTRAP], %o0	! %o0 = on_trap_data pointer
	brz,pn	%o0, .peekfail			! if (%o0 == NULL) panic
	nop
	lduh	[%o0 + OT_PROT], %o1		! %o1 = %o0->ot_prot
	andcc	%o1, OT_DATA_ACCESS, %g0	! if (!(%o1 & OT_DATA_ACCESS))
	bz,pn	%icc, .peekfail			!     panic
	rdpr	%pstate, %o3

	andcc	%o3, PSTATE_IE, %g0		! enable interrupts
	bnz	1f
	nop
	wrpr	%o3, PSTATE_IE, %pstate
1:	
	retl
	sub	%g0, 1, %o0			! return (DDI_FAILURE);
.peekfail:
	set	.peek_panic, %o0		! Load panic message
	call	panic				! Panic if bad t_ontrap data
	nop
	SET_SIZE(peek_fault)


	ENTRY(poke_fault)
	ldn	[THREAD_REG + T_ONTRAP], %o0	! %o0 = on_trap_data pointer
	brz,pn	%o0, .pokefail			! if (%o0 == NULL) panic
	nop
	lduh	[%o0 + OT_PROT], %o1		! %o1 = %o0->ot_prot
	andcc	%o1, OT_DATA_ACCESS, %g0	! if (!(%o1 & OT_DATA_ACCESS))
	bz,pn	%icc, .pokefail			!     panic
	nop
	retl
	sub	%g0, 1, %o0			! return (DDI_FAILURE);
.pokefail:
	set	.poke_panic, %o0		! Load panic message
	call	panic				! Panic if bad t_ontrap data
	nop
	SET_SIZE(poke_fault)


/*
 * IO Fault Services
 *
 * Support for protected IO accesses is implemented in the following
 * functions.  A driver may request one of three protection mechanisms
 * that enable the system to survive an access errors.  The protection
 * mechansim is set-up during ddi_regs_map_setup time and may be one of:
 *
 *	DDI_DEFAULT_ACC	- no error protection requested.  We will
 *			use the standard ddi_get/ddi_put operations
 *			defined above.
 *
 *	DDI_FLAGERR - Driver requests that errors encountered will
 *			be flagged by the system.  The driver is
 *			responsible for checking the error status
 *			of the access with a call to ddi_acc_err_get()
 *			upon return of ddi_get or ddi_put.  To prevent
 *			an access from causing a system we use internal
 *			on_trap semantics.
 *
 *			The system, depending upon the error,
 *			may or may not panic.
 *
 *	DDI_CAUTIOUS_ACC - Driver expects that the access may cause
 *			an error to occur.  The system will return
 *			an error status but will not generate an ereport.
 *			The system will also ensure synchronous and
 *			exclusive access to the IO space accessed by
 *			the caller.
 *
 *			To prevent an access from causing a system panic,
 *			we use on_trap semantics to catch the error and
 *			set error status.
 * 
 *	If a read access error is detected and DDI_CAUTIOUS_ACC or
 *	DDI_FLAGERR_ACC	protection was requested, we will trampoline to the
 *	error handler, i_ddi_trampoline.  i_ddi_trampoline will:
 *		- check for proper protection semantics
 *		- set the error status of the access handle to DDI_FM_NONFATAL
 *		- re-enable interrupts if neccessary
 *		- longjmp back to the initiating access function.

 *	If a write access error is detected, an interrupt is typically
 *	generated and claimed by a bus nexus responsible for the write
 *	transaction.  The nexus error handler is expected to set the
 *	error status and the IO initiating driver is expected to check
 *	for a failed transaction via ddi_fm_acc_err_get(). 
 * 
 */

	.seg	".data"
.acc_panic:
	.asciz	"DDI access: missing or invalid on_trap_data"

	ENTRY(i_ddi_caut_trampoline)
	ldn	[THREAD_REG + T_ONTRAP], %o5    ! %o5 = curthread->t_ontrap
	lduh	[%o5 + OT_PROT], %o1		! %o1 = %o0->ot_prot
	andcc	%o1, OT_DATA_ACCESS, %g0	! if (!(%o1 & OT_DATA_ACCESS))
	bz,pn	%icc, .cautaccfail		!     panic
	rdpr	%pstate, %o3
	andcc	%o3, PSTATE_IE, %g0		! enable interrupts
	bnz	1f
	nop
	wrpr	%o3, PSTATE_IE, %pstate
1:
	ldn	[%o5 + OT_HANDLE], %o0		! %o0 = ot_handle
	brz,pn	%o0, .cautaccfail		! if (ot_handle == NULL) panic
	nop
	ldn	[%o0 + AHI_ERR], %o4		! %o4 = hp->ahi_err
	membar	#Sync
	stx	%g0, [%o4 + ERR_ENA]		! ahi_err->err_ena = 0
	mov	-2, %o0
	st	%o0, [%o4 + ERR_STATUS]		! ahi_err->err_status = NONFATAL
	b	longjmp                		! longjmp back 
	add	%o5, OT_JMPBUF, %o0		! %o0 = &ot_jmpbuf
.cautaccfail:
	set	.acc_panic, %o0			! Load panic message
	call	panic				! Panic if bad t_ontrap data
	nop
	SET_SIZE(i_ddi_caut_trampoline)

/*
 * DDI on_trap set-up functions,  i_ddi_ontrap() and i_ddinotrap() are used
 * to protect * ddi_get accesses for DDI_CAUT_ACC.  i_ddi_ontrap() sets
 * the jumpbuf (setjmp) that will return back to the access routine from
 * i_ddi_trampoline().  DDI_NOPROTECT() clears the ontrap set-up.
 */
	ENTRY(i_ddi_ontrap)
	ldn	[%o0 + AHI_ERR], %o4
	ldn	[%o4 + ERR_ONTRAP],  %o4	! %o4 = hp->ahi_err->err_ontrap
	ldn	[THREAD_REG + T_ONTRAP], %o5	! %o5 = curthread->t_ontrap
	stn	%o5, [%o4 + OT_PREV]		! ot_prev = t_ontrap
	membar	#Sync				! force error barrier
	stn	%o4, [THREAD_REG + T_ONTRAP]	! t_ontrap = err_ontrap
	b	setjmp
	add	%o4, OT_JMPBUF, %o0
	SET_SIZE(i_ddi_ontrap)

	ENTRY(i_ddi_notrap)
	membar	#Sync				! force error barrier
	ldn	[%o0 + AHI_ERR], %o4
	ldn	[%o4 + ERR_ONTRAP],  %o4	! %o4 = hp->ahi_err->err_ontrap
	ldn	[%o4 + OT_PREV], %o4
	retl
	stn	%o4, [THREAD_REG + T_ONTRAP]	! restore curthread->t_ontrap
	SET_SIZE(i_ddi_notrap)

/*
 * Internal on_trap set-up macros.  DDI_PROTECT() and DDI_NOPROTECT() are used
 * to protect * ddi_get accesses for DDI_FLAGERR_ACC.  DDI_NOPROTECT() sets
 * the jumpbuf that will return back to the access routine from
 * i_ddi_protect_trampoline().  DDI_NOPROTECT() clears the ontrap set-up.
 */
	ENTRY(i_ddi_prot_trampoline)
	ldn	[THREAD_REG + T_ONTRAP], %o5    ! %o5 = curthread->t_ontrap
	lduh	[%o5 + OT_PROT], %o1		! %o1 = %o0->ot_prot
	andcc	%o1, OT_DATA_ACCESS, %g0	! if (!(%o1 & OT_DATA_ACCESS))
	bz,pn	%icc, .protaccfail		!     panic
	rdpr	%pstate, %o3
	andcc	%o3, PSTATE_IE, %g0		! enable interrupts
	bnz	1f
	nop
	wrpr	%o3, PSTATE_IE, %pstate
1:
	ldn	[%o5 + OT_HANDLE], %o0		! %o0 = ot_handle
	brz,pn	%o0, .protaccfail		! if (ot_handle == NULL) panic
	nop
	ldn	[%o0 + AHI_ERR], %o4		! %o4 = hp->ahi_err
	stn	%g0, [%o4 + ERR_ENA]		! ahi_err->err_ena = 0
	mov	-2, %o0
	st	%o0, [%o4 + ERR_STATUS]		! ahi_err->err_status = NONFATAL
	ldn	[%o5 + OT_PREV], %o0		! restore ontrap
	membar	#Sync				! force error barrier
	stn	%o0, [THREAD_REG + T_ONTRAP];
	b	longjmp                		! longjmp back 
	add	%o5, OT_JMPBUF, %o0		! %o0 = &ot_jmpbuf
.protaccfail:
	set	.acc_panic, %o0			! Load panic message
	call	panic				! Panic if bad t_ontrap data
	nop
	SET_SIZE(i_ddi_prot_trampoline)

#define	DDI_PROTECT()				\
	ldn	[%o0 + AHI_ERR], %o4;		\
	ldn	[%o4 + ERR_ONTRAP],  %o4;	\
	ldn	[THREAD_REG + T_ONTRAP], %o5;	\
	stn	%o5, [%o4 + OT_PREV];		\
	membar	#Sync;				\
	stn	%o4, [THREAD_REG + T_ONTRAP];	\
	add     %o4, OT_JMPBUF, %o0;		\
	stn	%o7, [%o0 + L_PC];		\
	stn	%sp, [%o0 + L_SP];		\
	clr	%o0;

#define	DDI_NOPROTECT()				\
	ldn	[THREAD_REG + T_ONTRAP], %o4;	\
	ldn	[%o4 + OT_PREV], %o5;		\
	membar	#Sync;				\
	stn	%o5, [THREAD_REG + T_ONTRAP];

/*
 * DDI_FLAGERR_ACC specific get/put routines.
 */
	.align 16
	ENTRY(i_ddi_prot_get8)
	DDI_PROTECT()				! set ontrap protection
	ldub	[%o1], %o2			! do the io access
	DDI_NOPROTECT()				! remove protection & ret
	retl
	mov	%o2, %o0			! set return value
	SET_SIZE(i_ddi_prot_get8)

	.align 16
	ENTRY(i_ddi_prot_get16)
	DDI_PROTECT()				! set ontrap protection
	lduh	[%o1], %o2			! do the io access
	DDI_NOPROTECT()				! remove protection & ret
	retl
	mov	%o2, %o0			! set return value
	SET_SIZE(i_ddi_prot_get16)

	.align 16
	ENTRY(i_ddi_prot_get32)
	DDI_PROTECT()				! set ontrap protection
	ld	[%o1], %o2			! do the io access
	DDI_NOPROTECT()				! remove protection & ret
	retl
	mov	%o2, %o0			! set return value
	SET_SIZE(i_ddi_prot_get32)

	.align 16
	ENTRY(i_ddi_prot_get64)
	DDI_PROTECT()				! set ontrap protection
	ldx	[%o1], %o2			! do the io access
	DDI_NOPROTECT()				! remove protection & ret
	retl
	mov	%o2, %o0			! set return value
	SET_SIZE(i_ddi_prot_get64)

	.align 16
	ENTRY(i_ddi_prot_put8)
	stub	%o2, [%o1]			! do the io access
	retl
	membar	#Sync;
	SET_SIZE(i_ddi_prot_put8)

	.align 16
	ENTRY(i_ddi_prot_put16)
	stuh	%o2, [%o1]			! do the io access
	retl
	membar	#Sync;
	SET_SIZE(i_ddi_prot_put16)

	.align 16
	ENTRY(i_ddi_prot_put32)
	st	%o2, [%o1]			! do the io access
	retl
	membar	#Sync;
	SET_SIZE(i_ddi_prot_put32)

	.align 16
	ENTRY(i_ddi_prot_put64)
	stx	%o2, [%o1]			! do the io access
	retl
	membar	#Sync;
	SET_SIZE(i_ddi_prot_put64)

	.align 16
	ENTRY(i_ddi_prot_rep_get8)
	DDI_PROTECT()				! set ontrap protection
	tst	%o0				! check access error
	bnz,a	1f
	nop
	DDI_REP_GET(1,ub)
1:
	DDI_NOPROTECT()				! remove protection & ret
	retl
	nop
	SET_SIZE(i_ddi_prot_rep_get8)

	.align 16
	ENTRY(i_ddi_prot_rep_get16)
	DDI_PROTECT()				! set ontrap protection
	tst	%o0				! check access error
	bnz,a	1f
	nop
	DDI_REP_GET(2,uh)
1:
	DDI_NOPROTECT()				! remove protection & ret
	retl
	nop
	SET_SIZE(i_ddi_prot_rep_get16)

	.align 16
	ENTRY(i_ddi_prot_rep_get32)
	DDI_PROTECT()				! set ontrap protection
	tst	%o0				! check access error
	bnz,a	1f
	nop
	DDI_REP_GET(4,/**/)
1:
	DDI_NOPROTECT()				! remove protection & ret
	retl
	nop
	SET_SIZE(i_ddi_prot_rep_get32)

	.align 16
	ENTRY(i_ddi_prot_rep_get64)
	DDI_PROTECT()				! set ontrap protection
	tst	%o0				! check access error
	bnz,a	1f
	nop
	DDI_REP_GET(8,x)
1:
	DDI_NOPROTECT()				! remove protection & ret
	retl
	nop
	SET_SIZE(i_ddi_prot_rep_get64)

	.align 16
	ENTRY(i_ddi_prot_rep_put8)
	DDI_REP_PUT(1,ub)
	retl
	membar	#Sync;
	SET_SIZE(i_ddi_prot_rep_put8)

	.align 16
	ENTRY(i_ddi_prot_rep_put16)
	DDI_REP_PUT(2,uh)
	retl
	membar	#Sync;
	SET_SIZE(i_ddi_prot_rep_put16)

	.align 16
	ENTRY(i_ddi_prot_rep_put32)
	DDI_REP_PUT(4,/**/)
	retl
	membar	#Sync;
	SET_SIZE(i_ddi_prot_rep_put32)

	.align 16
	ENTRY(i_ddi_prot_rep_put64)
	DDI_REP_PUT(8,x)
	retl
	membar	#Sync;
	SET_SIZE(i_ddi_prot_rep_put64)

/*
 * Common DDI_CAUTIOUS_ACC routine called from cautious access routines
 * in ddi_impl.c
 */
	ENTRY(i_ddi_caut_get)
	rdpr	%pstate, %o3	! check ints
	andcc	%o3, PSTATE_IE, %g0
	bz,a	cautdone
	nop
	wrpr	%o3, PSTATE_IE, %pstate
	cmp	%o0, 8		! 64-bit?
	bne,a	.get_int
	cmp	%o0, 4		! 32-bit?
	ldx	[%o1], %g1
	ba	.getdone
	stx	%g1, [%o2]
.get_int:
	bne,a	.get_half
	cmp	%o0, 2		! 16-bit?
	lduw	[%o1], %g1
	ba	.getdone
	stuw	%g1, [%o2]
.get_half:
	bne,a	.get_byte
	ldub	[%o1], %g1	! 8-bit!
	lduh	[%o1], %g1
	ba	.getdone
	stuh	%g1, [%o2]
.get_byte:
	stub	%g1, [%o2]
.getdone:
	rdpr	%pstate, %o3	! check&enable ints
	andcc	%o3, PSTATE_IE, %g0
	bnz,a	cautdone
	nop
	wrpr	%o3, PSTATE_IE, %pstate
cautdone:
	retl
	nop
	SET_SIZE(i_ddi_caut_get)

