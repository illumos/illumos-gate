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

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/asm_linkage.h>
#include <sys/vtrace.h>
#include <sys/machthread.h>
#include <sys/clock.h>
#include <sys/asi.h>
#include <sys/fsr.h>
#include <sys/privregs.h>

#include "assym.h"

/*
 * Error barrier:
 * We use membar sync to establish an error barrier for
 * deferred errors. Membar syncs are added before any update
 * to t_lofault to ensure that deferred errors from earlier
 * accesses will not be reported after the membar. This error
 * isolation is important when we try to recover from async
 * errors which tries to distinguish kernel accesses to user
 * data.
 */

/*
 * Copy a null terminated string from one point to another in
 * the kernel address space.
 * NOTE - don't use %o5 in this routine as copy{in,out}str uses it.
 *
 * copystr(from, to, maxlength, lencopied)
 *	caddr_t from, to;
 *	u_int maxlength, *lencopied;
 */

	ENTRY(copystr)
	orcc	%o2, %g0, %o4		! save original count
	bg,a	%ncc, 1f
	  sub	%o0, %o1, %o0		! o0 gets the difference of src and dst

	!
	! maxlength <= 0
	!
	bz	%ncc, .cs_out		! maxlength = 0
	mov	ENAMETOOLONG, %o0

	b	2f			! maxlength < 0
	mov	EFAULT, %o0		! return failure

	!
	! Do a byte by byte loop.
	! We do this instead of a word by word copy because most strings
	! are small and this takes a small number of cache lines.
	!
0:
	stb	%g1, [%o1]		! store byte
	tst	%g1
	bnz,pt	%icc, 1f
	add	%o1, 1, %o1		! incr dst addr

	ba,pt	%ncc, .cs_out		! last byte in string
	mov	0, %o0			! ret code = 0
1:
	subcc	%o2, 1, %o2		! test count
	bgeu,a	%ncc, 0b
	ldub	[%o0 + %o1], %g1	! delay slot, get source byte

	mov	0, %o2			! max number of bytes moved
	mov	ENAMETOOLONG, %o0	! ret code = ENAMETOOLONG
.cs_out:
	tst	%o3
	bz	%ncc, 2f
	sub	%o4, %o2, %o4		! compute length and store it
	stn	%o4, [%o3]
2:
	retl
	nop
	SET_SIZE(copystr)


/*
 * Copy a null terminated string from the user address space into
 * the kernel address space.
 */

	ENTRY(copyinstr)
	sethi	%hi(.copyinstr_err), %o4
	ldn	[THREAD_REG + T_LOFAULT], %o5	! catch faults
	or	%o4, %lo(.copyinstr_err), %o4
	membar	#Sync				! sync error barrier
	stn	%o4, [THREAD_REG + T_LOFAULT]

	brz,a,pn %o2, .copyinstr_out
	mov	ENAMETOOLONG, %o0

	mov	%o2, %g3		! g3 is the current count
	mov	%o1, %g4		! g4 is the dest addr

	b	1f
	sub	%o0, %o1, %g2		! g2 gets the difference of src and dst

	!
	! Do a byte by byte loop.
	! We do this instead of a word by word copy because most strings
	! are small and this takes a small number of cache lines.
	!
0:
	stb	%g1, [%g4]		! store byte
	tst	%g1
	bnz,pt	%icc, 1f
	add	%g4, 1, %g4		! incr dst addr

	ba,pt	%ncc, .copyinstr_out	! last byte in string
	mov	0, %o0			! ret code = 0
1:
	subcc	%g3, 1, %g3		! test count
	bgeu,a	%ncc, 0b
	lduba	[%g2+%g4]ASI_USER, %g1	! delay slot, get source byte

	mov	0, %g3			! max number of bytes moved
	ba,pt	%ncc, .copyinstr_out
	  mov	ENAMETOOLONG, %o0	! ret code = ENAMETOOLONG

/*
 * Fault while trying to move from or to user space.
 * Set and return error code.
 */
.copyinstr_err:
	membar	#Sync			! sync error barrier
	stn	%o5, [THREAD_REG + T_LOFAULT]
	ldn	[THREAD_REG + T_COPYOPS], %o4
	brz	%o4, 1f
	nop
	ldn	[%o4 + CP_COPYINSTR], %g1
	jmp	%g1
	nop
1:
	retl
	mov	EFAULT, %o0
.copyinstr_out:
	tst	%o3			! want length?
	bz	%ncc, 2f
	sub	%o2, %g3, %o2		! compute length and store it
	stn	%o2, [%o3]
2:
	membar	#Sync			! sync error barrier
	retl
	stn	%o5, [THREAD_REG + T_LOFAULT]	! stop catching faults
	SET_SIZE(copyinstr)

	ENTRY(copyinstr_noerr)
	mov	%o2, %o4		! save original count

	! maxlength is unsigned so the only error is if it's 0
	brz,a,pn %o2, .copyinstr_noerr_out
	mov	ENAMETOOLONG, %o0

	b	1f
	sub	%o0, %o1, %o0		! o0 gets the difference of src and dst

	!
	! Do a byte by byte loop.
	! We do this instead of a word by word copy because most strings
	! are small and this takes a small number of cache lines.
	!
0:
	stb	%g1, [%o1]		! store byte
	tst	%g1			! null byte?
	bnz	1f
	add	%o1, 1, %o1		! incr dst addr

	ba,pt	%ncc, .copyinstr_noerr_out	! last byte in string
	mov	0, %o0			! ret code = 0
1:
	subcc	%o2, 1, %o2		! test count
	bgeu,a	%ncc, 0b
	lduba	[%o0 + %o1]ASI_USER, %g1	! delay slot, get source byte

	mov	0, %o2			! max number of bytes moved
	b	.copyinstr_noerr_out
	  mov	ENAMETOOLONG, %o0	! ret code = ENAMETOOLONG
.copyinstr_noerr_out:
	tst	%o3			! want length?
	bz	%ncc, 2f
	sub	%o4, %o2, %o4
	stn	%o4, [%o3]
2:
	retl
	nop
	SET_SIZE(copyinstr_noerr)

/*
 * Copy a null terminated string from the kernel
 * address space to the user address space.
 */

	ENTRY(copyoutstr)
	sethi	%hi(.copyoutstr_err), %o5
	ldn	[THREAD_REG + T_LOFAULT], %o4	! catch faults
	or	%o5, %lo(.copyoutstr_err), %o5
	membar	#Sync				! sync error barrier
	stn	%o5, [THREAD_REG + T_LOFAULT]
	mov	%o4, %o5

	brz,a,pn %o2, .copyoutstr_out
	mov	ENAMETOOLONG, %o0

	mov	%o2, %g3		! g3 is the current count
	mov	%o1, %g4		! g4 is the dest addr

	b	1f
	sub	%o0, %o1, %g2		! g2 gets the difference of src and dst

	!
	! Do a byte by byte loop.
	! We do this instead of a word by word copy because most strings
	! are small and this takes a small number of cache lines.
	!
0:
	stba	%g1, [%g4]ASI_USER	! store byte
	tst	%g1
	bnz,pt	%icc, 1f
	add	%g4, 1, %g4		! incr dst addr

	ba,pt	%ncc, .copyoutstr_out	! last byte in string
	mov	0, %o0			! ret code = 0
1:
	subcc	%g3, 1, %g3		! test count
	bgeu,a	%ncc, 0b
	ldub	[%g2 + %g4], %g1	! delay slot, get source byte

	mov	0, %g3			! max number of bytes moved
	ba,pt	%ncc, .copyoutstr_out
	  mov	ENAMETOOLONG, %o0	! ret code = ENAMETOOLONG

/*
 * Fault while trying to move from or to user space.
 * Set and return error code.
 */
.copyoutstr_err:
	membar	#Sync			! sync error barrier
	stn	%o5, [THREAD_REG + T_LOFAULT]
	ldn	[THREAD_REG + T_COPYOPS], %o4
	brz	%o4, 1f
	nop
	ldn	[%o4 + CP_COPYOUTSTR], %g1
	jmp	%g1
	nop
1:
	retl
	mov	EFAULT, %o0
.copyoutstr_out:
	tst	%o3			! want length?
	bz	%ncc, 2f
	sub	%o2, %g3, %o2		! compute length and store it
	stn	%o2, [%o3]
2:
	membar	#Sync			! sync error barrier
	retl
	stn	%o5, [THREAD_REG + T_LOFAULT]	! stop catching faults
	SET_SIZE(copyoutstr)

	ENTRY(copyoutstr_noerr)
	mov	%o2, %o4		! save original count

	brz,a,pn %o2, .copyoutstr_noerr_out
	mov	ENAMETOOLONG, %o0

	b	1f
	sub	%o0, %o1, %o0		! o0 gets the difference of src and dst

	!
	! Do a byte by byte loop.
	! We do this instead of a word by word copy because most strings
	! are small and this takes a small number of cache lines.
	!
0:
	stba	%g1, [%o1]ASI_USER	! store byte
	tst	%g1			! null byte?
	bnz	1f
	add	%o1, 1, %o1		! incr dst addr

	b	.copyoutstr_noerr_out	! last byte in string
	mov	0, %o0			! ret code = 0
1:
	subcc	%o2, 1, %o2		! test count
	bgeu,a	%ncc, 0b
	ldub	[%o0+%o1], %g1	! delay slot, get source byte

	mov	0, %o2			! max number of bytes moved
	b	.copyoutstr_noerr_out
	  mov	ENAMETOOLONG, %o0	! ret code = ENAMETOOLONG
.copyoutstr_noerr_out:
	tst	%o3			! want length?
	bz	%ncc, 2f
	sub	%o4, %o2, %o4
	stn	%o4, [%o3]
2:
	retl
	nop
	SET_SIZE(copyoutstr_noerr)


/*
 * Copy a block of storage.  If the source and target regions overlap,
 * one or both of the regions will be silently corrupted.
 * No fault handler installed (to be called under on_fault())
 */

	ENTRY(ucopy)
	save	%sp, -SA(MINFRAME), %sp ! get another window

	subcc	%g0, %i2, %i3
	add	%i0, %i2, %i0
	bz,pn	%ncc, 5f
	add	%i1, %i2, %i1
	lduba	[%i0 + %i3]ASI_USER, %i4
4:	stba	%i4, [%i1 + %i3]ASI_USER
	inccc	%i3
	bcc,a,pt %ncc, 4b
	lduba  [%i0 + %i3]ASI_USER, %i4
5:
	ret
	restore %g0, 0, %o0		! return (0)

	SET_SIZE(ucopy)

/*
 * Copy a user-land string.  If the source and target regions overlap,
 * one or both of the regions will be silently corrupted.
 * No fault handler installed (to be called under on_fault())
 */

	ENTRY(ucopystr)
	save	%sp, -SA(MINFRAME), %sp ! get another window

	brz	%i2, 5f
	clr	%i5

	lduba	[%i0 + %i5]ASI_USER, %i4
4:	stba	%i4, [%i1 + %i5]ASI_USER
	brz,pn	%i4, 5f
	inc	%i5
	deccc	%i2
	bnz,a,pt %ncc, 4b
	lduba	[%i0 + %i5]ASI_USER, %i4
5:
	brnz,a,pt %i3, 6f
	stn	%i5, [%i3]
6:
	ret
	restore %g0, 0, %o0		! return (0)

	SET_SIZE(ucopystr)
