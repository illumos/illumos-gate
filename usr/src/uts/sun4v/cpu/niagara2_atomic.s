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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if !defined(lint)
#include <sys/asm_linkage.h>

#if defined(_KERNEL)
	/*
	 * Legacy kernel interfaces; they will go away (eventually).
	 */
	ANSI_PRAGMA_WEAK2(cas8,atomic_cas_8,function)
	ANSI_PRAGMA_WEAK2(cas32,atomic_cas_32,function)
	ANSI_PRAGMA_WEAK2(cas64,atomic_cas_64,function)
	ANSI_PRAGMA_WEAK2(caslong,atomic_cas_ulong,function)
	ANSI_PRAGMA_WEAK2(casptr,atomic_cas_ptr,function)
	ANSI_PRAGMA_WEAK2(atomic_and_long,atomic_and_ulong,function)
	ANSI_PRAGMA_WEAK2(atomic_or_long,atomic_or_ulong,function)
	ANSI_PRAGMA_WEAK2(swapl,atomic_swap_32,function)
#else
	/*
	 * Include the definitions for the libc weak aliases.
	 */
#include "../atomic_asm_weak.h"
#endif

#ifdef N2_ERRATUM_181_WORKAROUND
#define	BACKOFF_INIT_VALUE	1
#define	BACKOFF_LIMIT_VALUE	16384
	
#define	ATOMIC_BACKOFF_INIT(val) \
	mov	BACKOFF_INIT_VALUE, val
	
#define	ATOMIC_BACKOFF_BRANCH(cr, backoff, loop) \
	bne,a,pn cr, backoff
	
#define	ATOMIC_BACKOFF_BACKOFF(val, limit, label, retlabel) \
	/* simplistic exponential back-off */ \
	set	BACKOFF_LIMIT_VALUE, limit	; \
	cmp	val, limit	; \
	blu,a,pt %xcc, label/**/_0 ; \
	  sllx	val, 1, val	; \
label/**/_0:			; \
	mov	val, limit	; \
label/**/_1:			; \
	deccc	limit		; \
	bnz,pn	%xcc, label/**/_1 ; \
	nop			; \
	ba,pt	%xcc, retlabel	; \
	nop
#else
#define	ATOMIC_BACKOFF_INIT(val)
	
#define	ATOMIC_BACKOFF_BRANCH(cr, backoff, loop) \
	bne,a,pn cr, loop
	
#define	ATOMIC_BACKOFF_BACKOFF(val, limit, label, retlabel)
#endif


	ENTRY(atomic_inc_8)
	ALTENTRY(atomic_inc_8_nv)
	ALTENTRY(atomic_inc_uchar)
	ALTENTRY(atomic_inc_uchar_nv)
	ba	add_8
	  add	%g0, 1, %o1
	SET_SIZE(atomic_inc_uchar_nv)
	SET_SIZE(atomic_inc_uchar)
	SET_SIZE(atomic_inc_8_nv)
	SET_SIZE(atomic_inc_8)

	ENTRY(atomic_dec_8)
	ALTENTRY(atomic_dec_8_nv)
	ALTENTRY(atomic_dec_uchar)
	ALTENTRY(atomic_dec_uchar_nv)
	ba	add_8
	  sub	%g0, 1, %o1
	SET_SIZE(atomic_dec_uchar_nv)
	SET_SIZE(atomic_dec_uchar)
	SET_SIZE(atomic_dec_8_nv)
	SET_SIZE(atomic_dec_8)

	ENTRY(atomic_add_8)
	ALTENTRY(atomic_add_8_nv)
	ALTENTRY(atomic_add_char)
	ALTENTRY(atomic_add_char_nv)
add_8:
	and	%o0, 0x3, %o4		! %o4 = byte offset, left-to-right
	xor	%o4, 0x3, %g1		! %g1 = byte offset, right-to-left
	sll	%g1, 3, %g1		! %g1 = bit offset, right-to-left
	set	0xff, %o3		! %o3 = mask
	sll	%o3, %g1, %o3		! %o3 = shifted to bit offset
	sll	%o1, %g1, %o1		! %o1 = shifted to bit offset
	and	%o1, %o3, %o1		! %o1 = single byte value
	andn	%o0, 0x3, %o0		! %o0 = word address
	ld	[%o0], %o2		! read old value
1:
	add	%o2, %o1, %o5		! add value to the old value
	and	%o5, %o3, %o5		! clear other bits
	andn	%o2, %o3, %o4		! clear target bits
	or	%o4, %o5, %o5		! insert the new value
	cas	[%o0], %o2, %o5
	cmp	%o2, %o5
	bne,a,pn %icc, 1b
	  mov	%o5, %o2		! %o2 = old value
	add	%o2, %o1, %o5
	and	%o5, %o3, %o5
	retl
	srl	%o5, %g1, %o0		! %o0 = new value
	SET_SIZE(atomic_add_char_nv)
	SET_SIZE(atomic_add_char)
	SET_SIZE(atomic_add_8_nv)
	SET_SIZE(atomic_add_8)

	ENTRY(atomic_inc_16)
	ALTENTRY(atomic_inc_16_nv)
	ALTENTRY(atomic_inc_ushort)
	ALTENTRY(atomic_inc_ushort_nv)
	ba	add_16
	  add	%g0, 1, %o1
	SET_SIZE(atomic_inc_ushort_nv)
	SET_SIZE(atomic_inc_ushort)
	SET_SIZE(atomic_inc_16_nv)
	SET_SIZE(atomic_inc_16)

	ENTRY(atomic_dec_16)
	ALTENTRY(atomic_dec_16_nv)
	ALTENTRY(atomic_dec_ushort)
	ALTENTRY(atomic_dec_ushort_nv)
	ba	add_16
	  sub	%g0, 1, %o1
	SET_SIZE(atomic_dec_ushort_nv)
	SET_SIZE(atomic_dec_ushort)
	SET_SIZE(atomic_dec_16_nv)
	SET_SIZE(atomic_dec_16)

	ENTRY(atomic_add_16)
	ALTENTRY(atomic_add_16_nv)
	ALTENTRY(atomic_add_short)
	ALTENTRY(atomic_add_short_nv)
add_16:
	and	%o0, 0x2, %o4		! %o4 = byte offset, left-to-right
	xor	%o4, 0x2, %g1		! %g1 = byte offset, right-to-left
	sll	%o4, 3, %o4		! %o4 = bit offset, left-to-right
	sll	%g1, 3, %g1		! %g1 = bit offset, right-to-left
	sethi	%hi(0xffff0000), %o3	! %o3 = mask
	srl	%o3, %o4, %o3		! %o3 = shifted to bit offset
	sll	%o1, %g1, %o1		! %o1 = shifted to bit offset
	and	%o1, %o3, %o1		! %o1 = single short value
	andn	%o0, 0x2, %o0		! %o0 = word address
	! if low-order bit is 1, we will properly get an alignment fault here
	ld	[%o0], %o2		! read old value
1:
	add	%o1, %o2, %o5		! add value to the old value
	and	%o5, %o3, %o5		! clear other bits
	andn	%o2, %o3, %o4		! clear target bits
	or	%o4, %o5, %o5		! insert the new value
	cas	[%o0], %o2, %o5
	cmp	%o2, %o5
	bne,a,pn %icc, 1b
	  mov	%o5, %o2		! %o2 = old value
	add	%o1, %o2, %o5
	and	%o5, %o3, %o5
	retl
	srl	%o5, %g1, %o0		! %o0 = new value
	SET_SIZE(atomic_add_short_nv)
	SET_SIZE(atomic_add_short)
	SET_SIZE(atomic_add_16_nv)
	SET_SIZE(atomic_add_16)

	ENTRY(atomic_inc_32)
	ALTENTRY(atomic_inc_32_nv)
	ALTENTRY(atomic_inc_uint)
	ALTENTRY(atomic_inc_uint_nv)
	ba	add_32
	  add	%g0, 1, %o1
	SET_SIZE(atomic_inc_uint_nv)
	SET_SIZE(atomic_inc_uint)
	SET_SIZE(atomic_inc_32_nv)
	SET_SIZE(atomic_inc_32)

	ENTRY(atomic_dec_32)
	ALTENTRY(atomic_dec_32_nv)
	ALTENTRY(atomic_dec_uint)
	ALTENTRY(atomic_dec_uint_nv)
	ba	add_32
	  sub	%g0, 1, %o1
	SET_SIZE(atomic_dec_uint_nv)
	SET_SIZE(atomic_dec_uint)
	SET_SIZE(atomic_dec_32_nv)
	SET_SIZE(atomic_dec_32)


	ENTRY(atomic_add_32)
	ALTENTRY(atomic_add_32_nv)
	ALTENTRY(atomic_add_int)
	ALTENTRY(atomic_add_int_nv)
add_32:
	ATOMIC_BACKOFF_INIT(%o4)
0:
	ld	[%o0], %o2
1:
	add	%o2, %o1, %o3
	cas	[%o0], %o2, %o3
	cmp	%o2, %o3
	ATOMIC_BACKOFF_BRANCH(%icc, 2f, 1b)
	  mov	%o3, %o2
	retl
	add	%o2, %o1, %o0		! return new value
2:	
	ATOMIC_BACKOFF_BACKOFF(%o4, %o5, add32, 0b)
	SET_SIZE(atomic_add_int_nv)
	SET_SIZE(atomic_add_int)
	SET_SIZE(atomic_add_32_nv)
	SET_SIZE(atomic_add_32)

	ENTRY(atomic_inc_64)
	ALTENTRY(atomic_inc_64_nv)
	ALTENTRY(atomic_inc_ulong)
	ALTENTRY(atomic_inc_ulong_nv)
	ba	add_64
	  add	%g0, 1, %o1
	SET_SIZE(atomic_inc_ulong_nv)
	SET_SIZE(atomic_inc_ulong)
	SET_SIZE(atomic_inc_64_nv)
	SET_SIZE(atomic_inc_64)

	ENTRY(atomic_dec_64)
	ALTENTRY(atomic_dec_64_nv)
	ALTENTRY(atomic_dec_ulong)
	ALTENTRY(atomic_dec_ulong_nv)
	ba	add_64
	  sub	%g0, 1, %o1
	SET_SIZE(atomic_dec_ulong_nv)
	SET_SIZE(atomic_dec_ulong)
	SET_SIZE(atomic_dec_64_nv)
	SET_SIZE(atomic_dec_64)

	ENTRY(atomic_add_64)
	ALTENTRY(atomic_add_64_nv)
	ALTENTRY(atomic_add_ptr)
	ALTENTRY(atomic_add_ptr_nv)
	ALTENTRY(atomic_add_long)
	ALTENTRY(atomic_add_long_nv)
add_64:
	ATOMIC_BACKOFF_INIT(%o4)
0:
	ldx	[%o0], %o2
1:
	add	%o2, %o1, %o3
	casx	[%o0], %o2, %o3
	cmp	%o2, %o3
	ATOMIC_BACKOFF_BRANCH(%xcc, 2f, 1b)
	  mov	%o3, %o2
	retl
	add	%o2, %o1, %o0		! return new value

2:	
	ATOMIC_BACKOFF_BACKOFF(%o4, %o5, add64, 0b)
	SET_SIZE(atomic_add_long_nv)
	SET_SIZE(atomic_add_long)
	SET_SIZE(atomic_add_ptr_nv)
	SET_SIZE(atomic_add_ptr)
	SET_SIZE(atomic_add_64_nv)
	SET_SIZE(atomic_add_64)

	ENTRY(atomic_or_8)
	ALTENTRY(atomic_or_8_nv)
	ALTENTRY(atomic_or_uchar)
	ALTENTRY(atomic_or_uchar_nv)
	and	%o0, 0x3, %o4		! %o4 = byte offset, left-to-right
	xor	%o4, 0x3, %g1		! %g1 = byte offset, right-to-left
	sll	%g1, 3, %g1		! %g1 = bit offset, right-to-left
	set	0xff, %o3		! %o3 = mask
	sll	%o3, %g1, %o3		! %o3 = shifted to bit offset
	sll	%o1, %g1, %o1		! %o1 = shifted to bit offset
	and	%o1, %o3, %o1		! %o1 = single byte value
	andn	%o0, 0x3, %o0		! %o0 = word address
	ld	[%o0], %o2		! read old value
1:
	or	%o2, %o1, %o5		! or in the new value
	cas	[%o0], %o2, %o5
	cmp	%o2, %o5
	bne,a,pn %icc, 1b
	  mov	%o5, %o2		! %o2 = old value
	or	%o2, %o1, %o5
	and	%o5, %o3, %o5
	retl
	srl	%o5, %g1, %o0		! %o0 = new value
	SET_SIZE(atomic_or_uchar_nv)
	SET_SIZE(atomic_or_uchar)
	SET_SIZE(atomic_or_8_nv)
	SET_SIZE(atomic_or_8)

	ENTRY(atomic_or_16)
	ALTENTRY(atomic_or_16_nv)
	ALTENTRY(atomic_or_ushort)
	ALTENTRY(atomic_or_ushort_nv)
	and	%o0, 0x2, %o4		! %o4 = byte offset, left-to-right
	xor	%o4, 0x2, %g1		! %g1 = byte offset, right-to-left
	sll	%o4, 3, %o4		! %o4 = bit offset, left-to-right
	sll	%g1, 3, %g1		! %g1 = bit offset, right-to-left
	sethi	%hi(0xffff0000), %o3	! %o3 = mask
	srl	%o3, %o4, %o3		! %o3 = shifted to bit offset
	sll	%o1, %g1, %o1		! %o1 = shifted to bit offset
	and	%o1, %o3, %o1		! %o1 = single short value
	andn	%o0, 0x2, %o0		! %o0 = word address
	! if low-order bit is 1, we will properly get an alignment fault here
	ld	[%o0], %o2		! read old value
1:
	or	%o2, %o1, %o5		! or in the new value
	cas	[%o0], %o2, %o5
	cmp	%o2, %o5
	bne,a,pn %icc, 1b
	  mov	%o5, %o2		! %o2 = old value
	or	%o2, %o1, %o5		! or in the new value
	and	%o5, %o3, %o5
	retl
	srl	%o5, %g1, %o0		! %o0 = new value
	SET_SIZE(atomic_or_ushort_nv)
	SET_SIZE(atomic_or_ushort)
	SET_SIZE(atomic_or_16_nv)
	SET_SIZE(atomic_or_16)

	ENTRY(atomic_or_32)
	ALTENTRY(atomic_or_32_nv)
	ALTENTRY(atomic_or_uint)
	ALTENTRY(atomic_or_uint_nv)
	ATOMIC_BACKOFF_INIT(%o4)
0:
	ld	[%o0], %o2
1:
	or	%o2, %o1, %o3
	cas	[%o0], %o2, %o3
	cmp	%o2, %o3
	ATOMIC_BACKOFF_BRANCH(%icc, 2f, 1b)
	  mov	%o3, %o2
	retl
	or	%o2, %o1, %o0		! return new value

2:	
	ATOMIC_BACKOFF_BACKOFF(%o4, %o5, or32, 0b)
	SET_SIZE(atomic_or_uint_nv)
	SET_SIZE(atomic_or_uint)
	SET_SIZE(atomic_or_32_nv)
	SET_SIZE(atomic_or_32)

	ENTRY(atomic_or_64)
	ALTENTRY(atomic_or_64_nv)
	ALTENTRY(atomic_or_ulong)
	ALTENTRY(atomic_or_ulong_nv)
	ATOMIC_BACKOFF_INIT(%o4)
0:
	ldx	[%o0], %o2
1:
	or	%o2, %o1, %o3
	casx	[%o0], %o2, %o3
	cmp	%o2, %o3
	ATOMIC_BACKOFF_BRANCH(%xcc, 2f, 1b)
	  mov	%o3, %o2
	retl
	or	%o2, %o1, %o0		! return new value
	
2:	
	ATOMIC_BACKOFF_BACKOFF(%o4, %o5, or64, 0b)
	SET_SIZE(atomic_or_ulong_nv)
	SET_SIZE(atomic_or_ulong)
	SET_SIZE(atomic_or_64_nv)
	SET_SIZE(atomic_or_64)

	ENTRY(atomic_and_8)
	ALTENTRY(atomic_and_8_nv)
	ALTENTRY(atomic_and_uchar)
	ALTENTRY(atomic_and_uchar_nv)
	and	%o0, 0x3, %o4		! %o4 = byte offset, left-to-right
	xor	%o4, 0x3, %g1		! %g1 = byte offset, right-to-left
	sll	%g1, 3, %g1		! %g1 = bit offset, right-to-left
	set	0xff, %o3		! %o3 = mask
	sll	%o3, %g1, %o3		! %o3 = shifted to bit offset
	sll	%o1, %g1, %o1		! %o1 = shifted to bit offset
	orn	%o1, %o3, %o1		! all ones in other bytes
	andn	%o0, 0x3, %o0		! %o0 = word address
	ld	[%o0], %o2		! read old value
1:
	and	%o2, %o1, %o5		! and in the new value
	cas	[%o0], %o2, %o5
	cmp	%o2, %o5
	bne,a,pn %icc, 1b
	  mov	%o5, %o2		! %o2 = old value
	and	%o2, %o1, %o5
	and	%o5, %o3, %o5
	retl
	srl	%o5, %g1, %o0		! %o0 = new value
	SET_SIZE(atomic_and_uchar_nv)
	SET_SIZE(atomic_and_uchar)
	SET_SIZE(atomic_and_8_nv)
	SET_SIZE(atomic_and_8)

	ENTRY(atomic_and_16)
	ALTENTRY(atomic_and_16_nv)
	ALTENTRY(atomic_and_ushort)
	ALTENTRY(atomic_and_ushort_nv)
	and	%o0, 0x2, %o4		! %o4 = byte offset, left-to-right
	xor	%o4, 0x2, %g1		! %g1 = byte offset, right-to-left
	sll	%o4, 3, %o4		! %o4 = bit offset, left-to-right
	sll	%g1, 3, %g1		! %g1 = bit offset, right-to-left
	sethi	%hi(0xffff0000), %o3	! %o3 = mask
	srl	%o3, %o4, %o3		! %o3 = shifted to bit offset
	sll	%o1, %g1, %o1		! %o1 = shifted to bit offset
	orn	%o1, %o3, %o1		! all ones in the other half
	andn	%o0, 0x2, %o0		! %o0 = word address
	! if low-order bit is 1, we will properly get an alignment fault here
	ld	[%o0], %o2		! read old value
1:
	and	%o2, %o1, %o5		! and in the new value
	cas	[%o0], %o2, %o5
	cmp	%o2, %o5
	bne,a,pn %icc, 1b
	  mov	%o5, %o2		! %o2 = old value
	and	%o2, %o1, %o5
	and	%o5, %o3, %o5
	retl
	srl	%o5, %g1, %o0		! %o0 = new value
	SET_SIZE(atomic_and_ushort_nv)
	SET_SIZE(atomic_and_ushort)
	SET_SIZE(atomic_and_16_nv)
	SET_SIZE(atomic_and_16)

	ENTRY(atomic_and_32)
	ALTENTRY(atomic_and_32_nv)
	ALTENTRY(atomic_and_uint)
	ALTENTRY(atomic_and_uint_nv)
	ATOMIC_BACKOFF_INIT(%o4)
0:
	ld	[%o0], %o2
1:
	and	%o2, %o1, %o3
	cas	[%o0], %o2, %o3
	cmp	%o2, %o3
	ATOMIC_BACKOFF_BRANCH(%icc, 2f, 1b)
	  mov	%o3, %o2
	retl
	and	%o2, %o1, %o0		! return new value

2:	
	ATOMIC_BACKOFF_BACKOFF(%o4, %o5, and32, 0b)
	SET_SIZE(atomic_and_uint_nv)
	SET_SIZE(atomic_and_uint)
	SET_SIZE(atomic_and_32_nv)
	SET_SIZE(atomic_and_32)

	ENTRY(atomic_and_64)
	ALTENTRY(atomic_and_64_nv)
	ALTENTRY(atomic_and_ulong)
	ALTENTRY(atomic_and_ulong_nv)
	ATOMIC_BACKOFF_INIT(%o4)
0:
	ldx	[%o0], %o2
1:
	and	%o2, %o1, %o3
	casx	[%o0], %o2, %o3
	cmp	%o2, %o3
	ATOMIC_BACKOFF_BRANCH(%xcc, 2f, 1b)
	  mov	%o3, %o2
	retl
	and	%o2, %o1, %o0		! return new value

2:	
	ATOMIC_BACKOFF_BACKOFF(%o4, %o5, and64, 0b)
	SET_SIZE(atomic_and_ulong_nv)
	SET_SIZE(atomic_and_ulong)
	SET_SIZE(atomic_and_64_nv)
	SET_SIZE(atomic_and_64)

	ENTRY(atomic_cas_8)
	ALTENTRY(atomic_cas_uchar)
	and	%o0, 0x3, %o4		! %o4 = byte offset, left-to-right
	xor	%o4, 0x3, %g1		! %g1 = byte offset, right-to-left
	sll	%g1, 3, %g1		! %g1 = bit offset, right-to-left
	set	0xff, %o3		! %o3 = mask
	sll	%o3, %g1, %o3		! %o3 = shifted to bit offset
	sll	%o1, %g1, %o1		! %o1 = shifted to bit offset
	and	%o1, %o3, %o1		! %o1 = single byte value
	sll	%o2, %g1, %o2		! %o2 = shifted to bit offset
	and	%o2, %o3, %o2		! %o2 = single byte value
	andn	%o0, 0x3, %o0		! %o0 = word address
	ld	[%o0], %o4		! read old value
1:
	andn	%o4, %o3, %o4		! clear target bits
	or	%o4, %o2, %o5		! insert the new value
	or	%o4, %o1, %o4		! insert the comparison value
	cas	[%o0], %o4, %o5
	cmp	%o4, %o5		! did we succeed?
	be,pt	%icc, 2f
	  and	%o5, %o3, %o4		! isolate the old value
	cmp	%o1, %o4		! should we have succeeded?
	be,a,pt	%icc, 1b		! yes, try again
	  mov	%o5, %o4		! %o4 = old value
2:
	retl
	srl	%o4, %g1, %o0		! %o0 = old value
	SET_SIZE(atomic_cas_uchar)
	SET_SIZE(atomic_cas_8)

	ENTRY(atomic_cas_16)
	ALTENTRY(atomic_cas_ushort)
	and	%o0, 0x2, %o4		! %o4 = byte offset, left-to-right
	xor	%o4, 0x2, %g1		! %g1 = byte offset, right-to-left
	sll	%o4, 3, %o4		! %o4 = bit offset, left-to-right
	sll	%g1, 3, %g1		! %g1 = bit offset, right-to-left
	sethi	%hi(0xffff0000), %o3	! %o3 = mask
	srl	%o3, %o4, %o3		! %o3 = shifted to bit offset
	sll	%o1, %g1, %o1		! %o1 = shifted to bit offset
	and	%o1, %o3, %o1		! %o1 = single short value
	sll	%o2, %g1, %o2		! %o2 = shifted to bit offset
	and	%o2, %o3, %o2		! %o2 = single short value
	andn	%o0, 0x2, %o0		! %o0 = word address
	! if low-order bit is 1, we will properly get an alignment fault here
	ld	[%o0], %o4		! read old value
1:
	andn	%o4, %o3, %o4		! clear target bits
	or	%o4, %o2, %o5		! insert the new value
	or	%o4, %o1, %o4		! insert the comparison value
	cas	[%o0], %o4, %o5
	cmp	%o4, %o5		! did we succeed?
	be,pt	%icc, 2f
	  and	%o5, %o3, %o4		! isolate the old value
	cmp	%o1, %o4		! should we have succeeded?
	be,a,pt	%icc, 1b		! yes, try again
	  mov	%o5, %o4		! %o4 = old value
2:
	retl
	srl	%o4, %g1, %o0		! %o0 = old value
	SET_SIZE(atomic_cas_ushort)
	SET_SIZE(atomic_cas_16)

	ENTRY(atomic_cas_32)
	ALTENTRY(atomic_cas_uint)
	cas	[%o0], %o1, %o2
	retl
	mov	%o2, %o0
	SET_SIZE(atomic_cas_uint)
	SET_SIZE(atomic_cas_32)

	ENTRY(atomic_cas_64)
	ALTENTRY(atomic_cas_ptr)
	ALTENTRY(atomic_cas_ulong)
	casx	[%o0], %o1, %o2
	retl
	mov	%o2, %o0
	SET_SIZE(atomic_cas_ulong)
	SET_SIZE(atomic_cas_ptr)
	SET_SIZE(atomic_cas_64)

	ENTRY(atomic_swap_8)
	ALTENTRY(atomic_swap_uchar)
	and	%o0, 0x3, %o4		! %o4 = byte offset, left-to-right
	xor	%o4, 0x3, %g1		! %g1 = byte offset, right-to-left
	sll	%g1, 3, %g1		! %g1 = bit offset, right-to-left
	set	0xff, %o3		! %o3 = mask
	sll	%o3, %g1, %o3		! %o3 = shifted to bit offset
	sll	%o1, %g1, %o1		! %o1 = shifted to bit offset
	and	%o1, %o3, %o1		! %o1 = single byte value
	andn	%o0, 0x3, %o0		! %o0 = word address
	ld	[%o0], %o2		! read old value
1:
	andn	%o2, %o3, %o5		! clear target bits
	or	%o5, %o1, %o5		! insert the new value
	cas	[%o0], %o2, %o5
	cmp	%o2, %o5
	bne,a,pn %icc, 1b
	  mov	%o5, %o2		! %o2 = old value
	and	%o5, %o3, %o5
	retl
	srl	%o5, %g1, %o0		! %o0 = old value
	SET_SIZE(atomic_swap_uchar)
	SET_SIZE(atomic_swap_8)

	ENTRY(atomic_swap_16)
	ALTENTRY(atomic_swap_ushort)
	and	%o0, 0x2, %o4		! %o4 = byte offset, left-to-right
	xor	%o4, 0x2, %g1		! %g1 = byte offset, right-to-left
	sll	%o4, 3, %o4		! %o4 = bit offset, left-to-right
	sll	%g1, 3, %g1		! %g1 = bit offset, right-to-left
	sethi	%hi(0xffff0000), %o3	! %o3 = mask
	srl	%o3, %o4, %o3		! %o3 = shifted to bit offset
	sll	%o1, %g1, %o1		! %o1 = shifted to bit offset
	and	%o1, %o3, %o1		! %o1 = single short value
	andn	%o0, 0x2, %o0		! %o0 = word address
	! if low-order bit is 1, we will properly get an alignment fault here
	ld	[%o0], %o2		! read old value
1:
	andn	%o2, %o3, %o5		! clear target bits
	or	%o5, %o1, %o5		! insert the new value
	cas	[%o0], %o2, %o5
	cmp	%o2, %o5
	bne,a,pn %icc, 1b
	  mov	%o5, %o2		! %o2 = old value
	and	%o5, %o3, %o5
	retl
	srl	%o5, %g1, %o0		! %o0 = old value
	SET_SIZE(atomic_swap_ushort)
	SET_SIZE(atomic_swap_16)

	ENTRY(atomic_swap_32)
	ALTENTRY(atomic_swap_uint)
	ATOMIC_BACKOFF_INIT(%o4)
0:
	ld	[%o0], %o2
1:
	mov	%o1, %o3
	cas	[%o0], %o2, %o3
	cmp	%o2, %o3
	ATOMIC_BACKOFF_BRANCH(%icc, 2f, 1b)
	  mov	%o3, %o2
	retl
	mov	%o3, %o0
2:	
	ATOMIC_BACKOFF_BACKOFF(%o4, %o5, swap32, 0b)
	SET_SIZE(atomic_swap_uint)
	SET_SIZE(atomic_swap_32)

	ENTRY(atomic_swap_64)
	ALTENTRY(atomic_swap_ptr)
	ALTENTRY(atomic_swap_ulong)
	ATOMIC_BACKOFF_INIT(%o4)
0:
	ldx	[%o0], %o2
1:
	mov	%o1, %o3
	casx	[%o0], %o2, %o3
	cmp	%o2, %o3
	ATOMIC_BACKOFF_BRANCH(%xcc, 2f, 1b)
	  mov	%o3, %o2
	retl
	mov	%o3, %o0
2:	
	ATOMIC_BACKOFF_BACKOFF(%o4, %o5, swap64, 0b)
	SET_SIZE(atomic_swap_ulong)
	SET_SIZE(atomic_swap_ptr)
	SET_SIZE(atomic_swap_64)

	ENTRY(atomic_set_long_excl)
	ATOMIC_BACKOFF_INIT(%o5)
	mov	1, %o3
	slln	%o3, %o1, %o3
0:
	ldn	[%o0], %o2
1:
	andcc	%o2, %o3, %g0		! test if the bit is set
	bnz,a,pn %ncc, 2f		! if so, then fail out
	  mov	-1, %o0
	or	%o2, %o3, %o4		! set the bit, and try to commit it
	casn	[%o0], %o2, %o4
	cmp	%o2, %o4
	ATOMIC_BACKOFF_BRANCH(%ncc, 5f, 1b)
	  mov	%o4, %o2
	mov	%g0, %o0
2:
	retl
	nop
5:	
	ATOMIC_BACKOFF_BACKOFF(%o5, %g1, setlongexcl, 0b)
	SET_SIZE(atomic_set_long_excl)

	ENTRY(atomic_clear_long_excl)
	ATOMIC_BACKOFF_INIT(%o5)
	mov	1, %o3
	slln	%o3, %o1, %o3
0:
	ldn	[%o0], %o2
1:
	andncc	%o3, %o2, %g0		! test if the bit is clear
	bnz,a,pn %ncc, 2f		! if so, then fail out
	  mov	-1, %o0
	andn	%o2, %o3, %o4		! clear the bit, and try to commit it
	casn	[%o0], %o2, %o4
	cmp	%o2, %o4
	ATOMIC_BACKOFF_BRANCH(%ncc, 5f, 1b)
	  mov	%o4, %o2
	mov	%g0, %o0
2:
	retl
	nop
5:	
	ATOMIC_BACKOFF_BACKOFF(%o5, %g1, clrlongexcl, 0b)
	SET_SIZE(atomic_clear_long_excl)

#if !defined(_KERNEL)

	ENTRY(membar_enter)
	membar	#StoreLoad|#StoreStore
	retl
	nop
	SET_SIZE(membar_enter)

	ENTRY(membar_exit)
	membar	#LoadStore|#StoreStore
	retl
	nop
	SET_SIZE(membar_exit)

	ENTRY(membar_producer)
	membar	#StoreStore
	retl
	nop
	SET_SIZE(membar_producer)

	ENTRY(membar_consumer)
	membar	#LoadLoad
	retl
	nop
	SET_SIZE(membar_consumer)

#endif	/* !_KERNEL */
#endif	/* lint */
