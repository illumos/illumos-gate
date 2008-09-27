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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/asm_linkage.h>

#ifndef chkpt 
#define chkpt(FAILADDR) btrans.FAILADDR:	\
		.word 0x30500000|((FAILADDR-btrans.FAILADDR)>>2)
#endif

#ifndef commit
#define commit	.word 0xbdf00000
#endif

#if defined(lint)

/* ARGSUSED */
uint8_t
cas8(uint8_t *target, uint8_t value1, uint8_t value2)
{ return (0); }

/* ARGSUSED */
uint32_t
cas32(uint32_t *target, uint32_t value1, uint32_t value2)
{ return (0); }

/* ARGSUSED */
uint64_t
cas64(uint64_t *target, uint64_t value1, uint64_t value2)
{ return (0); }

/* ARGSUSED */
ulong_t
caslong(ulong_t *target, ulong_t value1, ulong_t value2)
{ return (0); }

/* ARGSUSED */
void *
casptr(void *ptr1, void *ptr2, void *ptr3)
{ return (0); }

/* ARGSUSED */
void
atomic_and_long(ulong_t *target, ulong_t value)
{}

/* ARGSUSED */
void
atomic_or_long(ulong_t *target, ulong_t value)
{}

/* ARGSUSED */
void
atomic_inc_8(volatile uint8_t *target)
{}

/* ARGSUSED */
void
atomic_inc_uchar(volatile uchar_t *target)
{}

/* ARGSUSED */
void
atomic_inc_16(volatile uint16_t *target)
{}

/* ARGSUSED */
void
atomic_inc_ushort(volatile ushort_t *target)
{}

/* ARGSUSED */
void
atomic_inc_32(volatile uint32_t *target)
{}

/* ARGSUSED */
void
atomic_inc_uint(volatile uint_t *target)
{}

/* ARGSUSED */
void
atomic_inc_ulong(volatile ulong_t *target)
{}

/* ARGSUSED */
void
atomic_inc_64(volatile uint64_t *target)
{}

/* ARGSUSED */
void
atomic_dec_8(volatile uint8_t *target)
{}

/* ARGSUSED */
void
atomic_dec_uchar(volatile uchar_t *target)
{}

/* ARGSUSED */
void
atomic_dec_16(volatile uint16_t *target)
{}

/* ARGSUSED */
void
atomic_dec_ushort(volatile ushort_t *target)
{}

/* ARGSUSED */
void
atomic_dec_32(volatile uint32_t *target)
{}

/* ARGSUSED */
void
atomic_dec_uint(volatile uint_t *target)
{}

/* ARGSUSED */
void
atomic_dec_ulong(volatile ulong_t *target)
{}

/* ARGSUSED */
void
atomic_dec_64(volatile uint64_t *target)
{}

/* ARGSUSED */
void
atomic_add_8(volatile uint8_t *target, int8_t value)
{}

/* ARGSUSED */
void
atomic_add_char(volatile uchar_t *target, signed char value)
{}

/* ARGSUSED */
void
atomic_add_16(volatile uint16_t *target, int16_t delta)
{}

/* ARGSUSED */
void
atomic_add_ushort(volatile ushort_t *target, short value)
{}

/* ARGSUSED */
void
atomic_add_32(volatile uint32_t *target, int32_t delta)
{}

/* ARGSUSED */
void
atomic_add_ptr(volatile void *target, ssize_t value)
{}

/* ARGSUSED */
void
atomic_add_long(volatile ulong_t *target, long delta)
{}

/* ARGSUSED */
void
atomic_add_64(volatile uint64_t *target, int64_t delta)
{}

/* ARGSUSED */
void
atomic_or_8(volatile uint8_t *target, uint8_t bits)
{}

/* ARGSUSED */
void
atomic_or_uchar(volatile uchar_t *target, uchar_t bits)
{}

/* ARGSUSED */
void
atomic_or_16(volatile uint16_t *target, uint16_t bits)
{}

/* ARGSUSED */
void
atomic_or_ushort(volatile ushort_t *target, ushort_t bits)
{}

/* ARGSUSED */
void
atomic_or_32(volatile uint32_t *target, uint32_t bits)
{}

/* ARGSUSED */
void
atomic_or_uint(volatile uint_t *target, uint_t bits)
{}

/* ARGSUSED */
void
atomic_or_ulong(volatile ulong_t *target, ulong_t bits)
{}

/* ARGSUSED */
void
atomic_or_64(volatile uint64_t *target, uint64_t bits)
{}

/* ARGSUSED */
void
atomic_and_8(volatile uint8_t *target, uint8_t bits)
{}

/* ARGSUSED */
void
atomic_and_uchar(volatile uchar_t *target, uchar_t bits)
{}

/* ARGSUSED */
void
atomic_and_16(volatile uint16_t *target, uint16_t bits)
{}

/* ARGSUSED */
void
atomic_and_ushort(volatile ushort_t *target, ushort_t bits)
{}

/* ARGSUSED */
void
atomic_and_32(volatile uint32_t *target, uint32_t bits)
{}

/* ARGSUSED */
void
atomic_and_uint(volatile uint_t *target, uint_t bits)
{}

/* ARGSUSED */
void
atomic_and_ulong(volatile ulong_t *target, ulong_t bits)
{}

/* ARGSUSED */
void
atomic_and_64(volatile uint64_t *target, uint64_t bits)
{}

/* ARGSUSED */
uint8_t
atomic_inc_8_nv(volatile uint8_t *target)
{ return (0); }

/* ARGSUSED */
uchar_t
atomic_inc_uchar_nv(volatile uchar_t *target)
{ return (0); }

/* ARGSUSED */
uint16_t
atomic_inc_16_nv(volatile uint16_t *target)
{ return (0); }

/* ARGSUSED */
ushort_t
atomic_inc_ushort_nv(volatile ushort_t *target)
{ return (0); }

/* ARGSUSED */
uint32_t
atomic_inc_32_nv(volatile uint32_t *target)
{ return (0); }

/* ARGSUSED */
uint_t
atomic_inc_uint_nv(volatile uint_t *target)
{ return (0); }

/* ARGSUSED */
ulong_t
atomic_inc_ulong_nv(volatile ulong_t *target)
{ return (0); }

/* ARGSUSED */
uint64_t
atomic_inc_64_nv(volatile uint64_t *target)
{ return (0); }

/* ARGSUSED */
uint8_t
atomic_dec_8_nv(volatile uint8_t *target)
{ return (0); }

/* ARGSUSED */
uchar_t
atomic_dec_uchar_nv(volatile uchar_t *target)
{ return (0); }

/* ARGSUSED */
uint16_t
atomic_dec_16_nv(volatile uint16_t *target)
{ return (0); }

/* ARGSUSED */
ushort_t
atomic_dec_ushort_nv(volatile ushort_t *target)
{ return (0); }

/* ARGSUSED */
uint32_t
atomic_dec_32_nv(volatile uint32_t *target)
{ return (0); }

/* ARGSUSED */
uint_t
atomic_dec_uint_nv(volatile uint_t *target)
{ return (0); }

/* ARGSUSED */
ulong_t
atomic_dec_ulong_nv(volatile ulong_t *target)
{ return (0); }

/* ARGSUSED */
uint64_t
atomic_dec_64_nv(volatile uint64_t *target)
{ return (0); }

/* ARGSUSED */
uint8_t
atomic_add_8_nv(volatile uint8_t *target, int8_t value)
{ return (0); }

/* ARGSUSED */
uchar_t
atomic_add_char_nv(volatile uchar_t *target, signed char value)
{ return (0); }

/* ARGSUSED */
uint16_t
atomic_add_16_nv(volatile uint16_t *target, int16_t delta)
{ return (0); }

/* ARGSUSED */
ushort_t
atomic_add_short_nv(volatile ushort_t *target, short value)
{ return (0); }

/* ARGSUSED */
uint32_t
atomic_add_32_nv(volatile uint32_t *target, int32_t delta)
{ return (0); }

/* ARGSUSED */
uint_t
atomic_add_int_nv(volatile uint_t *target, int delta)
{ return (0); }

/* ARGSUSED */
void *
atomic_add_ptr_nv(volatile void *target, ssize_t value)
{ return (0); }

/* ARGSUSED */
ulong_t
atomic_add_long_nv(volatile ulong_t *target, long delta)
{ return (0); }

/* ARGSUSED */
uint64_t
atomic_add_64_nv(volatile uint64_t *target, int64_t delta)
{ return (0); }

/* ARGSUSED */
uint8_t
atomic_or_8_nv(volatile uint8_t *target, uint8_t value)
{ return (0); }

/* ARGSUSED */
uchar_t
atomic_or_uchar_nv(volatile uchar_t *target, uchar_t value)
{ return (0); }

/* ARGSUSED */
uint16_t
atomic_or_16_nv(volatile uint16_t *target, uint16_t value)
{ return (0); }

/* ARGSUSED */
ushort_t
atomic_or_ushort_nv(volatile ushort_t *target, ushort_t value)
{ return (0); }

/* ARGSUSED */
uint32_t
atomic_or_32_nv(volatile uint32_t *target, uint32_t value)
{ return (0); }

/* ARGSUSED */
uint_t
atomic_or_uint_nv(volatile uint_t *target, uint_t value)
{ return (0); }

/* ARGSUSED */
ulong_t
atomic_or_ulong_nv(volatile ulong_t *target, ulong_t value)
{ return (0); }

/* ARGSUSED */
uint64_t
atomic_or_64_nv(volatile uint64_t *target, uint64_t value)
{ return (0); }

/* ARGSUSED */
uint8_t
atomic_and_8_nv(volatile uint8_t *target, uint8_t value)
{ return (0); }

/* ARGSUSED */
uchar_t
atomic_and_uchar_nv(volatile uchar_t *target, uchar_t value)
{ return (0); }

/* ARGSUSED */
uint16_t
atomic_and_16_nv(volatile uint16_t *target, uint16_t value)
{ return (0); }

/* ARGSUSED */
ushort_t
atomic_and_ushort_nv(volatile ushort_t *target, ushort_t value)
{ return (0); }

/* ARGSUSED */
uint32_t
atomic_and_32_nv(volatile uint32_t *target, uint32_t value)
{ return (0); }

/* ARGSUSED */
uint_t
atomic_and_uint_nv(volatile uint_t *target, uint_t value)
{ return (0); }

/* ARGSUSED */
ulong_t
atomic_and_ulong_nv(volatile ulong_t *target, ulong_t value)
{ return (0); }

/* ARGSUSED */
uint64_t
atomic_and_64_nv(volatile uint64_t *target, uint64_t value)
{ return (0); }

/* ARGSUSED */
uint8_t
atomic_cas_8(volatile uint8_t *target, uint8_t cmp, uint8_t new)
{ return (0); }

/* ARGSUSED */
uchar_t
atomic_cas_uchar(volatile uchar_t *target, uchar_t cmp, uchar_t new)
{ return (0); }

/* ARGSUSED */
uint16_t
atomic_cas_16(volatile uint16_t *target, uint16_t cmp, uint16_t new)
{ return (0); }

/* ARGSUSED */
ushort_t
atomic_cas_ushort(volatile ushort_t *target, ushort_t cmp, ushort_t new)
{ return (0); }

/* ARGSUSED */
uint32_t
atomic_cas_32(volatile uint32_t *target, uint32_t cmp, uint32_t new)
{ return (0); }

/* ARGSUSED */
uint_t
atomic_cas_uint(volatile uint_t *target, uint_t cmp, uint_t new)
{ return (0); }

/* ARGSUSED */
ulong_t
atomic_cas_ulong(volatile ulong_t *target, ulong_t cmp, ulong_t new)
{ return (0); }

/* ARGSUSED */
uint64_t
atomic_cas_uint64(volatile uint64_t *target, ulong_t cmp, uint64_t new)
{ return (0); }

/* ARGSUSED */
void *
atomic_cas_ptr(volatile void *target, void *cmp, void *new)
{ return (0); }

/* ARGSUSED */
uint8_t
atomic_swap_8(volatile uint8_t *target, uint8_t new)
{ return (0); }

/* ARGSUSED */
uchar_t
atomic_swap_char(volatile uchar_t *target, uchar_t new)
{ return (0); }

/* ARGSUSED */
uint16_t
atomic_swap_16(volatile uint16_t *target, uint16_t new)
{ return (0); }

/* ARGSUSED */
ushort_t
atomic_swap_ushort(volatile ushort_t *target, ushort_t new)
{ return (0); }

/* ARGSUSED */
uint32_t
atomic_swap_32(volatile uint32_t *target, uint32_t new)
{ return (0); }

/* ARGSUSED */
uint_t
atomic_swap_uint(volatile uint_t *target, uint_t new)
{ return (0); }

/* ARGSUSED */
uint64_t
atomic_swap_64(volatile uint64_t *target, uint64_t new)
{ return (0); }

/* ARGSUSED */
void *
atomic_swap_ptr(volatile void *target, void *new)
{ return (0); }

/* ARGSUSED */
ulong_t
atomic_swap_ulong(volatile ulong_t *target, ulong_t new)
{ return (0); }

/* ARGSUSED */
int
atomic_set_long_excl(volatile ulong_t *target, uint_t value)
{ return (0); }

/* ARGSUSED */
int
atomic_clear_long_excl(volatile ulong_t *target, uint_t value)
{ return (0); }

#else	/* lint */

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
add_8:	chkpt (add08_tmfail)		! Enter transaction
	ldub	[%o0], %o2              ! read old value
	add     %o2, %o1, %o3           ! add value to the old value
	stub	%o3, [%o0]		! Store back
	commit				! Commit transaction
	retl
	 mov	%o3, %o0		! Retrun result for free in delay slot
add08_tmfail:
	and     %o0, 0x3, %o4           ! %o4 = byte offset, left-to-right
	xor     %o4, 0x3, %g1           ! %g1 = byte offset, right-to-left
	sll     %g1, 3, %g1             ! %g1 = bit offset, right-to-left
	set     0xff, %o3               ! %o3 = mask
	sll     %o3, %g1, %o3           ! %o3 = shifted to bit offset
	sll     %o1, %g1, %o1           ! %o1 = shifted to bit offset
	and     %o1, %o3, %o1           ! %o1 = single byte value
	andn    %o0, 0x3, %o0           ! %o0 = word address
	ld      [%o0], %o2              ! read old value
1:
	add     %o2, %o1, %o5           ! add value to the old value
	and     %o5, %o3, %o5           ! clear other bits
	andn    %o2, %o3, %o4           ! clear target bits
	or      %o4, %o5, %o5           ! insert the new value
	cas     [%o0], %o2, %o5
	cmp     %o2, %o5
	bne,a,pn %icc, 1b
	  mov   %o5, %o2                ! %o2 = old value
	add     %o2, %o1, %o5
	and     %o5, %o3, %o5
	retl
	srl     %o5, %g1, %o0           ! %o0 = new value
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
add_16:	chkpt (add16_tmfail)		! Enter transaction
	lduh	[%o0], %o2              ! read old value
	add     %o2, %o1, %o3           ! add value to the old value
	stuh	%o3, [%o0]		! Store back
	commit				! Commit transaction
	retl
	 mov	%o3, %o0		! Retrun result for free in delay slot
add16_tmfail:
	and     %o0, 0x2, %o4           ! %o4 = byte offset, left-to-right
	xor     %o4, 0x2, %g1           ! %g1 = byte offset, right-to-left
	sll     %o4, 3, %o4             ! %o4 = bit offset, left-to-right
	sll     %g1, 3, %g1             ! %g1 = bit offset, right-to-left
	sethi   %hi(0xffff0000), %o3    ! %o3 = mask
	srl     %o3, %o4, %o3           ! %o3 = shifted to bit offset
	sll     %o1, %g1, %o1           ! %o1 = shifted to bit offset
	and     %o1, %o3, %o1           ! %o1 = single short value
	andn    %o0, 0x2, %o0           ! %o0 = word address
	! if low-order bit is 1, we will properly get an alignment fault here
	ld      [%o0], %o2              ! read old value
1:
	add     %o1, %o2, %o5           ! add value to the old value
	and     %o5, %o3, %o5           ! clear other bits
	andn    %o2, %o3, %o4           ! clear target bits
	or      %o4, %o5, %o5           ! insert the new value
	cas     [%o0], %o2, %o5
	cmp     %o2, %o5
	bne,a,pn %icc, 1b
	  mov   %o5, %o2                ! %o2 = old value
	add     %o1, %o2, %o5
	and     %o5, %o3, %o5
	retl
	srl     %o5, %g1, %o0           ! %o0 = new value
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
add_32: chkpt (add32_tmfail)		! Enter transaction
	lduw    [%o0], %o2              ! read old value
	add     %o2, %o1, %o3           ! add value to the old value
	stuw    %o3, [%o0]              ! Store back
	commit                          ! Commit transaction
	retl
	 mov    %o3, %o0                ! Retrun result for free in delay slot
add32_tmfail:
	ld	[%o0], %o2
1:
	add	%o2, %o1, %o3
	cas	[%o0], %o2, %o3
	cmp	%o2, %o3
	bne,a,pn %icc, 1b
	  mov	%o3, %o2
	retl
	add	%o2, %o1, %o0		! return new value
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
add_64: chkpt (add64_tmfail)		! Enter transaction
	ldx     [%o0], %o2              ! read old value
	add     %o2, %o1, %o3           ! add value to the old value
	stx     %o3, [%o0]              ! Store back
	commit                          ! Commit transaction
	retl
	 mov    %o3, %o0                ! Retrun result for free in delay slot
add64_tmfail:
	ldx     [%o0], %o2
1:
	add     %o2, %o1, %o3
	casx    [%o0], %o2, %o3
	cmp     %o2, %o3
	bne,a,pn %xcc, 1b
	  mov   %o3, %o2
	retl
	add     %o2, %o1, %o0           ! return new value
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
	chkpt (or08_tmfail)	
	ldub	[%o0], %o2     
	or	%o2, %o1, %o3 
	stub	%o3, [%o0]
	commit		
	retl
	 mov	%o3, %o0
or08_tmfail:
	and     %o0, 0x3, %o4           ! %o4 = byte offset, left-to-right
	xor     %o4, 0x3, %g1           ! %g1 = byte offset, right-to-left
	sll     %g1, 3, %g1             ! %g1 = bit offset, right-to-left
	set     0xff, %o3               ! %o3 = mask
	sll     %o3, %g1, %o3           ! %o3 = shifted to bit offset
	sll     %o1, %g1, %o1           ! %o1 = shifted to bit offset
	and     %o1, %o3, %o1           ! %o1 = single byte value
	andn    %o0, 0x3, %o0           ! %o0 = word address
	ld      [%o0], %o2              ! read old value
1:
	or      %o2, %o1, %o5           ! or in the new value
	cas     [%o0], %o2, %o5
	cmp     %o2, %o5
	bne,a,pn %icc, 1b
	  mov   %o5, %o2                ! %o2 = old value
	or      %o2, %o1, %o5
	and     %o5, %o3, %o5
	retl
	srl     %o5, %g1, %o0           ! %o0 = new value
	SET_SIZE(atomic_or_uchar_nv)
	SET_SIZE(atomic_or_uchar)
	SET_SIZE(atomic_or_8_nv)
	SET_SIZE(atomic_or_8)



	ENTRY(atomic_or_16)
	ALTENTRY(atomic_or_16_nv)
	ALTENTRY(atomic_or_ushort)
	ALTENTRY(atomic_or_ushort_nv)
	chkpt (or16_tmfail)	
	lduh	[%o0], %o2     
	or	%o2, %o1, %o3 
	stuh	%o3, [%o0]
	commit		
	retl
	 mov	%o3, %o0
or16_tmfail:
	and     %o0, 0x2, %o4           ! %o4 = byte offset, left-to-right
	xor     %o4, 0x2, %g1           ! %g1 = byte offset, right-to-left
	sll     %o4, 3, %o4             ! %o4 = bit offset, left-to-right
	sll     %g1, 3, %g1             ! %g1 = bit offset, right-to-left
	sethi   %hi(0xffff0000), %o3    ! %o3 = mask
	srl     %o3, %o4, %o3           ! %o3 = shifted to bit offset
	sll     %o1, %g1, %o1           ! %o1 = shifted to bit offset
	and     %o1, %o3, %o1           ! %o1 = single short value
	andn    %o0, 0x2, %o0           ! %o0 = word address
	! if low-order bit is 1, we will properly get an alignment fault here
	ld      [%o0], %o2              ! read old value
1:
	or      %o2, %o1, %o5           ! or in the new value
	cas     [%o0], %o2, %o5
	cmp     %o2, %o5
	bne,a,pn %icc, 1b
	  mov   %o5, %o2                ! %o2 = old value
	or      %o2, %o1, %o5           ! or in the new value
	and     %o5, %o3, %o5
	retl
	srl     %o5, %g1, %o0           ! %o0 = new value
	SET_SIZE(atomic_or_ushort_nv)
	SET_SIZE(atomic_or_ushort)
	SET_SIZE(atomic_or_16_nv)
	SET_SIZE(atomic_or_16)



	ENTRY(atomic_or_32)
	ALTENTRY(atomic_or_32_nv)
	ALTENTRY(atomic_or_uint)
	ALTENTRY(atomic_or_uint_nv)
	chkpt (or32_tmfail)	
	lduw	[%o0], %o2     
	or	%o2, %o1, %o3 
	stuw	%o3, [%o0]
	commit		
	retl
	 mov	%o3, %o0
or32_tmfail:
	ld      [%o0], %o2
1:
	or      %o2, %o1, %o3
	cas     [%o0], %o2, %o3
	cmp     %o2, %o3
	bne,a,pn %icc, 1b
	  mov   %o3, %o2
	retl
	or      %o2, %o1, %o0           ! return new value
	SET_SIZE(atomic_or_uint_nv)
	SET_SIZE(atomic_or_uint)
	SET_SIZE(atomic_or_32_nv)
	SET_SIZE(atomic_or_32)



	ENTRY(atomic_or_64)
	ALTENTRY(atomic_or_64_nv)
	ALTENTRY(atomic_or_ulong)
	ALTENTRY(atomic_or_ulong_nv)
	chkpt (or64_tmfail)	
	ldx	[%o0], %o2     
	or	%o2, %o1, %o3 
	stx	%o3, [%o0]
	commit		
	retl
	 mov	%o3, %o0
or64_tmfail:
	ldx     [%o0], %o2
1:
	or      %o2, %o1, %o3
	casx    [%o0], %o2, %o3
	cmp     %o2, %o3
	bne,a,pn %xcc, 1b
	  mov   %o3, %o2
	retl
	or      %o2, %o1, %o0           ! return new value
	SET_SIZE(atomic_or_ulong_nv)
	SET_SIZE(atomic_or_ulong)
	SET_SIZE(atomic_or_64_nv)
	SET_SIZE(atomic_or_64)



	ENTRY(atomic_and_8)
	ALTENTRY(atomic_and_8_nv)
	ALTENTRY(atomic_and_uchar)
	ALTENTRY(atomic_and_uchar_nv)
	chkpt (and08_tmfail)	
	ldub	[%o0], %o2     
	and	%o2, %o1, %o3 
	stub	%o3, [%o0]
	commit		
	retl
	 mov	%o3, %o0
and08_tmfail:
	and     %o0, 0x3, %o4           ! %o4 = byte offset, left-to-right
	xor     %o4, 0x3, %g1           ! %g1 = byte offset, right-to-left
	sll     %g1, 3, %g1             ! %g1 = bit offset, right-to-left
	set     0xff, %o3               ! %o3 = mask
	sll     %o3, %g1, %o3           ! %o3 = shifted to bit offset
	sll     %o1, %g1, %o1           ! %o1 = shifted to bit offset
	orn     %o1, %o3, %o1           ! all ones in other bytes
	andn    %o0, 0x3, %o0           ! %o0 = word address
	ld      [%o0], %o2              ! read old value
1:
	and     %o2, %o1, %o5           ! and in the new value
	cas     [%o0], %o2, %o5
	cmp     %o2, %o5
	bne,a,pn %icc, 1b
	  mov   %o5, %o2                ! %o2 = old value
	and     %o2, %o1, %o5
	and     %o5, %o3, %o5
	retl
	srl     %o5, %g1, %o0           ! %o0 = new value
	SET_SIZE(atomic_and_uchar_nv)
	SET_SIZE(atomic_and_uchar)
	SET_SIZE(atomic_and_8_nv)
	SET_SIZE(atomic_and_8)



	ENTRY(atomic_and_16)
	ALTENTRY(atomic_and_16_nv)
	ALTENTRY(atomic_and_ushort)
	ALTENTRY(atomic_and_ushort_nv)
	chkpt (and16_tmfail)	
	lduh	[%o0], %o2     
	and	%o2, %o1, %o3 
	stuh	%o3, [%o0]
	commit		
	retl
	 mov	%o3, %o0
and16_tmfail:
	and     %o0, 0x2, %o4           ! %o4 = byte offset, left-to-right
	xor     %o4, 0x2, %g1           ! %g1 = byte offset, right-to-left
	sll     %o4, 3, %o4             ! %o4 = bit offset, left-to-right
	sll     %g1, 3, %g1             ! %g1 = bit offset, right-to-left
	sethi   %hi(0xffff0000), %o3    ! %o3 = mask
	srl     %o3, %o4, %o3           ! %o3 = shifted to bit offset
	sll     %o1, %g1, %o1           ! %o1 = shifted to bit offset
	orn     %o1, %o3, %o1           ! all ones in the other half
	andn    %o0, 0x2, %o0           ! %o0 = word address
	! if low-order bit is 1, we will properly get an alignment fault here
	ld      [%o0], %o2              ! read old value
1:
	and     %o2, %o1, %o5           ! and in the new value
	cas     [%o0], %o2, %o5
	cmp     %o2, %o5
	bne,a,pn %icc, 1b
	  mov   %o5, %o2                ! %o2 = old value
	and     %o2, %o1, %o5
	and     %o5, %o3, %o5
	retl
	srl     %o5, %g1, %o0           ! %o0 = new value
	SET_SIZE(atomic_and_ushort_nv)
	SET_SIZE(atomic_and_ushort)
	SET_SIZE(atomic_and_16_nv)
	SET_SIZE(atomic_and_16)



	ENTRY(atomic_and_32)
	ALTENTRY(atomic_and_32_nv)
	ALTENTRY(atomic_and_uint)
	ALTENTRY(atomic_and_uint_nv)
	chkpt (and32_tmfail)	
	lduw	[%o0], %o2     
	and	%o2, %o1, %o3 
	stuw	%o3, [%o0]
	commit		
	retl
	 mov	%o3, %o0
and32_tmfail:
	ld      [%o0], %o2
1:
	and     %o2, %o1, %o3
	cas     [%o0], %o2, %o3
	cmp     %o2, %o3
	bne,a,pn %icc, 1b
	  mov   %o3, %o2
	retl
	and     %o2, %o1, %o0           ! return new value
	SET_SIZE(atomic_and_uint_nv)
	SET_SIZE(atomic_and_uint)
	SET_SIZE(atomic_and_32_nv)
	SET_SIZE(atomic_and_32)



	ENTRY(atomic_and_64)
	ALTENTRY(atomic_and_64_nv)
	ALTENTRY(atomic_and_ulong)
	ALTENTRY(atomic_and_ulong_nv)
	chkpt (and64_tmfail)	
	ldx	[%o0], %o2     
	and	%o2, %o1, %o3 
	stx	%o3, [%o0]
	commit		
	retl
	 mov	%o3, %o0
and64_tmfail:
	ldx     [%o0], %o2
1:
	and     %o2, %o1, %o3
	casx    [%o0], %o2, %o3
	cmp     %o2, %o3
	bne,a,pn %xcc, 1b
	  mov   %o3, %o2
	retl
	and     %o2, %o1, %o0           ! return new value
	SET_SIZE(atomic_and_ulong_nv)
	SET_SIZE(atomic_and_ulong)
	SET_SIZE(atomic_and_64_nv)
	SET_SIZE(atomic_and_64)



	ENTRY(atomic_cas_8)
	ALTENTRY(atomic_cas_uchar)
	chkpt (cas08_tmfail)
	ldub    [%o0], %o3
	cmp     %o3, %o1
	bne,a,pn %icc, ret_cas8
	nop
	stub    %o2, [%o0]
	commit
ret_cas8:    retl
	mov     %o3, %o2
cas08_tmfail:
	and     %o0, 0x3, %o4           ! %o4 = byte offset, left-to-right
	xor     %o4, 0x3, %g1           ! %g1 = byte offset, right-to-left
	sll     %g1, 3, %g1             ! %g1 = bit offset, right-to-left
	set     0xff, %o3               ! %o3 = mask
	sll     %o3, %g1, %o3           ! %o3 = shifted to bit offset
	sll     %o1, %g1, %o1           ! %o1 = shifted to bit offset
	and     %o1, %o3, %o1           ! %o1 = single byte value
	sll     %o2, %g1, %o2           ! %o2 = shifted to bit offset
	and     %o2, %o3, %o2           ! %o2 = single byte value
	andn    %o0, 0x3, %o0           ! %o0 = word address
	ld      [%o0], %o4              ! read old value
1:
	andn    %o4, %o3, %o4           ! clear target bits
	or      %o4, %o2, %o5           ! insert the new value
	or      %o4, %o1, %o4           ! insert the comparison value
	cas     [%o0], %o4, %o5
	cmp     %o4, %o5                ! did we succeed?
	be,pt   %icc, 2f
	  and   %o5, %o3, %o4           ! isolate the old value
	cmp     %o1, %o4                ! should we have succeeded?
	be,a,pt %icc, 1b                ! yes, try again
	  mov   %o5, %o4                ! %o4 = old value
2:
	retl
	srl     %o4, %g1, %o0           ! %o0 = old value
	SET_SIZE(atomic_cas_uchar)
	SET_SIZE(atomic_cas_8)



	ENTRY(atomic_cas_16)
	ALTENTRY(atomic_cas_ushort)
	chkpt (cas16_tmfail)
	lduh    [%o0], %o3
	cmp     %o3, %o1
	bne,a,pn %icc, ret_cas16
	nop
	stuh    %o2, [%o0]
	commit
ret_cas16:    retl
	mov     %o3, %o2
cas16_tmfail:
	and     %o0, 0x2, %o4           ! %o4 = byte offset, left-to-right
	xor     %o4, 0x2, %g1           ! %g1 = byte offset, right-to-left
	sll     %o4, 3, %o4             ! %o4 = bit offset, left-to-right
	sll     %g1, 3, %g1             ! %g1 = bit offset, right-to-left
	sethi   %hi(0xffff0000), %o3    ! %o3 = mask
	srl     %o3, %o4, %o3           ! %o3 = shifted to bit offset
	sll     %o1, %g1, %o1           ! %o1 = shifted to bit offset
	and     %o1, %o3, %o1           ! %o1 = single short value
	sll     %o2, %g1, %o2           ! %o2 = shifted to bit offset
	and     %o2, %o3, %o2           ! %o2 = single short value
	andn    %o0, 0x2, %o0           ! %o0 = word address
	! if low-order bit is 1, we will properly get an alignment fault here
	ld      [%o0], %o4              ! read old value
1:
	andn    %o4, %o3, %o4           ! clear target bits
	or      %o4, %o2, %o5           ! insert the new value
	or      %o4, %o1, %o4           ! insert the comparison value
	cas     [%o0], %o4, %o5
	cmp     %o4, %o5                ! did we succeed?
	be,pt   %icc, 2f
	  and   %o5, %o3, %o4           ! isolate the old value
	cmp     %o1, %o4                ! should we have succeeded?
	be,a,pt %icc, 1b                ! yes, try again
	  mov   %o5, %o4                ! %o4 = old value
2:
	retl
	srl     %o4, %g1, %o0           ! %o0 = old value
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
	chkpt (swp08_tmfail)
	ldub    [%o0], %o2
	stub    %o1, [%o0]
	commit
	retl
	mov     %o2, %o1
swp08_tmfail:
	and     %o0, 0x3, %o4           ! %o4 = byte offset, left-to-right
	xor     %o4, 0x3, %g1           ! %g1 = byte offset, right-to-left
	sll     %g1, 3, %g1             ! %g1 = bit offset, right-to-left
	set     0xff, %o3               ! %o3 = mask
	sll     %o3, %g1, %o3           ! %o3 = shifted to bit offset
	sll     %o1, %g1, %o1           ! %o1 = shifted to bit offset
	and     %o1, %o3, %o1           ! %o1 = single byte value
	andn    %o0, 0x3, %o0           ! %o0 = word address
	ld      [%o0], %o2              ! read old value
1:
	andn    %o2, %o3, %o5           ! clear target bits
	or      %o5, %o1, %o5           ! insert the new value
	cas     [%o0], %o2, %o5
	cmp     %o2, %o5
	bne,a,pn %icc, 1b
	  mov   %o5, %o2                ! %o2 = old value
	and     %o5, %o3, %o5
	retl
	srl     %o5, %g1, %o0           ! %o0 = old value
	SET_SIZE(atomic_swap_uchar)
	SET_SIZE(atomic_swap_8)


	ENTRY(atomic_swap_16)
	ALTENTRY(atomic_swap_ushort)
	chkpt (swp16_tmfail)
	lduh    [%o0], %o2
	stuh    %o1, [%o0]
	commit
	retl
	mov     %o2, %o1
swp16_tmfail:
	and     %o0, 0x2, %o4           ! %o4 = byte offset, left-to-right
	xor     %o4, 0x2, %g1           ! %g1 = byte offset, right-to-left
	sll     %o4, 3, %o4             ! %o4 = bit offset, left-to-right
	sll     %g1, 3, %g1             ! %g1 = bit offset, right-to-left
	sethi   %hi(0xffff0000), %o3    ! %o3 = mask
	srl     %o3, %o4, %o3           ! %o3 = shifted to bit offset
	sll     %o1, %g1, %o1           ! %o1 = shifted to bit offset
	and     %o1, %o3, %o1           ! %o1 = single short value
	andn    %o0, 0x2, %o0           ! %o0 = word address
	! if low-order bit is 1, we will properly get an alignment fault here
	ld      [%o0], %o2              ! read old value
1:
	andn    %o2, %o3, %o5           ! clear target bits
	or      %o5, %o1, %o5           ! insert the new value
	cas     [%o0], %o2, %o5
	cmp     %o2, %o5
	bne,a,pn %icc, 1b
	  mov   %o5, %o2                ! %o2 = old value
	and     %o5, %o3, %o5
	retl
	srl     %o5, %g1, %o0           ! %o0 = old value
	SET_SIZE(atomic_swap_ushort)
	SET_SIZE(atomic_swap_16)


	ENTRY(atomic_swap_32)
	ALTENTRY(atomic_swap_uint)
	chkpt (swp32_tmfail)
	lduw    [%o0], %o2
	stuw    %o1, [%o0]
	commit
	retl
	mov     %o2, %o1
swp32_tmfail:
	ld      [%o0], %o2
1:
	mov     %o1, %o3
	cas     [%o0], %o2, %o3
	cmp     %o2, %o3
	bne,a,pn %icc, 1b
	  mov   %o3, %o2
	retl
	mov     %o3, %o0
	SET_SIZE(atomic_swap_uint)
	SET_SIZE(atomic_swap_32)


	ENTRY(atomic_swap_64)
	ALTENTRY(atomic_swap_ptr)
	ALTENTRY(atomic_swap_ulong)

	chkpt (swp64_tmfail)
	ldx    [%o0], %o2
	stx    %o1, [%o0]
	commit
	retl
	mov     %o2, %o1
swp64_tmfail:
	ldx     [%o0], %o2
1:
	mov     %o1, %o3
	casx    [%o0], %o2, %o3
	cmp     %o2, %o3
	bne,a,pn %xcc, 1b
	  mov   %o3, %o2
	retl
	mov     %o3, %o0
	SET_SIZE(atomic_swap_ulong)
	SET_SIZE(atomic_swap_ptr)
	SET_SIZE(atomic_swap_64)


	ENTRY(atomic_set_long_excl)
	mov	1, %o3
	slln	%o3, %o1, %o3
	chkpt(slong_tmfail)
	ldn	[%o0], %o2
	or	%o2, %o3, %o4		! set the bit, and try to commit it
	stn	%o4, [%o0]
	commit
	retl
	mov	%o4, %o0
slong_tmfail:
	ldn	[%o0], %o2
1:
	andcc	%o2, %o3, %g0		! test if the bit is set
	bnz,a,pn %ncc, 2f		! if so, then fail out
	  mov	-1, %o0
	or	%o2, %o3, %o4		! set the bit, and try to commit it
	casn	[%o0], %o2, %o4
	cmp	%o2, %o4
	bne,a,pn %ncc, 1b		! failed to commit, try again
	  mov	%o4, %o2
	mov	%g0, %o0
2:
	retl
	nop
	SET_SIZE(atomic_set_long_excl)


	ENTRY(atomic_clear_long_excl)
	mov	1, %o3
	slln	%o3, %o1, %o3
	chkpt(clong_tmfail)
	ldn	[%o0], %o2
	andn	%o2, %o3, %o4		! clear the bit, and try to commit it
	stn	%o4, [%o0]
	commit
	retl
	mov	%o4, %o0
clong_tmfail:
	ldn	[%o0], %o2
1:
	andncc	%o3, %o2, %g0		! test if the bit is clear
	bnz,a,pn %ncc, 2f		! if so, then fail out
	  mov	-1, %o0
	andn	%o2, %o3, %o4		! clear the bit, and try to commit it
	casn	[%o0], %o2, %o4
	cmp	%o2, %o4
	bne,a,pn %ncc, 1b		! failed to commit, try again
	  mov	%o4, %o2
	mov	%g0, %o0
2:
	retl
	nop
	SET_SIZE(atomic_clear_long_excl)

#endif	/* lint */
