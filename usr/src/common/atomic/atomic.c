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

#include <sys/atomic.h>

/*
 * This file exists only for the purpose of running lint.
 */

#if defined(__lint)

void
atomic_inc_8(volatile uint8_t *target)
{ (*target)++; }

void
atomic_inc_uchar(volatile uchar_t *target)
{ (*target)++; }

void
atomic_inc_16(volatile uint16_t *target)
{ (*target)++; }

void
atomic_inc_ushort(volatile ushort_t *target)
{ (*target)++; }

void
atomic_inc_32(volatile uint32_t *target)
{ (*target)++; }

void
atomic_inc_uint(volatile uint_t *target)
{ (*target)++; }

void
atomic_inc_ulong(volatile ulong_t *target)
{ (*target)++; }

void
atomic_inc_64(volatile uint64_t *target)
{ (*target)++; }

void
atomic_dec_8(volatile uint8_t *target)
{ (*target)--; }

void
atomic_dec_uchar(volatile uchar_t *target)
{ (*target)--; }

void
atomic_dec_16(volatile uint16_t *target)
{ (*target)--; }

void
atomic_dec_ushort(volatile ushort_t *target)
{ (*target)--; }

void
atomic_dec_32(volatile uint32_t *target)
{ (*target)--; }

void
atomic_dec_uint(volatile uint_t *target)
{ (*target)--; }

void
atomic_dec_ulong(volatile ulong_t *target)
{ (*target)--; }

void
atomic_dec_64(volatile uint64_t *target)
{ (*target)--; }

void
atomic_add_8(volatile uint8_t *target, int8_t value)
{ *target += value; }

void
atomic_add_char(volatile uchar_t *target, signed char value)
{ *target += value; }

void
atomic_add_16(volatile uint16_t *target, int16_t delta)
{ *target += delta; }

void
atomic_add_ushort(volatile ushort_t *target, short value)
{ *target += value; }

void
atomic_add_32(volatile uint32_t *target, int32_t delta)
{ *target += delta; }

void
atomic_add_ptr(volatile void *target, ssize_t value)
{ *(caddr_t *)target += value; }

void
atomic_add_long(volatile ulong_t *target, long delta)
{ *target += delta; }

void
atomic_add_64(volatile uint64_t *target, int64_t delta)
{ *target += delta; }

void
atomic_or_8(volatile uint8_t *target, uint8_t bits)
{ *target |= bits; }

void
atomic_or_uchar(volatile uchar_t *target, uchar_t bits)
{ *target |= bits; }

void
atomic_or_16(volatile uint16_t *target, uint16_t bits)
{ *target |= bits; }

void
atomic_or_ushort(volatile ushort_t *target, ushort_t bits)
{ *target |= bits; }

void
atomic_or_32(volatile uint32_t *target, uint32_t bits)
{ *target |= bits; }

void
atomic_or_uint(volatile uint_t *target, uint_t bits)
{ *target |= bits; }

void
atomic_or_ulong(volatile ulong_t *target, ulong_t bits)
{ *target |= bits; }

void
atomic_or_64(volatile uint64_t *target, uint64_t bits)
{ *target |= bits; }

void
atomic_and_8(volatile uint8_t *target, uint8_t bits)
{ *target &= bits; }

void
atomic_and_uchar(volatile uchar_t *target, uchar_t bits)
{ *target &= bits; }

void
atomic_and_16(volatile uint16_t *target, uint16_t bits)
{ *target &= bits; }

void
atomic_and_ushort(volatile ushort_t *target, ushort_t bits)
{ *target &= bits; }

void
atomic_and_32(volatile uint32_t *target, uint32_t bits)
{ *target &= bits; }

void
atomic_and_uint(volatile uint_t *target, uint_t bits)
{ *target &= bits; }

void
atomic_and_ulong(volatile ulong_t *target, ulong_t bits)
{ *target &= bits; }

void
atomic_and_64(volatile uint64_t *target, uint64_t bits)
{ *target &= bits; }

uint8_t
atomic_inc_8_nv(volatile uint8_t *target)
{ return (++(*target)); }

uchar_t
atomic_inc_uchar_nv(volatile uchar_t *target)
{ return (++(*target)); }

uint16_t
atomic_inc_16_nv(volatile uint16_t *target)
{ return (++(*target)); }

ushort_t
atomic_inc_ushort_nv(volatile ushort_t *target)
{ return (++(*target)); }

uint32_t
atomic_inc_32_nv(volatile uint32_t *target)
{ return (++(*target)); }

uint_t
atomic_inc_uint_nv(volatile uint_t *target)
{ return (++(*target)); }

ulong_t
atomic_inc_ulong_nv(volatile ulong_t *target)
{ return (++(*target)); }

uint64_t
atomic_inc_64_nv(volatile uint64_t *target)
{ return (++(*target)); }

uint8_t
atomic_dec_8_nv(volatile uint8_t *target)
{ return (--(*target)); }

uchar_t
atomic_dec_uchar_nv(volatile uchar_t *target)
{ return (--(*target)); }

uint16_t
atomic_dec_16_nv(volatile uint16_t *target)
{ return (--(*target)); }

ushort_t
atomic_dec_ushort_nv(volatile ushort_t *target)
{ return (--(*target)); }

uint32_t
atomic_dec_32_nv(volatile uint32_t *target)
{ return (--(*target)); }

uint_t
atomic_dec_uint_nv(volatile uint_t *target)
{ return (--(*target)); }

ulong_t
atomic_dec_ulong_nv(volatile ulong_t *target)
{ return (--(*target)); }

uint64_t
atomic_dec_64_nv(volatile uint64_t *target)
{ return (--(*target)); }

uint8_t
atomic_add_8_nv(volatile uint8_t *target, int8_t value)
{ return (*target += value); }

uchar_t
atomic_add_char_nv(volatile uchar_t *target, signed char value)
{ return (*target += value); }

uint16_t
atomic_add_16_nv(volatile uint16_t *target, int16_t delta)
{ return (*target += delta); }

ushort_t
atomic_add_short_nv(volatile ushort_t *target, short value)
{ return (*target += value); }

uint32_t
atomic_add_32_nv(volatile uint32_t *target, int32_t delta)
{ return (*target += delta); }

uint_t
atomic_add_int_nv(volatile uint_t *target, int delta)
{ return (*target += delta); }

void *
atomic_add_ptr_nv(volatile void *target, ssize_t value)
{ return (*(caddr_t *)target += value); }

ulong_t
atomic_add_long_nv(volatile ulong_t *target, long delta)
{ return (*target += delta); }

uint64_t
atomic_add_64_nv(volatile uint64_t *target, int64_t delta)
{ return (*target += delta); }

uint8_t
atomic_or_8_nv(volatile uint8_t *target, uint8_t value)
{ return (*target |= value); }

uchar_t
atomic_or_uchar_nv(volatile uchar_t *target, uchar_t value)
{ return (*target |= value); }

uint16_t
atomic_or_16_nv(volatile uint16_t *target, uint16_t value)
{ return (*target |= value); }

ushort_t
atomic_or_ushort_nv(volatile ushort_t *target, ushort_t value)
{ return (*target |= value); }

uint32_t
atomic_or_32_nv(volatile uint32_t *target, uint32_t value)
{ return (*target |= value); }

uint_t
atomic_or_uint_nv(volatile uint_t *target, uint_t value)
{ return (*target |= value); }

ulong_t
atomic_or_ulong_nv(volatile ulong_t *target, ulong_t value)
{ return (*target |= value); }

uint64_t
atomic_or_64_nv(volatile uint64_t *target, uint64_t value)
{ return (*target |= value); }

uint8_t
atomic_and_8_nv(volatile uint8_t *target, uint8_t value)
{ return (*target &= value); }

uchar_t
atomic_and_uchar_nv(volatile uchar_t *target, uchar_t value)
{ return (*target &= value); }

uint16_t
atomic_and_16_nv(volatile uint16_t *target, uint16_t value)
{ return (*target &= value); }

ushort_t
atomic_and_ushort_nv(volatile ushort_t *target, ushort_t value)
{ return (*target &= value); }

uint32_t
atomic_and_32_nv(volatile uint32_t *target, uint32_t value)
{ return (*target &= value); }

uint_t
atomic_and_uint_nv(volatile uint_t *target, uint_t value)
{ return (*target &= value); }

ulong_t
atomic_and_ulong_nv(volatile ulong_t *target, ulong_t value)
{ return (*target &= value); }

uint64_t
atomic_and_64_nv(volatile uint64_t *target, uint64_t value)
{ return (*target &= value); }

uint8_t
atomic_cas_8(volatile uint8_t *target, uint8_t cmp, uint8_t new)
{
	uint8_t old = *target;
	if (old == cmp)
		*target = new;
	return (old);
}

uchar_t
atomic_cas_uchar(volatile uchar_t *target, uchar_t cmp, uchar_t new)
{
	uchar_t old = *target;
	if (old == cmp)
		*target = new;
	return (old);
}

uint16_t
atomic_cas_16(volatile uint16_t *target, uint16_t cmp, uint16_t new)
{
	uint16_t old = *target;
	if (old == cmp)
		*target = new;
	return (old);
}

ushort_t
atomic_cas_ushort(volatile ushort_t *target, ushort_t cmp, ushort_t new)
{
	ushort_t old = *target;
	if (old == cmp)
		*target = new;
	return (old);
}

uint32_t
atomic_cas_32(volatile uint32_t *target, uint32_t cmp, uint32_t new)
{
	uint32_t old = *target;
	if (old == cmp)
		*target = new;
	return (old);
}

uint_t
atomic_cas_uint(volatile uint_t *target, uint_t cmp, uint_t new)
{
	uint_t old = *target;
	if (old == cmp)
		*target = new;
	return (old);
}

ulong_t
atomic_cas_ulong(volatile ulong_t *target, ulong_t cmp, ulong_t new)
{
	ulong_t old = *target;
	if (old == cmp)
		*target = new;
	return (old);
}

uint64_t
atomic_cas_uint64(volatile uint64_t *target, ulong_t cmp, uint64_t new)
{
	uint64_t old = *target;
	if (old == cmp)
		*target = new;
	return (old);
}

void *
atomic_cas_ptr(volatile void *target, void *cmp, void *new)
{
	void *old = *(void **)target;
	if (old == cmp)
		*(void **)target = new;
	return (old);
}

uint8_t
atomic_swap_8(volatile uint8_t *target, uint8_t new)
{
	uint8_t old = *target;
	*target = new;
	return (old);
}

uchar_t
atomic_swap_char(volatile uchar_t *target, uchar_t new)
{
	uchar_t old = *target;
	*target = new;
	return (old);
}

uint16_t
atomic_swap_16(volatile uint16_t *target, uint16_t new)
{
	uint16_t old = *target;
	*target = new;
	return (old);
}

ushort_t
atomic_swap_ushort(volatile ushort_t *target, ushort_t new)
{
	ushort_t old = *target;
	*target = new;
	return (old);
}

uint32_t
atomic_swap_32(volatile uint32_t *target, uint32_t new)
{
	uint32_t old = *target;
	*target = new;
	return (old);
}

uint_t
atomic_swap_uint(volatile uint_t *target, uint_t new)
{
	uint_t old = *target;
	*target = new;
	return (old);
}

uint64_t
atomic_swap_64(volatile uint64_t *target, uint64_t new)
{
	uint64_t old = *target;
	*target = new;
	return (old);
}

void *
atomic_swap_ptr(volatile void *target, void *new)
{
	void *old = *(void **)target;
	*(void **)target = new;
	return (old);
}

ulong_t
atomic_swap_ulong(volatile ulong_t *target, ulong_t new)
{
	ulong_t old = *target;
	*target = new;
	return (old);
}

int
atomic_set_long_excl(volatile ulong_t *target, uint_t value)
{
	ulong_t bit = (1UL << value);
	if ((*target & bit) != 0)
		return (-1);
	*target |= bit;
	return (0);
}

int
atomic_clear_long_excl(volatile ulong_t *target, uint_t value)
{
	ulong_t bit = (1UL << value);
	if ((*target & bit) == 0)
		return (-1);
	*target &= ~bit;
	return (0);
}

#if !defined(_KERNEL)

void
membar_enter(void)
{}

void
membar_exit(void)
{}

void
membar_producer(void)
{}

void
membar_consumer(void)
{}

#endif	/* _KERNEL */

#endif	/* __lint */
