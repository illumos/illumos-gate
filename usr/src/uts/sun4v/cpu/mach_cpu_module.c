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

#include <sys/cpu_module.h>
#include <vm/page.h>
#include <vm/seg_map.h>

/*ARGSUSED*/
void
cpu_fiximp(struct cpu_node *cpunode)
{}

/*ARGSUSED*/
void
cpu_map_exec_units(struct cpu *cp)
{}

void
cpu_flush_ecache(void)
{}

/*ARGSUSED*/
void
cpu_faulted_enter(struct cpu *cp)
{}

/*ARGSUSED*/
void
cpu_faulted_exit(struct cpu *cp)
{}

/*
 * Ecache scrub operations
 */
void
cpu_init_cache_scrub(void)
{}

/* ARGSUSED */
void
prefetch_page_w(void *pp)
{
#define	ECACHE_SUBBLOCKS_PER_PAGE	2
#define	ECACHE_SUBBLOCK_SIZE_BYTES	64
#define	ECACHE_PAGE_BYTE_MAX	\
	(ECACHE_SUBBLOCKS_PER_PAGE*ECACHE_SUBBLOCK_SIZE_BYTES+1)

	/*
	 * The following line is intended to cause an error
	 * whenever the sun4u page_t grows beyond 128
	 * bytes.
	 *
	 * If you get an error here, you'll need to change
	 * the 'prefetch_page_w' assembly language code
	 * (see also prefetch_page_w prologue comment)
	 */
	/*LINTED*/
	volatile int garbage[ECACHE_PAGE_BYTE_MAX - sizeof (page_t)];
}

/* ARGSUSED */
void
prefetch_page_r(void *pp)
{
#define	ECACHE_SUBBLOCKS_PER_PAGE	2
#define	ECACHE_SUBBLOCK_SIZE_BYTES	64
#define	ECACHE_PAGE_BYTE_MAX	\
	(ECACHE_SUBBLOCKS_PER_PAGE*ECACHE_SUBBLOCK_SIZE_BYTES+1)

	/*
	 * The following line is intended to cause an error
	 * whenever the sun4u page_t grows beyond 128
	 * bytes.
	 *
	 * If you get an error here, you'll need to change
	 * the 'prefetch_page_r' assembly language code
	 * (see also prefetch_page_w prologue comment)
	 */
	/*LINTED*/
	volatile int garbage[ECACHE_PAGE_BYTE_MAX - sizeof (page_t)];
}


#ifdef	SEGKPM_SUPPORT
#define	SMAP_SIZE	80
#else
#define	SMAP_SIZE	56
#endif

/* ARGSUSED */
void
prefetch_smap_w(void *smp)
{

	/*
	 * The following lines are intended to cause an error
	 * whenever the smap object size changes from the current
	 * size of 48 bytes.  If you get an error here, you'll
	 * need to update the code in the 'prefetch_smap_w' assembly
	 * language code.
	 */
	/*LINTED*/
	volatile int smap_size_changed [SMAP_SIZE - sizeof (struct smap) + 1];
	volatile int smap_size_changed2 [sizeof (struct smap) - SMAP_SIZE + 1];
}

void
kdi_flush_caches(void)
{}

/*ARGSUSED*/
int
kzero(void *addr, size_t count)
{ return (0); }

/*ARGSUSED*/
void
uzero(void *addr, size_t count)
{}

/*ARGSUSED*/
void
bzero(void *addr, size_t count)
{}

/*ARGSUSED*/
void
cpu_inv_tsb(caddr_t tsb_base, uint_t tsb_bytes)
{}

/*
 *  Atomic Function Stubs
 */

/* ARGSUSED */
uint64_t
atomic_cas_64(volatile uint64_t *target, uint64_t value1, uint64_t value2)
{ return (0); }

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
{ return (NULL); }

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
{ return (NULL); }

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
{ return (NULL); }

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

void
fp_zero(void)
{}

uint64_t
gettick_npt(void)
{ return (0); }

uint64_t
getstick_npt(void)
{ return (0); }
