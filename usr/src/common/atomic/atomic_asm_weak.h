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

ANSI_PRAGMA_WEAK(atomic_inc_8,function)
ANSI_PRAGMA_WEAK(atomic_inc_uchar,function)
ANSI_PRAGMA_WEAK(atomic_inc_16,function)
ANSI_PRAGMA_WEAK(atomic_inc_ushort,function)
ANSI_PRAGMA_WEAK(atomic_inc_32,function)
ANSI_PRAGMA_WEAK(atomic_inc_uint,function)
ANSI_PRAGMA_WEAK(atomic_inc_64,function)
ANSI_PRAGMA_WEAK(atomic_inc_ulong,function)
ANSI_PRAGMA_WEAK(atomic_inc_8_nv,function)
ANSI_PRAGMA_WEAK(atomic_inc_uchar_nv,function)
ANSI_PRAGMA_WEAK(atomic_inc_16_nv,function)
ANSI_PRAGMA_WEAK(atomic_inc_ushort_nv,function)
ANSI_PRAGMA_WEAK(atomic_inc_32_nv,function)
ANSI_PRAGMA_WEAK(atomic_inc_uint_nv,function)
ANSI_PRAGMA_WEAK(atomic_inc_64_nv,function)
ANSI_PRAGMA_WEAK(atomic_inc_ulong_nv,function)
ANSI_PRAGMA_WEAK(atomic_dec_8,function)
ANSI_PRAGMA_WEAK(atomic_dec_uchar,function)
ANSI_PRAGMA_WEAK(atomic_dec_16,function)
ANSI_PRAGMA_WEAK(atomic_dec_ushort,function)
ANSI_PRAGMA_WEAK(atomic_dec_32,function)
ANSI_PRAGMA_WEAK(atomic_dec_uint,function)
ANSI_PRAGMA_WEAK(atomic_dec_64,function)
ANSI_PRAGMA_WEAK(atomic_dec_ulong,function)
ANSI_PRAGMA_WEAK(atomic_dec_8_nv,function)
ANSI_PRAGMA_WEAK(atomic_dec_uchar_nv,function)
ANSI_PRAGMA_WEAK(atomic_dec_16_nv,function)
ANSI_PRAGMA_WEAK(atomic_dec_ushort_nv,function)
ANSI_PRAGMA_WEAK(atomic_dec_32_nv,function)
ANSI_PRAGMA_WEAK(atomic_dec_uint_nv,function)
ANSI_PRAGMA_WEAK(atomic_dec_64_nv,function)
ANSI_PRAGMA_WEAK(atomic_dec_ulong_nv,function)
ANSI_PRAGMA_WEAK(atomic_add_8,function)
ANSI_PRAGMA_WEAK(atomic_add_char,function)
ANSI_PRAGMA_WEAK(atomic_add_16,function)
ANSI_PRAGMA_WEAK(atomic_add_short,function)
ANSI_PRAGMA_WEAK(atomic_add_32,function)
ANSI_PRAGMA_WEAK(atomic_add_int,function)
ANSI_PRAGMA_WEAK(atomic_add_64,function)
ANSI_PRAGMA_WEAK(atomic_add_ptr,function)
ANSI_PRAGMA_WEAK(atomic_add_long,function)
ANSI_PRAGMA_WEAK(atomic_add_8_nv,function)
ANSI_PRAGMA_WEAK(atomic_add_char_nv,function)
ANSI_PRAGMA_WEAK(atomic_add_16_nv,function)
ANSI_PRAGMA_WEAK(atomic_add_short_nv,function)
ANSI_PRAGMA_WEAK(atomic_add_32_nv,function)
ANSI_PRAGMA_WEAK(atomic_add_int_nv,function)
ANSI_PRAGMA_WEAK(atomic_add_64_nv,function)
ANSI_PRAGMA_WEAK(atomic_add_ptr_nv,function)
ANSI_PRAGMA_WEAK(atomic_add_long_nv,function)
ANSI_PRAGMA_WEAK(atomic_or_8,function)
ANSI_PRAGMA_WEAK(atomic_or_uchar,function)
ANSI_PRAGMA_WEAK(atomic_or_16,function)
ANSI_PRAGMA_WEAK(atomic_or_ushort,function)
ANSI_PRAGMA_WEAK(atomic_or_32,function)
ANSI_PRAGMA_WEAK(atomic_or_uint,function)
ANSI_PRAGMA_WEAK(atomic_or_ulong,function)
ANSI_PRAGMA_WEAK(atomic_or_64,function)
ANSI_PRAGMA_WEAK(atomic_or_8_nv,function)
ANSI_PRAGMA_WEAK(atomic_or_uchar_nv,function)
ANSI_PRAGMA_WEAK(atomic_or_16_nv,function)
ANSI_PRAGMA_WEAK(atomic_or_ushort_nv,function)
ANSI_PRAGMA_WEAK(atomic_or_32_nv,function)
ANSI_PRAGMA_WEAK(atomic_or_uint_nv,function)
ANSI_PRAGMA_WEAK(atomic_or_ulong_nv,function)
ANSI_PRAGMA_WEAK(atomic_or_64_nv,function)
ANSI_PRAGMA_WEAK(atomic_and_8,function)
ANSI_PRAGMA_WEAK(atomic_and_uchar,function)
ANSI_PRAGMA_WEAK(atomic_and_16,function)
ANSI_PRAGMA_WEAK(atomic_and_ushort,function)
ANSI_PRAGMA_WEAK(atomic_and_32,function)
ANSI_PRAGMA_WEAK(atomic_and_uint,function)
ANSI_PRAGMA_WEAK(atomic_and_ulong,function)
ANSI_PRAGMA_WEAK(atomic_and_64,function)
ANSI_PRAGMA_WEAK(atomic_and_8_nv,function)
ANSI_PRAGMA_WEAK(atomic_and_uchar_nv,function)
ANSI_PRAGMA_WEAK(atomic_and_16_nv,function)
ANSI_PRAGMA_WEAK(atomic_and_ushort_nv,function)
ANSI_PRAGMA_WEAK(atomic_and_32_nv,function)
ANSI_PRAGMA_WEAK(atomic_and_uint_nv,function)
ANSI_PRAGMA_WEAK(atomic_and_ulong_nv,function)
ANSI_PRAGMA_WEAK(atomic_and_64_nv,function)
ANSI_PRAGMA_WEAK(atomic_cas_8,function)
ANSI_PRAGMA_WEAK(atomic_cas_uchar,function)
ANSI_PRAGMA_WEAK(atomic_cas_16,function)
ANSI_PRAGMA_WEAK(atomic_cas_ushort,function)
ANSI_PRAGMA_WEAK(atomic_cas_32,function)
ANSI_PRAGMA_WEAK(atomic_cas_uint,function)
ANSI_PRAGMA_WEAK(atomic_cas_64,function)
ANSI_PRAGMA_WEAK(atomic_cas_ptr,function)
ANSI_PRAGMA_WEAK(atomic_cas_ulong,function)
ANSI_PRAGMA_WEAK(atomic_swap_8,function)
ANSI_PRAGMA_WEAK(atomic_swap_uchar,function)
ANSI_PRAGMA_WEAK(atomic_swap_16,function)
ANSI_PRAGMA_WEAK(atomic_swap_ushort,function)
ANSI_PRAGMA_WEAK(atomic_swap_32,function)
ANSI_PRAGMA_WEAK(atomic_swap_uint,function)
ANSI_PRAGMA_WEAK(atomic_swap_64,function)
ANSI_PRAGMA_WEAK(atomic_swap_ptr,function)
ANSI_PRAGMA_WEAK(atomic_swap_ulong,function)
ANSI_PRAGMA_WEAK(atomic_set_long_excl,function)
ANSI_PRAGMA_WEAK(atomic_clear_long_excl,function)
ANSI_PRAGMA_WEAK(membar_enter,function)
ANSI_PRAGMA_WEAK(membar_exit,function)
ANSI_PRAGMA_WEAK(membar_producer,function)
ANSI_PRAGMA_WEAK(membar_consumer,function)

#define	atomic_inc_8		_atomic_inc_8
#define	atomic_inc_uchar	_atomic_inc_uchar
#define	atomic_inc_16		_atomic_inc_16
#define	atomic_inc_ushort	_atomic_inc_ushort
#define	atomic_inc_32		_atomic_inc_32
#define	atomic_inc_uint		_atomic_inc_uint
#define	atomic_inc_ulong	_atomic_inc_ulong
#define	atomic_inc_64		_atomic_inc_64
#define	atomic_dec_8		_atomic_dec_8
#define	atomic_dec_uchar	_atomic_dec_uchar
#define	atomic_dec_16		_atomic_dec_16
#define	atomic_dec_ushort	_atomic_dec_ushort
#define	atomic_dec_32		_atomic_dec_32
#define	atomic_dec_uint		_atomic_dec_uint
#define	atomic_dec_ulong	_atomic_dec_ulong
#define	atomic_dec_64		_atomic_dec_64
#define	atomic_add_8		_atomic_add_8
#define	atomic_add_char		_atomic_add_char
#define	atomic_add_16		_atomic_add_16
#define	atomic_add_short	_atomic_add_short
#define	atomic_add_32		_atomic_add_32
#define	atomic_add_int		_atomic_add_int
#define	atomic_add_64		_atomic_add_64
#define	atomic_add_ptr		_atomic_add_ptr
#define	atomic_add_long		_atomic_add_long
#define	atomic_or_8		_atomic_or_8
#define	atomic_or_uchar		_atomic_or_uchar
#define	atomic_or_16		_atomic_or_16
#define	atomic_or_ushort	_atomic_or_ushort
#define	atomic_or_32		_atomic_or_32
#define	atomic_or_uint		_atomic_or_uint
#define	atomic_or_64		_atomic_or_64
#define	atomic_or_ulong		_atomic_or_ulong
#define	atomic_and_8		_atomic_and_8
#define	atomic_and_uchar	_atomic_and_uchar
#define	atomic_and_16		_atomic_and_16
#define	atomic_and_ushort	_atomic_and_ushort
#define	atomic_and_32		_atomic_and_32
#define	atomic_and_uint		_atomic_and_uint
#define	atomic_and_64		_atomic_and_64
#define	atomic_and_ulong	_atomic_and_ulong
#define	atomic_inc_8_nv		_atomic_inc_8_nv
#define	atomic_inc_uchar_nv	_atomic_inc_uchar_nv
#define	atomic_inc_16_nv	_atomic_inc_16_nv
#define	atomic_inc_ushort_nv	_atomic_inc_ushort_nv
#define	atomic_inc_32_nv	_atomic_inc_32_nv
#define	atomic_inc_uint_nv	_atomic_inc_uint_nv
#define	atomic_inc_ulong_nv	_atomic_inc_ulong_nv
#define	atomic_inc_64_nv	_atomic_inc_64_nv
#define	atomic_dec_8_nv		_atomic_dec_8_nv
#define	atomic_dec_uchar_nv	_atomic_dec_uchar_nv
#define	atomic_dec_16_nv	_atomic_dec_16_nv
#define	atomic_dec_ushort_nv	_atomic_dec_ushort_nv
#define	atomic_dec_32_nv	_atomic_dec_32_nv
#define	atomic_dec_uint_nv	_atomic_dec_uint_nv
#define	atomic_dec_ulong_nv	_atomic_dec_ulong_nv
#define	atomic_dec_64_nv	_atomic_dec_64_nv
#define	atomic_add_8_nv		_atomic_add_8_nv
#define	atomic_add_char_nv	_atomic_add_char_nv
#define	atomic_add_16_nv	_atomic_add_16_nv
#define	atomic_add_short_nv	_atomic_add_short_nv
#define	atomic_add_32_nv	_atomic_add_32_nv
#define	atomic_add_int_nv	_atomic_add_int_nv
#define	atomic_add_64_nv	_atomic_add_64_nv
#define	atomic_add_ptr_nv	_atomic_add_ptr_nv
#define	atomic_add_long_nv	_atomic_add_long_nv
#define	atomic_or_8_nv		_atomic_or_8_nv
#define	atomic_or_uchar_nv	_atomic_or_uchar_nv
#define	atomic_or_16_nv		_atomic_or_16_nv
#define	atomic_or_ushort_nv	_atomic_or_ushort_nv
#define	atomic_or_32_nv		_atomic_or_32_nv
#define	atomic_or_uint_nv	_atomic_or_uint_nv
#define	atomic_or_64_nv		_atomic_or_64_nv
#define	atomic_or_ulong_nv	_atomic_or_ulong_nv
#define	atomic_and_8_nv		_atomic_and_8_nv
#define	atomic_and_uchar_nv	_atomic_and_uchar_nv
#define	atomic_and_16_nv	_atomic_and_16_nv
#define	atomic_and_ushort_nv	_atomic_and_ushort_nv
#define	atomic_and_32_nv	_atomic_and_32_nv
#define	atomic_and_uint_nv	_atomic_and_uint_nv
#define	atomic_and_64_nv	_atomic_and_64_nv
#define	atomic_and_ulong_nv	_atomic_and_ulong_nv
#define	atomic_cas_8		_atomic_cas_8
#define	atomic_cas_uchar	_atomic_cas_uchar
#define	atomic_cas_16		_atomic_cas_16
#define	atomic_cas_ushort	_atomic_cas_ushort
#define	atomic_cas_32		_atomic_cas_32
#define	atomic_cas_uint		_atomic_cas_uint
#define	atomic_cas_ptr		_atomic_cas_ptr
#define	atomic_cas_ulong	_atomic_cas_ulong
#define	atomic_cas_64		_atomic_cas_64
#define	atomic_swap_8		_atomic_swap_8
#define	atomic_swap_uchar	_atomic_swap_uchar
#define	atomic_swap_16		_atomic_swap_16
#define	atomic_swap_ushort	_atomic_swap_ushort
#define	atomic_swap_32		_atomic_swap_32
#define	atomic_swap_uint	_atomic_swap_uint
#define	atomic_swap_ptr		_atomic_swap_ptr
#define	atomic_swap_ulong	_atomic_swap_ulong
#define	atomic_swap_64		_atomic_swap_64
#define	atomic_set_long_excl	_atomic_set_long_excl
#define	atomic_clear_long_excl	_atomic_clear_long_excl
#define	membar_enter		_membar_enter
#define	membar_exit		_membar_exit
#define	membar_producer		_membar_producer
#define	membar_consumer		_membar_consumer
