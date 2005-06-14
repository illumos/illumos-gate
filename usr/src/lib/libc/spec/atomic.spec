#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

function	atomic_inc_8
include		<atomic.h>
declaration	void atomic_inc_8(volatile uint8_t *)
version		SUNW_1.22.1
end

function	_atomic_inc_8
weak		atomic_inc_8
version		SUNWprivate_1.1
end

function	atomic_inc_uchar
include		<atomic.h>
declaration	void atomic_inc_uchar(volatile uchar_t *)
version		SUNW_1.22.1
end

function	_atomic_inc_uchar
weak		atomic_inc_uchar
version		SUNWprivate_1.1
end

function	atomic_inc_16
include		<atomic.h>
declaration	void atomic_inc_16(volatile uint16_t *)
version		SUNW_1.22.1
end

function	_atomic_inc_16
weak		atomic_inc_16
version		SUNWprivate_1.1
end

function	atomic_inc_ushort
include		<atomic.h>
declaration	void atomic_inc_ushort(volatile ushort_t *)
version		SUNW_1.22.1
end

function	_atomic_inc_ushort
weak		atomic_inc_ushort
version		SUNWprivate_1.1
end

function	atomic_inc_32
include		<atomic.h>
declaration	void atomic_inc_32(volatile uint32_t *)
version		SUNW_1.22.1
end

function	_atomic_inc_32
weak		atomic_inc_32
version		SUNWprivate_1.1
end

function	atomic_inc_uint
include		<atomic.h>
declaration	void atomic_inc_uint(volatile uint_t *)
version		SUNW_1.22.1
end

function	_atomic_inc_uint
weak		atomic_inc_uint
version		SUNWprivate_1.1
end

function	atomic_inc_ulong
include		<atomic.h>
declaration	void atomic_inc_ulong(volatile ulong_t *)
version		SUNW_1.22.1
end

function	_atomic_inc_ulong
weak		atomic_inc_ulong
version		SUNWprivate_1.1
end

function	atomic_inc_64
include		<atomic.h>
declaration	void atomic_inc_64(volatile uint64_t *)
version		SUNW_1.22.1
end

function	_atomic_inc_64
weak		atomic_inc_64
version		SUNWprivate_1.1
end

function	atomic_dec_8
include		<atomic.h>
declaration	void atomic_dec_8(volatile uint8_t *)
version		SUNW_1.22.1
end

function	_atomic_dec_8
weak		atomic_dec_8
version		SUNWprivate_1.1
end

function	atomic_dec_uchar
include		<atomic.h>
declaration	void atomic_dec_uchar(volatile uchar_t *)
version		SUNW_1.22.1
end

function	_atomic_dec_uchar
weak		atomic_dec_uchar
version		SUNWprivate_1.1
end

function	atomic_dec_16
include		<atomic.h>
declaration	void atomic_dec_16(volatile uint16_t *)
version		SUNW_1.22.1
end

function	_atomic_dec_16
weak		atomic_dec_16
version		SUNWprivate_1.1
end

function	atomic_dec_ushort
include		<atomic.h>
declaration	void atomic_dec_ushort(volatile ushort_t *)
version		SUNW_1.22.1
end

function	_atomic_dec_ushort
weak		atomic_dec_ushort
version		SUNWprivate_1.1
end

function	atomic_dec_32
include		<atomic.h>
declaration	void atomic_dec_32(volatile uint32_t *)
version		SUNW_1.22.1
end

function	_atomic_dec_32
weak		atomic_dec_32
version		SUNWprivate_1.1
end

function	atomic_dec_uint
include		<atomic.h>
declaration	void atomic_dec_uint(volatile uint_t *)
version		SUNW_1.22.1
end

function	_atomic_dec_uint
weak		atomic_dec_uint
version		SUNWprivate_1.1
end

function	atomic_dec_ulong
include		<atomic.h>
declaration	void atomic_dec_ulong(volatile ulong_t *)
version		SUNW_1.22.1
end

function	_atomic_dec_ulong
weak		atomic_dec_ulong
version		SUNWprivate_1.1
end

function	atomic_dec_64
include		<atomic.h>
declaration	void atomic_dec_64(volatile uint64_t *)
version		SUNW_1.22.1
end

function	_atomic_dec_64
weak		atomic_dec_64
version		SUNWprivate_1.1
end

function	atomic_add_8
include		<atomic.h>
declaration	void atomic_add_8(volatile uint8_t *, int8_t)
version		SUNW_1.22.1
end

function	_atomic_add_8
weak		atomic_add_8
version		SUNWprivate_1.1
end

function	atomic_add_char
include		<atomic.h>
declaration	void atomic_add_char(volatile uint8_t *, signed char)
version		SUNW_1.22.1
end

function	_atomic_add_char
weak		atomic_add_char
version		SUNWprivate_1.1
end

function	atomic_add_16
include		<atomic.h>
declaration	void atomic_add_16(volatile uint16_t *, int16_t)
version		SUNW_1.22
end

function	_atomic_add_16
weak		atomic_add_16
version		SUNWprivate_1.1
end

function	atomic_add_short
include		<atomic.h>
declaration	void atomic_add_short(volatile ushort_t *, short)
version		SUNW_1.22.1
end

function	_atomic_add_short
weak		atomic_add_short
version		SUNWprivate_1.1
end

function	atomic_add_32
include		<atomic.h>
declaration	void atomic_add_32(volatile uint32_t *, int32_t)
version		SUNW_1.22
end

function	_atomic_add_32
weak		atomic_add_32
version		SUNWprivate_1.1
end

function	atomic_add_int
include		<atomic.h>
declaration	void atomic_add_int(volatile uint_t *, int)
version		SUNW_1.22.1
end

function	_atomic_add_int
weak		atomic_add_int
version		SUNWprivate_1.1
end

function	atomic_add_ptr
include		<atomic.h>
declaration	void atomic_add_ptr(volatile void *, ssize_t)
version		SUNW_1.22.1
end

function	_atomic_add_ptr
weak		atomic_add_ptr
version		SUNWprivate_1.1
end

function	atomic_add_long
include		<atomic.h>
declaration	void atomic_add_long(volatile ulong_t *, long)
version		SUNW_1.22
end

function	_atomic_add_long
weak		atomic_add_long
version		SUNWprivate_1.1
end

function	atomic_add_64
include		<atomic.h>
declaration	void atomic_add_64(volatile uint64_t *, int64_t)
version		SUNW_1.22
end

function	_atomic_add_64
weak		atomic_add_64
version		SUNWprivate_1.1
end

function	atomic_or_8
include		<atomic.h>
declaration	void atomic_or_8(volatile uint8_t *, uint8_t)
version		SUNW_1.22.1
end

function	_atomic_or_8
weak		atomic_or_8
version		SUNWprivate_1.1
end

function	atomic_or_uchar
include		<atomic.h>
declaration	void atomic_or_uchar(volatile uchar_t *, uchar_t)
version		SUNW_1.22.1
end

function	_atomic_or_uchar
weak		atomic_or_uchar
version		SUNWprivate_1.1
end

function	atomic_or_16
include		<atomic.h>
declaration	void atomic_or_16(volatile uint16_t *, uint16_t)
version		SUNW_1.22.1
end

function	_atomic_or_16
weak		atomic_or_16
version		SUNWprivate_1.1
end

function	atomic_or_ushort
include		<atomic.h>
declaration	void atomic_or_ushort(volatile ushort_t *, ushort_t)
version		SUNW_1.22.1
end

function	_atomic_or_ushort
weak		atomic_or_ushort
version		SUNWprivate_1.1
end

function	atomic_or_32
include		<atomic.h>
declaration	void atomic_or_32(volatile uint32_t *, uint32_t)
version		SUNW_1.22
end

function	_atomic_or_32
weak		atomic_or_32
version		SUNWprivate_1.1
end

function	atomic_or_uint
include		<atomic.h>
declaration	void atomic_or_uint(volatile uint_t *, uint_t)
version		SUNW_1.22
end

function	_atomic_or_uint
weak		atomic_or_uint
version		SUNWprivate_1.1
end

function	atomic_or_ulong
include		<atomic.h>
declaration	void atomic_or_ulong(volatile ulong_t *, ulong_t)
version		SUNW_1.22.1
end

function	_atomic_or_ulong
weak		atomic_or_ulong
version		SUNWprivate_1.1
end

function	atomic_or_64
include		<atomic.h>
declaration	void atomic_or_64(volatile uint64_t *, uint64_t)
version		SUNW_1.22.1
end

function	_atomic_or_64
weak		atomic_or_64
version		SUNWprivate_1.1
end

function	atomic_and_8
include		<atomic.h>
declaration	void atomic_and_8(volatile uint8_t *, uint8_t)
version		SUNW_1.22.1
end

function	_atomic_and_8
weak		atomic_and_8
version		SUNWprivate_1.1
end

function	atomic_and_uchar
include		<atomic.h>
declaration	void atomic_and_uchar(volatile uchar_t *, uchar_t)
version		SUNW_1.22.1
end

function	_atomic_and_uchar
weak		atomic_and_uchar
version		SUNWprivate_1.1
end

function	atomic_and_16
include		<atomic.h>
declaration	void atomic_and_16(volatile uint16_t *, uint16_t)
version		SUNW_1.22.1
end

function	_atomic_and_16
weak		atomic_and_16
version		SUNWprivate_1.1
end

function	atomic_and_ushort
include		<atomic.h>
declaration	void atomic_and_ushort(volatile ushort_t *, ushort_t)
version		SUNW_1.22.1
end

function	_atomic_and_ushort
weak		atomic_and_ushort
version		SUNWprivate_1.1
end

function	atomic_and_32
include		<atomic.h>
declaration	void atomic_and_32(volatile uint32_t *, uint32_t)
version		SUNW_1.22
end

function	_atomic_and_32
weak		atomic_and_32
version		SUNWprivate_1.1
end

function	atomic_and_uint
include		<atomic.h>
declaration	void atomic_and_uint(volatile uint_t *, uint_t)
version		SUNW_1.22
end

function	_atomic_and_uint
weak		atomic_and_uint
version		SUNWprivate_1.1
end

function	atomic_and_ulong
include		<atomic.h>
declaration	void atomic_and_ulong(volatile ulong_t *, ulong_t)
version		SUNW_1.22.1
end

function	_atomic_and_ulong
weak		atomic_and_ulong
version		SUNWprivate_1.1
end

function	atomic_and_64
include		<atomic.h>
declaration	void atomic_and_64(volatile uint64_t *, uint64_t)
version		SUNW_1.22.1
end

function	_atomic_and_64
weak		atomic_and_64
version		SUNWprivate_1.1
end

function	atomic_inc_8_nv
include		<atomic.h>
declaration	uint8_t atomic_inc_8_nv(volatile uint8_t *)
version		SUNW_1.22.1
end

function	_atomic_inc_8_nv
weak		atomic_inc_8_nv
version		SUNWprivate_1.1
end

function	atomic_inc_uchar_nv
include		<atomic.h>
declaration	uchar_t atomic_inc_uchar_nv(volatile uchar_t *)
version		SUNW_1.22.1
end

function	_atomic_inc_uchar_nv
weak		atomic_inc_uchar_nv
version		SUNWprivate_1.1
end

function	atomic_inc_16_nv
include		<atomic.h>
declaration	uint16_t atomic_inc_16_nv(volatile uint16_t *)
version		SUNW_1.22.1
end

function	_atomic_inc_16_nv
weak		atomic_inc_16_nv
version		SUNWprivate_1.1
end

function	atomic_inc_ushort_nv
include		<atomic.h>
declaration	ushort_t atomic_inc_ushort_nv(volatile ushort_t *)
version		SUNW_1.22.1
end

function	_atomic_inc_ushort_nv
weak		atomic_inc_ushort_nv
version		SUNWprivate_1.1
end

function	atomic_inc_32_nv
include		<atomic.h>
declaration	uint32_t atomic_inc_32_nv(volatile uint32_t *)
version		SUNW_1.22.1
end

function	_atomic_inc_32_nv
weak		atomic_inc_32_nv
version		SUNWprivate_1.1
end

function	atomic_inc_uint_nv
include		<atomic.h>
declaration	uint_t atomic_inc_uint_nv(volatile uint_t *)
version		SUNW_1.22.1
end

function	_atomic_inc_uint_nv
weak		atomic_inc_uint_nv
version		SUNWprivate_1.1
end

function	atomic_inc_ulong_nv
include		<atomic.h>
declaration	ulong_t atomic_inc_ulong_nv(volatile ulong_t *)
version		SUNW_1.22.1
end

function	_atomic_inc_ulong_nv
weak		atomic_inc_ulong_nv
version		SUNWprivate_1.1
end

function	atomic_inc_64_nv
include		<atomic.h>
declaration	uint64_t atomic_inc_64_nv(volatile uint64_t *)
version		SUNW_1.22.1
end

function	_atomic_inc_64_nv
weak		atomic_inc_64_nv
version		SUNWprivate_1.1
end

function	atomic_dec_8_nv
include		<atomic.h>
declaration	uint8_t atomic_dec_8_nv(volatile uint8_t *)
version		SUNW_1.22.1
end

function	_atomic_dec_8_nv
weak		atomic_dec_8_nv
version		SUNWprivate_1.1
end

function	atomic_dec_uchar_nv
include		<atomic.h>
declaration	uchar_t atomic_dec_uchar_nv(volatile uchar_t *)
version		SUNW_1.22.1
end

function	_atomic_dec_uchar_nv
weak		atomic_dec_uchar_nv
version		SUNWprivate_1.1
end

function	atomic_dec_16_nv
include		<atomic.h>
declaration	uint16_t atomic_dec_16_nv(volatile uint16_t *)
version		SUNW_1.22.1
end

function	_atomic_dec_16_nv
weak		atomic_dec_16_nv
version		SUNWprivate_1.1
end

function	atomic_dec_ushort_nv
include		<atomic.h>
declaration	ushort_t atomic_dec_ushort_nv(volatile ushort_t *)
version		SUNW_1.22.1
end

function	_atomic_dec_ushort_nv
weak		atomic_dec_ushort_nv
version		SUNWprivate_1.1
end

function	atomic_dec_32_nv
include		<atomic.h>
declaration	uint32_t atomic_dec_32_nv(volatile uint32_t *)
version		SUNW_1.22.1
end

function	_atomic_dec_32_nv
weak		atomic_dec_32_nv
version		SUNWprivate_1.1
end

function	atomic_dec_uint_nv
include		<atomic.h>
declaration	uint_t atomic_dec_uint_nv(volatile uint_t *)
version		SUNW_1.22.1
end

function	_atomic_dec_uint_nv
weak		atomic_dec_uint_nv
version		SUNWprivate_1.1
end

function	atomic_dec_ulong_nv
include		<atomic.h>
declaration	ulong_t atomic_dec_ulong_nv(volatile ulong_t *)
version		SUNW_1.22.1
end

function	_atomic_dec_ulong_nv
weak		atomic_dec_ulong_nv
version		SUNWprivate_1.1
end

function	atomic_dec_64_nv
include		<atomic.h>
declaration	uint64_t atomic_dec_64_nv(volatile uint64_t *)
version		SUNW_1.22.1
end

function	_atomic_dec_64_nv
weak		atomic_dec_64_nv
version		SUNWprivate_1.1
end

function	atomic_add_8_nv
include		<atomic.h>
declaration	uint8_t atomic_add_8_nv(volatile uint8_t *, int8_t)
version		SUNW_1.22.1
end

function	_atomic_add_8_nv
weak		atomic_add_8_nv
version		SUNWprivate_1.1
end

function	atomic_add_char_nv
include		<atomic.h>
declaration	uchar_t atomic_add_char_nv(volatile uchar_t *, signed char)
version		SUNW_1.22.1
end

function	_atomic_add_char_nv
weak		atomic_add_char_nv
version		SUNWprivate_1.1
end

function	atomic_add_16_nv
include		<atomic.h>
declaration	uint16_t atomic_add_16_nv(volatile uint16_t *, int16_t)
version		SUNW_1.22
end

function	_atomic_add_16_nv
weak		atomic_add_16_nv
version		SUNWprivate_1.1
end

function	atomic_add_short_nv
include		<atomic.h>
declaration	ushort_t atomic_add_short_nv(volatile ushort_t *, short)
version		SUNW_1.22.1
end

function	_atomic_add_short_nv
weak		atomic_add_short_nv
version		SUNWprivate_1.1
end

function	atomic_add_32_nv
include		<atomic.h>
declaration	uint32_t atomic_add_32_nv(volatile uint32_t *, int32_t)
version		SUNW_1.22
end

function	_atomic_add_32_nv
weak		atomic_add_32_nv
version		SUNWprivate_1.1
end

function	atomic_add_int_nv
include		<atomic.h>
declaration	uint_t atomic_add_int_nv(volatile uint_t *, int)
version		SUNW_1.22.1
end

function	_atomic_add_int_nv
weak		atomic_add_int_nv
version		SUNWprivate_1.1
end

function	atomic_add_ptr_nv
include		<atomic.h>
declaration	void *atomic_add_ptr_nv(volatile void *, ssize_t)
version		SUNW_1.22.1
end

function	_atomic_add_ptr_nv
weak		atomic_add_ptr_nv
version		SUNWprivate_1.1
end

function	atomic_add_long_nv
include		<atomic.h>
declaration	ulong_t atomic_add_long_nv(volatile ulong_t *, long)
version		SUNW_1.22
end

function	_atomic_add_long_nv
weak		atomic_add_long_nv
version		SUNWprivate_1.1
end

function	atomic_add_64_nv
include		<atomic.h>
declaration	uint64_t atomic_add_64_nv(volatile uint64_t *, int64_t)
version		SUNW_1.22
end

function	_atomic_add_64_nv
weak		atomic_add_64_nv
version		SUNWprivate_1.1
end

function	atomic_or_8_nv
include		<atomic.h>
declaration	uint8_t atomic_or_8_nv(volatile uint8_t *, uint8_t)
version		SUNW_1.22.1
end

function	_atomic_or_8_nv
weak		atomic_or_8_nv
version		SUNWprivate_1.1
end

function	atomic_or_uchar_nv
include		<atomic.h>
declaration	uchar_t atomic_or_uchar_nv(volatile uchar_t *, uchar_t)
version		SUNW_1.22.1
end

function	_atomic_or_uchar_nv
weak		atomic_or_uchar_nv
version		SUNWprivate_1.1
end

function	atomic_or_16_nv
include		<atomic.h>
declaration	uint16_t atomic_or_16_nv(volatile uint16_t *, uint16_t)
version		SUNW_1.22.1
end

function	_atomic_or_16_nv
weak		atomic_or_16_nv
version		SUNWprivate_1.1
end

function	atomic_or_ushort_nv
include		<atomic.h>
declaration	ushort_t atomic_or_ushort_nv(volatile ushort_t *, ushort_t)
version		SUNW_1.22.1
end

function	_atomic_or_ushort_nv
weak		atomic_or_ushort_nv
version		SUNWprivate_1.1
end

function	atomic_or_32_nv
include		<atomic.h>
declaration	uint32_t atomic_or_32_nv(volatile uint32_t *, uint32_t)
version		SUNW_1.22.1
end

function	_atomic_or_32_nv
weak		atomic_or_32_nv
version		SUNWprivate_1.1
end

function	atomic_or_uint_nv
include		<atomic.h>
declaration	uint_t atomic_or_uint_nv(volatile uint_t *, uint_t)
version		SUNW_1.22.1
end

function	_atomic_or_uint_nv
weak		atomic_or_uint_nv
version		SUNWprivate_1.1
end

function	atomic_or_ulong_nv
include		<atomic.h>
declaration	ulong_t atomic_or_ulong_nv(volatile ulong_t *, ulong_t)
version		SUNW_1.22.1
end

function	_atomic_or_ulong_nv
weak		atomic_or_ulong_nv
version		SUNWprivate_1.1
end

function	atomic_or_64_nv
include		<atomic.h>
declaration	uint64_t atomic_or_64_nv(volatile uint64_t *, uint64_t)
version		SUNW_1.22.1
end

function	_atomic_or_64_nv
weak		atomic_or_64_nv
version		SUNWprivate_1.1
end

function	atomic_and_8_nv
include		<atomic.h>
declaration	uint8_t atomic_and_8_nv(volatile uint8_t *, uint8_t)
version		SUNW_1.22.1
end

function	_atomic_and_8_nv
weak		atomic_and_8_nv
version		SUNWprivate_1.1
end

function	atomic_and_uchar_nv
include		<atomic.h>
declaration	uchar_t atomic_and_uchar_nv(volatile uchar_t *, uchar_t)
version		SUNW_1.22.1
end

function	_atomic_and_uchar_nv
weak		atomic_and_uchar_nv
version		SUNWprivate_1.1
end

function	atomic_and_16_nv
include		<atomic.h>
declaration	uint16_t atomic_and_16_nv(volatile uint16_t *, uint16_t)
version		SUNW_1.22.1
end

function	_atomic_and_16_nv
weak		atomic_and_16_nv
version		SUNWprivate_1.1
end

function	atomic_and_ushort_nv
include		<atomic.h>
declaration	ushort_t atomic_and_ushort_nv(volatile ushort_t *, ushort_t)
version		SUNW_1.22.1
end

function	_atomic_and_ushort_nv
weak		atomic_and_ushort_nv
version		SUNWprivate_1.1
end

function	atomic_and_32_nv
include		<atomic.h>
declaration	uint32_t atomic_and_32_nv(volatile uint32_t *, uint32_t)
version		SUNW_1.22.1
end

function	_atomic_and_32_nv
weak		atomic_and_32_nv
version		SUNWprivate_1.1
end

function	atomic_and_uint_nv
include		<atomic.h>
declaration	uint_t atomic_and_uint_nv(volatile uint_t *, uint_t)
version		SUNW_1.22.1
end

function	_atomic_and_uint_nv
weak		atomic_and_uint_nv
version		SUNWprivate_1.1
end

function	atomic_and_ulong_nv
include		<atomic.h>
declaration	ulong_t atomic_and_ulong_nv(volatile ulong_t *, ulong_t)
version		SUNW_1.22.1
end

function	_atomic_and_ulong_nv
weak		atomic_and_ulong_nv
version		SUNWprivate_1.1
end

function	atomic_and_64_nv
include		<atomic.h>
declaration	uint64_t atomic_and_64_nv(volatile uint64_t *, uint64_t)
version		SUNW_1.22.1
end

function	_atomic_and_64_nv
weak		atomic_and_64_nv
version		SUNWprivate_1.1
end

function	atomic_cas_8
include		<atomic.h>
declaration	uint8_t atomic_cas_8(volatile uint8_t *, uint8_t, uint8_t)
version		SUNW_1.22.1
end

function	_atomic_cas_8
weak		atomic_cas_8
version		SUNWprivate_1.1
end

function	atomic_cas_uchar
include		<atomic.h>
declaration	uchar_t atomic_cas_uchar(volatile uchar_t *, uchar_t, uchar_t)
version		SUNW_1.22.1
end

function	_atomic_cas_uchar
weak		atomic_cas_uchar
version		SUNWprivate_1.1
end

function	atomic_cas_16
include		<atomic.h>
declaration	uint16_t atomic_cas_16(volatile uint16_t *, uint16_t, uint16_t)
version		SUNW_1.22.1
end

function	_atomic_cas_16
weak		atomic_cas_16
version		SUNWprivate_1.1
end

function	atomic_cas_ushort
include		<atomic.h>
declaration	ushort_t atomic_cas_ushort(volatile ushort_t *, ushort_t, ushort_t)
version		SUNW_1.22.1
end

function	_atomic_cas_ushort
weak		atomic_cas_ushort
version		SUNWprivate_1.1
end

function	atomic_cas_32
include		<atomic.h>
declaration	uint32_t atomic_cas_32(volatile uint32_t *, uint32_t, uint32_t)
version		SUNW_1.22.1
end

function	_atomic_cas_32
weak		atomic_cas_32
version		SUNWprivate_1.1
end

function	atomic_cas_uint
include		<atomic.h>
declaration	uint32_t atomic_cas_uint(volatile uint_t *, uint_t, uint_t)
version		SUNW_1.22.1
end

function	_atomic_cas_uint
weak		atomic_cas_uint
version		SUNWprivate_1.1
end

function	atomic_cas_ptr
include		<atomic.h>
declaration	void *atomic_cas_ptr(volatile void *, void *, void *)
version		SUNW_1.22.1
end

function	_atomic_cas_ptr
weak		atomic_cas_ptr
version		SUNWprivate_1.1
end

function	atomic_cas_ulong
include		<atomic.h>
declaration	ulong_t atomic_cas_ulong(volatile ulong_t *, ulong_t, ulong_t)
version		SUNW_1.22.1
end

function	_atomic_cas_ulong
weak		atomic_cas_ulong
version		SUNWprivate_1.1
end

function	atomic_cas_64
include		<atomic.h>
declaration	uint64_t atomic_cas_64(volatile uint64_t *, uint64_t, uint64_t)
version		SUNW_1.22.1
end

function	_atomic_cas_64
weak		atomic_cas_64
version		SUNWprivate_1.1
end

function	atomic_swap_8
include		<atomic.h>
declaration	uint8_t atomic_swap_8(volatile uint8_t *, uint8_t)
version		SUNW_1.22.1
end

function	_atomic_swap_8
weak		atomic_swap_8
version		SUNWprivate_1.1
end

function	atomic_swap_uchar
include		<atomic.h>
declaration	uchar_t atomic_swap_uchar(volatile uchar_t *, uchar_t)
version		SUNW_1.22.1
end

function	_atomic_swap_uchar
weak		atomic_swap_uchar
version		SUNWprivate_1.1
end

function	atomic_swap_16
include		<atomic.h>
declaration	uint16_t atomic_swap_16(volatile uint16_t *, uint16_t)
version		SUNW_1.22.1
end

function	_atomic_swap_16
weak		atomic_swap_16
version		SUNWprivate_1.1
end

function	atomic_swap_ushort
include		<atomic.h>
declaration	ushort_t atomic_swap_ushort(volatile ushort_t *, ushort_t)
version		SUNW_1.22.1
end

function	_atomic_swap_ushort
weak		atomic_swap_ushort
version		SUNWprivate_1.1
end

function	atomic_swap_32
include		<atomic.h>
declaration	uint32_t atomic_swap_32(volatile uint32_t *, uint32_t)
version		SUNW_1.22.1
end

function	_atomic_swap_32
weak		atomic_swap_32
version		SUNWprivate_1.1
end

function	atomic_swap_uint
include		<atomic.h>
declaration	uint32_t atomic_swap_uint(volatile uint_t *, uint_t)
version		SUNW_1.22.1
end

function	_atomic_swap_uint
weak		atomic_swap_uint
version		SUNWprivate_1.1
end

function	atomic_swap_ptr
include		<atomic.h>
declaration	void *atomic_swap_ptr(volatile void *, void *)
version		SUNW_1.22.1
end

function	_atomic_swap_ptr
weak		atomic_swap_ptr
version		SUNWprivate_1.1
end

function	atomic_swap_ulong
include		<atomic.h>
declaration	ulong_t atomic_swap_ulong(volatile ulong_t *, ulong_t)
version		SUNW_1.22.1
end

function	_atomic_swap_ulong
weak		atomic_swap_ulong
version		SUNWprivate_1.1
end

function	atomic_swap_64
include		<atomic.h>
declaration	uint64_t atomic_swap_64(volatile uint64_t *, uint64_t)
version		SUNW_1.22.1
end

function	_atomic_swap_64
weak		atomic_swap_64
version		SUNWprivate_1.1
end

function	atomic_set_long_excl
include		<atomic.h>
declaration	int atomic_set_long_excl(volatile ulong_t *, uint_t)
version		SUNW_1.22.1
end

function	_atomic_set_long_excl
weak		atomic_set_long_excl
version		SUNWprivate_1.1
end

function	atomic_clear_long_excl
include		<atomic.h>
declaration	int atomic_clear_long_excl(volatile ulong_t *, uint_t)
version		SUNW_1.22.1
end

function	_atomic_clear_long_excl
weak		atomic_clear_long_excl
version		SUNWprivate_1.1
end

function	membar_enter
include		<atomic.h>
declaration	void membar_enter(void)
version		SUNW_1.22.1
end

function	_membar_enter
weak		membar_enter
version		SUNWprivate_1.1
end

function	membar_exit
include		<atomic.h>
declaration	void membar_exit(void)
version		SUNW_1.22.1
end

function	_membar_exit
weak		membar_exit
version		SUNWprivate_1.1
end

function	membar_producer
include		<atomic.h>
declaration	void membar_producer(void)
version		SUNW_1.22.1
end

function	_membar_producer
weak		membar_producer
version		SUNWprivate_1.1
end

function	membar_consumer
include		<atomic.h>
declaration	void membar_consumer(void)
version		SUNW_1.22.1
end

function	_membar_consumer
weak		membar_consumer
version		SUNWprivate_1.1
end

