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
 *	Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

#include "libtnf.h"

/*
 *
 */

#define	CHECK_SCALAR(datum)	check_scalar(datum)

#define	DATUM_NATIVE(x)		DATUM_TNF(datum)->file_native

/*
 *
 */

static void		check_scalar(tnf_datum_t);

static tnf_uint64_t	get_uint64(TNF *tnf, caddr_t val);

/*
 *
 */

static void
check_scalar(tnf_datum_t datum)
{
	CHECK_DATUM(datum);
	if (!INFO_SCALAR(DATUM_INFO(datum)))
		_tnf_error(DATUM_TNF(datum), TNF_ERR_TYPEMISMATCH);
	/* XXX Need to check for exact scalar type match as well */
}

/*
 * Exported scalar operations
 */

/* No swapping required: */

char
tnf_get_char(tnf_datum_t datum)
{
	CHECK_SCALAR(datum);
	return (*(char *)DATUM_VAL(datum));
}

tnf_int8_t
tnf_get_int8(tnf_datum_t datum)
{
	CHECK_SCALAR(datum);
	return (*(tnf_int8_t *)DATUM_VAL(datum));
}

tnf_int16_t
tnf_get_int16(tnf_datum_t datum)
{
	tnf_int16_t	val;

	CHECK_SCALAR(datum);
	/* LINTED pointer cast may result in improper alignment */
	val = *(tnf_int16_t *)DATUM_VAL(datum);
	return (DATUM_NATIVE(datum) ? val : _tnf_swap16(val));
}

/* 32-bit integers: */

tnf_int32_t
tnf_get_int32(tnf_datum_t datum)
{
	CHECK_SCALAR(datum);
	/* LINTED pointer cast may result in improper alignment */
	return (_GET_INT32(DATUM_TNF(datum), DATUM_VAL(datum)));
}

/* 64-bit integers: */

static tnf_uint64_t
get_uint64(TNF *tnf, caddr_t val)
{
	tnf_uint32_t	hi32, lo32; /* XXX both assumed unsigned */

	/* XXX Can't rely on address alignment */
	/* LINTED pointer cast may result in improper alignment */
	hi32 = *(tnf_uint32_t *)val;
	/* LINTED pointer cast may result in improper alignment */
	lo32 = *(tnf_uint32_t *)(val + sizeof (tnf_uint32_t));

#ifdef _LONG_LONG_HTOL
	/* eg. sparc */
	if (tnf->file_native)
		return ((((tnf_uint64_t)hi32) << 32)
			+ (tnf_uint64_t)lo32);
	else
		/* XXX Assume words are swapped as well: */
		return ((((tnf_uint64_t)_tnf_swap32(lo32)) << 32)
			+ (tnf_uint64_t)_tnf_swap32(hi32));
#else
	/* eg. i386 */
	if (tnf->file_native)
		return ((((tnf_uint64_t)lo32) << 32)
			+ (tnf_uint64_t)hi32);
	else
		/* XXX Assume words are swapped as well: */
		return ((((tnf_uint64_t)_tnf_swap32(hi32)) << 32)
			+ (tnf_uint64_t)_tnf_swap32(lo32));
#endif
}

tnf_int64_t
tnf_get_int64(tnf_datum_t datum)
{
	CHECK_SCALAR(datum);
	return (get_uint64(DATUM_TNF(datum), DATUM_VAL(datum)));
}

/* floats: */

tnf_float32_t
tnf_get_float32(tnf_datum_t datum)
{
	union {
		tnf_uint32_t	i32;
		tnf_float32_t	f32;
	} u;

	CHECK_SCALAR(datum);

	/* LINTED pointer cast may result in improper alignment */
	u.i32 = _GET_UINT32(DATUM_TNF(datum), DATUM_VAL(datum)); /* XXX */
	return (u.f32);
}

tnf_float64_t
tnf_get_float64(tnf_datum_t datum)
{
	union {
		tnf_uint64_t	i64;
		tnf_float64_t	f64;
	} u;

	CHECK_SCALAR(datum);

	u.i64 = get_uint64(DATUM_TNF(datum), DATUM_VAL(datum)); /* XXX */
	return (u.f64);
}
