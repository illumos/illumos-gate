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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All Rights Reserved
 */

#ifndef _NAN_H
#define	_NAN_H

/*
 * Handling of Not_a_Number's (only in IEEE floating-point standard)
 */

#include <sys/isa_defs.h>
#include <values.h>

#ifdef	__cplusplus
extern "C" {
#endif

#if defined(_IEEE_754)
/*
 * Structure order is endian dependent.  Only the common variants of
 * big and little endian are supported.
 */

#if defined(_BIG_ENDIAN)

typedef union
{
	struct
	{
		unsigned sign		: 1;
		unsigned exponent	:11;
		unsigned bits		:20;
		unsigned fraction_low	:32;
	} inf_parts;
	struct
	{
		unsigned sign		: 1;
		unsigned exponent	:11;
		unsigned qnan_bit	: 1;
		unsigned bits		:19;
		unsigned fraction_low	:32;
	} nan_parts;
	double d;

} dnan;

#else	/* Must be _LITTLE_ENDIAN */

typedef union
{
	struct {
		unsigned fraction_low	:32;
		unsigned bits		:20;
		unsigned exponent	:11;
		unsigned sign		: 1;
	} inf_parts;
	struct {
		unsigned fraction_low	:32;
		unsigned bits		:19;
		unsigned qnan_bit	: 1;
		unsigned exponent	:11;
		unsigned sign		: 1;
	} nan_parts;
	double d;
} dnan;

#endif	/* Endian based selection */

/*
 * IsNANorINF checks that exponent of double == 2047
 * i.e. that number is a NaN or an infinity
 */
#define	IsNANorINF(X)  (((dnan *)&(X))->nan_parts.exponent == 0x7ff)

/*
 * IsINF must be used after IsNANorINF has checked the exponent
 */
#define	IsINF(X)	(((dnan *)&(X))->inf_parts.bits == 0 && \
			    ((dnan *)&(X))->inf_parts.fraction_low == 0)

/*
 * IsPosNAN and IsNegNAN can be used to check the sign of infinities too
 */
#define	IsPosNAN(X)	(((dnan *)&(X))->nan_parts.sign == 0)

#define	IsNegNAN(X)	(((dnan *)&(X))->nan_parts.sign == 1)

/*
 * GETNaNPC gets the leftmost 32 bits of the fraction part
 */
#define	GETNaNPC(dval)	(((dnan *)&(dval))->inf_parts.bits << 12 | \
			    ((dnan *)&(dval))->nan_parts.fraction_low >> 20)

#define	KILLFPE()	(void) _kill(_getpid(), 8)
#define	NaN(X)		(((dnan *)&(X))->nan_parts.exponent == 0x7ff)
#define	KILLNaN(X)	if (NaN(X)) KILLFPE()

#else	/* defined(_IEEE_754) */
/* #error is strictly ansi-C, but works as well as anything for K&R systems. */
#error ISA not supported
#endif	/* defined(_IEEE_754) */

#ifdef	__cplusplus
}
#endif

#endif	/* _NAN_H */
