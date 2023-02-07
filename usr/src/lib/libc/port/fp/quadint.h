/*
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This software was developed by the Computer Systems Engineering group
 * at Lawrence Berkeley Laboratory under DARPA contract BG 91-66 and
 * contributed to Berkeley.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)quad.h	8.1 (Berkeley) 6/4/93
 */

/*
 * Quad arithmetic.
 *
 * This library makes the following assumptions:
 *
 *  - The type long long aka longlong_t exists.
 *
 *  - A quad variable is exactly twice as long as `long'.
 *
 *  - The machine's arithmetic is two's complement.
 *
 * This library can provide 128-bit arithmetic on a machine with 128-bit
 * quads and 64-bit longs, for instance, or 96-bit arithmetic on machines
 * with 48-bit longs.
 */

#ifndef __QUADINT_H
#define	__QUADINT_H

#include <sys/isa_defs.h>
#include <sys/types.h>
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Define the order of 32-bit words in 64-bit words.
 */
#ifdef _LONG_LONG_LTOH
#define	_QUAD_HIGHWORD 1
#define	_QUAD_LOWWORD 0
#else
#define	_QUAD_HIGHWORD 0
#define	_QUAD_LOWWORD 1
#endif

/*
 * Depending on the desired operation, we view a `long long' in
 * one or more of the following formats.
 */
union uu {
	longlong_t	q;		/* as a (signed) quad */
	u_longlong_t	uq;		/* as an unsigned quad */
	long		sl[2];		/* as two signed longs */
	ulong_t		ul[2];		/* as two unsigned longs */
};

/*
 * Define high and low longwords.
 */
#define	H		_QUAD_HIGHWORD
#define	L		_QUAD_LOWWORD

/*
 * Total number of bits in a longlong_t and in the pieces that make it up.
 * These are used for shifting, and also below for halfword extraction
 * and assembly.
 */
#define	QUAD_BITS	(sizeof (u_longlong_t) * CHAR_BIT)
#define	LONG_BITS	(sizeof (long) * CHAR_BIT)
#define	HALF_BITS	(sizeof (long) * CHAR_BIT / 2)

/*
 * Extract high and low shortwords from longword, and move low shortword of
 * longword to upper half of long, i.e., produce the upper longword of
 * ((longlong_t)(x) << (number_of_bits_in_long/2)).
 * (`x' must actually be ulong_t.)
 *
 * These are used in the multiply code, to split a longword into upper
 * and lower halves, and to reassemble a product as a longlong_t, shifted left
 * (sizeof(long)*CHAR_BIT/2).
 */
#define	HHALF(x)	((x) >> HALF_BITS)
#define	LHALF(x)	((x) & ((1 << HALF_BITS) - 1))
#define	LHUP(x)		((x) << HALF_BITS)

longlong_t	___divdi3(longlong_t a, longlong_t b);
longlong_t	___moddi3(longlong_t a, longlong_t b);
u_longlong_t	___qdivrem(u_longlong_t u, u_longlong_t v, u_longlong_t *rem);
u_longlong_t	___udivdi3(u_longlong_t a, u_longlong_t b);
u_longlong_t	___umoddi3(u_longlong_t a, u_longlong_t b);

typedef unsigned int	qshift_t;

#ifdef __cplusplus
}
#endif

#endif	/* !__QUADINT_H */
