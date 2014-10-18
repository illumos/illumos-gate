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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _COMPLEX_WRAPPER_H
#define	_COMPLEX_WRAPPER_H

#pragma ident	"@(#)complex_wrapper.h	1.7	06/01/31 SMI"

#if defined(__GNUC__)
#define dcomplex double _Complex
#define fcomplex float _Complex
#define ldcomplex long double _Complex
#define D_RE(x) __real__ x
#define D_IM(x) __imag__ x
#define F_RE(x) __real__ x
#define F_IM(x) __imag__ x
#define LD_RE(x) __real__ x
#define LD_IM(x) __imag__ x

#include <complex.h>
#else

#define	dcomplex	double complex
#define	fcomplex	float complex
#define	ldcomplex	long double complex
#define	_X_RE(__t, __z)	((__t *) &__z)[0]
#define	_X_IM(__t, __z)	((__t *) &__z)[1]
#define	D_RE(__z)	_X_RE(double, __z)
#define	D_IM(__z)	_X_IM(double, __z)
#define	F_RE(__z)	_X_RE(float, __z)
#define	F_IM(__z)	_X_IM(float, __z)
#define	LD_RE(__z)	_X_RE(long double, __z)
#define	LD_IM(__z)	_X_IM(long double, __z)

#include <complex.h>
#endif

#if defined(__sparc)
#define	HIWORD	0
#define	LOWORD	1
#define	HI_XWORD(x)	((unsigned *) &x)[0]
#define	XFSCALE(x, n)	((unsigned *) &x)[0] += n << 16	/* signbitl(x) == 0 */
#define	CHOPPED(x)	((long double) ((double) (x)))
#elif defined(__x86)
#define	HIWORD	1
#define	LOWORD	0
#define	HI_XWORD(x)	((((int *) &x)[2] << 16) | \
			(0xffff & ((unsigned *) &x)[1] >> 15))
#define	XFSCALE(x, n)	((unsigned short *) &x)[4] += n	/* signbitl(x) == 0 */
#define	CHOPPED(x)	((long double) ((float) (x)))
#else
#error Unknown architecture
#endif
#define	HI_WORD(x)	((int *) &x)[HIWORD]	/* for double */
#define	LO_WORD(x)	((int *) &x)[LOWORD]	/* for double */
#define	THE_WORD(x)	((int *) &x)[0]		/* for float */

/*
 * iy:ly must have the sign bit already cleared
 */
#define	ISINF(iy, ly)	(((iy - 0x7ff00000) | ly) == 0)

#endif	/* _COMPLEX_WRAPPER_H */
