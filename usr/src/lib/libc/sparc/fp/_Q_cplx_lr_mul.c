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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * On SPARC V8, _Q_cplx_lr_mul(v, z, w) sets *v = *z * *w computed by
 * the textbook formula without regard to exceptions or special cases.
 *
 * On SPARC V9, _Q_cplx_lr_mul(z, w) returns *z * *w.
 *
 * This code is intended to be used only when CX_LIMITED_RANGE is ON;
 * otherwise use _Q_cplx_mul.
 */

#if !defined(sparc) && !defined(__sparc)
#error This code is for SPARC only
#endif

#ifdef __sparcv9
long double _Complex
_Q_cplx_lr_mul(const long double _Complex *z, const long double _Complex *w)
{
	long double _Complex	v;
#else
void
_Q_cplx_lr_mul(long double _Complex *v, const long double _Complex *z,
	const long double _Complex *w)
{
#endif
	long double	a, b, c, d;

	a = ((long double *)z)[0];
	b = ((long double *)z)[1];
	c = ((long double *)w)[0];
	d = ((long double *)w)[1];

#ifdef __sparcv9
	((long double *)&v)[0] = (a * c - b * d);
	((long double *)&v)[1] = (a * d + b * c);
	return (v);
#else
	((long double *)v)[0] = (a * c - b * d);
	((long double *)v)[1] = (a * d + b * c);
#endif
}
