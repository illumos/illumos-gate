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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * _D_cplx_lr_div_rx(a, w) returns a / w computed by the textbook
 * formula without regard to exceptions or special cases.
 *
 * This code is intended to be used only when CX_LIMITED_RANGE is
 * ON; otherwise use _D_cplx_div_rx.
 */

#if !defined(i386) && !defined(__i386) && !defined(__amd64)
#error This code is for x86 only
#endif

double _Complex
_D_cplx_lr_div_rx(double a, double _Complex w)
{
	double _Complex	v;
	long double	c, d, r;

	/* LINTED alignment */
	c = ((double *)&w)[0];
	/* LINTED alignment */
	d = ((double *)&w)[1];
	r = a / (c * c + d * d);
	/* LINTED alignment */
	((double *)&v)[0] = (double)(r * c);
	/* LINTED alignment */
	((double *)&v)[1] = (double)(r * -d);
	return (v);
}
