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
 * _F_cplx_lr_div(z, w) returns z / w computed by the textbook
 * formula without regard to exceptions or special cases.
 *
 * This code is intended to be used only when CX_LIMITED_RANGE is
 * ON; otherwise use _F_cplx_div.
 */

#if !defined(i386) && !defined(__i386) && !defined(__amd64)
#error This code is for x86 only
#endif

float _Complex
_F_cplx_lr_div(float _Complex z, float _Complex w)
{
	float _Complex	v;
	long double	a, b, c, d, r;

	a = ((float *)&z)[0];
	b = ((float *)&z)[1];
	c = ((float *)&w)[0];
	d = ((float *)&w)[1];
	r = 1.0f / (c * c + d * d);
	((float *)&v)[0] = (float)((a * c + b * d) * r);
	((float *)&v)[1] = (float)((b * c - a * d) * r);
	return (v);
}
