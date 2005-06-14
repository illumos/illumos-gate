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
#pragma ident	"%Z%%M%	%I%	%E% SMI" 

/*
 * Copyright (c) 1988 by Sun Microsystems, Inc.
 */

/*
 * Conversion between single, and extended binary and decimal
 * floating point - separated from double_to_decimal to minimize impact on
 * main(){printf("Hello");}
 */

#include "base_conversion.h"

void
single_to_decimal(px, pm, pd, ps)
	single         *px;
	decimal_mode   *pm;
	decimal_record *pd;
	fp_exception_field_type *ps;
{
	single_equivalence kluge;
	unpacked        u;

	*ps = 0;		/* Initialize *ps - no exceptions. */
	kluge.x = *px;
	pd->sign = kluge.f.msw.sign;
	pd->fpclass = _class_single(px);
	switch (pd->fpclass) {
	case fp_zero:
		break;
	case fp_infinity:
		break;
	case fp_quiet:
		break;
	case fp_signaling:
		break;
	default:
		_unpack_single(&u, &kluge.x);
		_unpacked_to_decimal(&u, pm, pd, ps);
	}
}

void
extended_to_decimal(px, pm, pd, ps)
	extended       *px;
	decimal_mode   *pm;
	decimal_record *pd;
	fp_exception_field_type *ps;
{
	extended_equivalence kluge;
	unpacked        u;

	*ps = 0;		/* Initialize *ps - no exceptions. */
	kluge.x[0] = (*px)[0];
	kluge.x[1] = (*px)[1];
	kluge.x[2] = (*px)[2];
	pd->sign = kluge.f.msw.sign;
	pd->fpclass = _class_extended(px);
	switch (pd->fpclass) {
	case fp_zero:
		break;
	case fp_infinity:
		break;
	case fp_quiet:
		break;
	case fp_signaling:
		break;
	default:
		_unpack_extended(&u, px);
		_unpacked_to_decimal(&u, pm, pd, ps);
	}
}
