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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include "base_conversion.h"
#include <sys/isa_defs.h>

#define	CSR_DEFAULT 0x1f80

/* The following should be coded as inline expansion templates.	 */

/*
 * Multiplies two normal or subnormal doubles, returns result and exceptions.
 */
double
__mul_set(double x, double y, int *pe) {
	extern void _putmxcsr(), _getmxcsr();
	int csr;
	double z;

	_putmxcsr(CSR_DEFAULT);
	z = x * y;
	_getmxcsr(&csr);
	if ((csr & 0x3f) == 0) {
		*pe = 0;
	} else {
		/* Result may not be exact. */
		*pe = 1;
	}
	return (z);
}

/*
 * Divides two normal or subnormal doubles x/y, returns result and exceptions.
 */
double
__div_set(double x, double y, int *pe) {
	extern void _putmxcsr(), _getmxcsr();
	int csr;
	double z;

	_putmxcsr(CSR_DEFAULT);
	z = x / y;
	_getmxcsr(&csr);
	if ((csr & 0x3f) == 0) {
		*pe = 0;
	} else {
		*pe = 1;
	}
	return (z);
}

double
__dabs(double *d)
{
	/* should use hardware fabs instruction */
	return ((*d < 0.0) ? -*d : *d);
}

/*
 * Returns IEEE mode/status and
 * sets up standard environment for base conversion.
 */
void
__get_ieee_flags(__ieee_flags_type *b) {
	extern void _getmxcsr(), _putmxcsr();

	_getmxcsr(&b->status);

	/* round-to-nearest, all exceptions masked, gradual underflow */
	_putmxcsr(CSR_DEFAULT);
}

/*
 * Restores previous IEEE mode/status
 */
void
__set_ieee_flags(__ieee_flags_type *b) {
	extern void _putmxcsr();

	_putmxcsr(b->status);
}
