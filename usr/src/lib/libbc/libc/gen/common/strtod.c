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
 * Copyright (c) 1987 by Sun Microsystems, Inc. 
 */

#include <errno.h>
#include <stdio.h>
#include <values.h>
#include <floatingpoint.h>

double
strtod(cp, ptr)
	char           *cp;
	char          **ptr;
{
	double          x;
	decimal_mode    mr;
	decimal_record  dr;
	fp_exception_field_type fs;
	enum decimal_string_form form;
	char           *pechar;

	string_to_decimal(&cp, MAXINT, 0, &dr, &form, &pechar);
	if (ptr != (char **) NULL)
		*ptr = cp;
	if (form == invalid_form)
		return 0.0;	/* Shameful kluge for SVID's sake. */
	mr.rd = fp_direction;
	decimal_to_double(&x, &mr, &dr, &fs);
	if (fs & (1 << fp_overflow)) {	/* Overflow. */
		errno = ERANGE;
	}
	if (fs & (1 << fp_underflow)) {	/* underflow */
		errno = ERANGE;
	}
	return x;
}
