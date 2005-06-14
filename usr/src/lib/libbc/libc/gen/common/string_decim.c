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

#include <ctype.h>
#include <stdio.h>
#ifndef PRE41
#include <locale.h>
#endif
#include "base_conversion.h"

void
string_to_decimal(ppc, nmax, fortran_conventions, pd, pform, pechar)
	char          **ppc;
	int             nmax;
	int             fortran_conventions;
	decimal_record *pd;
	enum decimal_string_form *pform;
	char          **pechar;

{
	register char  *cp = *ppc;
	register int    current;
	register int    nread = 1;	/* Number of characters read so far. */
	char           *cp0 = cp;
	char           *good = cp - 1;	/* End of known good token. */

	current = *cp;

#define ATEOF 0			/* A string is never at EOF.	 */
#define CURRENT current
#define NEXT \
	if (nread < nmax) \
		{cp++ ; current = *cp ; nread++ ;} \
	else \
		{current = NULL ; } ;	/* Increment input character and cp. */

#include "char_to_decimal.h"
#undef CURRENT
#undef NEXT
}
