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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif_impl.h>

int
promif_test(void *p)
{
	cell_t		*ci = (cell_t *)p;
	char		*opname;
	cif_func_t	func;
	int		rv;

	ASSERT(ci[1] == 1);

	opname = p1275_cell2ptr(ci[3]);

	func = promif_find_cif_callback(opname);

	/* zero indicates operation is supported */
	rv = (func != NULL) ? 0 : 1;

	ci[4] = p1275_int2cell(rv);

	return (0);
}
