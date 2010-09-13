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
 * Copyright (c) 1994 by Sun Microsystems, Inc.
 * All Rights Reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif.h>
#include <sys/promimpl.h>

void *
prom_set_callback(void *handler)
{
	cell_t ci[5];

	ci[0] = p1275_ptr2cell("set-callback");	/* Service name */
	ci[1] = (cell_t)1;			/* #argument cells */
	ci[2] = (cell_t)1;			/* #return cells */
	ci[3] = p1275_ptr2cell(handler);	/* Arg1: New handler */
	ci[4] = (cell_t)-1;			/* Res1: Prime result */

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();

	return (p1275_cell2ptr(ci[4]));		/* Res1: Old handler */
}

void
prom_set_symbol_lookup(void *sym2val, void *val2sym)
{
	cell_t ci[5];

	ci[0] = p1275_ptr2cell("set-symbol-lookup");	/* Service name */
	ci[1] = (cell_t)2;			/* #argument cells */
	ci[2] = (cell_t)0;			/* #return cells */
	ci[3] = p1275_ptr2cell(sym2val);	/* Arg1: s2v handler */
	ci[4] = p1275_ptr2cell(val2sym);	/* Arg1: v2s handler */

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();
}
