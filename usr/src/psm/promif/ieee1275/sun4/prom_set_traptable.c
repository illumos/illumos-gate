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
 * Copyright (c) 1994, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif.h>
#include <sys/promimpl.h>

/*
 * This interface allows the client to safely take over the %tba by
 * the prom's service. The prom will take care of the quiescence of
 * interrupts and handle any pending soft interrupts.
 */
void
prom_set_traptable(void *tba_addr)
{
	cell_t ci[4];

	ci[0] = p1275_ptr2cell("SUNW,set-trap-table");	/* Service name */
	ci[1] = (cell_t) 1;			/* #argument cells */
	ci[2] = (cell_t) 0;			/* #result cells */
	ci[3] = p1275_ptr2cell(tba_addr);	/* Arg1: tba address */

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();
}
