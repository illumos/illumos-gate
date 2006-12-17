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

#include <sys/promif.h>
#include <sys/promimpl.h>

/*
 * This interface allows the client to specify that the client
 * supports soft state, so OBP should not set SIS_NORMAL.
 */
void
prom_sun4v_soft_state_supported(void)
{
	cell_t ci[3];

	if (prom_test("SUNW,soft-state-supported") != 0)
		return;

	ci[0] = p1275_ptr2cell("SUNW,soft-state-supported");	/* Service */
	ci[1] = (cell_t)0;			/* No Arguments */
	ci[2] = (cell_t)0;			/* No return values */

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();
}
