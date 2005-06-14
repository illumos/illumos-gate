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
 * Allocate retained physical memory
 * Returns 0: Success; Non-zero: failure.
 * Returns *phys_hi, *phys_lo only if successful.
 */
int
prom_retain(char *id, size_t size, u_int align, unsigned long long *physaddr)
{
	cell_t ci[11];
	int rv;
	ihandle_t imemory = prom_memory_ihandle();

	if ((imemory == (ihandle_t)-1))
		return (-1);

	ci[0] = p1275_ptr2cell("call-method");	/* Service name */
	ci[1] = (cell_t)5;			/* #argument cells */
	ci[2] = (cell_t)3;			/* #result cells */
	ci[3] = p1275_ptr2cell("SUNW,retain");	/* Arg1: Method name */
	ci[4] = p1275_ihandle2cell(imemory);	/* Arg2: memory ihandle */
	ci[5] = p1275_uint2cell(align);		/* Arg2: SA1: align */
	ci[6] = p1275_size2cell(size);		/* Arg3: SA2: size */
	ci[7] = p1275_ptr2cell(id);		/* Arg4: SA3: id name */

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	if (rv != 0)
		return (rv);		/* Service "call-method" failed */
	if (ci[8] != 0)			/* Res1: catch-result */
		return (-1);		/* Method "SUNW,retain" failed */

	*physaddr = p1275_cells2ull(ci[9], ci[10]);
					/* Res3: base.hi, Res4: base.lo */
	return (0);
}
