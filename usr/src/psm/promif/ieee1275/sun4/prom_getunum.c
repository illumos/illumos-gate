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
 * Copyright (c) 1994-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif.h>
#include <sys/promimpl.h>

/*
 * This service converts the given physical address into a text string,
 * representing the name of the field-replacable part for the given
 * physical address. In other words, it tells the kernel which chip got
 * the (un)correctable ECC error, which info is hopefully relayed to the user!
 */
int
prom_get_unum(int syn_code, unsigned long long physaddr, char *buf,
		uint_t buflen, int *ustrlen)
{
	cell_t ci[12];
	int rv;
	ihandle_t imemory = prom_memory_ihandle();

	*ustrlen = -1;
	if ((imemory == (ihandle_t)-1))
		return (-1);

	ci[0] = p1275_ptr2cell("call-method");		/* Service name */
	ci[1] = (cell_t)7;				/* #argument cells */
	ci[2] = (cell_t)2;				/* #result cells */
	ci[3] = p1275_ptr2cell("SUNW,get-unumber");	/* Arg1: Method name */
	ci[4] = p1275_ihandle2cell(imemory);		/* Arg2: mem. ihandle */
	ci[5] = p1275_uint2cell(buflen);		/* Arg3: buflen */
	ci[6] = p1275_ptr2cell(buf);			/* Arg4: buf */
	ci[7] = p1275_ull2cell_high(physaddr);		/* Arg5: physhi */
	ci[8] = p1275_ull2cell_low(physaddr);		/* Arg6: physlo */
	ci[9] = p1275_int2cell(syn_code);		/* Arg7: bit # */
	ci[10] = (cell_t)-1;				/* ret1: catch result */
	ci[11] = (cell_t)-1;				/* ret2: length */

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	if (rv != 0)
		return (rv);
	if (p1275_cell2int(ci[10]) != 0)	/* Res1: catch result */
		return (-1);			/* "SUNW,get-unumber" failed */
	*ustrlen = p1275_cell2uint(ci[11]);	/* Res2: unum str length */
	return (0);
}
