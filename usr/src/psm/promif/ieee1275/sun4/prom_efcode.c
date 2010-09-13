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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Embedded Fcode Interpreter "get-fcode" client interfaces.
 */

#include <sys/promif.h>
#include <sys/promimpl.h>

/*
 * Get Fcode size, test if OBP supports this interface.
 */
int
prom_get_fcode_size(char *str)
{
	cell_t ci[5];
	int rv;

	if (prom_test("SUNW,get-fcode-size") != 0) {
		return (0);
	}

	ci[0] = p1275_ptr2cell("SUNW,get-fcode-size");
	ci[1] = (cell_t)1;	/* 1 input arg: str */
	ci[2] = (cell_t)1;	/* 1 output result: len or zero */
	ci[3] = p1275_ptr2cell(str);
	ci[4] = (cell_t)0;

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	if (rv == 0)
		return (p1275_cell2int(ci[4]));
	return (0);
}

/*
 * Get Fcode into supplied buffer.
 */
int
prom_get_fcode(char *str, char *buf)
{
	cell_t ci[6];
	int rv;

	if (prom_test("SUNW,get-fcode") != 0) {
		return (0);
	}

	ci[0] = p1275_ptr2cell("SUNW,get-fcode");
	ci[1] = (cell_t)2;	/* 2 input args: str + buf */
	ci[2] = (cell_t)1;	/* 1 output result: true or false */
	ci[3] = p1275_ptr2cell(buf);	/* Arg#1: buffer to put fcode */
	ci[4] = p1275_ptr2cell(str);	/* Arg#2: name of drop-in */
	ci[5] = (cell_t)0;

	promif_preprom();
	rv = p1275_cif_handler(&ci);
	promif_postprom();

	if (rv == 0)
		return (p1275_cell2int(ci[5]));
	return (0);
}
