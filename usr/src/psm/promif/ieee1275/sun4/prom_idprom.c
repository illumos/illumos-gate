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
 * Copyright (c) 1990,1992-1994 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * XXX: Break this up into individual property lookups.
 */

#include <sys/promif.h>
#include <sys/promimpl.h>
#include <sys/idprom.h>

/*
 * Get idprom property from root node, return to callers buffer.
 */

int
prom_getidprom(caddr_t addr, int size)
{
	u_char *cp, val = 0;
	/*LINTED [idprom unused]*/
	idprom_t idprom;
	int i;
	int length;

	length = prom_getproplen(prom_rootnode(), OBP_IDPROM);
	if (length == -1)  {
		prom_printf("Missing OBP idprom property.\n");
		return (-1);
	}

	if (length > size) {
		prom_printf("Buffer size too small.\n");
		return (-1);
	}

	(void) prom_getprop(prom_rootnode(), OBP_IDPROM,
		(caddr_t) addr);

	/*
	 * Test the checksum for sanity
	 */
	for (cp = (u_char *)addr, i = 0;
			i < (sizeof (idprom) - sizeof (idprom.id_undef)); i++)
		val ^= *cp++;

	if (val != 0)
		prom_printf("Warning: IDprom checksum error.\n");

	return (0);
}
