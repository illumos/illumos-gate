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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Search routines for processing new-style mon.out files.
 */

#include "profv.h"

/*
 * Look up an address in a sorted-by-address namelist; this deals with
 * misses by mapping them to the next lower entry point.
 */
nltype *
nllookup(mod_info_t *module, Address address, Address *nxtsym_val)
{
	size_t		low = 0, middle, high = module->nfuncs - 1;
	nltype		*nl = module->nl;
	Address		keyval;

	/*
	 * If this is the program executable in which we are looking up
	 * a symbol, then the actual load address will be the same as the
	 * address specified in the ELF file. For shared objects, the
	 * load address may differ from what is specified in the file. In
	 * this case, we may need to look for a different value altogether.
	 */
	keyval = module->txt_origin + (address - module->load_base);

	if (keyval < nl[low].value) {
		if (nxtsym_val) {
			*nxtsym_val = module->load_base +
					(nl[low].value - module->txt_origin);
		}
		return (NULL);
	}

	if (keyval >= nl[high].value) {
		if (nxtsym_val)
			*nxtsym_val = module->load_end;
		return (&nl[high]);
	}

	while (low != high) {
		middle = (high + low) >> 1;

		if ((nl[middle].value <= keyval) &&
					(nl[middle + 1].value > keyval)) {
			if (nxtsym_val) {
				*nxtsym_val = module->load_base +
				    (nl[middle + 1].value - module->txt_origin);
			}

			return (&nl[middle]);
		}

		if (nl[middle].value > keyval)
			high = middle;
		else
			low = middle + 1;
	}

	/* must never reach here! */
	return (NULL);
}

/*
 * Look up a module's base address in a sorted list of pc-hits. Unlike
 * nllookup(), this deals with misses by mapping them to the next *higher*
 * pc-hit. This is so that we get into the module's first pc-hit rightaway,
 * even if the module's entry-point (load_base) itself is not a hit.
 */
Address *
locate(Address	*pclist, size_t nelem, Address keypc)
{
	size_t	low = 0, middle, high = nelem - 1;

	if (keypc <= pclist[low])
		return (pclist);

	if (keypc > pclist[high])
		return (NULL);

	while (low != high) {
		middle = (high + low) >> 1;

		if ((pclist[middle] < keypc) && (pclist[middle + 1] >= keypc))
			return (&pclist[middle + 1]);

		if (pclist[middle] >= keypc)
			high = middle;
		else
			low = middle + 1;
	}

	/* must never reach here! */
	return (NULL);
}
