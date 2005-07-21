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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "gprof.h"

/*
 * look up an address in a sorted-by-address namelist
 * this deals with misses by mapping them to the next lower
 * entry point.
 */
static   int	searchmsg = 0; /* Emit the diagnostic only once */

nltype *
nllookup(mod_info_t *module, pctype address, pctype *nxtsym)
{
	size_t	low = 0, middle, high = module->nname - 1;
	pctype	keyval;
	nltype	*mnl = module->nl;

	/*
	 * If this is the program executable in which we are looking up
	 * a symbol, then the actual load address will be the same as the
	 * address specified in the ELF file. For shared objects, the
	 * load address may differ from what is specified in the file. In
	 * this case, we may need to look for a different value altogether.
	 */
	keyval = module->txt_origin + (address - module->load_base);

	if (keyval < mnl[low].value) {
		if (nxtsym) {
			*nxtsym = module->load_base +
					(mnl[low].value - module->txt_origin);
		}
		return (NULL);
	}

	if (keyval >= mnl[high].value) {
		if (nxtsym)
			*nxtsym = module->load_end;
		return (&mnl[high]);
	}

	while (low != high) {
		middle = (high + low) >> 1;

		if (mnl[middle].value <= keyval &&
					    mnl[middle + 1].value > keyval) {
			if (nxtsym) {
				*nxtsym = module->load_base +
						    (mnl[middle + 1].value -
						    module->txt_origin);
			}
			return (&mnl[middle]);
		}

		if (mnl[middle].value > keyval) {
			high = middle;
		} else {
			low = middle + 1;
		}
	}

	if (searchmsg++ == 0)
		(void) fprintf(stderr, "[nllookup] binary search fails???\n");

	/* must never reach here! */
	return (0);
}

arctype *
arclookup(nltype *parentp, nltype *childp)
{
	arctype	*arcp;

	if (parentp == 0 || childp == 0) {
		(void) fprintf(stderr,
		    "[arclookup] parentp == 0 || childp == 0\n");
		return (0);
	}
#ifdef DEBUG
	if (debug & LOOKUPDEBUG) {
		(void) printf("[arclookup] parent %s child %s\n",
		    parentp->name, childp->name);
	}
#endif /* DEBUG */

	for (arcp = parentp->children; arcp; arcp = arcp->arc_childlist) {
#ifdef DEBUG
		if (debug & LOOKUPDEBUG) {
			(void) printf(
			    "[arclookup]\t arc_parent %s arc_child %s\n",
			    arcp->arc_parentp->name,
			    arcp->arc_childp->name);
		}
#endif /* DEBUG */
		if (arcp->arc_childp == childp) {
			return (arcp);
		}
	}
	return (0);
}
