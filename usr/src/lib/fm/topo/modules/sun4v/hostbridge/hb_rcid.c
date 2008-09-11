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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <strings.h>

#include "hb_rcid.h"

/* A list of physical root complexes of the SUNW,Sun-Fire-T200 platform */
prc_t t200_prcs[] = {
	/* physical id, bus address */
	{ 0, 0x780 },
	{ 1, 0x7c0 }
};

/* A list of physical root complexes of the SUNW,T5140 platform */
prc_t t5140_prcs[] = {
	/* physical id, bus address */
	{ 0, 0x400 },
	{ 1, 0x500 }
};


pprc_t plat_prcids[] = {
	/*
	 * platforms that have the same map with T200
	 */
	{ "SUNW,Sun-Fire-T200",
	    sizeof (t200_prcs) / sizeof (prc_t),
	    t200_prcs },
	{ "SUNW,Sun-Fire-T1000",
	    sizeof (t200_prcs) / sizeof (prc_t),
	    t200_prcs },
	{ "SUNW,SPARC-Enterprise-T2000",
	    sizeof (t200_prcs) / sizeof (prc_t),
	    t200_prcs },
	{ "SUNW,SPARC-Enterprise-T1000",
	    sizeof (t200_prcs) / sizeof (prc_t),
	    t200_prcs },
	{ "SUNW,Netra-CP3060",
	    sizeof (t200_prcs) / sizeof (prc_t),
	    t200_prcs },
	{ "SUNW,Netra-T2000",
	    sizeof (t200_prcs) / sizeof (prc_t),
	    t200_prcs },
	{ "SUNW,Sun-Blade-T6300",
	    sizeof (t200_prcs) / sizeof (prc_t),
	    t200_prcs },

	/*
	 * platforms that have the same map with T5140
	 */
	{ "SUNW,T5140",
	    sizeof (t5140_prcs) / sizeof (prc_t),
	    t5140_prcs },
	{ "SUNW,T5240",
	    sizeof (t5140_prcs) / sizeof (prc_t),
	    t5140_prcs },
	{ "SUNW,Netra-T5440",
	    sizeof (t5140_prcs) / sizeof (prc_t),
	    t5140_prcs },
	{ "SUNW,Sun-Blade-T6340",
	    sizeof (t5140_prcs) / sizeof (prc_t),
	    t5140_prcs },
	{ "SUNW,USBRDT-5240",
	    sizeof (t5140_prcs) / sizeof (prc_t),
	    t5140_prcs }
};

pprcs_t prcids = {
	sizeof (plat_prcids) / sizeof (pprc_t),
	plat_prcids
};

/*
 * hb_find_rc_pid()
 * Description:
 *    Return the physical id (non-negative) of a root complex given the
 *    plaform name and its bus address.
 */
int
hb_find_rc_pid(char *platform, uint64_t ba)
{
	int rcid = -1;
	int p, i;

	for (p = 0; p < prcids.nplats; p++) {
		if (strcmp(prcids.plats[p].platform, platform) != 0)
			continue;
		for (i = 0; i < prcids.plats[p].nrcs; i++) {
			prc_t pciexrc;
			pciexrc = prcids.plats[p].rcs[i];
			if (pciexrc.ba == ba) {
				rcid = pciexrc.id;
				break;
			}
		}
		break;
	}
	return (rcid);
}
