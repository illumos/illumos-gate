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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _PCI_SUN4V_H
#define	_PCI_SUN4V_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "pcibus_labels.h"

#ifdef __cplusplus
extern "C" {
#endif

physnm_t t200_pnms[] = {
	/* Slot #, Label */
	{ 224, "PCIE0" },
	{ 225, "PCIE1" },
	{ 226, "PCIE2" }
};

physnm_t t5120_pnms[] = {
	/* Slot #, Label */
	{   0, "MB/RISER0/PCIE0" },
	{   1, "MB/RISER1/PCIE1" },
	{   2, "MB/RISER2/PCIE2" }
};

physnm_t t5220_pnms[] = {
	/* Slot #, Label */
	{   0, "MB/RISER0/PCIE0" },
	{   1, "MB/RISER1/PCIE1" },
	{   2, "MB/RISER2/PCIE2" },
	{   3, "MB/RISER0/PCIE3" },
	{   4, "MB/RISER1/PCIE4" },
	{   5, "MB/RISER2/PCIE5" }
};

physnm_t netra_t5220_pnms[] = {
	/* Slot #, Label */
	{   0, "MB/RISER0/PCIE0" },
	{   1, "MB/RISER1/PCIE1" },
	{   2, "MB/RISER2/PCIE2" },
	{   3, "MB/PCI_MEZZ/PCIE3" },
	{   4, "MB/PCI_MEZZ/PCIX1" },
	{   5, "MB/PCI_MEZZ/PCIX2" }
};

pphysnm_t plat_pnames[] = {
	{ "Sun-Fire-T200",
	    sizeof (t200_pnms) / sizeof (physnm_t),
	    t200_pnms },
	{ "SPARC-Enterprise-T5120",
	    sizeof (t5120_pnms) / sizeof (physnm_t),
	    t5120_pnms },
	{ "SPARC-Enterprise-T5220",
	    sizeof (t5220_pnms) / sizeof (physnm_t),
	    t5220_pnms },
	/*
	 * T5140/T5240 uses the same chassis as T5120/T5220, hence
	 * the same PCI slot mappings
	 */
	{ "T5140",
	    sizeof (t5120_pnms) / sizeof (physnm_t),
	    t5120_pnms },
	{ "T5240",
	    sizeof (t5220_pnms) / sizeof (physnm_t),
	    t5220_pnms },
	{ "Netra-T5220",
	    sizeof (netra_t5220_pnms) / sizeof (physnm_t),
	    netra_t5220_pnms }
};

physlot_names_t PhyslotNMs = {
	sizeof (plat_pnames) / sizeof (pphysnm_t),
	plat_pnames
};

devlab_t t200_missing[] = {
	/* board, bridge, root-complex, bus, dev, label */
	{ 0, 0, 1 - TO_PCI, 6, 1, "PCIX1" },
	{ 0, 0, 1 - TO_PCI, 6, 2, "PCIX0" }
};

pdevlabs_t plats_missing[] = {
	{ "Sun-Fire-T200",
	    sizeof (t200_missing) / sizeof (devlab_t),
	    t200_missing },
	{ "SPARC-Enterprise-T5120",
	    0,
	    NULL },
	{ "SPARC-Enterprise-T5220",
	    0,
	    NULL },
	{ "T5140",
	    0,
	    NULL },
	{ "T5240",
	    0,
	    NULL },
	{ "Netra-T5220",
	    0,
	    NULL }
};

missing_names_t Missing = {
	sizeof (plats_missing) / sizeof (pdevlabs_t),
	plats_missing
};

slotnm_rewrite_t *Slot_Rewrites = NULL;
physlot_names_t *Physlot_Names = &PhyslotNMs;
missing_names_t *Missing_Names = &Missing;

#ifdef __cplusplus
}
#endif

#endif /* _PCI_SUN4V_H */
