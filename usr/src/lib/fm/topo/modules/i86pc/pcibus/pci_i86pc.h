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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _PCI_I86PC_H
#define	_PCI_I86PC_H

#include <pcibus_labels.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Data for label lookup based on existing slot label.
 *
 * Platforms may need entries here if the slot labels
 * provided by firmware are incorrect.
 *
 * Note that re-writing to NULL provides a way of getting rid of totally
 * spurious labels.
 */

slot_rwd_t x4600_rewrites[] = {
	/* from hw, should be, test func */
	{ "PCIX SLOT0", NULL, NULL },
	{ "PCIX SLOT1", NULL, NULL },
	{ "PCIX SLOT2", NULL, NULL },
	{ "PCIExp SLOT2", NULL, NULL },
	{ "PCIExp SLOT3", NULL, NULL },
	{ "PCIExp SLOT4", NULL, NULL },
	{ "PCIExp SLOT5", NULL, NULL },
	{ "PCIExp SLOT6", NULL, NULL },
	{ "PCIExp SLOT7", NULL, NULL },
	{ "PCIExp SLOT8", NULL, NULL }
};

slot_rwd_t netra_x4200_rewrites[] = {
	/* from hw, should be, test func */
	{ "PCIExp SLOT1", NULL, NULL },
	{ "PCIX SLOT2", NULL, NULL },
};

slot_rwd_t x4250_rewrites[] = {
	/* from hw, should be, test func */
	{ "SLOT0", NULL, NULL },
	{ "SLOT1", NULL, NULL },
	{ "SLOT2", NULL, NULL }
};

plat_rwd_t plat_rewrites[] = {
	{ "Sun-Fire-X4600",
	    sizeof (x4600_rewrites) / sizeof (slot_rwd_t),
	    x4600_rewrites },
	{ "Sun-Fire-X4600-M2",
	    sizeof (x4600_rewrites) / sizeof (slot_rwd_t),
	    x4600_rewrites },
	{ "Sun-Fire-X4250",
	    sizeof (x4250_rewrites) / sizeof (slot_rwd_t),
	    x4250_rewrites },
	{ "Netra-X4200-M2",
	    sizeof (netra_x4200_rewrites) / sizeof (slot_rwd_t),
	    netra_x4200_rewrites }
};

slotnm_rewrite_t SlotRWs = {
	sizeof (plat_rewrites) / sizeof (plat_rwd_t),
	plat_rewrites
};

/*
 * Data for label lookup based on device info.
 *
 * Platforms need entries here if there is no physical slot number
 * or slot-names.
 */

extern	int	parent_is_rc(topo_mod_t *, did_t *);
extern	int	ba_is_2(topo_mod_t *, did_t *);
extern	int	ba_is_4(topo_mod_t *, did_t *);

devlab_t x4600_missing[] = {
	/* board, bridge, root-complex, bus, dev, label, test func */
	{ 0, 2, 2, -1, -1, "PCIExp SLOT4", parent_is_rc },
	{ 0, 3, 3, -1, -1, "PCIExp SLOT2", parent_is_rc },
	{ 0, 4, 4, -1, -1, "PCIExp SLOT3", parent_is_rc },
	{ 0, 8, 8, -1, -1, "PCIExp SLOT7", parent_is_rc },
	{ 0, 9, 9, -1, -1, "PCIExp SLOT5", parent_is_rc },
	{ 0, 10, 10, -1, -1, "PCIExp SLOT6", parent_is_rc }
};

devlab_t x4600m2_missing[] = {
	/* board, bridge, root-complex, bus, dev, label, test func */
	{ 0, 1, 1, -1, -1, "PCIExp SLOT4", parent_is_rc },
	{ 0, 2, 2, -1, -1, "PCIExp SLOT2", parent_is_rc },
	{ 0, 3, 3, -1, -1, "PCIExp SLOT3", parent_is_rc },
	{ 0, 6, 6, -1, -1, "PCIExp SLOT7", parent_is_rc },
	{ 0, 7, 7, -1, -1, "PCIExp SLOT5", parent_is_rc },
	{ 0, 8, 8, -1, -1, "PCIExp SLOT6", parent_is_rc }
};

devlab_t x4250_missing[] = {
	/* board, bridge, root-complex, bus, dev, label, test func */
	{ 0, 0, 0, -1, -1, "PCIExp SLOT3", ba_is_2 },
	{ 0, 0, 0, -1, -1, "PCIExp SLOT0", ba_is_4 },
	{ 0, 2, 2, -1, -1, "PCIExp SLOT4", ba_is_2 },
	{ 0, 2, 2, -1, -1, "PCIExp SLOT1", ba_is_4 },
	{ 0, 4, 4, -1, -1, "PCIExp SLOT5", ba_is_2 },
	{ 0, 4, 4, -1, -1, "PCIExp SLOT2", ba_is_4 }
};

devlab_t netra_x4200_missing[] = {
	/* board, bridge, root-complex, bus, dev, label, test func */
	{ 0, 4, 4, -1, -1, "PCIExp SLOT0", NULL },
	{ 0, 0, 3 - TO_PCI, -1, -1, "PCIX SLOT", NULL },
	{ 0, 0, 7 - TO_PCI, -1, -1, "PCIX SLOT", NULL }
};

pdevlabs_t plats_missing[] = {
	{ "Sun-Fire-X4600",
	    sizeof (x4600_missing) / sizeof (devlab_t),
	    x4600_missing },
	{ "Sun-Fire-X4600-M2",
	    sizeof (x4600m2_missing) / sizeof (devlab_t),
	    x4600m2_missing },
	{ "Sun-Fire-X4250",
	    sizeof (x4250_missing) / sizeof (devlab_t),
	    x4250_missing },
	{ "Netra-X4200-M2",
	    sizeof (netra_x4200_missing) / sizeof (devlab_t),
	    netra_x4200_missing }
};

physnm_t x2100m2_pnms[] = {
	/* Slot #, Label */
	{   37, "PCIe 0" },
	{   32, "PCIe 1" }
};

physnm_t x2200m2_pnms[] = {
	/* Slot #, Label */
	{   37, "PCIe 0" },
	{   32, "PCIe 1" }
};

physnm_t x2250_pnms[] = {
	/* Slot #, Label */
	{   6, "PCIe 0" }
};

physnm_t x2270_pnms[] = {
	/* Slot #, Label */
	{   55, "PCIe 0" }
};

physnm_t x4170_pnms[] = {
	/* Slot #, Label */
	{   1, "PCIe 0" },
	{   2, "PCIe 1" },
	{   3, "PCIe 2" }
};

physnm_t x4270_pnms[] = {
	/* Slot #, Label */
	{   1, "PCIe 0" },
	{   2, "PCIe 1" },
	{   3, "PCIe 2" },
	{   4, "PCIe 3" },
	{   5, "PCIe 4" },
	{   6, "PCIe 5" }
};

physnm_t x4275_pnms[] = {
	/* Slot #, Label */
	{   1, "PCIe 0" },
	{   2, "PCIe 1" },
	{   3, "PCIe 2" },
	{   4, "PCIe 3" },
	{   5, "PCIe 4" },
	{   6, "PCIe 5" }
};

physnm_t netra4270_pnms[] = {
	/* Slot #, Label */
	{   1, "PCIe 0" },
	{   2, "PCIe 1" },
	{   3, "PCIe 2" },
	{   5, "PCIe 4" },
	{   6, "PCIe 5" }
};

physnm_t x4150_pnms[] = {
	/* Slot #, Label */
	{   40, "PCIe 0" },
	{   48, "PCIe 1" },
	{   50, "PCIe 2" }
};

physnm_t x4450_pnms[] = {
	/* Slot #, Label */
	{   52, "PCIe 0" },
	{   54, "PCIe 1" },
	{   40, "PCIe 2" },
	{   49, "PCIe 3" },
	{   51, "PCIe 4" },
	{   41, "PCIe 5" }
};

pphysnm_t plat_pnames[] = {
	{ "X2100-M2",
	    sizeof (x2100m2_pnms) / sizeof (physnm_t),
	    x2100m2_pnms },
	{ "Sun-Fire-X2100-M2",
	    sizeof (x2100m2_pnms) / sizeof (physnm_t),
	    x2100m2_pnms },
	{ "X2200-M2",
	    sizeof (x2200m2_pnms) / sizeof (physnm_t),
	    x2200m2_pnms },
	{ "Sun-Fire-X2200-M2",
	    sizeof (x2200m2_pnms) / sizeof (physnm_t),
	    x2200m2_pnms },
	{ "Sun-Fire-X2250",
	    sizeof (x2250_pnms) / sizeof (physnm_t),
	    x2250_pnms },
	{ "Sun-Fire-X2270",
	    sizeof (x2270_pnms) / sizeof (physnm_t),
	    x2270_pnms },
	{ "Sun-Fire-X4170",
	    sizeof (x4170_pnms) / sizeof (physnm_t),
	    x4170_pnms },
	{ "Sun-Fire-X4270",
	    sizeof (x4270_pnms) / sizeof (physnm_t),
	    x4270_pnms },
	{ "Sun-Fire-X4275",
	    sizeof (x4275_pnms) / sizeof (physnm_t),
	    x4275_pnms },
	{ "Sun-Fire-X4170-Server",
	    sizeof (x4170_pnms) / sizeof (physnm_t),
	    x4170_pnms },
	{ "Sun-Fire-X4270-Server",
	    sizeof (x4270_pnms) / sizeof (physnm_t),
	    x4270_pnms },
	{ "Sun-Fire-X4275-Server",
	    sizeof (x4275_pnms) / sizeof (physnm_t),
	    x4275_pnms },
	{ "Sun-Netra-X4270",
	    sizeof (netra4270_pnms) / sizeof (physnm_t),
	    netra4270_pnms },
	{ "Sun-Fire-X4150",
	    sizeof (x4150_pnms) / sizeof (physnm_t),
	    x4150_pnms },
	{ "Sun-Fire-X4450",
	    sizeof (x4450_pnms) / sizeof (physnm_t),
	    x4450_pnms }
};

missing_names_t Missing = {
	sizeof (plats_missing) / sizeof (pdevlabs_t),
	plats_missing
};

physlot_names_t PhyslotNMs = {
	sizeof (plat_pnames) / sizeof (pphysnm_t),
	plat_pnames
};

slotnm_rewrite_t *Slot_Rewrites = &SlotRWs;
physlot_names_t *Physlot_Names = &PhyslotNMs;
missing_names_t *Missing_Names = &Missing;

#ifdef __cplusplus
}
#endif

#endif /* _PCI_I86PC_H */
