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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _PCI_SUN4U_H
#define	_PCI_SUN4U_H

#include <pcibus_labels.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	XMITS_COMPAT	"pci108e,8002"	/* compatible property for XMits */

/*
 * Functions for platforms that need a label lookup
 * test in addition to the standard ones provided.
 */
extern	int	sunfire_test_func(topo_mod_t *, did_t *);

/*
 * Data for label lookup based on existing slot label.
 *
 * Platforms may need entries here if the slot labels
 * provided by firmware are incorrect.
 */

slot_rwd_t v240_rewrites[] = {
	/* from OBP, should be, test func */
	{ "PCI3", "PCI0", NULL },
	{ "PCI1", "PCI2", NULL },
	{ "PCI2", "PCI1", NULL }
};

slot_rwd_t sunfire_rewrites[] = {
	{ "slot 2", "slot 3", sunfire_test_func },
	{ "slot 3", "slot 2", sunfire_test_func },
	{ "slot 6", "slot 7", sunfire_test_func },
	{ "slot 7", "slot 6", sunfire_test_func }
};

plat_rwd_t plat_rewrites[] = {
	{ "Sun-Fire-V240",
	    sizeof (v240_rewrites) / sizeof (slot_rwd_t),
	    v240_rewrites },
	{ "Sun-Fire",
	    sizeof (sunfire_rewrites) / sizeof (slot_rwd_t),
	    sunfire_rewrites }
};

slotnm_rewrite_t SlotRWs = {
	sizeof (plat_rewrites) / sizeof (plat_rwd_t),
	plat_rewrites
};

slotnm_rewrite_t *Slot_Rewrites = &SlotRWs;
physlot_names_t *Physlot_Names = NULL;
missing_names_t *Missing_Names = NULL;

#ifdef __cplusplus
}
#endif

#endif /* _PCI_SUN4U_H */
