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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _PCI_SUN4U_H
#define	_PCI_SUN4U_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <pcibus_labels.h>

#ifdef __cplusplus
extern "C" {
#endif

slot_rwd_t v240_rewrites[] = {
	/* From OPB, Should Be */
	{ "PCI3", "PCI0" },
	{ "PCI1", "PCI2" },
	{ "PCI2", "PCI1" }
};

plat_rwd_t plat_rewrites[] = {
	{ "SUNW,Sun-Fire-V240",
	    sizeof (v240_rewrites) / sizeof (slot_rwd_t),
	    v240_rewrites }
};

slotnm_rewrite_t SlotRWs = {
	1,
	plat_rewrites
};

slotnm_rewrite_t *Slot_Rewrites = &SlotRWs;
physlot_names_t *Physlot_Names = NULL;
missing_names_t *Missing_Names = NULL;

#ifdef __cplusplus
}
#endif

#endif /* _PCI_SUN4U_H */
