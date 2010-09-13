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

#ifndef _XAUI_H
#define	_XAUI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * When all we're provided is a physical slot number, these structures
 * allow us to attach an accompanying label.
 */
typedef struct physnm {
	int ps_num;
	const char *ps_label;
} physnm_t;

typedef struct pphysnm {
	const char *pnm_platform;	/* platform on which the names apply */
	int pnm_nnames;			/* number of names */
	struct physnm *pnm_names;	/* array of labels */
} pphysnm_t;

typedef struct physlot_names {
	int psn_nplats;
	struct pphysnm *psn_names;
} physlot_names_t;

/* T5120/T5220 xaui slot numbers */
physnm_t t5120_pnms[] = {
	/* Slot #, Label */
	{   0, "MB/RISER2/XAUI0" },
	{   1, "MB/RISER3/XAUI1" }
};

/* T5140/T5240 xaui slot numbers */
physnm_t t5140_pnms[] = {
	/* Slot #, Label */
	{   0, "MB/RISER0/XAUI0" },
	{   1, "MB/RISER1/XAUI1" }
};

/* T5440 xaui slot numbers */
physnm_t t5440_pnms[] = {
	/* Slot #, Label */
	{   0, "MB/XAUI0" },
	{   1, "MB/XAUI1" }
};

pphysnm_t plat_pnames[] = {
	{ "SPARC-Enterprise-T5120",
	sizeof (t5120_pnms) / sizeof (physnm_t),
	t5120_pnms },
	{ "SPARC-Enterprise-T5220",
	sizeof (t5120_pnms) / sizeof (physnm_t),
	t5120_pnms },
	{ "T5140",
	sizeof (t5140_pnms) / sizeof (physnm_t),
	t5140_pnms },
	{ "T5240",
	sizeof (t5140_pnms) / sizeof (physnm_t),
	t5140_pnms },
	{ "T5440",
	sizeof (t5440_pnms) / sizeof (physnm_t),
	t5440_pnms }
};

physlot_names_t PhyxauiNMs = {
	sizeof (plat_pnames) / sizeof (pphysnm_t),
	plat_pnames
};

physlot_names_t *Phyxaui_Names = &PhyxauiNMs;

#ifdef __cplusplus
}
#endif

#endif /* _XAUI_H */
