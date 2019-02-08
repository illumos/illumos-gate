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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2019 Peter Tribble.
 */

#ifndef	_SYS_PCI_CB_H
#define	_SYS_PCI_CB_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef uint16_t cb_nid_t;
enum cb_nintr_index {
	CBNINTR_PBM = 0,		/* all		not shared */
	CBNINTR_PBM66 = 0,		/* all		not shared */
	CBNINTR_PBM33 = 0,		/* all		not shared */
	CBNINTR_UE = 1,			/* all		shared	   */
	CBNINTR_CE = 2,			/* all		shared	   */
	CBNINTR_POWER_FAIL	= 3,	/* psycho	shared	   */
	CBNINTR_POWER_BUTTON	= 3,	/* sabre	N/A	   */
	CBNINTR_PME_HB		= 3,	/* hummingbird	N/A	   */
	CBNINTR_BUS_ERROR	= 3,	/* schizo	shared	   */
	CBNINTR_THERMAL 	= 4,	/* psycho	shared	   */
	CBNINTR_PME		= 4,	/* schizo	not shared */
	CBNINTR_CDMA		= 4,	/* schizo	not shared */
	CBNINTR_PWR_MANAGE	= 5,	/* psycho	shared	   */
	CBNINTR_MAX			/* count	coding	   */
};

/*
 * control block soft state structure:
 *
 * Each pci node contains shares a control block structure with its peer
 * node.  The control block node contains csr and id registers for chip
 * and acts as a "catch all" for other functionality that does not cleanly
 * fall into other functional blocks.  This block is also used to handle
 * software workarounds for known hardware bugs in different chip revs.
 */
typedef struct cb cb_t;
struct cb {
	pci_common_t *cb_pci_cmn_p;
	cb_nid_t cb_node_id;
	pci_ign_t cb_ign;		/* 1st-attached-side interrupt grp#  */

	kmutex_t cb_intr_lock;		/* guards add/rem intr and intr dist */
	uint32_t cb_no_of_inos;		/* # of actual inos, including PBM   */
	uint32_t cb_inos[CBNINTR_MAX];	/* subset of pci_p->pci_inos array   */

	uint64_t cb_base_pa;		/* PA of schizo CSR bank, 2nd "reg"  */
	uint64_t cb_icbase_pa;		/* PA of tomatillo IChip register    */
					/* bank, 4th "reg" entry */
	uint64_t cb_map_pa;		/* 1st-attached-side map reg base PA */
	uint64_t cb_clr_pa;		/* 1st-attached-side clr reg base PA */
	uint64_t cb_obsta_pa;		/* 1st-attached-side sta reg base PA */

	uint64_t *cb_imr_save;
};

#define	CB_INO_TO_MONDO(cb_p, ino)	((cb_p)->cb_ign << PCI_INO_BITS | (ino))
#define	CB_MONDO_TO_XMONDO(cb_p, mondo) /* local mondo to global mondo */ \
	((cb_p)->cb_node_id << (PCI_IGN_BITS + PCI_INO_BITS) | (mondo))

extern void cb_create(pci_t *pci_p);
extern void cb_destroy(pci_t *pci_p);
extern void cb_suspend(cb_t *cb_p);
extern void cb_resume(cb_t *cb_p);
extern void cb_enable_nintr(pci_t *pci_p, enum cb_nintr_index idx);
extern void cb_disable_nintr(cb_t *cb_p, enum cb_nintr_index idx, int wait);
extern void cb_clear_nintr(cb_t *cb_p, enum cb_nintr_index idx);
extern void cb_intr_dist(void *arg);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_CB_H */
