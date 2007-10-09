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

#ifndef _PCIBUS_LABELS_H
#define	_PCIBUS_LABELS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <hostbridge.h>
#include <did.h>

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

/*
 * Sometimes OBP gets it wrong, there's a slot-names property, but it
 * is incorrect.  These structures allow us to replace a given label A
 * with a different label B prior to attaching the label to a topology node.
 */
typedef struct slot_rwd {
	const char *srw_obp;		/* slot name found */
	const char *srw_new;		/* replacement slot name */
} slot_rwd_t;

typedef struct plat_rwd {
	const char *prw_platform;	/* platform on which the names apply */
	int prw_nrewrites;		/* number of rewrites */
	struct slot_rwd *prw_rewrites;	/* array of rewrites */
} plat_rwd_t;

typedef struct slotnm_rewrite {
	int srw_nplats;
	struct plat_rwd *srw_platrewrites;
} slotnm_rewrite_t;

/*
 * We can locate a label without help from OBP slot-names or a
 * physical slot-name, if need be.  Having to resort to this, though is
 * really an indication that there's a bug in the platform OBP.
 */
typedef struct devlab {
	int dl_board;
	int dl_bridge;
	int dl_rc;
	int dl_bus;
	int dl_dev;
	const char *dl_label;
} devlab_t;

typedef struct pdevlabs {
	const char *pdl_platform;	/* Name of the platform */
	int pdl_nnames;			/* number of missing names */
	struct devlab *pdl_names;	/* the missing names */
} pdevlabs_t;

typedef struct missing_names {
	int mn_nplats;			/* number of platforms with entries */
	struct pdevlabs *mn_names;	/* platform entries */
} missing_names_t;

extern int pci_label_cmn(topo_mod_t *mod, tnode_t *, nvlist_t *, nvlist_t **);
extern int pci_fru_cmn(topo_mod_t *mod, tnode_t *, nvlist_t *, nvlist_t **);
extern const char *
pci_slotname_lookup(topo_mod_t *, tnode_t *, did_t *, did_t *);

#ifdef __cplusplus
}
#endif

#endif /* _PCIBUS_LABELS_H */
