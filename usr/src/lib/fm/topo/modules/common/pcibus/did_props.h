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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2018, Joyent, Inc.
 */

#ifndef _DID_PROPS_H
#define	_DID_PROPS_H

#include <sys/pci.h>
#include <fm/topo_mod.h>
#include <libdevinfo.h>
#include <libnvpair.h>

#include <did.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * pci_props_set() processes an array of structures that translate
 * from devinfo props to properties on topology nodes.  The structure
 * provides the name of a devinfo prop, the name of the property
 * group, the name of the property and the stability of the property
 * group that should be established on the topology node, as well as a
 * function to do the work.
 */
typedef struct txprop {
	const char *tx_diprop;	/* property examined off the di_node_t */
	const topo_pgroup_info_t *tx_tpgroup; /* pgroup defined for tnode_t */
	const char *tx_tprop;	/* property defined on the tnode_t */
	/*
	 * translation function
	 *	If NULL, the devinfo prop's value is copied to the
	 *	topo property.
	 */
	int (*tx_xlate)(tnode_t *, did_t *,
	    const char *, const char *, const char *);
} txprop_t;

#define	DI_DEVTYPPROP		"device_type"
#define	DI_VENDIDPROP		"vendor-id"
#define	DI_SUBVENDIDPROP	"subsystem-vendor-id"
#define	DI_SUBSYSTEMID		"subsystem-id"
#define	DI_DEVIDPROP		"device-id"
#define	DI_CLASSPROP		"class-code"
#define	DI_REGPROP		"reg"
#define	DI_CCPROP		"class-code"
#define	DI_PHYSPROP		"physical-slot#"
#define	DI_SLOTPROP		"slot-names"
#define	DI_AADDRPROP		"assigned-addresses"
#define	DI_RECEPTACLE_PHYMASK	"receptacle-pm"
#define	DI_RECEPTACLE_LABEL	"receptacle-label"

extern int did_props_set(tnode_t *, did_t *, txprop_t[], int);
extern tnode_t *find_predecessor(tnode_t *, char *);

extern char *pci_devtype_get(topo_mod_t *, di_node_t);
extern int pciex_cap_get(topo_mod_t *, di_node_t);
extern int pci_BDF_get(topo_mod_t *, di_node_t, int *, int *, int *);
extern int pci_classcode_get(topo_mod_t *, di_node_t, uint_t *, uint_t *);

extern int di_uintprop_get(topo_mod_t *, di_node_t, const char *, uint_t *);
extern int di_bytes_get(topo_mod_t *, di_node_t, const char *, int *,
    uchar_t **);
extern int FRU_fmri_set(topo_mod_t *, tnode_t *);

#ifdef __cplusplus
}
#endif

#endif /* _DID_PROPS_H */
