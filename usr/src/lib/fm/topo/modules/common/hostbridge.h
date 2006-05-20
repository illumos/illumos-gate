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

#ifndef _HOSTBRIDGE_H
#define	_HOSTBRIDGE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libdevinfo.h>
#include "did.h"

#ifdef __cplusplus
extern "C" {
#endif

#define	HB_ENUMR_VERS	1

#define	PATH_TO_HB_ENUM "%s/usr/platform/%s/lib/fm/topo/plugins/hostbridge.so"

#define	HOSTBRIDGE	"hostbridge"

#define	MAX_HBS	255

/*
 * Solaris Drivers for hostbridge ASICs.
 */
#define	SCHIZO "pcisch"
#define	PSYCHO "pcipsy"
#define	NPE "npe"
#define	PCIE_PCI "pcie_pci"
#define	PCI_PCI "pci_pci"
#define	PCI "pci"
#define	PX "px"

/*
 * These #defines are special values of bus and root complex instance
 * numbers, used in calls to did_create().  They're here because it's
 * the hostbridge enumerator that generally establishes the did_t values
 * at the top level.
 */
#define	TRUST_BDF	(-1)	/* Believe the bus value in the reg property */
#define	NO_RC		(-2)	/* Not a pci-express bus, so no root complex */

/*
 * PCI-express bridges to PCI, root complex instance is set to
 * (instance of the PCI-express side root complex - TO_PCI)
 */
#define	TO_PCI		(1000)

struct did_hash;

extern tnode_t *pcihostbridge_declare(tnode_t *, di_node_t, topo_instance_t,
    struct did_hash *, di_prom_handle_t, topo_mod_t *);
extern tnode_t *pciexhostbridge_declare(tnode_t *, di_node_t, topo_instance_t,
    struct did_hash *, di_prom_handle_t, topo_mod_t *);
extern tnode_t *pciexrc_declare(tnode_t *, di_node_t, topo_instance_t,
    struct did_hash *, di_prom_handle_t, topo_mod_t *);

extern int platform_hb_label(tnode_t *, nvlist_t *, nvlist_t **, topo_mod_t *);
extern int platform_hb_enum(tnode_t *,
    const char *, topo_instance_t, topo_instance_t, did_hash_t *,
    di_prom_handle_t, topo_mod_t *);

#ifdef __cplusplus
}
#endif

#endif /* _HOSTBRIDGE_H */
