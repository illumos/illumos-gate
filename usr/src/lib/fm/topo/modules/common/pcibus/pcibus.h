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

#ifndef _PCIBUS_H
#define	_PCIBUS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/pci.h>
#include <fm/topo_mod.h>
#include <libdevinfo.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	PCI_ENUMR_VERS	1

#define	PCI_ENUM "pcibus"

#define	PCI_BUS		"pcibus"
#define	PCI_DEVICE	"pcidev"
#define	PCI_FUNCTION	"pcifn"
#define	PCIEX_ROOT	"pciexrc"
#define	PCIEX_SWUP	"pciexswu"
#define	PCIEX_SWDWN	"pciexswd"
#define	PCIEX_BUS	"pciexbus"
#define	PCIEX_DEVICE	"pciexdev"
#define	PCIEX_FUNCTION	"pciexfn"

#define	PCIEXTYPE "pciex"
#define	PCITYPE "pci"

#define	MAX_HB_BUSES	255
#define	MAX_PCIBUS_DEVS	32
#define	MAX_PCIDEV_FNS	8

/* vendor/device ids for Neptune */
#define	SUN_VENDOR_ID		0x108e
#define	NEPTUNE_DEVICE_ID	0xabcd

#define	GETCLASS(x) (((x) & 0xff0000) >> 16)
#define	GETSUBCLASS(x) (((x) & 0xff00) >> 8)

extern tnode_t *pcibus_declare(topo_mod_t *, tnode_t *, di_node_t,
    topo_instance_t);
extern tnode_t *pcidev_declare(topo_mod_t *, tnode_t *, di_node_t,
    topo_instance_t);
extern tnode_t *pcifn_declare(topo_mod_t *, tnode_t *, di_node_t,
    topo_instance_t);
extern tnode_t *pciexbus_declare(topo_mod_t *, tnode_t *, di_node_t,
    topo_instance_t);
extern tnode_t *pciexdev_declare(topo_mod_t *, tnode_t *, di_node_t,
    topo_instance_t);
extern tnode_t *pciexfn_declare(topo_mod_t *, tnode_t *, di_node_t,
    topo_instance_t);
extern int pci_children_instantiate(topo_mod_t *, tnode_t *, di_node_t,
    int, int, int, int, int);

extern int platform_pci_label(topo_mod_t *, tnode_t *, nvlist_t *, nvlist_t **);

#ifdef __cplusplus
}
#endif

#endif /* _PCIBUS_H */
