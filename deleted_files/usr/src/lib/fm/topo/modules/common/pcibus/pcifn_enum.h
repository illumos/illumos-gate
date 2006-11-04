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

#ifndef	_PCIFN_ENUM_H
#define	_PCIFN_ENUM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/pci.h>
#include <fm/topo_mod.h>

#define	PATH_TEMPLATE "%s/usr/platform/%s/lib/fm/topo/plugins/%s.so"

/*
 * When a pci or pci-express function is enumerated in the topology
 * we'll attempt to load modules that can expand the topology
 * beneath that function.  This data structure helps us track which modules
 * to attempt to load, whether or not the loading was successful
 * so we don't waste time trying again, and if loading is successful,
 * the module pointer returned by topo_mod_load().
 */
typedef struct pfn_enum {
	uint_t pfne_class;	/* expected PCI class of the parent function */
	const char *pfne_modname; /* enumerator module name */
	const char *pfne_childname; /* name of nodes to enumerate */
	topo_instance_t pfne_imin; /* minimum instance number to enumerate */
	topo_instance_t pfne_imax; /* maximum instance number to enumerate */
} pfn_enum_t;

/*
 * The current list of modules to potentially load and expand topology
 * beneath pci(-express) functions.
 */
pfn_enum_t Pcifn_enumerators[] = {
	{ PCI_CLASS_MASS, "sata", "sata-port", 0, 7	},
	{ PCI_CLASS_MASS, "scsi", "disk", 0, 15		}
};

int Pcifn_enumerator_count = sizeof (Pcifn_enumerators) / sizeof (pfn_enum_t);

#endif /* _PCIFN_ENUM_H */
