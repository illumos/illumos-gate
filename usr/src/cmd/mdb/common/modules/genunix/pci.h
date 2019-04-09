/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019, Joyent, Inc.
 */

#ifndef _MDB_PCI_H
#define	_MDB_PCI_H

/*
 * genunix PCI dcmds and walkers.
 */

#include <mdb/mdb_modapi.h>
#include <sys/dditypes.h>
#include <sys/ddi_impldefs.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int pcie_bus_walk_init(mdb_walk_state_t *);
extern int pcie_bus_walk_step(mdb_walk_state_t *);

extern boolean_t pcie_bus_match(const struct dev_info *, uintptr_t *);

#ifdef __cplusplus
}
#endif

#endif /* _MDB_PCI_H */
