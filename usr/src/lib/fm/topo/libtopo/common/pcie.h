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
 * Copyright 2023 Oxide Computer Company
 */

#ifndef	_PCIE_H
#define	_PCIE_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	PCIE_VERSION	1
#define	PCIE		"pcie"

extern int pcie_init(topo_mod_t *, topo_version_t);
extern void pcie_fini(topo_mod_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _PCIE_H */
