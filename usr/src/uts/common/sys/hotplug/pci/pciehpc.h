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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_HOTPLUG_PCI_PCIEHPC_H
#define	_SYS_HOTPLUG_PCI_PCIEHPC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Interfaces exported by PCI-E nexus Hot Plug Controller extension module
 */

/* register ops for read/write of non-standard HPC (e.g: OPL platform) */
typedef struct pciehpc_regops {
	uint_t	(*get)(void *cookie, off_t offset);
	uint_t	(*put)(void *cookie, off_t offset, uint_t val);
	void	*cookie;
} pciehpc_regops_t;

int pciehpc_init(dev_info_t *, pciehpc_regops_t *);
int pciehpc_uninit(dev_info_t *);
int pciehpc_intr(dev_info_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HOTPLUG_PCI_PCIEHPC_H */
