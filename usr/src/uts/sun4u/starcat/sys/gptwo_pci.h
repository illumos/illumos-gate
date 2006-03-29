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
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_GPTWO_PCI_H
#define	_SYS_GPTWO_PCI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Header file for the PCI/Schizo component to the
 * Safari Configurator (gptwo_cpu).
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/safari_pcd.h>

gptwocfg_ops_cookie_t gptwocfg_alloc_pci_ops(int, int);
gptwo_new_nodes_t *gptwo_configure_pci(dev_info_t *, spcd_t *, uint_t);
dev_info_t *gptwo_prepare_pci(dev_info_t *);
dev_info_t *gptwo_unconfigure_pci(dev_info_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_GPTWO_PCI_H */
