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

#ifndef	_SYS_PCI_FDVMA_H
#define	_SYS_PCI_FDVMA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct fast_dvma fdvma_t;

extern int pci_fdvma_reserve(dev_info_t *dip, dev_info_t *rdip, pci_t *pci_p,
	struct ddi_dma_req *dmareq, ddi_dma_handle_t *handlep);
extern int pci_fdvma_release(dev_info_t *dip, pci_t *pci_p, ddi_dma_impl_t *mp);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_FDVMA_H */
