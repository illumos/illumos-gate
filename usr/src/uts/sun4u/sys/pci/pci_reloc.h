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

#ifndef	_SYS_PCI_RELOC_H
#define	_SYS_PCI_RELOC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

extern int pci_dvma_remap_enabled;
extern kthread_t *pci_reloc_thread;
extern kmutex_t pci_reloc_mutex;
extern kcondvar_t pci_reloc_cv;
extern int pci_reloc_presuspend;
extern int pci_reloc_suspend;

extern void pci_reloc_init();
extern void pci_reloc_fini();

extern int pci_reloc_getkey();

extern int pci_dvma_remap(dev_info_t *, dev_info_t *, ddi_dma_impl_t *,
	off_t, size_t);
extern void pci_dvma_unregister_callbacks(pci_t *, ddi_dma_impl_t *);

extern void pci_fdvma_remap(ddi_dma_impl_t *, caddr_t, dvma_addr_t,
	size_t, size_t, pfn_t);
extern void pci_fdvma_unregister_callbacks(pci_t *, fdvma_t *,
	ddi_dma_impl_t *, uint_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_RELOC_H */
