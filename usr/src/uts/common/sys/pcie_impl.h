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

#ifndef	_SYS_PCIE_IMPL_H
#define	_SYS_PCIE_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The following flag is used for Broadcom 5714/5715 bridge prefetch issue.
 * This flag will be used both by px and px_pci nexus drivers.
 */
#define	PX_DMAI_FLAGS_MAP_BUFZONE	0x40000

/*
 * PCI-Express Friendly Functions
 */
extern int pcie_initchild(dev_info_t *dip);
extern void pcie_uninitchild(dev_info_t *dip);
extern void pcie_clear_errors(dev_info_t *dip,
    ddi_acc_handle_t config_handle);
extern int pcie_postattach_child(dev_info_t *dip);
extern void pcie_enable_errors(dev_info_t *dip,
    ddi_acc_handle_t config_handle);
extern void pcie_disable_errors(dev_info_t *dip,
    ddi_acc_handle_t config_handle);
extern int pcie_enable_ce(dev_info_t *dip,
    ddi_acc_handle_t config_handle);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCIE_IMPL_H */
