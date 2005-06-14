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
 *
 * PCItool interfaces internal to the i86pc PCI nexus driver.
 */

#ifndef	_SYS_PCI_VAR_H
#define	_SYS_PCI_VAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

extern void *pci_statep;

/* State structure. */
typedef struct pci_state {
	dev_info_t *pci_dip;
} pci_state_t;

/*
 * The way the minor number for the devctl node is constructed in pcihp is:
 * PCIHP_AP_MINOR_NUM(ddi_get_instance(dip), PCIHP_DEVCTL_MINOR)
 * Use this number as the index value to ddi_soft_state_zalloc.
 */
#define	DIP_TO_MINOR(dip) \
	(PCIHP_AP_MINOR_NUM(ddi_get_instance(dip), PCIHP_DEVCTL_MINOR))

#define	PCI_DEV_TO_STATE(dev) \
	((pci_state_t *)(ddi_get_soft_state(pci_statep, getminor(dev))))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_VAR_H */
