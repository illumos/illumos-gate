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
 * Copyright (c) 1994-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_PCI_NEXUS_H
#define	_SYS_PCI_NEXUS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct pci_ispec pci_ispec_t;

struct pci_ispec {
	struct intrspec ispec;		/* interrupt pri/pil, vec/ino, func */
	dev_info_t *pci_ispec_dip;	/* interrupt parent dip */
	uint32_t pci_ispec_intr;	/* dev "interrupts" prop or imap */
					/* lookup result storage for UPA */
					/* intr */
	void *pci_ispec_arg;		/* interrupt handler argument */
	ddi_acc_handle_t pci_ispec_hdl;	/* map hdl to dev PCI config space */
	pci_ispec_t *pci_ispec_next;	/* per ino link list */
};

enum pci_fault_ops { FAULT_LOG, FAULT_RESET, FAULT_POKEFLT, FAULT_POKEFINI };

struct pci_fault_handle {
	dev_info_t *fh_dip;		/* device registered fault handler */
	int (*fh_f)();			/* fault handler function */
	void *fh_arg;			/* argument for fault handler */
	struct pci_fault_handle *fh_next;
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_NEXUS_H */
