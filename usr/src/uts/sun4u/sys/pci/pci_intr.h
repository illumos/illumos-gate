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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_PCI_INTR_H
#define	_SYS_PCI_INTR_H

#ifdef	__cplusplus
extern "C" {
#endif

extern dev_info_t *get_my_childs_dip(dev_info_t *dip, dev_info_t *rdip);
extern int pci_add_intr(dev_info_t *dip, dev_info_t *rdip,
	ddi_intr_handle_impl_t *hdlp);
extern int pci_remove_intr(dev_info_t *dip, dev_info_t *rdip,
	ddi_intr_handle_impl_t *hdlp);
extern uint_t pci_intr_wrapper(caddr_t arg);
extern void pci_intr_teardown(pci_t *pci_p);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_INTR_H */
