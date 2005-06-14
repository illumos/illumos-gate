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

#ifndef	_SYS_PCI_UTIL_H
#define	_SYS_PCI_UTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

extern int init_child(pci_t *pci_p, dev_info_t *child);
extern int uninit_child(pci_t *pci_p, dev_info_t *child);
extern int report_dev(dev_info_t *dip);
extern int get_pci_properties(pci_t *pci_p, dev_info_t *dip);
extern void free_pci_properties(pci_t *pci_p);
extern void unmap_pci_registers(pci_t *pci_p);
extern void fault_init(pci_t *pci_p);
extern void fault_fini(pci_t *pci_p);
extern int pci_log_cfg_err(dev_info_t *dip, ushort_t status_reg, char *err_msg);
extern int pci_get_portid(dev_info_t *dip);

/* bus map routines */
extern int pci_reloc_reg(dev_info_t *dip, dev_info_t *rdip, pci_t *pci_p,
	pci_regspec_t *pci_rp);
extern int pci_xlate_reg(pci_t *pci_p, pci_regspec_t *pci_rp,
	struct regspec *new_rp);

/* bus add intrspec */
extern uint_t get_nreg_set(dev_info_t *child);
extern uint_t get_nintr(dev_info_t *child);
extern uint64_t pci_get_cfg_pabase(pci_t *pci_p);
extern int pci_cfg_report(dev_info_t *, ddi_fm_error_t *, pci_errstate_t *,
	int, uint32_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_UTIL_H */
