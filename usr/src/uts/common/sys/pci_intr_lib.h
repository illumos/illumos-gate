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

#ifndef	_SYS_PCI_INTR_LIB_H
#define	_SYS_PCI_INTR_LIB_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct pci_class_val {
	uint32_t class_code;
	uint32_t class_mask;
	uint32_t class_val;
} pci_class_val_t;

extern	int	pci_msi_get_cap(dev_info_t *rdip, int type, int *flagsp);
extern	int	pci_msi_configure(dev_info_t *rdip, int type, int count,
		    int inum, uint64_t addr, uint64_t data);
extern	int	pci_msi_unconfigure(dev_info_t *rdip, int type, int inum);
extern	int	pci_is_msi_enabled(dev_info_t *rdip, int type);
extern	int	pci_msi_enable_mode(dev_info_t *rdip, int type);
extern	int	pci_msi_disable_mode(dev_info_t *rdip, int type);
extern	int	pci_msi_set_mask(dev_info_t *rdip, int type, int inum);
extern	int	pci_msi_clr_mask(dev_info_t *rdip, int type, int inum);
extern	int	pci_msi_get_pending(dev_info_t *rdip, int type, int inum,
		    int *pendingp);
extern	int	pci_msi_get_nintrs(dev_info_t *rdip, int type, int *nintrs);
extern	int	pci_msi_set_nintrs(dev_info_t *rdip, int type, int navail);
extern	int	pci_msi_get_supported_type(dev_info_t *rdip, int *typesp);

extern  ddi_intr_msix_t	*pci_msix_init(dev_info_t *rdip);
extern void	pci_msix_fini(ddi_intr_msix_t *msix_p);
extern int	pci_msix_dup(dev_info_t *rdip, int org_inum, int dup_inum);

extern	int	pci_intx_get_cap(dev_info_t *dip, int *flagsp);
extern int	pci_intx_set_mask(dev_info_t *dip);
extern int	pci_intx_clr_mask(dev_info_t *dip);
extern int	pci_intx_get_pending(dev_info_t *dip, int *pendingp);
extern ddi_intrspec_t	pci_intx_get_ispec(dev_info_t *dip, dev_info_t *rdip,
			    int inum);
extern uint32_t	pci_class_to_pil(dev_info_t *dip);
extern int32_t	pci_class_to_intr_weight(dev_info_t *dip);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_INTR_LIB_H */
