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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_PCI_TYPES_H
#define	_SYS_PCI_TYPES_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	HI32(x) ((uint32_t)(((uint64_t)(x)) >> 32))
#define	LO32(x) ((uint32_t)(x))
#define	NAMEINST(dip)	ddi_driver_name(dip), ddi_get_instance(dip)
#define	NAMEADDR(dip)	ddi_node_name(dip), ddi_get_name_addr(dip)

typedef uint16_t pci_ign_t;
typedef struct pci pci_t;
typedef struct pci_common pci_common_t;
typedef struct pci_errstate pci_errstate_t;
typedef struct iommu_errstate iommu_errstate_t;
typedef struct ecc_errstate ecc_errstate_t;
typedef struct pbm_errstate pbm_errstate_t;
typedef struct cb_errstate cb_errstate_t;

/*
 * external global function prototypes
 */
extern int pf_is_memory(pfn_t);
extern void do_shutdown();
extern void power_down();
extern void set_intr_mapping_reg(int, uint64_t *, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_TYPES_H */
