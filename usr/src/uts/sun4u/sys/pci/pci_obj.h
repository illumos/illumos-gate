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

/*
 * Copyright 2019 Peter Tribble.
 */

#ifndef	_SYS_PCI_OBJ_H
#define	_SYS_PCI_OBJ_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/pci.h>
#include <sys/pci_impl.h>
#include <sys/pci_intr_lib.h>
#include <sys/pci/pci_nexus.h>
#include <sys/pci/pci_types.h>
#include <sys/pci/pci_iommu.h>
#include <sys/pci/pci_space.h>
#include <sys/pci/pci_dma.h>	/* macros use perf counters in pci_space.h */
#include <sys/pci/pci_sc.h>	/* needs pci_iommu.h */
#include <sys/pci/pci_fdvma.h>
#include <sys/pci/pci_ib.h>
#include <sys/pci/pci_cb.h>
#include <sys/pci/pci_ecc.h>
#include <sys/pci/pci_pbm.h>
#include <sys/pci/pci_intr.h>	/* needs pci_ib.h */
#include <sys/pci/pci_counters.h>
#include <sys/pci/pci_var.h>
#include <sys/pci/pci_util.h>
#include <sys/pci/pci_regs.h>
#include <sys/pci/pci_debug.h>
#include <sys/pci/pci_fm.h>	/* needs pci_var.h */
#include <sys/pci/pci_chip.h>	/* collection of chip specific interface */
#include <sys/pci/pci_reloc.h>
#ifdef PCI_DMA_TEST
#include <sys/pci/pci_test.h>
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_OBJ_H */
