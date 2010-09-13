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

#ifndef	_PCI_VAR_H
#define	_PCI_VAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* Functions exported from pci_common.c */
#define	IS_IRQ	B_TRUE
#define	IS_VEC	B_FALSE
extern int pci_get_intr_from_vecirq(apic_get_intr_t *intrinfo_p,
    int vecirq, boolean_t is_irq);
extern int pci_get_cpu_from_vecirq(int vecirq, boolean_t is_irq);

/* Functions exported from pci_kstats.c */
extern void pci_kstat_create(kstat_t **kspp, dev_info_t *nexus_dip,
    ddi_intr_handle_impl_t *hdlp);
extern void pci_kstat_delete(kstat_t *kspp);

#ifdef	__cplusplus
}
#endif

#endif	/* _PCI_VAR_H */
