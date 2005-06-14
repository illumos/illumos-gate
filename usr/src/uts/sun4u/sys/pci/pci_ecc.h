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

#ifndef	_SYS_PCI_ECC_H
#define	_SYS_PCI_ECC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/errorq.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct ecc_intr_info {
	struct ecc *ecc_p;

	int ecc_type;			/* CBNINTR_UE or CBNINTR_CE */

	/*
	 * ECC status registers.
	 */
	uint64_t ecc_afsr_pa;
	uint64_t ecc_afar_pa;

	/*
	 * Implementation-specific masks & shift values.
	 */
	uint64_t ecc_errpndg_mask;	/* 0 if not applicable. */
	uint64_t ecc_offset_mask;
	uint_t ecc_offset_shift;
	uint_t ecc_size_log2;
} ecc_intr_info_t;

typedef struct ecc {
	pci_common_t *ecc_pci_cmn_p;

	/*
	 * ECC control and status registers:
	 */
	volatile uint64_t ecc_csr_pa;

	/*
	 * Information specific to error type.
	 */
	struct ecc_intr_info ecc_ue;
	struct ecc_intr_info ecc_ce;
	timeout_id_t ecc_to_id;
} ecc_t;

extern void ecc_create(pci_t *pci_p);
extern int ecc_register_intr(pci_t *pci_p);
extern void ecc_destroy(pci_t *pci_p);
extern void ecc_configure(pci_t *pci_p);
extern void ecc_enable_intr(pci_t *pci_p);
extern void ecc_disable_wait(ecc_t *ecc_p);
extern uint_t ecc_disable_nowait(ecc_t *ecc_p);
extern uint_t ecc_intr(caddr_t a);
extern int ecc_err_handler(ecc_errstate_t *ecc_err_p);
extern void ecc_err_drain(void *, ecc_errstate_t *, errorq_elem_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_ECC_H */
