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

#ifndef	_SYS_PCMU_ECC_H
#define	_SYS_PCMU_ECC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

struct pcmu_ecc_intr_info {
	pcmu_ecc_t *pecc_p;
	int pecc_type;			/* CBNINTR_UE */
	uint64_t pecc_afsr_pa;		/* ECC AFSR phsyical address */
	uint64_t pecc_afar_pa;		/* ECC AFAR physical address */

	/*
	 * Implementation-specific masks & shift values.
	 */
	uint64_t pecc_errpndg_mask;	/* 0 if not applicable. */ /* RAGS */
	uint64_t pecc_offset_mask;
	uint_t pecc_offset_shift;
	uint_t pecc_size_log2;
};

struct pcmu_ecc {
	pcmu_t *pecc_pcmu_p;
	volatile uint64_t pecc_csr_pa;		/* ECC control & status reg */
	struct pcmu_ecc_intr_info pecc_ue;	/* ECC UE error intr info */
	timeout_id_t pecc_tout_id;
};

/*
 * Prototypes
 */
extern void pcmu_ecc_create(pcmu_t *pcmu_p);
extern int pcmu_ecc_register_intr(pcmu_t *pcmu_p);
extern void pcmu_ecc_destroy(pcmu_t *pcmu_p);
extern void pcmu_ecc_configure(pcmu_t *pcmu_p);
extern void pcmu_ecc_enable_intr(pcmu_t *pcmu_p);
extern void pcmu_ecc_disable_wait(pcmu_ecc_t *pecc_p);
extern uint_t pcmu_ecc_disable_nowait(pcmu_ecc_t *pecc_p);
extern uint_t pcmu_ecc_intr(caddr_t a);
extern int pcmu_ecc_err_handler(pcmu_ecc_errstate_t *ecc_err_p);
extern void pcmu_ecc_err_drain(void *not_used, pcmu_ecc_errstate_t *ecc_err);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCMU_ECC_H */
