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

#ifndef	_SYS_PX_ERR_H
#define	_SYS_PX_ERR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum {
	PX_ERR_JBC,
	PX_ERR_UBC,
	PX_ERR_MMU,
	PX_ERR_IMU,
	PX_ERR_TLU_UE,
	PX_ERR_TLU_CE,
	PX_ERR_TLU_OE,
	PX_ERR_ILU,
	PX_ERR_LPU_LINK,
	PX_ERR_LPU_PHY,
	PX_ERR_LPU_RX,
	PX_ERR_LPU_TX,
	PX_ERR_LPU_LTSSM,
	PX_ERR_LPU_GIGABLZ
} px_err_id_t;

#define	PX_ERR_ENABLE	B_TRUE
#define	PX_ERR_DISABLE	B_FALSE

void px_err_reg_enable(px_err_id_t reg_id, caddr_t csr_base);
void px_err_reg_disable(px_err_id_t reg_id, caddr_t csr_base);
void px_err_reg_setup_pcie(uint8_t chip_mask, caddr_t csr_base,
    boolean_t enable);

#define	PX_ERR_EN_ALL			-1ull
#define	PX_ERR_MASK_NONE		0ull

#define	LPU_INTR_ENABLE 0ull
#define	LPU_INTR_DISABLE -1ull

extern uint64_t px_tlu_ue_intr_mask;
extern uint64_t px_tlu_ue_log_mask;
extern uint64_t px_tlu_ue_count_mask;

extern uint64_t px_tlu_ce_intr_mask;
extern uint64_t px_tlu_ce_log_mask;
extern uint64_t px_tlu_ce_count_mask;

extern uint64_t px_tlu_oe_intr_mask;
extern uint64_t px_tlu_oe_log_mask;
extern uint64_t px_tlu_oe_count_mask;

extern uint64_t px_mmu_intr_mask;
extern uint64_t px_mmu_log_mask;
extern uint64_t px_mmu_count_mask;

extern uint64_t px_imu_intr_mask;
extern uint64_t px_imu_log_mask;
extern uint64_t px_imu_count_mask;

extern uint64_t px_ilu_intr_mask;
extern uint64_t px_ilu_log_mask;
extern uint64_t px_ilu_count_mask;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_ERR_H */
