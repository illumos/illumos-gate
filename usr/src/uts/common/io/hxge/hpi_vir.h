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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _HPI_VIR_H
#define	_HPI_VIR_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <hpi.h>
#include <hxge_peu_hw.h>

/*
 * Virtualization and Logical devices HPI error codes
 */
#define	VIR_ERR_ST		(VIR_BLK_ID << HPI_BLOCK_ID_SHIFT)
#define	VIR_ID_SHIFT(n)		(n << HPI_PORT_CHAN_SHIFT)

#define	VIR_LD_INVALID		(HPI_BK_ERROR_START | 0x30)
#define	VIR_LDG_INVALID		(HPI_BK_ERROR_START | 0x31)
#define	VIR_LDSV_INVALID	(HPI_BK_ERROR_START | 0x32)

#define	VIR_INTM_TM_INVALID	(HPI_BK_ERROR_START | 0x33)
#define	VIR_TM_RES_INVALID	(HPI_BK_ERROR_START | 0x34)
#define	VIR_SID_VEC_INVALID	(HPI_BK_ERROR_START | 0x35)

/*
 * Error codes of logical devices and groups functions.
 */
#define	HPI_VIR_LD_INVALID(n) 	(VIR_ID_SHIFT(n) | VIR_ERR_ST | VIR_LD_INVALID)
#define	HPI_VIR_LDG_INVALID(n)	(VIR_ID_SHIFT(n) | VIR_ERR_ST | VIR_LDG_INVALID)
#define	HPI_VIR_LDSV_INVALID(n) (VIR_ID_SHIFT(n) | \
					VIR_ERR_ST | VIR_LDSV_INVALID)
#define	HPI_VIR_INTM_TM_INVALID(n)	(VIR_ID_SHIFT(n) | \
					VIR_ERR_ST | VIR_INTM_TM_INVALID)
#define	HPI_VIR_TM_RES_INVALID		(VIR_ERR_ST | VIR_TM_RES_INVALID)
#define	HPI_VIR_SID_VEC_INVALID(n)	(VIR_ID_SHIFT(n) | \
						VIR_ERR_ST | VIR_TM_RES_INVALID)

/*
 * Logical device definitions.
 */
#define	LDG_NUM_STEP		4
#define	LD_NUM_OFFSET(ld)	(ld * LDG_NUM_STEP)

#define	LDSV_STEP		8192
#define	LDSVG_OFFSET(ldg)	(ldg * LDSV_STEP)
#define	LDSV_OFFSET(ldv)	(ldv * LDSV_STEP)
#define	LDSV_OFFSET_MASK(ld)	(LD_INTR_MASK + LDSV_OFFSET(ld))

#define	LDG_SID_STEP		8192
#define	LDG_SID_OFFSET(ldg)	(ldg * LDG_SID_STEP)

typedef enum {
	VECTOR0,
	VECTOR1
} ldsv_type_t;

/*
 * Definitions for the system interrupt data.
 */
typedef struct _fzc_sid {
	uint8_t		ldg;
	uint8_t		vector;
} fzc_sid_t, *p_fzc_sid_t;

/*
 * Virtualization and Interrupt Prototypes.
 */
hpi_status_t hpi_fzc_ldg_num_set(hpi_handle_t handle, uint8_t ld, uint8_t ldg);
hpi_status_t hpi_ldsv_ldfs_get(hpi_handle_t handle, uint8_t ldg,
    uint32_t *vector0_p, uint32_t *vecto1_p);
hpi_status_t hpi_ldsv_get(hpi_handle_t handle, uint8_t ldg, ldsv_type_t vector,
    uint32_t *ldf_p);
hpi_status_t hpi_intr_mask_set(hpi_handle_t handle, uint8_t ld,
    uint8_t ldf_mask);
hpi_status_t hpi_intr_ldg_mgmt_set(hpi_handle_t handle, uint8_t ldg,
    boolean_t arm, uint8_t timer);
hpi_status_t hpi_fzc_ldg_timer_res_set(hpi_handle_t handle, uint32_t res);
hpi_status_t hpi_fzc_sid_set(hpi_handle_t handle, fzc_sid_t sid);
hpi_status_t hpi_fzc_sys_err_mask_set(hpi_handle_t handle, boolean_t mask);
hpi_status_t hpi_fzc_sys_err_stat_get(hpi_handle_t handle,
    dev_err_stat_t *statp);

#ifdef	__cplusplus
}
#endif

#endif	/* _HPI_VIR_H */
