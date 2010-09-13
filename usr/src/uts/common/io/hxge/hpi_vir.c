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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <hpi_vir.h>
#include <hxge_defs.h>
#include <hxge_impl.h>

/*
 * Set up a logical group number that a logical device belongs to.
 */
hpi_status_t
hpi_fzc_ldg_num_set(hpi_handle_t handle, uint8_t ld, uint8_t ldg)
{
	ld_grp_ctrl_t	gnum;

	if (!LD_VALID(ld)) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_fzc_ldg_num_set ld <0x%x>", ld));
		return (HPI_FAILURE | HPI_VIR_LD_INVALID(ld));
	}

	if (!LDG_VALID(ldg)) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_fzc_ldg_num_set ldg <0x%x>", ldg));
		return (HPI_FAILURE | HPI_VIR_LDG_INVALID(ld));
	}

	gnum.value = 0;
	gnum.bits.num = ldg;

	HXGE_REG_WR32(handle, LD_GRP_CTRL + LD_NUM_OFFSET(ld), gnum.value);

	return (HPI_SUCCESS);
}

/*
 * Get device state vectors.
 */
hpi_status_t
hpi_ldsv_ldfs_get(hpi_handle_t handle, uint8_t ldg, uint32_t *vector0_p,
    uint32_t *vector1_p)
{
	int	status;

	if ((status = hpi_ldsv_get(handle, ldg, VECTOR0, vector0_p))) {
		return (status);
	}
	if ((status = hpi_ldsv_get(handle, ldg, VECTOR1, vector1_p))) {
		return (status);
	}

	return (HPI_SUCCESS);
}

/*
 * Get device state vectors.
 */
hpi_status_t
hpi_ldsv_get(hpi_handle_t handle, uint8_t ldg, ldsv_type_t vector,
    uint32_t *ldf_p)
{
	uint32_t	offset;

	if (!LDG_VALID(ldg)) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_ldsv_get Invalid Input ldg <0x%x>", ldg));
		return (HPI_FAILURE | HPI_VIR_LDG_INVALID(ldg));
	}

	switch (vector) {
	case VECTOR0:
		offset = LDSV0 + LDSV_OFFSET(ldg);
		break;

	case VECTOR1:
		offset = LDSV1 + LDSV_OFFSET(ldg);
		break;

	default:
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_ldsv_get Invalid Input: ldsv type <0x%x>", vector));
		return (HPI_FAILURE | HPI_VIR_LDSV_INVALID(vector));
	}

	HXGE_REG_RD32(handle, offset, ldf_p);

	return (HPI_SUCCESS);
}

/*
 * Set the mask bits for both ldf0 and ldf1.
 */
hpi_status_t
hpi_intr_mask_set(hpi_handle_t handle, uint8_t ld, uint8_t ldf_mask)
{
	uint32_t	offset;

	if (!LD_VALID(ld)) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_intr_mask_set ld", ld));
		return (HPI_FAILURE | HPI_VIR_LD_INVALID(ld));
	}

	ldf_mask &= LD_IM_MASK;
	offset = LDSV_OFFSET_MASK(ld);

	HPI_DEBUG_MSG((handle.function, HPI_VIR_CTL,
	    "hpi_intr_mask_set: ld %d offset 0x%0x mask 0x%x",
	    ld, offset, ldf_mask));

	HXGE_REG_WR32(handle, offset, (uint32_t)ldf_mask);

	return (HPI_SUCCESS);
}

/*
 * Set interrupt timer and arm bit.
 */
hpi_status_t
hpi_intr_ldg_mgmt_set(hpi_handle_t handle, uint8_t ldg, boolean_t arm,
    uint8_t timer)
{
	ld_intr_mgmt_t	mgm;

	if (!LDG_VALID(ldg)) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_intr_ldg_mgmt_set Invalid Input: ldg <0x%x>", ldg));
		return (HPI_FAILURE | HPI_VIR_LDG_INVALID(ldg));
	}

	if (!LD_INTTIMER_VALID(timer)) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_intr_ldg_mgmt_set Invalid Input"
		    " timer <0x%x>", timer));
		return (HPI_FAILURE | HPI_VIR_INTM_TM_INVALID(ldg));
	}

	if (arm) {
		mgm.bits.arm = 1;
	} else {
		HXGE_REG_RD32(handle, LD_INTR_MGMT + LDSV_OFFSET(ldg),
		    &mgm.value);
	}

	mgm.bits.timer = timer;
	HXGE_REG_WR32(handle, LD_INTR_MGMT + LDSV_OFFSET(ldg), mgm.value);

	HPI_DEBUG_MSG((handle.function, HPI_VIR_CTL,
	    " hpi_intr_ldg_mgmt_set: ldg %d reg offset 0x%x",
	    ldg, LD_INTR_MGMT + LDSV_OFFSET(ldg)));

	return (HPI_SUCCESS);
}

/*
 * Set the timer resolution.
 */
hpi_status_t
hpi_fzc_ldg_timer_res_set(hpi_handle_t handle, uint32_t res)
{
	ld_intr_tim_res_t	tm;

	if (res > LDGTITMRES_RES_MASK) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_fzc_ldg_timer_res_set Invalid Input: res <0x%x>",
		    res));
		return (HPI_FAILURE | HPI_VIR_TM_RES_INVALID);
	}

	tm.value = 0;
	tm.bits.res = res;

	HXGE_REG_WR32(handle, LD_INTR_TIM_RES, tm.value);

	return (HPI_SUCCESS);
}

/*
 * Set the system interrupt data.
 */
hpi_status_t
hpi_fzc_sid_set(hpi_handle_t handle, fzc_sid_t sid)
{
	sid_t	sd;

	if (!LDG_VALID(sid.ldg)) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_fzc_sid_set Invalid Input: ldg <0x%x>", sid.ldg));
		return (HPI_FAILURE | HPI_VIR_LDG_INVALID(sid.ldg));
	}

	if (!SID_VECTOR_VALID(sid.vector)) {
		HPI_ERROR_MSG((handle.function, HPI_ERR_CTL,
		    " hpi_fzc_sid_set Invalid Input: vector <0x%x>",
		    sid.vector));

		return (HPI_FAILURE | HPI_VIR_SID_VEC_INVALID(sid.vector));
	}

	sd.value = 0;
	sd.bits.data = sid.vector;
	HXGE_REG_WR32(handle,  SID + LDG_SID_OFFSET(sid.ldg), sd.value);

	return (HPI_SUCCESS);
}

/*
 * Mask/Unmask the device error mask bits.
 */
hpi_status_t
hpi_fzc_sys_err_mask_set(hpi_handle_t handle, boolean_t mask)
{
	dev_err_mask_t	dev_mask;

	dev_mask.value = 0;
	if (mask) {
		dev_mask.bits.tdc_mask0 = 1;
		dev_mask.bits.rdc_mask0 = 1;
		dev_mask.bits.vnm_pio_mask1 = 1;
		dev_mask.bits.tdc_mask1 = 1;
		dev_mask.bits.rdc_mask1 = 1;
		dev_mask.bits.peu_mask1 = 1;
	}

	HXGE_REG_WR32(handle, DEV_ERR_MASK, dev_mask.value);
	return (HPI_SUCCESS);
}

/*
 * Get the system error stats.
 */
hpi_status_t
hpi_fzc_sys_err_stat_get(hpi_handle_t handle, dev_err_stat_t *statp)
{
	HXGE_REG_RD32(handle,  DEV_ERR_STAT, &statp->value);
	return (HPI_SUCCESS);
}
