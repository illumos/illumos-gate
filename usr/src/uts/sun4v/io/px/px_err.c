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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * sun4v Fire Error Handling
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/membar.h>
#include "px_obj.h"
#include "px_err.h"

static uint_t px_err_common_intr(px_fault_t *fault_p, px_rc_err_t *epkt);
static int  px_err_check_severity(px_t *px_p, ddi_fm_error_t *derr,
    px_rc_err_t *epkt, int caller);

static int px_cb_check_errors(dev_info_t *dip, ddi_fm_error_t *derr,
    px_rc_err_t *epkt, int caller);
static int px_mmu_check_errors(dev_info_t *dip, ddi_fm_error_t *derr,
    px_rc_err_t *epkt, int caller);
static int px_pcie_check_errors(dev_info_t *dip, ddi_fm_error_t *derr,
    px_rc_err_t *epkt, int caller);

/*
 * px_err_cb_intr:
 * Interrupt handler for the Host Bus Block.
 */
uint_t
px_err_cb_intr(caddr_t arg)
{
	px_fault_t	*fault_p = (px_fault_t *)arg;
	px_rc_err_t	*epkt = (px_rc_err_t *)fault_p->px_intr_payload;

	if (epkt != NULL) {
		return (px_err_common_intr(fault_p, epkt));
	}

	return (DDI_INTR_UNCLAIMED);
}

/*
 * px_err_dmc_pec_intr:
 * Interrupt handler for the DMC/PEC block.
 */
uint_t
px_err_dmc_pec_intr(caddr_t arg)
{
	px_fault_t	*fault_p = (px_fault_t *)arg;
	px_rc_err_t	*epkt = (px_rc_err_t *)fault_p->px_intr_payload;

	if (epkt != NULL) {
		return (px_err_common_intr(fault_p, epkt));
	}

	return (DDI_INTR_UNCLAIMED);
}

/*
 * px_err_handle:
 * Common function called by trap, mondo and fabric intr.
 * This function is more meaningful in sun4u implementation.  Kept
 * to mirror sun4u call stack.
 * o check for safe access
 *
 * @param px_p		leaf in which to check access
 * @param derr		fm err data structure to be updated
 * @param caller	PX_TRAP_CALL | PX_INTR_CALL
 * @param chkjbc	whether to handle hostbus registers (ignored)
 * @return err		PX_OK | PX_NONFATAL |
 *                      PX_FATAL_GOS | PX_FATAL_HW | PX_STUCK_FATAL
 */
/* ARGSUSED */
int
px_err_handle(px_t *px_p, ddi_fm_error_t *derr, int caller,
    boolean_t chkxbc)
{
	/* check for safe access */
	px_err_safeacc_check(px_p, derr);

	return (DDI_FM_OK);
}

/*
 * px_err_common_intr:
 * Interrupt handler for the JBC/DMC/PEC block.
 * o lock
 * o create derr
 * o check safe access
 * o px_err_check_severiy(epkt)
 * o dispatch
 * o Idle intr state
 * o unlock
 * o handle error: fatal? fm_panic() : return INTR_CLAIMED)
 */
static uint_t
px_err_common_intr(px_fault_t *fault_p, px_rc_err_t *epkt)
{
	px_t		*px_p = DIP_TO_STATE(fault_p->px_fh_dip);
	dev_info_t	*rpdip = px_p->px_dip;
	px_cb_t		*cb_p = px_p->px_cb_p;
	int		err, ret;
	ddi_fm_error_t	derr;

	mutex_enter(&cb_p->xbc_fm_mutex);

	/* Create the derr */
	bzero(&derr, sizeof (ddi_fm_error_t));
	derr.fme_version = DDI_FME_VERSION;
	derr.fme_ena = fm_ena_generate(epkt->stick, FM_ENA_FMT1);
	derr.fme_flag = DDI_FM_ERR_UNEXPECTED;

	/* Basically check for safe access */
	(void) px_err_handle(px_p, &derr, PX_INTR_CALL, B_FALSE);

	/* Check the severity of this error */
	err = px_err_check_severity(px_p, &derr, epkt, PX_INTR_CALL);

	/* check for error severity */
	ret = ndi_fm_handler_dispatch(rpdip, NULL, &derr);

	/* Set the intr state to idle for the leaf that received the mondo */
	if (px_lib_intr_setstate(rpdip, fault_p->px_fh_sysino,
		INTR_IDLE_STATE) != DDI_SUCCESS) {
		mutex_exit(&cb_p->xbc_fm_mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	mutex_exit(&cb_p->xbc_fm_mutex);

	if ((err & (PX_FATAL_GOS | PX_FATAL_SW)) || (ret == DDI_FM_FATAL))
		fm_panic("Fatal System Bus Error has occurred\n");

	return (DDI_INTR_CLAIMED);
}

/*
 * px_err_check_severity:
 * Check the severity of the fire error based the epkt received
 *
 * @param px_p		leaf in which to take the snap shot.
 * @param derr		fm err in which the ereport is to be based on
 * @param epkt		epkt recevied from HV
 */
static int
px_err_check_severity(px_t *px_p, ddi_fm_error_t *derr, px_rc_err_t *epkt,
    int caller)
{
	px_pec_t 	*pec_p = px_p->px_pec_p;
	dev_info_t	*dip = px_p->px_dip;
	int		err = 0;

	/* Cautious access error handling  */
	if (derr->fme_flag == DDI_FM_ERR_EXPECTED) {
		if (caller == PX_TRAP_CALL) {
			/*
			 * for ddi_caut_get treat all events as nonfatal
			 * The trampoline will set err_ena = 0,
			 * err_status = NONFATAL.
			 */
			derr->fme_status = DDI_FM_NONFATAL;
		} else {
			/*
			 * For ddi_caut_put treat all events as nonfatal. Here
			 * we have the handle and can call ndi_fm_acc_err_set().
			 */
			derr->fme_status = DDI_FM_NONFATAL;
			ndi_fm_acc_err_set(pec_p->pec_acc_hdl, derr);
		}
	}

	switch (epkt->rc_descr.block) {
	case BLOCK_HOSTBUS:
		err = px_cb_check_errors(dip, derr, epkt, caller);
		break;
	case BLOCK_MMU:
		err = px_mmu_check_errors(dip, derr, epkt, caller);
		break;
	case BLOCK_INTR:
		err = PX_NONFATAL;
		break;
	case BLOCK_PCIE:
		err = px_pcie_check_errors(dip, derr, epkt, caller);
		break;
	default:
		err = PX_ERR_UNKNOWN;
	}

	return (err);
}

/* ARGSUSED */
static int
px_cb_check_errors(dev_info_t *dip, ddi_fm_error_t *derr,
    px_rc_err_t *epkt, int caller)
{
	int		fme_flag = derr->fme_flag;
	boolean_t	is_safeacc;
	int		ret,  err = 0;

	is_safeacc = (fme_flag == DDI_FM_ERR_EXPECTED) ||
	    (fme_flag == DDI_FM_ERR_PEEK) ||
	    (fme_flag == DDI_FM_ERR_POKE);

	/* block/op/phase/cond/dir/flag... */
	switch (epkt->rc_descr.op) {
	case OP_PIO:
		err |= PX_NONFATAL;

		/* check handle if affected memory address is captured */
		if (epkt->rc_descr.M != 0) {
			ret = px_handle_lookup(dip, ACC_HANDLE,
			    derr->fme_ena, (void *)epkt->addr);
		}
		if (ret == DDI_FM_FATAL)
			err |= PX_FATAL_SW;
		break;

	case OP_DMA:
		switch (epkt->rc_descr.phase) {
		case PH_ADDR:
			err |= PX_FATAL_GOS;
			break;
		case PH_DATA:
			if (epkt->rc_descr.cond == CND_UE) {
				err |= PX_FATAL_GOS;
				break;
			}

			err |= PX_NONFATAL;
			if (epkt->rc_descr.M == 1) {
				ret = px_handle_lookup(dip, DMA_HANDLE,
				    derr->fme_ena, (void *)epkt->addr);
				if (ret == DDI_FM_FATAL)
					err |= PX_FATAL_SW;
			}
			break;
		default:
			DBG(DBG_ERR_INTR, dip, "Unexpected epkt");
			err |= PX_ERR_UNKNOWN;
			break;
		}
		break;
	case OP_UNKNOWN:
		err |= PX_NONFATAL;
		if (epkt->rc_descr.M == 1) {
			int	ret1, ret2;
			ret1 = px_handle_lookup(dip, DMA_HANDLE, derr->fme_ena,
			    (void *)epkt->addr);
			ret2 = px_handle_lookup(dip, ACC_HANDLE, derr->fme_ena,
			    (void *)epkt->addr);
			if ((ret1 == DDI_FM_FATAL) || (ret2 == DDI_FM_FATAL))
				err |= PX_FATAL_SW;
		}
		break;

	case OP_RESERVED:
	default:
		DBG(DBG_ERR_INTR, NULL, "Unrecognized JBC error.");
		err |= PX_ERR_UNKNOWN;
		break;
	}

	/*
	 * For protected safe access, consider PX_FATAL_GOS as the only
	 * exception for px to take immediate panic, else, treat errors
	 * as nonfatal.
	 */
	if (is_safeacc) {
		if (err & PX_FATAL_GOS)
			err = PX_FATAL_GOS;
		else
			err = PX_NONFATAL;
	}

	return (err);
}

/* ARGSUSED */
static int
px_mmu_check_errors(dev_info_t *dip, ddi_fm_error_t *derr,
    px_rc_err_t *epkt, int caller)
{
	int		ret, err = 0;

	switch (epkt->rc_descr.op) {
	case OP_BYPASS:	/* nonfatal */
	case OP_XLAT:	/* nonfatal, stuck-fatal, fatal-reset */
	case OP_TBW:	/* nonfatal, stuck-fatal */
		err = PX_NONFATAL;
		break;

	default:
		err = PX_ERR_UNKNOWN;
		break;
	}

	if ((epkt->rc_descr.D != 0) || (epkt->rc_descr.M != 0)) {
		ret = px_handle_lookup(dip, DMA_HANDLE, derr->fme_ena,
		    (void *)epkt->addr);
	}

	if (ret == DDI_FM_FATAL)
		err = PX_FATAL_SW;
	else if ((ret == DDI_FM_NONFATAL) && (err = PX_ERR_UNKNOWN))
		err = PX_NONFATAL;

	return (err);
}

/* ARGSUSED */
static int
px_pcie_check_errors(dev_info_t *dip, ddi_fm_error_t *derr,
    px_rc_err_t *epkt, int caller)
{
	int		ret = DDI_FM_OK;
	px_pec_err_t	*pec = (px_pec_err_t *)epkt;

	switch (pec->pec_descr.dir) {
	case DIR_INGRESS:
	case DIR_EGRESS:
	case DIR_LINK:
		/* Will eventually call pciex_rc_check_status(...); */
		break;
	default:
		ret = DDI_FM_OK;
		break;
	}

	return (ret);
}
