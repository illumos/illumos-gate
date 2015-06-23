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
 * tavor_qpmod.c
 *    Tavor Queue Pair Modify Routines
 *
 *    This contains all the routines necessary to implement the Tavor
 *    ModifyQP() verb.  This includes all the code for legal transitions to
 *    and from Reset, Init, RTR, RTS, SQD, SQErr, and Error.
 */

#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/bitmap.h>

#include <sys/ib/adapters/tavor/tavor.h>
#include <sys/ib/ib_pkt_hdrs.h>

static int tavor_qp_reset2init(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_qp_info_t *info_p);
static int tavor_qp_init2init(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p);
static int tavor_qp_init2rtr(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p);
static int tavor_qp_rtr2rts(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p);
static int tavor_qp_rts2rts(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p);
static int tavor_qp_rts2sqd(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_cep_modify_flags_t flags);
static int tavor_qp_sqd2rts(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p);
static int tavor_qp_sqd2sqd(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p);
static int tavor_qp_sqerr2rts(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p);
static int tavor_qp_to_error(tavor_state_t *state, tavor_qphdl_t qp);
static int tavor_qp_reset2err(tavor_state_t *state, tavor_qphdl_t qp);

static uint_t tavor_check_rdma_enable_flags(ibt_cep_modify_flags_t flags,
    ibt_qp_info_t *info_p, tavor_hw_qpc_t *qpc);
static int tavor_qp_validate_resp_rsrc(tavor_state_t *state,
    ibt_qp_rc_attr_t *rc, uint_t *rra_max);
static int tavor_qp_validate_init_depth(tavor_state_t *state,
    ibt_qp_rc_attr_t *rc, uint_t *sra_max);
static int tavor_qp_validate_mtu(tavor_state_t *state, uint_t mtu);

/*
 * tavor_qp_modify()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
int
tavor_qp_modify(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p,
    ibt_queue_sizes_t *actual_sz)
{
	ibt_cep_state_t		cur_state, mod_state;
	ibt_cep_modify_flags_t	okflags;
	int			status;
	char			*errormsg;

	TAVOR_TNF_ENTER(tavor_qp_modify);

	/*
	 * Lock the QP so that we can modify it atomically.  After grabbing
	 * the lock, get the current QP state.  We will use this current QP
	 * state to determine the legal transitions (and the checks that need
	 * to be performed.)
	 * Below you will find a case for every possible QP state.  In each
	 * case we check that no flags are set which are not valid for the
	 * possible transitions from that state.  If these tests pass (and if
	 * the state transition we are attempting is legal), then we call
	 * one of the helper functions.  Each of these functions does some
	 * additional setup before posting a Tavor firmware command for the
	 * appropriate state transition.
	 */
	mutex_enter(&qp->qp_lock);

	/*
	 * Verify that the transport type matches between the serv_type and the
	 * qp_trans.  A caller to IBT must specify the qp_trans field as
	 * IBT_UD_SRV, IBT_RC_SRV, or IBT_UC_SRV, depending on the QP.  We
	 * check here that the correct value was specified, based on our
	 * understanding of the QP serv type.
	 *
	 * Because callers specify part of a 'union' based on what QP type they
	 * think they're working with, this ensures that we do not pickup bogus
	 * data if the caller thought they were working with a different QP
	 * type.
	 */
	if (!(TAVOR_QP_TYPE_VALID(info_p->qp_trans, qp->qp_serv_type))) {
		mutex_exit(&qp->qp_lock);
		TNF_PROBE_1(tavor_qp_modify_inv_qp_trans_fail,
		    TAVOR_TNF_ERROR, "", tnf_uint, qptrans,
		    info_p->qp_trans);
		TAVOR_TNF_EXIT(tavor_qp_modify);
		return (IBT_QP_SRV_TYPE_INVALID);
	}

	/*
	 * If this is a transition to RTS (which is valid from RTR, RTS,
	 * SQError, and SQ Drain) then we should honor the "current QP state"
	 * specified by the consumer.  This means converting the IBTF QP state
	 * in "info_p->qp_current_state" to a Tavor QP state.  Otherwise, we
	 * assume that we already know the current state (i.e. whatever it was
	 * last modified to or queried as - in "qp->qp_state").
	 */
	mod_state = info_p->qp_state;

	if (flags & IBT_CEP_SET_RTR_RTS) {
		cur_state = TAVOR_QP_RTR;		/* Ready to Receive */

	} else if ((flags & IBT_CEP_SET_STATE) &&
	    (mod_state == IBT_STATE_RTS)) {

		/* Convert the current IBTF QP state to a Tavor QP state */
		switch (info_p->qp_current_state) {
		case IBT_STATE_RTR:
			cur_state = TAVOR_QP_RTR;	/* Ready to Receive */
			break;
		case IBT_STATE_RTS:
			cur_state = TAVOR_QP_RTS;	/* Ready to Send */
			break;
		case IBT_STATE_SQE:
			cur_state = TAVOR_QP_SQERR;	/* Send Queue Error */
			break;
		case IBT_STATE_SQD:
			cur_state = TAVOR_QP_SQD;	/* SQ Drained */
			break;
		default:
			mutex_exit(&qp->qp_lock);
			TNF_PROBE_1(tavor_qp_modify_inv_currqpstate_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, qpstate,
			    info_p->qp_current_state);
			TAVOR_TNF_EXIT(tavor_qp_modify);
			return (IBT_QP_STATE_INVALID);
		}
	} else {
		cur_state = qp->qp_state;
	}

	switch (cur_state) {
	case TAVOR_QP_RESET:
		okflags = (IBT_CEP_SET_STATE | IBT_CEP_SET_RESET_INIT |
		    IBT_CEP_SET_RDMA_R | IBT_CEP_SET_RDMA_W |
		    IBT_CEP_SET_ATOMIC | IBT_CEP_SET_PKEY_IX |
		    IBT_CEP_SET_PORT | IBT_CEP_SET_QKEY);

		/*
		 * Check for attempts to modify invalid attributes from the
		 * "Reset" state
		 */
		if (flags & ~okflags) {
			mutex_exit(&qp->qp_lock);
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(IBT_QP_ATTR_RO, "reset: invalid flag");
			goto qpmod_fail;
		}

		/*
		 * Verify state transition is to either "Init", back to
		 * "Reset", or to "Error".
		 */
		if ((flags & IBT_CEP_SET_RESET_INIT) &&
		    (flags & IBT_CEP_SET_STATE) &&
		    (mod_state != IBT_STATE_INIT)) {
			/* Invalid transition - ambiguous flags */
			mutex_exit(&qp->qp_lock);
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(IBT_QP_STATE_INVALID,
			    "reset: ambiguous flags");
			goto qpmod_fail;

		} else if ((flags & IBT_CEP_SET_RESET_INIT) ||
		    ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_INIT))) {
			/*
			 * Attempt to transition from "Reset" to "Init"
			 */
			status = tavor_qp_reset2init(state, qp, info_p);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				/* Set "status"/"errormsg", goto failure */
				TAVOR_TNF_FAIL(status, "reset to init");
				goto qpmod_fail;
			}
			qp->qp_state = TAVOR_QP_INIT;

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_RESET)) {
			/*
			 * Attempt to transition from "Reset" back to "Reset"
			 *    Nothing to do here really... just drop the lock
			 *    and return success.  The qp->qp_state should
			 *    already be set to TAVOR_QP_RESET.
			 *
			 * Note: We return here because we do not want to fall
			 *    through to the tavor_wrid_from_reset_handling()
			 *    routine below (since we are not really moving
			 *    _out_ of the "Reset" state.
			 */
			mutex_exit(&qp->qp_lock);
			TNF_PROBE_0_DEBUG(tavor_qp_modify_rst2rst,
			    TAVOR_TNF_TRACE, "");
			TAVOR_TNF_EXIT(tavor_qp_modify);
			return (DDI_SUCCESS);

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_ERROR)) {
			/*
			 * Attempt to transition from "Reset" to "Error"
			 */
			status = tavor_qp_reset2err(state, qp);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				/* Set "status"/"errormsg", goto failure */
				TAVOR_TNF_FAIL(status, "reset to error");
				goto qpmod_fail;
			}
			qp->qp_state = TAVOR_QP_ERR;

		} else {
			/* Invalid transition - return error */
			mutex_exit(&qp->qp_lock);
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(IBT_QP_STATE_INVALID,
			    "reset: invalid transition");
			goto qpmod_fail;
		}

		/*
		 * Do any additional handling necessary here for the transition
		 * from the "Reset" state (e.g. re-initialize the workQ WRID
		 * lists).  Note: If tavor_wrid_from_reset_handling() fails,
		 * then we attempt to transition the QP back to the "Reset"
		 * state.  If that fails, then it is an indication of a serious
		 * problem (either HW or SW).  So we print out a warning
		 * message and return failure.
		 */
		status = tavor_wrid_from_reset_handling(state, qp);
		if (status != DDI_SUCCESS) {
			if (tavor_qp_to_reset(state, qp) != DDI_SUCCESS) {
				TAVOR_WARNING(state, "failed to reset QP");
			}
			qp->qp_state = TAVOR_QP_RESET;

			mutex_exit(&qp->qp_lock);
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(status, "reset: wrid_from_reset hdl");
			goto qpmod_fail;
		}
		break;

	case TAVOR_QP_INIT:
		okflags = (IBT_CEP_SET_STATE | IBT_CEP_SET_INIT_RTR |
		    IBT_CEP_SET_ADDS_VECT | IBT_CEP_SET_RDMARA_IN |
		    IBT_CEP_SET_MIN_RNR_NAK | IBT_CEP_SET_ALT_PATH |
		    IBT_CEP_SET_RDMA_R | IBT_CEP_SET_RDMA_W |
		    IBT_CEP_SET_ATOMIC | IBT_CEP_SET_PKEY_IX |
		    IBT_CEP_SET_QKEY | IBT_CEP_SET_PORT);

		/*
		 * Check for attempts to modify invalid attributes from the
		 * "Init" state
		 */
		if (flags & ~okflags) {
			mutex_exit(&qp->qp_lock);
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(IBT_QP_ATTR_RO, "init: invalid flag");
			goto qpmod_fail;
		}

		/*
		 * Verify state transition is to either "RTR", back to "Init",
		 * to "Reset", or to "Error"
		 */
		if ((flags & IBT_CEP_SET_INIT_RTR) &&
		    (flags & IBT_CEP_SET_STATE) &&
		    (mod_state != IBT_STATE_RTR)) {
			/* Invalid transition - ambiguous flags */
			mutex_exit(&qp->qp_lock);
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(IBT_QP_STATE_INVALID,
			    "init: ambiguous flags");
			goto qpmod_fail;

		} else if ((flags & IBT_CEP_SET_INIT_RTR) ||
		    ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_RTR))) {
			/*
			 * Attempt to transition from "Init" to "RTR"
			 */
			status = tavor_qp_init2rtr(state, qp, flags, info_p);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				/* Set "status"/"errormsg", goto failure */
				TAVOR_TNF_FAIL(status, "init to rtr");
				goto qpmod_fail;
			}
			qp->qp_state = TAVOR_QP_RTR;

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_INIT)) {
			/*
			 * Attempt to transition from "Init" to "Init"
			 */
			status = tavor_qp_init2init(state, qp, flags, info_p);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				/* Set "status"/"errormsg", goto failure */
				TAVOR_TNF_FAIL(status, "init to init");
				goto qpmod_fail;
			}
			qp->qp_state = TAVOR_QP_INIT;

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_RESET)) {
			/*
			 * Attempt to transition from "Init" to "Reset"
			 */
			status = tavor_qp_to_reset(state, qp);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				/* Set "status"/"errormsg", goto failure */
				TAVOR_TNF_FAIL(status, "init to reset");
				goto qpmod_fail;
			}
			qp->qp_state = TAVOR_QP_RESET;

			/*
			 * Do any additional handling necessary for the
			 * transition _to_ the "Reset" state (e.g. update the
			 * workQ WRID lists)
			 */
			tavor_wrid_to_reset_handling(state, qp);

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_ERROR)) {
			/*
			 * Attempt to transition from "Init" to "Error"
			 */
			status = tavor_qp_to_error(state, qp);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				/* Set "status"/"errormsg", goto failure */
				TAVOR_TNF_FAIL(status, "init to error");
				goto qpmod_fail;
			}
			qp->qp_state = TAVOR_QP_ERR;

		} else {
			/* Invalid transition - return error */
			mutex_exit(&qp->qp_lock);
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(IBT_QP_STATE_INVALID,
			    "init: invalid transition");
			goto qpmod_fail;
		}
		break;

	case TAVOR_QP_RTR:
		okflags = (IBT_CEP_SET_STATE | IBT_CEP_SET_RTR_RTS |
		    IBT_CEP_SET_TIMEOUT | IBT_CEP_SET_RETRY |
		    IBT_CEP_SET_RNR_NAK_RETRY | IBT_CEP_SET_RDMARA_OUT |
		    IBT_CEP_SET_RDMA_R | IBT_CEP_SET_RDMA_W |
		    IBT_CEP_SET_ATOMIC | IBT_CEP_SET_QKEY |
		    IBT_CEP_SET_ALT_PATH | IBT_CEP_SET_MIG |
		    IBT_CEP_SET_MIN_RNR_NAK);

		/*
		 * Check for attempts to modify invalid attributes from the
		 * "RTR" state
		 */
		if (flags & ~okflags) {
			mutex_exit(&qp->qp_lock);
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(IBT_QP_ATTR_RO, "rtr: invalid flag");
			goto qpmod_fail;
		}

		/*
		 * Verify state transition is to either "RTS", "Reset",
		 * or "Error"
		 */
		if ((flags & IBT_CEP_SET_RTR_RTS) &&
		    (flags & IBT_CEP_SET_STATE) &&
		    (mod_state != IBT_STATE_RTS)) {
			/* Invalid transition - ambiguous flags */
			mutex_exit(&qp->qp_lock);
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(IBT_QP_STATE_INVALID,
			    "reset: ambiguous flags");
			goto qpmod_fail;

		} else if ((flags & IBT_CEP_SET_RTR_RTS) ||
		    ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_RTS))) {
			/*
			 * Attempt to transition from "RTR" to "RTS"
			 */
			status = tavor_qp_rtr2rts(state, qp, flags, info_p);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				/* Set "status"/"errormsg", goto failure */
				TAVOR_TNF_FAIL(status, "rtr to rts");
				goto qpmod_fail;
			}
			qp->qp_state = TAVOR_QP_RTS;

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_RESET)) {
			/*
			 * Attempt to transition from "RTR" to "Reset"
			 */
			status = tavor_qp_to_reset(state, qp);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				/* Set "status"/"errormsg", goto failure */
				TAVOR_TNF_FAIL(status, "rtr to reset");
				goto qpmod_fail;
			}
			qp->qp_state = TAVOR_QP_RESET;

			/*
			 * Do any additional handling necessary for the
			 * transition _to_ the "Reset" state (e.g. update the
			 * workQ WRID lists)
			 */
			tavor_wrid_to_reset_handling(state, qp);

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_ERROR)) {
			/*
			 * Attempt to transition from "RTR" to "Error"
			 */
			status = tavor_qp_to_error(state, qp);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				/* Set "status"/"errormsg", goto failure */
				TAVOR_TNF_FAIL(status, "rtr to error");
				goto qpmod_fail;
			}
			qp->qp_state = TAVOR_QP_ERR;

		} else {
			/* Invalid transition - return error */
			mutex_exit(&qp->qp_lock);
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(IBT_QP_STATE_INVALID,
			    "rtr: invalid transition");
			goto qpmod_fail;
		}
		break;

	case TAVOR_QP_RTS:
		okflags = (IBT_CEP_SET_STATE | IBT_CEP_SET_RDMA_R |
		    IBT_CEP_SET_RDMA_W | IBT_CEP_SET_ATOMIC |
		    IBT_CEP_SET_QKEY | IBT_CEP_SET_ALT_PATH |
		    IBT_CEP_SET_MIG | IBT_CEP_SET_MIN_RNR_NAK |
		    IBT_CEP_SET_SQD_EVENT);

		/*
		 * Check for attempts to modify invalid attributes from the
		 * "RTS" state
		 */
		if (flags & ~okflags) {
			mutex_exit(&qp->qp_lock);
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(IBT_QP_ATTR_RO, "rts: invalid flag");
			goto qpmod_fail;
		}

		/*
		 * Verify state transition is to either "RTS", "SQD", "Reset",
		 * or "Error"
		 */
		if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_RTS)) {
			/*
			 * Attempt to transition from "RTS" to "RTS"
			 */
			status = tavor_qp_rts2rts(state, qp, flags, info_p);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				/* Set "status"/"errormsg", goto failure */
				TAVOR_TNF_FAIL(status, "rts to rts");
				goto qpmod_fail;
			}
			/* qp->qp_state = TAVOR_QP_RTS; */

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_SQD)) {
			/*
			 * Attempt to transition from "RTS" to "SQD"
			 */
			status = tavor_qp_rts2sqd(state, qp, flags);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				/* Set "status"/"errormsg", goto failure */
				TAVOR_TNF_FAIL(status, "rts to sqd");
				goto qpmod_fail;
			}
			qp->qp_state = TAVOR_QP_SQD;

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_RESET)) {
			/*
			 * Attempt to transition from "RTS" to "Reset"
			 */
			status = tavor_qp_to_reset(state, qp);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				/* Set "status"/"errormsg", goto failure */
				TAVOR_TNF_FAIL(status, "rts to reset");
				goto qpmod_fail;
			}
			qp->qp_state = TAVOR_QP_RESET;

			/*
			 * Do any additional handling necessary for the
			 * transition _to_ the "Reset" state (e.g. update the
			 * workQ WRID lists)
			 */
			tavor_wrid_to_reset_handling(state, qp);

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_ERROR)) {
			/*
			 * Attempt to transition from "RTS" to "Error"
			 */
			status = tavor_qp_to_error(state, qp);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				/* Set "status"/"errormsg", goto failure */
				TAVOR_TNF_FAIL(status, "rts to error");
				goto qpmod_fail;
			}
			qp->qp_state = TAVOR_QP_ERR;

		} else {
			/* Invalid transition - return error */
			mutex_exit(&qp->qp_lock);
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(IBT_QP_STATE_INVALID,
			    "rts: invalid transition");
			goto qpmod_fail;
		}
		break;

	case TAVOR_QP_SQERR:
		okflags = (IBT_CEP_SET_STATE | IBT_CEP_SET_RDMA_R |
		    IBT_CEP_SET_RDMA_W | IBT_CEP_SET_ATOMIC |
		    IBT_CEP_SET_QKEY | IBT_CEP_SET_MIN_RNR_NAK);

		/*
		 * Check for attempts to modify invalid attributes from the
		 * "SQErr" state
		 */
		if (flags & ~okflags) {
			mutex_exit(&qp->qp_lock);
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(IBT_QP_ATTR_RO, "sqerr: invalid flag");
			goto qpmod_fail;
		}

		/*
		 * Verify state transition is to either "RTS", "Reset", or
		 * "Error"
		 */
		if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_RTS)) {
			/*
			 * Attempt to transition from "SQErr" to "RTS"
			 */
			status = tavor_qp_sqerr2rts(state, qp, flags, info_p);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				/* Set "status"/"errormsg", goto failure */
				TAVOR_TNF_FAIL(status, "sqerr to rts");
				goto qpmod_fail;
			}
			qp->qp_state = TAVOR_QP_RTS;

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_RESET)) {
			/*
			 * Attempt to transition from "SQErr" to "Reset"
			 */
			status = tavor_qp_to_reset(state, qp);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				/* Set "status"/"errormsg", goto failure */
				TAVOR_TNF_FAIL(status, "sqerr to reset");
				goto qpmod_fail;
			}
			qp->qp_state = TAVOR_QP_RESET;

			/*
			 * Do any additional handling necessary for the
			 * transition _to_ the "Reset" state (e.g. update the
			 * workQ WRID lists)
			 */
			tavor_wrid_to_reset_handling(state, qp);

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_ERROR)) {
			/*
			 * Attempt to transition from "SQErr" to "Error"
			 */
			status = tavor_qp_to_error(state, qp);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				/* Set "status"/"errormsg", goto failure */
				TAVOR_TNF_FAIL(status, "sqerr to error");
				goto qpmod_fail;
			}
			qp->qp_state = TAVOR_QP_ERR;

		} else {
			/* Invalid transition - return error */
			mutex_exit(&qp->qp_lock);
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(IBT_QP_STATE_INVALID,
			    "sqerr: invalid transition");
			goto qpmod_fail;
		}
		break;

	case TAVOR_QP_SQD:
		okflags = (IBT_CEP_SET_STATE | IBT_CEP_SET_ADDS_VECT |
		    IBT_CEP_SET_ALT_PATH | IBT_CEP_SET_MIG |
		    IBT_CEP_SET_RDMARA_OUT | IBT_CEP_SET_RDMARA_IN |
		    IBT_CEP_SET_QKEY | IBT_CEP_SET_PKEY_IX |
		    IBT_CEP_SET_TIMEOUT | IBT_CEP_SET_RETRY |
		    IBT_CEP_SET_RNR_NAK_RETRY | IBT_CEP_SET_PORT |
		    IBT_CEP_SET_MIN_RNR_NAK | IBT_CEP_SET_RDMA_R |
		    IBT_CEP_SET_RDMA_W | IBT_CEP_SET_ATOMIC);

		/*
		 * Check for attempts to modify invalid attributes from the
		 * "SQD" state
		 */
		if (flags & ~okflags) {
			mutex_exit(&qp->qp_lock);
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(IBT_QP_ATTR_RO, "sqd: invalid flag");
			goto qpmod_fail;
		}

		/*
		 * Verify state transition is to either "SQD", "RTS", "Reset",
		 * or "Error"
		 */

		if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_SQD)) {
			/*
			 * Attempt to transition from "SQD" to "SQD"
			 */
			status = tavor_qp_sqd2sqd(state, qp, flags, info_p);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				/* Set "status"/"errormsg", goto failure */
				TAVOR_TNF_FAIL(status, "sqd to sqd");
				goto qpmod_fail;
			}
			qp->qp_state = TAVOR_QP_SQD;

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_RTS)) {
			/*
			 * If still draining SQ, then fail transition attempt
			 * to RTS.
			 */
			if (qp->qp_sqd_still_draining) {
				mutex_exit(&qp->qp_lock);
				/* Set "status"/"errormsg", goto failure */
				status = IBT_QP_STATE_INVALID;
				TAVOR_TNF_FAIL(status, "sqd to rts; draining");
				goto qpmod_fail;
			}

			/*
			 * Attempt to transition from "SQD" to "RTS"
			 */
			status = tavor_qp_sqd2rts(state, qp, flags, info_p);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				/* Set "status"/"errormsg", goto failure */
				TAVOR_TNF_FAIL(status, "sqd to rts");
				goto qpmod_fail;
			}
			qp->qp_state = TAVOR_QP_RTS;

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_RESET)) {
			/*
			 * Attempt to transition from "SQD" to "Reset"
			 */
			status = tavor_qp_to_reset(state, qp);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				/* Set "status"/"errormsg", goto failure */
				TAVOR_TNF_FAIL(status, "sqd to reset");
				goto qpmod_fail;
			}
			qp->qp_state = TAVOR_QP_RESET;

			/*
			 * Do any additional handling necessary for the
			 * transition _to_ the "Reset" state (e.g. update the
			 * workQ WRID lists)
			 */
			tavor_wrid_to_reset_handling(state, qp);

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_ERROR)) {
			/*
			 * Attempt to transition from "SQD" to "Error"
			 */
			status = tavor_qp_to_error(state, qp);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				/* Set "status"/"errormsg", goto failure */
				TAVOR_TNF_FAIL(status, "sqd to error");
				goto qpmod_fail;
			}
			qp->qp_state = TAVOR_QP_ERR;

		} else {
			/* Invalid transition - return error */
			mutex_exit(&qp->qp_lock);
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(IBT_QP_STATE_INVALID,
			    "sqd: invalid transition");
			goto qpmod_fail;
		}
		break;

	case TAVOR_QP_ERR:
		/*
		 * Verify state transition is to either "Reset" or back to
		 * "Error"
		 */
		if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_RESET)) {
			/*
			 * Attempt to transition from "Error" to "Reset"
			 */
			status = tavor_qp_to_reset(state, qp);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				/* Set "status"/"errormsg", goto failure */
				TAVOR_TNF_FAIL(status, "error to reset");
				goto qpmod_fail;
			}
			qp->qp_state = TAVOR_QP_RESET;

			/*
			 * Do any additional handling necessary for the
			 * transition _to_ the "Reset" state (e.g. update the
			 * workQ WRID lists)
			 */
			tavor_wrid_to_reset_handling(state, qp);

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_ERROR)) {
			/*
			 * Attempt to transition from "Error" back to "Error"
			 *    Nothing to do here really... just drop the lock
			 *    and return success.  The qp->qp_state should
			 *    already be set to TAVOR_QP_ERR.
			 *
			 */
			mutex_exit(&qp->qp_lock);
			TNF_PROBE_0_DEBUG(tavor_qp_modify_err2err,
			    TAVOR_TNF_TRACE, "");
			TAVOR_TNF_EXIT(tavor_qp_modify);
			return (DDI_SUCCESS);

		} else {
			/* Invalid transition - return error */
			mutex_exit(&qp->qp_lock);
			/* Set "status" and "errormsg" and goto failure */
			TAVOR_TNF_FAIL(IBT_QP_STATE_INVALID,
			    "error: invalid transition");
			goto qpmod_fail;
		}
		break;

	default:
		/*
		 * Invalid QP state.  If we got here then it's a warning of
		 * a probably serious problem.  So print a message and return
		 * failure
		 */
		mutex_exit(&qp->qp_lock);
		TAVOR_WARNING(state, "unknown QP state in modify");
		/* Set "status" and "errormsg" and goto failure */
		TAVOR_TNF_FAIL(IBT_QP_STATE_INVALID, "invalid curr QP state");
		goto qpmod_fail;
	}

	mutex_exit(&qp->qp_lock);
	TAVOR_TNF_EXIT(tavor_qp_modify);
	return (DDI_SUCCESS);

qpmod_fail:
	TNF_PROBE_1(tavor_qp_modify_fail, TAVOR_TNF_ERROR, "",
	    tnf_string, msg, errormsg);
	TAVOR_TNF_EXIT(tavor_qp_modify);
	return (status);
}


/*
 * tavor_qp_reset2init()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_qp_reset2init(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_qp_info_t *info_p)
{
	tavor_hw_qpc_t		*qpc;
	ibt_qp_rc_attr_t	*rc;
	ibt_qp_ud_attr_t	*ud;
	ibt_qp_uc_attr_t	*uc;
	uint_t			portnum, pkeyindx;
	int			status;

	TAVOR_TNF_ENTER(tavor_qp_reset2init);

	ASSERT(MUTEX_HELD(&qp->qp_lock));

	/*
	 * Grab the temporary QPC entry from QP software state
	 */
	qpc = &qp->qpc;

	/*
	 * Fill in the common and/or Tavor-specific fields in the QPC
	 */
	if (qp->qp_is_special) {
		qpc->serv_type	= TAVOR_QP_MLX;
	} else {
		qpc->serv_type	= qp->qp_serv_type;
	}
	qpc->pm_state		= TAVOR_QP_PMSTATE_MIGRATED;
	qpc->de			= TAVOR_QP_DESC_EVT_ENABLED;
	qpc->sched_q		= TAVOR_QP_SCHEDQ_GET(qp->qp_qpnum);
	if (qp->qp_is_umap) {
		qpc->usr_page = qp->qp_uarpg;
	} else {
		qpc->usr_page = 0;
	}
	qpc->pd			= qp->qp_pdhdl->pd_pdnum;
	qpc->wqe_baseaddr	= 0;
	qpc->wqe_lkey		= qp->qp_mrhdl->mr_lkey;
	qpc->ssc		= qp->qp_sq_sigtype;
	qpc->cqn_snd		= qp->qp_sq_cqhdl->cq_cqnum;
	qpc->rsc		= TAVOR_QP_RQ_ALL_SIGNALED;
	qpc->cqn_rcv		= qp->qp_rq_cqhdl->cq_cqnum;
	qpc->srq_en		= qp->qp_srq_en;

	if (qp->qp_srq_en == TAVOR_QP_SRQ_ENABLED) {
		qpc->srq_number	= qp->qp_srqhdl->srq_srqnum;
	} else {
		qpc->srq_number = 0;
	}

	/*
	 * Now fill in the QPC fields which are specific to transport type
	 */
	if (qp->qp_serv_type == TAVOR_QP_UD) {
		ud = &info_p->qp_transport.ud;

		/* Set the QKey */
		qpc->qkey = ud->ud_qkey;

		/* Check for valid port number and fill it in */
		portnum = ud->ud_port;
		if (tavor_portnum_is_valid(state, portnum)) {
			qpc->pri_addr_path.portnum = portnum;
		} else {
			TNF_PROBE_1(tavor_qp_reset2init_inv_port_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, port, portnum);
			TAVOR_TNF_EXIT(tavor_qp_reset2init);
			return (IBT_HCA_PORT_INVALID);
		}

		/* Check for valid PKey index and fill it in */
		pkeyindx = ud->ud_pkey_ix;
		if (tavor_pkeyindex_is_valid(state, pkeyindx)) {
			qpc->pri_addr_path.pkey_indx = pkeyindx;
			qp->qp_pkeyindx = pkeyindx;
		} else {
			TNF_PROBE_1(tavor_qp_reset2init_inv_pkey_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, pkeyindx, pkeyindx);
			TAVOR_TNF_EXIT(tavor_qp_reset2init);
			return (IBT_PKEY_IX_ILLEGAL);
		}

	} else if (qp->qp_serv_type == TAVOR_QP_RC) {
		rc = &info_p->qp_transport.rc;

		/* Set the RDMA (recv) enable/disable flags */
		qpc->rre = (info_p->qp_flags & IBT_CEP_RDMA_RD) ? 1 : 0;
		qpc->rwe = (info_p->qp_flags & IBT_CEP_RDMA_WR) ? 1 : 0;
		qpc->rae = (info_p->qp_flags & IBT_CEP_ATOMIC)  ? 1 : 0;

		/* Check for valid port number and fill it in */
		portnum = rc->rc_path.cep_hca_port_num;
		if (tavor_portnum_is_valid(state, portnum)) {
			qpc->pri_addr_path.portnum = portnum;
		} else {
			TNF_PROBE_1(tavor_qp_reset2init_inv_port_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, port, portnum);
			TAVOR_TNF_EXIT(tavor_qp_reset2init);
			return (IBT_HCA_PORT_INVALID);
		}

		/* Check for valid PKey index and fill it in */
		pkeyindx = rc->rc_path.cep_pkey_ix;
		if (tavor_pkeyindex_is_valid(state, pkeyindx)) {
			qpc->pri_addr_path.pkey_indx = pkeyindx;
		} else {
			TNF_PROBE_1(tavor_qp_reset2init_inv_pkey_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, pkeyindx, pkeyindx);
			TAVOR_TNF_EXIT(tavor_qp_reset2init);
			return (IBT_PKEY_IX_ILLEGAL);
		}

	} else if (qp->qp_serv_type == TAVOR_QP_UC) {
		uc = &info_p->qp_transport.uc;

		/*
		 * Set the RDMA (recv) enable/disable flags.  Note: RDMA Read
		 * and Atomic are ignored by default.
		 */
		qpc->rwe = (info_p->qp_flags & IBT_CEP_RDMA_WR) ? 1 : 0;

		/* Check for valid port number and fill it in */
		portnum = uc->uc_path.cep_hca_port_num;
		if (tavor_portnum_is_valid(state, portnum)) {
			qpc->pri_addr_path.portnum = portnum;
		} else {
			TNF_PROBE_1(tavor_qp_reset2init_inv_port_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, port, portnum);
			TAVOR_TNF_EXIT(tavor_qp_reset2init);
			return (IBT_HCA_PORT_INVALID);
		}

		/* Check for valid PKey index and fill it in */
		pkeyindx = uc->uc_path.cep_pkey_ix;
		if (tavor_pkeyindex_is_valid(state, pkeyindx)) {
			qpc->pri_addr_path.pkey_indx = pkeyindx;
		} else {
			TNF_PROBE_1(tavor_qp_reset2init_inv_pkey_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, pkeyindx, pkeyindx);
			TAVOR_TNF_EXIT(tavor_qp_reset2init);
			return (IBT_PKEY_IX_ILLEGAL);
		}
	} else {
		/*
		 * Invalid QP transport type. If we got here then it's a
		 * warning of a probably serious problem.  So print a message
		 * and return failure
		 */
		TAVOR_WARNING(state, "unknown QP transport type in rst2init");
		TNF_PROBE_0(tavor_qp_reset2init_inv_transtype_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_qp_reset2init);
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Post the RST2INIT_QP command to the Tavor firmware
	 *
	 * We do a TAVOR_NOSLEEP here because we are still holding the
	 * "qp_lock".  If we got raised to interrupt level by priority
	 * inversion, we do not want to block in this routine waiting for
	 * success.
	 */
	status = tavor_cmn_qp_cmd_post(state, RST2INIT_QP, qpc, qp->qp_qpnum,
	    0, TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Tavor: RST2INIT_QP command failed: %08x\n",
		    status);
		TNF_PROBE_1(tavor_qp_reset2init_cmd_fail, TAVOR_TNF_ERROR, "",
		    tnf_uint, status, status);
		TAVOR_TNF_EXIT(tavor_qp_reset2init);
		return (ibc_get_ci_failure(0));
	}

	TAVOR_TNF_EXIT(tavor_qp_reset2init);
	return (DDI_SUCCESS);
}


/*
 * tavor_qp_init2init()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_qp_init2init(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p)
{
	tavor_hw_qpc_t		*qpc;
	ibt_qp_rc_attr_t	*rc;
	ibt_qp_ud_attr_t	*ud;
	ibt_qp_uc_attr_t	*uc;
	uint_t			portnum, pkeyindx;
	uint32_t		opmask = 0;
	int			status;

	TAVOR_TNF_ENTER(tavor_qp_init2init);

	ASSERT(MUTEX_HELD(&qp->qp_lock));

	/*
	 * Grab the temporary QPC entry from QP software state
	 */
	qpc = &qp->qpc;

	/*
	 * Since there are no common and/or Tavor-specific fields to be filled
	 * in for this command, we begin with the QPC fields which are
	 * specific to transport type.
	 */
	if (qp->qp_serv_type == TAVOR_QP_UD) {
		ud = &info_p->qp_transport.ud;

		/*
		 * If we are attempting to modify the port for this QP, then
		 * check for valid port number and fill it in.  Also set the
		 * appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_PORT) {
			portnum = ud->ud_port;
			if (tavor_portnum_is_valid(state, portnum)) {
				qpc->pri_addr_path.portnum = portnum;
			} else {
				TNF_PROBE_1(tavor_qp_init2init_inv_port_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, port,
				    portnum);
				TAVOR_TNF_EXIT(tavor_qp_init2init);
				return (IBT_HCA_PORT_INVALID);
			}
			opmask |= TAVOR_CMD_OP_PRIM_PORT;
		}

		/*
		 * If we are attempting to modify the PKey index for this QP,
		 * then check for valid PKey index and fill it in.  Also set
		 * the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_PKEY_IX) {
			pkeyindx = ud->ud_pkey_ix;
			if (tavor_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->pri_addr_path.pkey_indx = pkeyindx;
				opmask |= TAVOR_CMD_OP_PKEYINDX;
				qp->qp_pkeyindx = pkeyindx;
			} else {
				TNF_PROBE_1(tavor_qp_init2init_inv_pkey_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, pkeyindx,
				    pkeyindx);
				TAVOR_TNF_EXIT(tavor_qp_init2init);
				return (IBT_PKEY_IX_ILLEGAL);
			}
		}

		/*
		 * If we are attempting to modify the QKey for this QP, then
		 * fill it in and set the appropriate flag in the "opmask"
		 * parameter.
		 */
		if (flags & IBT_CEP_SET_QKEY) {
			qpc->qkey = ud->ud_qkey;
			opmask |= TAVOR_CMD_OP_QKEY;
		}

	} else if (qp->qp_serv_type == TAVOR_QP_RC) {
		rc = &info_p->qp_transport.rc;

		/*
		 * If we are attempting to modify the port for this QP, then
		 * check for valid port number and fill it in.  Also set the
		 * appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_PORT) {
			portnum = rc->rc_path.cep_hca_port_num;
			if (tavor_portnum_is_valid(state, portnum)) {
				qpc->pri_addr_path.portnum = portnum;
			} else {
				TNF_PROBE_1(tavor_qp_init2init_inv_port_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, port,
				    portnum);
				TAVOR_TNF_EXIT(tavor_qp_init2init);
				return (IBT_HCA_PORT_INVALID);
			}
			opmask |= TAVOR_CMD_OP_PRIM_PORT;
		}

		/*
		 * If we are attempting to modify the PKey index for this QP,
		 * then check for valid PKey index and fill it in.  Also set
		 * the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_PKEY_IX) {
			pkeyindx = rc->rc_path.cep_pkey_ix;
			if (tavor_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->pri_addr_path.pkey_indx = pkeyindx;
				opmask |= TAVOR_CMD_OP_PKEYINDX;
			} else {
				TNF_PROBE_1(tavor_qp_init2init_inv_pkey_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, pkeyindx,
				    pkeyindx);
				TAVOR_TNF_EXIT(tavor_qp_init2init);
				return (IBT_PKEY_IX_ILLEGAL);
			}
		}

		/*
		 * Check if any of the flags indicate a change in the RDMA
		 * (recv) enable/disable flags and set the appropriate flag in
		 * the "opmask" parameter
		 */
		opmask |= tavor_check_rdma_enable_flags(flags, info_p, qpc);

	} else if (qp->qp_serv_type == TAVOR_QP_UC) {
		uc = &info_p->qp_transport.uc;

		/*
		 * If we are attempting to modify the port for this QP, then
		 * check for valid port number and fill it in.  Also set the
		 * appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_PORT) {
			portnum = uc->uc_path.cep_hca_port_num;
			if (tavor_portnum_is_valid(state, portnum)) {
				qpc->pri_addr_path.portnum = portnum;
			} else {
				TNF_PROBE_1(tavor_qp_init2init_inv_port_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, port,
				    portnum);
				TAVOR_TNF_EXIT(tavor_qp_init2init);
				return (IBT_HCA_PORT_INVALID);
			}
			opmask |= TAVOR_CMD_OP_PRIM_PORT;
		}

		/*
		 * If we are attempting to modify the PKey index for this QP,
		 * then check for valid PKey index and fill it in.  Also set
		 * the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_PKEY_IX) {
			pkeyindx = uc->uc_path.cep_pkey_ix;
			if (tavor_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->pri_addr_path.pkey_indx = pkeyindx;
				opmask |= TAVOR_CMD_OP_PKEYINDX;
			} else {
				TNF_PROBE_1(tavor_qp_init2init_inv_pkey_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, pkeyindx,
				    pkeyindx);
				TAVOR_TNF_EXIT(tavor_qp_init2init);
				return (IBT_PKEY_IX_ILLEGAL);
			}
		}

		/*
		 * Check if any of the flags indicate a change in the RDMA
		 * Write (recv) enable/disable and set the appropriate flag
		 * in the "opmask" parameter. Note: RDMA Read and Atomic are
		 * not valid for UC transport.
		 */
		if (flags & IBT_CEP_SET_RDMA_W) {
			qpc->rwe = (info_p->qp_flags & IBT_CEP_RDMA_WR) ? 1 : 0;
			opmask |= TAVOR_CMD_OP_RWE;
		}
	} else {
		/*
		 * Invalid QP transport type. If we got here then it's a
		 * warning of a probably serious problem.  So print a message
		 * and return failure
		 */
		TAVOR_WARNING(state, "unknown QP transport type in init2init");
		TNF_PROBE_0(tavor_qp_init2init_inv_transtype_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_qp_init2init);
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Post the INIT2INIT_QP command to the Tavor firmware
	 *
	 * We do a TAVOR_NOSLEEP here because we are still holding the
	 * "qp_lock".  If we got raised to interrupt level by priority
	 * inversion, we do not want to block in this routine waiting for
	 * success.
	 */
	status = tavor_cmn_qp_cmd_post(state, INIT2INIT_QP, qpc, qp->qp_qpnum,
	    opmask, TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		if (status != TAVOR_CMD_BAD_QP_STATE) {
			cmn_err(CE_CONT, "Tavor: INIT2INIT_QP command failed: "
			    "%08x\n", status);
			TNF_PROBE_1(tavor_qp_init2init_cmd_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, status, status);
			TAVOR_TNF_EXIT(tavor_qp_init2init);
			return (ibc_get_ci_failure(0));
		} else {
			TNF_PROBE_0(tavor_qp_init2init_inv_qpstate_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_qp_init2init);
			return (IBT_QP_STATE_INVALID);
		}
	}

	TAVOR_TNF_EXIT(tavor_qp_init2init);
	return (DDI_SUCCESS);
}


/*
 * tavor_qp_init2rtr()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_qp_init2rtr(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p)
{
	tavor_hw_qpc_t		*qpc;
	ibt_qp_rc_attr_t	*rc;
	ibt_qp_ud_attr_t	*ud;
	ibt_qp_uc_attr_t	*uc;
	tavor_hw_addr_path_t	*qpc_path;
	ibt_adds_vect_t		*adds_vect;
	uint_t			portnum, pkeyindx, rdma_ra_in, rra_max;
	uint_t			mtu;
	uint32_t		opmask = 0;
	int			status;

	TAVOR_TNF_ENTER(tavor_qp_init2rtr);

	ASSERT(MUTEX_HELD(&qp->qp_lock));

	/*
	 * Grab the temporary QPC entry from QP software state
	 */
	qpc = &qp->qpc;

	/*
	 * Since there are no common and/or Tavor-specific fields to be filled
	 * in for this command, we begin with the QPC fields which are
	 * specific to transport type.
	 */
	if (qp->qp_serv_type == TAVOR_QP_UD) {
		ud = &info_p->qp_transport.ud;

		/*
		 * If this UD QP is also a "special QP" (QP0 or QP1), then
		 * the MTU is 256 bytes.  However, Tavor HW requires us to
		 * set the MTU to 4 (which is the IB code for a 2K MTU).
		 * If this is not a special QP, then we set the MTU to the
		 * configured maximum (which defaults to 2K).  Note: the
		 * QPC "msg_max" must also be set so as to correspond with
		 * the specified MTU value.
		 */
		if (qp->qp_is_special) {
			qpc->mtu = 4;
		} else {
			qpc->mtu = state->ts_cfg_profile->cp_max_mtu;
		}
		qpc->msg_max = qpc->mtu + 7;  /* must equal MTU plus seven */

		/*
		 * Save away the MTU value.  This is used in future sqd2sqd
		 * transitions, as the MTU must remain the same in future
		 * changes.
		 */
		qp->qp_save_mtu = qpc->mtu;

		/*
		 * If we are attempting to modify the PKey index for this QP,
		 * then check for valid PKey index and fill it in.  Also set
		 * the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_PKEY_IX) {
			pkeyindx = ud->ud_pkey_ix;
			if (tavor_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->pri_addr_path.pkey_indx = pkeyindx;
				opmask |= TAVOR_CMD_OP_PKEYINDX;
				qp->qp_pkeyindx = pkeyindx;
			} else {
				TNF_PROBE_1(tavor_qp_init2rtr_inv_pkey_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, pkeyindx,
				    pkeyindx);
				TAVOR_TNF_EXIT(tavor_qp_init2rtr);
				return (IBT_PKEY_IX_ILLEGAL);
			}
		}

		/*
		 * If we are attempting to modify the QKey for this QP, then
		 * fill it in and set the appropriate flag in the "opmask"
		 * parameter.
		 */
		if (flags & IBT_CEP_SET_QKEY) {
			qpc->qkey = ud->ud_qkey;
			opmask |= TAVOR_CMD_OP_QKEY;
		}

	} else if (qp->qp_serv_type == TAVOR_QP_RC) {
		rc = &info_p->qp_transport.rc;
		qpc_path = &qpc->pri_addr_path;
		adds_vect = &rc->rc_path.cep_adds_vect;

		/*
		 * Set the common primary address path fields
		 */
		status = tavor_set_addr_path(state, adds_vect, qpc_path,
		    TAVOR_ADDRPATH_QP, qp);
		if (status != DDI_SUCCESS) {
			TNF_PROBE_0(tavor_qp_init2rtr_setaddrpath_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_qp_init2rtr);
			return (status);
		}

		/*
		 * The following values are apparently "required" here (as
		 * they are part of the IBA-defined "Remote Node Address
		 * Vector").  However, they are also going to be "required"
		 * later - at RTR2RTS_QP time.  Not sure why.  But we set
		 * them here anyway.
		 */
		qpc_path->rnr_retry	= rc->rc_rnr_retry_cnt;
		qpc->retry_cnt		= rc->rc_retry_cnt;
		qpc_path->ack_timeout	= rc->rc_path.cep_timeout;

		/*
		 * Setup the destination QP, recv PSN, MTU, max msg size,etc.
		 * Note max message size is defined to be the maximum IB
		 * allowed message size (which is 2^31 bytes).  Also max
		 * MTU is defined by HCA port properties.
		 */
		qpc->rem_qpn	  = rc->rc_dst_qpn;
		qpc->next_rcv_psn = rc->rc_rq_psn;
		qpc->msg_max	  = TAVOR_QP_LOG_MAX_MSGSZ;

		/*
		 * If this QP is using an SRQ, 'ric' must be set to 1.
		 */
		qpc->ric = (qp->qp_srq_en == TAVOR_QP_SRQ_ENABLED) ? 1 : 0;
		mtu = rc->rc_path_mtu;
		if (tavor_qp_validate_mtu(state, mtu) != DDI_SUCCESS) {
			TNF_PROBE_1(tavor_qp_init2rtr_inv_mtu_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, mtu, mtu);
			TAVOR_TNF_EXIT(tavor_qp_init2rtr);
			return (IBT_HCA_PORT_MTU_EXCEEDED);
		}
		qpc->mtu = mtu;

		/*
		 * Save away the MTU value.  This is used in future sqd2sqd
		 * transitions, as the MTU must remain the same in future
		 * changes.
		 */
		qp->qp_save_mtu = qpc->mtu;

		/*
		 * Though it is a "required" parameter, "min_rnr_nak" is
		 * optionally specifiable in Tavor.  So we hardcode the
		 * optional flag here.
		 */
		qpc->min_rnr_nak = rc->rc_min_rnr_nak;
		opmask |= TAVOR_CMD_OP_MINRNRNAK;

		/*
		 * Check that the number of specified "incoming RDMA resources"
		 * is valid.  And if it is, then setup the "rra_max" and
		 * "ra_buf_index" fields in the QPC to point to the
		 * pre-allocated RDB resources (in DDR)
		 */
		rdma_ra_in = rc->rc_rdma_ra_in;
		if (tavor_qp_validate_resp_rsrc(state, rc, &rra_max) !=
		    DDI_SUCCESS) {
			TNF_PROBE_1(tavor_qp_init2rtr_inv_rdma_in_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, rdma_ra_in,
			    rdma_ra_in);
			TAVOR_TNF_EXIT(tavor_qp_init2rtr);
			return (IBT_INVALID_PARAM);
		}
		qpc->rra_max = rra_max;
		qpc->ra_buff_indx = qp->qp_rdb_ddraddr >> TAVOR_RDB_SIZE_SHIFT;

		/*
		 * If we are attempting to modify the PKey index for this QP,
		 * then check for valid PKey index and fill it in.  Also set
		 * the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_PKEY_IX) {
			pkeyindx = rc->rc_path.cep_pkey_ix;
			if (tavor_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->pri_addr_path.pkey_indx = pkeyindx;
				opmask |= TAVOR_CMD_OP_PKEYINDX;
			} else {
				TNF_PROBE_1(tavor_qp_init2rtr_inv_pkey_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, pkeyindx,
				    pkeyindx);
				TAVOR_TNF_EXIT(tavor_qp_init2rtr);
				return (IBT_PKEY_IX_ILLEGAL);
			}
		}

		/*
		 * Check if any of the flags indicate a change in the RDMA
		 * (recv) enable/disable flags and set the appropriate flag in
		 * the "opmask" parameter
		 */
		opmask |= tavor_check_rdma_enable_flags(flags, info_p, qpc);

		/*
		 * Check for optional alternate path and fill in the
		 * appropriate QPC fields if one is specified
		 */
		if (flags & IBT_CEP_SET_ALT_PATH) {
			qpc_path = &qpc->alt_addr_path;
			adds_vect = &rc->rc_alt_path.cep_adds_vect;

			/* Set the common alternate address path fields */
			status = tavor_set_addr_path(state, adds_vect, qpc_path,
			    TAVOR_ADDRPATH_QP, qp);
			if (status != DDI_SUCCESS) {
				TNF_PROBE_0(tavor_qp_init2rtr_setaddrpath_fail,
				    TAVOR_TNF_ERROR, "");
				TAVOR_TNF_EXIT(tavor_qp_init2rtr);
				return (status);
			}
			qpc_path->ack_timeout = rc->rc_alt_path.cep_timeout;

			/*
			 * Copy the "RNR Retry count" value from the primary
			 * path.  Just as we did above, we need to hardcode
			 * the optional flag here (see below).
			 */
			qpc_path->rnr_retry = rc->rc_rnr_retry_cnt;

			/*
			 * Check for valid alternate path port number and fill
			 * it in
			 */
			portnum = rc->rc_alt_path.cep_hca_port_num;
			if (tavor_portnum_is_valid(state, portnum)) {
				qpc->alt_addr_path.portnum = portnum;
			} else {
				TNF_PROBE_1(tavor_qp_init2rtr_inv_altport_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, altport,
				    portnum);
				TAVOR_TNF_EXIT(tavor_qp_init2rtr);
				return (IBT_HCA_PORT_INVALID);
			}

			/*
			 * Check for valid alternate path PKey index and fill
			 * it in
			 */
			pkeyindx = rc->rc_alt_path.cep_pkey_ix;
			if (tavor_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->alt_addr_path.pkey_indx = pkeyindx;
			} else {
				TNF_PROBE_1(tavor_qp_init2rtr_inv_altpkey_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, altpkeyindx,
				    pkeyindx);
				TAVOR_TNF_EXIT(tavor_qp_init2rtr);
				return (IBT_PKEY_IX_ILLEGAL);
			}
			opmask |= (TAVOR_CMD_OP_ALT_PATH |
			    TAVOR_CMD_OP_ALT_RNRRETRY);
		}

	} else if (qp->qp_serv_type == TAVOR_QP_UC) {
		uc = &info_p->qp_transport.uc;
		qpc_path = &qpc->pri_addr_path;
		adds_vect = &uc->uc_path.cep_adds_vect;

		/*
		 * Set the common primary address path fields
		 */
		status = tavor_set_addr_path(state, adds_vect, qpc_path,
		    TAVOR_ADDRPATH_QP, qp);
		if (status != DDI_SUCCESS) {
			TNF_PROBE_0(tavor_qp_init2rtr_setaddrpath_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_qp_init2rtr);
			return (status);
		}

		/*
		 * Setup the destination QP, recv PSN, MTU, max msg size,etc.
		 * Note max message size is defined to be the maximum IB
		 * allowed message size (which is 2^31 bytes).  Also max
		 * MTU is defined by HCA port properties.
		 */
		qpc->rem_qpn	  = uc->uc_dst_qpn;
		qpc->next_rcv_psn = uc->uc_rq_psn;
		qpc->msg_max	  = TAVOR_QP_LOG_MAX_MSGSZ;
		mtu = uc->uc_path_mtu;
		if (tavor_qp_validate_mtu(state, mtu) != DDI_SUCCESS) {
			TNF_PROBE_1(tavor_qp_init2rtr_inv_mtu_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, mtu, mtu);
			TAVOR_TNF_EXIT(tavor_qp_init2rtr);
			return (IBT_HCA_PORT_MTU_EXCEEDED);
		}
		qpc->mtu = mtu;

		/*
		 * Save away the MTU value.  This is used in future sqd2sqd
		 * transitions, as the MTU must remain the same in future
		 * changes.
		 */
		qp->qp_save_mtu = qpc->mtu;

		/*
		 * If we are attempting to modify the PKey index for this QP,
		 * then check for valid PKey index and fill it in.  Also set
		 * the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_PKEY_IX) {
			pkeyindx = uc->uc_path.cep_pkey_ix;
			if (tavor_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->pri_addr_path.pkey_indx = pkeyindx;
				opmask |= TAVOR_CMD_OP_PKEYINDX;
			} else {
				TNF_PROBE_1(tavor_qp_init2rtr_inv_pkey_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, pkeyindx,
				    pkeyindx);
				TAVOR_TNF_EXIT(tavor_qp_init2rtr);
				return (IBT_PKEY_IX_ILLEGAL);
			}
		}

		/*
		 * Check if any of the flags indicate a change in the RDMA
		 * Write (recv) enable/disable and set the appropriate flag
		 * in the "opmask" parameter. Note: RDMA Read and Atomic are
		 * not valid for UC transport.
		 */
		if (flags & IBT_CEP_SET_RDMA_W) {
			qpc->rwe = (info_p->qp_flags & IBT_CEP_RDMA_WR) ? 1 : 0;
			opmask |= TAVOR_CMD_OP_RWE;
		}

		/*
		 * Check for optional alternate path and fill in the
		 * appropriate QPC fields if one is specified
		 */
		if (flags & IBT_CEP_SET_ALT_PATH) {
			qpc_path = &qpc->alt_addr_path;
			adds_vect = &uc->uc_alt_path.cep_adds_vect;

			/* Set the common alternate address path fields */
			status = tavor_set_addr_path(state, adds_vect, qpc_path,
			    TAVOR_ADDRPATH_QP, qp);
			if (status != DDI_SUCCESS) {
				TNF_PROBE_0(tavor_qp_init2rtr_setaddrpath_fail,
				    TAVOR_TNF_ERROR, "");
				TAVOR_TNF_EXIT(tavor_qp_init2rtr);
				return (status);
			}

			/*
			 * Check for valid alternate path port number and fill
			 * it in
			 */
			portnum = uc->uc_alt_path.cep_hca_port_num;
			if (tavor_portnum_is_valid(state, portnum)) {
				qpc->alt_addr_path.portnum = portnum;
			} else {
				TNF_PROBE_1(tavor_qp_init2rtr_inv_altport_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, altport,
				    portnum);
				TAVOR_TNF_EXIT(tavor_qp_init2rtr);
				return (IBT_HCA_PORT_INVALID);
			}

			/*
			 * Check for valid alternate path PKey index and fill
			 * it in
			 */
			pkeyindx = uc->uc_alt_path.cep_pkey_ix;
			if (tavor_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->alt_addr_path.pkey_indx = pkeyindx;
			} else {
				TNF_PROBE_1(tavor_qp_init2rtr_inv_altpkey_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, altpkeyindx,
				    pkeyindx);
				TAVOR_TNF_EXIT(tavor_qp_init2rtr);
				return (IBT_PKEY_IX_ILLEGAL);
			}
			opmask |= TAVOR_CMD_OP_ALT_PATH;
		}
	} else {
		/*
		 * Invalid QP transport type. If we got here then it's a
		 * warning of a probably serious problem.  So print a message
		 * and return failure
		 */
		TAVOR_WARNING(state, "unknown QP transport type in init2rtr");
		TNF_PROBE_0(tavor_qp_init2rtr_inv_transtype_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_qp_init2rtr);
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Post the INIT2RTR_QP command to the Tavor firmware
	 *
	 * We do a TAVOR_NOSLEEP here because we are still holding the
	 * "qp_lock".  If we got raised to interrupt level by priority
	 * inversion, we do not want to block in this routine waiting for
	 * success.
	 */
	status = tavor_cmn_qp_cmd_post(state, INIT2RTR_QP, qpc, qp->qp_qpnum,
	    opmask, TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		if (status != TAVOR_CMD_BAD_QP_STATE) {
			cmn_err(CE_CONT, "Tavor: INIT2RTR_QP command failed: "
			    "%08x\n", status);
			TNF_PROBE_1(tavor_qp_init2rtr_cmd_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, status, status);
			TAVOR_TNF_EXIT(tavor_qp_init2rtr);
			return (ibc_get_ci_failure(0));
		} else {
			TNF_PROBE_0(tavor_qp_init2rtr_inv_qpstate_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_qp_init2rtr);
			return (IBT_QP_STATE_INVALID);
		}
	}

	TAVOR_TNF_EXIT(tavor_qp_init2rtr);
	return (DDI_SUCCESS);
}


/*
 * tavor_qp_rtr2rts()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_qp_rtr2rts(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p)
{
	tavor_hw_qpc_t		*qpc;
	ibt_qp_rc_attr_t	*rc;
	ibt_qp_ud_attr_t	*ud;
	ibt_qp_uc_attr_t	*uc;
	tavor_hw_addr_path_t	*qpc_path;
	ibt_adds_vect_t		*adds_vect;
	uint_t			portnum, pkeyindx, rdma_ra_out, sra_max;
	uint32_t		opmask = 0;
	int			status;

	TAVOR_TNF_ENTER(tavor_qp_rtr2rts);

	ASSERT(MUTEX_HELD(&qp->qp_lock));

	/*
	 * Grab the temporary QPC entry from QP software state
	 */
	qpc = &qp->qpc;

	/*
	 * Fill in the common and/or Tavor-specific fields in the QPC
	 */
	qpc->flight_lim = TAVOR_QP_FLIGHT_LIM_UNLIMITED;

	/*
	 * Now fill in the QPC fields which are specific to transport type
	 */
	if (qp->qp_serv_type == TAVOR_QP_UD) {
		ud = &info_p->qp_transport.ud;

		/* Set the send PSN */
		qpc->next_snd_psn = ud->ud_sq_psn;

		/*
		 * If we are attempting to modify the QKey for this QP, then
		 * fill it in and set the appropriate flag in the "opmask"
		 * parameter.
		 */
		if (flags & IBT_CEP_SET_QKEY) {
			qpc->qkey = ud->ud_qkey;
			opmask |= TAVOR_CMD_OP_QKEY;
		}

	} else if (qp->qp_serv_type == TAVOR_QP_RC) {
		rc = &info_p->qp_transport.rc;
		qpc_path = &qpc->pri_addr_path;

		/*
		 * Setup the send PSN, ACK timeout, and retry counts
		 */
		qpc->next_snd_psn	= rc->rc_sq_psn;
		qpc_path->ack_timeout	= rc->rc_path.cep_timeout;
		qpc_path->rnr_retry	= rc->rc_rnr_retry_cnt;
		qpc->retry_cnt		= rc->rc_retry_cnt;

		/*
		 * Set "ack_req_freq" based on the configuration variable
		 */
		qpc->ack_req_freq = state->ts_cfg_profile->cp_ackreq_freq;

		/*
		 * Check that the number of specified "outgoing RDMA resources"
		 * is valid.  And if it is, then setup the "sra_max"
		 * appropriately
		 */
		rdma_ra_out = rc->rc_rdma_ra_out;
		if (tavor_qp_validate_init_depth(state, rc, &sra_max) !=
		    DDI_SUCCESS) {
			TNF_PROBE_1(tavor_qp_rtr2rts_inv_rdma_out_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, rdma_ra_out,
			    rdma_ra_out);
			TAVOR_TNF_EXIT(tavor_qp_rtr2rts);
			return (IBT_INVALID_PARAM);
		}
		qpc->sra_max = sra_max;

		/*
		 * Configure the QP to allow (sending of) all types of RC
		 * traffic.  Tavor hardware allows these bits to be set to
		 * zero (thereby disabling certain outgoing RDMA types), but
		 * we do not desire to do this.
		 */
		qpc->sre = qpc->swe = qpc->sae = 1;
		qpc->sic = 0;

		/*
		 * Check if any of the flags indicate a change in the RDMA
		 * (recv) enable/disable flags and set the appropriate flag in
		 * the "opmask" parameter
		 */
		opmask |= tavor_check_rdma_enable_flags(flags, info_p, qpc);

		/*
		 * If we are attempting to modify the path migration state for
		 * this QP, then check for valid state and fill it in.  Also
		 * set the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_MIG) {
			if (rc->rc_mig_state == IBT_STATE_MIGRATED) {
				qpc->pm_state = TAVOR_QP_PMSTATE_MIGRATED;
			} else if (rc->rc_mig_state == IBT_STATE_REARMED) {
				qpc->pm_state = TAVOR_QP_PMSTATE_REARM;
			} else {
				TNF_PROBE_1(tavor_qp_rtr2rts_inv_mig_state_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, mig_state,
				    rc->rc_mig_state);
				TAVOR_TNF_EXIT(tavor_qp_rtr2rts);
				return (IBT_QP_APM_STATE_INVALID);
			}
			opmask |= TAVOR_CMD_OP_PM_STATE;
		}

		/*
		 * If we are attempting to modify the "Minimum RNR NAK" value
		 * for this QP, then fill it in and set the appropriate flag
		 * in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_MIN_RNR_NAK) {
			qpc->min_rnr_nak = rc->rc_min_rnr_nak;
			opmask |= TAVOR_CMD_OP_MINRNRNAK;
		}

		/*
		 * Check for optional alternate path and fill in the
		 * appropriate QPC fields if one is specified
		 */
		if (flags & IBT_CEP_SET_ALT_PATH) {
			qpc_path = &qpc->alt_addr_path;
			adds_vect = &rc->rc_alt_path.cep_adds_vect;

			/* Set the common alternate address path fields */
			status = tavor_set_addr_path(state, adds_vect, qpc_path,
			    TAVOR_ADDRPATH_QP, qp);
			if (status != DDI_SUCCESS) {
				TNF_PROBE_0(tavor_qp_rtr2rts_setaddrpath_fail,
				    TAVOR_TNF_ERROR, "");
				TAVOR_TNF_EXIT(tavor_qp_rtr2rts);
				return (status);
			}

			qpc_path->ack_timeout = rc->rc_alt_path.cep_timeout;

			/*
			 * Copy the "RNR Retry count" value from the primary
			 * path.  Just as we did above, we need to hardcode
			 * the optional flag here (see below).
			 */
			qpc_path->rnr_retry = rc->rc_rnr_retry_cnt;

			/*
			 * Check for valid alternate path port number and fill
			 * it in
			 */
			portnum = rc->rc_alt_path.cep_hca_port_num;
			if (tavor_portnum_is_valid(state, portnum)) {
				qpc->alt_addr_path.portnum = portnum;
			} else {
				TNF_PROBE_1(tavor_qp_rtr2rts_inv_altport_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, altport,
				    portnum);
				TAVOR_TNF_EXIT(tavor_qp_rtr2rts);
				return (IBT_HCA_PORT_INVALID);
			}

			/*
			 * Check for valid alternate path PKey index and fill
			 * it in
			 */
			pkeyindx = rc->rc_alt_path.cep_pkey_ix;
			if (tavor_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->alt_addr_path.pkey_indx = pkeyindx;
			} else {
				TNF_PROBE_1(tavor_qp_rtr2rts_inv_altpkey_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, altpkeyindx,
				    pkeyindx);
				TAVOR_TNF_EXIT(tavor_qp_rtr2rts);
				return (IBT_PKEY_IX_ILLEGAL);
			}
			opmask |= (TAVOR_CMD_OP_ALT_PATH |
			    TAVOR_CMD_OP_ALT_RNRRETRY);
		}

	} else if (qp->qp_serv_type == TAVOR_QP_UC) {
		uc = &info_p->qp_transport.uc;

		/* Set the send PSN */
		qpc->next_snd_psn = uc->uc_sq_psn;

		/*
		 * Configure the QP to allow (sending of) all types of allowable
		 * UC traffic (i.e. RDMA Write).
		 */
		qpc->swe = 1;

		/*
		 * Check if any of the flags indicate a change in the RDMA
		 * Write (recv) enable/disable and set the appropriate flag
		 * in the "opmask" parameter. Note: RDMA Read and Atomic are
		 * not valid for UC transport.
		 */
		if (flags & IBT_CEP_SET_RDMA_W) {
			qpc->rwe = (info_p->qp_flags & IBT_CEP_RDMA_WR) ? 1 : 0;
			opmask |= TAVOR_CMD_OP_RWE;
		}

		/*
		 * If we are attempting to modify the path migration state for
		 * this QP, then check for valid state and fill it in.  Also
		 * set the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_MIG) {
			if (uc->uc_mig_state == IBT_STATE_MIGRATED) {
				qpc->pm_state = TAVOR_QP_PMSTATE_MIGRATED;
			} else if (uc->uc_mig_state == IBT_STATE_REARMED) {
				qpc->pm_state = TAVOR_QP_PMSTATE_REARM;
			} else {
				TNF_PROBE_1(tavor_qp_rtr2rts_inv_mig_state_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, mig_state,
				    uc->uc_mig_state);
				TAVOR_TNF_EXIT(tavor_qp_rtr2rts);
				return (IBT_QP_APM_STATE_INVALID);
			}
			opmask |= TAVOR_CMD_OP_PM_STATE;
		}

		/*
		 * Check for optional alternate path and fill in the
		 * appropriate QPC fields if one is specified
		 */
		if (flags & IBT_CEP_SET_ALT_PATH) {
			qpc_path = &qpc->alt_addr_path;
			adds_vect = &uc->uc_alt_path.cep_adds_vect;

			/* Set the common alternate address path fields */
			status = tavor_set_addr_path(state, adds_vect, qpc_path,
			    TAVOR_ADDRPATH_QP, qp);
			if (status != DDI_SUCCESS) {
				TNF_PROBE_0(tavor_qp_rtr2rts_setaddrpath_fail,
				    TAVOR_TNF_ERROR, "");
				TAVOR_TNF_EXIT(tavor_qp_rtr2rts);
				return (status);
			}

			/*
			 * Check for valid alternate path port number and fill
			 * it in
			 */
			portnum = uc->uc_alt_path.cep_hca_port_num;
			if (tavor_portnum_is_valid(state, portnum)) {
				qpc->alt_addr_path.portnum = portnum;
			} else {
				TNF_PROBE_1(tavor_qp_rtr2rts_inv_altport_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, altport,
				    portnum);
				TAVOR_TNF_EXIT(tavor_qp_rtr2rts);
				return (IBT_HCA_PORT_INVALID);
			}

			/*
			 * Check for valid alternate path PKey index and fill
			 * it in
			 */
			pkeyindx = uc->uc_alt_path.cep_pkey_ix;
			if (tavor_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->alt_addr_path.pkey_indx = pkeyindx;
			} else {
				TNF_PROBE_1(tavor_qp_rtr2rts_inv_altpkey_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, altpkeyindx,
				    pkeyindx);
				TAVOR_TNF_EXIT(tavor_qp_rtr2rts);
				return (IBT_PKEY_IX_ILLEGAL);
			}
			opmask |= TAVOR_CMD_OP_ALT_PATH;
		}
	} else {
		/*
		 * Invalid QP transport type. If we got here then it's a
		 * warning of a probably serious problem.  So print a message
		 * and return failure
		 */
		TAVOR_WARNING(state, "unknown QP transport type in rtr2rts");
		TNF_PROBE_0(tavor_qp_rtr2rts_inv_transtype_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_qp_rtr2rts);
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Post the RTR2RTS_QP command to the Tavor firmware
	 *
	 * We do a TAVOR_NOSLEEP here because we are still holding the
	 * "qp_lock".  If we got raised to interrupt level by priority
	 * inversion, we do not want to block in this routine waiting for
	 * success.
	 */
	status = tavor_cmn_qp_cmd_post(state, RTR2RTS_QP, qpc, qp->qp_qpnum,
	    opmask, TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		if (status != TAVOR_CMD_BAD_QP_STATE) {
			cmn_err(CE_CONT, "Tavor: RTR2RTS_QP command failed: "
			    "%08x\n", status);
			TNF_PROBE_1(tavor_qp_rtr2rts_cmd_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, status, status);
			TAVOR_TNF_EXIT(tavor_qp_rtr2rts);
			return (ibc_get_ci_failure(0));
		} else {
			TNF_PROBE_0(tavor_qp_rtr2rts_inv_qpstate_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_qp_rtr2rts);
			return (IBT_QP_STATE_INVALID);
		}
	}

	TAVOR_TNF_EXIT(tavor_qp_rtr2rts);
	return (DDI_SUCCESS);
}


/*
 * tavor_qp_rts2rts()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_qp_rts2rts(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p)
{
	tavor_hw_qpc_t		*qpc;
	ibt_qp_rc_attr_t	*rc;
	ibt_qp_ud_attr_t	*ud;
	ibt_qp_uc_attr_t	*uc;
	tavor_hw_addr_path_t	*qpc_path;
	ibt_adds_vect_t		*adds_vect;
	uint_t			portnum, pkeyindx;
	uint32_t		opmask = 0;
	int			status;

	TAVOR_TNF_ENTER(tavor_qp_rts2rts);

	ASSERT(MUTEX_HELD(&qp->qp_lock));

	/*
	 * Grab the temporary QPC entry from QP software state
	 */
	qpc = &qp->qpc;

	/*
	 * Since there are no common and/or Tavor-specific fields to be filled
	 * in for this command, we begin with the QPC fields which are
	 * specific to transport type.
	 */
	if (qp->qp_serv_type == TAVOR_QP_UD) {
		ud = &info_p->qp_transport.ud;

		/*
		 * If we are attempting to modify the QKey for this QP, then
		 * fill it in and set the appropriate flag in the "opmask"
		 * parameter.
		 */
		if (flags & IBT_CEP_SET_QKEY) {
			qpc->qkey = ud->ud_qkey;
			opmask |= TAVOR_CMD_OP_QKEY;
		}

	} else if (qp->qp_serv_type == TAVOR_QP_RC) {
		rc = &info_p->qp_transport.rc;

		/*
		 * Check if any of the flags indicate a change in the RDMA
		 * (recv) enable/disable flags and set the appropriate flag in
		 * the "opmask" parameter
		 */
		opmask |= tavor_check_rdma_enable_flags(flags, info_p, qpc);

		/*
		 * If we are attempting to modify the path migration state for
		 * this QP, then check for valid state and fill it in.  Also
		 * set the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_MIG) {
			if (rc->rc_mig_state == IBT_STATE_MIGRATED) {
				qpc->pm_state = TAVOR_QP_PMSTATE_MIGRATED;
			} else if (rc->rc_mig_state == IBT_STATE_REARMED) {
				qpc->pm_state = TAVOR_QP_PMSTATE_REARM;
			} else {
				TNF_PROBE_1(tavor_qp_rts2rts_inv_mig_state_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, mig_state,
				    rc->rc_mig_state);
				TAVOR_TNF_EXIT(tavor_qp_rts2rts);
				return (IBT_QP_APM_STATE_INVALID);
			}
			opmask |= TAVOR_CMD_OP_PM_STATE;
		}

		/*
		 * If we are attempting to modify the "Minimum RNR NAK" value
		 * for this QP, then fill it in and set the appropriate flag
		 * in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_MIN_RNR_NAK) {
			qpc->min_rnr_nak = rc->rc_min_rnr_nak;
			opmask |= TAVOR_CMD_OP_MINRNRNAK;
		}

		/*
		 * Check for optional alternate path and fill in the
		 * appropriate QPC fields if one is specified
		 */
		if (flags & IBT_CEP_SET_ALT_PATH) {
			qpc_path = &qpc->alt_addr_path;
			adds_vect = &rc->rc_alt_path.cep_adds_vect;

			/* Set the common alternate address path fields */
			status = tavor_set_addr_path(state, adds_vect, qpc_path,
			    TAVOR_ADDRPATH_QP, qp);
			if (status != DDI_SUCCESS) {
				TNF_PROBE_0(tavor_qp_rts2rts_setaddrpath_fail,
				    TAVOR_TNF_ERROR, "");
				TAVOR_TNF_EXIT(tavor_qp_rts2rts);
				return (status);
			}
			qpc_path->ack_timeout = rc->rc_alt_path.cep_timeout;

			/*
			 * Check for valid alternate path port number and fill
			 * it in
			 */
			portnum = rc->rc_alt_path.cep_hca_port_num;
			if (tavor_portnum_is_valid(state, portnum)) {
				qpc->alt_addr_path.portnum = portnum;
			} else {
				TNF_PROBE_1(tavor_qp_rts2rts_inv_altport_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, altport,
				    portnum);
				TAVOR_TNF_EXIT(tavor_qp_rts2rts);
				return (IBT_HCA_PORT_INVALID);
			}

			/*
			 * Check for valid alternate path PKey index and fill
			 * it in
			 */
			pkeyindx = rc->rc_alt_path.cep_pkey_ix;
			if (tavor_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->alt_addr_path.pkey_indx = pkeyindx;
			} else {
				TNF_PROBE_1(tavor_qp_rts2rts_inv_altpkey_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, altpkeyindx,
				    pkeyindx);
				TAVOR_TNF_EXIT(tavor_qp_rts2rts);
				return (IBT_PKEY_IX_ILLEGAL);
			}
			opmask |= TAVOR_CMD_OP_ALT_PATH;
		}

	} else if (qp->qp_serv_type == TAVOR_QP_UC) {
		uc = &info_p->qp_transport.uc;

		/*
		 * Check if any of the flags indicate a change in the RDMA
		 * Write (recv) enable/disable and set the appropriate flag
		 * in the "opmask" parameter. Note: RDMA Read and Atomic are
		 * not valid for UC transport.
		 */
		if (flags & IBT_CEP_SET_RDMA_W) {
			qpc->rwe = (info_p->qp_flags & IBT_CEP_RDMA_WR) ? 1 : 0;
			opmask |= TAVOR_CMD_OP_RWE;
		}

		/*
		 * If we are attempting to modify the path migration state for
		 * this QP, then check for valid state and fill it in.  Also
		 * set the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_MIG) {
			if (uc->uc_mig_state == IBT_STATE_MIGRATED) {
				qpc->pm_state = TAVOR_QP_PMSTATE_MIGRATED;
			} else if (uc->uc_mig_state == IBT_STATE_REARMED) {
				qpc->pm_state = TAVOR_QP_PMSTATE_REARM;
			} else {
				TNF_PROBE_1(tavor_qp_rts2rts_inv_mig_state_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, mig_state,
				    uc->uc_mig_state);
				TAVOR_TNF_EXIT(tavor_qp_rts2rts);
				return (IBT_QP_APM_STATE_INVALID);
			}
			opmask |= TAVOR_CMD_OP_PM_STATE;
		}

		/*
		 * Check for optional alternate path and fill in the
		 * appropriate QPC fields if one is specified
		 */
		if (flags & IBT_CEP_SET_ALT_PATH) {
			qpc_path = &qpc->alt_addr_path;
			adds_vect = &uc->uc_alt_path.cep_adds_vect;

			/* Set the common alternate address path fields */
			status = tavor_set_addr_path(state, adds_vect, qpc_path,
			    TAVOR_ADDRPATH_QP, qp);
			if (status != DDI_SUCCESS) {
				TNF_PROBE_0(tavor_qp_rts2rts_setaddrpath_fail,
				    TAVOR_TNF_ERROR, "");
				TAVOR_TNF_EXIT(tavor_qp_rts2rts);
				return (status);
			}

			/*
			 * Check for valid alternate path port number and fill
			 * it in
			 */
			portnum = uc->uc_alt_path.cep_hca_port_num;
			if (tavor_portnum_is_valid(state, portnum)) {
				qpc->alt_addr_path.portnum = portnum;
			} else {
				TNF_PROBE_1(tavor_qp_rts2rts_inv_altport_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, altport,
				    portnum);
				TAVOR_TNF_EXIT(tavor_qp_rts2rts);
				return (IBT_HCA_PORT_INVALID);
			}

			/*
			 * Check for valid alternate path PKey index and fill
			 * it in
			 */
			pkeyindx = uc->uc_alt_path.cep_pkey_ix;
			if (tavor_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->alt_addr_path.pkey_indx = pkeyindx;
			} else {
				TNF_PROBE_1(tavor_qp_rts2rts_inv_altpkey_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, altpkeyindx,
				    pkeyindx);
				TAVOR_TNF_EXIT(tavor_qp_rts2rts);
				return (IBT_PKEY_IX_ILLEGAL);
			}
			opmask |= TAVOR_CMD_OP_ALT_PATH;
		}
	} else {
		/*
		 * Invalid QP transport type. If we got here then it's a
		 * warning of a probably serious problem.  So print a message
		 * and return failure
		 */
		TAVOR_WARNING(state, "unknown QP transport type in rts2rts");
		TNF_PROBE_0(tavor_qp_rts2rts_inv_transtype_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_qp_rts2rts);
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Post the RTS2RTS_QP command to the Tavor firmware
	 *
	 * We do a TAVOR_NOSLEEP here because we are still holding the
	 * "qp_lock".  If we got raised to interrupt level by priority
	 * inversion, we do not want to block in this routine waiting for
	 * success.
	 */
	status = tavor_cmn_qp_cmd_post(state, RTS2RTS_QP, qpc, qp->qp_qpnum,
	    opmask, TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		if (status != TAVOR_CMD_BAD_QP_STATE) {
			cmn_err(CE_CONT, "Tavor: RTS2RTS_QP command failed: "
			    "%08x\n", status);
			TNF_PROBE_1(tavor_qp_rts2rts_cmd_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, status, status);
			TAVOR_TNF_EXIT(tavor_qp_rts2rts);
			return (ibc_get_ci_failure(0));
		} else {
			TNF_PROBE_0(tavor_qp_rts2rts_inv_qpstate_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_qp_rts2rts);
			return (IBT_QP_STATE_INVALID);
		}
	}

	TAVOR_TNF_EXIT(tavor_qp_rts2rts);
	return (DDI_SUCCESS);
}


/*
 * tavor_qp_rts2sqd()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_qp_rts2sqd(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_cep_modify_flags_t flags)
{
	int			status;

	TAVOR_TNF_ENTER(tavor_qp_rts2sqd);

	ASSERT(MUTEX_HELD(&qp->qp_lock));

	/*
	 * Set a flag to indicate whether or not the consumer is interested
	 * in receiving the SQ drained event.  Since we are going to always
	 * request hardware generation of the SQD event, we use the value in
	 * "qp_forward_sqd_event" to determine whether or not to pass the event
	 * to the IBTF or to silently consume it.
	 */
	qp->qp_forward_sqd_event = (flags & IBT_CEP_SET_SQD_EVENT) ? 1 : 0;

	/*
	 * Post the RTS2SQD_QP command to the Tavor firmware
	 *
	 * We do a TAVOR_NOSLEEP here because we are still holding the
	 * "qp_lock".  If we got raised to interrupt level by priority
	 * inversion, we do not want to block in this routine waiting for
	 * success.
	 */
	status = tavor_cmn_qp_cmd_post(state, RTS2SQD_QP, NULL, qp->qp_qpnum,
	    0, TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		if (status != TAVOR_CMD_BAD_QP_STATE) {
			cmn_err(CE_CONT, "Tavor: RTS2SQD_QP command failed: "
			    "%08x\n", status);
			TNF_PROBE_1(tavor_qp_rts2sqd_cmd_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, status, status);
			TAVOR_TNF_EXIT(tavor_qp_rts2sqd);
			return (ibc_get_ci_failure(0));
		} else {
			TNF_PROBE_0(tavor_qp_rts2sqd_inv_qpstate_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_qp_rts2sqd);
			return (IBT_QP_STATE_INVALID);
		}
	}

	/*
	 * Mark the current QP state as "SQ Draining".  This allows us to
	 * distinguish between the two underlying states in SQD. (see QueryQP()
	 * code in tavor_qp.c)
	 */
	qp->qp_sqd_still_draining = 1;

	TAVOR_TNF_EXIT(tavor_qp_rts2sqd);
	return (DDI_SUCCESS);
}


/*
 * tavor_qp_sqd2rts()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_qp_sqd2rts(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p)
{
	tavor_hw_qpc_t		*qpc;
	ibt_qp_rc_attr_t	*rc;
	ibt_qp_ud_attr_t	*ud;
	ibt_qp_uc_attr_t	*uc;
	tavor_hw_addr_path_t	*qpc_path;
	ibt_adds_vect_t		*adds_vect;
	uint_t			portnum, pkeyindx;
	uint32_t		opmask = 0;
	int			status;

	TAVOR_TNF_ENTER(tavor_qp_sqd2rts);

	ASSERT(MUTEX_HELD(&qp->qp_lock));

	/*
	 * Grab the temporary QPC entry from QP software state
	 */
	qpc = &qp->qpc;

	/*
	 * Since there are no common and/or Tavor-specific fields to be filled
	 * in for this command, we begin with the QPC fields which are
	 * specific to transport type.
	 */
	if (qp->qp_serv_type == TAVOR_QP_UD) {
		ud = &info_p->qp_transport.ud;

		/*
		 * If we are attempting to modify the QKey for this QP, then
		 * fill it in and set the appropriate flag in the "opmask"
		 * parameter.
		 */
		if (flags & IBT_CEP_SET_QKEY) {
			qpc->qkey = ud->ud_qkey;
			opmask |= TAVOR_CMD_OP_QKEY;
		}

	} else if (qp->qp_serv_type == TAVOR_QP_RC) {
		rc = &info_p->qp_transport.rc;

		/*
		 * Check if any of the flags indicate a change in the RDMA
		 * (recv) enable/disable flags and set the appropriate flag in
		 * the "opmask" parameter
		 */
		opmask |= tavor_check_rdma_enable_flags(flags, info_p, qpc);

		/*
		 * If we are attempting to modify the path migration state for
		 * this QP, then check for valid state and fill it in.  Also
		 * set the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_MIG) {
			if (rc->rc_mig_state == IBT_STATE_MIGRATED) {
				qpc->pm_state = TAVOR_QP_PMSTATE_MIGRATED;
			} else if (rc->rc_mig_state == IBT_STATE_REARMED) {
				qpc->pm_state = TAVOR_QP_PMSTATE_REARM;
			} else {
				TNF_PROBE_1(tavor_qp_sqd2rts_inv_mig_state_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, mig_state,
				    rc->rc_mig_state);
				TAVOR_TNF_EXIT(tavor_qp_sqd2rts);
				return (IBT_QP_APM_STATE_INVALID);
			}
			opmask |= TAVOR_CMD_OP_PM_STATE;
		}

		/*
		 * Check for optional alternate path and fill in the
		 * appropriate QPC fields if one is specified
		 */
		if (flags & IBT_CEP_SET_ALT_PATH) {
			qpc_path = &qpc->alt_addr_path;
			adds_vect = &rc->rc_alt_path.cep_adds_vect;

			/* Set the common alternate address path fields */
			status = tavor_set_addr_path(state, adds_vect, qpc_path,
			    TAVOR_ADDRPATH_QP, qp);
			if (status != DDI_SUCCESS) {
				TNF_PROBE_0(tavor_qp_sqd2rts_setaddrpath_fail,
				    TAVOR_TNF_ERROR, "");
				TAVOR_TNF_EXIT(tavor_qp_sqd2rts);
				return (status);
			}
			qpc_path->ack_timeout = rc->rc_alt_path.cep_timeout;

			/*
			 * Check for valid alternate path port number and fill
			 * it in
			 */
			portnum = rc->rc_alt_path.cep_hca_port_num;
			if (tavor_portnum_is_valid(state, portnum)) {
				qpc->alt_addr_path.portnum = portnum;
			} else {
				TNF_PROBE_1(tavor_qp_sqd2rts_inv_altport_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, altport,
				    portnum);
				TAVOR_TNF_EXIT(tavor_qp_sqd2rts);
				return (IBT_HCA_PORT_INVALID);
			}

			/*
			 * Check for valid alternate path PKey index and fill
			 * it in
			 */
			pkeyindx = rc->rc_alt_path.cep_pkey_ix;
			if (tavor_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->alt_addr_path.pkey_indx = pkeyindx;
			} else {
				TNF_PROBE_1(tavor_qp_sqd2rts_inv_altpkey_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, altpkeyindx,
				    pkeyindx);
				TAVOR_TNF_EXIT(tavor_qp_sqd2rts);
				return (IBT_PKEY_IX_ILLEGAL);
			}
			opmask |= TAVOR_CMD_OP_ALT_PATH;
		}

		/*
		 * If we are attempting to modify the "Minimum RNR NAK" value
		 * for this QP, then fill it in and set the appropriate flag
		 * in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_MIN_RNR_NAK) {
			qpc->min_rnr_nak = rc->rc_min_rnr_nak;
			opmask |= TAVOR_CMD_OP_MINRNRNAK;
		}

	} else if (qp->qp_serv_type == TAVOR_QP_UC) {
		uc = &info_p->qp_transport.uc;

		/*
		 * Check if any of the flags indicate a change in the RDMA
		 * Write (recv) enable/disable and set the appropriate flag
		 * in the "opmask" parameter. Note: RDMA Read and Atomic are
		 * not valid for UC transport.
		 */
		if (flags & IBT_CEP_SET_RDMA_W) {
			qpc->rwe = (info_p->qp_flags & IBT_CEP_RDMA_WR) ? 1 : 0;
			opmask |= TAVOR_CMD_OP_RWE;
		}

		/*
		 * If we are attempting to modify the path migration state for
		 * this QP, then check for valid state and fill it in.  Also
		 * set the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_MIG) {
			if (uc->uc_mig_state == IBT_STATE_MIGRATED) {
				qpc->pm_state = TAVOR_QP_PMSTATE_MIGRATED;
			} else if (uc->uc_mig_state == IBT_STATE_REARMED) {
				qpc->pm_state = TAVOR_QP_PMSTATE_REARM;
			} else {
				TNF_PROBE_1(tavor_qp_sqd2rts_inv_mig_state_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, mig_state,
				    uc->uc_mig_state);
				TAVOR_TNF_EXIT(tavor_qp_sqd2rts);
				return (IBT_QP_APM_STATE_INVALID);
			}
			opmask |= TAVOR_CMD_OP_PM_STATE;
		}

		/*
		 * Check for optional alternate path and fill in the
		 * appropriate QPC fields if one is specified
		 */
		if (flags & IBT_CEP_SET_ALT_PATH) {
			qpc_path = &qpc->alt_addr_path;
			adds_vect = &uc->uc_alt_path.cep_adds_vect;

			/* Set the common alternate address path fields */
			status = tavor_set_addr_path(state, adds_vect, qpc_path,
			    TAVOR_ADDRPATH_QP, qp);
			if (status != DDI_SUCCESS) {
				TNF_PROBE_0(tavor_qp_sqd2rts_setaddrpath_fail,
				    TAVOR_TNF_ERROR, "");
				TAVOR_TNF_EXIT(tavor_qp_sqd2rts);
				return (status);
			}

			/*
			 * Check for valid alternate path port number and fill
			 * it in
			 */
			portnum = uc->uc_alt_path.cep_hca_port_num;
			if (tavor_portnum_is_valid(state, portnum)) {
				qpc->alt_addr_path.portnum = portnum;
			} else {
				TNF_PROBE_1(tavor_qp_sqd2rts_inv_altport_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, altport,
				    portnum);
				TAVOR_TNF_EXIT(tavor_qp_sqd2rts);
				return (IBT_HCA_PORT_INVALID);
			}

			/*
			 * Check for valid alternate path PKey index and fill
			 * it in
			 */
			pkeyindx = uc->uc_alt_path.cep_pkey_ix;
			if (tavor_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->alt_addr_path.pkey_indx = pkeyindx;
			} else {
				TNF_PROBE_1(tavor_qp_sqd2rts_inv_altpkey_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, altpkeyindx,
				    pkeyindx);
				TAVOR_TNF_EXIT(tavor_qp_sqd2rts);
				return (IBT_PKEY_IX_ILLEGAL);
			}
			opmask |= TAVOR_CMD_OP_ALT_PATH;
		}
	} else {
		/*
		 * Invalid QP transport type. If we got here then it's a
		 * warning of a probably serious problem.  So print a message
		 * and return failure
		 */
		TAVOR_WARNING(state, "unknown QP transport type in sqd2rts");
		TNF_PROBE_0(tavor_qp_sqd2rts_inv_transtype_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_qp_sqd2rts);
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Post the SQD2RTS_QP command to the Tavor firmware
	 *
	 * We do a TAVOR_NOSLEEP here because we are still holding the
	 * "qp_lock".  If we got raised to interrupt level by priority
	 * inversion, we do not want to block in this routine waiting for
	 * success.
	 */
	status = tavor_cmn_qp_cmd_post(state, SQD2RTS_QP, qpc, qp->qp_qpnum,
	    opmask, TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		if (status != TAVOR_CMD_BAD_QP_STATE) {
			cmn_err(CE_CONT, "Tavor: SQD2RTS_QP command failed: "
			    "%08x\n", status);
			TNF_PROBE_1(tavor_qp_sqd2rts_cmd_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, status, status);
			TAVOR_TNF_EXIT(tavor_qp_sqd2rts);
			return (ibc_get_ci_failure(0));
		} else {
			TNF_PROBE_0(tavor_qp_sqd2rts_inv_qpstate_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_qp_sqd2rts);
			return (IBT_QP_STATE_INVALID);
		}
	}

	TAVOR_TNF_EXIT(tavor_qp_sqd2rts);
	return (DDI_SUCCESS);
}


/*
 * tavor_qp_sqd2sqd()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_qp_sqd2sqd(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p)
{
	tavor_hw_qpc_t		*qpc;
	ibt_qp_rc_attr_t	*rc;
	ibt_qp_ud_attr_t	*ud;
	ibt_qp_uc_attr_t	*uc;
	tavor_hw_addr_path_t	*qpc_path;
	ibt_adds_vect_t		*adds_vect;
	uint_t			portnum, pkeyindx, rdma_ra_out, rdma_ra_in;
	uint_t			rra_max, sra_max;
	uint32_t		opmask = 0;
	int			status;

	TAVOR_TNF_ENTER(tavor_qp_sqd2sqd);

	ASSERT(MUTEX_HELD(&qp->qp_lock));

	/*
	 * Grab the temporary QPC entry from QP software state
	 */
	qpc = &qp->qpc;

	/*
	 * Since there are no common and/or Tavor-specific fields to be filled
	 * in for this command, we begin with the QPC fields which are
	 * specific to transport type.
	 */
	if (qp->qp_serv_type == TAVOR_QP_UD) {
		ud = &info_p->qp_transport.ud;

		/*
		 * If we are attempting to modify the PKey index for this QP,
		 * then check for valid PKey index and fill it in.  Also set
		 * the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_PKEY_IX) {
			pkeyindx = ud->ud_pkey_ix;
			if (tavor_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->pri_addr_path.pkey_indx = pkeyindx;
				opmask |= TAVOR_CMD_OP_PKEYINDX;
				qp->qp_pkeyindx = pkeyindx;
			} else {
				TNF_PROBE_1(tavor_qp_sqd2sqd_inv_pkey_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, pkeyindx,
				    pkeyindx);
				TAVOR_TNF_EXIT(tavor_qp_sqd2sqd);
				return (IBT_PKEY_IX_ILLEGAL);
			}
		}

		/*
		 * If we are attempting to modify the QKey for this QP, then
		 * fill it in and set the appropriate flag in the "opmask"
		 * parameter.
		 */
		if (flags & IBT_CEP_SET_QKEY) {
			qpc->qkey = ud->ud_qkey;
			opmask |= TAVOR_CMD_OP_QKEY;
		}

	} else if (qp->qp_serv_type == TAVOR_QP_RC) {
		rc = &info_p->qp_transport.rc;

		/*
		 * Check if any of the flags indicate a change in the RDMA
		 * (recv) enable/disable flags and set the appropriate flag in
		 * the "opmask" parameter
		 */
		opmask |= tavor_check_rdma_enable_flags(flags, info_p, qpc);

		/*
		 * Check for optional primary path and fill in the
		 * appropriate QPC fields if one is specified
		 */
		if (flags & IBT_CEP_SET_ADDS_VECT) {
			qpc_path = &qpc->pri_addr_path;
			adds_vect = &rc->rc_path.cep_adds_vect;

			/* Set the common primary address path fields */
			status = tavor_set_addr_path(state, adds_vect, qpc_path,
			    TAVOR_ADDRPATH_QP, qp);
			if (status != DDI_SUCCESS) {
				TNF_PROBE_0(tavor_qp_sqd2sqd_setaddrpath_fail,
				    TAVOR_TNF_ERROR, "");
				TAVOR_TNF_EXIT(tavor_qp_sqd2sqd);
				return (status);
			}
			qpc_path->rnr_retry = rc->rc_rnr_retry_cnt;
			qpc_path->ack_timeout = rc->rc_path.cep_timeout;
			qpc->retry_cnt = rc->rc_retry_cnt;

			/*
			 * MTU changes as part of sqd2sqd are not allowed.
			 * Simply keep the same MTU value here, stored in the
			 * qphdl from init2rtr time.
			 */
			qpc->mtu = qp->qp_save_mtu;

			opmask |= (TAVOR_CMD_OP_PRIM_PATH |
			    TAVOR_CMD_OP_RETRYCNT | TAVOR_CMD_OP_ACKTIMEOUT |
			    TAVOR_CMD_OP_PRIM_RNRRETRY);
		}

		/*
		 * If we are attempting to modify the path migration state for
		 * this QP, then check for valid state and fill it in.  Also
		 * set the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_MIG) {
			if (rc->rc_mig_state == IBT_STATE_MIGRATED) {
				qpc->pm_state = TAVOR_QP_PMSTATE_MIGRATED;
			} else if (rc->rc_mig_state == IBT_STATE_REARMED) {
				qpc->pm_state = TAVOR_QP_PMSTATE_REARM;
			} else {
				TNF_PROBE_1(tavor_qp_sqd2sqd_inv_mig_state_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, mig_state,
				    rc->rc_mig_state);
				TAVOR_TNF_EXIT(tavor_qp_sqd2sqd);
				return (IBT_QP_APM_STATE_INVALID);
			}
			opmask |= TAVOR_CMD_OP_PM_STATE;
		}

		/*
		 * If we are attempting to modify the PKey index for this QP,
		 * then check for valid PKey index and fill it in.  Also set
		 * the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_PKEY_IX) {
			pkeyindx = rc->rc_path.cep_pkey_ix;
			if (tavor_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->pri_addr_path.pkey_indx = pkeyindx;
				opmask |= TAVOR_CMD_OP_PKEYINDX;
			} else {
				TNF_PROBE_1(tavor_qp_sqd2sqd_inv_pkey_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, pkeyindx,
				    pkeyindx);
				TAVOR_TNF_EXIT(tavor_qp_sqd2sqd);
				return (IBT_PKEY_IX_ILLEGAL);
			}
		}

		/*
		 * If we are attempting to modify the port for this QP, then
		 * check for valid port number and fill it in.  Also set the
		 * appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_PORT) {
			portnum = rc->rc_path.cep_hca_port_num;
			if (tavor_portnum_is_valid(state, portnum)) {
				qpc->pri_addr_path.portnum = portnum;
			} else {
				TNF_PROBE_1(tavor_qp_sqd2sqd_inv_port_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, port,
				    portnum);
				TAVOR_TNF_EXIT(tavor_qp_sqd2sqd);
				return (IBT_HCA_PORT_INVALID);
			}
			opmask |= TAVOR_CMD_OP_PRIM_PORT;
		}

		/*
		 * Check for optional alternate path and fill in the
		 * appropriate QPC fields if one is specified
		 */
		if (flags & IBT_CEP_SET_ALT_PATH) {
			qpc_path = &qpc->alt_addr_path;
			adds_vect = &rc->rc_alt_path.cep_adds_vect;

			/* Set the common alternate address path fields */
			status = tavor_set_addr_path(state, adds_vect, qpc_path,
			    TAVOR_ADDRPATH_QP, qp);
			if (status != DDI_SUCCESS) {
				TNF_PROBE_0(tavor_qp_sqd2sqd_setaddrpath_fail,
				    TAVOR_TNF_ERROR, "");
				TAVOR_TNF_EXIT(tavor_qp_sqd2sqd);
				return (status);
			}
			qpc_path->ack_timeout = rc->rc_alt_path.cep_timeout;

			/*
			 * Check for valid alternate path port number and fill
			 * it in
			 */
			portnum = rc->rc_alt_path.cep_hca_port_num;
			if (tavor_portnum_is_valid(state, portnum)) {
				qpc->alt_addr_path.portnum = portnum;
			} else {
				TNF_PROBE_1(tavor_qp_sqd2sqd_inv_altport_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, altport,
				    portnum);
				TAVOR_TNF_EXIT(tavor_qp_sqd2sqd);
				return (IBT_HCA_PORT_INVALID);
			}

			/*
			 * Check for valid alternate path PKey index and fill
			 * it in
			 */
			pkeyindx = rc->rc_alt_path.cep_pkey_ix;
			if (tavor_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->alt_addr_path.pkey_indx = pkeyindx;
			} else {
				TNF_PROBE_1(tavor_qp_sqd2sqd_inv_altpkey_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, altpkeyindx,
				    pkeyindx);
				TAVOR_TNF_EXIT(tavor_qp_sqd2sqd);
				return (IBT_PKEY_IX_ILLEGAL);
			}
			opmask |= TAVOR_CMD_OP_ALT_PATH;
		}

		/*
		 * If we are attempting to modify the number of "outgoing
		 * RDMA resources" for this QP, then check for valid value and
		 * fill it in.  Also set the appropriate flag in the "opmask"
		 * parameter.
		 */
		if (flags & IBT_CEP_SET_RDMARA_OUT) {
			rdma_ra_out = rc->rc_rdma_ra_out;
			if (tavor_qp_validate_init_depth(state, rc,
			    &sra_max) != DDI_SUCCESS) {
				TNF_PROBE_1(tavor_qp_sqd2sqd_inv_rdma_out_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, rdma_ra_out,
				    rdma_ra_out);
				TAVOR_TNF_EXIT(tavor_qp_sqd2sqd);
				return (IBT_INVALID_PARAM);
			}
			qpc->sra_max = sra_max;
			opmask |= TAVOR_CMD_OP_SRA_SET;
		}

		/*
		 * If we are attempting to modify the number of "incoming
		 * RDMA resources" for this QP, then check for valid value and
		 * update the "rra_max" and "ra_buf_index" fields in the QPC to
		 * point to the pre-allocated RDB resources (in DDR).  Also set
		 * the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_RDMARA_IN) {
			rdma_ra_in = rc->rc_rdma_ra_in;
			if (tavor_qp_validate_resp_rsrc(state, rc,
			    &rra_max) != DDI_SUCCESS) {
				TNF_PROBE_1(tavor_qp_sqd2sqd_inv_rdma_in_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, rdma_ra_in,
				    rdma_ra_in);
				TAVOR_TNF_EXIT(tavor_qp_sqd2sqd);
				return (IBT_INVALID_PARAM);
			}
			qpc->rra_max = rra_max;
			qpc->ra_buff_indx = qp->qp_rdb_ddraddr >>
			    TAVOR_RDB_SIZE_SHIFT;
			opmask |= TAVOR_CMD_OP_RRA_SET;
		}

		/*
		 * If we are attempting to modify the "Local Ack Timeout" value
		 * for this QP, then fill it in and set the appropriate flag in
		 * the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_TIMEOUT) {
			qpc_path = &qpc->pri_addr_path;
			qpc_path->ack_timeout = rc->rc_path.cep_timeout;
			opmask |= TAVOR_CMD_OP_ACKTIMEOUT;
		}

		/*
		 * If we are attempting to modify the "Retry Count" for this QP,
		 * then fill it in and set the appropriate flag in the "opmask"
		 * parameter.
		 */
		if (flags & IBT_CEP_SET_RETRY) {
			qpc->retry_cnt = rc->rc_retry_cnt;
			opmask |= TAVOR_CMD_OP_PRIM_RNRRETRY;
		}

		/*
		 * If we are attempting to modify the "RNR Retry Count" for this
		 * QP, then fill it in and set the appropriate flag in the
		 * "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_RNR_NAK_RETRY) {
			qpc_path = &qpc->pri_addr_path;
			qpc_path->rnr_retry = rc->rc_rnr_retry_cnt;
			opmask |= TAVOR_CMD_OP_RETRYCNT;
		}

		/*
		 * If we are attempting to modify the "Minimum RNR NAK" value
		 * for this QP, then fill it in and set the appropriate flag
		 * in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_MIN_RNR_NAK) {
			qpc->min_rnr_nak = rc->rc_min_rnr_nak;
			opmask |= TAVOR_CMD_OP_MINRNRNAK;
		}

	} else if (qp->qp_serv_type == TAVOR_QP_UC) {
		uc = &info_p->qp_transport.uc;

		/*
		 * Check if any of the flags indicate a change in the RDMA
		 * Write (recv) enable/disable and set the appropriate flag
		 * in the "opmask" parameter. Note: RDMA Read and Atomic are
		 * not valid for UC transport.
		 */
		if (flags & IBT_CEP_SET_RDMA_W) {
			qpc->rwe = (info_p->qp_flags & IBT_CEP_RDMA_WR) ? 1 : 0;
			opmask |= TAVOR_CMD_OP_RWE;
		}

		/*
		 * Check for optional primary path and fill in the
		 * appropriate QPC fields if one is specified
		 */
		if (flags & IBT_CEP_SET_ADDS_VECT) {
			qpc_path = &qpc->pri_addr_path;
			adds_vect = &uc->uc_path.cep_adds_vect;

			/* Set the common primary address path fields */
			status = tavor_set_addr_path(state, adds_vect, qpc_path,
			    TAVOR_ADDRPATH_QP, qp);
			if (status != DDI_SUCCESS) {
				TNF_PROBE_0(tavor_qp_sqd2sqd_setaddrpath_fail,
				    TAVOR_TNF_ERROR, "");
				TAVOR_TNF_EXIT(tavor_qp_sqd2sqd);
				return (status);
			}

			/*
			 * MTU changes as part of sqd2sqd are not allowed.
			 * Simply keep the same MTU value here, stored in the
			 * qphdl from init2rtr time.
			 */
			qpc->mtu = qp->qp_save_mtu;

			opmask |= TAVOR_CMD_OP_PRIM_PATH;
		}

		/*
		 * If we are attempting to modify the path migration state for
		 * this QP, then check for valid state and fill it in.  Also
		 * set the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_MIG) {
			if (uc->uc_mig_state == IBT_STATE_MIGRATED) {
				qpc->pm_state = TAVOR_QP_PMSTATE_MIGRATED;
			} else if (uc->uc_mig_state == IBT_STATE_REARMED) {
				qpc->pm_state = TAVOR_QP_PMSTATE_REARM;
			} else {
				TNF_PROBE_1(tavor_qp_sqd2sqd_inv_mig_state_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, mig_state,
				    uc->uc_mig_state);
				TAVOR_TNF_EXIT(tavor_qp_sqd2sqd);
				return (IBT_QP_APM_STATE_INVALID);
			}
			opmask |= TAVOR_CMD_OP_PM_STATE;
		}

		/*
		 * If we are attempting to modify the PKey index for this QP,
		 * then check for valid PKey index and fill it in.  Also set
		 * the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_PKEY_IX) {
			pkeyindx = uc->uc_path.cep_pkey_ix;
			if (tavor_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->pri_addr_path.pkey_indx = pkeyindx;
				opmask |= TAVOR_CMD_OP_PKEYINDX;
			} else {
				TNF_PROBE_1(tavor_qp_sqd2sqd_inv_pkey,
				    TAVOR_TNF_ERROR, "", tnf_uint, pkeyindx,
				    pkeyindx);
				TAVOR_TNF_EXIT(tavor_qp_sqd2sqd);
				return (IBT_PKEY_IX_ILLEGAL);
			}
		}

		/*
		 * Check for optional alternate path and fill in the
		 * appropriate QPC fields if one is specified
		 */
		if (flags & IBT_CEP_SET_ALT_PATH) {
			qpc_path = &qpc->alt_addr_path;
			adds_vect = &uc->uc_alt_path.cep_adds_vect;

			/* Set the common alternate address path fields */
			status = tavor_set_addr_path(state, adds_vect, qpc_path,
			    TAVOR_ADDRPATH_QP, qp);
			if (status != DDI_SUCCESS) {
				TNF_PROBE_0(tavor_qp_sqd2sqd_setaddrpath_fail,
				    TAVOR_TNF_ERROR, "");
				TAVOR_TNF_EXIT(tavor_qp_sqd2sqd);
				return (status);
			}

			/*
			 * Check for valid alternate path port number and fill
			 * it in
			 */
			portnum = uc->uc_alt_path.cep_hca_port_num;
			if (tavor_portnum_is_valid(state, portnum)) {
				qpc->alt_addr_path.portnum = portnum;
			} else {
				TNF_PROBE_1(tavor_qp_sqd2sqd_inv_altport_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, altport,
				    portnum);
				TAVOR_TNF_EXIT(tavor_qp_sqd2sqd);
				return (IBT_HCA_PORT_INVALID);
			}

			/*
			 * Check for valid alternate path PKey index and fill
			 * it in
			 */
			pkeyindx = uc->uc_alt_path.cep_pkey_ix;
			if (tavor_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->alt_addr_path.pkey_indx = pkeyindx;
			} else {
				TNF_PROBE_1(tavor_qp_sqd2sqd_inv_altpkey_fail,
				    TAVOR_TNF_ERROR, "", tnf_uint, altpkeyindx,
				    pkeyindx);
				TAVOR_TNF_EXIT(tavor_qp_sqd2sqd);
				return (IBT_PKEY_IX_ILLEGAL);
			}
			opmask |= TAVOR_CMD_OP_ALT_PATH;
		}
	} else {
		/*
		 * Invalid QP transport type. If we got here then it's a
		 * warning of a probably serious problem.  So print a message
		 * and return failure
		 */
		TAVOR_WARNING(state, "unknown QP transport type in sqd2sqd");
		TNF_PROBE_0(tavor_qp_sqd2sqd_inv_transtype_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_qp_sqd2sqd);
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Post the SQD2SQD_QP command to the Tavor firmware
	 *
	 * We do a TAVOR_NOSLEEP here because we are still holding the
	 * "qp_lock".  If we got raised to interrupt level by priority
	 * inversion, we do not want to block in this routine waiting for
	 * success.
	 */
	status = tavor_cmn_qp_cmd_post(state, SQD2SQD_QP, qpc, qp->qp_qpnum,
	    opmask, TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		if (status != TAVOR_CMD_BAD_QP_STATE) {
			cmn_err(CE_CONT, "Tavor: SQD2SQD_QP command failed: "
			    "%08x\n", status);
			TNF_PROBE_1(tavor_qp_sqd2sqd_cmd_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, status, status);
			TAVOR_TNF_EXIT(tavor_qp_sqd2sqd);
			return (ibc_get_ci_failure(0));
		} else {
			TNF_PROBE_0(tavor_qp_sqd2sqd_inv_qpstate_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_qp_sqd2sqd);
			return (IBT_QP_STATE_INVALID);
		}
	}

	TAVOR_TNF_EXIT(tavor_qp_sqd2sqd);
	return (DDI_SUCCESS);
}


/*
 * tavor_qp_sqerr2rts()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_qp_sqerr2rts(tavor_state_t *state, tavor_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p)
{
	tavor_hw_qpc_t		*qpc;
	ibt_qp_ud_attr_t	*ud;
	uint32_t		opmask = 0;
	int			status;

	TAVOR_TNF_ENTER(tavor_qp_sqerr2rts);

	ASSERT(MUTEX_HELD(&qp->qp_lock));

	/*
	 * Grab the temporary QPC entry from QP software state
	 */
	qpc = &qp->qpc;

	/*
	 * Since there are no common and/or Tavor-specific fields to be filled
	 * in for this command, we begin with the QPC fields which are
	 * specific to transport type.
	 */
	if (qp->qp_serv_type == TAVOR_QP_UD) {
		ud = &info_p->qp_transport.ud;

		/*
		 * If we are attempting to modify the QKey for this QP, then
		 * fill it in and set the appropriate flag in the "opmask"
		 * parameter.
		 */
		if (flags & IBT_CEP_SET_QKEY) {
			qpc->qkey = ud->ud_qkey;
			opmask |= TAVOR_CMD_OP_QKEY;
		}

	} else if (qp->qp_serv_type == TAVOR_QP_UC) {

		/*
		 * Check if any of the flags indicate a change in the RDMA
		 * Write (recv) enable/disable and set the appropriate flag
		 * in the "opmask" parameter. Note: RDMA Read and Atomic are
		 * not valid for UC transport.
		 */
		if (flags & IBT_CEP_SET_RDMA_W) {
			qpc->rwe = (info_p->qp_flags & IBT_CEP_RDMA_WR) ? 1 : 0;
			opmask |= TAVOR_CMD_OP_RWE;
		}
	} else {
		/*
		 * Invalid QP transport type. If we got here then it's a
		 * warning of a probably serious problem.  So print a message
		 * and return failure
		 */
		TAVOR_WARNING(state, "unknown QP transport type in sqerr2rts");
		TNF_PROBE_0(tavor_qp_sqerr2rts_inv_transtype_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_qp_sqerr2rts);
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Post the SQERR2RTS_QP command to the Tavor firmware
	 *
	 * We do a TAVOR_NOSLEEP here because we are still holding the
	 * "qp_lock".  If we got raised to interrupt level by priority
	 * inversion, we do not want to block in this routine waiting for
	 * success.
	 */
	status = tavor_cmn_qp_cmd_post(state, SQERR2RTS_QP, qpc, qp->qp_qpnum,
	    opmask, TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		if (status != TAVOR_CMD_BAD_QP_STATE) {
			cmn_err(CE_CONT, "Tavor: SQERR2RTS_QP command failed: "
			    "%08x\n", status);
			TNF_PROBE_1(tavor_qp_sqerr2rts_cmd_fail,
			    TAVOR_TNF_ERROR, "", tnf_uint, status, status);
			TAVOR_TNF_EXIT(tavor_qp_sqerr2rts);
			return (ibc_get_ci_failure(0));
		} else {
			TNF_PROBE_0(tavor_qp_sqerr2rts_inv_qpstate_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_qp_sqerr2rts);
			return (IBT_QP_STATE_INVALID);
		}
	}

	TAVOR_TNF_EXIT(tavor_qp_sqerr2rts);
	return (DDI_SUCCESS);
}


/*
 * tavor_qp_to_error()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_qp_to_error(tavor_state_t *state, tavor_qphdl_t qp)
{
	int	status;

	TAVOR_TNF_ENTER(tavor_qp_to_error);

	ASSERT(MUTEX_HELD(&qp->qp_lock));

	/*
	 * Post the TOERR_QP command to the Tavor firmware
	 *
	 * We do a TAVOR_NOSLEEP here because we are still holding the
	 * "qp_lock".  If we got raised to interrupt level by priority
	 * inversion, we do not want to block in this routine waiting for
	 * success.
	 */
	status = tavor_cmn_qp_cmd_post(state, TOERR_QP, NULL, qp->qp_qpnum,
	    0, TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Tavor: TOERR_QP command failed: %08x\n",
		    status);
		TNF_PROBE_1(tavor_qp_to_error_cmd_fail,
		    TAVOR_TNF_ERROR, "", tnf_uint, status, status);
		TAVOR_TNF_EXIT(tavor_qp_to_error);
		return (ibc_get_ci_failure(0));
	}

	TAVOR_TNF_EXIT(tavor_qp_to_error);
	return (DDI_SUCCESS);
}


/*
 * tavor_qp_to_reset()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_qp_to_reset(tavor_state_t *state, tavor_qphdl_t qp)
{
	tavor_hw_qpc_t	*qpc;
	int		status;

	TAVOR_TNF_ENTER(tavor_qp_to_reset);

	ASSERT(MUTEX_HELD(&qp->qp_lock));

	/*
	 * Grab the temporary QPC entry from QP software state
	 */
	qpc = &qp->qpc;

	/*
	 * Post the TORST_QP command to the Tavor firmware
	 *
	 * We do a TAVOR_NOSLEEP here because we are still holding the
	 * "qp_lock".  If we got raised to interrupt level by priority
	 * inversion, we do not want to block in this routine waiting for
	 * success.
	 */
	status = tavor_cmn_qp_cmd_post(state, TORST_QP, qpc, qp->qp_qpnum,
	    0, TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Tavor: TORST_QP command failed: %08x\n",
		    status);
		TNF_PROBE_1(tavor_qp_to_reset_cmd_fail,
		    TAVOR_TNF_ERROR, "", tnf_uint, status, status);
		TAVOR_TNF_EXIT(tavor_qp_to_reset);
		return (ibc_get_ci_failure(0));
	}

	TAVOR_TNF_EXIT(tavor_qp_to_reset);
	return (DDI_SUCCESS);
}


/*
 * tavor_qp_reset2err()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_qp_reset2err(tavor_state_t *state, tavor_qphdl_t qp)
{
	tavor_hw_qpc_t	*qpc;
	int		status;

	TAVOR_TNF_ENTER(tavor_qp_reset2err);

	ASSERT(MUTEX_HELD(&qp->qp_lock));

	/*
	 * In order to implement the transition from "Reset" directly to the
	 * "Error" state, it is necessary to first give ownership of the QP
	 * context to the Tavor hardware.  This is accomplished by transitioning
	 * the QP to "Init" as an intermediate step and then, immediately
	 * transitioning to "Error".
	 *
	 * When this function returns success, the QP context will be owned by
	 * the Tavor hardware and will be in the "Error" state.
	 */

	/*
	 * Grab the temporary QPC entry from QP software state
	 */
	qpc = &qp->qpc;

	/*
	 * Fill in the common and/or Tavor-specific fields in the QPC
	 */
	if (qp->qp_is_special) {
		qpc->serv_type	= TAVOR_QP_MLX;
	} else {
		qpc->serv_type	= qp->qp_serv_type;
	}
	qpc->pm_state		= TAVOR_QP_PMSTATE_MIGRATED;
	qpc->de			= TAVOR_QP_DESC_EVT_ENABLED;
	qpc->sched_q		= TAVOR_QP_SCHEDQ_GET(qp->qp_qpnum);
	if (qp->qp_is_umap) {
		qpc->usr_page = qp->qp_uarpg;
	} else {
		qpc->usr_page = 0;
	}
	qpc->pd			= qp->qp_pdhdl->pd_pdnum;
	qpc->wqe_baseaddr	= 0;
	qpc->wqe_lkey		= qp->qp_mrhdl->mr_lkey;
	qpc->ssc		= qp->qp_sq_sigtype;
	qpc->cqn_snd		= qp->qp_sq_cqhdl->cq_cqnum;
	qpc->rsc		= TAVOR_QP_RQ_ALL_SIGNALED;
	qpc->cqn_rcv		= qp->qp_rq_cqhdl->cq_cqnum;
	qpc->srq_en		= qp->qp_srq_en;

	if (qp->qp_srq_en == TAVOR_QP_SRQ_ENABLED) {
		qpc->srq_number	= qp->qp_srqhdl->srq_srqnum;
	} else {
		qpc->srq_number = 0;
	}

	/*
	 * Now fill in the QPC fields which are specific to transport type
	 */
	if (qp->qp_serv_type == TAVOR_QP_UD) {
		/* Set the UD parameters to an invalid default */
		qpc->qkey = 0;
		qpc->pri_addr_path.portnum = 1;
		qpc->pri_addr_path.pkey_indx = 0;

	} else if (qp->qp_serv_type == TAVOR_QP_RC) {
		/* Set the RC parameters to invalid default */
		qpc->rre = 0;
		qpc->rwe = 0;
		qpc->rae = 0;
		qpc->pri_addr_path.portnum = 1;
		qpc->pri_addr_path.pkey_indx = 0;

	} else if (qp->qp_serv_type == TAVOR_QP_UC) {
		/* Set the UC parameters to invalid default */
		qpc->rwe = 0;
		qpc->pri_addr_path.portnum = 1;
		qpc->pri_addr_path.pkey_indx = 0;

	} else {
		/*
		 * Invalid QP transport type. If we got here then it's a
		 * warning of a probably serious problem.  So print a message
		 * and return failure
		 */
		TAVOR_WARNING(state, "unknown QP transport type in rst2err");
		TNF_PROBE_0(tavor_qp_reset2err_inv_transtype_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_qp_reset2err);
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Post the RST2INIT_QP command to the Tavor firmware
	 *
	 * We do a TAVOR_NOSLEEP here because we are still holding the
	 * "qp_lock".  If we got raised to interrupt level by priority
	 * inversion, we do not want to block in this routine waiting for
	 * success.
	 */
	status = tavor_cmn_qp_cmd_post(state, RST2INIT_QP, qpc, qp->qp_qpnum,
	    0, TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Tavor: RST2INIT_QP command failed: %08x\n",
		    status);
		TNF_PROBE_1(tavor_qp_reset2err_rst2init_cmd_fail,
		    TAVOR_TNF_ERROR, "", tnf_uint, status, status);
		TAVOR_TNF_EXIT(tavor_qp_reset2err);
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Now post the TOERR_QP command to the Tavor firmware
	 *
	 * We still do a TAVOR_NOSLEEP here because we are still holding the
	 * "qp_lock".  Note:  If this fails (which it really never should),
	 * it indicates a serious problem in the HW or SW.  We try to move
	 * the QP back to the "Reset" state if possible and print a warning
	 * message if not.  In any case, we return an error here.
	 */
	status = tavor_cmn_qp_cmd_post(state, TOERR_QP, NULL, qp->qp_qpnum,
	    0, TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Tavor: TOERR_QP command failed: %08x\n",
		    status);
		if (tavor_qp_to_reset(state, qp) != DDI_SUCCESS) {
			TAVOR_WARNING(state, "failed to reset QP context");
		}
		TNF_PROBE_1(tavor_qp_reset2err_toerr_cmd_fail,
		    TAVOR_TNF_ERROR, "", tnf_uint, status, status);
		TAVOR_TNF_EXIT(tavor_qp_reset2err);
		return (ibc_get_ci_failure(0));
	}

	TAVOR_TNF_EXIT(tavor_qp_reset2err);
	return (DDI_SUCCESS);
}


/*
 * tavor_check_rdma_enable_flags()
 *    Context: Can be called from interrupt or base context.
 */
static uint_t
tavor_check_rdma_enable_flags(ibt_cep_modify_flags_t flags,
    ibt_qp_info_t *info_p, tavor_hw_qpc_t *qpc)
{
	uint_t	opmask = 0;

	if (flags & IBT_CEP_SET_RDMA_R) {
		qpc->rre = (info_p->qp_flags & IBT_CEP_RDMA_RD) ? 1 : 0;
		opmask |= TAVOR_CMD_OP_RRE;
	}

	if (flags & IBT_CEP_SET_RDMA_W) {
		qpc->rwe = (info_p->qp_flags & IBT_CEP_RDMA_WR) ? 1 : 0;
		opmask |= TAVOR_CMD_OP_RWE;
	}

	if (flags & IBT_CEP_SET_ATOMIC) {
		qpc->rae = (info_p->qp_flags & IBT_CEP_ATOMIC) ? 1 : 0;
		opmask |= TAVOR_CMD_OP_RAE;
	}

	return (opmask);
}

/*
 * tavor_qp_validate_resp_rsrc()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_qp_validate_resp_rsrc(tavor_state_t *state, ibt_qp_rc_attr_t *rc,
    uint_t *rra_max)
{
	uint_t	rdma_ra_in;

	rdma_ra_in = rc->rc_rdma_ra_in;

	/*
	 * Check if number of responder resources is too large.  Return an
	 * error if it is
	 */
	if (rdma_ra_in > state->ts_cfg_profile->cp_hca_max_rdma_in_qp) {
		return (IBT_INVALID_PARAM);
	}

	/*
	 * If the number of responder resources is too small, round it up.
	 * Then find the next highest power-of-2
	 */
	if (rdma_ra_in == 0) {
		rdma_ra_in = 1;
	}
	if (ISP2(rdma_ra_in)) {
		*rra_max = highbit(rdma_ra_in) - 1;
	} else {
		*rra_max = highbit(rdma_ra_in);
	}
	return (DDI_SUCCESS);
}


/*
 * tavor_qp_validate_init_depth()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_qp_validate_init_depth(tavor_state_t *state, ibt_qp_rc_attr_t *rc,
    uint_t *sra_max)
{
	uint_t	rdma_ra_out;

	rdma_ra_out = rc->rc_rdma_ra_out;

	/*
	 * Check if requested initiator depth is too large.  Return an error
	 * if it is
	 */
	if (rdma_ra_out > state->ts_cfg_profile->cp_hca_max_rdma_out_qp) {
		return (IBT_INVALID_PARAM);
	}

	/*
	 * If the requested initiator depth is too small, round it up.
	 * Then find the next highest power-of-2
	 */
	if (rdma_ra_out == 0) {
		rdma_ra_out = 1;
	}
	if (ISP2(rdma_ra_out)) {
		*sra_max = highbit(rdma_ra_out) - 1;
	} else {
		*sra_max = highbit(rdma_ra_out);
	}
	return (DDI_SUCCESS);
}


/*
 * tavor_qp_validate_mtu()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_qp_validate_mtu(tavor_state_t *state, uint_t mtu)
{
	/*
	 * Check for invalid MTU values (i.e. zero or any value larger than
	 * the HCA's port maximum).
	 */
	if ((mtu == 0) || (mtu > state->ts_cfg_profile->cp_max_mtu)) {
		return (IBT_HCA_PORT_MTU_EXCEEDED);
	}
	return (DDI_SUCCESS);
}
