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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * hermon_qpmod.c
 *    Hermon Queue Pair Modify Routines
 *
 *    This contains all the routines necessary to implement the
 *    ModifyQP() verb.  This includes all the code for legal
 *    transitions to and from Reset, Init, RTR, RTS, SQD, SQErr,
 *    and Error.
 */

#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/bitmap.h>

#include <sys/ib/adapters/hermon/hermon.h>
#include <sys/ib/ib_pkt_hdrs.h>

static int hermon_qp_reset2init(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_qp_info_t *info_p);
static int hermon_qp_init2init(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p);
static int hermon_qp_init2rtr(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p);
static int hermon_qp_rtr2rts(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p);
static int hermon_qp_rts2rts(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p);
#ifdef HERMON_NOTNOW
static int hermon_qp_rts2sqd(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_cep_modify_flags_t flags);
#endif
static int hermon_qp_sqd2rts(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p);
static int hermon_qp_sqd2sqd(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p);
static int hermon_qp_sqerr2rts(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p);
static int hermon_qp_to_error(hermon_state_t *state, hermon_qphdl_t qp);
static int hermon_qp_reset2err(hermon_state_t *state, hermon_qphdl_t qp);

static uint_t hermon_check_rdma_enable_flags(ibt_cep_modify_flags_t flags,
    ibt_qp_info_t *info_p, hermon_hw_qpc_t *qpc);
static int hermon_qp_validate_resp_rsrc(hermon_state_t *state,
    ibt_qp_rc_attr_t *rc, uint_t *rra_max);
static int hermon_qp_validate_init_depth(hermon_state_t *state,
    ibt_qp_rc_attr_t *rc, uint_t *sra_max);
static int hermon_qp_validate_mtu(hermon_state_t *state, uint_t mtu);

/*
 * hermon_qp_modify()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
int
hermon_qp_modify(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p,
    ibt_queue_sizes_t *actual_sz)
{
	ibt_cep_state_t		cur_state, mod_state;
	ibt_cep_modify_flags_t	okflags;
	int			status;

	/*
	 * TODO add support for SUSPEND and RESUME
	 */

	/*
	 * Lock the QP so that we can modify it atomically.  After grabbing
	 * the lock, get the current QP state.  We will use this current QP
	 * state to determine the legal transitions (and the checks that need
	 * to be performed.)
	 * Below is a case for every possible QP state.  In each case, we
	 * check that no flags are set which are not valid for the possible
	 * transitions from that state.  If these tests pass and the
	 * state transition we are attempting is legal, then we call one
	 * of the helper functions.  Each of these functions does some
	 * additional setup before posting the firmware command for the
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
	if (!(HERMON_QP_TYPE_VALID(info_p->qp_trans, qp->qp_serv_type))) {
		mutex_exit(&qp->qp_lock);
		return (IBT_QP_SRV_TYPE_INVALID);
	}

	/*
	 * If this is a transition to RTS (which is valid from RTR, RTS,
	 * SQError, and SQ Drain) then we should honor the "current QP state"
	 * specified by the consumer.  This means converting the IBTF QP state
	 * in "info_p->qp_current_state" to an Hermon QP state.  Otherwise, we
	 * assume that we already know the current state (i.e. whatever it was
	 * last modified to or queried as - in "qp->qp_state").
	 */
	mod_state = info_p->qp_state;

	if (flags & IBT_CEP_SET_RTR_RTS) {
		cur_state = HERMON_QP_RTR;		/* Ready to Receive */

	} else if ((flags & IBT_CEP_SET_STATE) &&
	    (mod_state == IBT_STATE_RTS)) {

		/* Convert the current IBTF QP state to an Hermon QP state */
		switch (info_p->qp_current_state) {
		case IBT_STATE_RTR:
			cur_state = HERMON_QP_RTR;	/* Ready to Receive */
			break;
		case IBT_STATE_RTS:
			cur_state = HERMON_QP_RTS;	/* Ready to Send */
			break;
		case IBT_STATE_SQE:
			cur_state = HERMON_QP_SQERR;	/* Send Queue Error */
			break;
		case IBT_STATE_SQD:
			cur_state = HERMON_QP_SQD;	/* SQ Drained */
			break;
		default:
			mutex_exit(&qp->qp_lock);
			return (IBT_QP_STATE_INVALID);
		}
	} else {
		cur_state = qp->qp_state;
	}

	switch (cur_state) {
	case HERMON_QP_RESET:
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
			status = IBT_QP_ATTR_RO;
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
			status = IBT_QP_STATE_INVALID;
			goto qpmod_fail;

		} else if ((flags & IBT_CEP_SET_RESET_INIT) ||
		    ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_INIT))) {
			/*
			 * Attempt to transition from "Reset" to "Init"
			 */
			status = hermon_qp_reset2init(state, qp, info_p);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}
			qp->qp_state = HERMON_QP_INIT;
			HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_INIT);

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_RESET)) {
			/*
			 * Attempt to transition from "Reset" back to "Reset"
			 *    Nothing to do here really... just drop the lock
			 *    and return success.  The qp->qp_state should
			 *    already be set to HERMON_QP_RESET.
			 *
			 * Note: We return here because we do not want to fall
			 *    through to the hermon_wrid_from_reset_handling()
			 *    routine below (since we are not really moving
			 *    _out_ of the "Reset" state.
			 */
			mutex_exit(&qp->qp_lock);
			return (DDI_SUCCESS);

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_ERROR)) {
			/*
			 * Attempt to transition from "Reset" to "Error"
			 */
			status = hermon_qp_reset2err(state, qp);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}
			qp->qp_state = HERMON_QP_ERR;
			HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_ERR);

		} else {
			/* Invalid transition - return error */
			mutex_exit(&qp->qp_lock);
			status = IBT_QP_STATE_INVALID;
			goto qpmod_fail;
		}

		/*
		 * Do any additional handling necessary here for the transition
		 * from the "Reset" state (e.g. re-initialize the workQ WRID
		 * lists).  Note: If hermon_wrid_from_reset_handling() fails,
		 * then we attempt to transition the QP back to the "Reset"
		 * state.  If that fails, then it is an indication of a serious
		 * problem (either HW or SW).  So we print out a warning
		 * message and return failure.
		 */
		status = hermon_wrid_from_reset_handling(state, qp);
		if (status != DDI_SUCCESS) {
			if (hermon_qp_to_reset(state, qp) != DDI_SUCCESS) {
				HERMON_WARNING(state, "failed to reset QP");
			}
			qp->qp_state = HERMON_QP_RESET;
			HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_RESET);

			mutex_exit(&qp->qp_lock);
			goto qpmod_fail;
		}
		break;

	case HERMON_QP_INIT:
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
			status = IBT_QP_ATTR_RO;
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
			status = IBT_QP_STATE_INVALID;
			goto qpmod_fail;

		} else if ((flags & IBT_CEP_SET_INIT_RTR) ||
		    ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_RTR))) {
			/*
			 * Attempt to transition from "Init" to "RTR"
			 */
			status = hermon_qp_init2rtr(state, qp, flags, info_p);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}
			qp->qp_state = HERMON_QP_RTR;
			HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_RTR);

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_INIT)) {
			/*
			 * Attempt to transition from "Init" to "Init"
			 */
			status = hermon_qp_init2init(state, qp, flags, info_p);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}
			qp->qp_state = HERMON_QP_INIT;
			HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_INIT);

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_RESET)) {
			/*
			 * Attempt to transition from "Init" to "Reset"
			 */
			status = hermon_qp_to_reset(state, qp);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}
			qp->qp_state = HERMON_QP_RESET;
			HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_RESET);

			/*
			 * Do any additional handling necessary for the
			 * transition _to_ the "Reset" state (e.g. update the
			 * workQ WRID lists)
			 */
			status = hermon_wrid_to_reset_handling(state, qp);
			if (status != IBT_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_ERROR)) {
			/*
			 * Attempt to transition from "Init" to "Error"
			 */
			status = hermon_qp_to_error(state, qp);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}
			qp->qp_state = HERMON_QP_ERR;
			HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_ERR);

		} else {
			/* Invalid transition - return error */
			mutex_exit(&qp->qp_lock);
			status = IBT_QP_STATE_INVALID;
			goto qpmod_fail;
		}
		break;

	case HERMON_QP_RTR:
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
			status = IBT_QP_ATTR_RO;
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
			status = IBT_QP_STATE_INVALID;
			goto qpmod_fail;

		} else if ((flags & IBT_CEP_SET_RTR_RTS) ||
		    ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_RTS))) {
			/*
			 * Attempt to transition from "RTR" to "RTS"
			 */
			status = hermon_qp_rtr2rts(state, qp, flags, info_p);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}
			qp->qp_state = HERMON_QP_RTS;
			HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_RTS);

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_RESET)) {
			/*
			 * Attempt to transition from "RTR" to "Reset"
			 */
			status = hermon_qp_to_reset(state, qp);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}
			qp->qp_state = HERMON_QP_RESET;
			HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_RESET);

			/*
			 * Do any additional handling necessary for the
			 * transition _to_ the "Reset" state (e.g. update the
			 * workQ WRID lists)
			 */
			status = hermon_wrid_to_reset_handling(state, qp);
			if (status != IBT_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_ERROR)) {
			/*
			 * Attempt to transition from "RTR" to "Error"
			 */
			status = hermon_qp_to_error(state, qp);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}
			qp->qp_state = HERMON_QP_ERR;
			HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_ERR);

		} else {
			/* Invalid transition - return error */
			mutex_exit(&qp->qp_lock);
			status = IBT_QP_STATE_INVALID;
			goto qpmod_fail;
		}
		break;

	case HERMON_QP_RTS:
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
			status = IBT_QP_ATTR_RO;
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
			status = hermon_qp_rts2rts(state, qp, flags, info_p);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}
			qp->qp_state = HERMON_QP_RTS;
			HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_RTS);

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_SQD)) {
#ifdef HERMON_NOTNOW
			/*
			 * Attempt to transition from "RTS" to "SQD"
			 */
			status = hermon_qp_rts2sqd(state, qp, flags);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}
			qp->qp_state = HERMON_QP_SQD;
			HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_SQD);
#else
			/* hack because of the lack of fw support for SQD */
			mutex_exit(&qp->qp_lock);
			status = IBT_QP_STATE_INVALID;
			goto qpmod_fail;
#endif

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_RESET)) {
			/*
			 * Attempt to transition from "RTS" to "Reset"
			 */
			status = hermon_qp_to_reset(state, qp);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}
			qp->qp_state = HERMON_QP_RESET;
			HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_RESET);

			/*
			 * Do any additional handling necessary for the
			 * transition _to_ the "Reset" state (e.g. update the
			 * workQ WRID lists)
			 */
			status = hermon_wrid_to_reset_handling(state, qp);
			if (status != IBT_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_ERROR)) {
			/*
			 * Attempt to transition from "RTS" to "Error"
			 */
			status = hermon_qp_to_error(state, qp);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}
			qp->qp_state = HERMON_QP_ERR;
			HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_ERR);

		} else {
			/* Invalid transition - return error */
			mutex_exit(&qp->qp_lock);
			status = IBT_QP_STATE_INVALID;
			goto qpmod_fail;
		}
		break;

	case HERMON_QP_SQERR:
		okflags = (IBT_CEP_SET_STATE | IBT_CEP_SET_RDMA_R |
		    IBT_CEP_SET_RDMA_W | IBT_CEP_SET_ATOMIC |
		    IBT_CEP_SET_QKEY | IBT_CEP_SET_MIN_RNR_NAK);

		/*
		 * Check for attempts to modify invalid attributes from the
		 * "SQErr" state
		 */
		if (flags & ~okflags) {
			mutex_exit(&qp->qp_lock);
			status = IBT_QP_ATTR_RO;
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
			status = hermon_qp_sqerr2rts(state, qp, flags, info_p);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}
			qp->qp_state = HERMON_QP_RTS;
			HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_RTS);

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_RESET)) {
			/*
			 * Attempt to transition from "SQErr" to "Reset"
			 */
			status = hermon_qp_to_reset(state, qp);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}
			qp->qp_state = HERMON_QP_RESET;
			HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_RESET);

			/*
			 * Do any additional handling necessary for the
			 * transition _to_ the "Reset" state (e.g. update the
			 * workQ WRID lists)
			 */
			status = hermon_wrid_to_reset_handling(state, qp);
			if (status != IBT_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_ERROR)) {
			/*
			 * Attempt to transition from "SQErr" to "Error"
			 */
			status = hermon_qp_to_error(state, qp);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}
			qp->qp_state = HERMON_QP_ERR;
			HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_ERR);

		} else {
			/* Invalid transition - return error */
			mutex_exit(&qp->qp_lock);
			status = IBT_QP_STATE_INVALID;
			goto qpmod_fail;
		}
		break;

	case HERMON_QP_SQD:
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
			status = IBT_QP_ATTR_RO;
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
			status = hermon_qp_sqd2sqd(state, qp, flags, info_p);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}
			qp->qp_state = HERMON_QP_SQD;
			HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_SQD);

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_RTS)) {
			/*
			 * If still draining SQ, then fail transition attempt
			 * to RTS, even though this is now done is two steps
			 * (see below) if the consumer has tried this before
			 * it's drained, let him fail and wait appropriately
			 */
			if (qp->qp_sqd_still_draining) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}
			/*
			 * IBA 1.2 has changed - most/all the things that were
			 * done in SQD2RTS can be done in SQD2SQD.  So make this
			 * a 2-step process.  First, set any attributes requsted
			 * w/ SQD2SQD, but no real transition.
			 *
			 * First, Attempt to transition from "SQD" to "SQD"
			 */
			status = hermon_qp_sqd2sqd(state, qp, flags, info_p);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}
			qp->qp_state = HERMON_QP_SQD;
			HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_SQD);

			/*
			 * The, attempt to transition from "SQD" to "RTS", but
			 * request only the state transition, no attributes
			 */

			status = hermon_qp_sqd2rts(state, qp,
			    IBT_CEP_SET_STATE, info_p);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}
			qp->qp_state = HERMON_QP_RTS;
			HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_RTS);

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_RESET)) {
			/*
			 * Attempt to transition from "SQD" to "Reset"
			 */
			status = hermon_qp_to_reset(state, qp);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}
			qp->qp_state = HERMON_QP_RESET;
			HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_RESET);

			/*
			 * Do any additional handling necessary for the
			 * transition _to_ the "Reset" state (e.g. update the
			 * workQ WRID lists)
			 */
			status = hermon_wrid_to_reset_handling(state, qp);
			if (status != IBT_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_ERROR)) {
			/*
			 * Attempt to transition from "SQD" to "Error"
			 */
			status = hermon_qp_to_error(state, qp);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}
			qp->qp_state = HERMON_QP_ERR;
			HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_ERR);

		} else {
			/* Invalid transition - return error */
			mutex_exit(&qp->qp_lock);
			status = IBT_QP_STATE_INVALID;
			goto qpmod_fail;
		}
		break;

	case HERMON_QP_ERR:
		/*
		 * Verify state transition is to either "Reset" or back to
		 * "Error"
		 */
		if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_RESET)) {
			/*
			 * Attempt to transition from "Error" to "Reset"
			 */
			status = hermon_qp_to_reset(state, qp);
			if (status != DDI_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}
			qp->qp_state = HERMON_QP_RESET;
			HERMON_SET_QP_POST_SEND_STATE(qp, HERMON_QP_RESET);

			/*
			 * Do any additional handling necessary for the
			 * transition _to_ the "Reset" state (e.g. update the
			 * workQ WRID lists)
			 */
			status = hermon_wrid_to_reset_handling(state, qp);
			if (status != IBT_SUCCESS) {
				mutex_exit(&qp->qp_lock);
				goto qpmod_fail;
			}

		} else if ((flags & IBT_CEP_SET_STATE) &&
		    (mod_state == IBT_STATE_ERROR)) {
			/*
			 * Attempt to transition from "Error" back to "Error"
			 *    Nothing to do here really... just drop the lock
			 *    and return success.  The qp->qp_state should
			 *    already be set to HERMON_QP_ERR.
			 *
			 */
			mutex_exit(&qp->qp_lock);
			return (DDI_SUCCESS);

		} else {
			/* Invalid transition - return error */
			mutex_exit(&qp->qp_lock);
			status = IBT_QP_STATE_INVALID;
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
		HERMON_WARNING(state, "unknown QP state in modify");
		status = IBT_QP_STATE_INVALID;
		goto qpmod_fail;
	}

	mutex_exit(&qp->qp_lock);
	return (DDI_SUCCESS);

qpmod_fail:
	return (status);
}


/*
 * hermon_qp_reset2init()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_qp_reset2init(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_qp_info_t *info_p)
{
	hermon_hw_qpc_t		*qpc;
	ibt_qp_rc_attr_t	*rc;
	ibt_qp_ud_attr_t	*ud;
	ibt_qp_uc_attr_t	*uc;
	uint_t			portnum, pkeyindx;
	int			status;
	uint32_t		cqnmask;
	int			qp_srq_en;

	ASSERT(MUTEX_HELD(&qp->qp_lock));

	/*
	 * Grab the temporary QPC entry from QP software state
	 */
	qpc = &qp->qpc;

	/*
	 * Fill in the common fields in the QPC
	 */

	if (qp->qp_is_special) {
		qpc->serv_type	= HERMON_QP_MLX;
	} else {
		qpc->serv_type	= qp->qp_serv_type;
	}
	qpc->pm_state		= HERMON_QP_PMSTATE_MIGRATED;

	qpc->pd			= qp->qp_pdhdl->pd_pdnum;

	qpc->log_sq_stride	= qp->qp_sq_log_wqesz - 4;
	qpc->log_rq_stride	= qp->qp_rq_log_wqesz - 4;
	qpc->sq_no_prefetch	= qp->qp_no_prefetch;
	qpc->log_sq_size	= highbit(qp->qp_sq_bufsz) - 1;
	qpc->log_rq_size	= highbit(qp->qp_rq_bufsz) - 1;

	qpc->usr_page		= qp->qp_uarpg;

	cqnmask = (1 << state->hs_cfg_profile->cp_log_num_cq) - 1;
	qpc->cqn_snd		=
	    (qp->qp_sq_cqhdl == NULL) ? 0 : qp->qp_sq_cqhdl->cq_cqnum & cqnmask;
	qpc->page_offs		= qp->qp_wqinfo.qa_pgoffs >> 6;
	qpc->cqn_rcv		=
	    (qp->qp_rq_cqhdl == NULL) ? 0 : qp->qp_rq_cqhdl->cq_cqnum & cqnmask;

	/* dbr is now an address, not an index */
	qpc->dbr_addrh		= ((uint64_t)qp->qp_rq_pdbr >> 32);
	qpc->dbr_addrl		= ((uint64_t)qp->qp_rq_pdbr & 0xFFFFFFFC) >> 2;
	qpc->sq_wqe_counter	= 0;
	qpc->rq_wqe_counter	= 0;
	/*
	 * HERMON:
	 * qpc->wqe_baseaddr is replaced by LKey from the cMPT, and
	 * page_offset, mtt_base_addr_h/l, and log2_page_size will
	 * be used to map the WQE buffer
	 * NOTE that the cMPT is created implicitly when the QP is
	 * transitioned from reset to init
	 */
	qpc->log2_pgsz		= qp->qp_mrhdl->mr_log2_pgsz;
	qpc->mtt_base_addrl	= (qp->qp_mrhdl->mr_mttaddr) >> 3;
	qpc->mtt_base_addrh	= (uint32_t)((qp->qp_mrhdl->mr_mttaddr >> 32) &
	    0xFF);
	qp_srq_en		= (qp->qp_alloc_flags & IBT_QP_USES_SRQ) != 0;
	qpc->srq_en		= qp_srq_en;

	if (qp_srq_en) {
		qpc->srq_number	= qp->qp_srqhdl->srq_srqnum;
	} else {
		qpc->srq_number = 0;
	}

	/*
	 * Fast Registration Work Requests and Reserved Lkey are enabled
	 * with the single IBT bit stored in qp_rlky.
	 */
	qpc->fre		= qp->qp_rlky;
	qpc->rlky		= qp->qp_rlky;

	/* 1.2 verbs extensions disabled for now */
	qpc->header_sep		= 0; /* disable header separation for now */
	qpc->rss		= qp->qp_alloc_flags & IBT_QP_USES_RSS ? 1 : 0;
	qpc->inline_scatter	= 0; /* disable inline scatter for now */

	/*
	 * Now fill in the QPC fields which are specific to transport type
	 */
	if (qp->qp_type == IBT_UD_RQP) {
		int my_fc_id_idx, exch_base;

		ud = &info_p->qp_transport.ud;

		/* Set the QKey */
		qpc->qkey = ud->ud_qkey;

		/*
		 * Set MTU and message max. Hermon checks the QPC
		 * MTU settings rather than just the port MTU,
		 * so set it to maximum size.
		 */
		qpc->mtu = HERMON_MAX_MTU;
		if (qp->qp_uses_lso)
			qpc->msg_max = state->hs_devlim.log_max_gso_sz;
		else if (qp->qp_is_special)
			qpc->msg_max = HERMON_MAX_MTU + 6;
		else
			qpc->msg_max = HERMON_QP_LOG_MAX_MSGSZ;

		/* Check for valid port number and fill it in */
		portnum = ud->ud_port;
		if (hermon_portnum_is_valid(state, portnum)) {
			qp->qp_portnum = portnum - 1;
			qpc->pri_addr_path.sched_q =
			    HERMON_QP_SCHEDQ_GET(portnum - 1,
			    0, qp->qp_is_special);
		} else {
			return (IBT_HCA_PORT_INVALID);
		}


		/* Check for valid PKey index and fill it in */
		pkeyindx = ud->ud_pkey_ix;
		if (hermon_pkeyindex_is_valid(state, pkeyindx)) {
			qpc->pri_addr_path.pkey_indx = pkeyindx;
			qp->qp_pkeyindx = pkeyindx;
		} else {
			return (IBT_PKEY_IX_ILLEGAL);
		}

		/* fill in the RSS fields */
		if (qpc->rss) {
			struct hermon_hw_rss_s *rssp;
			ibt_rss_flags_t flags = ud->ud_rss.rss_flags;

			rssp = (struct hermon_hw_rss_s *)&qpc->pri_addr_path;
			rssp->log2_tbl_sz = ud->ud_rss.rss_log2_table;
			rssp->base_qpn = ud->ud_rss.rss_base_qpn;
			rssp->default_qpn = ud->ud_rss.rss_def_qpn;
			if (flags & IBT_RSS_ALG_XOR)
				rssp->hash_fn = 0;	/* XOR Hash Function */
			else if (flags & IBT_RSS_ALG_TPL)
				rssp->hash_fn = 1;	/* Toeplitz Hash Fn */
			else
				return (IBT_INVALID_PARAM);
			rssp->ipv4 = (flags & IBT_RSS_HASH_IPV4) != 0;
			rssp->tcp_ipv4 = (flags & IBT_RSS_HASH_TCP_IPV4) != 0;
			rssp->ipv6 = (flags & IBT_RSS_HASH_IPV6) != 0;
			rssp->tcp_ipv4 = (flags & IBT_RSS_HASH_TCP_IPV6) != 0;
			bcopy(ud->ud_rss.rss_toe_key, rssp->rss_key, 40);
		} else if (qp->qp_serv_type == HERMON_QP_RFCI) {
			status = hermon_fcoib_set_id(state, portnum,
			    qp->qp_qpnum, ud->ud_fc.fc_src_id);
			if (status != DDI_SUCCESS)
				return (status);
			qp->qp_fc_attr = ud->ud_fc;
		} else if (qp->qp_serv_type == HERMON_QP_FEXCH) {
			my_fc_id_idx = hermon_fcoib_get_id_idx(state,
			    portnum, &ud->ud_fc);
			if (my_fc_id_idx == -1)
				return (IBT_INVALID_PARAM);
			qpc->my_fc_id_idx = my_fc_id_idx;

			status = hermon_fcoib_fexch_mkey_init(state,
			    qp->qp_pdhdl, ud->ud_fc.fc_hca_port,
			    qp->qp_qpnum, HERMON_CMD_NOSLEEP_SPIN);
			if (status != DDI_SUCCESS)
				return (status);
			qp->qp_fc_attr = ud->ud_fc;
		} else if (qp->qp_serv_type == HERMON_QP_FCMND) {
			my_fc_id_idx = hermon_fcoib_get_id_idx(state,
			    portnum, &ud->ud_fc);
			if (my_fc_id_idx == -1)
				return (IBT_INVALID_PARAM);
			qpc->my_fc_id_idx = my_fc_id_idx;
			exch_base = hermon_fcoib_check_exch_base_off(state,
			    portnum, &ud->ud_fc);
			if (exch_base == -1)
				return (IBT_INVALID_PARAM);
			qpc->exch_base = exch_base;
			qpc->exch_size = ud->ud_fc.fc_exch_log2_sz;
			qp->qp_fc_attr = ud->ud_fc;
		}

	} else if (qp->qp_serv_type == HERMON_QP_RC) {
		rc = &info_p->qp_transport.rc;

		/* Set the RDMA (recv) enable/disable flags */
		qpc->rre = (info_p->qp_flags & IBT_CEP_RDMA_RD) ? 1 : 0;
		qpc->rwe = (info_p->qp_flags & IBT_CEP_RDMA_WR) ? 1 : 0;
		qpc->rae = (info_p->qp_flags & IBT_CEP_ATOMIC)  ? 1 : 0;

		/* Check for valid port number and fill it in */
		portnum = rc->rc_path.cep_hca_port_num;
		if (hermon_portnum_is_valid(state, portnum)) {
			qp->qp_portnum = portnum - 1;
			qpc->pri_addr_path.sched_q =
			    HERMON_QP_SCHEDQ_GET(portnum - 1,
			    0, qp->qp_is_special);
		} else {
			return (IBT_HCA_PORT_INVALID);
		}

		/* Check for valid PKey index and fill it in */
		pkeyindx = rc->rc_path.cep_pkey_ix;
		if (hermon_pkeyindex_is_valid(state, pkeyindx)) {
			qpc->pri_addr_path.pkey_indx = pkeyindx;
		} else {
			return (IBT_PKEY_IX_ILLEGAL);
		}

	} else if (qp->qp_serv_type == HERMON_QP_UC) {
		uc = &info_p->qp_transport.uc;

		/*
		 * Set the RDMA (recv) enable/disable flags.  Note: RDMA Read
		 * and Atomic are ignored by default.
		 */
		qpc->rwe = (info_p->qp_flags & IBT_CEP_RDMA_WR) ? 1 : 0;

		/* Check for valid port number and fill it in */
		portnum = uc->uc_path.cep_hca_port_num;
		if (hermon_portnum_is_valid(state, portnum)) {
			qp->qp_portnum = portnum - 1;
			qpc->pri_addr_path.sched_q =
			    HERMON_QP_SCHEDQ_GET(portnum - 1,
			    0, qp->qp_is_special);
		} else {
			return (IBT_HCA_PORT_INVALID);
		}

		/* Check for valid PKey index and fill it in */
		pkeyindx = uc->uc_path.cep_pkey_ix;
		if (hermon_pkeyindex_is_valid(state, pkeyindx)) {
			qpc->pri_addr_path.pkey_indx = pkeyindx;
		} else {
			return (IBT_PKEY_IX_ILLEGAL);
		}

	} else {
		/*
		 * Invalid QP transport type. If we got here then it's a
		 * warning of a probably serious problem.  So print a message
		 * and return failure
		 */
		HERMON_WARNING(state, "unknown QP transport type in rst2init");
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Post the RST2INIT_QP command to the Hermon firmware
	 *
	 * We do a HERMON_NOSLEEP here because we are still holding the
	 * "qp_lock".  If we got raised to interrupt level by priority
	 * inversion, we do not want to block in this routine waiting for
	 * success.
	 */
	status = hermon_cmn_qp_cmd_post(state, RST2INIT_QP, qpc, qp->qp_qpnum,
	    0, HERMON_CMD_NOSLEEP_SPIN);
	if (status != HERMON_CMD_SUCCESS) {
		cmn_err(CE_NOTE, "hermon%d: RST2INIT_QP command failed: %08x\n",
		    state->hs_instance, status);
		if (status == HERMON_CMD_INVALID_STATUS) {
			hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_SRV_LOST);
		}
		return (ibc_get_ci_failure(0));
	}

	return (DDI_SUCCESS);
}


/*
 * hermon_qp_init2init()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_qp_init2init(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p)
{
	hermon_hw_qpc_t		*qpc;
	ibt_qp_rc_attr_t	*rc;
	ibt_qp_ud_attr_t	*ud;
	ibt_qp_uc_attr_t	*uc;
	uint_t			portnum, pkeyindx;
	uint32_t		opmask = 0;
	int			status;

	ASSERT(MUTEX_HELD(&qp->qp_lock));

	/*
	 * Grab the temporary QPC entry from QP software state
	 */
	qpc = &qp->qpc;

	/*
	 * Since there are no common fields to be filled in for this command,
	 * we begin with the QPC fields which are specific to transport type.
	 */
	if (qp->qp_type == IBT_UD_RQP) {
		ud = &info_p->qp_transport.ud;

		/*
		 * If we are attempting to modify the port for this QP, then
		 * check for valid port number and fill it in.  Also set the
		 * appropriate flag in the "opmask" parameter.
		 */
	/*
	 * set port is not supported in init2init - however, in init2rtr it will
	 * take the entire qpc, including the embedded sched_q in the path
	 * structure - so, we can just skip setting the opmask for it explicitly
	 * and allow it to be set later on
	 */
		if (flags & IBT_CEP_SET_PORT) {
			portnum = ud->ud_port;
			if (hermon_portnum_is_valid(state, portnum)) {
				qp->qp_portnum = portnum - 1; /* save it away */
				qpc->pri_addr_path.sched_q =
				    HERMON_QP_SCHEDQ_GET(portnum - 1,
				    0, qp->qp_is_special);
			} else {
				return (IBT_HCA_PORT_INVALID);
			}
		}

		/*
		 * If we are attempting to modify the PKey index for this QP,
		 * then check for valid PKey index and fill it in.  Also set
		 * the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_PKEY_IX) {
			pkeyindx = ud->ud_pkey_ix;
			if (hermon_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->pri_addr_path.pkey_indx = pkeyindx;
				opmask |= HERMON_CMD_OP_PKEYINDX;
				qp->qp_pkeyindx = pkeyindx;
			} else {
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
			opmask |= HERMON_CMD_OP_QKEY;
		}

	} else if (qp->qp_serv_type == HERMON_QP_RC) {
		rc = &info_p->qp_transport.rc;

		/*
		 * If we are attempting to modify the port for this QP, then
		 * check for valid port number and fill it in.  Also set the
		 * appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_PORT) {
			portnum = rc->rc_path.cep_hca_port_num;
			if (hermon_portnum_is_valid(state, portnum)) {
				qp->qp_portnum = portnum - 1;
				qpc->pri_addr_path.sched_q =
				    HERMON_QP_SCHEDQ_GET(portnum - 1,
				    0, qp->qp_is_special);
			} else {
				return (IBT_HCA_PORT_INVALID);
			}

		}

		/*
		 * If we are attempting to modify the PKey index for this QP,
		 * then check for valid PKey index and fill it in.  Also set
		 * the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_PKEY_IX) {
			pkeyindx = rc->rc_path.cep_pkey_ix;
			if (hermon_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->pri_addr_path.pkey_indx = pkeyindx;
				opmask |= HERMON_CMD_OP_PKEYINDX;
			} else {
				return (IBT_PKEY_IX_ILLEGAL);
			}
		}

		/*
		 * Check if any of the flags indicate a change in the RDMA
		 * (recv) enable/disable flags and set the appropriate flag in
		 * the "opmask" parameter
		 */
		opmask |= hermon_check_rdma_enable_flags(flags, info_p, qpc);

	} else if (qp->qp_serv_type == HERMON_QP_UC) {
		uc = &info_p->qp_transport.uc;

		/*
		 * If we are attempting to modify the port for this QP, then
		 * check for valid port number and fill it in.  Also set the
		 * appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_PORT) {
			portnum = uc->uc_path.cep_hca_port_num;
			if (hermon_portnum_is_valid(state, portnum)) {
				qp->qp_portnum = portnum - 1;
				qpc->pri_addr_path.sched_q =
				    HERMON_QP_SCHEDQ_GET(portnum - 1,
				    0, qp->qp_is_special);
			} else {
				return (IBT_HCA_PORT_INVALID);
			}
		/* port# cannot be set in this transition - defer to init2rtr */
		}

		/*
		 * If we are attempting to modify the PKey index for this QP,
		 * then check for valid PKey index and fill it in.  Also set
		 * the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_PKEY_IX) {
			pkeyindx = uc->uc_path.cep_pkey_ix;
			if (hermon_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->pri_addr_path.pkey_indx = pkeyindx;
				opmask |= HERMON_CMD_OP_PKEYINDX;
			} else {
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
			opmask |= HERMON_CMD_OP_RWE;
		}
	} else {
		/*
		 * Invalid QP transport type. If we got here then it's a
		 * warning of a probably serious problem.  So print a message
		 * and return failure
		 */
		HERMON_WARNING(state, "unknown QP transport type in init2init");
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Post the INIT2INIT_QP command to the Hermon firmware
	 *
	 * We do a HERMON_NOSLEEP here because we are still holding the
	 * "qp_lock".  If we got raised to interrupt level by priority
	 * inversion, we do not want to block in this routine waiting for
	 * success.
	 */
	status = hermon_cmn_qp_cmd_post(state, INIT2INIT_QP, qpc, qp->qp_qpnum,
	    opmask, HERMON_CMD_NOSLEEP_SPIN);
	if (status != HERMON_CMD_SUCCESS) {
		if (status != HERMON_CMD_BAD_QP_STATE) {
			cmn_err(CE_NOTE, "hermon%d: INIT2INIT_QP command "
			    "failed: %08x\n", state->hs_instance, status);
			if (status == HERMON_CMD_INVALID_STATUS) {
				hermon_fm_ereport(state, HCA_SYS_ERR,
				    HCA_ERR_SRV_LOST);
			}
			return (ibc_get_ci_failure(0));
		} else {
			return (IBT_QP_STATE_INVALID);
		}
	}

	return (DDI_SUCCESS);
}


/*
 * hermon_qp_init2rtr()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_qp_init2rtr(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p)
{
	hermon_hw_qpc_t		*qpc;
	ibt_qp_rc_attr_t	*rc;
	ibt_qp_ud_attr_t	*ud;
	ibt_qp_uc_attr_t	*uc;
	hermon_hw_addr_path_t	*qpc_path;
	ibt_adds_vect_t		*adds_vect;
	uint_t			portnum, pkeyindx, rra_max;
	uint_t			mtu;
	uint32_t		opmask = 0;
	int			status;

	ASSERT(MUTEX_HELD(&qp->qp_lock));

	/*
	 * Grab the temporary QPC entry from QP software state
	 */
	qpc = &qp->qpc;

	/*
	 * Since there are few common fields to be filled in for this command,
	 * we just do the QPC fields that are specific to transport type.
	 */
	if (qp->qp_type == IBT_UD_RQP) {
		ud = &info_p->qp_transport.ud;

		/*
		 * If this UD QP is also a "special QP" (QP0 or QP1), then
		 * the MTU is 256 bytes.  However, Hermon checks the QPC
		 * MTU settings rather than just the port MTU, so we will
		 * set it to maximum size for all UD.
		 */
		qpc->mtu = HERMON_MAX_MTU;
		if (qp->qp_uses_lso)
			qpc->msg_max = state->hs_devlim.log_max_gso_sz;
		else
			qpc->msg_max = HERMON_QP_LOG_MAX_MSGSZ;

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
			if (hermon_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->pri_addr_path.pkey_indx = pkeyindx;
				opmask |= HERMON_CMD_OP_PKEYINDX;
				qp->qp_pkeyindx = pkeyindx;
			} else {
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
			opmask |= HERMON_CMD_OP_QKEY;
		}

	} else if (qp->qp_serv_type == HERMON_QP_RC) {
		rc = &info_p->qp_transport.rc;
		qpc_path = &qpc->pri_addr_path;
		adds_vect = &rc->rc_path.cep_adds_vect;

		/*
		 * Set the common primary address path fields
		 */
		status = hermon_set_addr_path(state, adds_vect, qpc_path,
		    HERMON_ADDRPATH_QP);
		if (status != DDI_SUCCESS) {
			return (status);
		}
		/* set the primary port number/sched_q */
		portnum = qp->qp_portnum + 1;
		if (hermon_portnum_is_valid(state, portnum)) {
			qpc->pri_addr_path.sched_q  =
			    HERMON_QP_SCHEDQ_GET(qp->qp_portnum,
			    adds_vect->av_srvl, qp->qp_is_special);
		} else {
			return (IBT_HCA_PORT_INVALID);
		}

		/*
		 * The following values are apparently "required" here (as
		 * they are part of the IBA-defined "Remote Node Address
		 * Vector").  However, they are also going to be "required"
		 * later - at RTR2RTS_QP time.  Not sure why.  But we set
		 * them here anyway.
		 */
		qpc->rnr_retry		= rc->rc_rnr_retry_cnt;
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
		qpc->msg_max	  = HERMON_QP_LOG_MAX_MSGSZ;
		qpc->ric	  = 0;
		mtu		  = rc->rc_path_mtu;

		if (hermon_qp_validate_mtu(state, mtu) != DDI_SUCCESS) {
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
		 * optionally specifiable in Hermon.  So we force the
		 * optional flag here.
		 */
		qpc->min_rnr_nak = rc->rc_min_rnr_nak;
		opmask |= HERMON_CMD_OP_MINRNRNAK;

		/*
		 * Check that the number of specified "incoming RDMA resources"
		 * is valid.  And if it is, then setup the "rra_max
		 */
		if (hermon_qp_validate_resp_rsrc(state, rc, &rra_max) !=
		    DDI_SUCCESS) {
			return (IBT_INVALID_PARAM);
		}
		qpc->rra_max = rra_max;

		/* don't need to set up ra_buff_indx, implicit for hermon */

		/*
		 * If we are attempting to modify the PKey index for this QP,
		 * then check for valid PKey index and fill it in.  Also set
		 * the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_PKEY_IX) {
			pkeyindx = rc->rc_path.cep_pkey_ix;
			if (hermon_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->pri_addr_path.pkey_indx = pkeyindx;
				opmask |= HERMON_CMD_OP_PKEYINDX;
			} else {
				return (IBT_PKEY_IX_ILLEGAL);
			}
		}

		/*
		 * Check if any of the flags indicate a change in the RDMA
		 * (recv) enable/disable flags and set the appropriate flag in
		 * the "opmask" parameter
		 */
		opmask |= hermon_check_rdma_enable_flags(flags, info_p, qpc);

		/*
		 * Check for optional alternate path and fill in the
		 * appropriate QPC fields if one is specified
		 */
		if (flags & IBT_CEP_SET_ALT_PATH) {
			qpc_path = &qpc->alt_addr_path;
			adds_vect = &rc->rc_alt_path.cep_adds_vect;

			/* Set the common alternate address path fields */
			status = hermon_set_addr_path(state, adds_vect,
			    qpc_path, HERMON_ADDRPATH_QP);
			if (status != DDI_SUCCESS) {
				return (status);
			}
			qpc_path->ack_timeout = rc->rc_alt_path.cep_timeout;


			/*
			 * Check for valid alternate path port number and fill
			 * it in
			 */
			portnum = rc->rc_alt_path.cep_hca_port_num;
			if (hermon_portnum_is_valid(state, portnum)) {
				qp->qp_portnum_alt = portnum - 1;
				qpc->alt_addr_path.sched_q =
				    HERMON_QP_SCHEDQ_GET(portnum - 1,
				    adds_vect->av_srvl, qp->qp_is_special);
			} else {
				return (IBT_HCA_PORT_INVALID);
			}
			/*
			 * Check for valid alternate path PKey index and fill
			 * it in
			 */
			pkeyindx = rc->rc_alt_path.cep_pkey_ix;
			if (hermon_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->alt_addr_path.pkey_indx = pkeyindx;
			} else {
				return (IBT_PKEY_IX_ILLEGAL);
			}
			opmask |= HERMON_CMD_OP_ALT_PATH;
		}

	} else if (qp->qp_serv_type == HERMON_QP_UC) {
		uc = &info_p->qp_transport.uc;
		qpc_path = &qpc->pri_addr_path;
		adds_vect = &uc->uc_path.cep_adds_vect;

		/*
		 * Set the common primary address path fields
		 */
		status = hermon_set_addr_path(state, adds_vect, qpc_path,
		    HERMON_ADDRPATH_QP);
		if (status != DDI_SUCCESS) {
			return (status);
		}

		/* set the primary port num/schedq */
		portnum = qp->qp_portnum + 1;
		if (hermon_portnum_is_valid(state, portnum)) {
			qpc->pri_addr_path.sched_q  =
			    HERMON_QP_SCHEDQ_GET(qp->qp_portnum,
			    adds_vect->av_srvl, qp->qp_is_special);
		} else {
			return (IBT_HCA_PORT_INVALID);
		}

		/*
		 * Setup the destination QP, recv PSN, MTU, max msg size,etc.
		 * Note max message size is defined to be the maximum IB
		 * allowed message size (which is 2^31 bytes).  Also max
		 * MTU is defined by HCA port properties.
		 */
		qpc->rem_qpn	  = uc->uc_dst_qpn;
		qpc->next_rcv_psn = uc->uc_rq_psn;
		qpc->msg_max	  = HERMON_QP_LOG_MAX_MSGSZ;
		mtu = uc->uc_path_mtu;
		if (hermon_qp_validate_mtu(state, mtu) != DDI_SUCCESS) {
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
			if (hermon_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->pri_addr_path.pkey_indx = pkeyindx;
				opmask |= HERMON_CMD_OP_PKEYINDX;
			} else {
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
			opmask |= HERMON_CMD_OP_RWE;
		}

		/*
		 * Check for optional alternate path and fill in the
		 * appropriate QPC fields if one is specified
		 */
		if (flags & IBT_CEP_SET_ALT_PATH) {
			qpc_path = &qpc->alt_addr_path;
			adds_vect = &uc->uc_alt_path.cep_adds_vect;

			/* Set the common alternate address path fields */
			status = hermon_set_addr_path(state, adds_vect,
			    qpc_path, HERMON_ADDRPATH_QP);
			if (status != DDI_SUCCESS) {
				return (status);
			}

			qpc_path->ack_timeout = rc->rc_alt_path.cep_timeout;

			/*
			 * Check for valid alternate path port number and fill
			 * it in
			 */
			portnum = uc->uc_alt_path.cep_hca_port_num;
			if (hermon_portnum_is_valid(state, portnum)) {
				qp->qp_portnum_alt = portnum - 1;
				qpc->alt_addr_path.sched_q =
				    HERMON_QP_SCHEDQ_GET(portnum - 1,
				    adds_vect->av_srvl, qp->qp_is_special);
			} else {
				return (IBT_HCA_PORT_INVALID);
			}

			/*
			 * Check for valid alternate path PKey index and fill
			 * it in
			 */
			pkeyindx = uc->uc_alt_path.cep_pkey_ix;
			if (hermon_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->alt_addr_path.pkey_indx = pkeyindx;
			} else {
				return (IBT_PKEY_IX_ILLEGAL);
			}
			opmask |= HERMON_CMD_OP_ALT_PATH;
		}
	} else {
		/*
		 * Invalid QP transport type. If we got here then it's a
		 * warning of a probably serious problem.  So print a message
		 * and return failure
		 */
		HERMON_WARNING(state, "unknown QP transport type in init2rtr");
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Post the INIT2RTR_QP command to the Hermon firmware
	 *
	 * We do a HERMON_NOSLEEP here because we are still holding the
	 * "qp_lock".  If we got raised to interrupt level by priority
	 * inversion, we do not want to block in this routine waiting for
	 * success.
	 */
	status = hermon_cmn_qp_cmd_post(state, INIT2RTR_QP, qpc, qp->qp_qpnum,
	    opmask, HERMON_CMD_NOSLEEP_SPIN);
	if (status != HERMON_CMD_SUCCESS) {
		if (status != HERMON_CMD_BAD_QP_STATE) {
			cmn_err(CE_NOTE, "hermon%d: INIT2RTR_QP command "
			    "failed: %08x\n", state->hs_instance, status);
			if (status == HERMON_CMD_INVALID_STATUS) {
				hermon_fm_ereport(state, HCA_SYS_ERR,
				    HCA_ERR_SRV_LOST);
			}
			return (ibc_get_ci_failure(0));
		} else {
			return (IBT_QP_STATE_INVALID);
		}
	}

	return (DDI_SUCCESS);
}


/*
 * hermon_qp_rtr2rts()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_qp_rtr2rts(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p)
{
	hermon_hw_qpc_t		*qpc;
	ibt_qp_rc_attr_t	*rc;
	ibt_qp_ud_attr_t	*ud;
	ibt_qp_uc_attr_t	*uc;
	hermon_hw_addr_path_t	*qpc_path;
	ibt_adds_vect_t		*adds_vect;
	uint_t			portnum, pkeyindx, sra_max;
	uint32_t		opmask = 0;
	int			status;

	ASSERT(MUTEX_HELD(&qp->qp_lock));

	/*
	 * Grab the temporary QPC entry from QP software state
	 */
	qpc = &qp->qpc;

	/*
	 * Now fill in the QPC fields which are specific to transport type
	 */
	if (qp->qp_type == IBT_UD_RQP) {
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
			opmask |= HERMON_CMD_OP_QKEY;
		}

	} else if (qp->qp_serv_type == HERMON_QP_RC) {
		rc = &info_p->qp_transport.rc;
		qpc_path = &qpc->pri_addr_path;

		/*
		 * Setup the send PSN, ACK timeout, and retry counts
		 */
		qpc->next_snd_psn	= rc->rc_sq_psn;
		qpc_path->ack_timeout	= rc->rc_path.cep_timeout;
		qpc->rnr_retry		= rc->rc_rnr_retry_cnt;
						/* in qpc now, not path */
		qpc->retry_cnt		= rc->rc_retry_cnt;

		/*
		 * Set "ack_req_freq" based on the configuration variable
		 */
		qpc->ack_req_freq = state->hs_cfg_profile->cp_ackreq_freq;

		/*
		 * Check that the number of specified "outgoing RDMA resources"
		 * is valid.  And if it is, then setup the "sra_max"
		 * appropriately
		 */
		if (hermon_qp_validate_init_depth(state, rc, &sra_max) !=
		    DDI_SUCCESS) {
			return (IBT_INVALID_PARAM);
		}
		qpc->sra_max = sra_max;


		/*
		 * Check if any of the flags indicate a change in the RDMA
		 * (recv) enable/disable flags and set the appropriate flag in
		 * the "opmask" parameter
		 */
		opmask |= hermon_check_rdma_enable_flags(flags, info_p, qpc);

		/*
		 * If we are attempting to modify the path migration state for
		 * this QP, then check for valid state and fill it in.  Also
		 * set the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_MIG) {
			if (rc->rc_mig_state == IBT_STATE_MIGRATED) {
				qpc->pm_state = HERMON_QP_PMSTATE_MIGRATED;
			} else if (rc->rc_mig_state == IBT_STATE_REARMED) {
				qpc->pm_state = HERMON_QP_PMSTATE_REARM;
			} else {
				return (IBT_QP_APM_STATE_INVALID);
			}
			opmask |= HERMON_CMD_OP_PM_STATE;
		}

		/*
		 * If we are attempting to modify the "Minimum RNR NAK" value
		 * for this QP, then fill it in and set the appropriate flag
		 * in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_MIN_RNR_NAK) {
			qpc->min_rnr_nak = rc->rc_min_rnr_nak;
			opmask |= HERMON_CMD_OP_MINRNRNAK;
		}

		/*
		 * Check for optional alternate path and fill in the
		 * appropriate QPC fields if one is specified
		 */
		if (flags & IBT_CEP_SET_ALT_PATH) {
			qpc_path = &qpc->alt_addr_path;
			adds_vect = &rc->rc_alt_path.cep_adds_vect;

			/* Set the common alternate address path fields */
			status = hermon_set_addr_path(state, adds_vect,
			    qpc_path, HERMON_ADDRPATH_QP);
			if (status != DDI_SUCCESS) {
				return (status);
			}

			qpc_path->ack_timeout = rc->rc_alt_path.cep_timeout;

			/*
			 * Check for valid alternate path port number and fill
			 * it in
			 */
			portnum = rc->rc_alt_path.cep_hca_port_num;
			if (hermon_portnum_is_valid(state, portnum)) {
				qp->qp_portnum_alt = portnum - 1;
				qpc->alt_addr_path.sched_q =
				    HERMON_QP_SCHEDQ_GET(portnum - 1,
				    adds_vect->av_srvl, qp->qp_is_special);
			} else {
				return (IBT_HCA_PORT_INVALID);
			}

			/*
			 * Check for valid alternate path PKey index and fill
			 * it in
			 */
			pkeyindx = rc->rc_alt_path.cep_pkey_ix;
			if (hermon_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->alt_addr_path.pkey_indx = pkeyindx;
			} else {
				return (IBT_PKEY_IX_ILLEGAL);
			}
			opmask |= HERMON_CMD_OP_ALT_PATH;
		}

	} else if (qp->qp_serv_type == HERMON_QP_UC) {
		uc = &info_p->qp_transport.uc;

		/* Set the send PSN */
		qpc->next_snd_psn = uc->uc_sq_psn;

		/*
		 * Configure the QP to allow (sending of) all types of allowable
		 * UC traffic (i.e. RDMA Write).
		 */


		/*
		 * Check if any of the flags indicate a change in the RDMA
		 * Write (recv) enable/disable and set the appropriate flag
		 * in the "opmask" parameter. Note: RDMA Read and Atomic are
		 * not valid for UC transport.
		 */
		if (flags & IBT_CEP_SET_RDMA_W) {
			qpc->rwe = (info_p->qp_flags & IBT_CEP_RDMA_WR) ? 1 : 0;
			opmask |= HERMON_CMD_OP_RWE;
		}

		/*
		 * If we are attempting to modify the path migration state for
		 * this QP, then check for valid state and fill it in.  Also
		 * set the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_MIG) {
			if (uc->uc_mig_state == IBT_STATE_MIGRATED) {
				qpc->pm_state = HERMON_QP_PMSTATE_MIGRATED;
			} else if (uc->uc_mig_state == IBT_STATE_REARMED) {
				qpc->pm_state = HERMON_QP_PMSTATE_REARM;
			} else {
				return (IBT_QP_APM_STATE_INVALID);
			}
			opmask |= HERMON_CMD_OP_PM_STATE;
		}

		/*
		 * Check for optional alternate path and fill in the
		 * appropriate QPC fields if one is specified
		 */
		if (flags & IBT_CEP_SET_ALT_PATH) {
			qpc_path = &qpc->alt_addr_path;
			adds_vect = &uc->uc_alt_path.cep_adds_vect;

			/* Set the common alternate address path fields */
			status = hermon_set_addr_path(state, adds_vect,
			    qpc_path, HERMON_ADDRPATH_QP);
			if (status != DDI_SUCCESS) {
				return (status);
			}
			qpc_path->ack_timeout = rc->rc_alt_path.cep_timeout;

			/*
			 * Check for valid alternate path port number and fill
			 * it in
			 */
			portnum = uc->uc_alt_path.cep_hca_port_num;
			if (hermon_portnum_is_valid(state, portnum)) {
				qpc->alt_addr_path.sched_q =
				    HERMON_QP_SCHEDQ_GET(portnum - 1,
				    adds_vect->av_srvl, qp->qp_is_special);
			} else {
				return (IBT_HCA_PORT_INVALID);
			}

			/*
			 * Check for valid alternate path PKey index and fill
			 * it in
			 */
			pkeyindx = uc->uc_alt_path.cep_pkey_ix;
			if (hermon_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->alt_addr_path.pkey_indx = pkeyindx;
			} else {
				return (IBT_PKEY_IX_ILLEGAL);
			}
			opmask |= HERMON_CMD_OP_ALT_PATH;
		}
	} else {
		/*
		 * Invalid QP transport type. If we got here then it's a
		 * warning of a probably serious problem.  So print a message
		 * and return failure
		 */
		HERMON_WARNING(state, "unknown QP transport type in rtr2rts");
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Post the RTR2RTS_QP command to the Hermon firmware
	 *
	 * We do a HERMON_NOSLEEP here because we are still holding the
	 * "qp_lock".  If we got raised to interrupt level by priority
	 * inversion, we do not want to block in this routine waiting for
	 * success.
	 */
	status = hermon_cmn_qp_cmd_post(state, RTR2RTS_QP, qpc, qp->qp_qpnum,
	    opmask, HERMON_CMD_NOSLEEP_SPIN);
	if (status != HERMON_CMD_SUCCESS) {
		if (status != HERMON_CMD_BAD_QP_STATE) {
			cmn_err(CE_NOTE, "hermon%d: RTR2RTS_QP command failed: "
			    "%08x\n", state->hs_instance, status);
			if (status == HERMON_CMD_INVALID_STATUS) {
				hermon_fm_ereport(state, HCA_SYS_ERR,
				    HCA_ERR_SRV_LOST);
			}
			return (ibc_get_ci_failure(0));
		} else {
			return (IBT_QP_STATE_INVALID);
		}
	}

	return (DDI_SUCCESS);
}


/*
 * hermon_qp_rts2rts()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_qp_rts2rts(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p)
{
	hermon_hw_qpc_t		*qpc;
	ibt_qp_rc_attr_t	*rc;
	ibt_qp_ud_attr_t	*ud;
	ibt_qp_uc_attr_t	*uc;
	hermon_hw_addr_path_t	*qpc_path;
	ibt_adds_vect_t		*adds_vect;
	uint_t			portnum, pkeyindx;
	uint32_t		opmask = 0;
	int			status;

	ASSERT(MUTEX_HELD(&qp->qp_lock));

	/*
	 * Grab the temporary QPC entry from QP software state
	 */

	qpc = &qp->qpc;

	/*
	 * Since there are no common fields to be filled in for this command,
	 * we begin with the QPC fields which are specific to transport type.
	 */
	if (qp->qp_type == IBT_UD_RQP) {
		ud = &info_p->qp_transport.ud;

		/*
		 * If we are attempting to modify the QKey for this QP, then
		 * fill it in and set the appropriate flag in the "opmask"
		 * parameter.
		 */
		if (flags & IBT_CEP_SET_QKEY) {
			qpc->qkey = ud->ud_qkey;
			opmask |= HERMON_CMD_OP_QKEY;
		}

	} else if (qp->qp_serv_type == HERMON_QP_RC) {
		rc = &info_p->qp_transport.rc;

		/*
		 * Check if any of the flags indicate a change in the RDMA
		 * (recv) enable/disable flags and set the appropriate flag in
		 * the "opmask" parameter
		 */
		opmask |= hermon_check_rdma_enable_flags(flags, info_p, qpc);

		/*
		 * If we are attempting to modify the path migration state for
		 * this QP, then check for valid state and fill it in.  Also
		 * set the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_MIG) {
			if (rc->rc_mig_state == IBT_STATE_MIGRATED) {
				qpc->pm_state = HERMON_QP_PMSTATE_MIGRATED;
			} else if (rc->rc_mig_state == IBT_STATE_REARMED) {
				qpc->pm_state = HERMON_QP_PMSTATE_REARM;
			} else {
				return (IBT_QP_APM_STATE_INVALID);
			}
			opmask |= HERMON_CMD_OP_PM_STATE;
		}

		/*
		 * If we are attempting to modify the "Minimum RNR NAK" value
		 * for this QP, then fill it in and set the appropriate flag
		 * in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_MIN_RNR_NAK) {
			qpc->min_rnr_nak = rc->rc_min_rnr_nak;
			opmask |= HERMON_CMD_OP_MINRNRNAK;
		}

		/*
		 * Check for optional alternate path and fill in the
		 * appropriate QPC fields if one is specified
		 */
		if (flags & IBT_CEP_SET_ALT_PATH) {
			qpc_path = &qpc->alt_addr_path;
			adds_vect = &rc->rc_alt_path.cep_adds_vect;

			/* Set the common alternate address path fields */
			status = hermon_set_addr_path(state, adds_vect,
			    qpc_path, HERMON_ADDRPATH_QP);
			if (status != DDI_SUCCESS) {
				return (status);
			}
			qpc_path->ack_timeout = rc->rc_alt_path.cep_timeout;

			/*
			 * Check for valid alternate path port number and fill
			 * it in
			 */
			portnum = rc->rc_alt_path.cep_hca_port_num;
			if (hermon_portnum_is_valid(state, portnum)) {
				qp->qp_portnum_alt = portnum - 1;
				qpc->alt_addr_path.sched_q =
				    HERMON_QP_SCHEDQ_GET(portnum - 1,
				    adds_vect->av_srvl, qp->qp_is_special);
			} else {
				return (IBT_HCA_PORT_INVALID);
			}

			/*
			 * Check for valid alternate path PKey index and fill
			 * it in
			 */
			pkeyindx = rc->rc_alt_path.cep_pkey_ix;
			if (hermon_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->alt_addr_path.pkey_indx = pkeyindx;
			} else {
				return (IBT_PKEY_IX_ILLEGAL);
			}
			opmask |= HERMON_CMD_OP_ALT_PATH;
		}

	} else if (qp->qp_serv_type == HERMON_QP_UC) {
		uc = &info_p->qp_transport.uc;

		/*
		 * Check if any of the flags indicate a change in the RDMA
		 * Write (recv) enable/disable and set the appropriate flag
		 * in the "opmask" parameter. Note: RDMA Read and Atomic are
		 * not valid for UC transport.
		 */
		if (flags & IBT_CEP_SET_RDMA_W) {
			qpc->rwe = (info_p->qp_flags & IBT_CEP_RDMA_WR) ? 1 : 0;
			opmask |= HERMON_CMD_OP_RWE;
		}

		/*
		 * If we are attempting to modify the path migration state for
		 * this QP, then check for valid state and fill it in.  Also
		 * set the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_MIG) {
			if (uc->uc_mig_state == IBT_STATE_MIGRATED) {
				qpc->pm_state = HERMON_QP_PMSTATE_MIGRATED;
			} else if (uc->uc_mig_state == IBT_STATE_REARMED) {
				qpc->pm_state = HERMON_QP_PMSTATE_REARM;
			} else {
				return (IBT_QP_APM_STATE_INVALID);
			}
			opmask |= HERMON_CMD_OP_PM_STATE;
		}

		/*
		 * Check for optional alternate path and fill in the
		 * appropriate QPC fields if one is specified
		 */
		if (flags & IBT_CEP_SET_ALT_PATH) {
			qpc_path = &qpc->alt_addr_path;
			adds_vect = &uc->uc_alt_path.cep_adds_vect;

			/* Set the common alternate address path fields */
			status = hermon_set_addr_path(state, adds_vect,
			    qpc_path, HERMON_ADDRPATH_QP);
			if (status != DDI_SUCCESS) {
				return (status);
			}

			/*
			 * Check for valid alternate path port number and fill
			 * it in
			 */
			portnum = uc->uc_alt_path.cep_hca_port_num;
			if (hermon_portnum_is_valid(state, portnum)) {
				qp->qp_portnum_alt = portnum - 1;
				qpc->alt_addr_path.sched_q =
				    HERMON_QP_SCHEDQ_GET(portnum - 1,
				    adds_vect->av_srvl, qp->qp_is_special);
			} else {
				return (IBT_HCA_PORT_INVALID);
			}

			/*
			 * Check for valid alternate path PKey index and fill
			 * it in
			 */
			pkeyindx = uc->uc_alt_path.cep_pkey_ix;
			if (hermon_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->alt_addr_path.pkey_indx = pkeyindx;
			} else {
				return (IBT_PKEY_IX_ILLEGAL);
			}
			opmask |= HERMON_CMD_OP_ALT_PATH;
		}
	} else {
		/*
		 * Invalid QP transport type. If we got here then it's a
		 * warning of a probably serious problem.  So print a message
		 * and return failure
		 */
		HERMON_WARNING(state, "unknown QP transport type in rts2rts");
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Post the RTS2RTS_QP command to the Hermon firmware
	 *
	 * We do a HERMON_NOSLEEP here because we are still holding the
	 * "qp_lock".  If we got raised to interrupt level by priority
	 * inversion, we do not want to block in this routine waiting for
	 * success.
	 */
	status = hermon_cmn_qp_cmd_post(state, RTS2RTS_QP, qpc, qp->qp_qpnum,
	    opmask, HERMON_CMD_NOSLEEP_SPIN);
	if (status != HERMON_CMD_SUCCESS) {
		if (status != HERMON_CMD_BAD_QP_STATE) {
			cmn_err(CE_NOTE, "hermon%d: RTS2RTS_QP command failed: "
			    "%08x\n", state->hs_instance, status);
			if (status == HERMON_CMD_INVALID_STATUS) {
				hermon_fm_ereport(state, HCA_SYS_ERR,
				    HCA_ERR_SRV_LOST);
			}
			return (ibc_get_ci_failure(0));
		} else {
			return (IBT_QP_STATE_INVALID);
		}
	}

	return (DDI_SUCCESS);
}


#ifdef HERMON_NOTNOW
/*
 * hermon_qp_rts2sqd()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_qp_rts2sqd(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_cep_modify_flags_t flags)
{
	int			status;

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
	 * Post the RTS2SQD_QP command to the Hermon firmware
	 *
	 * We do a HERMON_NOSLEEP here because we are still holding the
	 * "qp_lock".  If we got raised to interrupt level by priority
	 * inversion, we do not want to block in this routine waiting for
	 * success.
	 */
	status = hermon_cmn_qp_cmd_post(state, RTS2SQD_QP, NULL, qp->qp_qpnum,
	    0, HERMON_CMD_NOSLEEP_SPIN);
	if (status != HERMON_CMD_SUCCESS) {
		if (status != HERMON_CMD_BAD_QP_STATE) {
			cmn_err(CE_NOTE, "hermon%d: RTS2SQD_QP command failed: "
			    "%08x\n", state->hs_instance, status);
			if (status == HERMON_CMD_INVALID_STATUS) {
				hermon_fm_ereport(state, HCA_SYS_ERR,
				    HCA_ERR_SRV_LOST);
			}
			return (ibc_get_ci_failure(0));
		} else {
			return (IBT_QP_STATE_INVALID);
		}
	}

	/*
	 * Mark the current QP state as "SQ Draining".  This allows us to
	 * distinguish between the two underlying states in SQD. (see QueryQP()
	 * code in hermon_qp.c)
	 */
	qp->qp_sqd_still_draining = 1;

	return (DDI_SUCCESS);
}
#endif


/*
 * hermon_qp_sqd2rts()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_qp_sqd2rts(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p)
{
	hermon_hw_qpc_t		*qpc;
	ibt_qp_rc_attr_t	*rc;
	ibt_qp_ud_attr_t	*ud;
	ibt_qp_uc_attr_t	*uc;
	hermon_hw_addr_path_t	*qpc_path;
	ibt_adds_vect_t		*adds_vect;
	uint_t			portnum, pkeyindx;
	uint_t			rra_max, sra_max;
	uint32_t		opmask = 0;
	int			status;

	ASSERT(MUTEX_HELD(&qp->qp_lock));

	/*
	 * Grab the temporary QPC entry from QP software state
	 */
	qpc = &qp->qpc;

	/*
	 * Fill in the common fields in the QPC
	 */

	/*
	 * Now fill in the QPC fields which are specific to transport type
	 */
	if (qp->qp_type == IBT_UD_RQP) {
		ud = &info_p->qp_transport.ud;

		/*
		 * If we are attempting to modify the port for this QP, then
		 * check for valid port number and fill it in.  Also set the
		 * appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_PORT) {
			portnum = ud->ud_port;
			if (hermon_portnum_is_valid(state, portnum)) {
				qp->qp_portnum = portnum - 1;
				qpc->pri_addr_path.sched_q =
				    HERMON_QP_SCHEDQ_GET(portnum - 1,
				    0, qp->qp_is_special);
			} else {
				return (IBT_HCA_PORT_INVALID);
			}
			opmask |= HERMON_CMD_OP_PRIM_PORT;
		}

		/*
		 * If we are attempting to modify the PKey index for this QP,
		 * then check for valid PKey index and fill it in.  Also set
		 * the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_PKEY_IX) {
			pkeyindx = ud->ud_pkey_ix;
			if (hermon_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->pri_addr_path.pkey_indx = pkeyindx;
				opmask |= HERMON_CMD_OP_PKEYINDX;
				qp->qp_pkeyindx = pkeyindx;
			} else {
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
			opmask |= HERMON_CMD_OP_QKEY;
		}

	} else if (qp->qp_serv_type == HERMON_QP_RC) {
		rc = &info_p->qp_transport.rc;

		/*
		 * Check if any of the flags indicate a change in the RDMA
		 * (recv) enable/disable flags and set the appropriate flag in
		 * the "opmask" parameter
		 */
		opmask |= hermon_check_rdma_enable_flags(flags, info_p, qpc);

		qpc->retry_cnt = rc->rc_retry_cnt;

		/*
		 * If we are attempting to modify the path migration state for
		 * this QP, then check for valid state and fill it in.  Also
		 * set the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_MIG) {
			if (rc->rc_mig_state == IBT_STATE_MIGRATED) {
				qpc->pm_state = HERMON_QP_PMSTATE_MIGRATED;
			} else if (rc->rc_mig_state == IBT_STATE_REARMED) {
				qpc->pm_state = HERMON_QP_PMSTATE_REARM;
			} else {
				return (IBT_QP_APM_STATE_INVALID);
			}
			opmask |= HERMON_CMD_OP_PM_STATE;
		}

		/*
		 * Check for optional alternate path and fill in the
		 * appropriate QPC fields if one is specified
		 */
		if (flags & IBT_CEP_SET_ALT_PATH) {
			qpc_path = &qpc->alt_addr_path;
			adds_vect = &rc->rc_alt_path.cep_adds_vect;

			/* Set the common alternate address path fields */
			status = hermon_set_addr_path(state, adds_vect,
			    qpc_path, HERMON_ADDRPATH_QP);
			if (status != DDI_SUCCESS) {
				return (status);
			}
			qpc_path->ack_timeout = rc->rc_alt_path.cep_timeout;
			/*
			 * Check for valid alternate path port number and fill
			 * it in
			 */
			portnum = rc->rc_alt_path.cep_hca_port_num;
			if (hermon_portnum_is_valid(state, portnum)) {
				qp->qp_portnum_alt = portnum - 1;
				qpc->alt_addr_path.sched_q =
				    HERMON_QP_SCHEDQ_GET(portnum - 1,
				    adds_vect->av_srvl, qp->qp_is_special);
			} else {
				return (IBT_HCA_PORT_INVALID);
			}

			/*
			 * Check for valid alternate path PKey index and fill
			 * it in
			 */
			pkeyindx = rc->rc_alt_path.cep_pkey_ix;
			if (hermon_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->alt_addr_path.pkey_indx = pkeyindx;
			} else {
				return (IBT_PKEY_IX_ILLEGAL);
			}
			opmask |= HERMON_CMD_OP_ALT_PATH;
		}

		/*
		 * If we are attempting to modify the number of "outgoing
		 * RDMA resources" for this QP, then check for valid value and
		 * fill it in.  Also set the appropriate flag in the "opmask"
		 * parameter.
		 */
		if (flags & IBT_CEP_SET_RDMARA_OUT) {
			if (hermon_qp_validate_init_depth(state, rc,
			    &sra_max) != DDI_SUCCESS) {
				return (IBT_INVALID_PARAM);
			}
			qpc->sra_max = sra_max;
			opmask |= HERMON_CMD_OP_SRA_SET;
		}

		/*
		 * If we are attempting to modify the number of "incoming
		 * RDMA resources" for this QP, then check for valid value and
		 * update the "rra_max" and "ra_buf_index" fields in the QPC to
		 * point to the pre-allocated RDB resources (in DDR).  Also set
		 * the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_RDMARA_IN) {
			if (hermon_qp_validate_resp_rsrc(state, rc,
			    &rra_max) != DDI_SUCCESS) {
				return (IBT_INVALID_PARAM);
			}
			qpc->rra_max = rra_max;
			opmask |= HERMON_CMD_OP_RRA_SET;
		}


		/*
		 * If we are attempting to modify the "Minimum RNR NAK" value
		 * for this QP, then fill it in and set the appropriate flag
		 * in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_MIN_RNR_NAK) {
			qpc->min_rnr_nak = rc->rc_min_rnr_nak;
			opmask |= HERMON_CMD_OP_MINRNRNAK;
		}

	} else if (qp->qp_serv_type == HERMON_QP_UC) {
		uc = &info_p->qp_transport.uc;

		/*
		 * Check if any of the flags indicate a change in the RDMA
		 * Write (recv) enable/disable and set the appropriate flag
		 * in the "opmask" parameter. Note: RDMA Read and Atomic are
		 * not valid for UC transport.
		 */
		if (flags & IBT_CEP_SET_RDMA_W) {
			qpc->rwe = (info_p->qp_flags & IBT_CEP_RDMA_WR) ? 1 : 0;
			opmask |= HERMON_CMD_OP_RWE;
		}

		/*
		 * If we are attempting to modify the path migration state for
		 * this QP, then check for valid state and fill it in.  Also
		 * set the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_MIG) {
			if (uc->uc_mig_state == IBT_STATE_MIGRATED) {
				qpc->pm_state = HERMON_QP_PMSTATE_MIGRATED;
			} else if (uc->uc_mig_state == IBT_STATE_REARMED) {
				qpc->pm_state = HERMON_QP_PMSTATE_REARM;
			} else {
				return (IBT_QP_APM_STATE_INVALID);
			}
			opmask |= HERMON_CMD_OP_PM_STATE;
		}

		/*
		 * Check for optional alternate path and fill in the
		 * appropriate QPC fields if one is specified
		 */
		if (flags & IBT_CEP_SET_ALT_PATH) {
			qpc_path = &qpc->alt_addr_path;
			adds_vect = &uc->uc_alt_path.cep_adds_vect;

			/* Set the common alternate address path fields */
			status = hermon_set_addr_path(state, adds_vect,
			    qpc_path, HERMON_ADDRPATH_QP);
			if (status != DDI_SUCCESS) {
				return (status);
			}

			/*
			 * Check for valid alternate path port number and fill
			 * it in
			 */
			portnum = uc->uc_alt_path.cep_hca_port_num;
			if (hermon_portnum_is_valid(state, portnum)) {
				qp->qp_portnum_alt = portnum - 1;
				qpc->alt_addr_path.sched_q =
				    HERMON_QP_SCHEDQ_GET(portnum - 1,
				    adds_vect->av_srvl, qp->qp_is_special);
			} else {
				return (IBT_HCA_PORT_INVALID);
			}

			/*
			 * Check for valid alternate path PKey index and fill
			 * it in
			 */
			pkeyindx = uc->uc_alt_path.cep_pkey_ix;
			if (hermon_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->alt_addr_path.pkey_indx = pkeyindx;
			} else {
				return (IBT_PKEY_IX_ILLEGAL);
			}
			opmask |= HERMON_CMD_OP_ALT_PATH;
		}
	} else {
		/*
		 * Invalid QP transport type. If we got here then it's a
		 * warning of a probably serious problem.  So print a message
		 * and return failure
		 */
		HERMON_WARNING(state, "unknown QP transport type in sqd2rts");
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Post the SQD2RTS_QP command to the Hermon firmware
	 *
	 * We do a HERMON_NOSLEEP here because we are still holding the
	 * "qp_lock".  If we got raised to interrupt level by priority
	 * inversion, we do not want to block in this routine waiting for
	 * success.
	 */
	status = hermon_cmn_qp_cmd_post(state, SQD2RTS_QP, qpc, qp->qp_qpnum,
	    opmask, HERMON_CMD_NOSLEEP_SPIN);
	if (status != HERMON_CMD_SUCCESS) {
		if (status != HERMON_CMD_BAD_QP_STATE) {
			cmn_err(CE_NOTE, "hermon%d: SQD2RTS_QP command failed: "
			    "%08x\n", state->hs_instance, status);
			if (status == HERMON_CMD_INVALID_STATUS) {
				hermon_fm_ereport(state, HCA_SYS_ERR,
				    HCA_ERR_SRV_LOST);
			}
			return (ibc_get_ci_failure(0));
		} else {
			return (IBT_QP_STATE_INVALID);
		}
	}

	return (DDI_SUCCESS);
}


/*
 * hermon_qp_sqd2sqd()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_qp_sqd2sqd(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p)
{
	hermon_hw_qpc_t		*qpc;
	ibt_qp_rc_attr_t	*rc;
	ibt_qp_ud_attr_t	*ud;
	ibt_qp_uc_attr_t	*uc;
	hermon_hw_addr_path_t	*qpc_path;
	ibt_adds_vect_t		*adds_vect;
	uint_t			portnum, pkeyindx;
	uint_t			rra_max, sra_max;
	uint32_t		opmask = 0;
	int			status;

	ASSERT(MUTEX_HELD(&qp->qp_lock));

	/*
	 * Grab the temporary QPC entry from QP software state
	 */
	qpc = &qp->qpc;

	/*
	 * Fill in the common fields in the QPC
	 */

	/*
	 * Now fill in the QPC fields which are specific to transport type
	 */
	if (qp->qp_type == IBT_UD_RQP) {
		ud = &info_p->qp_transport.ud;

		/*
		 * If we are attempting to modify the port for this QP, then
		 * check for valid port number and fill it in.  Also set the
		 * appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_PORT) {
			portnum = ud->ud_port;
			if (hermon_portnum_is_valid(state, portnum)) {
				qp->qp_portnum = portnum - 1;
				qpc->pri_addr_path.sched_q =
				    HERMON_QP_SCHEDQ_GET(portnum - 1,
				    0, qp->qp_is_special);
			} else {
				return (IBT_HCA_PORT_INVALID);
			}
			opmask |= HERMON_CMD_OP_SCHEDQUEUE;
		}

		/*
		 * If we are attempting to modify the PKey index for this QP,
		 * then check for valid PKey index and fill it in.  Also set
		 * the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_PKEY_IX) {
			pkeyindx = ud->ud_pkey_ix;
			if (hermon_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->pri_addr_path.pkey_indx = pkeyindx;
				opmask |= HERMON_CMD_OP_PKEYINDX;
				qp->qp_pkeyindx = pkeyindx;
			} else {
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
			opmask |= HERMON_CMD_OP_QKEY;
		}

	} else if (qp->qp_serv_type == HERMON_QP_RC) {
		rc = &info_p->qp_transport.rc;

		/*
		 * Check if any of the flags indicate a change in the RDMA
		 * (recv) enable/disable flags and set the appropriate flag in
		 * the "opmask" parameter
		 */
		opmask |= hermon_check_rdma_enable_flags(flags, info_p, qpc);

		/*
		 * Check for optional primary path and fill in the
		 * appropriate QPC fields if one is specified
		 */
		if (flags & IBT_CEP_SET_ADDS_VECT) {
			qpc_path = &qpc->pri_addr_path;
			adds_vect = &rc->rc_path.cep_adds_vect;

			/* Set the common primary address path fields */
			status = hermon_set_addr_path(state, adds_vect,
			    qpc_path, HERMON_ADDRPATH_QP);
			if (status != DDI_SUCCESS) {
				return (status);
			}
			qpc->rnr_retry = rc->rc_rnr_retry_cnt;
			qpc_path->ack_timeout = rc->rc_path.cep_timeout;
			qpc->retry_cnt = rc->rc_retry_cnt;

			portnum = qp->qp_portnum + 1;
			if (hermon_portnum_is_valid(state, portnum)) {
				qpc->pri_addr_path.sched_q  =
				    HERMON_QP_SCHEDQ_GET(qp->qp_portnum,
				    adds_vect->av_srvl, qp->qp_is_special);
			} else {
				return (IBT_HCA_PORT_INVALID);
			}

			/*
			 * MTU changes as part of sqd2sqd are not allowed.
			 * Simply keep the same MTU value here, stored in the
			 * qphdl from init2rtr time.
			 */
			qpc->mtu = qp->qp_save_mtu;

			opmask |= (HERMON_CMD_OP_PRIM_PATH |
			    HERMON_CMD_OP_RETRYCNT | HERMON_CMD_OP_ACKTIMEOUT |
			    HERMON_CMD_OP_PRIM_RNRRETRY);
		}

		/*
		 * If we are attempting to modify the path migration state for
		 * this QP, then check for valid state and fill it in.  Also
		 * set the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_MIG) {
			if (rc->rc_mig_state == IBT_STATE_MIGRATED) {
				qpc->pm_state = HERMON_QP_PMSTATE_MIGRATED;
			} else if (rc->rc_mig_state == IBT_STATE_REARMED) {
				qpc->pm_state = HERMON_QP_PMSTATE_REARM;
			} else {
				return (IBT_QP_APM_STATE_INVALID);
			}
			opmask |= HERMON_CMD_OP_PM_STATE;
		}

		/*
		 * If we are attempting to modify the PKey index for this QP,
		 * then check for valid PKey index and fill it in.  Also set
		 * the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_PKEY_IX) {
			pkeyindx = rc->rc_path.cep_pkey_ix;
			if (hermon_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->pri_addr_path.pkey_indx = pkeyindx;
				opmask |= HERMON_CMD_OP_PKEYINDX;
			} else {
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
			if (hermon_portnum_is_valid(state, portnum)) {
				qp->qp_portnum = portnum - 1;
				qpc->pri_addr_path.sched_q =
				    HERMON_QP_SCHEDQ_GET(portnum - 1,
				    adds_vect->av_srvl, qp->qp_is_special);
			} else {
				return (IBT_HCA_PORT_INVALID);
			}
			opmask |= HERMON_CMD_OP_SCHEDQUEUE;
		}

		/*
		 * Check for optional alternate path and fill in the
		 * appropriate QPC fields if one is specified
		 */
		if (flags & IBT_CEP_SET_ALT_PATH) {
			qpc_path = &qpc->alt_addr_path;
			adds_vect = &rc->rc_alt_path.cep_adds_vect;

			/* Set the common alternate address path fields */
			status = hermon_set_addr_path(state, adds_vect,
			    qpc_path, HERMON_ADDRPATH_QP);
			if (status != DDI_SUCCESS) {
				return (status);
			}
			qpc_path->ack_timeout = rc->rc_alt_path.cep_timeout;

			/*
			 * Check for valid alternate path port number and fill
			 * it in
			 */
			portnum = rc->rc_alt_path.cep_hca_port_num;
			if (hermon_portnum_is_valid(state, portnum)) {
				qp->qp_portnum_alt = portnum - 1;
				qpc->alt_addr_path.sched_q =
				    HERMON_QP_SCHEDQ_GET(portnum - 1,
				    adds_vect->av_srvl, qp->qp_is_special);
			} else {
				return (IBT_HCA_PORT_INVALID);
			}

			/*
			 * Check for valid alternate path PKey index and fill
			 * it in
			 */
			pkeyindx = rc->rc_alt_path.cep_pkey_ix;
			if (hermon_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->alt_addr_path.pkey_indx = pkeyindx;
			} else {
				return (IBT_PKEY_IX_ILLEGAL);
			}
			opmask |= HERMON_CMD_OP_ALT_PATH;
		}

		/*
		 * If we are attempting to modify the number of "outgoing
		 * RDMA resources" for this QP, then check for valid value and
		 * fill it in.  Also set the appropriate flag in the "opmask"
		 * parameter.
		 */
		if (flags & IBT_CEP_SET_RDMARA_OUT) {
			if (hermon_qp_validate_init_depth(state, rc,
			    &sra_max) != DDI_SUCCESS) {
				return (IBT_INVALID_PARAM);
			}
			qpc->sra_max = sra_max;
			opmask |= HERMON_CMD_OP_SRA_SET;
		}

		/*
		 * If we are attempting to modify the number of "incoming
		 * RDMA resources" for this QP, then check for valid value and
		 * update the "rra_max" and "ra_buf_index" fields in the QPC to
		 * point to the pre-allocated RDB resources (in DDR).  Also set
		 * the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_RDMARA_IN) {
			if (hermon_qp_validate_resp_rsrc(state, rc,
			    &rra_max) != DDI_SUCCESS) {
				return (IBT_INVALID_PARAM);
			}
			qpc->rra_max = rra_max;
			opmask |= HERMON_CMD_OP_RRA_SET;
		}

		/*
		 * If we are attempting to modify the "Local Ack Timeout" value
		 * for this QP, then fill it in and set the appropriate flag in
		 * the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_TIMEOUT) {
			qpc_path = &qpc->pri_addr_path;
			qpc_path->ack_timeout = rc->rc_path.cep_timeout;
			opmask |= HERMON_CMD_OP_ACKTIMEOUT;
		}

		/*
		 * If we are attempting to modify the "Retry Count" for this QP,
		 * then fill it in and set the appropriate flag in the "opmask"
		 * parameter.
		 */
		if (flags & IBT_CEP_SET_RETRY) {
			qpc->retry_cnt = rc->rc_retry_cnt;
			opmask |= HERMON_CMD_OP_PRIM_RNRRETRY;
		}

		/*
		 * If we are attempting to modify the "RNR Retry Count" for this
		 * QP, then fill it in and set the appropriate flag in the
		 * "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_RNR_NAK_RETRY) {
			qpc_path = &qpc->pri_addr_path;
			qpc->rnr_retry = rc->rc_rnr_retry_cnt;
			opmask |= HERMON_CMD_OP_RETRYCNT;
		}

		/*
		 * If we are attempting to modify the "Minimum RNR NAK" value
		 * for this QP, then fill it in and set the appropriate flag
		 * in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_MIN_RNR_NAK) {
			qpc->min_rnr_nak = rc->rc_min_rnr_nak;
			opmask |= HERMON_CMD_OP_MINRNRNAK;
		}

	} else if (qp->qp_serv_type == HERMON_QP_UC) {
		uc = &info_p->qp_transport.uc;

		/*
		 * Check if any of the flags indicate a change in the RDMA
		 * Write (recv) enable/disable and set the appropriate flag
		 * in the "opmask" parameter. Note: RDMA Read and Atomic are
		 * not valid for UC transport.
		 */
		if (flags & IBT_CEP_SET_RDMA_W) {
			qpc->rwe = (info_p->qp_flags & IBT_CEP_RDMA_WR) ? 1 : 0;
			opmask |= HERMON_CMD_OP_RWE;
		}

		/*
		 * Check for optional primary path and fill in the
		 * appropriate QPC fields if one is specified
		 */
		if (flags & IBT_CEP_SET_ADDS_VECT) {
			qpc_path = &qpc->pri_addr_path;
			adds_vect = &uc->uc_path.cep_adds_vect;

			/* Set the common primary address path fields */
			status = hermon_set_addr_path(state, adds_vect,
			    qpc_path, HERMON_ADDRPATH_QP);
			if (status != DDI_SUCCESS) {
				return (status);
			}
			portnum = qp->qp_portnum + 1;
			if (hermon_portnum_is_valid(state, portnum)) {
				qpc->pri_addr_path.sched_q =
				    HERMON_QP_SCHEDQ_GET(qp->qp_portnum,
				    adds_vect->av_srvl, qp->qp_is_special);
			} else {
				return (IBT_HCA_PORT_INVALID);
			}

			/*
			 * MTU changes as part of sqd2sqd are not allowed.
			 * Simply keep the same MTU value here, stored in the
			 * qphdl from init2rtr time.
			 */
			qpc->mtu = qp->qp_save_mtu;

			opmask |= HERMON_CMD_OP_PRIM_PATH;
		}

		/*
		 * If we are attempting to modify the path migration state for
		 * this QP, then check for valid state and fill it in.  Also
		 * set the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_MIG) {
			if (uc->uc_mig_state == IBT_STATE_MIGRATED) {
				qpc->pm_state = HERMON_QP_PMSTATE_MIGRATED;
			} else if (uc->uc_mig_state == IBT_STATE_REARMED) {
				qpc->pm_state = HERMON_QP_PMSTATE_REARM;
			} else {
				return (IBT_QP_APM_STATE_INVALID);
			}
			opmask |= HERMON_CMD_OP_PM_STATE;
		}

		/*
		 * If we are attempting to modify the PKey index for this QP,
		 * then check for valid PKey index and fill it in.  Also set
		 * the appropriate flag in the "opmask" parameter.
		 */
		if (flags & IBT_CEP_SET_PKEY_IX) {
			pkeyindx = uc->uc_path.cep_pkey_ix;
			if (hermon_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->pri_addr_path.pkey_indx = pkeyindx;
				opmask |= HERMON_CMD_OP_PKEYINDX;
			} else {
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
			status = hermon_set_addr_path(state, adds_vect,
			    qpc_path, HERMON_ADDRPATH_QP);
			if (status != DDI_SUCCESS) {
				return (status);
			}

			/*
			 * Check for valid alternate path port number and fill
			 * it in
			 */
			portnum = uc->uc_alt_path.cep_hca_port_num;
			if (hermon_portnum_is_valid(state, portnum)) {
				qp->qp_portnum_alt = portnum - 1;
				qpc->alt_addr_path.sched_q =
				    HERMON_QP_SCHEDQ_GET(portnum - 1,
				    adds_vect->av_srvl, qp->qp_is_special);
			} else {
				return (IBT_HCA_PORT_INVALID);
			}

			/*
			 * Check for valid alternate path PKey index and fill
			 * it in
			 */
			pkeyindx = uc->uc_alt_path.cep_pkey_ix;
			if (hermon_pkeyindex_is_valid(state, pkeyindx)) {
				qpc->alt_addr_path.pkey_indx = pkeyindx;
			} else {
				return (IBT_PKEY_IX_ILLEGAL);
			}
			opmask |= HERMON_CMD_OP_ALT_PATH;
		}
	} else {
		/*
		 * Invalid QP transport type. If we got here then it's a
		 * warning of a probably serious problem.  So print a message
		 * and return failure
		 */
		HERMON_WARNING(state, "unknown QP transport type in sqd2sqd");
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Post the SQD2SQD_QP command to the Hermon firmware
	 *
	 * We do a HERMON_NOSLEEP here because we are still holding the
	 * "qp_lock".  If we got raised to interrupt level by priority
	 * inversion, we do not want to block in this routine waiting for
	 * success.
	 */
	status = hermon_cmn_qp_cmd_post(state, SQD2SQD_QP, qpc, qp->qp_qpnum,
	    opmask, HERMON_CMD_NOSLEEP_SPIN);
	if (status != HERMON_CMD_SUCCESS) {
		if (status != HERMON_CMD_BAD_QP_STATE) {
			cmn_err(CE_NOTE, "hermon%d: SQD2SQD_QP command failed: "
			    "%08x\n", state->hs_instance, status);
			if (status == HERMON_CMD_INVALID_STATUS) {
				hermon_fm_ereport(state, HCA_SYS_ERR,
				    HCA_ERR_SRV_LOST);
			}
			return (ibc_get_ci_failure(0));
		} else {
			return (IBT_QP_STATE_INVALID);
		}
	}

	return (DDI_SUCCESS);
}


/*
 * hermon_qp_sqerr2rts()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_qp_sqerr2rts(hermon_state_t *state, hermon_qphdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p)
{
	hermon_hw_qpc_t		*qpc;
	ibt_qp_ud_attr_t	*ud;
	uint32_t		opmask = 0;
	int			status;

	ASSERT(MUTEX_HELD(&qp->qp_lock));

	/*
	 * Grab the temporary QPC entry from QP software state
	 */
	qpc = &qp->qpc;

	/*
	 * Since there are no common fields to be filled in for this command,
	 * we begin with the QPC fields which are specific to transport type.
	 */
	if (qp->qp_type == IBT_UD_RQP) {
		ud = &info_p->qp_transport.ud;

		/*
		 * If we are attempting to modify the QKey for this QP, then
		 * fill it in and set the appropriate flag in the "opmask"
		 * parameter.
		 */
		if (flags & IBT_CEP_SET_QKEY) {
			qpc->qkey = ud->ud_qkey;
			opmask |= HERMON_CMD_OP_QKEY;
		}

	} else if (qp->qp_serv_type == HERMON_QP_UC) {

		/*
		 * Check if any of the flags indicate a change in the RDMA
		 * Write (recv) enable/disable and set the appropriate flag
		 * in the "opmask" parameter. Note: RDMA Read and Atomic are
		 * not valid for UC transport.
		 */
		if (flags & IBT_CEP_SET_RDMA_W) {
			qpc->rwe = (info_p->qp_flags & IBT_CEP_RDMA_WR) ? 1 : 0;
			opmask |= HERMON_CMD_OP_RWE;
		}
	} else {
		/*
		 * Invalid QP transport type. If we got here then it's a
		 * warning of a probably serious problem.  So print a message
		 * and return failure
		 */
		HERMON_WARNING(state, "unknown QP transport type in sqerr2rts");
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Post the SQERR2RTS_QP command to the Hermon firmware
	 *
	 * We do a HERMON_NOSLEEP here because we are still holding the
	 * "qp_lock".  If we got raised to interrupt level by priority
	 * inversion, we do not want to block in this routine waiting for
	 * success.
	 */
	status = hermon_cmn_qp_cmd_post(state, SQERR2RTS_QP, qpc, qp->qp_qpnum,
	    opmask, HERMON_CMD_NOSLEEP_SPIN);
	if (status != HERMON_CMD_SUCCESS) {
		if (status != HERMON_CMD_BAD_QP_STATE) {
			cmn_err(CE_NOTE, "hermon%d: SQERR2RTS_QP command "
			    "failed: %08x\n", state->hs_instance, status);
			if (status == HERMON_CMD_INVALID_STATUS) {
				hermon_fm_ereport(state, HCA_SYS_ERR,
				    HCA_ERR_SRV_LOST);
			}
			return (ibc_get_ci_failure(0));
		} else {
			return (IBT_QP_STATE_INVALID);
		}
	}

	return (DDI_SUCCESS);
}


/*
 * hermon_qp_to_error()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_qp_to_error(hermon_state_t *state, hermon_qphdl_t qp)
{
	int	status;

	ASSERT(MUTEX_HELD(&qp->qp_lock));

	/*
	 * Post the TOERR_QP command to the Hermon firmware
	 *
	 * We do a HERMON_NOSLEEP here because we are still holding the
	 * "qp_lock".  If we got raised to interrupt level by priority
	 * inversion, we do not want to block in this routine waiting for
	 * success.
	 */
	status = hermon_cmn_qp_cmd_post(state, TOERR_QP, NULL, qp->qp_qpnum,
	    0, HERMON_CMD_NOSLEEP_SPIN);
	if (status != HERMON_CMD_SUCCESS) {
		cmn_err(CE_NOTE, "hermon%d: TOERR_QP command failed: %08x\n",
		    state->hs_instance, status);
		if (status == HERMON_CMD_INVALID_STATUS) {
			hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_SRV_LOST);
		}
		return (ibc_get_ci_failure(0));
	}

	return (DDI_SUCCESS);
}


/*
 * hermon_qp_to_reset()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_qp_to_reset(hermon_state_t *state, hermon_qphdl_t qp)
{
	hermon_hw_qpc_t	*qpc;
	int		status;

	ASSERT(MUTEX_HELD(&qp->qp_lock));

	/*
	 * Grab the temporary QPC entry from QP software state
	 */
	qpc = &qp->qpc;

	/*
	 * Post the TORST_QP command to the Hermon firmware
	 *
	 * We do a HERMON_NOSLEEP here because we are still holding the
	 * "qp_lock".  If we got raised to interrupt level by priority
	 * inversion, we do not want to block in this routine waiting for
	 * success.
	 */
	status = hermon_cmn_qp_cmd_post(state, TORST_QP, qpc, qp->qp_qpnum,
	    0, HERMON_CMD_NOSLEEP_SPIN);
	if (status != HERMON_CMD_SUCCESS) {
		cmn_err(CE_NOTE, "hermon%d: TORST_QP command failed: %08x\n",
		    state->hs_instance, status);
		if (status == HERMON_CMD_INVALID_STATUS) {
			hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_SRV_LOST);
		}
		return (ibc_get_ci_failure(0));
	}
	if (qp->qp_serv_type == HERMON_QP_FEXCH) {
		status = hermon_fcoib_fexch_mkey_fini(state, qp->qp_pdhdl,
		    qp->qp_qpnum, HERMON_CMD_NOSLEEP_SPIN);
		if (status != DDI_SUCCESS)
			cmn_err(CE_NOTE, "hermon%d: fexch_mkey_fini failed "
			    "%08x\n", state->hs_instance, status);
	}
	return (DDI_SUCCESS);
}


/*
 * hermon_qp_reset2err()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_qp_reset2err(hermon_state_t *state, hermon_qphdl_t qp)
{
	hermon_hw_qpc_t	*qpc;
	int		status;
	uint32_t	cqnmask;

	ASSERT(MUTEX_HELD(&qp->qp_lock));

	/*
	 * In order to implement the transition from "Reset" directly to the
	 * "Error" state, it is necessary to first give ownership of the QP
	 * context to the Hermon hardware.  This is accomplished by
	 * transitioning the QP to "Init" as an intermediate step and then,
	 * immediately transitioning to "Error".
	 *
	 * When this function returns success, the QP context will be owned by
	 * the Hermon hardware and will be in the "Error" state.
	 */

	/*
	 * Grab the temporary QPC entry from QP software state
	 */
	qpc = &qp->qpc;

	/*
	 * Fill in the common fields in the QPC
	 */
	if (qp->qp_is_special) {
		qpc->serv_type	= HERMON_QP_MLX;
	} else {
		qpc->serv_type	= qp->qp_serv_type;
	}
	qpc->pm_state		= HERMON_QP_PMSTATE_MIGRATED;
	qpc->usr_page		= qp->qp_uarpg;
	/* dbr is now an address, not an index */
	qpc->dbr_addrh		= ((uint64_t)qp->qp_rq_pdbr >> 32);
	qpc->dbr_addrl		= ((uint64_t)qp->qp_rq_pdbr & 0xFFFFFFFC) >> 2;
	qpc->pd			= qp->qp_pdhdl->pd_pdnum;
	/*
	 * HERMON:
	 * qpc->wqe_baseaddr is replaced by LKey from the cMPT, and
	 * page_offset, mtt_base_addr_h/l, and log2_page_size will
	 * be used to map the WQE buffer
	 * NOTE that the cMPT is created implicitly when the QP is
	 * transitioned from reset to init
	 */
	qpc->log2_pgsz		= qp->qp_mrhdl->mr_log2_pgsz;
	qpc->mtt_base_addrh	= (qp->qp_mrhdl->mr_mttaddr) >> 32 & 0xFF;
	qpc->mtt_base_addrl	= (qp->qp_mrhdl->mr_mttaddr) >> 3 & 0xFFFFFFFF;
	cqnmask = (1 << state->hs_cfg_profile->cp_log_num_cq) - 1;
	qpc->cqn_snd		=
	    (qp->qp_sq_cqhdl == NULL) ? 0 : qp->qp_sq_cqhdl->cq_cqnum & cqnmask;
	qpc->page_offs		= qp->qp_wqinfo.qa_pgoffs >> 6;
	qpc->cqn_rcv		=
	    (qp->qp_rq_cqhdl == NULL) ? 0 : qp->qp_rq_cqhdl->cq_cqnum & cqnmask;

	qpc->sq_wqe_counter	= 0;
	qpc->rq_wqe_counter	= 0;
	qpc->log_sq_stride	= qp->qp_sq_log_wqesz - 4;
	qpc->log_rq_stride	= qp->qp_rq_log_wqesz - 4;
	qpc->log_sq_size	= highbit(qp->qp_sq_bufsz) - 1;
	qpc->log_rq_size	= highbit(qp->qp_rq_bufsz) - 1;
	qpc->srq_en		= (qp->qp_alloc_flags & IBT_QP_USES_SRQ) != 0;
	qpc->sq_no_prefetch	= qp->qp_no_prefetch;

	if (qp->qp_alloc_flags & IBT_QP_USES_SRQ) {
		qpc->srq_number	= qp->qp_srqhdl->srq_srqnum;
	} else {
		qpc->srq_number = 0;
	}

	qpc->fre		= 0; /* default disable fast registration WR */
	qpc->rlky		= 0; /* default disable reserved lkey */

	/*
	 * Now fill in the QPC fields which are specific to transport type
	 */
	if (qp->qp_type == IBT_UD_RQP) {
		/* Set the UD parameters to an invalid default */
		qpc->qkey = 0;
		qpc->pri_addr_path.sched_q =
		    HERMON_QP_SCHEDQ_GET(0, 0, qp->qp_is_special);
		qpc->pri_addr_path.pkey_indx = 0;

	} else if (qp->qp_serv_type == HERMON_QP_RC) {
		/* Set the RC parameters to invalid default */
		qpc->rre = 0;
		qpc->rwe = 0;
		qpc->rae = 0;
		qpc->alt_addr_path.sched_q =
		    HERMON_QP_SCHEDQ_GET(0, 0, qp->qp_is_special);
		qpc->pri_addr_path.pkey_indx = 0;

	} else if (qp->qp_serv_type == HERMON_QP_UC) {
		/* Set the UC parameters to invalid default */
		qpc->rwe = 0;
		qpc->alt_addr_path.sched_q =
		    HERMON_QP_SCHEDQ_GET(0, 0, qp->qp_is_special);
		qpc->pri_addr_path.pkey_indx = 0;

	} else {
		/*
		 * Invalid QP transport type. If we got here then it's a
		 * warning of a probably serious problem.  So print a message
		 * and return failure
		 */
		HERMON_WARNING(state, "unknown QP transport type in rst2err");
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Post the RST2INIT_QP command to the Hermon firmware
	 *
	 * We do a HERMON_NOSLEEP here because we are still holding the
	 * "qp_lock".  If we got raised to interrupt level by priority
	 * inversion, we do not want to block in this routine waiting for
	 * success.
	 */
	status = hermon_cmn_qp_cmd_post(state, RST2INIT_QP, qpc, qp->qp_qpnum,
	    0, HERMON_CMD_NOSLEEP_SPIN);
	if (status != HERMON_CMD_SUCCESS) {
		cmn_err(CE_NOTE, "hermon%d: RST2INIT_QP command failed: %08x\n",
		    state->hs_instance, status);
		if (status == HERMON_CMD_INVALID_STATUS) {
			hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_SRV_LOST);
		}
		return (ibc_get_ci_failure(0));
	}

	/*
	 * Now post the TOERR_QP command to the Hermon firmware
	 *
	 * We still do a HERMON_NOSLEEP here because we are still holding the
	 * "qp_lock".  Note:  If this fails (which it really never should),
	 * it indicates a serious problem in the HW or SW.  We try to move
	 * the QP back to the "Reset" state if possible and print a warning
	 * message if not.  In any case, we return an error here.
	 */
	status = hermon_cmn_qp_cmd_post(state, TOERR_QP, NULL, qp->qp_qpnum,
	    0, HERMON_CMD_NOSLEEP_SPIN);
	if (status != HERMON_CMD_SUCCESS) {
		cmn_err(CE_NOTE, "hermon%d: TOERR_QP command failed: %08x\n",
		    state->hs_instance, status);
		if (status == HERMON_CMD_INVALID_STATUS) {
			hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_SRV_LOST);
		}
		if (hermon_qp_to_reset(state, qp) != DDI_SUCCESS) {
			HERMON_WARNING(state, "failed to reset QP context");
		}
		return (ibc_get_ci_failure(0));
	}

	return (DDI_SUCCESS);
}


/*
 * hermon_check_rdma_enable_flags()
 *    Context: Can be called from interrupt or base context.
 */
static uint_t
hermon_check_rdma_enable_flags(ibt_cep_modify_flags_t flags,
    ibt_qp_info_t *info_p, hermon_hw_qpc_t *qpc)
{
	uint_t	opmask = 0;

	if (flags & IBT_CEP_SET_RDMA_R) {
		qpc->rre = (info_p->qp_flags & IBT_CEP_RDMA_RD) ? 1 : 0;
		opmask |= HERMON_CMD_OP_RRE;
	}

	if (flags & IBT_CEP_SET_RDMA_W) {
		qpc->rwe = (info_p->qp_flags & IBT_CEP_RDMA_WR) ? 1 : 0;
		opmask |= HERMON_CMD_OP_RWE;
	}

	if (flags & IBT_CEP_SET_ATOMIC) {
		qpc->rae = (info_p->qp_flags & IBT_CEP_ATOMIC) ? 1 : 0;
		opmask |= HERMON_CMD_OP_RAE;
	}

	return (opmask);
}

/*
 * hermon_qp_validate_resp_rsrc()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_qp_validate_resp_rsrc(hermon_state_t *state, ibt_qp_rc_attr_t *rc,
    uint_t *rra_max)
{
	uint_t	rdma_ra_in;

	rdma_ra_in = rc->rc_rdma_ra_in;

	/*
	 * Check if number of responder resources is too large.  Return an
	 * error if it is
	 */
	if (rdma_ra_in > state->hs_cfg_profile->cp_hca_max_rdma_in_qp) {
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
 * hermon_qp_validate_init_depth()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_qp_validate_init_depth(hermon_state_t *state, ibt_qp_rc_attr_t *rc,
    uint_t *sra_max)
{
	uint_t	rdma_ra_out;

	rdma_ra_out = rc->rc_rdma_ra_out;

	/*
	 * Check if requested initiator depth is too large.  Return an error
	 * if it is
	 */
	if (rdma_ra_out > state->hs_cfg_profile->cp_hca_max_rdma_out_qp) {
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
 * hermon_qp_validate_mtu()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_qp_validate_mtu(hermon_state_t *state, uint_t mtu)
{
	/*
	 * Check for invalid MTU values (i.e. zero or any value larger than
	 * the HCA's port maximum).
	 */
	if ((mtu == 0) || (mtu > state->hs_cfg_profile->cp_max_mtu)) {
		return (IBT_HCA_PORT_MTU_EXCEEDED);
	}
	return (DDI_SUCCESS);
}
