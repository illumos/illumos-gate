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

/*
 * hci1394_ixl_update.c
 *    Isochronous IXL update routines.
 *    Routines used to dynamically update a compiled and presumably running
 *    IXL program.
 */

#include <sys/kmem.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/disp.h>

#include <sys/tnf_probe.h>

#include <sys/1394/h1394.h>
#include <sys/1394/ixl1394.h>	/* IXL opcodes & data structs */

#include <sys/1394/adapters/hci1394.h>


/* local defines for hci1394_ixl_update_prepare return codes */
#define	IXL_PREP_READY	    1
#define	IXL_PREP_SUCCESS    0
#define	IXL_PREP_FAILURE    (-1)

/*
 * variable used to indicate the number of times update will wait for
 * interrupt routine to complete.
 */
int hci1394_upd_retries_before_fail = 50;

/* IXL runtime update static functions */
static int hci1394_ixl_update_prepare(hci1394_ixl_update_vars_t *uvp);
static int hci1394_ixl_update_prep_jump(hci1394_ixl_update_vars_t *uvp);
static int hci1394_ixl_update_prep_set_skipmode(hci1394_ixl_update_vars_t *uvp);
static int hci1394_ixl_update_prep_set_tagsync(hci1394_ixl_update_vars_t *uvp);
static int hci1394_ixl_update_prep_recv_pkt(hci1394_ixl_update_vars_t *uvp);
static int hci1394_ixl_update_prep_recv_buf(hci1394_ixl_update_vars_t *uvp);
static int hci1394_ixl_update_prep_send_pkt(hci1394_ixl_update_vars_t *uvp);
static int hci1394_ixl_update_prep_send_buf(hci1394_ixl_update_vars_t *uvp);
static int hci1394_ixl_update_perform(hci1394_ixl_update_vars_t *uvp);
static int hci1394_ixl_update_evaluate(hci1394_ixl_update_vars_t *uvp);
static int hci1394_ixl_update_analysis(hci1394_ixl_update_vars_t *uvp);
static void hci1394_ixl_update_set_locn_info(hci1394_ixl_update_vars_t *uvp);
static int hci1394_ixl_update_enable(hci1394_ixl_update_vars_t *uvp);
static int hci1394_ixl_update_endup(hci1394_ixl_update_vars_t *uvp);

/*
 *	IXL commands and included fields which can be updated
 * IXL1394_OP_CALLBACK:		callback(), callback_data
 * IXL1394_OP_JUMP:		label
 * IXL1394_OP_RECV_PKT		ixl_buf, size, mem_bufp
 * IXL1394_OP_RECV_PKT_ST	ixl_buf, size, mem_bufp
 * IXL1394_OP_RECV_BUF(ppb)	ixl_buf, size, pkt_size, mem_bufp, buf_offset
 * IXL1394_OP_RECV_BUF(fill)	ixl_buf, size, pkt_size, mem_bufp, buf_offset
 * IXL1394_OP_SEND_PKT		ixl_buf, size, mem_bufp
 * IXL1394_OP_SEND_PKT_ST	ixl_buf, size, mem_bufp
 * IXL1394_OP_SEND_PKT_WHDR_ST	ixl_buf, size, mem_bufp
 * IXL1394_OP_SEND_BUF		ixl_buf, size, pkt_size, mem_bufp, buf_offset
 * IXL1394_OP_SET_TAGSYNC	tag, sync
 * IXL1394_OP_SET_SKIPMODE	skipmode, label
 *
 *	IXL commands which can not be updated
 * IXL1394_OP_LABEL
 * IXL1394_OP_SEND_HDR_ONLY
 * IXL1394_OP_SEND_NOPKT
 * IXL1394_OP_STORE_VALUE
 * IXL1394_OP_STORE_TIMESTAMP
 * IXL1394_OP_SET_SYNCWAIT
 */

/*
 * hci1394_ixl_update
 *    main entrypoint into dynamic update code: initializes temporary
 *    update variables, evaluates request, coordinates with potentially
 *    simultaneous run of interrupt stack, evaluates likelyhood of success,
 *    performs the update, checks if completed, performs cleanup
 *    resulting from coordination with interrupt stack.
 */
int
hci1394_ixl_update(hci1394_state_t *soft_statep, hci1394_iso_ctxt_t *ctxtp,
    ixl1394_command_t *ixlnewp, ixl1394_command_t *ixloldp,
    uint_t riskoverride, int *resultp)
{
	hci1394_ixl_update_vars_t uv;	/* update work variables structure */
	int prepstatus;
	int ret;

	TNF_PROBE_0_DEBUG(hci1394_ixl_update_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");


	/* save caller specified values in update work variables structure */
	uv.soft_statep = soft_statep;
	uv.ctxtp = ctxtp;
	uv.ixlnewp = ixlnewp;
	uv.ixloldp = ixloldp;
	uv.risklevel = riskoverride;

	/* initialize remainder of update work variables */
	uv.ixlxferp = NULL;
	uv.skipxferp = NULL;
	uv.skipmode = 0;
	uv.skipaddr = 0;
	uv.jumpaddr = 0;
	uv.pkthdr1 = 0;
	uv.pkthdr2 = 0;
	uv.bufaddr = 0;
	uv.bufsize = 0;
	uv.ixl_opcode = uv.ixlnewp->ixl_opcode;
	uv.hcihdr = 0;
	uv.hcistatus = 0;
	uv.hci_offset = 0;
	uv.hdr_offset = 0;

	/* set done ok return status */
	uv.upd_status = 0;

	/* evaluate request and prepare to perform update */
	prepstatus = hci1394_ixl_update_prepare(&uv);
	if (prepstatus != IXL_PREP_READY) {
		/*
		 * if either done or nothing to do or an evaluation error,
		 * return update status
		 */
		*resultp = uv.upd_status;

		/* if prep evaluation error, return failure */
		if (prepstatus != IXL_PREP_SUCCESS) {
			TNF_PROBE_1_DEBUG(hci1394_ixl_update_error,
			    HCI1394_TNF_HAL_ERROR_ISOCH, "", tnf_string, msg,
			    "IXL_PREP_FAILURE");
			TNF_PROBE_0_DEBUG(hci1394_ixl_update_exit,
			    HCI1394_TNF_HAL_STACK_ISOCH, "");
			return (DDI_FAILURE);
		}
		/* if no action or update done, return update successful */
		TNF_PROBE_0_DEBUG(hci1394_ixl_update_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (DDI_SUCCESS);
	}

	/* perform update processing reservation of interrupt context */
	ret = hci1394_ixl_update_enable(&uv);
	if (ret != DDI_SUCCESS) {

		/* error acquiring control of context - return */
		*resultp = uv.upd_status;

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (DDI_FAILURE);
	}

	/* perform update risk analysis */
	if (hci1394_ixl_update_analysis(&uv) != DDI_SUCCESS) {
		/*
		 * return, if excessive risk or dma execution processing lost
		 * (note: caller risk override not yet implemented)
		 */

		/* attempt intr processing cleanup, unless err is dmalost */
		if (uv.upd_status != IXL1394_EPRE_UPD_DMALOST) {
			(void) hci1394_ixl_update_endup(&uv);
		} else {
			/*
			 * error is dmalost, just release interrupt context.
			 * take the lock here to ensure an atomic read, modify,
			 * write of the "intr_flags" field while we try to
			 * clear the "in update" flag.  protects from the
			 * interrupt routine.
			 */
			mutex_enter(&ctxtp->intrprocmutex);
			ctxtp->intr_flags &= ~HCI1394_ISO_CTXT_INUPDATE;
			mutex_exit(&ctxtp->intrprocmutex);
		}
		*resultp = uv.upd_status;

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (DDI_FAILURE);
	}


	/* perform requested update */
	if (hci1394_ixl_update_perform(&uv) != DDI_SUCCESS) {
		/*
		 * if non-completion condition, return update status
		 * attempt interrupt processing cleanup first
		 */
		(void) hci1394_ixl_update_endup(&uv);

		*resultp = uv.upd_status;

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (DDI_FAILURE);
	}

	/* evaluate update completion, setting completion status */
	if (hci1394_ixl_update_evaluate(&uv) != DDI_SUCCESS) {
		/*
		 * update failed - bad, just release interrupt context
		 * take the lock here too (jsut like above) to ensure an
		 * atomic read, modify, write of the "intr_flags" field
		 * while we try to clear the "in update" flag.  protects
		 * from the interrupt routine.
		 */
		mutex_enter(&ctxtp->intrprocmutex);
		ctxtp->intr_flags &= ~HCI1394_ISO_CTXT_INUPDATE;
		mutex_exit(&ctxtp->intrprocmutex);

		/* if DMA stopped or lost, formally stop context */
		if (uv.upd_status == HCI1394_IXL_INTR_DMASTOP) {
			hci1394_do_stop(soft_statep, ctxtp, B_TRUE,
			    ID1394_DONE);
		} else if (uv.upd_status == HCI1394_IXL_INTR_DMALOST) {
			hci1394_do_stop(soft_statep, ctxtp, B_TRUE,
			    ID1394_FAIL);
		}

		*resultp = uv.upd_status;

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (DDI_FAILURE);
	}

	/* perform interrupt processing cleanup */
	uv.upd_status = hci1394_ixl_update_endup(&uv);

	/* return update completion status */
	*resultp = uv.upd_status;

	TNF_PROBE_0_DEBUG(hci1394_ixl_update_exit, HCI1394_TNF_HAL_STACK_ISOCH,
	    "");
	return (DDI_SUCCESS);
}

/*
 * hci1394_ixl_update_enable
 *	Used to coordinate dynamic update activities with simultaneous
 *	interrupt handler processing, while holding the context mutex
 *      for as short a time as possible.
 */
static int
hci1394_ixl_update_enable(hci1394_ixl_update_vars_t *uvp)
{
	int	status;
	boolean_t retry;
	uint_t	remretries;

	TNF_PROBE_0_DEBUG(hci1394_ixl_update_enable_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	retry = B_TRUE;
	/* set arbitrary number of retries before giving up */
	remretries = hci1394_upd_retries_before_fail;
	status = DDI_SUCCESS;

	/*
	 * if waited for completion of interrupt processing generated callback,
	 * retry here
	 */
	ASSERT(MUTEX_NOT_HELD(&uvp->ctxtp->intrprocmutex));
	mutex_enter(&uvp->ctxtp->intrprocmutex);

	while (retry == B_TRUE) {
		retry = B_FALSE;
		remretries--;

		/* failure if update processing is already in progress */
		if (uvp->ctxtp->intr_flags & HCI1394_ISO_CTXT_INUPDATE) {
			uvp->upd_status = IXL1394_EUPDATE_DISALLOWED;
			status = DDI_FAILURE;
		} else if (uvp->ctxtp->intr_flags & HCI1394_ISO_CTXT_ININTR) {
			/*
			 * if have retried max number of times or if this update
			 * request is on the interrupt stack, which means that
			 * the callback function of the target driver initiated
			 * the update, set update failure.
			 */
			if ((remretries <= 0) ||
			    (servicing_interrupt())) {
				uvp->upd_status = IXL1394_EUPDATE_DISALLOWED;
				status = DDI_FAILURE;
			} else {
				/*
				 * if not on interrupt stack and retries not
				 * exhausted, free mutex, wait a short time
				 * and then retry.
				 */
				retry = B_TRUE;
				mutex_exit(&uvp->ctxtp->intrprocmutex);
				drv_usecwait(1);
				mutex_enter(&uvp->ctxtp->intrprocmutex);
				continue;
			}
		} else if (uvp->ctxtp->intr_flags & HCI1394_ISO_CTXT_INCALL) {
			uvp->upd_status = IXL1394_EINTERNAL_ERROR;
			status = DDI_FAILURE;
		}
	}

	/* if context is available, reserve it for this update request */
	if (status == DDI_SUCCESS) {
		uvp->ctxtp->intr_flags |= HCI1394_ISO_CTXT_INUPDATE;
	}

	ASSERT(MUTEX_HELD(&uvp->ctxtp->intrprocmutex));
	mutex_exit(&uvp->ctxtp->intrprocmutex);

	TNF_PROBE_0_DEBUG(hci1394_ixl_update_enable_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
	return (status);
}

/*
 * hci1394_ixl_update_endup()
 *    The ending stage of coordinating with simultaneously running interrupts.
 *    Perform interrupt processing sync tasks if we (update) had blocked the
 *    interrupt out when it wanted a turn.
 */
static int
hci1394_ixl_update_endup(hci1394_ixl_update_vars_t *uvp)
{
	uint_t status;
	hci1394_iso_ctxt_t *ctxtp;

	TNF_PROBE_0_DEBUG(hci1394_ixl_update_endup_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	status = HCI1394_IXL_INTR_NOERROR;
	ctxtp = uvp->ctxtp;

	while (ctxtp->intr_flags & HCI1394_ISO_CTXT_INUPDATE) {

		if (ctxtp->intr_flags & HCI1394_ISO_CTXT_INTRSET) {
			/*
			 * We don't need to grab the lock here because
			 * the "intr_flags" field is only modified in two
			 * ways - one in UPDATE and one in INTR routine. Since
			 * we know that it can't be modified simulataneously
			 * in another UDPATE thread - that is assured by the
			 * checks in "update_enable" - we would only be trying
			 * to protect against the INTR thread.  And since we
			 * are going to clear a bit here (and check it again
			 * at the top of the loop) we are not really concerned
			 * about missing its being set by the INTR routine.
			 */
			ctxtp->intr_flags &= ~HCI1394_ISO_CTXT_INTRSET;

			status = hci1394_ixl_dma_sync(uvp->soft_statep, ctxtp);
			if (status ==  HCI1394_IXL_INTR_DMALOST) {
				/*
				 * Unlike above, we do care here as we are
				 * trying to clear the "in update" flag, and
				 * we don't want that lost because the INTR
				 * routine is trying to set its flag.
				 */
				mutex_enter(&uvp->ctxtp->intrprocmutex);
				ctxtp->intr_flags &= ~HCI1394_ISO_CTXT_INUPDATE;
				mutex_exit(&uvp->ctxtp->intrprocmutex);
				continue;
			}
		}

		ASSERT(MUTEX_NOT_HELD(&uvp->ctxtp->intrprocmutex));
		mutex_enter(&uvp->ctxtp->intrprocmutex);
		if (!(ctxtp->intr_flags & HCI1394_ISO_CTXT_INTRSET)) {
			ctxtp->intr_flags &= ~HCI1394_ISO_CTXT_INUPDATE;
		}
		mutex_exit(&uvp->ctxtp->intrprocmutex);
	}

	/* if DMA stopped or lost, formally stop context */
	if (status == HCI1394_IXL_INTR_DMASTOP) {
		hci1394_do_stop(uvp->soft_statep, ctxtp, B_TRUE, ID1394_DONE);
	} else if (status == HCI1394_IXL_INTR_DMALOST) {
		hci1394_do_stop(uvp->soft_statep, ctxtp, B_TRUE, ID1394_FAIL);
	}

	TNF_PROBE_0_DEBUG(hci1394_ixl_update_endup_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
	return (status);
}

/*
 * hci1394_ixl_update_prepare()
 *    Preparation for the actual update (using temp uvp struct)
 */
static int
hci1394_ixl_update_prepare(hci1394_ixl_update_vars_t *uvp)
{
	int		    ret;

	TNF_PROBE_0_DEBUG(hci1394_ixl_update_prepare_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	/* both new and old ixl commands must be the same */
	if (uvp->ixlnewp->ixl_opcode != uvp->ixloldp->ixl_opcode) {

		uvp->upd_status = IXL1394_EOPCODE_MISMATCH;

		TNF_PROBE_1_DEBUG(hci1394_ixl_update_prepare_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "", tnf_string, msg,
		    "EOPCODE_MISMATCH");
		return (IXL_PREP_FAILURE);
	}

	/*
	 * perform evaluation and prepare update based on specific
	 * IXL command type
	 */
	switch (uvp->ixl_opcode) {

	case IXL1394_OP_CALLBACK_U: {
		ixl1394_callback_t *old_callback_ixlp;
		ixl1394_callback_t *new_callback_ixlp;

		old_callback_ixlp = (ixl1394_callback_t *)uvp->ixloldp;
		new_callback_ixlp = (ixl1394_callback_t *)uvp->ixlnewp;

		/* perform update now without further evaluation */
		old_callback_ixlp->callback_arg =
		    new_callback_ixlp->callback_arg;
		old_callback_ixlp->callback = new_callback_ixlp->callback;

		/* nothing else to do, return with done ok status */
		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prepare_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (IXL_PREP_SUCCESS);
	}

	case IXL1394_OP_JUMP_U:
		ret = hci1394_ixl_update_prep_jump(uvp);

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prepare_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (ret);

	case IXL1394_OP_SET_SKIPMODE_U:
		ret = hci1394_ixl_update_prep_set_skipmode(uvp);

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prepare_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (ret);

	case IXL1394_OP_SET_TAGSYNC_U:
		ret = hci1394_ixl_update_prep_set_tagsync(uvp);

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prepare_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (ret);

	case IXL1394_OP_RECV_PKT_U:
	case IXL1394_OP_RECV_PKT_ST_U:
		ret = hci1394_ixl_update_prep_recv_pkt(uvp);

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prepare_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (ret);

	case IXL1394_OP_RECV_BUF_U:
		ret = hci1394_ixl_update_prep_recv_buf(uvp);

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prepare_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (ret);

	case IXL1394_OP_SEND_PKT_U:
	case IXL1394_OP_SEND_PKT_ST_U:
	case IXL1394_OP_SEND_PKT_WHDR_ST_U:
		ret = hci1394_ixl_update_prep_send_pkt(uvp);

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prepare_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (ret);

	case IXL1394_OP_SEND_BUF_U:
		ret = hci1394_ixl_update_prep_send_buf(uvp);

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prepare_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (ret);

	default:
		/* ixl command being updated must be one of above, else error */
		uvp->upd_status = IXL1394_EOPCODE_DISALLOWED;

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prepare_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (IXL_PREP_FAILURE);
	}
}

/*
 * hci1394_ixl_update_prep_jump()
 *    Preparation for update of an IXL1394_OP_JUMP_U command.
 */
static int
hci1394_ixl_update_prep_jump(hci1394_ixl_update_vars_t *uvp)
{
	ixl1394_jump_t	    *old_jump_ixlp;
	ixl1394_jump_t	    *new_jump_ixlp;
	ixl1394_command_t   *ixlp;
	hci1394_xfer_ctl_t  *xferctlp;
	hci1394_desc_t	    *hcidescp;
	uint_t		    cbcnt;
	ddi_acc_handle_t    acc_hdl;
	ddi_dma_handle_t    dma_hdl;
	uint32_t	    desc_hdr;
	int		    err;

	TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_jump_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	old_jump_ixlp = (ixl1394_jump_t *)uvp->ixloldp;
	new_jump_ixlp = (ixl1394_jump_t *)uvp->ixlnewp;

	/* check if any change between new and old ixl jump command */
	if (new_jump_ixlp->label == old_jump_ixlp->label) {

		/* if none, return with done ok status */
		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_jump_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (IXL_PREP_SUCCESS);
	}

	/* new ixl jump command label must be ptr to valid ixl label or NULL */
	if ((new_jump_ixlp->label != NULL) &&
	    (new_jump_ixlp->label->ixl_opcode != IXL1394_OP_LABEL)) {

		/* if not jumping to label, return an error */
		uvp->upd_status = IXL1394_EJUMP_NOT_TO_LABEL;

		TNF_PROBE_1_DEBUG(hci1394_ixl_update_prepare_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "", tnf_string, errmsg,
		    "EJUMP_NOT_TO_LABEL");
		return (IXL_PREP_FAILURE);
	}

	/*
	 * follow exec path from new ixl jump command label to determine new
	 * jump destination ixl xfer command
	 */
	(void) hci1394_ixl_find_next_exec_xfer(new_jump_ixlp->label, &cbcnt,
	    &ixlp);
	if (ixlp != NULL) {
		/*
		 * get the bound address of the first descriptor block reached
		 * by the jump destination.  (This descriptor is the first
		 * transfer command following the jumped-to label.)  Set the
		 * descriptor's address (with Z bits) into jumpaddr.
		 */
		uvp->jumpaddr = ((hci1394_xfer_ctl_t *)
		    ixlp->compiler_privatep)->dma[0].dma_bound;
	}

	/*
	 * get associated xfer IXL command from compiler_privatep of old
	 * jump command
	 */
	if ((uvp->ixlxferp = (ixl1394_command_t *)
	    old_jump_ixlp->compiler_privatep) == NULL) {

		/* if none, return an error */
		uvp->upd_status = IXL1394_EORIG_IXL_CORRUPTED;

		TNF_PROBE_1_DEBUG(hci1394_ixl_update_prep_jump_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "", tnf_string, errmsg,
		    "EORIG_IXL_CORRUPTED");
		return (IXL_PREP_FAILURE);
	}

	/*
	 * get the associated IXL xfer command's last dma descriptor block
	 * last descriptor, then get hcihdr from its hdr field,
	 * removing interrupt enabled bits
	 */
	xferctlp = (hci1394_xfer_ctl_t *)uvp->ixlxferp->compiler_privatep;
	hcidescp = (hci1394_desc_t *)xferctlp->dma[xferctlp->cnt - 1].dma_descp;
	acc_hdl  = xferctlp->dma[xferctlp->cnt - 1].dma_buf->bi_handle;
	dma_hdl  = xferctlp->dma[xferctlp->cnt - 1].dma_buf->bi_dma_handle;

	/* Sync the descriptor before we grab the header(s) */
	err = ddi_dma_sync(dma_hdl, (off_t)hcidescp, sizeof (hci1394_desc_t),
	    DDI_DMA_SYNC_FORCPU);
	if (err != DDI_SUCCESS) {
		uvp->upd_status = IXL1394_EINTERNAL_ERROR;

		TNF_PROBE_1_DEBUG(hci1394_ixl_update_prep_jump_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "", tnf_string, errmsg,
		    "EINTERNAL_ERROR: dma_sync() failed");
		return (IXL_PREP_FAILURE);
	}

	desc_hdr = ddi_get32(acc_hdl, &hcidescp->hdr);
	uvp->hcihdr = desc_hdr & ~DESC_INTR_ENBL;

	/* set depth to last dma descriptor block & update count to 1 */
	uvp->ixldepth = xferctlp->cnt - 1;
	uvp->ixlcount = 1;

	/*
	 * if there is only one dma descriptor block and IXL xfer command
	 * inited by a label or have found callbacks along the exec path to the
	 * new destination IXL xfer command, enable interrupt in hcihdr value
	 */
	if (((xferctlp->cnt == 1) &&
	    ((xferctlp->ctl_flags & XCTL_LABELLED) != 0)) || (cbcnt != 0)) {

		uvp->hcihdr |= DESC_INTR_ENBL;
	}

	/* If either old or new destination was/is NULL, enable interrupt */
	if ((new_jump_ixlp->label == NULL) || (old_jump_ixlp->label == NULL)) {
		uvp->hcihdr |= DESC_INTR_ENBL;
	}

	/*
	 * if xfer type is xmit and skip mode for this for this xfer command is
	 * IXL1394_SKIP_TO_NEXT then set uvp->skipmode to IXL1394_SKIP_TO_NEXT
	 * and set uvp->skipxferp to uvp->jumpaddr and set uvp->hci_offset to
	 * offset from last dma descriptor to first dma descriptor
	 * (where skipaddr goes).
	 *
	 * update perform processing will have to set skip branch address to
	 * same location as jump destination in this case.
	 */
	uvp->skipmode = IXL1394_SKIP_TO_STOP;
	if ((uvp->ixlxferp->ixl_opcode & IXL1394_OPF_ONXMIT) != 0) {

		if ((xferctlp->skipmodep && (((ixl1394_set_skipmode_t *)
		    xferctlp->skipmodep)->skipmode == IXL1394_SKIP_TO_NEXT)) ||
		    (uvp->ctxtp->default_skipmode == IXL1394_OPF_ONXMIT)) {

			uvp->skipmode = IXL1394_SKIP_TO_NEXT;
			uvp->skipaddr = uvp->jumpaddr;

			/*
			 * calc hci_offset to first descriptor (where skipaddr
			 * goes) of dma descriptor block from current (last)
			 * descriptor of the descriptor block (accessed in
			 * xfer_ctl dma_descp of IXL xfer command)
			 */
			if (uvp->ixlxferp->ixl_opcode ==
			    IXL1394_OP_SEND_HDR_ONLY) {
				/*
				 * send header only is (Z bits - 2)
				 * descriptor components back from last one
				 */
				uvp->hci_offset -= 2;
			} else {
				/*
				 * all others are (Z bits - 1) descriptor
				 * components back from last component
				 */
				uvp->hci_offset -= 1;
			}
		}
	}
	TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_jump_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
	return (IXL_PREP_READY);
}

/*
 * hci1394_ixl_update_prep_set_skipmode()
 *    Preparation for update of an IXL1394_OP_SET_SKIPMODE_U command.
 */
static int
hci1394_ixl_update_prep_set_skipmode(hci1394_ixl_update_vars_t *uvp)
{
	ixl1394_set_skipmode_t	*old_set_skipmode_ixlp;
	ixl1394_set_skipmode_t	*new_set_skipmode_ixlp;
	ixl1394_command_t	*ixlp;
	hci1394_xfer_ctl_t	*xferctlp;

	TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_set_skipmode_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	old_set_skipmode_ixlp = (ixl1394_set_skipmode_t *)uvp->ixloldp;
	new_set_skipmode_ixlp = (ixl1394_set_skipmode_t *)uvp->ixlnewp;

	/* check if new set skipmode is change from old set skipmode */
	if (new_set_skipmode_ixlp->skipmode ==
	    old_set_skipmode_ixlp->skipmode) {

		if ((new_set_skipmode_ixlp->skipmode !=
		    IXL1394_SKIP_TO_LABEL) ||
		    (old_set_skipmode_ixlp->label ==
		    new_set_skipmode_ixlp->label)) {

			TNF_PROBE_0_DEBUG(
			    hci1394_ixl_update_prep_set_skipmode_exit,
			    HCI1394_TNF_HAL_STACK_ISOCH, "");

			/* No change, return with done ok status */
			return (IXL_PREP_SUCCESS);
		}
	}

	/* find associated ixl xfer commnd by following old ixl links */
	uvp->ixlxferp = uvp->ixloldp->next_ixlp;
	while ((uvp->ixlxferp != NULL) && (((uvp->ixlxferp->ixl_opcode &
	    IXL1394_OPF_ISXFER) == 0) ||
	    ((uvp->ixlxferp->ixl_opcode & IXL1394_OPTY_MASK) !=	0))) {

		uvp->ixlxferp = uvp->ixlxferp->next_ixlp;
	}

	/* return an error if no ixl xfer command found */
	if (uvp->ixlxferp == NULL) {

		uvp->upd_status = IXL1394_EORIG_IXL_CORRUPTED;

		TNF_PROBE_1_DEBUG(hci1394_ixl_update_prep_set_skipmode_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "", tnf_string,
		    errmsg, "EORIG_IXL_CORRUPTED");
		return (IXL_PREP_FAILURE);
	}

	/*
	 * get Z bits (number of descriptor components in descriptor block)
	 * from a dma bound addr in the xfer_ctl struct of the IXL xfer command
	 */
	if ((xferctlp = (hci1394_xfer_ctl_t *)
	    uvp->ixlxferp->compiler_privatep) == NULL) {

		uvp->upd_status = IXL1394_EORIG_IXL_CORRUPTED;

		TNF_PROBE_1_DEBUG(hci1394_ixl_update_prep_set_skipmode_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "", tnf_string, errmsg,
		    "EORIG_IXL_CORRUPTED");
		return (IXL_PREP_FAILURE);
	}
	uvp->hci_offset = xferctlp->dma[0].dma_bound & DESC_Z_MASK;

	/*
	 * determine hci_offset to first component (where skipaddr goes) of
	 * dma descriptor block from current (last) descriptor component of
	 * desciptor block (accessed in xfer_ctl dma_descp of IXL xfer command)
	 */
	if (uvp->ixlxferp->ixl_opcode == IXL1394_OP_SEND_HDR_ONLY) {
		/*
		 * "send header only" is (Z bits - 2) descriptors back
		 * from last one
		 */
		uvp->hci_offset -= 2;
	} else {
		/*
		 * all others are (Z bits - 1) descroptors back from
		 * last descriptor.
		 */
		uvp->hci_offset -= 1;
	}

	/* set depth to zero and count to update all dma descriptors */
	uvp->ixldepth = 0;
	uvp->ixlcount = xferctlp->cnt;

	/* set new skipmode and validate */
	uvp->skipmode = new_set_skipmode_ixlp->skipmode;

	if ((uvp->skipmode != IXL1394_SKIP_TO_NEXT) &&
	    (uvp->skipmode != IXL1394_SKIP_TO_SELF) &&
	    (uvp->skipmode != IXL1394_SKIP_TO_STOP) &&
	    (uvp->skipmode != IXL1394_SKIP_TO_LABEL)) {

		/* return an error if invalid mode */
		uvp->upd_status = IXL1394_EBAD_SKIPMODE;

		TNF_PROBE_1_DEBUG(hci1394_ixl_update_prep_set_skipmode_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "", tnf_string,
		    errmsg, "EBAD_SKIPMODE");
		return (IXL_PREP_FAILURE);
	}

	/* if mode is skip to label */
	if (uvp->skipmode == IXL1394_SKIP_TO_LABEL) {

		/* verify label field is valid ixl label cmd */
		if ((new_set_skipmode_ixlp->label == NULL) ||
		    (new_set_skipmode_ixlp->label->ixl_opcode !=
		    IXL1394_OP_LABEL)) {

			/* Error - not skipping to valid label */
			uvp->upd_status = IXL1394_EBAD_SKIP_LABEL;

			TNF_PROBE_0_DEBUG(
			    hci1394_ixl_update_prep_set_skipmode_exit,
			    HCI1394_TNF_HAL_STACK_ISOCH, "");
			return (IXL_PREP_FAILURE);
		}

		/*
		 * follow new skip exec path after label to next xfer
		 * IXL command
		 */
		(void) hci1394_ixl_find_next_exec_xfer(
		    new_set_skipmode_ixlp->label, NULL, &ixlp);

		/*
		 * set skip destination IXL xfer command.
		 * after update set into old set skip mode IXL compiler_privatep
		 */
		if ((uvp->skipxferp = ixlp) != NULL) {
			/*
			 * set skipaddr to be the first dma descriptor block's
			 * dma bound address w/Z bits
			 */
			xferctlp = (hci1394_xfer_ctl_t *)
			    ixlp->compiler_privatep;
			uvp->skipaddr = xferctlp->dma[0].dma_bound;
		}
	}

	/*
	 * if mode is skip to next, get skipaddr for last dma descriptor block
	 */
	if (uvp->skipmode == IXL1394_SKIP_TO_NEXT) {
		/* follow normal exec path to next xfer ixl command */
		(void) hci1394_ixl_find_next_exec_xfer(uvp->ixlxferp->next_ixlp,
		    NULL, &ixlp);

		/*
		 * get skip_next destination IXL xfer command
		 * (for last iteration)
		 */
		if (ixlp != NULL) {
			/*
			 * set skipaddr to first dma descriptor block's
			 * dma bound address w/Z bits
			 */
			xferctlp = (hci1394_xfer_ctl_t *)
			    ixlp->compiler_privatep;
			uvp->skipaddr = xferctlp->dma[0].dma_bound;
		}
	}
	TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_set_skipmode_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
	return (IXL_PREP_READY);
}

/*
 * hci1394_ixl_update_prep_set_tagsync()
 *    Preparation for update of an IXL1394_OP_SET_TAGSYNC_U command.
 */
static int
hci1394_ixl_update_prep_set_tagsync(hci1394_ixl_update_vars_t *uvp)
{
	ixl1394_set_tagsync_t	*old_set_tagsync_ixlp;
	ixl1394_set_tagsync_t	*new_set_tagsync_ixlp;
	hci1394_xfer_ctl_t	*xferctlp;

	TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_set_tagsync_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	old_set_tagsync_ixlp = (ixl1394_set_tagsync_t *)uvp->ixloldp;
	new_set_tagsync_ixlp = (ixl1394_set_tagsync_t *)uvp->ixlnewp;

	/* check if new set tagsync is change from old set tagsync. */
	if ((new_set_tagsync_ixlp->tag == old_set_tagsync_ixlp->tag) &&
	    (new_set_tagsync_ixlp->sync == old_set_tagsync_ixlp->sync)) {

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_set_tagsync_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");

		/* no change, return with done ok status */
		return (IXL_PREP_SUCCESS);
	}

	/* find associated IXL xfer commnd by following old ixl links */
	uvp->ixlxferp = uvp->ixloldp->next_ixlp;
	while ((uvp->ixlxferp != NULL) && (((uvp->ixlxferp->ixl_opcode &
	    IXL1394_OPF_ISXFER) == 0) ||
	    ((uvp->ixlxferp->ixl_opcode & IXL1394_OPTY_MASK) != 0))) {

		uvp->ixlxferp = uvp->ixlxferp->next_ixlp;
	}

	/* return an error if no IXL xfer command found */
	if (uvp->ixlxferp == NULL) {

		uvp->upd_status = IXL1394_EORIG_IXL_CORRUPTED;

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_set_tagsync_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (IXL_PREP_FAILURE);
	}

	/* is IXL xfer command an IXL1394_OP_SEND_NO_PKT? */
	if (uvp->ixlxferp->ixl_opcode == IXL1394_OP_SEND_NO_PKT) {
		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_set_tagsync_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");

		/* no update needed, return done ok status */
		return (IXL_PREP_SUCCESS);
	}

	/* build new pkthdr1 from new IXL tag/sync bits */
	uvp->pkthdr1 = (uvp->ctxtp->isospd << DESC_PKT_SPD_SHIFT) |
	    (new_set_tagsync_ixlp->tag << DESC_PKT_TAG_SHIFT) |
	    (uvp->ctxtp->isochan << DESC_PKT_CHAN_SHIFT) |
	    (new_set_tagsync_ixlp->sync << DESC_PKT_SY_SHIFT);

	/*
	 * get Z bits (# of descriptor components in descriptor block) from
	 * any dma bound address in the xfer_ctl struct of the IXL xfer cmd
	 */
	if ((xferctlp =	(hci1394_xfer_ctl_t *)
	    uvp->ixlxferp->compiler_privatep) == NULL) {

		uvp->upd_status = IXL1394_EORIG_IXL_CORRUPTED;

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_set_tagsync_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (IXL_PREP_FAILURE);
	}
	uvp->hdr_offset = xferctlp->dma[0].dma_bound & DESC_Z_MASK;

	/*
	 * determine hdr_offset from the current(last) descriptor of the
	 * DMA descriptor block to the descriptor where pkthdr1 goes
	 * by examining IXL xfer command
	 */
	if (uvp->ixlxferp->ixl_opcode == IXL1394_OP_SEND_HDR_ONLY) {
		/*
		 * if IXL send header only, the current (last)
		 * descriptor is the one
		 */
		uvp->hdr_offset = 0;
	} else {
		/*
		 * all others are the first descriptor (Z bits - 1)
		 * back from the last
		 */
		uvp->hdr_offset -= 1;
	}

	/* set depth to zero and count to update all dma descriptors */
	uvp->ixldepth = 0;
	uvp->ixlcount = xferctlp->cnt;

	TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_set_tagsync_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
	return (IXL_PREP_READY);
}

/*
 * hci1394_ixl_update_prep_recv_pkt()
 *    Preparation for update of an IXL1394_OP_RECV_PKT_U or
 *    IXL1394_OP_RECV_PKT_ST_U command.
 */
static int
hci1394_ixl_update_prep_recv_pkt(hci1394_ixl_update_vars_t *uvp)
{
	ixl1394_xfer_pkt_t *old_xfer_pkt_ixlp;
	ixl1394_xfer_pkt_t *new_xfer_pkt_ixlp;
	hci1394_xfer_ctl_t *xferctlp;
	hci1394_desc_t	   *hcidescp;
	ddi_acc_handle_t   acc_hdl;
	ddi_dma_handle_t   dma_hdl;
	uint32_t	   desc_hdr;
	int		   err;

	TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_recv_pkt_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	old_xfer_pkt_ixlp = (ixl1394_xfer_pkt_t *)uvp->ixloldp;
	new_xfer_pkt_ixlp = (ixl1394_xfer_pkt_t *)uvp->ixlnewp;

	/* check if any change between new and old IXL xfer commands */
	if ((new_xfer_pkt_ixlp->size == old_xfer_pkt_ixlp->size) &&
	    (new_xfer_pkt_ixlp->ixl_buf.ixldmac_addr ==
	    old_xfer_pkt_ixlp->ixl_buf.ixldmac_addr) &&
	    (new_xfer_pkt_ixlp->mem_bufp == old_xfer_pkt_ixlp->mem_bufp)) {

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_recv_pkt_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");

		/* no change. return with done ok status */
		return (IXL_PREP_SUCCESS);
	}

	/* if new IXL buffer addrs are null, return error */
	if ((new_xfer_pkt_ixlp->ixl_buf.ixldmac_addr == NULL) ||
	    (new_xfer_pkt_ixlp->mem_bufp == NULL)) {

		uvp->upd_status = IXL1394_EXFER_BUF_MISSING;

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_recv_pkt_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (IXL_PREP_FAILURE);
	}

	/* if IXL xfer command is not xfer start command */
	if (uvp->ixl_opcode == IXL1394_OP_RECV_PKT_U) {
		/*
		 * find IXL xfer start command in the compiler_privatep of the
		 * old IXL xfer command
		 */
		uvp->ixlxferp = (ixl1394_command_t *)
		    uvp->ixloldp->compiler_privatep;

		if (uvp->ixlxferp == NULL) {

			/* Error - no IXL xfer start command found */
			uvp->upd_status = IXL1394_EORIG_IXL_CORRUPTED;

			TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_recv_pkt_exit,
			    HCI1394_TNF_HAL_STACK_ISOCH, "");
			return (IXL_PREP_FAILURE);
		}
	} else {
		/* IXL xfer command is the IXL xfer start command */
		uvp->ixlxferp = uvp->ixloldp;
	}

	/* check that xfer_ctl is present in the IXL xfer start command */
	if ((xferctlp = (hci1394_xfer_ctl_t *)
	    uvp->ixlxferp->compiler_privatep) == NULL) {

		/* Error - no xfer_ctl struct found */
		uvp->upd_status = IXL1394_EORIG_IXL_CORRUPTED;

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_recv_pkt_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (IXL_PREP_FAILURE);
	}

	/* set depth to zero and count to 1 to update dma descriptor */
	uvp->ixldepth = 0;
	uvp->ixlcount = 1;

	/*
	 * get Z bits (number of descriptors in descriptor block) from the DMA
	 * bound address in the xfer_ctl struct of the IXL xfer start cpmmand.
	 */
	uvp->hci_offset = xferctlp->dma[0].dma_bound & DESC_Z_MASK;

	/*
	 * set offset from the current(last) descriptor to the descriptor for
	 * this packet command
	 */
	uvp->hci_offset -= (1 + uvp->ixloldp->compiler_resv);

	/*
	 * set bufsize to the new IXL xfer size, and bufaddr to the new
	 * IXL xfer bufp
	 */
	uvp->bufsize = ((ixl1394_xfer_pkt_t *)uvp->ixlnewp)->size;
	uvp->bufaddr = ((ixl1394_xfer_pkt_t *)
	    uvp->ixlnewp)->ixl_buf.ixldmac_addr;

	/*
	 * update old hcihdr w/new bufsize, set hcistatus rescnt to
	 * new bufsize
	 */
	hcidescp = (hci1394_desc_t *)xferctlp->dma[0].dma_descp -
	    uvp->hci_offset;
	acc_hdl  = xferctlp->dma[0].dma_buf->bi_handle;
	dma_hdl  = xferctlp->dma[0].dma_buf->bi_dma_handle;

	/* Sync the descriptor before we grab the header(s) */
	err = ddi_dma_sync(dma_hdl, (off_t)hcidescp, sizeof (hci1394_desc_t),
	    DDI_DMA_SYNC_FORCPU);
	if (err != DDI_SUCCESS) {
		uvp->upd_status = IXL1394_EINTERNAL_ERROR;

		TNF_PROBE_1_DEBUG(hci1394_ixl_update_prep_recv_pkt_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "", tnf_string, errmsg,
		    "EINTERNAL_ERROR: dma_sync() failed");
		return (IXL_PREP_FAILURE);
	}

	desc_hdr = ddi_get32(acc_hdl, &hcidescp->hdr);
	uvp->hcihdr = desc_hdr;
	uvp->hcihdr &= ~DESC_HDR_REQCOUNT_MASK;
	uvp->hcihdr |= (uvp->bufsize << DESC_HDR_REQCOUNT_SHIFT) &
	    DESC_HDR_REQCOUNT_MASK;
	uvp->hcistatus = (uvp->bufsize << DESC_ST_RESCOUNT_SHIFT) &
	    DESC_ST_RESCOUNT_MASK;

	TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_recv_pkt_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
	return (IXL_PREP_READY);
}

/*
 * hci1394_ixl_update_prep_recv_buf()
 *    Preparation for update of an IXL1394_OP_RECV_BUF_U command.
 */
static int
hci1394_ixl_update_prep_recv_buf(hci1394_ixl_update_vars_t *uvp)
{
	ixl1394_xfer_buf_t *old_xfer_buf_ixlp;
	ixl1394_xfer_buf_t *new_xfer_buf_ixlp;
	hci1394_xfer_ctl_t *xferctlp;

	TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_recv_buf_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	old_xfer_buf_ixlp = (ixl1394_xfer_buf_t *)uvp->ixloldp;
	new_xfer_buf_ixlp = (ixl1394_xfer_buf_t *)uvp->ixlnewp;

	/* check if any change between new and old IXL xfer commands */
	if ((new_xfer_buf_ixlp->size ==	old_xfer_buf_ixlp->size) &&
	    (new_xfer_buf_ixlp->ixl_buf.ixldmac_addr ==
	    old_xfer_buf_ixlp->ixl_buf.ixldmac_addr) &&
	    (new_xfer_buf_ixlp->mem_bufp == old_xfer_buf_ixlp->mem_bufp)) {

		if (((uvp->ctxtp->ctxt_flags & HCI1394_ISO_CTXT_BFFILL) != 0) ||
		    (new_xfer_buf_ixlp->pkt_size ==
		    old_xfer_buf_ixlp->pkt_size)) {

			TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_recv_buf_exit,
			    HCI1394_TNF_HAL_STACK_ISOCH, "");

			/* no change. return with done ok status */
			return (IXL_PREP_SUCCESS);
		}
	}

	/* if new IXL buffer addrs are null, return error */
	if ((new_xfer_buf_ixlp->ixl_buf.ixldmac_addr == NULL) ||
	    (new_xfer_buf_ixlp->mem_bufp == NULL)) {

		uvp->upd_status = IXL1394_EXFER_BUF_MISSING;

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_recv_buf_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (IXL_PREP_FAILURE);
	}

	/*
	 * if not buffer fill mode, check that the new pkt_size > 0 and
	 * new size/pkt_size doesn't change the count of dma descriptor
	 * blocks required
	 */
	if ((uvp->ctxtp->ctxt_flags & HCI1394_ISO_CTXT_BFFILL) == 0) {
		if ((new_xfer_buf_ixlp->pkt_size == 0) ||
		    ((new_xfer_buf_ixlp->size /	new_xfer_buf_ixlp->pkt_size) !=
		    (old_xfer_buf_ixlp->size / old_xfer_buf_ixlp->pkt_size))) {

			/* count changes. return an error */
			uvp->upd_status = IXL1394_EXFER_BUF_CNT_DIFF;

			TNF_PROBE_0_DEBUG(
			    hci1394_ixl_update_prep_recv_buf_exit,
			    HCI1394_TNF_HAL_STACK_ISOCH, "");
			return (IXL_PREP_FAILURE);
		}
	}

	/* set old IXL xfer command as the current IXL xfer command */
	uvp->ixlxferp = uvp->ixloldp;

	/* check that the xfer_ctl struct is present in IXL xfer command */
	if ((xferctlp = (hci1394_xfer_ctl_t *)uvp->ixlxferp->compiler_privatep)
	    == NULL) {

		/* return an error if no xfer_ctl struct is found for command */
		uvp->upd_status = IXL1394_EORIG_IXL_CORRUPTED;

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_recv_buf_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (IXL_PREP_FAILURE);
	}

	/* set depth to zero and count to update all dma descriptors */
	uvp->ixldepth = 0;
	uvp->ixlcount = xferctlp->cnt;

	/* set bufsize to new pkt_size (or to new size if buffer fill mode) */
	if ((uvp->ctxtp->ctxt_flags & HCI1394_ISO_CTXT_BFFILL) == 0) {
		uvp->bufsize = new_xfer_buf_ixlp->pkt_size;
	} else {
		uvp->bufsize = new_xfer_buf_ixlp->size;
	}

	/* set bufaddr to new ixl_buf */
	uvp->bufaddr = new_xfer_buf_ixlp->ixl_buf.ixldmac_addr;

	/* set hcihdr reqcnt and hcistatus rescnt to new bufsize */
	uvp->hci_offset = 0;
	uvp->hcihdr = (uvp->bufsize << DESC_HDR_REQCOUNT_SHIFT) &
	    DESC_HDR_REQCOUNT_MASK;
	uvp->hcistatus = (uvp->bufsize << DESC_ST_RESCOUNT_SHIFT) &
	    DESC_ST_RESCOUNT_MASK;

	TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_recv_buf_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
	return (IXL_PREP_READY);
}

/*
 * hci1394_ixl_update_prep_send_pkt()
 *    Preparation for update of an IXL1394_OP_SEND_PKT_U command,
 *    IXL1394_OP_SEND_PKT_ST_U command and IXL1394_OP_SEND_PKT_WHDR_ST_U
 *    command.
 */
static int
hci1394_ixl_update_prep_send_pkt(hci1394_ixl_update_vars_t *uvp)
{
	ixl1394_xfer_pkt_t *old_xfer_pkt_ixlp;
	ixl1394_xfer_pkt_t *new_xfer_pkt_ixlp;
	hci1394_xfer_ctl_t *xferctlp;
	hci1394_desc_imm_t *hcidescp;
	ddi_acc_handle_t   acc_hdl;
	ddi_dma_handle_t   dma_hdl;
	uint32_t	   desc_hdr, desc_hdr2;
	int		   err;

	TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_send_pkt_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	old_xfer_pkt_ixlp = (ixl1394_xfer_pkt_t *)uvp->ixloldp;
	new_xfer_pkt_ixlp = (ixl1394_xfer_pkt_t *)uvp->ixlnewp;

	/* check if any change between new and old IXL xfer commands */
	if ((new_xfer_pkt_ixlp->size ==	old_xfer_pkt_ixlp->size) &&
	    (new_xfer_pkt_ixlp->ixl_buf.ixldmac_addr ==
	    old_xfer_pkt_ixlp->ixl_buf.ixldmac_addr) &&
	    (new_xfer_pkt_ixlp->mem_bufp == old_xfer_pkt_ixlp->mem_bufp)) {

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_send_pkt_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");

		/* if none, return with done ok status */
		return (IXL_PREP_SUCCESS);
	}

	/* if new ixl buffer addrs are null, return error */
	if ((new_xfer_pkt_ixlp->ixl_buf.ixldmac_addr == NULL) ||
	    (new_xfer_pkt_ixlp->mem_bufp == NULL)) {

		uvp->upd_status = IXL1394_EXFER_BUF_MISSING;

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_send_pkt_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (IXL_PREP_FAILURE);
	}

	/* error if IXL1394_OP_SEND_PKT_WHDR_ST_U opcode and size < 4 */
	if ((uvp->ixl_opcode == IXL1394_OP_SEND_PKT_WHDR_ST_U) &&
	    (new_xfer_pkt_ixlp->size < 4)) {

		uvp->upd_status = IXL1394_EPKT_HDR_MISSING;

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_send_pkt_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (IXL_PREP_FAILURE);
	}

	/* if IXL xfer command is not an IXL xfer start command */
	if (uvp->ixl_opcode == IXL1394_OP_SEND_PKT_U) {
		/*
		 * find IXL xfer start command in the compiler_privatep of the
		 * old IXL xfer command
		 */
		uvp->ixlxferp = (ixl1394_command_t *)
		    old_xfer_pkt_ixlp->compiler_privatep;

		if (uvp->ixlxferp == NULL) {
			/* error if no IXL xfer start command found */
			uvp->upd_status = IXL1394_EORIG_IXL_CORRUPTED;

			TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_send_pkt_exit,
			    HCI1394_TNF_HAL_STACK_ISOCH, "");
			return (IXL_PREP_FAILURE);
		}
	} else {
		/* IXL xfer command is the IXL xfer start command */
		uvp->ixlxferp = uvp->ixloldp;
	}

	/*
	 * get Z bits (number of descriptor components in the descriptor block)
	 * from a dma bound address in the xfer_ctl structure of the IXL
	 * xfer start command
	 */
	if ((xferctlp = (hci1394_xfer_ctl_t *)
	    uvp->ixlxferp->compiler_privatep) == NULL) {

		uvp->upd_status = IXL1394_EORIG_IXL_CORRUPTED;

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_send_pkt_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (IXL_PREP_FAILURE);
	}

	/* set depth to zero and count to 1 to update dma descriptor */
	uvp->ixldepth = 0;
	uvp->ixlcount = 1;

	/*
	 * set offset to the header(first) descriptor from the
	 * current(last) descriptor
	 */
	uvp->hdr_offset = xferctlp->dma[0].dma_bound & DESC_Z_MASK - 1;

	/*
	 * set offset from the current(last) descriptor to the descriptor for
	 * this packet command
	 */
	uvp->hci_offset = uvp->hdr_offset - 2 - uvp->ixloldp->compiler_resv;

	/* set bufsize to new pkt buffr size, set bufaddr to new bufp */
	uvp->bufsize = new_xfer_pkt_ixlp->size;
	uvp->bufaddr = new_xfer_pkt_ixlp->ixl_buf.ixldmac_addr;

	/*
	 * if IXL1394_OP_SEND_PKT_WHDR_ST_U opcode, adjust size & buff,
	 * step over hdr
	 */
	if (uvp->ixl_opcode == IXL1394_OP_SEND_PKT_WHDR_ST_U) {
		uvp->bufsize -= 4;
		uvp->bufaddr += 4;
	}

	/* update old hcihdr w/new bufsize */
	hcidescp = (hci1394_desc_imm_t *)xferctlp->dma[0].dma_descp -
	    uvp->hci_offset;
	acc_hdl  = xferctlp->dma[0].dma_buf->bi_handle;
	dma_hdl  = xferctlp->dma[0].dma_buf->bi_dma_handle;

	/* Sync the descriptor before we grab the header(s) */
	err = ddi_dma_sync(dma_hdl, (off_t)hcidescp,
	    sizeof (hci1394_desc_imm_t), DDI_DMA_SYNC_FORCPU);
	if (err != DDI_SUCCESS) {
		uvp->upd_status = IXL1394_EINTERNAL_ERROR;

		TNF_PROBE_1_DEBUG(hci1394_ixl_update_prep_send_pkt_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "", tnf_string, errmsg,
		    "EINTERNAL_ERROR: dma_sync() failed");
		return (IXL_PREP_FAILURE);
	}

	desc_hdr = ddi_get32(acc_hdl, &hcidescp->hdr);
	uvp->hcihdr = desc_hdr;
	uvp->hcihdr &= ~DESC_HDR_REQCOUNT_MASK;
	uvp->hcihdr |= (uvp->bufsize << DESC_HDR_REQCOUNT_SHIFT) &
	    DESC_HDR_REQCOUNT_MASK;

	/* update old pkthdr2 w/new bufsize. error if exceeds 16k */
	desc_hdr2 = ddi_get32(acc_hdl, &hcidescp->q2);
	uvp->pkthdr2 = desc_hdr2;
	uvp->pkthdr2 = (uvp->pkthdr2 & DESC_PKT_DATALEN_MASK) >>
	    DESC_PKT_DATALEN_SHIFT;
	uvp->pkthdr2 -= old_xfer_pkt_ixlp->size;
	uvp->pkthdr2 += uvp->bufsize;

	if (uvp->pkthdr2 > 0xFFFF) {
		uvp->upd_status = IXL1394_EPKTSIZE_MAX_OFLO;

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_send_pkt_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (IXL_PREP_FAILURE);
	}
	uvp->pkthdr2 = (uvp->pkthdr2 << DESC_PKT_DATALEN_SHIFT) &
	    DESC_PKT_DATALEN_MASK;

	TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_send_pkt_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
	return (IXL_PREP_READY);
}

/*
 * hci1394_ixl_update_prep_send_buf()
 *    Preparation for update of an IXL1394_OP_SEND_BUF_U command.
 */
static int
hci1394_ixl_update_prep_send_buf(hci1394_ixl_update_vars_t *uvp)
{
	ixl1394_xfer_buf_t *old_xfer_buf_ixlp;
	ixl1394_xfer_buf_t *new_xfer_buf_ixlp;
	hci1394_xfer_ctl_t *xferctlp;

	TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_send_buf_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	old_xfer_buf_ixlp = (ixl1394_xfer_buf_t *)uvp->ixloldp;
	new_xfer_buf_ixlp = (ixl1394_xfer_buf_t *)uvp->ixlnewp;

	/* check if any change between new and old IXL xfer commands */
	if ((new_xfer_buf_ixlp->size == old_xfer_buf_ixlp->size) &&
	    (new_xfer_buf_ixlp->pkt_size == old_xfer_buf_ixlp->pkt_size) &&
	    (new_xfer_buf_ixlp->ixl_buf.ixldmac_addr ==
	    old_xfer_buf_ixlp->ixl_buf.ixldmac_addr) &&
	    (new_xfer_buf_ixlp->mem_bufp == old_xfer_buf_ixlp->mem_bufp)) {

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_send_buf_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");

		/* no change, return with done ok status */
		return (IXL_PREP_SUCCESS);
	}

	/* if new IXL buffer addresses are null, return error */
	if ((new_xfer_buf_ixlp->ixl_buf.ixldmac_addr == NULL) ||
	    (new_xfer_buf_ixlp->mem_bufp == NULL)) {

		uvp->upd_status = IXL1394_EXFER_BUF_MISSING;

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_send_buf_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (IXL_PREP_FAILURE);
	}

	/*
	 * check that the new pkt_size > 0 and the new size/pkt_size
	 * doesn't change the count of DMA descriptor blocks required
	 */
	if ((new_xfer_buf_ixlp->pkt_size == 0) ||
	    ((new_xfer_buf_ixlp->size / new_xfer_buf_ixlp->pkt_size) !=
	    (old_xfer_buf_ixlp->size / old_xfer_buf_ixlp->pkt_size))) {

		/* Error - new has different pkt count than old */
		uvp->upd_status = IXL1394_EXFER_BUF_CNT_DIFF;

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_send_buf_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (IXL_PREP_FAILURE);
	}

	/* set the old IXL xfer command as the current IXL xfer command */
	uvp->ixlxferp = uvp->ixloldp;

	/*
	 * get Z bits (number of descriptor components in descriptor block)
	 * from a DMA bound address in the xfer_ctl struct of the
	 * IXL xfer command
	 */
	if ((xferctlp = (hci1394_xfer_ctl_t *)
	    uvp->ixlxferp->compiler_privatep) == NULL) {

		uvp->upd_status = IXL1394_EORIG_IXL_CORRUPTED;

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_send_buf_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (IXL_PREP_FAILURE);
	}

	/* set depth to zero and count to update all dma descriptors */
	uvp->ixldepth = 0;
	uvp->ixlcount = xferctlp->cnt;

	/*
	 * set offset to the header(first) descriptor from the current (last)
	 * descriptor.
	 */
	uvp->hdr_offset = xferctlp->dma[0].dma_bound & DESC_Z_MASK - 1;

	/* set offset to the only(last) xfer descriptor */
	uvp->hci_offset = 0;

	/* set bufsize to the new pkt_size, set bufaddr to the new bufp */
	uvp->bufsize = new_xfer_buf_ixlp->pkt_size;
	uvp->bufaddr = new_xfer_buf_ixlp->ixl_buf.ixldmac_addr;

	/*
	 * if IXL1394_OP_SEND_PKT_WHDR_ST_U opcode, adjust size & buff,
	 * step over header (a quadlet)
	 */
	if (uvp->ixl_opcode == IXL1394_OP_SEND_PKT_WHDR_ST_U) {
		uvp->bufsize -= 4;
		uvp->bufaddr += 4;
	}

	/* set hcihdr to new bufsize */
	uvp->hcihdr = (uvp->bufsize << DESC_HDR_REQCOUNT_SHIFT) &
	    DESC_HDR_REQCOUNT_MASK;

	/* set pkthdr2 to new bufsize */
	uvp->pkthdr2 = (uvp->bufsize << DESC_PKT_DATALEN_SHIFT) &
	    DESC_PKT_DATALEN_MASK;

	TNF_PROBE_0_DEBUG(hci1394_ixl_update_prep_send_buf_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
	return (IXL_PREP_READY);
}

/*
 * hci1394_ixl_update_perform()
 *    performs the actual update into DMA memory.
 */
static int
hci1394_ixl_update_perform(hci1394_ixl_update_vars_t *uvp)
{
	int			ii;
	uint_t			skipaddrlast;
	hci1394_xfer_ctl_t	*xferctlp;
	hci1394_desc_imm_t	*hcidescp;
	hci1394_iso_ctxt_t	*ctxtp;
	ddi_acc_handle_t	acc_hdl;
	ddi_dma_handle_t	dma_hdl;
	int			err;

	TNF_PROBE_0_DEBUG(hci1394_ixl_update_perform_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	ctxtp = uvp->ctxtp;

	/*
	 * if no target ixl xfer command to be updated or it has
	 * no xfer_ctl struct, then internal error.
	 */
	if ((uvp->ixlxferp == NULL) ||
	    ((xferctlp = (hci1394_xfer_ctl_t *)
	    uvp->ixlxferp->compiler_privatep) == NULL)) {

		uvp->upd_status = IXL1394_EINTERNAL_ERROR;

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_perform_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");

		return (DDI_FAILURE);
	}

	/* perform update based on specific ixl command type */
	switch (uvp->ixl_opcode) {

	case IXL1394_OP_JUMP_U: {
		ixl1394_jump_t *old_jump_ixlp;
		ixl1394_jump_t *new_jump_ixlp;

		old_jump_ixlp = (ixl1394_jump_t *)uvp->ixloldp;
		new_jump_ixlp = (ixl1394_jump_t *)uvp->ixlnewp;

		/*
		 * set new hdr and new branch fields into last component of last
		 * dma descriptor block of ixl xfer cmd associated with
		 * ixl jump cmd
		 */
		hcidescp = (hci1394_desc_imm_t *)
		    xferctlp->dma[xferctlp->cnt - 1].dma_descp;
		acc_hdl	 = xferctlp->dma[xferctlp->cnt - 1].dma_buf->bi_handle;
		dma_hdl	 =
		    xferctlp->dma[xferctlp->cnt - 1].dma_buf->bi_dma_handle;

		ddi_put32(acc_hdl, &hcidescp->hdr, uvp->hcihdr);
		ddi_put32(acc_hdl, &hcidescp->branch, uvp->jumpaddr);

		/*
		 * if xfer type is send and skip mode is IXL1394__SKIP_TO_NEXT
		 * also set branch location into branch field of first
		 * component (skip to address) of last dma descriptor block
		 */
		if (uvp->skipmode == IXL1394_SKIP_TO_NEXT) {
			hcidescp -= uvp->hci_offset;
			ddi_put32(acc_hdl, &hcidescp->branch, uvp->skipaddr);
		}

		/* Sync descriptor for device (desc was modified) */
		err = ddi_dma_sync(dma_hdl, (off_t)hcidescp,
		    sizeof (hci1394_desc_imm_t), DDI_DMA_SYNC_FORDEV);
		if (err != DDI_SUCCESS) {
			uvp->upd_status = IXL1394_EINTERNAL_ERROR;

			TNF_PROBE_0_DEBUG(hci1394_ixl_update_perform_exit,
			    HCI1394_TNF_HAL_STACK_ISOCH, "");
			return (DDI_FAILURE);
		}

		/* set old ixl jump cmd label from new ixl jump cmd label */
		old_jump_ixlp->label = new_jump_ixlp->label;
		break;
	}
	case IXL1394_OP_SET_SKIPMODE_U: {
		ixl1394_set_skipmode_t *old_set_skipmode_ixlp;
		ixl1394_set_skipmode_t *new_set_skipmode_ixlp;

		old_set_skipmode_ixlp = (ixl1394_set_skipmode_t *)uvp->ixloldp;
		new_set_skipmode_ixlp = (ixl1394_set_skipmode_t *)uvp->ixlnewp;

		/*
		 * if skip to next mode, save skip addr for last iteration
		 * thru dma descriptor blocks for associated ixl xfer command
		 */
		if (uvp->skipmode == IXL1394_SKIP_TO_NEXT) {
			skipaddrlast = uvp->skipaddr;
		}

		/*
		 * iterate through set of dma descriptor blocks for associated
		 * ixl xfer start cmd and set new skip address into first hci
		 * descriptor of each if skip next or skip self, first determine
		 * address in each iteration
		 */
		for (ii = 0; ii < xferctlp->cnt; ii++) {
			hcidescp = (hci1394_desc_imm_t *)
			    xferctlp->dma[ii].dma_descp - uvp->hci_offset;
			acc_hdl	 = xferctlp->dma[ii].dma_buf->bi_handle;
			dma_hdl	 = xferctlp->dma[ii].dma_buf->bi_dma_handle;

			if (uvp->skipmode == IXL1394_SKIP_TO_NEXT) {
				if (ii < (xferctlp->cnt - 1)) {
					uvp->skipaddr =
					    xferctlp->dma[ii + 1].dma_bound;
				} else {
					uvp->skipaddr = skipaddrlast;
				}
			} else if (uvp->skipmode == IXL1394_SKIP_TO_SELF) {
				uvp->skipaddr = xferctlp->dma[ii].dma_bound;
			}

			ddi_put32(acc_hdl, &hcidescp->branch, uvp->skipaddr);

			/* Sync descriptor for device (desc was modified) */
			err = ddi_dma_sync(dma_hdl, (off_t)hcidescp,
			    sizeof (hci1394_desc_imm_t), DDI_DMA_SYNC_FORDEV);
			if (err != DDI_SUCCESS) {
				uvp->upd_status = IXL1394_EINTERNAL_ERROR;

				TNF_PROBE_0_DEBUG(
				    hci1394_ixl_update_perform_exit,
				    HCI1394_TNF_HAL_STACK_ISOCH, "");
				return (DDI_FAILURE);
			}
		}

		/*
		 * set old ixl set skip mode cmd mode and label from new ixl cmd
		 * set old ixl set skip mode cmd compilier_privatep to
		 * uvp->skipxferp
		 */
		old_set_skipmode_ixlp->skipmode = uvp->skipmode;
		old_set_skipmode_ixlp->label = new_set_skipmode_ixlp->label;
		old_set_skipmode_ixlp->compiler_privatep =
		    (ixl1394_priv_t)uvp->skipxferp;
		break;
	}
	case IXL1394_OP_SET_TAGSYNC_U: {
		ixl1394_set_tagsync_t *old_set_tagsync_ixlp;
		ixl1394_set_tagsync_t *new_set_tagsync_ixlp;

		old_set_tagsync_ixlp = (ixl1394_set_tagsync_t *)uvp->ixloldp;
		new_set_tagsync_ixlp = (ixl1394_set_tagsync_t *)uvp->ixlnewp;

		/*
		 * iterate through set of descriptor blocks for associated IXL
		 * xfer command and set new pkthdr1 value into output more/last
		 * immediate hci descriptor (first/last hci descriptor of each
		 * descriptor block)
		 */
		for (ii = 0; ii < xferctlp->cnt; ii++) {
			hcidescp = (hci1394_desc_imm_t *)
			    xferctlp->dma[ii].dma_descp - uvp->hdr_offset;
			acc_hdl	 = xferctlp->dma[ii].dma_buf->bi_handle;
			dma_hdl	 = xferctlp->dma[ii].dma_buf->bi_dma_handle;
			ddi_put32(acc_hdl, &hcidescp->q1, uvp->pkthdr1);

			/* Sync descriptor for device (desc was modified) */
			err = ddi_dma_sync(dma_hdl, (off_t)hcidescp,
			    sizeof (hci1394_desc_imm_t), DDI_DMA_SYNC_FORDEV);
			if (err != DDI_SUCCESS) {
				uvp->upd_status = IXL1394_EINTERNAL_ERROR;

				TNF_PROBE_0_DEBUG(
				    hci1394_ixl_update_perform_exit,
				    HCI1394_TNF_HAL_STACK_ISOCH, "");
				return (DDI_FAILURE);
			}
		}

		/*
		 * set old ixl set tagsync cmd tag & sync from new ixl set
		 * tagsync cmd
		 */
		old_set_tagsync_ixlp->tag = new_set_tagsync_ixlp->tag;
		old_set_tagsync_ixlp->sync = new_set_tagsync_ixlp->sync;
		break;
	}
	case IXL1394_OP_RECV_PKT_U:
	case IXL1394_OP_RECV_PKT_ST_U: {
		ixl1394_xfer_pkt_t *old_xfer_pkt_ixlp;
		ixl1394_xfer_pkt_t *new_xfer_pkt_ixlp;
		uint32_t	   desc_status;

		old_xfer_pkt_ixlp = (ixl1394_xfer_pkt_t *)uvp->ixloldp;
		new_xfer_pkt_ixlp = (ixl1394_xfer_pkt_t *)uvp->ixlnewp;

		/*
		 * alter buffer address, count and rescount in ixl recv pkt cmd
		 * related hci component in dma descriptor block
		 */
		hcidescp = (hci1394_desc_imm_t *)
		    xferctlp->dma[0].dma_descp - uvp->hci_offset;
		acc_hdl	 = xferctlp->dma[0].dma_buf->bi_handle;
		dma_hdl	 = xferctlp->dma[0].dma_buf->bi_dma_handle;
		ddi_put32(acc_hdl, &hcidescp->hdr, uvp->hcihdr);
		ddi_put32(acc_hdl, &hcidescp->data_addr, uvp->bufaddr);

		/* Sync the descriptor before we grab the status */
		err = ddi_dma_sync(dma_hdl, (off_t)hcidescp,
		    sizeof (hci1394_desc_imm_t), DDI_DMA_SYNC_FORCPU);
		if (err != DDI_SUCCESS) {
			uvp->upd_status = IXL1394_EINTERNAL_ERROR;

			TNF_PROBE_0_DEBUG(hci1394_ixl_update_perform_exit,
			    HCI1394_TNF_HAL_STACK_ISOCH, "");
			return (DDI_FAILURE);
		}

		/* change only low 1/2 word and leave status bits unchanged */
		desc_status = ddi_get32(acc_hdl, &hcidescp->status);
		desc_status = (desc_status & ~DESC_ST_RESCOUNT_MASK) |
		    uvp->hcistatus;
		ddi_put32(acc_hdl, &hcidescp->status, desc_status);

		/* Sync descriptor for device (desc was modified) */
		err = ddi_dma_sync(dma_hdl, (off_t)hcidescp,
		    sizeof (hci1394_desc_imm_t), DDI_DMA_SYNC_FORDEV);
		if (err != DDI_SUCCESS) {
			uvp->upd_status = IXL1394_EINTERNAL_ERROR;

			TNF_PROBE_0_DEBUG(hci1394_ixl_update_perform_exit,
			    HCI1394_TNF_HAL_STACK_ISOCH, "");
			return (DDI_FAILURE);
		}

		/*
		 * set old ixl recv pkt size and buffers from new
		 * ixl recv pkt command
		 */
		old_xfer_pkt_ixlp->size = new_xfer_pkt_ixlp->size;
		old_xfer_pkt_ixlp->ixl_buf.ixldmac_addr =
		    new_xfer_pkt_ixlp->ixl_buf.ixldmac_addr;
		old_xfer_pkt_ixlp->mem_bufp = new_xfer_pkt_ixlp->mem_bufp;
		break;
	}
	case IXL1394_OP_RECV_BUF_U: {
		ixl1394_xfer_buf_t *old_xfer_buf_ixlp;
		ixl1394_xfer_buf_t *new_xfer_buf_ixlp;
		uint32_t	   desc_hdr;
		uint32_t	   desc_status;

		old_xfer_buf_ixlp = (ixl1394_xfer_buf_t *)uvp->ixloldp;
		new_xfer_buf_ixlp = (ixl1394_xfer_buf_t *)uvp->ixlnewp;

		/*
		 * iterate through set of descriptor blocks for this IXL xfer
		 * command altering buffer, count and rescount in each
		 * input more/last(the only) hci descriptor block descriptor.
		 */
		for (ii = 0; ii < xferctlp->cnt; ii++) {

			hcidescp = (hci1394_desc_imm_t *)
			    xferctlp->dma[ii].dma_descp - uvp->hci_offset;
			acc_hdl	 = xferctlp->dma[ii].dma_buf->bi_handle;
			dma_hdl	 = xferctlp->dma[ii].dma_buf->bi_dma_handle;

			ddi_put32(acc_hdl, &hcidescp->data_addr, uvp->bufaddr);

			/*
			 * advance to next buffer segment, adjust over header
			 * if appropriate
			 */
			uvp->bufaddr += uvp->bufsize;

			/* Sync the descriptor before we grab the header(s) */
			err = ddi_dma_sync(dma_hdl, (off_t)hcidescp,
			    sizeof (hci1394_desc_imm_t), DDI_DMA_SYNC_FORCPU);
			if (err != DDI_SUCCESS) {
				uvp->upd_status = IXL1394_EINTERNAL_ERROR;

				TNF_PROBE_0_DEBUG(
				    hci1394_ixl_update_perform_exit,
				    HCI1394_TNF_HAL_STACK_ISOCH, "");
				return (DDI_FAILURE);
			}

			/*
			 * this preserves interrupt enable bits, et al. in each
			 * descriptor block header.
			 */
			desc_hdr = ddi_get32(acc_hdl, &hcidescp->hdr);
			desc_hdr = (desc_hdr & ~DESC_HDR_REQCOUNT_MASK) |
			    uvp->hcihdr;
			ddi_put32(acc_hdl, &hcidescp->hdr, desc_hdr);

			/*
			 * change only low 1/2 word leaving status bits
			 * unchanged
			 */
			desc_status = ddi_get32(acc_hdl, &hcidescp->status);
			desc_status = (desc_status & ~DESC_ST_RESCOUNT_MASK) |
			    uvp->hcistatus;
			ddi_put32(acc_hdl, &hcidescp->status, desc_status);

			/* Sync descriptor for device (desc was modified) */
			err = ddi_dma_sync(dma_hdl, (off_t)hcidescp,
			    sizeof (hci1394_desc_imm_t), DDI_DMA_SYNC_FORDEV);
			if (err != DDI_SUCCESS) {
				uvp->upd_status = IXL1394_EINTERNAL_ERROR;

				TNF_PROBE_0_DEBUG(
				    hci1394_ixl_update_perform_exit,
				    HCI1394_TNF_HAL_STACK_ISOCH, "");
				return (DDI_FAILURE);
			}
		}

		/*
		 * set old ixl recv buf sizes and buffers from
		 * new ixl recv pkt cmd
		 */
		old_xfer_buf_ixlp->pkt_size = new_xfer_buf_ixlp->pkt_size;
		old_xfer_buf_ixlp->size = new_xfer_buf_ixlp->size;
		old_xfer_buf_ixlp->ixl_buf.ixldmac_addr =
		    new_xfer_buf_ixlp->ixl_buf.ixldmac_addr;
		old_xfer_buf_ixlp->mem_bufp = new_xfer_buf_ixlp->mem_bufp;
		break;
	}
	case IXL1394_OP_SEND_PKT_U:
	case IXL1394_OP_SEND_PKT_ST_U:
	case IXL1394_OP_SEND_PKT_WHDR_ST_U: {
		ixl1394_xfer_pkt_t *old_xfer_pkt_ixlp;
		ixl1394_xfer_pkt_t *new_xfer_pkt_ixlp;

		old_xfer_pkt_ixlp = (ixl1394_xfer_pkt_t *)uvp->ixloldp;
		new_xfer_pkt_ixlp = (ixl1394_xfer_pkt_t *)uvp->ixlnewp;

		/*
		 * replace pkthdr2 in output more immediate (the first) hci
		 * descriptor in block, then alter buffer address and count in
		 * IXL send pkt command related output more/last hci descriptor.
		 */
		hcidescp = (hci1394_desc_imm_t *)xferctlp->dma[0].dma_descp -
		    uvp->hdr_offset;
		acc_hdl	 = xferctlp->dma[0].dma_buf->bi_handle;
		dma_hdl	 = xferctlp->dma[0].dma_buf->bi_dma_handle;

		ddi_put32(acc_hdl, &hcidescp->q2, uvp->pkthdr2);
		ddi_put32(acc_hdl, &hcidescp->hdr, uvp->hcihdr);
		ddi_put32(acc_hdl, &hcidescp->data_addr, uvp->bufaddr);

		/* Sync descriptor for device (desc was modified) */
		err = ddi_dma_sync(dma_hdl, (off_t)hcidescp,
		    sizeof (hci1394_desc_imm_t), DDI_DMA_SYNC_FORDEV);
		if (err != DDI_SUCCESS) {
			uvp->upd_status = IXL1394_EINTERNAL_ERROR;

			TNF_PROBE_0_DEBUG(hci1394_ixl_update_perform_exit,
			    HCI1394_TNF_HAL_STACK_ISOCH, "");
			return (DDI_FAILURE);
		}

		/*
		 * set old ixl recv pkt size and buffers from
		 * new ixl recv pkt cmd
		 */
		old_xfer_pkt_ixlp->size = new_xfer_pkt_ixlp->size;
		old_xfer_pkt_ixlp->ixl_buf.ixldmac_addr =
		    new_xfer_pkt_ixlp->ixl_buf.ixldmac_addr;
		old_xfer_pkt_ixlp->mem_bufp = new_xfer_pkt_ixlp->mem_bufp;
		break;
	}
	case IXL1394_OP_SEND_BUF_U: {
		ixl1394_xfer_buf_t *old_xfer_buf_ixlp;
		ixl1394_xfer_buf_t *new_xfer_buf_ixlp;
		uint32_t	   desc_hdr;

		old_xfer_buf_ixlp = (ixl1394_xfer_buf_t *)uvp->ixloldp;
		new_xfer_buf_ixlp = (ixl1394_xfer_buf_t *)uvp->ixlnewp;

		/*
		 * iterate through set of descriptor blocks for this IXL xfer
		 * command replacing pkthdr2 in output more immediate
		 * (the first) hci descriptor block descriptor, then altering
		 * buffer address and count in each output last (the only other)
		 * hci descriptor block descriptor.
		 */
		for (ii = 0; ii < xferctlp->cnt; ii++) {
			hcidescp = (hci1394_desc_imm_t *)
			    xferctlp->dma[ii].dma_descp - uvp->hdr_offset;
			acc_hdl	 = xferctlp->dma[ii].dma_buf->bi_handle;
			dma_hdl	 = xferctlp->dma[ii].dma_buf->bi_dma_handle;

			ddi_put32(acc_hdl, &hcidescp->q2, uvp->pkthdr2);
			ddi_put32(acc_hdl, &hcidescp->data_addr, uvp->bufaddr);

			/* advance to next buffer segment */
			uvp->bufaddr += uvp->bufsize;

			/* Sync the descriptor before we grab the header(s) */
			err = ddi_dma_sync(dma_hdl, (off_t)hcidescp,
			    sizeof (hci1394_desc_imm_t), DDI_DMA_SYNC_FORCPU);
			if (err != DDI_SUCCESS) {
				uvp->upd_status = IXL1394_EINTERNAL_ERROR;

				TNF_PROBE_0_DEBUG(
				    hci1394_ixl_update_perform_exit,
				    HCI1394_TNF_HAL_STACK_ISOCH, "");
				return (DDI_FAILURE);
			}

			/*
			 * this preserves interrupt enable bits, et al
			 * in each desc block hdr
			 */
			desc_hdr = ddi_get32(acc_hdl, &hcidescp->hdr);
			desc_hdr = (desc_hdr & ~DESC_HDR_REQCOUNT_MASK) |
			    uvp->hcihdr;
			ddi_put32(acc_hdl, &hcidescp->hdr, desc_hdr);

			/* Sync descriptor for device (desc was modified) */
			err = ddi_dma_sync(dma_hdl, (off_t)hcidescp,
			    sizeof (hci1394_desc_imm_t), DDI_DMA_SYNC_FORDEV);
			if (err != DDI_SUCCESS) {
				uvp->upd_status = IXL1394_EINTERNAL_ERROR;

				TNF_PROBE_0_DEBUG(
				    hci1394_ixl_update_perform_exit,
				    HCI1394_TNF_HAL_STACK_ISOCH, "");
				return (DDI_FAILURE);
			}
		}

		/*
		 * set old ixl recv buf sizes and buffers from
		 * new ixl recv pkt cmd
		 */
		old_xfer_buf_ixlp->pkt_size = new_xfer_buf_ixlp->pkt_size;
		old_xfer_buf_ixlp->size = new_xfer_buf_ixlp->size;
		old_xfer_buf_ixlp->ixl_buf.ixldmac_addr =
		    new_xfer_buf_ixlp->ixl_buf.ixldmac_addr;
		old_xfer_buf_ixlp->mem_bufp = new_xfer_buf_ixlp->mem_bufp;
		break;
	}
	default:
		/* ixl command being updated must be one of above, else error */
		uvp->upd_status = IXL1394_EINTERNAL_ERROR;

		TNF_PROBE_0_DEBUG(hci1394_ixl_update_perform_exit,
		    HCI1394_TNF_HAL_STACK_ISOCH, "");
		return (DDI_FAILURE);
	}

	/* hit the WAKE bit in the context control register */
	if (ctxtp->ctxt_flags & HCI1394_ISO_CTXT_RECV) {
		HCI1394_IRCTXT_CTRL_SET(uvp->soft_statep, ctxtp->ctxt_index,
		    0, 0, 0, 0, 0, 1 /* wake */);
	} else {
		HCI1394_ITCTXT_CTRL_SET(uvp->soft_statep, ctxtp->ctxt_index,
		    0, 0, 0, 1 /* wake */);
	}

	/* perform update completed successfully */
	TNF_PROBE_0_DEBUG(hci1394_ixl_update_perform_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
	return (DDI_SUCCESS);
}

/*
 * hci1394_ixl_update_evaluate()
 *    Evaluate where the hardware is in running through the DMA descriptor
 *    blocks.
 */
static int
hci1394_ixl_update_evaluate(hci1394_ixl_update_vars_t *uvp)
{
	hci1394_iso_ctxt_t	*ctxtp;
	ixl1394_command_t	*ixlp;
	int			ixldepth;
	int			ii;

	TNF_PROBE_0_DEBUG(hci1394_ixl_update_evaluate_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	ctxtp = uvp->ctxtp;

	ixlp = NULL;
	ixldepth = 0xFFFFFFFF;

	/*
	 * repeat until IXL execution status evaluation function returns error
	 * or until pointer to currently executing IXL command and its depth
	 * stablize
	 */
	while ((ixlp != ctxtp->ixl_execp) ||
	    (ixldepth != ctxtp->ixl_exec_depth)) {

		ixlp = ctxtp->ixl_execp;
		ixldepth = ctxtp->ixl_exec_depth;

		/*
		 * call IXL execution status evaluation (ixl_dma_sync)
		 * function returning if error (HCI1394_IXL_INTR_DMALOST is
		 * only error condition).
		 *
		 * Note: interrupt processing function can only return one of
		 * the following statuses here:
		 *    HCI1394_IXL_INTR_NOERROR, HCI1394_IXL_INTR_DMASTOP,
		 *    HCI1394_IXL_INTR_DMALOST
		 *
		 * it can not return the following status here:
		 *    HCI1394_IXL_INTR_NOADV
		 *
		 * Don't need to grab the lock here... for the same reason
		 * explained in hci1394_ixl_update_endup() above.
		 */
		ctxtp->intr_flags &= ~HCI1394_ISO_CTXT_INTRSET;
		if (hci1394_ixl_dma_sync(uvp->soft_statep, ctxtp) ==
		    HCI1394_IXL_INTR_DMALOST) {

			/* return post-perform update failed status */
			uvp->upd_status = IXL1394_EPOST_UPD_DMALOST;

			TNF_PROBE_0_DEBUG(hci1394_ixl_update_evaluate_exit,
			    HCI1394_TNF_HAL_STACK_ISOCH, "");
			return (DDI_FAILURE);
		}
	}

	/*
	 * if the currently executing IXL command is one of the IXL_MAX_LOCN
	 * locations saved before update was performed, return update
	 * successful status.
	 */
	for (ii = 0; ii < IXL_MAX_LOCN; ii++) {
		if ((uvp->locn_info[ii].ixlp == ixlp) &&
		    (uvp->locn_info[ii].ixldepth == ixldepth)) {

			TNF_PROBE_0_DEBUG(hci1394_ixl_update_evaluate_exit,
			    HCI1394_TNF_HAL_STACK_ISOCH, "");
			return (DDI_SUCCESS);
		}
	}

	/*
	 * else return post-perform update failed status.
	 * note: later can make more sophisticated evaluations about where
	 * execution processing went, and if update has really failed.
	 */
	uvp->upd_status = IXL1394_EPOST_UPD_DMALOST;

	TNF_PROBE_0_DEBUG(hci1394_ixl_update_evaluate_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
	return (DDI_FAILURE);
}

/*
 * hci1394_ixl_update_analysis()
 *    Determine if the hardware is within the range we expected it to be.
 *    If so the update succeeded.
 */
static int
hci1394_ixl_update_analysis(hci1394_ixl_update_vars_t *uvp)
{
	hci1394_iso_ctxt_t	*ctxtp;
	ixl1394_command_t	*ixlp;
	int			ixldepth;
	int			ii;
	int			status;

	TNF_PROBE_0_DEBUG(hci1394_ixl_update_analysis_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	ctxtp = uvp->ctxtp;

	ixlp = NULL;
	ixldepth = 0xFFFFFFFF;

	/*
	 * repeat until ixl execution status evaluation function returns error
	 * or until pointer to currently executing ixl command and its depth
	 * stablize.
	 */
	while ((ixlp != ctxtp->ixl_execp) ||
	    (ixldepth != ctxtp->ixl_exec_depth)) {

		ixlp = ctxtp->ixl_execp;
		ixldepth = ctxtp->ixl_exec_depth;

		/*
		 * call ixl execution status evaluation (interrupt processing).
		 * set IXL1394_EIDU_PRE_UPD_DMALOST if status INTR_DMALOST and
		 * return.
		 *
		 * Note: interrupt processing function can only return one of
		 * the following statuses here:
		 *    HCI1394_IXL_INTR_NOERROR, HCI1394_IXL_INTR_DMASTOP or
		 *    HCI1394_IXL_INTR_DMALOST
		 *
		 * it can not return the following status here:
		 *    HCI1394_IXL_INTR_NOADV
		 *
		 * Don't need to grab the lock here... for the same reason
		 * explained in hci1394_ixl_update_endup() above.
		 */
		ctxtp->intr_flags &= ~HCI1394_ISO_CTXT_INTRSET;

		status = hci1394_ixl_dma_sync(uvp->soft_statep, ctxtp);
		if (status == HCI1394_IXL_INTR_DMALOST) {
			/*
			 * set pre-update dma processing lost status and
			 * return error
			 */
			uvp->upd_status = IXL1394_EPRE_UPD_DMALOST;

			TNF_PROBE_0_DEBUG(hci1394_ixl_update_analysis_exit,
			    HCI1394_TNF_HAL_STACK_ISOCH, "");
			return (DDI_FAILURE);
		}
	}

	/*
	 * save locations of currently executing ixl command and the
	 * 3 following it.
	 */
	hci1394_ixl_update_set_locn_info(uvp);

	/*
	 * if xfer_ixl_cmd associated with the IXL_command being updated is one
	 * of the saved (currently executing) IXL commands, risk is too great to
	 * perform update now, set IXL1394_ERISK_PROHIBITS_UPD status and
	 * return error.
	 *
	 * Note: later can implement more sophisticated risk override
	 * evaluations and processing.
	 */
	for (ii = 0; ii < IXL_MAX_LOCN; ii++) {

		if ((uvp->locn_info[ii].ixlp == uvp->ixlxferp) &&
		    (uvp->locn_info[ii].ixldepth >= uvp->ixldepth) &&
		    (uvp->locn_info[ii].ixldepth <
		    (uvp->ixldepth + uvp->ixlcount))) {

			uvp->upd_status = IXL1394_ERISK_PROHIBITS_UPD;

			TNF_PROBE_0_DEBUG(hci1394_ixl_update_analysis_exit,
			    HCI1394_TNF_HAL_STACK_ISOCH, "");
			return (DDI_FAILURE);
		}
	}

	/* is save for update to be performed, return ok status */
	TNF_PROBE_0_DEBUG(hci1394_ixl_update_analysis_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
	return (DDI_SUCCESS);
}

/*
 * hci1394_ixl_update_set_locn_info()
 *    set up the local list of the IXL_MAX_LOCN next commandPtr locations we
 *    expect the hardware to get to in the next 125 microseconds.
 */
static void
hci1394_ixl_update_set_locn_info(hci1394_ixl_update_vars_t *uvp)
{
	hci1394_iso_ctxt_t	*ctxtp;
	ixl1394_command_t	*ixlp;
	int			ixldepth;
	int			ii;

	TNF_PROBE_0_DEBUG(hci1394_ixl_update_set_locn_info_enter,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");

	/*
	 * find next xfer start ixl command, starting with current ixl command
	 * where execution last left off
	 */
	ctxtp = uvp->ctxtp;

	ixldepth = ctxtp->ixl_exec_depth;
	(void) hci1394_ixl_find_next_exec_xfer(ctxtp->ixl_execp, NULL, &ixlp);

	/*
	 * if the current IXL command wasn't a xfer start command, then reset
	 * the depth to 0 for xfer command found
	 */
	if (ixlp != ctxtp->ixl_execp)
		ixldepth = 0;

	/*
	 * save xfer start IXL command & its depth and also save location and
	 * depth of the next IXL_MAX_LOCN-1 xfer start IXL commands following
	 * it (if any)
	 */
	for (ii = 0; ii < IXL_MAX_LOCN; ii++) {
		uvp->locn_info[ii].ixlp = ixlp;
		uvp->locn_info[ii].ixldepth = ixldepth;

		if (ixlp) {
			/*
			 * if more dma commands generated by this xfer command
			 * still follow, use them. else, find the next xfer
			 * start IXL command and set its depth to 0.
			 */
			if (++ixldepth >= ((hci1394_xfer_ctl_t *)
			    ixlp->compiler_privatep)->cnt) {

				(void) hci1394_ixl_find_next_exec_xfer(
				    ixlp->next_ixlp, NULL, &ixlp);
				ixldepth = 0;
			}
		}
	}
	TNF_PROBE_0_DEBUG(hci1394_ixl_update_set_locn_info_exit,
	    HCI1394_TNF_HAL_STACK_ISOCH, "");
}
