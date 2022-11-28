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
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * hci1394_isoch.c
 *    HCI HAL isochronous interface routines.  Contains routines used
 *    internally within the HAL to manage isochronous contexts, and
 *    also routines called from the Services Layer to manage an isochronous
 *    DMA resource.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/1394/h1394.h>
#include <sys/1394/adapters/hci1394.h>

/*
 * Patchable variable used to indicate the number of microseconds to wait
 * for an isoch ctxt to stop ("active" goes low) after clearing the "run"
 * bit
 */
uint_t hci1394_iso_ctxt_stop_delay_uS = 1000;

/*
 * Number of microseconds to wait in hci1394_do_stop() for an isoch ctxt
 * interrupt handler to complete. Experiments showed that in some cases
 * the timeout needed was as long as 2 seconds. This is probably due to
 * significant interrupt processing overhead for certain IXL chains.
 */
uint_t hci1394_iso_ctxt_stop_intr_timeout_uS = 5 * 1000000;

/*
 * hci1394_isoch_init()
 *    Initialize the isochronous dma soft state.
 */
void
hci1394_isoch_init(hci1394_drvinfo_t *drvinfo,  hci1394_ohci_handle_t ohci,
    hci1394_isoch_handle_t *isoch_hdl)
{
	hci1394_isoch_t *isochp;
	int i;

	ASSERT(drvinfo != NULL);
	ASSERT(isoch_hdl != NULL);

	isochp = kmem_alloc(sizeof (hci1394_isoch_t), KM_SLEEP);

	/* initialize contexts */
	for (i = 0; i < HCI1394_MAX_ISOCH_CONTEXTS; i++) {
		isochp->ctxt_xmit[i].ctxt_index = i;

		/* init context flags to 0 */
		isochp->ctxt_xmit[i].ctxt_flags = 0;

		mutex_init(&isochp->ctxt_xmit[i].intrprocmutex, NULL,
		    MUTEX_DRIVER, drvinfo->di_iblock_cookie);
		cv_init(&isochp->ctxt_xmit[i].intr_cv, NULL,
		    CV_DRIVER, NULL);

		isochp->ctxt_recv[i].ctxt_index = i;
		isochp->ctxt_recv[i].ctxt_flags = HCI1394_ISO_CTXT_RECV;
		mutex_init(&isochp->ctxt_recv[i].intrprocmutex, NULL,
		    MUTEX_DRIVER, drvinfo->di_iblock_cookie);
		cv_init(&isochp->ctxt_recv[i].intr_cv, NULL,
		    CV_DRIVER, NULL);
	}

	/* initialize the count for allocated isoch dma */
	isochp->isoch_dma_alloc_cnt = 0;

	/* initialize the cycle_lost_thresh struct */
	isochp->cycle_lost_thresh.last_intr_time  = 0;
	isochp->cycle_lost_thresh.delta_t_counter = 0;
	isochp->cycle_lost_thresh.delta_t_thresh  = HCI1394_CYC_LOST_DELTA;
	isochp->cycle_lost_thresh.counter_thresh  = HCI1394_CYC_LOST_COUNT;

	/* initialize the cycle_incon_thresh struct */
	isochp->cycle_incon_thresh.last_intr_time  = 0;
	isochp->cycle_incon_thresh.delta_t_counter = 0;
	isochp->cycle_incon_thresh.delta_t_thresh  = HCI1394_CYC_INCON_DELTA;
	isochp->cycle_incon_thresh.counter_thresh  = HCI1394_CYC_INCON_COUNT;

	/* determine number of contexts supported */
	isochp->ctxt_xmit_count = hci1394_ohci_it_ctxt_count_get(ohci);
	isochp->ctxt_recv_count = hci1394_ohci_ir_ctxt_count_get(ohci);

	/* the isochronous context mutex is used during some error interrupts */
	mutex_init(&isochp->ctxt_list_mutex, NULL, MUTEX_DRIVER,
	    drvinfo->di_iblock_cookie);

	*isoch_hdl = isochp;
}

/*
 * hci1394_isoch_fini()
 *    Cleanup after hci1394_isoch_init.  This should be called during detach.
 */
void
hci1394_isoch_fini(hci1394_isoch_handle_t *isoch_hdl)
{
	hci1394_isoch_t *isochp;
	int i;

	ASSERT(isoch_hdl != NULL);

	isochp = *isoch_hdl;

	for (i = 0; i < HCI1394_MAX_ISOCH_CONTEXTS; i++) {
		mutex_destroy(&isochp->ctxt_xmit[i].intrprocmutex);
		mutex_destroy(&isochp->ctxt_recv[i].intrprocmutex);
		cv_destroy(&isochp->ctxt_xmit[i].intr_cv);
		cv_destroy(&isochp->ctxt_recv[i].intr_cv);
	}

	mutex_destroy(&isochp->ctxt_list_mutex);
	kmem_free(isochp, sizeof (hci1394_isoch_t));
	*isoch_hdl = NULL;
}


/*
 * hci1394_isoch_resume()
 *    There is currently nothing to do for resume.  This is a placeholder.
 */
/* ARGSUSED */
int
hci1394_isoch_resume(hci1394_state_t *soft_state)
{
	return (DDI_SUCCESS);
}

/*
 * hci1394_alloc_isoch_dma ()
 *    Called by the Services Layer. Used to allocate a local Isoch DMA context.
 *    Goes through appropriate context list (either transmit or receive)
 *    looking for an unused context.  Fails if none found.
 *    Then compiles the provided IXL program.
 */
int
hci1394_alloc_isoch_dma(void *hal_private, id1394_isoch_dmainfo_t *idi,
    void **hal_idma_handlep, int *resultp)
{
	int		    i;
	int		    err;
	hci1394_state_t	    *soft_statep = (hci1394_state_t *)hal_private;
	hci1394_isoch_t	    *isochp;
	hci1394_iso_ctxt_t  *ctxtp;


	ASSERT(soft_statep != NULL);
	ASSERT(hal_idma_handlep != NULL);

	isochp = soft_statep->isoch;
	*hal_idma_handlep = NULL;

	/*
	 * find context to use based on whether talking(send) or listening(recv)
	 */
	mutex_enter(&isochp->ctxt_list_mutex);
	if ((idi->idma_options & ID1394_TALK) != 0) {
		/* TRANSMIT */

		/*
		 * search through list of hardware supported contexts for
		 * one that's not inuse
		 */
		for (i = 0; i < isochp->ctxt_xmit_count; i++) {
			if ((isochp->ctxt_xmit[i].ctxt_flags &
			    HCI1394_ISO_CTXT_INUSE) == 0) {
				break;
			}
		}

		/* if there aren't any left, return an error */
		if (i >= isochp->ctxt_xmit_count) {
			mutex_exit(&isochp->ctxt_list_mutex);
			*resultp = IXL1394_ENO_DMA_RESRCS;
			return (DDI_FAILURE);
		}

		/* mark inuse and set up handle to context */
		isochp->ctxt_xmit[i].ctxt_flags |= HCI1394_ISO_CTXT_INUSE;
		ctxtp = &isochp->ctxt_xmit[i];
		isochp->ctxt_xmit[i].ctxt_regsp =
		    &soft_statep->ohci->ohci_regs->it[i];
	} else {
		/* RECEIVE */

		/* search thru implemented contexts for one that's available */
		for (i = 0; i < isochp->ctxt_recv_count; i++) {
			if ((isochp->ctxt_recv[i].ctxt_flags &
			    HCI1394_ISO_CTXT_INUSE) == 0) {
				break;
			}
		}

		/* if there aren't any left, return an error */
		/* XXX support for multi-chan could go here */
		if (i >= isochp->ctxt_recv_count) {
			mutex_exit(&isochp->ctxt_list_mutex);
			*resultp = IXL1394_ENO_DMA_RESRCS;
			return (DDI_FAILURE);
		}

		/* set up receive mode flags */
		if ((idi->idma_options & ID1394_LISTEN_BUF_MODE) != 0) {
			isochp->ctxt_recv[i].ctxt_flags |=
			    HCI1394_ISO_CTXT_BFFILL;
		}
		if ((idi->idma_options & ID1394_RECV_HEADERS) != 0) {
			isochp->ctxt_recv[i].ctxt_flags |=
			    HCI1394_ISO_CTXT_RHDRS;
		}

		/* mark inuse and set up handle to context */
		isochp->ctxt_recv[i].ctxt_flags |= HCI1394_ISO_CTXT_INUSE;
		ctxtp = &isochp->ctxt_recv[i];

		isochp->ctxt_recv[i].ctxt_regsp = (hci1394_ctxt_regs_t *)
		    &soft_statep->ohci->ohci_regs->ir[i];
	}
	mutex_exit(&isochp->ctxt_list_mutex);

	/* before compiling, set up some default context values */
	ctxtp->isochan = idi->channel_num;
	ctxtp->default_tag = idi->default_tag;
	ctxtp->default_sync = idi->default_sync;
	ctxtp->global_callback_arg = idi->global_callback_arg;
	ctxtp->isoch_dma_stopped = idi->isoch_dma_stopped;
	ctxtp->idma_evt_arg = idi->idma_evt_arg;
	ctxtp->isospd = idi->it_speed;
	ctxtp->default_skipmode = idi->it_default_skip;
	ctxtp->default_skiplabelp = idi->it_default_skiplabel;

	err = hci1394_compile_ixl(soft_statep, ctxtp, idi->ixlp, resultp);


	/*
	 * if the compile failed, clear the appropriate flags.
	 * Note that the context mutex is needed to eliminate race condition
	 * with cycle_inconsistent and other error intrs.
	 */
	if (err != DDI_SUCCESS) {

		mutex_enter(&isochp->ctxt_list_mutex);
		if ((ctxtp->ctxt_flags & HCI1394_ISO_CTXT_RECV) != 0) {
			/* undo the set up of receive mode flags */
			isochp->ctxt_recv[i].ctxt_flags &=
			    ~HCI1394_ISO_CTXT_BFFILL;
			isochp->ctxt_recv[i].ctxt_flags &=
			    ~HCI1394_ISO_CTXT_RHDRS;
		}
		ctxtp->ctxt_flags &= ~HCI1394_ISO_CTXT_INUSE;
		mutex_exit(&isochp->ctxt_list_mutex);

		return (DDI_FAILURE);
	}

	/*
	 * Update count of allocated isoch dma (and enable interrupts
	 * if necessary)
	 */
	mutex_enter(&isochp->ctxt_list_mutex);
	if (isochp->isoch_dma_alloc_cnt == 0) {
		hci1394_ohci_intr_clear(soft_statep->ohci,
		    OHCI_INTR_CYC_LOST | OHCI_INTR_CYC_INCONSISTENT);
		hci1394_ohci_intr_enable(soft_statep->ohci,
		    OHCI_INTR_CYC_LOST | OHCI_INTR_CYC_INCONSISTENT);
	}
	isochp->isoch_dma_alloc_cnt++;
	mutex_exit(&isochp->ctxt_list_mutex);

	/* No errors, so all set to go.  initialize interrupt/execution flags */
	ctxtp->intr_flags = 0;

	*hal_idma_handlep = ctxtp;
	return (DDI_SUCCESS);
}


/*
 * hci1394_start_isoch_dma()
 *    Used to start an allocated isochronous dma resource.
 *    Sets the context's command ptr to start at the first IXL,
 *    sets up IR match register (if IR), and enables the context_control
 *    register RUN bit.
 */
/* ARGSUSED */
int
hci1394_start_isoch_dma(void *hal_private, void *hal_isoch_dma_handle,
    id1394_isoch_dma_ctrlinfo_t *idma_ctrlinfop, uint_t flags, int *result)
{
	hci1394_state_t	    *soft_statep = (hci1394_state_t *)hal_private;
	hci1394_iso_ctxt_t  *ctxtp;
	int		    tag0, tag1, tag2, tag3;

	/* pick up the context pointer from the private idma data */
	ctxtp = (hci1394_iso_ctxt_t *)hal_isoch_dma_handle;

	ASSERT(hal_private != NULL);
	ASSERT(ctxtp != NULL);
	ASSERT(idma_ctrlinfop != NULL);

	/* if the context is already running, just exit.  else set running */
	mutex_enter(&soft_statep->isoch->ctxt_list_mutex);
	if ((ctxtp->ctxt_flags & HCI1394_ISO_CTXT_RUNNING) != 0) {

		mutex_exit(&soft_statep->isoch->ctxt_list_mutex);

		return (DDI_SUCCESS);
	}
	ctxtp->ctxt_flags |= HCI1394_ISO_CTXT_RUNNING;
	mutex_exit(&soft_statep->isoch->ctxt_list_mutex);

	ctxtp->intr_flags &= ~HCI1394_ISO_CTXT_STOP;

	/* initialize context values */
	ctxtp->ixl_execp = ctxtp->ixl_firstp;	/* start of ixl chain */
	ctxtp->ixl_exec_depth = 0;
	ctxtp->dma_last_time = 0;
	ctxtp->rem_noadv_intrs = ctxtp->max_noadv_intrs;

	/*
	 * clear out hci DMA descriptor status to start with clean slate.
	 * note that statuses could be set if context was previously started
	 * then stopped.
	 */
	hci1394_ixl_reset_status(ctxtp);

	/* set up registers, and start isoch */
	if (ctxtp->ctxt_flags & HCI1394_ISO_CTXT_RECV) {

		/* set context's command ptr to the first descriptor */
		hci1394_ohci_ir_cmd_ptr_set(soft_statep->ohci,
		    ctxtp->ctxt_index, ctxtp->dma_mem_execp);

		/*
		 * determine correct tag values.  map target's requested 2-bit
		 * tag into one of the 4 openHCI tag bits.
		 * XXX for now the t1394 api only supports a single tag setting,
		 * whereas openhci supports a set of (non-mutually exclusive)
		 * valid tags. if the api changes to support multiple
		 * simultaneous tags, then this code must be changed.
		 */
		tag0 = 0;
		tag1 = 1;
		tag2 = 2;
		tag3 = 3;
		if (ctxtp->default_tag == 0x0)
			tag0 = 1;
		else if (ctxtp->default_tag == 0x1)
			tag1 = 1;
		else if (ctxtp->default_tag == 0x2)
			tag2 = 1;
		else if (ctxtp->default_tag == 0x3)
			tag3 = 1;

		/* set match register as desired */
		HCI1394_IRCTXT_MATCH_WRITE(soft_statep, ctxtp->ctxt_index, tag3,
		    tag2, tag1, tag0,
		    idma_ctrlinfop->start_cycle /* cycleMatch */,
		    ctxtp->default_sync /* sync */, 0 /* tag1sync */,
		    ctxtp->isochan /* chan */);

		/* clear all bits in context ctrl reg to init to known state */
		HCI1394_IRCTXT_CTRL_CLR(soft_statep, ctxtp->ctxt_index,
		    (uint32_t)1, 1, 1, 1, 1);

		/* set desired values in context control register */
		HCI1394_IRCTXT_CTRL_SET(soft_statep, ctxtp->ctxt_index,
		    (ctxtp->ctxt_flags & HCI1394_ISO_CTXT_BFFILL) != 0 /* bf */,
		    (ctxtp->ctxt_flags & HCI1394_ISO_CTXT_RHDRS) != 0 /* hdr */,
		    (flags & ID1394_START_ON_CYCLE) != 0 /* match enbl */,
		    0 /* multi-chan mode */, 1 /* run */, 0 /* wake */);

		/*
		 * before enabling interrupts, make sure any vestige interrupt
		 * event (from a previous use) is cleared.
		 */
		hci1394_ohci_ir_intr_clear(soft_statep->ohci,
		    (uint32_t)(0x1 << ctxtp->ctxt_index));

		/* enable interrupts for this IR context */
		hci1394_ohci_ir_intr_enable(soft_statep->ohci,
		    (uint32_t)(0x1 << ctxtp->ctxt_index));

	} else {
		/* TRANSMIT */

		/* set context's command ptr to the first descriptor */
		hci1394_ohci_it_cmd_ptr_set(soft_statep->ohci,
		    ctxtp->ctxt_index, ctxtp->dma_mem_execp);

		/* set desired values in context control register */
		HCI1394_ITCTXT_CTRL_SET(soft_statep, ctxtp->ctxt_index,
		    ((flags & ID1394_START_ON_CYCLE) != 0) /* match enable */,
		    idma_ctrlinfop->start_cycle /* cycle Match */,
		    1 /* run */, 0 /* wake */);

		/*
		 * before enabling interrupts, make sure any vestige interrupt
		 * event (from a previous use) is cleared.
		 */
		hci1394_ohci_it_intr_clear(soft_statep->ohci,
		    (uint32_t)(0x1 << ctxtp->ctxt_index));

		/* enable interrupts for this IT context */
		hci1394_ohci_it_intr_enable(soft_statep->ohci,
		    (uint32_t)(0x1 << ctxtp->ctxt_index));
	}

	return (DDI_SUCCESS);
}

/*
 * hci1394_update_isoch_dma()
 *
 * Returns DDI_SUCCESS, or DDI_FAILURE.  If DDI_FAILURE, then resultp
 * contains the error code.
 */
/* ARGSUSED */
int
hci1394_update_isoch_dma(void *hal_private, void *hal_isoch_dma_handle,
    id1394_isoch_dma_updateinfo_t *idma_updateinfop, uint_t flags, int *resultp)
{
	hci1394_state_t	    *soft_statep = (hci1394_state_t *)hal_private;
	hci1394_iso_ctxt_t  *ctxtp;
	ixl1394_command_t   *cur_new_ixlp;
	ixl1394_command_t   *cur_orig_ixlp;
	int		    ii;
	int		    err = DDI_SUCCESS;

	/* pick up the context pointer from the private idma data */
	ctxtp = (hci1394_iso_ctxt_t *)hal_isoch_dma_handle;

	ASSERT(hal_private != NULL);
	ASSERT(ctxtp != NULL);
	ASSERT(idma_updateinfop != NULL);

	/*
	 * regardless of the type of context (IR or IT), loop through each
	 * command pair (one from new, one from orig), updating the relevant
	 * fields of orig with those from new.
	 */
	cur_new_ixlp = idma_updateinfop->temp_ixlp;
	cur_orig_ixlp = idma_updateinfop->orig_ixlp;

	ASSERT(cur_new_ixlp != NULL);
	ASSERT(cur_orig_ixlp != NULL);

	for (ii = 0; (ii < idma_updateinfop->ixl_count) && (err == DDI_SUCCESS);
	    ii++) {

		/* error if hit a null ixl command too soon */
		if ((cur_new_ixlp == NULL) || (cur_orig_ixlp == NULL)) {
			*resultp = IXL1394_ECOUNT_MISMATCH;
			err = DDI_FAILURE;

			break;
		}

		/* proceed with the update */
		err = hci1394_ixl_update(soft_statep, ctxtp, cur_new_ixlp,
		    cur_orig_ixlp, 0, resultp);

		/* advance new and orig chains */
		cur_new_ixlp = cur_new_ixlp->next_ixlp;
		cur_orig_ixlp = cur_orig_ixlp->next_ixlp;
	}

	return (err);
}


/*
 * hci1394_stop_isoch_dma()
 *    Used to stop a "running" isochronous dma resource.
 *    This is a wrapper which calls the hci1394_do_stop to do the actual work,
 *    but NOT to invoke the target's isoch_dma_stopped().
 */
/* ARGSUSED */
void
hci1394_stop_isoch_dma(void *hal_private, void *hal_isoch_dma_handle,
    int	*result)
{
	hci1394_state_t	    *soft_statep = (hci1394_state_t *)hal_private;
	hci1394_iso_ctxt_t  *ctxtp;

	/* pick up the context pointer from the private idma data */
	ctxtp = (hci1394_iso_ctxt_t *)hal_isoch_dma_handle;

	ASSERT(hal_private != NULL);
	ASSERT(ctxtp != NULL);

	/* stop the context, do not invoke target's stop callback */
	hci1394_do_stop(soft_statep, ctxtp, B_FALSE, 0);

	/*
	 * call interrupt processing functions to bring callbacks and
	 * store_timestamps upto date.  Don't care about errors.
	 */
	hci1394_ixl_interrupt(soft_statep, ctxtp, B_TRUE);
}

/*
 * hci1394_do_stop()
 *    Used to stop a "running" isochronous dma resource.
 *    Disables interrupts for the context, clears the context_control register's
 *    RUN bit, and makes sure the ixl is up-to-date with where the hardware is
 *    in the DMA chain.
 *    If do_callback is B_TRUE, the target's isoch_dma_stopped() callback is
 *    invoked.  Caller must not hold mutex(es) if calling with
 *    do_callback==B_TRUE, otherwise mutex(es) will be held during callback.
 *    If do_callback is B_FALSE, the isoch_dma_stopped() callback is NOT
 *    invoked and stop_args is ignored.
 */
void
hci1394_do_stop(hci1394_state_t *soft_statep, hci1394_iso_ctxt_t *ctxtp,
    boolean_t do_callback, id1394_isoch_dma_stopped_t stop_args)
{
	int	count;
	clock_t	upto;

	/* already stopped? if yes, done, else set state to not-running */
	mutex_enter(&soft_statep->isoch->ctxt_list_mutex);
	if ((ctxtp->ctxt_flags & HCI1394_ISO_CTXT_RUNNING) == 0) {
		mutex_exit(&soft_statep->isoch->ctxt_list_mutex);
		return;
	}
	ctxtp->ctxt_flags &= ~HCI1394_ISO_CTXT_RUNNING;
	mutex_exit(&soft_statep->isoch->ctxt_list_mutex);

	/* turn off context control register's run bit */
	if (ctxtp->ctxt_flags & HCI1394_ISO_CTXT_RECV) {
		/* RECEIVE */

		/* disable interrupts for this IR context */
		hci1394_ohci_ir_intr_disable(soft_statep->ohci,
		    (uint32_t)(0x1 << ctxtp->ctxt_index));

		/* turn off run bit */
		HCI1394_IRCTXT_CTRL_CLR(soft_statep, ctxtp->ctxt_index,
		    0 /* bffill */, 0 /* iso hdrs */, 0 /* match enbl */,
		    0 /* multi-chan mode (not implemented) */, 1 /* run */);
	} else {
		/* TRANSMIT */

		/* disable interrupts for this IT context */
		hci1394_ohci_it_intr_disable(soft_statep->ohci,
		    (uint32_t)(0x1 << ctxtp->ctxt_index));

		/* turn of run bit */
		HCI1394_ITCTXT_CTRL_CLR(soft_statep, ctxtp->ctxt_index,
		    0 /* match enbl */, 0 /* match */, 1 /* run */);
	}

	/*
	 * If interrupt is already in progress, wait until it's over.
	 * Otherwise, set flag to prevent the new interrupt.
	 */
	mutex_enter(&ctxtp->intrprocmutex);
	ctxtp->intr_flags |= HCI1394_ISO_CTXT_STOP;
	if (ctxtp->intr_flags & HCI1394_ISO_CTXT_ININTR) {
		upto = ddi_get_lbolt() +
		    drv_usectohz(hci1394_iso_ctxt_stop_intr_timeout_uS);
		while (ctxtp->intr_flags & HCI1394_ISO_CTXT_ININTR) {
			if (cv_timedwait(&ctxtp->intr_cv, &ctxtp->intrprocmutex,
			    upto) <= 0) {
				break;
			}
		}
	}
	mutex_exit(&ctxtp->intrprocmutex);

	/* Wait until "active" bit is cleared before continuing */
	count = 0;
	while (count < hci1394_iso_ctxt_stop_delay_uS) {
		/* Has the "active" bit gone low yet? */
		if (HCI1394_ISOCH_CTXT_ACTIVE(soft_statep, ctxtp) == 0)
			break;

		/*
		 * The context did not stop yet.  Wait 1us, increment the
		 * count and try again.
		 */
		drv_usecwait(1);
		count++;
	}

	/* Check to see if we timed out or not */
	if (count >= hci1394_iso_ctxt_stop_delay_uS) {
		h1394_error_detected(soft_statep->drvinfo.di_sl_private,
		    H1394_SELF_INITIATED_SHUTDOWN, NULL);
		cmn_err(CE_WARN, "hci1394(%d): driver shutdown: "
		    "unable to stop isoch context",
		    soft_statep->drvinfo.di_instance);
		hci1394_shutdown(soft_statep->drvinfo.di_dip);

		return;
	}

	/*
	 * invoke callback as directed.  Note that the CTXT_INCALL flag is NOT
	 * needed here.  That flag is only used when we have to drop a mutex
	 * that we want to grab back again. We're not doing that here.
	 */
	if (do_callback == B_TRUE) {
		if (ctxtp->isoch_dma_stopped != NULL) {
			ctxtp->isoch_dma_stopped(
			    (struct isoch_dma_handle *)ctxtp,
			    ctxtp->idma_evt_arg, stop_args);
		}
	}
}

/*
 * hci1394_free_isoch_dma()
 *    Used to free up usage of an isochronous context and any other
 *    system resources acquired during IXL compilation.
 *    This does NOT free up the IXL and it's data buffers which is
 *    the target driver's responsibility.
 */
void
hci1394_free_isoch_dma(void *hal_private, void *hal_isoch_dma_handle)
{
	hci1394_state_t	    *soft_statep = (hci1394_state_t *)hal_private;
	hci1394_iso_ctxt_t  *ctxtp;
	hci1394_isoch_t	    *isochp;

	/* pick up the context pointer from the private idma data */
	ctxtp = (hci1394_iso_ctxt_t *)hal_isoch_dma_handle;

	ASSERT(soft_statep);
	ASSERT(ctxtp);

	isochp = soft_statep->isoch;

	mutex_enter(&soft_statep->isoch->ctxt_list_mutex);

	/* delete xfer_ctl structs and pages of allocated hci_desc memory */
	hci1394_ixl_cleanup(soft_statep, ctxtp);

	/*
	 * free context. no need to determine if xmit or recv. clearing of recv
	 * flags is harmless for xmit.
	 */
	ctxtp->ctxt_flags &= ~(HCI1394_ISO_CTXT_INUSE |
	    HCI1394_ISO_CTXT_BFFILL | HCI1394_ISO_CTXT_RHDRS);

	/*
	 * Update count of allocated isoch dma (and disable interrupts
	 * if necessary)
	 */
	ASSERT(isochp->isoch_dma_alloc_cnt > 0);
	isochp->isoch_dma_alloc_cnt--;
	if (isochp->isoch_dma_alloc_cnt == 0) {
		hci1394_ohci_intr_disable(soft_statep->ohci,
		    OHCI_INTR_CYC_LOST | OHCI_INTR_CYC_INCONSISTENT);
	}

	mutex_exit(&soft_statep->isoch->ctxt_list_mutex);
}

/*
 * hci1394_isoch_recv_count_get()
 *    returns the number of supported isoch receive contexts.
 */
int
hci1394_isoch_recv_count_get(hci1394_isoch_handle_t isoch_hdl)
{
	ASSERT(isoch_hdl != NULL);
	return (isoch_hdl->ctxt_recv_count);
}

/*
 * hci1394_isoch_recv_ctxt_get()
 *    given a context index, returns its isoch receive context struct
 */
hci1394_iso_ctxt_t *
hci1394_isoch_recv_ctxt_get(hci1394_isoch_handle_t isoch_hdl, int num)
{
	ASSERT(isoch_hdl != NULL);
	return (&isoch_hdl->ctxt_recv[num]);
}

/*
 * hci1394_isoch_xmit_count_get()
 *    returns the number of supported isoch transmit contexts.
 */
int
hci1394_isoch_xmit_count_get(hci1394_isoch_handle_t isoch_hdl)
{
	ASSERT(isoch_hdl != NULL);
	return (isoch_hdl->ctxt_xmit_count);
}

/*
 * hci1394_isoch_xmit_ctxt_get()
 *    given a context index, returns its isoch transmit context struct
 */
hci1394_iso_ctxt_t *
hci1394_isoch_xmit_ctxt_get(hci1394_isoch_handle_t isoch_hdl, int num)
{
	ASSERT(isoch_hdl != NULL);
	return (&isoch_hdl->ctxt_xmit[num]);
}

/*
 * hci1394_isoch_error_ints_enable()
 *    after bus reset, reenable CYCLE_LOST and CYCLE_INCONSISTENT
 *    interrupts (if necessary).
 */
void
hci1394_isoch_error_ints_enable(hci1394_state_t *soft_statep)
{
	ASSERT(soft_statep);

	mutex_enter(&soft_statep->isoch->ctxt_list_mutex);

	if (soft_statep->isoch->isoch_dma_alloc_cnt != 0) {
		soft_statep->isoch->cycle_lost_thresh.delta_t_counter  = 0;
		soft_statep->isoch->cycle_incon_thresh.delta_t_counter = 0;
		hci1394_ohci_intr_clear(soft_statep->ohci,
		    OHCI_INTR_CYC_LOST | OHCI_INTR_CYC_INCONSISTENT);
		hci1394_ohci_intr_enable(soft_statep->ohci,
		    OHCI_INTR_CYC_LOST | OHCI_INTR_CYC_INCONSISTENT);
	}
	mutex_exit(&soft_statep->isoch->ctxt_list_mutex);
}
