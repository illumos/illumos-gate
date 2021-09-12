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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * hci1394_ixl_isr.c
 *    Isochronous IXL Interrupt Service Routines.
 *    The interrupt handler determines which OpenHCI DMA descriptors
 *    have been executed by the hardware, tracks the path in the
 *    corresponding IXL program, issues callbacks as needed, and resets
 *    the OpenHCI DMA descriptors.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/1394/h1394.h>
#include <sys/1394/ixl1394.h>
#include <sys/1394/adapters/hci1394.h>


/* Return values for local hci1394_ixl_intr_check_done() */
#define	IXL_CHECK_LOST	(-1)	/* ixl cmd intr processing lost */
#define	IXL_CHECK_DONE	0	/* ixl cmd intr processing done */
#define	IXL_CHECK_SKIP	1	/* ixl cmd intr processing context skipped */
#define	IXL_CHECK_STOP	2	/* ixl cmd intr processing context stopped */

static boolean_t hci1394_ixl_intr_check_xfer(hci1394_state_t *soft_statep,
    hci1394_iso_ctxt_t *ctxtp, ixl1394_command_t *ixlp,
    ixl1394_command_t **ixlnextpp, uint16_t *timestampp, int *donecodep);
static int hci1394_ixl_intr_check_done(hci1394_state_t *soft_statep,
    hci1394_iso_ctxt_t *ctxtp);

/*
 * hci1394_ixl_interrupt
 *    main entry point (front-end) into interrupt processing.
 *    acquires mutex, checks if update in progress, sets flags accordingly,
 *    and calls to do real interrupt processing.
 */
void
hci1394_ixl_interrupt(hci1394_state_t *soft_statep,
    hci1394_iso_ctxt_t *ctxtp, boolean_t in_stop)
{
	uint_t	status;
	int	retcode;

	status = 1;

	/* acquire the interrupt processing context mutex */
	mutex_enter(&ctxtp->intrprocmutex);

	/* set flag to indicate that interrupt processing is required */
	ctxtp->intr_flags |= HCI1394_ISO_CTXT_INTRSET;

	/* if update proc already in progress, let it handle intr processing */
	if (ctxtp->intr_flags & HCI1394_ISO_CTXT_INUPDATE) {
		retcode = HCI1394_IXL_INTR_INUPDATE;
		status = 0;
	} else if (ctxtp->intr_flags & HCI1394_ISO_CTXT_ININTR) {
		/* else fatal error if inter processing already in progress */
		retcode = HCI1394_IXL_INTR_ININTR;
		status = 0;
	} else if (ctxtp->intr_flags & HCI1394_ISO_CTXT_INCALL) {
		/* else fatal error if callback in progress flag is set */
		retcode = HCI1394_IXL_INTR_INCALL;
		status = 0;
	} else if (!in_stop && (ctxtp->intr_flags & HCI1394_ISO_CTXT_STOP)) {
		/* context is being stopped */
		retcode = HCI1394_IXL_INTR_STOP;
		status = 0;
	}

	/*
	 * if context is available, reserve it, do interrupt processing
	 * and free it
	 */
	if (status) {
		ctxtp->intr_flags |= HCI1394_ISO_CTXT_ININTR;
		ctxtp->intr_flags &= ~HCI1394_ISO_CTXT_INTRSET;
		mutex_exit(&ctxtp->intrprocmutex);

		retcode = hci1394_ixl_dma_sync(soft_statep, ctxtp);

		mutex_enter(&ctxtp->intrprocmutex);
		ctxtp->intr_flags &= ~HCI1394_ISO_CTXT_ININTR;

		/* notify stop thread that the interrupt is finished */
		if ((ctxtp->intr_flags & HCI1394_ISO_CTXT_STOP) && !in_stop) {
			cv_signal(&ctxtp->intr_cv);
		}
	};

	/* free the intr processing context mutex before error checks */
	mutex_exit(&ctxtp->intrprocmutex);

	/* if context stopped, invoke callback */
	if (retcode == HCI1394_IXL_INTR_DMASTOP) {
		hci1394_do_stop(soft_statep, ctxtp, B_TRUE, ID1394_DONE);
	}
	/* if error, stop and invoke callback */
	if (retcode == HCI1394_IXL_INTR_DMALOST) {
		hci1394_do_stop(soft_statep, ctxtp, B_TRUE, ID1394_FAIL);
	}
}

/*
 * hci1394_ixl_dma_sync()
 *    the heart of interrupt processing, this routine correlates where the
 *    hardware is for the specified context with the IXL program.  Invokes
 *    callbacks as needed.  Also called by "update" to make sure ixl is
 *    sync'ed up with where the hardware is.
 *    Returns one of the ixl_intr defined return codes - HCI1394_IXL_INTR...
 *    {..._DMALOST, ..._DMASTOP, ..._NOADV,... _NOERROR}
 */
int
hci1394_ixl_dma_sync(hci1394_state_t *soft_statep, hci1394_iso_ctxt_t *ctxtp)
{
	ixl1394_command_t *ixlp = NULL;	/* current ixl command */
	ixl1394_command_t *ixlnextp;	/* next ixl command */
	uint16_t	ixlopcode;
	uint16_t	timestamp;
	int		donecode;
	boolean_t	isdone;

	void (*callback)(opaque_t, struct ixl1394_callback *);

	ASSERT(MUTEX_NOT_HELD(&ctxtp->intrprocmutex));

	/* xfer start ixl cmd where last left off */
	ixlnextp = ctxtp->ixl_execp;

	/* last completed descriptor block's timestamp  */
	timestamp = ctxtp->dma_last_time;

	/*
	 * follow execution path in IXL, until find dma descriptor in IXL
	 * xfer command whose status isn't set or until run out of IXL cmds
	 */
	while (ixlnextp != NULL) {
		ixlp = ixlnextp;
		ixlnextp = ixlp->next_ixlp;
		ixlopcode = ixlp->ixl_opcode & ~IXL1394_OPF_UPDATE;

		/*
		 * process IXL commands: xfer start, callback, store timestamp
		 * and jump and ignore the others
		 */

		/* determine if this is an xfer start IXL command */
		if (((ixlopcode & IXL1394_OPF_ISXFER) != 0) &&
		    ((ixlopcode & IXL1394_OPTY_MASK) != 0)) {

			/* process xfer cmd to see if HW has been here */
			isdone = hci1394_ixl_intr_check_xfer(soft_statep, ctxtp,
			    ixlp, &ixlnextp, &timestamp, &donecode);

			if (isdone == B_TRUE) {
				return (donecode);
			}

			/* continue to process next IXL command */
			continue;
		}

		/* else check if IXL cmd - jump, callback or store timestamp */
		switch (ixlopcode) {
		case IXL1394_OP_JUMP:
			/*
			 * set next IXL cmd to label ptr in current IXL jump cmd
			 */
			ixlnextp = ((ixl1394_jump_t *)ixlp)->label;
			break;

		case IXL1394_OP_STORE_TIMESTAMP:
			/*
			 * set last timestamp value recorded into current IXL
			 * cmd
			 */
			((ixl1394_store_timestamp_t *)ixlp)->timestamp =
			    timestamp;
			break;

		case IXL1394_OP_CALLBACK:
			/*
			 * if callback function is specified, call it with IXL
			 * cmd addr.  Make sure to grab the lock before setting
			 * the "in callback" flag in intr_flags.
			 */
			mutex_enter(&ctxtp->intrprocmutex);
			ctxtp->intr_flags |= HCI1394_ISO_CTXT_INCALL;
			mutex_exit(&ctxtp->intrprocmutex);

			callback = ((ixl1394_callback_t *)ixlp)->callback;
			if (callback != NULL) {
				callback(ctxtp->global_callback_arg,
				    (ixl1394_callback_t *)ixlp);
			}

			/*
			 * And grab the lock again before clearing
			 * the "in callback" flag.
			 */
			mutex_enter(&ctxtp->intrprocmutex);
			ctxtp->intr_flags &= ~HCI1394_ISO_CTXT_INCALL;
			mutex_exit(&ctxtp->intrprocmutex);
			break;
		}
	}

	/*
	 * If we jumped to NULL because of an updateable JUMP, set ixl_execp
	 * back to ixlp.  The destination label might get updated to a
	 * non-NULL value.
	 */
	if ((ixlp != NULL) && (ixlp->ixl_opcode == IXL1394_OP_JUMP_U)) {
		ctxtp->ixl_execp = ixlp;
		return (HCI1394_IXL_INTR_NOERROR);
	}

	/* save null IXL cmd and depth and last timestamp */
	ctxtp->ixl_execp = NULL;
	ctxtp->ixl_exec_depth = 0;
	ctxtp->dma_last_time = timestamp;

	ctxtp->rem_noadv_intrs = 0;


	/* return stopped status if at end of IXL cmds & context stopped */
	if (HCI1394_ISOCH_CTXT_ACTIVE(soft_statep, ctxtp) == 0) {
		return (HCI1394_IXL_INTR_DMASTOP);
	}

	/* else interrupt processing is lost */
	return (HCI1394_IXL_INTR_DMALOST);
}

/*
 * hci1394_ixl_intr_check_xfer()
 *    Process given IXL xfer cmd, checking status of each dma descriptor block
 *    for the command until find one whose status isn't set or until full depth
 *    reached at current IXL command or until find hardware skip has occurred.
 *
 *    Returns B_TRUE if processing should terminate (either have stopped
 *    or encountered an error), and B_FALSE if it should continue looking.
 *    If B_TRUE, donecodep contains the reason: HCI1394_IXL_INTR_DMALOST,
 *    HCI1394_IXL_INTR_DMASTOP, HCI1394_IXL_INTR_NOADV, or
 *    HCI1394_IXL_INTR_NOERROR.  NOERROR means that the current location
 *    has been determined and do not need to look further.
 */
static boolean_t
hci1394_ixl_intr_check_xfer(hci1394_state_t *soft_statep,
    hci1394_iso_ctxt_t *ctxtp, ixl1394_command_t *ixlp,
    ixl1394_command_t **ixlnextpp, uint16_t *timestampp, int *donecodep)
{
	uint_t		    dma_advances;
	int		    intrstatus;
	uint_t		    skipped;
	hci1394_xfer_ctl_t  *xferctlp;
	uint16_t	    ixldepth;
	uint16_t	    ixlopcode;

	*donecodep = 0;
	dma_advances = 0;
	ixldepth = ctxtp->ixl_exec_depth;
	ixlopcode = ixlp->ixl_opcode & ~IXL1394_OPF_UPDATE;

	/* get control struct for this xfer start IXL command */
	xferctlp = (hci1394_xfer_ctl_t *)ixlp->compiler_privatep;

	skipped = 0;
	while ((skipped == 0) && (ixldepth < xferctlp->cnt)) {
		/*
		 * check if status is set in dma descriptor
		 * block at cur depth in cur xfer start IXL cmd
		 */
		if (hci1394_ixl_check_status(&xferctlp->dma[ixldepth],
		    ixlopcode, timestampp, B_TRUE) != 0) {

			/* advance depth to next desc block in cur IXL cmd */
			ixldepth++;

			/*
			 * count dma desc blks whose status was set
			 * (i.e. advanced to next dma desc)
			 */
			dma_advances++;
			continue;
		}

		/* if get to here, status is not set */

		/*
		 * cur IXL cmd dma desc status not set.  save IXL cur cmd
		 * and depth and last timestamp for next time.
		 */
		ctxtp->ixl_execp = ixlp;
		ctxtp->ixl_exec_depth = ixldepth;
		ctxtp->dma_last_time = *timestampp;

		/*
		 * check if dma descriptor processing location is indeterminate
		 * (lost), context has either stopped, is done, or has skipped
		 */
		intrstatus = hci1394_ixl_intr_check_done(soft_statep, ctxtp);
		if (intrstatus == IXL_CHECK_LOST) {
			/*
			 * location indeterminate, try once more to determine
			 * current state.  First, recheck if status has become
			 * set in cur dma descriptor block.  (don't reset status
			 * here if is set)
			 */
			if (hci1394_ixl_check_status(&xferctlp->dma[ixldepth],
			    ixlopcode, timestampp, 1) != B_TRUE) {
				/* resume from where we left off */
				skipped = 0;
				continue;
			}

			/*
			 * status not set, check intr processing
			 * completion status again
			 */
			if ((intrstatus = hci1394_ixl_intr_check_done(
				soft_statep, ctxtp)) == IXL_CHECK_LOST) {
				/*
				 * location still indeterminate,
				 * processing is lost
				 */
				*donecodep = HCI1394_IXL_INTR_DMALOST;
				return (B_TRUE);
			}
		}

		/*
		 * if dma processing stopped. current location has been
		 * determined.
		 */
		if (intrstatus == IXL_CHECK_STOP) {
			/*
			 * save timestamp, clear currently executing IXL
			 * command and depth. return stopped.
			 */
			ctxtp->ixl_execp = NULL;
			ctxtp->ixl_exec_depth = 0;
			ctxtp->dma_last_time = *timestampp;
			ctxtp->rem_noadv_intrs = 0;

			*donecodep = HCI1394_IXL_INTR_DMASTOP;
			return (B_TRUE);
		}

		/*
		 * dma processing done for now. current location has
		 * has been determined
		 */
		if (intrstatus == IXL_CHECK_DONE) {
			/*
			 * if in update processing call:
			 *    clear update processing flag & return ok.
			 *    if dma advances happened, reset to max allowed.
			 *    however, if none have, don't reduce remaining
			 *    amount - that's for real interrupt call to adjust.
			 */
			if (ctxtp->intr_flags & HCI1394_ISO_CTXT_INUPDATE) {

				if (dma_advances > 0) {
					ctxtp->rem_noadv_intrs =
					    ctxtp->max_noadv_intrs;
				}

				*donecodep = HCI1394_IXL_INTR_NOERROR;
				return (B_TRUE);
			}

			/*
			 * else, not in update call processing, are in normal
			 * intr call.  if no dma statuses were found set
			 * (i.e. no dma advances), reduce remaining count of
			 * interrupts allowed with no I/O completions
			 */
			if (dma_advances == 0) {
				ctxtp->rem_noadv_intrs--;
			} else {
				/*
				 * else some dma statuses were found set.
				 * reinit remaining count of interrupts allowed
				 * with no I/O completions
				 */
				ctxtp->rem_noadv_intrs = ctxtp->max_noadv_intrs;
			}

			/*
			 * if no remaining count of interrupts allowed with no
			 * I/O completions, return failure (no dma advance after
			 * max retries), else return ok
			 */
			if (ctxtp->rem_noadv_intrs == 0) {
				*donecodep = HCI1394_IXL_INTR_NOADV;
				return (B_TRUE);
			}

			*donecodep = HCI1394_IXL_INTR_NOERROR;
			return (B_TRUE);
		}

		/*
		 * else (intrstatus == IXL_CHECK_SKIP) indicating skip has
		 * occured, retrieve current IXL cmd, depth, and timestamp and
		 * continue interrupt processing
		 */
		skipped = 1;
		*ixlnextpp = ctxtp->ixl_execp;
		ixldepth = ctxtp->ixl_exec_depth;
		*timestampp = ctxtp->dma_last_time;

		/*
		 * also count as 1, intervening skips to next posted
		 * dma descriptor.
		 */
		dma_advances++;
	}

	/*
	 * if full depth reached at current IXL cmd, set back to start for next
	 * IXL xfer command that will be processed
	 */
	if ((skipped == 0) && (ixldepth >= xferctlp->cnt)) {
		ctxtp->ixl_exec_depth = 0;
	}

	/*
	 * make sure rem_noadv_intrs is reset to max if we advanced.
	 */
	if (dma_advances > 0) {
		ctxtp->rem_noadv_intrs = ctxtp->max_noadv_intrs;
	}

	/* continue to process next IXL command */
	return (B_FALSE);
}

/*
 * hci1394_ixl_intr_check_done()
 *    checks if context has stopped, or if able to match hardware location
 *    with an expected IXL program location.
 */
static int
hci1394_ixl_intr_check_done(hci1394_state_t *soft_statep,
    hci1394_iso_ctxt_t *ctxtp)
{
	ixl1394_command_t   *ixlp;
	hci1394_xfer_ctl_t  *xferctlp;
	uint_t		    ixldepth;
	hci1394_xfer_ctl_dma_t *dma;
	ddi_acc_handle_t    acc_hdl;
	ddi_dma_handle_t    dma_hdl;
	uint32_t	    desc_status;
	hci1394_desc_t	    *hcidescp;
	off_t		    hcidesc_off;
	uint32_t	    dma_cmd_cur_loc;
	uint32_t	    dma_cmd_last_loc;
	uint32_t	    dma_loc_check_enabled;
	uint32_t	    dmastartp;
	uint32_t	    dmaendp;

	uint_t		    rem_dma_skips;
	uint16_t	    skipmode;
	uint16_t	    skipdepth;
	ixl1394_command_t   *skipdestp;
	ixl1394_command_t   *skipxferp;

	/*
	 * start looking through the IXL list from the xfer start command where
	 * we last left off (for composite opcodes, need to start from the
	 * appropriate depth).
	 */

	ixlp = ctxtp->ixl_execp;
	ixldepth = ctxtp->ixl_exec_depth;

	/* control struct for xfer start IXL command */
	xferctlp = (hci1394_xfer_ctl_t *)ixlp->compiler_privatep;
	dma = &xferctlp->dma[ixldepth];

	/* determine if dma location checking is enabled */
	if ((dma_loc_check_enabled =
	    (ctxtp->ctxt_flags & HCI1394_ISO_CTXT_CMDREG)) != 0) {

		/* if so, get current dma command location */
		dma_cmd_last_loc = 0xFFFFFFFF;

		while ((dma_cmd_cur_loc = HCI1394_ISOCH_CTXT_CMD_PTR(
		    soft_statep, ctxtp)) != dma_cmd_last_loc) {

			/* retry get until location register stabilizes */
			dma_cmd_last_loc = dma_cmd_cur_loc;
		}
	}

	/*
	 * compare the (bound) address of the DMA descriptor corresponding to
	 * the current xfer IXL command against the current value in the
	 * DMA location register.  If exists and if matches, then
	 *    if context stopped, return stopped, else return done.
	 *
	 * The dma start address is the first address of the descriptor block.
	 * Since "Z" is a count of 16-byte descriptors in the block, calculate
	 * the end address by adding Z*16 to the start addr.
	 */
	dmastartp = dma->dma_bound & ~DESC_Z_MASK;
	dmaendp = dmastartp + ((dma->dma_bound & DESC_Z_MASK) << 4);

	if (dma_loc_check_enabled &&
	    ((dma_cmd_cur_loc >= dmastartp) && (dma_cmd_cur_loc < dmaendp))) {

		if (HCI1394_ISOCH_CTXT_ACTIVE(soft_statep, ctxtp) == 0) {
			return (IXL_CHECK_STOP);
		}

		return (IXL_CHECK_DONE);
	}

	/*
	 * if receive mode:
	 */
	if ((ixlp->ixl_opcode & IXL1394_OPF_ONXMIT) == 0)  {
		/*
		 * if context stopped, return stopped, else,
		 * if there is no current dma location reg, return done
		 * else return location indeterminate
		 */
		if (HCI1394_ISOCH_CTXT_ACTIVE(soft_statep, ctxtp) == 0) {
			return (IXL_CHECK_STOP);
		}
		if (!dma_loc_check_enabled) {
			return (IXL_CHECK_DONE);
		}

		return (IXL_CHECK_LOST);
	}

	/*
	 * else is xmit mode:
	 * check status of current xfer IXL command's dma descriptor
	 */
	acc_hdl  = dma->dma_buf->bi_handle;
	dma_hdl  = dma->dma_buf->bi_dma_handle;
	hcidescp = (hci1394_desc_t *)dma->dma_descp;
	hcidesc_off = (off_t)hcidescp - (off_t)dma->dma_buf->bi_kaddr;

	/* Sync the descriptor before we get the status */
	(void) ddi_dma_sync(dma_hdl, hcidesc_off, sizeof (hci1394_desc_t),
	    DDI_DMA_SYNC_FORCPU);
	desc_status = ddi_get32(acc_hdl, &hcidescp->status);

	if ((desc_status & DESC_XFER_ACTIVE_MASK) != 0) {

		/*
		 * if status is now set here, return skipped, to cause calling
		 * function to continue, even though location hasn't changed
		 */
		return (IXL_CHECK_SKIP);
	}

	/*
	 * At this point, we have gotten to a DMA descriptor with an empty
	 * status.  This is not enough information however to determine that
	 * we've found all processed DMA descriptors because during cycle-lost
	 * conditions, the HW will skip over some descriptors without writing
	 * status.  So we have to look ahead until we're convinced that the HW
	 * hasn't jumped ahead.
	 *
	 * Follow the IXL skip-to links until find one whose status is set
	 * or until dma location register (if any) matches an xfer IXL
	 * command's dma location or until have examined max_dma_skips
	 * IXL commands.
	 */
	rem_dma_skips = ctxtp->max_dma_skips;

	while (rem_dma_skips-- > 0) {

		/*
		 * get either IXL command specific or
		 * system default skipmode info
		 */
		skipdepth = 0;
		if (xferctlp->skipmodep != NULL) {
			skipmode  = xferctlp->skipmodep->skipmode;
			skipdestp = xferctlp->skipmodep->label;
			skipxferp = (ixl1394_command_t *)
			    xferctlp->skipmodep->compiler_privatep;
		} else {
			skipmode  = ctxtp->default_skipmode;
			skipdestp = ctxtp->default_skiplabelp;
			skipxferp = ctxtp->default_skipxferp;
		}

		switch (skipmode) {

		case IXL1394_SKIP_TO_SELF:
			/*
			 * mode is skip to self:
			 *   if context is stopped, return stopped, else
			 *   if dma location reg not enabled, return done
			 *   else, return location indeterminate
			 */
			if (HCI1394_ISOCH_CTXT_ACTIVE(soft_statep, ctxtp) ==
			    0) {
				return (IXL_CHECK_STOP);
			}

			if (!dma_loc_check_enabled) {
				return (IXL_CHECK_DONE);
			}

			return (IXL_CHECK_LOST);

		case IXL1394_SKIP_TO_NEXT:
			/*
			 * mode is skip to next:
			 *    set potential skip target to current command at
			 *    next depth
			 */
			skipdestp = ixlp;
			skipxferp = ixlp;
			skipdepth = ixldepth + 1;

			/*
			 * else if at max depth at current cmd adjust to next
			 * IXL command.
			 *
			 * (NOTE: next means next IXL command along execution
			 * path,  whatever IXL command it might be.  e.g. store
			 * timestamp or callback or label or jump or send... )
			 */
			if (skipdepth >= xferctlp->cnt) {
				skipdepth = 0;
				skipdestp = ixlp->next_ixlp;
				skipxferp = xferctlp->execp;
			}

			/* evaluate skip to status further, below */
			break;


		case IXL1394_SKIP_TO_LABEL:
			/*
			 * mode is skip to label:
			 *    set skip destination depth to 0 (should be
			 *    redundant)
			 */
			skipdepth = 0;

			/* evaluate skip to status further, below */
			break;

		case IXL1394_SKIP_TO_STOP:
			/*
			 * mode is skip to stop:
			 *    set all xfer and destination skip to locations to
			 *    null
			 */
			skipxferp = NULL;
			skipdestp = NULL;
			skipdepth = 0;

			/* evaluate skip to status further, below */
			break;

		} /* end switch */

		/*
		 * if no xfer IXL command follows at or after current skip-to
		 * location
		 */
		if (skipxferp == NULL) {
			/*
			 *   if context is stopped, return stopped, else
			 *   if dma location reg not enabled, return done
			 *   else, return location indeterminate
			 */
			if (HCI1394_ISOCH_CTXT_ACTIVE(soft_statep, ctxtp) ==
			    0) {
				return (IXL_CHECK_STOP);
			}

			if (!dma_loc_check_enabled) {
				return (IXL_CHECK_DONE);
			}
			return (IXL_CHECK_LOST);
		}

		/*
		 * if the skip to xfer IXL dma descriptor's status is set,
		 * then execution did skip
		 */
		xferctlp = (hci1394_xfer_ctl_t *)skipxferp->compiler_privatep;
		dma	 = &xferctlp->dma[skipdepth];
		acc_hdl  = dma->dma_buf->bi_handle;
		dma_hdl  = dma->dma_buf->bi_dma_handle;
		hcidescp = (hci1394_desc_t *)dma->dma_descp;
		hcidesc_off = (off_t)hcidescp - (off_t)dma->dma_buf->bi_kaddr;

		/* Sync the descriptor before we get the status */
		(void) ddi_dma_sync(dma_hdl, hcidesc_off,
		    sizeof (hci1394_desc_t), DDI_DMA_SYNC_FORCPU);
		desc_status = ddi_get32(acc_hdl, &hcidescp->status);

		if ((desc_status & DESC_XFER_ACTIVE_MASK) != 0) {

			/*
			 * adjust to continue from skip to IXL command and
			 * return skipped, to have calling func continue.
			 * (Note: next IXL command may be any allowed IXL
			 * command)
			 */
			ctxtp->ixl_execp = skipdestp;
			ctxtp->ixl_exec_depth = skipdepth;

			return (IXL_CHECK_SKIP);
		}

		/*
		 * if dma location command register checking is enabled,
		 * and the skip to xfer IXL dma location matches current
		 * dma location register value, execution did skip
		 */
		dmastartp = dma->dma_bound & ~DESC_Z_MASK;
		dmaendp = dmastartp + ((dma->dma_bound & DESC_Z_MASK) << 4);

		if (dma_loc_check_enabled && ((dma_cmd_cur_loc >= dmastartp) &&
		    (dma_cmd_cur_loc < dmaendp))) {

			/* if the context is stopped, return stopped */
			if (HCI1394_ISOCH_CTXT_ACTIVE(soft_statep, ctxtp) ==
			    0) {
				return (IXL_CHECK_STOP);
			}
			/*
			 * adjust to continue from skip to IXL command and
			 * return skipped, to have calling func continue
			 * (Note: next IXL command may be any allowed IXL cmd)
			 */
			ctxtp->ixl_execp = skipdestp;
			ctxtp->ixl_exec_depth = skipdepth;

			return (IXL_CHECK_SKIP);
		}

		/*
		 * else, advance working current locn to skipxferp and
		 * skipdepth and continue skip evaluation loop processing
		 */
		ixlp = skipxferp;
		ixldepth = skipdepth;

	} /* end while */

	/*
	 * didn't find dma status set, nor location reg match, along skip path
	 *
	 * if context is stopped, return stopped,
	 *
	 * else if no current location reg active don't change context values,
	 * just return done (no skip)
	 *
	 * else, return location indeterminate
	 */

	if (HCI1394_ISOCH_CTXT_ACTIVE(soft_statep, ctxtp) == 0) {
		return (IXL_CHECK_STOP);
	}
	if (!dma_loc_check_enabled) {
		return (IXL_CHECK_DONE);
	}

	return (IXL_CHECK_LOST);
}

/*
 * hci1394_isoch_cycle_inconsistent()
 *    Called during interrupt notification to indicate that the cycle time
 *    has changed unexpectedly.  We need to take this opportunity to
 *    update our tracking of each running transmit context's execution.
 *    cycle_inconsistent only affects transmit, so recv contexts are left alone.
 */
void
hci1394_isoch_cycle_inconsistent(hci1394_state_t *soft_statep)
{
	int i, cnt_thresh;
	boolean_t note;
	hrtime_t current_time, last_time, delta, delta_thresh;
	hci1394_iso_ctxt_t *ctxtp; 	/* current context */

	ASSERT(soft_statep);

	hci1394_ohci_intr_clear(soft_statep->ohci, OHCI_INTR_CYC_INCONSISTENT);

	/* grab the mutex before checking each context's INUSE and RUNNING */
	mutex_enter(&soft_statep->isoch->ctxt_list_mutex);

	/* check for transmit contexts which are inuse and running */
	for (i = 0; i < soft_statep->isoch->ctxt_xmit_count; i++) {
		ctxtp = &soft_statep->isoch->ctxt_xmit[i];

		if ((ctxtp->ctxt_flags &
		    (HCI1394_ISO_CTXT_INUSE | HCI1394_ISO_CTXT_RUNNING)) != 0) {

			mutex_exit(&soft_statep->isoch->ctxt_list_mutex);
			hci1394_ixl_interrupt(soft_statep, ctxtp, B_FALSE);
			mutex_enter(&soft_statep->isoch->ctxt_list_mutex);
		}
	}

	/*
	 * get the current time and calculate the delta between now and
	 * when the last interrupt was processed.  (NOTE: if the time
	 * returned by gethrtime() rolls-over while we are counting these
	 * interrupts, we will incorrectly restart the counting process.
	 * However, because the probability of this happening is small and
	 * not catching the roll-over will AT MOST double the time it takes
	 * us to discover and correct from this condition, we can safely
	 * ignore it.)
	 */
	current_time = gethrtime();
	last_time = soft_statep->isoch->cycle_incon_thresh.last_intr_time;
	delta = current_time - last_time;

	/*
	 * compare the calculated delta to the delta T threshold.  If it
	 * is less than the threshold, then increment the counter.  If it
	 * is not then reset the counter.
	 */
	delta_thresh = soft_statep->isoch->cycle_incon_thresh.delta_t_thresh;
	if (delta < delta_thresh)
		soft_statep->isoch->cycle_incon_thresh.delta_t_counter++;
	else
		soft_statep->isoch->cycle_incon_thresh.delta_t_counter = 0;

	/*
	 * compare the counter to the counter threshold.  If it is greater,
	 * then disable the cycle inconsistent interrupt.
	 */
	cnt_thresh = soft_statep->isoch->cycle_incon_thresh.counter_thresh;
	note = B_FALSE;
	if (soft_statep->isoch->cycle_incon_thresh.delta_t_counter >
	    cnt_thresh) {
		hci1394_ohci_intr_disable(soft_statep->ohci,
		    OHCI_INTR_CYC_INCONSISTENT);
		note = B_TRUE;
	}

	/* save away the current time into the last_intr_time field */
	soft_statep->isoch->cycle_incon_thresh.last_intr_time = current_time;

	mutex_exit(&soft_statep->isoch->ctxt_list_mutex);

	if (note == B_TRUE) {
		cmn_err(CE_NOTE, "!hci1394(%d): cycle_inconsistent interrupt "
		    "disabled until next bus reset",
		    soft_statep->drvinfo.di_instance);
	}
}


/*
 * hci1394_isoch_cycle_lost()
 *    Interrupt indicates an expected cycle_start packet (and therefore our
 *    opportunity to transmit) did not show up.  Update our tracking of each
 *    running transmit context.
 */
void
hci1394_isoch_cycle_lost(hci1394_state_t *soft_statep)
{
	int i, cnt_thresh;
	boolean_t note;
	hrtime_t current_time, last_time, delta, delta_thresh;
	hci1394_iso_ctxt_t *ctxtp; 	/* current context */

	ASSERT(soft_statep);

	hci1394_ohci_intr_clear(soft_statep->ohci, OHCI_INTR_CYC_LOST);

	/* grab the mutex before checking each context's INUSE and RUNNING */
	mutex_enter(&soft_statep->isoch->ctxt_list_mutex);

	/* check for transmit contexts which are inuse and running */
	for (i = 0; i < soft_statep->isoch->ctxt_xmit_count; i++) {
		ctxtp = &soft_statep->isoch->ctxt_xmit[i];

		if ((ctxtp->ctxt_flags &
		    (HCI1394_ISO_CTXT_INUSE | HCI1394_ISO_CTXT_RUNNING)) != 0) {

			mutex_exit(&soft_statep->isoch->ctxt_list_mutex);
			hci1394_ixl_interrupt(soft_statep, ctxtp, B_FALSE);
			mutex_enter(&soft_statep->isoch->ctxt_list_mutex);
		}
	}

	/*
	 * get the current time and calculate the delta between now and
	 * when the last interrupt was processed.  (NOTE: if the time
	 * returned by gethrtime() rolls-over while we are counting these
	 * interrupts, we will incorrectly restart the counting process.
	 * However, because the probability of this happening is small and
	 * not catching the roll-over will AT MOST double the time it takes
	 * us to discover and correct from this condition, we can safely
	 * ignore it.)
	 */
	current_time = gethrtime();
	last_time = soft_statep->isoch->cycle_lost_thresh.last_intr_time;
	delta = current_time - last_time;

	/*
	 * compare the calculated delta to the delta T threshold.  If it
	 * is less than the threshold, then increment the counter.  If it
	 * is not then reset the counter.
	 */
	delta_thresh = soft_statep->isoch->cycle_lost_thresh.delta_t_thresh;
	if (delta < delta_thresh)
		soft_statep->isoch->cycle_lost_thresh.delta_t_counter++;
	else
		soft_statep->isoch->cycle_lost_thresh.delta_t_counter = 0;

	/*
	 * compare the counter to the counter threshold.  If it is greater,
	 * then disable the cycle lost interrupt.
	 */
	cnt_thresh = soft_statep->isoch->cycle_lost_thresh.counter_thresh;
	note = B_FALSE;
	if (soft_statep->isoch->cycle_lost_thresh.delta_t_counter >
	    cnt_thresh) {
		hci1394_ohci_intr_disable(soft_statep->ohci,
		    OHCI_INTR_CYC_LOST);
		note = B_TRUE;
	}

	/* save away the current time into the last_intr_time field */
	soft_statep->isoch->cycle_lost_thresh.last_intr_time = current_time;

	mutex_exit(&soft_statep->isoch->ctxt_list_mutex);

	if (note == B_TRUE) {
		cmn_err(CE_NOTE, "!hci1394(%d): cycle_lost interrupt "
		    "disabled until next bus reset",
		    soft_statep->drvinfo.di_instance);
	}
}
