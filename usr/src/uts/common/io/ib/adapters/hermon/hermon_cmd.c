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
 * hermon_cmd.c
 *    Hermon Firmware Command Routines
 *
 *    Implements all the routines necessary for allocating, posting, and
 *    freeing commands for the Hermon firmware.  These routines manage a
 *    preallocated list of command mailboxes and provide interfaces to post
 *    each of the several dozen commands to the Hermon firmware.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/bitmap.h>

#include <sys/ib/adapters/hermon/hermon.h>

static int hermon_impl_mbox_alloc(hermon_state_t *state,
    hermon_mboxlist_t *mblist, hermon_mbox_t **mb, uint_t mbox_wait);
static void hermon_impl_mbox_free(hermon_mboxlist_t *mblist,
    hermon_mbox_t **mb);
static int hermon_impl_mboxlist_init(hermon_state_t *state,
    hermon_mboxlist_t *mblist, uint_t num_mbox, hermon_rsrc_type_t type);
static void hermon_impl_mboxlist_fini(hermon_state_t *state,
    hermon_mboxlist_t *mblist);
static int hermon_outstanding_cmd_alloc(hermon_state_t *state,
    hermon_cmd_t **cmd_ptr, uint_t cmd_wait);
static void hermon_outstanding_cmd_free(hermon_state_t *state,
    hermon_cmd_t **cmd_ptr);
static int hermon_write_hcr(hermon_state_t *state, hermon_cmd_post_t *cmdpost,
    uint16_t token, int *hwerr);
static void hermon_mbox_sync(hermon_mbox_t *mbox, uint_t offset,
    uint_t length, uint_t flag);
static void hermon_cmd_check_status(hermon_state_t *state, int status);

/*
 * hermon_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *
 *    The "cp_flags" field in cmdpost
 *    is used to determine whether to wait for an available
 *    outstanding command (if necessary) or to return error.
 */
int
hermon_cmd_post(hermon_state_t *state, hermon_cmd_post_t *cmdpost)
{
	hermon_cmd_t	*cmdptr;
	int		status, retry_cnt, retry_cnt2, hw_err;
	uint16_t	token;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*cmdpost))

	/* Determine if we are going to spin until completion */
	if (cmdpost->cp_flags == HERMON_CMD_NOSLEEP_SPIN) {

		/* Write the command to the HCR */
		retry_cnt = HCA_PIO_RETRY_CNT;
		do {
			status = hermon_write_hcr(state, cmdpost, 0, &hw_err);
		} while (status == HERMON_CMD_INTERNAL_ERR && retry_cnt-- > 0);

		/* Check if there is an error status in hermon_write_hcr() */
		if (status != HERMON_CMD_SUCCESS) {
			/*
			 * If there is a HW error, call hermon_cmd_retry_ok()
			 * to check the side-effect of the operation retry.
			 */
			if ((retry_cnt == HCA_PIO_RETRY_CNT &&
			    hw_err == HCA_PIO_OK) ||
			    !hermon_cmd_retry_ok(cmdpost, status)) {
				hermon_cmd_check_status(state, status);
				return (status);
			}
		/* Check if there is a transient internal error */
		} else if (retry_cnt != HCA_PIO_RETRY_CNT) {
			hermon_fm_ereport(state, HCA_IBA_ERR,
			    HCA_ERR_TRANSIENT);
		}

	} else {  /* "HERMON_CMD_SLEEP_NOSPIN" */
		ASSERT(HERMON_SLEEPFLAG_FOR_CONTEXT() != HERMON_NOSLEEP);

		/* NOTE: Expect threads to be waiting in here */
		status = hermon_outstanding_cmd_alloc(state, &cmdptr,
		    cmdpost->cp_flags);
		if (status != HERMON_CMD_SUCCESS) {
			return (status);
		}
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*cmdptr))

		retry_cnt = HCA_PIO_RETRY_CNT;
retry:
		/*
		 * Set status to "HERMON_CMD_INVALID_STATUS".  It is
		 * appropriate to do this here without the "cmd_comp_lock"
		 * because this register is overloaded.  Later it will be
		 * used to indicate - through a change from this invalid
		 * value to some other value - that the condition variable
		 * has been signaled.  Once it has, status will then contain
		 * the _real_ completion status
		 */
		cmdptr->cmd_status = HERMON_CMD_INVALID_STATUS;

		/* Write the command to the HCR */
		token = (uint16_t)cmdptr->cmd_indx;
		retry_cnt2 = HCA_PIO_RETRY_CNT;
		do {
			status = hermon_write_hcr(state, cmdpost, token,
			    &hw_err);
		} while (status == HERMON_CMD_INTERNAL_ERR && retry_cnt2-- > 0);

		/* Check if there is an error status in hermon_write_hcr() */
		if (status != HERMON_CMD_SUCCESS) {
			/*
			 * If there is a HW error, call hermon_cmd_retry_ok()
			 * to check the side-effect of the operation retry.
			 */
			if ((retry_cnt == HCA_PIO_RETRY_CNT &&
			    hw_err == HCA_PIO_OK) ||
			    !hermon_cmd_retry_ok(cmdpost, status)) {
				hermon_cmd_check_status(state, status);
				hermon_outstanding_cmd_free(state, &cmdptr);
				return (status);
			}
		/* Check if there is a transient internal error */
		} else if (retry_cnt2 != HCA_PIO_RETRY_CNT) {
			hermon_fm_ereport(state, HCA_IBA_ERR,
			    HCA_ERR_TRANSIENT);
		}

		/*
		 * cv_wait() on the "command_complete" condition variable.
		 * Note: We have the "__lock_lint" here to workaround warlock.
		 * Since warlock doesn't know that other parts of the Hermon
		 * may occasionally call this routine while holding their own
		 * locks, it complains about this cv_wait.  In reality,
		 * however, the rest of the driver never calls this routine
		 * with a lock held unless they pass HERMON_CMD_NOSLEEP.
		 */
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*cmdptr))
		mutex_enter(&cmdptr->cmd_comp_lock);
		while (cmdptr->cmd_status == HERMON_CMD_INVALID_STATUS) {
#ifndef	__lock_lint
			cv_wait(&cmdptr->cmd_comp_cv, &cmdptr->cmd_comp_lock);
			/* NOTE: EXPECT SEVERAL THREADS TO BE WAITING HERE */
#endif
		}
		mutex_exit(&cmdptr->cmd_comp_lock);
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*cmdptr))

		/*
		 * Wake up after command completes (cv_signal).  Read status
		 * from the command (success, fail, etc.).  It is appropriate
		 * here (as above) to read the status field without the
		 * "cmd_comp_lock" because it is no longer being used to
		 * indicate whether the condition variable has been signaled
		 * (i.e. at this point we are certain that it already has).
		 */
		status = cmdptr->cmd_status;

		/* retry the operation if an internal error occurs */
		if (status == HERMON_CMD_INTERNAL_ERR && retry_cnt-- > 0)
			goto retry;

		/* Save the "outparam" values into the cmdpost struct */
		cmdpost->cp_outparm = cmdptr->cmd_outparm;

		/*
		 * Add the command back to the "outstanding commands list".
		 * Signal the "cmd_list" condition variable, if necessary.
		 */
		hermon_outstanding_cmd_free(state, &cmdptr);

		/* Check if there is an error status in hermon_write_hcr() */
		if (status != HERMON_CMD_SUCCESS) {
			/*
			 * If there is a HW error, call hermon_cmd_retry_ok()
			 * to check the side-effect of the operation retry.
			 */
			if ((retry_cnt == HCA_PIO_RETRY_CNT &&
			    hw_err == HCA_PIO_OK) ||
			    !hermon_cmd_retry_ok(cmdpost, status)) {
				hermon_cmd_check_status(state, status);
				cmn_err(CE_NOTE, "hermon%d: post cmd failed "
				    "opcode (0x%x) status (0x%x)\n",
				    state->hs_instance, cmdpost->cp_opcode,
				    status);
				return (status);
			}
		/* Check if there is a transient internal error */
		} else if (retry_cnt != HCA_PIO_RETRY_CNT) {
			hermon_fm_ereport(state, HCA_IBA_ERR,
			    HCA_ERR_TRANSIENT);
		}
	}

	return (HERMON_CMD_SUCCESS);
}

/*
 * hermon_cmd_check_status()
 *	Context:  Can be called from interrupt or base
 *
 * checks the status returned from write_hcr and does the right
 * notice to the console, if any
 */
static void
hermon_cmd_check_status(hermon_state_t *state, int status)
{
	switch (status) {
		case HERMON_CMD_TIMEOUT_TOGGLE:
			HERMON_FMANOTE(state, HERMON_FMA_TOTOG);
			hermon_fm_ereport(state, HCA_IBA_ERR,
			    HCA_ERR_NON_FATAL);
			break;

		case HERMON_CMD_TIMEOUT_GOBIT:
			HERMON_FMANOTE(state, HERMON_FMA_GOBIT);
			hermon_fm_ereport(state, HCA_IBA_ERR,
			    HCA_ERR_NON_FATAL);
			break;

		case HERMON_CMD_INSUFF_RSRC:
			HERMON_FMANOTE(state, HERMON_FMA_RSRC);
			break;

		case HERMON_CMD_INVALID_STATUS:
			HERMON_FMANOTE(state, HERMON_FMA_CMDINV);
			hermon_fm_ereport(state, HCA_IBA_ERR,
			    HCA_ERR_NON_FATAL);
			break;

		case HERMON_CMD_INTERNAL_ERR:
			HERMON_FMANOTE(state, HERMON_FMA_HCRINT);
			hermon_fm_ereport(state, HCA_IBA_ERR,
			    HCA_ERR_NON_FATAL);
			break;

		case HERMON_CMD_BAD_NVMEM:
			/*
			 * No need of an ereport here since this case
			 * is treated as a degradation later.
			 */
			HERMON_FMANOTE(state, HERMON_FMA_NVMEM);
			break;

		default:
			break;
	}
}

/*
 * hermon_mbox_alloc()
 *    Context: Can be called from interrupt or base context.
 *
 *    The "mbox_wait" parameter is used to determine whether to
 *    wait for a mailbox to become available or not.
 */
int
hermon_mbox_alloc(hermon_state_t *state, hermon_mbox_info_t *mbox_info,
    uint_t mbox_wait)
{
	int		status;
	uint_t		sleep_context;

	sleep_context = HERMON_SLEEPFLAG_FOR_CONTEXT();

	/* Allocate an "In" mailbox */
	if (mbox_info->mbi_alloc_flags & HERMON_ALLOC_INMBOX) {
		/* Determine correct mboxlist based on calling context */
		if (sleep_context == HERMON_NOSLEEP) {
			status = hermon_impl_mbox_alloc(state,
			    &state->hs_in_intr_mblist,
			    &mbox_info->mbi_in, mbox_wait);

			ASSERT(status == HERMON_CMD_SUCCESS);
		} else {
			/* NOTE: Expect threads to be waiting in here */
			status = hermon_impl_mbox_alloc(state,
			    &state->hs_in_mblist, &mbox_info->mbi_in,
			    mbox_wait);
			if (status != HERMON_CMD_SUCCESS) {
				return (status);
			}
		}

	}

	/* Allocate an "Out" mailbox */
	if (mbox_info->mbi_alloc_flags & HERMON_ALLOC_OUTMBOX) {
		/* Determine correct mboxlist based on calling context */
		if (sleep_context == HERMON_NOSLEEP) {
			status = hermon_impl_mbox_alloc(state,
			    &state->hs_out_intr_mblist,
			    &mbox_info->mbi_out, mbox_wait);

			ASSERT(status == HERMON_CMD_SUCCESS);
		} else {
			/* NOTE: Expect threads to be waiting in here */
			status = hermon_impl_mbox_alloc(state,
			    &state->hs_out_mblist, &mbox_info->mbi_out,
			    mbox_wait);
			if (status != HERMON_CMD_SUCCESS) {
				/* If we allocated an "In" mailbox, free it */
				if (mbox_info->mbi_alloc_flags &
				    HERMON_ALLOC_INMBOX) {
					hermon_impl_mbox_free(
					    &state->hs_in_mblist,
					    &mbox_info->mbi_in);
				}
				return (status);
			}
		}
	}

	/* Store appropriate context in mbox_info */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(mbox_info->mbi_sleep_context))
	mbox_info->mbi_sleep_context = sleep_context;

	return (HERMON_CMD_SUCCESS);
}


/*
 * hermon_mbox_free()
 *    Context: Can be called from interrupt or base context.
 */
void
hermon_mbox_free(hermon_state_t *state, hermon_mbox_info_t *mbox_info)
{
	/*
	 * The mailbox has to be freed in the same context from which it was
	 * allocated.  The context is stored in the mbox_info at
	 * hermon_mbox_alloc() time.  We check the stored context against the
	 * current context here.
	 */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(mbox_info->mbi_sleep_context))
	ASSERT(mbox_info->mbi_sleep_context == HERMON_SLEEPFLAG_FOR_CONTEXT());

	/* Determine correct mboxlist based on calling context */
	if (mbox_info->mbi_sleep_context == HERMON_NOSLEEP) {
		/* Free the intr "In" mailbox */
		if (mbox_info->mbi_alloc_flags & HERMON_ALLOC_INMBOX) {
			hermon_impl_mbox_free(&state->hs_in_intr_mblist,
			    &mbox_info->mbi_in);
		}

		/* Free the intr "Out" mailbox */
		if (mbox_info->mbi_alloc_flags & HERMON_ALLOC_OUTMBOX) {
			hermon_impl_mbox_free(&state->hs_out_intr_mblist,
			    &mbox_info->mbi_out);
		}
	} else {
		/* Free the "In" mailbox */
		if (mbox_info->mbi_alloc_flags & HERMON_ALLOC_INMBOX) {
			hermon_impl_mbox_free(&state->hs_in_mblist,
			    &mbox_info->mbi_in);
		}

		/* Free the "Out" mailbox */
		if (mbox_info->mbi_alloc_flags & HERMON_ALLOC_OUTMBOX) {
			hermon_impl_mbox_free(&state->hs_out_mblist,
			    &mbox_info->mbi_out);
		}
	}
}



/*
 * hermon_cmd_complete_handler()
 *    Context: Called only from interrupt context.
 */
/* ARGSUSED */
int
hermon_cmd_complete_handler(hermon_state_t *state, hermon_eqhdl_t eq,
    hermon_hw_eqe_t *eqe)
{
	hermon_cmd_t		*cmdp;

	/*
	 * Find the outstanding command pointer based on value returned
	 * in "token"
	 */
	cmdp = &state->hs_cmd_list.cml_cmd[HERMON_EQE_CMDTOKEN_GET(eq, eqe)];

	/* Signal the waiting thread */
	mutex_enter(&cmdp->cmd_comp_lock);
	cmdp->cmd_outparm = ((uint64_t)HERMON_EQE_CMDOUTP0_GET(eq, eqe) << 32) |
	    HERMON_EQE_CMDOUTP1_GET(eq, eqe);
	cmdp->cmd_status = HERMON_EQE_CMDSTATUS_GET(eq, eqe);

	cv_signal(&cmdp->cmd_comp_cv);
	mutex_exit(&cmdp->cmd_comp_lock);

	return (DDI_SUCCESS);
}


/*
 * hermon_inmbox_list_init()
 *    Context: Only called from attach() path context
 */
int
hermon_inmbox_list_init(hermon_state_t *state)
{
	int		status;
	uint_t		num_inmbox;

	/* Initialize the "In" mailbox list */
	num_inmbox  =  (1 << state->hs_cfg_profile->cp_log_num_inmbox);
	status = hermon_impl_mboxlist_init(state, &state->hs_in_mblist,
	    num_inmbox, HERMON_IN_MBOX);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * hermon_intr_inmbox_list_init()
 *    Context: Only called from attach() path context
 */
int
hermon_intr_inmbox_list_init(hermon_state_t *state)
{
	int		status;
	uint_t		num_inmbox;

	/* Initialize the interrupt "In" mailbox list */
	num_inmbox  =  (1 << state->hs_cfg_profile->cp_log_num_intr_inmbox);
	status = hermon_impl_mboxlist_init(state, &state->hs_in_intr_mblist,
	    num_inmbox, HERMON_INTR_IN_MBOX);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * hermon_outmbox_list_init()
 *    Context: Only called from attach() path context
 */
int
hermon_outmbox_list_init(hermon_state_t *state)
{
	int		status;
	uint_t		num_outmbox;

	/* Initialize the "Out" mailbox list */
	num_outmbox  =  (1 << state->hs_cfg_profile->cp_log_num_outmbox);
	status = hermon_impl_mboxlist_init(state, &state->hs_out_mblist,
	    num_outmbox, HERMON_OUT_MBOX);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * hermon_intr_outmbox_list_init()
 *    Context: Only called from attach() path context
 */
int
hermon_intr_outmbox_list_init(hermon_state_t *state)
{
	int		status;
	uint_t		num_outmbox;

	/* Initialize the interrupts "Out" mailbox list */
	num_outmbox  =  (1 << state->hs_cfg_profile->cp_log_num_intr_outmbox);
	status = hermon_impl_mboxlist_init(state, &state->hs_out_intr_mblist,
	    num_outmbox, HERMON_INTR_OUT_MBOX);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * hermon_inmbox_list_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
void
hermon_inmbox_list_fini(hermon_state_t *state)
{
	/* Free up the "In" mailbox list */
	hermon_impl_mboxlist_fini(state, &state->hs_in_mblist);
}


/*
 * hermon_intr_inmbox_list_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
void
hermon_intr_inmbox_list_fini(hermon_state_t *state)
{
	/* Free up the interupts "In" mailbox list */
	hermon_impl_mboxlist_fini(state, &state->hs_in_intr_mblist);
}


/*
 * hermon_outmbox_list_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
void
hermon_outmbox_list_fini(hermon_state_t *state)
{
	/* Free up the "Out" mailbox list */
	hermon_impl_mboxlist_fini(state, &state->hs_out_mblist);
}


/*
 * hermon_intr_outmbox_list_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
void
hermon_intr_outmbox_list_fini(hermon_state_t *state)
{
	/* Free up the interrupt "Out" mailbox list */
	hermon_impl_mboxlist_fini(state, &state->hs_out_intr_mblist);
}


/*
 * hermon_impl_mbox_alloc()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_impl_mbox_alloc(hermon_state_t *state, hermon_mboxlist_t *mblist,
    hermon_mbox_t **mb, uint_t mbox_wait)
{
	hermon_mbox_t	*mbox_ptr;
	uint_t		index, next, prev;
	uint_t		count, countmax;

	/*
	 * If the mailbox list is empty, then wait (if appropriate in the
	 * current context).  Otherwise, grab the next available mailbox.
	 */
	if (mbox_wait == HERMON_NOSLEEP) {
		count	 = 0;
		countmax = state->hs_cfg_profile->cp_cmd_poll_max;

		mutex_enter(&mblist->mbl_lock);
		mblist->mbl_pollers++;
		while (mblist->mbl_entries_free == 0) {
			mutex_exit(&mblist->mbl_lock);
			/* Delay loop polling for an available mbox */
			if (++count > countmax) {
				return (HERMON_CMD_INSUFF_RSRC);
			}

			/* Delay before polling for mailbox again */
			drv_usecwait(state->hs_cfg_profile->cp_cmd_poll_delay);
			mutex_enter(&mblist->mbl_lock);
		}
		mblist->mbl_pollers--;

	/* HERMON_SLEEP */
	} else {
		/*
		 * Grab lock here as we prepare to cv_wait if needed.
		 */
		mutex_enter(&mblist->mbl_lock);
		while (mblist->mbl_entries_free == 0) {
			/*
			 * Wait (on cv) for a mailbox to become free.  Note:
			 * Just as we do above in hermon_cmd_post(), we also
			 * have the "__lock_lint" here to workaround warlock.
			 * Warlock doesn't know that other parts of the Hermon
			 * may occasionally call this routine while holding
			 * their own locks, so it complains about this cv_wait.
			 * In reality, however, the rest of the driver never
			 * calls this routine with a lock held unless they pass
			 * HERMON_CMD_NOSLEEP.
			 */
			mblist->mbl_waiters++;
#ifndef	__lock_lint
			cv_wait(&mblist->mbl_cv, &mblist->mbl_lock);
#endif
		}
	}

	/* Grab the next available mailbox from list */
	mbox_ptr = mblist->mbl_mbox;
	index	 = mblist->mbl_head_indx;
	next	 = mbox_ptr[index].mb_next;
	prev	 = mbox_ptr[index].mb_prev;

	/* Remove it from the mailbox list */
	mblist->mbl_mbox[next].mb_prev	= prev;
	mblist->mbl_mbox[prev].mb_next	= next;
	mblist->mbl_head_indx		= next;

	/* Update the "free" count and return the mailbox pointer */
	mblist->mbl_entries_free--;
	*mb = &mbox_ptr[index];

	mutex_exit(&mblist->mbl_lock);

	return (HERMON_CMD_SUCCESS);
}


/*
 * hermon_impl_mbox_free()
 *    Context: Can be called from interrupt or base context.
 */
static void
hermon_impl_mbox_free(hermon_mboxlist_t *mblist, hermon_mbox_t **mb)
{
	uint_t		mbox_indx;

	mutex_enter(&mblist->mbl_lock);

	/* Pull the "index" from mailbox entry */
	mbox_indx = (*mb)->mb_indx;

	/*
	 * If mailbox list is not empty, then insert the entry.  Otherwise,
	 * this is the only entry.  So update the pointers appropriately.
	 */
	if (mblist->mbl_entries_free++ != 0) {
		/* Update the current mailbox */
		(*mb)->mb_next = mblist->mbl_head_indx;
		(*mb)->mb_prev = mblist->mbl_tail_indx;

		/* Update head and tail mailboxes */
		mblist->mbl_mbox[mblist->mbl_head_indx].mb_prev = mbox_indx;
		mblist->mbl_mbox[mblist->mbl_tail_indx].mb_next = mbox_indx;

		/* Update tail index */
		mblist->mbl_tail_indx = mbox_indx;

	} else {
		/* Update the current mailbox */
		(*mb)->mb_next = mbox_indx;
		(*mb)->mb_prev = mbox_indx;

		/* Update head and tail indexes */
		mblist->mbl_tail_indx = mbox_indx;
		mblist->mbl_head_indx = mbox_indx;
	}

	/*
	 * Because we can have both waiters (SLEEP treads waiting for a
	 * cv_signal to continue processing) and pollers (NOSLEEP treads
	 * polling for a mailbox to become available), we try to share CPU time
	 * between them.  We do this by signalling the waiters only every other
	 * call to mbox_free.  This gives the pollers a chance to get some CPU
	 * time to do their command.  If we signalled every time, the pollers
	 * would have a much harder time getting CPU time.
	 *
	 * If there are waiters and no pollers, then we signal always.
	 *
	 * Otherwise, if there are either no waiters, there may in fact be
	 * pollers, so we do not signal in that case.
	 */
	if (mblist->mbl_pollers > 0 && mblist->mbl_waiters > 0) {
		/* flip the signal value */
		mblist->mbl_signal = (mblist->mbl_signal + 1) % 2;
	} else if (mblist->mbl_waiters > 0) {
		mblist->mbl_signal = 1;
	} else {
		mblist->mbl_signal = 0;
	}

	/*
	 * Depending on the conditions in the previous check, we signal only if
	 * we are supposed to.
	 */
	if (mblist->mbl_signal) {
		mblist->mbl_waiters--;
		cv_signal(&mblist->mbl_cv);
	}

	/* Clear out the mailbox entry pointer */
	*mb = NULL;

	mutex_exit(&mblist->mbl_lock);
}


/*
 * hermon_impl_mboxlist_init()
 *    Context: Only called from attach() path context
 */
static int
hermon_impl_mboxlist_init(hermon_state_t *state, hermon_mboxlist_t *mblist,
    uint_t num_mbox, hermon_rsrc_type_t type)
{
	hermon_rsrc_t		*rsrc;
	ddi_dma_cookie_t	dma_cookie;
	uint_t			dma_cookiecnt;
	int			status, i;

	/* Allocate the memory for the mailbox entries list */
	mblist->mbl_list_sz = num_mbox;
	mblist->mbl_mbox = kmem_zalloc(mblist->mbl_list_sz *
	    sizeof (hermon_mbox_t), KM_SLEEP);

	/* Initialize the mailbox entries list */
	mblist->mbl_head_indx	 = 0;
	mblist->mbl_tail_indx	 = mblist->mbl_list_sz - 1;
	mblist->mbl_entries_free = mblist->mbl_list_sz;
	mblist->mbl_waiters	 = 0;
	mblist->mbl_num_alloc	 = 0;

	/* Set up the mailbox list's cv and mutex */
	mutex_init(&mblist->mbl_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->hs_intrmsi_pri));
	cv_init(&mblist->mbl_cv, NULL, CV_DRIVER, NULL);

	/* Initialize the mailbox list entries */
	for (i = 0; i < mblist->mbl_list_sz; i++) {
		/* Allocate resources for the mailbox */
		status = hermon_rsrc_alloc(state, type, 1, HERMON_SLEEP,
		    &rsrc);
		if (status != DDI_SUCCESS) {
			/* Jump to cleanup and return error */
			goto mboxlist_init_fail;
		}

		/* Save away the mailbox resource info */
		mblist->mbl_mbox[i].mb_rsrcptr	= rsrc;
		mblist->mbl_mbox[i].mb_addr	= rsrc->hr_addr;
		mblist->mbl_mbox[i].mb_acchdl	= rsrc->hr_acchdl;

		/*
		 * Get a PCI mapped address for each mailbox.  Note: this
		 * uses the ddi_dma_handle return from the resource
		 * allocation routine
		 */
		status = ddi_dma_addr_bind_handle(rsrc->hr_dmahdl, NULL,
		    rsrc->hr_addr, rsrc->hr_len,
		    (DDI_DMA_RDWR | DDI_DMA_CONSISTENT),
		    DDI_DMA_SLEEP, NULL, &dma_cookie, &dma_cookiecnt);
		if (status != DDI_SUCCESS) {
			/* Jump to cleanup and return error */
			hermon_rsrc_free(state, &rsrc);
			goto mboxlist_init_fail;
		}

		/* Save away the mapped address for the mailbox */
		mblist->mbl_mbox[i].mb_mapaddr	= dma_cookie.dmac_laddress;

		/* Make each entry point to the "next" and "prev" entries */
		mblist->mbl_mbox[i].mb_next	= i+1;
		mblist->mbl_mbox[i].mb_prev	= i-1;
		mblist->mbl_mbox[i].mb_indx	= i;
		mblist->mbl_num_alloc		= i + 1;
	}

	/* Make the "head" and "tail" entries point to each other */
	mblist->mbl_mbox[mblist->mbl_head_indx].mb_prev =
	    mblist->mbl_tail_indx;
	mblist->mbl_mbox[mblist->mbl_tail_indx].mb_next =
	    mblist->mbl_head_indx;

	return (DDI_SUCCESS);

mboxlist_init_fail:
	hermon_impl_mboxlist_fini(state, mblist);

	return (DDI_FAILURE);
}


/*
 * hermon_impl_mboxlist_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
static void
hermon_impl_mboxlist_fini(hermon_state_t *state, hermon_mboxlist_t *mblist)
{
	hermon_rsrc_t	*rsrc;
	int		i, status;

	/* Release the resources for each of the mailbox list entries */
	for (i = 0; i < mblist->mbl_num_alloc; i++) {
		rsrc = mblist->mbl_mbox[i].mb_rsrcptr;

		/*
		 * First, unbind the DMA memory for the mailbox
		 *
		 * Note: The only way ddi_dma_unbind_handle() currently
		 * can return an error is if the handle passed in is invalid.
		 * Since this should never happen, we choose to return void
		 * from this function!  If this does return an error,
		 * however, then we print a warning message to the console.
		 */
		status = ddi_dma_unbind_handle(rsrc->hr_dmahdl);
		if (status != DDI_SUCCESS) {
			HERMON_WARNING(state, "failed to unbind DMA mapping");
			return;
		}

		/* Next, free the mailbox resource */
		hermon_rsrc_free(state, &rsrc);
	}

	/* Destroy the mailbox list mutex and cv */
	mutex_destroy(&mblist->mbl_lock);
	cv_destroy(&mblist->mbl_cv);

	/* Free up the memory for tracking the mailbox list */
	kmem_free(mblist->mbl_mbox, mblist->mbl_list_sz *
	    sizeof (hermon_mbox_t));
}


/*
 * hermon_outstanding_cmd_alloc()
 *    Context: Can be called only from base context.
 */
static int
hermon_outstanding_cmd_alloc(hermon_state_t *state, hermon_cmd_t **cmd_ptr,
    uint_t cmd_wait)
{
	hermon_cmdlist_t	*cmd_list;
	uint_t		next, prev, head;

	cmd_list = &state->hs_cmd_list;
	mutex_enter(&cmd_list->cml_lock);

	/* Ensure that outstanding commands are supported */
	ASSERT(cmd_list->cml_num_alloc != 0);

	/*
	 * If the outstanding command list is empty, then wait (if
	 * appropriate in the current context).  Otherwise, grab the
	 * next available command.
	 */
	while (cmd_list->cml_entries_free == 0) {
		/* No free commands */
		if (cmd_wait == HERMON_NOSLEEP) {
			mutex_exit(&cmd_list->cml_lock);
			return (HERMON_CMD_INSUFF_RSRC);
		}

		/*
		 * Wait (on cv) for a command to become free.  Note: Just
		 * as we do above in hermon_cmd_post(), we also have the
		 * "__lock_lint" here to workaround warlock.  Warlock doesn't
		 * know that other parts of the Hermon may occasionally call
		 * this routine while holding their own locks, so it complains
		 * about this cv_wait.  In reality, however, the rest of the
		 * driver never calls this routine with a lock held unless
		 * they pass HERMON_CMD_NOSLEEP.
		 */
		cmd_list->cml_waiters++;
#ifndef	__lock_lint
		cv_wait(&cmd_list->cml_cv, &cmd_list->cml_lock);
#endif
	}

	/* Grab the next available command from the list */
	head = cmd_list->cml_head_indx;
	*cmd_ptr = &cmd_list->cml_cmd[head];
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(**cmd_ptr))
	next = (*cmd_ptr)->cmd_next;
	prev = (*cmd_ptr)->cmd_prev;
	(*cmd_ptr)->cmd_status = HERMON_CMD_INVALID_STATUS;

	/* Remove it from the command list */
	cmd_list->cml_cmd[next].cmd_prev = prev;
	cmd_list->cml_cmd[prev].cmd_next = next;
	cmd_list->cml_head_indx		 = next;

	/* Update the "free" count and return */
	cmd_list->cml_entries_free--;

	mutex_exit(&cmd_list->cml_lock);

	return (HERMON_CMD_SUCCESS);
}


/*
 * hermon_outstanding_cmd_free()
 *    Context: Can be called only from base context.
 */
static void
hermon_outstanding_cmd_free(hermon_state_t *state, hermon_cmd_t **cmd_ptr)
{
	hermon_cmdlist_t	*cmd_list;
	uint_t		cmd_indx;

	cmd_list = &state->hs_cmd_list;
	mutex_enter(&cmd_list->cml_lock);

	/* Pull the "index" from command entry */
	cmd_indx = (*cmd_ptr)->cmd_indx;

	/*
	 * If outstanding command list is not empty, then insert the entry.
	 * Otherwise, this is the only entry.  So update the pointers
	 * appropriately.
	 */
	if (cmd_list->cml_entries_free++ != 0) {
		/* Update the current command */
		(*cmd_ptr)->cmd_next = cmd_list->cml_head_indx;
		(*cmd_ptr)->cmd_prev = cmd_list->cml_tail_indx;

		/* Update head and tail commands */
		cmd_list->cml_cmd[cmd_list->cml_head_indx].cmd_prev = cmd_indx;
		cmd_list->cml_cmd[cmd_list->cml_tail_indx].cmd_next = cmd_indx;

		/* Update tail index */
		cmd_list->cml_tail_indx = cmd_indx;

	} else {
		/* Update the current command */
		(*cmd_ptr)->cmd_next = cmd_indx;
		(*cmd_ptr)->cmd_prev = cmd_indx;

		/* Update head and tail indexes */
		cmd_list->cml_head_indx = cmd_indx;
		cmd_list->cml_tail_indx = cmd_indx;
	}

	/* If there are threads waiting, signal one of them */
	if (cmd_list->cml_waiters > 0) {
		cmd_list->cml_waiters--;
		cv_signal(&cmd_list->cml_cv);
	}

	/* Clear out the command entry pointer */
	*cmd_ptr = NULL;

	mutex_exit(&cmd_list->cml_lock);
}


/*
 * hermon_write_hcr()
 *    Context: Can be called from interrupt or base context.
 */
static int
hermon_write_hcr(hermon_state_t *state, hermon_cmd_post_t *cmdpost,
    uint16_t token, int *hw_err)
{
	hermon_hw_hcr_t	*hcr;
	uint_t		status, count, countmax;
	uint64_t	hcrreg;
	uint64_t	togmask;
	ddi_acc_handle_t cmdhdl = hermon_get_cmdhdl(state);
	boolean_t	hw_error = B_FALSE;

	/* initialize the FMA retry loop */
	hermon_pio_init(fm_loop_cnt, fm_status, fm_test);

	/*
	 * Grab the "HCR access" lock if the driver is not in
	 * fastreboot. In fastreboot, this function is called
	 * with the single thread but in high interrupt context
	 * (so that this mutex lock cannot be used).
	 */
#ifdef __lock_lint
	mutex_enter(&state->hs_cmd_regs.hcr_lock);
#else
	if (!HERMON_IN_FASTREBOOT(state)) {
		mutex_enter(&state->hs_cmd_regs.hcr_lock);
	}
#endif
	hcr = state->hs_cmd_regs.hcr;

	/*
	 * First, check the "go" bit to see if any previous hcr usage is
	 * complete.  As long as it is set then we must continue to poll.
	 */

	countmax = state->hs_cfg_profile->cp_cmd_poll_max;
	togmask = (state->hs_cmd_toggle & 0x01) << HERMON_HCR_CMD_T_SHFT;

	/* the FMA retry loop starts. */
	hermon_pio_start(state, cmdhdl, pio_error, fm_loop_cnt, fm_status,
	    fm_test);

	count	 = 0;
	for (;;) {
		hcrreg = ddi_get32(cmdhdl, &hcr->cmd);

		/* If "go" bit is clear and toggle reset, then done */
		if (((hcrreg & HERMON_HCR_CMD_GO_MASK) == 0) &&
		    ((hcrreg & HERMON_HCR_CMD_T_MASK)  == togmask)) {
			break;
		}
		/* Delay before polling the "go" bit again */
		drv_usecwait(state->hs_cfg_profile->cp_cmd_poll_delay);

		/*
		 * If we poll more than the maximum number of times, then
		 * return a "timeout" error.
		 */
		if (++count > countmax) {
#ifdef __lock_lint
			mutex_exit(&state->hs_cmd_regs.hcr_lock);
#else
			if (!HERMON_IN_FASTREBOOT(state)) {
				mutex_exit(&state->hs_cmd_regs.hcr_lock);
			}
#endif
			cmn_err(CE_NOTE, "write_hcr: cannot start cmd");
			return (HERMON_CMD_TIMEOUT_GOBIT);
		}
	}

	/* the FMA retry loop ends. */
	hermon_pio_end(state, cmdhdl, pio_error, fm_loop_cnt, fm_status,
	    fm_test);

	/* check if there is a transient error */
	if (fm_loop_cnt != HCA_PIO_RETRY_CNT) {
		hw_error = B_TRUE;
	}

	/* succeeded, so update the cmd counter for this cmd's completion */
	state->hs_cmd_toggle++;
	togmask = (state->hs_cmd_toggle & 0x01) << HERMON_HCR_CMD_T_SHFT;

	/* the FMA retry loop starts. */
	hermon_pio_start(state, cmdhdl, pio_error, fm_loop_cnt, fm_status,
	    fm_test);

	/* Write "inparam" as a 64-bit quantity */
	ddi_put64(cmdhdl, (uint64_t *)(void *)&hcr->in_param0,
	    cmdpost->cp_inparm);

	/* Write "inmod" and 32-bits of "outparam" as 64-bit */
	hcrreg = ((uint64_t)cmdpost->cp_inmod << 32);
	hcrreg = hcrreg | (cmdpost->cp_outparm >> 32);

	ddi_put64(cmdhdl, (uint64_t *)(void *)&hcr->input_modifier, hcrreg);

	/* Write the other 32-bits of "outparam" and "token" as 64-bit */
	hcrreg = (cmdpost->cp_outparm << 32);
	hcrreg = hcrreg | ((uint32_t)token << HERMON_HCR_TOKEN_SHIFT);

	ddi_put64(cmdhdl, (uint64_t *)(void *)&hcr->out_param1, hcrreg);

	/* Then setup the final hcrreg to hit doorbell (i.e. "go" bit) */
	hcrreg = HERMON_HCR_CMD_GO_MASK;
	/* Then set the toggle bit for this command */
	hcrreg |= (state->hs_cmd_toggle & 0x01) << HERMON_HCR_CMD_T_SHFT;
	if (cmdpost->cp_flags == HERMON_CMD_SLEEP_NOSPIN) {
		hcrreg = hcrreg | HERMON_HCR_CMD_E_MASK;
	}
	hcrreg = hcrreg | (cmdpost->cp_opmod << HERMON_HCR_CMD_OPMOD_SHFT);
	hcrreg = hcrreg | (cmdpost->cp_opcode);

	/* Write the doorbell to the HCR */
	ddi_put32(cmdhdl, &hcr->cmd, hcrreg);

	/* the FMA retry loop ends. */
	hermon_pio_end(state, cmdhdl, pio_error, fm_loop_cnt, fm_status,
	    fm_test);

	/* check if there is a transient error */
	if (fm_loop_cnt != HCA_PIO_RETRY_CNT) {
		hw_error = B_TRUE;
	}

	/*
	 * In the SPIN case we read the HCR and check the "go" bit.  For the
	 * NOSPIN case we do not have to poll, we simply release the HCR lock
	 * and return.
	 */
	if (cmdpost->cp_flags == HERMON_CMD_NOSLEEP_SPIN) {

		countmax = (state->hs_cfg_profile->cp_cmd_poll_max << 4);

		/* the FMA retry loop starts. */
		hermon_pio_start(state, cmdhdl, pio_error, fm_loop_cnt,
		    fm_status, fm_test);

		count	 = 0;
		for (;;) {
			hcrreg = ddi_get32(cmdhdl, &hcr->cmd);

			/* If "go" bit is clear and toggle reset, then done */
			if (((hcrreg & HERMON_HCR_CMD_GO_MASK) == 0) &&
			    ((hcrreg & HERMON_HCR_CMD_T_MASK)  == togmask)) {
				break;
			}
			/* Delay before polling the "go" bit again */
			drv_usecwait(state->hs_cfg_profile->cp_cmd_poll_delay);

			/*
			 * If we poll more than the maximum number of times,
			 * then return a "timeout" error.
			 */
			if (++count > countmax) {
#ifdef __lock_lint
				mutex_exit(&state-> hs_cmd_regs.hcr_lock);
#else
				if (!HERMON_IN_FASTREBOOT(state)) {
					mutex_exit(&state->
					    hs_cmd_regs.hcr_lock);
				}
#endif
				cmn_err(CE_NOTE,
				    "write_hcr: cannot complete cmd");
				return (HERMON_CMD_TIMEOUT_GOBIT);
			}
		}

		/* Pull out the "status" bits from the HCR */
		status = (hcrreg >> HERMON_HCR_CMD_STATUS_SHFT);

		/*
		 * Read the "outparam" value.  Note: we have to read "outparam"
		 * as two separate 32-bit reads because the field in the HCR is
		 * not 64-bit aligned.
		 */
		hcrreg = ddi_get32(cmdhdl, &hcr->out_param0);
		cmdpost->cp_outparm = hcrreg << 32;
		hcrreg = ddi_get32(cmdhdl, &hcr->out_param1);
		cmdpost->cp_outparm |= hcrreg;

		/* the FMA retry loop ends. */
		hermon_pio_end(state, cmdhdl, pio_error, fm_loop_cnt, fm_status,
		    fm_test);

		/* check if there is a transient error */
		if (fm_loop_cnt != HCA_PIO_RETRY_CNT) {
			hw_error = B_TRUE;
		}

	/* END SPIN */
	} else {		/* NOSPIN */
		status = HERMON_CMD_SUCCESS;
	}

	/* Drop the "HCR access" lock */
#ifdef __lock_lint
	mutex_exit(&state->hs_cmd_regs.hcr_lock);
#else
	if (!HERMON_IN_FASTREBOOT(state)) {
		mutex_exit(&state->hs_cmd_regs.hcr_lock);
	}
#endif
	if (hw_error == B_TRUE) {
		*hw_err = HCA_PIO_TRANSIENT;
	} else {
		*hw_err = HCA_PIO_OK;
	}
#ifdef FMA_TEST
	if (hermon_test_num == -3) {
		status = HERMON_CMD_INTERNAL_ERR;
	}
#endif
	return (status);

pio_error:
#ifdef __lock_lint
	mutex_exit(&state->hs_cmd_regs.hcr_lock);
#else
	if (!HERMON_IN_FASTREBOOT(state)) {
		mutex_exit(&state->hs_cmd_regs.hcr_lock);
	}
#endif
	hermon_fm_ereport(state, HCA_SYS_ERR, HCA_ERR_NON_FATAL);
	*hw_err = HCA_PIO_PERSISTENT;
	return (HERMON_CMD_INVALID_STATUS);
}


/*
 * hermon_outstanding_cmdlist_init()
 *    Context: Only called from attach() path context
 */
int
hermon_outstanding_cmdlist_init(hermon_state_t *state)
{
	uint_t		num_outstanding_cmds, head, tail;
	int		i;

	/*
	 * Determine the number of the outstanding commands supported
	 * by the Hermon device (obtained from the QUERY_FW command).  Note:
	 * Because we handle both SLEEP and NOSLEEP cases around the hermon HCR,
	 * we know that when an interrupt comes in it will be next on the
	 * command register, and will at most have to wait one commands time.
	 * We do not have to reserve an outstanding command here for
	 * interrupts.
	 */
	num_outstanding_cmds = (1 << state->hs_fw.log_max_cmd);

	/* Initialize the outstanding command list */
	state->hs_cmd_list.cml_list_sz	 = num_outstanding_cmds;
	state->hs_cmd_list.cml_head_indx = 0;
	state->hs_cmd_list.cml_tail_indx = state->hs_cmd_list.cml_list_sz - 1;
	state->hs_cmd_list.cml_entries_free = state->hs_cmd_list.cml_list_sz;
	state->hs_cmd_list.cml_waiters	 = 0;
	state->hs_cmd_list.cml_num_alloc = 0;

	/* Allocate the memory for the outstanding command list */
	if (num_outstanding_cmds) {
		state->hs_cmd_list.cml_cmd =
		    kmem_zalloc(state->hs_cmd_list.cml_list_sz *
		    sizeof (hermon_cmd_t), KM_SLEEP);
	}
	mutex_init(&state->hs_cmd_list.cml_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->hs_intrmsi_pri));
	cv_init(&state->hs_cmd_list.cml_cv, NULL, CV_DRIVER, NULL);

	/* Initialize the individual outstanding command list entries */
	for (i = 0; i < state->hs_cmd_list.cml_list_sz; i++) {
		mutex_init(&state->hs_cmd_list.cml_cmd[i].cmd_comp_lock,
		    NULL, MUTEX_DRIVER, DDI_INTR_PRI(state->hs_intrmsi_pri));
		cv_init(&state->hs_cmd_list.cml_cmd[i].cmd_comp_cv, NULL,
		    CV_DRIVER, NULL);

		state->hs_cmd_list.cml_cmd[i].cmd_next	= i+1;
		state->hs_cmd_list.cml_cmd[i].cmd_prev	= i-1;
		state->hs_cmd_list.cml_cmd[i].cmd_indx	= i;
		state->hs_cmd_list.cml_num_alloc	= i + 1;
	}
	if (num_outstanding_cmds) {
		head = state->hs_cmd_list.cml_head_indx;
		tail = state->hs_cmd_list.cml_tail_indx;
		state->hs_cmd_list.cml_cmd[head].cmd_prev =
		    state->hs_cmd_list.cml_tail_indx;
		state->hs_cmd_list.cml_cmd[tail].cmd_next =
		    state->hs_cmd_list.cml_head_indx;
	}

	return (DDI_SUCCESS);
}


/*
 * hermon_outstanding_cmdlist_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
void
hermon_outstanding_cmdlist_fini(hermon_state_t *state)
{
	int		i;

	/* Destroy the outstanding command list entries */
	for (i = 0; i < state->hs_cmd_list.cml_num_alloc; i++) {
		mutex_destroy(&state->hs_cmd_list.cml_cmd[i].cmd_comp_lock);
		cv_destroy(&state->hs_cmd_list.cml_cmd[i].cmd_comp_cv);
	}

	/* Destroy the lock (and cv) and free up memory for list */
	mutex_destroy(&state->hs_cmd_list.cml_lock);
	cv_destroy(&state->hs_cmd_list.cml_cv);
	if (state->hs_cmd_list.cml_num_alloc) {
		kmem_free(state->hs_cmd_list.cml_cmd,
		    state->hs_cmd_list.cml_list_sz * sizeof (hermon_cmd_t));
	}
}


/*
 * hermon_mbox_sync()
 */
static void
hermon_mbox_sync(hermon_mbox_t *mbox, uint_t offset, uint_t length,
    uint_t flag)
{
	ddi_dma_handle_t	dmahdl;
	int			status;

	/* Get the DMA handle from mailbox */
	dmahdl = mbox->mb_rsrcptr->hr_dmahdl;

	/* Calculate offset into mailbox */
	status = ddi_dma_sync(dmahdl, (off_t)offset, (size_t)length, flag);
	if (status != DDI_SUCCESS) {
		return;
	}
}


/*
 * hermon_init_hca_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *    (Currently called only from attach() path context)
 */
int
hermon_init_hca_cmd_post(hermon_state_t *state,
    hermon_hw_initqueryhca_t *inithca, uint_t sleepflag)
{
	hermon_mbox_info_t	mbox_info;
	hermon_cmd_post_t	cmd;
	uint64_t		data;
	uint_t			size;
	int			status, i;

	/* Make sure we are called with the correct flag */
	ASSERT(sleepflag == HERMON_CMD_NOSLEEP_SPIN);

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Get an "In" mailbox for the command */
	mbox_info.mbi_alloc_flags = HERMON_ALLOC_INMBOX;
	status = hermon_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != HERMON_CMD_SUCCESS) {
		return (status);
	}

	/* Copy the Hermon "INIT_HCA" command into the mailbox */
	size = sizeof (hermon_hw_initqueryhca_t);
	for (i = 0; i < (size >> 3); i++) {
		data = ((uint64_t *)inithca)[i];
		ddi_put64(mbox_info.mbi_in->mb_acchdl,
		    ((uint64_t *)mbox_info.mbi_in->mb_addr + i), data);
	}

	/* Sync the mailbox for the device to read */
	hermon_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup and post the Hermon "INIT_HCA" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= 0;
	cmd.cp_opcode	= INIT_HCA;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= sleepflag;
	status = hermon_cmd_post(state, &cmd);

	/* Free the mailbox */
	hermon_mbox_free(state, &mbox_info);
	return (status);
}


/*
 * hermon_close_hca_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *    (Currently called only from attach() and/or detach() path contexts)
 */
int
hermon_close_hca_cmd_post(hermon_state_t *state, uint_t sleepflag)
{
	hermon_cmd_post_t	cmd;
	int			status;

	/* Make sure we are called with the correct flag */
	ASSERT(sleepflag == HERMON_CMD_NOSLEEP_SPIN);

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));


	/* Setup and post the Hermon "CLOSE_HCA" command */
	cmd.cp_inparm	= 0;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= 0;
	cmd.cp_opcode	= CLOSE_HCA;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= sleepflag;
	status = hermon_cmd_post(state, &cmd);
	return (status);
}


/*
 * hermon_set_port_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *    (Currently called only from attach() path context)
 */
int
hermon_set_port_cmd_post(hermon_state_t *state, hermon_hw_set_port_t *initport,
    uint_t port, uint_t sleepflag)
{
	hermon_mbox_info_t	mbox_info;
	hermon_cmd_post_t	cmd;
	uint64_t		data;
	uint_t			size;
	int			status, i;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Get an "In" mailbox for the command */
	mbox_info.mbi_alloc_flags = HERMON_ALLOC_INMBOX;
	status = hermon_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != HERMON_CMD_SUCCESS) {
		return (status);
	}

	/* Copy the Hermon "INIT_PORT" command into the mailbox */
	size = sizeof (hermon_hw_set_port_t);
	for (i = 0; i < (size >> 3); i++) {
		data = ((uint64_t *)initport)[i];
		ddi_put64(mbox_info.mbi_in->mb_acchdl,
		    ((uint64_t *)mbox_info.mbi_in->mb_addr + i), data);
	}

	/* Sync the mailbox for the device to read */
	hermon_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup and post the Hermon "SET_PORT" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= port;
	cmd.cp_opcode	= SET_PORT;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= sleepflag;
	status = hermon_cmd_post(state, &cmd);

	/* Free the mailbox */
	hermon_mbox_free(state, &mbox_info);
	return (status);
}


/*
 * hermon_init_port_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *    (Currently called only from attach() and/or detach() path contexts)
 */
int
hermon_init_port_cmd_post(hermon_state_t *state, uint_t port, uint_t sleepflag)
{
	hermon_cmd_post_t	cmd;
	int			status;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Setup and post the Hermon "INIT_PORT" command */
	cmd.cp_inparm	= 0;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= port;
	cmd.cp_opcode	= INIT_PORT;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= sleepflag;
	status = hermon_cmd_post(state, &cmd);

	return (status);
}


/*
 * hermon_close_port_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *    (Currently called only from attach() and/or detach() path contexts)
 */
int
hermon_close_port_cmd_post(hermon_state_t *state, uint_t port, uint_t sleepflag)
{
	hermon_cmd_post_t	cmd;
	int			status;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Setup and post the Hermon "CLOSE_PORT" command */
	cmd.cp_inparm	= 0;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= port;
	cmd.cp_opcode	= CLOSE_PORT;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= sleepflag;
	status = hermon_cmd_post(state, &cmd);
	return (status);
}


/*
 * hermon_mod_stat_cfg_cmd_post()
 *    Context: Can be called only from attach() path
 *
 * This routine was initially implemented to enable SRQ. That's no longer needed
 * in hermon, and the code is conditionally compiled OUT, but left here because
 * there are other static configuration parameters we might one day want to set
 */
#ifdef HERMON_NO_MOD_STAT_CFG
int
hermon_mod_stat_cfg_cmd_post(hermon_state_t *state)
{
	hermon_mbox_info_t	mbox_info;
	hermon_cmd_post_t	cmd;
	hermon_hw_mod_stat_cfg_t	*mod;
	hermon_hw_msg_in_mod_t	inmod;
	uint64_t		data;
	uint_t			size;
	int			status, i;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/*
	 * "MOD_STAT_CFG" needs an INMBOX parameter, to specify what operations
	 * to do.  However, at the point in time that we call this command, the
	 * DDR has not yet been initialized, and all INMBOX'es are located in
	 * DDR.  Because we want to call MOD_STAT_CFG before QUERY_DEVLIM is
	 * called, and thus call it before DDR is setup, we simply use an
	 * OUTMBOX memory location here as our INMBOX parameter.
	 */
	mbox_info.mbi_alloc_flags = HERMON_ALLOC_OUTMBOX;
	status = hermon_mbox_alloc(state, &mbox_info, HERMON_NOSLEEP);
	if (status != HERMON_CMD_SUCCESS) {
		return (status);
	}

	/*
	 * Allocate on the heap our 'mod_stat_cfg' structure.  We want to
	 * ideally move all of this on to the stack in the future, but this
	 * works well for now.
	 */
	mod = (hermon_hw_mod_stat_cfg_t *)kmem_zalloc(
	    sizeof (hermon_hw_mod_stat_cfg_t), KM_SLEEP);

	/* Setup "MOD_STAT_CFG" settings */
	mod->srq_m	= 1;
	mod->srq	= state->hs_cfg_profile->cp_srq_enable;

	if (mod->srq) {
		/*  use DEV_LIMS num srq */
		mod->log_max_srq = state->hs_cfg_profile->cp_log_num_srq;
	} else {
		mod->log_max_srq = 0;
	}

	/* Copy the "MOD_STAT_CFG" command into the "In" mailbox */
	size = sizeof (hermon_hw_mod_stat_cfg_t);
	for (i = 0; i < (size >> 3); i++) {
		data = ((uint64_t *)mod)[i];
		ddi_put64(mbox_info.mbi_in->mb_acchdl,
		    ((uint64_t *)mbox_info.mbi_in->mb_addr + i), data);
	}

	/* Sync the mailbox for the device to read */
	hermon_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup and post the Hermon "MOD_STAT_CFG" command */
	cmd.cp_inparm	= mbox_info.mbi_out->mb_mapaddr;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= 0;
	cmd.cp_opcode	= MOD_STAT_CFG;
	cmd.cp_opmod	= HERMON_MOD_STAT_CFG_PTR;
	cmd.cp_flags	= HERMON_CMD_NOSLEEP_SPIN;
	status = hermon_cmd_post(state, &cmd);

	/* Free "MOD_STAT_CFG" struct */
	kmem_free(mod, sizeof (hermon_hw_mod_stat_cfg_t));

	/* Free the mailbox */
	hermon_mbox_free(state, &mbox_info);
	return (status);
}
#endif


/*
 * hermon_map_cmd_post()
 *    Context: Can be called only from user or kernel context
 *
 * Generic routine to map FW, ICMA, and ICM.
 */
int
hermon_map_cmd_post(hermon_state_t *state, hermon_dma_info_t *dma,
    uint16_t opcode, ddi_dma_cookie_t cookie, uint_t ccount)
{
	hermon_mbox_info_t	mbox_info;
	hermon_cmd_post_t	cmd;
	hermon_hw_vpm_t		vpm;
	uint64_t		data;
	uint64_t		paddr, vaddr;
	uint_t			size;
	int			status, i, j, k = 0;
	int			max_mailbox_size;
	int			cookie_num_icm_pages;
	int			num_vpm_entries;
	int			log2_npages;
	int			npages;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Allocate an IN mailbox */
	mbox_info.mbi_alloc_flags = HERMON_ALLOC_INMBOX;
	status = hermon_mbox_alloc(state, &mbox_info, HERMON_SLEEP);
	if (status != HERMON_CMD_SUCCESS) {
		return (status);
	}

	/* Initialize cmd parameters */
	cmd.cp_outparm	= 0;
	cmd.cp_opcode	= opcode;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= HERMON_CMD_NOSLEEP_SPIN;

	/*
	 * Allocate a list of VPM (Virtual Physical Mapping) structures.
	 * A VPM encodes a power-of-2 number of DMA pages that have been
	 * allocated and are passed in the dma_info. We need to break up
	 * the DMA cookies that are in the dma_info into power-of-2 page
	 * mappings. We also need to keep track of the number of VPMs we
	 * have total, as it is used as the inmod for this command.
	 */

	/* Start with the ICM address passed and the first cookie */
	vaddr  = dma->icmaddr;

	/* Initialize the VPM count and the VPM struct */
	num_vpm_entries = 0;
	size = sizeof (hermon_hw_vpm_t);
	bzero(&vpm, size);

	/*
	 * Establish a max mailbox size (in VPM entries). If we reach this,
	 * we must post a MAP command, reinitialzie num_vpm_entries, and
	 * continue.
	 */
	max_mailbox_size = HERMON_MBOX_SIZE / size;

	/*
	 * First, walk through the DMA cookies and build VPMs from them.
	 */
	while (ccount-- > 0) {

		/* Determine the number of ICM pages in this cookie. */
		cookie_num_icm_pages = cookie.dmac_size / HERMON_PAGESIZE;

		/* Initialize this set of VPM's starting physical address. */
		paddr = cookie.dmac_laddress;

		/*
		 * Now build a set of VPMs for this cookie's memory, breaking
		 * up the cookies into multiple VPMs if necessary to achieve
		 * the required power-of-2 number of pages per VPM. Once each
		 * VPM is constructed, write it out to the mailbox memory.
		 */
		for (i = cookie_num_icm_pages; i > 0; i -= npages) {
			log2_npages = highbit(i) - 1;
			npages	    = (1 << log2_npages);
			/* Ensure this chunk is aligned on it's own size */
			while (((npages * HERMON_PAGESIZE - 1) & paddr) != 0) {
				log2_npages--;
				npages = (1 << log2_npages);
			}
			vpm.log2sz    = log2_npages;

			vpm.paddr_l = (uint32_t)(paddr >> 12);
			vpm.paddr_h = (uint32_t)(paddr >> 32);
			/* Increment the paddr for the next VPM */
			paddr += npages * HERMON_PAGESIZE;

			if (opcode == MAP_ICM) {
				vpm.vaddr_l = (uint32_t)(vaddr >> 12);
				vpm.vaddr_h = (uint32_t)(vaddr >> 32);
				/* Increment the ICM address for the next VPM */
				vaddr += npages * HERMON_PAGESIZE;
			}

			/*
			 * Copy this VPM into the "In" mailbox. Note we're
			 * using 'k' as the offset from mb_addr for this cmd.
			 */
			for (j = 0; j < (size >> 3); j++, k++) {
				data = ((uint64_t *)(void *)&vpm)[j];
				ddi_put64(mbox_info.mbi_in->mb_acchdl,
				    ((uint64_t *)mbox_info.mbi_in->mb_addr + k),
				    data);
			}

			/*
			 * Increment the number of VPM entries and check
			 * against max mailbox size. If we have reached
			 * the maximum mailbox size, post the map cmd.
			 */
			if (++num_vpm_entries == max_mailbox_size) {

				/* Sync the mailbox for the device to read */
				hermon_mbox_sync(mbox_info.mbi_in, 0, (size *
				    num_vpm_entries), DDI_DMA_SYNC_FORDEV);

				/* Setup and post the command */
				cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
				cmd.cp_inmod	= num_vpm_entries;
				status = hermon_cmd_post(state, &cmd);
				if (status != HERMON_CMD_SUCCESS) {
					cmn_err(CE_NOTE, "hermon%d: %s cmd "
					    "failed (0x%x)", state->hs_instance,
					    opcode == MAP_FA ? "MAP_FA" :
					    opcode == MAP_ICM ? "MAP_ICM" :
					    opcode == MAP_ICM_AUX ? "MAP_ICMA" :
					    "UNKNOWN", status);
					goto map_fail;
				}

				/*
				 * Reinitialize num_vpm_entries, and the
				 * mb_addr offset
				 */
				num_vpm_entries = k = 0;
			}
		}

		/* If count remains, move onto the next cookie */
		if (ccount != 0) {
			ddi_dma_nextcookie(dma->dma_hdl, &cookie);
		}
	}

	if (num_vpm_entries) {

		/* Sync the mailbox for the device to read */
		hermon_mbox_sync(mbox_info.mbi_in, 0, (size * num_vpm_entries),
		    DDI_DMA_SYNC_FORDEV);

		/* Setup and post the command */
		cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
		cmd.cp_inmod	= num_vpm_entries;
		status = hermon_cmd_post(state, &cmd);
		if (status != HERMON_CMD_SUCCESS) {
			cmn_err(CE_NOTE, "hermon%d: %s cmd "
			    "failed (0x%x)", state->hs_instance,
			    opcode == MAP_FA ? "MAP_FA" :
			    opcode == MAP_ICM ? "MAP_ICM" :
			    opcode == MAP_ICM_AUX ? "MAP_ICMA" :
			    "UNKNOWN", status);
			goto map_fail;
		}
	}

map_fail:
	/* Free the mailbox */
	hermon_mbox_free(state, &mbox_info);
	return (status);
}


/*
 * hermon_unmap_fa_cmd_post()
 *    Context: Can be called only from attach() path
 */
int
hermon_unmap_fa_cmd_post(hermon_state_t *state)
{
	hermon_cmd_post_t	cmd;
	int			status;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Setup and post the Hermon "UNMAP_FA" command */
	cmd.cp_inparm	= 0;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= 0;
	cmd.cp_opcode	= UNMAP_FA;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= HERMON_CMD_NOSLEEP_SPIN;
	status = hermon_cmd_post(state, &cmd);

	return (status);
}


/*
 * hermon_run_fw_cmd_post()
 *    Context: Can be called only from attach() path
 */
int
hermon_run_fw_cmd_post(hermon_state_t *state)
{
	hermon_cmd_post_t	cmd;
	int			status;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Setup and post the Hermon "RUN_FW" command */
	cmd.cp_inparm	= 0;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= 0;
	cmd.cp_opcode	= RUN_FW;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= HERMON_CMD_NOSLEEP_SPIN;

	status = hermon_cmd_post(state, &cmd);
#ifdef FMA_TEST
	if (hermon_test_num == -2) {
		status = HERMON_CMD_BAD_NVMEM;
		/*
		 * No need of an ereport here since this case
		 * is treated as a degradation later.
		 */
		HERMON_FMANOTE(state, HERMON_FMA_BADNVMEM);
	}
#endif
	return (status);
}


/*
 * hermon_set_icm_size_cmd_post()
 *    Context: Can be called only from attach() path
 */
int
hermon_set_icm_size_cmd_post(hermon_state_t *state)
{
	hermon_cmd_post_t	cmd;
	int			status;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Setup and post the Hermon "SET_ICM_SIZE" command */
	cmd.cp_inparm	= (uint64_t)state->hs_icm_sz;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= 0;
	cmd.cp_opcode	= SET_ICM_SIZE;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= HERMON_CMD_NOSLEEP_SPIN;
	status = hermon_cmd_post(state, &cmd);

	/*
	 * Aux ICM size in 4K pages returned in output param
	 * convert it to bytes
	 */
	state->hs_icma_sz = (uint64_t)(cmd.cp_outparm << HERMON_PAGESHIFT);
	return (status);
}


/*
 * hermon_unmap_icm_aux_cmd_post()
 *    Context: Can be called only from attach() path
 */
int
hermon_unmap_icm_aux_cmd_post(hermon_state_t *state)
{
	hermon_cmd_post_t	cmd;
	int			status;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Setup and post the Hermon "UNMAP_ICM_AUX" command */
	cmd.cp_inparm	= 0;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= 0;
	cmd.cp_opcode	= UNMAP_ICM_AUX;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= HERMON_CMD_NOSLEEP_SPIN;
	status = hermon_cmd_post(state, &cmd);
	return (status);
}


/*
 * hermon_unmap_icm_cmd_post()
 *    Context: Can be called from base or attach context
 */
int
hermon_unmap_icm_cmd_post(hermon_state_t *state, hermon_dma_info_t *dma_info)
{
	hermon_cmd_post_t	cmd;
	uint64_t		addr;
	uint32_t		npages;
	int			status;

	/*
	 * Setup and post the Hermon "UNMAP_ICM" command. If a
	 * hermon_dma_info_t was passed, we want to unmap a set
	 * of pages. Otherwise, unmap all of ICM.
	 */
	if (dma_info != NULL) {
		addr   = dma_info->icmaddr;
		npages = dma_info->length / HERMON_PAGESIZE;
	} else {
		addr   = 0;
		npages = state->hs_icm_sz / HERMON_PAGESIZE;
	}

	/* Setup and post the Hermon "UNMAP_ICM" command */
	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));
	cmd.cp_inparm	= addr;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= npages;
	cmd.cp_opcode	= UNMAP_ICM;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= HERMON_CMD_NOSLEEP_SPIN;
	status = hermon_cmd_post(state, &cmd);
	return (status);
}


/*
 * hermon_mad_ifc_cmd_post()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_mad_ifc_cmd_post(hermon_state_t *state, uint_t port,
    uint_t sleepflag, uint32_t *mad, uint32_t *resp)
{
	hermon_mbox_info_t	mbox_info;
	hermon_cmd_post_t	cmd;
	uint_t			size;
	int			status;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Get "In" and "Out" mailboxes for the command */
	mbox_info.mbi_alloc_flags = HERMON_ALLOC_INMBOX | HERMON_ALLOC_OUTMBOX;
	status = hermon_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != HERMON_CMD_SUCCESS) {
		return (status);
	}

	/* Copy the request MAD into the "In" mailbox */
	size = HERMON_CMD_MAD_IFC_SIZE;
	bcopy(mad, mbox_info.mbi_in->mb_addr, size);

	/* Sync the mailbox for the device to read */
	hermon_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup the Hermon "MAD_IFC" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= mbox_info.mbi_out->mb_mapaddr;
	cmd.cp_inmod	= port;
	cmd.cp_opcode	= MAD_IFC;
	cmd.cp_opmod	= HERMON_CMD_MKEY_CHECK;  /* Enable MKey checking */
	cmd.cp_flags	= sleepflag;
	status = hermon_cmd_post(state, &cmd);
	if (status != HERMON_CMD_SUCCESS) {
		goto mad_ifc_fail;
	}

	/* Sync the mailbox to read the results */
	hermon_mbox_sync(mbox_info.mbi_out, 0, size, DDI_DMA_SYNC_FORCPU);

	/* Copy the response MAD into "resp" */
	bcopy(mbox_info.mbi_out->mb_addr, resp, size);

mad_ifc_fail:
	/* Free the mailbox */
	hermon_mbox_free(state, &mbox_info);
	return (status);
}


/*
 * hermon_getportinfo_cmd_post()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_getportinfo_cmd_post(hermon_state_t *state, uint_t port,
    uint_t sleepflag, sm_portinfo_t *portinfo)
{
	hermon_mbox_info_t	mbox_info;
	hermon_cmd_post_t	cmd;
	uint32_t		*mbox;
	uint_t			size;
	int			status, i;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Get "In" and "Out" mailboxes for the command */
	mbox_info.mbi_alloc_flags = HERMON_ALLOC_INMBOX | HERMON_ALLOC_OUTMBOX;
	status = hermon_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != HERMON_CMD_SUCCESS) {
		return (status);
	}

	/* Build the GetPortInfo request MAD in the "In" mailbox */
	size = HERMON_CMD_MAD_IFC_SIZE;
	mbox = (uint32_t *)mbox_info.mbi_in->mb_addr;
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[0], HERMON_CMD_MADHDR0);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[1], HERMON_CMD_MADHDR1);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[2], HERMON_CMD_MADHDR2);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[3], HERMON_CMD_MADHDR3);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[4], HERMON_CMD_PORTINFO);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[5], port);
	for (i = 6; i < (size >> 2); i++) {
		ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[i], 0);
	}

	/* Sync the mailbox for the device to read */
	hermon_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup the Hermon "MAD_IFC" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= mbox_info.mbi_out->mb_mapaddr;
	cmd.cp_inmod	= port;
	cmd.cp_opcode	= MAD_IFC;
	cmd.cp_opmod	= HERMON_CMD_MKEY_DONTCHECK;  /* No MKey checking */
	cmd.cp_flags	= HERMON_CMD_NOSLEEP_SPIN; /* NO SLEEP */
	status = hermon_cmd_post(state, &cmd);
	if (status != HERMON_CMD_SUCCESS) {
		goto getportinfo_fail;
	}

	/* Sync the mailbox to read the results */
	size = sizeof (sm_portinfo_t);
	hermon_mbox_sync(mbox_info.mbi_out, HERMON_CMD_MADDATA_OFFSET,
	    size, DDI_DMA_SYNC_FORCPU);

	/*
	 * Copy GetPortInfo response MAD into "portinfo".  Do any endian
	 * swapping that may be necessary to flip any of the "portinfo"
	 * fields
	 */
	bcopy((void *)((uintptr_t)mbox_info.mbi_out->mb_addr +
	    HERMON_CMD_MADDATA_OFFSET), portinfo, size);
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*portinfo))
	HERMON_GETPORTINFO_SWAP(portinfo);

getportinfo_fail:
	/* Free the mailbox */
	hermon_mbox_free(state, &mbox_info);
	return (status);
}

/*
 * hermon_is_ext_port_counters_supported()
 *
 * Determine weather extended port counters are supported or not by sending
 * ClassPortInfo perf mgmt class MAD.
 */
int
hermon_is_ext_port_counters_supported(hermon_state_t *state, uint_t port,
    uint_t sleepflag, int *ext_width_supported)
{
	hermon_mbox_info_t	mbox_info;
	hermon_cmd_post_t	cmd;
	uint64_t		data;
	uint32_t		*mbox;
	int			status;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Get "In" and "Out" mailboxes for the command */
	mbox_info.mbi_alloc_flags = HERMON_ALLOC_INMBOX | HERMON_ALLOC_OUTMBOX;
	status = hermon_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != HERMON_CMD_SUCCESS) {
		return (status);
	}

	/* Build the ClassPortInfo request MAD in the "In" mailbox */
	mbox = (uint32_t *)mbox_info.mbi_in->mb_addr;

	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[0], HERMON_CMD_PERF_GET);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[1], HERMON_CMD_MADHDR1);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[2], HERMON_CMD_MADHDR2);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[3], HERMON_CMD_MADHDR3);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[4],
	    HERMON_CMD_CLASSPORTINFO);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[5], HERMON_CMD_PERFATTR);

	/* Sync the mailbox for the device to read */
	hermon_mbox_sync(mbox_info.mbi_in, 0, HERMON_CMD_MAD_IFC_SIZE,
	    DDI_DMA_SYNC_FORDEV);

	/* Setup the Hermon "MAD_IFC" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= mbox_info.mbi_out->mb_mapaddr;
	cmd.cp_inmod	= port;
	cmd.cp_opcode	= MAD_IFC;
	/* No MKey and BKey checking */
	cmd.cp_opmod	= HERMON_CMD_MKEY_DONTCHECK | HERMON_CMD_BKEY_DONTCHECK;
	cmd.cp_flags	= HERMON_CMD_NOSLEEP_SPIN; /* NO SLEEP */
	status = hermon_cmd_post(state, &cmd);
	if (status != HERMON_CMD_SUCCESS) {
		goto fail;
	}

	/* Sync the mailbox to read the results */
	hermon_mbox_sync(mbox_info.mbi_out, 0, HERMON_CMD_MAD_IFC_SIZE,
	    DDI_DMA_SYNC_FORCPU);

	/*
	 * We can discard the MAD header and the reserved area of the
	 * perf mgmt class MAD
	 */
	data = ddi_get64(mbox_info.mbi_out->mb_acchdl,
	    ((uint64_t *)mbox_info.mbi_out->mb_addr + 8));
	*ext_width_supported = (data & (HERMON_IS_EXT_WIDTH_SUPPORTED |
	    HERMON_IS_EXT_WIDTH_SUPPORTED_NOIETF)) ? 1 : 0;

fail:
	/* Free the mailbox */
	hermon_mbox_free(state, &mbox_info);
	return (status);
}

/*
 * hermon_getextpefcntr_cmd_post()
 *
 * Read the extended performance counters of the specified port and
 * copy them into perfinfo.
 */
int
hermon_getextperfcntr_cmd_post(hermon_state_t *state, uint_t port,
    uint_t sleepflag, hermon_hw_sm_extperfcntr_t *perfinfo)
{
	hermon_mbox_info_t	mbox_info;
	hermon_cmd_post_t	cmd;
	uint64_t		data;
	uint32_t		*mbox;
	int			status, i;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Get "In" and "Out" mailboxes for the command */
	mbox_info.mbi_alloc_flags = HERMON_ALLOC_INMBOX | HERMON_ALLOC_OUTMBOX;
	status = hermon_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != HERMON_CMD_SUCCESS) {
		return (status);
	}

	/* Build PortCountersExtended request MAD in the "In" mailbox */
	mbox = (uint32_t *)mbox_info.mbi_in->mb_addr;

	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[0], HERMON_CMD_PERF_GET);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[1], HERMON_CMD_MADHDR1);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[2], HERMON_CMD_MADHDR2);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[3], HERMON_CMD_MADHDR3);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[4],
	    HERMON_CMD_EXTPERFCNTRS);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[5], HERMON_CMD_PERFATTR);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[16], (port << 16));

	/* Sync the mailbox for the device to read */
	hermon_mbox_sync(mbox_info.mbi_in, 0, HERMON_CMD_MAD_IFC_SIZE,
	    DDI_DMA_SYNC_FORDEV);

	/* Setup the Hermon "MAD_IFC" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= mbox_info.mbi_out->mb_mapaddr;
	cmd.cp_inmod	= port;
	cmd.cp_opcode	= MAD_IFC;
	/* No MKey and BKey checking */
	cmd.cp_opmod	= HERMON_CMD_MKEY_DONTCHECK | HERMON_CMD_BKEY_DONTCHECK;
	cmd.cp_flags	= HERMON_CMD_NOSLEEP_SPIN; /* NO SLEEP */
	status = hermon_cmd_post(state, &cmd);
	if (status != HERMON_CMD_SUCCESS) {
		goto fail;
	}

	/* Sync the mailbox to read the results */
	hermon_mbox_sync(mbox_info.mbi_out, 0, HERMON_CMD_MAD_IFC_SIZE,
	    DDI_DMA_SYNC_FORCPU);

	/*
	 * Copy Perfcounters into "perfinfo". We can discard the MAD
	 * header and the reserved area of the perf mgmt class MAD.
	 */
	for (i = 0; i < (sizeof (hermon_hw_sm_extperfcntr_t) >> 3); i++) {
		data = ddi_get64(mbox_info.mbi_out->mb_acchdl,
		    ((uint64_t *)mbox_info.mbi_out->mb_addr + i + 8));
		((uint64_t *)(void *)perfinfo)[i] = data;
	}

fail:
	/* Free the mailbox */
	hermon_mbox_free(state, &mbox_info);
	return (status);
}

/*
 * hermon_getpefcntr_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *
 * If reset is zero, read the performance counters of the specified port and
 * copy them into perfinfo.
 * If reset is non-zero reset the performance counters of the specified port.
 */
int
hermon_getperfcntr_cmd_post(hermon_state_t *state, uint_t port,
    uint_t sleepflag, hermon_hw_sm_perfcntr_t *perfinfo, int reset)
{
	hermon_mbox_info_t	mbox_info;
	hermon_cmd_post_t	cmd;
	uint64_t		data;
	uint32_t		*mbox;
	uint_t			size;
	int			status, i;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Get "In" and "Out" mailboxes for the command */
	mbox_info.mbi_alloc_flags = HERMON_ALLOC_INMBOX | HERMON_ALLOC_OUTMBOX;
	status = hermon_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != HERMON_CMD_SUCCESS) {
		return (status);
	}

	/* Build the GetPortInfo request MAD in the "In" mailbox */
	size = HERMON_CMD_MAD_IFC_SIZE;
	mbox = (uint32_t *)mbox_info.mbi_in->mb_addr;

	if (reset) {
		ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[0],
		    HERMON_CMD_PERF_SET);
	} else {
		ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[0],
		    HERMON_CMD_PERF_GET);
	}
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[1], HERMON_CMD_MADHDR1);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[2], HERMON_CMD_MADHDR2);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[3], HERMON_CMD_MADHDR3);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[4], HERMON_CMD_PERFCNTRS);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[5], HERMON_CMD_PERFATTR);

	if (reset) {
		/* reset counters for XmitData, RcvData, XmitPkts, RcvPkts */
		ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[16],
		    ((port << 16) | 0xf000));

		ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[22], 0);
		ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[23], 0);
		ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[24], 0);
		ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[25], 0);
	} else
		ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[16], (port << 16));

	/* Sync the mailbox for the device to read */
	hermon_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup the Hermon "MAD_IFC" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= mbox_info.mbi_out->mb_mapaddr;
	cmd.cp_inmod	= port;
	cmd.cp_opcode	= MAD_IFC;
	/* No MKey and BKey checking */
	cmd.cp_opmod	= HERMON_CMD_MKEY_DONTCHECK | HERMON_CMD_BKEY_DONTCHECK;
	cmd.cp_flags	= HERMON_CMD_NOSLEEP_SPIN; /* NO SLEEP */
	status = hermon_cmd_post(state, &cmd);
	if (status != HERMON_CMD_SUCCESS) {
		goto getperfinfo_fail;
	}

	/* Sync the mailbox to read the results */
	size = HERMON_CMD_MAD_IFC_SIZE;
	hermon_mbox_sync(mbox_info.mbi_out, 0, size, DDI_DMA_SYNC_FORCPU);

	if (reset == 0) {
		size = sizeof (hermon_hw_sm_perfcntr_t); /* for the copy */
		/*
		 * Copy Perfcounters into "perfinfo".  We can discard the MAD
		 * header and the 8 Quadword reserved area of the PERM mgmt
		 * class MAD
		 */

		for (i = 0; i < size >> 3; i++) {
			data = ddi_get64(mbox_info.mbi_out->mb_acchdl,
			    ((uint64_t *)mbox_info.mbi_out->mb_addr + i + 8));
			((uint64_t *)(void *)perfinfo)[i] = data;
		}
	}

getperfinfo_fail:
	/* Free the mailbox */
	hermon_mbox_free(state, &mbox_info);
	return (status);
}



/*
 * hermon_getnodeinfo_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *    (Currently called only from attach() and detach() path contexts)
 */
int
hermon_getnodeinfo_cmd_post(hermon_state_t *state, uint_t sleepflag,
    sm_nodeinfo_t *nodeinfo)
{
	hermon_mbox_info_t	mbox_info;
	hermon_cmd_post_t	cmd;
	uint32_t		*mbox;
	uint_t			size;
	int			status, i;

	/* Make sure we are called with the correct flag */
	ASSERT(sleepflag == HERMON_CMD_NOSLEEP_SPIN);

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Get "In" and "Out" mailboxes for the command */
	mbox_info.mbi_alloc_flags = HERMON_ALLOC_INMBOX | HERMON_ALLOC_OUTMBOX;
	status = hermon_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != HERMON_CMD_SUCCESS) {
		return (status);
	}

	/* Build the GetNodeInfo request MAD into the "In" mailbox */
	size = HERMON_CMD_MAD_IFC_SIZE;
	mbox = (uint32_t *)mbox_info.mbi_in->mb_addr;
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[0], HERMON_CMD_MADHDR0);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[1], HERMON_CMD_MADHDR1);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[2], HERMON_CMD_MADHDR2);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[3], HERMON_CMD_MADHDR3);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[4], HERMON_CMD_NODEINFO);
	for (i = 5; i < (size >> 2); i++) {
		ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[i], 0);
	}

	/* Sync the mailbox for the device to read */
	hermon_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup the Hermon "MAD_IFC" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= mbox_info.mbi_out->mb_mapaddr;
	cmd.cp_inmod	= 1;  /* Get NodeInfo from port #1 */
	cmd.cp_opcode	= MAD_IFC;
	cmd.cp_opmod	= HERMON_CMD_MKEY_DONTCHECK;  /* No MKey checking */
	cmd.cp_flags	= sleepflag;
	status = hermon_cmd_post(state, &cmd);
	if (status != HERMON_CMD_SUCCESS) {
		goto getnodeinfo_fail;
	}

	/* Sync the mailbox to read the results */
	size = sizeof (sm_nodeinfo_t);
	hermon_mbox_sync(mbox_info.mbi_out, HERMON_CMD_MADDATA_OFFSET,
	    size, DDI_DMA_SYNC_FORCPU);

	/*
	 * Copy GetNodeInfo response MAD into "nodeinfo".  Do any endian
	 * swapping that may be necessary to flip any of the "nodeinfo"
	 * fields
	 */
	bcopy((void *)((uintptr_t)mbox_info.mbi_out->mb_addr +
	    HERMON_CMD_MADDATA_OFFSET), nodeinfo, size);
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*nodeinfo))
	HERMON_GETNODEINFO_SWAP(nodeinfo);

getnodeinfo_fail:
	/* Free the mailbox */
	hermon_mbox_free(state, &mbox_info);
	return (status);
}


/*
 * hermon_getnodedesc_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *    (Currently called only from attach() and detach() path contexts)
 */
int
hermon_getnodedesc_cmd_post(hermon_state_t *state, uint_t sleepflag,
    sm_nodedesc_t *nodedesc)
{
	hermon_mbox_info_t	mbox_info;
	hermon_cmd_post_t	cmd;
	uint32_t		*mbox;
	uint_t			size;
	int			status, i;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Get "In" and "Out" mailboxes for the command */
	mbox_info.mbi_alloc_flags = HERMON_ALLOC_INMBOX | HERMON_ALLOC_OUTMBOX;
	status = hermon_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != HERMON_CMD_SUCCESS) {
		return (status);
	}

	/* Build the GetNodeDesc request MAD into the "In" mailbox */
	size = HERMON_CMD_MAD_IFC_SIZE;
	mbox = (uint32_t *)mbox_info.mbi_in->mb_addr;
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[0], HERMON_CMD_MADHDR0);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[1], HERMON_CMD_MADHDR1);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[2], HERMON_CMD_MADHDR2);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[3], HERMON_CMD_MADHDR3);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[4], HERMON_CMD_NODEDESC);
	for (i = 5; i < (size >> 2); i++) {
		ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[i], 0);
	}

	/* Sync the mailbox for the device to read */
	hermon_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup the Hermon "MAD_IFC" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= mbox_info.mbi_out->mb_mapaddr;
	cmd.cp_inmod	= 1;  /* Get NodeDesc from port #1 */
	cmd.cp_opcode	= MAD_IFC;
	cmd.cp_opmod	= HERMON_CMD_MKEY_DONTCHECK;  /* No MKey checking */
	cmd.cp_flags	= sleepflag;
	status = hermon_cmd_post(state, &cmd);
	if (status != HERMON_CMD_SUCCESS) {
		goto getnodedesc_fail;
	}

	/* Sync the mailbox to read the results */
	size = sizeof (sm_nodedesc_t);
	hermon_mbox_sync(mbox_info.mbi_out, HERMON_CMD_MADDATA_OFFSET,
	    size, DDI_DMA_SYNC_FORCPU);

	/* Copy GetNodeDesc response MAD into "nodedesc" */
	bcopy((void *)((uintptr_t)mbox_info.mbi_out->mb_addr +
	    HERMON_CMD_MADDATA_OFFSET), nodedesc, size);

getnodedesc_fail:
	/* Free the mailbox */
	hermon_mbox_free(state, &mbox_info);
	return (status);
}


/*
 * hermon_getguidinfo_cmd_post()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_getguidinfo_cmd_post(hermon_state_t *state, uint_t port,
    uint_t guidblock, uint_t sleepflag, sm_guidinfo_t *guidinfo)
{
	hermon_mbox_info_t	mbox_info;
	hermon_cmd_post_t	cmd;
	uint32_t		*mbox;
	uint_t			size;
	int			status, i;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Get "In" and "Out" mailboxes for the command */
	mbox_info.mbi_alloc_flags = HERMON_ALLOC_INMBOX | HERMON_ALLOC_OUTMBOX;
	status = hermon_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != HERMON_CMD_SUCCESS) {
		return (status);
	}

	/* Build the GetGUIDInfo request MAD into the "In" mailbox */
	size = HERMON_CMD_MAD_IFC_SIZE;
	mbox = (uint32_t *)mbox_info.mbi_in->mb_addr;
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[0], HERMON_CMD_MADHDR0);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[1], HERMON_CMD_MADHDR1);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[2], HERMON_CMD_MADHDR2);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[3], HERMON_CMD_MADHDR3);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[4], HERMON_CMD_GUIDINFO);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[5], guidblock);
	for (i = 6; i < (size >> 2); i++) {
		ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[i], 0);
	}

	/* Sync the mailbox for the device to read */
	hermon_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup the Hermon "MAD_IFC" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= mbox_info.mbi_out->mb_mapaddr;
	cmd.cp_inmod	= port;
	cmd.cp_opcode	= MAD_IFC;
	cmd.cp_opmod	= HERMON_CMD_MKEY_DONTCHECK;  /* No MKey checking */
	cmd.cp_flags	= sleepflag;
	status = hermon_cmd_post(state, &cmd);
	if (status != HERMON_CMD_SUCCESS) {
		goto getguidinfo_fail;
	}

	/* Sync the mailbox to read the results */
	size = sizeof (sm_guidinfo_t);
	hermon_mbox_sync(mbox_info.mbi_out, HERMON_CMD_MADDATA_OFFSET,
	    size, DDI_DMA_SYNC_FORCPU);

	/*
	 * Copy GetGUIDInfo response MAD into "guidinfo".  Do any endian
	 * swapping that may be necessary to flip the "guidinfo" fields
	 */
	bcopy((void *)((uintptr_t)mbox_info.mbi_out->mb_addr +
	    HERMON_CMD_MADDATA_OFFSET), guidinfo, size);
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*guidinfo))
	HERMON_GETGUIDINFO_SWAP(guidinfo);

getguidinfo_fail:
	/* Free the mailbox */
	hermon_mbox_free(state, &mbox_info);
	return (status);
}


/*
 * hermon_getpkeytable_cmd_post()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_getpkeytable_cmd_post(hermon_state_t *state, uint_t port,
    uint_t pkeyblock, uint_t sleepflag, sm_pkey_table_t *pkeytable)
{
	hermon_mbox_info_t	mbox_info;
	hermon_cmd_post_t	cmd;
	uint32_t		*mbox;
	uint_t			size;
	int			status, i;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Get "In" and "Out" mailboxes for the command */
	mbox_info.mbi_alloc_flags = HERMON_ALLOC_INMBOX | HERMON_ALLOC_OUTMBOX;
	status = hermon_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != HERMON_CMD_SUCCESS) {
		return (status);
	}

	/* Build the GetPkeyTable request MAD into the "In" mailbox */
	size = HERMON_CMD_MAD_IFC_SIZE;
	mbox = (uint32_t *)mbox_info.mbi_in->mb_addr;
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[0], HERMON_CMD_MADHDR0);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[1], HERMON_CMD_MADHDR1);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[2], HERMON_CMD_MADHDR2);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[3], HERMON_CMD_MADHDR3);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[4], HERMON_CMD_PKEYTBLE);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[5], pkeyblock);
	for (i = 6; i < (size >> 2); i++) {
		ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[i], 0);
	}

	/* Sync the mailbox for the device to read */
	hermon_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup the Hermon "MAD_IFC" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= mbox_info.mbi_out->mb_mapaddr;
	cmd.cp_inmod	= port;
	cmd.cp_opcode	= MAD_IFC;
	cmd.cp_opmod	= HERMON_CMD_MKEY_DONTCHECK;  /* No MKey checking */
	cmd.cp_flags	= sleepflag;
	status = hermon_cmd_post(state, &cmd);
	if (status != HERMON_CMD_SUCCESS) {
		goto getpkeytable_fail;
	}

	/* Sync the mailbox to read the results */
	size = sizeof (sm_pkey_table_t);
	hermon_mbox_sync(mbox_info.mbi_out, HERMON_CMD_MADDATA_OFFSET,
	    size, DDI_DMA_SYNC_FORCPU);

	/*
	 * Copy GetPKeyTable response MAD into "pkeytable".  Do any endian
	 * swapping that may be necessary to flip the "pkeytable" fields
	 */
	bcopy((void *)((uintptr_t)mbox_info.mbi_out->mb_addr +
	    HERMON_CMD_MADDATA_OFFSET), pkeytable, size);
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*pkeytable))
	HERMON_GETPKEYTABLE_SWAP(pkeytable);

getpkeytable_fail:
	/* Free the mailbox */
	hermon_mbox_free(state, &mbox_info);
	return (status);
}


/*
 * hermon_write_mtt_cmd_post()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_write_mtt_cmd_post(hermon_state_t *state, hermon_rsrc_t *mtt,
    uint64_t start_addr, uint_t nummtt, uint_t sleepflag)
{
	hermon_mbox_info_t	mbox_info;
	hermon_cmd_post_t	cmd;
	uint64_t		data;
	uint_t			size;
	int			status;
	int			i;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Get an "In" mailbox for the command */
	mbox_info.mbi_alloc_flags = HERMON_ALLOC_INMBOX;
	status = hermon_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != HERMON_CMD_SUCCESS) {
		return (status);
	}

	/*
	 * The WRITE_MTT command input parameter contains the 64-bit addr of
	 * the first target MTT, followed by 64 bits reserved, followed by an
	 * array of MTT entries.
	 *
	 */
	ddi_put64(mbox_info.mbi_in->mb_acchdl,
	    ((uint64_t *)mbox_info.mbi_in->mb_addr),
	    start_addr);

	ddi_put64(mbox_info.mbi_in->mb_acchdl,
	    ((uint64_t *)mbox_info.mbi_in->mb_addr + 1), 0x0);

	for (i = 0; i < nummtt; i++) {
		data = ((uint64_t *)mtt->hr_addr)[i];
		ddi_put64(mbox_info.mbi_in->mb_acchdl,
		    ((uint64_t *)mbox_info.mbi_in->mb_addr + i + 2), data);
	}

	/* Sync the mailbox for the device to read */
	size = (nummtt << HERMON_MTT_SIZE_SHIFT) + HERMON_CMD_WRITEMTT_RSVD_SZ;
	hermon_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup and post Hermon "WRITE_MTT" command */
	cmd.cp_inparm   = mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm  = 0;
	cmd.cp_inmod    = nummtt;
	cmd.cp_opcode   = WRITE_MTT;
	cmd.cp_opmod    = 0;
	cmd.cp_flags    = sleepflag;
	status = hermon_cmd_post(state, &cmd);
	if (status != HERMON_CMD_SUCCESS) {
		cmn_err(CE_CONT, "WRITE_MTT failed (0x%x)\n", status);
	}

	/* Free the mailbox */
	hermon_mbox_free(state, &mbox_info);
	return (status);
}


/*
 * hermon_sync_tpt_cmd_post()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_sync_tpt_cmd_post(hermon_state_t *state, uint_t sleepflag)
{
	hermon_cmd_post_t	cmd;
	int			status;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Setup and post the Hermon "SYNC_TPT" command */
	cmd.cp_inparm	= 0;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= 0;
	cmd.cp_opcode	= SYNC_TPT;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= sleepflag;
	status = hermon_cmd_post(state, &cmd);

	return (status);
}

/*
 * hermon_map_eq_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *    (Currently called only from attach() and/or detach() path contexts)
 */
int
hermon_map_eq_cmd_post(hermon_state_t *state, uint_t map, uint_t eqcindx,
    uint64_t eqmapmask, uint_t sleepflag)
{
	hermon_cmd_post_t	cmd;
	int			status;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Setup and post Hermon "MAP_EQ" command */
	cmd.cp_inparm	= eqmapmask;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= eqcindx;
	if (map != HERMON_CMD_MAP_EQ_EVT_MAP) {
		cmd.cp_inmod |= HERMON_CMD_UNMAP_EQ_MASK;
	}
	cmd.cp_opcode	= MAP_EQ;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= sleepflag;
	status = hermon_cmd_post(state, &cmd);
	return (status);
}


/*
 * hermon_resize_cq_cmd_post()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_resize_cq_cmd_post(hermon_state_t *state, hermon_hw_cqc_t *cqc,
    uint_t cqcindx, uint32_t *prod_indx, uint_t sleepflag)
{
	hermon_mbox_info_t	mbox_info;
	hermon_cmd_post_t	cmd;
	uint64_t		data;
	uint_t			size;
	int			status, i;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Get an "In" mailbox for the command */
	mbox_info.mbi_alloc_flags = HERMON_ALLOC_INMBOX;
	status = hermon_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != HERMON_CMD_SUCCESS) {
		return (status);
	}

	/* Copy the Hermon "MODIFY_CQ" command into mailbox */
	size = sizeof (hermon_hw_cqc_t);
	for (i = 0; i < (size >> 3); i++) {
		data = ((uint64_t *)(void *)cqc)[i];
		ddi_put64(mbox_info.mbi_in->mb_acchdl,
		    ((uint64_t *)mbox_info.mbi_in->mb_addr + i), data);
	}

	/* Sync the mailbox for the device to read */
	hermon_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup and post Hermon "MODIFY_CQ" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= 0;	/* resize cq */
	cmd.cp_inmod	= cqcindx;
	cmd.cp_opcode	= MODIFY_CQ;
	cmd.cp_opmod	= RESIZE_CQ;
	cmd.cp_flags	= sleepflag;
	status = hermon_cmd_post(state, &cmd);

	/*
	 * New "producer index" is returned in the upper 32 bits of
	 * command "outparam"
	 */
	*prod_indx = (cmd.cp_outparm >> 32);

	/* Free the mailbox */
	hermon_mbox_free(state, &mbox_info);
	return (status);
}


/*
 * hermon_modify_cq_cmd_post()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_modify_cq_cmd_post(hermon_state_t *state, hermon_hw_cqc_t *cqc,
    uint_t cqcindx, uint_t opmod, uint_t sleepflag)
{
	hermon_mbox_info_t	mbox_info;
	hermon_cmd_post_t	cmd;
	uint64_t		data;
	uint_t			size;
	int			status, i;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Get an "In" mailbox for the command */
	mbox_info.mbi_alloc_flags = HERMON_ALLOC_INMBOX;
	status = hermon_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != HERMON_CMD_SUCCESS) {
		return (status);
	}

	/* Copy the Hermon "MODIFY_CQ" command into mailbox */
	size = sizeof (hermon_hw_cqc_t);
	for (i = 0; i < (size >> 3); i++) {
		data = ((uint64_t *)(void *)cqc)[i];
		ddi_put64(mbox_info.mbi_in->mb_acchdl,
		    ((uint64_t *)mbox_info.mbi_in->mb_addr + i), data);
	}

	/* Sync the mailbox for the device to read */
	hermon_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup and post Hermon "MODIFY_CQ" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= cqcindx;
	cmd.cp_opcode	= MODIFY_CQ;
	cmd.cp_opmod	= (uint16_t)opmod;
	cmd.cp_flags	= sleepflag;
	status = hermon_cmd_post(state, &cmd);

	/* Free the mailbox */
	hermon_mbox_free(state, &mbox_info);
	return (status);
}


/*
 * hermon_cmn_qp_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *
 *    This is the common function for posting all the various types of
 *    QP state transition related Hermon commands.  Since some of the
 *    commands differ from the others in the number (and type) of arguments
 *    that each require, this routine does checks based on opcode type
 *    (explained in more detail below).
 *
 * Note: This common function should be used only with the following
 *    opcodes: RTS2SQD_QP, TOERR_QP, TORST_QP, RST2INIT_QP, INIT2INIT_QP,
 *    INIT2RTR_QP, RTR2RTS_QP, RTS2RTS_QP, SQD2RTS_QP, and SQERR2RTS_QP.
 */
int
hermon_cmn_qp_cmd_post(hermon_state_t *state, uint_t opcode,
    hermon_hw_qpc_t *qp, uint_t qpindx, uint32_t opmask,
    uint_t sleepflag)
{
	hermon_mbox_info_t	mbox_info;
	hermon_cmd_post_t	cmd;
	uint64_t		data, in_mapaddr, out_mapaddr;
	uint_t			size, flags, opmod;
	int			status, i;

	/*
	 * Use the specified opcode type to set the appropriate parameters.
	 * Specifically, we need to set in_mapaddr, out_mapaddr, flags, and
	 * opmod (as necessary).  Setting these parameters may also require
	 * us to allocate an "In" or "Out" mailbox depending on the command
	 * type.
	 */

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	if (opcode == RTS2SQD_QP) {
		/*
		 * Note: For RTS-to-SendQueueDrain state transitions we
		 * always want to request the event generation from the
		 * hardware.  Though we may not notify the consumer of the
		 * drained event, the decision to forward (or not) is made
		 * later in the SQD event handler.
		 */
		flags = HERMON_CMD_REQ_SQD_EVENT;

		/*
		 * The RTS2SQD_QP command uses no "In" or "Out" mailboxes (and
		 * has no special opcode modifiers).
		 */
		in_mapaddr  = 0;
		out_mapaddr = 0;
		opmod = 0;

	} else if (opcode == TOERR_QP) {
		/*
		 * The TOERR_QP command uses no "In" or "Out" mailboxes, has no
		 * special opcode modifiers, and takes no special flags.
		 */
		in_mapaddr  = 0;
		out_mapaddr = 0;
		opmod = 0;
		flags = 0;

	} else if (opcode == TORST_QP) {
		/*
		 * The TORST_QP command could take an "Out" mailbox, but we do
		 * not require it here.  It also does not takes any special
		 * flags.  It does however, take a HERMON_CMD_DIRECT_TO_RESET
		 * opcode modifier, which indicates that the transition to
		 * reset should happen without first moving the QP through the
		 * Error state (and, hence, without generating any unnecessary
		 * "flushed-in-error" completions).
		 */
		in_mapaddr  = 0;
		out_mapaddr = 0;
		opmod = HERMON_CMD_DIRECT_TO_RESET | HERMON_CMD_NO_OUTMBOX;
		flags = 0;

	} else {
		/*
		 * All the other QP state transition commands (RST2INIT_QP,
		 * INIT2INIT_QP, INIT2RTR_QP, RTR2RTS_QP, RTS2RTS_QP,
		 * SQD2RTS_QP, and SQERR2RTS_QP) require an "In" mailbox.
		 * None of these require any special flags or opcode modifiers.
		 */
		mbox_info.mbi_alloc_flags = HERMON_ALLOC_INMBOX;
		status = hermon_mbox_alloc(state, &mbox_info, sleepflag);
		if (status != HERMON_CMD_SUCCESS) {
			return (status);
		}
		in_mapaddr  = mbox_info.mbi_in->mb_mapaddr;
		out_mapaddr = 0;
		flags = 0;
		opmod = 0;

		/* Copy the Hermon command into the "In" mailbox */
		size = sizeof (hermon_hw_qpc_t);
		for (i = 0; i < (size >> 3); i++) {
			data = ((uint64_t *)(void *)qp)[i];
			ddi_put64(mbox_info.mbi_in->mb_acchdl,
			    ((uint64_t *)mbox_info.mbi_in->mb_addr + i + 1),
			    data);
		}
		ddi_put32(mbox_info.mbi_in->mb_acchdl,
		    ((uint32_t *)mbox_info.mbi_in->mb_addr), opmask);

		/*
		 * Sync the mailbox for the device to read.  We have to add
		 * eight bytes here to account for "opt_param_mask" and
		 * proper alignment.
		 */
		hermon_mbox_sync(mbox_info.mbi_in, 0, size + 8,
		    DDI_DMA_SYNC_FORDEV);
	}

	/* Setup and post Hermon QP state transition command */
	cmd.cp_inparm	= in_mapaddr;
	cmd.cp_outparm	= out_mapaddr;
	cmd.cp_inmod	= qpindx | flags;
	cmd.cp_opcode	= (uint16_t)opcode;
	cmd.cp_opmod	= (uint16_t)opmod;
	cmd.cp_flags	= sleepflag;
	status = hermon_cmd_post(state, &cmd);

	/*
	 * If we allocated a mailbox (either an "In" or an "Out") above,
	 * then free it now before returning.
	 */
	if ((opcode != RTS2SQD_QP) && (opcode != TOERR_QP) &&
	    (opcode != TORST_QP)) {
		/* Free the mailbox */
		hermon_mbox_free(state, &mbox_info);
	}
	return (status);
}


/*
 * hermon_cmn_query_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *
 *    This is the common function for posting all the various types of
 *    Hermon query commands.  All Hermon query commands require an "Out"
 *    mailbox to be allocated for the resulting queried data.
 *
 * Note: This common function should be used only with the following
 *    opcodes: QUERY_DEV_LIM, QUERY_FW, QUERY_DDR, QUERY_ADAPTER, QUERY_PORT
 *     QUERY_HCA, QUERY_MPT, QUERY_EQ, QUERY_CQ, and QUERY_QP.
 *	With support of FCoIB, this also supports QUERY_FC.
 */
int
hermon_cmn_query_cmd_post(hermon_state_t *state, uint_t opcode, uint_t opmod,
    uint_t queryindx, void *query, uint_t size, uint_t sleepflag)
{
	hermon_mbox_info_t	mbox_info;
	hermon_cmd_post_t	cmd;
	uint64_t		data;
	uint_t			offset;
	int			status, i;

	bzero(&cmd, sizeof (hermon_cmd_post_t));

	/* Get an "Out" mailbox for the command */
	mbox_info.mbi_alloc_flags = HERMON_ALLOC_OUTMBOX;
	status = hermon_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != HERMON_CMD_SUCCESS) {
		return (status);
	}

	/* Setup and post the Hermon query command */
	cmd.cp_inparm	= 0;
	cmd.cp_outparm	= mbox_info.mbi_out->mb_mapaddr;
	cmd.cp_inmod	= queryindx;
	cmd.cp_opcode	= (uint16_t)opcode;
	cmd.cp_opmod	= (uint16_t)opmod;
	cmd.cp_flags	= sleepflag;
	status = hermon_cmd_post(state, &cmd);
	if (status != HERMON_CMD_SUCCESS) {
		goto cmn_query_fail;
	}

	/* Sync the mailbox to read the results */
	hermon_mbox_sync(mbox_info.mbi_out, 0, size, DDI_DMA_SYNC_FORCPU);

	/*
	 * QUERY_QP is handled somewhat differently than the other query
	 * commands.  For QUERY_QP, the actual queried data is offset into
	 * the mailbox (by one 64-bit word).
	 */
	offset = (opcode == QUERY_QP) ? 1 : 0;

	/* Copy query command results into "query" */
	for (i = 0; i < (size >> 3); i++) {
		data = ddi_get64(mbox_info.mbi_out->mb_acchdl,
		    ((uint64_t *)mbox_info.mbi_out->mb_addr + i + offset));
		((uint64_t *)query)[i] = data;
	}

cmn_query_fail:
	/* Free the mailbox */
	hermon_mbox_free(state, &mbox_info);
	return (status);
}


/*
 * hermon_cmn_ownership_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *
 *    This is the common function for posting all the various types of
 *    Hermon HW/SW resource ownership commands.  Since some of the commands
 *    differ from the others in the direction of ownership change (i.e.
 *    from HW ownership to SW, or vice versa), they differ in the type of
 *    mailbox and specific handling that each requires.  This routine does
 *    certain checks based on opcode type to determine the direction of
 *    the transition and to correctly handle the request.
 *
 * Note: This common function should be used only with the following
 *    opcodes: HW2SW_MPT, HW2SW_EQ, HW2SW_CQ, SW2HW_MPT, SW2HW_EQ, and
 *    SW2HW_CQ
 */
int
hermon_cmn_ownership_cmd_post(hermon_state_t *state, uint_t opcode,
    void *hwrsrc, uint_t size, uint_t hwrsrcindx, uint_t sleepflag)
{
	hermon_mbox_info_t	mbox_info;
	hermon_cmd_post_t	cmd;
	uint64_t		data, in_mapaddr, out_mapaddr;
	uint_t			direction, opmod;
	int			status, i;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/*
	 * Determine the direction of the ownership transfer based on the
	 * provided opcode
	 */
	if ((opcode == HW2SW_MPT) || (opcode == HW2SW_EQ) ||
	    (opcode == HW2SW_CQ) || (opcode == HW2SW_SRQ)) {
		direction = HERMON_CMD_RSRC_HW2SW;

	} else if ((opcode == SW2HW_MPT) || (opcode == SW2HW_EQ) ||
	    (opcode == SW2HW_CQ) || (opcode == SW2HW_SRQ)) {
		direction = HERMON_CMD_RSRC_SW2HW;

	} else {
		return (HERMON_CMD_INVALID_STATUS);
	}

	/*
	 * If hwrsrc is NULL then we do not allocate a mailbox.  This is used
	 * in the case of memory deregister where the out mailbox is not
	 * needed.  In the case of re-register, we do use the hwrsrc.
	 *
	 * Otherwise, If ownership transfer is going from hardware to software,
	 * then allocate an "Out" mailbox.  This will be filled in later as a
	 * result of the Hermon command.
	 *
	 * And if the ownership transfer is going from software to hardware,
	 * then we need an "In" mailbox, and we need to fill it in and sync it
	 * (if necessary).  Then the mailbox can be passed to the Hermon
	 * firmware.
	 *
	 * For the HW2SW (dereg) case, we only use an out mbox if hwrsrc is !=
	 * NULL.  This implies a re-reg, and the out mbox must be used.  If
	 * hwrsrc is == NULL, then we can save some time and resources by not
	 * using an out mbox at all.  We must set opmod to HERMON_CMD_DO_OUTMBOX
	 * and HERMON_CMD_NO_OUTMBOX appropriately in this case.
	 *
	 * For the SW2HW (reg) case, no out mbox is possible.  We set opmod to
	 * 0 anyway, but this field is not used in this case.
	 */
	if (direction == HERMON_CMD_RSRC_HW2SW) {
		if (hwrsrc != NULL) {
			mbox_info.mbi_alloc_flags = HERMON_ALLOC_OUTMBOX;
			status = hermon_mbox_alloc(state, &mbox_info,
			    sleepflag);
			if (status != HERMON_CMD_SUCCESS) {
				return (status);
			}
			in_mapaddr  = 0;
			out_mapaddr = mbox_info.mbi_out->mb_mapaddr;
			opmod = HERMON_CMD_DO_OUTMBOX;
		} else {
			in_mapaddr = 0;
			out_mapaddr = 0;
			opmod = HERMON_CMD_NO_OUTMBOX;
		}
	} else {  /* HERMON_CMD_RSRC_SW2HW */
		mbox_info.mbi_alloc_flags = HERMON_ALLOC_INMBOX;
		status = hermon_mbox_alloc(state, &mbox_info, sleepflag);
		if (status != HERMON_CMD_SUCCESS) {
			return (status);
		}

		/* Copy the SW2HW ownership command into mailbox */
		for (i = 0; i < (size >> 3); i++) {
			data = ((uint64_t *)hwrsrc)[i];
			ddi_put64(mbox_info.mbi_in->mb_acchdl,
			    ((uint64_t *)mbox_info.mbi_in->mb_addr + i),
			    data);
		}

		/* Sync the mailbox for the device to read */
		hermon_mbox_sync(mbox_info.mbi_in, 0, size,
		    DDI_DMA_SYNC_FORDEV);

		in_mapaddr  = mbox_info.mbi_in->mb_mapaddr;
		out_mapaddr = 0;
		opmod = 0;
	}

	/* Setup and post the Hermon ownership command */
	cmd.cp_inparm	= in_mapaddr;
	cmd.cp_outparm	= out_mapaddr;
	cmd.cp_inmod	= hwrsrcindx;
	cmd.cp_opcode	= (uint16_t)opcode;
	cmd.cp_opmod	= (uint16_t)opmod;
	cmd.cp_flags	= sleepflag;
	status = hermon_cmd_post(state, &cmd);
	if (status != HERMON_CMD_SUCCESS) {
		goto cmn_ownership_fail;
	}

	/*
	 * As mentioned above, for HW2SW ownership transfers we need to
	 * sync (if necessary) and copy out the resulting data from the
	 * "Out" mailbox" (assuming the above command was successful).
	 */
	if (direction == HERMON_CMD_RSRC_HW2SW && hwrsrc != NULL) {

		/* Sync the mailbox to read the results */
		hermon_mbox_sync(mbox_info.mbi_out, 0, size,
		    DDI_DMA_SYNC_FORCPU);

		/* Copy HW2SW ownership command results into "hwrsrc" */
		for (i = 0; i < (size >> 3); i++) {
			data = ddi_get64(mbox_info.mbi_out->mb_acchdl,
			    ((uint64_t *)mbox_info.mbi_out->mb_addr + i));
			((uint64_t *)hwrsrc)[i] = data;
		}
	}

cmn_ownership_fail:
	if (hwrsrc != NULL) {
		/* Free the mailbox */
		hermon_mbox_free(state, &mbox_info);
	}
	return (status);
}


/*
 * hermon_conf_special_qp_cmd_post()
 *    Context: Can be called from interrupt or base context.
 */
/*ARGSUSED*/
int
hermon_conf_special_qp_cmd_post(hermon_state_t *state, uint_t qpindx,
    uint_t qptype, uint_t sleepflag, uint_t opmod)
{
	hermon_cmd_post_t	cmd;
	int			status;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Setup and post Hermon "CONF_SPECIAL_QP" command */
	cmd.cp_inparm	= 0;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= qpindx & 0x00FFFFF8;	/* mask off low 3 bits */
	cmd.cp_opcode	= CONF_SPECIAL_QP;
	cmd.cp_opmod	= (uint16_t)opmod;
	cmd.cp_flags	= sleepflag;
	status = hermon_cmd_post(state, &cmd);

	return (status);
}


/*
 * hermon_get_heart_beat_rq_cmd_post()
 *    Context: Can be called only from kernel or interrupt context
 */
int
hermon_get_heart_beat_rq_cmd_post(hermon_state_t *state, uint_t qpindx,
    uint64_t *outparm)
{
	hermon_cmd_post_t	cmd;
	int			status;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Setup and post the Hermon "HEART_BEAT_RQ" command */
	cmd.cp_inparm	= 0;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= qpindx;
	cmd.cp_opcode	= HEART_BEAT_RQ;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= HERMON_CMD_NOSLEEP_SPIN;
	status = hermon_cmd_post(state, &cmd);

	/*
	 * Return immediate out param through argument pointer.
	 */
	*outparm = cmd.cp_outparm;
	return (status);
}


/*
 * hermon_mgid_hash_cmd_post()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_mgid_hash_cmd_post(hermon_state_t *state, uint64_t mgid_h,
    uint64_t mgid_l, uint64_t *mgid_hash, uint_t sleepflag)
{
	hermon_mbox_info_t	mbox_info;
	hermon_cmd_post_t	cmd;
	int			status;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Get an "In" mailbox for the command */
	mbox_info.mbi_alloc_flags = HERMON_ALLOC_INMBOX;
	status = hermon_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != HERMON_CMD_SUCCESS) {
		return (status);
	}

	/* Copy the Hermon "MGID_HASH" command into mailbox */
	ddi_put64(mbox_info.mbi_in->mb_acchdl,
	    ((uint64_t *)mbox_info.mbi_in->mb_addr + 0), mgid_h);
	ddi_put64(mbox_info.mbi_in->mb_acchdl,
	    ((uint64_t *)mbox_info.mbi_in->mb_addr + 1), mgid_l);

	/* Sync the mailbox for the device to read */
	hermon_mbox_sync(mbox_info.mbi_in, 0, HERMON_CMD_MGIDHASH_SZ,
	    DDI_DMA_SYNC_FORDEV);

	/* Setup and post the Hermon "MGID_HASH" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= 0;
	cmd.cp_opcode	= MGID_HASH;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= sleepflag;
	status = hermon_cmd_post(state, &cmd);

	/* MGID hash value is returned in command "outparam" */
	*mgid_hash = cmd.cp_outparm;

	/* Free the mailbox */
	hermon_mbox_free(state, &mbox_info);
	return (status);
}


/*
 * hermon_read_mgm_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *
 * Note: It is assumed that the "mcg" parameter is actually a pointer to a
 *    "hermon_hw_mcg_t" struct and some number of "hermon_hw_mcg_qp_list_t"
 *    structs.  Combined size should be equal to result of HERMON_MCGMEM_SZ()
 *    macro.
 */
int
hermon_read_mgm_cmd_post(hermon_state_t *state, hermon_hw_mcg_t *mcg,
    uint_t mcgindx, uint_t sleepflag)
{
	hermon_mbox_info_t	mbox_info;
	hermon_cmd_post_t	cmd;
	uint64_t		data;
	uint32_t		data32;
	uint_t			size, hdrsz, qplistsz;
	int			status, i;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Get an "Out" mailbox for the results */
	mbox_info.mbi_alloc_flags = HERMON_ALLOC_OUTMBOX;
	status = hermon_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != HERMON_CMD_SUCCESS) {
		return (status);
	}

	/* Setup and post Hermon "READ_MGM" command */
	cmd.cp_inparm	= 0;
	cmd.cp_outparm	= mbox_info.mbi_out->mb_mapaddr;
	cmd.cp_inmod	= mcgindx;
	cmd.cp_opcode	= READ_MGM;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= sleepflag;
	status = hermon_cmd_post(state, &cmd);
	if (status != HERMON_CMD_SUCCESS) {
		goto read_mgm_fail;
	}

	/* Sync the mailbox to read the results */
	size = HERMON_MCGMEM_SZ(state);
	hermon_mbox_sync(mbox_info.mbi_out, 0, size, DDI_DMA_SYNC_FORCPU);

	/* Copy the READ_MGM command results into "mcg" */
	hdrsz = sizeof (hermon_hw_mcg_t);
	for (i = 0; i < (hdrsz >> 3); i++) {
		data = ddi_get64(mbox_info.mbi_out->mb_acchdl,
		    ((uint64_t *)mbox_info.mbi_out->mb_addr + i));
		((uint64_t *)mcg)[i] = data;
	}
	qplistsz = size - hdrsz;
	for (i = 0; i < (qplistsz >> 2); i++) {
		data32 = ddi_get32(mbox_info.mbi_out->mb_acchdl,
		    ((uint32_t *)mbox_info.mbi_out->mb_addr + i + 8));
		((uint32_t *)mcg)[i + 8] = data32;
	}

read_mgm_fail:
	/* Free the mailbox */
	hermon_mbox_free(state, &mbox_info);
	return (status);
}


/*
 * hermon_write_mgm_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *
 * Note: It is assumed that the "mcg" parameter is actually a pointer to a
 *    "hermon_hw_mcg_t" struct and some number of "hermon_hw_mcg_qp_list_t"
 *    structs.  Combined size should be equal to result of HERMON_MCGMEM_SZ()
 *    macro.
 */
int
hermon_write_mgm_cmd_post(hermon_state_t *state, hermon_hw_mcg_t *mcg,
    uint_t mcgindx, uint_t sleepflag)
{
	hermon_mbox_info_t	mbox_info;
	hermon_cmd_post_t	cmd;
	uint64_t		data;
	uint_t			size, hdrsz, qplistsz;
	int			status, i;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Get an "In" mailbox for the command */
	mbox_info.mbi_alloc_flags = HERMON_ALLOC_INMBOX;
	status = hermon_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != HERMON_CMD_SUCCESS) {
		return (status);
	}

	/* Copy the Hermon "WRITE_MGM" command into mailbox */
	size  = HERMON_MCGMEM_SZ(state);
	hdrsz = sizeof (hermon_hw_mcg_t);
	for (i = 0; i < (hdrsz >> 3); i++) {
		data = ((uint64_t *)mcg)[i];
		ddi_put64(mbox_info.mbi_in->mb_acchdl,
		    ((uint64_t *)mbox_info.mbi_in->mb_addr + i), data);
	}
	qplistsz = size - hdrsz;
	for (i = 0; i < (qplistsz >> 2); i++) {
		data = ((uint32_t *)mcg)[i + 8];
		ddi_put32(mbox_info.mbi_in->mb_acchdl,
		    ((uint32_t *)mbox_info.mbi_in->mb_addr + i + 8), data);
	}

	/* Sync the mailbox for the device to read */
	hermon_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup and post Hermon "WRITE_MGM" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= mcgindx;
	cmd.cp_opcode	= WRITE_MGM;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= sleepflag;
	status = hermon_cmd_post(state, &cmd);

	/* Free the mailbox */
	hermon_mbox_free(state, &mbox_info);
	return (status);
}

/*
 * hermon_resize_srq_cmd_post()
 *    Context: Can be called from interrupt or base context.
 */

int hermon_resize_srq_cmd_post(hermon_state_t *state, hermon_hw_srqc_t *srq,
    uint_t srqnum, uint_t sleepflag)
{
	hermon_mbox_info_t	mbox_info;
	hermon_cmd_post_t	cmd;
	uint64_t		data;
	uint_t			size;
	int			status, i;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Get an "In" mailbox for the command */
	mbox_info.mbi_alloc_flags = HERMON_ALLOC_INMBOX;
	status = hermon_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != HERMON_CMD_SUCCESS) {
		return (status);
	}

	/* Copy the Hermon "RESIZE_SRQ" command into mailbox */
	size = sizeof (hermon_hw_srqc_t);
	for (i = 0; i < (size >> 3); i++) {
		data = ((uint64_t *)(void *)srq)[i];
		ddi_put64(mbox_info.mbi_in->mb_acchdl,
		    ((uint64_t *)mbox_info.mbi_in->mb_addr + i), data);
	}

	/* Sync the mailbox for the device to read */
	hermon_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup and post Hermon "RESIZE_SRQ" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= srqnum;
	cmd.cp_opcode	= RESIZE_SRQ;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= sleepflag;
	status = hermon_cmd_post(state, &cmd);

	/* Free the mailbox */
	hermon_mbox_free(state, &mbox_info);
	return (status);
}
/*
 * hermon_modify_mpt_cmd_post()
 *    Context: Can be called from interrupt or base context.
 */
int
hermon_modify_mpt_cmd_post(hermon_state_t *state, hermon_hw_dmpt_t *mpt,
    uint_t mptindx, uint_t flags, uint_t sleepflag)
{
	hermon_mbox_info_t	mbox_info;
	hermon_cmd_post_t	cmd;
	uint64_t		data;
	uint_t			size;
	int			status, i;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Get an "In" mailbox for the command */
	mbox_info.mbi_alloc_flags = HERMON_ALLOC_INMBOX;
	status = hermon_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != HERMON_CMD_SUCCESS) {
		return (status);
	}

	/* Copy the Hermon "MODIFY_MPT" command into mailbox */
	size = sizeof (hermon_hw_dmpt_t);
	for (i = 0; i < (size >> 3); i++) {
		data = ((uint64_t *)mpt)[i];
		ddi_put64(mbox_info.mbi_in->mb_acchdl,
		    ((uint64_t *)mbox_info.mbi_in->mb_addr + i), data);
	}

	/* Sync the mailbox for the device to read */
	hermon_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup and post Hermon "MODIFY_MPT" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= mptindx;
	cmd.cp_opcode	= MODIFY_MPT;
	cmd.cp_opmod	= (uint16_t)flags;
	cmd.cp_flags	= sleepflag;
	status = hermon_cmd_post(state, &cmd);

	/* Free the mailbox */
	hermon_mbox_free(state, &mbox_info);
	return (status);
}


/*
 * hermon_config_fc_cmd_post()
 *    	Context: Can be called from user or kernel context.
 *	This can do either a basic config passing in
 * 	*hermon_hw_config_fc_basic_s, or config the N_Port table.
 *	passing in pointer to an array of 32-bit id's
 *	Note that either one needs to be cast to void *
 */
int
hermon_config_fc_cmd_post(hermon_state_t *state, void *cfginfo, int enable,
    int selector, int n_ports, int portnum, uint_t sleepflag)
{
	hermon_mbox_info_t	mbox_info;
	hermon_cmd_post_t	cmd;
	uint64_t		data;
	uint32_t		portid;
	uint_t			size;
	int			status, i;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Get an "In" mailbox for the command */
	mbox_info.mbi_alloc_flags = HERMON_ALLOC_INMBOX;
	status = hermon_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != HERMON_CMD_SUCCESS) {
		return (status);
	}

	/* Copy the appropriate info into mailbox */
	if (selector == HERMON_HW_FC_CONF_BASIC) {	/* basic info */
		size = sizeof (hermon_hw_config_fc_basic_t);
		for (i = 0; i < (size >> 3); i++) {
			data = ((uint64_t *)cfginfo)[i];
			ddi_put64(mbox_info.mbi_in->mb_acchdl,
			    ((uint64_t *)mbox_info.mbi_in->mb_addr + i), data);
		}
	} else {					/* NPort config */
		ASSERT(selector == HERMON_HW_FC_CONF_NPORT);
		size = n_ports * sizeof (uint32_t);
		/*
		 * n_ports must == number queried from card
		 *
		 * passed in is an array but for little endian needs to
		 * be rearranged in the mbox
		 */
		for (i = 0; i < (size >> 3); i++) {
			portid = ((uint32_t *)cfginfo)[i * 2];
			data = (uint64_t)portid << 32;
			if (i * 2 < n_ports) {
				portid = ((uint32_t *)cfginfo)[i * 2 + 1];
				data |= portid;
			}
			ddi_put64(mbox_info.mbi_in->mb_acchdl,
			    ((uint64_t *)mbox_info.mbi_in->mb_addr + i), data);
		}
	}

	/* Sync the mailbox for the device to read */
	hermon_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup and post Hermon "CONFIG_FC" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= (uint32_t)(selector | portnum);
	cmd.cp_opcode	= CONFIG_FC;
	cmd.cp_opmod	= (uint16_t)enable;
	cmd.cp_flags	= sleepflag;
	status = hermon_cmd_post(state, &cmd);

	/* Free the mailbox */
	hermon_mbox_free(state, &mbox_info);
	return (status);
}

/*
 * hermon_sense_port_post() - used to send protocol running on a port
 *	Context: Can be called from interrupt or base context
 */

int
hermon_sense_port_post(hermon_state_t *state, uint_t portnum,
    uint32_t *protocol)
{
	hermon_cmd_post_t	cmd;
	int			status;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Setup and post Hermon "CMD_NOP" command */
	cmd.cp_inparm	= 0;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= (uint32_t)portnum;
	cmd.cp_opcode	= SENSE_PORT;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= HERMON_CMD_NOSLEEP_SPIN;
	status = hermon_cmd_post(state, &cmd);
	if (status == HERMON_CMD_SUCCESS) *protocol = (uint32_t)cmd.cp_outparm;
	return (status);
}


/*
 * CONFIG_INT_MOD - used to configure INTERRUPT moderation
 *	if command fails, *health is invalid/undefined
 */
int
hermon_config_int_mod(hermon_state_t *state, uint_t min_delay, uint_t vector)
{
	hermon_cmd_post_t	cmd;
	int			status;
	uint64_t		inparm = 0;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Setup and post Hermon "CONFIG_INT_MOD" command */
	inparm = (((uint64_t)min_delay & 0xFFFF) << 48) ||
	    (((uint64_t)vector & 0xFFFF) << 32);

	cmd.cp_inparm	= inparm;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= 0;
	cmd.cp_opcode	= CONFIG_INT_MOD;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= HERMON_CMD_NOSLEEP_SPIN;
	status = hermon_cmd_post(state, &cmd);
	return (status);
}


int
hermon_nop_post(hermon_state_t *state, uint_t interval, uint_t sleep)
{
	hermon_cmd_post_t	cmd;
	int			status;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Setup and post Hermon "CMD_NOP" command */
	cmd.cp_inparm	= 0;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= interval;
	cmd.cp_opcode	= CMD_NOP;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= HERMON_CMD_SLEEP_NOSPIN;
	if (sleep) cmd.cp_flags	= HERMON_CMD_NOSLEEP_SPIN;
	status = hermon_cmd_post(state, &cmd);
	return (status);
}

int
hermon_hw_health_check(hermon_state_t *state, int *health)
{
	hermon_cmd_post_t	cmd;
	int			status;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Setup and post Hermon "CMD_NOP" command */
	cmd.cp_inparm	= 0;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= 0;
	cmd.cp_opcode	= HW_HEALTH_CHECK;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= HERMON_CMD_NOSLEEP_SPIN;
	status = hermon_cmd_post(state, &cmd);
	*health = (int)cmd.cp_outparm;
	return (status);
}

int
hermon_setdebug_post(hermon_state_t *state)
{
	hermon_cmd_post_t	cmd;
	int			status;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Setup and post Hermon "CMD_NOP" command */
	cmd.cp_inparm	= 0xFFFFFFFFFFFFFFFF;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= 0;
	cmd.cp_opcode	= SET_DEBUG_MSG;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= HERMON_CMD_NOSLEEP_SPIN;
	status = hermon_cmd_post(state, &cmd);
	return (status);
}


int
hermon_read_mtt_cmd_post(hermon_state_t *state, uint64_t mtt_addr,
	hermon_hw_mtt_t *mtt)
{

	hermon_cmd_post_t	cmd;
	hermon_mbox_info_t	mbox_info;
	int			i, status;
	uint_t			size;
	uint64_t		data;

	bzero((void *)&cmd, sizeof (hermon_cmd_post_t));

	/* Get an "Out" mailbox for the command */
	mbox_info.mbi_alloc_flags = HERMON_ALLOC_OUTMBOX;
	status = hermon_mbox_alloc(state, &mbox_info, HERMON_CMD_SLEEP_NOSPIN);
	if (status != HERMON_CMD_SUCCESS) {
		return (status);
	}

	/* Setup and post the "READ_MTT" command */
	cmd.cp_inparm	= mtt_addr;
	cmd.cp_outparm	= mbox_info.mbi_out->mb_mapaddr;
	cmd.cp_inmod	= 1;
	cmd.cp_opcode	= READ_MTT;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= HERMON_CMD_NOSLEEP_SPIN;
	status = hermon_cmd_post(state, &cmd);
	if (status != HERMON_CMD_SUCCESS) {
		return (status);
	}

	/* Sync the mailbox to read the results */
	size = sizeof (hermon_hw_mtt_t);
	hermon_mbox_sync(mbox_info.mbi_out, 0, size, DDI_DMA_SYNC_FORCPU);

	/* Copy mtt read out */
	for (i = 0; i < (size >> 3); i++) {
		data = ddi_get64(mbox_info.mbi_out->mb_acchdl,
		    ((uint64_t *)mbox_info.mbi_out->mb_addr + i));
		((uint64_t *)(void *)mtt)[i] = data;
	}

	/* Free the mailbox */
	hermon_mbox_free(state, &mbox_info);
	return (status);
}
