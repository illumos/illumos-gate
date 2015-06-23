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
 * tavor_cmd.c
 *    Tavor Firmware Command Routines
 *
 *    Implements all the routines necessary for allocating, posting, and
 *    freeing commands for the Tavor firmware.  These routines manage a
 *    preallocated list of command mailboxes and provide interfaces to post
 *    each of the several dozen commands to the Tavor firmware.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>

#include <sys/ib/adapters/tavor/tavor.h>

static int tavor_impl_mbox_alloc(tavor_state_t *state, tavor_mboxlist_t *mblist,
    tavor_mbox_t **mb, uint_t mbox_wait);
static void tavor_impl_mbox_free(tavor_mboxlist_t *mblist, tavor_mbox_t **mb);
static int tavor_impl_mboxlist_init(tavor_state_t *state,
    tavor_mboxlist_t *mblist, uint_t num_mbox, tavor_rsrc_type_t type);
static void tavor_impl_mboxlist_fini(tavor_state_t *state,
    tavor_mboxlist_t *mblist);
static int tavor_outstanding_cmd_alloc(tavor_state_t *state,
    tavor_cmd_t **cmd_ptr, uint_t cmd_wait);
static void tavor_outstanding_cmd_free(tavor_state_t *state,
    tavor_cmd_t **cmd_ptr);
static int tavor_write_hcr(tavor_state_t *state, tavor_cmd_post_t *cmdpost,
    uint16_t token);
static void tavor_mbox_sync(tavor_mbox_t *mbox, uint_t offset,
    uint_t length, uint_t flag);

/*
 * tavor_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *
 *    The "cp_flags" field in cmdpost
 *    is used to determine whether to wait for an available
 *    outstanding command (if necessary) or to return error.
 */
int
tavor_cmd_post(tavor_state_t *state, tavor_cmd_post_t *cmdpost)
{
	tavor_cmd_t	*cmdptr;
	int		status;
	uint16_t	token;

	TAVOR_TNF_ENTER(tavor_cmd_post);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*cmdpost))

	/* Determine if we are going to spin until completion */
	if (cmdpost->cp_flags == TAVOR_CMD_NOSLEEP_SPIN) {

		TNF_PROBE_0_DEBUG(tavor_cmd_post_spin, TAVOR_TNF_TRACE, "");

		/* Write the command to the HCR */
		status = tavor_write_hcr(state, cmdpost, 0);
		if (status != TAVOR_CMD_SUCCESS) {
			TNF_PROBE_0(tavor_cmd_post_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_cmd_post);
			return (status);
		}

		TAVOR_TNF_EXIT(tavor_cmd_post);
		return (TAVOR_CMD_SUCCESS);

	} else {  /* "TAVOR_CMD_SLEEP_NOSPIN" */

		TNF_PROBE_0_DEBUG(tavor_cmd_post_nospin, TAVOR_TNF_TRACE, "");

		ASSERT(TAVOR_SLEEPFLAG_FOR_CONTEXT() != TAVOR_NOSLEEP);

		/* NOTE: Expect threads to be waiting in here */
		status = tavor_outstanding_cmd_alloc(state, &cmdptr,
		    cmdpost->cp_flags);
		if (status != TAVOR_CMD_SUCCESS) {
			TNF_PROBE_0(tavor_cmd_alloc_fail, TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_cmd_post);
			return (status);
		}
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*cmdptr))

		/*
		 * Set status to "TAVOR_CMD_INVALID_STATUS".  It is
		 * appropriate to do this here without the "cmd_comp_lock"
		 * because this register is overloaded.  Later it will be
		 * used to indicate - through a change from this invalid
		 * value to some other value - that the condition variable
		 * has been signaled.  Once it has, status will then contain
		 * the _real_ completion status
		 */
		cmdptr->cmd_status = TAVOR_CMD_INVALID_STATUS;

		/* Write the command to the HCR */
		token = (uint16_t)cmdptr->cmd_indx;
		status = tavor_write_hcr(state, cmdpost, token);
		if (status != TAVOR_CMD_SUCCESS) {
			tavor_outstanding_cmd_free(state, &cmdptr);
			TNF_PROBE_0(tavor_cmd_post_fail, TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_cmd_post);
			return (status);
		}

		/*
		 * cv_wait() on the "command_complete" condition variable.
		 * Note: We have the "__lock_lint" here to workaround warlock.
		 * Since warlock doesn't know that other parts of the Tavor
		 * may occasionally call this routine while holding their own
		 * locks, it complains about this cv_wait.  In reality,
		 * however, the rest of the driver never calls this routine
		 * with a lock held unless they pass TAVOR_CMD_NOSLEEP.
		 */
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*cmdptr))
		mutex_enter(&cmdptr->cmd_comp_lock);
		while (cmdptr->cmd_status == TAVOR_CMD_INVALID_STATUS) {
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

		/* Save the "outparam" values into the cmdpost struct */
		cmdpost->cp_outparm = cmdptr->cmd_outparm;

		/*
		 * Add the command back to the "outstanding commands list".
		 * Signal the "cmd_list" condition variable, if necessary.
		 */
		tavor_outstanding_cmd_free(state, &cmdptr);

		if (status != TAVOR_CMD_SUCCESS) {
			TNF_PROBE_0(tavor_cmd_post_fail, TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_cmd_post);
			return (status);
		}

		TAVOR_TNF_EXIT(tavor_cmd_post);
		return (TAVOR_CMD_SUCCESS);
	}
}


/*
 * tavor_mbox_alloc()
 *    Context: Can be called from interrupt or base context.
 *
 *    The "mbox_wait" parameter is used to determine whether to
 *    wait for a mailbox to become available or not.
 */
int
tavor_mbox_alloc(tavor_state_t *state, tavor_mbox_info_t *mbox_info,
    uint_t mbox_wait)
{
	int			status;
	uint_t			sleep_context;

	TAVOR_TNF_ENTER(tavor_mbox_alloc);

	sleep_context = TAVOR_SLEEPFLAG_FOR_CONTEXT();

	/* Allocate an "In" mailbox */
	if (mbox_info->mbi_alloc_flags & TAVOR_ALLOC_INMBOX) {
		/* Determine correct mboxlist based on calling context */
		if (sleep_context == TAVOR_NOSLEEP) {
			status = tavor_impl_mbox_alloc(state,
			    &state->ts_in_intr_mblist,
			    &mbox_info->mbi_in, mbox_wait);

			ASSERT(status == TAVOR_CMD_SUCCESS);
		} else {
			/* NOTE: Expect threads to be waiting in here */
			status = tavor_impl_mbox_alloc(state,
			    &state->ts_in_mblist, &mbox_info->mbi_in,
			    mbox_wait);
			if (status != TAVOR_CMD_SUCCESS) {
				TAVOR_TNF_EXIT(tavor_mbox_alloc);
				return (status);
			}
		}

	}

	/* Allocate an "Out" mailbox */
	if (mbox_info->mbi_alloc_flags & TAVOR_ALLOC_OUTMBOX) {
		/* Determine correct mboxlist based on calling context */
		if (sleep_context == TAVOR_NOSLEEP) {
			status = tavor_impl_mbox_alloc(state,
			    &state->ts_out_intr_mblist,
			    &mbox_info->mbi_out, mbox_wait);

			ASSERT(status == TAVOR_CMD_SUCCESS);
		} else {
			/* NOTE: Expect threads to be waiting in here */
			status = tavor_impl_mbox_alloc(state,
			    &state->ts_out_mblist, &mbox_info->mbi_out,
			    mbox_wait);
			if (status != TAVOR_CMD_SUCCESS) {
				/* If we allocated an "In" mailbox, free it */
				if (mbox_info->mbi_alloc_flags &
				    TAVOR_ALLOC_INMBOX) {
					tavor_impl_mbox_free(
					    &state->ts_in_mblist,
					    &mbox_info->mbi_in);
				}
				TAVOR_TNF_EXIT(tavor_mbox_alloc);
				return (status);
			}
		}
	}

	/* Store appropriate context in mbox_info */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(mbox_info->mbi_sleep_context))
	mbox_info->mbi_sleep_context = sleep_context;

	TAVOR_TNF_EXIT(tavor_mbox_alloc);
	return (TAVOR_CMD_SUCCESS);
}


/*
 * tavor_mbox_free()
 *    Context: Can be called from interrupt or base context.
 */
void
tavor_mbox_free(tavor_state_t *state, tavor_mbox_info_t *mbox_info)
{
	TAVOR_TNF_ENTER(tavor_mbox_free);

	/*
	 * The mailbox has to be freed in the same context from which it was
	 * allocated.  The context is stored in the mbox_info at
	 * tavor_mbox_alloc() time.  We check the stored context against the
	 * current context here.
	 */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(mbox_info->mbi_sleep_context))
	ASSERT(mbox_info->mbi_sleep_context == TAVOR_SLEEPFLAG_FOR_CONTEXT());

	/* Determine correct mboxlist based on calling context */
	if (mbox_info->mbi_sleep_context == TAVOR_NOSLEEP) {
		/* Free the intr "In" mailbox */
		if (mbox_info->mbi_alloc_flags & TAVOR_ALLOC_INMBOX) {
			tavor_impl_mbox_free(&state->ts_in_intr_mblist,
			    &mbox_info->mbi_in);
		}

		/* Free the intr "Out" mailbox */
		if (mbox_info->mbi_alloc_flags & TAVOR_ALLOC_OUTMBOX) {
			tavor_impl_mbox_free(&state->ts_out_intr_mblist,
			    &mbox_info->mbi_out);
		}
	} else {
		/* Free the "In" mailbox */
		if (mbox_info->mbi_alloc_flags & TAVOR_ALLOC_INMBOX) {
			tavor_impl_mbox_free(&state->ts_in_mblist,
			    &mbox_info->mbi_in);
		}

		/* Free the "Out" mailbox */
		if (mbox_info->mbi_alloc_flags & TAVOR_ALLOC_OUTMBOX) {
			tavor_impl_mbox_free(&state->ts_out_mblist,
			    &mbox_info->mbi_out);
		}
	}

	TAVOR_TNF_EXIT(tavor_mbox_free);
}


/*
 * tavor_cmd_complete_handler()
 *    Context: Called only from interrupt context.
 */
int
tavor_cmd_complete_handler(tavor_state_t *state, tavor_eqhdl_t eq,
    tavor_hw_eqe_t *eqe)
{
	tavor_cmd_t		*cmdp;
	uint_t			eqe_evttype;

	TAVOR_TNF_ENTER(tavor_cmd_complete_handler);

	eqe_evttype = TAVOR_EQE_EVTTYPE_GET(eq, eqe);

	ASSERT(eqe_evttype == TAVOR_EVT_COMMAND_INTF_COMP ||
	    eqe_evttype == TAVOR_EVT_EQ_OVERFLOW);

	if (eqe_evttype == TAVOR_EVT_EQ_OVERFLOW) {
		TNF_PROBE_0(tavor_cmd_complete_overflow_condition,
		    TAVOR_TNF_ERROR, "");
		tavor_eq_overflow_handler(state, eq, eqe);

		TAVOR_TNF_EXIT(tavor_cmd_complete_handler);
		return (DDI_FAILURE);
	}

	/*
	 * Find the outstanding command pointer based on value returned
	 * in "token"
	 */
	cmdp = &state->ts_cmd_list.cml_cmd[TAVOR_EQE_CMDTOKEN_GET(eq, eqe)];

	/* Signal the waiting thread */
	mutex_enter(&cmdp->cmd_comp_lock);
	cmdp->cmd_outparm = ((uint64_t)TAVOR_EQE_CMDOUTP0_GET(eq, eqe) << 32) |
	    TAVOR_EQE_CMDOUTP1_GET(eq, eqe);
	cmdp->cmd_status = TAVOR_EQE_CMDSTATUS_GET(eq, eqe);

	cv_signal(&cmdp->cmd_comp_cv);
	mutex_exit(&cmdp->cmd_comp_lock);

	TAVOR_TNF_EXIT(tavor_cmd_complete_handler);
	return (DDI_SUCCESS);
}


/*
 * tavor_inmbox_list_init()
 *    Context: Only called from attach() path context
 */
int
tavor_inmbox_list_init(tavor_state_t *state)
{
	int		status;
	uint_t		num_inmbox;

	TAVOR_TNF_ENTER(tavor_inmbox_list_init);

	/* Initialize the "In" mailbox list */
	num_inmbox  =  (1 << state->ts_cfg_profile->cp_log_num_inmbox);
	status = tavor_impl_mboxlist_init(state, &state->ts_in_mblist,
	    num_inmbox, TAVOR_IN_MBOX);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(tavor_impl_mboxlist_init_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_inmbox_list_init);
		return (DDI_FAILURE);
	}

	TAVOR_TNF_EXIT(tavor_inmbox_list_init);
	return (DDI_SUCCESS);
}


/*
 * tavor_intr_inmbox_list_init()
 *    Context: Only called from attach() path context
 */
int
tavor_intr_inmbox_list_init(tavor_state_t *state)
{
	int		status;
	uint_t		num_inmbox;

	TAVOR_TNF_ENTER(tavor_intr_inmbox_list_init);

	/* Initialize the interrupt "In" mailbox list */
	num_inmbox  =  (1 << state->ts_cfg_profile->cp_log_num_intr_inmbox);
	status = tavor_impl_mboxlist_init(state, &state->ts_in_intr_mblist,
	    num_inmbox, TAVOR_INTR_IN_MBOX);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(tavor_impl_mboxlist_init_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_intr_inmbox_list_init);
		return (DDI_FAILURE);
	}

	TAVOR_TNF_EXIT(tavor_intr_inmbox_list_init);
	return (DDI_SUCCESS);
}


/*
 * tavor_outmbox_list_init()
 *    Context: Only called from attach() path context
 */
int
tavor_outmbox_list_init(tavor_state_t *state)
{
	int		status;
	uint_t		num_outmbox;

	TAVOR_TNF_ENTER(tavor_outmbox_list_init);

	/* Initialize the "Out" mailbox list */
	num_outmbox  =  (1 << state->ts_cfg_profile->cp_log_num_outmbox);
	status = tavor_impl_mboxlist_init(state, &state->ts_out_mblist,
	    num_outmbox, TAVOR_OUT_MBOX);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(tavor_impl_mboxlist_init_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_outmbox_list_init);
		return (DDI_FAILURE);
	}

	TAVOR_TNF_EXIT(tavor_outmbox_list_init);
	return (DDI_SUCCESS);
}


/*
 * tavor_intr_outmbox_list_init()
 *    Context: Only called from attach() path context
 */
int
tavor_intr_outmbox_list_init(tavor_state_t *state)
{
	int		status;
	uint_t		num_outmbox;

	TAVOR_TNF_ENTER(tavor_intr_outmbox_list_init);

	/* Initialize the interrupts "Out" mailbox list */
	num_outmbox  =  (1 << state->ts_cfg_profile->cp_log_num_intr_outmbox);
	status = tavor_impl_mboxlist_init(state, &state->ts_out_intr_mblist,
	    num_outmbox, TAVOR_INTR_OUT_MBOX);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(tavor_impl_mboxlist_init_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_intr_outmbox_list_init);
		return (DDI_FAILURE);
	}

	TAVOR_TNF_EXIT(tavor_intr_outmbox_list_init);
	return (DDI_SUCCESS);
}


/*
 * tavor_inmbox_list_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
void
tavor_inmbox_list_fini(tavor_state_t *state)
{
	TAVOR_TNF_ENTER(tavor_inmbox_list_fini);

	/* Free up the "In" mailbox list */
	tavor_impl_mboxlist_fini(state, &state->ts_in_mblist);

	TAVOR_TNF_EXIT(tavor_inmbox_list_fini);
}


/*
 * tavor_intr_inmbox_list_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
void
tavor_intr_inmbox_list_fini(tavor_state_t *state)
{
	TAVOR_TNF_ENTER(tavor_intr_inmbox_list_fini);

	/* Free up the interupts "In" mailbox list */
	tavor_impl_mboxlist_fini(state, &state->ts_in_intr_mblist);

	TAVOR_TNF_EXIT(tavor_intr_inmbox_list_fini);
}


/*
 * tavor_outmbox_list_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
void
tavor_outmbox_list_fini(tavor_state_t *state)
{
	TAVOR_TNF_ENTER(tavor_outmbox_list_fini);

	/* Free up the "Out" mailbox list */
	tavor_impl_mboxlist_fini(state, &state->ts_out_mblist);

	TAVOR_TNF_EXIT(tavor_outmbox_list_fini);
}


/*
 * tavor_intr_outmbox_list_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
void
tavor_intr_outmbox_list_fini(tavor_state_t *state)
{
	TAVOR_TNF_ENTER(tavor_intr_outmbox_list_fini);

	/* Free up the interrupt "Out" mailbox list */
	tavor_impl_mboxlist_fini(state, &state->ts_out_intr_mblist);

	TAVOR_TNF_EXIT(tavor_intr_outmbox_list_fini);
}


/*
 * tavor_impl_mbox_alloc()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_impl_mbox_alloc(tavor_state_t *state, tavor_mboxlist_t *mblist,
    tavor_mbox_t **mb, uint_t mbox_wait)
{
	tavor_mbox_t	*mbox_ptr;
	uint_t		index, next, prev;
	uint_t		count, countmax;

	TAVOR_TNF_ENTER(tavor_impl_mbox_alloc);

	/*
	 * If the mailbox list is empty, then wait (if appropriate in the
	 * current context).  Otherwise, grab the next available mailbox.
	 */
	if (mbox_wait == TAVOR_NOSLEEP) {
		count	 = 0;
		countmax = state->ts_cfg_profile->cp_cmd_poll_max;

		mutex_enter(&mblist->mbl_lock);
		mblist->mbl_pollers++;
		while (mblist->mbl_entries_free == 0) {
			mutex_exit(&mblist->mbl_lock);
			/* Delay loop polling for an available mbox */
			if (++count > countmax) {
				TNF_PROBE_0(tavor_impl_mbox_alloc_fail,
				    TAVOR_TNF_ERROR, "");
				TAVOR_TNF_EXIT(tavor_impl_mbox_alloc);
				return (TAVOR_CMD_INSUFF_RSRC);
			}

			/* Delay before polling for mailbox again */
			drv_usecwait(state->ts_cfg_profile->cp_cmd_poll_delay);
			mutex_enter(&mblist->mbl_lock);
		}
		mblist->mbl_pollers--;

	/* TAVOR_SLEEP */
	} else {
		/*
		 * Grab lock here as we prepare to cv_wait if needed.
		 */
		mutex_enter(&mblist->mbl_lock);
		while (mblist->mbl_entries_free == 0) {
			/*
			 * Wait (on cv) for a mailbox to become free.  Note:
			 * Just as we do above in tavor_cmd_post(), we also
			 * have the "__lock_lint" here to workaround warlock.
			 * Warlock doesn't know that other parts of the Tavor
			 * may occasionally call this routine while holding
			 * their own locks, so it complains about this cv_wait.
			 * In reality, however, the rest of the driver never
			 * calls this routine with a lock held unless they pass
			 * TAVOR_CMD_NOSLEEP.
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

	TAVOR_TNF_EXIT(tavor_impl_mbox_alloc);
	return (TAVOR_CMD_SUCCESS);
}


/*
 * tavor_impl_mbox_free()
 *    Context: Can be called from interrupt or base context.
 */
static void
tavor_impl_mbox_free(tavor_mboxlist_t *mblist, tavor_mbox_t **mb)
{
	uint_t		mbox_indx;

	TAVOR_TNF_ENTER(tavor_impl_mbox_free);

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

	TAVOR_TNF_EXIT(tavor_impl_mbox_free);
}


/*
 * tavor_impl_mboxlist_init()
 *    Context: Only called from attach() path context
 */
static int
tavor_impl_mboxlist_init(tavor_state_t *state, tavor_mboxlist_t *mblist,
    uint_t num_mbox, tavor_rsrc_type_t type)
{
	tavor_rsrc_t		*rsrc;
	ddi_dma_cookie_t	dma_cookie;
	uint_t			dma_cookiecnt, flag, sync;
	int			status, i;

	TAVOR_TNF_ENTER(tavor_impl_mboxlist_init);

	/* Allocate the memory for the mailbox entries list */
	mblist->mbl_list_sz = num_mbox;
	mblist->mbl_mbox = kmem_zalloc(mblist->mbl_list_sz *
	    sizeof (tavor_mbox_t), KM_SLEEP);

	/* Initialize the mailbox entries list */
	mblist->mbl_head_indx	 = 0;
	mblist->mbl_tail_indx	 = mblist->mbl_list_sz - 1;
	mblist->mbl_entries_free = mblist->mbl_list_sz;
	mblist->mbl_waiters	 = 0;
	mblist->mbl_num_alloc	 = 0;

	/* Set up the mailbox list's cv and mutex */
	mutex_init(&mblist->mbl_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->ts_intrmsi_pri));
	cv_init(&mblist->mbl_cv, NULL, CV_DRIVER, NULL);

	/* Determine if syncs will be necessary */
	sync = TAVOR_MBOX_IS_SYNC_REQ(state, type);

	/* Determine whether to map DDI_DMA_STREAMING or DDI_DMA_CONSISTENT */
	flag = state->ts_cfg_profile->cp_streaming_consistent;

	/* Initialize the mailbox list entries */
	for (i = 0; i < mblist->mbl_list_sz; i++) {
		/* Allocate resources for the mailbox */
		status = tavor_rsrc_alloc(state, type, 1, TAVOR_SLEEP,
		    &rsrc);
		if (status != DDI_SUCCESS) {
			/* Jump to cleanup and return error */
			TNF_PROBE_0(tavor_impl_mbox_init_rsrcalloc_fail,
			    TAVOR_TNF_ERROR, "");
			goto mboxlist_init_fail;
		}

		/* Save away the mailbox resource info */
		mblist->mbl_mbox[i].mb_rsrcptr	= rsrc;
		mblist->mbl_mbox[i].mb_addr	= rsrc->tr_addr;
		mblist->mbl_mbox[i].mb_acchdl	= rsrc->tr_acchdl;

		/*
		 * Get a PCI mapped address for each mailbox.  Note: this
		 * uses the ddi_dma_handle return from the resource
		 * allocation routine
		 */
		status = ddi_dma_addr_bind_handle(rsrc->tr_dmahdl, NULL,
		    rsrc->tr_addr, rsrc->tr_len, (DDI_DMA_RDWR | flag),
		    DDI_DMA_SLEEP, NULL, &dma_cookie, &dma_cookiecnt);
		if (status != DDI_SUCCESS) {
			/* Jump to cleanup and return error */
			tavor_rsrc_free(state, &rsrc);
			TNF_PROBE_0(tavor_impl_mbox_init_dmabind_fail,
			    TAVOR_TNF_ERROR, "");
			goto mboxlist_init_fail;
		}

		/* Save away the mapped address for the mailbox */
		mblist->mbl_mbox[i].mb_mapaddr	= dma_cookie.dmac_laddress;

		/* Set sync flag appropriately */
		mblist->mbl_mbox[i].mb_sync	= sync;

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

	TAVOR_TNF_EXIT(tavor_impl_mboxlist_init);
	return (DDI_SUCCESS);

mboxlist_init_fail:
	tavor_impl_mboxlist_fini(state, mblist);

	TAVOR_TNF_EXIT(tavor_impl_mboxlist_init);
	return (DDI_FAILURE);
}


/*
 * tavor_impl_mboxlist_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
static void
tavor_impl_mboxlist_fini(tavor_state_t *state, tavor_mboxlist_t *mblist)
{
	tavor_rsrc_t	*rsrc;
	int		i, status;

	TAVOR_TNF_ENTER(tavor_impl_mboxlist_fini);

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
		status = ddi_dma_unbind_handle(rsrc->tr_dmahdl);
		if (status != DDI_SUCCESS) {
			TAVOR_WARNING(state, "failed to unbind DMA mapping");
			TNF_PROBE_0(tavor_impl_mboxlist_fini_dmaunbind_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_impl_mboxlist_fini);
			return;
		}

		/* Next, free the mailbox resource */
		tavor_rsrc_free(state, &rsrc);
	}

	/* Destroy the mailbox list mutex and cv */
	mutex_destroy(&mblist->mbl_lock);
	cv_destroy(&mblist->mbl_cv);

	/* Free up the memory for tracking the mailbox list */
	kmem_free(mblist->mbl_mbox, mblist->mbl_list_sz *
	    sizeof (tavor_mbox_t));

	TAVOR_TNF_EXIT(tavor_impl_mboxlist_fini);
}


/*
 * tavor_outstanding_cmd_alloc()
 *    Context: Can be called only from base context.
 */
static int
tavor_outstanding_cmd_alloc(tavor_state_t *state, tavor_cmd_t **cmd_ptr,
    uint_t cmd_wait)
{
	tavor_cmdlist_t	*cmd_list;
	uint_t		next, prev, head;

	TAVOR_TNF_ENTER(tavor_outstanding_cmd_alloc);

	cmd_list = &state->ts_cmd_list;
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
		if (cmd_wait == TAVOR_NOSLEEP) {
			mutex_exit(&cmd_list->cml_lock);
			TNF_PROBE_0(tavor_outstanding_cmd_alloc_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_outstanding_cmd_alloc);
			return (TAVOR_CMD_INSUFF_RSRC);
		}

		/*
		 * Wait (on cv) for a command to become free.  Note: Just
		 * as we do above in tavor_cmd_post(), we also have the
		 * "__lock_lint" here to workaround warlock.  Warlock doesn't
		 * know that other parts of the Tavor may occasionally call
		 * this routine while holding their own locks, so it complains
		 * about this cv_wait.  In reality, however, the rest of the
		 * driver never calls this routine with a lock held unless
		 * they pass TAVOR_CMD_NOSLEEP.
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
	(*cmd_ptr)->cmd_status = TAVOR_CMD_INVALID_STATUS;

	/* Remove it from the command list */
	cmd_list->cml_cmd[next].cmd_prev = prev;
	cmd_list->cml_cmd[prev].cmd_next = next;
	cmd_list->cml_head_indx		 = next;

	/* Update the "free" count and return */
	cmd_list->cml_entries_free--;

	mutex_exit(&cmd_list->cml_lock);

	TAVOR_TNF_EXIT(tavor_outstanding_cmd_alloc);
	return (TAVOR_CMD_SUCCESS);
}


/*
 * tavor_outstanding_cmd_free()
 *    Context: Can be called only from base context.
 */
static void
tavor_outstanding_cmd_free(tavor_state_t *state, tavor_cmd_t **cmd_ptr)
{
	tavor_cmdlist_t	*cmd_list;
	uint_t		cmd_indx;

	TAVOR_TNF_ENTER(tavor_outstanding_cmd_free);

	cmd_list = &state->ts_cmd_list;
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

	TAVOR_TNF_EXIT(tavor_outstanding_cmd_free);
}


/*
 * tavor_write_hcr()
 *    Context: Can be called from interrupt or base context.
 */
static int
tavor_write_hcr(tavor_state_t *state, tavor_cmd_post_t *cmdpost,
    uint16_t token)
{
	tavor_hw_hcr_t	*hcr;
	uint_t		status, count, countmax;
	uint64_t	hcrreg;

	TAVOR_TNF_ENTER(tavor_write_hcr);

	/*
	 * Grab the "HCR access" lock if the driver is not in
	 * fastreboot. In fastreboot, this function is called
	 * with the single thread but in high interrupt context
	 * (so that this mutex lock cannot be used).
	 */
#ifdef __lock_lint
	mutex_enter(&state->ts_cmd_regs.hcr_lock);
#else
	if (!TAVOR_IN_FASTREBOOT(state)) {
		mutex_enter(&state->ts_cmd_regs.hcr_lock);
	}
#endif

	hcr = state->ts_cmd_regs.hcr;

	/*
	 * First, check the "go" bit to see if the previous hcr usage is
	 * complete.  As long as it is set then we must continue to poll.
	 */
	count	 = 0;
	countmax = state->ts_cfg_profile->cp_cmd_poll_max;
	for (;;) {
		hcrreg = ddi_get32(state->ts_reg_cmdhdl, &hcr->cmd);

		/* If "go" bit is clear, then done */
		if ((hcrreg & TAVOR_HCR_CMD_GO_MASK) == 0) {
			TNF_PROBE_1_DEBUG(tavor_write_hcr_loop_count,
			    TAVOR_TNF_ERROR, "", tnf_uint, nospinloopcount,
			    count);
			break;
		}
		/* Delay before polling the "go" bit again */
		drv_usecwait(state->ts_cfg_profile->cp_cmd_poll_delay);

		/*
		 * If we poll more than the maximum number of times, then
		 * return a "timeout" error.
		 */
		if (++count > countmax) {
#ifdef __lock_lint
			mutex_exit(&state->ts_cmd_regs.hcr_lock);
#else
			if (!TAVOR_IN_FASTREBOOT(state)) {
				mutex_exit(&state->ts_cmd_regs.hcr_lock);
			}
#endif
			TNF_PROBE_0(tavor_write_hcr_timeout1, TAVOR_TNF_ERROR,
			    "");
			TAVOR_TNF_EXIT(tavor_write_hcr);
			return (TAVOR_CMD_TIMEOUT);
		}
	}

	/* Write "inparam" as a 64-bit quantity */
	ddi_put64(state->ts_reg_cmdhdl, (uint64_t *)&hcr->in_param0,
	    cmdpost->cp_inparm);

	/* Write "inmod" and 32-bits of "outparam" as 64-bit */
	hcrreg = ((uint64_t)cmdpost->cp_inmod << 32);
	hcrreg = hcrreg | (cmdpost->cp_outparm >> 32);
	ddi_put64(state->ts_reg_cmdhdl, (uint64_t *)&hcr->input_modifier,
	    hcrreg);

	/* Write the other 32-bits of "outparam" and "token" as 64-bit */
	hcrreg = (cmdpost->cp_outparm << 32);
	hcrreg = hcrreg | ((uint32_t)token << TAVOR_HCR_TOKEN_SHIFT);
	ddi_put64(state->ts_reg_cmdhdl, (uint64_t *)&hcr->out_param1,
	    hcrreg);

	/* Then setup the final hcrreg to hit doorbell (i.e. "go" bit) */
	hcrreg = TAVOR_HCR_CMD_GO_MASK;
	if (cmdpost->cp_flags == TAVOR_CMD_SLEEP_NOSPIN)
		hcrreg = hcrreg | TAVOR_HCR_CMD_E_MASK;
	hcrreg = hcrreg | (cmdpost->cp_opmod << TAVOR_HCR_CMD_OPMOD_SHFT);
	hcrreg = hcrreg | (cmdpost->cp_opcode);

	/* Write the doorbell to the HCR */
	ddi_put32(state->ts_reg_cmdhdl, &hcr->cmd, hcrreg);

	/*
	 * In the SPIN case we read the HCR and check the "go" bit.  For the
	 * NOSPIN case we do not have to poll, we simply release the HCR lock
	 * and return.
	 */
	if (cmdpost->cp_flags == TAVOR_CMD_NOSLEEP_SPIN) {
		count	 = 0;
		countmax = state->ts_cfg_profile->cp_cmd_poll_max;

		for (;;) {
			hcrreg = ddi_get32(state->ts_reg_cmdhdl, &hcr->cmd);

			/* If "go" bit is clear, then done */
			if ((hcrreg & TAVOR_HCR_CMD_GO_MASK) == 0) {
				TNF_PROBE_1_DEBUG(tavor_write_hcr_loop_count,
				    TAVOR_TNF_ERROR, "", tnf_uint,
				    spinloopcount, count);
				break;
			}
			/* Delay before polling the "go" bit again */
			drv_usecwait(state->ts_cfg_profile->cp_cmd_poll_delay);

			/*
			 * If we poll more than the maximum number of times,
			 * then return a "timeout" error.
			 */
			if (++count > countmax) {
#ifdef __lock_lint
				mutex_exit(&state-> ts_cmd_regs.hcr_lock);
#else
				if (!TAVOR_IN_FASTREBOOT(state)) {
					mutex_exit(&state->
					    ts_cmd_regs.hcr_lock);
				}
#endif
				TNF_PROBE_0(tavor_write_hcr_timeout2,
				    TAVOR_TNF_ERROR, "");
				TAVOR_TNF_EXIT(tavor_write_hcr);
				return (TAVOR_CMD_TIMEOUT);
			}
		}

		/* Pull out the "status" bits from the HCR */
		status = (hcrreg >> TAVOR_HCR_CMD_STATUS_SHFT);

		/*
		 * Read the "outparam" value.  Note: we have to read "outparam"
		 * as two separate 32-bit reads because the field in the HCR is
		 * not 64-bit aligned.
		 */
		hcrreg = ddi_get32(state->ts_reg_cmdhdl, &hcr->out_param0);
		cmdpost->cp_outparm = hcrreg << 32;
		hcrreg = ddi_get32(state->ts_reg_cmdhdl, &hcr->out_param1);
		cmdpost->cp_outparm |= hcrreg;

	/* NOSPIN */
	} else {
		status = TAVOR_CMD_SUCCESS;
	}

	/* Drop the "HCR access" lock */
#ifdef __lock_lint
	mutex_exit(&state->ts_cmd_regs.hcr_lock);
#else
	if (!TAVOR_IN_FASTREBOOT(state)) {
		mutex_exit(&state->ts_cmd_regs.hcr_lock);
	}
#endif

	TAVOR_TNF_EXIT(tavor_write_hcr);
	return (status);
}


/*
 * tavor_outstanding_cmdlist_init()
 *    Context: Only called from attach() path context
 */
int
tavor_outstanding_cmdlist_init(tavor_state_t *state)
{
	uint_t		num_outstanding_cmds, head, tail;
	int		i;

	TAVOR_TNF_ENTER(tavor_outstanding_cmdlist_init);

	/*
	 * Determine the number of the outstanding commands supported
	 * by the Tavor device (obtained from the QUERY_FW command).  Note:
	 * Because we handle both SLEEP and NOSLEEP cases around the tavor HCR,
	 * we know that when an interrupt comes in it will be next on the
	 * command register, and will at most have to wait one commands time.
	 * We do not have to reserve an outstanding command here for
	 * interrupts.
	 */
	num_outstanding_cmds = (1 << state->ts_fw.log_max_cmd);

	/* Initialize the outstanding command list */
	state->ts_cmd_list.cml_list_sz	 = num_outstanding_cmds;
	state->ts_cmd_list.cml_head_indx = 0;
	state->ts_cmd_list.cml_tail_indx = state->ts_cmd_list.cml_list_sz - 1;
	state->ts_cmd_list.cml_entries_free = state->ts_cmd_list.cml_list_sz;
	state->ts_cmd_list.cml_waiters	 = 0;
	state->ts_cmd_list.cml_num_alloc = 0;

	/* Allocate the memory for the outstanding command list */
	if (num_outstanding_cmds) {
		state->ts_cmd_list.cml_cmd =
		    kmem_zalloc(state->ts_cmd_list.cml_list_sz *
		    sizeof (tavor_cmd_t), KM_SLEEP);
	}
	mutex_init(&state->ts_cmd_list.cml_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(state->ts_intrmsi_pri));
	cv_init(&state->ts_cmd_list.cml_cv, NULL, CV_DRIVER, NULL);

	/* Initialize the individual outstanding command list entries */
	for (i = 0; i < state->ts_cmd_list.cml_list_sz; i++) {
		mutex_init(&state->ts_cmd_list.cml_cmd[i].cmd_comp_lock,
		    NULL, MUTEX_DRIVER, DDI_INTR_PRI(state->ts_intrmsi_pri));
		cv_init(&state->ts_cmd_list.cml_cmd[i].cmd_comp_cv, NULL,
		    CV_DRIVER, NULL);

		state->ts_cmd_list.cml_cmd[i].cmd_next	= i+1;
		state->ts_cmd_list.cml_cmd[i].cmd_prev	= i-1;
		state->ts_cmd_list.cml_cmd[i].cmd_indx	= i;
		state->ts_cmd_list.cml_num_alloc	= i + 1;
	}
	if (num_outstanding_cmds) {
		head = state->ts_cmd_list.cml_head_indx;
		tail = state->ts_cmd_list.cml_tail_indx;
		state->ts_cmd_list.cml_cmd[head].cmd_prev =
		    state->ts_cmd_list.cml_tail_indx;
		state->ts_cmd_list.cml_cmd[tail].cmd_next =
		    state->ts_cmd_list.cml_head_indx;
	}

	TAVOR_TNF_EXIT(tavor_outstanding_cmdlist_init);
	return (DDI_SUCCESS);
}


/*
 * tavor_outstanding_cmdlist_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
void
tavor_outstanding_cmdlist_fini(tavor_state_t *state)
{
	int		i;

	TAVOR_TNF_ENTER(tavor_outstanding_cmdlist_fini);

	/* Destroy the outstanding command list entries */
	for (i = 0; i < state->ts_cmd_list.cml_num_alloc; i++) {
		mutex_destroy(&state->ts_cmd_list.cml_cmd[i].cmd_comp_lock);
		cv_destroy(&state->ts_cmd_list.cml_cmd[i].cmd_comp_cv);
	}

	/* Destroy the lock (and cv) and free up memory for list */
	mutex_destroy(&state->ts_cmd_list.cml_lock);
	cv_destroy(&state->ts_cmd_list.cml_cv);
	if (state->ts_cmd_list.cml_num_alloc) {
		kmem_free(state->ts_cmd_list.cml_cmd,
		    state->ts_cmd_list.cml_list_sz * sizeof (tavor_cmd_t));
	}

	TAVOR_TNF_EXIT(tavor_outstanding_cmdlist_fini);
}


/*
 * tavor_mbox_sync()
 */
static void
tavor_mbox_sync(tavor_mbox_t *mbox, uint_t offset, uint_t length,
    uint_t flag)
{
	ddi_dma_handle_t	dmahdl;
	int			status;

	TAVOR_TNF_ENTER(tavor_mbox_sync);

	/* Determine if mailbox needs to be synced or not */
	if (mbox->mb_sync == 0) {
		TAVOR_TNF_EXIT(tavor_mbox_sync);
		return;
	}

	/* Get the DMA handle from mailbox */
	dmahdl = mbox->mb_rsrcptr->tr_dmahdl;

	/* Calculate offset into mailbox */
	status = ddi_dma_sync(dmahdl, (off_t)offset, (size_t)length, flag);
	if (status != DDI_SUCCESS) {
		TNF_PROBE_0(tavor_mbox_sync_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_mbox_sync);
		return;
	}

	TAVOR_TNF_EXIT(tavor_mbox_sync);
}


/*
 * tavor_sys_en_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *    (Currently called only from attach() path context)
 */
int
tavor_sys_en_cmd_post(tavor_state_t *state, uint_t flags,
    uint64_t *errorcode, uint_t sleepflag)
{
	tavor_cmd_post_t	cmd;
	int			status;

	TAVOR_TNF_ENTER(tavor_sys_en_cmd_post);

	/* Make sure we are called with the correct flag */
	ASSERT(sleepflag == TAVOR_CMD_NOSLEEP_SPIN);

	/* Setup and post the Tavor "SYS_EN" command */
	cmd.cp_inparm	= 0;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= 0;
	cmd.cp_opcode	= SYS_EN;
	cmd.cp_opmod	= flags;
	cmd.cp_flags	= sleepflag;
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_sys_en_cmd_post_fail, TAVOR_TNF_ERROR, "");
		/*
		 * When the SYS_EN command fails, the "outparam" field may
		 * contain more detailed information about what caused the
		 * failure.
		 */
		*errorcode = cmd.cp_outparm;
	}

	TAVOR_TNF_EXIT(tavor_sys_en_cmd_post);
	return (status);
}


/*
 * tavor_sys_dis_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *    (Currently called only from attach() and/or detach() path contexts)
 */
int
tavor_sys_dis_cmd_post(tavor_state_t *state, uint_t sleepflag)
{
	tavor_cmd_post_t	cmd;
	int			status;

	TAVOR_TNF_ENTER(tavor_sys_dis_cmd_post);

	/* Make sure we are called with the correct flag */
	ASSERT(sleepflag == TAVOR_CMD_NOSLEEP_SPIN);

	/* Setup and post the Tavor "SYS_DIS" command */
	cmd.cp_inparm	= 0;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= 0;
	cmd.cp_opcode	= SYS_DIS;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= sleepflag;
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_sys_dis_cmd_post_fail,
		    TAVOR_TNF_ERROR, "");
	}

	TAVOR_TNF_EXIT(tavor_sys_dis_cmd_post);
	return (status);
}


/*
 * tavor_init_hca_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *    (Currently called only from attach() path context)
 */
int
tavor_init_hca_cmd_post(tavor_state_t *state,
    tavor_hw_initqueryhca_t *inithca, uint_t sleepflag)
{
	tavor_mbox_info_t	mbox_info;
	tavor_cmd_post_t	cmd;
	uint64_t		data;
	uint_t			size;
	int			status, i;

	TAVOR_TNF_ENTER(tavor_init_hca_cmd_post);

	/* Make sure we are called with the correct flag */
	ASSERT(sleepflag == TAVOR_CMD_NOSLEEP_SPIN);

	/* Get an "In" mailbox for the command */
	mbox_info.mbi_alloc_flags = TAVOR_ALLOC_INMBOX;
	status = tavor_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_init_hca_mbox_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_init_hca_cmd_post);
		return (status);
	}

	/* Copy the Tavor "INIT_HCA" command into the mailbox */
	size = sizeof (tavor_hw_initqueryhca_t);
	for (i = 0; i < (size >> 3); i++) {
		data = ((uint64_t *)inithca)[i];
		ddi_put64(mbox_info.mbi_in->mb_acchdl,
		    ((uint64_t *)mbox_info.mbi_in->mb_addr + i), data);
	}

	/* Sync the mailbox for the device to read */
	tavor_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup and post the Tavor "INIT_HCA" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= 0;
	cmd.cp_opcode	= INIT_HCA;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= sleepflag;
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_init_hca_cmd_post_fail,
		    TAVOR_TNF_ERROR, "");
	}

	/* Free the mailbox */
	tavor_mbox_free(state, &mbox_info);

	TAVOR_TNF_EXIT(tavor_init_hca_cmd_post);
	return (status);
}


/*
 * tavor_close_hca_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *    (Currently called only from attach() and/or detach() path contexts)
 */
int
tavor_close_hca_cmd_post(tavor_state_t *state, uint_t sleepflag)
{
	tavor_cmd_post_t	cmd;
	int			status;

	TAVOR_TNF_ENTER(tavor_close_hca_cmd_post);

	/* Make sure we are called with the correct flag */
	ASSERT(sleepflag == TAVOR_CMD_NOSLEEP_SPIN);

	/* Setup and post the Tavor "CLOSE_HCA" command */
	cmd.cp_inparm	= 0;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= 0;
	cmd.cp_opcode	= CLOSE_HCA;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= sleepflag;
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_close_hca_cmd_post_fail,
		    TAVOR_TNF_ERROR, "");
	}

	TAVOR_TNF_EXIT(tavor_close_hca_cmd_post);
	return (status);
}


/*
 * tavor_init_ib_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *    (Currently called only from attach() path context)
 */
int
tavor_init_ib_cmd_post(tavor_state_t *state, tavor_hw_initib_t *initib,
    uint_t port, uint_t sleepflag)
{
	tavor_mbox_info_t	mbox_info;
	tavor_cmd_post_t	cmd;
	uint64_t		data;
	uint_t			size;
	int			status, i;

	TAVOR_TNF_ENTER(tavor_init_ib_cmd_post);

	/* Make sure we are called with the correct flag */
	ASSERT(sleepflag == TAVOR_CMD_NOSLEEP_SPIN);

	/* Get an "In" mailbox for the command */
	mbox_info.mbi_alloc_flags = TAVOR_ALLOC_INMBOX;
	status = tavor_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_init_ib_mbox_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_init_ib_cmd_post);
		return (status);
	}

	/* Copy the Tavor "INIT_IB" command into the mailbox */
	size = sizeof (tavor_hw_initib_t);
	for (i = 0; i < (size >> 3); i++) {
		data = ((uint64_t *)initib)[i];
		ddi_put64(mbox_info.mbi_in->mb_acchdl,
		    ((uint64_t *)mbox_info.mbi_in->mb_addr + i), data);
	}

	/* Sync the mailbox for the device to read */
	tavor_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup and post the Tavor "INIT_IB" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= port;
	cmd.cp_opcode	= INIT_IB;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= sleepflag;
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_init_ib_cmd_post_fail,
		    TAVOR_TNF_ERROR, "");
	}

	/* Free the mailbox */
	tavor_mbox_free(state, &mbox_info);

	TAVOR_TNF_EXIT(tavor_init_ib_cmd_post);
	return (status);
}


/*
 * tavor_close_ib_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *    (Currently called only from attach() and/or detach() path contexts)
 */
int
tavor_close_ib_cmd_post(tavor_state_t *state, uint_t port, uint_t sleepflag)
{
	tavor_cmd_post_t	cmd;
	int			status;

	TAVOR_TNF_ENTER(tavor_close_ib_cmd_post);

	/* Setup and post the Tavor "CLOSE_IB" command */
	cmd.cp_inparm	= 0;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= port;
	cmd.cp_opcode	= CLOSE_IB;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= sleepflag;
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_close_ib_cmd_post_fail, TAVOR_TNF_ERROR, "");
	}

	TAVOR_TNF_EXIT(tavor_close_ib_cmd_post);
	return (status);
}


/*
 * tavor_set_ib_cmd_post()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_set_ib_cmd_post(tavor_state_t *state, uint32_t capmask, uint_t port,
    uint_t reset_qkey, uint_t sleepflag)
{
	tavor_mbox_info_t	mbox_info;
	tavor_cmd_post_t	cmd;
	int			status;

	TAVOR_TNF_ENTER(tavor_set_ib_cmd_post);

	/* Get an "In" mailbox for the command */
	mbox_info.mbi_alloc_flags = TAVOR_ALLOC_INMBOX;
	status = tavor_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_set_ib_mbox_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_set_ib_cmd_post);
		return (status);
	}

	/* Copy the Tavor "SET_IB" command into mailbox */
	ddi_put32(mbox_info.mbi_in->mb_acchdl,
	    ((uint32_t *)mbox_info.mbi_in->mb_addr + 0), reset_qkey);
	ddi_put32(mbox_info.mbi_in->mb_acchdl,
	    ((uint32_t *)mbox_info.mbi_in->mb_addr + 1), capmask);

	/* Sync the mailbox for the device to read */
	tavor_mbox_sync(mbox_info.mbi_in, 0, TAVOR_CMD_SETIB_SZ,
	    DDI_DMA_SYNC_FORDEV);

	/* Setup and post the Tavor "SET_IB" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= port;
	cmd.cp_opcode	= SET_IB;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= sleepflag;
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_set_ib_cmd_post_fail, TAVOR_TNF_ERROR, "");
	}

	/* Free the mailbox */
	tavor_mbox_free(state, &mbox_info);

	TAVOR_TNF_EXIT(tavor_set_ib_cmd_post);
	return (status);
}


/*
 * tavor_mod_stat_cfg_cmd_post()
 *    Context: Can be called only from attach() path
 */
int
tavor_mod_stat_cfg_cmd_post(tavor_state_t *state)
{
	tavor_mbox_info_t	mbox_info;
	tavor_cmd_post_t	cmd;
	tavor_hw_mod_stat_cfg_t	*mod;
	uint64_t		data;
	uint_t			size;
	int			status, i;

	TAVOR_TNF_ENTER(tavor_mod_stat_cfg_cmd_post);

	/*
	 * "MOD_STAT_CFG" needs an INMBOX parameter, to specify what operations
	 * to do.  However, at the point in time that we call this command, the
	 * DDR has not yet been initialized, and all INMBOX'es are located in
	 * DDR.  Because we want to call MOD_STAT_CFG before QUERY_DEVLIM is
	 * called, and thus call it before DDR is setup, we simply use an
	 * OUTMBOX memory location here as our INMBOX parameter.
	 */
	mbox_info.mbi_alloc_flags = TAVOR_ALLOC_OUTMBOX;
	status = tavor_mbox_alloc(state, &mbox_info, TAVOR_NOSLEEP);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_mod_stat_cfg_mbox_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_mod_stat_cfg_cmd_post);
		return (status);
	}

	/*
	 * Allocate on the heap our 'mod_stat_cfg' structure.  We want to
	 * ideally move all of this on to the stack in the future, but this
	 * works well for now.
	 */
	mod = (tavor_hw_mod_stat_cfg_t *)kmem_zalloc(
	    sizeof (tavor_hw_mod_stat_cfg_t), KM_SLEEP);

	/* Setup "MOD_STAT_CFG" settings */
	mod->srq_m	= 1;
	mod->srq	= state->ts_cfg_profile->cp_srq_enable;

	if (mod->srq) {
		mod->log_max_srq = state->ts_cfg_profile->cp_log_num_srq;
	} else {
		mod->log_max_srq = 0;
	}

	/* Copy the "MOD_STAT_CFG" command into the "In" mailbox */
	size = sizeof (tavor_hw_mod_stat_cfg_t);
	for (i = 0; i < (size >> 3); i++) {
		data = ((uint64_t *)mod)[i];
		ddi_put64(mbox_info.mbi_out->mb_acchdl,
		    ((uint64_t *)mbox_info.mbi_out->mb_addr + i), data);
	}

	/* Sync the mailbox for the device to read */
	tavor_mbox_sync(mbox_info.mbi_out, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup and post the Tavor "MOD_STAT_CFG" command */
	cmd.cp_inparm	= mbox_info.mbi_out->mb_mapaddr;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= 0;
	cmd.cp_opcode	= MOD_STAT_CFG;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= TAVOR_CMD_NOSLEEP_SPIN;
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_mod_stat_cfg_cmd_post_fail, TAVOR_TNF_ERROR,
		    "");
	}

	/* Free "MOD_STAT_CFG" struct */
	kmem_free(mod, sizeof (tavor_hw_mod_stat_cfg_t));

	/* Free the mailbox */
	tavor_mbox_free(state, &mbox_info);

	TAVOR_TNF_EXIT(tavor_mod_stat_cfg_cmd_post);
	return (status);
}


/*
 * tavor_mad_ifc_cmd_post()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_mad_ifc_cmd_post(tavor_state_t *state, uint_t port,
    uint_t sleepflag, uint32_t *mad, uint32_t *resp)
{
	tavor_mbox_info_t	mbox_info;
	tavor_cmd_post_t	cmd;
	uint_t			size;
	int			status;

	TAVOR_TNF_ENTER(tavor_mad_ifc_cmd_post);

	/* Get "In" and "Out" mailboxes for the command */
	mbox_info.mbi_alloc_flags = TAVOR_ALLOC_INMBOX | TAVOR_ALLOC_OUTMBOX;
	status = tavor_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_mad_ifc_mbox_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_mad_ifc_cmd_post);
		return (status);
	}

	/* Copy the request MAD into the "In" mailbox */
	size = TAVOR_CMD_MAD_IFC_SIZE;
	bcopy(mad, mbox_info.mbi_in->mb_addr, size);

	/* Sync the mailbox for the device to read */
	tavor_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup the Tavor "MAD_IFC" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= mbox_info.mbi_out->mb_mapaddr;
	cmd.cp_inmod	= port;
	cmd.cp_opcode	= MAD_IFC;
	cmd.cp_opmod	= TAVOR_CMD_MKEY_CHECK;  /* Enable MKey checking */
	cmd.cp_flags	= sleepflag;
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_mad_ifc_cmd_post_fail,
		    TAVOR_TNF_ERROR, "");
		goto mad_ifc_fail;
	}

	/* Sync the mailbox to read the results */
	tavor_mbox_sync(mbox_info.mbi_out, 0, size, DDI_DMA_SYNC_FORCPU);

	/* Copy the response MAD into "resp" */
	bcopy(mbox_info.mbi_out->mb_addr, resp, size);

mad_ifc_fail:
	/* Free the mailbox */
	tavor_mbox_free(state, &mbox_info);

	TAVOR_TNF_EXIT(tavor_mad_ifc_cmd_post);
	return (status);
}


/*
 * tavor_getportinfo_cmd_post()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_getportinfo_cmd_post(tavor_state_t *state, uint_t port,
    uint_t sleepflag, sm_portinfo_t *portinfo)
{
	tavor_mbox_info_t	mbox_info;
	tavor_cmd_post_t	cmd;
	uint32_t		*mbox;
	uint_t			size;
	int			status, i;

	TAVOR_TNF_ENTER(tavor_getportinfo_cmd_post);

	/* Get "In" and "Out" mailboxes for the command */
	mbox_info.mbi_alloc_flags = TAVOR_ALLOC_INMBOX | TAVOR_ALLOC_OUTMBOX;
	status = tavor_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_getportinfo_mbox_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_getportinfo_cmd_post);
		return (status);
	}

	/* Build the GetPortInfo request MAD in the "In" mailbox */
	size = TAVOR_CMD_MAD_IFC_SIZE;
	mbox = (uint32_t *)mbox_info.mbi_in->mb_addr;
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[0], TAVOR_CMD_MADHDR0);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[1], TAVOR_CMD_MADHDR1);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[2], TAVOR_CMD_MADHDR2);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[3], TAVOR_CMD_MADHDR3);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[4], TAVOR_CMD_PORTINFO);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[5], port);
	for (i = 6; i < (size >> 2); i++) {
		ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[i], 0);
	}

	/* Sync the mailbox for the device to read */
	tavor_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup the Tavor "MAD_IFC" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= mbox_info.mbi_out->mb_mapaddr;
	cmd.cp_inmod	= port;
	cmd.cp_opcode	= MAD_IFC;
	cmd.cp_opmod	= TAVOR_CMD_MKEY_DONTCHECK;  /* No MKey checking */
	cmd.cp_flags	= sleepflag;
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_getportinfo_cmd_post_fail,
		    TAVOR_TNF_ERROR, "");
		goto getportinfo_fail;
	}

	/* Sync the mailbox to read the results */
	size = sizeof (sm_portinfo_t);
	tavor_mbox_sync(mbox_info.mbi_out, TAVOR_CMD_MADDATA_OFFSET,
	    size, DDI_DMA_SYNC_FORCPU);

	/*
	 * Copy GetPortInfo response MAD into "portinfo".  Do any endian
	 * swapping that may be necessary to flip any of the "portinfo"
	 * fields
	 */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*portinfo))
	bcopy((void *)((uintptr_t)mbox_info.mbi_out->mb_addr +
	    TAVOR_CMD_MADDATA_OFFSET), portinfo, size);
	TAVOR_GETPORTINFO_SWAP(portinfo);
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*portinfo))

getportinfo_fail:
	/* Free the mailbox */
	tavor_mbox_free(state, &mbox_info);

	TAVOR_TNF_EXIT(tavor_getportinfo_cmd_post);
	return (status);
}


/*
 * tavor_getnodeinfo_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *    (Currently called only from attach() and detach() path contexts)
 */
int
tavor_getnodeinfo_cmd_post(tavor_state_t *state, uint_t sleepflag,
    sm_nodeinfo_t *nodeinfo)
{
	tavor_mbox_info_t	mbox_info;
	tavor_cmd_post_t	cmd;
	uint32_t		*mbox;
	uint_t			size;
	int			status, i;

	TAVOR_TNF_ENTER(tavor_getnodeinfo_cmd_post);

	/* Make sure we are called with the correct flag */
	ASSERT(sleepflag == TAVOR_CMD_NOSLEEP_SPIN);

	/* Get "In" and "Out" mailboxes for the command */
	mbox_info.mbi_alloc_flags = TAVOR_ALLOC_INMBOX | TAVOR_ALLOC_OUTMBOX;
	status = tavor_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_getnodeinfo_mbox_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_getnodeinfo_cmd_post);
		return (status);
	}

	/* Build the GetNodeInfo request MAD into the "In" mailbox */
	size = TAVOR_CMD_MAD_IFC_SIZE;
	mbox = (uint32_t *)mbox_info.mbi_in->mb_addr;
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[0], TAVOR_CMD_MADHDR0);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[1], TAVOR_CMD_MADHDR1);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[2], TAVOR_CMD_MADHDR2);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[3], TAVOR_CMD_MADHDR3);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[4], TAVOR_CMD_NODEINFO);
	for (i = 5; i < (size >> 2); i++) {
		ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[i], 0);
	}

	/* Sync the mailbox for the device to read */
	tavor_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup the Tavor "MAD_IFC" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= mbox_info.mbi_out->mb_mapaddr;
	cmd.cp_inmod	= 1;  /* Get NodeInfo from port #1 */
	cmd.cp_opcode	= MAD_IFC;
	cmd.cp_opmod	= TAVOR_CMD_MKEY_DONTCHECK;  /* No MKey checking */
	cmd.cp_flags	= sleepflag;
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_getnodeinfo_cmd_post_fail,
		    TAVOR_TNF_ERROR, "");
		goto getnodeinfo_fail;
	}

	/* Sync the mailbox to read the results */
	size = sizeof (sm_nodeinfo_t);
	tavor_mbox_sync(mbox_info.mbi_out, TAVOR_CMD_MADDATA_OFFSET,
	    size, DDI_DMA_SYNC_FORCPU);

	/*
	 * Copy GetNodeInfo response MAD into "nodeinfo".  Do any endian
	 * swapping that may be necessary to flip any of the "nodeinfo"
	 * fields
	 */
	bcopy((void *)((uintptr_t)mbox_info.mbi_out->mb_addr +
	    TAVOR_CMD_MADDATA_OFFSET), nodeinfo, size);
	TAVOR_GETNODEINFO_SWAP(nodeinfo);

getnodeinfo_fail:
	/* Free the mailbox */
	tavor_mbox_free(state, &mbox_info);

	TAVOR_TNF_EXIT(tavor_getnodeinfo_cmd_post);
	return (status);
}


/*
 * tavor_getnodedesc_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *    (Currently called only from attach() and detach() path contexts)
 */
int
tavor_getnodedesc_cmd_post(tavor_state_t *state, uint_t sleepflag,
    sm_nodedesc_t *nodedesc)
{
	tavor_mbox_info_t	mbox_info;
	tavor_cmd_post_t	cmd;
	uint32_t		*mbox;
	uint_t			size;
	int			status, i;

	TAVOR_TNF_ENTER(tavor_getnodedesc_cmd_post);

	/* Get "In" and "Out" mailboxes for the command */
	mbox_info.mbi_alloc_flags = TAVOR_ALLOC_INMBOX | TAVOR_ALLOC_OUTMBOX;
	status = tavor_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_getnodedesc_mbox_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_getnodedesc_cmd_post);
		return (status);
	}

	/* Build the GetNodeDesc request MAD into the "In" mailbox */
	size = TAVOR_CMD_MAD_IFC_SIZE;
	mbox = (uint32_t *)mbox_info.mbi_in->mb_addr;
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[0], TAVOR_CMD_MADHDR0);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[1], TAVOR_CMD_MADHDR1);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[2], TAVOR_CMD_MADHDR2);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[3], TAVOR_CMD_MADHDR3);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[4], TAVOR_CMD_NODEDESC);
	for (i = 5; i < (size >> 2); i++) {
		ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[i], 0);
	}

	/* Sync the mailbox for the device to read */
	tavor_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup the Tavor "MAD_IFC" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= mbox_info.mbi_out->mb_mapaddr;
	cmd.cp_inmod	= 1;  /* Get NodeDesc from port #1 */
	cmd.cp_opcode	= MAD_IFC;
	cmd.cp_opmod	= TAVOR_CMD_MKEY_DONTCHECK;  /* No MKey checking */
	cmd.cp_flags	= sleepflag;
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_getnodedesc_cmd_post_fail,
		    TAVOR_TNF_ERROR, "");
		goto getnodedesc_fail;
	}

	/* Sync the mailbox to read the results */
	size = sizeof (sm_nodedesc_t);
	tavor_mbox_sync(mbox_info.mbi_out, TAVOR_CMD_MADDATA_OFFSET,
	    size, DDI_DMA_SYNC_FORCPU);

	/* Copy GetNodeDesc response MAD into "nodedesc" */
	bcopy((void *)((uintptr_t)mbox_info.mbi_out->mb_addr +
	    TAVOR_CMD_MADDATA_OFFSET), nodedesc, size);

getnodedesc_fail:
	/* Free the mailbox */
	tavor_mbox_free(state, &mbox_info);

	TAVOR_TNF_EXIT(tavor_getnodedesc_cmd_post);
	return (status);
}


/*
 * tavor_getguidinfo_cmd_post()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_getguidinfo_cmd_post(tavor_state_t *state, uint_t port,
    uint_t guidblock, uint_t sleepflag, sm_guidinfo_t *guidinfo)
{
	tavor_mbox_info_t	mbox_info;
	tavor_cmd_post_t	cmd;
	uint32_t		*mbox;
	uint_t			size;
	int			status, i;

	TAVOR_TNF_ENTER(tavor_getguidinfo_cmd_post);

	/* Get "In" and "Out" mailboxes for the command */
	mbox_info.mbi_alloc_flags = TAVOR_ALLOC_INMBOX | TAVOR_ALLOC_OUTMBOX;
	status = tavor_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_getguidinfo_mbox_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_getguidinfo_cmd_post);
		return (status);
	}

	/* Build the GetGUIDInfo request MAD into the "In" mailbox */
	size = TAVOR_CMD_MAD_IFC_SIZE;
	mbox = (uint32_t *)mbox_info.mbi_in->mb_addr;
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[0], TAVOR_CMD_MADHDR0);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[1], TAVOR_CMD_MADHDR1);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[2], TAVOR_CMD_MADHDR2);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[3], TAVOR_CMD_MADHDR3);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[4], TAVOR_CMD_GUIDINFO);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[5], guidblock);
	for (i = 6; i < (size >> 2); i++) {
		ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[i], 0);
	}

	/* Sync the mailbox for the device to read */
	tavor_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup the Tavor "MAD_IFC" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= mbox_info.mbi_out->mb_mapaddr;
	cmd.cp_inmod	= port;
	cmd.cp_opcode	= MAD_IFC;
	cmd.cp_opmod	= TAVOR_CMD_MKEY_DONTCHECK;  /* No MKey checking */
	cmd.cp_flags	= sleepflag;
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_getguidinfo_cmd_post_fail,
		    TAVOR_TNF_ERROR, "");
		goto getguidinfo_fail;
	}

	/* Sync the mailbox to read the results */
	size = sizeof (sm_guidinfo_t);
	tavor_mbox_sync(mbox_info.mbi_out, TAVOR_CMD_MADDATA_OFFSET,
	    size, DDI_DMA_SYNC_FORCPU);

	/*
	 * Copy GetGUIDInfo response MAD into "guidinfo".  Do any endian
	 * swapping that may be necessary to flip the "guidinfo" fields
	 */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*guidinfo))
	bcopy((void *)((uintptr_t)mbox_info.mbi_out->mb_addr +
	    TAVOR_CMD_MADDATA_OFFSET), guidinfo, size);
	TAVOR_GETGUIDINFO_SWAP(guidinfo);
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*guidinfo))

getguidinfo_fail:
	/* Free the mailbox */
	tavor_mbox_free(state, &mbox_info);

	TAVOR_TNF_EXIT(tavor_getguidinfo_cmd_post);
	return (status);
}


/*
 * tavor_getpkeytable_cmd_post()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_getpkeytable_cmd_post(tavor_state_t *state, uint_t port,
    uint_t pkeyblock, uint_t sleepflag, sm_pkey_table_t *pkeytable)
{
	tavor_mbox_info_t	mbox_info;
	tavor_cmd_post_t	cmd;
	uint32_t		*mbox;
	uint_t			size;
	int			status, i;

	TAVOR_TNF_ENTER(tavor_getpkeytable_cmd_post);

	/* Get "In" and "Out" mailboxes for the command */
	mbox_info.mbi_alloc_flags = TAVOR_ALLOC_INMBOX | TAVOR_ALLOC_OUTMBOX;
	status = tavor_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_getpkeytable_mbox_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_getpkeytable_cmd_post);
		return (status);
	}

	/* Build the GetPkeyTable request MAD into the "In" mailbox */
	size = TAVOR_CMD_MAD_IFC_SIZE;
	mbox = (uint32_t *)mbox_info.mbi_in->mb_addr;
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[0], TAVOR_CMD_MADHDR0);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[1], TAVOR_CMD_MADHDR1);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[2], TAVOR_CMD_MADHDR2);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[3], TAVOR_CMD_MADHDR3);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[4], TAVOR_CMD_PKEYTBLE);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[5], pkeyblock);
	for (i = 6; i < (size >> 2); i++) {
		ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[i], 0);
	}

	/* Sync the mailbox for the device to read */
	tavor_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup the Tavor "MAD_IFC" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= mbox_info.mbi_out->mb_mapaddr;
	cmd.cp_inmod	= port;
	cmd.cp_opcode	= MAD_IFC;
	cmd.cp_opmod	= TAVOR_CMD_MKEY_DONTCHECK;  /* No MKey checking */
	cmd.cp_flags	= sleepflag;
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_getpkeytable_cmd_post_fail,
		    TAVOR_TNF_ERROR, "");
		goto getpkeytable_fail;
	}

	/* Sync the mailbox to read the results */
	size = sizeof (sm_pkey_table_t);
	tavor_mbox_sync(mbox_info.mbi_out, TAVOR_CMD_MADDATA_OFFSET,
	    size, DDI_DMA_SYNC_FORCPU);

	/*
	 * Copy GetPKeyTable response MAD into "pkeytable".  Do any endian
	 * swapping that may be necessary to flip the "pkeytable" fields
	 */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*pkeytable))
	bcopy((void *)((uintptr_t)mbox_info.mbi_out->mb_addr +
	    TAVOR_CMD_MADDATA_OFFSET), pkeytable, size);
	TAVOR_GETPKEYTABLE_SWAP(pkeytable);
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*pkeytable))

getpkeytable_fail:
	/* Free the mailbox */
	tavor_mbox_free(state, &mbox_info);

	TAVOR_TNF_EXIT(tavor_getpkeytable_cmd_post);
	return (status);
}


/*
 * tavor_write_mtt_cmd_post()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_write_mtt_cmd_post(tavor_state_t *state, tavor_mbox_info_t *mbox_info,
    uint_t num_mtt, uint_t sleepflag)
{
	tavor_cmd_post_t	cmd;
	uint_t			size;
	int			status;

	TAVOR_TNF_ENTER(tavor_write_mtt_cmd_post);

	/*
	 * The WRITE_MTT command is unlike the other commands we use, in that
	 * we have intentionally separated the mailbox allocation step from
	 * the rest of the command posting steps.  At this point (when this
	 * function is called) the "In" mailbox already contains all the MTT
	 * entries to be copied into the Tavor tables (starting at offset
	 * 0x10) _and_ the 64-bit address of the destination for the first
	 * MTT entry in the MTT table.
	 */

	/* Sync the mailbox for the device to read */
	size = (num_mtt << TAVOR_MTT_SIZE_SHIFT) + TAVOR_CMD_WRITEMTT_RSVD_SZ;
	tavor_mbox_sync(mbox_info->mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup and post Tavor "WRITE_MTT" command */
	cmd.cp_inparm	= mbox_info->mbi_in->mb_mapaddr;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= num_mtt;
	cmd.cp_opcode	= WRITE_MTT;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= sleepflag;
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_write_mtt_cmd_fail, TAVOR_TNF_ERROR, "");
	}

	TAVOR_TNF_EXIT(tavor_write_mtt_cmd_post);
	return (status);
}


/*
 * tavor_sync_tpt_cmd_post()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_sync_tpt_cmd_post(tavor_state_t *state, uint_t sleepflag)
{
	tavor_cmd_post_t	cmd;
	int			status;

	TAVOR_TNF_ENTER(tavor_sync_tpt_cmd_post);

	/* Setup and post the Tavor "SYNC_TPT" command */
	cmd.cp_inparm	= 0;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= 0;
	cmd.cp_opcode	= SYNC_TPT;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= sleepflag;
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_sync_tpt_cmd_post_fail, TAVOR_TNF_ERROR, "");
	}

	TAVOR_TNF_EXIT(tavor_sync_tpt_cmd_post);
	return (status);
}

/*
 * tavor_map_eq_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *    (Currently called only from attach() and/or detach() path contexts)
 */
int
tavor_map_eq_cmd_post(tavor_state_t *state, uint_t map, uint_t eqcindx,
    uint64_t eqmapmask, uint_t sleepflag)
{
	tavor_cmd_post_t	cmd;
	int			status;

	TAVOR_TNF_ENTER(tavor_map_eq_cmd_post);

	/* Setup and post Tavor "MAP_EQ" command */
	cmd.cp_inparm	= eqmapmask;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= eqcindx;
	if (map != TAVOR_CMD_MAP_EQ_EVT_MAP) {
		cmd.cp_inmod |= TAVOR_CMD_UNMAP_EQ_MASK;
	}
	cmd.cp_opcode	= MAP_EQ;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= sleepflag;
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_map_eq_cmd_post_fail, TAVOR_TNF_ERROR, "");
	}

	TAVOR_TNF_EXIT(tavor_map_eq_cmd_post);
	return (status);
}


/*
 * tavor_resize_cq_cmd_post()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_resize_cq_cmd_post(tavor_state_t *state, tavor_hw_cqc_t *cqc,
    uint_t cqcindx, uint32_t *prod_indx, uint_t sleepflag)
{
	tavor_mbox_info_t	mbox_info;
	tavor_cmd_post_t	cmd;
	uint64_t		data;
	uint_t			size;
	int			status, i;

	TAVOR_TNF_ENTER(tavor_resize_cq_cmd_post);

	/* Get an "In" mailbox for the command */
	mbox_info.mbi_alloc_flags = TAVOR_ALLOC_INMBOX;
	status = tavor_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_resize_cq_mbox_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_resize_cq_cmd_post);
		return (status);
	}

	/* Copy the Tavor "RESIZE_CQ" command into mailbox */
	size = sizeof (tavor_hw_cqc_t);
	for (i = 0; i < (size >> 3); i++) {
		data = ((uint64_t *)cqc)[i];
		ddi_put64(mbox_info.mbi_in->mb_acchdl,
		    ((uint64_t *)mbox_info.mbi_in->mb_addr + i), data);
	}

	/* Sync the mailbox for the device to read */
	tavor_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup and post Tavor "RESIZE_CQ" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= cqcindx;
	cmd.cp_opcode	= RESIZE_CQ;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= sleepflag;
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_resize_cq_cmd_post_fail, TAVOR_TNF_ERROR, "");
	}

	/*
	 * New "producer index" is returned in the upper 32 bits of
	 * command "outparam"
	 */
	*prod_indx = (cmd.cp_outparm >> 32);

	/* Free the mailbox */
	tavor_mbox_free(state, &mbox_info);

	TAVOR_TNF_EXIT(tavor_resize_cq_cmd_post);
	return (status);
}


/*
 * tavor_cmn_qp_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *
 *    This is the common function for posting all the various types of
 *    QP state transition related Tavor commands.  Since some of the
 *    commands differ from the others in the number (and type) of arguments
 *    that each require, this routine does checks based on opcode type
 *    (explained in more detail below).
 *
 * Note: This common function should be used only with the following
 *    opcodes: RTS2SQD_QP, TOERR_QP, TORST_QP, RST2INIT_QP, INIT2INIT_QP,
 *    INIT2RTR_QP, RTR2RTS_QP, RTS2RTS_QP, SQD2RTS_QP, and SQERR2RTS_QP.
 */
int
tavor_cmn_qp_cmd_post(tavor_state_t *state, uint_t opcode,
    tavor_hw_qpc_t *qp, uint_t qpindx, uint32_t opmask,
    uint_t sleepflag)
{
	tavor_mbox_info_t	mbox_info;
	tavor_cmd_post_t	cmd;
	uint64_t		data, in_mapaddr, out_mapaddr;
	uint_t			size, flags, opmod;
	int			status, i;

	TAVOR_TNF_ENTER(tavor_cmn_qp_cmd_post);

	/*
	 * Use the specified opcode type to set the appropriate parameters.
	 * Specifically, we need to set in_mapaddr, out_mapaddr, flags, and
	 * opmod (as necessary).  Setting these parameters may also require
	 * us to allocate an "In" or "Out" mailbox depending on the command
	 * type.
	 */
	if (opcode == RTS2SQD_QP) {
		/*
		 * Note: For RTS-to-SendQueueDrain state transitions we
		 * always want to request the event generation from the
		 * hardware.  Though we may not notify the consumer of the
		 * drained event, the decision to forward (or not) is made
		 * later in the SQD event handler.
		 */
		flags = TAVOR_CMD_REQ_SQD_EVENT;

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
		 * flags.  It does however, take a TAVOR_CMD_DIRECT_TO_RESET
		 * opcode modifier, which indicates that the transition to
		 * reset should happen without first moving the QP through the
		 * Error state (and, hence, without generating any unnecessary
		 * "flushed-in-error" completions).
		 */
		in_mapaddr  = 0;
		out_mapaddr = 0;
		opmod = TAVOR_CMD_DIRECT_TO_RESET | TAVOR_CMD_NO_OUTMBOX;
		flags = 0;

	} else {
		/*
		 * All the other QP state transition commands (RST2INIT_QP,
		 * INIT2INIT_QP, INIT2RTR_QP, RTR2RTS_QP, RTS2RTS_QP,
		 * SQD2RTS_QP, and SQERR2RTS_QP) require an "In" mailbox.
		 * None of these require any special flags or opcode modifiers.
		 */
		mbox_info.mbi_alloc_flags = TAVOR_ALLOC_INMBOX;
		status = tavor_mbox_alloc(state, &mbox_info, sleepflag);
		if (status != TAVOR_CMD_SUCCESS) {
			TNF_PROBE_0(tavor_cmn_qp_mbox_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_cmn_qp_cmd_post);
			return (status);
		}
		in_mapaddr  = mbox_info.mbi_in->mb_mapaddr;
		out_mapaddr = 0;
		flags = 0;
		opmod = 0;

		/* Copy the Tavor command into the "In" mailbox */
		size = sizeof (tavor_hw_qpc_t);
		for (i = 0; i < (size >> 3); i++) {
			data = ((uint64_t *)qp)[i];
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
		tavor_mbox_sync(mbox_info.mbi_in, 0, size + 8,
		    DDI_DMA_SYNC_FORDEV);
	}

	/* Setup and post Tavor QP state transition command */
	cmd.cp_inparm	= in_mapaddr;
	cmd.cp_outparm	= out_mapaddr;
	cmd.cp_inmod	= qpindx | flags;
	cmd.cp_opcode	= opcode;
	cmd.cp_opmod	= opmod;
	cmd.cp_flags	= sleepflag;
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_cmn_qp_cmd_post_fail, TAVOR_TNF_ERROR, "");
	}

	/*
	 * If we allocated a mailbox (either an "In" or an "Out") above,
	 * then free it now before returning.
	 */
	if ((opcode != RTS2SQD_QP) && (opcode != TOERR_QP) &&
	    (opcode != TORST_QP)) {
		/* Free the mailbox */
		tavor_mbox_free(state, &mbox_info);
	}

	TAVOR_TNF_EXIT(tavor_cmn_qp_cmd_post);
	return (status);
}


/*
 * tavor_cmn_query_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *
 *    This is the common function for posting all the various types of
 *    Tavor query commands.  All Tavor query commands require an "Out"
 *    mailbox to be allocated for the resulting queried data.
 *
 * Note: This common function should be used only with the following
 *    opcodes: QUERY_DEV_LIM, QUERY_FW, QUERY_DDR, QUERY_ADAPTER,
 *     QUERY_HCA, QUERY_MPT, QUERY_EQ, QUERY_CQ, and QUERY_QP.
 */
int
tavor_cmn_query_cmd_post(tavor_state_t *state, uint_t opcode,
    uint_t queryindx, void *query, uint_t size, uint_t sleepflag)
{
	tavor_mbox_info_t	mbox_info;
	tavor_cmd_post_t	cmd;
	uint64_t		data;
	uint_t			offset;
	int			status, i;

	TAVOR_TNF_ENTER(tavor_cmn_query_cmd_post);

	/* Get an "Out" mailbox for the command */
	mbox_info.mbi_alloc_flags = TAVOR_ALLOC_OUTMBOX;
	status = tavor_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_cmn_query_mbox_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_cmn_query_cmd_post);
		return (status);
	}

	/* Setup and post the Tavor query command */
	cmd.cp_inparm	= 0;
	cmd.cp_outparm	= mbox_info.mbi_out->mb_mapaddr;
	cmd.cp_inmod	= queryindx;
	cmd.cp_opcode	= opcode;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= sleepflag;
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_cmn_query_cmd_post_fail, TAVOR_TNF_ERROR, "");
		goto cmn_query_fail;
	}

	/* Sync the mailbox to read the results */
	tavor_mbox_sync(mbox_info.mbi_out, 0, size, DDI_DMA_SYNC_FORCPU);

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
	tavor_mbox_free(state, &mbox_info);

	TAVOR_TNF_EXIT(tavor_cmn_query_cmd_post);
	return (status);
}


/*
 * tavor_cmn_ownership_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *
 *    This is the common function for posting all the various types of
 *    Tavor HW/SW resource ownership commands.  Since some of the commands
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
tavor_cmn_ownership_cmd_post(tavor_state_t *state, uint_t opcode,
    void *hwrsrc, uint_t size, uint_t hwrsrcindx, uint_t sleepflag)
{
	tavor_mbox_info_t	mbox_info;
	tavor_cmd_post_t	cmd;
	uint64_t		data, in_mapaddr, out_mapaddr;
	uint_t			direction, opmod;
	int			status, i;

	TAVOR_TNF_ENTER(tavor_cmn_ownership_cmd_post);

	/*
	 * Determine the direction of the ownership transfer based on the
	 * provided opcode
	 */
	if ((opcode == HW2SW_MPT) || (opcode == HW2SW_EQ) ||
	    (opcode == HW2SW_CQ) || (opcode == HW2SW_SRQ)) {
		direction = TAVOR_CMD_RSRC_HW2SW;

	} else if ((opcode == SW2HW_MPT) || (opcode == SW2HW_EQ) ||
	    (opcode == SW2HW_CQ) || (opcode == SW2HW_SRQ)) {
		direction = TAVOR_CMD_RSRC_SW2HW;

	} else {
		TNF_PROBE_0(tavor_cmn_ownership_dir_fail,
		    TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_cmn_ownership_cmd_post);
		return (TAVOR_CMD_INVALID_STATUS);
	}

	/*
	 * If hwrsrc is NULL then we do not allocate a mailbox.  This is used
	 * in the case of memory deregister where the out mailbox is not
	 * needed.  In the case of re-register, we do use the hwrsrc.
	 *
	 * Otherwise, If ownership transfer is going from hardware to software,
	 * then allocate an "Out" mailbox.  This will be filled in later as a
	 * result of the Tavor command.
	 *
	 * And if the ownership transfer is going from software to hardware,
	 * then we need an "In" mailbox, and we need to fill it in and sync it
	 * (if necessary).  Then the mailbox can be passed to the Tavor
	 * firmware.
	 *
	 * For the HW2SW (dereg) case, we only use an out mbox if hwrsrc is !=
	 * NULL.  This implies a re-reg, and the out mbox must be used.  If
	 * hwrsrc is == NULL, then we can save some time and resources by not
	 * using an out mbox at all.  We must set opmod to TAVOR_CMD_DO_OUTMBOX
	 * and TAVOR_CMD_NO_OUTMBOX appropriately in this case.
	 *
	 * For the SW2HW (reg) case, no out mbox is possible.  We set opmod to
	 * 0 anyway, but this field is not used in this case.
	 */
	if (direction == TAVOR_CMD_RSRC_HW2SW) {
		if (hwrsrc != NULL) {
			mbox_info.mbi_alloc_flags = TAVOR_ALLOC_OUTMBOX;
			status = tavor_mbox_alloc(state, &mbox_info,
			    sleepflag);
			if (status != TAVOR_CMD_SUCCESS) {
				TNF_PROBE_0(tavor_cmn_ownership_mbox_fail,
				    TAVOR_TNF_ERROR, "");
				TAVOR_TNF_EXIT(tavor_cmn_ownership_cmd_post);
				return (status);
			}
			in_mapaddr  = 0;
			out_mapaddr = mbox_info.mbi_out->mb_mapaddr;
			opmod = TAVOR_CMD_DO_OUTMBOX;
		} else {
			in_mapaddr = 0;
			out_mapaddr = 0;
			opmod = TAVOR_CMD_NO_OUTMBOX;
		}
	} else {  /* TAVOR_CMD_RSRC_SW2HW */
		mbox_info.mbi_alloc_flags = TAVOR_ALLOC_INMBOX;
		status = tavor_mbox_alloc(state, &mbox_info, sleepflag);
		if (status != TAVOR_CMD_SUCCESS) {
			TNF_PROBE_0(tavor_cmn_ownership_mbox_fail,
			    TAVOR_TNF_ERROR, "");
			TAVOR_TNF_EXIT(tavor_sw2hw_mpt_cmd_post);
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
		tavor_mbox_sync(mbox_info.mbi_in, 0, size,
		    DDI_DMA_SYNC_FORDEV);

		in_mapaddr  = mbox_info.mbi_in->mb_mapaddr;
		out_mapaddr = 0;
		opmod = 0;
	}


	/* Setup and post the Tavor ownership command */
	cmd.cp_inparm	= in_mapaddr;
	cmd.cp_outparm	= out_mapaddr;
	cmd.cp_inmod	= hwrsrcindx;
	cmd.cp_opcode	= opcode;
	cmd.cp_opmod	= opmod;
	cmd.cp_flags	= sleepflag;
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_cmn_ownership_cmd_post_fail,
		    TAVOR_TNF_ERROR, "");
		goto cmn_ownership_fail;
	}

	/*
	 * As mentioned above, for HW2SW ownership transfers we need to
	 * sync (if necessary) and copy out the resulting data from the
	 * "Out" mailbox" (assuming the above command was successful).
	 */
	if (direction == TAVOR_CMD_RSRC_HW2SW && hwrsrc != NULL) {
		/* Sync the mailbox to read the results */
		tavor_mbox_sync(mbox_info.mbi_out, 0, size,
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
		tavor_mbox_free(state, &mbox_info);
	}

	TAVOR_TNF_EXIT(tavor_cmn_ownership_cmd_post);
	return (status);
}


/*
 * tavor_conf_special_qp_cmd_post()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_conf_special_qp_cmd_post(tavor_state_t *state, uint_t qpindx,
    uint_t qptype, uint_t sleepflag)
{
	tavor_cmd_post_t	cmd;
	int			status;

	TAVOR_TNF_ENTER(tavor_conf_special_qp_cmd_post);

	/* Setup and post Tavor "CONF_SPECIAL_QP" command */
	cmd.cp_inparm	= 0;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= qpindx;
	cmd.cp_opcode	= CONF_SPECIAL_QP;
	cmd.cp_opmod	= qptype;
	cmd.cp_flags	= sleepflag;
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_conf_special_qp_cmd_post_fail,
		    TAVOR_TNF_ERROR, "");
	}

	TAVOR_TNF_EXIT(tavor_conf_special_qp_cmd_post);
	return (status);
}


/*
 * tavor_mgid_hash_cmd_post()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_mgid_hash_cmd_post(tavor_state_t *state, uint64_t mgid_h,
    uint64_t mgid_l, uint64_t *mgid_hash, uint_t sleepflag)
{
	tavor_mbox_info_t	mbox_info;
	tavor_cmd_post_t	cmd;
	int			status;

	TAVOR_TNF_ENTER(tavor_mgid_hash_cmd_post);

	/* Get an "In" mailbox for the command */
	mbox_info.mbi_alloc_flags = TAVOR_ALLOC_INMBOX;
	status = tavor_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_mgid_hash_mbox_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_mgid_hash_cmd_post);
		return (status);
	}

	/* Copy the Tavor "MGID_HASH" command into mailbox */
	ddi_put64(mbox_info.mbi_in->mb_acchdl,
	    ((uint64_t *)mbox_info.mbi_in->mb_addr + 0), mgid_h);
	ddi_put64(mbox_info.mbi_in->mb_acchdl,
	    ((uint64_t *)mbox_info.mbi_in->mb_addr + 1), mgid_l);

	/* Sync the mailbox for the device to read */
	tavor_mbox_sync(mbox_info.mbi_in, 0, TAVOR_CMD_MGIDHASH_SZ,
	    DDI_DMA_SYNC_FORDEV);

	/* Setup and post the Tavor "MGID_HASH" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= 0;
	cmd.cp_opcode	= MGID_HASH;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= sleepflag;
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_mgid_hash_cmd_post_fail, TAVOR_TNF_ERROR, "");
	}

	/* MGID hash value is returned in command "outparam" */
	*mgid_hash = cmd.cp_outparm;

	/* Free the mailbox */
	tavor_mbox_free(state, &mbox_info);

	TAVOR_TNF_EXIT(tavor_mgid_hash_cmd_post);
	return (status);
}


/*
 * tavor_read_mgm_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *
 * Note: It is assumed that the "mcg" parameter is actually a pointer to a
 *    "tavor_hw_mcg_t" struct and some number of "tavor_hw_mcg_qp_list_t"
 *    structs.  Combined size should be equal to result of TAVOR_MCGMEM_SZ()
 *    macro.
 */
int
tavor_read_mgm_cmd_post(tavor_state_t *state, tavor_hw_mcg_t *mcg,
    uint_t mcgindx, uint_t sleepflag)
{
	tavor_mbox_info_t	mbox_info;
	tavor_cmd_post_t	cmd;
	uint64_t		data;
	uint_t			size, hdrsz, qplistsz;
	int			status, i;

	TAVOR_TNF_ENTER(tavor_read_mgm_cmd_post);

	/* Get an "Out" mailbox for the results */
	mbox_info.mbi_alloc_flags = TAVOR_ALLOC_OUTMBOX;
	status = tavor_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_read_mgm_mbox_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_read_mgm_cmd_post);
		return (status);
	}

	/* Setup and post Tavor "READ_MGM" command */
	cmd.cp_inparm	= 0;
	cmd.cp_outparm	= mbox_info.mbi_out->mb_mapaddr;
	cmd.cp_inmod	= mcgindx;
	cmd.cp_opcode	= READ_MGM;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= sleepflag;
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_read_mgm_cmd_post_fail, TAVOR_TNF_ERROR, "");
		goto read_mgm_fail;
	}

	/* Sync the mailbox to read the results */
	size = TAVOR_MCGMEM_SZ(state);
	tavor_mbox_sync(mbox_info.mbi_out, 0, size, DDI_DMA_SYNC_FORCPU);

	/* Copy the READ_MGM command results into "mcg" */
	hdrsz = sizeof (tavor_hw_mcg_t);
	for (i = 0; i < (hdrsz >> 3); i++) {
		data = ddi_get64(mbox_info.mbi_out->mb_acchdl,
		    ((uint64_t *)mbox_info.mbi_out->mb_addr + i));
		((uint64_t *)mcg)[i] = data;
	}
	qplistsz = size - hdrsz;
	for (i = 0; i < (qplistsz >> 2); i++) {
		data = ddi_get32(mbox_info.mbi_out->mb_acchdl,
		    ((uint32_t *)mbox_info.mbi_out->mb_addr + i + 8));
		((uint32_t *)mcg)[i + 8] = data;
	}

read_mgm_fail:
	/* Free the mailbox */
	tavor_mbox_free(state, &mbox_info);

	TAVOR_TNF_EXIT(tavor_read_mgm_cmd_post);
	return (status);
}


/*
 * tavor_write_mgm_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *
 * Note: It is assumed that the "mcg" parameter is actually a pointer to a
 *    "tavor_hw_mcg_t" struct and some number of "tavor_hw_mcg_qp_list_t"
 *    structs.  Combined size should be equal to result of TAVOR_MCGMEM_SZ()
 *    macro.
 */
int
tavor_write_mgm_cmd_post(tavor_state_t *state, tavor_hw_mcg_t *mcg,
    uint_t mcgindx, uint_t sleepflag)
{
	tavor_mbox_info_t	mbox_info;
	tavor_cmd_post_t	cmd;
	uint64_t		data;
	uint_t			size, hdrsz, qplistsz;
	int			status, i;

	TAVOR_TNF_ENTER(tavor_write_mgm_cmd_post);

	/* Get an "In" mailbox for the command */
	mbox_info.mbi_alloc_flags = TAVOR_ALLOC_INMBOX;
	status = tavor_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_write_mcg_mbox_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_write_mgm_cmd_post);
		return (status);
	}

	/* Copy the Tavor "WRITE_MGM" command into mailbox */
	size  = TAVOR_MCGMEM_SZ(state);
	hdrsz = sizeof (tavor_hw_mcg_t);
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
	tavor_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup and post Tavor "WRITE_MGM" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= mcgindx;
	cmd.cp_opcode	= WRITE_MGM;
	cmd.cp_opmod	= 0;
	cmd.cp_flags	= sleepflag;
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_write_mgm_cmd_post_fail, TAVOR_TNF_ERROR, "");
	}

	/* Free the mailbox */
	tavor_mbox_free(state, &mbox_info);

	TAVOR_TNF_EXIT(tavor_write_mgm_cmd_post);
	return (status);

}


/*
 * tavor_modify_mpt_cmd_post()
 *    Context: Can be called from interrupt or base context.
 */
int
tavor_modify_mpt_cmd_post(tavor_state_t *state, tavor_hw_mpt_t *mpt,
    uint_t mptindx, uint_t flags, uint_t sleepflag)
{
	tavor_mbox_info_t	mbox_info;
	tavor_cmd_post_t	cmd;
	uint64_t		data;
	uint_t			size;
	int			status, i;

	TAVOR_TNF_ENTER(tavor_modify_mpt_cmd_post);

	/* Get an "In" mailbox for the command */
	mbox_info.mbi_alloc_flags = TAVOR_ALLOC_INMBOX;
	status = tavor_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_modify_mpt_mbox_fail, TAVOR_TNF_ERROR, "");
		TAVOR_TNF_EXIT(tavor_modify_mpt_cmd_post);
		return (status);
	}

	/* Copy the Tavor "MODIFY_MPT" command into mailbox */
	size = sizeof (tavor_hw_mpt_t);
	for (i = 0; i < (size >> 3); i++) {
		data = ((uint64_t *)mpt)[i];
		ddi_put64(mbox_info.mbi_in->mb_acchdl,
		    ((uint64_t *)mbox_info.mbi_in->mb_addr + i), data);
	}

	/* Sync the mailbox for the device to read */
	tavor_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup and post Tavor "MODIFY_MPT" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= 0;
	cmd.cp_inmod	= mptindx;
	cmd.cp_opcode	= MODIFY_MPT;
	cmd.cp_opmod	= flags;
	cmd.cp_flags	= sleepflag;
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		TNF_PROBE_0(tavor_modify_mpt_cmd_post_fail,
		    TAVOR_TNF_ERROR, "");
	}

	/* Free the mailbox */
	tavor_mbox_free(state, &mbox_info);

	TAVOR_TNF_EXIT(tavor_modify_mpt_cmd_post);
	return (status);
}

/*
 * tavor_getpefcntr_cmd_post()
 *    Context: Can be called from interrupt or base context.
 *
 * If reset is zero, read the performance counters of the specified port and
 * copy them into perfinfo.
 * If reset is non-zero reset the performance counters of the specified port.
 */
int
tavor_getperfcntr_cmd_post(tavor_state_t *state, uint_t port,
    uint_t sleepflag, tavor_hw_sm_perfcntr_t *perfinfo, int reset)
{
	tavor_mbox_info_t	mbox_info;
	tavor_cmd_post_t	cmd;
	uint64_t		data;
	uint32_t		*mbox;
	uint_t			size;
	int			status, i;

	bzero((void *)&cmd, sizeof (tavor_cmd_post_t));

	/* Get "In" and "Out" mailboxes for the command */
	mbox_info.mbi_alloc_flags = TAVOR_ALLOC_INMBOX | TAVOR_ALLOC_OUTMBOX;
	status = tavor_mbox_alloc(state, &mbox_info, sleepflag);
	if (status != TAVOR_CMD_SUCCESS) {
		return (status);
	}

	/* Build request MAD in the "In" mailbox */
	size = TAVOR_CMD_MAD_IFC_SIZE;
	mbox = (uint32_t *)mbox_info.mbi_in->mb_addr;

	if (reset) {
		ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[0],
		    TAVOR_CMD_PERF_SET);
	} else {
		ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[0],
		    TAVOR_CMD_PERF_GET);
	}
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[1], TAVOR_CMD_MADHDR1);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[2], TAVOR_CMD_MADHDR2);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[3], TAVOR_CMD_MADHDR3);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[4], TAVOR_CMD_PERFCNTRS);
	ddi_put32(mbox_info.mbi_in->mb_acchdl, &mbox[5], TAVOR_CMD_PERFATTR);

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
	tavor_mbox_sync(mbox_info.mbi_in, 0, size, DDI_DMA_SYNC_FORDEV);

	/* Setup the Hermon "MAD_IFC" command */
	cmd.cp_inparm	= mbox_info.mbi_in->mb_mapaddr;
	cmd.cp_outparm	= mbox_info.mbi_out->mb_mapaddr;
	cmd.cp_inmod	= port;
	cmd.cp_opcode	= MAD_IFC;
	/* No MKey and BKey checking */
	cmd.cp_opmod	= TAVOR_CMD_MKEY_DONTCHECK | TAVOR_CMD_BKEY_DONTCHECK;
	cmd.cp_flags	= TAVOR_CMD_NOSLEEP_SPIN; /* NO SLEEP */
	status = tavor_cmd_post(state, &cmd);
	if (status != TAVOR_CMD_SUCCESS) {
		goto getperfinfo_fail;
	}

	/* Sync the mailbox to read the results */
	size = TAVOR_CMD_MAD_IFC_SIZE;
	tavor_mbox_sync(mbox_info.mbi_out, 0, size, DDI_DMA_SYNC_FORCPU);

	if (reset == 0) {
		size = sizeof (tavor_hw_sm_perfcntr_t); /* for the copy */
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
	tavor_mbox_free(state, &mbox_info);
	return (status);
}
