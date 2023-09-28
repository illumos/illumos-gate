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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * tavor_event.c
 *    Tavor Interrupt and Event Processing Routines
 *
 *    Implements all the routines necessary for allocating, freeing, and
 *    handling all of the various event types that the Tavor hardware can
 *    generate.
 *    These routines include the main Tavor interrupt service routine
 *    (tavor_isr()) as well as all the code necessary to setup and handle
 *    events from each of the many event queues used by the Tavor device.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>

#include <sys/ib/adapters/tavor/tavor.h>

static void tavor_eq_poll(tavor_state_t *state, tavor_eqhdl_t eq);
static void tavor_eq_catastrophic(tavor_state_t *state);
static int tavor_eq_alloc(tavor_state_t *state, uint32_t log_eq_size,
    uint_t intr, tavor_eqhdl_t *eqhdl);
static int tavor_eq_free(tavor_state_t *state, tavor_eqhdl_t *eqhdl);
static int tavor_eq_handler_init(tavor_state_t *state, tavor_eqhdl_t eq,
    uint_t evt_type_mask, int (*eqfunc)(tavor_state_t *state,
    tavor_eqhdl_t eq, tavor_hw_eqe_t *eqe));
static int tavor_eq_handler_fini(tavor_state_t *state, tavor_eqhdl_t eq);
static void tavor_eqe_sync(tavor_eqhdl_t eq, tavor_hw_eqe_t *eqe, uint_t flag,
    uint_t force_sync);
static int tavor_port_state_change_handler(tavor_state_t *state,
    tavor_eqhdl_t eq, tavor_hw_eqe_t *eqe);
static int tavor_comm_estbl_handler(tavor_state_t *state,
    tavor_eqhdl_t eq, tavor_hw_eqe_t *eqe);
static int tavor_local_wq_cat_err_handler(tavor_state_t *state,
    tavor_eqhdl_t eq, tavor_hw_eqe_t *eqe);
static int tavor_invreq_local_wq_err_handler(tavor_state_t *state,
    tavor_eqhdl_t eq, tavor_hw_eqe_t *eqe);
static int tavor_local_acc_vio_wq_err_handler(tavor_state_t *state,
    tavor_eqhdl_t eq, tavor_hw_eqe_t *eqe);
static int tavor_sendq_drained_handler(tavor_state_t *state,
    tavor_eqhdl_t eq, tavor_hw_eqe_t *eqe);
static int tavor_path_mig_handler(tavor_state_t *state,
    tavor_eqhdl_t eq, tavor_hw_eqe_t *eqe);
static int tavor_path_mig_err_handler(tavor_state_t *state,
    tavor_eqhdl_t eq, tavor_hw_eqe_t *eqe);
static int tavor_srq_catastrophic_handler(tavor_state_t *state,
    tavor_eqhdl_t eq, tavor_hw_eqe_t *eqe);
static int tavor_srq_last_wqe_reached_handler(tavor_state_t *state,
    tavor_eqhdl_t eq, tavor_hw_eqe_t *eqe);
static int tavor_ecc_detection_handler(tavor_state_t *state,
    tavor_eqhdl_t eq, tavor_hw_eqe_t *eqe);
static int tavor_no_eqhandler(tavor_state_t *state, tavor_eqhdl_t eq,
    tavor_hw_eqe_t *eqe);


/*
 * tavor_eq_init_all
 *    Context: Only called from attach() path context
 */
int
tavor_eq_init_all(tavor_state_t *state)
{
	uint_t		log_eq_size, intr_num;
	uint_t		num_eq, num_eq_init, num_eq_unmap;
	int		status, i;

	/*
	 * For now, all Event Queues default to the same size (pulled from
	 * the current configuration profile) and are all assigned to the
	 * same interrupt or MSI.  In the future we may support assigning
	 * EQs to specific interrupts or MSIs XXX
	 */
	log_eq_size = state->ts_cfg_profile->cp_log_default_eq_sz;

	/*
	 * If MSI is to be used, then set intr_num to the MSI number
	 * (currently zero because we're using only one) or'd with the
	 * MSI enable flag.  Otherwise, for regular (i.e. 'legacy') interrupt,
	 * use the 'inta_pin' value returned by QUERY_ADAPTER.
	 */
	if (state->ts_intr_type_chosen == DDI_INTR_TYPE_MSI) {
		intr_num = TAVOR_EQ_MSI_ENABLE_FLAG | 0;
	} else {
		intr_num = state->ts_adapter.inta_pin;
	}

	/*
	 * Total number of supported EQs is hardcoded.  Tavor hardware
	 * supports up to 64 EQs.  We are currently using only 45 of them
	 * We will set aside the first 32 for use with Completion Queues (CQ)
	 * and reserve a few of the other 32 for each specific class of event
	 * (see below for more details).
	 */
	num_eq = TAVOR_NUM_EQ_USED;

	/*
	 * The "num_eq_unmap" variable is used in any possible failure
	 * cleanup (below) to indicate which events queues might require
	 * possible event class unmapping.
	 */
	num_eq_unmap = 0;

	/*
	 * Allocate and initialize all the Event Queues.  If any of these
	 * EQ allocations fail then jump to the end, cleanup what had been
	 * successfully initialized, and return an error.
	 */
	for (i = 0; i < num_eq; i++) {
		status = tavor_eq_alloc(state, log_eq_size, intr_num,
		    &state->ts_eqhdl[i]);
		if (status != DDI_SUCCESS) {
			num_eq_init = i;
			goto all_eq_init_fail;
		}
	}
	num_eq_init = num_eq;

	/*
	 * Setup EQ0-EQ31 for use with Completion Queues.  Note: We can
	 * cast the return value to void here because, when we use the
	 * TAVOR_EVT_NO_MASK flag, it is not possible for
	 * tavor_eq_handler_init() to return an error.
	 */
	for (i = 0; i < 32; i++) {
		(void) tavor_eq_handler_init(state, state->ts_eqhdl[i],
		    TAVOR_EVT_NO_MASK, tavor_cq_handler);
	}
	num_eq_unmap = 32;

	/*
	 * Setup EQ32 for handling Completion Queue Error Events.
	 *
	 * These events include things like CQ overflow or CQ access
	 * violation errors.  If this setup fails for any reason (which, in
	 * general, it really never should), then jump to the end, cleanup
	 * everything that has been successfully initialized, and return an
	 * error.
	 */
	status = tavor_eq_handler_init(state, state->ts_eqhdl[32],
	    TAVOR_EVT_MSK_CQ_ERRORS, tavor_cq_err_handler);
	if (status != DDI_SUCCESS) {
		goto all_eq_init_fail;
	}
	num_eq_unmap = 33;

	/*
	 * Setup EQ33 for handling Port State Change Events
	 *
	 * These events include things like Port Up and Port Down events.
	 * If this setup fails for any reason (which, in general, it really
	 * never should), then undo all previous EQ mapping, jump to the end,
	 * cleanup everything that has been successfully initialized, and
	 * return an error.
	 */
	status = tavor_eq_handler_init(state, state->ts_eqhdl[33],
	    TAVOR_EVT_MSK_PORT_STATE_CHANGE, tavor_port_state_change_handler);
	if (status != DDI_SUCCESS) {
		goto all_eq_init_fail;
	}
	num_eq_unmap = 34;

	/*
	 * Setup EQ34 for handling Communication Established Events
	 *
	 * These events correspond to the IB affiliated asynchronous events
	 * that are used for connection management.  If this setup fails for
	 * any reason (which, in general, it really never should), then undo
	 * all previous EQ mapping, jump to the end, cleanup everything that
	 * has been successfully initialized, and return an error.
	 */
	status = tavor_eq_handler_init(state, state->ts_eqhdl[34],
	    TAVOR_EVT_MSK_COMM_ESTABLISHED, tavor_comm_estbl_handler);
	if (status != DDI_SUCCESS) {
		goto all_eq_init_fail;
	}
	num_eq_unmap = 35;

	/*
	 * Setup EQ35 for handling Command Completion Events
	 *
	 * These events correspond to the Tavor generated events that are used
	 * to indicate Tavor firmware command completion.  These events are
	 * only generated when Tavor firmware commands are posted using the
	 * asynchronous completion mechanism.  If this setup fails for any
	 * reason (which, in general, it really never should), then undo all
	 * previous EQ mapping, jump to the end, cleanup everything that has
	 * been successfully initialized, and return an error.
	 */
	status = tavor_eq_handler_init(state, state->ts_eqhdl[35],
	    TAVOR_EVT_MSK_COMMAND_INTF_COMP, tavor_cmd_complete_handler);
	if (status != DDI_SUCCESS) {
		goto all_eq_init_fail;
	}
	num_eq_unmap = 36;

	/*
	 * Setup EQ36 for handling Local WQ Catastrophic Error Events
	 *
	 * These events correspond to the similarly-named IB affiliated
	 * asynchronous error type.  If this setup fails for any reason
	 * (which, in general, it really never should), then undo all previous
	 * EQ mapping, jump to the end, cleanup everything that has been
	 * successfully initialized, and return an error.
	 */
	status = tavor_eq_handler_init(state, state->ts_eqhdl[36],
	    TAVOR_EVT_MSK_LOCAL_WQ_CAT_ERROR, tavor_local_wq_cat_err_handler);
	if (status != DDI_SUCCESS) {
		goto all_eq_init_fail;
	}
	num_eq_unmap = 37;

	/*
	 * Setup EQ37 for handling Invalid Req Local WQ Error Events
	 *
	 * These events also correspond to the similarly-named IB affiliated
	 * asynchronous error type.  If this setup fails for any reason
	 * (which, in general, it really never should), then undo all previous
	 * EQ mapping, jump to the end, cleanup everything that has been
	 * successfully initialized, and return an error.
	 */
	status = tavor_eq_handler_init(state, state->ts_eqhdl[37],
	    TAVOR_EVT_MSK_INV_REQ_LOCAL_WQ_ERROR,
	    tavor_invreq_local_wq_err_handler);
	if (status != DDI_SUCCESS) {
		goto all_eq_init_fail;
	}
	num_eq_unmap = 38;

	/*
	 * Setup EQ38 for handling Local Access Violation WQ Error Events
	 *
	 * These events also correspond to the similarly-named IB affiliated
	 * asynchronous error type.  If this setup fails for any reason
	 * (which, in general, it really never should), then undo all previous
	 * EQ mapping, jump to the end, cleanup everything that has been
	 * successfully initialized, and return an error.
	 */
	status = tavor_eq_handler_init(state, state->ts_eqhdl[38],
	    TAVOR_EVT_MSK_LOCAL_ACC_VIO_WQ_ERROR,
	    tavor_local_acc_vio_wq_err_handler);
	if (status != DDI_SUCCESS) {
		goto all_eq_init_fail;
	}
	num_eq_unmap = 39;

	/*
	 * Setup EQ39 for handling Send Queue Drained Events
	 *
	 * These events correspond to the IB affiliated asynchronous events
	 * that are used to indicate completion of a Send Queue Drained QP
	 * state transition.  If this setup fails for any reason (which, in
	 * general, it really never should), then undo all previous EQ
	 * mapping, jump to the end, cleanup everything that has been
	 * successfully initialized, and return an error.
	 */
	status = tavor_eq_handler_init(state, state->ts_eqhdl[39],
	    TAVOR_EVT_MSK_SEND_QUEUE_DRAINED, tavor_sendq_drained_handler);
	if (status != DDI_SUCCESS) {
		goto all_eq_init_fail;
	}
	num_eq_unmap = 40;

	/*
	 * Setup EQ40 for handling Path Migration Succeeded Events
	 *
	 * These events correspond to the IB affiliated asynchronous events
	 * that are used to indicate successful completion of a path
	 * migration.  If this setup fails for any reason (which, in general,
	 * it really never should), then undo all previous EQ mapping, jump
	 * to the end, cleanup everything that has been successfully
	 * initialized, and return an error.
	 */
	status = tavor_eq_handler_init(state, state->ts_eqhdl[40],
	    TAVOR_EVT_MSK_PATH_MIGRATED, tavor_path_mig_handler);
	if (status != DDI_SUCCESS) {
		goto all_eq_init_fail;
	}
	num_eq_unmap = 41;

	/*
	 * Setup EQ41 for handling Path Migration Failed Events
	 *
	 * These events correspond to the IB affiliated asynchronous events
	 * that are used to indicate that path migration was not successful.
	 * If this setup fails for any reason (which, in general, it really
	 * never should), then undo all previous EQ mapping, jump to the end,
	 * cleanup everything that has been successfully initialized, and
	 * return an error.
	 */
	status = tavor_eq_handler_init(state, state->ts_eqhdl[41],
	    TAVOR_EVT_MSK_PATH_MIGRATE_FAILED, tavor_path_mig_err_handler);
	if (status != DDI_SUCCESS) {
		goto all_eq_init_fail;
	}
	num_eq_unmap = 42;

	/*
	 * Setup EQ42 for handling Local Catastrophic Error Events
	 *
	 * These events correspond to the similarly-named IB unaffiliated
	 * asynchronous error type.  If this setup fails for any reason
	 * (which, in general, it really never should), then undo all previous
	 * EQ mapping, jump to the end, cleanup everything that has been
	 * successfully initialized, and return an error.
	 *
	 * This error is unique, in that an EQE is not generated if this event
	 * occurs.  Instead, an interrupt is called and we must poll the
	 * Catastrophic Error buffer in CR-Space.  This mapping is setup simply
	 * to enable this error reporting.  We pass in a NULL handler since it
	 * will never be called.
	 */
	status = tavor_eq_handler_init(state, state->ts_eqhdl[42],
	    TAVOR_EVT_MSK_LOCAL_CAT_ERROR, NULL);
	if (status != DDI_SUCCESS) {
		goto all_eq_init_fail;
	}
	num_eq_unmap = 43;

	/*
	 * Setup EQ43 for handling SRQ Catastrophic Error Events
	 *
	 * These events correspond to the similarly-named IB affiliated
	 * asynchronous error type.  If this setup fails for any reason
	 * (which, in general, it really never should), then undo all previous
	 * EQ mapping, jump to the end, cleanup everything that has been
	 * successfully initialized, and return an error.
	 */
	status = tavor_eq_handler_init(state, state->ts_eqhdl[43],
	    TAVOR_EVT_MSK_SRQ_CATASTROPHIC_ERROR,
	    tavor_srq_catastrophic_handler);
	if (status != DDI_SUCCESS) {
		goto all_eq_init_fail;
	}
	num_eq_unmap = 44;

	/*
	 * Setup EQ44 for handling SRQ Last WQE Reached Events
	 *
	 * These events correspond to the similarly-named IB affiliated
	 * asynchronous event type.  If this setup fails for any reason
	 * (which, in general, it really never should), then undo all previous
	 * EQ mapping, jump to the end, cleanup everything that has been
	 * successfully initialized, and return an error.
	 */
	status = tavor_eq_handler_init(state, state->ts_eqhdl[44],
	    TAVOR_EVT_MSK_SRQ_LAST_WQE_REACHED,
	    tavor_srq_last_wqe_reached_handler);
	if (status != DDI_SUCCESS) {
		goto all_eq_init_fail;
	}
	num_eq_unmap = 45;

	/*
	 * Setup EQ45 for handling ECC error detection events
	 *
	 * These events correspond to the similarly-named IB affiliated
	 * asynchronous event type.  If this setup fails for any reason
	 * (which, in general, it really never should), then undo all previous
	 * EQ mapping, jump to the end, cleanup everything that has been
	 * successfully initialized, and return an error.
	 */
	status = tavor_eq_handler_init(state, state->ts_eqhdl[45],
	    TAVOR_EVT_MSK_ECC_DETECTION,
	    tavor_ecc_detection_handler);
	if (status != DDI_SUCCESS) {
		goto all_eq_init_fail;
	}
	num_eq_unmap = 46;

	/*
	 * Setup EQ46 to catch all other types of events.  Specifically, we
	 * do not catch the "Local EEC Catastrophic Error Event" because we
	 * should have no EEC (the Tavor driver does not support RD).  We also
	 * choose not to handle any of the address translation page fault
	 * event types.  Since we are not doing any page fault handling (and
	 * since the Tavor firmware does not currently support any such
	 * handling), we allow these events to go to the catch-all handler.
	 */
	status = tavor_eq_handler_init(state, state->ts_eqhdl[46],
	    TAVOR_EVT_CATCHALL_MASK, tavor_no_eqhandler);
	if (status != DDI_SUCCESS) {
		goto all_eq_init_fail;
	}

	return (DDI_SUCCESS);

all_eq_init_fail:
	/* Unmap any of the partially mapped EQs from above */
	for (i = 0; i < num_eq_unmap; i++) {
		(void) tavor_eq_handler_fini(state, state->ts_eqhdl[i]);
	}

	/* Free up any of the partially allocated EQs from above */
	for (i = 0; i < num_eq_init; i++) {
		(void) tavor_eq_free(state, &state->ts_eqhdl[i]);
	}
	return (status);
}


/*
 * tavor_eq_fini_all
 *    Context: Only called from attach() and/or detach() path contexts
 */
int
tavor_eq_fini_all(tavor_state_t *state)
{
	uint_t		num_eq;
	int		status, i;

	/*
	 * Grab the total number of supported EQs again.  This is the same
	 * hardcoded value that was used above (during the event queue
	 * initialization.)
	 */
	num_eq = TAVOR_NUM_EQ_USED;

	/*
	 * For each of the event queues that we initialized and mapped
	 * earlier, attempt to unmap the events from the EQ.
	 */
	for (i = 0; i < num_eq; i++) {
		status = tavor_eq_handler_fini(state, state->ts_eqhdl[i]);
		if (status != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
	}

	/*
	 * Teardown and free up all the Event Queues that were allocated
	 * earlier.
	 */
	for (i = 0; i < num_eq; i++) {
		status = tavor_eq_free(state, &state->ts_eqhdl[i]);
		if (status != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
}


/*
 * tavor_eq_arm_all
 *    Context: Only called from attach() and/or detach() path contexts
 */
void
tavor_eq_arm_all(tavor_state_t *state)
{
	uint_t		num_eq;
	int		i;

	/*
	 * Grab the total number of supported EQs again.  This is the same
	 * hardcoded value that was used above (during the event queue
	 * initialization.)
	 */
	num_eq = TAVOR_NUM_EQ_USED;

	/*
	 * For each of the event queues that we initialized and mapped
	 * earlier, attempt to arm it for event generation.
	 */
	for (i = 0; i < num_eq; i++) {
		tavor_eq_doorbell(state, TAVOR_EQDB_REARM_EQ, i, 0);
	}
}


/*
 * tavor_isr()
 *    Context: Only called from interrupt context (and during panic)
 */
/* ARGSUSED */
uint_t
tavor_isr(caddr_t arg1, caddr_t arg2)
{
	tavor_state_t	*state;
	uint64_t	*ecr, *clr_int;
	uint64_t	ecrreg, int_mask;
	uint_t		status;
	int		i;

	/*
	 * Grab the Tavor softstate pointer from the input parameter
	 */
	state	= (tavor_state_t *)arg1;

	/*
	 * Find the pointers to the ECR and clr_INT registers
	 */
	ecr	= state->ts_cmd_regs.ecr;
	clr_int = state->ts_cmd_regs.clr_int;

	/*
	 * Read the ECR register.  Each of the 64 bits in the ECR register
	 * corresponds to an event queue.  If a bit is set, then the
	 * corresponding event queue has fired.
	 */
	ecrreg = ddi_get64(state->ts_reg_cmdhdl, ecr);

	/*
	 * As long as there are bits set (i.e. as long as there are still
	 * EQs in the "fired" state), call tavor_eq_poll() to process each
	 * fired EQ.  If no ECR bits are set, do not claim the interrupt.
	 */
	status = DDI_INTR_UNCLAIMED;
	do {
		i = 0;
		while (ecrreg != 0x0) {
			if (ecrreg & 0x1) {
				tavor_eq_poll(state, state->ts_eqhdl[i]);
				status = DDI_INTR_CLAIMED;
			}
			ecrreg = ecrreg >> 1;
			i++;
		}

		/*
		 * Clear the interrupt.  Note: Depending on the type of
		 * event (interrupt or MSI), we need to use a different
		 * mask to clear the event.  In the case of MSI, the bit
		 * to clear corresponds to the MSI number, and for legacy
		 * interrupts the bit corresponds to the value in 'inta_pin'.
		 */
		if (state->ts_intr_type_chosen == DDI_INTR_TYPE_MSI) {
			int_mask = ((uint64_t)1 << 0);
		} else {
			int_mask = ((uint64_t)1 << state->ts_adapter.inta_pin);
		}
		ddi_put64(state->ts_reg_cmdhdl, clr_int, int_mask);

		/* Reread the ECR register */
		ecrreg = ddi_get64(state->ts_reg_cmdhdl, ecr);

	} while (ecrreg != 0x0);

	return (status);
}


/*
 * tavor_eq_doorbell
 *    Context: Only called from interrupt context
 */
void
tavor_eq_doorbell(tavor_state_t *state, uint32_t eq_cmd, uint32_t eqn,
    uint32_t eq_param)
{
	uint64_t	doorbell = 0;

	/* Build the doorbell from the parameters */
	doorbell = ((uint64_t)eq_cmd << TAVOR_EQDB_CMD_SHIFT) |
	    ((uint64_t)eqn << TAVOR_EQDB_EQN_SHIFT) | eq_param;

	/* Write the doorbell to UAR */
	TAVOR_UAR_DOORBELL(state, (uint64_t *)&state->ts_uar->eq,
	    doorbell);
}

/*
 * tavor_eq_poll
 *    Context: Only called from interrupt context (and during panic)
 */
static void
tavor_eq_poll(tavor_state_t *state, tavor_eqhdl_t eq)
{
	uint64_t	*clr_ecr;
	tavor_hw_eqe_t	*eqe;
	uint64_t	ecr_mask;
	uint32_t	cons_indx, wrap_around_mask;
	int (*eqfunction)(tavor_state_t *state, tavor_eqhdl_t eq,
	    tavor_hw_eqe_t *eqe);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*eq))

	/* Find the pointer to the clr_ECR register */
	clr_ecr = state->ts_cmd_regs.clr_ecr;

	/*
	 * Check for Local Catastrophic Error If we have this kind of error,
	 * then we don't need to do anything else here, as this kind of
	 * catastrophic error is handled separately.  So we call the
	 * catastrophic handler, clear the ECR and then return.
	 */
	if (eq->eq_evttypemask == TAVOR_EVT_MSK_LOCAL_CAT_ERROR) {
		/*
		 * Call Catastrophic Error handler
		 */
		tavor_eq_catastrophic(state);

		/*
		 * Clear the ECR.  Specifically, clear the bit corresponding
		 * to the event queue just processed.
		 */
		ecr_mask = ((uint64_t)1 << eq->eq_eqnum);
		ddi_put64(state->ts_reg_cmdhdl, clr_ecr, ecr_mask);

		return;
	}

	/* Get the consumer pointer index */
	cons_indx = eq->eq_consindx;

	/*
	 * Calculate the wrap around mask.  Note: This operation only works
	 * because all Tavor event queues have power-of-2 sizes
	 */
	wrap_around_mask = (eq->eq_bufsz - 1);

	/* Calculate the pointer to the first EQ entry */
	eqe = &eq->eq_buf[cons_indx];
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*eqe))

	/*
	 * Sync the current EQE to read
	 *    We need to force a ddi_dma_sync() here (independent of how the
	 *    EQ was mapped) because it is possible for us to receive the
	 *    interrupt, do a read of the ECR, and have each of these
	 *    operations complete successfully even though the hardware's DMA
	 *    to the EQ has not yet completed.
	 */
	tavor_eqe_sync(eq, eqe, DDI_DMA_SYNC_FORCPU, TAVOR_EQ_SYNC_FORCE);

	/*
	 * Pull the handler function for this EQ from the Tavor Event Queue
	 * handle
	 */
	eqfunction = eq->eq_func;

	/*
	 * Keep pulling entries from the EQ until we find an entry owner by
	 * the hardware.  As long as there the EQE's owned by SW, process
	 * each entry by calling its handler function and updating the EQ
	 * consumer index.
	 */
	do {
		while (TAVOR_EQE_OWNER_IS_SW(eq, eqe)) {
			/*
			 * Call the EQ handler function.  But only call if we
			 * are not in polled I/O mode (i.e. not processing
			 * because of a system panic).  Note: We don't call
			 * the EQ handling functions from a system panic
			 * because we are primarily concerned only with
			 * ensuring that the event queues do not overflow (or,
			 * more specifically, the event queue associated with
			 * the CQ that is being used in the sync/dump process).
			 * Also, we don't want to make any upcalls (to the
			 * IBTF) because we can't guarantee when/if those
			 * calls would ever return.  And, if we're in panic,
			 * then we reached here through a PollCQ() call (from
			 * tavor_cq_poll()), and we need to ensure that we
			 * successfully return any work completions to the
			 * caller.
			 */
			if (ddi_in_panic() == 0) {
				eqfunction(state, eq, eqe);
			}

			/* Reset entry to hardware ownership */
			TAVOR_EQE_OWNER_SET_HW(eq, eqe);

			/* Sync the current EQE for device */
			tavor_eqe_sync(eq, eqe, DDI_DMA_SYNC_FORDEV,
			    TAVOR_EQ_SYNC_NORMAL);

			/* Increment the consumer index */
			cons_indx = (cons_indx + 1) & wrap_around_mask;

			/* Update the pointer to the next EQ entry */
			eqe = &eq->eq_buf[cons_indx];

			/* Sync the next EQE to read */
			tavor_eqe_sync(eq, eqe, DDI_DMA_SYNC_FORCPU,
			    TAVOR_EQ_SYNC_NORMAL);
		}

		/*
		 * Clear the ECR.  Specifically, clear the bit corresponding
		 * to the event queue just processed.
		 */
		ecr_mask = ((uint64_t)1 << eq->eq_eqnum);
		ddi_put64(state->ts_reg_cmdhdl, clr_ecr, ecr_mask);

		/* Write an EQ doorbell to update the consumer index */
		eq->eq_consindx = cons_indx;
		tavor_eq_doorbell(state, TAVOR_EQDB_SET_CONSINDX, eq->eq_eqnum,
		    cons_indx);

		/* Write another EQ doorbell to rearm */
		tavor_eq_doorbell(state, TAVOR_EQDB_REARM_EQ, eq->eq_eqnum, 0);

		/*
		 * NOTE: Due to the nature of Mellanox hardware, we do not have
		 * to do an explicit PIO read to ensure that the doorbell write
		 * has been flushed to the hardware.  There is state encoded in
		 * the doorbell information we write which makes this
		 * unnecessary.  We can be assured that if an event needs to be
		 * generated, the hardware will make sure that it is, solving
		 * the possible race condition.
		 */

		/* Sync the next EQE to read */
		tavor_eqe_sync(eq, eqe, DDI_DMA_SYNC_FORCPU,
		    TAVOR_EQ_SYNC_NORMAL);

	} while (TAVOR_EQE_OWNER_IS_SW(eq, eqe));
}


/*
 * tavor_eq_catastrophic
 *    Context: Only called from interrupt context (and during panic)
 */
static void
tavor_eq_catastrophic(tavor_state_t *state)
{
	ibt_async_code_t	type;
	ibc_async_event_t	event;
	uint32_t		*base_addr;
	uint32_t		buf_size;
	uint32_t		word;
	uint8_t			err_type;
	uint32_t		err_buf;
	int			i;

	bzero(&event, sizeof (ibc_async_event_t));

	base_addr = (uint32_t *)(uintptr_t)(
	    (uintptr_t)state->ts_reg_cmd_baseaddr +
	    state->ts_fw.error_buf_addr);
	buf_size = state->ts_fw.error_buf_sz;

	word = ddi_get32(state->ts_reg_cmdhdl, base_addr);

	err_type = (word & 0xFF000000) >> 24;
	type	 = IBT_ERROR_LOCAL_CATASTROPHIC;

	switch (err_type) {
	case TAVOR_CATASTROPHIC_INTERNAL_ERROR:
		cmn_err(CE_WARN, "Catastrophic Internal Error: 0x%02x",
		    err_type);

		break;

	case TAVOR_CATASTROPHIC_UPLINK_BUS_ERROR:
		cmn_err(CE_WARN, "Catastrophic Uplink Bus Error: 0x%02x",
		    err_type);

		break;

	case TAVOR_CATASTROPHIC_DDR_DATA_ERROR:
		cmn_err(CE_WARN, "Catastrophic DDR Data Error: 0x%02x",
		    err_type);

		break;

	case TAVOR_CATASTROPHIC_INTERNAL_PARITY_ERROR:
		cmn_err(CE_WARN, "Catastrophic Internal Parity Error: 0x%02x",
		    err_type);

		break;

	default:
		/* Unknown type of Catastrophic error */
		cmn_err(CE_WARN, "Catastrophic Unknown Error: 0x%02x",
		    err_type);

		break;
	}

	/*
	 * Read in the catastrophic error buffer from the hardware, printing
	 * only to the log file only
	 */
	for (i = 0; i < buf_size; i += 4) {
		base_addr = (uint32_t *)((uintptr_t)(state->ts_reg_cmd_baseaddr
		    + state->ts_fw.error_buf_addr + (i * 4)));
		err_buf = ddi_get32(state->ts_reg_cmdhdl, base_addr);
		cmn_err(CE_WARN, "catastrophic_error[%02x]: %08X", i, err_buf);
	}

	/*
	 * We also call the IBTF here to inform it of the catastrophic error.
	 * Note: Since no event information (i.e. QP handles, CQ handles,
	 * etc.) is necessary, we pass a NULL pointer instead of a pointer to
	 * an empty ibc_async_event_t struct.
	 *
	 * But we also check if "ts_ibtfpriv" is NULL.  If it is then it
	 * means that we've have either received this event before we
	 * finished attaching to the IBTF or we've received it while we
	 * are in the process of detaching.
	 */
	if (state->ts_ibtfpriv != NULL) {
		TAVOR_DO_IBTF_ASYNC_CALLB(state, type, &event);
	}
}


/*
 * tavor_eq_alloc()
 *    Context: Only called from attach() path context
 */
static int
tavor_eq_alloc(tavor_state_t *state, uint32_t log_eq_size, uint_t intr,
    tavor_eqhdl_t *eqhdl)
{
	tavor_rsrc_t		*eqc, *rsrc;
	tavor_hw_eqc_t		eqc_entry;
	tavor_eqhdl_t		eq;
	ibt_mr_attr_t		mr_attr;
	tavor_mr_options_t	op;
	tavor_pdhdl_t		pd;
	tavor_mrhdl_t		mr;
	tavor_hw_eqe_t		*buf;
	uint64_t		addr;
	uint32_t		lkey;
	uint_t			dma_xfer_mode;
	int			status, i;

	/* Use the internal protection domain (PD) for setting up EQs */
	pd = state->ts_pdhdl_internal;

	/* Increment the reference count on the protection domain (PD) */
	tavor_pd_refcnt_inc(pd);

	/*
	 * Allocate an EQ context entry.  This will be filled in with all
	 * the necessary parameters to define the Event Queue.  And then
	 * ownership will be passed to the hardware in the final step
	 * below.  If we fail here, we must undo the protection domain
	 * reference count.
	 */
	status = tavor_rsrc_alloc(state, TAVOR_EQC, 1, TAVOR_SLEEP, &eqc);
	if (status != DDI_SUCCESS) {
		goto eqalloc_fail1;
	}

	/*
	 * Allocate the software structure for tracking the event queue (i.e.
	 * the Tavor Event Queue handle).  If we fail here, we must undo the
	 * protection domain reference count and the previous resource
	 * allocation.
	 */
	status = tavor_rsrc_alloc(state, TAVOR_EQHDL, 1, TAVOR_SLEEP, &rsrc);
	if (status != DDI_SUCCESS) {
		goto eqalloc_fail2;
	}
	eq = (tavor_eqhdl_t)rsrc->tr_addr;

	/*
	 * Allocate the memory for Event Queue.  Note: Although we use the
	 * common queue allocation routine, we always specify
	 * TAVOR_QUEUE_LOCATION_NORMAL (i.e. EQ located in system memory)
	 * because it would be inefficient to have EQs located in DDR memory.
	 * This is primarily because EQs are read from (by software) more
	 * than they are written to.  Also note that, unlike Tavor QP work
	 * queues, event queues do not have the same strict alignment
	 * requirements.  It is sufficient for the EQ memory to be both
	 * aligned to and bound to addresses which are a multiple of EQE size.
	 */
	eq->eq_eqinfo.qa_size = (1 << log_eq_size) * sizeof (tavor_hw_eqe_t);
	eq->eq_eqinfo.qa_alloc_align = sizeof (tavor_hw_eqe_t);
	eq->eq_eqinfo.qa_bind_align  = sizeof (tavor_hw_eqe_t);
	eq->eq_eqinfo.qa_location = TAVOR_QUEUE_LOCATION_NORMAL;
	status = tavor_queue_alloc(state, &eq->eq_eqinfo, TAVOR_SLEEP);
	if (status != DDI_SUCCESS) {
		goto eqalloc_fail3;
	}
	buf = (tavor_hw_eqe_t *)eq->eq_eqinfo.qa_buf_aligned;

	/*
	 * Initialize each of the Event Queue Entries (EQE) by setting their
	 * ownership to hardware ("owner" bit set to HW).  This is in
	 * preparation for the final transfer of ownership (below) of the
	 * EQ context itself.
	 */
	for (i = 0; i < (1 << log_eq_size); i++) {
		TAVOR_EQE_OWNER_SET_HW(eq, &buf[i]);
	}

	/*
	 * Register the memory for the EQ.  The memory for the EQ must
	 * be registered in the Tavor TPT tables.  This gives us the LKey
	 * to specify in the EQ context below.
	 *
	 * Because we are in the attach path we use NOSLEEP here so that we
	 * SPIN in the HCR since the event queues are not setup yet, and we
	 * cannot NOSPIN at this point in time.
	 */
	mr_attr.mr_vaddr = (uint64_t)(uintptr_t)buf;
	mr_attr.mr_len	 = eq->eq_eqinfo.qa_size;
	mr_attr.mr_as	 = NULL;
	mr_attr.mr_flags = IBT_MR_NOSLEEP | IBT_MR_ENABLE_LOCAL_WRITE;
	dma_xfer_mode	 = state->ts_cfg_profile->cp_streaming_consistent;
	if (dma_xfer_mode == DDI_DMA_STREAMING) {
		mr_attr.mr_flags |= IBT_MR_NONCOHERENT;
	}
	op.mro_bind_type   = state->ts_cfg_profile->cp_iommu_bypass;
	op.mro_bind_dmahdl = eq->eq_eqinfo.qa_dmahdl;
	op.mro_bind_override_addr = 0;
	status = tavor_mr_register(state, pd, &mr_attr, &mr, &op);
	if (status != DDI_SUCCESS) {
		goto eqalloc_fail4;
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mr))
	addr = mr->mr_bindinfo.bi_addr;
	lkey = mr->mr_lkey;

	/* Determine if later ddi_dma_sync will be necessary */
	eq->eq_sync = TAVOR_EQ_IS_SYNC_REQ(state, eq->eq_eqinfo);

	/* Sync entire EQ for use by the hardware (if necessary) */
	if (eq->eq_sync) {
		(void) ddi_dma_sync(mr->mr_bindinfo.bi_dmahdl, 0,
		    eq->eq_eqinfo.qa_size, DDI_DMA_SYNC_FORDEV);
	}

	/*
	 * Fill in the EQC entry.  This is the final step before passing
	 * ownership of the EQC entry to the Tavor hardware.  We use all of
	 * the information collected/calculated above to fill in the
	 * requisite portions of the EQC.  Note:  We create all EQs in the
	 * "fired" state.  We will arm them later (after our interrupt
	 * routine had been registered.)
	 */
	bzero(&eqc_entry, sizeof (tavor_hw_eqc_t));
	eqc_entry.owner		= TAVOR_HW_OWNER;
	eqc_entry.xlat		= TAVOR_VA2PA_XLAT_ENABLED;
	eqc_entry.state		= TAVOR_EQ_FIRED;
	eqc_entry.start_addr_h	= (addr >> 32);
	eqc_entry.start_addr_l	= (addr & 0xFFFFFFFF);
	eqc_entry.log_eq_sz	= log_eq_size;
	eqc_entry.usr_page	= 0;
	eqc_entry.pd		= pd->pd_pdnum;
	eqc_entry.intr		= intr;
	eqc_entry.lkey		= lkey;

	/*
	 * Write the EQC entry to hardware.  Lastly, we pass ownership of
	 * the entry to the hardware (using the Tavor SW2HW_EQ firmware
	 * command).  Note: in general, this operation shouldn't fail.  But
	 * if it does, we have to undo everything we've done above before
	 * returning error.
	 */
	status = tavor_cmn_ownership_cmd_post(state, SW2HW_EQ, &eqc_entry,
	    sizeof (tavor_hw_eqc_t), eqc->tr_indx, TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		cmn_err(CE_CONT, "Tavor: SW2HW_EQ command failed: %08x\n",
		    status);
		goto eqalloc_fail5;
	}

	/*
	 * Fill in the rest of the Tavor Event Queue handle.  Having
	 * successfully transferred ownership of the EQC, we can update the
	 * following fields for use in further operations on the EQ.
	 */
	eq->eq_eqcrsrcp	 = eqc;
	eq->eq_rsrcp	 = rsrc;
	eq->eq_consindx	 = 0;
	eq->eq_eqnum	 = eqc->tr_indx;
	eq->eq_buf	 = buf;
	eq->eq_bufsz	 = (1 << log_eq_size);
	eq->eq_mrhdl	 = mr;
	*eqhdl		 = eq;

	return (DDI_SUCCESS);

/*
 * The following is cleanup for all possible failure cases in this routine
 */
eqalloc_fail5:
	if (tavor_mr_deregister(state, &mr, TAVOR_MR_DEREG_ALL,
	    TAVOR_NOSLEEP) != DDI_SUCCESS) {
		TAVOR_WARNING(state, "failed to deregister EQ memory");
	}
eqalloc_fail4:
	tavor_queue_free(state, &eq->eq_eqinfo);
eqalloc_fail3:
	tavor_rsrc_free(state, &rsrc);
eqalloc_fail2:
	tavor_rsrc_free(state, &eqc);
eqalloc_fail1:
	tavor_pd_refcnt_dec(pd);
	return (status);
}


/*
 * tavor_eq_free()
 *    Context: Only called from attach() and/or detach() path contexts
 */
static int
tavor_eq_free(tavor_state_t *state, tavor_eqhdl_t *eqhdl)
{
	tavor_rsrc_t		*eqc, *rsrc;
	tavor_hw_eqc_t		eqc_entry;
	tavor_pdhdl_t		pd;
	tavor_mrhdl_t		mr;
	tavor_eqhdl_t		eq;
	uint32_t		eqnum;
	int			status;

	/*
	 * Pull all the necessary information from the Tavor Event Queue
	 * handle.  This is necessary here because the resource for the
	 * EQ handle is going to be freed up as part of this operation.
	 */
	eq	= *eqhdl;
	eqc	= eq->eq_eqcrsrcp;
	rsrc	= eq->eq_rsrcp;
	pd	= state->ts_pdhdl_internal;
	mr	= eq->eq_mrhdl;
	eqnum	= eq->eq_eqnum;

	/*
	 * Reclaim EQC entry from hardware (using the Tavor HW2SW_EQ
	 * firmware command).  If the ownership transfer fails for any reason,
	 * then it is an indication that something (either in HW or SW) has
	 * gone seriously wrong.
	 */
	status = tavor_cmn_ownership_cmd_post(state, HW2SW_EQ, &eqc_entry,
	    sizeof (tavor_hw_eqc_t), eqnum, TAVOR_CMD_NOSLEEP_SPIN);
	if (status != TAVOR_CMD_SUCCESS) {
		TAVOR_WARNING(state, "failed to reclaim EQC ownership");
		cmn_err(CE_CONT, "Tavor: HW2SW_EQ command failed: %08x\n",
		    status);
		return (DDI_FAILURE);
	}

	/*
	 * Deregister the memory for the Event Queue.  If this fails
	 * for any reason, then it is an indication that something (either
	 * in HW or SW) has gone seriously wrong.  So we print a warning
	 * message and continue.
	 */
	status = tavor_mr_deregister(state, &mr, TAVOR_MR_DEREG_ALL,
	    TAVOR_NOSLEEP);
	if (status != DDI_SUCCESS) {
		TAVOR_WARNING(state, "failed to deregister EQ memory");
	}

	/* Free the memory for the EQ */
	tavor_queue_free(state, &eq->eq_eqinfo);

	/* Free the Tavor Event Queue handle */
	tavor_rsrc_free(state, &rsrc);

	/* Free up the EQC entry resource */
	tavor_rsrc_free(state, &eqc);

	/* Decrement the reference count on the protection domain (PD) */
	tavor_pd_refcnt_dec(pd);

	/* Set the eqhdl pointer to NULL and return success */
	*eqhdl = NULL;

	return (DDI_SUCCESS);
}


/*
 * tavor_eq_handler_init
 *    Context: Only called from attach() path context
 */
static int
tavor_eq_handler_init(tavor_state_t *state, tavor_eqhdl_t eq,
    uint_t evt_type_mask, int (*eq_func)(tavor_state_t *state,
    tavor_eqhdl_t eq, tavor_hw_eqe_t *eqe))
{
	int		status;

	/*
	 * Save away the EQ handler function and the event type mask.  These
	 * will be used later during interrupt and event queue processing.
	 */
	eq->eq_func	   = eq_func;
	eq->eq_evttypemask = evt_type_mask;

	/*
	 * Map the EQ to a specific class of event (or events) depending
	 * on the mask value passed in.  The TAVOR_EVT_NO_MASK means not
	 * to attempt associating the EQ with any specific class of event.
	 * This is particularly useful when initializing the events queues
	 * used for CQ events.   The mapping is done using the Tavor MAP_EQ
	 * firmware command.  Note: This command should not, in general, fail.
	 * If it does, then something (probably HW related) has gone seriously
	 * wrong.
	 */
	if (evt_type_mask != TAVOR_EVT_NO_MASK) {
		status = tavor_map_eq_cmd_post(state,
		    TAVOR_CMD_MAP_EQ_EVT_MAP, eq->eq_eqnum, evt_type_mask,
		    TAVOR_CMD_NOSLEEP_SPIN);
		if (status != TAVOR_CMD_SUCCESS) {
			cmn_err(CE_CONT, "Tavor: MAP_EQ command failed: "
			    "%08x\n", status);
			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
}


/*
 * tavor_eq_handler_fini
 *    Context: Only called from attach() and/or detach() path contexts
 */
static int
tavor_eq_handler_fini(tavor_state_t *state, tavor_eqhdl_t eq)
{
	int			status;

	/*
	 * Unmap the EQ from the event class to which it had been previously
	 * mapped.  The unmapping is done using the Tavor MAP_EQ (in much
	 * the same way that the initial mapping was done).  The difference,
	 * however, is in the TAVOR_EQ_EVT_UNMAP flag that is passed to the
	 * MAP_EQ firmware command.  The TAVOR_EVT_NO_MASK (which may have
	 * been passed in at init time) still means that no association has
	 * been made between the EQ and any specific class of event (and,
	 * hence, no unmapping is necessary).  Note: This command should not,
	 * in general, fail.  If it does, then something (probably HW related)
	 * has gone seriously wrong.
	 */
	if (eq->eq_evttypemask != TAVOR_EVT_NO_MASK) {
		status = tavor_map_eq_cmd_post(state,
		    TAVOR_CMD_MAP_EQ_EVT_UNMAP, eq->eq_eqnum,
		    eq->eq_evttypemask, TAVOR_CMD_NOSLEEP_SPIN);
		if (status != TAVOR_CMD_SUCCESS) {
			cmn_err(CE_CONT, "Tavor: MAP_EQ command failed: "
			    "%08x\n", status);
			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
}


/*
 * tavor_eqe_sync()
 *    Context: Can be called from interrupt or base context.
 *
 *    Typically, this routine does nothing unless the EQ memory is
 *    mapped as DDI_DMA_STREAMING.  However, there is a condition where
 *    ddi_dma_sync() is necessary even if the memory was mapped in
 *    consistent mode.  The "force_sync" parameter is used here to force
 *    the call to ddi_dma_sync() independent of how the EQ memory was
 *    mapped.
 */
static void
tavor_eqe_sync(tavor_eqhdl_t eq, tavor_hw_eqe_t *eqe, uint_t flag,
    uint_t force_sync)
{
	ddi_dma_handle_t	dmahdl;
	off_t			offset;

	/* Determine if EQ needs to be synced or not */
	if ((eq->eq_sync == 0) && (force_sync == TAVOR_EQ_SYNC_NORMAL)) {
		return;
	}

	/* Get the DMA handle from EQ context */
	dmahdl = eq->eq_mrhdl->mr_bindinfo.bi_dmahdl;

	/* Calculate offset of next EQE */
	offset = (off_t)((uintptr_t)eqe - (uintptr_t)&eq->eq_buf[0]);
	(void) ddi_dma_sync(dmahdl, offset, sizeof (tavor_hw_eqe_t), flag);
}


/*
 * tavor_port_state_change_handler()
 *    Context: Only called from interrupt context
 */
static int
tavor_port_state_change_handler(tavor_state_t *state, tavor_eqhdl_t eq,
    tavor_hw_eqe_t *eqe)
{
	ibc_async_event_t	event;
	ibt_async_code_t	type;
	uint_t			port, subtype;
	uint_t			eqe_evttype;
	char			link_msg[24];

	eqe_evttype = TAVOR_EQE_EVTTYPE_GET(eq, eqe);

	ASSERT(eqe_evttype == TAVOR_EVT_PORT_STATE_CHANGE ||
	    eqe_evttype == TAVOR_EVT_EQ_OVERFLOW);

	if (eqe_evttype == TAVOR_EVT_EQ_OVERFLOW) {
		tavor_eq_overflow_handler(state, eq, eqe);

		return (DDI_FAILURE);
	}

	/*
	 * Depending on the type of Port State Change event, pass the
	 * appropriate asynch event to the IBTF.
	 */
	port = TAVOR_EQE_PORTNUM_GET(eq, eqe);

	/* Check for valid port number in event */
	if ((port == 0) || (port > state->ts_cfg_profile->cp_num_ports)) {
		TAVOR_WARNING(state, "Unexpected port number in port state "
		    "change event");
		cmn_err(CE_CONT, "  Port number: %02x\n", port);
		return (DDI_FAILURE);
	}

	subtype = TAVOR_EQE_EVTSUBTYPE_GET(eq, eqe);
	if (subtype == TAVOR_PORT_LINK_ACTIVE) {
		event.ev_port 	= port;
		type		= IBT_EVENT_PORT_UP;

		(void) snprintf(link_msg, 23, "port %d up", port);
		ddi_dev_report_fault(state->ts_dip, DDI_SERVICE_RESTORED,
		    DDI_EXTERNAL_FAULT, link_msg);
	} else if (subtype == TAVOR_PORT_LINK_DOWN) {
		event.ev_port	= port;
		type		= IBT_ERROR_PORT_DOWN;

		(void) snprintf(link_msg, 23, "port %d down", port);
		ddi_dev_report_fault(state->ts_dip, DDI_SERVICE_LOST,
		    DDI_EXTERNAL_FAULT, link_msg);
	} else {
		TAVOR_WARNING(state, "Unexpected subtype in port state change "
		    "event");
		cmn_err(CE_CONT, "  Event type: %02x, subtype: %02x\n",
		    TAVOR_EQE_EVTTYPE_GET(eq, eqe), subtype);
		return (DDI_FAILURE);
	}

	/*
	 * Deliver the event to the IBTF.  Note: If "ts_ibtfpriv" is NULL,
	 * then we have either received this event before we finished
	 * attaching to the IBTF or we've received it while we are in the
	 * process of detaching.
	 */
	if (state->ts_ibtfpriv != NULL) {
		TAVOR_DO_IBTF_ASYNC_CALLB(state, type, &event);
	}

	return (DDI_SUCCESS);
}


/*
 * tavor_comm_estbl_handler()
 *    Context: Only called from interrupt context
 */
static int
tavor_comm_estbl_handler(tavor_state_t *state, tavor_eqhdl_t eq,
    tavor_hw_eqe_t *eqe)
{
	tavor_qphdl_t		qp;
	uint_t			qpnum;
	ibc_async_event_t	event;
	ibt_async_code_t	type;
	uint_t			eqe_evttype;

	eqe_evttype = TAVOR_EQE_EVTTYPE_GET(eq, eqe);

	ASSERT(eqe_evttype == TAVOR_EVT_COMM_ESTABLISHED ||
	    eqe_evttype == TAVOR_EVT_EQ_OVERFLOW);

	if (eqe_evttype == TAVOR_EVT_EQ_OVERFLOW) {
		tavor_eq_overflow_handler(state, eq, eqe);

		return (DDI_FAILURE);
	}

	/* Get the QP handle from QP number in event descriptor */
	qpnum = TAVOR_EQE_QPNUM_GET(eq, eqe);
	qp = tavor_qphdl_from_qpnum(state, qpnum);

	/*
	 * If the QP handle is NULL, this is probably an indication
	 * that the QP has been freed already.  In which case, we
	 * should not deliver this event.
	 *
	 * We also check that the QP number in the handle is the
	 * same as the QP number in the event queue entry.  This
	 * extra check allows us to handle the case where a QP was
	 * freed and then allocated again in the time it took to
	 * handle the event queue processing.  By constantly incrementing
	 * the non-constrained portion of the QP number every time
	 * a new QP is allocated, we mitigate (somewhat) the chance
	 * that a stale event could be passed to the client's QP
	 * handler.
	 *
	 * Lastly, we check if "ts_ibtfpriv" is NULL.  If it is then it
	 * means that we've have either received this event before we
	 * finished attaching to the IBTF or we've received it while we
	 * are in the process of detaching.
	 */
	if ((qp != NULL) && (qp->qp_qpnum == qpnum) &&
	    (state->ts_ibtfpriv != NULL)) {
		event.ev_qp_hdl = (ibtl_qp_hdl_t)qp->qp_hdlrarg;
		type		= IBT_EVENT_COM_EST_QP;

		TAVOR_DO_IBTF_ASYNC_CALLB(state, type, &event);
	}

	return (DDI_SUCCESS);
}


/*
 * tavor_local_wq_cat_err_handler()
 *    Context: Only called from interrupt context
 */
static int
tavor_local_wq_cat_err_handler(tavor_state_t *state, tavor_eqhdl_t eq,
    tavor_hw_eqe_t *eqe)
{
	tavor_qphdl_t		qp;
	uint_t			qpnum;
	ibc_async_event_t	event;
	ibt_async_code_t	type;
	uint_t			eqe_evttype;

	eqe_evttype = TAVOR_EQE_EVTTYPE_GET(eq, eqe);

	ASSERT(eqe_evttype == TAVOR_EVT_LOCAL_WQ_CAT_ERROR ||
	    eqe_evttype == TAVOR_EVT_EQ_OVERFLOW);

	if (eqe_evttype == TAVOR_EVT_EQ_OVERFLOW) {
		tavor_eq_overflow_handler(state, eq, eqe);

		return (DDI_FAILURE);
	}

	/* Get the QP handle from QP number in event descriptor */
	qpnum = TAVOR_EQE_QPNUM_GET(eq, eqe);
	qp = tavor_qphdl_from_qpnum(state, qpnum);

	/*
	 * If the QP handle is NULL, this is probably an indication
	 * that the QP has been freed already.  In which case, we
	 * should not deliver this event.
	 *
	 * We also check that the QP number in the handle is the
	 * same as the QP number in the event queue entry.  This
	 * extra check allows us to handle the case where a QP was
	 * freed and then allocated again in the time it took to
	 * handle the event queue processing.  By constantly incrementing
	 * the non-constrained portion of the QP number every time
	 * a new QP is allocated, we mitigate (somewhat) the chance
	 * that a stale event could be passed to the client's QP
	 * handler.
	 *
	 * Lastly, we check if "ts_ibtfpriv" is NULL.  If it is then it
	 * means that we've have either received this event before we
	 * finished attaching to the IBTF or we've received it while we
	 * are in the process of detaching.
	 */
	if ((qp != NULL) && (qp->qp_qpnum == qpnum) &&
	    (state->ts_ibtfpriv != NULL)) {
		event.ev_qp_hdl = (ibtl_qp_hdl_t)qp->qp_hdlrarg;
		type		= IBT_ERROR_CATASTROPHIC_QP;

		TAVOR_DO_IBTF_ASYNC_CALLB(state, type, &event);
	}

	return (DDI_SUCCESS);
}


/*
 * tavor_invreq_local_wq_err_handler()
 *    Context: Only called from interrupt context
 */
static int
tavor_invreq_local_wq_err_handler(tavor_state_t *state, tavor_eqhdl_t eq,
    tavor_hw_eqe_t *eqe)
{
	tavor_qphdl_t		qp;
	uint_t			qpnum;
	ibc_async_event_t	event;
	ibt_async_code_t	type;
	uint_t			eqe_evttype;

	eqe_evttype = TAVOR_EQE_EVTTYPE_GET(eq, eqe);

	ASSERT(eqe_evttype == TAVOR_EVT_INV_REQ_LOCAL_WQ_ERROR ||
	    eqe_evttype == TAVOR_EVT_EQ_OVERFLOW);

	if (eqe_evttype == TAVOR_EVT_EQ_OVERFLOW) {
		tavor_eq_overflow_handler(state, eq, eqe);

		return (DDI_FAILURE);
	}

	/* Get the QP handle from QP number in event descriptor */
	qpnum = TAVOR_EQE_QPNUM_GET(eq, eqe);
	qp = tavor_qphdl_from_qpnum(state, qpnum);

	/*
	 * If the QP handle is NULL, this is probably an indication
	 * that the QP has been freed already.  In which case, we
	 * should not deliver this event.
	 *
	 * We also check that the QP number in the handle is the
	 * same as the QP number in the event queue entry.  This
	 * extra check allows us to handle the case where a QP was
	 * freed and then allocated again in the time it took to
	 * handle the event queue processing.  By constantly incrementing
	 * the non-constrained portion of the QP number every time
	 * a new QP is allocated, we mitigate (somewhat) the chance
	 * that a stale event could be passed to the client's QP
	 * handler.
	 *
	 * Lastly, we check if "ts_ibtfpriv" is NULL.  If it is then it
	 * means that we've have either received this event before we
	 * finished attaching to the IBTF or we've received it while we
	 * are in the process of detaching.
	 */
	if ((qp != NULL) && (qp->qp_qpnum == qpnum) &&
	    (state->ts_ibtfpriv != NULL)) {
		event.ev_qp_hdl = (ibtl_qp_hdl_t)qp->qp_hdlrarg;
		type		= IBT_ERROR_INVALID_REQUEST_QP;

		TAVOR_DO_IBTF_ASYNC_CALLB(state, type, &event);
	}

	return (DDI_SUCCESS);
}


/*
 * tavor_local_acc_vio_wq_err_handler()
 *    Context: Only called from interrupt context
 */
static int
tavor_local_acc_vio_wq_err_handler(tavor_state_t *state, tavor_eqhdl_t eq,
    tavor_hw_eqe_t *eqe)
{
	tavor_qphdl_t		qp;
	uint_t			qpnum;
	ibc_async_event_t	event;
	ibt_async_code_t	type;
	uint_t			eqe_evttype;

	eqe_evttype = TAVOR_EQE_EVTTYPE_GET(eq, eqe);

	ASSERT(eqe_evttype == TAVOR_EVT_LOCAL_ACC_VIO_WQ_ERROR ||
	    eqe_evttype == TAVOR_EVT_EQ_OVERFLOW);

	if (eqe_evttype == TAVOR_EVT_EQ_OVERFLOW) {
		tavor_eq_overflow_handler(state, eq, eqe);

		return (DDI_FAILURE);
	}

	/* Get the QP handle from QP number in event descriptor */
	qpnum = TAVOR_EQE_QPNUM_GET(eq, eqe);
	qp = tavor_qphdl_from_qpnum(state, qpnum);

	/*
	 * If the QP handle is NULL, this is probably an indication
	 * that the QP has been freed already.  In which case, we
	 * should not deliver this event.
	 *
	 * We also check that the QP number in the handle is the
	 * same as the QP number in the event queue entry.  This
	 * extra check allows us to handle the case where a QP was
	 * freed and then allocated again in the time it took to
	 * handle the event queue processing.  By constantly incrementing
	 * the non-constrained portion of the QP number every time
	 * a new QP is allocated, we mitigate (somewhat) the chance
	 * that a stale event could be passed to the client's QP
	 * handler.
	 *
	 * Lastly, we check if "ts_ibtfpriv" is NULL.  If it is then it
	 * means that we've have either received this event before we
	 * finished attaching to the IBTF or we've received it while we
	 * are in the process of detaching.
	 */
	if ((qp != NULL) && (qp->qp_qpnum == qpnum) &&
	    (state->ts_ibtfpriv != NULL)) {
		event.ev_qp_hdl = (ibtl_qp_hdl_t)qp->qp_hdlrarg;
		type		= IBT_ERROR_ACCESS_VIOLATION_QP;

		TAVOR_DO_IBTF_ASYNC_CALLB(state, type, &event);
	}

	return (DDI_SUCCESS);
}


/*
 * tavor_sendq_drained_handler()
 *    Context: Only called from interrupt context
 */
static int
tavor_sendq_drained_handler(tavor_state_t *state, tavor_eqhdl_t eq,
    tavor_hw_eqe_t *eqe)
{
	tavor_qphdl_t		qp;
	uint_t			qpnum;
	ibc_async_event_t	event;
	uint_t			forward_sqd_event;
	ibt_async_code_t	type;
	uint_t			eqe_evttype;

	eqe_evttype = TAVOR_EQE_EVTTYPE_GET(eq, eqe);

	ASSERT(eqe_evttype == TAVOR_EVT_SEND_QUEUE_DRAINED ||
	    eqe_evttype == TAVOR_EVT_EQ_OVERFLOW);

	if (eqe_evttype == TAVOR_EVT_EQ_OVERFLOW) {
		tavor_eq_overflow_handler(state, eq, eqe);

		return (DDI_FAILURE);
	}

	/* Get the QP handle from QP number in event descriptor */
	qpnum = TAVOR_EQE_QPNUM_GET(eq, eqe);
	qp = tavor_qphdl_from_qpnum(state, qpnum);

	/*
	 * If the QP handle is NULL, this is probably an indication
	 * that the QP has been freed already.  In which case, we
	 * should not deliver this event.
	 *
	 * We also check that the QP number in the handle is the
	 * same as the QP number in the event queue entry.  This
	 * extra check allows us to handle the case where a QP was
	 * freed and then allocated again in the time it took to
	 * handle the event queue processing.  By constantly incrementing
	 * the non-constrained portion of the QP number every time
	 * a new QP is allocated, we mitigate (somewhat) the chance
	 * that a stale event could be passed to the client's QP
	 * handler.
	 *
	 * And then we check if "ts_ibtfpriv" is NULL.  If it is then it
	 * means that we've have either received this event before we
	 * finished attaching to the IBTF or we've received it while we
	 * are in the process of detaching.
	 */
	if ((qp != NULL) && (qp->qp_qpnum == qpnum) &&
	    (state->ts_ibtfpriv != NULL)) {
		event.ev_qp_hdl = (ibtl_qp_hdl_t)qp->qp_hdlrarg;
		type		= IBT_EVENT_SQD;

		/*
		 * Grab the QP lock and update the QP state to reflect that
		 * the Send Queue Drained event has arrived.  Also determine
		 * whether the event is intended to be forwarded on to the
		 * consumer or not.  This information is used below in
		 * determining whether or not to call the IBTF.
		 */
		mutex_enter(&qp->qp_lock);
		forward_sqd_event = qp->qp_forward_sqd_event;
		qp->qp_forward_sqd_event  = 0;
		qp->qp_sqd_still_draining = 0;
		mutex_exit(&qp->qp_lock);

		if (forward_sqd_event != 0) {
			TAVOR_DO_IBTF_ASYNC_CALLB(state, type, &event);
		}
	}

	return (DDI_SUCCESS);
}


/*
 * tavor_path_mig_handler()
 *    Context: Only called from interrupt context
 */
static int
tavor_path_mig_handler(tavor_state_t *state, tavor_eqhdl_t eq,
    tavor_hw_eqe_t *eqe)
{
	tavor_qphdl_t		qp;
	uint_t			qpnum;
	ibc_async_event_t	event;
	ibt_async_code_t	type;
	uint_t			eqe_evttype;

	eqe_evttype = TAVOR_EQE_EVTTYPE_GET(eq, eqe);

	ASSERT(eqe_evttype == TAVOR_EVT_PATH_MIGRATED ||
	    eqe_evttype == TAVOR_EVT_EQ_OVERFLOW);

	if (eqe_evttype == TAVOR_EVT_EQ_OVERFLOW) {
		tavor_eq_overflow_handler(state, eq, eqe);

		return (DDI_FAILURE);
	}

	/* Get the QP handle from QP number in event descriptor */
	qpnum = TAVOR_EQE_QPNUM_GET(eq, eqe);
	qp = tavor_qphdl_from_qpnum(state, qpnum);

	/*
	 * If the QP handle is NULL, this is probably an indication
	 * that the QP has been freed already.  In which case, we
	 * should not deliver this event.
	 *
	 * We also check that the QP number in the handle is the
	 * same as the QP number in the event queue entry.  This
	 * extra check allows us to handle the case where a QP was
	 * freed and then allocated again in the time it took to
	 * handle the event queue processing.  By constantly incrementing
	 * the non-constrained portion of the QP number every time
	 * a new QP is allocated, we mitigate (somewhat) the chance
	 * that a stale event could be passed to the client's QP
	 * handler.
	 *
	 * Lastly, we check if "ts_ibtfpriv" is NULL.  If it is then it
	 * means that we've have either received this event before we
	 * finished attaching to the IBTF or we've received it while we
	 * are in the process of detaching.
	 */
	if ((qp != NULL) && (qp->qp_qpnum == qpnum) &&
	    (state->ts_ibtfpriv != NULL)) {
		event.ev_qp_hdl = (ibtl_qp_hdl_t)qp->qp_hdlrarg;
		type		= IBT_EVENT_PATH_MIGRATED_QP;

		TAVOR_DO_IBTF_ASYNC_CALLB(state, type, &event);
	}

	return (DDI_SUCCESS);
}


/*
 * tavor_path_mig_err_handler()
 *    Context: Only called from interrupt context
 */
static int
tavor_path_mig_err_handler(tavor_state_t *state, tavor_eqhdl_t eq,
    tavor_hw_eqe_t *eqe)
{
	tavor_qphdl_t		qp;
	uint_t			qpnum;
	ibc_async_event_t	event;
	ibt_async_code_t	type;
	uint_t			eqe_evttype;

	eqe_evttype = TAVOR_EQE_EVTTYPE_GET(eq, eqe);

	ASSERT(eqe_evttype == TAVOR_EVT_PATH_MIGRATE_FAILED ||
	    eqe_evttype == TAVOR_EVT_EQ_OVERFLOW);

	if (eqe_evttype == TAVOR_EVT_EQ_OVERFLOW) {
		tavor_eq_overflow_handler(state, eq, eqe);

		return (DDI_FAILURE);
	}

	/* Get the QP handle from QP number in event descriptor */
	qpnum = TAVOR_EQE_QPNUM_GET(eq, eqe);
	qp = tavor_qphdl_from_qpnum(state, qpnum);

	/*
	 * If the QP handle is NULL, this is probably an indication
	 * that the QP has been freed already.  In which case, we
	 * should not deliver this event.
	 *
	 * We also check that the QP number in the handle is the
	 * same as the QP number in the event queue entry.  This
	 * extra check allows us to handle the case where a QP was
	 * freed and then allocated again in the time it took to
	 * handle the event queue processing.  By constantly incrementing
	 * the non-constrained portion of the QP number every time
	 * a new QP is allocated, we mitigate (somewhat) the chance
	 * that a stale event could be passed to the client's QP
	 * handler.
	 *
	 * Lastly, we check if "ts_ibtfpriv" is NULL.  If it is then it
	 * means that we've have either received this event before we
	 * finished attaching to the IBTF or we've received it while we
	 * are in the process of detaching.
	 */
	if ((qp != NULL) && (qp->qp_qpnum == qpnum) &&
	    (state->ts_ibtfpriv != NULL)) {
		event.ev_qp_hdl = (ibtl_qp_hdl_t)qp->qp_hdlrarg;
		type		= IBT_ERROR_PATH_MIGRATE_REQ_QP;

		TAVOR_DO_IBTF_ASYNC_CALLB(state, type, &event);
	}

	return (DDI_SUCCESS);
}


/*
 * tavor_srq_catastrophic_handler()
 *    Context: Only called from interrupt context
 */
static int
tavor_srq_catastrophic_handler(tavor_state_t *state, tavor_eqhdl_t eq,
    tavor_hw_eqe_t *eqe)
{
	tavor_qphdl_t		qp;
	uint_t			qpnum;
	ibc_async_event_t	event;
	ibt_async_code_t	type;
	uint_t			eqe_evttype;

	eqe_evttype = TAVOR_EQE_EVTTYPE_GET(eq, eqe);

	ASSERT(eqe_evttype == TAVOR_EVT_SRQ_CATASTROPHIC_ERROR ||
	    eqe_evttype == TAVOR_EVT_EQ_OVERFLOW);

	if (eqe_evttype == TAVOR_EVT_EQ_OVERFLOW) {
		tavor_eq_overflow_handler(state, eq, eqe);

		return (DDI_FAILURE);
	}

	/* Get the QP handle from QP number in event descriptor */
	qpnum = TAVOR_EQE_QPNUM_GET(eq, eqe);
	qp = tavor_qphdl_from_qpnum(state, qpnum);

	/*
	 * If the QP handle is NULL, this is probably an indication
	 * that the QP has been freed already.  In which case, we
	 * should not deliver this event.
	 *
	 * We also check that the QP number in the handle is the
	 * same as the QP number in the event queue entry.  This
	 * extra check allows us to handle the case where a QP was
	 * freed and then allocated again in the time it took to
	 * handle the event queue processing.  By constantly incrementing
	 * the non-constrained portion of the QP number every time
	 * a new QP is allocated, we mitigate (somewhat) the chance
	 * that a stale event could be passed to the client's QP
	 * handler.
	 *
	 * Lastly, we check if "ts_ibtfpriv" is NULL.  If it is then it
	 * means that we've have either received this event before we
	 * finished attaching to the IBTF or we've received it while we
	 * are in the process of detaching.
	 */
	if ((qp != NULL) && (qp->qp_qpnum == qpnum) &&
	    (state->ts_ibtfpriv != NULL)) {
		event.ev_srq_hdl = (ibt_srq_hdl_t)qp->qp_srqhdl->srq_hdlrarg;
		type		= IBT_ERROR_CATASTROPHIC_SRQ;

		mutex_enter(&qp->qp_srqhdl->srq_lock);
		qp->qp_srqhdl->srq_state = TAVOR_SRQ_STATE_ERROR;
		mutex_exit(&qp->qp_srqhdl->srq_lock);

		TAVOR_DO_IBTF_ASYNC_CALLB(state, type, &event);
	}

	return (DDI_SUCCESS);
}


/*
 * tavor_srq_last_wqe_reached_handler()
 *    Context: Only called from interrupt context
 */
static int
tavor_srq_last_wqe_reached_handler(tavor_state_t *state, tavor_eqhdl_t eq,
    tavor_hw_eqe_t *eqe)
{
	tavor_qphdl_t		qp;
	uint_t			qpnum;
	ibc_async_event_t	event;
	ibt_async_code_t	type;
	uint_t			eqe_evttype;

	eqe_evttype = TAVOR_EQE_EVTTYPE_GET(eq, eqe);

	ASSERT(eqe_evttype == TAVOR_EVT_SRQ_LAST_WQE_REACHED ||
	    eqe_evttype == TAVOR_EVT_EQ_OVERFLOW);

	if (eqe_evttype == TAVOR_EVT_EQ_OVERFLOW) {
		tavor_eq_overflow_handler(state, eq, eqe);

		return (DDI_FAILURE);
	}

	/* Get the QP handle from QP number in event descriptor */
	qpnum = TAVOR_EQE_QPNUM_GET(eq, eqe);
	qp = tavor_qphdl_from_qpnum(state, qpnum);

	/*
	 * If the QP handle is NULL, this is probably an indication
	 * that the QP has been freed already.  In which case, we
	 * should not deliver this event.
	 *
	 * We also check that the QP number in the handle is the
	 * same as the QP number in the event queue entry.  This
	 * extra check allows us to handle the case where a QP was
	 * freed and then allocated again in the time it took to
	 * handle the event queue processing.  By constantly incrementing
	 * the non-constrained portion of the QP number every time
	 * a new QP is allocated, we mitigate (somewhat) the chance
	 * that a stale event could be passed to the client's QP
	 * handler.
	 *
	 * Lastly, we check if "ts_ibtfpriv" is NULL.  If it is then it
	 * means that we've have either received this event before we
	 * finished attaching to the IBTF or we've received it while we
	 * are in the process of detaching.
	 */
	if ((qp != NULL) && (qp->qp_qpnum == qpnum) &&
	    (state->ts_ibtfpriv != NULL)) {
		event.ev_qp_hdl = (ibtl_qp_hdl_t)qp->qp_hdlrarg;
		type		= IBT_EVENT_EMPTY_CHAN;

		TAVOR_DO_IBTF_ASYNC_CALLB(state, type, &event);
	}

	return (DDI_SUCCESS);
}


/*
 * tavor_ecc_detection_handler()
 *    Context: Only called from interrupt context
 */
static int
tavor_ecc_detection_handler(tavor_state_t *state, tavor_eqhdl_t eq,
    tavor_hw_eqe_t *eqe)
{
	uint_t			eqe_evttype;
	uint_t			data;
	int			i;

	eqe_evttype = TAVOR_EQE_EVTTYPE_GET(eq, eqe);

	ASSERT(eqe_evttype == TAVOR_EVT_ECC_DETECTION ||
	    eqe_evttype == TAVOR_EVT_EQ_OVERFLOW);

	if (eqe_evttype == TAVOR_EVT_EQ_OVERFLOW) {
		tavor_eq_overflow_handler(state, eq, eqe);

		return (DDI_FAILURE);
	}

	/*
	 * The "ECC Detection Event" indicates that a correctable single-bit
	 * has occurred with the attached DDR.  The EQE provides some
	 * additional information about the errored EQ.  So we print a warning
	 * message here along with that additional information.
	 */
	TAVOR_WARNING(state, "ECC Correctable Error Event Detected");
	for (i = 0; i < sizeof (tavor_hw_eqe_t) >> 2; i++) {
		data = ((uint_t *)eqe)[i];
		cmn_err(CE_CONT, "!  EQE[%02x]: %08x\n", i, data);
	}

	return (DDI_SUCCESS);
}


/*
 * tavor_eq_overflow_handler()
 *    Context: Only called from interrupt context
 */
void
tavor_eq_overflow_handler(tavor_state_t *state, tavor_eqhdl_t eq,
    tavor_hw_eqe_t *eqe)
{
	uint_t		error_type, data;

	ASSERT(TAVOR_EQE_EVTTYPE_GET(eq, eqe) == TAVOR_EVT_EQ_OVERFLOW);

	/*
	 * The "Event Queue Overflow Event" indicates that something has
	 * probably gone seriously wrong with some hardware (or, perhaps,
	 * with the software... though it's unlikely in this case).  The EQE
	 * provides some additional information about the errored EQ.  So we
	 * print a warning message here along with that additional information.
	 */
	error_type = TAVOR_EQE_OPERRTYPE_GET(eq, eqe);
	data	   = TAVOR_EQE_OPERRDATA_GET(eq, eqe);

	TAVOR_WARNING(state, "Event Queue overflow");
	cmn_err(CE_CONT, "  Error type: %02x, data: %08x\n", error_type, data);
}


/*
 * tavor_no_eqhandler
 *    Context: Only called from interrupt context
 */
/* ARGSUSED */
static int
tavor_no_eqhandler(tavor_state_t *state, tavor_eqhdl_t eq,
    tavor_hw_eqe_t *eqe)
{
	uint_t		data;
	int		i;

	/*
	 * This "unexpected event" handler (or "catch-all" handler) will
	 * receive all events for which no other handler has been registered.
	 * If we end up here, then something has probably gone seriously wrong
	 * with the Tavor hardware (or, perhaps, with the software... though
	 * it's unlikely in this case).  The EQE provides all the information
	 * about the event.  So we print a warning message here along with
	 * the contents of the EQE.
	 */
	TAVOR_WARNING(state, "Unexpected Event handler");
	cmn_err(CE_CONT, "  Event type: %02x, subtype: %02x\n",
	    TAVOR_EQE_EVTTYPE_GET(eq, eqe), TAVOR_EQE_EVTSUBTYPE_GET(eq, eqe));
	for (i = 0; i < sizeof (tavor_hw_eqe_t) >> 2; i++) {
		data = ((uint_t *)eqe)[i];
		cmn_err(CE_CONT, "  EQE[%02x]: %08x\n", i, data);
	}

	return (DDI_SUCCESS);
}
