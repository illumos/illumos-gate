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
 * Interface for Serengeti IOSRAM mailbox
 * OS <-> SC communication protocol
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/uadmin.h>
#include <sys/machsystm.h>
#include <sys/disp.h>
#include <sys/taskq.h>

#include <sys/sgevents.h>
#include <sys/sgsbbc_priv.h>
#include <sys/sgsbbc_iosram_priv.h>
#include <sys/sgsbbc_mailbox_priv.h>
#include <sys/plat_ecc_unum.h>
#include <sys/plat_ecc_dimm.h>
#include <sys/serengeti.h>
#include <sys/fm/util.h>
#include <sys/promif.h>
#include <sys/plat_datapath.h>

sbbc_mailbox_t	*master_mbox = NULL;

/*
 * Panic Shutdown event support
 */
static	kmutex_t	panic_hdlr_lock;

/*
 * The ID of the soft interrupt which triggers the bringing down of a Domain
 * when a PANIC_SHUTDOWN event is received.
 */
static ddi_softintr_t	panic_softintr_id = 0;

static sg_panic_shutdown_t	panic_payload;
static sbbc_msg_t		panic_payload_msg;

/*
 * A queue for making sure outgoing messages are in order as ScApp
 * does not support interleaving messages.
 */
static kcondvar_t	outbox_queue;
static kmutex_t		outbox_queue_lock;

/*
 * Handle unsolicited capability message.
 */
static plat_capability_data_t	cap_payload;
static sbbc_msg_t		cap_payload_msg;
static kmutex_t			cap_msg_hdlr_lock;

/*
 * Datapath error and fault messages arrive unsolicited.  The message data
 * is contained in a plat_datapath_info_t structure.
 */
typedef struct {
	uint8_t		type;		/* CDS, DX, CP */
	uint8_t		pad;		/* for alignment */
	uint16_t	cpuid;		/* Safari ID of base CPU */
	uint32_t	t_value;	/* SERD timeout threshold (seconds) */
} plat_datapath_info_t;

/*
 * Unsolicited datapath error messages are processed via a soft interrupt,
 * triggered in unsolicited interrupt processing.
 */
static	ddi_softintr_t		dp_softintr_id = 0;
static	kmutex_t		dp_hdlr_lock;

static	plat_datapath_info_t	dp_payload;
static	sbbc_msg_t		dp_payload_msg;

static char *dperrtype[] = {
	DP_ERROR_CDS,
	DP_ERROR_DX,
	DP_ERROR_RP
};

/*
 * Variable indicating if we are already processing requests.
 * Setting this value must be protected by outbox_queue_lock.
 */
static int		outbox_busy = 0;

/*
 * local stuff
 */
static int sbbc_mbox_send_msg(sbbc_msg_t *, int, uint_t, time_t, clock_t);
static int sbbc_mbox_recv_msg();
static int mbox_write(struct sbbc_mbox_header *,
	struct sbbc_fragment *, sbbc_msg_t *);
static int mbox_read(struct sbbc_mbox_header *, struct sbbc_fragment *,
	sbbc_msg_t *);
static int mbox_has_free_space(struct sbbc_mbox_header *);
static void mbox_skip_next_msg(struct sbbc_mbox_header *);
static int mbox_read_header(uint32_t, struct sbbc_mbox_header *);
static void mbox_update_header(uint32_t, struct sbbc_mbox_header *);
static int mbox_read_frag(struct sbbc_mbox_header *, struct sbbc_fragment *);
static struct sbbc_msg_waiter *mbox_find_waiter(uint16_t, uint32_t);
static void wakeup_next(void);
static uint_t sbbc_panic_shutdown_handler(char *arg);
static uint_t sbbc_do_fast_shutdown(char *arg);
static void sbbc_mbox_post_reg(sbbc_softstate_t *softsp);
static uint_t cap_ecc_msg_handler(char *);
static uint_t sbbc_datapath_error_msg_handler(char *arg);
static uint_t sbbc_datapath_fault_msg_handler(char *arg);
static uint_t sbbc_dp_trans_event(char *arg);


/*
 * Interrupt handlers
 */
static int sbbc_mbox_msgin(void);
static int sbbc_mbox_msgout(void);
static int sbbc_mbox_spacein(void);
static int sbbc_mbox_spaceout(void);

/*
 * ECC event mailbox message taskq and parameters
 */
static taskq_t	*sbbc_ecc_mbox_taskq = NULL;
static int	sbbc_ecc_mbox_taskq_errs = 0;
static int	sbbc_ecc_mbox_send_errs = 0;
static int	sbbc_ecc_mbox_inval_errs = 0;
static int	sbbc_ecc_mbox_other_errs = 0;
int	sbbc_ecc_mbox_err_throttle = ECC_MBOX_TASKQ_ERR_THROTTLE;

/*
 * Called when SBBC driver is loaded
 * Initialise global mailbox stuff, etc
 */
void
sbbc_mbox_init()
{
	int	i;

	master_mbox = kmem_zalloc(sizeof (sbbc_mailbox_t), KM_NOSLEEP);
	if (master_mbox == NULL) {
		cmn_err(CE_PANIC, "Can't allocate memory for mailbox\n");
	}

	/*
	 * mutex'es for the wait-lists
	 */
	for (i = 0; i < SBBC_MBOX_MSG_TYPES; i++) {
		mutex_init(&master_mbox->mbox_wait_lock[i],
			NULL, MUTEX_DEFAULT, NULL);
		master_mbox->mbox_wait_list[i] = NULL;
	}

	for (i = 0; i < SBBC_MBOX_MSG_TYPES; i++)
		master_mbox->intrs[i] = NULL;

	/*
	 * Two mailbox channels SC -> OS , read-only
	 *			OS -> SC, read/write
	 */
	master_mbox->mbox_in = kmem_zalloc(sizeof (sbbc_mbox_t), KM_NOSLEEP);
	if (master_mbox->mbox_in == NULL) {
		cmn_err(CE_PANIC,
			"Can't allocate memory for inbound mailbox\n");
	}

	master_mbox->mbox_out = kmem_zalloc(sizeof (sbbc_mbox_t), KM_NOSLEEP);
	if (master_mbox->mbox_out == NULL) {
		cmn_err(CE_PANIC,
			"Can't allocate memory for outbound mailbox\n");
	}

	mutex_init(&master_mbox->mbox_in->mb_lock, NULL,
		MUTEX_DEFAULT, NULL);
	mutex_init(&master_mbox->mbox_out->mb_lock, NULL,
		MUTEX_DEFAULT, NULL);

	/*
	 * Add PANIC_SHUTDOWN Event mutex
	 */
	mutex_init(&panic_hdlr_lock, NULL, MUTEX_DEFAULT, NULL);

	/* Initialize datapath error message handler mutex */
	mutex_init(&dp_hdlr_lock, NULL, MUTEX_DEFAULT, NULL);

	/* Initialize capability message handler event mutex */
	mutex_init(&cap_msg_hdlr_lock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * NOT USED YET
	 */
	master_mbox->mbox_in->mb_type =
		master_mbox->mbox_out->mb_type = 0;

	cv_init(&outbox_queue, NULL, CV_DEFAULT, NULL);
	mutex_init(&outbox_queue_lock, NULL, MUTEX_DEFAULT, NULL);

}

/*
 * called when the SBBC driver is unloaded
 */
void
sbbc_mbox_fini()
{
	int	i;
	int	err;

	/*
	 * destroy ECC event mailbox taskq
	 */
	if (sbbc_ecc_mbox_taskq != NULL) {
		taskq_destroy(sbbc_ecc_mbox_taskq);
		sbbc_ecc_mbox_taskq = NULL;
		sbbc_ecc_mbox_taskq_errs = 0;
	}

	/*
	 * unregister interrupts
	 */
	(void) iosram_unreg_intr(SBBC_MAILBOX_IN);
	(void) iosram_unreg_intr(SBBC_MAILBOX_IN);
	(void) iosram_unreg_intr(SBBC_MAILBOX_SPACE_IN);
	(void) iosram_unreg_intr(SBBC_MAILBOX_SPACE_OUT);

	/*
	 * Remove Panic Shutdown and Datapath Error event support.
	 *
	 * NOTE: If we have not added the soft interrupt handlers for these
	 * then we know that we have not registered the event handlers either.
	 */
	if (panic_softintr_id != 0) {
		ddi_remove_softintr(panic_softintr_id);

		err = sbbc_mbox_unreg_intr(MBOX_EVENT_PANIC_SHUTDOWN,
			sbbc_panic_shutdown_handler);
		if (err != 0) {
			cmn_err(CE_WARN, "Failed to unreg Panic Shutdown "
				"handler. Err=%d", err);
		}
	}
	if (dp_softintr_id != 0) {
		ddi_remove_softintr(dp_softintr_id);

		err = sbbc_mbox_unreg_intr(MBOX_EVENT_DP_ERROR,
			sbbc_datapath_error_msg_handler);
		err |= sbbc_mbox_unreg_intr(MBOX_EVENT_DP_FAULT,
			sbbc_datapath_fault_msg_handler);
		if (err != 0) {
			cmn_err(CE_WARN, "Failed to unreg Datapath Error "
				"handler. Err=%d", err);
		}
	}

	/*
	 * destroy all its mutex'es, lists etc
	 */

	/*
	 * mutex'es for the wait-lists
	 */
	for (i = 0; i < SBBC_MBOX_MSG_TYPES; i++) {
		mutex_destroy(&master_mbox->mbox_wait_lock[i]);
	}

	mutex_destroy(&master_mbox->mbox_in->mb_lock);
	mutex_destroy(&master_mbox->mbox_out->mb_lock);

	mutex_destroy(&panic_hdlr_lock);
	mutex_destroy(&dp_hdlr_lock);

	kmem_free(master_mbox->mbox_in, sizeof (sbbc_mbox_t));
	kmem_free(master_mbox->mbox_out, sizeof (sbbc_mbox_t));
	kmem_free(master_mbox, sizeof (sbbc_mailbox_t));

	cv_destroy(&outbox_queue);
	mutex_destroy(&outbox_queue_lock);

	err = sbbc_mbox_unreg_intr(INFO_MBOX, cap_ecc_msg_handler);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to unregister capability message "
		    "handler. Err=%d", err);
	}

	mutex_destroy(&cap_msg_hdlr_lock);
}

/*
 * Update iosram_sbbc to the new softstate after a tunnel switch.
 * Move software interrupts from the old dip to the new dip.
 */
int
sbbc_mbox_switch(sbbc_softstate_t *softsp)
{
	sbbc_intrs_t	*intr;
	int		msg_type;
	int		rc = 0;
	int		err;

	if (master_mbox == NULL)
		return (ENXIO);

	ASSERT(MUTEX_HELD(&master_iosram->iosram_lock));

	for (msg_type = 0; msg_type < SBBC_MBOX_MSG_TYPES; msg_type++) {

		for (intr = master_mbox->intrs[msg_type]; intr != NULL;
			intr = intr->sbbc_intr_next) {

			if (intr->sbbc_intr_id) {
				ddi_remove_softintr(intr->sbbc_intr_id);

				if (ddi_add_softintr(softsp->dip,
					DDI_SOFTINT_HIGH,
					&intr->sbbc_intr_id, NULL, NULL,
					intr->sbbc_handler, intr->sbbc_arg)
					!= DDI_SUCCESS) {

					cmn_err(CE_WARN,
						"Can't add SBBC mailbox "
						"softint for msg_type %x\n",
							msg_type);
					rc = ENXIO;
				}
			}
		}
	}

	/*
	 * Add PANIC_SHUTDOWN Event handler
	 */
	if (panic_softintr_id) {
		ddi_remove_softintr(panic_softintr_id);

		err = ddi_add_softintr(softsp->dip, DDI_SOFTINT_LOW,
			&panic_softintr_id, NULL, NULL,
			sbbc_do_fast_shutdown, NULL);

		if (err != DDI_SUCCESS) {
			cmn_err(CE_WARN, "Failed to register Panic "
				"Shutdown handler. Err=%d", err);
			(void) sbbc_mbox_unreg_intr(MBOX_EVENT_PANIC_SHUTDOWN,
				sbbc_panic_shutdown_handler);
			rc = ENXIO;
		}

	}
	/*
	 * Add Datapath Error Event handler
	 */
	if (dp_softintr_id) {
		ddi_remove_softintr(dp_softintr_id);

		err = ddi_add_softintr(softsp->dip, DDI_SOFTINT_LOW,
			&dp_softintr_id, NULL, NULL,
			sbbc_dp_trans_event, NULL);

		if (err != DDI_SUCCESS) {
			cmn_err(CE_WARN, "Failed to register Datapath "
				"Error Event handler. Err=%d", err);
			(void) sbbc_mbox_unreg_intr(MBOX_EVENT_DP_ERROR,
				sbbc_datapath_error_msg_handler);
			(void) sbbc_mbox_unreg_intr(MBOX_EVENT_DP_FAULT,
				sbbc_datapath_fault_msg_handler);
			rc = ENXIO;
		}

	}

	return (rc);
}

/*
 * Called when the IOSRAM tunnel is created for the 'chosen' node.
 *
 * Read the mailbox header from the IOSRAM
 * tunnel[SBBC_MAILBOX_KEY]
 * Register the mailbox interrupt handlers
 * for messages in/space etc
 */
int
sbbc_mbox_create(sbbc_softstate_t *softsp)
{
	struct sbbc_mbox_header	header;

	int	i;
	int	err;
	int	rc = 0;

	/*
	 * This function should only be called once when
	 * the chosen node is initialized.
	 */
	ASSERT(MUTEX_HELD(&chosen_lock));

	if (master_mbox == NULL)
		return (ENXIO);

	/*
	 * read the header at offset 0
	 * check magic/version etc
	 */
	if (rc = iosram_read(SBBC_MAILBOX_KEY, 0, (caddr_t)&header,
	    sizeof (struct sbbc_mbox_header))) {

		return (rc);
	}

	/*
	 * add the interrupt handlers for the mailbox
	 * interrupts
	 */
	for (i = 0; i < MBOX_INTRS; i++) {
		sbbc_intrfunc_t		intr_handler;
		uint_t 			*state;
		kmutex_t 		*lock;
		uint32_t		intr_num;

		switch (i) {
		case MBOX_MSGIN_INTR:
			intr_handler = (sbbc_intrfunc_t)sbbc_mbox_msgin;
			intr_num = SBBC_MAILBOX_IN;
			break;
		case MBOX_MSGOUT_INTR:
			intr_handler = (sbbc_intrfunc_t)sbbc_mbox_msgout;
			intr_num = SBBC_MAILBOX_OUT;
			break;
		case MBOX_SPACEIN_INTR:
			intr_handler = (sbbc_intrfunc_t)sbbc_mbox_spacein;
			intr_num = SBBC_MAILBOX_SPACE_IN;
			break;
		case MBOX_SPACEOUT_INTR:
			intr_handler = (sbbc_intrfunc_t)sbbc_mbox_spaceout;
			intr_num = SBBC_MAILBOX_SPACE_OUT;
			break;
		}
		state = (uint_t *)&master_mbox->intr_state[i].mbox_intr_state;
		lock = &master_mbox->intr_state[i].mbox_intr_lock;
		if (iosram_reg_intr(intr_num, intr_handler, (caddr_t)NULL,
			state, lock)) {

			cmn_err(CE_WARN,
				"Can't register Mailbox interrupts \n");
		}
	}

	/*
	 * Add PANIC_SHUTDOWN Event handler
	 */
	panic_payload_msg.msg_buf = (caddr_t)&panic_payload;
	panic_payload_msg.msg_len = sizeof (panic_payload);

	err = ddi_add_softintr(softsp->dip, DDI_SOFTINT_LOW, &panic_softintr_id,
		NULL, NULL, sbbc_do_fast_shutdown, NULL);

	if (err == DDI_SUCCESS) {
		err = sbbc_mbox_reg_intr(MBOX_EVENT_PANIC_SHUTDOWN,
			sbbc_panic_shutdown_handler, &panic_payload_msg,
			NULL, &panic_hdlr_lock);
		if (err != 0) {
			cmn_err(CE_WARN, "Failed to register Panic "
				"Shutdown handler. Err=%d", err);
		}

	} else {
		cmn_err(CE_WARN, "Failed to add Panic Shutdown "
			"softintr handler");
	}

	/*
	 * Add Unsolicited Datapath Error Events handler
	 */
	dp_payload_msg.msg_buf = (caddr_t)&dp_payload;
	dp_payload_msg.msg_len = sizeof (dp_payload);

	err = ddi_add_softintr(softsp->dip, DDI_SOFTINT_LOW, &dp_softintr_id,
		NULL, NULL, sbbc_dp_trans_event, NULL);

	if (err == DDI_SUCCESS) {
		err = sbbc_mbox_reg_intr(MBOX_EVENT_DP_ERROR,
			sbbc_datapath_error_msg_handler, &dp_payload_msg,
			NULL, &dp_hdlr_lock);
		err |= sbbc_mbox_reg_intr(MBOX_EVENT_DP_FAULT,
			sbbc_datapath_fault_msg_handler, &dp_payload_msg,
			NULL, &dp_hdlr_lock);
		if (err != 0) {
			cmn_err(CE_WARN, "Failed to register Datapath "
				"error handler. Err=%d", err);
		}

	} else {
		cmn_err(CE_WARN, "Failed to add Datapath error "
			"softintr handler");
	}

	/*
	 * Register an interrupt handler with the sgbbc driver for the
	 * unsolicited INFO_MBOX response for the capability bitmap.
	 * This message is expected whenever the SC is (re)booted or
	 * failed over.
	 */
	cap_payload_msg.msg_buf = (caddr_t)&cap_payload;
	cap_payload_msg.msg_len = sizeof (cap_payload);

	err = sbbc_mbox_reg_intr(INFO_MBOX, cap_ecc_msg_handler,
	    &cap_payload_msg, NULL, &cap_msg_hdlr_lock);
	if (err != 0) {
		cmn_err(CE_WARN, "Failed to register capability message"
		    " handler with Err=%d", err);
	}

	/*
	 * Now is the opportunity to register
	 * the deferred mbox intrs.
	 */
	sbbc_mbox_post_reg(softsp);

	return (rc);
}

/*
 * Called when chosen IOSRAM is initialized
 * to register the deferred mbox intrs.
 */
static void
sbbc_mbox_post_reg(sbbc_softstate_t *softsp)
{
	uint32_t msg_type;
	sbbc_intrs_t	*intr;

	ASSERT(master_mbox);
	for (msg_type = 0;  msg_type < SBBC_MBOX_MSG_TYPES; msg_type++) {
		intr = master_mbox->intrs[msg_type];
		while (intr != NULL) {
			if (!intr->registered) {
				SGSBBC_DBG_INTR(CE_CONT, "sbbc_mbox_post_reg: "
					"postreg for msgtype=%x\n", msg_type);
				if (ddi_add_softintr(softsp->dip,
					DDI_SOFTINT_HIGH, &intr->sbbc_intr_id,
					NULL, NULL, intr->sbbc_handler,
					(caddr_t)intr->sbbc_arg)
						!= DDI_SUCCESS) {
					cmn_err(CE_WARN, "Can't add SBBC "
						"deferred mailbox softint \n");
				} else
					intr->registered = 1;
			}
			intr = intr->sbbc_intr_next;
		}
	}
}

/*
 * Register a handler for a message type
 * NB NB NB
 * arg must be either NULL or the address of a sbbc_fragment
 * pointer
 */
int
sbbc_mbox_reg_intr(uint32_t msg_type, sbbc_intrfunc_t intr_handler,
		sbbc_msg_t *arg, uint_t *state, kmutex_t *lock)
{
	sbbc_intrs_t	*intr, *previntr;
	int		rc = 0;

	/*
	 * Validate arguments
	 */
	if (msg_type >= SBBC_MBOX_MSG_TYPES)
		return (EINVAL);

	/*
	 * Verify that we have already set up the master sbbc
	 */
	if (master_iosram == NULL || master_mbox == NULL)
		return (ENXIO);

	mutex_enter(&master_iosram->iosram_lock);
	msg_type &= SBBC_MSG_TYPE_MASK;
	previntr = intr = master_mbox->intrs[msg_type];

	/* Find the end of the link list */
	while (intr != NULL && intr->sbbc_handler != intr_handler) {

		previntr = intr;
		intr = intr->sbbc_intr_next;
	}

	/* Return if the handler has been registered */
	if (intr != NULL) {
		mutex_exit(&master_iosram->iosram_lock);
		return (EBUSY);
	}

	/*
	 * The requested handler has not been installed.
	 * Allocate some memory.
	 */
	intr = kmem_zalloc(sizeof (sbbc_intrs_t), KM_SLEEP);

	intr->sbbc_handler  = intr_handler;
	intr->sbbc_arg = (caddr_t)arg;
	intr->sbbc_intr_state = state;
	intr->sbbc_intr_lock = lock;
	intr->sbbc_intr_next = NULL;
	/* not registered yet */
	intr->registered = 0;

	if (previntr != NULL)
		previntr->sbbc_intr_next = intr;
	else
		master_mbox->intrs[msg_type] = intr;

	/*
	 * register only if the chosen IOSRAM is
	 * initialized, otherwise defer the registration
	 * until IOSRAM initialization.
	 */
	if (master_iosram->iosram_sbbc) {
		if (ddi_add_softintr(master_iosram->iosram_sbbc->dip,
			DDI_SOFTINT_HIGH,
			&intr->sbbc_intr_id, NULL, NULL,
			intr_handler, (caddr_t)arg) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "Can't add SBBC mailbox softint \n");
			rc = ENXIO;
		} else
			intr->registered = 1;
	} else {
		SGSBBC_DBG_INTR(CE_CONT, "sbbc_mbox_reg_intr: "
				"deferring msg=%x registration\n", msg_type);
	}

	mutex_exit(&master_iosram->iosram_lock);

	return (rc);
}

/*
 * Unregister a handler for a message type
 */
int
sbbc_mbox_unreg_intr(uint32_t msg_type, sbbc_intrfunc_t intr_handler)
{
	sbbc_intrs_t		*intr, *previntr, *nextintr;

	/*
	 * Verify that we have already set up the master sbbc
	 */
	if (master_iosram == NULL || master_mbox == NULL)
		return (ENXIO);

	msg_type &= SBBC_MSG_TYPE_MASK;

	if (msg_type >= SBBC_MBOX_MSG_TYPES ||
		intr_handler == (sbbc_intrfunc_t)NULL) {

		return (EINVAL);
	}

	mutex_enter(&master_iosram->iosram_lock);

	previntr = intr = master_mbox->intrs[msg_type];

	/*
	 * No handlers installed
	 */
	if (intr == NULL) {
		mutex_exit(&master_iosram->iosram_lock);
		return (EINVAL);
	}

	while (intr != NULL) {

		/* Save the next pointer */
		nextintr = intr->sbbc_intr_next;

		/* Found a match.  Remove it from the link list */
		if (intr->sbbc_handler == intr_handler) {

			if (intr->sbbc_intr_id)
				ddi_remove_softintr(intr->sbbc_intr_id);

			kmem_free(intr, sizeof (sbbc_intrs_t));

			if (previntr != master_mbox->intrs[msg_type])
				previntr->sbbc_intr_next = nextintr;
			else
				master_mbox->intrs[msg_type] = nextintr;

			break;
		}

		/* update pointers */
		previntr = intr;
		intr = nextintr;
	}

	mutex_exit(&master_iosram->iosram_lock);

	return (0);
}
/*
 * Interrupt handlers - one for each mailbox
 * interrupt type
 */

/*
 * mailbox message received
 */
static int
sbbc_mbox_msgin()
{
	mutex_enter(&master_mbox->intr_state[MBOX_MSGIN_INTR].mbox_intr_lock);
	master_mbox->intr_state[MBOX_MSGIN_INTR].mbox_intr_state =
		SBBC_INTR_RUNNING;
	mutex_exit(&master_mbox->intr_state[MBOX_MSGIN_INTR].mbox_intr_lock);

	/*
	 * We are only locking the InBox here, not the whole
	 * mailbox. This is based on the assumption of
	 * complete separation of mailboxes - outbox is
	 * read/write, inbox is read-only.
	 * We only ever update the producer for the
	 * outbox and the consumer for the inbox.
	 */
	mutex_enter(&master_mbox->mbox_in->mb_lock);

	for (;;) {
		/*
		 * Get as many incoming messages as possible
		 */
		while (sbbc_mbox_recv_msg() == 0)
			/* empty */;

		/*
		 * send interrupt to SC to let it know that
		 * space is available over here
		 */
		(void) iosram_send_intr(SBBC_MAILBOX_SPACE_IN);

		mutex_enter(&master_mbox->intr_state[MBOX_MSGIN_INTR].
			mbox_intr_lock);
		/*
		 * Read the inbox one more time to see if new messages
		 * has come in after we exit the loop.
		 */
		if (sbbc_mbox_recv_msg() == 0) {
			mutex_exit(&master_mbox->intr_state[MBOX_MSGIN_INTR].
				mbox_intr_lock);
		} else {
			master_mbox->intr_state[MBOX_MSGIN_INTR].
				mbox_intr_state = SBBC_INTR_IDLE;
			mutex_exit(&master_mbox->intr_state[MBOX_MSGIN_INTR].
				mbox_intr_lock);
			break;
		}
	}

	mutex_exit(&master_mbox->mbox_in->mb_lock);

	return (DDI_INTR_CLAIMED);
}

/*
 * mailbox message sent
 */
static int
sbbc_mbox_msgout()
{
	/*
	 * Should never get this
	 */

	return (DDI_INTR_CLAIMED);
}

/*
 * space in the inbox
 */
static int
sbbc_mbox_spacein()
{
	/*
	 * Should never get this
	 */

	return (DDI_INTR_CLAIMED);
}

/*
 * space in the outbox
 */
static int
sbbc_mbox_spaceout()
{
	/*
	 * cv_broadcast() the threads waiting on the
	 * outbox's mb_full
	 */

	mutex_enter(&master_mbox->mbox_out->mb_lock);

	cv_broadcast(&master_mbox->mbox_out->mb_full);

	mutex_exit(&master_mbox->mbox_out->mb_lock);

	return (DDI_INTR_CLAIMED);
}

/*
 * Client Interface
 *
 * The main interface will be
 *
 * sbbc_mbox_request_response(sbbc_msg_t *request,
 * 			sbbc_msg_t *response, time_t wait_time)
 *
 * 1) the client calls request_response
 * 2) a new unique msg ID is assigned for that msg
 * 3) if there is space available in the outbox
 *    - the request msg is written to the mbox_out mailbox
 *	and the mailbox info updated.
 *    - allocate a sbbc_msg_waiter struct for this
 *	message, initialise the w_cv condvar.
 *    - get the mailbox mbox_wait_lock mutex for this
 *      message type
 *    - the response msg is put on the mbox_wait_list for
 *	that message type to await the SC's response
 *    - wait on the w_cv condvar protected by the
 *	mbox_wait_lock
 *    - SBBC_MAILBOX_OUT interrupt is sent to the SC
 *
 * 4) if no space in the outbox,
 *    - the request message blocks waiting
 *	for a SBBC_MAILBOX_SPACE_OUT interrupt
 *      It will block on the mailbox mb_full condvar.
 *    - go to (3) above
 * 5) When we get a SBBC_MAILBOX_IN interrupt.
 *    - read the message ID of the next message (FIFO)
 *    - find that ID on the wait list
 *    - no wait list entry => unsolicited message. If theres
 *      a handler, trigger it
 *    - if someone is waiting, read the message in from
 *	SRAM, handling fragmentation, wraparound, etc
 *    - if the whole message has been read, signal
 *	the waiter
 *    - read next message until mailbox empty
 *    - send SBBC_MAILBOX_SPACE_IN interrupt to the SC
 *
 * 6) If a response is required and none is received, the client
 *	will timeout after <wait_time> seconds and the message
 *	status will be set to ETIMEDOUT.
 */
int
sbbc_mbox_request_response(sbbc_msg_t *request,
		sbbc_msg_t *response, time_t wait_time)
{

	struct sbbc_msg_waiter	*waiter;
	uint_t			msg_id;
	int			rc = 0;
	int			flags;
	uint16_t		msg_type;
	clock_t			stop_time;
	clock_t			clockleft;
	kmutex_t		*mbox_wait_lock;
	kmutex_t		*mb_lock;
	static fn_t		f = "sbbc_mbox_request_response";

	if ((request == NULL) ||
		(request->msg_type.type >= SBBC_MBOX_MSG_TYPES) ||
		((response != NULL) &&
		(response->msg_type.type >= SBBC_MBOX_MSG_TYPES)))
		return (EINVAL);

	msg_type = request->msg_type.type;

	/*
	 * Verify that we have already set up the master sbbc
	 */
	if (master_mbox == NULL)
		return (ENXIO);
	mbox_wait_lock = &master_mbox->mbox_wait_lock[msg_type];

	flags = WAIT_FOR_REPLY|WAIT_FOR_SPACE;

	/*
	 * We want to place a lower limit on the shortest amount of time we
	 * will wait before timing out while communicating with the SC via
	 * the mailbox.
	 */
	if (wait_time < sbbc_mbox_min_timeout)
		wait_time = sbbc_mbox_default_timeout;

	stop_time = ddi_get_lbolt() + wait_time * drv_usectohz(MICROSEC);

	/*
	 * If there is a message being processed, sleep until it is our turn.
	 */
	mutex_enter(&outbox_queue_lock);

	/*
	 * allocate an ID for this message, let it wrap
	 * around transparently.
	 * msg_id == 0 is unsolicited message
	 */
	msg_id = ++(master_mbox->mbox_msg_id);
	if (msg_id == 0)
		msg_id = ++(master_mbox->mbox_msg_id);

	SGSBBC_DBG_MBOX("%s: msg_id = 0x%x, msg_len = 0x%x\n",
		f, msg_id, request->msg_len);

	/*
	 * A new message can actually grab the lock before the thread
	 * that has just been signaled.  Therefore, we need to double
	 * check to make sure that outbox_busy is not already set
	 * after we wake up.
	 *
	 * Potentially this could mean starvation for certain unfortunate
	 * threads that keep getting woken up and putting back to sleep.
	 * But the window of such contention is very small to begin with.
	 */
	while (outbox_busy) {

		clockleft = cv_timedwait(&outbox_queue, &outbox_queue_lock,
			stop_time);

		SGSBBC_DBG_MBOX("%s: msg_id = 0x%x is woken up\n", f, msg_id);

		/*
		 * If we have timed out, set status to ETIMEOUT and return.
		 */
		if (clockleft < 0) {
			SGSBBC_DBG_MBOX("%s: msg_id = 0x%x has timed out\n",
				f, msg_id);
			cmn_err(CE_NOTE,
				"Timed out obtaining SBBC outbox lock");
			request->msg_status = ETIMEDOUT;
			if (response != NULL)
				response->msg_status = ETIMEDOUT;
			mutex_exit(&outbox_queue_lock);
			return (ETIMEDOUT);
		}
	}

	outbox_busy = 1;
	mutex_exit(&outbox_queue_lock);

	/*
	 * We are only locking the OutBox from here, not the whole
	 * mailbox. This is based on the assumption of
	 * complete separation of mailboxes - outbox is
	 * read/write, inbox is read-only.
	 * We only ever update the producer for the
	 * outbox and the consumer for the inbox.
	 */
	mb_lock = &master_mbox->mbox_out->mb_lock;
	mutex_enter(mb_lock);

	/*
	 * No response expected ? Just send the message and return
	 */
	if (response == NULL) {
		rc = sbbc_mbox_send_msg(request, flags, msg_id, wait_time,
			stop_time);
		SGSBBC_DBG_MBOX("%s: msg_id = 0x%x send rc = %d\n",
		    f, msg_id, rc);

		wakeup_next();

		mutex_exit(mb_lock);
		request->msg_status = rc;
		return (rc);
	}

	/*
	 * allocate/initialise a waiter
	 */
	waiter = kmem_zalloc(sizeof (struct sbbc_msg_waiter), KM_NOSLEEP);

	if (waiter == (struct sbbc_msg_waiter *)NULL) {
		cmn_err(CE_WARN, "SBBC Mailbox can't allocate waiter\n");

		wakeup_next();

		mutex_exit(mb_lock);
		return (ENOMEM);
	}

	waiter->w_id = 0;	/* Until we get an ID from the send */
	waiter->w_msg = response;
	waiter->w_msg->msg_status = EINPROGRESS;

	cv_init(&waiter->w_cv, NULL, CV_DEFAULT, NULL);

	rc = sbbc_mbox_send_msg(request, flags, msg_id, wait_time, stop_time);

	wakeup_next();

	if (rc != 0) {

		request->msg_status = response->msg_status = rc;
		mutex_exit(mb_lock);

		/* Free the waiter */
		cv_destroy(&waiter->w_cv);
		kmem_free(waiter, sizeof (struct sbbc_msg_waiter));

		SGSBBC_DBG_MBOX("%s: msg_id = 0x%x send rc = %d\n",
		    f, msg_id, rc);

		return (rc);
	}

	waiter->w_id = msg_id;

	/*
	 * Lock this waiter list and add the waiter
	 */
	mutex_enter(mbox_wait_lock);

	if (master_mbox->mbox_wait_list[msg_type] == NULL) {
		master_mbox->mbox_wait_list[msg_type] = waiter;
		waiter->w_next = NULL;
	} else {
		struct sbbc_msg_waiter	*tmp;
		tmp = master_mbox->mbox_wait_list[msg_type];
		master_mbox->mbox_wait_list[msg_type] = waiter;
		waiter->w_next = tmp;
	}

	mutex_exit(mb_lock);

	/*
	 * wait here for a response to our message
	 * holding the mbox_wait_lock for the list ensures
	 * that the interrupt handler can't get in before
	 * we block.
	 * NOTE: We use the request msg_type for the
	 *	 the wait_list. This ensures that  the
	 *	 msg_type won't change.
	 */
	clockleft = cv_timedwait(&waiter->w_cv, mbox_wait_lock, stop_time);

	SGSBBC_DBG_MBOX("%s: msg_id = 0x%x is woken up for response\n",
		f, msg_id);

	/*
	 * If we have timed out, set msg_status to ETIMEDOUT,
	 * and remove the waiter from the waiter list.
	 */
	if (clockleft < 0) {
		/*
		 * Remove the waiter from the waiter list.
		 * If we can't find the waiter in the list,
		 * 1. msg_status == EINPROGRESS
		 *    It is being processed.  We will give it
		 *    a chance to finish.
		 * 2. msg_status != EINPROGRESS
		 *    It is done processing.  We can safely
		 *    remove it.
		 * If we can find the waiter, it has timed out.
		 */
		SGSBBC_DBG_MBOX("%s: msg_id = 0x%x has timed out\n",
			f, msg_id);
		if (mbox_find_waiter(msg_type, msg_id) == NULL) {
			if (waiter->w_msg->msg_status == EINPROGRESS) {
				SGSBBC_DBG_MBOX("%s: Waiting for msg_id = 0x%x "
					"complete.\n", f, msg_id);
				cv_wait(&waiter->w_cv, mbox_wait_lock);
			}
		} else {
			SGSBBC_DBG_MBOX("%s: setting msg_id = 0x%x "
				"to ETIMEDOUT\n", f, msg_id);
			cmn_err(CE_NOTE, "Timed out waiting for SC response");
			rc = waiter->w_msg->msg_status = ETIMEDOUT;
		}
	}

	/*
	 * lose the waiter
	 */
	cv_destroy(&waiter->w_cv);
	kmem_free(waiter, sizeof (struct sbbc_msg_waiter));

	mutex_exit(mbox_wait_lock);

	return (rc);

}

static void
wakeup_next()
{
	/*
	 * Done sending the current message or encounter an error.
	 * Wake up the one request in the outbox_queue.
	 */
	mutex_enter(&outbox_queue_lock);
	outbox_busy = 0;
	cv_signal(&outbox_queue);
	mutex_exit(&outbox_queue_lock);
}


/* ARGSUSED */
int
sbbc_mbox_send_msg(sbbc_msg_t *msg, int flags, uint_t msg_id,
	time_t wait_time, clock_t stop_time)
{
	struct sbbc_mbox_header	header;
	struct sbbc_fragment	frag;
	int			rc = 0;
	int			bytes_written;
	uint32_t		intr_enabled;
	clock_t			clockleft;
	static fn_t		f = "sbbc_mbox_send_msg";

	/*
	 * First check that the SC has enabled its mailbox
	 */
	rc = iosram_read(SBBC_INTR_SC_ENABLED_KEY, 0,
		(caddr_t)&intr_enabled, sizeof (intr_enabled));

	if (rc)
		return (rc);

	if (!(intr_enabled & SBBC_MAILBOX_OUT))
		return (ENOTSUP);

	/*
	 * read the mailbox header
	 */
	if (rc = mbox_read_header(SBBC_OUTBOX, &header))
		return (rc);

	/*
	 * Allocate/initialise a fragment for this message
	 */
	frag.f_id = msg_id;
	frag.f_type = msg->msg_type;
	frag.f_status = 0;
	frag.f_total_len = msg->msg_len;
	frag.f_frag_offset = 0;
	/*
	 * Throw in the message data
	 */
	bcopy(&msg->msg_data, &frag.f_data, sizeof (msg->msg_data));

	/*
	 * If not enough space is available
	 * write what we can and wait for
	 * an interrupt to tell us that more
	 * space is available
	 */

	bytes_written = 0;
	do {
		rc = mbox_write(&header, &frag, msg);

		if (rc != 0 && rc != ENOSPC) {
			return (rc);
		}

		if (rc == 0) {
			/*
			 * Always tell the SC when there is a message.
			 * Ignore returned value as not being able to
			 * signal the SC about space available does
			 * not stop the SC from processing input.
			 */
			(void) iosram_send_intr(SBBC_MAILBOX_OUT);
		}

		bytes_written += frag.f_frag_len;
		frag.f_frag_offset += frag.f_frag_len;
		if ((bytes_written < msg->msg_len) || (rc == ENOSPC)) {

			if (mbox_has_free_space(&header) <=
				sizeof (struct sbbc_fragment)) {

				int tmprc;

				clockleft = cv_timedwait(
					&master_mbox->mbox_out->mb_full,
					&master_mbox->mbox_out->mb_lock,
					stop_time);

				/* Return ETIMEDOUT if we timed out */
				if (clockleft < 0) {
					SGSBBC_DBG_MBOX("%s: msg_id = 0x%x "
						"has timed out\n", f, msg_id);
					cmn_err(CE_NOTE,
						"Timed out sending message "
						"to SC");
					return (ETIMEDOUT);
				}

				/* Read updated header from IOSRAM */
				if (tmprc = mbox_read_header(SBBC_OUTBOX,
				    &header)) {

					return (tmprc);
				}
			}
		}

		SGSBBC_DBG_MBOX("%s: msg_id = 0x%x, bytes_written = 0x%x, "
			"msg_len = 0x%x\n", f,
				msg_id, bytes_written, msg->msg_len);
	} while ((bytes_written < msg->msg_len) || (rc == ENOSPC));

	/*
	 * this could be a spurious interrupt
	 * as the SC may be merrily readings its
	 * mail even as send, but what can you do ? No
	 * synchronization method between SC <-> OS
	 * SRAM data eaters means that this is inevitable.
	 * It would take a bigger brain to fix this.
	 *
	 */
	(void) iosram_send_intr(SBBC_MAILBOX_OUT);

	return (rc);
}


/*
 * get next message
 * Read the next message from SRAM
 * Check if theres an entry on the wait queue
 * for this message
 * If yes, read the message in and signal
 * the waiter (if all the message has been received)
 * No, its unsolicited, if theres a handler installed for
 * this message type trigger it, otherwise toss
 * the message
 */
int
sbbc_mbox_recv_msg()
{
	struct sbbc_mbox_header	header;
	struct sbbc_fragment	frag;
	sbbc_msg_t		tmpmsg;	/* Temporary msg storage */
	int			rc = 0, i, first_hdlr, last_hdlr;
	uint32_t		intr_enabled;
	sbbc_intrs_t		*intr;
	struct sbbc_msg_waiter	*waiter;
	uint16_t		type;	/* frag.f_type.type */
	uint32_t		f_id;	/* frag.f_id */
	uint32_t		f_frag_offset, f_frag_len;
	kmutex_t		*mbox_wait_lock;
	static fn_t		f = "sbbc_mbox_recv_msg";

	/*
	 * First check that the OS has enabled its mailbox
	 */
	rc = iosram_read(SBBC_SC_INTR_ENABLED_KEY, 0,
		(caddr_t)&intr_enabled, sizeof (intr_enabled));

	if (rc) {
		return (rc);
	}

	if (!(intr_enabled & SBBC_MAILBOX_IN))
		return (ENOTSUP);

	/*
	 * read the mailbox header
	 */
	if (rc = mbox_read_header(SBBC_INBOX, &header))
		return (rc);

	/*
	 * check if any messages available. If
	 * consumer == producer then no more
	 * messages
	 */
	if ((header.mailboxes[SBBC_INBOX].mbox_consumer ==
		header.mailboxes[SBBC_INBOX].mbox_producer)) {

		return (-1);
	}

	/*
	 * read the fragment header for this message
	 */
	if (rc = mbox_read_frag(&header, &frag)) {

		return (rc);
	}

	/* Save to local variable for easy reading */
	type = frag.f_type.type;
	f_id = frag.f_id;

	SGSBBC_DBG_MBOX("%s: f_id = 0x%x\n", f, f_id);

	/*
	 * check the message type. If its invalid, we will
	 * just toss the message
	 */
	if (type >= SBBC_MBOX_MSG_TYPES) {
		goto done;
	}

	/*
	 * if theres no waiters for this message type, and theres
	 * no message handler installed, toss it.
	 *
	 * Unsolicited messages (f_id == 0) are tricky because we won't know
	 * when the handler has finished so that we can
	 * remove the message, so, given the small brains in operation
	 * here, what we do is restrict junk mail to zero-length
	 * messages, then we allocate a fragment using kmem,
	 * make a copy of the fragment in this memory,
	 * pass this pointer to the fragment, then skip the message.
	 * So even if there is data associated with the junkmail,
	 * the message handler doesn't get to see it
	 * We expect the mesaage handler to free the memory.
	 */
	if (type == SBBC_BROADCAST_MSG) {
		/*
		 * Broadcast message, trigger all handlers
		 */
		first_hdlr = 0;
		last_hdlr = SBBC_MBOX_MSG_TYPES - 1;
	} else if ((master_mbox->mbox_wait_list[type] == NULL) || (f_id == 0)) {
		/*
		 * Theres no waiters, or its unsolicited anyway
		 */
		first_hdlr = last_hdlr = type;
	} else {
		/*
		 * check the fragment message type, look at the wait list for
		 * that type to find its associated message
		 *
		 * First find the message. If we get it, take it off
		 * the waiter list and read the data. We will
		 * put it back on the list if necessary.
		 * This avoids the problem of a second message-in
		 * interrupt playing with this waiter.
		 * This will cut down on mutex spinning on the wait
		 * list locks, also, expect the next fragment to be
		 * for this messageso we might as well have it at the
		 * start of the list.
		 *
		 * its possible that a return message has a different type,
		 * (possible but not recommended!). So, if we don't find
		 * it on the list pointed to by the request type,
		 * go look at all the other lists
		 */

		mbox_wait_lock = &master_mbox->mbox_wait_lock[type];

		mutex_enter(mbox_wait_lock);
		if ((waiter = mbox_find_waiter(type, f_id)) == NULL) {
			for (i = 0; i < SBBC_MBOX_MSG_TYPES; i++) {
				if (i == type)
					continue;
				if ((waiter = mbox_find_waiter(i, f_id))
					!= NULL)
					break;
			}
		}
		mutex_exit(mbox_wait_lock);

		if (waiter == NULL) {
			rc = -1;
			/*
			 * there's no waiter for this message, but that
			 * could mean that this message is the start of
			 * a send/receive to us, and every 'first' request
			 * must by definition be unsolicited,
			 * so trigger the handler
			 */
			first_hdlr = last_hdlr = type;
		} else {
			SGSBBC_DBG_MBOX("%s: f_id = 0x%x, msg_id = 0x%x, "
				"msg_len = 0x%x\n",
					f, f_id, waiter->w_id,
					waiter->w_msg->msg_len);

			rc = mbox_read(&header, &frag, waiter->w_msg);

			SGSBBC_DBG_MBOX("%s: f_id = 0x%x, offset = 0x%x, "
				"len = 0x%x, total_len = 0x%x\n",
					f, frag.f_id, frag.f_frag_offset,
					frag.f_frag_len, frag.f_total_len);

			if (rc || ((frag.f_frag_offset + frag.f_frag_len) ==
				frag.f_total_len)) {
				/*
				 * failed or all the message has been read in
				 */
				mutex_enter(mbox_wait_lock);
				waiter->w_msg->msg_status = (rc == ENOMEM)?
					rc : frag.f_status;
				SGSBBC_DBG_MBOX("%s: msg_status = %d\n",
					f, waiter->w_msg->msg_status);
				cv_signal(&waiter->w_cv);
				mutex_exit(mbox_wait_lock);

			} else {
				/*
				 * back on the wait list
				 */
				mutex_enter(mbox_wait_lock);
				if (waiter->w_msg->msg_status == ETIMEDOUT) {
					cv_signal(&waiter->w_cv);
					mutex_exit(mbox_wait_lock);
					goto done;
				}

				if (master_mbox->mbox_wait_list[type] == NULL) {
					master_mbox->mbox_wait_list[type] =
						waiter;
					waiter->w_next = NULL;
				} else {
					struct sbbc_msg_waiter	*tmp;
					tmp = master_mbox->mbox_wait_list[type];
					master_mbox->mbox_wait_list[type] =
						waiter;
					waiter->w_next = tmp;
				}
				mutex_exit(mbox_wait_lock);
			}
			goto done;
		}
	}

	/*
	 * Set msg_len to f_frag_len so msg_buf will be large enough
	 * to contain what is in the fragment.
	 */
	f_frag_len = tmpmsg.msg_len = frag.f_frag_len;
	/*
	 * Save the f_frag_offset for copying into client's space.
	 * Set frag.f_frag_offset to 0 so we don't have to allocate
	 * too much space for reading in the message.
	 */
	f_frag_offset = frag.f_frag_offset;
	frag.f_frag_offset = 0;

	/* Allocate space for msg_buf */
	if (f_frag_len != 0 && (tmpmsg.msg_buf =
		kmem_alloc(f_frag_len, KM_NOSLEEP)) == NULL) {

		rc = ENOMEM;
		cmn_err(CE_WARN, "Can't allocate memory"
			" for unsolicited messages\n");
	} else {
		/* Save the incoming message in tmpmsg */
		rc = mbox_read(&header, &frag, &tmpmsg);

		for (i = first_hdlr; rc == 0 && i <= last_hdlr; i++) {

			intr = master_mbox->intrs[i];
			if ((intr == NULL) || (intr->sbbc_intr_id == 0)) {
				continue;
			}

			while (intr != NULL) {
				/*
				 * If the client has allocated enough space
				 * for incoming message, copy into the
				 * client buffer.
				 */
				sbbc_msg_t *arg = (sbbc_msg_t *)intr->sbbc_arg;
				if (arg != (void *)NULL) {
					if (arg->msg_len >= frag.f_total_len) {
						if (f_frag_len > 0)
							bcopy(tmpmsg.msg_buf,
								arg->msg_buf +
								f_frag_offset,
								f_frag_len);
					} else {
						arg->msg_status = ENOMEM;
					}
				}

				/*
				 * Only trigger the interrupt when we
				 * have received the whole message.
				 */
				if (f_frag_offset + f_frag_len ==
					frag.f_total_len) {

					ddi_trigger_softintr(
						intr->sbbc_intr_id);
				}
				intr = intr->sbbc_intr_next;
			}
		}

		if (f_frag_len != 0) {
			/* Don't forget to free the buffer */
			kmem_free(tmpmsg.msg_buf, f_frag_len);
		}
	}
done:
	mbox_skip_next_msg(&header);
	return (rc);
}

/*
 * available free space in the outbox
 */
static int
mbox_has_free_space(struct sbbc_mbox_header *header)
{
	uint32_t	space = 0;

	ASSERT(MUTEX_HELD(&master_mbox->mbox_out->mb_lock));

	if (header->mailboxes[SBBC_OUTBOX].mbox_producer ==
		header->mailboxes[SBBC_OUTBOX].mbox_consumer) {
		/*
		 * mailbox is empty
		 */
		space += header->mailboxes[SBBC_OUTBOX].mbox_len -
			header->mailboxes[SBBC_OUTBOX].mbox_producer;
		space +=
			header->mailboxes[SBBC_OUTBOX].mbox_producer;
	} else if (header->mailboxes[SBBC_OUTBOX].mbox_producer >
		header->mailboxes[SBBC_OUTBOX].mbox_consumer) {
		space += header->mailboxes[SBBC_OUTBOX].mbox_len -
			header->mailboxes[SBBC_OUTBOX].mbox_producer;
		space += header->mailboxes[SBBC_OUTBOX].mbox_consumer;
	} else {
		/*
		 * mailbox wrapped around
		 */
		space += header->mailboxes[SBBC_OUTBOX].mbox_consumer -
			header->mailboxes[SBBC_OUTBOX].mbox_producer;
	}

	/*
	 * Need to make sure that the mailbox never
	 * gets completely full, as consumer == producer is
	 * our test for empty, so we drop MBOX_ALIGN_BYTES.
	 */

	if (space >= MBOX_ALIGN_BYTES)
		space -= MBOX_ALIGN_BYTES;
	else
		space = 0;

	return (space);

}
/*
 * Write the data to IOSRAM
 * Update the SRAM mailbox header
 * Update the local mailbox pointers
 * Only write a single fragment. If possible,
 * put the whole message into a fragment.
 *
 * Note: We assume that there is no 'max' message
 *	 size. We will just keep fragmenting.
 * Note: We always write to SBBC_OUTBOX and
 *	 read from SBBC_INBOX
 *
 * If we get an error at any time, return immediately
 * without updating the mailbox header in SRAM
 */
static int
mbox_write(struct sbbc_mbox_header *header,
	struct sbbc_fragment *frag, sbbc_msg_t *msg)
{
	int		bytes_written, bytes_remaining, free_space;
	int		rc = 0;
	caddr_t		src;
	uint32_t	sram_dst;
	int		space_at_end, space_at_start;
	uint32_t	mbox_offset, mbox_len;
	uint32_t	mbox_producer, mbox_consumer;
	uint32_t	f_total_len, f_frag_offset;
	uint32_t	frag_header_size;
	static fn_t	f = "mbox_write";

	ASSERT(MUTEX_HELD(&master_mbox->mbox_out->mb_lock));

	/*
	 * Save to local variables to make code more readable
	 */
	mbox_offset = header->mailboxes[SBBC_OUTBOX].mbox_offset;
	mbox_len = header->mailboxes[SBBC_OUTBOX].mbox_len;
	mbox_producer = header->mailboxes[SBBC_OUTBOX].mbox_producer;
	mbox_consumer = header->mailboxes[SBBC_OUTBOX].mbox_consumer;
	f_total_len = frag->f_total_len;
	f_frag_offset = frag->f_frag_offset;
	frag_header_size = sizeof (struct sbbc_fragment);

	SGSBBC_DBG_MBOX("%s: mbox_consumer = 0x%x, "
		"mbox_producer = 0x%x\n", f, mbox_consumer, mbox_producer);

	/*
	 * Write pointer in SRAM
	 */
	sram_dst = mbox_offset + mbox_producer;

	/*
	 * NB We assume that the consumer stays constant
	 *    during the write. It may not necessarily
	 *    be the case but it won't cause us any problems, just means
	 *    we fragment more than is absolutely necessary
	 *
	 * possible cases
	 * 1) consumer == producer, mailbox empty
	 *	space_at_end == mailbox end - producer
	 *	space_at_start == producer - MBOX_ALIGN_BYTES
	 * 2) producer < consumer
	 *	space_at_end = (consumer - producer - MBOX_ALIGN_BYTES)
	 *	space_at_start == 0
	 * 3) producer > consumer
	 *	space_at_end = mailbox end - producer
	 *	space_at_start = consumer - MBOX_ALIGN_BYTES
	 *
	 * (space - MBOX_ALIGN_BYTES) because we need to avoid the
	 * scenario where the producer wraps around completely and
	 * producer == consumer, as this is our test for 'empty'.
	 * Also we want it to be 8-byte aligned.
	 * Note: start is assumed = 0
	 */
	if (mbox_producer < mbox_consumer) {
		space_at_end = mbox_consumer - mbox_producer - MBOX_ALIGN_BYTES;
		if (space_at_end < 0)
			space_at_end = 0;
		space_at_start = 0;
	} else {
		space_at_end = mbox_len - mbox_producer;
		if (mbox_consumer == 0)
			space_at_end -= MBOX_ALIGN_BYTES;
		space_at_start = mbox_consumer - MBOX_ALIGN_BYTES;
		if (space_at_start < 0)
			space_at_start = 0;
	}

	SGSBBC_DBG_MBOX("%s: space_at_end = 0x%x, space_at_start = 0x%x\n",
		f, space_at_end, space_at_start);

	free_space = space_at_end + space_at_start;

	if (free_space < frag_header_size) {
		/*
		 * can't even write a fragment header, so just return
		 * the caller will block waiting for space
		 */
		frag->f_frag_len = 0;
		return (ENOSPC);
	}

	/*
	 * How many bytes will be in the fragment ?
	 */
	bytes_remaining = f_total_len - f_frag_offset;
	frag->f_frag_len = min(bytes_remaining, free_space - frag_header_size);

	SGSBBC_DBG_MBOX("%s: writing header:sram_dst = 0x%x\n",
		f, sram_dst);

	/*
	 * we can write the fragment header and some data
	 * First, the fragment header
	 */
	if (space_at_end >=  frag_header_size) {
		rc = iosram_write(SBBC_MAILBOX_KEY, sram_dst, (caddr_t)frag,
			frag_header_size);
		if (rc)
			return (rc);

		sram_dst = (uint32_t)(sram_dst + frag_header_size);
		/*
		 * Wrap around if we reach the end
		 */
		if (sram_dst >= (mbox_len + mbox_offset)) {
			sram_dst = mbox_offset;
		}
		space_at_end -= frag_header_size;
	} else {
		/* wraparound */
		if (space_at_end) {
			rc = iosram_write(SBBC_MAILBOX_KEY, sram_dst,
				(caddr_t)frag, space_at_end);
			if (rc)
				return (rc);
			sram_dst = (uint32_t)mbox_offset;
		}
		rc = iosram_write(SBBC_MAILBOX_KEY, sram_dst,
			(caddr_t)((caddr_t)frag + space_at_end),
			(frag_header_size - space_at_end));
		if (rc)
			return (rc);
		sram_dst += frag_header_size - space_at_end;
		space_at_start -= (frag_header_size - space_at_end);
		space_at_end = 0;
	}

	SGSBBC_DBG_MBOX("%s: space_at_end = 0x%x, space_at_start = 0x%x\n",
		f, space_at_end, space_at_start);

	/*
	 * Now the fragment data
	 */
	free_space -= frag_header_size;
	src = (caddr_t)(msg->msg_buf + f_frag_offset);
	bytes_written = 0;
	if (space_at_end) {
		SGSBBC_DBG_MBOX("%s: writing data:sram_dst = 0x%x, "
			"bytes_remaining = 0x%x\n",
				f, sram_dst, bytes_remaining);

		if (space_at_end < bytes_remaining)
			bytes_written = space_at_end;
		else
			bytes_written = bytes_remaining;
		rc = iosram_write(SBBC_MAILBOX_KEY, sram_dst, src,
			bytes_written);
		if (rc)
			return (rc);

		sram_dst = (uint32_t)(sram_dst + bytes_written);
		/*
		 * Wrap around if we reach the end
		 */
		if (sram_dst >= (mbox_len + mbox_offset)) {
			sram_dst = mbox_offset;
		}
		src = (caddr_t)(src + bytes_written);
		bytes_remaining -= bytes_written;
	}

	if ((bytes_remaining > 0) && space_at_start) {
		SGSBBC_DBG_MBOX("%s: writing the rest:sram_dst = 0x%x, "
			"bytes_remaining = 0x%x\n",
				f, sram_dst, bytes_remaining);
		if (space_at_start < bytes_remaining) {
			rc = iosram_write(SBBC_MAILBOX_KEY, sram_dst, src,
				space_at_start);
			bytes_written += space_at_start;
		} else {
			rc = iosram_write(SBBC_MAILBOX_KEY, sram_dst, src,
				bytes_remaining);
			bytes_written += bytes_remaining;
		}
		if (rc)
			return (rc);
	}

	frag->f_frag_len = bytes_written;

	/*
	 * update header->mbox_producer (bytes_written + frag_size)
	 */
	sram_dst = mbox_producer + bytes_written + frag_header_size;
	if (sram_dst >= mbox_len) {
		sram_dst = sram_dst % mbox_len;
	}

	SGSBBC_DBG_MBOX("%s: after writing data:sram_dst = 0x%x, "
		"bytes_written = 0x%x\n", f, sram_dst, bytes_written);

	header->mailboxes[SBBC_OUTBOX].mbox_producer = sram_dst;

	mbox_update_header(SBBC_OUTBOX, header);


	return (rc);
}


/*
 * Get the next frag from IOSRAM.
 * Write it to the corresponding msg buf.
 * The caller must update the SRAM pointers etc.
 */
static int
mbox_read(struct sbbc_mbox_header *header,
	struct sbbc_fragment *frag, sbbc_msg_t *msg)
{
	int			rc = 0;
	uint32_t		sram_src, sram_end;
	caddr_t			msg_buf;
	int			bytes_at_start, bytes_at_end;
	int			bytes_to_read;
	uint32_t		frag_header_size, frag_total_size;
	uint32_t		f_frag_offset, f_frag_len;
	uint32_t		mbox_producer, mbox_consumer;
	uint32_t		mbox_len, mbox_offset;
	static fn_t		f = "mbox_read";

	ASSERT(MUTEX_HELD(&master_mbox->mbox_in->mb_lock));

	/*
	 * Save to local variables to make code more readable
	 */
	mbox_producer = header->mailboxes[SBBC_INBOX].mbox_producer;
	mbox_consumer = header->mailboxes[SBBC_INBOX].mbox_consumer;
	mbox_len = header->mailboxes[SBBC_INBOX].mbox_len;
	mbox_offset = header->mailboxes[SBBC_INBOX].mbox_offset;
	frag_header_size = sizeof (struct sbbc_fragment);
	f_frag_offset = frag->f_frag_offset;
	f_frag_len = frag->f_frag_len;
	frag_total_size = frag_header_size + f_frag_len;

	/*
	 * If the message buffer size is smaller than the fragment
	 * size, return an error.
	 */
	if (msg->msg_len < f_frag_len)  {
		rc = ENOMEM;
		goto done;
	}

	msg_buf = (caddr_t)(msg->msg_buf + f_frag_offset);

	/*
	 * Throw in the message data
	 */
	bcopy(&frag->f_data, &msg->msg_data, sizeof (msg->msg_data));

	/*
	 * We have it all, waiter, message, so lets
	 * go get that puppy!
	 * Message could be in one or two chunks -
	 * consumer < producer: 1 chunk, (producer - consumer)
	 * consumer > producer: 2 chunks, (end - consumer)
	 *				 (producer - start)
	 */
	sram_end =  (uint32_t)(mbox_offset + mbox_len);
	sram_src = (uint32_t)(mbox_offset + mbox_consumer + frag_header_size);

	/*
	 * wraparound
	 */
	if (sram_src >= sram_end)
		sram_src -= mbox_len;

	/*
	 * find where the data is
	 * possible cases
	 * 1) consumer == producer, mailbox empty
	 *	error
	 * 2) producer < consumer
	 *	bytes_at_end =  mailbox end - consumer
	 *	bytes_at_start = producer
	 * 3) producer > consumer
	 *	bytes_at_end =  producer - consumer
	 *	bytes_at_start = 0
	 */

	SGSBBC_DBG_MBOX("%s: mbox_consumer = 0x%x, mbox_producer = 0x%x, "
		"frag_len = 0x%x\n",
			f, mbox_consumer, mbox_producer, f_frag_len);

	if (mbox_producer == mbox_consumer) {
		bytes_at_end = bytes_at_start = 0;
	} else if (mbox_producer < mbox_consumer) {
		bytes_at_end = mbox_len - mbox_consumer;
		bytes_at_start = mbox_producer;
	} else {
		bytes_at_end = mbox_producer - mbox_consumer;
		bytes_at_start = 0;
	}

	SGSBBC_DBG_MBOX("%s: bytes_at_end = 0x%x, "
		"bytes_at_start = 0x%x\n", f, bytes_at_end, bytes_at_start);

	if ((bytes_at_end + bytes_at_start) < frag_total_size) {

		/*
		 * mailbox is corrupt
		 * but what to do ?
		 */
		cmn_err(CE_PANIC, "Corrupt INBOX!\n"
		    "producer = %x, consumer = %x, bytes_at_start = %x, "
		    "bytes_at_end = %x\n", mbox_producer, mbox_consumer,
		    bytes_at_start, bytes_at_end);
	}

	/*
	 * If bytes_at_end is greater than header size, read the
	 * part at the end of the mailbox, and then update the
	 * pointers and bytes_to_read.
	 */
	if (bytes_at_end > frag_header_size) {
		/*
		 * We are only interested in the data segment.
		 */
		bytes_at_end -= frag_header_size;
		bytes_to_read = (bytes_at_end >= f_frag_len)?
			f_frag_len : bytes_at_end;
		SGSBBC_DBG_MBOX("%s: reading data: sram_src = 0x%x, "
			"bytes_to_read = 0x%x\n", f, sram_src, bytes_to_read);
		rc = iosram_read(SBBC_MAILBOX_KEY, sram_src, msg_buf,
			bytes_to_read);
		if (rc) {
			goto done;
		}

		/*
		 * Update pointers in SRAM and message buffer.
		 */
		sram_src = (uint32_t)mbox_offset;
		msg_buf = (caddr_t)(msg_buf + bytes_to_read);
		bytes_to_read = f_frag_len - bytes_to_read;
	} else {
		bytes_to_read = f_frag_len;
	}

	/*
	 * wraparound to start of mailbox
	 */
	if (bytes_to_read > 0) {
		SGSBBC_DBG_MBOX("%s: reading the rest: sram_src = 0x%x, "
			"bytes_to_read = 0x%x\n", f, sram_src, bytes_to_read);
		rc = iosram_read(SBBC_MAILBOX_KEY, sram_src, msg_buf,
			bytes_to_read);
	}

done:
	msg->msg_bytes += f_frag_len;

	return (rc);
}

/*
 * move past the next message in the inbox
 */
static void
mbox_skip_next_msg(struct sbbc_mbox_header *header)
{
	struct sbbc_fragment	frag;
	uint32_t		next_msg;

	ASSERT(MUTEX_HELD(&master_mbox->mbox_in->mb_lock));

	if (mbox_read_frag(header, &frag)) {
		cmn_err(CE_PANIC, "INBOX is Corrupt !\n");
	}

	/*
	 * Move on to the next message
	 */
	next_msg = header->mailboxes[SBBC_INBOX].mbox_consumer;
	next_msg += sizeof (struct sbbc_fragment);
	next_msg += frag.f_frag_len;
	if (next_msg >= header->mailboxes[SBBC_INBOX].mbox_len) {
		next_msg = (next_msg +
			header->mailboxes[SBBC_INBOX].mbox_len) %
			header->mailboxes[SBBC_INBOX].mbox_len;
	}
	header->mailboxes[SBBC_INBOX].mbox_consumer =
		next_msg;

	mbox_update_header(SBBC_INBOX, header);

	return;

}

static struct sbbc_msg_waiter *
mbox_find_waiter(uint16_t msg_type, uint32_t msg_id)
{
	struct	sbbc_msg_waiter	*waiter, *prev;

	prev = NULL;
	for (waiter = master_mbox->mbox_wait_list[msg_type];
		waiter != NULL; waiter = waiter->w_next) {

		if (waiter->w_id == msg_id) {
			if (prev != NULL) {
				prev->w_next = waiter->w_next;
			} else {
				master_mbox->mbox_wait_list[msg_type] =
					waiter->w_next;
			}
			break;
		}
		prev = waiter;
	}

	return (waiter);
}

static int
mbox_read_header(uint32_t mailbox, struct sbbc_mbox_header *header)
{
	struct sbbc_mbox_header *hd;
	uint32_t	offset;
	int		rc;

	/*
	 * Initialize a sbbc_mbox_header pointer to 0 so that we
	 * can use it to calculate the offsets of fields inside
	 * the structure.
	 */
	hd = (struct sbbc_mbox_header *)0;

	if (rc = iosram_read(SBBC_MAILBOX_KEY, 0, (caddr_t)header,
	    sizeof (struct sbbc_mbox_header)))
		return (rc);

	/*
	 * Since the header is read in a byte-by-byte fashion
	 * using ddi_rep_get8, we need to re-read the producer
	 * or consumer pointer as integer in case it has changed
	 * after part of the previous value has been read.
	 */
	switch (mailbox) {

	case SBBC_INBOX:
		offset = (uint32_t)(uintptr_t)
		    (&hd->mailboxes[SBBC_INBOX].mbox_producer);
		rc = iosram_read(SBBC_MAILBOX_KEY, offset,
		    (caddr_t)&header->mailboxes[SBBC_INBOX].mbox_producer,
		    sizeof (uint32_t));
		break;
	case SBBC_OUTBOX:
		offset = (uint32_t)(uintptr_t)
		    (&hd->mailboxes[SBBC_OUTBOX].mbox_consumer);
		rc = iosram_read(SBBC_MAILBOX_KEY, offset,
		    (caddr_t)&header->mailboxes[SBBC_OUTBOX].mbox_consumer,
		    sizeof (uint32_t));
		break;
	default:
		cmn_err(CE_PANIC, "Invalid Mbox header type\n");
		break;

	}

	return (rc);
}

/*
 * There are only two fields updated by the  domain,
 * the inbox consumer field and the outbox producer
 * field. These fields are protected by the respective
 * mbox_{in|out}->mb_lock so that accesses will
 * be serialised. The only coherency issue is writing
 * back the header, so we do it here after grabbing
 * the global mailbox lock.
 */
static void
mbox_update_header(uint32_t mailbox, struct sbbc_mbox_header *header)
{
	struct sbbc_mbox_header	*hd;
	uint32_t		value, offset, mbox_len;

	/*
	 * Initialize a sbbc_mbox_header pointer to 0 so that we
	 * can use it to calculate the offsets of fields inside
	 * the structure.
	 */
	hd = (struct sbbc_mbox_header *)0;

	switch (mailbox) {

	case SBBC_INBOX:
		value = header->mailboxes[SBBC_INBOX].mbox_consumer;
		offset = (uint32_t)(uintptr_t)
			(&hd->mailboxes[SBBC_INBOX].mbox_consumer);

		mbox_len = header->mailboxes[SBBC_INBOX].mbox_len;
		break;
	case SBBC_OUTBOX:
		value = header->mailboxes[SBBC_OUTBOX].mbox_producer;
		offset = (uint32_t)(uintptr_t)
			(&hd->mailboxes[SBBC_OUTBOX].mbox_producer);
		mbox_len = header->mailboxes[SBBC_OUTBOX].mbox_len;
		break;
	default:
		cmn_err(CE_PANIC, "Invalid Mbox header type\n");
		break;

	}

	/*
	 * If the last read/write would cause the next read/write
	 * to be unaligned, we skip on modulo MBOX_ALIGN_BYTES.
	 * This is OK because all the mailbox handlers will
	 * conform to this.
	 */
	if (value % MBOX_ALIGN_BYTES) {
		value += (MBOX_ALIGN_BYTES - (value % MBOX_ALIGN_BYTES));
		value %= mbox_len;
	}

	if (iosram_write(SBBC_MAILBOX_KEY, offset, (caddr_t)&value,
		sizeof (uint32_t))) {
		cmn_err(CE_PANIC, "Mailbox Corrupt ! \n");
	}

	/*
	 * Update internal pointers so they won't be out of sync with
	 * the values in IOSRAM.
	 */
	switch (mailbox) {

	case SBBC_INBOX:
		header->mailboxes[SBBC_INBOX].mbox_consumer = value;
		break;
	case SBBC_OUTBOX:
		header->mailboxes[SBBC_OUTBOX].mbox_producer = value;
		break;
	}
}

static int
mbox_read_frag(struct sbbc_mbox_header *header,
	struct sbbc_fragment *frag)
{
	int			rc = 0;
	uint32_t		sram_src, bytes;
	caddr_t			dst;

	ASSERT(MUTEX_HELD(&master_mbox->mbox_in->mb_lock));
	/*
	 * read the fragment header for this message
	 */
	sram_src = (uint32_t)(header->mailboxes[SBBC_INBOX].mbox_offset +
		header->mailboxes[SBBC_INBOX].mbox_consumer);

	/*
	 * wraparound ?
	 */
	if ((header->mailboxes[SBBC_INBOX].mbox_consumer +
		sizeof (struct sbbc_fragment)) >=
		header->mailboxes[SBBC_INBOX].mbox_len) {

		dst = (caddr_t)frag;
		bytes = header->mailboxes[SBBC_INBOX].mbox_len -
			header->mailboxes[SBBC_INBOX].mbox_consumer;

		if (rc = iosram_read(SBBC_MAILBOX_KEY, sram_src, dst, bytes)) {
			return (rc);
		}

		dst += bytes;
		sram_src = header->mailboxes[SBBC_INBOX].mbox_offset;
		bytes = (header->mailboxes[SBBC_INBOX].mbox_consumer +
			sizeof (struct sbbc_fragment)) %
			header->mailboxes[SBBC_INBOX].mbox_len;

		if (rc = iosram_read(SBBC_MAILBOX_KEY, sram_src,
			dst, bytes)) {
			return (rc);
		}
	} else {
		if (rc = iosram_read(SBBC_MAILBOX_KEY, sram_src, (caddr_t)frag,
			sizeof (struct sbbc_fragment))) {
			return (rc);
		}
	}

	return (0);
}


/*
 * This function is triggered by a soft interrupt and it's purpose is to call
 * to kadmin() to shutdown the Domain.
 */
/*ARGSUSED0*/
static uint_t
sbbc_do_fast_shutdown(char *arg)
{
	(void) kadmin(A_SHUTDOWN, AD_POWEROFF, NULL, kcred);

	/*
	 * If kadmin fails for some reason then we bring the system down
	 * via power_down(), or failing that using halt().
	 */
	power_down("kadmin() failed, trying power_down()");

	halt("power_down() failed, trying halt()");

	/*
	 * We should never make it this far, so something must have gone
	 * horribly, horribly wrong.
	 */
	/*NOTREACHED*/
	return (DDI_INTR_UNCLAIMED);
}


/*
 * This function handles unsolicited PANIC_SHUTDOWN events
 */
static uint_t
sbbc_panic_shutdown_handler(char *arg)
{
	static fn_t	f = "sbbc_panic_shutdown_handler()";

	sg_panic_shutdown_t	*payload = NULL;
	sbbc_msg_t		*msg = NULL;

	if (arg == NULL) {
		SGSBBC_DBG_EVENT(CE_NOTE, "%s: arg == NULL", f);
		return (DDI_INTR_UNCLAIMED);
	}

	msg = (sbbc_msg_t *)arg;

	if (msg->msg_buf == NULL) {
		SGSBBC_DBG_EVENT(CE_NOTE, "%s: msg_buf == NULL", f);
		return (DDI_INTR_UNCLAIMED);
	}

	payload = (sg_panic_shutdown_t *)msg->msg_buf;

	switch (*payload) {
	case SC_EVENT_PANIC_ENV:

		/*
		 * Let the user know why the domain is going down.
		 */
		cmn_err(CE_WARN, "%s", PANIC_ENV_EVENT_MSG);

		/*
		 * trigger sbbc_do_fast_shutdown().
		 */
		ddi_trigger_softintr(panic_softintr_id);

		/*NOTREACHED*/
		break;

	case SC_EVENT_PANIC_KEYSWITCH:
		/*
		 * The SC warns a user if they try a destructive keyswitch
		 * command on a Domain which is currently running Solaris.
		 * If the user chooses to continue despite our best advise
		 * then we bring down the Domain immediately without trying
		 * to shut the system down gracefully.
		 */
		break;

	default:
		SGSBBC_DBG_EVENT(CE_NOTE, "%s: Unknown payload:%d", f,
			*payload);
		return (DDI_INTR_UNCLAIMED);
	}

	return (DDI_INTR_CLAIMED);
}

/*
 * dp_get_cores()
 *
 * Checks cpu implementation for the input cpuid and returns
 * the number of cores.
 * If implementation cannot be determined, returns 1
 */
static int
dp_get_cores(uint16_t cpuid)
{
	int	bd, ii, impl, nc;

	bd = cpuid / 4;
	nc = SG_MAX_CPUS_PER_BD;

	/* find first with valid implementation */
	for (ii = 0; ii < nc; ii++)
		if (cpu[MAKE_CPUID(bd, ii)]) {
			impl = cpunodes[MAKE_CPUID(bd, ii)].implementation;
			break;
		}

	if (IS_JAGUAR(impl) || IS_PANTHER(impl))
		return (2);
	else
		return (1);
}

/*
 * dp_payload_add_cpus()
 *
 * From datapath mailbox message, determines the number of and safari IDs
 * for affected cpus, then adds this info to the datapath ereport.
 *
 */
static int
dp_payload_add_cpus(plat_datapath_info_t *dpmsg, nvlist_t *erp)
{
	int		jj = 0, numcpus = 0;
	int		bd, procpos, ii, num, ncores, ret;
	uint16_t	*dparray, cpuid;
	uint64_t	*snarray;

	/* check for multiple core architectures */
	ncores = dp_get_cores(dpmsg->cpuid);

	switch (dpmsg->type) {
		case DP_CDS_TYPE:
			numcpus = ncores;
			break;

		case DP_DX_TYPE:
			numcpus = 2 * ncores;
			break;

		case DP_RP_TYPE:
			numcpus = SG_MAX_CPUS_PER_BD;
			break;

		default:
			ASSERT(0);
			return (-1);
	}

	num = numcpus;

	/*
	 * populate dparray with impacted cores (only those present)
	 */
	dparray = kmem_zalloc(num * sizeof (uint16_t *), KM_SLEEP);
	bd = SG_PORTID_TO_BOARD_NUM(SG_CPUID_TO_PORTID(dpmsg->cpuid));
	procpos = SG_CPUID_TO_PORTID(dpmsg->cpuid) & 0x3;

	mutex_enter(&cpu_lock);

	switch (dpmsg->type) {

		case DP_CDS_TYPE:
			/*
			 * For a CDS error, it's the reporting cpuid
			 * and it's other core (if present)
			 */
			cpuid = dpmsg->cpuid & 0x1FF;	/* core 0 */
			if (cpu[cpuid])
				dparray[jj++] = cpuid;

			cpuid = dpmsg->cpuid | SG_CORE_ID_MASK;	/* core 1 */
			if (cpu[cpuid])
				dparray[jj++] = cpuid;
			break;

		case DP_DX_TYPE:
			/*
			 * For a DX error, it's the reporting cpuid (all
			 * cores) and the other CPU sharing the same
			 * DX<-->DCDS interface (all cores)
			 */

			/* reporting cpuid */
			cpuid = dpmsg->cpuid & 0x1FF;	/* core 0 */
			if (cpu[cpuid])
				dparray[jj++] = cpuid;

			cpuid = dpmsg->cpuid | SG_CORE_ID_MASK;	/* core 1 */
			if (cpu[cpuid])
				dparray[jj++] = cpuid;

			/* find partner cpuid */
			if (procpos == 0 || procpos == 2)
				cpuid = dpmsg->cpuid + 1;
			else
				cpuid = dpmsg->cpuid - 1;

			/* add partner cpuid */
			cpuid &= 0x1FF;			/* core 0 */
			if (cpu[cpuid])
				dparray[jj++] = cpuid;

			cpuid |= SG_CORE_ID_MASK;	/* core 1 */
			if (cpu[cpuid])
				dparray[jj++] = cpuid;
			break;

		case DP_RP_TYPE:
			/*
			 * For a RP error, it's all cpuids (all cores) on
			 * the reporting board
			 */
			for (ii = 0; ii < SG_MAX_CMPS_PER_BD; ii++) {
				cpuid = MAKE_CPUID(bd, ii);
				if (cpu[cpuid])		/* core 0 */
					dparray[jj++] = cpuid;
				cpuid |= SG_CORE_ID_MASK;
				if (cpu[cpuid])		/* core 1 */
					dparray[jj++] = cpuid;
			}
			break;
	}

	mutex_exit(&cpu_lock);

	/*
	 * The datapath message could not be associated with any
	 * configured CPU.
	 */
	if (!jj) {
		kmem_free(dparray, num * sizeof (uint16_t *));
		ret = nvlist_add_uint32(erp, DP_LIST_SIZE, jj);
		ASSERT(ret == 0);
		return (-1);
	}

	snarray = kmem_zalloc(jj * sizeof (uint64_t), KM_SLEEP);
	for (ii = 0; ii < jj; ii++)
		snarray[ii] = cpunodes[dparray[ii]].device_id;

	ret = nvlist_add_uint32(erp, DP_LIST_SIZE, jj);
	ret |= nvlist_add_uint16_array(erp, DP_LIST, dparray, jj);
	ret |= nvlist_add_uint64_array(erp, SN_LIST, snarray, jj);
	ASSERT(ret == 0);

	kmem_free(dparray, num * sizeof (uint16_t *));
	kmem_free(snarray, jj * sizeof (uint64_t *));

	return (0);
}

/*
 * sbbc_dp_trans_event() - datapath message handler.
 *
 * Process datapath error and fault messages received from the SC.  Checks
 * for, and disregards, messages associated with I/O boards.  Otherwise,
 * extracts message info to produce a datapath ereport.
 */
/*ARGSUSED*/
static uint_t
sbbc_dp_trans_event(char *arg)
{
	const char	*f = "sbbc_dp_trans_event()";
	nvlist_t	*erp, *detector, *hcelem;
	char		buf[FM_MAX_CLASS];
	int		board;
	plat_datapath_info_t	*dpmsg;
	sbbc_msg_t	*msg;
	int		msgtype;

	/* set i/f message and payload pointers */
	msg = &dp_payload_msg;
	dpmsg = &dp_payload;
	msgtype = msg->msg_type.type;

	cmn_err(CE_NOTE, "%s: msgtype=0x%x\n", f, msgtype);
	cmn_err(CE_NOTE, "type=0x%x cpuid=0x%x t_value=0x%x\n", dpmsg->type,
		dpmsg->cpuid, dpmsg->t_value);

	/* check for valid type */
	if (dpmsg->type > DP_RP_TYPE) {
		cmn_err(CE_WARN, "%s: dpmsg type 0x%x invalid\n",
			f, dpmsg->type);
		return (DDI_INTR_CLAIMED);
	}

	/* check for I/O board message -  Schizo AIDs are 25 - 30 */
	if (dpmsg->cpuid > 23) {
		cmn_err(CE_NOTE, "%s: ignore I/O board msg\n", f);
		return (DDI_INTR_CLAIMED);
	}

	/* allocate space for ereport */
	erp = fm_nvlist_create(NULL);

/*
 * Member Name	Data Type	   Comments
 * -----------	---------	   -----------
 * version	uint8		   0
 * class	string		   "asic"
 * ENA		uint64		   ENA Format 1
 * detector	fmri		   aggregated ID data for SC-DE
 *
 * Datapath ereport subclasses and data payloads:
 * There will be two types of ereports (error and fault) which will be
 * identified by the "type" member.
 *
 * ereport.asic.serengeti.cds.cds-dp
 * ereport.asic.serengeti.dx.dx-dp	(board)
 * ereport.asic.serengeti.rp.rp-dp	(centerplane)
 *
 * Member Name	Data Type	  Comments
 * -----------	---------	  -----------
 * erptype	uint16		  derived from message type: error or
 *				  fault
 * t-value	uint32		  SC's datapath SERD timeout threshold
 * dp-list-sz	uint8		  number of dp-list array elements
 * dp-list	array of uint16	  Safari IDs of affected cpus
 * sn-list	array of uint64	  Serial numbers of affected cpus
 */

	/* compose common ereport elements */
	detector = fm_nvlist_create(NULL);

	/*
	 *  Create legacy FMRI for the detector
	 */
	board = SG_PORTID_TO_BOARD_NUM(SG_CPUID_TO_PORTID(dpmsg->cpuid));
	switch (dpmsg->type) {
		case DP_CDS_TYPE:
		case DP_DX_TYPE:
			(void) snprintf(buf, FM_MAX_CLASS, "SB%d", board);
			break;
		case DP_RP_TYPE:
			(void) snprintf(buf, FM_MAX_CLASS, "RP");
			break;
		default:
			(void) snprintf(buf, FM_MAX_CLASS, "UNKNOWN");
			break;
	}

	hcelem = fm_nvlist_create(NULL);

	(void) nvlist_add_string(hcelem, FM_FMRI_HC_NAME, FM_FMRI_LEGACY_HC);
	(void) nvlist_add_string(hcelem, FM_FMRI_HC_ID, buf);

	(void) nvlist_add_uint8(detector, FM_VERSION, FM_HC_SCHEME_VERSION);
	(void) nvlist_add_string(detector, FM_FMRI_SCHEME, FM_FMRI_SCHEME_HC);
	(void) nvlist_add_string(detector, FM_FMRI_HC_ROOT, "");
	(void) nvlist_add_uint32(detector, FM_FMRI_HC_LIST_SZ, 1);
	(void) nvlist_add_nvlist_array(detector, FM_FMRI_HC_LIST, &hcelem, 1);

	/* build ereport class name */
	(void) snprintf(buf, FM_MAX_CLASS, "asic.serengeti.%s.%s-%s",
		dperrtype[dpmsg->type], dperrtype[dpmsg->type],
		FM_ERROR_DATAPATH);

	fm_ereport_set(erp, FM_EREPORT_VERSION, buf,
		fm_ena_generate(0, FM_ENA_FMT1), detector, NULL);

	/* add payload elements */
	if (msgtype == MBOX_EVENT_DP_ERROR)
		fm_payload_set(erp,
			DP_EREPORT_TYPE, DATA_TYPE_UINT16, DP_ERROR, NULL);
	else
		fm_payload_set(erp,
			DP_EREPORT_TYPE, DATA_TYPE_UINT16, DP_FAULT, NULL);

	fm_payload_set(erp, DP_TVALUE, DATA_TYPE_UINT32, dpmsg->t_value, NULL);

	(void) dp_payload_add_cpus(dpmsg, erp);

	/* post ereport */
	fm_ereport_post(erp, EVCH_SLEEP);

	/* free ereport memory */
	fm_nvlist_destroy(erp, FM_NVA_FREE);
	fm_nvlist_destroy(detector, FM_NVA_FREE);

	return (DDI_INTR_CLAIMED);
}

static uint_t
sbbc_datapath_error_msg_handler(char *arg)
{
	static fn_t	f = "sbbc_datapath_error_msg_handler()";
	sbbc_msg_t	*msg = NULL;

	if (arg == NULL) {
		SGSBBC_DBG_EVENT(CE_NOTE, "%s: arg == NULL", f);
		return (DDI_INTR_UNCLAIMED);
	}

	msg = (sbbc_msg_t *)arg;

	if (msg->msg_buf == NULL) {
		SGSBBC_DBG_EVENT(CE_NOTE, "%s: msg_buf == NULL", f);
		return (DDI_INTR_UNCLAIMED);
	}

	msg->msg_type.type = MBOX_EVENT_DP_ERROR;

	/* trigger sbbc_dp_trans_event() */
	ddi_trigger_softintr(dp_softintr_id);

	return (DDI_INTR_CLAIMED);
}

static uint_t
sbbc_datapath_fault_msg_handler(char *arg)
{

	static fn_t	f = "sbbc_datapath_fault_msg_handler()";

	sbbc_msg_t		*msg = NULL;

	if (arg == NULL) {
		SGSBBC_DBG_EVENT(CE_NOTE, "%s: arg == NULL", f);
		return (DDI_INTR_UNCLAIMED);
	}

	msg = (sbbc_msg_t *)arg;

	if (msg->msg_buf == NULL) {
		SGSBBC_DBG_EVENT(CE_NOTE, "%s: msg_buf == NULL", f);
		return (DDI_INTR_UNCLAIMED);
	}

	msg->msg_type.type = MBOX_EVENT_DP_FAULT;

	/* trigger sbbc_dp_trans_event() */
	ddi_trigger_softintr(dp_softintr_id);

	return (DDI_INTR_CLAIMED);
}

/*
 * Log an ECC event message to the SC.  This is called from the
 * sbbc_ecc_mbox_taskq or directly from plat_send_ecc_mailbox_msg
 * for indictment messages.
 */
int
sbbc_mbox_ecc_output(sbbc_ecc_mbox_t *msgp)
{
	int				rv;
	plat_capability_data_t		*cap;
	plat_dimm_sid_board_data_t	*ddata;
	plat_ecc_msg_hdr_t		*hdr;

	rv = sbbc_mbox_request_response(&msgp->ecc_req, &msgp->ecc_resp,
		sbbc_mbox_default_timeout);

	if (rv != 0) {
		/*
		 * Indictment messages use the return value to indicate a
		 * problem in the mailbox.  For Error mailbox messages, we'll
		 * have to use a syslog message.
		 */
		if (msgp->ecc_log_error) {
			if (sbbc_ecc_mbox_send_errs == 0) {
				cmn_err(CE_NOTE, "!Solaris failed to send a "
				    "message (0x%x/0x%x) to the System "
				    "Controller. Error: %d, Message Status: %d",
				    msgp->ecc_resp.msg_type.type,
				    msgp->ecc_resp.msg_type.sub_type,
				    rv, msgp->ecc_resp.msg_status);
			}

			if (++sbbc_ecc_mbox_send_errs >=
			    sbbc_ecc_mbox_err_throttle) {
				sbbc_ecc_mbox_send_errs = 0;
			}
		}

	} else if (msgp->ecc_resp.msg_status != 0) {
		if (msgp->ecc_resp.msg_type.type == INFO_MBOX) {
			switch (msgp->ecc_resp.msg_type.sub_type) {
			case INFO_MBOX_ECC:
				hdr = (plat_ecc_msg_hdr_t *)
				    msgp->ecc_req.msg_buf;
				if (hdr->emh_msg_type ==
				    PLAT_ECC_DIMM_SID_MESSAGE) {
					rv = msgp->ecc_resp.msg_status;
					break;
				}
			/*FALLTHROUGH*/
			case INFO_MBOX_ECC_CAP:
				/*
				 * The positive response comes only
				 * from the AVL FS1 updated SC.
				 * If the firmware is either downgraded
				 * or failover to an older version, then
				 * lets reset the SC capability to
				 * default.
				 */
				plat_ecc_capability_sc_set
				    (PLAT_ECC_CAPABILITY_SC_DEFAULT);
				break;
			default:
				break;
			}
		}
		if (msgp->ecc_log_error) {
			if (sbbc_ecc_mbox_inval_errs == 0) {
				cmn_err(CE_NOTE, "!An internal error (%d) "
				    "occurred in the System Controller while "
				    "processing this message (0x%x/0x%x)",
				    msgp->ecc_resp.msg_status,
				    msgp->ecc_resp.msg_type.type,
				    msgp->ecc_resp.msg_type.sub_type);
			}
			if (msgp->ecc_resp.msg_status == EINVAL) {
				if (++sbbc_ecc_mbox_inval_errs >=
				    sbbc_ecc_mbox_err_throttle) {
					sbbc_ecc_mbox_inval_errs = 0;
				}
				rv = ENOMSG;
			} else {
				if (++sbbc_ecc_mbox_other_errs >=
				    sbbc_ecc_mbox_err_throttle) {
					sbbc_ecc_mbox_other_errs = 0;
				}
				rv = msgp->ecc_resp.msg_status;
			}
		}

	} else {
		if (msgp->ecc_resp.msg_type.type == INFO_MBOX) {
			switch (msgp->ecc_resp.msg_type.sub_type) {
			case INFO_MBOX_ECC_CAP:
				/*
				 * Successfully received the response
				 * for the capability message, so updating
				 * the SC ECC messaging capability.
				 */
				cap = (plat_capability_data_t *)
				    msgp->ecc_resp.msg_buf;
				plat_ecc_capability_sc_set
				    (cap->capd_capability);
				break;

			case INFO_MBOX_ECC:
				hdr = (plat_ecc_msg_hdr_t *)
				    msgp->ecc_resp.msg_buf;
				if (hdr && (hdr->emh_msg_type ==
				    PLAT_ECC_DIMM_SID_MESSAGE)) {
					/*
					 * Successfully received a response
					 * to a request for DIMM serial ids.
					 */
					ddata = (plat_dimm_sid_board_data_t *)
					    msgp->ecc_resp.msg_buf;
					(void) plat_store_mem_sids(ddata);
				}
				break;

			default:
				break;
			}
		}
	}

	if (msgp->ecc_resp.msg_buf)
		kmem_free((void *)msgp->ecc_resp.msg_buf,
		    (size_t)msgp->ecc_resp.msg_len);

	kmem_free((void *)msgp->ecc_req.msg_buf, (size_t)msgp->ecc_req.msg_len);
	kmem_free(msgp, sizeof (sbbc_ecc_mbox_t));
	return (rv);
}

/*
 * Enqueue ECC event message on taskq to SC.  This is invoked from
 * plat_send_ecc_mailbox_msg() for each ECC event generating a message.
 */
void
sbbc_mbox_queue_ecc_event(sbbc_ecc_mbox_t *sbbc_ecc_msgp)
{
	/*
	 * Create the ECC event mailbox taskq, if it does not yet exist.
	 * This must be done here rather than in sbbc_mbox_init().  The
	 * sgsbbc driver is loaded very early in the boot flow.  Calling
	 * taskq_create() from sbbc_mbox_init could lead to a boot deadlock.
	 *
	 * There might be a tiny probability that two ECC handlers on
	 * different processors could arrive here simultaneously.  If
	 * the taskq has not been created previously, then these two
	 * simultaneous events could cause the creation of an extra taskq.
	 * Given the extremely small likelihood (if not outright impossibility)
	 * of this occurrence, sbbc_ecc_mbox_taskq is not protected by a lock.
	 */

	if (sbbc_ecc_mbox_taskq == NULL) {
		sbbc_ecc_mbox_taskq = taskq_create("ECC_event_mailbox", 1,
		    minclsyspri, ECC_MBOX_TASKQ_MIN, ECC_MBOX_TASKQ_MAX,
		    TASKQ_PREPOPULATE);
		if (sbbc_ecc_mbox_taskq == NULL) {
			if (sbbc_ecc_mbox_taskq_errs == 0) {
				cmn_err(CE_NOTE, "Unable to create mailbox "
				    "task queue for ECC event logging to "
				    "System Controller");
			}
			if (++sbbc_ecc_mbox_taskq_errs >=
			    sbbc_ecc_mbox_err_throttle) {
				sbbc_ecc_mbox_taskq_errs = 0;
			}

			kmem_free((void *)sbbc_ecc_msgp->ecc_req.msg_buf,
				(size_t)sbbc_ecc_msgp->ecc_req.msg_len);
			kmem_free((void *)sbbc_ecc_msgp,
				sizeof (sbbc_ecc_mbox_t));
			return;
		}

		/*
		 * Reset error counter so that first taskq_dispatch
		 * error will be output
		 */
		sbbc_ecc_mbox_taskq_errs = 0;
	}

	/*
	 * Enqueue the message
	 */

	if (taskq_dispatch(sbbc_ecc_mbox_taskq,
	    (task_func_t *)sbbc_mbox_ecc_output, sbbc_ecc_msgp,
	    TQ_NOSLEEP) == TASKQID_INVALID) {

		if (sbbc_ecc_mbox_taskq_errs == 0) {
			cmn_err(CE_NOTE, "Unable to send ECC event "
				"message to System Controller");
		}
		if (++sbbc_ecc_mbox_taskq_errs >= sbbc_ecc_mbox_err_throttle) {
			sbbc_ecc_mbox_taskq_errs = 0;
		}

		kmem_free((void *)sbbc_ecc_msgp->ecc_req.msg_buf,
				(size_t)sbbc_ecc_msgp->ecc_req.msg_len);
		kmem_free((void *)sbbc_ecc_msgp, sizeof (sbbc_ecc_mbox_t));
	}
}

static uint_t
cap_ecc_msg_handler(char *addr)
{
	sbbc_msg_t *msg = NULL;
	plat_capability_data_t *cap = NULL;
	static fn_t f = "cap_ecc_msg_handler";

	msg = (sbbc_msg_t *)addr;

	if (msg == NULL) {
		SGSBBC_DBG_EVENT(CE_WARN, "cap_ecc_msg_handler() called with "
		    "null addr");
		return (DDI_INTR_CLAIMED);
	}

	if (msg->msg_buf == NULL) {
		SGSBBC_DBG_EVENT(CE_WARN, "cap_ecc_msg_handler() called with "
		    "null data buffer");
		return (DDI_INTR_CLAIMED);
	}

	cap = (plat_capability_data_t *)msg->msg_buf;
	switch (cap->capd_msg_type) {
	case PLAT_ECC_CAPABILITY_MESSAGE:
		SGSBBC_DBG_MBOX("%s: capability  0x%x\n", f,
		    cap->capd_capability);
		plat_ecc_capability_sc_set(cap->capd_capability);
		break;
	default:
		SGSBBC_DBG_MBOX("%s: Unknown message type = 0x%x\n", f,
		    cap->capd_msg_type);
		break;
	}

	return (DDI_INTR_CLAIMED);
}
