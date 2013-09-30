/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (C) 2013 Hewlett-Packard Development Company, L.P.
 */

#include "cpqary3.h"

/*
 * Function	: 	cpqary3_hw_isr
 * Description	: 	This routine determines if this instance of the
 * 			HBA interrupted and if positive triggers a software
 *			interrupt.
 *			For SAS controllers which operate in performant mode
 *			we clear the interrupt.
 *			For CISS controllers which operate in simple mode
 *			we get the tag value.
 * Called By	: 	kernel
 * Parameters	: 	per-controller
 * Calls	: 	cpqary3_check_ctlr_intr()
 * Return Values: 	DDI_INTR_CLAIMED/UNCLAIMED
 *			[We either CLAIM the interrupt or Discard it]
 */
uint_t
cpqary3_hw_isr(caddr_t per_ctlr)
{
	uint8_t			need_swintr;
	cpqary3_t		*cpqary3p;
	cpqary3_drvr_replyq_t	*replyq_ptr;
	volatile CfgTable_t	*ctp;
	uint32_t		spr0;
	uint32_t		doorbell_status;
	uint32_t		tag;

	cpqary3p = (void *)per_ctlr;
	ctp = (CfgTable_t *)cpqary3p->ct;
	replyq_ptr = (cpqary3_drvr_replyq_t *)cpqary3p->drvr_replyq;

	if (CPQARY3_FAILURE == cpqary3p->check_ctlr_intr(cpqary3p)) {
		if (cpqary3p->heartbeat ==
		    DDI_GET32(cpqary3p, &ctp->HeartBeat)) {
			if (0x2 & ddi_get32(cpqary3p->odr_handle,
			    (uint32_t *)cpqary3p->odr)) {
				spr0 = ddi_get32(cpqary3p->spr0_handle,
				    (uint32_t *)cpqary3p->spr0);
				spr0 = spr0 >> 16;
				cmn_err(CE_WARN, "CPQary3 : %s HBA firmware "
				    "Locked !!!  Lockup Code: 0x%x",
				    cpqary3p->hba_name, spr0);
				cmn_err(CE_WARN, "CPQary3 : Please reboot "
				    "the system");
				ddi_put32(cpqary3p->odr_cl_handle,
				    (uint32_t *)cpqary3p->odr_cl, 0x2);
				cpqary3_intr_onoff(cpqary3p,
				    CPQARY3_INTR_DISABLE);
				if (cpqary3p->host_support & 0x4) {
					cpqary3_lockup_intr_onoff(cpqary3p,
					    CPQARY3_LOCKUP_INTR_DISABLE);
				}
				cpqary3p->controller_lockup = CPQARY3_TRUE;
			}
			return (DDI_INTR_CLAIMED);
		}
		return (DDI_INTR_UNCLAIMED);
	}

	/* PERF */

	/*
	 * We decided that we will have only one retrieve function for
	 * both simple and performant mode. To achieve this we have to mimic
	 * what controller does for performant mode in simple mode.
	 * For simple mode we are making replq_simple_ptr and
	 * replq_headptr of performant
	 * mode point to the same location in the reply queue.
	 * For the performant mode, we clear the interrupt
	 */

	if (!(cpqary3p->bddef->bd_flags & SA_BD_SAS)) {
		while ((tag = ddi_get32(cpqary3p->opq_handle,
		    (uint32_t *)cpqary3p->opq)) != 0xFFFFFFFF) {
			replyq_ptr->replyq_simple_ptr[0] = tag;
			replyq_ptr->replyq_simple_ptr[0] |=
			    replyq_ptr->simple_cyclic_indicator;
			++replyq_ptr->simple_index;

			if (replyq_ptr->simple_index == replyq_ptr->max_index) {
				replyq_ptr->simple_index = 0;
				/* Toggle at wraparound */
				replyq_ptr->simple_cyclic_indicator =
				    (replyq_ptr->simple_cyclic_indicator == 0) ?
				    1 : 0;
				replyq_ptr->replyq_simple_ptr =
				    /* LINTED: alignment */
				    (uint32_t *)(replyq_ptr->replyq_start_addr);
			} else {
				replyq_ptr->replyq_simple_ptr += 2;
			}
		}
	} else {
		doorbell_status = ddi_get32(cpqary3p->odr_handle,
		    (uint32_t *)cpqary3p->odr);
		if (doorbell_status & 0x1) {
			ddi_put32(cpqary3p->odr_cl_handle,
			    (uint32_t *)cpqary3p->odr_cl,
			    (ddi_get32(cpqary3p->odr_cl_handle,
			    (uint32_t *)cpqary3p->odr_cl) | 0x1));
			doorbell_status = ddi_get32(cpqary3p->odr_handle,
			    (uint32_t *)cpqary3p->odr);
		}
	}

	/* PERF */

	/*
	 * If s/w interrupt handler is already running, do not trigger another
	 * since packets have already been transferred to Retrieved Q.
	 * Else, Set swintr_flag to state to the s/w interrupt handler
	 * that it has a job to do.
	 * trigger the s/w interrupt handler
	 * Claim the interrupt
	 */

	mutex_enter(&cpqary3p->hw_mutex);

	if (cpqary3p->swintr_flag == CPQARY3_TRUE) {
		need_swintr = CPQARY3_FALSE;
	} else {
		need_swintr = CPQARY3_TRUE;
		cpqary3p->swintr_flag = CPQARY3_TRUE;
	}

	mutex_exit(&cpqary3p->hw_mutex);

	if (CPQARY3_TRUE == need_swintr)
		ddi_trigger_softintr(cpqary3p->cpqary3_softintr_id);

	return (DDI_INTR_CLAIMED);
}

/*
 * Function	:	cpqary3_sw_isr
 * Description	:	This routine determines if this instance of the
 * 			software interrupt handler was triggered by its
 * 			respective h/w interrupt handler and if affermative
 * 			processes the completed commands.
 * Called By	:	kernel (Triggered by : cpqary3_hw_isr)
 * Parameters	:	per-controller
 * Calls	:	cpqary3_retrieve()
 * Return Values: 	DDI_INTR_CLAIMED/UNCLAIMED
 *			[We either CLAIM the interrupr or DON'T]
 */
uint_t
cpqary3_sw_isr(caddr_t per_ctlr)
{
	cpqary3_t	*cpqary3p;

	cpqary3p = (void *)per_ctlr;
	if (!cpqary3p) {
		cmn_err(CE_PANIC, "CPQary3 : Software Interrupt Service "
		    "Routine invoked with NULL pointer argument \n");
	}

	/*
	 * Ensure that our hardware routine actually triggered this routine.
	 * If it was not the case, do NOT CLAIM the interrupt
	 */

	mutex_enter(&cpqary3p->hw_mutex);
	if (CPQARY3_TRUE != cpqary3p->swintr_flag) {
		mutex_exit(&cpqary3p->hw_mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	cpqary3p->swintr_flag = CPQARY3_FALSE;

	/* PERF */
	mutex_exit(&cpqary3p->hw_mutex);
	(void) cpqary3_retrieve(cpqary3p);
	/* PERF */

	return (DDI_INTR_CLAIMED);
}
