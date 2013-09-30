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

/*
 * This module contains routines that program the controller. All
 * operations  viz.,  initialization of  controller,  submision &
 * retrieval  of  commands, enabling &  disabling of  interrupts,
 * checking interrupt status are performed here.
 */

#include <sys/sdt.h>
#include "cpqary3.h"

/*
 * Local Functions Definitions
 */
uint8_t cpqary3_check_simple_ctlr_intr(cpqary3_t *cpqary3p);
uint8_t cpqary3_check_perf_ctlr_intr(cpqary3_t *cpqary3p);
uint8_t cpqary3_check_perf_e200_intr(cpqary3_t *cpqary3p);
uint8_t cpqary3_check_ctlr_init(cpqary3_t *);

/*
 * Function	: 	cpqary3_check_simple_ctlr_intr
 * Description	: 	This routine determines if the controller did interrupt.
 * Called By	: 	cpqary3_hw_isr()
 * Parameters	: 	per-controller
 * Calls	: 	None
 * Return Values: 	SUCCESS : This controller did interrupt.
 *			FAILURE : It did not.
 */
uint8_t
cpqary3_check_simple_ctlr_intr(cpqary3_t *cpqary3p)
{
	uint32_t	intr_pending_mask = 0;

	/*
	 * Read the Interrupt Status Register and
	 * if bit 3 is set, it indicates that we have completed commands
	 * in the controller
	 */
	intr_pending_mask = cpqary3p->bddef->bd_intrpendmask;

	if (intr_pending_mask &
	    (ddi_get32(cpqary3p->isr_handle, (uint32_t *)cpqary3p->isr)))
		return (CPQARY3_SUCCESS);

	return (CPQARY3_FAILURE);
}

/*
 * Function	:      	cpqary3_check_perf_ctlr_intr
 * Description	:      	This routine determines if the
 *			controller did interrupt.
 * Called By	:      	cpqary3_hw_isr()
 * Parameters	:      	per-controller
 * Calls	:      	None
 * Return Values:      	SUCCESS : This controller did interrupt.
 *			FAILURE : It did not.
 */
uint8_t
cpqary3_check_perf_ctlr_intr(cpqary3_t *cpqary3p)
{
	/*
	 * Read the Interrupt Status Register and
	 * if bit 3 is set, it indicates that we have completed commands
	 * in the controller
	 */
	if (0x1 & (ddi_get32(cpqary3p->isr_handle,
	    (uint32_t *)cpqary3p->isr))) {
		return (CPQARY3_SUCCESS);
	}

	return (CPQARY3_FAILURE);
}

/*
 * Function	:      	cpqary3_check_perf_e200_intr
 * Description	:      	This routine determines if the controller
 *			did interrupt.
 * Called By	:      	cpqary3_hw_isr()
 * Parameters	:      	per-controller
 * Calls	:      	None
 * Return Values:      	SUCCESS : This controller did interrupt.
 *			FAILURE : It did not.
 */
uint8_t
cpqary3_check_perf_e200_intr(cpqary3_t *cpqary3p)
{
	/*
	 * Read the Interrupt Status Register and
	 * if bit 3 is set, it indicates that we have completed commands
	 * in the controller
	 */
	if (0x4 & (ddi_get32(cpqary3p->isr_handle,
	    (uint32_t *)cpqary3p->isr))) {
		return (CPQARY3_SUCCESS);
	}

	return (CPQARY3_FAILURE);
}


/*
 * Function	: 	cpqary3_retrieve
 * Description	: 	This routine retrieves the completed command from the
 *			controller reply queue.
 *			and processes the completed commands.
 * Called By	:  	cpqary3_sw_isr(), cpqary3_handle_flag_nointr()
 * Parameters	: 	per-controller
 * Calls	: 	packet completion routines
 * Return Values: 	SUCCESS : A completed command has been retrieved
 *			and processed.
 *			FAILURE : No completed command was in the controller.
 */
uint8_t
cpqary3_retrieve(cpqary3_t *cpqary3p)
{
	uint32_t			tag;
	uint32_t			CmdsOutMax;
	cpqary3_cmdpvt_t		*cpqary3_cmdpvtp;
	cpqary3_drvr_replyq_t		*replyq_ptr;

	/*
	 * Get the Reply Command List Addr
	 * Update the returned Tag in that particular command structure.
	 * If a valid one, de-q that from the SUBMITTED Q and
	 * enqueue that to the RETRIEVED Q.
	 */

	RETURN_FAILURE_IF_NULL(cpqary3p);

	/* PERF */
	replyq_ptr = (cpqary3_drvr_replyq_t *)cpqary3p->drvr_replyq;
	CmdsOutMax = cpqary3p->ctlr_maxcmds;

	while ((replyq_ptr->replyq_headptr[0] & 0x01) ==
	    replyq_ptr->cyclic_indicator) {
		/* command has completed */
		/* Get the tag */

		tag = replyq_ptr->replyq_headptr[0];
		if ((tag >> CPQARY3_GET_MEM_TAG) >= (CmdsOutMax / 3) * 3) {
			cmn_err(CE_WARN,
			    "CPQary3 : HBA returned Spurious Tag");
			return (CPQARY3_FAILURE);
		}

		cpqary3_cmdpvtp = &cpqary3p->cmdmemlistp->pool[
		    tag >> CPQARY3_GET_MEM_TAG];
		cpqary3_cmdpvtp->cmdlist_memaddr->
		    Header.Tag.drvinfo_n_err = (tag & 0xF) >> 1;
		mutex_enter(&cpqary3p->sw_mutex);
		cpqary3_cmdpvtp->complete(cpqary3_cmdpvtp);
		mutex_exit(&cpqary3p->sw_mutex);

		/* Traverse to the next command in reply queue */

		++replyq_ptr->index;
		if (replyq_ptr->index == replyq_ptr->max_index) {
			replyq_ptr->index = 0;
			/* Toggle at wraparound */
			replyq_ptr->cyclic_indicator =
			    (replyq_ptr->cyclic_indicator == 0) ? 1 : 0;
			replyq_ptr->replyq_headptr =
			    /* LINTED: alignment */
			    (uint32_t *)(replyq_ptr->replyq_start_addr);
		} else {
			replyq_ptr->replyq_headptr += 2;
		}
	}
	/* PERF */

	return (CPQARY3_SUCCESS);
}


/*
 * Function	:  cpqary3_poll_retrieve
 * Description	:  This routine retrieves the completed command from the
 *			controller reply queue in poll mode.
 *			and processes the completed commands.
 * Called By	:  cpqary3_poll
 * Parameters	:  per-controller
 * Calls	:  packet completion routines
 * Return Values:  If the polled command is completed, send back a success.
 *			If not return failure.
 */
uint8_t
cpqary3_poll_retrieve(cpqary3_t *cpqary3p, uint32_t poll_tag)
{
	uint32_t			tag;
	uint32_t			CmdsOutMax;
	cpqary3_cmdpvt_t		*cpqary3_cmdpvtp;
	cpqary3_drvr_replyq_t		*replyq_ptr;
	uint32_t			temp_tag;
	uint8_t				tag_flag = 0;

	RETURN_FAILURE_IF_NULL(cpqary3p);

	/* PERF */
	replyq_ptr = (cpqary3_drvr_replyq_t *)cpqary3p->drvr_replyq;
	CmdsOutMax = cpqary3p->cmdmemlistp->max_memcnt;

	if (!(cpqary3p->bddef->bd_flags & SA_BD_SAS)) {
		while ((tag = ddi_get32(cpqary3p->opq_handle,
		    (uint32_t *)cpqary3p->opq)) != 0xFFFFFFFF) {
			cpqary3_cmdpvtp = &cpqary3p->cmdmemlistp->pool[
			    tag >> CPQARY3_GET_MEM_TAG];
			cpqary3_cmdpvtp->cmdlist_memaddr->
			    Header.Tag.drvinfo_n_err = (tag & 0xF) >> 1;
			temp_tag = cpqary3_cmdpvtp->tag.tag_value;

			if (temp_tag == poll_tag)
				tag_flag = 1;
			cpqary3_cmdpvtp->complete(cpqary3_cmdpvtp);
		}
	} else {
		while ((replyq_ptr->replyq_headptr[0] & 0x01) ==
		    replyq_ptr->cyclic_indicator) {
			/* command has completed */
			/* Get the tag */
			tag = replyq_ptr->replyq_headptr[0];

			if ((tag >> CPQARY3_GET_MEM_TAG) >= (CmdsOutMax/3)*3) {
				cmn_err(CE_WARN,
				    "CPQary3 : HBA returned Spurious Tag");
				return (CPQARY3_FAILURE);
			}

			cpqary3_cmdpvtp = &cpqary3p->cmdmemlistp->pool[
			    tag >> CPQARY3_GET_MEM_TAG];
			cpqary3_cmdpvtp->cmdlist_memaddr->
			    Header.Tag.drvinfo_n_err = (tag & 0xF) >> 1;
			temp_tag = cpqary3_cmdpvtp->tag.tag_value;

			if (temp_tag == poll_tag)
				tag_flag = 1;

			cpqary3_cmdpvtp->complete(cpqary3_cmdpvtp);

			/* Traverse to the next command in reply queue */
			++replyq_ptr->index;
			if (replyq_ptr->index == replyq_ptr->max_index) {
				replyq_ptr->index = 0;
				/* Toggle at wraparound */
				replyq_ptr->cyclic_indicator =
				    (replyq_ptr->cyclic_indicator == 0) ? 1 : 0;
				replyq_ptr->replyq_headptr =
				    /* LINTED: alignment */
				    (uint32_t *)(replyq_ptr->replyq_start_addr);
			} else {
				replyq_ptr->replyq_headptr += 2;
			}
		}
	}
	/* PERF */
	if (tag_flag) {
		return (CPQARY3_SUCCESS);
	}

	return (CPQARY3_FAILURE);
}

/*
 * Function	: 	cpqary3_submit
 * Description	: 	This routine submits the command to the Inbound Post Q.
 * Called By	: 	cpqary3_transport(), cpqary3_send_NOE_command(),
 *			cpqary3_disable_NOE_command(),
 *			cpqary3_handle_flag_nointr(),
 *			cpqary3_tick_hdlr(), cpqary3_synccmd_send()
 * Parameters	: 	per-controller, physical address
 * Calls	: 	None
 * Return Values: 	None
 */
int32_t
cpqary3_submit(cpqary3_t *cpqary3p, uint32_t cmd_phyaddr)
{
	uint32_t		phys_addr = 0;
	uint8_t			retval  = 0;

	/*
	 * Write the Physical Address of the command-to-be-submitted
	 * into the Controller's Inbound Post Q.
	 */

	ASSERT(cpqary3p != NULL);

#ifdef AMD64_DEBUG
	{
	char		debug_char;
	uint32_t	tmp_cmd_phyaddr;

	tmp_cmd_phyaddr = (uint32_t)(cmd_phyaddr & 0XFFFFFFFF);

	cmn_err(CE_WARN, "CPQary3: cmd_phyaddr = %lX\n tmp_cmd_phyaddr = %lX",
	    cmd_phyaddr, tmp_cmd_phyaddr);

	debug_enter(&debug_char);
	ddi_put32(cpqary3p->ipq_handle, (uint32_t *)cpqary3p->ipq, cmd_phyaddr);
	}
#endif


	/* CONTROLLER_LOCKUP */
	if (cpqary3p->controller_lockup == CPQARY3_TRUE) {
		retval = EIO;
		return (retval);
	}
	/* CONTROLLER_LOCKUP */

	if (!(cpqary3p->bddef->bd_flags & SA_BD_SAS)) {
		ddi_put32(cpqary3p->ipq_handle,
		    (uint32_t *)cpqary3p->ipq, cmd_phyaddr);
	} else {
		/* The driver always uses the 0th block fetch count always */
		phys_addr = cmd_phyaddr | 0 | 0x1;
		ddi_put32(cpqary3p->ipq_handle,
		    (uint32_t *)cpqary3p->ipq, phys_addr);
	}

	/* PERF */

	/*
	 * Command submission can NEVER FAIL since the number of commands that
	 * can reside in the controller at any time is 1024 and our memory
	 * allocation is for 225 commands ONLY. Thus, at any given time the
	 * maximum number of commands in the controller is 225.
	 */

	/* CONTROLLER_LOCKUP */
	return (retval);
	/* CONTROLLER_LOCKUP */

}


/*
 * Function	: 	cpqary3_intr_onoff
 * Description	: 	This routine enables/disables the HBA interrupt.
 * Called By	: 	cpqary3_attach(), ry3_handle_flag_nointr(),
 *			cpqary3_tick_hdlr(), cpqary3_init_ctlr_resource()
 * Parameters	: 	per-controller, flag stating enable/disable
 * Calls	: 	None
 * Return Values: 	None
 */
void
cpqary3_intr_onoff(cpqary3_t *cpqary3p, uint8_t flag)
{
	uint32_t	intr = 0;
	uint32_t	intr_mask = 0;

	/*
	 * Enable or disable the interrupt based on the flag
	 * Read the Interrupt Mask Register first and then update it
	 * accordingly
	 */

	ASSERT(cpqary3p != NULL);

	intr = ddi_get32(cpqary3p->imr_handle, (uint32_t *)cpqary3p->imr);
	intr_mask = cpqary3p->bddef->bd_intrmask;

	if (flag == CPQARY3_INTR_ENABLE) {
		ddi_put32(cpqary3p->imr_handle,
		    (uint32_t *)cpqary3p->imr, intr & ~(intr_mask));
	} else {
		ddi_put32(cpqary3p->imr_handle,
		    (uint32_t *)cpqary3p->imr, (intr | intr_mask));
	}
}


/*
 * Function	: 	cpqary3_lockup_intr_onoff
 * Description	: 	This routine enables/disables the lockup interrupt.
 * Called By	: 	cpqary3_attach(), cpqary3_handle_flag_nointr(),
 *			cpqary3_tick_hdlr(), cpqary3_hw_isr,
 *			cpqary3_init_ctlr_resource()
 * Parameters	: 	per-controller, flag stating enable/disable
 * Calls	: 	None
 * Return Values: 	None
 */
void
cpqary3_lockup_intr_onoff(cpqary3_t *cpqary3p, uint8_t flag)
{
	uint32_t	intr = 0;
	uint32_t	intr_lockup_mask = 0;

	/*
	 * Enable or disable the interrupt based on the flag
	 * Read the Interrupt Mask Register first and then update it
	 * accordingly
	 */

	ASSERT(cpqary3p != NULL);

	intr = ddi_get32(cpqary3p->imr_handle, (uint32_t *)cpqary3p->imr);
	intr_lockup_mask = cpqary3p->bddef->bd_lockup_intrmask;

	if (flag == CPQARY3_INTR_ENABLE) {
		ddi_put32(cpqary3p->imr_handle,
		    (uint32_t *)cpqary3p->imr, intr & ~(intr_lockup_mask));
	} else {
		ddi_put32(cpqary3p->imr_handle,
		    (uint32_t *)cpqary3p->imr, (intr | intr_lockup_mask));
	}
}

/*
 * Function	: 	cpqary3_init_ctlr
 * Description	: 	This routine initialises the HBA to Simple Transport
 *			Method. Refer to CISS for more information.
 *			It checks the readiness of the HBA.
 * Called By	: 	cpqary3_init_ctlr_resource()
 * Parameters	: 	per-controller(), physical address()
 * Calls	: 	cpqary3_check_ctlr_init
 * Return Values: 	SUCCESS / FAILURE
 *			[Shall return failure if the initialization of the
 *			controller to the Simple Transport Method fails]
 */
uint8_t
cpqary3_init_ctlr(cpqary3_t *cpqary3p)
{
	uint8_t				cntr;
	uint8_t				signature[4] = { 'C', 'I', 'S', 'S' };
	volatile CfgTable_t		*ctp;
	volatile CfgTrans_Perf_t	*perf_cfg;
	cpqary3_phyctg_t		*cpqary3_phyctgp;
	uint32_t			phy_addr;
	size_t				cmd_size;
	uint32_t			queue_depth;
	uint32_t			CmdsOutMax;
	uint32_t			BlockFetchCnt[8];
	caddr_t				replyq_start_addr = NULL;
	/* SG */
	uint32_t			max_blk_fetch_cnt = 0;
	uint32_t			max_sg_cnt = 0;
	uint32_t			optimal_sg = 0;
	uint32_t			optimal_sg_size = 0;
	/* Header + Request + Error */
	uint32_t			size_of_HRE = 0;
	uint32_t			size_of_cmdlist = 0;
	/* SG */

	RETURN_FAILURE_IF_NULL(cpqary3p);
	ctp = (CfgTable_t *)cpqary3p->ct;
	perf_cfg = (CfgTrans_Perf_t *)cpqary3p->cp;

	/* QUEUE CHANGES */
	cpqary3p->drvr_replyq =
	    (cpqary3_drvr_replyq_t *)MEM_ZALLOC(sizeof (cpqary3_drvr_replyq_t));
	/* QUEUE CHANGES */

	if (!cpqary3_check_ctlr_init(cpqary3p))
		return (CPQARY3_FAILURE);

	DTRACE_PROBE1(ctlr_init_start, CfgTable_t *, ctp);

	/*
	 * Validate the signature - should be "CISS"
	 * Use of cntr in the for loop does not suggest a counter - it just
	 * saves declaration of another variable.
	 */

	for (cntr = 0; cntr < 4; cntr++) {
		if (DDI_GET8(cpqary3p, &ctp->Signature[cntr]) !=
		    signature[cntr]) {
			cmn_err(CE_WARN, "CPQary3 : Controller NOT ready");
			cmn_err(CE_WARN, "CPQary3 : _cpqary3_init_ctlr : "
			    "Signature not stamped");
			return (CPQARY3_FAILURE);
		}
	}


	if (!(cpqary3p->bddef->bd_flags & SA_BD_SAS)) {
		CmdsOutMax = DDI_GET32(cpqary3p, &ctp->CmdsOutMax);

		if (CmdsOutMax == 0) {
			cmn_err(CE_CONT, "CPQary3 : HBA Maximum Outstanding "
			    "Commands set to Zero\n");
			cmn_err(CE_CONT, "CPQary3 : Cannot continue driver "
			    "initialization \n");
			return (CPQARY3_FAILURE);
		}

		cpqary3p->ctlr_maxcmds = CmdsOutMax;
		cpqary3p->sg_cnt = CPQARY3_SG_CNT;

		queue_depth = cpqary3p->ctlr_maxcmds;
		cmd_size = (8 * queue_depth);
		/* QUEUE CHANGES */
		cpqary3p->drvr_replyq->cyclic_indicator =
		    CPQARY3_REPLYQ_INIT_CYCLIC_IND;
		cpqary3p->drvr_replyq->simple_cyclic_indicator =
		    CPQARY3_REPLYQ_INIT_CYCLIC_IND;
		cpqary3p->drvr_replyq->max_index = cpqary3p->ctlr_maxcmds;
		cpqary3p->drvr_replyq->simple_index = 0;
		replyq_start_addr = MEM_ZALLOC(cmd_size);
		bzero(replyq_start_addr, cmd_size);
		cpqary3p->drvr_replyq->replyq_headptr =
		    /* LINTED: alignment */
		    (uint32_t *)replyq_start_addr;
		cpqary3p->drvr_replyq->replyq_simple_ptr =
		    /* LINTED: alignment */
		    (uint32_t *)replyq_start_addr;
		cpqary3p->drvr_replyq->replyq_start_addr = replyq_start_addr;

		/* PERF */

		/*
		 * Check for support of SIMPLE Transport Method
		 */
		if (!(DDI_GET32(cpqary3p, &ctp->TransportSupport) &
		    CFGTBL_XPORT_SIMPLE)) {
			cmn_err(CE_WARN, "CPQary3 : Controller "
			    "NOT YET INITIALIZED");
			cmn_err(CE_CONT, "CPQary3 : For Hot Plug Operations, "
			    "try again later \n");
			return (CPQARY3_FAILURE);
		}

		/*
		 * Configuration Table Initialization
		 * Set bit 0 of InBound Door Bell Reg to inform the controller
		 * about the changes related to the Configuration table
		 */
		DTRACE_PROBE(cfgtable_init_start);

		DDI_PUT32(cpqary3p, &ctp->HostWrite.TransportRequest,
		    CFGTBL_XPORT_SIMPLE);
		ddi_put32(cpqary3p->idr_handle, (uint32_t *)cpqary3p->idr,
		    ddi_get32(cpqary3p->idr_handle, (uint32_t *)cpqary3p->idr) |
		    CFGTBL_CHANGE_REQ);

		/*
		 * Check whether the controller is  ready
		 */

		cntr = 0;
		while (ddi_get32(cpqary3p->idr_handle,
		    (uint32_t *)cpqary3p->idr) & CFGTBL_ACC_CMDS) {
			drv_usecwait(1000000); /* Wait for 1 Sec. */
			cntr++;

			/*
			 * Wait for a maximum of 90 seconds. No f/w should take
			 * more than 90 secs to initialize. If the controller
			 * is not ready even after 90 secs, it suggests that
			 * something is wrong
			 * (wrt the controller, what else) !!!
			 */

			if (cntr > CISS_INIT_TIME) /* 1.30 Mins */ {
				cmn_err(CE_CONT, "CPQary3 : Controller "
				    "Initialization Failed \n");
				return (CPQARY3_FAILURE);
			}
		}

		DTRACE_PROBE(cfgtable_init_done);

		/*
		 * Check whether controller accepts the requested method of
		 * transport
		 */
		if (!(DDI_GET32(cpqary3p, &ctp->TransportActive) &
		    CFGTBL_XPORT_SIMPLE)) {
			cmn_err(CE_CONT, "CPQary3 : Failed to Initialize "
			    "Controller \n");
			cmn_err(CE_CONT, "CPQary3 : For Hot Plug Operations, "
			    "try again later\n");
			return (CPQARY3_FAILURE);
		}

		DTRACE_PROBE(ctlr_init_simple);

		/*
		 * Check if Controller is ready to accept Commands
		 */

		if (!(DDI_GET32(cpqary3p, &ctp->TransportActive) &
		    CFGTBL_ACC_CMDS)) {
			cmn_err(CE_CONT, "CPQary3: Controller NOT ready to "
			    "accept Commands \n");
			return (CPQARY3_FAILURE);
		}

		DTRACE_PROBE(ctlr_init_ready);

		/*
		 * Check if the maximum number of oustanding commands for the
		 * initialized controller is something greater than Zero.
		 */

		CmdsOutMax = DDI_GET32(cpqary3p, &ctp->CmdsOutMax);

		if (CmdsOutMax == 0) {
			cmn_err(CE_CONT, "CPQary3 : HBA Maximum Outstanding "
			    "Commands set to Zero\n");
			cmn_err(CE_CONT, "CPQary3 : Cannot continue driver "
			    "initialization \n");
			return (CPQARY3_FAILURE);
		}
		cpqary3p->ctlr_maxcmds = CmdsOutMax;

		/*
		 * Zero the Upper 32 Address in the Controller
		 */

		DDI_PUT32(cpqary3p, &ctp->HostWrite.Upper32Addr, 0x00000000);
		cpqary3p->heartbeat = DDI_GET32(cpqary3p, &ctp->HeartBeat);

		/* Set the controller interrupt check routine */
		cpqary3p->check_ctlr_intr = cpqary3_check_simple_ctlr_intr;

		cpqary3p->host_support =
		    DDI_GET32(cpqary3p, &ctp->HostDrvrSupport);
		DDI_PUT32(cpqary3p, &ctp->HostDrvrSupport,
		    (cpqary3p->host_support | 0x4));
		cpqary3p->host_support =
		    DDI_GET32(cpqary3p, &ctp->HostDrvrSupport);

		cpqary3p->lockup_logged = CPQARY3_FALSE;
	} else {
	/* PERF */

		/*
		 * Check for support of PERF Transport Method
		 */
		if (!(DDI_GET32(cpqary3p, &ctp->TransportSupport)
		    & CFGTBL_XPORT_PERFORMANT)) {
			cmn_err(CE_WARN, "CPQary3 : Controller "
			    "NOT YET INITIALIZED");
			cmn_err(CE_CONT, "CPQary3 : For Hot Plug Operations, "
			    "try again later \n");
			return (CPQARY3_FAILURE);
		}

		CmdsOutMax = DDI_GET32(cpqary3p, &ctp->MaxPerfModeCmdsOutMax);
		if (CmdsOutMax == 0)
			CmdsOutMax = DDI_GET32(cpqary3p, &ctp->CmdsOutMax);
		if (CmdsOutMax == 0) {
			cmn_err(CE_CONT, "CPQary3 : HBA Maximum Outstanding "
			    "Commands set to Zero\n");
			cmn_err(CE_CONT, "CPQary3 : Cannot continue driver "
			    "initialization \n");
			return (CPQARY3_FAILURE);
		}

		cpqary3p->ctlr_maxcmds = CmdsOutMax;


		/* Initialize the Performant Method Transport Method Table */

		queue_depth = cpqary3p->ctlr_maxcmds;

		DDI_PUT32_CP(cpqary3p, &perf_cfg->ReplyQSize, queue_depth);
		DDI_PUT32_CP(cpqary3p, &perf_cfg->ReplyQCount, 1);
		DDI_PUT32_CP(cpqary3p, &perf_cfg->ReplyQCntrAddrLow32, 0);
		DDI_PUT32_CP(cpqary3p, &perf_cfg->ReplyQCntrAddrHigh32, 0);

		cpqary3_phyctgp =
		    (cpqary3_phyctg_t *)MEM_ZALLOC(sizeof (cpqary3_phyctg_t));

		if (!cpqary3_phyctgp) {
			cmn_err(CE_NOTE,
			    "CPQary3: Initial mem zalloc failed");
			return (CPQARY3_FAILURE);
		}
		cmd_size = (8 * queue_depth);
		phy_addr = 0;
		replyq_start_addr = cpqary3_alloc_phyctgs_mem(cpqary3p,
		    cmd_size, &phy_addr, cpqary3_phyctgp);

		if (!replyq_start_addr) {
			cmn_err(CE_WARN, "MEMALLOC returned failure");
			return (CPQARY3_FAILURE);
		}

		bzero(replyq_start_addr, cmd_size);
		cpqary3p->drvr_replyq->replyq_headptr =
		    /* LINTED: alignment */
		    (uint32_t *)replyq_start_addr;
		cpqary3p->drvr_replyq->index = 0;
		cpqary3p->drvr_replyq->max_index = queue_depth;
		cpqary3p->drvr_replyq->replyq_start_addr = replyq_start_addr;
		cpqary3p->drvr_replyq->cyclic_indicator =
		    CPQARY3_REPLYQ_INIT_CYCLIC_IND;
		cpqary3p->drvr_replyq->replyq_start_paddr = phy_addr;

		DDI_PUT32_CP(cpqary3p, &perf_cfg->ReplyQAddr0Low32, phy_addr);
		DDI_PUT32_CP(cpqary3p, &perf_cfg->ReplyQAddr0High32, 0);

		max_blk_fetch_cnt =
		    DDI_GET32(cpqary3p, &ctp->MaxBlockFetchCount);

		/*
		 * For non-proton FW controllers, max_blk_fetch_count is not
		 * implemented in the firmware
		 */

		/*
		 * When blk fetch count is 0, FW auto fetches 564 bytes
		 * corresponding to an optimal S/G of 31
		 */
		if (max_blk_fetch_cnt == 0) {
			BlockFetchCnt[0] = 35;
		} else {
			/*
			 * With MAX_PERF_SG_CNT set to 64, block fetch count
			 * is got by:(sizeof (CommandList_t) + 15)/16
			 */
			if (max_blk_fetch_cnt > 68)
				BlockFetchCnt[0] = 68;
			else
				BlockFetchCnt[0] = max_blk_fetch_cnt;
		}

		DDI_PUT32_CP(cpqary3p, &perf_cfg->BlockFetchCnt[0],
		    BlockFetchCnt[0]);
		DDI_PUT32(cpqary3p, &ctp->HostWrite.TransportRequest,
		    CFGTBL_XPORT_PERFORMANT);
		ddi_put32(cpqary3p->idr_handle, (uint32_t *)cpqary3p->idr,
		    ddi_get32(cpqary3p->idr_handle, (uint32_t *)cpqary3p->idr) |
		    CFGTBL_CHANGE_REQ);

		/*
		 * Check whether the controller is  ready
		 */

		cntr = 0;
		while (ddi_get32(cpqary3p->idr_handle,
		    (uint32_t *)cpqary3p->idr) & CFGTBL_ACC_CMDS) {
			drv_usecwait(1000000); /* Wait for 1 Sec. */
			cntr++;


			/*
			 * Wait for a maximum of 90 seconds. No f/w should take
			 * more than 90 secs to initialize. If the controller
			 * is not ready even after 90 secs, it suggests that
			 * something is wrong
			 * (wrt the controller, what else) !!!
			 */

			if (cntr > CISS_INIT_TIME) /* 1.30 Mins */ {
				cmn_err(CE_CONT, "CPQary3 : Controller "
				    "Initialization Failed \n");
				return (CPQARY3_FAILURE);
			}
		}

		/*
		 * Check whether controller accepts the requested method of
		 * transport
		 */

		if (!(DDI_GET32(cpqary3p, &ctp->TransportActive) &
		    CFGTBL_XPORT_PERFORMANT)) {
			cmn_err(CE_NOTE, "CPQary3 : Failed to Initialize "
			    "Controller");
			cmn_err(CE_CONT, "CPQary3 : For Hot Plug Operations, "
			    "try again later\n");
			DTRACE_PROBE1(ctlr_init_perf_fail, CfgTable_t *, ctp);
			return (CPQARY3_FAILURE);
		}

		DTRACE_PROBE(ctlr_init_simple);

		/*
		 * Check if Controller is ready to accept Commands
		 */

		if (!(DDI_GET32(cpqary3p, &ctp->TransportActive) &
		    CFGTBL_ACC_CMDS)) {
			cmn_err(CE_NOTE, "CPQary3: Controller NOT ready to "
			    "accept Commands");
			return (CPQARY3_FAILURE);
		}

		/*
		 * Check if the maximum number of oustanding commands for the
		 * initialized controller is something greater than Zero.
		 */

		CmdsOutMax = DDI_GET32(cpqary3p, &ctp->MaxPerfModeCmdsOutMax);
		if (CmdsOutMax == 0)
			CmdsOutMax = DDI_GET32(cpqary3p, &ctp->CmdsOutMax);

		if (CmdsOutMax == 0) {
			cmn_err(CE_NOTE, "CPQary3 : HBA Maximum Outstanding "
			    "Commands set to Zero");
			cmn_err(CE_NOTE, "CPQary3 : Cannot continue driver "
			    "initialization");
			return (CPQARY3_FAILURE);
		}

		cpqary3p->ctlr_maxcmds = CmdsOutMax;

		/* SG */
		max_sg_cnt = DDI_GET32(cpqary3p, &ctp->MaxSGElements);
		max_blk_fetch_cnt =
		    DDI_GET32(cpqary3p, &ctp->MaxBlockFetchCount);

		/* 32 byte aligned - size_of_cmdlist */
		size_of_cmdlist = ((sizeof (CommandList_t) + 31) / 32) * 32;
		size_of_HRE  = size_of_cmdlist -
		    (sizeof (SGDescriptor_t) * CISS_MAXSGENTRIES);

		if ((max_blk_fetch_cnt == 0) || (max_sg_cnt == 0) ||
		    ((max_blk_fetch_cnt * 16) <= size_of_HRE)) {
			cpqary3p->sg_cnt = CPQARY3_PERF_SG_CNT;
		} else {
			/*
			 * Get the optimal_sg - no of the SG's that will fit
			 * into the max_blk_fetch_cnt
			 */

			optimal_sg_size =
			    (max_blk_fetch_cnt * 16) - size_of_HRE;

			if (optimal_sg_size < sizeof (SGDescriptor_t)) {
				optimal_sg = CPQARY3_PERF_SG_CNT;
			} else {
				optimal_sg =
				    optimal_sg_size / sizeof (SGDescriptor_t);
			}

			cpqary3p->sg_cnt = MIN(max_sg_cnt, optimal_sg);

			if (cpqary3p->sg_cnt > MAX_PERF_SG_CNT)
				cpqary3p->sg_cnt = MAX_PERF_SG_CNT;
		}

		/* SG */

		/*
		 * Zero the Upper 32 Address in the Controller
		 */

		DDI_PUT32(cpqary3p, &ctp->HostWrite.Upper32Addr, 0x00000000);
		cpqary3p->heartbeat = DDI_GET32(cpqary3p, &ctp->HeartBeat);

		/* Set the controller interrupt check routine */

		if (cpqary3p->bddef->bd_is_e200) {
			cpqary3p->check_ctlr_intr =
			    cpqary3_check_perf_e200_intr;
		} else {
			cpqary3p->check_ctlr_intr =
			    cpqary3_check_perf_ctlr_intr;
		}

		if ((!cpqary3p->bddef->bd_is_e200) &&
		    (!cpqary3p->bddef->bd_is_ssll)) {
			cpqary3p->host_support =
			    DDI_GET32(cpqary3p, &ctp->HostDrvrSupport);
			DDI_PUT32(cpqary3p, &ctp->HostDrvrSupport,
			    (cpqary3p->host_support | 0x4));
		}
		cpqary3p->host_support =
		    DDI_GET32(cpqary3p, &ctp->HostDrvrSupport);
		cpqary3p->lockup_logged = CPQARY3_FALSE;
	}

	return (CPQARY3_SUCCESS);
}

/*
 * Function	: 	cpqary3_check_ctlr_init
 * Description	: 	This routine checks to see if the HBA is initialized.
 * Called By	: 	cpqary3_init_ctlr()
 * Parameters	: 	per-controller
 * Calls	: 	None
 * Return Values: 	SUCCESS / FAILURE
 */
uint8_t
cpqary3_check_ctlr_init(cpqary3_t *cpqary3p)
{
	int8_t				retvalue;
	uint16_t			i;
	uint32_t			*ctlr_init;
	ddi_acc_handle_t		ctlr_init_handle;
	extern ddi_device_acc_attr_t	cpqary3_dev_attributes;

	RETURN_FAILURE_IF_NULL(cpqary3p);

	/*
	 * Set up the mapping for a Register at offset 0xB0 from I2O Bar
	 * The value 0xB0 taken from the CONFIGM utility.
	 * It should read 0xffff0000 if the controller is initialized.
	 * if not yet initialized, read it every second for 300 secs.
	 * If not set even after 300 secs, return FAILURE.
	 * If set, free the mapping and continue
	 */
	retvalue = ddi_regs_map_setup(cpqary3p->dip, INDEX_PCI_BASE0,
	    (caddr_t *)&ctlr_init, (offset_t)I2O_CTLR_INIT, 4,
	    &cpqary3_dev_attributes, &ctlr_init_handle);

	if (retvalue != DDI_SUCCESS) {
		if (DDI_REGS_ACC_CONFLICT == retvalue)
			cmn_err(CE_WARN,
			    "CPQary3 : HBA Init Register Mapping Conflict");
		cmn_err(CE_WARN,
		    "CPQary3 : HBA Init Regsiter Mapping Failed");
		return (CPQARY3_FAILURE);
	}

	for (i = 0; i < 300; i++) {	/* loop for 300 seconds */
		if (CISS_CTLR_INIT == ddi_get32(ctlr_init_handle, ctlr_init)) {
			DTRACE_PROBE(ctlr_init_check_ready);
			ddi_regs_map_free(&ctlr_init_handle);
			break;
		} else {
			DTRACE_PROBE(ctlr_init_check_notready);
			delay(drv_usectohz(1000000));
		}
	}

	if (i >= 300) {	/* HBA not initialized even after 300 seconds !!! */
		ddi_regs_map_free(&ctlr_init_handle);
		cmn_err(CE_WARN, "CPQary3 : %s NOT initialized !!! HBA may not "
		    "function properly. Please replace the hardware or check "
		    "the connections", cpqary3p->hba_name);
		return (CPQARY3_FAILURE);
	}

	return (CPQARY3_SUCCESS);
}
