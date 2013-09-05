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
 * This  File  has  Modules  that  handle  the NOE  functionality  for
 *	this driver.
 *	It  builds and  submits  the NOE  command to  the adapter.  It also
 *	processes a completed NOE command.
 *	A study of the FirmWare specifications would be neccessary to relate
 *	coding in this module to the hardware functionality.
 */

#include "cpqary3.h"

/*
 * Local Functions Definitions
 */

uint8_t cpqary3_disable_NOE_command(cpqary3_t *);

/*
 * Last reason a drive at this position was failed by the
 * controller firmware (saved in the RIS).
 */

#define	MAX_KNOWN_FAILURE_REASON	31

char *ascii_failure_reason[] = {
	"NONE",
	"TOO_SMALL_IN_LOAD_CONFIG",
	"ERROR_ERASING_RIS",
	"ERROR_SAVING_RIS",
	"FAIL_DRIVE_COMMAND",
	"MARK_BAD_FAILED",
	"MARK_BAD_FAILED_IN_FINISH_REMAP",
	"TIMEOUT",
	"AUTOSENSE_FAILED",
	"MEDIUM_ERROR_1",
	"MEDIUM_ERROR_2",
	"NOT_READY_BAD_SENSE",
	"NOT_READY",
	"HARDWARE_ERROR",
	"ABORTED_COMMAND",
	"WRITE_PROTECTED",
	"SPIN_UP_FAILURE_IN_RECOVER",
	"REBUILD_WRITE_ERROR",
	"TOO_SMALL_IN_HOT_PLUG",
	"RESET_RECOVERY_ABORT",
	"REMOVED_IN_HOT_PLUG",
	"INIT_REQUEST_SENSE_FAILED",
	"INIT_START_UNIT_FAILED",
	"GDP_INQUIRY_FAILED",
	"GDP_NON_DISK_DEVICE",
	"GDP_READ_CAPACITY_FAILED",
	"GDP_INVALID_BLOCK_SIZE",
	"HOTP_REQUEST_SENSE_FAILED",
	"HOTP_START_UNIT_FAILED",
	"WRITE_ERROR_AFTER_REMAP",
	"INIT_RESET_RECOVERY_ABORTED"
};

/*
 * All Possible Logical Volume Status
 */

char *log_vol_status[] = {
	"OK",
	"Failed",
	"Not Configured",
	"Regenerating",
	"Needs Rebuild Permission",
	"Rebuilding",
	"Wrong Drive Replaced",
	"Bad Drive Connection",
	"Box Overheating",
	"Box Overheated",
	"Volume Expanding",
	"Not Yet Available",
	"Volume Needs to Expand",
	"Unknown"
};

/*
 * Function	: 	cpqary3_send_NOE_command
 * Description	: 	This routine builds and submits the NOE Command
 *  			to the Controller.
 * Called By	:   	cpqary3_attach(), cpqary3_NOE_handler()
 * Parameters	: 	per-controller, per-command,
 *  			Flag to signify first time or otherwise
 * Calls	:   	cpqary3_alloc_phyctgs_mem(), cpqary3_cmdlist_occupy(),
 *			cpqary3_submit(), cpqary3_add2submitted_cmdq(),
 *			cpqary3_free_phyctgs_mem()
 * Return Values: 	SUCCESS / FAILURE
 *			[Shall fail only if memory allocation issues exist]
 */
uint8_t
cpqary3_send_NOE_command(cpqary3_t *ctlr, cpqary3_cmdpvt_t *memp, uint8_t flag)
{
	uint32_t		phys_addr = 0;
	NoeBuffer 		*databuf;
	CommandList_t		*cmdlist;
	cpqary3_phyctg_t	*phys_handle;
	int			rv;

	/*
	 * NOTE : DO NOT perform this operation for memp. Shall result in a
	 * failure of submission of the NOE command as it shall be NULL for
	 * the very first time
	 */
	RETURN_FAILURE_IF_NULL(ctlr);

	/*
	 * Allocate Memory for Return data
	 * if failure, RETURN.
	 * Allocate Memory for CommandList
	 * If error, RETURN.
	 * get the Request Block from the CommandList
	 * Fill in the Request Packet with the corresponding values
	 * Special Information can be filled in the "bno" field of
	 * the request structure.
	 * Here, the "bno" field is filled for Asynchronous Mode.
	 * Submit the Command.
	 * If Failure, WARN and RETURN.
	 */
	if (CPQARY3_NOE_RESUBMIT == flag) {
		if ((NULL == memp) || (NULL == memp->cmdlist_memaddr)) {
			cmn_err(CE_WARN, " CPQary3 : _send_NOE_command : "
			    "Re-Use Not possible; CommandList NULL");
			return (CPQARY3_FAILURE);
		}

		bzero(MEM2DRVPVT(memp)->sg, sizeof (NoeBuffer));
		memp->cmdlist_memaddr->Header.Tag.drvinfo_n_err =
		    CPQARY3_NOECMD_SUCCESS;
	} else if (CPQARY3_NOE_INIT == flag) {
		phys_handle =
		    (cpqary3_phyctg_t *)MEM_ZALLOC(sizeof (cpqary3_phyctg_t));
		if (!phys_handle)
			return (CPQARY3_FAILURE);

		databuf = (NoeBuffer *)cpqary3_alloc_phyctgs_mem(ctlr,
		    sizeof (NoeBuffer), &phys_addr, phys_handle);
		if (!databuf) {
			return (CPQARY3_FAILURE);
		}
		bzero(databuf, sizeof (NoeBuffer));

		if (NULL == (memp = cpqary3_cmdlist_occupy(ctlr))) {
			cpqary3_free_phyctgs_mem(phys_handle,
			    CPQARY3_FREE_PHYCTG_MEM);
			return (CPQARY3_FAILURE);
		}

		memp->driverdata = (cpqary3_private_t *)
		    MEM_ZALLOC(sizeof (cpqary3_private_t));
		if (NULL == memp->driverdata) {
			cpqary3_free_phyctgs_mem(phys_handle,
			    CPQARY3_FREE_PHYCTG_MEM);
			cpqary3_cmdlist_release(memp, CPQARY3_HOLD_SW_MUTEX);
			return (CPQARY3_FAILURE);
		}
		memp->driverdata->sg = databuf;
		memp->driverdata->phyctgp = phys_handle;

		cmdlist = memp->cmdlist_memaddr;
		cmdlist->Header.SGTotal = 1;
		cmdlist->Header.SGList = 1;
		cmdlist->Header.Tag.drvinfo_n_err = CPQARY3_NOECMD_SUCCESS;
		cmdlist->Header.LUN.PhysDev.Mode = PERIPHERIAL_DEV_ADDR;

		cmdlist->Request.CDBLen = CISS_NOE_CDB_LEN;
		cmdlist->Request.Timeout = 0;
		cmdlist->Request.Type.Type = CISS_TYPE_CMD;
		cmdlist->Request.Type.Attribute = CISS_ATTR_HEADOFQUEUE;
		cmdlist->Request.Type.Direction = CISS_XFER_READ;
		cmdlist->Request.CDB[0] = CISS_NEW_READ;
		cmdlist->Request.CDB[1] = BMIC_NOTIFY_ON_EVENT;
		cmdlist->Request.CDB[10] = (NOE_BUFFER_LENGTH >> 8) & 0xff;
		cmdlist->Request.CDB[11] = NOE_BUFFER_LENGTH & 0xff;

		cmdlist->SG[0].Addr = phys_addr;
		cmdlist->SG[0].Len = NOE_BUFFER_LENGTH;
	}

	/* PERF */

	memp->complete = cpqary3_noe_complete;

	mutex_enter(&ctlr->hw_mutex);
	rv = cpqary3_submit(ctlr, memp->cmdlist_phyaddr);
	mutex_exit(&ctlr->hw_mutex);

	if (rv != 0)
		return (CPQARY3_FAILURE);

	/* PERF */
	return (CPQARY3_SUCCESS);
}

/*
 * Function	: 	cpqary3_disable_NOE_command
 * Description	: 	This routine disables the Event Notifier
 *			for the specified Controller.
 * Called By	: 	cpqary3_cleanup()
 * Parameters	: 	Per Controller Structure
 * Calls	:   	cpqary3_cmdlist_occupy(), cpqary3_submit(),
 *			cpqary3_add2submitted_cmdq()
 * Return Values: 	SUCCESS / FAILURE
 *			[Shall fail only if Memory Constraints exist]
 */
uint8_t
cpqary3_disable_NOE_command(cpqary3_t *ctlr)
{
	CommandList_t		*cmdlist;
	cpqary3_cmdpvt_t	*memp;
	int			rv;

	RETURN_FAILURE_IF_NULL(ctlr);

	/*
	 * Allocate Memory for CommandList
	 * If error, RETURN.
	 * get the Request Block from the CommandList
	 * Fill in the Request Packet with the corresponding values
	 * Submit the Command.
	 * If Failure, WARN and RETURN.
	 */

	if (NULL == (memp = cpqary3_cmdlist_occupy(ctlr))) {
		cmn_err(CE_WARN, "CPQary3 : _disable_NOE_command : Failed");
		return (CPQARY3_FAILURE);
	}

	cmdlist = memp->cmdlist_memaddr;
	cmdlist->Header.Tag.drvinfo_n_err = CPQARY3_NOECMD_SUCCESS;
	cmdlist->Header.LUN.PhysDev.Mode = PERIPHERIAL_DEV_ADDR;

	cmdlist->Request.CDBLen = CISS_CANCEL_NOE_CDB_LEN;
	cmdlist->Request.Timeout = 0;
	cmdlist->Request.Type.Type = CISS_TYPE_CMD;
	cmdlist->Request.Type.Attribute = CISS_ATTR_HEADOFQUEUE;
	cmdlist->Request.Type.Direction = CISS_XFER_NONE;
	cmdlist->Request.CDB[0] = ARRAY_WRITE;	/* 0x27 */
	cmdlist->Request.CDB[6] = BMIC_CANCEL_NOTIFY_ON_EVENT;

	/* PERF */

	memp->complete = cpqary3_noe_complete;

	mutex_enter(&ctlr->hw_mutex);
	rv = cpqary3_submit(ctlr, memp->cmdlist_phyaddr);
	mutex_exit(&ctlr->hw_mutex);

	if (rv != 0)
		return (CPQARY3_FAILURE);

	/* PERF */
	return (CPQARY3_SUCCESS);
}

/*
 * Function	: 	cpqary3_NOE_handler
 * Description	: 	This routine handles all those NOEs tabulated at the
 *			begining of this code.
 * Called By	: 	cpqary3_process_pkt()
 * Parameters	: 	Pointer to the Command List
 * Calls	:   	cpqary3_send_NOE_command(),
 *			cpqary3_display_spare_status()
 *			cpqary3_free_phyctgs_mem(), cpqary3_cmdlist_release()
 * Return Values: 	None
 */
void
cpqary3_NOE_handler(cpqary3_cmdpvt_t *memp)
{
	uint16_t		drive = 0;
	NoeBuffer 		*evt;
	cpqary3_t		*ctlr;
	cpqary3_phyctg_t	*phys_handle;
	uint8_t			driveId = 0;

	/*
	 * This should never happen....
	 * If the pointer passed as argument is NULL, Panic the System.
	 */
	VERIFY(memp != NULL);

	evt = (NoeBuffer *)MEM2DRVPVT(memp)->sg;
	ctlr = (cpqary3_t *)memp->ctlr;
	phys_handle = (cpqary3_phyctg_t *)MEM2DRVPVT(memp)->phyctgp;

	/* Don't display more than 79 characters */
	evt->ascii_message[79] = 0;


	switch (evt->event_class_code) {
	case CLASS_PROTOCOL:
		/*
		 * the following cases are not handled:
		 * 000 	: This is for Synchronous NOE.
		 *	  CPQary3 follows asynchronous NOE.
		 * 002	: Asynchronous NOE time out.
		 *	  CPQary3 does not implement time
		 *	  outs for NOE. It shall always reside in the HBA.
		 */

		cmn_err(CE_NOTE, " %s", ctlr->hba_name);
		if ((evt->event_subclass_code == SUB_CLASS_NON_EVENT) &&
		    (evt->event_detail_code == DETAIL_DISABLED)) {
			cmn_err(CE_CONT, " %s", ctlr->hba_name);
			cmn_err(CE_CONT,
			    "CPQary3 : Event Notifier Disabled \n");
			MEM_SFREE(memp->driverdata, sizeof (cpqary3_private_t));
			cpqary3_free_phyctgs_mem(phys_handle,
			    CPQARY3_FREE_PHYCTG_MEM);
			cpqary3_cmdlist_release(memp, CPQARY3_NO_MUTEX);
			return;
		} else if ((evt->event_subclass_code ==
		    SUB_CLASS_PROTOCOL_ERR) &&
		    (evt->event_detail_code == DETAIL_EVENT_Q_OVERFLOW)) {
			cmn_err(CE_CONT, " %s\n", evt->ascii_message);
		}
		cmn_err(CE_CONT, "\n");
		break;

	case CLASS_HOT_PLUG:
		if (evt->event_subclass_code == SUB_CLASS_HP_CHANGE) {
			cmn_err(CE_NOTE, " %s", ctlr->hba_name);
			cmn_err(CE_CONT, " %s\n", evt->ascii_message);

			/*
			 * Fix for QUIX 1000440284: Display the Physical
			 * Drive Num info only for CISS Controllers
			 */

			if (!(ctlr->bddef->bd_flags & SA_BD_SAS)) {
				driveId =
				    /* LINTED: alignment */
				    *(uint16_t *)(&evt->event_specific_data[0]);
				if (driveId & 0x80) {
					driveId -= 0x80;
					cmn_err(CE_CONT, " Physical Drive Num "
					    "....... SCSI Port %u, "
					    "Drive Id %u\n",
					    (driveId / 16) + 1,
					    (driveId % 16));
				} else {
					cmn_err(CE_CONT, " Physical Drive Num "
					    "....... SCSI Port %u, "
					    "Drive Id %u\n",
					    (driveId / 16) + 1, (driveId % 16));
				}
			}

			cmn_err(CE_CONT, " Configured Drive ? ....... %s\n",
			    evt->event_specific_data[2] ? "YES" : "NO");
			if (evt->event_specific_data[3]) {
				cmn_err(CE_CONT, " Spare Drive? "
				    "............. %s\n",
				    evt->event_specific_data[3] ? "YES" : "NO");
			}
		} else if (evt->event_subclass_code == SUB_CLASS_SB_HP_CHANGE) {
			if (evt->event_detail_code == DETAIL_PATH_REMOVED) {
				cmn_err(CE_WARN, " %s", ctlr->hba_name);
				cmn_err(CE_CONT,
				    " Storage Enclosure cable or %s\n",
				    evt->ascii_message);
			} else if (evt->event_detail_code ==
			    DETAIL_PATH_REPAIRED) {
				cmn_err(CE_NOTE, " %s", ctlr->hba_name);
				cmn_err(CE_CONT,
				    " Storage Enclosure Cable or %s\n",
				    evt->ascii_message);
			} else {
				cmn_err(CE_NOTE, " %s", ctlr->hba_name);
				cmn_err(CE_CONT, " %s\n", evt->ascii_message);
			}
		} else {
			cmn_err(CE_NOTE, " %s", ctlr->hba_name);
			cmn_err(CE_CONT, " %s\n", evt->ascii_message);
		}

		cmn_err(CE_CONT, "\n");
		break;

	case CLASS_HARDWARE:
	case CLASS_ENVIRONMENT:
		cmn_err(CE_NOTE, " %s", ctlr->hba_name);
		cmn_err(CE_CONT, " %s\n", evt->ascii_message);
		cmn_err(CE_CONT, "\n");
		break;

	case CLASS_PHYSICAL_DRIVE:
		cmn_err(CE_WARN, " %s", ctlr->hba_name);
		cmn_err(CE_CONT, " %s\n", evt->ascii_message);

		/*
		 * Fix for QUIX 1000440284: Display the Physical Drive
		 * Num info only for CISS Controllers
		 */

		if (!(ctlr->bddef->bd_flags & SA_BD_SAS)) {
			/* LINTED: alignment */
			driveId = *(uint16_t *)(&evt->event_specific_data[0]);
			if (driveId & 0x80) {
				driveId -= 0x80;
				cmn_err(CE_CONT, " Physical Drive Num ....... "
				    "SCSI Port %u, Drive Id %u\n",
				    (driveId / 16) + 1, (driveId % 16));
			} else {
				cmn_err(CE_CONT, " Physical Drive Num ....... "
				    "SCSI Port %u, Drive Id %u\n",
				    (driveId / 16) + 1, (driveId % 16));
			}
		}

		if (evt->event_specific_data[2] < MAX_KNOWN_FAILURE_REASON) {
			cmn_err(CE_CONT, " Failure Reason............ %s\n",
			    ascii_failure_reason[evt->event_specific_data[2]]);
		} else {
			cmn_err(CE_CONT,
			    " Failure Reason............ UNKNOWN \n");
		}

		cmn_err(CE_CONT, "\n");
		break;

	case CLASS_LOGICAL_DRIVE:
		cmn_err(CE_NOTE, " %s", ctlr->hba_name);

		/*
		 * Fix for QXCR1000717274 - We are appending the logical
		 * voulme number by one to be in sync with logical volume
		 * details given by HPQacucli
		 */

		if ((evt->event_subclass_code == SUB_CLASS_STATUS) &&
		    (evt->event_detail_code == DETAIL_CHANGE)) {
			cmn_err(CE_CONT, " State change, logical drive %u\n",
			    /* LINTED: alignment */
			    (*(uint16_t *)(&evt->event_specific_data[0]) + 1));
			cmn_err(CE_CONT, " New Logical Drive State... %s\n",
			    log_vol_status[evt->event_specific_data[3]]);

			/*
			 * If the Logical drive has FAILED or it was
			 * NOT CONFIGURED, in the corresponding target
			 * structure, set flag as NONE to suggest that no
			 * target exists at this id.
			 */

			if ((evt->event_specific_data[3] == 1) ||
			    (evt->event_specific_data[3] == 2)) {
				/* LINTED: alignment */
				drive =	*(uint16_t *)
				    (&evt->event_specific_data[0]);
				drive = ((drive < CTLR_SCSI_ID)
				    ? drive : drive + CPQARY3_TGT_ALIGNMENT);
				if (ctlr && ctlr->cpqary3_tgtp[drive]) {
					ctlr->cpqary3_tgtp[drive]->type =
					    CPQARY3_TARGET_NONE;
				}
			}

			if (evt->event_specific_data[4] & SPARE_REBUILDING) {
				cmn_err(CE_CONT, " Logical Drive %d: "
				    "Data is rebuilding on spare drive\n",
				    /* LINTED: alignment */
				    (*(uint16_t *)
				    (&evt->event_specific_data[0]) + 1));
			}

			if (evt->event_specific_data[4] & SPARE_REBUILT) {
				cmn_err(CE_CONT,
				    " Logical Drive %d: Rebuild complete. "
				    "Spare is now active\n",
				    /* LINTED: alignment */
				    (*(uint16_t *)
				    (&evt->event_specific_data[0]) + 1));
			}
		} else if ((evt->event_subclass_code == SUB_CLASS_STATUS) &&
		    (evt->event_detail_code == MEDIA_EXCHANGE)) {
			cmn_err(CE_CONT, " Media exchange detected, "
			    "logical drive %u\n",
			    /* LINTED: alignment */
			    (*(uint16_t *)
			    (&evt->event_specific_data[0]) + 1));
		} else {
			cmn_err(CE_CONT, " %s\n", evt->ascii_message);
		}

		cmn_err(CE_CONT, "\n");
		break;

	default:
		cmn_err(CE_NOTE, "%s", ctlr->hba_name);
		cmn_err(CE_CONT, " %s\n", evt->ascii_message);
		cmn_err(CE_CONT, "\n");
		break;
	}

	/*
	 * Here, we reuse this command block to resubmit the NOE
	 * command.
	 * Ideally speaking, the resubmit should never fail
	 */
	if (CPQARY3_FAILURE ==
	    cpqary3_send_NOE_command(ctlr, memp, CPQARY3_NOE_RESUBMIT)) {
		cmn_err(CE_WARN, "CPQary3: Failed to ReInitialize "
		    "NOTIFY OF EVENT");
		cpqary3_free_phyctgs_mem(MEM2DRVPVT(memp)->phyctgp,
		    CPQARY3_FREE_PHYCTG_MEM);
		cpqary3_cmdlist_release(memp, CPQARY3_NO_MUTEX);
	}
}

/* PERF */
/*
 * Function	:      	cpqary3_noe_complete
 * Description	:      	This routine processes the completed
 *			NOE commands and
 *			initiates any callback that is needed.
 * Called By	:      	cpqary3_send_NOE_command,
 *			cpqary3_disable_NOE_command
 * Parameters	:      	per-command
 * Calls	:      	cpqary3_NOE_handler, cpqary3_cmdlist_release
 * Return Values:      	None
 */
void
cpqary3_noe_complete(cpqary3_cmdpvt_t *cpqary3_cmdpvtp)
{
	ASSERT(cpqary3_cmdpvtp != NULL);

	if (CPQARY3_TIMEOUT == cpqary3_cmdpvtp->cmdpvt_flag) {
		cpqary3_cmdlist_release(cpqary3_cmdpvtp, CPQARY3_NO_MUTEX);
		return;
	}

	if (cpqary3_cmdpvtp->cmdlist_memaddr->Request.CDB[6] ==
	    BMIC_CANCEL_NOTIFY_ON_EVENT) {
		cv_signal(&cpqary3_cmdpvtp->ctlr->cv_noe_wait);
		cpqary3_cmdlist_release(cpqary3_cmdpvtp, CPQARY3_NO_MUTEX);
	} else {
		cpqary3_NOE_handler(cpqary3_cmdpvtp);
	}
}

/* PERF */
