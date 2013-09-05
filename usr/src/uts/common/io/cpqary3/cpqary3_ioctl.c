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
 * Supported IOCTLs :
 *	CPQARY3_IOCTL_DRIVER_INFO	- to get driver details
 *	CPQARY3_IOCTL_CTLR_INFO		- to get controller details
 *	CPQARY3_IOCTL_BMIC_PASS		- to pass BMIC commands
 *	CPQARY3_IOCTL_SCSI_PASS		- to pass SCSI commands
 */

#include "cpqary3.h"

/*
 * Local Functions Declaration
 */

static int32_t cpqary3_ioctl_send_bmiccmd(cpqary3_t *, cpqary3_bmic_pass_t *,
    int);
static void cpqary3_ioctl_fil_bmic(CommandList_t *, cpqary3_bmic_pass_t *);
static void cpqary3_ioctl_fil_bmic_sas(CommandList_t *, cpqary3_bmic_pass_t *);
static int32_t cpqary3_ioctl_send_scsicmd(cpqary3_t *, cpqary3_scsi_pass_t *,
    int);
static void cpqary3_ioctl_fil_scsi(CommandList_t *, cpqary3_scsi_pass_t *);

/*
 * Global Variables Definitions
 */

cpqary3_driver_info_t gdriver_info = {0};

/* Function Definitions  */

/*
 * Function	:	cpqary3_ioctl_driver_info
 * Description	:	This routine will get major/ minor versions, Number of
 *			controllers detected & MAX Number of controllers
 *			supported
 * Called By	:	cpqary3_ioctl
 * Parameters	: 	ioctl_reqp	- address of the parameter sent from
 *					  the application
 *			cpqary3p	- address of the PerController structure
 *			mode		- mode which comes from application
 * Return Values:	EFAULT on Failure, 0 on SUCCESS
 */
int32_t
cpqary3_ioctl_driver_info(uintptr_t ioctl_reqp, int mode)
{
	cpqary3_ioctl_request_t *request;

	request = (cpqary3_ioctl_request_t *)
	    MEM_ZALLOC(sizeof (cpqary3_ioctl_request_t));

	if (NULL == request)
		return (FAILURE);

	/*
	 * First let us copyin the ioctl_reqp user buffer to request(kernel)
	 * memory.  This is very much recomended before we access any of the
	 * fields.
	 */
	if (ddi_copyin((void *)ioctl_reqp, (void *)request,
	    sizeof (cpqary3_ioctl_request_t), mode)) {
		MEM_SFREE(request, sizeof (cpqary3_ioctl_request_t));
		return (EFAULT);
	}

	/*
	 * Fill up the global structure "gdriver_info" memory.
	 * Fill this structure with available info, which will be copied
	 * back later
	 */

	(void) strcpy(gdriver_info.name, "cpqary3");
	gdriver_info.version.minor = CPQARY3_MINOR_REV_NO;
	gdriver_info.version.major = CPQARY3_MAJOR_REV_NO;
	gdriver_info.version.dd = CPQARY3_REV_MONTH;
	gdriver_info.version.mm = CPQARY3_REV_DATE;
	gdriver_info.version.yyyy = CPQARY3_REV_YEAR;
	gdriver_info.max_num_ctlr = MAX_CTLRS;

	/*
	 * First Copy out the driver_info structure
	 */

	if (ddi_copyout((void *)&gdriver_info, (void *)(uintptr_t)request->argp,
	    sizeof (cpqary3_driver_info_t), mode)) {
		MEM_SFREE(request, sizeof (cpqary3_ioctl_request_t));
		return (EFAULT);
	}

	/*
	 * Copy out the request structure back
	 */

	if (ddi_copyout((void *)request, (void *)ioctl_reqp,
	    sizeof (cpqary3_ioctl_request_t), mode)) {
		MEM_SFREE(request, sizeof (cpqary3_ioctl_request_t));
		return (EFAULT);
	}

	MEM_SFREE(request, sizeof (cpqary3_ioctl_request_t));

	/*
	 * Everything looks fine. So return SUCCESS
	 */

	return (SUCCESS);
}

/*
 * Function	:	cpqary3_ioctl_ctlr_info
 * Description	:	This routine will get the controller related info, like
 * 			board-id, subsystem-id, num of logical drives,
 * 			slot number
 * Called By	:	cpqary3_ioctl
 * Parameters	: 	ioctl_reqp - address of the parameter sent form the
 *				     application
 *			cpqary3p   - address of the PerController structure
 *			mode	   - mode which comes from application
 * Return Values:	EFAULT on Failure, 0 on SUCCESS
 */
int32_t
cpqary3_ioctl_ctlr_info(uintptr_t ioctl_reqp, cpqary3_t *cpqary3p, int mode)
{
	cpqary3_ioctl_request_t	*request;
	cpqary3_ctlr_info_t	*ctlr_info;

	request = (cpqary3_ioctl_request_t *)
	    MEM_ZALLOC(sizeof (cpqary3_ioctl_request_t));

	if (NULL == request)
		return (FAILURE);

	/*
	 * First let us copyin the buffer to kernel memory. This is very much
	 * recomended before we access any of the fields.
	 */

	if (ddi_copyin((void *) ioctl_reqp, (void *)request,
	    sizeof (cpqary3_ioctl_request_t), mode)) {
		MEM_SFREE(request, sizeof (cpqary3_ioctl_request_t));
		return (EFAULT);
	}

	ctlr_info = (cpqary3_ctlr_info_t *)
	    MEM_ZALLOC(sizeof (cpqary3_ctlr_info_t));

	if (NULL == ctlr_info) {
		MEM_SFREE(request, sizeof (cpqary3_ioctl_request_t));
		return (FAILURE);
	}

	/*
	 * in the driver, board_id is actually subsystem_id
	 */

	ctlr_info->subsystem_id = cpqary3p->board_id;
	ctlr_info->bus = cpqary3p->bus;
	ctlr_info->dev = cpqary3p->dev;
	ctlr_info->fun = cpqary3p->fun;
	ctlr_info->num_of_tgts = cpqary3p->num_of_targets;
	ctlr_info->controller_instance = cpqary3p->instance;

	/*
	 * TODO: ctlr_info.slot_num has to be implemented
	 * state & board_id fields are kept for future implementation i
	 * if required!
	 */

	/*
	 * First Copy out the ctlr_info structure
	 */

	if (ddi_copyout((void *)ctlr_info, (void *)(uintptr_t)request->argp,
	    sizeof (cpqary3_ctlr_info_t), mode)) {
		MEM_SFREE(ctlr_info, sizeof (cpqary3_ctlr_info_t));
		MEM_SFREE(request, sizeof (cpqary3_ioctl_request_t));
		return (EFAULT);
	}

	/*
	 * Copy out the request structure back
	 */

	if (ddi_copyout((void *)request, (void *)ioctl_reqp,
	    sizeof (cpqary3_ioctl_request_t), mode)) {
		MEM_SFREE(ctlr_info, sizeof (cpqary3_ctlr_info_t));
		MEM_SFREE(request, sizeof (cpqary3_ioctl_request_t));
		return (EFAULT);
	}

	MEM_SFREE(ctlr_info, sizeof (cpqary3_ctlr_info_t));
	MEM_SFREE(request, sizeof (cpqary3_ioctl_request_t));

	/*
	 * Everything looks fine. So return SUCCESS
	 */

	return (SUCCESS);
}

/*
 * Function	:	cpqary3_ioctl_bmic_pass
 * Description	:	This routine will pass the BMIC commands to controller
 * Called By	:	cpqary3_ioctl
 * Parameters	: 	ioctl_reqp - address of the parameter sent from the
 *				     application
 *			cpqary3p   - address of the PerController structure
 *			mode	   - mode which comes directly from application
 * Return Values:	EFAULT on Failure, 0 on SUCCESS
 */
int32_t
cpqary3_ioctl_bmic_pass(uintptr_t ioctl_reqp, cpqary3_t *cpqary3p, int mode)
{
	cpqary3_ioctl_request_t	*request;
	cpqary3_bmic_pass_t 	*bmic_pass;
	int32_t			retval = SUCCESS;

	request = (cpqary3_ioctl_request_t *)
	    MEM_ZALLOC(sizeof (cpqary3_ioctl_request_t));

	if (NULL == request)
		return (FAILURE);

	/*
	 * First let us copyin the ioctl_reqp(user) buffer to request(kernel)
	 * memory.  This is very much recommended before we access any of the
	 * fields.
	 */

	if (ddi_copyin((void *)ioctl_reqp, (void *)request,
	    sizeof (cpqary3_ioctl_request_t), mode)) {
		MEM_SFREE(request, sizeof (cpqary3_ioctl_request_t));
		return (EFAULT);
	}

	bmic_pass = (cpqary3_bmic_pass_t *)
	    MEM_ZALLOC(sizeof (cpqary3_bmic_pass_t));

	if (NULL == bmic_pass) {
		MEM_SFREE(request, sizeof (cpqary3_ioctl_request_t));
		return (FAILURE);
	}

	/*
	 * Copy in "cpqary3_bmic_pass_t" structure from argp member
	 * of ioctl_reqp.
	 */

	if (ddi_copyin((void *)(uintptr_t)request->argp, (void *)bmic_pass,
	    sizeof (cpqary3_bmic_pass_t), mode)) {
		MEM_SFREE(bmic_pass, sizeof (cpqary3_bmic_pass_t));
		MEM_SFREE(request, sizeof (cpqary3_ioctl_request_t));
		return (EFAULT);
	}

	/*
	 * Get the free command list, fill in the bmic command and send it
	 * to the controller. This will return 0 on success.
	 */

	retval = cpqary3_ioctl_send_bmiccmd(cpqary3p, bmic_pass, mode);

	/*
	 * Now copy the  bmic_pass (kernel) to the user argp
	 */

	if (ddi_copyout((void *) bmic_pass, (void *)(uintptr_t)request->argp,
	    sizeof (cpqary3_bmic_pass_t), mode)) {
		MEM_SFREE(bmic_pass, sizeof (cpqary3_bmic_pass_t));
		MEM_SFREE(request, sizeof (cpqary3_ioctl_request_t));
		retval = EFAULT; /* copyout failed */
	}

	/*
	 * Now copy the  request(kernel) to ioctl_reqp(user)
	 */

	if (ddi_copyout((void *) request, (void *)ioctl_reqp,
	    sizeof (cpqary3_ioctl_request_t), mode)) {
		MEM_SFREE(bmic_pass, sizeof (cpqary3_bmic_pass_t));
		MEM_SFREE(request, sizeof (cpqary3_ioctl_request_t));
		retval = EFAULT;
	}

	MEM_SFREE(bmic_pass, sizeof (cpqary3_bmic_pass_t));
	MEM_SFREE(request, sizeof (cpqary3_ioctl_request_t));

	return (retval);
}

/*
 * Function	:	cpqary3_ioctl_send_bmiccmd
 * Description	:	This routine will get the free command,
 *			allocate memory and send it to controller.
 * Called By	:	cpqary3_ioctl_bmic_pass
 * Parameters	: 	cpqary3_t - PerController structure
 *			cpqary3_bmic_pass_t - bmic structure
 *			mode - mode value sent from application
 * Return Values:	0 on success
 *			FAILURE, EFAULT, ETIMEOUT based on the failure
 */

uint32_t cpqary3_ioctl_wait_ms = 30000;

static int32_t
cpqary3_ioctl_send_bmiccmd(cpqary3_t *cpqary3p,
    cpqary3_bmic_pass_t *bmic_pass, int mode)
{
	cpqary3_cmdpvt_t	*memp    = NULL;
	CommandList_t		*cmdlist = NULL;
	int8_t			*databuf = NULL;
	uint8_t			retval  = 0;

	/* allocate a command with a dma buffer */
	memp = cpqary3_synccmd_alloc(cpqary3p, bmic_pass->buf_len);
	if (memp == NULL)
		return (FAILURE);

	/* Get the databuf when buf_len is greater than zero */
	if (bmic_pass->buf_len > 0) {
		databuf = memp->driverdata->sg;
	}

	cmdlist	= memp->cmdlist_memaddr;

	/*
	 * If io_direction is CPQARY3_SCSI_OUT, we have to copy user buffer
	 * to databuf
	 */

	if (bmic_pass->io_direction == CPQARY3_SCSI_OUT) {
		/* Do a copyin when buf_len is greater than zero */
		if (bmic_pass->buf_len > 0) {
			if (ddi_copyin((void*)(uintptr_t)(bmic_pass->buf),
			    (void*)databuf, bmic_pass->buf_len, mode)) {
				cpqary3_synccmd_free(cpqary3p, memp);
				return (EFAULT);
			}
		}
	}

	/*
	 * Now fill the command as per the BMIC
	 */
	if (cpqary3p->bddef->bd_flags & SA_BD_SAS) {
		cpqary3_ioctl_fil_bmic_sas(cmdlist, bmic_pass);
	} else {
		cpqary3_ioctl_fil_bmic(cmdlist, bmic_pass);
	}


	/* PERF */

	memp->complete = cpqary3_synccmd_complete;

	/* PERF */

	/* send command to controller and wait for a reply */
	if (cpqary3_synccmd_send(cpqary3p, memp, cpqary3_ioctl_wait_ms,
	    CPQARY3_SYNCCMD_SEND_WAITSIG) != 0) {
		cpqary3_synccmd_free(cpqary3p, memp);
		return (ETIMEDOUT);
	}

	/*
	 * Now the command is completed and copy the buffers back
	 * First copy the buffer databuf to bmic_pass.buf
	 * which is used as a buffer before passing the command to the
	 * controller.
	 */

	if (bmic_pass->io_direction == CPQARY3_SCSI_IN) {
		/* Do a copyout when buf_len is greater than zero */
		if (bmic_pass->buf_len > 0) {
			if (ddi_copyout((void *)databuf,
			    (void *)(uintptr_t)bmic_pass->buf,
			    bmic_pass->buf_len, mode)) {
				retval = EFAULT;
			}
		}
	}

	/*
	 * This is case where the command completes with error,
	 * Then tag would have set its 1st(10) bit.
	 */

	if (cmdlist->Header.Tag.drvinfo_n_err == CPQARY3_SYNCCMD_FAILURE) {
		bmic_pass->err_status = 1;
		bcopy((caddr_t)memp->errorinfop, &bmic_pass->err_info,
		    sizeof (ErrorInfo_t));
		switch (memp->errorinfop->CommandStatus) {
		case CISS_CMD_DATA_OVERRUN :
		case CISS_CMD_DATA_UNDERRUN :
		case CISS_CMD_SUCCESS :
		case CISS_CMD_TARGET_STATUS :
			retval = SUCCESS;
			break;
		default :
			retval = EIO;
			break;
		}
	}

	cpqary3_synccmd_free(cpqary3p, memp);

	return (retval);
}

/*
 * Function	:	cpqary3_ioctl_fil_bmic
 * Description	:	This routine will fill the cmdlist with BMIC details
 * Called By	:	cpqary3_ioctl_send_bmiccmd
 * Parameters	: 	cmdlist 	- command packet
 *			bmic_pass 	- bmic structure
 * Return Values:	void
 */
static void
cpqary3_ioctl_fil_bmic(CommandList_t *cmdlist,
    cpqary3_bmic_pass_t *bmic_pass)
{
	cmdlist->Header.SGTotal = 1;
	cmdlist->Header.SGList = 1;
	cmdlist->Request.CDBLen = bmic_pass->cmd_len;
	cmdlist->Request.Timeout = bmic_pass->timeout;
	cmdlist->Request.Type.Type = CISS_TYPE_CMD;
	cmdlist->Request.Type.Attribute = CISS_ATTR_HEADOFQUEUE;

	switch (bmic_pass->io_direction) {
	case CPQARY3_SCSI_OUT:
		cmdlist->Request.Type.Direction = CISS_XFER_WRITE;
		break;
	case CPQARY3_SCSI_IN:
		cmdlist->Request.Type.Direction = CISS_XFER_READ;
		break;
	case CPQARY3_NODATA_XFER:
		cmdlist->Request.Type.Direction = CISS_XFER_NONE;
		break;
	default:
		cmdlist->Request.Type.Direction = CISS_XFER_RSVD;
		break;
	}

	cmdlist ->Request.CDB[0] =
	    (bmic_pass->io_direction == CPQARY3_SCSI_IN) ? 0x26: 0x27;
	cmdlist ->Request.CDB[1] = bmic_pass->unit_number; /* Unit Number */

	/*
	 * BMIC Detail - bytes 2[MSB] to 5[LSB]
	 */

	cmdlist->Request.CDB[2] = (bmic_pass->blk_number >> 24) & 0xff;
	cmdlist->Request.CDB[3] = (bmic_pass->blk_number >> 16) & 0xff;
	cmdlist->Request.CDB[4] = (bmic_pass->blk_number >> 8) & 0xff;
	cmdlist->Request.CDB[5] = bmic_pass->blk_number;

	cmdlist->Request.CDB[6] = bmic_pass->cmd; /* BMIC Command */

	/* Transfer Length - bytes 7[MSB] to 8[LSB] */

	cmdlist->Request.CDB[7] = (bmic_pass->buf_len >> 8) & 0xff;
	cmdlist->Request.CDB[8] = bmic_pass->buf_len & 0xff;
	cmdlist->Request.CDB[9] = 0x00; /* Reserved */

	/*
	 * Copy the Lun address from the request
	 */

	bcopy(&bmic_pass->lun_addr[0], &(cmdlist->Header.LUN),
	    sizeof (LUNAddr_t));
	cmdlist->SG[0].Len = bmic_pass->buf_len;
}

/*
 * Function	:	cpqary3_ioctl_scsi_pass
 * Description	:	This routine will pass the SCSI commands to controller
 * Called By	:	cpqary3_ioctl
 * Parameters	:  	ioctl_reqp - address of the parameter sent
 *				     from the application
 *			cpqary3p   - Addess of the percontroller stucture
 *			mode       - mode which comes directly from application
 * Return Values:	EFAULT on Failure, 0 on SUCCESS
 */
int32_t
cpqary3_ioctl_scsi_pass(uintptr_t ioctl_reqp, cpqary3_t *cpqary3p, int mode)
{
	cpqary3_ioctl_request_t	*request;
	cpqary3_scsi_pass_t 	*scsi_pass;
	int32_t			retval = SUCCESS;

	request = (cpqary3_ioctl_request_t *)
	    MEM_ZALLOC(sizeof (cpqary3_ioctl_request_t));

	if (NULL == request)
		return (FAILURE);

	/*
	 * First let us copyin the ioctl_reqp(user) buffer to request(kernel)
	 * memory.  * This is very much recommended before we access any of
	 * the fields.
	 */

	if (ddi_copyin((void *)ioctl_reqp, (void *)request,
	    sizeof (cpqary3_ioctl_request_t), mode)) {
		MEM_SFREE(request, sizeof (cpqary3_ioctl_request_t));
		return (EFAULT);
	}

	scsi_pass = (cpqary3_scsi_pass_t *)
	    MEM_ZALLOC(sizeof (cpqary3_scsi_pass_t));

	if (NULL == scsi_pass) {
		MEM_SFREE(request, sizeof (cpqary3_ioctl_request_t));
		return (FAILURE);
	}

	/*
	 * Copy in "cpqary3_scsi_pass_t" structure from argp member
	 * of ioctl_reqp.
	 */

	if (ddi_copyin((void *)(uintptr_t)request->argp, (void *)scsi_pass,
	    sizeof (cpqary3_scsi_pass_t), mode)) {
		MEM_SFREE(scsi_pass, sizeof (cpqary3_scsi_pass_t));
		MEM_SFREE(request, sizeof (cpqary3_ioctl_request_t));
		return (EFAULT);
	}

	/*
	 * Get the free command list, fill in the scsi command and send it
	 * to the controller. This will return 0 on success.
	 */

	retval = cpqary3_ioctl_send_scsicmd(cpqary3p, scsi_pass, mode);

	/*
	 * Now copy the  scsi_pass (kernel) to the user argp
	 */

	if (ddi_copyout((void *)scsi_pass, (void *)(uintptr_t)request->argp,
	    sizeof (cpqary3_scsi_pass_t), mode)) {
		MEM_SFREE(scsi_pass, sizeof (cpqary3_scsi_pass_t));
		MEM_SFREE(request, sizeof (cpqary3_ioctl_request_t));
		retval = EFAULT; /* copyout failed */
	}

	/*
	 * Now copy the  request(kernel) to ioctl_reqp(user)
	 */

	if (ddi_copyout((void *)request, (void *)ioctl_reqp,
	    sizeof (cpqary3_ioctl_request_t), mode)) {
		MEM_SFREE(scsi_pass, sizeof (cpqary3_scsi_pass_t));
		MEM_SFREE(request, sizeof (cpqary3_ioctl_request_t));
		retval = EFAULT;
	}

	MEM_SFREE(scsi_pass, sizeof (cpqary3_scsi_pass_t));
	MEM_SFREE(request, sizeof (cpqary3_ioctl_request_t));

	return (retval);
}

/*
 * Function	:	cpqary3_ioctl_send_scsiccmd
 * Description	:	This routine will pass the SCSI commands to controller
 * Called By	:	cpqary3_ioctl_scsi_pass
 * Parameters	: 	cpqary3_t		- PerController structure,
 *			cpqary3_scsi_pass_t	- scsi parameter
 *			mode			- sent from the application
 * Return Values:	0 on success
 *			FAILURE, EFAULT, ETIMEOUT based on the failure
 */
static int32_t
cpqary3_ioctl_send_scsicmd(cpqary3_t *cpqary3p,
    cpqary3_scsi_pass_t *scsi_pass, int mode)
{
	cpqary3_cmdpvt_t	*memp    = NULL;
	CommandList_t		*cmdlist = NULL;
	int8_t			*databuf = NULL;
	uint8_t			retval  = 0;
	NoeBuffer		*evt;
	uint16_t		drive = 0;

	/* allocate a command with a dma buffer */
	memp = cpqary3_synccmd_alloc(cpqary3p, scsi_pass->buf_len);
	if (memp == NULL)
		return (FAILURE);

	/* Get the databuf when buf_len is greater than zero */
	if (scsi_pass->buf_len > 0) {
		databuf = memp->driverdata->sg;
	}

	cmdlist	= memp->cmdlist_memaddr;

	if (scsi_pass->io_direction == CPQARY3_SCSI_OUT) {
		/* Do a copyin when buf_len is greater than zero */
		if (scsi_pass->buf_len > 0) {
			if (ddi_copyin((void*)(uintptr_t)(scsi_pass->buf),
			    (void*)databuf, scsi_pass->buf_len, mode)) {
				cpqary3_synccmd_free(cpqary3p, memp);
				return (EFAULT);
			}
		}
	}

	/*
	 * Fill the scsi command
	 */
	cpqary3_ioctl_fil_scsi(cmdlist, scsi_pass);

	/* PERF */
	memp->complete = cpqary3_synccmd_complete;
	/* PERF */

	/* send command to controller and wait for a reply */
	if (cpqary3_synccmd_send(cpqary3p, memp, cpqary3_ioctl_wait_ms,
	    CPQARY3_SYNCCMD_SEND_WAITSIG) != 0) {
		cpqary3_synccmd_free(cpqary3p, memp);
		return (ETIMEDOUT);
	}

	/*
	 * If the command sent is NOE
	 * if the event class is CLASS_LOGICAL_DRIVE
	 * if the subcalls code is zero and if detail change is zero
	 * if the event specific data[3] is either 1 or 2 ie., if
	 * if the logical drive is failed set the target type to
	 * CPQARY3_TARGET_NONE
	 */

	/* NOE */
	if (cpqary3p->noe_support == 0 &&
	    cmdlist->Request.CDB[0] == 0x26 &&
	    cmdlist->Request.CDB[6] == BMIC_NOTIFY_ON_EVENT) {

		evt = (NoeBuffer*)MEM2DRVPVT(memp)->sg;

		if (evt->event_class_code == CLASS_LOGICAL_DRIVE &&
		    evt->event_subclass_code == SUB_CLASS_STATUS &&
		    evt->event_detail_code == DETAIL_CHANGE &&
		    evt->event_specific_data[3] == 1) {
			/* LINTED: alignment */
			drive =	*(uint16_t *)(&evt->event_specific_data[0]);
			drive = ((drive < CTLR_SCSI_ID) ?
			    drive : drive + CPQARY3_TGT_ALIGNMENT);

			if (cpqary3p && cpqary3p->cpqary3_tgtp[drive]) {
				cpqary3p->cpqary3_tgtp[drive]->type =
				    CPQARY3_TARGET_NONE;
			}
		}
	}

	/*
	 * Now the command is completed and copy the buffers back
	 * First copy the buffer databuf to scsi_pass->buf
	 * which is used as a buffer before passing the command to the
	 * controller.
	 */

	if (scsi_pass->io_direction == CPQARY3_SCSI_IN) {
		if (scsi_pass->buf_len > 0) {
			if (ddi_copyout((void *)databuf,
			    (void *)(uintptr_t)scsi_pass->buf,
			    scsi_pass->buf_len, mode)) {
				retval = EFAULT;
			}
		}
	}

	/*
	 * This is case where the command completes with error,
	 * Then tag would have set its 1st(10) bit.
	 */

	if (cmdlist->Header.Tag.drvinfo_n_err == CPQARY3_SYNCCMD_FAILURE) {
		scsi_pass->err_status = 1;
		bcopy((caddr_t)memp->errorinfop, &scsi_pass->err_info,
		    sizeof (ErrorInfo_t));
		switch (memp->errorinfop->CommandStatus) {
		case CISS_CMD_DATA_OVERRUN:
		case CISS_CMD_DATA_UNDERRUN:
		case CISS_CMD_SUCCESS:
		case CISS_CMD_TARGET_STATUS:
			retval = SUCCESS;
			break;
		default:
			retval = EIO;
			break;
		}
	}

	cpqary3_synccmd_free(cpqary3p, memp);

	return (retval);
}

/*
 * Function	:	cpqary3_ioctl_fil_scsi_
 * Description	:	This routine will fill the cmdlist with SCSI CDB
 * Called By	:	cpqary3_ioctl_send_scsicmd
 * Parameters	: 	cmdlist			- command packet
 *			cpqary3_scsi_pass_t	- scsi parameter
 * Return Values:	void
 */
static void
cpqary3_ioctl_fil_scsi(CommandList_t *cmdlist,
			cpqary3_scsi_pass_t *scsi_pass)
{
	cmdlist->Header.SGTotal = 1;
	cmdlist->Header.SGList = 1;
	cmdlist->Request.CDBLen = scsi_pass->cdb_len;
	cmdlist->Request.Timeout = scsi_pass->timeout;
	cmdlist->Request.Type.Type = CISS_TYPE_CMD;
	cmdlist->Request.Type.Attribute = CISS_ATTR_HEADOFQUEUE;

	switch (scsi_pass->io_direction) {
	case CPQARY3_SCSI_OUT:
		cmdlist->Request.Type.Direction = CISS_XFER_WRITE;
		break;
	case CPQARY3_SCSI_IN:
		cmdlist->Request.Type.Direction = CISS_XFER_READ;
		break;
	case CPQARY3_NODATA_XFER:
		cmdlist->Request.Type.Direction = CISS_XFER_NONE;
		break;
	default:
		cmdlist->Request.Type.Direction = CISS_XFER_RSVD;
		break;
	}

	/*
	 * Copy the SCSI CDB as is
	 */

	bcopy(&scsi_pass->cdb[0], &cmdlist->Request.CDB[0],
	    scsi_pass->cdb_len);

	/*
	 * Copy the Lun address from the request
	 */

	bcopy(&scsi_pass->lun_addr[0], &(cmdlist->Header.LUN),
	    sizeof (LUNAddr_t));

	cmdlist->SG[0].Len 	= scsi_pass->buf_len;
}

/*
 * Function	:	cpqary3_ioctl_fil_bmic_sas
 * Description	:	This routine will fill the cmdlist with BMIC details
 * Called By	:	cpqary3_ioctl_send_bmiccmd
 * Parameters	: 	cmdlist 	- command packet
 *			bmic_pass 	- bmic structure
 * Return Values:	void
 */
static void
cpqary3_ioctl_fil_bmic_sas(CommandList_t *cmdlist,
    cpqary3_bmic_pass_t *bmic_pass)
{
	cmdlist->Header.SGTotal = 1;
	cmdlist->Header.SGList = 1;
	cmdlist->Request.CDBLen = bmic_pass->cmd_len;
	cmdlist->Request.Timeout = bmic_pass->timeout;
	cmdlist->Request.Type.Type = CISS_TYPE_CMD;
	cmdlist->Request.Type.Attribute = CISS_ATTR_HEADOFQUEUE;

	switch (bmic_pass->io_direction) {
		case CPQARY3_SCSI_OUT:
			cmdlist->Request.Type.Direction = CISS_XFER_WRITE;
			break;
		case CPQARY3_SCSI_IN:
			cmdlist->Request.Type.Direction = CISS_XFER_READ;
			break;
		case CPQARY3_NODATA_XFER:
			cmdlist->Request.Type.Direction = CISS_XFER_NONE;
			break;
		default:
			cmdlist->Request.Type.Direction = CISS_XFER_RSVD;
			break;
	}

	cmdlist->Request.CDB[0] =
	    (bmic_pass->io_direction == CPQARY3_SCSI_IN) ? 0x26: 0x27;
	cmdlist->Request.CDB[1] = bmic_pass->unit_number; /* Unit Number */

	/*
	 * BMIC Detail - bytes 2[MSB] to 5[LSB]
	 */

	cmdlist->Request.CDB[2] = (bmic_pass->blk_number >> 24) & 0xff;
	cmdlist->Request.CDB[3] = (bmic_pass->blk_number >> 16) & 0xff;
	cmdlist->Request.CDB[4] = (bmic_pass->blk_number >> 8) & 0xff;
	cmdlist->Request.CDB[5] = bmic_pass->blk_number;

	cmdlist->Request.CDB[6] = bmic_pass->cmd; /* BMIC Command */

	/* Transfer Length - bytes 7[MSB] to 8[LSB] */

	cmdlist->Request.CDB[7] = (bmic_pass->buf_len >> 8) & 0xff;
	cmdlist->Request.CDB[8] = bmic_pass->buf_len & 0xff;
	cmdlist->Request.CDB[9] = 0x00; /* Reserved */

	/* Update CDB[2] = LSB bmix_index and CDB[9] = MSB bmic_index */
	switch (bmic_pass->cmd) {
	case HPSAS_ID_PHYSICAL_DRIVE:
	case HPSAS_TAPE_INQUIRY:
	case HPSAS_SENSE_MP_STAT:
	case HPSAS_SET_MP_THRESHOLD:
	case HPSAS_MP_PARAM_CONTROL:
	case HPSAS_SENSE_DRV_ERR_LOG:
	case HPSAS_SET_MP_VALUE:
		cmdlist -> Request.CDB[2] = bmic_pass->bmic_index & 0xff;
		cmdlist -> Request.CDB[9] = (bmic_pass->bmic_index >>8) & 0xff;
		break;

	case HPSAS_ID_LOG_DRIVE:
	case HPSAS_SENSE_LOG_DRIVE:
	case HPSAS_READ:
	case HPSAS_WRITE:
	case HPSAS_WRITE_THROUGH:
	case HPSAS_SENSE_CONFIG:
	case HPSAS_SET_CONFIG:
	case HPSAS_BYPASS_VOL_STATE:
	case HPSAS_CHANGE_CONFIG:
	case HPSAS_SENSE_ORIG_CONFIG:
	case HPSAS_LABEL_LOG_DRIVE:
		/* Unit Number MSB */
		cmdlist->Request.CDB[9] = (bmic_pass->unit_number >> 8) & 0xff;
		break;

	default:
		break;
	}


	/*
	 * Copy the Lun address from the request
	 */

	bcopy(&bmic_pass->lun_addr[0], &(cmdlist->Header.LUN),
	    sizeof (LUNAddr_t));

	cmdlist->SG[0].Len = bmic_pass->buf_len;
}
