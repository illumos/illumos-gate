/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2012 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#include <emlxs.h>

/* Required for EMLXS_CONTEXT in EMLXS_MSGF calls */
EMLXS_MSG_DEF(EMLXS_MBOX_C);


emlxs_table_t emlxs_mb_status_table[] = {
	{MBX_SUCCESS, "SUCCESS"},
	{MBX_FAILURE, "FAILURE"},
	{MBXERR_NUM_IOCBS, "NUM_IOCBS"},
	{MBXERR_IOCBS_EXCEEDED, "IOCBS_EXCEEDED"},
	{MBXERR_BAD_RING_NUMBER, "BAD_RING_NUMBER"},
	{MBXERR_MASK_ENTRIES_RANGE, "MASK_ENTRIES_RANGE"},
	{MBXERR_MASKS_EXCEEDED, "MASKS_EXCEEDED"},
	{MBXERR_BAD_PROFILE, "BAD_PROFILE"},
	{MBXERR_BAD_DEF_CLASS, "BAD_DEF_CLASS"},
	{MBXERR_BAD_MAX_RESPONDER, "BAD_MAX_RESPONDER"},
	{MBXERR_BAD_MAX_ORIGINATOR, "BAD_MAX_ORIGINATOR"},
	{MBXERR_RPI_REGISTERED, "RPI_REGISTERED"},
	{MBXERR_RPI_FULL, "RPI_FULL"},
	{MBXERR_NO_RESOURCES, "NO_RESOURCES"},
	{MBXERR_BAD_RCV_LENGTH, "BAD_RCV_LENGTH"},
	{MBXERR_DMA_ERROR, "DMA_ERROR"},
	{MBXERR_NOT_SUPPORTED, "NOT_SUPPORTED"},
	{MBXERR_UNSUPPORTED_FEATURE, "UNSUPPORTED_FEATURE"},
	{MBXERR_UNKNOWN_COMMAND, "UNKNOWN_COMMAND"},
	{MBXERR_BAD_IP_BIT, "BAD_IP_BIT"},
	{MBXERR_BAD_PCB_ALIGN, "BAD_PCB_ALIGN"},
	{MBXERR_BAD_HBQ_ID, "BAD_HBQ_ID"},
	{MBXERR_BAD_HBQ_STATE, "BAD_HBQ_STATE"},
	{MBXERR_BAD_HBQ_MASK_NUM, "BAD_HBQ_MASK_NUM"},
	{MBXERR_BAD_HBQ_MASK_SUBSET, "BAD_HBQ_MASK_SUBSET"},
	{MBXERR_HBQ_CREATE_FAIL, "HBQ_CREATE_FAIL"},
	{MBXERR_HBQ_EXISTING, "HBQ_EXISTING"},
	{MBXERR_HBQ_RSPRING_FULL, "HBQ_RSPRING_FULL"},
	{MBXERR_HBQ_DUP_MASK, "HBQ_DUP_MASK"},
	{MBXERR_HBQ_INVAL_GET_PTR, "HBQ_INVAL_GET_PTR"},
	{MBXERR_BAD_HBQ_SIZE, "BAD_HBQ_SIZE"},
	{MBXERR_BAD_HBQ_ORDER, "BAD_HBQ_ORDER"},
	{MBXERR_INVALID_ID, "INVALID_ID"},
	{MBXERR_INVALID_VFI, "INVALID_VFI"},
	{MBXERR_FLASH_WRITE_FAILED, "FLASH_WRITE_FAILED"},
	{MBXERR_INVALID_LINKSPEED, "INVALID_LINKSPEED"},
	{MBXERR_BAD_REDIRECT, "BAD_REDIRECT"},
	{MBXERR_RING_ALREADY_CONFIG, "RING_ALREADY_CONFIG"},
	{MBXERR_RING_INACTIVE, "RING_INACTIVE"},
	{MBXERR_RPI_INACTIVE, "RPI_INACTIVE"},
	{MBXERR_NO_ACTIVE_XRI, "NO_ACTIVE_XRI"},
	{MBXERR_XRI_NOT_ACTIVE, "XRI_NOT_ACTIVE"},
	{MBXERR_RPI_INUSE, "RPI_INUSE"},
	{MBXERR_NO_LINK_ATTENTION, "NO_LINK_ATTENTION"},
	{MBXERR_INVALID_SLI_MODE, "INVALID_SLI_MODE"},
	{MBXERR_INVALID_HOST_PTR, "INVALID_HOST_PTR"},
	{MBXERR_CANT_CFG_SLI_MODE, "CANT_CFG_SLI_MODE"},
	{MBXERR_BAD_OVERLAY, "BAD_OVERLAY"},
	{MBXERR_INVALID_FEAT_REQ, "INVALID_FEAT_REQ"},
	{MBXERR_CONFIG_CANT_COMPLETE, "CONFIG_CANT_COMPLETE"},
	{MBXERR_DID_ALREADY_REGISTERED, "DID_ALREADY_REGISTERED"},
	{MBXERR_DID_INCONSISTENT, "DID_INCONSISTENT"},
	{MBXERR_VPI_TOO_LARGE, "VPI_TOO_LARGE"},
	{MBXERR_STILL_ASSOCIATED, "STILL_ASSOCIATED"},
	{MBXERR_INVALID_VF_STATE, "INVALID_VF_STATE"},
	{MBXERR_VFI_ALREADY_REGISTERED, "VFI_ALREADY_REGISTERED"},
	{MBXERR_VFI_TOO_LARGE, "VFI_TOO_LARGE"},
	{MBXERR_LOAD_FW_FAILED, "LOAD_FW_FAILED"},
	{MBXERR_FIND_FW_FAILED, "FIND_FW_FAILED"},
};

emlxs_table_t emlxs_mb_cmd_table[] = {
	{MBX_SHUTDOWN, "SHUTDOWN"},
	{MBX_LOAD_SM, "LOAD_SM"},
	{MBX_READ_NV, "READ_NV"},
	{MBX_WRITE_NV, "WRITE_NV"},
	{MBX_RUN_BIU_DIAG, "RUN_BIU_DIAG"},
	{MBX_INIT_LINK, "INIT_LINK"},
	{MBX_DOWN_LINK, "DOWN_LINK"},
	{MBX_CONFIG_LINK, "CONFIG_LINK"},
	{MBX_PART_SLIM, "PART_SLIM"},
	{MBX_CONFIG_RING, "CONFIG_RING"},
	{MBX_RESET_RING, "RESET_RING"},
	{MBX_READ_CONFIG, "READ_CONFIG"},
	{MBX_READ_RCONFIG, "READ_RCONFIG"},
	{MBX_READ_SPARM, "READ_SPARM"},
	{MBX_READ_STATUS, "READ_STATUS"},
	{MBX_READ_RPI, "READ_RPI"},
	{MBX_READ_XRI, "READ_XRI"},
	{MBX_READ_REV, "READ_REV"},
	{MBX_READ_LNK_STAT, "READ_LNK_STAT"},
	{MBX_REG_LOGIN, "REG_LOGIN"},
	{MBX_UNREG_LOGIN, "UNREG_RPI"},
	{MBX_READ_LA, "READ_LA"},
	{MBX_CLEAR_LA, "CLEAR_LA"},
	{MBX_DUMP_MEMORY, "DUMP_MEMORY"},
	{MBX_DUMP_CONTEXT, "DUMP_CONTEXT"},
	{MBX_RUN_DIAGS, "RUN_DIAGS"},
	{MBX_RESTART, "RESTART"},
	{MBX_UPDATE_CFG, "UPDATE_CFG"},
	{MBX_DOWN_LOAD, "DOWN_LOAD"},
	{MBX_DEL_LD_ENTRY, "DEL_LD_ENTRY"},
	{MBX_RUN_PROGRAM, "RUN_PROGRAM"},
	{MBX_SET_MASK, "SET_MASK"},
	{MBX_SET_VARIABLE, "SET_VARIABLE"},
	{MBX_UNREG_D_ID, "UNREG_D_ID"},
	{MBX_KILL_BOARD, "KILL_BOARD"},
	{MBX_CONFIG_FARP, "CONFIG_FARP"},
	{MBX_LOAD_AREA, "LOAD_AREA"},
	{MBX_RUN_BIU_DIAG64, "RUN_BIU_DIAG64"},
	{MBX_CONFIG_PORT, "CONFIG_PORT"},
	{MBX_READ_SPARM64, "READ_SPARM64"},
	{MBX_READ_RPI64, "READ_RPI64"},
	{MBX_CONFIG_MSI, "CONFIG_MSI"},
	{MBX_CONFIG_MSIX, "CONFIG_MSIX"},
	{MBX_REG_LOGIN64, "REG_RPI"},
	{MBX_READ_LA64, "READ_LA64"},
	{MBX_FLASH_WR_ULA, "FLASH_WR_ULA"},
	{MBX_SET_DEBUG, "SET_DEBUG"},
	{MBX_GET_DEBUG, "GET_DEBUG"},
	{MBX_LOAD_EXP_ROM, "LOAD_EXP_ROM"},
	{MBX_BEACON, "BEACON"},
	{MBX_CONFIG_HBQ, "CONFIG_HBQ"},	/* SLI3 */
	{MBX_REG_VPI, "REG_VPI"},	/* NPIV */
	{MBX_UNREG_VPI, "UNREG_VPI"},	/* NPIV */
	{MBX_ASYNC_EVENT, "ASYNC_EVENT"},
	{MBX_HEARTBEAT, "HEARTBEAT"},
	{MBX_READ_EVENT_LOG_STATUS, "READ_EVENT_LOG_STATUS"},
	{MBX_READ_EVENT_LOG, "READ_EVENT_LOG"},
	{MBX_WRITE_EVENT_LOG, "WRITE_EVENT_LOG"},
	{MBX_NV_LOG, "NV_LOG"},
	{MBX_PORT_CAPABILITIES, "PORT_CAPABILITIES"},
	{MBX_IOV_CONTROL, "IOV_CONTROL"},
	{MBX_IOV_MBX, "IOV_MBX"},
	{MBX_SLI_CONFIG, "SLI_CONFIG"},
	{MBX_REQUEST_FEATURES, "REQUEST_FEATURES"},
	{MBX_RESUME_RPI, "RESUME_RPI"},
	{MBX_REG_VFI, "REG_VFI"},
	{MBX_REG_FCFI, "REG_FCFI"},
	{MBX_UNREG_VFI, "UNREG_VFI"},
	{MBX_UNREG_FCFI, "UNREG_FCFI"},
	{MBX_INIT_VFI, "INIT_VFI"},
	{MBX_INIT_VPI, "INIT_VPI"},
	{MBX_WRITE_VPARMS, "WRITE_VPARMS"},
	{MBX_ACCESS_VDATA, "ACCESS_VDATA"}
};	/* emlxs_mb_cmd_table */


emlxs_table_t emlxs_request_feature_table[] = {
	{SLI4_FEATURE_INHIBIT_AUTO_ABTS, "IAA "},	/* Bit 0 */
	{SLI4_FEATURE_NPIV, "NPIV "},			/* Bit 1 */
	{SLI4_FEATURE_DIF, "DIF "},			/* Bit 2 */
	{SLI4_FEATURE_VIRTUAL_FABRICS, "VF "},		/* Bit 3 */
	{SLI4_FEATURE_FCP_INITIATOR, "FCPI "},		/* Bit 4 */
	{SLI4_FEATURE_FCP_TARGET, "FCPT "},		/* Bit 5 */
	{SLI4_FEATURE_FCP_COMBO, "FCPC "},		/* Bit 6 */
	{SLI4_FEATURE_RSVD1, "RSVD1 "},			/* Bit 7 */
	{SLI4_FEATURE_RQD, "RQD "},			/* Bit 8 */
	{SLI4_FEATURE_INHIBIT_AUTO_ABTS_R, "IAAR "},	/* Bit 9 */
	{SLI4_FEATURE_HIGH_LOGIN_MODE, "HLM "},		/* Bit 10 */
	{SLI4_FEATURE_PERF_HINT, "PERFH "}		/* Bit 11 */
};	/* emlxs_request_feature_table */


extern char *
emlxs_mb_xlate_status(uint32_t status)
{
	static char	buffer[32];
	uint32_t	i;
	uint32_t	count;

	count = sizeof (emlxs_mb_status_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (status == emlxs_mb_status_table[i].code) {
			return (emlxs_mb_status_table[i].string);
		}
	}

	(void) snprintf(buffer, sizeof (buffer), "status=%x", status);
	return (buffer);

} /* emlxs_mb_xlate_status() */


/* SLI4 */
/*ARGSUSED*/
extern void
emlxs_mb_resetport(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX4 *mb4 = (MAILBOX4 *)mbq;

	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);
	mbq->nonembed = NULL;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

	/*
	 * Signifies an embedded command
	 */
	mb4->un.varSLIConfig.be.embedded = 1;

	mb4->mbxCommand = MBX_SLI_CONFIG;
	mb4->mbxOwner = OWN_HOST;
	mb4->un.varSLIConfig.be.payload_length = IOCTL_HEADER_SZ;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req.subsystem =
	    IOCTL_SUBSYSTEM_COMMON;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req.opcode = COMMON_OPCODE_RESET;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req.timeout = 0;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req.req_length = 0;

	return;

} /* emlxs_mb_resetport() */


/* SLI4 */
/*ARGSUSED*/
extern void
emlxs_mb_request_features(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t mask)
{
	MAILBOX4 *mb4 = (MAILBOX4 *)mbq;

	hba->flag &= ~FC_NPIV_ENABLED;
	hba->sli.sli4.flag &= ~(EMLXS_SLI4_PHON | EMLXS_SLI4_PHWQ);

	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);
	mbq->nonembed = NULL;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

	mb4->mbxCommand = MBX_REQUEST_FEATURES;
	mb4->mbxOwner = OWN_HOST;

	mb4->un.varReqFeatures.featuresRequested = mask;
	return;

} /* emlxs_mb_request_features() */


/* SLI4 */
/*ARGSUSED*/
extern void
emlxs_mb_noop(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX4 *mb4 = (MAILBOX4 *)mbq;
	IOCTL_COMMON_NOP *nop;

	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);
	mbq->nonembed = NULL;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

	/*
	 * Signifies an embedded command
	 */
	mb4->un.varSLIConfig.be.embedded = 1;

	mb4->mbxCommand = MBX_SLI_CONFIG;
	mb4->mbxOwner = OWN_HOST;
	mb4->un.varSLIConfig.be.payload_length = sizeof (IOCTL_COMMON_NOP) +
	    IOCTL_HEADER_SZ;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req.subsystem =
	    IOCTL_SUBSYSTEM_COMMON;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req.opcode = COMMON_OPCODE_NOP;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req.timeout = 0;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req.req_length =
	    sizeof (IOCTL_COMMON_NOP);
	nop = (IOCTL_COMMON_NOP *)&mb4->un.varSLIConfig.payload;
	nop->params.request.context = -1;

	return;

} /* emlxs_mb_noop() */


/* SLI4 */
/*ARGSUSED*/
extern int
emlxs_mbext_noop(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX4 *mb4 = (MAILBOX4 *)mbq;
	IOCTL_COMMON_NOP *nop;
	MATCHMAP *mp;
	mbox_req_hdr_t	*hdr_req;

	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);

	if ((mp = (MATCHMAP *)emlxs_mem_get(hba, MEM_BUF)) == 0) {
		return (1);
	}
	/*
	 * Save address for completion
	 * Signifies a non-embedded command
	 */
	mb4->un.varSLIConfig.be.embedded = 0;
	mbq->nonembed = (void *)mp;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

	mb4->mbxCommand = MBX_SLI_CONFIG;
	mb4->mbxOwner = OWN_HOST;

	hdr_req = (mbox_req_hdr_t *)mp->virt;
	hdr_req->subsystem = IOCTL_SUBSYSTEM_COMMON;
	hdr_req->opcode = COMMON_OPCODE_NOP;
	hdr_req->timeout = 0;
	hdr_req->req_length = sizeof (IOCTL_COMMON_NOP);
	nop = (IOCTL_COMMON_NOP *)(hdr_req + 1);
	nop->params.request.context = -1;

	return (0);

} /* emlxs_mbext_noop() */


/* SLI4 */
/*ARGSUSED*/
extern void
emlxs_mb_eq_create(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t num)
{
	MAILBOX4 *mb4 = (MAILBOX4 *)mbq;
	IOCTL_COMMON_EQ_CREATE *qp;
	uint64_t	addr;

	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);
	mbq->nonembed = NULL;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

	/*
	 * Signifies an embedded command
	 */
	mb4->un.varSLIConfig.be.embedded = 1;

	mb4->mbxCommand = MBX_SLI_CONFIG;
	mb4->mbxOwner = OWN_HOST;
	mb4->un.varSLIConfig.be.payload_length =
	    sizeof (IOCTL_COMMON_EQ_CREATE) + IOCTL_HEADER_SZ;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req.subsystem =
	    IOCTL_SUBSYSTEM_COMMON;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req.opcode = COMMON_OPCODE_EQ_CREATE;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req.timeout = 0;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req.req_length =
	    sizeof (IOCTL_COMMON_EQ_CREATE);
	mb4->un.varSLIConfig.be.un_hdr.hdr_req.version = 0;

	qp = (IOCTL_COMMON_EQ_CREATE *)&mb4->un.varSLIConfig.payload;

	/* 1024 * 4 bytes = 4K */
	qp->params.request.EQContext.Count = EQ_ELEMENT_COUNT_1024;
	qp->params.request.EQContext.Valid = 1;
	qp->params.request.EQContext.DelayMult = EQ_DELAY_MULT;

	addr = hba->sli.sli4.eq[num].addr.phys;
	qp->params.request.NumPages = 1;
	qp->params.request.Pages[0].addrLow = PADDR_LO(addr);
	qp->params.request.Pages[0].addrHigh = PADDR_HI(addr);

	return;

} /* emlxs_mb_eq_create() */


/* SLI4 */
/*ARGSUSED*/
extern void
emlxs_mb_cq_create(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t num)
{
	MAILBOX4 *mb4 = (MAILBOX4 *)mbq;
	IOCTL_COMMON_CQ_CREATE *qp;
	IOCTL_COMMON_CQ_CREATE_V2 *qp2;
	uint64_t	addr;
	uint32_t	i;

	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);
	mbq->nonembed = NULL;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

	/*
	 * Signifies an embedded command
	 */
	mb4->un.varSLIConfig.be.embedded = 1;

	mb4->mbxCommand = MBX_SLI_CONFIG;
	mb4->mbxOwner = OWN_HOST;

	switch (hba->sli.sli4.param.CQV) {
	case 0:
		mb4->un.varSLIConfig.be.payload_length =
		    sizeof (IOCTL_COMMON_CQ_CREATE) + IOCTL_HEADER_SZ;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.subsystem =
		    IOCTL_SUBSYSTEM_COMMON;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.opcode =
		    COMMON_OPCODE_CQ_CREATE;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.timeout = 0;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.req_length =
		    sizeof (IOCTL_COMMON_CQ_CREATE);
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.version = 0;

		qp = (IOCTL_COMMON_CQ_CREATE *)
		    &mb4->un.varSLIConfig.payload;

		/* 256 * 16 bytes = 4K */
		qp->params.request.CQContext.Count = CQ_ELEMENT_COUNT_256;
		qp->params.request.CQContext.EQId =
		    (uint8_t)hba->sli.sli4.cq[num].eqid;
		qp->params.request.CQContext.Valid = 1;
		qp->params.request.CQContext.Eventable = 1;
		qp->params.request.CQContext.NoDelay = 0;
		qp->params.request.CQContext.CoalesceWM = 0;

		addr = hba->sli.sli4.cq[num].addr.phys;
		qp->params.request.NumPages = 1;
		qp->params.request.Pages[0].addrLow = PADDR_LO(addr);
		qp->params.request.Pages[0].addrHigh = PADDR_HI(addr);

		break;

	case 2:
	default:
		mb4->un.varSLIConfig.be.payload_length =
		    sizeof (IOCTL_COMMON_CQ_CREATE_V2) + IOCTL_HEADER_SZ;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.subsystem =
		    IOCTL_SUBSYSTEM_COMMON;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.opcode =
		    COMMON_OPCODE_CQ_CREATE;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.timeout = 0;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.req_length =
		    sizeof (IOCTL_COMMON_CQ_CREATE_V2);
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.version = 2;

		qp2 = (IOCTL_COMMON_CQ_CREATE_V2 *)
		    &mb4->un.varSLIConfig.payload;

		qp2->params.request.CQContext.CqeCnt = CQ_ELEMENT_COUNT_1024;
		qp2->params.request.CQContext.CqeSize = CQE_SIZE_16_BYTES;
		qp2->params.request.CQContext.EQId = hba->sli.sli4.cq[num].eqid;
		qp2->params.request.CQContext.Valid = 1;
		qp2->params.request.CQContext.AutoValid = 0;
		qp2->params.request.CQContext.Eventable = 1;
		qp2->params.request.CQContext.NoDelay = 0;
		qp2->params.request.CQContext.Count1 = 0;
		qp2->params.request.CQContext.CoalesceWM = 0;

		addr = hba->sli.sli4.cq[num].addr.phys;
		qp2->params.request.PageSize = CQ_PAGE_SIZE_4K;
		qp2->params.request.NumPages = EMLXS_NUM_CQ_PAGES_V2;

		for (i = 0; i < EMLXS_NUM_CQ_PAGES_V2; i++) {
			qp2->params.request.Pages[i].addrLow = PADDR_LO(addr);
			qp2->params.request.Pages[i].addrHigh = PADDR_HI(addr);
			addr += 4096;
		}

		break;
	}
	return;

} /* emlxs_mb_cq_create() */


/* SLI4 */
/*ARGSUSED*/
extern void
emlxs_mb_get_port_name(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX4 *mb4 = (MAILBOX4 *)mbq;

	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);
	mbq->nonembed = NULL;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

	mb4->un.varSLIConfig.be.embedded = 1;
	mb4->mbxCommand = MBX_SLI_CONFIG;
	mb4->mbxOwner = OWN_HOST;

	mb4->un.varSLIConfig.be.payload_length = IOCTL_HEADER_SZ;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req.subsystem =
	    IOCTL_SUBSYSTEM_COMMON;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req.opcode =
	    COMMON_OPCODE_GET_PORT_NAME;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req.timeout = 0;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req.req_length = 0;

	if (hba->model_info.chip & EMLXS_BE_CHIPS) {
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.version = 0; /* V0 */
	} else {
		IOCTL_COMMON_GET_PORT_NAME_V1 *pn;

		mb4->un.varSLIConfig.be.un_hdr.hdr_req.version = 1; /* V1 */

		pn = (IOCTL_COMMON_GET_PORT_NAME_V1 *)
		    &mb4->un.varSLIConfig.payload;
		pn->params.request.pt = PORT_TYPE_FC;
	}

	return;

} /* emlxs_mb_get_port_name() */


/* SLI4 */
/*ARGSUSED*/
extern void
emlxs_mb_get_sli4_params(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX4 *mb4 = (MAILBOX4 *)mbq;

	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);
	mbq->nonembed = NULL;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

	mb4->un.varSLIConfig.be.embedded = 1;
	mb4->mbxCommand = MBX_SLI_CONFIG;
	mb4->mbxOwner = OWN_HOST;

	mb4->un.varSLIConfig.be.payload_length = IOCTL_HEADER_SZ;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req.subsystem =
	    IOCTL_SUBSYSTEM_COMMON;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req.opcode =
	    COMMON_OPCODE_GET_SLI4_PARAMS;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req.timeout = 0;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req.req_length = 0;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req.version = 0; /* V0 */

	return;

} /* emlxs_mb_get_sli4_params() */


/* SLI4 */
/*ARGSUSED*/
extern void
emlxs_mb_get_extents_info(emlxs_hba_t *hba, MAILBOXQ *mbq, uint16_t type)
{
	MAILBOX4 *mb4 = (MAILBOX4 *)mbq;
	IOCTL_COMMON_EXTENTS *ep;

	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);
	mbq->nonembed = NULL;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

	mb4->un.varSLIConfig.be.embedded = 1;
	mb4->mbxCommand = MBX_SLI_CONFIG;
	mb4->mbxOwner = OWN_HOST;

	mb4->un.varSLIConfig.be.payload_length = IOCTL_HEADER_SZ;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.subsystem =
	    IOCTL_SUBSYSTEM_COMMON;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.opcode =
	    COMMON_OPCODE_GET_EXTENTS_INFO;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.timeout = 0;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.req_length =
	    sizeof (IOCTL_COMMON_EXTENTS);
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.vf_number = 0;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.vh_number = 0;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.pf_number = 0;

	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.version = 0; /* V0 */

	ep = (IOCTL_COMMON_EXTENTS *)&mb4->un.varSLIConfig.payload;
	ep->params.request.RscType = type;

	return;

} /* emlxs_mb_get_extents_info() */


/* SLI4 */
/*ARGSUSED*/
extern void
emlxs_mb_get_extents(emlxs_hba_t *hba, MAILBOXQ *mbq, uint16_t type)
{
	MAILBOX4 *mb4 = (MAILBOX4 *)mbq;
	IOCTL_COMMON_EXTENTS *ep;

	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);
	mbq->nonembed = NULL;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

	mb4->un.varSLIConfig.be.embedded = 1;
	mb4->mbxCommand = MBX_SLI_CONFIG;
	mb4->mbxOwner = OWN_HOST;

	mb4->un.varSLIConfig.be.payload_length = IOCTL_HEADER_SZ;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.subsystem =
	    IOCTL_SUBSYSTEM_COMMON;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.opcode =
	    COMMON_OPCODE_GET_EXTENTS;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.timeout = 0;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.req_length =
	    sizeof (IOCTL_COMMON_EXTENTS);
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.vf_number = 0;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.vh_number = 0;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.pf_number = 0;

	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.version = 0; /* V0 */

	ep = (IOCTL_COMMON_EXTENTS *)&mb4->un.varSLIConfig.payload;
	ep->params.request.RscType = type;

	return;

} /* emlxs_mb_get_extents() */


/* SLI4 */
/*ARGSUSED*/
extern void
emlxs_mb_alloc_extents(emlxs_hba_t *hba, MAILBOXQ *mbq, uint16_t type,
    uint16_t count)
{
	MAILBOX4 *mb4 = (MAILBOX4 *)mbq;
	IOCTL_COMMON_EXTENTS *ep;

	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);
	mbq->nonembed = NULL;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

	mb4->un.varSLIConfig.be.embedded = 1;
	mb4->mbxCommand = MBX_SLI_CONFIG;
	mb4->mbxOwner = OWN_HOST;

	mb4->un.varSLIConfig.be.payload_length = IOCTL_HEADER_SZ;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.subsystem =
	    IOCTL_SUBSYSTEM_COMMON;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.opcode =
	    COMMON_OPCODE_ALLOC_EXTENTS;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.timeout = 0;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.req_length =
	    sizeof (IOCTL_COMMON_EXTENTS);
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.vf_number = 0;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.vh_number = 0;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.pf_number = 0;

	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.version = 0; /* V0 */

	ep = (IOCTL_COMMON_EXTENTS *)&mb4->un.varSLIConfig.payload;
	ep->params.request.RscType = type;

	count = min(count, MAX_EXTENTS);
	ep->params.request.RscCnt = count;

	return;

} /* emlxs_mb_alloc_extents() */


/* SLI4 */
/*ARGSUSED*/
extern void
emlxs_mb_dealloc_extents(emlxs_hba_t *hba, MAILBOXQ *mbq, uint16_t type)
{
	MAILBOX4 *mb4 = (MAILBOX4 *)mbq;
	IOCTL_COMMON_EXTENTS *ep;

	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);
	mbq->nonembed = NULL;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

	mb4->un.varSLIConfig.be.embedded = 1;
	mb4->mbxCommand = MBX_SLI_CONFIG;
	mb4->mbxOwner = OWN_HOST;

	mb4->un.varSLIConfig.be.payload_length = IOCTL_HEADER_SZ;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.subsystem =
	    IOCTL_SUBSYSTEM_COMMON;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.opcode =
	    COMMON_OPCODE_DEALLOC_EXTENTS;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.timeout = 0;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.req_length =
	    sizeof (IOCTL_COMMON_EXTENTS);
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.vf_number = 0;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.vh_number = 0;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.pf_number = 0;

	mb4->un.varSLIConfig.be.un_hdr.hdr_req2.version = 0; /* V0 */

	ep = (IOCTL_COMMON_EXTENTS *)&mb4->un.varSLIConfig.payload;
	ep->params.request.RscType = type;

	return;

} /* emlxs_mb_dealloc_extents() */


/* SLI4 */
/*ARGSUSED*/
extern void
emlxs_mb_wq_create(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t num)
{
	MAILBOX4 *mb4 = (MAILBOX4 *)mbq;
	IOCTL_FCOE_WQ_CREATE *qp;
	IOCTL_FCOE_WQ_CREATE_V1 *qp1;
	uint64_t addr;
	int i;

	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);
	mbq->nonembed = NULL;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

	/*
	 * Signifies an embedded command
	 */
	mb4->un.varSLIConfig.be.embedded = 1;

	mb4->mbxCommand = MBX_SLI_CONFIG;
	mb4->mbxOwner = OWN_HOST;

	switch (hba->sli.sli4.param.WQV) {
	case 0:
		mb4->un.varSLIConfig.be.payload_length =
		    sizeof (IOCTL_FCOE_WQ_CREATE) + IOCTL_HEADER_SZ;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.subsystem =
		    IOCTL_SUBSYSTEM_FCOE;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.opcode =
		    FCOE_OPCODE_WQ_CREATE;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.timeout = 0;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.req_length =
		    sizeof (IOCTL_FCOE_WQ_CREATE);
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.version = 0;

		addr = hba->sli.sli4.wq[num].addr.phys;
		qp = (IOCTL_FCOE_WQ_CREATE *)&mb4->un.varSLIConfig.payload;

		qp->params.request.CQId = hba->sli.sli4.wq[num].cqid;

		qp->params.request.NumPages = EMLXS_NUM_WQ_PAGES;
		for (i = 0; i < EMLXS_NUM_WQ_PAGES; i++) {
			qp->params.request.Pages[i].addrLow = PADDR_LO(addr);
			qp->params.request.Pages[i].addrHigh = PADDR_HI(addr);
			addr += 4096;
		}

		break;

	case 1:
	default:
		mb4->un.varSLIConfig.be.payload_length =
		    sizeof (IOCTL_FCOE_WQ_CREATE_V1) + IOCTL_HEADER_SZ;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.subsystem =
		    IOCTL_SUBSYSTEM_FCOE;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.opcode =
		    FCOE_OPCODE_WQ_CREATE;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.timeout = 0;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.req_length =
		    sizeof (IOCTL_FCOE_WQ_CREATE_V1);
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.version = 1;

		addr = hba->sli.sli4.wq[num].addr.phys;
		qp1 = (IOCTL_FCOE_WQ_CREATE_V1 *)&mb4->un.varSLIConfig.payload;

		qp1->params.request.CQId = hba->sli.sli4.wq[num].cqid;
		qp1->params.request.NumPages = EMLXS_NUM_WQ_PAGES;

		qp1->params.request.WqeCnt = WQ_DEPTH;
		qp1->params.request.WqeSize = WQE_SIZE_64_BYTES;
		qp1->params.request.PageSize = WQ_PAGE_SIZE_4K;

		for (i = 0; i < EMLXS_NUM_WQ_PAGES; i++) {
			qp1->params.request.Pages[i].addrLow = PADDR_LO(addr);
			qp1->params.request.Pages[i].addrHigh = PADDR_HI(addr);
			addr += 4096;
		}

		break;
	}

	return;

} /* emlxs_mb_wq_create() */


/* SLI4 */
/*ARGSUSED*/
extern void
emlxs_mb_rq_create(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t num)
{
	MAILBOX4 *mb4 = (MAILBOX4 *)mbq;
	IOCTL_FCOE_RQ_CREATE *qp;
	IOCTL_FCOE_RQ_CREATE_V1 *qp1;
	uint64_t	addr;

	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);
	mbq->nonembed = NULL;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

	/*
	 * Signifies an embedded command
	 */
	mb4->un.varSLIConfig.be.embedded = 1;

	mb4->mbxCommand = MBX_SLI_CONFIG;
	mb4->mbxOwner = OWN_HOST;

	switch (hba->sli.sli4.param.RQV) {
	case 0:
		mb4->un.varSLIConfig.be.payload_length =
		    sizeof (IOCTL_FCOE_RQ_CREATE) + IOCTL_HEADER_SZ;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.subsystem =
		    IOCTL_SUBSYSTEM_FCOE;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.opcode =
		    FCOE_OPCODE_RQ_CREATE;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.timeout = 0;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.req_length =
		    sizeof (IOCTL_FCOE_RQ_CREATE);
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.version = 0;

		addr = hba->sli.sli4.rq[num].addr.phys;

		qp = (IOCTL_FCOE_RQ_CREATE *)&mb4->un.varSLIConfig.payload;

		qp->params.request.RQContext.RqeCnt	= RQ_DEPTH_EXPONENT;
		qp->params.request.RQContext.BufferSize	= RQB_DATA_SIZE;
		qp->params.request.RQContext.CQId	=
		    hba->sli.sli4.rq[num].cqid;

		qp->params.request.NumPages = 1;
		qp->params.request.Pages[0].addrLow = PADDR_LO(addr);
		qp->params.request.Pages[0].addrHigh = PADDR_HI(addr);

		break;

	case 1:
	default:
		mb4->un.varSLIConfig.be.payload_length =
		    sizeof (IOCTL_FCOE_RQ_CREATE_V1) + IOCTL_HEADER_SZ;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.subsystem =
		    IOCTL_SUBSYSTEM_FCOE;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.opcode =
		    FCOE_OPCODE_RQ_CREATE;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.timeout = 0;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.req_length =
		    sizeof (IOCTL_FCOE_RQ_CREATE_V1);
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.version = 1;

		addr = hba->sli.sli4.rq[num].addr.phys;

		qp1 = (IOCTL_FCOE_RQ_CREATE_V1 *)&mb4->un.varSLIConfig.payload;

		qp1->params.request.RQContext.RqeCnt	 = RQ_DEPTH;
		qp1->params.request.RQContext.RqeSize	 = RQE_SIZE_8_BYTES;
		qp1->params.request.RQContext.PageSize	 = RQ_PAGE_SIZE_4K;

		qp1->params.request.RQContext.BufferSize = RQB_DATA_SIZE;
		qp1->params.request.RQContext.CQId	 =
		    hba->sli.sli4.rq[num].cqid;

		qp1->params.request.NumPages = 1;
		qp1->params.request.Pages[0].addrLow = PADDR_LO(addr);
		qp1->params.request.Pages[0].addrHigh = PADDR_HI(addr);

		break;
	}

	return;

} /* emlxs_mb_rq_create() */


/* SLI4 */
/*ARGSUSED*/
extern void
emlxs_mb_mq_create(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX4 *mb4 = (MAILBOX4 *)mbq;
	IOCTL_COMMON_MQ_CREATE *qp;
	uint64_t	addr;

	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);
	mbq->nonembed = NULL;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

	/*
	 * Signifies an embedded command
	 */
	mb4->un.varSLIConfig.be.embedded = 1;

	mb4->mbxCommand = MBX_SLI_CONFIG;
	mb4->mbxOwner = OWN_HOST;
	mb4->un.varSLIConfig.be.payload_length =
	    sizeof (IOCTL_COMMON_MQ_CREATE) + IOCTL_HEADER_SZ;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req.subsystem =
	    IOCTL_SUBSYSTEM_COMMON;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req.opcode = COMMON_OPCODE_MQ_CREATE;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req.timeout = 0;
	mb4->un.varSLIConfig.be.un_hdr.hdr_req.req_length =
	    sizeof (IOCTL_COMMON_MQ_CREATE);

	addr = hba->sli.sli4.mq.addr.phys;
	qp = (IOCTL_COMMON_MQ_CREATE *)&mb4->un.varSLIConfig.payload;

	qp->params.request.MQContext.Size = MQ_ELEMENT_COUNT_16;
	qp->params.request.MQContext.Valid = 1;
	qp->params.request.MQContext.CQId = hba->sli.sli4.mq.cqid;

	qp->params.request.NumPages = 1;
	qp->params.request.Pages[0].addrLow = PADDR_LO(addr);
	qp->params.request.Pages[0].addrHigh = PADDR_HI(addr);

	return;

} /* emlxs_mb_mq_create() */


/* SLI4 */
/*ARGSUSED*/
extern void
emlxs_mb_mq_create_ext(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX4 *mb4 = (MAILBOX4 *)mbq;
	IOCTL_COMMON_MQ_CREATE_EXT *qp;
	IOCTL_COMMON_MQ_CREATE_EXT_V1 *qp1;
	uint64_t	addr;

	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);
	mbq->nonembed = NULL;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

	/*
	 * Signifies an embedded command
	 */
	mb4->un.varSLIConfig.be.embedded = 1;

	mb4->mbxCommand = MBX_SLI_CONFIG;
	mb4->mbxOwner = OWN_HOST;

	switch (hba->sli.sli4.param.MQV) {
	case 0:
		mb4->un.varSLIConfig.be.payload_length =
		    sizeof (IOCTL_COMMON_MQ_CREATE_EXT) + IOCTL_HEADER_SZ;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.subsystem =
		    IOCTL_SUBSYSTEM_COMMON;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.opcode =
		    COMMON_OPCODE_MQ_CREATE_EXT;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.timeout = 0;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.req_length =
		    sizeof (IOCTL_COMMON_MQ_CREATE_EXT);
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.version = 0;

		addr = hba->sli.sli4.mq.addr.phys;
		qp = (IOCTL_COMMON_MQ_CREATE_EXT *)
		    &mb4->un.varSLIConfig.payload;

		qp->params.request.num_pages = 1;
		qp->params.request.async_event_bitmap =
		    ASYNC_LINK_EVENT | ASYNC_FCF_EVENT | ASYNC_GROUP5_EVENT;
		qp->params.request.context.Size = MQ_ELEMENT_COUNT_16;
		qp->params.request.context.Valid = 1;
		qp->params.request.context.CQId = hba->sli.sli4.mq.cqid;

		qp->params.request.pages[0].addrLow = PADDR_LO(addr);
		qp->params.request.pages[0].addrHigh = PADDR_HI(addr);

		break;

	case 1:
	default:
		mb4->un.varSLIConfig.be.payload_length =
		    sizeof (IOCTL_COMMON_MQ_CREATE) + IOCTL_HEADER_SZ;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.subsystem =
		    IOCTL_SUBSYSTEM_COMMON;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.opcode =
		    COMMON_OPCODE_MQ_CREATE_EXT;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.timeout = 0;
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.req_length =
		    sizeof (IOCTL_COMMON_MQ_CREATE_EXT_V1);
		mb4->un.varSLIConfig.be.un_hdr.hdr_req.version = 1;

		addr = hba->sli.sli4.mq.addr.phys;
		qp1 = (IOCTL_COMMON_MQ_CREATE_EXT_V1 *)
		    &mb4->un.varSLIConfig.payload;

		qp1->params.request.num_pages = 1;
		qp1->params.request.async_event_bitmap =
		    ASYNC_LINK_EVENT | ASYNC_FCF_EVENT | ASYNC_GROUP5_EVENT |
		    ASYNC_FC_EVENT | ASYNC_PORT_EVENT;
		qp1->params.request.context.Size = MQ_ELEMENT_COUNT_16;
		qp1->params.request.context.Valid = 1;
		qp1->params.request.CQId = hba->sli.sli4.mq.cqid;

		qp1->params.request.pages[0].addrLow = PADDR_LO(addr);
		qp1->params.request.pages[0].addrHigh = PADDR_HI(addr);

		break;
	}

	return;

} /* emlxs_mb_mq_create_ext() */


/*ARGSUSED*/
extern void
emlxs_mb_async_event(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX *mb = (MAILBOX *)mbq;

	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_ASYNC_EVENT;
	mb->mbxOwner = OWN_HOST;
	mb->un.varWords[0] = hba->channel_els;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

	return;

} /* emlxs_mb_async_event() */


/*ARGSUSED*/
extern void
emlxs_mb_heartbeat(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX *mb = (MAILBOX *)mbq;

	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_HEARTBEAT;
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = NULL; /* no cmpl needed for hbeat */
	mbq->port = (void *)&PPORT;

	return;

} /* emlxs_mb_heartbeat() */


#ifdef MSI_SUPPORT

/*ARGSUSED*/
extern void
emlxs_mb_config_msi(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t *intr_map,
    uint32_t intr_count)
{
	MAILBOX *mb = (MAILBOX *)mbq;
	uint16_t i;
	uint32_t mask;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_CONFIG_MSI;

	/* Set the default message id to zero */
	mb->un.varCfgMSI.defaultPresent = 1;
	mb->un.varCfgMSI.defaultMessageNumber = 0;

	for (i = 1; i < intr_count; i++) {
		mask = intr_map[i];

		mb->un.varCfgMSI.attConditions |= mask;

#ifdef EMLXS_BIG_ENDIAN
		if (mask & HA_R0ATT) {
			mb->un.varCfgMSI.messageNumberByHA[3] = i;
		}
		if (mask & HA_R1ATT) {
			mb->un.varCfgMSI.messageNumberByHA[7] = i;
		}
		if (mask & HA_R2ATT) {
			mb->un.varCfgMSI.messageNumberByHA[11] = i;
		}
		if (mask & HA_R3ATT) {
			mb->un.varCfgMSI.messageNumberByHA[15] = i;
		}
		if (mask & HA_LATT) {
			mb->un.varCfgMSI.messageNumberByHA[29] = i;
		}
		if (mask & HA_MBATT) {
			mb->un.varCfgMSI.messageNumberByHA[30] = i;
		}
		if (mask & HA_ERATT) {
			mb->un.varCfgMSI.messageNumberByHA[31] = i;
		}
#endif	/* EMLXS_BIG_ENDIAN */

#ifdef EMLXS_LITTLE_ENDIAN
		/* Accounts for half word swap of LE architecture */
		if (mask & HA_R0ATT) {
			mb->un.varCfgMSI.messageNumberByHA[2] = i;
		}
		if (mask & HA_R1ATT) {
			mb->un.varCfgMSI.messageNumberByHA[6] = i;
		}
		if (mask & HA_R2ATT) {
			mb->un.varCfgMSI.messageNumberByHA[10] = i;
		}
		if (mask & HA_R3ATT) {
			mb->un.varCfgMSI.messageNumberByHA[14] = i;
		}
		if (mask & HA_LATT) {
			mb->un.varCfgMSI.messageNumberByHA[28] = i;
		}
		if (mask & HA_MBATT) {
			mb->un.varCfgMSI.messageNumberByHA[31] = i;
		}
		if (mask & HA_ERATT) {
			mb->un.varCfgMSI.messageNumberByHA[30] = i;
		}
#endif	/* EMLXS_LITTLE_ENDIAN */
	}

	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

	return;

} /* emlxs_mb_config_msi() */


/*ARGSUSED*/
extern void
emlxs_mb_config_msix(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t *intr_map,
    uint32_t intr_count)
{
	MAILBOX *mb = (MAILBOX *)mbq;
	uint8_t i;
	uint32_t mask;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_CONFIG_MSIX;

	/* Set the default message id to zero */
	mb->un.varCfgMSIX.defaultPresent = 1;
	mb->un.varCfgMSIX.defaultMessageNumber = 0;

	for (i = 1; i < intr_count; i++) {
		mask = intr_map[i];

		mb->un.varCfgMSIX.attConditions1 |= mask;

#ifdef EMLXS_BIG_ENDIAN
		if (mask & HA_R0ATT) {
			mb->un.varCfgMSIX.messageNumberByHA[3] = i;
		}
		if (mask & HA_R1ATT) {
			mb->un.varCfgMSIX.messageNumberByHA[7] = i;
		}
		if (mask & HA_R2ATT) {
			mb->un.varCfgMSIX.messageNumberByHA[11] = i;
		}
		if (mask & HA_R3ATT) {
			mb->un.varCfgMSIX.messageNumberByHA[15] = i;
		}
		if (mask & HA_LATT) {
			mb->un.varCfgMSIX.messageNumberByHA[29] = i;
		}
		if (mask & HA_MBATT) {
			mb->un.varCfgMSIX.messageNumberByHA[30] = i;
		}
		if (mask & HA_ERATT) {
			mb->un.varCfgMSIX.messageNumberByHA[31] = i;
		}
#endif	/* EMLXS_BIG_ENDIAN */

#ifdef EMLXS_LITTLE_ENDIAN
		/* Accounts for word swap of LE architecture */
		if (mask & HA_R0ATT) {
			mb->un.varCfgMSIX.messageNumberByHA[0] = i;
		}
		if (mask & HA_R1ATT) {
			mb->un.varCfgMSIX.messageNumberByHA[4] = i;
		}
		if (mask & HA_R2ATT) {
			mb->un.varCfgMSIX.messageNumberByHA[8] = i;
		}
		if (mask & HA_R3ATT) {
			mb->un.varCfgMSIX.messageNumberByHA[12] = i;
		}
		if (mask & HA_LATT) {
			mb->un.varCfgMSIX.messageNumberByHA[30] = i;
		}
		if (mask & HA_MBATT) {
			mb->un.varCfgMSIX.messageNumberByHA[29] = i;
		}
		if (mask & HA_ERATT) {
			mb->un.varCfgMSIX.messageNumberByHA[28] = i;
		}
#endif	/* EMLXS_LITTLE_ENDIAN */
	}

	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

	return;

} /* emlxs_mb_config_msix() */


#endif	/* MSI_SUPPORT */


/*ARGSUSED*/
extern void
emlxs_mb_reset_ring(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t ringno)
{
	MAILBOX *mb = (MAILBOX *)mbq;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_RESET_RING;
	mb->un.varRstRing.ring_no = ringno;
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

	return;

} /* emlxs_mb_reset_ring() */


/*ARGSUSED*/
extern void
emlxs_mb_dump_vpd(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t offset)
{

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		MAILBOX4 *mb4 = (MAILBOX4 *)mbq;

		/* Clear the local dump_region */
		bzero(hba->sli.sli4.dump_region.virt,
		    hba->sli.sli4.dump_region.size);

		bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);

		mb4->mbxCommand = MBX_DUMP_MEMORY;
		mb4->un.varDmp4.type = DMP_NV_PARAMS;
		mb4->un.varDmp4.entry_index = offset;
		mb4->un.varDmp4.region_id = DMP_VPD_REGION;

		mb4->un.varDmp4.available_cnt = hba->sli.sli4.dump_region.size;
		mb4->un.varDmp4.addrHigh =
		    PADDR_HI(hba->sli.sli4.dump_region.phys);
		mb4->un.varDmp4.addrLow =
		    PADDR_LO(hba->sli.sli4.dump_region.phys);
		mb4->un.varDmp4.rsp_cnt = 0;

		mb4->mbxOwner = OWN_HOST;

	} else {
		MAILBOX *mb = (MAILBOX *)mbq;

		bzero((void *)mb, MAILBOX_CMD_BSIZE);

		mb->mbxCommand = MBX_DUMP_MEMORY;
		mb->un.varDmp.cv = 1;
		mb->un.varDmp.type = DMP_NV_PARAMS;
		mb->un.varDmp.entry_index = offset;
		mb->un.varDmp.region_id = DMP_VPD_REGION;

		/* limited by mailbox size */
		mb->un.varDmp.word_cnt = DMP_VPD_DUMP_WCOUNT;

		mb->un.varDmp.co = 0;
		mb->un.varDmp.resp_offset = 0;
		mb->mbxOwner = OWN_HOST;
	}

	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

} /* emlxs_mb_dump_vpd() */


/* SLI4 */
/*ARGSUSED*/
extern void
emlxs_mb_dump_fcoe(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t offset)
{
	MAILBOX4 *mb4 = (MAILBOX4 *)mbq;

	if (hba->sli_mode < EMLXS_HBA_SLI4_MODE) {
		return;
	}

	/* Clear the local dump_region */
	bzero(hba->sli.sli4.dump_region.virt,
	    hba->sli.sli4.dump_region.size);

	bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);

	mb4->mbxCommand = MBX_DUMP_MEMORY;
	mb4->un.varDmp4.type = DMP_NV_PARAMS;
	mb4->un.varDmp4.entry_index = offset;
	mb4->un.varDmp4.region_id = DMP_FCOE_REGION;

	mb4->un.varDmp4.available_cnt = hba->sli.sli4.dump_region.size;
	mb4->un.varDmp4.addrHigh =
	    PADDR_HI(hba->sli.sli4.dump_region.phys);
	mb4->un.varDmp4.addrLow =
	    PADDR_LO(hba->sli.sli4.dump_region.phys);
	mb4->un.varDmp4.rsp_cnt = 0;

	mb4->mbxOwner = OWN_HOST;

	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

} /* emlxs_mb_dump_fcoe() */


/*ARGSUSED*/
extern void
emlxs_mb_dump(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t offset, uint32_t words)
{

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		MAILBOX4 *mb4 = (MAILBOX4 *)mbq;

		/* Clear the local dump_region */
		bzero(hba->sli.sli4.dump_region.virt,
		    hba->sli.sli4.dump_region.size);

		bzero((void *) mb4, MAILBOX_CMD_SLI4_BSIZE);

		mb4->mbxCommand = MBX_DUMP_MEMORY;
		mb4->un.varDmp4.type = DMP_MEM_REG;
		mb4->un.varDmp4.entry_index = offset;
		mb4->un.varDmp4.region_id = 0;

		mb4->un.varDmp4.available_cnt = min((words*4),
		    hba->sli.sli4.dump_region.size);
		mb4->un.varDmp4.addrHigh =
		    PADDR_HI(hba->sli.sli4.dump_region.phys);
		mb4->un.varDmp4.addrLow =
		    PADDR_LO(hba->sli.sli4.dump_region.phys);
		mb4->un.varDmp4.rsp_cnt = 0;

		mb4->mbxOwner = OWN_HOST;

	} else {

		MAILBOX *mb = (MAILBOX *)mbq;

		bzero((void *)mb, MAILBOX_CMD_BSIZE);

		mb->mbxCommand = MBX_DUMP_MEMORY;
		mb->un.varDmp.type = DMP_MEM_REG;
		mb->un.varDmp.word_cnt = words;
		mb->un.varDmp.base_adr = offset;

		mb->un.varDmp.co = 0;
		mb->un.varDmp.resp_offset = 0;
		mb->mbxOwner = OWN_HOST;
	}

	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

	return;

} /* emlxs_mb_dump() */


/*
 *  emlxs_mb_read_nv  Issue a READ NVPARAM mailbox command
 */
/*ARGSUSED*/
extern void
emlxs_mb_read_nv(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX *mb = (MAILBOX *)mbq;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_READ_NV;
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

} /* emlxs_mb_read_nv() */


/*
 * emlxs_mb_read_rev  Issue a READ REV mailbox command
 */
/*ARGSUSED*/
extern void
emlxs_mb_read_rev(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t v3)
{
	MAILBOX *mb = (MAILBOX *)mbq;

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);
		mbq->nonembed = NULL;
	} else {
		bzero((void *)mb, MAILBOX_CMD_BSIZE);

		mb->un.varRdRev.cv = 1;

		if (v3) {
			mb->un.varRdRev.cv3 = 1;
		}
	}

	mb->mbxCommand = MBX_READ_REV;
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = NULL;
	mbq->port = (void *)&PPORT;

} /* emlxs_mb_read_rev() */


/*
 * emlxs_mb_run_biu_diag  Issue a RUN_BIU_DIAG mailbox command
 */
/*ARGSUSED*/
extern uint32_t
emlxs_mb_run_biu_diag(emlxs_hba_t *hba, MAILBOXQ *mbq, uint64_t out,
    uint64_t in)
{
	MAILBOX *mb = (MAILBOX *)mbq;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_RUN_BIU_DIAG64;
	mb->un.varBIUdiag.un.s2.xmit_bde64.tus.f.bdeSize = MEM_ELSBUF_SIZE;
	mb->un.varBIUdiag.un.s2.xmit_bde64.addrHigh = PADDR_HI(out);
	mb->un.varBIUdiag.un.s2.xmit_bde64.addrLow = PADDR_LO(out);
	mb->un.varBIUdiag.un.s2.rcv_bde64.tus.f.bdeSize = MEM_ELSBUF_SIZE;
	mb->un.varBIUdiag.un.s2.rcv_bde64.addrHigh = PADDR_HI(in);
	mb->un.varBIUdiag.un.s2.rcv_bde64.addrLow = PADDR_LO(in);
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

	return (0);
} /* emlxs_mb_run_biu_diag() */


/* This should only be called with active MBX_NOWAIT mailboxes */
void
emlxs_mb_retry(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX	*mb;
	MAILBOX	*mbox;
	int rc;

	mbox = (MAILBOX *)emlxs_mem_get(hba, MEM_MBOX);
	if (!mbox) {
		return;
	}
	mb = (MAILBOX *)mbq;
	bcopy((uint8_t *)mb, (uint8_t *)mbox, MAILBOX_CMD_BSIZE);
	mbox->mbxOwner = OWN_HOST;
	mbox->mbxStatus = 0;

	mutex_enter(&EMLXS_PORT_LOCK);

	HBASTATS.MboxCompleted++;

	if (mb->mbxStatus != 0) {
		HBASTATS.MboxError++;
	} else {
		HBASTATS.MboxGood++;
	}

	hba->mbox_mbq = NULL;
	hba->mbox_queue_flag = 0;

	mutex_exit(&EMLXS_PORT_LOCK);

	rc =  EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbox, MBX_NOWAIT, 0);
	if ((rc != MBX_BUSY) && (rc != MBX_SUCCESS)) {
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbox);
	}
	return;

} /* emlxs_mb_retry() */


/* SLI3 */
static uint32_t
emlxs_read_la_mbcmpl(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	emlxs_port_t *port = (emlxs_port_t *)mbq->port;
	MAILBOX *mb;
	MAILBOXQ *mbox;
	MATCHMAP *mp;
	READ_LA_VAR la;
	int i;
	uint32_t  control;

	mb = (MAILBOX *)mbq;
	if (mb->mbxStatus) {
		if (mb->mbxStatus == MBXERR_NO_RESOURCES) {
			control = mb->un.varReadLA.un.lilpBde64.tus.f.bdeSize;
			if (control == 0) {
				(void) emlxs_mb_read_la(hba, mbq);
			}
			emlxs_mb_retry(hba, mbq);
			return (1);
		}
		/* Enable Link Attention interrupts */
		mutex_enter(&EMLXS_PORT_LOCK);

		if (!(hba->sli.sli3.hc_copy & HC_LAINT_ENA)) {
			hba->sli.sli3.hc_copy |= HC_LAINT_ENA;
			WRITE_CSR_REG(hba, FC_HC_REG(hba),
			    hba->sli.sli3.hc_copy);
#ifdef FMA_SUPPORT
			/* Access handle validation */
			EMLXS_CHK_ACC_HANDLE(hba,
			    hba->sli.sli3.csr_acc_handle);
#endif  /* FMA_SUPPORT */
		}

		mutex_exit(&EMLXS_PORT_LOCK);
		return (0);
	}
	bcopy((void *)&mb->un.varReadLA, (void *)&la, sizeof (READ_LA_VAR));

	mp = (MATCHMAP *)mbq->bp;
	if (mp) {
		bcopy((caddr_t)mp->virt, (caddr_t)port->alpa_map, 128);
	} else {
		bzero((caddr_t)port->alpa_map, 128);
	}

	if (la.attType == AT_LINK_UP) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_linkup_atten_msg,
		    "tag=%d -> %d  ALPA=%x",
		    (uint32_t)hba->link_event_tag,
		    (uint32_t)la.eventTag,
		    (uint32_t)la.granted_AL_PA);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_linkdown_atten_msg,
		    "tag=%d -> %d  ALPA=%x",
		    (uint32_t)hba->link_event_tag,
		    (uint32_t)la.eventTag,
		    (uint32_t)la.granted_AL_PA);
	}

	if (la.pb) {
		hba->flag |= FC_BYPASSED_MODE;
	} else {
		hba->flag &= ~FC_BYPASSED_MODE;
	}

	if (hba->link_event_tag == la.eventTag) {
		HBASTATS.LinkMultiEvent++;
	} else if (hba->link_event_tag + 1 < la.eventTag) {
		HBASTATS.LinkMultiEvent++;

		/* Make sure link is declared down */
		emlxs_linkdown(hba);
	}

	hba->link_event_tag = la.eventTag;
	port->lip_type = 0;

	/* If link not already up then declare it up now */
	if ((la.attType == AT_LINK_UP) && (hba->state < FC_LINK_UP)) {

#ifdef MENLO_SUPPORT
		if ((hba->model_info.device_id == PCI_DEVICE_ID_HORNET) &&
		    (hba->flag & (FC_ILB_MODE | FC_ELB_MODE))) {
			la.topology = TOPOLOGY_LOOP;
			la.granted_AL_PA = 0;
			port->alpa_map[0] = 1;
			port->alpa_map[1] = 0;
			la.lipType = LT_PORT_INIT;
		}
#endif /* MENLO_SUPPORT */
		/* Save the linkspeed */
		hba->linkspeed = la.UlnkSpeed;

		/* Check for old model adapters that only */
		/* supported 1Gb */
		if ((hba->linkspeed == 0) &&
		    (hba->model_info.chip & EMLXS_DRAGONFLY_CHIP)) {
			hba->linkspeed = LA_1GHZ_LINK;
		}

		if ((hba->topology = la.topology) == TOPOLOGY_LOOP) {
			port->granted_alpa = la.granted_AL_PA;
			port->did = port->granted_alpa;
			port->lip_type = la.lipType;
			if (hba->flag & FC_SLIM2_MODE) {
				i = la.un.lilpBde64.tus.f.bdeSize;
			} else {
				i = la.un.lilpBde.bdeSize;
			}

			if (i == 0) {
				port->alpa_map[0] = 0;
			} else {
				uint8_t *alpa_map;
				uint32_t j;

				/* Check number of devices in map */
				if (port->alpa_map[0] > 127) {
					port->alpa_map[0] = 127;
				}

				alpa_map = (uint8_t *)port->alpa_map;

				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_link_atten_msg,
				    "alpa_map: %d device(s):      "
				    "%02x %02x %02x %02x %02x %02x "
				    "%02x", alpa_map[0], alpa_map[1],
				    alpa_map[2], alpa_map[3],
				    alpa_map[4], alpa_map[5],
				    alpa_map[6], alpa_map[7]);

				for (j = 8; j <= alpa_map[0]; j += 8) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_link_atten_msg,
					    "alpa_map:             "
					    "%02x %02x %02x %02x %02x "
					    "%02x %02x %02x",
					    alpa_map[j],
					    alpa_map[j + 1],
					    alpa_map[j + 2],
					    alpa_map[j + 3],
					    alpa_map[j + 4],
					    alpa_map[j + 5],
					    alpa_map[j + 6],
					    alpa_map[j + 7]);
				}
			}
		}
#ifdef MENLO_SUPPORT
		/* Check if Menlo maintenance mode is enabled */
		if (hba->model_info.device_id ==
		    PCI_DEVICE_ID_HORNET) {
			if (la.mm == 1) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_link_atten_msg,
				    "Maintenance Mode enabled.");

				mutex_enter(&EMLXS_PORT_LOCK);
				hba->flag |= FC_MENLO_MODE;
				mutex_exit(&EMLXS_PORT_LOCK);

				mutex_enter(&EMLXS_LINKUP_LOCK);
				cv_broadcast(&EMLXS_LINKUP_CV);
				mutex_exit(&EMLXS_LINKUP_LOCK);
			} else {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_link_atten_msg,
				    "Maintenance Mode disabled.");
			}

			/* Check FCoE attention bit */
			if (la.fa == 1) {
				emlxs_thread_spawn(hba,
				    emlxs_fcoe_attention_thread,
				    0, 0);
			}
		}
#endif /* MENLO_SUPPORT */

		if ((mbox = (MAILBOXQ *)emlxs_mem_get(hba,
		    MEM_MBOX))) {
			/* This should turn on DELAYED ABTS for */
			/* ELS timeouts */
			emlxs_mb_set_var(hba, mbox, 0x00052198, 0x1);

			emlxs_mb_put(hba, mbox);
		}

		if ((mbox = (MAILBOXQ *)emlxs_mem_get(hba,
		    MEM_MBOX))) {
			/* If link not already down then */
			/* declare it down now */
			if (emlxs_mb_read_sparam(hba, mbox) == 0) {
				emlxs_mb_put(hba, mbox);
			} else {
				emlxs_mem_put(hba, MEM_MBOX,
				    (void *)mbox);
			}
		}

		if ((mbox = (MAILBOXQ *)emlxs_mem_get(hba,
		    MEM_MBOX))) {
			emlxs_mb_config_link(hba, mbox);

			emlxs_mb_put(hba, mbox);
		}

		/* Declare the linkup here */
		emlxs_linkup(hba);
	}

	/* If link not already down then declare it down now */
	else if (la.attType == AT_LINK_DOWN) {
		/* Make sure link is declared down */
		emlxs_linkdown(hba);
	}

	/* Enable Link attention interrupt */
	mutex_enter(&EMLXS_PORT_LOCK);

	if (!(hba->sli.sli3.hc_copy & HC_LAINT_ENA)) {
		hba->sli.sli3.hc_copy |= HC_LAINT_ENA;
		WRITE_CSR_REG(hba, FC_HC_REG(hba), hba->sli.sli3.hc_copy);
#ifdef FMA_SUPPORT
		/* Access handle validation */
		EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli3.csr_acc_handle);
#endif  /* FMA_SUPPORT */
	}

	mutex_exit(&EMLXS_PORT_LOCK);

	return (0);

} /* emlxs_read_la_mbcmpl() */


extern uint32_t
emlxs_mb_read_la(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX *mb = (MAILBOX *)mbq;
	MATCHMAP *mp;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	if ((mp = (MATCHMAP *)emlxs_mem_get(hba, MEM_BUF)) == 0) {
		mb->mbxCommand = MBX_READ_LA64;

		return (1);
	}

	mb->mbxCommand = MBX_READ_LA64;
	mb->un.varReadLA.un.lilpBde64.tus.f.bdeSize = 128;
	mb->un.varReadLA.un.lilpBde64.addrHigh = PADDR_HI(mp->phys);
	mb->un.varReadLA.un.lilpBde64.addrLow = PADDR_LO(mp->phys);
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = emlxs_read_la_mbcmpl;
	mbq->port = (void *)&PPORT;

	/*
	 * save address for completion
	 */
	mbq->bp = (void *)mp;

	return (0);

} /* emlxs_mb_read_la() */


/* SLI3 */
static uint32_t
emlxs_clear_la_mbcmpl(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	emlxs_port_t *port = (emlxs_port_t *)mbq->port;
	MAILBOX *mb;
	MAILBOXQ *mbox;
	emlxs_port_t *vport;
	uint32_t la_enable;
	int i, rc;

	mb = (MAILBOX *)mbq;
	if (mb->mbxStatus) {
		la_enable = 1;

		if (mb->mbxStatus == 0x1601) {
			/* Get a buffer which will be used for */
			/* mailbox commands */
			if ((mbox = (MAILBOXQ *)emlxs_mem_get(hba,
			    MEM_MBOX))) {
				/* Get link attention message */
				if (emlxs_mb_read_la(hba, mbox) == 0) {
					rc =  EMLXS_SLI_ISSUE_MBOX_CMD(hba,
					    (MAILBOX *)mbox, MBX_NOWAIT, 0);
					if ((rc != MBX_BUSY) &&
					    (rc != MBX_SUCCESS)) {
						emlxs_mem_put(hba,
						    MEM_MBOX, (void *)mbox);
					}
					la_enable = 0;
				} else {
					emlxs_mem_put(hba, MEM_MBOX,
					    (void *)mbox);
				}
			}
		}

		mutex_enter(&EMLXS_PORT_LOCK);
		if (la_enable) {
			if (!(hba->sli.sli3.hc_copy & HC_LAINT_ENA)) {
				/* Enable Link Attention interrupts */
				hba->sli.sli3.hc_copy |= HC_LAINT_ENA;
				WRITE_CSR_REG(hba, FC_HC_REG(hba),
				    hba->sli.sli3.hc_copy);
#ifdef FMA_SUPPORT
				/* Access handle validation */
				EMLXS_CHK_ACC_HANDLE(hba,
				    hba->sli.sli3.csr_acc_handle);
#endif  /* FMA_SUPPORT */
			}
		} else {
			if (hba->sli.sli3.hc_copy & HC_LAINT_ENA) {
				/* Disable Link Attention interrupts */
				hba->sli.sli3.hc_copy &= ~HC_LAINT_ENA;
				WRITE_CSR_REG(hba, FC_HC_REG(hba),
				    hba->sli.sli3.hc_copy);
#ifdef FMA_SUPPORT
				/* Access handle validation */
				EMLXS_CHK_ACC_HANDLE(hba,
				    hba->sli.sli3.csr_acc_handle);
#endif  /* FMA_SUPPORT */
			}
		}
		mutex_exit(&EMLXS_PORT_LOCK);

		return (0);
	}
	/* Enable on Link Attention interrupts */
	mutex_enter(&EMLXS_PORT_LOCK);

	if (!(hba->sli.sli3.hc_copy & HC_LAINT_ENA)) {
		hba->sli.sli3.hc_copy |= HC_LAINT_ENA;
		WRITE_CSR_REG(hba, FC_HC_REG(hba), hba->sli.sli3.hc_copy);
#ifdef FMA_SUPPORT
		/* Access handle validation */
		EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli3.csr_acc_handle);
#endif  /* FMA_SUPPORT */
	}

	if (hba->state >= FC_LINK_UP) {
		EMLXS_STATE_CHANGE_LOCKED(hba, FC_READY);
	}

	mutex_exit(&EMLXS_PORT_LOCK);

	/* Adapter is now ready for FCP traffic */
	if (hba->state == FC_READY) {

		/* Register vpi's for all ports that have did's */
		for (i = 0; i < MAX_VPORTS; i++) {
			vport = &VPORT(i);

			if (!(vport->flag & EMLXS_PORT_BOUND) ||
			    !(vport->did)) {
				continue;
			}

			(void) emlxs_mb_reg_vpi(vport, NULL);
		}

		/* Attempt to send any pending IO */
		EMLXS_SLI_ISSUE_IOCB_CMD(hba, &hba->chan[hba->channel_fcp], 0);
	}
	return (0);

} /* emlxs_clear_la_mbcmpl() */


/* SLI3 */
extern void
emlxs_mb_clear_la(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX *mb = (MAILBOX *)mbq;

#ifdef FC_RPI_CHECK
	emlxs_rpi_check(hba);
#endif	/* FC_RPI_CHECK */

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->un.varClearLA.eventTag = hba->link_event_tag;
	mb->mbxCommand = MBX_CLEAR_LA;
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = emlxs_clear_la_mbcmpl;
	mbq->port = (void *)&PPORT;

	return;

} /* emlxs_mb_clear_la() */


/*
 * emlxs_mb_read_status  Issue a READ STATUS mailbox command
 */
/*ARGSUSED*/
extern void
emlxs_mb_read_status(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX *mb = (MAILBOX *)mbq;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_READ_STATUS;
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

} /* fc_read_status() */


/*
 * emlxs_mb_read_lnk_stat  Issue a LINK STATUS mailbox command
 */
/*ARGSUSED*/
extern void
emlxs_mb_read_lnk_stat(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX *mb = (MAILBOX *)mbq;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_READ_LNK_STAT;
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

} /* emlxs_mb_read_lnk_stat() */






/*
 * emlxs_mb_config_ring  Issue a CONFIG RING mailbox command
 */
extern void
emlxs_mb_config_ring(emlxs_hba_t *hba, int32_t ring, MAILBOXQ *mbq)
{
	MAILBOX *mb = (MAILBOX *)mbq;
	int32_t i;
	int32_t j;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	j = 0;
	for (i = 0; i < ring; i++) {
		j += hba->sli.sli3.ring_masks[i];
	}

	for (i = 0; i < hba->sli.sli3.ring_masks[ring]; i++) {
		if ((j + i) >= 6) {
			break;
		}

		mb->un.varCfgRing.rrRegs[i].rval  =
		    hba->sli.sli3.ring_rval[j + i];
		mb->un.varCfgRing.rrRegs[i].rmask =
		    hba->sli.sli3.ring_rmask[j + i];
		mb->un.varCfgRing.rrRegs[i].tval  =
		    hba->sli.sli3.ring_tval[j + i];
		mb->un.varCfgRing.rrRegs[i].tmask =
		    hba->sli.sli3.ring_tmask[j + i];
	}

	mb->un.varCfgRing.ring = ring;
	mb->un.varCfgRing.profile = 0;
	mb->un.varCfgRing.maxOrigXchg = 0;
	mb->un.varCfgRing.maxRespXchg = 0;
	mb->un.varCfgRing.recvNotify = 1;
	mb->un.varCfgRing.numMask = hba->sli.sli3.ring_masks[ring];
	mb->mbxCommand = MBX_CONFIG_RING;
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

	return;

} /* emlxs_mb_config_ring() */


/*
 *  emlxs_mb_config_link  Issue a CONFIG LINK mailbox command
 */
extern void
emlxs_mb_config_link(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX	*mb = (MAILBOX *)mbq;
	emlxs_port_t   *port = &PPORT;
	emlxs_config_t *cfg = &CFG;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	/*
	 * NEW_FEATURE SLI-2, Coalescing Response Feature.
	 */
	if (cfg[CFG_CR_DELAY].current) {
		mb->un.varCfgLnk.cr = 1;
		mb->un.varCfgLnk.ci = 1;
		mb->un.varCfgLnk.cr_delay = cfg[CFG_CR_DELAY].current;
		mb->un.varCfgLnk.cr_count = cfg[CFG_CR_COUNT].current;
	}

	if (cfg[CFG_ACK0].current) {
		mb->un.varCfgLnk.ack0_enable = 1;
	}

	mb->un.varCfgLnk.myId = port->did;
	mb->un.varCfgLnk.edtov = hba->fc_edtov;
	mb->un.varCfgLnk.arbtov = hba->fc_arbtov;
	mb->un.varCfgLnk.ratov = hba->fc_ratov;
	mb->un.varCfgLnk.rttov = hba->fc_rttov;
	mb->un.varCfgLnk.altov = hba->fc_altov;
	mb->un.varCfgLnk.crtov = hba->fc_crtov;
	mb->un.varCfgLnk.citov = hba->fc_citov;
	mb->mbxCommand = MBX_CONFIG_LINK;
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = NULL;
	mbq->port = (void *)port;

	return;

} /* emlxs_mb_config_link() */


static uint32_t
emlxs_init_link_mbcmpl(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	emlxs_port_t *port = (emlxs_port_t *)mbq->port;
	emlxs_config_t	*cfg = &CFG;
	MAILBOX *mb;

	mb = (MAILBOX *)mbq;
	if (mb->mbxStatus) {
		if ((hba->flag & FC_SLIM2_MODE) &&
		    (hba->mbox_queue_flag == MBX_NOWAIT)) {
			/* Retry only MBX_NOWAIT requests */

			if ((cfg[CFG_LINK_SPEED].current > 0) &&
			    ((mb->mbxStatus == 0x0011) ||
			    (mb->mbxStatus == 0x0500))) {

				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_mbox_event_msg,
				    "Retrying.  %s: status=%x. Auto-speed set.",
				    emlxs_mb_cmd_xlate(mb->mbxCommand),
				    (uint32_t)mb->mbxStatus);

				mb->un.varInitLnk.link_flags &=
				    ~FLAGS_LINK_SPEED;
				mb->un.varInitLnk.link_speed = 0;

				emlxs_mb_retry(hba, mbq);
				return (1);
			}
		}
	}
	return (0);

} /* emlxs_init_link_mbcmpl() */


/*
 *  emlxs_mb_init_link  Issue an INIT LINK mailbox command
 */
extern void
emlxs_mb_init_link(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t topology,
    uint32_t linkspeed)
{
	MAILBOX *mb = (MAILBOX *)mbq;
	emlxs_vpd_t	*vpd = &VPD;
	emlxs_config_t	*cfg = &CFG;

	if ((hba->sli_mode == EMLXS_HBA_SLI4_MODE) &&
	    (SLI4_FCOE_MODE)) {
		bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);
		mbq->nonembed = NULL;
		mbq->mbox_cmpl = NULL; /* no cmpl needed */
		mbq->port = (void *)&PPORT;

		mb->mbxCommand = (volatile uint8_t) MBX_INIT_LINK;
		mb->mbxOwner = OWN_HOST;
		return;
	}

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	switch (topology) {
	case FLAGS_LOCAL_LB:
		mb->un.varInitLnk.link_flags = FLAGS_TOPOLOGY_MODE_LOOP;
		mb->un.varInitLnk.link_flags |= FLAGS_LOCAL_LB;
		break;
	case FLAGS_TOPOLOGY_MODE_LOOP_PT:
		mb->un.varInitLnk.link_flags = FLAGS_TOPOLOGY_MODE_LOOP;
		mb->un.varInitLnk.link_flags |= FLAGS_TOPOLOGY_FAILOVER;
		break;
	case FLAGS_TOPOLOGY_MODE_PT_PT:
		mb->un.varInitLnk.link_flags = FLAGS_TOPOLOGY_MODE_PT_PT;
		break;
	case FLAGS_TOPOLOGY_MODE_LOOP:
		mb->un.varInitLnk.link_flags = FLAGS_TOPOLOGY_MODE_LOOP;
		break;
	case FLAGS_TOPOLOGY_MODE_PT_LOOP:
		mb->un.varInitLnk.link_flags = FLAGS_TOPOLOGY_MODE_PT_PT;
		mb->un.varInitLnk.link_flags |= FLAGS_TOPOLOGY_FAILOVER;
		break;
	}

	if (cfg[CFG_LILP_ENABLE].current == 0) {
		/* Disable LIRP/LILP support */
		mb->un.varInitLnk.link_flags |= FLAGS_LIRP_LILP;
	}

	/*
	 * Setting up the link speed
	 */
	switch (linkspeed) {
	case 0:
		break;

	case 1:
		if (!(vpd->link_speed & LMT_1GB_CAPABLE)) {
			linkspeed = 0;
		}
		break;

	case 2:
		if (!(vpd->link_speed & LMT_2GB_CAPABLE)) {
			linkspeed = 0;
		}
		break;

	case 4:
		if (!(vpd->link_speed & LMT_4GB_CAPABLE)) {
			linkspeed = 0;
		}
		break;

	case 8:
		if (!(vpd->link_speed & LMT_8GB_CAPABLE)) {
			linkspeed = 0;
		}
		break;

	case 10:
		if (!(vpd->link_speed & LMT_10GB_CAPABLE)) {
			linkspeed = 0;
		}
		break;

	case 16:
		if (!(vpd->link_speed & LMT_16GB_CAPABLE)) {
			linkspeed = 0;
		}
		break;

	default:
		linkspeed = 0;
		break;

	}

	if ((linkspeed > 0) && (vpd->feaLevelHigh >= 0x02)) {
		mb->un.varInitLnk.link_flags |= FLAGS_LINK_SPEED;
		mb->un.varInitLnk.link_speed = linkspeed;
	}

	mb->un.varInitLnk.link_flags |= FLAGS_PREABORT_RETURN;

	mb->un.varInitLnk.fabric_AL_PA =
	    (uint8_t)cfg[CFG_ASSIGN_ALPA].current;
	mb->mbxCommand = (volatile uint8_t) MBX_INIT_LINK;
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = emlxs_init_link_mbcmpl;
	mbq->port = (void *)&PPORT;


	return;

} /* emlxs_mb_init_link() */


/*
 *  emlxs_mb_down_link  Issue a DOWN LINK mailbox command
 */
/*ARGSUSED*/
extern void
emlxs_mb_down_link(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX *mb = (MAILBOX *)mbq;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_DOWN_LINK;
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = NULL;
	mbq->port = (void *)&PPORT;

	return;

} /* emlxs_mb_down_link() */


static uint32_t
emlxs_read_sparam_mbcmpl(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	emlxs_port_t *port = &PPORT;
	MAILBOX *mb;
	MATCHMAP *mp;
	emlxs_port_t *vport;
	int32_t i;
	uint32_t  control;
	uint8_t null_wwn[8];

	mb = (MAILBOX *)mbq;
	if (mb->mbxStatus) {
		if (mb->mbxStatus == MBXERR_NO_RESOURCES) {
			control = mb->un.varRdSparm.un.sp64.tus.f.bdeSize;
			if (control == 0) {
				(void) emlxs_mb_read_sparam(hba, mbq);
			}
			emlxs_mb_retry(hba, mbq);
			return (1);
		}
		return (0);
	}
	mp = (MATCHMAP *)mbq->bp;
	if (!mp) {
		return (0);
	}

	bcopy((caddr_t)mp->virt, (caddr_t)&hba->sparam, sizeof (SERV_PARM));

	/* Initialize the node name and port name only once */
	bzero(null_wwn, 8);
	if ((bcmp((caddr_t)&hba->wwnn, (caddr_t)null_wwn, 8) == 0) &&
	    (bcmp((caddr_t)&hba->wwpn, (caddr_t)null_wwn, 8) == 0)) {
		bcopy((caddr_t)&hba->sparam.nodeName,
		    (caddr_t)&hba->wwnn, sizeof (NAME_TYPE));

		bcopy((caddr_t)&hba->sparam.portName,
		    (caddr_t)&hba->wwpn, sizeof (NAME_TYPE));
	} else {
		bcopy((caddr_t)&hba->wwnn,
		    (caddr_t)&hba->sparam.nodeName, sizeof (NAME_TYPE));

		bcopy((caddr_t)&hba->wwpn,
		    (caddr_t)&hba->sparam.portName, sizeof (NAME_TYPE));
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "SPARAM: EDTOV hba=%x mbox_csp=%x BBC=%x",
	    hba->fc_edtov, hba->sparam.cmn.e_d_tov,
	    hba->sparam.cmn.bbCreditlsb);

	/* Initialize the physical port */
	bcopy((caddr_t)&hba->sparam, (caddr_t)&port->sparam,
	    sizeof (SERV_PARM));
	bcopy((caddr_t)&hba->wwpn, (caddr_t)&port->wwpn,
	    sizeof (NAME_TYPE));
	bcopy((caddr_t)&hba->wwnn, (caddr_t)&port->wwnn,
	    sizeof (NAME_TYPE));

	/* Initialize the virtual ports */
	for (i = 1; i < MAX_VPORTS; i++) {
		vport = &VPORT(i);
		if (! (vport->flag & EMLXS_PORT_BOUND)) {
			continue;
		}

		bcopy((caddr_t)&hba->sparam,
		    (caddr_t)&vport->sparam,
		    sizeof (SERV_PARM));

		bcopy((caddr_t)&vport->wwnn,
		    (caddr_t)&vport->sparam.nodeName,
		    sizeof (NAME_TYPE));

		bcopy((caddr_t)&vport->wwpn,
		    (caddr_t)&vport->sparam.portName,
		    sizeof (NAME_TYPE));
	}

	return (0);

} /* emlxs_read_sparam_mbcmpl() */


/*
 * emlxs_mb_read_sparam  Issue a READ SPARAM mailbox command
 */
extern uint32_t
emlxs_mb_read_sparam(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX *mb = (MAILBOX *)mbq;
	MATCHMAP *mp;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	if ((mp = (MATCHMAP *)emlxs_mem_get(hba, MEM_BUF)) == 0) {
		mb->mbxCommand = MBX_READ_SPARM64;

		return (1);
	}

	mb->un.varRdSparm.un.sp64.tus.f.bdeSize = sizeof (SERV_PARM);
	mb->un.varRdSparm.un.sp64.addrHigh = PADDR_HI(mp->phys);
	mb->un.varRdSparm.un.sp64.addrLow = PADDR_LO(mp->phys);
	mb->mbxCommand = MBX_READ_SPARM64;
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = emlxs_read_sparam_mbcmpl;
	mbq->port = (void *)&PPORT;

	/*
	 * save address for completion
	 */
	mbq->bp = (void *)mp;

	return (0);

} /* emlxs_mb_read_sparam() */


/*
 * emlxs_mb_read_rpi    Issue a READ RPI mailbox command
 */
/*ARGSUSED*/
extern uint32_t
emlxs_mb_read_rpi(emlxs_hba_t *hba, uint32_t rpi, MAILBOXQ *mbq,
    uint32_t flag)
{
	MAILBOX *mb = (MAILBOX *)mbq;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	/*
	 * Set flag to issue action on cmpl
	 */
	mb->un.varWords[30] = flag;
	mb->un.varRdRPI.reqRpi = (volatile uint16_t) rpi;
	mb->mbxCommand = MBX_READ_RPI64;
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

	return (0);
} /* emlxs_mb_read_rpi() */


/*
 * emlxs_mb_read_xri    Issue a READ XRI mailbox command
 */
/*ARGSUSED*/
extern uint32_t
emlxs_mb_read_xri(emlxs_hba_t *hba, uint32_t xri, MAILBOXQ *mbq,
    uint32_t flag)
{
	MAILBOX *mb = (MAILBOX *)mbq;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	/*
	 * Set flag to issue action on cmpl
	 */
	mb->un.varWords[30] = flag;
	mb->un.varRdXRI.reqXri = (volatile uint16_t)xri;
	mb->mbxCommand = MBX_READ_XRI;
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

	return (0);
} /* emlxs_mb_read_xri() */


/*ARGSUSED*/
extern int32_t
emlxs_mb_check_sparm(emlxs_hba_t *hba, SERV_PARM *nsp)
{
	uint32_t nsp_value;
	uint32_t *iptr;

	if (nsp->cmn.fPort) {
		return (0);
	}

	/* Validate the service parameters */
	iptr = (uint32_t *)&nsp->portName;
	if (iptr[0] == 0 && iptr[1] == 0) {
		return (1);
	}

	iptr = (uint32_t *)&nsp->nodeName;
	if (iptr[0] == 0 && iptr[1] == 0) {
		return (2);
	}

	if (nsp->cls2.classValid) {
		nsp_value =
		    ((nsp->cls2.rcvDataSizeMsb & 0x0f) << 8) | nsp->cls2.
		    rcvDataSizeLsb;

		/* If the receive data length is zero then set it to */
		/* the CSP value */
		if (!nsp_value) {
			nsp->cls2.rcvDataSizeMsb = nsp->cmn.bbRcvSizeMsb;
			nsp->cls2.rcvDataSizeLsb = nsp->cmn.bbRcvSizeLsb;
			return (0);
		}
	}

	if (nsp->cls3.classValid) {
		nsp_value =
		    ((nsp->cls3.rcvDataSizeMsb & 0x0f) << 8) | nsp->cls3.
		    rcvDataSizeLsb;

		/* If the receive data length is zero then set it to */
		/* the CSP value */
		if (!nsp_value) {
			nsp->cls3.rcvDataSizeMsb = nsp->cmn.bbRcvSizeMsb;
			nsp->cls3.rcvDataSizeLsb = nsp->cmn.bbRcvSizeLsb;
			return (0);
		}
	}

	return (0);

} /* emlxs_mb_check_sparm() */




/*
 * emlxs_mb_set_var   Issue a special debug mbox command to write slim
 */
/*ARGSUSED*/
extern void
emlxs_mb_set_var(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t addr,
    uint32_t value)
{
	MAILBOX *mb = (MAILBOX *)mbq;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	/* addr = 0x090597 is AUTO ABTS disable for ELS commands */
	/* addr = 0x052198 is DELAYED ABTS enable for ELS commands */
	/* addr = 0x100506 is for setting PCI MAX READ value */

	/*
	 * Always turn on DELAYED ABTS for ELS timeouts
	 */
	if ((addr == 0x052198) && (value == 0)) {
		value = 1;
	}

	mb->un.varWords[0] = addr;
	mb->un.varWords[1] = value;
	mb->mbxCommand = MBX_SET_VARIABLE;
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

} /* emlxs_mb_set_var() */


/*
 * Disable Traffic Cop
 */
/*ARGSUSED*/
extern void
emlxs_disable_tc(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX *mb = (MAILBOX *)mbq;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->un.varWords[0] = 0x50797;
	mb->un.varWords[1] = 0;
	mb->un.varWords[2] = 0xfffffffe;
	mb->mbxCommand = MBX_SET_VARIABLE;
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

} /* emlxs_disable_tc() */


extern void
emlxs_mb_config_hbq(emlxs_hba_t *hba, MAILBOXQ *mbq, int hbq_id)
{
	HBQ_INIT_t	*hbq;
	MAILBOX		*mb = (MAILBOX *)mbq;
	int		i;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	hbq = &hba->sli.sli3.hbq_table[hbq_id];

	mb->un.varCfgHbq.hbqId = hbq_id;
	mb->un.varCfgHbq.numEntries = hbq->HBQ_numEntries;
	mb->un.varCfgHbq.recvNotify = hbq->HBQ_recvNotify;
	mb->un.varCfgHbq.numMask = hbq->HBQ_num_mask;
	mb->un.varCfgHbq.profile = hbq->HBQ_profile;
	mb->un.varCfgHbq.ringMask = hbq->HBQ_ringMask;
	mb->un.varCfgHbq.headerLen = hbq->HBQ_headerLen;
	mb->un.varCfgHbq.logEntry = hbq->HBQ_logEntry;
	mb->un.varCfgHbq.hbqaddrLow = PADDR_LO(hbq->HBQ_host_buf.phys);
	mb->un.varCfgHbq.hbqaddrHigh = PADDR_HI(hbq->HBQ_host_buf.phys);
	mb->mbxCommand = MBX_CONFIG_HBQ;
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = NULL;
	mbq->port = (void *)&PPORT;

	/* Copy info for profiles 2,3,5. Other profiles this area is reserved */
	if ((hbq->HBQ_profile == 2) || (hbq->HBQ_profile == 3) ||
	    (hbq->HBQ_profile == 5)) {
		bcopy(&hbq->profiles.allprofiles,
		    &mb->un.varCfgHbq.profiles.allprofiles,
		    sizeof (hbq->profiles));
	}

	/* Return if no rctl / type masks for this HBQ */
	if (!hbq->HBQ_num_mask) {
		return;
	}

	/* Otherwise we setup specific rctl / type masks for this HBQ */
	for (i = 0; i < hbq->HBQ_num_mask; i++) {
		mb->un.varCfgHbq.hbqMasks[i].tmatch =
		    hbq->HBQ_Masks[i].tmatch;
		mb->un.varCfgHbq.hbqMasks[i].tmask = hbq->HBQ_Masks[i].tmask;
		mb->un.varCfgHbq.hbqMasks[i].rctlmatch =
		    hbq->HBQ_Masks[i].rctlmatch;
		mb->un.varCfgHbq.hbqMasks[i].rctlmask =
		    hbq->HBQ_Masks[i].rctlmask;
	}

	return;

} /* emlxs_mb_config_hbq() */


/* SLI3 */
static uint32_t
emlxs_reg_vpi_mbcmpl(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	emlxs_port_t *port = (emlxs_port_t *)mbq->port;
	MAILBOX *mb;

	mb = (MAILBOX *)mbq;

	mutex_enter(&EMLXS_PORT_LOCK);

	if (mb->mbxStatus != MBX_SUCCESS) {
		port->flag &= ~EMLXS_PORT_REG_VPI;
		mutex_exit(&EMLXS_PORT_LOCK);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "cmpl_reg_vpi:%d failed. status=%x",
		    port->vpi, mb->mbxStatus);
		return (0);
	}

	port->flag |= EMLXS_PORT_REG_VPI_CMPL;

	mutex_exit(&EMLXS_PORT_LOCK);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "cmpl_reg_vpi:%d ",
	    port->vpi);

	return (0);

} /* emlxs_reg_vpi_mbcmpl */


/* SLI3 */
extern uint32_t
emlxs_mb_reg_vpi(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	MAILBOXQ *mbq;
	MAILBOX	*mb;
	int rval;

	if (hba->sli_mode > EMLXS_HBA_SLI3_MODE) {
		return (1);
	}

	if (!(hba->flag & FC_NPIV_ENABLED)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "reg_vpi:%d failed. NPIV disabled.",
		    port->vpi);
		return (1);
	}

	if (port->flag & EMLXS_PORT_REG_VPI) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "reg_vpi:%d failed. Already registered.",
		    port->vpi);
		return (0);
	}

	mutex_enter(&EMLXS_PORT_LOCK);

	/* Can't reg vpi until ClearLA is sent */
	if (hba->state != FC_READY) {
		mutex_exit(&EMLXS_PORT_LOCK);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "reg_vpi:%d failed. HBA state not READY",
		    port->vpi);
		return (1);
	}

	/* Must have port id */
	if (!port->did) {
		mutex_exit(&EMLXS_PORT_LOCK);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "reg_vpi:%d failed. Port did=0",
		    port->vpi);
		return (1);
	}

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX))) {
		mutex_exit(&EMLXS_PORT_LOCK);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "reg_vpi:%d failed. Unable to allocate mbox.",
		    port->vpi);
		return (1);
	}

	port->flag |= EMLXS_PORT_REG_VPI;

	mutex_exit(&EMLXS_PORT_LOCK);

	mb = (MAILBOX *)mbq->mbox;
	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "reg_vpi:%d", port->vpi);

	mb->un.varRegVpi.vpi = port->vpi;
	mb->un.varRegVpi.sid = port->did;
	mb->mbxCommand = MBX_REG_VPI;
	mb->mbxOwner = OWN_HOST;

	mbq->sbp = (void *)sbp;
	mbq->mbox_cmpl = emlxs_reg_vpi_mbcmpl;
	mbq->context = NULL;
	mbq->port = (void *)port;

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "reg_vpi:%d failed. Unable to send request.",
		    port->vpi);

		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);
		return (1);
	}

	return (0);

} /* emlxs_mb_reg_vpi() */


/* SLI3 */
static uint32_t
emlxs_unreg_vpi_mbcmpl(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	emlxs_port_t *port = (emlxs_port_t *)mbq->port;
	MAILBOX *mb;

	mb  = (MAILBOX *)mbq->mbox;

	if (mb->mbxStatus != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "unreg_vpi_mbcmpl:%d failed. status=%x",
		    port->vpi, mb->mbxStatus);
		return (0);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "unreg_vpi_mbcmpl:%d", port->vpi);

	mutex_enter(&EMLXS_PORT_LOCK);
	port->flag &= ~EMLXS_PORT_REG_VPI_CMPL;
	mutex_exit(&EMLXS_PORT_LOCK);

	return (0);

} /* emlxs_unreg_vpi_mbcmpl() */


/* SLI3 */
extern uint32_t
emlxs_mb_unreg_vpi(emlxs_port_t *port)
{
	emlxs_hba_t	*hba = HBA;
	MAILBOXQ	*mbq;
	MAILBOX		*mb;
	int		rval;

	if (hba->sli_mode > EMLXS_HBA_SLI3_MODE) {
		return (1);
	}

	mutex_enter(&EMLXS_PORT_LOCK);

	if (!(port->flag & EMLXS_PORT_REG_VPI) ||
	    !(port->flag & EMLXS_PORT_REG_VPI_CMPL)) {

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "unreg_vpi:%d failed. Not registered. flag=%x",
		    port->vpi, port->flag);

		mutex_exit(&EMLXS_PORT_LOCK);
		return (0);
	}

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "unreg_vpi:%d failed. Unable to allocate mbox.",
		    port->vpi);

		mutex_exit(&EMLXS_PORT_LOCK);
		return (1);
	}

	port->flag &= ~EMLXS_PORT_REG_VPI;

	mutex_exit(&EMLXS_PORT_LOCK);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "unreg_vpi:%d", port->vpi);

	mb = (MAILBOX *)mbq->mbox;
	bzero((void *)mb, MAILBOX_CMD_BSIZE);
	mb->un.varUnregVpi.vpi = port->vpi;
	mb->mbxCommand = MBX_UNREG_VPI;
	mb->mbxOwner = OWN_HOST;

	mbq->mbox_cmpl = emlxs_unreg_vpi_mbcmpl;
	mbq->context = NULL;
	mbq->port = (void *)port;

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "unreg_vpi:%d failed. Unable to send request.",
		    port->vpi);

		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);
		return (1);
	}

	return (0);

} /* emlxs_mb_unreg_vpi() */


/*
 * emlxs_mb_config_farp  Issue a CONFIG FARP mailbox command
 */
extern void
emlxs_mb_config_farp(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX *mb = (MAILBOX *)mbq;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	bcopy((uint8_t *)&hba->wwpn,
	    (uint8_t *)&mb->un.varCfgFarp.portname, sizeof (NAME_TYPE));

	bcopy((uint8_t *)&hba->wwpn,
	    (uint8_t *)&mb->un.varCfgFarp.nodename, sizeof (NAME_TYPE));

	mb->un.varCfgFarp.filterEnable = 1;
	mb->un.varCfgFarp.portName = 1;
	mb->un.varCfgFarp.nodeName = 1;
	mb->mbxCommand = MBX_CONFIG_FARP;
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

} /* emlxs_mb_config_farp() */


/*
 * emlxs_mb_read_nv  Issue a READ CONFIG mailbox command
 */
/*ARGSUSED*/
extern void
emlxs_mb_read_config(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX *mb = (MAILBOX *)mbq;

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);
		mbq->nonembed = NULL;
	} else {
		bzero((void *)mb, MAILBOX_CMD_BSIZE);
	}

	mb->mbxCommand = MBX_READ_CONFIG;
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->port = (void *)&PPORT;

} /* emlxs_mb_read_config() */


/*
 * NAME:     emlxs_mb_put
 *
 * FUNCTION: put mailbox cmd onto the mailbox queue.
 *
 * EXECUTION ENVIRONMENT: process and interrupt level.
 *
 * NOTES:
 *
 * CALLED FROM: EMLXS_SLI_ISSUE_MBOX_CMD
 *
 * INPUT: hba           - pointer to the device info area
 *      mbp             - pointer to mailbox queue entry of mailbox cmd
 *
 * RETURNS: NULL - command queued
 */
extern void
emlxs_mb_put(emlxs_hba_t *hba, MAILBOXQ *mbq)
{

	mutex_enter(&EMLXS_MBOX_LOCK);

	if (hba->mbox_queue.q_first) {

		/*
		 * queue command to end of list
		 */
		((MAILBOXQ *)hba->mbox_queue.q_last)->next = mbq;
		hba->mbox_queue.q_last = (uint8_t *)mbq;
		hba->mbox_queue.q_cnt++;
	} else {

		/*
		 * add command to empty list
		 */
		hba->mbox_queue.q_first = (uint8_t *)mbq;
		hba->mbox_queue.q_last = (uint8_t *)mbq;
		hba->mbox_queue.q_cnt = 1;
	}

	mbq->next = NULL;

	mutex_exit(&EMLXS_MBOX_LOCK);
} /* emlxs_mb_put() */


/*
 * NAME:     emlxs_mb_get
 *
 * FUNCTION: get a mailbox command from mailbox command queue
 *
 * EXECUTION ENVIRONMENT: interrupt level.
 *
 * NOTES:
 *
 * CALLED FROM: emlxs_handle_mb_event
 *
 * INPUT: hba       - pointer to the device info area
 *
 * RETURNS: NULL - no match found mb pointer - pointer to a mailbox command
 */
extern MAILBOXQ *
emlxs_mb_get(emlxs_hba_t *hba)
{
	MAILBOXQ	*p_first = NULL;

	mutex_enter(&EMLXS_MBOX_LOCK);

	if (hba->mbox_queue.q_first) {
		p_first = (MAILBOXQ *)hba->mbox_queue.q_first;
		hba->mbox_queue.q_first = (uint8_t *)p_first->next;

		if (hba->mbox_queue.q_first == NULL) {
			hba->mbox_queue.q_last = NULL;
			hba->mbox_queue.q_cnt = 0;
		} else {
			hba->mbox_queue.q_cnt--;
		}

		p_first->next = NULL;
	}

	mutex_exit(&EMLXS_MBOX_LOCK);

	return (p_first);

} /* emlxs_mb_get() */


/* EMLXS_PORT_LOCK must be held when calling this */
void
emlxs_mb_init(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t flag, uint32_t tmo)
{
	MATCHMAP	*mp;

	HBASTATS.MboxIssued++;
	hba->mbox_queue_flag = flag;

	/* Set the Mailbox timer */
	if (hba->timer_tics) {
		hba->mbox_timer = hba->timer_tics + tmo;
	} else {
		hba->mbox_timer = DRV_TIME + tmo;
	}

	/* Initialize mailbox */
	mbq->flag &= MBQ_INIT_MASK;
	mbq->next = 0;

	mutex_enter(&EMLXS_MBOX_LOCK);
	hba->mbox_mbq = (void *)mbq;
	mutex_exit(&EMLXS_MBOX_LOCK);

	if (mbq->nonembed) {
		mp = (MATCHMAP *) mbq->nonembed;
		EMLXS_MPDATA_SYNC(mp->dma_handle, 0, mp->size,
		    DDI_DMA_SYNC_FORDEV);
	}

	if (mbq->bp) {
		mp = (MATCHMAP *) mbq->bp;
		EMLXS_MPDATA_SYNC(mp->dma_handle, 0, mp->size,
		    DDI_DMA_SYNC_FORDEV);
	}
	return;

} /* emlxs_mb_init() */


extern void
emlxs_mb_fini(emlxs_hba_t *hba, MAILBOX *mb, uint32_t mbxStatus)
{
	emlxs_port_t	*port = &PPORT;
	MATCHMAP	*mbox_nonembed;
	MATCHMAP	*mbox_bp;
	emlxs_buf_t	*mbox_sbp;
	fc_unsol_buf_t	*mbox_ubp;
	IOCBQ		*mbox_iocbq;
	MAILBOXQ	*mbox_mbq;
	MAILBOX		*mbox;
	uint32_t	mbox_queue_flag;

	mutex_enter(&EMLXS_PORT_LOCK);

	if (hba->mbox_queue_flag) {
		HBASTATS.MboxCompleted++;

		if (mbxStatus != MBX_SUCCESS) {
			HBASTATS.MboxError++;
		} else {
			HBASTATS.MboxGood++;
		}
	}

	mutex_enter(&EMLXS_MBOX_LOCK);
	mbox_queue_flag = hba->mbox_queue_flag;
	mbox_mbq = (MAILBOXQ *)hba->mbox_mbq;

	if (mbox_mbq) {
		mbox_nonembed = (MATCHMAP *)mbox_mbq->nonembed;
		mbox_bp = (MATCHMAP *)mbox_mbq->bp;
		mbox_sbp = (emlxs_buf_t *)mbox_mbq->sbp;
		mbox_ubp = (fc_unsol_buf_t *)mbox_mbq->ubp;
		mbox_iocbq = (IOCBQ *)mbox_mbq->iocbq;
	} else {
		mbox_nonembed = NULL;
		mbox_bp = NULL;
		mbox_sbp = NULL;
		mbox_ubp = NULL;
		mbox_iocbq = NULL;
	}

	hba->mbox_mbq = NULL;
	hba->mbox_queue_flag = 0;
	hba->mbox_timer = 0;
	mutex_exit(&EMLXS_MBOX_LOCK);

	mutex_exit(&EMLXS_PORT_LOCK);

#ifdef SFCT_SUPPORT
	if (mb && mbox_sbp && mbox_sbp->fct_cmd) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "FCT mailbox: %s: status=%x",
		    emlxs_mb_cmd_xlate(mb->mbxCommand),
		    mb->mbxStatus);
	}
#endif /* SFCT_SUPPORT */

	if (mbox_queue_flag == MBX_NOWAIT) {
		/* Check for deferred MBUF cleanup */
		if (mbox_bp) {
			emlxs_mem_put(hba, MEM_BUF, (void *)mbox_bp);
		}
		if (mbox_nonembed) {
			emlxs_mem_put(hba, MEM_BUF,
			    (void *)mbox_nonembed);
		}
		if (mbox_mbq) {
			emlxs_mem_put(hba, MEM_MBOX,
			    (void *)mbox_mbq);
		}
	} else {  /* MBX_WAIT */
		if (mbox_mbq) {
			if (mb) {
				/* Copy the local mailbox provided back into */
				/* the original mailbox */
				if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
					bcopy((uint32_t *)mb,
					    (uint32_t *)mbox_mbq,
					    MAILBOX_CMD_SLI4_BSIZE);
				} else {
					bcopy((uint32_t *)mb,
					    (uint32_t *)mbox_mbq,
					    MAILBOX_CMD_BSIZE);
				}
			}

			mbox = (MAILBOX *)mbox_mbq;
			mbox->mbxStatus = (uint16_t)mbxStatus;

			/* Mark mailbox complete */
			mbox_mbq->flag |= MBQ_COMPLETED;
		}

		/* Wake up the sleeping thread */
		if (mbox_queue_flag == MBX_SLEEP) {
			mutex_enter(&EMLXS_MBOX_LOCK);
			cv_broadcast(&EMLXS_MBOX_CV);
			mutex_exit(&EMLXS_MBOX_LOCK);
		}
	}

	emlxs_mb_deferred_cmpl(port, mbxStatus, mbox_sbp, mbox_ubp, mbox_iocbq);

	return;

} /* emlxs_mb_fini() */


extern void
emlxs_mb_deferred_cmpl(emlxs_port_t *port, uint32_t mbxStatus, emlxs_buf_t *sbp,
    fc_unsol_buf_t *ubp, IOCBQ *iocbq)
{
	emlxs_hba_t *hba = HBA;
	emlxs_ub_priv_t	*ub_priv;

#ifdef SFCT_SUPPORT
	if (sbp && sbp->fct_cmd && (sbp->fct_state == EMLXS_FCT_REG_PENDING)) {
		mutex_enter(&EMLXS_PKT_LOCK);
		sbp->fct_flags |= EMLXS_FCT_REGISTERED;
		cv_broadcast(&EMLXS_PKT_CV);
		mutex_exit(&EMLXS_PKT_LOCK);

		sbp = NULL;
	}
#endif /* SFCT_SUPPORT */

	/* Check for deferred pkt completion */
	if (sbp) {
		if (mbxStatus != MBX_SUCCESS) {
			/* Set error status */
			sbp->pkt_flags &= ~PACKET_STATE_VALID;
			emlxs_set_pkt_state(sbp, IOSTAT_LOCAL_REJECT,
			    IOERR_NO_RESOURCES, 1);
		}

		emlxs_pkt_complete(sbp, -1, 0, 1);
	}

	/* Check for deferred ub completion */
	if (ubp) {
		ub_priv = ubp->ub_fca_private;

		if (mbxStatus == MBX_SUCCESS) {
			emlxs_ub_callback(ub_priv->port, ubp);
		} else {
			(void) emlxs_fca_ub_release(ub_priv->port, 1,
			    &ubp->ub_token);
		}
	}

	/* Special handling for restricted login */
	if (iocbq == (IOCBQ *)1) {
		iocbq = NULL;
	}

	/* Check for deferred iocb tx */
	if (iocbq) {
		/* Check for driver special codes */
		/* These indicate the mailbox is being flushed */
		if (mbxStatus >= MBX_DRIVER_RESERVED) {
			/* Set the error status and return it */
			iocbq->iocb.ULPSTATUS = IOSTAT_LOCAL_REJECT;
			iocbq->iocb.un.grsp.perr.statLocalError =
			    IOERR_ABORT_REQUESTED;

			emlxs_proc_channel_event(hba, iocbq->channel,
			    iocbq);
		} else {
			EMLXS_SLI_ISSUE_IOCB_CMD(hba, iocbq->channel,
			    iocbq);
		}
	}

	return;

} /* emlxs_mb_deferred_cmpl() */


extern void
emlxs_mb_flush(emlxs_hba_t *hba)
{
	MAILBOXQ	*mbq;
	uint32_t	mbxStatus;

	mbxStatus = (hba->flag & FC_HARDWARE_ERROR) ?
	    MBX_HARDWARE_ERROR : MBX_NOT_FINISHED;

	/* Flush out the active mbox command */
	emlxs_mb_fini(hba, NULL, mbxStatus);

	/* Flush out the queued mbox commands */
	while (mbq = (MAILBOXQ *)emlxs_mb_get(hba)) {
		mutex_enter(&EMLXS_MBOX_LOCK);
		hba->mbox_queue_flag = MBX_NOWAIT;
		hba->mbox_mbq = (void *)mbq;
		mutex_exit(&EMLXS_MBOX_LOCK);

		emlxs_mb_fini(hba, NULL, mbxStatus);
	}

	return;

} /* emlxs_mb_flush */


extern char *
emlxs_mb_cmd_xlate(uint8_t cmd)
{
	static char	buffer[32];
	uint32_t	i;
	uint32_t	count;

	count = sizeof (emlxs_mb_cmd_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (cmd == emlxs_mb_cmd_table[i].code) {
			return (emlxs_mb_cmd_table[i].string);
		}
	}

	(void) snprintf(buffer, sizeof (buffer), "Cmd=0x%x", cmd);
	return (buffer);

} /* emlxs_mb_cmd_xlate() */

extern char *
emlxs_request_feature_xlate(uint32_t mask)
{
	static char	buffer[64];
	uint32_t	i;

	bzero((char *)&buffer[0], 64);
	for (i = 0; i < 12; i++) {
		if (mask & (1<<i)) {
			(void) strlcat(buffer,
			    emlxs_request_feature_table[i].string,
			    sizeof (buffer));
		}
	}
	return (buffer);
}
