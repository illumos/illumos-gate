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
 * Copyright 2009 Emulex.  All rights reserved.
 * Use is subject to license terms.
 */


#include <emlxs.h>

/* Required for EMLXS_CONTEXT in EMLXS_MSGF calls */
EMLXS_MSG_DEF(EMLXS_MBOX_C);

static void	emlxs_mb_part_slim(emlxs_hba_t *hba, MAILBOXQ *mbq,
			uint32_t hbainit);
static void	emlxs_mb_set_mask(emlxs_hba_t *hba, MAILBOXQ *mbq,
			uint32_t mask, uint32_t ringno);
static void	emlxs_mb_set_debug(emlxs_hba_t *hba, MAILBOXQ *mbq,
			uint32_t word0, uint32_t word1, uint32_t word2);
static void	emlxs_mb_write_nv(emlxs_hba_t *hba, MAILBOXQ *mbq);


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
	{MBX_UNREG_LOGIN, "UNREG_LOGIN"},
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
	{MBX_REG_LOGIN64, "REG_LOGIN64"},
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
	{MBX_INIT_VPI, "INIT_VPI"}
};	/* emlxs_mb_cmd_table */


/*
 * emlxs_mb_resetport  Issue a Port Reset mailbox command
 */
/*ARGSUSED*/
extern void
emlxs_mb_resetport(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX4 *mb = (MAILBOX4 *)mbq;

	bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);
	mbq->nonembed = NULL;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */

	/*
	 * Signifies an embedded command
	 */
	mb->un.varSLIConfig.be.embedded = 1;

	mb->mbxCommand = MBX_SLI_CONFIG;
	mb->mbxOwner = OWN_HOST;
	mb->un.varSLIConfig.be.payload_length = IOCTL_HEADER_SZ;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.subsystem =
	    IOCTL_SUBSYSTEM_COMMON;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.opcode = COMMON_OPCODE_RESET;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.timeout = 0;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.req_length = 0;

	return;

} /* emlxs_mb_resetport() */


/*
 * emlxs_mb_request_features  Issue a REQUEST FEATURES mailbox command
 */
/*ARGSUSED*/
extern void
emlxs_mb_request_features(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	emlxs_config_t	*cfg = &CFG;
	MAILBOX4 *mb = (MAILBOX4 *)mbq;

	hba->flag &= ~FC_NPIV_ENABLED;

	bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);
	mbq->nonembed = NULL;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */

	mb->mbxCommand = MBX_REQUEST_FEATURES;
	mb->mbxOwner = OWN_HOST;
	mb->un.varReqFeatures.featuresRequested |=
	    SLI4_FEATURE_FCP_INITIATOR;

	if (cfg[CFG_NPIV_ENABLE].current) {
		mb->un.varReqFeatures.featuresRequested |=
		    SLI4_FEATURE_NPIV;
	}

} /* emlxs_mb_request_features() */


/*
 * emlxs_mb_resume_rpi  Issue a RESUME_RPI mailbox command
 */
/*ARGSUSED*/
extern int
emlxs_mb_resume_rpi(emlxs_hba_t *hba, emlxs_buf_t *sbp, uint16_t rpi)
{
	MAILBOX4 *mb;
	MAILBOXQ *mbq;
	uint32_t rval;

	(void) emlxs_sli4_find_rpi(hba, rpi);

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX, 1))) {
		return (1);
	}
	mb = (MAILBOX4 *)mbq;

	bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);
	mbq->nonembed = NULL;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */
	mbq->sbp = (uint8_t *)sbp;

	mb->mbxCommand = MBX_RESUME_RPI;
	mb->mbxOwner = OWN_HOST;
	mb->un.varResumeRPI.EventTag = hba->link_event_tag;
	mb->un.varResumeRPI.RPI = rpi;

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbq);
	}
	return (rval);

} /* emlxs_mb_resume_rpi() */


/*ARGSUSED*/
extern void
emlxs_mb_noop(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX4 *mb = (MAILBOX4 *)mbq;
	IOCTL_COMMON_NOP *nop;

	bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);
	mbq->nonembed = NULL;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */

	/*
	 * Signifies an embedded command
	 */
	mb->un.varSLIConfig.be.embedded = 1;

	mb->mbxCommand = MBX_SLI_CONFIG;
	mb->mbxOwner = OWN_HOST;
	mb->un.varSLIConfig.be.payload_length = sizeof (IOCTL_COMMON_NOP) +
	    IOCTL_HEADER_SZ;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.subsystem =
	    IOCTL_SUBSYSTEM_COMMON;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.opcode = COMMON_OPCODE_NOP;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.timeout = 0;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.req_length =
	    sizeof (IOCTL_COMMON_NOP);
	nop = (IOCTL_COMMON_NOP *)&mb->un.varSLIConfig.payload;
	nop->params.request.context = -1;

	return;

} /* emlxs_mb_noop() */


/*ARGSUSED*/
extern int
emlxs_mbext_noop(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX4 *mb = (MAILBOX4 *)mbq;
	IOCTL_COMMON_NOP *nop;
	MATCHMAP *mp;
	mbox_req_hdr_t	*hdr_req;

	bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);

	if ((mp = (MATCHMAP *)emlxs_mem_get(hba, MEM_BUF, 1)) == 0) {
		return (1);
	}
	/*
	 * Save address for completion
	 * Signifies a non-embedded command
	 */
	mb->un.varSLIConfig.be.embedded = 0;
	mbq->nonembed = (uint8_t *)mp;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */

	mb->mbxCommand = MBX_SLI_CONFIG;
	mb->mbxOwner = OWN_HOST;

	hdr_req = (mbox_req_hdr_t *)mp->virt;
	hdr_req->subsystem = IOCTL_SUBSYSTEM_COMMON;
	hdr_req->opcode = COMMON_OPCODE_NOP;
	hdr_req->timeout = 0;
	hdr_req->req_length = sizeof (IOCTL_COMMON_NOP);
	nop = (IOCTL_COMMON_NOP *)(hdr_req + 1);
	nop->params.request.context = -1;

	return (0);

} /* emlxs_mbext_noop() */


int
emlxs_cmpl_read_fcf_table(void *arg1, MAILBOXQ *mbq)
{
	emlxs_hba_t *hba = (emlxs_hba_t *)arg1;
	emlxs_port_t *port = &PPORT;
	mbox_rsp_hdr_t	*hdr_rsp;
	IOCTL_FCOE_READ_FCF_TABLE *fcf;
	FCF_RECORD_t *fcfrec;
	FCFIobj_t *fcfp;
	MAILBOX4 *mb;
	MATCHMAP *mp;
	MAILBOXQ *fcfmbq;
	uint32_t i, *iptr;
	uint16_t s, *sptr;
	int rc;

	mb = (MAILBOX4 *)mbq;
	mp = (MATCHMAP *)mbq->nonembed;
	hdr_rsp = (mbox_rsp_hdr_t *)mp->virt;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "CMPL read fcf: stats: %x %x %x",
	    mb->mbxStatus, hdr_rsp->status, hdr_rsp->extra_status);

	if (mb->mbxStatus || hdr_rsp->status) {
		/* Wait for FCF found async event */
		return (0);
	}

	/*
	 * Only support 1 FCF for now, so we don't need to walk
	 * thru the FCF table.
	 */
	fcf = (IOCTL_FCOE_READ_FCF_TABLE *)(hdr_rsp + 1);
	fcfrec = &fcf->params.response.fcf_entry[0];

	/* Fix up data in FCF record */
	BE_SWAP32_BUFFER(&fcfrec->fabric_name_identifier[0], 8);
	BE_SWAP32_BUFFER(&fcfrec->switch_name_identifier[0], 8);
	BE_SWAP32_BUFFER(&fcfrec->vlan_bitmap[0], 512);
	iptr = (uint32_t *)&fcfrec->fcf_mac_address_hi[0];
	i = *iptr;
	*iptr = BE_SWAP32(i);
	sptr = (uint16_t *)&fcfrec->fcf_mac_address_low[0];
	s = *sptr;
	*sptr = BE_SWAP16(s);
#ifdef EMLXS_BIG_ENDIAN
	i = fcfrec->fc_map[0];
	fcfrec->fc_map[0] = fcfrec->fc_map[2];
	fcfrec->fc_map[2] = i;
#endif

	/* Assign a FCFI object for the fcf_index */
	fcfp = emlxs_sli4_assign_fcfi(hba, fcfrec);
	if (!fcfp) {
		return (0);
	}
	fcfp->EventTag = fcf->params.response.event_tag;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "CMPL read fcf: info: x%x x%x",
	    fcfp->EventTag, fcf->params.response.next_valid_fcf_index);

	if (emlxs_sli4_bind_fcfi(hba)) {
		/*
		 * In this phase, if we successfully bind to just
		 * 1 FCFI we are done.
		 */
		return (0);
	}

	if (fcf->params.response.next_valid_fcf_index == 0xffff) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "Waiting for a valid FCF to be discovered");
		return (0);
	}

	/* Get the next one */
	if (!(fcfmbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX, 1))) {
		return (0);
	}
	rc =  emlxs_mbext_read_fcf_table(hba, fcfmbq,
	    fcf->params.response.next_valid_fcf_index);
	if (rc == 0) {
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)fcfmbq);
		return (0);
	}

	rc =  EMLXS_SLI_ISSUE_MBOX_CMD(hba, fcfmbq, MBX_NOWAIT, 0);
	if ((rc != MBX_BUSY) && (rc != MBX_SUCCESS)) {
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)fcfmbq);
	}
	return (0);
} /* emlxs_cmpl_read_fcf_table() */


extern int
emlxs_mbext_read_fcf_table(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t index)
{
	MAILBOX4 *mb = (MAILBOX4 *)mbq;
	IOCTL_FCOE_READ_FCF_TABLE *fcf;
	MATCHMAP *mp;
	mbox_req_hdr_t	*hdr_req;

	bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);

	if ((mp = (MATCHMAP *)emlxs_mem_get(hba, MEM_BUF, 1)) == 0) {
		return (0);
	}
	/*
	 * Save address for completion
	 * Signifies a non-embedded command
	 */
	mb->un.varSLIConfig.be.embedded = 0;
	mbq->nonembed = (uint8_t *)mp;
	mbq->mbox_cmpl = emlxs_cmpl_read_fcf_table;

	mb->mbxCommand = MBX_SLI_CONFIG;
	mb->mbxOwner = OWN_HOST;

	hdr_req = (mbox_req_hdr_t *)mp->virt;
	hdr_req->subsystem = IOCTL_SUBSYSTEM_FCOE;
	hdr_req->opcode = FCOE_OPCODE_READ_FCF_TABLE;
	hdr_req->timeout = 0;
	hdr_req->req_length = sizeof (IOCTL_FCOE_READ_FCF_TABLE);
	fcf = (IOCTL_FCOE_READ_FCF_TABLE *)(hdr_req + 1);
	fcf->params.request.fcf_index = index;

	return (1);

} /* emlxs_mbext_read_fcf_table() */


int
emlxs_cmpl_add_fcf_table(void *arg1, MAILBOXQ *mbq)
{
	emlxs_hba_t *hba = (emlxs_hba_t *)arg1;
	emlxs_port_t *port = &PPORT;
	MAILBOX4 *mb;
	MAILBOXQ *mq;
	MATCHMAP *mp;
	mbox_rsp_hdr_t *hdr_rsp;
	uint32_t rc;

	mb = (MAILBOX4 *)mbq;
	mp = (MATCHMAP *)mbq->nonembed;

	hdr_rsp = (mbox_rsp_hdr_t *)mp->virt;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "CMPL add fcf: stats: %x %x %x",
	    mb->mbxStatus, hdr_rsp->status, hdr_rsp->extra_status);

	if (mbq->nonembed) {
		(void) emlxs_mem_put(hba, MEM_BUF, (uint8_t *)mbq->nonembed);
		mbq->nonembed = 0;
	}

	if (mb->mbxStatus) {
		/* In nonFIP mode, FCF Entries are persistent */
		if (!hdr_rsp->status ||
		    (hdr_rsp->status != MGMT_STATUS_FCF_IN_USE)) {
			return (0);
		}
	}

	/*
	 * Now that we have a fcf table entry, read it back
	 * to fall into the normal link up processing.
	 */
	if (!(mq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX, 1))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "CMPL add fcf: Cannot alloc mbox");
		return (0);
	}
	rc =  emlxs_mbext_read_fcf_table(hba, mq, -1);

	if (rc == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "CMPL add fcf: Cannot build read fcf mbox");
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mq);
		return (0);
	}

	rc =  EMLXS_SLI_ISSUE_MBOX_CMD(hba, mq, MBX_NOWAIT, 0);
	if ((rc != MBX_BUSY) && (rc != MBX_SUCCESS)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "CMPL add fcf: Cannot issue read fcf mbox");
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mq);
	}
	return (0);
} /* emlxs_cmpl_add_fcf_table() */


extern int
emlxs_mbext_add_fcf_table(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t index)
{
	emlxs_port_t *port = &PPORT;
	MAILBOX4 *mb = (MAILBOX4 *)mbq;
	IOCTL_FCOE_ADD_FCF_TABLE *fcf;
	FCF_RECORD_t *fcfrec;
	MATCHMAP *mp;
	mbox_req_hdr_t	*hdr_req;

	bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);

	if ((mp = (MATCHMAP *)emlxs_mem_get(hba, MEM_BUF, 1)) == 0) {
		return (0);
	}
	/*
	 * Save address for completion
	 * Signifies a non-embedded command
	 */
	mb->un.varSLIConfig.be.embedded = 0;
	mbq->nonembed = (uint8_t *)mp;
	mbq->mbox_cmpl = emlxs_cmpl_add_fcf_table;

	mb->mbxCommand = MBX_SLI_CONFIG;
	mb->mbxOwner = OWN_HOST;

	hdr_req = (mbox_req_hdr_t *)mp->virt;
	hdr_req->subsystem = IOCTL_SUBSYSTEM_FCOE;
	hdr_req->opcode = FCOE_OPCODE_ADD_FCF_TABLE;
	hdr_req->timeout = 0;
	hdr_req->req_length = sizeof (IOCTL_FCOE_ADD_FCF_TABLE);
	fcf = (IOCTL_FCOE_ADD_FCF_TABLE *)(hdr_req + 1);
	fcf->params.request.fcf_index = index;

	fcfrec = &fcf->params.request.fcf_entry;
	fcfrec->max_recv_size = EMLXS_FCOE_MAX_RCV_SZ;
	fcfrec->fka_adv_period = 0;
	fcfrec->fip_priority = 128;
#ifdef EMLXS_BIG_ENDIAN
	fcfrec->fcf_mac_address_hi[0] = FCOE_FCF_MAC3;
	fcfrec->fcf_mac_address_hi[1] = FCOE_FCF_MAC2;
	fcfrec->fcf_mac_address_hi[2] = FCOE_FCF_MAC1;
	fcfrec->fcf_mac_address_hi[3] = FCOE_FCF_MAC0;
	fcfrec->fcf_mac_address_low[0] = FCOE_FCF_MAC5;
	fcfrec->fcf_mac_address_low[1] = FCOE_FCF_MAC4;
	fcfrec->fc_map[0] = hba->sli.sli4.cfgFCOE.FCMap[2];
	fcfrec->fc_map[1] = hba->sli.sli4.cfgFCOE.FCMap[1];
	fcfrec->fc_map[2] = hba->sli.sli4.cfgFCOE.FCMap[0];
#endif
#ifdef EMLXS_LITTLE_ENDIAN
	fcfrec->fcf_mac_address_hi[0] = FCOE_FCF_MAC0;
	fcfrec->fcf_mac_address_hi[1] = FCOE_FCF_MAC1;
	fcfrec->fcf_mac_address_hi[2] = FCOE_FCF_MAC2;
	fcfrec->fcf_mac_address_hi[3] = FCOE_FCF_MAC3;
	fcfrec->fcf_mac_address_low[0] = FCOE_FCF_MAC4;
	fcfrec->fcf_mac_address_low[1] = FCOE_FCF_MAC5;
	fcfrec->fc_map[0] = hba->sli.sli4.cfgFCOE.FCMap[0];
	fcfrec->fc_map[1] = hba->sli.sli4.cfgFCOE.FCMap[1];
	fcfrec->fc_map[2] = hba->sli.sli4.cfgFCOE.FCMap[2];
#endif

	if (hba->sli.sli4.cfgFCOE.fip_flags & TLV_FCOE_VLAN) {
		uint16_t i;
		uint8_t bitmap[512];

		bzero((void *) bitmap, 512);
		i = hba->sli.sli4.cfgFCOE.VLanId;
		bitmap[i / 8] = (1 << (i % 8));
		BE_SWAP32_BCOPY(bitmap, fcfrec->vlan_bitmap, 512);
	}

	fcfrec->fcf_valid = 1;
	fcfrec->fcf_available = 1;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "ADD FCF %d: av: %x %x ste %x macp %x "
	    "addr: %02x:%02x:%02x:%02x:%02x:%02x",
	    fcfrec->fcf_index,
	    fcfrec->fcf_available,
	    fcfrec->fcf_valid,
	    fcfrec->fcf_state,
	    fcfrec->mac_address_provider,
	    fcfrec->fcf_mac_address_hi[0],
	    fcfrec->fcf_mac_address_hi[1],
	    fcfrec->fcf_mac_address_hi[2],
	    fcfrec->fcf_mac_address_hi[3],
	    fcfrec->fcf_mac_address_low[0],
	    fcfrec->fcf_mac_address_low[1]);
	return (1);

} /* emlxs_mbext_add_fcf_table() */


/*ARGSUSED*/
extern void
emlxs_mb_eq_create(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t num)
{
	MAILBOX4 *mb = (MAILBOX4 *)mbq;
	IOCTL_COMMON_EQ_CREATE *qp;
	uint64_t	addr;

	bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);
	mbq->nonembed = NULL;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */

	/*
	 * Signifies an embedded command
	 */
	mb->un.varSLIConfig.be.embedded = 1;

	mb->mbxCommand = MBX_SLI_CONFIG;
	mb->mbxOwner = OWN_HOST;
	mb->un.varSLIConfig.be.payload_length =
	    sizeof (IOCTL_COMMON_EQ_CREATE) + IOCTL_HEADER_SZ;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.subsystem =
	    IOCTL_SUBSYSTEM_COMMON;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.opcode = COMMON_OPCODE_EQ_CREATE;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.timeout = 0;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.req_length =
	    sizeof (IOCTL_COMMON_EQ_CREATE);
	qp = (IOCTL_COMMON_EQ_CREATE *)&mb->un.varSLIConfig.payload;

	/* 1024 * 4 bytes = 4K */
	qp->params.request.EQContext.Count = EQ_ELEMENT_COUNT_1024;
	qp->params.request.EQContext.Valid = 1;
	qp->params.request.EQContext.NoDelay = 0;
	qp->params.request.EQContext.DelayMult = EQ_DELAY_MULT;

	addr = hba->sli.sli4.eq[num].addr.phys;
	qp->params.request.NumPages = 1;
	qp->params.request.Pages[0].addrLow = PADDR_LO(addr);
	qp->params.request.Pages[0].addrHigh = PADDR_HI(addr);

	return;

} /* emlxs_mb_eq_create() */


/*ARGSUSED*/
extern void
emlxs_mb_cq_create(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t num)
{
	MAILBOX4 *mb = (MAILBOX4 *)mbq;
	IOCTL_COMMON_CQ_CREATE *qp;
	uint64_t	addr;

	bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);
	mbq->nonembed = NULL;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */

	/*
	 * Signifies an embedded command
	 */
	mb->un.varSLIConfig.be.embedded = 1;

	mb->mbxCommand = MBX_SLI_CONFIG;
	mb->mbxOwner = OWN_HOST;
	mb->un.varSLIConfig.be.payload_length =
	    sizeof (IOCTL_COMMON_CQ_CREATE) + IOCTL_HEADER_SZ;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.subsystem =
	    IOCTL_SUBSYSTEM_COMMON;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.opcode = COMMON_OPCODE_CQ_CREATE;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.timeout = 0;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.req_length =
	    sizeof (IOCTL_COMMON_CQ_CREATE);
	qp = (IOCTL_COMMON_CQ_CREATE *)&mb->un.varSLIConfig.payload;

	/* 256 * 16 bytes = 4K */
	qp->params.request.CQContext.Count = CQ_ELEMENT_COUNT_256;
	qp->params.request.CQContext.EQId = hba->sli.sli4.cq[num].eqid;
	qp->params.request.CQContext.Valid = 1;
	qp->params.request.CQContext.Eventable = 1;
	qp->params.request.CQContext.NoDelay = 0;

	addr = hba->sli.sli4.cq[num].addr.phys;
	qp->params.request.NumPages = 1;
	qp->params.request.Pages[0].addrLow = PADDR_LO(addr);
	qp->params.request.Pages[0].addrHigh = PADDR_HI(addr);

	return;

} /* emlxs_mb_cq_create() */


/*ARGSUSED*/
extern void
emlxs_mb_wq_create(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t num)
{
	MAILBOX4 *mb = (MAILBOX4 *)mbq;
	IOCTL_FCOE_WQ_CREATE *qp;
	uint64_t addr;
	int i;

	bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);
	mbq->nonembed = NULL;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */

	/*
	 * Signifies an embedded command
	 */
	mb->un.varSLIConfig.be.embedded = 1;

	mb->mbxCommand = MBX_SLI_CONFIG;
	mb->mbxOwner = OWN_HOST;
	mb->un.varSLIConfig.be.payload_length =
	    sizeof (IOCTL_FCOE_WQ_CREATE) + IOCTL_HEADER_SZ;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.subsystem =
	    IOCTL_SUBSYSTEM_FCOE;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.opcode = FCOE_OPCODE_WQ_CREATE;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.timeout = 0;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.req_length =
	    sizeof (IOCTL_FCOE_WQ_CREATE);

	addr = hba->sli.sli4.wq[num].addr.phys;
	qp = (IOCTL_FCOE_WQ_CREATE *)&mb->un.varSLIConfig.payload;

	qp->params.request.CQId = hba->sli.sli4.wq[num].cqid;

	qp->params.request.NumPages = EMLXS_NUM_WQ_PAGES;
	for (i = 0; i < EMLXS_NUM_WQ_PAGES; i++) {
		qp->params.request.Pages[i].addrLow = PADDR_LO(addr);
		qp->params.request.Pages[i].addrHigh = PADDR_HI(addr);
		addr += 4096;
	}

	return;

} /* emlxs_mb_wq_create() */


/*ARGSUSED*/
extern void
emlxs_mb_rq_create(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t num)
{
	MAILBOX4 *mb = (MAILBOX4 *)mbq;
	IOCTL_FCOE_RQ_CREATE *qp;
	uint64_t	addr;

	bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);
	mbq->nonembed = NULL;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */

	/*
	 * Signifies an embedded command
	 */
	mb->un.varSLIConfig.be.embedded = 1;

	mb->mbxCommand = MBX_SLI_CONFIG;
	mb->mbxOwner = OWN_HOST;
	mb->un.varSLIConfig.be.payload_length =
	    sizeof (IOCTL_FCOE_RQ_CREATE) + IOCTL_HEADER_SZ;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.subsystem =
	    IOCTL_SUBSYSTEM_FCOE;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.opcode = FCOE_OPCODE_RQ_CREATE;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.timeout = 0;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.req_length =
	    sizeof (IOCTL_FCOE_RQ_CREATE);
	addr = hba->sli.sli4.rq[num].addr.phys;

	qp = (IOCTL_FCOE_RQ_CREATE *)&mb->un.varSLIConfig.payload;

	qp->params.request.RQContext.RQSize	= RQ_DEPTH_EXPONENT;
	qp->params.request.RQContext.BufferSize	= RQB_DATA_SIZE;
	qp->params.request.RQContext.CQIdRecv	= hba->sli.sli4.rq[num].cqid;

	qp->params.request.NumPages = 1;
	qp->params.request.Pages[0].addrLow = PADDR_LO(addr);
	qp->params.request.Pages[0].addrHigh = PADDR_HI(addr);

	return;

} /* emlxs_mb_rq_create() */


/*ARGSUSED*/
extern void
emlxs_mb_mq_create(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX4 *mb = (MAILBOX4 *)mbq;
	IOCTL_COMMON_MQ_CREATE *qp;
	uint64_t	addr;

	bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);
	mbq->nonembed = NULL;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */

	/*
	 * Signifies an embedded command
	 */
	mb->un.varSLIConfig.be.embedded = 1;

	mb->mbxCommand = MBX_SLI_CONFIG;
	mb->mbxOwner = OWN_HOST;
	mb->un.varSLIConfig.be.payload_length =
	    sizeof (IOCTL_COMMON_MQ_CREATE) + IOCTL_HEADER_SZ;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.subsystem =
	    IOCTL_SUBSYSTEM_COMMON;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.opcode = COMMON_OPCODE_MQ_CREATE;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.timeout = 0;
	mb->un.varSLIConfig.be.un_hdr.hdr_req.req_length =
	    sizeof (IOCTL_COMMON_MQ_CREATE);

	addr = hba->sli.sli4.mq.addr.phys;
	qp = (IOCTL_COMMON_MQ_CREATE *)&mb->un.varSLIConfig.payload;

	qp->params.request.MQContext.Size = MQ_ELEMENT_COUNT_16;
	qp->params.request.MQContext.Valid = 1;
	qp->params.request.MQContext.CQId = hba->sli.sli4.mq.cqid;

	qp->params.request.NumPages = 1;
	qp->params.request.Pages[0].addrLow = PADDR_LO(addr);
	qp->params.request.Pages[0].addrHigh = PADDR_HI(addr);

	return;

} /* emlxs_mb_mq_create() */


static int
emlxs_cmpl_reg_fcfi(void *arg1, MAILBOXQ *mbq)
{
	emlxs_hba_t *hba = (emlxs_hba_t *)arg1;
	emlxs_port_t *port = &PPORT;
	FCFIobj_t *fcfp;
	VFIobj_t *vfip;
	RPIobj_t *rpip;
	MAILBOX4 *mb;

	mb = (MAILBOX4 *)mbq;
	fcfp = (FCFIobj_t *)mbq->context;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "CMPL reg fcfi: status: %x", mb->mbxStatus);

	if (mb->mbxStatus) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to register FCFI for FCFI %d index %d",
		    mb->un.varRegFCFI.FCFI, mb->un.varRegFCFI.InfoIndex);
		(void) emlxs_sli4_free_fcfi(hba, fcfp);
		return (0);
	}

	fcfp->state |= RESOURCE_FCFI_REG;

	if (!fcfp->fcf_vfi) {
		vfip = emlxs_sli4_alloc_vfi(hba, fcfp);
		if (!vfip) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
			    "Unable to alloc VFI for Fabric, fcf index %d",
			    fcfp->FCF_index);
			(void) emlxs_sli4_free_fcfi(hba, fcfp);
			return (0);
		}
		fcfp->fcf_vfi = vfip;
	}

	if (!fcfp->fcf_vpi) {
		fcfp->fcf_vpi = port;
		port->VFIp = fcfp->fcf_vfi;
		port->VFIp->outstandingVPIs++;
	}

	rpip = &fcfp->scratch_rpi;
	rpip->state = RESOURCE_ALLOCATED;
	rpip->VPIp = fcfp->fcf_vpi;
	rpip->RPI = 0xffff;
	rpip->index = 0xffff;

	fcfp->FCFI = mb->un.varRegFCFI.FCFI;

	/* Declare the linkup here */
	if (!(fcfp->state & RESOURCE_FCFI_DISC)) {
		fcfp->state |= RESOURCE_FCFI_DISC;
		emlxs_linkup(hba);
	}
	return (0);

} /* emlxs_cmpl_reg_fcfi() */


/*ARGSUSED*/
extern void
emlxs_mb_reg_fcfi(emlxs_hba_t *hba, MAILBOXQ *mbq, FCFIobj_t *fcfp)
{
	MAILBOX4 *mb = (MAILBOX4 *)mbq;

	bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);

	mb->mbxCommand = MBX_REG_FCFI;
	mb->mbxOwner = OWN_HOST;
	mb->un.varRegFCFI.FCFI = 0; /* FCFI will be returned by firmware */
	mb->un.varRegFCFI.InfoIndex = fcfp->FCF_index;

	mb->un.varRegFCFI.RQId0 = hba->sli.sli4.rq[EMLXS_FCFI_RQ0_INDEX].qid;
	mb->un.varRegFCFI.Id0_rctl_mask = EMLXS_FCFI_RQ0_RMASK;
	mb->un.varRegFCFI.Id0_rctl = EMLXS_FCFI_RQ0_RCTL;
	mb->un.varRegFCFI.Id0_type_mask = EMLXS_FCFI_RQ0_TMASK;
	mb->un.varRegFCFI.Id0_type = EMLXS_FCFI_RQ0_TYPE;

	mb->un.varRegFCFI.RQId1 = 0xffff;
	mb->un.varRegFCFI.RQId2 = 0xffff;
	mb->un.varRegFCFI.RQId3 = 0xffff;

	if (fcfp->state & RESOURCE_FCFI_VLAN_ID) {
		mb->un.varRegFCFI.vv = 1;
		mb->un.varRegFCFI.vlanTag = fcfp->vlan_id;
	}

	/* Ignore the fcf record and force FPMA */
	mb->un.varRegFCFI.mam = EMLXS_REG_FCFI_MAM_FPMA;

	mbq->mbox_cmpl = emlxs_cmpl_reg_fcfi;
	mbq->context = (uint8_t *)fcfp;
	return;

} /* emlxs_mb_reg_fcfi() */


/* SLI4 */
static int
emlxs_cmpl_unreg_fcfi(void *arg1, MAILBOXQ *mbq)
{
	emlxs_hba_t *hba = (emlxs_hba_t *)arg1;
	emlxs_port_t *port = &PPORT;
	FCFIobj_t *fcfp;
	MAILBOX4 *mb;

	mb = (MAILBOX4 *)mbq;
	fcfp = (FCFIobj_t *)mbq->context;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "CMPL unreg fcfi: status: %x", mb->mbxStatus);

	if (mb->mbxStatus) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to unregister FCFI %d index %d",
		    fcfp->FCFI, fcfp->FCF_index);
	}

	(void) emlxs_sli4_free_fcfi(hba, fcfp);

	/* Make sure link is declared down */
	emlxs_linkdown(hba);

	return (0);

} /* emlxs_cmpl_unreg_fcfi() */


/* ARGSUSED */
extern int
emlxs_mb_unreg_fcfi(emlxs_hba_t *hba, FCFIobj_t *fcfp)
{
	MAILBOXQ *mbq;
	MAILBOX4 *mb;
	uint32_t rval;

	mutex_enter(&EMLXS_PORT_LOCK);

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX, 1))) {
		mutex_exit(&EMLXS_PORT_LOCK);
		return (1);
	}
	mb = (MAILBOX4 *)mbq;
	mutex_exit(&EMLXS_PORT_LOCK);

	bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);

	mb->mbxCommand = MBX_UNREG_FCFI;
	mb->mbxOwner = OWN_HOST;
	mb->un.varUnRegFCFI.FCFI = fcfp->FCFI;

	mbq->mbox_cmpl = emlxs_cmpl_unreg_fcfi;
	mbq->context = (uint8_t *)fcfp;
	fcfp->fcf_vfi = NULL;
	fcfp->fcf_vpi = NULL;

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbq);
	}

	return (0);

} /* emlxs_mb_unreg_fcfi() */


int
emlxs_mb_cmpl_reg_vfi(void *arg1, MAILBOXQ *mbq)
{
	emlxs_hba_t *hba = (emlxs_hba_t *)arg1;
	emlxs_port_t *port = &PPORT;
	MAILBOX4 *mb;
	MAILBOXQ *mbox;
	MATCHMAP *mp;
	NODELIST *ndlp;
	emlxs_port_t *vport;
	VFIobj_t *vfip;
	uint8_t *wwn;
	volatile SERV_PARM *sp;
	int32_t i;
	uint32_t ldid;
	emlxs_vvl_fmt_t vvl;

	mb = (MAILBOX4 *)mbq;
	if (mb->mbxStatus) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_sli_detail_msg,
		    "REG_VFI failed. status=x%x", mb->mbxStatus);
		return (0);
	}

	vport = (emlxs_port_t *)mbq->context;
	vfip = vport->VFIp;
	vfip->state |= RESOURCE_VFI_REG;

	if (mb->un.varRegVFI4.vp) {
		vport->flag |= EMLXS_PORT_REGISTERED;
	}

	mp = (MATCHMAP *)mbq->bp;
	if (!mp) {
		return (0);
	}
	sp = (volatile SERV_PARM *)mp->virt;

	ldid = FABRIC_DID;
	ndlp = emlxs_node_find_did(port, ldid);

	if (!ndlp) {
		/* Attempt to create a node */
		if ((ndlp = (NODELIST *)emlxs_mem_get(hba, MEM_NLP, 0))) {
			ndlp->nlp_Rpi = 0xffff;
			ndlp->nlp_DID = ldid;

			bcopy((uint8_t *)sp, (uint8_t *)&ndlp->sparm,
			    sizeof (SERV_PARM));

			bcopy((uint8_t *)&sp->nodeName,
			    (uint8_t *)&ndlp->nlp_nodename,
			    sizeof (NAME_TYPE));

			bcopy((uint8_t *)&sp->portName,
			    (uint8_t *)&ndlp->nlp_portname,
			    sizeof (NAME_TYPE));

			ndlp->nlp_active = 1;
			ndlp->nlp_flag[hba->channel_ct]  |= NLP_CLOSED;
			ndlp->nlp_flag[hba->channel_els] |= NLP_CLOSED;
			ndlp->nlp_flag[hba->channel_fcp] |= NLP_CLOSED;
			ndlp->nlp_flag[hba->channel_ip]  |= NLP_CLOSED;

			/* Add the node */
			emlxs_node_add(port, ndlp);

			/* Open the node */
			emlxs_node_open(port, ndlp, hba->channel_ct);
			emlxs_node_open(port, ndlp, hba->channel_els);
			emlxs_node_open(port, ndlp, hba->channel_ip);
			emlxs_node_open(port, ndlp, hba->channel_fcp);
		} else {
			wwn = (uint8_t *)&sp->portName;
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_node_create_failed_msg,
			    "Unable to allocate node. did=%06x "
			    "wwpn=%02x%02x%02x%02x%02x%02x%02x%02x",
			    ldid, wwn[0], wwn[1], wwn[2],
			    wwn[3], wwn[4], wwn[5], wwn[6], wwn[7]);

			return (0);
		}
	} else {
		mutex_enter(&EMLXS_PORT_LOCK);

		ndlp->nlp_Rpi = 0xffff;
		ndlp->nlp_DID = ldid;

		bcopy((uint8_t *)sp,
		    (uint8_t *)&ndlp->sparm, sizeof (SERV_PARM));

		bcopy((uint8_t *)&sp->nodeName,
		    (uint8_t *)&ndlp->nlp_nodename, sizeof (NAME_TYPE));

		bcopy((uint8_t *)&sp->portName,
		    (uint8_t *)&ndlp->nlp_portname, sizeof (NAME_TYPE));

		wwn = (uint8_t *)&ndlp->nlp_portname;
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_update_msg,
		    "node=%p did=%06x rpi=%x "
		    "wwpn=%02x%02x%02x%02x%02x%02x%02x%02x",
		    ndlp, ndlp->nlp_DID, ndlp->nlp_Rpi, wwn[0],
		    wwn[1], wwn[2], wwn[3], wwn[4], wwn[5], wwn[6], wwn[7]);

		mutex_exit(&EMLXS_PORT_LOCK);

		/* Open the node */
		emlxs_node_open(port, ndlp, hba->channel_ct);
		emlxs_node_open(port, ndlp, hba->channel_els);
		emlxs_node_open(port, ndlp, hba->channel_ip);
		emlxs_node_open(port, ndlp, hba->channel_fcp);
	}

	bzero((char *)&vvl, sizeof (emlxs_vvl_fmt_t));

	if (sp->VALID_VENDOR_VERSION) {

		bcopy((caddr_t *)&sp->vendorVersion[0],
		    (caddr_t *)&vvl, sizeof (emlxs_vvl_fmt_t));

		vvl.un0.word0 = LE_SWAP32(vvl.un0.word0);
		vvl.un1.word1 = LE_SWAP32(vvl.un1.word1);

		if ((vvl.un0.w0.oui == 0x0000C9) &&
		    (vvl.un1.w1.vport)) {
			ndlp->nlp_fcp_info |= NLP_EMLX_VPORT;
		}
	}

	if ((mbox = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX, 1))) {
		/* If link not already down then */
		/* declare it down now */
		if (emlxs_mb_read_sparam(hba, mbox) == 0) {
			emlxs_mb_put(hba, mbox);
		} else {
			(void) emlxs_mem_put(hba, MEM_MBOX,
			    (uint8_t *)mbox);
		}
	}

	/* Since this is a fabric login */
	/*
	 * If NPIV Fabric support has just been established on
	 * the physical port, then notify the vports of the
	 * link up
	 */
	EMLXS_STATE_CHANGE_LOCKED(hba, FC_READY);
	if ((hba->flag & FC_NPIV_ENABLED) &&
	    (hba->flag & FC_NPIV_SUPPORTED)) {
		/* Skip the physical port */
		for (i = 1; i < MAX_VPORTS; i++) {
			vport = &VPORT(i);

			if (!(vport->flag & EMLXS_PORT_BOUND) ||
			    !(vport->flag & EMLXS_PORT_ENABLE)) {
				continue;
			}

			emlxs_port_online(vport);
		}
	}

#ifdef SFCT_SUPPORT
	if (mbq->sbp && ((emlxs_buf_t *)mbq->sbp)->fct_cmd) {
		emlxs_buf_t *cmd_sbp = (emlxs_buf_t *)mbq->sbp;

		if (cmd_sbp->fct_state == EMLXS_FCT_REG_PENDING) {
			mbq->sbp = NULL;

			mutex_enter(&EMLXS_PKT_LOCK);
			cmd_sbp->node = ndlp;
			cv_broadcast(&EMLXS_PKT_CV);
			mutex_exit(&EMLXS_PKT_LOCK);
		}
	}
#endif /* SFCT_SUPPORT */
	return (0);

} /* emlxs_mb_cmpl_reg_vfi */


/*ARGSUSED*/
extern int
emlxs_mb_reg_vfi(emlxs_hba_t *hba, MAILBOXQ *mbq, VFIobj_t *vfip,
    emlxs_port_t *port)
{
	MAILBOX4 *mb = (MAILBOX4 *)mbq;
	FCFIobj_t *fcfp;
	MATCHMAP *mp;

	bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);

	if ((mp = (MATCHMAP *)emlxs_mem_get(hba, MEM_BUF, 1)) == 0) {
		return (0);
	}

	mb->mbxCommand = MBX_REG_VFI;
	mb->mbxOwner = OWN_HOST;
	mb->un.varRegVFI4.vfi = vfip->VFI;
	if (!(port->flag & EMLXS_PORT_REGISTERED)) {
		mb->un.varRegVFI4.vp = 1;
		mb->un.varRegVFI4.vpi = port->vpi + hba->vpi_base;
	}
	fcfp = vfip->FCFIp;
	mb->un.varRegVFI4.fcfi = fcfp->FCFI;
	mb->un.varRegVFI4.sid = port->did;

	/* in ms */
	mb->un.varRegVFI4.edtov = fcfp->fcf_sparam.cmn.e_d_tov;

	/* Convert to seconds */
	mb->un.varRegVFI4.ratov = (fcfp->fcf_sparam.cmn.w2.r_a_tov +
	    999) / 1000;

	mb->un.varRegVFI4.bde.tus.f.bdeSize = sizeof (SERV_PARM);
	mb->un.varRegVFI4.bde.addrHigh = PADDR_HI(mp->phys);
	mb->un.varRegVFI4.bde.addrLow = PADDR_LO(mp->phys);
	bcopy((uint32_t *)&fcfp->fcf_sparam,
	    (uint32_t *)mp->virt, sizeof (SERV_PARM));

	mbq->mbox_cmpl = emlxs_mb_cmpl_reg_vfi;

	/*
	 * save address for completion
	 */
	mbq->bp = (uint8_t *)mp;
	mbq->context = (uint8_t *)port;
	return (1);

} /* emlxs_mb_reg_vfi() */


/*ARGSUSED*/
extern int
emlxs_mb_unreg_vfi(emlxs_hba_t *hba, VFIobj_t *vfip)
{
	FCFIobj_t *fcfp;
	MAILBOX4 *mb;
	MAILBOXQ *mbq;
	uint32_t rval;

	mutex_enter(&EMLXS_PORT_LOCK);
	if (!(vfip->state & RESOURCE_VFI_REG)) {
		mutex_exit(&EMLXS_PORT_LOCK);
		return (1);

	}
	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX, 1))) {
		mutex_exit(&EMLXS_PORT_LOCK);
		return (1);
	}

	vfip->state &= ~RESOURCE_VFI_REG;
	mutex_exit(&EMLXS_PORT_LOCK);

	mb = (MAILBOX4 *)mbq->mbox;

	bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);

	mb->mbxCommand = MBX_UNREG_VFI;
	mb->mbxOwner = OWN_HOST;

	mb->un.varUnRegVFI4.vfi = vfip->VFI;

	mbq->mbox_cmpl = NULL;

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbq);
	}

	fcfp = vfip->FCFIp;
	if (vfip == fcfp->fcf_vfi) {
		fcfp->fcf_vfi = NULL;
	}
	emlxs_sli4_free_vfi(hba, vfip);
	return (1);

} /* emlxs_mb_unreg_vfi() */


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

	return;

} /* emlxs_mb_heartbeat() */


#ifdef MSI_SUPPORT

/*ARGSUSED*/
extern void
emlxs_mb_config_msi(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t *intr_map,
    uint32_t intr_count)
{
	MAILBOX *mb = (MAILBOX *)mbq;
	uint32_t i;
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

	return;

} /* emlxs_mb_config_msi() */


/*ARGSUSED*/
extern void
emlxs_mb_config_msix(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t *intr_map,
    uint32_t intr_count)
{
	MAILBOX *mb = (MAILBOX *)mbq;
	uint32_t i;
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

	return;

} /* emlxs_mb_reset_ring() */


/*ARGSUSED*/
extern void
emlxs_mb_dump_vpd(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t offset)
{

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		MAILBOX4 *mb = (MAILBOX4 *)mbq;

		/* Clear the local dump_region */
		bzero(hba->sli.sli4.dump_region.virt,
		    hba->sli.sli4.dump_region.size);

		bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);

		mb->mbxCommand = MBX_DUMP_MEMORY;
		mb->un.varDmp4.type = DMP_NV_PARAMS;
		mb->un.varDmp4.entry_index = offset;
		mb->un.varDmp4.region_id = DMP_VPD_REGION;

		mb->un.varDmp4.available_cnt = hba->sli.sli4.dump_region.size;
		mb->un.varDmp4.addrHigh =
		    PADDR_HI(hba->sli.sli4.dump_region.phys);
		mb->un.varDmp4.addrLow =
		    PADDR_LO(hba->sli.sli4.dump_region.phys);
		mb->un.varDmp4.rsp_cnt = 0;

		mb->mbxOwner = OWN_HOST;

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

} /* emlxs_mb_dump_vpd() */


/*ARGSUSED*/
extern void
emlxs_mb_dump_fcoe(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t offset)
{
	MAILBOX4 *mb = (MAILBOX4 *)mbq;

	if (hba->sli_mode != EMLXS_HBA_SLI4_MODE) {
		return;
	}
	/* Clear the local dump_region */
	bzero(hba->sli.sli4.dump_region.virt,
	    hba->sli.sli4.dump_region.size);

	bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);

	mb->mbxCommand = MBX_DUMP_MEMORY;
	mb->un.varDmp4.type = DMP_NV_PARAMS;
	mb->un.varDmp4.entry_index = offset;
	mb->un.varDmp4.region_id = DMP_FCOE_REGION;

	mb->un.varDmp4.available_cnt = hba->sli.sli4.dump_region.size;
	mb->un.varDmp4.addrHigh =
	    PADDR_HI(hba->sli.sli4.dump_region.phys);
	mb->un.varDmp4.addrLow =
	    PADDR_LO(hba->sli.sli4.dump_region.phys);
	mb->un.varDmp4.rsp_cnt = 0;

	mb->mbxOwner = OWN_HOST;

	mbq->mbox_cmpl = NULL; /* no cmpl needed */

} /* emlxs_mb_dump_fcoe() */


/*ARGSUSED*/
extern void
emlxs_mb_dump(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t offset, uint32_t words)
{

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		MAILBOX4 *mb = (MAILBOX4 *)mbq;

		/* Clear the local dump_region */
		bzero(hba->sli.sli4.dump_region.virt,
		    hba->sli.sli4.dump_region.size);

		bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);

		mb->mbxCommand = MBX_DUMP_MEMORY;
		mb->un.varDmp4.type = DMP_MEM_REG;
		mb->un.varDmp4.entry_index = offset;
		mb->un.varDmp4.region_id = 0;

		mb->un.varDmp4.available_cnt = min((words*4),
		    hba->sli.sli4.dump_region.size);
		mb->un.varDmp4.addrHigh =
		    PADDR_HI(hba->sli.sli4.dump_region.phys);
		mb->un.varDmp4.addrLow =
		    PADDR_LO(hba->sli.sli4.dump_region.phys);
		mb->un.varDmp4.rsp_cnt = 0;

		mb->mbxOwner = OWN_HOST;

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

	return (0);
} /* emlxs_mb_run_biu_diag() */


/* This should only be called with active MBX_NOWAIT mailboxes */
void
emlxs_mb_retry(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX	*mb;
	MAILBOX	*mbox;
	int rc;

	mbox = (MAILBOX *)emlxs_mem_get(hba, MEM_MBOX, 1);
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

	hba->mbox_mbq = 0;
	hba->mbox_queue_flag = 0;

	mutex_exit(&EMLXS_PORT_LOCK);

	rc =  EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbox, MBX_NOWAIT, 0);
	if ((rc != MBX_BUSY) && (rc != MBX_SUCCESS)) {
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbox);
	}
	return;

} /* emlxs_mb_retry() */


int
emlxs_cmpl_read_la(void *arg1, MAILBOXQ *mbq)
{
	emlxs_hba_t *hba = (emlxs_hba_t *)arg1;
	emlxs_port_t *port = &PPORT;
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
	bcopy((uint32_t *)((char *)mb + sizeof (uint32_t)),
	    (uint32_t *)&la, sizeof (READ_LA_VAR));

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
		if ((hba->model_info.device_id == PCI_DEVICE_ID_LP21000_M) &&
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
			port->did = la.granted_AL_PA;
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
		    PCI_DEVICE_ID_LP21000_M) {
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
				    NULL, NULL);
			}
		}
#endif /* MENLO_SUPPORT */

		if ((mbox = (MAILBOXQ *)emlxs_mem_get(hba,
		    MEM_MBOX, 1))) {
			/* This should turn on DELAYED ABTS for */
			/* ELS timeouts */
			emlxs_mb_set_var(hba, mbox, 0x00052198, 0x1);

			emlxs_mb_put(hba, mbox);
		}

		if ((mbox = (MAILBOXQ *)emlxs_mem_get(hba,
		    MEM_MBOX, 1))) {
			/* If link not already down then */
			/* declare it down now */
			if (emlxs_mb_read_sparam(hba, mbox) == 0) {
				emlxs_mb_put(hba, mbox);
			} else {
				(void) emlxs_mem_put(hba, MEM_MBOX,
				    (uint8_t *)mbox);
			}
		}

		if ((mbox = (MAILBOXQ *)emlxs_mem_get(hba,
		    MEM_MBOX, 1))) {
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

	/* Log the link event */
	emlxs_log_link_event(port);
	return (0);

} /* emlxs_cmpl_read_la() */


/*
 *  emlxs_mb_read_la  Issue a READ LA mailbox command
 */
extern uint32_t
emlxs_mb_read_la(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX *mb = (MAILBOX *)mbq;
	MATCHMAP *mp;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	if ((mp = (MATCHMAP *)emlxs_mem_get(hba, MEM_BUF, 1)) == 0) {
		mb->mbxCommand = MBX_READ_LA64;

		return (1);
	}

	mb->mbxCommand = MBX_READ_LA64;
	mb->un.varReadLA.un.lilpBde64.tus.f.bdeSize = 128;
	mb->un.varReadLA.un.lilpBde64.addrHigh = PADDR_HI(mp->phys);
	mb->un.varReadLA.un.lilpBde64.addrLow = PADDR_LO(mp->phys);
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = emlxs_cmpl_read_la;

	/*
	 * save address for completion
	 */
	((MAILBOXQ *)mb)->bp = (uint8_t *)mp;

	return (0);

} /* emlxs_mb_read_la() */


int
emlxs_cmpl_clear_la(void *arg1, MAILBOXQ *mbq)
{
	emlxs_hba_t *hba = (emlxs_hba_t *)arg1;
	emlxs_port_t *port = &PPORT;
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
			    MEM_MBOX, 1))) {
				/* Get link attention message */
				if (emlxs_mb_read_la(hba, mbox) == 0) {
					rc =  EMLXS_SLI_ISSUE_MBOX_CMD(hba,
					    (MAILBOX *)mbox, MBX_NOWAIT, 0);
					if ((rc != MBX_BUSY) &&
					    (rc != MBX_SUCCESS)) {
						(void) emlxs_mem_put(hba,
						    MEM_MBOX, (uint8_t *)mbox);
					}
					la_enable = 0;
				} else {
					(void) emlxs_mem_put(hba, MEM_MBOX,
					    (uint8_t *)mbox);
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

} /* emlxs_cmpl_clear_la() */


/*
 *  emlxs_mb_clear_la  Issue a CLEAR LA mailbox command
 */
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
	mbq->mbox_cmpl = emlxs_cmpl_clear_la;

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

} /* emlxs_mb_read_lnk_stat() */


/*
 * emlxs_mb_write_nv  Issue a WRITE NVPARAM mailbox command
 */
static void
emlxs_emb_mb_write_nv(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX *mb = (MAILBOX *)mbq;
	int32_t		i;
	emlxs_config_t	*cfg = &CFG;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	bcopy((void *)&hba->wwnn,
	    (void *)mb->un.varWTnvp.nodename, sizeof (NAME_TYPE));

	bcopy((void *)&hba->wwpn,
	    (void *)mb->un.varWTnvp.portname, sizeof (NAME_TYPE));

	mb->un.varWTnvp.pref_DID = 0;
	mb->un.varWTnvp.hardAL_PA = (uint8_t)cfg[CFG_ASSIGN_ALPA].current;
	mb->un.varWTnvp.rsvd1[0] = 0xffffffff;
	mb->un.varWTnvp.rsvd1[1] = 0xffffffff;
	mb->un.varWTnvp.rsvd1[2] = 0xffffffff;
	for (i = 0; i < 21; i++) {
		mb->un.varWTnvp.rsvd3[i] = 0xffffffff;
	}

	mb->mbxCommand = MBX_WRITE_NV;
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */

} /* emlxs_mb_write_nv() */


/*
 * emlxs_mb_part_slim  Issue a PARTITION SLIM mailbox command
 */
static void
emlxs_mb_part_slim(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t hbainit)
{
	MAILBOX *mb = (MAILBOX *)mbq;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);


	mb->un.varSlim.numRing = hba->chan_count;
	mb->un.varSlim.hbainit = hbainit;
	mb->mbxCommand = MBX_PART_SLIM;
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */

} /* emlxs_mb_part_slim() */


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

	if (cfg[CFG_ACK0].current)
		mb->un.varCfgLnk.ack0_enable = 1;

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

	return;

} /* emlxs_mb_config_link() */


int
emlxs_cmpl_init_link(void *arg1, MAILBOXQ *mbq)
{
	emlxs_hba_t *hba = (emlxs_hba_t *)arg1;
	emlxs_port_t *port = &PPORT;
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

} /* emlxs_cmpl_init_link() */


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

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);
		mbq->nonembed = NULL;
		mbq->mbox_cmpl = NULL; /* no cmpl needed */

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
	mbq->mbox_cmpl = emlxs_cmpl_init_link;


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

	return;

} /* emlxs_mb_down_link() */


int
emlxs_cmpl_read_sparam(void *arg1, MAILBOXQ *mbq)
{
	emlxs_hba_t *hba = (emlxs_hba_t *)arg1;
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
	    "SPARAM: EDTOV hba=x%x mbox_csp=x%x,  BBC=x%x",
	    hba->fc_edtov, hba->sparam.cmn.e_d_tov,
	    hba->sparam.cmn.bbCreditlsb);

	hba->sparam.cmn.e_d_tov = hba->fc_edtov;

	/* Initialize the physical port */
	bcopy((caddr_t)&hba->sparam,
	    (caddr_t)&port->sparam, sizeof (SERV_PARM));
	bcopy((caddr_t)&hba->wwpn, (caddr_t)&port->wwpn,
	    sizeof (NAME_TYPE));
	bcopy((caddr_t)&hba->wwnn, (caddr_t)&port->wwnn,
	    sizeof (NAME_TYPE));

	/* Initialize the virtual ports */
	for (i = 1; i < MAX_VPORTS; i++) {
		vport = &VPORT(i);
		if (vport->flag & EMLXS_PORT_BOUND) {
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

} /* emlxs_cmpl_read_sparam() */


/*
 * emlxs_mb_read_sparam  Issue a READ SPARAM mailbox command
 */
extern uint32_t
emlxs_mb_read_sparam(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX *mb = (MAILBOX *)mbq;
	MATCHMAP *mp;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	if ((mp = (MATCHMAP *)emlxs_mem_get(hba, MEM_BUF, 1)) == 0) {
		mb->mbxCommand = MBX_READ_SPARM64;

		return (1);
	}

	mb->un.varRdSparm.un.sp64.tus.f.bdeSize = sizeof (SERV_PARM);
	mb->un.varRdSparm.un.sp64.addrHigh = PADDR_HI(mp->phys);
	mb->un.varRdSparm.un.sp64.addrLow = PADDR_LO(mp->phys);
	mb->mbxCommand = MBX_READ_SPARM64;
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = emlxs_cmpl_read_sparam;

	/*
	 * save address for completion
	 */
	mbq->bp = (uint8_t *)mp;

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


int
emlxs_cmpl_reg_did(void *arg1, MAILBOXQ *mbq)
{
	emlxs_hba_t *hba = (emlxs_hba_t *)arg1;
	emlxs_port_t *port = &PPORT;
	MAILBOX *mb;
	MATCHMAP *mp;
	NODELIST *ndlp;
	emlxs_port_t *vport;
	uint8_t *wwn;
	volatile SERV_PARM *sp;
	int32_t i;
	uint32_t  control;
	uint32_t ldata;
	uint32_t ldid;
	uint16_t lrpi;
	uint16_t lvpi;
	emlxs_vvl_fmt_t vvl;

	mb = (MAILBOX *)mbq;
	if (mb->mbxStatus) {
		if (mb->mbxStatus == MBXERR_NO_RESOURCES) {
			control = mb->un.varRegLogin.un.sp.bdeSize;
			if (control == 0) {
				/* Special handle for vport PLOGI */
				if (mbq->iocbq == (uint8_t *)1) {
					mbq->iocbq = NULL;
				}
				return (0);
			}
			emlxs_mb_retry(hba, mbq);
			return (1);
		}
		if (mb->mbxStatus == MBXERR_RPI_FULL) {
			port = &VPORT((mb->un.varRegLogin.vpi - hba->vpi_base));

			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_node_create_failed_msg,
			    "Limit reached. count=%d", port->node_count);
		}

		/* Special handle for vport PLOGI */
		if (mbq->iocbq == (uint8_t *)1) {
			mbq->iocbq = NULL;
		}

		return (0);
	}

	mp = (MATCHMAP *)mbq->bp;
	if (!mp) {
		return (0);
	}
	ldata = mb->un.varWords[5];
	lvpi = (ldata & 0xffff) - hba->vpi_base;
	port = &VPORT(lvpi);

	/* First copy command data */
	ldata = mb->un.varWords[0];	/* get rpi */
	lrpi = ldata & 0xffff;

	ldata = mb->un.varWords[1];	/* get did */
	ldid = ldata & MASK_DID;

	sp = (volatile SERV_PARM *)mp->virt;
	ndlp = emlxs_node_find_did(port, ldid);

	if (!ndlp) {
		/* Attempt to create a node */
		if ((ndlp = (NODELIST *)emlxs_mem_get(hba, MEM_NLP, 0))) {
			ndlp->nlp_Rpi = lrpi;
			ndlp->nlp_DID = ldid;

			bcopy((uint8_t *)sp, (uint8_t *)&ndlp->sparm,
			    sizeof (SERV_PARM));

			bcopy((uint8_t *)&sp->nodeName,
			    (uint8_t *)&ndlp->nlp_nodename,
			    sizeof (NAME_TYPE));

			bcopy((uint8_t *)&sp->portName,
			    (uint8_t *)&ndlp->nlp_portname,
			    sizeof (NAME_TYPE));

			ndlp->nlp_active = 1;
			ndlp->nlp_flag[hba->channel_ct]  |= NLP_CLOSED;
			ndlp->nlp_flag[hba->channel_els] |= NLP_CLOSED;
			ndlp->nlp_flag[hba->channel_fcp] |= NLP_CLOSED;
			ndlp->nlp_flag[hba->channel_ip]  |= NLP_CLOSED;

			/* Add the node */
			emlxs_node_add(port, ndlp);

			/* Open the node */
			emlxs_node_open(port, ndlp, hba->channel_ct);
			emlxs_node_open(port, ndlp, hba->channel_els);
			emlxs_node_open(port, ndlp, hba->channel_ip);
			emlxs_node_open(port, ndlp, hba->channel_fcp);
		} else {
			wwn = (uint8_t *)&sp->portName;
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_node_create_failed_msg,
			    "Unable to allocate node. did=%06x rpi=%x "
			    "wwpn=%02x%02x%02x%02x%02x%02x%02x%02x",
			    ldid, lrpi, wwn[0], wwn[1], wwn[2],
			    wwn[3], wwn[4], wwn[5], wwn[6], wwn[7]);

			return (0);
		}
	} else {
		mutex_enter(&EMLXS_PORT_LOCK);

		ndlp->nlp_Rpi = lrpi;
		ndlp->nlp_DID = ldid;

		bcopy((uint8_t *)sp,
		    (uint8_t *)&ndlp->sparm, sizeof (SERV_PARM));

		bcopy((uint8_t *)&sp->nodeName,
		    (uint8_t *)&ndlp->nlp_nodename, sizeof (NAME_TYPE));

		bcopy((uint8_t *)&sp->portName,
		    (uint8_t *)&ndlp->nlp_portname, sizeof (NAME_TYPE));

		wwn = (uint8_t *)&ndlp->nlp_portname;
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_update_msg,
		    "node=%p did=%06x rpi=%x "
		    "wwpn=%02x%02x%02x%02x%02x%02x%02x%02x",
		    ndlp, ndlp->nlp_DID, ndlp->nlp_Rpi, wwn[0],
		    wwn[1], wwn[2], wwn[3], wwn[4], wwn[5], wwn[6], wwn[7]);

		mutex_exit(&EMLXS_PORT_LOCK);

		/* Open the node */
		emlxs_node_open(port, ndlp, hba->channel_ct);
		emlxs_node_open(port, ndlp, hba->channel_els);
		emlxs_node_open(port, ndlp, hba->channel_ip);
		emlxs_node_open(port, ndlp, hba->channel_fcp);
	}

	bzero((char *)&vvl, sizeof (emlxs_vvl_fmt_t));

	if (sp->VALID_VENDOR_VERSION) {

		bcopy((caddr_t *)&sp->vendorVersion[0],
		    (caddr_t *)&vvl, sizeof (emlxs_vvl_fmt_t));

		vvl.un0.word0 = LE_SWAP32(vvl.un0.word0);
		vvl.un1.word1 = LE_SWAP32(vvl.un1.word1);

		if ((vvl.un0.w0.oui == 0x0000C9) &&
		    (vvl.un1.w1.vport)) {
			ndlp->nlp_fcp_info |= NLP_EMLX_VPORT;
		}
	}

	if ((hba->sli_mode == EMLXS_HBA_SLI4_MODE) &&
	    (ndlp->nlp_DID == NAMESERVER_DID)) {
			EMLXS_STATE_CHANGE_LOCKED(hba, FC_READY);
	}

	/* If this was a fabric login */
	if (ndlp->nlp_DID == FABRIC_DID) {
		/* If CLEAR_LA has been sent, then attempt to */
		/* register the vpi now */
		if (hba->state == FC_READY) {
			(void) emlxs_mb_reg_vpi(port, NULL);
		}

		/*
		 * If NPIV Fabric support has just been established on
		 * the physical port, then notify the vports of the
		 * link up
		 */
		if ((lvpi == 0) &&
		    (hba->flag & FC_NPIV_ENABLED) &&
		    (hba->flag & FC_NPIV_SUPPORTED)) {
			/* Skip the physical port */
			for (i = 1; i < MAX_VPORTS; i++) {
				vport = &VPORT(i);

				if (!(vport->flag & EMLXS_PORT_BOUND) ||
				    !(vport->flag & EMLXS_PORT_ENABLE)) {
					continue;
				}

				emlxs_port_online(vport);
			}
		}
	}

	if (mbq->iocbq == (uint8_t *)1) {
		mbq->iocbq = NULL;
		(void) emlxs_mb_unreg_did(port, ldid, NULL, NULL, NULL);
	}

#ifdef DHCHAP_SUPPORT
	if (mbq->sbp || mbq->ubp) {
		if (emlxs_dhc_auth_start(port, ndlp, mbq->sbp,
		    mbq->ubp) == 0) {
			/* Auth started - auth completion will */
			/* handle sbp and ubp now */
			mbq->sbp = NULL;
			mbq->ubp = NULL;
		}
	}
#endif	/* DHCHAP_SUPPORT */

#ifdef SFCT_SUPPORT
	if (mbq->sbp && ((emlxs_buf_t *)mbq->sbp)->fct_cmd) {
		emlxs_buf_t *cmd_sbp = (emlxs_buf_t *)mbq->sbp;

		if (cmd_sbp->fct_state == EMLXS_FCT_REG_PENDING) {
			mbq->sbp = NULL;

			mutex_enter(&EMLXS_PKT_LOCK);
			cmd_sbp->node = ndlp;
			cv_broadcast(&EMLXS_PKT_CV);
			mutex_exit(&EMLXS_PKT_LOCK);
		}
	}
#endif /* SFCT_SUPPORT */
	return (0);

} /* emlxs_cmpl_reg_did() */


/*
 * emlxs_mb_reg_did  Issue a REG_LOGIN mailbox command
 */
extern uint32_t
emlxs_mb_reg_did(emlxs_port_t *port, uint32_t did, SERV_PARM *param,
    emlxs_buf_t *sbp, fc_unsol_buf_t *ubp, IOCBQ *iocbq)
{
	emlxs_hba_t	*hba = HBA;
	MATCHMAP	*mp;
	MAILBOXQ	*mbq;
	MAILBOX		*mb;
	NODELIST	*node;
	RPIobj_t	*rp = NULL;
	uint32_t	rval;

	/* Check for invalid node ids to register */
	if ((did == 0) && (!(hba->flag & FC_LOOPBACK_MODE))) {
		return (1);
	}

	if (did & 0xff000000) {
		return (1);
	}

	if ((rval = emlxs_mb_check_sparm(hba, param))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_create_failed_msg,
		    "Invalid service parameters. did=%06x rval=%d", did,
		    rval);

		return (1);
	}

	/* Check if the node limit has been reached */
	if (port->node_count >= hba->max_nodes) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_create_failed_msg,
		    "Limit reached. did=%06x count=%d", did,
		    port->node_count);

		return (1);
	}

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX, 1))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_create_failed_msg,
		    "Unable to allocate mailbox. did=%x", did);

		return (1);
	}
	mb = (MAILBOX *)mbq->mbox;

	/* Build login request */
	if ((mp = (MATCHMAP *)emlxs_mem_get(hba, MEM_BUF, 1)) == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_create_failed_msg,
		    "Unable to allocate buffer. did=%x", did);

		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbq);
		return (1);
	}

	/*
	 * If we are SLI4, the RPI number gets assigned by the driver.
	 * For SLI3, the firmware assigns the RPI number.
	 */
	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		node = emlxs_node_find_did(port, did);
		rp = EMLXS_NODE_TO_RPI(hba, node);

		if (!rp) {
			rp = emlxs_sli4_alloc_rpi(port);
		}

		if (!rp) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_create_failed_msg,
			    "Unable to get an rpi. did=%x", did);

			(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbq);
			return (1);
		}
		rp->state &= ~RESOURCE_RPI_PAUSED;
	}

	bcopy((void *)param, (void *)mp->virt, sizeof (SERV_PARM));

	mb->un.varRegLogin.un.sp64.tus.f.bdeSize = sizeof (SERV_PARM);
	mb->un.varRegLogin.un.sp64.addrHigh = PADDR_HI(mp->phys);
	mb->un.varRegLogin.un.sp64.addrLow = PADDR_LO(mp->phys);
	mb->un.varRegLogin.did = did;
	mb->un.varWords[30] = 0;	/* flags */
	mb->mbxCommand = MBX_REG_LOGIN64;
	mb->mbxOwner = OWN_HOST;
	mb->un.varRegLogin.vpi = port->vpi + hba->vpi_base;
	mb->un.varRegLogin.rpi = (rp)? rp->RPI: 0;

	mbq->sbp = (uint8_t *)sbp;
	mbq->ubp = (uint8_t *)ubp;
	mbq->iocbq = (uint8_t *)iocbq;
	mbq->bp = (uint8_t *)mp;
	mbq->mbox_cmpl = emlxs_cmpl_reg_did;

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbq);
		if (rp) {
			emlxs_sli4_free_rpi(hba, rp);
		}
	}

	return (0);

} /* emlxs_mb_reg_did() */

/*
 * emlxs_mb_unreg_rpi  Issue a UNREG_LOGIN mailbox command
 */
extern uint32_t
emlxs_mb_unreg_rpi(emlxs_port_t *port, uint32_t rpi, emlxs_buf_t *sbp,
    fc_unsol_buf_t *ubp, IOCBQ *iocbq)
{
	emlxs_hba_t	*hba = HBA;
	MAILBOXQ	*mbq;
	MAILBOX		*mb;
	NODELIST	*ndlp;
	int rval;

	if (rpi != 0xffff) {
		/* Make sure the node does already exist */
		ndlp = emlxs_node_find_rpi(port, rpi);


		if (ndlp) {
			/*
			 * If we just unregistered the host node then
			 * clear the host DID
			 */
			if (ndlp->nlp_DID == port->did) {
				port->did = 0;
			}

			/* remove it */
			emlxs_node_rm(port, ndlp);

		} else {
			return (1);
		}
	} else {	/* Unreg all */

		emlxs_node_destroy_all(port);
	}

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX, 1))) {
		return (1);
	}

	mb = (MAILBOX *)mbq->mbox;

#define	INDEX_INDICATOR_VPI	1

	if ((hba->sli_mode == EMLXS_HBA_SLI4_MODE) && (rpi == 0xffff)) {
		mb->un.varUnregLogin.ll = INDEX_INDICATOR_VPI;
		mb->un.varUnregLogin.rpi = (uint16_t)port->vpi + hba->vpi_base;
	} else {
		mb->un.varUnregLogin.rpi = (uint16_t)rpi;
	}

	mb->un.varUnregLogin.vpi = port->vpi + hba->vpi_base;
	mb->mbxCommand = MBX_UNREG_LOGIN;
	mb->mbxOwner = OWN_HOST;
	mbq->sbp = (uint8_t *)sbp;
	mbq->ubp = (uint8_t *)ubp;
	mbq->iocbq = (uint8_t *)iocbq;
	mbq->mbox_cmpl = NULL;

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbq);
	}

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		port->outstandingRPIs--;
		if ((port->outstandingRPIs == 0) &&
		    (hba->state == FC_LINK_DOWN)) {
			/* No more RPIs so unreg the VPI */
			(void) emlxs_mb_unreg_vpi(port);
		}
	}

	return (0);
} /* emlxs_mb_unreg_rpi() */


/*
 * emlxs_mb_unreg_did  Issue a UNREG_DID mailbox command
 */
extern uint32_t
emlxs_mb_unreg_did(emlxs_port_t *port, uint32_t did, emlxs_buf_t *sbp,
    fc_unsol_buf_t *ubp, IOCBQ *iocbq)
{
	emlxs_hba_t	*hba = HBA;
	NODELIST	*ndlp;
	MAILBOXQ	*mbq;
	MAILBOX		*mb;
	int rval = 0;

	/*
	 * Unregister all default RPIs if did == 0xffffffff
	 */
	if (did != 0xffffffff) {
		/* Check for base node */
		if (did == BCAST_DID) {
			/* just flush base node */
			(void) emlxs_tx_node_flush(port, &port->node_base,
			    0, 0, 0);
			(void) emlxs_chipq_node_flush(port, 0,
			    &port->node_base, 0);

			/* Return now */
			return (1);
		}


		/*
		 * A zero DID means that we are trying to unreg the host node
		 * after a link bounce
		 */

		/*
		 * If the prev_did == 0 then the adapter has been reset and
		 * there is no need in unregistering
		 */

		/*
		 * If the prev_did != 0 then we can look for the hosts
		 * last known DID node
		 */

		if (did == 0) {
			if (port->prev_did == 0) {
				return (1);
			}

			did = port->prev_did;
		}

		/* Make sure the node does already exist */
		ndlp = emlxs_node_find_did(port, did);

		if (ndlp) {
			if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
				/* Use UNREG_RPI for SLI4 */
				if (ndlp->nlp_Rpi != 0xffff) {
					rval = emlxs_mb_unreg_rpi(port,
					    ndlp->nlp_Rpi, sbp, ubp, iocbq);
				}
				return (rval);
			}
			/* remove it */
			emlxs_node_rm(port, ndlp);

			/*
			 * If we just unregistered the host node then
			 * clear the host DID
			 */
			if (did == port->did) {
				port->did = 0;
			}

		} else {
			return (1);
		}
	} else {
		/* SLI4 doesn't have dflt RPIs in SLI Port */
		if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
			return (0);
		}
	}

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX, 1))) {
		return (1);
	}

	mb = (MAILBOX *)mbq->mbox;
	mb->un.varUnregDID.did = did;
	mb->un.varUnregDID.vpi = port->vpi + hba->vpi_base;
	mb->mbxCommand = MBX_UNREG_D_ID;
	mb->mbxOwner = OWN_HOST;
	mbq->sbp = (uint8_t *)sbp;
	mbq->ubp = (uint8_t *)ubp;
	mbq->iocbq = (uint8_t *)iocbq;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbq);
	}

	return (0);

} /* emlxs_mb_unreg_did() */


/*
 * emlxs_mb_set_mask   Issue a SET MASK mailbox command
 */
/*ARGSUSED*/
static void
emlxs_mb_set_mask(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t mask,
    uint32_t ringno)
{
	MAILBOX *mb = (MAILBOX *)mbq;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->un.varWords[0] = 0x11223344;	/* set passwd */
	mb->un.varWords[1] = mask;	/* set mask */
	mb->un.varWords[2] = ringno;	/* set ringno */
	mb->mbxCommand = MBX_SET_MASK;
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */

} /* emlxs_mb_set_mask() */


/*
 * emlxs_mb_set_debug  Issue a special debug mailbox command
 */
/*ARGSUSED*/
static void
emlxs_mb_set_debug(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t word0,
    uint32_t word1, uint32_t word2)
{
	MAILBOX *mb = (MAILBOX *)mbq;

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->un.varWords[0] = word0;
	mb->un.varWords[1] = word1;
	mb->un.varWords[2] = word2;
	mb->mbxCommand = MBX_SET_DEBUG;
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = NULL; /* no cmpl needed */

} /* emlxs_mb_set_debug() */


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

int
emlxs_cmpl_init_vpi(void *arg1, MAILBOXQ *mbq)
{
	emlxs_hba_t *hba = (emlxs_hba_t *)arg1;
	emlxs_port_t *port = &PPORT;
	emlxs_port_t *vport;
	MAILBOX4 *mb;

	mb = (MAILBOX4 *)mbq;

	if (mb->mbxStatus == MBX_SUCCESS) {
		vport = &VPORT((mb->un.varInitVPI4.vpi - hba->vpi_base));
		vport->flag |= EMLXS_PORT_INIT_VPI_CMPL;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "CMPL init_vpi: stats: %x", mb->mbxStatus);

	return (0);

} /* emlxs_cmpl_init_vpi() */


extern uint32_t
emlxs_mb_init_vpi(emlxs_port_t *port)
{
	emlxs_hba_t	*hba = HBA;
	emlxs_port_t    *phy_port = &PPORT;
	MAILBOXQ	*mbq;
	MAILBOX4	*mb;
	int rval;

	if (!(hba->flag & FC_NPIV_ENABLED)) {
		return (0);
	}

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX, 1))) {
		return (1);
	}


	mb = (MAILBOX4 *)mbq->mbox;
	bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);
	mbq->nonembed = NULL;
	mb->un.varInitVPI4.vfi = phy_port->VFIp->VFI;
	mb->un.varInitVPI4.vpi = port->vpi + hba->vpi_base;
	mb->mbxCommand = MBX_INIT_VPI;
	mb->mbxOwner = OWN_HOST;
	mbq->mbox_cmpl = emlxs_cmpl_init_vpi;

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbq);
	}

	return (0);

} /* emlxs_mb_init_vpi() */


/* Leadville wll start sending PLOGI right after */
/* FDISC completion, we need to wait for REG_VPI */
/* completion, before sending back the FDISK request */
/* Also, allocate a node structure for Fabric port */
int
emlxs_cmpl_reg_vpi(void *arg1, MAILBOXQ *mbq)
{
	emlxs_hba_t *hba = (emlxs_hba_t *)arg1;
	emlxs_port_t *port = &PPORT;
	emlxs_port_t *vport;
	MAILBOX *mb;
	emlxs_buf_t *sbp;
	SERV_PARM *sp;
	fc_packet_t *pkt;
	NODELIST *ndlp;
	uint32_t ldid;
	uint8_t *wwn;

	mb = (MAILBOX *)mbq;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "CMPL reg_vpi: stats: %x", mb->mbxStatus);

	if (mb->mbxStatus != MBX_SUCCESS) {
		return (0);
	}

	vport = &VPORT((mb->un.varRegVpi.vpi - hba->vpi_base));
	vport->flag |= EMLXS_PORT_REG_VPI_CMPL;
	sbp = (emlxs_buf_t *)mbq->sbp;

	if (!sbp) {
		return (0);
	}

	pkt = PRIV2PKT(sbp);
	sp = (SERV_PARM *)((caddr_t)pkt->pkt_resp + sizeof (uint32_t));

	vport->VFIp->outstandingVPIs++;

	ldid = FABRIC_DID;
	ndlp = emlxs_node_find_did(vport, ldid);

	if (!ndlp) {
		/* Attempt to create a node */
		if ((ndlp = (NODELIST *)emlxs_mem_get(hba, MEM_NLP, 0))) {
			ndlp->nlp_Rpi = 0xffff;
			ndlp->nlp_DID = ldid;

			bcopy((uint8_t *)sp, (uint8_t *)&ndlp->sparm,
			    sizeof (SERV_PARM));

			bcopy((uint8_t *)&sp->nodeName,
			    (uint8_t *)&ndlp->nlp_nodename,
			    sizeof (NAME_TYPE));

			bcopy((uint8_t *)&sp->portName,
			    (uint8_t *)&ndlp->nlp_portname,
			    sizeof (NAME_TYPE));

			ndlp->nlp_active = 1;
			ndlp->nlp_flag[hba->channel_ct]  |= NLP_CLOSED;
			ndlp->nlp_flag[hba->channel_els] |= NLP_CLOSED;
			ndlp->nlp_flag[hba->channel_fcp] |= NLP_CLOSED;
			ndlp->nlp_flag[hba->channel_ip]  |= NLP_CLOSED;

			/* Add the node */
			emlxs_node_add(vport, ndlp);

			/* Open the node */
			emlxs_node_open(vport, ndlp, hba->channel_ct);
			emlxs_node_open(vport, ndlp, hba->channel_els);
			emlxs_node_open(vport, ndlp, hba->channel_ip);
			emlxs_node_open(vport, ndlp, hba->channel_fcp);
		} else {
			wwn = (uint8_t *)&sp->portName;
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_node_create_failed_msg,
			    "Unable to allocate node. did=%06x "
			    "wwpn=%02x%02x%02x%02x%02x%02x%02x%02x",
			    ldid, wwn[0], wwn[1], wwn[2],
			    wwn[3], wwn[4], wwn[5], wwn[6], wwn[7]);

			return (0);
		}
	} else {
		mutex_enter(&EMLXS_PORT_LOCK);

		ndlp->nlp_Rpi = 0xffff;
		ndlp->nlp_DID = ldid;

		bcopy((uint8_t *)sp,
		    (uint8_t *)&ndlp->sparm, sizeof (SERV_PARM));

		bcopy((uint8_t *)&sp->nodeName,
		    (uint8_t *)&ndlp->nlp_nodename, sizeof (NAME_TYPE));

		bcopy((uint8_t *)&sp->portName,
		    (uint8_t *)&ndlp->nlp_portname, sizeof (NAME_TYPE));

		wwn = (uint8_t *)&ndlp->nlp_portname;
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_update_msg,
		    "node=%p did=%06x rpi=%x "
		    "wwpn=%02x%02x%02x%02x%02x%02x%02x%02x",
		    ndlp, ndlp->nlp_DID, ndlp->nlp_Rpi, wwn[0],
		    wwn[1], wwn[2], wwn[3], wwn[4], wwn[5], wwn[6], wwn[7]);

		mutex_exit(&EMLXS_PORT_LOCK);

		/* Open the node */
		emlxs_node_open(vport, ndlp, hba->channel_ct);
		emlxs_node_open(vport, ndlp, hba->channel_els);
		emlxs_node_open(vport, ndlp, hba->channel_ip);
		emlxs_node_open(vport, ndlp, hba->channel_fcp);
	}

	return (0);
} /* emlxs_cmpl_reg_vpi */


extern uint32_t
emlxs_mb_reg_vpi(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	MAILBOXQ *mbq;
	MAILBOX	*mb;
	int rval;

	if (!(hba->flag & FC_NPIV_ENABLED)) {
		return (0);
	}

	mutex_enter(&EMLXS_PORT_LOCK);

	/* Can't reg vpi until ClearLA is sent */
	if (hba->state != FC_READY) {
		mutex_exit(&EMLXS_PORT_LOCK);

		return (1);
	}

	/* Must have port id */
	if (!port->did) {
		mutex_exit(&EMLXS_PORT_LOCK);

		return (1);
	}

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX, 1))) {
		mutex_exit(&EMLXS_PORT_LOCK);

		return (1);
	}

	port->flag |= EMLXS_PORT_REGISTERED;

	mutex_exit(&EMLXS_PORT_LOCK);

	mb = (MAILBOX *)mbq->mbox;

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);
		mbq->nonembed = NULL;
		mb->un.varRegVpi.vfi = port->VFIp->VFI;
		mbq->mbox_cmpl = emlxs_cmpl_reg_vpi;
	} else {
		bzero((void *)mb, MAILBOX_CMD_BSIZE);
		mbq->mbox_cmpl = NULL; /* no cmpl needed */
	}

	if (sbp) {
		mbq->sbp = (uint8_t *)sbp;
	}

	mb->un.varRegVpi.vpi = port->vpi + hba->vpi_base;
	mb->un.varRegVpi.sid = port->did;
	mb->mbxCommand = MBX_REG_VPI;
	mb->mbxOwner = OWN_HOST;

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbq);
	}

	return (0);

} /* emlxs_mb_reg_vpi() */


int
emlxs_cmpl_unreg_vpi(void *arg1, MAILBOXQ *mbq)
{
	emlxs_hba_t *hba = (emlxs_hba_t *)arg1;
	emlxs_port_t *vport;
	MAILBOX *mb;

	mb = (MAILBOX *)mbq;
	if (mb->mbxStatus == MBX_SUCCESS) {
		vport = &VPORT(mb->un.varUnregVpi.vpi);
		vport->flag &= ~EMLXS_PORT_INIT_VPI_CMPL;
		vport->flag &= ~EMLXS_PORT_REG_VPI_CMPL;
	}
	return (0);

} /* emlxs_cmpl_unreg_vpi() */


extern uint32_t
emlxs_mb_unreg_vpi(emlxs_port_t *port)
{
	emlxs_hba_t	*hba = HBA;
	MAILBOXQ	*mbq;
	MAILBOX		*mb;
	MAILBOX4	*mb4;
	VFIobj_t	*vfip;
	FCFIobj_t	*fcfp;
	int		rval;

	mutex_enter(&EMLXS_PORT_LOCK);

	if (!(port->flag & EMLXS_PORT_REGISTERED)) {
		mutex_exit(&EMLXS_PORT_LOCK);
		return (0);
	}

	if (!(mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX, 1))) {
		mutex_exit(&EMLXS_PORT_LOCK);
		return (1);
	}

	port->flag &= ~EMLXS_PORT_REGISTERED;

	mutex_exit(&EMLXS_PORT_LOCK);

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		mb4 = (MAILBOX4 *)mbq->mbox;
		bzero((void *)mb4, MAILBOX_CMD_SLI4_BSIZE);
		mb4->un.varUnRegVPI4.ii = 0; /* index is a VPI */
		mb4->un.varUnRegVPI4.index = port->vpi + hba->vpi_base;
		mb4->mbxCommand = MBX_UNREG_VPI;
		mb4->mbxOwner = OWN_HOST;
		mbq->mbox_cmpl = emlxs_cmpl_unreg_vpi;
	} else {
		mb = (MAILBOX *)mbq->mbox;
		bzero((void *)mb, MAILBOX_CMD_BSIZE);
		mb->un.varUnregVpi.vpi = port->vpi + hba->vpi_base;
		mb->mbxCommand = MBX_UNREG_VPI;
		mb->mbxOwner = OWN_HOST;
		mbq->mbox_cmpl = NULL; /* no cmpl needed */
	}

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_BUSY) && (rval != MBX_SUCCESS)) {
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbq);
	}

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		if ((vfip = port->VFIp) != NULL) {

			fcfp = vfip->FCFIp;
			if (port == fcfp->fcf_vpi) {
				fcfp->fcf_vpi = NULL;
			}

			mutex_enter(&EMLXS_PORT_LOCK);
			vfip->outstandingVPIs--;
			if ((vfip->outstandingVPIs == 0) &&
			    (hba->state == FC_LINK_DOWN)) {
				mutex_exit(&EMLXS_PORT_LOCK);

				/* No more VPIs so unreg the VFI */
				(void) emlxs_mb_unreg_vfi(hba, vfip);
			} else {
				mutex_exit(&EMLXS_PORT_LOCK);
			}
		}
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
#ifdef FMA_SUPPORT
	emlxs_port_t *port = &PPORT;
#endif	/* FMA_SUPPORT */
	MATCHMAP	*mp;

	HBASTATS.MboxIssued++;
	hba->mbox_queue_flag = flag;

	/* Set the Mailbox timer */
	hba->mbox_timer = hba->timer_tics + tmo;

	/* Initialize mailbox */
	mbq->flag &= MBQ_INIT_MASK;
	mbq->next = 0;

	mutex_enter(&EMLXS_MBOX_LOCK);
	hba->mbox_mbq = (uint8_t *)mbq;
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
	emlxs_ub_priv_t	*ub_priv;

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

	hba->mbox_mbq = 0;
	hba->mbox_queue_flag = 0;
	hba->mbox_timer = 0;
	mutex_exit(&EMLXS_MBOX_LOCK);

	mutex_exit(&EMLXS_PORT_LOCK);

	if (mbox_queue_flag == MBX_NOWAIT) {
		/* Check for deferred MBUF cleanup */
		if (mbox_bp) {
			(void) emlxs_mem_put(hba, MEM_BUF, (uint8_t *)mbox_bp);
		}
		if (mbox_nonembed) {
			(void) emlxs_mem_put(hba, MEM_BUF,
			    (uint8_t *)mbox_nonembed);
		}
		if (mbox_mbq) {
			(void) emlxs_mem_put(hba, MEM_MBOX,
			    (uint8_t *)mbox_mbq);
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
			mbox->mbxStatus = mbxStatus;

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

#ifdef SFCT_SUPPORT
	if (mb && mbox_sbp && mbox_sbp->fct_cmd) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_detail_msg,
		    "FCT mailbox: %s: status=%x",
		    emlxs_mb_cmd_xlate(mb->mbxCommand),
		    (uint32_t)mb->mbxStatus);
	}
#endif /* SFCT_SUPPORT */

	/* Check for deferred pkt completion */
	if (mbox_sbp) {
		if (mbxStatus != MBX_SUCCESS) {
			/* Set error status */
			mbox_sbp->pkt_flags &= ~PACKET_STATE_VALID;
			emlxs_set_pkt_state(mbox_sbp, IOSTAT_LOCAL_REJECT,
			    IOERR_NO_RESOURCES, 1);
		}

		emlxs_pkt_complete(mbox_sbp, -1, 0, 1);
	}

	/* Check for deferred ub completion */
	if (mbox_ubp) {
		ub_priv = mbox_ubp->ub_fca_private;
		port = ub_priv->port;

		emlxs_ub_callback(port, mbox_ubp);
	}

	/* Special handling for vport PLOGI */
	if (mbox_iocbq == (IOCBQ *)1) {
		mbox_iocbq = NULL;
	}

	/* Check for deferred iocb tx */
	if (mbox_iocbq) {
		/* Check for driver special codes */
		/* These indicate the mailbox is being flushed */
		if (mbxStatus >= MBX_DRIVER_RESERVED) {
			/* Set the error status and return it */
			mbox_iocbq->iocb.ULPSTATUS = IOSTAT_LOCAL_REJECT;
			mbox_iocbq->iocb.un.grsp.perr.statLocalError =
			    IOERR_ABORT_REQUESTED;

			emlxs_proc_channel_event(hba, mbox_iocbq->channel,
			    mbox_iocbq);
		} else {
			EMLXS_SLI_ISSUE_IOCB_CMD(hba, mbox_iocbq->channel,
			    mbox_iocbq);
		}
	}
	return;

} /* emlxs_mb_fini() */


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
		hba->mbox_mbq = (uint8_t *)mbq;
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

	(void) sprintf(buffer, "Cmd=0x%x", cmd);
	return (buffer);

} /* emlxs_mb_cmd_xlate() */
