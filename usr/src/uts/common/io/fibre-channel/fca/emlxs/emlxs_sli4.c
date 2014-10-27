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
EMLXS_MSG_DEF(EMLXS_SLI4_C);

static int		emlxs_sli4_init_extents(emlxs_hba_t *hba,
				MAILBOXQ *mbq);
static uint32_t		emlxs_sli4_read_status(emlxs_hba_t *hba);

static int		emlxs_init_bootstrap_mb(emlxs_hba_t *hba);

static uint32_t		emlxs_sli4_read_sema(emlxs_hba_t *hba);

static uint32_t		emlxs_sli4_read_mbdb(emlxs_hba_t *hba);

static void		emlxs_sli4_write_mbdb(emlxs_hba_t *hba, uint32_t value);

static void		emlxs_sli4_write_wqdb(emlxs_hba_t *hba, uint32_t value);

static void		emlxs_sli4_write_mqdb(emlxs_hba_t *hba, uint32_t value);

static void		emlxs_sli4_write_rqdb(emlxs_hba_t *hba, uint32_t value);

static void		emlxs_sli4_write_cqdb(emlxs_hba_t *hba, uint32_t value);

static int		emlxs_sli4_create_queues(emlxs_hba_t *hba,
				MAILBOXQ *mbq);
static int		emlxs_sli4_post_hdr_tmplates(emlxs_hba_t *hba,
				MAILBOXQ *mbq);
static int		emlxs_sli4_post_sgl_pages(emlxs_hba_t *hba,
				MAILBOXQ *mbq);

static int		emlxs_sli4_read_eq(emlxs_hba_t *hba, EQ_DESC_t *eq);

static int		emlxs_sli4_map_hdw(emlxs_hba_t *hba);

static void		emlxs_sli4_unmap_hdw(emlxs_hba_t *hba);

static int32_t		emlxs_sli4_online(emlxs_hba_t *hba);

static void		emlxs_sli4_offline(emlxs_hba_t *hba,
				uint32_t reset_requested);

static uint32_t		emlxs_sli4_hba_reset(emlxs_hba_t *hba, uint32_t restart,
				uint32_t skip_post, uint32_t quiesce);
static void		emlxs_sli4_hba_kill(emlxs_hba_t *hba);

static uint32_t		emlxs_sli4_hba_init(emlxs_hba_t *hba);

static uint32_t		emlxs_sli4_bde_setup(emlxs_port_t *port,
				emlxs_buf_t *sbp);

static void		emlxs_sli4_issue_iocb_cmd(emlxs_hba_t *hba,
				CHANNEL *cp, IOCBQ *iocb_cmd);
static uint32_t		emlxs_sli4_issue_mbox_cmd(emlxs_hba_t *hba,
				MAILBOXQ *mbq, int32_t flg, uint32_t tmo);
static uint32_t		emlxs_sli4_issue_mbox_cmd4quiesce(emlxs_hba_t *hba,
				MAILBOXQ *mbq, int32_t flg, uint32_t tmo);
#ifdef SFCT_SUPPORT
static uint32_t		emlxs_sli4_prep_fct_iocb(emlxs_port_t *port,
				emlxs_buf_t *cmd_sbp, int channel);
static uint32_t		emlxs_sli4_fct_bde_setup(emlxs_port_t *port,
				emlxs_buf_t *sbp);
#endif /* SFCT_SUPPORT */

static uint32_t		emlxs_sli4_prep_fcp_iocb(emlxs_port_t *port,
				emlxs_buf_t *sbp, int ring);
static uint32_t		emlxs_sli4_prep_ip_iocb(emlxs_port_t *port,
				emlxs_buf_t *sbp);
static uint32_t		emlxs_sli4_prep_els_iocb(emlxs_port_t *port,
				emlxs_buf_t *sbp);
static uint32_t		emlxs_sli4_prep_ct_iocb(emlxs_port_t *port,
				emlxs_buf_t *sbp);
static void		emlxs_sli4_poll_intr(emlxs_hba_t *hba);
static int32_t		emlxs_sli4_intx_intr(char *arg);

#ifdef MSI_SUPPORT
static uint32_t		emlxs_sli4_msi_intr(char *arg1, char *arg2);
#endif /* MSI_SUPPORT */

static void		emlxs_sli4_resource_free(emlxs_hba_t *hba);

static int		emlxs_sli4_resource_alloc(emlxs_hba_t *hba);
extern void		emlxs_sli4_zero_queue_stat(emlxs_hba_t *hba);

static XRIobj_t		*emlxs_sli4_alloc_xri(emlxs_port_t *port,
				emlxs_buf_t *sbp, RPIobj_t *rpip,
				uint32_t type);
static void		emlxs_sli4_enable_intr(emlxs_hba_t *hba);

static void		emlxs_sli4_disable_intr(emlxs_hba_t *hba, uint32_t att);

static void		emlxs_sli4_timer(emlxs_hba_t *hba);

static void		emlxs_sli4_timer_check_mbox(emlxs_hba_t *hba);

static void		emlxs_sli4_poll_erratt(emlxs_hba_t *hba);

extern XRIobj_t 	*emlxs_sli4_reserve_xri(emlxs_port_t *port,
				RPIobj_t *rpip, uint32_t type, uint16_t rx_id);
static int		emlxs_check_hdw_ready(emlxs_hba_t *);

static uint32_t		emlxs_sli4_reg_did(emlxs_port_t *port,
				uint32_t did, SERV_PARM *param,
				emlxs_buf_t *sbp, fc_unsol_buf_t *ubp,
				IOCBQ *iocbq);

static uint32_t		emlxs_sli4_unreg_node(emlxs_port_t *port,
				emlxs_node_t *node, emlxs_buf_t *sbp,
				fc_unsol_buf_t *ubp, IOCBQ *iocbq);

static void		emlxs_sli4_handle_fc_link_att(emlxs_hba_t *hba,
				CQE_ASYNC_t *cqe);
static void		emlxs_sli4_handle_fcoe_link_event(emlxs_hba_t *hba,
				CQE_ASYNC_t *cqe);


static uint16_t		emlxs_sli4_rqid_to_index(emlxs_hba_t *hba,
				uint16_t rqid);
static uint16_t		emlxs_sli4_wqid_to_index(emlxs_hba_t *hba,
				uint16_t wqid);
static uint16_t		emlxs_sli4_cqid_to_index(emlxs_hba_t *hba,
				uint16_t cqid);

/* Define SLI4 API functions */
emlxs_sli_api_t emlxs_sli4_api = {
	emlxs_sli4_map_hdw,
	emlxs_sli4_unmap_hdw,
	emlxs_sli4_online,
	emlxs_sli4_offline,
	emlxs_sli4_hba_reset,
	emlxs_sli4_hba_kill,
	emlxs_sli4_issue_iocb_cmd,
	emlxs_sli4_issue_mbox_cmd,
#ifdef SFCT_SUPPORT
	emlxs_sli4_prep_fct_iocb,
#else
	NULL,
#endif /* SFCT_SUPPORT */
	emlxs_sli4_prep_fcp_iocb,
	emlxs_sli4_prep_ip_iocb,
	emlxs_sli4_prep_els_iocb,
	emlxs_sli4_prep_ct_iocb,
	emlxs_sli4_poll_intr,
	emlxs_sli4_intx_intr,
	emlxs_sli4_msi_intr,
	emlxs_sli4_disable_intr,
	emlxs_sli4_timer,
	emlxs_sli4_poll_erratt,
	emlxs_sli4_reg_did,
	emlxs_sli4_unreg_node
};


/* ************************************************************************** */

static void
emlxs_sli4_set_default_params(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;

	bzero((char *)&hba->sli.sli4.param, sizeof (sli_params_t));

	hba->sli.sli4.param.ProtocolType = 0x3; /* FC/FCoE */

	hba->sli.sli4.param.SliHint2 = 0;
	hba->sli.sli4.param.SliHint1 = 0;
	hba->sli.sli4.param.IfType = 0;
	hba->sli.sli4.param.SliFamily = 0;
	hba->sli.sli4.param.Revision = 0x4; /* SLI4 */
	hba->sli.sli4.param.FT = 0;

	hba->sli.sli4.param.EqeCntMethod = 0x1; /* Bit pattern */
	hba->sli.sli4.param.EqPageSize = 0x1; /* 4096 */
	hba->sli.sli4.param.EqeSize = 0x1; /* 4 byte */
	hba->sli.sli4.param.EqPageCnt = 8;
	hba->sli.sli4.param.EqeCntMask = 0x1F; /* 256-4096 elements */

	hba->sli.sli4.param.CqeCntMethod = 0x1; /* Bit pattern */
	hba->sli.sli4.param.CqPageSize = 0x1; /* 4096 */
	hba->sli.sli4.param.CQV = 0;
	hba->sli.sli4.param.CqeSize = 0x3; /* 16 byte */
	hba->sli.sli4.param.CqPageCnt = 4;
	hba->sli.sli4.param.CqeCntMask = 0x70; /* 256-1024 elements */

	hba->sli.sli4.param.MqeCntMethod = 0x1; /* Bit pattern */
	hba->sli.sli4.param.MqPageSize = 0x1; /* 4096 */
	hba->sli.sli4.param.MQV = 0;
	hba->sli.sli4.param.MqPageCnt = 8;
	hba->sli.sli4.param.MqeCntMask = 0x0F; /* 16-128 elements */

	hba->sli.sli4.param.WqeCntMethod = 0; /* Page Count */
	hba->sli.sli4.param.WqPageSize = 0x1; /* 4096 */
	hba->sli.sli4.param.WQV = 0;
	hba->sli.sli4.param.WqeSize = 0x5; /* 64 byte */
	hba->sli.sli4.param.WqPageCnt = 4;
	hba->sli.sli4.param.WqeCntMask = 0x10; /* 256 elements */

	hba->sli.sli4.param.RqeCntMethod = 0; /* Page Count */
	hba->sli.sli4.param.RqPageSize = 0x1; /* 4096 */
	hba->sli.sli4.param.RQV = 0;
	hba->sli.sli4.param.RqeSize = 0x2; /* 8 byte */
	hba->sli.sli4.param.RqPageCnt = 8;
	hba->sli.sli4.param.RqDbWin = 1;
	hba->sli.sli4.param.RqeCntMask = 0x100; /* 4096 elements */

	hba->sli.sli4.param.Loopback = 0xf; /* unsupported */
	hba->sli.sli4.param.PHWQ = 0;
	hba->sli.sli4.param.PHON = 0;
	hba->sli.sli4.param.TRIR = 0;
	hba->sli.sli4.param.TRTY = 0;
	hba->sli.sli4.param.TCCA = 0;
	hba->sli.sli4.param.MWQE = 0;
	hba->sli.sli4.param.ASSI = 0;
	hba->sli.sli4.param.TERP = 0;
	hba->sli.sli4.param.TGT  = 0;
	hba->sli.sli4.param.AREG = 0;
	hba->sli.sli4.param.FBRR = 0;
	hba->sli.sli4.param.SGLR = 1;
	hba->sli.sli4.param.HDRR = 1;
	hba->sli.sli4.param.EXT  = 0;
	hba->sli.sli4.param.FCOE = 1;

	hba->sli.sli4.param.SgeLength = (64 * 1024);
	hba->sli.sli4.param.SglAlign = 0x7 /* 4096 */;
	hba->sli.sli4.param.SglPageSize = 0x1; /* 4096 */
	hba->sli.sli4.param.SglPageCnt = 2;

	hba->sli.sli4.param.MinRqSize = 128;
	hba->sli.sli4.param.MaxRqSize = 2048;

	hba->sli.sli4.param.RPIMax = 0x3ff;
	hba->sli.sli4.param.XRIMax = 0x3ff;
	hba->sli.sli4.param.VFIMax = 0xff;
	hba->sli.sli4.param.VPIMax = 0xff;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
	    "Default SLI4 parameters set.");

} /* emlxs_sli4_set_default_params() */


/*
 * emlxs_sli4_online()
 *
 * This routine will start initialization of the SLI4 HBA.
 */
static int32_t
emlxs_sli4_online(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg;
	emlxs_vpd_t *vpd;
	MAILBOXQ *mbq = NULL;
	MAILBOX4 *mb  = NULL;
	MATCHMAP *mp  = NULL;
	uint32_t i;
	uint32_t j;
	uint32_t rval = 0;
	uint8_t *vpd_data;
	uint32_t sli_mode;
	uint8_t *outptr;
	uint32_t status;
	uint32_t fw_check;
	uint32_t kern_update = 0;
	emlxs_firmware_t hba_fw;
	emlxs_firmware_t *fw;
	uint16_t ssvid;
	char buf[64];

	cfg = &CFG;
	vpd = &VPD;

	sli_mode = EMLXS_HBA_SLI4_MODE;
	hba->sli_mode = sli_mode;

	/* Set the fw_check flag */
	fw_check = cfg[CFG_FW_CHECK].current;

	if ((fw_check & 0x04) ||
	    (hba->fw_flag & FW_UPDATE_KERNEL)) {
		kern_update = 1;
	}

	hba->mbox_queue_flag = 0;
	hba->fc_edtov = FF_DEF_EDTOV;
	hba->fc_ratov = FF_DEF_RATOV;
	hba->fc_altov = FF_DEF_ALTOV;
	hba->fc_arbtov = FF_DEF_ARBTOV;

	/* Networking not supported */
	if (cfg[CFG_NETWORK_ON].current) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
		    "Networking is not supported in SLI4, turning it off");
		cfg[CFG_NETWORK_ON].current = 0;
	}

	hba->chan_count = hba->intr_count * cfg[CFG_NUM_WQ].current;
	if (hba->chan_count > MAX_CHANNEL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Max channels exceeded, dropping num-wq from %d to 1",
		    cfg[CFG_NUM_WQ].current);
		cfg[CFG_NUM_WQ].current = 1;
		hba->chan_count = hba->intr_count * cfg[CFG_NUM_WQ].current;
	}
	hba->channel_fcp = 0; /* First channel */

	/* Default channel for everything else is the last channel */
	hba->channel_ip = hba->chan_count - 1;
	hba->channel_els = hba->chan_count - 1;
	hba->channel_ct = hba->chan_count - 1;

	hba->fc_iotag = 1;
	hba->io_count = 0;
	hba->channel_tx_count = 0;

	/* Initialize the local dump region buffer */
	bzero(&hba->sli.sli4.dump_region, sizeof (MBUF_INFO));
	hba->sli.sli4.dump_region.size = EMLXS_DUMP_REGION_SIZE;
	hba->sli.sli4.dump_region.flags = FC_MBUF_DMA | FC_MBUF_SNGLSG
	    | FC_MBUF_DMA32;
	hba->sli.sli4.dump_region.align = ddi_ptob(hba->dip, 1L);

	(void) emlxs_mem_alloc(hba, &hba->sli.sli4.dump_region);

	if (hba->sli.sli4.dump_region.virt == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to allocate dump region buffer.");

		return (ENOMEM);
	}

	/*
	 * Get a buffer which will be used repeatedly for mailbox commands
	 */
	mbq = (MAILBOXQ *) kmem_zalloc((sizeof (MAILBOXQ)), KM_SLEEP);

	mb = (MAILBOX4 *)mbq;

reset:
	/* Reset & Initialize the adapter */
	if (emlxs_sli4_hba_init(hba)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to init hba.");

		rval = EIO;
		goto failed1;
	}

#ifdef FMA_SUPPORT
	/* Access handle validation */
	switch (hba->sli_intf & SLI_INTF_IF_TYPE_MASK) {
	case SLI_INTF_IF_TYPE_2:
		if ((emlxs_fm_check_acc_handle(hba,
		    hba->pci_acc_handle) != DDI_FM_OK) ||
		    (emlxs_fm_check_acc_handle(hba,
		    hba->sli.sli4.bar0_acc_handle) != DDI_FM_OK)) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_invalid_access_handle_msg, NULL);

			rval = EIO;
			goto failed1;
		}
		break;

	default :
		if ((emlxs_fm_check_acc_handle(hba,
		    hba->pci_acc_handle) != DDI_FM_OK) ||
		    (emlxs_fm_check_acc_handle(hba,
		    hba->sli.sli4.bar1_acc_handle) != DDI_FM_OK) ||
		    (emlxs_fm_check_acc_handle(hba,
		    hba->sli.sli4.bar2_acc_handle) != DDI_FM_OK)) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_invalid_access_handle_msg, NULL);

			rval = EIO;
			goto failed1;
		}
		break;
	}
#endif	/* FMA_SUPPORT */

	/*
	 * Setup and issue mailbox READ REV command
	 */
	vpd->opFwRev = 0;
	vpd->postKernRev = 0;
	vpd->sli1FwRev = 0;
	vpd->sli2FwRev = 0;
	vpd->sli3FwRev = 0;
	vpd->sli4FwRev = 0;

	vpd->postKernName[0] = 0;
	vpd->opFwName[0] = 0;
	vpd->sli1FwName[0] = 0;
	vpd->sli2FwName[0] = 0;
	vpd->sli3FwName[0] = 0;
	vpd->sli4FwName[0] = 0;

	vpd->opFwLabel[0] = 0;
	vpd->sli1FwLabel[0] = 0;
	vpd->sli2FwLabel[0] = 0;
	vpd->sli3FwLabel[0] = 0;
	vpd->sli4FwLabel[0] = 0;

	EMLXS_STATE_CHANGE(hba, FC_INIT_REV);

	emlxs_mb_get_sli4_params(hba, mbq);
	if (emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Unable to read parameters. Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		/* Set param defaults */
		emlxs_sli4_set_default_params(hba);

	} else {
		/* Save parameters */
		bcopy((char *)&mb->un.varSLIConfig.payload,
		    (char *)&hba->sli.sli4.param, sizeof (sli_params_t));

		emlxs_data_dump(port, "SLI_PARMS",
		    (uint32_t *)&hba->sli.sli4.param,
		    sizeof (sli_params_t), 0);
	}

	/* Reuse mbq from previous mbox */
	bzero(mbq, sizeof (MAILBOXQ));

	emlxs_mb_get_port_name(hba, mbq);
	if (emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Unable to get port names. Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		bzero(hba->sli.sli4.port_name,
		    sizeof (hba->sli.sli4.port_name));
	} else {
		/* Save port names */
		bcopy((char *)&mb->un.varSLIConfig.payload,
		    (char *)&hba->sli.sli4.port_name,
		    sizeof (hba->sli.sli4.port_name));
	}

	/* Reuse mbq from previous mbox */
	bzero(mbq, sizeof (MAILBOXQ));

	emlxs_mb_read_rev(hba, mbq, 0);
	if (emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to read rev. Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		rval = EIO;
		goto failed1;

	}

	emlxs_data_dump(port, "RD_REV", (uint32_t *)mb, 18, 0);
	if (mb->un.varRdRev4.sliLevel != 4) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Invalid read rev Version for SLI4: 0x%x",
		    mb->un.varRdRev4.sliLevel);

		rval = EIO;
		goto failed1;
	}

	switch (mb->un.varRdRev4.dcbxMode) {
	case EMLXS_DCBX_MODE_CIN:	/* Mapped to nonFIP mode */
		hba->flag &= ~FC_FIP_SUPPORTED;
		break;

	case EMLXS_DCBX_MODE_CEE:	/* Mapped to FIP mode */
		hba->flag |= FC_FIP_SUPPORTED;
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Invalid read rev dcbx mode for SLI4: 0x%x",
		    mb->un.varRdRev4.dcbxMode);

		rval = EIO;
		goto failed1;
	}

	/* Set FC/FCoE mode */
	if (mb->un.varRdRev4.FCoE) {
		hba->sli.sli4.flag |= EMLXS_SLI4_FCOE_MODE;
	} else {
		hba->sli.sli4.flag &= ~EMLXS_SLI4_FCOE_MODE;
	}

	/* Save information as VPD data */
	vpd->rBit = 1;

	vpd->sli4FwRev = (mb->un.varRdRev4.ULPFwId);
	bcopy((char *)mb->un.varRdRev4.ULPFwName, vpd->sli4FwName, 16);

	vpd->opFwRev = (mb->un.varRdRev4.ULPFwId);
	bcopy((char *)mb->un.varRdRev4.ULPFwName, vpd->opFwName, 16);

	vpd->postKernRev = (mb->un.varRdRev4.ARMFwId);
	bcopy((char *)mb->un.varRdRev4.ARMFwName, vpd->postKernName, 16);

	vpd->biuRev = mb->un.varRdRev4.HwRev1;
	vpd->fcphHigh = mb->un.varRdRev4.fcphHigh;
	vpd->fcphLow = mb->un.varRdRev4.fcphLow;
	vpd->feaLevelHigh = mb->un.varRdRev4.feaLevelHigh;
	vpd->feaLevelLow = mb->un.varRdRev4.feaLevelLow;

	/* Decode FW labels */
	if (hba->model_info.chip == EMLXS_LANCER_CHIP) {
		bcopy(vpd->postKernName, vpd->sli4FwName, 16);
	}
	emlxs_decode_label(vpd->sli4FwName, vpd->sli4FwName, 0,
	    sizeof (vpd->sli4FwName));
	emlxs_decode_label(vpd->opFwName, vpd->opFwName, 0,
	    sizeof (vpd->opFwName));
	emlxs_decode_label(vpd->postKernName, vpd->postKernName, 0,
	    sizeof (vpd->postKernName));

	if (hba->model_info.chip == EMLXS_BE2_CHIP) {
		(void) strlcpy(vpd->sli4FwLabel, "be2.ufi",
		    sizeof (vpd->sli4FwLabel));
	} else if (hba->model_info.chip == EMLXS_BE3_CHIP) {
		(void) strlcpy(vpd->sli4FwLabel, "be3.ufi",
		    sizeof (vpd->sli4FwLabel));
	} else if (hba->model_info.chip == EMLXS_LANCER_CHIP) {
		(void) strlcpy(vpd->sli4FwLabel, "xe201.grp",
		    sizeof (vpd->sli4FwLabel));
	} else {
		(void) strlcpy(vpd->sli4FwLabel, "sli4.fw",
		    sizeof (vpd->sli4FwLabel));
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "VPD ULP:%08x %s ARM:%08x %s f:%d %d %d %d : dcbx %d",
	    vpd->opFwRev, vpd->opFwName, vpd->postKernRev, vpd->postKernName,
	    vpd->fcphHigh, vpd->fcphLow, vpd->feaLevelHigh, vpd->feaLevelLow,
	    mb->un.varRdRev4.dcbxMode);

	/* No key information is needed for SLI4 products */

	/* Get adapter VPD information */
	vpd->port_index = (uint32_t)-1;

	/* Reuse mbq from previous mbox */
	bzero(mbq, sizeof (MAILBOXQ));

	emlxs_mb_dump_vpd(hba, mbq, 0);
	vpd_data = hba->sli.sli4.dump_region.virt;

	if (emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) !=
	    MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "No VPD found. status=%x", mb->mbxStatus);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_init_debug_msg,
		    "VPD dumped. rsp_cnt=%d status=%x",
		    mb->un.varDmp4.rsp_cnt, mb->mbxStatus);

		if (mb->un.varDmp4.rsp_cnt) {
			EMLXS_MPDATA_SYNC(hba->sli.sli4.dump_region.dma_handle,
			    0, mb->un.varDmp4.rsp_cnt, DDI_DMA_SYNC_FORKERNEL);

#ifdef FMA_SUPPORT
			if (hba->sli.sli4.dump_region.dma_handle) {
				if (emlxs_fm_check_dma_handle(hba,
				    hba->sli.sli4.dump_region.dma_handle)
				    != DDI_FM_OK) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_invalid_dma_handle_msg,
					    "sli4_online: hdl=%p",
					    hba->sli.sli4.dump_region.
					    dma_handle);
					rval = EIO;
					goto failed1;
				}
			}
#endif /* FMA_SUPPORT */

		}
	}

	if (vpd_data[0]) {
		(void) emlxs_parse_vpd(hba, (uint8_t *)vpd_data,
		    mb->un.varDmp4.rsp_cnt);

		/*
		 * If there is a VPD part number, and it does not
		 * match the current default HBA model info,
		 * replace the default data with an entry that
		 * does match.
		 *
		 * After emlxs_parse_vpd model holds the VPD value
		 * for V2 and part_num hold the value for PN. These
		 * 2 values are NOT necessarily the same.
		 */

		rval = 0;
		if ((vpd->model[0] != 0) &&
		    (strcmp(&vpd->model[0], hba->model_info.model) != 0)) {

			/* First scan for a V2 match */

			for (i = 1; i < emlxs_pci_model_count; i++) {
				if (strcmp(&vpd->model[0],
				    emlxs_pci_model[i].model) == 0) {
					bcopy(&emlxs_pci_model[i],
					    &hba->model_info,
					    sizeof (emlxs_model_t));
					rval = 1;
					break;
				}
			}
		}

		if (!rval && (vpd->part_num[0] != 0) &&
		    (strcmp(&vpd->part_num[0], hba->model_info.model) != 0)) {

			/* Next scan for a PN match */

			for (i = 1; i < emlxs_pci_model_count; i++) {
				if (strcmp(&vpd->part_num[0],
				    emlxs_pci_model[i].model) == 0) {
					bcopy(&emlxs_pci_model[i],
					    &hba->model_info,
					    sizeof (emlxs_model_t));
					break;
				}
			}
		}

		/* HP CNA port indices start at 1 instead of 0 */
		if (hba->model_info.chip & EMLXS_BE_CHIPS) {
			ssvid = ddi_get16(hba->pci_acc_handle,
			    (uint16_t *)(hba->pci_addr + PCI_SSVID_REGISTER));

			if ((ssvid == PCI_SSVID_HP) && (vpd->port_index > 0)) {
				vpd->port_index--;
			}
		}

		/*
		 * Now lets update hba->model_info with the real
		 * VPD data, if any.
		 */

		/*
		 * Replace the default model description with vpd data
		 */
		if (vpd->model_desc[0] != 0) {
			(void) strncpy(hba->model_info.model_desc,
			    vpd->model_desc,
			    (sizeof (hba->model_info.model_desc)-1));
		}

		/* Replace the default model with vpd data */
		if (vpd->model[0] != 0) {
			(void) strncpy(hba->model_info.model, vpd->model,
			    (sizeof (hba->model_info.model)-1));
		}

		/* Replace the default program types with vpd data */
		if (vpd->prog_types[0] != 0) {
			emlxs_parse_prog_types(hba, vpd->prog_types);
		}
	}

	/*
	 * Since the adapter model may have changed with the vpd data
	 * lets double check if adapter is not supported
	 */
	if (hba->model_info.flags & EMLXS_NOT_SUPPORTED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unsupported adapter found.  "
		    "Id:%d  Device id:0x%x  SSDID:0x%x  Model:%s",
		    hba->model_info.id, hba->model_info.device_id,
		    hba->model_info.ssdid, hba->model_info.model);

		rval = EIO;
		goto failed1;
	}

	(void) strncpy(vpd->boot_version, vpd->sli4FwName,
	    (sizeof (vpd->boot_version)-1));

	/* Get fcode version property */
	emlxs_get_fcode_version(hba);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
	    "Firmware: kern=%08x stub=%08x sli1=%08x", vpd->postKernRev,
	    vpd->opFwRev, vpd->sli1FwRev);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
	    "Firmware: sli2=%08x sli3=%08x sli4=%08x fl=%x", vpd->sli2FwRev,
	    vpd->sli3FwRev, vpd->sli4FwRev, vpd->feaLevelHigh);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
	    "BIOS: boot=%s fcode=%s", vpd->boot_version, vpd->fcode_version);

	/*
	 * If firmware checking is enabled and the adapter model indicates
	 * a firmware image, then perform firmware version check
	 */
	hba->fw_flag = 0;
	hba->fw_timer = 0;

	if (((fw_check & 0x1) &&
	    (hba->model_info.flags & EMLXS_ORACLE_BRANDED) &&
	    hba->model_info.fwid) ||
	    ((fw_check & 0x2) && hba->model_info.fwid)) {

		/* Find firmware image indicated by adapter model */
		fw = NULL;
		for (i = 0; i < emlxs_fw_count; i++) {
			if (emlxs_fw_table[i].id == hba->model_info.fwid) {
				fw = &emlxs_fw_table[i];
				break;
			}
		}

		/*
		 * If the image was found, then verify current firmware
		 * versions of adapter
		 */
		if (fw) {
			/* Obtain current firmware version info */
			if (hba->model_info.chip & EMLXS_BE_CHIPS) {
				(void) emlxs_be_read_fw_version(hba, &hba_fw);
			} else {
				hba_fw.kern = vpd->postKernRev;
				hba_fw.stub = vpd->opFwRev;
				hba_fw.sli1 = vpd->sli1FwRev;
				hba_fw.sli2 = vpd->sli2FwRev;
				hba_fw.sli3 = vpd->sli3FwRev;
				hba_fw.sli4 = vpd->sli4FwRev;
			}

			if (!kern_update &&
			    ((fw->kern && (hba_fw.kern != fw->kern)) ||
			    (fw->stub && (hba_fw.stub != fw->stub)))) {

				hba->fw_flag |= FW_UPDATE_NEEDED;

			} else if ((fw->kern && (hba_fw.kern != fw->kern)) ||
			    (fw->stub && (hba_fw.stub != fw->stub)) ||
			    (fw->sli1 && (hba_fw.sli1 != fw->sli1)) ||
			    (fw->sli2 && (hba_fw.sli2 != fw->sli2)) ||
			    (fw->sli3 && (hba_fw.sli3 != fw->sli3)) ||
			    (fw->sli4 && (hba_fw.sli4 != fw->sli4))) {

				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
				    "Firmware update needed. "
				    "Updating. id=%d fw=%d",
				    hba->model_info.id, hba->model_info.fwid);

#ifdef MODFW_SUPPORT
				/*
				 * Load the firmware image now
				 * If MODFW_SUPPORT is not defined, the
				 * firmware image will already be defined
				 * in the emlxs_fw_table
				 */
				emlxs_fw_load(hba, fw);
#endif /* MODFW_SUPPORT */

				if (fw->image && fw->size) {
					uint32_t rc;

					rc = emlxs_fw_download(hba,
					    (char *)fw->image, fw->size, 0);
					if ((rc != FC_SUCCESS) &&
					    (rc != EMLXS_REBOOT_REQUIRED)) {
						EMLXS_MSGF(EMLXS_CONTEXT,
						    &emlxs_init_msg,
						    "Firmware update failed.");
						hba->fw_flag |=
						    FW_UPDATE_NEEDED;
					}
#ifdef MODFW_SUPPORT
					/*
					 * Unload the firmware image from
					 * kernel memory
					 */
					emlxs_fw_unload(hba, fw);
#endif /* MODFW_SUPPORT */

					fw_check = 0;

					goto reset;
				}

				hba->fw_flag |= FW_UPDATE_NEEDED;

				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
				    "Firmware image unavailable.");
			} else {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
				    "Firmware update not needed.");
			}
		} else {
			/*
			 * This means either the adapter database is not
			 * correct or a firmware image is missing from the
			 * compile
			 */
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
			    "Firmware image unavailable. id=%d fw=%d",
			    hba->model_info.id, hba->model_info.fwid);
		}
	}

	/* Reuse mbq from previous mbox */
	bzero(mbq, sizeof (MAILBOXQ));

	emlxs_mb_dump_fcoe(hba, mbq, 0);

	if (emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) !=
	    MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "No FCOE info found. status=%x", mb->mbxStatus);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_init_debug_msg,
		    "FCOE info dumped. rsp_cnt=%d status=%x",
		    mb->un.varDmp4.rsp_cnt, mb->mbxStatus);
		(void) emlxs_parse_fcoe(hba,
		    (uint8_t *)hba->sli.sli4.dump_region.virt,
		    mb->un.varDmp4.rsp_cnt);
	}

	/* Reuse mbq from previous mbox */
	bzero(mbq, sizeof (MAILBOXQ));

	status = 0;
	if (port->flag & EMLXS_INI_ENABLED) {
		status |= SLI4_FEATURE_FCP_INITIATOR;
	}
	if (port->flag & EMLXS_TGT_ENABLED) {
		status |= SLI4_FEATURE_FCP_TARGET;
	}
	if (cfg[CFG_NPIV_ENABLE].current) {
		status |= SLI4_FEATURE_NPIV;
	}
	if (cfg[CFG_RQD_MODE].current) {
		status |= SLI4_FEATURE_RQD;
	}
	if (cfg[CFG_PERF_HINT].current) {
		if (hba->sli.sli4.param.PHON) {
			status |= SLI4_FEATURE_PERF_HINT;
		}
	}

	emlxs_mb_request_features(hba, mbq, status);

	if (emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to REQUEST_FEATURES. Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		rval = EIO;
		goto failed1;
	}
	emlxs_data_dump(port, "REQ_FEATURE", (uint32_t *)mb, 6, 0);

	/* Check to see if we get the features we requested */
	if (status != mb->un.varReqFeatures.featuresEnabled) {

		/* Just report descrepencies, don't abort the attach */

		outptr = (uint8_t *)emlxs_request_feature_xlate(
		    mb->un.varReqFeatures.featuresRequested);
		(void) strlcpy(buf, (char *)outptr, sizeof (buf));

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "REQUEST_FEATURES: wanted:%s  got:%s",
		    &buf[0], emlxs_request_feature_xlate(
		    mb->un.varReqFeatures.featuresEnabled));

	}

	if ((port->flag & EMLXS_INI_ENABLED) &&
	    !(mb->un.varReqFeatures.featuresEnabled &
	    SLI4_FEATURE_FCP_INITIATOR)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Initiator mode not supported by adapter.");

		rval = EIO;

#ifdef SFCT_SUPPORT
		/* Check if we can fall back to just target mode */
		if ((hba->pm_state == EMLXS_PM_IN_ATTACH) &&
		    (mb->un.varReqFeatures.featuresEnabled &
		    SLI4_FEATURE_FCP_TARGET) &&
		    (cfg[CFG_DTM_ENABLE].current == 1) &&
		    (cfg[CFG_TARGET_MODE].current == 1)) {

			cfg[CFG_DTM_ENABLE].current = 0;

			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_init_failed_msg,
			    "Disabling dynamic target mode. "
			    "Enabling target mode only.");

			/* This will trigger the driver to reattach */
			rval = EAGAIN;
		}
#endif /* SFCT_SUPPORT */
		goto failed1;
	}

	if ((port->flag & EMLXS_TGT_ENABLED) &&
	    !(mb->un.varReqFeatures.featuresEnabled &
	    SLI4_FEATURE_FCP_TARGET)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Target mode not supported by adapter.");

		rval = EIO;

#ifdef SFCT_SUPPORT
		/* Check if we can fall back to just initiator mode */
		if ((hba->pm_state == EMLXS_PM_IN_ATTACH) &&
		    (mb->un.varReqFeatures.featuresEnabled &
		    SLI4_FEATURE_FCP_INITIATOR) &&
		    (cfg[CFG_DTM_ENABLE].current == 1) &&
		    (cfg[CFG_TARGET_MODE].current == 0)) {

			cfg[CFG_DTM_ENABLE].current = 0;

			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_init_failed_msg,
			    "Disabling dynamic target mode. "
			    "Enabling initiator mode only.");

			/* This will trigger the driver to reattach */
			rval = EAGAIN;
		}
#endif /* SFCT_SUPPORT */
		goto failed1;
	}

	if (mb->un.varReqFeatures.featuresEnabled & SLI4_FEATURE_NPIV) {
		hba->flag |= FC_NPIV_ENABLED;
	}

	if (mb->un.varReqFeatures.featuresEnabled & SLI4_FEATURE_PERF_HINT) {
		hba->sli.sli4.flag |= EMLXS_SLI4_PHON;
		if (hba->sli.sli4.param.PHWQ) {
			hba->sli.sli4.flag |= EMLXS_SLI4_PHWQ;
		}
	}

	/* Reuse mbq from previous mbox */
	bzero(mbq, sizeof (MAILBOXQ));

	emlxs_mb_read_config(hba, mbq);
	if (emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to READ_CONFIG. Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		rval = EIO;
		goto failed1;
	}
	emlxs_data_dump(port, "READ_CONFIG4", (uint32_t *)mb, 18, 0);

	/* Set default extents */
	hba->sli.sli4.XRICount = mb->un.varRdConfig4.XRICount;
	hba->sli.sli4.XRIExtCount = 1;
	hba->sli.sli4.XRIExtSize = hba->sli.sli4.XRICount;
	hba->sli.sli4.XRIBase[0] = mb->un.varRdConfig4.XRIBase;

	hba->sli.sli4.RPICount = mb->un.varRdConfig4.RPICount;
	hba->sli.sli4.RPIExtCount = 1;
	hba->sli.sli4.RPIExtSize = hba->sli.sli4.RPICount;
	hba->sli.sli4.RPIBase[0] = mb->un.varRdConfig4.RPIBase;

	hba->sli.sli4.VPICount = mb->un.varRdConfig4.VPICount;
	hba->sli.sli4.VPIExtCount = 1;
	hba->sli.sli4.VPIExtSize = hba->sli.sli4.VPICount;
	hba->sli.sli4.VPIBase[0] = mb->un.varRdConfig4.VPIBase;

	hba->sli.sli4.VFICount = mb->un.varRdConfig4.VFICount;
	hba->sli.sli4.VFIExtCount = 1;
	hba->sli.sli4.VFIExtSize = hba->sli.sli4.VFICount;
	hba->sli.sli4.VFIBase[0] = mb->un.varRdConfig4.VFIBase;

	hba->sli.sli4.FCFICount = mb->un.varRdConfig4.FCFICount;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
	    "CONFIG: xri:%d rpi:%d vpi:%d vfi:%d fcfi:%d",
	    hba->sli.sli4.XRICount,
	    hba->sli.sli4.RPICount,
	    hba->sli.sli4.VPICount,
	    hba->sli.sli4.VFICount,
	    hba->sli.sli4.FCFICount);

	if ((hba->sli.sli4.XRICount == 0) ||
	    (hba->sli.sli4.RPICount == 0) ||
	    (hba->sli.sli4.VPICount == 0) ||
	    (hba->sli.sli4.VFICount == 0) ||
	    (hba->sli.sli4.FCFICount == 0)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Invalid extent value(s) - xri:%d rpi:%d vpi:%d "
		    "vfi:%d fcfi:%d",
		    hba->sli.sli4.XRICount,
		    hba->sli.sli4.RPICount,
		    hba->sli.sli4.VPICount,
		    hba->sli.sli4.VFICount,
		    hba->sli.sli4.FCFICount);

		rval = EIO;
		goto failed1;
	}

	if (mb->un.varRdConfig4.extents) {
		if (emlxs_sli4_init_extents(hba, mbq)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
			    "Unable to initialize extents.");

			rval = EIO;
			goto failed1;
		}
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
	    "CONFIG: port_name:%c %c %c %c",
	    hba->sli.sli4.port_name[0],
	    hba->sli.sli4.port_name[1],
	    hba->sli.sli4.port_name[2],
	    hba->sli.sli4.port_name[3]);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
	    "CONFIG: ldv:%d link_type:%d link_number:%d",
	    mb->un.varRdConfig4.ldv,
	    mb->un.varRdConfig4.link_type,
	    mb->un.varRdConfig4.link_number);

	if (mb->un.varRdConfig4.ldv) {
		hba->sli.sli4.link_number = mb->un.varRdConfig4.link_number;
	} else {
		hba->sli.sli4.link_number = (uint32_t)-1;
	}

	if (hba->sli.sli4.VPICount) {
		hba->vpi_max = min(hba->sli.sli4.VPICount, MAX_VPORTS) - 1;
	}

	/* Set the max node count */
	if (cfg[CFG_NUM_NODES].current > 0) {
		hba->max_nodes =
		    min(cfg[CFG_NUM_NODES].current,
		    hba->sli.sli4.RPICount);
	} else {
		hba->max_nodes = hba->sli.sli4.RPICount;
	}

	/* Set the io throttle */
	hba->io_throttle = hba->sli.sli4.XRICount - IO_THROTTLE_RESERVE;

	/* Set max_iotag */
	/* We add 1 in case all XRI's are non-zero */
	hba->max_iotag = hba->sli.sli4.XRICount + 1;

	if (cfg[CFG_NUM_IOTAGS].current) {
		hba->max_iotag = min(hba->max_iotag,
		    (uint16_t)cfg[CFG_NUM_IOTAGS].current);
	}

	/* Set out-of-range iotag base */
	hba->fc_oor_iotag = hba->max_iotag;

	/* Save the link speed capabilities */
	vpd->link_speed = (uint16_t)mb->un.varRdConfig4.lmt;
	emlxs_process_link_speed(hba);

	/*
	 * Allocate some memory for buffers
	 */
	if (emlxs_mem_alloc_buffer(hba) == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to allocate memory buffers.");

		rval = ENOMEM;
		goto failed1;
	}

	if (emlxs_sli4_resource_alloc(hba)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to allocate resources.");

		rval = ENOMEM;
		goto failed2;
	}
	emlxs_data_dump(port, "XRIp", (uint32_t *)hba->sli.sli4.XRIp, 18, 0);
	emlxs_sli4_zero_queue_stat(hba);

#if (EMLXS_MODREV >= EMLXS_MODREV5)
	if ((cfg[CFG_NPIV_ENABLE].current) && (hba->flag & FC_NPIV_ENABLED)) {
		hba->fca_tran->fca_num_npivports = hba->vpi_max;
	}
#endif /* >= EMLXS_MODREV5 */

	/* Reuse mbq from previous mbox */
	bzero(mbq, sizeof (MAILBOXQ));

	if (emlxs_sli4_post_sgl_pages(hba, mbq)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to post sgl pages.");

		rval = EIO;
		goto failed3;
	}

	/* Reuse mbq from previous mbox */
	bzero(mbq, sizeof (MAILBOXQ));

	if (emlxs_sli4_post_hdr_tmplates(hba, mbq)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to post header templates.");

		rval = EIO;
		goto failed3;
	}

	/*
	 * Add our interrupt routine to kernel's interrupt chain & enable it
	 * If MSI is enabled this will cause Solaris to program the MSI address
	 * and data registers in PCI config space
	 */
	if (EMLXS_INTR_ADD(hba) != DDI_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to add interrupt(s).");

		rval = EIO;
		goto failed3;
	}

	/* Reuse mbq from previous mbox */
	bzero(mbq, sizeof (MAILBOXQ));

	/* This MUST be done after EMLXS_INTR_ADD */
	if (emlxs_sli4_create_queues(hba, mbq)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to create queues.");

		rval = EIO;
		goto failed3;
	}

	EMLXS_STATE_CHANGE(hba, FC_INIT_CFGPORT);

	/* Get and save the current firmware version (based on sli_mode) */
	emlxs_decode_firmware_rev(hba, vpd);


	EMLXS_STATE_CHANGE(hba, FC_INIT_INITLINK);

	if (SLI4_FC_MODE) {
		/* Reuse mbq from previous mbox */
		bzero(mbq, sizeof (MAILBOXQ));

		emlxs_mb_config_link(hba, mbq);
		if (emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) !=
		    MBX_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
			    "Unable to configure link. Mailbox cmd=%x "
			    "status=%x",
			    mb->mbxCommand, mb->mbxStatus);

			rval = EIO;
			goto failed3;
		}
	}

	/* Reuse mbq from previous mbox */
	bzero(mbq, sizeof (MAILBOXQ));

	/*
	 * We need to get login parameters for NID
	 */
	(void) emlxs_mb_read_sparam(hba, mbq);
	mp = (MATCHMAP *)mbq->bp;
	if (emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to read parameters. Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		rval = EIO;
		goto failed3;
	}

	/* Free the buffer since we were polling */
	emlxs_mem_put(hba, MEM_BUF, (void *)mp);
	mp = NULL;

	/* If no serial number in VPD data, then use the WWPN */
	if (vpd->serial_num[0] == 0) {
		outptr = (uint8_t *)&hba->wwpn.IEEE[0];
		for (i = 0; i < 12; i++) {
			status = *outptr++;
			j = ((status & 0xf0) >> 4);
			if (j <= 9) {
				vpd->serial_num[i] =
				    (char)((uint8_t)'0' + (uint8_t)j);
			} else {
				vpd->serial_num[i] =
				    (char)((uint8_t)'A' + (uint8_t)(j - 10));
			}

			i++;
			j = (status & 0xf);
			if (j <= 9) {
				vpd->serial_num[i] =
				    (char)((uint8_t)'0' + (uint8_t)j);
			} else {
				vpd->serial_num[i] =
				    (char)((uint8_t)'A' + (uint8_t)(j - 10));
			}
		}

		/*
		 * Set port number and port index to zero
		 * The WWN's are unique to each port and therefore port_num
		 * must equal zero. This effects the hba_fru_details structure
		 * in fca_bind_port()
		 */
		vpd->port_num[0] = 0;
		vpd->port_index = 0;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "CONFIG: WWPN: port_index=0");
	}

	/* Make final attempt to set a port index */
	if (vpd->port_index == (uint32_t)-1) {
		dev_info_t *p_dip;
		dev_info_t *c_dip;

		p_dip = ddi_get_parent(hba->dip);
		c_dip = ddi_get_child(p_dip);

		vpd->port_index = 0;
		while (c_dip && (hba->dip != c_dip)) {
			c_dip = ddi_get_next_sibling(c_dip);

			if (strcmp(ddi_get_name(c_dip), "ethernet") == 0) {
				continue;
			}

			vpd->port_index++;
		}

		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_init_debug_msg,
		    "CONFIG: Device tree: port_index=%d",
		    vpd->port_index);
	}

	if (vpd->port_num[0] == 0) {
		if (hba->model_info.channels == EMLXS_MULTI_CHANNEL) {
			(void) snprintf(vpd->port_num,
			    (sizeof (vpd->port_num)-1),
			    "%d", vpd->port_index);
		}
	}

	if (vpd->id[0] == 0) {
		(void) snprintf(vpd->id, (sizeof (vpd->id)-1),
		    "%s %d",
		    hba->model_info.model_desc, vpd->port_index);

	}

	if (vpd->manufacturer[0] == 0) {
		(void) strncpy(vpd->manufacturer, hba->model_info.manufacturer,
		    (sizeof (vpd->manufacturer)-1));
	}

	if (vpd->part_num[0] == 0) {
		(void) strncpy(vpd->part_num, hba->model_info.model,
		    (sizeof (vpd->part_num)-1));
	}

	if (vpd->model_desc[0] == 0) {
		(void) snprintf(vpd->model_desc, (sizeof (vpd->model_desc)-1),
		    "%s %d",
		    hba->model_info.model_desc, vpd->port_index);
	}

	if (vpd->model[0] == 0) {
		(void) strncpy(vpd->model, hba->model_info.model,
		    (sizeof (vpd->model)-1));
	}

	if (vpd->prog_types[0] == 0) {
		emlxs_build_prog_types(hba, vpd);
	}

	/* Create the symbolic names */
	(void) snprintf(hba->snn, (sizeof (hba->snn)-1),
	    "Emulex %s FV%s DV%s %s",
	    hba->model_info.model, hba->vpd.fw_version, emlxs_version,
	    (char *)utsname.nodename);

	(void) snprintf(hba->spn, (sizeof (hba->spn)-1),
	    "Emulex PPN-%01x%01x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
	    hba->wwpn.nameType, hba->wwpn.IEEEextMsn, hba->wwpn.IEEEextLsb,
	    hba->wwpn.IEEE[0], hba->wwpn.IEEE[1], hba->wwpn.IEEE[2],
	    hba->wwpn.IEEE[3], hba->wwpn.IEEE[4], hba->wwpn.IEEE[5]);


	EMLXS_STATE_CHANGE(hba, FC_LINK_DOWN);
	emlxs_sli4_enable_intr(hba);

	/* Check persist-linkdown */
	if (cfg[CFG_PERSIST_LINKDOWN].current) {
		EMLXS_STATE_CHANGE(hba, FC_LINK_DOWN_PERSIST);
		goto done;
	}

#ifdef SFCT_SUPPORT
	if ((port->mode == MODE_TARGET) &&
	    !(port->fct_flags & FCT_STATE_PORT_ONLINE)) {
		goto done;
	}
#endif /* SFCT_SUPPORT */

	/* Reuse mbq from previous mbox */
	bzero(mbq, sizeof (MAILBOXQ));

	/*
	 * Setup and issue mailbox INITIALIZE LINK command
	 * At this point, the interrupt will be generated by the HW
	 */
	emlxs_mb_init_link(hba, mbq,
	    cfg[CFG_TOPOLOGY].current, cfg[CFG_LINK_SPEED].current);

	rval = emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_NOWAIT, 0);
	if ((rval != MBX_SUCCESS) && (rval != MBX_BUSY)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to initialize link. "
		    "Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		rval = EIO;
		goto failed3;
	}

	/* Wait for link to come up */
	i = cfg[CFG_LINKUP_DELAY].current;
	while (i && (hba->state < FC_LINK_UP)) {
		/* Check for hardware error */
		if (hba->state == FC_ERROR) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_init_failed_msg,
			    "Adapter error.", mb->mbxCommand,
			    mb->mbxStatus);

			rval = EIO;
			goto failed3;
		}

		BUSYWAIT_MS(1000);
		i--;
	}

done:
	/*
	 * The leadville driver will now handle the FLOGI at the driver level
	 */

	if (mbq) {
		(void) kmem_free((uint8_t *)mbq, sizeof (MAILBOXQ));
		mbq = NULL;
		mb = NULL;
	}
	return (0);

failed3:
	EMLXS_STATE_CHANGE(hba, FC_ERROR);

	if (mp) {
		emlxs_mem_put(hba, MEM_BUF, (void *)mp);
		mp = NULL;
	}


	if (hba->intr_flags & EMLXS_MSI_ADDED) {
		(void) EMLXS_INTR_REMOVE(hba);
	}

	emlxs_sli4_resource_free(hba);

failed2:
	(void) emlxs_mem_free_buffer(hba);

failed1:
	if (mbq) {
		(void) kmem_free((uint8_t *)mbq, sizeof (MAILBOXQ));
		mbq = NULL;
		mb = NULL;
	}

	if (hba->sli.sli4.dump_region.virt) {
		(void) emlxs_mem_free(hba, &hba->sli.sli4.dump_region);
	}

	if (rval == 0) {
		rval = EIO;
	}

	return (rval);

} /* emlxs_sli4_online() */


static void
emlxs_sli4_offline(emlxs_hba_t *hba, uint32_t reset_requested)
{
	/* Reverse emlxs_sli4_online */

	mutex_enter(&EMLXS_PORT_LOCK);
	if (hba->flag & FC_INTERLOCKED) {
		mutex_exit(&EMLXS_PORT_LOCK);
		goto killed;
	}
	mutex_exit(&EMLXS_PORT_LOCK);

	if (reset_requested) {
		(void) emlxs_sli4_hba_reset(hba, 0, 0, 0);
	}

	/* Shutdown the adapter interface */
	emlxs_sli4_hba_kill(hba);

killed:

	/* Free SLI shared memory */
	emlxs_sli4_resource_free(hba);

	/* Free driver shared memory */
	(void) emlxs_mem_free_buffer(hba);

	/* Free the host dump region buffer */
	(void) emlxs_mem_free(hba, &hba->sli.sli4.dump_region);

} /* emlxs_sli4_offline() */


/*ARGSUSED*/
static int
emlxs_sli4_map_hdw(emlxs_hba_t *hba)
{
	emlxs_port_t		*port = &PPORT;
	dev_info_t		*dip;
	ddi_device_acc_attr_t	dev_attr;
	int			status;

	dip = (dev_info_t *)hba->dip;
	dev_attr = emlxs_dev_acc_attr;

	switch (hba->sli_intf & SLI_INTF_IF_TYPE_MASK) {
	case SLI_INTF_IF_TYPE_0:

		/* Map in Hardware BAR pages that will be used for */
		/* communication with HBA. */
		if (hba->sli.sli4.bar1_acc_handle == 0) {
			status = ddi_regs_map_setup(dip, PCI_BAR1_RINDEX,
			    (caddr_t *)&hba->sli.sli4.bar1_addr,
			    0, 0, &dev_attr, &hba->sli.sli4.bar1_acc_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "(PCI) ddi_regs_map_setup BAR1 failed. "
				    "stat=%d mem=%p attr=%p hdl=%p",
				    status, &hba->sli.sli4.bar1_addr, &dev_attr,
				    &hba->sli.sli4.bar1_acc_handle);
				goto failed;
			}
		}

		if (hba->sli.sli4.bar2_acc_handle == 0) {
			status = ddi_regs_map_setup(dip, PCI_BAR2_RINDEX,
			    (caddr_t *)&hba->sli.sli4.bar2_addr,
			    0, 0, &dev_attr, &hba->sli.sli4.bar2_acc_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "ddi_regs_map_setup BAR2 failed. status=%x",
				    status);
				goto failed;
			}
		}

		/* offset from beginning of register space */
		hba->sli.sli4.MPUEPSemaphore_reg_addr =
		    (uint32_t *)(hba->sli.sli4.bar1_addr +
		    CSR_MPU_EP_SEMAPHORE_OFFSET);
		hba->sli.sli4.MBDB_reg_addr =
		    (uint32_t *)(hba->sli.sli4.bar2_addr + PD_MB_DB_OFFSET);
		hba->sli.sli4.CQDB_reg_addr =
		    (uint32_t *)(hba->sli.sli4.bar2_addr + PD_CQ_DB_OFFSET);
		hba->sli.sli4.MQDB_reg_addr =
		    (uint32_t *)(hba->sli.sli4.bar2_addr + PD_MQ_DB_OFFSET);
		hba->sli.sli4.WQDB_reg_addr =
		    (uint32_t *)(hba->sli.sli4.bar2_addr + PD_WQ_DB_OFFSET);
		hba->sli.sli4.RQDB_reg_addr =
		    (uint32_t *)(hba->sli.sli4.bar2_addr + PD_RQ_DB_OFFSET);

		hba->sli.sli4.STATUS_reg_addr = 0;
		hba->sli.sli4.CNTL_reg_addr = 0;

		hba->sli.sli4.ERR1_reg_addr =
		    (uint32_t *)(hba->pci_addr + PCICFG_UE_STATUS_LO_OFFSET);
		hba->sli.sli4.ERR2_reg_addr =
		    (uint32_t *)(hba->pci_addr + PCICFG_UE_STATUS_HI_OFFSET);

		hba->sli.sli4.PHYSDEV_reg_addr = 0;
		break;

	case SLI_INTF_IF_TYPE_2:

		/* Map in Hardware BAR pages that will be used for */
		/* communication with HBA. */
		if (hba->sli.sli4.bar0_acc_handle == 0) {
			status = ddi_regs_map_setup(dip, PCI_BAR0_RINDEX,
			    (caddr_t *)&hba->sli.sli4.bar0_addr,
			    0, 0, &dev_attr, &hba->sli.sli4.bar0_acc_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "(PCI) ddi_regs_map_setup BAR0 failed. "
				    "stat=%d mem=%p attr=%p hdl=%p",
				    status, &hba->sli.sli4.bar0_addr, &dev_attr,
				    &hba->sli.sli4.bar0_acc_handle);
				goto failed;
			}
		}

		/* offset from beginning of register space */
		hba->sli.sli4.MPUEPSemaphore_reg_addr =
		    (uint32_t *)(hba->sli.sli4.bar0_addr +
		    SLIPORT_SEMAPHORE_OFFSET);
		hba->sli.sli4.MBDB_reg_addr =
		    (uint32_t *)(hba->sli.sli4.bar0_addr + PD_MB_DB_OFFSET);
		hba->sli.sli4.CQDB_reg_addr =
		    (uint32_t *)(hba->sli.sli4.bar0_addr + PD_CQ_DB_OFFSET);
		hba->sli.sli4.MQDB_reg_addr =
		    (uint32_t *)(hba->sli.sli4.bar0_addr + PD_MQ_DB_OFFSET);
		hba->sli.sli4.WQDB_reg_addr =
		    (uint32_t *)(hba->sli.sli4.bar0_addr + PD_WQ_DB_OFFSET);
		hba->sli.sli4.RQDB_reg_addr =
		    (uint32_t *)(hba->sli.sli4.bar0_addr + PD_RQ_DB_OFFSET);

		hba->sli.sli4.STATUS_reg_addr =
		    (uint32_t *)(hba->sli.sli4.bar0_addr +
		    SLIPORT_STATUS_OFFSET);
		hba->sli.sli4.CNTL_reg_addr =
		    (uint32_t *)(hba->sli.sli4.bar0_addr +
		    SLIPORT_CONTROL_OFFSET);
		hba->sli.sli4.ERR1_reg_addr =
		    (uint32_t *)(hba->sli.sli4.bar0_addr +
		    SLIPORT_ERROR1_OFFSET);
		hba->sli.sli4.ERR2_reg_addr =
		    (uint32_t *)(hba->sli.sli4.bar0_addr +
		    SLIPORT_ERROR2_OFFSET);
		hba->sli.sli4.PHYSDEV_reg_addr =
		    (uint32_t *)(hba->sli.sli4.bar0_addr +
		    PHYSDEV_CONTROL_OFFSET);

		break;

	case SLI_INTF_IF_TYPE_1:
	case SLI_INTF_IF_TYPE_3:
	default:
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_attach_failed_msg,
		    "Map hdw: Unsupported if_type %08x",
		    (hba->sli_intf & SLI_INTF_IF_TYPE_MASK));

		goto failed;
	}

	if (hba->sli.sli4.bootstrapmb.virt == 0) {
		MBUF_INFO	*buf_info;
		MBUF_INFO	bufinfo;

		buf_info = &bufinfo;

		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = EMLXS_BOOTSTRAP_MB_SIZE + MBOX_EXTENSION_SIZE;
		buf_info->flags =
		    FC_MBUF_DMA | FC_MBUF_SNGLSG | FC_MBUF_DMA32;
		buf_info->align = ddi_ptob(dip, 1L);

		(void) emlxs_mem_alloc(hba, buf_info);

		if (buf_info->virt == NULL) {
			goto failed;
		}

		hba->sli.sli4.bootstrapmb.virt = buf_info->virt;
		hba->sli.sli4.bootstrapmb.phys = buf_info->phys;
		hba->sli.sli4.bootstrapmb.size = EMLXS_BOOTSTRAP_MB_SIZE +
		    MBOX_EXTENSION_SIZE;
		hba->sli.sli4.bootstrapmb.data_handle = buf_info->data_handle;
		hba->sli.sli4.bootstrapmb.dma_handle = buf_info->dma_handle;
		bzero((char *)hba->sli.sli4.bootstrapmb.virt,
		    EMLXS_BOOTSTRAP_MB_SIZE);
	}

	hba->chan_count = MAX_CHANNEL;

	return (0);

failed:

	emlxs_sli4_unmap_hdw(hba);
	return (ENOMEM);


} /* emlxs_sli4_map_hdw() */


/*ARGSUSED*/
static void
emlxs_sli4_unmap_hdw(emlxs_hba_t *hba)
{
	MBUF_INFO	bufinfo;
	MBUF_INFO	*buf_info = &bufinfo;


	if (hba->sli.sli4.bar0_acc_handle) {
		ddi_regs_map_free(&hba->sli.sli4.bar0_acc_handle);
		hba->sli.sli4.bar0_acc_handle = 0;
	}

	if (hba->sli.sli4.bar1_acc_handle) {
		ddi_regs_map_free(&hba->sli.sli4.bar1_acc_handle);
		hba->sli.sli4.bar1_acc_handle = 0;
	}

	if (hba->sli.sli4.bar2_acc_handle) {
		ddi_regs_map_free(&hba->sli.sli4.bar2_acc_handle);
		hba->sli.sli4.bar2_acc_handle = 0;
	}

	if (hba->sli.sli4.bootstrapmb.virt) {
		bzero(buf_info, sizeof (MBUF_INFO));

		if (hba->sli.sli4.bootstrapmb.phys) {
			buf_info->phys = hba->sli.sli4.bootstrapmb.phys;
			buf_info->data_handle =
			    hba->sli.sli4.bootstrapmb.data_handle;
			buf_info->dma_handle =
			    hba->sli.sli4.bootstrapmb.dma_handle;
			buf_info->flags = FC_MBUF_DMA;
		}

		buf_info->virt = hba->sli.sli4.bootstrapmb.virt;
		buf_info->size = hba->sli.sli4.bootstrapmb.size;
		emlxs_mem_free(hba, buf_info);

		hba->sli.sli4.bootstrapmb.virt = NULL;
	}

	return;

} /* emlxs_sli4_unmap_hdw() */


static int
emlxs_check_hdw_ready(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	uint32_t status;
	uint32_t i = 0;
	uint32_t err1;
	uint32_t err2;

	/* Wait for reset completion */
	while (i < 30) {

		switch (hba->sli_intf & SLI_INTF_IF_TYPE_MASK) {
		case SLI_INTF_IF_TYPE_0:
			status = emlxs_sli4_read_sema(hba);

			/* Check to see if any errors occurred during init */
			if (status & ARM_POST_FATAL) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_reset_failed_msg,
				    "SEMA Error: status=%x", status);

				EMLXS_STATE_CHANGE(hba, FC_ERROR);

				return (1);
			}

			if ((status & ARM_UNRECOVERABLE_ERROR) ==
			    ARM_UNRECOVERABLE_ERROR) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_reset_failed_msg,
				    "Unrecoverable Error: status=%x", status);

				EMLXS_STATE_CHANGE(hba, FC_ERROR);

				return (1);
			}

			if ((status & ARM_POST_MASK) == ARM_POST_READY) {
				/* ARM Ready !! */
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_sli_detail_msg,
				    "ARM Ready: status=%x", status);

				return (0);
			}
			break;

		case SLI_INTF_IF_TYPE_2:
			status = emlxs_sli4_read_status(hba);

			if (status & SLI_STATUS_READY) {
				if (!(status & SLI_STATUS_ERROR)) {
					/* ARM Ready !! */
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_sli_detail_msg,
					    "ARM Ready: status=%x", status);

					return (0);
				}

				err1 = ddi_get32(hba->sli.sli4.bar0_acc_handle,
				    hba->sli.sli4.ERR1_reg_addr);
				err2 = ddi_get32(hba->sli.sli4.bar0_acc_handle,
				    hba->sli.sli4.ERR2_reg_addr);

				if (status & SLI_STATUS_RESET_NEEDED) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_sli_detail_msg,
					    "ARM Ready (Reset Needed): "
					    "status=%x err1=%x "
					    "err2=%x",
					    status, err1, err2);

					return (1);
				}

				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_reset_failed_msg,
				    "Unrecoverable Error: status=%x err1=%x "
				    "err2=%x",
				    status, err1, err2);

				EMLXS_STATE_CHANGE(hba, FC_ERROR);

				return (2);
			}

			break;

		default:
			EMLXS_STATE_CHANGE(hba, FC_ERROR);

			return (3);
		}

		BUSYWAIT_MS(1000);
		i++;
	}

	/* Timeout occurred */
	switch (hba->sli_intf & SLI_INTF_IF_TYPE_MASK) {
	case SLI_INTF_IF_TYPE_0:
		err1 = ddi_get32(hba->pci_acc_handle,
		    hba->sli.sli4.ERR1_reg_addr);
		err2 = ddi_get32(hba->pci_acc_handle,
		    hba->sli.sli4.ERR2_reg_addr);
		break;

	default:
		err1 = ddi_get32(hba->sli.sli4.bar0_acc_handle,
		    hba->sli.sli4.ERR1_reg_addr);
		err2 = ddi_get32(hba->sli.sli4.bar0_acc_handle,
		    hba->sli.sli4.ERR2_reg_addr);
		break;
	}

	if (status & SLI_STATUS_ERROR) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_reset_failed_msg,
		    "Ready Timeout: Port Error: status=%x err1=%x err2=%x",
		    status, err1, err2);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_reset_failed_msg,
		    "Ready Timeout: status=%x err1=%x err2=%x",
		    status, err1, err2);
	}

	EMLXS_STATE_CHANGE(hba, FC_ERROR);

	return (3);

} /* emlxs_check_hdw_ready() */


static uint32_t
emlxs_sli4_read_status(emlxs_hba_t *hba)
{
#ifdef FMA_SUPPORT
	emlxs_port_t *port = &PPORT;
#endif  /* FMA_SUPPORT */
	uint32_t status;

	switch (hba->sli_intf & SLI_INTF_IF_TYPE_MASK) {
	case SLI_INTF_IF_TYPE_2:
		status = ddi_get32(hba->sli.sli4.bar0_acc_handle,
		    hba->sli.sli4.STATUS_reg_addr);
#ifdef FMA_SUPPORT
		/* Access handle validation */
		EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli4.bar0_acc_handle);
#endif  /* FMA_SUPPORT */
		break;
	default:
		status = 0;
		break;
	}

	return (status);

} /* emlxs_sli4_read_status() */


static uint32_t
emlxs_sli4_read_sema(emlxs_hba_t *hba)
{
#ifdef FMA_SUPPORT
	emlxs_port_t *port = &PPORT;
#endif  /* FMA_SUPPORT */
	uint32_t status;

	switch (hba->sli_intf & SLI_INTF_IF_TYPE_MASK) {
	case SLI_INTF_IF_TYPE_0:
		status = ddi_get32(hba->sli.sli4.bar1_acc_handle,
		    hba->sli.sli4.MPUEPSemaphore_reg_addr);
#ifdef FMA_SUPPORT
		/* Access handle validation */
		EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli4.bar1_acc_handle);
#endif  /* FMA_SUPPORT */
		break;

	case SLI_INTF_IF_TYPE_2:
		status = ddi_get32(hba->sli.sli4.bar0_acc_handle,
		    hba->sli.sli4.MPUEPSemaphore_reg_addr);
#ifdef FMA_SUPPORT
		/* Access handle validation */
		EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli4.bar0_acc_handle);
#endif  /* FMA_SUPPORT */
		break;
	default:
		status = 0;
		break;
	}

	return (status);

} /* emlxs_sli4_read_sema() */


static uint32_t
emlxs_sli4_read_mbdb(emlxs_hba_t *hba)
{
#ifdef FMA_SUPPORT
	emlxs_port_t *port = &PPORT;
#endif  /* FMA_SUPPORT */
	uint32_t status;

	switch (hba->sli_intf & SLI_INTF_IF_TYPE_MASK) {
	case SLI_INTF_IF_TYPE_0:
		status = ddi_get32(hba->sli.sli4.bar2_acc_handle,
		    hba->sli.sli4.MBDB_reg_addr);

#ifdef FMA_SUPPORT
		/* Access handle validation */
		EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli4.bar2_acc_handle);
#endif  /* FMA_SUPPORT */
		break;

	case SLI_INTF_IF_TYPE_2:
		status = ddi_get32(hba->sli.sli4.bar0_acc_handle,
		    hba->sli.sli4.MBDB_reg_addr);
#ifdef FMA_SUPPORT
		/* Access handle validation */
		EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli4.bar0_acc_handle);
#endif  /* FMA_SUPPORT */
		break;
	default:
		status = 0;
		break;
	}

	return (status);

} /* emlxs_sli4_read_mbdb() */


static void
emlxs_sli4_write_mbdb(emlxs_hba_t *hba, uint32_t value)
{
	switch (hba->sli_intf & SLI_INTF_IF_TYPE_MASK) {
	case SLI_INTF_IF_TYPE_0:
		ddi_put32(hba->sli.sli4.bar2_acc_handle,
		    hba->sli.sli4.MBDB_reg_addr, value);
		break;

	case SLI_INTF_IF_TYPE_2:
		ddi_put32(hba->sli.sli4.bar0_acc_handle,
		    hba->sli.sli4.MBDB_reg_addr, value);
		break;
	}

} /* emlxs_sli4_write_mbdb() */


static void
emlxs_sli4_write_cqdb(emlxs_hba_t *hba, uint32_t value)
{
	switch (hba->sli_intf & SLI_INTF_IF_TYPE_MASK) {
	case SLI_INTF_IF_TYPE_0:
		ddi_put32(hba->sli.sli4.bar2_acc_handle,
		    hba->sli.sli4.CQDB_reg_addr, value);
		break;

	case SLI_INTF_IF_TYPE_2:
		ddi_put32(hba->sli.sli4.bar0_acc_handle,
		    hba->sli.sli4.CQDB_reg_addr, value);
		break;
	}

} /* emlxs_sli4_write_cqdb() */


static void
emlxs_sli4_write_rqdb(emlxs_hba_t *hba, uint32_t value)
{
	switch (hba->sli_intf & SLI_INTF_IF_TYPE_MASK) {
	case SLI_INTF_IF_TYPE_0:
		ddi_put32(hba->sli.sli4.bar2_acc_handle,
		    hba->sli.sli4.RQDB_reg_addr, value);
		break;

	case SLI_INTF_IF_TYPE_2:
		ddi_put32(hba->sli.sli4.bar0_acc_handle,
		    hba->sli.sli4.RQDB_reg_addr, value);
		break;
	}

} /* emlxs_sli4_write_rqdb() */


static void
emlxs_sli4_write_mqdb(emlxs_hba_t *hba, uint32_t value)
{
	switch (hba->sli_intf & SLI_INTF_IF_TYPE_MASK) {
	case SLI_INTF_IF_TYPE_0:
		ddi_put32(hba->sli.sli4.bar2_acc_handle,
		    hba->sli.sli4.MQDB_reg_addr, value);
		break;

	case SLI_INTF_IF_TYPE_2:
		ddi_put32(hba->sli.sli4.bar0_acc_handle,
		    hba->sli.sli4.MQDB_reg_addr, value);
		break;
	}

} /* emlxs_sli4_write_mqdb() */


static void
emlxs_sli4_write_wqdb(emlxs_hba_t *hba, uint32_t value)
{
	switch (hba->sli_intf & SLI_INTF_IF_TYPE_MASK) {
	case SLI_INTF_IF_TYPE_0:
		ddi_put32(hba->sli.sli4.bar2_acc_handle,
		    hba->sli.sli4.WQDB_reg_addr, value);
		break;

	case SLI_INTF_IF_TYPE_2:
		ddi_put32(hba->sli.sli4.bar0_acc_handle,
		    hba->sli.sli4.WQDB_reg_addr, value);
		break;
	}

} /* emlxs_sli4_write_wqdb() */


static uint32_t
emlxs_check_bootstrap_ready(emlxs_hba_t *hba, uint32_t tmo)
{
	emlxs_port_t *port = &PPORT;
	uint32_t status = 0;
	uint32_t err1;
	uint32_t err2;

	/* Wait for reset completion, tmo is in 10ms ticks */
	while (tmo) {
		status = emlxs_sli4_read_mbdb(hba);

		/* Check to see if any errors occurred during init */
		if (status & BMBX_READY) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "BMBX Ready: status=0x%x", status);

			return (tmo);
		}

		BUSYWAIT_MS(10);
		tmo--;
	}

	switch (hba->sli_intf & SLI_INTF_IF_TYPE_MASK) {
	case SLI_INTF_IF_TYPE_0:
		err1 = ddi_get32(hba->pci_acc_handle,
		    hba->sli.sli4.ERR1_reg_addr);
		err2 = ddi_get32(hba->pci_acc_handle,
		    hba->sli.sli4.ERR2_reg_addr);
		break;

	default:
		err1 = ddi_get32(hba->sli.sli4.bar0_acc_handle,
		    hba->sli.sli4.ERR1_reg_addr);
		err2 = ddi_get32(hba->sli.sli4.bar0_acc_handle,
		    hba->sli.sli4.ERR2_reg_addr);
		break;
	}

	/* Timeout occurred */
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_reset_failed_msg,
	    "Timeout waiting for BMailbox: status=%x err1=%x err2=%x",
	    status, err1, err2);

	EMLXS_STATE_CHANGE(hba, FC_ERROR);

	return (0);

} /* emlxs_check_bootstrap_ready() */


static uint32_t
emlxs_issue_bootstrap_mb(emlxs_hba_t *hba, uint32_t tmo)
{
	emlxs_port_t *port = &PPORT;
	uint32_t *iptr;
	uint32_t addr30;

	/*
	 * This routine assumes the bootstrap mbox is loaded
	 * with the mailbox command to be executed.
	 *
	 * First, load the high 30 bits of bootstrap mailbox
	 */
	addr30 = (uint32_t)((hba->sli.sli4.bootstrapmb.phys>>32) & 0xfffffffc);
	addr30 |= BMBX_ADDR_HI;
	emlxs_sli4_write_mbdb(hba, addr30);

	tmo = emlxs_check_bootstrap_ready(hba, tmo);
	if (tmo == 0) {
		return (0);
	}

	/* Load the low 30 bits of bootstrap mailbox */
	addr30 = (uint32_t)((hba->sli.sli4.bootstrapmb.phys>>2) & 0xfffffffc);
	emlxs_sli4_write_mbdb(hba, addr30);

	tmo = emlxs_check_bootstrap_ready(hba, tmo);
	if (tmo == 0) {
		return (0);
	}

	iptr = (uint32_t *)hba->sli.sli4.bootstrapmb.virt;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "BootstrapMB: %p Completed %08x %08x %08x",
	    hba->sli.sli4.bootstrapmb.virt,
	    *iptr, *(iptr+1), *(iptr+2));

	return (tmo);

} /* emlxs_issue_bootstrap_mb() */


static int
emlxs_init_bootstrap_mb(emlxs_hba_t *hba)
{
#ifdef FMA_SUPPORT
	emlxs_port_t *port = &PPORT;
#endif /* FMA_SUPPORT */
	uint32_t *iptr;
	uint32_t tmo;

	if (emlxs_check_hdw_ready(hba)) {
		return (1);
	}

	if (hba->flag & FC_BOOTSTRAPMB_INIT) {
		return (0);  /* Already initialized */
	}

	/* NOTE: tmo is in 10ms ticks */
	tmo = emlxs_check_bootstrap_ready(hba, 3000);
	if (tmo == 0) {
		return (1);
	}

	/* Issue FW_INITIALIZE command */

	/* Special words to initialize bootstrap mbox MUST be little endian */
	iptr = (uint32_t *)hba->sli.sli4.bootstrapmb.virt;
	*iptr = LE_SWAP32(FW_INITIALIZE_WORD0);
	*(iptr+1) = LE_SWAP32(FW_INITIALIZE_WORD1);

	EMLXS_MPDATA_SYNC(hba->sli.sli4.bootstrapmb.dma_handle, 0,
	    MAILBOX_CMD_BSIZE, DDI_DMA_SYNC_FORDEV);

	emlxs_data_dump(port, "FW_INIT", (uint32_t *)iptr, 6, 0);
	if (!emlxs_issue_bootstrap_mb(hba, tmo)) {
		return (1);
	}

#ifdef FMA_SUPPORT
	if (emlxs_fm_check_dma_handle(hba, hba->sli.sli4.bootstrapmb.dma_handle)
	    != DDI_FM_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_invalid_dma_handle_msg,
		    "init_bootstrap_mb: hdl=%p",
		    hba->sli.sli4.bootstrapmb.dma_handle);
		return (1);
	}
#endif
	hba->flag |= FC_BOOTSTRAPMB_INIT;
	return (0);

} /* emlxs_init_bootstrap_mb() */




static uint32_t
emlxs_sli4_hba_init(emlxs_hba_t *hba)
{
	int rc;
	uint16_t i;
	emlxs_port_t *vport;
	emlxs_config_t *cfg = &CFG;
	CHANNEL *cp;
	VPIobj_t *vpip;

	/* Restart the adapter */
	if (emlxs_sli4_hba_reset(hba, 1, 0, 0)) {
		return (1);
	}

	for (i = 0; i < hba->chan_count; i++) {
		cp = &hba->chan[i];
		cp->iopath = (void *)&hba->sli.sli4.wq[i];
	}

	/* Initialize all the port objects */
	hba->vpi_max  = 0;
	for (i = 0; i < MAX_VPORTS; i++) {
		vport = &VPORT(i);
		vport->hba = hba;
		vport->vpi = i;

		vpip = &vport->VPIobj;
		vpip->index = i;
		vpip->VPI = i;
		vpip->port = vport;
		vpip->state = VPI_STATE_OFFLINE;
		vport->vpip = vpip;
	}

	/* Set the max node count */
	if (hba->max_nodes == 0) {
		if (cfg[CFG_NUM_NODES].current > 0) {
			hba->max_nodes = cfg[CFG_NUM_NODES].current;
		} else {
			hba->max_nodes = 4096;
		}
	}

	rc = emlxs_init_bootstrap_mb(hba);
	if (rc) {
		return (rc);
	}

	hba->sli.sli4.cfgFCOE.FCMap[0] = FCOE_FCF_MAP0;
	hba->sli.sli4.cfgFCOE.FCMap[1] = FCOE_FCF_MAP1;
	hba->sli.sli4.cfgFCOE.FCMap[2] = FCOE_FCF_MAP2;

	if ((hba->sli_intf & SLI_INTF_IF_TYPE_MASK) == SLI_INTF_IF_TYPE_0) {
		/* Cache the UE MASK registers value for UE error detection */
		hba->sli.sli4.ue_mask_lo = ddi_get32(hba->pci_acc_handle,
		    (uint32_t *)(hba->pci_addr + PCICFG_UE_MASK_LO_OFFSET));
		hba->sli.sli4.ue_mask_hi = ddi_get32(hba->pci_acc_handle,
		    (uint32_t *)(hba->pci_addr + PCICFG_UE_MASK_HI_OFFSET));
	}

	return (0);

} /* emlxs_sli4_hba_init() */


/*ARGSUSED*/
static uint32_t
emlxs_sli4_hba_reset(emlxs_hba_t *hba, uint32_t restart, uint32_t skip_post,
		uint32_t quiesce)
{
	emlxs_port_t *port = &PPORT;
	emlxs_port_t *vport;
	CHANNEL *cp;
	emlxs_config_t *cfg = &CFG;
	MAILBOXQ mboxq;
	uint32_t value;
	uint32_t i;
	uint32_t rc;
	uint16_t channelno;
	uint32_t status;
	uint32_t err1;
	uint32_t err2;
	uint8_t generate_event = 0;

	if (!cfg[CFG_RESET_ENABLE].current) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_reset_failed_msg,
		    "Adapter reset disabled.");
		EMLXS_STATE_CHANGE(hba, FC_ERROR);

		return (1);
	}

	switch (hba->sli_intf & SLI_INTF_IF_TYPE_MASK) {
	case SLI_INTF_IF_TYPE_0:
		if (quiesce == 0) {
			emlxs_sli4_hba_kill(hba);

			/*
			 * Initalize Hardware that will be used to bring
			 * SLI4 online.
			 */
			rc = emlxs_init_bootstrap_mb(hba);
			if (rc) {
				return (rc);
			}
		}

		bzero((void *)&mboxq, sizeof (MAILBOXQ));
		emlxs_mb_resetport(hba, &mboxq);

		if (quiesce == 0) {
			if (emlxs_sli4_issue_mbox_cmd(hba, &mboxq,
			    MBX_POLL, 0) != MBX_SUCCESS) {
				/* Timeout occurred */
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_reset_failed_msg,
				    "Timeout: RESET");
				EMLXS_STATE_CHANGE(hba, FC_ERROR);
				/* Log a dump event - not supported */
				return (1);
			}
		} else {
			if (emlxs_sli4_issue_mbox_cmd4quiesce(hba, &mboxq,
			    MBX_POLL, 0) != MBX_SUCCESS) {
				EMLXS_STATE_CHANGE(hba, FC_ERROR);
				/* Log a dump event - not supported */
				return (1);
			}
		}
		emlxs_data_dump(port, "resetPort", (uint32_t *)&mboxq, 12, 0);
		break;

	case SLI_INTF_IF_TYPE_2:
		if (quiesce == 0) {
			emlxs_sli4_hba_kill(hba);
		}

		rc = emlxs_check_hdw_ready(hba);
		if (rc > 1) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_debug_msg,
			    "Adapter not ready for reset.");
			return (1);
		}

		if (rc == 1) {
			err1 = ddi_get32(hba->sli.sli4.bar0_acc_handle,
			    hba->sli.sli4.ERR1_reg_addr);
			err2 = ddi_get32(hba->sli.sli4.bar0_acc_handle,
			    hba->sli.sli4.ERR2_reg_addr);

			/* Don't generate an event if dump was forced */
			if ((err1 != 0x2) || (err2 != 0x2)) {
				generate_event = 1;
			}
		}

		/* Reset the port now */

		mutex_enter(&EMLXS_PORT_LOCK);
		value = SLI_CNTL_INIT_PORT;

		ddi_put32(hba->sli.sli4.bar0_acc_handle,
		    hba->sli.sli4.CNTL_reg_addr, value);
		mutex_exit(&EMLXS_PORT_LOCK);

		break;
	}

	/* Reset the hba structure */
	hba->flag &= FC_RESET_MASK;

	for (channelno = 0; channelno < hba->chan_count; channelno++) {
		cp = &hba->chan[channelno];
		cp->hba = hba;
		cp->channelno = channelno;
	}

	hba->channel_tx_count = 0;
	hba->io_count = 0;
	hba->iodone_count = 0;
	hba->topology = 0;
	hba->linkspeed = 0;
	hba->heartbeat_active = 0;
	hba->discovery_timer = 0;
	hba->linkup_timer = 0;
	hba->loopback_tics = 0;

	/* Reset the port objects */
	for (i = 0; i < MAX_VPORTS; i++) {
		vport = &VPORT(i);

		vport->flag &= EMLXS_PORT_RESET_MASK;
		vport->did = 0;
		vport->prev_did = 0;
		vport->lip_type = 0;
		bzero(&vport->fabric_sparam, sizeof (SERV_PARM));
		bzero(&vport->prev_fabric_sparam, sizeof (SERV_PARM));

		bzero((caddr_t)&vport->node_base, sizeof (NODELIST));
		vport->node_base.nlp_Rpi = 0;
		vport->node_base.nlp_DID = 0xffffff;
		vport->node_base.nlp_list_next = NULL;
		vport->node_base.nlp_list_prev = NULL;
		vport->node_base.nlp_active = 1;
		vport->node_count = 0;

		if (vport->ub_count < EMLXS_UB_TOKEN_OFFSET) {
			vport->ub_count = EMLXS_UB_TOKEN_OFFSET;
		}
	}

	if (emlxs_check_hdw_ready(hba)) {
		return (1);
	}

	if (generate_event) {
		status = emlxs_sli4_read_status(hba);
		if (status & SLI_STATUS_DUMP_IMAGE_PRESENT) {
			emlxs_log_dump_event(port, NULL, 0);
		}
	}

	return (0);

} /* emlxs_sli4_hba_reset */


#define	SGL_CMD		0
#define	SGL_RESP	1
#define	SGL_DATA	2
#define	SGL_LAST	0x80

/*ARGSUSED*/
static ULP_SGE64 *
emlxs_pkt_to_sgl(emlxs_port_t *port, fc_packet_t *pkt, ULP_SGE64 *sge,
    uint32_t sgl_type, uint32_t *pcnt)
{
#ifdef DEBUG_SGE
	emlxs_hba_t *hba = HBA;
#endif /* DEBUG_SGE */
	ddi_dma_cookie_t *cp;
	uint_t i;
	uint_t last;
	int32_t	size;
	int32_t	sge_size;
	uint64_t sge_addr;
	int32_t	len;
	uint32_t cnt;
	uint_t cookie_cnt;
	ULP_SGE64 stage_sge;

	last = sgl_type & SGL_LAST;
	sgl_type &= ~SGL_LAST;

#if (EMLXS_MODREV >= EMLXS_MODREV3)
	switch (sgl_type) {
	case SGL_CMD:
		cp = pkt->pkt_cmd_cookie;
		cookie_cnt = pkt->pkt_cmd_cookie_cnt;
		size = (int32_t)pkt->pkt_cmdlen;
		break;

	case SGL_RESP:
		cp = pkt->pkt_resp_cookie;
		cookie_cnt = pkt->pkt_resp_cookie_cnt;
		size = (int32_t)pkt->pkt_rsplen;
		break;


	case SGL_DATA:
		cp = pkt->pkt_data_cookie;
		cookie_cnt = pkt->pkt_data_cookie_cnt;
		size = (int32_t)pkt->pkt_datalen;
		break;

	default:
		return (NULL);
	}

#else
	switch (sgl_type) {
	case SGL_CMD:
		cp = &pkt->pkt_cmd_cookie;
		cookie_cnt = 1;
		size = (int32_t)pkt->pkt_cmdlen;
		break;

	case SGL_RESP:
		cp = &pkt->pkt_resp_cookie;
		cookie_cnt = 1;
		size = (int32_t)pkt->pkt_rsplen;
		break;


	case SGL_DATA:
		cp = &pkt->pkt_data_cookie;
		cookie_cnt = 1;
		size = (int32_t)pkt->pkt_datalen;
		break;

	default:
		return (NULL);
	}
#endif	/* >= EMLXS_MODREV3 */

	stage_sge.offset = 0;
	stage_sge.type = 0;
	stage_sge.last = 0;
	cnt = 0;
	for (i = 0; i < cookie_cnt && size > 0; i++, cp++) {

		sge_size = cp->dmac_size;
		sge_addr = cp->dmac_laddress;
		while (sge_size && size) {
			if (cnt) {
				/* Copy staged SGE before we build next one */
				BE_SWAP32_BCOPY((uint8_t *)&stage_sge,
				    (uint8_t *)sge, sizeof (ULP_SGE64));
				sge++;
			}
			len = MIN(EMLXS_MAX_SGE_SIZE, sge_size);
			len = MIN(size, len);

			stage_sge.addrHigh =
			    PADDR_HI(sge_addr);
			stage_sge.addrLow =
			    PADDR_LO(sge_addr);
			stage_sge.length = len;
			if (sgl_type == SGL_DATA) {
				stage_sge.offset = cnt;
			}
#ifdef DEBUG_SGE
			emlxs_data_dump(port, "SGE", (uint32_t *)&stage_sge,
			    4, 0);
#endif /* DEBUG_SGE */
			sge_addr += len;
			sge_size -= len;

			cnt += len;
			size -= len;
		}
	}

	if (last) {
		stage_sge.last = 1;
	}
	BE_SWAP32_BCOPY((uint8_t *)&stage_sge, (uint8_t *)sge,
	    sizeof (ULP_SGE64));

	sge++;

	if (pcnt) {
		*pcnt = cnt;
	}
	return (sge);

} /* emlxs_pkt_to_sgl */


/*ARGSUSED*/
uint32_t
emlxs_sli4_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	XRIobj_t *xrip;
	ULP_SGE64 *sge;
	emlxs_wqe_t *wqe;
	IOCBQ *iocbq;
	ddi_dma_cookie_t *cp_cmd;
	ddi_dma_cookie_t *cp_data;
	uint64_t sge_addr;
	uint32_t cmd_cnt;
	uint32_t resp_cnt;

	iocbq = (IOCBQ *) &sbp->iocbq;
	wqe = &iocbq->wqe;
	pkt = PRIV2PKT(sbp);
	xrip = sbp->xrip;
	sge = xrip->SGList.virt;

#if (EMLXS_MODREV >= EMLXS_MODREV3)
	cp_cmd = pkt->pkt_cmd_cookie;
	cp_data = pkt->pkt_data_cookie;
#else
	cp_cmd  = &pkt->pkt_cmd_cookie;
	cp_data = &pkt->pkt_data_cookie;
#endif	/* >= EMLXS_MODREV3 */

	iocbq = &sbp->iocbq;
	if (iocbq->flag & IOCB_FCP_CMD) {

		if (pkt->pkt_tran_type == FC_PKT_OUTBOUND) {
			return (1);
		}

		/* CMD payload */
		sge = emlxs_pkt_to_sgl(port, pkt, sge, SGL_CMD, &cmd_cnt);
		if (! sge) {
			return (1);
		}

		/* DATA payload */
		if (pkt->pkt_datalen != 0) {
			/* RSP payload */
			sge = emlxs_pkt_to_sgl(port, pkt, sge,
			    SGL_RESP, &resp_cnt);
			if (! sge) {
				return (1);
			}

			/* Data payload */
			sge = emlxs_pkt_to_sgl(port, pkt, sge,
			    SGL_DATA | SGL_LAST, 0);
			if (! sge) {
				return (1);
			}
sgl_done:
			if (hba->sli.sli4.flag & EMLXS_SLI4_PHON) {
				sge_addr = cp_data->dmac_laddress;
				wqe->FirstData.addrHigh = PADDR_HI(sge_addr);
				wqe->FirstData.addrLow = PADDR_LO(sge_addr);
				wqe->FirstData.tus.f.bdeSize =
				    cp_data->dmac_size;
			}
		} else {
			/* RSP payload */
			sge = emlxs_pkt_to_sgl(port, pkt, sge,
			    SGL_RESP | SGL_LAST, &resp_cnt);
			if (! sge) {
				return (1);
			}
		}

		wqe->un.FcpCmd.Payload.addrHigh =
		    PADDR_HI(cp_cmd->dmac_laddress);
		wqe->un.FcpCmd.Payload.addrLow =
		    PADDR_LO(cp_cmd->dmac_laddress);
		wqe->un.FcpCmd.Payload.tus.f.bdeSize = cmd_cnt;
		wqe->un.FcpCmd.PayloadLength = cmd_cnt + resp_cnt;

	} else {

		if (pkt->pkt_tran_type == FC_PKT_OUTBOUND) {
			/* CMD payload */
			sge = emlxs_pkt_to_sgl(port, pkt, sge,
			    SGL_CMD | SGL_LAST, &cmd_cnt);
			if (! sge) {
				return (1);
			}
		} else {
			/* CMD payload */
			sge = emlxs_pkt_to_sgl(port, pkt, sge,
			    SGL_CMD, &cmd_cnt);
			if (! sge) {
				return (1);
			}

			/* RSP payload */
			sge = emlxs_pkt_to_sgl(port, pkt, sge,
			    SGL_RESP | SGL_LAST, &resp_cnt);
			if (! sge) {
				return (1);
			}
			wqe->un.GenReq.PayloadLength = cmd_cnt;
		}

		wqe->un.GenReq.Payload.addrHigh =
		    PADDR_HI(cp_cmd->dmac_laddress);
		wqe->un.GenReq.Payload.addrLow =
		    PADDR_LO(cp_cmd->dmac_laddress);
		wqe->un.GenReq.Payload.tus.f.bdeSize = cmd_cnt;
	}
	return (0);
} /* emlxs_sli4_bde_setup */




#ifdef SFCT_SUPPORT
/*ARGSUSED*/
static uint32_t
emlxs_sli4_fct_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	emlxs_wqe_t *wqe;
	ULP_SGE64 stage_sge;
	ULP_SGE64 *sge;
	IOCB *iocb;
	IOCBQ *iocbq;
	MATCHMAP *mp;
	MATCHMAP *fct_mp;
	XRIobj_t *xrip;
	uint64_t sge_addr;
	uint32_t sge_size;
	uint32_t cnt;
	uint32_t len;
	uint32_t size;
	uint32_t *xrdy_vaddr;
	stmf_data_buf_t *dbuf;

	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;
	wqe = &iocbq->wqe;
	xrip = sbp->xrip;

	if (!sbp->fct_buf) {
		return (0);
	}

	size = sbp->fct_buf->db_data_size;

	/*
	 * The hardware will automaticlly round up
	 * to multiple of 4.
	 *
	 * if (size & 3) {
	 *	size = (size + 3) & 0xfffffffc;
	 * }
	 */
	fct_mp = (MATCHMAP *)sbp->fct_buf->db_port_private;

	if (sbp->fct_buf->db_sglist_length != 1) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "fct_bde_setup: Only 1 sglist entry supported: %d",
		    sbp->fct_buf->db_sglist_length);
		return (1);
	}

	sge = xrip->SGList.virt;

	if (iocb->ULPCOMMAND == CMD_FCP_TRECEIVE64_CX) {

		mp = emlxs_mem_buf_alloc(hba, EMLXS_XFER_RDY_SIZE);
		if (!mp || !mp->virt || !mp->phys) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
			    "fct_bde_setup: Cannot allocate XRDY memory");
			return (1);
		}
		/* Save the MATCHMAP info to free this memory later */
		iocbq->bp = mp;

		/* Point to XRDY payload */
		xrdy_vaddr = (uint32_t *)(mp->virt);

		/* Fill in burstsize in payload */
		*xrdy_vaddr++ = 0;
		*xrdy_vaddr++ = LE_SWAP32(size);
		*xrdy_vaddr = 0;

		/* First 2 SGEs are XRDY and SKIP */
		stage_sge.addrHigh = PADDR_HI(mp->phys);
		stage_sge.addrLow = PADDR_LO(mp->phys);
		stage_sge.length = EMLXS_XFER_RDY_SIZE;
		stage_sge.offset = 0;
		stage_sge.type = 0;
		stage_sge.last = 0;

		/* Words  0-3 */
		wqe->un.FcpCmd.Payload.addrHigh = stage_sge.addrHigh;
		wqe->un.FcpCmd.Payload.addrLow = stage_sge.addrLow;
		wqe->un.FcpCmd.Payload.tus.f.bdeSize = EMLXS_XFER_RDY_SIZE;
		wqe->un.FcpCmd.PayloadLength = EMLXS_XFER_RDY_SIZE;

	} else {	/* CMD_FCP_TSEND64_CX */
		/* First 2 SGEs are SKIP */
		stage_sge.addrHigh = 0;
		stage_sge.addrLow = 0;
		stage_sge.length = 0;
		stage_sge.offset = 0;
		stage_sge.type = EMLXS_SGE_TYPE_SKIP;
		stage_sge.last = 0;

		/* Words  0-3 */
		wqe->un.FcpCmd.Payload.addrHigh = PADDR_HI(fct_mp->phys);
		wqe->un.FcpCmd.Payload.addrLow = PADDR_LO(fct_mp->phys);

		/* The BDE should match the contents of the first SGE payload */
		len = MIN(EMLXS_MAX_SGE_SIZE, size);
		wqe->un.FcpCmd.Payload.tus.f.bdeSize = len;

		/* The PayloadLength should be set to 0 for TSEND64. */
		wqe->un.FcpCmd.PayloadLength = 0;
	}

	dbuf = sbp->fct_buf;
	/*
	 * TotalTransferCount equals to Relative Offset field (Word 4)
	 * in both TSEND64 and TRECEIVE64 WQE.
	 */
	wqe->un.FcpCmd.TotalTransferCount = dbuf->db_relative_offset;

	/* Copy staged SGE into SGL */
	BE_SWAP32_BCOPY((uint8_t *)&stage_sge,
	    (uint8_t *)sge, sizeof (ULP_SGE64));
	sge++;

	stage_sge.addrHigh = 0;
	stage_sge.addrLow = 0;
	stage_sge.length = 0;
	stage_sge.offset = 0;
	stage_sge.type = EMLXS_SGE_TYPE_SKIP;
	stage_sge.last = 0;

	/* Copy staged SGE into SGL */
	BE_SWAP32_BCOPY((uint8_t *)&stage_sge,
	    (uint8_t *)sge, sizeof (ULP_SGE64));
	sge++;

	sge_size = size;
	sge_addr = fct_mp->phys;
	cnt = 0;

	/* Build SGEs */
	while (sge_size) {
		if (cnt) {
			/* Copy staged SGE before we build next one */
			BE_SWAP32_BCOPY((uint8_t *)&stage_sge,
			    (uint8_t *)sge, sizeof (ULP_SGE64));
			sge++;
		}

		len = MIN(EMLXS_MAX_SGE_SIZE, sge_size);

		stage_sge.addrHigh = PADDR_HI(sge_addr);
		stage_sge.addrLow = PADDR_LO(sge_addr);
		stage_sge.length = len;
		stage_sge.offset = cnt;
		stage_sge.type = EMLXS_SGE_TYPE_DATA;

		sge_addr += len;
		sge_size -= len;
		cnt += len;
	}

	stage_sge.last = 1;

	if (hba->sli.sli4.flag & EMLXS_SLI4_PHON) {
		wqe->FirstData.addrHigh = stage_sge.addrHigh;
		wqe->FirstData.addrLow = stage_sge.addrLow;
		wqe->FirstData.tus.f.bdeSize = stage_sge.length;
	}
	/* Copy staged SGE into SGL */
	BE_SWAP32_BCOPY((uint8_t *)&stage_sge,
	    (uint8_t *)sge, sizeof (ULP_SGE64));

	return (0);

} /* emlxs_sli4_fct_bde_setup */
#endif /* SFCT_SUPPORT */


static void
emlxs_sli4_issue_iocb_cmd(emlxs_hba_t *hba, CHANNEL *cp, IOCBQ *iocbq)
{
	emlxs_port_t *port = &PPORT;
	emlxs_buf_t *sbp;
	uint32_t channelno;
	int32_t throttle;
	emlxs_wqe_t *wqe;
	emlxs_wqe_t *wqeslot;
	WQ_DESC_t *wq;
	uint32_t flag;
	uint32_t wqdb;
	uint16_t next_wqe;
	off_t offset;
#ifdef NODE_THROTTLE_SUPPORT
	int32_t node_throttle;
	NODELIST *marked_node = NULL;
#endif /* NODE_THROTTLE_SUPPORT */


	channelno = cp->channelno;
	wq = (WQ_DESC_t *)cp->iopath;

#ifdef DEBUG_FASTPATH
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "ISSUE WQE channel: %x  %p", channelno, wq);
#endif /* DEBUG_FASTPATH */

	throttle = 0;

	/* Check if FCP ring and adapter is not ready */
	/* We may use any ring for FCP_CMD */
	if (iocbq && (iocbq->flag & IOCB_FCP_CMD) && (hba->state != FC_READY)) {
		if (!(iocbq->flag & IOCB_SPECIAL) || !iocbq->port ||
		    (((emlxs_port_t *)iocbq->port)->mode == MODE_INITIATOR)) {
			emlxs_tx_put(iocbq, 1);
			return;
		}
	}

	/* Attempt to acquire CMD_RING lock */
	if (mutex_tryenter(&EMLXS_QUE_LOCK(channelno)) == 0) {
		/* Queue it for later */
		if (iocbq) {
			if ((hba->io_count -
			    hba->channel_tx_count) > 10) {
				emlxs_tx_put(iocbq, 1);
				return;
			} else {

				mutex_enter(&EMLXS_QUE_LOCK(channelno));
			}
		} else {
			return;
		}
	}
	/* EMLXS_QUE_LOCK acquired */

	/* Throttle check only applies to non special iocb */
	if (iocbq && (!(iocbq->flag & IOCB_SPECIAL))) {
		/* Check if HBA is full */
		throttle = hba->io_throttle - hba->io_active;
		if (throttle <= 0) {
			/* Hitting adapter throttle limit */
			/* Queue it for later */
			if (iocbq) {
				emlxs_tx_put(iocbq, 1);
			}

			goto busy;
		}
	}

	/* Check to see if we have room for this WQE */
	next_wqe = wq->host_index + 1;
	if (next_wqe >= wq->max_index) {
		next_wqe = 0;
	}

	if (next_wqe == wq->port_index) {
		/* Queue it for later */
		if (iocbq) {
			emlxs_tx_put(iocbq, 1);
		}
		goto busy;
	}

	/*
	 * We have a command ring slot available
	 * Make sure we have an iocb to send
	 */
	if (iocbq) {
		mutex_enter(&EMLXS_TX_CHANNEL_LOCK);

		/* Check if the ring already has iocb's waiting */
		if (cp->nodeq.q_first != NULL) {
			/* Put the current iocbq on the tx queue */
			emlxs_tx_put(iocbq, 0);

			/*
			 * Attempt to replace it with the next iocbq
			 * in the tx queue
			 */
			iocbq = emlxs_tx_get(cp, 0);
		}

		mutex_exit(&EMLXS_TX_CHANNEL_LOCK);
	} else {
		iocbq = emlxs_tx_get(cp, 1);
	}

sendit:
	/* Process each iocbq */
	while (iocbq) {
		sbp = iocbq->sbp;

#ifdef NODE_THROTTLE_SUPPORT
		if (sbp && sbp->node && sbp->node->io_throttle) {
			node_throttle = sbp->node->io_throttle -
			    sbp->node->io_active;
			if (node_throttle <= 0) {
				/* Node is busy */
				/* Queue this iocb and get next iocb from */
				/* channel */

				if (!marked_node) {
					marked_node = sbp->node;
				}

				mutex_enter(&EMLXS_TX_CHANNEL_LOCK);
				emlxs_tx_put(iocbq, 0);

				if (cp->nodeq.q_first == marked_node) {
					mutex_exit(&EMLXS_TX_CHANNEL_LOCK);
					goto busy;
				}

				iocbq = emlxs_tx_get(cp, 0);
				mutex_exit(&EMLXS_TX_CHANNEL_LOCK);
				continue;
			}
		}
		marked_node = 0;
#endif /* NODE_THROTTLE_SUPPORT */

		wqe = &iocbq->wqe;
#ifdef DEBUG_FASTPATH
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "ISSUE QID %d WQE iotag:%x xri:%d", wq->qid,
		    wqe->RequestTag, wqe->XRITag);
#endif /* DEBUG_FASTPATH */

		if (sbp) {
			/* If exchange removed after wqe was prep'ed, drop it */
			if (!(sbp->xrip)) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
				    "Xmit WQE iotag:%x xri:%d aborted",
				    wqe->RequestTag, wqe->XRITag);

				/* Get next iocb from the tx queue */
				iocbq = emlxs_tx_get(cp, 1);
				continue;
			}

			if (sbp->pkt_flags & PACKET_DELAY_REQUIRED) {

				/* Perform delay */
				if ((channelno == hba->channel_els) &&
				    !(iocbq->flag & IOCB_FCP_CMD)) {
					drv_usecwait(100000);
				} else {
					drv_usecwait(20000);
				}
			}

			/* Check for ULP pkt request */
			mutex_enter(&sbp->mtx);

			if (sbp->node == NULL) {
				/* Set node to base node by default */
				iocbq->node = (void *)&port->node_base;
				sbp->node = (void *)&port->node_base;
			}

			sbp->pkt_flags |= PACKET_IN_CHIPQ;
			mutex_exit(&sbp->mtx);

			atomic_inc_32(&hba->io_active);
#ifdef NODE_THROTTLE_SUPPORT
			if (sbp->node) {
				atomic_inc_32(&sbp->node->io_active);
			}
#endif /* NODE_THROTTLE_SUPPORT */

			sbp->xrip->flag |= EMLXS_XRI_PENDING_IO;
#ifdef SFCT_SUPPORT
#ifdef FCT_IO_TRACE
			if (sbp->fct_cmd) {
				emlxs_fct_io_trace(port, sbp->fct_cmd,
				    EMLXS_FCT_IOCB_ISSUED);
				emlxs_fct_io_trace(port, sbp->fct_cmd,
				    icmd->ULPCOMMAND);
			}
#endif /* FCT_IO_TRACE */
#endif /* SFCT_SUPPORT */
			cp->hbaSendCmd_sbp++;
			iocbq->channel = cp;
		} else {
			cp->hbaSendCmd++;
		}

		flag = iocbq->flag;

		/*
		 * At this point, we have a command ring slot available
		 * and an iocb to send
		 */
		wq->release_depth--;
		if (wq->release_depth == 0) {
			wq->release_depth = WQE_RELEASE_DEPTH;
			wqe->WQEC = 1;
		}

		HBASTATS.IocbIssued[channelno]++;
		wq->num_proc++;

		/* Send the iocb */
		wqeslot = (emlxs_wqe_t *)wq->addr.virt;
		wqeslot += wq->host_index;

		wqe->CQId = wq->cqid;
		if (hba->sli.sli4.param.PHWQ) {
			WQE_PHWQ_WQID(wqe, wq->qid);
		}
		BE_SWAP32_BCOPY((uint8_t *)wqe, (uint8_t *)wqeslot,
		    sizeof (emlxs_wqe_t));
#ifdef DEBUG_WQE
		emlxs_data_dump(port, "WQE", (uint32_t *)wqe, 18, 0);
#endif /* DEBUG_WQE */
		offset = (off_t)((uint64_t)((unsigned long)
		    wq->addr.virt) -
		    (uint64_t)((unsigned long)
		    hba->sli.sli4.slim2.virt));

		EMLXS_MPDATA_SYNC(wq->addr.dma_handle, offset,
		    4096, DDI_DMA_SYNC_FORDEV);

		/* Ring the WQ Doorbell */
		wqdb = wq->qid;
		wqdb |= ((1 << 24) | (wq->host_index << 16));

		/*
		 * After this, the sbp / iocb / wqe should not be
		 * accessed in the xmit path.
		 */

		emlxs_sli4_write_wqdb(hba, wqdb);
		wq->host_index = next_wqe;

#ifdef DEBUG_FASTPATH
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "WQ RING: %08x", wqdb);
#endif /* DEBUG_FASTPATH */

		if (!sbp) {
			emlxs_mem_put(hba, MEM_IOCB, (void *)iocbq);
		}

		if (iocbq && (!(flag & IOCB_SPECIAL))) {
			/* Check if HBA is full */
			throttle = hba->io_throttle - hba->io_active;
			if (throttle <= 0) {
				goto busy;
			}
		}

		/* Check to see if we have room for another WQE */
		next_wqe++;
		if (next_wqe >= wq->max_index) {
			next_wqe = 0;
		}

		if (next_wqe == wq->port_index) {
			/* Queue it for later */
			goto busy;
		}

		/* Get the next iocb from the tx queue if there is one */
		iocbq = emlxs_tx_get(cp, 1);
	}

	mutex_exit(&EMLXS_QUE_LOCK(channelno));

	return;

busy:
	wq->num_busy++;
	if (throttle <= 0) {
		HBASTATS.IocbThrottled++;
	} else {
		HBASTATS.IocbRingFull[channelno]++;
	}

	mutex_exit(&EMLXS_QUE_LOCK(channelno));

	return;

} /* emlxs_sli4_issue_iocb_cmd() */


/*ARGSUSED*/
static uint32_t
emlxs_sli4_issue_mq(emlxs_port_t *port, MAILBOX4 *mqe, MAILBOX *mb,
    uint32_t tmo)
{
	emlxs_hba_t *hba = HBA;
	MAILBOXQ	*mbq;
	MAILBOX4	*mb4;
	MATCHMAP	*mp;
	uint32_t	*iptr;
	uint32_t	mqdb;
	off_t		offset;

	mbq = (MAILBOXQ *)mb;
	mb4 = (MAILBOX4 *)mb;
	mp = (MATCHMAP *) mbq->nonembed;
	hba->mbox_mqe = (void *)mqe;

	if ((mb->mbxCommand != MBX_SLI_CONFIG) ||
	    (mb4->un.varSLIConfig.be.embedded)) {
		/*
		 * If this is an embedded mbox, everything should fit
		 * into the mailbox area.
		 */
		BE_SWAP32_BCOPY((uint8_t *)mb, (uint8_t *)mqe,
		    MAILBOX_CMD_SLI4_BSIZE);

		EMLXS_MPDATA_SYNC(hba->sli.sli4.mq.addr.dma_handle, 0,
		    4096, DDI_DMA_SYNC_FORDEV);

		if (mb->mbxCommand != MBX_HEARTBEAT) {
			emlxs_data_dump(port, "MBOX CMD", (uint32_t *)mqe,
			    18, 0);
		}
	} else {
		/* SLI_CONFIG and non-embedded */

		/*
		 * If this is not embedded, the MQ area
		 * MUST contain a SGE pointer to a larger area for the
		 * non-embedded mailbox command.
		 * mp will point to the actual mailbox command which
		 * should be copied into the non-embedded area.
		 */
		mb4->un.varSLIConfig.be.sge_cnt = 1;
		mb4->un.varSLIConfig.be.payload_length = mp->size;
		iptr = (uint32_t *)&mb4->un.varSLIConfig.be.un_hdr.hdr_req;
		*iptr++ = (uint32_t)PADDR_LO(mp->phys);
		*iptr++ = (uint32_t)PADDR_HI(mp->phys);
		*iptr = mp->size;

		BE_SWAP32_BUFFER(mp->virt, mp->size);

		EMLXS_MPDATA_SYNC(mp->dma_handle, 0, mp->size,
		    DDI_DMA_SYNC_FORDEV);

		BE_SWAP32_BCOPY((uint8_t *)mb, (uint8_t *)mqe,
		    MAILBOX_CMD_SLI4_BSIZE);

		offset = (off_t)((uint64_t)((unsigned long)
		    hba->sli.sli4.mq.addr.virt) -
		    (uint64_t)((unsigned long)
		    hba->sli.sli4.slim2.virt));

		EMLXS_MPDATA_SYNC(hba->sli.sli4.mq.addr.dma_handle, offset,
		    4096, DDI_DMA_SYNC_FORDEV);

		emlxs_data_dump(port, "MBOX EXT", (uint32_t *)mqe, 12, 0);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
		    "Extension Addr %p %p", mp->phys, (uint32_t *)(mp->virt));
		emlxs_data_dump(port, "EXT AREA", (uint32_t *)mp->virt, 24, 0);
	}

	/* Ring the MQ Doorbell */
	mqdb = hba->sli.sli4.mq.qid;
	mqdb |= ((1 << MQ_DB_POP_SHIFT) & MQ_DB_POP_MASK);

	if (mb->mbxCommand != MBX_HEARTBEAT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "MQ RING: %08x", mqdb);
	}

	emlxs_sli4_write_mqdb(hba, mqdb);

	return (MBX_SUCCESS);

} /* emlxs_sli4_issue_mq() */


/*ARGSUSED*/
static uint32_t
emlxs_sli4_issue_bootstrap(emlxs_hba_t *hba, MAILBOX *mb, uint32_t tmo)
{
	emlxs_port_t	*port = &PPORT;
	MAILBOXQ	*mbq;
	MAILBOX4	*mb4;
	MATCHMAP	*mp = NULL;
	uint32_t	*iptr;
	int		nonembed = 0;

	mbq = (MAILBOXQ *)mb;
	mb4 = (MAILBOX4 *)mb;
	mp = (MATCHMAP *) mbq->nonembed;
	hba->mbox_mqe = hba->sli.sli4.bootstrapmb.virt;

	if ((mb->mbxCommand != MBX_SLI_CONFIG) ||
	    (mb4->un.varSLIConfig.be.embedded)) {
		/*
		 * If this is an embedded mbox, everything should fit
		 * into the bootstrap mailbox area.
		 */
		iptr = (uint32_t *)hba->sli.sli4.bootstrapmb.virt;
		BE_SWAP32_BCOPY((uint8_t *)mb, (uint8_t *)iptr,
		    MAILBOX_CMD_SLI4_BSIZE);

		EMLXS_MPDATA_SYNC(hba->sli.sli4.bootstrapmb.dma_handle, 0,
		    MAILBOX_CMD_SLI4_BSIZE, DDI_DMA_SYNC_FORDEV);
		emlxs_data_dump(port, "MBOX CMD", iptr, 18, 0);
	} else {
		/*
		 * If this is not embedded, the bootstrap mailbox area
		 * MUST contain a SGE pointer to a larger area for the
		 * non-embedded mailbox command.
		 * mp will point to the actual mailbox command which
		 * should be copied into the non-embedded area.
		 */
		nonembed = 1;
		mb4->un.varSLIConfig.be.sge_cnt = 1;
		mb4->un.varSLIConfig.be.payload_length = mp->size;
		iptr = (uint32_t *)&mb4->un.varSLIConfig.be.un_hdr.hdr_req;
		*iptr++ = (uint32_t)PADDR_LO(mp->phys);
		*iptr++ = (uint32_t)PADDR_HI(mp->phys);
		*iptr = mp->size;

		BE_SWAP32_BUFFER(mp->virt, mp->size);

		EMLXS_MPDATA_SYNC(mp->dma_handle, 0, mp->size,
		    DDI_DMA_SYNC_FORDEV);

		iptr = (uint32_t *)hba->sli.sli4.bootstrapmb.virt;
		BE_SWAP32_BCOPY((uint8_t *)mb, (uint8_t *)iptr,
		    MAILBOX_CMD_SLI4_BSIZE);

		EMLXS_MPDATA_SYNC(hba->sli.sli4.bootstrapmb.dma_handle, 0,
		    EMLXS_BOOTSTRAP_MB_SIZE + MBOX_EXTENSION_SIZE,
		    DDI_DMA_SYNC_FORDEV);

		emlxs_data_dump(port, "MBOX EXT", iptr, 12, 0);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
		    "Extension Addr %p %p", mp->phys,
		    (uint32_t *)((uint8_t *)mp->virt));
		iptr = (uint32_t *)((uint8_t *)mp->virt);
		emlxs_data_dump(port, "EXT AREA", (uint32_t *)mp->virt, 24, 0);
	}


	/* NOTE: tmo is in 10ms ticks */
	if (!emlxs_issue_bootstrap_mb(hba, tmo)) {
		return (MBX_TIMEOUT);
	}

	if ((mb->mbxCommand != MBX_SLI_CONFIG) ||
	    (mb4->un.varSLIConfig.be.embedded)) {
		EMLXS_MPDATA_SYNC(hba->sli.sli4.bootstrapmb.dma_handle, 0,
		    MAILBOX_CMD_SLI4_BSIZE, DDI_DMA_SYNC_FORKERNEL);

		iptr = (uint32_t *)hba->sli.sli4.bootstrapmb.virt;
		BE_SWAP32_BCOPY((uint8_t *)iptr, (uint8_t *)mb,
		    MAILBOX_CMD_SLI4_BSIZE);

		emlxs_data_dump(port, "MBOX CMP", iptr, 18, 0);

	} else {
		EMLXS_MPDATA_SYNC(hba->sli.sli4.bootstrapmb.dma_handle, 0,
		    EMLXS_BOOTSTRAP_MB_SIZE + MBOX_EXTENSION_SIZE,
		    DDI_DMA_SYNC_FORKERNEL);

		EMLXS_MPDATA_SYNC(mp->dma_handle, 0, mp->size,
		    DDI_DMA_SYNC_FORKERNEL);

		BE_SWAP32_BUFFER(mp->virt, mp->size);

		iptr = (uint32_t *)hba->sli.sli4.bootstrapmb.virt;
		BE_SWAP32_BCOPY((uint8_t *)iptr, (uint8_t *)mb,
		    MAILBOX_CMD_SLI4_BSIZE);

		emlxs_data_dump(port, "MBOX CMP", iptr, 12, 0);
		iptr = (uint32_t *)((uint8_t *)mp->virt);
		emlxs_data_dump(port, "EXT AREA", (uint32_t *)iptr, 24, 0);
	}

#ifdef FMA_SUPPORT
	if (nonembed && mp) {
		if (emlxs_fm_check_dma_handle(hba, mp->dma_handle)
		    != DDI_FM_OK) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_invalid_dma_handle_msg,
			    "sli4_issue_bootstrap: mp_hdl=%p",
			    mp->dma_handle);
			return (MBXERR_DMA_ERROR);
		}
	}

	if (emlxs_fm_check_dma_handle(hba,
	    hba->sli.sli4.bootstrapmb.dma_handle)
	    != DDI_FM_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_invalid_dma_handle_msg,
		    "sli4_issue_bootstrap: hdl=%p",
		    hba->sli.sli4.bootstrapmb.dma_handle);
		return (MBXERR_DMA_ERROR);
	}
#endif

	return (MBX_SUCCESS);

} /* emlxs_sli4_issue_bootstrap() */


/*ARGSUSED*/
static uint32_t
emlxs_sli4_issue_mbox_cmd(emlxs_hba_t *hba, MAILBOXQ *mbq, int32_t flag,
    uint32_t tmo)
{
	emlxs_port_t	*port;
	MAILBOX4	*mb4;
	MAILBOX		*mb;
	mbox_rsp_hdr_t	*hdr_rsp;
	MATCHMAP	*mp;
	uint32_t	*iptr;
	uint32_t	rc;
	uint32_t	i;
	uint32_t	tmo_local;

	if (!mbq->port) {
		mbq->port = &PPORT;
	}

	port = (emlxs_port_t *)mbq->port;

	mb4 = (MAILBOX4 *)mbq;
	mb = (MAILBOX *)mbq;

	mb->mbxStatus = MBX_SUCCESS;
	rc = MBX_SUCCESS;

	/* Check for minimum timeouts */
	switch (mb->mbxCommand) {
	/* Mailbox commands that erase/write flash */
	case MBX_DOWN_LOAD:
	case MBX_UPDATE_CFG:
	case MBX_LOAD_AREA:
	case MBX_LOAD_EXP_ROM:
	case MBX_WRITE_NV:
	case MBX_FLASH_WR_ULA:
	case MBX_DEL_LD_ENTRY:
	case MBX_LOAD_SM:
	case MBX_DUMP_MEMORY:
	case MBX_WRITE_VPARMS:
	case MBX_ACCESS_VDATA:
		if (tmo < 300) {
			tmo = 300;
		}
		break;

	case MBX_SLI_CONFIG: {
		mbox_req_hdr_t *hdr_req;

		hdr_req = (mbox_req_hdr_t *)
		    &mb4->un.varSLIConfig.be.un_hdr.hdr_req;

		if (hdr_req->subsystem == IOCTL_SUBSYSTEM_COMMON) {
			switch (hdr_req->opcode) {
			case COMMON_OPCODE_WRITE_OBJ:
			case COMMON_OPCODE_READ_OBJ:
			case COMMON_OPCODE_READ_OBJ_LIST:
			case COMMON_OPCODE_DELETE_OBJ:
			case COMMON_OPCODE_SET_BOOT_CFG:
			case COMMON_OPCODE_GET_PROFILE_CFG:
			case COMMON_OPCODE_SET_PROFILE_CFG:
			case COMMON_OPCODE_GET_PROFILE_LIST:
			case COMMON_OPCODE_SET_ACTIVE_PROFILE:
			case COMMON_OPCODE_GET_PROFILE_CAPS:
			case COMMON_OPCODE_GET_MR_PROFILE_CAPS:
			case COMMON_OPCODE_SET_MR_PROFILE_CAPS:
			case COMMON_OPCODE_SET_FACTORY_PROFILE_CFG:
			case COMMON_OPCODE_SEND_ACTIVATION:
			case COMMON_OPCODE_RESET_LICENSES:
			case COMMON_OPCODE_SET_PHYSICAL_LINK_CFG_V1:
			case COMMON_OPCODE_GET_VPD_DATA:
				if (tmo < 300) {
					tmo = 300;
				}
				break;
			default:
				if (tmo < 30) {
					tmo = 30;
				}
			}
		} else if (hdr_req->subsystem == IOCTL_SUBSYSTEM_FCOE) {
			switch (hdr_req->opcode) {
			case FCOE_OPCODE_SET_FCLINK_SETTINGS:
				if (tmo < 300) {
					tmo = 300;
				}
				break;
			default:
				if (tmo < 30) {
					tmo = 30;
				}
			}
		} else {
			if (tmo < 30) {
				tmo = 30;
			}
		}

		/*
		 * Also: VENDOR_MANAGE_FFV  (0x13, 0x02) (not currently used)
		 */

		break;
	}
	default:
		if (tmo < 30) {
			tmo = 30;
		}
		break;
	}

	/* Convert tmo seconds to 10 millisecond tics */
	tmo_local = tmo * 100;

	mutex_enter(&EMLXS_PORT_LOCK);

	/* Adjust wait flag */
	if (flag != MBX_NOWAIT) {
		if (hba->sli.sli4.flag & EMLXS_SLI4_INTR_ENABLED) {
			flag = MBX_SLEEP;
		} else {
			flag = MBX_POLL;
		}
	} else {
		/* Must have interrupts enabled to perform MBX_NOWAIT */
		if (!(hba->sli.sli4.flag & EMLXS_SLI4_INTR_ENABLED)) {

			mb->mbxStatus = MBX_HARDWARE_ERROR;
			mutex_exit(&EMLXS_PORT_LOCK);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
			    "Interrupts disabled. %s failed.",
			    emlxs_mb_cmd_xlate(mb->mbxCommand));

			return (MBX_HARDWARE_ERROR);
		}
	}

	/* Check for hardware error ; special case SLI_CONFIG */
	if ((hba->flag & FC_HARDWARE_ERROR) &&
	    ! ((mb4->mbxCommand == MBX_SLI_CONFIG) &&
	    (mb4->un.varSLIConfig.be.un_hdr.hdr_req.opcode ==
	    COMMON_OPCODE_RESET))) {
		mb->mbxStatus = MBX_HARDWARE_ERROR;

		mutex_exit(&EMLXS_PORT_LOCK);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
		    "Hardware error reported. %s failed. status=%x mb=%p",
		    emlxs_mb_cmd_xlate(mb->mbxCommand), mb->mbxStatus, mb);

		return (MBX_HARDWARE_ERROR);
	}

	if (hba->mbox_queue_flag) {
		/* If we are not polling, then queue it for later */
		if (flag == MBX_NOWAIT) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
			    "Busy.      %s: mb=%p NoWait.",
			    emlxs_mb_cmd_xlate(mb->mbxCommand), mb);

			emlxs_mb_put(hba, mbq);

			HBASTATS.MboxBusy++;

			mutex_exit(&EMLXS_PORT_LOCK);

			return (MBX_BUSY);
		}

		while (hba->mbox_queue_flag) {
			mutex_exit(&EMLXS_PORT_LOCK);

			if (tmo_local-- == 0) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_mbox_event_msg,
				    "Timeout.   %s: mb=%p tmo=%d Waiting.",
				    emlxs_mb_cmd_xlate(mb->mbxCommand), mb,
				    tmo);

				/* Non-lethalStatus mailbox timeout */
				/* Does not indicate a hardware error */
				mb->mbxStatus = MBX_TIMEOUT;
				return (MBX_TIMEOUT);
			}

			BUSYWAIT_MS(10);
			mutex_enter(&EMLXS_PORT_LOCK);

			/* Check for hardware error ; special case SLI_CONFIG */
			if ((hba->flag & FC_HARDWARE_ERROR) &&
			    ! ((mb4->mbxCommand == MBX_SLI_CONFIG) &&
			    (mb4->un.varSLIConfig.be.un_hdr.hdr_req.opcode ==
			    COMMON_OPCODE_RESET))) {
				mb->mbxStatus = MBX_HARDWARE_ERROR;

				mutex_exit(&EMLXS_PORT_LOCK);

				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_mbox_detail_msg,
				    "Hardware error reported. %s failed. "
				    "status=%x mb=%p",
				    emlxs_mb_cmd_xlate(mb->mbxCommand),
				    mb->mbxStatus, mb);

				return (MBX_HARDWARE_ERROR);
			}
		}
	}

	/* Initialize mailbox area */
	emlxs_mb_init(hba, mbq, flag, tmo);

	if (mb->mbxCommand == MBX_DOWN_LINK) {
		hba->sli.sli4.flag |= EMLXS_SLI4_DOWN_LINK;
	}

	mutex_exit(&EMLXS_PORT_LOCK);
	switch (flag) {

	case MBX_NOWAIT:
		if (mb->mbxCommand != MBX_HEARTBEAT) {
			if (mb->mbxCommand != MBX_DOWN_LOAD
			    /* && mb->mbxCommand != MBX_DUMP_MEMORY */) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_mbox_detail_msg,
				    "Sending.   %s: mb=%p NoWait. embedded %d",
				    emlxs_mb_cmd_xlate(mb->mbxCommand), mb,
				    ((mb->mbxCommand != MBX_SLI_CONFIG) ? 1 :
				    (mb4->un.varSLIConfig.be.embedded)));
			}
		}

		iptr = hba->sli.sli4.mq.addr.virt;
		iptr += (hba->sli.sli4.mq.host_index * MAILBOX_CMD_SLI4_WSIZE);
		hba->sli.sli4.mq.host_index++;
		if (hba->sli.sli4.mq.host_index >= hba->sli.sli4.mq.max_index) {
			hba->sli.sli4.mq.host_index = 0;
		}

		if (mbq->bp) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
			    "BDE virt %p phys %p size x%x",
			    ((MATCHMAP *)mbq->bp)->virt,
			    ((MATCHMAP *)mbq->bp)->phys,
			    ((MATCHMAP *)mbq->bp)->size);
			emlxs_data_dump(port, "DATA",
			    (uint32_t *)(((MATCHMAP *)mbq->bp)->virt), 30, 0);
		}
		rc = emlxs_sli4_issue_mq(port, (MAILBOX4 *)iptr, mb, tmo_local);
		break;

	case MBX_POLL:
		if (mb->mbxCommand != MBX_DOWN_LOAD
		    /* && mb->mbxCommand != MBX_DUMP_MEMORY */) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
			    "Sending.   %s: mb=%p Poll. embedded %d",
			    emlxs_mb_cmd_xlate(mb->mbxCommand), mb,
			    ((mb->mbxCommand != MBX_SLI_CONFIG) ? 1 :
			    (mb4->un.varSLIConfig.be.embedded)));
		}

		rc = emlxs_sli4_issue_bootstrap(hba, mb, tmo_local);

		/* Clean up the mailbox area */
		if (rc == MBX_TIMEOUT) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
			    "Timeout.   %s: mb=%p tmo=%x Poll. embedded %d",
			    emlxs_mb_cmd_xlate(mb->mbxCommand), mb, tmo,
			    ((mb->mbxCommand != MBX_SLI_CONFIG) ? 1 :
			    (mb4->un.varSLIConfig.be.embedded)));

			hba->flag |= FC_MBOX_TIMEOUT;
			EMLXS_STATE_CHANGE(hba, FC_ERROR);
			emlxs_mb_fini(hba, NULL, MBX_TIMEOUT);

		} else {
			if (mb->mbxCommand != MBX_DOWN_LOAD
			    /* && mb->mbxCommand != MBX_DUMP_MEMORY */) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_mbox_detail_msg,
				    "Completed.   %s: mb=%p status=%x Poll. "
				    "embedded %d",
				    emlxs_mb_cmd_xlate(mb->mbxCommand), mb, rc,
				    ((mb->mbxCommand != MBX_SLI_CONFIG) ? 1 :
				    (mb4->un.varSLIConfig.be.embedded)));
			}

			/* Process the result */
			if (!(mbq->flag & MBQ_PASSTHRU)) {
				if (mbq->mbox_cmpl) {
					(void) (mbq->mbox_cmpl)(hba, mbq);
				}
			}

			emlxs_mb_fini(hba, NULL, mb->mbxStatus);
		}

		mp = (MATCHMAP *)mbq->nonembed;
		if (mp) {
			hdr_rsp = (mbox_rsp_hdr_t *)mp->virt;
			if (hdr_rsp->status) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_mbox_detail_msg,
				    "%s: MBX_NONEMBED_ERROR: 0x%x, 0x%x",
				    emlxs_mb_cmd_xlate(mb->mbxCommand),
				    hdr_rsp->status, hdr_rsp->extra_status);

				mb->mbxStatus = MBX_NONEMBED_ERROR;
			}
		}
		rc = mb->mbxStatus;

		/* Attempt to send pending mailboxes */
		mbq = (MAILBOXQ *)emlxs_mb_get(hba);
		if (mbq) {
			/* Attempt to send pending mailboxes */
			i =  emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_NOWAIT, 0);
			if ((i != MBX_BUSY) && (i != MBX_SUCCESS)) {
				emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);
			}
		}
		break;

	case MBX_SLEEP:
		if (mb->mbxCommand != MBX_DOWN_LOAD
		    /* && mb->mbxCommand != MBX_DUMP_MEMORY */) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
			    "Sending.   %s: mb=%p Sleep. embedded %d",
			    emlxs_mb_cmd_xlate(mb->mbxCommand), mb,
			    ((mb->mbxCommand != MBX_SLI_CONFIG) ? 1 :
			    (mb4->un.varSLIConfig.be.embedded)));
		}

		iptr = hba->sli.sli4.mq.addr.virt;
		iptr += (hba->sli.sli4.mq.host_index * MAILBOX_CMD_SLI4_WSIZE);
		hba->sli.sli4.mq.host_index++;
		if (hba->sli.sli4.mq.host_index >= hba->sli.sli4.mq.max_index) {
			hba->sli.sli4.mq.host_index = 0;
		}

		rc = emlxs_sli4_issue_mq(port, (MAILBOX4 *)iptr, mb, tmo_local);

		if (rc != MBX_SUCCESS) {
			break;
		}

		/* Wait for completion */
		/* The driver clock is timing the mailbox. */

		mutex_enter(&EMLXS_MBOX_LOCK);
		while (!(mbq->flag & MBQ_COMPLETED)) {
			cv_wait(&EMLXS_MBOX_CV, &EMLXS_MBOX_LOCK);
		}
		mutex_exit(&EMLXS_MBOX_LOCK);

		mp = (MATCHMAP *)mbq->nonembed;
		if (mp) {
			hdr_rsp = (mbox_rsp_hdr_t *)mp->virt;
			if (hdr_rsp->status) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_mbox_detail_msg,
				    "%s: MBX_NONEMBED_ERROR: 0x%x, 0x%x",
				    emlxs_mb_cmd_xlate(mb->mbxCommand),
				    hdr_rsp->status, hdr_rsp->extra_status);

				mb->mbxStatus = MBX_NONEMBED_ERROR;
			}
		}
		rc = mb->mbxStatus;

		if (rc == MBX_TIMEOUT) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
			    "Timeout.   %s: mb=%p tmo=%x Sleep. embedded %d",
			    emlxs_mb_cmd_xlate(mb->mbxCommand), mb, tmo,
			    ((mb->mbxCommand != MBX_SLI_CONFIG) ? 1 :
			    (mb4->un.varSLIConfig.be.embedded)));
		} else {
			if (mb->mbxCommand != MBX_DOWN_LOAD
			    /* && mb->mbxCommand != MBX_DUMP_MEMORY */) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_mbox_detail_msg,
				    "Completed.   %s: mb=%p status=%x Sleep. "
				    "embedded %d",
				    emlxs_mb_cmd_xlate(mb->mbxCommand), mb, rc,
				    ((mb->mbxCommand != MBX_SLI_CONFIG) ? 1 :
				    (mb4->un.varSLIConfig.be.embedded)));
			}
		}
		break;
	}

	return (rc);

} /* emlxs_sli4_issue_mbox_cmd() */



/*ARGSUSED*/
static uint32_t
emlxs_sli4_issue_mbox_cmd4quiesce(emlxs_hba_t *hba, MAILBOXQ *mbq, int32_t flag,
    uint32_t tmo)
{
	emlxs_port_t	*port = &PPORT;
	MAILBOX		*mb;
	mbox_rsp_hdr_t	*hdr_rsp;
	MATCHMAP	*mp;
	uint32_t	rc;
	uint32_t	tmo_local;

	mb = (MAILBOX *)mbq;

	mb->mbxStatus = MBX_SUCCESS;
	rc = MBX_SUCCESS;

	if (tmo < 30) {
		tmo = 30;
	}

	/* Convert tmo seconds to 10 millisecond tics */
	tmo_local = tmo * 100;

	flag = MBX_POLL;

	/* Check for hardware error */
	if (hba->flag & FC_HARDWARE_ERROR) {
		mb->mbxStatus = MBX_HARDWARE_ERROR;
		return (MBX_HARDWARE_ERROR);
	}

	/* Initialize mailbox area */
	emlxs_mb_init(hba, mbq, flag, tmo);

	switch (flag) {

	case MBX_POLL:

		rc = emlxs_sli4_issue_bootstrap(hba, mb, tmo_local);

		/* Clean up the mailbox area */
		if (rc == MBX_TIMEOUT) {
			hba->flag |= FC_MBOX_TIMEOUT;
			EMLXS_STATE_CHANGE(hba, FC_ERROR);
			emlxs_mb_fini(hba, NULL, MBX_TIMEOUT);

		} else {
			/* Process the result */
			if (!(mbq->flag & MBQ_PASSTHRU)) {
				if (mbq->mbox_cmpl) {
					(void) (mbq->mbox_cmpl)(hba, mbq);
				}
			}

			emlxs_mb_fini(hba, NULL, mb->mbxStatus);
		}

		mp = (MATCHMAP *)mbq->nonembed;
		if (mp) {
			hdr_rsp = (mbox_rsp_hdr_t *)mp->virt;
			if (hdr_rsp->status) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_mbox_detail_msg,
				    "%s: MBX_NONEMBED_ERROR: 0x%x, 0x%x",
				    emlxs_mb_cmd_xlate(mb->mbxCommand),
				    hdr_rsp->status, hdr_rsp->extra_status);

				mb->mbxStatus = MBX_NONEMBED_ERROR;
			}
		}
		rc = mb->mbxStatus;

		break;
	}

	return (rc);

} /* emlxs_sli4_issue_mbox_cmd4quiesce() */



#ifdef SFCT_SUPPORT
/*ARGSUSED*/
extern uint32_t
emlxs_sli4_prep_fct_iocb(emlxs_port_t *port, emlxs_buf_t *cmd_sbp, int channel)
{
	emlxs_hba_t *hba = HBA;
	emlxs_config_t *cfg = &CFG;
	fct_cmd_t *fct_cmd;
	stmf_data_buf_t *dbuf;
	scsi_task_t *fct_task;
	fc_packet_t *pkt;
	CHANNEL *cp;
	XRIobj_t *xrip;
	emlxs_node_t *ndlp;
	IOCBQ *iocbq;
	IOCB *iocb;
	emlxs_wqe_t *wqe;
	ULP_SGE64 stage_sge;
	ULP_SGE64 *sge;
	RPIobj_t *rpip;
	int32_t	sge_size;
	uint64_t sge_addr;
	uint32_t did;
	uint32_t timeout;

	ddi_dma_cookie_t *cp_cmd;

	pkt = PRIV2PKT(cmd_sbp);

	cp = (CHANNEL *)cmd_sbp->channel;

	iocbq = &cmd_sbp->iocbq;
	iocb = &iocbq->iocb;

	did = cmd_sbp->did;
	if (iocb->ULPCOMMAND == CMD_ABORT_XRI_CX) {

		ndlp = cmd_sbp->node;
		rpip = EMLXS_NODE_TO_RPI(port, ndlp);

		if (!rpip) {
			/* Use the fabric rpi */
			rpip = port->vpip->fabric_rpip;
		}

		/* Next allocate an Exchange for this command */
		xrip = emlxs_sli4_alloc_xri(port, cmd_sbp, rpip,
		    EMLXS_XRI_SOL_BLS_TYPE);

		if (!xrip) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
			    "Adapter Busy. Unable to allocate exchange. "
			    "did=0x%x", did);

			return (FC_TRAN_BUSY);
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "FCT Abort Request: xri=%d iotag=%d sbp=%p rxid=%x",
		    xrip->XRI, xrip->iotag, cmd_sbp, pkt->pkt_cmd_fhdr.rx_id);

		cmd_sbp->xrip = xrip;

		cp->ulpSendCmd++;

		/* Initalize iocbq */
		iocbq->port = (void *)port;
		iocbq->node = (void *)ndlp;
		iocbq->channel = (void *)cp;

		/*
		 * Don't give the abort priority, we want the IOCB
		 * we are aborting to be processed first.
		 */
		iocbq->flag |= IOCB_SPECIAL;

		wqe = &iocbq->wqe;
		bzero((void *)wqe, sizeof (emlxs_wqe_t));

		wqe = &iocbq->wqe;
		wqe->un.Abort.Criteria = ABORT_XRI_TAG;
		wqe->RequestTag = xrip->iotag;
		wqe->AbortTag = pkt->pkt_cmd_fhdr.rx_id;
		wqe->Command = CMD_ABORT_XRI_CX;
		wqe->Class = CLASS3;
		wqe->CQId = 0xffff;
		wqe->CmdType = WQE_TYPE_ABORT;

		if (hba->state >= FC_LINK_UP) {
			wqe->un.Abort.IA = 0;
		} else {
			wqe->un.Abort.IA = 1;
		}

		/* Set the pkt timer */
		cmd_sbp->ticks = hba->timer_tics + pkt->pkt_timeout +
		    ((pkt->pkt_timeout > 0xff) ? 0 : 10);

		return (IOERR_SUCCESS);

	} else if (iocb->ULPCOMMAND == CMD_FCP_TRSP64_CX) {

		timeout = pkt->pkt_timeout;
		ndlp = cmd_sbp->node;
		if (!ndlp) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
			    "Unable to find rpi. did=0x%x", did);

			emlxs_set_pkt_state(cmd_sbp, IOSTAT_LOCAL_REJECT,
			    IOERR_INVALID_RPI, 0);
			return (0xff);
		}

		cp->ulpSendCmd++;

		/* Initalize iocbq */
		iocbq->port = (void *)port;
		iocbq->node = (void *)ndlp;
		iocbq->channel = (void *)cp;

		wqe = &iocbq->wqe;
		bzero((void *)wqe, sizeof (emlxs_wqe_t));

		xrip = emlxs_sli4_register_xri(port, cmd_sbp,
		    pkt->pkt_cmd_fhdr.rx_id, did);

		if (!xrip) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
			    "Unable to register xri %x. did=0x%x",
			    pkt->pkt_cmd_fhdr.rx_id, did);

			emlxs_set_pkt_state(cmd_sbp, IOSTAT_LOCAL_REJECT,
			    IOERR_NO_XRI, 0);
			return (0xff);
		}

		cmd_sbp->iotag = xrip->iotag;
		cmd_sbp->channel = cp;

#if (EMLXS_MODREV >= EMLXS_MODREV3)
		cp_cmd = pkt->pkt_cmd_cookie;
#else
		cp_cmd  = &pkt->pkt_cmd_cookie;
#endif	/* >= EMLXS_MODREV3 */

		sge_size = pkt->pkt_cmdlen;
		/* Make size a multiple of 4 */
		if (sge_size & 3) {
			sge_size = (sge_size + 3) & 0xfffffffc;
		}
		sge_addr = cp_cmd->dmac_laddress;
		sge = xrip->SGList.virt;

		stage_sge.addrHigh = PADDR_HI(sge_addr);
		stage_sge.addrLow = PADDR_LO(sge_addr);
		stage_sge.length = sge_size;
		stage_sge.offset = 0;
		stage_sge.type = 0;
		stage_sge.last = 1;

		/* Copy staged SGE into SGL */
		BE_SWAP32_BCOPY((uint8_t *)&stage_sge,
		    (uint8_t *)sge, sizeof (ULP_SGE64));

		/* Words  0-3 */
		wqe->un.FcpCmd.Payload.addrHigh = stage_sge.addrHigh;
		wqe->un.FcpCmd.Payload.addrLow = stage_sge.addrLow;
		wqe->un.FcpCmd.Payload.tus.f.bdeSize = sge_size;
		wqe->un.FcpCmd.PayloadLength = sge_size;

		/*  Word  6 */
		wqe->ContextTag = ndlp->nlp_Rpi;
		wqe->XRITag = xrip->XRI;

		/*  Word  7 */
		wqe->Command  = iocb->ULPCOMMAND;
		wqe->Class = cmd_sbp->class;
		wqe->ContextType = WQE_RPI_CONTEXT;
		wqe->Timer = ((timeout > 0xff) ? 0 : timeout);

		/*  Word  8 */
		wqe->AbortTag = 0;

		/*  Word  9 */
		wqe->RequestTag = xrip->iotag;
		wqe->OXId = (uint16_t)xrip->rx_id;

		/*  Word  10 */
		if (xrip->flag & EMLXS_XRI_BUSY) {
			wqe->XC = 1;
		}

		if (!(hba->sli.sli4.param.PHWQ)) {
			wqe->QOSd = 1;
			wqe->DBDE = 1; /* Data type for BDE 0 */
		}

		/*  Word  11 */
		wqe->CmdType = WQE_TYPE_TRSP;
		wqe->CQId = (uint16_t)0xffff;  /* default CQ for response */

		/* Set the pkt timer */
		cmd_sbp->ticks = hba->timer_tics + timeout +
		    ((timeout > 0xff) ? 0 : 10);

		if (pkt->pkt_cmdlen) {
			EMLXS_MPDATA_SYNC(pkt->pkt_cmd_dma, 0, pkt->pkt_cmdlen,
			    DDI_DMA_SYNC_FORDEV);
		}

		return (IOERR_SUCCESS);
	}

	fct_cmd = cmd_sbp->fct_cmd;
	did = fct_cmd->cmd_rportid;
	dbuf = cmd_sbp->fct_buf;
	fct_task = (scsi_task_t *)fct_cmd->cmd_specific;
	ndlp = *(emlxs_node_t **)fct_cmd->cmd_rp->rp_fca_private;
	if (!ndlp) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Unable to find rpi. did=0x%x", did);

		emlxs_set_pkt_state(cmd_sbp, IOSTAT_LOCAL_REJECT,
		    IOERR_INVALID_RPI, 0);
		return (0xff);
	}


	/* Initalize iocbq */
	iocbq->port = (void *) port;
	iocbq->node = (void *)ndlp;
	iocbq->channel = (void *) cp;

	wqe = &iocbq->wqe;
	bzero((void *)wqe, sizeof (emlxs_wqe_t));

	xrip = cmd_sbp->xrip;
	if (!xrip) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Unable to find xri. did=0x%x", did);

		emlxs_set_pkt_state(cmd_sbp, IOSTAT_LOCAL_REJECT,
		    IOERR_NO_XRI, 0);
		return (0xff);
	}

	if (emlxs_sli4_register_xri(port, cmd_sbp,
	    xrip->XRI, ndlp->nlp_DID) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Unable to register xri. did=0x%x", did);

		emlxs_set_pkt_state(cmd_sbp, IOSTAT_LOCAL_REJECT,
		    IOERR_NO_XRI, 0);
		return (0xff);
	}
	cmd_sbp->iotag = xrip->iotag;
	cmd_sbp->channel = cp;

	if (cfg[CFG_TIMEOUT_ENABLE].current) {
		timeout =
		    ((2 * hba->fc_ratov) < 60) ? 60 : (2 * hba->fc_ratov);
	} else {
		timeout = 0x80000000;
	}
	cmd_sbp->ticks =
	    hba->timer_tics + timeout + ((timeout > 0xff) ? 0 : 10);


	iocb->ULPCT = 0;
	if (fct_task->task_flags & TF_WRITE_DATA) {
		iocb->ULPCOMMAND = CMD_FCP_TRECEIVE64_CX;
		wqe->CmdType = WQE_TYPE_TRECEIVE;		/* Word 11 */

	} else { /* TF_READ_DATA */

		iocb->ULPCOMMAND = CMD_FCP_TSEND64_CX;
		wqe->CmdType = WQE_TYPE_TSEND;			/* Word 11 */

		if ((dbuf->db_data_size >=
		    fct_task->task_expected_xfer_length)) {
			/* enable auto-rsp AP feature */
			wqe->AR = 0x1;
			iocb->ULPCT = 0x1; /* for cmpl */
		}
	}

	(void) emlxs_sli4_fct_bde_setup(port, cmd_sbp);

	/*  Word  6 */
	wqe->ContextTag = ndlp->nlp_Rpi;
	wqe->XRITag = xrip->XRI;

	/*  Word  7 */
	wqe->Command  = iocb->ULPCOMMAND;
	wqe->Class = cmd_sbp->class;
	wqe->ContextType = WQE_RPI_CONTEXT;
	wqe->Timer = ((timeout > 0xff) ? 0 : timeout);
	wqe->PU = 1;

	/*  Word  8 */
	wqe->AbortTag = 0;

	/*  Word  9 */
	wqe->RequestTag = xrip->iotag;
	wqe->OXId = (uint16_t)fct_cmd->cmd_oxid;

	/*  Word  10 */
	if (xrip->flag & EMLXS_XRI_BUSY) {
		wqe->XC = 1;
	}

	if (!(hba->sli.sli4.param.PHWQ)) {
		wqe->QOSd = 1;
		wqe->DBDE = 1; /* Data type for BDE 0 */
	}

	/*  Word  11 */
	wqe->CQId = (uint16_t)0xffff;  /* default CQ for response */

	/*  Word  12 */
	wqe->CmdSpecific = dbuf->db_data_size;

	return (IOERR_SUCCESS);

} /* emlxs_sli4_prep_fct_iocb() */
#endif /* SFCT_SUPPORT */


/*ARGSUSED*/
extern uint32_t
emlxs_sli4_prep_fcp_iocb(emlxs_port_t *port, emlxs_buf_t *sbp, int channel)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	CHANNEL *cp;
	RPIobj_t *rpip;
	XRIobj_t *xrip;
	emlxs_wqe_t *wqe;
	IOCBQ *iocbq;
	IOCB *iocb;
	NODELIST *node;
	uint16_t iotag;
	uint32_t did;
	off_t offset;

	pkt = PRIV2PKT(sbp);
	did = LE_SWAP24_LO(pkt->pkt_cmd_fhdr.d_id);
	cp = &hba->chan[channel];

	iocbq = &sbp->iocbq;
	iocbq->channel = (void *) cp;
	iocbq->port = (void *) port;

	wqe = &iocbq->wqe;
	iocb = &iocbq->iocb;
	bzero((void *)wqe, sizeof (emlxs_wqe_t));
	bzero((void *)iocb, sizeof (IOCB));

	/* Find target node object */
	node = (NODELIST *)iocbq->node;
	rpip = EMLXS_NODE_TO_RPI(port, node);

	if (!rpip) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Unable to find rpi. did=0x%x", did);

		emlxs_set_pkt_state(sbp, IOSTAT_LOCAL_REJECT,
		    IOERR_INVALID_RPI, 0);
		return (0xff);
	}

	sbp->channel = cp;
	/* Next allocate an Exchange for this command */
	xrip = emlxs_sli4_alloc_xri(port, sbp, rpip,
	    EMLXS_XRI_SOL_FCP_TYPE);

	if (!xrip) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to allocate exchange. did=0x%x", did);

		return (FC_TRAN_BUSY);
	}
	sbp->bmp = NULL;
	iotag = sbp->iotag;

#ifdef DEBUG_FASTPATH
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "FCP: Prep xri=%d iotag=%d oxid=%x rpi=%d",
	    xrip->XRI, xrip->iotag, xrip->rx_id, rpip->RPI);
#endif /* DEBUG_FASTPATH */

	/* Indicate this is a FCP cmd */
	iocbq->flag |= IOCB_FCP_CMD;

	if (emlxs_sli4_bde_setup(port, sbp)) {
		emlxs_sli4_free_xri(port, sbp, xrip, 1);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to setup SGE. did=0x%x", did);

		return (FC_TRAN_BUSY);
	}

	/* DEBUG */
#ifdef DEBUG_FCP
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "FCP: SGLaddr virt %p phys %p size %d", xrip->SGList.virt,
	    xrip->SGList.phys, pkt->pkt_datalen);
	emlxs_data_dump(port, "FCP: SGL", (uint32_t *)xrip->SGList.virt, 20, 0);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "FCP: CMD virt %p len %d:%d:%d",
	    pkt->pkt_cmd, pkt->pkt_cmdlen, pkt->pkt_rsplen, pkt->pkt_datalen);
	emlxs_data_dump(port, "FCP: CMD", (uint32_t *)pkt->pkt_cmd, 10, 0);
#endif /* DEBUG_FCP */

	offset = (off_t)((uint64_t)((unsigned long)
	    xrip->SGList.virt) -
	    (uint64_t)((unsigned long)
	    hba->sli.sli4.slim2.virt));

	EMLXS_MPDATA_SYNC(xrip->SGList.dma_handle, offset,
	    xrip->SGList.size, DDI_DMA_SYNC_FORDEV);

	/* if device is FCP-2 device, set the following bit */
	/* that says to run the FC-TAPE protocol. */
	if (node->nlp_fcp_info & NLP_FCP_2_DEVICE) {
		wqe->ERP = 1;
	}

	if (pkt->pkt_datalen == 0) {
		iocb->ULPCOMMAND = CMD_FCP_ICMND64_CR;
		wqe->Command = CMD_FCP_ICMND64_CR;
		wqe->CmdType = WQE_TYPE_FCP_DATA_IN;
	} else if (pkt->pkt_tran_type == FC_PKT_FCP_READ) {
		iocb->ULPCOMMAND = CMD_FCP_IREAD64_CR;
		wqe->Command = CMD_FCP_IREAD64_CR;
		wqe->CmdType = WQE_TYPE_FCP_DATA_IN;
		wqe->PU = PARM_XFER_CHECK;
	} else {
		iocb->ULPCOMMAND = CMD_FCP_IWRITE64_CR;
		wqe->Command = CMD_FCP_IWRITE64_CR;
		wqe->CmdType = WQE_TYPE_FCP_DATA_OUT;
	}
	wqe->un.FcpCmd.TotalTransferCount = pkt->pkt_datalen;

	if (!(hba->sli.sli4.param.PHWQ)) {
		wqe->DBDE = 1; /* Data type for BDE 0 */
	}
	wqe->ContextTag = rpip->RPI;
	wqe->ContextType = WQE_RPI_CONTEXT;
	wqe->XRITag = xrip->XRI;
	wqe->Timer =
	    ((pkt->pkt_timeout > 0xff) ? 0 : pkt->pkt_timeout);

	if (pkt->pkt_cmd_fhdr.f_ctl & F_CTL_CHAINED_SEQ) {
		wqe->CCPE = 1;
		wqe->CCP = pkt->pkt_cmd_fhdr.rsvd;
	}

	switch (FC_TRAN_CLASS(pkt->pkt_tran_flags)) {
	case FC_TRAN_CLASS2:
		wqe->Class = CLASS2;
		break;
	case FC_TRAN_CLASS3:
	default:
		wqe->Class = CLASS3;
		break;
	}
	sbp->class = wqe->Class;
	wqe->RequestTag = iotag;
	wqe->CQId = (uint16_t)0xffff;  /* default CQ for response */

	return (FC_SUCCESS);
} /* emlxs_sli4_prep_fcp_iocb() */


/*ARGSUSED*/
static uint32_t
emlxs_sli4_prep_ip_iocb(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	return (FC_TRAN_BUSY);

} /* emlxs_sli4_prep_ip_iocb() */


/*ARGSUSED*/
static uint32_t
emlxs_sli4_prep_els_iocb(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	IOCBQ *iocbq;
	IOCB *iocb;
	emlxs_wqe_t *wqe;
	FCFIobj_t *fcfp;
	RPIobj_t *reserved_rpip = NULL;
	RPIobj_t *rpip = NULL;
	XRIobj_t *xrip;
	CHANNEL *cp;
	uint32_t did;
	uint32_t cmd;
	ULP_SGE64 stage_sge;
	ULP_SGE64 *sge;
	ddi_dma_cookie_t *cp_cmd;
	ddi_dma_cookie_t *cp_resp;
	emlxs_node_t *node;
	off_t offset;

	pkt = PRIV2PKT(sbp);
	did = LE_SWAP24_LO(pkt->pkt_cmd_fhdr.d_id);

	iocbq = &sbp->iocbq;
	wqe = &iocbq->wqe;
	iocb = &iocbq->iocb;
	bzero((void *)wqe, sizeof (emlxs_wqe_t));
	bzero((void *)iocb, sizeof (IOCB));
	cp = &hba->chan[hba->channel_els];

	/* Initalize iocbq */
	iocbq->port = (void *) port;
	iocbq->channel = (void *) cp;

	sbp->channel = cp;
	sbp->bmp = NULL;

#if (EMLXS_MODREV >= EMLXS_MODREV3)
	cp_cmd = pkt->pkt_cmd_cookie;
	cp_resp = pkt->pkt_resp_cookie;
#else
	cp_cmd  = &pkt->pkt_cmd_cookie;
	cp_resp = &pkt->pkt_resp_cookie;
#endif	/* >= EMLXS_MODREV3 */

	/* CMD payload */
	sge = &stage_sge;
	sge->addrHigh = PADDR_HI(cp_cmd->dmac_laddress);
	sge->addrLow = PADDR_LO(cp_cmd->dmac_laddress);
	sge->length = pkt->pkt_cmdlen;
	sge->offset = 0;
	sge->type = 0;

	cmd = *((uint32_t *)pkt->pkt_cmd);
	cmd &= ELS_CMD_MASK;

	/* Initalize iocb */
	if (pkt->pkt_tran_type == FC_PKT_OUTBOUND) {
		/* ELS Response */

		sbp->xrip = 0;
		xrip = emlxs_sli4_register_xri(port, sbp,
		    pkt->pkt_cmd_fhdr.rx_id, did);

		if (!xrip) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_failed_msg,
			    "Unable to find XRI. rxid=%x",
			    pkt->pkt_cmd_fhdr.rx_id);

			emlxs_set_pkt_state(sbp, IOSTAT_LOCAL_REJECT,
			    IOERR_NO_XRI, 0);
			return (0xff);
		}

		rpip = xrip->rpip;

		if (!rpip) {
			/* This means that we had a node registered */
			/* when the unsol request came in but the node */
			/* has since been unregistered. */
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_failed_msg,
			    "Unable to find RPI. rxid=%x",
			    pkt->pkt_cmd_fhdr.rx_id);

			emlxs_set_pkt_state(sbp, IOSTAT_LOCAL_REJECT,
			    IOERR_INVALID_RPI, 0);
			return (0xff);
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "ELS: Prep xri=%d iotag=%d oxid=%x rpi=%d",
		    xrip->XRI, xrip->iotag, xrip->rx_id, rpip->RPI);

		iocb->ULPCOMMAND = CMD_XMIT_ELS_RSP64_CX;
		wqe->Command = CMD_XMIT_ELS_RSP64_CX;
		wqe->CmdType = WQE_TYPE_GEN;
		if (!(hba->sli.sli4.param.PHWQ)) {
			wqe->DBDE = 1; /* Data type for BDE 0 */
		}

		wqe->un.ElsRsp.Payload.addrHigh = sge->addrHigh;
		wqe->un.ElsRsp.Payload.addrLow = sge->addrLow;
		wqe->un.ElsRsp.Payload.tus.f.bdeSize = pkt->pkt_cmdlen;
		wqe->un.ElsCmd.PayloadLength = pkt->pkt_cmdlen;

		wqe->un.ElsRsp.RemoteId = did;
		wqe->PU = 0x3;
		wqe->OXId = xrip->rx_id;

		sge->last = 1;
		/* Now sge is fully staged */

		sge = xrip->SGList.virt;
		BE_SWAP32_BCOPY((uint8_t *)&stage_sge, (uint8_t *)sge,
		    sizeof (ULP_SGE64));

		if (rpip->RPI == FABRIC_RPI) {
			wqe->ContextTag = port->vpip->VPI;
			wqe->ContextType = WQE_VPI_CONTEXT;
		} else {
			wqe->ContextTag = rpip->RPI;
			wqe->ContextType = WQE_RPI_CONTEXT;
		}

		if ((cmd == ELS_CMD_ACC) && (sbp->ucmd == ELS_CMD_FLOGI)) {
			wqe->un.ElsCmd.SP = 1;
			wqe->un.ElsCmd.LocalId = 0xFFFFFE;
		}

	} else {
		/* ELS Request */

		fcfp = port->vpip->vfip->fcfp;
		node = (emlxs_node_t *)iocbq->node;
		rpip = EMLXS_NODE_TO_RPI(port, node);

		if (!rpip) {
			/* Use the fabric rpi */
			rpip = port->vpip->fabric_rpip;
		}

		/* Next allocate an Exchange for this command */
		xrip = emlxs_sli4_alloc_xri(port, sbp, rpip,
		    EMLXS_XRI_SOL_ELS_TYPE);

		if (!xrip) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
			    "Adapter Busy. Unable to allocate exchange. "
			    "did=0x%x", did);

			return (FC_TRAN_BUSY);
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "ELS: Prep xri=%d iotag=%d rpi=%d",
		    xrip->XRI, xrip->iotag, rpip->RPI);

		iocb->ULPCOMMAND = CMD_ELS_REQUEST64_CR;
		wqe->Command = CMD_ELS_REQUEST64_CR;
		wqe->CmdType = WQE_TYPE_ELS;
		if (!(hba->sli.sli4.param.PHWQ)) {
			wqe->DBDE = 1; /* Data type for BDE 0 */
		}

		wqe->un.ElsCmd.Payload.addrHigh = sge->addrHigh;
		wqe->un.ElsCmd.Payload.addrLow = sge->addrLow;
		wqe->un.ElsCmd.Payload.tus.f.bdeSize = pkt->pkt_cmdlen;

		wqe->un.ElsCmd.RemoteId = did;
		wqe->Timer = ((pkt->pkt_timeout > 0xff) ? 0 : pkt->pkt_timeout);

		/* setup for rsp */
		iocb->un.elsreq64.remoteID = (did == BCAST_DID) ? 0 : did;
		iocb->ULPPU = 1;	/* Wd4 is relative offset */

		sge->last = 0;

		sge = xrip->SGList.virt;
		BE_SWAP32_BCOPY((uint8_t *)&stage_sge, (uint8_t *)sge,
		    sizeof (ULP_SGE64));

		wqe->un.ElsCmd.PayloadLength =
		    pkt->pkt_cmdlen; /* Byte offset of rsp data */

		/* RSP payload */
		sge = &stage_sge;
		sge->addrHigh = PADDR_HI(cp_resp->dmac_laddress);
		sge->addrLow = PADDR_LO(cp_resp->dmac_laddress);
		sge->length = pkt->pkt_rsplen;
		sge->offset = 0;
		sge->last = 1;
		/* Now sge is fully staged */

		sge = xrip->SGList.virt;
		sge++;
		BE_SWAP32_BCOPY((uint8_t *)&stage_sge, (uint8_t *)sge,
		    sizeof (ULP_SGE64));
#ifdef DEBUG_ELS
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "ELS: SGLaddr virt %p phys %p",
		    xrip->SGList.virt, xrip->SGList.phys);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "ELS: PAYLOAD virt %p phys %p",
		    pkt->pkt_cmd, cp_cmd->dmac_laddress);
		emlxs_data_dump(port, "ELS: SGL", (uint32_t *)xrip->SGList.virt,
		    12, 0);
#endif /* DEBUG_ELS */

		switch (cmd) {
		case ELS_CMD_FLOGI:
			wqe->un.ElsCmd.SP = 1;

			if ((hba->sli_intf & SLI_INTF_IF_TYPE_MASK) ==
			    SLI_INTF_IF_TYPE_0) {
				wqe->ContextTag = fcfp->FCFI;
				wqe->ContextType = WQE_FCFI_CONTEXT;
			} else {
				wqe->ContextTag = port->vpip->VPI;
				wqe->ContextType = WQE_VPI_CONTEXT;
			}

			if (hba->flag & FC_FIP_SUPPORTED) {
				wqe->CmdType |= WQE_TYPE_MASK_FIP;
			}

			if (hba->topology == TOPOLOGY_LOOP) {
				wqe->un.ElsCmd.LocalId = port->did;
			}

			wqe->ELSId = WQE_ELSID_FLOGI;
			break;
		case ELS_CMD_FDISC:
			wqe->un.ElsCmd.SP = 1;
			wqe->ContextTag = port->vpip->VPI;
			wqe->ContextType = WQE_VPI_CONTEXT;

			if (hba->flag & FC_FIP_SUPPORTED) {
				wqe->CmdType |= WQE_TYPE_MASK_FIP;
			}

			wqe->ELSId = WQE_ELSID_FDISC;
			break;
		case ELS_CMD_LOGO:
			if ((did == FABRIC_DID) &&
			    (hba->flag & FC_FIP_SUPPORTED)) {
				wqe->CmdType |= WQE_TYPE_MASK_FIP;
			}

			wqe->ContextTag = port->vpip->VPI;
			wqe->ContextType = WQE_VPI_CONTEXT;
			wqe->ELSId = WQE_ELSID_LOGO;
			break;
		case ELS_CMD_PLOGI:
			if (rpip->RPI == FABRIC_RPI) {
				if (hba->flag & FC_PT_TO_PT) {
					wqe->un.ElsCmd.SP = 1;
					wqe->un.ElsCmd.LocalId = port->did;
				}

				wqe->ContextTag = port->vpip->VPI;
				wqe->ContextType = WQE_VPI_CONTEXT;
			} else {
				wqe->ContextTag = rpip->RPI;
				wqe->ContextType = WQE_RPI_CONTEXT;
			}

			wqe->ELSId = WQE_ELSID_PLOGI;
			break;
		default:
			if (rpip->RPI == FABRIC_RPI) {
				wqe->ContextTag = port->vpip->VPI;
				wqe->ContextType = WQE_VPI_CONTEXT;
			} else {
				wqe->ContextTag = rpip->RPI;
				wqe->ContextType = WQE_RPI_CONTEXT;
			}

			wqe->ELSId = WQE_ELSID_CMD;
			break;
		}

#ifdef SFCT_SUPPORT
		/* This allows fct to abort the request */
		if (sbp->fct_cmd) {
			sbp->fct_cmd->cmd_oxid = xrip->XRI;
			sbp->fct_cmd->cmd_rxid = 0xFFFF;
		}
#endif /* SFCT_SUPPORT */
	}

	if (wqe->ContextType == WQE_VPI_CONTEXT) {
		reserved_rpip = emlxs_rpi_reserve_notify(port, did, xrip);

		if (!reserved_rpip) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_failed_msg,
			    "Unable to alloc reserved RPI. rxid=%x. Rejecting.",
			    pkt->pkt_cmd_fhdr.rx_id);

			emlxs_set_pkt_state(sbp, IOSTAT_LOCAL_REJECT,
			    IOERR_INVALID_RPI, 0);
			return (0xff);
		}

		/* Store the reserved rpi */
		if (wqe->Command == CMD_ELS_REQUEST64_CR) {
			wqe->OXId = reserved_rpip->RPI;
		} else {
			wqe->CmdSpecific = reserved_rpip->RPI;
		}
	}

	offset = (off_t)((uint64_t)((unsigned long)
	    xrip->SGList.virt) -
	    (uint64_t)((unsigned long)
	    hba->sli.sli4.slim2.virt));

	EMLXS_MPDATA_SYNC(xrip->SGList.dma_handle, offset,
	    xrip->SGList.size, DDI_DMA_SYNC_FORDEV);

	if (pkt->pkt_cmd_fhdr.f_ctl & F_CTL_CHAINED_SEQ) {
		wqe->CCPE = 1;
		wqe->CCP = pkt->pkt_cmd_fhdr.rsvd;
	}

	switch (FC_TRAN_CLASS(pkt->pkt_tran_flags)) {
	case FC_TRAN_CLASS2:
		wqe->Class = CLASS2;
		break;
	case FC_TRAN_CLASS3:
	default:
		wqe->Class = CLASS3;
		break;
	}
	sbp->class = wqe->Class;
	wqe->XRITag = xrip->XRI;
	wqe->RequestTag = xrip->iotag;
	wqe->CQId = (uint16_t)0xffff;  /* default CQ for response */
	return (FC_SUCCESS);

} /* emlxs_sli4_prep_els_iocb() */


/*ARGSUSED*/
static uint32_t
emlxs_sli4_prep_ct_iocb(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	IOCBQ *iocbq;
	IOCB *iocb;
	emlxs_wqe_t *wqe;
	NODELIST *node = NULL;
	CHANNEL *cp;
	RPIobj_t *rpip;
	XRIobj_t *xrip;
	uint32_t did;
	off_t offset;

	pkt = PRIV2PKT(sbp);
	did = LE_SWAP24_LO(pkt->pkt_cmd_fhdr.d_id);

	iocbq = &sbp->iocbq;
	wqe = &iocbq->wqe;
	iocb = &iocbq->iocb;
	bzero((void *)wqe, sizeof (emlxs_wqe_t));
	bzero((void *)iocb, sizeof (IOCB));

	cp = &hba->chan[hba->channel_ct];

	iocbq->port = (void *) port;
	iocbq->channel = (void *) cp;

	sbp->bmp = NULL;
	sbp->channel = cp;

	/* Initalize wqe */
	if (pkt->pkt_tran_type == FC_PKT_OUTBOUND) {
		/* CT Response */

		sbp->xrip = 0;
		xrip = emlxs_sli4_register_xri(port, sbp,
		    pkt->pkt_cmd_fhdr.rx_id, did);

		if (!xrip) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_failed_msg,
			    "Unable to find XRI. rxid=%x",
			    pkt->pkt_cmd_fhdr.rx_id);

			emlxs_set_pkt_state(sbp, IOSTAT_LOCAL_REJECT,
			    IOERR_NO_XRI, 0);
			return (0xff);
		}

		rpip = xrip->rpip;

		if (!rpip) {
			/* This means that we had a node registered */
			/* when the unsol request came in but the node */
			/* has since been unregistered. */
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_failed_msg,
			    "Unable to find RPI. rxid=%x",
			    pkt->pkt_cmd_fhdr.rx_id);

			emlxs_set_pkt_state(sbp, IOSTAT_LOCAL_REJECT,
			    IOERR_INVALID_RPI, 0);
			return (0xff);
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "CT: Prep xri=%d iotag=%d oxid=%x rpi=%d",
		    xrip->XRI, xrip->iotag, xrip->rx_id, rpip->RPI);

		if (emlxs_sli4_bde_setup(port, sbp)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
			    "Adapter Busy. Unable to setup SGE. did=0x%x", did);

			return (FC_TRAN_BUSY);
		}

		if (!(hba->model_info.chip & EMLXS_BE_CHIPS)) {
			wqe->un.XmitSeq.Rsvd0 = 0; /* Word3 now reserved */
		}

		if (!(hba->sli.sli4.param.PHWQ)) {
			wqe->DBDE = 1; /* Data type for BDE 0 */
		}

		iocb->ULPCOMMAND = CMD_XMIT_SEQUENCE64_CR;
		wqe->CmdType = WQE_TYPE_GEN;
		wqe->Command = CMD_XMIT_SEQUENCE64_CR;
		wqe->LenLoc = 2;

		if (((SLI_CT_REQUEST *) pkt->pkt_cmd)->CommandResponse.bits.
		    CmdRsp == (LE_SWAP16(SLI_CT_LOOPBACK))) {
			wqe->un.XmitSeq.xo = 1;
		} else {
			wqe->un.XmitSeq.xo = 0;
		}

		if (pkt->pkt_cmd_fhdr.f_ctl & F_CTL_LAST_SEQ) {
			wqe->un.XmitSeq.ls = 1;
		}

		if (pkt->pkt_cmd_fhdr.f_ctl & F_CTL_SEQ_INITIATIVE) {
			wqe->un.XmitSeq.si = 1;
		}

		wqe->un.XmitSeq.DFctl  = pkt->pkt_cmd_fhdr.df_ctl;
		wqe->un.XmitSeq.Rctl  = pkt->pkt_cmd_fhdr.r_ctl;
		wqe->un.XmitSeq.Type  = pkt->pkt_cmd_fhdr.type;
		wqe->OXId = xrip->rx_id;
		wqe->XC = 0; /* xri_tag is a new exchange */
		wqe->CmdSpecific = wqe->un.GenReq.Payload.tus.f.bdeSize;

	} else {
		/* CT Request */

		node = (emlxs_node_t *)iocbq->node;
		rpip = EMLXS_NODE_TO_RPI(port, node);

		if (!rpip) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_failed_msg,
			    "Unable to find rpi. did=0x%x rpi=%d",
			    did, node->nlp_Rpi);

			emlxs_set_pkt_state(sbp, IOSTAT_LOCAL_REJECT,
			    IOERR_INVALID_RPI, 0);
			return (0xff);
		}

		/* Next allocate an Exchange for this command */
		xrip = emlxs_sli4_alloc_xri(port, sbp, rpip,
		    EMLXS_XRI_SOL_CT_TYPE);

		if (!xrip) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
			    "Adapter Busy. Unable to allocate exchange. "
			    "did=0x%x", did);

			return (FC_TRAN_BUSY);
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "CT: Prep xri=%d iotag=%d oxid=%x rpi=%d",
		    xrip->XRI, xrip->iotag, xrip->rx_id, rpip->RPI);

		if (emlxs_sli4_bde_setup(port, sbp)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
			    "Adapter Busy. Unable to setup SGE. did=0x%x", did);

			emlxs_sli4_free_xri(port, sbp, xrip, 1);
			return (FC_TRAN_BUSY);
		}

		if (!(hba->sli.sli4.param.PHWQ)) {
			wqe->DBDE = 1; /* Data type for BDE 0 */
		}

		iocb->ULPCOMMAND = CMD_GEN_REQUEST64_CR;
		wqe->CmdType = WQE_TYPE_GEN;
		wqe->Command = CMD_GEN_REQUEST64_CR;
		wqe->un.GenReq.la = 1;
		wqe->un.GenReq.DFctl  = pkt->pkt_cmd_fhdr.df_ctl;
		wqe->un.GenReq.Rctl  = pkt->pkt_cmd_fhdr.r_ctl;
		wqe->un.GenReq.Type  = pkt->pkt_cmd_fhdr.type;

#ifdef DEBUG_CT
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "CT: SGLaddr virt %p phys %p", xrip->SGList.virt,
		    xrip->SGList.phys);
		emlxs_data_dump(port, "CT: SGL", (uint32_t *)xrip->SGList.virt,
		    12, 0);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "CT: CMD virt %p len %d:%d",
		    pkt->pkt_cmd, pkt->pkt_cmdlen, pkt->pkt_rsplen);
		emlxs_data_dump(port, "CT: DATA", (uint32_t *)pkt->pkt_cmd,
		    20, 0);
#endif /* DEBUG_CT */

#ifdef SFCT_SUPPORT
		/* This allows fct to abort the request */
		if (sbp->fct_cmd) {
			sbp->fct_cmd->cmd_oxid = xrip->XRI;
			sbp->fct_cmd->cmd_rxid = 0xFFFF;
		}
#endif /* SFCT_SUPPORT */
	}

	/* Setup for rsp */
	iocb->un.genreq64.w5.hcsw.Rctl  = pkt->pkt_cmd_fhdr.r_ctl;
	iocb->un.genreq64.w5.hcsw.Type  = pkt->pkt_cmd_fhdr.type;
	iocb->un.genreq64.w5.hcsw.Dfctl  = pkt->pkt_cmd_fhdr.df_ctl;
	iocb->ULPPU = 1;	/* Wd4 is relative offset */

	offset = (off_t)((uint64_t)((unsigned long)
	    xrip->SGList.virt) -
	    (uint64_t)((unsigned long)
	    hba->sli.sli4.slim2.virt));

	EMLXS_MPDATA_SYNC(xrip->SGList.dma_handle, offset,
	    xrip->SGList.size, DDI_DMA_SYNC_FORDEV);

	wqe->ContextTag = rpip->RPI;
	wqe->ContextType = WQE_RPI_CONTEXT;
	wqe->XRITag = xrip->XRI;
	wqe->Timer = ((pkt->pkt_timeout > 0xff) ? 0 : pkt->pkt_timeout);

	if (pkt->pkt_cmd_fhdr.f_ctl & F_CTL_CHAINED_SEQ) {
		wqe->CCPE = 1;
		wqe->CCP = pkt->pkt_cmd_fhdr.rsvd;
	}

	switch (FC_TRAN_CLASS(pkt->pkt_tran_flags)) {
	case FC_TRAN_CLASS2:
		wqe->Class = CLASS2;
		break;
	case FC_TRAN_CLASS3:
	default:
		wqe->Class = CLASS3;
		break;
	}
	sbp->class = wqe->Class;
	wqe->RequestTag = xrip->iotag;
	wqe->CQId = (uint16_t)0xffff;  /* default CQ for response */
	return (FC_SUCCESS);

} /* emlxs_sli4_prep_ct_iocb() */


/*ARGSUSED*/
static int
emlxs_sli4_read_eq(emlxs_hba_t *hba, EQ_DESC_t *eq)
{
	uint32_t *ptr;
	EQE_u eqe;
	int rc = 0;
	off_t offset;

	mutex_enter(&EMLXS_PORT_LOCK);

	ptr = eq->addr.virt;
	ptr += eq->host_index;

	offset = (off_t)((uint64_t)((unsigned long)
	    eq->addr.virt) -
	    (uint64_t)((unsigned long)
	    hba->sli.sli4.slim2.virt));

	EMLXS_MPDATA_SYNC(eq->addr.dma_handle, offset,
	    4096, DDI_DMA_SYNC_FORKERNEL);

	eqe.word = *ptr;
	eqe.word = BE_SWAP32(eqe.word);

	if (eqe.word & EQE_VALID) {
		rc = 1;
	}

	mutex_exit(&EMLXS_PORT_LOCK);

	return (rc);

} /* emlxs_sli4_read_eq */


static void
emlxs_sli4_poll_intr(emlxs_hba_t *hba)
{
	int rc = 0;
	int i;
	char arg[] = {0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7};

	/* Check attention bits once and process if required */

	for (i = 0; i < hba->intr_count; i++) {
		rc = emlxs_sli4_read_eq(hba, &hba->sli.sli4.eq[i]);
		if (rc == 1) {
			break;
		}
	}

	if (rc != 1) {
		return;
	}

	(void) emlxs_sli4_msi_intr((char *)hba,
	    (char *)(unsigned long)arg[i]);

	return;

} /* emlxs_sli4_poll_intr() */


/*ARGSUSED*/
static void
emlxs_sli4_process_async_event(emlxs_hba_t *hba, CQE_ASYNC_t *cqe)
{
	emlxs_port_t *port = &PPORT;
	uint8_t status;

	/* Save the event tag */
	if (hba->link_event_tag == cqe->un.link.event_tag) {
		HBASTATS.LinkMultiEvent++;
	} else if (hba->link_event_tag + 1 < cqe->un.link.event_tag) {
		HBASTATS.LinkMultiEvent++;
	}
	hba->link_event_tag = cqe->un.link.event_tag;

	switch (cqe->event_code) {
	case ASYNC_EVENT_CODE_FCOE_LINK_STATE:
		HBASTATS.LinkEvent++;

		switch (cqe->un.link.link_status) {
		case ASYNC_EVENT_PHYS_LINK_UP:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "Link Async Event: PHYS_LINK_UP. val=%d "
			    "type=%x event=%x",
			    cqe->valid, cqe->event_type, HBASTATS.LinkEvent);
			break;

		case ASYNC_EVENT_LOGICAL_LINK_UP:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "Link Async Event: LOGICAL_LINK_UP. val=%d "
			    "type=%x event=%x",
			    cqe->valid, cqe->event_type, HBASTATS.LinkEvent);

			emlxs_sli4_handle_fcoe_link_event(hba, cqe);
			break;

		case ASYNC_EVENT_PHYS_LINK_DOWN:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "Link Async Event: PHYS_LINK_DOWN. val=%d "
			    "type=%x event=%x",
			    cqe->valid, cqe->event_type, HBASTATS.LinkEvent);

			emlxs_sli4_handle_fcoe_link_event(hba, cqe);
			break;

		case ASYNC_EVENT_LOGICAL_LINK_DOWN:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "Link Async Event: LOGICAL_LINK_DOWN. val=%d "
			    "type=%x event=%x",
			    cqe->valid, cqe->event_type, HBASTATS.LinkEvent);

			emlxs_sli4_handle_fcoe_link_event(hba, cqe);
			break;
		default:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "Link Async Event: Unknown link status=%d event=%x",
			    cqe->un.link.link_status, HBASTATS.LinkEvent);
			break;
		}
		break;
	case ASYNC_EVENT_CODE_FCOE_FIP:
		switch (cqe->un.fcoe.evt_type) {
		case ASYNC_EVENT_NEW_FCF_DISC:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "FIP Async Event: FCF_FOUND %d:%d",
			    cqe->un.fcoe.ref_index, cqe->un.fcoe.fcf_count);

			(void) emlxs_fcf_found_notify(port,
			    cqe->un.fcoe.ref_index);
			break;
		case ASYNC_EVENT_FCF_TABLE_FULL:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "FIP Async Event: FCFTAB_FULL %d:%d",
			    cqe->un.fcoe.ref_index, cqe->un.fcoe.fcf_count);

			(void) emlxs_fcf_full_notify(port);
			break;
		case ASYNC_EVENT_FCF_DEAD:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "FIP Async Event: FCF_LOST %d:%d",
			    cqe->un.fcoe.ref_index, cqe->un.fcoe.fcf_count);

			(void) emlxs_fcf_lost_notify(port,
			    cqe->un.fcoe.ref_index);
			break;
		case ASYNC_EVENT_VIRT_LINK_CLEAR:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "FIP Async Event: CVL %d",
			    cqe->un.fcoe.ref_index);

			(void) emlxs_fcf_cvl_notify(port,
			    emlxs_sli4_vpi_to_index(hba,
			    cqe->un.fcoe.ref_index));
			break;

		case ASYNC_EVENT_FCF_MODIFIED:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "FIP Async Event: FCF_CHANGED %d",
			    cqe->un.fcoe.ref_index);

			(void) emlxs_fcf_changed_notify(port,
			    cqe->un.fcoe.ref_index);
			break;
		default:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "FIP Async Event: Unknown event type=%d",
			    cqe->un.fcoe.evt_type);
			break;
		}
		break;
	case ASYNC_EVENT_CODE_DCBX:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "DCBX Async Event: type=%d. Not supported.",
		    cqe->event_type);
		break;
	case ASYNC_EVENT_CODE_GRP_5:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "Group 5 Async Event: type=%d.", cqe->event_type);
		if (cqe->event_type == ASYNC_EVENT_QOS_SPEED) {
			hba->qos_linkspeed = cqe->un.qos.qos_link_speed;
		}
		break;
	case ASYNC_EVENT_CODE_FC_EVENT:
		switch (cqe->event_type) {
		case ASYNC_EVENT_FC_LINK_ATT:
			HBASTATS.LinkEvent++;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "FC Async Event: Link Attention. event=%x",
			    HBASTATS.LinkEvent);

			emlxs_sli4_handle_fc_link_att(hba, cqe);
			break;
		case ASYNC_EVENT_FC_SHARED_LINK_ATT:
			HBASTATS.LinkEvent++;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "FC Async Event: Shared Link Attention. event=%x",
			    HBASTATS.LinkEvent);

			emlxs_sli4_handle_fc_link_att(hba, cqe);
			break;
		default:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "FC Async Event: Unknown event. type=%d event=%x",
			    cqe->event_type, HBASTATS.LinkEvent);
		}
		break;
	case ASYNC_EVENT_CODE_PORT:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "SLI Port Async Event: type=%d", cqe->event_type);
		if (cqe->event_type == ASYNC_EVENT_MISCONFIG_PORT) {
			*((uint32_t *)cqe->un.port.link_status) =
			    BE_SWAP32(*((uint32_t *)cqe->un.port.link_status));
			status =
			    cqe->un.port.link_status[hba->sli.sli4.link_number];

			switch (status) {
				case 0 :
				break;

				case 1 :
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_err_msg,
				    "SLI Port Async Event: Physical media not "
				    "detected");
				cmn_err(CE_WARN,
				    "^%s%d: Optics faulted/incorrectly "
				    "installed/not installed - Reseat optics, "
				    "if issue not resolved, replace.",
				    DRIVER_NAME, hba->ddiinst);
				break;

				case 2 :
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_err_msg,
				    "SLI Port Async Event: Wrong physical "
				    "media detected");
				cmn_err(CE_WARN,
				    "^%s%d: Optics of two types installed - "
				    "Remove one optic or install matching"
				    "pair of optics.",
				    DRIVER_NAME, hba->ddiinst);
				break;

				case 3 :
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_err_msg,
				    "SLI Port Async Event: Unsupported "
				    "physical media detected");
				cmn_err(CE_WARN,
				    "^%s%d:  Incompatible optics - Replace "
				    "with compatible optics for card to "
				    "function.",
				    DRIVER_NAME, hba->ddiinst);
				break;

				default :
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_err_msg,
				    "SLI Port Async Event: Physical media "
				    "error, status=%x", status);
				cmn_err(CE_WARN,
				    "^%s%d: Misconfigured port: status=0x%x - "
				    "Check optics on card.",
				    DRIVER_NAME, hba->ddiinst, status);
				break;
			}
		}
		break;
	case ASYNC_EVENT_CODE_VF:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "VF Async Event: type=%d",
		    cqe->event_type);
		break;
	case ASYNC_EVENT_CODE_MR:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "MR Async Event: type=%d",
		    cqe->event_type);
		break;
	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "Unknown Async Event: code=%d type=%d.",
		    cqe->event_code, cqe->event_type);
		break;
	}

} /* emlxs_sli4_process_async_event() */


/*ARGSUSED*/
static void
emlxs_sli4_process_mbox_event(emlxs_hba_t *hba, CQE_MBOX_t *cqe)
{
	emlxs_port_t *port = &PPORT;
	MAILBOX4 *mb;
	MATCHMAP *mbox_bp;
	MATCHMAP *mbox_nonembed;
	MAILBOXQ *mbq = NULL;
	uint32_t size;
	uint32_t *iptr;
	int rc;
	off_t offset;

	if (cqe->consumed && !cqe->completed) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "CQ ENTRY: Mbox event. Entry consumed but not completed");
		return;
	}

	mutex_enter(&EMLXS_PORT_LOCK);
	switch (hba->mbox_queue_flag) {
	case 0:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_stray_mbox_intr_msg,
		    "CQ ENTRY: Mbox event. No mailbox active.");

		mutex_exit(&EMLXS_PORT_LOCK);
		return;

	case MBX_POLL:

		/* Mark mailbox complete, this should wake up any polling */
		/* threads. This can happen if interrupts are enabled while */
		/* a polled mailbox command is outstanding. If we don't set */
		/* MBQ_COMPLETED here, the polling thread may wait until */
		/* timeout error occurs */

		mutex_enter(&EMLXS_MBOX_LOCK);
		mbq = (MAILBOXQ *)hba->mbox_mbq;
		if (mbq) {
			port = (emlxs_port_t *)mbq->port;
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
			    "CQ ENTRY: Mbox event. Completing Polled command.");
			mbq->flag |= MBQ_COMPLETED;
		}
		mutex_exit(&EMLXS_MBOX_LOCK);

		mutex_exit(&EMLXS_PORT_LOCK);
		return;

	case MBX_SLEEP:
	case MBX_NOWAIT:
		/* Check mbox_timer, it acts as a service flag too */
		/* The first to service the mbox queue will clear the timer */
		if (hba->mbox_timer) {
			hba->mbox_timer = 0;

			mutex_enter(&EMLXS_MBOX_LOCK);
			mbq = (MAILBOXQ *)hba->mbox_mbq;
			mutex_exit(&EMLXS_MBOX_LOCK);
		}

		if (!mbq) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
			    "Mailbox event. No service required.");
			mutex_exit(&EMLXS_PORT_LOCK);
			return;
		}

		mb = (MAILBOX4 *)mbq;
		mutex_exit(&EMLXS_PORT_LOCK);
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_completion_error_msg,
		    "CQ ENTRY: Mbox event. Invalid Mailbox flag (%x).",
		    hba->mbox_queue_flag);

		mutex_exit(&EMLXS_PORT_LOCK);
		return;
	}

	/* Set port context */
	port = (emlxs_port_t *)mbq->port;

	offset = (off_t)((uint64_t)((unsigned long)
	    hba->sli.sli4.mq.addr.virt) -
	    (uint64_t)((unsigned long)
	    hba->sli.sli4.slim2.virt));

	/* Now that we are the owner, DMA Sync entire MQ if needed */
	EMLXS_MPDATA_SYNC(hba->sli.sli4.mq.addr.dma_handle, offset,
	    4096, DDI_DMA_SYNC_FORDEV);

	BE_SWAP32_BCOPY((uint8_t *)hba->mbox_mqe, (uint8_t *)mb,
	    MAILBOX_CMD_SLI4_BSIZE);

	if (mb->mbxCommand != MBX_HEARTBEAT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "CQ ENTRY: Mbox event. Mbox complete. status=%x cmd=%x",
		    mb->mbxStatus, mb->mbxCommand);

		emlxs_data_dump(port, "MBOX CMP", (uint32_t *)hba->mbox_mqe,
		    12, 0);
	}

	if (mb->mbxCommand == MBX_SLI_CONFIG) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "Mbox sge_cnt: %d length: %d embed: %d",
		    mb->un.varSLIConfig.be.sge_cnt,
		    mb->un.varSLIConfig.be.payload_length,
		    mb->un.varSLIConfig.be.embedded);
	}

	/* Now sync the memory buffer if one was used */
	if (mbq->bp) {
		mbox_bp = (MATCHMAP *)mbq->bp;
		EMLXS_MPDATA_SYNC(mbox_bp->dma_handle, 0, mbox_bp->size,
		    DDI_DMA_SYNC_FORKERNEL);
#ifdef FMA_SUPPORT
		if (emlxs_fm_check_dma_handle(hba, mbox_bp->dma_handle)
		    != DDI_FM_OK) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_invalid_dma_handle_msg,
			    "sli4_process_mbox_event: hdl=%p",
			    mbox_bp->dma_handle);

			mb->mbxStatus = MBXERR_DMA_ERROR;
}
#endif
	}

	/* Now sync the memory buffer if one was used */
	if (mbq->nonembed) {
		mbox_nonembed = (MATCHMAP *)mbq->nonembed;
		size = mbox_nonembed->size;
		EMLXS_MPDATA_SYNC(mbox_nonembed->dma_handle, 0, size,
		    DDI_DMA_SYNC_FORKERNEL);
		iptr = (uint32_t *)((uint8_t *)mbox_nonembed->virt);
		BE_SWAP32_BCOPY((uint8_t *)iptr, (uint8_t *)iptr, size);

#ifdef FMA_SUPPORT
		if (emlxs_fm_check_dma_handle(hba,
		    mbox_nonembed->dma_handle) != DDI_FM_OK) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_invalid_dma_handle_msg,
			    "sli4_process_mbox_event: hdl=%p",
			    mbox_nonembed->dma_handle);

			mb->mbxStatus = MBXERR_DMA_ERROR;
		}
#endif
		emlxs_data_dump(port, "EXT AREA", (uint32_t *)iptr, 24, 0);
	}

	/* Mailbox has been completely received at this point */

	if (mb->mbxCommand == MBX_HEARTBEAT) {
		hba->heartbeat_active = 0;
		goto done;
	}

	if (hba->mbox_queue_flag == MBX_SLEEP) {
		if (mb->mbxCommand != MBX_DOWN_LOAD
		    /* && mb->mbxCommand != MBX_DUMP_MEMORY */) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
			    "Received.  %s: status=%x Sleep.",
			    emlxs_mb_cmd_xlate(mb->mbxCommand),
			    mb->mbxStatus);
		}
	} else {
		if (mb->mbxCommand != MBX_DOWN_LOAD
		    /* && mb->mbxCommand != MBX_DUMP_MEMORY */) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
			    "Completed. %s: status=%x",
			    emlxs_mb_cmd_xlate(mb->mbxCommand),
			    mb->mbxStatus);
		}
	}

	/* Filter out passthru mailbox */
	if (mbq->flag & MBQ_PASSTHRU) {
		goto done;
	}

	if (mb->mbxStatus) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
		    "%s: status=0x%x", emlxs_mb_cmd_xlate(mb->mbxCommand),
		    (uint32_t)mb->mbxStatus);
	}

	if (mbq->mbox_cmpl) {
		rc = (mbq->mbox_cmpl)(hba, mbq);

		/* If mbox was retried, return immediately */
		if (rc) {
			return;
		}
	}

done:

	/* Clean up the mailbox area */
	emlxs_mb_fini(hba, (MAILBOX *)mb, mb->mbxStatus);

	/* Attempt to send pending mailboxes */
	mbq = (MAILBOXQ *)emlxs_mb_get(hba);
	if (mbq) {
		/* Attempt to send pending mailboxes */
		rc =  emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_NOWAIT, 0);
		if ((rc != MBX_BUSY) && (rc != MBX_SUCCESS)) {
			emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);
		}
	}
	return;

} /* emlxs_sli4_process_mbox_event() */


/*ARGSUSED*/
static void
emlxs_CQE_to_IOCB(emlxs_hba_t *hba, CQE_CmplWQ_t *cqe, emlxs_buf_t *sbp)
{
#ifdef DEBUG_FASTPATH
	emlxs_port_t *port = &PPORT;
#endif /* DEBUG_FASTPATH */
	IOCBQ *iocbq;
	IOCB *iocb;
	uint32_t *iptr;
	fc_packet_t *pkt;
	emlxs_wqe_t *wqe;

	iocbq = &sbp->iocbq;
	wqe = &iocbq->wqe;
	iocb = &iocbq->iocb;

#ifdef DEBUG_FASTPATH
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "CQE to IOCB: cmd:%x tag:%x xri:%d", wqe->Command,
	    wqe->RequestTag, wqe->XRITag);
#endif /* DEBUG_FASTPATH */

	iocb->ULPSTATUS = cqe->Status;
	iocb->un.ulpWord[4] = cqe->Parameter;
	iocb->ULPIOTAG = cqe->RequestTag;
	iocb->ULPCONTEXT = wqe->XRITag;

	switch (wqe->Command) {

	case CMD_FCP_ICMND64_CR:
		iocb->ULPCOMMAND = CMD_FCP_ICMND64_CX;
		break;

	case CMD_FCP_IREAD64_CR:
		iocb->ULPCOMMAND = CMD_FCP_IREAD64_CX;
		iocb->ULPPU = PARM_XFER_CHECK;
		if (iocb->ULPSTATUS ==  IOSTAT_FCP_RSP_ERROR) {
			iocb->un.fcpi64.fcpi_parm =
			    wqe->un.FcpCmd.TotalTransferCount -
			    cqe->CmdSpecific;
		}
		break;

	case CMD_FCP_IWRITE64_CR:
		iocb->ULPCOMMAND = CMD_FCP_IWRITE64_CX;
		if (iocb->ULPSTATUS ==  IOSTAT_FCP_RSP_ERROR) {
			if (wqe->un.FcpCmd.TotalTransferCount >
			    cqe->CmdSpecific) {
				iocb->un.fcpi64.fcpi_parm =
				    wqe->un.FcpCmd.TotalTransferCount -
				    cqe->CmdSpecific;
			} else {
				iocb->un.fcpi64.fcpi_parm = 0;
			}
		}
		break;

	case CMD_ELS_REQUEST64_CR:
		iocb->ULPCOMMAND = CMD_ELS_REQUEST64_CX;
		iocb->un.elsreq64.bdl.bdeSize = cqe->CmdSpecific;
		if (iocb->ULPSTATUS == 0) {
			iocb->unsli3.ext_iocb.rsplen = cqe->CmdSpecific;
		}
		if (iocb->ULPSTATUS == IOSTAT_LS_RJT) {
			/* For LS_RJT, the driver populates the rsp buffer */
			pkt = PRIV2PKT(sbp);
			iptr = (uint32_t *)pkt->pkt_resp;
			*iptr++ = ELS_CMD_LS_RJT;
			*iptr = cqe->Parameter;
		}
		break;

	case CMD_GEN_REQUEST64_CR:
		iocb->ULPCOMMAND = CMD_GEN_REQUEST64_CX;
		iocb->unsli3.ext_iocb.rsplen = cqe->CmdSpecific;
		break;

	case CMD_XMIT_SEQUENCE64_CR:
		iocb->ULPCOMMAND = CMD_XMIT_SEQUENCE64_CX;
		break;

	case CMD_ABORT_XRI_CX:
		iocb->ULPCONTEXT = wqe->AbortTag;
		break;

	case CMD_FCP_TRECEIVE64_CX:
		/* free memory for XRDY */
		if (iocbq->bp) {
			emlxs_mem_buf_free(hba, iocbq->bp);
			iocbq->bp = 0;
		}

		/*FALLTHROUGH*/

	case CMD_FCP_TSEND64_CX:
	case CMD_FCP_TRSP64_CX:
	default:
		iocb->ULPCOMMAND = wqe->Command;

	}
} /* emlxs_CQE_to_IOCB() */


/*ARGSUSED*/
static void
emlxs_sli4_hba_flush_chipq(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	CHANNEL *cp;
	emlxs_buf_t *sbp;
	IOCBQ *iocbq;
	uint16_t i;
	uint32_t trigger = 0;
	CQE_CmplWQ_t cqe;

	mutex_enter(&EMLXS_FCTAB_LOCK);
	for (i = 0; i < hba->max_iotag; i++) {
		sbp = hba->fc_table[i];
		if (sbp == NULL || sbp == STALE_PACKET) {
			continue;
		}
		hba->fc_table[i] = STALE_PACKET;
		hba->io_count--;
		sbp->iotag = 0;
		mutex_exit(&EMLXS_FCTAB_LOCK);

		cp = sbp->channel;
		bzero(&cqe, sizeof (CQE_CmplWQ_t));
		cqe.RequestTag = i;
		cqe.Status = IOSTAT_LOCAL_REJECT;
		cqe.Parameter = IOERR_SEQUENCE_TIMEOUT;

		cp->hbaCmplCmd_sbp++;

#ifdef SFCT_SUPPORT
#ifdef FCT_IO_TRACE
		if (sbp->fct_cmd) {
			emlxs_fct_io_trace(port, sbp->fct_cmd,
			    EMLXS_FCT_IOCB_COMPLETE);
		}
#endif /* FCT_IO_TRACE */
#endif /* SFCT_SUPPORT */

		if (sbp->pkt_flags & PACKET_IN_CHIPQ) {
			atomic_dec_32(&hba->io_active);
#ifdef NODE_THROTTLE_SUPPORT
			if (sbp->node) {
				atomic_dec_32(&sbp->node->io_active);
			}
#endif /* NODE_THROTTLE_SUPPORT */
		}

		/* Copy entry to sbp's iocbq */
		iocbq = &sbp->iocbq;
		emlxs_CQE_to_IOCB(hba, &cqe, sbp);

		iocbq->next = NULL;

		/* Exchange is no longer busy on-chip, free it */
		emlxs_sli4_free_xri(port, sbp, sbp->xrip, 1);

		if (!(sbp->pkt_flags &
		    (PACKET_POLLED | PACKET_ALLOCATED))) {
			/* Add the IOCB to the channel list */
			mutex_enter(&cp->rsp_lock);
			if (cp->rsp_head == NULL) {
				cp->rsp_head = iocbq;
				cp->rsp_tail = iocbq;
			} else {
				cp->rsp_tail->next = iocbq;
				cp->rsp_tail = iocbq;
			}
			mutex_exit(&cp->rsp_lock);
			trigger = 1;
		} else {
			emlxs_proc_channel_event(hba, cp, iocbq);
		}
		mutex_enter(&EMLXS_FCTAB_LOCK);
	}
	mutex_exit(&EMLXS_FCTAB_LOCK);

	if (trigger) {
		for (i = 0; i < hba->chan_count; i++) {
			cp = &hba->chan[i];
			if (cp->rsp_head != NULL) {
				emlxs_thread_trigger2(&cp->intr_thread,
				    emlxs_proc_channel, cp);
			}
		}
	}

} /* emlxs_sli4_hba_flush_chipq() */


/*ARGSUSED*/
static void
emlxs_sli4_process_oor_wqe_cmpl(emlxs_hba_t *hba,
    CQ_DESC_t *cq, CQE_CmplWQ_t *cqe)
{
	emlxs_port_t *port = &PPORT;
	CHANNEL *cp;
	uint16_t request_tag;

	request_tag = cqe->RequestTag;

	/* 1 to 1 mapping between CQ and channel */
	cp = cq->channelp;

	cp->hbaCmplCmd++;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "CQ ENTRY: OOR Cmpl: iotag=%d", request_tag);

	emlxs_data_dump(port, "CQE", (uint32_t *)cqe, 4, 0);

} /* emlxs_sli4_process_oor_wqe_cmpl() */


/*ARGSUSED*/
static void
emlxs_sli4_process_wqe_cmpl(emlxs_hba_t *hba, CQ_DESC_t *cq, CQE_CmplWQ_t *cqe)
{
	emlxs_port_t *port = &PPORT;
	CHANNEL *cp;
	emlxs_buf_t *sbp;
	IOCBQ *iocbq;
	uint16_t request_tag;
#ifdef SFCT_SUPPORT
#ifdef FCT_IO_TRACE
	fct_cmd_t *fct_cmd;
	emlxs_buf_t *cmd_sbp;
#endif /* FCT_IO_TRACE */
#endif /* SFCT_SUPPORT */

	request_tag = cqe->RequestTag;

	/* 1 to 1 mapping between CQ and channel */
	cp = cq->channelp;

	mutex_enter(&EMLXS_FCTAB_LOCK);
	sbp = hba->fc_table[request_tag];

	if (!sbp) {
		cp->hbaCmplCmd++;
		mutex_exit(&EMLXS_FCTAB_LOCK);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "CQ ENTRY: NULL sbp. iotag=%d. Dropping...",
		    request_tag);
		return;
	}

	if (sbp == STALE_PACKET) {
		cp->hbaCmplCmd_sbp++;
		mutex_exit(&EMLXS_FCTAB_LOCK);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "CQ ENTRY: Stale sbp. iotag=%d. Dropping...", request_tag);
		return;
	}

	if (sbp->pkt_flags & PACKET_IN_CHIPQ) {
		atomic_add_32(&hba->io_active, -1);
#ifdef NODE_THROTTLE_SUPPORT
		if (sbp->node) {
			atomic_add_32(&sbp->node->io_active, -1);
		}
#endif /* NODE_THROTTLE_SUPPORT */
	}

	if (!(sbp->xrip)) {
		cp->hbaCmplCmd++;
		mutex_exit(&EMLXS_FCTAB_LOCK);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "CQ ENTRY: NULL sbp xrip %p. iotag=%d. Dropping...",
		    sbp, request_tag);
		return;
	}

#ifdef DEBUG_FASTPATH
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "CQ ENTRY: process wqe compl");
#endif /* DEBUG_FASTPATH */
	cp->hbaCmplCmd_sbp++;

	/* Copy entry to sbp's iocbq */
	iocbq = &sbp->iocbq;
	emlxs_CQE_to_IOCB(hba, cqe, sbp);

	iocbq->next = NULL;

	if (cqe->XB) {
		/* Mark exchange as ABORT in progress */
		sbp->xrip->flag &= ~EMLXS_XRI_PENDING_IO;
		sbp->xrip->flag |= EMLXS_XRI_BUSY;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "CQ ENTRY: XRI BUSY: iotag=%d xri=%d", request_tag,
		    sbp->xrip->XRI);

		emlxs_sli4_free_xri(port, sbp, 0, 0);
	} else {
		/* Exchange is no longer busy on-chip, free it */
		emlxs_sli4_free_xri(port, sbp, sbp->xrip, 0);
	}

	mutex_exit(&EMLXS_FCTAB_LOCK);

#ifdef SFCT_SUPPORT
#ifdef FCT_IO_TRACE
	fct_cmd = sbp->fct_cmd;
	if (fct_cmd) {
		cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;
		mutex_enter(&cmd_sbp->fct_mtx);
		EMLXS_FCT_STATE_CHG(fct_cmd, cmd_sbp, EMLXS_FCT_IOCB_COMPLETE);
		mutex_exit(&cmd_sbp->fct_mtx);
	}
#endif /* FCT_IO_TRACE */
#endif /* SFCT_SUPPORT */

	/*
	 * If this is NOT a polled command completion
	 * or a driver allocated pkt, then defer pkt
	 * completion.
	 */
	if (!(sbp->pkt_flags &
	    (PACKET_POLLED | PACKET_ALLOCATED))) {
		/* Add the IOCB to the channel list */
		mutex_enter(&cp->rsp_lock);
		if (cp->rsp_head == NULL) {
			cp->rsp_head = iocbq;
			cp->rsp_tail = iocbq;
		} else {
			cp->rsp_tail->next = iocbq;
			cp->rsp_tail = iocbq;
		}
		mutex_exit(&cp->rsp_lock);

		/* Delay triggering thread till end of ISR */
		cp->chan_flag |= EMLXS_NEEDS_TRIGGER;
	} else {
		emlxs_proc_channel_event(hba, cp, iocbq);
	}

} /* emlxs_sli4_process_wqe_cmpl() */


/*ARGSUSED*/
static void
emlxs_sli4_process_release_wqe(emlxs_hba_t *hba, CQ_DESC_t *cq,
    CQE_RelWQ_t *cqe)
{
	emlxs_port_t *port = &PPORT;
	WQ_DESC_t *wq;
	CHANNEL *cp;
	uint32_t i;
	uint16_t wqi;

	wqi = emlxs_sli4_wqid_to_index(hba, (uint16_t)cqe->WQid);

	/* Verify WQ index */
	if (wqi == 0xffff) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_err_msg,
		    "CQ ENTRY: Invalid WQid:%d. Dropping...",
		    cqe->WQid);
		return;
	}

	wq = &hba->sli.sli4.wq[wqi];

#ifdef DEBUG_FASTPATH
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "CQ ENTRY: process release wqe: old %d new %d", wq->port_index,
	    cqe->WQindex);
#endif /* DEBUG_FASTPATH */

	wq->port_index = cqe->WQindex;

	/* Cmd ring may be available. Try sending more iocbs */
	for (i = 0; i < hba->chan_count; i++) {
		cp = &hba->chan[i];
		if (wq == (WQ_DESC_t *)cp->iopath) {
			emlxs_sli4_issue_iocb_cmd(hba, cp, 0);
		}
	}

} /* emlxs_sli4_process_release_wqe() */


/*ARGSUSED*/
emlxs_iocbq_t *
emlxs_sli4_rxq_get(emlxs_hba_t *hba, fc_frame_hdr_t *fchdr)
{
	emlxs_queue_t *q;
	emlxs_iocbq_t *iocbq;
	emlxs_iocbq_t *prev;
	fc_frame_hdr_t *fchdr2;
	RXQ_DESC_t *rxq;

	switch (fchdr->type) {
	case 1: /* ELS */
		rxq = &hba->sli.sli4.rxq[EMLXS_RXQ_ELS];
		break;
	case 0x20: /* CT */
		rxq = &hba->sli.sli4.rxq[EMLXS_RXQ_CT];
		break;
	default:
		return (NULL);
	}

	mutex_enter(&rxq->lock);

	q = &rxq->active;
	iocbq  = (emlxs_iocbq_t *)q->q_first;
	prev = NULL;

	while (iocbq) {

		fchdr2 = (fc_frame_hdr_t *)iocbq->iocb.un.ulpWord;

		if ((fchdr2->s_id == fchdr->s_id) &&
		    (fchdr2->ox_id == fchdr->ox_id) &&
		    (fchdr2->seq_id == fchdr->seq_id)) {
			/* Remove iocbq */
			if (prev) {
				prev->next = iocbq->next;
			}
			if (q->q_first == (uint8_t *)iocbq) {
				q->q_first = (uint8_t *)iocbq->next;
			}
			if (q->q_last == (uint8_t *)iocbq) {
				q->q_last = (uint8_t *)prev;
			}
			q->q_cnt--;

			break;
		}

		prev  = iocbq;
		iocbq = iocbq->next;
	}

	mutex_exit(&rxq->lock);

	return (iocbq);

} /* emlxs_sli4_rxq_get() */


/*ARGSUSED*/
void
emlxs_sli4_rxq_put(emlxs_hba_t *hba, emlxs_iocbq_t *iocbq)
{
	emlxs_queue_t *q;
	fc_frame_hdr_t *fchdr;
	RXQ_DESC_t *rxq;

	fchdr = (fc_frame_hdr_t *)iocbq->iocb.RXFCHDR;

	switch (fchdr->type) {
	case 1: /* ELS */
		rxq = &hba->sli.sli4.rxq[EMLXS_RXQ_ELS];
		break;
	case 0x20: /* CT */
		rxq = &hba->sli.sli4.rxq[EMLXS_RXQ_CT];
		break;
	default:
		return;
	}

	mutex_enter(&rxq->lock);

	q = &rxq->active;

	if (q->q_last) {
		((emlxs_iocbq_t *)q->q_last)->next = iocbq;
		q->q_cnt++;
	} else {
		q->q_first = (uint8_t *)iocbq;
		q->q_cnt = 1;
	}

	q->q_last = (uint8_t *)iocbq;
	iocbq->next = NULL;

	mutex_exit(&rxq->lock);

	return;

} /* emlxs_sli4_rxq_put() */


static void
emlxs_sli4_rq_post(emlxs_port_t *port, uint16_t rqid)
{
	emlxs_hba_t *hba = HBA;
	emlxs_rqdbu_t rqdb;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "RQ POST: rqid=%d count=1", rqid);

	/* Ring the RQ doorbell once to repost the RQ buffer */
	rqdb.word = 0;
	rqdb.db.Qid = rqid;
	rqdb.db.NumPosted = 1;

	emlxs_sli4_write_rqdb(hba, rqdb.word);

} /* emlxs_sli4_rq_post() */


/*ARGSUSED*/
static void
emlxs_sli4_process_unsol_rcv(emlxs_hba_t *hba, CQ_DESC_t *cq,
    CQE_UnsolRcv_t *cqe)
{
	emlxs_port_t *port = &PPORT;
	emlxs_port_t *vport;
	RQ_DESC_t *hdr_rq;
	RQ_DESC_t *data_rq;
	MBUF_INFO *hdr_mp;
	MBUF_INFO *data_mp;
	MATCHMAP *seq_mp;
	uint32_t *data;
	fc_frame_hdr_t fchdr;
	uint16_t hdr_rqi;
	uint32_t host_index;
	emlxs_iocbq_t *iocbq = NULL;
	emlxs_iocb_t *iocb;
	emlxs_node_t *node = NULL;
	uint32_t i;
	uint32_t seq_len;
	uint32_t seq_cnt;
	uint32_t buf_type;
	char label[32];
	emlxs_wqe_t *wqe;
	CHANNEL *cp;
	XRIobj_t *xrip;
	RPIobj_t *rpip = NULL;
	uint32_t	cmd;
	uint32_t posted = 0;
	uint32_t abort = 1;
	off_t offset;
	uint32_t status;
	uint32_t data_size;
	uint16_t rqid;
	uint32_t hdr_size;
	fc_packet_t *pkt;
	emlxs_buf_t *sbp;

	if (cqe->Code == CQE_TYPE_UNSOL_RCV_V1) {
		CQE_UnsolRcvV1_t *cqeV1 = (CQE_UnsolRcvV1_t *)cqe;

		status	  = cqeV1->Status;
		data_size = cqeV1->data_size;
		rqid	  = cqeV1->RQid;
		hdr_size  = cqeV1->hdr_size;
	} else {
		status	  = cqe->Status;
		data_size = cqe->data_size;
		rqid	  = cqe->RQid;
		hdr_size  = cqe->hdr_size;
	}

	/* Validate the CQE */

	/* Check status */
	switch (status) {
	case RQ_STATUS_SUCCESS: /* 0x10 */
		break;

	case RQ_STATUS_BUFLEN_EXCEEDED:  /* 0x11 */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_err_msg,
		    "CQ ENTRY: Unsol Rcv: Payload truncated.");
		break;

	case RQ_STATUS_NEED_BUFFER: /* 0x12 */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "CQ ENTRY: Unsol Rcv: Payload buffer needed.");
		return;

	case RQ_STATUS_FRAME_DISCARDED:  /* 0x13 */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "CQ ENTRY: Unsol Rcv: Payload buffer discarded.");
		return;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_err_msg,
		    "CQ ENTRY: Unsol Rcv: Unknown status=%x.",
		    status);
		break;
	}

	/* Make sure there is a frame header */
	if (hdr_size < sizeof (fc_frame_hdr_t)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_err_msg,
		    "CQ ENTRY: Unsol Rcv: FC header too small. Dropping...");
		return;
	}

	hdr_rqi = emlxs_sli4_rqid_to_index(hba, rqid);

	/* Verify RQ index */
	if (hdr_rqi == 0xffff) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_err_msg,
		    "CQ ENTRY: Unsol Rcv: Invalid RQID:%d. Dropping...",
		    rqid);
		return;
	}

	hdr_rq  = &hba->sli.sli4.rq[hdr_rqi];
	data_rq = &hba->sli.sli4.rq[hdr_rqi + 1];

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "CQ ENTRY: Unsol Rcv:%x rqid=%d,%d index=%d status=%x "
	    "hdr_size=%d data_size=%d",
	    cqe->Code, rqid, hdr_rqi, hdr_rq->host_index, status, hdr_size,
	    data_size);

	hdr_rq->num_proc++;

	/* Update host index */
	mutex_enter(&hba->sli.sli4.rq[hdr_rqi].lock);
	host_index = hdr_rq->host_index;
	hdr_rq->host_index++;

	if (hdr_rq->host_index >= hdr_rq->max_index) {
		hdr_rq->host_index = 0;
	}
	data_rq->host_index = hdr_rq->host_index;
	mutex_exit(&hba->sli.sli4.rq[hdr_rqi].lock);

	/* Get the next header rqb */
	hdr_mp  = &hdr_rq->rqb[host_index];

	offset = (off_t)((uint64_t)((unsigned long)hdr_mp->virt) -
	    (uint64_t)((unsigned long)hba->sli.sli4.slim2.virt));

	EMLXS_MPDATA_SYNC(hdr_mp->dma_handle, offset,
	    sizeof (fc_frame_hdr_t), DDI_DMA_SYNC_FORKERNEL);

	LE_SWAP32_BCOPY(hdr_mp->virt, (uint8_t *)&fchdr,
	    sizeof (fc_frame_hdr_t));

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "RQ HDR[%d]: rctl:%x type:%x "
	    "sid:%x did:%x oxid:%x rxid:%x",
	    host_index, fchdr.r_ctl, fchdr.type,
	    fchdr.s_id,  fchdr.d_id, fchdr.ox_id, fchdr.rx_id);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "RQ HDR[%d]: fctl:%x seq_id:%x seq_cnt:%x df_ctl:%x ro:%x",
	    host_index, fchdr.f_ctl, fchdr.seq_id, fchdr.seq_cnt,
	    fchdr.df_ctl, fchdr.ro);

	/* Verify fc header type */
	switch (fchdr.type) {
	case 0: /* BLS */
		if (fchdr.r_ctl != 0x81) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "RQ ENTRY: Unexpected FC rctl (0x%x) "
			    "received. Dropping...",
			    fchdr.r_ctl);

			goto done;
		}

		/* Make sure there is no payload */
		if (data_size != 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_err_msg,
			    "RQ ENTRY: ABTS payload provided. Dropping...");

			goto done;
		}

		buf_type = 0xFFFFFFFF;
		(void) strlcpy(label, "ABTS", sizeof (label));
		cp = &hba->chan[hba->channel_els];
		break;

	case 0x01: /* ELS */
		/* Make sure there is a payload */
		if (data_size == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_err_msg,
			    "RQ ENTRY: Unsol Rcv: No ELS payload provided. "
			    "Dropping...");

			goto done;
		}

		buf_type = MEM_ELSBUF;
		(void) strlcpy(label, "Unsol ELS", sizeof (label));
		cp = &hba->chan[hba->channel_els];
		break;

	case 0x20: /* CT */
		/* Make sure there is a payload */
		if (data_size == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_err_msg,
			    "RQ ENTRY: Unsol Rcv: No CT payload provided. "
			    "Dropping...");

			goto done;
		}

		buf_type = MEM_CTBUF;
		(void) strlcpy(label, "Unsol CT", sizeof (label));
		cp = &hba->chan[hba->channel_ct];
		break;

	case 0x08: /* FCT */
		/* Make sure there is a payload */
		if (data_size == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_err_msg,
			    "RQ ENTRY: Unsol Rcv: No FCP payload provided. "
			    "Dropping...");

			goto done;
		}

		buf_type = MEM_FCTBUF;
		(void) strlcpy(label, "Unsol FCT", sizeof (label));
		cp = &hba->chan[hba->CHANNEL_FCT];
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "RQ ENTRY: Unexpected FC type (0x%x) received. Dropping...",
		    fchdr.type);

		goto done;
	}
	/* Fc Header is valid */

	/* Check if this is an active sequence */
	iocbq = emlxs_sli4_rxq_get(hba, &fchdr);

	if (!iocbq) {
		if (fchdr.type != 0) {
			if (!(fchdr.f_ctl & F_CTL_FIRST_SEQ)) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
				    "RQ ENTRY: %s: First of sequence not"
				    " set.  Dropping...",
				    label);

				goto done;
			}
		}

		if ((fchdr.type != 0) && (fchdr.seq_cnt != 0)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "RQ ENTRY: %s: Sequence count not zero (%d).  "
			    "Dropping...",
			    label, fchdr.seq_cnt);

			goto done;
		}

		/* Find vport */
		for (i = 0; i < MAX_VPORTS; i++) {
			vport = &VPORT(i);

			if (vport->did == fchdr.d_id) {
				port = vport;
				break;
			}
		}

		if (i == MAX_VPORTS) {
			/* Allow unsol FLOGI & PLOGI for P2P */
			if ((fchdr.type != 1 /* ELS*/) ||
			    ((fchdr.d_id != FABRIC_DID) &&
			    !(hba->flag & FC_PT_TO_PT))) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
				    "RQ ENTRY: %s: Invalid did=%x. Dropping...",
				    label, fchdr.d_id);

				goto done;
			}
		}

		/* Allocate an IOCBQ */
		iocbq = (emlxs_iocbq_t *)emlxs_mem_get(hba, MEM_IOCB);

		if (!iocbq) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "RQ ENTRY: %s: Out of IOCB "
			    "resources.  Dropping...",
			    label);

			goto done;
		}

		seq_mp = NULL;
		if (fchdr.type != 0) {
			/* Allocate a buffer */
			seq_mp = (MATCHMAP *)emlxs_mem_get(hba, buf_type);

			if (!seq_mp) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
				    "RQ ENTRY: %s: Out of buffer "
				    "resources.  Dropping...",
				    label);

				goto done;
			}

			iocbq->bp = (uint8_t *)seq_mp;
		}

		node = (void *)emlxs_node_find_did(port, fchdr.s_id, 1);
		if (node == NULL) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "RQ ENTRY: %s: Node not found. sid=%x",
			    label, fchdr.s_id);
		}

		/* Initialize the iocbq */
		iocbq->port = port;
		iocbq->channel = cp;
		iocbq->node = node;

		iocb = &iocbq->iocb;
		iocb->RXSEQCNT = 0;
		iocb->RXSEQLEN = 0;

		seq_len = 0;
		seq_cnt = 0;

	} else {

		iocb = &iocbq->iocb;
		port = iocbq->port;
		node = (emlxs_node_t *)iocbq->node;

		seq_mp = (MATCHMAP *)iocbq->bp;
		seq_len = iocb->RXSEQLEN;
		seq_cnt = iocb->RXSEQCNT;

		/* Check sequence order */
		if (fchdr.seq_cnt != seq_cnt) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "RQ ENTRY: %s: Out of order frame received "
			    "(%d != %d).  Dropping...",
			    label, fchdr.seq_cnt, seq_cnt);

			goto done;
		}
	}

	/* We now have an iocbq */

	if (!port->vpip->vfip) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "RQ ENTRY: %s: No fabric connection. "
		    "Dropping...",
		    label);

		goto done;
	}

	/* Save the frame data to our seq buffer */
	if (data_size && seq_mp) {
		/* Get the next data rqb */
		data_mp = &data_rq->rqb[host_index];

		offset = (off_t)((uint64_t)((unsigned long)
		    data_mp->virt) -
		    (uint64_t)((unsigned long)
		    hba->sli.sli4.slim2.virt));

		EMLXS_MPDATA_SYNC(data_mp->dma_handle, offset,
		    data_size, DDI_DMA_SYNC_FORKERNEL);

		data = (uint32_t *)data_mp->virt;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "RQ DAT[%d]: %08x %08x %08x %08x %08x %08x ...",
		    host_index, data[0], data[1], data[2], data[3],
		    data[4], data[5]);

		/* Check sequence length */
		if ((seq_len + data_size) > seq_mp->size) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_err_msg,
			    "RQ ENTRY: %s: Sequence buffer overflow. "
			    "(%d > %d). Dropping...",
			    label, (seq_len + data_size), seq_mp->size);

			goto done;
		}

		/* Copy data to local receive buffer */
		bcopy((uint8_t *)data, ((uint8_t *)seq_mp->virt +
		    seq_len), data_size);

		seq_len += data_size;
	}

	/* If this is not the last frame of sequence, queue it. */
	if (!(fchdr.f_ctl & F_CTL_END_SEQ)) {
		/* Save sequence header */
		if (seq_cnt == 0) {
			bcopy((uint8_t *)&fchdr, (uint8_t *)iocb->RXFCHDR,
			    sizeof (fc_frame_hdr_t));
		}

		/* Update sequence info in iocb */
		iocb->RXSEQCNT = seq_cnt + 1;
		iocb->RXSEQLEN = seq_len;

		/* Queue iocbq for next frame */
		emlxs_sli4_rxq_put(hba, iocbq);

		/* Don't free resources */
		iocbq = NULL;

		/* No need to abort */
		abort = 0;

		goto done;
	}

	emlxs_sli4_rq_post(port, hdr_rq->qid);
	posted = 1;

	/* End of sequence found. Process request now. */

	if (seq_cnt > 0) {
		/* Retrieve first frame of sequence */
		bcopy((uint8_t *)iocb->RXFCHDR, (uint8_t *)&fchdr,
		    sizeof (fc_frame_hdr_t));

		bzero((uint8_t *)iocb, sizeof (emlxs_iocb_t));
	}

	/* Build rcv iocb and process it */
	switch (fchdr.type) {
	case 0: /* BLS */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "RQ ENTRY: %s: oxid:%x rxid %x sid:%x. Sending BLS ACC...",
		    label, fchdr.ox_id, fchdr.rx_id, fchdr.s_id);

		/* Try to send abort response */
		if (!(pkt = emlxs_pkt_alloc(port, 0, 0, 0, KM_NOSLEEP))) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "RQ ENTRY: %s: Unable to alloc pkt. Dropping...",
			    label);
			goto done;
		}

		/* Setup sbp / iocb for driver initiated cmd */
		sbp = PKT2PRIV(pkt);

		/* Free the temporary iocbq */
		emlxs_mem_put(hba, MEM_IOCB, (void *)iocbq);

		iocbq = (emlxs_iocbq_t *)&sbp->iocbq;
		iocbq->port = port;
		iocbq->channel = cp;
		iocbq->node = node;

		sbp->pkt_flags &= ~PACKET_ULP_OWNED;

		if (node) {
			sbp->node = node;
			sbp->did  = node->nlp_DID;
		}

		iocbq->flag |= (IOCB_PRIORITY | IOCB_SPECIAL);

		/* BLS ACC Response */
		wqe = &iocbq->wqe;
		bzero((void *)wqe, sizeof (emlxs_wqe_t));

		iocbq->iocb.ULPCOMMAND = CMD_XMIT_BLS_RSP64_CX;
		wqe->Command = CMD_XMIT_BLS_RSP64_CX;
		wqe->CmdType = WQE_TYPE_GEN;

		wqe->un.BlsRsp.Payload0 = 0x80;
		wqe->un.BlsRsp.Payload1 = fchdr.seq_id;

		wqe->un.BlsRsp.OXId = fchdr.ox_id;
		wqe->un.BlsRsp.RXId = fchdr.rx_id;

		wqe->un.BlsRsp.SeqCntLow = 0;
		wqe->un.BlsRsp.SeqCntHigh = 0xFFFF;

		wqe->un.BlsRsp.XO = ((fchdr.f_ctl & F_CTL_XCHG_CONTEXT)? 1:0);
		wqe->un.BlsRsp.AR = 0;

		rpip = EMLXS_NODE_TO_RPI(port, node);

		if (rpip) {
			wqe->ContextType = WQE_RPI_CONTEXT;
			wqe->ContextTag = rpip->RPI;
		} else {
			wqe->ContextType = WQE_VPI_CONTEXT;
			wqe->ContextTag = port->vpip->VPI;

			rpip = emlxs_rpi_reserve_notify(port, fchdr.s_id, 0);

			if (!rpip) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
				    "RQ ENTRY: %s: Unable to alloc "
				    "reserved RPI. Dropping...",
				    label);

				goto done;
			}

			/* Store the reserved rpi */
			wqe->CmdSpecific = rpip->RPI;

			wqe->un.BlsRsp.RemoteId = fchdr.s_id;
			wqe->un.BlsRsp.LocalId = fchdr.d_id;
		}

		if (fchdr.f_ctl & F_CTL_CHAINED_SEQ) {
			wqe->CCPE = 1;
			wqe->CCP = fchdr.rsvd;
		}

		/* Allocate an exchange for this command */
		xrip = emlxs_sli4_alloc_xri(port, sbp, rpip,
		    EMLXS_XRI_SOL_BLS_TYPE);

		if (!xrip) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "RQ ENTRY: %s: Unable to alloc XRI. Dropping...",
			    label);
			goto done;
		}

		wqe->XRITag = xrip->XRI;
		wqe->Class = CLASS3;
		wqe->RequestTag = xrip->iotag;
		wqe->CQId = (uint16_t)0xffff;  /* default CQ for response */

		sbp->ticks = hba->timer_tics + 30;

		emlxs_sli4_issue_iocb_cmd(hba, iocbq->channel, iocbq);

		/* The temporary iocbq has been freed already */
		iocbq = NULL;

		break;

	case 1: /* ELS */
		cmd = *((uint32_t *)seq_mp->virt);
		cmd &= ELS_CMD_MASK;

		if (!(port->vpip->flag & EMLXS_VPI_PORT_ENABLED)) {
			uint32_t dropit = 1;

			/* Allow for P2P handshaking */
			switch (cmd) {
			case ELS_CMD_FLOGI:
				dropit = 0;
				break;

			case ELS_CMD_PLOGI:
			case ELS_CMD_PRLI:
				if (hba->flag & FC_PT_TO_PT) {
					dropit = 0;
				}
				break;
			}

			if (dropit) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_sli_detail_msg,
				    "RQ ENTRY: %s: Port not yet enabled. "
				    "Dropping...",
				    label);
				goto done;
			}
		}

		rpip = NULL;

		if (cmd != ELS_CMD_LOGO) {
			rpip = EMLXS_NODE_TO_RPI(port, node);
		}

		if (!rpip) {
			/* Use the fabric rpi */
			rpip = port->vpip->fabric_rpip;
		}

		xrip = emlxs_sli4_reserve_xri(port, rpip,
		    EMLXS_XRI_UNSOL_ELS_TYPE, fchdr.ox_id);

		if (!xrip) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "RQ ENTRY: %s: Out of exchange "
			    "resources.  Dropping...",
			    label);

			goto done;
		}

		/* Build CMD_RCV_ELS64_CX */
		iocb->un.rcvels64.elsReq.tus.f.bdeFlags = 0;
		iocb->un.rcvels64.elsReq.tus.f.bdeSize  = seq_len;
		iocb->un.rcvels64.elsReq.addrLow  = PADDR_LO(seq_mp->phys);
		iocb->un.rcvels64.elsReq.addrHigh = PADDR_HI(seq_mp->phys);
		iocb->ULPBDECOUNT = 1;

		iocb->un.rcvels64.remoteID = fchdr.s_id;
		iocb->un.rcvels64.parmRo = fchdr.d_id;

		iocb->ULPPU = 0x3;
		iocb->ULPCONTEXT = xrip->XRI;
		iocb->ULPIOTAG = ((node)? node->nlp_Rpi:0);
		iocb->ULPCLASS = CLASS3;
		iocb->ULPCOMMAND = CMD_RCV_ELS64_CX;

		iocb->unsli3.ext_rcv.seq_len = seq_len;
		iocb->unsli3.ext_rcv.vpi = port->vpip->VPI;
		iocb->unsli3.ext_rcv.oxid = fchdr.ox_id;

		if (fchdr.f_ctl & F_CTL_CHAINED_SEQ) {
			iocb->unsli3.ext_rcv.ccpe = 1;
			iocb->unsli3.ext_rcv.ccp = fchdr.rsvd;
		}

		if (port->mode == MODE_INITIATOR) {
			(void) emlxs_els_handle_unsol_req(port, iocbq->channel,
			    iocbq, seq_mp, seq_len);
		}
#ifdef SFCT_SUPPORT
		else if (port->mode == MODE_TARGET) {
			(void) emlxs_fct_handle_unsol_els(port, iocbq->channel,
			    iocbq, seq_mp, seq_len);
		}
#endif /* SFCT_SUPPORT */
		break;

#ifdef SFCT_SUPPORT
	case 8: /* FCT */
		if (!(port->VPIobj.flag & EMLXS_VPI_PORT_ENABLED)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "RQ ENTRY: %s: Port not yet enabled. "
			    "Dropping...",
			    label);

			goto done;
		}

		rpip = EMLXS_NODE_TO_RPI(port, node);

		if (!rpip) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "RQ ENTRY: %s: Port not logged in. "
			    "Dropping...",
			    label);

			goto done;
		}

		xrip = emlxs_sli4_reserve_xri(port, rpip,
		    EMLXS_XRI_UNSOL_FCP_TYPE, fchdr.ox_id);

		if (!xrip) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "RQ ENTRY: %s: Out of exchange "
			    "resources.  Dropping...",
			    label);

			goto done;
		}

		/* Build CMD_RCV_SEQUENCE64_CX */
		iocb->un.rcvseq64.rcvBde.tus.f.bdeFlags = 0;
		iocb->un.rcvseq64.rcvBde.tus.f.bdeSize  = seq_len;
		iocb->un.rcvseq64.rcvBde.addrLow  = PADDR_LO(seq_mp->phys);
		iocb->un.rcvseq64.rcvBde.addrHigh = PADDR_HI(seq_mp->phys);
		iocb->ULPBDECOUNT = 1;

		iocb->ULPPU = 0x3;
		iocb->ULPCONTEXT = xrip->XRI;
		iocb->ULPIOTAG = ((node)? node->nlp_Rpi:0);
		iocb->ULPCLASS = CLASS3;
		iocb->ULPCOMMAND = CMD_RCV_ELS64_CX;

		iocb->unsli3.ext_rcv.seq_len = seq_len;
		iocb->unsli3.ext_rcv.vpi = port->VPIobj.VPI;
		iocb->unsli3.ext_rcv.oxid = fchdr.ox_id;

		if (fchdr.f_ctl & F_CTL_CHAINED_SEQ) {
			iocb->unsli3.ext_rcv.ccpe = 1;
			iocb->unsli3.ext_rcv.ccp = fchdr.rsvd;
		}

		/* pass xrip to FCT in the iocbq */
		iocbq->sbp = xrip;

#define	EMLXS_FIX_CISCO_BUG1
#ifdef EMLXS_FIX_CISCO_BUG1
{
uint8_t *ptr;
ptr = ((uint8_t *)seq_mp->virt);
if (((*ptr+12) != 0xa0) && (*(ptr+20) == 0x8) && (*(ptr+21) == 0x8)) {
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_err_msg,
	    "RQ ENTRY: Bad CDB fixed");
	*ptr++ = 0;
	*ptr = 0;
}
}
#endif
		(void) emlxs_fct_handle_unsol_req(port, cp, iocbq,
			seq_mp, seq_len);
		break;
#endif /* SFCT_SUPPORT */

	case 0x20: /* CT */
		if (!(port->vpip->flag & EMLXS_VPI_PORT_ENABLED) &&
		    !(hba->flag & FC_LOOPBACK_MODE)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "RQ ENTRY: %s: Port not yet enabled. "
			    "Dropping...",
			    label);

			goto done;
		}

		if (!node) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "RQ ENTRY: %s: Node not found (did=%x).  "
			    "Dropping...",
			    label, fchdr.d_id);

			goto done;
		}

		rpip = EMLXS_NODE_TO_RPI(port, node);

		if (!rpip) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "RQ ENTRY: %s: RPI not found (did=%x rpi=%d).  "
			    "Dropping...",
			    label, fchdr.d_id, node->nlp_Rpi);

			goto done;
		}

		xrip = emlxs_sli4_reserve_xri(port, rpip,
		    EMLXS_XRI_UNSOL_CT_TYPE, fchdr.ox_id);

		if (!xrip) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "RQ ENTRY: %s: Out of exchange "
			    "resources.  Dropping...",
			    label);

			goto done;
		}

		/* Build CMD_RCV_SEQ64_CX */
		iocb->un.rcvseq64.rcvBde.tus.f.bdeFlags = 0;
		iocb->un.rcvseq64.rcvBde.tus.f.bdeSize  = seq_len;
		iocb->un.rcvseq64.rcvBde.addrLow  = PADDR_LO(seq_mp->phys);
		iocb->un.rcvseq64.rcvBde.addrHigh = PADDR_HI(seq_mp->phys);
		iocb->ULPBDECOUNT = 1;

		iocb->un.rcvseq64.xrsqRo = 0;
		iocb->un.rcvseq64.w5.hcsw.Rctl = fchdr.r_ctl;
		iocb->un.rcvseq64.w5.hcsw.Type = fchdr.type;
		iocb->un.rcvseq64.w5.hcsw.Dfctl = fchdr.df_ctl;
		iocb->un.rcvseq64.w5.hcsw.Fctl = fchdr.f_ctl;

		iocb->ULPPU = 0x3;
		iocb->ULPCONTEXT = xrip->XRI;
		iocb->ULPIOTAG = rpip->RPI;
		iocb->ULPCLASS = CLASS3;
		iocb->ULPCOMMAND = CMD_RCV_SEQ64_CX;

		iocb->unsli3.ext_rcv.seq_len = seq_len;
		iocb->unsli3.ext_rcv.vpi = port->vpip->VPI;

		if (fchdr.f_ctl & F_CTL_CHAINED_SEQ) {
			iocb->unsli3.ext_rcv.ccpe = 1;
			iocb->unsli3.ext_rcv.ccp = fchdr.rsvd;
		}

		(void) emlxs_ct_handle_unsol_req(port, iocbq->channel,
		    iocbq, seq_mp, seq_len);

		break;
	}

	/* Sequence handled, no need to abort */
	abort = 0;

done:

	if (!posted) {
		emlxs_sli4_rq_post(port, hdr_rq->qid);
	}

	if (abort) {
		/* Send ABTS for this exchange */
		/* !!! Currently, we have no implementation for this !!! */
		abort = 0;
	}

	/* Return memory resources to pools */
	if (iocbq) {
		if (iocbq->bp) {
			emlxs_mem_put(hba, buf_type, (void *)iocbq->bp);
			iocbq->bp = 0;
		}

		emlxs_mem_put(hba, MEM_IOCB, (void *)iocbq);
	}

#ifdef FMA_SUPPORT
	if (emlxs_fm_check_dma_handle(hba,
	    hba->sli.sli4.slim2.dma_handle)
	    != DDI_FM_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_invalid_dma_handle_msg,
		    "sli4_process_unsol_rcv: hdl=%p",
		    hba->sli.sli4.slim2.dma_handle);

		emlxs_thread_spawn(hba, emlxs_restart_thread,
		    0, 0);
	}
#endif
	return;

} /* emlxs_sli4_process_unsol_rcv() */


/*ARGSUSED*/
static void
emlxs_sli4_process_xri_aborted(emlxs_hba_t *hba, CQ_DESC_t *cq,
    CQE_XRI_Abort_t *cqe)
{
	emlxs_port_t *port = &PPORT;
	XRIobj_t *xrip;

	mutex_enter(&EMLXS_FCTAB_LOCK);

	xrip = emlxs_sli4_find_xri(port, cqe->XRI);
	if (xrip == NULL) {
		/* EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_err_msg, */
		/*    "CQ ENTRY: process xri aborted ignored");  */

		mutex_exit(&EMLXS_FCTAB_LOCK);
		return;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "CQ ENTRY: XRI Aborted: xri=%d IA=%d EO=%d BR=%d",
	    cqe->XRI, cqe->IA, cqe->EO, cqe->BR);

	if (!(xrip->flag & EMLXS_XRI_BUSY)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_err_msg,
		    "CQ ENTRY: XRI Aborted: xri=%d flag=%x. Bad state.",
		    xrip->XRI, xrip->flag);

		mutex_exit(&EMLXS_FCTAB_LOCK);
		return;
	}

	/* Exchange is no longer busy on-chip, free it */
	emlxs_sli4_free_xri(port, 0, xrip, 0);

	mutex_exit(&EMLXS_FCTAB_LOCK);

	return;

} /* emlxs_sli4_process_xri_aborted () */


/*ARGSUSED*/
static void
emlxs_sli4_process_cq(emlxs_hba_t *hba, CQ_DESC_t *cq)
{
	emlxs_port_t *port = &PPORT;
	CQE_u *cqe;
	CQE_u cq_entry;
	uint32_t cqdb;
	int num_entries = 0;
	off_t offset;

	/* EMLXS_PORT_LOCK must be held when entering this routine */

	cqe = (CQE_u *)cq->addr.virt;
	cqe += cq->host_index;

	offset = (off_t)((uint64_t)((unsigned long)
	    cq->addr.virt) -
	    (uint64_t)((unsigned long)
	    hba->sli.sli4.slim2.virt));

	EMLXS_MPDATA_SYNC(cq->addr.dma_handle, offset,
	    4096, DDI_DMA_SYNC_FORKERNEL);

	for (;;) {
		cq_entry.word[3] = BE_SWAP32(cqe->word[3]);
		if (!(cq_entry.word[3] & CQE_VALID)) {
			break;
		}

		cq_entry.word[2] = BE_SWAP32(cqe->word[2]);
		cq_entry.word[1] = BE_SWAP32(cqe->word[1]);
		cq_entry.word[0] = BE_SWAP32(cqe->word[0]);

#ifdef	DEBUG_CQE
		emlxs_data_dump(port, "CQE", (uint32_t *)cqe, 6, 0);
#endif /* DEBUG_CQE */
		num_entries++;
		cqe->word[3] = 0;

		cq->host_index++;
		if (cq->host_index >= cq->max_index) {
			cq->host_index = 0;
			cqe = (CQE_u *)cq->addr.virt;
		} else {
			cqe++;
		}
		mutex_exit(&EMLXS_PORT_LOCK);

		/* Now handle specific cq type */
		if (cq->type == EMLXS_CQ_TYPE_GROUP1) {
			if (cq_entry.cqAsyncEntry.async_evt) {
				emlxs_sli4_process_async_event(hba,
				    (CQE_ASYNC_t *)&cq_entry);
			} else {
				emlxs_sli4_process_mbox_event(hba,
				    (CQE_MBOX_t *)&cq_entry);
			}
		} else { /* EMLXS_CQ_TYPE_GROUP2 */
			switch (cq_entry.cqCmplEntry.Code) {
			case CQE_TYPE_WQ_COMPLETION:
				if (cq_entry.cqCmplEntry.RequestTag <
				    hba->max_iotag) {
					emlxs_sli4_process_wqe_cmpl(hba, cq,
					    (CQE_CmplWQ_t *)&cq_entry);
				} else {
					emlxs_sli4_process_oor_wqe_cmpl(hba, cq,
					    (CQE_CmplWQ_t *)&cq_entry);
				}
				break;
			case CQE_TYPE_RELEASE_WQE:
				emlxs_sli4_process_release_wqe(hba, cq,
				    (CQE_RelWQ_t *)&cq_entry);
				break;
			case CQE_TYPE_UNSOL_RCV:
			case CQE_TYPE_UNSOL_RCV_V1:
				emlxs_sli4_process_unsol_rcv(hba, cq,
				    (CQE_UnsolRcv_t *)&cq_entry);
				break;
			case CQE_TYPE_XRI_ABORTED:
				emlxs_sli4_process_xri_aborted(hba, cq,
				    (CQE_XRI_Abort_t *)&cq_entry);
				break;
			default:
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_err_msg,
				    "Invalid CQ entry %d: %08x %08x %08x %08x",
				    cq_entry.cqCmplEntry.Code, cq_entry.word[0],
				    cq_entry.word[1], cq_entry.word[2],
				    cq_entry.word[3]);
				break;
			}
		}

		mutex_enter(&EMLXS_PORT_LOCK);
	}

	/* Number of times this routine gets called for this CQ */
	cq->isr_count++;

	/* num_entries is the number of CQEs we process in this specific CQ */
	cq->num_proc += num_entries;
	if (cq->max_proc < num_entries)
		cq->max_proc = num_entries;

	cqdb = cq->qid;
	cqdb |= CQ_DB_REARM;
	if (num_entries != 0) {
		cqdb |= ((num_entries << CQ_DB_POP_SHIFT) & CQ_DB_POP_MASK);
	}

#ifdef DEBUG_FASTPATH
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "CQE: CLEAR cqdb=%08x: pops=%d", cqdb, num_entries);
#endif /* DEBUG_FASTPATH */

	emlxs_sli4_write_cqdb(hba, cqdb);

	/* EMLXS_PORT_LOCK must be held when exiting this routine */

} /* emlxs_sli4_process_cq() */


/*ARGSUSED*/
static void
emlxs_sli4_process_eq(emlxs_hba_t *hba, EQ_DESC_t *eq)
{
	emlxs_port_t *port = &PPORT;
	uint32_t eqdb;
	uint32_t *ptr;
	CHANNEL *cp;
	EQE_u eqe;
	uint32_t i;
	uint16_t cqi;
	int num_entries = 0;
	off_t offset;

	/* EMLXS_PORT_LOCK must be held when entering this routine */

	hba->intr_busy_cnt ++;

	ptr = eq->addr.virt;
	ptr += eq->host_index;

	offset = (off_t)((uint64_t)((unsigned long)
	    eq->addr.virt) -
	    (uint64_t)((unsigned long)
	    hba->sli.sli4.slim2.virt));

	EMLXS_MPDATA_SYNC(eq->addr.dma_handle, offset,
	    4096, DDI_DMA_SYNC_FORKERNEL);

	for (;;) {
		eqe.word = *ptr;
		eqe.word = BE_SWAP32(eqe.word);

		if (!(eqe.word & EQE_VALID)) {
			break;
		}

#ifdef DEBUG_FASTPATH
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "EQE00: %08x", eqe.word);
#endif /* DEBUG_FASTPATH */

		*ptr = 0;
		num_entries++;
		eq->host_index++;
		if (eq->host_index >= eq->max_index) {
			eq->host_index = 0;
			ptr = eq->addr.virt;
		} else {
			ptr++;
		}

		cqi = emlxs_sli4_cqid_to_index(hba, eqe.entry.CQId);

		/* Verify CQ index */
		if (cqi == 0xffff) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_err_msg,
			    "EQE: Invalid CQid: %d. Dropping...",
			    eqe.entry.CQId);
			continue;
		}

#ifdef DEBUG_FASTPATH
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "EQE: CQIndex:%x cqid:%x", cqi, eqe.entry.CQId);
#endif /* DEBUG_FASTPATH */

		emlxs_sli4_process_cq(hba, &hba->sli.sli4.cq[cqi]);
	}

	/* Number of times the ISR for this EQ gets called */
	eq->isr_count++;

	/* num_entries is the number of EQEs we process in this specific ISR */
	eq->num_proc += num_entries;
	if (eq->max_proc < num_entries) {
		eq->max_proc = num_entries;
	}

	eqdb = eq->qid;
	eqdb |= (EQ_DB_CLEAR | EQ_DB_EVENT | EQ_DB_REARM);

#ifdef DEBUG_FASTPATH
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "EQE: CLEAR eqdb=%08x pops=%d", eqdb, num_entries);
#endif /* DEBUG_FASTPATH */

	if (num_entries != 0) {
		eqdb |= ((num_entries << EQ_DB_POP_SHIFT) & EQ_DB_POP_MASK);
		for (i = 0; i < hba->chan_count; i++) {
			cp = &hba->chan[i];
			if (cp->chan_flag & EMLXS_NEEDS_TRIGGER) {
				cp->chan_flag &= ~EMLXS_NEEDS_TRIGGER;
				emlxs_thread_trigger2(&cp->intr_thread,
				    emlxs_proc_channel, cp);
			}
		}
	}

	emlxs_sli4_write_cqdb(hba, eqdb);

	/* EMLXS_PORT_LOCK must be held when exiting this routine */

	hba->intr_busy_cnt --;

} /* emlxs_sli4_process_eq() */


#ifdef MSI_SUPPORT
/*ARGSUSED*/
static uint32_t
emlxs_sli4_msi_intr(char *arg1, char *arg2)
{
	emlxs_hba_t *hba = (emlxs_hba_t *)arg1;
#ifdef DEBUG_FASTPATH
	emlxs_port_t *port = &PPORT;
#endif /* DEBUG_FASTPATH */
	uint16_t msgid;
	int rc;

#ifdef DEBUG_FASTPATH
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "msiINTR arg1:%p arg2:%p", arg1, arg2);
#endif /* DEBUG_FASTPATH */

	/* Check for legacy interrupt handling */
	if (hba->intr_type == DDI_INTR_TYPE_FIXED) {
		rc = emlxs_sli4_intx_intr(arg1);
		return (rc);
	}

	/* Get MSI message id */
	msgid = (uint16_t)((unsigned long)arg2);

	/* Validate the message id */
	if (msgid >= hba->intr_count) {
		msgid = 0;
	}
	mutex_enter(&EMLXS_PORT_LOCK);

	if ((hba->state == FC_KILLED) || (hba->flag & FC_OFFLINE_MODE)) {
		mutex_exit(&EMLXS_PORT_LOCK);
		return (DDI_INTR_UNCLAIMED);
	}

	/* The eq[] index == the MSI vector number */
	emlxs_sli4_process_eq(hba, &hba->sli.sli4.eq[msgid]);

	mutex_exit(&EMLXS_PORT_LOCK);
	return (DDI_INTR_CLAIMED);

} /* emlxs_sli4_msi_intr() */
#endif /* MSI_SUPPORT */


/*ARGSUSED*/
static int
emlxs_sli4_intx_intr(char *arg)
{
	emlxs_hba_t *hba = (emlxs_hba_t *)arg;
#ifdef DEBUG_FASTPATH
	emlxs_port_t *port = &PPORT;
#endif /* DEBUG_FASTPATH */

#ifdef DEBUG_FASTPATH
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "intxINTR arg:%p", arg);
#endif /* DEBUG_FASTPATH */

	mutex_enter(&EMLXS_PORT_LOCK);

	if ((hba->state == FC_KILLED) || (hba->flag & FC_OFFLINE_MODE)) {
		mutex_exit(&EMLXS_PORT_LOCK);
		return (DDI_INTR_UNCLAIMED);
	}

	emlxs_sli4_process_eq(hba, &hba->sli.sli4.eq[0]);

	mutex_exit(&EMLXS_PORT_LOCK);
	return (DDI_INTR_CLAIMED);
} /* emlxs_sli4_intx_intr() */


static void
emlxs_sli4_hba_kill(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	uint32_t j;

	mutex_enter(&EMLXS_PORT_LOCK);
	if (hba->flag & FC_INTERLOCKED) {
		EMLXS_STATE_CHANGE_LOCKED(hba, FC_KILLED);

		mutex_exit(&EMLXS_PORT_LOCK);

		return;
	}

	j = 0;
	while (j++ < 10000) {
		if ((hba->mbox_queue_flag == 0) &&
		    (hba->intr_busy_cnt == 0)) {
			break;
		}

		mutex_exit(&EMLXS_PORT_LOCK);
		BUSYWAIT_US(100);
		mutex_enter(&EMLXS_PORT_LOCK);
	}

	if ((hba->mbox_queue_flag != 0) || (hba->intr_busy_cnt > 0)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Board kill failed. Adapter busy, %d, %d.",
		    hba->mbox_queue_flag, hba->intr_busy_cnt);
		mutex_exit(&EMLXS_PORT_LOCK);
		return;
	}

	hba->flag |= FC_INTERLOCKED;

	EMLXS_STATE_CHANGE_LOCKED(hba, FC_KILLED);

	mutex_exit(&EMLXS_PORT_LOCK);

} /* emlxs_sli4_hba_kill() */


extern void
emlxs_sli4_hba_reset_all(emlxs_hba_t *hba, uint32_t flag)
{
	emlxs_port_t *port = &PPORT;
	uint32_t value;

	mutex_enter(&EMLXS_PORT_LOCK);

	if ((hba->sli_intf & SLI_INTF_IF_TYPE_MASK) != SLI_INTF_IF_TYPE_2) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_debug_msg,
		    "Reset All failed. Invalid Operation.");
		mutex_exit(&EMLXS_PORT_LOCK);
		return;
	}

	/* Issue a Firmware Reset All Request */
	if (flag) {
		value = SLI_PHYDEV_FRST | SLI_PHYDEV_FRL_ALL | SLI_PHYDEV_DD;
	} else {
		value = SLI_PHYDEV_FRST | SLI_PHYDEV_FRL_ALL;
	}

	ddi_put32(hba->sli.sli4.bar0_acc_handle,
	    hba->sli.sli4.PHYSDEV_reg_addr, value);

	mutex_exit(&EMLXS_PORT_LOCK);

} /* emlxs_sli4_hba_reset_all() */


static void
emlxs_sli4_enable_intr(emlxs_hba_t *hba)
{
	emlxs_config_t *cfg = &CFG;
	int i;
	int num_cq;
	uint32_t data;

	hba->sli.sli4.flag |= EMLXS_SLI4_INTR_ENABLED;

	num_cq = (hba->intr_count * cfg[CFG_NUM_WQ].current) +
	    EMLXS_CQ_OFFSET_WQ;

	/* ARM EQ / CQs */
	for (i = 0; i < num_cq; i++) {
		data = hba->sli.sli4.cq[i].qid;
		data |= CQ_DB_REARM;
		emlxs_sli4_write_cqdb(hba, data);
	}
	for (i = 0; i < hba->intr_count; i++) {
		data = hba->sli.sli4.eq[i].qid;
		data |= (EQ_DB_REARM | EQ_DB_EVENT);
		emlxs_sli4_write_cqdb(hba, data);
	}
} /* emlxs_sli4_enable_intr() */


static void
emlxs_sli4_disable_intr(emlxs_hba_t *hba, uint32_t att)
{
	if (att) {
		return;
	}

	hba->sli.sli4.flag &= ~EMLXS_SLI4_INTR_ENABLED;

	/* Short of reset, we cannot disable interrupts */
} /* emlxs_sli4_disable_intr() */


static void
emlxs_sli4_resource_free(emlxs_hba_t *hba)
{
	emlxs_port_t	*port = &PPORT;
	MBUF_INFO	*buf_info;
	uint32_t	i;

	buf_info = &hba->sli.sli4.slim2;
	if (buf_info->virt == 0) {
		/* Already free */
		return;
	}

	emlxs_fcf_fini(hba);

	buf_info = &hba->sli.sli4.HeaderTmplate;
	if (buf_info->virt) {
		bzero(buf_info, sizeof (MBUF_INFO));
	}

	if (hba->sli.sli4.XRIp) {
		if ((hba->sli.sli4.XRIinuse_f !=
		    (XRIobj_t *)&hba->sli.sli4.XRIinuse_f) ||
		    (hba->sli.sli4.XRIinuse_b !=
		    (XRIobj_t *)&hba->sli.sli4.XRIinuse_f)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_debug_msg,
			    "XRIs in use during free!: %p %p != %p\n",
			    hba->sli.sli4.XRIinuse_f,
			    hba->sli.sli4.XRIinuse_b,
			    &hba->sli.sli4.XRIinuse_f);
		}
		kmem_free(hba->sli.sli4.XRIp,
		    (sizeof (XRIobj_t) * hba->sli.sli4.XRICount));
		hba->sli.sli4.XRIp = NULL;

		hba->sli.sli4.XRIfree_f =
		    (XRIobj_t *)&hba->sli.sli4.XRIfree_f;
		hba->sli.sli4.XRIfree_b =
		    (XRIobj_t *)&hba->sli.sli4.XRIfree_f;
		hba->sli.sli4.xrif_count = 0;
	}

	for (i = 0; i < hba->intr_count; i++) {
		mutex_destroy(&hba->sli.sli4.eq[i].lastwq_lock);
		bzero(&hba->sli.sli4.eq[i], sizeof (EQ_DESC_t));
		hba->sli.sli4.eq[i].qid = 0xffff;
	}
	for (i = 0; i < EMLXS_MAX_CQS; i++) {
		bzero(&hba->sli.sli4.cq[i], sizeof (CQ_DESC_t));
		hba->sli.sli4.cq[i].qid = 0xffff;
	}
	for (i = 0; i < EMLXS_MAX_WQS; i++) {
		bzero(&hba->sli.sli4.wq[i], sizeof (WQ_DESC_t));
		hba->sli.sli4.wq[i].qid = 0xffff;
	}
	for (i = 0; i < EMLXS_MAX_RXQS; i++) {
		mutex_destroy(&hba->sli.sli4.rxq[i].lock);
		bzero(&hba->sli.sli4.rxq[i], sizeof (RXQ_DESC_t));
	}
	for (i = 0; i < EMLXS_MAX_RQS; i++) {
		mutex_destroy(&hba->sli.sli4.rq[i].lock);
		bzero(&hba->sli.sli4.rq[i], sizeof (RQ_DESC_t));
		hba->sli.sli4.rq[i].qid = 0xffff;
	}

	/* Free the MQ */
	bzero(&hba->sli.sli4.mq, sizeof (MQ_DESC_t));

	buf_info = &hba->sli.sli4.slim2;
	if (buf_info->virt) {
		buf_info->flags = FC_MBUF_DMA;
		emlxs_mem_free(hba, buf_info);
		bzero(buf_info, sizeof (MBUF_INFO));
	}

} /* emlxs_sli4_resource_free() */


static int
emlxs_sli4_resource_alloc(emlxs_hba_t *hba)
{
	emlxs_port_t	*port = &PPORT;
	emlxs_config_t	*cfg = &CFG;
	MBUF_INFO	*buf_info;
	int		num_eq;
	int		num_wq;
	uint16_t	i;
	uint32_t	j;
	uint32_t	k;
	uint16_t	cq_depth;
	uint32_t	cq_size;
	uint32_t	word;
	XRIobj_t	*xrip;
	RQE_t		*rqe;
	MBUF_INFO	*rqb;
	uint64_t	phys;
	uint64_t	tmp_phys;
	char		*virt;
	char		*tmp_virt;
	void		*data_handle;
	void		*dma_handle;
	int32_t		size;
	off_t		offset;
	uint32_t	count = 0;
	uint32_t	hddr_size = 0;
	uint32_t	align;
	uint32_t	iotag;

	buf_info = &hba->sli.sli4.slim2;
	if (buf_info->virt) {
		/* Already allocated */
		return (0);
	}

	emlxs_fcf_init(hba);

	switch (hba->sli.sli4.param.CQV) {
	case 0:
		cq_depth = CQ_DEPTH;
		break;
	case 2:
	default:
		cq_depth = CQ_DEPTH_V2;
		break;
	}
	cq_size = (cq_depth * CQE_SIZE);

	/* EQs - 1 per Interrupt vector */
	num_eq = hba->intr_count;

	/* CQs  - number of WQs + 1 for RQs + 1 for mbox/async events */
	num_wq = cfg[CFG_NUM_WQ].current * num_eq;

	/* Calculate total dmable memory we need */
	/* WARNING: make sure each section is aligned on 4K boundary */

	/* EQ */
	count += num_eq * 4096;

	/* CQ */
	count += (num_wq + EMLXS_CQ_OFFSET_WQ) * cq_size;

	/* WQ */
	count += num_wq * (4096 * EMLXS_NUM_WQ_PAGES);

	/* MQ */
	count +=  EMLXS_MAX_MQS * 4096;

	/* RQ */
	count +=  EMLXS_MAX_RQS * 4096;

	/* RQB/E */
	count += RQB_COUNT * (RQB_DATA_SIZE + RQB_HEADER_SIZE);
	count += (4096 - (count%4096)); /* Ensure 4K alignment */

	/* SGL */
	count += hba->sli.sli4.XRIExtSize * hba->sli.sli4.mem_sgl_size;
	count += (4096 - (count%4096)); /* Ensure 4K alignment */

	/* RPI Header Templates */
	if (hba->sli.sli4.param.HDRR) {
		/* Bytes per extent */
		j = hba->sli.sli4.RPIExtSize * sizeof (RPIHdrTmplate_t);

		/* Pages required per extent (page == 4096 bytes) */
		k = (j/4096) + ((j%4096)? 1:0);

		/* Total size */
		hddr_size = (k * hba->sli.sli4.RPIExtCount * 4096);

		count += hddr_size;
	}

	/* Allocate slim2 for SLI4 */
	buf_info = &hba->sli.sli4.slim2;
	buf_info->size = count;
	buf_info->flags = FC_MBUF_DMA | FC_MBUF_SNGLSG | FC_MBUF_DMA32;
	buf_info->align = ddi_ptob(hba->dip, 1L);

	(void) emlxs_mem_alloc(hba, buf_info);

	if (buf_info->virt == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_init_failed_msg,
		    "Unable to allocate internal memory for SLI4: %d",
		    count);
		goto failed;
	}
	bzero(buf_info->virt, buf_info->size);
	EMLXS_MPDATA_SYNC(buf_info->dma_handle, 0,
	    buf_info->size, DDI_DMA_SYNC_FORDEV);

	/* Assign memory to SGL, Head Template, EQ, CQ, WQ, RQ and MQ */
	data_handle = buf_info->data_handle;
	dma_handle = buf_info->dma_handle;
	phys = buf_info->phys;
	virt = (char *)buf_info->virt;

	/* Allocate space for queues */

	/* EQ */
	size = 4096;
	for (i = 0; i < num_eq; i++) {
		bzero(&hba->sli.sli4.eq[i], sizeof (EQ_DESC_t));

		buf_info = &hba->sli.sli4.eq[i].addr;
		buf_info->size = size;
		buf_info->flags =
		    FC_MBUF_DMA | FC_MBUF_SNGLSG | FC_MBUF_DMA32;
		buf_info->align = ddi_ptob(hba->dip, 1L);
		buf_info->phys = phys;
		buf_info->virt = (void *)virt;
		buf_info->data_handle = data_handle;
		buf_info->dma_handle = dma_handle;

		phys += size;
		virt += size;

		hba->sli.sli4.eq[i].max_index = EQ_DEPTH;
		hba->sli.sli4.eq[i].qid = 0xffff;

		mutex_init(&hba->sli.sli4.eq[i].lastwq_lock, NULL,
		    MUTEX_DRIVER, NULL);
	}


	/* CQ */
	for (i = 0; i < (num_wq + EMLXS_CQ_OFFSET_WQ); i++) {
		bzero(&hba->sli.sli4.cq[i], sizeof (CQ_DESC_t));

		buf_info = &hba->sli.sli4.cq[i].addr;
		buf_info->size = cq_size;
		buf_info->flags =
		    FC_MBUF_DMA | FC_MBUF_SNGLSG | FC_MBUF_DMA32;
		buf_info->align = ddi_ptob(hba->dip, 1L);
		buf_info->phys = phys;
		buf_info->virt = (void *)virt;
		buf_info->data_handle = data_handle;
		buf_info->dma_handle = dma_handle;

		phys += cq_size;
		virt += cq_size;

		hba->sli.sli4.cq[i].max_index = cq_depth;
		hba->sli.sli4.cq[i].qid = 0xffff;
	}


	/* WQ */
	size = 4096 * EMLXS_NUM_WQ_PAGES;
	for (i = 0; i < num_wq; i++) {
		bzero(&hba->sli.sli4.wq[i], sizeof (WQ_DESC_t));

		buf_info = &hba->sli.sli4.wq[i].addr;
		buf_info->size = size;
		buf_info->flags =
		    FC_MBUF_DMA | FC_MBUF_SNGLSG | FC_MBUF_DMA32;
		buf_info->align = ddi_ptob(hba->dip, 1L);
		buf_info->phys = phys;
		buf_info->virt = (void *)virt;
		buf_info->data_handle = data_handle;
		buf_info->dma_handle = dma_handle;

		phys += size;
		virt += size;

		hba->sli.sli4.wq[i].max_index = WQ_DEPTH;
		hba->sli.sli4.wq[i].release_depth = WQE_RELEASE_DEPTH;
		hba->sli.sli4.wq[i].qid = 0xFFFF;
	}


	/* MQ */
	size = 4096;
	bzero(&hba->sli.sli4.mq, sizeof (MQ_DESC_t));

	buf_info = &hba->sli.sli4.mq.addr;
	buf_info->size = size;
	buf_info->flags =
	    FC_MBUF_DMA | FC_MBUF_SNGLSG | FC_MBUF_DMA32;
	buf_info->align = ddi_ptob(hba->dip, 1L);
	buf_info->phys = phys;
	buf_info->virt = (void *)virt;
	buf_info->data_handle = data_handle;
	buf_info->dma_handle = dma_handle;

	phys += size;
	virt += size;

	hba->sli.sli4.mq.max_index = MQ_DEPTH;


	/* RXQ */
	for (i = 0; i < EMLXS_MAX_RXQS; i++) {
		bzero(&hba->sli.sli4.rxq[i], sizeof (RXQ_DESC_t));

		mutex_init(&hba->sli.sli4.rxq[i].lock, NULL, MUTEX_DRIVER,
		    NULL);
	}


	/* RQ */
	size = 4096;
	for (i = 0; i < EMLXS_MAX_RQS; i++) {
		bzero(&hba->sli.sli4.rq[i], sizeof (RQ_DESC_t));

		buf_info = &hba->sli.sli4.rq[i].addr;
		buf_info->size = size;
		buf_info->flags =
		    FC_MBUF_DMA | FC_MBUF_SNGLSG | FC_MBUF_DMA32;
		buf_info->align = ddi_ptob(hba->dip, 1L);
		buf_info->phys = phys;
		buf_info->virt = (void *)virt;
		buf_info->data_handle = data_handle;
		buf_info->dma_handle = dma_handle;

		phys += size;
		virt += size;

		hba->sli.sli4.rq[i].max_index = RQ_DEPTH;
		hba->sli.sli4.rq[i].qid = 0xFFFF;

		mutex_init(&hba->sli.sli4.rq[i].lock, NULL, MUTEX_DRIVER, NULL);
	}


	/* RQB/E */
	for (i = 0; i < EMLXS_MAX_RQS; i++) {
		size = (i & 0x1) ? RQB_DATA_SIZE : RQB_HEADER_SIZE;
		tmp_phys = phys;
		tmp_virt = virt;

		/* Initialize the RQEs */
		rqe = (RQE_t *)hba->sli.sli4.rq[i].addr.virt;
		for (j = 0; j < (RQ_DEPTH/RQB_COUNT); j++) {
			phys = tmp_phys;
			virt = tmp_virt;
			for (k = 0; k < RQB_COUNT; k++) {
				word = PADDR_HI(phys);
				rqe->AddrHi = BE_SWAP32(word);

				word = PADDR_LO(phys);
				rqe->AddrLo = BE_SWAP32(word);

				rqb = &hba->sli.sli4.rq[i].
				    rqb[k + (j * RQB_COUNT)];
				rqb->size = size;
				rqb->flags = FC_MBUF_DMA |
				    FC_MBUF_SNGLSG | FC_MBUF_DMA32;
				rqb->align = ddi_ptob(hba->dip, 1L);
				rqb->phys = phys;
				rqb->virt = (void *)virt;
				rqb->data_handle = data_handle;
				rqb->dma_handle = dma_handle;

				phys += size;
				virt += size;
#ifdef DEBUG_RQE
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
				    "RQ_ALLOC: rq[%d] rqb[%d,%d]=%p iotag=%d",
				    i, j, k, mp, mp->tag);
#endif /* DEBUG_RQE */

				rqe++;
			}
		}

		offset = (off_t)((uint64_t)((unsigned long)
		    hba->sli.sli4.rq[i].addr.virt) -
		    (uint64_t)((unsigned long)
		    hba->sli.sli4.slim2.virt));

		/* Sync the RQ buffer list */
		EMLXS_MPDATA_SYNC(hba->sli.sli4.rq[i].addr.dma_handle, offset,
		    hba->sli.sli4.rq[i].addr.size, DDI_DMA_SYNC_FORDEV);
	}

	/* 4K Alignment */
	align = (4096 - (phys%4096));
	phys += align;
	virt += align;

	/* SGL */
	/* Initialize double linked lists */
	hba->sli.sli4.XRIinuse_f =
	    (XRIobj_t *)&hba->sli.sli4.XRIinuse_f;
	hba->sli.sli4.XRIinuse_b =
	    (XRIobj_t *)&hba->sli.sli4.XRIinuse_f;
	hba->sli.sli4.xria_count = 0;

	hba->sli.sli4.XRIfree_f =
	    (XRIobj_t *)&hba->sli.sli4.XRIfree_f;
	hba->sli.sli4.XRIfree_b =
	    (XRIobj_t *)&hba->sli.sli4.XRIfree_f;
	hba->sli.sli4.xria_count = 0;

	hba->sli.sli4.XRIp = (XRIobj_t *)kmem_zalloc(
	    (sizeof (XRIobj_t) * hba->sli.sli4.XRICount), KM_SLEEP);

	xrip = hba->sli.sli4.XRIp;
	size = hba->sli.sli4.mem_sgl_size;
	iotag = 1;
	for (i = 0; i < hba->sli.sli4.XRICount; i++) {
		xrip->XRI = emlxs_sli4_index_to_xri(hba, i);

		/* We don't use XRI==0, since it also represents an */
		/* uninitialized exchange */
		if (xrip->XRI == 0) {
			xrip++;
			continue;
		}

		xrip->iotag = iotag++;
		xrip->sge_count =
		    (hba->sli.sli4.mem_sgl_size / sizeof (ULP_SGE64));

		/* Add xrip to end of free list */
		xrip->_b = hba->sli.sli4.XRIfree_b;
		hba->sli.sli4.XRIfree_b->_f = xrip;
		xrip->_f = (XRIobj_t *)&hba->sli.sli4.XRIfree_f;
		hba->sli.sli4.XRIfree_b = xrip;
		hba->sli.sli4.xrif_count++;

		/* Allocate SGL for this xrip */
		buf_info = &xrip->SGList;
		buf_info->size = size;
		buf_info->flags =
		    FC_MBUF_DMA | FC_MBUF_SNGLSG | FC_MBUF_DMA32;
		buf_info->align = size;
		buf_info->phys = phys;
		buf_info->virt = (void *)virt;
		buf_info->data_handle = data_handle;
		buf_info->dma_handle = dma_handle;

		phys += size;
		virt += size;

		xrip++;
	}

	/* 4K Alignment */
	align = (4096 - (phys%4096));
	phys += align;
	virt += align;

	/* RPI Header Templates */
	if (hba->sli.sli4.param.HDRR) {
		buf_info = &hba->sli.sli4.HeaderTmplate;
		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = hddr_size;
		buf_info->flags = FC_MBUF_DMA | FC_MBUF_DMA32;
		buf_info->align = ddi_ptob(hba->dip, 1L);
		buf_info->phys = phys;
		buf_info->virt = (void *)virt;
		buf_info->data_handle = data_handle;
		buf_info->dma_handle = dma_handle;
	}

#ifdef FMA_SUPPORT
	if (hba->sli.sli4.slim2.dma_handle) {
		if (emlxs_fm_check_dma_handle(hba,
		    hba->sli.sli4.slim2.dma_handle)
		    != DDI_FM_OK) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_invalid_dma_handle_msg,
			    "sli4_resource_alloc: hdl=%p",
			    hba->sli.sli4.slim2.dma_handle);
			goto failed;
		}
	}
#endif /* FMA_SUPPORT */

	return (0);

failed:

	(void) emlxs_sli4_resource_free(hba);
	return (ENOMEM);

} /* emlxs_sli4_resource_alloc */


extern void
emlxs_sli4_zero_queue_stat(emlxs_hba_t *hba)
{
	uint32_t i;
	uint32_t num_wq;
	emlxs_config_t	*cfg = &CFG;
	clock_t		time;

	/* EQ */
	for (i = 0; i < hba->intr_count; i++) {
		hba->sli.sli4.eq[i].num_proc = 0;
		hba->sli.sli4.eq[i].max_proc = 0;
		hba->sli.sli4.eq[i].isr_count = 0;
	}
	num_wq = cfg[CFG_NUM_WQ].current * hba->intr_count;
	/* CQ */
	for (i = 0; i < (num_wq + EMLXS_CQ_OFFSET_WQ); i++) {
		hba->sli.sli4.cq[i].num_proc = 0;
		hba->sli.sli4.cq[i].max_proc = 0;
		hba->sli.sli4.cq[i].isr_count = 0;
	}
	/* WQ */
	for (i = 0; i < num_wq; i++) {
		hba->sli.sli4.wq[i].num_proc = 0;
		hba->sli.sli4.wq[i].num_busy = 0;
	}
	/* RQ */
	for (i = 0; i < EMLXS_MAX_RQS; i++) {
		hba->sli.sli4.rq[i].num_proc = 0;
	}
	(void) drv_getparm(LBOLT, &time);
	hba->sli.sli4.que_stat_timer = (uint32_t)time;

} /* emlxs_sli4_zero_queue_stat */


extern XRIobj_t *
emlxs_sli4_reserve_xri(emlxs_port_t *port,  RPIobj_t *rpip, uint32_t type,
    uint16_t rx_id)
{
	emlxs_hba_t *hba = HBA;
	XRIobj_t	*xrip;
	uint16_t	iotag;

	mutex_enter(&EMLXS_FCTAB_LOCK);

	xrip = hba->sli.sli4.XRIfree_f;

	if (xrip == (XRIobj_t *)&hba->sli.sli4.XRIfree_f) {
		mutex_exit(&EMLXS_FCTAB_LOCK);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_err_msg,
		    "Unable to reserve XRI. type=%d",
		    type);

		return (NULL);
	}

	iotag = xrip->iotag;

	if ((!iotag) ||
	    ((hba->fc_table[iotag] != NULL) &&
	    (hba->fc_table[iotag] != STALE_PACKET))) {
		/*
		 * No more command slots available, retry later
		 */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to reserve iotag. type=%d",
		    type);

		mutex_exit(&EMLXS_FCTAB_LOCK);
		return (NULL);
	}

	xrip->state = XRI_STATE_ALLOCATED;
	xrip->type = type;
	xrip->flag = EMLXS_XRI_RESERVED;
	xrip->sbp = NULL;

	xrip->rpip = rpip;
	xrip->rx_id = rx_id;
	rpip->xri_count++;

	/* Take it off free list */
	(xrip->_b)->_f = xrip->_f;
	(xrip->_f)->_b = xrip->_b;
	xrip->_f = NULL;
	xrip->_b = NULL;
	hba->sli.sli4.xrif_count--;

	/* Add it to end of inuse list */
	xrip->_b = hba->sli.sli4.XRIinuse_b;
	hba->sli.sli4.XRIinuse_b->_f = xrip;
	xrip->_f = (XRIobj_t *)&hba->sli.sli4.XRIinuse_f;
	hba->sli.sli4.XRIinuse_b = xrip;
	hba->sli.sli4.xria_count++;

	mutex_exit(&EMLXS_FCTAB_LOCK);
	return (xrip);

} /* emlxs_sli4_reserve_xri() */


extern uint32_t
emlxs_sli4_unreserve_xri(emlxs_port_t *port, uint16_t xri, uint32_t lock)
{
	emlxs_hba_t *hba = HBA;
	XRIobj_t *xrip;

	if (lock) {
		mutex_enter(&EMLXS_FCTAB_LOCK);
	}

	xrip = emlxs_sli4_find_xri(port, xri);

	if (!xrip || xrip->state == XRI_STATE_FREE) {
		if (lock) {
			mutex_exit(&EMLXS_FCTAB_LOCK);
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "sli4_unreserve_xri:%d already freed.", xri);
		return (0);
	}

	/* Flush this unsolicited ct command */
	if (xrip->type == EMLXS_XRI_UNSOL_CT_TYPE) {
		(void) emlxs_flush_ct_event(port, xrip->rx_id);
	}

	if (!(xrip->flag & EMLXS_XRI_RESERVED)) {
		if (lock) {
			mutex_exit(&EMLXS_FCTAB_LOCK);
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "sli4_unreserve_xri:%d in use. type=%d",
		    xrip->XRI, xrip->type);
		return (1);
	}

	if (xrip->iotag &&
	    (hba->fc_table[xrip->iotag] != NULL) &&
	    (hba->fc_table[xrip->iotag] != STALE_PACKET)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_err_msg,
		    "sli4_unreserve_xri:%d  sbp dropped:%p type=%d",
		    xrip->XRI, hba->fc_table[xrip->iotag], xrip->type);

		hba->fc_table[xrip->iotag] = NULL;
		hba->io_count--;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "sli4_unreserve_xri:%d unreserved. type=%d",
	    xrip->XRI, xrip->type);

	xrip->state = XRI_STATE_FREE;
	xrip->type = 0;

	if (xrip->rpip) {
		xrip->rpip->xri_count--;
		xrip->rpip = NULL;
	}

	if (xrip->reserved_rpip) {
		xrip->reserved_rpip->xri_count--;
		xrip->reserved_rpip = NULL;
	}

	/* Take it off inuse list */
	(xrip->_b)->_f = xrip->_f;
	(xrip->_f)->_b = xrip->_b;
	xrip->_f = NULL;
	xrip->_b = NULL;
	hba->sli.sli4.xria_count--;

	/* Add it to end of free list */
	xrip->_b = hba->sli.sli4.XRIfree_b;
	hba->sli.sli4.XRIfree_b->_f = xrip;
	xrip->_f = (XRIobj_t *)&hba->sli.sli4.XRIfree_f;
	hba->sli.sli4.XRIfree_b = xrip;
	hba->sli.sli4.xrif_count++;

	if (lock) {
		mutex_exit(&EMLXS_FCTAB_LOCK);
	}

	return (0);

} /* emlxs_sli4_unreserve_xri() */


XRIobj_t *
emlxs_sli4_register_xri(emlxs_port_t *port, emlxs_buf_t *sbp, uint16_t xri,
    uint32_t did)
{
	emlxs_hba_t *hba = HBA;
	uint16_t	iotag;
	XRIobj_t	*xrip;
	emlxs_node_t	*node;
	RPIobj_t	*rpip;

	mutex_enter(&EMLXS_FCTAB_LOCK);

	xrip = sbp->xrip;
	if (!xrip) {
		xrip = emlxs_sli4_find_xri(port, xri);

		if (!xrip) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
			    "sli4_register_xri:%d XRI not found.", xri);

			mutex_exit(&EMLXS_FCTAB_LOCK);
			return (NULL);
		}
	}

	if ((xrip->state == XRI_STATE_FREE) ||
	    !(xrip->flag & EMLXS_XRI_RESERVED)) {

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "sli4_register_xri:%d Invalid XRI. xrip=%p "
		    "state=%x flag=%x",
		    xrip->XRI, xrip, xrip->state, xrip->flag);

		mutex_exit(&EMLXS_FCTAB_LOCK);
		return (NULL);
	}

	iotag = xrip->iotag;

	if ((!iotag) ||
	    ((hba->fc_table[iotag] != NULL) &&
	    (hba->fc_table[iotag] != STALE_PACKET))) {

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "sli4_register_xri:%d Invalid fc_table entry. "
		    "iotag=%d entry=%p",
		    xrip->XRI, iotag, hba->fc_table[iotag]);

		mutex_exit(&EMLXS_FCTAB_LOCK);
		return (NULL);
	}

	hba->fc_table[iotag] = sbp;
	hba->io_count++;

	sbp->iotag = iotag;
	sbp->xrip = xrip;

	xrip->flag &= ~EMLXS_XRI_RESERVED;
	xrip->sbp = sbp;

	/* If we did not have a registered RPI when we reserved */
	/* this exchange, check again now. */
	if (xrip->rpip && (xrip->rpip->RPI == FABRIC_RPI)) {
		node = emlxs_node_find_did(port, did, 1);
		rpip = EMLXS_NODE_TO_RPI(port, node);

		if (rpip && (rpip->RPI != FABRIC_RPI)) {
			/* Move the XRI to the new RPI */
			xrip->rpip->xri_count--;
			xrip->rpip = rpip;
			rpip->xri_count++;
		}
	}

	mutex_exit(&EMLXS_FCTAB_LOCK);

	return (xrip);

} /* emlxs_sli4_register_xri() */


/* Performs both reserve and register functions for XRI */
static XRIobj_t *
emlxs_sli4_alloc_xri(emlxs_port_t *port, emlxs_buf_t *sbp, RPIobj_t *rpip,
    uint32_t type)
{
	emlxs_hba_t *hba = HBA;
	XRIobj_t	*xrip;
	uint16_t	iotag;

	mutex_enter(&EMLXS_FCTAB_LOCK);

	xrip = hba->sli.sli4.XRIfree_f;

	if (xrip == (XRIobj_t *)&hba->sli.sli4.XRIfree_f) {
		mutex_exit(&EMLXS_FCTAB_LOCK);

		return (NULL);
	}

	/* Get the iotag by registering the packet */
	iotag = xrip->iotag;

	if ((!iotag) ||
	    ((hba->fc_table[iotag] != NULL) &&
	    (hba->fc_table[iotag] != STALE_PACKET))) {
		/*
		 * No more command slots available, retry later
		 */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to alloc iotag:(0x%x)(%p) type=%d",
		    iotag, hba->fc_table[iotag], type);

		mutex_exit(&EMLXS_FCTAB_LOCK);
		return (NULL);
	}

	hba->fc_table[iotag] = sbp;
	hba->io_count++;

	sbp->iotag = iotag;
	sbp->xrip = xrip;

	xrip->state = XRI_STATE_ALLOCATED;
	xrip->type = type;
	xrip->flag = 0;
	xrip->sbp = sbp;

	xrip->rpip = rpip;
	rpip->xri_count++;

	/* Take it off free list */
	(xrip->_b)->_f = xrip->_f;
	(xrip->_f)->_b = xrip->_b;
	xrip->_f = NULL;
	xrip->_b = NULL;
	hba->sli.sli4.xrif_count--;

	/* Add it to end of inuse list */
	xrip->_b = hba->sli.sli4.XRIinuse_b;
	hba->sli.sli4.XRIinuse_b->_f = xrip;
	xrip->_f = (XRIobj_t *)&hba->sli.sli4.XRIinuse_f;
	hba->sli.sli4.XRIinuse_b = xrip;
	hba->sli.sli4.xria_count++;

	mutex_exit(&EMLXS_FCTAB_LOCK);

	return (xrip);

} /* emlxs_sli4_alloc_xri() */


/* EMLXS_FCTAB_LOCK must be held to enter */
extern XRIobj_t *
emlxs_sli4_find_xri(emlxs_port_t *port, uint16_t xri)
{
	emlxs_hba_t *hba = HBA;
	XRIobj_t	*xrip;

	xrip = (XRIobj_t *)hba->sli.sli4.XRIinuse_f;
	while (xrip != (XRIobj_t *)&hba->sli.sli4.XRIinuse_f) {
		if ((xrip->state >= XRI_STATE_ALLOCATED) &&
		    (xrip->XRI == xri)) {
			return (xrip);
		}
		xrip = xrip->_f;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "Unable to find XRI x%x", xri);

	return (NULL);

} /* emlxs_sli4_find_xri() */




extern void
emlxs_sli4_free_xri(emlxs_port_t *port, emlxs_buf_t *sbp, XRIobj_t *xrip,
    uint8_t lock)
{
	emlxs_hba_t *hba = HBA;

	if (lock) {
		mutex_enter(&EMLXS_FCTAB_LOCK);
	}

	if (xrip) {
		if (xrip->state == XRI_STATE_FREE) {
			if (lock) {
				mutex_exit(&EMLXS_FCTAB_LOCK);
			}
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "Free XRI:%x, Already freed. type=%d",
			    xrip->XRI, xrip->type);
			return;
		}

		if (xrip->type == EMLXS_XRI_UNSOL_CT_TYPE) {
			(void) emlxs_flush_ct_event(port, xrip->rx_id);
		}

		if (xrip->iotag &&
		    (hba->fc_table[xrip->iotag] != NULL) &&
		    (hba->fc_table[xrip->iotag] != STALE_PACKET)) {
			hba->fc_table[xrip->iotag] = NULL;
			hba->io_count--;
		}

		xrip->state = XRI_STATE_FREE;
		xrip->type  = 0;
		xrip->flag  = 0;

		if (xrip->rpip) {
			xrip->rpip->xri_count--;
			xrip->rpip = NULL;
		}

		if (xrip->reserved_rpip) {
			xrip->reserved_rpip->xri_count--;
			xrip->reserved_rpip = NULL;
		}

		/* Take it off inuse list */
		(xrip->_b)->_f = xrip->_f;
		(xrip->_f)->_b = xrip->_b;
		xrip->_f = NULL;
		xrip->_b = NULL;
		hba->sli.sli4.xria_count--;

		/* Add it to end of free list */
		xrip->_b = hba->sli.sli4.XRIfree_b;
		hba->sli.sli4.XRIfree_b->_f = xrip;
		xrip->_f = (XRIobj_t *)&hba->sli.sli4.XRIfree_f;
		hba->sli.sli4.XRIfree_b = xrip;
		hba->sli.sli4.xrif_count++;
	}

	if (sbp) {
		if (!(sbp->pkt_flags & PACKET_VALID) ||
		    (sbp->pkt_flags &
		    (PACKET_ULP_OWNED|PACKET_COMPLETED|PACKET_IN_COMPLETION))) {
			if (lock) {
				mutex_exit(&EMLXS_FCTAB_LOCK);
			}
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "Free XRI: sbp invalid. sbp=%p flags=%x xri=%d",
			    sbp, sbp->pkt_flags, ((xrip)? xrip->XRI:0));
			return;
		}

		if (xrip && (xrip->iotag != sbp->iotag)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_debug_msg,
			    "sbp/iotag mismatch %p iotag:%d %d", sbp,
			    sbp->iotag, xrip->iotag);
		}

		if (sbp->iotag) {
			if (sbp == hba->fc_table[sbp->iotag]) {
				hba->fc_table[sbp->iotag] = NULL;
				hba->io_count--;

				if (sbp->xrip) {
					/* Exchange is still reserved */
					sbp->xrip->flag |= EMLXS_XRI_RESERVED;
				}
			}
			sbp->iotag = 0;
		}

		if (xrip) {
			sbp->xrip = 0;
		}

		if (lock) {
			mutex_exit(&EMLXS_FCTAB_LOCK);
		}

		/* Clean up the sbp */
		mutex_enter(&sbp->mtx);

		if (sbp->pkt_flags & PACKET_IN_TXQ) {
			sbp->pkt_flags &= ~PACKET_IN_TXQ;
			hba->channel_tx_count--;
		}

		if (sbp->pkt_flags & PACKET_IN_CHIPQ) {
			sbp->pkt_flags &= ~PACKET_IN_CHIPQ;
		}

		mutex_exit(&sbp->mtx);
	} else {
		if (lock) {
			mutex_exit(&EMLXS_FCTAB_LOCK);
		}
	}

} /* emlxs_sli4_free_xri() */


static int
emlxs_sli4_post_sgl_pages(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX4	*mb = (MAILBOX4 *)mbq;
	emlxs_port_t	*port = &PPORT;
	XRIobj_t	*xrip;
	MATCHMAP	*mp;
	mbox_req_hdr_t 	*hdr_req;
	uint32_t	i;
	uint32_t	cnt;
	uint32_t	xri_cnt;
	uint32_t	j;
	uint32_t	size;
	IOCTL_FCOE_CFG_POST_SGL_PAGES *post_sgl;

	bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);
	mbq->bp = NULL;
	mbq->mbox_cmpl = NULL;

	if ((mp = emlxs_mem_buf_alloc(hba, EMLXS_MAX_NONEMBED_SIZE)) == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "Unable to POST_SGL. Mailbox cmd=%x  ",
		    mb->mbxCommand);
		return (EIO);
	}
	mbq->nonembed = (void *)mp;

	/*
	 * Signifies a non embedded command
	 */
	mb->un.varSLIConfig.be.embedded = 0;
	mb->mbxCommand = MBX_SLI_CONFIG;
	mb->mbxOwner = OWN_HOST;

	hdr_req = (mbox_req_hdr_t *)mp->virt;
	post_sgl =
	    (IOCTL_FCOE_CFG_POST_SGL_PAGES *)(hdr_req + 1);

	xrip = hba->sli.sli4.XRIp;

	/* For each extent */
	for (j = 0; j < hba->sli.sli4.XRIExtCount; j++) {
		cnt = hba->sli.sli4.XRIExtSize;
		while (cnt) {
			if (xrip->XRI == 0) {
				cnt--;
				xrip++;
				continue;
			}

			bzero((void *) hdr_req, mp->size);
			size = mp->size - IOCTL_HEADER_SZ;

			mb->un.varSLIConfig.be.payload_length =
			    mp->size;
			mb->un.varSLIConfig.be.un_hdr.hdr_req.subsystem =
			    IOCTL_SUBSYSTEM_FCOE;
			mb->un.varSLIConfig.be.un_hdr.hdr_req.opcode =
			    FCOE_OPCODE_CFG_POST_SGL_PAGES;
			mb->un.varSLIConfig.be.un_hdr.hdr_req.timeout = 0;
			mb->un.varSLIConfig.be.un_hdr.hdr_req.req_length = size;

			hdr_req->subsystem = IOCTL_SUBSYSTEM_FCOE;
			hdr_req->opcode = FCOE_OPCODE_CFG_POST_SGL_PAGES;
			hdr_req->timeout = 0;
			hdr_req->req_length = size;

			post_sgl->params.request.xri_count = 0;
			post_sgl->params.request.xri_start = xrip->XRI;

			xri_cnt = (size -
			    sizeof (IOCTL_FCOE_CFG_POST_SGL_PAGES)) /
			    sizeof (FCOE_SGL_PAGES);

			for (i = 0; (i < xri_cnt) && cnt; i++) {
				post_sgl->params.request.xri_count++;
				post_sgl->params.request.pages[i].\
				    sgl_page0.addrLow =
				    PADDR_LO(xrip->SGList.phys);
				post_sgl->params.request.pages[i].\
				    sgl_page0.addrHigh =
				    PADDR_HI(xrip->SGList.phys);

				cnt--;
				xrip++;
			}

			if (emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) !=
			    MBX_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
				    "Unable to POST_SGL. Mailbox cmd=%x "
				    "status=%x XRI cnt:%d start:%d",
				    mb->mbxCommand, mb->mbxStatus,
				    post_sgl->params.request.xri_count,
				    post_sgl->params.request.xri_start);
				emlxs_mem_buf_free(hba, mp);
				mbq->nonembed = NULL;
				return (EIO);
			}
		}
	}

	emlxs_mem_buf_free(hba, mp);
	mbq->nonembed = NULL;
	return (0);

} /* emlxs_sli4_post_sgl_pages() */


static int
emlxs_sli4_post_hdr_tmplates(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX4	*mb = (MAILBOX4 *)mbq;
	emlxs_port_t	*port = &PPORT;
	uint32_t 	j;
	uint32_t 	k;
	uint64_t	addr;
	IOCTL_FCOE_POST_HDR_TEMPLATES *post_hdr;
	uint16_t	num_pages;

	if (!(hba->sli.sli4.param.HDRR)) {
		return (0);
	}

	/* Bytes per extent */
	j = hba->sli.sli4.RPIExtSize * sizeof (RPIHdrTmplate_t);

	/* Pages required per extent (page == 4096 bytes) */
	num_pages = (j/4096) + ((j%4096)? 1:0);

	addr = hba->sli.sli4.HeaderTmplate.phys;

	/* For each extent */
	for (j = 0; j < hba->sli.sli4.RPIExtCount; j++) {
		bzero((void *) mb, MAILBOX_CMD_SLI4_BSIZE);
		mbq->bp = NULL;
		mbq->mbox_cmpl = NULL;

		/*
		 * Signifies an embedded command
		 */
		mb->un.varSLIConfig.be.embedded = 1;

		mb->mbxCommand = MBX_SLI_CONFIG;
		mb->mbxOwner = OWN_HOST;
		mb->un.varSLIConfig.be.payload_length =
		    sizeof (IOCTL_FCOE_POST_HDR_TEMPLATES) + IOCTL_HEADER_SZ;
		mb->un.varSLIConfig.be.un_hdr.hdr_req.subsystem =
		    IOCTL_SUBSYSTEM_FCOE;
		mb->un.varSLIConfig.be.un_hdr.hdr_req.opcode =
		    FCOE_OPCODE_POST_HDR_TEMPLATES;
		mb->un.varSLIConfig.be.un_hdr.hdr_req.timeout = 0;
		mb->un.varSLIConfig.be.un_hdr.hdr_req.req_length =
		    sizeof (IOCTL_FCOE_POST_HDR_TEMPLATES);

		post_hdr =
		    (IOCTL_FCOE_POST_HDR_TEMPLATES *)
		    &mb->un.varSLIConfig.payload;
		post_hdr->params.request.num_pages = num_pages;
		post_hdr->params.request.rpi_offset = hba->sli.sli4.RPIBase[j];

		for (k = 0; k < num_pages; k++) {
			post_hdr->params.request.pages[k].addrLow =
			    PADDR_LO(addr);
			post_hdr->params.request.pages[k].addrHigh =
			    PADDR_HI(addr);
			addr += 4096;
		}

		if (emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) !=
		    MBX_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "Unable to POST_HDR_TEMPLATES. Mailbox cmd=%x "
			    "status=%x ",
			    mb->mbxCommand, mb->mbxStatus);
			return (EIO);
		}
		emlxs_data_dump(port, "POST_HDR", (uint32_t *)mb, 18, 0);
	}

	return (0);

} /* emlxs_sli4_post_hdr_tmplates() */


static int
emlxs_sli4_create_queues(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	MAILBOX4	*mb = (MAILBOX4 *)mbq;
	emlxs_port_t	*port = &PPORT;
	emlxs_config_t	*cfg = &CFG;
	IOCTL_COMMON_EQ_CREATE *eq;
	IOCTL_COMMON_CQ_CREATE *cq;
	IOCTL_FCOE_WQ_CREATE *wq;
	IOCTL_FCOE_RQ_CREATE *rq;
	IOCTL_COMMON_MQ_CREATE *mq;
	IOCTL_COMMON_MQ_CREATE_EXT *mq_ext;
	emlxs_rqdbu_t	rqdb;
	uint16_t i, j;
	uint16_t num_cq, total_cq;
	uint16_t num_wq, total_wq;

	/*
	 * The first CQ is reserved for ASYNC events,
	 * the second is reserved for unsol rcv, the rest
	 * correspond to WQs. (WQ0 -> CQ2, WQ1 -> CQ3, ...)
	 */

	total_cq = 0;
	total_wq = 0;

	/* Create EQ's */
	for (i = 0; i < hba->intr_count; i++) {
		emlxs_mb_eq_create(hba, mbq, i);
		if (emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) !=
		    MBX_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
			    "Unable to Create EQ %d: Mailbox cmd=%x status=%x ",
			    i, mb->mbxCommand, mb->mbxStatus);
			return (EIO);
		}
		eq = (IOCTL_COMMON_EQ_CREATE *)&mb->un.varSLIConfig.payload;
		hba->sli.sli4.eq[i].qid = eq->params.response.EQId;
		hba->sli.sli4.eq[i].lastwq = total_wq;
		hba->sli.sli4.eq[i].msix_vector = i;

		emlxs_data_dump(port, "EQ0_CREATE", (uint32_t *)mb, 18, 0);
		num_wq = cfg[CFG_NUM_WQ].current;
		num_cq = num_wq;
		if (i == 0) {
			/* One for RQ handling, one for mbox/event handling */
			num_cq += EMLXS_CQ_OFFSET_WQ;
		}

		/* Create CQ's */
		for (j = 0; j < num_cq; j++) {
			/* Reuse mbq from previous mbox */
			bzero(mbq, sizeof (MAILBOXQ));

			hba->sli.sli4.cq[total_cq].eqid =
			    hba->sli.sli4.eq[i].qid;

			emlxs_mb_cq_create(hba, mbq, total_cq);
			if (emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) !=
			    MBX_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_init_failed_msg, "Unable to Create "
				    "CQ %d: Mailbox cmd=%x status=%x ",
				    total_cq, mb->mbxCommand, mb->mbxStatus);
				return (EIO);
			}
			cq = (IOCTL_COMMON_CQ_CREATE *)
			    &mb->un.varSLIConfig.payload;
			hba->sli.sli4.cq[total_cq].qid =
			    cq->params.response.CQId;

			switch (total_cq) {
			case EMLXS_CQ_MBOX:
				/* First CQ is for async event handling */
				hba->sli.sli4.cq[total_cq].type =
				    EMLXS_CQ_TYPE_GROUP1;
				break;

			case EMLXS_CQ_RCV:
				/* Second CQ is for unsol receive handling */
				hba->sli.sli4.cq[total_cq].type =
				    EMLXS_CQ_TYPE_GROUP2;
				break;

			default:
				/* Setup CQ to channel mapping */
				hba->sli.sli4.cq[total_cq].type =
				    EMLXS_CQ_TYPE_GROUP2;
				hba->sli.sli4.cq[total_cq].channelp =
				    &hba->chan[total_cq - EMLXS_CQ_OFFSET_WQ];
				break;
			}
			emlxs_data_dump(port, "CQX_CREATE", (uint32_t *)mb,
			    18, 0);
			total_cq++;
		}

		/* Create WQ's */
		for (j = 0; j < num_wq; j++) {
			/* Reuse mbq from previous mbox */
			bzero(mbq, sizeof (MAILBOXQ));

			hba->sli.sli4.wq[total_wq].cqid =
			    hba->sli.sli4.cq[total_wq + EMLXS_CQ_OFFSET_WQ].qid;

			emlxs_mb_wq_create(hba, mbq, total_wq);
			if (emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) !=
			    MBX_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_init_failed_msg, "Unable to Create "
				    "WQ %d: Mailbox cmd=%x status=%x ",
				    total_wq, mb->mbxCommand, mb->mbxStatus);
				return (EIO);
			}
			wq = (IOCTL_FCOE_WQ_CREATE *)
			    &mb->un.varSLIConfig.payload;
			hba->sli.sli4.wq[total_wq].qid =
			    wq->params.response.WQId;

			hba->sli.sli4.wq[total_wq].cqid =
			    hba->sli.sli4.cq[total_wq+EMLXS_CQ_OFFSET_WQ].qid;
			emlxs_data_dump(port, "WQ_CREATE", (uint32_t *)mb,
			    18, 0);
			total_wq++;
		}
		hba->last_msiid = i;
	}

	/* We assume 1 RQ pair will handle ALL incoming data */
	/* Create RQs */
	for (i = 0; i < EMLXS_MAX_RQS; i++) {
		/* Personalize the RQ */
		switch (i) {
		case 0:
			hba->sli.sli4.rq[i].cqid =
			    hba->sli.sli4.cq[EMLXS_CQ_RCV].qid;
			break;
		case 1:
			hba->sli.sli4.rq[i].cqid =
			    hba->sli.sli4.cq[EMLXS_CQ_RCV].qid;
			break;
		default:
			hba->sli.sli4.rq[i].cqid = 0xffff;
		}

		/* Reuse mbq from previous mbox */
		bzero(mbq, sizeof (MAILBOXQ));

		emlxs_mb_rq_create(hba, mbq, i);
		if (emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) !=
		    MBX_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
			    "Unable to Create RQ %d: Mailbox cmd=%x status=%x ",
			    i, mb->mbxCommand, mb->mbxStatus);
			return (EIO);
		}

		rq = (IOCTL_FCOE_RQ_CREATE *)&mb->un.varSLIConfig.payload;
		hba->sli.sli4.rq[i].qid = rq->params.response.RQId;
		emlxs_data_dump(port, "RQ CREATE", (uint32_t *)mb, 18, 0);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "RQ CREATE: rq[%d].qid=%d cqid=%d",
		    i, hba->sli.sli4.rq[i].qid, hba->sli.sli4.rq[i].cqid);

		/* Initialize the host_index */
		hba->sli.sli4.rq[i].host_index = 0;

		/* If Data queue was just created, */
		/* then post buffers using the header qid */
		if ((i & 0x1)) {
			/* Ring the RQ doorbell to post buffers */
			rqdb.word = 0;
			rqdb.db.Qid = hba->sli.sli4.rq[i-1].qid;
			rqdb.db.NumPosted = RQB_COUNT;

			emlxs_sli4_write_rqdb(hba, rqdb.word);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			    "RQ CREATE: Doorbell rang: qid=%d count=%d",
			    hba->sli.sli4.rq[i-1].qid, RQB_COUNT);
		}
	}

	/* Create MQ */

	/* Personalize the MQ */
	hba->sli.sli4.mq.cqid = hba->sli.sli4.cq[EMLXS_CQ_MBOX].qid;

	/* Reuse mbq from previous mbox */
	bzero(mbq, sizeof (MAILBOXQ));

	emlxs_mb_mq_create_ext(hba, mbq);
	if (emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) !=
	    MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to Create MQ_EXT %d: Mailbox cmd=%x status=%x ",
		    i, mb->mbxCommand, mb->mbxStatus);

		/* Reuse mbq from previous mbox */
		bzero(mbq, sizeof (MAILBOXQ));

		emlxs_mb_mq_create(hba, mbq);
		if (emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) !=
		    MBX_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
			    "Unable to Create MQ %d: Mailbox cmd=%x status=%x ",
			    i, mb->mbxCommand, mb->mbxStatus);
			return (EIO);
		}

		mq = (IOCTL_COMMON_MQ_CREATE *)&mb->un.varSLIConfig.payload;
		hba->sli.sli4.mq.qid = mq->params.response.MQId;
		return (0);
	}

	mq_ext = (IOCTL_COMMON_MQ_CREATE_EXT *)&mb->un.varSLIConfig.payload;
	hba->sli.sli4.mq.qid = mq_ext->params.response.MQId;
	return (0);

} /* emlxs_sli4_create_queues() */


extern void
emlxs_sli4_timer(emlxs_hba_t *hba)
{
	/* Perform SLI4 level timer checks */

	emlxs_fcf_timer_notify(hba);

	emlxs_sli4_timer_check_mbox(hba);

	return;

} /* emlxs_sli4_timer() */


static void
emlxs_sli4_timer_check_mbox(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg = &CFG;
	MAILBOX *mb = NULL;

	if (!cfg[CFG_TIMEOUT_ENABLE].current) {
		return;
	}

	mutex_enter(&EMLXS_PORT_LOCK);

	/* Return if timer hasn't expired */
	if (!hba->mbox_timer || (hba->timer_tics < hba->mbox_timer)) {
		mutex_exit(&EMLXS_PORT_LOCK);
		return;
	}

	/* The first to service the mbox queue will clear the timer */
	hba->mbox_timer = 0;

	if (hba->mbox_queue_flag) {
		if (hba->mbox_mbq) {
			mb = (MAILBOX *)hba->mbox_mbq;
		}
	}

	if (mb) {
		switch (hba->mbox_queue_flag) {
		case MBX_NOWAIT:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_timeout_msg,
			    "%s: Nowait.",
			    emlxs_mb_cmd_xlate(mb->mbxCommand));
			break;

		case MBX_SLEEP:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_timeout_msg,
			    "%s: mb=%p Sleep.",
			    emlxs_mb_cmd_xlate(mb->mbxCommand),
			    mb);
			break;

		case MBX_POLL:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_timeout_msg,
			    "%s: mb=%p Polled.",
			    emlxs_mb_cmd_xlate(mb->mbxCommand),
			    mb);
			break;

		default:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_timeout_msg,
			    "%s: mb=%p (%d).",
			    emlxs_mb_cmd_xlate(mb->mbxCommand),
			    mb, hba->mbox_queue_flag);
			break;
		}
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_timeout_msg, NULL);
	}

	hba->flag |= FC_MBOX_TIMEOUT;
	EMLXS_STATE_CHANGE_LOCKED(hba, FC_ERROR);

	mutex_exit(&EMLXS_PORT_LOCK);

	/* Perform mailbox cleanup */
	/* This will wake any sleeping or polling threads */
	emlxs_mb_fini(hba, NULL, MBX_TIMEOUT);

	/* Trigger adapter shutdown */
	emlxs_thread_spawn(hba, emlxs_shutdown_thread, 0, 0);

	return;

} /* emlxs_sli4_timer_check_mbox() */


extern void
emlxs_data_dump(emlxs_port_t *port, char *str, uint32_t *iptr, int cnt, int err)
{
	void *msg;

	if (!port || !str || !iptr || !cnt) {
		return;
	}

	if (err) {
		msg = &emlxs_sli_err_msg;
	} else {
		msg = &emlxs_sli_detail_msg;
	}

	if (cnt) {
		EMLXS_MSGF(EMLXS_CONTEXT, msg,
		    "%s00: %08x %08x %08x %08x %08x %08x", str, *iptr,
		    *(iptr+1), *(iptr+2), *(iptr+3), *(iptr+4), *(iptr+5));
	}
	if (cnt > 6) {
		EMLXS_MSGF(EMLXS_CONTEXT, msg,
		    "%s06: %08x %08x %08x %08x %08x %08x", str, *(iptr+6),
		    *(iptr+7), *(iptr+8), *(iptr+9), *(iptr+10), *(iptr+11));
	}
	if (cnt > 12) {
		EMLXS_MSGF(EMLXS_CONTEXT, msg,
		    "%s12: %08x %08x %08x %08x %08x %08x", str, *(iptr+12),
		    *(iptr+13), *(iptr+14), *(iptr+15), *(iptr+16), *(iptr+17));
	}
	if (cnt > 18) {
		EMLXS_MSGF(EMLXS_CONTEXT, msg,
		    "%s18: %08x %08x %08x %08x %08x %08x", str, *(iptr+18),
		    *(iptr+19), *(iptr+20), *(iptr+21), *(iptr+22), *(iptr+23));
	}
	if (cnt > 24) {
		EMLXS_MSGF(EMLXS_CONTEXT, msg,
		    "%s24: %08x %08x %08x %08x %08x %08x", str, *(iptr+24),
		    *(iptr+25), *(iptr+26), *(iptr+27), *(iptr+28), *(iptr+29));
	}
	if (cnt > 30) {
		EMLXS_MSGF(EMLXS_CONTEXT, msg,
		    "%s30: %08x %08x %08x %08x %08x %08x", str, *(iptr+30),
		    *(iptr+31), *(iptr+32), *(iptr+33), *(iptr+34), *(iptr+35));
	}
	if (cnt > 36) {
		EMLXS_MSGF(EMLXS_CONTEXT, msg,
		    "%s36: %08x %08x %08x %08x %08x %08x", str, *(iptr+36),
		    *(iptr+37), *(iptr+38), *(iptr+39), *(iptr+40), *(iptr+41));
	}

} /* emlxs_data_dump() */


extern void
emlxs_ue_dump(emlxs_hba_t *hba, char *str)
{
	emlxs_port_t *port = &PPORT;
	uint32_t status;
	uint32_t ue_h;
	uint32_t ue_l;
	uint32_t on1;
	uint32_t on2;

	switch (hba->sli_intf & SLI_INTF_IF_TYPE_MASK) {
	case SLI_INTF_IF_TYPE_0:
		ue_l = ddi_get32(hba->pci_acc_handle,
		    hba->sli.sli4.ERR1_reg_addr);
		ue_h = ddi_get32(hba->pci_acc_handle,
		    hba->sli.sli4.ERR2_reg_addr);

		on1 = ddi_get32(hba->pci_acc_handle,
		    (uint32_t *)(hba->pci_addr + PCICFG_UE_STATUS_ONLINE1));
		on2 = ddi_get32(hba->pci_acc_handle,
		    (uint32_t *)(hba->pci_addr + PCICFG_UE_STATUS_ONLINE2));

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "%s: ueLow:%08x ueHigh:%08x on1:%08x on2:%08x", str,
		    ue_l, ue_h, on1, on2);
		break;

	case SLI_INTF_IF_TYPE_2:
		status = ddi_get32(hba->sli.sli4.bar0_acc_handle,
		    hba->sli.sli4.STATUS_reg_addr);

		ue_l = ddi_get32(hba->sli.sli4.bar0_acc_handle,
		    hba->sli.sli4.ERR1_reg_addr);
		ue_h = ddi_get32(hba->sli.sli4.bar0_acc_handle,
		    hba->sli.sli4.ERR2_reg_addr);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "%s: status:%08x err1:%08x err2:%08x", str,
		    status, ue_l, ue_h);

		break;
	}

#ifdef FMA_SUPPORT
	/* Access handle validation */
	EMLXS_CHK_ACC_HANDLE(hba, hba->pci_acc_handle);
#endif  /* FMA_SUPPORT */

} /* emlxs_ue_dump() */


static void
emlxs_sli4_poll_erratt(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	uint32_t status;
	uint32_t ue_h;
	uint32_t ue_l;
	uint32_t error = 0;

	if (hba->flag & FC_HARDWARE_ERROR) {
		return;
	}

	switch (hba->sli_intf & SLI_INTF_IF_TYPE_MASK) {
	case SLI_INTF_IF_TYPE_0:
		ue_l = ddi_get32(hba->pci_acc_handle,
		    hba->sli.sli4.ERR1_reg_addr);
		ue_h = ddi_get32(hba->pci_acc_handle,
		    hba->sli.sli4.ERR2_reg_addr);

		if ((~hba->sli.sli4.ue_mask_lo & ue_l) ||
		    (~hba->sli.sli4.ue_mask_hi & ue_h) ||
		    (hba->sli.sli4.flag & EMLXS_SLI4_HW_ERROR)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_hardware_error_msg,
			    "Host Error: ueLow:%08x ueHigh:%08x maskLow:%08x "
			    "maskHigh:%08x flag:%08x",
			    ue_l, ue_h, hba->sli.sli4.ue_mask_lo,
			    hba->sli.sli4.ue_mask_hi, hba->sli.sli4.flag);

			error = 2;
		}
		break;

	case SLI_INTF_IF_TYPE_2:
		status = ddi_get32(hba->sli.sli4.bar0_acc_handle,
		    hba->sli.sli4.STATUS_reg_addr);

		if ((status & SLI_STATUS_ERROR) ||
		    (hba->sli.sli4.flag & EMLXS_SLI4_HW_ERROR)) {
			ue_l = ddi_get32(hba->sli.sli4.bar0_acc_handle,
			    hba->sli.sli4.ERR1_reg_addr);
			ue_h = ddi_get32(hba->sli.sli4.bar0_acc_handle,
			    hba->sli.sli4.ERR2_reg_addr);

			error = (status & SLI_STATUS_RESET_NEEDED)? 1:2;

			if (error == 1) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_debug_msg,
				    "Host Error: status:%08x err1:%08x "
				    "err2:%08x flag:%08x",
				    status, ue_l, ue_h, hba->sli.sli4.flag);
			} else {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_hardware_error_msg,
				    "Host Error: status:%08x err1:%08x "
				    "err2:%08x flag:%08x",
				    status, ue_l, ue_h, hba->sli.sli4.flag);
			}
		}
		break;
	}

	if (error == 2) {
		EMLXS_STATE_CHANGE(hba, FC_ERROR);

		emlxs_sli4_hba_flush_chipq(hba);

		emlxs_thread_spawn(hba, emlxs_shutdown_thread, 0, 0);

	} else if (error == 1) {
		EMLXS_STATE_CHANGE(hba, FC_ERROR);

		emlxs_sli4_hba_flush_chipq(hba);

		emlxs_thread_spawn(hba, emlxs_restart_thread, 0, 0);
	}

#ifdef FMA_SUPPORT
	/* Access handle validation */
	EMLXS_CHK_ACC_HANDLE(hba, hba->pci_acc_handle);
#endif  /* FMA_SUPPORT */

} /* emlxs_sli4_poll_erratt() */


static uint32_t
emlxs_sli4_reg_did(emlxs_port_t *port, uint32_t did, SERV_PARM *param,
    emlxs_buf_t *sbp, fc_unsol_buf_t *ubp, IOCBQ *iocbq)
{
	emlxs_hba_t	*hba = HBA;
	NODELIST	*node;
	RPIobj_t	*rpip;
	uint32_t	rval;

	/* Check for invalid node ids to register */
	if ((did == 0) && (!(hba->flag & FC_LOOPBACK_MODE))) {
		return (1);
	}

	if (did & 0xff000000) {
		return (1);
	}

	/* We don't register our own did */
	if ((did == port->did) && (!(hba->flag & FC_LOOPBACK_MODE))) {
		return (1);
	}

	if (did != FABRIC_DID) {
		if ((rval = emlxs_mb_check_sparm(hba, param))) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_create_failed_msg,
			    "Invalid service parameters. did=%06x rval=%d", did,
			    rval);

			return (1);
		}
	}

	/* Check if the node limit has been reached */
	if (port->node_count >= hba->max_nodes) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_create_failed_msg,
		    "Limit reached. did=%06x count=%d", did,
		    port->node_count);

		return (1);
	}

	node = emlxs_node_find_did(port, did, 1);
	rpip = EMLXS_NODE_TO_RPI(port, node);

	rval = emlxs_rpi_online_notify(port, rpip, did, param, (void *)sbp,
	    (void *)ubp, (void *)iocbq);

	return (rval);

} /* emlxs_sli4_reg_did() */


static uint32_t
emlxs_sli4_unreg_node(emlxs_port_t *port, emlxs_node_t *node,
    emlxs_buf_t *sbp, fc_unsol_buf_t *ubp, IOCBQ *iocbq)
{
	RPIobj_t	*rpip;
	uint32_t	rval;

	if (!node) {
		/* Unreg all nodes */
		(void) emlxs_sli4_unreg_all_nodes(port);
		return (1);
	}

	/* Check for base node */
	if (node == &port->node_base) {
		/* Just flush base node */
		(void) emlxs_tx_node_flush(port, &port->node_base,
		    0, 0, 0);

		(void) emlxs_chipq_node_flush(port, 0,
		    &port->node_base, 0);

		port->did = 0;

		/* Return now */
		return (1);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	    "unreg_node:%p did=%x rpi=%d",
	    node, node->nlp_DID, node->nlp_Rpi);

	rpip = EMLXS_NODE_TO_RPI(port, node);

	if (!rpip) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "unreg_node:%p did=%x rpi=%d. RPI not found.",
		    node, node->nlp_DID, node->nlp_Rpi);

		emlxs_node_rm(port, node);
		return (1);
	}

	rval = emlxs_rpi_offline_notify(port, rpip, (void *)sbp, (void *)ubp,
	    (void *)iocbq);

	return (rval);

} /* emlxs_sli4_unreg_node() */


extern uint32_t
emlxs_sli4_unreg_all_nodes(emlxs_port_t *port)
{
	NODELIST	*nlp;
	int		i;
	uint32_t 	found;

	/* Set the node tags */
	/* We will process all nodes with this tag */
	rw_enter(&port->node_rwlock, RW_READER);
	found = 0;
	for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
		nlp = port->node_table[i];
		while (nlp != NULL) {
			found = 1;
			nlp->nlp_tag = 1;
			nlp = nlp->nlp_list_next;
		}
	}
	rw_exit(&port->node_rwlock);

	if (!found) {
		return (0);
	}

	for (;;) {
		rw_enter(&port->node_rwlock, RW_READER);
		found = 0;
		for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
			nlp = port->node_table[i];
			while (nlp != NULL) {
				if (!nlp->nlp_tag) {
					nlp = nlp->nlp_list_next;
					continue;
				}
				nlp->nlp_tag = 0;
				found = 1;
				break;
			}

			if (found) {
				break;
			}
		}
		rw_exit(&port->node_rwlock);

		if (!found) {
			break;
		}

		(void) emlxs_sli4_unreg_node(port, nlp, 0, 0, 0);
	}

	return (0);

} /* emlxs_sli4_unreg_all_nodes() */


static void
emlxs_sli4_handle_fcoe_link_event(emlxs_hba_t *hba, CQE_ASYNC_t *cqe)
{
	emlxs_port_t *port = &PPORT;

	/* Handle link down */
	if ((cqe->un.link.link_status == ASYNC_EVENT_LOGICAL_LINK_DOWN) ||
	    (cqe->un.link.link_status == ASYNC_EVENT_PHYS_LINK_DOWN)) {
		(void) emlxs_fcf_linkdown_notify(port);

		mutex_enter(&EMLXS_PORT_LOCK);
		hba->sli.sli4.flag &= ~EMLXS_SLI4_DOWN_LINK;
		mutex_exit(&EMLXS_PORT_LOCK);
		return;
	}

	/* Link is up */

	/* Set linkspeed */
	switch (cqe->un.link.port_speed) {
	case PHY_1GHZ_LINK:
		hba->linkspeed = LA_1GHZ_LINK;
		break;
	case PHY_10GHZ_LINK:
		hba->linkspeed = LA_10GHZ_LINK;
		break;
	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "sli4_handle_fcoe_link_event: Unknown link speed=%x.",
		    cqe->un.link.port_speed);
		hba->linkspeed = 0;
		break;
	}

	/* Set qos_linkspeed */
	hba->qos_linkspeed = cqe->un.link.qos_link_speed;

	/* Set topology */
	hba->topology = TOPOLOGY_PT_PT;

	mutex_enter(&EMLXS_PORT_LOCK);
	hba->sli.sli4.flag &= ~EMLXS_SLI4_DOWN_LINK;
	mutex_exit(&EMLXS_PORT_LOCK);

	(void) emlxs_fcf_linkup_notify(port);

	return;

} /* emlxs_sli4_handle_fcoe_link_event()  */


static void
emlxs_sli4_handle_fc_link_att(emlxs_hba_t *hba, CQE_ASYNC_t *cqe)
{
	emlxs_port_t *port = &PPORT;

	/* Handle link down */
	if (cqe->un.fc.att_type == ATT_TYPE_LINK_DOWN) {
		(void) emlxs_fcf_linkdown_notify(port);

		mutex_enter(&EMLXS_PORT_LOCK);
		hba->sli.sli4.flag &= ~EMLXS_SLI4_DOWN_LINK;
		mutex_exit(&EMLXS_PORT_LOCK);
		return;
	}

	/* Link is up */

	/* Set linkspeed */
	switch (cqe->un.fc.port_speed) {
	case 1:
		hba->linkspeed = LA_1GHZ_LINK;
		break;
	case 2:
		hba->linkspeed = LA_2GHZ_LINK;
		break;
	case 4:
		hba->linkspeed = LA_4GHZ_LINK;
		break;
	case 8:
		hba->linkspeed = LA_8GHZ_LINK;
		break;
	case 10:
		hba->linkspeed = LA_10GHZ_LINK;
		break;
	case 16:
		hba->linkspeed = LA_16GHZ_LINK;
		break;
	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "sli4_handle_fc_link_att: Unknown link speed=%x.",
		    cqe->un.fc.port_speed);
		hba->linkspeed = 0;
		break;
	}

	/* Set qos_linkspeed */
	hba->qos_linkspeed = cqe->un.fc.link_speed;

	/* Set topology */
	hba->topology = cqe->un.fc.topology;

	mutex_enter(&EMLXS_PORT_LOCK);
	hba->sli.sli4.flag &= ~EMLXS_SLI4_DOWN_LINK;
	mutex_exit(&EMLXS_PORT_LOCK);

	(void) emlxs_fcf_linkup_notify(port);

	return;

} /* emlxs_sli4_handle_fc_link_att() */


static int
emlxs_sli4_init_extents(emlxs_hba_t *hba, MAILBOXQ *mbq)
{
	emlxs_port_t *port = &PPORT;
	MAILBOX4 *mb4;
	IOCTL_COMMON_EXTENTS *ep;
	uint32_t i;
	uint32_t ExtentCnt;

	if (!(hba->sli.sli4.param.EXT)) {
		return (0);
	}

	mb4 = (MAILBOX4 *) mbq;

	/* Discover XRI Extents */
	bzero(mbq, sizeof (MAILBOXQ));
	emlxs_mb_get_extents_info(hba, mbq, RSC_TYPE_FCOE_XRI);

	if (emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to discover XRI extents.  Mailbox cmd=%x status=%x",
		    mb4->mbxCommand, mb4->mbxStatus);

		return (EIO);
	}

	ep = (IOCTL_COMMON_EXTENTS *)&mb4->un.varSLIConfig.payload;
	hba->sli.sli4.XRIExtSize = ep->params.response.ExtentSize;
	ExtentCnt = ep->params.response.ExtentCnt;

	/* Allocate XRI Extents */
	bzero(mbq, sizeof (MAILBOXQ));
	emlxs_mb_alloc_extents(hba, mbq, RSC_TYPE_FCOE_XRI, ExtentCnt);

	if (emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to allocate XRI extents.  Mailbox cmd=%x status=%x",
		    mb4->mbxCommand, mb4->mbxStatus);

		return (EIO);
	}
	ep = (IOCTL_COMMON_EXTENTS *)&mb4->un.varSLIConfig.payload;

	bcopy((uint8_t *)ep->params.response.RscId,
	    (uint8_t *)hba->sli.sli4.XRIBase,
	    (ep->params.response.ExtentCnt * sizeof (uint16_t)));

	hba->sli.sli4.XRIExtCount = ep->params.response.ExtentCnt;
	hba->sli.sli4.XRICount = hba->sli.sli4.XRIExtCount *
	    hba->sli.sli4.XRIExtSize;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
	    "XRI Ext: size=%d cnt=%d/%d",
	    hba->sli.sli4.XRIExtSize,
	    hba->sli.sli4.XRIExtCount, ExtentCnt);

	for (i = 0; i < ep->params.response.ExtentCnt; i += 4) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "XRI Ext%d: %d, %d, %d, %d", i,
		    hba->sli.sli4.XRIBase[i],
		    hba->sli.sli4.XRIBase[i+1],
		    hba->sli.sli4.XRIBase[i+2],
		    hba->sli.sli4.XRIBase[i+3]);
	}


	/* Discover RPI Extents */
	bzero(mbq, sizeof (MAILBOXQ));
	emlxs_mb_get_extents_info(hba, mbq, RSC_TYPE_FCOE_RPI);

	if (emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to discover RPI extents.  Mailbox cmd=%x status=%x",
		    mb4->mbxCommand, mb4->mbxStatus);

		return (EIO);
	}

	ep = (IOCTL_COMMON_EXTENTS *)&mb4->un.varSLIConfig.payload;
	hba->sli.sli4.RPIExtSize = ep->params.response.ExtentSize;
	ExtentCnt = ep->params.response.ExtentCnt;

	/* Allocate RPI Extents */
	bzero(mbq, sizeof (MAILBOXQ));
	emlxs_mb_alloc_extents(hba, mbq, RSC_TYPE_FCOE_RPI, ExtentCnt);

	if (emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to allocate RPI extents.  Mailbox cmd=%x status=%x",
		    mb4->mbxCommand, mb4->mbxStatus);

		return (EIO);
	}
	ep = (IOCTL_COMMON_EXTENTS *)&mb4->un.varSLIConfig.payload;

	bcopy((uint8_t *)ep->params.response.RscId,
	    (uint8_t *)hba->sli.sli4.RPIBase,
	    (ep->params.response.ExtentCnt * sizeof (uint16_t)));

	hba->sli.sli4.RPIExtCount = ep->params.response.ExtentCnt;
	hba->sli.sli4.RPICount = hba->sli.sli4.RPIExtCount *
	    hba->sli.sli4.RPIExtSize;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
	    "RPI Ext: size=%d cnt=%d/%d",
	    hba->sli.sli4.RPIExtSize,
	    hba->sli.sli4.RPIExtCount, ExtentCnt);

	for (i = 0; i < ep->params.response.ExtentCnt; i += 4) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "RPI Ext%d: %d, %d, %d, %d", i,
		    hba->sli.sli4.RPIBase[i],
		    hba->sli.sli4.RPIBase[i+1],
		    hba->sli.sli4.RPIBase[i+2],
		    hba->sli.sli4.RPIBase[i+3]);
	}


	/* Discover VPI Extents */
	bzero(mbq, sizeof (MAILBOXQ));
	emlxs_mb_get_extents_info(hba, mbq, RSC_TYPE_FCOE_VPI);

	if (emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to discover VPI extents.  Mailbox cmd=%x status=%x",
		    mb4->mbxCommand, mb4->mbxStatus);

		return (EIO);
	}

	ep = (IOCTL_COMMON_EXTENTS *)&mb4->un.varSLIConfig.payload;
	hba->sli.sli4.VPIExtSize = ep->params.response.ExtentSize;
	ExtentCnt = ep->params.response.ExtentCnt;

	/* Allocate VPI Extents */
	bzero(mbq, sizeof (MAILBOXQ));
	emlxs_mb_alloc_extents(hba, mbq, RSC_TYPE_FCOE_VPI, ExtentCnt);

	if (emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to allocate VPI extents.  Mailbox cmd=%x status=%x",
		    mb4->mbxCommand, mb4->mbxStatus);

		return (EIO);
	}
	ep = (IOCTL_COMMON_EXTENTS *)&mb4->un.varSLIConfig.payload;

	bcopy((uint8_t *)ep->params.response.RscId,
	    (uint8_t *)hba->sli.sli4.VPIBase,
	    (ep->params.response.ExtentCnt * sizeof (uint16_t)));

	hba->sli.sli4.VPIExtCount = ep->params.response.ExtentCnt;
	hba->sli.sli4.VPICount = hba->sli.sli4.VPIExtCount *
	    hba->sli.sli4.VPIExtSize;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
	    "VPI Ext: size=%d cnt=%d/%d",
	    hba->sli.sli4.VPIExtSize,
	    hba->sli.sli4.VPIExtCount, ExtentCnt);

	for (i = 0; i < ep->params.response.ExtentCnt; i += 4) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "VPI Ext%d: %d, %d, %d, %d", i,
		    hba->sli.sli4.VPIBase[i],
		    hba->sli.sli4.VPIBase[i+1],
		    hba->sli.sli4.VPIBase[i+2],
		    hba->sli.sli4.VPIBase[i+3]);
	}

	/* Discover VFI Extents */
	bzero(mbq, sizeof (MAILBOXQ));
	emlxs_mb_get_extents_info(hba, mbq, RSC_TYPE_FCOE_VFI);

	if (emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to discover VFI extents.  Mailbox cmd=%x status=%x",
		    mb4->mbxCommand, mb4->mbxStatus);

		return (EIO);
	}

	ep = (IOCTL_COMMON_EXTENTS *)&mb4->un.varSLIConfig.payload;
	hba->sli.sli4.VFIExtSize = ep->params.response.ExtentSize;
	ExtentCnt = ep->params.response.ExtentCnt;

	/* Allocate VFI Extents */
	bzero(mbq, sizeof (MAILBOXQ));
	emlxs_mb_alloc_extents(hba, mbq, RSC_TYPE_FCOE_VFI, ExtentCnt);

	if (emlxs_sli4_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to allocate VFI extents.  Mailbox cmd=%x status=%x",
		    mb4->mbxCommand, mb4->mbxStatus);

		return (EIO);
	}
	ep = (IOCTL_COMMON_EXTENTS *)&mb4->un.varSLIConfig.payload;

	bcopy((uint8_t *)ep->params.response.RscId,
	    (uint8_t *)hba->sli.sli4.VFIBase,
	    (ep->params.response.ExtentCnt * sizeof (uint16_t)));

	hba->sli.sli4.VFIExtCount = ep->params.response.ExtentCnt;
	hba->sli.sli4.VFICount = hba->sli.sli4.VFIExtCount *
	    hba->sli.sli4.VFIExtSize;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
	    "VFI Ext: size=%d cnt=%d/%d",
	    hba->sli.sli4.VFIExtSize,
	    hba->sli.sli4.VFIExtCount, ExtentCnt);

	for (i = 0; i < ep->params.response.ExtentCnt; i += 4) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "VFI Ext%d: %d, %d, %d, %d", i,
		    hba->sli.sli4.VFIBase[i],
		    hba->sli.sli4.VFIBase[i+1],
		    hba->sli.sli4.VFIBase[i+2],
		    hba->sli.sli4.VFIBase[i+3]);
	}

	return (0);

} /* emlxs_sli4_init_extents() */


extern uint32_t
emlxs_sli4_index_to_rpi(emlxs_hba_t *hba, uint32_t index)
{
	uint32_t i;
	uint32_t j;
	uint32_t rpi;

	i = index / hba->sli.sli4.RPIExtSize;
	j = index % hba->sli.sli4.RPIExtSize;
	rpi = hba->sli.sli4.RPIBase[i] + j;

	return (rpi);

} /* emlxs_sli4_index_to_rpi */


extern uint32_t
emlxs_sli4_rpi_to_index(emlxs_hba_t *hba, uint32_t rpi)
{
	uint32_t i;
	uint32_t lo;
	uint32_t hi;
	uint32_t index = hba->sli.sli4.RPICount;

	for (i = 0; i < hba->sli.sli4.RPIExtCount; i++) {
		lo = hba->sli.sli4.RPIBase[i];
		hi = lo + hba->sli.sli4.RPIExtSize;

		if ((rpi < hi) && (rpi >= lo)) {
			index = (i * hba->sli.sli4.RPIExtSize) + (rpi - lo);
			break;
		}
	}

	return (index);

} /* emlxs_sli4_rpi_to_index */


extern uint32_t
emlxs_sli4_index_to_xri(emlxs_hba_t *hba, uint32_t index)
{
	uint32_t i;
	uint32_t j;
	uint32_t xri;

	i = index / hba->sli.sli4.XRIExtSize;
	j = index % hba->sli.sli4.XRIExtSize;
	xri = hba->sli.sli4.XRIBase[i] + j;

	return (xri);

} /* emlxs_sli4_index_to_xri */




extern uint32_t
emlxs_sli4_index_to_vpi(emlxs_hba_t *hba, uint32_t index)
{
	uint32_t i;
	uint32_t j;
	uint32_t vpi;

	i = index / hba->sli.sli4.VPIExtSize;
	j = index % hba->sli.sli4.VPIExtSize;
	vpi = hba->sli.sli4.VPIBase[i] + j;

	return (vpi);

} /* emlxs_sli4_index_to_vpi */


extern uint32_t
emlxs_sli4_vpi_to_index(emlxs_hba_t *hba, uint32_t vpi)
{
	uint32_t i;
	uint32_t lo;
	uint32_t hi;
	uint32_t index = hba->sli.sli4.VPICount;

	for (i = 0; i < hba->sli.sli4.VPIExtCount; i++) {
		lo = hba->sli.sli4.VPIBase[i];
		hi = lo + hba->sli.sli4.VPIExtSize;

		if ((vpi < hi) && (vpi >= lo)) {
			index = (i * hba->sli.sli4.VPIExtSize) + (vpi - lo);
			break;
		}
	}

	return (index);

} /* emlxs_sli4_vpi_to_index */




extern uint32_t
emlxs_sli4_index_to_vfi(emlxs_hba_t *hba, uint32_t index)
{
	uint32_t i;
	uint32_t j;
	uint32_t vfi;

	i = index / hba->sli.sli4.VFIExtSize;
	j = index % hba->sli.sli4.VFIExtSize;
	vfi = hba->sli.sli4.VFIBase[i] + j;

	return (vfi);

} /* emlxs_sli4_index_to_vfi */


static uint16_t
emlxs_sli4_rqid_to_index(emlxs_hba_t *hba, uint16_t rqid)
{
	uint16_t i;

	if (rqid < 0xffff) {
		for (i = 0; i < EMLXS_MAX_RQS; i++) {
			if (hba->sli.sli4.rq[i].qid == rqid) {
				return (i);
			}
		}
	}

	return (0xffff);

} /* emlxs_sli4_rqid_to_index */


static uint16_t
emlxs_sli4_wqid_to_index(emlxs_hba_t *hba, uint16_t wqid)
{
	uint16_t i;

	if (wqid < 0xffff) {
		for (i = 0; i < EMLXS_MAX_WQS; i++) {
			if (hba->sli.sli4.wq[i].qid == wqid) {
				return (i);
			}
		}
	}

	return (0xffff);

} /* emlxs_sli4_wqid_to_index */


static uint16_t
emlxs_sli4_cqid_to_index(emlxs_hba_t *hba, uint16_t cqid)
{
	uint16_t i;

	if (cqid < 0xffff) {
		for (i = 0; i < EMLXS_MAX_CQS; i++) {
			if (hba->sli.sli4.cq[i].qid == cqid) {
				return (i);
			}
		}
	}

	return (0xffff);

} /* emlxs_sli4_cqid_to_index */
