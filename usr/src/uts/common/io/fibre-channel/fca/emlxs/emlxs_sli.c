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
 * Use is subject to License terms.
 */

#include <emlxs.h>

/* Required for EMLXS_CONTEXT in EMLXS_MSGF calls */
EMLXS_MSG_DEF(EMLXS_SLI_C);

static void emlxs_issue_iocb(emlxs_hba_t *hba, RING *rp, IOCBQ *iocbq);
static void emlxs_handle_link_event(emlxs_hba_t *hba);
static void emlxs_handle_ring_event(emlxs_hba_t *hba, int32_t ring_no,
	uint32_t ha_copy);
static int emlxs_mb_handle_cmd(emlxs_hba_t *hba, MAILBOX *mb);
#ifdef SFCT_SUPPORT
static uint32_t emlxs_fct_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp);
#endif /* SFCT_SUPPORT */
static uint32_t	emlxs_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp);

int
emlxs_sli3_map_hdw(emlxs_hba_t *hba)
{
	emlxs_port_t		*port = &PPORT;
	dev_info_t		*dip;
	ddi_device_acc_attr_t	dev_attr;
	int			status;

	dip = (dev_info_t *)hba->dip;
	dev_attr = emlxs_dev_acc_attr;

	if (hba->bus_type == SBUS_FC) {

		if (hba->slim_acc_handle == 0) {
			status = ddi_regs_map_setup(dip,
			    SBUS_DFLY_SLIM_RINDEX,
			    (caddr_t *)&hba->slim_addr,
			    0, 0, &dev_attr, &hba->slim_acc_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "(SBUS) ddi_regs_map_setup SLIM failed. "
				    "status=%x", status);
				goto failed;
			}
		}
		if (hba->csr_acc_handle == 0) {
			status = ddi_regs_map_setup(dip,
			    SBUS_DFLY_CSR_RINDEX,
			    (caddr_t *)&hba->csr_addr,
			    0, 0, &dev_attr, &hba->csr_acc_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "(SBUS) ddi_regs_map_setup DFLY CSR "
				    "failed. status=%x", status);
				goto failed;
			}
		}
		if (hba->sbus_flash_acc_handle == 0) {
			status = ddi_regs_map_setup(dip, SBUS_FLASH_RDWR,
			    (caddr_t *)&hba->sbus_flash_addr,
			    0, 0, &dev_attr, &hba->sbus_flash_acc_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "(SBUS) ddi_regs_map_setup Fcode Flash "
				    "failed. status=%x", status);
				goto failed;
			}
		}
		if (hba->sbus_core_acc_handle == 0) {
			status = ddi_regs_map_setup(dip, SBUS_TITAN_CORE_RINDEX,
			    (caddr_t *)&hba->sbus_core_addr,
			    0, 0, &dev_attr, &hba->sbus_core_acc_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "(SBUS) ddi_regs_map_setup TITAN CORE "
				    "failed. status=%x", status);
				goto failed;
			}
		}

		if (hba->sbus_csr_handle == 0) {
			status = ddi_regs_map_setup(dip, SBUS_TITAN_CSR_RINDEX,
			    (caddr_t *)&hba->sbus_csr_addr,
			    0, 0, &dev_attr, &hba->sbus_csr_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "(SBUS) ddi_regs_map_setup TITAN CSR "
				    "failed. status=%x", status);
				goto failed;
			}
		}
	} else {	/* ****** PCI ****** */

		if (hba->slim_acc_handle == 0) {
			status = ddi_regs_map_setup(dip, PCI_SLIM_RINDEX,
			    (caddr_t *)&hba->slim_addr,
			    0, 0, &dev_attr, &hba->slim_acc_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "(PCI) ddi_regs_map_setup SLIM failed. "
				    "stat=%d mem=%p attr=%p hdl=%p",
				    status, &hba->slim_addr, &dev_attr,
				    &hba->slim_acc_handle);
				goto failed;
			}
		}

		/*
		 * Map in control registers, using memory-mapped version of
		 * the registers rather than the I/O space-mapped registers.
		 */
		if (hba->csr_acc_handle == 0) {
			status = ddi_regs_map_setup(dip, PCI_CSR_RINDEX,
			    (caddr_t *)&hba->csr_addr,
			    0, 0, &dev_attr, &hba->csr_acc_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "ddi_regs_map_setup CSR failed. status=%x",
				    status);
				goto failed;
			}
		}
	}

	if (hba->slim2.virt == 0) {
		MBUF_INFO	*buf_info;
		MBUF_INFO	bufinfo;

		buf_info = &bufinfo;

		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = SLI_SLIM2_SIZE;
		buf_info->flags =
		    FC_MBUF_DMA | FC_MBUF_SNGLSG | FC_MBUF_DMA32;
		buf_info->align = ddi_ptob(dip, 1L);

		(void) emlxs_mem_alloc(hba, buf_info);

		if (buf_info->virt == NULL) {
			goto failed;
		}

		hba->slim2.virt = (uint8_t *)buf_info->virt;
		hba->slim2.phys = buf_info->phys;
		hba->slim2.size = SLI_SLIM2_SIZE;
		hba->slim2.data_handle = buf_info->data_handle;
		hba->slim2.dma_handle = buf_info->dma_handle;
		bzero((char *)hba->slim2.virt, SLI_SLIM2_SIZE);
	}

	/* offset from beginning of register space */
	hba->ha_reg_addr = (sizeof (uint32_t) * HA_REG_OFFSET);
	hba->ca_reg_addr = (sizeof (uint32_t) * CA_REG_OFFSET);
	hba->hs_reg_addr = (sizeof (uint32_t) * HS_REG_OFFSET);
	hba->hc_reg_addr = (sizeof (uint32_t) * HC_REG_OFFSET);
	hba->bc_reg_addr = (sizeof (uint32_t) * BC_REG_OFFSET);

	if (hba->bus_type == SBUS_FC) {
		/* offset from beginning of register space */
		/* for TITAN registers */
		hba->shc_reg_addr =
		    (sizeof (uint32_t) * SBUS_CTRL_REG_OFFSET);
		hba->shs_reg_addr =
		    (sizeof (uint32_t) * SBUS_STAT_REG_OFFSET);
		hba->shu_reg_addr =
		    (sizeof (uint32_t) * SBUS_UPDATE_REG_OFFSET);
	}

	return (0);

failed:

	emlxs_sli3_unmap_hdw(hba);
	return (ENOMEM);

} /* emlxs_sli3_map_hdw() */


/*ARGSUSED*/
int
emlxs_sli4_map_hdw(emlxs_hba_t *hba)
{
	/*
	 * Map in Hardware BAR pages that will be used for
	 * communication with HBA.
	 */
	return (0);
} /* emlxs_sli4_map_hdw() */

void
emlxs_sli3_unmap_hdw(emlxs_hba_t *hba)
{
	MBUF_INFO	bufinfo;
	MBUF_INFO	*buf_info = &bufinfo;

	if (hba->csr_acc_handle) {
		ddi_regs_map_free(&hba->csr_acc_handle);
		hba->csr_acc_handle = 0;
	}

	if (hba->slim_acc_handle) {
		ddi_regs_map_free(&hba->slim_acc_handle);
		hba->slim_acc_handle = 0;
	}

	if (hba->sbus_flash_acc_handle) {
		ddi_regs_map_free(&hba->sbus_flash_acc_handle);
		hba->sbus_flash_acc_handle = 0;
	}

	if (hba->sbus_core_acc_handle) {
		ddi_regs_map_free(&hba->sbus_core_acc_handle);
		hba->sbus_core_acc_handle = 0;
	}

	if (hba->sbus_csr_handle) {
		ddi_regs_map_free(&hba->sbus_csr_handle);
		hba->sbus_csr_handle = 0;
	}

	if (hba->slim2.virt) {
		bzero(buf_info, sizeof (MBUF_INFO));

		if (hba->slim2.phys) {
			buf_info->phys = hba->slim2.phys;
			buf_info->data_handle = hba->slim2.data_handle;
			buf_info->dma_handle = hba->slim2.dma_handle;
			buf_info->flags = FC_MBUF_DMA;
		}

		buf_info->virt = (uint32_t *)hba->slim2.virt;
		buf_info->size = hba->slim2.size;
		emlxs_mem_free(hba, buf_info);

		hba->slim2.virt = 0;
	}

	return;

} /* emlxs_sli3_unmap_hdw() */


/*ARGSUSED*/
void
emlxs_sli4_unmap_hdw(emlxs_hba_t *hba)
{
	/*
	 * Free map for Hardware BAR pages that were used for
	 * communication with HBA.
	 */
} /* emlxs_sli4_unmap_hdw() */


extern int
emlxs_sli3_online(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	emlxs_port_t *vport;
	emlxs_config_t *cfg;
	int32_t i;

	cfg = &CFG;
	i = 0;

	/* Restart the adapter */
	if (emlxs_sli3_hba_reset(hba, 1, 0)) {
		return (1);
	}

	hba->ring_count = MAX_RINGS;	/* number of rings used */

	/*
	 * WARNING: There is a max of 6 ring masks allowed
	 */
	/* RING 0 - FCP */
	if (hba->tgt_mode) {
		hba->ring_masks[FC_FCP_RING] = 1;
		hba->ring_rval[i] = FC_FCP_CMND;
		hba->ring_rmask[i] = 0;
		hba->ring_tval[i] = FC_FCP_DATA;
		hba->ring_tmask[i++] = 0xFF;
	} else {
		hba->ring_masks[FC_FCP_RING] = 0;
	}

	hba->ring[FC_FCP_RING].fc_numCiocb = SLIM_IOCB_CMD_R0_ENTRIES;
	hba->ring[FC_FCP_RING].fc_numRiocb = SLIM_IOCB_RSP_R0_ENTRIES;

	/* RING 1 - IP */
	if (cfg[CFG_NETWORK_ON].current) {
		hba->ring_masks[FC_IP_RING] = 1;
		hba->ring_rval[i] = FC_UNSOL_DATA;	/* Unsolicited Data */
		hba->ring_rmask[i] = 0xFF;
		hba->ring_tval[i] = FC_LLC_SNAP;	/* LLC/SNAP */
		hba->ring_tmask[i++] = 0xFF;
	} else {
		hba->ring_masks[FC_IP_RING] = 0;
	}

	hba->ring[FC_IP_RING].fc_numCiocb = SLIM_IOCB_CMD_R1_ENTRIES;
	hba->ring[FC_IP_RING].fc_numRiocb = SLIM_IOCB_RSP_R1_ENTRIES;

	/* RING 2 - ELS */
	hba->ring_masks[FC_ELS_RING] = 1;
	hba->ring_rval[i] = FC_ELS_REQ;		/* ELS request/response */
	hba->ring_rmask[i] = 0xFE;
	hba->ring_tval[i] = FC_ELS_DATA;	/* ELS */
	hba->ring_tmask[i++] = 0xFF;

	hba->ring[FC_ELS_RING].fc_numCiocb = SLIM_IOCB_CMD_R2_ENTRIES;
	hba->ring[FC_ELS_RING].fc_numRiocb = SLIM_IOCB_RSP_R2_ENTRIES;

	/* RING 3 - CT */
	hba->ring_masks[FC_CT_RING] = 1;
	hba->ring_rval[i] = FC_UNSOL_CTL;	/* CT request/response */
	hba->ring_rmask[i] = 0xFE;
	hba->ring_tval[i] = FC_CT_TYPE;		/* CT */
	hba->ring_tmask[i++] = 0xFF;

	hba->ring[FC_CT_RING].fc_numCiocb = SLIM_IOCB_CMD_R3_ENTRIES;
	hba->ring[FC_CT_RING].fc_numRiocb = SLIM_IOCB_RSP_R3_ENTRIES;

	if (i > 6) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_failed_msg,
		    "emlxs_hba_init: Too many ring masks defined. cnt=%d", i);
		return (1);
	}

	/* Initialize all the port objects */
	hba->vpi_max = 1;
	for (i = 0; i < MAX_VPORTS; i++) {
		vport = &VPORT(i);
		vport->hba = hba;
		vport->vpi = i;
	}

	/*
	 * Initialize the max_node count to a default value if needed
	 * This determines how many node objects we preallocate in the pool
	 * The actual max_nodes will be set later based on adapter info
	 */
	if (hba->max_nodes == 0) {
		if (cfg[CFG_NUM_NODES].current > 0) {
			hba->max_nodes = cfg[CFG_NUM_NODES].current;
		} else if (hba->model_info.chip >= EMLXS_SATURN_CHIP) {
			hba->max_nodes = 4096;
		} else {
			hba->max_nodes = 512;
		}
	}


	return (0);
}  /* emlxs_sli3_online() */


/*ARGSUSED*/
extern int
emlxs_sli4_online(emlxs_hba_t *hba)
{
	/*
	 * Initalize Hardware that will be used to bring
	 * SLI4 online.
	 */
	return (0);

}  /* emlxs_sli4_online() */


extern void
emlxs_sli3_offline(emlxs_hba_t *hba)
{
	/* Interlock the adapter to take it down */
	(void) emlxs_interlock(hba);

}  /* emlxs_sli3_offline() */


/*ARGSUSED*/
extern void
emlxs_sli4_offline(emlxs_hba_t *hba)
{
	return;

}  /* emlxs_sli4_offline() */


extern uint32_t
emlxs_sli3_hba_reset(emlxs_hba_t *hba, uint32_t restart, uint32_t skip_post)
{
	emlxs_port_t *port = &PPORT;
	MAILBOX *swpmb;
	MAILBOX *mb;
	uint32_t word0;
	uint16_t cfg_value;
	uint32_t status;
	uint32_t status1;
	uint32_t status2;
	uint32_t i;
	uint32_t ready;
	emlxs_port_t *vport;
	RING *rp;
	emlxs_config_t *cfg = &CFG;

	i = 0;

	if (!cfg[CFG_RESET_ENABLE].current) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_reset_failed_msg,
		    "Adapter reset disabled.");
		emlxs_ffstate_change(hba, FC_ERROR);

		return (1);
	}

	/* Make sure we have called interlock */
	(void) emlxs_interlock(hba);

	if (restart) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Restarting.");
		emlxs_ffstate_change(hba, FC_INIT_START);

		ready = (HS_FFRDY | HS_MBRDY);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Resetting.");
		emlxs_ffstate_change(hba, FC_WARM_START);

		ready = HS_MBRDY;
	}

	hba->flag &= ~(FC_SLIM2_MODE | FC_HARDWARE_ERROR);

	mb = FC_SLIM1_MAILBOX(hba);
	swpmb = (MAILBOX *)&word0;

reset:

	/* Save reset time */
	HBASTATS.ResetTime = hba->timer_tics;

	if (restart) {
		/* First put restart command in mailbox */
		word0 = 0;
		swpmb->mbxCommand = MBX_RESTART;
		swpmb->mbxHc = 1;
		WRITE_SLIM_ADDR(hba, ((volatile uint32_t *)mb), word0);

		/* Only skip post after emlxs_ffinit is completed  */
		if (skip_post) {
			WRITE_SLIM_ADDR(hba, (((volatile uint32_t *)mb) + 1),
			    1);
		} else {
			WRITE_SLIM_ADDR(hba, (((volatile uint32_t *)mb) + 1),
			    0);
		}

	}

	/*
	 * Turn off SERR, PERR in PCI cmd register
	 */
	cfg_value = ddi_get16(hba->pci_acc_handle,
	    (uint16_t *)(hba->pci_addr + PCI_COMMAND_REGISTER));

	ddi_put16(hba->pci_acc_handle,
	    (uint16_t *)(hba->pci_addr + PCI_COMMAND_REGISTER),
	    (uint16_t)(cfg_value & ~(CMD_PARITY_CHK | CMD_SERR_ENBL)));

	hba->hc_copy = HC_INITFF;
	WRITE_CSR_REG(hba, FC_HC_REG(hba, hba->csr_addr), hba->hc_copy);

	/* Wait 1 msec before restoring PCI config */
	DELAYMS(1);

	/* Restore PCI cmd register */
	ddi_put16(hba->pci_acc_handle,
	    (uint16_t *)(hba->pci_addr + PCI_COMMAND_REGISTER),
	    (uint16_t)cfg_value);

	/* Wait 3 seconds before checking */
	DELAYMS(3000);
	i += 3;

	/* Wait for reset completion */
	while (i < 30) {
		/* Check status register to see what current state is */
		status = READ_CSR_REG(hba, FC_HS_REG(hba, hba->csr_addr));

		/* Check to see if any errors occurred during init */
		if (status & HS_FFERM) {
			status1 =
			    READ_SLIM_ADDR(hba,
			    ((volatile uint8_t *)hba->slim_addr + 0xa8));
			status2 =
			    READ_SLIM_ADDR(hba,
			    ((volatile uint8_t *)hba->slim_addr + 0xac));

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_reset_failed_msg,
			    "HS_FFERM: status=0x%x status1=0x%x status2=0x%x",
			    status, status1, status2);

			emlxs_ffstate_change(hba, FC_ERROR);
			return (1);
		}

		if ((status & ready) == ready) {
			/* Reset Done !! */
			goto done;
		}

		/*
		 * Check every 1 second for 15 seconds, then reset board
		 * again (w/post), then check every 1 second for 15 * seconds.
		 */
		DELAYMS(1000);
		i++;

		/* Reset again (w/post) at 15 seconds */
		if (i == 15) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "Reset failed. Retrying...");

			goto reset;
		}
	}

	/* Timeout occurred */
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_reset_failed_msg,
	    "Timeout: status=0x%x", status);
	emlxs_ffstate_change(hba, FC_ERROR);

	/* Log a dump event */
	emlxs_log_dump_event(port, NULL, 0);

	return (1);

done:

	/* Reset the hba structure */
	hba->flag &= FC_RESET_MASK;
	bzero(hba->ring_tx_count, sizeof (hba->ring_tx_count));
	bzero(hba->io_count, sizeof (hba->io_count));
	hba->iodone_count = 0;
	hba->topology = 0;
	hba->linkspeed = 0;
	hba->heartbeat_active = 0;
	hba->discovery_timer = 0;
	hba->linkup_timer = 0;
	hba->loopback_tics = 0;

	/* Initialize hc_copy */
	hba->hc_copy = READ_CSR_REG(hba, FC_HC_REG(hba, hba->csr_addr));

	/* Reset the ring objects */
	for (i = 0; i < MAX_RINGS; i++) {
		rp = &hba->ring[i];
		rp->fc_mpon = 0;
		rp->fc_mpoff = 0;
	}

	/* Reset the port objects */
	for (i = 0; i < MAX_VPORTS; i++) {
		vport = &VPORT(i);

		vport->flag &= EMLXS_PORT_RESET_MASK;
		vport->did = 0;
		vport->prev_did = 0;
		vport->lip_type = 0;
		bzero(&vport->fabric_sparam, sizeof (SERV_PARM));

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

	return (0);

}  /* emlxs_sli3_hba_reset */

/*ARGSUSED*/
extern uint32_t
emlxs_sli4_hba_reset(emlxs_hba_t *hba, uint32_t restart, uint32_t skip_post)
{
	return (0);

}  /* emlxs_sli4_hba_reset */


#define	BPL_CMD		0
#define	BPL_RESP	1
#define	BPL_DATA	2

ULP_BDE64 *
emlxs_pkt_to_bpl(ULP_BDE64 *bpl, fc_packet_t *pkt, uint32_t bpl_type,
    uint8_t bdeFlags)
{
	ddi_dma_cookie_t *cp;
	uint_t	i;
	int32_t	size;
	uint_t	cookie_cnt;

#if (EMLXS_MODREV >= EMLXS_MODREV3)
	switch (bpl_type) {
	case BPL_CMD:
		cp = pkt->pkt_cmd_cookie;
		cookie_cnt = pkt->pkt_cmd_cookie_cnt;
		size = (int32_t)pkt->pkt_cmdlen;
		break;

	case BPL_RESP:
		cp = pkt->pkt_resp_cookie;
		cookie_cnt = pkt->pkt_resp_cookie_cnt;
		size = (int32_t)pkt->pkt_rsplen;
		break;


	case BPL_DATA:
		cp = pkt->pkt_data_cookie;
		cookie_cnt = pkt->pkt_data_cookie_cnt;
		size = (int32_t)pkt->pkt_datalen;
		break;
	}

#else
	switch (bpl_type) {
	case BPL_CMD:
		cp = &pkt->pkt_cmd_cookie;
		cookie_cnt = 1;
		size = (int32_t)pkt->pkt_cmdlen;
		break;

	case BPL_RESP:
		cp = &pkt->pkt_resp_cookie;
		cookie_cnt = 1;
		size = (int32_t)pkt->pkt_rsplen;
		break;


	case BPL_DATA:
		cp = &pkt->pkt_data_cookie;
		cookie_cnt = 1;
		size = (int32_t)pkt->pkt_datalen;
		break;
	}
#endif	/* >= EMLXS_MODREV3 */

	for (i = 0; i < cookie_cnt && size > 0; i++, cp++) {
		bpl->addrHigh =
		    PCIMEM_LONG(putPaddrHigh(cp->dmac_laddress));
		bpl->addrLow =
		    PCIMEM_LONG(putPaddrLow(cp->dmac_laddress));
		bpl->tus.f.bdeSize = MIN(size, cp->dmac_size);
		bpl->tus.f.bdeFlags = bdeFlags;
		bpl->tus.w = PCIMEM_LONG(bpl->tus.w);

		bpl++;
		size -= cp->dmac_size;
	}

	return (bpl);

} /* emlxs_pkt_to_bpl */


uint32_t
emlxs_sli2_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t	*hba = HBA;
	fc_packet_t	*pkt;
	MATCHMAP	*bmp;
	ULP_BDE64	*bpl;
	uint64_t	bp;
	uint8_t		bdeFlag;
	IOCB		*iocb;
	RING		*rp;
	uint32_t	cmd_cookie_cnt;
	uint32_t	resp_cookie_cnt;
	uint32_t	data_cookie_cnt;
	uint32_t	cookie_cnt;

	rp = sbp->ring;
	iocb = (IOCB *) & sbp->iocbq;
	pkt = PRIV2PKT(sbp);

#ifdef EMLXS_SPARC
	if (rp->ringno == FC_FCP_RING) {
		/* Use FCP MEM_BPL table to get BPL buffer */
		bmp = &hba->fcp_bpl_table[sbp->iotag];
	} else {
		/* Use MEM_BPL pool to get BPL buffer */
		bmp = (MATCHMAP *) emlxs_mem_get(hba, MEM_BPL);
	}

#else
	/* Use MEM_BPL pool to get BPL buffer */
	bmp = (MATCHMAP *) emlxs_mem_get(hba, MEM_BPL);

#endif

	if (!bmp) {
		return (1);
	}

	sbp->bmp = bmp;
	bpl = (ULP_BDE64 *)bmp->virt;
	bp = bmp->phys;
	cookie_cnt = 0;

#if (EMLXS_MODREV >= EMLXS_MODREV3)
	cmd_cookie_cnt  = pkt->pkt_cmd_cookie_cnt;
	resp_cookie_cnt = pkt->pkt_resp_cookie_cnt;
	data_cookie_cnt = pkt->pkt_data_cookie_cnt;
#else
	cmd_cookie_cnt  = 1;
	resp_cookie_cnt = 1;
	data_cookie_cnt = 1;
#endif	/* >= EMLXS_MODREV3 */

	switch (rp->ringno) {
	case FC_FCP_RING:

		/* CMD payload */
		bpl = emlxs_pkt_to_bpl(bpl, pkt, BPL_CMD, 0);
		cookie_cnt = cmd_cookie_cnt;

		if (pkt->pkt_tran_type != FC_PKT_OUTBOUND) {
			/* RSP payload */
			bpl =
			    emlxs_pkt_to_bpl(bpl, pkt, BPL_RESP,
			    BUFF_USE_RCV);
			cookie_cnt += resp_cookie_cnt;

			/* DATA payload */
			if (pkt->pkt_datalen != 0) {
				bdeFlag =
				    (pkt->pkt_tran_type ==
				    FC_PKT_FCP_READ) ? BUFF_USE_RCV : 0;
				bpl =
				    emlxs_pkt_to_bpl(bpl, pkt, BPL_DATA,
				    bdeFlag);
				cookie_cnt += data_cookie_cnt;
			}
		}
		/*
		 * else
		 * {
		 * 	Target mode FCP status. Do nothing more.
		 * }
		 */

		break;

	case FC_IP_RING:

		/* CMD payload */
		bpl = emlxs_pkt_to_bpl(bpl, pkt, BPL_CMD, 0);
		cookie_cnt = cmd_cookie_cnt;

		break;

	case FC_ELS_RING:

		/* CMD payload */
		bpl = emlxs_pkt_to_bpl(bpl, pkt, BPL_CMD, 0);
		cookie_cnt = cmd_cookie_cnt;

		/* RSP payload */
		if (pkt->pkt_tran_type != FC_PKT_OUTBOUND) {
			bpl =
			    emlxs_pkt_to_bpl(bpl, pkt, BPL_RESP,
			    BUFF_USE_RCV);
			cookie_cnt += resp_cookie_cnt;
		}

		break;


	case FC_CT_RING:

		/* CMD payload */
		bpl = emlxs_pkt_to_bpl(bpl, pkt, BPL_CMD, 0);
		cookie_cnt = cmd_cookie_cnt;

		if ((pkt->pkt_tran_type != FC_PKT_OUTBOUND) ||
		    (pkt->pkt_cmd_fhdr.type == EMLXS_MENLO_TYPE)) {
			/* RSP payload */
			bpl =
			    emlxs_pkt_to_bpl(bpl, pkt, BPL_RESP,
			    BUFF_USE_RCV);
			cookie_cnt += resp_cookie_cnt;
		}

		break;

	}

	iocb->un.genreq64.bdl.bdeFlags = BUFF_TYPE_BDL;
	iocb->un.genreq64.bdl.addrHigh = putPaddrHigh(bp);
	iocb->un.genreq64.bdl.addrLow  = putPaddrLow(bp);
	iocb->un.genreq64.bdl.bdeSize  = cookie_cnt * sizeof (ULP_BDE64);

	iocb->ulpBdeCount = 1;
	iocb->ulpLe = 1;

	return (0);

} /* emlxs_sli2_bde_setup */


#ifdef SLI3_SUPPORT
uint32_t
emlxs_sli3_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	ddi_dma_cookie_t *cp_cmd;
	ddi_dma_cookie_t *cp_resp;
	ddi_dma_cookie_t *cp_data;
	fc_packet_t	*pkt;
	ULP_BDE64	*bde;
	int		data_cookie_cnt;
	uint32_t	i;
	IOCB		*iocb;
	RING		*rp;

	rp = sbp->ring;
	iocb = (IOCB *) & sbp->iocbq;
	pkt = PRIV2PKT(sbp);
#if (EMLXS_MODREV >= EMLXS_MODREV3)
	if ((pkt->pkt_cmd_cookie_cnt > 1) ||
	    (pkt->pkt_resp_cookie_cnt > 1) ||
	    ((pkt->pkt_cmd_cookie_cnt + pkt->pkt_resp_cookie_cnt +
	    pkt->pkt_data_cookie_cnt) > SLI3_MAX_BDE)) {
		i = emlxs_sli2_bde_setup(port, sbp);
		return (i);
	}

#endif	/* >= EMLXS_MODREV3 */

#if (EMLXS_MODREV >= EMLXS_MODREV3)
	cp_cmd = pkt->pkt_cmd_cookie;
	cp_resp = pkt->pkt_resp_cookie;
	cp_data = pkt->pkt_data_cookie;
	data_cookie_cnt = pkt->pkt_data_cookie_cnt;
#else
	cp_cmd  = &pkt->pkt_cmd_cookie;
	cp_resp = &pkt->pkt_resp_cookie;
	cp_data = &pkt->pkt_data_cookie;
	data_cookie_cnt = 1;
#endif	/* >= EMLXS_MODREV3 */

	iocb->unsli3.ext_iocb.ebde_count = 0;

	switch (rp->ringno) {
	case FC_FCP_RING:

		/* CMD payload */
		iocb->un.fcpi64.bdl.addrHigh =
		    putPaddrHigh(cp_cmd->dmac_laddress);
		iocb->un.fcpi64.bdl.addrLow =
		    putPaddrLow(cp_cmd->dmac_laddress);
		iocb->un.fcpi64.bdl.bdeSize  = pkt->pkt_cmdlen;
		iocb->un.fcpi64.bdl.bdeFlags = 0;

		if (pkt->pkt_tran_type != FC_PKT_OUTBOUND) {
			/* RSP payload */
			iocb->unsli3.ext_iocb.ebde1.addrHigh =
			    putPaddrHigh(cp_resp->dmac_laddress);
			iocb->unsli3.ext_iocb.ebde1.addrLow =
			    putPaddrLow(cp_resp->dmac_laddress);
			iocb->unsli3.ext_iocb.ebde1.tus.f.bdeSize =
			    pkt->pkt_rsplen;
			iocb->unsli3.ext_iocb.ebde1.tus.f.bdeFlags = 0;
			iocb->unsli3.ext_iocb.ebde_count = 1;

			/* DATA payload */
			if (pkt->pkt_datalen != 0) {
				bde =
				    (ULP_BDE64 *)&iocb->unsli3.ext_iocb.
				    ebde2;
				for (i = 0; i < data_cookie_cnt; i++) {
					bde->addrHigh =
					    putPaddrHigh(cp_data->
					    dmac_laddress);
					bde->addrLow =
					    putPaddrLow(cp_data->
					    dmac_laddress);
					bde->tus.f.bdeSize =
					    cp_data->dmac_size;
					bde->tus.f.bdeFlags = 0;
					cp_data++;
					bde++;
				}
				iocb->unsli3.ext_iocb.ebde_count +=
				    data_cookie_cnt;
			}
		}
		/*
		 * else
		 * {
		 * 	Target mode FCP status. Do nothing more.
		 * }
		 */

		break;

	case FC_IP_RING:

		/* CMD payload */
		iocb->un.xseq64.bdl.addrHigh =
		    putPaddrHigh(cp_cmd->dmac_laddress);
		iocb->un.xseq64.bdl.addrLow =
		    putPaddrLow(cp_cmd->dmac_laddress);
		iocb->un.xseq64.bdl.bdeSize  = pkt->pkt_cmdlen;
		iocb->un.xseq64.bdl.bdeFlags = 0;

		break;

	case FC_ELS_RING:

		/* CMD payload */
		iocb->un.elsreq64.bdl.addrHigh =
		    putPaddrHigh(cp_cmd->dmac_laddress);
		iocb->un.elsreq64.bdl.addrLow =
		    putPaddrLow(cp_cmd->dmac_laddress);
		iocb->un.elsreq64.bdl.bdeSize  = pkt->pkt_cmdlen;
		iocb->un.elsreq64.bdl.bdeFlags = 0;

		/* RSP payload */
		if (pkt->pkt_tran_type != FC_PKT_OUTBOUND) {
			iocb->unsli3.ext_iocb.ebde1.addrHigh =
			    putPaddrHigh(cp_resp->dmac_laddress);
			iocb->unsli3.ext_iocb.ebde1.addrLow =
			    putPaddrLow(cp_resp->dmac_laddress);
			iocb->unsli3.ext_iocb.ebde1.tus.f.bdeSize =
			    pkt->pkt_rsplen;
			iocb->unsli3.ext_iocb.ebde1.tus.f.bdeFlags =
			    BUFF_USE_RCV;
			iocb->unsli3.ext_iocb.ebde_count = 1;
		}

		break;

	case FC_CT_RING:

		/* CMD payload */
		iocb->un.genreq64.bdl.addrHigh =
		    putPaddrHigh(cp_cmd->dmac_laddress);
		iocb->un.genreq64.bdl.addrLow =
		    putPaddrLow(cp_cmd->dmac_laddress);
		iocb->un.genreq64.bdl.bdeSize  = pkt->pkt_cmdlen;
		iocb->un.genreq64.bdl.bdeFlags = 0;

		if ((pkt->pkt_tran_type != FC_PKT_OUTBOUND) ||
		    (pkt->pkt_cmd_fhdr.type == EMLXS_MENLO_TYPE)) {
			/* RSP payload */
			iocb->unsli3.ext_iocb.ebde1.addrHigh =
			    putPaddrHigh(cp_resp->dmac_laddress);
			iocb->unsli3.ext_iocb.ebde1.addrLow =
			    putPaddrLow(cp_resp->dmac_laddress);
			iocb->unsli3.ext_iocb.ebde1.tus.f.bdeSize =
			    pkt->pkt_rsplen;
			iocb->unsli3.ext_iocb.ebde1.tus.f.bdeFlags =
			    BUFF_USE_RCV;
			iocb->unsli3.ext_iocb.ebde_count = 1;
		}

		break;
	}

	iocb->ulpBdeCount = 0;
	iocb->ulpLe = 0;

	return (0);

} /* emlxs_sli3_bde_setup */
#endif	/* SLI3_SUPPORT */


/*ARGSUSED*/
uint32_t
emlxs_sli4_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	return (0);

} /* emlxs_sli4_bde_setup */


/* Only used for FCP Data xfers */
uint32_t
emlxs_sli2_fct_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp)
{
#ifdef SFCT_SUPPORT
	emlxs_hba_t *hba = HBA;
	scsi_task_t *fct_task;
	MATCHMAP *bmp;
	ULP_BDE64 *bpl;
	uint64_t bp;
	uint8_t bdeFlags;
	IOCB *iocb;
	uint32_t resid;
	uint32_t count;
	uint32_t size;
	uint32_t sgllen;
	struct stmf_sglist_ent *sgl;
	emlxs_fct_dmem_bctl_t *bctl;

	iocb = (IOCB *)&sbp->iocbq;
	sbp->bmp = NULL;

	if (!sbp->fct_buf) {
		iocb->un.fcpt64.bdl.addrHigh = 0;
		iocb->un.fcpt64.bdl.addrLow = 0;
		iocb->un.fcpt64.bdl.bdeSize = 0;
		iocb->un.fcpt64.bdl.bdeFlags = 0;
		iocb->un.fcpt64.fcpt_Offset = 0;
		iocb->un.fcpt64.fcpt_Length = 0;
		iocb->ulpBdeCount = 0;
		iocb->ulpLe = 1;
		return (0);
	}
#ifdef EMLXS_SPARC
	/* Use FCP MEM_BPL table to get BPL buffer */
	bmp = &hba->fcp_bpl_table[sbp->iotag];
#else
	/* Use MEM_BPL pool to get BPL buffer */
	bmp = (MATCHMAP *)emlxs_mem_get(hba, MEM_BPL);
#endif /* EMLXS_SPARC */

	if (!bmp) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "emlxs_fct_sli2_bde_setup: Unable to BPL buffer. iotag=%x",
		    sbp->iotag);

		iocb->un.fcpt64.bdl.addrHigh = 0;
		iocb->un.fcpt64.bdl.addrLow = 0;
		iocb->un.fcpt64.bdl.bdeSize = 0;
		iocb->un.fcpt64.bdl.bdeFlags = 0;
		iocb->un.fcpt64.fcpt_Offset = 0;
		iocb->un.fcpt64.fcpt_Length = 0;
		iocb->ulpBdeCount = 0;
		iocb->ulpLe = 1;
		return (1);
	}

	bpl = (ULP_BDE64 *)bmp->virt;
	bp = bmp->phys;

	fct_task = (scsi_task_t *)sbp->fct_cmd->cmd_specific;

	size = sbp->fct_buf->db_data_size;
	count = sbp->fct_buf->db_sglist_length;
	bctl = (emlxs_fct_dmem_bctl_t *)sbp->fct_buf->db_port_private;

	bdeFlags = (fct_task->task_flags & TF_WRITE_DATA) ? BUFF_USE_RCV : 0;
	sgl = sbp->fct_buf->db_sglist;
	resid = size;

	/* Init the buffer list */
	for (sgllen = 0; sgllen < count && resid > 0; sgllen++) {
		bpl->addrHigh =
		    PCIMEM_LONG(putPaddrHigh(bctl->bctl_dev_addr));
		bpl->addrLow =
		    PCIMEM_LONG(putPaddrLow(bctl->bctl_dev_addr));
		bpl->tus.f.bdeSize = MIN(resid, sgl->seg_length);
		bpl->tus.f.bdeFlags = bdeFlags;
		bpl->tus.w = PCIMEM_LONG(bpl->tus.w);
		bpl++;

		resid -= MIN(resid, sgl->seg_length);
		sgl++;
	}

	/* Init the IOCB */
	iocb->un.fcpt64.bdl.addrHigh = putPaddrHigh(bp);
	iocb->un.fcpt64.bdl.addrLow = putPaddrLow(bp);
	iocb->un.fcpt64.bdl.bdeSize = sgllen * sizeof (ULP_BDE64);
	iocb->un.fcpt64.bdl.bdeFlags = BUFF_TYPE_BDL;

	iocb->un.fcpt64.fcpt_Length =
	    (fct_task->task_flags & TF_WRITE_DATA) ? size : 0;
	iocb->un.fcpt64.fcpt_Offset = 0;

	iocb->ulpBdeCount = 1;
	iocb->ulpLe = 1;
	sbp->bmp = bmp;
#endif /* SFCT_SUPPORT */

	return (0);

}  /* emlxs_sli2_fct_bde_setup */



#ifdef SLI3_SUPPORT

/*ARGSUSED*/
uint32_t
emlxs_sli3_fct_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp)
{
#ifdef SFCT_SUPPORT
	scsi_task_t *fct_task;
	ULP_BDE64 *bde;
	IOCB *iocb;
	uint32_t size;
	uint32_t count;
	uint32_t sgllen;
	int32_t resid;
	struct stmf_sglist_ent *sgl;
	uint32_t bdeFlags;
	emlxs_fct_dmem_bctl_t *bctl;

	iocb = (IOCB *)&sbp->iocbq;

	if (!sbp->fct_buf) {
		iocb->un.fcpt64.bdl.addrHigh = 0;
		iocb->un.fcpt64.bdl.addrLow = 0;
		iocb->un.fcpt64.bdl.bdeSize = 0;
		iocb->un.fcpt64.bdl.bdeFlags = 0;
		iocb->un.fcpt64.fcpt_Offset = 0;
		iocb->un.fcpt64.fcpt_Length = 0;
		iocb->ulpBdeCount = 0;
		iocb->ulpLe = 0;
		iocb->unsli3.ext_iocb.ebde_count = 0;
		return (0);
	}

	fct_task = (scsi_task_t *)sbp->fct_cmd->cmd_specific;

	size = sbp->fct_buf->db_data_size;
	count = sbp->fct_buf->db_sglist_length;
	bctl = (emlxs_fct_dmem_bctl_t *)sbp->fct_buf->db_port_private;

	bdeFlags = (fct_task->task_flags & TF_WRITE_DATA) ? BUFF_USE_RCV : 0;
	sgl = sbp->fct_buf->db_sglist;
	resid = size;

	/* Init first BDE */
	iocb->un.fcpt64.bdl.addrHigh = putPaddrHigh(bctl->bctl_dev_addr);
	iocb->un.fcpt64.bdl.addrLow = putPaddrLow(bctl->bctl_dev_addr);
	iocb->un.fcpt64.bdl.bdeSize = MIN(resid, sgl->seg_length);
	iocb->un.fcpt64.bdl.bdeFlags = bdeFlags;
	resid -= MIN(resid, sgl->seg_length);
	sgl++;

	/* Init remaining BDE's */
	bde = (ULP_BDE64 *)&iocb->unsli3.ext_iocb.ebde1;
	for (sgllen = 1; sgllen < count && resid > 0; sgllen++) {
		bde->addrHigh = putPaddrHigh(bctl->bctl_dev_addr);
		bde->addrLow = putPaddrLow(bctl->bctl_dev_addr);
		bde->tus.f.bdeSize = MIN(resid, sgl->seg_length);
		bde->tus.f.bdeFlags = bdeFlags;
		bde++;

		resid -= MIN(resid, sgl->seg_length);
		sgl++;
	}

	iocb->unsli3.ext_iocb.ebde_count = sgllen - 1;
	iocb->un.fcpt64.fcpt_Length =
	    (fct_task->task_flags & TF_WRITE_DATA) ? size : 0;
	iocb->un.fcpt64.fcpt_Offset = 0;

	iocb->ulpBdeCount = 0;
	iocb->ulpLe = 0;
#endif /* SFCT_SUPPORT */

	return (0);

}  /* emlxs_sli3_fct_bde_setup */

#endif /* SLI3_SUPPORT */

/*ARGSUSED*/
uint32_t
emlxs_sli4_fct_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	return (0);

} /* emlxs_sli4_fct_bde_setup */


extern void
emlxs_sli3_issue_iocb_cmd(emlxs_hba_t *hba, RING *rp, IOCBQ *iocbq)
{
#ifdef FMA_SUPPORT
	emlxs_port_t *port = &PPORT;
#endif	/* FMA_SUPPORT */
	PGP *pgp;
	emlxs_buf_t *sbp;
	SLIM2 *slim2p = (SLIM2 *)hba->slim2.virt;
	uint32_t nextIdx;
	uint32_t status;
	void *ioa2;
	off_t offset;
	uint32_t count;
	uint32_t ringno;
	int32_t throttle;

	ringno = rp->ringno;
	throttle = 0;

	/* Check if FCP ring and adapter is not ready */
	if (iocbq && (ringno == FC_FCP_RING) && (hba->state != FC_READY)) {
		if (!(iocbq->flag & IOCB_SPECIAL) || !iocbq->port ||
		    !(((emlxs_port_t *)iocbq->port)->tgt_mode)) {
			emlxs_tx_put(iocbq, 1);
			return;
		}
	}


	/* Attempt to acquire CMD_RING lock */
	if (mutex_tryenter(&EMLXS_CMD_RING_LOCK(ringno)) == 0) {
		/* Queue it for later */
		if (iocbq) {
			if ((hba->io_count[ringno] -
			    hba->ring_tx_count[ringno]) > 10) {
				emlxs_tx_put(iocbq, 1);
				return;
			} else {

				/*
				 * EMLXS_MSGF(EMLXS_CONTEXT,
				 * &emlxs_ring_watchdog_msg,
				 * "%s host=%d port=%d cnt=%d,%d  RACE
				 * CONDITION3 DETECTED.",
				 * emlxs_ring_xlate(ringno),
				 * rp->fc_cmdidx, rp->fc_port_cmdidx,
				 * hba->ring_tx_count[ringno],
				 * hba->io_count[ringno]);
				 */
				mutex_enter(&EMLXS_CMD_RING_LOCK(ringno));
			}
		} else {
			return;
		}
	}
	/* CMD_RING_LOCK acquired */

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

	/* Read adapter's get index */
	pgp = (PGP *)&((SLIM2 *)hba->slim2.virt)->mbx.us.s2.port[ringno];
	offset =
	    (off_t)((uint64_t)((unsigned long)&(pgp->cmdGetInx)) -
	    (uint64_t)((unsigned long)hba->slim2.virt));
	emlxs_mpdata_sync(hba->slim2.dma_handle, offset, 4,
	    DDI_DMA_SYNC_FORKERNEL);
	rp->fc_port_cmdidx = PCIMEM_LONG(pgp->cmdGetInx);

	/* Calculate the next put index */
	nextIdx =
	    (rp->fc_cmdidx + 1 >= rp->fc_numCiocb) ? 0 : rp->fc_cmdidx + 1;

	/* Check if ring is full */
	if (nextIdx == rp->fc_port_cmdidx) {
		/* Try one more time */
		emlxs_mpdata_sync(hba->slim2.dma_handle, offset, 4,
		    DDI_DMA_SYNC_FORKERNEL);
		rp->fc_port_cmdidx = PCIMEM_LONG(pgp->cmdGetInx);

		if (nextIdx == rp->fc_port_cmdidx) {
			/* Queue it for later */
			if (iocbq) {
				emlxs_tx_put(iocbq, 1);
			}

			goto busy;
		}
	}

	/*
	 * We have a command ring slot available
	 * Make sure we have an iocb to send
	 */
	if (iocbq) {
		mutex_enter(&EMLXS_RINGTX_LOCK);

		/* Check if the ring already has iocb's waiting */
		if (rp->nodeq.q_first != NULL) {
			/* Put the current iocbq on the tx queue */
			emlxs_tx_put(iocbq, 0);

			/*
			 * Attempt to replace it with the next iocbq
			 * in the tx queue
			 */
			iocbq = emlxs_tx_get(rp, 0);
		}

		mutex_exit(&EMLXS_RINGTX_LOCK);
	} else {
		/* Try to get the next iocb on the tx queue */
		iocbq = emlxs_tx_get(rp, 1);
	}

sendit:
	count = 0;

	/* Process each iocbq */
	while (iocbq) {

#ifdef NPIV_SUPPORT
		/*
		 */
		sbp = iocbq->sbp;
		if (sbp && (sbp->pkt_flags & PACKET_DELAY_REQUIRED)) {
			/*
			 * Update adapter if needed, since we are about to
			 * delay here
			 */
			if (count) {
				count = 0;

				/* Update the adapter's cmd put index */
				if (hba->bus_type == SBUS_FC) {
					slim2p->mbx.us.s2.host[ringno].
					    cmdPutInx =
					    PCIMEM_LONG(rp->fc_cmdidx);

					/* DMA sync the index for the adapter */
					offset = (off_t)
					    ((uint64_t)
					    ((unsigned long)&(slim2p->
					    mbx.us.s2.host[ringno].cmdPutInx)) -
					    (uint64_t)((unsigned long)slim2p));
					emlxs_mpdata_sync(hba->slim2.
					    dma_handle, offset, 4,
					    DDI_DMA_SYNC_FORDEV);
				} else {
					ioa2 =
					    (void *)((char *)hba->slim_addr +
					    hba->hgp_ring_offset +
					    ((ringno * 2) * sizeof (uint32_t)));
					WRITE_SLIM_ADDR(hba,
					    (volatile uint32_t *)ioa2,
					    rp->fc_cmdidx);
				}

				status = (CA_R0ATT << (ringno * 4));
				WRITE_CSR_REG(hba, FC_CA_REG(hba,
				    hba->csr_addr), (volatile uint32_t)status);

			}

			/* Perform delay */
			if (ringno == FC_ELS_RING) {
				drv_usecwait(100000);
			} else {
				drv_usecwait(20000);
			}
		}
#endif /* NPIV_SUPPORT */

		/*
		 * At this point, we have a command ring slot available
		 * and an iocb to send
		 */

		/* Send the iocb */
		emlxs_issue_iocb(hba, rp, iocbq);

		count++;

		/* Check if HBA is full */
		throttle = hba->io_throttle - hba->io_active;
		if (throttle <= 0) {
			goto busy;
		}

		/* Calculate the next put index */
		nextIdx =
		    (rp->fc_cmdidx + 1 >=
		    rp->fc_numCiocb) ? 0 : rp->fc_cmdidx + 1;

		/* Check if ring is full */
		if (nextIdx == rp->fc_port_cmdidx) {
			/* Try one more time */
			emlxs_mpdata_sync(hba->slim2.dma_handle, offset, 4,
			    DDI_DMA_SYNC_FORKERNEL);
			rp->fc_port_cmdidx = PCIMEM_LONG(pgp->cmdGetInx);

			if (nextIdx == rp->fc_port_cmdidx) {
				goto busy;
			}
		}

		/* Get the next iocb from the tx queue if there is one */
		iocbq = emlxs_tx_get(rp, 1);
	}

	if (count) {
		/* Update the adapter's cmd put index */
		if (hba->bus_type == SBUS_FC) {
			slim2p->mbx.us.s2.host[ringno].
			    cmdPutInx = PCIMEM_LONG(rp->fc_cmdidx);

			/* DMA sync the index for the adapter */
			offset = (off_t)
			    ((uint64_t)((unsigned long)&(slim2p->mbx.us.s2.
			    host[ringno].cmdPutInx)) -
			    (uint64_t)((unsigned long)slim2p));
			emlxs_mpdata_sync(hba->slim2.dma_handle, offset, 4,
			    DDI_DMA_SYNC_FORDEV);
		} else {
			ioa2 =
			    (void *)((char *)hba->slim_addr +
			    hba->hgp_ring_offset +
			    ((ringno * 2) * sizeof (uint32_t)));
			WRITE_SLIM_ADDR(hba, (volatile uint32_t *)ioa2,
			    rp->fc_cmdidx);
		}

		status = (CA_R0ATT << (ringno * 4));
		WRITE_CSR_REG(hba, FC_CA_REG(hba, hba->csr_addr),
		    (volatile uint32_t)status);

		/* Check tx queue one more time before releasing */
		if ((iocbq = emlxs_tx_get(rp, 1))) {
			/*
			 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ring_watchdog_msg,
			 * "%s host=%d port=%d   RACE CONDITION1
			 * DETECTED.", emlxs_ring_xlate(ringno),
			 * rp->fc_cmdidx, rp->fc_port_cmdidx);
			 */
			goto sendit;
		}
	}

	mutex_exit(&EMLXS_CMD_RING_LOCK(ringno));

	return;

busy:

	/*
	 * Set ring to SET R0CE_REQ in Chip Att register.
	 * Chip will tell us when an entry is freed.
	 */
	if (count) {
		/* Update the adapter's cmd put index */
		if (hba->bus_type == SBUS_FC) {
			slim2p->mbx.us.s2.host[ringno].cmdPutInx =
			    PCIMEM_LONG(rp->fc_cmdidx);

			/* DMA sync the index for the adapter */
			offset = (off_t)
			    ((uint64_t)((unsigned long)&(slim2p->mbx.us.s2.
			    host[ringno].cmdPutInx)) -
			    (uint64_t)((unsigned long)slim2p));
			emlxs_mpdata_sync(hba->slim2.dma_handle, offset, 4,
			    DDI_DMA_SYNC_FORDEV);
		} else {
			ioa2 =
			    (void *)((char *)hba->slim_addr +
			    hba->hgp_ring_offset +
			    ((ringno * 2) * sizeof (uint32_t)));
			WRITE_SLIM_ADDR(hba, (volatile uint32_t *)ioa2,
			    rp->fc_cmdidx);
		}
	}

	status = ((CA_R0ATT | CA_R0CE_REQ) << (ringno * 4));
	WRITE_CSR_REG(hba, FC_CA_REG(hba, hba->csr_addr),
	    (volatile uint32_t)status);

	if (throttle <= 0) {
		HBASTATS.IocbThrottled++;
	} else {
		HBASTATS.IocbRingFull[ringno]++;
	}

	mutex_exit(&EMLXS_CMD_RING_LOCK(ringno));

	return;

}  /* emlxs_sli3_issue_iocb_cmd() */


/*ARGSUSED*/
extern void
emlxs_sli4_issue_iocb_cmd(emlxs_hba_t *hba, RING *rp, IOCBQ *iocbq)
{
	return;

}  /* emlxs_sli4_issue_iocb_cmd() */


/* MBX_NOWAIT - returns MBX_BUSY or MBX_SUCCESS or MBX_HARDWARE_ERROR */
/* MBX_WAIT   - returns MBX_TIMEOUT or mailbox_status */
/* MBX_SLEEP  - returns MBX_TIMEOUT or mailbox_status */
/* MBX_POLL   - returns MBX_TIMEOUT or mailbox_status */

extern uint32_t
emlxs_sli3_issue_mbox_cmd(emlxs_hba_t *hba, MAILBOX *mb, int32_t flag,
    uint32_t tmo)
{
	emlxs_port_t		*port = &PPORT;
	SLIM2			*slim2p = (SLIM2 *)hba->slim2.virt;
	MAILBOX			*mbox;
	MAILBOXQ		*mbq;
	volatile uint32_t	word0;
	volatile uint32_t	ldata;
	uint32_t		ha_copy;
	off_t			offset;
	MATCHMAP		*mbox_bp;
	uint32_t		tmo_local;
	MAILBOX			*swpmb;

	mbq = (MAILBOXQ *)mb;
	swpmb = (MAILBOX *)&word0;

	mb->mbxStatus = MBX_SUCCESS;

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
		if (tmo < 300) {
			tmo = 300;
		}
		break;

	default:
		if (tmo < 30) {
			tmo = 30;
		}
		break;
	}

	/* Adjust wait flag */
	if (flag != MBX_NOWAIT) {
		/* If interrupt is enabled, use sleep, otherwise poll */
		if (hba->hc_copy & HC_MBINT_ENA) {
			flag = MBX_SLEEP;
		} else {
			flag = MBX_POLL;
		}
	}

	mutex_enter(&EMLXS_PORT_LOCK);

	/* Check for hardware error */
	if (hba->flag & FC_HARDWARE_ERROR) {
		mb->mbxStatus = (hba-> flag & FC_OVERTEMP_EVENT) ?
		    MBX_OVERTEMP_ERROR : MBX_HARDWARE_ERROR;

		mutex_exit(&EMLXS_PORT_LOCK);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
		    "Hardware error reported. %s failed. status=%x mb=%p",
		    emlxs_mb_cmd_xlate(mb->mbxCommand),  mb->mbxStatus, mb);

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

		/* Convert tmo seconds to 50 millisecond tics */
		tmo_local = tmo * 20;
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

			DELAYMS(50);
			mutex_enter(&EMLXS_PORT_LOCK);
		}
	}

	/* Initialize mailbox area */
	emlxs_mb_init(hba, mbq, flag, tmo);

	switch (flag) {
	case MBX_NOWAIT:

		if (mb->mbxCommand != MBX_HEARTBEAT) {
			if (mb->mbxCommand != MBX_DOWN_LOAD &&
			    mb->mbxCommand != MBX_DUMP_MEMORY) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_mbox_detail_msg,
				    "Sending.   %s: mb=%p NoWait.",
				    emlxs_mb_cmd_xlate(mb->mbxCommand), mb);
			}
		}

		break;

	case MBX_SLEEP:
		if (mb->mbxCommand != MBX_DOWN_LOAD &&
		    mb->mbxCommand != MBX_DUMP_MEMORY) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
			    "Sending.   %s: mb=%p Sleep.",
			    emlxs_mb_cmd_xlate(mb->mbxCommand), mb);
		}

		break;

	case MBX_POLL:
		if (mb->mbxCommand != MBX_DOWN_LOAD &&
		    mb->mbxCommand != MBX_DUMP_MEMORY) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
			    "Sending.   %s: mb=%p Polled.",
			    emlxs_mb_cmd_xlate(mb->mbxCommand), mb);
		}
		break;
	}

	mb->mbxOwner = OWN_CHIP;

	/* Clear the attention bit */
	WRITE_CSR_REG(hba, FC_HA_REG(hba, hba->csr_addr), HA_MBATT);

	if (hba->flag & FC_SLIM2_MODE) {
		/* First copy command data */
		mbox = FC_SLIM2_MAILBOX(hba);
		offset =
		    (off_t)((uint64_t)((unsigned long)mbox)
		    - (uint64_t)((unsigned long)slim2p));

#ifdef MBOX_EXT_SUPPORT
		if (hba->mbox_ext) {
			uint32_t *mbox_ext =
			    (uint32_t *)((uint8_t *)mbox +
			    MBOX_EXTENSION_OFFSET);
			off_t offset_ext   = offset + MBOX_EXTENSION_OFFSET;

			emlxs_pcimem_bcopy((uint32_t *)hba->mbox_ext,
			    mbox_ext, hba->mbox_ext_size);
			emlxs_mpdata_sync(hba->slim2.dma_handle, offset_ext,
			    hba->mbox_ext_size, DDI_DMA_SYNC_FORDEV);
		}
#endif /* MBOX_EXT_SUPPORT */

		emlxs_pcimem_bcopy((uint32_t *)mb, (uint32_t *)mbox,
		    MAILBOX_CMD_BSIZE);
		emlxs_mpdata_sync(hba->slim2.dma_handle, offset,
		    MAILBOX_CMD_BSIZE, DDI_DMA_SYNC_FORDEV);
	}
	/* Check for config port command */
	else if (mb->mbxCommand == MBX_CONFIG_PORT) {
		/* copy command data into host mbox for cmpl */
		mbox = FC_SLIM2_MAILBOX(hba);
		offset = (off_t)((uint64_t)((unsigned long)mbox)
		    - (uint64_t)((unsigned long)slim2p));

		emlxs_pcimem_bcopy((uint32_t *)mb, (uint32_t *)mbox,
		    MAILBOX_CMD_BSIZE);
		emlxs_mpdata_sync(hba->slim2.dma_handle, offset,
		    MAILBOX_CMD_BSIZE, DDI_DMA_SYNC_FORDEV);

		/* First copy command data */
		mbox = FC_SLIM1_MAILBOX(hba);
		WRITE_SLIM_COPY(hba, &mb->un.varWords, &mbox->un.varWords,
		    (MAILBOX_CMD_WSIZE - 1));

		/* copy over last word, with mbxOwner set */
		ldata = *((volatile uint32_t *)mb);
		WRITE_SLIM_ADDR(hba, ((volatile uint32_t *)mbox), ldata);

		/* switch over to host mailbox */
		hba->flag |= FC_SLIM2_MODE;
	} else {	/* SLIM 1 */

		mbox = FC_SLIM1_MAILBOX(hba);

#ifdef MBOX_EXT_SUPPORT
		if (hba->mbox_ext) {
			uint32_t *mbox_ext =
			    (uint32_t *)((uint8_t *)mbox +
			    MBOX_EXTENSION_OFFSET);
			WRITE_SLIM_COPY(hba, (uint32_t *)hba->mbox_ext,
			    mbox_ext, (hba->mbox_ext_size / 4));
		}
#endif /* MBOX_EXT_SUPPORT */

		/* First copy command data */
		WRITE_SLIM_COPY(hba, &mb->un.varWords, &mbox->un.varWords,
		    (MAILBOX_CMD_WSIZE - 1));

		/* copy over last word, with mbxOwner set */
		ldata = *((volatile uint32_t *)mb);
		WRITE_SLIM_ADDR(hba, ((volatile uint32_t *)mbox), ldata);
	}

	/* Interrupt board to do it right away */
	WRITE_CSR_REG(hba, FC_CA_REG(hba, hba->csr_addr), CA_MBATT);

	mutex_exit(&EMLXS_PORT_LOCK);

	switch (flag) {
	case MBX_NOWAIT:
		return (MBX_SUCCESS);

	case MBX_SLEEP:

		/* Wait for completion */
		/* The driver clock is timing the mailbox. */
		/* emlxs_mb_fini() will be called externally. */

		mutex_enter(&EMLXS_MBOX_LOCK);
		while (!(mbq->flag & MBQ_COMPLETED)) {
			cv_wait(&EMLXS_MBOX_CV, &EMLXS_MBOX_LOCK);
		}
		mutex_exit(&EMLXS_MBOX_LOCK);

		if (mb->mbxStatus == MBX_TIMEOUT) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_event_msg,
			    "Timeout.   %s: mb=%p tmo=%d. Sleep.",
			    emlxs_mb_cmd_xlate(mb->mbxCommand), mb, tmo);
		} else {
			if (mb->mbxCommand != MBX_DOWN_LOAD &&
			    mb->mbxCommand != MBX_DUMP_MEMORY) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_mbox_detail_msg,
				    "Completed. %s: mb=%p status=%x Sleep.",
				    emlxs_mb_cmd_xlate(mb->mbxCommand), mb,
				    mb->mbxStatus);
			}
		}

		break;

	case MBX_POLL:

		/* Convert tmo seconds to 500 usec tics */
		tmo_local = tmo * 2000;

		if (hba->state >= FC_INIT_START) {
			ha_copy =
			    READ_CSR_REG(hba, FC_HA_REG(hba, hba->csr_addr));

			/* Wait for command to complete */
			while (!(ha_copy & HA_MBATT) &&
			    !(mbq->flag & MBQ_COMPLETED)) {
				if (!hba->timer_id && (tmo_local-- == 0)) {
					/* self time */
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_mbox_timeout_msg,
					    "%s: mb=%p Polled.",
					    emlxs_mb_cmd_xlate(mb->
					    mbxCommand), mb);

					hba->flag |= FC_MBOX_TIMEOUT;
					emlxs_ffstate_change(hba, FC_ERROR);
					emlxs_mb_fini(hba, NULL, MBX_TIMEOUT);

					break;
				}

				DELAYUS(500);
				ha_copy = READ_CSR_REG(hba, FC_HA_REG(hba,
				    hba->csr_addr));
			}

			if (mb->mbxStatus == MBX_TIMEOUT) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_mbox_event_msg,
				    "Timeout.   %s: mb=%p tmo=%d. Polled.",
				    emlxs_mb_cmd_xlate(mb->mbxCommand), mb,
				    tmo);

				break;
			}
		}

		/* Get first word of mailbox */
		if (hba->flag & FC_SLIM2_MODE) {
			mbox = FC_SLIM2_MAILBOX(hba);
			offset = (off_t)((uint64_t)((unsigned long)mbox) -
			    (uint64_t)((unsigned long)slim2p));

			emlxs_mpdata_sync(hba->slim2.dma_handle, offset,
			    sizeof (uint32_t), DDI_DMA_SYNC_FORKERNEL);
			word0 = *((volatile uint32_t *)mbox);
			word0 = PCIMEM_LONG(word0);
		} else {
			mbox = FC_SLIM1_MAILBOX(hba);
			word0 =
			    READ_SLIM_ADDR(hba, ((volatile uint32_t *)mbox));
		}

		/* Wait for command to complete */
		while ((swpmb->mbxOwner == OWN_CHIP) &&
		    !(mbq->flag & MBQ_COMPLETED)) {
			if (!hba->timer_id && (tmo_local-- == 0)) {
				/* self time */
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_mbox_timeout_msg,
				    "%s: mb=%p Polled.",
				    emlxs_mb_cmd_xlate(mb->mbxCommand), mb);

				hba->flag |= FC_MBOX_TIMEOUT;
				emlxs_ffstate_change(hba, FC_ERROR);
				emlxs_mb_fini(hba, NULL, MBX_TIMEOUT);

				break;
			}

			DELAYUS(500);

			/* Get first word of mailbox */
			if (hba->flag & FC_SLIM2_MODE) {
				emlxs_mpdata_sync(hba->slim2.dma_handle,
				    offset, sizeof (uint32_t),
				    DDI_DMA_SYNC_FORKERNEL);
				word0 = *((volatile uint32_t *)mbox);
				word0 = PCIMEM_LONG(word0);
			} else {
				word0 =
				    READ_SLIM_ADDR(hba,
				    ((volatile uint32_t *)mbox));
			}

		}	/* while */

		if (mb->mbxStatus == MBX_TIMEOUT) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_event_msg,
			    "Timeout.   %s: mb=%p tmo=%d. Polled.",
			    emlxs_mb_cmd_xlate(mb->mbxCommand), mb, tmo);

			break;
		}

		/* copy results back to user */
		if (hba->flag & FC_SLIM2_MODE) {
			emlxs_mpdata_sync(hba->slim2.dma_handle, offset,
			    MAILBOX_CMD_BSIZE, DDI_DMA_SYNC_FORKERNEL);
			emlxs_pcimem_bcopy((uint32_t *)mbox, (uint32_t *)mb,
			    MAILBOX_CMD_BSIZE);
		} else {
			READ_SLIM_COPY(hba, (uint32_t *)mb,
			    (uint32_t *)mbox, MAILBOX_CMD_WSIZE);
		}

#ifdef MBOX_EXT_SUPPORT
		if (hba->mbox_ext) {
			uint32_t *mbox_ext =
			    (uint32_t *)((uint8_t *)mbox +
			    MBOX_EXTENSION_OFFSET);
			off_t offset_ext   = offset + MBOX_EXTENSION_OFFSET;

			if (hba->flag & FC_SLIM2_MODE) {
				emlxs_mpdata_sync(hba->slim2.dma_handle,
				    offset_ext, hba->mbox_ext_size,
				    DDI_DMA_SYNC_FORKERNEL);
				emlxs_pcimem_bcopy(mbox_ext,
				    (uint32_t *)hba->mbox_ext,
				    hba->mbox_ext_size);
			} else {
				READ_SLIM_COPY(hba,
				    (uint32_t *)hba->mbox_ext, mbox_ext,
				    (hba->mbox_ext_size / 4));
			}
			}
#endif /* MBOX_EXT_SUPPORT */

		/* Sync the memory buffer */
		if (hba->mbox_bp) {
			mbox_bp = (MATCHMAP *)hba->mbox_bp;
			emlxs_mpdata_sync(mbox_bp->dma_handle, 0,
			    mbox_bp->size, DDI_DMA_SYNC_FORKERNEL);
		}

		if (mb->mbxCommand != MBX_DOWN_LOAD &&
		    mb->mbxCommand != MBX_DUMP_MEMORY) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
			    "Completed. %s: mb=%p status=%x Polled.",
			    emlxs_mb_cmd_xlate(mb->mbxCommand), mb,
			    mb->mbxStatus);
		}

		/* Process the result */
		if (!(mbq->flag & MBQ_PASSTHRU)) {
			(void) emlxs_mb_handle_cmd(hba, mb);
		}

		/* Clear the attention bit */
		WRITE_CSR_REG(hba, FC_HA_REG(hba, hba->csr_addr), HA_MBATT);

		/* Clean up the mailbox area */
		emlxs_mb_fini(hba, NULL, mb->mbxStatus);

		break;

	}	/* switch (flag) */

	return (mb->mbxStatus);

} /* emlxs_sli3_issue_mbox_cmd() */

/*ARGSUSED*/
extern uint32_t
emlxs_sli4_issue_mbox_cmd(emlxs_hba_t *hba, MAILBOX *mb, int32_t flag,
    uint32_t tmo)
{
	return (0);

} /* emlxs_sli4_issue_mbox_cmd() */


#ifdef SFCT_SUPPORT
extern uint32_t
emlxs_sli3_prep_fct_iocb(emlxs_port_t *port, emlxs_buf_t *cmd_sbp)
{
	emlxs_hba_t *hba = HBA;
	emlxs_config_t *cfg = &CFG;
	fct_cmd_t *fct_cmd;
	stmf_data_buf_t *dbuf;
	scsi_task_t *fct_task;
	uint32_t did;
	IOCBQ *iocbq;
	IOCB *iocb;
	uint32_t timeout;
	uint32_t iotag;
	emlxs_node_t *ndlp;

	dbuf = cmd_sbp->fct_buf;
	fct_cmd = cmd_sbp->fct_cmd;
	fct_task = (scsi_task_t *)fct_cmd->cmd_specific;
	ndlp = *(emlxs_node_t **)fct_cmd->cmd_rp->rp_fca_private;
	did = fct_cmd->cmd_rportid;

	iocbq = &cmd_sbp->iocbq;
	iocb = &iocbq->iocb;

	if (cfg[CFG_TIMEOUT_ENABLE].current) {
		timeout =
		    ((2 * hba->fc_ratov) < 60) ? 60 : (2 * hba->fc_ratov);
	} else {
		timeout = 0x80000000;
	}

#ifdef FCT_API_TRACE
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_api_msg,
	    "emlxs_fct_send_fcp_data %p: flgs=%x ioflags=%x dl=%d,%d,%d",
	    fct_cmd, dbuf->db_flags, ioflags, fct_task->task_cmd_xfer_length,
	    fct_task->task_nbytes_transferred, dbuf->db_data_size);
#endif /* FCT_API_TRACE */

	/* Get the iotag by registering the packet */
	iotag = emlxs_register_pkt(cmd_sbp->ring, cmd_sbp);

	if (!iotag) {
		/* No more command slots available, retry later */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to allocate iotag. did=0x%x", did);

		return (IOERR_NO_RESOURCES);
	}

	cmd_sbp->ticks =
	    hba->timer_tics + timeout + ((timeout > 0xff) ? 0 : 10);

	/* Initalize iocbq */
	iocbq->port = (void *)port;
	iocbq->node = (void *)ndlp;
	iocbq->ring = (void *)cmd_sbp->ring;


	if (emlxs_fct_bde_setup(port, cmd_sbp)) {
		/* Unregister the packet */
		(void) emlxs_unregister_pkt(cmd_sbp->ring, iotag, 0);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to setup buffer list. did=%x", did);

		return (IOERR_INTERNAL_ERROR);
	}
	/* Point of no return */

	/* Initalize iocb */
	iocb->ulpContext = (uint16_t)fct_cmd->cmd_rxid;
	iocb->ulpIoTag = iotag;
	iocb->ulpRsvdByte = ((timeout > 0xff) ? 0 : timeout);
	iocb->ulpOwner = OWN_CHIP;
	iocb->ulpClass = cmd_sbp->class;

	iocb->ulpPU = 1;	/* Wd4 is relative offset */
	iocb->un.fcpt64.fcpt_Offset = dbuf->db_relative_offset;

	if (fct_task->task_flags & TF_WRITE_DATA) {
		iocb->ulpCommand = CMD_FCP_TRECEIVE64_CX;
	} else {	/* TF_READ_DATA */

		iocb->ulpCommand = CMD_FCP_TSEND64_CX;
	}

	return (IOERR_SUCCESS);

}  /* emlxs_sli3_prep_fct_iocb() */


/*ARGSUSED*/
extern uint32_t
emlxs_sli4_prep_fct_iocb(emlxs_port_t *port, emlxs_buf_t *cmd_sbp)
{
	return (FCT_SUCCESS);

}  /* emlxs_sli4_prep_fct_iocb() */
#endif /* SFCT_SUPPORT */


extern uint32_t
emlxs_sli3_prep_fcp_iocb(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	RING *rp;
	IOCBQ *iocbq;
	IOCB *iocb;
	NODELIST *ndlp;
	uint16_t iotag;
	uint32_t did;

	pkt = PRIV2PKT(sbp);
	did = SWAP_DATA24_LO(pkt->pkt_cmd_fhdr.d_id);
	rp = &hba->ring[FC_FCP_RING];

	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;

	/* Find target node object */
	ndlp = (NODELIST *)iocbq->node;

	/* Get the iotag by registering the packet */
	iotag = emlxs_register_pkt(rp, sbp);

	if (!iotag) {
		/*
		 * No more command slots available, retry later
		 */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to allocate iotag: did=0x%x", did);

		return (FC_TRAN_BUSY);
	}

	/* Initalize iocbq */
	iocbq->port = (void *) port;
	iocbq->ring = (void *) rp;

	if (emlxs_bde_setup(port, sbp)) {
		/* Unregister the packet */
		(void) emlxs_unregister_pkt(rp, iotag, 0);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to setup buffer list. did=%x", did);

		return (FC_TRAN_BUSY);
	}
	/* Point of no return */

	/* Initalize iocb */
	iocb->ulpContext = ndlp->nlp_Rpi;
	iocb->ulpIoTag = iotag;
	iocb->ulpRsvdByte =
	    ((pkt->pkt_timeout > 0xff) ? 0 : pkt->pkt_timeout);
	iocb->ulpOwner = OWN_CHIP;

	switch (FC_TRAN_CLASS(pkt->pkt_tran_flags)) {
	case FC_TRAN_CLASS1:
		iocb->ulpClass = CLASS1;
		break;
	case FC_TRAN_CLASS2:
		iocb->ulpClass = CLASS2;
		/* iocb->ulpClass = CLASS3; */
		break;
	case FC_TRAN_CLASS3:
	default:
		iocb->ulpClass = CLASS3;
		break;
	}

	/* if device is FCP-2 device, set the following bit */
	/* that says to run the FC-TAPE protocol. */
	if (ndlp->nlp_fcp_info & NLP_FCP_2_DEVICE) {
		iocb->ulpFCP2Rcvy = 1;
	}

	if (pkt->pkt_datalen == 0) {
		iocb->ulpCommand = CMD_FCP_ICMND64_CR;
	} else if (pkt->pkt_tran_type == FC_PKT_FCP_READ) {
		iocb->ulpCommand = CMD_FCP_IREAD64_CR;
		iocb->ulpPU = PARM_READ_CHECK;
		iocb->un.fcpi64.fcpi_parm = pkt->pkt_datalen;
	} else {
		iocb->ulpCommand = CMD_FCP_IWRITE64_CR;
	}

	return (FC_SUCCESS);

} /* emlxs_sli3_prep_fcp_iocb() */


/*ARGSUSED*/
extern uint32_t
emlxs_sli4_prep_fcp_iocb(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	return (FC_SUCCESS);

} /* emlxs_sli4_prep_fcp_iocb() */


extern uint32_t
emlxs_sli3_prep_ip_iocb(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	IOCBQ *iocbq;
	IOCB *iocb;
	RING *rp;
	NODELIST *ndlp;
	uint16_t iotag;
	uint32_t did;

	pkt = PRIV2PKT(sbp);
	rp = &hba->ring[FC_IP_RING];
	did = SWAP_DATA24_LO(pkt->pkt_cmd_fhdr.d_id);

	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;
	ndlp = (NODELIST *)iocbq->node;

	/* Get the iotag by registering the packet */
	iotag = emlxs_register_pkt(rp, sbp);

	if (!iotag) {
		/*
		 * No more command slots available, retry later
		 */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to allocate iotag: did=0x%x", did);

		return (FC_TRAN_BUSY);
	}

	/* Initalize iocbq */
	iocbq->port = (void *) port;
	iocbq->ring = (void *) rp;

	if (emlxs_bde_setup(port, sbp)) {
		/* Unregister the packet */
		(void) emlxs_unregister_pkt(rp, iotag, 0);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to setup buffer list. did=%x", did);

		return (FC_TRAN_BUSY);
	}
	/* Point of no return */

	/* Initalize iocb */
	iocb->un.xseq64.w5.hcsw.Fctl = 0;

	if (pkt->pkt_cmd_fhdr.f_ctl & F_CTL_FIRST_SEQ) {
		iocb->un.xseq64.w5.hcsw.Fctl |= FSEQ;
	}
	if (pkt->pkt_cmd_fhdr.f_ctl & F_CTL_SEQ_INITIATIVE) {
		iocb->un.xseq64.w5.hcsw.Fctl |= SI;
	}

	/* network headers */
	iocb->un.xseq64.w5.hcsw.Dfctl = pkt->pkt_cmd_fhdr.df_ctl;
	iocb->un.xseq64.w5.hcsw.Rctl = pkt->pkt_cmd_fhdr.r_ctl;
	iocb->un.xseq64.w5.hcsw.Type = pkt->pkt_cmd_fhdr.type;

	iocb->ulpIoTag = iotag;
	iocb->ulpRsvdByte =
	    ((pkt->pkt_timeout > 0xff) ? 0 : pkt->pkt_timeout);
	iocb->ulpOwner = OWN_CHIP;

	if (pkt->pkt_tran_type == FC_PKT_BROADCAST) {
		HBASTATS.IpBcastIssued++;

		iocb->ulpCommand = CMD_XMIT_BCAST64_CN;
		iocb->ulpContext = 0;

#ifdef SLI3_SUPPORT
		if (hba->sli_mode >= 3) {
			if (hba->topology != TOPOLOGY_LOOP) {
				iocb->ulpCT = 0x1;
			}
			iocb->ulpContext = port->vpi;
		}
#endif	/* SLI3_SUPPORT */

	} else {
		HBASTATS.IpSeqIssued++;

		iocb->ulpCommand = CMD_XMIT_SEQUENCE64_CX;
		iocb->ulpContext = ndlp->nlp_Xri;
	}

	switch (FC_TRAN_CLASS(pkt->pkt_tran_flags)) {
	case FC_TRAN_CLASS1:
		iocb->ulpClass = CLASS1;
		break;
	case FC_TRAN_CLASS2:
		iocb->ulpClass = CLASS2;
		break;
	case FC_TRAN_CLASS3:
	default:
		iocb->ulpClass = CLASS3;
		break;
	}

	return (FC_SUCCESS);

} /* emlxs_sli3_prep_ip_iocb() */


/*ARGSUSED*/
extern uint32_t
emlxs_sli4_prep_ip_iocb(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	return (FC_SUCCESS);

} /* emlxs_sli4_prep_ip_iocb() */


extern uint32_t
emlxs_sli3_prep_els_iocb(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	IOCBQ *iocbq;
	IOCB *iocb;
	RING *rp;
	uint16_t iotag;
	uint32_t did;
	uint32_t cmd;

	pkt = PRIV2PKT(sbp);
	rp = &hba->ring[FC_ELS_RING];
	did = SWAP_DATA24_LO(pkt->pkt_cmd_fhdr.d_id);

	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;


	/* Get the iotag by registering the packet */
	iotag = emlxs_register_pkt(rp, sbp);

	if (!iotag) {
		/*
		 * No more command slots available, retry later
		 */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to allocate iotag. did=0x%x", did);

		return (FC_TRAN_BUSY);
	}
	/* Initalize iocbq */
	iocbq->port = (void *) port;
	iocbq->ring = (void *) rp;

	if (emlxs_bde_setup(port, sbp)) {
		/* Unregister the packet */
		(void) emlxs_unregister_pkt(rp, iotag, 0);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to setup buffer list. did=%x", did);

		return (FC_TRAN_BUSY);
	}
	/* Point of no return */

	/* Initalize iocb */
	if (pkt->pkt_tran_type == FC_PKT_OUTBOUND) {
		/* ELS Response */
		iocb->ulpContext = (volatile uint16_t) pkt->pkt_cmd_fhdr.rx_id;
		iocb->ulpCommand = CMD_XMIT_ELS_RSP64_CX;
	} else {
		/* ELS Request */
		iocb->un.elsreq64.remoteID = (did == Bcast_DID) ? 0 : did;
		iocb->ulpContext =
		    (did == Bcast_DID) ? pkt->pkt_cmd_fhdr.seq_id : 0;
		iocb->ulpCommand = CMD_ELS_REQUEST64_CR;

		if (hba->topology != TOPOLOGY_LOOP) {
			cmd = *((uint32_t *)pkt->pkt_cmd);
			cmd &= ELS_CMD_MASK;

			if ((cmd == ELS_CMD_FLOGI) || (cmd == ELS_CMD_FDISC)) {
				iocb->ulpCT = 0x2;
			} else {
				iocb->ulpCT = 0x1;
			}
		}
		iocb->ulpContext = port->vpi;
	}
	iocb->ulpIoTag = iotag;
	iocb->ulpRsvdByte =
	    ((pkt->pkt_timeout > 0xff) ? 0 : pkt->pkt_timeout);
	iocb->ulpOwner = OWN_CHIP;

	switch (FC_TRAN_CLASS(pkt->pkt_tran_flags)) {
	case FC_TRAN_CLASS1:
		iocb->ulpClass = CLASS1;
		break;
	case FC_TRAN_CLASS2:
		iocb->ulpClass = CLASS2;
		break;
	case FC_TRAN_CLASS3:
	default:
		iocb->ulpClass = CLASS3;
		break;
	}

	return (FC_SUCCESS);

} /* emlxs_sli3_prep_els_iocb() */


/*ARGSUSED*/
extern uint32_t
emlxs_sli4_prep_els_iocb(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	return (FC_SUCCESS);

} /* emlxs_sli4_prep_els_iocb() */


extern uint32_t
emlxs_sli3_prep_ct_iocb(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	IOCBQ *iocbq;
	IOCB *iocb;
	RING *rp;
	NODELIST *ndlp;
	uint16_t iotag;
	uint32_t did;

	pkt = PRIV2PKT(sbp);
	did = SWAP_DATA24_LO(pkt->pkt_cmd_fhdr.d_id);
	rp = &hba->ring[FC_CT_RING];

	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;
	ndlp = (NODELIST *)iocbq->node;


	/* Get the iotag by registering the packet */
	iotag = emlxs_register_pkt(rp, sbp);

	if (!iotag) {
		/*
		 * No more command slots available, retry later
		 */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to allocate iotag. did=0x%x", did);

		return (FC_TRAN_BUSY);
	}

	if (emlxs_bde_setup(port, sbp)) {
		/* Unregister the packet */
		(void) emlxs_unregister_pkt(rp, iotag, 0);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to setup buffer list. did=%x", did);

		return (FC_TRAN_BUSY);
	}

	/* Point of no return */

	/* Initalize iocbq */
	iocbq->port = (void *) port;
	iocbq->ring = (void *) rp;

	/* Fill in rest of iocb */
	iocb->un.genreq64.w5.hcsw.Fctl = LA;

	if (pkt->pkt_cmd_fhdr.f_ctl & F_CTL_LAST_SEQ) {
		iocb->un.genreq64.w5.hcsw.Fctl |= LSEQ;
	}
	if (pkt->pkt_cmd_fhdr.f_ctl & F_CTL_SEQ_INITIATIVE) {
		iocb->un.genreq64.w5.hcsw.Fctl |= SI;
	}

	/* Initalize iocb */
	if (pkt->pkt_tran_type == FC_PKT_OUTBOUND) {
		/* CT Response */
		iocb->ulpCommand = CMD_XMIT_SEQUENCE64_CX;
		iocb->un.genreq64.w5.hcsw.Dfctl  = pkt->pkt_cmd_fhdr.df_ctl;
		iocb->ulpContext  = pkt->pkt_cmd_fhdr.rx_id;
	} else {
		/* CT Request */
		iocb->ulpCommand  = CMD_GEN_REQUEST64_CR;
		iocb->un.genreq64.w5.hcsw.Dfctl = 0;
		iocb->ulpContext  = ndlp->nlp_Rpi;
	}

	iocb->un.genreq64.w5.hcsw.Rctl  = pkt->pkt_cmd_fhdr.r_ctl;
	iocb->un.genreq64.w5.hcsw.Type  = pkt->pkt_cmd_fhdr.type;

	iocb->ulpIoTag    = iotag;
	iocb->ulpRsvdByte =
	    ((pkt->pkt_timeout > 0xff) ? 0 : pkt->pkt_timeout);
	iocb->ulpOwner    = OWN_CHIP;

	switch (FC_TRAN_CLASS(pkt->pkt_tran_flags)) {
	case FC_TRAN_CLASS1:
		iocb->ulpClass = CLASS1;
		break;
	case FC_TRAN_CLASS2:
		iocb->ulpClass = CLASS2;
		break;
	case FC_TRAN_CLASS3:
	default:
		iocb->ulpClass = CLASS3;
		break;
	}

	return (FC_SUCCESS);

} /* emlxs_sli3_prep_ct_iocb() */


/*ARGSUSED*/
extern uint32_t
emlxs_sli4_prep_ct_iocb(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	return (FC_SUCCESS);

} /* emlxs_sli4_prep_ct_iocb() */


#ifdef SFCT_SUPPORT
static uint32_t
emlxs_fct_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	uint32_t sgllen = 1;
	uint32_t rval;
	uint32_t size;
	uint32_t count;
	uint32_t resid;
	struct stmf_sglist_ent *sgl;

	size = sbp->fct_buf->db_data_size;
	count = sbp->fct_buf->db_sglist_length;
	sgl = sbp->fct_buf->db_sglist;
	resid = size;

	for (sgllen = 0; sgllen < count && resid > 0; sgllen++) {
		resid -= MIN(resid, sgl->seg_length);
		sgl++;
	}

	if (resid > 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fct_error_msg,
		    "emlxs_fct_bde_setup: Not enough scatter gather buffers "
		    " size=%d resid=%d count=%d",
		    size, resid, count);
		return (1);
	}
#ifdef SLI3_SUPPORT
	if ((hba->sli_mode < 3) || (sgllen > SLI3_MAX_BDE)) {
		rval = emlxs_sli2_fct_bde_setup(port, sbp);
	} else {
		rval = emlxs_sli3_fct_bde_setup(port, sbp);
	}
#else /* !SLI3_SUPPORT */
	rval = emlxs_sli2_fct_bde_setup(port, sbp);
#endif /* SLI3_SUPPORT */

	return (rval);

}  /* emlxs_fct_bde_setup() */
#endif /* SFCT_SUPPORT */

static uint32_t
emlxs_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	uint32_t	rval;

#ifdef SLI3_SUPPORT
	emlxs_hba_t	*hba = HBA;

	if (hba->sli_mode < 3) {
		rval = emlxs_sli2_bde_setup(port, sbp);
	} else {
		rval = emlxs_sli3_bde_setup(port, sbp);
	}

#else	/* !SLI3_SUPPORT */
	rval = emlxs_sli2_bde_setup(port, sbp);
#endif	/* SLI3_SUPPORT */

	return (rval);

} /* emlxs_bde_setup() */

extern void
emlxs_sli3_poll_intr(emlxs_hba_t *hba, uint32_t att_bit)
{
	uint32_t ha_copy;

	/*
	 * Polling a specific attention bit.
	 */
	for (;;) {
		ha_copy = emlxs_check_attention(hba);

		if (ha_copy & att_bit) {
			break;
		}

	}

	mutex_enter(&EMLXS_PORT_LOCK);
	ha_copy = emlxs_get_attention(hba, -1);
	mutex_exit(&EMLXS_PORT_LOCK);

	/* Process the attentions */
	emlxs_proc_attention(hba, ha_copy);

	return;

}  /* emlxs_sli3_poll_intr() */

/*ARGSUSED*/
extern void
emlxs_sli4_poll_intr(emlxs_hba_t *hba, uint32_t att_bit)
{
	return;

}  /* emlxs_sli4_poll_intr() */

#ifdef MSI_SUPPORT

extern uint32_t
emlxs_sli3_msi_intr(char *arg1, char *arg2)
{
	emlxs_hba_t *hba = (emlxs_hba_t *)arg1;
	uint16_t msgid;
	uint32_t hc_copy;
	uint32_t ha_copy;
	uint32_t restore = 0;

	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
	 * "emlxs_sli3_msi_intr: arg1=%p arg2=%p", arg1, arg2);
	 */

	/* Check for legacy interrupt handling */
	if (hba->intr_type == DDI_INTR_TYPE_FIXED) {
		mutex_enter(&EMLXS_PORT_LOCK);

		if (hba->flag & FC_OFFLINE_MODE) {
			mutex_exit(&EMLXS_PORT_LOCK);

			if (hba->bus_type == SBUS_FC) {
				return (DDI_INTR_CLAIMED);
			} else {
				return (DDI_INTR_UNCLAIMED);
			}
		}

		/* Get host attention bits */
		ha_copy = emlxs_get_attention(hba, -1);

		if (ha_copy == 0) {
			if (hba->intr_unclaimed) {
				mutex_exit(&EMLXS_PORT_LOCK);
				return (DDI_INTR_UNCLAIMED);
			}

			hba->intr_unclaimed = 1;
		} else {
			hba->intr_unclaimed = 0;
		}

		mutex_exit(&EMLXS_PORT_LOCK);

		/* Process the interrupt */
		emlxs_proc_attention(hba, ha_copy);

		return (DDI_INTR_CLAIMED);
	}

	/* DDI_INTR_TYPE_MSI  */
	/* DDI_INTR_TYPE_MSIX */

	/* Get MSI message id */
	msgid = (uint16_t)((unsigned long)arg2);

	/* Validate the message id */
	if (msgid >= hba->intr_count) {
		msgid = 0;
	}

	mutex_enter(&EMLXS_INTR_LOCK(msgid));

	mutex_enter(&EMLXS_PORT_LOCK);

	/* Check if adapter is offline */
	if (hba->flag & FC_OFFLINE_MODE) {
		mutex_exit(&EMLXS_PORT_LOCK);
		mutex_exit(&EMLXS_INTR_LOCK(msgid));

		/* Always claim an MSI interrupt */
		return (DDI_INTR_CLAIMED);
	}

	/* Disable interrupts associated with this msgid */
	if (msgid == 0 && (hba->model_info.chip == EMLXS_ZEPHYR_CHIP)) {
		hc_copy = hba->hc_copy & ~hba->intr_mask;
		WRITE_CSR_REG(hba, FC_HC_REG(hba, hba->csr_addr), hc_copy);
		restore = 1;
	}

	/* Get host attention bits */
	ha_copy = emlxs_get_attention(hba, msgid);

	mutex_exit(&EMLXS_PORT_LOCK);

	/* Process the interrupt */
	emlxs_proc_attention(hba, ha_copy);

	/* Restore interrupts */
	if (restore) {
		mutex_enter(&EMLXS_PORT_LOCK);
		WRITE_CSR_REG(hba, FC_HC_REG(hba, hba->csr_addr),
		    hba->hc_copy);
		mutex_exit(&EMLXS_PORT_LOCK);
	}

	mutex_exit(&EMLXS_INTR_LOCK(msgid));

	return (DDI_INTR_CLAIMED);

}  /* emlxs_sli3_msi_intr() */


/*ARGSUSED*/
extern uint32_t
emlxs_sli4_msi_intr(char *arg1, char *arg2)
{
	return (DDI_INTR_CLAIMED);

}  /* emlxs_sli4_msi_intr() */

#endif /* MSI_SUPPORT */

extern int
emlxs_sli3_intx_intr(char *arg)
{
	emlxs_hba_t *hba = (emlxs_hba_t *)arg;
	uint32_t ha_copy = 0;

	mutex_enter(&EMLXS_PORT_LOCK);

	if (hba->flag & FC_OFFLINE_MODE) {
		mutex_exit(&EMLXS_PORT_LOCK);

		if (hba->bus_type == SBUS_FC) {
			return (DDI_INTR_CLAIMED);
		} else {
			return (DDI_INTR_UNCLAIMED);
		}
	}

	/* Get host attention bits */
	ha_copy = emlxs_get_attention(hba, -1);

	if (ha_copy == 0) {
		if (hba->intr_unclaimed) {
			mutex_exit(&EMLXS_PORT_LOCK);
			return (DDI_INTR_UNCLAIMED);
		}

		hba->intr_unclaimed = 1;
	} else {
		hba->intr_unclaimed = 0;
	}

	mutex_exit(&EMLXS_PORT_LOCK);

	/* Process the interrupt */
	emlxs_proc_attention(hba, ha_copy);

	return (DDI_INTR_CLAIMED);

}  /* emlxs_sli3_intx_intr() */

/*ARGSUSED*/
extern int
emlxs_sli4_intx_intr(char *arg)
{
	return (DDI_INTR_CLAIMED);

}  /* emlxs_sli4_intx_intr() */


/* EMLXS_PORT_LOCK must be held when call this routine */
uint32_t
emlxs_get_attention(emlxs_hba_t *hba, uint32_t msgid)
{
	uint32_t ha_copy = 0;
	uint32_t ha_copy2;
	uint32_t mask = hba->hc_copy;

#ifdef MSI_SUPPORT

read_ha_register:

	/* Check for default MSI interrupt */
	if (msgid == 0) {
		/* Read host attention register to determine interrupt source */
		ha_copy2 = READ_CSR_REG(hba, FC_HA_REG(hba, hba->csr_addr));

		/* Filter out MSI non-default attention bits */
		ha_copy2 &= ~(hba->intr_cond);
	}

	/* Check for polled or fixed type interrupt */
	else if (msgid == -1) {
		/* Read host attention register to determine interrupt source */
		ha_copy2 = READ_CSR_REG(hba, FC_HA_REG(hba, hba->csr_addr));
	}

	/* Otherwise, assume a mapped MSI interrupt */
	else {
		/* Convert MSI msgid to mapped attention bits */
		ha_copy2 = hba->intr_map[msgid];
	}

#else /* !MSI_SUPPORT */

	/* Read host attention register to determine interrupt source */
	ha_copy2 = READ_CSR_REG(hba, FC_HA_REG(hba, hba->csr_addr));

#endif /* MSI_SUPPORT */

	/* Check if Hardware error interrupt is enabled */
	if ((ha_copy2 & HA_ERATT) && !(mask & HC_ERINT_ENA)) {
		ha_copy2 &= ~HA_ERATT;
	}

	/* Check if link interrupt is enabled */
	if ((ha_copy2 & HA_LATT) && !(mask & HC_LAINT_ENA)) {
		ha_copy2 &= ~HA_LATT;
	}

	/* Check if Mailbox interrupt is enabled */
	if ((ha_copy2 & HA_MBATT) && !(mask & HC_MBINT_ENA)) {
		ha_copy2 &= ~HA_MBATT;
	}

	/* Check if ring0 interrupt is enabled */
	if ((ha_copy2 & HA_R0ATT) && !(mask & HC_R0INT_ENA)) {
		ha_copy2 &= ~HA_R0ATT;
	}

	/* Check if ring1 interrupt is enabled */
	if ((ha_copy2 & HA_R1ATT) && !(mask & HC_R1INT_ENA)) {
		ha_copy2 &= ~HA_R1ATT;
	}

	/* Check if ring2 interrupt is enabled */
	if ((ha_copy2 & HA_R2ATT) && !(mask & HC_R2INT_ENA)) {
		ha_copy2 &= ~HA_R2ATT;
	}

	/* Check if ring3 interrupt is enabled */
	if ((ha_copy2 & HA_R3ATT) && !(mask & HC_R3INT_ENA)) {
		ha_copy2 &= ~HA_R3ATT;
	}

	/* Accumulate attention bits */
	ha_copy |= ha_copy2;

	/* Clear attentions except for error, link, and autoclear(MSIX) */
	ha_copy2 &= ~(HA_ERATT | HA_LATT);	/* | hba->intr_autoClear */

	if (ha_copy2) {
		WRITE_CSR_REG(hba, FC_HA_REG(hba, hba->csr_addr), ha_copy2);
	}

	return (ha_copy);

}  /* emlxs_get_attention() */


void
emlxs_proc_attention(emlxs_hba_t *hba, uint32_t ha_copy)
{
	/* ha_copy should be pre-filtered */

	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	 * "emlxs_proc_attention: ha_copy=%x", ha_copy);
	 */

	if (hba->state < FC_WARM_START) {
		return;
	}

	if (!ha_copy) {
		return;
	}

	if (hba->bus_type == SBUS_FC) {
		(void) READ_SBUS_CSR_REG(hba,
		    FC_SHS_REG(hba, hba->sbus_csr_addr));
	}

	/* Adapter error */
	if (ha_copy & HA_ERATT) {
		HBASTATS.IntrEvent[6]++;
		emlxs_handle_ff_error(hba);
		return;
	}

	/* Mailbox interrupt */
	if (ha_copy & HA_MBATT) {
		HBASTATS.IntrEvent[5]++;
		(void) emlxs_handle_mb_event(hba);
	}

	/* Link Attention interrupt */
	if (ha_copy & HA_LATT) {
		HBASTATS.IntrEvent[4]++;
		emlxs_handle_link_event(hba);
	}

	/* event on ring 0 - FCP Ring */
	if (ha_copy & HA_R0ATT) {
		HBASTATS.IntrEvent[0]++;
		emlxs_handle_ring_event(hba, 0, ha_copy);
	}

	/* event on ring 1 - IP Ring */
	if (ha_copy & HA_R1ATT) {
		HBASTATS.IntrEvent[1]++;
		emlxs_handle_ring_event(hba, 1, ha_copy);
	}

	/* event on ring 2 - ELS Ring */
	if (ha_copy & HA_R2ATT) {
		HBASTATS.IntrEvent[2]++;
		emlxs_handle_ring_event(hba, 2, ha_copy);
	}

	/* event on ring 3 - CT Ring */
	if (ha_copy & HA_R3ATT) {
		HBASTATS.IntrEvent[3]++;
		emlxs_handle_ring_event(hba, 3, ha_copy);
	}

	if (hba->bus_type == SBUS_FC) {
		WRITE_SBUS_CSR_REG(hba, FC_SHS_REG(hba, hba->sbus_csr_addr),
		    SBUS_STAT_IP);
	}

	/* Set heartbeat flag to show activity */
	hba->heartbeat_flag = 1;

	return;

}  /* emlxs_proc_attention() */


/*
 * emlxs_handle_ff_error()
 *
 *    Description: Processes a FireFly error
 *    Runs at Interrupt level
 */
extern void
emlxs_handle_ff_error(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	uint32_t status;
	uint32_t status1;
	uint32_t status2;
	int i = 0;

	/* do what needs to be done, get error from STATUS REGISTER */
	status = READ_CSR_REG(hba, FC_HS_REG(hba, hba->csr_addr));

	/* Clear Chip error bit */
	WRITE_CSR_REG(hba, FC_HA_REG(hba, hba->csr_addr), HA_ERATT);

	/* If HS_FFER1 is set, then wait until the HS_FFER1 bit clears */
	if (status & HS_FFER1) {

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_hardware_error_msg,
		    "HS_FFER1 received");
		emlxs_ffstate_change(hba, FC_ERROR);
		(void) emlxs_offline(hba);
		while ((status & HS_FFER1) && (i < 300)) {
			status =
			    READ_CSR_REG(hba, FC_HS_REG(hba, hba->csr_addr));
			DELAYMS(1000);
			i++;
		}
	}

	if (i == 300) {
		/* 5 minutes is up, shutdown HBA */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_hardware_error_msg,
		    "HS_FFER1 clear timeout");
		goto go_shutdown;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_hardware_error_msg,
	    "HS_FFER1 cleared");

	if (status & HS_OVERTEMP) {
		status1 =
		    READ_SLIM_ADDR(hba,
		    ((volatile uint8_t *)hba->slim_addr + 0xb0));

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_hardware_error_msg,
		    "Maximum adapter temperature exceeded (%d °C).", status1);

		hba->flag |= FC_OVERTEMP_EVENT;
		emlxs_log_temp_event(port, 0x01, status1);
	} else {
		status1 =
		    READ_SLIM_ADDR(hba,
		    ((volatile uint8_t *)hba->slim_addr + 0xa8));
		status2 =
		    READ_SLIM_ADDR(hba,
		    ((volatile uint8_t *)hba->slim_addr + 0xac));

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_hardware_error_msg,
		    "Host Error Attention: "
		    "status=0x%x status1=0x%x status2=0x%x",
		    status, status1, status2);
	}

	emlxs_ffstate_change(hba, FC_ERROR);

	if (status & HS_FFER6) {
		thread_create(NULL, 0, emlxs_restart_thread, (char *)hba, 0,
		    &p0, TS_RUN, v.v_maxsyspri - 2);
	} else {
go_shutdown:
		thread_create(NULL, 0, emlxs_shutdown_thread, (char *)hba, 0,
		    &p0, TS_RUN, v.v_maxsyspri - 2);
	}

}  /* emlxs_handle_ff_error() */


/*
 *  emlxs_handle_link_event()
 *
 *    Description: Process a Link Attention.
 */
static void
emlxs_handle_link_event(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	MAILBOX *mb;

	HBASTATS.LinkEvent++;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_link_event_msg, "event=%x",
	    HBASTATS.LinkEvent);


	/* Get a buffer which will be used for mailbox commands */
	if ((mb = (MAILBOX *)emlxs_mem_get(hba, MEM_MBOX | MEM_PRI))) {
		/* Get link attention message */
		if (emlxs_mb_read_la(hba, mb) == 0) {
			if (emlxs_sli_issue_mbox_cmd(hba, mb, MBX_NOWAIT,
			    0) != MBX_BUSY) {
				(void) emlxs_mem_put(hba, MEM_MBOX,
				    (uint8_t *)mb);
			}

			mutex_enter(&EMLXS_PORT_LOCK);


			/*
			 * Clear Link Attention in HA REG
			 */
			WRITE_CSR_REG(hba, FC_HA_REG(hba, hba->csr_addr),
			    HA_LATT);

			mutex_exit(&EMLXS_PORT_LOCK);
		} else {
			(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
		}
	}

}  /* emlxs_handle_link_event()  */


/*
 *  emlxs_handle_ring_event()
 *
 *    Description: Process a Ring Attention.
 */
static void
emlxs_handle_ring_event(emlxs_hba_t *hba, int32_t ring_no, uint32_t ha_copy)
{
	emlxs_port_t *port = &PPORT;
	SLIM2 *slim2p = (SLIM2 *)hba->slim2.virt;
	RING *rp;
	IOCB *entry;
	IOCBQ *iocbq;
	IOCBQ local_iocbq;
	PGP *pgp;
	uint32_t count;
	volatile uint32_t chipatt;
	void *ioa2;
	uint32_t reg;
	off_t offset;
	IOCBQ *rsp_head = NULL;
	IOCBQ *rsp_tail = NULL;
	emlxs_buf_t *sbp = NULL;

	count = 0;
	rp = &hba->ring[ring_no];

	/*
	 * Isolate this ring's host attention bits
	 * This makes all ring attention bits equal
	 * to Ring0 attention bits
	 */
	reg = (ha_copy >> (ring_no * 4)) & 0x0f;

	/*
	 * Gather iocb entries off response ring.
	 * Ensure entry is owned by the host.
	 */
	pgp = (PGP *)&slim2p->mbx.us.s2.port[ring_no];
	offset =
	    (off_t)((uint64_t)((unsigned long)&(pgp->rspPutInx)) -
	    (uint64_t)((unsigned long)slim2p));
	emlxs_mpdata_sync(hba->slim2.dma_handle, offset, 4,
	    DDI_DMA_SYNC_FORKERNEL);
	rp->fc_port_rspidx = PCIMEM_LONG(pgp->rspPutInx);

	/* While ring is not empty */
	while (rp->fc_rspidx != rp->fc_port_rspidx) {
		HBASTATS.IocbReceived[ring_no]++;

		/* Get the next response ring iocb */
		entry =
		    (IOCB *)(((char *)rp->fc_rspringaddr +
		    (rp->fc_rspidx * hba->iocb_rsp_size)));

		/* DMA sync the response ring iocb for the adapter */
		offset = (off_t)((uint64_t)((unsigned long)entry)
		    - (uint64_t)((unsigned long)slim2p));
		emlxs_mpdata_sync(hba->slim2.dma_handle, offset,
		    hba->iocb_rsp_size, DDI_DMA_SYNC_FORKERNEL);

		count++;

		/* Copy word6 and word7 to local iocb for now */
		iocbq = &local_iocbq;
		emlxs_pcimem_bcopy((uint32_t *)entry + 6,
		    (uint32_t *)iocbq + 6, (sizeof (uint32_t) * 2));

		/* when LE is not set, entire Command has not been received */
		if (!iocbq->iocb.ulpLe) {
			/* This should never happen */
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ring_error_msg,
			    "ulpLE is not set. "
			    "ring=%d iotag=%x cmd=%x status=%x",
			    ring_no, iocbq->iocb.ulpIoTag,
			    iocbq->iocb.ulpCommand, iocbq->iocb.ulpStatus);

			goto next;
		}

		switch (iocbq->iocb.ulpCommand) {
#ifdef SFCT_SUPPORT
		case CMD_CLOSE_XRI_CX:
		case CMD_ABORT_XRI_CX:
			if (!port->tgt_mode) {
				sbp = NULL;
				break;
			}

			sbp =
			    emlxs_unregister_pkt(rp, iocbq->iocb.ulpIoTag, 0);
			break;
#endif /* SFCT_SUPPORT */

			/* Ring 0 registered commands */
		case CMD_FCP_ICMND_CR:
		case CMD_FCP_ICMND_CX:
		case CMD_FCP_IREAD_CR:
		case CMD_FCP_IREAD_CX:
		case CMD_FCP_IWRITE_CR:
		case CMD_FCP_IWRITE_CX:
		case CMD_FCP_ICMND64_CR:
		case CMD_FCP_ICMND64_CX:
		case CMD_FCP_IREAD64_CR:
		case CMD_FCP_IREAD64_CX:
		case CMD_FCP_IWRITE64_CR:
		case CMD_FCP_IWRITE64_CX:
#ifdef SFCT_SUPPORT
		case CMD_FCP_TSEND_CX:
		case CMD_FCP_TSEND64_CX:
		case CMD_FCP_TRECEIVE_CX:
		case CMD_FCP_TRECEIVE64_CX:
		case CMD_FCP_TRSP_CX:
		case CMD_FCP_TRSP64_CX:
#endif /* SFCT_SUPPORT */

			/* Ring 1 registered commands */
		case CMD_XMIT_BCAST_CN:
		case CMD_XMIT_BCAST_CX:
		case CMD_XMIT_SEQUENCE_CX:
		case CMD_XMIT_SEQUENCE_CR:
		case CMD_XMIT_BCAST64_CN:
		case CMD_XMIT_BCAST64_CX:
		case CMD_XMIT_SEQUENCE64_CX:
		case CMD_XMIT_SEQUENCE64_CR:
		case CMD_CREATE_XRI_CR:
		case CMD_CREATE_XRI_CX:

			/* Ring 2 registered commands */
		case CMD_ELS_REQUEST_CR:
		case CMD_ELS_REQUEST_CX:
		case CMD_XMIT_ELS_RSP_CX:
		case CMD_ELS_REQUEST64_CR:
		case CMD_ELS_REQUEST64_CX:
		case CMD_XMIT_ELS_RSP64_CX:

			/* Ring 3 registered commands */
		case CMD_GEN_REQUEST64_CR:
		case CMD_GEN_REQUEST64_CX:

			sbp =
			    emlxs_unregister_pkt(rp, iocbq->iocb.ulpIoTag, 0);
			break;

		default:
			sbp = NULL;
		}

		/* If packet is stale, then drop it. */
		if (sbp == STALE_PACKET) {
			/* Copy entry to the local iocbq */
			emlxs_pcimem_bcopy((uint32_t *)entry,
			    (uint32_t *)iocbq, hba->iocb_rsp_size);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_iocb_stale_msg,
			    "ringno=%d iocb=%p cmd=%x status=%x "
			    "error=%x iotag=%x context=%x info=%x",
			    ring_no, iocbq, (uint8_t)iocbq->iocb.ulpCommand,
			    iocbq->iocb.ulpStatus,
			    (uint8_t)iocbq->iocb.un.grsp.perr.statLocalError,
			    (uint16_t)iocbq->iocb.ulpIoTag,
			    (uint16_t)iocbq->iocb.ulpContext,
			    (uint8_t)iocbq->iocb.ulpRsvdByte);

			goto next;
		}

		/*
		 * If a packet was found, then queue the packet's
		 * iocb for deferred processing
		 */
		else if (sbp) {
#ifdef SFCT_SUPPORT
			fct_cmd_t *fct_cmd;
			emlxs_buf_t *cmd_sbp;

			fct_cmd = sbp->fct_cmd;
			if (fct_cmd) {
				cmd_sbp =
				    (emlxs_buf_t *)fct_cmd->cmd_fca_private;
				mutex_enter(&cmd_sbp->fct_mtx);
				emlxs_fct_state_chg(fct_cmd, cmd_sbp,
				    EMLXS_FCT_IOCB_COMPLETE);
				mutex_exit(&cmd_sbp->fct_mtx);
			}
#endif /* SFCT_SUPPORT */
			atomic_add_32(&hba->io_active, -1);

			/* Copy entry to sbp's iocbq */
			iocbq = &sbp->iocbq;
			emlxs_pcimem_bcopy((uint32_t *)entry,
			    (uint32_t *)iocbq, hba->iocb_rsp_size);

			iocbq->next = NULL;

			/*
			 * If this is NOT a polled command completion
			 * or a driver allocated pkt, then defer pkt
			 * completion.
			 */
			if (!(sbp->pkt_flags &
			    (PACKET_POLLED | PACKET_ALLOCATED))) {
				/* Add the IOCB to the local list */
				if (!rsp_head) {
					rsp_head = iocbq;
				} else {
					rsp_tail->next = iocbq;
				}

				rsp_tail = iocbq;

				goto next;
			}
		} else {
			/* Copy entry to the local iocbq */
			emlxs_pcimem_bcopy((uint32_t *)entry,
			    (uint32_t *)iocbq, hba->iocb_rsp_size);

			iocbq->next = NULL;
			iocbq->bp = NULL;
			iocbq->port = &PPORT;
			iocbq->ring = rp;
			iocbq->node = NULL;
			iocbq->sbp = NULL;
			iocbq->flag = 0;
		}

		/* process the ring event now */
		emlxs_proc_ring_event(hba, rp, iocbq);

next:
		/* Increment the driver's local response get index */
		if (++rp->fc_rspidx >= rp->fc_numRiocb) {
			rp->fc_rspidx = 0;
		}

	}	/* while(TRUE) */

	if (rsp_head) {
		mutex_enter(&rp->rsp_lock);
		if (rp->rsp_head == NULL) {
			rp->rsp_head = rsp_head;
			rp->rsp_tail = rsp_tail;
		} else {
			rp->rsp_tail->next = rsp_head;
			rp->rsp_tail = rsp_tail;
		}
		mutex_exit(&rp->rsp_lock);

		emlxs_thread_trigger2(&rp->intr_thread, emlxs_proc_ring, rp);
	}

	/* Check if at least one response entry was processed */
	if (count) {
		/* Update response get index for the adapter */
		if (hba->bus_type == SBUS_FC) {
			slim2p->mbx.us.s2.host[ring_no].rspGetInx
			    = PCIMEM_LONG(rp->fc_rspidx);

			/* DMA sync the index for the adapter */
			offset = (off_t)
			    ((uint64_t)((unsigned long)&(slim2p->mbx.us.s2.
			    host[ring_no].rspGetInx))
			    - (uint64_t)((unsigned long)slim2p));
			emlxs_mpdata_sync(hba->slim2.dma_handle, offset, 4,
			    DDI_DMA_SYNC_FORDEV);
		} else {
			ioa2 =
			    (void *)((char *)hba->slim_addr +
			    hba->hgp_ring_offset + (((ring_no * 2) +
			    1) * sizeof (uint32_t)));
			WRITE_SLIM_ADDR(hba, (volatile uint32_t *)ioa2,
			    rp->fc_rspidx);
		}

		if (reg & HA_R0RE_REQ) {
			/* HBASTATS.chipRingFree++; */

			mutex_enter(&EMLXS_PORT_LOCK);

			/* Tell the adapter we serviced the ring */
			chipatt = ((CA_R0ATT | CA_R0RE_RSP) << (ring_no * 4));
			WRITE_CSR_REG(hba, FC_CA_REG(hba, hba->csr_addr),
			    chipatt);

			mutex_exit(&EMLXS_PORT_LOCK);
		}
	}

	if ((reg & HA_R0CE_RSP) || hba->ring_tx_count[ring_no]) {
		/* HBASTATS.hostRingFree++; */

		/* Cmd ring may be available. Try sending more iocbs */
		emlxs_sli_issue_iocb_cmd(hba, rp, 0);
	}

	/* HBASTATS.ringEvent++; */

	return;

}  /* emlxs_handle_ring_event() */

int
emlxs_handle_rcv_seq(emlxs_hba_t *hba, RING *rp, IOCBQ *iocbq)
{
	emlxs_port_t *port = &PPORT;
	IOCB *iocb;
	MATCHMAP *mp = NULL;
	uint64_t bdeAddr;
	uint32_t vpi = 0;
	uint32_t ringno;
	uint32_t size = 0;
	uint32_t *RcvError;
	uint32_t *RcvDropped;
	uint32_t *UbPosted;
	emlxs_msg_t *dropped_msg;
	char error_str[64];
	uint32_t buf_type;
	uint32_t *word;

#ifdef SLI3_SUPPORT
	uint32_t hbq_id;
#endif /* SLI3_SUPPORT */

	ringno = rp->ringno;
	iocb = &iocbq->iocb;
	word = (uint32_t *)iocb;

	switch (ringno) {
#ifdef SFCT_SUPPORT
	case FC_FCT_RING:
		HBASTATS.FctRingEvent++;
		RcvError = &HBASTATS.FctRingError;
		RcvDropped = &HBASTATS.FctRingDropped;
		UbPosted = &HBASTATS.FctUbPosted;
		dropped_msg = &emlxs_fct_detail_msg;
		buf_type = MEM_FCTBUF;
		break;
#endif /* SFCT_SUPPORT */

	case FC_IP_RING:
		HBASTATS.IpRcvEvent++;
		RcvError = &HBASTATS.IpDropped;
		RcvDropped = &HBASTATS.IpDropped;
		UbPosted = &HBASTATS.IpUbPosted;
		dropped_msg = &emlxs_unsol_ip_dropped_msg;
		buf_type = MEM_IPBUF;
		break;

	case FC_ELS_RING:
		HBASTATS.ElsRcvEvent++;
		RcvError = &HBASTATS.ElsRcvError;
		RcvDropped = &HBASTATS.ElsRcvDropped;
		UbPosted = &HBASTATS.ElsUbPosted;
		dropped_msg = &emlxs_unsol_els_dropped_msg;
		buf_type = MEM_ELSBUF;
		break;

	case FC_CT_RING:
		HBASTATS.CtRcvEvent++;
		RcvError = &HBASTATS.CtRcvError;
		RcvDropped = &HBASTATS.CtRcvDropped;
		UbPosted = &HBASTATS.CtUbPosted;
		dropped_msg = &emlxs_unsol_ct_dropped_msg;
		buf_type = MEM_CTBUF;
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_iocb_invalid_msg,
		    "ring=%d cmd=%x  %s %x %x %x %x",
		    ringno, iocb->ulpCommand,
		    emlxs_state_xlate(iocb->ulpStatus), word[4], word[5],
		    word[6], word[7]);
		return (1);
	}

	if (iocb->ulpStatus) {
		if ((iocb->ulpStatus == IOSTAT_LOCAL_REJECT) &&
		    (iocb->un.grsp.perr.statLocalError ==
		    IOERR_RCV_BUFFER_TIMEOUT)) {
			(void) strcpy(error_str, "Out of posted buffers:");
		} else if ((iocb->ulpStatus == IOSTAT_LOCAL_REJECT) &&
		    (iocb->un.grsp.perr.statLocalError ==
		    IOERR_RCV_BUFFER_WAITING)) {
			(void) strcpy(error_str, "Buffer waiting:");
			goto done;
		} else if (iocb->ulpStatus == IOSTAT_ILLEGAL_FRAME_RCVD) {
			(void) strcpy(error_str, "Illegal frame:");
		} else {
			(void) strcpy(error_str, "General error:");
		}

		goto failed;
	}
#ifdef SLI3_SUPPORT
	if (hba->flag & FC_HBQ_ENABLED) {
		HBQ_INIT_t *hbq;
		HBQE_t *hbqE;
		uint32_t hbqe_tag;

		(*UbPosted)--;

		hbqE = (HBQE_t *)iocb;
		hbq_id = hbqE->unt.ext.HBQ_tag;
		hbqe_tag = hbqE->unt.ext.HBQE_tag;

		hbq = &hba->hbq_table[hbq_id];

		if (hbqe_tag >= hbq->HBQ_numEntries) {
			(void) sprintf(error_str, "Invalid HBQE tag=%x:",
			    hbqe_tag);
			goto dropped;
		}

		mp = hba->hbq_table[hbq_id].HBQ_PostBufs[hbqe_tag];

		size = iocb->unsli3.ext_rcv.seq_len;
	} else
#endif /* SLI3_SUPPORT */
	{
		bdeAddr =
		    getPaddr(iocb->un.cont64[0].addrHigh,
		    iocb->un.cont64[0].addrLow);

		/* Check for invalid buffer */
		if (iocb->un.cont64[0].tus.f.bdeFlags & BUFF_TYPE_INVALID) {
			(void) strcpy(error_str, "Invalid buffer:");
			goto dropped;
		}

		mp = emlxs_mem_get_vaddr(hba, rp, bdeAddr);

		size = iocb->un.rcvseq64.rcvBde.tus.f.bdeSize;
	}

	if (!mp) {
		(void) strcpy(error_str, "Buffer not mapped:");
		goto dropped;
	}

	if (!size) {
		(void) strcpy(error_str, "Buffer empty:");
		goto dropped;
	}
#ifdef SLI3_SUPPORT
	/* To avoid we drop the broadcast packets */
	if (ringno != FC_IP_RING) {
		/* Get virtual port */
		if (hba->flag & FC_NPIV_ENABLED) {
			vpi = iocb->unsli3.ext_rcv.vpi;
			if (vpi >= hba->vpi_max) {
				(void) sprintf(error_str,
				"Invalid VPI=%d:", vpi);
				goto dropped;
			}

			port = &VPORT(vpi);
		}
	}
#endif /* SLI3_SUPPORT */

	/* Process request */
	switch (ringno) {
#ifdef SFCT_SUPPORT
	case FC_FCT_RING:
		(void) emlxs_fct_handle_unsol_req(port, rp, iocbq, mp, size);
		break;
#endif /* SFCT_SUPPORT */

	case FC_IP_RING:
		(void) emlxs_ip_handle_unsol_req(port, rp, iocbq, mp, size);
		break;

	case FC_ELS_RING:
		/* If this is a target port, then let fct handle this */
		if (port->tgt_mode) {
#ifdef SFCT_SUPPORT
			(void) emlxs_fct_handle_unsol_els(port, rp, iocbq, mp,
			    size);
#endif /* SFCT_SUPPORT */
		} else {
			(void) emlxs_els_handle_unsol_req(port, rp, iocbq, mp,
			    size);
		}
		break;

	case FC_CT_RING:
		(void) emlxs_ct_handle_unsol_req(port, rp, iocbq, mp, size);
		break;
	}

	goto done;

dropped:
	(*RcvDropped)++;

	EMLXS_MSGF(EMLXS_CONTEXT, dropped_msg,
	    "%s: cmd=%x  %s %x %x %x %x",
	    error_str, iocb->ulpCommand, emlxs_state_xlate(iocb->ulpStatus),
	    word[4], word[5], word[6], word[7]);

	if (ringno == FC_FCT_RING) {
		uint32_t sid;

#ifdef SLI3_SUPPORT
		if (hba->sli_mode >= EMLXS_HBA_SLI3_MODE) {
			emlxs_node_t *ndlp;
			ndlp = emlxs_node_find_rpi(port, iocb->ulpIoTag);
			sid = ndlp->nlp_DID;
		} else
#endif /* SLI3_SUPPORT */
		{
			sid = iocb->un.ulpWord[4] & 0xFFFFFF;
		}

		emlxs_send_logo(port, sid);
	}

	goto done;

failed:
	(*RcvError)++;

	EMLXS_MSGF(EMLXS_CONTEXT, dropped_msg,
	    "%s: cmd=%x %s  %x %x %x %x  hba:%x %x",
	    error_str, iocb->ulpCommand, emlxs_state_xlate(iocb->ulpStatus),
	    word[4], word[5], word[6], word[7], hba->state, hba->flag);

done:

#ifdef SLI3_SUPPORT
	if (hba->flag & FC_HBQ_ENABLED) {
		emlxs_update_HBQ_index(hba, hbq_id);
	} else
#endif /* SLI3_SUPPORT */
	{
		if (mp) {
			(void) emlxs_mem_put(hba, buf_type, (uint8_t *)mp);
		}
		(void) emlxs_post_buffer(hba, rp, 1);
	}

	return (0);

}  /* emlxs_handle_rcv_seq() */



/* EMLXS_CMD_RING_LOCK must be held when calling this function */
static void
emlxs_issue_iocb(emlxs_hba_t *hba, RING *rp, IOCBQ *iocbq)
{
	emlxs_port_t *port;
	IOCB *icmd;
	IOCB *iocb;
	emlxs_buf_t *sbp;
	off_t offset;
	uint32_t ringno;

	ringno = rp->ringno;
	sbp = iocbq->sbp;
	icmd = &iocbq->iocb;
	port = iocbq->port;

	HBASTATS.IocbIssued[ringno]++;

	/* Check for ULP pkt request */
	if (sbp) {
		mutex_enter(&sbp->mtx);

		if (sbp->node == NULL) {
			/* Set node to base node by default */
			iocbq->node = (void *)&port->node_base;
			sbp->node = (void *)&port->node_base;
		}

		sbp->pkt_flags |= PACKET_IN_CHIPQ;
		mutex_exit(&sbp->mtx);

		atomic_add_32(&hba->io_active, 1);
	}

	/* get the next available command ring iocb */
	iocb =
	    (IOCB *)(((char *)rp->fc_cmdringaddr +
	    (rp->fc_cmdidx * hba->iocb_cmd_size)));

	/* Copy the local iocb to the command ring iocb */
	emlxs_pcimem_bcopy((uint32_t *)icmd, (uint32_t *)iocb,
	    hba->iocb_cmd_size);

	/* DMA sync the command ring iocb for the adapter */
	offset = (off_t)((uint64_t)((unsigned long)iocb)
	    - (uint64_t)((unsigned long)hba->slim2.virt));
	emlxs_mpdata_sync(hba->slim2.dma_handle, offset, hba->iocb_cmd_size,
	    DDI_DMA_SYNC_FORDEV);

	/* Free the local iocb if there is no sbp tracking it */
	if (!sbp) {
		(void) emlxs_mem_put(hba, MEM_IOCB, (uint8_t *)iocbq);
	}
#ifdef SFCT_SUPPORT
	else {
		fct_cmd_t *fct_cmd = sbp->fct_cmd;
		emlxs_buf_t *cmd_sbp;

		if (fct_cmd) {
			cmd_sbp = (emlxs_buf_t *)fct_cmd->cmd_fca_private;

			emlxs_fct_state_chg(fct_cmd, cmd_sbp,
			    EMLXS_FCT_IOCB_ISSUED);
#ifdef FCT_IO_TRACE
			emlxs_fct_io_trace(port, sbp->fct_cmd,
			    icmd->ulpCommand);
#endif /* FCT_IO_TRACE */

		}
	}
#endif /* SFCT_SUPPORT */

	/* update local ring index to next available ring index */
	rp->fc_cmdidx =
	    (rp->fc_cmdidx + 1 >= rp->fc_numCiocb) ? 0 : rp->fc_cmdidx + 1;


	return;

}  /* emlxs_issue_iocb() */


extern uint32_t
emlxs_interlock(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	MAILBOX *swpmb;
	MAILBOX *mb2;
	MAILBOX *mb1;
	uint32_t word0;
	uint32_t j;
	uint32_t interlock_failed;
	uint32_t ha_copy;
	uint32_t value;
	off_t offset;
	uint32_t size;

	interlock_failed = 0;

	mutex_enter(&EMLXS_PORT_LOCK);
	if (hba->flag & FC_INTERLOCKED) {
		emlxs_ffstate_change_locked(hba, FC_KILLED);

		mutex_exit(&EMLXS_PORT_LOCK);

		return (FC_SUCCESS);
	}

	j = 0;
	while (j++ < 10000) {
		if (hba->mbox_queue_flag == 0) {
			break;
		}

		mutex_exit(&EMLXS_PORT_LOCK);
		DELAYUS(100);
		mutex_enter(&EMLXS_PORT_LOCK);
	}

	if (hba->mbox_queue_flag != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Interlock failed. Mailbox busy.");
		mutex_exit(&EMLXS_PORT_LOCK);
		return (FC_SUCCESS);
	}

	hba->flag |= FC_INTERLOCKED;
	hba->mbox_queue_flag = 1;

	/* Disable all host interrupts */
	hba->hc_copy = 0;
	WRITE_CSR_REG(hba, FC_HC_REG(hba, hba->csr_addr), hba->hc_copy);
	WRITE_CSR_REG(hba, FC_HA_REG(hba, hba->csr_addr), 0xffffffff);

	mb2 = FC_SLIM2_MAILBOX(hba);
	mb1 = FC_SLIM1_MAILBOX(hba);
	swpmb = (MAILBOX *)&word0;

	if (!(hba->flag & FC_SLIM2_MODE)) {
		goto mode_B;
	}

mode_A:

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
	    "Attempting SLIM2 Interlock...");

interlock_A:

	value = 0xFFFFFFFF;
	word0 = 0;
	swpmb->mbxCommand = MBX_KILL_BOARD;
	swpmb->mbxOwner = OWN_CHIP;

	/* Write value to SLIM */
	WRITE_SLIM_ADDR(hba, (((volatile uint32_t *)mb1) + 1), value);
	WRITE_SLIM_ADDR(hba, (((volatile uint32_t *)mb1)), word0);

	/* Send Kill board request */
	mb2->un.varWords[0] = value;
	mb2->mbxCommand = MBX_KILL_BOARD;
	mb2->mbxOwner = OWN_CHIP;

	/* Sync the memory */
	offset = (off_t)((uint64_t)((unsigned long)mb2)
	    - (uint64_t)((unsigned long)hba->slim2.virt));
	size = (sizeof (uint32_t) * 2);
	emlxs_pcimem_bcopy((uint32_t *)mb2, (uint32_t *)mb2, size);
	emlxs_mpdata_sync(hba->slim2.dma_handle, offset, size,
	    DDI_DMA_SYNC_FORDEV);

	/* interrupt board to do it right away */
	WRITE_CSR_REG(hba, FC_CA_REG(hba, hba->csr_addr), CA_MBATT);

	/* First wait for command acceptence */
	j = 0;
	while (j++ < 1000) {
		value = READ_SLIM_ADDR(hba, (((volatile uint32_t *)mb1) + 1));

		if (value == 0) {
			break;
		}

		DELAYUS(50);
	}

	if (value == 0) {
		/* Now wait for mailbox ownership to clear */
		while (j++ < 10000) {
			word0 =
			    READ_SLIM_ADDR(hba, ((volatile uint32_t *)mb1));

			if (swpmb->mbxOwner == 0) {
				break;
			}

			DELAYUS(50);
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Interlock succeeded.");

		goto done;
	}

	/* Interlock failed !!! */
	interlock_failed = 1;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg, "Interlock failed.");

mode_B:

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
	    "Attempting SLIM1 Interlock...");

interlock_B:

	value = 0xFFFFFFFF;
	word0 = 0;
	swpmb->mbxCommand = MBX_KILL_BOARD;
	swpmb->mbxOwner = OWN_CHIP;

	/* Write KILL BOARD to mailbox */
	WRITE_SLIM_ADDR(hba, (((volatile uint32_t *)mb1) + 1), value);
	WRITE_SLIM_ADDR(hba, ((volatile uint32_t *)mb1), word0);

	/* interrupt board to do it right away */
	WRITE_CSR_REG(hba, FC_CA_REG(hba, hba->csr_addr), CA_MBATT);

	/* First wait for command acceptence */
	j = 0;
	while (j++ < 1000) {
		value = READ_SLIM_ADDR(hba, (((volatile uint32_t *)mb1) + 1));

		if (value == 0) {
			break;
		}

		DELAYUS(50);
	}

	if (value == 0) {
		/* Now wait for mailbox ownership to clear */
		while (j++ < 10000) {
			word0 =
			    READ_SLIM_ADDR(hba, ((volatile uint32_t *)mb1));

			if (swpmb->mbxOwner == 0) {
				break;
			}

			DELAYUS(50);
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Interlock succeeded.");

		goto done;
	}

	/* Interlock failed !!! */

	/* If this is the first time then try again */
	if (interlock_failed == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Interlock failed. Retrying...");

		/* Try again */
		interlock_failed = 1;
		goto interlock_B;
	}

	/*
	 * Now check for error attention to indicate the board has
	 * been kiilled
	 */
	j = 0;
	while (j++ < 10000) {
		ha_copy = READ_CSR_REG(hba, FC_HA_REG(hba, hba->csr_addr));

		if (ha_copy & HA_ERATT) {
			break;
		}

		DELAYUS(50);
	}

	if (ha_copy & HA_ERATT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Interlock failed. Board killed.");
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Interlock failed. Board not killed.");
	}

done:

	hba->mbox_queue_flag = 0;

	emlxs_ffstate_change_locked(hba, FC_KILLED);

	mutex_exit(&EMLXS_PORT_LOCK);

	return (FC_SUCCESS);

}  /* emlxs_interlock() */



extern uint32_t
emlxs_reset_ring(emlxs_hba_t *hba, uint32_t ringno)
{
	emlxs_port_t *port = &PPORT;
	RING *rp;
	MAILBOX *mb;
	PGP *pgp;
	off_t offset;
	NODELIST *ndlp;
	uint32_t i;
	emlxs_port_t *vport;

	rp = &hba->ring[ringno];
	pgp = (PGP *)&((SLIM2 *)hba->slim2.virt)->mbx.us.s2.port[ringno];

	if ((mb = (MAILBOX *)emlxs_mem_get(hba, MEM_MBOX | MEM_PRI)) == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ring_reset_msg,
		    "%s: Unable to allocate mailbox buffer.",
		    emlxs_ring_xlate(ringno));

		return ((uint32_t)FC_FAILURE);
	}

	emlxs_mb_reset_ring(hba, mb, ringno);
	if (emlxs_sli_issue_mbox_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ring_reset_msg,
		    "%s: Unable to reset ring. Mailbox cmd=%x status=%x",
		    emlxs_ring_xlate(ringno), mb->mbxCommand, mb->mbxStatus);

		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
		return ((uint32_t)FC_FAILURE);
	}

	/* Free the mailbox */
	(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);

	/* Update the response ring indicies */
	offset = (off_t)((uint64_t)((unsigned long)&(pgp->rspPutInx))
	    - (uint64_t)((unsigned long)hba->slim2.virt));
	emlxs_mpdata_sync(hba->slim2.dma_handle, offset, 4,
	    DDI_DMA_SYNC_FORKERNEL);
	rp->fc_rspidx = rp->fc_port_rspidx = PCIMEM_LONG(pgp->rspPutInx);

	/* Update the command ring indicies */
	offset = (off_t)((uint64_t)((unsigned long)&(pgp->cmdGetInx)) -
	    (uint64_t)((unsigned long)hba->slim2.virt));
	emlxs_mpdata_sync(hba->slim2.dma_handle, offset, 4,
	    DDI_DMA_SYNC_FORKERNEL);
	rp->fc_cmdidx = rp->fc_port_cmdidx = PCIMEM_LONG(pgp->cmdGetInx);

	for (i = 0; i < MAX_VPORTS; i++) {
		vport = &VPORT(i);

		if (!(vport->flag & EMLXS_PORT_BOUND)) {
			continue;
		}

		/* Clear all node XRI contexts */
		rw_enter(&vport->node_rwlock, RW_WRITER);
		mutex_enter(&EMLXS_RINGTX_LOCK);
		for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
			ndlp = vport->node_table[i];
			while (ndlp != NULL) {
				ndlp->nlp_flag[FC_IP_RING] &= ~NLP_RPI_XRI;
				ndlp = ndlp->nlp_list_next;
			}
		}
		mutex_exit(&EMLXS_RINGTX_LOCK);
		rw_exit(&vport->node_rwlock);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ring_reset_msg, "%s",
	    emlxs_ring_xlate(ringno));

	return (FC_SUCCESS);

}  /* emlxs_reset_ring() */


/*
 * emlxs_handle_mb_event
 *
 * Description: Process a Mailbox Attention.
 * Called from host_interrupt to process MBATT
 *
 *   Returns:
 *
 */
extern uint32_t
emlxs_handle_mb_event(emlxs_hba_t *hba)
{
	emlxs_port_t		*port = &PPORT;
	MAILBOX			*mb;
	MAILBOX			*swpmb;
	MAILBOX			*mbox;
	MAILBOXQ		*mbq;
	emlxs_config_t		*cfg;
	uint32_t		control;
	volatile uint32_t	word0;
	MATCHMAP		*mbox_bp;
	uint32_t		la_enable;
	off_t			offset;
	uint32_t		i;
	MAILBOXQ		mailbox;

	cfg = &CFG;
	swpmb = (MAILBOX *)&word0;
	mb = (MAILBOX *)&mailbox;

	switch (hba->mbox_queue_flag) {
	case 0:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_stray_mbox_intr_msg,
		    "No mailbox active.");
		return (0);

	case MBX_POLL:

		/* Mark mailbox complete, this should wake up any polling */
		/* threads. This can happen if interrupts are enabled while */
		/* a polled mailbox command is outstanding. If we don't set */
		/* MBQ_COMPLETED here, the polling thread may wait until */
		/* timeout error occurs */

		mutex_enter(&EMLXS_MBOX_LOCK);
		mbq = (MAILBOXQ *)hba->mbox_mbq;
		if (mbq) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
			    "Mailbox event. Completing Polled command.");
			mbq->flag |= MBQ_COMPLETED;
		}
		mutex_exit(&EMLXS_MBOX_LOCK);

		return (0);

	case MBX_SLEEP:
	case MBX_NOWAIT:
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_completion_error_msg,
		    "Invalid Mailbox flag (%x).");
		return (0);
	}

	/* Get first word of mailbox */
	if (hba->flag & FC_SLIM2_MODE) {
		mbox = FC_SLIM2_MAILBOX(hba);
		offset = (off_t)((uint64_t)((unsigned long)mbox)
		    - (uint64_t)((unsigned long)hba->slim2.virt));

		emlxs_mpdata_sync(hba->slim2.dma_handle, offset,
		    sizeof (uint32_t), DDI_DMA_SYNC_FORKERNEL);
		word0 = *((volatile uint32_t *)mbox);
		word0 = PCIMEM_LONG(word0);
	} else {
		mbox = FC_SLIM1_MAILBOX(hba);
		word0 = READ_SLIM_ADDR(hba, ((volatile uint32_t *)mbox));
	}

	i = 0;
	while (swpmb->mbxOwner == OWN_CHIP) {
		if (i++ > 10000) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_stray_mbox_intr_msg,
			    "OWN_CHIP: %s: status=%x",
			    emlxs_mb_cmd_xlate(swpmb->mbxCommand),
			    swpmb->mbxStatus);

			return (1);
		}

		/* Get first word of mailbox */
		if (hba->flag & FC_SLIM2_MODE) {
			emlxs_mpdata_sync(hba->slim2.dma_handle, offset,
			    sizeof (uint32_t), DDI_DMA_SYNC_FORKERNEL);
			word0 = *((volatile uint32_t *)mbox);
			word0 = PCIMEM_LONG(word0);
		} else {
			word0 =
			    READ_SLIM_ADDR(hba, ((volatile uint32_t *)mbox));
		}
		}

	/* Now that we are the owner, DMA Sync entire mailbox if needed */
	if (hba->flag & FC_SLIM2_MODE) {
		emlxs_mpdata_sync(hba->slim2.dma_handle, offset,
		    MAILBOX_CMD_BSIZE, DDI_DMA_SYNC_FORKERNEL);
		emlxs_pcimem_bcopy((uint32_t *)mbox, (uint32_t *)mb,
		    MAILBOX_CMD_BSIZE);
	} else {
		READ_SLIM_COPY(hba, (uint32_t *)mb, (uint32_t *)mbox,
		    MAILBOX_CMD_WSIZE);
	}

#ifdef MBOX_EXT_SUPPORT
	if (hba->mbox_ext) {
		uint32_t *mbox_ext =
		    (uint32_t *)((uint8_t *)mbox + MBOX_EXTENSION_OFFSET);
		off_t offset_ext   = offset + MBOX_EXTENSION_OFFSET;

		if (hba->flag & FC_SLIM2_MODE) {
			emlxs_mpdata_sync(hba->slim2.dma_handle, offset_ext,
			    hba->mbox_ext_size, DDI_DMA_SYNC_FORKERNEL);
			emlxs_pcimem_bcopy(mbox_ext,
			    (uint32_t *)hba->mbox_ext, hba->mbox_ext_size);
		} else {
			READ_SLIM_COPY(hba, (uint32_t *)hba->mbox_ext,
			    mbox_ext, (hba->mbox_ext_size / 4));
		}
		}
#endif /* MBOX_EXT_SUPPORT */

	/* Now sync the memory buffer if one was used */
	if (hba->mbox_bp) {
		mbox_bp = (MATCHMAP *)hba->mbox_bp;
		emlxs_mpdata_sync(mbox_bp->dma_handle, 0, mbox_bp->size,
		    DDI_DMA_SYNC_FORKERNEL);
	}

	/* Mailbox has been completely received at this point */

	if (mb->mbxCommand == MBX_HEARTBEAT) {
		hba->heartbeat_active = 0;
		goto done;
	}

	if (hba->mbox_queue_flag == MBX_SLEEP) {
		if (swpmb->mbxCommand != MBX_DOWN_LOAD &&
		    swpmb->mbxCommand != MBX_DUMP_MEMORY) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
			    "Received.  %s: status=%x Sleep.",
			    emlxs_mb_cmd_xlate(swpmb->mbxCommand),
			    swpmb->mbxStatus);
		}
	} else {
		if (swpmb->mbxCommand != MBX_DOWN_LOAD &&
		    swpmb->mbxCommand != MBX_DUMP_MEMORY) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
			    "Completed. %s: status=%x",
			    emlxs_mb_cmd_xlate(swpmb->mbxCommand),
			    swpmb->mbxStatus);
		}
	}

	/* Filter out passthru mailbox */
	if (hba->mbox_mbqflag & MBQ_PASSTHRU) {
		goto done;
	}

	/* If succesful, process the result */
	if (mb->mbxStatus == 0) {
		(void) emlxs_mb_handle_cmd(hba, mb);
		goto done;
	}

	/* ERROR RETURNED */

	/* Check for no resources */
	if ((mb->mbxStatus == MBXERR_NO_RESOURCES) &&
	    (hba->mbox_queue_flag == MBX_NOWAIT)) {
		/* Retry only MBX_NOWAIT requests */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_event_msg,
		    "Retrying.  %s: status=%x",
		    emlxs_mb_cmd_xlate(mb->mbxCommand),
		    (uint32_t)mb->mbxStatus);

		if ((mbox = (MAILBOX *)emlxs_mem_get(hba, MEM_MBOX))) {
			bcopy((uint8_t *)mb, (uint8_t *)mbox,
			    MAILBOX_CMD_BSIZE);

			switch (mbox->mbxCommand) {
			case MBX_READ_SPARM:
				control = mbox->un.varRdSparm.un.sp.bdeSize;
				if (control == 0) {
					(void) emlxs_mb_read_sparam(hba, mbox);
				}
				break;

			case MBX_READ_SPARM64:
				control =
				    mbox->un.varRdSparm.un.sp64.tus.f.bdeSize;
				if (control == 0) {
					(void) emlxs_mb_read_sparam(hba, mbox);
				}
				break;

			case MBX_REG_LOGIN:
				control = mbox->un.varRegLogin.un.sp.bdeSize;
				if (control == 0) {
#ifdef NPIV_SUPPORT
					/* Special handle for vport PLOGI */
					if (hba->mbox_iocbq == (uint8_t *)1) {
						hba->mbox_iocbq = NULL;
					}
#endif /* NPIV_SUPPORT */
					goto done;
				}
				break;

			case MBX_REG_LOGIN64:
				control =
				    mbox->un.varRegLogin.un.sp64.tus.f.
				    bdeSize;
				if (control == 0) {
#ifdef NPIV_SUPPORT
					/* Special handle for vport PLOGI */
					if (hba->mbox_iocbq == (uint8_t *)1) {
						hba->mbox_iocbq = NULL;
					}
#endif /* NPIV_SUPPORT */
					goto done;
				}
				break;

			case MBX_READ_LA:
				control =
				    mbox->un.varReadLA.un.lilpBde.bdeSize;
				if (control == 0) {
					(void) emlxs_mb_read_la(hba, mbox);
				}
				break;

			case MBX_READ_LA64:
				control =
				    mbox->un.varReadLA.un.lilpBde64.tus.f.
				    bdeSize;
				if (control == 0) {
					(void) emlxs_mb_read_la(hba, mbox);
				}
				break;
			}

			mbox->mbxOwner = OWN_HOST;
			mbox->mbxStatus = 0;

			/* Refresh the mailbox area */
			emlxs_mb_retry(hba, mbox);

			if (emlxs_sli_issue_mbox_cmd(hba, mbox, MBX_NOWAIT,
			    0) != MBX_BUSY) {
				(void) emlxs_mem_put(hba, MEM_MBOX,
				    (uint8_t *)mbox);
			}

			return (0);
		}
	}


	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_completion_error_msg,
	    "%s: status=0x%x", emlxs_mb_cmd_xlate(mb->mbxCommand),
	    (uint32_t)mb->mbxStatus);

	/*
	 * ERROR: process mailbox command error
	 */
	switch (mb->mbxCommand) {
	case MBX_REG_LOGIN:
	case MBX_REG_LOGIN64:

		if (mb->mbxStatus == MBXERR_RPI_FULL) {
#ifdef SLI3_SUPPORT
			port = &VPORT(mb->un.varRegLogin.vpi);
#endif	/* SLI3_SUPPORT */

			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_node_create_failed_msg,
			    "Limit reached. count=%d", port->node_count);
		}

#ifdef NPIV_SUPPORT
		/* Special handle for vport PLOGI */
		if (hba->mbox_iocbq == (uint8_t *)1) {
			hba->mbox_iocbq = NULL;
		}
#endif /* NPIV_SUPPORT */
		break;

	case MBX_READ_LA:
	case MBX_READ_LA64:

		/* Enable Link Attention interrupts */
		mutex_enter(&EMLXS_PORT_LOCK);

		if (!(hba->hc_copy & HC_LAINT_ENA)) {
			hba->hc_copy |= HC_LAINT_ENA;
			WRITE_CSR_REG(hba, FC_HC_REG(hba, hba->csr_addr),
			    hba->hc_copy);
		}

		mutex_exit(&EMLXS_PORT_LOCK);

		break;


	case MBX_CLEAR_LA:

		la_enable = 1;

		if (mb->mbxStatus == 0x1601) {
			/* Get a buffer which will be used for */
			/* mailbox commands */
			if ((mbox = (MAILBOX *)emlxs_mem_get(hba,
			    MEM_MBOX | MEM_PRI))) {
				/* Get link attention message */
				if (emlxs_mb_read_la(hba, mbox) == 0) {
					if (emlxs_sli_issue_mbox_cmd(hba, mbox,
					    MBX_NOWAIT, 0) != MBX_BUSY) {
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
			if (!(hba->hc_copy & HC_LAINT_ENA)) {
				/* Enable Link Attention interrupts */
				hba->hc_copy |= HC_LAINT_ENA;
				WRITE_CSR_REG(hba,
				    FC_HC_REG(hba, hba->csr_addr),
				    hba->hc_copy);
			}
		} else {
			if (hba->hc_copy & HC_LAINT_ENA) {
				/* Disable Link Attention interrupts */
				hba->hc_copy &= ~HC_LAINT_ENA;
				WRITE_CSR_REG(hba,
				    FC_HC_REG(hba, hba->csr_addr),
				    hba->hc_copy);
			}
		}
		mutex_exit(&EMLXS_PORT_LOCK);

		break;

	case MBX_INIT_LINK:
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

				if ((mbox = (MAILBOX *)emlxs_mem_get(hba,
				    MEM_MBOX))) {
					bcopy((uint8_t *)mb, (uint8_t *)mbox,
					    MAILBOX_CMD_BSIZE);

					mbox->un.varInitLnk.link_flags &=
					    ~FLAGS_LINK_SPEED;
					mbox->un.varInitLnk.link_speed = 0;
					mbox->mbxOwner = OWN_HOST;
					mbox->mbxStatus = 0;

					/* Refresh the mailbox area */
					emlxs_mb_retry(hba, mbox);

					if (emlxs_sli_issue_mbox_cmd(hba, mbox,
					    MBX_NOWAIT, 0) != MBX_BUSY) {
						(void) emlxs_mem_put(hba,
						    MEM_MBOX, (uint8_t *)mbox);
					}
					return (0);
				}
			}
		}
		break;
	}

done:

	/* Clean up the mailbox area */
	emlxs_mb_fini(hba, mb, mb->mbxStatus);

	/* Attempt to send pending mailboxes */
	if ((mbox = (MAILBOX *)emlxs_mb_get(hba))) {
		if (emlxs_sli_issue_mbox_cmd(hba, mbox, MBX_NOWAIT, 0) !=
		    MBX_BUSY) {
			(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbox);
		}
	}

	return (0);

}	/* emlxs_handle_mb_event() */



/*
 * emlxs_mb_handle_cmd
 *
 * Description: Process a Mailbox Command.
 * Called from host_interrupt to process MBATT
 *
 *   Returns:
 *
 */
static int
emlxs_mb_handle_cmd(emlxs_hba_t *hba, MAILBOX *mb)
{
	emlxs_port_t		*port = &PPORT;
	emlxs_port_t		*vport;
	MAILBOXQ		*mbox;
	NODELIST		*ndlp;
	volatile SERV_PARM	*sp;
	int32_t			i;
	uint32_t		ldata;
	uint32_t		ldid;
	uint16_t		lrpi;
	uint16_t		lvpi;
	MATCHMAP		*mp;
	uint8_t			*wwn;
	READ_LA_VAR		la;
	emlxs_vvl_fmt_t		vvl;

	if (mb->mbxStatus != 0) {
		return (1);
	}

	mp = (MATCHMAP *)hba->mbox_bp;

	/*
	 * Mailbox command completed successfully, process completion
	 */
	switch (mb->mbxCommand) {
	case MBX_SHUTDOWN:
	case MBX_LOAD_SM:
	case MBX_READ_NV:
	case MBX_WRITE_NV:
	case MBX_RUN_BIU_DIAG:
	case MBX_RUN_BIU_DIAG64:
	case MBX_INIT_LINK:
	case MBX_DOWN_LINK:
	case MBX_CONFIG_LINK:
	case MBX_PART_SLIM:
	case MBX_CONFIG_RING:
	case MBX_RESET_RING:
	case MBX_READ_CONFIG:
	case MBX_READ_RCONFIG:
	case MBX_READ_STATUS:
	case MBX_READ_XRI:
	case MBX_READ_REV:
	case MBX_READ_LNK_STAT:
	case MBX_UNREG_LOGIN:
	case MBX_DUMP_MEMORY:
	case MBX_DUMP_CONTEXT:
	case MBX_RUN_DIAGS:
	case MBX_RESTART:
	case MBX_UPDATE_CFG:
	case MBX_DOWN_LOAD:
	case MBX_DEL_LD_ENTRY:
	case MBX_RUN_PROGRAM:
	case MBX_SET_MASK:
	case MBX_SET_VARIABLE:
	case MBX_UNREG_D_ID:
	case MBX_KILL_BOARD:
	case MBX_CONFIG_FARP:
	case MBX_LOAD_AREA:
	case MBX_CONFIG_PORT:
	case MBX_CONFIG_MSI:
	case MBX_FLASH_WR_ULA:
	case MBX_SET_DEBUG:
	case MBX_GET_DEBUG:
	case MBX_LOAD_EXP_ROM:
	case MBX_BEACON:
	case MBX_READ_RPI:
	case MBX_READ_RPI64:
	case MBX_REG_VPI:
	case MBX_UNREG_VPI:
	case MBX_CONFIG_HBQ:
	case MBX_ASYNC_EVENT:
	case MBX_HEARTBEAT:
	case MBX_READ_EVENT_LOG_STATUS:
	case MBX_READ_EVENT_LOG:
	case MBX_WRITE_EVENT_LOG:
	case MBX_NV_LOG:
	case MBX_PORT_CAPABILITIES:
	case MBX_IOV_CONTROL:
	case MBX_IOV_MBX:
		break;

	case MBX_CONFIG_MSIX:
		break;

	case MBX_READ_SPARM:	/* a READ SPARAM command completed */
	case MBX_READ_SPARM64:	/* a READ SPARAM command completed */
	{
		if (mp) {
			bcopy((caddr_t)mp->virt, (caddr_t)&hba->sparam,
			    sizeof (SERV_PARM));

			bcopy((caddr_t)&hba->sparam.nodeName,
			    (caddr_t)&hba->wwnn, sizeof (NAME_TYPE));

			bcopy((caddr_t)&hba->sparam.portName,
			    (caddr_t)&hba->wwpn, sizeof (NAME_TYPE));

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

		}
		break;
	}


	case MBX_REG_LOGIN:
	case MBX_REG_LOGIN64:

		if (!mp) {
			break;
		}
#ifdef SLI3_SUPPORT
		ldata = mb->un.varWords[5];
		lvpi = ldata & 0xffff;
		port = &VPORT(lvpi);
#endif	/* SLI3_SUPPORT */

		/* First copy command data */
		ldata = mb->un.varWords[0];	/* get rpi */
		lrpi = ldata & 0xffff;

		ldata = mb->un.varWords[1];	/* get did */
		ldid = ldata & Mask_DID;

		sp = (volatile SERV_PARM *)mp->virt;
		ndlp = emlxs_node_find_did(port, ldid);

		if (!ndlp) {
			/* Attempt to create a node */
			if ((ndlp = (NODELIST *)emlxs_mem_get(hba, MEM_NLP))) {
				ndlp->nlp_Rpi = lrpi;
				ndlp->nlp_DID = ldid;

				bcopy((uint8_t *)sp,
				    (uint8_t *)&ndlp->sparm,
				    sizeof (SERV_PARM));

				bcopy((uint8_t *)&sp->nodeName,
				    (uint8_t *)&ndlp->nlp_nodename,
				    sizeof (NAME_TYPE));

				bcopy((uint8_t *)&sp->portName,
				    (uint8_t *)&ndlp->nlp_portname,
				    sizeof (NAME_TYPE));

				ndlp->nlp_active = 1;
				ndlp->nlp_flag[FC_CT_RING]  |= NLP_CLOSED;
				ndlp->nlp_flag[FC_ELS_RING] |= NLP_CLOSED;
				ndlp->nlp_flag[FC_FCP_RING] |= NLP_CLOSED;
				ndlp->nlp_flag[FC_IP_RING]  |= NLP_CLOSED;

				/* Add the node */
				emlxs_node_add(port, ndlp);

				/* Open the node */
				emlxs_node_open(port, ndlp, FC_CT_RING);
				emlxs_node_open(port, ndlp, FC_ELS_RING);
				emlxs_node_open(port, ndlp, FC_IP_RING);
				emlxs_node_open(port, ndlp, FC_FCP_RING);
			} else {
				wwn = (uint8_t *)&sp->portName;
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_node_create_failed_msg,
				    "Unable to allocate node. did=%06x rpi=%x "
				    "wwpn=%02x%02x%02x%02x%02x%02x%02x%02x",
				    ldid, lrpi, wwn[0], wwn[1], wwn[2],
				    wwn[3], wwn[4], wwn[5], wwn[6], wwn[7]);

				break;
			}
		} else {
			mutex_enter(&EMLXS_PORT_LOCK);

			ndlp->nlp_Rpi = lrpi;
			ndlp->nlp_DID = ldid;

			bcopy((uint8_t *)sp,
			    (uint8_t *)&ndlp->sparm, sizeof (SERV_PARM));

			bcopy((uint8_t *)&sp->nodeName,
			    (uint8_t *)&ndlp->nlp_nodename,
			    sizeof (NAME_TYPE));

			bcopy((uint8_t *)&sp->portName,
			    (uint8_t *)&ndlp->nlp_portname,
			    sizeof (NAME_TYPE));

			wwn = (uint8_t *)&ndlp->nlp_portname;
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_node_update_msg,
			    "node=%p did=%06x rpi=%x "
			    "wwpn=%02x%02x%02x%02x%02x%02x%02x%02x",
			    ndlp, ndlp->nlp_DID, ndlp->nlp_Rpi, wwn[0],
			    wwn[1], wwn[2], wwn[3], wwn[4], wwn[5], wwn[6],
			    wwn[7]);

			mutex_exit(&EMLXS_PORT_LOCK);

			/* Open the node */
			emlxs_node_open(port, ndlp, FC_CT_RING);
			emlxs_node_open(port, ndlp, FC_ELS_RING);
			emlxs_node_open(port, ndlp, FC_IP_RING);
			emlxs_node_open(port, ndlp, FC_FCP_RING);
		}

		bzero((char *)&vvl, sizeof (emlxs_vvl_fmt_t));

		if (sp->valid_vendor_version) {

			bcopy((caddr_t *)&sp->vendorVersion[0],
			    (caddr_t *)&vvl, sizeof (emlxs_vvl_fmt_t));

			vvl.un0.word0 = SWAP_DATA32(vvl.un0.word0);
			vvl.un1.word1 = SWAP_DATA32(vvl.un1.word1);

			if ((vvl.un0.w0.oui == 0x0000C9) &&
			    (vvl.un1.w1.vport)) {
				ndlp->nlp_fcp_info |= NLP_EMLX_VPORT;
			}
		}

		/* If this was a fabric login */
		if (ndlp->nlp_DID == Fabric_DID) {
			/* If CLEAR_LA has been sent, then attempt to */
			/* register the vpi now */
			if (hba->state == FC_READY) {
				(void) emlxs_mb_reg_vpi(port);
			}
#ifdef SLI3_SUPPORT
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
					    !(vport->flag &
					    EMLXS_PORT_ENABLE)) {
						continue;
					}

					emlxs_port_online(vport);
				}
			}
#endif	/* SLI3_SUPPORT */

		}
#ifdef NPIV_SUPPORT
		if (hba->mbox_iocbq == (uint8_t *)1) {
			hba->mbox_iocbq = NULL;
			(void) emlxs_mb_unreg_did(port, ldid, NULL, NULL, NULL);
		}
#endif /* NPIV_SUPPORT */

#ifdef DHCHAP_SUPPORT
		if (hba->mbox_sbp || hba->mbox_ubp) {
			if (emlxs_dhc_auth_start(port, ndlp, hba->mbox_sbp,
			    hba->mbox_ubp) == 0) {
				/* Auth started - auth completion will */
				/* handle sbp and ubp now */
				hba->mbox_sbp = NULL;
				hba->mbox_ubp = NULL;
			}
		}
#endif	/* DHCHAP_SUPPORT */

#ifdef SFCT_SUPPORT
		if (hba->mbox_sbp && ((emlxs_buf_t *)hba->mbox_sbp)->fct_cmd) {
			emlxs_buf_t *cmd_sbp = (emlxs_buf_t *)hba->mbox_sbp;

			if (cmd_sbp->fct_state == EMLXS_FCT_REG_PENDING) {
				hba->mbox_sbp = NULL;

				mutex_enter(&cmd_sbp->fct_mtx);
				emlxs_fct_state_chg(fct_cmd, cmd_sbp,
				    EMLXS_FCT_REG_COMPLETE);
				mutex_exit(&cmd_sbp->fct_mtx);

				mutex_enter(&EMLXS_PKT_LOCK);
				cmd_sbp->node = ndlp;
				cv_broadcast(&EMLXS_PKT_CV);
				mutex_exit(&EMLXS_PKT_LOCK);
			}
		}
#endif /* SFCT_SUPPORT */

		break;

	case MBX_READ_LA:
	case MBX_READ_LA64:
	{
		bcopy((uint32_t *)((char *)mb + sizeof (uint32_t)),
		    (uint32_t *)&la, sizeof (READ_LA_VAR));

		if (mp) {
			bcopy((caddr_t)mp->virt, (caddr_t)port->alpa_map,
			    128);
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

			if (hba->state > FC_LINK_DOWN) {
				/* Declare link down here */
				emlxs_linkdown(hba);
			}
		}

		hba->link_event_tag = la.eventTag;
		port->lip_type = 0;

		/* If link not already up then declare it up now */
		if ((la.attType == AT_LINK_UP) && (hba->state < FC_LINK_UP)) {

#ifdef MENLO_SUPPORT
			if ((hba->model_info.device_id ==
			    PCI_DEVICE_ID_LP21000_M) &&
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
					uint8_t		*alpa_map;
					uint32_t	j;

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
					thread_create(NULL, 0,
					    emlxs_fcoe_attention_thread,
					    (char *)hba, 0, &p0, TS_RUN,
					    v.v_maxsyspri - 2);
				}
			}
#endif /* MENLO_SUPPORT */

			if ((mbox = (MAILBOXQ *)emlxs_mem_get(hba,
			    MEM_MBOX | MEM_PRI))) {
				/* This should turn on DELAYED ABTS for */
				/* ELS timeouts */
				emlxs_mb_set_var(hba, (MAILBOX *)mbox,
				    0x00052198, 0x1);

					emlxs_mb_put(hba, mbox);
			}

			if ((mbox = (MAILBOXQ *)emlxs_mem_get(hba,
			    MEM_MBOX | MEM_PRI))) {
				/* If link not already down then */
				/* declare it down now */
				if (emlxs_mb_read_sparam(hba,
				    (MAILBOX *)mbox) == 0) {
					emlxs_mb_put(hba, mbox);
				} else {
					(void) emlxs_mem_put(hba, MEM_MBOX,
					    (uint8_t *)mbox);
				}
			}

			if ((mbox = (MAILBOXQ *)emlxs_mem_get(hba,
			    MEM_MBOX | MEM_PRI))) {
				emlxs_mb_config_link(hba, (MAILBOX *)mbox);

				emlxs_mb_put(hba, mbox);
			}

			/* Declare the linkup here */
			emlxs_linkup(hba);
		}

		/* If link not already down then declare it down now */
		else if ((la.attType == AT_LINK_DOWN) &&
		    (hba->state > FC_LINK_DOWN)) {
			/* Declare link down here */
			emlxs_linkdown(hba);
		}

		/* Enable Link attention interrupt */
		mutex_enter(&EMLXS_PORT_LOCK);

		if (!(hba->hc_copy & HC_LAINT_ENA)) {
			hba->hc_copy |= HC_LAINT_ENA;
			WRITE_CSR_REG(hba, FC_HC_REG(hba, hba->csr_addr),
			    hba->hc_copy);
		}

		mutex_exit(&EMLXS_PORT_LOCK);

		/* Log the link event */
		emlxs_log_link_event(port);

		break;
	}

	case MBX_CLEAR_LA:
		/* Enable on Link Attention interrupts */
		mutex_enter(&EMLXS_PORT_LOCK);

		if (!(hba->hc_copy & HC_LAINT_ENA)) {
			hba->hc_copy |= HC_LAINT_ENA;
			WRITE_CSR_REG(hba, FC_HC_REG(hba, hba->csr_addr),
			    hba->hc_copy);
		}

		if (hba->state >= FC_LINK_UP) {
			emlxs_ffstate_change_locked(hba, FC_READY);
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

				(void) emlxs_mb_reg_vpi(vport);
			}

			/* Attempt to send any pending IO */
			emlxs_sli_issue_iocb_cmd(hba, &hba->ring[FC_FCP_RING],
			    0);
		}

		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_completion_error_msg,
		    "Unknown mailbox cmd: 0x%x", mb->mbxCommand);
		HBASTATS.MboxInvalid++;
		break;
	}

	return (0);

} /* emlxs_mb_handle_cmd() */


void
emlxs_timer_check_mbox(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg = &CFG;
	MAILBOX *mb;
	uint32_t word0;
	uint32_t offset;
	uint32_t ha_copy = 0;

	if (!cfg[CFG_TIMEOUT_ENABLE].current) {
		return;
	}

	mutex_enter(&EMLXS_PORT_LOCK);

	/* Return if timer hasn't expired */
	if (!hba->mbox_timer || (hba->timer_tics < hba->mbox_timer)) {
		mutex_exit(&EMLXS_PORT_LOCK);
		return;
	}
	hba->mbox_timer = 0;

	/* Mailbox timed out, first check for error attention */
	ha_copy = emlxs_check_attention(hba);

	if (ha_copy & HA_ERATT) {
		mutex_exit(&EMLXS_PORT_LOCK);
		emlxs_handle_ff_error(hba);
		return;
	}

	if (hba->mbox_queue_flag) {
		/* Get first word of mailbox */
		if (hba->flag & FC_SLIM2_MODE) {
			mb = FC_SLIM2_MAILBOX(hba);
			offset = (off_t)((uint64_t)((unsigned long)mb)
			    - (uint64_t)((unsigned long)hba->slim2.virt));

			emlxs_mpdata_sync(hba->slim2.dma_handle, offset,
			    sizeof (uint32_t), DDI_DMA_SYNC_FORKERNEL);
			word0 = *((volatile uint32_t *)mb);
			word0 = PCIMEM_LONG(word0);
		} else {
			mb = FC_SLIM1_MAILBOX(hba);
			word0 =
			    READ_SLIM_ADDR(hba, ((volatile uint32_t *)mb));
		}

		mb = (MAILBOX *)&word0;

		/* Check if mailbox has actually completed */
		if (mb->mbxOwner == OWN_HOST) {
			/* Read host attention register to determine */
			/* interrupt source */
			uint32_t ha_copy = emlxs_check_attention(hba);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
			    "Mailbox attention missed: %s. Forcing event. "
			    "hc=%x ha=%x", emlxs_mb_cmd_xlate(mb->mbxCommand),
			    hba->hc_copy, ha_copy);

			mutex_exit(&EMLXS_PORT_LOCK);

			(void) emlxs_handle_mb_event(hba);

			return;
		}

		if (hba->mbox_mbq) {
			mb = (MAILBOX *)hba->mbox_mbq;
		}
	}

	switch (hba->mbox_queue_flag) {
	case MBX_NOWAIT:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_timeout_msg,
		    "%s: Nowait.", emlxs_mb_cmd_xlate(mb->mbxCommand));
		break;

	case MBX_SLEEP:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_timeout_msg,
		    "%s: mb=%p Sleep.", emlxs_mb_cmd_xlate(mb->mbxCommand),
		    mb);
		break;

	case MBX_POLL:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_timeout_msg,
		    "%s: mb=%p Polled.", emlxs_mb_cmd_xlate(mb->mbxCommand),
		    mb);
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_timeout_msg, NULL);
		break;
	}

	hba->flag |= FC_MBOX_TIMEOUT;
	emlxs_ffstate_change_locked(hba, FC_ERROR);

	mutex_exit(&EMLXS_PORT_LOCK);

	/* Perform mailbox cleanup */
	/* This will wake any sleeping or polling threads */
	emlxs_mb_fini(hba, NULL, MBX_TIMEOUT);

	/* Trigger adapter shutdown */
	thread_create(NULL, 0, emlxs_shutdown_thread, (char *)hba, 0,
	    &p0, TS_RUN, v.v_maxsyspri - 2);

	return;

}  /* emlxs_timer_check_mbox() */


/*
 * emlxs_mb_config_port  Issue a CONFIG_PORT mailbox command
 */
uint32_t
emlxs_mb_config_port(emlxs_hba_t *hba, MAILBOX *mb, uint32_t sli_mode,
    uint32_t hbainit)
{
	emlxs_vpd_t	*vpd = &VPD;
	emlxs_port_t	*port = &PPORT;
	emlxs_config_t	*cfg;
	RING		*rp;
	uint64_t	pcb;
	uint64_t	mbx;
	uint64_t	hgp;
	uint64_t	pgp;
	uint64_t	rgp;
	MAILBOX		*mbox;
	SLIM2		*slim;
	SLI2_RDSC	*rdsc;
	uint64_t	offset;
	uint32_t	Laddr;
	uint32_t	i;

	cfg = &CFG;
	bzero((void *)mb, MAILBOX_CMD_BSIZE);
	mbox = NULL;
	slim = NULL;

	mb->mbxCommand = MBX_CONFIG_PORT;
	mb->mbxOwner = OWN_HOST;

	mb->un.varCfgPort.pcbLen = sizeof (PCB);

#ifdef SLI3_SUPPORT
	mb->un.varCfgPort.hbainit[0] = hbainit;
#else	/* SLI3_SUPPORT */
	mb->un.varCfgPort.hbainit = hbainit;
#endif	/* SLI3_SUPPORT */

	pcb = hba->slim2.phys + (uint64_t)((unsigned long)&(slim->pcb));
	mb->un.varCfgPort.pcbLow = putPaddrLow(pcb);
	mb->un.varCfgPort.pcbHigh = putPaddrHigh(pcb);

	/* Set Host pointers in SLIM flag */
	mb->un.varCfgPort.hps = 1;

	/* Initialize hba structure for assumed default SLI2 mode */
	/* If config port succeeds, then we will update it then   */
	hba->sli_mode = sli_mode;
	hba->vpi_max = 1;
	hba->flag &= ~FC_NPIV_ENABLED;

#ifdef SLI3_SUPPORT
	if (sli_mode >= EMLXS_HBA_SLI3_MODE) {
		mb->un.varCfgPort.sli_mode = EMLXS_HBA_SLI3_MODE;
		mb->un.varCfgPort.cerbm = 1;
		mb->un.varCfgPort.max_hbq = EMLXS_NUM_HBQ;

#ifdef NPIV_SUPPORT
		if (cfg[CFG_NPIV_ENABLE].current) {
			if (vpd->feaLevelHigh >= 0x09) {
				if (hba->model_info.chip >= EMLXS_SATURN_CHIP) {
					mb->un.varCfgPort.vpi_max =
					    MAX_VPORTS - 1;
				} else {
					mb->un.varCfgPort.vpi_max =
					    MAX_VPORTS_LIMITED - 1;
				}

				mb->un.varCfgPort.cmv = 1;
			} else {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_init_debug_msg,
				    "CFGPORT: Firmware does not support NPIV. "
				    "level=%d", vpd->feaLevelHigh);
			}

		}
#endif	/* NPIV_SUPPORT */
	}
#endif	/* SLI3_SUPPORT */

	/*
	 * Now setup pcb
	 */
	((SLIM2 *)hba->slim2.virt)->pcb.type = TYPE_NATIVE_SLI2;
	((SLIM2 *)hba->slim2.virt)->pcb.feature = FEATURE_INITIAL_SLI2;
	((SLIM2 *)hba->slim2.virt)->pcb.maxRing = (hba->ring_count - 1);
	((SLIM2 *)hba->slim2.virt)->pcb.mailBoxSize =
	    sizeof (MAILBOX) + MBOX_EXTENSION_SIZE;

	mbx = hba->slim2.phys + (uint64_t)((unsigned long)&(slim->mbx));
	((SLIM2 *)hba->slim2.virt)->pcb.mbAddrHigh = putPaddrHigh(mbx);
	((SLIM2 *)hba->slim2.virt)->pcb.mbAddrLow = putPaddrLow(mbx);


	/*
	 * Set up HGP - Port Memory
	 *
	 * CR0Put   - SLI2(no HBQs) =	0xc0, With HBQs =	0x80
	 * RR0Get			0xc4			0x84
	 * CR1Put			0xc8			0x88
	 * RR1Get			0xcc			0x8c
	 * CR2Put			0xd0			0x90
	 * RR2Get			0xd4			0x94
	 * CR3Put			0xd8			0x98
	 * RR3Get			0xdc			0x9c
	 *
	 * Reserved			0xa0-0xbf
	 *
	 * If HBQs configured:
	 * HBQ 0 Put ptr  0xc0
	 * HBQ 1 Put ptr  0xc4
	 * HBQ 2 Put ptr  0xc8
	 * ...
	 * HBQ(M-1)Put Pointer 0xc0+(M-1)*4
	 */

#ifdef SLI3_SUPPORT
	if (sli_mode >= EMLXS_HBA_SLI3_MODE) {
		/* ERBM is enabled */
		hba->hgp_ring_offset = 0x80;
		hba->hgp_hbq_offset = 0xC0;

		hba->iocb_cmd_size = SLI3_IOCB_CMD_SIZE;
		hba->iocb_rsp_size = SLI3_IOCB_RSP_SIZE;

	} else	/* SLI2 */
#endif	/* SLI3_SUPPORT */
	{
		/* ERBM is disabled */
		hba->hgp_ring_offset = 0xC0;
		hba->hgp_hbq_offset = 0;

		hba->iocb_cmd_size = SLI2_IOCB_CMD_SIZE;
		hba->iocb_rsp_size = SLI2_IOCB_RSP_SIZE;
	}

	/* The Sbus card uses Host Memory. The PCI card uses SLIM POINTER */
	if (hba->bus_type == SBUS_FC) {
		hgp = hba->slim2.phys +
		    (uint64_t)((unsigned long)&(mbox->us.s2.host));
		((SLIM2 *)hba->slim2.virt)->pcb.hgpAddrHigh = putPaddrHigh(hgp);
		((SLIM2 *)hba->slim2.virt)->pcb.hgpAddrLow = putPaddrLow(hgp);
	} else {
		((SLIM2 *)hba->slim2.virt)->pcb.hgpAddrHigh =
		    (uint32_t)ddi_get32(hba->pci_acc_handle,
		    (uint32_t *)(hba->pci_addr + PCI_BAR_1_REGISTER));

		Laddr =
		    ddi_get32(hba->pci_acc_handle,
		    (uint32_t *)(hba->pci_addr + PCI_BAR_0_REGISTER));
		Laddr &= ~0x4;
		((SLIM2 *)hba->slim2.virt)->pcb.hgpAddrLow =
		    (uint32_t)(Laddr + hba->hgp_ring_offset);

	}

	pgp = hba->slim2.phys + (uint64_t)((unsigned long)&(mbox->us.s2.port));
	((SLIM2 *)hba->slim2.virt)->pcb.pgpAddrHigh = putPaddrHigh(pgp);
	((SLIM2 *)hba->slim2.virt)->pcb.pgpAddrLow = putPaddrLow(pgp);

	offset = 0;
	for (i = 0; i < 4; i++) {
		rp = &hba->ring[i];
		rdsc = &((SLIM2 *)hba->slim2.virt)->pcb.rdsc[i];

		/* Setup command ring */
		rgp = hba->slim2.phys +
		    (uint64_t)((unsigned long)&(slim->IOCBs[offset]));
		rdsc->cmdAddrHigh = putPaddrHigh(rgp);
		rdsc->cmdAddrLow = putPaddrLow(rgp);
		rdsc->cmdEntries = rp->fc_numCiocb;

		rp->fc_cmdringaddr =
		    (void *)&((SLIM2 *)hba->slim2.virt)->IOCBs[offset];
		offset += rdsc->cmdEntries * hba->iocb_cmd_size;

		/* Setup response ring */
		rgp = hba->slim2.phys +
		    (uint64_t)((unsigned long)&(slim->IOCBs[offset]));
		rdsc->rspAddrHigh = putPaddrHigh(rgp);
		rdsc->rspAddrLow = putPaddrLow(rgp);
		rdsc->rspEntries = rp->fc_numRiocb;

		rp->fc_rspringaddr =
		    (void *)&((SLIM2 *)hba->slim2.virt)->IOCBs[offset];
		offset += rdsc->rspEntries * hba->iocb_rsp_size;
	}

	emlxs_pcimem_bcopy((uint32_t *)(&((SLIM2 *)hba->slim2.virt)->pcb),
	    (uint32_t *)(&((SLIM2 *)hba->slim2.virt)->pcb), sizeof (PCB));

	offset =
	    ((uint64_t)((unsigned long)&(((SLIM2 *)hba->slim2.virt)->pcb)) -
	    (uint64_t)((unsigned long)hba->slim2.virt));
	emlxs_mpdata_sync(hba->slim2.dma_handle, (off_t)offset, sizeof (PCB),
	    DDI_DMA_SYNC_FORDEV);

	return (0);

} /* emlxs_mb_config_port() */


uint32_t
emlxs_hbq_setup(emlxs_hba_t *hba, uint32_t hbq_id)
{
	emlxs_port_t *port = &PPORT;
	HBQ_INIT_t *hbq;
	MATCHMAP *mp;
	HBQE_t *hbqE;
	MAILBOX *mb;
	void *ioa2;
	uint32_t j;
	uint32_t count;
	uint32_t size;
	uint32_t ringno;
	uint32_t seg;

	switch (hbq_id) {
	case EMLXS_ELS_HBQ_ID:
		count = MEM_ELSBUF_COUNT;
		size = MEM_ELSBUF_SIZE;
		ringno = FC_ELS_RING;
		seg = MEM_ELSBUF;
		HBASTATS.ElsUbPosted = count;
		break;

	case EMLXS_IP_HBQ_ID:
		count = MEM_IPBUF_COUNT;
		size = MEM_IPBUF_SIZE;
		ringno = FC_IP_RING;
		seg = MEM_IPBUF;
		HBASTATS.IpUbPosted = count;
		break;

	case EMLXS_CT_HBQ_ID:
		count = MEM_CTBUF_COUNT;
		size = MEM_CTBUF_SIZE;
		ringno = FC_CT_RING;
		seg = MEM_CTBUF;
		HBASTATS.CtUbPosted = count;
		break;

#ifdef SFCT_SUPPORT
	case EMLXS_FCT_HBQ_ID:
		count = MEM_FCTBUF_COUNT;
		size = MEM_FCTBUF_SIZE;
		ringno = FC_FCT_RING;
		seg = MEM_FCTBUF;
		HBASTATS.FctUbPosted = count;
		break;
#endif /* SFCT_SUPPORT */

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_msg,
		    "emlxs_hbq_setup: Invalid HBQ id. (%x)", hbq_id);
		return (1);
	}

	/* Configure HBQ */
	hbq = &hba->hbq_table[hbq_id];
	hbq->HBQ_numEntries = count;

	/* Get a Mailbox buffer to setup mailbox commands for CONFIG_HBQ */
	if ((mb = (MAILBOX *)emlxs_mem_get(hba, (MEM_MBOX | MEM_PRI))) == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_msg,
		    "emlxs_hbq_setup: Unable to get mailbox.");
		return (1);
	}

	/* Allocate HBQ Host buffer and Initialize the HBQEs */
	if (emlxs_hbq_alloc(hba, hbq_id)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_msg,
		    "emlxs_hbq_setup: Unable to allocate HBQ.");
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
		return (1);
	}

	hbq->HBQ_recvNotify = 1;
	hbq->HBQ_num_mask = 0;			/* Bind to ring */
	hbq->HBQ_profile = 0;			/* Selection profile */
						/* 0=all, 7=logentry */
	hbq->HBQ_ringMask = 1 << ringno;	/* b0100 * ringno - Binds */
						/* HBQ to a ring */
						/* Ring0=b0001, Ring1=b0010, */
						/* Ring2=b0100 */
	hbq->HBQ_headerLen = 0;			/* 0 if not profile 4 or 5 */
	hbq->HBQ_logEntry = 0;			/* Set to 1 if this HBQ will */
						/* be used for */
	hbq->HBQ_id = hbq_id;
	hbq->HBQ_PutIdx_next = 0;
	hbq->HBQ_PutIdx = hbq->HBQ_numEntries - 1;
	hbq->HBQ_GetIdx = 0;
	hbq->HBQ_PostBufCnt = hbq->HBQ_numEntries;
	bzero(hbq->HBQ_PostBufs, sizeof (hbq->HBQ_PostBufs));

	/* Fill in POST BUFFERs in HBQE */
	hbqE = (HBQE_t *)hbq->HBQ_host_buf.virt;
	for (j = 0; j < hbq->HBQ_numEntries; j++, hbqE++) {
		/* Allocate buffer to post */
		if ((mp = (MATCHMAP *)emlxs_mem_get(hba,
		    (seg | MEM_PRI))) == 0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_msg,
			    "emlxs_hbq_setup: Unable to allocate HBQ buffer. "
			    "cnt=%d", j);
			emlxs_hbq_free_all(hba, hbq_id);
			return (1);
		}

		hbq->HBQ_PostBufs[j] = mp;

		hbqE->unt.ext.HBQ_tag = hbq_id;
		hbqE->unt.ext.HBQE_tag = j;
		hbqE->bde.tus.f.bdeSize = size;
		hbqE->bde.tus.f.bdeFlags = 0;
		hbqE->unt.w = PCIMEM_LONG(hbqE->unt.w);
		hbqE->bde.tus.w = PCIMEM_LONG(hbqE->bde.tus.w);
		hbqE->bde.addrLow =
		    PCIMEM_LONG(putPaddrLow(mp->phys));
		hbqE->bde.addrHigh =
		    PCIMEM_LONG(putPaddrHigh(mp->phys));
	}

	/* Issue CONFIG_HBQ */
	emlxs_mb_config_hbq(hba, mb, hbq_id);
	if (emlxs_sli_issue_mbox_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "emlxs_hbq_setup: Unable to config HBQ. cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
		emlxs_hbq_free_all(hba, hbq_id);
		return (1);
	}

	/* Setup HBQ Get/Put indexes */
	ioa2 = (void *)((char *)hba->slim_addr + (hba->hgp_hbq_offset +
	    (hbq_id * sizeof (uint32_t))));
	WRITE_SLIM_ADDR(hba, (volatile uint32_t *)ioa2, hbq->HBQ_PutIdx);

	hba->hbq_count++;

	(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);

	return (0);

}  /* emlxs_hbq_setup */


void
emlxs_hbq_free_all(emlxs_hba_t *hba, uint32_t hbq_id)
{
	HBQ_INIT_t *hbq;
	MBUF_INFO *buf_info;
	MBUF_INFO bufinfo;
	uint32_t seg;
	uint32_t j;

	switch (hbq_id) {
	case EMLXS_ELS_HBQ_ID:
		seg = MEM_ELSBUF;
		HBASTATS.ElsUbPosted = 0;
		break;

	case EMLXS_IP_HBQ_ID:
		seg = MEM_IPBUF;
		HBASTATS.IpUbPosted = 0;
		break;

	case EMLXS_CT_HBQ_ID:
		seg = MEM_CTBUF;
		HBASTATS.CtUbPosted = 0;
		break;

#ifdef SFCT_SUPPORT
	case EMLXS_FCT_HBQ_ID:
		seg = MEM_FCTBUF;
		HBASTATS.FctUbPosted = 0;
		break;
#endif /* SFCT_SUPPORT */

	default:
		return;
	}


	hbq = &hba->hbq_table[hbq_id];

	if (hbq->HBQ_host_buf.virt != 0) {
		for (j = 0; j < hbq->HBQ_PostBufCnt; j++) {
			(void) emlxs_mem_put(hba, seg,
			    (uint8_t *)hbq->HBQ_PostBufs[j]);
			hbq->HBQ_PostBufs[j] = NULL;
		}
		hbq->HBQ_PostBufCnt = 0;

		buf_info = &bufinfo;
		bzero(buf_info, sizeof (MBUF_INFO));

		buf_info->size = hbq->HBQ_host_buf.size;
		buf_info->virt = hbq->HBQ_host_buf.virt;
		buf_info->phys = hbq->HBQ_host_buf.phys;
		buf_info->dma_handle = hbq->HBQ_host_buf.dma_handle;
		buf_info->data_handle = hbq->HBQ_host_buf.data_handle;
		buf_info->flags = FC_MBUF_DMA;

		emlxs_mem_free(hba, buf_info);

		hbq->HBQ_host_buf.virt = NULL;
	}

	return;

}  /* emlxs_hbq_free_all() */


void
emlxs_update_HBQ_index(emlxs_hba_t *hba, uint32_t hbq_id)
{
	void *ioa2;
	uint32_t status;
	uint32_t HBQ_PortGetIdx;
	HBQ_INIT_t *hbq;

	switch (hbq_id) {
	case EMLXS_ELS_HBQ_ID:
		HBASTATS.ElsUbPosted++;
		break;

	case EMLXS_IP_HBQ_ID:
		HBASTATS.IpUbPosted++;
		break;

	case EMLXS_CT_HBQ_ID:
		HBASTATS.CtUbPosted++;
		break;

#ifdef SFCT_SUPPORT
	case EMLXS_FCT_HBQ_ID:
		HBASTATS.FctUbPosted++;
		break;
#endif /* SFCT_SUPPORT */

	default:
		return;
	}

	hbq = &hba->hbq_table[hbq_id];

	hbq->HBQ_PutIdx =
	    (hbq->HBQ_PutIdx + 1 >=
	    hbq->HBQ_numEntries) ? 0 : hbq->HBQ_PutIdx + 1;

	if (hbq->HBQ_PutIdx == hbq->HBQ_GetIdx) {
		HBQ_PortGetIdx =
		    PCIMEM_LONG(((SLIM2 *)hba->slim2.virt)->mbx.us.s2.
		    HBQ_PortGetIdx[hbq_id]);

		hbq->HBQ_GetIdx = HBQ_PortGetIdx;

		if (hbq->HBQ_PutIdx == hbq->HBQ_GetIdx) {
			return;
		}
	}

	ioa2 = (void *)((char *)hba->slim_addr + (hba->hgp_hbq_offset +
	    (hbq_id * sizeof (uint32_t))));
	status = hbq->HBQ_PutIdx;
	WRITE_SLIM_ADDR(hba, (volatile uint32_t *)ioa2, status);

	return;

}  /* emlxs_update_HBQ_index() */


void
emlxs_intr_initialize(emlxs_hba_t *hba)
{
	uint32_t status;

	/* Enable mailbox, error attention interrupts */
	status = (uint32_t)(HC_MBINT_ENA | HC_ERINT_ENA);

	/* Enable ring interrupts */
	if (hba->ring_count >= 4) {
		status |=
		    (HC_R3INT_ENA | HC_R2INT_ENA | HC_R1INT_ENA |
		    HC_R0INT_ENA);
	} else if (hba->ring_count == 3) {
		status |= (HC_R2INT_ENA | HC_R1INT_ENA | HC_R0INT_ENA);
	} else if (hba->ring_count == 2) {
		status |= (HC_R1INT_ENA | HC_R0INT_ENA);
	} else if (hba->ring_count == 1) {
		status |= (HC_R0INT_ENA);
	}

	hba->hc_copy = status;
	WRITE_CSR_REG(hba, FC_HC_REG(hba, hba->csr_addr), hba->hc_copy);
}

void
emlxs_enable_latt(emlxs_hba_t *hba)
{
	mutex_enter(&EMLXS_PORT_LOCK);
	hba->hc_copy |= HC_LAINT_ENA;
	WRITE_CSR_REG(hba, FC_HC_REG(hba, hba->csr_addr), hba->hc_copy);
	mutex_exit(&EMLXS_PORT_LOCK);
}

void
emlxs_disable_intr(emlxs_hba_t *hba, uint32_t att)
{
	/* Disable all adapter interrupts */
	hba->hc_copy = att;
	WRITE_CSR_REG(hba, FC_HC_REG(hba, hba->csr_addr), hba->hc_copy);
}

uint32_t
emlxs_check_attention(emlxs_hba_t *hba)
{
	uint32_t ha_copy;

	ha_copy = READ_CSR_REG(hba, FC_HA_REG(hba, hba->csr_addr));
	return (ha_copy);
}
