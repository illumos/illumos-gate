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
 * Copyright 2010 Emulex.  All rights reserved.
 * Use is subject to license terms.
 */


#include <emlxs.h>

/* Required for EMLXS_CONTEXT in EMLXS_MSGF calls */
EMLXS_MSG_DEF(EMLXS_SLI3_C);

static void emlxs_sli3_issue_iocb(emlxs_hba_t *hba, RING *rp, IOCBQ *iocbq);
static void emlxs_sli3_handle_link_event(emlxs_hba_t *hba);
static void emlxs_sli3_handle_ring_event(emlxs_hba_t *hba, int32_t ring_no,
	uint32_t ha_copy);
#ifdef SFCT_SUPPORT
static uint32_t emlxs_fct_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp);
#endif /* SFCT_SUPPORT */

static uint32_t	emlxs_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp);

static uint32_t emlxs_disable_traffic_cop = 1;

static int			emlxs_sli3_map_hdw(emlxs_hba_t *hba);

static void			emlxs_sli3_unmap_hdw(emlxs_hba_t *hba);

static int32_t			emlxs_sli3_online(emlxs_hba_t *hba);

static void			emlxs_sli3_offline(emlxs_hba_t *hba);

static uint32_t			emlxs_sli3_hba_reset(emlxs_hba_t *hba,
					uint32_t restart, uint32_t skip_post,
					uint32_t quiesce);

static void			emlxs_sli3_hba_kill(emlxs_hba_t *hba);
static void			emlxs_sli3_hba_kill4quiesce(emlxs_hba_t *hba);
static uint32_t			emlxs_sli3_hba_init(emlxs_hba_t *hba);

static uint32_t			emlxs_sli2_bde_setup(emlxs_port_t *port,
					emlxs_buf_t *sbp);
static uint32_t			emlxs_sli3_bde_setup(emlxs_port_t *port,
					emlxs_buf_t *sbp);
static uint32_t			emlxs_sli2_fct_bde_setup(emlxs_port_t *port,
					emlxs_buf_t *sbp);
static uint32_t			emlxs_sli3_fct_bde_setup(emlxs_port_t *port,
					emlxs_buf_t *sbp);


static void			emlxs_sli3_issue_iocb_cmd(emlxs_hba_t *hba,
					CHANNEL *rp, IOCBQ *iocb_cmd);


static uint32_t			emlxs_sli3_issue_mbox_cmd(emlxs_hba_t *hba,
					MAILBOXQ *mbq, int32_t flg,
					uint32_t tmo);


#ifdef SFCT_SUPPORT
static uint32_t			emlxs_sli3_prep_fct_iocb(emlxs_port_t *port,
					emlxs_buf_t *cmd_sbp, int channel);

#endif /* SFCT_SUPPORT */

static uint32_t			emlxs_sli3_prep_fcp_iocb(emlxs_port_t *port,
					emlxs_buf_t *sbp, int ring);

static uint32_t			emlxs_sli3_prep_ip_iocb(emlxs_port_t *port,
					emlxs_buf_t *sbp);

static uint32_t			emlxs_sli3_prep_els_iocb(emlxs_port_t *port,
					emlxs_buf_t *sbp);


static uint32_t			emlxs_sli3_prep_ct_iocb(emlxs_port_t *port,
					emlxs_buf_t *sbp);


static void			emlxs_sli3_poll_intr(emlxs_hba_t *hba,
					uint32_t att_bit);

static int32_t			emlxs_sli3_intx_intr(char *arg);
#ifdef MSI_SUPPORT
static uint32_t			emlxs_sli3_msi_intr(char *arg1, char *arg2);
#endif /* MSI_SUPPORT */

static void			emlxs_sli3_enable_intr(emlxs_hba_t *hba);

static void			emlxs_sli3_disable_intr(emlxs_hba_t *hba,
					uint32_t att);


static void			emlxs_handle_ff_error(emlxs_hba_t *hba);

static uint32_t			emlxs_handle_mb_event(emlxs_hba_t *hba);

static void			emlxs_sli3_timer_check_mbox(emlxs_hba_t *hba);

static uint32_t			emlxs_mb_config_port(emlxs_hba_t *hba,
					MAILBOXQ *mbq, uint32_t sli_mode,
					uint32_t hbainit);
static void			emlxs_enable_latt(emlxs_hba_t *hba);

static uint32_t			emlxs_check_attention(emlxs_hba_t *hba);

static uint32_t			emlxs_get_attention(emlxs_hba_t *hba,
					int32_t msgid);
static void			emlxs_proc_attention(emlxs_hba_t *hba,
					uint32_t ha_copy);
/* static int			emlxs_handle_rcv_seq(emlxs_hba_t *hba, */
					/* CHANNEL *cp, IOCBQ *iocbq); */
/* static void			emlxs_update_HBQ_index(emlxs_hba_t *hba, */
					/* uint32_t hbq_id); */
/* static void			emlxs_hbq_free_all(emlxs_hba_t *hba, */
					/* uint32_t hbq_id); */
static uint32_t			emlxs_hbq_setup(emlxs_hba_t *hba,
					uint32_t hbq_id);
extern void			emlxs_sli3_timer(emlxs_hba_t *hba);

extern void			emlxs_sli3_poll_erratt(emlxs_hba_t *hba);


/* Define SLI3 API functions */
emlxs_sli_api_t emlxs_sli3_api = {
	emlxs_sli3_map_hdw,
	emlxs_sli3_unmap_hdw,
	emlxs_sli3_online,
	emlxs_sli3_offline,
	emlxs_sli3_hba_reset,
	emlxs_sli3_hba_kill,
	emlxs_sli3_issue_iocb_cmd,
	emlxs_sli3_issue_mbox_cmd,
#ifdef SFCT_SUPPORT
	emlxs_sli3_prep_fct_iocb,
#else
	NULL,
#endif /* SFCT_SUPPORT */
	emlxs_sli3_prep_fcp_iocb,
	emlxs_sli3_prep_ip_iocb,
	emlxs_sli3_prep_els_iocb,
	emlxs_sli3_prep_ct_iocb,
	emlxs_sli3_poll_intr,
	emlxs_sli3_intx_intr,
	emlxs_sli3_msi_intr,
	emlxs_sli3_disable_intr,
	emlxs_sli3_timer,
	emlxs_sli3_poll_erratt
};


/*
 * emlxs_sli3_online()
 *
 * This routine will start initialization of the SLI2/3 HBA.
 */
static int32_t
emlxs_sli3_online(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg;
	emlxs_vpd_t *vpd;
	MAILBOX *mb = NULL;
	MAILBOXQ *mbq = NULL;
	RING *rp;
	CHANNEL *cp;
	MATCHMAP *mp = NULL;
	MATCHMAP *mp1 = NULL;
	uint8_t *inptr;
	uint8_t *outptr;
	uint32_t status;
	uint16_t i;
	uint32_t j;
	uint32_t read_rev_reset;
	uint32_t key = 0;
	uint32_t fw_check;
	uint32_t kern_update = 0;
	uint32_t rval = 0;
	uint32_t offset;
	uint8_t vpd_data[DMP_VPD_SIZE];
	uint32_t MaxRbusSize;
	uint32_t MaxIbusSize;
	uint32_t sli_mode;
	uint32_t sli_mode_mask;

	cfg = &CFG;
	vpd = &VPD;
	MaxRbusSize = 0;
	MaxIbusSize = 0;
	read_rev_reset = 0;
	hba->chan_count = MAX_RINGS;

	if (hba->bus_type == SBUS_FC) {
		(void) READ_SBUS_CSR_REG(hba, FC_SHS_REG(hba));
	}

	/* Set the fw_check flag */
	fw_check = cfg[CFG_FW_CHECK].current;

	if ((fw_check & 0x04) ||
	    (hba->fw_flag & FW_UPDATE_KERNEL)) {
		kern_update = 1;
	}

	hba->mbox_queue_flag = 0;
	hba->sli.sli3.hc_copy = 0;
	hba->fc_edtov = FF_DEF_EDTOV;
	hba->fc_ratov = FF_DEF_RATOV;
	hba->fc_altov = FF_DEF_ALTOV;
	hba->fc_arbtov = FF_DEF_ARBTOV;

	/*
	 * Get a buffer which will be used repeatedly for mailbox commands
	 */
	mbq = (MAILBOXQ *) kmem_zalloc((sizeof (MAILBOXQ)), KM_SLEEP);

	mb = (MAILBOX *)mbq;

reset:
	/* Initialize sli mode based on configuration parameter */
	switch (cfg[CFG_SLI_MODE].current) {
	case 2:	/* SLI2 mode */
		sli_mode = EMLXS_HBA_SLI2_MODE;
		sli_mode_mask = EMLXS_SLI2_MASK;
		break;

	case 3:	/* SLI3 mode */
		sli_mode = EMLXS_HBA_SLI3_MODE;
		sli_mode_mask = EMLXS_SLI3_MASK;
		break;

	case 0:	/* Best available */
	case 1:	/* Best available */
	default:
		if (hba->model_info.sli_mask & EMLXS_SLI3_MASK) {
			sli_mode = EMLXS_HBA_SLI3_MODE;
			sli_mode_mask = EMLXS_SLI3_MASK;
		} else if (hba->model_info.sli_mask & EMLXS_SLI2_MASK) {
			sli_mode = EMLXS_HBA_SLI2_MODE;
			sli_mode_mask = EMLXS_SLI2_MASK;
		}
	}
	/* SBUS adapters only available in SLI2 */
	if (hba->bus_type == SBUS_FC) {
		sli_mode = EMLXS_HBA_SLI2_MODE;
		sli_mode_mask = EMLXS_SLI2_MASK;
	}

	/* Reset & Initialize the adapter */
	if (emlxs_sli3_hba_init(hba)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to init hba.");

		rval = EIO;
		goto failed;
	}

#ifdef FMA_SUPPORT
	/* Access handle validation */
	if ((emlxs_fm_check_acc_handle(hba, hba->pci_acc_handle)
	    != DDI_FM_OK) ||
	    (emlxs_fm_check_acc_handle(hba, hba->sli.sli3.slim_acc_handle)
	    != DDI_FM_OK) ||
	    (emlxs_fm_check_acc_handle(hba, hba->sli.sli3.csr_acc_handle)
	    != DDI_FM_OK)) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_invalid_access_handle_msg, NULL);

		rval = EIO;
		goto failed;
	}
#endif	/* FMA_SUPPORT */

	/* Check for the LP9802 (This is a special case) */
	/* We need to check for dual channel adapter */
	if (hba->model_info.device_id == PCI_DEVICE_ID_LP9802) {
		/* Try to determine if this is a DC adapter */
		if (emlxs_get_max_sram(hba, &MaxRbusSize, &MaxIbusSize) == 0) {
			if (MaxRbusSize == REDUCED_SRAM_CFG) {
				/* LP9802DC */
				for (i = 1; i < emlxs_pci_model_count; i++) {
					if (emlxs_pci_model[i].id == LP9802DC) {
						bcopy(&emlxs_pci_model[i],
						    &hba->model_info,
						    sizeof (emlxs_model_t));
						break;
					}
				}
			} else if (hba->model_info.id != LP9802) {
				/* LP9802 */
				for (i = 1; i < emlxs_pci_model_count; i++) {
					if (emlxs_pci_model[i].id == LP9802) {
						bcopy(&emlxs_pci_model[i],
						    &hba->model_info,
						    sizeof (emlxs_model_t));
						break;
					}
				}
			}
		}
	}

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

	/* Sanity check */
	if (hba->model_info.sli_mask & EMLXS_SLI4_MASK) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Adapter / SLI mode mismatch mask:x%x",
		    hba->model_info.sli_mask);

		rval = EIO;
		goto failed;
	}

	EMLXS_STATE_CHANGE(hba, FC_INIT_REV);
	emlxs_mb_read_rev(hba, mbq, 0);
	if (emlxs_sli3_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to read rev. Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		rval = EIO;
		goto failed;
	}

	if (mb->un.varRdRev.rr == 0) {
		/* Old firmware */
		if (read_rev_reset == 0) {
			read_rev_reset = 1;

			goto reset;
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
			    "Outdated firmware detected.");
		}

		vpd->rBit = 0;
	} else {
		if (mb->un.varRdRev.un.b.ProgType != FUNC_FIRMWARE) {
			if (read_rev_reset == 0) {
				read_rev_reset = 1;

				goto reset;
			} else {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
				    "Non-operational firmware detected. "
				    "type=%x",
				    mb->un.varRdRev.un.b.ProgType);
			}
		}

		vpd->rBit = 1;
		vpd->sli1FwRev = mb->un.varRdRev.sliFwRev1;
		bcopy((char *)mb->un.varRdRev.sliFwName1, vpd->sli1FwLabel,
		    16);
		vpd->sli2FwRev = mb->un.varRdRev.sliFwRev2;
		bcopy((char *)mb->un.varRdRev.sliFwName2, vpd->sli2FwLabel,
		    16);

		/*
		 * Lets try to read the SLI3 version
		 * Setup and issue mailbox READ REV(v3) command
		 */
		EMLXS_STATE_CHANGE(hba, FC_INIT_REV);

		/* Reuse mbq from previous mbox */
		bzero(mbq, sizeof (MAILBOXQ));

		emlxs_mb_read_rev(hba, mbq, 1);

		if (emlxs_sli3_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) !=
		    MBX_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
			    "Unable to read rev (v3). Mailbox cmd=%x status=%x",
			    mb->mbxCommand, mb->mbxStatus);

			rval = EIO;
			goto failed;
		}

		if (mb->un.varRdRev.rf3) {
			/*
			 * vpd->sli2FwRev = mb->un.varRdRev.sliFwRev1;
			 * Not needed
			 */
			vpd->sli3FwRev = mb->un.varRdRev.sliFwRev2;
			bcopy((char *)mb->un.varRdRev.sliFwName2,
			    vpd->sli3FwLabel, 16);
		}
	}

	if ((sli_mode == EMLXS_HBA_SLI3_MODE) && (vpd->sli3FwRev == 0)) {
		if (vpd->sli2FwRev) {
			sli_mode = EMLXS_HBA_SLI2_MODE;
			sli_mode_mask = EMLXS_SLI2_MASK;
		} else {
			sli_mode = 0;
			sli_mode_mask = 0;
		}
	}

	else if ((sli_mode == EMLXS_HBA_SLI2_MODE) && (vpd->sli2FwRev == 0)) {
		if (vpd->sli3FwRev) {
			sli_mode = EMLXS_HBA_SLI3_MODE;
			sli_mode_mask = EMLXS_SLI3_MASK;
		} else {
			sli_mode = 0;
			sli_mode_mask = 0;
		}
	}

	if (!(hba->model_info.sli_mask & sli_mode_mask)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Firmware not available. sli-mode=%d",
		    cfg[CFG_SLI_MODE].current);

		rval = EIO;
		goto failed;
	}

	/* Save information as VPD data */
	vpd->postKernRev = mb->un.varRdRev.postKernRev;
	vpd->opFwRev = mb->un.varRdRev.opFwRev;
	bcopy((char *)mb->un.varRdRev.opFwName, vpd->opFwLabel, 16);
	vpd->biuRev = mb->un.varRdRev.biuRev;
	vpd->smRev = mb->un.varRdRev.smRev;
	vpd->smFwRev = mb->un.varRdRev.un.smFwRev;
	vpd->endecRev = mb->un.varRdRev.endecRev;
	vpd->fcphHigh = mb->un.varRdRev.fcphHigh;
	vpd->fcphLow = mb->un.varRdRev.fcphLow;
	vpd->feaLevelHigh = mb->un.varRdRev.feaLevelHigh;
	vpd->feaLevelLow = mb->un.varRdRev.feaLevelLow;

	/* Decode FW names */
	emlxs_decode_version(vpd->postKernRev, vpd->postKernName);
	emlxs_decode_version(vpd->opFwRev, vpd->opFwName);
	emlxs_decode_version(vpd->sli1FwRev, vpd->sli1FwName);
	emlxs_decode_version(vpd->sli2FwRev, vpd->sli2FwName);
	emlxs_decode_version(vpd->sli3FwRev, vpd->sli3FwName);
	emlxs_decode_version(vpd->sli4FwRev, vpd->sli4FwName);

	/* Decode FW labels */
	emlxs_decode_label(vpd->opFwLabel, vpd->opFwLabel, 1);
	emlxs_decode_label(vpd->sli1FwLabel, vpd->sli1FwLabel, 1);
	emlxs_decode_label(vpd->sli2FwLabel, vpd->sli2FwLabel, 1);
	emlxs_decode_label(vpd->sli3FwLabel, vpd->sli3FwLabel, 1);
	emlxs_decode_label(vpd->sli4FwLabel, vpd->sli4FwLabel, 1);

	/* Reuse mbq from previous mbox */
	bzero(mbq, sizeof (MAILBOXQ));

	key = emlxs_get_key(hba, mbq);

	/* Get adapter VPD information */
	offset = 0;
	bzero(vpd_data, sizeof (vpd_data));
	vpd->port_index = (uint32_t)-1;

	while (offset < DMP_VPD_SIZE) {
		/* Reuse mbq from previous mbox */
		bzero(mbq, sizeof (MAILBOXQ));

		emlxs_mb_dump_vpd(hba, mbq, offset);
		if (emlxs_sli3_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) !=
		    MBX_SUCCESS) {
			/*
			 * Let it go through even if failed.
			 * Not all adapter's have VPD info and thus will
			 * fail here. This is not a problem
			 */

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "No VPD found. offset=%x status=%x", offset,
			    mb->mbxStatus);
			break;
		} else {
			if (mb->un.varDmp.ra == 1) {
				uint32_t *lp1, *lp2;
				uint32_t bsize;
				uint32_t wsize;

				/*
				 * mb->un.varDmp.word_cnt is actually byte
				 * count for the dump reply
				 */
				bsize = mb->un.varDmp.word_cnt;

				/* Stop if no data was received */
				if (bsize == 0) {
					break;
				}

				/* Check limit on byte size */
				bsize = (bsize >
				    (sizeof (vpd_data) - offset)) ?
				    (sizeof (vpd_data) - offset) : bsize;

				/*
				 * Convert size from bytes to words with
				 * minimum of 1 word
				 */
				wsize = (bsize > 4) ? (bsize >> 2) : 1;

				/*
				 * Transfer data into vpd_data buffer one
				 * word at a time
				 */
				lp1 = (uint32_t *)&mb->un.varDmp.resp_offset;
				lp2 = (uint32_t *)&vpd_data[offset];

				for (i = 0; i < wsize; i++) {
					status = *lp1++;
					*lp2++ = BE_SWAP32(status);
				}

				/* Increment total byte count saved */
				offset += (wsize << 2);

				/*
				 * Stop if less than a full transfer was
				 * received
				 */
				if (wsize < DMP_VPD_DUMP_WCOUNT) {
					break;
				}

			} else {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_init_debug_msg,
				    "No VPD acknowledgment. offset=%x",
				    offset);
				break;
			}
		}

	}

	if (vpd_data[0]) {
		(void) emlxs_parse_vpd(hba, (uint8_t *)vpd_data, offset);

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

		/*
		 * Now lets update hba->model_info with the real
		 * VPD data, if any.
		 */

		/*
		 * Replace the default model description with vpd data
		 */
		if (vpd->model_desc[0] != 0) {
			(void) strcpy(hba->model_info.model_desc,
			    vpd->model_desc);
		}

		/* Replace the default model with vpd data */
		if (vpd->model[0] != 0) {
			(void) strcpy(hba->model_info.model, vpd->model);
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
		goto failed;
	}

	/* Read the adapter's wakeup parms */
	(void) emlxs_read_wakeup_parms(hba, &hba->wakeup_parms, 1);
	emlxs_decode_version(hba->wakeup_parms.u0.boot_bios_wd[0],
	    vpd->boot_version);

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

	if (((fw_check & 0x1) && (hba->model_info.flags & EMLXS_SUN_BRANDED) &&
	    hba->model_info.fwid) || ((fw_check & 0x2) &&
	    hba->model_info.fwid)) {
		emlxs_firmware_t *fw;

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
			if (!kern_update &&
			    ((fw->kern && (vpd->postKernRev != fw->kern)) ||
			    (fw->stub && (vpd->opFwRev != fw->stub)))) {

				hba->fw_flag |= FW_UPDATE_NEEDED;

			} else if ((fw->kern && (vpd->postKernRev !=
			    fw->kern)) ||
			    (fw->stub && (vpd->opFwRev != fw->stub)) ||
			    (fw->sli1 && (vpd->sli1FwRev != fw->sli1)) ||
			    (fw->sli2 && (vpd->sli2FwRev != fw->sli2)) ||
			    (fw->sli3 && (vpd->sli3FwRev != fw->sli3)) ||
			    (fw->sli4 && (vpd->sli4FwRev != fw->sli4))) {
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
					if (emlxs_fw_download(hba,
					    (char *)fw->image, fw->size, 0)) {
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

				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
				    "Firmware image unavailable.");
			} else {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
				    "Firmware update not needed.");
			}
		} else {
			/* This should not happen */

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

	/*
	 * Add our interrupt routine to kernel's interrupt chain & enable it
	 * If MSI is enabled this will cause Solaris to program the MSI address
	 * and data registers in PCI config space
	 */
	if (EMLXS_INTR_ADD(hba) != DDI_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to add interrupt(s).");

		rval = EIO;
		goto failed;
	}

	EMLXS_STATE_CHANGE(hba, FC_INIT_CFGPORT);

	/* Reuse mbq from previous mbox */
	bzero(mbq, sizeof (MAILBOXQ));

	(void) emlxs_mb_config_port(hba, mbq, sli_mode, key);
	if (emlxs_sli3_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to configure port. "
		    "Mailbox cmd=%x status=%x slimode=%d key=%x",
		    mb->mbxCommand, mb->mbxStatus, sli_mode, key);

		for (sli_mode--; sli_mode > 0; sli_mode--) {
			/* Check if sli_mode is supported by this adapter */
			if (hba->model_info.sli_mask &
			    EMLXS_SLI_MASK(sli_mode)) {
				sli_mode_mask = EMLXS_SLI_MASK(sli_mode);
				break;
			}
		}

		if (sli_mode) {
			fw_check = 0;

			goto reset;
		}

		hba->flag &= ~FC_SLIM2_MODE;

		rval = EIO;
		goto failed;
	}

	/* Check if SLI3 mode was achieved */
	if (mb->un.varCfgPort.rMA &&
	    (mb->un.varCfgPort.sli_mode == EMLXS_HBA_SLI3_MODE)) {

		if (mb->un.varCfgPort.vpi_max > 1) {
			hba->flag |= FC_NPIV_ENABLED;

			if (hba->model_info.chip >= EMLXS_SATURN_CHIP) {
				hba->vpi_max =
				    min(mb->un.varCfgPort.vpi_max,
				    MAX_VPORTS - 1);
			} else {
				hba->vpi_max =
				    min(mb->un.varCfgPort.vpi_max,
				    MAX_VPORTS_LIMITED - 1);
			}
		}

#if (EMLXS_MODREV >= EMLXS_MODREV5)
		hba->fca_tran->fca_num_npivports =
		    (cfg[CFG_NPIV_ENABLE].current) ? hba->vpi_max : 0;
#endif /* >= EMLXS_MODREV5 */

		if (mb->un.varCfgPort.gerbm && mb->un.varCfgPort.max_hbq) {
			hba->flag |= FC_HBQ_ENABLED;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "SLI3 mode: flag=%x vpi_max=%d", hba->flag, hba->vpi_max);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "SLI2 mode: flag=%x", hba->flag);
		sli_mode = EMLXS_HBA_SLI2_MODE;
		sli_mode_mask = EMLXS_SLI2_MASK;
		hba->sli_mode = sli_mode;
	}

	/* Get and save the current firmware version (based on sli_mode) */
	emlxs_decode_firmware_rev(hba, vpd);

	emlxs_pcix_mxr_update(hba, 0);

	/* Reuse mbq from previous mbox */
	bzero(mbq, sizeof (MAILBOXQ));

	emlxs_mb_read_config(hba, mbq);
	if (emlxs_sli3_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to read configuration.  Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		rval = EIO;
		goto failed;
	}

	/* Save the link speed capabilities */
	vpd->link_speed = (uint16_t)mb->un.varRdConfig.lmt;
	emlxs_process_link_speed(hba);

	/* Set the max node count */
	if (cfg[CFG_NUM_NODES].current > 0) {
		hba->max_nodes =
		    min(cfg[CFG_NUM_NODES].current,
		    mb->un.varRdConfig.max_rpi);
	} else {
		hba->max_nodes = mb->un.varRdConfig.max_rpi;
	}

	/* Set the io throttle */
	hba->io_throttle = mb->un.varRdConfig.max_xri - IO_THROTTLE_RESERVE;
	hba->max_iotag = mb->un.varRdConfig.max_xri;

	/*
	 * Allocate some memory for buffers
	 */
	if (emlxs_mem_alloc_buffer(hba) == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to allocate memory buffers.");

		EMLXS_STATE_CHANGE(hba, FC_ERROR);
		return (ENOMEM);
	}

	/*
	 * Setup and issue mailbox RUN BIU DIAG command Setup test buffers
	 */
	if (((mp = (MATCHMAP *)emlxs_mem_get(hba, MEM_BUF, 1)) == 0) ||
	    ((mp1 = (MATCHMAP *)emlxs_mem_get(hba, MEM_BUF, 1)) == 0)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to allocate diag buffers.");

		rval = ENOMEM;
		goto failed;
	}

	bcopy((caddr_t)&emlxs_diag_pattern[0], (caddr_t)mp->virt,
	    MEM_ELSBUF_SIZE);
	EMLXS_MPDATA_SYNC(mp->dma_handle, 0, MEM_ELSBUF_SIZE,
	    DDI_DMA_SYNC_FORDEV);

	bzero(mp1->virt, MEM_ELSBUF_SIZE);
	EMLXS_MPDATA_SYNC(mp1->dma_handle, 0, MEM_ELSBUF_SIZE,
	    DDI_DMA_SYNC_FORDEV);

	/* Reuse mbq from previous mbox */
	bzero(mbq, sizeof (MAILBOXQ));

	(void) emlxs_mb_run_biu_diag(hba, mbq, mp->phys, mp1->phys);

	if (emlxs_sli3_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to run BIU diag.  Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		rval = EIO;
		goto failed;
	}

	EMLXS_MPDATA_SYNC(mp1->dma_handle, 0, MEM_ELSBUF_SIZE,
	    DDI_DMA_SYNC_FORKERNEL);

#ifdef FMA_SUPPORT
	if (mp->dma_handle) {
		if (emlxs_fm_check_dma_handle(hba, mp->dma_handle)
		    != DDI_FM_OK) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_invalid_dma_handle_msg,
			    "emlxs_sli3_online: hdl=%p",
			    mp->dma_handle);
			rval = EIO;
			goto failed;
		}
	}

	if (mp1->dma_handle) {
		if (emlxs_fm_check_dma_handle(hba, mp1->dma_handle)
		    != DDI_FM_OK) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_invalid_dma_handle_msg,
			    "emlxs_sli3_online: hdl=%p",
			    mp1->dma_handle);
			rval = EIO;
			goto failed;
		}
	}
#endif  /* FMA_SUPPORT */

	outptr = mp->virt;
	inptr = mp1->virt;

	for (i = 0; i < MEM_ELSBUF_SIZE; i++) {
		if (*outptr++ != *inptr++) {
			outptr--;
			inptr--;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
			    "BIU diagnostic failed. "
			    "offset %x value %x should be %x.",
			    i, (uint32_t)*inptr, (uint32_t)*outptr);

			rval = EIO;
			goto failed;
		}
	}

	/* Free the buffers since we were polling */
	emlxs_mem_put(hba, MEM_BUF, (void *)mp);
	mp = NULL;
	emlxs_mem_put(hba, MEM_BUF, (void *)mp1);
	mp1 = NULL;

	hba->channel_fcp = FC_FCP_RING;
	hba->channel_els = FC_ELS_RING;
	hba->channel_ip = FC_IP_RING;
	hba->channel_ct = FC_CT_RING;
	hba->sli.sli3.ring_count = MAX_RINGS;

	hba->channel_tx_count = 0;
	hba->io_count = 0;
	hba->fc_iotag = 1;

	/*
	 * OutOfRange (oor) iotags are used for abort or
	 * close XRI commands
	 */
	hba->fc_oor_iotag = hba->max_iotag;

	for (i = 0; i < hba->chan_count; i++) {
		cp = &hba->chan[i];

		/* 1 to 1 mapping between ring and channel */
		cp->iopath = (void *)&hba->sli.sli3.ring[i];

		cp->hba = hba;
		cp->channelno = i;
	}

	/*
	 * Setup and issue mailbox CONFIGURE RING command
	 */
	for (i = 0; i < (uint32_t)hba->sli.sli3.ring_count; i++) {
		/*
		 * Initialize cmd/rsp ring pointers
		 */
		rp = &hba->sli.sli3.ring[i];

		/* 1 to 1 mapping between ring and channel */
		rp->channelp = &hba->chan[i];

		rp->hba = hba;
		rp->ringno = (uint8_t)i;

		rp->fc_cmdidx = 0;
		rp->fc_rspidx = 0;
		EMLXS_STATE_CHANGE(hba, FC_INIT_CFGRING);

		/* Reuse mbq from previous mbox */
		bzero(mbq, sizeof (MAILBOXQ));

		emlxs_mb_config_ring(hba, i, mbq);
		if (emlxs_sli3_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) !=
		    MBX_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
			    "Unable to configure ring. "
			    "Mailbox cmd=%x status=%x",
			    mb->mbxCommand, mb->mbxStatus);

			rval = EIO;
			goto failed;
		}
	}

	/*
	 * Setup link timers
	 */
	EMLXS_STATE_CHANGE(hba, FC_INIT_INITLINK);

	/* Reuse mbq from previous mbox */
	bzero(mbq, sizeof (MAILBOXQ));

	emlxs_mb_config_link(hba, mbq);
	if (emlxs_sli3_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to configure link. Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		rval = EIO;
		goto failed;
	}

#ifdef MAX_RRDY_SUPPORT
	/* Set MAX_RRDY if one is provided */
	if (cfg[CFG_MAX_RRDY].current) {

		/* Reuse mbq from previous mbox */
		bzero(mbq, sizeof (MAILBOXQ));

		emlxs_mb_set_var(hba, (MAILBOX *)mbq, 0x00060412,
		    cfg[CFG_MAX_RRDY].current);

		if (emlxs_sli3_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) !=
		    MBX_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "MAX_RRDY: Unable to set.  status=%x " \
			    "value=%d",
			    mb->mbxStatus, cfg[CFG_MAX_RRDY].current);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "MAX_RRDY: %d", cfg[CFG_MAX_RRDY].current);
		}
	}
#endif /* MAX_RRDY_SUPPORT */

	/* Reuse mbq from previous mbox */
	bzero(mbq, sizeof (MAILBOXQ));

	/*
	 * We need to get login parameters for NID
	 */
	(void) emlxs_mb_read_sparam(hba, mbq);
	mp = (MATCHMAP *)mbq->bp;
	if (emlxs_sli3_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to read parameters. Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		rval = EIO;
		goto failed;
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
	}

	/*
	 * Make first attempt to set a port index
	 * Check if this is a multifunction adapter
	 */
	if ((vpd->port_index == (uint32_t)-1) &&
	    (hba->model_info.chip >= EMLXS_THOR_CHIP)) {
		char *buffer;
		int32_t i;

		/*
		 * The port address looks like this:
		 * 1	- for port index 0
		 * 1,1	- for port index 1
		 * 1,2	- for port index 2
		 */
		buffer = ddi_get_name_addr(hba->dip);

		if (buffer) {
			vpd->port_index = 0;

			/* Reverse scan for a comma */
			for (i = strlen(buffer) - 1; i > 0; i--) {
				if (buffer[i] == ',') {
					/* Comma found - set index now */
					vpd->port_index =
					    emlxs_strtol(&buffer[i + 1], 10);
					break;
				}
			}
		}
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
			vpd->port_index++;
		}
	}

	if (vpd->port_num[0] == 0) {
		if (hba->model_info.channels > 1) {
			(void) sprintf(vpd->port_num, "%d", vpd->port_index);
		}
	}

	if (vpd->id[0] == 0) {
		(void) strcpy(vpd->id, hba->model_info.model_desc);
	}

	if (vpd->manufacturer[0] == 0) {
		(void) strcpy(vpd->manufacturer, hba->model_info.manufacturer);
	}

	if (vpd->part_num[0] == 0) {
		(void) strcpy(vpd->part_num, hba->model_info.model);
	}

	if (vpd->model_desc[0] == 0) {
		(void) strcpy(vpd->model_desc, hba->model_info.model_desc);
	}

	if (vpd->model[0] == 0) {
		(void) strcpy(vpd->model, hba->model_info.model);
	}

	if (vpd->prog_types[0] == 0) {
		emlxs_build_prog_types(hba, vpd->prog_types);
	}

	/* Create the symbolic names */
	(void) sprintf(hba->snn, "Emulex %s FV%s DV%s %s",
	    hba->model_info.model, hba->vpd.fw_version, emlxs_version,
	    (char *)utsname.nodename);

	(void) sprintf(hba->spn,
	    "Emulex PPN-%01x%01x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
	    hba->wwpn.nameType, hba->wwpn.IEEEextMsn, hba->wwpn.IEEEextLsb,
	    hba->wwpn.IEEE[0], hba->wwpn.IEEE[1], hba->wwpn.IEEE[2],
	    hba->wwpn.IEEE[3], hba->wwpn.IEEE[4], hba->wwpn.IEEE[5]);

	if (cfg[CFG_NETWORK_ON].current) {
		if ((hba->sparam.portName.nameType != NAME_IEEE) ||
		    (hba->sparam.portName.IEEEextMsn != 0) ||
		    (hba->sparam.portName.IEEEextLsb != 0)) {

			cfg[CFG_NETWORK_ON].current = 0;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
			    "WWPN doesn't conform to IP profile: nameType=%x",
			    hba->sparam.portName.nameType);
		}

		/* Reuse mbq from previous mbox */
		bzero(mbq, sizeof (MAILBOXQ));

		/* Issue CONFIG FARP */
		emlxs_mb_config_farp(hba, mbq);
		if (emlxs_sli3_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) !=
		    MBX_SUCCESS) {
			/*
			 * Let it go through even if failed.
			 */
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
			    "Unable to configure FARP. "
			    "Mailbox cmd=%x status=%x",
			    mb->mbxCommand, mb->mbxStatus);
		}
	}
#ifdef MSI_SUPPORT
	/* Configure MSI map if required */
	if (hba->intr_count > 1) {

		if (hba->intr_type == DDI_INTR_TYPE_MSIX) {
			/* always start from 0 */
			hba->last_msiid = 0;
		}

		/* Reuse mbq from previous mbox */
		bzero(mbq, sizeof (MAILBOXQ));

		emlxs_mb_config_msix(hba, mbq, hba->intr_map, hba->intr_count);

		if (emlxs_sli3_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) ==
		    MBX_SUCCESS) {
			goto msi_configured;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Unable to config MSIX.  Mailbox cmd=0x%x status=0x%x",
		    mb->mbxCommand, mb->mbxStatus);

		/* Reuse mbq from previous mbox */
		bzero(mbq, sizeof (MAILBOXQ));

		emlxs_mb_config_msi(hba, mbq, hba->intr_map, hba->intr_count);

		if (emlxs_sli3_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) ==
		    MBX_SUCCESS) {
			goto msi_configured;
		}


		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Unable to config MSI.  Mailbox cmd=0x%x status=0x%x",
		    mb->mbxCommand, mb->mbxStatus);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Attempting single interrupt mode...");

		/* First cleanup old interrupts */
		(void) emlxs_msi_remove(hba);
		(void) emlxs_msi_uninit(hba);

		status = emlxs_msi_init(hba, 1);

		if (status != DDI_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
			    "Unable to initialize interrupt. status=%d",
			    status);

			rval = EIO;
			goto failed;
		}

		/*
		 * Reset adapter - The adapter needs to be reset because
		 * the bus cannot handle the MSI change without handshaking
		 * with the adapter again
		 */

		(void) emlxs_mem_free_buffer(hba);
		fw_check = 0;
		goto reset;
	}

msi_configured:


	if ((hba->intr_count >= 1) &&
	    (hba->sli_mode == EMLXS_HBA_SLI3_MODE)) {
		/* intr_count is a sequence of msi id */
		/* Setup msi2chan[msi_id] */
		for (i = 0; i < hba->intr_count; i ++) {
			hba->msi2chan[i] = i;
			if (i >= hba->chan_count)
				hba->msi2chan[i] = (i - hba->chan_count);
		}
	}
#endif /* MSI_SUPPORT */

	/*
	 * We always disable the firmware traffic cop feature
	 */
	if (emlxs_disable_traffic_cop) {
		/* Reuse mbq from previous mbox */
		bzero(mbq, sizeof (MAILBOXQ));

		emlxs_disable_tc(hba, mbq);
		if (emlxs_sli3_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) !=
		    MBX_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
			    "Unable to disable traffic cop. "
			    "Mailbox cmd=%x status=%x",
			    mb->mbxCommand, mb->mbxStatus);

			rval = EIO;
			goto failed;
		}
	}


	/* Reuse mbq from previous mbox */
	bzero(mbq, sizeof (MAILBOXQ));

	/* Register for async events */
	emlxs_mb_async_event(hba, mbq);
	if (emlxs_sli3_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Async events disabled. Mailbox status=%x",
		    mb->mbxStatus);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Async events enabled.");
		hba->flag |= FC_ASYNC_EVENTS;
	}

	EMLXS_STATE_CHANGE(hba, FC_LINK_DOWN);

	emlxs_sli3_enable_intr(hba);

	if (hba->flag & FC_HBQ_ENABLED) {
		if (hba->tgt_mode) {
			if (emlxs_hbq_setup(hba, EMLXS_FCT_HBQ_ID)) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_init_failed_msg,
				    "Unable to setup FCT HBQ.");

				rval = ENOMEM;
				goto failed;
			}
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "FCT Ring: Posted %d buffers.", MEM_FCTBUF_COUNT);
		}

		if (cfg[CFG_NETWORK_ON].current) {
			if (emlxs_hbq_setup(hba, EMLXS_IP_HBQ_ID)) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_init_failed_msg,
				    "Unable to setup IP HBQ.");

				rval = ENOMEM;
				goto failed;
			}
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "IP  Ring: Posted %d buffers.", MEM_IPBUF_COUNT);
		}

		if (emlxs_hbq_setup(hba, EMLXS_ELS_HBQ_ID)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
			    "Unable to setup ELS HBQ.");
			rval = ENOMEM;
			goto failed;
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "ELS Ring: Posted %d buffers.", MEM_ELSBUF_COUNT);

		if (emlxs_hbq_setup(hba, EMLXS_CT_HBQ_ID)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
			    "Unable to setup CT HBQ.");

			rval = ENOMEM;
			goto failed;
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "CT  Ring: Posted %d buffers.", MEM_CTBUF_COUNT);
	} else {
		if (hba->tgt_mode) {
			/* Post the FCT unsol buffers */
			rp = &hba->sli.sli3.ring[FC_FCT_RING];
			for (j = 0; j < MEM_FCTBUF_COUNT; j += 2) {
				(void) emlxs_post_buffer(hba, rp, 2);
			}
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "FCP Ring: Posted %d buffers.", MEM_FCTBUF_COUNT);
		}

		if (cfg[CFG_NETWORK_ON].current) {
			/* Post the IP unsol buffers */
			rp = &hba->sli.sli3.ring[FC_IP_RING];
			for (j = 0; j < MEM_IPBUF_COUNT; j += 2) {
				(void) emlxs_post_buffer(hba, rp, 2);
			}
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "IP  Ring: Posted %d buffers.", MEM_IPBUF_COUNT);
		}

		/* Post the ELS unsol buffers */
		rp = &hba->sli.sli3.ring[FC_ELS_RING];
		for (j = 0; j < MEM_ELSBUF_COUNT; j += 2) {
			(void) emlxs_post_buffer(hba, rp, 2);
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "ELS Ring: Posted %d buffers.", MEM_ELSBUF_COUNT);


		/* Post the CT unsol buffers */
		rp = &hba->sli.sli3.ring[FC_CT_RING];
		for (j = 0; j < MEM_CTBUF_COUNT; j += 2) {
			(void) emlxs_post_buffer(hba, rp, 2);
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "CT  Ring: Posted %d buffers.", MEM_CTBUF_COUNT);
	}

	(void) kmem_free((uint8_t *)mbq, sizeof (MAILBOXQ));

	/*
	 * Setup and issue mailbox INITIALIZE LINK command
	 * At this point, the interrupt will be generated by the HW
	 * Do this only if persist-linkdown is not set
	 */
	if (cfg[CFG_PERSIST_LINKDOWN].current == 0) {
		mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX, 1);
		if (mbq == NULL) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
			    "Unable to allocate mailbox buffer.");

			rval = EIO;
			goto failed;
		}

		emlxs_mb_init_link(hba, mbq, cfg[CFG_TOPOLOGY].current,
		    cfg[CFG_LINK_SPEED].current);

		rval = emlxs_sli3_issue_mbox_cmd(hba, mbq, MBX_NOWAIT, 0);
		if ((rval != MBX_SUCCESS) && (rval != MBX_BUSY)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
			    "Unable to initialize link. " \
			    "Mailbox cmd=%x status=%x",
			    mb->mbxCommand, mb->mbxStatus);

			emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);
			mbq = NULL;
			rval = EIO;
			goto failed;
		}

		/*
		 * Enable link attention interrupt
		 */
		emlxs_enable_latt(hba);

		/* Wait for link to come up */
		i = cfg[CFG_LINKUP_DELAY].current;
		while (i && (hba->state < FC_LINK_UP)) {
			/* Check for hardware error */
			if (hba->state == FC_ERROR) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_init_failed_msg,
				    "Adapter error.");

				mbq = NULL;
				rval = EIO;
				goto failed;
			}

			DELAYMS(1000);
			i--;
		}
	} else {
		EMLXS_STATE_CHANGE(hba, FC_LINK_DOWN_PERSIST);
	}

	/*
	 * The leadvile driver will now handle the FLOGI at the driver level
	 */

	return (0);

failed:

	EMLXS_STATE_CHANGE(hba, FC_ERROR);

	if (hba->intr_flags & EMLXS_MSI_ADDED) {
		(void) EMLXS_INTR_REMOVE(hba);
	}

	if (mp) {
		emlxs_mem_put(hba, MEM_BUF, (void *)mp);
		mp = NULL;
	}

	if (mp1) {
		emlxs_mem_put(hba, MEM_BUF, (void *)mp1);
		mp1 = NULL;
	}

	(void) emlxs_mem_free_buffer(hba);

	if (mbq) {
		(void) kmem_free((uint8_t *)mbq, sizeof (MAILBOXQ));
		mbq = NULL;
		mb = NULL;
	}

	if (rval == 0) {
		rval = EIO;
	}

	return (rval);

} /* emlxs_sli3_online() */


static void
emlxs_sli3_offline(emlxs_hba_t *hba)
{
	/* Reverse emlxs_sli3_online */

	/* Kill the adapter */
	emlxs_sli3_hba_kill(hba);

	/* Free driver shared memory */
	(void) emlxs_mem_free_buffer(hba);

} /* emlxs_sli3_offline() */


static int
emlxs_sli3_map_hdw(emlxs_hba_t *hba)
{
	emlxs_port_t		*port = &PPORT;
	dev_info_t		*dip;
	ddi_device_acc_attr_t	dev_attr;
	int			status;

	dip = (dev_info_t *)hba->dip;
	dev_attr = emlxs_dev_acc_attr;

	if (hba->bus_type == SBUS_FC) {

		if (hba->sli.sli3.slim_acc_handle == 0) {
			status = ddi_regs_map_setup(dip,
			    SBUS_DFLY_SLIM_RINDEX,
			    (caddr_t *)&hba->sli.sli3.slim_addr,
			    0, 0, &dev_attr, &hba->sli.sli3.slim_acc_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "(SBUS) ddi_regs_map_setup SLIM failed. "
				    "status=%x", status);
				goto failed;
			}
		}
		if (hba->sli.sli3.csr_acc_handle == 0) {
			status = ddi_regs_map_setup(dip,
			    SBUS_DFLY_CSR_RINDEX,
			    (caddr_t *)&hba->sli.sli3.csr_addr,
			    0, 0, &dev_attr, &hba->sli.sli3.csr_acc_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "(SBUS) ddi_regs_map_setup DFLY CSR "
				    "failed. status=%x", status);
				goto failed;
			}
		}
		if (hba->sli.sli3.sbus_flash_acc_handle == 0) {
			status = ddi_regs_map_setup(dip, SBUS_FLASH_RDWR,
			    (caddr_t *)&hba->sli.sli3.sbus_flash_addr, 0, 0,
			    &dev_attr, &hba->sli.sli3.sbus_flash_acc_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "(SBUS) ddi_regs_map_setup Fcode Flash "
				    "failed. status=%x", status);
				goto failed;
			}
		}
		if (hba->sli.sli3.sbus_core_acc_handle == 0) {
			status = ddi_regs_map_setup(dip, SBUS_TITAN_CORE_RINDEX,
			    (caddr_t *)&hba->sli.sli3.sbus_core_addr, 0, 0,
			    &dev_attr, &hba->sli.sli3.sbus_core_acc_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "(SBUS) ddi_regs_map_setup TITAN CORE "
				    "failed. status=%x", status);
				goto failed;
			}
		}

		if (hba->sli.sli3.sbus_csr_handle == 0) {
			status = ddi_regs_map_setup(dip, SBUS_TITAN_CSR_RINDEX,
			    (caddr_t *)&hba->sli.sli3.sbus_csr_addr,
			    0, 0, &dev_attr, &hba->sli.sli3.sbus_csr_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "(SBUS) ddi_regs_map_setup TITAN CSR "
				    "failed. status=%x", status);
				goto failed;
			}
		}
	} else {	/* ****** PCI ****** */

		if (hba->sli.sli3.slim_acc_handle == 0) {
			status = ddi_regs_map_setup(dip, PCI_SLIM_RINDEX,
			    (caddr_t *)&hba->sli.sli3.slim_addr,
			    0, 0, &dev_attr, &hba->sli.sli3.slim_acc_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "(PCI) ddi_regs_map_setup SLIM failed. "
				    "stat=%d mem=%p attr=%p hdl=%p",
				    status, &hba->sli.sli3.slim_addr, &dev_attr,
				    &hba->sli.sli3.slim_acc_handle);
				goto failed;
			}
		}

		/*
		 * Map in control registers, using memory-mapped version of
		 * the registers rather than the I/O space-mapped registers.
		 */
		if (hba->sli.sli3.csr_acc_handle == 0) {
			status = ddi_regs_map_setup(dip, PCI_CSR_RINDEX,
			    (caddr_t *)&hba->sli.sli3.csr_addr,
			    0, 0, &dev_attr, &hba->sli.sli3.csr_acc_handle);
			if (status != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_attach_failed_msg,
				    "ddi_regs_map_setup CSR failed. status=%x",
				    status);
				goto failed;
			}
		}
	}

	if (hba->sli.sli3.slim2.virt == 0) {
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

		hba->sli.sli3.slim2.virt = buf_info->virt;
		hba->sli.sli3.slim2.phys = buf_info->phys;
		hba->sli.sli3.slim2.size = SLI_SLIM2_SIZE;
		hba->sli.sli3.slim2.data_handle = buf_info->data_handle;
		hba->sli.sli3.slim2.dma_handle = buf_info->dma_handle;
		bzero((char *)hba->sli.sli3.slim2.virt, SLI_SLIM2_SIZE);
	}

	/* offset from beginning of register space */
	hba->sli.sli3.ha_reg_addr = (uint32_t *)(hba->sli.sli3.csr_addr +
	    (sizeof (uint32_t) * HA_REG_OFFSET));
	hba->sli.sli3.ca_reg_addr = (uint32_t *)(hba->sli.sli3.csr_addr +
	    (sizeof (uint32_t) * CA_REG_OFFSET));
	hba->sli.sli3.hs_reg_addr = (uint32_t *)(hba->sli.sli3.csr_addr +
	    (sizeof (uint32_t) * HS_REG_OFFSET));
	hba->sli.sli3.hc_reg_addr = (uint32_t *)(hba->sli.sli3.csr_addr +
	    (sizeof (uint32_t) * HC_REG_OFFSET));
	hba->sli.sli3.bc_reg_addr = (uint32_t *)(hba->sli.sli3.csr_addr +
	    (sizeof (uint32_t) * BC_REG_OFFSET));

	if (hba->bus_type == SBUS_FC) {
		/* offset from beginning of register space */
		/* for TITAN registers */
		hba->sli.sli3.shc_reg_addr =
		    (uint32_t *)(hba->sli.sli3.sbus_csr_addr +
		    (sizeof (uint32_t) * SBUS_CTRL_REG_OFFSET));
		hba->sli.sli3.shs_reg_addr =
		    (uint32_t *)(hba->sli.sli3.sbus_csr_addr +
		    (sizeof (uint32_t) * SBUS_STAT_REG_OFFSET));
		hba->sli.sli3.shu_reg_addr =
		    (uint32_t *)(hba->sli.sli3.sbus_csr_addr +
		    (sizeof (uint32_t) * SBUS_UPDATE_REG_OFFSET));
	}
	hba->chan_count = MAX_RINGS;

	return (0);

failed:

	emlxs_sli3_unmap_hdw(hba);
	return (ENOMEM);

} /* emlxs_sli3_map_hdw() */


static void
emlxs_sli3_unmap_hdw(emlxs_hba_t *hba)
{
	MBUF_INFO	bufinfo;
	MBUF_INFO	*buf_info = &bufinfo;

	if (hba->sli.sli3.csr_acc_handle) {
		ddi_regs_map_free(&hba->sli.sli3.csr_acc_handle);
		hba->sli.sli3.csr_acc_handle = 0;
	}

	if (hba->sli.sli3.slim_acc_handle) {
		ddi_regs_map_free(&hba->sli.sli3.slim_acc_handle);
		hba->sli.sli3.slim_acc_handle = 0;
	}

	if (hba->sli.sli3.sbus_flash_acc_handle) {
		ddi_regs_map_free(&hba->sli.sli3.sbus_flash_acc_handle);
		hba->sli.sli3.sbus_flash_acc_handle = 0;
	}

	if (hba->sli.sli3.sbus_core_acc_handle) {
		ddi_regs_map_free(&hba->sli.sli3.sbus_core_acc_handle);
		hba->sli.sli3.sbus_core_acc_handle = 0;
	}

	if (hba->sli.sli3.sbus_csr_handle) {
		ddi_regs_map_free(&hba->sli.sli3.sbus_csr_handle);
		hba->sli.sli3.sbus_csr_handle = 0;
	}

	if (hba->sli.sli3.slim2.virt) {
		bzero(buf_info, sizeof (MBUF_INFO));

		if (hba->sli.sli3.slim2.phys) {
			buf_info->phys = hba->sli.sli3.slim2.phys;
			buf_info->data_handle = hba->sli.sli3.slim2.data_handle;
			buf_info->dma_handle = hba->sli.sli3.slim2.dma_handle;
			buf_info->flags = FC_MBUF_DMA;
		}

		buf_info->virt = hba->sli.sli3.slim2.virt;
		buf_info->size = hba->sli.sli3.slim2.size;
		emlxs_mem_free(hba, buf_info);

		hba->sli.sli3.slim2.virt = NULL;
	}


	return;

} /* emlxs_sli3_unmap_hdw() */


static uint32_t
emlxs_sli3_hba_init(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	emlxs_port_t *vport;
	emlxs_config_t *cfg;
	uint16_t i;

	cfg = &CFG;
	i = 0;

	/* Restart the adapter */
	if (emlxs_sli3_hba_reset(hba, 1, 0, 0)) {
		return (1);
	}

	hba->channel_fcp = FC_FCP_RING;
	hba->channel_els = FC_ELS_RING;
	hba->channel_ip = FC_IP_RING;
	hba->channel_ct = FC_CT_RING;
	hba->chan_count = MAX_RINGS;
	hba->sli.sli3.ring_count = MAX_RINGS;

	/*
	 * WARNING: There is a max of 6 ring masks allowed
	 */
	/* RING 0 - FCP */
	if (hba->tgt_mode) {
		hba->sli.sli3.ring_masks[FC_FCP_RING] = 1;
		hba->sli.sli3.ring_rval[i] = FC_FCP_CMND;
		hba->sli.sli3.ring_rmask[i] = 0;
		hba->sli.sli3.ring_tval[i] = FC_FCP_DATA;
		hba->sli.sli3.ring_tmask[i++] = 0xFF;
	} else {
		hba->sli.sli3.ring_masks[FC_FCP_RING] = 0;
	}

	hba->sli.sli3.ring[FC_FCP_RING].fc_numCiocb = SLIM_IOCB_CMD_R0_ENTRIES;
	hba->sli.sli3.ring[FC_FCP_RING].fc_numRiocb = SLIM_IOCB_RSP_R0_ENTRIES;

	/* RING 1 - IP */
	if (cfg[CFG_NETWORK_ON].current) {
		hba->sli.sli3.ring_masks[FC_IP_RING] = 1;
		hba->sli.sli3.ring_rval[i] = FC_UNSOL_DATA; /* Unsol Data */
		hba->sli.sli3.ring_rmask[i] = 0xFF;
		hba->sli.sli3.ring_tval[i] = FC_LLC_SNAP; /* LLC/SNAP */
		hba->sli.sli3.ring_tmask[i++] = 0xFF;
	} else {
		hba->sli.sli3.ring_masks[FC_IP_RING] = 0;
	}

	hba->sli.sli3.ring[FC_IP_RING].fc_numCiocb = SLIM_IOCB_CMD_R1_ENTRIES;
	hba->sli.sli3.ring[FC_IP_RING].fc_numRiocb = SLIM_IOCB_RSP_R1_ENTRIES;

	/* RING 2 - ELS */
	hba->sli.sli3.ring_masks[FC_ELS_RING] = 1;
	hba->sli.sli3.ring_rval[i] = FC_ELS_REQ;	/* ELS request/rsp */
	hba->sli.sli3.ring_rmask[i] = 0xFE;
	hba->sli.sli3.ring_tval[i] = FC_ELS_DATA;	/* ELS */
	hba->sli.sli3.ring_tmask[i++] = 0xFF;

	hba->sli.sli3.ring[FC_ELS_RING].fc_numCiocb = SLIM_IOCB_CMD_R2_ENTRIES;
	hba->sli.sli3.ring[FC_ELS_RING].fc_numRiocb = SLIM_IOCB_RSP_R2_ENTRIES;

	/* RING 3 - CT */
	hba->sli.sli3.ring_masks[FC_CT_RING] = 1;
	hba->sli.sli3.ring_rval[i] = FC_UNSOL_CTL;	/* CT request/rsp */
	hba->sli.sli3.ring_rmask[i] = 0xFE;
	hba->sli.sli3.ring_tval[i] = FC_CT_TYPE;	/* CT */
	hba->sli.sli3.ring_tmask[i++] = 0xFF;

	hba->sli.sli3.ring[FC_CT_RING].fc_numCiocb = SLIM_IOCB_CMD_R3_ENTRIES;
	hba->sli.sli3.ring[FC_CT_RING].fc_numRiocb = SLIM_IOCB_RSP_R3_ENTRIES;

	if (i > 6) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_failed_msg,
		    "emlxs_hba_init: Too many ring masks defined. cnt=%d", i);
		return (1);
	}

	/* Initialize all the port objects */
	hba->vpi_base = 0;
	hba->vpi_max = 0;
	for (i = 0; i < MAX_VPORTS; i++) {
		vport = &VPORT(i);
		vport->hba = hba;
		vport->vpi = i;
		vport->VPIobj.index = i;
		vport->VPIobj.VPI = i;
		vport->VPIobj.port = vport;
		vport->VPIobj.state = VPI_STATE_OFFLINE;
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

} /* emlxs_sli3_hba_init() */


/*
 * 0: quiesce indicates the call is not from quiesce routine.
 * 1: quiesce indicates the call is from quiesce routine.
 */
static uint32_t
emlxs_sli3_hba_reset(emlxs_hba_t *hba, uint32_t restart, uint32_t skip_post,
	uint32_t quiesce)
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
		EMLXS_STATE_CHANGE(hba, FC_ERROR);

		return (1);
	}

	/* Kill the adapter first */
	if (quiesce == 0) {
		emlxs_sli3_hba_kill(hba);
	} else {
		emlxs_sli3_hba_kill4quiesce(hba);
	}

	if (restart) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Restarting.");
		EMLXS_STATE_CHANGE(hba, FC_INIT_START);

		ready = (HS_FFRDY | HS_MBRDY);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Resetting.");
		EMLXS_STATE_CHANGE(hba, FC_WARM_START);

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

		/* Only skip post after emlxs_sli3_online is completed */
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

	hba->sli.sli3.hc_copy = HC_INITFF;
	WRITE_CSR_REG(hba, FC_HC_REG(hba), hba->sli.sli3.hc_copy);

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
		status = READ_CSR_REG(hba, FC_HS_REG(hba));

		/* Check to see if any errors occurred during init */
		if (status & HS_FFERM) {
			status1 = READ_SLIM_ADDR(hba, ((volatile uint8_t *)
			    hba->sli.sli3.slim_addr + 0xa8));
			status2 = READ_SLIM_ADDR(hba, ((volatile uint8_t *)
			    hba->sli.sli3.slim_addr + 0xac));

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_reset_failed_msg,
			    "HS_FFERM: status=0x%x status1=0x%x status2=0x%x",
			    status, status1, status2);

			EMLXS_STATE_CHANGE(hba, FC_ERROR);
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

#ifdef FMA_SUPPORT
reset_fail:
#endif  /* FMA_SUPPORT */

	/* Timeout occurred */
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_reset_failed_msg,
	    "Timeout: status=0x%x", status);
	EMLXS_STATE_CHANGE(hba, FC_ERROR);

	/* Log a dump event */
	emlxs_log_dump_event(port, NULL, 0);

	return (1);

done:

	/* Initialize hc_copy */
	hba->sli.sli3.hc_copy = READ_CSR_REG(hba, FC_HC_REG(hba));

#ifdef FMA_SUPPORT
	/* Access handle validation */
	if ((emlxs_fm_check_acc_handle(hba, hba->pci_acc_handle)
	    != DDI_FM_OK) ||
	    (emlxs_fm_check_acc_handle(hba, hba->sli.sli3.slim_acc_handle)
	    != DDI_FM_OK) ||
	    (emlxs_fm_check_acc_handle(hba, hba->sli.sli3.csr_acc_handle)
	    != DDI_FM_OK)) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_invalid_access_handle_msg, NULL);
		goto reset_fail;
	}
#endif  /* FMA_SUPPORT */

	/* Reset the hba structure */
	hba->flag &= FC_RESET_MASK;
	hba->channel_tx_count = 0;
	hba->io_count = 0;
	hba->iodone_count = 0;
	hba->topology = 0;
	hba->linkspeed = 0;
	hba->heartbeat_active = 0;
	hba->discovery_timer = 0;
	hba->linkup_timer = 0;
	hba->loopback_tics = 0;


	/* Reset the ring objects */
	for (i = 0; i < MAX_RINGS; i++) {
		rp = &hba->sli.sli3.ring[i];
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

	return (0);

} /* emlxs_sli3_hba_reset */


#define	BPL_CMD		0
#define	BPL_RESP	1
#define	BPL_DATA	2

static ULP_BDE64 *
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
		    BE_SWAP32(PADDR_HI(cp->dmac_laddress));
		bpl->addrLow =
		    BE_SWAP32(PADDR_LO(cp->dmac_laddress));
		bpl->tus.f.bdeSize = MIN(size, cp->dmac_size);
		bpl->tus.f.bdeFlags = bdeFlags;
		bpl->tus.w = BE_SWAP32(bpl->tus.w);

		bpl++;
		size -= cp->dmac_size;
	}

	return (bpl);

} /* emlxs_pkt_to_bpl */


static uint32_t
emlxs_sli2_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t	*hba = HBA;
	fc_packet_t	*pkt;
	MATCHMAP	*bmp;
	ULP_BDE64	*bpl;
	uint64_t	bp;
	uint8_t		bdeFlag;
	IOCB		*iocb;
	IOCBQ		*iocbq;
	CHANNEL	*cp;
	uint32_t	cmd_cookie_cnt;
	uint32_t	resp_cookie_cnt;
	uint32_t	data_cookie_cnt;
	uint32_t	cookie_cnt;

	cp = sbp->channel;
	iocb = (IOCB *) & sbp->iocbq;
	pkt = PRIV2PKT(sbp);

#ifdef EMLXS_SPARC
	/* Use FCP MEM_BPL table to get BPL buffer */
	bmp = hba->sli.sli3.fcp_bpl_table[sbp->iotag];
#else
	/* Use MEM_BPL pool to get BPL buffer */
	bmp = (MATCHMAP *) emlxs_mem_get(hba, MEM_BPL, 0);

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

	iocbq = &sbp->iocbq;
	if (iocbq->flag & IOCB_FCP_CMD)
		goto fcpcmd;

	switch (cp->channelno) {
	case FC_FCP_RING:
fcpcmd:
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
	iocb->un.genreq64.bdl.addrHigh = PADDR_HI(bp);
	iocb->un.genreq64.bdl.addrLow  = PADDR_LO(bp);
	iocb->un.genreq64.bdl.bdeSize  = cookie_cnt * sizeof (ULP_BDE64);

	iocb->ULPBDECOUNT = 1;
	iocb->ULPLE = 1;

	return (0);

} /* emlxs_sli2_bde_setup */


static uint32_t
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
	IOCBQ		*iocbq;
	CHANNEL		*cp;

	cp = sbp->channel;
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

	iocbq = &sbp->iocbq;
	if (iocbq->flag & IOCB_FCP_CMD)
		goto fcpcmd;

	switch (cp->channelno) {
	case FC_FCP_RING:
fcpcmd:
		/* CMD payload */
		iocb->un.fcpi64.bdl.addrHigh =
		    PADDR_HI(cp_cmd->dmac_laddress);
		iocb->un.fcpi64.bdl.addrLow =
		    PADDR_LO(cp_cmd->dmac_laddress);
		iocb->un.fcpi64.bdl.bdeSize  = pkt->pkt_cmdlen;
		iocb->un.fcpi64.bdl.bdeFlags = 0;

		if (pkt->pkt_tran_type != FC_PKT_OUTBOUND) {
			/* RSP payload */
			iocb->unsli3.ext_iocb.ebde1.addrHigh =
			    PADDR_HI(cp_resp->dmac_laddress);
			iocb->unsli3.ext_iocb.ebde1.addrLow =
			    PADDR_LO(cp_resp->dmac_laddress);
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
					    PADDR_HI(cp_data->
					    dmac_laddress);
					bde->addrLow =
					    PADDR_LO(cp_data->
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
		    PADDR_HI(cp_cmd->dmac_laddress);
		iocb->un.xseq64.bdl.addrLow =
		    PADDR_LO(cp_cmd->dmac_laddress);
		iocb->un.xseq64.bdl.bdeSize  = pkt->pkt_cmdlen;
		iocb->un.xseq64.bdl.bdeFlags = 0;

		break;

	case FC_ELS_RING:

		/* CMD payload */
		iocb->un.elsreq64.bdl.addrHigh =
		    PADDR_HI(cp_cmd->dmac_laddress);
		iocb->un.elsreq64.bdl.addrLow =
		    PADDR_LO(cp_cmd->dmac_laddress);
		iocb->un.elsreq64.bdl.bdeSize  = pkt->pkt_cmdlen;
		iocb->un.elsreq64.bdl.bdeFlags = 0;

		/* RSP payload */
		if (pkt->pkt_tran_type != FC_PKT_OUTBOUND) {
			iocb->unsli3.ext_iocb.ebde1.addrHigh =
			    PADDR_HI(cp_resp->dmac_laddress);
			iocb->unsli3.ext_iocb.ebde1.addrLow =
			    PADDR_LO(cp_resp->dmac_laddress);
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
		    PADDR_HI(cp_cmd->dmac_laddress);
		iocb->un.genreq64.bdl.addrLow =
		    PADDR_LO(cp_cmd->dmac_laddress);
		iocb->un.genreq64.bdl.bdeSize  = pkt->pkt_cmdlen;
		iocb->un.genreq64.bdl.bdeFlags = 0;

		if ((pkt->pkt_tran_type != FC_PKT_OUTBOUND) ||
		    (pkt->pkt_cmd_fhdr.type == EMLXS_MENLO_TYPE)) {
			/* RSP payload */
			iocb->unsli3.ext_iocb.ebde1.addrHigh =
			    PADDR_HI(cp_resp->dmac_laddress);
			iocb->unsli3.ext_iocb.ebde1.addrLow =
			    PADDR_LO(cp_resp->dmac_laddress);
			iocb->unsli3.ext_iocb.ebde1.tus.f.bdeSize =
			    pkt->pkt_rsplen;
			iocb->unsli3.ext_iocb.ebde1.tus.f.bdeFlags =
			    BUFF_USE_RCV;
			iocb->unsli3.ext_iocb.ebde_count = 1;
		}

		break;
	}

	iocb->ULPBDECOUNT = 0;
	iocb->ULPLE = 0;

	return (0);

} /* emlxs_sli3_bde_setup */


/* Only used for FCP Data xfers */
#ifdef SFCT_SUPPORT
/*ARGSUSED*/
static uint32_t
emlxs_sli2_fct_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp)
{
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
		iocb->ULPBDECOUNT = 0;
		iocb->ULPLE = 1;
		return (0);
	}
#ifdef EMLXS_SPARC
	/* Use FCP MEM_BPL table to get BPL buffer */
	bmp = hba->sli.sli3.fcp_bpl_table[sbp->iotag];
#else
	/* Use MEM_BPL pool to get BPL buffer */
	bmp = (MATCHMAP *)emlxs_mem_get(hba, MEM_BPL, 0);
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
		iocb->ULPBDECOUNT = 0;
		iocb->ULPLE = 1;
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
		    BE_SWAP32(PADDR_HI(bctl->bctl_dev_addr));
		bpl->addrLow =
		    BE_SWAP32(PADDR_LO(bctl->bctl_dev_addr));
		bpl->tus.f.bdeSize = MIN(resid, sgl->seg_length);
		bpl->tus.f.bdeFlags = bdeFlags;
		bpl->tus.w = BE_SWAP32(bpl->tus.w);
		bpl++;

		resid -= MIN(resid, sgl->seg_length);
		sgl++;
	}

	/* Init the IOCB */
	iocb->un.fcpt64.bdl.addrHigh = PADDR_HI(bp);
	iocb->un.fcpt64.bdl.addrLow = PADDR_LO(bp);
	iocb->un.fcpt64.bdl.bdeSize = sgllen * sizeof (ULP_BDE64);
	iocb->un.fcpt64.bdl.bdeFlags = BUFF_TYPE_BDL;

	iocb->un.fcpt64.fcpt_Length =
	    (fct_task->task_flags & TF_WRITE_DATA) ? size : 0;
	iocb->un.fcpt64.fcpt_Offset = 0;

	iocb->ULPBDECOUNT = 1;
	iocb->ULPLE = 1;
	sbp->bmp = bmp;

	return (0);

} /* emlxs_sli2_fct_bde_setup */
#endif /* SFCT_SUPPORT */


#ifdef SFCT_SUPPORT
/*ARGSUSED*/
static uint32_t
emlxs_sli3_fct_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp)
{
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
		iocb->ULPBDECOUNT = 0;
		iocb->ULPLE = 0;
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
	iocb->un.fcpt64.bdl.addrHigh = PADDR_HI(bctl->bctl_dev_addr);
	iocb->un.fcpt64.bdl.addrLow = PADDR_LO(bctl->bctl_dev_addr);
	iocb->un.fcpt64.bdl.bdeSize = MIN(resid, sgl->seg_length);
	iocb->un.fcpt64.bdl.bdeFlags = bdeFlags;
	resid -= MIN(resid, sgl->seg_length);
	sgl++;

	/* Init remaining BDE's */
	bde = (ULP_BDE64 *)&iocb->unsli3.ext_iocb.ebde1;
	for (sgllen = 1; sgllen < count && resid > 0; sgllen++) {
		bde->addrHigh = PADDR_HI(bctl->bctl_dev_addr);
		bde->addrLow = PADDR_LO(bctl->bctl_dev_addr);
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

	iocb->ULPBDECOUNT = 0;
	iocb->ULPLE = 0;

	return (0);

} /* emlxs_sli3_fct_bde_setup */
#endif /* SFCT_SUPPORT */


static void
emlxs_sli3_issue_iocb_cmd(emlxs_hba_t *hba, CHANNEL *cp, IOCBQ *iocbq)
{
#ifdef FMA_SUPPORT
	emlxs_port_t *port = &PPORT;
#endif	/* FMA_SUPPORT */
	PGP *pgp;
	emlxs_buf_t *sbp;
	SLIM2 *slim2p = (SLIM2 *)hba->sli.sli3.slim2.virt;
	RING *rp;
	uint32_t nextIdx;
	uint32_t status;
	void *ioa2;
	off_t offset;
	uint32_t count = 0;
	uint32_t flag;
	uint32_t channelno;
	int32_t throttle;

	channelno = cp->channelno;
	rp = (RING *)cp->iopath;

	throttle = 0;

	/* Check if FCP ring and adapter is not ready */
	/* We may use any ring for FCP_CMD */
	if (iocbq && (iocbq->flag & IOCB_FCP_CMD) && (hba->state != FC_READY)) {
		if (!(iocbq->flag & IOCB_SPECIAL) || !iocbq->port ||
		    !(((emlxs_port_t *)iocbq->port)->tgt_mode)) {
			emlxs_tx_put(iocbq, 1);
			return;
		}
	}

	/* Attempt to acquire CMD_RING lock */
	if (mutex_tryenter(&EMLXS_CMD_RING_LOCK(channelno)) == 0) {
		/* Queue it for later */
		if (iocbq) {
			if ((hba->io_count -
			    hba->channel_tx_count) > 10) {
				emlxs_tx_put(iocbq, 1);
				return;
			} else {

				/*
				 * EMLXS_MSGF(EMLXS_CONTEXT,
				 * &emlxs_ring_watchdog_msg,
				 * "%s host=%d port=%d cnt=%d,%d  RACE
				 * CONDITION3 DETECTED.",
				 * emlxs_ring_xlate(channelno),
				 * rp->fc_cmdidx, rp->fc_port_cmdidx,
				 * hba->channel_tx_count,
				 * hba->io_count);
				 */
				mutex_enter(&EMLXS_CMD_RING_LOCK(channelno));
			}
		} else {
			return;
		}
	}
	/* CMD_RING_LOCK acquired */

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

	/* Read adapter's get index */
	pgp = (PGP *)
	    &((SLIM2 *)hba->sli.sli3.slim2.virt)->mbx.us.s2.port[channelno];
	offset =
	    (off_t)((uint64_t)((unsigned long)&(pgp->cmdGetInx)) -
	    (uint64_t)((unsigned long)hba->sli.sli3.slim2.virt));
	EMLXS_MPDATA_SYNC(hba->sli.sli3.slim2.dma_handle, offset, 4,
	    DDI_DMA_SYNC_FORKERNEL);
	rp->fc_port_cmdidx = BE_SWAP32(pgp->cmdGetInx);

	/* Calculate the next put index */
	nextIdx =
	    (rp->fc_cmdidx + 1 >= rp->fc_numCiocb) ? 0 : rp->fc_cmdidx + 1;

	/* Check if ring is full */
	if (nextIdx == rp->fc_port_cmdidx) {
		/* Try one more time */
		EMLXS_MPDATA_SYNC(hba->sli.sli3.slim2.dma_handle, offset, 4,
		    DDI_DMA_SYNC_FORKERNEL);
		rp->fc_port_cmdidx = BE_SWAP32(pgp->cmdGetInx);

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
		/* Try to get the next iocb on the tx queue */
		iocbq = emlxs_tx_get(cp, 1);
	}

sendit:
	count = 0;

	/* Process each iocbq */
	while (iocbq) {

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
					slim2p->mbx.us.s2.host[channelno].
					    cmdPutInx =
					    BE_SWAP32(rp->fc_cmdidx);

					/* DMA sync the index for the adapter */
					offset = (off_t)
					    ((uint64_t)
					    ((unsigned long)&(slim2p->mbx.us.
					    s2.host[channelno].cmdPutInx)) -
					    (uint64_t)((unsigned long)slim2p));
					EMLXS_MPDATA_SYNC(hba->sli.sli3.slim2.
					    dma_handle, offset, 4,
					    DDI_DMA_SYNC_FORDEV);
				} else {
					ioa2 = (void *)
					    ((char *)hba->sli.sli3.slim_addr +
					    hba->sli.sli3.hgp_ring_offset +
					    ((channelno * 2) *
					    sizeof (uint32_t)));
					WRITE_SLIM_ADDR(hba,
					    (volatile uint32_t *)ioa2,
					    rp->fc_cmdidx);
				}

				status = (CA_R0ATT << (channelno * 4));
				WRITE_CSR_REG(hba, FC_CA_REG(hba),
				    (volatile uint32_t)status);

			}
			/* Perform delay */
			if ((channelno == FC_ELS_RING) &&
			    !(iocbq->flag & IOCB_FCP_CMD)) {
				drv_usecwait(100000);
			} else {
				drv_usecwait(20000);
			}
		}

		/*
		 * At this point, we have a command ring slot available
		 * and an iocb to send
		 */
		flag =  iocbq->flag;

		/* Send the iocb */
		emlxs_sli3_issue_iocb(hba, rp, iocbq);
		/*
		 * After this, the sbp / iocb should not be
		 * accessed in the xmit path.
		 */

		count++;
		if (iocbq && (!(flag & IOCB_SPECIAL))) {
			/* Check if HBA is full */
			throttle = hba->io_throttle - hba->io_active;
			if (throttle <= 0) {
				goto busy;
			}
		}

		/* Calculate the next put index */
		nextIdx =
		    (rp->fc_cmdidx + 1 >=
		    rp->fc_numCiocb) ? 0 : rp->fc_cmdidx + 1;

		/* Check if ring is full */
		if (nextIdx == rp->fc_port_cmdidx) {
			/* Try one more time */
			EMLXS_MPDATA_SYNC(hba->sli.sli3.slim2.dma_handle,
			    offset, 4, DDI_DMA_SYNC_FORKERNEL);
			rp->fc_port_cmdidx = BE_SWAP32(pgp->cmdGetInx);

			if (nextIdx == rp->fc_port_cmdidx) {
				goto busy;
			}
		}

		/* Get the next iocb from the tx queue if there is one */
		iocbq = emlxs_tx_get(cp, 1);
	}

	if (count) {
		/* Update the adapter's cmd put index */
		if (hba->bus_type == SBUS_FC) {
			slim2p->mbx.us.s2.host[channelno].
			    cmdPutInx = BE_SWAP32(rp->fc_cmdidx);

			/* DMA sync the index for the adapter */
			offset = (off_t)
			    ((uint64_t)((unsigned long)&(slim2p->mbx.us.s2.
			    host[channelno].cmdPutInx)) -
			    (uint64_t)((unsigned long)slim2p));
			EMLXS_MPDATA_SYNC(hba->sli.sli3.slim2.dma_handle,
			    offset, 4, DDI_DMA_SYNC_FORDEV);
		} else {
			ioa2 =
			    (void *)((char *)hba->sli.sli3.slim_addr +
			    hba->sli.sli3.hgp_ring_offset +
			    ((channelno * 2) * sizeof (uint32_t)));
			WRITE_SLIM_ADDR(hba, (volatile uint32_t *)ioa2,
			    rp->fc_cmdidx);
		}

		status = (CA_R0ATT << (channelno * 4));
		WRITE_CSR_REG(hba, FC_CA_REG(hba),
		    (volatile uint32_t)status);

		/* Check tx queue one more time before releasing */
		if ((iocbq = emlxs_tx_get(cp, 1))) {
			/*
			 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ring_watchdog_msg,
			 * "%s host=%d port=%d   RACE CONDITION1
			 * DETECTED.", emlxs_ring_xlate(channelno),
			 * rp->fc_cmdidx, rp->fc_port_cmdidx);
			 */
			goto sendit;
		}
	}

#ifdef FMA_SUPPORT
	/* Access handle validation */
	EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli3.slim_acc_handle);
	EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli3.csr_acc_handle);
#endif  /* FMA_SUPPORT */

	mutex_exit(&EMLXS_CMD_RING_LOCK(channelno));

	return;

busy:

	/*
	 * Set ring to SET R0CE_REQ in Chip Att register.
	 * Chip will tell us when an entry is freed.
	 */
	if (count) {
		/* Update the adapter's cmd put index */
		if (hba->bus_type == SBUS_FC) {
			slim2p->mbx.us.s2.host[channelno].cmdPutInx =
			    BE_SWAP32(rp->fc_cmdidx);

			/* DMA sync the index for the adapter */
			offset = (off_t)
			    ((uint64_t)((unsigned long)&(slim2p->mbx.us.s2.
			    host[channelno].cmdPutInx)) -
			    (uint64_t)((unsigned long)slim2p));
			EMLXS_MPDATA_SYNC(hba->sli.sli3.slim2.dma_handle,
			    offset, 4, DDI_DMA_SYNC_FORDEV);
		} else {
			ioa2 =
			    (void *)((char *)hba->sli.sli3.slim_addr +
			    hba->sli.sli3.hgp_ring_offset +
			    ((channelno * 2) * sizeof (uint32_t)));
			WRITE_SLIM_ADDR(hba, (volatile uint32_t *)ioa2,
			    rp->fc_cmdidx);
		}
	}

	status = ((CA_R0ATT | CA_R0CE_REQ) << (channelno * 4));
	WRITE_CSR_REG(hba, FC_CA_REG(hba), (volatile uint32_t)status);

	if (throttle <= 0) {
		HBASTATS.IocbThrottled++;
	} else {
		HBASTATS.IocbRingFull[channelno]++;
	}

#ifdef FMA_SUPPORT
	/* Access handle validation */
	EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli3.slim_acc_handle);
	EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli3.csr_acc_handle);
#endif  /* FMA_SUPPORT */

	mutex_exit(&EMLXS_CMD_RING_LOCK(channelno));

	return;

} /* emlxs_sli3_issue_iocb_cmd() */


/* MBX_NOWAIT - returns MBX_BUSY or MBX_SUCCESS or MBX_HARDWARE_ERROR */
/* MBX_WAIT   - returns MBX_TIMEOUT or mailbox_status */
/* MBX_SLEEP  - returns MBX_TIMEOUT or mailbox_status */
/* MBX_POLL   - returns MBX_TIMEOUT or mailbox_status */

static uint32_t
emlxs_sli3_issue_mbox_cmd(emlxs_hba_t *hba, MAILBOXQ *mbq, int32_t flag,
    uint32_t tmo)
{
	emlxs_port_t		*port;
	SLIM2			*slim2p = (SLIM2 *)hba->sli.sli3.slim2.virt;
	MAILBOX			*mbox;
	MAILBOX			*mb;
	volatile uint32_t	word0;
	volatile uint32_t	ldata;
	uint32_t		ha_copy;
	off_t			offset;
	MATCHMAP		*mbox_bp;
	uint32_t		tmo_local;
	MAILBOX			*swpmb;

	if (!mbq->port) {
		mbq->port = &PPORT;
	}

	port = (emlxs_port_t *)mbq->port;

	mb = (MAILBOX *)mbq;
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

	/* Convert tmo seconds to 10 millisecond tics */
	tmo_local = tmo * 100;

	/* Adjust wait flag */
	if (flag != MBX_NOWAIT) {
		/* If interrupt is enabled, use sleep, otherwise poll */
		if (hba->sli.sli3.hc_copy & HC_MBINT_ENA) {
			flag = MBX_SLEEP;
		} else {
			flag = MBX_POLL;
		}
	}

	mutex_enter(&EMLXS_PORT_LOCK);

	/* Check for hardware error */
	if (hba->flag & FC_HARDWARE_ERROR) {
		mb->mbxStatus = (hba->flag & FC_OVERTEMP_EVENT) ?
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

			DELAYMS(10);
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
	WRITE_CSR_REG(hba, FC_HA_REG(hba), HA_MBATT);

	if (hba->flag & FC_SLIM2_MODE) {
		/* First copy command data */
		mbox = FC_SLIM2_MAILBOX(hba);
		offset =
		    (off_t)((uint64_t)((unsigned long)mbox)
		    - (uint64_t)((unsigned long)slim2p));

#ifdef MBOX_EXT_SUPPORT
		if (mbq->extbuf) {
			uint32_t *mbox_ext =
			    (uint32_t *)((uint8_t *)mbox +
			    MBOX_EXTENSION_OFFSET);
			off_t offset_ext   = offset + MBOX_EXTENSION_OFFSET;

			BE_SWAP32_BCOPY((uint8_t *)mbq->extbuf,
			    (uint8_t *)mbox_ext, mbq->extsize);

			EMLXS_MPDATA_SYNC(hba->sli.sli3.slim2.dma_handle,
			    offset_ext, mbq->extsize,
			    DDI_DMA_SYNC_FORDEV);
		}
#endif /* MBOX_EXT_SUPPORT */

		BE_SWAP32_BCOPY((uint8_t *)mb, (uint8_t *)mbox,
		    MAILBOX_CMD_BSIZE);

		EMLXS_MPDATA_SYNC(hba->sli.sli3.slim2.dma_handle, offset,
		    MAILBOX_CMD_BSIZE, DDI_DMA_SYNC_FORDEV);
	}
	/* Check for config port command */
	else if (mb->mbxCommand == MBX_CONFIG_PORT) {
		/* copy command data into host mbox for cmpl */
		mbox = FC_SLIM2_MAILBOX(hba);
		offset = (off_t)((uint64_t)((unsigned long)mbox)
		    - (uint64_t)((unsigned long)slim2p));

		BE_SWAP32_BCOPY((uint8_t *)mb, (uint8_t *)mbox,
		    MAILBOX_CMD_BSIZE);

		EMLXS_MPDATA_SYNC(hba->sli.sli3.slim2.dma_handle, offset,
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
		if (mbq->extbuf) {
			uint32_t *mbox_ext =
			    (uint32_t *)((uint8_t *)mbox +
			    MBOX_EXTENSION_OFFSET);
			WRITE_SLIM_COPY(hba, (uint32_t *)mbq->extbuf,
			    mbox_ext, (mbq->extsize / 4));
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
	WRITE_CSR_REG(hba, FC_CA_REG(hba), CA_MBATT);

	mutex_exit(&EMLXS_PORT_LOCK);

#ifdef FMA_SUPPORT
	/* Access handle validation */
	if ((emlxs_fm_check_acc_handle(hba, hba->sli.sli3.slim_acc_handle)
	    != DDI_FM_OK) ||
	    (emlxs_fm_check_acc_handle(hba, hba->sli.sli3.csr_acc_handle)
	    != DDI_FM_OK)) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_invalid_access_handle_msg, NULL);
		return (MBX_HARDWARE_ERROR);
	}
#endif  /* FMA_SUPPORT */

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
			    READ_CSR_REG(hba, FC_HA_REG(hba));

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
					EMLXS_STATE_CHANGE(hba, FC_ERROR);
					emlxs_mb_fini(hba, NULL, MBX_TIMEOUT);

					break;
				}

				DELAYUS(500);
				ha_copy = READ_CSR_REG(hba, FC_HA_REG(hba));
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

			EMLXS_MPDATA_SYNC(hba->sli.sli3.slim2.dma_handle,
			    offset, sizeof (uint32_t), DDI_DMA_SYNC_FORKERNEL);
			word0 = *((volatile uint32_t *)mbox);
			word0 = BE_SWAP32(word0);
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
				EMLXS_STATE_CHANGE(hba, FC_ERROR);
				emlxs_mb_fini(hba, NULL, MBX_TIMEOUT);

				break;
			}

			DELAYUS(500);

			/* Get first word of mailbox */
			if (hba->flag & FC_SLIM2_MODE) {
				EMLXS_MPDATA_SYNC(
				    hba->sli.sli3.slim2.dma_handle, offset,
				    sizeof (uint32_t), DDI_DMA_SYNC_FORKERNEL);
				word0 = *((volatile uint32_t *)mbox);
				word0 = BE_SWAP32(word0);
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
			EMLXS_MPDATA_SYNC(hba->sli.sli3.slim2.dma_handle,
			    offset, MAILBOX_CMD_BSIZE, DDI_DMA_SYNC_FORKERNEL);

			BE_SWAP32_BCOPY((uint8_t *)mbox, (uint8_t *)mb,
			    MAILBOX_CMD_BSIZE);
		} else {
			READ_SLIM_COPY(hba, (uint32_t *)mb,
			    (uint32_t *)mbox, MAILBOX_CMD_WSIZE);
		}

#ifdef MBOX_EXT_SUPPORT
		if (mbq->extbuf) {
			uint32_t *mbox_ext =
			    (uint32_t *)((uint8_t *)mbox +
			    MBOX_EXTENSION_OFFSET);
			off_t offset_ext   = offset + MBOX_EXTENSION_OFFSET;

			if (hba->flag & FC_SLIM2_MODE) {
				EMLXS_MPDATA_SYNC(
				    hba->sli.sli3.slim2.dma_handle, offset_ext,
				    mbq->extsize, DDI_DMA_SYNC_FORKERNEL);

				BE_SWAP32_BCOPY((uint8_t *)mbox_ext,
				    (uint8_t *)mbq->extbuf, mbq->extsize);
			} else {
				READ_SLIM_COPY(hba,
				    (uint32_t *)mbq->extbuf, mbox_ext,
				    (mbq->extsize / 4));
			}
		}
#endif /* MBOX_EXT_SUPPORT */

		/* Sync the memory buffer */
		if (mbq->bp) {
			mbox_bp = (MATCHMAP *)mbq->bp;
			EMLXS_MPDATA_SYNC(mbox_bp->dma_handle, 0,
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
			if (mbq->mbox_cmpl) {
				(void) (mbq->mbox_cmpl)(hba, mbq);
			}
		}

		/* Clear the attention bit */
		WRITE_CSR_REG(hba, FC_HA_REG(hba), HA_MBATT);

		/* Clean up the mailbox area */
		emlxs_mb_fini(hba, NULL, mb->mbxStatus);

		break;

	}	/* switch (flag) */

	return (mb->mbxStatus);

} /* emlxs_sli3_issue_mbox_cmd() */


#ifdef SFCT_SUPPORT
static uint32_t
emlxs_sli3_prep_fct_iocb(emlxs_port_t *port, emlxs_buf_t *cmd_sbp,
	int channel)
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
	CHANNEL *cp;

	dbuf = cmd_sbp->fct_buf;
	fct_cmd = cmd_sbp->fct_cmd;
	fct_task = (scsi_task_t *)fct_cmd->cmd_specific;
	ndlp = *(emlxs_node_t **)fct_cmd->cmd_rp->rp_fca_private;
	did = fct_cmd->cmd_rportid;

	cp = (CHANNEL *)cmd_sbp->channel;

	channel = channel;
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
	    "emlxs_fct_send_fcp_data %p: flgs=%x ioflags=%x dl=%d,%d,%d,%d,%d",
	    fct_cmd, dbuf->db_flags, ioflags, fct_task->task_cmd_xfer_length,
	    fct_task->task_nbytes_transferred, dbuf->db_data_size,
	    fct_task->task_expected_xfer_length, channel);
#endif /* FCT_API_TRACE */


	/* Get the iotag by registering the packet */
	iotag = emlxs_register_pkt(cp, cmd_sbp);

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


	iocbq->channel = (void *)cmd_sbp->channel;

	if (emlxs_fct_bde_setup(port, cmd_sbp)) {
		/* Unregister the packet */
		(void) emlxs_unregister_pkt(cmd_sbp->channel, iotag, 0);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to setup buffer list. did=%x", did);

		return (IOERR_INTERNAL_ERROR);
	}
	/* Point of no return */

	/* Initalize iocb */
	iocb->ULPCONTEXT = (uint16_t)fct_cmd->cmd_rxid;
	iocb->ULPIOTAG = (uint16_t)iotag;
	iocb->ULPRSVDBYTE = ((timeout > 0xff) ? 0 : timeout);
	iocb->ULPOWNER = OWN_CHIP;
	iocb->ULPCLASS = cmd_sbp->class;

	iocb->ULPPU = 1;	/* Wd4 is relative offset */
	iocb->un.fcpt64.fcpt_Offset = dbuf->db_relative_offset;

	if (fct_task->task_flags & TF_WRITE_DATA) {
		iocb->ULPCOMMAND = CMD_FCP_TRECEIVE64_CX;
	} else {	/* TF_READ_DATA */

		iocb->ULPCOMMAND = CMD_FCP_TSEND64_CX;

		if ((hba->sli_mode == EMLXS_HBA_SLI3_MODE) &&
		    (dbuf->db_data_size ==
		    fct_task->task_expected_xfer_length)) {
			iocb->ULPCT = 0x1;
			/* enable auto-rsp AP feature */
		}
	}

	return (IOERR_SUCCESS);

} /* emlxs_sli3_prep_fct_iocb() */
#endif /* SFCT_SUPPORT */

/* ARGSUSED */
static uint32_t
emlxs_sli3_prep_fcp_iocb(emlxs_port_t *port, emlxs_buf_t *sbp, int channel)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	CHANNEL *cp;
	IOCBQ *iocbq;
	IOCB *iocb;
	NODELIST *ndlp;
	uint16_t iotag;
	uint32_t did;

	pkt = PRIV2PKT(sbp);
	did = LE_SWAP24_LO(pkt->pkt_cmd_fhdr.d_id);
	cp = &hba->chan[FC_FCP_RING];

	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;

	/* Find target node object */
	ndlp = (NODELIST *)iocbq->node;

	/* Get the iotag by registering the packet */
	iotag = emlxs_register_pkt(cp, sbp);

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
	iocbq->channel = (void *) cp;

	/* Indicate this is a FCP cmd */
	iocbq->flag |= IOCB_FCP_CMD;

	if (emlxs_bde_setup(port, sbp)) {
		/* Unregister the packet */
		(void) emlxs_unregister_pkt(cp, iotag, 0);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to setup buffer list. did=%x", did);

		return (FC_TRAN_BUSY);
	}
	/* Point of no return */

	/* Initalize iocb */
	iocb->ULPCONTEXT = ndlp->nlp_Rpi;
	iocb->ULPIOTAG = iotag;
	iocb->ULPRSVDBYTE =
	    ((pkt->pkt_timeout > 0xff) ? 0 : pkt->pkt_timeout);
	iocb->ULPOWNER = OWN_CHIP;

	switch (FC_TRAN_CLASS(pkt->pkt_tran_flags)) {
	case FC_TRAN_CLASS1:
		iocb->ULPCLASS = CLASS1;
		break;
	case FC_TRAN_CLASS2:
		iocb->ULPCLASS = CLASS2;
		/* iocb->ULPCLASS = CLASS3; */
		break;
	case FC_TRAN_CLASS3:
	default:
		iocb->ULPCLASS = CLASS3;
		break;
	}

	/* if device is FCP-2 device, set the following bit */
	/* that says to run the FC-TAPE protocol. */
	if (ndlp->nlp_fcp_info & NLP_FCP_2_DEVICE) {
		iocb->ULPFCP2RCVY = 1;
	}

	if (pkt->pkt_datalen == 0) {
		iocb->ULPCOMMAND = CMD_FCP_ICMND64_CR;
	} else if (pkt->pkt_tran_type == FC_PKT_FCP_READ) {
		iocb->ULPCOMMAND = CMD_FCP_IREAD64_CR;
		iocb->ULPPU = PARM_READ_CHECK;
		iocb->un.fcpi64.fcpi_parm = pkt->pkt_datalen;
	} else {
		iocb->ULPCOMMAND = CMD_FCP_IWRITE64_CR;
	}

	return (FC_SUCCESS);

} /* emlxs_sli3_prep_fcp_iocb() */


static uint32_t
emlxs_sli3_prep_ip_iocb(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	IOCBQ *iocbq;
	IOCB *iocb;
	CHANNEL *cp;
	NODELIST *ndlp;
	uint16_t iotag;
	uint32_t did;

	pkt = PRIV2PKT(sbp);
	cp = &hba->chan[FC_IP_RING];
	did = LE_SWAP24_LO(pkt->pkt_cmd_fhdr.d_id);

	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;
	ndlp = (NODELIST *)iocbq->node;

	/* Get the iotag by registering the packet */
	iotag = emlxs_register_pkt(cp, sbp);

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
	iocbq->channel = (void *) cp;

	if (emlxs_bde_setup(port, sbp)) {
		/* Unregister the packet */
		(void) emlxs_unregister_pkt(cp, iotag, 0);

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

	iocb->ULPIOTAG = iotag;
	iocb->ULPRSVDBYTE =
	    ((pkt->pkt_timeout > 0xff) ? 0 : pkt->pkt_timeout);
	iocb->ULPOWNER = OWN_CHIP;

	if (pkt->pkt_tran_type == FC_PKT_BROADCAST) {
		HBASTATS.IpBcastIssued++;

		iocb->ULPCOMMAND = CMD_XMIT_BCAST64_CN;
		iocb->ULPCONTEXT = 0;

		if (hba->sli_mode == EMLXS_HBA_SLI3_MODE) {
			if (hba->topology != TOPOLOGY_LOOP) {
				iocb->ULPCT = 0x1;
			}
			iocb->ULPCONTEXT = port->vpi;
		}
	} else {
		HBASTATS.IpSeqIssued++;

		iocb->ULPCOMMAND = CMD_XMIT_SEQUENCE64_CX;
		iocb->ULPCONTEXT = ndlp->nlp_Xri;
	}

	switch (FC_TRAN_CLASS(pkt->pkt_tran_flags)) {
	case FC_TRAN_CLASS1:
		iocb->ULPCLASS = CLASS1;
		break;
	case FC_TRAN_CLASS2:
		iocb->ULPCLASS = CLASS2;
		break;
	case FC_TRAN_CLASS3:
	default:
		iocb->ULPCLASS = CLASS3;
		break;
	}

	return (FC_SUCCESS);

} /* emlxs_sli3_prep_ip_iocb() */


static uint32_t
emlxs_sli3_prep_els_iocb(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	IOCBQ *iocbq;
	IOCB *iocb;
	CHANNEL *cp;
	uint16_t iotag;
	uint32_t did;
	uint32_t cmd;

	pkt = PRIV2PKT(sbp);
	cp = &hba->chan[FC_ELS_RING];
	did = LE_SWAP24_LO(pkt->pkt_cmd_fhdr.d_id);

	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;


	/* Get the iotag by registering the packet */
	iotag = emlxs_register_pkt(cp, sbp);

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
	iocbq->channel = (void *) cp;

	if (emlxs_bde_setup(port, sbp)) {
		/* Unregister the packet */
		(void) emlxs_unregister_pkt(cp, iotag, 0);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to setup buffer list. did=%x", did);

		return (FC_TRAN_BUSY);
	}
	/* Point of no return */

	/* Initalize iocb */
	if (pkt->pkt_tran_type == FC_PKT_OUTBOUND) {
		/* ELS Response */
		iocb->ULPCONTEXT = (volatile uint16_t) pkt->pkt_cmd_fhdr.rx_id;
		iocb->ULPCOMMAND = CMD_XMIT_ELS_RSP64_CX;
	} else {
		/* ELS Request */
		iocb->un.elsreq64.remoteID = (did == BCAST_DID) ? 0 : did;
		iocb->ULPCONTEXT =
		    (did == BCAST_DID) ? pkt->pkt_cmd_fhdr.seq_id : 0;
		iocb->ULPCOMMAND = CMD_ELS_REQUEST64_CR;

		if (hba->sli_mode == EMLXS_HBA_SLI3_MODE) {
			if (hba->topology != TOPOLOGY_LOOP) {
				cmd = *((uint32_t *)pkt->pkt_cmd);
				cmd &= ELS_CMD_MASK;

				if ((cmd == ELS_CMD_FLOGI) ||
				    (cmd == ELS_CMD_FDISC)) {
					iocb->ULPCT = 0x2;
				} else {
					iocb->ULPCT = 0x1;
				}
			}
			iocb->ULPCONTEXT = port->vpi;
		}
	}
	iocb->ULPIOTAG = iotag;
	iocb->ULPRSVDBYTE =
	    ((pkt->pkt_timeout > 0xff) ? 0 : pkt->pkt_timeout);
	iocb->ULPOWNER = OWN_CHIP;

	switch (FC_TRAN_CLASS(pkt->pkt_tran_flags)) {
	case FC_TRAN_CLASS1:
		iocb->ULPCLASS = CLASS1;
		break;
	case FC_TRAN_CLASS2:
		iocb->ULPCLASS = CLASS2;
		break;
	case FC_TRAN_CLASS3:
	default:
		iocb->ULPCLASS = CLASS3;
		break;
	}
	sbp->class = iocb->ULPCLASS;

	return (FC_SUCCESS);

} /* emlxs_sli3_prep_els_iocb() */


static uint32_t
emlxs_sli3_prep_ct_iocb(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	IOCBQ *iocbq;
	IOCB *iocb;
	CHANNEL *cp;
	NODELIST *ndlp;
	uint16_t iotag;
	uint32_t did;

	pkt = PRIV2PKT(sbp);
	did = LE_SWAP24_LO(pkt->pkt_cmd_fhdr.d_id);
	cp = &hba->chan[FC_CT_RING];

	iocbq = &sbp->iocbq;
	iocb = &iocbq->iocb;
	ndlp = (NODELIST *)iocbq->node;

	/* Get the iotag by registering the packet */
	iotag = emlxs_register_pkt(cp, sbp);

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
		(void) emlxs_unregister_pkt(cp, iotag, 0);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Adapter Busy. Unable to setup buffer list. did=%x", did);

		return (FC_TRAN_BUSY);
	}

	/* Point of no return */

	/* Initalize iocbq */
	iocbq->port = (void *) port;
	iocbq->channel = (void *) cp;

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
		iocb->ULPCOMMAND = CMD_XMIT_SEQUENCE64_CX;
		iocb->un.genreq64.w5.hcsw.Dfctl  = pkt->pkt_cmd_fhdr.df_ctl;
		iocb->ULPCONTEXT  = pkt->pkt_cmd_fhdr.rx_id;
	} else {
		/* CT Request */
		iocb->ULPCOMMAND  = CMD_GEN_REQUEST64_CR;
		iocb->un.genreq64.w5.hcsw.Dfctl = 0;
		iocb->ULPCONTEXT  = ndlp->nlp_Rpi;
	}

	iocb->un.genreq64.w5.hcsw.Rctl  = pkt->pkt_cmd_fhdr.r_ctl;
	iocb->un.genreq64.w5.hcsw.Type  = pkt->pkt_cmd_fhdr.type;

	iocb->ULPIOTAG    = iotag;
	iocb->ULPRSVDBYTE =
	    ((pkt->pkt_timeout > 0xff) ? 0 : pkt->pkt_timeout);
	iocb->ULPOWNER    = OWN_CHIP;

	switch (FC_TRAN_CLASS(pkt->pkt_tran_flags)) {
	case FC_TRAN_CLASS1:
		iocb->ULPCLASS = CLASS1;
		break;
	case FC_TRAN_CLASS2:
		iocb->ULPCLASS = CLASS2;
		break;
	case FC_TRAN_CLASS3:
	default:
		iocb->ULPCLASS = CLASS3;
		break;
	}

	return (FC_SUCCESS);

} /* emlxs_sli3_prep_ct_iocb() */


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

	if ((hba->sli_mode < EMLXS_HBA_SLI3_MODE) ||
	    (sgllen > SLI3_MAX_BDE)) {
		rval = emlxs_sli2_fct_bde_setup(port, sbp);
	} else {
		rval = emlxs_sli3_fct_bde_setup(port, sbp);
	}

	return (rval);

} /* emlxs_fct_bde_setup() */
#endif /* SFCT_SUPPORT */

static uint32_t
emlxs_bde_setup(emlxs_port_t *port, emlxs_buf_t *sbp)
{
	uint32_t	rval;
	emlxs_hba_t	*hba = HBA;

	if (hba->sli_mode < EMLXS_HBA_SLI3_MODE) {
		rval = emlxs_sli2_bde_setup(port, sbp);
	} else {
		rval = emlxs_sli3_bde_setup(port, sbp);
	}

	return (rval);

} /* emlxs_bde_setup() */


static void
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

} /* emlxs_sli3_poll_intr() */

#ifdef MSI_SUPPORT
static uint32_t
emlxs_sli3_msi_intr(char *arg1, char *arg2)
{
	emlxs_hba_t *hba = (emlxs_hba_t *)arg1;
#ifdef FMA_SUPPORT
	emlxs_port_t *port = &PPORT;
#endif  /* FMA_SUPPORT */
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
		hc_copy = hba->sli.sli3.hc_copy & ~hba->intr_mask;
		WRITE_CSR_REG(hba, FC_HC_REG(hba), hc_copy);
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
		WRITE_CSR_REG(hba, FC_HC_REG(hba), hba->sli.sli3.hc_copy);
#ifdef FMA_SUPPORT
		/* Access handle validation */
		EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli3.csr_acc_handle);
#endif  /* FMA_SUPPORT */
		mutex_exit(&EMLXS_PORT_LOCK);
	}

	mutex_exit(&EMLXS_INTR_LOCK(msgid));

	return (DDI_INTR_CLAIMED);

} /* emlxs_sli3_msi_intr() */
#endif /* MSI_SUPPORT */


static int
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

} /* emlxs_sli3_intx_intr() */


/* EMLXS_PORT_LOCK must be held when call this routine */
static uint32_t
emlxs_get_attention(emlxs_hba_t *hba, int32_t msgid)
{
#ifdef FMA_SUPPORT
	emlxs_port_t *port = &PPORT;
#endif  /* FMA_SUPPORT */
	uint32_t ha_copy = 0;
	uint32_t ha_copy2;
	uint32_t mask = hba->sli.sli3.hc_copy;

#ifdef MSI_SUPPORT

read_ha_register:

	/* Check for default MSI interrupt */
	if (msgid == 0) {
		/* Read host attention register to determine interrupt source */
		ha_copy2 = READ_CSR_REG(hba, FC_HA_REG(hba));

		/* Filter out MSI non-default attention bits */
		ha_copy2 &= ~(hba->intr_cond);
	}

	/* Check for polled or fixed type interrupt */
	else if (msgid == -1) {
		/* Read host attention register to determine interrupt source */
		ha_copy2 = READ_CSR_REG(hba, FC_HA_REG(hba));
	}

	/* Otherwise, assume a mapped MSI interrupt */
	else {
		/* Convert MSI msgid to mapped attention bits */
		ha_copy2 = hba->intr_map[msgid];
	}

#else /* !MSI_SUPPORT */

	/* Read host attention register to determine interrupt source */
	ha_copy2 = READ_CSR_REG(hba, FC_HA_REG(hba));

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
		WRITE_CSR_REG(hba, FC_HA_REG(hba), ha_copy2);
	}

#ifdef FMA_SUPPORT
	/* Access handle validation */
	EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli3.csr_acc_handle);
#endif  /* FMA_SUPPORT */

	return (ha_copy);

} /* emlxs_get_attention() */


static void
emlxs_proc_attention(emlxs_hba_t *hba, uint32_t ha_copy)
{
#ifdef FMA_SUPPORT
	emlxs_port_t *port = &PPORT;
#endif  /* FMA_SUPPORT */

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
		(void) READ_SBUS_CSR_REG(hba, FC_SHS_REG(hba));
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
		emlxs_sli3_handle_link_event(hba);
	}

	/* event on ring 0 - FCP Ring */
	if (ha_copy & HA_R0ATT) {
		HBASTATS.IntrEvent[0]++;
		emlxs_sli3_handle_ring_event(hba, 0, ha_copy);
	}

	/* event on ring 1 - IP Ring */
	if (ha_copy & HA_R1ATT) {
		HBASTATS.IntrEvent[1]++;
		emlxs_sli3_handle_ring_event(hba, 1, ha_copy);
	}

	/* event on ring 2 - ELS Ring */
	if (ha_copy & HA_R2ATT) {
		HBASTATS.IntrEvent[2]++;
		emlxs_sli3_handle_ring_event(hba, 2, ha_copy);
	}

	/* event on ring 3 - CT Ring */
	if (ha_copy & HA_R3ATT) {
		HBASTATS.IntrEvent[3]++;
		emlxs_sli3_handle_ring_event(hba, 3, ha_copy);
	}

	if (hba->bus_type == SBUS_FC) {
		WRITE_SBUS_CSR_REG(hba, FC_SHS_REG(hba), SBUS_STAT_IP);
	}

	/* Set heartbeat flag to show activity */
	hba->heartbeat_flag = 1;

#ifdef FMA_SUPPORT
	if (hba->bus_type == SBUS_FC) {
		/* Access handle validation */
		EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli3.sbus_csr_handle);
	}
#endif  /* FMA_SUPPORT */

	return;

} /* emlxs_proc_attention() */


/*
 * emlxs_handle_ff_error()
 *
 *    Description: Processes a FireFly error
 *    Runs at Interrupt level
 */
static void
emlxs_handle_ff_error(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	uint32_t status;
	uint32_t status1;
	uint32_t status2;
	int i = 0;

	/* do what needs to be done, get error from STATUS REGISTER */
	status = READ_CSR_REG(hba, FC_HS_REG(hba));

	/* Clear Chip error bit */
	WRITE_CSR_REG(hba, FC_HA_REG(hba), HA_ERATT);

	/* If HS_FFER1 is set, then wait until the HS_FFER1 bit clears */
	if (status & HS_FFER1) {

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_hardware_error_msg,
		    "HS_FFER1 received");
		EMLXS_STATE_CHANGE(hba, FC_ERROR);
		(void) emlxs_offline(hba);
		while ((status & HS_FFER1) && (i < 300)) {
			status =
			    READ_CSR_REG(hba, FC_HS_REG(hba));
			DELAYMS(1000);
			i++;
		}
	}

	if (i == 300) {
		/* 5 minutes is up, shutdown HBA */
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_hardware_error_msg,
		    "HS_FFER1 clear timeout");

		EMLXS_STATE_CHANGE(hba, FC_ERROR);
		emlxs_thread_spawn(hba, emlxs_shutdown_thread, NULL, NULL);

		goto done;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_hardware_error_msg,
	    "HS_FFER1 cleared");

	if (status & HS_OVERTEMP) {
		status1 =
		    READ_SLIM_ADDR(hba,
		    ((volatile uint8_t *)hba->sli.sli3.slim_addr + 0xb0));

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_hardware_error_msg,
		    "Maximum adapter temperature exceeded (%d °C).", status1);

		hba->temperature = status1;
		hba->flag |= FC_OVERTEMP_EVENT;

		EMLXS_STATE_CHANGE(hba, FC_ERROR);
		emlxs_thread_spawn(hba, emlxs_shutdown_thread,
		    NULL, NULL);

	} else {
		status1 =
		    READ_SLIM_ADDR(hba,
		    ((volatile uint8_t *)hba->sli.sli3.slim_addr + 0xa8));
		status2 =
		    READ_SLIM_ADDR(hba,
		    ((volatile uint8_t *)hba->sli.sli3.slim_addr + 0xac));

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_hardware_error_msg,
		    "Host Error Attention: "
		    "status=0x%x status1=0x%x status2=0x%x",
		    status, status1, status2);

		EMLXS_STATE_CHANGE(hba, FC_ERROR);

		if (status & HS_FFER6) {
			emlxs_thread_spawn(hba, emlxs_restart_thread,
			    NULL, NULL);
		} else {
			emlxs_thread_spawn(hba, emlxs_shutdown_thread,
			    NULL, NULL);
		}
	}

done:
#ifdef FMA_SUPPORT
	/* Access handle validation */
	EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli3.slim_acc_handle);
	EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli3.csr_acc_handle);
#endif  /* FMA_SUPPORT */

	return;

} /* emlxs_handle_ff_error() */


/*
 *  emlxs_sli3_handle_link_event()
 *
 *    Description: Process a Link Attention.
 */
static void
emlxs_sli3_handle_link_event(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	MAILBOXQ *mbq;
	int rc;

	HBASTATS.LinkEvent++;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_link_event_msg, "event=%x",
	    HBASTATS.LinkEvent);

	/* Make sure link is declared down */
	emlxs_linkdown(hba);


	/* Get a buffer which will be used for mailbox commands */
	if ((mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX, 1))) {
		/* Get link attention message */
		if (emlxs_mb_read_la(hba, mbq) == 0) {
			rc =  emlxs_sli3_issue_mbox_cmd(hba, mbq,
			    MBX_NOWAIT, 0);
			if ((rc != MBX_BUSY) && (rc != MBX_SUCCESS)) {
				emlxs_mem_put(hba, MEM_MBOX,
				    (void *)mbq);
			}

			mutex_enter(&EMLXS_PORT_LOCK);


			/*
			 * Clear Link Attention in HA REG
			 */
			WRITE_CSR_REG(hba, FC_HA_REG(hba), HA_LATT);

#ifdef FMA_SUPPORT
			/* Access handle validation */
			EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli3.csr_acc_handle);
#endif  /* FMA_SUPPORT */

			mutex_exit(&EMLXS_PORT_LOCK);
		} else {
			emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);
		}
	}

} /* emlxs_sli3_handle_link_event()  */


/*
 *  emlxs_sli3_handle_ring_event()
 *
 *    Description: Process a Ring Attention.
 */
static void
emlxs_sli3_handle_ring_event(emlxs_hba_t *hba, int32_t ring_no,
    uint32_t ha_copy)
{
	emlxs_port_t *port = &PPORT;
	SLIM2 *slim2p = (SLIM2 *)hba->sli.sli3.slim2.virt;
	CHANNEL *cp;
	RING *rp;
	IOCB *entry;
	IOCBQ *iocbq;
	IOCBQ local_iocbq;
	PGP *pgp;
	uint32_t count;
	volatile uint32_t chipatt;
	void *ioa2;
	uint32_t reg;
	uint32_t channel_no;
	off_t offset;
	IOCBQ *rsp_head = NULL;
	IOCBQ *rsp_tail = NULL;
	emlxs_buf_t *sbp = NULL;

	count = 0;
	rp = &hba->sli.sli3.ring[ring_no];
	cp = rp->channelp;
	channel_no = cp->channelno;

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
	EMLXS_MPDATA_SYNC(hba->sli.sli3.slim2.dma_handle, offset, 4,
	    DDI_DMA_SYNC_FORKERNEL);
	rp->fc_port_rspidx = BE_SWAP32(pgp->rspPutInx);

	/* While ring is not empty */
	while (rp->fc_rspidx != rp->fc_port_rspidx) {
		HBASTATS.IocbReceived[channel_no]++;

		/* Get the next response ring iocb */
		entry =
		    (IOCB *)(((char *)rp->fc_rspringaddr +
		    (rp->fc_rspidx * hba->sli.sli3.iocb_rsp_size)));

		/* DMA sync the response ring iocb for the adapter */
		offset = (off_t)((uint64_t)((unsigned long)entry)
		    - (uint64_t)((unsigned long)slim2p));
		EMLXS_MPDATA_SYNC(hba->sli.sli3.slim2.dma_handle, offset,
		    hba->sli.sli3.iocb_rsp_size, DDI_DMA_SYNC_FORKERNEL);

		count++;

		/* Copy word6 and word7 to local iocb for now */
		iocbq = &local_iocbq;

		BE_SWAP32_BCOPY((uint8_t *)entry + (sizeof (uint32_t) * 6),
		    (uint8_t *)iocbq + (sizeof (uint32_t) * 6),
		    (sizeof (uint32_t) * 2));

		/* when LE is not set, entire Command has not been received */
		if (!iocbq->iocb.ULPLE) {
			/* This should never happen */
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ring_error_msg,
			    "ulpLE is not set. "
			    "ring=%d iotag=%x cmd=%x status=%x",
			    channel_no, iocbq->iocb.ULPIOTAG,
			    iocbq->iocb.ULPCOMMAND, iocbq->iocb.ULPSTATUS);

			goto next;
		}

		switch (iocbq->iocb.ULPCOMMAND) {
#ifdef SFCT_SUPPORT
		case CMD_CLOSE_XRI_CX:
		case CMD_CLOSE_XRI_CN:
		case CMD_ABORT_XRI_CX:
			if (!port->tgt_mode) {
				sbp = NULL;
				break;
			}

			sbp =
			    emlxs_unregister_pkt(cp, iocbq->iocb.ULPIOTAG, 0);
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
			    emlxs_unregister_pkt(cp, iocbq->iocb.ULPIOTAG, 0);
			break;

		default:
			sbp = NULL;
		}

		/* If packet is stale, then drop it. */
		if (sbp == STALE_PACKET) {
			cp->hbaCmplCmd_sbp++;
			/* Copy entry to the local iocbq */
			BE_SWAP32_BCOPY((uint8_t *)entry,
			    (uint8_t *)iocbq, hba->sli.sli3.iocb_rsp_size);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_iocb_stale_msg,
			    "channelno=%d iocb=%p cmd=%x status=%x "
			    "error=%x iotag=%x context=%x info=%x",
			    channel_no, iocbq, (uint8_t)iocbq->iocb.ULPCOMMAND,
			    iocbq->iocb.ULPSTATUS,
			    (uint8_t)iocbq->iocb.un.grsp.perr.statLocalError,
			    (uint16_t)iocbq->iocb.ULPIOTAG,
			    (uint16_t)iocbq->iocb.ULPCONTEXT,
			    (uint8_t)iocbq->iocb.ULPRSVDBYTE);

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
				EMLXS_FCT_STATE_CHG(fct_cmd, cmd_sbp,
				    EMLXS_FCT_IOCB_COMPLETE);
				mutex_exit(&cmd_sbp->fct_mtx);
			}
#endif /* SFCT_SUPPORT */
			cp->hbaCmplCmd_sbp++;
			atomic_dec_32(&hba->io_active);

			/* Copy entry to sbp's iocbq */
			iocbq = &sbp->iocbq;
			BE_SWAP32_BCOPY((uint8_t *)entry,
			    (uint8_t *)iocbq, hba->sli.sli3.iocb_rsp_size);

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
			cp->hbaCmplCmd++;
			/* Copy entry to the local iocbq */
			BE_SWAP32_BCOPY((uint8_t *)entry,
			    (uint8_t *)iocbq, hba->sli.sli3.iocb_rsp_size);

			iocbq->next = NULL;
			iocbq->bp = NULL;
			iocbq->port = &PPORT;
			iocbq->channel = cp;
			iocbq->node = NULL;
			iocbq->sbp = NULL;
			iocbq->flag = 0;
		}

		/* process the channel event now */
		emlxs_proc_channel_event(hba, cp, iocbq);

next:
		/* Increment the driver's local response get index */
		if (++rp->fc_rspidx >= rp->fc_numRiocb) {
			rp->fc_rspidx = 0;
		}

	}	/* while (TRUE) */

	if (rsp_head) {
		mutex_enter(&cp->rsp_lock);
		if (cp->rsp_head == NULL) {
			cp->rsp_head = rsp_head;
			cp->rsp_tail = rsp_tail;
		} else {
			cp->rsp_tail->next = rsp_head;
			cp->rsp_tail = rsp_tail;
		}
		mutex_exit(&cp->rsp_lock);

		emlxs_thread_trigger2(&cp->intr_thread, emlxs_proc_channel, cp);
	}

	/* Check if at least one response entry was processed */
	if (count) {
		/* Update response get index for the adapter */
		if (hba->bus_type == SBUS_FC) {
			slim2p->mbx.us.s2.host[channel_no].rspGetInx
			    = BE_SWAP32(rp->fc_rspidx);

			/* DMA sync the index for the adapter */
			offset = (off_t)
			    ((uint64_t)((unsigned long)&(slim2p->mbx.us.s2.
			    host[channel_no].rspGetInx))
			    - (uint64_t)((unsigned long)slim2p));
			EMLXS_MPDATA_SYNC(hba->sli.sli3.slim2.dma_handle,
			    offset, 4, DDI_DMA_SYNC_FORDEV);
		} else {
			ioa2 =
			    (void *)((char *)hba->sli.sli3.slim_addr +
			    hba->sli.sli3.hgp_ring_offset + (((channel_no * 2) +
			    1) * sizeof (uint32_t)));
			WRITE_SLIM_ADDR(hba, (volatile uint32_t *)ioa2,
			    rp->fc_rspidx);
#ifdef FMA_SUPPORT
			/* Access handle validation */
			EMLXS_CHK_ACC_HANDLE(hba,
			    hba->sli.sli3.slim_acc_handle);
#endif  /* FMA_SUPPORT */
		}

		if (reg & HA_R0RE_REQ) {
			/* HBASTATS.chipRingFree++; */

			mutex_enter(&EMLXS_PORT_LOCK);

			/* Tell the adapter we serviced the ring */
			chipatt = ((CA_R0ATT | CA_R0RE_RSP) <<
			    (channel_no * 4));
			WRITE_CSR_REG(hba, FC_CA_REG(hba), chipatt);

#ifdef FMA_SUPPORT
			/* Access handle validation */
			EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli3.csr_acc_handle);
#endif  /* FMA_SUPPORT */

			mutex_exit(&EMLXS_PORT_LOCK);
		}
	}

	if ((reg & HA_R0CE_RSP) || hba->channel_tx_count) {
		/* HBASTATS.hostRingFree++; */

		/* Cmd ring may be available. Try sending more iocbs */
		emlxs_sli3_issue_iocb_cmd(hba, cp, 0);
	}

	/* HBASTATS.ringEvent++; */

	return;

} /* emlxs_sli3_handle_ring_event() */


extern int
emlxs_handle_rcv_seq(emlxs_hba_t *hba, CHANNEL *cp, IOCBQ *iocbq)
{
	emlxs_port_t *port = &PPORT;
	IOCB *iocb;
	RING *rp;
	MATCHMAP *mp = NULL;
	uint64_t bdeAddr;
	uint32_t vpi = 0;
	uint32_t channelno;
	uint32_t size = 0;
	uint32_t *RcvError;
	uint32_t *RcvDropped;
	uint32_t *UbPosted;
	emlxs_msg_t *dropped_msg;
	char error_str[64];
	uint32_t buf_type;
	uint32_t *word;
	uint32_t hbq_id;

	channelno = cp->channelno;
	rp = &hba->sli.sli3.ring[channelno];

	iocb = &iocbq->iocb;
	word = (uint32_t *)iocb;

	switch (channelno) {
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
		    "channel=%d cmd=%x  %s %x %x %x %x",
		    channelno, iocb->ULPCOMMAND,
		    emlxs_state_xlate(iocb->ULPSTATUS), word[4], word[5],
		    word[6], word[7]);
		return (1);
	}

	if (iocb->ULPSTATUS) {
		if ((iocb->ULPSTATUS == IOSTAT_LOCAL_REJECT) &&
		    (iocb->un.grsp.perr.statLocalError ==
		    IOERR_RCV_BUFFER_TIMEOUT)) {
			(void) strcpy(error_str, "Out of posted buffers:");
		} else if ((iocb->ULPSTATUS == IOSTAT_LOCAL_REJECT) &&
		    (iocb->un.grsp.perr.statLocalError ==
		    IOERR_RCV_BUFFER_WAITING)) {
			(void) strcpy(error_str, "Buffer waiting:");
			goto done;
		} else if (iocb->ULPSTATUS == IOSTAT_NEED_BUFF_ENTRY) {
			(void) strcpy(error_str, "Need Buffer Entry:");
			goto done;
		} else {
			(void) strcpy(error_str, "General error:");
		}

		goto failed;
	}

	if (hba->flag & FC_HBQ_ENABLED) {
		HBQ_INIT_t *hbq;
		HBQE_t *hbqE;
		uint32_t hbqe_tag;

		(*UbPosted)--;

		hbqE = (HBQE_t *)iocb;
		hbq_id = hbqE->unt.ext.HBQ_tag;
		hbqe_tag = hbqE->unt.ext.HBQE_tag;

		hbq = &hba->sli.sli3.hbq_table[hbq_id];

		if (hbqe_tag >= hbq->HBQ_numEntries) {
			(void) sprintf(error_str, "Invalid HBQE tag=%x:",
			    hbqe_tag);
			goto dropped;
		}

		mp = hba->sli.sli3.hbq_table[hbq_id].HBQ_PostBufs[hbqe_tag];

		size = iocb->unsli3.ext_rcv.seq_len;
	} else {
		bdeAddr =
		    PADDR(iocb->un.cont64[0].addrHigh,
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

#ifdef FMA_SUPPORT
	if (mp->dma_handle) {
		if (emlxs_fm_check_dma_handle(hba, mp->dma_handle)
		    != DDI_FM_OK) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_invalid_dma_handle_msg,
			    "emlxs_handle_rcv_seq: hdl=%p",
			    mp->dma_handle);
			goto dropped;
		}
	}
#endif  /* FMA_SUPPORT */

	if (!size) {
		(void) strcpy(error_str, "Buffer empty:");
		goto dropped;
	}

	/* To avoid we drop the broadcast packets */
	if (channelno != FC_IP_RING) {
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

	/* Process request */
	switch (channelno) {
#ifdef SFCT_SUPPORT
	case FC_FCT_RING:
		(void) emlxs_fct_handle_unsol_req(port, cp, iocbq, mp, size);
		break;
#endif /* SFCT_SUPPORT */

	case FC_IP_RING:
		(void) emlxs_ip_handle_unsol_req(port, cp, iocbq, mp, size);
		break;

	case FC_ELS_RING:
		/* If this is a target port, then let fct handle this */
		if (port->ini_mode) {
			(void) emlxs_els_handle_unsol_req(port, cp, iocbq, mp,
			    size);
		}
#ifdef SFCT_SUPPORT
		else if (port->tgt_mode) {
			(void) emlxs_fct_handle_unsol_els(port, cp, iocbq, mp,
			    size);
		}
#endif /* SFCT_SUPPORT */
		break;

	case FC_CT_RING:
		(void) emlxs_ct_handle_unsol_req(port, cp, iocbq, mp, size);
		break;
	}

	goto done;

dropped:
	(*RcvDropped)++;

	EMLXS_MSGF(EMLXS_CONTEXT, dropped_msg,
	    "%s: cmd=%x  %s %x %x %x %x",
	    error_str, iocb->ULPCOMMAND, emlxs_state_xlate(iocb->ULPSTATUS),
	    word[4], word[5], word[6], word[7]);

	if (channelno == FC_FCT_RING) {
		uint32_t sid;

		if (hba->sli_mode >= EMLXS_HBA_SLI3_MODE) {
			emlxs_node_t *ndlp;
			ndlp = emlxs_node_find_rpi(port, iocb->ULPIOTAG);
			sid = ndlp->nlp_DID;
		} else {
			sid = iocb->un.ulpWord[4] & 0xFFFFFF;
		}

		emlxs_send_logo(port, sid);
	}

	goto done;

failed:
	(*RcvError)++;

	EMLXS_MSGF(EMLXS_CONTEXT, dropped_msg,
	    "%s: cmd=%x %s  %x %x %x %x  hba:%x %x",
	    error_str, iocb->ULPCOMMAND, emlxs_state_xlate(iocb->ULPSTATUS),
	    word[4], word[5], word[6], word[7], hba->state, hba->flag);

done:

	if (hba->flag & FC_HBQ_ENABLED) {
		emlxs_update_HBQ_index(hba, hbq_id);
	} else {
		if (mp) {
			emlxs_mem_put(hba, buf_type, (void *)mp);
		}
		(void) emlxs_post_buffer(hba, rp, 1);
	}

	return (0);

} /* emlxs_handle_rcv_seq() */


/* EMLXS_CMD_RING_LOCK must be held when calling this function */
static void
emlxs_sli3_issue_iocb(emlxs_hba_t *hba, RING *rp, IOCBQ *iocbq)
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

		atomic_inc_32(&hba->io_active);

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

		rp->channelp->hbaSendCmd_sbp++;
		iocbq->channel = rp->channelp;
	} else {
		rp->channelp->hbaSendCmd++;
	}

	/* get the next available command ring iocb */
	iocb =
	    (IOCB *)(((char *)rp->fc_cmdringaddr +
	    (rp->fc_cmdidx * hba->sli.sli3.iocb_cmd_size)));

	/* Copy the local iocb to the command ring iocb */
	BE_SWAP32_BCOPY((uint8_t *)icmd, (uint8_t *)iocb,
	    hba->sli.sli3.iocb_cmd_size);

	/* DMA sync the command ring iocb for the adapter */
	offset = (off_t)((uint64_t)((unsigned long)iocb)
	    - (uint64_t)((unsigned long)hba->sli.sli3.slim2.virt));
	EMLXS_MPDATA_SYNC(hba->sli.sli3.slim2.dma_handle, offset,
	    hba->sli.sli3.iocb_cmd_size, DDI_DMA_SYNC_FORDEV);

	/*
	 * After this, the sbp / iocb should not be
	 * accessed in the xmit path.
	 */

	/* Free the local iocb if there is no sbp tracking it */
	if (!sbp) {
		emlxs_mem_put(hba, MEM_IOCB, (void *)iocbq);
	}

	/* update local ring index to next available ring index */
	rp->fc_cmdidx =
	    (rp->fc_cmdidx + 1 >= rp->fc_numCiocb) ? 0 : rp->fc_cmdidx + 1;


	return;

} /* emlxs_sli3_issue_iocb() */


static void
emlxs_sli3_hba_kill(emlxs_hba_t *hba)
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

	/* Perform adapter interlock to kill adapter */
	interlock_failed = 0;

	mutex_enter(&EMLXS_PORT_LOCK);
	if (hba->flag & FC_INTERLOCKED) {
		EMLXS_STATE_CHANGE_LOCKED(hba, FC_KILLED);

		mutex_exit(&EMLXS_PORT_LOCK);

		return;
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
		return;
	}

	hba->flag |= FC_INTERLOCKED;
	hba->mbox_queue_flag = 1;

	/* Disable all host interrupts */
	hba->sli.sli3.hc_copy = 0;
	WRITE_CSR_REG(hba, FC_HC_REG(hba), hba->sli.sli3.hc_copy);
	WRITE_CSR_REG(hba, FC_HA_REG(hba), 0xffffffff);

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

	value = 0x55555555;
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
	    - (uint64_t)((unsigned long)hba->sli.sli3.slim2.virt));
	size = (sizeof (uint32_t) * 2);

	BE_SWAP32_BCOPY((uint8_t *)mb2, (uint8_t *)mb2, size);

	EMLXS_MPDATA_SYNC(hba->sli.sli3.slim2.dma_handle, offset, size,
	    DDI_DMA_SYNC_FORDEV);

	/* interrupt board to do it right away */
	WRITE_CSR_REG(hba, FC_CA_REG(hba), CA_MBATT);

	/* First wait for command acceptence */
	j = 0;
	while (j++ < 1000) {
		value = READ_SLIM_ADDR(hba, (((volatile uint32_t *)mb1) + 1));

		if (value == 0xAAAAAAAA) {
			break;
		}

		DELAYUS(50);
	}

	if (value == 0xAAAAAAAA) {
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

	value = 0x55555555;
	word0 = 0;
	swpmb->mbxCommand = MBX_KILL_BOARD;
	swpmb->mbxOwner = OWN_CHIP;

	/* Write KILL BOARD to mailbox */
	WRITE_SLIM_ADDR(hba, (((volatile uint32_t *)mb1) + 1), value);
	WRITE_SLIM_ADDR(hba, ((volatile uint32_t *)mb1), word0);

	/* interrupt board to do it right away */
	WRITE_CSR_REG(hba, FC_CA_REG(hba), CA_MBATT);

	/* First wait for command acceptence */
	j = 0;
	while (j++ < 1000) {
		value = READ_SLIM_ADDR(hba, (((volatile uint32_t *)mb1) + 1));

		if (value == 0xAAAAAAAA) {
			break;
		}

		DELAYUS(50);
	}

	if (value == 0xAAAAAAAA) {
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
		ha_copy = READ_CSR_REG(hba, FC_HA_REG(hba));

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

	EMLXS_STATE_CHANGE_LOCKED(hba, FC_KILLED);

#ifdef FMA_SUPPORT
	/* Access handle validation */
	EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli3.slim_acc_handle);
	EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli3.csr_acc_handle);
#endif  /* FMA_SUPPORT */

	mutex_exit(&EMLXS_PORT_LOCK);

	return;

} /* emlxs_sli3_hba_kill() */


static void
emlxs_sli3_hba_kill4quiesce(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	MAILBOX *swpmb;
	MAILBOX *mb2;
	MAILBOX *mb1;
	uint32_t word0;
	off_t offset;
	uint32_t j;
	uint32_t value;
	uint32_t size;

	/* Disable all host interrupts */
	hba->sli.sli3.hc_copy = 0;
	WRITE_CSR_REG(hba, FC_HC_REG(hba), hba->sli.sli3.hc_copy);
	WRITE_CSR_REG(hba, FC_HA_REG(hba), 0xffffffff);

	mb2 = FC_SLIM2_MAILBOX(hba);
	mb1 = FC_SLIM1_MAILBOX(hba);
	swpmb = (MAILBOX *)&word0;

	value = 0x55555555;
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
	    - (uint64_t)((unsigned long)hba->sli.sli3.slim2.virt));
	size = (sizeof (uint32_t) * 2);

	BE_SWAP32_BCOPY((uint8_t *)mb2, (uint8_t *)mb2, size);

	EMLXS_MPDATA_SYNC(hba->sli.sli3.slim2.dma_handle, offset, size,
	    DDI_DMA_SYNC_FORDEV);

	/* interrupt board to do it right away */
	WRITE_CSR_REG(hba, FC_CA_REG(hba), CA_MBATT);

	/* First wait for command acceptence */
	j = 0;
	while (j++ < 1000) {
		value = READ_SLIM_ADDR(hba, (((volatile uint32_t *)mb1) + 1));

		if (value == 0xAAAAAAAA) {
			break;
		}
		DELAYUS(50);
	}
	if (value == 0xAAAAAAAA) {
		/* Now wait for mailbox ownership to clear */
		while (j++ < 10000) {
			word0 =
			    READ_SLIM_ADDR(hba, ((volatile uint32_t *)mb1));
			if (swpmb->mbxOwner == 0) {
				break;
			}
			DELAYUS(50);
		}
		goto done;
	}

done:
	EMLXS_STATE_CHANGE_LOCKED(hba, FC_KILLED);

#ifdef FMA_SUPPORT
	/* Access handle validation */
	EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli3.slim_acc_handle);
	EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli3.csr_acc_handle);
#endif  /* FMA_SUPPORT */
	return;

} /* emlxs_sli3_hba_kill4quiesce */




/*
 * emlxs_handle_mb_event
 *
 * Description: Process a Mailbox Attention.
 * Called from host_interrupt to process MBATT
 *
 *   Returns:
 *
 */
static uint32_t
emlxs_handle_mb_event(emlxs_hba_t *hba)
{
	emlxs_port_t		*port = &PPORT;
	MAILBOX			*mb;
	MAILBOX			*swpmb;
	MAILBOX			*mbox;
	MAILBOXQ		*mbq = NULL;
	volatile uint32_t	word0;
	MATCHMAP		*mbox_bp;
	off_t			offset;
	uint32_t		i;
	int			rc;

	swpmb = (MAILBOX *)&word0;

	mutex_enter(&EMLXS_PORT_LOCK);
	switch (hba->mbox_queue_flag) {
	case 0:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_stray_mbox_intr_msg,
		    "No mailbox active.");

		mutex_exit(&EMLXS_PORT_LOCK);
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
			port = (emlxs_port_t *)mbq->port;
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_detail_msg,
			    "Mailbox event. Completing Polled command.");
			mbq->flag |= MBQ_COMPLETED;
		}
		mutex_exit(&EMLXS_MBOX_LOCK);

		mutex_exit(&EMLXS_PORT_LOCK);
		return (0);

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
			return (0);
		}

		mb = (MAILBOX *)mbq;
		mutex_exit(&EMLXS_PORT_LOCK);
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mbox_completion_error_msg,
		    "Invalid Mailbox flag (%x).");

		mutex_exit(&EMLXS_PORT_LOCK);
		return (0);
	}

	/* Set port context */
	port = (emlxs_port_t *)mbq->port;

	/* Get first word of mailbox */
	if (hba->flag & FC_SLIM2_MODE) {
		mbox = FC_SLIM2_MAILBOX(hba);
		offset = (off_t)((uint64_t)((unsigned long)mbox)
		    - (uint64_t)((unsigned long)hba->sli.sli3.slim2.virt));

		EMLXS_MPDATA_SYNC(hba->sli.sli3.slim2.dma_handle, offset,
		    sizeof (uint32_t), DDI_DMA_SYNC_FORKERNEL);
		word0 = *((volatile uint32_t *)mbox);
		word0 = BE_SWAP32(word0);
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
			EMLXS_MPDATA_SYNC(hba->sli.sli3.slim2.dma_handle,
			    offset, sizeof (uint32_t), DDI_DMA_SYNC_FORKERNEL);
			word0 = *((volatile uint32_t *)mbox);
			word0 = BE_SWAP32(word0);
		} else {
			word0 =
			    READ_SLIM_ADDR(hba, ((volatile uint32_t *)mbox));
		}
	}

	/* Now that we are the owner, DMA Sync entire mailbox if needed */
	if (hba->flag & FC_SLIM2_MODE) {
		EMLXS_MPDATA_SYNC(hba->sli.sli3.slim2.dma_handle, offset,
		    MAILBOX_CMD_BSIZE, DDI_DMA_SYNC_FORKERNEL);

		BE_SWAP32_BCOPY((uint8_t *)mbox, (uint8_t *)mb,
		    MAILBOX_CMD_BSIZE);
	} else {
		READ_SLIM_COPY(hba, (uint32_t *)mb, (uint32_t *)mbox,
		    MAILBOX_CMD_WSIZE);
	}

#ifdef MBOX_EXT_SUPPORT
	if (mbq->extbuf) {
		uint32_t *mbox_ext =
		    (uint32_t *)((uint8_t *)mbox + MBOX_EXTENSION_OFFSET);
		off_t offset_ext   = offset + MBOX_EXTENSION_OFFSET;

		if (hba->flag & FC_SLIM2_MODE) {
			EMLXS_MPDATA_SYNC(hba->sli.sli3.slim2.dma_handle,
			    offset_ext, mbq->extsize,
			    DDI_DMA_SYNC_FORKERNEL);
			BE_SWAP32_BCOPY((uint8_t *)mbox_ext,
			    (uint8_t *)mbq->extbuf, mbq->extsize);
		} else {
			READ_SLIM_COPY(hba, (uint32_t *)mbq->extbuf,
			    mbox_ext, (mbq->extsize / 4));
		}
	}
#endif /* MBOX_EXT_SUPPORT */

#ifdef FMA_SUPPORT
	if (!(hba->flag & FC_SLIM2_MODE)) {
		/* Access handle validation */
		EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli3.slim_acc_handle);
	}
#endif  /* FMA_SUPPORT */

	/* Now sync the memory buffer if one was used */
	if (mbq->bp) {
		mbox_bp = (MATCHMAP *)mbq->bp;
		EMLXS_MPDATA_SYNC(mbox_bp->dma_handle, 0, mbox_bp->size,
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
			return (0);
		}
	}

done:

	/* Clean up the mailbox area */
	emlxs_mb_fini(hba, mb, mb->mbxStatus);

	mbq = (MAILBOXQ *)emlxs_mb_get(hba);
	if (mbq) {
		/* Attempt to send pending mailboxes */
		rc =  emlxs_sli3_issue_mbox_cmd(hba, mbq, MBX_NOWAIT, 0);
		if ((rc != MBX_BUSY) && (rc != MBX_SUCCESS)) {
			emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);
		}
	}
	return (0);

} /* emlxs_handle_mb_event() */


extern void
emlxs_sli3_timer(emlxs_hba_t *hba)
{
	/* Perform SLI3 level timer checks */

	emlxs_sli3_timer_check_mbox(hba);

} /* emlxs_sli3_timer() */


static void
emlxs_sli3_timer_check_mbox(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg = &CFG;
	MAILBOX *mb = NULL;
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

	/* Mailbox timed out, first check for error attention */
	ha_copy = emlxs_check_attention(hba);

	if (ha_copy & HA_ERATT) {
		hba->mbox_timer = 0;
		mutex_exit(&EMLXS_PORT_LOCK);
		emlxs_handle_ff_error(hba);
		return;
	}

	if (hba->mbox_queue_flag) {
		/* Get first word of mailbox */
		if (hba->flag & FC_SLIM2_MODE) {
			mb = FC_SLIM2_MAILBOX(hba);
			offset =
			    (off_t)((uint64_t)((unsigned long)mb) - (uint64_t)
			    ((unsigned long)hba->sli.sli3.slim2.virt));

			EMLXS_MPDATA_SYNC(hba->sli.sli3.slim2.dma_handle,
			    offset, sizeof (uint32_t), DDI_DMA_SYNC_FORKERNEL);
			word0 = *((volatile uint32_t *)mb);
			word0 = BE_SWAP32(word0);
		} else {
			mb = FC_SLIM1_MAILBOX(hba);
			word0 =
			    READ_SLIM_ADDR(hba, ((volatile uint32_t *)mb));
#ifdef FMA_SUPPORT
			/* Access handle validation */
			EMLXS_CHK_ACC_HANDLE(hba,
			    hba->sli.sli3.slim_acc_handle);
#endif  /* FMA_SUPPORT */
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
			    hba->sli.sli3.hc_copy, ha_copy);

			mutex_exit(&EMLXS_PORT_LOCK);

			(void) emlxs_handle_mb_event(hba);

			return;
		}

		/* The first to service the mbox queue will clear the timer */
		/* We will service the mailbox here */
		hba->mbox_timer = 0;

		mutex_enter(&EMLXS_MBOX_LOCK);
		mb = (MAILBOX *)hba->mbox_mbq;
		mutex_exit(&EMLXS_MBOX_LOCK);
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
	emlxs_thread_spawn(hba, emlxs_shutdown_thread, NULL, NULL);

	return;

} /* emlxs_sli3_timer_check_mbox() */


/*
 * emlxs_mb_config_port  Issue a CONFIG_PORT mailbox command
 */
static uint32_t
emlxs_mb_config_port(emlxs_hba_t *hba, MAILBOXQ *mbq, uint32_t sli_mode,
    uint32_t hbainit)
{
	MAILBOX		*mb = (MAILBOX *)mbq;
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
	mbq->mbox_cmpl = NULL;

	mb->un.varCfgPort.pcbLen = sizeof (PCB);
	mb->un.varCfgPort.hbainit[0] = hbainit;

	pcb = hba->sli.sli3.slim2.phys +
	    (uint64_t)((unsigned long)&(slim->pcb));
	mb->un.varCfgPort.pcbLow = PADDR_LO(pcb);
	mb->un.varCfgPort.pcbHigh = PADDR_HI(pcb);

	/* Set Host pointers in SLIM flag */
	mb->un.varCfgPort.hps = 1;

	/* Initialize hba structure for assumed default SLI2 mode */
	/* If config port succeeds, then we will update it then   */
	hba->sli_mode = sli_mode;
	hba->vpi_max = 0;
	hba->flag &= ~FC_NPIV_ENABLED;

	if (sli_mode == EMLXS_HBA_SLI3_MODE) {
		mb->un.varCfgPort.sli_mode = EMLXS_HBA_SLI3_MODE;
		mb->un.varCfgPort.cerbm = 1;
		mb->un.varCfgPort.max_hbq = EMLXS_NUM_HBQ;

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
	}

	/*
	 * Now setup pcb
	 */
	((SLIM2 *)hba->sli.sli3.slim2.virt)->pcb.type = TYPE_NATIVE_SLI2;
	((SLIM2 *)hba->sli.sli3.slim2.virt)->pcb.feature = FEATURE_INITIAL_SLI2;
	((SLIM2 *)hba->sli.sli3.slim2.virt)->pcb.maxRing =
	    (hba->sli.sli3.ring_count - 1);
	((SLIM2 *)hba->sli.sli3.slim2.virt)->pcb.mailBoxSize =
	    sizeof (MAILBOX) + MBOX_EXTENSION_SIZE;

	mbx = hba->sli.sli3.slim2.phys +
	    (uint64_t)((unsigned long)&(slim->mbx));
	((SLIM2 *)hba->sli.sli3.slim2.virt)->pcb.mbAddrHigh = PADDR_HI(mbx);
	((SLIM2 *)hba->sli.sli3.slim2.virt)->pcb.mbAddrLow = PADDR_LO(mbx);


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

	if (sli_mode >= EMLXS_HBA_SLI3_MODE) {
		/* ERBM is enabled */
		hba->sli.sli3.hgp_ring_offset = 0x80;
		hba->sli.sli3.hgp_hbq_offset = 0xC0;

		hba->sli.sli3.iocb_cmd_size = SLI3_IOCB_CMD_SIZE;
		hba->sli.sli3.iocb_rsp_size = SLI3_IOCB_RSP_SIZE;

	} else { /* SLI2 */
		/* ERBM is disabled */
		hba->sli.sli3.hgp_ring_offset = 0xC0;
		hba->sli.sli3.hgp_hbq_offset = 0;

		hba->sli.sli3.iocb_cmd_size = SLI2_IOCB_CMD_SIZE;
		hba->sli.sli3.iocb_rsp_size = SLI2_IOCB_RSP_SIZE;
	}

	/* The Sbus card uses Host Memory. The PCI card uses SLIM POINTER */
	if (hba->bus_type == SBUS_FC) {
		hgp = hba->sli.sli3.slim2.phys +
		    (uint64_t)((unsigned long)&(mbox->us.s2.host));
		((SLIM2 *)hba->sli.sli3.slim2.virt)->pcb.hgpAddrHigh =
		    PADDR_HI(hgp);
		((SLIM2 *)hba->sli.sli3.slim2.virt)->pcb.hgpAddrLow =
		    PADDR_LO(hgp);
	} else {
		((SLIM2 *)hba->sli.sli3.slim2.virt)->pcb.hgpAddrHigh =
		    (uint32_t)ddi_get32(hba->pci_acc_handle,
		    (uint32_t *)(hba->pci_addr + PCI_BAR_1_REGISTER));

		Laddr =
		    ddi_get32(hba->pci_acc_handle,
		    (uint32_t *)(hba->pci_addr + PCI_BAR_0_REGISTER));
		Laddr &= ~0x4;
		((SLIM2 *)hba->sli.sli3.slim2.virt)->pcb.hgpAddrLow =
		    (uint32_t)(Laddr + hba->sli.sli3.hgp_ring_offset);

#ifdef FMA_SUPPORT
		/* Access handle validation */
		EMLXS_CHK_ACC_HANDLE(hba, hba->pci_acc_handle);
#endif  /* FMA_SUPPORT */

	}

	pgp = hba->sli.sli3.slim2.phys +
	    (uint64_t)((unsigned long)&(mbox->us.s2.port));
	((SLIM2 *)hba->sli.sli3.slim2.virt)->pcb.pgpAddrHigh =
	    PADDR_HI(pgp);
	((SLIM2 *)hba->sli.sli3.slim2.virt)->pcb.pgpAddrLow =
	    PADDR_LO(pgp);

	offset = 0;
	for (i = 0; i < 4; i++) {
		rp = &hba->sli.sli3.ring[i];
		rdsc = &((SLIM2 *)hba->sli.sli3.slim2.virt)->pcb.rdsc[i];

		/* Setup command ring */
		rgp = hba->sli.sli3.slim2.phys +
		    (uint64_t)((unsigned long)&(slim->IOCBs[offset]));
		rdsc->cmdAddrHigh = PADDR_HI(rgp);
		rdsc->cmdAddrLow = PADDR_LO(rgp);
		rdsc->cmdEntries = rp->fc_numCiocb;

		rp->fc_cmdringaddr =
		    (void *)&((SLIM2 *)hba->sli.sli3.slim2.virt)->IOCBs[offset];
		offset += rdsc->cmdEntries * hba->sli.sli3.iocb_cmd_size;

		/* Setup response ring */
		rgp = hba->sli.sli3.slim2.phys +
		    (uint64_t)((unsigned long)&(slim->IOCBs[offset]));
		rdsc->rspAddrHigh = PADDR_HI(rgp);
		rdsc->rspAddrLow = PADDR_LO(rgp);
		rdsc->rspEntries = rp->fc_numRiocb;

		rp->fc_rspringaddr =
		    (void *)&((SLIM2 *)hba->sli.sli3.slim2.virt)->IOCBs[offset];
		offset += rdsc->rspEntries * hba->sli.sli3.iocb_rsp_size;
	}

	BE_SWAP32_BCOPY((uint8_t *)
	    (&((SLIM2 *)hba->sli.sli3.slim2.virt)->pcb),
	    (uint8_t *)(&((SLIM2 *)hba->sli.sli3.slim2.virt)->pcb),
	    sizeof (PCB));

	offset = ((uint64_t)((unsigned long)
	    &(((SLIM2 *)hba->sli.sli3.slim2.virt)->pcb)) -
	    (uint64_t)((unsigned long)hba->sli.sli3.slim2.virt));
	EMLXS_MPDATA_SYNC(hba->sli.sli3.slim2.dma_handle, (off_t)offset,
	    sizeof (PCB), DDI_DMA_SYNC_FORDEV);

	return (0);

} /* emlxs_mb_config_port() */


static uint32_t
emlxs_hbq_setup(emlxs_hba_t *hba, uint32_t hbq_id)
{
	emlxs_port_t *port = &PPORT;
	HBQ_INIT_t *hbq;
	MATCHMAP *mp;
	HBQE_t *hbqE;
	MAILBOX *mb;
	MAILBOXQ *mbq;
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
	hbq = &hba->sli.sli3.hbq_table[hbq_id];
	hbq->HBQ_numEntries = count;

	/* Get a Mailbox buffer to setup mailbox commands for CONFIG_HBQ */
	if ((mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX, 1)) == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_msg,
		    "emlxs_hbq_setup: Unable to get mailbox.");
		return (1);
	}
	mb = (MAILBOX *)mbq;

	/* Allocate HBQ Host buffer and Initialize the HBQEs */
	if (emlxs_hbq_alloc(hba, hbq_id)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_msg,
		    "emlxs_hbq_setup: Unable to allocate HBQ.");
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);
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
		    seg, 1)) == 0) {
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
		hbqE->unt.w = BE_SWAP32(hbqE->unt.w);
		hbqE->bde.tus.w = BE_SWAP32(hbqE->bde.tus.w);
		hbqE->bde.addrLow =
		    BE_SWAP32(PADDR_LO(mp->phys));
		hbqE->bde.addrHigh =
		    BE_SWAP32(PADDR_HI(mp->phys));
	}

	/* Issue CONFIG_HBQ */
	emlxs_mb_config_hbq(hba, mbq, hbq_id);
	if (emlxs_sli3_issue_mbox_cmd(hba, mbq, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "emlxs_hbq_setup: Unable to config HBQ. cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);
		emlxs_hbq_free_all(hba, hbq_id);
		return (1);
	}

	/* Setup HBQ Get/Put indexes */
	ioa2 = (void *)((char *)hba->sli.sli3.slim_addr +
	    (hba->sli.sli3.hgp_hbq_offset + (hbq_id * sizeof (uint32_t))));
	WRITE_SLIM_ADDR(hba, (volatile uint32_t *)ioa2, hbq->HBQ_PutIdx);

	hba->sli.sli3.hbq_count++;

	emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);

#ifdef FMA_SUPPORT
	/* Access handle validation */
	if (emlxs_fm_check_acc_handle(hba, hba->sli.sli3.slim_acc_handle)
	    != DDI_FM_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_invalid_access_handle_msg, NULL);
		emlxs_hbq_free_all(hba, hbq_id);
		return (1);
	}
#endif  /* FMA_SUPPORT */

	return (0);

} /* emlxs_hbq_setup() */


extern void
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


	hbq = &hba->sli.sli3.hbq_table[hbq_id];

	if (hbq->HBQ_host_buf.virt != 0) {
		for (j = 0; j < hbq->HBQ_PostBufCnt; j++) {
			emlxs_mem_put(hba, seg,
			    (void *)hbq->HBQ_PostBufs[j]);
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

} /* emlxs_hbq_free_all() */


extern void
emlxs_update_HBQ_index(emlxs_hba_t *hba, uint32_t hbq_id)
{
#ifdef FMA_SUPPORT
	emlxs_port_t *port = &PPORT;
#endif  /* FMA_SUPPORT */
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

	hbq = &hba->sli.sli3.hbq_table[hbq_id];

	hbq->HBQ_PutIdx =
	    (hbq->HBQ_PutIdx + 1 >=
	    hbq->HBQ_numEntries) ? 0 : hbq->HBQ_PutIdx + 1;

	if (hbq->HBQ_PutIdx == hbq->HBQ_GetIdx) {
		HBQ_PortGetIdx =
		    BE_SWAP32(((SLIM2 *)hba->sli.sli3.slim2.virt)->mbx.us.s2.
		    HBQ_PortGetIdx[hbq_id]);

		hbq->HBQ_GetIdx = HBQ_PortGetIdx;

		if (hbq->HBQ_PutIdx == hbq->HBQ_GetIdx) {
			return;
		}
	}

	ioa2 = (void *)((char *)hba->sli.sli3.slim_addr +
	    (hba->sli.sli3.hgp_hbq_offset + (hbq_id * sizeof (uint32_t))));
	status = hbq->HBQ_PutIdx;
	WRITE_SLIM_ADDR(hba, (volatile uint32_t *)ioa2, status);

#ifdef FMA_SUPPORT
	/* Access handle validation */
	EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli3.slim_acc_handle);
#endif  /* FMA_SUPPORT */

	return;

} /* emlxs_update_HBQ_index() */


static void
emlxs_sli3_enable_intr(emlxs_hba_t *hba)
{
#ifdef FMA_SUPPORT
	emlxs_port_t *port = &PPORT;
#endif  /* FMA_SUPPORT */
	uint32_t status;

	/* Enable mailbox, error attention interrupts */
	status = (uint32_t)(HC_MBINT_ENA);

	/* Enable ring interrupts */
	if (hba->sli.sli3.ring_count >= 4) {
		status |=
		    (HC_R3INT_ENA | HC_R2INT_ENA | HC_R1INT_ENA |
		    HC_R0INT_ENA);
	} else if (hba->sli.sli3.ring_count == 3) {
		status |= (HC_R2INT_ENA | HC_R1INT_ENA | HC_R0INT_ENA);
	} else if (hba->sli.sli3.ring_count == 2) {
		status |= (HC_R1INT_ENA | HC_R0INT_ENA);
	} else if (hba->sli.sli3.ring_count == 1) {
		status |= (HC_R0INT_ENA);
	}

	hba->sli.sli3.hc_copy = status;
	WRITE_CSR_REG(hba, FC_HC_REG(hba), hba->sli.sli3.hc_copy);

#ifdef FMA_SUPPORT
	/* Access handle validation */
	EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli3.csr_acc_handle);
#endif  /* FMA_SUPPORT */

} /* emlxs_sli3_enable_intr() */


static void
emlxs_enable_latt(emlxs_hba_t *hba)
{
#ifdef FMA_SUPPORT
	emlxs_port_t *port = &PPORT;
#endif  /* FMA_SUPPORT */

	mutex_enter(&EMLXS_PORT_LOCK);
	hba->sli.sli3.hc_copy |= HC_LAINT_ENA;
	WRITE_CSR_REG(hba, FC_HC_REG(hba), hba->sli.sli3.hc_copy);
#ifdef FMA_SUPPORT
	/* Access handle validation */
	EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli3.csr_acc_handle);
#endif  /* FMA_SUPPORT */
	mutex_exit(&EMLXS_PORT_LOCK);

} /* emlxs_enable_latt() */


static void
emlxs_sli3_disable_intr(emlxs_hba_t *hba, uint32_t att)
{
#ifdef FMA_SUPPORT
	emlxs_port_t *port = &PPORT;
#endif  /* FMA_SUPPORT */

	/* Disable all adapter interrupts */
	hba->sli.sli3.hc_copy = att;
	WRITE_CSR_REG(hba, FC_HC_REG(hba), hba->sli.sli3.hc_copy);
#ifdef FMA_SUPPORT
	/* Access handle validation */
	EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli3.csr_acc_handle);
#endif  /* FMA_SUPPORT */

} /* emlxs_sli3_disable_intr() */


static uint32_t
emlxs_check_attention(emlxs_hba_t *hba)
{
#ifdef FMA_SUPPORT
	emlxs_port_t *port = &PPORT;
#endif  /* FMA_SUPPORT */
	uint32_t ha_copy;

	ha_copy = READ_CSR_REG(hba, FC_HA_REG(hba));
#ifdef FMA_SUPPORT
	/* Access handle validation */
	EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli3.csr_acc_handle);
#endif  /* FMA_SUPPORT */
	return (ha_copy);

} /* emlxs_check_attention() */

void
emlxs_sli3_poll_erratt(emlxs_hba_t *hba)
{
	uint32_t ha_copy;

	ha_copy = emlxs_check_attention(hba);

	/* Adapter error */
	if (ha_copy & HA_ERATT) {
		HBASTATS.IntrEvent[6]++;
		emlxs_handle_ff_error(hba);
	}
}
