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
 * Copyright 2008 Emulex.  All rights reserved.
 * Use is subject to License terms.
 */


#define	EMLXS_MODEL_DEF

#include "emlxs.h"

/* Required for EMLXS_CONTEXT in EMLXS_MSGF calls */
EMLXS_MSG_DEF(EMLXS_HBA_C);

static void emlxs_proc_attention(emlxs_hba_t *hba, uint32_t ha_copy);
static uint32_t emlxs_get_attention(emlxs_hba_t *hba, uint32_t msgid);
static void emlxs_handle_link_event(emlxs_hba_t *hba);
static void emlxs_handle_ring_event(emlxs_hba_t *hba, int32_t ring,
    uint32_t ha_copy);
static uint32_t emlxs_decode_biu_rev(uint32_t rev);
static uint32_t emlxs_decode_endec_rev(uint32_t rev);
static void emlxs_parse_prog_types(emlxs_hba_t *hba, char *types);
static int32_t emlxs_hba_init(emlxs_hba_t *hba);
static int32_t emlxs_parse_vpd(emlxs_hba_t *hba, uint8_t *vpd, uint32_t size);
static void emlxs_proc_ring_event(emlxs_hba_t *hba, RING *rp, IOCBQ *iocbq);
static void emlxs_issue_iocb(emlxs_hba_t *hba, RING *rp, IOCBQ *iocbq);
static void emlxs_build_prog_types(emlxs_hba_t *hba, char *prog_types);
static void emlxs_handle_async_event(emlxs_hba_t *hba, RING *rp, IOCBQ *iocbq);
static void emlxs_process_link_speed(emlxs_hba_t *hba);
static int emlxs_handle_rcv_seq(emlxs_hba_t *hba, RING *rp, IOCBQ *iocbq);
static void emlxs_decode_label(char *label, char *buffer);

#ifdef MSI_SUPPORT
static uint32_t emlxs_msi_intr(char *arg1, char *arg2);
uint32_t emlxs_msi_map[EMLXS_MSI_MODES][EMLXS_MSI_MAX_INTRS] =
{
	EMLXS_MSI_MAP1,
	EMLXS_MSI_MAP2,
	EMLXS_MSI_MAP4,
	EMLXS_MSI_MAP8
};
uint32_t emlxs_msi_mask[EMLXS_MSI_MODES] =
{
	EMLXS_MSI0_MASK1,
	EMLXS_MSI0_MASK2,
	EMLXS_MSI0_MASK4,
	EMLXS_MSI0_MASK8
};
#endif	/* MSI_SUPPORT */

static int32_t emlxs_intx_intr(char *arg);


static uint32_t emlxs_disable_traffic_cop = 1;

emlxs_table_t emlxs_ring_table[] =
{
	{FC_FCP_RING, "FCP Ring"},
	{FC_IP_RING, "IP  Ring"},
	{FC_ELS_RING, "ELS Ring"},
	{FC_CT_RING, "CT  Ring"}

};	/* emlxs_ring_table */


emlxs_table_t emlxs_ffstate_table[] =
{
	{0, "NULL"},
	{FC_ERROR, "ERROR"},
	{FC_KILLED, "KILLED"},
	{FC_WARM_START, "WARM_START"},
	{FC_INIT_START, "INIT_START"},
	{FC_INIT_NVPARAMS, "INIT_NVPARAMS"},
	{FC_INIT_REV, "INIT_REV"},
	{FC_INIT_CFGPORT, "INIT_CFGPORT"},
	{FC_INIT_CFGRING, "INIT_CFGRING"},
	{FC_INIT_INITLINK, "INIT_INITLINK"},
	{FC_LINK_DOWN, "LINK_DOWN"},
	{FC_LINK_UP, "LINK_UP"},
	{FC_CLEAR_LA, "CLEAR_LA"},
	{FC_READY, "READY"}

};	/* emlxs_ffstate_table */



/*
 *
 * emlxs_ffinit
 * This routine will start initialization of the FireFly Chipset
 *
 */
extern int
emlxs_ffinit(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg;
	emlxs_vpd_t *vpd;
	MAILBOX *mb;
	RING *rp;
	MATCHMAP *mp;
	MATCHMAP *mp1;
	uint8_t *inptr;
	uint8_t *outptr;
	uint32_t status;
	uint32_t i;
	uint32_t j;
	uint32_t read_rev_reset;
	uint32_t key = 0;
	uint32_t fw_check;
	uint32_t rval;
	uint32_t offset;
	uint8_t vpd_data[DMP_VPD_SIZE];
	uint32_t MaxRbusSize;
	uint32_t MaxIbusSize;
	uint32_t sli_mode;

	cfg = &CFG;
	vpd = &VPD;
	mb = 0;
	MaxRbusSize = 0;
	MaxIbusSize = 0;
	read_rev_reset = 0;
	sli_mode = 2;

#ifdef SLI3_SUPPORT
	/* Initialize sli mode based on configuration parameter */
	switch (cfg[CFG_SLI_MODE].current) {
	case 2:	/* SLI2 mode */
		sli_mode = 2;
		break;

	case 0:	/* Best available */
	case 1:	/* Best available */
	case 3:	/* SLI3 mode */
	default:
		/* SBUS adapters only available in SLI2 */
		if (hba->bus_type == SBUS_FC) {
			sli_mode = 2;
		} else {
			sli_mode = 3;
		}
		break;
	}
#endif	/* SLI3_SUPPORT */

	/* Set the fw_check flag */
	fw_check = cfg[CFG_FW_CHECK].current;

	hba->mbox_queue_flag = 0;
	hba->hc_copy = 0;
	hba->fc_edtov = FF_DEF_EDTOV;
	hba->fc_ratov = FF_DEF_RATOV;
	hba->fc_altov = FF_DEF_ALTOV;
	hba->fc_arbtov = FF_DEF_ARBTOV;

reset:

	/* Reset and initialize the adapter */
	if (emlxs_hba_init(hba)) {
		return (EIO);
	}
	/*
	 * Allocate some memory for buffers
	 */
	if (emlxs_mem_alloc_buffer(hba) == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to allocate memory buffers.");

		emlxs_ffstate_change(hba, FC_ERROR);

		return (ENOMEM);
	}
	/*
	 * Get a buffer which will be used repeatedly for mailbox commands
	 */
	if ((mb = (MAILBOX *) emlxs_mem_get(hba, MEM_MBOX | MEM_PRI)) == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to allocate mailbox buffer.");

		emlxs_ffstate_change(hba, FC_ERROR);
		(void) emlxs_mem_free_buffer(hba);

		return (ENOMEM);
	}
	/* Check for the LP9802 (This is a special case) */
	/* We need to check for dual channel adapter */
	if (hba->model_info.device_id == PCI_DEVICE_ID_LP9802) {
		/* Try to determine if this is a DC adapter */
		if (emlxs_get_max_sram(hba, &MaxRbusSize, &MaxIbusSize) == 0) {
			if (MaxRbusSize == REDUCED_SRAM_CFG) {
				/* LP9802DC */
				for (i = 1; i < EMLXS_PCI_MODEL_COUNT; i++) {
					if (emlxs_pci_model[i].id == LP9802DC) {
						bcopy(&emlxs_pci_model[i],
						    &hba->model_info,
						    sizeof (emlxs_model_t));
						break;
					}
				}
			} else if (hba->model_info.id != LP9802) {
				/* LP9802 */
				for (i = 1; i < EMLXS_PCI_MODEL_COUNT; i++) {
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

	emlxs_ffstate_change(hba, FC_INIT_REV);
	emlxs_mb_read_rev(hba, mb, 0);
	if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to read rev. Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		emlxs_ffstate_change(hba, FC_ERROR);
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
		(void) emlxs_mem_free_buffer(hba);

		return (EIO);
	}
	if (mb->un.varRdRev.rr == 0) {
		/* Old firmware */
		if (read_rev_reset == 0) {
			/* Clean up */
			(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
			(void) emlxs_mem_free_buffer(hba);

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
				/* Clean up */
				(void) emlxs_mem_put(hba, MEM_MBOX,
				    (uint8_t *)mb);
				(void) emlxs_mem_free_buffer(hba);

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
		bcopy((char *)mb->un.varRdRev.sliFwName1,
		    vpd->sli1FwLabel, 16);
		vpd->sli2FwRev = mb->un.varRdRev.sliFwRev2;
		bcopy((char *)mb->un.varRdRev.sliFwName2,
		    vpd->sli2FwLabel, 16);

		/* Lets try to read the SLI3 version */
		/* Setup and issue mailbox READ REV(v3) command */
		emlxs_ffstate_change(hba, FC_INIT_REV);
		emlxs_mb_read_rev(hba, mb, 1);

		if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
			    "Unable to read rev (v3). Mailbox cmd=%x status=%x",
			    mb->mbxCommand, mb->mbxStatus);

			emlxs_ffstate_change(hba, FC_ERROR);
			(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
			(void) emlxs_mem_free_buffer(hba);

			return (EIO);
		}
		if (mb->un.varRdRev.rf3) {
			/*
			 * vpd->sli2FwRev = mb->un.varRdRev.sliFwRev1;  Not
			 * needed
			 */
			vpd->sli3FwRev = mb->un.varRdRev.sliFwRev2;
			bcopy((char *)mb->un.varRdRev.sliFwName2,
			    vpd->sli3FwLabel, 16);
		}
	}

	/* Check sli mode against available firmware levels */
	if ((sli_mode == 4) && (vpd->sli4FwRev == 0)) {
		if (vpd->sli3FwRev) {
			sli_mode = 3;
		} else if (vpd->sli2FwRev) {
			sli_mode = 2;
		} else {
			sli_mode = 0;
		}
	} else if ((sli_mode == 3) && (vpd->sli3FwRev == 0)) {
		if (vpd->sli4FwRev) {
			sli_mode = 4;
		} else if (vpd->sli2FwRev) {
			sli_mode = 2;
		} else {
			sli_mode = 0;
		}
	} else if ((sli_mode == 2) && (vpd->sli2FwRev == 0)) {
		if (vpd->sli4FwRev) {
			sli_mode = 4;
		} else if (vpd->sli3FwRev) {
			sli_mode = 3;
		} else {
			sli_mode = 0;
		}
	}
	if (sli_mode == 0) {
#ifdef SLI3_SUPPORT
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Firmware not available. sli-mode=%d",
		    cfg[CFG_SLI_MODE].current);
#else
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Firmware not available. sli-mode=2");
#endif	/* SLI3_SUPPORT */

		emlxs_ffstate_change(hba, FC_ERROR);
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
		(void) emlxs_mem_free_buffer(hba);

		return (EIO);
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
	emlxs_decode_label(vpd->opFwLabel, vpd->opFwLabel);
	emlxs_decode_label(vpd->sli1FwLabel, vpd->sli1FwLabel);
	emlxs_decode_label(vpd->sli2FwLabel, vpd->sli2FwLabel);
	emlxs_decode_label(vpd->sli3FwLabel, vpd->sli3FwLabel);
	emlxs_decode_label(vpd->sli4FwLabel, vpd->sli4FwLabel);

	key = emlxs_get_key(hba, mb);

	/* Get adapter VPD information */
	offset = 0;
	bzero(vpd_data, sizeof (vpd_data));
	vpd->port_index = (uint32_t)-1;

	while (offset < DMP_VPD_SIZE) {
		emlxs_mb_dump_vpd(hba, mb, offset);
		if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
			/*
			 * Let it go through even if failed.*
			 */
			/*
			 * Not all adapter's have VPD info and thus will fail
			 * here
			 */
			/* This is not a problem */

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "No VPD found. offset=%x status=%x",
			    offset, mb->mbxStatus);
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
				bsize = (bsize > (sizeof (vpd_data) - offset)) ?
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
					*lp2++ = SWAP_LONG(status);
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
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
				    "No VPD acknowledgment. offset=%x", offset);
				break;
			}
		}

	}

	if (vpd_data[0]) {

		(void) emlxs_parse_vpd(hba, (uint8_t *)vpd_data, offset);

		/*
		 * Some adapter models require the vpd data to identify the
		 * exact model
		 */

		/*
		 * Check if vpd->part_num is now defined and the LP8000
		 * adapter (This is a special case)
		 */
		/* We need to look for LP8000DC */
		if ((hba->model_info.device_id == PCI_DEVICE_ID_LP8000) &&
		    (vpd->part_num[0] != 0)) {
			if (strncmp(vpd->part_num, "LP8000DC", 8) == 0) {
				/* LP8000DC */
				for (i = 1; i < EMLXS_PCI_MODEL_COUNT; i++) {
					if (emlxs_pci_model[i].id == LP8000DC) {
						bcopy(&emlxs_pci_model[i],
						    &hba->model_info,
						    sizeof (emlxs_model_t));
						break;
					}
				}
			} else if (hba->model_info.id != LP8000) {
				/* LP8000 */
				for (i = 1; i < EMLXS_PCI_MODEL_COUNT; i++) {
					if (emlxs_pci_model[i].id == LP8000) {
						bcopy(&emlxs_pci_model[i],
						    &hba->model_info,
						    sizeof (emlxs_model_t));
						break;
					}
				}
			}
		}
		/* PCI_DEVICE_ID_LP8000 */
		/*
		 * Check if vpd->part_num is now defined and the LP9002L
		 * adapter (This is a special case)
		 */
		/*
		 * We need to look for LP9002C, LP9002DC, and the LP9402DC
		 * adapters
		 */
		else if ((hba->model_info.device_id == PCI_DEVICE_ID_LP9002L) &&
		    (vpd->part_num[0] != 0)) {
			if (strncmp(vpd->part_num, "LP9002C", 7) == 0) {
				/* LP9002C */
				for (i = 1; i < EMLXS_PCI_MODEL_COUNT; i++) {
					if (emlxs_pci_model[i].id == LP9002C) {
						bcopy(&emlxs_pci_model[i],
						    &hba->model_info,
						    sizeof (emlxs_model_t));
						break;
					}
				}
			} else if (strncmp(vpd->part_num, "LP9002DC", 8) == 0) {
				/* LP9002DC */
				for (i = 1; i < EMLXS_PCI_MODEL_COUNT; i++) {
					if (emlxs_pci_model[i].id == LP9002DC) {
						bcopy(&emlxs_pci_model[i],
						    &hba->model_info,
						    sizeof (emlxs_model_t));
						break;
					}
				}
			} else if (strncmp(vpd->part_num, "LP9402DC", 8) == 0) {
				/* LP9402DC */
				for (i = 1; i < EMLXS_PCI_MODEL_COUNT; i++) {
					if (emlxs_pci_model[i].id == LP9402DC) {
						bcopy(&emlxs_pci_model[i],
						    &hba->model_info,
						    sizeof (emlxs_model_t));
						break;
					}
				}
			} else if (hba->model_info.id != LP9002L) {
				/* LP9002 */
				for (i = 1; i < EMLXS_PCI_MODEL_COUNT; i++) {
					if (emlxs_pci_model[i].id == LP9002L) {
						bcopy(&emlxs_pci_model[i],
						    &hba->model_info,
						    sizeof (emlxs_model_t));
						break;
					}
				}
			}
		}
		/* PCI_DEVICE_ID_LP9002 */
		/*
		 * We need the vpd->part_num to decern between the LP10000DC
		 * and LP10000ExDC
		 */
		else if ((hba->model_info.device_id == PCI_DEVICE_ID_LP10000) &&
		    (vpd->part_num[0] != 0)) {
			if (strncmp(vpd->part_num, "LP10000DC", 9) == 0) {
				/* LP10000DC */
				for (i = 1; i < EMLXS_PCI_MODEL_COUNT; i++) {
					if (emlxs_pci_model[i].id ==
					    LP10000DC) {
						bcopy(&emlxs_pci_model[i],
						    &hba->model_info,
						    sizeof (emlxs_model_t));
						break;
					}
				}
			} else if (strncmp(vpd->part_num, "LP10000ExDC", 11)
			    == 0) {
				/* LP10000ExDC */
				for (i = 1; i < EMLXS_PCI_MODEL_COUNT; i++) {
					if (emlxs_pci_model[i].id ==
					    LP10000ExDC) {
						bcopy(&emlxs_pci_model[i],
						    &hba->model_info,
						    sizeof (emlxs_model_t));
						break;
					}
				}
			} else if (hba->model_info.id != LP10000) {
				/* LP10000 */
				for (i = 1; i < EMLXS_PCI_MODEL_COUNT; i++) {
					if (emlxs_pci_model[i].id == LP10000) {
						bcopy(&emlxs_pci_model[i],
						    &hba->model_info,
						    sizeof (emlxs_model_t));
						break;
					}
				}
			}
		}	/* PCI_DEVICE_ID_LP10000 */
		/* Replace the default model description with vpd data */
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
	/* Since the adapter model may have changed with the vpd data */
	/* lets double check if adapter is not supported */
	if (hba->model_info.flags & EMLXS_NOT_SUPPORTED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unsupported adapter found.  Id:%d  Device id:0x%x "
		    "SSDID:0x%x  Model:%s", hba->model_info.id,
		    hba->model_info.device_id, hba->model_info.ssdid,
		    hba->model_info.model);

		emlxs_ffstate_change(hba, FC_ERROR);
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
		(void) emlxs_mem_free_buffer(hba);

		return (EIO);
	}
	/* Read the adapter's wakeup parms */
	(void) emlxs_read_wakeup_parms(hba, &hba->wakeup_parms, 1);
	emlxs_decode_version(hba->wakeup_parms.u0.boot_bios_wd[0],
	    vpd->boot_version);

	/* Get fcode version property */
	emlxs_get_fcode_version(hba);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
	    "Firmware: kern=%08x stub=%08x sli1=%08x",
	    vpd->postKernRev, vpd->opFwRev, vpd->sli1FwRev);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
	    "Firmware: sli2=%08x sli3=%08x sli4=%08x fl=%x",
	    vpd->sli2FwRev, vpd->sli3FwRev, vpd->sli4FwRev, vpd->feaLevelHigh);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
	    "BIOS: boot=%s fcode=%s", vpd->boot_version, vpd->fcode_version);

	/*
	 * If firmware checking is enabled and the adapter model indicates a
	 * firmware image,
	 */
	/* then perform firmware version check */
	if (((fw_check == 1) && (hba->model_info.flags & EMLXS_SUN_BRANDED) &&
	    hba->model_info.fwid) ||
	    ((fw_check == 2) && hba->model_info.fwid)) {
		emlxs_image_t *image;

		/* Find firmware image indicated by adapter model */
		image = NULL;
		for (i = 0; i < EMLXS_IMAGE_COUNT; i++) {
			if (emlxs_fw_image[i].id == hba->model_info.fwid) {
				image = &emlxs_fw_image[i];
				break;
			}
		}

		/*
		 * If the image was found, then verify current firmware
		 * versions of adapter
		 */
		if (image) {
			if ((vpd->postKernRev != image->kern) ||
			    (vpd->opFwRev != image->stub) ||
			    (vpd->sli1FwRev != image->sli1) ||
			    (vpd->sli2FwRev != image->sli2) ||
			    (image->sli3 && (vpd->sli3FwRev != image->sli3)) ||
			    (image->sli4 && (vpd->sli4FwRev != image->sli4))) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
				    "Firmware update needed. Updating... "
				    "(id=%d fw=%d)", hba->model_info.id,
				    hba->model_info.fwid);

				if (emlxs_fw_download(hba,
				    (char *)image->buffer, image->size, 0)) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_init_failed_msg,
					    "Firmware update failed.");
				}
				/* Clean up */
				(void) emlxs_mem_put(hba, MEM_MBOX,
				    (uint8_t *)mb);
				(void) emlxs_mem_free_buffer(hba);

				fw_check = 0;

				goto reset;
			}
		} else {
			/* This should not happen */

			/*
			 * This means either the adapter database is not
			 * correct or a firmware image is missing from the
			 * compile
			 */
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
			    "Driver firmware image unavailable. (id=%d fw=%d)",
			    hba->model_info.id, hba->model_info.fwid);
		}

	}
	/* Add our interrupt routine to kernel's interrupt chain & enable it */
	/*
	 * If MSI is enabled this will cause Solaris to program the MSI
	 * address
	 */
	/* and data registers in PCI config space */
	if (EMLXS_INTR_ADD(hba) != DDI_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to add interrupt(s).");

		emlxs_ffstate_change(hba, FC_ERROR);
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
		(void) emlxs_mem_free_buffer(hba);

		return (EIO);
	}
	/*
	 * Initialize cmd/rsp ring pointers
	 */
	for (i = 0; i < (uint32_t)hba->ring_count; i++) {
		rp = &hba->ring[i];

		rp->hba = hba;
		rp->ringno = (uint8_t)i;

		rp->fc_iocbhd = 0;
		rp->fc_iocbtl = 0;
		rp->fc_cmdidx = 0;
		rp->fc_rspidx = 0;
		/* Used for pkt io */
		rp->fc_iotag = 1;
		/* Used for abort or close XRI iotags */
		rp->fc_abort_iotag = rp->max_iotag;

	}

	emlxs_ffstate_change(hba, FC_INIT_CFGPORT);
	(void) emlxs_mb_config_port(hba, mb, sli_mode, key);
	if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to configure port. Mailbox cmd=%x status=%x "
		    "slimode=%d key=%x", mb->mbxCommand, mb->mbxStatus,
		    sli_mode, key);

#ifdef SLI3_SUPPORT
		/* Try to fall back to SLI2 if possible */
		if (sli_mode >= 3) {
			sli_mode = 2;

			/* Clean up */
			(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
			(void) emlxs_mem_free_buffer(hba);

			fw_check = 0;

			goto reset;
		}
#endif	/* SLI3_SUPPORT */

		hba->flag &= ~FC_SLIM2_MODE;
		emlxs_ffstate_change(hba, FC_ERROR);
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
		(void) emlxs_mem_free_buffer(hba);

		return (EIO);
	}
#ifdef SLI3_SUPPORT
	/* Check if SLI3 mode was achieved */
	if (mb->un.varCfgPort.rMA && (mb->un.varCfgPort.sli_mode == 3)) {
		hba->sli_mode = 3;

#ifdef NPIV_SUPPORT
		if (mb->un.varCfgPort.vpi_max > 1) {
			hba->flag |= FC_NPIV_ENABLED;

			if (hba->model_info.chip >= EMLXS_SATURN_CHIP) {
				hba->vpi_max = min(mb->un.varCfgPort.vpi_max,
				    MAX_VPORTS - 1);
			} else {
				hba->vpi_max = min(mb->un.varCfgPort.vpi_max,
				    MAX_VPORTS_LIMITED - 1);
			}
		}
#endif	/* NPIV_SUPPORT */

		if (mb->un.varCfgPort.gerbm && mb->un.varCfgPort.max_hbq) {
			hba->flag |= FC_HBQ_ENABLED;
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "SLI3 mode: flag=%x vpi_max=%d", hba->flag, hba->vpi_max);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "SLI2 mode: flag=%x", hba->flag);
	}
#endif	/* SLI3_SUPPORT */

	/* Get and save the current firmware version (based on sli_mode) */
	emlxs_decode_firmware_rev(hba, vpd);

	emlxs_pcix_mxr_update(hba, 0);

	/*
	 * Setup and issue mailbox RUN BIU DIAG command Setup test buffers
	 */
	mp = 0;
	mp1 = 0;
	if (((mp = (MATCHMAP *) emlxs_mem_get(hba, MEM_BUF | MEM_PRI)) == 0) ||
	    ((mp1 = (MATCHMAP *) emlxs_mem_get(hba, MEM_BUF | MEM_PRI)) == 0)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to allocate diag buffers.");

		emlxs_ffstate_change(hba, FC_ERROR);

		if (mp) {
			(void) emlxs_mem_put(hba, MEM_BUF, (uint8_t *)mp);
		}
		if (mp1) {
			(void) emlxs_mem_put(hba, MEM_BUF, (uint8_t *)mp1);
		}
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
		(void) emlxs_mem_free_buffer(hba);

		return (ENOMEM);
	}
	bcopy((caddr_t)&emlxs_diag_pattern[0], (caddr_t)mp->virt,
	    MEM_ELSBUF_SIZE);
	emlxs_mpdata_sync(mp->dma_handle, 0, MEM_ELSBUF_SIZE,
	    DDI_DMA_SYNC_FORDEV);

	bzero(mp1->virt, MEM_ELSBUF_SIZE);
	emlxs_mpdata_sync(mp1->dma_handle, 0, MEM_ELSBUF_SIZE,
	    DDI_DMA_SYNC_FORDEV);

	(void) emlxs_mb_run_biu_diag(hba, mb, mp->phys, mp1->phys);

	if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to run BIU diag.  Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		emlxs_ffstate_change(hba, FC_ERROR);

		(void) emlxs_mem_put(hba, MEM_BUF, (uint8_t *)mp);
		(void) emlxs_mem_put(hba, MEM_BUF, (uint8_t *)mp1);
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
		(void) emlxs_mem_free_buffer(hba);

		return (EIO);
	}
	emlxs_mpdata_sync(mp1->dma_handle, 0, MEM_ELSBUF_SIZE,
	    DDI_DMA_SYNC_FORKERNEL);

	outptr = mp->virt;
	inptr = mp1->virt;

	for (i = 0; i < MEM_ELSBUF_SIZE; i++) {
		if (*outptr++ != *inptr++) {
			outptr--;
			inptr--;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
			    "BIU diagnostic failed. offset %x value %x "
			    "should be %x.", i, (uint32_t)*inptr,
			    (uint32_t)*outptr);

			emlxs_ffstate_change(hba, FC_ERROR);

			(void) emlxs_mem_put(hba, MEM_BUF, (uint8_t *)mp);
			(void) emlxs_mem_put(hba, MEM_BUF, (uint8_t *)mp1);

			(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
			(void) emlxs_mem_free_buffer(hba);

			return (EIO);
		}
	}

	(void) emlxs_mem_put(hba, MEM_BUF, (uint8_t *)mp);
	(void) emlxs_mem_put(hba, MEM_BUF, (uint8_t *)mp1);

	/*
	 * Setup and issue mailbox CONFIGURE RING command
	 */
	for (i = 0; i < (uint32_t)hba->ring_count; i++) {
		emlxs_ffstate_change(hba, FC_INIT_CFGRING);
		emlxs_mb_config_ring(hba, i, mb);
		if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
			    "Unable to configure ring. Mailbox cmd=%x "
			    "status=%x", mb->mbxCommand, mb->mbxStatus);

			emlxs_ffstate_change(hba, FC_ERROR);
			(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
			(void) emlxs_mem_free_buffer(hba);

			return (EIO);
		}
	}

	/*
	 * Setup link timers
	 */
	emlxs_ffstate_change(hba, FC_INIT_INITLINK);
	emlxs_mb_config_link(hba, mb);
	if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to configure link. Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		emlxs_ffstate_change(hba, FC_ERROR);
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
		emlxs_ffcleanup(hba);
		(void) emlxs_mem_free_buffer(hba);

		return (EIO);
	}
#ifdef MAX_RRDY_PATCH
	/* Set MAX_RRDY if one is provided */
	if (cfg[CFG_MAX_RRDY].current) {
		emlxs_mb_set_var(hba, (MAILBOX *) mb, 0x00060412,
		    cfg[CFG_MAX_RRDY].current);

		if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "MAX_RRDY: Unable to set.  status=%x value=%d",
			    mb->mbxStatus, cfg[CFG_MAX_RRDY].current);
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "MAX_RRDY: %d", cfg[CFG_MAX_RRDY].current);
		}
	}
#endif	/* MAX_RRDY_PATCH */

	/*
	 * We need to get login parameters for NID
	 */
	(void) emlxs_mb_read_sparam(hba, mb);
	mp = (MATCHMAP *) (((MAILBOXQ *)mb)->bp);
	if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to read parameters. Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		emlxs_ffstate_change(hba, FC_ERROR);
		(void) emlxs_mem_put(hba, MEM_BUF, (uint8_t *)mp);
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
		emlxs_ffcleanup(hba);
		(void) emlxs_mem_free_buffer(hba);

		return (EIO);
	}
	/* Free the buffer since we were polling */
	(void) emlxs_mem_put(hba, MEM_BUF, (uint8_t *)mp);

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

		/* Set port number and port index to zero */
		/*
		 * The WWN's are unique to each port and therefore port_num
		 * must equal zero
		 */
		/*
		 * This effects the hba_fru_details structure in
		 * fca_bind_port()
		 */
		vpd->port_num[0] = 0;
		vpd->port_index = 0;
	}
	/* Make first attempt to set a port index   */
	/* Check if this is a multifunction adapter */
	if ((vpd->port_index == -1) &&
	    (hba->model_info.chip >= EMLXS_THOR_CHIP)) {
		char *buffer;
		int32_t i;

		/* The port address looks like this: */
		/* 1 - for port index 0   */
		/* 1,1 - for port index 1 */
		/* 1,2 - for port index 2 */
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
	if (vpd->port_index == -1) {
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
		/* Issue CONFIG FARP */
		emlxs_mb_config_farp(hba, mb);
		if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
			/*
			 * Let it go through even if failed.
			 */
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_msg,
			    "Unable to configure FARP. Mailbox cmd=%x "
			    "status=%x", mb->mbxCommand, mb->mbxStatus);
		}
	}
#ifdef MSI_SUPPORT
	/* Configure MSI map if required */
	if (hba->intr_count > 1) {
		emlxs_mb_config_msix(hba, mb, hba->intr_map, hba->intr_count);

		if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) == MBX_SUCCESS) {
			goto msi_configured;
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Unable to config MSIX.  Mailbox cmd=0x%x status=0x%x",
		    mb->mbxCommand, mb->mbxStatus);

		emlxs_mb_config_msi(hba, mb, hba->intr_map, hba->intr_count);

		if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) == MBX_SUCCESS) {
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

			emlxs_ffstate_change(hba, FC_ERROR);
			(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
			emlxs_ffcleanup(hba);
			(void) emlxs_mem_free_buffer(hba);

			return (EIO);
		}
		/*
		 * Reset adapter - The adapter needs to be reset because the
		 * bus cannot handle the MSI change without handshaking with
		 * the adapter again
		 */

		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
		(void) emlxs_mem_free_buffer(hba);
		fw_check = 0;
		goto reset;
	}
msi_configured:

#endif	/* MSI_SUPPORT */

	/*
	 * We always disable the firmware traffic cop feature
	 */
	if (emlxs_disable_traffic_cop) {
		emlxs_disable_tc(hba, (MAILBOX *) mb);
		if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
			    "Unable to disable traffic cop. Mailbox cmd=%x "
			    "status=%x", mb->mbxCommand, mb->mbxStatus);

			(void) EMLXS_INTR_REMOVE(hba);
			emlxs_ffstate_change(hba, FC_ERROR);
			(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
			emlxs_ffcleanup(hba);
			(void) emlxs_mem_free_buffer(hba);

			return (EIO);
		}
	}
	emlxs_mb_read_config(hba, (MAILBOX *) mb);
	if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to read configuration.  Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		(void) EMLXS_INTR_REMOVE(hba);
		emlxs_ffstate_change(hba, FC_ERROR);
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
		emlxs_ffcleanup(hba);
		(void) emlxs_mem_free_buffer(hba);

		return (EIO);
	}
	/* Save the link speed capabilities */
	vpd->link_speed = mb->un.varRdConfig.lmt;
	emlxs_process_link_speed(hba);

	/* Set the io throttle */
	hba->io_throttle = mb->un.varRdConfig.max_xri - IO_THROTTLE_RESERVE;

	/* Set the max node count */
	if (cfg[CFG_NUM_NODES].current > 0) {
		hba->max_nodes =
		    min(cfg[CFG_NUM_NODES].current, mb->un.varRdConfig.max_rpi);
	} else {
		hba->max_nodes = mb->un.varRdConfig.max_rpi;
	}

	emlxs_ffstate_change(hba, FC_LINK_DOWN);

	/* Enable mailbox, error attention interrupts */
	status = (uint32_t)(HC_MBINT_ENA | HC_ERINT_ENA);

	/* Enable ring interrupts */
	if (hba->ring_count >= 4) {
		status |= (HC_R3INT_ENA | HC_R2INT_ENA | HC_R1INT_ENA |
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

#ifdef SLI3_SUPPORT

	if (hba->flag & FC_HBQ_ENABLED) {
		if (hba->tgt_mode) {
			if (emlxs_hbq_setup(hba, EMLXS_FCT_HBQ_ID)) {
				return (ENOMEM);
			}
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "FCT Ring: Posted %d buffers.", MEM_FCTBUF_COUNT);
		}
		if (cfg[CFG_NETWORK_ON].current) {
			if (emlxs_hbq_setup(hba, EMLXS_IP_HBQ_ID)) {
				return (ENOMEM);
			}
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "IP  Ring: Posted %d buffers.", MEM_IPBUF_COUNT);
		}
		if (emlxs_hbq_setup(hba, EMLXS_ELS_HBQ_ID)) {
			return (ENOMEM);
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "ELS Ring: Posted %d buffers.", MEM_ELSBUF_COUNT);

		if (emlxs_hbq_setup(hba, EMLXS_CT_HBQ_ID)) {
			return (ENOMEM);
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "CT  Ring: Posted %d buffers.", MEM_CTBUF_COUNT);
	} else
#endif	/* SLI3_SUPPORT */
	{
		if (hba->tgt_mode) {
			/* Post the FCT unsol buffers */
			rp = &hba->ring[FC_FCT_RING];
			for (j = 0; j < MEM_FCTBUF_COUNT; j += 2) {
				(void) emlxs_post_buffer(hba, rp, 2);
			}
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "FCP Ring: Posted %d buffers.", MEM_FCTBUF_COUNT);
		}
		if (cfg[CFG_NETWORK_ON].current) {
			/* Post the IP unsol buffers */
			rp = &hba->ring[FC_IP_RING];
			for (j = 0; j < MEM_IPBUF_COUNT; j += 2) {
				(void) emlxs_post_buffer(hba, rp, 2);
			}
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "IP  Ring: Posted %d buffers.", MEM_IPBUF_COUNT);
		}
		/* Post the ELS unsol buffers */
		rp = &hba->ring[FC_ELS_RING];
		for (j = 0; j < MEM_ELSBUF_COUNT; j += 2) {
			(void) emlxs_post_buffer(hba, rp, 2);
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "ELS Ring: Posted %d buffers.", MEM_ELSBUF_COUNT);


		/* Post the CT unsol buffers */
		rp = &hba->ring[FC_CT_RING];
		for (j = 0; j < MEM_CTBUF_COUNT; j += 2) {
			(void) emlxs_post_buffer(hba, rp, 2);
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "CT  Ring: Posted %d buffers.", MEM_CTBUF_COUNT);
	}

	/* Register for async events */
	emlxs_mb_async_event(hba, mb);
	if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Async events disabled. Mailbox status=%x", mb->mbxStatus);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Async events enabled.");
		hba->flag |= FC_ASYNC_EVENTS;
	}


	/*
	 * Setup and issue mailbox INITIALIZE LINK command At this point, the
	 * interrupt will be generated by the HW
	 */
	emlxs_mb_init_link(hba, mb, cfg[CFG_TOPOLOGY].current,
	    cfg[CFG_LINK_SPEED].current);

	rval = emlxs_mb_issue_cmd(hba, mb, MBX_NOWAIT, 0);

	if (rval != MBX_SUCCESS && rval != MBX_BUSY) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "Unable to initialize link.  Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		(void) EMLXS_INTR_REMOVE(hba);
		emlxs_ffstate_change(hba, FC_ERROR);
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
		emlxs_ffcleanup(hba);
		(void) emlxs_mem_free_buffer(hba);

		return (EIO);
	}
	(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);

	/*
	 * Enable link attention interrupt
	 */
	mutex_enter(&EMLXS_PORT_LOCK);
	hba->hc_copy |= HC_LAINT_ENA;
	WRITE_CSR_REG(hba, FC_HC_REG(hba, hba->csr_addr), hba->hc_copy);
	mutex_exit(&EMLXS_PORT_LOCK);


	/* Wait for link to come up */
	i = cfg[CFG_LINKUP_DELAY].current;
	while (i && (hba->state < FC_LINK_UP)) {
		/* Check for hardware error */
		if (hba->state == FC_ERROR) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
			    "Adapter error.", mb->mbxCommand, mb->mbxStatus);

			(void) EMLXS_INTR_REMOVE(hba);
			emlxs_ffcleanup(hba);
			(void) emlxs_mem_free_buffer(hba);

			return (EIO);
		}
		DELAYMS(1000);
		i--;
	}

out:

	/*
	 * The leadvile driver will now handle the FLOGI at the driver level
	 */

	return (0);

} /* emlxs_ffinit() */


#ifdef MSI_SUPPORT

/* EMLXS_INTR_INIT */
int32_t
emlxs_msi_init(emlxs_hba_t *hba, uint32_t max)
{
	emlxs_port_t *port = &PPORT;
	int32_t pass = 0;
	int32_t type = 0;
	char s_type[16];
	int32_t types;
	int32_t count;
	int32_t nintrs;
	int32_t mode;
	int32_t actual;
	int32_t new_actual;
	int32_t i;
	int32_t ret;
	ddi_intr_handle_t *htable = NULL;
	ddi_intr_handle_t *new_htable = NULL;
	uint32_t *intr_pri = NULL;
	int32_t *intr_cap = NULL;
	int32_t hilevel_pri;
	emlxs_config_t *cfg = &CFG;
	char buf[64];

	if (!(hba->intr_flags & EMLXS_MSI_ENABLED)) {
		return (emlxs_intx_init(hba, max));
	}
	if (hba->intr_flags & EMLXS_MSI_INITED) {
		return (DDI_SUCCESS);
	}
	/* Set max interrupt count if not specified */
	if (max == 0) {
		if ((cfg[CFG_MSI_MODE].current == 2) ||
		    (cfg[CFG_MSI_MODE].current == 3)) {
			max = EMLXS_MSI_MAX_INTRS;
		} else {
			max = 1;
		}
	}
	/* Filter max interrupt count with adapter model specification */
	if (hba->model_info.intr_limit && (max > hba->model_info.intr_limit)) {
		max = hba->model_info.intr_limit;
	}
	/* Get the available interrupt types from the kernel */
	types = 0;
	ret = ddi_intr_get_supported_types(hba->dip, &types);

	if ((ret != DDI_SUCCESS)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "MSI: ddi_intr_get_supported_types failed. ret=%d", ret);

		/* Default to fixed type */
		types = DDI_INTR_TYPE_FIXED;
	}
	/* Check if fixed interrupts are being forced */
	if (cfg[CFG_MSI_MODE].current == 0) {
		types &= DDI_INTR_TYPE_FIXED;
	}
	/* Check if MSI interrupts are being forced */
	else if ((cfg[CFG_MSI_MODE].current == 1) ||
	    (cfg[CFG_MSI_MODE].current == 2)) {
		types &= (DDI_INTR_TYPE_MSI | DDI_INTR_TYPE_FIXED);
	}
begin:

	/* Set interrupt type and interrupt count */
	type = 0;

	/* Check if MSIX is fully supported */
	if ((types & DDI_INTR_TYPE_MSIX) &&
	    (hba->model_info.flags & EMLXS_MSIX_SUPPORTED)) {
		/* Get the max interrupt count from the adapter */
		nintrs = 0;
		ret =
		    ddi_intr_get_nintrs(hba->dip, DDI_INTR_TYPE_MSIX, &nintrs);

		if (ret == DDI_SUCCESS && nintrs) {
			type = DDI_INTR_TYPE_MSIX;
			(void) strcpy(s_type, "TYPE_MSIX");
			goto initialize;
		}
	}
	/* Check if MSI is fully supported */
	if ((types & DDI_INTR_TYPE_MSI) &&
	    (hba->model_info.flags & EMLXS_MSI_SUPPORTED)) {
		/* Get the max interrupt count from the adapter */
		nintrs = 0;
		ret = ddi_intr_get_nintrs(hba->dip, DDI_INTR_TYPE_MSI, &nintrs);

		if (ret == DDI_SUCCESS && nintrs) {
			type = DDI_INTR_TYPE_MSI;
			(void) strcpy(s_type, "TYPE_MSI");
			goto initialize;
		}
	}
	/* Check if fixed interrupts are fully supported */
	if ((types & DDI_INTR_TYPE_FIXED) &&
	    (hba->model_info.flags & EMLXS_INTX_SUPPORTED)) {
		/* Get the max interrupt count from the adapter */
		nintrs = 0;
		ret =
		    ddi_intr_get_nintrs(hba->dip, DDI_INTR_TYPE_FIXED, &nintrs);

		if (ret == DDI_SUCCESS) {
			type = DDI_INTR_TYPE_FIXED;
			(void) strcpy(s_type, "TYPE_FIXED");
			goto initialize;
		}
	}
	goto init_failed;


initialize:

	pass++;
	mode = 0;
	actual = 0;
	htable = NULL;
	intr_pri = NULL;
	intr_cap = NULL;
	hilevel_pri = 0;

	if (pass == 1) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "MSI: %s: mode=%d types=0x%x nintrs=%d",
		    s_type, cfg[CFG_MSI_MODE].current, types, nintrs);
	}
	/* Validate interrupt count */
	count = min(nintrs, max);

	if (count >= 8) {
		count = 8;
	} else if (count >= 4) {
		count = 4;
	} else if (count >= 2) {
		count = 2;
	} else {
		count = 1;
	}

	/* Allocate an array of interrupt handles */
	htable =
	    kmem_alloc((size_t)(count * sizeof (ddi_intr_handle_t)), KM_SLEEP);

	if (htable == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "MSI: Unable to allocate interrupt handle table");

		goto init_failed;
	}
	/* Allocate 'count' interrupts */
	ret = ddi_intr_alloc(hba->dip, htable, type, EMLXS_MSI_INUMBER, count,
	    &actual, DDI_INTR_ALLOC_NORMAL);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
	    "MSI: %s: count=%d actual=%d", s_type, count, actual);

	if ((ret != DDI_SUCCESS) || (actual == 0)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "MSI: Unable to allocate interrupts. error=%d", ret);

		goto init_failed;
	}
	if (actual != count) {
		/* Validate actual count */
		if (actual >= 8) {
			new_actual = 8;
		} else if (actual >= 4) {
			new_actual = 4;
		} else if (actual >= 2) {
			new_actual = 2;
		} else {
			new_actual = 1;
		}

		if (new_actual < actual) {
			/* Free extra handles */
			for (i = new_actual; i < actual; i++) {
				(void) ddi_intr_free(htable[i]);
			}

			actual = new_actual;
		}
		/* Allocate a new array of interrupt handles */
		new_htable =
		    kmem_alloc((size_t)(actual * sizeof (ddi_intr_handle_t)),
		    KM_SLEEP);

		if (new_htable == NULL) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "MSI: Unable to allocate new interrupt handle "
			    "table");

			goto init_failed;
		}
		/* Copy old array to new array */
		bcopy((uint8_t *)htable, (uint8_t *)new_htable,
		    (actual * sizeof (ddi_intr_handle_t)));

		/* Free the old array */
		kmem_free(htable, (count * sizeof (ddi_intr_handle_t)));

		htable = new_htable;
		count = actual;
	}
	/* Allocate interrupt priority table */
	intr_pri =
	    (uint32_t *)kmem_alloc((size_t)(count * sizeof (uint32_t)),
	    KM_SLEEP);

	if (intr_pri == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "MSI: Unable to allocate interrupt priority table");

		goto init_failed;
	}
	/* Allocate interrupt capability table */
	intr_cap = kmem_alloc((size_t)(count * sizeof (uint32_t)), KM_SLEEP);

	if (intr_cap == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "MSI: Unable to allocate interrupt capability table");

		goto init_failed;
	}
	/* Get minimum hilevel priority */
	hilevel_pri = ddi_intr_get_hilevel_pri();

	/* Fill the priority and capability tables */
	for (i = 0; i < count; ++i) {
		ret = ddi_intr_get_pri(htable[i], &intr_pri[i]);

		if (ret != DDI_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "MSI: ddi_intr_get_pri(%d) failed. "
			    "handle=%p ret=%d", i, &htable[i], ret);

			/* Clean up the interrupts */
			goto init_failed;
		}
		if (intr_pri[i] >= hilevel_pri) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "MSI: Interrupt(%d) level too high. "
			    "pri=0x%x hilevel=0x%x",
			    i, intr_pri[i], hilevel_pri);

			/* Clean up the interrupts */
			goto init_failed;
		}
		ret = ddi_intr_get_cap(htable[i], &intr_cap[i]);

		if (ret != DDI_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "MSI: ddi_intr_get_cap(%d) failed. handle=%p "
			    "ret=%d", i, &htable[i], ret);

			/* Clean up the interrupts */
			goto init_failed;
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "MSI: %s: %d: cap=0x%x pri=0x%x hilevel=0x%x",
		    s_type, i, intr_cap[i], intr_pri[i], hilevel_pri);

	}

	/* Set mode */
	switch (count) {
	case 8:
		mode = EMLXS_MSI_MODE8;
		break;

	case 4:
		mode = EMLXS_MSI_MODE4;
		break;

	case 2:
		mode = EMLXS_MSI_MODE2;
		break;

	default:
		mode = EMLXS_MSI_MODE1;
	}

	/* Save the info */
	hba->intr_htable = htable;
	hba->intr_count = count;
	hba->intr_pri = intr_pri;
	hba->intr_cap = intr_cap;
	hba->intr_type = type;
	hba->intr_arg = (void *)(unsigned long) intr_pri[0];
	hba->intr_mask = emlxs_msi_mask[mode];

	hba->intr_cond = 0;
	for (i = 0; i < EMLXS_MSI_MAX_INTRS; i++) {
		hba->intr_map[i] = emlxs_msi_map[mode][i];
		hba->intr_cond |= emlxs_msi_map[mode][i];

		(void) sprintf(buf, "%s%d_msi%d mutex", DRIVER_NAME,
		    hba->ddiinst, i);
		mutex_init(&hba->intr_lock[i], buf, MUTEX_DRIVER,
		    (void *) hba->intr_arg);
	}

	/* Set flag to indicate support */
	hba->intr_flags |= EMLXS_MSI_INITED;

	/* Create the interrupt threads */
	for (i = 0; i < MAX_RINGS; i++) {
		(void) sprintf(buf, "%s%d_ring%d mutex", DRIVER_NAME,
		    hba->ddiinst, i);
		mutex_init(&hba->ring[i].rsp_lock, buf, MUTEX_DRIVER,
		    (void *) hba->intr_arg);

		emlxs_thread_create(hba, &hba->ring[i].intr_thread);
	}

	return (DDI_SUCCESS);


init_failed:

	if (intr_cap) {
		kmem_free(intr_cap, (count * sizeof (int32_t)));
	}
	if (intr_pri) {
		kmem_free(intr_pri, (count * sizeof (int32_t)));
	}
	if (htable) {
		/* Process the interrupt handlers */
		for (i = 0; i < actual; i++) {
			/* Free the handle[i] */
			(void) ddi_intr_free(htable[i]);
		}

		kmem_free(htable, (count * sizeof (ddi_intr_handle_t)));
	}
	/* Initialize */
	hba->intr_htable = NULL;
	hba->intr_count = 0;
	hba->intr_pri = NULL;
	hba->intr_cap = NULL;
	hba->intr_type = 0;
	hba->intr_arg = NULL;
	hba->intr_cond = 0;
	bzero(hba->intr_map, sizeof (hba->intr_map));
	bzero(hba->intr_lock, sizeof (hba->intr_lock));

	if (type == DDI_INTR_TYPE_MSIX) {
		types &= (DDI_INTR_TYPE_MSI | DDI_INTR_TYPE_FIXED);
		goto begin;
	} else if (type == DDI_INTR_TYPE_MSI) {
		types &= DDI_INTR_TYPE_FIXED;
		goto begin;
	}
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
	    "MSI: Unable to initialize interrupts");

	return (DDI_FAILURE);


} /* emlxs_msi_init() */


/* EMLXS_INTR_UNINIT */
int32_t
emlxs_msi_uninit(emlxs_hba_t *hba)
{
	uint32_t count;
	int32_t i;
	ddi_intr_handle_t *htable;
	uint32_t *intr_pri;
	int32_t *intr_cap;
	int32_t ret;

	if (!(hba->intr_flags & EMLXS_MSI_ENABLED)) {
		return (emlxs_intx_uninit(hba));
	}
	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg, "MSI:
	 * emlxs_msi_uninit called. flags=%x", hba->intr_flags);
	 */

	/* Make sure interrupts have been removed first */
	if ((hba->intr_flags & EMLXS_MSI_ADDED)) {
		ret = emlxs_msi_remove(hba);

		if (ret != DDI_SUCCESS) {
			return (ret);
		}
	}
	/* Check if the interrupts are still initialized */
	if (!(hba->intr_flags & EMLXS_MSI_INITED)) {
		return (DDI_SUCCESS);
	}
	hba->intr_flags &= ~EMLXS_MSI_INITED;

	/* Get handle table parameters */
	htable = hba->intr_htable;
	count = hba->intr_count;
	intr_pri = hba->intr_pri;
	intr_cap = hba->intr_cap;

	/* Clean up */
	hba->intr_count = 0;
	hba->intr_htable = NULL;
	hba->intr_pri = NULL;
	hba->intr_cap = NULL;
	hba->intr_type = 0;
	hba->intr_arg = NULL;
	hba->intr_cond = 0;
	bzero(hba->intr_map, sizeof (hba->intr_map));

	if (intr_cap) {
		kmem_free(intr_cap, (count * sizeof (int32_t)));
	}
	if (intr_pri) {
		kmem_free(intr_pri, (count * sizeof (int32_t)));
	}
	if (htable) {
		/* Process the interrupt handlers */
		for (i = 0; i < count; ++i) {
			/* Free the handle[i] */
			(void) ddi_intr_free(htable[i]);
		}

		kmem_free(htable, (count * sizeof (ddi_intr_handle_t)));
	}
	/* Destroy the intr locks */
	for (i = 0; i < EMLXS_MSI_MAX_INTRS; i++) {
		mutex_destroy(&hba->intr_lock[i]);
	}

	/* Destroy the interrupt threads */
	for (i = 0; i < MAX_RINGS; i++) {
		emlxs_thread_destroy(&hba->ring[i].intr_thread);
		mutex_destroy(&hba->ring[i].rsp_lock);
	}

	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg, "MSI:
	 * emlxs_msi_uninit done. flags=%x", hba->intr_flags);
	 */

	return (DDI_SUCCESS);

} /* emlxs_msi_uninit() */


/* EMLXS_INTR_ADD */
int32_t
emlxs_msi_add(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	int32_t count;
	int32_t i;
	int32_t ret;
	ddi_intr_handle_t *htable = NULL;
	int32_t *intr_cap = NULL;

	if (!(hba->intr_flags & EMLXS_MSI_ENABLED)) {
		return (emlxs_intx_add(hba));
	}
	/* Check if interrupts have already been added */
	if (hba->intr_flags & EMLXS_MSI_ADDED) {
		return (DDI_SUCCESS);
	}
	/* Check if interrupts have been initialized */
	if (!(hba->intr_flags & EMLXS_MSI_INITED)) {
		ret = emlxs_msi_init(hba, 0);

		if (ret != DDI_SUCCESS) {
			return (ret);
		}
	}
	/* Get handle table parameters */
	htable = hba->intr_htable;
	count = hba->intr_count;
	intr_cap = hba->intr_cap;

	/* Add the interrupt handlers */
	for (i = 0; i < count; ++i) {
		/* add handler for handle[i] */
		ret = ddi_intr_add_handler(htable[i], emlxs_msi_intr,
		    (char *)hba, (char *)(unsigned long)i);

		if (ret != DDI_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
			    "MSI: ddi_intr_add_handler(%d) failed. handle=%p "
			    "ret=%d", i, &htable[i], ret);

			/* Process the remaining interrupt handlers */
			while (i) {
				/* Decrement i */
				i--;

				/* Remove the handler */
				ret = ddi_intr_remove_handler(htable[i]);

			}

			return (DDI_FAILURE);
		}
	}

	/* Enable the interrupts */
	if (intr_cap[0] & DDI_INTR_FLAG_BLOCK) {
		ret = ddi_intr_block_enable(htable, count);

		if (ret != DDI_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "MSI: ddi_intr_block_enable(%d) failed. ret=%d",
			    count, ret);

			for (i = 0; i < count; ++i) {
				ret = ddi_intr_enable(htable[i]);

				if (ret != DDI_SUCCESS) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_init_debug_msg,
					    "MSI: ddi_intr_enable(%d) failed. "
					    "ret=%d", i, ret);
				}
			}
		}
	} else {
		for (i = 0; i < count; ++i) {
			ret = ddi_intr_enable(htable[i]);

			if (ret != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
				    "MSI: ddi_intr_enable(%d) failed. ret=%d",
				    i, ret);
			}
		}
	}


	/* Set flag to indicate support */
	hba->intr_flags |= EMLXS_MSI_ADDED;

	return (DDI_SUCCESS);

} /* emlxs_msi_add() */



/* EMLXS_INTR_REMOVE */
int32_t
emlxs_msi_remove(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	uint32_t count;
	int32_t i;
	ddi_intr_handle_t *htable;
	int32_t *intr_cap;
	int32_t ret;

	if (!(hba->intr_flags & EMLXS_MSI_ENABLED)) {
		return (emlxs_intx_remove(hba));
	}
	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg, "MSI:
	 * emlxs_msi_remove called. flags=%x", hba->intr_flags);
	 */

	/* Check if interrupts have already been removed */
	if (!(hba->intr_flags & EMLXS_MSI_ADDED)) {
		return (DDI_SUCCESS);
	}
	hba->intr_flags &= ~EMLXS_MSI_ADDED;

	/* Disable all adapter interrupts */
	hba->hc_copy = 0;
	WRITE_CSR_REG(hba, FC_HC_REG(hba, hba->csr_addr), hba->hc_copy);

	/* Get handle table parameters */
	htable = hba->intr_htable;
	count = hba->intr_count;
	intr_cap = hba->intr_cap;

	/* Disable the interrupts */
	if (intr_cap[0] & DDI_INTR_FLAG_BLOCK) {
		ret = ddi_intr_block_disable(htable, count);

		if (ret != DDI_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "MSI: ddi_intr_block_disable(%d) failed. ret=%d",
			    count, ret);

			for (i = 0; i < count; i++) {
				ret = ddi_intr_disable(htable[i]);

				if (ret != DDI_SUCCESS) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_init_debug_msg,
					    "MSI: ddi_intr_disable(%d) failed. "
					    "ret=%d", i, ret);
				}
			}
		}
	} else {
		for (i = 0; i < count; i++) {
			ret = ddi_intr_disable(htable[i]);

			if (ret != DDI_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
				    "MSI: ddi_intr_disable(%d) failed. ret=%d",
				    i, ret);
			}
		}
	}

	/* Process the interrupt handlers */
	for (i = 0; i < count; i++) {
		/* Remove the handler */
		ret = ddi_intr_remove_handler(htable[i]);


	}

	return (DDI_SUCCESS);

} /* emlxs_msi_remove() */


#endif	/* MSI_SUPPORT */


/* EMLXS_INTR_INIT */
/* ARGSUSED */
int32_t
emlxs_intx_init(emlxs_hba_t *hba, uint32_t max)
{
	emlxs_port_t *port = &PPORT;
	int32_t ret;
	uint32_t i;
	char buf[64];

	/* Check if interrupts have already been initialized */
	if (hba->intr_flags & EMLXS_INTX_INITED) {
		return (DDI_SUCCESS);
	}
	/* Check if adapter is flagged for INTX support */
	if (!(hba->model_info.flags & EMLXS_INTX_SUPPORTED)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "INTX: %s does not support INTX.  flags=0x%x",
		    hba->model_info.model, hba->model_info.flags);

		return (DDI_FAILURE);
	}
	/*
	 * Interrupt number '0' is a high-level interrupt. This driver does
	 * not support having its interrupts mapped above scheduler priority;
	 * i.e., we always expect to be able to call general kernel routines
	 * that may invoke the scheduler.
	 */
	if (ddi_intr_hilevel(hba->dip, EMLXS_INUMBER) != 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "INTX: High-level interrupt not supported.");

		return (DDI_FAILURE);
	}
	/* Get an iblock cookie */
	ret = ddi_get_iblock_cookie(hba->dip, (uint32_t)EMLXS_INUMBER,
	    (ddi_iblock_cookie_t *)&hba->intr_arg);
	if (ret != DDI_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "INTX: ddi_get_iblock_cookie failed. ret=%d", ret);

		return (ret);
	}
	hba->intr_flags |= EMLXS_INTX_INITED;

	/* Create the interrupt threads */
	for (i = 0; i < MAX_RINGS; i++) {
		(void) sprintf(buf, "%s%d_ring%d mutex", DRIVER_NAME,
		    hba->ddiinst, i);
		mutex_init(&hba->ring[i].rsp_lock, buf, MUTEX_DRIVER,
		    (void *)hba->intr_arg);

		emlxs_thread_create(hba, &hba->ring[i].intr_thread);
	}

	return (DDI_SUCCESS);

} /* emlxs_intx_init() */


/* EMLXS_INTR_UNINIT */
int32_t
emlxs_intx_uninit(emlxs_hba_t *hba)
{
	int32_t ret;
	uint32_t i;

	/* Make sure interrupts have been removed */
	if ((hba->intr_flags & EMLXS_INTX_ADDED)) {
		ret = emlxs_intx_remove(hba);

		if (ret != DDI_SUCCESS) {
			return (ret);
		}
	}
	/* Check if the interrupts are still initialized */
	if (!(hba->intr_flags & EMLXS_INTX_INITED)) {
		return (DDI_SUCCESS);
	}
	hba->intr_flags &= ~EMLXS_INTX_INITED;

	hba->intr_arg = NULL;

	/* Create the interrupt threads */
	for (i = 0; i < MAX_RINGS; i++) {
		emlxs_thread_destroy(&hba->ring[i].intr_thread);
		mutex_destroy(&hba->ring[i].rsp_lock);
	}

	return (DDI_SUCCESS);

} /* emlxs_intx_uninit() */


/* This is the legacy method for adding interrupts in Solaris */
/* EMLXS_INTR_ADD */
int32_t
emlxs_intx_add(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	int32_t ret;

	/* Check if interrupts have already been added */
	if (hba->intr_flags & EMLXS_INTX_ADDED) {
		return (DDI_SUCCESS);
	}
	/* Check if interrupts have been initialized */
	if (!(hba->intr_flags & EMLXS_INTX_INITED)) {
		ret = emlxs_intx_init(hba, 0);

		if (ret != DDI_SUCCESS) {
			return (ret);
		}
	}
	/* add intrrupt handler routine */
	ret = ddi_add_intr((void *)hba->dip, (uint_t)EMLXS_INUMBER,
	    (ddi_iblock_cookie_t *)&hba->intr_arg, (ddi_idevice_cookie_t *)0,
	    (uint_t(*) ())emlxs_intx_intr, (caddr_t)hba);

	if (ret != DDI_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_attach_failed_msg,
		    "INTX: ddi_add_intr failed. ret=%d", ret);

		return (ret);
	}
	hba->intr_flags |= EMLXS_INTX_ADDED;

	return (DDI_SUCCESS);

} /* emlxs_intx_add() */


/* EMLXS_INTR_REMOVE */
int32_t
emlxs_intx_remove(emlxs_hba_t *hba)
{

	/* Check if interrupts have already been removed */
	if (!(hba->intr_flags & EMLXS_INTX_ADDED)) {
		return (DDI_SUCCESS);
	}
	hba->intr_flags &= ~EMLXS_INTX_ADDED;

	/* Diable all adapter interrupts */
	hba->hc_copy = 0;
	WRITE_CSR_REG(hba, FC_HC_REG(hba, hba->csr_addr), hba->hc_copy);

	/* Remove the interrupt */
	(void) ddi_remove_intr((void *)hba->dip, (uint_t)EMLXS_INUMBER,
	    hba->intr_arg);

	return (DDI_SUCCESS);

} /* emlxs_intx_remove() */


extern int
emlxs_hba_init(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	emlxs_port_t *vport;
	emlxs_config_t *cfg;
	int32_t i;

	cfg = &CFG;
	i = 0;

	/* Restart the adapter */
	if (emlxs_hba_reset(hba, 1, 0)) {
		return (1);
	}
	hba->ring_count = MAX_RINGS;	/* number of rings used */

	/* WARNING: There is a max of 6 ring masks allowed */
	/*
	 * RING 0 - FCP
	 */
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

	/*
	 * RING 1 - IP
	 */
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

	/*
	 * RING 2 - ELS
	 */
	hba->ring_masks[FC_ELS_RING] = 1;
	hba->ring_rval[i] = FC_ELS_REQ;	/* ELS request/response */
	hba->ring_rmask[i] = 0xFE;
	hba->ring_tval[i] = FC_ELS_DATA;	/* ELS */
	hba->ring_tmask[i++] = 0xFF;

	hba->ring[FC_ELS_RING].fc_numCiocb = SLIM_IOCB_CMD_R2_ENTRIES;
	hba->ring[FC_ELS_RING].fc_numRiocb = SLIM_IOCB_RSP_R2_ENTRIES;

	/*
	 * RING 3 - CT
	 */
	hba->ring_masks[FC_CT_RING] = 1;
	hba->ring_rval[i] = FC_UNSOL_CTL;	/* CT request/response */
	hba->ring_rmask[i] = 0xFE;
	hba->ring_tval[i] = FC_CT_TYPE;	/* CT */
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

} /* emlxs_hba_init() */


static void
emlxs_process_link_speed(emlxs_hba_t *hba)
{
	emlxs_vpd_t *vpd;
	emlxs_config_t *cfg;
	char *cptr;
	uint32_t hi;

	/*
	 * This routine modifies the link-speed config parameter entry based
	 * on adapter capabilities
	 */
	vpd = &VPD;
	cfg = &hba->config[CFG_LINK_SPEED];

	cptr = cfg->help;
	(void) strcpy(cptr, "Select link speed. [0=Auto");
	cptr += 26;
	hi = 0;

	if (vpd->link_speed & LMT_1GB_CAPABLE) {
		(void) strcpy(cptr, ", 1=1Gb");
		cptr += 7;
		hi = 1;
	}
	if (vpd->link_speed & LMT_2GB_CAPABLE) {
		(void) strcpy(cptr, ", 2=2Gb");
		cptr += 7;
		hi = 2;
	}
	if (vpd->link_speed & LMT_4GB_CAPABLE) {
		(void) strcpy(cptr, ", 4=4Gb");
		cptr += 7;
		hi = 4;
	}
	if (vpd->link_speed & LMT_8GB_CAPABLE) {
		(void) strcpy(cptr, ", 8=8Gb");
		cptr += 7;
		hi = 8;
	}
	if (vpd->link_speed & LMT_10GB_CAPABLE) {
		(void) strcpy(cptr, ", 10=10Gb");
		cptr += 9;
		hi = 10;
	}
	(void) strcpy(cptr, "]");
	cfg->hi = hi;

	/* Now revalidate the current parameter setting */
	cfg->current = emlxs_check_parm(hba, CFG_LINK_SPEED, cfg->current);

	return;

} /* emlxs_process_link_speed() */


/*
 *
 * emlxs_parse_vpd
 * This routine will parse the VPD data
 *
 */
extern int
emlxs_parse_vpd(emlxs_hba_t *hba, uint8_t *vpd_buf, uint32_t size)
{
	emlxs_port_t *port = &PPORT;
	char tag[3];
	uint8_t lenlo, lenhi;
	uint32_t n;
	uint16_t block_size;
	uint32_t block_index = 0;
	uint8_t sub_size;
	uint32_t sub_index;
	int32_t finished = 0;
	int32_t index = 0;
	char buffer[128];
	emlxs_vpd_t *vpd;
	emlxs_config_t *cfg;

	vpd = &VPD;
	cfg = &CFG;

#ifdef MENLO_TEST
	/* Check if VPD is disabled Hornet adapters */
	if ((hba->model_info.device_id == PCI_DEVICE_ID_LP21000_M) &&
	    (cfg[CFG_HORNET_VPD].current == 0)) {
		return (1);
	}
#endif	/* MENLO_TEST */


	while (!finished && (block_index < size)) {
		/*
		 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg, "block_index =
		 * %x", block_index);
		 */

		switch (vpd_buf[block_index]) {
		case 0x82:
			index = block_index;
			index += 1;
			lenlo = vpd_buf[index];
			index += 1;
			lenhi = vpd_buf[index];
			index += 1;
			block_index = index;

			block_size = ((((uint16_t)lenhi) << 8) + lenlo);
			block_index += block_size;

			/*
			 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
			 * "block_size = %x", block_size);
			 */

			n = sizeof (buffer);
			bzero(buffer, n);
			bcopy(&vpd_buf[index], buffer,
			    (block_size < (n - 1)) ? block_size : (n - 1));

			(void) strcpy(vpd->id, buffer);
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
			    "ID: %s", vpd->id);

			break;

		case 0x90:
			index = block_index;
			index += 1;
			lenlo = vpd_buf[index];
			index += 1;
			lenhi = vpd_buf[index];
			index += 1;
			block_index = index;
			sub_index = index;

			block_size = ((((uint16_t)lenhi) << 8) + lenlo);
			block_index += block_size;

			/*
			 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
			 * "block_size = %x", block_size);
			 */

			/* Scan for sub-blocks */
			while ((sub_index < block_index) &&
			    (sub_index < size)) {
				/*
				 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
				 * "sub_index = %x", sub_index);
				 */

				index = sub_index;
				tag[0] = vpd_buf[index++];
				tag[1] = vpd_buf[index++];
				tag[2] = 0;
				sub_size = vpd_buf[index++];

				/*
				 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
				 * "sub_size = %x", sub_size);
				 */

				sub_index = (index + sub_size);

				n = sizeof (buffer);
				bzero(buffer, n);
				bcopy(&vpd_buf[index], buffer,
				    (sub_size < (n - 1)) ? sub_size : (n - 1));

				/*
				 * Look for Engineering Change (EC)
				 */
				if (strcmp(tag, "EC") == 0) {
					(void) strcpy(vpd->eng_change, buffer);
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_vpd_msg,
					    "EC: %s", vpd->eng_change);
				}
				/*
				 * Look for Manufacturer (MN)
				 */
				else if (strcmp(tag, "MN") == 0) {
					(void) strcpy(vpd->manufacturer,
					    buffer);
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_vpd_msg,
					    "MN: %s", vpd->manufacturer);
				}
				/*
				 * Look for Serial Number (SN)
				 */
				else if (strcmp(tag, "SN") == 0) {
					(void) strcpy(vpd->serial_num, buffer);
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_vpd_msg,
					    "SN: %s", vpd->serial_num);

					/* Validate the serial number */
					if ((strncmp(buffer, "FFFFFFFFFF",
					    10) == 0) ||
					    (strncmp(buffer, "0000000000",
					    10) == 0)) {
						vpd->serial_num[0] = 0;
					}
				}
				/*
				 * Look for Part Number (PN)
				 */
				else if (strcmp(tag, "PN") == 0) {
					(void) strcpy(vpd->part_num, buffer);
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_vpd_msg,
					    "PN: %s", vpd->part_num);
				}
				/*
				 * Look for (V0)
				 */
				else if (strcmp(tag, "V0") == 0) {
					/* Not used */
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_vpd_msg,
					    "V0: %s", buffer);
				}
				/*
				 * Look for model description (V1)
				 */
				else if (strcmp(tag, "V1") == 0) {
					(void) strcpy(vpd->model_desc, buffer);
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_vpd_msg,
					    "Desc: %s", vpd->model_desc);
				}
				/*
				 * Look for model (V2)
				 */
				else if (strcmp(tag, "V2") == 0) {
					(void) strcpy(vpd->model, buffer);
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_vpd_msg,
					    "Model: %s", vpd->model);
				}
				/*
				 * Look for program type (V3)
				 */

				else if (strcmp(tag, "V3") == 0) {
					(void) strcpy(vpd->prog_types, buffer);
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_vpd_msg,
					    "Prog Types: %s", vpd->prog_types);
				}
				/*
				 * Look for port number (V4)
				 */
				else if (strcmp(tag, "V4") == 0) {
					(void) strcpy(vpd->port_num, buffer);
					vpd->port_index =
					    emlxs_strtol(vpd->port_num, 10);

					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_vpd_msg,
					    "Port: %s",
					    (vpd->port_num[0]) ?
					    vpd->port_num : "not applicable");
				}
				/*
				 * Look for checksum (RV)
				 */
				else if (strcmp(tag, "RV") == 0) {
					/* Not used */
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_vpd_msg,
					    "Checksum: 0x%x", buffer[0]);
				} else {
					/* Generic */
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_vpd_msg,
					    "Tag: %s: %s", tag, buffer);
				}
			}

			break;

		case 0x78:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg, "End Tag.");
			finished = 1;
			break;

		default:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
			    "Unknown block: %x %x %x %x %x %x %x %x",
			    vpd_buf[index], vpd_buf[index + 1],
			    vpd_buf[index + 2], vpd_buf[index + 3],
			    vpd_buf[index + 4], vpd_buf[index + 5],
			    vpd_buf[index + 6], vpd_buf[index + 7]);
			return (0);
		}
	}

	return (1);

} /* emlxs_parse_vpd */



static uint32_t
emlxs_decode_biu_rev(uint32_t rev)
{
	return (rev & 0xf);
} /* End emlxs_decode_biu_rev */


static uint32_t
emlxs_decode_endec_rev(uint32_t rev)
{
	return ((rev >> 28) & 0xf);
} /* End emlxs_decode_endec_rev */


extern void
emlxs_decode_firmware_rev(emlxs_hba_t *hba, emlxs_vpd_t *vpd)
{
	if (vpd->rBit) {
		switch (hba->sli_mode) {
			case 4:
			(void) strcpy(vpd->fw_version, vpd->sli4FwName);
			(void) strcpy(vpd->fw_label, vpd->sli4FwLabel);
			break;
		case 3:
			(void) strcpy(vpd->fw_version, vpd->sli3FwName);
			(void) strcpy(vpd->fw_label, vpd->sli3FwLabel);
			break;
		case 2:
			(void) strcpy(vpd->fw_version, vpd->sli2FwName);
			(void) strcpy(vpd->fw_label, vpd->sli2FwLabel);
			break;
		case 1:
			(void) strcpy(vpd->fw_version, vpd->sli1FwName);
			(void) strcpy(vpd->fw_label, vpd->sli1FwLabel);
			break;
		default:
			(void) strcpy(vpd->fw_version, "unknown");
			(void) strcpy(vpd->fw_label, vpd->fw_version);
		}
	} else {
		emlxs_decode_version(vpd->smFwRev, vpd->fw_version);
		(void) strcpy(vpd->fw_label, vpd->fw_version);
	}

	return;

} /* emlxs_decode_firmware_rev() */



extern void
emlxs_decode_version(uint32_t version, char *buffer)
{
	uint32_t b1, b2, b3, b4;
	char c;

	b1 = (version & 0x0000f000) >> 12;
	b2 = (version & 0x00000f00) >> 8;
	b3 = (version & 0x000000c0) >> 6;
	b4 = (version & 0x00000030) >> 4;

	if (b1 == 0 && b2 == 0) {
		(void) sprintf(buffer, "none");
		return;
	}
	c = 0;
	switch (b4) {
	case 0:
		c = 'n';
		break;
	case 1:
		c = 'a';
		break;
	case 2:
		c = 'b';
		break;
	case 3:
		if ((version & 0x0000000f)) {
			c = 'x';
		}
		break;

	}
	b4 = (version & 0x0000000f);

	if (c == 0) {
		(void) sprintf(buffer, "%d.%d%d", b1, b2, b3);
	} else {
		(void) sprintf(buffer, "%d.%d%d%c%d", b1, b2, b3, c, b4);
	}

	return;

} /* emlxs_decode_version() */


static void
emlxs_decode_label(char *label, char *buffer)
{
	uint32_t i;
	char name[16];
#ifdef EMLXS_LITTLE_ENDIAN
	uint32_t *wptr;
	uint32_t word;
#endif	/* EMLXS_LITTLE_ENDIAN */

	bcopy(label, name, 16);

#ifdef EMLXS_LITTLE_ENDIAN
	wptr = (uint32_t *)name;
	for (i = 0; i < 3; i++) {
		word = *wptr;
		word = SWAP_DATA32(word);
		*wptr++ = word;
	}
#endif	/* EMLXS_LITTLE_ENDIAN */

	for (i = 0; i < 16; i++) {
		if (name[i] == 0x20) {
			name[i] = 0;
		}
	}

	(void) strcpy(buffer, name);

	return;

} /* emlxs_decode_label() */


extern uint32_t
emlxs_strtol(char *str, uint32_t base)
{
	uint32_t value = 0;
	char *ptr;
	uint32_t factor = 1;
	uint32_t digits;

	if (*str == 0) {
		return (0);
	}
	if (base != 10 && base != 16) {
		return (0);
	}
	/* Get max digits of value */
	digits = (base == 10) ? 9 : 8;

	/* Position pointer to end of string */
	ptr = str + strlen(str);

	/* Process string backwards */
	while ((ptr-- > str) && digits) {
		/* check for base 10 numbers */
		if (*ptr >= '0' && *ptr <= '9') {
			value += ((uint32_t)(*ptr - '0')) * factor;
			factor *= base;
			digits--;
		} else if (base == 16) {
			/* Check for base 16 numbers */
			if (*ptr >= 'a' && *ptr <= 'f') {
				value += ((uint32_t)(*ptr - 'a') + 10) * factor;
				factor *= base;
				digits--;
			} else if (*ptr >= 'A' && *ptr <= 'F') {
				value += ((uint32_t)(*ptr - 'A') + 10) * factor;
				factor *= base;
				digits--;
			} else if (factor > 1) {
				break;
			}
		} else if (factor > 1) {
			break;
		}
	}

	return (value);

} /* emlxs_strtol() */


extern uint64_t
emlxs_strtoll(char *str, uint32_t base)
{
	uint64_t value = 0;
	char *ptr;
	uint32_t factor = 1;
	uint32_t digits;

	if (*str == 0) {
		return (0);
	}
	if (base != 10 && base != 16) {
		return (0);
	}
	/* Get max digits of value */
	digits = (base == 10) ? 19 : 16;

	/* Position pointer to end of string */
	ptr = str + strlen(str);

	/* Process string backwards */
	while ((ptr-- > str) && digits) {
		/* check for base 10 numbers */
		if (*ptr >= '0' && *ptr <= '9') {
			value += ((uint32_t)(*ptr - '0')) * factor;
			factor *= base;
			digits--;
		} else if (base == 16) {
			/* Check for base 16 numbers */
			if (*ptr >= 'a' && *ptr <= 'f') {
				value += ((uint32_t)(*ptr - 'a') + 10) * factor;
				factor *= base;
				digits--;
			} else if (*ptr >= 'A' && *ptr <= 'F') {
				value += ((uint32_t)(*ptr - 'A') + 10) * factor;
				factor *= base;
				digits--;
			} else if (factor > 1) {
				break;
			}
		} else if (factor > 1) {
			break;
		}
	}

	return (value);

} /* emlxs_strtoll() */

static void
emlxs_parse_prog_types(emlxs_hba_t *hba, char *prog_types)
{
	emlxs_port_t *port = &PPORT;
	uint32_t i;
	char *ptr;
	emlxs_model_t *model;
	char types_buffer[256];
	char *types;

	bcopy(prog_types, types_buffer, 256);
	types = types_buffer;

	model = &hba->model_info;

	while (*types) {
		if (strncmp(types, "T2:", 3) == 0) {
			bzero(model->pt_2, sizeof (model->pt_2));
			types += 3;

			i = 0;
			while (*types && *types != 'T') {
				/* Null terminate the next value */
				ptr = types;
				while (*ptr && (*ptr != ','))
					ptr++;
				*ptr = 0;

				/* Save the value */
				model->pt_2[i++] =
				    (uint8_t)emlxs_strtol(types, 16);

				/*
				 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
				 * "T2[%d]: 0x%x", i-1, model->pt_2[i-1]);
				 */

				/* Move the str pointer */
				types = ptr + 1;
			}

		} else if (strncmp(types, "T3:", 3) == 0) {
			bzero(model->pt_3, sizeof (model->pt_3));
			types += 3;

			i = 0;
			while (*types && *types != 'T') {
				/* Null terminate the next value */
				ptr = types;
				while (*ptr && (*ptr != ','))
					ptr++;
				*ptr = 0;

				/* Save the value */
				model->pt_3[i++] =
				    (uint8_t)emlxs_strtol(types, 16);

				/*
				 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
				 * "T3[%d]: 0x%x", i-1, model->pt_3[i-1]);
				 */

				/* Move the str pointer */
				types = ptr + 1;
			}
		} else if (strncmp(types, "T6:", 3) == 0) {
			bzero(model->pt_6, sizeof (model->pt_6));
			types += 3;

			i = 0;
			while (*types && *types != 'T') {
				/* Null terminate the next value */
				ptr = types;
				while (*ptr && (*ptr != ','))
					ptr++;
				*ptr = 0;

				/* Save the value */
				model->pt_6[i++] =
				    (uint8_t)emlxs_strtol(types, 16);
				model->pt_6[i] = 0;

				/*
				 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
				 * "T6[%d]: 0x%x", i-1, model->pt_6[i-1]);
				 */

				/* Move the str pointer */
				types = ptr + 1;
			}
		} else if (strncmp(types, "T7:", 3) == 0) {
			bzero(model->pt_7, sizeof (model->pt_7));
			types += 3;

			i = 0;
			while (*types && *types != 'T') {
				/* Null terminate the next value */
				ptr = types;
				while (*ptr && (*ptr != ','))
					ptr++;
				*ptr = 0;

				/* Save the value */
				model->pt_7[i++] =
				    (uint8_t)emlxs_strtol(types, 16);
				model->pt_7[i] = 0;

				/*
				 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
				 * "T7[%d]: 0x%x", i-1, model->pt_7[i-1]);
				 */

				/* Move the str pointer */
				types = ptr + 1;
			}
		} else if (strncmp(types, "TA:", 3) == 0) {
			bzero(model->pt_A, sizeof (model->pt_A));
			types += 3;

			i = 0;
			while (*types && *types != 'T') {
				/* Null terminate the next value */
				ptr = types;
				while (*ptr && (*ptr != ','))
					ptr++;
				*ptr = 0;

				/* Save the value */
				model->pt_A[i++] =
				    (uint8_t)emlxs_strtol(types, 16);

				/*
				 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
				 * "TA[%d]: 0x%x", i-1, model->pt_A[i-1]);
				 */

				/* Move the str pointer */
				types = ptr + 1;
			}
		} else if (strncmp(types, "TB:", 3) == 0) {
			bzero(model->pt_B, sizeof (model->pt_B));
			types += 3;

			i = 0;
			while (*types && *types != 'T') {
				/* Null terminate the next value */
				ptr = types;
				while (*ptr && (*ptr != ','))
					ptr++;
				*ptr = 0;

				/* Save the value */
				model->pt_B[i++] =
				    (uint8_t)emlxs_strtol(types, 16);

				/*
				 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
				 * "TB[%d]: 0x%x", i-1, model->pt_B[i-1]);
				 */

				/* Move the str pointer */
				types = ptr + 1;
			}
		} else if (strncmp(types, "TFF:", 4) == 0) {
			bzero(model->pt_FF, sizeof (model->pt_FF));
			types += 4;

			i = 0;
			while (*types && *types != 'T') {
				/* Null terminate the next value */
				ptr = types;
				while (*ptr && (*ptr != ','))
					ptr++;
				*ptr = 0;

				/* Save the value */
				model->pt_FF[i++] =
				    (uint8_t)emlxs_strtol(types, 16);

				/*
				 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
				 * "TF[%d]: 0x%x", i-1, model->pt_FF[i-1]);
				 */

				/* Move the str pointer */
				types = ptr + 1;
			}
		} else {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_vpd_msg,
			    "Unknown prog type string = %s", types);
			break;
		}
	}

	return;

} /* emlxs_parse_prog_types() */


static void
emlxs_build_prog_types(emlxs_hba_t *hba, char *prog_types)
{
	uint32_t i;
	uint32_t found = 0;
	char buffer[256];

	bzero(prog_types, 256);

	/* Rebuild the prog type string */
	if (hba->model_info.pt_2[0]) {
		(void) strcat(prog_types, "T2:");
		found = 1;

		i = 0;
		while (hba->model_info.pt_2[i] && i < 8) {
			(void) sprintf(buffer, "%X,", hba->model_info.pt_2[i]);
			(void) strcat(prog_types, buffer);
			i++;
		}
	}
	if (hba->model_info.pt_3[0]) {
		(void) strcat(prog_types, "T3:");
		found = 1;

		i = 0;
		while (hba->model_info.pt_3[i] && i < 8) {
			(void) sprintf(buffer, "%X,", hba->model_info.pt_3[i]);
			(void) strcat(prog_types, buffer);
			i++;

		}
	}
	if (hba->model_info.pt_6[0]) {
		(void) strcat(prog_types, "T6:");
		found = 1;

		i = 0;
		while (hba->model_info.pt_6[i] && i < 8) {
			(void) sprintf(buffer, "%X,", hba->model_info.pt_6[i]);
			(void) strcat(prog_types, buffer);
			i++;
		}
	}
	if (hba->model_info.pt_7[0]) {
		(void) strcat(prog_types, "T7:");
		found = 1;

		i = 0;
		while (hba->model_info.pt_7[i] && i < 8) {
			(void) sprintf(buffer, "%X,", hba->model_info.pt_7[i]);
			(void) strcat(prog_types, buffer);
			i++;
		}
	}
	if (hba->model_info.pt_A[0]) {
		(void) strcat(prog_types, "TA:");
		found = 1;

		i = 0;
		while (hba->model_info.pt_A[i] && i < 8) {
			(void) sprintf(buffer, "%X,", hba->model_info.pt_A[i]);
			(void) strcat(prog_types, buffer);
			i++;
		}
	}
	if (hba->model_info.pt_B[0]) {
		(void) strcat(prog_types, "TB:");
		found = 1;

		i = 0;
		while (hba->model_info.pt_B[i] && i < 8) {
			(void) sprintf(buffer, "%X,", hba->model_info.pt_B[i]);
			(void) strcat(prog_types, buffer);
			i++;
		}
	}
	if (hba->model_info.pt_FF[0]) {
		(void) strcat(prog_types, "TFF:");
		found = 1;

		i = 0;
		while (hba->model_info.pt_FF[i] && i < 8) {
			(void) sprintf(buffer, "%X,", hba->model_info.pt_FF[i]);
			(void) strcat(prog_types, buffer);
			i++;
		}
	}
	if (found) {
		/* Terminate at the last comma in string */
		prog_types[(strlen(prog_types) - 1)] = 0;
	}
	return;

} /* emlxs_build_prog_types() */




extern uint32_t
emlxs_init_adapter_info(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg;
	uint32_t pci_id;
	uint32_t cache_line;
	uint32_t channels;
	uint16_t device_id;
	uint16_t ssdid;
	uint32_t i;
	uint32_t found = 0;

	cfg = &CFG;

	if (hba->bus_type == SBUS_FC) {
		if (hba->pci_acc_handle == NULL) {
			bcopy(&emlxs_sbus_model[0], &hba->model_info,
			    sizeof (emlxs_model_t));

			hba->model_info.device_id = 0;

			return (0);
		}
		/* Read the PCI device id */
		pci_id = ddi_get32(hba->pci_acc_handle,
		    (uint32_t *)(hba->pci_addr + PCI_VENDOR_ID_REGISTER));
		device_id = (uint16_t)(pci_id >> 16);

		/* Find matching adapter model */
		for (i = 1; i < EMLXS_SBUS_MODEL_COUNT; i++) {
			if (emlxs_sbus_model[i].device_id == device_id) {
				bcopy(&emlxs_sbus_model[i], &hba->model_info,
				    sizeof (emlxs_model_t));
				found = 1;
				break;
			}
		}

		/* If not found then use the unknown model */
		if (!found) {
			bcopy(&emlxs_sbus_model[0], &hba->model_info,
			    sizeof (emlxs_model_t));

			hba->model_info.device_id = device_id;

			return (0);
		}
	} else {	/* PCI model */
		if (hba->pci_acc_handle == NULL) {
			bcopy(&emlxs_pci_model[0], &hba->model_info,
			    sizeof (emlxs_model_t));

			hba->model_info.device_id = 0;

			return (0);
		}
		/* Read the PCI device id */
		device_id = ddi_get16(hba->pci_acc_handle,
		    (uint16_t *)(hba->pci_addr + PCI_DEVICE_ID_REGISTER));

		/* Read the PCI Subsystem id */
		ssdid = ddi_get16(hba->pci_acc_handle,
		    (uint16_t *)(hba->pci_addr + PCI_SSDID_REGISTER));

		if (ssdid == 0 || ssdid == 0xffff) {
			ssdid = device_id;
		}
		/* Read the Cache Line reg */
		cache_line = ddi_get32(hba->pci_acc_handle,
		    (uint32_t *)(hba->pci_addr + PCI_CACHE_LINE_REGISTER));

		/* Check for the multifunction bit being set */
		if ((cache_line & 0x00ff0000) == 0x00800000) {
			channels = 2;
		} else {
			channels = 1;
		}

#ifdef MENLO_TEST
		/* Convert Zephyr adapters to Hornet adapters */
		if ((device_id == PCI_DEVICE_ID_LPe11000_M4) &&
		    (cfg[CFG_HORNET_ID].current == 0)) {
			device_id = PCI_DEVICE_ID_LP21000_M;
			ssdid = PCI_SSDID_LP21000_M;
		}
#endif	/* MENLO_TEST */

		/* If device ids are unique, then use them for search */
		if (device_id != ssdid) {
			if (channels > 1) {
				/*
				 * Find matching adapter model using
				 * device_id, ssdid and channels
				 */
				for (i = 1; i < EMLXS_PCI_MODEL_COUNT; i++) {
					if ((emlxs_pci_model[i].device_id ==
					    device_id) &&
					    (emlxs_pci_model[i].ssdid ==
					    ssdid) &&
					    (emlxs_pci_model[i].channels ==
					    channels)) {
						bcopy(&emlxs_pci_model[i],
						    &hba->model_info,
						    sizeof (emlxs_model_t));
						found = 1;
						break;
					}
				}
			} else {
				/*
				 * Find matching adapter model using
				 * device_id and ssdid
				 */
				for (i = 1; i < EMLXS_PCI_MODEL_COUNT; i++) {
					if ((emlxs_pci_model[i].device_id ==
					    device_id) &&
					    (emlxs_pci_model[i].ssdid ==
					    ssdid)) {
						bcopy(&emlxs_pci_model[i],
						    &hba->model_info,
						    sizeof (emlxs_model_t));
						found = 1;
						break;
					}
				}
			}
		}
		/* If adapter not found, try again */
		if (!found) {
			/* Find matching adapter model */
			for (i = 1; i < EMLXS_PCI_MODEL_COUNT; i++) {
				if (emlxs_pci_model[i].device_id == device_id &&
				    emlxs_pci_model[i].channels == channels) {
					bcopy(&emlxs_pci_model[i],
					    &hba->model_info,
					    sizeof (emlxs_model_t));
					found = 1;
					break;
				}
			}
		}
		/* If adapter not found, try one last time */
		if (!found) {
			/* Find matching adapter model */
			for (i = 1; i < EMLXS_PCI_MODEL_COUNT; i++) {
				if (emlxs_pci_model[i].device_id == device_id) {
					bcopy(&emlxs_pci_model[i],
					    &hba->model_info,
					    sizeof (emlxs_model_t));
					found = 1;
					break;
				}
			}
		}
		/* If not found, set adapter to unknown */
		if (!found) {
			bcopy(&emlxs_pci_model[0], &hba->model_info,
			    sizeof (emlxs_model_t));

			hba->model_info.device_id = device_id;
			hba->model_info.ssdid = ssdid;

			return (0);
		}
#ifdef MENLO_TEST
		/* Convert Hornet program types to Zephyr program types */
		if ((hba->model_info.device_id == PCI_DEVICE_ID_LP21000_M) &&
		    (cfg[CFG_HORNET_PTYPES].current == 0)) {
			/*
			 * Find matching Zephyr card and copy Zephyr program
			 * types
			 */
			for (i = 1; i < EMLXS_PCI_MODEL_COUNT; i++) {
				if ((emlxs_pci_model[i].device_id ==
				    PCI_DEVICE_ID_LPe11000_M4) &&
				    (emlxs_pci_model[i].ssdid ==
				    PCI_SSDID_LPe11000_M4) &&
				    (emlxs_pci_model[i].channels == channels)) {
					bcopy(emlxs_pci_model[i].pt_2,
					    hba->model_info.pt_2, 8);
					bcopy(emlxs_pci_model[i].pt_3,
					    hba->model_info.pt_3, 8);
					bcopy(emlxs_pci_model[i].pt_6,
					    hba->model_info.pt_6, 8);
					bcopy(emlxs_pci_model[i].pt_7,
					    hba->model_info.pt_7, 8);
					bcopy(emlxs_pci_model[i].pt_A,
					    hba->model_info.pt_A, 8);
					bcopy(emlxs_pci_model[i].pt_B,
					    hba->model_info.pt_B, 8);
					bcopy(emlxs_pci_model[i].pt_E,
					    hba->model_info.pt_E, 8);
					bcopy(emlxs_pci_model[i].pt_FF,
					    hba->model_info.pt_FF, 8);
					break;
				}
			}
		}
#endif	/* MENLO_TEST */

#ifndef SATURN_MSI_SUPPORT
		/*
		 * This will disable MSI support for Saturn adapter's due to
		 * a PCI bus issue
		 */
		if (hba->model_info.chip == EMLXS_SATURN_CHIP) {
			hba->model_info.flags &=
			    ~(EMLXS_MSI_SUPPORTED | EMLXS_MSIX_SUPPORTED);
		}
#endif	/* !SATURN_MSI_SUPPORT */


#ifdef MSI_SUPPORT
		/* Verify MSI support */
		if (hba->model_info.flags & EMLXS_MSI_SUPPORTED) {
			uint32_t offset;
			uint32_t reg;

			/* Scan for MSI capabilities register */
			offset = ddi_get32(hba->pci_acc_handle,
			    (uint32_t *)(hba->pci_addr + PCI_CAP_POINTER));
			offset &= 0xff;

			while (offset) {
				reg = ddi_get32(hba->pci_acc_handle,
				    (uint32_t *)(hba->pci_addr + offset));

				if ((reg & 0xff) == MSI_CAP_ID) {
					break;
				}
				offset = (reg >> 8) & 0xff;
			}

			if (offset) {
				hba->msi_cap_offset = offset + 2;
			} else {
				hba->msi_cap_offset = 0;
				hba->model_info.flags &= ~EMLXS_MSI_SUPPORTED;

				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
				    "MSI: control_reg capability not found!");
			}
		}
		/* Verify MSI-X support */
		if (hba->model_info.flags & EMLXS_MSIX_SUPPORTED) {
			uint32_t offset;
			uint32_t reg;

			/* Scan for MSI capabilities register */
			offset = ddi_get32(hba->pci_acc_handle,
			    (uint32_t *)(hba->pci_addr + PCI_CAP_POINTER));
			offset &= 0xff;

			while (offset) {
				reg = ddi_get32(hba->pci_acc_handle,
				    (uint32_t *)(hba->pci_addr + offset));

				if ((reg & 0xff) == MSIX_CAP_ID) {
					break;
				}
				offset = (reg >> 8) & 0xff;
			}

			if (offset) {
				hba->msix_cap_offset = offset;
			} else {
				hba->msix_cap_offset = 0;
				hba->model_info.flags &= ~EMLXS_MSIX_SUPPORTED;

				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
				    "MSIX: control_reg capability not found!");
			}
		}
#endif	/* MSI_SUPPORT */

	}

	return (1);

} /* emlxs_init_adapter_info()  */


/* EMLXS_PORT_LOCK must be held when call this routine */
static uint32_t
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

#else	/* !MSI_SUPPORT */

	/* Read host attention register to determine interrupt source */
	ha_copy2 = READ_CSR_REG(hba, FC_HA_REG(hba, hba->csr_addr));

#endif	/* MSI_SUPPORT */

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
	ha_copy2 &= ~(HA_ERATT | HA_LATT /* | hba->intr_autoClear */);

	if (ha_copy2) {
		WRITE_CSR_REG(hba, FC_HA_REG(hba, hba->csr_addr), ha_copy2);
	}
	return (ha_copy);

} /* emlxs_get_attention() */


static void
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
		(void) READ_SBUS_CSR_REG(hba, FC_SHS_REG(hba,
		    hba->sbus_csr_addr));
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
		WRITE_SBUS_CSR_REG(hba,
		    FC_SHS_REG(hba, hba->sbus_csr_addr),
		    SBUS_STAT_IP);
	}
	/* Set heartbeat flag to show activity */
	hba->heartbeat_flag = 1;

	return;

} /* emlxs_proc_attention() */


#ifdef MSI_SUPPORT

static uint32_t
emlxs_msi_intr(char *arg1, char *arg2)
{
	emlxs_hba_t *hba = (emlxs_hba_t *)arg1;
	uint16_t msgid;
	uint32_t hc_copy;
	uint32_t ha_copy;
	uint32_t restore = 0;

	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg, "emlxs_msi_intr:
	 * arg1=%p arg2=%p", arg1, arg2);
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
	msgid = (uint16_t)(unsigned long)arg2;

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
		WRITE_CSR_REG(hba, FC_HC_REG(hba, hba->csr_addr), hba->hc_copy);
		mutex_exit(&EMLXS_PORT_LOCK);
	}
	mutex_exit(&EMLXS_INTR_LOCK(msgid));

	return (DDI_INTR_CLAIMED);

} /* emlxs_msi_intr() */

#endif	/* MSI_SUPPORT */

static int
emlxs_intx_intr(char *arg)
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

} /* emlxs_intx_intr() */


/* ARGSUSED */
static void
emlxs_handle_async_event(emlxs_hba_t *hba, RING *rp, IOCBQ *iocbq)
{
	emlxs_port_t *port = &PPORT;
	IOCB *iocb;

	iocb = &iocbq->iocb;

	if (iocb->ulpStatus != 0) {
		return;
	}
	switch (iocb->un.astat.EventCode) {
	case 0x0100:	/* Temp Warning */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_temp_warning_msg,
		    "Adapter is very hot (%d °C). Take corrective action.",
		    iocb->ulpContext);

		emlxs_log_temp_event(port, 0x02, iocb->ulpContext);

		break;


	case 0x0101:	/* Temp Safe */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_temp_msg,
		    "Adapter temperature now safe (%d °C).",
		    iocb->ulpContext);

		emlxs_log_temp_event(port, 0x03, iocb->ulpContext);

		break;
	}

	return;

} /* emlxs_handle_async_event() */


/*
 *  emlxs_handle_ff_error
 *
 *    Description: Processes a FireFly error
 *    Runs at Interrupt level
 *
 */
extern void
emlxs_handle_ff_error(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	uint32_t status;
	uint32_t status1;
	uint32_t status2;

	/* do what needs to be done, get error from STATUS REGISTER */
	status = READ_CSR_REG(hba, FC_HS_REG(hba, hba->csr_addr));

	/* Clear Chip error bit */
	WRITE_CSR_REG(hba, FC_HA_REG(hba, hba->csr_addr), HA_ERATT);

	if (status & HS_OVERTEMP) {
		status1 = READ_SLIM_ADDR(hba,
		    ((volatile uint8_t *) hba->slim_addr + 0xb0));

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_hardware_error_msg,
		    "Maximum adapter temperature exceeded (%d °C).",
		    status1);

		hba->flag |= FC_OVERTEMP_EVENT;
		emlxs_log_temp_event(port, 0x01, status1);
	} else {
		status1 = READ_SLIM_ADDR(hba,
		    ((volatile uint8_t *) hba->slim_addr + 0xa8));
		status2 = READ_SLIM_ADDR(hba,
		    ((volatile uint8_t *) hba->slim_addr + 0xac));

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_hardware_error_msg,
		    "Host Error Attention: status=0x%x status1=0x%x "
		    "status2=0x%x", status, status1, status2);
	}

	emlxs_ffstate_change(hba, FC_ERROR);

	if (status & HS_FFER6) {
		(void) thread_create(NULL, 0, emlxs_restart_thread,
		    (char *)hba, 0, &p0, TS_RUN, v.v_maxsyspri - 2);
	} else {
		(void) thread_create(NULL, 0, emlxs_shutdown_thread,
		    (char *)hba, 0, &p0, TS_RUN, v.v_maxsyspri - 2);
	}

} /* emlxs_handle_ff_error() */



extern void
emlxs_reset_link_thread(void *arg)
{
	emlxs_hba_t *hba = (emlxs_hba_t *)arg;
	emlxs_port_t *port = &PPORT;

	/* Attempt a link reset to recover */
	(void) emlxs_reset(port, FC_FCA_LINK_RESET);

	(void) thread_exit();

} /* emlxs_reset_link_thread() */


extern void
emlxs_restart_thread(void *arg)
{
	emlxs_hba_t *hba = (emlxs_hba_t *)arg;
	emlxs_port_t *port = &PPORT;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_adapter_trans_msg, "Restarting...");

	/* Attempt a full hardware reset to recover */
	if (emlxs_reset(port, FC_FCA_RESET) != FC_SUCCESS) {
		emlxs_ffstate_change(hba, FC_ERROR);

		(void) thread_create(NULL, 0, emlxs_shutdown_thread,
		    (char *)hba, 0, &p0, TS_RUN, v.v_maxsyspri - 2);
	}
	(void) thread_exit();

} /* emlxs_restart_thread() */


extern void
emlxs_shutdown_thread(void *arg)
{
	emlxs_hba_t *hba = (emlxs_hba_t *)arg;
	emlxs_port_t *port = &PPORT;

	mutex_enter(&EMLXS_PORT_LOCK);
	if (hba->flag & FC_SHUTDOWN) {
		mutex_exit(&EMLXS_PORT_LOCK);
		(void) thread_exit();
	}
	hba->flag |= FC_SHUTDOWN;
	mutex_exit(&EMLXS_PORT_LOCK);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_adapter_trans_msg, "Shutting down...");

	/* Take adapter offline and leave it there */
	(void) emlxs_offline(hba);

	/* Log a dump event */
	emlxs_log_dump_event(port, NULL, 0);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_shutdown_msg, "Reboot required.");

	(void) thread_exit();

} /* emlxs_shutdown_thread() */



/*
 *  emlxs_handle_link_event
 *
 *    Description: Process a Link Attention.
 *
 */
static void
emlxs_handle_link_event(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	MAILBOX *mb;

	HBASTATS.LinkEvent++;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_link_event_msg,
	    "event=%x", HBASTATS.LinkEvent);


	/* Get a buffer which will be used for mailbox commands */
	if ((mb = (MAILBOX *) emlxs_mem_get(hba, MEM_MBOX | MEM_PRI))) {
		/* Get link attention message */
		if (emlxs_mb_read_la(hba, mb) == 0) {
			if (emlxs_mb_issue_cmd(hba, mb, MBX_NOWAIT, 0) !=
			    MBX_BUSY) {
				(void) emlxs_mem_put(hba, MEM_MBOX,
				    (uint8_t *)mb);
			}
			mutex_enter(&EMLXS_PORT_LOCK);


			/*
			 * Clear Link Attention in HA REG
			 */
			WRITE_CSR_REG(hba,
			    FC_HA_REG(hba, hba->csr_addr), HA_LATT);

			mutex_exit(&EMLXS_PORT_LOCK);
		} else {
			(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
		}
	}
} /* emlxs_handle_link_event()  */


/*
 *  emlxs_handle_ring_event
 *
 *    Description: Process a Ring Attention.
 *
 */
static void
emlxs_handle_ring_event(emlxs_hba_t *hba, int32_t ring_no, uint32_t ha_copy)
{
	emlxs_port_t *port = &PPORT;
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
	emlxs_buf_t *sbp;

	count = 0;
	rp = &hba->ring[ring_no];

	/* Isolate this ring's host attention bits */
	/* This makes all ring attention bits equal to Ring0 attention bits */
	reg = (ha_copy >> (ring_no * 4)) & 0x0f;

	/*
	 * Gather iocb entries off response ring. Ensure entry is owned by
	 * the host.
	 */
	pgp = (PGP *) & ((SLIM2 *) hba->slim2.virt)->mbx.us.s2.port[ring_no];
	offset = (off_t)((uint64_t)(unsigned long)&(pgp->rspPutInx) -
	    (uint64_t)(unsigned long)hba->slim2.virt);
	emlxs_mpdata_sync(hba->slim2.dma_handle, offset, 4,
	    DDI_DMA_SYNC_FORKERNEL);
	rp->fc_port_rspidx = PCIMEM_LONG(pgp->rspPutInx);

	/* While ring is not empty */
	while (rp->fc_rspidx != rp->fc_port_rspidx) {
		HBASTATS.IocbReceived[ring_no]++;

		/* Get the next response ring iocb */
		entry = (IOCB *) (((char *)rp->fc_rspringaddr +
		    (rp->fc_rspidx * hba->iocb_rsp_size)));

		/* DMA sync the response ring iocb for the adapter */
		offset = (off_t)((uint64_t)(unsigned long)entry -
		    (uint64_t)(unsigned long)hba->slim2.virt);
		emlxs_mpdata_sync(hba->slim2.dma_handle, offset,
		    hba->iocb_rsp_size, DDI_DMA_SYNC_FORKERNEL);

		count++;

		/* Copy word6 and word7 to local iocb for now */
		iocbq = &local_iocbq;
		emlxs_pcimem_bcopy((uint32_t *)entry + 6, (uint32_t *)iocbq + 6,
		    (sizeof (uint32_t) * 2));

		/* when LE is not set, entire Command has not been received */
		if (!iocbq->iocb.ulpLe) {
			/* This should never happen */
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ring_error_msg,
			    "ulpLE is not set. ring=%d iotag=%x cmd=%x "
			    "status=%x", ring_no, iocbq->iocb.ulpIoTag,
			    iocbq->iocb.ulpCommand, iocbq->iocb.ulpStatus);

			goto next;
		}
		switch (iocbq->iocb.ulpCommand) {
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
#endif	/* SFCT_SUPPORT */

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

			sbp = emlxs_unregister_pkt(rp, iocbq->iocb.ulpIoTag, 0);
			break;

		default:
			sbp = NULL;
		}

		/* If packet is stale, then drop it. */
		if (sbp == STALE_PACKET) {
			/* Copy entry to the local iocbq */
			emlxs_pcimem_bcopy((uint32_t *)entry, (uint32_t *)iocbq,
			    hba->iocb_rsp_size);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_iocb_stale_msg,
			    "ringno=%d iocb=%p cmd=%x status=%x error=%x "
			    "iotag=%x context=%x info=%x", ring_no, iocbq,
			    (uint8_t)iocbq->iocb.ulpCommand,
			    iocbq->iocb.ulpStatus,
			    (uint8_t)iocbq->iocb.un.grsp.perr.statLocalError,
			    (uint16_t)iocbq->iocb.ulpIoTag,
			    (uint16_t)iocbq->iocb.ulpContext,
			    (uint8_t)iocbq->iocb.ulpRsvdByte);

			goto next;
		}
		/*
		 * If a packet was found, then queue the packet's iocb for
		 * deferred processing
		 */
		else if (sbp) {
			atomic_add_32(&hba->io_active, -1);

			/* Copy entry to sbp's iocbq */
			iocbq = &sbp->iocbq;
			emlxs_pcimem_bcopy((uint32_t *)entry, (uint32_t *)iocbq,
			    hba->iocb_rsp_size);

			iocbq->next = NULL;

			/*
			 * If this is NOT a polled command completion or a
			 * driver allocated pkt, then defer pkt completion.
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
			emlxs_pcimem_bcopy((uint32_t *)entry, (uint32_t *)iocbq,
			    hba->iocb_rsp_size);

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
			((SLIM2 *) hba->slim2.virt)->mbx.us.s2.host[ring_no].
			    rspGetInx = PCIMEM_LONG(rp->fc_rspidx);

			/* DMA sync the index for the adapter */
			offset = (off_t)((uint64_t)(unsigned long)&((
			    (SLIM2 *)hba->slim2.virt)->mbx.us.s2.host[ring_no].
			    rspGetInx) -
			    (uint64_t)(unsigned long)hba->slim2.virt);
			emlxs_mpdata_sync(hba->slim2.dma_handle, offset, 4,
			    DDI_DMA_SYNC_FORDEV);
		} else {
			ioa2 = (void *) ((char *)hba->slim_addr +
			    hba->hgp_ring_offset + (((ring_no * 2) + 1) *
			    sizeof (uint32_t)));
			WRITE_SLIM_ADDR(hba, (volatile uint32_t *) ioa2,
			    rp->fc_rspidx);
		}

		if (reg & HA_R0RE_REQ) {
			/* HBASTATS.chipRingFree++; */

			mutex_enter(&EMLXS_PORT_LOCK);

			/* Tell the adapter we serviced the ring */
			chipatt = ((CA_R0ATT | CA_R0RE_RSP) <<
			    (ring_no * 4));
			WRITE_CSR_REG(hba, FC_CA_REG(hba, hba->csr_addr),
			    chipatt);

			mutex_exit(&EMLXS_PORT_LOCK);
		}
	}
	if (reg & HA_R0CE_RSP) {
		/* HBASTATS.hostRingFree++; */

		/* Cmd ring may be available. Try sending more iocbs */
		emlxs_issue_iocb_cmd(hba, rp, 0);
	}
	/* HBASTATS.ringEvent++; */

	return;

} /* emlxs_handle_ring_event() */


/* ARGSUSED */
extern void
emlxs_proc_ring(emlxs_hba_t *hba, RING *rp, void *arg2)
{
	IOCBQ *iocbq;
	IOCBQ *rsp_head;

	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg, "emlxs_proc_ring:
	 * ringo=%d", rp->ringno);
	 */

	mutex_enter(&rp->rsp_lock);

	while ((rsp_head = rp->rsp_head) != NULL) {
		rp->rsp_head = NULL;
		rp->rsp_tail = NULL;

		mutex_exit(&rp->rsp_lock);

		while ((iocbq = rsp_head) != NULL) {
			rsp_head = (IOCBQ *) iocbq->next;

			emlxs_proc_ring_event(hba, rp, iocbq);
		}

		mutex_enter(&rp->rsp_lock);
	}

	mutex_exit(&rp->rsp_lock);

	emlxs_issue_iocb_cmd(hba, rp, 0);

	return;

} /* emlxs_proc_ring() */


/*
 * Called from SLI-1 and SLI-2 ring event routines to process a rsp ring IOCB.
 */
static void
emlxs_proc_ring_event(emlxs_hba_t *hba, RING *rp, IOCBQ *iocbq)
{
	emlxs_port_t *port = &PPORT;
	char buffer[MAX_MSG_DATA + 1];
	IOCB *iocb;

	iocb = &iocbq->iocb;

	/* Check for IOCB local error */
	if (iocb->ulpStatus == IOSTAT_LOCAL_REJECT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_iocb_event_msg,
		    "Local reject. ringno=%d iocb=%p cmd=%x iotag=%x "
		    "context=%x info=%x error=%x",
		    rp->ringno, iocb, (uint8_t)iocb->ulpCommand,
		    (uint16_t)iocb->ulpIoTag, (uint16_t)iocb->ulpContext,
		    (uint8_t)iocb->ulpRsvdByte,
		    (uint8_t)iocb->un.grsp.perr.statLocalError);
	} else if (iocb->ulpStatus == IOSTAT_ILLEGAL_FRAME_RCVD) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_iocb_event_msg,
		    "Illegal frame. ringno=%d iocb=%p cmd=%x iotag=%x "
		    "context=%x info=%x error=%x",
		    rp->ringno, iocb, (uint8_t)iocb->ulpCommand,
		    (uint16_t)iocb->ulpIoTag, (uint16_t)iocb->ulpContext,
		    (uint8_t)iocb->ulpRsvdByte,
		    (uint8_t)iocb->un.grsp.perr.statLocalError);
	}
	switch (iocb->ulpCommand) {
		/* RING 0 FCP commands */
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
		(void) emlxs_handle_fcp_event(hba, rp, iocbq);
		break;

#ifdef SFCT_SUPPORT
	case CMD_FCP_TSEND_CX:	/* FCP_TARGET IOCB command */
	case CMD_FCP_TSEND64_CX:	/* FCP_TARGET IOCB command */
	case CMD_FCP_TRECEIVE_CX:	/* FCP_TARGET IOCB command */
	case CMD_FCP_TRECEIVE64_CX:	/* FCP_TARGET IOCB command */
	case CMD_FCP_TRSP_CX:	/* FCP_TARGET IOCB command */
	case CMD_FCP_TRSP64_CX:	/* FCP_TARGET IOCB command */
		(void) emlxs_fct_handle_fcp_event(hba, rp, iocbq);
		break;
#endif	/* SFCT_SUPPORT */

		/* RING 1 IP commands */
	case CMD_XMIT_BCAST_CN:
	case CMD_XMIT_BCAST_CX:
	case CMD_XMIT_BCAST64_CN:
	case CMD_XMIT_BCAST64_CX:
		(void) emlxs_ip_handle_event(hba, rp, iocbq);
		break;

	case CMD_XMIT_SEQUENCE_CX:
	case CMD_XMIT_SEQUENCE_CR:
	case CMD_XMIT_SEQUENCE64_CX:
	case CMD_XMIT_SEQUENCE64_CR:
		switch (iocb->un.rcvseq64.w5.hcsw.Type) {
		case FC_TYPE_IS8802_SNAP:
			(void) emlxs_ip_handle_event(hba, rp, iocbq);
			break;

		case FC_TYPE_FC_SERVICES:
			(void) emlxs_ct_handle_event(hba, rp, iocbq);
			break;

		default:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_iocb_invalid_msg,
			    "cmd=%x type=%x status=%x iotag=%x context=%x ",
			    iocb->ulpCommand, iocb->un.rcvseq64.w5.hcsw.Type,
			    iocb->ulpStatus, iocb->ulpIoTag, iocb->ulpContext);
		}
		break;

	case CMD_RCV_SEQUENCE_CX:
	case CMD_RCV_SEQUENCE64_CX:
	case CMD_RCV_SEQ64_CX:
	case CMD_RCV_ELS_REQ_CX:	/* Unsolicited ELS frame  */
	case CMD_RCV_ELS_REQ64_CX:	/* Unsolicited ELS frame  */
	case CMD_RCV_ELS64_CX:	/* Unsolicited ELS frame  */
		(void) emlxs_handle_rcv_seq(hba, rp, iocbq);
		break;

	case CMD_RCV_SEQ_LIST64_CX:
		(void) emlxs_ip_handle_rcv_seq_list(hba, rp, iocbq);
		break;

	case CMD_CREATE_XRI_CR:
	case CMD_CREATE_XRI_CX:
		(void) emlxs_handle_create_xri(hba, rp, iocbq);
		break;

		/* RING 2 ELS commands */
	case CMD_ELS_REQUEST_CR:
	case CMD_ELS_REQUEST_CX:
	case CMD_XMIT_ELS_RSP_CX:
	case CMD_ELS_REQUEST64_CR:
	case CMD_ELS_REQUEST64_CX:
	case CMD_XMIT_ELS_RSP64_CX:
		(void) emlxs_els_handle_event(hba, rp, iocbq);
		break;

		/* RING 3 CT commands */
	case CMD_GEN_REQUEST64_CR:
	case CMD_GEN_REQUEST64_CX:
		switch (iocb->un.rcvseq64.w5.hcsw.Type) {
#ifdef MENLO_SUPPORT
		case EMLXS_MENLO_TYPE:
			(void) emlxs_menlo_handle_event(hba, rp, iocbq);
			break;
#endif	/* MENLO_SUPPORT */

		case FC_TYPE_FC_SERVICES:
			(void) emlxs_ct_handle_event(hba, rp, iocbq);
			break;

		default:
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_iocb_invalid_msg,
			    "cmd=%x type=%x status=%x iotag=%x context=%x ",
			    iocb->ulpCommand, iocb->un.rcvseq64.w5.hcsw.Type,
			    iocb->ulpStatus, iocb->ulpIoTag, iocb->ulpContext);
		}
		break;

	case CMD_ABORT_XRI_CN:	/* Abort fcp command */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_flushed_msg,
		    "ABORT_XRI_CN: rpi=%d iotag=%x status=%x parm=%x",
		    (uint32_t)iocb->un.acxri.abortContextTag,
		    (uint32_t)iocb->un.acxri.abortIoTag,
		    iocb->ulpStatus, iocb->un.acxri.parm);

		break;

	case CMD_ABORT_XRI_CX:	/* Abort command */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_flushed_msg,
		    "ABORT_XRI_CX: rpi=%d iotag=%x status=%x parm=%x",
		    (uint32_t)iocb->un.acxri.abortContextTag,
		    (uint32_t)iocb->un.acxri.abortIoTag,
		    iocb->ulpStatus, iocb->un.acxri.parm);

		break;

	case CMD_XRI_ABORTED_CX:	/* Handle ABORT condition */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_flushed_msg,
		    "XRI_ABORTED_CX: rpi=%d iotag=%x status=%x parm=%x",
		    (uint32_t)iocb->un.acxri.abortContextTag,
		    (uint32_t)iocb->un.acxri.abortIoTag,
		    iocb->ulpStatus, iocb->un.acxri.parm);

		break;

	case CMD_CLOSE_XRI_CN:	/* Handle CLOSE condition */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_flushed_msg,
		    "CLOSE_XRI_CR: rpi=%d iotag=%x status=%x parm=%x",
		    (uint32_t)iocb->un.acxri.abortContextTag,
		    (uint32_t)iocb->un.acxri.abortIoTag,
		    iocb->ulpStatus, iocb->un.acxri.parm);

		break;

	case CMD_CLOSE_XRI_CX:	/* Handle CLOSE condition */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_flushed_msg,
		    "CLOSE_XRI_CX: rpi=%d iotag=%x status=%x parm=%x",
		    (uint32_t)iocb->un.acxri.abortContextTag,
		    (uint32_t)iocb->un.acxri.abortIoTag,
		    iocb->ulpStatus, iocb->un.acxri.parm);

		break;

	case CMD_ADAPTER_MSG:
		/* Allows debug adapter firmware messages to print on host */
		bzero(buffer, sizeof (buffer));
		bcopy((uint8_t *)iocb, buffer, MAX_MSG_DATA);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_adapter_msg, "%s", buffer);

		break;

	case CMD_QUE_RING_LIST64_CN:
	case CMD_QUE_RING_BUF64_CN:
		break;

	case CMD_ASYNC_STATUS:
		(void) emlxs_handle_async_event(hba, rp, iocbq);
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_iocb_invalid_msg,
		    "cmd=%x status=%x iotag=%x context=%x",
		    iocb->ulpCommand, iocb->ulpStatus, iocb->ulpIoTag,
		    iocb->ulpContext);

		break;
	}	/* switch(entry->ulpCommand) */

	return;

} /* emlxs_proc_ring_event() */



static int
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
#endif	/* SLI3_SUPPORT */

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
#endif	/* SFCT_SUPPORT */

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
		    emlxs_state_xlate(iocb->ulpStatus),
		    word[4], word[5], word[6], word[7]);
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

		*UbPosted -= 1;

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
#endif	/* SLI3_SUPPORT */
	{
		bdeAddr = getPaddr(iocb->un.cont64[0].addrHigh,
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
				(void) sprintf(error_str, "Invalid VPI=%d:",
				    vpi);
				goto dropped;
			}
			port = &VPORT(vpi);
		}
	}
#endif	/* SLI3_SUPPORT */

	/* Process request */
	switch (ringno) {
#ifdef SFCT_SUPPORT
	case FC_FCT_RING:
		(void) emlxs_fct_handle_unsol_req(port, rp, iocbq, mp, size);
		break;
#endif	/* SFCT_SUPPORT */

	case FC_IP_RING:
		(void) emlxs_ip_handle_unsol_req(port, rp, iocbq, mp, size);
		break;

	case FC_ELS_RING:
		/* If this is a target port, then let fct handle this */
#ifdef SFCT_SUPPORT
		if (port->tgt_mode) {
			(void) emlxs_fct_handle_unsol_els(port, rp, iocbq,
			    mp, size);
		} else {
			(void) emlxs_els_handle_unsol_req(port, rp, iocbq,
			    mp, size);
		}
#else
		(void) emlxs_els_handle_unsol_req(port, rp, iocbq,
		    mp, size);
#endif	/* SFCT_SUPPORT */
		break;

	case FC_CT_RING:
		(void) emlxs_ct_handle_unsol_req(port, rp, iocbq, mp, size);
		break;
	}

	goto done;

dropped:
	*RcvDropped += 1;

	EMLXS_MSGF(EMLXS_CONTEXT, dropped_msg,
	    "%s: cmd=%x  %s %x %x %x %x",
	    error_str, iocb->ulpCommand, emlxs_state_xlate(iocb->ulpStatus),
	    word[4], word[5], word[6], word[7]);

	if (ringno == FC_FCT_RING) {
		uint32_t sid;

#ifdef SLI3_SUPPORT
		if (hba->sli_mode >= 3) {
			emlxs_node_t *ndlp;
			ndlp = emlxs_node_find_rpi(port, iocb->ulpIoTag);
			sid = ndlp->nlp_DID;
		} else
#endif	/* SLI3_SUPPORT */
		{
			sid = iocb->un.ulpWord[4] & 0xFFFFFF;
		}

		emlxs_send_logo(port, sid);
	}
	goto done;

failed:
	*RcvError += 1;

	EMLXS_MSGF(EMLXS_CONTEXT, dropped_msg,
	    "%s: cmd=%x %s  %x %x %x %x  hba:%x %x",
	    error_str, iocb->ulpCommand, emlxs_state_xlate(iocb->ulpStatus),
	    word[4], word[5], word[6], word[7], hba->state, hba->flag);

done:

#ifdef SLI3_SUPPORT
	if (hba->flag & FC_HBQ_ENABLED) {
		emlxs_update_HBQ_index(hba, hbq_id);
	} else
#endif	/* SLI3_SUPPORT */
	{
		if (mp) {
			(void) emlxs_mem_put(hba, buf_type, (uint8_t *)mp);
		}
		(void) emlxs_post_buffer(hba, rp, 1);
	}

	return (0);

} /* emlxs_handle_rcv_seq() */



extern void
emlxs_issue_iocb_cmd(emlxs_hba_t *hba, RING *rp, IOCBQ *iocbq)
{
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

begin:

	/* Check if FCP ring and adapter is not ready */
	if ((ringno == FC_FCP_RING) && (hba->state != FC_READY)) {
		if (!iocbq) {
			return;
		}
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
				 * &emlxs_ring_watchdog_msg, "%s host=%d
				 * port=%d cnt=%d,%d  RACE CONDITION3
				 * DETECTED.", emlxs_ring_xlate(ringno),
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
	pgp = (PGP *) & ((SLIM2 *) hba->slim2.virt)->mbx.us.s2.port[ringno];
	offset = (off_t)((uint64_t)(unsigned long)&(pgp->cmdGetInx) -
	    (uint64_t)(unsigned long)hba->slim2.virt);
	emlxs_mpdata_sync(hba->slim2.dma_handle, offset, 4,
	    DDI_DMA_SYNC_FORKERNEL);
	rp->fc_port_cmdidx = PCIMEM_LONG(pgp->cmdGetInx);

	/* Calculate the next put index */
	nextIdx = (rp->fc_cmdidx + 1 >= rp->fc_numCiocb) ?
	    0 : rp->fc_cmdidx + 1;

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
	/* We have a command ring slot available */
	/* Make sure we have an iocb to send */

	if (iocbq) {
		mutex_enter(&EMLXS_RINGTX_LOCK);

		/* Check if the ring already has iocb's waiting */
		if (rp->nodeq.q_first != NULL) {
			/* Put the current iocbq on the tx queue */
			emlxs_tx_put(iocbq, 0);

			/*
			 * Attempt to replace it with the next iocbq in the
			 * tx queue
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
					offset =
					    (off_t)
					    ((uint64_t)(unsigned long)&(slim2p->
					    mbx.us.s2.host[ringno].cmdPutInx) -
					    (uint64_t)(unsigned long)slim2p);
					emlxs_mpdata_sync(hba->slim2.dma_handle,
					    offset, 4, DDI_DMA_SYNC_FORDEV);
				} else {
					ioa2 = (void *)((char *)hba->slim_addr +
					    hba->hgp_ring_offset +
					    ((ringno * 2) * sizeof (uint32_t)));
					WRITE_SLIM_ADDR(hba,
					    (volatile uint32_t *)ioa2,
					    rp->fc_cmdidx);
				}

				status = (CA_R0ATT << (ringno * 4));
				WRITE_CSR_REG(hba,
				    FC_CA_REG(hba, hba->csr_addr),
				    (volatile uint32_t)status);

			}
			/* Perform delay */
			if (ringno == FC_ELS_RING) {
				(void) drv_usecwait(100000);
			} else {
				(void) drv_usecwait(20000);
			}
		}
#endif	/* NPIV_SUPPORT */

		/* At this point, we have a command ring slot available */
		/* and an iocb to send */

		/* Send the iocb */
		emlxs_issue_iocb(hba, rp, iocbq);

		count++;

		/* Check if HBA is full */
		throttle = hba->io_throttle - hba->io_active;
		if (throttle <= 0) {
			goto busy;
		}
		/* Calculate the next put index */
		nextIdx = (rp->fc_cmdidx + 1 >= rp->fc_numCiocb) ?
		    0 : rp->fc_cmdidx + 1;

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
			    ((uint64_t)(unsigned long)&(slim2p->mbx.us.s2.
			    host[ringno].cmdPutInx) -
			    (uint64_t)(unsigned long)slim2p);
			emlxs_mpdata_sync(hba->slim2.dma_handle, offset, 4,
			    DDI_DMA_SYNC_FORDEV);
		} else {
			ioa2 = (void *) ((char *)hba->slim_addr +
			    hba->hgp_ring_offset + ((ringno * 2) *
			    sizeof (uint32_t)));
			WRITE_SLIM_ADDR(hba,
			    (volatile uint32_t *)ioa2, rp->fc_cmdidx);
		}

		status = (CA_R0ATT << (ringno * 4));
		WRITE_CSR_REG(hba, FC_CA_REG(hba, hba->csr_addr),
		    (volatile uint32_t)status);

		/* Check tx queue one more time before releasing */
		if ((iocbq = emlxs_tx_get(rp, 1))) {
			/*
			 * EMLXS_MSGF(EMLXS_CONTEXT,
			 * &emlxs_ring_watchdog_msg, "%s host=%d port=%d
			 * RACE CONDITION1 DETECTED.",
			 * emlxs_ring_xlate(ringno), rp->fc_cmdidx,
			 * rp->fc_port_cmdidx);
			 */
			goto sendit;
		}
	}
	mutex_exit(&EMLXS_CMD_RING_LOCK(ringno));

	return;

busy:

	/*
	 * Set ring to SET R0CE_REQ in Chip Att register. Chip will tell us
	 * when an entry is freed.
	 */
	if (count) {
		/* Update the adapter's cmd put index */
		if (hba->bus_type == SBUS_FC) {
			slim2p->mbx.us.s2.host[ringno].cmdPutInx =
			    PCIMEM_LONG(rp->fc_cmdidx);

			/* DMA sync the index for the adapter */
			offset = (off_t)
			    ((uint64_t)(unsigned long)&(slim2p->mbx.us.s2.
			    host[ringno].cmdPutInx) -
			    (uint64_t)(unsigned long)slim2p);
			emlxs_mpdata_sync(hba->slim2.dma_handle, offset, 4,
			    DDI_DMA_SYNC_FORDEV);
		} else {
			ioa2 = (void *) ((char *)hba->slim_addr +
			    hba->hgp_ring_offset + ((ringno * 2) *
			    sizeof (uint32_t)));
			WRITE_SLIM_ADDR(hba, (volatile uint32_t *) ioa2,
			    rp->fc_cmdidx);
		}
	}
	status = ((CA_R0ATT | CA_R0CE_REQ) << (ringno * 4));
	WRITE_CSR_REG(hba, FC_CA_REG(hba, hba->csr_addr),
	    (volatile uint32_t) status);

	if (throttle <= 0) {
		HBASTATS.IocbThrottled++;
	} else {
		HBASTATS.IocbRingFull[ringno]++;
	}

	mutex_exit(&EMLXS_CMD_RING_LOCK(ringno));

	return;

} /* emlxs_issue_iocb_cmd() */



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
			iocbq->node = (void *) &port->node_base;
			sbp->node = (void *) &port->node_base;
		}
		sbp->pkt_flags |= PACKET_IN_CHIPQ;
		mutex_exit(&sbp->mtx);

		atomic_add_32(&hba->io_active, 1);
	}
	/* get the next available command ring iocb */
	iocb = (IOCB *) (((char *)rp->fc_cmdringaddr +
	    (rp->fc_cmdidx * hba->iocb_cmd_size)));

	/* Copy the local iocb to the command ring iocb */
	emlxs_pcimem_bcopy((uint32_t *)icmd, (uint32_t *)iocb,
	    hba->iocb_cmd_size);

	/* DMA sync the command ring iocb for the adapter */
	offset = (off_t)((uint64_t)(unsigned long)iocb -
	    (uint64_t)(unsigned long)hba->slim2.virt);
	emlxs_mpdata_sync(hba->slim2.dma_handle, offset,
	    hba->iocb_cmd_size, DDI_DMA_SYNC_FORDEV);

	/* Free the local iocb if there is no sbp tracking it */
	if (!sbp) {
		(void) emlxs_mem_put(hba, MEM_IOCB, (uint8_t *)iocbq);
	}
	/* update local ring index to next available ring index */
	rp->fc_cmdidx = (rp->fc_cmdidx + 1 >= rp->fc_numCiocb) ?
	    0 : rp->fc_cmdidx + 1;


	return;

} /* emlxs_issue_iocb() */


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
	swpmb = (MAILBOX *) & word0;

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
	WRITE_SLIM_ADDR(hba, (((volatile uint32_t *) mb1) + 1), value);
	WRITE_SLIM_ADDR(hba, (((volatile uint32_t *) mb1)), word0);

	/* Send Kill board request */
	mb2->un.varWords[0] = value;
	mb2->mbxCommand = MBX_KILL_BOARD;
	mb2->mbxOwner = OWN_CHIP;

	/* Sync the memory */
	offset = (off_t)((uint64_t)(unsigned long)mb2 -
	    (uint64_t)(unsigned long)hba->slim2.virt);
	size = (sizeof (uint32_t) * 2);
	emlxs_pcimem_bcopy((uint32_t *)mb2, (uint32_t *)mb2, size);
	emlxs_mpdata_sync(hba->slim2.dma_handle, offset, size,
	    DDI_DMA_SYNC_FORDEV);

	/* interrupt board to do it right away */
	WRITE_CSR_REG(hba, FC_CA_REG(hba, hba->csr_addr), CA_MBATT);

	/* First wait for command acceptence */
	j = 0;
	while (j++ < 1000) {
		value = READ_SLIM_ADDR(hba, (((volatile uint32_t *) mb1) + 1));

		if (value == 0) {
			break;
		}
		DELAYUS(50);
	}

	if (value == 0) {
		/* Now wait for mailbox ownership to clear */
		while (j++ < 10000) {
			word0 = READ_SLIM_ADDR(hba,
			    ((volatile uint32_t *)mb1));

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

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
	    "Interlock failed.");

mode_B:

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
	    "Attempting SLIM1 Interlock...");

interlock_B:

	value = 0xFFFFFFFF;
	word0 = 0;
	swpmb->mbxCommand = MBX_KILL_BOARD;
	swpmb->mbxOwner = OWN_CHIP;

	/* Write KILL BOARD to mailbox */
	WRITE_SLIM_ADDR(hba, (((volatile uint32_t *) mb1) + 1), value);
	WRITE_SLIM_ADDR(hba, ((volatile uint32_t *) mb1), word0);

	/* interrupt board to do it right away */
	WRITE_CSR_REG(hba, FC_CA_REG(hba, hba->csr_addr), CA_MBATT);

	/* First wait for command acceptence */
	j = 0;
	while (j++ < 1000) {
		value = READ_SLIM_ADDR(hba, (((volatile uint32_t *) mb1) + 1));

		if (value == 0) {
			break;
		}
		DELAYUS(50);
	}

	if (value == 0) {
		/* Now wait for mailbox ownership to clear */
		while (j++ < 10000) {
			word0 = READ_SLIM_ADDR(hba,
			    ((volatile uint32_t *)mb1));

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
	 * Now check for error attention to indicate the board has been
	 * kiilled
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

} /* emlxs_interlock() */



extern uint32_t
emlxs_hba_reset(emlxs_hba_t *hba, uint32_t restart, uint32_t skip_post)
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
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg, "Restarting.");
		emlxs_ffstate_change(hba, FC_INIT_START);

		ready = (HS_FFRDY | HS_MBRDY);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg, "Resetting.");
		emlxs_ffstate_change(hba, FC_WARM_START);

		ready = HS_MBRDY;
	}

	hba->flag &= ~(FC_SLIM2_MODE | FC_HARDWARE_ERROR);

	mb = FC_SLIM1_MAILBOX(hba);
	swpmb = (MAILBOX *) & word0;

reset:

	/* Save reset time */
	HBASTATS.ResetTime = hba->timer_tics;

	if (restart) {
		/* First put restart command in mailbox */
		word0 = 0;
		swpmb->mbxCommand = MBX_RESTART;
		swpmb->mbxHc = 1;
		WRITE_SLIM_ADDR(hba, ((volatile uint32_t *) mb), word0);

		/* Only skip post after emlxs_ffinit is completed  */
		if (skip_post) {
			WRITE_SLIM_ADDR(hba,
			    (((volatile uint32_t *)mb) + 1), 1);
		} else {
			WRITE_SLIM_ADDR(hba,
			    (((volatile uint32_t *)mb) + 1), 0);
		}

	}
	/*
	 * Turn off SERR, PERR in PCI cmd register
	 */
	cfg_value = ddi_get16(hba->pci_acc_handle,
	    (uint16_t *)(hba->pci_addr + PCI_COMMAND_REGISTER));

	(void) ddi_put16(hba->pci_acc_handle,
	    (uint16_t *)(hba->pci_addr + PCI_COMMAND_REGISTER),
	    (uint16_t)(cfg_value & ~(CMD_PARITY_CHK | CMD_SERR_ENBL)));

	hba->hc_copy = HC_INITFF;
	WRITE_CSR_REG(hba, FC_HC_REG(hba, hba->csr_addr), hba->hc_copy);

	/* Wait 1 msec before restoring PCI config */
	DELAYMS(1);

	/* Restore PCI cmd register */
	(void) ddi_put16(hba->pci_acc_handle,
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
			status1 = READ_SLIM_ADDR(hba,
			    ((volatile uint8_t *) hba->slim_addr + 0xa8));
			status2 = READ_SLIM_ADDR(hba,
			    ((volatile uint8_t *) hba->slim_addr + 0xac));

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
		 * again (w/post), then check every 1 second for 15 seconds.
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

} /* emlxs_hba_reset */



extern void
emlxs_poll_intr(emlxs_hba_t *hba, uint32_t att_bit)
{
	uint32_t ha_copy;

	/*
	 * Polling a specific attention bit.
	 */
	for (;;) {
		ha_copy = READ_CSR_REG(hba, FC_HA_REG(hba, hba->csr_addr));

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

} /* emlxs_poll_intr() */


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
	pgp = (PGP *) & ((SLIM2 *) hba->slim2.virt)->mbx.us.s2.port[ringno];

	if ((mb = (MAILBOX *) emlxs_mem_get(hba, MEM_MBOX | MEM_PRI)) == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ring_reset_msg,
		    "%s: Unable to allocate mailbox buffer.",
		    emlxs_ring_xlate(ringno));

		return ((uint32_t)FC_FAILURE);
	}
	emlxs_mb_reset_ring(hba, mb, ringno);
	if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ring_reset_msg,
		    "%s: Unable to reset ring. Mailbox cmd=%x status=%x",
		    emlxs_ring_xlate(ringno), mb->mbxCommand, mb->mbxStatus);

		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
		return ((uint32_t)FC_FAILURE);
	}
	/* Free the mailbox */
	(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);

	/* Update the response ring indicies */
	offset = (off_t)((uint64_t)(unsigned long)&(pgp->rspPutInx) -
	    (uint64_t)(unsigned long)hba->slim2.virt);
	emlxs_mpdata_sync(hba->slim2.dma_handle, offset, 4,
	    DDI_DMA_SYNC_FORKERNEL);
	rp->fc_rspidx = rp->fc_port_rspidx = PCIMEM_LONG(pgp->rspPutInx);

	/* Update the command ring indicies */
	offset = (off_t)((uint64_t)(unsigned long)&(pgp->cmdGetInx) -
	    (uint64_t)(unsigned long)hba->slim2.virt);
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

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_ring_reset_msg,
	    "%s", emlxs_ring_xlate(ringno));

	return (FC_SUCCESS);

} /* emlxs_reset_ring() */


extern char *
emlxs_ffstate_xlate(uint32_t state)
{
	static char buffer[32];
	uint32_t i;
	uint32_t count;

	count = sizeof (emlxs_ffstate_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (state == emlxs_ffstate_table[i].code) {
			return (emlxs_ffstate_table[i].string);
		}
	}

	(void) sprintf(buffer, "state=0x%x", state);
	return (buffer);

} /* emlxs_ffstate_xlate() */


extern char *
emlxs_ring_xlate(uint32_t ringno)
{
	static char buffer[32];
	uint32_t i;
	uint32_t count;

	count = sizeof (emlxs_ring_table) / sizeof (emlxs_table_t);
	for (i = 0; i < count; i++) {
		if (ringno == emlxs_ring_table[i].code) {
			return (emlxs_ring_table[i].string);
		}
	}

	(void) sprintf(buffer, "ring=0x%x", ringno);
	return (buffer);

} /* emlxs_ring_xlate() */



extern void
emlxs_pcix_mxr_update(emlxs_hba_t *hba, uint32_t verbose)
{
	emlxs_port_t *port = &PPORT;
	MAILBOX *mb;
	emlxs_config_t *cfg;
	uint32_t value;

	cfg = &CFG;

xlate:

	switch (cfg[CFG_PCI_MAX_READ].current) {
	case 512:
		value = 0;
		break;

	case 1024:
		value = 1;
		break;

	case 2048:
		value = 2;
		break;

	case 4096:
		value = 3;
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "PCI_MAX_READ: Invalid parameter value. old=%d new=%d",
		    cfg[CFG_PCI_MAX_READ].current, cfg[CFG_PCI_MAX_READ].def);

		cfg[CFG_PCI_MAX_READ].current = cfg[CFG_PCI_MAX_READ].def;
		goto xlate;
	}

	if ((mb = (MAILBOX *) emlxs_mem_get(hba, MEM_MBOX | MEM_PRI)) == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "PCI_MAX_READ: Unable to allocate mailbox buffer.");
		return;
	}
	emlxs_mb_set_var(hba, (MAILBOX *) mb, 0x00100506, value);

	if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		if (verbose || (mb->mbxStatus != 0x12)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "PCI_MAX_READ: Unable to update. status=%x "
			    "value=%d (%d bytes)", mb->mbxStatus, value,
			    cfg[CFG_PCI_MAX_READ].current);
		}
	} else {
		if (verbose && (cfg[CFG_PCI_MAX_READ].current !=
		    cfg[CFG_PCI_MAX_READ].def)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "PCI_MAX_READ: Updated. %d bytes",
			    cfg[CFG_PCI_MAX_READ].current);
		}
	}

	(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);

	return;

} /* emlxs_pcix_mxr_update */



extern uint32_t
emlxs_get_key(emlxs_hba_t *hba, MAILBOX *mb)
{
	emlxs_port_t *port = &PPORT;
	uint32_t npname0, npname1;
	uint32_t tmpkey, theKey;
	uint16_t key850;
	uint32_t t1, t2, t3, t4;
	uint32_t ts;

#define	SEED 0x876EDC21

	/* This key is only used currently for SBUS adapters */
	if (hba->bus_type != SBUS_FC) {
		return (0);
	}
	tmpkey = mb->un.varWords[30];
	emlxs_ffstate_change(hba, FC_INIT_NVPARAMS);

	emlxs_mb_read_nv(hba, mb);
	if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "Unable to read nvram. cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		return (0);
	}
	npname0 = mb->un.varRDnvp.portname[0];
	npname1 = mb->un.varRDnvp.portname[1];

	key850 = (uint16_t)((tmpkey & 0x00FFFF00) >> 8);
	ts = (uint16_t)(npname1 + 1);
	t1 = ts * key850;
	ts = (uint16_t)((npname1 >> 16) + 1);
	t2 = ts * key850;
	ts = (uint16_t)(npname0 + 1);
	t3 = ts * key850;
	ts = (uint16_t)((npname0 >> 16) + 1);
	t4 = ts * key850;
	theKey = SEED + t1 + t2 + t3 + t4;

	return (theKey);

} /* emlxs_get_key() */
