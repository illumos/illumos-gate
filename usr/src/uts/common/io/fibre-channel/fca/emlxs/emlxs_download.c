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


#include "emlxs.h"

/* Required for EMLXS_CONTEXT in EMLXS_MSGF calls */
EMLXS_MSG_DEF(EMLXS_DOWNLOAD_C);

#define	MAX_BOOTID	10

#define	DATA32_SWAP(x)	((((x) & 0xFF)<<24) | (((x) & 0xFF00)<<8) | \
	(((x) & 0xFF0000)>>8) | (((x) & 0xFF000000)>>24))

static uint32_t emlxs_erase_fcode_flash(emlxs_hba_t *hba);
static uint32_t emlxs_write_fcode_flash(emlxs_hba_t *hba, PIMAGE_HDR ImageHdr,
    caddr_t Buffer);

static int32_t emlxs_build_parms(caddr_t Buffer, PWAKE_UP_PARMS AbsWakeUpParms,
    uint32_t BufferSize, PAIF_HDR AifHeader, int32_t DwcFile);

static uint32_t emlxs_validate_image(emlxs_hba_t *hba, caddr_t Buffer,
    uint32_t Size, emlxs_fw_image_t *fw_image);

static void emlxs_format_dump(MAILBOX *mb, uint32_t Type, uint32_t RegionId,
    uint32_t WordCount, uint32_t BaseAddr);

static uint32_t emlxs_start_abs_download(emlxs_hba_t *hba, PAIF_HDR AifHdr,
    caddr_t Buffer, PWAKE_UP_PARMS WakeUpParms, uint32_t MaxRbusSramSize,
    uint32_t MaxIbusSramSize, PWAKE_UP_PARMS AbsWakeUpParms, int32_t DwcFile);

static uint32_t emlxs_start_abs_download_2mb(emlxs_hba_t *hba, caddr_t buffer,
    uint32_t len, uint32_t offline, emlxs_fw_image_t *fw_image);

static uint32_t emlxs_proc_abs_2mb(emlxs_hba_t *hba, PAIF_HDR AifHdr,
    caddr_t EntireBuffer, uint32_t FileType, uint32_t BWCflag,
    uint32_t extType);

static void emlxs_format_load_area_cmd(MAILBOX *mb, uint32_t Base,
    uint32_t DlByteCount, uint32_t Function, uint32_t Complete,
    uint32_t DataOffset, uint32_t AreaId, uint8_t MbxCmd, uint32_t StepCmd);

static uint32_t emlxs_build_parms_2mb_bwc(emlxs_hba_t *hba, PAIF_HDR AifHdr,
    uint32_t extType, PWAKE_UP_PARMS AbsWakeUpParms);

static uint32_t emlxs_build_parms_2mb_dwc(emlxs_hba_t *hba, caddr_t Buffer,
    uint32_t BufferSize, PAIF_HDR AifHeader, PWAKE_UP_PARMS AbsWakeUpParms,
    uint32_t BWCflag, uint32_t extType, uint32_t *numBootImage);

static uint32_t emlxs_update_exp_rom(emlxs_hba_t *hba,
    PWAKE_UP_PARMS WakeUpParms);

extern uint32_t emlxs_get_max_sram(emlxs_hba_t *hba, uint32_t *MaxRbusSize,
    uint32_t *MaxIbusSize);

static void emlxs_format_prog_flash(MAILBOX *mb, uint32_t Base,
    uint32_t DlByteCount, uint32_t Function, uint32_t Complete,
    uint32_t BdeAddress, uint32_t BdeSize, PROG_ID * ProgId);

static void emlxs_format_update_parms(MAILBOX * mb, PWAKE_UP_PARMS WakeUpParms);

static void emlxs_format_update_pci_cfg(emlxs_hba_t *hba, MAILBOX *mb,
    uint32_t region_id, uint32_t size);

static uint32_t emlxs_update_wakeup_parms(emlxs_hba_t *hba,
    PWAKE_UP_PARMS AbsWakeUpParms, PWAKE_UP_PARMS WakeUpParms);

static uint32_t emlxs_update_boot_wakeup_parms(emlxs_hba_t *hba,
    PWAKE_UP_PARMS WakeUpParms, PROG_ID *id, uint32_t proc_erom);

static uint32_t emlxs_update_ff_wakeup_parms(emlxs_hba_t *hba,
    PWAKE_UP_PARMS WakeUpParms, PROG_ID *id);

static uint32_t emlxs_update_sli1_wakeup_parms(emlxs_hba_t *hba,
    PWAKE_UP_PARMS WakeUpParms, PROG_ID *id);

static uint32_t emlxs_update_sli2_wakeup_parms(emlxs_hba_t *hba,
    PWAKE_UP_PARMS WakeUpParms, PROG_ID *id);

static uint32_t emlxs_update_sli3_wakeup_parms(emlxs_hba_t *hba,
    PWAKE_UP_PARMS WakeUpParms, PROG_ID *id);

static uint32_t emlxs_update_sli4_wakeup_parms(emlxs_hba_t *hba,
    PWAKE_UP_PARMS WakeUpParms, PROG_ID *id);


static uint32_t emlxs_start_rel_download(emlxs_hba_t *hba,
    PIMAGE_HDR ImageHdr, caddr_t Buffer, PWAKE_UP_PARMS WakeUpParms,
    uint32_t MaxRbusSramSize, uint32_t MaxIbusSramSize);

/*
 * static void emlxs_del_all_fw_images(emlxs_hba_t *hbat,
 *     PWAKE_UP_PARMS WakeUpParms, PIMAGE_HDR ImageHdr);
 */

static uint32_t emlxs_read_load_list(emlxs_hba_t *hba, LOAD_LIST *LoadList);

/* static void    emlxs_format_del_entry(MAILBOX *mb, PROG_ID Id); */

static uint32_t emlxs_valid_cksum(uint32_t *StartAddr, uint32_t *EndAddr);
static void emlxs_disp_aif_header(emlxs_hba_t *hba, PAIF_HDR AifHdr);
static void emlxs_dump_image_header(emlxs_hba_t *hba, PIMAGE_HDR image);
static uint32_t emlxs_get_abs_image_type(caddr_t Buffer, uint32_t BufferSize);

static uint32_t emlxs_get_dwc_image_type(emlxs_hba_t *hba, caddr_t Buffer,
    uint32_t BufferSize, PAIF_HDR AifHeader);

static uint32_t emlxs_type_check(uint32_t type);
static uint32_t emlxs_kern_check(emlxs_hba_t *hba, uint32_t version);
static uint32_t emlxs_stub_check(emlxs_hba_t *hba, uint32_t version);
static uint32_t emlxs_sli1_check(emlxs_hba_t *hba, uint32_t version);
static uint32_t emlxs_sli2_check(emlxs_hba_t *hba, uint32_t version);
static uint32_t emlxs_sli3_check(emlxs_hba_t *hba, uint32_t version);
static uint32_t emlxs_sli4_check(emlxs_hba_t *hba, uint32_t version);
static uint32_t emlxs_bios_check(emlxs_hba_t *hba, uint32_t version);
static uint32_t emlxs_sbus_fcode_check(emlxs_hba_t *hba, uint32_t version);
static uint32_t emlxs_validate_version(emlxs_hba_t *hba, emlxs_fw_file_t *file,
    uint32_t id, uint32_t type, char *file_type);

extern int32_t
emlxs_fw_download(emlxs_hba_t *hba, caddr_t buffer, uint32_t len,
    uint32_t offline)
{
	emlxs_port_t *port = &PPORT;
	uint32_t *Uptr;
	IMAGE_HDR ImageHdr;
	AIF_HDR AifHdr;
	uint32_t ImageType;
	WAKE_UP_PARMS WakeUpParms;
	WAKE_UP_PARMS AbsWakeUpParms;
	uint32_t MaxRbusSramSize;
	uint32_t MaxIbusSramSize;
	int32_t AbsChangeParams = 0;
	int32_t DwcFile = FALSE;
	uint32_t rval = 0;
	emlxs_fw_image_t fw_image;
	uint32_t i;

#ifdef EMLXS_I386
	caddr_t local_buffer;
	uint32_t *bptr1;
	uint32_t *bptr2;
#endif	/* EMLXS_I386 */

	if (buffer == NULL || len == 0) {
		return (EMLXS_IMAGE_BAD);
	}
#ifdef EMLXS_I386
	/* We need to swap the image buffer before we start */

	/*
	 * Use KM_SLEEP to allocate a temporary buffer
	 */
	local_buffer = (caddr_t)kmem_zalloc(len, KM_SLEEP);

	if (local_buffer == NULL) {
		return (FC_NOMEM);
	}
	/* Perform a 32 bit swap of the image */
	bptr1 = (uint32_t *)local_buffer;
	bptr2 = (uint32_t *)buffer;
	for (i = 0; i < (len / 4); i++) {
		*bptr1 = SWAP_DATA32(*bptr2);
		bptr1++;
		bptr2++;
	}

	/* Replace the original buffer */
	buffer = local_buffer;
#endif	/* EMLXS_I386 */

	bzero(&fw_image, sizeof (emlxs_fw_image_t));
	for (i = 0; i < MAX_PROG_TYPES; i++) {
		(void) strcpy(fw_image.prog[i].label, "none");
	}

	/* Validate image */
	if ((rval = emlxs_validate_image(hba, buffer, len, &fw_image))) {
		goto done;
	}
	/* Get image type */
	Uptr = (uint32_t *)buffer;
	ImageType = *Uptr;

	/*
	 * Pegasus and beyond FW download is done differently for absolute
	 * download.
	 */

	/* Check for absolute image */
	if ((ImageType == NOP_IMAGE_TYPE) &&
	    !(hba->model_info.chip &
	    (EMLXS_DRAGONFLY_CHIP | EMLXS_CENTAUR_CHIP))) {
		/*
		 * Because 2Mb flash download file format is different from
		 * 512k, it needs to be handled differently
		 */
		if (rval = emlxs_start_abs_download_2mb(hba, buffer, len,
		    offline, &fw_image)) {
			goto done;
		}
		/* Offline already handled */
		offline = 0;

		goto SLI_DOWNLOAD_EXIT;
	}
	/* Pre-pegasus adapters only */

	/* Check for absolute image */
	else if (ImageType == NOP_IMAGE_TYPE) {
		bcopy(buffer, &AifHdr, sizeof (AIF_HDR));
		bzero((void *)&ImageHdr, sizeof (IMAGE_HDR));

		if (AifHdr.ImageBase && (AifHdr.ImageBase == 0x20000)) {
			DwcFile = TRUE;
		}
		AbsChangeParams = emlxs_build_parms(buffer, &AbsWakeUpParms,
		    len, &AifHdr, DwcFile);
	} else {	/* (ImageType != NOP_IMAGE_TYPE) Relative image */
		bzero((void *)&AifHdr, sizeof (AIF_HDR));
		bcopy(buffer, &ImageHdr, sizeof (IMAGE_HDR));
	}

	/*
	 * Everything checks out, now to just do it
	 */

	if (offline) {
		if (emlxs_offline(hba) != FC_SUCCESS) {
			offline = 0;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
			    "Unable to take adapter offline.");

			rval = EMLXS_OFFLINE_FAILED;

			goto SLI_DOWNLOAD_EXIT;
		}
		if (emlxs_hba_reset(hba, 1, 1) != FC_SUCCESS) {
			offline = 0;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
			    "Unable to restart adapter.");

			rval = EMLXS_OFFLINE_FAILED;

			goto SLI_DOWNLOAD_EXIT;
		}
	}
	if (ImageHdr.Id.Type == SBUS_FCODE) {
		/* Erase Flash */
		if (emlxs_erase_fcode_flash(hba)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
			    "Unable to erase flash.");

			rval = EMLXS_IMAGE_FAILED;

			goto SLI_DOWNLOAD_EXIT;
		}
		/* Write FCODE */
		if (emlxs_write_fcode_flash(hba, &ImageHdr, buffer)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
			    "Unable to write flash.");

			rval = EMLXS_IMAGE_FAILED;

			goto SLI_DOWNLOAD_EXIT;
		}
	} else {	/* !SBUS_FCODE */

		if (emlxs_read_wakeup_parms(hba, &WakeUpParms, 1)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
			    "Unable to get parameters.");

			rval = EMLXS_IMAGE_FAILED;

			goto SLI_DOWNLOAD_EXIT;
		}
		if (emlxs_get_max_sram(hba, &MaxRbusSramSize,
		    &MaxIbusSramSize)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
			    "Unable to get RAM size.");

			rval = EMLXS_IMAGE_FAILED;

			goto SLI_DOWNLOAD_EXIT;
		}
		if (ImageType == NOP_IMAGE_TYPE) {
			if (emlxs_start_abs_download(hba, &AifHdr, buffer,
			    &WakeUpParms, MaxRbusSramSize, MaxIbusSramSize,
			    (AbsChangeParams) ? &AbsWakeUpParms : NULL,
			    DwcFile)) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_download_failed_msg,
				    "Failed to program flash.");

				rval = EMLXS_IMAGE_FAILED;

				goto SLI_DOWNLOAD_EXIT;
			}
		} else {

			if (emlxs_start_rel_download(hba, &ImageHdr, buffer,
			    &WakeUpParms, MaxRbusSramSize, MaxIbusSramSize)) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_download_failed_msg,
				    "Failed to program flash.");

				rval = EMLXS_IMAGE_FAILED;

				goto SLI_DOWNLOAD_EXIT;
			}
		}

	}	/* !SBUS_FCODE */


SLI_DOWNLOAD_EXIT:

	if (offline) {
		(void) emlxs_online(hba);
	}
	if (rval == 0) {


		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_complete_msg,
		    "Status good.");
	}
done:

#ifdef EMLXS_I386
	/* Free the local buffer */
	kmem_free(local_buffer, len);
#endif	/* EMLXS_I386 */

	return (rval);

} /* emlxs_fw_download */



extern int32_t
emlxs_cfl_download(emlxs_hba_t *hba, uint32_t region, caddr_t buffer,
    uint32_t len)
{
	emlxs_port_t *port = &PPORT;
	MAILBOXQ *mbox = NULL;
	MAILBOX *mb;
	uint32_t rval = 0;
	uint32_t region_id;
	uint32_t id;

#ifndef EMLXS_I386
	caddr_t local_buffer;
	uint32_t *bptr1;
	uint32_t *bptr2;
	uint32_t i;
#endif	/* !EMLXS_I386 */

	if (buffer == NULL || len == 0) {
		return (EMLXS_IMAGE_BAD);
	}
#ifndef EMLXS_I386
	/* We need to swap the image buffer before we start */

	/*
	 * Use KM_SLEEP to allocate a temporary buffer
	 */
	local_buffer = (caddr_t)kmem_zalloc(len, KM_SLEEP);

	if (local_buffer == NULL) {
		return (FC_NOMEM);
	}
	/* Perform a 32 bit swap of the image */
	bptr1 = (uint32_t *)local_buffer;
	bptr2 = (uint32_t *)buffer;

	for (i = 0; i < (len / 4); i++) {
		*bptr1 = DATA32_SWAP(*bptr2);
		bptr1++;
		bptr2++;
	}

	/* Replace the original buffer */
	buffer = local_buffer;

#endif	/* !EMLXS_I386 */

	if (len > 128) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_bad_msg,
		    "Invalid image length: 0x%x > 128",
		    len);

		return (EMLXS_IMAGE_BAD);
	}
	/* Check the region number */
	if ((region > 2) && (region != 0xff)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_bad_msg,
		    "Invalid region id: 0x%x",
		    region);

		return (EMLXS_IMAGE_BAD);

	}
	/* Check the image vendor id */
	id = *(int32_t *)buffer;
	if ((id & 0xffff) != 0x10df) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_bad_msg,
		    "Invalid image id: 0x%x",
		    id);

		return (EMLXS_IMAGE_BAD);
	}
	if ((mbox = (MAILBOXQ *)
	    kmem_zalloc(sizeof (MAILBOXQ), KM_NOSLEEP)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to allocate mailbox buffer.");

		rval = 1;

		goto done;
	}
	mb = (MAILBOX *)mbox;

	/*
	 * Everything checks out, now to just do it
	 */
	if (emlxs_offline(hba) != FC_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to take HBA offline.");

		rval = EMLXS_OFFLINE_FAILED;

		goto done;
	}
	if (emlxs_hba_reset(hba, 1, 1) != FC_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to restart adapter.");

		rval = EMLXS_OFFLINE_FAILED;

		goto done;
	}
	/* Check if default region is requested */
	if (region == 0xff) {
		/*
		 * Sun-branded Helios and Zypher have different default PCI
		 * region
		 */
		if ((hba->model_info.flags & EMLXS_SUN_BRANDED) &&
		    (hba->model_info.chip &
		    (EMLXS_HELIOS_CHIP | EMLXS_ZEPHYR_CHIP))) {
			region = 2;
		} else {
			region = 0;
		}
	}
	/* Set region id based on PCI region requested */
	region_id = DEF_PCI_CFG_REGION_ID + region;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_msg,
	    "PCI configuration: PCI%d region=%d id=0x%x size=%d",
	    region, region_id, id, len);

	/* Copy the data buffer to SLIM */
	WRITE_SLIM_COPY(hba, (uint32_t *)buffer,
	    (volatile uint32_t *)
	    ((volatile char *)hba->slim_addr + sizeof (MAILBOX)),
	    (len / sizeof (uint32_t)));

	emlxs_format_update_pci_cfg(hba, mb, region_id, len);

	if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to update PCI configuration: "
		    "Mailbox cmd=%x status=%x info=%d",
		    mb->mbxCommand, mb->mbxStatus,
		    mb->un.varUpdateCfg.rsp_info);

		rval = 1;
	}
	(void) emlxs_online(hba);

	if (rval == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_complete_msg,
		    "Status good.");
	}
done:

	if (mbox) {
		kmem_free(mbox, sizeof (MAILBOXQ));
	}
#ifndef EMLXS_I386
	/* Free the local buffer */
	kmem_free(local_buffer, len);
#endif	/* !EMLXS_I386 */

	return (rval);

} /* emlxs_cfl_download */



static uint32_t
emlxs_valid_cksum(uint32_t *StartAddr, uint32_t *EndAddr)
{
	uint32_t Temp;
	uint32_t CkSum;

	EndAddr++;
	CkSum = SLI_CKSUM_SEED;

	CkSum = (CkSum >> 1) | (CkSum << 31);
	while (StartAddr != EndAddr) {
		CkSum = (CkSum << 1) | (CkSum >> 31);
		Temp = *StartAddr;

		CkSum ^= Temp;
		StartAddr++;
	}

	return (CkSum << 1) | (CkSum >> 31);

} /* emlxs_valid_cksum() */


static void
emlxs_disp_aif_header(emlxs_hba_t *hba, PAIF_HDR AifHdr)
{
	emlxs_port_t *port = &PPORT;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "AIF Header: ");
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "AIF Header: compress_br = 0x%x", AifHdr->CompressBr);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "AIF Header: reloc_br = 0x%x", AifHdr->RelocBr);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "AIF Header: zinit_br = 0x%x", AifHdr->ZinitBr);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "AIF Header: entry_br = 0x%x", AifHdr->EntryBr);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "AIF Header: area_id = 0x%x", AifHdr->Area_ID);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "AIF Header: rosize = 0x%x", AifHdr->RoSize);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "AIF Header: dbgsize = 0x%x", AifHdr->DbgSize);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "AIF Header: zinitsize = 0x%x", AifHdr->ZinitSize);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "AIF Header: dbgtype = 0x%x", AifHdr->DbgType);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "AIF Header: imagebase = 0x%x", AifHdr->ImageBase);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "AIF Header: area_size = 0x%x", AifHdr->Area_Size);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "AIF Header: address_mode = 0x%x", AifHdr->AddressMode);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "AIF Header: database = 0x%x", AifHdr->DataBase);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "AIF Header: aversion = 0x%x", AifHdr->AVersion);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "AIF Header: spare2 = 0x%x", AifHdr->Spare2);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "AIF Header: debug_swi = 0x%x", AifHdr->DebugSwi);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "AIF Header: zinitcode[0] = 0x%x", AifHdr->ZinitCode[0]);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "AIF Header: zinitcode[1] = 0x%x", AifHdr->ZinitCode[1]);

} /* emlxs_disp_aif_header() */



static void
emlxs_dump_image_header(emlxs_hba_t *hba, PIMAGE_HDR image)
{
	emlxs_port_t *port = &PPORT;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "Img Header: ");
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "Img Header: BlockSize = 0x%x", image->BlockSize);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "Img Header: PROG_ID Type = 0x%x", image->Id.Type);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "Img Header: PROG_ID Id = 0x%x", image->Id.Id);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "Img Header: PROG_ID Ver = 0x%x", image->Id.Ver);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "Img Header: PROG_ID Rev = 0x%x", image->Id.Rev);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "Img Header: PROG_ID revcomp = 0x%x", image->Id.un.revcomp);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "Img Header: Flags = 0x%x", image->Flags);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "Img Header: EntryAdr = 0x%x", image->EntryAdr);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "Img Header: InitAdr = 0x%x", image->InitAdr);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "Img Header: ExitAdr = 0x%x", image->ExitAdr);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "Img Header: ImageBase = 0x%x", image->ImageBase);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "Img Header: ImageSize = 0x%x", image->ImageSize);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "Img Header: ZinitSize = 0x%x", image->ZinitSize);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "Img Header: RelocSize = 0x%x", image->RelocSize);
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_detail_msg,
	    "Img Header: HdrCks = 0x%x", image->HdrCks);

} /* emlxs_dump_image_header() */


static void
emlxs_format_dump(MAILBOX *mb, uint32_t Type, uint32_t RegionId,
    uint32_t WordCount, uint32_t BaseAddr)
{
	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_DUMP_MEMORY;
	mb->un.varDmp.type = Type;
	mb->un.varDmp.region_id = RegionId;
	mb->un.varDmp.word_cnt = WordCount;
	mb->un.varDmp.base_adr = BaseAddr;
	mb->mbxOwner = OWN_HOST;

	return;

} /* emlxs_format_dump() */


/* ARGSUSED */
static uint32_t
emlxs_start_abs_download(emlxs_hba_t *hba, PAIF_HDR AifHdr, caddr_t Buffer,
    PWAKE_UP_PARMS WakeUpParms, uint32_t MaxRbusSramSize,
    uint32_t MaxIbusSramSize, PWAKE_UP_PARMS AbsWakeUpParms, int32_t DwcFile)
{
	emlxs_port_t *port = &PPORT;
	uint32_t DlByteCount = AifHdr->RoSize + AifHdr->RwSize;
	IMAGE_HDR ImageHdr;
	uint32_t *Src;
	uint32_t *Dst;
	caddr_t DataBuffer = NULL;
	MAILBOXQ *mbox;
	MAILBOX *mb;
	uint32_t rval = 1;
	uint32_t SegSize = DL_SLIM_SEG_BYTE_COUNT;
	uint32_t DlToAddr = AifHdr->ImageBase;
	uint32_t DlCount;
	uint32_t i;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_msg,
	    "Performing absolute download...");

	if ((DataBuffer = (caddr_t)
	    kmem_zalloc(DL_SLIM_SEG_BYTE_COUNT, KM_NOSLEEP)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to allocate data buffer.");

		return (rval);
	}
	if ((mbox = (MAILBOXQ *)
	    kmem_zalloc(sizeof (MAILBOXQ), KM_NOSLEEP)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to allocate mailbox buffer.");

		kmem_free(DataBuffer, DL_SLIM_SEG_BYTE_COUNT);

		return (rval);
	}
	mb = (MAILBOX *)mbox;

	Buffer += sizeof (AIF_HDR);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_msg,
	    "Erasing flash...");

	if (DwcFile) {
		emlxs_format_prog_flash(mb, 0x20000, 0x50000, ERASE_FLASH,
		    0, 0, 0, NULL);
	} else {
		emlxs_format_prog_flash(mb, DlToAddr, DlByteCount, ERASE_FLASH,
		    0, 0, 0, NULL);
	}

	if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to erase Flash: Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		rval = 1;

		goto EXIT_ABS_DOWNLOAD;
	}
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_msg, "Programming flash...");

	while (DlByteCount) {

		if (DlByteCount > SegSize) {
			DlCount = SegSize;
		} else {
			DlCount = DlByteCount;
		}
		DlByteCount -= DlCount;

		Dst = (uint32_t *)DataBuffer;
		Src = (uint32_t *)Buffer;

		for (i = 0; i < (DlCount / 4); i++) {
			*Dst = *Src;
			Dst++;
			Src++;
		}

		WRITE_SLIM_COPY(hba, (uint32_t *)DataBuffer,
		    (volatile uint32_t *)
		    ((volatile char *)hba->slim_addr + sizeof (MAILBOX)),
		    (DlCount / sizeof (uint32_t)));

		emlxs_format_prog_flash(mb, DlToAddr, DlCount, PROGRAM_FLASH,
		    (DlByteCount) ? 0 : 1, 0, DlCount, NULL);

		if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
			    "Unable to program Flash: Mailbox cmd=%x status=%x",
			    mb->mbxCommand, mb->mbxStatus);

			rval = 1;

			goto EXIT_ABS_DOWNLOAD;
		}
		Buffer += DlCount;
		DlToAddr += DlCount;
	}

	bzero((caddr_t)&ImageHdr, sizeof (IMAGE_HDR));
	ImageHdr.Id.Type = FUNC_FIRMWARE;

	switch (MaxRbusSramSize) {
	case REDUCED_RBUS_SRAM_CFG:
		ImageHdr.Id.Id = REDUCED_SRAM_CFG_PROG_ID;
		break;
	case FULL_RBUS_SRAM_CFG:
		ImageHdr.Id.Id = FULL_SRAM_CFG_PROG_ID;
		break;
	default:
		ImageHdr.Id.Id = OTHER_SRAM_CFG_PROG_ID;
		break;
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_msg, "Updating params...");

	if (AbsWakeUpParms) {
		rval = emlxs_update_wakeup_parms(hba, AbsWakeUpParms,
		    WakeUpParms);
	} else {
		rval = emlxs_update_boot_wakeup_parms(hba, WakeUpParms,
		    &ImageHdr.Id, 1);
	}

EXIT_ABS_DOWNLOAD:
	if (DataBuffer) {
		kmem_free(DataBuffer, DL_SLIM_SEG_BYTE_COUNT);
	}
	if (mbox) {
		kmem_free(mbox, sizeof (MAILBOXQ));
	}
	return (rval);

} /* emlxs_start_abs_download() */


/* ARGSUSED */
static void
emlxs_format_prog_flash(MAILBOX *mb, uint32_t Base, uint32_t DlByteCount,
    uint32_t Function, uint32_t Complete, uint32_t BdeAddress,
    uint32_t BdeSize, PROG_ID *ProgId)
{

	bzero((void *) mb, MAILBOX_CMD_BSIZE);

	if (ProgId)
		mb->mbxCommand = MBX_DOWN_LOAD;
	else
		mb->mbxCommand = MBX_LOAD_SM;

	mb->un.varLdSM.load_cmplt = Complete;
	mb->un.varLdSM.method = DL_FROM_SLIM;
	mb->un.varLdSM.update_flash = 1;
	mb->un.varLdSM.erase_or_prog = Function;
	mb->un.varLdSM.dl_to_adr = Base;
	mb->un.varLdSM.dl_len = DlByteCount;

	if (BdeSize) {
		mb->un.varLdSM.un.dl_from_slim_offset = DL_FROM_SLIM_OFFSET;
	} else if (ProgId) {
		mb->un.varLdSM.un.prog_id = *ProgId;
	} else {
		mb->un.varLdSM.un.dl_from_slim_offset = 0;
	}

	mb->mbxOwner = OWN_HOST;

} /* emlxs_format_prog_flash() */


static void
emlxs_format_update_parms(MAILBOX *mb, PWAKE_UP_PARMS WakeUpParms)
{
	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_UPDATE_CFG;
	mb->un.varUpdateCfg.req_type = UPDATE_DATA;
	mb->un.varUpdateCfg.region_id = WAKE_UP_PARMS_REGION_ID;
	mb->un.varUpdateCfg.entry_len = sizeof (WAKE_UP_PARMS);
	mb->un.varUpdateCfg.byte_len = sizeof (WAKE_UP_PARMS);

	bcopy((caddr_t)WakeUpParms, (caddr_t)&(mb->un.varUpdateCfg.cfg_data),
	    sizeof (WAKE_UP_PARMS));

} /* emlxs_format_update_parms () */


/* ARGSUSED */
static void
emlxs_format_update_pci_cfg(emlxs_hba_t *hba, MAILBOX *mb,
    uint32_t region_id, uint32_t size)
{

	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MBX_UPDATE_CFG;
	mb->un.varUpdateCfg.Vbit = 1;
	mb->un.varUpdateCfg.Obit = 1;
	mb->un.varUpdateCfg.cfg_data = DL_FROM_SLIM_OFFSET;
	mb->un.varUpdateCfg.req_type = UPDATE_DATA;
	mb->un.varUpdateCfg.region_id = region_id;
	mb->un.varUpdateCfg.entry_len = size;
	mb->un.varUpdateCfg.byte_len = size;


} /* emlxs_format_update_pci_cfg() */



static uint32_t
emlxs_update_boot_wakeup_parms(emlxs_hba_t *hba, PWAKE_UP_PARMS WakeUpParms,
    PROG_ID * prog_id, uint32_t proc_erom)
{
	emlxs_port_t *port = &PPORT;
	MAILBOX *mb;
	MAILBOXQ *mbox;
	uint32_t rval = 0;

	if ((mbox = (MAILBOXQ *)
	    kmem_zalloc(sizeof (MAILBOXQ), KM_NOSLEEP)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to allocate mailbox buffer.");

		return (1);
	}
	mb = (MAILBOX *) mbox;

	if (proc_erom &&
	    !(hba->model_info.chip &
	    (EMLXS_DRAGONFLY_CHIP | EMLXS_CENTAUR_CHIP))) {
		WakeUpParms->u1.EROM_prog_id = *prog_id;
		(void) emlxs_update_exp_rom(hba, WakeUpParms);
	}
	WakeUpParms->u0.boot_bios_id = *prog_id;

	emlxs_format_update_parms(mb, WakeUpParms);

	if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to update boot wakeup parms: "
		    "Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		rval = 1;
	}
	if (mbox) {
		kmem_free(mbox, sizeof (MAILBOXQ));
	}
	return (rval);

} /* emlxs_update_boot_wakeup_parms() */



static uint32_t
emlxs_update_ff_wakeup_parms(emlxs_hba_t *hba, PWAKE_UP_PARMS WakeUpParms,
    PROG_ID *prog_id)
{
	emlxs_port_t *port = &PPORT;
	uint32_t rval = 0;
	MAILBOXQ *mbox;
	MAILBOX *mb;

	if ((mbox = (MAILBOXQ *)
	    kmem_zalloc(sizeof (MAILBOXQ), KM_NOSLEEP)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to allocate mailbox buffer.");

		return (1);
	}
	mb = (MAILBOX *)mbox;

	WakeUpParms->prog_id = *prog_id;

	emlxs_format_update_parms(mb, WakeUpParms);

	if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to update wakeup parameters: "
		    "Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		rval = 1;
	}
	if (mbox) {
		kmem_free(mbox, sizeof (MAILBOXQ));
	}
	return (rval);

} /* emlxs_update_ff_wakeup_parms() */


static uint32_t
emlxs_update_sli1_wakeup_parms(emlxs_hba_t *hba, PWAKE_UP_PARMS WakeUpParms,
    PROG_ID *prog_id)
{
	emlxs_port_t *port = &PPORT;
	uint32_t rval = 0;
	MAILBOXQ *mbox;
	MAILBOX *mb;

	if ((mbox = (MAILBOXQ *)
	    kmem_zalloc(sizeof (MAILBOXQ), KM_NOSLEEP)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to allocate mailbox buffer.");

		return (1);
	}
	mb = (MAILBOX *)mbox;

	WakeUpParms->sli1_prog_id = *prog_id;

	emlxs_format_update_parms(mb, WakeUpParms);

	if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to update wakeup parameters. "
		    "Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		rval = 1;
	}
	if (mbox) {
		kmem_free(mbox, sizeof (MAILBOXQ));
	}
	return (rval);

} /* emlxs_update_sli1_wakeup_parms() */


static uint32_t
emlxs_update_sli2_wakeup_parms(emlxs_hba_t *hba, PWAKE_UP_PARMS WakeUpParms,
    PROG_ID *prog_id)
{
	emlxs_port_t *port = &PPORT;
	uint32_t rval = 0;
	MAILBOXQ *mbox;
	MAILBOX *mb;

	if ((mbox = (MAILBOXQ *)
	    kmem_zalloc(sizeof (MAILBOXQ), KM_NOSLEEP)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to allocate mailbox buffer.");

		return (1);
	}
	mb = (MAILBOX *)mbox;

	WakeUpParms->sli2_prog_id = *prog_id;

	emlxs_format_update_parms(mb, WakeUpParms);

	if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to update wakeup parameters. "
		    "Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		rval = 1;
	}
	if (mbox) {
		kmem_free(mbox, sizeof (MAILBOXQ));
	}
	return (rval);

} /* emlxs_update_sli2_wakeup_parms() */


static uint32_t
emlxs_update_sli3_wakeup_parms(emlxs_hba_t *hba, PWAKE_UP_PARMS WakeUpParms,
    PROG_ID *prog_id)
{
	emlxs_port_t *port = &PPORT;
	uint32_t rval = 0;
	MAILBOXQ *mbox;
	MAILBOX *mb;

	if ((mbox = (MAILBOXQ *)
	    kmem_zalloc(sizeof (MAILBOXQ), KM_NOSLEEP)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to allocate mailbox buffer.");

		return (1);
	}
	mb = (MAILBOX *)mbox;

	WakeUpParms->sli3_prog_id = *prog_id;

	emlxs_format_update_parms(mb, WakeUpParms);

	if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to update wakeup parameters. "
		    "Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		rval = 1;
	}
	if (mbox) {
		kmem_free(mbox, sizeof (MAILBOXQ));
	}
	return (rval);

} /* emlxs_update_sli3_wakeup_parms() */


static uint32_t
emlxs_update_sli4_wakeup_parms(emlxs_hba_t *hba, PWAKE_UP_PARMS WakeUpParms,
    PROG_ID *prog_id)
{
	emlxs_port_t *port = &PPORT;
	uint32_t rval = 0;
	MAILBOXQ *mbox;
	MAILBOX *mb;

	if ((mbox = (MAILBOXQ *)
	    kmem_zalloc(sizeof (MAILBOXQ), KM_NOSLEEP)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to allocate mailbox buffer.");

		return (1);
	}
	mb = (MAILBOX *)mbox;

	WakeUpParms->sli4_prog_id = *prog_id;

	emlxs_format_update_parms(mb, WakeUpParms);

	if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to update wakeup parameters. "
		    "Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		rval = 1;
	}
	if (mbox) {
		kmem_free(mbox, sizeof (MAILBOXQ));
	}
	return (rval);

} /* emlxs_update_sli4_wakeup_parms() */


/* ARGSUSED */
static uint32_t
emlxs_start_rel_download(emlxs_hba_t *hba, PIMAGE_HDR ImageHdr,
    caddr_t Buffer, PWAKE_UP_PARMS WakeUpParms,
    uint32_t MaxRbusSramSize, uint32_t MaxIbusSramSize)
{
	emlxs_port_t *port = &PPORT;
	MAILBOXQ *mbox;
	MAILBOX *mb;
	uint32_t *Src;
	uint32_t *Dst;
	caddr_t DataBuffer = NULL;
	uint32_t rval = 1;
	uint32_t DlByteCount = ImageHdr->BlockSize;
	uint32_t SegSize = DL_SLIM_SEG_BYTE_COUNT;
	uint32_t DlCount;
	uint32_t i;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_msg,
	    "Performing relative download...");

	if ((DataBuffer = (caddr_t)
	    kmem_zalloc(DL_SLIM_SEG_BYTE_COUNT, KM_NOSLEEP)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to allocate data buffer.");

		return (rval);
	}
	if ((mbox = (MAILBOXQ *)
	    kmem_zalloc(sizeof (MAILBOXQ), KM_NOSLEEP)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to allocate mailbox buffer.");

		kmem_free(DataBuffer, DL_SLIM_SEG_BYTE_COUNT);

		return (rval);
	}
	if (ImageHdr->Id.Type == FUNC_FIRMWARE) {
		switch (MaxRbusSramSize) {
		case REDUCED_RBUS_SRAM_CFG:
			if (ImageHdr->Id.Id != REDUCED_SRAM_CFG_PROG_ID) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_bad_msg,
				    "Invalid header id.");

				return (1);
			}
			break;
		case FULL_RBUS_SRAM_CFG:
			if (ImageHdr->Id.Id != FULL_SRAM_CFG_PROG_ID) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_bad_msg,
				    "Invalid header id.");

				return (1);
			}
			break;
		default:
			if (ImageHdr->Id.Id != OTHER_SRAM_CFG_PROG_ID) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_bad_msg,
				    "Invalid header id.");

				return (1);
			}
			break;
		}
	}
	mb = (MAILBOX *)mbox;

	emlxs_format_prog_flash(mb, 0, DlByteCount, ERASE_FLASH,
	    0, 0, 0, &ImageHdr->Id);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_msg, "Erasing flash...");

	if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to erase flash. Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		rval = 1;

		goto EXIT_REL_DOWNLOAD;
	}
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_msg, "Programming flash...");

	while (DlByteCount) {
		if (DlByteCount > SegSize) {
			DlCount = SegSize;
		} else {
			DlCount = DlByteCount;
		}
		DlByteCount -= DlCount;

		Dst = (uint32_t *)DataBuffer;
		Src = (uint32_t *)Buffer;

		for (i = 0; i < (DlCount / 4); i++) {
			*Dst = *Src;
			Dst++;
			Src++;
		}

		WRITE_SLIM_COPY(hba, (uint32_t *)DataBuffer,
		    (volatile uint32_t *)
		    ((volatile char *)hba->slim_addr + sizeof (MAILBOX)),
		    (DlCount / sizeof (uint32_t)));

		emlxs_format_prog_flash(mb, 0, DlCount, PROGRAM_FLASH,
		    (DlByteCount) ? 0 : 1, 0, DlCount, &ImageHdr->Id);

		if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
			    "Unable to program flash. Mailbox cmd=%x status=%x",
			    mb->mbxCommand, mb->mbxStatus);

			rval = 1;

			goto EXIT_REL_DOWNLOAD;
		}
		Buffer += DlCount;
	}

	switch (ImageHdr->Id.Type) {
	case TEST_PROGRAM:
		rval = 0;
		break;

	case FUNC_FIRMWARE:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_msg,
		    "FF: Updating parms...");
		rval = emlxs_update_ff_wakeup_parms(hba, WakeUpParms,
		    &ImageHdr->Id);
		break;

	case BOOT_BIOS:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_msg,
		    "BOOT: Updating parms...");
		rval = emlxs_update_boot_wakeup_parms(hba, WakeUpParms,
		    &ImageHdr->Id, 1);
		break;

	case SLI1_OVERLAY:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_msg,
		    "SLI1: Updating parms...");
		rval = emlxs_update_sli1_wakeup_parms(hba, WakeUpParms,
		    &ImageHdr->Id);
		break;

	case SLI2_OVERLAY:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_msg,
		    "SLI2: Updating parms...");
		rval = emlxs_update_sli2_wakeup_parms(hba, WakeUpParms,
		    &ImageHdr->Id);
		break;

	case SLI3_OVERLAY:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_msg,
		    "SLI3: Updating parms...");
		rval = emlxs_update_sli3_wakeup_parms(hba, WakeUpParms,
		    &ImageHdr->Id);
		break;

	case SLI4_OVERLAY:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_msg,
		    "SLI4: Updating parms...");
		rval = emlxs_update_sli4_wakeup_parms(hba, WakeUpParms,
		    &ImageHdr->Id);
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_incompat_msg,
		    "Image type not supported. Type=%x",
		    ImageHdr->Id.Type);

		break;
	}

EXIT_REL_DOWNLOAD:
	if (DataBuffer) {
		kmem_free(DataBuffer, DL_SLIM_SEG_BYTE_COUNT);
	}
	if (mbox) {
		kmem_free(mbox, sizeof (MAILBOXQ));
	}
	return (rval);

} /* emlxs_start_rel_download() */


#define	FLASH_POLLING_BIT	0x80
#define	FLASH_ERROR_BIT		0x20

typedef struct _flash_t {
	uint32_t offset;
	uint8_t val;
} flash_t;



static uint32_t
emlxs_write_fcode_flash(emlxs_hba_t *hba, PIMAGE_HDR ImageHdr, caddr_t Buffer)
{
	emlxs_port_t *port = &PPORT;
	uint8_t bb;
	uint8_t cc;
	uint8_t *src;
	uint32_t DlByteCount = ImageHdr->BlockSize;
	uint32_t i;
	uint32_t j;
	uint32_t k;

	flash_t wr[3] =
	{
		{0x555, 0xaa},
		{0x2aa, 0x55},
		{0x555, 0xa0}
	};

	/* Load Fcode */
	src = (uint8_t *)Buffer + sizeof (IMAGE_HDR);
	for (i = 0; i < DlByteCount; i++) {
		for (k = 0; k < 3; k++) {
			SBUS_WRITE_FLASH_COPY(hba, wr[k].offset, wr[k].val);
		}

		/* Reverse Endian word alignment */
		j = (i & 3) ^ 3;

		bb = src[j];

		if (j == 0) {
			src += 4;
		}
		SBUS_WRITE_FLASH_COPY(hba, i, bb);

		/* check for complete */
		for (;;) {
			DELAYUS(20);

			cc = SBUS_READ_FLASH_COPY(hba, i);

			/* If data matches then continue */
			if (cc == bb) {
				break;
			}
			/*
			 * Polling bit will be inverse final value while
			 * active
			 */
			if ((cc ^ bb) & FLASH_POLLING_BIT) {
				/* Still busy */

				/* Check for error bit */
				if (cc & FLASH_ERROR_BIT) {
					/* Read data one more time */
					cc = SBUS_READ_FLASH_COPY(hba, i);

					/* Check if data matches */
					if (cc == bb) {
						break;
					}
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_download_failed_msg,
					    "FCode write error: offset:%x "
					    "wrote:%x read:%x\n",
					    i, bb, cc);

					return (1);
				}
			}
		}
	}

	/* Load Header */
	src = (uint8_t *)ImageHdr;

	for (i = (0xFFFF - sizeof (IMAGE_HDR)); i < 0xFFFF; i++) {
		for (k = 0; k < 3; k++) {
			SBUS_WRITE_FLASH_COPY(hba, wr[k].offset, wr[k].val);
		}

		/* Reverse Endian word alignment */
		j = (i & 3) ^ 3;

		bb = src[j];

		if (j == 0) {
			src += 4;
		}
		SBUS_WRITE_FLASH_COPY(hba, i, bb);

		/* check for complete */
		for (;;) {
			DELAYUS(20);

			cc = SBUS_READ_FLASH_COPY(hba, i);

			/* If data matches then continue */
			if (cc == bb) {
				break;
			}
			/*
			 * Polling bit will be inverse final value while
			 * active
			 */
			if ((cc ^ bb) & FLASH_POLLING_BIT) {
				/* Still busy */

				/* Check for error bit */
				if (cc & FLASH_ERROR_BIT) {
					/* Read data one more time */
					cc = SBUS_READ_FLASH_COPY(hba, i);

					/* Check if data matches */
					if (cc == bb) {
						break;
					}
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_download_failed_msg,
					    "FCode write error: offset:%x "
					    "wrote:%x read:%x\n",
					    i, bb, cc);

					return (1);
				}
			}
		}
	}

	return (0);

} /* emlxs_write_fcode_flash() */



static uint32_t
emlxs_erase_fcode_flash(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	int32_t i, j;
	uint8_t cc;
	uint32_t offset;

	flash_t ef[6] =
	{
		{0x555, 0xaa},
		{0x2aa, 0x55},
		{0x555, 0x80},
		{0x555, 0xaa},
		{0x2aa, 0x55},
		{0x555, 0x10}
	};

	/* Auto select */
	flash_t as[3] =
	{
		{0x555, 0xaa},
		{0x2aa, 0x55},
		{0x555, 0x90}
	};


	/* Check Manufacturers Code */
	for (i = 0; i < 3; i++) {
		SBUS_WRITE_FLASH_COPY(hba, as[i].offset, as[i].val);
	}

	cc = SBUS_READ_FLASH_COPY(hba, 0);

	/* Check Device Code */
	for (i = 0; i < 3; i++) {
		SBUS_WRITE_FLASH_COPY(hba, as[i].offset, as[i].val);
	}

	cc = SBUS_READ_FLASH_COPY(hba, 1);


	/* Check block protections (up to 4 16K blocks = 64K) */
	for (j = 0; j < 4; j++) {
		for (i = 0; i < 3; i++) {
			SBUS_WRITE_FLASH_COPY(hba, as[i].offset, as[i].val);
		}

		offset = (j << 14) | 0x2;

		cc = SBUS_READ_FLASH_COPY(hba, offset);

		if (cc == 0x01) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
			    "Block %d is protected and can't be erased.", j);
		}
	}

	/* Write erase flash sequence */
	for (i = 0; i < 6; i++) {
		SBUS_WRITE_FLASH_COPY(hba, ef[i].offset, ef[i].val);
	}

	/* check for complete */
	for (;;) {
		/* Delay 3 seconds */
		DELAYMS(3000);

		cc = SBUS_READ_FLASH_COPY(hba, 0);


		/* If data matches then continue; */
		if (cc == 0xff) {
			break;
		}
		/* Polling bit will be inverse final value while active */
		if ((cc ^ 0xff) & FLASH_POLLING_BIT) {
			/* Still busy */

			/* Check for error bit */
			if (cc & FLASH_ERROR_BIT) {
				/* Read data one more time */
				cc = SBUS_READ_FLASH_COPY(hba, 0);

				/* Check if data matches */
				if (cc == 0xff) {
					break;
				}
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_download_failed_msg,
				    "FCode write error: "
				    "offset:%x wrote:%x read:%x\n",
				    i, 0xff, cc);

				return (1);
			}
		}
	}

	return (0);

} /* emlxs_erase_fcode_flash() */


extern uint32_t
emlxs_get_load_list(emlxs_hba_t *hba, PROG_ID *load_list)
{
	emlxs_port_t *port = &PPORT;
	LOAD_ENTRY *LoadEntry;
	LOAD_LIST *LoadList = NULL;
	uint32_t i;
	uint32_t rval = 0;

	bzero(load_list, (sizeof (PROG_ID) * MAX_LOAD_ENTRY));

	if ((LoadList = (LOAD_LIST *)
	    kmem_zalloc(sizeof (LOAD_LIST), KM_NOSLEEP)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_msg,
		    "Unable to allocate LOADLIST buffer.");

		rval = 1;
		goto done;
	}
	if (emlxs_read_load_list(hba, LoadList)) {
		rval = 1;
		goto done;
	}
	for (i = 0; i < LoadList->entry_cnt; i++) {
		LoadEntry = &LoadList->load_entry[i];
		if ((LoadEntry->un.wd[0] != 0) &&
		    (LoadEntry->un.wd[0] != 0xffffffff)) {
			load_list[i] = LoadEntry->un.id;
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "Load List[%d]: %08x %08x",
			    i, LoadEntry->un.wd[0], LoadEntry->un.wd[1]);
		}
	}

done:

	if (LoadList) {
		kmem_free(LoadList, sizeof (LOAD_LIST));
	}
	return (rval);

} /* emlxs_get_load_list() */


extern uint32_t
emlxs_read_wakeup_parms(emlxs_hba_t *hba, PWAKE_UP_PARMS WakeUpParms,
    uint32_t verbose)
{
	emlxs_port_t *port = &PPORT;
	MAILBOXQ *mbox;
	MAILBOX *mb;
	uint32_t rval = 0;
	uint32_t *wd;

	bzero(WakeUpParms, sizeof (WAKE_UP_PARMS));

	if ((mbox = (MAILBOXQ *)
	    kmem_zalloc(sizeof (MAILBOXQ), KM_NOSLEEP)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_msg,
		    "Unable to allocate mailbox buffer.");

		return (1);
	}
	mb = (MAILBOX *)mbox;

	emlxs_format_dump(mb, DMP_NV_PARAMS, WAKE_UP_PARMS_REGION_ID,
	    sizeof (WAKE_UP_PARMS) / sizeof (uint32_t), 0);

	if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_msg,
		    "Unable to get parameters: Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		if (mb->un.varDmp.word_cnt == (uint32_t)CFG_DATA_NO_REGION) {
			rval = (uint32_t)CFG_DATA_NO_REGION;
		} else {
			rval = 1;
		}
	} else {
		bcopy((caddr_t)&mb->un.varDmp.resp_offset,
		    (caddr_t)WakeUpParms, sizeof (WAKE_UP_PARMS));

		if (verbose) {
			wd = (uint32_t *)&WakeUpParms->prog_id;
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "Wakeup:      prog_id=%08x %08x",
			    wd[0], wd[1]);

			wd = (uint32_t *)&WakeUpParms->u0.boot_bios_id;
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "Wakeup: boot_bios_id=%08x %08x",
			    wd[0], wd[1]);

			wd = (uint32_t *)&WakeUpParms->sli1_prog_id;
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "Wakeup: sli1_prog_id=%08x %08x",
			    wd[0], wd[1]);

			wd = (uint32_t *)&WakeUpParms->sli2_prog_id;
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "Wakeup: sli2_prog_id=%08x %08x",
			    wd[0], wd[1]);

			wd = (uint32_t *)&WakeUpParms->sli3_prog_id;
			if (wd[0] || wd[1]) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
				    "Wakeup: sli3_prog_id=%08x %08x",
				    wd[0], wd[1]);
			}
			wd = (uint32_t *)&WakeUpParms->sli4_prog_id;
			if (wd[0] || wd[1]) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
				    "Wakeup: sli4_prog_id=%08x %08x",
				    wd[0], wd[1]);
			}
			wd = (uint32_t *)&WakeUpParms->u1.EROM_prog_id;
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "Wakeup: EROM_prog_id=%08x %08x",
			    wd[0], wd[1]);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "Wakeup: pci_cfg_rsvd=%x",
			    WakeUpParms->pci_cfg_rsvd);
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "Wakeup:  use_hdw_def=%x",
			    WakeUpParms->use_hdw_def);
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "Wakeup:  pci_cfg_sel=%x",
			    WakeUpParms->pci_cfg_sel);
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
			    "Wakeup:   cfg_lookup=%x",
			    WakeUpParms->pci_cfg_lookup_sel);
		}
	}

done:

	if (mbox) {
		kmem_free(mbox, sizeof (MAILBOXQ));
	}
	return (rval);

} /* emlxs_read_wakeup_parms() */


static uint32_t
emlxs_read_load_list(emlxs_hba_t *hba, LOAD_LIST * LoadList)
{
	emlxs_port_t *port = &PPORT;
	LOAD_ENTRY *LoadEntry;
	uint32_t *Uptr;
	uint32_t CurEntryAddr;
	MAILBOXQ *mbox = NULL;
	MAILBOX *mb;

	bzero((caddr_t)LoadList, sizeof (LOAD_LIST));

	if ((mbox = (MAILBOXQ *)
	    kmem_zalloc(sizeof (MAILBOXQ), KM_NOSLEEP)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_msg,
		    "Unable to allocate mailbox buffer.");

		return (1);
	}
	mb = (MAILBOX *)mbox;

	emlxs_format_dump(mb, DMP_MEM_REG, 0, 2, FLASH_LOAD_LIST_ADR);

	if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_msg,
		    "Unable to get load list: Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		goto done;
	}
	Uptr = (uint32_t *)&mb->un.varDmp.resp_offset;

	LoadList->head = Uptr[0];
	LoadList->tail = Uptr[1];

	CurEntryAddr = LoadList->head;

	while ((CurEntryAddr != FLASH_LOAD_LIST_ADR) &&
	    (LoadList->entry_cnt < MAX_LOAD_ENTRY)) {
		LoadEntry = &LoadList->load_entry[LoadList->entry_cnt];
		LoadList->entry_cnt++;

		emlxs_format_dump(mb, DMP_MEM_REG, 0, FLASH_LOAD_ENTRY_SIZE,
		    CurEntryAddr);

		if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_msg,
			    "Unable to get load list (%d): "
			    "Mailbox cmd=%x status=%x",
			    LoadList->entry_cnt,
			    mb->mbxCommand, mb->mbxStatus);

			goto done;
		}
		Uptr = (uint32_t *)&(mb->un.varDmp.resp_offset);

		LoadEntry->next = Uptr[0];
		LoadEntry->prev = Uptr[1];
		LoadEntry->start_adr = Uptr[2];
		LoadEntry->len = Uptr[3];
		LoadEntry->un.wd[0] = Uptr[4];
		LoadEntry->un.wd[1] = Uptr[5];

		/* update next current load entry address */
		CurEntryAddr = LoadEntry->next;

	}	/* end of while (not end of list) */

done:

	if (mbox) {
		kmem_free(mbox, sizeof (MAILBOXQ));
	}
	return (0);

} /* emlxs_read_load_list() */




static uint32_t
emlxs_get_abs_image_type(caddr_t Buffer, uint32_t BufferSize)
{
	uint32_t Version;

	if (BufferSize < (SLI_VERSION_LOC + 4))
		return (0xffffffff);

	Buffer += SLI_VERSION_LOC;
	Version = *((uint32_t *)Buffer);

	return (Version);

} /* emlxs_get_abs_image_type() */


static uint32_t
emlxs_get_dwc_image_type(emlxs_hba_t *hba, caddr_t Buffer,
    uint32_t BufferSize, PAIF_HDR AifHeader)
{
	emlxs_port_t *port = &PPORT;
	IMAGE_HDR ImageHdr;
	uint32_t NextImage;
	uint32_t i;
	uint8_t *Sptr;
	uint8_t *Dptr;
	uint32_t HwId = 0xffffffff;

	NextImage = SLI_IMAGE_START - AifHeader->ImageBase;

	while (BufferSize > NextImage) {
		Sptr = (uint8_t *)&Buffer[NextImage];
		Dptr = (uint8_t *)&ImageHdr;
		for (i = 0; i < sizeof (IMAGE_HDR); i++) {
			Dptr[i] = Sptr[i];
		}

		if (ImageHdr.BlockSize == 0xffffffff)
			break;

		switch (ImageHdr.Id.Type) {
		case 6:
		case 7:
			if (HwId == 0xffffffff) {
				HwId = ImageHdr.Id.Id;
			}
			if (HwId != ImageHdr.Id.Id) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_bad_msg,
				    "Invalid hardware id. %x %x",
				    HwId, ImageHdr.Id.Id);
			}
			break;
		}

		NextImage += ImageHdr.BlockSize;
	}

	return (HwId);

} /* emlxs_get_dwc_image_type() */


static int
emlxs_build_parms(caddr_t Buffer, PWAKE_UP_PARMS AbsWakeUpParms,
    uint32_t BufferSize, PAIF_HDR AifHeader, int32_t DwcFile)
{
	IMAGE_HDR ImageHdr;
	uint32_t NextImage;
	uint32_t i;
	int32_t ChangeParams = FALSE;
	caddr_t Sptr;
	caddr_t Dptr;

	bzero((caddr_t)AbsWakeUpParms, sizeof (WAKE_UP_PARMS));

	if (!DwcFile && ((AifHeader->RoSize + AifHeader->RwSize) <= 0x20000)) {
		return (FALSE);
	}
	NextImage = SLI_IMAGE_START - AifHeader->ImageBase;

	while (BufferSize > NextImage) {
		Sptr = &Buffer[NextImage];
		Dptr = (caddr_t)&ImageHdr;
		for (i = 0; i < sizeof (IMAGE_HDR); i++) {
			Dptr[i] = Sptr[i];
		}

		if (ImageHdr.BlockSize == 0xffffffff)
			break;

		switch (ImageHdr.Id.Type) {
		case TEST_PROGRAM:
			break;
		case FUNC_FIRMWARE:
			AbsWakeUpParms->prog_id = ImageHdr.Id;
			ChangeParams = TRUE;
			break;
		case BOOT_BIOS:
			AbsWakeUpParms->u0.boot_bios_id = ImageHdr.Id;
			ChangeParams = TRUE;
			break;
		case SLI1_OVERLAY:
			AbsWakeUpParms->sli1_prog_id = ImageHdr.Id;
			ChangeParams = TRUE;
			break;
		case SLI2_OVERLAY:
			AbsWakeUpParms->sli2_prog_id = ImageHdr.Id;
			ChangeParams = TRUE;
			break;
		case SLI3_OVERLAY:
			AbsWakeUpParms->sli3_prog_id = ImageHdr.Id;
			ChangeParams = TRUE;
			break;
		case SLI4_OVERLAY:
			AbsWakeUpParms->sli4_prog_id = ImageHdr.Id;
			ChangeParams = TRUE;
			break;
		default:
			break;
		}

		NextImage += ImageHdr.BlockSize;
	}

	return (ChangeParams);

} /* emlxs_build_parms() */


static uint32_t
emlxs_update_wakeup_parms(emlxs_hba_t *hba,
    PWAKE_UP_PARMS AbsWakeUpParms, PWAKE_UP_PARMS WakeUpParms)
{
	emlxs_port_t *port = &PPORT;
	MAILBOX *mb;
	MAILBOXQ *mbox;
	uint32_t rval = 0;

	if ((mbox = (MAILBOXQ *)
	    kmem_zalloc(sizeof (MAILBOXQ), KM_NOSLEEP)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to allocate mailbox buffer.");

		return (1);
	}
	mb = (MAILBOX *)mbox;

	WakeUpParms->prog_id = AbsWakeUpParms->prog_id;
	WakeUpParms->u0.boot_bios_id = AbsWakeUpParms->u0.boot_bios_id;
	WakeUpParms->sli1_prog_id = AbsWakeUpParms->sli1_prog_id;
	WakeUpParms->sli2_prog_id = AbsWakeUpParms->sli2_prog_id;
	WakeUpParms->sli3_prog_id = AbsWakeUpParms->sli3_prog_id;
	WakeUpParms->sli4_prog_id = AbsWakeUpParms->sli4_prog_id;

	emlxs_format_update_parms(mb, WakeUpParms);

	if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to update wakeup parameters: "
		    "Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		rval = 1;
	}
	if (mbox) {
		kmem_free(mbox, sizeof (MAILBOXQ));
	}
	return (rval);

} /* emlxs_update_wakeup_parms() */


static uint32_t
emlxs_validate_version(emlxs_hba_t *hba, emlxs_fw_file_t *file,
    uint32_t id, uint32_t type, char *file_type)
{
	emlxs_port_t *port = &PPORT;

	/* Create the version label */
	emlxs_decode_version(file->version, file->label);

	/* Process the DWC type */
	switch (type) {
	case TEST_PROGRAM:

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_msg,
		    "%s: TEST: offset=%08x  version=%08x, %s",
		    file_type, file->offset,
		    file->version, file->label);

		break;

	case BOOT_BIOS:

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_msg,
		    "%s: BOOT: offset=%08x  version=%08x, %s",
		    file_type, file->offset,
		    file->version, file->label);

		if (!emlxs_bios_check(hba, id)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_incompat_msg,
			    "BOOT Check: Image not compatible with %s. id=%02x",
			    hba->model_info.model, id);

			return (EMLXS_IMAGE_INCOMPATIBLE);
		}
		break;

	case FUNC_FIRMWARE:	/* Stub */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_msg,
		    "%s: STUB: offset=%08x  version=%08x, %s",
		    file_type, file->offset,
		    file->version, file->label);

		if (!emlxs_stub_check(hba, id)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_incompat_msg,
			    "STUB Check: Image not compatible with %s. id=%02x",
			    hba->model_info.model, id);

			return (EMLXS_IMAGE_INCOMPATIBLE);
		}
		break;

	case SLI1_OVERLAY:

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_msg,
		    "%s: SLI1: offset=%08x  version=%08x, %s",
		    file_type, file->offset,
		    file->version, file->label);

		if (!emlxs_sli1_check(hba, id)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_incompat_msg,
			    "SLI1 Check: Image not compatible with %s. id=%02x",
			    hba->model_info.model, id);

			return (EMLXS_IMAGE_INCOMPATIBLE);
		}
		break;

	case SLI2_OVERLAY:

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_msg,
		    "%s: SLI2: offset=%08x  version=%08x, %s",
		    file_type, file->offset,
		    file->version, file->label);

		if (!emlxs_sli2_check(hba, id)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_incompat_msg,
			    "SLI2 Check: Image not compatible with %s. id=%02x",
			    hba->model_info.model, id);

			return (EMLXS_IMAGE_INCOMPATIBLE);
		}
		break;

	case SLI3_OVERLAY:

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_msg,
		    "%s: SLI3: offset=%08x  version=%08x, %s",
		    file_type, file->offset,
		    file->version, file->label);

		if (!emlxs_sli3_check(hba, id)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_incompat_msg,
			    "SLI3 Check: Image not compatible with %s. id=%02x",
			    hba->model_info.model, id);

			return (EMLXS_IMAGE_INCOMPATIBLE);
		}
		break;

	case SLI4_OVERLAY:

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_msg,
		    "%s: SLI4: offset=%08x  version=%08x, %s",
		    file_type, file->offset,
		    file->version, file->label);

		if (!emlxs_sli4_check(hba, id)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_incompat_msg,
			    "SLI4 Check: Image not compatible with %s. id=%02x",
			    hba->model_info.model, id);

			return (EMLXS_IMAGE_INCOMPATIBLE);
		}
		break;

	case SBUS_FCODE:

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_msg,
		    "%s: SBUS FCODE: offset=%08x  version=%08x, %s",
		    file_type, file->offset,
		    file->version, file->label);

		if (!emlxs_sbus_fcode_check(hba, id)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_incompat_msg,
			    "SBUS FCODE Check: Image not compatible with %s. "
			    "id=%02x",
			    hba->model_info.model, id);

			return (EMLXS_IMAGE_INCOMPATIBLE);
		}
		break;

	case KERNEL_CODE:

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_msg,
		    "%s: KERN: offset=%08x  version=%08x, %s",
		    file_type, file->offset,
		    file->version, file->label);

		if (!emlxs_kern_check(hba, id)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_incompat_msg,
			    "KERN Check: Image not compatible with %s. id=%02x",
			    hba->model_info.model, id);

			return (EMLXS_IMAGE_INCOMPATIBLE);
		}
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_bad_msg,
		    "%s: Image type not supported. type=%x",
		    file_type, type);

		return (EMLXS_IMAGE_BAD);
	}

	return (0);

} /* emlxs_validate_version() */


static uint32_t
emlxs_validate_image(emlxs_hba_t *hba, caddr_t Buffer, uint32_t Size,
    emlxs_fw_image_t *image)
{
	emlxs_port_t *port = &PPORT;
	uint32_t ImageType;
	AIF_HDR AifHdr;
	IMAGE_HDR ImageHdr;
	uint32_t NextImage;
	uint32_t FileType;
	uint32_t FileLen = 0;
	uint32_t TotalLen = 0;
	uint32_t *CkSumEnd;
	uint32_t id;
	uint32_t type;
	uint32_t ver;
	uint32_t ImageLength;
	uint32_t BufferSize;
	uint32_t rval = 0;
	caddr_t bptr;
	emlxs_vpd_t *vpd;

	vpd = &VPD;

	/* Get image type */
	ImageType = *((uint32_t *)Buffer);

	/* Pegasus and beyond adapters */
	if ((ImageType == NOP_IMAGE_TYPE) &&
	    !(hba->model_info.chip &
	    (EMLXS_DRAGONFLY_CHIP | EMLXS_CENTAUR_CHIP))) {
		bptr = Buffer;
		TotalLen = sizeof (uint32_t);

		while (TotalLen < Size) {
			if (Size < sizeof (AIF_HDR)) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_bad_msg,
				    "Invalid image header length: 0x%x < 0x%x",
				    Size, sizeof (AIF_HDR));

				return (EMLXS_IMAGE_BAD);
			}
			bcopy(bptr, &AifHdr, sizeof (AIF_HDR));
			emlxs_disp_aif_header(hba, &AifHdr);

			ImageLength = AifHdr.RoSize;

			/* Validate checksum */
			CkSumEnd = (uint32_t *)
			    (bptr + ImageLength + sizeof (AIF_HDR));
			if (emlxs_valid_cksum((uint32_t *)bptr, CkSumEnd)) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_bad_msg,
				    "Invalid checksum found.");

				return (EMLXS_IMAGE_BAD);
			}
			FileType = AifHdr.ZinitBr;
			switch (FileType) {
			case FILE_TYPE_AWC:
				image->awc.offset = (uint32_t)
				    ((uintptr_t)bptr - (uintptr_t)Buffer);
				image->awc.version = AifHdr.AVersion;
				image->awc.revcomp = 0;

				id = (AifHdr.AVersion & 0x00ff0000) >> 16;
				type = emlxs_type_check(
				    (AifHdr.AVersion & 0xff000000) >> 24);

				/* Validate the file version */
				if ((rval = emlxs_validate_version(hba,
				    &image->awc, id, type, "AWC file"))) {
					return (rval);
				}
				break;

			case FILE_TYPE_BWC:
				image->bwc.offset = (uint32_t)
				    ((uintptr_t)bptr - (uintptr_t)Buffer);
				image->bwc.version = AifHdr.AVersion;
				image->bwc.revcomp = 0;

				id = (AifHdr.AVersion & 0x00ff0000) >> 16;
				type = emlxs_type_check(
				    (AifHdr.AVersion & 0xff000000) >> 24);

				/* Validate the file version */
				if ((rval = emlxs_validate_version(hba,
				    &image->bwc, id, type, "BWC file"))) {
					return (rval);
				}
				break;

			case FILE_TYPE_DWC:
				image->dwc.offset = (uint32_t)
				    ((uintptr_t)bptr - (uintptr_t)Buffer);
				image->dwc.version = AifHdr.AVersion;
				image->dwc.revcomp = 0;

				id = (AifHdr.AVersion & 0x00ff0000) >> 16;
				type = emlxs_type_check(
				    (AifHdr.AVersion & 0xff000000) >> 24);

				/* Validate the file version */
				if ((rval = emlxs_validate_version(hba,
				    &image->dwc, id, type, "DWC file"))) {
					return (rval);
				}
				/* Scan for program types */
				NextImage = sizeof (AIF_HDR) + 4;
				BufferSize = AifHdr.RoSize + AifHdr.RwSize;

				while (BufferSize > NextImage) {
					bcopy(&bptr[NextImage], &ImageHdr,
					    sizeof (IMAGE_HDR));
					emlxs_dump_image_header(hba, &ImageHdr);

					/* Validate block size */
					if (ImageHdr.BlockSize == 0xffffffff) {
						break;
					}
					type = emlxs_type_check(
					    ImageHdr.Id.Type);

					/* Calculate the program offset */
					image->prog[type].offset = (uint32_t)
					    ((uintptr_t)&bptr[NextImage] -
					    (uintptr_t)Buffer);

					/* Acquire the versions */
					image->prog[type].version =
					    (ImageHdr.Id.Type << 24) |
					    (ImageHdr.Id.Id << 16) |
					    (ImageHdr.Id.Ver << 8) |
					    ImageHdr.Id.Rev;

					image->prog[type].revcomp =
					    ImageHdr.Id.un.revcomp;

					/* Validate the file version */
					if ((rval = emlxs_validate_version(hba,
					    &image->prog[type], ImageHdr.Id.Id,
					    type, "DWC prog"))) {
						return (rval);
					}
					NextImage += ImageHdr.BlockSize;

				}	/* while() */

				break;
			}

			FileLen = sizeof (AIF_HDR) + ImageLength +
			    sizeof (uint32_t);
			TotalLen += FileLen;
			bptr += FileLen;
		}
	}
	/* Pre-pegasus adapters */

	else if (ImageType == NOP_IMAGE_TYPE) {
		if (Size < sizeof (AIF_HDR)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_bad_msg,
			    "Invalid image header length: 0x%x < 0x%x",
			    Size, sizeof (AIF_HDR));

			return (EMLXS_IMAGE_BAD);
		}
		bcopy(Buffer, &AifHdr, sizeof (AIF_HDR));
		emlxs_disp_aif_header(hba, &AifHdr);

		ImageLength = AifHdr.RoSize + AifHdr.RwSize;

		if (Size != (sizeof (AIF_HDR) + ImageLength + sizeof (int))) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_bad_msg,
			    "Image length incorrect: 0x%x != 0x%x",
			    Size,
			    sizeof (AIF_HDR) + ImageLength + sizeof (uint32_t));

			return (EMLXS_IMAGE_BAD);
		}
		if (AifHdr.ImageBase && AifHdr.ImageBase != 0x20000) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_bad_msg,
			    "Invalid imageBase value %x != 0x20000",
			    AifHdr.ImageBase);

			return (EMLXS_IMAGE_BAD);
		}
		CkSumEnd = (uint32_t *)
		    (Buffer + ImageLength + sizeof (AIF_HDR));
		if (emlxs_valid_cksum((uint32_t *)Buffer, CkSumEnd)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_bad_msg,
			    "Invalid checksum found.");

			return (EMLXS_IMAGE_BAD);
		}
		image->dwc.offset = 0;
		image->dwc.version = AifHdr.AVersion;
		image->dwc.revcomp = 0;

		id = (AifHdr.AVersion & 0x00ff0000) >> 16;
		type = emlxs_type_check((AifHdr.AVersion & 0xff000000) >> 24);

		/* Validate the file version */
		if ((rval = emlxs_validate_version(hba, &image->dwc,
		    id, type, "DWC file"))) {
			return (rval);
		}
		NextImage = SLI_IMAGE_START - AifHdr.ImageBase;
		while (Size > NextImage) {
			bcopy(&Buffer[NextImage], &ImageHdr,
			    sizeof (IMAGE_HDR));
			emlxs_dump_image_header(hba, &ImageHdr);

			/* Validate block size */
			if (ImageHdr.BlockSize == 0xffffffff) {
				break;
			}
			type = emlxs_type_check(ImageHdr.Id.Type);

			/* Calculate the program offset */
			image->prog[type].offset = NextImage;

			/* Acquire the versions */
			image->prog[type].version = (ImageHdr.Id.Type << 24) |
			    (ImageHdr.Id.Id << 16) | (ImageHdr.Id.Ver << 8) |
			    ImageHdr.Id.Rev;

			image->prog[type].revcomp = ImageHdr.Id.un.revcomp;

			/* Validate the file version */
			if ((rval = emlxs_validate_version(hba,
			    &image->prog[type], ImageHdr.Id.Id,
			    type, "DWC prog"))) {
				return (rval);
			}
			NextImage += ImageHdr.BlockSize;
		}
	} else {
		/* Precheck image size */
		if (Size < sizeof (IMAGE_HDR)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_bad_msg,
			    "Invalid image header length: 0x%x < 0x%x",
			    Size, sizeof (IMAGE_HDR));

			return (EMLXS_IMAGE_BAD);
		}
		bcopy(Buffer, &ImageHdr, sizeof (IMAGE_HDR));
		emlxs_dump_image_header(hba, &ImageHdr);

		/* Validate block size */
		if (ImageHdr.BlockSize == 0xffffffff) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_bad_msg,
			    "Invalid block size.");

			return (EMLXS_IMAGE_BAD);
		}
		ImageLength = ImageHdr.BlockSize;

		/* Validate image length */
		if (Size != ImageLength) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_bad_msg,
			    "Invalid image length: 0x%x != 0x%x",
			    Size, ImageLength);

			return (EMLXS_IMAGE_BAD);
		}
		/* Validate Checksum */
		CkSumEnd = (uint32_t *)
		    Buffer + (ImageLength / sizeof (uint32_t)) - 1;
		if (emlxs_valid_cksum((uint32_t *)Buffer, CkSumEnd)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_bad_msg,
			    "Invalid checksum found.");

			return (EMLXS_IMAGE_BAD);
		}
		type = emlxs_type_check(ImageHdr.Id.Type);

		/* Calculate the program offset */
		image->prog[type].offset = 0;

		/* Acquire the versions */
		image->prog[type].version = (ImageHdr.Id.Type << 24) |
		    (ImageHdr.Id.Id << 16) | (ImageHdr.Id.Ver << 8) |
		    ImageHdr.Id.Rev;

		image->prog[type].revcomp = ImageHdr.Id.un.revcomp;

		/* Validate the file version */
		if ((rval = emlxs_validate_version(hba, &image->prog[type],
		    ImageHdr.Id.Id, type, "DWC file"))) {
			return (rval);
		}
	}

	/*
	 * This checks if a DragonFly (pre-V2 ASIC) SLI2 image file is
	 * greater than version 3.8
	 */
	if (FC_JEDEC_ID(vpd->biuRev) == DRAGONFLY_JEDEC_ID) {
		if (image->prog[SLI2_OVERLAY].version != 0) {
			ver = (image->prog[SLI2_OVERLAY].version &
			    0x0000ff00) >> 8;

			if ((((ver & 0xf0) == 0x30) &&
			    ((ver & 0x0f) >= 0x08)) ||
			    ((ver & 0xf0) > 0x30)) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_image_incompat_msg,
				    "ASIC Check: Image requires "
				    "DragonFly V2 ASIC");

				return (EMLXS_IMAGE_INCOMPATIBLE);
			}
		}
	}
	return (0);

} /* emlxs_validate_image() */


static uint32_t
emlxs_update_exp_rom(emlxs_hba_t *hba, PWAKE_UP_PARMS WakeUpParms)
{
	emlxs_port_t *port = &PPORT;
	MAILBOXQ *mbox;
	MAILBOX *mb;
	uint32_t next_address;
	uint32_t rval = 0;

	if (WakeUpParms->u1.EROM_prog_wd[0] == 0) {
		return (1);
	}
	if ((mbox = (MAILBOXQ *)
	    kmem_zalloc(sizeof (MAILBOXQ), KM_NOSLEEP)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to allocate mailbox buffer.");

		return (1);
	}
	bzero(mbox, sizeof (MAILBOXQ));

	mb = (MAILBOX *)mbox;
	mb->mbxCommand = MBX_LOAD_EXP_ROM;
	mb->un.varLdExpRom.step = EROM_CMD_FIND_IMAGE;
	mb->un.varLdExpRom.progress = 0;
	mb->un.varLdExpRom.un.prog_id = WakeUpParms->u1.EROM_prog_id;

	if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to load exp ROM. Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		rval = 1;

		goto SLI_DOWNLOAD_EXIT;
	}
	if (mb->un.varLdExpRom.progress == EROM_RSP_COPY_DONE) {
		(void) emlxs_update_wakeup_parms(hba, WakeUpParms, WakeUpParms);

		rval = 1;
		goto SLI_DOWNLOAD_EXIT;
	}
	if (mb->un.varLdExpRom.progress != EROM_RSP_ERASE_STARTED) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Invalid exp ROM progress. progress=%x",
		    mb->un.varLdExpRom.progress);

		rval = 1;

		goto SLI_DOWNLOAD_EXIT;
	}
	/*
	 * continue Erase
	 */
	while (mb->un.varLdExpRom.progress != EROM_RSP_ERASE_COMPLETE) {

		next_address = mb->un.varLdExpRom.dl_to_adr;

		bzero((void *)mb, MAILBOX_CMD_BSIZE);

		mb->mbxCommand = MBX_LOAD_EXP_ROM;
		mb->un.varLdExpRom.step = EROM_CMD_CONTINUE_ERASE;
		mb->un.varLdExpRom.dl_to_adr = next_address;
		mb->un.varLdExpRom.progress = 0;
		mb->un.varLdExpRom.un.prog_id = WakeUpParms->u1.EROM_prog_id;

		if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
			    "Unable to load exp ROM. Mailbox cmd=%x status=%x",
			    mb->mbxCommand, mb->mbxStatus);

			rval = 1;
			goto SLI_DOWNLOAD_EXIT;
		}
	}

	while (mb->un.varLdExpRom.progress != EROM_RSP_COPY_DONE) {
		next_address = mb->un.varLdExpRom.dl_to_adr;

		bzero((void *)mb, MAILBOX_CMD_BSIZE);

		mb->mbxCommand = MBX_LOAD_EXP_ROM;
		mb->un.varLdExpRom.step = EROM_CMD_COPY;
		mb->un.varLdExpRom.dl_to_adr = next_address;
		mb->un.varLdExpRom.progress = 0;
		mb->un.varLdExpRom.un.prog_id = WakeUpParms->u1.EROM_prog_id;

		if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
			    "Unable to load exp ROM. Mailbox cmd=%x status=%x",
			    mb->mbxCommand, mb->mbxStatus);

			rval = 1;

			goto SLI_DOWNLOAD_EXIT;
		}
	}

	rval = emlxs_update_wakeup_parms(hba, WakeUpParms, WakeUpParms);

SLI_DOWNLOAD_EXIT:

	if (mbox) {
		kmem_free(mbox, sizeof (MAILBOXQ));
	}
	return (rval);

} /* emlxs_update_exp_rom() */


/*
 *
 * FUNCTION NAME: emlxs_start_abs_download_2mb
 *
 * DESCRIPTION: Perform absolute download for 2 MB flash.  A incoming
 *              buffer may consist of more than 1 file.  This function
 *              will parse the buffer to find all the files.
 *
 *
 * PARAMETERS:
 *
 *
 * RETURNS:
 *
 */
/* ARGSUSED */
static uint32_t
emlxs_start_abs_download_2mb(emlxs_hba_t *hba, caddr_t buffer, uint32_t len,
    uint32_t offline, emlxs_fw_image_t *fw_image)
{
	emlxs_port_t *port = &PPORT;
	caddr_t AwcBuffer = NULL;
	caddr_t BwcBuffer = NULL;
	caddr_t DwcBuffer = NULL;
	AIF_HDR *AwcAifHdr;
	AIF_HDR *BwcAifHdr;
	AIF_HDR *DwcAifHdr;
	uint32_t BWCflag;
	emlxs_vpd_t *vpd;
	uint32_t i;
	uint32_t count;
	uint32_t extType = 0;
	uint32_t rval = 0;

	vpd = &VPD;

	/* Check for AWC file */
	if (fw_image->awc.version) {
		AwcBuffer = buffer + fw_image->awc.offset;
		AwcAifHdr = (AIF_HDR *) AwcBuffer;
	}
	/* Check for BWC file */
	if (fw_image->bwc.version) {
		extType = BWCext;
		BwcBuffer = buffer + fw_image->bwc.offset;
		BwcAifHdr = (AIF_HDR *) BwcBuffer;
	}
	/* Check for DWC file */
	if (fw_image->dwc.version) {
		extType = DWCext;
		DwcBuffer = buffer + fw_image->dwc.offset;
		DwcAifHdr = (AIF_HDR *) DwcBuffer;
	}
	/* Check for program files */
	count = 0;
	for (i = 0; i < MAX_PROG_TYPES; i++) {
		if (fw_image->prog[i].version) {
			count++;
		}
	}

	if (count > 1) {
		extType = ALLext;

		if (fw_image->bwc.version) {
			BWCflag = ALL_WITH_BWC;
		} else {
			BWCflag = ALL_WITHOUT_BWC;
		}
	} else {
		BWCflag = NO_ALL;
	}

	/* If nothing to download then quit now */
	if (!AwcBuffer && !DwcBuffer && !BwcBuffer) {
		return (0);
	}
	/*
	 * Everything checks out, now to just do it
	 */
	if (offline) {
		if (emlxs_offline(hba) != FC_SUCCESS) {
			return (EMLXS_OFFLINE_FAILED);
		}
		if (emlxs_hba_reset(hba, 1, 1) != FC_SUCCESS) {
			return (EMLXS_OFFLINE_FAILED);
		}
	}
	if (AwcBuffer) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_msg,
		    "AWC file: KERN: old=%s  new=%s ",
		    vpd->postKernName, fw_image->awc.label);

		rval = emlxs_proc_abs_2mb(hba, AwcAifHdr, AwcBuffer,
		    FILE_TYPE_AWC, BWCflag, extType);

		if (rval) {
			goto SLI_DOWNLOAD_2MB_EXIT;
		}
	}
	if (DwcBuffer) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_msg,
		    "DWC file: TEST:             new=%s ",
		    fw_image->prog[TEST_PROGRAM].label);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_msg,
		    "DWC file: STUB: old=%s  new=%s ",
		    vpd->opFwName, fw_image->prog[FUNC_FIRMWARE].label);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_msg,
		    "DWC file: SLI1: old=%s  new=%s ",
		    vpd->sli1FwName, fw_image->prog[SLI1_OVERLAY].label);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_msg,
		    "DWC file: SLI2: old=%s  new=%s ",
		    vpd->sli2FwName, fw_image->prog[SLI2_OVERLAY].label);

		if (vpd->sli3FwRev || fw_image->prog[SLI3_OVERLAY].version) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_msg,
			    "DWC file: SLI3: old=%s  new=%s ",
			    vpd->sli3FwName,
			    fw_image->prog[SLI3_OVERLAY].label);
		}
		if (vpd->sli4FwRev || fw_image->prog[SLI4_OVERLAY].version) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_msg,
			    "DWC file: SLI4: old=%s  new=%s ",
			    vpd->sli4FwName,
			    fw_image->prog[SLI4_OVERLAY].label);
		}
		rval = emlxs_proc_abs_2mb(hba, DwcAifHdr, DwcBuffer,
		    FILE_TYPE_DWC, BWCflag, extType);

		if (rval) {
			goto SLI_DOWNLOAD_2MB_EXIT;
		}
	}
	if (BwcBuffer) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_msg,
		    "BWC file: BOOT: old=%s  new=%s ",
		    vpd->fcode_version, fw_image->bwc.label);

		rval = emlxs_proc_abs_2mb(hba, BwcAifHdr, BwcBuffer,
		    FILE_TYPE_BWC, BWCflag, extType);
	}
SLI_DOWNLOAD_2MB_EXIT:

	if (offline) {
		(void) emlxs_online(hba);
	}
	return (rval);

} /* emlxs_start_abs_download_2mb() */


/*
 *
 * FUNCTION NAME: emlxs_proc_abs_2mb
 *
 * DESCRIPTION: Given one of the 3 file types(awc/bwc/dwc), it will reset
 *              the port and download the file with sliIssueMbCommand()
 *
 *
 * PARAMETERS:
 *
 *
 * RETURNS:
 *
 */
static uint32_t
emlxs_proc_abs_2mb(emlxs_hba_t *hba, PAIF_HDR AifHdr, caddr_t EntireBuffer,
    uint32_t FileType, uint32_t BWCflag, uint32_t extType)
{
	emlxs_port_t *port = &PPORT;
	caddr_t Buffer = NULL;
	caddr_t DataBuffer = NULL;
	uint32_t *Src;
	uint32_t *Dst;
	MAILBOXQ *mbox;
	MAILBOX *mb;
	uint32_t DlByteCount = AifHdr->RoSize + AifHdr->RwSize;
	uint32_t rval = 0;
	uint32_t SegSize = DL_SLIM_SEG_BYTE_COUNT;
	uint32_t DlToAddr = AifHdr->ImageBase;
	uint32_t DlCount;
	WAKE_UP_PARMS AbsWakeUpParms;
	uint32_t i;
	uint32_t NextAddr;
	uint32_t EraseByteCount;
	uint32_t AreaId;
	uint32_t RspProgress = 0;
	uint32_t numBootImage = 0;
	uint32_t ParamsChg = 0;
	uint32_t BufferSize;

	if ((DataBuffer = (caddr_t)
	    kmem_zalloc(DL_SLIM_SEG_BYTE_COUNT, KM_NOSLEEP)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "%x: Unable to allocate data buffer.", FileType);

		return (EMLXS_IMAGE_FAILED);
	}
	bzero(DataBuffer, sizeof (DL_SLIM_SEG_BYTE_COUNT));

	if ((mbox = (MAILBOXQ *)
	    kmem_zalloc(sizeof (MAILBOXQ), KM_NOSLEEP)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "%x: Unable to allocate mailbox buffer.", FileType);

		kmem_free(DataBuffer, DL_SLIM_SEG_BYTE_COUNT);

		return (EMLXS_IMAGE_FAILED);
	}
	mb = (MAILBOX *)mbox;

	BufferSize = DlByteCount + sizeof (AIF_HDR) + sizeof (uint32_t);
	Buffer = EntireBuffer + sizeof (AIF_HDR);

	switch (FileType) {
	case FILE_TYPE_AWC:
		break;

	case FILE_TYPE_BWC:
		ParamsChg = emlxs_build_parms_2mb_bwc(hba, AifHdr,
		    extType, &AbsWakeUpParms);

		if (ParamsChg == FALSE) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
			    "BWC build parms failed.");

			rval = EMLXS_IMAGE_FAILED;

			goto EXIT_ABS_DOWNLOAD;
		}
		break;

	case FILE_TYPE_DWC:
		ParamsChg = emlxs_build_parms_2mb_dwc(hba, Buffer,
		    BufferSize, AifHdr, &AbsWakeUpParms, BWCflag,
		    extType, &numBootImage);

		if (ParamsChg == FALSE) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
			    "DWC build parms failed.");

			rval = EMLXS_IMAGE_FAILED;

			goto EXIT_ABS_DOWNLOAD;
		}
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_image_bad_msg,
		    "Invalid file type: %x", FileType);

		rval = EMLXS_IMAGE_BAD;

		goto EXIT_ABS_DOWNLOAD;

	}

	EraseByteCount = AifHdr->Area_Size;
	AreaId = AifHdr->Area_ID;

	emlxs_format_load_area_cmd(mb, DlToAddr, EraseByteCount, ERASE_FLASH,
	    0, DL_FROM_SLIM_OFFSET, AreaId, MBX_LOAD_AREA, CMD_START_ERASE);

	if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "%x: Could not erase 2MB Flash: Mailbox cmd=%x status=%x",
		    FileType, mb->mbxCommand, mb->mbxStatus);

		rval = EMLXS_IMAGE_FAILED;

		goto EXIT_ABS_DOWNLOAD;
	}
	while (mb->un.varLdArea.progress != RSP_ERASE_COMPLETE) {
		NextAddr = mb->un.varLdArea.dl_to_adr;

		emlxs_format_load_area_cmd(mb, NextAddr, EraseByteCount,
		    ERASE_FLASH, 0, DL_FROM_SLIM_OFFSET, AreaId, MBX_LOAD_AREA,
		    CMD_CONTINUE_ERASE);

		if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
			    "%x: Could not erase 2MB Flash2: "
			    "Mailbox cmd=%x status=%x",
			    FileType, mb->mbxCommand, mb->mbxStatus);

			rval = EMLXS_IMAGE_FAILED;

			goto EXIT_ABS_DOWNLOAD;
		}
	}

	while (DlByteCount) {
		if (DlByteCount >= SegSize)
			DlCount = SegSize;
		else
			DlCount = DlByteCount;

		DlByteCount -= DlCount;

		Dst = (uint32_t *)DataBuffer;
		Src = (uint32_t *)Buffer;

		for (i = 0; i < (DlCount / 4); i++) {
			*Dst = *Src;
			Dst++;
			Src++;
		}

		WRITE_SLIM_COPY(hba, (uint32_t *)DataBuffer,
		    (volatile uint32_t *)
		    ((volatile char *)hba->slim_addr + sizeof (MAILBOX)),
		    (DlCount / sizeof (uint32_t)));

		if ((RspProgress == RSP_DOWNLOAD_MORE) || (RspProgress == 0)) {
			emlxs_format_load_area_cmd(mb, DlToAddr, DlCount,
			    PROGRAM_FLASH, (DlByteCount) ? 0 : 1,
			    DL_FROM_SLIM_OFFSET, AreaId, MBX_LOAD_AREA,
			    (DlByteCount) ? CMD_DOWNLOAD : CMD_END_DOWNLOAD);

			if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) !=
			    MBX_SUCCESS) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_download_failed_msg,
				    "%x: Could not program 2MB Flash: "
				    "Mailbox cmd=%x status=%x",
				    FileType, mb->mbxCommand, mb->mbxStatus);

				rval = EMLXS_IMAGE_FAILED;

				goto EXIT_ABS_DOWNLOAD;
			}
		}
		RspProgress = mb->un.varLdArea.progress;

		Buffer += DlCount;
		DlToAddr += DlCount;
	}

	if (RspProgress != RSP_DOWNLOAD_DONE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "%x: Failed download response received. %x",
		    FileType, RspProgress);

		rval = EMLXS_IMAGE_FAILED;

		goto EXIT_ABS_DOWNLOAD;
	}
	if (ParamsChg) {
		if (emlxs_update_wakeup_parms(hba, &AbsWakeUpParms,
		    &AbsWakeUpParms)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
			    "%x: Unable to update parms.", FileType);

			rval = EMLXS_IMAGE_FAILED;
		}
	}
EXIT_ABS_DOWNLOAD:

	if (DataBuffer) {
		kmem_free(DataBuffer, DL_SLIM_SEG_BYTE_COUNT);
	}
	if (mbox) {
		kmem_free(mbox, sizeof (MAILBOXQ));
	}
	return (rval);

} /* emlxs_proc_abs_2mb() */


static void
emlxs_format_load_area_cmd(MAILBOX *mb, uint32_t Base, uint32_t DlByteCount,
    uint32_t Function, uint32_t Complete, uint32_t DataOffset, uint32_t AreaId,
    uint8_t MbxCmd, uint32_t StepCmd)
{
	bzero((void *)mb, MAILBOX_CMD_BSIZE);

	mb->mbxCommand = MbxCmd;
	mb->mbxOwner = OWN_HOST;
	mb->un.varLdArea.update_flash = 1;
	mb->un.varLdArea.erase_or_prog = Function;
	mb->un.varLdArea.dl_to_adr = Base;
	mb->un.varLdArea.dl_len = DlByteCount;
	mb->un.varLdArea.load_cmplt = Complete;
	mb->un.varLdArea.method = DL_FROM_SLIM;
	mb->un.varLdArea.area_id = AreaId;
	mb->un.varLdArea.step = StepCmd;
	mb->un.varLdArea.un.dl_from_slim_offset = DataOffset;

} /* emlxs_format_load_area_cmd() */


static uint32_t
emlxs_build_parms_2mb_bwc(emlxs_hba_t *hba, PAIF_HDR AifHdr, uint32_t extType,
    PWAKE_UP_PARMS AbsWakeUpParms)
{
	emlxs_port_t *port = &PPORT;
	uint32_t pId[2];
	uint32_t returnStat;

	/* Read wakeup paramters */
	if (emlxs_read_wakeup_parms(hba, AbsWakeUpParms, 0) ==
	    CFG_DATA_NO_REGION) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to get BWC parameters.");
		return (FALSE);
	}
	pId[0] = AifHdr->AVersion;
	pId[1] = 0;

	if (extType == BWCext) {
		AbsWakeUpParms->u0.boot_bios_wd[0] = pId[0];
		AbsWakeUpParms->u0.boot_bios_wd[1] = pId[1];
		AbsWakeUpParms->u1.EROM_prog_wd[0] = pId[0];
		AbsWakeUpParms->u1.EROM_prog_wd[1] = pId[1];
	} else if (extType == ALLext) {
		if (!AbsWakeUpParms->u0.boot_bios_wd[0]) {
			/* case of EROM inactive */
			AbsWakeUpParms->u1.EROM_prog_wd[1] = pId[1];
			AbsWakeUpParms->u1.EROM_prog_wd[0] = pId[0];
		} else {
			/* case of EROM active */
			if (AbsWakeUpParms->u0.boot_bios_wd[0] == pId[0]) {
				/* same ID */
				AbsWakeUpParms->u0.boot_bios_wd[0] = pId[0];
				AbsWakeUpParms->u0.boot_bios_wd[1] = pId[1];
				AbsWakeUpParms->u1.EROM_prog_wd[0] = pId[0];
				AbsWakeUpParms->u1.EROM_prog_wd[1] = pId[1];
			} else {
				/* different ID */
				AbsWakeUpParms->u1.EROM_prog_wd[0] = pId[0];
				AbsWakeUpParms->u1.EROM_prog_wd[1] = pId[1];

				returnStat = emlxs_update_exp_rom(hba,
				    AbsWakeUpParms);

				if (returnStat) {
					AbsWakeUpParms->u0.boot_bios_wd[0] =
					    pId[0];
					AbsWakeUpParms->u0.boot_bios_wd[1] =
					    pId[1];
				}
			}
		}
	}
	return (TRUE);

} /* emlxs_build_parms_2mb_bwc() */


/* ARGSUSED */
static uint32_t
emlxs_build_parms_2mb_dwc(emlxs_hba_t *hba, caddr_t Buffer,
    uint32_t BufferSize, PAIF_HDR AifHeader,
    PWAKE_UP_PARMS AbsWakeUpParms, uint32_t BWCflag,
    uint32_t extType, uint32_t *numBootImage)
{
	emlxs_port_t *port = &PPORT;
	uint32_t NextImage;
	uint32_t i;
	IMAGE_HDR ImageHdr;
	uint32_t *ptr1;
	uint32_t *ptr2;
	PROG_ID BootId[MAX_BOOTID];
	uint32_t ChangeParams = FALSE;
	WAKE_UP_PARMS WakeUpParms;
	caddr_t Sptr;
	caddr_t Dptr;

	bzero(&BootId, (sizeof (PROG_ID)) * MAX_BOOTID);

	/* Read wakeup paramters */
	if (emlxs_read_wakeup_parms(hba, AbsWakeUpParms, 0) ==
	    CFG_DATA_NO_REGION) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to get DWC parameters.");
		return (FALSE);
	}
	bcopy((caddr_t)AbsWakeUpParms, (caddr_t)&WakeUpParms,
	    sizeof (WAKE_UP_PARMS));

	if (((BWCflag == ALL_WITHOUT_BWC) || (extType == DWCext)) &&
	    (WakeUpParms.u0.boot_bios_wd[0])) {
		*numBootImage = 0;
	}
	/* incoming buffer is without aif header */
	NextImage = 0x84 - sizeof (AIF_HDR);
	BufferSize -= (sizeof (AIF_HDR) + sizeof (uint32_t));

	while (BufferSize > NextImage) {
		Sptr = &Buffer[NextImage];
		Dptr = (caddr_t)&ImageHdr;
		for (i = 0; i < sizeof (IMAGE_HDR); i++) {
			Dptr[i] = Sptr[i];
		}

		if (ImageHdr.BlockSize == 0xffffffff) {
			break;
		}
		switch (ImageHdr.Id.Type) {
		case TEST_PROGRAM:
			break;

		case FUNC_FIRMWARE:
			AbsWakeUpParms->prog_id = ImageHdr.Id;
			ChangeParams = TRUE;
			break;

		case BOOT_BIOS:
			if (!WakeUpParms.u0.boot_bios_wd[0]) {
				if (extType == DWCext) {
					break;
				} else if (BWCflag == ALL_WITHOUT_BWC) {
					/* for possible future * changes */
					break;
				}
			}
			ChangeParams = TRUE;

			if (*numBootImage < MAX_BOOTID) {
				BootId[*numBootImage] = ImageHdr.Id;
				(*numBootImage)++;
			}
			break;

		case SLI1_OVERLAY:
			AbsWakeUpParms->sli1_prog_id = ImageHdr.Id;
			ChangeParams = TRUE;
			break;

		case SLI2_OVERLAY:
			AbsWakeUpParms->sli2_prog_id = ImageHdr.Id;
			ChangeParams = TRUE;
			break;

		case SLI3_OVERLAY:
			AbsWakeUpParms->sli3_prog_id = ImageHdr.Id;
			ChangeParams = TRUE;
			break;

		case SLI4_OVERLAY:
			AbsWakeUpParms->sli4_prog_id = ImageHdr.Id;
			ChangeParams = TRUE;
			break;
		}

		NextImage += ImageHdr.BlockSize;
	}

	if ((ChangeParams) && ((BWCflag == ALL_WITHOUT_BWC) ||
	    (extType == DWCext))) {

		if (*numBootImage > 1) {
			for (i = 0; i < *numBootImage; i++) {
				ptr1 = (uint32_t *)&WakeUpParms.u0.boot_bios_id;
				ptr2 = (uint32_t *)&BootId[i];

				if (ptr1[0] == ptr2[0]) {
					AbsWakeUpParms->u1.EROM_prog_id =
					    BootId[i];
					(void) emlxs_update_exp_rom(hba,
					    AbsWakeUpParms);
					break;
				}
			}
		} else {
			if (*numBootImage == 1) {
				ptr2 = (uint32_t *)&BootId[0];

				if (WakeUpParms.u0.boot_bios_wd[0] == ptr2[0]) {
					AbsWakeUpParms->u1.EROM_prog_id =
					    BootId[0];
					(void) emlxs_update_exp_rom(hba,
					    AbsWakeUpParms);
				}
			}
		}
	}
	return (ChangeParams);


} /* emlxs_build_parms_2mb_dwc() */


extern uint32_t
emlxs_get_max_sram(emlxs_hba_t *hba, uint32_t *MaxRbusSize,
    uint32_t *MaxIbusSize)
{
	emlxs_port_t *port = &PPORT;
	MAILBOXQ *mbox;
	MAILBOX *mb;
	uint32_t *Uptr;
	uint32_t rval = 0;

	if ((mbox = (MAILBOXQ *)
	    kmem_zalloc(sizeof (MAILBOXQ), KM_NOSLEEP)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to allocate mailbox buffer.");

		return (1);
	}
	mb = (MAILBOX *)mbox;

	emlxs_format_dump(mb, DMP_MEM_REG, 0, 2, MAX_RBUS_SRAM_SIZE_ADR);

	if ((rval = emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0)) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_download_failed_msg,
		    "Unable to get SRAM size: Mailbox cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		rval = 1;

		goto Exit_Function;
	}
	Uptr = (uint32_t *)&mb->un.varDmp.resp_offset;

	*MaxRbusSize = Uptr[0];
	*MaxIbusSize = Uptr[1];

Exit_Function:

	if (mbox) {
		kmem_free(mbox, sizeof (MAILBOXQ));
	}
	return (rval);

} /* emlxs_get_max_sram() */


static uint32_t
emlxs_kern_check(emlxs_hba_t *hba, uint32_t version)
{
	uint8_t *ptr;
	uint8_t ver;

	ver = version & 0xff;
	ptr = hba->model_info.pt_FF;

	while (*ptr) {
		if (*ptr++ == ver) {
			return (1);
		}
	}

	return (0);

} /* emlxs_kern_check() */

static uint32_t
emlxs_stub_check(emlxs_hba_t *hba, uint32_t version)
{
	uint8_t *ptr;
	uint8_t ver;

	ver = version & 0xff;
	ptr = hba->model_info.pt_2;

	while (*ptr) {
		if (*ptr++ == ver) {
			return (1);
		}
	}

	return (0);

} /* emlxs_stub_check() */

static uint32_t
emlxs_bios_check(emlxs_hba_t *hba, uint32_t version)
{
	uint8_t *ptr;
	uint8_t ver;

	ver = version & 0xff;
	ptr = hba->model_info.pt_3;

	while (*ptr) {
		if (*ptr++ == ver) {
			return (1);
		}
	}

	return (0);

} /* emlxs_bios_check() */

static uint32_t
emlxs_sli1_check(emlxs_hba_t *hba, uint32_t version)
{
	uint8_t *ptr;
	uint8_t ver;

	ver = version & 0xff;
	ptr = hba->model_info.pt_6;

	while (*ptr) {
		if (*ptr++ == ver) {
			return (1);
		}
	}

	return (0);

} /* emlxs_sli1_check() */

static uint32_t
emlxs_sli2_check(emlxs_hba_t *hba, uint32_t version)
{
	uint8_t *ptr;
	uint8_t ver;

	ver = version & 0xff;
	ptr = hba->model_info.pt_7;

	while (*ptr) {
		if (*ptr++ == ver) {
			return (1);
		}
	}

	return (0);

} /* emlxs_sli2_check() */

static uint32_t
emlxs_sli3_check(emlxs_hba_t *hba, uint32_t version)
{
	uint8_t *ptr;
	uint8_t ver;

	ver = version & 0xff;
	ptr = hba->model_info.pt_B;

	while (*ptr) {
		if (*ptr++ == ver) {
			return (1);
		}
	}

	return (0);

} /* emlxs_sli3_check() */


static uint32_t
emlxs_sli4_check(emlxs_hba_t *hba, uint32_t version)
{
	uint8_t *ptr;
	uint8_t ver;

	ver = version & 0xff;
	ptr = hba->model_info.pt_E;

	while (*ptr) {
		if (*ptr++ == ver) {
			return (1);
		}
	}

	return (0);

} /* emlxs_sli4_check() */


static uint32_t
emlxs_sbus_fcode_check(emlxs_hba_t *hba, uint32_t version)
{
	uint8_t *ptr;
	uint8_t ver;

	ver = version & 0xff;
	ptr = hba->model_info.pt_A;

	while (*ptr) {
		if (*ptr++ == ver) {
			return (1);
		}
	}

	return (0);

} /* emlxs_sbus_fcode_check() */

static uint32_t
emlxs_type_check(uint32_t type)
{
	if (type == 0xff) {
		return (KERNEL_CODE);
	}
	if (type >= MAX_PROG_TYPES) {
		return (RESERVED_D);
	}
	return (type);

} /* emlxs_type_check() */



extern uint32_t
emlxs_boot_code_disable(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	PROG_ID Id;
	emlxs_vpd_t *vpd;

	vpd = &VPD;

	if (emlxs_read_wakeup_parms(hba, &hba->wakeup_parms, 0)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "emlxs_boot_code_disable: Unable to read wake up parms.");

		return ((uint32_t)FC_FAILURE);
	}
	/* Check if boot code is already disabled */
	if (hba->wakeup_parms.u0.boot_bios_wd[0] == 0) {
		return (FC_SUCCESS);
	}
	/* Make sure EROM entry has copy of boot bios entry */
	if (!(hba->model_info.chip &
	    (EMLXS_DRAGONFLY_CHIP | EMLXS_CENTAUR_CHIP)) &&
	    (hba->wakeup_parms.u0.boot_bios_wd[0] !=
	    hba->wakeup_parms.u1.EROM_prog_wd[0]) &&
	    (hba->wakeup_parms.u0.boot_bios_wd[1] !=
	    hba->wakeup_parms.u1.EROM_prog_wd[1])) {
		(void) emlxs_update_boot_wakeup_parms(hba, &hba->wakeup_parms,
		    &hba->wakeup_parms.u0.boot_bios_id, 1);
	}
	/* Update the bios id with a zero id */
	/* Don't load the EROM this time */
	bzero(&Id, sizeof (PROG_ID));
	(void) emlxs_update_boot_wakeup_parms(hba, &hba->wakeup_parms, &Id, 0);

	/* Now read the parms again to verify */
	(void) emlxs_read_wakeup_parms(hba, &hba->wakeup_parms, 1);
	emlxs_decode_version(hba->wakeup_parms.u0.boot_bios_wd[0],
	    vpd->boot_version);
	/* (void) strcpy(vpd->fcode_version, vpd->boot_version); */

	/* Return the result */
	return ((hba->wakeup_parms.u0.boot_bios_wd[0] == 0)
	    ? FC_SUCCESS : FC_FAILURE);

} /* emlxs_boot_code_disable() */


extern uint32_t
emlxs_boot_code_enable(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	emlxs_vpd_t *vpd;
	PROG_ID load_list[MAX_LOAD_ENTRY];
	uint32_t i;

	vpd = &VPD;

	/* Read the wakeup parms */
	if (emlxs_read_wakeup_parms(hba, &hba->wakeup_parms, 0)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "emlxs_boot_code_enable: Unable to read wake up parms.");

		return ((uint32_t)FC_FAILURE);
	}
	/* Check if boot code is already enabled */
	if (hba->wakeup_parms.u0.boot_bios_id.Type == BOOT_BIOS) {
		return (FC_SUCCESS);
	}
	if (!(hba->model_info.chip &
	    (EMLXS_DRAGONFLY_CHIP | EMLXS_CENTAUR_CHIP))) {
		if (hba->wakeup_parms.u1.EROM_prog_id.Type != BOOT_BIOS) {
			return (EMLXS_NO_BOOT_CODE);
		}
		/* Update the parms with the boot image id */
		/* Don't load the EROM this time */
		(void) emlxs_update_boot_wakeup_parms(hba, &hba->wakeup_parms,
		    &hba->wakeup_parms.u1.EROM_prog_id, 0);
	} else {	/* (EMLXS_DRAGONFLY_CHIP | EMLXS_CENTAUR_CHIP) */
		if (emlxs_get_load_list(hba, load_list)) {
			return ((uint32_t)FC_FAILURE);
		}
		/* Scan load list for a boot image */
		for (i = 0; i < MAX_LOAD_ENTRY; i++) {
			if (load_list[i].Type == BOOT_BIOS) {
				/* Update the parms with the boot image id */
				/* Don't load the EROM this time */
				(void) emlxs_update_boot_wakeup_parms(hba,
				    &hba->wakeup_parms, &load_list[i], 0);

				break;
			}
		}

		if (i == MAX_LOAD_ENTRY) {
			return (EMLXS_NO_BOOT_CODE);
		}
	}

	/* Now read the parms again to verify */
	(void) emlxs_read_wakeup_parms(hba, &hba->wakeup_parms, 1);
	emlxs_decode_version(hba->wakeup_parms.u0.boot_bios_wd[0],
	    vpd->boot_version);
	/* strcpy(vpd->fcode_version, vpd->boot_version); */

	/* return the result */
	return ((hba->wakeup_parms.u0.boot_bios_wd[0] != 0)
	    ? FC_SUCCESS : FC_FAILURE);

} /* emlxs_boot_code_enable() */



extern uint32_t
emlxs_boot_code_state(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;

	/* Read the wakeup parms */
	if (emlxs_read_wakeup_parms(hba, &hba->wakeup_parms, 1)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sfs_debug_msg,
		    "emlxs_boot_code_state: Unable to read wake up parms.");

		return ((uint32_t)FC_FAILURE);
	}
	/* return the result */
	return ((hba->wakeup_parms.u0.boot_bios_wd[0] != 0)
	    ? FC_SUCCESS : FC_FAILURE);

} /* emlxs_boot_code_state() */
