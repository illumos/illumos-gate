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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * ConnectX (hermon) firmware image verification plugin
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <sys/condvar.h>
#include <string.h>
#include <strings.h>

#include <sys/byteorder.h>

#include <libintl.h> /* for gettext(3c) */

#include <fwflash/fwflash.h>
#include "../hdrs/hermon_ib.h"

char vendor[] = "MELLANOX\0";

extern struct vrfyplugin *verifier;


/* required functions for this plugin */
int vendorvrfy(struct devicelist *devicenode);

/* helper functions */
static uint16_t cnx_check_hwver_img(ib_cnx_encap_ident_t *handle);
static void cnx_flash_verify_flash_match_img(ib_cnx_encap_ident_t *handle);
static void cnx_flash_verify_flash_pn_img(ib_cnx_encap_ident_t *handle,
    uchar_t *psid, int psid_size);
static uchar_t *cnx_flash_get_psid_img(ib_cnx_encap_ident_t *handle);
static void cnx_display_fwver(ib_cnx_encap_ident_t *handle);
static int cnx_check_guid_section();


int
vendorvrfy(struct devicelist *devicenode)
{
	struct ib_cnx_encap_ident_s	*handle;
	uint16_t	ver;

	logmsg(MSG_INFO, "hermon: vendorvrfy \n");

	handle = (struct ib_cnx_encap_ident_s *)devicenode->ident->encap_ident;

	if (CNX_I_CHECK_HANDLE(handle)) {
		logmsg(MSG_ERROR, gettext("hermon: Invalid Handle for "
		    "device %s! \n"), devicenode->access_devname);
		return (FWFLASH_FAILURE);
	}

	/*
	 * NOTE verifier->fwimage is where file is read to.
	 */
	if (cnx_is_magic_pattern_present(&verifier->fwimage[0], 1) !=
	    FWFLASH_SUCCESS) {
		logmsg(MSG_ERROR, gettext("%s firmware image verifier: "
		    "No magic pattern found in firmware file %s \n"),
		    verifier->vendor, verifier->imgfile);
		return (FWFLASH_FAILURE);
	}

	if (cnx_check_guid_section() == FWFLASH_FAILURE) {
		logmsg(MSG_INFO, "%s firmware image verifier: "
		    "Firmware Image GUID section is invalid\n",
		    verifier->vendor);
	}

	cnx_flash_verify_flash_match_img(handle);

	/* Check Hardware Rev */
	ver = cnx_check_hwver_img(handle);
	if (ver != 0) {
		logmsg(MSG_ERROR, gettext("hermon: Firmware mismatch: "
		    "ver(0x%X) hw_ver(0x%X)\n"), (ver >> 8), ver & 0xFF);
		return (FWFLASH_FAILURE);
	}

	if (handle->hwfw_match == 0) {
		int resp;

		if (handle->pn_len != 0) {
			/* HW VPD exist and a mismatch was found */
			logmsg(MSG_ERROR, gettext("hermon: Please verify that "
			    "the firmware image is intended for use with this "
			    "hardware\n"));
		} else {
			logmsg(MSG_ERROR, gettext("hermon: Unable to verify "
			    "firmware is appropriate for the hardware\n"));
		}
		logmsg(MSG_ERROR, gettext("Do you want to continue? (Y/N): "));
		(void) fflush(stdin);
		resp = getchar();
		if (resp != 'Y' && resp != 'y') {
			logmsg(MSG_ERROR, gettext("Not proceeding with "
			    "flash operation of %s on %s"),
			    verifier->imgfile, devicenode->drvname);
			return (FWFLASH_FAILURE);
		}
	} else {
		logmsg(MSG_INFO, "%s firmware image verifier: HCA PSID (%s) "
		    "matches firmware image %s's PSID\n", verifier->vendor,
		    handle->info.mlx_psid, verifier->imgfile);

		cnx_display_fwver(handle);
	}

	return (FWFLASH_SUCCESS);
}

static uint16_t
cnx_check_hwver_img(ib_cnx_encap_ident_t *handle)
{
	uint8_t	hwver;
	uint8_t	local_hwver;

	logmsg(MSG_INFO, "hermon: verify: cnx_check_hwver_img\n");
	if ((handle->state & FWFLASH_IB_STATE_IMAGE_PRI) == 0 &&
	    (handle->state & FWFLASH_IB_STATE_IMAGE_SEC) == 0) {
		logmsg(MSG_ERROR, gettext("hermon: Must read in image "
		    "first\n"));
		return (1);
	}

	/* Read Flash HW Version */
	hwver = (uint8_t)handle->hwrev;
	local_hwver = (ntohl(verifier->fwimage[CNX_HWVER_OFFSET / 4]) &
	    CNX_HWVER_MASK) >> 24;

	logmsg(MSG_INFO, "local_hwver: %x, hwver: %x\n", local_hwver, hwver);

	if ((hwver == 0xA0 || hwver == 0x00 || hwver == 0x20) &&
	    (local_hwver == 0x00 || local_hwver == 0xA0 ||
	    local_hwver == 0x20)) {
		logmsg(MSG_INFO, ("A0 board found.\r\n"));
	} else if (hwver == 0xA1 && local_hwver == 0xA1) {
		logmsg(MSG_INFO, ("A1 board found.\r\n"));
	} else if (hwver == 0xA2 && local_hwver == 0xA2) {
		logmsg(MSG_INFO, ("A2 board found.\r\n"));
	} else if (hwver == 0xA3 && local_hwver == 0xA3) {
		logmsg(MSG_INFO, ("A3 board found.\r\n"));
	} else {
		return ((uint16_t)(local_hwver << 8) | hwver);
	}
	return (0);
}

static void
cnx_display_fwver(ib_cnx_encap_ident_t *handle)
{
	logmsg(MSG_INFO, "hermon: verify: cnx_display_fwver\n");

	(void) fprintf(stdout, gettext("  The current HCA firmware version "
	    "is    : %d.%d.%03d\n"),
	    handle->hwfw_img_info.fw_rev.major,
	    handle->hwfw_img_info.fw_rev.minor,
	    handle->hwfw_img_info.fw_rev.subminor);
	(void) fprintf(stdout, gettext("  Will be updated to HCA firmware "
	    "ver of : %d.%d.%03d\n"),
	    handle->file_img_info.fw_rev.major,
	    handle->file_img_info.fw_rev.minor,
	    handle->file_img_info.fw_rev.subminor);
}

static uchar_t *
cnx_flash_get_psid_img(ib_cnx_encap_ident_t *handle)
{
	uint32_t	ii_ptr_addr;
	uint32_t	ii_size;

	logmsg(MSG_INFO, "hermon: verify: cnx_flash_get_psid_img\n");

	/* Get the image info pointer */
	ii_ptr_addr = ntohl(verifier->fwimage[CNX_IMG_INF_PTR_OFFSET / 4]);
	ii_ptr_addr &= 0xffffff; /* Bits 23:0 - Image Info Data Pointer */

	/* Get the image info size, a negative offset from the image info ptr */
	ii_size =
	    ntohl(verifier->fwimage[(ii_ptr_addr + CNX_IMG_INF_SZ_OFFSET) / 4]);
	/* size is in dwords--convert it to bytes */
	ii_size *= 4;

	logmsg(MSG_INFO, "ImgInfo_ptr_addr: 0x%lx, ImgInfo_size: 0x%x\n",
	    ii_ptr_addr, ii_size);

	/* Parse the image info section */
	if (cnx_parse_img_info(&verifier->fwimage[ii_ptr_addr / 4], ii_size,
	    &handle->file_img_info, CNX_FILE_IMG) != FWFLASH_SUCCESS) {
		logmsg(MSG_WARN, gettext("hermon: Failed to parse ImageInfo "
		    "section\n"));
		return (NULL);
	}

	return (handle->file_img_info.psid);
}

static void
cnx_flash_verify_flash_pn_img(ib_cnx_encap_ident_t *handle, uchar_t *psid,
    int psid_size)
{
	int	i;
	int	no_match = 0;

	logmsg(MSG_INFO, "hermon: verify: cnx_flash_verify_flash_pn_img\n");
	/* verify fw matches the hardware */
	if (handle->hwfw_match == 1) {
		/* already been verified */
		return;
	}

	/* find the PSID from FW in the mlx table */
	for (i = 0; i < MLX_MAX_ID; i++) {
		if (handle->hwfw_match == 1) {
			/*
			 * Need this check here and the 'continue's below
			 * because there are some cards that have a
			 * 'new' part number but the same PSID value.
			 */
			break;
		}

		/* match PSID */
		if (strncmp((const char *)psid, mlx_mdr[i].mlx_psid,
		    psid_size) == 0) {
			logmsg(MSG_INFO, "Found Matching firmware image's "
			    "PSID (%s) entry in MDR Table\n", psid);

			logmsg(MSG_INFO, "Search for firmware image's part# "
			    "(%s), MDR/HW PN (%s) \n",
			    handle->info.mlx_pn, mlx_mdr[i].mlx_pn);

			/* match part numbers */
			if (strncmp(handle->info.mlx_pn, mlx_mdr[i].mlx_pn,
			    handle->pn_len) == 0) {
				handle->hwfw_match = 1;
				logmsg(MSG_INFO, "Match Found \n");
				continue;
			} else {
				handle->hwfw_match = 0;
				no_match = i;
				logmsg(MSG_INFO, "Match NOT Found \n");
				continue;
			}
		}
	}
	if (i == MLX_MAX_ID && no_match == 0) {
		/* no match found */
		handle->hwfw_match = 0;
		handle->pn_len = 0;
		logmsg(MSG_WARN, gettext("hermon: No PSID match found\n"));
	} else {
		if (handle->hwfw_match == 0) {
			logmsg(MSG_WARN, gettext("WARNING: Firmware "
			    "image is meant for %s but the hardware "
			    "is %s\n"), mlx_mdr[no_match].mlx_pn,
			    handle->info.mlx_pn);
		}
	}
}

static void
cnx_flash_verify_flash_match_img(ib_cnx_encap_ident_t *handle)
{
	uchar_t	*psid;

	logmsg(MSG_INFO, "hermon: verify: cnx_flash_verify_flash_match_img\n");
	/* get PSID of firmware file */
	psid = cnx_flash_get_psid_img(handle);
	if (psid == NULL) {
		handle->hwfw_match = 0;
		handle->pn_len = 0;
		return;
	}
	logmsg(MSG_INFO, "FW PSID (%s)\n", psid);

	/*
	 * Check the part number of the hardware against the part number
	 * of the firmware file. If the hardware information is not
	 * available, check the currently loaded firmware against the
	 * firmware file to be uploaded.
	 */
	if (handle->pn_len != 0) {
		cnx_flash_verify_flash_pn_img(handle, psid, CNX_PSID_SZ);
	}
}


static int
cnx_check_guid_section()
{
	struct mlx_cnx_xfi  		xfisect;
	struct mlx_cnx_guid_sect	guidsect;
	uint32_t			nguidptr_addr;
	uint16_t			calculated_crc;

	logmsg(MSG_INFO, "cnx_check_guid_section: \n");

	bcopy(&verifier->fwimage[0], &xfisect, sizeof (struct mlx_cnx_xfi));
	logmsg(MSG_INFO, "FailSafeChunkSz: 0x%08x, ImageInfoPtr: 0x%08x\n",
	    MLXSWAPBITS32(xfisect.failsafechunkinfo),
	    MLXSWAPBITS32(xfisect.imageinfoptr) & CNX_XFI_IMGINFO_PTR_MASK);
	logmsg(MSG_INFO, "FW Size: 0x%08x NGUIDPTR: 0x%08x\n",
	    MLXSWAPBITS32(xfisect.fwimagesz), MLXSWAPBITS32(xfisect.nguidptr));

	nguidptr_addr = (MLXSWAPBITS32(xfisect.nguidptr) - 0x10) / 4;
	bcopy(&verifier->fwimage[nguidptr_addr], &guidsect,
	    sizeof (struct mlx_cnx_guid_sect));

	logmsg(MSG_INFO, "Node GUID : 0x%016llx \n",
	    MLXSWAPBITS64(guidsect.nodeguid));
	logmsg(MSG_INFO, "Port1 GUID: 0x%016llx \n",
	    MLXSWAPBITS64(guidsect.port1guid));
	logmsg(MSG_INFO, "Port2 GUID: 0x%016llx \n",
	    MLXSWAPBITS64(guidsect.port2guid));
	logmsg(MSG_INFO, "SysIm GUID: 0x%016llx \n",
	    MLXSWAPBITS64(guidsect.sysimguid));
	logmsg(MSG_INFO, "Port 1 MAC: 0x%016llx \n",
	    MLXSWAPBITS64(guidsect.port1_mac));
	logmsg(MSG_INFO, "Port 2 MAC: 0x%016llx \n",
	    MLXSWAPBITS64(guidsect.port2_mac));

	calculated_crc = cnx_crc16((uint8_t *)&verifier->fwimage[nguidptr_addr],
	    CNX_GUID_CRC16_SIZE, CNX_FILE_IMG);
	if (calculated_crc != ntohs(guidsect.guidcrc)) {
		logmsg(MSG_WARN, gettext("hermon: calculated crc value 0x%x "
		    "differs from GUID section 0x%x\n"), calculated_crc,
		    ntohs(guidsect.guidcrc));
	} else {
		logmsg(MSG_INFO, "hermon: calculated crc value 0x%x MATCHES "
		    "with GUID section 0x%x\n", calculated_crc,
		    ntohs(guidsect.guidcrc));
	}

	if ((MLXSWAPBITS64(guidsect.nodeguid) == MLX_DEFAULT_NODE_GUID) &&
	    (MLXSWAPBITS64(guidsect.port1guid) == MLX_DEFAULT_P1_GUID) &&
	    (MLXSWAPBITS64(guidsect.port2guid) == MLX_DEFAULT_P2_GUID) &&
	    ((MLXSWAPBITS64(guidsect.sysimguid) == MLX_DEFAULT_SYSIMG_GUID) ||
	    (MLXSWAPBITS64(guidsect.sysimguid) == MLX_DEFAULT_NODE_GUID)) ||
	    ((((MLXSWAPBITS64(guidsect.nodeguid) & HIGHBITS64) >> 40) ==
	    MLX_OUI) ||
	    (((MLXSWAPBITS64(guidsect.port1guid) & HIGHBITS64) >> 40) ==
	    MLX_OUI) ||
	    (((MLXSWAPBITS64(guidsect.port2guid) & HIGHBITS64) >> 40) ==
	    MLX_OUI) ||
	    (((MLXSWAPBITS64(guidsect.sysimguid) & HIGHBITS64) >> 40) ==
	    MLX_OUI)) ||
	    ((((MLXSWAPBITS64(guidsect.nodeguid) & HIGHBITS64) >> 40) ==
	    SUNW_OUI) ||
	    (((MLXSWAPBITS64(guidsect.port1guid) & HIGHBITS64) >> 40) ==
	    SUNW_OUI) ||
	    (((MLXSWAPBITS64(guidsect.port2guid) & HIGHBITS64) >> 40) ==
	    SUNW_OUI) ||
	    (((MLXSWAPBITS64(guidsect.sysimguid) & HIGHBITS64) >> 40) ==
	    SUNW_OUI))) {
		logmsg(MSG_INFO, "%s firmware image verifier: GUID Prefix "
		    "is as expected\n", verifier->vendor);
		return (FWFLASH_SUCCESS);
	} else {
		logmsg(MSG_INFO, "%s firmware image verifier: GUID prefix "
		    "is not as expected\n", verifier->vendor);
		return (FWFLASH_FAILURE);
	}
}
