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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Mellanox firmware image verification plugin
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
#include "../hdrs/MELLANOX.h"
#include "../hdrs/tavor_ib.h"

char vendor[] = "MELLANOX\0";

extern int errno;
extern struct vrfyplugin *verifier;


/* required functions for this plugin */
int vendorvrfy(struct devicelist *devicenode);


/* helper functions */
static int check_guid_ptr(uint8_t *data);


int
vendorvrfy(struct devicelist *devicenode)
{
	struct ib_encap_ident	*encap;
	uint32_t	sector_sz;
	int		*firmware;
	uint32_t	vp_fia, vs_fia;
	uint32_t	vp_imginfo, vs_imginfo;
	struct mlx_xps	*vps;
	uint8_t		*vfi;
	int		i = 0, a, b, c, d;
	char		temppsid[17];
	char		rawpsid[16];
	int		offset;

	encap = (struct ib_encap_ident *)devicenode->ident->encap_ident;

	/*
	 * NOTE that since verifier->fwimage is an array of ints,
	 * we have to divide our actual desired number by 4 to get
	 * the right data.
	 */
	firmware = verifier->fwimage;

	/*
	 * The actual location of log2_sector_sz can be calculated
	 * by adding 0x32 to the value that is written in the
	 * log2_sector_sz_ptr field.  The log2_sector_sz_ptr is located
	 * at 0x16 byte offset in Invariant Sector.
	 */
	offset = FLASH_IS_SECTOR_SIZE_OFFSET +
	    MLXSWAPBITS32(firmware[FLASH_IS_SECT_SIZE_PTR/4]);

	sector_sz = 1 << MLXSWAPBITS32(firmware[offset/4]);

	if (sector_sz != encap->sector_sz) {
		logmsg(MSG_ERROR,
		    gettext("%s firmware image verifier: "
		    "Invariant Sector is invalid\n"), verifier->vendor);
		logmsg(MSG_ERROR, gettext("Mis-match in sector size: "
		    "device's 0x%X file 0x%X\n"), encap->sector_sz, sector_sz);
		logmsg(MSG_ERROR, gettext("Firmware image file is not "
		    "appropriate for this device.\n"));
		/* this is fatal */
		return (FWFLASH_FAILURE);
	}

	/* now verify primary pointer sector */
	if ((vps = calloc(1, sizeof (struct mlx_xps))) == NULL) {
		logmsg(MSG_ERROR,
		    gettext("%s firmware image verifier: "
		    "Unable to allocate memory for Primary Pointer "
		    "Sector verification\n"), verifier->vendor);
		return (FWFLASH_FAILURE);
	}
	bcopy(&firmware[sector_sz / 4], vps, sizeof (struct mlx_xps));
	if ((MLXSWAPBITS32(vps->signature) != FLASH_PS_SIGNATURE) ||
	    (vps->xpsresv3 != 0)) {
		logmsg(MSG_ERROR,
		    gettext("%s firmware image verifier: "
		    "Primary Pointer Sector is invalid\n"),
		    verifier->vendor);
	}
	vp_fia = MLXSWAPBITS32(vps->fia);

	/*
	 * A slight diversion - check the PSID in the last
	 * 16 bytes of the first 256bytes in the xPS sectors.
	 * This will give us our part number to match. If the
	 * part number in the image doesn't match the part number
	 * in the encap_ident info (and pn_len > 0) then we reject
	 * this image as being incompatible with the HCA.
	 *
	 * In this bit we're only checking the info.mlx_psid field
	 * of the primary image in the on-disk image. If that's
	 * invalid we reject the image.
	 */

	bzero(temppsid, 17);
	bcopy(vps->vsdpsid+0xd0, &rawpsid, 16);

	for (i = 0; i < 16; i += 4) {
		temppsid[i]   = rawpsid[i+3];
		temppsid[i+1] = rawpsid[i+2];
		temppsid[i+2] = rawpsid[i+1];
		temppsid[i+3] = rawpsid[i];
	}
	logmsg(MSG_INFO,
	    "tavor: have raw '%s', want munged '%s'\n",
	    rawpsid, temppsid);
	logmsg(MSG_INFO, "tavor_vrfy: PSID file '%s' HCA's PSID '%s'\n",
	    (temppsid != NULL) ? temppsid : "(null)",
	    (encap->info.mlx_psid != NULL) ? encap->info.mlx_psid : "(null)");

	if (encap->info.mlx_psid != NULL) {
		int resp;
		if (strncmp(encap->info.mlx_psid, temppsid, 16) != 0) {
			logmsg(MSG_ERROR,
			    gettext("%s firmware image verifier: "
			    "firmware image file %s is not appropriate "
			    "for device "
			    "%s (PSID file %s vs PSID device %s)\n"),
			    verifier->vendor, verifier->imgfile,
			    devicenode->drvname,
			    ((temppsid != NULL) ? temppsid : "(null)"),
			    encap->info.mlx_psid);

			logmsg(MSG_ERROR,
			    gettext("Do you want to continue? (Y/N): "));
			(void) fflush(stdin);
			resp = getchar();
			if (resp != 'Y' && resp != 'y') {
				free(vps);
				logmsg(MSG_ERROR, gettext("Not proceeding with "
				    "flash operation of %s on %s\n"),
				    verifier->imgfile, devicenode->drvname);
				return (FWFLASH_FAILURE);
			}
		} else {
			logmsg(MSG_INFO,
			    "%s firmware image verifier: HCA PSID (%s) "
			    "matches firmware image %s's PSID\n",
			    verifier->vendor,
			    encap->info.mlx_psid,
			    verifier->imgfile);
		}
	}


	/* now verify secondary pointer sector */
	bzero(vps, sizeof (struct mlx_xps));

	bcopy(&firmware[sector_sz / 2], vps, sizeof (struct mlx_xps));
	if ((MLXSWAPBITS32(vps->signature) != FLASH_PS_SIGNATURE) ||
	    (vps->xpsresv3 != 0)) {
		logmsg(MSG_ERROR,
		    gettext("%s firmware image verifier: "
		    "Secondary Pointer Sector is invalid\n"),
		    verifier->vendor);
	}
	vs_fia = MLXSWAPBITS32(vps->fia);

	(void) free(vps);

	if ((vfi = calloc(1, sector_sz)) == NULL) {
		logmsg(MSG_ERROR,
		    gettext("%s firmware image verifier: "
		    "Unable to allocate space for Primary "
		    "Firmware Image verification\n"),
		    verifier->vendor);
		return (FWFLASH_FAILURE);
	}
	bcopy(&firmware[vp_fia / 4], vfi, sector_sz);
	bcopy(&vfi[XFI_IMGINFO_OFFSET], &i, 4);
	vp_imginfo = MLXSWAPBITS32(i);

	/* for readability only */
	a = (vp_imginfo & 0xff000000) >> 24;
	b = (vp_imginfo & 0x00ff0000) >> 16;
	c = (vp_imginfo & 0x0000ff00) >> 8;
	d = (vp_imginfo & 0x000000ff);

	/*
	 * It appears to be the case (empirically) that this particular
	 * check condition for ImageInfoPtr doesn't hold for A1 firmware
	 * images. So if the ((a+b+c+d)%0x100) fails, don't worry unless
	 * the contents of the GUID section do not match the Mellanox
	 * default GUIDs 2c9000100d05[0123]. The A2++ images also have
	 * these default GUIDS.
	 *
	 * Unfortunately we can't depend on the hwrev field of the image's
	 * Invariant Sector for another level of confirmation, since A2++
	 * images seem to have that field set to 0xa1 as well as the A1
	 * images. Annoying!
	 */

	if ((((a+b+c+d) % 0x100) == 0) &&
	    (vp_imginfo != 0x00000000)) {
		logmsg(MSG_INFO,
		    "%s firmware image verifier: "
		    "Primary Firmware Image Info pointer is valid\n",
		    verifier->vendor);
	} else {

		logmsg(MSG_INFO,
		    gettext("%s firmware image verifier: "
		    "Primary Firmware Image Info pointer is invalid "
		    "(0x%04x)\nChecking GUID section.....\n"),
		    verifier->vendor, vp_imginfo);

		if (check_guid_ptr(vfi) == FWFLASH_FAILURE) {
			logmsg(MSG_INFO,
			    gettext("%s firmware image verifier: "
			    "Primary Firmware Image GUID section "
			    "is invalid\n"),
			    verifier->vendor);
			i = 1;
		} else {
			logmsg(MSG_INFO,
			    "%s firmware image verifier: "
			    "Primary GUID section is ok\n",
			    verifier->vendor);
		}

	}

	bzero(vfi, sector_sz);
	bcopy(&firmware[vs_fia / 4], vfi, sector_sz);

	bcopy(&vfi[XFI_IMGINFO_OFFSET], &i, 4);
	vs_imginfo = MLXSWAPBITS32(i);

	/* for readability only */
	a = (vs_imginfo & 0xff000000) >> 24;
	b = (vs_imginfo & 0x00ff0000) >> 16;
	c = (vs_imginfo & 0x0000ff00) >> 8;
	d = (vs_imginfo & 0x000000ff);

	if ((((a+b+c+d) % 0x100) == 0) &&
	    (vs_imginfo != 0x00000000)) {
		logmsg(MSG_INFO,
		    "%s firmware image verifier: "
		    "Secondary Firmware Image Info pointer is valid\n",
		    verifier->vendor);
	} else {
		logmsg(MSG_INFO,
		    gettext("%s firmware image verifier: "
		    "Secondary Firmware Image Info pointer is invalid "
		    "(0x%04x)\nChecking GUID section.....\n"),
		    verifier->vendor, vp_imginfo);

		if (check_guid_ptr(vfi) == FWFLASH_FAILURE) {
			logmsg(MSG_INFO,
			    gettext("%s firmware image verifier: "
			    "Secondary Firmware Image GUID section "
			    "is invalid\n"),
			    verifier->vendor);
			i++;
		}
	}

	free(vfi);

	if (i == 2)
		logmsg(MSG_WARN, gettext("%s firmware image verifier: "
		    "FAILED\n"), verifier->vendor);

	return ((i == 2) ? (FWFLASH_FAILURE) : (FWFLASH_SUCCESS));
}


/*
 * Very simple function - we're given an array of bytes,
 * we know that we need to read the value at offset FLASH_GUID_PTR
 * and jump to that location to read 4x uint64_t of (hopefully)
 * GUID data. If we can read that data, and it matches the default
 * Mellanox GUIDs, then we return success. We need all 4 default
 * GUIDs to match otherwise we return failure.
 */
static int
check_guid_ptr(uint8_t *data)
{
	struct mlx_xfi	xfisect;
	struct mlx_guid_sect	guidsect;

	bcopy(data, &xfisect, sizeof (xfisect));
	bcopy(&data[MLXSWAPBITS32(xfisect.nguidptr) - 16], &guidsect,
	    GUIDSECTION_SZ);

	logmsg(MSG_INFO, "nodeguid:  %0llx\n",
	    MLXSWAPBITS64(guidsect.nodeguid));
	logmsg(MSG_INFO, "port1guid: %0llx\n",
	    MLXSWAPBITS64(guidsect.port1guid));
	logmsg(MSG_INFO, "port2guid: %0llx\n",
	    MLXSWAPBITS64(guidsect.port2guid));
	logmsg(MSG_INFO, "sysimguid: %0llx\n",
	    MLXSWAPBITS64(guidsect.sysimguid));

	if ((MLXSWAPBITS64(guidsect.nodeguid) == MLX_DEFAULT_NODE_GUID) &&
	    (MLXSWAPBITS64(guidsect.port1guid) == MLX_DEFAULT_P1_GUID) &&
	    (MLXSWAPBITS64(guidsect.port2guid) == MLX_DEFAULT_P2_GUID) &&
	    ((MLXSWAPBITS64(guidsect.sysimguid) == MLX_DEFAULT_SYSIMG_GUID) ||
	    (MLXSWAPBITS64(guidsect.sysimguid) == MLX_DEFAULT_NODE_GUID)) ||
	    ((((MLXSWAPBITS64(guidsect.nodeguid) & HIGHBITS64) >> 40)
	    == MLX_OUI) ||
	    (((MLXSWAPBITS64(guidsect.port1guid) & HIGHBITS64) >> 40)
	    == MLX_OUI) ||
	    (((MLXSWAPBITS64(guidsect.port2guid) & HIGHBITS64) >> 40)
	    == MLX_OUI) ||
	    (((MLXSWAPBITS64(guidsect.sysimguid) & HIGHBITS64) >> 40)
	    == MLX_OUI))) {
		return (FWFLASH_SUCCESS);
	} else {
		return (FWFLASH_FAILURE);
	}
}
