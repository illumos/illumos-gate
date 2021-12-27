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
 * b_generic.c :
 *      This file contains the functions for generic block devices
 *	for libsmedia.
 */

#include <stdio.h>
#include <unistd.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/dkio.h>
#include <string.h>
#include "../../../library/inc/smedia.h"
#include "../../../library/inc/rmedia.h"
#include "../../../library/common/l_defines.h"

#define	PERROR(string)	my_perror(gettext(string))

static void
my_perror(char *err_string)
{

	int error_no;
	if (errno == 0)
		return;

	error_no = errno;
	(void) fprintf(stderr, gettext(err_string));
	(void) fprintf(stderr, gettext(" : "));
	errno = error_no;
	perror("");
}

int32_t
_m_version_no(void)
{
	return (SM_BLKDEV_VERSION_1);
}

int32_t
_m_device_type(ushort_t ctype, ushort_t mtype)
{
	if (ctype == DKC_BLKDEV) {
		if (mtype == 0)
			return (0);
	}
	return (-1);
}


int32_t
_m_get_media_info(rmedia_handle_t *handle, void *ip)
{
	smmedium_prop_t *mp = (smmedium_prop_t *)ip;
	struct dk_geom		dkg;
	struct dk_minfo		minfo;
	enum dkio_state		state = DKIO_NONE;
	int			ret_val;

	if (handle == NULL) {
		DPRINTF("Null Handle\n");
		errno = EINVAL;
		return (-1);
	}
	if (handle->sm_signature != (int32_t)LIBSMEDIA_SIGNATURE) {
		DPRINTF2("Signature expected=0x%x, found=0x%x\n",
		    LIBSMEDIA_SIGNATURE, handle->sm_signature);
		errno = EINVAL;
		return (-1);
	}

	if (ioctl(handle->sm_fd, DKIOCSTATE, &state) < 0) {
		PERROR("DKIOCSTATE failed");
		return (-1);
	}

	if (state != DKIO_INSERTED) {
		DPRINTF("No media.\n");
		mp->sm_media_type = SM_NOT_PRESENT;
		mp->sm_version = SMMEDIA_PROP_V_1;
		return (0);

	}

	ret_val = ioctl(handle->sm_fd, DKIOCGMEDIAINFO, &minfo);
	if (ret_val < 0) {
		DPRINTF("DKIOCGMEDIAINFO ioctl failed");
		return (ret_val);
	}
	ret_val = ioctl(handle->sm_fd, DKIOCGGEOM, &dkg);
	if (ret_val < 0) {
		DPRINTF("DKIOCGGEOM ioctl failed");
		return (ret_val);
	}

	mp->sm_media_type = SM_BLOCK;
	mp->sm_blocksize = minfo.dki_lbsize;
	mp->sm_capacity = minfo.dki_capacity;
	mp->sm_pcyl = dkg.dkg_pcyl;
	mp->sm_nhead = dkg.dkg_nhead;
	mp->sm_nsect = dkg.dkg_nsect;
	return (0);
}



/* ARGSUSED0 */

int32_t
_m_get_device_info(rmedia_handle_t *handle, void *ip)
{
	smdevice_info_t *mp = (smdevice_info_t *)ip;
	char *vendor_name, *product_name, *fw_version;

	if (handle == NULL) {
		DPRINTF("Null Handle\n");
		errno = EINVAL;
		return (-1);
	}
	if (handle->sm_signature != (int32_t)LIBSMEDIA_SIGNATURE) {
		DPRINTF2("Signature expected=0x%x, found=0x%x\n",
		    LIBSMEDIA_SIGNATURE, handle->sm_signature);
		errno = EINVAL;
		return (-1);
	}
	vendor_name = (char *)malloc(1);
	if (vendor_name == NULL) {
		if (!errno)
			errno = ENOMEM;
		return (-1);
	}
	product_name = (char *)malloc(1);
	if (product_name == NULL) {
		free(vendor_name);
		if (!errno)
			errno = ENOMEM;
		return (-1);
	}

	fw_version = (char *)malloc(1);
	if (fw_version == NULL) {
		free(vendor_name);
		free(product_name);
			if (!errno)
		errno = ENOMEM;
		return (-1);
	}

	/* Note: we could potentially offer more here */
	vendor_name[0] = 0;
	product_name[0] = 0;
	fw_version[0] = 0;
	mp->sm_interface_type = IF_BLOCK;
	mp->sm_vendor_name = vendor_name;
	mp->sm_product_name = product_name;
	mp->sm_firmware_version = fw_version;
	return (0);
}

int32_t
_m_free_device_info(rmedia_handle_t *handle, void *ip)
{
	struct smdevice_info *dev_info = ip;

	/* Check for valid handle */
	if (handle == NULL) {
		DPRINTF("Null Handle\n");
		errno = EINVAL;
		return (-1);
	}
	if (handle->sm_signature != LIBSMEDIA_SIGNATURE) {
		DPRINTF("Invalid signature in handle.\n");
		errno = EINVAL;
		return (-1);
	}

	free(dev_info->sm_vendor_name);
	free(dev_info->sm_product_name);
	free(dev_info->sm_firmware_version);
	return (0);
}
