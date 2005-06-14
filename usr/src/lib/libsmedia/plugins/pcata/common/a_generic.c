/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * a_generic.c :
 *      This file contains generic PCATA related functions for pcata plug-in
 * 	for libsm.so.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/dkio.h>
#include <sys/dktp/dadkio.h>
#include <string.h>
#include "../../../library/inc/smedia.h"
#include "../../../library/inc/rmedia.h"
#include "../../../library/common/l_defines.h"

#define	PERROR(string)  my_perror(gettext(string))

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
	return (SM_PCATA_VERSION_1);
}

int32_t
_m_device_type(ushort_t ctype, ushort_t mtype)
{
	if (ctype == DKC_PCMCIA_ATA) {
		if (mtype == 0)
			return (0);
	}
	return (-1);
}


int32_t
_m_get_media_info(rmedia_handle_t *handle, void *ip)
{
	smmedium_prop_t *medinfo = ip;
	struct dk_minfo media_info;
	struct dk_geom	dkgeom;
	int32_t ret_val;
	enum dkio_state state = DKIO_NONE;

	if (handle == NULL) {
		DPRINTF("Null Handle\n");
		errno = EINVAL;
		return (-1);
	}
	if (handle->sm_signature != (int32_t)LIBSMEDIA_SIGNATURE) {
		DPRINTF2(
		    "Signature expected=0x%x, found=0x%x\n",
		    LIBSMEDIA_SIGNATURE, handle->sm_signature);
		errno = EINVAL;
		return (-1);
	}
	if (handle->sm_fd < 0) {
		DPRINTF("Invalid file handle.\n");
		errno = EINVAL;
		return (-1);
	}
	if (ioctl(handle->sm_fd, DKIOCSTATE, &state) < 0) {
		PERROR("DKIOCSTATE failed");
		return (-1);
	}
	if (state != DKIO_INSERTED) {
		DPRINTF("No media.\n");
		medinfo->sm_media_type = SM_NOT_PRESENT;
		medinfo->sm_version = SMMEDIA_PROP_V_1;
		return (0);
	}

	(void) memset((void *) medinfo, 0, sizeof (smmedium_prop_t));

	ret_val = ioctl(handle->sm_fd, DKIOCGMEDIAINFO, &media_info);
	if (ret_val < 0) {
		DPRINTF("DKIOCGMEDIAINFO ioctl failed");
		return (ret_val);
	}

	medinfo->sm_media_type = media_info.dki_media_type;
	medinfo->sm_blocksize = media_info.dki_lbsize;
	medinfo->sm_capacity = media_info.dki_capacity;

	/* Is it a removable magnetic disk? */
	if (medinfo->sm_media_type == DK_FIXED_DISK) {
		int32_t removable = 0;

		ret_val = ioctl(handle->sm_fd, DKIOCREMOVABLE, &removable);
		if (ret_val < 0) {
			DPRINTF("DKIOCREMOVABLE ioctl failed");
			return (ret_val);
		}
		if (removable) {
			medinfo->sm_media_type = SM_PCMCIA_ATA;
		}
	}
	ret_val = ioctl(handle->sm_fd, DKIOCGGEOM, &dkgeom);
	if (ret_val < 0) {
#ifdef sparc
		DPRINTF("DKIOCGGEOM ioctl failed");
		return (ret_val);
#else /* !sparc */
		/*
		 * Try getting Physical geometry on x86.
		 */
		ret_val = ioctl(handle->sm_fd, DKIOCG_PHYGEOM, &dkgeom);
		if (ret_val < 0) {
			DPRINTF("DKIOCG_PHYGEOM ioctl failed");
			return (ret_val);
		}
#endif /* sparc */
	}

	medinfo->sm_pcyl = dkgeom.dkg_pcyl;
	medinfo->sm_nhead = dkgeom.dkg_nhead;
	medinfo->sm_nsect = dkgeom.dkg_nsect;

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
		DPRINTF2(
			"Signature expected=0x%x, found=0x%x\n",
			LIBSMEDIA_SIGNATURE, handle->sm_signature);
		errno = EINVAL;
		return (-1);
	}
	if (handle->sm_fd < 0) {
		DPRINTF("Invalid file handle.\n");
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

	vendor_name[0] = NULL;
	product_name[0] = NULL;
	fw_version[0] = NULL;
	mp->sm_interface_type = IF_PCMCIA;
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
