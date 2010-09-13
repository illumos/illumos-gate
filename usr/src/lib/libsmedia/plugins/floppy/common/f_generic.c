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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * f_generic.c :
 *      This file contains all the functionalities except format of
 *	floppy plug-in for libsm.so.
 */

#include <sys/types.h>
#include <sys/fdio.h>
#include <stdlib.h>
#include <sys/smedia.h>
#include "../../../library/inc/rmedia.h"
#include "f_defines.h"


void
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
_m_device_type(ushort_t ctype, ushort_t mtype)
{
	if ((ctype == DKC_INTEL82077) || (ctype == DKC_UNKNOWN)) {
		if (mtype == 0)
			return (0);
	}
	return (-1);
}

int32_t
_m_version_no(void)
{
	return (SM_FD_VERSION_1);
}

int32_t
_m_get_media_info(rmedia_handle_t *handle, void *ip)
{
	smmedium_prop_t *med_info = (smmedium_prop_t *)ip;
struct fd_char fdchar;

	/* Check for valid handle */
	if (handle == NULL) {
		DPRINTF("Null Handle\n");
		errno = EINVAL;
		return (-1);
	}
	if (handle->sm_signature != (int32_t)LIBSMEDIA_SIGNATURE) {
		DPRINTF("Invalid signature in handle.\n");
		DPRINTF2(
			"Signature expected=0x%x found=0x%x\n",
				LIBSMEDIA_SIGNATURE,
				handle->sm_signature);
		errno = EINVAL;
		return (-1);
	}
	if (handle->sm_fd < 0) {
		DPRINTF("Invalid file handle.\n");
		errno = EINVAL;
		return (-1);
	}
	if (ioctl(handle->sm_fd, FDIOGCHAR, &fdchar) < 0) {
		PERROR("Ioctl failed :");
		return (-1);
	}

	med_info->sm_media_type = SM_FLOPPY;
	med_info->sm_blocksize  = fdchar.fdc_sec_size;
	med_info->sm_capacity = fdchar.fdc_ncyl * fdchar.fdc_nhead
					* fdchar.fdc_secptrack;
	med_info->sm_pcyl = fdchar.fdc_ncyl;
	med_info->sm_nhead = fdchar.fdc_nhead;
	med_info->sm_nsect = fdchar.fdc_secptrack;
	return (0);
}

/* ARGSUSED0 */
int32_t
_m_get_device_info(rmedia_handle_t *handle, void *ip)
{
	smdevice_info_t *dev_info = (smdevice_info_t *)ip;
	char *vendor_name, *product_name, *fw_version;

	/* Check for valid handle */
	if (handle == NULL) {
		DPRINTF("Null Handle\n");
		errno = EINVAL;
		return (-1);
	}
	if (handle->sm_signature != (int32_t)LIBSMEDIA_SIGNATURE) {
		DPRINTF("Invalid signature in handle.\n");
		DPRINTF2(
			"Signature expected=0x%x found=0x%x\n",
				LIBSMEDIA_SIGNATURE,
				handle->sm_signature);
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

	vendor_name[0] = 0;
	product_name[0] = 0;
	fw_version[0] = 0;

	dev_info->sm_interface_type = IF_FLOPPY;
	dev_info->sm_vendor_name = vendor_name;
	dev_info->sm_product_name = product_name;
	dev_info->sm_firmware_version = fw_version;

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

/* ARGSUSED1 */
int32_t
_m_get_media_status(rmedia_handle_t *handle, void *ip)
{
	smwp_state_t	*wp = ip;
	int32_t j;

	if (ioctl(handle->sm_fd, FDGETCHANGE, &j)) {
		return (-1);
	}
	if (j & FDGC_CURWPROT)
		wp->sm_new_state = SM_WRITE_PROTECT_NOPASSWD;
	else
		wp->sm_new_state = SM_WRITE_PROTECT_DISABLE;
	return (0);
}

int32_t
_m_raw_read(rmedia_handle_t *handle, void *ip)
{
	struct raw_params *r_p = (struct raw_params *)ip;

	int32_t	sector_size;
	int32_t ret_val;
	struct	fd_raw fdraw;
	struct	fd_char fdchar;
	int32_t cyl, rem, head, start_sector;


	/* Check for valid handle */
	if (handle == NULL) {
		DPRINTF("Null Handle\n");
		errno = EINVAL;
		return (-1);
	}
	if (handle->sm_signature != (int32_t)LIBSMEDIA_SIGNATURE) {
		DPRINTF("Invalid signature in handle.\n");
		DPRINTF2(
			"Signature expected=0x%x found=0x%x\n",
				LIBSMEDIA_SIGNATURE,
				handle->sm_signature);
		errno = EINVAL;
		return (-1);
	}
	if (handle->sm_fd < 0) {
		DPRINTF("Invalid file handle.\n");
		errno = EINVAL;
		return (-1);
	}
	if (ioctl(handle->sm_fd, FDIOGCHAR, &fdchar) < 0) {
		PERROR("Ioctl failed :");
		return (-1);
	}

	sector_size = fdchar.fdc_sec_size;

	if ((!r_p->size) || (r_p->size % sector_size)) {
		errno = EINVAL;
		return (-1);
	}

	cyl = r_p->offset/(fdchar.fdc_nhead * fdchar.fdc_secptrack);
	rem = r_p->offset%(fdchar.fdc_nhead * fdchar.fdc_secptrack);
	head = rem/fdchar.fdc_secptrack;
	start_sector = rem%fdchar.fdc_secptrack + 1;

	fdraw.fdr_nbytes = r_p->size;
	fdraw.fdr_addr = r_p->buffer;


	fdraw.fdr_cmd[0] = (uint8_t)0xE0 | FDRAW_RDCMD;	/* command */
					/* MFM | MT | SK| FDRAW_RDCMD */
	fdraw.fdr_cmd[1] = (head << 2);		/* using head 1 */
	fdraw.fdr_cmd[2] = cyl;		/* track number */
	fdraw.fdr_cmd[3] = head;		/* drive head number */
	fdraw.fdr_cmd[4] = start_sector;	/* start sector number */
	fdraw.fdr_cmd[5] = (sector_size == 512) ? 2 : 3;
	fdraw.fdr_cmd[6] = fdchar.fdc_secptrack;
	fdraw.fdr_cmd[7] = 0x1B; 	/* GPLN, GAP length */
	fdraw.fdr_cmd[8] = (uchar_t)0xFF; 	/* SSSDTL, data length */
	fdraw.fdr_cnum = 0x9; 	/* NCBRW, no. cmd bytes defined in fdreg.h */

	errno = 0;
	ret_val = ioctl(handle->sm_fd, FDRAW, &fdraw);
	if (ret_val < 0) {
		PERROR("RAW READ failed:");
		return (-1);
	}

	return (fdraw.fdr_nbytes);
}
int32_t
_m_raw_write(rmedia_handle_t *handle, void *ip)
{
	struct raw_params *r_p = (struct raw_params *)ip;

	int32_t	sector_size;
	int32_t ret_val;
	struct	fd_raw fdraw;
	struct	fd_char fdchar;
	int32_t cyl, rem, head, start_sector;


	/* Check for valid handle */
	if (handle == NULL) {
		DPRINTF("Null Handle\n");
		errno = EINVAL;
		return (-1);
	}
	if (handle->sm_signature != (int32_t)LIBSMEDIA_SIGNATURE) {
		DPRINTF("Invalid signature in handle.\n");
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
	if (ioctl(handle->sm_fd, FDIOGCHAR, &fdchar) < 0) {
		PERROR("Ioctl failed :");
		return (-1);
	}

	sector_size = fdchar.fdc_sec_size;

	if ((!r_p->size) || (r_p->size % sector_size)) {
		errno = EINVAL;
		return (-1);
	}

	cyl = r_p->offset/(fdchar.fdc_nhead * fdchar.fdc_secptrack);
	rem = r_p->offset%(fdchar.fdc_nhead * fdchar.fdc_secptrack);
	head = rem/fdchar.fdc_secptrack;
	start_sector = rem%fdchar.fdc_secptrack + 1;

	fdraw.fdr_nbytes = r_p->size;
	fdraw.fdr_addr = r_p->buffer;


	fdraw.fdr_cmd[0] = (uint8_t)0xE0| FDRAW_WRCMD;	/* command */
				/* MFM | MT | SK| FDRAW_WRCMD;	*/
	fdraw.fdr_cmd[1] = (head << 2);		/* using head 1 */
	fdraw.fdr_cmd[2] = cyl;		/* track number */
	fdraw.fdr_cmd[3] = head;		/* drive head number */
	fdraw.fdr_cmd[4] = start_sector;	/* start sector number */
	fdraw.fdr_cmd[5] = (sector_size == 512) ? 2 : 3;
	fdraw.fdr_cmd[6] = fdchar.fdc_secptrack;
	fdraw.fdr_cmd[7] = 0x1B;	/* GPLN, GAP length */
	fdraw.fdr_cmd[8] = (uchar_t)0xFF; 	/* SSSDTL, data length */
	fdraw.fdr_cnum = 0x9;	/* NCBRW, no. cmd bytes defined in fdreg.h */

	errno = 0;
	ret_val = ioctl(handle->sm_fd, FDRAW, &fdraw);
	if (ret_val < 0) {
		PERROR("RAW READ failed:");
		return (-1);
	}

	return (fdraw.fdr_nbytes);
}

/* ARGSUSED */
int32_t
_m_eject(rmedia_handle_t *handle, void *ip)
{

	/* Check for valid handle */
	if (handle == NULL) {
		DPRINTF("Null Handle\n");
		errno = EINVAL;
		return (-1);
	}
	if (handle->sm_signature != (int32_t)LIBSMEDIA_SIGNATURE) {
		DPRINTF("Invalid signature in handle.\n");
		DPRINTF2(
		"Signature expected=0x%x found=0x%x\n",
			LIBSMEDIA_SIGNATURE, handle->sm_signature);
		errno = EINVAL;
		return (-1);
	}
	if (handle->sm_fd < 0) {
		DPRINTF("Invalid file handle.\n");
		errno = EINVAL;
		return (-1);
	}
#ifdef sparc
	return (ioctl(handle->sm_fd, FDEJECT));
#else
	errno = ENOTSUP;
	return (-1);
#endif
}
