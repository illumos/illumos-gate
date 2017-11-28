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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * s_generic.c :
 *      This file contains generic SCSI related functions for scsi plug-in
 * 	for libsm.so.
 */


#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/smedia.h>
#include "../../../library/inc/rmedia.h"
#include <smserver.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/scsi/scsi.h>
#include <strings.h>
#include "../../../library/common/l_defines.h"


static int32_t remap_shared_buf(rmedia_handle_t *, size_t, char *);

#define	W_E_MASK 0x80
#define	BUF_SIZE_MULTIPLE	0x2000

int32_t
_m_get_media_info(rmedia_handle_t *handle, void *ip)
{
	smmedium_prop_t *medinfo = ip;
	int32_t ret_val;
	smedia_reqget_medium_property_t	reqget_medium_property;
	smedia_retget_medium_property_t	*retget_medium_property;
	smedia_reterror_t	*reterror;
	door_arg_t	door_args;
	char	rbuf[sizeof (smedia_services_t) + sizeof (door_desc_t)];

	DPRINTF("get_media_info called.\n");
	/* Check for valid handle */
	if (handle == NULL) {
		DPRINTF("Null Handle\n");
		errno = EINVAL;
		return (-1);
	}
	if (handle->sm_signature != (int32_t)LIBSMEDIA_SIGNATURE) {
		DPRINTF("Invalid signature in handle.\n");
		DPRINTF2("Signature expected=0x%x, found=0x%x\n",
		    LIBSMEDIA_SIGNATURE, handle->sm_signature);
		DPRINTF1("fd=%d\n", handle->sm_fd);
		errno = EINVAL;
		return (-1);
	}
	(void) memset((void *) medinfo, 0, sizeof (smmedium_prop_t));

	reqget_medium_property.cnum = SMEDIA_CNUM_GET_MEDIUM_PROPERTY;
	door_args.data_ptr = (char *)&reqget_medium_property;
	door_args.data_size = sizeof (smedia_services_t);
	door_args.desc_ptr = NULL;
	door_args.desc_num = 0;
	door_args.rbuf = rbuf;
	door_args.rsize = sizeof (rbuf);

	ret_val = door_call(handle->sm_door, &door_args);
	if (ret_val < 0) {
		perror("door_call");
		return (-1);
	}
	retget_medium_property =
	    (smedia_retget_medium_property_t *)((void *)door_args.data_ptr);
	reterror = (smedia_reterror_t *)((void *)door_args.data_ptr);
	if (reterror->cnum == SMEDIA_CNUM_ERROR) {
		DPRINTF1(
	"Error in get_medium_property. errnum = 0x%x \n", reterror->errnum);
		errno = reterror->errnum;
		return (-1);
	}

	*medinfo = retget_medium_property->smprop;

	return (0);
}

int32_t
_m_get_device_info(rmedia_handle_t *handle, void *ip)
{
	struct smdevice_info *dev_info = ip;
	int32_t	ret_val;
	smedia_reqget_device_info_t	reqget_device_info;
	smedia_retget_device_info_t	*retget_device_info;
	smedia_reterror_t	*reterror;
	door_arg_t	door_args;
	char	rbuf[sizeof (smedia_services_t) + sizeof (door_desc_t)];
	char *vendor_name, *product_name, *fw_version;

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

	vendor_name = (char *)malloc(9);
	if (vendor_name == NULL) {
		if (!errno)
			errno = ENOMEM;
		return (-1);
	}
	product_name = (char *)malloc(17);
	if (product_name == NULL) {
		free(vendor_name);
		if (!errno)
			errno = ENOMEM;
		return (-1);
	}

	fw_version = (char *)malloc(18);
	if (fw_version == NULL) {
		free(vendor_name);
		free(product_name);
		if (!errno)
			errno = ENOMEM;
		return (-1);
	}
	reqget_device_info.cnum = SMEDIA_CNUM_GET_DEVICE_INFO;
	door_args.data_ptr = (char *)&reqget_device_info;
	door_args.data_size = sizeof (smedia_services_t);
	door_args.desc_ptr = NULL;
	door_args.desc_num = 0;
	door_args.rbuf = rbuf;
	door_args.rsize = sizeof (rbuf);

	ret_val = door_call(handle->sm_door, &door_args);
	if (ret_val < 0) {
		perror("door_call");
		free(vendor_name);
		free(product_name);
		free(fw_version);
		return (-1);
	}
	retget_device_info = (smedia_retget_device_info_t *)
	    ((void *)door_args.data_ptr);
	reterror = (smedia_reterror_t *)((void *)door_args.data_ptr);
	if (reterror->cnum == SMEDIA_CNUM_ERROR) {
		DPRINTF1("Error in get_device_info. errnum = 0x%x \n",
		    reterror->errnum);
		errno = reterror->errnum;
		free(vendor_name);
		free(product_name);
		free(fw_version);
		return (-1);
	}

	dev_info->sm_vendor_name = vendor_name;
	dev_info->sm_product_name = product_name;
	dev_info->sm_firmware_version = fw_version;


	(void) strlcpy(dev_info->sm_vendor_name,
	    retget_device_info->sm_vendor_name, 8);
	dev_info->sm_vendor_name[8] = 0;
	(void) strlcpy(dev_info->sm_product_name,
	    retget_device_info->sm_product_name, 16);
	dev_info->sm_product_name[16] = 0;
	(void) strlcpy(dev_info->sm_firmware_version,
	    retget_device_info->sm_firmware_version, 17);
	dev_info->sm_firmware_version[17] = 0;

	dev_info->sm_interface_type = retget_device_info->sm_interface_type;

#ifdef DEBUG
	DPRINTF1("Vendor name = %s\n", dev_info->sm_vendor_name);
	DPRINTF1("product name = %s\n", dev_info->sm_product_name);
	DPRINTF1("Firmware revision = %s\n", dev_info->sm_firmware_version);
#endif /* DEBUG */

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

int32_t
_m_raw_write(rmedia_handle_t *handle, void *i_p)
{
	int32_t	ret_val;
	struct raw_params *r_p = (struct raw_params *)i_p;
	smedia_reqraw_write_t	reqraw_write;
	smedia_retraw_write_t	*retraw_write;
	smedia_reterror_t	*reterror;
	door_arg_t	door_args;
	char	rbuf[sizeof (smedia_services_t) + sizeof (door_desc_t)];

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
	(void) mutex_lock(&handle->sm_bufmutex);
	ret_val = remap_shared_buf(handle, r_p->size, r_p->buffer);
	if (ret_val != 0) goto error;
	reqraw_write.cnum = SMEDIA_CNUM_RAW_WRITE;
	reqraw_write.blockno = r_p->offset;
	reqraw_write.nbytes = r_p->size;
	bcopy(r_p->buffer, handle->sm_buf, r_p->size);
	door_args.data_ptr = (char *)&reqraw_write;
	door_args.data_size = sizeof (reqraw_write);
	door_args.desc_ptr = NULL;
	door_args.desc_num = 0;
	door_args.rbuf = rbuf;
	door_args.rsize = sizeof (rbuf);

	ret_val = door_call(handle->sm_door, &door_args);
	if (ret_val < 0) {
		perror("door_call");
		goto error;
	}
	retraw_write = (smedia_retraw_write_t *)((void *)door_args.data_ptr);
	reterror = (smedia_reterror_t *)((void *)door_args.data_ptr);
	if (reterror->cnum == SMEDIA_CNUM_ERROR) {
		DPRINTF3("Error in raw write. errnum = 0x%x "
		    "blk_num = 0x%x(%d)\n", reterror->errnum, r_p->offset,
		    r_p->offset);
		errno = reterror->errnum;
		goto error;
	}
	(void) mutex_unlock(&handle->sm_bufmutex);
	return (retraw_write->nbytes);

error:
	(void) mutex_unlock(&handle->sm_bufmutex);
	return (-1);
}

size_t
_m_raw_read(rmedia_handle_t *handle, void *i_p)
{
	struct raw_params *r_p = (struct raw_params *)i_p;
	int32_t	ret_val, bytes_read;
	smedia_reqraw_read_t	reqraw_read;
	smedia_retraw_read_t	*retraw_read;
	smedia_reterror_t	*reterror;
	door_arg_t	door_args;
	char	rbuf[sizeof (smedia_services_t) + sizeof (door_desc_t)];

	/* Check for valid handle */
	if (handle == NULL) {
		DPRINTF("Null Handle\n");
		errno = EINVAL;
		return (size_t)(-1);
	}
	if (handle->sm_signature != LIBSMEDIA_SIGNATURE) {
		DPRINTF("Invalid signature in handle.\n");
		return (size_t)(-1);
	}
	/*
	 * Check if another thread is doing an IO with same handle.
	 * In that case ww block here.
	 */
	(void) mutex_lock(&handle->sm_bufmutex);
	ret_val = remap_shared_buf(handle, r_p->size, r_p->buffer);
	if (ret_val != 0) goto error;

	reqraw_read.cnum = SMEDIA_CNUM_RAW_READ;
	reqraw_read.blockno = r_p->offset;
	reqraw_read.nbytes = r_p->size;
	door_args.data_ptr = (char *)&reqraw_read;
	door_args.data_size = sizeof (smedia_services_t);
	door_args.desc_ptr = NULL;
	door_args.desc_num = 0;
	door_args.rbuf = rbuf;
	door_args.rsize = sizeof (rbuf);

	ret_val = door_call(handle->sm_door, &door_args);
	if (ret_val < 0) {
		perror("door_call");
		goto error;
	}
	retraw_read = (smedia_retraw_read_t *)((void *)door_args.data_ptr);
	reterror = (smedia_reterror_t *)((void *)door_args.data_ptr);
	if (reterror->cnum == SMEDIA_CNUM_ERROR) {
		/*
		 * free(rbuf);
		 */
		DPRINTF3("Error in raw read. errnum = 0x%x "
		    "blk_num = 0x%x(%d)\n", reterror->errnum, r_p->offset,
		    r_p->offset);
		errno = reterror->errnum;
		goto error;
	}
	(void) memcpy(r_p->buffer, handle->sm_buf, retraw_read->nbytes);
	bytes_read = retraw_read->nbytes;
	(void) mutex_unlock(&handle->sm_bufmutex);
	return (bytes_read);

error:
	(void) mutex_unlock(&handle->sm_bufmutex);
	return (size_t)(-1);

}

size_t
_m_media_format(rmedia_handle_t *handle, void *ip)
{
	int32_t ret_val;
	struct format_flags *ffl = (struct format_flags *)ip;
	smedia_reqformat_t	reqformat;
	smedia_reterror_t	*reterror;
	door_arg_t	door_args;
	char	rbuf[sizeof (smedia_services_t) + sizeof (door_desc_t)];

	/* Check for valid handle */
	if (handle == NULL) {
		DPRINTF("Null Handle\n");
		errno = EINVAL;
		return (size_t)(-1);
	}
	if (handle->sm_signature != LIBSMEDIA_SIGNATURE) {
		DPRINTF("Invalid signature in handle.\n");
		errno = EINVAL;
		return (size_t)(-1);
	}
	reqformat.cnum = SMEDIA_CNUM_FORMAT;
	reqformat.flavor = ffl->flavor;
	reqformat.mode = ffl->mode;
	door_args.data_ptr = (char *)&reqformat;
	door_args.data_size = sizeof (smedia_services_t);
	door_args.desc_ptr = NULL;
	door_args.desc_num = 0;
	door_args.rbuf = rbuf;
	door_args.rsize = sizeof (rbuf);

	ret_val = door_call(handle->sm_door, &door_args);
	if (ret_val < 0) {
		perror("door_call");
		return (size_t)(-1);
	}
	reterror = (smedia_reterror_t *)((void *)door_args.data_ptr);
	if (reterror->cnum == SMEDIA_CNUM_ERROR) {
		DPRINTF1("Error in format. errnum = 0x%x \n", reterror->errnum);
		errno = reterror->errnum;
		return (size_t)(-1);
	}
	return (0);
}

int32_t
_m_get_media_status(rmedia_handle_t *handle, void *ip)
{
	smwp_state_t	*wp = ip;
	int32_t ret_val;
	smedia_reqget_protection_status_t	reqget_protection_status;
	smedia_retget_protection_status_t	*retget_protection_status;
	smedia_reterror_t	*reterror;
	door_arg_t	door_args;
	char	rbuf[sizeof (smedia_services_t) + sizeof (door_desc_t)];

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
	reqget_protection_status.cnum = SMEDIA_CNUM_GET_PROTECTION_STATUS;
	door_args.data_ptr = (char *)&reqget_protection_status;
	door_args.data_size = sizeof (smedia_services_t);
	door_args.desc_ptr = NULL;
	door_args.desc_num = 0;
	door_args.rbuf = rbuf;
	door_args.rsize = sizeof (rbuf);

	ret_val = door_call(handle->sm_door, &door_args);
	if (ret_val < 0) {
		perror("door_call");
		return (-1);
	}
	retget_protection_status = (smedia_retget_protection_status_t *)
	    ((void *)door_args.data_ptr);
	reterror = (smedia_reterror_t *)((void *)door_args.data_ptr);
	if (reterror->cnum == SMEDIA_CNUM_ERROR) {
		DPRINTF1("Error in get_protection-status. errnum = 0x%x \n",
		    reterror->errnum);
		errno = reterror->errnum;
		return (-1);
	}
	(void) memcpy((char *)wp, (char *)&retget_protection_status->prot_state,
	    sizeof (smwp_state_t));
	return (0);
}

int32_t
_m_set_media_status(rmedia_handle_t *handle, void *ip)
{

	smwp_state_t	*wp = ip;
	int32_t ret_val;
	smedia_reqset_protection_status_t	reqset_protection_status;
	smedia_reterror_t	*reterror;
	door_arg_t	door_args;
	char	rbuf[sizeof (smedia_services_t) + sizeof (door_desc_t)];

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
	reqset_protection_status.cnum = SMEDIA_CNUM_SET_PROTECTION_STATUS;
	reqset_protection_status.prot_state = *wp;
	door_args.data_ptr = (char *)&reqset_protection_status;
	door_args.data_size = sizeof (smedia_services_t);
	door_args.desc_ptr = NULL;
	door_args.desc_num = 0;
	door_args.rbuf = rbuf;
	door_args.rsize = sizeof (rbuf);

	ret_val = door_call(handle->sm_door, &door_args);
	if (ret_val < 0) {
		perror("door_call");
		return (-1);
	}
	reterror = (smedia_reterror_t *)((void *)door_args.data_ptr);
	if (reterror->cnum == SMEDIA_CNUM_ERROR) {
		DPRINTF1(
	"Error in set_protection-status. errnum = 0x%x \n", reterror->errnum);
		errno = reterror->errnum;
		return (-1);
	}
	return (0);
}

int32_t
_m_reassign_block(rmedia_handle_t *handle, void *ip)
{
	uint32_t block;
	diskaddr_t *blockp  = (diskaddr_t *)ip;
	int32_t	ret_val;
	smedia_reqreassign_block_t	reqreassign_block;
	smedia_reterror_t		*reterror;
	door_arg_t	door_args;
	char	rbuf[sizeof (smedia_services_t) + sizeof (door_desc_t)];

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
	block = *blockp;
	DPRINTF1("reassign block %d\n", block);
	reqreassign_block.cnum = SMEDIA_CNUM_REASSIGN_BLOCK;
	reqreassign_block.blockno = block;
	door_args.data_ptr = (char *)&reqreassign_block;
	door_args.data_size = sizeof (smedia_services_t);
	door_args.desc_ptr = NULL;
	door_args.desc_num = 0;
	door_args.rbuf = rbuf;
	door_args.rsize = sizeof (rbuf);

	ret_val = door_call(handle->sm_door, &door_args);
	if (ret_val < 0) {
		perror("door_call");
		return (-1);
	}
	reterror = (smedia_reterror_t *)((void *)door_args.data_ptr);
	if (reterror->cnum == SMEDIA_CNUM_ERROR) {
		DPRINTF2("Error in reassign_block. block = 0x%x "
		    "errnum = 0x%x \n", block, reterror->errnum);
		errno = reterror->errnum;
		return (-1);
	}
	return (0);
}

/* ARGSUSED1 */
int32_t
_m_eject(rmedia_handle_t *handle, void *ip)
{
	int32_t	fd;

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
	fd = handle->sm_fd;
	return (ioctl(fd, DKIOCEJECT));
}

int32_t
_m_device_type(ushort_t ctype, ushort_t mtype)
{
	if ((ctype == DKC_SCSI_CCS) ||
	    (ctype == DKC_MD21) ||
	    (ctype == DKC_CDROM)) {
		if (mtype == 0)
			return (0);
	}
	return (-1);
}

int32_t
_m_version_no(void)
{
	return (SM_SCSI_VERSION_1);
}

int32_t
_m_check_format_status(rmedia_handle_t *handle, void *ip)
{
	int32_t ret_val;
	smedia_reqcheck_format_status_t	reqcheck_format_status;
	smedia_retcheck_format_status_t	*retcheck_format_status;
	smedia_reterror_t	*reterror;
	door_arg_t	door_args;
	char	rbuf[sizeof (smedia_services_t) + sizeof (door_desc_t)];
#ifdef	lint
	ip = ip;
#endif

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
	reqcheck_format_status.cnum = SMEDIA_CNUM_CHECK_FORMAT_STATUS;
	door_args.data_ptr = (char *)&reqcheck_format_status;
	door_args.data_size = sizeof (smedia_services_t);
	door_args.desc_ptr = NULL;
	door_args.desc_num = 0;
	door_args.rbuf = rbuf;
	door_args.rsize = sizeof (rbuf);

	ret_val = door_call(handle->sm_door, &door_args);
	if (ret_val < 0) {
		perror("door_call");
		return (-1);
	}
	retcheck_format_status =
	    (smedia_retcheck_format_status_t *)((void *)door_args.data_ptr);
	reterror = (smedia_reterror_t *)((void *)door_args.data_ptr);
	if (reterror->cnum == SMEDIA_CNUM_ERROR) {
		DPRINTF1("Error in check_format_status. errnum = 0x%x \n",
		    reterror->errnum);
		errno = reterror->errnum;
		return (-1);
	}
	return (retcheck_format_status->percent_complete);
}

int32_t
_m_uscsi_cmd(rmedia_handle_t *handle, struct uscsi_cmd *ucmd)
{
	int32_t	ret_val;
	smedia_requscsi_cmd_t	requscsi_cmd;
	smedia_retuscsi_cmd_t	*retuscsi_cmd;
	smedia_reterror_t	*reterror;
	door_arg_t	door_args;
	char	rbuf[sizeof (smedia_services_t) + sizeof (door_desc_t)];

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
	/*
	 * We will be validating the user supplied buffer lengths and
	 * buffer pointers.
	 */
	if (ucmd->uscsi_cdblen > MAX_CDB_LEN) {
		DPRINTF("Invalid cdblen specified.\n");
		errno = EINVAL;
		return (-1);
	}
	if ((ucmd->uscsi_flags & USCSI_RQENABLE) &&
	    (ucmd->uscsi_rqlen > MAX_RQ_LEN)) {
		DPRINTF("Invalid rqlen specified.\n");
		errno = EINVAL;
		return (-1);
	}
	if (ucmd->uscsi_cdb == NULL) {
		DPRINTF("cdb buffer is NULL.\n");
		errno = EINVAL;
		return (-1);
	}
	if ((ucmd->uscsi_buflen) && (ucmd->uscsi_bufaddr == NULL)) {
		DPRINTF("bufaddr is NULL.\n");
		errno = EINVAL;
		return (-1);
	}
	if ((ucmd->uscsi_flags & USCSI_RQENABLE) &&
	    (ucmd->uscsi_rqbuf == NULL)) {
		DPRINTF("rqbuf is NULL.\n");
		errno = EINVAL;
		return (-1);
	}
	/*
	 * Check if another thread is doing an IO with same handle.
	 * In that case we block here.
	 */
	(void) mutex_lock(&handle->sm_bufmutex);
	ret_val = remap_shared_buf(handle, ucmd->uscsi_buflen,
	    ucmd->uscsi_bufaddr);
	if (ret_val != 0) {
		DPRINTF("remap of shared buf failed.\n");
		goto error;
	}

	requscsi_cmd.cnum = SMEDIA_CNUM_USCSI_CMD;
	requscsi_cmd.uscsi_flags = ucmd->uscsi_flags;
	requscsi_cmd.uscsi_timeout = ucmd->uscsi_timeout;
	requscsi_cmd.uscsi_buflen = ucmd->uscsi_buflen;
	requscsi_cmd.uscsi_cdblen = ucmd->uscsi_cdblen;
	requscsi_cmd.uscsi_rqlen = ucmd->uscsi_rqlen;

	/*
	 * The uscsi_buflen has been validated in the call to
	 * remap_shared_buf() done earlier.
	 */
	/* Check for write */
	if (!(ucmd->uscsi_flags & USCSI_READ)) {
		bcopy(ucmd->uscsi_bufaddr, handle->sm_buf, ucmd->uscsi_buflen);
	}

	bcopy(ucmd->uscsi_cdb, requscsi_cmd.uscsi_cdb, ucmd->uscsi_cdblen);

	door_args.data_ptr = (char *)&requscsi_cmd;
	door_args.data_size = sizeof (smedia_services_t);
	door_args.desc_ptr = NULL;
	door_args.desc_num = 0;
	door_args.rbuf = rbuf;
	door_args.rsize = sizeof (rbuf);

	ret_val = door_call(handle->sm_door, &door_args);
	if (ret_val < 0) {
		perror("door_call");
		goto error;
	}
	retuscsi_cmd = (smedia_retuscsi_cmd_t *)((void *)door_args.data_ptr);
	reterror = (smedia_reterror_t *)((void *)door_args.data_ptr);
	if (reterror->cnum == SMEDIA_CNUM_ERROR) {
		DPRINTF1(
		"Error in uscsi cmd. errnum = 0x%x\n", reterror->errnum);
		errno = reterror->errnum;
		goto error;
	}
	ucmd->uscsi_status = retuscsi_cmd->uscsi_status;
	ucmd->uscsi_resid = retuscsi_cmd->uscsi_resid;
	ucmd->uscsi_rqstatus = retuscsi_cmd->uscsi_rqstatus;
	ucmd->uscsi_rqresid = retuscsi_cmd->uscsi_rqresid;
	if ((ucmd->uscsi_flags & USCSI_RQENABLE) &&
	    (ucmd->uscsi_rqbuf != NULL)) {
		bcopy(retuscsi_cmd->uscsi_rqbuf, ucmd->uscsi_rqbuf,
		    ucmd->uscsi_rqlen);
	}
	errno = retuscsi_cmd->uscsi_errno;
	if (errno) {
		goto error;
	}

	if (ucmd->uscsi_resid > ucmd->uscsi_buflen) {
		/*
		 * Invalid resid value. return error.
		 */
		errno = EINVAL;
		goto error;
	}
	if (ucmd->uscsi_flags & USCSI_READ) {
		(void) memcpy(ucmd->uscsi_bufaddr,
		    handle->sm_buf, ucmd->uscsi_buflen - ucmd->uscsi_resid);
	}
	(void) mutex_unlock(&handle->sm_bufmutex);
#ifdef DEBUG
	if (retuscsi_cmd->uscsi_retval || ucmd->uscsi_status)
		DPRINTF2("Error in uscsi_cmd: retval=0x%x uscsi_status=0x%x\n",
		    retuscsi_cmd->uscsi_retval, ucmd->uscsi_status);
#endif
	return (retuscsi_cmd->uscsi_retval);
error:
	(void) mutex_unlock(&handle->sm_bufmutex);
	return (-1);
}

int32_t
remap_shared_buf(rmedia_handle_t *handle, size_t buf_size, char *buffer)
{
	char	rbuf[sizeof (smedia_services_t) + sizeof (door_desc_t)];
	char	fname[128];
	smedia_reqset_shfd_t	reqset_shfd;
	smedia_reterror_t	*reterror;
	int	ret_val, fd;
	door_arg_t	door_args;
	door_desc_t	ddesc[2];
	char	*fbuf;
	size_t	shared_bufsize;
	off_t	file_size, ret;

	if (handle->sm_bufsize >= buf_size)
		return (0);
	shared_bufsize = ((buf_size + BUF_SIZE_MULTIPLE - 1)/BUF_SIZE_MULTIPLE)
	    * BUF_SIZE_MULTIPLE;
	if (handle->sm_buffd != -1) {
		/* extend the file and re-map */
		fd = handle->sm_buffd;
		ret_val = munmap(handle->sm_buf, handle->sm_bufsize);
		if (ret_val != 0) {
			DPRINTF1("remap:munmap failed. errno = 0x%x\n", errno);
			(void) close(fd);
			handle->sm_buf = NULL;
			handle->sm_bufsize = 0;
			handle->sm_buffd = -1;
			return (errno);
		}
		file_size = lseek(fd, 0, SEEK_END);
		if (file_size == -1) {
			DPRINTF1("remap:lseek failed. errno = 0x%x\n", errno);
			return (errno);
		}
		handle->sm_buf = NULL;
		handle->sm_bufsize = 0;
		handle->sm_buffd = -1;
	} else {
		/* create a new file and mapping */
		(void) sprintf(fname, "/tmp/libsmedia_mmaped_file_XXXXXX");
		fd = mkstemp(fname);
		if (fd == -1) {
			DPRINTF1("remap:mktemp failed. errno = 0x%x\n", errno);
			return (errno);
		}
		ret_val = unlink(fname);
		if (ret_val == -1) {
			DPRINTF1("remap:unlink failed. errno = 0x%x\n", errno);
			(void) close(fd);
			return (errno);
		}
		file_size = 0;
	}
	/* Need to start at the beginning of the file when enlarging */
	ret = lseek(fd, 0, SEEK_SET);
	if (ret == -1) {
		DPRINTF1("remap:lseek failed. errno = 0x%x\n", errno);
		return (errno);
	}
	while (file_size < shared_bufsize) {
		ret_val = write(fd, buffer, buf_size);
		if (ret_val != buf_size) {
			DPRINTF1("remap:write failed. errno = 0x%x\n", errno);
			(void) close(fd);
			return (errno);
		}
		file_size += buf_size;
	}
	fbuf = mmap(NULL, shared_bufsize, PROT_READ | PROT_WRITE,
	    MAP_SHARED, fd, 0);
	if (fbuf == (char *)-1) {
		perror("mmap failed");
		(void) close(fd);
		return (errno);
	}

	reqset_shfd.cnum = SMEDIA_CNUM_SET_SHFD;
	reqset_shfd.fdbuf_len = shared_bufsize;
	ddesc[0].d_data.d_desc.d_descriptor = fd;
	ddesc[0].d_attributes = DOOR_DESCRIPTOR;
	door_args.data_ptr = (char *)&reqset_shfd;
	door_args.data_size = sizeof (reqset_shfd);
	door_args.desc_ptr = &ddesc[0];
	door_args.desc_num = 1;
	door_args.rbuf = rbuf;
	door_args.rsize = sizeof (rbuf);

	ret_val = door_call(handle->sm_door, &door_args);
	if (ret_val < 0) {
		perror("door_call");
		(void) close(fd);
		return (-1);
	}
	reterror = (smedia_reterror_t *)((void *)door_args.data_ptr);
	if (reterror->cnum == SMEDIA_CNUM_ERROR) {
		DPRINTF1("Error in set shfd. errnum = 0x%x\n",
		    reterror->errnum);
		errno = reterror->errnum;
		(void) close(fd);
		return (errno);
	}
	handle->sm_buffd = fd;
	handle->sm_buf = fbuf;
	handle->sm_bufsize = shared_bufsize;
	DPRINTF("Returned successful from remap shared buf routine.\n");
	return (0);
}
