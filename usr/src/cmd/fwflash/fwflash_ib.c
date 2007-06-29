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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * fwflash_ib.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <locale.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <libdevinfo.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <sys/ib/adapters/tavor/tavor_ioctl.h>
#include "fwflash.h"
#include "fwflash_ib.h"
#include "fwflash_ib_impl.h"
#include "fwflash_mlx.h"

/*
 * Internal IB Flash update routines
 */
static int fwflash_ib_i_check_handle(fwflash_ib_hdl_t *handle);
static int fwflash_ib_i_num_sectors(fwflash_ib_hdl_t *handle, int size);
static int fwflash_ib_i_read_file(FILE *fp, int len, void *buf);
static int fwflash_ib_i_local_verify(fwflash_ib_hdl_t *handle, uint32_t offset);
static int fwflash_ib_i_flash_verify_signature(fwflash_ib_hdl_t *handle,
    uint32_t offset);
static int fwflash_ib_i_local_verify_signature(fwflash_ib_hdl_t *handle,
    uint32_t offset);
static int fwflash_ib_i_local_verify_vsd(fwflash_ib_hdl_t *handle,
    uint32_t offset);
static int fwflash_ib_i_flash_zero_signature(fwflash_ib_hdl_t *handle,
    uint32_t offset);
static int fwflash_ib_i_local_verify_xps_crc(fwflash_ib_hdl_t *handle,
    uint32_t offset);
static void fwflash_ib_i_local_set_xps_crc(fwflash_ib_hdl_t *handle,
    uint32_t offset);
static int fwflash_ib_i_flash_set_xps_crc(fwflash_ib_hdl_t *handle,
    uint32_t offset);
static uint32_t fwflash_ib_i_flash_get_sect_size(fwflash_ib_hdl_t *handle);
static uint32_t fwflash_ib_i_local_get_sect_size(fwflash_ib_hdl_t *handle);
static int fwflash_ib_i_flash_verify_is(fwflash_ib_hdl_t *handle);
static int fwflash_ib_i_flash_verify_flash_info(fwflash_ib_hdl_t *handle,
    uint32_t size);
static void fwflash_ib_i_flash_verify_flash_match(fwflash_ib_hdl_t *handle,
    int offset, int type);
static void fwflash_ib_i_flash_verify_flash_pn(fwflash_ib_hdl_t *handle,
    uchar_t *psid, int psid_size, int type);
static void fwflash_ib_i_flash_verify_flash_fwpsid(fwflash_ib_hdl_t *handle,
    uchar_t *psid, int psid_size);
static uchar_t *fwflash_ib_i_flash_get_psid(fwflash_ib_hdl_t *handle,
    int offset);
static uint16_t fwflash_ib_i_check_hwver(fwflash_ib_hdl_t *handle);
static void fwflash_ib_i_local_zero_crc(fwflash_ib_hdl_t *handle,
    uint32_t offset);
static int fwflash_ib_i_flash_zero_crc(fwflash_ib_hdl_t *handle,
    uint32_t offset);
static uint32_t fwflash_ib_i_local_get_fw_size(fwflash_ib_hdl_t *handle,
    uint32_t offset);
static uint32_t fwflash_ib_i_local_get_fw_addr(fwflash_ib_hdl_t *handle,
    uint32_t offset);
static uint32_t fwflash_ib_i_flash_get_fw_addr(fwflash_ib_hdl_t *handle,
    uint32_t offset);
static int fwflash_ib_i_flash_set_fw_addr(fwflash_ib_hdl_t *handle,
    uint32_t offset, uint32_t addr);
static int fwflash_ib_i_flash_set_signature(fwflash_ib_hdl_t *handle,
    uint32_t offset);
static int fwflash_ib_i_flash_read_guids(fwflash_ib_hdl_t *handle, void *buf,
    int type);
static void fwflash_ib_i_local_set_guid_crc(fwflash_ib_hdl_t *handle,
    uint32_t offset);
static uint16_t crc16(uint8_t *image, uint32_t size);

/* global arg list */
extern int fwflash_arg_list;

/*
 * Generate list of devices.
 */
char **
fwflash_ib_device_list(int *count)
{
	di_node_t	root_node;
	di_node_t	node;
	char		*phys_path;
	int		phys_path_len;
	char		**device_list = NULL;
	int		i;

	DPRINTF(DBG_INFO, ("fwflash_ib_device_list\n"));
	if (count == NULL) {
		DPRINTF(DBG_ERR, ("\nNULL count\n"));
		goto out;
	}

	root_node = di_init("/", DINFOCPYALL);
	if (root_node == DI_NODE_NIL) {
		DPRINTF(DBG_ERR, ("\nNo root node\n"));
		goto out;
	}

	*count = 0;
	node = di_drv_first_node(FWFLASH_IB_DRIVER_NAME, root_node);
	while (node != DI_NODE_NIL) {
		node = di_drv_next_node(node);
		++(*count);
	}

	if (*count <= 0) {
		DPRINTF(DBG_ERR, ("\nNo devices found\n"));
		di_fini(root_node);
		goto out;
	}

	/* Allocate device_list for number of devices */
	device_list = (char **)malloc(sizeof (char *) * (*count));
	if (device_list == NULL) {
		DPRINTF(DBG_ERR, ("\nCan't malloc device_list (0x%x)\n",
		    errno));
		goto out;
	}

	i = 0;
	node = di_drv_first_node(FWFLASH_IB_DRIVER_NAME, root_node);
	while (node != DI_NODE_NIL) {
		phys_path = di_devfs_path(node);

		if (phys_path == NULL) {
			DPRINTF(DBG_ERR, ("\n%s phys_path is NULL \n",
			    FWFLASH_IB_DRIVER_NAME));
			free(device_list);
		}

		/*
		 * Set path length, plus enough spaces to add
		 * /devices/etc. paths below.
		 */
		phys_path_len = strlen(phys_path) + 25;

		device_list[i] = (char *)malloc(sizeof (char) *
		    (phys_path_len + 2));
		if (device_list[i] == NULL) {
			DPRINTF(DBG_ERR, ("\nCan't malloc %s list[%d] (0x%x)\n",
			    FWFLASH_IB_DRIVER_NAME, i, errno));
			free(device_list);
			device_list = (char **)NULL;
			goto out;
		}
		(void) snprintf(device_list[i], phys_path_len,
		    "/devices%s:devctl", phys_path);

		i++;
		di_devfs_path_free(phys_path);
		node = di_drv_next_node(node);
	}
	di_fini(root_node);
out:
	return (device_list);
}

fwflash_ib_hdl_t *
fwflash_ib_open(char *dev_path)
{
	tavor_flash_init_ioctl_t	init_ioctl;
	fwflash_ib_hdl_t		*handle;
	cfi_t				cfi;
	int				fd = 0;
	int				id_size = 0;
	int				ret;
	int				i, j;

	DPRINTF(DBG_INFO, ("fwflash_ib_open\n"));
	if (dev_path == NULL) {
		DPRINTF(DBG_ERR, ("\ndevpath is NULL\n"));
		goto bad;
	}

	fd = open(dev_path, O_RDWR);
	if (fd == -1) {
		perror("fwflash_ib_open");
		goto bad;
	}

	handle = (fwflash_ib_hdl_t *)malloc(sizeof (fwflash_ib_hdl_t));
	if (handle == NULL) {
		DPRINTF(DBG_ERR, ("\nhandle malloc failed (%d)\n", errno));
		goto bad;
	}
	bzero(handle, sizeof (fwflash_ib_hdl_t));

	handle->magic = FWFLASH_IB_MAGIC_NUMBER;
	handle->state = FWFLASH_IB_STATE_NONE;

	handle->fd = fd;

	/*
	 * Inform driver: this cmd supports the Intel Extended CFI
	 * command set.
	 */
	cfi.cfi_char[0x10] = 'M';
	cfi.cfi_char[0x11] = 'X';
	cfi.cfi_char[0x12] = '2';
	init_ioctl.tf_cfi_info[0x4] = ntohl(cfi.cfi_int[0x4]);

	/* call flash init ioctl */
	ret = ioctl(handle->fd, TAVOR_IOCTL_FLASH_INIT, &init_ioctl);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nTAVOR_IOCTL_FLASH_INIT failed "
		    "(0x%x)\n", errno));
		goto bad;
	}
	handle->hwrev = init_ioctl.tf_hwrev;

	/*
	 * Determine if the attached driver doesn't support
	 * the Intel Extended CFI command set. And if not,
	 * verify it's the AMD command set. If not error out
	 * as the Intel cmd set can't be used without support
	 * in the driver.
	 */
	for (i = 0; i < TAVOR_FLASH_CFI_SIZE_QUADLET; i++) {
		cfi.cfi_int[i] = ntohl(init_ioctl.tf_cfi_info[i]);
	}

	handle->cmd_set = cfi.cfi_char[0x13];
	if (cfi.cfi_char[0x10] == 'Q' &&
	    cfi.cfi_char[0x11] == 'R' &&
	    cfi.cfi_char[0x12] == 'Y') {
		/* make sure the cmd set is AMD */
		if (handle->cmd_set != TAVOR_FLASH_AMD_CMDSET) {
			(void) fprintf(stderr,
			    gettext("Unsupported flash device command set"));
			(void) fprintf(stderr, "\n");
			goto bad;
		}
		/* set some defaults */
		handle->sector_sz = TAVOR_FLASH_SECTOR_SZ_DEFAULT;
		handle->device_sz = TAVOR_FLASH_DEVICE_SZ_DEFAULT;
	} else {
		if (handle->cmd_set != TAVOR_FLASH_AMD_CMDSET &&
		    handle->cmd_set != TAVOR_FLASH_INTEL_CMDSET) {
			(void) fprintf(stderr,
			    gettext("Uknown flash device command set"));
			(void) fprintf(stderr, "\n");
			goto bad;
		}
		/* read from the CFI data */
		handle->sector_sz = ((cfi.cfi_char[0x30] << 8) |
		    cfi.cfi_char[0x2F]) << 8;
		handle->device_sz = 0x1 << cfi.cfi_char[0x27];
	}

	DPRINTF(DBG_INFO, ("sector_sz: 0x%08x\ndevice_sz: 0x%08x\n",
	    handle->sector_sz, handle->device_sz));

	handle->dev_path = strdup(dev_path);

	handle->fw = (uint32_t *)malloc(handle->device_sz);
	if (handle->fw == NULL) {
		DPRINTF(DBG_ERR, ("\nfw malloc failed (%d)\n", errno));
		goto bad;
	}

	bzero(handle->fw, sizeof (handle->device_sz));
	handle->state |= FWFLASH_IB_STATE_MMAP;

	/* set firmware revision */
	handle->fw_rev.major = init_ioctl.tf_fwrev.tfi_maj;
	handle->fw_rev.minor = init_ioctl.tf_fwrev.tfi_min;
	handle->fw_rev.subminor = init_ioctl.tf_fwrev.tfi_sub;

	/* set hw part number, psid, and name in handle */
	if (init_ioctl.tf_pn_len != 0) {
		/* part number length */
		for (i = 0; i < init_ioctl.tf_pn_len; i++) {
			if (init_ioctl.tf_hwpn[i] == ' ') {
				handle->pn_len = i;
				break;
			}
		}
		if (i == init_ioctl.tf_pn_len) {
			handle->pn_len = init_ioctl.tf_pn_len;
		}
	} else {
		handle->pn_len = 0;
	}

	if (handle->pn_len != 0) {
		handle->info.mlx_pn = malloc(handle->pn_len);
		if (handle->info.mlx_pn == NULL) {
			DPRINTF(DBG_ERR, ("\nhandle PN malloc failed (%d)\n",
			    errno));
			goto bad;
		}
		(void) memcpy(handle->info.mlx_pn, init_ioctl.tf_hwpn,
		    handle->pn_len);
		DPRINTF(DBG_INFO, ("HCA PN (%s)\n", handle->info.mlx_pn));

		/* Find part number, set the rest */
		for (i = 0; i < FWFLASH_MAX_ID; i++) {
			if (strncmp((const char *)init_ioctl.tf_hwpn,
			    mlx_mdr[i].mlx_pn, handle->pn_len) == 0) {
				/* Set PSID */
				handle->info.mlx_psid = malloc(FWFLASH_PSID_SZ);
				if (handle->info.mlx_psid == NULL) {
					DPRINTF(DBG_ERR,
					    ("\nPSID malloc failed (%d)\n",
					    errno));
					goto bad;
				}
				(void) memcpy(handle->info.mlx_psid,
				    mlx_mdr[i].mlx_psid, FWFLASH_PSID_SZ);
				handle->info.mlx_psid[FWFLASH_PSID_SZ] = 0;
				DPRINTF(DBG_INFO, ("HCA PSID (%s)\n",
				    handle->info.mlx_psid));

				/* determine name length */
				for (j = 0; j < FWFLASH_MAX_ID_SZ; j++) {
					int id_char = (int)mlx_mdr[i].mlx_id[j];
					if (!isalpha(id_char) &&
					    !isspace(id_char)) {
						id_size = j + 1;
						break;
					}
				}
				if (j == FWFLASH_MAX_ID_SZ) {
					id_size = FWFLASH_MAX_ID_SZ;
				}

				/* Set string ID */
				handle->info.mlx_id = malloc(id_size);
				if (handle->info.mlx_psid == NULL) {
					DPRINTF(DBG_ERR,
					    ("\nID malloc failed (%d)\n",
					    errno));
					goto bad;
				}
				(void) memcpy(handle->info.mlx_id,
				    mlx_mdr[i].mlx_id, id_size);
				handle->info.mlx_id[id_size] = 0;
				DPRINTF(DBG_INFO, ("HCA Name (%s)\n",
				    handle->info.mlx_id));

				break;
			}
		}
		if (i == FWFLASH_MAX_ID) {
			DPRINTF(DBG_ERR, ("\nUnknown Part Number: (%s)\n",
			    handle->info.mlx_pn));
			handle->pn_len = 0;
		}
	}

	return (handle);
bad:
	/* cleanup */
	if (handle->info.mlx_id != NULL) {
		free(handle->info.mlx_id);
	}
	if (handle->info.mlx_psid != NULL) {
		free(handle->info.mlx_psid);
	}
	if (handle->info.mlx_pn != NULL) {
		free(handle->info.mlx_pn);
	}
	if (handle != NULL) {
		free(handle);
	}
	return (NULL);
}

/*
 * Close device by calling _FINI.
 */
void
fwflash_ib_close(fwflash_ib_hdl_t *handle)
{
	int	ret;

	DPRINTF(DBG_INFO, ("fwflash_ib_close\n"));
	ret = fwflash_ib_i_check_handle(handle);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nInvalid handle\n"));
		return;
	}

	if (handle->fd > 0) {
		(void) ioctl(handle->fd, TAVOR_IOCTL_FLASH_FINI);
		ret = close(handle->fd);
		if (ret != 0) {
			perror("fwflash_ib_close");
			return;
		}
	}

	/* cleanup */
	if (handle->fw != NULL) {
		free(handle->fw);
	}
	if (handle->info.mlx_id != NULL) {
		free(handle->info.mlx_id);
	}
	if (handle->info.mlx_psid != NULL) {
		free(handle->info.mlx_psid);
	}
	if (handle->info.mlx_pn != NULL) {
		free(handle->info.mlx_pn);
	}
	free(handle);
	handle = NULL;
}

/*
 * Driver read/write ioctl calls.
 */
int
fwflash_read_ioctl(fwflash_ib_hdl_t *hdl, tavor_flash_ioctl_t *info)
{
	int ret;

	DPRINTF(DBG_INFO, ("flash_read: fd(%d) tf_type(0x%x) tf_addr(0x%x)\n",
	    hdl->fd, info->tf_type, info->tf_addr));
	ret = ioctl(hdl->fd, TAVOR_IOCTL_FLASH_READ, info);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nTAVOR_IOCTL_FLASH_READ failed (0x%x)\n",
		    errno));
	}
	return (ret);
}

int
fwflash_write_ioctl(fwflash_ib_hdl_t *hdl, tavor_flash_ioctl_t *info)
{
	int ret;

	DPRINTF(DBG_INFO, ("flash_write fd(%d) tf_type(0x%x) tf_addr(0x%x)\n",
	    hdl->fd, info->tf_type, info->tf_addr));
	ret = ioctl(hdl->fd, TAVOR_IOCTL_FLASH_WRITE, info);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nTAVOR_IOCTL_FLASH_WRITE failed (0x%x)\n",
		    errno));
	}
	return (ret);
}

/*
 * Notes:
 * 1. flash read is done in 32 bit quantities, and the driver returns
 *    data in host byteorder form.
 * 2. flash write is done in 8 bit quantities by the driver.
 * 3. data in the flash should be in network byteorder.
 * 4. data in image files is in network byteorder form.
 * 5. data in image structures in memory is kept in network byteorder.
 * 6. the functions in this file deal with data in host byteorder form.
 */

int
fwflash_ib_read_image(fwflash_ib_hdl_t *handle, int type)
{
	tavor_flash_ioctl_t	ioctl_info;
	uint32_t		sector_size;
	int			start_sector;
	int			ps_offset;
	int			ret, len, i;
#ifdef _LITTLE_ENDIAN
	uint32_t		*ptr;
	int			j;
#endif

	DPRINTF(DBG_INFO, ("fwflash_ib_read_image\n"));
	/* Get Sector Size */
	sector_size = fwflash_ib_i_flash_get_sect_size(handle);
	DPRINTF(DBG_INFO, ("sector_size: 0x%x\n", sector_size));

	/* Verify flash info */
	ret = fwflash_ib_i_flash_verify_flash_info(handle, sector_size);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nFailed to verify flash info\n"));
		goto out;
	}

	/* Read IS Sector */
	ioctl_info.tf_type = TAVOR_FLASH_READ_SECTOR;
	ioctl_info.tf_sector_num = 0;
	ioctl_info.tf_sector = FLASH_SECTOR_OFFSET(handle->fw, 0, sector_size);
	ret = fwflash_read_ioctl(handle, &ioctl_info);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nFailed to read IS\n"));
		goto out;
	}
#ifdef _LITTLE_ENDIAN
	/* swap sector contents into network byte order form */
	ptr = (uint32_t *)(uintptr_t)ioctl_info.tf_sector;
	for (i = 0; i < (1 << sector_size)/4; i ++) {
		ptr[i] = htonl(ptr[i]);
	}
#endif

	/* offset is the start of the xPS sector */
	/* 'type' is the sector number input as PPS or SPS */
	ps_offset = type << sector_size;

	DPRINTF(DBG_INFO, ("type: 0x%x\n", type));
	DPRINTF(DBG_INFO, ("ps_offset: 0x%x\n", ps_offset));

	/* Read in PS */
	ioctl_info.tf_type = TAVOR_FLASH_READ_SECTOR;
	ioctl_info.tf_sector_num = type;
	ioctl_info.tf_sector = FLASH_SECTOR_OFFSET(handle->fw, type,
	    sector_size);
	ret = fwflash_read_ioctl(handle, &ioctl_info);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nFailed to read PS\n"));
		goto out;
	}
#ifdef _LITTLE_ENDIAN
	/* swap sector contents into network byte order form */
	ptr = (uint32_t *)(uintptr_t)ioctl_info.tf_sector;
	for (i = 0; i < (1 << sector_size)/4; i ++) {
		ptr[i] = htonl(ptr[i]);
	}
#endif

	/* Verify Valid signature */
	ret = fwflash_ib_i_local_verify_signature(handle, ps_offset);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nFailed to verify signature for %s image\n",
		    type == 0x1 ? "Primary" : "Secondary"));
		goto out;
	}

	/* Verify Valid CRC */
	ret = fwflash_ib_i_local_verify_xps_crc(handle, ps_offset);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nFailed to verify crc for %s image\n",
		    type == 0x1 ? "Primary" : "Secondary"));
		goto out;
	}

	/* Read Firmware Image Size */
	ioctl_info.tf_type = TAVOR_FLASH_READ_QUADLET;
	ioctl_info.tf_addr = ps_offset + FLASH_PS_FW_SIZE_OFFSET;
	ret = fwflash_read_ioctl(handle, &ioctl_info);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nFailed to read FW image size\n"));
		goto out;
	}
	DPRINTF(DBG_INFO, ("fw_size: 0x%x\n", ioctl_info.tf_quadlet));

	/* Based on firmware size, see how many sectors it takes up */
	len = fwflash_ib_i_num_sectors(handle, ioctl_info.tf_quadlet);
	DPRINTF(DBG_INFO, ("num_sectors: 0x%x\n", len));

	/* Get Firmware Start Address */
	ioctl_info.tf_type = TAVOR_FLASH_READ_QUADLET;
	ioctl_info.tf_addr = ps_offset + FLASH_PS_FI_ADDR_OFFSET;
	ret = fwflash_read_ioctl(handle, &ioctl_info);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nFailed to read FW start addr\n"));
		goto out;
	}
	DPRINTF(DBG_INFO, ("fw_addr: 0x%x\n", ioctl_info.tf_quadlet));

	/* Translate fw addr to sector offset */
	start_sector = ioctl_info.tf_quadlet >> sector_size;
	DPRINTF(DBG_INFO, ("start_sector: 0x%x\n", start_sector));

	/* Read one sector at a time */
	ioctl_info.tf_type = TAVOR_FLASH_READ_SECTOR;
	for (i = start_sector; i < (len + start_sector); i++) {
		ioctl_info.tf_sector_num = i;
		ioctl_info.tf_sector = FLASH_SECTOR_OFFSET(handle->fw, i,
		    sector_size);
		ret = fwflash_read_ioctl(handle, &ioctl_info);
		if (ret != 0) {
			DPRINTF(DBG_ERR, ("\nFailed to read sec %d\n", i));
			goto out;
		}
#ifdef _LITTLE_ENDIAN
		/* swap sector contents into network byte order form */
		ptr = (uint32_t *)(uintptr_t)ioctl_info.tf_sector;
		for (j = 0; j < (1 << sector_size)/4; j ++) {
			ptr[j] = htonl(ptr[j]);
		}
#endif

	}

	handle->state |= type;
out:
	return (ret);
}

/*
 * type is PRIMARY or SECONDARY
 */
int
fwflash_ib_write_image(fwflash_ib_hdl_t *handle, int type)
{
	tavor_flash_ioctl_t	ioctl_info;
	int			ps_offset;
	int			sector_size;
	int			start_sector_local;
	int			start_sector_flash;
	int			local_addr, flash_addr;
	int			addr, size;
	int			save_addr;
	int			len, ret, i;
	uint16_t		ver;

	DPRINTF(DBG_INFO, ("fwflash_ib_write_image\n"));
	ret = fwflash_ib_i_check_handle(handle);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nInvalid handle\n"));
		goto out;
	}

	if ((handle->state & type) == 0) {
		DPRINTF(DBG_ERR, ("\nMust read in image first\n"));
		ret = -1;
		goto out;
	}

	/* Check Hardware Rev */
	ver = fwflash_ib_i_check_hwver(handle);
	if (ver != 0) {
		DPRINTF(DBG_ERR, ("\nFirmware missmatch: ver(0x%X) "
		    "hw_ver(0x%X)\n", (ver >> 8), ver & 0xFF));
		ret = -1;
		goto out;
	}

	ret = fwflash_ib_i_flash_verify_is(handle);
	if (ret != 0) {
		DPRINTF(DBG_INFO, ("Writing new Invariant Sector...\n"));
		ret = fwflash_ib_write_is(handle);
		if (ret != 0) {
			DPRINTF(DBG_ERR,
			    ("\nFailed to write Invariant Sector\n"));
			goto out;
		}
	}

	/* Get Sector Size */
	sector_size = fwflash_ib_i_local_get_sect_size(handle);
	DPRINTF(DBG_INFO, ("sector_size: 0x%x\n", sector_size));

	DPRINTF(DBG_INFO, ("type: 0x%x\n", type));
	ps_offset = type << sector_size;
	DPRINTF(DBG_INFO, ("ps_offset: 0x%x\n", ps_offset));

	/* Verify local PS */
	ret = fwflash_ib_i_local_verify(handle, ps_offset);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nFailed to verify local %s image\n",
		    type == 1 ? "Primary" : "Secondary"));
		goto out;
	}

	/* Invalidate FW Signature */
	DPRINTF(DBG_INFO, ("Invalidate flash sig\n"));
	ret = fwflash_ib_i_flash_zero_signature(handle, ps_offset);
	if (ret != 0) {
		goto out;
	}

	/* Invalidate FW CRC */
	DPRINTF(DBG_INFO, ("Invalidate flash crc\n"));
	(void) fwflash_ib_i_flash_zero_crc(handle, ps_offset);

	/* Read Image Size */
	size = fwflash_ib_i_local_get_fw_size(handle, ps_offset);
	DPRINTF(DBG_INFO, ("Local fw size: 0x%x\n", size));

	/* Based on size, calculate how many sectors we need */
	len = fwflash_ib_i_num_sectors(handle, size);
	DPRINTF(DBG_INFO, ("Number of sectors: 0x%x\n", len));

	/* Get Firmware Start Address on local */
	local_addr = fwflash_ib_i_local_get_fw_addr(handle, ps_offset);
	DPRINTF(DBG_INFO, ("Local FW start addr: 0x%x\n", local_addr));

	/* Get Firmware Start Address on flash */
	flash_addr = fwflash_ib_i_flash_get_fw_addr(handle, ps_offset);
	DPRINTF(DBG_INFO, ("Flash FW start addr: 0x%x\n", flash_addr));

	if (local_addr < flash_addr) {
		addr = flash_addr;
	} else {
		addr = local_addr;
	}

	/* Translate fw addr to sector offset */
	start_sector_local = local_addr >> sector_size;
	start_sector_flash  = addr >> sector_size;
	DPRINTF(DBG_INFO, ("local start_sector: 0x%x\n", start_sector_local));
	DPRINTF(DBG_INFO, ("flash start_sector: 0x%x\n", start_sector_flash));

	/* Write one sector of fw image at a time */
	ioctl_info.tf_type = TAVOR_FLASH_WRITE_SECTOR;
	for (i = 0; i < len; i++) {
		ioctl_info.tf_sector_num = start_sector_flash + i;
		ioctl_info.tf_sector = FLASH_SECTOR_OFFSET(handle->fw,
		    start_sector_local + i, sector_size);

		/* give the user some progress output */
		(void) printf(" .");
		(void) fflush((void *)NULL);

		DPRINTF(DBG_INFO, ("Writing sector: 0x%x\n",
		    ioctl_info.tf_sector_num));
		ret = fwflash_write_ioctl(handle, &ioctl_info);
		if (ret != 0) {
			DPRINTF(DBG_ERR, ("\nFailed to write sector (0x%x)\n",
			    ioctl_info.tf_sector_num));
			goto out;
		}
	}

	/* Invalidate local SIG and CRC */
	handle->fw[(ps_offset + FLASH_PS_SIGNATURE_OFFSET) / 4] = 0xFFFFFFFF;
	fwflash_ib_i_local_zero_crc(handle, ps_offset);

	/* Invalidate Firmware Image Address but save it to put back locally */
	save_addr = handle->fw[(ps_offset + FLASH_PS_FI_ADDR_OFFSET) / 4];
	handle->fw[(ps_offset + FLASH_PS_FI_ADDR_OFFSET) / 4] = 0xFFFFFFFF;

	/* Write fw PS */
	ioctl_info.tf_type = TAVOR_FLASH_WRITE_SECTOR;
	ioctl_info.tf_sector_num = type;
	ioctl_info.tf_sector = FLASH_SECTOR_OFFSET(handle->fw, type,
	    sector_size);
	ret = fwflash_write_ioctl(handle, &ioctl_info);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nFailed to write PS\n"));
		goto out;
	}

	/* Make sure fw addr pointer is updated to be correct */
	DPRINTF(DBG_ERR, ("Updating fw addr pointer in PS: 0x%x\n", addr));
	ret = fwflash_ib_i_flash_set_fw_addr(handle, ps_offset, addr);
	if (ret != 0) {
		goto out;
	}

	/* Restore previous firmware address in local image */
	handle->fw[(ps_offset + FLASH_PS_FI_ADDR_OFFSET) / 4] = save_addr;

	/* Set local SIG */
	handle->fw[(ps_offset + FLASH_PS_SIGNATURE_OFFSET) / 4] =
	    (uint32_t)htonl(FLASH_PS_SIGNATURE);

	/* calc local CRC */
	fwflash_ib_i_local_set_xps_crc(handle, ps_offset);

	/* Set CRC */
	ret = fwflash_ib_i_flash_set_xps_crc(handle, ps_offset);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nFailed to set crc\n"));
		goto out;
	}

	/* Set Signature */
	ret = fwflash_ib_i_flash_set_signature(handle, ps_offset);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nFailed to set signature\n"));
		goto out;
	}

	ret = fwflash_ib_i_flash_verify_signature(handle, ps_offset);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nFailed to verify flash sig\n"));
	}
out:
	return (ret);
}

int
fwflash_ib_verify_image(fwflash_ib_hdl_t *handle, int type)
{
	tavor_flash_ioctl_t	ioctl_info;
	uint32_t		*flash;
	uint32_t		start_addr;
	uint32_t		end_addr;
	int			len, size;
	int			sector_size;
	int			start_sector_local;
	int			start_sector_flash;
	int			local_addr, flash_addr;
	int			addr, ps_offset;
	int			ret, i;
#ifdef _LITTLE_ENDIAN
	uint32_t		*ptr;
	int			j;
#endif

	DPRINTF(DBG_INFO, ("fwflash_ib_verify_image\n"));
	ret = fwflash_ib_i_check_handle(handle);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nInvalid handle\n"));
		goto out;
	}

	if ((handle->state & type) == 0) {
		DPRINTF(DBG_ERR, ("\nMust read in an image first\n"));
		ret = -1;
		goto out;
	}

	flash = (uint32_t *)malloc(handle->device_sz);
	if (flash == NULL) {
		DPRINTF(DBG_ERR, ("\nflash malloc failed (0x%x\n", errno));
		ret = -1;
		goto out;
	}

	/* Get Sector Size */
	sector_size = fwflash_ib_i_local_get_sect_size(handle);

	/* Get offset to pointer sector based on type */
	ps_offset = type << sector_size;

	/* Get FW Size */
	size = fwflash_ib_i_local_get_fw_size(handle, ps_offset);

	/* Based on size, determine number of sectors needed */
	len = fwflash_ib_i_num_sectors(handle, size);

	/* First read IS sector */
	ioctl_info.tf_type = TAVOR_FLASH_READ_SECTOR;
	ioctl_info.tf_sector_num = 0;
	ioctl_info.tf_sector = FLASH_SECTOR_OFFSET(&flash[0], 0, sector_size);
	ret = fwflash_read_ioctl(handle, &ioctl_info);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nFailed to read IS\n"));
		goto out;
	}
#ifdef _LITTLE_ENDIAN
	/* swap sector contents into network byte order form */
	ptr = (uint32_t *)(uintptr_t)ioctl_info.tf_sector;
	for (i = 0; i < (1 << sector_size)/4; i ++) {
		ptr[i] = htonl(ptr[i]);
	}
#endif

	/* Compare IS */
	DPRINTF(DBG_INFO, ("Comparing IS..\n"));
	for (i = 0; i < (1 << sector_size) / 4; i++) {
		if (flash[i] != handle->fw[i]) {
			DPRINTF(DBG_ERR, ("\nIS Verify failed at offset: %d\n",
			    i));
			DPRINTF(DBG_ERR, ("expected: 0x%X, actual: 0x%X\n",
			    handle->fw[i], flash[i]));
			ret = -1;
			goto out;
		}
	}

	/* First read pointer sector */
	ioctl_info.tf_type = TAVOR_FLASH_READ_SECTOR;
	ioctl_info.tf_sector_num = type;
	ioctl_info.tf_sector =
	    FLASH_SECTOR_OFFSET(&flash[0], type, sector_size);
	ret = fwflash_read_ioctl(handle, &ioctl_info);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nFailed to read pointer (0x%x)\n", type));
		goto out;
	}
#ifdef _LITTLE_ENDIAN
	/* swap sector contents into network byte order form */
	ptr = (uint32_t *)(uintptr_t)ioctl_info.tf_sector;
	for (i = 0; i < (1 << sector_size)/4; i ++) {
		ptr[i] = htonl(ptr[i]);
	}
#endif
	/* Get Firmware Start Address */
	local_addr = fwflash_ib_i_local_get_fw_addr(handle, ps_offset);
	DPRINTF(DBG_INFO, ("Local FW start addr: 0x%x\n", local_addr));

	/* Get Firmware Start Address on flash */
	flash_addr = fwflash_ib_i_flash_get_fw_addr(handle, ps_offset);
	DPRINTF(DBG_INFO, ("\nFlash FW start addr: 0x%x\n", flash_addr));

	/* Compare PS */
	DPRINTF(DBG_INFO, ("Comparing PS: start: 0x%x, end: 0x%x\n",
	    ps_offset, ps_offset + (1 << sector_size)));
	for (i = ps_offset / 4; i < (ps_offset + (1 << sector_size)) / 4; i++) {
		if (flash[i] != handle->fw[i]) {
			/* Skip error, if firmware image addr is correct */
			if (i == (ps_offset / 4) &&
			    ntohl(flash[i]) == flash_addr &&
			    ntohl(handle->fw[i]) == local_addr) {
				continue;
			}
			DPRINTF(DBG_ERR, ("\nPS Verify failed at offset: %d\n",
			    i));
			DPRINTF(DBG_ERR, ("expected: 0x%X, actual: 0x%X\n",
			    handle->fw[i], flash[i]));
			ret = -1;
			goto out;
		}
	}

	/* Setup addr pointer based on firmware size differences */
	if (local_addr < flash_addr) {
		addr = flash_addr;
	} else {
		addr = local_addr;
	}

	/* Translate fw addr to sector offset */
	start_sector_local = local_addr >> sector_size;
	start_sector_flash  = addr >> sector_size;
	DPRINTF(DBG_INFO, ("start_sector: 0x%x\n", start_sector_local));
	DPRINTF(DBG_INFO, ("start_sector: 0x%x\n", start_sector_flash));

	/* Read FW image */
	ioctl_info.tf_type = TAVOR_FLASH_READ_SECTOR;
	for (i = 0; i < len; i++) {
		ioctl_info.tf_sector_num = start_sector_flash + i;
		ioctl_info.tf_sector = FLASH_SECTOR_OFFSET(&flash[0],
		    start_sector_local + i, sector_size);
		ret = fwflash_read_ioctl(handle, &ioctl_info);
		if (ret != 0) {
			DPRINTF(DBG_ERR, ("\nFailed to read FW\n"));
			goto out;
		}
#ifdef _LITTLE_ENDIAN
		/* swap sector contents into network byte order form */
		ptr = (uint32_t *)(uintptr_t)ioctl_info.tf_sector;
		for (j = 0; j < (1 << sector_size)/4; j ++) {
			ptr[j] = htonl(ptr[j]);
		}
#endif
	}

	/* Compare FW Image */
	start_addr = start_sector_local << sector_size;
	end_addr = start_addr + size;
	DPRINTF(DBG_INFO, ("FW Compare: start: 0x%x, end: 0x%x\n", start_addr,
	    end_addr));

	for (i = start_addr / 4;
	    i < end_addr / 4; i++) {
		if (flash[i] != handle->fw[i]) {
			DPRINTF(DBG_ERR, ("\nVerify failed at offset: 0x%x\n",
			    i));
			DPRINTF(DBG_ERR, ("expected: 0x%X, actual: 0x%X\n",
			    handle->fw[i], flash[i]));
			ret = -1;
			break;
		}
	}
out:
	if (flash != NULL) {
		free(flash);
	}
	return (ret);
}

int
fwflash_ib_write_is(fwflash_ib_hdl_t *handle)
{
	tavor_flash_ioctl_t	ioctl_info;
	int			sector_size;
	int			ret;

	DPRINTF(DBG_INFO, ("fwflash_ib_write_is\n"));
	if ((handle->state & FWFLASH_IB_STATE_PFI_IMAGE) == 0 &&
	    (handle->state & FWFLASH_IB_STATE_SFI_IMAGE) == 0) {
		DPRINTF(DBG_ERR, ("Must read in image first.\n"));
		return (-1);
	}

	/* Get sector size */
	sector_size = fwflash_ib_i_local_get_sect_size(handle);

	/* Write one sector of IS */
	ioctl_info.tf_type = TAVOR_FLASH_WRITE_SECTOR;
	ioctl_info.tf_sector_num = 0;
	ioctl_info.tf_sector = FLASH_SECTOR_OFFSET(handle->fw, 0, sector_size);

	ret = fwflash_write_ioctl(handle, &ioctl_info);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nFailed to write IS\n"));
		return (-1);
	}

	return (0);
}

int
fwflash_ib_read_file(fwflash_ib_hdl_t *handle, const char *filename)
{
	FILE	*fp;
	char	ans;
	int	sector_size;
	int	ps_okay[2];
	int	ps_offset;
	int	len, ps;
	int	ret, i;

	DPRINTF(DBG_INFO, ("fwflash_ib_read_file: file %s\n", filename));
	fp = fopen(filename, "r");
	if (fp == NULL) {
		(void) fprintf(stderr, "\n");
		(void) fprintf(stderr, gettext("Unknown filename"));
		(void) fprintf(stderr, ": %s\n", filename);
		ret = -1;
		goto out;
	}

	len = handle->device_sz;
	ret = fwflash_ib_i_read_file(fp, len, &handle->fw[0]);
	if (ret != 0) {
		(void) fprintf(stderr, "\n");
		(void) fprintf(stderr, gettext("Error reading file"));
		(void) fprintf(stderr, ": %s\n", filename);
		goto out;
	}

	/* Get sector size */
	sector_size = fwflash_ib_i_local_get_sect_size(handle);

	/* Verify flash info */
	ret = fwflash_ib_i_flash_verify_flash_info(handle, sector_size);
	if (ret != 0) {
		(void) fprintf(stderr, "\n");
		(void) fprintf(stderr, gettext("Unknown file type"));
		(void) fprintf(stderr, ": %s\n", filename);
		goto out;
	}

	handle->hwfw_match = 0;
	for (i = 1; i < 3; i++) {
		/* set array pointer */
		ps = i - 1;

		/* Read PS */
		ps_offset = i << sector_size;

		ps_okay[ps] = fwflash_ib_i_local_verify_xps_crc(handle,
		    ps_offset);

		if (ps_okay[ps] == 0) {
			/* set state field correctly */
			handle->state |= i;
		}

		/* verify fw matches the hardware */
		fwflash_ib_i_flash_verify_flash_match(handle, ps_offset, i);
	}

	if (handle->hwfw_match == 0) {
		(void) fprintf(stderr, "\n\t");
		if (handle->pn_len != 0) {
			/* HW VPD exist and a mismatch was found */
			(void) fprintf(stderr, gettext(
			    "Please verify that the firmware image"
			    "\n\tis intended for use with this hardware"));
		} else {
			(void) fprintf(stdout, gettext(
			    "Unable to verify firmware is appropriate"
			    "\n\tfor the hardware"));
		}
		(void) fprintf(stdout, "\n\t");
		(void) fprintf(stdout, gettext("Do you want to continue"));
		(void) fprintf(stdout, " (Y/N): ");
		ans = getchar();
		if (ans != 'Y' && ans != 'y') {
			ret = -1;
		} else {
			fwflash_arg_list |= FWFLASH_YES_FLAG;
			ret = 0;
		}
	}

out:
	if (fp != NULL) {
		(void) fclose(fp);
	}
	return (ret);
}

int
fwflash_ib_write_file(fwflash_ib_hdl_t *handle, const char *filename)
{
	FILE		*fp;
	uint32_t	*fw;
	uint8_t		*fwp;
	int		ps_offset;
	int		sector;
	int		sector_size;
	int		sector_size_val;
	int		ps_okay[2];
	uint32_t	fw_addr[2];
	uint32_t	fw_size[2];
	uint32_t	fw_new_addr[2];
	uint16_t	crc;
	int		addr;
	int		len;
	int		ret;
	int		ps;
	int		i;

	DPRINTF(DBG_INFO, ("fwflash_ib_write_file\n"));
	ret = fwflash_ib_i_check_handle(handle);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nInvalid handle\n"));
		goto out;
	}

	if ((handle->state & FWFLASH_IB_STATE_PFI_IMAGE) == 0 &&
	    (handle->state & FWFLASH_IB_STATE_SFI_IMAGE) == 0) {
		DPRINTF(DBG_ERR, ("Must read in image first.\n"));
		return (-1);
	}

	fp = fopen(filename, "w");
	if (fp == NULL) {
		(void) fprintf(stderr, "\n");
		(void) fprintf(stderr, gettext("Unknown filename"));
		(void) fprintf(stderr, ": %s\n", filename);
		ret = -1;
		goto out;
	}

	/* Get Sector Size */
	sector_size = fwflash_ib_i_local_get_sect_size(handle);
	sector_size_val = 1 << sector_size;
	DPRINTF(DBG_INFO, ("sector_size: 0x%x\n", sector_size));

	for (i = 1; i < 3; i++) {
		/* set array pointer */
		ps = i - 1;

		/* Read PS */
		ps_offset = i << sector_size;

		ps_okay[ps] = fwflash_ib_i_local_verify(handle,
		    ps_offset);

		if (ps_okay[ps] != 0) {
			continue;
		}

		/* Get FW addr */
		fw_addr[ps] = fwflash_ib_i_local_get_fw_addr(handle,
		    ps_offset);

		/* Get length */
		fw_size[ps] = fwflash_ib_i_local_get_fw_size(handle,
		    ps_offset);
	}

	if (ps_okay[0] != 0 && ps_okay[1] != 0) {
		(void) fprintf(stderr,
		    gettext("ERROR: no valid Pointer Sector found"));
		(void) fprintf(stderr, "\n");

		(void) fclose(fp);
		return (-1);
	}

	/* Build image to write out */
	fw = (uint32_t *)malloc(handle->device_sz);
	fwp = (uint8_t *)&fw[0];
	addr = 3 << sector_size;
	len = 3 << sector_size; /* len is always at least 3 sectors */

	/* Copy IS */
	(void) memcpy(&fw[0], &handle->fw[0], sector_size_val);

	/* Setup PS */
	if (ps_okay[0] == 0) {
		ps_offset = 1 << sector_size;
		fw_new_addr[0] = addr;

		/* Copy in PS */
		(void) memcpy(&fw[ps_offset / 4], &handle->fw[ps_offset / 4],
		    sector_size_val);

		/* Set new FW addr */
		fw[(ps_offset + FLASH_PS_FI_ADDR_OFFSET) / 4] =
		    htonl(fw_new_addr[0]);

		/* Set new Crc16 */
		crc = crc16((uint8_t *)
		    &fw[ps_offset / 4], FLASH_PS_CRC16_SIZE);
		crc = htons(crc);
		(void) memcpy(&fwp[ps_offset + FLASH_PS_CRC16_OFFSET], &crc, 2);

		/* Copy FW Image */
		(void) memcpy(&fw[fw_new_addr[0] / 4],
		    &handle->fw[fw_addr[0] / 4],
		    fw_size[0]);

		len += (fwflash_ib_i_num_sectors(handle,
		    fw_size[0]) << sector_size);

		if (fw_addr[0] != fw_addr[1]) {
			sector = (fw_addr[0] + fw_size[0]) >> sector_size;
			addr = (sector + 1) << sector_size;
		}
	}

	if (ps_okay[1] == 0) {
		ps_offset = 2 << sector_size;
		fw_new_addr[1] = addr;

		/* Copy in PS */
		(void) memcpy(&fw[ps_offset / 4], &handle->fw[ps_offset / 4],
		    sector_size_val);

		/* Set new FW addr */
		fw[(ps_offset + FLASH_PS_FI_ADDR_OFFSET) / 4] =
		    htonl(fw_new_addr[1]);

		/* Set new Crc16 */
		crc = crc16((uint8_t *)&fw[ps_offset / 4],
		    FLASH_PS_CRC16_SIZE);
		crc = htons(crc);
		(void) memcpy(&fwp[ps_offset + FLASH_PS_CRC16_OFFSET], &crc, 2);

		len += fw_size[1];

		/* Copy FW Image if needed */
		if (fw_addr[0] != fw_addr[1]) {
			(void) memcpy(&fw[fw_new_addr[1] / 4],
			    &handle->fw[fw_addr[1] / 4],
			    fw_size[1]);
		}
	}

	ret = fwrite(&fw[0], len, 1, fp);
	if (ret == 0) {
		(void) fprintf(stderr, "\n");
		(void) fprintf(stderr, gettext("ERROR: fwrite failed"));
		(void) fprintf(stderr, "\n");
		perror("fwrite");
		(void) fclose(fp);
		return (-1);
	}

	(void) fclose(fp);
out:
	return (ret);
}

int
fwflash_ib_set_guids(fwflash_ib_hdl_t *handle, void *arg, int type)
{
	uint32_t	addr;
	uint32_t	*guids;
	uint32_t	fw_addr;
	uint32_t	guid_ptr;
	int		sector_size;
	int		ps_offset;
	int		ret = 0;

	DPRINTF(DBG_INFO, ("fwflash_ib_set_guids\n"));
	if (arg == NULL) {
		DPRINTF(DBG_ERR, ("\nNULL guids\n"));
		ret = -1;
		goto out;
	}

	if ((handle->state & FWFLASH_IB_STATE_MMAP) == 0) {
		DPRINTF(DBG_INFO, ("\nFWFLASH_IB_STATE_MMAP\n"));
		goto out;
	}

	if (type == 0x1 && (handle->state & FWFLASH_IB_STATE_PFI_IMAGE) == 0) {
		DPRINTF(DBG_INFO, ("Reading primary from flash\n"));
		ret = fwflash_ib_read_image(handle, type);
		if (ret != 0) {
			DPRINTF(DBG_ERR, ("\nFailed to read PFI\n"));
			goto out;
		}
	}

	if (type == 0x2 && (handle->state & FWFLASH_IB_STATE_SFI_IMAGE) == 0) {
		DPRINTF(DBG_INFO, ("Reading secondary from flash\n"));
		ret = fwflash_ib_read_image(handle, type);
		if (ret != 0) {
			DPRINTF(DBG_ERR, ("\nFailed to read SFI\n"));
			goto out;
		}
	}

	/* Read Sector Size */
	sector_size = fwflash_ib_i_local_get_sect_size(handle);
	DPRINTF(DBG_INFO, ("sector_size: 0x%x\n", sector_size));

	/* ps_offset is the start of the xPS sector */
	/* 'type' is the sector number input as PPS or SPS */
	ps_offset = type << sector_size;
	DPRINTF(DBG_INFO, ("ps_offset: 0x%x\n", ps_offset));

	fw_addr = fwflash_ib_i_local_get_fw_addr(handle, ps_offset);
	DPRINTF(DBG_INFO, ("fw_addr: 0x%x\n", fw_addr));

	guid_ptr = ntohl(handle->fw[(fw_addr + FLASH_GUID_PTR) / 4]);
	DPRINTF(DBG_INFO, ("guid_ptr: 0x%x\n", guid_ptr));

	guids = (uint32_t *)arg;
	addr = (fw_addr + guid_ptr + FLASH_FI_NGUID_OFFSET) / 4;
	DPRINTF(DBG_INFO, ("guid_start_addr: 0x%x\n", addr * 4));

	/*
	 * guids are supplied by callers as 64 bit values in host byteorder.
	 * Storage is in network byteorder.
	 */
#ifdef _BIG_ENDIAN
	if (handle->state & FWFLASH_IB_STATE_GUIDN) {
		handle->fw[addr] = guids[0];
		handle->fw[addr + 1] = guids[1];
	}

	if (handle->state & FWFLASH_IB_STATE_GUID1) {
		handle->fw[addr + 2] = guids[2];
		handle->fw[addr + 3] = guids[3];
	}

	if (handle->state & FWFLASH_IB_STATE_GUID2) {
		handle->fw[addr + 4] = guids[4];
		handle->fw[addr + 5] = guids[5];
	}

	if (handle->state & FWFLASH_IB_STATE_GUIDS) {
		handle->fw[addr + 6] = guids[6];
		handle->fw[addr + 7] = guids[7];
	}
#else
	if (handle->state & FWFLASH_IB_STATE_GUIDN) {
		handle->fw[addr] = htonl(guids[1]);
		handle->fw[addr + 1] = htonl(guids[0]);
	}

	if (handle->state & FWFLASH_IB_STATE_GUID1) {
		handle->fw[addr + 2] = htonl(guids[3]);
		handle->fw[addr + 3] = htonl(guids[2]);
	}

	if (handle->state & FWFLASH_IB_STATE_GUID2) {
		handle->fw[addr + 4] = htonl(guids[5]);
		handle->fw[addr + 5] = htonl(guids[4]);
	}

	if (handle->state & FWFLASH_IB_STATE_GUIDS) {
		handle->fw[addr + 6] = htonl(guids[7]);
		handle->fw[addr + 7] = htonl(guids[6]);
	}
#endif

	fwflash_ib_i_local_set_guid_crc(handle, (addr * 4) - 0x10);
out:
	return (ret);
}

int
fwflash_ib_flash_read_guids(fwflash_ib_hdl_t *handle, void *guids, int type)
{
	int		ret;
#ifdef _LITTLE_ENDIAN
	uint32_t	*ptr, tmp;
#endif

	DPRINTF(DBG_INFO, ("fwflash_ib_flash_read_guids\n"));
	ret = fwflash_ib_i_check_handle(handle);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nInvalid handle\n"));
		goto out;
	}

	if (guids == NULL) {
		DPRINTF(DBG_INFO, ("\nNULL guids\n"));
		ret = -1;
		goto out;
	}

	ret = fwflash_ib_i_flash_read_guids(handle, guids, type);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nFailed to read GUIDs\n"));
		goto out;
	}

#ifdef _LITTLE_ENDIAN
	/*
	 * guids are read as pairs of 32 bit host byteorder values and treated
	 * by callers as 64 bit values. So swap each pair of 32 bit values
	 * to make them correct
	 */
	ptr = (uint32_t *)guids;
	for (ret = 0; ret < 8; ret += 2) {
		tmp = ptr[ret];
		ptr[ret] = ptr[ret+1];
		ptr[ret+1] = tmp;
	}
#endif

	handle->state |= FWFLASH_IB_STATE_GUIDN | FWFLASH_IB_STATE_GUID1 |
	    FWFLASH_IB_STATE_GUID2 | FWFLASH_IB_STATE_GUIDS;
	ret = fwflash_ib_set_guids(handle, guids, type);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nFailed to set GUIDs\n"));
	}
out:
	return (ret);
}

/*
 * Notes:
 * 1. flash read is done in 32 bit quantities, and the driver returns
 *    data in host byteorder form.
 * 2. flash write is done in 8 bit quantities by the driver.
 * 3. data in the flash should be in network byteorder.
 * 4. data in image files is in network byteorder form.
 * 5. data in image structures in memory is kept in network byteorder.
 * 6. the functions in this file only deal with 32 bit and smaller data
 *    in host byteorder form.
 */

static int
fwflash_ib_i_check_handle(fwflash_ib_hdl_t *handle)
{
	if ((handle == NULL) || (handle->magic != FWFLASH_IB_MAGIC_NUMBER)) {
		return (-1);
	}
	return (0);
}

static int
fwflash_ib_i_num_sectors(fwflash_ib_hdl_t *handle, int size)
{
	int	num_sectors;
	int	mod;

	num_sectors = size / handle->sector_sz;
	mod = size % handle->sector_sz;

	if (mod > 0) {
		num_sectors++;
	}
	return (num_sectors);
}

static int
fwflash_ib_i_read_file(FILE *fp, int len, void *buf)
{
	uint32_t	*bg;
	int		ret;
	int		i;

	bg = (uint32_t *)buf;

	for (i = 0; i < len / 4; i++) {
		ret = fread(&bg[i], 4, 1, fp);
		if (ret == 0) {
			if (feof(fp) != 0) {
				break;
			} else {
				return (ferror(fp));
			}
		}
	}
	return (0);
}

static int
fwflash_ib_i_local_verify(fwflash_ib_hdl_t *handle, uint32_t offset)
{
	int	ret;

	ret = fwflash_ib_i_local_verify_signature(handle, offset);
	if (ret != 0) {
		return (ret);
	}

	ret = fwflash_ib_i_local_verify_vsd(handle, offset);
	if (ret != 0) {
		return (ret);
	}

	ret = fwflash_ib_i_local_verify_xps_crc(handle, offset);
	return (ret);
}

static int
fwflash_ib_i_flash_verify_signature(fwflash_ib_hdl_t *handle, uint32_t offset)
{
	tavor_flash_ioctl_t	ioctl_info;
	int			ret;

	DPRINTF(DBG_INFO, ("fwflash_ib_i_flash_verify_signature\n"));
	ioctl_info.tf_type = TAVOR_FLASH_READ_QUADLET;
	ioctl_info.tf_addr = offset + FLASH_PS_SIGNATURE_OFFSET;
	ret = fwflash_read_ioctl(handle, &ioctl_info);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nFailed to read sig\n"));
		goto out;
	}

	DPRINTF(DBG_INFO, ("local_quadlet: %08x, ps_signature: %08x\n",
	    ioctl_info.tf_quadlet, FLASH_PS_SIGNATURE));

	if (ioctl_info.tf_quadlet != FLASH_PS_SIGNATURE) {
		DPRINTF(DBG_ERR, ("flash signature compare failed.\n"));
		ret = -1;
	}
out:
	return (ret);
}

/*
 * We would not need this if it were not for Cisco's image using the
 * VSD to store boot options and flags for their PXE boot extension,
 * but not setting the proper default values for the extension in
 * their image.  As it turns out, some of the data for the extension
 * is stored in the VSD in the firmware file, and the rest is set by
 * their firmware utility.  That's not very nice for us, since it could
 * change at any time without our knowledge.  Well, for the time being,
 * we can use this to examine and fix up anything in the VSD that we might
 * need to handle, for any vendor specific settings.
 */
static int
fwflash_ib_i_local_verify_vsd(fwflash_ib_hdl_t *handle, uint32_t offset)
{
	vsd_t		vsd;
	uint32_t	addr;
	uint16_t	vsd_sig1;
	uint16_t	vsd_sig2;
	int		i;

	DPRINTF(DBG_INFO, ("fwflash_ib_i_local_verify_vsd\n"));
	DPRINTF(DBG_INFO, ("verifying vsd in PS at offset 0x%x\n", offset));
	/* read the VSD into local storage */
	addr = offset + FLASH_PS_VSD_OFFSET;
	for (i = 0; i < FLASH_PS_VSD_LENGTH / 4; i++) {
		vsd.vsd_int[i] = (uint32_t)ntohl(handle->fw[(addr / 4) + i]);
	}

	/* check for the Cisco signature at the first and last 16b */
	vsd_sig1 = (uint16_t)(vsd.vsd_int[0] >> 16);
	vsd_sig2 = (uint16_t)vsd.vsd_int[(FLASH_PS_VSD_LENGTH / 4) - 1];

	if (vsd_sig1 == FLASH_VSD_CISCO_SIGNATURE &&
	    vsd_sig2 == FLASH_VSD_CISCO_SIGNATURE) {

		DPRINTF(DBG_INFO, ("VSD contains Cisco signatures\n"));

		/*
		 * Fix up this VSD so that it contains the proper
		 * default values for the Cisco, nee Topspin, boot
		 * extension(s)
		 */

		/*
		 * Set the Cisco VSD's "boot_version" to '2'. This value is
		 * located in the 2nd byte of the last dword. Just or the bit
		 * in and move on.
		 */
		handle->fw[(addr / 4) + ((FLASH_PS_VSD_LENGTH - 1) / 4)] =
		    htonl(vsd.vsd_int[(FLASH_PS_VSD_LENGTH / 4) - 1] |
		    0x00020000);

		/*
		 * Set some defaults for the SRP boot extension. This is
		 * currently the only extension we support. The boot options
		 * flags are located in the second dword of the VSD.
		 */
		DPRINTF(DBG_INFO, ("boot flags in Cisco image currently "
		    "set to 0x%08x\n", vsd.vsd_int[1]));

		handle->fw[(addr / 4) + 1] = htonl(vsd.vsd_int[1] |
		    FLASH_VSD_CISCO_FLAG_AUTOUPGRADE |
		    FLASH_VSD_CISCO_BOOT_OPTIONS |
		    FLASH_VSD_CISCO_FLAG_BOOT_ENABLE_PORT_1 |
		    FLASH_VSD_CISCO_FLAG_BOOT_ENABLE_PORT_2 |
		    FLASH_VSD_CISCO_FLAG_BOOT_ENABLE_SCAN |
		    FLASH_VSD_CISCO_FLAG_BOOT_TYPE_WELL_KNOWN |
		    FLASH_VSD_CISCO_FLAG_BOOT_TRY_FOREVER);

		DPRINTF(DBG_INFO, ("boot flags now set to 0x%08x\n",
		    ntohl(handle->fw[(addr / 4) + 1])));

		/* Set updated PS CRC */
		fwflash_ib_i_local_set_xps_crc(handle, offset);
	}

	return (0);
}

static int
fwflash_ib_i_local_verify_signature(fwflash_ib_hdl_t *handle, uint32_t offset)
{
	uint32_t	addr;

	addr = offset + FLASH_PS_SIGNATURE_OFFSET;

	if (ntohl(handle->fw[addr / 4]) != FLASH_PS_SIGNATURE) {
		return (-1);
	}
	return (0);
}

static int
fwflash_ib_i_flash_zero_signature(fwflash_ib_hdl_t *handle, uint32_t offset)
{
	tavor_flash_ioctl_t	ioctl_info;
	int			ret, i;

	DPRINTF(DBG_INFO, ("fwflash_ib_i_flash_zero_signature\n"));
	for (i = 0; i < 4; i++) {
		ioctl_info.tf_type = TAVOR_FLASH_WRITE_BYTE;
		ioctl_info.tf_addr = offset + FLASH_PS_SIGNATURE_OFFSET + i;
		ioctl_info.tf_byte = 0;

		ret = fwflash_write_ioctl(handle, &ioctl_info);
		if (ret != 0) {
			DPRINTF(DBG_ERR, ("\nFailed to write sig\n"));
			return (ret);
		}
	}
	return (0);
}

/*
 * Due to calling convention, handle->fw is in network byte order.
 * CRC must be calculated on bytes in network byte order.
 *
 * Yet when compared, they are compared in host byteorder.  Since the crc16
 * function returns host byteorder.
 */

static int
fwflash_ib_i_local_verify_xps_crc(fwflash_ib_hdl_t *handle, uint32_t offset)
{
	uint16_t	crc;
	uint16_t	local_crc;

	DPRINTF(DBG_INFO, ("fwflash_ib_i_local_verify_xps_crc\n"));
	crc = (crc16((uint8_t *)&handle->fw[offset / 4], FLASH_PS_CRC16_SIZE));

	local_crc = (uint16_t)(ntohl(handle->fw[(offset +
	    FLASH_PS_CRC16_OFFSET) /4]));

	DPRINTF(DBG_INFO, ("local crc: 0x%x calc crc: 0x%x\n", local_crc, crc));

	if (crc != local_crc) {
		DPRINTF(DBG_ERR, ("\nFailed to verify crc\n"));
		return (-1);
	}
	return (0);
}

static void
fwflash_ib_i_local_set_xps_crc(fwflash_ib_hdl_t *handle, uint32_t offset)
{
	uint16_t	crc;
	uint8_t		*fw_p = (uint8_t *)&handle->fw[0];

	DPRINTF(DBG_INFO, ("fwflash_ib_i_local_set_xps_crc\n"));
	crc = htons(crc16((uint8_t *)&handle->fw[offset / 4],
	    FLASH_PS_CRC16_SIZE));

	DPRINTF(DBG_INFO, ("set local xps crc: %x\n", ntohs(crc)));
	(void) memcpy(&fw_p[offset + FLASH_PS_CRC16_OFFSET], &crc, 2);
}

static int
fwflash_ib_i_flash_set_xps_crc(fwflash_ib_hdl_t *handle, uint32_t offset)
{
	tavor_flash_ioctl_t	ioctl_info;
	uint16_t		crc;
	uint8_t			*crc_p = (uint8_t *)&crc;
	int			ret, i;

	DPRINTF(DBG_INFO, ("fwflash_ib_i_flash_set_xps_crc\n"));
	crc = htons(crc16((uint8_t *)&handle->fw[offset / 4],
	    FLASH_PS_CRC16_SIZE));

	DPRINTF(DBG_INFO, ("set flash xps crc: %x\n", ntohs(crc)));
	for (i = 0; i < 2; i++) {
		ioctl_info.tf_type = TAVOR_FLASH_WRITE_BYTE;
		ioctl_info.tf_addr = offset + FLASH_PS_CRC16_OFFSET + i;
		ioctl_info.tf_byte = crc_p[i];

		ret = fwflash_write_ioctl(handle, &ioctl_info);
		if (ret != 0) {
			DPRINTF(DBG_ERR, ("\nFailed to write crc (0x%x)\n", i));
			return (ret);
		}
	}
	return (0);
}

static uint32_t
fwflash_ib_i_flash_get_sect_size(fwflash_ib_hdl_t *handle)
{
	tavor_flash_ioctl_t	ioctl_info;
	int			ret;

	DPRINTF(DBG_INFO, ("fwflash_ib_i_flash_get_sect_size\n"));
	ioctl_info.tf_type = TAVOR_FLASH_READ_QUADLET;
	ioctl_info.tf_addr = FLASH_IS_SECT_SIZE_PTR;
	ret = fwflash_read_ioctl(handle, &ioctl_info);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nFailed to read size\n"));
		return (ret);
	}

	DPRINTF(DBG_INFO, ("sect size ptr: 0x%x\n", ioctl_info.tf_quadlet));

	ioctl_info.tf_type = TAVOR_FLASH_READ_QUADLET;
	ioctl_info.tf_addr = ioctl_info.tf_quadlet +
	    FLASH_IS_SECTOR_SIZE_OFFSET;
	ret = fwflash_read_ioctl(handle, &ioctl_info);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nFailed to read size\n"));
		return (ret);
	}

#ifdef DEBUG
	{
	uint8_t	*byte;
	int	i;

	byte = (uint8_t *)&ioctl_info.tf_quadlet;
	DPRINTF(DBG_INFO, ("sect size quadlet: %x\n", ioctl_info.tf_quadlet));
	for (i = 0; i < 4; i++)
		DPRINTF(DBG_INFO, ("sect size[%d]: %x\n", i, byte[i]));
	}
#endif /* DEBUG */
	return (ioctl_info.tf_quadlet & FLASH_IS_SECTOR_SIZE_MASK);
}

static uint32_t
fwflash_ib_i_local_get_sect_size(fwflash_ib_hdl_t *handle)
{
	uint32_t	size;
	int		offset;

	offset = FLASH_IS_SECTOR_SIZE_OFFSET +
	    ntohl(handle->fw[FLASH_IS_SECT_SIZE_PTR / 4]);

	if (offset > handle->device_sz) {
		DPRINTF(DBG_INFO, ("offset too large: %x\n", offset));
		return (0);
	}
	size = ntohl(handle->fw[offset / 4]);

	return (size & FLASH_IS_SECTOR_SIZE_MASK);
}

static int
fwflash_ib_i_flash_verify_is(fwflash_ib_hdl_t *handle)
{
	tavor_flash_ioctl_t	ioctl_info;
	uint32_t		*flash;
	int			sector_size;
	int			ps_offset;
	int			ret, i;
#ifdef _LITTLE_ENDIAN
	uint32_t		*ptr;
#endif

	DPRINTF(DBG_INFO, ("fwflash_ib_i_flash_verify_is\n"));
	if ((handle->state & FWFLASH_IB_STATE_PFI_IMAGE) == 0 &&
	    (handle->state & FWFLASH_IB_STATE_SFI_IMAGE) == 0) {
		DPRINTF(DBG_ERR, ("\nMust read in an image first\n"));
		ret = -1;
		goto out;
	}

	/* Get Sector Size */
	sector_size = fwflash_ib_i_local_get_sect_size(handle);

	/* Get offset to pointer sector based on type */
	ps_offset = 1 << sector_size;

	flash = (uint32_t *)malloc(handle->device_sz);
	if (flash == NULL) {
		DPRINTF(DBG_ERR, ("\nmalloc failed (0x%x)\n", errno));
		ret = -1;
		goto out;
	}

	/* Read IS sector */
	ioctl_info.tf_type = TAVOR_FLASH_READ_SECTOR;
	ioctl_info.tf_sector_num = 0;
	ioctl_info.tf_sector = FLASH_SECTOR_OFFSET(&flash[0], 0, sector_size);
	ret = fwflash_read_ioctl(handle, &ioctl_info);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nFailed to read IS\n"));
		goto out;
	}
#ifdef _LITTLE_ENDIAN
	/* swap sector contents into network byte order form */
	ptr = (uint32_t *)(uintptr_t)ioctl_info.tf_sector;
	for (i = 0; i < (1 << sector_size)/4; i ++) {
		ptr[i] = htonl(ptr[i]);
	}
#endif

	/* Compare IS */
	for (i = 0; i < (ps_offset / 4); i++) {
		if (flash[i] != handle->fw[i]) {
			DPRINTF(DBG_ERR, ("\nVerify IS failed at offset: %d\n",
			    i));
			DPRINTF(DBG_ERR, ("expected: 0x%X, actual: 0x%X\n",
			    handle->fw[i], flash[i]));
			ret = -1;
			break;
		}
	}
out:
	if (flash != NULL) {
		free(flash);
	}
	return (ret);
}

static int
fwflash_ib_i_flash_verify_flash_info(fwflash_ib_hdl_t *handle, uint32_t size)
{
	DPRINTF(DBG_INFO, ("fwflash_ib_i_flash_verify_flash_info\n"));
	if (handle->sector_sz != (1 << size)) {
		DPRINTF(DBG_ERR, ("Sector size values didn't match. "
		    "Expected: 0x%08x, actual: 0x%08x.\n",
		    handle->sector_sz, 1 << size));
		return (1);
	}
	return (0);
}

static uchar_t *
fwflash_ib_i_flash_get_psid(fwflash_ib_hdl_t *handle, int offset)
{
	int	i;
	uchar_t	*psid_str;
#ifndef _LITTLE_ENDIAN
	uint32_t data32;
#endif /* _LITTLE_ENDIAN */
	union {
		uchar_t		psid_char[FWFLASH_PSID_SZ];
		uint32_t	psid_int[FWFLASH_PSID_SZ/4];
	} psid;

	for (i = 0; i < FWFLASH_PSID_SZ/4; i++) {
		psid.psid_int[i] = (uint32_t)ntohl(handle->fw[(offset +
		    FLASH_PS_PSID_OFFSET) / 4 + i]);
#ifndef _LITTLE_ENDIAN
		data32 = psid.psid_int[i];
		psid.psid_char[i << 2] =
		    (uchar_t)(data32 & 0x000000ff);
		psid.psid_char[(i << 2) + 1] =
		    (uchar_t)((data32 & 0x0000ff00) >> 8);
		psid.psid_char[(i << 2) + 2] =
		    (uchar_t)((data32 & 0x00ff0000) >> 16);
		psid.psid_char[(i << 2) + 3] =
		    (uchar_t)((data32 & 0xff000000) >> 24);
#endif /* _LITTLE_ENDIAN */
	}

	psid_str = malloc(FWFLASH_PSID_SZ);
	if (psid_str == NULL) {
		DPRINTF(DBG_ERR, ("\nmalloc failed (0x%x)\n", errno));
		goto out;
	}

	(void) memcpy(psid_str, (const uchar_t *)psid.psid_char,
	    FWFLASH_PSID_SZ);
out:
	return (psid_str);
}

static void
fwflash_ib_i_flash_verify_flash_match(fwflash_ib_hdl_t *handle, int offset,
    int type)
{
	uchar_t	*psid;

	DPRINTF(DBG_INFO, ("fwflash_ib_i_flash_verify_flash_match\n"));
	/* get PSID of firmware file */
	psid = fwflash_ib_i_flash_get_psid(handle, offset);
	if (psid == NULL) {
		handle->hwfw_match = 0;
		handle->pn_len = 0;
		return;
	}
	DPRINTF(DBG_INFO, ("FW PSID (%s)\n", psid));

	/*
	 * Check the part number of the hardware against the part number
	 * of the firmware file. If the hardware information is not
	 * available, check the currently loaded firmware against the
	 * firmware file to be uploaded.
	 */
	if (handle->pn_len != 0) {
		fwflash_ib_i_flash_verify_flash_pn(handle, psid,
		    FWFLASH_PSID_SZ, type);
	} else {
		DPRINTF(DBG_ERR, ("No VPD data available for HW\n"));
		fwflash_ib_i_flash_verify_flash_fwpsid(handle, psid,
		    FWFLASH_PSID_SZ);
	}
	free(psid);
}

static void
fwflash_ib_i_flash_verify_flash_pn(fwflash_ib_hdl_t *handle, uchar_t *psid,
    int psid_size, int type)
{
	int	i;
	int	no_match = 0;

	DPRINTF(DBG_INFO, ("fwflash_ib_i_flash_verify_flash_pn\n"));
	/* verify fw matches the hardware */
	if (handle->hwfw_match == 1) {
		/* already been verified */
		return;
	}

	/* find the PSID from FW in the mlx table */
	for (i = 0; i < FWFLASH_MAX_ID; i++) {
		if (handle->hwfw_match == 1) {
			/*
			 * Need this check here and the 'continue's below
			 * becasue there are some cards that have a
			 * 'new' part number but the same PSID value.
			 */
			break;
		}
		DPRINTF(DBG_INFO, ("psid (%s) mlx_psid (%s)\n",
		    psid, mlx_mdr[i].mlx_psid));

		/* match PSID */
		if (strncmp((const char *)psid, mlx_mdr[i].mlx_psid,
		    psid_size) == 0) {
			DPRINTF(DBG_INFO, ("FW PSID (%s) MDR/HW PSID (%s) "
			    "FW PN (%s) MDR/HW PN (%s)\n",
			    psid, mlx_mdr[i].mlx_psid,
			    handle->info.mlx_pn, mlx_mdr[i].mlx_pn));

			/* match part numbers */
			if (strncmp(handle->info.mlx_pn, mlx_mdr[i].mlx_pn,
			    handle->pn_len) == 0) {
				handle->hwfw_match = 1;
				continue;
			} else {
				handle->hwfw_match = 0;
				no_match = i;
				continue;
			}
		}
	}
	if (i == FWFLASH_MAX_ID && no_match == 0) {
		/* no match found */
		handle->hwfw_match = 0;
		handle->pn_len = 0;
		DPRINTF(DBG_ERR, ("No PSID match found\n"));
	} else {
		if (handle->hwfw_match == 0) {
			(void) fprintf(stderr, "\t");
			(void) fprintf(stderr, gettext("WARNING"));
			(void) fprintf(stderr, ": %s",
			    type == 1 ? " Primary " : " Secondary ");
			(void) fprintf(stderr, gettext(
			    "firmware image is meant for"));
			(void) fprintf(stderr, " %s ",
			    mlx_mdr[no_match].mlx_pn);
			(void) fprintf(stderr, "\n\t");
			(void) fprintf(stderr, gettext("but the harware is"));
			(void) fprintf(stderr, " %s\n",
			    handle->info.mlx_pn);
		}
	}
}

static void
fwflash_ib_i_flash_verify_flash_fwpsid(fwflash_ib_hdl_t *handle,
    uchar_t *psid, int psid_size)
{
	tavor_flash_ioctl_t	ioctl_info;
	uint32_t		sector_size;
	uint32_t		device_size;
	int			ps_offset;
	int			ret, i;
	fwflash_ib_hdl_t	*hdl;
	uchar_t			*hw_psid;
#ifdef _LITTLE_ENDIAN
	int			j;
	uint32_t		*ptr;
#endif

	DPRINTF(DBG_INFO, ("fwflash_ib_i_flash_verify_flash_fwpsid\n"));
	/* Get Sector Size */
	sector_size = fwflash_ib_i_flash_get_sect_size(handle);
	DPRINTF(DBG_INFO, ("sector_size: 0x%x\n", sector_size));

	/* get device size */
	device_size = handle->device_sz;
	DPRINTF(DBG_INFO, ("device_size: 0x%x\n", device_size));

	/* allocate some space */
	hdl = malloc(sizeof (fwflash_ib_hdl_t));
	hdl->fw = malloc(device_size);

	/* Look for PSID in PPS first, then SPS if no match */
	for (i = 1; i < 3; i++) {
		ps_offset = i << sector_size;

		DPRINTF(DBG_INFO, ("type: 0x%x\n", i));
		DPRINTF(DBG_INFO, ("ps_offset: 0x%x\n", ps_offset));

		/* Read in xPS */
		ioctl_info.tf_type = TAVOR_FLASH_READ_SECTOR;
		ioctl_info.tf_sector_num = i;
		ioctl_info.tf_sector = FLASH_SECTOR_OFFSET(hdl->fw, i,
		    sector_size);
		hdl->fd = handle->fd;
		ret = fwflash_read_ioctl(hdl, &ioctl_info);
		if (ret != 0) {
			DPRINTF(DBG_ERR, ("\nFailed to read PS\n"));
			handle->hwfw_match = 0;
			return;
		}
#ifdef _LITTLE_ENDIAN
		/* swap sector contents into network byte order form */
		ptr = (uint32_t *)(uintptr_t)ioctl_info.tf_sector;
		for (j = 0; j < (1 << sector_size)/4; j++) {
			ptr[j] = htonl(ptr[j]);
		}
#endif
		/* grab PSID from xPS */
		hw_psid = fwflash_ib_i_flash_get_psid(hdl, ps_offset);
		if (hw_psid == NULL) {
			handle->hwfw_match = 0;
			handle->pn_len = 0;
			return;
		}
		DPRINTF(DBG_INFO, ("%s PSID (%s) file PSID (%s)\n",
		    i == 1 ? "Primary" : "Secondary",
		    hw_psid, psid));

		/* compare PSIDs */
		if (strncmp((const char *)psid, (const char *)hw_psid,
		    psid_size) == 0) {
			handle->hwfw_match = 1;
			break;
		} else {
			handle->hwfw_match = 0;
		}
	}
	free(hdl->fw);
	free(hdl);
	free(hw_psid);
}

static uint16_t
fwflash_ib_i_check_hwver(fwflash_ib_hdl_t *handle)
{
	uint8_t	hwver;
	uint8_t	local_hwver;

	DPRINTF(DBG_INFO, ("fwflash_ib_i_check_hwver\n"));
	if ((handle->state & FWFLASH_IB_STATE_PFI_IMAGE) == 0 &&
	    (handle->state & FWFLASH_IB_STATE_SFI_IMAGE) == 0) {
		DPRINTF(DBG_ERR, ("\nMust read in image first\n"));
		return (1);
	}

	/* Read Flash HW Version */
	hwver = (uint8_t)handle->hwrev;
	local_hwver = (ntohl(handle->fw[FLASH_IS_HWVER_OFFSET / 4]) &
	    FLASH_IS_HWVER_MASK) >> 24;

	DPRINTF(DBG_INFO, ("local_hwver: %x, hwver: %x\n", local_hwver, hwver));

	if ((hwver == 0xA0 || hwver == 0x00 || hwver == 0x20) &&
	    (local_hwver == 0x00 || local_hwver == 0xA0 ||
	    local_hwver == 0x20)) {
		DPRINTF(DBG_INFO, ("A0 board found.\r\n"));
	} else if (hwver == 0xA1 && local_hwver == 0xA1) {
		DPRINTF(DBG_INFO, ("A1 board found.\r\n"));
	} else if (hwver == 0xA2 && local_hwver == 0xA2) {
		DPRINTF(DBG_INFO, ("A2 board found.\r\n"));
	} else if (hwver == 0xA3 && local_hwver == 0xA3) {
		DPRINTF(DBG_INFO, ("A3 board found.\r\n"));
	} else {
		return ((uint16_t)(local_hwver << 8) | hwver);
	}
	return (0);
}

static void
fwflash_ib_i_local_zero_crc(fwflash_ib_hdl_t *handle, uint32_t offset)
{
	uint8_t	*image = (uint8_t *)&handle->fw[0];

	image[offset + FLASH_PS_CRC16_OFFSET] = 0xFF;
	image[offset + FLASH_PS_CRC16_OFFSET + 1] = 0xFF;
}

static int
fwflash_ib_i_flash_zero_crc(fwflash_ib_hdl_t *handle, uint32_t offset)
{
	tavor_flash_ioctl_t	ioctl_info;
	int			ret, i;

	DPRINTF(DBG_INFO, ("fwflash_ib_i_flash_zero_crc\n"));
	for (i = 0; i < 2; i++) {
		ioctl_info.tf_type = TAVOR_FLASH_WRITE_BYTE;
		ioctl_info.tf_addr = offset + FLASH_PS_CRC16_OFFSET + i;
		ioctl_info.tf_byte = 0;

		ret = fwflash_write_ioctl(handle, &ioctl_info);
		if (ret != 0) {
			DPRINTF(DBG_ERR, ("\nFailed to zero crc (%d)\n", i));
			return (ret);
		}
	}
	return (0);
}

static uint32_t
fwflash_ib_i_local_get_fw_size(fwflash_ib_hdl_t *handle, uint32_t offset)
{
	uint32_t	size;

	size = ntohl(handle->fw[(offset + FLASH_PS_FW_SIZE_OFFSET) / 4]);
	return (size);
}

static uint32_t
fwflash_ib_i_local_get_fw_addr(fwflash_ib_hdl_t *handle, uint32_t offset)
{
	uint32_t	addr;

	addr = ntohl(handle->fw[(offset + FLASH_PS_FI_ADDR_OFFSET) / 4]);
	return (addr);
}

static uint32_t
fwflash_ib_i_flash_get_fw_addr(fwflash_ib_hdl_t *handle, uint32_t offset)
{
	tavor_flash_ioctl_t	ioctl_info;
	int			ret;

	DPRINTF(DBG_INFO, ("fwflash_ib_i_flash_get_fw_addr\n"));
	ioctl_info.tf_type = TAVOR_FLASH_READ_QUADLET;
	ioctl_info.tf_addr = offset + FLASH_PS_FI_ADDR_OFFSET;
	ret = fwflash_read_ioctl(handle, &ioctl_info);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nFailed to read addr\n"));
		return (ret);
	}
	return (ioctl_info.tf_quadlet);
}

static int
fwflash_ib_i_flash_set_fw_addr(fwflash_ib_hdl_t *handle, uint32_t offset,
    uint32_t addr)
{
	tavor_flash_ioctl_t	ioctl_info;
	uint32_t		fw_addr = htonl(addr);
	uint8_t			*fw_addrp = (uint8_t *)&fw_addr;
	int			ret, i;

	DPRINTF(DBG_INFO, ("fwflash_ib_i_flash_set_fw_addr\n"));
	ioctl_info.tf_type = TAVOR_FLASH_WRITE_BYTE;
	for (i = 0; i < 4; i++) {
		ioctl_info.tf_addr = offset + FLASH_PS_FI_ADDR_OFFSET + i;
		ioctl_info.tf_byte = fw_addrp[i];
		ret = fwflash_write_ioctl(handle, &ioctl_info);
		if (ret != 0) {
			DPRINTF(DBG_ERR, ("\nFailed to set fw addr\n"));
			return (ret);
		}
	}
	return (0);
}

static int
fwflash_ib_i_flash_set_signature(fwflash_ib_hdl_t *handle, uint32_t offset)
{
	tavor_flash_ioctl_t	ioctl_info;
	uint32_t		signature = (uint32_t)htonl(FLASH_PS_SIGNATURE);
	uint8_t			*signaturep = (uint8_t *)&signature;
	int			ret, i;

	DPRINTF(DBG_INFO, ("fwflash_ib_i_flash_set_signature\n"));
	DPRINTF(DBG_INFO, ("flash set sig: %x\n", ntohl(signature)));
	ioctl_info.tf_type = TAVOR_FLASH_WRITE_BYTE;
	for (i = 0; i < 4; i++) {
		ioctl_info.tf_addr = offset + FLASH_PS_SIGNATURE_OFFSET + i;
		ioctl_info.tf_byte = signaturep[i];
		ret = fwflash_write_ioctl(handle, &ioctl_info);
		if (ret != 0) {
			DPRINTF(DBG_ERR, ("\nFailed to set sig\n"));
			return (ret);
		}
	}
	return (0);
}

static int
fwflash_ib_i_flash_read_guids(fwflash_ib_hdl_t *handle, void *buf, int type)
{
	tavor_flash_ioctl_t	ioctl_info;
	uint32_t		*guids;
	uint32_t		fw_addr;
	uint32_t		guid_ptr;
	int			start_addr;
	int			sector_size;
	int			ps_offset;
	int			ret, i;

	DPRINTF(DBG_INFO, ("fwflash_ib_i_flash_read_guids\n"));
	/* Read Sector Size */
	sector_size = fwflash_ib_i_flash_get_sect_size(handle);

	/* offset is the start of the xPS sector */
	/* 'type' is the sector number input as PPS or SPS */
	ps_offset = type << sector_size;

	ret = fwflash_ib_i_flash_verify_signature(handle, ps_offset);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nFailed to verify signature\n"));
		return (ret);
	}

	fw_addr = fwflash_ib_i_flash_get_fw_addr(handle, ps_offset);

	ioctl_info.tf_type = TAVOR_FLASH_READ_QUADLET;
	ioctl_info.tf_addr = fw_addr + FLASH_GUID_PTR;
	ret = fwflash_read_ioctl(handle, &ioctl_info);
	if (ret != 0) {
		DPRINTF(DBG_ERR, ("\nFailed to read fw_addr\n"));
		return (ret);
	}

	guid_ptr = ioctl_info.tf_quadlet;
	guids = (uint32_t *)buf;
	start_addr = fw_addr + guid_ptr + FLASH_FI_NGUID_OFFSET;

	ioctl_info.tf_addr = start_addr;
	for (i = 0; i < 8; i++) {
		ioctl_info.tf_type = TAVOR_FLASH_READ_QUADLET;
		ret = fwflash_read_ioctl(handle, &ioctl_info);
		if (ret != 0) {
			DPRINTF(DBG_ERR, ("\nFailed to read guid (0x%x)\n", i));
			return (ret);
		}

		guids[i] = ioctl_info.tf_quadlet;
		ioctl_info.tf_addr += 4;
	}

	return (0);
}

static void
fwflash_ib_i_local_set_guid_crc(fwflash_ib_hdl_t *handle, uint32_t offset)
{
	uint16_t	crc;
	uint8_t		*fw_p = (uint8_t *)&handle->fw[0];

	DPRINTF(DBG_INFO, ("fwflash_ib_i_local_set_guid_crc\n"));
	crc = htons(crc16((uint8_t *)&handle->fw[offset / 4],
	    FLASH_GUID_CRC16_SIZE));

	DPRINTF(DBG_INFO, ("local crc guid: %x\n", ntohs(crc)));
	(void) memcpy(&fw_p[offset + FLASH_GUID_CRC16_OFFSET], &crc, 2);
}

/*
 * crc16 - computes 16 bit crc of supplied buffer.
 *   image should be in network byteorder
 *   result is returned in host byteorder form
 */
static uint16_t
crc16(uint8_t *image, uint32_t size)
{
	const uint16_t	poly = 0x100b;
	uint32_t	crc = 0xFFFF;
	uint32_t	word;
	uint32_t	i, j;

	for (i = 0; i < size / 4; i++) {
		word =  (image[4 * i] << 24) |
		    (image[4 * i + 1] << 16) |
		    (image[4 * i + 2] << 8) |
		    (image[4 * i + 3]);

		for (j = 0; j < 32; j++) {
			if (crc & 0x8000) {
				crc = (((crc << 1) |
				    (word >> 31)) ^ poly) & 0xFFFF;
			} else {
				crc = ((crc << 1) | (word >> 31)) & 0xFFFF;
			}
			word = (word << 1) & 0xFFFFFFFF;
		}
	}

	for (i = 0; i < 16; i++) {
		if (crc & 0x8000) {
			crc = ((crc << 1) ^ poly) & 0xFFFF;
		} else {
			crc = (crc << 1) & 0xFFFF;
		}
	}

	crc = crc ^ 0xFFFF;
	return (crc & 0xFFFF);
}
