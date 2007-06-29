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

#ifndef _FWFLASH_IB_H
#define	_FWFLASH_IB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * fwflash_ib.h
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/ib/adapters/tavor/tavor_ioctl.h>

#define	FWFLASH_IB_DRIVER_NAME		"tavor"
#define	FWFLASH_IB_MAGIC_NUMBER		0xF00B0021

#define	NODE_GUID_OFFSET		0x0
#define	PORT1_GUID_OFFSET		0x08
#define	PORT2_GUID_OFFSET		0x10
#define	FLASH_SIZE_OFFSET		0x20
#define	FLASH_GUID_PTR			0x24

#define	FWFLASH_IB_STATE_NONE		0x00
#define	FWFLASH_IB_STATE_IMAGE		0x01
#define	FWFLASH_IB_STATE_MMAP		0x04
#define	FWFLASH_IB_STATE_GUIDN		0x10
#define	FWFLASH_IB_STATE_GUID1		0x20
#define	FWFLASH_IB_STATE_GUID2		0x40
#define	FWFLASH_IB_STATE_GUIDS		0x80

#define	FWFLASH_IB_STATE_PFI_IMAGE	0x1
#define	FWFLASH_IB_STATE_SFI_IMAGE	0x2
#define	FWFLASH_IB_PRIMARY_IMAGE	FWFLASH_IB_STATE_PFI_IMAGE
#define	FWFLASH_IB_SECONDARY_IMAGE	FWFLASH_IB_STATE_SFI_IMAGE


/*
 * Structure to hold the part number, PSID, and string ID
 * for an HCA card.
 */
typedef struct mlx_mdr_s {
	char *mlx_pn;
	char *mlx_psid;
	char *mlx_id;
} mlx_mdr_t;

typedef struct fw_rev_s {
	uint32_t	major:16;
	uint32_t	minor:16;
	uint32_t	subminor:16;
	uint32_t	holder:16;
} fw_rev_t;

typedef struct fwflash_ib_hdl_s {
	uint_t		magic;
	int		fd;
	fw_rev_t	fw_rev;
	char		*dev_path;
	uint32_t	*fw;
	uint32_t	hwrev;
	uint32_t	sector_sz;
	uint32_t	device_sz;
	uint32_t	state;
	int		cmd_set;
	mlx_mdr_t	info;
	int		pn_len;
	int		hwfw_match;
} fwflash_ib_hdl_t;

/* IB Specific functions */
char ** fwflash_ib_device_list(int *count);
fwflash_ib_hdl_t *fwflash_ib_open(char *dev_path);
void fwflash_ib_close(fwflash_ib_hdl_t *handle);
int fwflash_ib_read_file(fwflash_ib_hdl_t *handle, const char *filename);

int fwflash_read_ioctl(fwflash_ib_hdl_t *hdl, tavor_flash_ioctl_t *ioctl_info);
int fwflash_write_ioctl(fwflash_ib_hdl_t *hdl, tavor_flash_ioctl_t *ioctl_info);

int fwflash_ib_write_is(fwflash_ib_hdl_t *handle);
int fwflash_ib_write_image(fwflash_ib_hdl_t *handle, int type);
int fwflash_ib_verify_image(fwflash_ib_hdl_t *handle, int type);
int fwflash_ib_read_image(fwflash_ib_hdl_t *handle, int type);
int fwflash_ib_write_file(fwflash_ib_hdl_t *handle, const char *filename);
int fwflash_ib_set_guids(fwflash_ib_hdl_t *handle, void *guids, int type);
int fwflash_ib_flash_read_guids(fwflash_ib_hdl_t *handle, void *guids,
    int type);

#ifdef __cplusplus
}
#endif

#endif /* _FWFLASH_IB_H */
