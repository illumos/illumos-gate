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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SMEDIA_H_
#define	_SMEDIA_H_

/*
 * smedia.h header for libsmedia library
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <sys/scsi/scsi.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <synch.h>

typedef struct smdevice_info {
	uchar_t	sm_version;
	int32_t	sm_interface_type;	/* Interface type */
	char	*sm_vendor_name;	/* Vendor name */
	char 	*sm_product_name;	/* Product name */
	char 	*sm_firmware_version;	/* Firmware version */
}smdevice_info_t;

typedef	void	*smedia_handle_t;


#define	SMDEVICE_INFO_V_1	1

/* Interface Types */

#define	IF_SCSI		0x0
#define	IF_FLOPPY	0x1
#define	IF_PCMCIA	0x2
#define	IF_BLOCK	0x3


typedef struct smmedium_property {
	int32_t sm_version;
	int32_t sm_media_type;	/* Medium type */
	int32_t sm_blocksize;	/* Medium block size in bytes */
	int32_t sm_capacity;	/* Medium capacity in no. of blocks */
	int32_t sm_pcyl;	/* No. of cylinders on the medium */
	int32_t sm_nhead;	/* No. of heads */
	int32_t sm_nsect;	/* No. of sectors per cylinder */
}smmedium_prop_t;

#define	SMMEDIA_PROP_V_1	1

/*
 * Media types not defined for DKIOCGMEDIAINFO
 */

#define	SM_REMOVABLE_DISK	0x20005 /* Removable disk */
					/* FIXED_DISK + REMOVABLE */
#define	SM_FLOPPY		0x10002 /* Floppy media */
#define	SM_SCSI_FLOPPY		0x10005 /* SCSI floppy device */
#define	SM_PCMCIA_MEM		0x20006 /* PCMCIA memory card (Obsolete) */
#define	SM_PCMCIA_ATA		0x20007 /* PCMCIA ata card */
#define	SM_BLOCK		0x20008	/* Generic block device */
#define	SM_NOT_PRESENT		0xFFFF


#define	MAX_PASSWD_LENGTH		32

#define	PASSWD		0x1000

#define	SM_WRITE_PROTECT_DISABLE	(PASSWD|0x0)
#define	SM_WRITE_PROTECT_NOPASSWD	(PASSWD|0x2)
#define	SM_WRITE_PROTECT_PASSWD		(PASSWD|0x4)
#define	SM_READ_WRITE_PROTECT		(PASSWD|0x8)
#define	SM_TEMP_UNLOCK_MODE		(PASSWD|0x10)
#define	SM_STATUS_UNKNOWN		(PASSWD|0xFF)

#define	SM_UNPROTECTED			SM_WRITE_PROTECT_DISABLE
#define	SM_WRITE_PROTECTED 		SM_WRITE_PROTECT_NOPASSWD
#define	SM_WRITE_PROTECTED_WP   	SM_WRITE_PROTECT_PASSWD
#define	SM_READ_WRITE_PROTECTED 	SM_READ_WRITE_PROTECT


typedef struct smwp_state {
	uchar_t sm_version;
	int32_t	sm_new_state;
	int32_t	sm_passwd_len;
	char	sm_passwd[MAX_PASSWD_LENGTH];
}smwp_state_t;

#define	SMWP_STATE_V_1			1

#define	FORMAT	0x2000

#define	SM_FORMAT_LONG		(FORMAT|0x0001)
#define	SM_FORMAT_QUICK		(FORMAT|0x0002)
#define	SM_FORMAT_FORCE		(FORMAT|0x0003)

/* Floppy specific options */
#define	SM_FORMAT_HD	(FORMAT|0x0011) /* Format high density (1.44MB) */
#define	SM_FORMAT_DD	(FORMAT|0x0012) /* Format Double density (720KB) */
#define	SM_FORMAT_ED	(FORMAT|0x0013) /* Format Extended density (2.88MB) */
#define	SM_FORMAT_MD	(FORMAT|0x0014) /* Format Medium density (1.2MB) */

#define	SM_FORMAT_IMMEDIATE	(FORMAT|0x0021)
#define	SM_FORMAT_BLOCKED	(FORMAT|0x0022)


/* New Library interface prototypes */

int smedia_get_device_info(smedia_handle_t handle, smdevice_info_t *smdevinfop);
int smedia_free_device_info(smedia_handle_t handle,
		smdevice_info_t *smdevinfop);
int smedia_get_medium_property(smedia_handle_t handle,
		smmedium_prop_t *smpropp);
int smedia_get_protection_status(smedia_handle_t handle,
		smwp_state_t *wpstatep);
int smedia_set_protection_status(smedia_handle_t handle,
		smwp_state_t *wpstatep);
size_t smedia_raw_read(smedia_handle_t handle, diskaddr_t blockno,
		caddr_t buffer,
							size_t nbytes);
size_t smedia_raw_write(smedia_handle_t handle, diskaddr_t blockno,
		caddr_t buffer,
							size_t nbytes);
int smedia_format(smedia_handle_t handle, uint_t flavor, uint_t mode);
int smedia_check_format_status(smedia_handle_t handle);
int smedia_format_track(smedia_handle_t handle, uint_t trackno, uint_t head,
							uint_t density);
int smedia_eject(smedia_handle_t handle);
int smedia_reassign_block(smedia_handle_t handle, diskaddr_t blockno);
smedia_handle_t smedia_get_handle(int32_t);
int smedia_release_handle(smedia_handle_t handle);
int smedia_uscsi_cmd(smedia_handle_t handle, struct uscsi_cmd *cmd);


#ifdef __cplusplus
}
#endif

#endif /* _SMEDIA_H_ */
