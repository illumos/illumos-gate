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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _DDA_H
#define	_DDA_H


#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/byteorder.h>

/*
 * Driver for Disk Archiving (dda)
 */

/* Begin: 32-bit align copyin() structs for amd64 only due to 32-bit x86 ABI */
#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

/* version for cartridge and dda */
#define	DDA_MAJOR_VERSION	1	/* dda driver major version */
#define	DDA_MINOR_VERSION	0	/* dda driver minor version */

/* cartridge file names */
#define	DDA_METADATA_FNAME	"metadata"	/* metadata file name */
#define	DDA_INDEX_FNAME		"index"		/* index file name */
#define	DDA_DATA_FNAME		"data"		/* data file name */

/* inquiry and mt config data */
#define	DDA_VENDOR		"SUNW    "
#define	DDA_PRODUCT		"DISK_ARCHIVING  "
#define	DDA_VID 		DDA_VENDOR DDA_PRODUCT
#define	DDA_ST_NAME 		"SUNW MMS disk archiving"

/*
 * DM ioctls:
 * cmd			arg
 * ---			---
 * DDA_CMD_LOAD		char path[PATH_MAX]
 *			Returns 0 if cartridge path is successfully loaded,
 *			else non-zero.
 * DDA_CMD_NAME		char path[PATH_MAX]
 *			Returns 0 and loaded cartridge path, else non-zero.
 * DDA_CMD_CAPACITY	dda_capacity_t *capacity
 *			If loaded returns 0 along with the cartridge capacity
 *			and space remaining, else non-zero.
 * DDA_CMD_WROTECT      NULL
 *                      Returns 0 if WP flag on, else non-zero.
 * DDA_CMD_BLKLMT	dda_blklmt_t *blklmt
 *			Returns 0 and the cartridge maximum and minimum block
 *			size, else non-zero.
 * DDA_CMD_SERIAL	dda_serial_t serial
 *			Returns 0 and pseudo drive unit serial number as
 *			the host id followed by the instance number.
 */
#define	DDA_IOC			(('D' << 24) | ('D' << 16) | ('A' << 8))
#define	DDA_CMD_LOAD		(DDA_IOC | 1)	/* load cartridge */
#define	DDA_CMD_NAME		(DDA_IOC | 2)	/* get cartridge name */
#define	DDA_CMD_CAPACITY	(DDA_IOC | 3)	/* get tape capacity/space */
#define	DDA_CMD_WPROTECT	(DDA_IOC | 4)	/* get cartridge WP flag */
#define	DDA_CMD_BLKLMT		(DDA_IOC | 5)	/* get block limits */
#define	DDA_CMD_SERIAL		(DDA_IOC | 6)	/* drive serial number */

typedef char dda_serial_t[13];		/* drive serial number */

/* cartridge capacity */
typedef struct dda_capacity {
	int64_t		dda_capacity;	/* tape capacity in bytes */
	int64_t		dda_space;	/* unused tape bytes remaining to eom */
} dda_capacity_t;

/* read block limits */
typedef struct dda_blklmt {
	int32_t		dda_blkmax;	/* maximum block length */
	int32_t		dda_blkmin;	/* minimum block length */
} dda_blklmt_t;

/* versioning */
typedef struct dda_version {
	int32_t		dda_major;	/* dda drive/media major version */
	int32_t		dda_minor;	/* dda drive/media minor version */
} dda_version_t;

/* metadata flags */
#define	DDA_FLAG_WPROTECT	0x1	/* cartridge write protect tab */

/* metadata file contents */
typedef struct dda_metadata {
	dda_version_t	dda_version;	/* dda media version */
	int64_t		dda_capacity;	/* tape capacity in bytes */
	int32_t		dda_sector; 	/* sector alignment */
	int32_t		dda_stripe; 	/* raid 5 stripe alignment */
	int32_t		dda_flags;	/* cartridge flags */
	int32_t		dda_pad;	/* padding */
} dda_metadata_t;

/* index file record */
typedef struct dda_index {
	off64_t		dda_offset;	/* data file offset */
	int32_t		dda_blksize;	/* data block size */
	int32_t		dda_pad;	/* padding */
	int64_t		dda_blkcount;	/* data block count */
	int64_t		dda_fmcount;	/* file marks following data blocks */
	int64_t		dda_fileno;	/* file mark number */
	int64_t		dda_lba;	/* logical block address */
} dda_index_t;

/* convert metadata file record between big endian and native byte order */
#define	DDA_BE_METADATA(a, b) { \
	b.dda_version.dda_major = BE_32(a.dda_version.dda_major); \
	b.dda_version.dda_minor = BE_32(a.dda_version.dda_minor); \
	b.dda_capacity = BE_64(a.dda_capacity); \
	b.dda_sector = BE_32(a.dda_sector); \
	b.dda_stripe = BE_32(a.dda_stripe); \
	b.dda_flags = BE_32(a.dda_flags); \
	b.dda_pad = BE_32(a.dda_pad); \
}

/* convert index file record between big endian and native byte order */
#define	DDA_BE_INDEX(a, b) { \
	b.dda_offset = BE_64(a.dda_offset); \
	b.dda_blksize = BE_32(a.dda_blksize); \
	b.dda_pad = BE_32(a.dda_pad); \
	b.dda_blkcount = BE_64(a.dda_blkcount); \
	b.dda_fmcount = BE_64(a.dda_fmcount); \
	b.dda_fileno = BE_64(a.dda_fileno); \
	b.dda_lba = BE_64(a.dda_lba); \
}

/* End: 32-bit align copyin() structs for amd64 only due to 32-bit x86 ABI */
#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#ifdef	_KERNEL

/* emulated tape drive data structure */
typedef struct dda {
	char		dda_path[PATH_MAX]; /* cartridge path */
	short		dda_status;	/* sense key */
	int32_t		dda_resid;	/* residual */
	int64_t		dda_blkno;	/* block number */
	off64_t		dda_early_warn;	/* early warning */
	uint32_t	dda_flags;	/* operation flags */

	struct vnode 	*dda_metadata_vp; /* metadata file */
	dda_metadata_t	dda_metadata;	/* metatdata file data */

	struct vnode	*dda_index_vp;	/* index file */
	off64_t		dda_index_fsize; /* index file size */
	off64_t		dda_index_offset; /* index file offset */
	dda_index_t	dda_index;	/* index file record */
	int64_t		dda_pos;	/* index record current block */

	struct vnode	*dda_data_vp;	/* data file */
	off64_t		dda_data_fsize; /* data file size */

	int		dda_inst;	/* driver instance (drive number) */
	dda_serial_t	dda_serial;	/* serial number */
	dev_info_t	*dda_dip;	/* driver instance info */
	kmutex_t	dda_mutex;	/* serialize drive access */
	int		dda_loaded;	/* media loaded */
	pid_t		dda_pid;	/* process opened by */
	cred_t		*dda_cred;	/* user credentials */
	int		dda_read_only;	/* opened read only */
	int32_t		dda_rec_size;	/* variable or fixed blocks */
	int		dda_ili;	/* incorrect length indicator */
} dda_t;

#endif	/* _KERNEL */


#ifdef	__cplusplus
}
#endif

#endif	/* _DDA_H */
