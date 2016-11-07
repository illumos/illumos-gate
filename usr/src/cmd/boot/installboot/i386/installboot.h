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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 */

#ifndef	_INSTALLBOOT_H
#define	_INSTALLBOOT_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/multiboot.h>
#include <sys/types.h>

#define	SECTOR_SIZE	(512)

/* partitioning type for device */
enum ig_devtype_t {
	IG_DEV_VTOC = 0,
	IG_DEV_MBR,
	IG_DEV_EFI
};

/* file system type */
enum ig_fstype_t {
	IG_FS_NONE = 0,
	IG_FS_ZFS,
	IG_FS_UFS,
	IG_FS_PCFS
};

/* partition info for boot block location. */
struct stage_part {
	char *path;			/* device name */
	int fd;				/* open file descriptor */
	int id;				/* partition/slice number */
	enum ig_devtype_t devtype;	/* partitioning type */
	enum ig_fstype_t fstype;	/* none or pcfs */
	uint64_t start;			/* partition LBA */
	uint64_t size;			/* partition size */
	uint64_t offset;		/* block offset */
};

/* boot device data */
typedef struct _ib_device {
	char		*path;			/* whole disk */
	int		fd;			/* whole disk fd */
	enum ig_devtype_t devtype;
	struct stage_part stage;		/* location of boot block */
	struct stage_part target;		/* target file system */
	char		mbr[SECTOR_SIZE];
} ib_device_t;

/* stage 2 location */
typedef struct _ib_bootblock {
	char			*buf;
	char			*file;
	char			*extra;
	multiboot_header_t	*mboot;
	uint32_t		mboot_off;
	uint32_t		file_size;
	uint32_t		buf_size;
	uint32_t		extra_size;
} ib_bootblock_t;

typedef struct _ib_data {
	unsigned char	stage1[SECTOR_SIZE];	/* partition boot block */
	ib_device_t	device;			/* boot device */
	ib_bootblock_t	bootblock;		/* stage 2 */
} ib_data_t;

#define	BBLK_BLKLIST_OFF	50	/* vtoc/disk boot offset */
#define	BBLK_ZFS_BLK_OFF	1024	/* vdev boot offset */
#define	BBLK_ZFS_BLK_SIZE	(7ULL << 19)	/* vdev max boot size */

/* locations of MBR parts, must be reviewd if mbr code is changed */
#define	STAGE1_BPB_OFFSET	(0x3)	/* technically BPB starts at 0xb */
#define	STAGE1_BPB_SIZE		(0x3b)
#define	STAGE1_MBR_VERSION	(0xfa)	/* 2 bytes, not used */
#define	STAGE1_STAGE2_SIZE	(0xfc)	/* 16bits */
#define	STAGE1_STAGE2_LBA	(0xfe)	/* 64bits */
#define	STAGE1_STAGE2_UUID	(0x106)	/* 128bits */
#define	STAGE1_SIG		(0x1b8)	/* 4+2 bytes */
#define	STAGE1_PARTTBL		(0x1be)	/* MBR partition table */
#define	STAGE1_MAGIC		(0x1fe)	/* 0xAA55 */
#ifdef	__cplusplus
}
#endif

#endif /* _INSTALLBOOT_H */
