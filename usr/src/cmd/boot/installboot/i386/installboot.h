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

#include <stdbool.h>
#include <sys/multiboot.h>
#include <sys/types.h>
#include <sys/queue.h>

#define	SECTOR_SIZE	(512)

/* partitioning type for device */
typedef enum ib_devtype {
	IB_DEV_UNKNOWN = 0,
	IB_DEV_VTOC,
	IB_DEV_MBR,
	IB_DEV_EFI
} ib_devtype_t;

/* file system type */
typedef enum ib_fstype {
	IB_FS_NONE = 0,
	IB_FS_ZFS,
	IB_FS_UFS,
	IB_FS_PCFS
} ib_fstype_t;

/* boot block type */
typedef enum ib_bblktype {
	IB_BBLK_FILE,
	IB_BBLK_MBR,		/* MBR/PMBR */
	IB_BBLK_STAGE1,		/* BIOS stage 1 */
	IB_BBLK_STAGE2,		/* BIOS stage 2 */
	IB_BBLK_EFI		/* EFI Boot Program */
} ib_bblktype_t;

/* partition info for boot block location. */
struct stage_part {
	char *path;			/* device name */
	char *mntpnt;			/* mountpoint for stage fs */
	int id;				/* partition/slice number */
	ib_devtype_t devtype;		/* partitioning type */
	ib_fstype_t fstype;
	uint16_t tag;			/* partition tag */
	uint64_t start;			/* partition LBA */
	uint64_t size;			/* partition size */
	uint64_t offset;		/* block offset */
};

/* boot device data */
typedef struct _ib_device {
	ib_devtype_t devtype;
	struct stage_part stage;		/* location of boot block */
	struct stage_part target;		/* target file system */
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

struct partlist;

struct part_cb {
	bool (*read)(struct partlist *);
	bool (*read_bbl)(struct partlist *);
	bool (*compare)(struct partlist *);
	void (*install)(void *, struct partlist *);
	void (*print)(struct partlist *);
};

struct partlist {
	char			*pl_devname;
	ib_device_t		*pl_device;

	/* boot block type */
	ib_bblktype_t		pl_type;
	/* stage from target disk, either stage1 or stage2 */
	void			*pl_stage;
	/* name of the source file */
	const char		*pl_src_name;
	/* stage data from source file. */
	void			*pl_src_data;
	struct part_cb		pl_cb;
	STAILQ_ENTRY(partlist)	pl_next;
};

typedef STAILQ_HEAD(part_list, partlist) part_list_t;

typedef struct _ib_data {
	ib_device_t	device;			/* boot device */
	ib_bootblock_t	bootblock;		/* stage 2 */
	struct stage_part target;		/* target file system */
	part_list_t	*plist;			/* boot blocks */
} ib_data_t;

#define	BBLK_BLKLIST_OFF	50	/* vtoc/disk boot offset sectors */
#define	BBLK_ZFS_BLK_OFF	(1 << 19)	/* vdev boot offset bytes */
#define	BBLK_ZFS_BLK_SIZE	(7ULL << 19)	/* vdev max boot size bytes */

/* locations of MBR parts, must be reviewd if mbr code is changed */
#define	STAGE1_BPB_OFFSET	(0x3)	/* technically BPB starts at 0xb */
#define	STAGE1_BPB_BPS		(0xb)	/* Bytes Per Sector */
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
