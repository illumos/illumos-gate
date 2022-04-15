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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 * Copyright 2024 MNX Cloud, Inc.
 */

#ifndef _PCFS_BPB_H
#define	_PCFS_BPB_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Common Bios Parameter Block definitions for the pcfs user-level utilities
 */
#define	MINBPS		512
#define	MAXBPS		4096

#define	OPCODE1		0xE9
#define	OPCODE2		0xEB
#define	BOOTSECSIG	0xAA55

/*
 * Offset (in bytes) from address of boot sector to where we put
 * the backup copy of that sector.  (FAT32 only)
 */
#define	BKUP_BOOTSECT_OFFSET	0xC00

#define	uppercase(c)	((c) >= 'a' && (c) <= 'z' ? (c) - 'a' + 'A' : (c))

#define	FAT12_TYPE_STRING	"FAT12   "
#define	FAT16_TYPE_STRING	"FAT16   "
#define	FAT32_TYPE_STRING	"FAT32   "

#define	FAT12_ENTSPERSECT	341
#define	FAT16_ENTSPERSECT	256
#define	FAT32_ENTSPERSECT	128

#ifndef	SUNIXOSBOOT
#define	SUNIXOSBOOT	190	/* Solaris UNIX boot partition */
#endif

/*
 *	MS-DOS Disk layout:
 *
 *	---------------------
 *	|    Boot sector    |
 *	|-------------------|
 *	|   Reserved area   |
 *	|-------------------|
 *	|	FAT #1      |
 *	|-------------------|
 *	|	FAT #2      |
 *	|-------------------|
 *	|   Root directory  |
 *	|-------------------|
 *	|                   |
 *	|     File area     |
 *	|___________________|
 */
#ifdef _LITTLE_ENDIAN
#pragma	pack(1)
#endif
struct _orig_bios_param_blk {
	uint16_t bytes_per_sector;
	uchar_t	 sectors_per_cluster;
	uint16_t resv_sectors;
	uchar_t	 num_fats;
	uint16_t num_root_entries;
/*
 *  The sectors_in_volume field will be zero on larger volumes (>32Mb)
 *  and newer file systems (>=MSDOS4.0).  In these cases the
 *  sectors_in_logical_volume field should be used instead.
 */
	uint16_t sectors_in_volume;
	uchar_t	 media;
	uint16_t sectors_per_fat;
	uint16_t sectors_per_track;
	uint16_t heads;
/*
 *  Number of sectors in the partition prior to the start of the logical disk
 */
	uint32_t hidden_sectors;
	uint32_t sectors_in_logical_volume;
};
#ifdef _LITTLE_ENDIAN
#pragma pack()
#endif

#ifdef _LITTLE_ENDIAN
#pragma	pack(1)
#endif
struct _bpb32_extensions {
	uint32_t big_sectors_per_fat;
	uint16_t ext_flags;
	uchar_t	 fs_vers_lo;
	uchar_t	 fs_vers_hi;
	uint32_t root_dir_clust;
	uint16_t fsinfosec;
	uint16_t backupboot;
	uint16_t reserved[6];
};
#ifdef _LITTLE_ENDIAN
#pragma pack()
#endif

#ifdef _LITTLE_ENDIAN
#pragma	pack(1)
#endif
struct _bpb_extensions {
	uchar_t  phys_drive_num;
	uchar_t  reserved;
	uchar_t  ext_signature;
	uint32_t volume_id;
	uchar_t  volume_label[11];
	uchar_t  type[8];
};
#ifdef _LITTLE_ENDIAN
#pragma pack()
#endif

#ifdef _LITTLE_ENDIAN
#pragma	pack(1)
#endif
struct _sun_bpb_extensions {
	uint16_t  bs_offset_high;
	uint16_t  bs_offset_low;
};
#ifdef _LITTLE_ENDIAN
#pragma pack()
#endif

/*
 * bpb_t is a conglomeration of all the fields a bpb can have.  Every
 * bpb will have the orig_bios struct, but only FAT32's will have bpb32,
 * and only Solaris boot diskettes will have the sunbpb structure.
 */
typedef struct _bios_param_blk {
	struct _orig_bios_param_blk bpb;
	struct _bpb32_extensions    bpb32;
	struct _bpb_extensions	    ebpb;
	struct _sun_bpb_extensions  sunbpb;
} bpb_t;

#ifdef _LITTLE_ENDIAN
#pragma	pack(1)
struct _bpb_head {
	uchar_t			    bs_jump_code[3];
	uchar_t			    bs_oem_name[8];
	struct _orig_bios_param_blk bs_bpb;
};
#pragma pack()

#pragma	pack(1)
struct _boot_sector {
	struct _bpb_head	    bs_front;
	struct _bpb_extensions	    bs_ebpb;
	struct _sun_bpb_extensions  bs_sebpb;
	uchar_t			    bs_bootstrap[444];
	uchar_t			    bs_signature[2];
};
#pragma pack()

#pragma	pack(1)
struct _boot_sector32 {
	struct _bpb_head	    bs_front;
	struct _bpb32_extensions    bs_bpb32;
	struct _bpb_extensions	    bs_ebpb;
	uchar_t			    bs_bootstrap[420];
	uchar_t			    bs_signature[2];
};
#pragma pack()
#else
#define	ORIG_BPB_START_INDEX	8	/* index into filler field */
#define	EXT_BPB_START_INDEX	33	/* index into filler field */
#define	BPB_32_START_INDEX	33	/* index into filler field */
#define	EXT_BPB_32_START_INDEX	61	/* index into filler field */
struct _boot_sector {
	uchar_t	 bs_jump_code[3];
	uchar_t  bs_filler[59];
	uchar_t  bs_sun_bpb[4];
	uchar_t	 bs_bootstrap[444];
	uchar_t  bs_signature[2];
};

struct _boot_sector32 {
	uchar_t	 bs_jump_code[3];
	uchar_t  bs_filler[87];
	uchar_t	 bs_bootstrap[420];
	uchar_t  bs_signature[2];
};
#endif

typedef union _ubso {
	struct _boot_sector	bs;
	struct _boot_sector32	bs32;
	struct mboot		mb;
	uchar_t			buf[MAXBPS];
} boot_sector_t;

#ifdef __cplusplus
}
#endif

#endif /* _PCFS_BPB_H */
