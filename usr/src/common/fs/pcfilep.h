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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _PCFILEP_H
#define	_PCFILEP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAX_DOSMOUNT_RETRIES 3

#define	TICKS_PER_SEC	18		/* It's really 18.2! */
#define	SECSIZ 512
#define	fat_bpc(i) (pi[(i)]->f_bpb.bs_spc * SECSIZ)

/*
 * Access permissions for dosAccess(), dosOpen()
 * NOTE: These permission need to match those for the DOS compiler.
 */
#define	FILE_EXISTS	1
#define	FILE_READ	0x0000
#define	FILE_WRITE	0x0001
#define	FILE_RDWR	0x0002
#define	FILE_APPEND	0x0008
#define	FILE_CREATE	0x0100
#define	FILE_TRUNC	0x0200

#define	TYPE_EMPTY	0x00		/* undefined partition */
#define	TYPE_DOS	0x13		/* causes fatInit() to search for */
					/* active partition */
#define	TYPE_DOS_12	0x01		/* partition with FAT12 filesys */
#define	TYPE_DOS_16	0x04		/* partition with FAT16 filesys */
#define	TYPE_DOS_EXT	0x05		/* not bootable, ignore */
#define	TYPE_HUGH	0x06		/* HUGH partition */
#define	TYPE_COMPAQ	0x12		/* Compaq's diag partition */
#define	TYPE_SOLARIS	0x82
#define	TYPE_SOLARIS_BOOT	0xBE	/* For "boot hill" project */

#define	FDISK_START	0x1be		/* location in first sector where */
					/* the fdisk starts. */

#define	FDISK_PARTS	4		/* Number of partitions in a fdisk */
#define	FDISK_ACTIVE	0x80		/* indicates partition is active */
#define	FDISK_INACTIVE	0x00		/*  " partition inactive */

#pragma pack(1)
struct _fdisk_partition_ {
	uchar_t	fd_active;
	uchar_t	fd_b_head;
	uchar_t	fd_b_sec;
	uchar_t	fd_b_cyl;
	uchar_t	fd_type;
	uchar_t	fd_e_head;
	uchar_t	fd_e_sec;
	uchar_t	fd_e_cyl;
	union {
		long	fd_start_sec_long;
		struct {
			ushort_t low;
			ushort_t high;
		} s;
	} u;
	long	fd_part_len;
};
#define	fd_start_sec u.fd_start_sec_long
#define	fd_partition fd_type
typedef struct _fdisk_partition_ _fdisk_t, *_fdisk_p;
#pragma pack()

#pragma pack(1)
struct _boot_sector_ {
	uchar_t	bs_jump_code[3];
	uchar_t	bs_oem_name[8];
	uchar_t	bs_bytes_sector[2];
	uchar_t	bs_spc;			/* ... sectors per cluster */
	uchar_t	bs_resv_sectors[2];
	uchar_t	bs_num_fats;
	uchar_t	bs_num_root_entries[2];
	uchar_t	bs_siv[2];			/* ... sectors in volume */
	uchar_t	bs_media;
	uchar_t	bs_spf[2];			/* ... sectors per fat */
	uchar_t	bs_sectors_per_track[2];
	uchar_t	bs_heads[2];
	/*
	 * Byte offset at this point is 28 so we can declare the next
	 * variable with the correct type and not worry about alignment.
	 */
	long	bs_hidden_sectors;
	long	bs_lsiv;		/* ... logical sectors in volume */
	uchar_t	bs_phys_drive_num;
	uchar_t	bs_reserved;
	uchar_t	bs_ext_signature;
	char	bs_volume_id[4];
	char	bs_volume_label[11];
	char	bs_type[8];

	/* ---- ADDED BY SUNSOFT FOR MDBOOT ---- */
	ushort_t	bs_offset_high;
	ushort_t	bs_offset_low;
};
#pragma pack()
typedef struct _boot_sector_  _boot_sector_t, *_boot_sector_p;

/*
 * Cluster types
 */
#define	CLUSTER_AVAIL	0x00
#define	CLUSTER_RES_12_0	0x0ff0	/* 12bit fat, first reserved */
#define	CLUSTER_RES_12_6	0x0ff6	/* 12bit fat, last reserved */
#define	CLUSTER_RES_16_0	0xfff0	/* 16bit fat, first reserved */
#define	CLUSTER_RES_16_6	0xfff6	/* 16bit fat, last reserved */
#define	CLUSTER_BAD_12	0x0ff7	/* 12bit fat, bad entry */
#define	CLUSTER_BAD_16	0xfff7	/* 16bit fat, bad entry */
#define	CLUSTER_EOF		CLUSTER_EOF_16_0
#define	CLUSTER_MAX_12		0x0ff7	/* max clusters for 12bit fat */
#define	CLUSTER_EOF_12_0	0x0ff8	/* 12bit fat, EOF first entry */
#define	CLUSTER_EOF_12_8	0x0fff	/* 12bit fat, EOF last entry */
#define	CLUSTER_EOF_16_0	0xfff8	/* 16bit fat, EOF first entry */
#define	CLUSTER_EOF_16_8	0xffff	/* 16bit fat, EOF last entry */

/*
 * Cluster operations for allocation
 */
#define	CLUSTER_NOOP		0x0001	/* ... just allocate cluster */
#define	CLUSTER_ZEROFILL	0x0002	/* ... zero fill the alloc'd cluster */

#define	CLUSTER_FIRST		0x0002	/* ... first cluster number to search */
#define	CLUSTER_ROOTDIR		0x0000	/* ... root dir's cluster number */

/*
 * This structure is filled in by initFAT()
 */
struct _fat_controller_ {
	union {
		_boot_sector_t	fu_bpb;	 /* boot parameter block */
		uchar_t		fu_sector[SECSIZ];
	} fu;
	long		f_adjust;	/* starting sec for part. */
	long		f_rootsec;	/* root dir starting sec. */
	long		f_rootlen;	/* length of root in sectors */
	long		f_filesec;	/* adjustment for clusters */
	long		f_dclust;	/* cur dir cluster */
	int		f_nxtfree;	/* next free cluster */
	int		f_ncluster;	/* number of cluster in part */
	char		f_16bit:1,	/* 1 if 16bit fat entries */
			f_flush:1;	/* flush the fat */
};
typedef struct _fat_controller_ _fat_controller_t, *_fat_controller_p;

#define	f_bpb fu.fu_bpb
#define	f_sector fu.fu_sector

#define	NAMESIZ		8
#define	EXTSIZ		3
#pragma pack(1)
struct _dir_entry_ {
	char	d_name[NAMESIZ];
	char	d_ext[EXTSIZ];
	uchar_t	d_attr;
	char	d_res[10];
	short	d_time;
	short	d_date;
	ushort_t d_cluster;
	long	d_size;
};
#pragma pack()
typedef struct _dir_entry_ _dir_entry_t, *_dir_entry_p;

/*
 * Number of entries in one sector
 */
#define	DIRENTS (SECSIZ / sizeof (_dir_entry_t))

/*
 * Directory entry attributes
 */
#define	DE_READONLY		0x01
#define	DE_HIDDEN		0x02
#define	DE_SYSTEM		0x04
#define	DE_LABEL		0x08
#define	DE_DIRECTORY		0x10
#define	DE_ARCHIVE		0x20
#define	DE_RESERVED1		0x40
#define	DE_RESERVED2		0x80

#define	DE_IS_LFN (DE_READONLY | DE_HIDDEN | DE_SYSTEM | DE_LABEL)

struct _file_descriptor_ {
	struct _file_descriptor_ *f_forw; /* link to next file descriptor */
	int	f_desc;			/* descriptor number */
	long	f_startclust;		/* starting cluster number */
	long	f_off;			/* current offset */
	long	f_len;			/* size of file */
	long	f_index;		/* index into directory block */
	uchar_t	f_attr;			/* attributes */
	int	f_volidx;		/* Volume device index */
	char	*f_volname;		/* Name of volume */
};
typedef struct _file_descriptor_ _file_desc_t, *_file_desc_p;

#ifdef	__cplusplus
}
#endif

#endif	/* _PCFILEP_H */
