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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015 Nexenta Systems, Inc. All rights reserved.
 */

#ifndef	_HARDWARE_STRUCTS_H
#define	_HARDWARE_STRUCTS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/isa_defs.h>

#include <sys/dktp/fdisk.h>
#include <sys/dklabel.h>
#include <sys/efi_partition.h>

/*
 * This file contains definitions of data structures pertaining to disks
 * and controllers.
 */

/*
 * This structure describes a specific disk.  These structures are in a
 * linked list because they are malloc'd as disks are found during the
 * initial search.
 */
struct disk_info {
	int			label_type;	/* EFI or non-EFI disk */
	struct dk_cinfo		disk_dkinfo;	/* controller config info */
	struct disk_type	*disk_type;	/* ptr to physical info */
	struct partition_info	*disk_parts;	/* ptr to partition info */
	struct dk_gpt		*efi_parts;	/* ptr to partition info */
	struct ctlr_info	*disk_ctlr;	/* ptr to disk's ctlr */
	struct disk_info	*disk_next;	/* ptr to next disk */
	struct ipart		fdisk_part;	/* fdisk partition info */
	int			disk_flags;	/* misc gotchas */
	char			*disk_name;	/* name of the disk */
	char			*disk_path;	/* pathname to device */
	char			*devfs_name;	/* devfs name for device */
	char			v_volume[LEN_DKL_VVOL];
						/* volume name from label */
						/* (no terminating null) */
	uint_t			disk_lbasize;	/* disk block size */

};

#define	NSPECIFICS	8

/*
 * This structure describes a type (model) of drive.  It is malloc'd
 * and filled in as the data file is read and when a type 'other' disk
 * is selected.  The link is used to make a list of all drive types
 * supported by a ctlr type.
 */
struct disk_type {
	char	*dtype_asciilabel;		/* drive identifier */
	int	dtype_flags;			/* flags for disk type */
	ulong_t	dtype_options;			/* flags for options */
	uint_t	dtype_fmt_time;			/* format time */
	uint_t	dtype_bpt;			/* # bytes per track */
	uint_t	dtype_ncyl;			/* # of data cylinders */
	uint_t	dtype_acyl;			/* # of alternate cylinders */
	uint_t	dtype_pcyl;			/* # of physical cylinders */
	uint_t	dtype_nhead;			/* # of heads */
	uint_t	dtype_phead;			/* # of physical heads */
	uint_t	dtype_nsect;			/* # of data sectors/track */
	uint_t	dtype_psect;			/* # physical sectors/track */
	uint_t	dtype_rpm;			/* rotations per minute */
	int	dtype_cyl_skew;			/* cylinder skew */
	int	dtype_trk_skew;			/* track skew */
	uint_t	dtype_trks_zone;		/* # tracks per zone */
	uint_t	dtype_atrks;			/* # alt. tracks  */
	uint_t	dtype_asect;			/* # alt. sectors */
	int	dtype_cache;			/* cache control */
	int	dtype_threshold;		/* cache prefetch threshold */
	int	dtype_read_retries;		/* read retries */
	int	dtype_write_retries;		/* write retries */
	int	dtype_prefetch_min;		/* cache min. prefetch */
	int	dtype_prefetch_max;		/* cache max. prefetch */
	uint_t	dtype_specifics[NSPECIFICS];	/* ctlr specific drive info */
	struct	chg_list	*dtype_chglist;	/* mode sense/select */
						/* change list - scsi */
	struct	partition_info	*dtype_plist;	/* possible partitions */
	struct	disk_type	*dtype_next;	/* ptr to next drive type */
	/*
	 * Added so that we can print a useful diagnostic if
	 * inconsistent definitions found in multiple files.
	 */
	char	*dtype_filename;		/* filename where defined */
	int	dtype_lineno;			/* line number in file */

	char		*vendor;
	char		*product;
	char		*revision;
	uint64_t	capacity;
};

struct efi_info {
	char		*vendor;
	char		*product;
	char		*revision;
	uint64_t	capacity;
	struct dk_gpt	*e_parts;
};

/*
 * This structure describes a specific ctlr.  These structures are in
 * a linked list because they are malloc'd as ctlrs are found during
 * the initial search.
 */
struct ctlr_info {
	char	ctlr_cname[DK_DEVLEN+1];	/* name of ctlr */
	char	ctlr_dname[DK_DEVLEN+1];	/* name of disks */
	ushort_t ctlr_flags;			/* flags for ctlr */
	short	ctlr_num;			/* number of ctlr */
	int	ctlr_addr;			/* address of ctlr */
	uint_t	ctlr_space;			/* bus space it occupies */
	int	ctlr_prio;			/* interrupt priority */
	int	ctlr_vec;			/* interrupt vector */
	struct	ctlr_type *ctlr_ctype;		/* ptr to ctlr type info */
	struct	ctlr_info *ctlr_next;		/* ptr to next ctlr */
};

/*
 * This structure describes a type (model) of ctlr.  All supported ctlr
 * types are built into the program statically, they cannot be added by
 * the user.
 */
struct ctlr_type {
	ushort_t ctype_ctype;			/* type of ctlr */
	char	*ctype_name;			/* name of ctlr type */
	struct	ctlr_ops *ctype_ops;		/* ptr to ops vector */
	int	ctype_flags;			/* flags for gotchas */
	struct	disk_type *ctype_dlist;		/* list of disk types */
};

/*
 * This structure is the operation vector for a controller type.  It
 * contains pointers to all the functions a controller type can support.
 */
struct ctlr_ops {
	int	(*op_rdwr)();		/* read/write - mandatory */
	int	(*op_ck_format)();	/* check format - mandatory */
	int	(*op_format)();		/* format - mandatory */
	int	(*op_ex_man)();		/* get manufacturer's list - optional */
	int	(*op_ex_cur)();		/* get current list - optional */
	int	(*op_repair)();		/* repair bad sector - optional */
	int	(*op_create)();		/* create original manufacturers */
					/* defect list. - optional */
	int	(*op_wr_cur)();		/* write current list - optional */
};

/*
 * This structure describes a specific partition layout.  It is malloc'd
 * when the data file is read and whenever the user creates his own
 * partition layout.  The link is used to make a list of possible
 * partition layouts for each drive type.
 */
struct partition_info {
	char	*pinfo_name;			/* name of layout */
	struct	dk_map32 pinfo_map[NDKMAP];	/* layout info */
	struct	dk_vtoc vtoc;			/* SVr4 vtoc additions */
	struct	partition_info *pinfo_next;	/* ptr to next layout */
	char	*pinfo_filename;		/* filename where defined */
	int	pinfo_lineno;			/* line number in file */
	struct	dk_gpt	*etoc;			/* EFI partition info */
};


/*
 * This structure describes a change to be made to a particular
 * SCSI mode sense page, before issuing a mode select on that
 * page.  This changes are specified in format.dat, and one
 * such structure is created for each specification, linked
 * into a list, in the order specified.
 */
struct chg_list {
	int		pageno;		/* mode sense page no. */
	int		byteno;		/* byte within page */
	int		mode;		/* see below */
	int		value;		/* desired value */
	struct chg_list	*next;		/* ptr to next */
};

/*
 * Change list modes
 */
#define	CHG_MODE_UNDEFINED	(-1)		/* undefined value */
#define	CHG_MODE_SET		0		/* set bits by or'ing */
#define	CHG_MODE_CLR		1		/* clr bits by and'ing */
#define	CHG_MODE_ABS		2		/* set absolute value */

/*
 * This is the structure that creates a dynamic list of controllers
 * that we know about.  This structure will point to the items that
 * use to be statically created in the format program but will now allow
 * dynamic creation of the list so that we can do 3'rd party generic
 * disk/controller support.
 */

struct mctlr_list {
	struct mctlr_list *next;
	struct ctlr_type  *ctlr_type;
};

#ifdef	__cplusplus
}
#endif

#endif	/* _HARDWARE_STRUCTS_H */
