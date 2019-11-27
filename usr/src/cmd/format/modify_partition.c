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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file contains functions to implement the partition menu commands.
 */
#include <stdlib.h>
#include <string.h>
#include "global.h"
#include "partition.h"
#include "menu_partition.h"
#include "menu_command.h"
#include "modify_partition.h"
#include "checkdev.h"
#include "misc.h"
#include "label.h"
#include "auto_sense.h"

#ifdef __STDC__

/* Function prototypes for ANSI C Compilers */

static void	adj_cyl_offset(struct dk_map32 *map);
static int	check_map(struct dk_map32 *map);
static void	get_user_map(struct dk_map32 *map, int float_part);
static void	get_user_map_efi(struct dk_gpt *map, int float_part);

#else	/* __STDC__ */

/* Function prototypes for non-ANSI C Compilers */

static void	adj_cyl_offset();
static int	check_map();
static void	get_user_map();
static void	get_user_map_efi();

#endif	/* __STDC__ */

static char *partn_list[] = { "0", "1", "2", "3", "4", "5", "6", "7", NULL };

static char *sel_list[] = { "0", "1", "2", "3", NULL };

#define	MBYTE	(1024*1024)


/*
 * Modify/Create a predefined partition table.
 */
int
p_modify()
{
	struct	partition_info	tmp_pinfo[1];
	struct	dk_map32	*map = tmp_pinfo->pinfo_map;
	u_ioparam_t		ioparam;
	int			inpt_dflt = 0;
	int			free_hog = -1;
	int			i;
	char			tmpstr[80];
	char			tmpstr2[300];
	int			sel_type = 0;

	/*
	 * There must be a current disk type (and therefore a current disk).
	 */
	if (cur_dtype == NULL) {
		err_print("Current Disk Type is not set.\n");
		return (-1);
	}

	/*
	 * check if there exists a partition table for the disk.
	 */
	if (cur_parts == NULL) {
		err_print("Current Disk has no partition table.\n");
		return (-1);
	}


	/*
	 * If the disk has mounted partitions, cannot modify
	 */
	if (checkmount((diskaddr_t)-1, (diskaddr_t)-1)) {
		err_print(
"Cannot modify disk partitions while it has mounted partitions.\n\n");
		return (-1);
	}

	/*
	 * If the disk has partitions currently being used for
	 * swapping, cannot modify
	 */
	if (checkswap((diskaddr_t)-1, (diskaddr_t)-1)) {
		err_print(
"Cannot modify disk partitions while it is \
currently being used for swapping.\n");
		return (-1);
	}

	/*
	 * Check to see if any partitions used for svm, vxvm, ZFS zpool
	 * or live upgrade are on the disk.
	 */
	if (checkdevinuse(cur_disk->disk_name, (diskaddr_t)-1,
	    (diskaddr_t)-1, 0, 0)) {
		err_print("Cannot modify disk partition when "
		    "partitions are in use as described.\n");
		return (-1);
	}

	/*
	 * prompt user for a partition table base
	 */
	if (cur_parts->pinfo_name != NULL) {
		(void) snprintf(tmpstr, sizeof (tmpstr),
			"\t0. Current partition table (%s)",
			cur_parts->pinfo_name);
	} else {
		(void) sprintf(tmpstr,
			"\t0. Current partition table (unnamed)");
	}

	(void) snprintf(tmpstr2, sizeof (tmpstr2),
"Select partitioning base:\n%s\n"
"\t1. All Free Hog\n"
"Choose base (enter number) ",
		tmpstr);

	ioparam.io_charlist = sel_list;
	sel_type = input(FIO_MSTR, tmpstr2, '?', &ioparam,
		&sel_type, DATA_INPUT);

	switch (cur_label) {
	case L_TYPE_SOLARIS:
	    if (sel_type == 0) {
		/*
		 * Check for invalid parameters but do
		 * not modify the table.
		 */
		if (check_map(cur_parts->pinfo_map)) {
			err_print("\
Warning: Fix, or select a different partition table.\n");
			return (0);
		}
		/*
		 * Create partition map from existing map
		 */
		tmp_pinfo->vtoc = cur_parts->vtoc;
		for (i = 0; i < NDKMAP; i++) {
			map[i].dkl_nblk = cur_parts->pinfo_map[i].dkl_nblk;
			map[i].dkl_cylno = cur_parts->pinfo_map[i].dkl_cylno;
		}
	    } else {
		/*
		 * Make an empty partition map, with all the space
		 * in the c partition.
		 */
		set_vtoc_defaults(tmp_pinfo);
		for (i = 0; i < NDKMAP; i++) {
			map[i].dkl_nblk = 0;
			map[i].dkl_cylno = 0;
		}
		map[C_PARTITION].dkl_nblk = ncyl * spc();

#if defined(i386)
		/*
		 * Adjust for the boot and possibly alternates partitions
		 */
		map[I_PARTITION].dkl_nblk = spc();
		map[I_PARTITION].dkl_cylno = 0;
		if (cur_ctype->ctype_ctype != DKC_SCSI_CCS) {
			map[J_PARTITION].dkl_nblk = 2 * spc();
			map[J_PARTITION].dkl_cylno = spc() / spc();
		}
#endif			/* defined(i386) */
	    }
	    break;
	case L_TYPE_EFI:
	    if (sel_type == 1) {
		for (i = 0; i < cur_parts->etoc->efi_nparts; i++) {
		    cur_parts->etoc->efi_parts[i].p_start = 0;
		    cur_parts->etoc->efi_parts[i].p_size = 0;
		}
	    }
	    break;
	}

	fmt_print("\n");
	if (cur_label == L_TYPE_SOLARIS) {
	    print_map(tmp_pinfo);
	} else {
	    print_map(cur_parts);
	}

	ioparam.io_charlist = confirm_list;
	if (input(FIO_MSTR,
"Do you wish to continue creating a new partition\ntable based on above table",
			'?', &ioparam, &inpt_dflt, DATA_INPUT)) {
		return (0);
	}

	/*
	 * get Free Hog partition
	 */
	inpt_dflt = 1;
	while ((free_hog < 0) && (cur_label == L_TYPE_SOLARIS)) {
		free_hog = G_PARTITION;	/* default to g partition */
		ioparam.io_charlist = partn_list;
		free_hog = input(FIO_MSTR, "Free Hog partition", '?',
			&ioparam, &free_hog, DATA_INPUT);
		/* disallow c partition */
		if (free_hog == C_PARTITION) {
			fmt_print("'%c' cannot be the 'Free Hog' partition.\n",
				C_PARTITION + PARTITION_BASE);
			free_hog = -1;
			continue;
		}
		/*
		 * If user selected all float set the
		 * float to be the whole disk.
		 */
		if (sel_type == 1) {
			map[free_hog].dkl_nblk = map[C_PARTITION].dkl_nblk;
#if defined(i386)
			map[free_hog].dkl_nblk -= map[I_PARTITION].dkl_nblk;
			if (cur_ctype->ctype_ctype != DKC_SCSI_CCS) {
				map[free_hog].dkl_nblk -=
					map[J_PARTITION].dkl_nblk;
			}
#endif			/* defined(i386) */
			break;
		}
		/*
		 * Warn the user if there is no free space in
		 * the float partition.
		 */
		if (map[free_hog].dkl_nblk == 0) {
			err_print("\
Warning: No space available from Free Hog partition.\n");
			ioparam.io_charlist = confirm_list;
			if (input(FIO_MSTR, "Continue", '?',
				&ioparam, &inpt_dflt, DATA_INPUT)) {
				free_hog = -1;
			}
		}
	}
	inpt_dflt = 0;

	if (cur_label == L_TYPE_EFI) {
	    free_hog = G_PARTITION; /* default to g partition */
	    ioparam.io_charlist = partn_list;
	    free_hog = input(FIO_MSTR, "Free Hog partition", '?',
		&ioparam, &free_hog, DATA_INPUT);
	    /* disallow c partition */
	    if (free_hog == C_PARTITION) {
		fmt_print("'%c' cannot be the 'Free Hog' partition.\n",
		    C_PARTITION + PARTITION_BASE);
		return (-1);
	    }
	    get_user_map_efi(cur_parts->etoc, free_hog);
	    print_map(cur_parts);
	    if (check("Ready to label disk, continue")) {
		return (-1);
	    }
	    fmt_print("\n");
	    if (write_label()) {
		err_print("Writing label failed\n");
		return (-1);
	    }
	    return (0);
	}
	/*
	 * get user modified partition table
	 */
	get_user_map(map, free_hog);

	/*
	 * Update cylno offsets
	 */
	adj_cyl_offset(map);

	fmt_print("\n");
	print_map(tmp_pinfo);

	ioparam.io_charlist = confirm_list;
	if (input(FIO_MSTR, "\
Okay to make this the current partition table", '?',
		&ioparam, &inpt_dflt, DATA_INPUT)) {
		return (0);
	} else {
		make_partition();
		/*
		 * Update new partition map
		 */
		for (i = 0; i < NDKMAP; i++) {
			cur_parts->pinfo_map[i].dkl_nblk = map[i].dkl_nblk;
			cur_parts->pinfo_map[i].dkl_cylno = map[i].dkl_cylno;
#ifdef i386
			cur_parts->vtoc.v_part[i].p_start =
				map[i].dkl_cylno * nhead * nsect;
			cur_parts->vtoc.v_part[i].p_size =
				map[i].dkl_nblk;
#endif
		}
		(void) p_name();

		/*
		 * Label the disk now
		 */
		if (check("Ready to label disk, continue")) {
			return (-1);
		}
		fmt_print("\n");
		if (write_label()) {
			err_print("Writing label failed\n");
			return (-1);
		}
		return (0);
	}
}



/*
 * Adjust cylinder offsets
 */
static void
adj_cyl_offset(map)
	struct	dk_map32 *map;
{
	int	i;
	int	cyloffset = 0;


	/*
	 * Update cylno offsets
	 */

#if defined(_SUNOS_VTOC_16)
	/*
	 * Correct cylinder allocation for having the boot and alternates
	 * slice in the beginning of the disk
	 */
	for (i = NDKMAP/2; i < NDKMAP; i++) {
		if (i != C_PARTITION && map[i].dkl_nblk) {
			map[i].dkl_cylno = cyloffset;
			cyloffset += (map[i].dkl_nblk + (spc()-1))/spc();
		} else if (map[i].dkl_nblk == 0) {
			map[i].dkl_cylno = 0;
		}
	}
	for (i = 0; i < NDKMAP/2; i++) {

#else					/* !defined(_SUNOS_VTOC_16) */
	for (i = 0; i < NDKMAP; i++) {
#endif					/* defined(_SUNOS_VTOC_16) */

		if (i != C_PARTITION && map[i].dkl_nblk) {
			map[i].dkl_cylno = cyloffset;
			cyloffset += (map[i].dkl_nblk + (spc()-1))/spc();
		} else if (map[i].dkl_nblk == 0) {
			map[i].dkl_cylno = 0;
		}
	}
}


/*
 * Check partition table
 */
static int
check_map(map)
	struct	dk_map32 *map;
{
	int		i;
	int		cyloffset = 0;
	blkaddr32_t	tot_blks = 0;

#ifdef i386
	/*
	 * On x86, we must account for the boot and alternates
	 */
	cyloffset = map[0].dkl_cylno;
	tot_blks = map[0].dkl_nblk;
#endif

	/*
	 * Do some checks for invalid parameters but do
	 * not modify the table.
	 */
	for (i = 0; i < NDKMAP; i++) {
		if (map[i].dkl_cylno > (blkaddr32_t)ncyl-1) {
			err_print("\
Warning: Partition %c starting cylinder %d is out of range.\n",
				(PARTITION_BASE+i), map[i].dkl_cylno);
			return (-1);
		}
		if (map[i].dkl_nblk >
			(blkaddr32_t)(ncyl - map[i].dkl_cylno) * spc()) {
			err_print("\
Warning: Partition %c, specified # of blocks, %u, is out of range.\n",
				(PARTITION_BASE+i), map[i].dkl_nblk);
			return (-1);
		}
		if (i != C_PARTITION && map[i].dkl_nblk) {
#ifdef	i386
			if (i == I_PARTITION || i == J_PARTITION)
				continue;
#endif
			if (map[i].dkl_cylno < cyloffset) {
				err_print(
"Warning: Overlapping partition (%c) in table.\n", PARTITION_BASE+i);
				return (-1);
			} else if (map[i].dkl_cylno > cyloffset) {
				err_print(
"Warning: Non-contiguous partition (%c) in table.\n", PARTITION_BASE+i);
			}
			cyloffset += (map[i].dkl_nblk + (spc()-1))/spc();
			tot_blks = map[i].dkl_nblk;
		}
	}
	if (tot_blks > map[C_PARTITION].dkl_nblk) {
		err_print("\
Warning: Total blocks used is greater than number of blocks in '%c'\n\
\tpartition.\n", C_PARTITION + PARTITION_BASE);
	return (-1);
	}
	return (0);
}



/*
 * get user defined partitions
 */
static void
get_user_map(map, float_part)
	struct	dk_map32 *map;
	int	float_part;
{
	int		i;
	blkaddr32_t	newsize;
	blkaddr32_t	deflt;
	char		tmpstr[80];
	u_ioparam_t	ioparam;

	/*
	 * Get partition sizes
	 */
	for (i = 0; i < NDKMAP; i++) {
		if (partn_list[i] == NULL)
			break;
		if ((i == C_PARTITION) || (i == float_part))
			continue;
		else {
			ioparam.io_bounds.lower = 0;
			ioparam.io_bounds.upper = map[i].dkl_nblk +
				map[float_part].dkl_nblk;
			deflt = map[i].dkl_nblk;
			if (ioparam.io_bounds.upper == 0) {
				err_print("\
Warning: no space available for '%s' from Free Hog partition\n",
					partn_list[i]);
				continue;
			}
			(void) snprintf(tmpstr, sizeof (tmpstr),
				"Enter size of partition '%s' ",
				partn_list[i]);
			newsize = (blkaddr32_t)input(FIO_CYL, tmpstr, ':',
				&ioparam, (int *)&deflt, DATA_INPUT);
			map[float_part].dkl_nblk -= (newsize - map[i].dkl_nblk);
			map[i].dkl_nblk = newsize;
		}
	}
}

static struct partition_info *
build_partition(tptr)
struct disk_type *tptr;
{
	struct partition_info	*part;
	struct dk_label		*label;
	int			i;

#ifdef DEBUG
	fmt_print("Creating Default Partition for the disk \n");
#endif
	/*
	 * construct a label and pass it on to
	 * build_default_partition() which builds the
	 * default partition list.
	 */
	label = zalloc(sizeof (struct dk_label));
	label->dkl_pcyl = tptr->dtype_pcyl;
	label->dkl_ncyl = tptr->dtype_ncyl;
	label->dkl_acyl = tptr->dtype_acyl;
	label->dkl_nhead = tptr->dtype_nhead;
	label->dkl_nsect = tptr->dtype_nsect;
	label->dkl_apc = apc;
	label->dkl_intrlv = 1;
	label->dkl_rpm	= tptr->dtype_rpm;

	if (!build_default_partition(label, cur_ctype->ctype_ctype))
		return (NULL);

	part = (struct partition_info *)
		    zalloc(sizeof (struct partition_info));
	part->pinfo_name = alloc_string(tptr->dtype_asciilabel);
	/*
	 * Fill in the partition info from the label
	 */
	for (i = 0; i < NDKMAP; i++) {
#if defined(_SUNOS_VTOC_8)
	    part->pinfo_map[i] = label->dkl_map[i];
#else
	    part->pinfo_map[i].dkl_cylno =
		label->dkl_vtoc.v_part[i].p_start /
		(blkaddr32_t)(tptr->dtype_nhead * tptr->dtype_nsect - apc);
	    part->pinfo_map[i].dkl_nblk =
		label->dkl_vtoc.v_part[i].p_size;
#endif /* ifdefined(_SUNOS_VTOC_8) */
	}
	part->vtoc = label->dkl_vtoc;
	return (part);
}

/*
 * build new partition table for given disk type
 */
static void
get_user_map_efi(map, float_part)
	struct dk_gpt *map;
	int	float_part;
{

	int		i;
	efi_deflt_t	efi_deflt;
	u_ioparam_t	ioparam;
	char		tmpstr[80];
	uint64_t	i64;
	uint64_t	start_lba = map->efi_first_u_lba;
	uint64_t	reserved;

	reserved = efi_reserved_sectors(map);
	for (i = 0; i < map->efi_nparts - 1; i++) {
		/* GPT partition 7 is whole disk device, minor node "wd" */
		if (i == float_part || i == 7)
			continue;

		ioparam.io_bounds.lower = start_lba;
		ioparam.io_bounds.upper = map->efi_last_u_lba;
		efi_deflt.start_sector = ioparam.io_bounds.lower;
		efi_deflt.end_sector = map->efi_parts[i].p_size;
		(void) sprintf(tmpstr, "Enter size of partition %d ", i);
		i64 = input(FIO_EFI, tmpstr, ':',
		    &ioparam, (int *)&efi_deflt, DATA_INPUT);
		if (i64 == 0) {
			map->efi_parts[i].p_tag = V_UNASSIGNED;
		} else if ((i64 != 0) && (map->efi_parts[i].p_tag ==
		    V_UNASSIGNED)) {
			map->efi_parts[i].p_tag = V_USR;
		}
		if (i64 == 0) {
			map->efi_parts[i].p_start = 0;
		} else {
			map->efi_parts[i].p_start = start_lba;
		}
		map->efi_parts[i].p_size = i64;
		start_lba += i64;
	}
	map->efi_parts[float_part].p_start = start_lba;
	map->efi_parts[float_part].p_size = map->efi_last_u_lba + 1 -
		start_lba - reserved;
	map->efi_parts[float_part].p_tag = V_USR;
	if (map->efi_parts[float_part].p_size == 0) {
		map->efi_parts[float_part].p_size = 0;
		map->efi_parts[float_part].p_start = 0;
		map->efi_parts[float_part].p_tag = V_UNASSIGNED;
		fmt_print("Warning: No space left for HOG\n");
	}

	for (i = 0; i < map->efi_nparts; i++) {
		if (map->efi_parts[i].p_tag == V_RESERVED) {
			map->efi_parts[i].p_start = map->efi_last_u_lba -
			    reserved + 1;
			map->efi_parts[i].p_size = reserved;
			break;
		}
	}
}


void
new_partitiontable(tptr, oldtptr)
struct disk_type	*tptr, *oldtptr;
{
	struct partition_info *part;

	/*
	 * check if disk geometry has changed , if so add new
	 * partition table else copy the old partition table.(best guess).
	 */
	if ((oldtptr != NULL) &&
		(tptr->dtype_ncyl ==  oldtptr->dtype_ncyl) &&
		(tptr->dtype_nhead == oldtptr->dtype_nhead) &&
		(tptr->dtype_nsect == oldtptr->dtype_nsect)) {

	    part = (struct partition_info *)
			zalloc(sizeof (struct partition_info));
	    bcopy((char *)cur_parts, (char *)part,
			sizeof (struct partition_info));
	    part->pinfo_next = tptr->dtype_plist;
	    tptr->dtype_plist = part;
	} else {

#ifdef DEBUG
		if (cur_parts != NULL) {
			fmt_print("Warning: Partition Table is set");
			fmt_print("to default partition table. \n");
		}
#endif
		if (tptr->dtype_plist == NULL) {
			part = (struct partition_info *)build_partition(tptr);
			if (part != NULL) {
				part->pinfo_next = tptr->dtype_plist;
				tptr->dtype_plist = part;
			}
		}
	}
}
