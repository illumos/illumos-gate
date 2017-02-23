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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * This file contains functions that operate on partition tables.
 */
#include <string.h>
#include <stdlib.h>
#include "global.h"
#include "partition.h"
#include "misc.h"
#include "menu_command.h"
#include "menu_partition.h"


/*
 * Default vtoc information for non-SVr4 partitions
 */
struct dk_map2	default_vtoc_map[NDKMAP] = {
	{	V_ROOT,		0	},		/* a - 0 */
	{	V_SWAP,		V_UNMNT	},		/* b - 1 */
	{	V_BACKUP,	V_UNMNT	},		/* c - 2 */
	{	V_UNASSIGNED,	0	},		/* d - 3 */
	{	V_UNASSIGNED,	0	},		/* e - 4 */
	{	V_UNASSIGNED,	0	},		/* f - 5 */
	{	V_USR,		0	},		/* g - 6 */
	{	V_UNASSIGNED,	0	},		/* h - 7 */

#if defined(_SUNOS_VTOC_16)

#if defined(i386)
	{	V_BOOT,		V_UNMNT	},		/* i - 8 */
	{	V_ALTSCTR,	0	},		/* j - 9 */

#else
#error No VTOC format defined.
#endif			/* defined(i386) */

	{	V_UNASSIGNED,	0	},		/* k - 10 */
	{	V_UNASSIGNED,	0	},		/* l - 11 */
	{	V_UNASSIGNED,	0	},		/* m - 12 */
	{	V_UNASSIGNED,	0	},		/* n - 13 */
	{	V_UNASSIGNED,	0	},		/* o - 14 */
	{	V_UNASSIGNED,	0	},		/* p - 15 */
#endif			/* defined(_SUNOS_VTOC_16) */
};

/*
 * This routine finds the last usable sector in the partition table.
 * It skips the BACKUP partition.
 */
static uint64_t
maxofN(struct dk_gpt *map)
{
	uint64_t	max;
	uint64_t	sec_no[2], start[2], size[2];
	int		i;

	for (i = 0; i < map->efi_nparts - 1; i++) {
	    start[0] = map->efi_parts[i].p_start;
	    size[0] = map->efi_parts[i].p_size;
	    sec_no[0] = start[0] + size[0];

	    start[1] = map->efi_parts[i+1].p_start;
	    size[1] = map->efi_parts[i+1].p_size;
	    sec_no[1] = start[1] + size[1];

	    if (map->efi_parts[i].p_tag == V_BACKUP) {
		sec_no[0] = 0;
	    }
	    if (map->efi_parts[i+1].p_tag == V_BACKUP) {
		sec_no[1] = 0;
	    }
	    if (i == 0) {
		max = sec_no[1];
	    }
	    if (sec_no[0] > max) {
		max = sec_no[0];
	    } else {
		max = max;
	    }
	}
	if (max == 0)
	    max = 34;
	return (max);
}

/*
 * This routine allows the user to change the boundaries of the given
 * partition in the current partition map.
 */
void
change_partition(int num)
{
	uint_t		i;
	uint64_t	i64, j64;
	uint_t		j;
	int		deflt;
	part_deflt_t	p_deflt;
	u_ioparam_t	ioparam;
	int		tag;
	int		flag;
	char		msg[256];
	blkaddr32_t	cyl_offset = 0;
	efi_deflt_t	efi_deflt;

	/*
	 * check if there exists a partition table for the disk.
	 */
	if (cur_parts == NULL) {
		err_print("Current Disk has no partition table.\n");
		return;
	}

	if (cur_label == L_TYPE_EFI) {
	    if (num > cur_parts->etoc->efi_nparts - 1) {
		err_print("Invalid partition for EFI label\n");
		return;
	    }
	    print_efi_partition(cur_parts->etoc, num, 1);
	    fmt_print("\n");
		/*
		 * Prompt for p_tag and p_flag values for this partition
		 */
	    deflt = cur_parts->etoc->efi_parts[num].p_tag;
	    if (deflt == V_UNASSIGNED) {
		deflt = V_USR;
	    }
	    (void) sprintf(msg, "Enter partition id tag");
	    ioparam.io_slist = ptag_choices;
	    tag = input(FIO_SLIST, msg, ':', &ioparam, &deflt, DATA_INPUT);

	    deflt = cur_parts->etoc->efi_parts[num].p_flag;
	    (void) sprintf(msg, "Enter partition permission flags");
	    ioparam.io_slist = pflag_choices;
	    flag = input(FIO_SLIST, msg, ':', &ioparam, &deflt, DATA_INPUT);

	    ioparam.io_bounds.lower = 34;
	    ioparam.io_bounds.upper = cur_parts->etoc->efi_last_u_lba;

	    efi_deflt.start_sector = maxofN(cur_parts->etoc);
	    if ((cur_parts->etoc->efi_parts[num].p_start != 0) &&
		(cur_parts->etoc->efi_parts[num].p_size != 0)) {
		    efi_deflt.start_sector =
			cur_parts->etoc->efi_parts[num].p_start;
	    }
	    efi_deflt.end_sector = ioparam.io_bounds.upper -
					efi_deflt.start_sector;
	    i64 = input(FIO_INT64, "Enter new starting Sector", ':', &ioparam,
		(int *)&efi_deflt, DATA_INPUT);

	    ioparam.io_bounds.lower = 0;
	    ioparam.io_bounds.upper = cur_parts->etoc->efi_last_u_lba;
	    efi_deflt.end_sector = cur_parts->etoc->efi_parts[num].p_size;
	    efi_deflt.start_sector = i64;
	    j64 = input(FIO_EFI, "Enter partition size", ':', &ioparam,
		(int *)&efi_deflt, DATA_INPUT);
	    if (j64 == 0) {
		tag = V_UNASSIGNED;
		i64 = 0;
	    } else if ((j64 != 0) && (tag == V_UNASSIGNED)) {
		tag = V_USR;
	    }

	    if (cur_parts->pinfo_name != NULL)
		make_partition();

	    cur_parts->etoc->efi_parts[num].p_tag = tag;
	    cur_parts->etoc->efi_parts[num].p_flag = flag;
	    cur_parts->etoc->efi_parts[num].p_start = i64;
	    cur_parts->etoc->efi_parts[num].p_size = j64;
	/*
	 * We are now done with EFI part, so return now
	 */
	    return;
	}
	/*
	 * Print out the given partition so the user knows what they're
	 * getting into.
	 */
	print_partition(cur_parts, num, 1);
	fmt_print("\n");

	/*
	 * Prompt for p_tag and p_flag values for this partition.
	 */
	assert(cur_parts->vtoc.v_version == V_VERSION);
	deflt = cur_parts->vtoc.v_part[num].p_tag;
	(void) sprintf(msg, "Enter partition id tag");
	ioparam.io_slist = ptag_choices;
	tag = input(FIO_SLIST, msg, ':', &ioparam, &deflt, DATA_INPUT);

	deflt = cur_parts->vtoc.v_part[num].p_flag;
	(void) sprintf(msg, "Enter partition permission flags");
	ioparam.io_slist = pflag_choices;
	flag = input(FIO_SLIST, msg, ':', &ioparam, &deflt, DATA_INPUT);

	/*
	 * Ask for the new values.  The old values are the defaults, and
	 * strict bounds checking is done on the values given.
	 */

#if defined(i386)

	if (tag != V_UNASSIGNED && tag != V_BACKUP && tag != V_BOOT) {
		/*
		 * Determine cyl offset for boot and alternate partitions.
		 * Assuming that the alternate sectors partition (slice)
		 * physical location immediately follows the boot
		 * partition and partition sizes are expressed in multiples
		 * of cylinder size.
		 */
		cyl_offset = cur_parts->pinfo_map[I_PARTITION].dkl_cylno + 1;
		if (tag != V_ALTSCTR) {
			if (cur_parts->pinfo_map[J_PARTITION].dkl_nblk != 0) {
				cyl_offset =
				cur_parts->pinfo_map[J_PARTITION].dkl_cylno +
				((cur_parts->pinfo_map[J_PARTITION].dkl_nblk +
				(spc()-1)) / spc());
			}
		}
	}
#endif	/* defined(i386) */

	ioparam.io_bounds.lower = 0;
	ioparam.io_bounds.upper = ncyl - 1;
	deflt = max(cur_parts->pinfo_map[num].dkl_cylno,
		cyl_offset);
	i = (uint_t)input(FIO_INT, "Enter new starting cyl", ':', &ioparam,
	    &deflt, DATA_INPUT);

	ioparam.io_bounds.lower = 0;
	ioparam.io_bounds.upper = (ncyl - i) * spc();

	/* fill in defaults for the current partition */
	p_deflt.start_cyl = i;
	p_deflt.deflt_size =
		min(cur_parts->pinfo_map[num].dkl_nblk,
		    ioparam.io_bounds.upper);

	/* call input, passing p_deflt's address, typecast to (int *) */
	j = (uint_t)input(FIO_ECYL, "Enter partition size", ':', &ioparam,
	    (int *)&p_deflt, DATA_INPUT);

	/*
	 * If the current partition has a size of zero change the
	 * tag to Unassigned and the starting cylinder to zero
	 */

	if (j == 0) {
		tag = V_UNASSIGNED;
		i = 0;
	}


#if defined(i386)

	if (i < cyl_offset && tag != V_UNASSIGNED && tag != V_BACKUP &&
	    tag != V_BOOT) {
		/*
		 * This slice overlaps boot and/or alternates slice
		 * Check if it's the boot or alternates slice and warn
		 * accordingly
		 */
		if (i < cur_parts->pinfo_map[I_PARTITION].dkl_cylno + 1) {
			fmt_print("\nWarning: Partition overlaps boot ");
			fmt_print("partition. Specify different start cyl.\n");
			return;
		}
		/*
		 * Cyl offset for alternates partition was calculated before
		 */
		if (i < cyl_offset) {
			fmt_print("\nWarning: Partition overlaps alternates ");
			fmt_print("partition. Specify different start cyl.\n");
			return;
		}
	}

#endif	/* defined(i386) */

	/*
	 * If user has entered a V_BACKUP tag then the partition
	 * size should specify full disk capacity else
	 * return an Error.
	 */
	if (tag == V_BACKUP) {
		uint_t fullsz;

		fullsz = ncyl * nhead * nsect;
		if (fullsz != j) {
		/*
		 * V_BACKUP Tag Partition != full disk capacity.
		 * print useful messages.
		 */
		fmt_print("\nWarning: Partition with V_BACKUP tag should ");
		fmt_print("specify full disk capacity. \n");
		return;
		}
	}


	/*
	 * If the current partition is named, we can't change it.
	 * We create a new current partition map instead.
	 */
	if (cur_parts->pinfo_name != NULL)
		make_partition();
	/*
	 * Change the values.
	 */
	cur_parts->pinfo_map[num].dkl_cylno = i;
	cur_parts->pinfo_map[num].dkl_nblk = j;

#if defined(_SUNOS_VTOC_16)
	cur_parts->vtoc.v_part[num].p_start = (daddr_t)(i * (nhead * nsect));
	cur_parts->vtoc.v_part[num].p_size = (long)j;
#endif	/* defined(_SUNOS_VTOC_16) */

	/*
	 * Install the p_tag and p_flag values for this partition
	 */
	assert(cur_parts->vtoc.v_version == V_VERSION);
	cur_parts->vtoc.v_part[num].p_tag = (ushort_t)tag;
	cur_parts->vtoc.v_part[num].p_flag = (ushort_t)flag;
}


/*
 * This routine picks to closest partition table which matches the
 * selected disk type.  It is called each time the disk type is
 * changed.  If no match is found, it uses the first element
 * of the partition table.  If no table exists, a dummy is
 * created.
 */
int
get_partition()
{
	register struct partition_info *pptr;
	register struct partition_info *parts;

	/*
	 * If there are no pre-defined maps for this disk type, it's
	 * an error.
	 */
	parts = cur_dtype->dtype_plist;
	if (parts == NULL) {
		err_print("No defined partition tables.\n");
		make_partition();
		return (-1);
	}
	/*
	 * Loop through the pre-defined maps searching for one which match
	 * disk type.  If found copy it into unmamed partition.
	 */
	enter_critical();
	for (pptr = parts; pptr != NULL; pptr = pptr->pinfo_next) {
	    if (cur_dtype->dtype_asciilabel) {
		if (pptr->pinfo_name != NULL && strcmp(pptr->pinfo_name,
				cur_dtype->dtype_asciilabel) == 0) {
			/*
			 * Set current partition and name it.
			 */
			cur_disk->disk_parts = cur_parts = pptr;
			cur_parts->pinfo_name = pptr->pinfo_name;
			exit_critical();
			return (0);
		}
	    }
	}
	/*
	 * If we couldn't find a match, take the first one.
	 * Set current partition and name it.
	 */
	cur_disk->disk_parts = cur_parts = cur_dtype->dtype_plist;
	cur_parts->pinfo_name = parts->pinfo_name;
	exit_critical();
	return (0);
}


/*
 * This routine creates a new partition map and sets it current.  If there
 * was a current map, the new map starts out identical to it.  Otherwise
 * the new map starts out all zeroes.
 */
void
make_partition()
{
	register struct partition_info *pptr, *parts;
	int	i;

	/*
	 * Lock out interrupts so the lists don't get mangled.
	 */
	enter_critical();
	/*
	 * Get space for for the new map and link it into the list
	 * of maps for the current disk type.
	 */
	pptr = (struct partition_info *)zalloc(sizeof (struct partition_info));
	parts = cur_dtype->dtype_plist;
	if (parts == NULL) {
		cur_dtype->dtype_plist = pptr;
	} else {
		while (parts->pinfo_next != NULL) {
			parts = parts->pinfo_next;
		}
		parts->pinfo_next = pptr;
		pptr->pinfo_next = NULL;
	}
	/*
	 * If there was a current map, copy its values.
	 */
	if (cur_label == L_TYPE_EFI) {
	    struct dk_gpt	*map;
	    int			nparts;
	    int			size;

	    nparts = cur_parts->etoc->efi_nparts;
	    size = sizeof (struct dk_part) * nparts + sizeof (struct dk_gpt);
	    map = zalloc(size);
	    (void) memcpy(map, cur_parts->etoc, size);
	    pptr->etoc = map;
	    cur_disk->disk_parts = cur_parts = pptr;
	    exit_critical();
	    return;
	}
	if (cur_parts != NULL) {
		for (i = 0; i < NDKMAP; i++) {
			pptr->pinfo_map[i] = cur_parts->pinfo_map[i];
		}
		pptr->vtoc = cur_parts->vtoc;
	} else {
		/*
		 * Otherwise set initial default vtoc values
		 */
		set_vtoc_defaults(pptr);
	}

	/*
	 * Make the new one current.
	 */
	cur_disk->disk_parts = cur_parts = pptr;
	exit_critical();
}


/*
 * This routine deletes a partition map from the list of maps for
 * the given disk type.
 */
void
delete_partition(struct partition_info *parts)
{
	struct	partition_info *pptr;

	/*
	 * If there isn't a current map, it's an error.
	 */
	if (cur_dtype->dtype_plist == NULL) {
		err_print("Error: unexpected null partition list.\n");
		fullabort();
	}
	/*
	 * Remove the map from the list.
	 */
	if (cur_dtype->dtype_plist == parts)
		cur_dtype->dtype_plist = parts->pinfo_next;
	else {
		for (pptr = cur_dtype->dtype_plist; pptr->pinfo_next != parts;
		    pptr = pptr->pinfo_next)
			;
		pptr->pinfo_next = parts->pinfo_next;
	}
	/*
	 * Free the space it was using.
	 */
	destroy_data((char *)parts);
}


/*
 * Set all partition vtoc fields to defaults
 */
void
set_vtoc_defaults(struct partition_info *part)
{
	int	i;

	bzero((caddr_t)&part->vtoc, sizeof (struct dk_vtoc));

	part->vtoc.v_version = V_VERSION;
	part->vtoc.v_nparts = NDKMAP;
	part->vtoc.v_sanity = VTOC_SANE;

	for (i = 0; i < NDKMAP; i++) {
		part->vtoc.v_part[i].p_tag = default_vtoc_map[i].p_tag;
		part->vtoc.v_part[i].p_flag = default_vtoc_map[i].p_flag;
	}
}
