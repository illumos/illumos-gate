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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Fdisk partition class implementation file
 */

/*
 * System include files
 */

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<sys/types.h>
#include	<fcntl.h>
#include	<ctype.h>
#include	<string.h>
#include	<sys/dktp/fdisk.h>
#include	<sys/vtoc.h>
#include	<sys/dklabel.h>
#include	<sys/fs/pc_label.h>
#include	<sys/fs/pc_fs.h>
#include	<sys/fs/pc_dir.h>

/*
 * Private data and procedure declarations
 */

#include "partition_private.h"

#define	DOS_READ_LENGTH (4 * PC_SECSIZE)

/*
 * Forward declarations of private methods
 */

static partition_result_t
	create_fdisk_vnodes(partition_private_t *partition_privatep);

static int is_dos_drive(uchar_t);

/*
 * Methods that implement abstract methods
 * declared in the parent partition class
 */

static partition_methods_t  partition_methods =
	{create_fdisk_vnodes, read_fdisk_partition};

/*
 * Definition of the public read_partition() method that
 * identifies the partition type and sets its attributes
 */

partition_result_t
read_fdisk_partition(partition_private_t *partition_privatep)
{
	/*
	 * Check to see if there is an fdisk partition table in
	 * the partition.  If so, searche the fdisk partition
	 * table for partitions that aren't empty and aren't
	 * extended DOS partitions.  If such a partition exists,
	 * create an empty child partition object and link it to
	 * the parent fdisk partition.  Set the child partition's
	 * offset on the medium and call read_partition(), passing
	 * it the child object's handle.
	 *
	 * Next, search the fdisk partition table for extended
	 * DOS partitions.  If one exists, create an empty child
	 * partition object and link it to the fdisk partition.
	 * Set the child partition's offset on the medium and call
	 * read_partition(), passing it the child object's handle.
	 *
	 * NOTE: This method is recursive.  It can call itself
	 *	 and call other read_partition() methods that
	 *	 can call it.
	 */

	partition_private_t	*child_privatep;
	struct mboot		*master_boot_recordp;
	medium_private_t	*medium_privatep;
	partition_handle_t	new_childp;
	int			partition_index;
	struct ipart		*partition_table_entryp;
	struct ipart		*partition_tablep;
	partition_result_t	partition_result;
	int			read_length;
	ushort_t		signature;
	unsigned char		systid;
	off_t			offset, seek_off;
	int			solaris_offset;
	boolean_t		primary_partition;

	debug(2, "entering read_fdisk_partition()\n");

	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;
	if (partition_privatep->primary_part_idx != 0) {
		/*
		 * There should be no fdisk partition in the primary
		 * fdisk partition.
		 */
		partition_result = PARTITION_NOT_THIS_TYPE;
		goto dun;
	}

	if (++medium_privatep->partition_depth > MAX_PARTITION_DEPTH) {
		partition_result = PARTITION_TOO_MANY_PARTITIONS;
		goto dun;
	}

	primary_partition = (partition_privatep->parentp == NULL);
	partition_result = PARTITION_SUCCESS;

	master_boot_recordp = calloc(1, sizeof (struct mboot));
	partition_tablep = calloc(FD_NUMPART, sizeof (struct ipart));
	if ((master_boot_recordp == NULL) || (partition_tablep == NULL)) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	}
	offset = partition_privatep->base_offset
			+ partition_privatep->offset;
	if (partition_result == PARTITION_SUCCESS) {
		if ((offset + sizeof (struct mboot)) >
		    medium_privatep->medium_capacity) {
			partition_result = PARTITION_CANT_READ_MEDIUM;
		}
	}
	if (partition_result == PARTITION_SUCCESS) {
		seek_off = lseek(partition_privatep->file_descriptor,
				offset, SEEK_SET);
		if (seek_off != offset) {
			partition_result = PARTITION_CANT_READ_MEDIUM;
		}
	}
	if (partition_result == PARTITION_SUCCESS) {
		read_length = read(partition_privatep->file_descriptor,
					(void *)master_boot_recordp,
					sizeof (struct mboot));
		if (read_length != sizeof (struct mboot)) {
			partition_result = PARTITION_CANT_READ_MEDIUM;
		}
	}
	if (partition_result == PARTITION_SUCCESS) {
		signature = ltohs(master_boot_recordp->signature);
		if (signature != MBB_MAGIC) {
			partition_result = PARTITION_NOT_THIS_TYPE;
		} else {
			partition_privatep->methodsp = &partition_methods;
			partition_privatep->state = NOT_MOUNTABLE;
			partition_privatep->type = FDISK;
			medium_privatep->partition_counts[FDISK]++;
			(void) memcpy((void *)partition_tablep,
				(const void *)master_boot_recordp->parts,
				(size_t)(FD_NUMPART * sizeof (struct ipart)));
		}
	}

	solaris_offset = -1;

#ifdef _FIRMWARE_NEEDS_FDISK
	if (primary_partition) {
		/*
		 * Solaris partition cannot exist in extended DOS partition.
		 */
		partition_index = 0;
		while ((partition_result == PARTITION_SUCCESS) &&
		    (partition_index < FD_NUMPART)) {
			unsigned char bootid;

			partition_table_entryp = partition_tablep +
				partition_index;
			systid = partition_table_entryp->systid;
			bootid = partition_table_entryp->bootid;
			/*
			 * see sd.c on how scsi driver picks the solaris
			 * partition.
			 */
			if (systid == SUNIXOS || systid == SUNIXOS2) {
				if (solaris_offset == -1 || bootid == ACTIVE) {
					solaris_offset = partition_index;
				}
			}
			partition_index++;
		}
	}
#endif

	partition_index = 0;
	while ((partition_result == PARTITION_SUCCESS) &&
		(partition_index < FD_NUMPART)) {
		partition_table_entryp = partition_tablep + partition_index;
		systid = partition_table_entryp->systid;
		if (systid != EXTDOS && systid != FDISK_EXTLBA &&
		    systid != 0 &&
		    partition_table_entryp->relsect != 0) {
			partition_result = create_child_partition(
				(partition_handle_t)partition_privatep,
				&new_childp);
			if (partition_result == PARTITION_SUCCESS) {
				child_privatep = (partition_private_t *)
					new_childp;
				child_privatep->offset = offset +
					(PC_SECSIZE *
					ltohi(partition_table_entryp->relsect));
				if (partition_index != solaris_offset) {
					child_privatep->no_solaris_partition
						= TRUE;
				}
				if (primary_partition) {
					child_privatep->primary_part_idx =
						(char)partition_index + 1;
				} else {
					child_privatep->primary_part_idx =
						-((char)partition_index + 1);
				}
				child_privatep->no_pcfs_partition =
					(is_dos_drive(systid) == 0);
				partition_result =
					read_partition(child_privatep);
			}
		}
		partition_index++;
	}
	partition_index = 0;
	while ((partition_result == PARTITION_SUCCESS) &&
		(partition_index < FD_NUMPART)) {
		partition_table_entryp = partition_tablep + partition_index;
		systid = partition_table_entryp->systid;
		if ((systid == EXTDOS || systid == FDISK_EXTLBA) &&
		    partition_table_entryp->relsect != 0) {
			partition_result = create_child_partition(
				(partition_handle_t)partition_privatep,
				&new_childp);
			if (partition_result != PARTITION_SUCCESS)
				break;
			child_privatep = (partition_private_t *)new_childp;
			seek_off = (PC_SECSIZE *
				ltohi(partition_table_entryp->relsect));
			if (primary_partition) {
				/*
				 * This is the primary record, calc the
				 * base offset of the extended partition
				 * record.
				 */
				child_privatep->base_offset = offset + seek_off;
				child_privatep->offset = 0;
			} else {
				/* This is an extended partition record */
				child_privatep->base_offset =
					partition_privatep->base_offset;
				child_privatep->offset = seek_off;
			}
			/*
			 * There should be no solaris partition in
			 * the extended partition.
			 */
			child_privatep->primary_part_idx = 0;
			child_privatep->no_solaris_partition = TRUE;
			partition_result = read_fdisk_partition(child_privatep);
			/*
			 * There is only one extended partition should exist
			 * in this record.
			 */
			break;
		}
		partition_index++;
	}
	if (master_boot_recordp != NULL) {
		free(master_boot_recordp);
	}
	if (partition_tablep != NULL) {
		free(partition_tablep);
	}
dun:
	medium_privatep->partition_depth--;
	debug(2, "leaving read_fdisk_partition(), result code = %s\n",
		partition_result_codes[partition_result]);

	return (partition_result);
}

/*
 * Definitions of private methods
 */

static partition_result_t
create_fdisk_vnodes(partition_private_t *partition_privatep)
{
	/*
	 * An fdisk partition has no vnodes of its own, because
	 * it's not represented in the external structures of
	 * file systems.  It simply appropriates the vnodes of
	 * the medium, by way of any parent fdisk partitions
	 * that may exist on the medium.
	 */
	partition_handle_t	childp;
	partition_private_t	*child_privatep;
	medium_private_t	*medium_privatep;
	partition_private_t	*parent_privatep;
	partition_result_t	partition_result;

	debug(2, "entering create_fdisk_vnodes()\n");

	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;
	parent_privatep = (partition_private_t *)partition_privatep->parentp;
	partition_result = PARTITION_SUCCESS;

	if (parent_privatep != NULL) {
		/*
		 * The partition has a parent fdisk partition.
		 * It's pathnames and vvnodes are the same
		 * as those of its parent.
		 */
		if (parent_privatep->block_pathnamep != NULL) {
			partition_privatep->block_pathnamep =
				strdup(parent_privatep->block_pathnamep);
		} else {
			partition_privatep->block_pathnamep = NULL;
		}
		partition_privatep->raw_pathnamep =
			strdup(parent_privatep->raw_pathnamep);
		partition_privatep->parent_block_vvnodep =
			parent_privatep->block_vvnodep;
		partition_privatep->block_vvnodep =
			parent_privatep->block_vvnodep;
		partition_privatep->parent_raw_vvnodep =
			parent_privatep->raw_vvnodep;
		partition_privatep->raw_vvnodep =
			parent_privatep->raw_vvnodep;
		if (partition_privatep->raw_pathnamep == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		}

	} else {
		/*
		 * The partition is the top partition on
		 * the medium.  It's pathnames and vvnodes
		 * are the same as those of the medium.
		 */
		if (medium_privatep->block_pathnamep != NULL) {
			partition_privatep->block_pathnamep =
				strdup(medium_privatep->block_pathnamep);
		} else {
			partition_privatep->block_pathnamep = NULL;
		}
		partition_privatep->raw_pathnamep =
			strdup(medium_privatep->raw_pathnamep);
		medium_privatep = (medium_private_t *)
			partition_privatep->on_mediump;
		partition_privatep->parent_block_vvnodep =
			medium_privatep->block_vvnodep;
		partition_privatep->block_vvnodep =
			medium_privatep->block_vvnodep;
		partition_privatep->parent_raw_vvnodep =
			medium_privatep->raw_vvnodep;
		partition_privatep->raw_vvnodep =
			medium_privatep->raw_vvnodep;
		if (partition_privatep->raw_pathnamep == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		}
	}
	/*
	 * Create vnodes for the partitions described in the fdisk
	 * partition table.
	 */
	childp = partition_privatep->left_childp;
	while ((partition_result == PARTITION_SUCCESS) && (childp != NULL)) {
		partition_result = partition_create_vnodes(childp);
		child_privatep = (partition_private_t *)childp;
		childp = child_privatep->right_siblingp;
	}
	debug(2, "leaving create_fdisk_vnodes(), result code = %s\n",
		partition_result_codes[partition_result]);

	return (partition_result);
}

static int
is_dos_drive(uchar_t check)
{
	return ((check == DOSOS12) || (check == DOSOS16) ||
	    (check == DOSHUGE) || (check == FDISK_WINDOWS) ||
	    (check == FDISK_EXT_WIN) || (check == FDISK_FAT95) ||
	    (check == DIAGPART));
}
