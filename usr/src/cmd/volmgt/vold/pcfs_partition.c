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
 * DOS partition class implementation file
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
 * Private attribute and method declarations
 */

#include "partition_private.h"

typedef struct pcfs_attributes {
	char    dos_partition_letterp[2];
} pcfs_attributes_t;

/*
 * Offset in the volume header of the ascii name of the volume.
 * This is only valid for dos 4.0 and later.
 */

#define	DOS_NAME_OFFSET	0x2b

/*
 * Number of bytes in the "volume header" located in sector
 * 0 on a DOS disk.  Used to calculate the checksum.
 */

#define	DOS_LABLEN	0x3e

/*
 * Number of bytes to read from a DOS disk
 */

#define	DOS_READ_LENGTH  	(PC_SECSIZE * 4)

/*
 * Mask used to compute the offset of a DOS FAT within a sector
 */

#define	DOS_READ_LENGTH_MASK	(DOS_READ_LENGTH - 1)

/*
 * Volume name used for the first PCFS partition on a medium
 * that contains other file systems and whose PCFS file
 * system has no label
 */

#define	UNNAMED_PCFS  "unnamed_pcfs"

/*
 * Forward declarations of private methods
 */

static partition_result_t check_fat(uchar_t *, partition_private_t *);
static partition_result_t check_label(uchar_t *, partition_private_t *);
static partition_result_t create_pcfs_pathnames(partition_private_t *);
static partition_result_t create_pcfs_symlink(partition_private_t *);
static partition_result_t create_pcfs_volume(partition_private_t *);
static partition_result_t create_pcfs_vnodes(partition_private_t *);
static partition_result_t create_top_level_pcfs_vnodes(partition_private_t *);
static partition_result_t dir_entry_to_volname(struct pcdir *, char **);
static bool_t	dos_filename_char(char);
static int 	dos_label_char(int);
static void	find_parent_pcfs_vvnodes(partition_private_t *);
static partition_result_t get_label(partition_private_t *);
static partition_result_t get_volume_name(uchar_t *, partition_private_t *);
static partition_result_t
	get_volume_name_from_label(uchar_t *, partition_private_t *);
static partition_result_t
	get_volume_name_from_rootdir(uchar_t *, partition_private_t *);
static partition_result_t read_label(uchar_t *, partition_private_t *);
static partition_result_t set_dos_partition_letter(partition_private_t *);

/*
 * Methods that implement abstract methods
 * declared in the parent partition class
 */

static partition_methods_t  partition_methods =
	{create_pcfs_vnodes, read_pcfs_partition};

/*
 * Definition of the public read_partition() method that
 * identifies the partition type and sets its attributes
 */

partition_result_t
read_pcfs_partition(partition_private_t *partition_privatep)
{
	/*
	 * If there's a readable PCFS label on the partition,
	 * set the partition's attributes and return PARTITION_SUCCESS.
	 */
	medium_private_t	*medium_privatep;
	partition_private_t	*parent_privatep;
	partition_result_t	partition_result;

	debug(2, "entering read_pcfs_partition()\n");

	if (partition_privatep->no_pcfs_partition == B_TRUE) {
		partition_result = PARTITION_NOT_THIS_TYPE;
		goto dun;
	}

	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;
	parent_privatep = (partition_private_t *)partition_privatep->parentp;

	partition_result = get_label(partition_privatep);

	if (partition_result == PARTITION_SUCCESS) {
		partition_privatep->attributesp =
			malloc(sizeof (pcfs_attributes_t));
		if (partition_privatep->attributesp == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		}
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_privatep->methodsp = &partition_methods;
		partition_privatep->number_of_slices = ONE_SLICE;
#ifdef i386
		partition_privatep->partition_mask =
			DEFAULT_INTEL_PARTITION_MASK;
#else
		partition_privatep->partition_mask =
			DEFAULT_SPARC_PARTITION_MASK;
#endif
		partition_privatep->type = PCFS;
		if ((parent_privatep != NULL) &&
		    (parent_privatep->type != FDISK)) {
			/*
			 * The partition is a subpartition of a parent
			 * partition.  The read_slices() method has
			 * already assigned the partition a devmap index,
			 * partition_number, and volume name.  Transfer
			 * the volume name to the partition's label.
			 * Don't increment the medium's PCFS partition
			 * counter.  It's only used to count the number
			 * of top level PCFS partitions on the medium.
			 */
			partition_privatep->location = SLICE;
			partition_privatep->state = NOT_MOUNTABLE;
			free(partition_privatep->labelp->volume_namep);
			partition_privatep->labelp->volume_namep =
				strdup(partition_privatep->volume_namep);
			if (partition_privatep->labelp->volume_namep == NULL) {
				partition_result = PARTITION_OUT_OF_MEMORY;
			}
		} else {
			/*
			 * This is a top level PCFS partition.  It
			 * could be the only top level PCFS partition
			 * on the medium, the first of several, or
			 * one of several but not the first.  If there
			 * are several top level PCFS partitions on the
			 * medium, the create_pcfs_vnodes() method will
			 * create a directory structure to contain them.
			 * Set the partition's PCFS partition number and
			 * the medium's top level PCFS partition counter
			 * so the create_pcfs_vnodes() method will create
			 * the correct directory structure.
			 */
			partition_privatep->devmap_index = 0;
			partition_privatep->location = TOP;
			partition_privatep->partition_number =
				medium_privatep->partition_counts[PCFS];
			medium_privatep->partition_counts[PCFS]++;
			if (partition_privatep->partition_number == 0) {
				/*
				 * This is the first top level PCFS partition
				 * on the medium.  Set the partition's state
				 * to mountable.  Set the medium's first
				 * PCFS partition address attribute to the
				 * address of this partition and increment
				 * the medium's file system type count.
				 */
				partition_privatep->state = MOUNTABLE;
				medium_privatep->first_pcfs_partitionp =
					(partition_handle_t)partition_privatep;
				medium_privatep->number_of_filesystems++;
			} else {
				partition_privatep->state = NOT_MOUNTABLE;
			}
		}
	}
	if (partition_result == PARTITION_SUCCESS) {
		/*
		 * The DOS partition letter isn't used if the partition
		 * is a subpartition, but the create_pcfs_volume()
		 * method expects it to be set anyway.
		 */
		partition_result = set_dos_partition_letter(partition_privatep);
	}
	if ((partition_result != PARTITION_SUCCESS) &&
		(partition_privatep->attributesp != NULL)) {
		free(partition_privatep->attributesp);
	}
dun:
	debug(2, "leaving read_pcfs_partition(), result code = %s\n",
		partition_result_codes[partition_result]);

	return (partition_result);
}

/*
 * Definitions of private methods
 */

static partition_result_t
check_fat(uchar_t *label_bufferp, partition_private_t *partition_privatep)
{
	uchar_t			*fat_bufferp;
	off_t			fat_offset_in_bytes;
	off_t			fat_offset_in_sector;
	off_t			offset_to_fat_sector;
	partition_result_t	partition_result;
	medium_private_t	*medium_privatep;

	fat_bufferp = NULL;
	fat_offset_in_bytes = 0;
	fat_offset_in_sector = 0;
	offset_to_fat_sector = 0;
	partition_result = PARTITION_SUCCESS;
	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;

	fat_bufferp = malloc(DOS_READ_LENGTH);
	if (fat_bufferp == NULL) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	}
	if (partition_result == PARTITION_SUCCESS) {
		fat_offset_in_bytes = ltohs(label_bufferp[PCB_BPSEC]) *
			ltohs(label_bufferp[PCB_RESSEC]);
		offset_to_fat_sector =
			partition_privatep->offset +
			(fat_offset_in_bytes & ~DOS_READ_LENGTH_MASK);
		fat_offset_in_sector =
			fat_offset_in_bytes & DOS_READ_LENGTH_MASK;
		if ((offset_to_fat_sector + DOS_READ_LENGTH) >
		    medium_privatep->medium_capacity) {
			partition_result = PARTITION_CANT_READ_MEDIUM;
		}
		if ((partition_result == PARTITION_SUCCESS) &&
		    lseek(partition_privatep->file_descriptor,
				offset_to_fat_sector, SEEK_SET) !=
				offset_to_fat_sector) {

			partition_result = PARTITION_CANT_READ_MEDIUM;
		}
		if ((partition_result == PARTITION_SUCCESS) &&
			(read(partition_privatep->file_descriptor,
				fat_bufferp,
				DOS_READ_LENGTH) != DOS_READ_LENGTH)) {

			partition_result = PARTITION_CANT_READ_MEDIUM;
		}
		if (partition_result == PARTITION_SUCCESS) {
			if ((fat_bufferp[fat_offset_in_sector] !=
				label_bufferp[PCB_MEDIA]) ||
				(fat_bufferp[fat_offset_in_sector + 1]
					!= (uchar_t)0xff) ||
				(fat_bufferp[fat_offset_in_sector + 2]
					!= (uchar_t)0xff)) {

				partition_result =
					PARTITION_NOT_THIS_TYPE;
			}
		}
	}
	if (fat_bufferp != NULL) {
		free(fat_bufferp);
	}
	return (partition_result);
}

static partition_result_t
check_label(uchar_t *label_bufferp, partition_private_t *partition_privatep)
{

	/*
	 * Look for the identifying jump instructions in the label
	 * buffer.  If they're not there return PARTITION_NOT_THIS_TYPE.
	 * Find the PCFS FAT.  Check for 0Xff characters in the second
	 * and third bytes of the FAT.  If they're not there return
	 * PARTITION_NOT_THIS_TYPE.
	 */

	partition_result_t  partition_result;

	partition_result = PARTITION_SUCCESS;

	if ((*label_bufferp != (uchar_t)DOS_ID1) &&
	    (*label_bufferp != (uchar_t)DOS_ID2a)) {
		partition_result = PARTITION_NOT_THIS_TYPE;
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result =
			check_fat(label_bufferp, partition_privatep);
	}
	return (partition_result);
}

static partition_result_t
create_pcfs_pathnames(partition_private_t *partition_privatep)
{
	pcfs_attributes_t	*attributesp;
	int			block_pathname_length;
	partition_private_t	*first_partition_privatep;
	medium_private_t	*medium_privatep;
	char			*name_bufferp;
	partition_result_t	partition_result;
	int			raw_pathname_length;
	int			type_index;

	attributesp = (pcfs_attributes_t *)partition_privatep->attributesp;
	block_pathname_length = 0;
	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;
	first_partition_privatep = (partition_private_t *)
		medium_privatep->first_pcfs_partitionp;
	name_bufferp = NULL;
	partition_result = PARTITION_SUCCESS;
	raw_pathname_length = 0;
	type_index = (int)partition_privatep->type;

	name_bufferp = malloc(MAXPATHLEN);
	if (name_bufferp == NULL) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	}
	if ((partition_result == PARTITION_SUCCESS) &&
		(partition_privatep->location == TOP) &&
		(partition_privatep->partition_number == 0) &&
		(medium_privatep->partition_counts[type_index] > 1)) {
		/*
		 * This is the first of several top level PCFS partitions
		 * on the medium.  The create_top_level_pcfs_vnodes()
		 * method has already created pathnames for it that end
		 * in its volume name.  Add a slash and the partition's
		 * DOS partition letter to each pathname to distinguish
		 * its pathnames from those of the other top level PCFS
		 * partitions.
		 */
		if (partition_privatep->block_pathnamep != NULL) {
			(void) snprintf(name_bufferp, MAXPATHLEN, "%s/%s",
					partition_privatep->block_pathnamep,
					attributesp->dos_partition_letterp);
			free(partition_privatep->block_pathnamep);
			partition_privatep->block_pathnamep =
				strdup(name_bufferp);
		}
		(void) snprintf(name_bufferp, MAXPATHLEN, "%s/%s",
				partition_privatep->raw_pathnamep,
				attributesp->dos_partition_letterp);
		free(partition_privatep->raw_pathnamep);
		partition_privatep->raw_pathnamep = strdup(name_bufferp);
	}
	if ((partition_result == PARTITION_SUCCESS) &&
		(partition_privatep->location == TOP) &&
		(partition_privatep->partition_number > 0)) {
		/*
		 * This is a top level PCFS partition, but not
		 * the first one on the medium.  Copy the first
		 * top level PCFS  partition's pathnames to this
		 * partition's pathnames, and replace the first
		 * partition's DOS partition letter in the pathnames
		 * with this partition's DOS partition letter.
		 */
		if (first_partition_privatep->block_pathnamep != NULL) {
			block_pathname_length =
				strlen(first_partition_privatep->
					block_pathnamep);
			(void) strncpy(name_bufferp,
					first_partition_privatep->
						block_pathnamep,
					(block_pathname_length - 1));
			name_bufferp[block_pathname_length - 1] = NULLC;
			(void) strcat(name_bufferp,
					attributesp->dos_partition_letterp);
			partition_privatep->block_pathnamep =
					strdup(name_bufferp);
		}
		raw_pathname_length =
			strlen(first_partition_privatep->raw_pathnamep);
		(void) strncpy(name_bufferp,
				first_partition_privatep->raw_pathnamep,
				(raw_pathname_length - 1));
		name_bufferp[raw_pathname_length - 1] = NULLC;
		(void) strcat(name_bufferp,
				attributesp->dos_partition_letterp);
		partition_privatep->raw_pathnamep = strdup(name_bufferp);
	}
	if ((partition_result == PARTITION_SUCCESS) &&
		(partition_privatep->location == SLICE)) {
		/*
		 * This is a PCFS subpartition of a parent partition
		 * (a slice.)  The generic create_pathnames() method
		 * will create the correct pathnames for it.
		 */
		partition_result = create_pathnames(partition_privatep);
	}
	if (partition_privatep->raw_pathnamep == NULL) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	}
	if (name_bufferp != NULL) {
		free(name_bufferp);
	}
	return (partition_result);
}

static partition_result_t
create_pcfs_symlink(partition_private_t *partition_privatep)
{
	/*
	 * Only called for the first top level PCFS partition
	 * on the medium.
	 */
	struct devs		*devicep;
	int			directory_name_length;
	char			*filenamep;
	medium_private_t	*medium_privatep;
	char			*name_bufferp;
	partition_result_t	partition_result;
	char			*pcfs_dirnamep;
	char			*raw_pathnamep;
	int			type_index;

	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;
	devicep = dev_getdp(medium_privatep->in_device);
	directory_name_length = 0;
	filenamep = NULL;
	name_bufferp = NULL;
	partition_result = PARTITION_SUCCESS;
	pcfs_dirnamep = NULL;
	raw_pathnamep = NULL;
	type_index = (int)partition_privatep->type;

	name_bufferp = malloc(MAXPATHLEN + 1);
	if (name_bufferp == NULL) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	}
	if ((partition_result == PARTITION_SUCCESS) &&
		(medium_privatep->partition_counts[type_index] > 1)) {
		/*
		 * There are at least two top level PCFS partitions on
		 * the medium.  Find the pathname of the directory that
		 * contains them.
		 */
		raw_pathnamep = partition_privatep->raw_pathnamep;
		filenamep = find_filenamep(raw_pathnamep);
		directory_name_length = (int)(filenamep - raw_pathnamep) - 1;
		(void) strncpy(name_bufferp,
				raw_pathnamep,
				directory_name_length);
		name_bufferp[directory_name_length] = NULLC;
		pcfs_dirnamep = strdup(name_bufferp);
		if (pcfs_dirnamep == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		}
	}
	if ((partition_result == PARTITION_SUCCESS) &&
		(medium_privatep->partition_counts[type_index] == 1)) {
		/*
		 * There's only one top level PCFS partition on the medium.
		 * Create the symbolic link in the /vol/dev/aliases
		 * directory, give it the symbolic name of the device in
		 * which the medium is inserted, and link it to the raw
		 * vvnode of the partition.
		 */
		partition_privatep->symlink_vvnodep =
			node_symlink(dev_dirpath(ALIAS_DIRECTORY_NAME),
					devicep->dp_symname,
					partition_privatep->raw_pathnamep,
					NODE_TMPID,
					NULL);
		devicep->dp_symvn = partition_privatep->symlink_vvnodep;
	}
	if ((partition_result == PARTITION_SUCCESS) &&
		(medium_privatep->partition_counts[type_index] > 1)) {
		/*
		 * There are at least two top level PCFS partitions on the
		 * medium.  Create the symbolic link in the
		 * /vol/dev/aliases directory, give it the symbolic name
		 * of the device in which the medium is inserted, and link
		 * it to the vnode of the directory containing the top
		 * level PCFS partitions.
		 */
		partition_privatep->symlink_vvnodep =
			node_symlink(dev_dirpath(ALIAS_DIRECTORY_NAME),
					devicep->dp_symname,
					pcfs_dirnamep,
					NODE_TMPID,
					NULL);
		devicep->dp_symvn = partition_privatep->symlink_vvnodep;
	}
	if (name_bufferp != NULL) {
		free(name_bufferp);
	}
	if (pcfs_dirnamep != NULL) {
		free(pcfs_dirnamep);
	}
	return (partition_result);
}

static partition_result_t
create_pcfs_vnodes(partition_private_t *partition_privatep)
{
	/*
	 * NOTE: The file system structure that this method
	 *	 creates is a legacy public interface between
	 *	 the volume manager and user-level applications.
	 *	 Changing it will cause those applications to fail.
	 */
	partition_label_t	*labelp;
	medium_private_t	*medium_privatep;
	partition_private_t	*parent_privatep;
	partition_result_t	partition_result;
	int			type_index;

	debug(2, "entering create_pcfs_vnodes()\n");

	labelp = NULL;
	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;
	parent_privatep = (partition_private_t *)partition_privatep->parentp;
	partition_result = PARTITION_SUCCESS;
	type_index = (int)partition_privatep->type;

	if ((medium_privatep->number_of_filesystems > 1) &&
		(partition_privatep->location == TOP) &&
		(partition_privatep->partition_number == 0) &&
		(partition_privatep->has_volume_name == B_FALSE)) {
		/*
		 * This is the first top level PCFS partition on
		 * the medium, and it doesn't have a volume name.
		 * Give it a volume name that distinguishes it from
		 * the partitions containing other file systems.
		 */
		labelp = partition_privatep->labelp;
		free(labelp->volume_namep);
		labelp->volume_namep = strdup(UNNAMED_PCFS);
		if (labelp->volume_namep == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		}
	}
	if ((partition_result == PARTITION_SUCCESS) &&
		(partition_privatep->location == TOP) &&
		(partition_privatep->partition_number == 0)) {
		/*
		 * This is the first top level PCFS partition on the
		 * medium.  Create  top level vnodes for it.  If there
		 * are several top level PCFS partitions on the medium
		 * the convert_vnodes_to_parent_vnodes() and
		 * create_slice_vvnodes() methods will create a
		 * directory structure for them.
		 */
		partition_result =
			create_top_level_pcfs_vnodes(partition_privatep);
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = create_pcfs_pathnames(partition_privatep);
	}
	if ((partition_result == PARTITION_SUCCESS) &&
		((partition_privatep->location == SLICE) ||
		(partition_privatep->partition_number > 0)))	{
		/*
		 * This isn't the first top level PCFS partition on
		 * the medium.  The create_top_level_pcfs_vnodes()
		 * method has already created a volume object for
		 * that partition.
		 */
		partition_result = create_pcfs_volume(partition_privatep);
	}
	/*
	 * If the partition is one of several top level PCFS partitions
	 * on the medium, or if it is a slice, find or create its parent
	 * vnodes and add slice vnodes for the partition to the parent
	 * vnodes.
	 */
	if ((partition_result == PARTITION_SUCCESS) &&
		(partition_privatep->location == TOP) &&
		(partition_privatep->partition_number == 0) &&
		(medium_privatep->partition_counts[type_index] > 1)) {
		/*
		 * This is the first of several top level PCFS
		 * partitions on the medium.  Convert its vnodes
		 * into directory vnodes and make them its parent
		 * vnodes.  The create_pcfs_pathnames(),
		 * create_pcfs_volume(), and create_slice_vvnodes()
		 * methods attach slice vnodes for all the top
		 * level PCFS partitions, including the first one,
		 * to the parent vnodes.
		 */
		convert_vnodes_to_parent_vnodes(partition_privatep);
	}
	if ((partition_result == PARTITION_SUCCESS) &&
		(partition_privatep->location == TOP) &&
		(partition_privatep->partition_number > 0)) {
		/*
		 * This is one of several top level PCFS partitions
		 * on the medium, but not the first.  Find the
		 * parent vvnodes created for the first top level
		 * PCFS partition and write their addresses to the
		 * partition's parent vvnode address attributes.
		 */
		find_parent_pcfs_vvnodes(partition_privatep);
	}
	if ((partition_result == PARTITION_SUCCESS) &&
		(partition_privatep->location == SLICE)) {
		/*
		 * This partition is a subpartition of another
		 * partition, and its parent vvnodes are that
		 * partition's vvnodes.
		 */
		partition_privatep->parent_global_block_vvnodep =
			parent_privatep->global_block_vvnodep;
		partition_privatep->parent_global_raw_vvnodep =
			parent_privatep->global_raw_vvnodep;
		partition_privatep->parent_block_vvnodep =
			parent_privatep->block_vvnodep;
		partition_privatep->parent_raw_vvnodep =
			parent_privatep->raw_vvnodep;
	}
	if ((partition_result == PARTITION_SUCCESS) &&
		((partition_privatep->location == SLICE) ||
			(medium_privatep->partition_counts[type_index] > 1))) {
		/*
		 * This partition is either a subpartition of another
		 * partition or it's one of several top level PCFS
		 * partitions on the medium.  Create slice vvnodes for
		 * it beneath its parent vvnodes.
		 */
		partition_result = create_slice_vvnodes(partition_privatep);
	}
	if (partition_result == PARTITION_SUCCESS) {
		correct_pathnames(partition_privatep);
	}
	if ((partition_result == PARTITION_SUCCESS) &&
		(partition_privatep->location == TOP) &&
		(partition_privatep->partition_number == 0)) {
		/*
		 * Only create a symlink to the first top level PCFS
		 * partition on the medium.
		 */
		partition_result = create_pcfs_symlink(partition_privatep);
	}

	debug(2, "leaving create_pcfs_vnodes(), result code = %s\n",
		partition_result_codes[partition_result]);

	return (partition_result);
}

static partition_result_t
create_pcfs_volume(partition_private_t *partition_privatep)
{
	pcfs_attributes_t	*attributesp;
	partition_result_t	partition_result;

	attributesp = (pcfs_attributes_t *)partition_privatep->attributesp;

	partition_result = create_volume(partition_privatep);

	if (partition_result == PARTITION_SUCCESS) {
		partition_privatep->volumep->v_pcfs_part_id[0] =
			attributesp->dos_partition_letterp[0];
		partition_privatep->volumep->v_pcfs_part_id[1] = NULLC;
	}
	return (partition_result);
}

static partition_result_t
create_top_level_pcfs_vnodes(partition_private_t *partition_privatep)
{
	/*
	 * Only called for the first top level PCFS partition
	 * on the medium.
	 */
	medium_private_t		*medium_privatep;
	partition_private_t		*parent_privatep;
	partition_result_t		partition_result;

	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;
	parent_privatep = (partition_private_t *)partition_privatep->parentp;
	partition_result = PARTITION_SUCCESS;

	partition_result = create_pathnames(partition_privatep);
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = create_pcfs_volume(partition_privatep);
	}
	if (partition_result == PARTITION_SUCCESS) {
		if (parent_privatep != NULL) {
			/*
			 * This partition has a parent fdisk partition.
			 * Its parent vvnodes are the fdisk partition's
			 * vvnodes.
			 */
			partition_privatep->parent_block_vvnodep =
				parent_privatep->block_vvnodep;
			partition_privatep->parent_raw_vvnodep =
				parent_privatep->raw_vvnodep;
		} else {
			/*
			 * This is the only partition on the
			 * medium.  Its parent vvnodes are
			 * the medium's vvnodes.
			 */
			partition_privatep->parent_block_vvnodep =
				medium_privatep->block_vvnodep;
			partition_privatep->parent_raw_vvnodep =
				medium_privatep->raw_vvnodep;
		}
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = create_top_level_vvnodes(partition_privatep);
	}
	return (partition_result);
}

static partition_result_t
dir_entry_to_volname(struct pcdir *dir_entryp, char **volume_namepp)
{
	int			dest_index;
	partition_result_t	partition_result;
	int			source_index;
	int			test_char;
	char			*volume_namep;

	dest_index = 0;
	partition_result = PARTITION_SUCCESS;
	source_index = 0;
	test_char = (int)NULLC;
	volume_namep = NULL;

	volume_namep = malloc(PCFNAMESIZE + PCFEXTSIZE + 1);
	if (volume_namep == NULL) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	}
	if (partition_result == PARTITION_SUCCESS) {
		source_index = 0;
		dest_index = 0;
		test_char =
			dos_label_char(dir_entryp->pcd_filename[source_index]);
		while ((test_char != (int)NULLC) &&
			(source_index < PCFNAMESIZE)) {
			volume_namep[dest_index] = (char)test_char;
			dest_index++;
			source_index++;
			test_char =
				dos_label_char(
					dir_entryp->pcd_filename[source_index]);
		}
		source_index = 0;
		test_char = dos_label_char(dir_entryp->pcd_ext[source_index]);
		while ((test_char != (int)NULLC) &&
			(source_index < PCFEXTSIZE)) {
			volume_namep[dest_index] = (char)test_char;
			dest_index++;
			source_index++;
			test_char =
				dos_label_char(
					dir_entryp->pcd_ext[source_index]);
		}
		/*
		 * Reset the destination string index to the last character
		 * in the volume name string, and strip off any trailing
		 * underscore characters that might have been added by
		 * dos_label_char().
		 */
		dest_index--;
		while ((dest_index >= 0) && (volume_namep[dest_index] == '_')) {
			dest_index--;
		}
		dest_index++;
		volume_namep[dest_index] = NULLC;
	}
	*volume_namepp = volume_namep;
	return (partition_result);
}

static bool_t
dos_filename_char(char  c)
{
	/*
	 * copied from pc_validchar() in the kernel
	 *
	 * isdigit(), isupper(), ..., aren't used because they're
	 * character-set-dependent, but DOS isn't
	 */

	static char valid_chars[] = {
		"$#&@!%()-{}<>`_\\^~|'"
	};

	char	*charp;
	bool_t  is_valid;

	/*
	 * Should be "$#&@!%()-{}`_^~' " ??
	 * From experiment in DOSWindows, "*+=|\[];:\",<>.?/" are illegal.
	 * See IBM DOS4.0 Tech Ref. B-57.
	 */

	charp = valid_chars;
	is_valid = FALSE;
	if ((c >= 'A') && (c <= 'Z')) {
		is_valid = TRUE;
	} else if ((c >= '0') && (c <= '9')) {
		is_valid = TRUE;
	} else {
		charp = valid_chars;
		while ((*charp != NULLC) && (is_valid == FALSE)) {
			if (c == *charp) {
				is_valid = TRUE;
			}
			charp++;
		}
	}
	return (is_valid);
}

static int
dos_label_char(int c)
{
	int return_char;

	return_char = NULLC;

	if (isalnum(c)) {
		return_char = c;
	} else if (isspace(c)) {
		return_char = '_';
	} else {
		switch (c) {
		case '.':
		case '_':
		case '+':
			return_char = c;
			break;
		default:
			return_char = NULLC;
		}
	}
	return (return_char);
}

static void
find_parent_pcfs_vvnodes(partition_private_t *partition_privatep)
{
	/*
	 * Set the partition's parent vvnode address attributes
	 * to the parent vvnode addresses of the first PCFS
	 * partition on the medium.
	 */
	partition_private_t	*first_pcfs_partition_privatep;
	medium_private_t	*medium_privatep;

	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;
	first_pcfs_partition_privatep =
		(partition_private_t *)medium_privatep->first_pcfs_partitionp;

	partition_privatep->parent_global_block_vvnodep =
		first_pcfs_partition_privatep->parent_global_block_vvnodep;
	partition_privatep->parent_global_raw_vvnodep =
		first_pcfs_partition_privatep->parent_global_raw_vvnodep;
	partition_privatep->parent_block_vvnodep =
		first_pcfs_partition_privatep->parent_block_vvnodep;
	partition_privatep->parent_raw_vvnodep =
		first_pcfs_partition_privatep->parent_raw_vvnodep;
}

static partition_result_t
get_label(partition_private_t *partition_privatep)
{
	uchar_t			*label_bufferp;
	partition_result_t	partition_result;
	medium_private_t	*medium_privatep;

	label_bufferp = NULL;
	partition_result = PARTITION_SUCCESS;
	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;

	label_bufferp = malloc(DOS_READ_LENGTH);
	if (label_bufferp == NULL) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	}
	if (partition_result == PARTITION_SUCCESS &&
	    (partition_privatep->offset + DOS_READ_LENGTH) >
	    medium_privatep->medium_capacity) {
		partition_result = PARTITION_CANT_READ_MEDIUM;
	}
	if ((partition_result == PARTITION_SUCCESS) &&
	    lseek(partition_privatep->file_descriptor,
			partition_privatep->offset,
			SEEK_SET) != partition_privatep->offset) {
		partition_result = PARTITION_CANT_READ_MEDIUM;
	}
	if ((partition_result == PARTITION_SUCCESS) &&
	    (read(partition_privatep->file_descriptor,
			label_bufferp,
			DOS_READ_LENGTH) != DOS_READ_LENGTH))  {
		partition_result = PARTITION_CANT_READ_MEDIUM;
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = check_label(label_bufferp,
						partition_privatep);
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = read_label(label_bufferp,
						partition_privatep);
	}
	if (label_bufferp != NULL) {
		free(label_bufferp);
	}
	return (partition_result);
}


static partition_result_t
get_volume_name(uchar_t *label_bufferp,
			partition_private_t *partition_privatep)
{

	char			*name_bufferp;
	partition_result_t	partition_result;

	name_bufferp = NULL;
	partition_result = PARTITION_SUCCESS;

	if (dos_filename_char((char)label_bufferp[DOS_NAME_OFFSET])) {
		partition_result = get_volume_name_from_label(label_bufferp,
							partition_privatep);
	} else {
		partition_result =
			get_volume_name_from_rootdir(label_bufferp,
							partition_privatep);
	}
	if ((partition_result == PARTITION_SUCCESS) &&
		(partition_privatep->labelp->volume_namep != NULL)) {

		partition_privatep->has_volume_name = B_TRUE;

	} else if (partition_result == PARTITION_SUCCESS) {

		partition_privatep->has_volume_name = B_FALSE;
		name_bufferp = malloc(MAXNAMELEN);
		if (name_bufferp == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		} else {
			snprintf(name_bufferp, MAXNAMELEN, "%s%s",
				UNNAMED_PREFIX,
				partition_privatep->medium_typep);
			partition_privatep->labelp->volume_namep =
				strdup(name_bufferp);
			if (partition_privatep->labelp->volume_namep == NULL) {
				partition_result = PARTITION_OUT_OF_MEMORY;
			}
		}
	}
	if (name_bufferp != NULL) {
		free(name_bufferp);
	}
	return (partition_result);
}

static partition_result_t
get_volume_name_from_label(uchar_t *label_bufferp,
			partition_private_t *partition_privatep)
{
	partition_result_t	partition_result;
	char			*volume_namep;
	int			buffer_offset;
	char			test_char;

	partition_result = PARTITION_SUCCESS;
	volume_namep = NULL;

	buffer_offset = DOS_NAME_OFFSET;
	test_char = (char)dos_label_char((char)label_bufferp[buffer_offset]);
	while ((buffer_offset < (DOS_NAME_OFFSET + PCFNAMESIZE + PCFEXTSIZE)) &&
	    (test_char != NULLC)) {
		buffer_offset++;
		test_char = (char)dos_label_char(label_bufferp[buffer_offset]);
	}
	if (buffer_offset == (DOS_NAME_OFFSET + PCFNAMESIZE + PCFEXTSIZE)) {
		/*
		 * Set the buffer offset back to the last character in the
		 * label.
		 */
		buffer_offset--;
	}
	while (((char)label_bufferp[buffer_offset] == '-') &&
		(buffer_offset >= DOS_NAME_OFFSET)) {
		buffer_offset--;
	}
	if (buffer_offset >= DOS_NAME_OFFSET) {
		volume_namep = malloc(buffer_offset - DOS_NAME_OFFSET + 2);
		if (volume_namep == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		} else {
			(void) strncpy(volume_namep,
				(char *)&label_bufferp[DOS_NAME_OFFSET],
				(buffer_offset - DOS_NAME_OFFSET + 1));
			volume_namep[buffer_offset - DOS_NAME_OFFSET + 1] =
				NULLC;
		}
	}
	if (volume_namep != NULL) {
		partition_privatep->labelp->volume_namep =
			makename(volume_namep, strlen(volume_namep));
		free(volume_namep);
		if (partition_privatep->labelp->volume_namep == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		}
	}
	return (partition_result);
}

static partition_result_t
get_volume_name_from_rootdir(uchar_t *label_bufferp,
			partition_private_t *partition_privatep)
{
	ushort_t		dir_index;
	struct pcdir		*dir_list;
	ushort_t		num_entries;
	size_t			dir_size;
	partition_result_t	partition_result;
	ushort_t		root_sector;
	ushort_t		sector_size;
	off_t			offset;
	char			*volume_namep;
	medium_private_t	*medium_privatep;

	dir_index = 0;
	dir_list = NULL;
	num_entries = ltohs(label_bufferp[PCB_NROOTENT]);
	dir_size = (size_t)(num_entries * sizeof (struct pcdir));
	partition_result = PARTITION_SUCCESS;
	root_sector = ltohs(label_bufferp[PCB_RESSEC]) +
		((ushort_t)label_bufferp[PCB_NFAT] *
		ltohs(label_bufferp[PCB_SPF]));
	sector_size = ltohs(label_bufferp[PCB_BPSEC]);
	offset = (off_t)partition_privatep->offset +
			(off_t)(root_sector * sector_size);
	volume_namep = NULL;
	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;

	dir_list = malloc(dir_size);
	if (dir_list == NULL) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	}
	if (partition_result == PARTITION_SUCCESS) {
		if ((offset + dir_size) > medium_privatep->medium_capacity) {
			partition_result = PARTITION_CANT_READ_MEDIUM;
		}
	}
	if (partition_result == PARTITION_SUCCESS) {
		if (lseek(partition_privatep->file_descriptor,
			offset,
			SEEK_SET) < 0) {
			partition_result = PARTITION_CANT_READ_MEDIUM;
		}
	}
	if (partition_result == PARTITION_SUCCESS) {
		if (read(partition_privatep->file_descriptor,
			(void *)dir_list,
			dir_size) != dir_size) {
			partition_result = PARTITION_CANT_READ_MEDIUM;
		}
	}
	if (partition_result == PARTITION_SUCCESS) {
		dir_index = 0;
		volume_namep = NULL;
		while ((volume_namep == NULL) &&
			(dir_list[dir_index].pcd_filename[0] != PCD_UNUSED) &&
			(dir_index < num_entries)) {

			if ((dir_list[dir_index].pcd_filename[0] !=
				PCD_ERASED) &&
			((dir_list[dir_index].pcd_attr & PCDL_LFN_BITS) !=
				PCDL_LFN_BITS) &&
			((dir_list[dir_index].pcd_attr & PCA_LABEL) != 0)) {

				partition_result =
					dir_entry_to_volname(
						&(dir_list[dir_index]),
						&volume_namep);
			}
			dir_index++;
		}
	}
	if ((volume_namep != NULL) && (volume_namep[0] != NULLC)) {
		partition_privatep->labelp->volume_namep =
			makename(volume_namep, strlen(volume_namep));
		free(volume_namep);
		if (partition_privatep->labelp->volume_namep == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		}
	}
	if (dir_list != NULL) {
		free(dir_list);
	}
	return (partition_result);
}

static partition_result_t
read_label(uchar_t *label_bufferp, partition_private_t *partition_privatep)
{
	char			*key_bufferp;
	partition_result_t	partition_result;

	key_bufferp = NULL;
	partition_result = PARTITION_SUCCESS;

	key_bufferp = malloc(KEY_BUFFER_LENGTH);
	if (key_bufferp == NULL) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = create_label(&(partition_privatep->labelp));
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_privatep->labelp->crc =
			calc_crc(label_bufferp, DOS_LABLEN);
		(void) snprintf(key_bufferp, KEY_BUFFER_LENGTH, "0x%lx",
				partition_privatep->labelp->crc);
		partition_privatep->labelp->keyp = strdup(key_bufferp);
		if (partition_privatep->labelp->keyp == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		}
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = get_volume_name(label_bufferp,
						partition_privatep);
	}
	if (partition_result != PARTITION_SUCCESS) {
		destroy_label(&(partition_privatep->labelp));
	}
	if (key_bufferp != NULL) {
		free(key_bufferp);
	}
	return (partition_result);
}

static partition_result_t
set_dos_partition_letter(partition_private_t *partition_privatep)
{
	static const char dos_partition_letters[] =
	{
		'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
		'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
	};

	partition_result_t	partition_result;
	pcfs_attributes_t	*attributesp;

	attributesp = (pcfs_attributes_t *)partition_privatep->attributesp;
	partition_result = PARTITION_SUCCESS;

	if (partition_privatep->partition_number > 23) {
		partition_result = PARTITION_TOO_MANY_PARTITIONS;
	} else {
		attributesp->dos_partition_letterp[0] =
			dos_partition_letters[
				partition_privatep->partition_number];
		attributesp->dos_partition_letterp[1] = NULLC;
	}
	return (partition_result);
}
