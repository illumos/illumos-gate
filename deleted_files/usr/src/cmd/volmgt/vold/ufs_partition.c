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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * UFS partition class implementation file
 */

/*
 * System include files
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <sys/fs/ufs_fs.h>

/*
 * Local include files
 */

#include "medium.h"
#include "partition.h"

/*
 * Private attribute and method declarations
 */

#include "partition_private.h"

/*
 * Private method declarations
 */

static partition_result_t
create_ufs_vnodes(partition_private_t *partition_privatep);

static partition_result_t
get_label(partition_private_t *partition_privatep);

static partition_result_t
read_label(struct fs *file_system_structp,
	partition_private_t *partition_privatep);

/*
 * Methods that implement abstract methods
 * declared in the parent partition class
 */

static partition_methods_t  partition_methods =
	{create_ufs_vnodes, read_ufs_partition};

/*
 * Definition of the public read_partition() method that
 * identifies the partition type and sets its attributes
 */

partition_result_t
read_ufs_partition(partition_private_t *partition_privatep)
{
	medium_private_t	*medium_privatep;
	partition_private_t	*parent_privatep;
	partition_result_t	partition_result;

	debug(2, "entering read_ufs_partition()\n");

	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;
	parent_privatep = (partition_private_t *)partition_privatep->parentp;

	partition_result = get_label(partition_privatep);

	if (partition_result == PARTITION_SUCCESS) {
		partition_privatep->attributesp = NULL;
		partition_privatep->methodsp = &partition_methods;
		partition_privatep->number_of_slices = ONE_SLICE;
#ifdef i386
		partition_privatep->partition_mask =
			DEFAULT_INTEL_PARTITION_MASK;
#else
		partition_privatep->partition_mask =
			DEFAULT_SPARC_PARTITION_MASK;
#endif
		partition_privatep->type = UFS;
		if ((parent_privatep != NULL) &&
			(parent_privatep->type != FDISK)) {
			/*
			 * The partition is a subpartition of a parent
			 * partition (a slice.) The read_slices() method
			 * has already assigned the partition a devmap
			 * index, partition number, and volume name.
			 * Transfer the volume name to the partition's
			 * label.
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
			 * This is a top level partition, either standalone
			 * or inside an fdisk table.  Set the devmap_index
			 * to point to the first entry in the volume's devmap,
			 * which is the entry for the partition that starts at
			 * the first data block and includes the entire medium.
			 * Set the partition's top level partition number.
			 * Preseve the volume name on the partition's label.
			 */
			partition_privatep->devmap_index = 0;
			partition_privatep->location = TOP;
			partition_privatep->state = MOUNTABLE;
			medium_privatep->partition_counts[UFS]++;
			medium_privatep->number_of_filesystems++;
		}
	}
	debug(2, "leaving read_ufs_partition(), result code = %s\n",
		partition_result_codes[partition_result]);

	return (partition_result);
}

/*
 * Definitions of private methods
 */

static partition_result_t
create_ufs_vnodes(partition_private_t *partition_privatep)
{
	partition_result_t	partition_result;

	debug(2, "entering create_ufs_vnodes()\n");

	partition_result = create_pathnames(partition_privatep);
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = create_volume(partition_privatep);
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = create_vvnodes(partition_privatep);
	}
	if (partition_result == PARTITION_SUCCESS) {
		correct_pathnames(partition_privatep);
	}
	if ((partition_result == PARTITION_SUCCESS) &&
	    (partition_privatep->location == TOP)) {
		partition_result = create_symlink(partition_privatep);
	}

	debug(2, "leaving create_ufs_vnodes(), result code = %s\n",
		partition_result_codes[partition_result]);

	return (partition_result);
}

static partition_result_t
get_label(partition_private_t *partition_privatep)
{
	struct fs		*file_system_structp;
	off_t			offset;
	partition_result_t	partition_result;
	void 			*super_blockp;
	medium_private_t	*medium_privatep;

	partition_result = PARTITION_SUCCESS;
	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;

	file_system_structp = malloc(sizeof (struct fs));
	super_blockp = malloc(SBSIZE);
	if ((file_system_structp == NULL) || (super_blockp == NULL)) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	}
	offset = partition_privatep->offset + SBOFF;
	if (partition_result == PARTITION_SUCCESS) {
		if ((offset + SBSIZE) > medium_privatep->medium_capacity) {
			partition_result = PARTITION_CANT_READ_MEDIUM;
		}
	}
	if (partition_result == PARTITION_SUCCESS) {
		if (lseek(partition_privatep->file_descriptor,
				offset,
				SEEK_SET) != offset) {
			partition_result = PARTITION_CANT_READ_MEDIUM;
		}
	}
	if ((partition_result == PARTITION_SUCCESS) &&
	    (read(partition_privatep->file_descriptor,
	    super_blockp, SBSIZE) != SBSIZE))  {
		partition_result = PARTITION_CANT_READ_MEDIUM;
	} else {
		(void) memcpy(file_system_structp, super_blockp,
				sizeof (struct fs));
	}
	if (partition_result == PARTITION_SUCCESS &&
	    file_system_structp->fs_magic != FS_MAGIC &&
	    file_system_structp->fs_magic != MTB_UFS_MAGIC) {
		partition_result = PARTITION_NOT_THIS_TYPE;
	}
	if (partition_result == PARTITION_SUCCESS &&
	    file_system_structp->fs_magic == FS_MAGIC &&
	    file_system_structp->fs_version != UFS_EFISTYLE4NONEFI_VERSION_2 &&
	    file_system_structp->fs_version != UFS_VERSION_MIN) {
		partition_result = PARTITION_NOT_THIS_TYPE;
	}
	if (partition_result == PARTITION_SUCCESS &&
	    file_system_structp->fs_magic == MTB_UFS_MAGIC &&
	    (file_system_structp->fs_version > MTB_UFS_VERSION_1 ||
	    file_system_structp->fs_version < MTB_UFS_VERSION_MIN)) {
		partition_result = PARTITION_NOT_THIS_TYPE;
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = create_label(&(partition_privatep->labelp));
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = read_label(file_system_structp,
						partition_privatep);
	}
	if (partition_result != PARTITION_SUCCESS) {
		destroy_label(&(partition_privatep->labelp));
	}
	if (file_system_structp != NULL) {
		free(file_system_structp);
	}
	if (super_blockp != NULL) {
		free(super_blockp);
	}
	return (partition_result);
}


static partition_result_t
read_label(struct fs *file_system_structp,
	partition_private_t *partition_privatep)
{
	char			*key_bufferp;
	char			*name_bufferp;
	partition_result_t	partition_result;

	partition_result = PARTITION_SUCCESS;
	key_bufferp = malloc(KEY_BUFFER_LENGTH);
	name_bufferp = malloc(MAXNAMELEN);
	if ((key_bufferp == NULL) || (name_bufferp == NULL)) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_privatep->labelp->crc =
			calc_crc((uchar_t *)file_system_structp,
				sizeof (struct fs));
		(void) snprintf(key_bufferp, KEY_BUFFER_LENGTH, "0x%lx",
				partition_privatep->labelp->crc);
		partition_privatep->labelp->keyp = strdup(key_bufferp);
		if (partition_privatep->labelp->keyp == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		}
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_privatep->has_volume_name = B_FALSE;
		(void) snprintf(name_bufferp, MAXNAMELEN, "%s%s",
			UNNAMED_PREFIX,
			partition_privatep->medium_typep);
		partition_privatep->labelp->volume_namep = strdup(name_bufferp);
		if (partition_privatep->labelp->volume_namep == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		}
	}
	if (key_bufferp != NULL) {
		free(key_bufferp);
	}
	if (name_bufferp != NULL) {
		free(name_bufferp);
	}
	return (partition_result);
}
