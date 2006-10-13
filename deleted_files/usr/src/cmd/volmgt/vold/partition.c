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
 * Partition class implementation file.
 */

/*
 * System include files
 */

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <thread.h>
#include <unistd.h>

/*
 * Local include files
 */

#include "partition.h"

/*
 * A medium can have a single partition, or a nested structure of
 * partitions of varying types.  The medium's top level partition
 * can be a DOS partition containing a PCFS file system, an fdisk
 * partition containing a table that gives the types and locations
 * of other partitions on the medium, a Solaris partition containing
 * a volume table of contents (VTOC), that gives the locations and
 * sizes of the Solaris slices located on the medium, an HSFS
 * partition, a UDF partition, or a DVD video partition.  The
 * headers of most partition types can contain descriptions of
 * the types and locations of other partitions on the medium.
 * A medium can therefore contain multiple partitions of differing
 * types.
 *
 * The methods in this class implementation file read removable
 * media and create models of their partition structures.  The
 * models have tree structures of the form shown below.
 *
 *     -----------------------
 *     |                     |
 *     | Top Level Partition |
 *     |                     |
 *     -----------------------
 *                ^   ^
 *                |   |
 *                |   ---------------------------
 *                V                             |
 *     ------------------------    ---------------------------
 *     |                      |    |                         |
 *     | Left Child Partition |<-->| Right Sibling Partition |<-->....
 *     |                      |    |                         |
 *     ------------------------    ---------------------------
 *                ^                             ^
 *                |                             |
 *                |                             |
 *                V                             V
 *                .                             .
 *                .                             .
 *
 * In the diagram above, the arrows indicate connections between
 * parent partition objects and child partition objects and
 * connections between sibling partition objects.  Parent object
 * private data structures contain handles for their leftmost
 * children, sibling object private data structures contain
 * handles for their left and right siblings, and child object
 * private data structures contain handles for their parent objects.
 *
 * The public create_top_partition() method creates a single empty
 * partition object that models the entire medium.  It then
 * calls the read_partition() method, which calls all the
 * descendant class read_partition() methods in turn to try
 * to read the description of the partition from the medium
 * into the empty partition object.  If the medium's top
 * level partition contains subpartitions, its read_partition()
 * method creates a nested structure of partition objects of
 * the appropriate types and calls the appropriate
 * read_partition() method for each partition to read the
 * description of the partition into the partition object that
 * corresponds to it.
 */

/*
 * Private attribute and method declarations
 */

/*
 * The partition_private.h include file defines the
 * partition_private_t data type and declares private partition
 * methods used by descendant partition classes of specialized
 * types, such as the fdisk_partition class.  The C source
 * files for the specialized descendant partition types also
 * include it so their private methods can write to private
 * partition data structures and call the private partition
 * methods when manipulating nested partition structures
 * containing different partition types.
 *
 * Using private include files to hide type definitions and
 * method declarations from clients but make them visible to
 * private methods located in separate source files provides a
 * mechanism for inheritance of abstract methods that are
 * implemented differently in different descendant classes of a
 * parent class.  In this case the parent class is the partition
 * class, and the descendant classes are the classes that define
 * the various types of partition objects, such as fdisk partition
 * objects, PCFS partition objects, Solaris partition objects,
 * UFS partition objects, HSFS partition objects, UDF partition
 * objects, HSFS audio partition objects, DVD video partition
 * objects, and other types of partition objects that may be
 * specified in later versions of the software.
 */

#include "partition_private.h"
#include "vtoc.h"

#define	START_OF_MEDIUM			(off_t)0L
#define	PASSWORD_PROTECTED_NAME		"password_protected"

/*
 * The volfs_t types in the file_system_types[] array below MUST
 * match the partition types in the typedef enum partition_type_t
 * in partition_private.h
 */

static const volfs_t file_system_types [] = {
	V_FDISK,
	V_HSFS,
	V_PCFS,
	V_SOLARIS,
	V_UDFS,
	V_UFS,
	V_UNKNOWN
};

/*
 * The strings in the permission_codes[] array below MUST match
 * the permission types defined in typedef enum permissions_t
 * in medium_private.h
 */

static const char *permission_codes[] = {
	"pp",	/* password protected */
	"pw",	/* password write protected */
	"ro",	/* read only */
	"rw"	/* read write */
};

/*
 * Names of the slices in a Solaris or HSFS VTOC
 */

static const char *slice_names[] = {
	"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
	"s8", "s9", "s10", "s11", "s12", "s13", "s14", "s15"
};

/*
 * Declarations of private methods
 */

static void partition_destroy_volume(partition_private_t *);
static partition_result_t create_slice_object(vol_t *, char *, obj_t **);
static partition_result_t create_right_sibling_partition
		(partition_handle_t, partition_handle_t *);
static partition_result_t find_vvnode_in_db(partition_private_t *, vvnode_t **);
static partition_handle_t get_rightmost_child(partition_private_t *);
static partition_result_t read_slice_partition(partition_private_t *);

/*
 * Definitions of public methods
 */

partition_result_t
create_top_partition(medium_handle_t		on_mediump,
			partition_handle_t	*top_partitionpp)
{
	medium_private_t	*medium_privatep;
	partition_private_t 	*partition_privatep;
	partition_result_t	partition_result;
	partition_handle_t	top_partitionp;

	debug(2, "entering create_top_partition()\n");

	if ((on_mediump == NULL) || (top_partitionpp == NULL)) {
		partition_result = PARTITION_BAD_INPUT_PARAMETER;
	} else {
		partition_result = create_empty_partition(&top_partitionp);
	}
	if (partition_result == PARTITION_SUCCESS) {
		medium_privatep =
			(medium_private_t *)on_mediump;
		partition_privatep =
			(partition_private_t *)top_partitionp;
		partition_privatep->file_descriptor =
			medium_privatep->file_descriptor;
		partition_privatep->gid =
			medium_privatep->gid;
		partition_privatep->left_childp = NULL;
		partition_privatep->left_siblingp = NULL;

		debug(8, "create_top_partition(): setting medium_typep\n");

		partition_privatep->medium_typep =
			strdup(medium_privatep->medium_typep);
		if (partition_privatep->medium_typep == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		}
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_privatep->mode = medium_privatep->mode;
		partition_privatep->on_mediump = on_mediump;
		partition_privatep->parentp = NULL;
		partition_privatep->permissions = medium_privatep->permissions;
		partition_privatep->right_siblingp = NULL;
		partition_privatep->uid = medium_privatep->uid;
		partition_privatep->offset = START_OF_MEDIUM;

		debug(8, "create_top_partition(): checking permissions\n");

		if (partition_privatep->permissions == PASSWORD_PROTECTED) {
			partition_privatep->type = UNKNOWN;
			partition_result =
				read_blank_partition(partition_privatep);
			if (partition_result == PARTITION_SUCCESS) {
				free(partition_privatep->labelp->volume_namep);
				partition_privatep->labelp->volume_namep =
					strdup(PASSWORD_PROTECTED_NAME);
				if (partition_privatep->labelp->volume_namep ==
					NULL) {
					partition_result =
						PARTITION_OUT_OF_MEMORY;
				}
			}
		} else {
			partition_result = read_partition(partition_privatep);
		}
	}
	*top_partitionpp = top_partitionp;

	debug(2, "leaving create_top_partition(), result code = %s\n",
		partition_result_codes[partition_result]);

	return (partition_result);
}

void
destroy_partition(partition_handle_t *partitionpp)
{
	/*
	 * NOTE: This method is recursive.  It calls itself to
	 *	 destroy all the children of the partition it is
	 *	 destroying before destroying the partition itself.
	 *	 It does NOT destroy the volume object associated
	 *	 with the partition, since that volume object is
	 *	 also associated with other objects.
	 */

	partition_private_t 	*child_privatep;
	partition_handle_t	current_childp;
	partition_handle_t	next_childp;
	partition_result_t	partition_result;
	partition_private_t 	*partition_privatep;

	debug(2, "entering destroy_partition()\n");

	partition_result = PARTITION_SUCCESS;
	if (partitionpp == NULL) {
		partition_result = PARTITION_BAD_INPUT_PARAMETER;
	} else {
		partition_privatep = (partition_private_t *)*partitionpp;
		if (partition_privatep == NULL) {
			partition_result = PARTITION_BAD_INPUT_PARAMETER;
		}
	}
	if (partition_result == PARTITION_SUCCESS) {
		current_childp = partition_privatep->left_childp;
		while (current_childp != NULL) {
			child_privatep = (partition_private_t *)current_childp;
			next_childp = child_privatep->right_siblingp;
			destroy_partition(&current_childp);
			current_childp = next_childp;
		}
		if (partition_privatep->medium_typep != NULL) {
			free(partition_privatep->medium_typep);
		}
		if (partition_privatep->attributesp != NULL) {
			free(partition_privatep->attributesp);
		}
		destroy_label(&(partition_privatep->labelp));
		if (partition_privatep->volume_namep != NULL) {
			free(partition_privatep->volume_namep);
		}
		destroy_pathnames(partition_privatep);
		if (partition_privatep->location != TOP) {
			/*
			 * If the medium has been reformatted,
			 * the volume object corresponding to the
			 * medium's top partition has been removed
			 * from the database and destroyed.  If the
			 * medium has been ejected, the volume object
			 * corresponding to its top partition must be
			 * preserved so it can be found in the database
			 * if the medium is reinserted.
			 */
			partition_destroy_volume(partition_privatep);

		} else if ((partition_privatep->type == PCFS) &&
			(partition_privatep->partition_number != 0)) {
			/*
			 * All PCFS partitions described in top level
			 * fdisk tables are top level partitions, but
			 * only the volume object corresponding to the
			 * first PCFS partition must be preserved when
			 * the medium is ejected, because that's the
			 * only volume object in the database.
			 */
			partition_destroy_volume(partition_privatep);
		}
		free(*partitionpp);
		*partitionpp = NULL;
	}

	debug(2, "leaving destroy_partition(), result code = %s\n",
		partition_result_codes[partition_result]);
}

partition_result_t
mount_partition(partition_handle_t  partitionp)
{
	/*
	 * NOTE: This method is recursive.  It calls itself to
	 *	 mount all the children of the partition it is
	 *	 mounting before mounting the partition itself.
	 *
	 * This method mounts the partition by adding an async_task
	 * structure with its act field set to INSERT to the
	 * volume manager daemon's event handling queue.  It
	 * includes a vol_t object containing all the mount
	 * parameters in the async_task object.
	 *
	 * Later versions of this method will execute the mount
	 * command themselves.  The volume manager daemon's
	 * current event handling mechanism doesn't allow that.
	 */

	partition_private_t 	*child_privatep;
	medium_private_t 	*medium_privatep;
	struct async_task 	*mount_as;
	partition_handle_t	next_childp;
	partition_result_t	partition_result;
	partition_private_t 	*partition_privatep;

	debug(2, "entering mount_partition()\n");

	partition_result = PARTITION_SUCCESS;
	partition_privatep = (partition_private_t *)partitionp;
	if (partition_privatep == NULL) {
		partition_result = PARTITION_BAD_INPUT_PARAMETER;
	}
	next_childp = partition_privatep->left_childp;
	while ((partition_result == PARTITION_SUCCESS) &&
		(next_childp != NULL)) {

		partition_result = mount_partition(next_childp);
		child_privatep = (partition_private_t *)next_childp;
		next_childp = child_privatep->right_siblingp;
	}
	if ((partition_result == PARTITION_SUCCESS) &&
	    (partition_privatep->state == MOUNTABLE)) {
		medium_privatep =
			(medium_private_t *)partition_privatep->on_mediump;
		mount_as = malloc(sizeof (struct async_task));
		if (mount_as == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		} else {
			mount_as->act = ASACT_MOUNT;
			mount_as->data[0] =
				(uintptr_t)medium_privatep->in_device;
			mount_as->data[1] =
				(uintptr_t)partition_privatep->volumep;
			async_taskq_insert(mount_as);
			partition_privatep->state = MOUNTED;
		}
	}

	debug(2, "leaving mount_partition(), result code = %s\n",
		partition_result_codes[partition_result]);

	return (partition_result);
}

int
number_of_partition_types()
{
	return ((int)NUMBER_OF_PARTITION_TYPES);
}

partition_result_t
partition_create_vnodes(partition_handle_t  partitionp)
{
	partition_private_t 	*partition_privatep;
	partition_result_t	partition_result;

	debug(2, "entering partition_create_vnodes()\n");

	partition_privatep = (partition_private_t *)partitionp;
	partition_result = (*partition_privatep->methodsp->create_vnodes)
				(partition_privatep);

	debug(2, "leaving partition_create_vnodes(), result code = %s\n",
		partition_result_codes[partition_result]);

	return (partition_result);
}

partition_result_t
remount_partition(partition_handle_t  partitionp)
{
	/*
	 * NOTE: This method is recursive.  It calls itself to
	 *	 remount all the children of the partition it is
	 *	 remounting before remounting the partition itself.
	 *
	 * This method remounts the partition by adding an async_task
	 * structure with its act field set to REMOUNT to the
	 * volume manager daemon's event handling queue.  It
	 * includes a vol_t object containing all the remount
	 * parameters in the async_task object.
	 *
	 * Later versions of this method will execute the mount
	 * command themselves.  The volume manager daemon's
	 * current event handling mechanism doesn't allow that.
	 */

	partition_private_t 	*child_privatep;
	medium_private_t 	*medium_privatep;
	struct async_task 	*mount_as;
	partition_handle_t	next_childp;
	partition_result_t	partition_result;
	partition_private_t 	*partition_privatep;

	debug(2, "entering remount_partition()\n");

	partition_result = PARTITION_SUCCESS;
	partition_privatep = (partition_private_t *)partitionp;
	if (partition_privatep == NULL) {
		partition_result = PARTITION_BAD_INPUT_PARAMETER;
	}
	next_childp = partition_privatep->left_childp;
	while ((partition_result == PARTITION_SUCCESS) &&
		(next_childp != NULL)) {

		partition_result = remount_partition(next_childp);
		child_privatep = (partition_private_t *)next_childp;
		next_childp = child_privatep->right_siblingp;
	}
	if ((partition_result == PARTITION_SUCCESS) &&
	    (partition_privatep->state == MOUNTABLE)) {
		medium_privatep =
			(medium_private_t *)partition_privatep->on_mediump;
		mount_as = malloc(sizeof (struct async_task));
		if (mount_as == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		} else {
			mount_as->act = ASACT_REMOUNT;
			mount_as->data[0] =
				(uintptr_t)medium_privatep->in_device;
			mount_as->data[1] =
				(uintptr_t)partition_privatep->volumep;
			async_taskq_insert(mount_as);
			partition_privatep->state = MOUNTED;
		}
	}

	debug(2, "leaving remount_partition(), result code = %s\n",
		partition_result_codes[partition_result]);

	return (partition_result);
}

partition_result_t
unmount_partition(partition_handle_t  partitionp)
{
	/*
	 * NOTE: This method is recursive.  It calls itself to
	 *	 unmount all the children of the partition it is
	 *	 unmounting before unmounting the partition itself.
	 *
	 * Later versions of this method will execute the unmount
	 * command themselves.  The volume manager daemon's
	 * current event handling mechanism doesn't allow that.
	 */

	partition_private_t 	*child_privatep;
	partition_handle_t	next_childp;
	partition_result_t	partition_result;
	partition_private_t 	*partition_privatep;

	debug(2, "entering unmount_partition()\n");

	partition_privatep = (partition_private_t *)partitionp;
	partition_result = PARTITION_SUCCESS;

	if (partition_privatep == NULL) {
		partition_result = PARTITION_BAD_INPUT_PARAMETER;
	}
	next_childp = partition_privatep->left_childp;
	while ((partition_result == PARTITION_SUCCESS) &&
		(next_childp != NULL)) {
			partition_result = unmount_partition(next_childp);

			child_privatep = (partition_private_t *)next_childp;
			next_childp = child_privatep->right_siblingp;
	}
	if ((partition_result == PARTITION_SUCCESS) &&
	    (partition_privatep->state == MOUNTED)) {
		/*
		 * The current version of the software can't
		 * unmount individual partitions, because the
		 * current volume manager event handling mechanism
		 * doesn't permit it.  Later versions of this
		 * method will issue the unmount command directly.
		 */
		partition_privatep->state = MOUNTABLE;
	}

	debug(2, "leaving unmount_partition(), result code = %s\n",
		partition_result_codes[partition_result]);

	return (partition_result);
}

/*
 * The following method definitions must be visible to classes
 * descended from the partition class, such as the pcfs_partition
 * and fdisk_partition classes.  They are therefore visible outside
 * this file.  To keep their declarations invisible to clients of
 * the partition class, they are declared in the partition_private.h
 * include file.
 */

mode_t
add_execute_permissions(mode_t mode)
{
	if (mode & S_IRUSR) {
		mode |= S_IXUSR;
	}
	if (mode & S_IRGRP) {
		mode |= S_IXGRP;
	}
	if (mode & S_IROTH) {
		mode |= S_IXOTH;
	}
	return (mode);
}

partition_result_t
clone_label(partition_label_t	*original_labelp,
	    partition_label_t	**cloned_labelpp)
{
	partition_label_t	*cloned_labelp;
	partition_result_t	partition_result;

	partition_result = PARTITION_SUCCESS;
	cloned_labelp = calloc(1, sizeof (partition_label_t));
	if (cloned_labelp == NULL) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	} else {
		(void) memcpy(cloned_labelp,
				original_labelp, sizeof (partition_label_t));
		cloned_labelp->keyp = strdup(original_labelp->keyp);
		if (cloned_labelp->keyp == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
			destroy_label(&cloned_labelp);
		} else {
			cloned_labelp->volume_namep =
				strdup(original_labelp->volume_namep);
			if (cloned_labelp->volume_namep == NULL) {
				partition_result = PARTITION_OUT_OF_MEMORY;
				destroy_label(&cloned_labelp);
			}
		}
	}
	*cloned_labelpp = cloned_labelp;
	return (partition_result);
}

void
convert_vnodes_to_dir_vnodes(partition_private_t *partition_privatep)
{

	if (partition_privatep->global_block_vvnodep != NULL) {
		partition_privatep->global_block_vvnodep->vn_type = VV_DIR;
		partition_privatep->global_block_vvnodep->vn_otype = VV_BLK;
		partition_privatep->global_block_vvnodep->vn_obj->o_mode =
			add_execute_permissions(
				partition_privatep->global_block_vvnodep->
					vn_obj->o_mode);
	}
	partition_privatep->global_raw_vvnodep->vn_type = VV_DIR;
	partition_privatep->global_raw_vvnodep->vn_otype = VV_CHR;
	partition_privatep->global_raw_vvnodep->vn_obj->o_mode =
		add_execute_permissions(
			partition_privatep->global_raw_vvnodep->vn_obj->o_mode);

	if (partition_privatep->block_vvnodep != NULL) {
		partition_privatep->block_vvnodep->vn_type = VV_DIR;
		partition_privatep->block_vvnodep->vn_otype = VV_BLK;
		partition_privatep->block_vvnodep->vn_obj->o_mode =
			add_execute_permissions(
				partition_privatep->block_vvnodep->
					vn_obj->o_mode);
	}
	partition_privatep->raw_vvnodep->vn_type = VV_DIR;
	partition_privatep->raw_vvnodep->vn_otype = VV_CHR;
	partition_privatep->raw_vvnodep->vn_obj->o_mode =
		add_execute_permissions(
			partition_privatep->raw_vvnodep->vn_obj->o_mode);
}

void
convert_vnodes_to_parent_vnodes(partition_private_t *partition_privatep)
{
	/*
	 * Convert a partition's vnodes to directory vnodes
	 * and make them the parent vnodes of the partition.
	 */
	convert_vnodes_to_dir_vnodes(partition_privatep);

	partition_privatep->parent_global_block_vvnodep =
		partition_privatep->global_block_vvnodep;
	partition_privatep->global_block_vvnodep = NULL;

	partition_privatep->parent_global_raw_vvnodep =
		partition_privatep->global_raw_vvnodep;
	partition_privatep->global_raw_vvnodep = NULL;

	partition_privatep->parent_block_vvnodep =
		partition_privatep->block_vvnodep;
	partition_privatep->block_vvnodep = NULL;

	partition_privatep->parent_raw_vvnodep =
		partition_privatep->raw_vvnodep;
	partition_privatep->raw_vvnodep = NULL;
}

void
correct_pathnames(partition_private_t *partition_privatep)
{
	/*
	 * Correct the block and raw pathnames.
	 * That may be necessary if there are duplicate vvnodes
	 * in the database and node_mkobj() has had to change
	 * the block and raw vvnode names to avoid duplication.
	 *
	 * Entry conditions:
	 *
	 *  ((partition_privatep->raw_pathnamep != NULL) &&
	 *   (partition_privatep->raw_vvnodep != NULL))
	 *
	 * Exit conditions:
	 *
	 *  ((partition_privatep->raw_pathnamep != NULL) &&
	 *   (partition_privatep->raw_vvnodep != NULL))
	 *
	 */

	if (partition_privatep->block_pathnamep != NULL) {
		free(partition_privatep->block_pathnamep);
		partition_privatep->block_pathnamep = NULL;
	}
	if (partition_privatep->block_vvnodep != NULL) {
		partition_privatep->block_pathnamep =
			path_make(partition_privatep->block_vvnodep);
	}
	free(partition_privatep->raw_pathnamep);
	partition_privatep->raw_pathnamep =
		path_make(partition_privatep->raw_vvnodep);
}

partition_result_t
create_child_partition(partition_handle_t    parentp,
			partition_handle_t *new_childpp)
{
	partition_private_t	*new_child_privatep;
	partition_handle_t	new_childp;
	partition_private_t	*parent_privatep;
	partition_result_t	partition_result;
	partition_handle_t	rightmost_childp;

	parent_privatep = (partition_private_t *)parentp;
	rightmost_childp = get_rightmost_child(parent_privatep);
	if (rightmost_childp != NULL) {
		partition_result =
			create_right_sibling_partition(rightmost_childp,
							&new_childp);
	} else {
		partition_result = create_empty_partition(&new_childp);
		if (partition_result == PARTITION_SUCCESS) {
			parent_privatep->left_childp =
				new_childp;
			new_child_privatep =
				(partition_private_t *)new_childp;
			new_child_privatep->file_descriptor =
				parent_privatep->file_descriptor;
			new_child_privatep->gid =
				parent_privatep->gid;
			new_child_privatep->left_childp =
				NULL;
			new_child_privatep->left_siblingp =
				NULL;
			new_child_privatep->medium_typep =
				strdup(parent_privatep->medium_typep);
			if (new_child_privatep->medium_typep == NULL) {
				partition_result = PARTITION_OUT_OF_MEMORY;
			} else {
				new_child_privatep->mode =
					parent_privatep->mode;
				new_child_privatep->on_mediump =
					parent_privatep->on_mediump;
				new_child_privatep->parentp =
					parentp;
				new_child_privatep->permissions =
					parent_privatep->permissions;
				new_child_privatep->right_siblingp =
					NULL;
				new_child_privatep->uid =
					parent_privatep->uid;
			}
		}
	}
	*new_childpp = new_childp;
	return (partition_result);
}

partition_result_t
create_empty_partition(partition_handle_t *partitionpp)
{
	partition_handle_t  new_partitionp;
	partition_result_t  partition_result;

	partition_result = PARTITION_SUCCESS;
	new_partitionp = calloc(1, sizeof (partition_private_t));
	if (new_partitionp == NULL) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	}
	*partitionpp = new_partitionp;
	return (partition_result);
}

partition_result_t
create_label(partition_label_t **labelpp)
{
	/*
	 * creates an empty label structure that the
	 * read_label() methods of the descendant
	 * partition classes fill in.
	 */

	partition_label_t	*labelp;
	partition_result_t	partition_result;

	partition_result = PARTITION_SUCCESS;
	labelp = calloc(1, sizeof (partition_label_t));
	if (labelp != NULL) {
		*labelpp = labelp;
	} else {
		partition_result = PARTITION_OUT_OF_MEMORY;
	}
	return (partition_result);
}

partition_result_t
create_pathnames(partition_private_t *partition_privatep)
{
	medium_private_t	*medium_privatep;
	char			*name_bufferp;
	char			*parent_block_pathnamep;
	partition_private_t	*parent_privatep;
	char			*parent_raw_pathnamep;
	partition_result_t	partition_result;
	char			*volume_namep;

	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;
	parent_privatep = (partition_private_t *)partition_privatep->parentp;
	partition_result = PARTITION_SUCCESS;

	name_bufferp = malloc(MAXPATHLEN);
	if (name_bufferp == NULL) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	}
	if (partition_result == PARTITION_SUCCESS) {
		if (parent_privatep != NULL) {
			parent_block_pathnamep =
				parent_privatep->block_pathnamep;
			parent_raw_pathnamep = parent_privatep->raw_pathnamep;
		} else {
			parent_block_pathnamep =
				medium_privatep->block_pathnamep;
			parent_raw_pathnamep = medium_privatep->raw_pathnamep;
		}
		volume_namep = partition_privatep->labelp->volume_namep;
		if (parent_block_pathnamep != NULL) {
			(void) snprintf(name_bufferp, MAXPATHLEN, "%s/%s",
					parent_block_pathnamep,
					volume_namep);
			partition_privatep->block_pathnamep =
				strdup(name_bufferp);
		} else {
			partition_privatep->block_pathnamep = NULL;
		}
		(void) snprintf(name_bufferp, MAXPATHLEN, "%s/%s",
				parent_raw_pathnamep,
				volume_namep);
		partition_privatep->raw_pathnamep = strdup(name_bufferp);
		if (partition_privatep->raw_pathnamep == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		}
	}
	if (name_bufferp != NULL) {
		free(name_bufferp);
	}
	return (partition_result);
}

partition_result_t
create_slice_vvnodes(partition_private_t *partition_privatep)
{
	/*
	 * NOTE:
	 *
	 * This method serves as part of the interface between
	 * the new partition class and the legacy database.  When the
	 * legacy database is replaced or eliminated, this method
	 * wlll no longer be needed.
	 */

	obj_t			*block_slice_objectp;
	uint_t			error;
	uint_t			flags;
	obj_t			*global_block_slice_objectp;
	obj_t			*global_raw_slice_objectp;
	partition_result_t	partition_result;
	obj_t			*raw_slice_objectp;
	char			*vvnode_namep;

	partition_result = PARTITION_SUCCESS;
	flags = NODE_TMPID;

	vvnode_namep = find_filenamep(partition_privatep->raw_pathnamep);
	partition_result =
		create_slice_object(
			partition_privatep->volumep,
			vvnode_namep,
			&global_block_slice_objectp);
	if ((partition_result == PARTITION_SUCCESS) &&
		(partition_privatep->parent_global_block_vvnodep != NULL)) {
		partition_privatep->global_block_vvnodep =
			node_mkobj(partition_privatep->
					parent_global_block_vvnodep,
					global_block_slice_objectp,
					flags | NODE_BLK,
					&error);
		partition_privatep->global_block_vvnodep->vn_num =
			partition_privatep->devmap_index;
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result =
			create_slice_object(
					partition_privatep->volumep,
					vvnode_namep,
					&global_raw_slice_objectp);
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_privatep->global_raw_vvnodep =
			node_mkobj(partition_privatep->
				parent_global_raw_vvnodep,
				global_raw_slice_objectp,
				flags | NODE_CHR,
				&error);
		partition_privatep->global_raw_vvnodep->vn_num =
			partition_privatep->devmap_index;

		partition_result =
			create_slice_object(partition_privatep->volumep,
						vvnode_namep,
						&block_slice_objectp);
	}
	if ((partition_result == PARTITION_SUCCESS) &&
		(partition_privatep->parent_block_vvnodep != NULL)) {
		partition_privatep->block_vvnodep =
			node_mkobj(partition_privatep->parent_block_vvnodep,
					block_slice_objectp,
					flags | NODE_BLK,
					&error);
		partition_privatep->block_vvnodep->vn_num =
			partition_privatep->devmap_index;
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result =
			create_slice_object(
				partition_privatep->volumep,
				vvnode_namep,
				&raw_slice_objectp);
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_privatep->raw_vvnodep =
			node_mkobj(partition_privatep->parent_raw_vvnodep,
					raw_slice_objectp,
					flags | NODE_CHR,
					&error);
		partition_privatep->raw_vvnodep->vn_num =
			partition_privatep->devmap_index;
	}
	return (partition_result);
}

partition_result_t
create_symlink(partition_private_t *partition_privatep)
{
	/*
	 * This method handles two cases.
	 *
	 * 1. The medium contains only one file system.
	 *    Create a symlink called "<device_name>" in
	 *    /vol/dev/aliases and make it point to the raw
	 *    vnode of the partition.  Write a pointer
	 *    to the symlink to the dp_symvn attribute
	 *    of the device object that models the device
	 *    in which the medium is inserted.
	 *
	 * 2. The medium contains more than one file system.
	 *    Create a symlink called "<volume_name>" in the
	 *    /vol/dev/aliases/<device> directory that the
	 *    parent medium has created and make it point to
	 *    the raw vnode of the partition.
	 */

	struct devs		*devicep;
	medium_private_t	*medium_privatep;
	partition_result_t	partition_result;
	char			*volume_namep;

	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;
	devicep = dev_getdp(medium_privatep->in_device);
	partition_result = PARTITION_SUCCESS;
	volume_namep = partition_privatep->labelp->volume_namep;

	if (medium_privatep->number_of_filesystems <= 1) {
		/*
		 * There is either no file system on the medium
		 * or one file system on the medium.  Create a
		 * a symbolic link to the top level raw vnode
		 * on the medium in the /vol/dev/aliases directory
		 * and give it the symbolic name of the device
		 * (e.g. floppy0, zip0, cdrom0, jaz0.)
		 */
		partition_privatep->symlink_vvnodep =
			node_symlink(dev_dirpath(ALIAS_DIRECTORY_NAME),
					devicep->dp_symname,
					partition_privatep->raw_pathnamep,
					NODE_TMPID,
					NULL);
		devicep->dp_symvn = partition_privatep->symlink_vvnodep;
	} else {
		/*
		 * In this case there are two or more volumes on the
		 * medium, and the current software architecture
		 * provides no way to connect them both to the device.
		 * The dp_mediump attribute of the device object
		 * connects the device to the medium, and that
		 * connection will have to be used on ejection to
		 * remove all volumes from the device.  The mechanism
		 * for doing that has yet to be designed.
		 */
		partition_privatep->symlink_vvnodep =
			node_symlink(medium_privatep->symlink_dir_vvnodep,
					volume_namep,
					partition_privatep->raw_pathnamep,
					NODE_TMPID,
					NULL);
	}
	return (partition_result);
}

partition_result_t
create_top_level_vvnodes(partition_private_t *partition_privatep)
{
	struct devs		*devicep;
	uint_t			error;
	uint_t			flags;
	vvnode_t		*global_raw_vvnodep;
	dev_t			in_device;
	medium_private_t	*medium_privatep;
	medium_private_t	*omedium_privatep;
	medium_private_t	*vmedium_privatep;
	partition_result_t	partition_result;
	vol_t			*ovolumep;

	flags = (uint_t)0;
	partition_result = PARTITION_SUCCESS;

	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;
	in_device = medium_privatep->in_device;
	devicep = dev_getdp(in_device);
	omedium_privatep = vmedium_privatep = NULL;
	ovolumep = NULL;
	partition_result = PARTITION_SUCCESS;

	/*
	 * The current version of the software must find or create
	 * a global raw vvnode for the volume in the database to
	 * be able to find and mount a volume.  Failure to find
	 * or create the global vvnode causes assertion failures
	 * and core dumps.
	 */

	/*
	 * At this point, nfs server has been suspended by acquiring
	 * vold_main_mutex. Therefore it is safe to create/remove the
	 * node and changing devmaps.
	 */
	if (devicep->dp_vol != NULL)
		dev_unhangvol(devicep);

	/*
	 * if previous volume was unlabelled, dp_mediump should have
	 * been cleared.
	 */
	if (devicep->dp_mediump != NULL) {
		omedium_privatep = (medium_private_t *)devicep->dp_mediump;
		if (omedium_privatep != NULL)
			ovolumep = omedium_privatep->volumep;
		/*
		 * we will remove the node which has been made by the
		 * previous medium which was in the drive. If the volume
		 * object has been taken over by the other drive, ovolumep
		 * should be NULL.
		 */
		if (ovolumep != NULL &&
		    (ovolumep->v_flags & V_UNLAB) == 0) {
			ovolumep->v_confirmed = FALSE;
			node_remove((obj_t *)ovolumep, TRUE, &error);
		}
	}

	if ((partition_privatep->volumep->v_flags & V_UNLAB) == 0) {
		partition_result = find_vvnode_in_db(partition_privatep,
							&global_raw_vvnodep);
		if ((partition_result == PARTITION_SUCCESS) &&
			(global_raw_vvnodep != NULL)) {
			/*
			 * The given vvnode can be created by the different
			 * device. So the volume hanging on vn_vol may have
			 * been pointed by other medium which has been
			 * inactivated. Thus, we detach volume from the
			 * medium, so that other device won't go to release
			 * the volume.
			 */
			ovolumep = global_raw_vvnodep->vn_vol;
			vmedium_privatep = ovolumep->v_mediump;
			if (vmedium_privatep != NULL)
				vmedium_privatep->volumep = NULL;
			/*
			 * The database contains a vvnode whose label
			 * key matches the label key of the volume
			 * that the partition object has just created.
			 * Remove the old vvnodes and volume from the
			 * database.  The next guarded sequence replaces
			 * the vvnodes with new ones based on the new
			 * volume structure.
			 */
			ovolumep->v_confirmed = FALSE;
			node_remove((obj_t *)global_raw_vvnodep->vn_vol,
				TRUE, &error);
		}
		if (partition_result == PARTITION_SUCCESS) {
			partition_privatep->global_raw_vvnodep =
				node_mkobj(rdskroot,
					(obj_t *)partition_privatep->
					volumep,
					NODE_FIXNAME | NODE_DBUP | NODE_CHR,
					&error);
			/*
			 * The "twinning" code in the node_mkobj() creates
			 * both partition_privatep->global_raw_vvnodep
			 * and partition_privatep->global_block_vvnodep
			 * when called once to create
			 * partition_privatep->global_raw_vvnodep, and writes
			 * a pointer to partition_privatep->global_block_vvnodep
			 * to partition_privatep->global_raw_vvnodep->vn_twin.
			 *
			 * NOTE:
			 *
			 * Remove the code that produces side effects like
			 * twin nodes and partition nodes from the node_mkobj()
			 * method as soon as time and resources permit.
			 */
			partition_privatep->global_block_vvnodep =
				partition_privatep->global_raw_vvnodep->vn_twin;
			if (partition_privatep->global_block_vvnodep != NULL) {
				partition_privatep->global_block_vvnodep->
					vn_num =
						partition_privatep->
							devmap_index;
			}
			partition_privatep->global_raw_vvnodep->vn_num =
				partition_privatep->devmap_index;
		}
	}

	if (partition_result == PARTITION_SUCCESS) {
		if (partition_privatep->volumep->v_flags & V_UNLAB) {
			flags |= NODE_TMPID;
		}
		/*
		 * If we do not have a block device we do not want to
		 * create a vnode for it.
		 */
		if (partition_privatep->parent_block_vvnodep != NULL) {
			partition_privatep->block_vvnodep =
				node_mkobj(
					partition_privatep->
						parent_block_vvnodep,
					(obj_t *)partition_privatep->volumep,
					flags | NODE_BLK,
					&error);
			partition_privatep->block_vvnodep->vn_num =
				partition_privatep->devmap_index;
		}
		partition_privatep->raw_vvnodep =
			node_mkobj(partition_privatep->parent_raw_vvnodep,
				(obj_t *)partition_privatep->volumep,
				flags | NODE_CHR,
				&error);
		partition_privatep->raw_vvnodep->vn_num =
			partition_privatep->devmap_index;
		change_atime((obj_t *)partition_privatep->volumep,
				&current_time);
		change_location((obj_t *)partition_privatep->volumep,
				devicep->dp_path);
		partition_privatep->volumep->v_confirmed = TRUE;
		debug(1, "found volume \"%s\" in %s (%d,%d)\n",
				partition_privatep->volumep->v_obj.o_name,
				devicep->dp_path,
				major(in_device),
				minor(in_device));
		if ((partition_privatep->volumep->v_flags & V_UNLAB) == 0) {
			(void) db_update(
				(obj_t *)partition_privatep->volumep);
		}
		devicep->dp_vol = partition_privatep->volumep;
		/*
		 * The next statement enables remove_medium_from_db()
		 * to find the volume representing the medium in the
		 * database.
		 */
		medium_privatep->volumep = partition_privatep->volumep;
	}

	if (partition_result == PARTITION_SUCCESS) {
		if (ovolumep != NULL) {
			/*
			 * first create the new devmap by copying the old
			 * one as much as possible.
			 */
			dev_reset_devmap(ovolumep, medium_privatep->volumep);

			/*
			 * volume is being destroyed. We will take care of
			 * missing events if exists.
			 */
			dev_handle_missing(ovolumep, medium_privatep->volumep);

			/*
			 * if this volume was taken over from the other
			 * medium, destroy here.
			 */
			if (ovolumep->v_mediump !=
			    (medium_handle_t)omedium_privatep) {
				destroy_volume(ovolumep);
			}
		} else {
			dev_devmap(medium_privatep->volumep);
		}

		if (medium_privatep->volumep->v_devmap == NULL) {
			partition_result = PARTITION_CANT_CREATE_DEVMAP;
		}
	}
	if (partition_result == PARTITION_SUCCESS) {
		/*
		 * devmap has been created.
		 * we need to notify vold of the new mapping, so that
		 * cancelled volume won't be failed with EIO.
		 */
		if (dev_map_dropin(medium_privatep->volumep) == FALSE) {
			partition_result = PARTITION_CANT_CREATE_DEVMAP;
		}

		/*
		 * release old own volume/medium.
		 */
		if (omedium_privatep != NULL) {
			if (omedium_privatep->volumep != NULL)
				destroy_volume(omedium_privatep->volumep);
			destroy_medium((medium_handle_t *)&omedium_privatep);
		}
	}
	/*
	 * Only if we failed to create devmap, we destroy volume etc.
	 * Unlabelled volume will be released in dev_unhangvol(), so
	 * we need to know before calling dev_unhangvol().
	 */
	if (partition_result == PARTITION_CANT_CREATE_DEVMAP) {
		devicep->dp_mediump = medium_privatep;
		dev_unhangvol(devicep);
		if (devicep->dp_mediump != NULL) {
			/* volume hasn't gone(ie labelled volume) */
			node_remove((obj_t *)medium_privatep->volumep,
				TRUE, &error);
			partition_destroy_volume(partition_privatep);
		}
		devicep->dp_mediump = NULL;
	}
	return (partition_result);
}

partition_result_t
create_volume(partition_private_t *partition_privatep)
{
	/*
	 * Each potentially mountable partition has a volume associated
	 * with it, because the current version of the volume management
	 * daemon passes a volume structure to the current version of
	 * the mount method in order to mount the partition.  We plan to
	 * elminate the current version of the mount method in a future
	 * version of the software and enable individual partitions
	 * to mount themselves.  That will eliminate the need for
	 * the volume structure.
	 */

	struct devs		*devicep;
	medium_private_t	*medium_privatep;
	partition_result_t	partition_result;
	int			type_index;
	vol_t			*volumep;


	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;
	devicep = dev_getdp(medium_privatep->in_device);
	partition_result = PARTITION_SUCCESS;

	volumep = calloc(1, sizeof (vol_t));
	if (volumep == NULL) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	}
	if (partition_result == PARTITION_SUCCESS) {
		volumep->v_obj.o_name =
			strdup(partition_privatep->labelp->volume_namep);
		if (volumep->v_obj.o_name == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		}
	}
	if (partition_result == PARTITION_SUCCESS) {
		volumep->v_obj.o_type = VV_CHR;
		volumep->v_obj.o_uid = partition_privatep->uid;
		volumep->v_obj.o_gid = partition_privatep->gid;
		volumep->v_obj.o_mode = partition_privatep->mode;
		volumep->v_obj.o_nlinks = (uint_t)1;
		change_atime((obj_t *)volumep, &current_time);
		volumep->v_obj.o_ctime = current_time;
		volumep->v_obj.o_mtime = current_time;
	}
	if (partition_result == PARTITION_SUCCESS) {
		volumep->v_mtype = strdup(medium_privatep->medium_typep);
		if (volumep->v_mtype == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		}
	}
	if (partition_result == PARTITION_SUCCESS) {
		volumep->v_label.l_type = PARTITION_LABEL;
		partition_result =
			clone_label(partition_privatep->labelp,
				    (partition_label_t **)
				    &(volumep->v_label.l_label));
	}
	if (partition_result == PARTITION_SUCCESS) {
		volumep->v_parts = partition_privatep->partition_mask;
		volumep->v_ndev = partition_privatep->number_of_slices;
		volumep->v_basedev = NODEV;
		if (devicep->dp_dsw->d_flags & D_RMONEJECT) {
			volumep->v_flags |= V_RMONEJECT;
		}
		if (devicep->dp_flags & DP_MEJECTABLE) {
			volumep->v_flags |= V_MEJECTABLE;
		}
		if (partition_privatep->type != UNKNOWN) {
			volumep->v_flags |= V_NETWIDE;
		} else {
			volumep->v_flags |= V_UNLAB;
		}
		switch (partition_privatep->permissions) {
		case PASSWORD_WRITE_PROTECTED:
		case READ_ONLY:
			volumep->v_flags |= V_RDONLY;
			break;
		}
		type_index = (int)partition_privatep->type;
		volumep->v_fstype = file_system_types[type_index];
		/*
		 * mount mode is always "ro" for medium in cdrom drive.
		 */
		if (strcmp(medium_privatep->medium_typep, CDROM_MTYPE) == 0) {
			(void) strcpy(volumep->v_mount_mode,
			    permission_codes[READ_ONLY]);
		} else {
			(void) strcpy(volumep->v_mount_mode,
			    permission_codes[partition_privatep->permissions]);
		}
		volumep->v_partitionp =
			(partition_handle_t *)partition_privatep;
		volumep->v_mediump = partition_privatep->on_mediump;
		volumep->v_device = medium_privatep->in_device;
	}
	partition_privatep->volumep = volumep;
	if (partition_result != PARTITION_SUCCESS) {
		partition_destroy_volume(partition_privatep);
	}
	return (partition_result);
}

partition_result_t
create_vvnodes(partition_private_t *partition_privatep)
{
	/*
	 * NOTE:
	 *
	 * This method serves as part of the interface between
	 * the new partition class and the legacy database.  When the
	 * legacy database is replaced or eliminated, this method
	 * wlll no longer be needed.
	 */

	medium_private_t	*medium_privatep;
	partition_private_t	*parent_privatep;
	partition_result_t	partition_result;

	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;
	parent_privatep = (partition_private_t *)partition_privatep->parentp;

	if (partition_privatep->location == TOP) {
		/*
		 * The partition is a top level partition
		 */
		partition_privatep->parent_block_vvnodep =
			medium_privatep->block_vvnodep;
		partition_privatep->parent_raw_vvnodep =
			medium_privatep->raw_vvnodep;

		partition_result = create_top_level_vvnodes(partition_privatep);

	} else {
		/*
		 * The partition is a slice or subpartition.
		 */
		partition_privatep->parent_global_block_vvnodep =
			parent_privatep->global_block_vvnodep;
		partition_privatep->parent_global_raw_vvnodep =
			parent_privatep->global_raw_vvnodep;
		partition_privatep->parent_block_vvnodep =
			parent_privatep->block_vvnodep;
		partition_privatep->parent_raw_vvnodep =
			parent_privatep->raw_vvnodep;

		partition_result = create_slice_vvnodes(partition_privatep);
	}
	return (partition_result);
}

void
destroy_pathnames(partition_private_t *partition_privatep)
{
	if (partition_privatep->block_pathnamep != NULL) {
		free(partition_privatep->block_pathnamep);
		partition_privatep->block_pathnamep = NULL;
	}
	if (partition_privatep->raw_pathnamep != NULL) {
		free(partition_privatep->raw_pathnamep);
		partition_privatep->raw_pathnamep = NULL;
	}
}

char *
find_filenamep(char *directory_namep)
{
	/*
	 * returns a pointer to the filename string
	 * doesn't duplicate the string
	 */

	char	*last_slash_ptr;
	char	*filenamep;
	char	*next_slash_ptr;

	next_slash_ptr = strstr(directory_namep, "/");
	while (next_slash_ptr != NULL) {
		last_slash_ptr = next_slash_ptr;
		next_slash_ptr = strstr((last_slash_ptr + 1), "/");
	}
	filenamep = last_slash_ptr + 1;
	return (filenamep);
}

partition_result_t
read_partition(partition_private_t *partition_privatep)
{
	partition_result_t	partition_result;

	debug(8, "entering read_partition()\n");

	partition_result = PARTITION_NOT_THIS_TYPE;
	if (strcmp(partition_privatep->medium_typep, CDROM_MTYPE) == 0) {
		partition_result = read_hsfs_partition(partition_privatep);
		if (partition_result != PARTITION_SUCCESS) {
			partition_result =
				read_udfs_partition(partition_privatep);
		}
		if (partition_result != PARTITION_SUCCESS) {
			partition_result =
				read_solaris_partition(partition_privatep);
		}
		if (partition_result != PARTITION_SUCCESS) {
			partition_result =
				read_ufs_partition(partition_privatep);
		}
	}
	if (strcmp(partition_privatep->medium_typep, RMDISK_MTYPE) == 0) {
		partition_result = read_pcfs_partition(partition_privatep);
		if (partition_result != PARTITION_SUCCESS) {
			partition_result =
				read_fdisk_partition(partition_privatep);
		}
		if (partition_result != PARTITION_SUCCESS) {
			partition_result =
				read_solaris_partition(partition_privatep);
		}
		if (partition_result != PARTITION_SUCCESS) {
			partition_result =
				read_udfs_partition(partition_privatep);
		}
		if (partition_result != PARTITION_SUCCESS) {
			partition_result =
				read_ufs_partition(partition_privatep);
		}
	}
	if ((strcmp(partition_privatep->medium_typep, FLOPPY_MTYPE) == 0) ||
		(strcmp(partition_privatep->medium_typep, PCMEM_MTYPE) == 0)) {
		partition_result = read_pcfs_partition(partition_privatep);
		if (partition_result != PARTITION_SUCCESS) {
			partition_result =
				read_fdisk_partition(partition_privatep);
		}
		if (partition_result != PARTITION_SUCCESS) {
			partition_result =
				read_solaris_partition(partition_privatep);
		}
		if (partition_result != PARTITION_SUCCESS) {
			partition_result =
				read_ufs_partition(partition_privatep);
		}
		if (partition_result != PARTITION_SUCCESS) {
			partition_result =
				read_udfs_partition(partition_privatep);
		}
	}
	if (strcmp(partition_privatep->medium_typep, TEST_MTYPE) == 0) {
		partition_result = read_pcfs_partition(partition_privatep);
		if (partition_result != PARTITION_SUCCESS) {
			partition_result =
				read_fdisk_partition(partition_privatep);
		}
		if (partition_result != PARTITION_SUCCESS) {
			partition_result =
				read_solaris_partition(partition_privatep);
		}
		if (partition_result != PARTITION_SUCCESS) {
			partition_result =
				read_ufs_partition(partition_privatep);
		}
	}
	if (strcmp(partition_privatep->medium_typep, CDTEST_MTYPE) == 0) {
		partition_result = read_hsfs_partition(partition_privatep);
		if (partition_result != PARTITION_SUCCESS) {
			partition_result =
				read_solaris_partition(partition_privatep);
		}
	}
	if (partition_result != PARTITION_SUCCESS) {
		partition_result = read_blank_partition(partition_privatep);
	}
	debug(8, "leaving read_partition(), result code = %s\n",
		partition_result_codes[partition_result]);

	return (partition_result);
}

partition_result_t
read_slices(partition_private_t *partition_privatep)
{
	partition_handle_t	childp;
	partition_private_t	*child_privatep;
	partition_private_t	*parent_privatep;
	int			ioctl_result;
	int			number_found;
	int			number_of_slices;
	int			partition_index;
	ulong_t			partition_mask;
	partition_result_t	partition_result;
	partition_handle_t	partitionp;
	struct vtoc		*vtocp;

	number_of_slices = (int)partition_privatep->number_of_slices;
	partition_mask = partition_privatep->partition_mask;
	partitionp = (partition_handle_t)partition_privatep;
	parent_privatep = partition_privatep->parentp;

	number_found = 0;
	partition_result = PARTITION_SUCCESS;
	vtocp = malloc(sizeof (struct vtoc));
	if (vtocp == NULL) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	}
	if (partition_result == PARTITION_SUCCESS) {
		ioctl_result = ioctl(partition_privatep->file_descriptor,
					DKIOCGVTOC,
					vtocp);
		if ((ioctl_result == -1) || (vtoc_valid(vtocp) == B_FALSE)) {
				partition_result = PARTITION_CANT_READ_MEDIUM;
		}
	}
	for (partition_index = 0; partition_result == PARTITION_SUCCESS &&
		number_found < number_of_slices; partition_index++) {

		if ((partition_mask & ((ulong_t)1 << partition_index)) == 0)
			continue;

		partition_result = create_child_partition(partitionp, &childp);
		if (partition_result != PARTITION_SUCCESS)
			continue;

		child_privatep = (partition_private_t *)childp;
		if (parent_privatep != NULL &&
		    parent_privatep->type == FDISK) {
			child_privatep->offset =
				partition_privatep->offset +
				vtoc_partition_offset(vtocp, partition_index);
		} else {
			child_privatep->offset =
				vtoc_partition_offset(vtocp, partition_index);
		}

		child_privatep->devmap_index = number_found++;
		child_privatep->partition_number = partition_index;
		child_privatep->volume_namep =
			strdup(slice_names[partition_index]);
		if (child_privatep->volume_namep == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		}
		if (partition_result == PARTITION_SUCCESS) {
			partition_result = read_slice_partition(child_privatep);
		}
	}
	if (vtocp != NULL) {
		free(vtocp);
	}
	return (partition_result);
}

/*
 * Definitions of private methods
 */

static void
partition_destroy_volume(partition_private_t *partition_privatep)
{
	destroy_volume(partition_privatep->volumep);
	partition_privatep->volumep = NULL;
}

static partition_result_t
create_slice_object(vol_t *volumep,
			char *object_namep,
			obj_t **slice_objectpp)
{
	/*
	 * NOTE:
	 *
	 * This method serves as part of the interface between
	 * the new partition class and the legacy database.  When the
	 * legacy database is replaced or eliminated, this method
	 * wlll no longer be needed.
	 */

	partition_result_t	partition_result;
	partat_t		*slice_objectp;

	partition_result = PARTITION_SUCCESS;
	slice_objectp = calloc(1, sizeof (partat_t));
	if (slice_objectp == NULL) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	} else {
		slice_objectp->pa_obj.o_name =
			strdup(object_namep);
		if (slice_objectp->pa_obj.o_name == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		}
	}
	if (partition_result == PARTITION_SUCCESS) {
		slice_objectp->pa_obj.o_type = VV_PART;
		slice_objectp->pa_obj.o_uid = volumep->v_obj.o_uid;
		slice_objectp->pa_obj.o_gid = volumep->v_obj.o_gid;
		slice_objectp->pa_obj.o_mode = volumep->v_obj.o_mode;
		slice_objectp->pa_obj.o_atime = volumep->v_obj.o_atime;
		slice_objectp->pa_obj.o_ctime = volumep->v_obj.o_ctime;
		slice_objectp->pa_obj.o_mtime = volumep->v_obj.o_mtime;
		slice_objectp->pa_obj.o_nlinks = 1;
	}
	*slice_objectpp = ((obj_t *)slice_objectp);
	return (partition_result);
}

static partition_result_t
create_right_sibling_partition(partition_handle_t    partitionp,
				partition_handle_t *new_siblingpp)
{
	partition_private_t	*new_sibling_privatep;
	partition_handle_t	new_siblingp;
	partition_private_t	*partition_privatep;
	partition_result_t	partition_result;

	partition_result = create_empty_partition(&new_siblingp);
	if (partition_result == PARTITION_SUCCESS) {
		partition_privatep = (partition_private_t *)partitionp;
		partition_privatep->right_siblingp = new_siblingp;
		new_sibling_privatep =
			(partition_private_t *)new_siblingp;
		new_sibling_privatep->file_descriptor =
			partition_privatep->file_descriptor;
		new_sibling_privatep->gid = partition_privatep->gid;
		new_sibling_privatep->left_childp = NULL;
		new_sibling_privatep->left_siblingp = partitionp;
		new_sibling_privatep->medium_typep =
			strdup(partition_privatep->medium_typep);
		if (new_sibling_privatep->medium_typep == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		} else {
			new_sibling_privatep->mode = partition_privatep->mode;
			new_sibling_privatep->on_mediump =
				partition_privatep->on_mediump;
			new_sibling_privatep->parentp =
				partition_privatep->parentp;
			new_sibling_privatep->permissions =
				partition_privatep->permissions;
			new_sibling_privatep->right_siblingp = NULL;
			new_sibling_privatep->uid = partition_privatep->uid;
		}
	}
	*new_siblingpp = new_siblingp;
	return (partition_result);
}

static partition_result_t
find_vvnode_in_db(partition_private_t *partition_privatep,
		vvnode_t **found_vvnodepp)
{
	vol_t			*found_volumep;
	vvnode_t		*found_vvnodep;
	label			*labelp;
	char			*name_bufferp;
	struct vnwrap		*next_vvnode_linkp;
	partition_result_t	partition_result;
	struct vnwrap		*vvnode_linkp;

	found_volumep = NULL;
	found_vvnodep = NULL;
	labelp = NULL;
	name_bufferp = NULL;
	next_vvnode_linkp = NULL;
	partition_result = PARTITION_SUCCESS;
	vvnode_linkp = NULL;

	name_bufferp = malloc(MAXPATHLEN);
	if (name_bufferp == NULL) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	} else {
		labelp = malloc(sizeof (label));
		if (labelp == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		} else {
			labelp->l_type = PARTITION_LABEL;
			labelp->l_label = (void *)partition_privatep->labelp;
			found_volumep =
				db_findlabel(partition_privatep->medium_typep,
					labelp);
		}
	}
	if (found_volumep != NULL) {
		vvnode_linkp = node_findnode(found_volumep->v_obj.o_id,
						FN_ANY, FN_ANY, FN_ANY);
		if (vvnode_linkp == NULL) {
			(void) snprintf(name_bufferp, MAXPATHLEN, "%s/%s",
					found_volumep->v_obj.o_dir,
					found_volumep->v_obj.o_name);
			(void) node_lookup(name_bufferp);
			vvnode_linkp =
				node_findnode(found_volumep->v_obj.o_id,
						FN_ANY, FN_ANY, FN_ANY);
			if (vvnode_linkp == NULL) {
				partition_result = PARTITION_DB_ERROR;
			}
		}
	}
	if (vvnode_linkp != NULL) {
		/*
		 * Find the global vvnode for the volume.
		 */
		found_vvnodep = vvnode_linkp->vw_node;
		next_vvnode_linkp = vvnode_linkp;
		while ((found_vvnodep->vn_dirtype != DIR_RDSK) &&
			(next_vvnode_linkp != NULL)) {
			found_vvnodep = next_vvnode_linkp->vw_node;
			next_vvnode_linkp = next_vvnode_linkp->vw_next;
		}
		if (found_vvnodep->vn_dirtype != DIR_RDSK) {
			found_vvnodep = NULL;
		}
		/*
		 * Remove the vvnode link structure.
		 */
		node_findnode_free(vvnode_linkp);
	}
	if ((found_vvnodep != NULL) &&
	    (found_vvnodep->vn_vol->v_confirmed)) {
		noise("%s named %s already inserted in a drive\n",
			found_vvnodep->vn_vol->v_mtype,
			found_vvnodep->vn_vol->v_obj.o_name);
		partition_result = PARTITION_DUPLICATE_VOLUME;
	}
	*found_vvnodepp = found_vvnodep;
	if (name_bufferp != NULL) {
		free(name_bufferp);
	}
	if (labelp != NULL) {
		free(labelp);
	}
	return (partition_result);
}

static partition_handle_t
get_rightmost_child(partition_private_t *parent_privatep)
{
	partition_private_t	*child_privatep;
	partition_handle_t	next_childp;
	partition_handle_t	rightmost_childp;

	rightmost_childp = NULL;
	next_childp = parent_privatep->left_childp;
	while (next_childp != NULL) {
		rightmost_childp = next_childp;
		child_privatep = (partition_private_t *)next_childp;
		next_childp = child_privatep->right_siblingp;
	}
	return (rightmost_childp);
}

static partition_result_t
read_slice_partition(partition_private_t *partition_privatep)
{

	partition_result_t	partition_result;

	partition_result = read_ufs_partition(partition_privatep);
	if (partition_result != PARTITION_SUCCESS) {
		partition_result = read_udfs_partition(partition_privatep);
	}
	if (partition_result != PARTITION_SUCCESS) {
		partition_result = read_blank_partition(partition_privatep);
	}
	return (partition_result);
}
