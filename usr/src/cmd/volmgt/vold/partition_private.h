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

#ifndef __PARTITION_PRIVATE_H
#define	__PARTITION_PRIVATE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Definitions of data types and methods private to the
 * partition class, but shared with descendant classes
 * like pcfs_partition, fdisk_partition, and hsfs_partition.
 * Included in the implementation file of the partition
 * class (partition.c) and the implementation files of the
 * descendant classes (pcfs_partition.c, fdisk_partition.c,
 * etc.) so they can set and get private partition attributes
 * and call private partition methods.
 */

/*
 * System include files
 */

#include <sys/stat.h>
#include <sys/mkdev.h>

/*
 * Local include files
 */

#include "medium.h"
#include "partition.h"
#include "vold.h"

/*
 * Include vold.h because it includes all the other old include
 * files in an order that compensates for their dependencies on each
 * other.  In the old include file structure every include file
 * depends on almost every other include file.
 *
 * NOTE: We need to remove those dependencies as soon as we have
 *       the time and resources.
 */

#include "medium_private.h"

/*
 * The partition classs is a "friend" class of the medium class
 * and as such has access to its private attributes and methods.
 */

/*
 * Expose this vvnode to partition.c to compensate
 * for poor factoring in node_findlabel(), which has
 * been replaced by find_vvnode_in_db() in partition.c.
 *
 * NOTE: Refactor node_findlabel() and repair its
 *       interfaces with other methods as soon as
 *       time and resources permit.
 *
 */

extern vvnode_t *rdskroot;

/*
 * Pointer to a partition's type-specific attributes,
 * like the number of subpartitions, or bitmasks that
 * indicate which subpartitions may contain file systems.
 */

typedef void	*attribute_handle_t;

/*
 * Location of the partition on the medium,
 * TOP, for top level partiitions, and SLICE
 * for subpartitions of top level partitions
 * or subpartitions of subpartitions.
 */

typedef enum partition_location {
	SLICE,
	TOP
} partition_location_t;

/*
 * Can the partition me mounted?
 * Is it already mounted?
 */

typedef enum partition_state {
	MOUNTABLE,
	MOUNTED,
	NOT_MOUNTABLE
} partition_state_t;

/*
 * Private partition type definitions
 * The volfs_t types in the static file_system_types[] array in
 * partition.c MUST match the partition types in the typedef
 * enum partition_type_t array below.
 */

typedef enum partition_type {
	FDISK = 0,
	HSFS,
	PCFS,
	SOLARIS,
	UDFS,
	UFS,
	UNKNOWN,
	NUMBER_OF_PARTITION_TYPES
} partition_type_t;

/*
 * Generic partition attributes
 */

/*
 * Forward declaration of the partition_methods struct
 * used in the partition_private_t defined below
 */

struct partition_methods;

typedef struct partition_private {

	/*
	 * SET THE VALUES OF THE FIELDS BELOW IN
	 * create_child_partition(),
	 * create_right_sibling_partition(), AND
	 * create_top_partition.
	 */

	int				file_descriptor;
	gid_t				gid;
	partition_handle_t		left_childp;
	partition_handle_t		left_siblingp;
	char				*medium_typep;
	mode_t				mode;
	medium_handle_t			on_mediump;
	partition_handle_t		parentp;
	permissions_t			permissions;
	partition_handle_t		right_siblingp;
	uid_t				uid;
	/*
	 * SET THE VALUE OF THE FIELD BELOW BEFORE
	 * CALLING THE read_partition() METHOD.
	 */
	off_t				base_offset;
	off_t				offset;

	/*
	 * SET THE VALUES OF THE FIELDS BELOW IN THE
	 * DESCENDANT CLASS read_partition() METHOD.
	 */

	attribute_handle_t		attributesp;
	int				devmap_index;
	/*
	 * index of the partition in the legacy "devmap"
	 * array created for volumes that contain more
	 * than one partition; a devmap array only contains
	 * elements for nonempty partitions, so the devmap
	 * index of a partition can differ from its partition
	 * number; for example, if slice 1 is the first
	 * nonempty partition in a Solaris VTOC, its devmap
	 * index is 0, but its partition number is 1, because
	 * it's slice 1 in the VTOC, and therefore preceded in
	 * the VTOC by (the empty) slice 0, which has a
	 * partition number of 0, but no entry in the devmap.
	 */
	boolean_t			has_volume_name;
	boolean_t			no_solaris_partition;
	boolean_t			no_pcfs_partition;
	char				primary_part_idx;
	partition_label_t		*labelp;
	partition_location_t		location;
	struct partition_methods	*methodsp;
	uchar_t				number_of_slices;
	ulong_t				partition_mask;
	int				partition_number;
	partition_state_t		state;
	partition_type_t		type;
	char				*volume_namep;

	/*
	 * SET THE VALUES OF THE FIELDS BELOW IN THE
	 * DESCENDANT CLASS create_vnodes() METHOD.
	 */

	char				*block_pathnamep;
	vvnode_t			*block_vvnodep;
	vvnode_t			*global_block_vvnodep;
	vvnode_t			*global_raw_vvnodep;
	vvnode_t			*parent_global_block_vvnodep;
	vvnode_t			*parent_global_raw_vvnodep;
	vvnode_t			*parent_block_vvnodep;
	vvnode_t			*parent_raw_vvnodep;
	char				*raw_pathnamep;
	vvnode_t			*raw_vvnodep;
	vvnode_t			*symlink_vvnodep;
	vol_t				*volumep;
} partition_private_t;

/*
 * A set of pointers to the descendant class methods that implement
 * the abstract partition class methods
 */

typedef struct partition_methods {
	partition_result_t	(*create_vnodes)(partition_private_t *);
	partition_result_t	(*read_partition)(partition_private_t *);
} partition_methods_t;

/*
 * Declarations of the descendant class implementations of the partition
 * class's abstract read_partition() method
 */

extern partition_result_t read_fdisk_partition(partition_private_t *);
extern partition_result_t read_hsfs_partition(partition_private_t *);
extern partition_result_t read_pcfs_partition(partition_private_t *);
extern partition_result_t read_solaris_partition(partition_private_t *);
extern partition_result_t read_udfs_partition(partition_private_t *);
extern partition_result_t read_ufs_partition(partition_private_t *);
extern partition_result_t read_blank_partition(partition_private_t *);

/*
 * Methods defined in the generic partition class and used by its
 * descendant classes
 */

/*
 * The following methods form part of the interface between
 * the partition object and the legacy file system and
 * database.  When the file system and database are replaced
 * they will be changed or eliminated.
 */

extern mode_t	add_execute_permissions(mode_t);

extern partition_result_t
	clone_label(partition_label_t *, partition_label_t **);

/*
 * The following methods can probably be reused without change
 * in future versions of the volume manager software.
 */

extern partition_result_t
	create_child_partition(partition_handle_t, partition_handle_t *);
extern partition_result_t create_empty_partition(partition_handle_t *);

/*
 * The following methods form part of the interface between
 * the partition object and the legacy file system and
 * database.  When the file system and database are replaced
 * they will be changed or eliminated.
 */

extern void convert_vnodes_to_dir_vnodes(partition_private_t *);
extern void convert_vnodes_to_parent_vnodes(partition_private_t *);
extern void correct_pathnames(partition_private_t *);

extern partition_result_t create_label(partition_label_t **);
extern partition_result_t create_top_level_vvnodes(partition_private_t *);
extern partition_result_t create_pathnames(partition_private_t *);
extern partition_result_t create_slice_vvnodes(partition_private_t *);
extern partition_result_t create_symlink(partition_private_t *);
extern partition_result_t create_volume(partition_private_t *);
extern partition_result_t create_vvnodes(partition_private_t *);

extern void destroy_pathnames(partition_private_t *);

/*
 * The following methods can probably be reused without change
 * in future versions of the volume manager software.
 */

extern char *find_filenamep(char *);

extern partition_result_t read_partition(partition_private_t *);
extern partition_result_t read_slices(partition_private_t *);

/*
 * Constant character strings used in the partition class and its
 * descendant classes.
 */

/*
 * IMPORTANT NOTE:
 *
 * The strings in the partition_result_codes[] string array below
 * MUST match the result types in typedef enum partition_result_t
 * in partition.h.  When adding or removing result types, keep the
 * result types and the matching strings in alphabetical order
 * to make it easier to maintain the match.
 */

static const char *partition_result_codes[] = {
	"bad input parameter",
	"can't mount partition",
	"can't read medium",
	"can't remount partition",
	"can't unmount partition",
	"can't write medium",
	"db error",
	"duplicate volume",
	"label blank",
	"partition not this type",
	"out of memory",
	"success",
	"too many partitions",
	"can't create devmap",
};

/*
 * Length of the character buffer used to compute the partition label key
 */

#define	KEY_BUFFER_LENGTH  512

/*
 * Default partition masks and partition counts for media without
 * readable VTOCs.  The current default partition mask for Intel systems
 * is ((u_long) 1), which corresponds to partition P0 only.  The current
 * default partition mask for SPARC systems is ((u_long) 4), which
 * corresponds to partition S2 only.
 */

#define	DEFAULT_INTEL_PARTITION_MASK	((ulong_t)1)
#define	DEFAULT_SPARC_PARTITION_MASK	((ulong_t)4)
#define	ONE_SLICE			((uchar_t)1)

/*
 * Empty flags for node_mkobj()
 */

#define	NO_FLAGS (uint_t)0

#ifdef	__cplusplus
}
#endif

#endif /* __PARTITION_PRIVATE_H */
