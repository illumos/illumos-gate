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

#ifndef __MEDIUM_PRIVATE_H
#define	__MEDIUM_PRIVATE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Definitions of data types and methods private to the
 * medium class, but shared with friend classes
 * like the partition class;
 */

/*
 * System include files
 */

#include <sys/types.h>
#include <sys/smedia.h>

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

/*
 * Private type declarations
 */

/*
 * The order of the strings in the permission_codes[] string array
 * in partition.c MUST match the order of the permission types in the
 * typdef enum permissions_t below.
 */
typedef enum permissions {
	PASSWORD_PROTECTED = 0,
	PASSWORD_WRITE_PROTECTED,
	READ_ONLY,
	READ_WRITE
} permissions_t;

typedef struct medium_private {
	char			*block_pathnamep;
	vvnode_t		*block_vvnodep;
	int			file_descriptor;

	/*
	 * number of partitions of each type on the medium
	 */

	int			*partition_counts;
	partition_handle_t	first_pcfs_partitionp;
	gid_t			gid;
	dev_t			in_device;
	char			*medium_typep;
	mode_t			mode;

	/*
	 * number of file systems on the medium
	 */

	int			number_of_filesystems;

	/*
	 * number of partition types that the system can recognize
	 */

	int			number_of_partition_types;
	int			partition_depth;
	permissions_t		permissions;
	char			*raw_pathnamep;
	vvnode_t		*raw_vvnodep;
	char			*symlink_dir_namep;
	vvnode_t		*symlink_dir_vvnodep;
	partition_handle_t	top_partitionp;
	uid_t			uid;
	vol_t			*volumep;
	u_longlong_t		medium_capacity;
} medium_private_t;

#define	ALIAS_DIRECTORY_NAME	"/dev/aliases"
#define	NO_FILE_DESCRIPTOR	-1
#define	MAX_PARTITION_DEPTH	128

#ifdef	__cplusplus
}
#endif

#endif /* __MEDIUM_PRIVATE_H */
