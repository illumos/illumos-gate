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

#ifndef __PARTITION_H
#define	__PARTITION_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Partition class interface file.
 */

/*
 * Local include files
 */

#include "medium.h"

/*
 * The partition class stores its attributes as private
 * data.  Client classes can't access them directly.
 * They can only use the services declared in this
 * public include file.
 */

typedef void * partition_handle_t;

/*
 * IMPORTANT NOTE:
 *
 * The strings in the partition_result_codes[] string array in
 * partition_private.h MUST match the result types in typdef enum
 * partition_result_t below.  When you add or remove result
 * types, keep the result types and the matching strings in
 * alphabetical order to make it easier to maintain the match.
 */

typedef enum partition_result {
	PARTITION_BAD_INPUT_PARAMETER = 0,
	PARTITION_CANT_MOUNT,
	PARTITION_CANT_READ_MEDIUM,
	PARTITION_CANT_REMOUNT,
	PARTITION_CANT_UNMOUNT,
	PARTITION_CANT_WRITE_MEDIUM,
	PARTITION_DB_ERROR,
	PARTITION_DUPLICATE_VOLUME,
	PARTITION_LABEL_BLANK,
	PARTITION_NOT_THIS_TYPE,
	PARTITION_OUT_OF_MEMORY,
	PARTITION_SUCCESS,
	PARTITION_TOO_MANY_PARTITIONS,
	PARTITION_CANT_CREATE_DEVMAP
} partition_result_t;

extern partition_result_t
create_top_partition(medium_handle_t		on_mediump,
			partition_handle_t *top_partitionpp);
/*
 * Creates a partition object that models the top-level
 * partition on the medium modeled by the medium object
 * whose handle is on_mediump.  Writes a handle to the
 * object to the partition handle addressed by partitionpp.
 * If it can't create the object it returns an error code
 * and nulls the partition handle.
 */

void
destroy_partition(partition_handle_t *partitionpp);
/*
 * Destroys the partition object whose handle is addressed
 * by partitionpp.  Nulls the handle.
 * intact.
 */

extern partition_result_t
mount_partition(partition_handle_t  partitionp);
/*
 * Mounts the partition modeled by the partition object addressed by
 * partitionp.
 */

extern int
number_of_partition_types();
/*
 * Returns the number of different partition types currently supported
 * by the partition class.
 */

extern partition_result_t
partition_create_vnodes(partition_handle_t  partitionp);
/*
 * Creates vnodes that link the file system to the partition
 * modeled by the partition object addressed by partitionp.
 */

extern partition_result_t
remount_partition(partition_handle_t  partitionp);
/*
 * Remounts the partition modeled by the partition object addressed by
 * partitionp.
 */

extern partition_result_t
unmount_partition(partition_handle_t  partitionp);
/*
 * Unmounts the partition modeled by the partition object addressed
 * by partitionp.
 */

#ifdef	__cplusplus
}
#endif

#endif /* __PARTITION_H */
