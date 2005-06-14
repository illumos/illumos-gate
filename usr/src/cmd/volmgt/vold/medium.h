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

#ifndef __MEDIUM_H
#define	__MEDIUM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Medium class interface file.
 */


/*
 * System include files
 */

#include <sys/types.h>
#include <sys/param.h>

/*
 * Include <sys/param.h> for the definition of NODEV
 */


#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The medium class stores its attributes as private
 * data.  Client classes can't access them directly.
 * They can only use the services declared in this
 * public include file.
 */

typedef void * medium_handle_t;

/*
 * IMPORTANT NOTE:
 *
 * The strings in the medium_result_codes[] string array
 * in medium.c MUST match the result types in typedef enum
 * medium_result_t below.  When you add or remove result
 * types, keep the result types and the matching strings in
 * alphabetical order to make it easier to maintain the match.
 */

typedef enum medium_result {
	MEDIUM_BAD_DEVICE = 0,
	MEDIUM_BAD_FILE_DESCRIPTOR,
	MEDIUM_BAD_INPUT_PARAMETER,
	MEDIUM_CANT_CREATE_PARTITIONS,
	MEDIUM_CANT_CREATE_PATHNAMES,
	MEDIUM_CANT_CREATE_VNODES,
	MEDIUM_CANT_GET_ACCESS_MODE,
	MEDIUM_CANT_MOUNT_PARTITIONS,
	MEDIUM_CANT_REMOUNT_PARTITIONS,
	MEDIUM_CANT_REMOVE_FROM_DB,
	MEDIUM_CANT_UNMOUNT_PARTITIONS,
	MEDIUM_OUT_OF_MEMORY,
	MEDIUM_SUCCESS
} medium_result_t;

extern medium_result_t
create_medium(dev_t			in_device,
		medium_handle_t		*mediumpp);
/*
 * Creates a medium object that models the medium inserted in the
 * device modelled by the device object whose handle is in_device.
 * Writes the address of the medium object to the medium handle
 * addressed by mediumpp.  If it can't create the object it returns
 * an error code and nulls the medium handle.
 */

extern void destroy_medium(medium_handle_t *mediumpp);
/*
 * Destroys the medium object addressed by the handle addressed
 * by mediumpp.  Nulls the handle.
 */

extern medium_result_t
medium_mount_partitions(medium_handle_t		mediump);
/*
 * Mounts all the partitions on the medium modeled by the
 * medium object addressed by mediump.
 */

extern medium_result_t
medium_remount_partitions(medium_handle_t	mediump);
/*
 * Remounts all the partitions on the medium modeled by the
 * medium object addressed by mediump.
 */

extern medium_result_t
medium_unmount_partitions(medium_handle_t	mediump);
/*
 * Unmounts all the partitions on the medium modeled by the
 * medium object addressed by mediump.
 */

extern void clean_medium_and_volume(medium_handle_t);

#ifdef __cplusplus
}
#endif

#endif /* __MEDIUM_H */
