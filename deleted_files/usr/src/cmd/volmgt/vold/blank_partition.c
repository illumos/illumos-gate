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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Blank partition class implementation file
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

/*
 * Private parent class attribute and method declarations
 */

#include "partition_private.h"

#define	NO_LABEL_KEY		"no_label_key"
#define	UNKNOWN_FORMAT		"unknown_format"

/*
 * Private attribute and method declarations
 */

static partition_result_t
create_blank_label(partition_private_t *	partition_privatep);

static partition_result_t
create_blank_vnodes(partition_private_t *	partition_privatep);

/*
 * Methods that implement abstract methods
 * declared in the parent partition class
 */

static partition_methods_t  partition_methods =
	{create_blank_vnodes, read_blank_partition};

/*
 * Definition of the public read_partition() method that
 * identifies the partition type and sets its attributes
 */

partition_result_t
read_blank_partition(partition_private_t *  partition_privatep)
{
	medium_private_t *	medium_privatep;
	partition_private_t *	parent_privatep;
	partition_result_t	partition_result;
	int			type_index;

	debug(2, "entering read_blank_partition()\n");

	medium_privatep = (medium_private_t *) partition_privatep->on_mediump;
	parent_privatep = (partition_private_t *) partition_privatep->parentp;

	partition_result = create_blank_label(partition_privatep);
	if (partition_result == PARTITION_SUCCESS) {
		partition_privatep->attributesp = NULL;
		partition_privatep->methodsp = &partition_methods;
		partition_privatep->number_of_slices = ONE_SLICE;
#ifdef	i386
		partition_privatep->partition_mask =
			DEFAULT_INTEL_PARTITION_MASK;
#else
		partition_privatep->partition_mask =
			DEFAULT_SPARC_PARTITION_MASK;
#endif
		partition_privatep->state = NOT_MOUNTABLE;
		partition_privatep->type = UNKNOWN;
		if ((parent_privatep != NULL) &&
			(parent_privatep->type != FDISK)) {
			/*
			 * The partition is a subpartition (a slice.)
			 * The read_slices() method has already
			 * assigned the partition a volume name,
			 * partition number, and devmap index.  Transfer
			 * the volume name to the partition's label.
			 */
			partition_privatep->location = SLICE;
			free(partition_privatep->labelp->volume_namep);
			partition_privatep->labelp->volume_namep =
				strdup(partition_privatep->volume_namep);
			if (partition_privatep->labelp->volume_namep == NULL) {
				partition_result = PARTITION_OUT_OF_MEMORY;
			}
		} else {
			/*
			 * This a blank top level partition.  Assign
			 * it a top level blank partition number and
			 * increment the medium's count of top level blank
			 * partitions. That enables the create_blank_vnodes()
			 * method to expose the first top level blank
			 * partition to applications if there are no file
			 * systems on the medium while concealing any
			 * other top level blank partitions that may exist.
			 */
			partition_privatep->devmap_index = 0;
			partition_privatep->location = TOP;
			type_index = (int) partition_privatep->type;
			partition_privatep->partition_number =
				medium_privatep->partition_counts[type_index];
			medium_privatep->partition_counts[type_index]++;
		}
	}
	debug(2, "leaving read_blank_partition(), result code = %s\n",
		partition_result_codes[partition_result]);

	return (partition_result);
}

/*
 * Definitions of private methods
 */

static partition_result_t
create_blank_label(partition_private_t *  partition_privatep)
{
	partition_label_t *	labelp;
	partition_result_t	partition_result;

	partition_result = create_label(&labelp);
	if (partition_result == PARTITION_SUCCESS) {
		labelp->volume_namep = strdup(UNKNOWN_FORMAT);
		if (labelp->volume_namep == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
			destroy_label(&labelp);
		}
	}
	if (partition_result == PARTITION_SUCCESS) {
		labelp->keyp = strdup(NO_LABEL_KEY);
		if (labelp->keyp == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
			destroy_label(&labelp);
		}
	}
	partition_privatep->labelp = labelp;
	return (partition_result);
}

static partition_result_t
create_blank_vnodes(partition_private_t *  partition_privatep)
{
	medium_private_t *	medium_privatep;
	partition_result_t	partition_result;

	debug(2, "entering create_blank_vnodes()\n");

	medium_privatep = (medium_private_t *) partition_privatep->on_mediump;
	partition_result = PARTITION_SUCCESS;

	if ((medium_privatep->number_of_filesystems == 0) &&
		(partition_privatep->location == TOP) &&
		(partition_privatep->partition_number == 0)) {
		/*
		 * There are no file systems or VTOCs on the medium,
		 * and this is the first or only top level blank
		 * partition on the medium.  Create mountable vnodes
		 * and a symlink for the partition so application level
		 * tools can format the medium and create file systems
		 * on it.
		 */
		partition_privatep->state = MOUNTABLE;
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
		if (partition_result == PARTITION_SUCCESS) {
			partition_result = create_symlink(partition_privatep);
		}
	} else if (partition_privatep->location == SLICE) {
		/*
		 * The partition is a subpartition of a mountable
		 * parent partition.  Create slice vnodes for the
		 * partition so application level tools can create
		 * file systems on it.
		 */
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
	}
	debug(2, "leaving create_blank_vnodes(), result code = %s\n",
		partition_result_codes[partition_result]);

	return (partition_result);
}
