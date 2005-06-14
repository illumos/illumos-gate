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
 * Solaris partition class implementation file
 */

/*
 * System include files
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/dkio.h>
#include <sys/dklabel.h>
#include <unistd.h>

/*
 * Local include files
 */

#include "vold.h"

#include "medium.h"
#include "partition.h"
#include "vtoc.h"

/*
 * Private data and procedure declarations
 */

#include "partition_private.h"

#define	KEY_BUFFER_LENGTH  512

#define	UNNAMED_SOLARIS "unnamed_solaris"

/*
 * Forward declarations of private methods
 */

static partition_result_t check_checksum(struct dk_label *);
static partition_result_t check_label(struct dk_label *);
static partition_result_t create_solaris_vnodes(partition_private_t *);
static daddr_t dk_label_offset(char *);
static partition_result_t get_label(partition_private_t *);
static partition_result_t read_label(struct dk_label *, partition_private_t *);
static partition_result_t read_solaris_vtoc(partition_private_t *);

/*
 * Methods that implement abstract methods
 * declared in the parent partition class
 */

static partition_methods_t  partition_methods =
	{create_solaris_vnodes, read_solaris_partition};

/*
 * Definition of the public read_partition() method that
 * identifies the partition type and sets its attributes
 */

partition_result_t
read_solaris_partition(partition_private_t *partition_privatep)
{
	/*
	 * Try to read the label and VTOC from the medium and verify
	 * that the partition is a Solaris partition.  If it is,
	 * set the partition's attributes accordingly, and if the
	 * partition has more than one nonempty slice, create child
	 * partitions for the slices and read the slice data into
	 * them.
	 */

	medium_private_t	*medium_privatep;
	partition_result_t	partition_result;

	debug(2, "entering read_solaris_partition()\n");

	if (partition_privatep->no_solaris_partition == B_TRUE) {
		partition_result = PARTITION_NOT_THIS_TYPE;
		goto dun;
	}

	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;

	partition_result = get_label(partition_privatep);

	if (partition_result == PARTITION_SUCCESS) {
		partition_privatep->attributesp = NULL;
		partition_privatep->devmap_index = 0;
		partition_privatep->location = TOP;
		partition_privatep->methodsp = &partition_methods;
		partition_privatep->state = MOUNTABLE;
		partition_privatep->type = SOLARIS;
		medium_privatep->number_of_filesystems++;
		if (partition_privatep->number_of_slices > ONE_SLICE) {
			partition_result = read_slices(partition_privatep);
		}
	}
dun:
	debug(2, "leaving read_solaris_partition(), result code = %s\n",
		partition_result_codes[partition_result]);

	return (partition_result);
}

/*
 * Definitions of private methods
 */

static partition_result_t
check_checksum(struct dk_label *solaris_labelp)
{
	/*
	 * XORs dkl_checksum with the rest of the 16-bit words in the
	 * label;  Since dkl_checksum is computed by XORing the rest
	 * of the 16-bit words in the label, the net result should
	 * be the XOR of dkl_checksum with itself, which is zero.
	 */

	uint16_t		checksum;
	uint16_t		*next_wordp;
	partition_result_t	partition_result;
	int			word_count;

	checksum = 0;
	next_wordp = (uint16_t *)solaris_labelp;
	word_count = sizeof (struct dk_label) / sizeof (uint16_t);

	while (word_count > 0) {
		checksum ^= *next_wordp;
		next_wordp++;
		word_count--;
	}
	if (checksum == 0) {
		partition_result = PARTITION_SUCCESS;
	} else {
		partition_result = PARTITION_NOT_THIS_TYPE;
	}
	return (partition_result);
}

static partition_result_t
check_label(struct dk_label *solaris_labelp)
{
	partition_result_t  partition_result;

	partition_result = PARTITION_SUCCESS;
	if (solaris_labelp->dkl_magic != DKL_MAGIC) {
		partition_result = PARTITION_NOT_THIS_TYPE;
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = check_checksum(solaris_labelp);
	}
	return (partition_result);
}

static partition_result_t
create_solaris_vnodes(partition_private_t *partition_privatep)
{
	/*
	 * NOTE: The file system structure created by this
	 *	 function is a legacy public interface
	 *	 between the volume manager and user-level
	 *	 applications.  Changing it will cause
	 *	 those applications to fail.
	 */
	partition_handle_t	childp;
	partition_private_t	*child_privatep;
	partition_label_t	*labelp;
	medium_private_t	*medium_privatep;
	partition_result_t	partition_result;

	debug(2, "entering create_solaris_vnodes()\n");

	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;
	partition_result = PARTITION_SUCCESS;

	if ((medium_privatep->number_of_filesystems > 1) &&
		(partition_privatep->has_volume_name == B_FALSE)) {
		/*
		 * The medium contains more than one file system.
		 * If the partition's label is blank, rename the
		 * partition's volume in a way that distinguishes
		 * the partition from the other partitions on the
		 * medium that contain file systems.
		 */
		labelp = partition_privatep->labelp;
		free(labelp->volume_namep);
		labelp->volume_namep = strdup(UNNAMED_SOLARIS);
		if (labelp->volume_namep == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		}
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = create_pathnames(partition_privatep);
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = create_volume(partition_privatep);
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = create_vvnodes(partition_privatep);
	}
	if ((partition_result == PARTITION_SUCCESS) &&
		(partition_privatep->number_of_slices > 1)) {
		/*
		 * The partition contains more than one slice.
		 * Convert its vnodes to directory vnodes
		 * and attach vnodes for the slices to the
		 * directory vnodes.
		 */
		convert_vnodes_to_dir_vnodes(partition_privatep);

		childp = partition_privatep->left_childp;
		while ((partition_result == PARTITION_SUCCESS) &&
			(childp != NULL)) {

			partition_result = partition_create_vnodes(childp);
			child_privatep = (partition_private_t *)childp;
			childp = child_privatep->right_siblingp;
		}
	}
	if (partition_result == PARTITION_SUCCESS) {
		correct_pathnames(partition_privatep);
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = create_symlink(partition_privatep);
	}

	debug(2, "leaving create_solaris_vnodes(), result code = %s\n",
		partition_result_codes[partition_result]);

	return (partition_result);
}

static daddr_t
dk_label_offset(char *medium_typep)
{
	daddr_t  offset;

	if ((strcmp(medium_typep, FLOPPY_MTYPE) == 0) ||
	    (strcmp(medium_typep, PCMEM_MTYPE) == 0) ||
	    (strcmp(medium_typep, TEST_MTYPE) == 0)) {
		offset = (daddr_t)0;
	} else {
		offset = (daddr_t)(DK_LABEL_LOC * DEV_BSIZE);
	}
	return (offset);
}

static partition_result_t
get_label(partition_private_t *partition_privatep)
{
	daddr_t			offset;
	struct dk_label		solaris_label;
	partition_result_t	partition_result;
	medium_private_t	*medium_privatep;

	partition_result = PARTITION_SUCCESS;
	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;
	offset = (daddr_t)partition_privatep->offset +
		dk_label_offset(partition_privatep->medium_typep);
	if ((offset + sizeof (struct dk_label)) >
	    medium_privatep->medium_capacity) {
		partition_result = PARTITION_CANT_READ_MEDIUM;
	}
	if (partition_result == PARTITION_SUCCESS &&
	    lseek(partition_privatep->file_descriptor, offset,
	    SEEK_SET) != offset) {
		partition_result = PARTITION_CANT_READ_MEDIUM;
	}
	if (partition_result == PARTITION_SUCCESS &&
	    read(partition_privatep->file_descriptor,
	    &solaris_label,
	    sizeof (struct dk_label)) != sizeof (struct dk_label)) {
		partition_result = PARTITION_CANT_READ_MEDIUM;
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = check_label(&solaris_label);
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = read_label(&solaris_label,
						partition_privatep);
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = read_solaris_vtoc(partition_privatep);
	}
	return (partition_result);
}

static partition_result_t
read_label(struct dk_label *solaris_labelp,
	partition_private_t *partition_privatep)
{
	char			*key_bufferp;
	partition_label_t	*labelp;
	char			*name_bufferp;
	partition_result_t	partition_result;

	partition_result = PARTITION_SUCCESS;

	key_bufferp = malloc(KEY_BUFFER_LENGTH);
	name_bufferp = malloc(MAXNAMELEN);

	if ((key_bufferp == NULL) || (name_bufferp == NULL)) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = create_label(&(partition_privatep->labelp));
	}
	if (partition_result == PARTITION_SUCCESS) {
		labelp = partition_privatep->labelp;
		labelp->crc = calc_crc((uchar_t *)solaris_labelp,
					sizeof (struct dk_label));
		(void) snprintf(key_bufferp, KEY_BUFFER_LENGTH, "0x%lx",
			labelp->crc);
		labelp->keyp = strdup(key_bufferp);
		if (labelp->keyp == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		}
	}
	if (partition_result == PARTITION_SUCCESS) {
		if (solaris_labelp->dkl_vtoc.v_volume[0] != NULLC) {

			partition_privatep->has_volume_name = B_TRUE;
			(void) strncpy(name_bufferp,
					solaris_labelp->dkl_vtoc.v_volume,
					LEN_DKL_VVOL);
			name_bufferp[LEN_DKL_VVOL] = '\0';
			/*
			 * NOTE: The makename() method comes from
			 *	 vold_util.c.  Clean it up and move
			 *	 it to partition.c as soon as time
			 *	 and resources permit.
			 */
			labelp->volume_namep =
				makename(name_bufferp, LEN_DKL_VVOL);
		} else {
			partition_privatep->has_volume_name = B_FALSE;
			(void) snprintf(name_bufferp, MAXNAMELEN, "%s%s",
					UNNAMED_PREFIX,
					partition_privatep->medium_typep);
			labelp->volume_namep = strdup(name_bufferp);
		}
		if (labelp->volume_namep == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		}
	}
	if (partition_result != PARTITION_SUCCESS) {
		destroy_label(&partition_privatep->labelp);
	}
	if (key_bufferp != NULL) {
		free(key_bufferp);
	}
	if (name_bufferp != NULL) {
		free(name_bufferp);
	}
	return (partition_result);
}

static partition_result_t
read_solaris_vtoc(partition_private_t *partition_privatep)
{
	int			ioctl_result;
	partition_result_t	partition_result;
	struct vtoc		*vtocp;

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
	if (partition_result == PARTITION_SUCCESS) {
		if (strcmp(partition_privatep->medium_typep, FLOPPY_MTYPE) ==
			0) {
			partition_privatep->number_of_slices = ONE_SLICE;
			partition_privatep->partition_mask =
				DEFAULT_SPARC_PARTITION_MASK;
		} else {
			partition_privatep->number_of_slices =
				vtoc_number_of_partitions(vtocp);
			partition_privatep->partition_mask =
				vtoc_partition_mask(vtocp);
		}
	}
	if (vtocp != NULL) {
		free(vtocp);
	}
	return (partition_result);
}
