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
 * HSFS partition class implementation file
 */

/*
 * System include files
 */

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<errno.h>
#include	<sys/types.h>
#include	<sys/param.h>
#include	<sys/stat.h>
#include	<sys/dkio.h>
#include	<sys/cdio.h>
#include	<sys/fs/hsfs_isospec.h>
#include	<sys/fs/hsfs_spec.h>
#include	<fcntl.h>
#include	<string.h>

/*
 * Private attribute and method declarations
 */

#include "partition_private.h"
#include "vtoc.h"

typedef struct hsfs_attributes {
	boolean_t	has_audio;
	boolean_t	has_data;
} hsfs_attributes_t;

typedef struct table_of_contents {
	struct cdrom_tochdr	header;
	/*
	 * The maximum number of tracks is 100 -
	 * 99 audio tracks and one lead-in track
	 */
	struct cdrom_tocentry	entry[100];
} table_of_contents_t;

#define	CDI_ID_STRING	"CD-I"
#define	CDI_ID_STRLEN	4
#define	AUDIO_CD	"audio_cd"

/*
 * Volume name used for an unlabeled HSFS partition on a medium
 * that contains other file systems
 */

#define	UNNAMED_HSFS  "unnamed_hsfs"

/*
 * Forward declarations of private methods
 */

static partition_result_t compute_audio_crc(partition_private_t *);
static partition_result_t create_hsfs_vnodes(partition_private_t *);
static partition_result_t find_cdi_volume(partition_private_t *);
static partition_result_t find_hsfs_volume(partition_private_t *);
static partition_result_t find_iso9660_volume(partition_private_t *);
static partition_result_t get_sector(int, int, uchar_t *, ulonglong_t);
static boolean_t has_audio(partition_private_t *);
static boolean_t has_data(partition_private_t *);
static partition_result_t read_label(partition_private_t *);
static partition_result_t read_hsfs_vtoc(partition_private_t *);
static partition_result_t write_audio_label(partition_private_t *);

/*
 * Methods that implement abstract methods
 * declared in the parent partition class
 */

static partition_methods_t  partition_methods =
	{create_hsfs_vnodes, read_hsfs_partition};

/*
 * Definition of the public read_partition() method that
 * identifies the partition type and sets its attributes
 */

partition_result_t
read_hsfs_partition(partition_private_t *partition_privatep)
{
	medium_private_t	*medium_privatep;
	partition_result_t	partition_result;

	debug(2, "entering read_hsfs_partition()\n");

	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;

	partition_result = read_label(partition_privatep);

	if (partition_result == PARTITION_SUCCESS) {
		if (partition_privatep->attributesp != NULL)
			free(partition_privatep->attributesp);
		partition_privatep->attributesp = NULL;
		partition_privatep->devmap_index = 0;
		partition_privatep->location = TOP;
		partition_privatep->methodsp = &partition_methods;
		partition_privatep->state = MOUNTABLE;
		partition_privatep->type = HSFS;
		medium_privatep->number_of_filesystems++;
		if (partition_privatep->number_of_slices > ONE_SLICE) {
			partition_result = read_slices(partition_privatep);
		}
	}
	debug(2, "leaving read_hsfs_partition(), result code = %s\n",
		partition_result_codes[partition_result]);

	return (partition_result);
}

/*
 * Definitions of private methods
 */

static partition_result_t
compute_audio_crc(partition_private_t *partition_privatep)
{
	partition_result_t	partition_result;
	unsigned char		track_number;
	table_of_contents_t	*table_of_contentsp;

	partition_result = PARTITION_SUCCESS;
	table_of_contentsp = calloc(1, sizeof (table_of_contents_t));
	if (table_of_contentsp == NULL) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	}
	if (partition_result == PARTITION_SUCCESS) {
		/*
		 * Read the table of contents header.
		 */
		if (ioctl(partition_privatep->file_descriptor,
			CDROMREADTOCHDR,
			&(table_of_contentsp->header)) < 0) {
			partition_result = PARTITION_CANT_READ_MEDIUM;
		} else {
			table_of_contentsp->entry[0].cdte_track =
				(unsigned char) CDROM_LEADOUT;
			table_of_contentsp->entry[0].cdte_format =
				CDROM_MSF;
			if (ioctl(partition_privatep->file_descriptor,
				CDROMREADTOCENTRY,
				&(table_of_contentsp->entry[0])) < 0) {
				partition_result = PARTITION_CANT_READ_MEDIUM;
			}
		}
	}
	if (partition_result == PARTITION_SUCCESS) {
		/*
		 * Fill in the rest of the table of contents.
		 */
		track_number = table_of_contentsp->header.cdth_trk0;
		while ((partition_result == PARTITION_SUCCESS) &&
			(track_number <=
				table_of_contentsp->header.cdth_trk1)) {

			table_of_contentsp->entry[track_number].cdte_track =
				track_number;
			table_of_contentsp->entry[track_number].cdte_format =
				CDROM_MSF;
			if (ioctl(partition_privatep->file_descriptor,
				CDROMREADTOCENTRY,
				&(table_of_contentsp->entry[track_number]))
				< 0) {
				partition_result = PARTITION_CANT_READ_MEDIUM;
			}
			track_number++;
		}
	}
	if (partition_result == PARTITION_SUCCESS) {
		/*
		 * Compute the cyclic redundancy checksum from
		 * the table of contents.
		 */
		partition_privatep->labelp->crc =
			calc_crc((uchar_t *)table_of_contentsp,
				sizeof (table_of_contents_t));
	}
	if (table_of_contentsp != NULL) {
		free(table_of_contentsp);
	}
	return (partition_result);
}

static partition_result_t
create_hsfs_vnodes(partition_private_t *partition_privatep)
{
	partition_handle_t	childp;
	partition_private_t	*child_privatep;
	partition_result_t	partition_result;

	debug(2, "entering create_hsfs_vnodes()\n");

	partition_result = create_pathnames(partition_privatep);
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

	debug(2, "leaving create_hsfs_vnodes(), result code = %s\n",
		partition_result_codes[partition_result]);

	return (partition_result);
}

static partition_result_t
find_cdi_volume(partition_private_t *partition_privatep)
{
	medium_private_t	*medium_privatep;
	partition_result_t	partition_result;
	uchar_t			*sector_bufferp;
	int			sector_number;
	int			string_index;

	partition_result = PARTITION_SUCCESS;
	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;
	sector_bufferp = malloc(ISO_SECTOR_SIZE);
	if (sector_bufferp == NULL) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	}
	if (partition_result == PARTITION_SUCCESS) {
		/*
		 * Get the first sector that might contain an
		 * "Interactive CD" volume descriptor.
		 */
		sector_number = ISO_VOLDESC_SEC;
		partition_result =
			get_sector(partition_privatep->file_descriptor,
				sector_number,
				sector_bufferp,
				medium_privatep->medium_capacity);
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = PARTITION_NOT_THIS_TYPE;
	}
	while ((partition_result == PARTITION_NOT_THIS_TYPE) &&
		(ISO_DESC_TYPE(sector_bufferp) != ISO_VD_EOV)) {
		/*
		 * Search all the volume descriptor sectors for
		 * an "Interactive CD" volume descriptor.
		 */
		string_index = 0;
		while ((string_index < CDI_ID_STRLEN) &&
			(ISO_STD_ID(sector_bufferp)[string_index] ==
			CDI_ID_STRING[string_index])) {
			string_index++;
		}
		if (string_index == CDI_ID_STRLEN) {
			partition_result = PARTITION_SUCCESS;
		} else {
			partition_result = PARTITION_NOT_THIS_TYPE;
			break;
		}
		if ((partition_result == PARTITION_SUCCESS) &&
			(ISO_STD_VER(sector_bufferp) != ISO_ID_VER)) {
			partition_result = PARTITION_NOT_THIS_TYPE;
		}
		if ((partition_result == PARTITION_SUCCESS) &&
			(ISO_DESC_TYPE(sector_bufferp) != ISO_VD_PVD)) {
			partition_result = PARTITION_NOT_THIS_TYPE;
		}
		if (partition_result == PARTITION_SUCCESS) {
			partition_privatep->labelp->crc =
				calc_crc(sector_bufferp, ISO_SECTOR_SIZE);
			partition_privatep->labelp->volume_namep =
				makename((char *)ISO_vol_id(sector_bufferp),
					ISO_VOL_ID_STRLEN);
			if (partition_privatep->labelp->volume_namep == NULL) {
				partition_result = PARTITION_OUT_OF_MEMORY;
			}
		}
		if (partition_result == PARTITION_NOT_THIS_TYPE) {
			sector_number++;
			partition_result =
				get_sector(partition_privatep->file_descriptor,
					sector_number,
					sector_bufferp,
					medium_privatep->medium_capacity);
			if (partition_result == PARTITION_SUCCESS) {
				partition_result = PARTITION_NOT_THIS_TYPE;
			}
		}
	}
	if (sector_bufferp != NULL) {
		free(sector_bufferp);
	}
	return (partition_result);
}

static partition_result_t
find_hsfs_volume(partition_private_t *partition_privatep)
{
	medium_private_t	*medium_privatep;
	partition_result_t	partition_result;
	uchar_t			*sector_bufferp;
	int			sector_number;
	int			string_index;

	partition_result = PARTITION_SUCCESS;
	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;
	sector_bufferp = malloc(ISO_SECTOR_SIZE);
	if (sector_bufferp == NULL) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	}
	if (partition_result == PARTITION_SUCCESS) {
		/*
		 * Get the first sector that might contain a
		 * High Sierra File System volume descriptor.
		 */
		sector_number = ISO_VOLDESC_SEC;
		partition_result =
			get_sector(partition_privatep->file_descriptor,
				sector_number,
				sector_bufferp,
				medium_privatep->medium_capacity);
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = PARTITION_NOT_THIS_TYPE;
	}
	while ((partition_result == PARTITION_NOT_THIS_TYPE) &&
		(HSV_DESC_TYPE(sector_bufferp) != VD_EOV)) {
		/*
		 * Search all the volume descriptor sectors for
		 * a High Sierra File System volume descriptor.
		 */
		string_index = 0;
		while ((string_index < HSV_ID_STRLEN) &&
			(HSV_STD_ID(sector_bufferp)[string_index] ==
			HSV_ID_STRING[string_index])) {
			string_index++;
		}
		if (string_index == HSV_ID_STRLEN) {
			partition_result = PARTITION_SUCCESS;
		} else {
			partition_result = PARTITION_NOT_THIS_TYPE;
			break;
		}
		if ((partition_result == PARTITION_SUCCESS) &&
			(HSV_STD_VER(sector_bufferp) != HSV_ID_VER)) {
			partition_result = PARTITION_NOT_THIS_TYPE;
			break;
		}
		if ((partition_result == PARTITION_SUCCESS) &&
			(HSV_DESC_TYPE(sector_bufferp) != VD_SFS)) {
			partition_result = PARTITION_NOT_THIS_TYPE;
		}
		if (partition_result == PARTITION_SUCCESS) {
			partition_privatep->labelp->crc =
				calc_crc(sector_bufferp, ISO_SECTOR_SIZE);
			partition_privatep->labelp->volume_namep =
				makename((char *)HSV_vol_id(sector_bufferp),
					HSV_VOL_ID_STRLEN);
			if (partition_privatep->labelp->volume_namep == NULL) {
				partition_result = PARTITION_OUT_OF_MEMORY;
			}
		}
		if (partition_result == PARTITION_NOT_THIS_TYPE) {
			sector_number++;
			partition_result =
				get_sector(partition_privatep->file_descriptor,
					sector_number,
					sector_bufferp,
					medium_privatep->medium_capacity);
			if (partition_result == PARTITION_SUCCESS) {
				partition_result = PARTITION_NOT_THIS_TYPE;
			}
		}
	}
	if (sector_bufferp != NULL) {
		free(sector_bufferp);
	}
	return (partition_result);
}

static partition_result_t
find_iso9660_volume(partition_private_t *partition_privatep)
{
	medium_private_t	*medium_privatep;
	partition_result_t	partition_result;
	uchar_t			*sector_bufferp;
	int			sector_number;
	int			string_index;

	partition_result = PARTITION_SUCCESS;
	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;
	sector_bufferp = malloc(ISO_SECTOR_SIZE);
	if (sector_bufferp == NULL) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	}
	if (partition_result == PARTITION_SUCCESS) {
		/*
		 * Get the first sector that might contain
		 * an ISO9660 volume descriptor.
		 */
		sector_number = ISO_VOLDESC_SEC;
		partition_result =
			get_sector(partition_privatep->file_descriptor,
				sector_number,
				sector_bufferp,
				medium_privatep->medium_capacity);
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = PARTITION_NOT_THIS_TYPE;
	}
	while ((partition_result == PARTITION_NOT_THIS_TYPE) &&
		(ISO_DESC_TYPE(sector_bufferp) != ISO_VD_EOV)) {
		/*
		 * Search all the volume descriptor sectors
		 * for an ISO9660 volume descriptor.
		 */
		string_index = 0;
		while ((string_index < ISO_ID_STRLEN) &&
			(ISO_STD_ID(sector_bufferp)[string_index] ==
			ISO_ID_STRING[string_index])) {
			string_index++;
		}
		if (string_index == ISO_ID_STRLEN) {
			partition_result = PARTITION_SUCCESS;
		} else {
			partition_result = PARTITION_NOT_THIS_TYPE;
			break;
		}
		if ((partition_result == PARTITION_SUCCESS) &&
			(ISO_STD_VER(sector_bufferp) != ISO_ID_VER)) {
			partition_result = PARTITION_NOT_THIS_TYPE;
			break;
		}
		if ((partition_result == PARTITION_SUCCESS) &&
			(ISO_DESC_TYPE(sector_bufferp) != ISO_VD_PVD)) {
			partition_result = PARTITION_NOT_THIS_TYPE;
		}
		if (partition_result == PARTITION_SUCCESS) {
			partition_privatep->labelp->crc =
				calc_crc(sector_bufferp, ISO_SECTOR_SIZE);
			partition_privatep->labelp->volume_namep =
				makename((char *)ISO_vol_id(sector_bufferp),
					ISO_VOL_ID_STRLEN);
			if (partition_privatep->labelp->volume_namep == NULL) {
				partition_result = PARTITION_OUT_OF_MEMORY;
			}
		}
		if (partition_result == PARTITION_NOT_THIS_TYPE) {
			sector_number++;
			partition_result =
				get_sector(partition_privatep->file_descriptor,
					sector_number,
					sector_bufferp,
					medium_privatep->medium_capacity);
			if (partition_result == PARTITION_SUCCESS) {
				partition_result = PARTITION_NOT_THIS_TYPE;
			}
		}
	}
	if (sector_bufferp != NULL) {
		free(sector_bufferp);
	}
	return (partition_result);
}

static partition_result_t
get_sector(int				file_descriptor,
	int				sector_number,
	uchar_t				*sector_bufferp,
	ulonglong_t			medium_capacity)
{
	off_t			offset;
	partition_result_t	partition_result;
	size_t			read_length;

	offset = (off_t)(sector_number * ISO_SECTOR_SIZE);
	partition_result = PARTITION_SUCCESS;
	read_length = ISO_SECTOR_SIZE;

	if ((offset + read_length) > medium_capacity) {
		partition_result = PARTITION_CANT_READ_MEDIUM;
	}
	if (partition_result == PARTITION_SUCCESS) {
		if (lseek(file_descriptor, offset, SEEK_SET) < 0L) {
			partition_result = PARTITION_CANT_READ_MEDIUM;
		}
	}
	if ((partition_result == PARTITION_SUCCESS) &&
		(read(file_descriptor,
			sector_bufferp,
			read_length) != read_length)) {
		partition_result = PARTITION_CANT_READ_MEDIUM;
	}
	return (partition_result);
}

static boolean_t
has_audio(partition_private_t *partition_privatep)
{
	boolean_t		has_audio_data;
	int			ioctl_result;
	struct cdrom_tochdr	table_of_contents;
	struct cdrom_tocentry	table_of_contents_entry;
	unsigned char		track_number;

	has_audio_data = B_FALSE;
	ioctl_result = ioctl(partition_privatep->file_descriptor,
		CDROMREADTOCHDR,
		&table_of_contents);
	if (ioctl_result >= 0) {
		if (table_of_contents.cdth_trk0 <=
			table_of_contents.cdth_trk1) {

			track_number = table_of_contents.cdth_trk0;

			while ((has_audio_data == B_FALSE) &&
				(track_number <= table_of_contents.cdth_trk1)) {

				table_of_contents_entry.cdte_track =
					track_number;
				table_of_contents_entry.cdte_format = CDROM_MSF;

				ioctl_result = ioctl(partition_privatep->
						file_descriptor,
						CDROMREADTOCENTRY,
						&table_of_contents_entry);
				if ((ioctl_result >= 0) &&
					((table_of_contents_entry.cdte_ctrl &
						CDROM_DATA_TRACK) == 0)) {

					has_audio_data = B_TRUE;
				}
				track_number++;
			}
		}
	}
	return (has_audio_data);
}

static boolean_t
has_data(partition_private_t *partition_privatep)
{
	boolean_t		has_digital_data;
	int			ioctl_result;
	struct cdrom_tochdr	table_of_contents;
	struct cdrom_tocentry	table_of_contents_entry;
	unsigned char		track_number;

	has_digital_data = B_FALSE;
	ioctl_result = ioctl(partition_privatep->file_descriptor,
		CDROMREADTOCHDR,
		&table_of_contents);
	if (ioctl_result >= 0) {
		if (table_of_contents.cdth_trk0 >
			table_of_contents.cdth_trk1) {
			has_digital_data = B_TRUE;
		} else {
			track_number = table_of_contents.cdth_trk0;
			while ((has_digital_data == B_FALSE) &&
				(track_number <= table_of_contents.cdth_trk1)) {

				table_of_contents_entry.cdte_track =
					track_number;
				table_of_contents_entry.cdte_format = CDROM_MSF;

				ioctl_result = ioctl(partition_privatep->
						file_descriptor,
						CDROMREADTOCENTRY,
						&table_of_contents_entry);
				if (ioctl_result < 0) {
					has_digital_data = B_TRUE;
				} else if ((table_of_contents_entry.cdte_ctrl &
						CDROM_DATA_TRACK) != 0) {
					has_digital_data = B_TRUE;
				}
				track_number++;
			}
			if (has_digital_data == B_FALSE) {

				table_of_contents_entry.cdte_track =
					(unsigned char) CDROM_LEADOUT;
				table_of_contents_entry.cdte_format = CDROM_MSF;

				ioctl_result = ioctl(partition_privatep->
						file_descriptor,
						CDROMREADTOCENTRY,
						&table_of_contents_entry);
				if (ioctl_result < 0) {
					has_digital_data = B_TRUE;
				} else if ((table_of_contents_entry.cdte_ctrl &
						CDROM_DATA_TRACK) != 0) {
					has_digital_data = B_TRUE;
				}
			}
		}
	}
	return (has_digital_data);
}

static partition_result_t
read_label(partition_private_t *partition_privatep)
{
	hsfs_attributes_t	*attributesp;
	char			*key_bufferp;
	partition_result_t	partition_result;

	partition_result = PARTITION_SUCCESS;
	partition_privatep->attributesp = malloc(sizeof (hsfs_attributes_t));
	if (partition_privatep->attributesp == NULL) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	} else {
		attributesp =
			(hsfs_attributes_t *)partition_privatep->attributesp;
	}
	key_bufferp = malloc(MAXPATHLEN);
	if (key_bufferp == NULL) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = create_label(&(partition_privatep->labelp));
	}
	if (partition_result == PARTITION_SUCCESS) {
		(void) fcntl(partition_privatep->file_descriptor,
				F_SETFD,
				FD_CLOEXEC);
		attributesp->has_audio = has_audio(partition_privatep);
		attributesp->has_data = has_data(partition_privatep);
		if (attributesp->has_audio == B_TRUE) {

			partition_privatep->has_volume_name = B_FALSE;
			partition_privatep->number_of_slices = ONE_SLICE;
#ifdef i386
			partition_privatep->partition_mask =
				DEFAULT_INTEL_PARTITION_MASK;
#else
			partition_privatep->partition_mask =
				DEFAULT_SPARC_PARTITION_MASK;
#endif
			partition_result =
				write_audio_label(partition_privatep);

		} else if (attributesp->has_data == B_TRUE) {
			partition_result =
				find_iso9660_volume(partition_privatep);

			if (partition_result == PARTITION_NOT_THIS_TYPE) {
				partition_result =
					find_hsfs_volume(partition_privatep);
			}
			if (partition_result == PARTITION_NOT_THIS_TYPE) {
				partition_result =
					find_cdi_volume(partition_privatep);
			}
			if (partition_result == PARTITION_SUCCESS) {
				partition_label_t *labelp;

				partition_privatep->has_volume_name = B_TRUE;
				labelp = partition_privatep->labelp;
				if (*labelp->volume_namep == NULLC) {
					free(labelp->volume_namep);
					labelp->volume_namep =
						strdup(UNNAMED_HSFS);
				}
				if (labelp->volume_namep == NULL) {
					partition_result =
						PARTITION_OUT_OF_MEMORY;
				}
			}
			if (partition_result == PARTITION_SUCCESS) {
				partition_result =
					read_hsfs_vtoc(partition_privatep);
			}
		} else {
			partition_result = PARTITION_NOT_THIS_TYPE;
		}
	}
	if (partition_result == PARTITION_SUCCESS) {
		(void) sprintf(key_bufferp,
				"0x%lx",
				partition_privatep->labelp->crc);
		if (partition_privatep->labelp->keyp != NULL)
			free(partition_privatep->labelp->keyp);
		partition_privatep->labelp->keyp = strdup(key_bufferp);
		if (partition_privatep->labelp->keyp == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		}
	}
	if (partition_result != PARTITION_SUCCESS) {
		destroy_label(&(partition_privatep->labelp));
	}
	if (key_bufferp != NULL) {
		free(key_bufferp);
	}
	if (partition_privatep->attributesp != NULL) {
		free(partition_privatep->attributesp);
		partition_privatep->attributesp = NULL;
	}
	return (partition_result);
}

static partition_result_t
read_hsfs_vtoc(partition_private_t *partition_privatep)
{
	partition_result_t	partition_result;
	struct vtoc		*vtocp;

	partition_result = PARTITION_SUCCESS;
	vtocp = malloc(sizeof (struct vtoc));
	if (vtocp == NULL) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	} else {
		if ((ioctl(partition_privatep->file_descriptor,
		    DKIOCGVTOC, vtocp) >= 0) &&
		    (vtoc_valid(vtocp) == B_TRUE)) {

			partition_privatep->number_of_slices =
				vtoc_number_of_partitions(vtocp);
			partition_privatep->partition_mask =
				vtoc_partition_mask(vtocp);
		} else {
			partition_privatep->number_of_slices = ONE_SLICE;
#ifdef i386
			partition_privatep->partition_mask =
				DEFAULT_INTEL_PARTITION_MASK;
#else
			partition_privatep->partition_mask =
				DEFAULT_SPARC_PARTITION_MASK;
#endif
		}
	}
	if (vtocp != NULL)
		free(vtocp);
	return (partition_result);
}

static partition_result_t
write_audio_label(partition_private_t *partition_privatep)
{
	char			*key_bufferp;
	partition_result_t	partition_result;

	partition_result = PARTITION_SUCCESS;
	key_bufferp = malloc(MAXPATHLEN);
	if (key_bufferp == NULL) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = compute_audio_crc(partition_privatep);
	}
	if (partition_result == PARTITION_SUCCESS) {
		(void) sprintf(key_bufferp,
				"0x%lx",
				partition_privatep->labelp->crc);
		partition_privatep->labelp->keyp = strdup(key_bufferp);
		if (partition_privatep->labelp->keyp == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		}
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_privatep->labelp->volume_namep =
			strdup(AUDIO_CD);
		if (partition_privatep->labelp->volume_namep == NULL) {
			partition_result = PARTITION_OUT_OF_MEMORY;
		}
	}
	if (key_bufferp != NULL) {
		free(key_bufferp);
	}
	return (partition_result);
}
