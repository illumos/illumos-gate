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
#include	<sys/vtoc.h>
#include	<fcntl.h>
#include	<string.h>
#include	<locale.h>
#include	<sys/fcntl.h>
#include	<sys/mntent.h>
#include	<sys/fs/udf_volume.h>

/*
 * Private attribute and method declarations
 */

#include "partition_private.h"

typedef unsigned short unicode_t;

#define	DOT			0x002E
#define	KEY_BUFFER_LENGTH	512
#define	MAX_UNICODE_NAMELEN	(2 * MAXNAMELEN)
#define	MAXIMUM_BLOCK_SIZE	(64 * 1024)
#define	MINIMUM_BLOCK_SIZE	(512)
#define	POUND			0x0023
#define	SLASH			0x002F
#define	UNDERBAR		0x005F

/*
 * Volume name used for an unlabeled UDFS partition on a medium
 * that contains other file systems
 */

#define	UNNAMED_UDFS		"unnamed_udfs"

static uint16_t htoc[16] = {'0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

static char osta_comp_uni[63] = "OSTA Compressed Unicode";

/*
 * Forward declarations of private methods
 */

static partition_result_t create_udfs_vnodes(partition_private_t *);
static partition_result_t get_anch_vol_desc(partition_private_t *,
		anch_vol_desc_ptr_t **, int32_t *);

/*
 * The get_anch_vol_desc() method returns both a pointer
 * to the anchor volume descriptor and the block size of the medium.
 * Clients of the method must free *anchor_vol_desc_ptrpp to avoid
 * memory leaks.
 */

static partition_result_t get_label(partition_private_t *);
static partition_result_t read_label(partition_private_t *,
		anch_vol_desc_ptr_t *, int32_t);

/*
 * The following methods have been copied from
 * usr/src/cmd/fs.d/udfs/fstyp/ud_lib.c
 */

static int32_t ud_convert2utf8(uint8_t *, uint8_t *, int32_t);
static uint16_t ud_crc(uint8_t *, int32_t);
static int32_t UncompressUnicode(int32_t, uint8_t *, unicode_t *);
static int32_t UdfTxName(unicode_t *, int32_t);

/*
 * The following method is a modified version of the
 * ud_verify_tag() method in usr/src/cmd/fs.d/udfs/fstyp/ud_lib.c
 */

static partition_result_t verify_tag(tag_t *, uint16_t);

/*
 * Methods that implement abstract methods
 * declared in the parent partition class
 */

static partition_methods_t  partition_methods =
	{create_udfs_vnodes, read_udfs_partition};

/*
 * Definition of the public read_partition() method that
 * identifies the partition type and sets its attributes
 */

partition_result_t
read_udfs_partition(partition_private_t *partition_privatep)
{
	medium_private_t	*medium_privatep;
	partition_private_t	*parent_privatep;
	partition_result_t	partition_result;

	debug(2, "entering read_udfs_partition()\n");

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
		partition_privatep->type = UDFS;
		if ((parent_privatep != NULL) &&
			(parent_privatep->type != FDISK)) {
			/*
			 * The partition is a subpartition of a parent
			 * partition (a slice.)  The read_slices() method
			 * has already assigned the partition a devmap_index,
			 * partition number, and volume name.  Transfer
			 * the volume name to the partition's label.
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
			medium_privatep->number_of_filesystems++;
		}
	}
	debug(2, "leaving read_udfs_partion(), result code = %s\n",
		partition_result_codes[partition_result]);

	return (partition_result);
}


/*
 * Definitions of private methods
 */

static partition_result_t
create_udfs_vnodes(partition_private_t *partition_privatep)
{
	partition_result_t	partition_result;

	debug(2, "entering create_udfs_vnodes()\n");

	partition_result = PARTITION_SUCCESS;
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
	debug(2, "leaving create_udfs_vnodes(), result code = %s\n",
		partition_result_codes[partition_result]);

	return (partition_result);
}

static partition_result_t
get_anch_vol_desc(partition_private_t *partition_privatep,
		anch_vol_desc_ptr_t **anchor_vol_desc_ptrpp,
		int32_t *block_sizep)
{
	int8_t			*block_bufferp;
	int32_t			block_size;
	anch_vol_desc_ptr_t	*anchor_vol_desc_ptrp;
	off_t			offset;
	partition_result_t	partition_result;
	medium_private_t	*medium_privatep;

	anchor_vol_desc_ptrp = NULL;
	block_bufferp = NULL;
	block_size = 0;
	partition_result = PARTITION_SUCCESS;
	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;

	block_bufferp = malloc(MAXIMUM_BLOCK_SIZE);
	*anchor_vol_desc_ptrpp = NULL;
	anchor_vol_desc_ptrp = malloc(sizeof (anch_vol_desc_ptr_t));
	if ((block_bufferp == NULL) || (anchor_vol_desc_ptrp == NULL)) {
		partition_result = PARTITION_OUT_OF_MEMORY;
	}
	if (partition_result == PARTITION_SUCCESS) {
		block_size = MINIMUM_BLOCK_SIZE;
		partition_result = PARTITION_NOT_THIS_TYPE;
	}
	while ((partition_result == PARTITION_NOT_THIS_TYPE) &&
		(block_size <= MAXIMUM_BLOCK_SIZE)) {

		offset = partition_privatep->offset +
				(off_t)(ANCHOR_VOL_DESC_LOC * block_size);

		if ((offset + block_size) > medium_privatep->medium_capacity) {
			partition_result = PARTITION_CANT_READ_MEDIUM;
			continue;
		}
		if (lseek(partition_privatep->file_descriptor, offset,
			SEEK_SET) == -1) {

			partition_result = PARTITION_CANT_READ_MEDIUM;

		} else if (read(partition_privatep->file_descriptor,
				block_bufferp,
				block_size) != block_size) {

			partition_result = PARTITION_CANT_READ_MEDIUM;

		} else {
			(void) memcpy(anchor_vol_desc_ptrp, block_bufferp,
				sizeof (anch_vol_desc_ptr_t));
			partition_result =
				verify_tag(&(anchor_vol_desc_ptrp->avd_tag),
					UD_ANCH_VOL_DESC);
			if (partition_result == PARTITION_SUCCESS) {
				*anchor_vol_desc_ptrpp = anchor_vol_desc_ptrp;
				*block_sizep = block_size;
			}
		}
		block_size = 2 * block_size;
	}
	if (block_bufferp != NULL) {
		free(block_bufferp);
	}
	/*
	 * if we don't pass the buffer, but the buffer was allocated,
	 * we need to free.
	 */
	if (*anchor_vol_desc_ptrpp == NULL && anchor_vol_desc_ptrp != NULL) {
		free(anchor_vol_desc_ptrp);
	}
	return (partition_result);
}

static partition_result_t
get_label(partition_private_t *partition_privatep)
{
	anch_vol_desc_ptr_t	*anchor_vol_desc_ptrp;
	int32_t			block_size;
	partition_result_t	partition_result;

	anchor_vol_desc_ptrp = NULL;
	block_size = 0;
	partition_result = PARTITION_SUCCESS;
	if (partition_result == PARTITION_SUCCESS) {
		partition_result =
			get_anch_vol_desc(partition_privatep,
						&anchor_vol_desc_ptrp,
						&block_size);
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = create_label(&(partition_privatep->labelp));
	}
	if (partition_result == PARTITION_SUCCESS) {
		partition_result = read_label(partition_privatep,
						anchor_vol_desc_ptrp,
						block_size);
	}
	if (partition_result != PARTITION_SUCCESS) {
		destroy_label(&(partition_privatep->labelp));
	}
	if (anchor_vol_desc_ptrp != NULL) {
		/*
		 * allocated by get_anch_vol_desc()
		 */
		free(anchor_vol_desc_ptrp);
	}
	return (partition_result);
}

static partition_result_t
read_label(partition_private_t *partition_privatep,
		anch_vol_desc_ptr_t *anchor_vol_desc_ptrp,
		int32_t	block_size)
{
	uchar_t			*block_bufferp;
	uint32_t		block_number;
	uint32_t		end_of_vol_desc_blocks;
	uint32_t		first_vol_desc_block;
	char			*key_bufferp;
	char			*name_bufferp;
	uint32_t		number_of_vol_desc_blocks;
	partition_result_t	partition_result;
	struct pri_vol_desc	*primary_vol_descp;
	char			*string_bufferp;
	off_t			offset;
	medium_private_t	*medium_privatep;

	first_vol_desc_block =
		SWAP_32(anchor_vol_desc_ptrp->avd_main_vdse.ext_loc);
	number_of_vol_desc_blocks =
		SWAP_32(anchor_vol_desc_ptrp->avd_main_vdse.ext_len)
			/ block_size;
	end_of_vol_desc_blocks =
		first_vol_desc_block + number_of_vol_desc_blocks;
	partition_result = PARTITION_SUCCESS;
	medium_privatep = (medium_private_t *)partition_privatep->on_mediump;

	block_bufferp = malloc(block_size);
	key_bufferp = malloc(MAXPATHLEN);
	name_bufferp = malloc(MAXNAMELEN);
	primary_vol_descp = malloc(sizeof (struct pri_vol_desc));
	string_bufferp = malloc(MAX_UNICODE_NAMELEN);
	if ((block_bufferp == NULL) ||
		(key_bufferp == NULL) ||
		(name_bufferp == NULL) ||
		(primary_vol_descp == NULL) ||
		(string_bufferp == NULL)) {

		partition_result = PARTITION_OUT_OF_MEMORY;
	}
	if (partition_result == PARTITION_SUCCESS) {
		block_number = first_vol_desc_block;
		partition_result = PARTITION_NOT_THIS_TYPE;
	}
	while ((partition_result == PARTITION_NOT_THIS_TYPE) &&
			(block_number < end_of_vol_desc_blocks)) {

		offset = partition_privatep->offset +
				(off_t)(block_number * block_size);
		if ((offset + block_size) > medium_privatep->medium_capacity) {
			partition_result = PARTITION_CANT_READ_MEDIUM;
			continue;
		}
		if (lseek(partition_privatep->file_descriptor, offset,
			SEEK_SET) == -1) {

			partition_result = PARTITION_CANT_READ_MEDIUM;

		} else if (read(partition_privatep->file_descriptor,
				block_bufferp,
				block_size) != block_size) {

			partition_result = PARTITION_CANT_READ_MEDIUM;
		} else {
			(void) memcpy(primary_vol_descp, block_bufferp,
				sizeof (struct pri_vol_desc));
			partition_result =
				verify_tag(&(primary_vol_descp->pvd_tag),
					UD_PRI_VOL_DESC);
		}
		block_number++;
	}
	if (partition_result == PARTITION_SUCCESS) {
		/*
		 * Check the character set.  Solaris only supports
		 * the OSTA Compressed Unicode character set for UDFS.
		 */
		if ((primary_vol_descp->pvd_desc_cs.cs_type != CS_TYPE0) ||
			(strncmp(primary_vol_descp->pvd_desc_cs.cs_info,
				osta_comp_uni, 63) != 0)) {

				partition_result = PARTITION_CANT_READ_MEDIUM;

		} else {
			(void) ud_convert2utf8(
				(uint8_t *)(primary_vol_descp->pvd_vol_id),
				(uint8_t *)string_bufferp,
				strlen(primary_vol_descp->pvd_vol_id));

			if ((string_bufferp[0] == NULLC) ||
				(strcmp(string_bufferp, "UNDEFINED") == 0)) {

				partition_privatep->has_volume_name = B_FALSE;
				(void) snprintf(name_bufferp, MAXNAMELEN,
					"%s%s",
					UNNAMED_PREFIX,
					partition_privatep->medium_typep);
				partition_privatep->labelp->volume_namep =
					strdup(name_bufferp);
			} else {
				partition_privatep->has_volume_name = B_TRUE;
				partition_privatep->labelp->volume_namep =
					strdup(string_bufferp);
			}
			if (partition_privatep->labelp->volume_namep == NULL) {
				partition_result = PARTITION_OUT_OF_MEMORY;
			} else {
				partition_privatep->labelp->crc =
					calc_crc(block_bufferp, block_size);
				(void) snprintf(key_bufferp, MAXPATHLEN,
					"0x%lx",
					partition_privatep->labelp->crc);
				partition_privatep->labelp->keyp =
						strdup(key_bufferp);
				if (partition_privatep->labelp->keyp == NULL) {
					partition_result =
						PARTITION_OUT_OF_MEMORY;
				}
			}
		}
	}
	if (block_bufferp != NULL) {
		free(block_bufferp);
	}
	if (key_bufferp != NULL) {
		free(key_bufferp);
	}
	if (name_bufferp != NULL) {
		free(name_bufferp);
	}
	if (primary_vol_descp != NULL) {
		free(primary_vol_descp);
	}
	if (string_bufferp != NULL) {
		free(string_bufferp);
	}
	return (partition_result);
}

static int32_t
ud_convert2utf8(uint8_t *ibuf, uint8_t *obuf, int32_t length)
{
	int i, size;
	unicode_t *buf;

	/* LINTED */
	buf = (unicode_t *)obuf;

	size = UncompressUnicode(length, ibuf, buf);

	size = UdfTxName(buf, size);

	for (i = 0; i < size; i++) {
		obuf[i] = (uint8_t)buf[i];
	}
	obuf[i] = '\0';

	return (size);
}

static uint16_t ud_crc_table[256] = {
	0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
	0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
	0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
	0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
	0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
	0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
	0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
	0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
	0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
	0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
	0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
	0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
	0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
	0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
	0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
	0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
	0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
	0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
	0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
	0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
	0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
	0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
	0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
	0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
	0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
	0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
	0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
	0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
	0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,
	0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
	0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,
	0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0
};

static uint16_t
ud_crc(uint8_t *addr, int32_t len)
{
	uint16_t	crc;

	crc = 0;
	while (len > 0) {
		crc = ud_crc_table[(crc >> 8 ^ *addr) & 0xff] ^ (crc<<8);
		addr++;
		len--;
	}
	return (crc);
}

static int32_t
UdfTxName(unicode_t *unicode, int32_t count)
{
	/*
	 * unicode is the string of 16-bit characters
	 * count is the number of 16-bit characters
	 */

	int32_t i, j, k, lic, make_crc, dot_loc;
	uint16_t crc;

	if ((unicode[0] == DOT) &&
		((count == 1) || ((count == 2) && (unicode[1] == DOT)))) {
		crc = DOT;
		if (count == 2) {
			crc += DOT;
		}
		unicode[0] = UNDERBAR;
		unicode[1] = POUND;
		unicode[2] = htoc[(uint16_t)(crc & 0xf000) >> 12];
		unicode[3] = htoc[(uint16_t)(crc & 0xf00) >> 8];
		unicode[4] = htoc[(uint16_t)(crc & 0xf0) >> 4];
		unicode[5] = htoc[crc & 0xf];
		return (6);
	}
	crc = 0;
	j = make_crc = 0;
	lic = dot_loc = -1;
	for (i = 0; i < count; i++) {
		if (make_crc) {
			crc += unicode[i];
		}
		if (unicode[i] == DOT) {
			dot_loc = j;
		}
		if ((unicode[i] == SLASH) ||
			(unicode[i] == NULL)) {
			if (make_crc == 0) {
				for (k = 0; k <= i; k++) {
					crc += unicode[k];
				}
				make_crc = 1;
			}
			if (lic != (i - 1)) {
				unicode[j++] = UNDERBAR;
			}
			lic = i;
		} else {
			unicode[j++] = unicode[i];
		}
	}

	if (make_crc) {
		if (dot_loc != -1) {
			if ((j + 5) > MAX_UNICODE_NAMELEN) {
				if ((j - dot_loc + 5) > MAX_UNICODE_NAMELEN) {
					j = MAX_UNICODE_NAMELEN - 5 + dot_loc;
					for (k = MAX_UNICODE_NAMELEN;
						j >= dot_loc; k --, j--) {
						unicode[k] = unicode[j];
					}
					k = 0;
				} else {
					for (k = MAX_UNICODE_NAMELEN;
						j >= dot_loc; k--, j--) {
						unicode[k] = unicode[j];
					}
					k -= 4;
				}
				j = MAX_UNICODE_NAMELEN;
			} else {
				for (k = j; k >= dot_loc; k--) {
					unicode[k + 5] = unicode[k];
				}
				k = dot_loc;
				j += 5;
			}
		} else {
			if ((j + 5) > MAX_UNICODE_NAMELEN) {
				j = MAX_UNICODE_NAMELEN;
				k = MAX_UNICODE_NAMELEN - 5;
			} else {
				k = j;
				j += 5;
			}
		}
		unicode[k++] = POUND;
		unicode[k++] = htoc[(uint16_t)(crc & 0xf000) >> 12];
		unicode[k++] = htoc[(uint16_t)(crc & 0xf00) >> 8];
		unicode[k++] = htoc[(uint16_t)(crc & 0xf0) >> 4];
		unicode[k++] = htoc[crc & 0xf];
	}
	return (j);
}

static int32_t
UncompressUnicode(
	int32_t numberOfBytes,	/* (Input) number of bytes read from media. */
	uint8_t *UDFCompressed,	/* (Input) bytes read from media. */
	unicode_t *unicode)	/* (Output) uncompressed unicode characters. */
{
	/*
	 * Assumes that the output buffer is large enough
	 * to hold the uncompressed unicode characters
	 */

	int32_t compID;
	int32_t returnValue, unicodeIndex, byteIndex;

	/*
	 * Use UDFCompressed to store current byte being read.
	 */

	compID = UDFCompressed[0];

	/*
	 * First check for valid compID.
	 */

	if (compID != 8 && compID != 16) {
		returnValue = -1;
	} else {
		unicodeIndex = 0;
		byteIndex = 1;
		while (byteIndex < numberOfBytes) {
			if (compID == 16) {
				/*
				 * Move the first byte to the
				 * high bits of the unicode char.
				 */
				unicode[unicodeIndex] =
					UDFCompressed[byteIndex] << 8;
				byteIndex++;
			} else {
				unicode[unicodeIndex] = 0;
			}
			if (byteIndex < numberOfBytes) {
				/*
				 * Move the next byte to the low bits.
				 */
				unicode[unicodeIndex] |=
					UDFCompressed[byteIndex];
					byteIndex++;
			}
			unicodeIndex++;
		}
		returnValue = unicodeIndex;
	}
	return (returnValue);
}

static partition_result_t
verify_tag(tag_t *tagp, uint16_t tag_id)
{
	int			byte_index;
	uint8_t			checksum;
	uint8_t			*check_bytesp;
	uint16_t		crc;
	partition_result_t	partition_result;

	partition_result = PARTITION_SUCCESS;
	if (tagp->tag_id != SWAP_16(tag_id)) {
		partition_result = PARTITION_NOT_THIS_TYPE;
	}
	if (partition_result == PARTITION_SUCCESS) {
		byte_index = 0;
		check_bytesp = (uint8_t *)tagp;
		checksum = 0;
		while (byte_index <= 3) {
			checksum += check_bytesp[byte_index];
			byte_index++;
		}
		/*
		 * Skip the tag checksum, which is byte 4 of the tag.
		 */
		byte_index = 5;
		while (byte_index <= 15) {
			checksum += check_bytesp[byte_index];
			byte_index++;
		}
		if (checksum != tagp->tag_cksum) {
			partition_result = PARTITION_NOT_THIS_TYPE;
		}
	}
	if ((partition_result == PARTITION_SUCCESS) &&
		(tagp->tag_crc_len != 0)) {
		/*
		 * Start computing the crc at the first byte after the tag.
		 */
		crc = ud_crc(check_bytesp + 0x10, SWAP_16(tagp->tag_crc_len));
		if (crc != SWAP_16(tagp->tag_crc)) {
			partition_result = PARTITION_NOT_THIS_TYPE;
		}
	}
	return (partition_result);
}
