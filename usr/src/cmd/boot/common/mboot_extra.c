/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Nexenta Systems, Inc. All rights reserved.
 */

#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <libintl.h>
#include <sys/multiboot.h>
#include <sys/sysmacros.h>

#include "bblk_einfo.h"
#include "boot_utils.h"
#include "mboot_extra.h"

/*
 * Common functions to deal with the fake-multiboot encapsulation of the
 * bootblock and the location of the extra information area.
 */

/* mboot checksum routine. */
uint32_t
compute_checksum(char *data, uint32_t size)
{
	uint32_t	*ck_ptr;
	uint32_t	cksum = 0;
	int		i;

	ck_ptr = (uint32_t *)data;
	for (i = 0; i < size; i += sizeof (uint32_t))
		cksum += *ck_ptr++;

	return (-cksum);
}

/* Given a buffer, look for a multiboot header within it. */
int
find_multiboot(char *buffer, uint32_t buf_size, uint32_t *mboot_off)
{
	multiboot_header_t	*mboot;
	uint32_t		*iter;
	uint32_t		cksum;
	uint32_t		boundary;
	int			i = 0;

	iter = (uint32_t *)buffer;
	*mboot_off = 0;
	/* multiboot header has to be within the first 32K. */
	boundary = MBOOT_SCAN_SIZE;
	if (boundary > buf_size)
		boundary = buf_size;

	boundary = boundary - sizeof (multiboot_header_t);

	for (i = 0; i < boundary; i += 4, iter++) {

		mboot = (multiboot_header_t *)iter;
		if (mboot->magic != MB_HEADER_MAGIC)
			continue;

		/* Found magic signature -- check checksum. */
		cksum = -(mboot->flags + mboot->magic);
		if (mboot->checksum != cksum) {
			BOOT_DEBUG("multiboot magic found at %p, but checksum "
			    "mismatches (is %x, should be %x)\n", mboot,
			    mboot->checksum, cksum);
			continue;
		} else {
			if (!(mboot->flags & BB_MBOOT_AOUT_FLAG)) {
				BOOT_DEBUG("multiboot structure found, but no "
				    "AOUT kludge specified, skipping.\n");
				continue;
			} else {
				/* proper multiboot structure found. */
				*mboot_off = i;
				return (BC_SUCCESS);
			}
		}
	}

	return (BC_ERROR);
}

/*
 * Given a pointer to the extra information area (a sequence of bb_header_ext_t
 * + payload chunks), find the extended information structure.
 */
bblk_einfo_t *
find_einfo(char *extra, uint32_t size)
{
	bb_header_ext_t		*ext_header;
	bblk_einfo_t		*einfo;
	uint32_t		cksum;

	assert(extra != NULL);

	ext_header = (bb_header_ext_t *)extra;
	if (ext_header->size > size) {
		BOOT_DEBUG("Unable to find extended versioning information, "
		    "data size too big\n");
		return (NULL);
	}

	cksum = compute_checksum(extra + sizeof (bb_header_ext_t),
	    ext_header->size);
	BOOT_DEBUG("Extended information header checksum is %x\n", cksum);

	if (cksum != ext_header->checksum) {
		BOOT_DEBUG("Unable to find extended versioning information, "
		    "data looks corrupted\n");
		return (NULL);
	}

	/*
	 * Currently we only have one extra header so it must be encapsulating
	 * the extended information structure.
	 */
	einfo = (bblk_einfo_t *)(extra + sizeof (bb_header_ext_t));
	if (memcmp(einfo->magic, EINFO_MAGIC, EINFO_MAGIC_SIZE) != 0) {
		BOOT_DEBUG("Unable to read stage2 extended versioning "
		    "information, wrong magic identifier\n");
		BOOT_DEBUG("Found %s, expected %s\n", einfo->magic,
		    EINFO_MAGIC);
		return (NULL);
	}

	return (einfo);
}

/*
 * Given a pointer to the extra area, add the extended information structure
 * encapsulated by a bb_header_ext_t structure.
 */
void
add_einfo(char *extra, char *updt_str, bblk_hs_t *hs, uint32_t avail_space)
{
	bb_header_ext_t	*ext_hdr;
	uint32_t	used_space;
	unsigned char	*dest;
	int		ret;

	assert(extra != NULL);

	if (updt_str == NULL) {
		BOOT_DEBUG("WARNING: no update string passed to "
		    "add_stage2_einfo()\n");
		return;
	}

	/* Reserve space for the extra header. */
	ext_hdr = (bb_header_ext_t *)extra;
	dest = (unsigned char *)extra + sizeof (*ext_hdr);
	/* Place the extended information structure. */
	ret = prepare_and_write_einfo(dest, updt_str, hs, avail_space,
	    &used_space);
	if (ret != 0) {
		(void) fprintf(stderr, gettext("Unable to write the extended "
		    "versioning information\n"));
		return;
	}

	/* Fill the extended information associated header. */
	ext_hdr->size = P2ROUNDUP(used_space, 8);
	ext_hdr->checksum = compute_checksum((char *)dest, ext_hdr->size);
}
