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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2025 Oxide Computer Company
 */

#include <sys/types.h>
#include <sys/ucode.h>
#include <sys/ucode_amd.h>
#include <sys/stdbool.h>
#ifdef	_KERNEL
#include <sys/systm.h>
#else
#include <strings.h>
#endif

/*
 * Perform basic validation of an AMD microcode container file.
 */
ucode_errno_t
ucode_validate_amd(uint8_t *ucodep, size_t size)
{
	uint8_t *ptr = ucodep;
	bool first = true;
	uint32_t magic;

	if (ucodep == NULL || size <= 0)
		return (EM_INVALIDARG);

	/* Magic Number */
	bcopy(ptr, &magic, sizeof (magic));
	if (magic != UCODE_AMD_CONTAINER_MAGIC)
		return (EM_FILEFORMAT);
	ptr += sizeof (magic);
	size -= sizeof (magic);

	/*
	 * There follow one or more TLV-encoded sections. We expect that the
	 * first section is an equivalence table and all subsequent sections
	 * are patches and return EM_FILEFORMAT if that is not the case.
	 */
	while (size > sizeof (ucode_section_amd_t)) {
		ucode_section_amd_t section;

		bcopy(ptr, &section, sizeof (section));
		if (section.usa_size == 0 || section.usa_size > size)
			return (EM_FILEFORMAT);
		ptr += sizeof (section);
		size -= sizeof (section);

		switch (section.usa_type) {
		case UCODE_AMD_CONTAINER_TYPE_EQUIV:
			if (!first)
				return (EM_FILEFORMAT);
			/*
			 * The equivalence table maps processor IDs (family,
			 * stepping, model) to a Microcode Patch Equivalent
			 * Processor ID. We just verify that it its size is a
			 * whole number of entries.
			 */
			if (section.usa_size % sizeof (ucode_eqtbl_amd_t) != 0)
				return (EM_FILEFORMAT);
			break;

		case UCODE_AMD_CONTAINER_TYPE_PATCH:
			if (first)
				return (EM_FILEFORMAT);
			break;

		default:
			return (EM_FILEFORMAT);
		}

		size -= section.usa_size;
		ptr += section.usa_size;
		first = false;
	}

	/* We don't expect there to be any unaccounted for trailing data */
	if (size != 0)
		return (EM_FILEFORMAT);

	return (EM_OK);
}
