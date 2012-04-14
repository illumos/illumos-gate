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
 */

#include <sys/types.h>
#include <sys/ucode.h>
#ifdef	_KERNEL
#include <sys/systm.h>
#else
#include <strings.h>
#endif

/*
 * Refer to
 *	Intel 64 and IA-32 Architectures Software Developers's Manual
 *		Chapter 9.11 Microcode Update Facilities
 * for details.
 */

/*
 * Validates the microcode header.
 * Returns EM_OK on success, EM_HEADER on failure.
 */
ucode_errno_t
ucode_header_validate_intel(ucode_header_intel_t *uhp)
{
	uint32_t header_size, body_size, total_size;

	if (uhp == NULL)
		return (EM_HEADER);

	/*
	 * The only header version number supported is 1.
	 */
	if (uhp->uh_header_ver != 0x1)
		return (EM_HEADER);

	header_size = UCODE_HEADER_SIZE_INTEL;
	total_size = UCODE_TOTAL_SIZE_INTEL(uhp->uh_total_size);
	body_size = UCODE_BODY_SIZE_INTEL(uhp->uh_body_size);

	/*
	 * The body size field of the microcode code header specifies the size
	 * of the encrypted data section, its value must be a multiple of the
	 * size of DWORD.  The total size field must be in multiples of 1K
	 * bytes.
	 */
	if ((body_size % sizeof (int)) ||
	    (total_size < (header_size + body_size)) ||
	    (total_size % UCODE_KB(1)))

		return (EM_HEADER);

	/*
	 * Sanity check to avoid reading bogus files
	 */
	if (total_size < UCODE_MIN_SIZE || total_size > UCODE_MAX_SIZE)
		return (EM_HEADER);

	/*
	 * If there is extended signature table, total_size is the sum of
	 *	header_size
	 *	body_size
	 *	sizeof (struct ucode_ext_table)
	 *	n * sizeof (struct ucode_ext_sig)
	 * where n is indicated by uet_count in struct ucode_ext_table.
	 */
	if (total_size > (header_size + body_size)) {
		if ((total_size - body_size - header_size -
		    UCODE_EXT_TABLE_SIZE_INTEL) % UCODE_EXT_SIG_SIZE_INTEL) {

			return (EM_HEADER);
		}
	}

	return (EM_OK);
}

/*
 * Returns checksum.
 */
uint32_t
ucode_checksum_intel(uint32_t sum, uint32_t size, uint8_t *code)
{
	int i;
	uint32_t *lcode = (uint32_t *)(intptr_t)code;

	i = size >> 2;
	while (i--)
		sum += lcode[i];

	return (sum);
}

ucode_errno_t
ucode_validate_amd(uint8_t *ucodep, int size)
{
	/* LINTED: pointer alignment */
	uint32_t *ptr = (uint32_t *)ucodep;
	uint32_t count;

	if (ucodep == NULL || size <= 0)
		return (EM_INVALIDARG);

	/* Magic Number: "AMD\0" */
	size -= 4;
	if (*ptr++ != 0x00414d44)
		return (EM_FILEFORMAT);

	/* equivalence table */
	size -= 4;
	if (*ptr++)
		return (EM_FILEFORMAT);

	size -= 4;
	if (((count = *ptr++) > size) || (count % 16))
		return (EM_FILEFORMAT);

	/* LINTED: pointer alignment */
	ptr = (uint32_t *)(((uint8_t *)ptr) + count);
	size -= count;

	while (size > 8) {
		/* microcode patch */
		size -= 4;
		if (*ptr++ != 1)
			return (EM_FILEFORMAT);

		size -= 4;
		if (((count = *ptr++) > size))
			return (EM_FILEFORMAT);

		/* LINTED: pointer alignment */
		ptr = (uint32_t *)(((uint8_t *)ptr) + count);
		size -= count;
	}

	if (size)
		return (EM_FILEFORMAT);

	return (EM_OK);
}

ucode_errno_t
ucode_validate_intel(uint8_t *ucodep, int size)
{
	uint32_t header_size = UCODE_HEADER_SIZE_INTEL;
	int remaining;

	if (ucodep == NULL || size <= 0)
		return (EM_INVALIDARG);

	for (remaining = size; remaining > 0; ) {
		uint32_t total_size, body_size, ext_size;
		ucode_header_intel_t *uhp;
		uint8_t *curbuf = &ucodep[size - remaining];
		ucode_errno_t rc;

		uhp = (ucode_header_intel_t *)(intptr_t)curbuf;

		if ((rc = ucode_header_validate_intel(uhp)) != EM_OK)
			return (rc);

		total_size = UCODE_TOTAL_SIZE_INTEL(uhp->uh_total_size);

		if (ucode_checksum_intel(0, total_size, curbuf))
			return (EM_CHECKSUM);

		body_size = UCODE_BODY_SIZE_INTEL(uhp->uh_body_size);
		ext_size = total_size - (header_size + body_size);

		if (ext_size > 0) {
			uint32_t i;

			if (ucode_checksum_intel(0, ext_size,
			    &curbuf[header_size + body_size])) {
				return (EM_CHECKSUM);
			}

			ext_size -= UCODE_EXT_TABLE_SIZE_INTEL;
			for (i = 0; i < ext_size / UCODE_EXT_SIG_SIZE_INTEL;
			    i++) {
				if (ucode_checksum_intel(0,
				    UCODE_EXT_SIG_SIZE_INTEL,
				    &curbuf[total_size - ext_size +
				    i * UCODE_EXT_SIG_SIZE_INTEL])) {

					return (EM_CHECKSUM);
				}
			}
		}

		remaining -= total_size;
	}
	return (EM_OK);
}
