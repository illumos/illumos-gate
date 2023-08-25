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
 * Copyright 2023 Oxide Computer Company
 */

#include <sys/types.h>
#include <sys/ucode.h>
#include <sys/ucode_amd.h>
#ifdef	_KERNEL
#include <sys/systm.h>
#else
#include <strings.h>
#endif

/*
 * Perform basic validation of an AMD microcode bundle file.
 */
ucode_errno_t
ucode_validate_amd(uint8_t *ucodep, int size)
{
	uint32_t *ptr = (uint32_t *)ucodep;
	uint32_t count;

	if (ucodep == NULL || size <= 0)
		return (EM_INVALIDARG);

	/* Magic Number: "AMD\0" */
	size -= 4;
	if (*ptr++ != 0x00414d44)
		return (EM_FILEFORMAT);

	/*
	 * There follows an equivalence table that maps processor IDs (family,
	 * stepping, model) to a Microcode Patch Equivalent Processor ID.
	 * The format of the equivalence table is:
	 *    0-3 version? - always 0
	 *    4-7 count - number of entries in table, including terminator
	 *    < 16 byte record > * (count - 1)
	 *    < 16 byte terminating record, all zeros >
	 */
	size -= 4;
	if (*ptr++ != 0)
		return (EM_FILEFORMAT);

	size -= 4;
	count = *ptr++;
	if (count > size || count % 16 != 0)
		return (EM_FILEFORMAT);

	/* Skip past equivalence table and the terminating record */
	ptr = (uint32_t *)(((uint8_t *)ptr) + count);
	size -= count;

	/*
	 * There then follow one or more microcode patches in the following
	 * format:
	 *   0-3   patch type
	 *   4-7   patch length
	 *   < length bytes >
	 */
	while (size > 8) {
		/* We only support patch type 1 */
		size -= 4;
		if (*ptr++ != 1)
			return (EM_FILEFORMAT);

		size -= 4;
		if (((count = *ptr++) > size))
			return (EM_FILEFORMAT);

		ptr = (uint32_t *)(((uint8_t *)ptr) + count);
		size -= count;
	}

	if (size != 0)
		return (EM_FILEFORMAT);

	return (EM_OK);
}
