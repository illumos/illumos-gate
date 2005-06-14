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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/crc32.h>

static unsigned int crc32_tab[] = { CRC32_TABLE };

/*
 * Return a 32-bit CRC of the contents of the buffer.
 *
 * The seed is 0xffffffff and the result is XORed with 0xffffffff
 * because this is what the Itanium firmware expects.
 */
unsigned int
efi_crc32(const unsigned char *s, unsigned int len)
{
	unsigned int crc32val;

	CRC32(crc32val, s, len, -1U, crc32_tab);

	return (crc32val ^ -1U);
}
