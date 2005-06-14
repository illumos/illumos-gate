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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#include <cryptoutil.h>

/*
 * tohexstr
 * IN	bytes
 *	blen
 *	hexlen should be 2 * blen + 1
 * OUT
 *	hexstr
 */
void
tohexstr(uchar_t *bytes, size_t blen, char *hexstr, size_t hexlen)
{
	size_t i;
	char hexlist[] = "0123456789abcdef";

	for (i = 0; i < blen; i++) {
		if (hexlen < (2 * i + 1))
			break;
		hexstr[2 * i] = hexlist[(bytes[i] >> 4) & 0xf];
		hexstr[2 * i + 1] = hexlist[bytes[i] & 0xf];
	}
	hexstr[2 * blen] = '\0';
}
