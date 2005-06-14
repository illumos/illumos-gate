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

/*
 * Common functions used by the crypto tests.
 */

#include <stdio.h>
#include "cmn_test.h"

/*
 * hexascii to integer conversion
 */
static int
xstrtoi(char *str, int len) {
	int val;
	int c;
	int i;

	val = 0;
	for (i = 0, c = *str++; len-- > 0; i++, c = *str++) {
		if (c >= '0' && c <= '9') {
			c -= '0';
		} else if (c >= 'A' && c <= 'F') {
			c = (c - 'A') + 10;
		} else if (c >= 'a' && c <= 'f') {
			c = (c - 'a') + 10;
		} else {
			break;
		}
		val *= 16;
		val += c;
	}
	return (val);
}

/*
 * Accepts a buffer containing a hexascii string and converts
 * it to a buffer with the hexascii nibbles converted to integers.
 */
void
getxdata(unsigned char *cp, char *field, int len)
{
	int i;
	int t;

	for (i = 0; i < len; i++) {
		t = xstrtoi(field, 2);
		*cp++ = (char)t;
		field += 2;
	}
}

/*
 * Accepts a buffer of integer nibbles and prints them
 * out as a hexascii string.
 */
void
putxdata(unsigned char *cp, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		(void) printf("%02X", *cp++ & 0xff);
	}
}
