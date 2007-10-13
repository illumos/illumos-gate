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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <locale.h>
#include <cryptoutil.h>

#define	RANDOM_DEVICE		"/dev/urandom"	/* random device name */

/*
 * Put the requested amount of random data into a preallocated buffer.
 * Good for passphrase salts, initialization vectors.
 */
int
pkcs11_random_data(void *dbuf, size_t dlen)
{
	int	fd;

	if (dbuf == NULL || dlen == 0)
		return (0);

	/* Read random data directly from /dev/urandom */
	if ((fd = open(RANDOM_DEVICE, O_RDONLY)) != -1) {
		if (read(fd, dbuf, dlen) == dlen) {
			(void) close(fd);
			return (0);
		}
		(void) close(fd);
	}
	return (-1);
}
