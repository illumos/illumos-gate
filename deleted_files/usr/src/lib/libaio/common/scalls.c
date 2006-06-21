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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak close = _libaio_close

#include "libaio.h"

extern void _cancel_prologue(void);
extern void _cancel_epilogue(void);

int
_libaio_close(int fd)
{
	int rc;

	/*
	 * Cancel all outstanding aio requests for this file descriptor.
	 */
	if (fd >= 0 && __uaio_ok)
		(void) aiocancel_all(fd);
	/*
	 * If we have allocated the bit array, clear the bit for this file.
	 * The next open may re-use this file descriptor and the new file
	 * may have different kaio() behaviour.
	 */
	if (_kaio_supported != NULL)
		CLEAR_KAIO_SUPPORTED(fd);

	_cancel_prologue();
	rc = _close(fd);
	_cancel_epilogue();

	return (rc);
}
