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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak _getpeerucred = getpeerucred

#include "lint.h"

#include <sys/types.h>
#include <sys/syscall.h>
#include <ucred.h>
#include <sys/ucred.h>

int
getpeerucred(int fd, ucred_t **ucp)
{
	ucred_t *uc = *ucp;

	if (uc == NULL) {
		uc = _ucred_alloc();
		if (uc == NULL)
			return (-1);
	}

	if (syscall(SYS_ucredsys, UCREDSYS_GETPEERUCRED, fd, uc) != 0) {
		if (*ucp == NULL)
			ucred_free(uc);
		return (-1);
	}
	*ucp = uc;
	return (0);
}
