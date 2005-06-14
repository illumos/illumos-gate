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
#ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 1997 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/pathname.h>

int
resolvepath(char *path, char *buf, size_t count)
{
	struct pathname lookpn;
	struct pathname resolvepn;
	int error;

	if (count == 0)
		return (0);
	if (error = pn_get(path, UIO_USERSPACE, &lookpn))
		return (set_errno(error));
	pn_alloc(&resolvepn);
	error = lookuppn(&lookpn, &resolvepn, FOLLOW, NULL, NULL);
	if (error == 0) {
		if (count > resolvepn.pn_pathlen)
			count = resolvepn.pn_pathlen;
		if (copyout(resolvepn.pn_path, buf, count))
			error = EFAULT;
	}
	pn_free(&resolvepn);
	pn_free(&lookpn);

	if (error)
		return (set_errno(error));
	return ((int)count);
}
