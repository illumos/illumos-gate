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
 * Copyright (c) 1994, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#include <sys/param.h>
#include <sys/isa_defs.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/debug.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <c2/audit.h>

/*
 * Rename a file relative to a given directory
 */
int
renameat(int ffd, char *from, int tfd, char *to)
{
	vnode_t *fstartvp = NULL;
	vnode_t *tstartvp = NULL;
	int error;

	if (from == NULL || to == NULL)
		return (set_errno(EFAULT));
	if ((error = fgetstartvp(ffd, from, &fstartvp)) != 0)
		goto out;
	if ((error = fgetstartvp(tfd, to, &tstartvp)) != 0)
		goto out;

	error = vn_renameat(fstartvp, from, tstartvp, to, UIO_USERSPACE);

out:
	if (fstartvp != NULL)
		VN_RELE(fstartvp);
	if (tstartvp != NULL)
		VN_RELE(tstartvp);
	if (error)
		return (set_errno(error));
	return (0);
}

int
rename(char *from, char *to)
{
	return (renameat(AT_FDCWD, from, AT_FDCWD, to));
}
