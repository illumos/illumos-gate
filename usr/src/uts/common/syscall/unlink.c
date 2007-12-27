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

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
 * Unlink (i.e. delete) a file.
 */
int
unlink(char *fname)
{
	int	error;

	if (error = vn_remove(fname, UIO_USERSPACE, RMFILE))
		return (set_errno(error));
	return (0);
}

/*
 * Unlink a file from a directory
 */
int
unlinkat(int fd, char *name, int flags)
{
	file_t *dirfp;
	vnode_t *dirvp;
	int error;
	char startchar;

	if (fd == AT_FDCWD && name == NULL)
		return (set_errno(EFAULT));

	if (name != NULL) {
		if (copyin(name, &startchar, sizeof (char)))
			return (set_errno(EFAULT));
	} else
		startchar = '\0';

	if (fd == AT_FDCWD) {
		dirvp = NULL;
	} else {
		if (startchar != '/') {
			if ((dirfp = getf(fd)) == NULL) {
				return (set_errno(EBADF));
			}
			dirvp = dirfp->f_vnode;
			VN_HOLD(dirvp);
			releasef(fd);
		} else {
			dirvp = NULL;
		}
	}

	if (audit_active)
		audit_setfsat_path(1);

	error = vn_removeat(dirvp, name,
	    UIO_USERSPACE, (flags == AT_REMOVEDIR) ? RMDIRECTORY : RMFILE);
	if (dirvp != NULL)
		VN_RELE(dirvp);

	if (error != NULL)
		return (set_errno(error));
	return (0);
}
