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
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2017, Joyent, Inc.
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2011, 2017 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * Portions of code from both of:
 *	syscall/rename.c
 *	fs/vnode.c
 * heavily modified for this use.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/file.h>
#include <sys/pathname.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/rwstlock.h>
#include <sys/fem.h>
#include <sys/stat.h>
#include <sys/mode.h>
#include <sys/conf.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/acl.h>
#include <sys/nbmlock.h>
#include <sys/fcntl.h>
#include <fs/fs_subr.h>
#include <sys/taskq.h>
#include <fs/fs_reparse.h>
#include <sys/time.h>

#include <libfksmbfs.h>

int
fake_rename(char *frompath, char *topath)
{
	vnode_t *fdvp = NULL;
	vnode_t *tdvp = NULL;
	char *fname = NULL;
	char *tname = NULL;
	int error;

	/*
	 * Lookup to and from directories.
	 */
	if ((error = fake_lookup_dir(frompath, &fdvp, &fname)) != 0)
		goto out;
	if ((error = fake_lookup_dir(topath, &tdvp, &tname)) != 0)
		goto out;

	/*
	 * Make sure both the from vnode directory and the to directory
	 * are in the same vfs and the to directory is writable.
	 */
	if (fdvp != tdvp && fdvp->v_vfsp != tdvp->v_vfsp) {
		error = EXDEV;
		goto out;
	}
	if (tdvp->v_vfsp->vfs_flag & VFS_RDONLY) {
		error = EROFS;
		goto out;
	}

	/*
	 * Do the rename.
	 */
	error = VOP_RENAME(fdvp, fname, tdvp, tname, CRED(), NULL, 0);

out:
	if (fdvp)
		VN_RELE(fdvp);
	if (tdvp)
		VN_RELE(tdvp);

	return (error);
}
