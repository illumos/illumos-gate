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
 * Copyright 2024 Oxide Computer Company
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#include <sys/types.h>
#include <sys/cred.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/file.h>
#include <sys/fdsync.h>

/*
 * This is the common system call for fsync(), fdatasync(), and syncfs(). It
 * performs the requested I/O synchronization for the file descriptor.
 */
int
fdsync(int fd, uint32_t arg)
{
	file_t *fp;
	int ret;

	if ((fp = getf(fd)) == NULL) {
		return (set_errno(EBADF));
	}

	switch (arg) {
	case FDSYNC_FS:
		ret = VFS_SYNCFS(fp->f_vnode->v_vfsp, 0, fp->f_cred);
		break;
	case FDSYNC_FILE:
		ret = VOP_FSYNC(fp->f_vnode, FSYNC, fp->f_cred, NULL);
		break;
	case FDSYNC_DATA:
		ret = VOP_FSYNC(fp->f_vnode, FDSYNC, fp->f_cred, NULL);
		break;
	default:
		ret = EINVAL;
		break;
	}

	releasef(fd);
	if (ret != 0) {
		(void) set_errno(ret);
	}

	return (ret);
}
