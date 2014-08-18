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
 * Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T. All Rights Reserved.
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2013 OmniTI Computer Consulting, Inc. All rights reserved.
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#include <sys/zone.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/fs/fifonode.h>
#include <sys/fcntl.h>
#include <sys/brand.h>
#include <sys/lx_brand.h>

/*
 * Based on native pipe(2) system call, except that the pipe is half-duplex.
 */
static int
lx_hd_pipe(intptr_t arg, int flags)
{
	vnode_t *vp1, *vp2;
	struct file *fp1, *fp2;
	int error = 0;
	int flag1, flag2, iflags;
	int fd1, fd2;

	/*
	 * Validate allowed flags.
	 */
	if ((flags & ~(FCLOEXEC|FNONBLOCK)) != 0) {
		return (set_errno(EINVAL));
	}
	/*
	 * Allocate and initialize two vnodes.
	 */
	makepipe(&vp1, &vp2);

	/*
	 * Allocate and initialize two file table entries and two
	 * file pointers. The first file pointer is open for read and the
	 * second is open for write.
	 */
	if ((error = falloc(vp1, FREAD, &fp1, &fd1)) != 0) {
		VN_RELE(vp1);
		VN_RELE(vp2);
		return (set_errno(error));
	}

	if ((error = falloc(vp2, FWRITE, &fp2, &fd2)) != 0)
		goto out2;

	/*
	 * Create two stream heads and attach to each vnode.
	 */
	if ((error = fifo_stropen(&vp1, FREAD, fp1->f_cred, 0, 0)) != 0)
		goto out;

	if ((error = fifo_stropen(&vp2, FWRITE, fp2->f_cred, 0, 0)) != 0) {
		(void) VOP_CLOSE(vp1, FREAD, 1, (offset_t)0,
		    fp1->f_cred, NULL);
		goto out;
	}

	strmate(vp1, vp2);

	VTOF(vp1)->fn_ino = VTOF(vp2)->fn_ino = fifogetid();

	/*
	 * Set the O_NONBLOCK flag if requested.
	 */
	if (flags & FNONBLOCK) {
		flag1 = fp1->f_flag;
		flag2 = fp2->f_flag;
		iflags = flags & FNONBLOCK;

		if ((error = VOP_SETFL(vp1, flag1, iflags, fp1->f_cred,
		    NULL)) != 0) {
			goto out_vop_close;
		}
		fp1->f_flag |= iflags;

		if ((error = VOP_SETFL(vp2, flag2, iflags, fp2->f_cred,
		    NULL)) != 0) {
			goto out_vop_close;
		}
		fp2->f_flag |= iflags;
	}

	/*
	 * Return the file descriptors to the user. They now
	 * point to two different vnodes which have different
	 * stream heads.
	 */
	if (copyout(&fd1, &((int *)arg)[0], sizeof (int)) ||
	    copyout(&fd2, &((int *)arg)[1], sizeof (int))) {
		error = EFAULT;
		goto out_vop_close;
	}

	/*
	 * Now fill in the entries that falloc reserved
	 */
	mutex_exit(&fp1->f_tlock);
	mutex_exit(&fp2->f_tlock);
	setf(fd1, fp1);
	setf(fd2, fp2);

	/*
	 * Optionally set the FCLOEXEC flag
	 */
	if ((flags & FCLOEXEC) != 0) {
		f_setfd(fd1, FD_CLOEXEC);
		f_setfd(fd2, FD_CLOEXEC);
	}

	return (0);
out_vop_close:
	(void) VOP_CLOSE(vp1, FREAD, 1, (offset_t)0, fp1->f_cred, NULL);
	(void) VOP_CLOSE(vp2, FWRITE, 1, (offset_t)0, fp2->f_cred, NULL);
out:
	setf(fd2, NULL);
	unfalloc(fp2);
out2:
	setf(fd1, NULL);
	unfalloc(fp1);
	VN_RELE(vp1);
	VN_RELE(vp2);
	return (set_errno(error));
}

/*
 * pipe(2) system call.
 */
long
lx_pipe(intptr_t arg)
{
	return (lx_hd_pipe(arg, 0));
}

/*
 * pipe2(2) system call.
 */
long
lx_pipe2(intptr_t arg, int flags)
{
	return (lx_hd_pipe(arg, flags));
}
