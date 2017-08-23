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
 * Copyright 2017 Joyent, Inc.
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
#include <sys/policy.h>
#include <sys/brand.h>
#include <sys/lx_brand.h>
#include <sys/lx_fcntl.h>
#include <sys/sysmacros.h>

#define	LX_DEFAULT_PIPE_SIZE	65536

/*
 * Our default value for fs.pipe-size-max mirrors Linux.  The enforced maximum
 * is meant to provide some sort of upper bound on pipe buffer sizing.  Its
 * value was chosen somewhat arbitrarily.
 */
uint_t lx_pipe_max_default = 1048576;
uint_t lx_pipe_max_limit = 8388608;

int
lx_pipe_setsz(stdata_t *str, uint_t size, boolean_t is_init)
{
	int err;
	stdata_t *mate;
	lx_zone_data_t *lxzd = ztolxzd(curzone);
	uint_t max_size = lxzd->lxzd_pipe_max_sz;


	size = P2ROUNDUP(size, PAGESIZE);
	if (size == 0) {
		return (EINVAL);
	} else if (size > max_size && secpolicy_resource(CRED()) != 0) {
		if (!is_init) {
			return (EPERM);
		}
		/*
		 * If the size limit is breached during initial pipe setup,
		 * simply clamp it to the maximum.  On Linux kernels prior to
		 * 4.9, this clamping would not occur and it would be possible
		 * to open a pipe with the default buffer size even if it
		 * exceeded the sysctl limit.  Rather than trigger behavior
		 * here based on  the configured kernel version, it is applied
		 * to all callers.
		 */
		size = max_size;
		ASSERT(max_size <= lx_pipe_max_limit);
	} else if (size > lx_pipe_max_limit) {
		/*
		 * Unlike Linux, we do maintain a global hard cap on pipe
		 * buffer limits.
		 */
		return (EPERM);
	}

	if (!STRMATED(str)) {
		return (strqset(RD(str->sd_wrq), QHIWAT, 0, (intptr_t)size));
	}

	/*
	 * Ensure consistent order so the set operation is always attempted on
	 * the "higher" stream first.
	 */
	if (str > str->sd_mate) {
		VERIFY((mate = str->sd_mate) != NULL);
	} else {
		mate = str;
		VERIFY((str = mate->sd_mate) != NULL);
	}

	/*
	 * While it is unfortunate that an error could occur for the latter
	 * half of the stream pair, there is little to be done about it aside
	 * from reporting the failure.
	 */
	if ((err = strqset(RD(str->sd_wrq), QHIWAT, 0, (intptr_t)size)) == 0) {
		err = strqset(RD(mate->sd_wrq), QHIWAT, 0, (intptr_t)size);
	}
	return (err);
}

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
	stdata_t *str;

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
	 * Attempt to set pipe buffer sizes to expected value.
	 */
	VERIFY((str = vp1->v_stream) != NULL);
	(void) lx_pipe_setsz(str, LX_DEFAULT_PIPE_SIZE, B_TRUE);

	/*
	 * Because we're using streams to increase the capacity of the pipe
	 * up to the default Linux capacity, we have to switch the pipe
	 * out of FIFOFAST mode and back to a normal stream. In fast mode
	 * the pipe capacity is limited to "Fifohiwat" which is a compile-time
	 * limit set to FIFOHIWAT.
	 */
	fifo_fastoff(VTOF(vp1));

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
lx_pipe2(intptr_t arg, int lxflags)
{
	int flags = 0;

	/*
	 * Validate allowed flags.
	 */
	if ((lxflags & ~(LX_O_NONBLOCK | LX_O_CLOEXEC)) != 0) {
		return (set_errno(EINVAL));
	}

	/*
	 * Convert from Linux flags to illumos flags.
	 */
	if (lxflags & LX_O_NONBLOCK) {
		flags |= FNONBLOCK;
	}
	if (lxflags & LX_O_CLOEXEC) {
		flags |= FCLOEXEC;
	}

	return (lx_hd_pipe(arg, flags));
}
