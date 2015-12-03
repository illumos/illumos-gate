/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Joyent, Inc.
 */

#include <sys/systm.h>
#include <sys/zone.h>
#include <sys/types.h>
#include <sys/filio.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/nbmlock.h>
#include <sys/lx_impl.h>
#include <sys/lx_brand.h>
#include <sys/sdt.h>

extern int flock_check(vnode_t *, flock64_t *, offset_t, offset_t);

#define	LX_FALLOC_FL_KEEP_SIZE		0x01
#define	LX_FALLOC_FL_PUNCH_HOLE		0x02
#define	LX_FALLOC_FL_NO_HIDE_STALE	0x04
#define	LX_FALLOC_FL_COLLAPSE_RANGE	0x08
#define	LX_FALLOC_FL_ZERO_RANGE		0x10

#define	LX_FALLOC_VALID	(LX_FALLOC_FL_KEEP_SIZE | LX_FALLOC_FL_PUNCH_HOLE | \
	LX_FALLOC_FL_NO_HIDE_STALE | LX_FALLOC_FL_COLLAPSE_RANGE | \
	LX_FALLOC_FL_ZERO_RANGE)

#define	LX_FALLOC_UNSUPP	(LX_FALLOC_FL_NO_HIDE_STALE | \
	LX_FALLOC_FL_COLLAPSE_RANGE)

long
lx_fallocate(int fd, int mode, off_t offset, off_t len)
{
	int error = 0;
	file_t *fp;
	vnode_t *vp;
	int64_t tot;
	struct flock64 bf;
	vattr_t vattr;
	u_offset_t f_offset;
	boolean_t in_crit = B_FALSE;

	/*
	 * Error checking is in a specific order to make LTP happy.
	 */

	tot = offset + len;
	if (tot > (LLONG_MAX / (int64_t)1024))
		return (set_errno(EFBIG));

	if (mode & LX_FALLOC_UNSUPP)
		return (set_errno(EOPNOTSUPP));

	if ((fp = getf(fd)) == NULL)
		return (set_errno(EBADF));

	if ((fp->f_flag & FWRITE) == 0) {
		error = EBADF;
		goto done;
	}

	vp = fp->f_vnode;
	if (vp->v_type != VREG) {
		error = EINVAL;
		goto done;
	}

	if (offset < 0 || len <= 0) {
		error = EINVAL;
		goto done;
	}

	if (tot < 0LL) {
		error = EFBIG;
		goto done;
	}

	if ((mode & ~LX_FALLOC_VALID) != 0) {
		error = EINVAL;
		goto done;
	}

	/*
	 * If this is the only flag then we don't actually do any work.
	 */
	if (mode == LX_FALLOC_FL_KEEP_SIZE)
		goto done;

	bzero(&bf, sizeof (bf));

	vattr.va_mask = AT_SIZE;
	if ((error = VOP_GETATTR(vp, &vattr, 0, CRED(), NULL)) != 0)
		goto done;

	if (mode == 0) {
		/* Nothing to do if not extending the file */
		if (vattr.va_size >= tot)
			goto done;

		/* Extend the file. */
		bf.l_start = (off64_t)tot;
		bf.l_len = (off64_t)0;

	} else if (mode & LX_FALLOC_FL_PUNCH_HOLE) {
		/*
		 * Deallocate space in the file.
		 */
		if ((mode & LX_FALLOC_FL_KEEP_SIZE) == 0) {
			/* this flag is required with punch hole */
			error = EINVAL;
			goto done;
		}

		if (mode &
		    ~(LX_FALLOC_FL_PUNCH_HOLE | LX_FALLOC_FL_KEEP_SIZE)) {
			error = EINVAL;
			goto done;
		}

		/* Make sure we don't extend since keep_size is set. */
		if (vattr.va_size < tot) {
			if (offset > vattr.va_size)
				goto done;
			len = (off_t)vattr.va_size - offset;
		}

		bf.l_start = (off64_t)offset;
		bf.l_len = (off64_t)len;

	} else if (mode & LX_FALLOC_FL_ZERO_RANGE) {
		/*
		 * Zero out the space in the file.
		 */
		if (mode &
		    ~(LX_FALLOC_FL_ZERO_RANGE | LX_FALLOC_FL_KEEP_SIZE)) {
			error = EINVAL;
			goto done;
		}

		/* Make sure we don't extend when keep_size is set. */
		if (mode & LX_FALLOC_FL_KEEP_SIZE && vattr.va_size < tot) {
			if (offset > vattr.va_size)
				goto done;
			len = vattr.va_size - offset;
		}

		bf.l_start = (off64_t)offset;
		bf.l_len = (off64_t)len;
	} else {
		/* We should have already handled all flags */
		VERIFY(0);
	}

	/*
	 * Check for locks in the range.
	 */
	f_offset = fp->f_offset;
	error = flock_check(vp, &bf, f_offset, MAXOFF_T);
	if (error != 0)
		goto done;

	/*
	 * Check for conflicting non-blocking mandatory locks.
	 * We need to get the size again under nbl_start_crit.
	 */
	if (nbl_need_check(vp)) {
		u_offset_t	begin;
		ssize_t		length;

		nbl_start_crit(vp, RW_READER);
		in_crit = B_TRUE;
		vattr.va_mask = AT_SIZE;
		if ((error = VOP_GETATTR(vp, &vattr, 0, CRED(), NULL)) != 0)
			goto done;

		/*
		 * Make sure we don't extend when keep_size is set.
		 */
		if (mode & LX_FALLOC_FL_KEEP_SIZE && vattr.va_size < tot) {
			ASSERT(mode & (LX_FALLOC_FL_PUNCH_HOLE |
			    LX_FALLOC_FL_ZERO_RANGE));

			/*
			 * If the size grew we can short-circuit the rest of
			 * the work, otherwise adjust bf for the vop_space
			 * call.
			 */
			if (offset >= vattr.va_size)
				goto done;
			len = vattr.va_size - offset;
			bf.l_len = (off64_t)len;
		}

		if (offset > vattr.va_size) {
			begin = vattr.va_size;
			length = offset - vattr.va_size;
		} else {
			begin = offset;
			length = vattr.va_size - offset;
		}

		if (nbl_conflict(vp, NBL_WRITE, begin, length, 0, NULL)) {
			error = EACCES;
			goto done;
		}
	}

	error = VOP_SPACE(vp, F_FREESP, &bf, 0, f_offset, fp->f_cred, NULL);

done:
	if (in_crit)
		nbl_end_crit(vp);

	releasef(fd);
	if (error != 0)
		return (set_errno(error));

	return (0);
}

long
lx_fallocate32(int fd, int mode, uint32_t offl, uint32_t offh, uint32_t lenl,
    uint32_t lenh)
{
	int64_t offset = 0, len = 0;

	/*
	 * From 32-bit callers, Linux passes the 64-bit offset and len by
	 * concatenating consecutive arguments. We must perform the same
	 * conversion here.
	 */
	offset = offh;
	offset = offset << 32;
	offset |= offl;
	len = lenh;
	len = len << 32;
	len |= lenl;

	return (lx_fallocate(fd, mode, (off_t)offset, (off_t)len));
}
