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
#include <sys/cred.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/filio.h>

/*
 * These are defined in unistd.h - but we can't include that
 */
#define	SEEK_SET	0	/* Set file pointer to "offset" */
#define	SEEK_CUR	1	/* Set file pointer to current plus "offset" */
#define	SEEK_END	2	/* Set file pointer to EOF plus "offset" */
#define	SEEK_DATA	3	/* Set file pointer to next data past offset */
#define	SEEK_HOLE	4	/* Set file pointer to next hole past offset */

/*
 * Seek on a file
 */

#if defined(_SYSCALL32_IMPL) || defined(_ILP32)
/*
 * Workhorse for the 32-bit seek variants: lseek32 and llseek32
 *
 * 'max' represents the maximum possible representation of offset
 * in the data type corresponding to lseek and llseek. It is
 * MAXOFF32_T for off32_t and MAXOFFSET_T for off64_t.
 * We return EOVERFLOW if we cannot represent the resulting offset
 * in the data type.
 * We provide support for character devices to be seeked beyond MAXOFF32_T
 * by lseek. To maintain compatibility in such cases lseek passes
 * the arguments carefully to lseek_common when file is not regular.
 * (/dev/kmem is a good example of a > 2Gbyte seek!)
 */
static int
lseek32_common(file_t *fp, int stype, offset_t off, offset_t max,
    offset_t *retoff)
{
	vnode_t *vp;
	struct vattr vattr;
	int error;
	u_offset_t noff;
	offset_t curoff, newoff;
	int reg;

	vp = fp->f_vnode;
	reg = (vp->v_type == VREG);

	curoff = fp->f_offset;

	switch (stype) {
	case SEEK_SET:
		noff = (u_offset_t)off;
		if (reg && noff > max) {
			error = EINVAL;
			goto out;
		}
		break;

	case SEEK_CUR:
		if (reg && off > (max - curoff)) {
			error = EOVERFLOW;
			goto out;
		}
		noff = (u_offset_t)(off + curoff);
		if (reg && noff > max) {
			error = EINVAL;
			goto out;
		}
		break;

	case SEEK_END:
		vattr.va_mask = AT_SIZE;
		if (error = VOP_GETATTR(vp, &vattr, 0, fp->f_cred, NULL)) {
			goto out;
		}
		if (reg && (off  > (max - (offset_t)vattr.va_size))) {
			error = EOVERFLOW;
			goto out;
		}
		noff = (u_offset_t)(off + (offset_t)vattr.va_size);
		if (reg && noff > max) {
			error = EINVAL;
			goto out;
		}
		break;

	case SEEK_DATA:
		/*
		 * Get and set the file pointer to the offset of the next
		 * data past "off"
		 */
		noff = (u_offset_t)off;
		error = VOP_IOCTL(vp, _FIO_SEEK_DATA, (intptr_t)(&noff),
		    FKIOCTL, kcred, NULL, NULL);
		if (error) {
			if (error != ENOTTY)
				return (error);
			/*
			 * The ioctl is not supported, check the supplied
			 * "off" is not past the end of file
			 */
			vattr.va_mask = AT_SIZE;
			error = VOP_GETATTR(vp, &vattr, 0, fp->f_cred, NULL);
			if (error)
				return (error);
			if (noff >= (u_offset_t)vattr.va_size)
				return (ENXIO);
		}
		if (reg && (noff > max))
			return (EOVERFLOW);

		fp->f_offset = (offset_t)noff;
		(*retoff) = (offset_t)noff;
		return (0);

	case SEEK_HOLE:
		/*
		 * Get and set the file pointer to the offset of the next
		 * hole past "off"
		 */
		noff = (u_offset_t)off;
		error = VOP_IOCTL(vp, _FIO_SEEK_HOLE, (intptr_t)(&noff),
		    FKIOCTL, kcred, NULL, NULL);
		if (error) {
			if (error != ENOTTY)
				return (error);
			/*
			 * ioctl is not supported, if the off is valid return
			 * the "virtual hole" at the end of the file.
			 */
			vattr.va_mask = AT_SIZE;
			error = VOP_GETATTR(vp, &vattr, 0, fp->f_cred, NULL);
			if (error)
				return (error);
			if (off < (offset_t)vattr.va_size)
				noff = (u_offset_t)vattr.va_size;
			else
				return (ENXIO);
		}
		if (reg && (noff > max))
			return (EOVERFLOW);

		fp->f_offset = (offset_t)noff;
		(*retoff) = (offset_t)noff;
		return (0);

	default:
		error = EINVAL;
		goto out;
	}

	ASSERT((reg && noff <= max) || !reg);
	newoff = (offset_t)noff;
	if ((error = VOP_SEEK(vp, curoff, &newoff, NULL)) == 0) {
		fp->f_offset = newoff;
		(*retoff) = newoff;
		return (0);
	}
out:
	return (error);
}

off32_t
lseek32(int32_t fdes, off32_t off, int32_t stype)
{
	file_t *fp;
	int error;
	offset_t retoff;

	if ((fp = getf(fdes)) == NULL)
		return ((off32_t)set_errno(EBADF));

	/*
	 * lseek32 returns EOVERFLOW if we cannot represent the resulting
	 * offset from seek in a 32-bit off_t.
	 * The following routines are sensitive to sign extensions and
	 * calculations and if ever you change this make sure it works for
	 * special files.
	 *
	 * When VREG is not set we do the check for stype != SEEK_SET
	 * to send the unsigned value to lseek_common and not the sign
	 * extended value. (The maximum representable value is not
	 * checked by lseek_common for special files.)
	 */
	if (fp->f_vnode->v_type == VREG || stype != SEEK_SET)
		error = lseek32_common(fp, stype, (offset_t)off,
		    (offset_t)MAXOFF32_T, &retoff);
	else if (stype == SEEK_SET)
		error = lseek32_common(fp, stype, (offset_t)(uint_t)off,
		    (offset_t)(uint_t)UINT_MAX, &retoff);

	releasef(fdes);
	if (!error)
		return ((off32_t)retoff);
	return ((off32_t)set_errno(error));
}

/*
 * 64-bit seeks from 32-bit applications
 */
offset_t
llseek32(int32_t fdes, uint32_t off1, uint32_t off2, int stype)
{
	file_t *fp;
	int error;
	offset_t retoff;
#if defined(_LITTLE_ENDIAN)
	offset_t off = ((u_offset_t)off2 << 32) | (u_offset_t)off1;
#else
	offset_t off = ((u_offset_t)off1 << 32) | (u_offset_t)off2;
#endif

	if ((fp = getf(fdes)) == NULL)
		error = EBADF;
	else {
		error = lseek32_common(fp, stype, off, MAXOFFSET_T, &retoff);
		releasef(fdes);
	}

	return (error ? (offset_t)set_errno(error) : retoff);
}
#endif	/* _SYSCALL32_IMPL || _ILP32 */

#ifdef _LP64
/*
 * Seek on a file.
 *
 * Life is almost simple again (at least until we do 128-bit files ;-)
 * This is both 'lseek' and 'llseek' to a 64-bit application.
 */
off_t
lseek64(int fdes, off_t off, int stype)
{
	file_t *fp;
	vnode_t *vp;
	struct vattr vattr;
	int error;
	off_t old_off;
	offset_t new_off;

	if ((fp = getf(fdes)) == NULL)
		return ((off_t)set_errno(EBADF));

	vp = fp->f_vnode;
	new_off = off;

	switch (stype) {
	case SEEK_CUR:
		new_off += fp->f_offset;
		break;

	case SEEK_END:
		vattr.va_mask = AT_SIZE;
		if ((error = VOP_GETATTR(vp, &vattr, 0, fp->f_cred, NULL)) != 0)
			goto lseek64error;
		new_off += vattr.va_size;
		break;

	case SEEK_SET:
		break;

	case SEEK_DATA:
		/*
		 * Get and set the file pointer to the offset of the next
		 * data past "off"
		 */
		new_off = (offset_t)off;
		error = VOP_IOCTL(vp, _FIO_SEEK_DATA, (intptr_t)(&new_off),
		    FKIOCTL, kcred, NULL, NULL);
		if (error) {
			if (error != ENOTTY) {
				goto lseek64error;
			}
			/*
			 * The ioctl is not supported, check the supplied off
			 * is not past end of file
			 */
			vattr.va_mask = AT_SIZE;
			error = VOP_GETATTR(vp, &vattr, 0, fp->f_cred, NULL);
			if (error)
				goto lseek64error;
			if (new_off >= (offset_t)vattr.va_size) {
				error = ENXIO;
				goto lseek64error;
			}
		}
		fp->f_offset = new_off;
		releasef(fdes);
		return (new_off);

	case SEEK_HOLE:
		/*
		 * Get and set the file pointer to the offset of the next
		 * hole past "off"
		 */
		new_off = off;
		error = VOP_IOCTL(vp, _FIO_SEEK_HOLE, (intptr_t)(&new_off),
		    FKIOCTL, kcred, NULL, NULL);
		if (error) {
			if (error != ENOTTY)
				goto lseek64error;
			/*
			 * ioctl is not supported, if the off is valid return
			 * the "virtual hole" at the end of the file.
			 */
			vattr.va_mask = AT_SIZE;
			error = VOP_GETATTR(vp, &vattr, 0, fp->f_cred, NULL);
			if (error)
				goto lseek64error;
			if (off < (offset_t)vattr.va_size) {
				new_off = (offset_t)vattr.va_size;
			} else {
				error = ENXIO;
				goto lseek64error;
			}
		}
		fp->f_offset = new_off;
		releasef(fdes);
		return (new_off);

	default:
		error = EINVAL;
		goto lseek64error;
	}

	old_off = fp->f_offset;
	if ((error = VOP_SEEK(vp, old_off, &new_off, NULL)) == 0) {
		fp->f_offset = new_off;
		releasef(fdes);
		return (new_off);
	}

lseek64error:
	releasef(fdes);
	return ((off_t)set_errno(error));
}
#endif	/* _LP64 */
